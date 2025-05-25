use core::{cell::RefCell, fmt::Write};

use algorithms::{
    pagetable::PageTableManager,
    unialloc::{UniAllocTrait, UntypedInfoAdapter},
};
use alloc::collections::BTreeMap;
use elf::{
    abi::{PF_R, PF_X, PT_LOAD},
    endian::LittleEndian,
    ElfBytes,
};
use iced_x86::{Code, Register};
use intrusive_collections::LinkedList;
use ipc::{
    conventions::{SUBPROC_CSPACE, SUBPROC_VSPACE},
    host_paging::{HostPageTableManager, HostPagingService, SMALL_PAGE_SIZE_BITS},
    println,
    untyped::UntypedCap,
    vmmsvc::VmPagingMode,
};
use sel4::{
    cap::{CNode, VSpace},
    CPtr, CapRights, FrameObjectType, IpcBuffer, VmAttributes,
};
use vmm::{
    paging::VmPagingContext,
    pv::patch_point::{PatchPoint, PatchPointSet},
};
use x86::bits64::paging::{PAddr, PDEntry, PDFlags, PDPTEntry, PDPTFlags, PML4Entry, PML4Flags};

use crate::shared::{
    ELF_LOAD_REGION, GUEST_INITIAL_PT_PDPT_PHYS, GUEST_INITIAL_PT_PD_PHYS,
    GUEST_INITIAL_PT_PML4_PHYS, GUEST_RAMDISK_PHYS, GUEST_START_INFO_PHYS,
    GUEST_VIRTIO_MMIO_INTERRUPT_BASE, GUEST_VIRTIO_MMIO_START, IDMAP_REGION, KERNEL_BUCKET_CAP,
};

pub const HVM_START_MAGIC_VALUE: u32 = 0x336ec578;
pub const HVM_MEMMAP_TYPE_RAM: u32 = 1;

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HvmStartInfo {
    pub magic: u32,
    pub version: u32,
    pub flags: u32,
    pub nr_modules: u32,
    pub modlist_paddr: u64,
    pub cmdline_paddr: u64,
    pub rsdp_paddr: u64,
    pub memmap_paddr: u64,
    pub memmap_entries: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HvmMemmapEntry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HvmModlistEntry {
    pub paddr: u64,
    pub size: u64,
    pub cmdline_paddr: u64,
    pub reserved: u64,
}

#[derive(Debug)]
pub struct NanosBootInfo {
    pub entrypoint: u64,
    pub patch_point_set: PatchPointSet,
}

pub fn load_elf(
    ipc: &mut IpcBuffer,
    ua: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
    paging: &VmPagingContext,
    num_kernel_pages: usize,
    num_virtio_devices: usize,
) -> NanosBootInfo {
    let mut ptm: HostPageTableManager = PageTableManager::new();
    let mut ps = HostPagingService {
        alloc: ua,
        cspace: CNode::from_cptr(SUBPROC_CSPACE),
        hostpml4: VSpace::from_cptr(SUBPROC_VSPACE),
        skip_pdpt: true,
        utlist: LinkedList::new(UntypedInfoAdapter::NEW),
    };
    let tmpcap = CPtr::from_bits(
        ua.borrow_mut()
            .get_capalloc()
            .alloc()
            .expect("alloc failed"),
    );
    let kernel_bucket_cnode_bits = num_kernel_pages.next_power_of_two().trailing_zeros() as u8;
    for i in 0..num_kernel_pages {
        assert_eq!(
            ipc.inner_mut().seL4_CNode_Move(
                SUBPROC_CSPACE.bits(),
                tmpcap.bits(),
                64,
                KERNEL_BUCKET_CAP.bits(),
                i as u64,
                kernel_bucket_cnode_bits,
            ),
            0
        );

        let vaddr = ELF_LOAD_REGION.start + i * FrameObjectType::GRANULE.bytes();
        ptm.allocate(ipc, vaddr as u64, 3, &mut ps)
            .expect("Failed to allocate paging structures");

        assert_eq!(
            ipc.inner_mut().seL4_X86_Page_Map(
                tmpcap.bits(),
                SUBPROC_VSPACE.bits(),
                vaddr as u64,
                CapRights::read_only().into_inner(),
                VmAttributes::DEFAULT.into_inner()
            ),
            0
        );

        assert_eq!(
            ipc.inner_mut().seL4_CNode_Move(
                KERNEL_BUCKET_CAP.bits(),
                i as u64,
                kernel_bucket_cnode_bits,
                SUBPROC_CSPACE.bits(),
                tmpcap.bits(),
                64,
            ),
            0
        );
    }
    let nanos_elf = unsafe {
        core::slice::from_raw_parts(
            ELF_LOAD_REGION.start as *const u8,
            num_kernel_pages * FrameObjectType::GRANULE.bytes(),
        )
    };
    for x in ptm.paging_structures().filter(|x| x.cap.bits() != 0) {
        paging.ps.borrow().blackhole().dispose_and_free(ipc, x.cap);
    }
    for ut in core::mem::take(&mut ps.utlist) {
        paging
            .ps
            .borrow()
            .blackhole()
            .dispose_and_free(ipc, ut.cap.0.cptr());
    }
    drop(ptm);
    drop(ps);

    println!(
        "Loading Nanos unikernel ({} bytes @ {:p})",
        nanos_elf.len(),
        nanos_elf.as_ptr(),
    );

    let is_pv = paging.ps.borrow().config().mode == VmPagingMode::Pv;
    let mut patch_point_set = PatchPointSet {
        patch_points: BTreeMap::new(),
    };

    let elf = ElfBytes::<LittleEndian>::minimal_parse(nanos_elf).expect("invalid ELF");

    for phdr in elf.segments().expect("no elf segments") {
        if phdr.p_type != PT_LOAD {
            continue;
        }

        let ptr = IDMAP_REGION
            .start
            .checked_add(phdr.p_paddr as usize)
            .expect("overflow") as *mut u8;
        let data = elf
            .segment_data(&phdr)
            .expect("failed to read segment data");
        assert_eq!(data.len(), phdr.p_filesz as usize);
        println!(
            "Copying segment: [{:#x}, {:#x}) ({}/{} bytes), original vaddr: {:p}, file offset: {:#x}",
            phdr.p_paddr,
            phdr.p_paddr + phdr.p_memsz,
            phdr.p_memsz,
            phdr.p_filesz,
            data.as_ptr(),
            phdr.p_offset
        );
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }
        if is_pv && phdr.p_flags == PF_R | PF_X {
            patch_code(&mut patch_point_set, phdr.p_paddr, unsafe {
                core::slice::from_raw_parts_mut(ptr, data.len())
            });
        }
    }

    let mut pvh_start_phys = None;

    let (syms, strs) = elf
        .symbol_table()
        .expect("failed to parse symbol table")
        .expect("no symbol table");
    let entry_sym = if is_pv {
        "pvh_long_mode"
    } else {
        "pvh_start_long_mode"
    };
    for sym in syms {
        let name = strs.get(sym.st_name as usize).unwrap_or_default();
        if name == entry_sym {
            pvh_start_phys = Some(sym.st_value);
        }
    }

    let pvh_start_phys = pvh_start_phys.expect("entry symbol not found");

    // write hvm start info
    let mut cmdline_writer;
    unsafe {
        let num_memmap_entries = if paging.high_region.is_some() {
            2u32
        } else {
            1u32
        };

        let start_info = (IDMAP_REGION.start as u64 + GUEST_START_INFO_PHYS) as *mut HvmStartInfo;
        let memmap = start_info.add(1) as *mut HvmMemmapEntry;
        let modentry = memmap.add(num_memmap_entries as usize) as *mut HvmModlistEntry;
        let cmdline = modentry.add(1) as *mut u8;
        let start_info = &mut *start_info;
        start_info.magic = HVM_START_MAGIC_VALUE;
        start_info.version = 1;
        start_info.modlist_paddr = modentry as u64 - IDMAP_REGION.start as u64;
        start_info.nr_modules = 0;
        start_info.cmdline_paddr = cmdline as u64 - IDMAP_REGION.start as u64;
        start_info.memmap_paddr = memmap as u64 - IDMAP_REGION.start as u64;
        start_info.memmap_entries = num_memmap_entries;
        core::ptr::write(
            memmap,
            HvmMemmapEntry {
                addr: 0x100_000,
                size: paging.low_region.end - 0x100_000,
                type_: HVM_MEMMAP_TYPE_RAM,
                reserved: 0,
            },
        );
        if let Some(high_region) = &paging.high_region {
            core::ptr::write(
                memmap.add(1),
                HvmMemmapEntry {
                    addr: high_region.start,
                    size: high_region.end - high_region.start,
                    type_: HVM_MEMMAP_TYPE_RAM,
                    reserved: 0,
                },
            );
        }
        core::ptr::write(
            modentry,
            HvmModlistEntry {
                paddr: GUEST_RAMDISK_PHYS,
                size: 0,
                cmdline_paddr: 0,
                reserved: 0,
            },
        );

        cmdline_writer = StringWriter {
            backing: core::slice::from_raw_parts_mut(cmdline, 1024),
            cursor: 0,
        };
    }
    cmdline_writer.write_str("verbose").unwrap();
    for i in 0..num_virtio_devices {
        let mmio = GUEST_VIRTIO_MMIO_START as usize + (i << SMALL_PAGE_SIZE_BITS);
        let interrupt = GUEST_VIRTIO_MMIO_INTERRUPT_BASE + i as u8;
        write!(
            cmdline_writer,
            " virtio_mmio.device=4K@{:#x}:{}",
            mmio, interrupt
        )
        .unwrap();
    }
    cmdline_writer.write_str("\0").unwrap();

    // Create guest page tables for first 4MB
    let pml4 = unsafe {
        &mut *((IDMAP_REGION.start as u64 + GUEST_INITIAL_PT_PML4_PHYS) as *mut [PML4Entry; 512])
    };
    let pdpt = unsafe {
        &mut *((IDMAP_REGION.start as u64 + GUEST_INITIAL_PT_PDPT_PHYS) as *mut [PDPTEntry; 512])
    };
    let pd = unsafe {
        &mut *((IDMAP_REGION.start as u64 + GUEST_INITIAL_PT_PD_PHYS) as *mut [PDEntry; 512])
    };

    pml4[0] = PML4Entry::new(
        PAddr(GUEST_INITIAL_PT_PDPT_PHYS),
        PML4Flags::P | PML4Flags::RW,
    );
    pdpt[0] = PDPTEntry::new(
        PAddr(GUEST_INITIAL_PT_PD_PHYS),
        PDPTFlags::P | PDPTFlags::RW,
    );
    for i in 0..512 {
        pd[i] = PDEntry::new(
            PAddr((0x200000usize * i) as u64),
            PDFlags::P | PDFlags::RW | PDFlags::PS,
        );
    }

    NanosBootInfo {
        entrypoint: pvh_start_phys,
        patch_point_set,
    }
}

struct StringWriter<'a> {
    backing: &'a mut [u8],
    cursor: usize,
}

impl<'a> Write for StringWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if bytes.len() > self.backing.len() - self.cursor {
            return Err(core::fmt::Error);
        }
        self.backing[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        Ok(())
    }
}

fn patch_code(patch_point_set: &mut PatchPointSet, paddr: u64, data: &mut [u8]) {
    let mut decoder = iced_x86::Decoder::with_ip(64, data, paddr, 0);
    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            continue;
        }

        match insn.code() {
            Code::Vmcall => {
                patch_point_set
                    .patch_points
                    .insert(insn.ip(), (PatchPoint::Vmcall, insn.len() as u8));
            }
            Code::Pushfw => {
                panic!("unexpected PUSHFW instruction, paddr: {:#x}", insn.ip());
            }
            Code::Pushfd => {
                panic!("unexpected PUSHFD instruction, paddr: {:#x}", insn.ip());
            }
            Code::Pushfq => {
                // ignore instructions with prefix (REX)
                if insn.len() == 1 {
                    patch_point_set
                        .patch_points
                        .insert(insn.ip(), (PatchPoint::Pushfq, insn.len() as u8));
                }
            }
            Code::Popfw => {
                panic!("unexpected POPFW instruction, paddr: {:#x}", insn.ip());
            }
            Code::Popfd => {
                panic!("unexpected POPFD instruction, paddr: {:#x}", insn.ip());
            }
            Code::Popfq => {
                // ignore instructions with prefix (REX)
                if insn.len() == 1 {
                    patch_point_set
                        .patch_points
                        .insert(insn.ip(), (PatchPoint::Popfq, insn.len() as u8));
                }
            }
            Code::Sidt_m1664 => {
                if insn.memory_base() == Register::RAX
                    && insn.memory_index() == Register::None
                    && insn.memory_displacement64() == 0
                {
                    patch_point_set
                        .patch_points
                        .insert(insn.ip(), (PatchPoint::SidtRax, insn.len() as u8));
                } else {
                    panic!(
                        "unexpected SIDT instruction with op0_register: {:?}, paddr: {:#x}",
                        insn.op0_register(),
                        insn.ip()
                    );
                }
            }
            Code::Cpuid => {
                patch_point_set
                    .patch_points
                    .insert(insn.ip(), (PatchPoint::Cpuid, insn.len() as u8));
            }
            Code::Iretq => {
                patch_point_set
                    .patch_points
                    .insert(insn.ip(), (PatchPoint::Iretq, insn.len() as u8));
            }
            _ => {}
        }
    }

    for (insn_paddr, (pp, insn_len)) in &patch_point_set.patch_points {
        let offset = *insn_paddr - paddr;
        match pp {
            PatchPoint::Vmcall => {
                assert_eq!(*insn_len, 3, "vmcall instruction length mismatch");

                // replace with syscall + nop
                data[offset as usize..offset as usize + 3].copy_from_slice(&[0x0f, 0x05, 0x90]);
            }
            _ => {
                // http://ref.x86asm.net/coder64.html
                for i in 0..*insn_len {
                    data[offset as usize + i as usize] = 0x0e;
                }
            }
        }
    }
    println!(
        "applied {} patch points",
        patch_point_set.patch_points.len()
    );
}
