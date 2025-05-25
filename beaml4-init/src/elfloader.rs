use core::ptr::NonNull;

use algorithms::{
    idalloc::IdAlloc64Trait,
    pagetable::PageTableManager,
    unialloc::{UniAllocTrait, UntypedInfoAdapter},
};
use alloc::{collections::BTreeMap, sync::Arc};
use elf::{abi::PT_LOAD, endian::LittleEndian, ElfBytes};
use intrusive_collections::LinkedList;
use ipc::{conventions, untyped::UntypedCap};
use sel4::{
    cap::{CNode, Endpoint, Tcb, PML4},
    init_thread::slot::{ASID_POOL, CNODE, TCB, VSPACE},
    sys::priorityConstants::seL4_MaxPrio,
    with_ipc_buffer_mut, CNodeCapData, CPtr, CPtrWithDepth, CapRights, ObjectBlueprint,
    ObjectBlueprintX64, ObjectBlueprintX86, UserContext, VmAttributes,
};

use crate::alloc_control::AllocState;
use ipc::host_paging::{
    HostPagingContext, HostPagingService, HostPagingStructure, SMALL_PAGE_SIZE_BITS,
};

pub struct ProcessInfo {
    pub endpoint_sender: Endpoint,
    pub tcb: Tcb,
    pub utlist: LinkedList<UntypedInfoAdapter<UntypedCap>>,
    pub page_bucket: CNode,
}

#[derive(Copy, Clone, Debug)]
pub struct SubprocessConfig {
    pub cnode_bits: u8,
    pub priority: u8,
    pub badge: usize,
    pub expose_tcb: bool,
}

pub fn start_process(
    alloc_state: &AllocState,
    host_paging: &HostPagingContext,
    elf_bytes: &[u8],
    config: SubprocessConfig,
) -> ProcessInfo {
    assert!(config.cnode_bits > 0);
    assert!(config.cnode_bits < 32);

    let elf = ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).expect("invalid ELF");
    let mut utlist = LinkedList::new(UntypedInfoAdapter::NEW);

    let stack_addr = 0x1fff_0000_0000u64;
    let stack_size = 65536u64;

    // estimate number of process pages:
    // ipc page + stack pages (16) + ELF total memsz + ELF non-aligned segment overhead
    let estimated_pages = 1
        + stack_size.div_ceil(1 << SMALL_PAGE_SIZE_BITS)
        + elf
            .segments()
            .map(|x| {
                x.iter()
                    .map(|x| x.p_memsz)
                    .sum::<u64>()
                    .div_ceil(1 << SMALL_PAGE_SIZE_BITS)
            })
            .unwrap_or(0)
        + elf.segments().map(|x| x.iter().count()).unwrap_or_default() as u64
        + 16;

    // pages + paging structures
    let page_bucket_bits = estimated_pages.next_power_of_two().trailing_zeros() + 1;

    let page_bucket = CNode::from_cptr(alloc_state.alloc_empty_cap());
    utlist.push_back(Arc::new(alloc_state.alloc_and_retype(
        &ObjectBlueprint::CNode {
            size_bits: page_bucket_bits as _,
        },
        page_bucket.cptr(),
    )));
    let page_bucket_local = CNode::from_cptr(alloc_state.alloc_empty_cap());
    let page_bucket_local_ut = alloc_state.alloc_and_retype(
        &ObjectBlueprint::CNode {
            size_bits: page_bucket_bits as _,
        },
        page_bucket_local.cptr(),
    );
    let mut page_bucket_cursor = 0u64;

    let vspace = PML4::from_cptr(alloc_state.alloc_empty_cap());
    utlist.push_back(Arc::new(alloc_state.alloc_and_retype(
        &ObjectBlueprint::Arch(ObjectBlueprintX86::SeL4Arch(ObjectBlueprintX64::PML4)),
        vspace.cptr(),
    )));
    ASID_POOL
        .cap()
        .asid_pool_assign(vspace)
        .expect("Failed to assign ASID pool");

    let cspace = CNode::from_cptr(alloc_state.alloc_empty_cap());
    utlist.push_back(Arc::new(alloc_state.alloc_and_retype(
        &ObjectBlueprint::CNode {
            size_bits: config.cnode_bits as _,
        },
        cspace.cptr(),
    )));

    let tcb_cap = Tcb::from_cptr(alloc_state.alloc_empty_cap());
    utlist.push_back(Arc::new(
        alloc_state.alloc_and_retype(&ObjectBlueprint::Tcb, tcb_cap.cptr()),
    ));

    let ipcbuf_cap = alloc_state.alloc_empty_cap();
    utlist.push_back(Arc::new(alloc_state.alloc_and_retype(
        &ObjectBlueprint::Arch(ObjectBlueprintX86::_4k),
        ipcbuf_cap,
    )));
    let ipcbuf_cap = sel4::cap::_4k::from_cptr(ipcbuf_cap);
    let ipcbuf_remote_addr = 0x1000usize;
    tcb_cap
        .tcb_configure(
            CPtr::from_bits(0),
            cspace,
            CNodeCapData::new(0, (64 - config.cnode_bits) as usize),
            vspace,
            ipcbuf_remote_addr as u64,
            ipcbuf_cap,
        )
        .expect("Failed to configure TCB");
    tcb_cap
        .tcb_set_sched_params(TCB.cap(), seL4_MaxPrio as u64, config.priority as u64)
        .expect("Failed to set TCB priority");

    let mut child_paging = PageTableManager::<HostPagingStructure, 4, 9, 12>::new();
    let mut cps = HostPagingService {
        alloc: &alloc_state.ua,
        cspace: CNODE.cap(),
        hostpml4: vspace,
        skip_pdpt: false,
        utlist: LinkedList::new(UntypedInfoAdapter::NEW),
    };
    with_ipc_buffer_mut(|ipc| {
        child_paging
            .allocate(ipc, ipcbuf_remote_addr as u64, 3, &mut cps)
            .expect("Failed to allocate IPC buffer");
        assert_eq!(
            ipc.inner_mut().seL4_X86_Page_Map(
                ipcbuf_cap.bits(),
                vspace.bits(),
                ipcbuf_remote_addr as u64,
                CapRights::read_write().into_inner(),
                VmAttributes::DEFAULT.into_inner(),
            ),
            0
        );

        // Pre-allocate page table structures
        child_paging
            .allocate(
                ipc,
                conventions::SUBPROC_PREMAPPED_LOW_REGION.start as u64,
                3,
                &mut cps,
            )
            .expect("Failed to allocate premapped region");
        for page_start in (conventions::SUBPROC_PREMAPPED_HIGH_REGION.start
            ..conventions::SUBPROC_PREMAPPED_HIGH_REGION.end)
            .step_by(0x20_0000)
        {
            child_paging
                .allocate(ipc, page_start as u64, 3, &mut cps)
                .expect("Failed to allocate premapped region");
        }
        for page_start in (conventions::SUBPROC_PREMAPPED_LARGE_PAGE_REGION.start
            ..conventions::SUBPROC_PREMAPPED_LARGE_PAGE_REGION.end)
            .step_by(0x4000_0000)
        {
            child_paging
                .allocate(ipc, page_start as u64, 2, &mut cps)
                .expect("Failed to allocate premapped region");
        }
    });

    // shadow host mappings
    let mut shadow_mapping: BTreeMap<u64, NonNull<[u8; 1 << SMALL_PAGE_SIZE_BITS]>> =
        BTreeMap::new();

    for phdr in elf.segments().expect("no elf segments") {
        if phdr.p_type != PT_LOAD || phdr.p_memsz == 0 {
            continue;
        }

        let first_page_idx = phdr.p_vaddr >> SMALL_PAGE_SIZE_BITS;
        let last_page_idx = (phdr.p_vaddr + phdr.p_memsz - 1) >> SMALL_PAGE_SIZE_BITS;
        let mut data = &elf_bytes[phdr.p_offset as usize..(phdr.p_offset + phdr.p_filesz) as usize];
        let guest = sel4::cap::_4k::from_cptr(alloc_state.alloc_empty_cap());
        let shadow = sel4::cap::_4k::from_cptr(alloc_state.alloc_empty_cap());
        for page_idx in first_page_idx..=last_page_idx {
            let page_start_vaddr = page_idx << SMALL_PAGE_SIZE_BITS;
            let page_end_vaddr = (page_idx + 1) << SMALL_PAGE_SIZE_BITS;

            let write_start_vaddr = phdr.p_vaddr.max(page_start_vaddr).min(page_end_vaddr);
            let write_end_vaddr = (phdr.p_vaddr + phdr.p_filesz)
                .max(page_start_vaddr)
                .min(page_end_vaddr);
            assert!(write_end_vaddr >= write_start_vaddr);

            let write_start_offset = write_start_vaddr - page_start_vaddr;
            let write_end_offset = write_end_vaddr - page_start_vaddr;

            let shadow_mapping_ptr = shadow_mapping.entry(page_start_vaddr).or_insert_with(|| {
                let va = with_ipc_buffer_mut(|ipc| host_paging.alloc_unmapped_page(ipc));
                utlist.push_back(Arc::new(alloc_state.alloc_and_retype(
                    &ObjectBlueprint::Arch(ObjectBlueprintX86::_4k),
                    shadow.cptr(),
                )));
                shadow
                    .frame_map(
                        VSPACE.cap(),
                        va.addr().get(),
                        CapRights::read_write(),
                        VmAttributes::DEFAULT,
                    )
                    .expect("Failed to map shadow page");
                CNODE
                    .cap()
                    .absolute_cptr(guest.cptr())
                    .copy(
                        &CNODE.cap().absolute_cptr(shadow.cptr()),
                        CapRights::read_write(),
                    )
                    .expect("Failed to copy shadow page");
                with_ipc_buffer_mut(|ipc| {
                    child_paging
                        .allocate(ipc, page_start_vaddr, 3, &mut cps)
                        .expect("Failed to allocate guest page vaddr")
                });
                guest
                    .frame_map(
                        vspace,
                        page_start_vaddr as usize,
                        CapRights::read_write(),
                        VmAttributes::DEFAULT,
                    )
                    .expect("Failed to map guest page");
                page_bucket
                    .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
                        page_bucket_cursor,
                        page_bucket_bits as usize,
                    ))
                    .move_(&CNODE.cap().absolute_cptr(guest.cptr()))
                    .expect("Failed to move guest ELF page cap");
                page_bucket_local
                    .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
                        page_bucket_cursor,
                        page_bucket_bits as usize,
                    ))
                    .move_(&CNODE.cap().absolute_cptr(shadow.cptr()))
                    .expect("Failed to move shadow ELF page cap");
                page_bucket_cursor += 1;
                va
            });
            let mut shadow_mapping_ptr = *shadow_mapping_ptr;
            let shadow = unsafe { shadow_mapping_ptr.as_mut() };
            let (our_data, rest) = data.split_at((write_end_offset - write_start_offset) as usize);
            data = rest;
            shadow[write_start_offset as usize..write_end_offset as usize]
                .copy_from_slice(our_data);
        }
        assert!(alloc_state.borrow_mut().capalloc.free(guest.bits()));
        assert!(alloc_state.borrow_mut().capalloc.free(shadow.bits()));
        assert!(data.is_empty());
    }

    for (_, ptr) in shadow_mapping {
        assert!(host_paging.free_unmapped_page(ptr));
    }

    // Free shadow-mapped host pages
    CNODE
        .cap()
        .absolute_cptr(page_bucket_local_ut.cap.0)
        .revoke()
        .expect("Failed to revoke page bucket local ut");
    assert!(alloc_state
        .borrow_mut()
        .capalloc
        .free(page_bucket_local.bits()));
    alloc_state.borrow_mut().free_normal(&page_bucket_local_ut);

    for page_addr in (stack_addr..stack_addr + stack_size).step_by(1 << SMALL_PAGE_SIZE_BITS) {
        with_ipc_buffer_mut(|ipc| {
            child_paging
                .allocate(ipc, page_addr, 3, &mut cps)
                .expect("Failed to allocate stack")
        });
        let stack_frame = sel4::cap::_4k::from_cptr(alloc_state.alloc_empty_cap());
        utlist.push_back(Arc::new(alloc_state.alloc_and_retype(
            &ObjectBlueprint::Arch(ObjectBlueprintX86::_4k),
            stack_frame.cptr(),
        )));
        stack_frame
            .frame_map(
                vspace,
                page_addr as usize,
                CapRights::read_write(),
                VmAttributes::DEFAULT,
            )
            .expect("Failed to map stack page");
        page_bucket
            .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
                page_bucket_cursor,
                page_bucket_bits as usize,
            ))
            .move_(&CNODE.cap().absolute_cptr(stack_frame.cptr()))
            .expect("Failed to move guest stack page cap");
        page_bucket_cursor += 1;
        assert!(alloc_state.borrow_mut().capalloc.free(stack_frame.bits()));
    }

    let mut child_entry = None;

    let (syms, strs) = elf
        .symbol_table()
        .expect("failed to parse symbol table")
        .expect("no symbol table");
    for sym in syms {
        let name = strs.get(sym.st_name as usize).unwrap_or_default();
        if name == "_start" {
            child_entry = Some(sym.st_value);
            break;
        }
    }
    let Some(child_entry) = child_entry else {
        panic!("_start not found");
    };

    // create an endpoint
    let endpoint = alloc_state.alloc_empty_cap();
    utlist.push_back(Arc::new(
        alloc_state.alloc_and_retype(&ObjectBlueprint::Endpoint, endpoint),
    ));
    let endpoint_sender = Endpoint::from_cptr(alloc_state.alloc_empty_cap());
    CNODE
        .cap()
        .absolute_cptr(endpoint_sender.cptr())
        .mint(
            &CNODE.cap().absolute_cptr(endpoint),
            CapRights::new(true, true, false, true),
            config.badge as _,
        )
        .expect("Failed to mint endpoint sender");
    cspace
        .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            conventions::SUBPROC_ENDPOINT.bits(),
            config.cnode_bits as usize,
        ))
        .move_(&CNODE.cap().absolute_cptr(endpoint))
        .expect("Failed to move endpoint");
    assert!(alloc_state.borrow_mut().capalloc.free(endpoint.bits()));
    cspace
        .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            conventions::SUBPROC_VSPACE.bits(),
            config.cnode_bits as usize,
        ))
        .move_(&CNODE.cap().absolute_cptr(vspace))
        .expect("Failed to move vspace");
    assert!(alloc_state.borrow_mut().capalloc.free(vspace.bits()));
    cspace
        .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            conventions::SUBPROC_IPC_BUFFER.bits(),
            config.cnode_bits as usize,
        ))
        .move_(&CNODE.cap().absolute_cptr(ipcbuf_cap.cptr()))
        .expect("Failed to move ipcbuf cap");
    assert!(alloc_state.borrow_mut().capalloc.free(ipcbuf_cap.bits()));
    if config.expose_tcb {
        cspace
            .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
                conventions::SUBPROC_TCB.bits(),
                config.cnode_bits as usize,
            ))
            .copy(
                &CNODE.cap().absolute_cptr(tcb_cap.cptr()),
                CapRights::read_write(),
            )
            .expect("Failed to copy tcb");
    }

    cspace
        .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            conventions::SUBPROC_CSPACE.bits(),
            config.cnode_bits as usize,
        ))
        .mutate(
            &CNODE.cap().absolute_cptr(cspace),
            CNodeCapData::new(0, 64 - config.cnode_bits as usize).into_word(),
        )
        .expect("Failed to move cspace");
    assert!(alloc_state.borrow_mut().capalloc.free(cspace.bits()));

    // free child paging structure caps by moving them into the page bucket
    for p in child_paging.paging_structures() {
        page_bucket
            .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
                page_bucket_cursor,
                page_bucket_bits as usize,
            ))
            .move_(&CNODE.cap().absolute_cptr(p.cap))
            .expect("Failed to move child paging structure");
        page_bucket_cursor += 1;
        assert!(alloc_state.borrow_mut().capalloc.free(p.cap.bits()));
    }

    let mut regs = UserContext::default();
    *regs.pc_mut() = child_entry;
    *regs.sp_mut() = stack_addr + stack_size - 8;
    *regs.c_param_mut(0) = ipcbuf_remote_addr as u64;
    tcb_cap
        .tcb_write_all_registers(true, &mut regs)
        .expect("Failed to write registers");

    for x in cps.utlist {
        utlist.push_back(x);
    }

    ProcessInfo {
        endpoint_sender,
        tcb: tcb_cap,
        utlist,
        page_bucket,
    }
}

impl ProcessInfo {
    pub fn total_bytes(&self) -> usize {
        let mut counter = 0usize;
        for ut in &self.utlist {
            counter += 1usize << ut.size_bits
        }
        counter
    }

    #[allow(dead_code)]
    pub fn destroy(self, alloc_state: &AllocState) {
        self.tcb.tcb_suspend().expect("Failed to suspend TCB");

        for ut in self.utlist {
            CNODE
                .cap()
                .absolute_cptr(ut.cap.0)
                .revoke()
                .expect("Failed to revoke ut");
            if ut.is_device {
                alloc_state.borrow_mut().free_device(&ut);
            } else {
                alloc_state.borrow_mut().free_normal(&ut);
            }
        }

        for cap in [
            self.tcb.cptr(),
            self.page_bucket.cptr(),
            self.endpoint_sender.cptr(),
        ] {
            assert!(alloc_state.borrow_mut().capalloc.free(cap.bits()));
        }
    }
}
