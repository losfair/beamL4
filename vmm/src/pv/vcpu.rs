use core::{cell::RefCell, time::Duration};

use algorithms::{
    unialloc::{UniAllocTrait, UntypedInfoAdapter},
    vm::vcpu::{AbstractVcpu, InterruptBitmap, VcpuException, VcpuFault, VcpuState, VcpuStateMask},
};
use alloc::boxed::Box;
use bitfield::{Bit, BitMut, BitRange, BitRangeMut};
use iced_x86::{Code, Decoder, Register};
use intrusive_collections::LinkedList;
use ipc::{
    alloc::alloc_and_retype,
    cap_blackhole::CapBlackhole,
    conventions::SUBPROC_TCB,
    host_paging::{
        HostPageTableManager, HostPagingContext, HostPagingService, SMALL_PAGE_SIZE_BITS,
    },
    misc::now_cycles,
    untyped::UntypedCap,
    vmmsvc::VmPagingMode,
};
use sel4::{
    CNodeCapData, CPtr, CapRights, IpcBuffer, MessageInfo, ObjectBlueprint, ObjectBlueprintX86,
    VmAttributes,
    cap::{CNode, Endpoint, Tcb},
    sys::{
        seL4_Fault_tag, seL4_UnknownSyscall_Msg, seL4_UserContext,
        seL4_UserException_Msg::{self, seL4_UserException_Code, seL4_UserException_Number},
        seL4_VMFault_Msg::{seL4_VMFault_Addr, seL4_VMFault_FSR},
    },
};

use crate::{
    dump::dump_state,
    paging::{L0CNodeInfo, VmPagingContext},
    pv::{
        patch_point::PatchPoint,
        swtlb::{GUEST_TOP, WriteProtect},
    },
    x86_exception,
};

use super::{patch_point::PatchPointSet, ptw::PageTableWalker, swtlb::Swtlb};

// static TRIGGER: AtomicBool = AtomicBool::new(false);

const IA32_EFER: u32 = 0xc000_0080;
const IA32_LSTAR_MSR: u32 = 0xc000_0082;
const IA32_STAR_MSR: u32 = 0xc000_0081;
const IA32_CSTAR_MSR: u32 = 0xc000_0083;
const IA32_FMASK_MSR: u32 = 0xc000_0084;
const MSR_FS_BASE: u32 = 0xc000_0100;
const MSR_GS_BASE: u32 = 0xc000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

const FAULT_IPC_BADGE: u64 = 1 << 63;
const UCTX_NUM_REGS: usize = core::mem::size_of::<seL4_UserContext>() / core::mem::size_of::<u64>();

enum EmulateInsnResult {
    Passthrough,
    Continue,
    Fault,
}

pub struct PvVcpu {
    tcb: Tcb,
    paging: &'static VmPagingContext<'static>,
    patch_point_set: PatchPointSet,
    swtlb: Swtlb,
    fault_endpoint: Endpoint,
    state: VcpuState,
    fault: VcpuFault,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    efer: u64,
    lstar: u64,
    star: u64,
    cstar: u64,
    fmask: u64,
    cpl: u8,
    gdtr: (u64, u16),
    idtr: (u64, u16),
    tr: (u64, u16),
    uctx: seL4_UserContext,
    uctx_valid_length: usize,
    priority: u8,
    pending_interrupts: InterruptBitmap,
    reply_protocol: ReplyProtocol,
    tsc_freq_mhz: u32,
    ua: &'static RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
    shared_page: &'static mut PvSharedPage,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
enum ReplyProtocol {
    NoReply,
    ReplyEmpty,
    ReplyUserError,
    ReplySyscall,
}

#[repr(C)]
pub struct PvSharedPage {
    pub flags: u64,
    pub kernel_gs: u64,
    pub interrupt_window_requested: u64,
}

#[derive(Copy, Clone, Debug)]
pub struct GdtEntry {
    pub base: u64,
    pub limit: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct PvVcpuContext {
    pub affinity: u32,
    pub tsc_freq_mhz: u32,
    pub priority: u8,
}

impl PvVcpu {
    pub fn new_boxed(
        ipc: &mut IpcBuffer,
        cspace: CNode,
        l0c: L0CNodeInfo,
        ua: &'static RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
        paging: &'static VmPagingContext<'static>,
        host_paging: &HostPagingContext,
        patch_point_set: PatchPointSet,
        ctx: PvVcpuContext,
    ) -> Box<Self> {
        assert_eq!(paging.ps.borrow().config().mode, VmPagingMode::Pv);
        let mut me = unsafe { Box::<PvVcpu>::new_zeroed().assume_init() };
        me.paging = paging;
        unsafe {
            core::ptr::write(&mut me.patch_point_set, patch_point_set);
        }
        me.ua = ua;
        let blackhole = CapBlackhole::new(ipc, cspace, ua);
        unsafe {
            core::ptr::write(
                &mut me.swtlb,
                Swtlb::new(ipc, paging.ps.borrow().vmpml4(), ua, blackhole, l0c),
            );
        }
        me.tcb = Tcb::from_bits(
            ua.borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("alloc failed"),
        );
        alloc_and_retype(ipc, ua, cspace, &ObjectBlueprint::Tcb, me.tcb.cptr())
            .expect("alloc_and_retype failed");
        me.fault_endpoint = Endpoint::from_bits(
            ua.borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("alloc failed"),
        );
        me.uctx_valid_length = UCTX_NUM_REGS;
        me.efer = (1 << 8) | (1 << 10); // LME, LMA
        me.tsc_freq_mhz = ctx.tsc_freq_mhz;
        alloc_and_retype(
            ipc,
            ua,
            cspace,
            &ObjectBlueprint::Endpoint,
            me.fault_endpoint.cptr(),
        )
        .expect("alloc_and_retype failed");

        let dummy_cnode = CNode::from_bits(
            ua.borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("alloc failed"),
        );

        alloc_and_retype(
            ipc,
            ua,
            cspace,
            &ObjectBlueprint::CNode { size_bits: 1 },
            dummy_cnode.cptr(),
        )
        .expect("alloc_and_retype failed");
        assert_eq!(
            ipc.inner_mut().seL4_CNode_Mint(
                dummy_cnode.bits(),
                0,
                1,
                cspace.bits(),
                me.fault_endpoint.bits(),
                64,
                CapRights::new(true, false, false, true).into_inner(),
                FAULT_IPC_BADGE,
            ),
            0
        );
        assert_eq!(
            ipc.inner_mut().seL4_TCB_Configure(
                me.tcb.bits(),
                0,
                dummy_cnode.bits(),
                CNodeCapData::new(0, 63).into_word(),
                paging.ps.borrow().vmpml4().bits(),
                0,
                0,
                0
            ),
            0
        );
        assert_eq!(
            ipc.inner_mut().seL4_TCB_SetSchedParams(
                me.tcb.bits(),
                SUBPROC_TCB.bits(),
                ctx.priority as _,
                ctx.priority as _,
            ),
            0
        );
        me.priority = ctx.priority;

        // intentionally do not check errors
        ipc.inner_mut()
            .seL4_TCB_SetAffinity(me.tcb.bits(), ctx.affinity.into());

        // allocate pv shared page
        let guest_pv_shared_page_addr = GUEST_TOP;
        HostPageTableManager::new()
            .allocate(
                ipc,
                guest_pv_shared_page_addr,
                3,
                &mut HostPagingService {
                    alloc: ua,
                    cspace,
                    hostpml4: paging.ps.borrow().vmpml4(),
                    skip_pdpt: false,
                    utlist: LinkedList::new(UntypedInfoAdapter::NEW),
                },
            )
            .expect("Failed to allocate paging structures for pv shared page");
        let pv_shared_page = host_paging.alloc_unmapped_page(ipc);
        let page_cap = CPtr::from_bits(
            ua.borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("alloc failed"),
        );
        alloc_and_retype(
            ipc,
            ua,
            cspace,
            &ObjectBlueprint::Arch(ObjectBlueprintX86::_4k),
            page_cap,
        )
        .expect("alloc_and_retype failed");
        let page_cap_copy = CPtr::from_bits(
            ua.borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("alloc failed"),
        );
        assert_eq!(
            ipc.inner_mut().seL4_CNode_Copy(
                cspace.bits(),
                page_cap_copy.bits(),
                64,
                cspace.bits(),
                page_cap.bits(),
                64,
                CapRights::read_write().into_inner()
            ),
            0
        );
        assert_eq!(
            ipc.inner_mut().seL4_X86_Page_Map(
                page_cap.bits(),
                paging.ps.borrow().vmpml4().bits(),
                guest_pv_shared_page_addr,
                CapRights::read_write().into_inner(),
                VmAttributes::DEFAULT.into_inner()
            ),
            0
        );
        assert_eq!(
            ipc.inner_mut().seL4_X86_Page_Map(
                page_cap_copy.bits(),
                host_paging.hostpml4().bits(),
                pv_shared_page.addr().get() as u64,
                CapRights::read_write().into_inner(),
                VmAttributes::DEFAULT.into_inner()
            ),
            0
        );
        me.shared_page = unsafe { &mut *pv_shared_page.as_ptr().cast::<PvSharedPage>() };
        me
    }

    fn idt_dispatch(&mut self, vector: u8, code: Option<u64>) {
        let offset = self.idtr.0 as usize;
        let size = self.idtr.1 as usize + 1;
        let entry = offset + vector as usize * 16;
        if entry + 16 > offset + size {
            panic!("IDT entry out of bounds, vector {}", vector);
        }
        let ptw = PageTableWalker {
            paging: self.paging,
            cr3: self.cr3,
        };
        let mut idt_entry = [0u8; 16];
        ptw.read(entry, &mut idt_entry);
        let idt_entry = u128::from_ne_bytes(idt_entry);
        if !idt_entry.bit(47) {
            panic!("IDT entry not present, vector {}", vector);
        }
        let offset_high: u64 = idt_entry.bit_range(95, 48);
        let offset_low: u64 = idt_entry.bit_range(15, 0);
        let offset = (offset_high << 16) | offset_low;
        let ist_index: u64 = idt_entry.bit_range(34, 32);
        assert_ne!(ist_index, 0, "IDT entry has IST index 0, vector {}", vector);
        let ist = self.read_tss_ist(ist_index as usize);
        let gate_type: u64 = idt_entry.bit_range(43, 40);
        assert_eq!(
            gate_type, 0xe,
            "IDT entry not interrupt gate, vector {}",
            vector
        );
        // XXX: DPL check skipped

        // let old_cpl = self.cpl;

        // Push RSP, RFLAGS, CS, RIP, (optionally code)
        let mut flags = self.uctx.rflags;
        flags.set_bit(9, self.shared_page.flags.bit(9));
        let mut push = [0u8; 40];
        push[0..8].copy_from_slice(&code.unwrap_or_default().to_ne_bytes());
        push[8..16].copy_from_slice(&self.uctx.rip.to_ne_bytes());
        // TODO: do not hard code CS selector 0x08
        push[16..24].copy_from_slice(&(self.cpl as u64 | 0x08).to_ne_bytes());
        push[24..32].copy_from_slice(&flags.to_ne_bytes());
        push[32..40].copy_from_slice(&self.uctx.rsp.to_ne_bytes());
        self.uctx.rip = offset;
        self.uctx.rsp = ist;
        self.cpl = 0;
        self.shared_page.flags.set_bit(9, false);
        if code.is_some() {
            self.uctx.rsp -= 40;
            ptw.write(self.uctx.rsp as usize, &push);
        } else {
            self.uctx.rsp -= 32;
            ptw.write(self.uctx.rsp as usize, &push[8..]);
        }

        self.reply_protocol = ReplyProtocol::NoReply;

        // println!(
        //     "IDT dispatch: vector = {}, rip = {:#x}, rsp = {:#x}, code = {:?}, old cpl = {}",
        //     vector, self.uctx.rip, self.uctx.rsp, code, old_cpl
        // );
    }

    fn read_tss_ist(&self, n: usize) -> u64 {
        assert!(n >= 1 && n <= 7);
        let ptw = PageTableWalker {
            paging: self.paging,
            cr3: self.cr3,
        };
        let tss = self.tr.0 as usize;
        assert_eq!(self.tr.1, 0x68);
        let mut ist = [0u8; 8];
        ptw.try_read(tss + 0x24 + (n - 1) * 8, &mut ist)
            .unwrap_or_else(|_| panic!("Failed to read IST {} from TSS, tss = {:#x}", n, tss));
        u64::from_ne_bytes(ist)
    }

    fn suspend_and_read_uctx(&mut self, ipc: &mut IpcBuffer) {
        assert_eq!(
            ipc.inner_mut().seL4_TCB_ReadRegisters(
                self.tcb.bits(),
                1,
                0,
                UCTX_NUM_REGS as u64,
                &mut self.uctx,
            ),
            0
        );
        self.uctx_valid_length = UCTX_NUM_REGS;
    }

    fn read_uctx(&mut self, ipc: &mut IpcBuffer) {
        assert_eq!(
            ipc.inner_mut().seL4_TCB_ReadRegisters(
                self.tcb.bits(),
                0,
                0,
                UCTX_NUM_REGS as u64,
                &mut self.uctx,
            ),
            0
        );
        self.uctx_valid_length = UCTX_NUM_REGS;
    }

    fn getreg(&self, reg: Register) -> Option<u64> {
        match reg {
            Register::RAX => Some(self.uctx.rax),
            Register::EAX => Some(self.uctx.rax as u32 as u64),
            Register::RCX => Some(self.uctx.rcx),
            Register::ECX => Some(self.uctx.rcx as u32 as u64),
            Register::RDI => Some(self.uctx.rdi),
            Register::EDI => Some(self.uctx.rdi as u32 as u64),
            Register::RBP => Some(self.uctx.rbp),
            _ => None,
        }
    }

    fn setreg(&mut self, reg: Register, value: u64) -> bool {
        match reg {
            Register::RAX => self.uctx.rax = value,
            Register::RCX => self.uctx.rcx = value,
            Register::RDI => self.uctx.rdi = value,
            Register::RBP => self.uctx.rbp = value,
            _ => return false,
        }
        true
    }

    fn read_gdt(&self, ptw: &PageTableWalker, selector: u32, long: bool) -> Option<GdtEntry> {
        let gdt_limit = self.gdtr.1 as u32 + 1;
        if selector & 0x7 == 0 && selector.saturating_add(if long { 16 } else { 8 }) <= gdt_limit {
            let mut descriptor_bytes = [0u8; 16];
            ptw.read(
                self.gdtr.0 as usize + selector as usize,
                if long {
                    &mut descriptor_bytes
                } else {
                    &mut descriptor_bytes[0..8]
                },
            );
            let descriptor = u64::from_ne_bytes(descriptor_bytes[..8].try_into().unwrap());
            let limit_low: u32 = descriptor.bit_range(15, 0);
            let limit_high: u32 = descriptor.bit_range(51, 48);
            let base_low: u32 = descriptor.bit_range(39, 16);
            let base_high: u32 = descriptor.bit_range(63, 56);
            let mut base = ((base_high << 24) | base_low) as u64;
            let limit = (limit_high << 16) | limit_low;

            if long {
                base |=
                    (u32::from_ne_bytes(descriptor_bytes[8..12].try_into().unwrap()) as u64) << 32;
            }
            return Some(GdtEntry { base, limit });
        }
        None
    }
    // fn emulate_lgdt(&mut self, )

    fn patch_ud_nouctx(
        &mut self,
        ipc: &mut IpcBuffer,
        did_read_uctx: &mut bool,
    ) -> EmulateInsnResult {
        self.uctx.rip = ipc.msg_regs()[seL4_UserException_Msg::seL4_UserException_FaultIP as usize];
        self.uctx.rsp = ipc.msg_regs()[seL4_UserException_Msg::seL4_UserException_SP as usize];
        self.uctx.rflags =
            ipc.msg_regs()[seL4_UserException_Msg::seL4_UserException_FLAGS as usize] as u64;

        let ptw = PageTableWalker {
            paging: self.paging,
            cr3: self.cr3,
        };
        let Some((paddr, _)) = ptw.try_lookup_guest_phys(self.uctx.rip as usize) else {
            return EmulateInsnResult::Passthrough;
        };
        let Some((pp, insn_len)) = self.patch_point_set.patch_points.get(&paddr) else {
            return EmulateInsnResult::Passthrough;
        };
        assert!(*insn_len > 0);
        let pp = *pp;
        let insn_len = *insn_len;

        // println!("patchpoint @ {:#x}: {:?} {}", paddr, pp, insn_len);
        match pp {
            PatchPoint::Pushfq => {
                let mut flags: u64 = self.uctx.rflags;
                flags.set_bit(9, self.shared_page.flags.bit(9));
                self.uctx.rsp -= 8;
                ptw.write(self.uctx.rsp as usize, &flags.to_ne_bytes());
                self.reply_protocol = ReplyProtocol::ReplyUserError;
                self.uctx.rip += insn_len as u64;
                EmulateInsnResult::Continue
            }
            PatchPoint::Popfq => {
                let mut flags = [0u8; 8];
                ptw.read(self.uctx.rsp as usize, &mut flags);
                self.uctx.rflags = u64::from_ne_bytes(flags);
                self.shared_page.flags.set_bit(9, self.uctx.rflags.bit(9));
                self.uctx.rsp += 8;
                self.reply_protocol = ReplyProtocol::ReplyUserError;
                self.uctx.rip += insn_len as u64;
                EmulateInsnResult::Continue
            }
            PatchPoint::SidtRax => {
                let mut data = [0u8; 10];
                data[0..2].copy_from_slice(&self.idtr.1.to_ne_bytes());
                data[2..10].copy_from_slice(&self.idtr.0.to_ne_bytes());
                self.read_uctx(ipc);
                *did_read_uctx = true;
                ptw.write(self.uctx.rax as usize, &data);
                self.uctx.rip += insn_len as u64;
                // println!(
                //     "SidtRax: idtr = {:#x}, limit = {:#x}, output = {:#x}",
                //     self.idtr.0, self.idtr.1, self.uctx.rax
                // );
                EmulateInsnResult::Continue
            }
            PatchPoint::Cpuid => {
                self.fault.reason = 10;
                self.fault.instruction_len = insn_len as u64;
                EmulateInsnResult::Fault
            }
            PatchPoint::Iretq => {
                let mut pop = [0u8; 32];
                ptw.read(self.uctx.rsp as usize, &mut pop);

                let cs = u64::from_ne_bytes(pop[8..16].try_into().unwrap());
                self.uctx.rip = u64::from_ne_bytes(pop[0..8].try_into().unwrap());
                self.cpl = (cs & 3) as u8;
                self.uctx.rflags = u64::from_ne_bytes(pop[16..24].try_into().unwrap());
                self.uctx.rsp = u64::from_ne_bytes(pop[24..32].try_into().unwrap());
                self.shared_page.flags.set_bit(9, self.uctx.rflags.bit(9));
                if cs != 0x8 && cs != 0xb {
                    panic!("iretq to invalid cs: {:#x}, rip = {:#x}", cs, self.uctx.rip);
                }
                if self.cpl == 3 && !self.uctx.rflags.bit(9) {
                    panic!(
                        "iretq to ring 3 with interrupts disabled, rip = {:#x}",
                        self.uctx.rip
                    );
                }
                // TODO: interrupt window
                self.reply_protocol = ReplyProtocol::ReplyUserError;
                return EmulateInsnResult::Continue;
            }
            _ => {
                println!("unhandled patchpoint @ {:#x}: {:?} {}", paddr, pp, insn_len);
                self.read_uctx(ipc);
                *did_read_uctx = true;
                self.idt_dispatch(6, None);
                EmulateInsnResult::Continue
            }
        }
    }

    fn emulate_insn(&mut self, ipc: &mut IpcBuffer) -> EmulateInsnResult {
        const MAX_INSN_LEN: usize = 15;
        let mut insn = [0u8; MAX_INSN_LEN];
        let mut valid_insn_len: usize = 0;
        let ptw = PageTableWalker {
            paging: self.paging,
            cr3: self.cr3,
        };
        for i in (1..=MAX_INSN_LEN).rev() {
            if ptw.try_read(self.uctx.rip as usize, &mut insn[..i]).is_ok() {
                valid_insn_len = i;
                break;
            }
        }
        if valid_insn_len == 0 {
            println!("failed to read instruction at {:#x}", self.uctx.rip);
            return EmulateInsnResult::Passthrough;
        }
        let raw_insn = &insn[..valid_insn_len];
        let mut decoder = Decoder::with_ip(64, raw_insn, self.uctx.rip, 0);
        let insn = decoder.decode();
        if insn.is_invalid() {
            println!(
                "invalid instruction at {:#x}: {:x?}",
                self.uctx.rip, raw_insn
            );
            return EmulateInsnResult::Passthrough;
        }
        self.fault.instruction_len = insn.len() as u64;

        if self.cpl != 0 {
            println!("not emulating insn in non-privileged mode: {:?}", insn);
            return EmulateInsnResult::Passthrough;
        }

        match insn.code() {
            Code::In_AL_DX | Code::In_AX_DX | Code::In_EAX_DX => {
                self.fault.reason = 30;
                self.fault.qualification = 0;
                self.fault.qualification.set_bit_range(
                    1,
                    0,
                    match insn.code() {
                        Code::In_AL_DX => 0,
                        Code::In_AX_DX => 1,
                        Code::In_EAX_DX => 3,
                        _ => unreachable!(),
                    },
                );
                self.fault.qualification.set_bit(3, true); // Direction: IN
                self.fault
                    .qualification
                    .set_bit_range(31, 16, self.uctx.rdx as u16);
                // println!("IN AL, DX, port = {:#x}", self.uctx.rdx);
                return EmulateInsnResult::Fault;
            }
            Code::In_AL_imm8 | Code::In_AX_imm8 | Code::In_EAX_imm8 => {
                self.fault.reason = 30;
                self.fault.qualification = 0;
                self.fault.qualification.set_bit_range(
                    1,
                    0,
                    match insn.code() {
                        Code::In_AL_imm8 => 0,
                        Code::In_AX_imm8 => 1,
                        Code::In_EAX_imm8 => 3,
                        _ => unreachable!(),
                    },
                );
                self.fault.qualification.set_bit(3, true); // Direction: IN
                self.fault
                    .qualification
                    .set_bit_range(31, 16, insn.immediate8() as u16);
                // println!("IN AL, DX, port = {:#x}", self.uctx.rdx);
                return EmulateInsnResult::Fault;
            }
            Code::Out_DX_AL | Code::Out_DX_AX | Code::Out_DX_EAX => {
                self.fault.reason = 30;
                self.fault.qualification = 0;
                self.fault.qualification.set_bit_range(
                    1,
                    0,
                    match insn.code() {
                        Code::Out_DX_AL => 0,
                        Code::Out_DX_AX => 1,
                        Code::Out_DX_EAX => 3,
                        _ => unreachable!(),
                    },
                );
                self.fault.qualification.set_bit(3, false); // Direction: OUT
                self.fault
                    .qualification
                    .set_bit_range(31, 16, self.uctx.rdx as u16);
                return EmulateInsnResult::Fault;
            }
            Code::Out_imm8_AL | Code::Out_imm8_AX | Code::Out_imm8_EAX => {
                self.fault.reason = 30;
                self.fault.qualification = 0;
                self.fault.qualification.set_bit_range(
                    1,
                    0,
                    match insn.code() {
                        Code::Out_imm8_AL => 0,
                        Code::Out_imm8_AX => 1,
                        Code::Out_imm8_EAX => 3,
                        _ => unreachable!(),
                    },
                );
                self.fault.qualification.set_bit(3, false); // Direction: OUT
                self.fault
                    .qualification
                    .set_bit_range(31, 16, insn.immediate8() as u16);
                return EmulateInsnResult::Fault;
            }
            Code::Mov_r64_cr => {
                if insn.op1_register() == Register::CR0 {
                    if self.setreg(insn.op0_register(), self.cr0) {
                        self.uctx.rip = insn.next_ip();
                        return EmulateInsnResult::Continue;
                    }
                }
                if insn.op1_register() == Register::CR2 {
                    if self.setreg(insn.op0_register(), self.cr2) {
                        self.uctx.rip = insn.next_ip();
                        return EmulateInsnResult::Continue;
                    }
                }
                if insn.op1_register() == Register::CR3 {
                    if self.setreg(insn.op0_register(), self.cr3) {
                        self.uctx.rip = insn.next_ip();
                        return EmulateInsnResult::Continue;
                    }
                }
                if insn.op1_register() == Register::CR4 {
                    if self.setreg(insn.op0_register(), self.cr4) {
                        self.uctx.rip = insn.next_ip();
                        return EmulateInsnResult::Continue;
                    }
                }
            }
            Code::Mov_cr_r64 => {
                if insn.op0_register() == Register::CR0 {
                    if let Some(x) = self.getreg(insn.op1_register()) {
                        let wp_change = x.bit(16) != self.cr0.bit(16);
                        self.cr0 = x;
                        println!("mov CR0, {:#x}", x);
                        if wp_change {
                            self.swtlb.shootdown(ipc, self.ua, 0, 0x8000_0000_0000);
                            println!("shooting down swtlb because of CR0 WP change");
                        }
                        self.uctx.rip = insn.next_ip();
                        return EmulateInsnResult::Continue;
                    }
                }
                if insn.op0_register() == Register::CR3 {
                    if let Some(x) = self.getreg(insn.op1_register()) {
                        self.cr3 = x;
                        let start_time = now_cycles();
                        let start_syscalls = self.swtlb.syscall_counter();
                        self.swtlb.shootdown(ipc, self.ua, 0, 0x8000_0000_0000);
                        let end_time = now_cycles();
                        let end_syscalls = self.swtlb.syscall_counter();
                        let duration = Duration::from_micros(
                            (end_time - start_time) / self.tsc_freq_mhz as u64,
                        );
                        if duration > Duration::from_millis(1) {
                            println!(
                                "slow mov CR3, {:#x} took {:?}, {} syscalls, {:?} per syscall",
                                x,
                                duration,
                                end_syscalls - start_syscalls,
                                duration / (end_syscalls - start_syscalls) as u32,
                            );
                        }
                        self.uctx.rip = insn.next_ip();
                        return EmulateInsnResult::Continue;
                    }
                }
                if insn.op0_register() == Register::CR4 {
                    if let Some(x) = self.getreg(insn.op1_register()) {
                        self.cr4 = x;
                        println!("mov CR4, {:#x}", x);
                        self.uctx.rip = insn.next_ip();
                        return EmulateInsnResult::Continue;
                    }
                }
            }
            Code::Rdmsr => {
                self.fault.reason = 31;
                return EmulateInsnResult::Fault;
            }
            Code::Wrmsr => {
                self.fault.reason = 32;
                return EmulateInsnResult::Fault;
            }
            Code::Cli => {
                self.shared_page.flags.set_bit(9, false);
                self.uctx.rip = insn.next_ip();
                return EmulateInsnResult::Continue;
            }
            Code::Sti => {
                // Detect "sti; hlt;" sequence
                self.shared_page.flags.set_bit(9, true);
                self.uctx.rip = insn.next_ip();

                let next = decoder.decode();
                if next.code() == Code::Hlt {
                    self.fault.reason = 12;
                    return EmulateInsnResult::Fault;
                } else if !self.pending_interrupts.is_empty() {
                    // interrupt window
                    // println!("sti: pending interrupts");
                    self.fault.reason = 7;
                    return EmulateInsnResult::Fault;
                } else {
                    return EmulateInsnResult::Continue;
                }
            }
            Code::Invlpg_m => {
                // XXX: only works correctly for 4kb pages
                if let Some(addr) = self.getreg(insn.memory_base()) {
                    let start_va = addr & !((1 << SMALL_PAGE_SIZE_BITS) - 1);
                    let end_va = start_va + (1 << SMALL_PAGE_SIZE_BITS);
                    self.swtlb
                        .shootdown(ipc, self.ua, start_va as usize, end_va as usize);
                    self.uctx.rip = insn.next_ip();
                    return EmulateInsnResult::Continue;
                }
            }
            Code::Xsetbv => {
                self.fault.reason = 55;
                return EmulateInsnResult::Fault;
            }
            Code::Lgdt_m1664 => {
                if let Some(addr) = self.getreg(insn.memory_base()) {
                    let addr = addr.wrapping_add(insn.memory_displacement64());
                    let mut gdt = [0u8; 10];
                    ptw.read(addr as usize, &mut gdt);
                    self.gdtr.0 = u64::from_ne_bytes(gdt[2..10].try_into().unwrap());
                    self.gdtr.1 = u16::from_ne_bytes(gdt[0..2].try_into().unwrap());
                    println!("lgdt: gdt = {:#x}, limit = {:#x}", self.gdtr.0, self.gdtr.1);
                    self.uctx.rip = insn.next_ip();
                    return EmulateInsnResult::Continue;
                }
            }
            Code::Lidt_m1664 => {
                if let Some(addr) = self.getreg(insn.memory_base()) {
                    let addr = addr.wrapping_add(insn.memory_displacement64());
                    let mut idt = [0u8; 10];
                    ptw.read(addr as usize, &mut idt);
                    self.idtr.0 = u64::from_ne_bytes(idt[2..10].try_into().unwrap());
                    self.idtr.1 = u16::from_ne_bytes(idt[0..2].try_into().unwrap());
                    println!("lidt: idt = {:#x}, limit = {:#x}", self.idtr.0, self.idtr.1);
                    self.uctx.rip = insn.next_ip();
                    return EmulateInsnResult::Continue;
                }
            }
            Code::Ltr_r32m16 => {
                if let Some(selector) = self.getreg(insn.op0_register()) {
                    if let Some(entry) = self.read_gdt(&ptw, selector as u32, true) {
                        if let Ok(limit) = u16::try_from(entry.limit) {
                            self.tr.0 = entry.base;
                            self.tr.1 = limit;
                            println!("ltr: base = {:#x}, limit = {:#x}", self.tr.0, self.tr.1);
                            self.uctx.rip = insn.next_ip();
                            return EmulateInsnResult::Continue;
                        }
                    }
                }
            }
            Code::Mov_Sreg_r32m16 => {
                println!(
                    "ignore mov sreg: {:?} <- {:?}",
                    insn.op0_register(),
                    insn.op1_register()
                );
                self.uctx.rip = insn.next_ip();
                return EmulateInsnResult::Continue;
            }
            Code::Retfq => {
                let mut buf = [0u8; 16];
                ptw.read(self.uctx.rsp as usize, &mut buf);
                self.uctx.rsp += 16;
                let new_ip = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
                println!("retfq: new ip = {:#x}", new_ip);
                self.uctx.rip = new_ip;
                return EmulateInsnResult::Continue;
            }
            Code::Swapgs => {
                // println!(
                //     "swapgs {:#x} -> {:#x}, rip {:#x}",
                //     self.uctx.gs_base, self.shared_page.kernel_gs, self.uctx.rip
                // );
                core::mem::swap(&mut self.shared_page.kernel_gs, &mut self.uctx.gs_base);
                self.uctx.rip = insn.next_ip();
                return EmulateInsnResult::Continue;
            }
            Code::Hlt => {
                self.fault.reason = 12;
                return EmulateInsnResult::Fault;
            }
            Code::Syscall => {
                // This is a hypercall - CPL=3 syscalls do not go here
                // XXX: for some reason this does not work
                self.fault.reason = 18;
                // println!(
                //     "hypercall: rip = {:#x}, rax = {:#x}",
                //     self.uctx.rip, self.uctx.rax
                // );
                return EmulateInsnResult::Fault;
            }
            Code::Sysretq => {
                let cs: u16 = self.star.bit_range(63, 48);
                self.cpl = (cs & 3) as u8;
                // println!(
                //     "sysretq: rip = {:#x} -> {:#x}, rax = {:#x}, new cpl {}",
                //     self.uctx.rip, self.uctx.rcx, self.uctx.rax, self.cpl
                // );
                self.uctx.rip = self.uctx.rcx;
                self.uctx.rflags = self.uctx.r11;
                self.uctx.rflags.set_bit(9, true);
                self.shared_page.flags.set_bit(9, true);
                if !self.pending_interrupts.is_empty() {
                    self.fault.reason = 7;
                    return EmulateInsnResult::Fault;
                }
                return EmulateInsnResult::Continue;
            }
            _ => {}
        }

        println!("did not emulate insn: {:?}", insn);
        EmulateInsnResult::Passthrough
    }
}

impl AbstractVcpu for PvVcpu {
    type Context = IpcBuffer;

    fn state(&self) -> &VcpuState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut VcpuState {
        &mut self.state
    }

    fn fault(&self) -> &VcpuFault {
        &self.fault
    }

    fn fault_mut(&mut self) -> &mut VcpuFault {
        &mut self.fault
    }

    #[inline]
    fn load_state(&mut self, _: &mut IpcBuffer, mut regs: VcpuStateMask) {
        let mut cmov = |m: VcpuStateMask, src: &u64, dst: &mut u64| {
            if regs.contains(m) {
                regs.remove(m);
                self.state.valid |= m;
                *dst = *src;
            }
        };
        let mut rflags = self.uctx.rflags;
        rflags.set_bit(9, self.shared_page.flags.bit(9));
        cmov(VcpuStateMask::EIP, &self.uctx.rip, &mut self.state.eip);
        cmov(VcpuStateMask::ESP, &self.uctx.rsp, &mut self.state.esp);
        cmov(VcpuStateMask::RFLAGS, &rflags, &mut self.state.rflags);
        cmov(VcpuStateMask::EAX, &self.uctx.rax, &mut self.state.eax);
        cmov(VcpuStateMask::EBX, &self.uctx.rbx, &mut self.state.ebx);
        cmov(VcpuStateMask::ECX, &self.uctx.rcx, &mut self.state.ecx);
        cmov(VcpuStateMask::EDX, &self.uctx.rdx, &mut self.state.edx);
        cmov(VcpuStateMask::ESI, &self.uctx.rsi, &mut self.state.esi);
        cmov(VcpuStateMask::EDI, &self.uctx.rdi, &mut self.state.edi);
        cmov(VcpuStateMask::EBP, &self.uctx.rbp, &mut self.state.ebp);
        cmov(VcpuStateMask::R8, &self.uctx.r8, &mut self.state.r8);
        cmov(VcpuStateMask::R9, &self.uctx.r9, &mut self.state.r9);
        cmov(VcpuStateMask::R10, &self.uctx.r10, &mut self.state.r10);
        cmov(VcpuStateMask::R11, &self.uctx.r11, &mut self.state.r11);
        cmov(VcpuStateMask::R12, &self.uctx.r12, &mut self.state.r12);
        cmov(VcpuStateMask::R13, &self.uctx.r13, &mut self.state.r13);
        cmov(VcpuStateMask::R14, &self.uctx.r14, &mut self.state.r14);
        cmov(VcpuStateMask::R15, &self.uctx.r15, &mut self.state.r15);
        cmov(VcpuStateMask::CR0, &self.cr0, &mut self.state.cr0);
        cmov(VcpuStateMask::CR3, &self.cr3, &mut self.state.cr3);
        cmov(VcpuStateMask::CR4, &self.cr4, &mut self.state.cr4);

        if regs.contains(VcpuStateMask::ACTIVITY_STATE) {
            regs.remove(VcpuStateMask::ACTIVITY_STATE);
            self.state.activity_state = 0;
        }

        if regs.contains(VcpuStateMask::CS_ACCESS_RIGHTS) {
            regs.remove(VcpuStateMask::CS_ACCESS_RIGHTS);
            self.state.cs_access_rights = (self.cpl as u32) << 5;
        }

        if !regs.is_empty() {
            panic!("did not load state bits: {:?}", regs);
        }
    }

    #[inline]
    fn commit_state(&mut self, _ipc: &mut IpcBuffer, mut regs: VcpuStateMask) {
        let mut cmov = |m: VcpuStateMask, src: &u64, dst: &mut u64| {
            if regs.contains(m) {
                regs.remove(m);
                *dst = *src;
            }
        };
        cmov(VcpuStateMask::EIP, &self.state.eip, &mut self.uctx.rip);
        cmov(VcpuStateMask::ESP, &self.state.esp, &mut self.uctx.rsp);
        cmov(
            VcpuStateMask::RFLAGS,
            &self.state.rflags,
            &mut self.uctx.rflags,
        );
        cmov(VcpuStateMask::EAX, &self.state.eax, &mut self.uctx.rax);
        cmov(VcpuStateMask::EBX, &self.state.ebx, &mut self.uctx.rbx);
        cmov(VcpuStateMask::ECX, &self.state.ecx, &mut self.uctx.rcx);
        cmov(VcpuStateMask::EDX, &self.state.edx, &mut self.uctx.rdx);
        cmov(VcpuStateMask::ESI, &self.state.esi, &mut self.uctx.rsi);
        cmov(VcpuStateMask::EDI, &self.state.edi, &mut self.uctx.rdi);
        cmov(VcpuStateMask::EBP, &self.state.ebp, &mut self.uctx.rbp);
        cmov(VcpuStateMask::R8, &self.state.r8, &mut self.uctx.r8);
        cmov(VcpuStateMask::R9, &self.state.r9, &mut self.uctx.r9);
        cmov(VcpuStateMask::R10, &self.state.r10, &mut self.uctx.r10);
        cmov(VcpuStateMask::R11, &self.state.r11, &mut self.uctx.r11);
        cmov(VcpuStateMask::R12, &self.state.r12, &mut self.uctx.r12);
        cmov(VcpuStateMask::R13, &self.state.r13, &mut self.uctx.r13);
        cmov(VcpuStateMask::R14, &self.state.r14, &mut self.uctx.r14);
        cmov(VcpuStateMask::R15, &self.state.r15, &mut self.uctx.r15);
        cmov(VcpuStateMask::CR0, &self.state.cr0, &mut self.cr0);
        cmov(VcpuStateMask::CR3, &self.state.cr3, &mut self.cr3);
        cmov(VcpuStateMask::CR4, &self.state.cr4, &mut self.cr4);
        if !regs.is_empty() {
            panic!("uncommitted state bits: {:?}", regs);
        }
    }

    fn inject_exception(&mut self, _: &mut IpcBuffer, exc: VcpuException) {
        match exc {
            VcpuException::GeneralProtectionFault(code) => {
                self.idt_dispatch(x86_exception::GP, Some(code as u64));
            }
            VcpuException::InvalidOpcode => {
                self.idt_dispatch(x86_exception::UD, None);
            }
        }
    }

    fn inject_external_interrupt(&mut self, _ipc: &mut IpcBuffer, intr: u8) {
        self.pending_interrupts.activate(intr);
    }

    fn external_interrupt_pending(&self) -> bool {
        !self.pending_interrupts.is_empty()
    }

    fn read_msr(&mut self, _: &mut IpcBuffer, msr: u32) -> Option<u64> {
        match msr {
            self::IA32_EFER => Some(self.efer),
            self::IA32_LSTAR_MSR => Some(self.lstar),
            self::IA32_STAR_MSR => Some(self.star),
            self::IA32_CSTAR_MSR => Some(self.cstar),
            self::IA32_FMASK_MSR => Some(self.fmask),
            self::MSR_FS_BASE => Some(self.uctx.fs_base),
            self::MSR_GS_BASE => Some(self.uctx.gs_base),
            self::MSR_KERNEL_GS_BASE => Some(self.shared_page.kernel_gs),
            _ => None,
        }
    }

    fn write_msr(&mut self, _: &mut IpcBuffer, msr: u32, value: u64) -> Option<u64> {
        match msr {
            self::IA32_EFER => {
                self.efer = value;
                Some(self.efer)
            }
            self::IA32_LSTAR_MSR => {
                self.lstar = value;
                Some(self.lstar)
            }
            self::IA32_STAR_MSR => {
                self.star = value;
                Some(self.star)
            }
            self::IA32_CSTAR_MSR => {
                self.cstar = value;
                Some(self.cstar)
            }
            self::IA32_FMASK_MSR => {
                self.fmask = value;
                Some(self.fmask)
            }
            self::MSR_FS_BASE => {
                self.uctx.fs_base = value;
                Some(self.uctx.fs_base)
            }
            self::MSR_GS_BASE => {
                self.uctx.gs_base = value;
                Some(self.uctx.gs_base)
            }
            self::MSR_KERNEL_GS_BASE => {
                self.shared_page.kernel_gs = value;
                Some(self.shared_page.kernel_gs)
            }
            _ => None,
        }
    }

    fn lgdt(&mut self, _: &mut IpcBuffer, _: u64, _: u16) {
        todo!()
    }

    fn enter(&mut self, ipc: &mut IpcBuffer) -> (bool, u64) {
        self.shared_page.interrupt_window_requested = 0;
        if !self.pending_interrupts.is_empty() {
            let intr = self.pending_interrupts.first();
            if self.shared_page.flags.bit(9) {
                self.pending_interrupts.deactivate(intr);
                // dump_state(ipc, self);
                self.idt_dispatch(intr, None);
            } else {
                self.shared_page.interrupt_window_requested = 1;
            }
        }

        let ret = loop {
            if self.uctx.rip >= 0x5000_0000_0000 && self.uctx.rip < 0x6000_0000_0000 {
                println!("strange enter: rip = {:#x}", self.uctx.rip);
                self.load_state(ipc, VcpuStateMask::reg_state());
                dump_state(ipc, self);
            }
            assert!(self.uctx_valid_length <= UCTX_NUM_REGS);
            let (msg, badge) = match self.reply_protocol {
                ReplyProtocol::NoReply => {
                    if self.uctx_valid_length > 0 {
                        assert_eq!(
                            ipc.inner_mut().seL4_TCB_WriteRegisters(
                                self.tcb.bits(),
                                1,
                                0,
                                self.uctx_valid_length as u64,
                                &self.uctx
                            ),
                            0
                        );
                    } else {
                        assert_eq!(ipc.inner_mut().seL4_TCB_Resume(self.tcb.bits()), 0);
                    }
                    ipc.inner_mut().seL4_Recv(self.fault_endpoint.bits(), ())
                }
                ReplyProtocol::ReplyEmpty => ipc.inner_mut().seL4_ReplyRecv(
                    self.fault_endpoint.bits(),
                    MessageInfo::new(0, 0, 0, 0).into_inner(),
                    (),
                ),
                ReplyProtocol::ReplyUserError => {
                    let mr = ipc.msg_regs_mut();
                    mr[seL4_UserException_Msg::seL4_UserException_FaultIP as usize] = self.uctx.rip;
                    mr[seL4_UserException_Msg::seL4_UserException_SP as usize] = self.uctx.rsp;
                    mr[seL4_UserException_Msg::seL4_UserException_FLAGS as usize] =
                        self.uctx.rflags;
                    ipc.inner_mut().seL4_ReplyRecv(
                        self.fault_endpoint.bits(),
                        MessageInfo::new(0, 0, 0, 3).into_inner(),
                        (),
                    )
                }
                ReplyProtocol::ReplySyscall => {
                    // println!("replying to syscall");
                    // self.load_state(ipc, VcpuStateMask::reg_state());
                    // dump_state(ipc, self);
                    let mr = ipc.msg_regs_mut();
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RAX as usize] = self.uctx.rax;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RBX as usize] = self.uctx.rbx;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RCX as usize] = self.uctx.rcx;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RDX as usize] = self.uctx.rdx;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RSI as usize] = self.uctx.rsi;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RDI as usize] = self.uctx.rdi;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RBP as usize] = self.uctx.rbp;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R8 as usize] = self.uctx.r8;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R9 as usize] = self.uctx.r9;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R10 as usize] = self.uctx.r10;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R11 as usize] = self.uctx.r11;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R12 as usize] = self.uctx.r12;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R13 as usize] = self.uctx.r13;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R14 as usize] = self.uctx.r14;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R15 as usize] = self.uctx.r15;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_FaultIP as usize] =
                        self.uctx.rip;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_SP as usize] = self.uctx.rsp;
                    mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_FLAGS as usize] =
                        self.uctx.rflags;
                    ipc.inner_mut().seL4_ReplyRecv(
                        self.fault_endpoint.bits(),
                        MessageInfo::new(0, 0, 0, 18).into_inner(),
                        (),
                    )
                }
            };
            self.reply_protocol = ReplyProtocol::NoReply;
            self.uctx_valid_length = 0;

            // Notification?
            if badge != FAULT_IPC_BADGE {
                self.suspend_and_read_uctx(ipc);
                // println!(
                //     "got notification, badge = {:#x}, rip = {:#x}",
                //     badge, self.uctx.rip
                // );

                // let ptw = PageTableWalker {
                //     paging: self.paging,
                //     cr3: self.cr3,
                // };
                // if let Some((paddr, _)) = ptw.try_lookup_guest_phys(self.uctx.rip as usize - 1) {
                //     if let Some(x) = self.patch_point_set.patch_points.get(&paddr) {
                //         println!(
                //             "W: suspended right after patch point: {:#x} {:?}",
                //             self.uctx.rip, x
                //         );
                //     }
                // }
                break (false, badge);
            }

            match msg.get_label() {
                seL4_Fault_tag::seL4_Fault_UnknownSyscall => {
                    // syscall emulation
                    assert_eq!(
                        msg.get_length(),
                        seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_Length
                    );
                    let mr = ipc.msg_regs();

                    // XXX: fsbase/gsbase are not present
                    self.uctx.rax = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RAX as usize];
                    self.uctx.rbx = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RBX as usize];
                    self.uctx.rcx = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RCX as usize];
                    self.uctx.rdx = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RDX as usize];
                    self.uctx.rsi = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RSI as usize];
                    self.uctx.rdi = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RDI as usize];
                    self.uctx.rbp = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_RBP as usize];
                    self.uctx.r8 = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R8 as usize];
                    self.uctx.r9 = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R9 as usize];
                    self.uctx.r10 = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R10 as usize];
                    self.uctx.r11 = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R11 as usize];
                    self.uctx.r12 = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R12 as usize];
                    self.uctx.r13 = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R13 as usize];
                    self.uctx.r14 = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R14 as usize];
                    self.uctx.r15 = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_R15 as usize];
                    self.uctx.rip =
                        mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_FaultIP as usize];
                    self.uctx.rsp = mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_SP as usize];
                    self.uctx.rflags =
                        mr[seL4_UnknownSyscall_Msg::seL4_UnknownSyscall_FLAGS as usize];
                    self.uctx_valid_length = 18;

                    if self.cpl == 0 {
                        // vmcall
                        // println!(
                        //     "krnl syscall: rip: {:#x}, rax = {:#x}, rsp = {:#x}",
                        //     self.uctx.rip, self.uctx.rax, self.uctx.rsp
                        // );

                        // This is a hypercall, we must return to RIP+2
                        self.reply_protocol = ReplyProtocol::ReplySyscall;

                        match self.emulate_insn(ipc) {
                            EmulateInsnResult::Passthrough => {}
                            EmulateInsnResult::Continue => {
                                continue;
                            }
                            EmulateInsnResult::Fault => {
                                break (true, 0);
                            }
                        }
                    } else {
                        // user syscall
                        // must not use ReplySyscall because RIP change
                        // println!(
                        //     "user syscall: rip: {:#x} -> {:#x}, rax = {:#x}",
                        //     self.uctx.rip, self.lstar, self.uctx.rax
                        // );
                        self.cpl = 0;
                        self.uctx.r11 = self.uctx.rflags;
                        self.uctx.rflags &= !self.fmask;
                        self.shared_page.flags.set_bit(9, self.uctx.rflags.bit(9));
                        // syscall/sysenter both have size 2
                        self.uctx.rcx = self.uctx.rip + 2;
                        self.uctx.rip = self.lstar;
                        continue;
                    }
                }
                seL4_Fault_tag::seL4_Fault_UserException => {
                    let intr = ipc.msg_regs()[seL4_UserException_Number as usize];
                    let code = ipc.msg_regs()[seL4_UserException_Code as usize];
                    assert!(intr < 32);
                    let intr = intr as u8;
                    let mut did_read_uctx = false;
                    let res = if self.cpl == 0 && intr == 13 {
                        // println!("user exception, insn emulation, vector {}", intr);
                        did_read_uctx = true;
                        self.read_uctx(ipc);
                        self.emulate_insn(ipc)
                    } else if self.cpl == 0 && intr == 6 {
                        self.patch_ud_nouctx(ipc, &mut did_read_uctx)
                    } else {
                        EmulateInsnResult::Passthrough
                    };
                    match res {
                        EmulateInsnResult::Passthrough => {
                            if !did_read_uctx {
                                self.read_uctx(ipc);
                            }
                        }
                        EmulateInsnResult::Continue => {
                            assert!(
                                did_read_uctx
                                    || !matches!(self.reply_protocol, ReplyProtocol::NoReply)
                            );
                            continue;
                        }
                        EmulateInsnResult::Fault => {
                            if !did_read_uctx {
                                self.read_uctx(ipc);
                            }
                            break (true, 0);
                        }
                    }
                    println!(
                        "user exception, vector {}, fsbase = {:#x}, gsbase = {:#x}",
                        intr, self.uctx.fs_base, self.uctx.gs_base
                    );
                    self.load_state(ipc, VcpuStateMask::reg_state());
                    dump_state(ipc, self);
                    let code = if intr == 13 { Some(code) } else { None };
                    self.idt_dispatch(intr, code);
                }
                seL4_Fault_tag::seL4_Fault_VMFault => {
                    let addr = ipc.msg_regs()[seL4_VMFault_Addr as usize];
                    let code = ipc.msg_regs()[seL4_VMFault_FSR as usize];
                    if code & 1 == 0 {
                        let va = addr & !((1 << SMALL_PAGE_SIZE_BITS) - 1);
                        let cr0_wp = self.cr0.bit(16);
                        let ok = self.swtlb.populate(
                            ipc,
                            self.ua,
                            &PageTableWalker {
                                paging: self.paging,
                                cr3: self.cr3,
                            },
                            va as _,
                            if cr0_wp {
                                WriteProtect::Enable
                            } else {
                                WriteProtect::Ignore
                            },
                        );
                        if ok {
                            // println!(
                            //     "VM fault: populated page, addr = {:#x}, pc = {:#x}",
                            //     addr, ip
                            // );
                            self.reply_protocol = ReplyProtocol::ReplyEmpty;
                            continue;
                        }
                    }
                    // if ip >= 0x4000_0000_0000 {
                    //     println!("VM fault: addr = {:#x}, pc = {:#x}", addr, ip);
                    //     if addr == 0 {
                    //         panic!(
                    //             "NULL pointer dereference in guest kernel code, ip = {:#x}",
                    //             ip
                    //         );
                    //     }
                    // }
                    self.read_uctx(ipc);
                    // if ip >= 0x7000_0000_0000 {
                    //     self.load_state(ipc, VcpuStateMask::reg_state());
                    //     dump_state(ipc, self);
                    // }
                    self.cr2 = addr;
                    self.idt_dispatch(crate::x86_exception::PF, Some(code));
                }
                _ => panic!("unexpected fault message: {:?}", msg),
            }
        };

        self.state.valid = VcpuStateMask::empty();
        self.load_state(ipc, VcpuStateMask::reg_state());
        ret
    }
}
