use core::time::Duration;

use algorithms::{
    unialloc::UniAllocTrait,
    vm::vcpu::{AbstractVcpu, InterruptBitmap, VcpuException, VcpuFault, VcpuState, VcpuStateMask},
};
use alloc::boxed::Box;
use ipc::{
    timer::Timer,
    untyped::{UntypedCap, UntypedCapContext},
};
use sel4::{
    CPtr, IpcBuffer,
    cap::{CNode, Tcb},
    sys::{_object::seL4_X86_VCPUObject, seL4_VCPUContext, seL4_X86_VCPUBits},
};
use x86::vmx::vmcs::{self, control::PrimaryControls};

use crate::{
    dump::dump_state,
    vmx::helper::{VmEnterFault, read_vmcs, seL4_VMEnter, write_vmcs},
};

pub struct VmxVcpu {
    pub vcpu_cap: CPtr,
    raw_fault: VmEnterFault,
    pub pending_interrupts: InterruptBitmap,

    state: VcpuState,
    fault: VcpuFault,

    interrupt_window_requested_at: Option<Duration>,
    timer: &'static dyn Timer,

    vm_exec_time: Duration,
    fault_counter: u64,
}

pub struct VmxVcpuContext {
    pub tcb: Tcb,
    pub rtc_ioport: Option<CPtr>,
}
impl VmxVcpu {
    pub fn new_boxed(
        ipc: &mut IpcBuffer,
        cspace: CNode,
        ua: &mut dyn UniAllocTrait<Untyped = UntypedCap>,
        timer: &'static dyn Timer,
        ctx: VmxVcpuContext,
    ) -> Box<Self> {
        let vcpu_cap =
            CPtr::from_bits(ua.get_capalloc().alloc().expect("Failed to alloc vcpu cap"));
        let ut = UntypedCapContext::with(ipc, cspace, |ctx| {
            ua.try_alloc(ctx, sel4::sys::seL4_VCPUBits as usize)
        })
        .expect("Failed to alloc untyped");
        assert_eq!(
            ipc.inner_mut().seL4_Untyped_Retype(
                ut.cap.0.bits(),
                seL4_X86_VCPUObject as _,
                seL4_X86_VCPUBits as _,
                cspace.bits(),
                cspace.bits(),
                64,
                vcpu_cap.bits(),
                1,
            ),
            0,
            "Failed to retype untyped to vcpu"
        );
        assert_eq!(
            ipc.inner_mut()
                .seL4_X86_VCPU_SetTCB(vcpu_cap.bits(), ctx.tcb.bits()),
            0,
            "Failed to set VCPU for TCB"
        );

        let mut me = Box::<VmxVcpu>::new_uninit();
        let mut me = unsafe {
            core::ptr::write_bytes(me.as_mut_ptr(), 0u8, 1);
            me.assume_init()
        };
        me.vcpu_cap = vcpu_cap;
        me.interrupt_window_requested_at = None;
        me.timer = timer;
        me.init_state(ipc);

        // passthrough rtc
        if let Some(rtc_ioport) = ctx.rtc_ioport {
            assert_eq!(
                ipc.inner_mut().seL4_X86_VCPU_EnableIOPort(
                    vcpu_cap.bits(),
                    rtc_ioport.bits(),
                    0x70,
                    0x71,
                ),
                0,
                "Failed to enable RTC IO port"
            );
        }

        me
    }

    fn init_state(&mut self, ipc: &mut IpcBuffer) {
        // https://xenbits.xen.org/docs/unstable/misc/pvh.html
        // The domain builder must load the kernel into the guest memory space and jump into the entry point defined at XEN_ELFNOTE_PHYS32_ENTRY with the following machine state:
        // ebx: contains the physical memory address where the loader has placed the boot start info structure.
        // cr0: bit 0 (PE) must be set. All the other writeable bits are cleared.
        // cr4: all bits are cleared.
        // cs: must be a 32-bit read/execute code segment with a base of ‘0’ and a limit of ‘0xFFFFFFFF’. The selector value is unspecified.
        // ds, es, ss: must be a 32-bit read/write data segment with a base of ‘0’ and a limit of ‘0xFFFFFFFF’. The selector values are all unspecified.
        // tr: must be a 32-bit TSS (active) with a base of ‘0’ and a limit of ‘0x67’.
        // eflags: bit 17 (VM) must be cleared. Bit 9 (IF) must be cleared. Bit 8 (TF) must be cleared. Other bits are all unspecified.
        let mut write_vmcs =
            |field: u32, value: u64| -> u64 { write_vmcs(self.vcpu_cap, ipc, field, value) };

        write_vmcs(
            vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,
            vmcs::control::SecondaryControls::ENABLE_RDTSCP
                .bits()
                .into(),
        );

        // https://github.com/seL4/seL4_projects_libs/blob/master/libsel4vm/src/arch/x86/vmcs.c
        // https://github.com/mirage/xen/blob/master/xen/arch/x86/hvm/vmx/vmcs.c

        write_vmcs(vmcs::guest::ES_LIMIT, !0);
        write_vmcs(vmcs::guest::SS_LIMIT, !0);
        write_vmcs(vmcs::guest::DS_LIMIT, !0);
        write_vmcs(vmcs::guest::FS_LIMIT, !0);
        write_vmcs(vmcs::guest::GS_LIMIT, !0);
        write_vmcs(vmcs::guest::CS_LIMIT, !0);

        write_vmcs(vmcs::guest::GDTR_BASE, 0);
        write_vmcs(vmcs::guest::IDTR_BASE, 0);
        write_vmcs(vmcs::guest::GDTR_LIMIT, 0);
        write_vmcs(vmcs::guest::IDTR_LIMIT, 0);

        write_vmcs(vmcs::guest::ES_ACCESS_RIGHTS, 0xc093);
        write_vmcs(vmcs::guest::SS_ACCESS_RIGHTS, 0xc093);
        write_vmcs(vmcs::guest::DS_ACCESS_RIGHTS, 0xc093);
        write_vmcs(vmcs::guest::FS_ACCESS_RIGHTS, 0xc093);
        write_vmcs(vmcs::guest::GS_ACCESS_RIGHTS, 0xc093);
        write_vmcs(vmcs::guest::CS_ACCESS_RIGHTS, 0xc09b);

        write_vmcs(vmcs::guest::ES_BASE, 0);
        write_vmcs(vmcs::guest::SS_BASE, 0);
        write_vmcs(vmcs::guest::DS_BASE, 0);
        write_vmcs(vmcs::guest::FS_BASE, 0);
        write_vmcs(vmcs::guest::GS_BASE, 0);
        write_vmcs(vmcs::guest::CS_BASE, 0);

        write_vmcs(vmcs::guest::LDTR_BASE, 0);
        write_vmcs(vmcs::guest::LDTR_LIMIT, 0);
        write_vmcs(vmcs::guest::LDTR_SELECTOR, 0);
        write_vmcs(vmcs::guest::LDTR_ACCESS_RIGHTS, 0x0082);

        write_vmcs(vmcs::guest::TR_BASE, 0);
        write_vmcs(vmcs::guest::TR_LIMIT, 0xFF);
        write_vmcs(vmcs::guest::TR_SELECTOR, 0);
        write_vmcs(vmcs::guest::TR_ACCESS_RIGHTS, 0x008b);

        write_vmcs(vmcs::guest::IA32_SYSENTER_CS, 0);
        write_vmcs(vmcs::control::CR4_GUEST_HOST_MASK, 0);
        write_vmcs(vmcs::control::CR4_READ_SHADOW, 0);
        write_vmcs(vmcs::guest::RFLAGS, 2);
        write_vmcs(vmcs::guest::IA32_SYSENTER_ESP, 0);
        write_vmcs(vmcs::guest::IA32_SYSENTER_EIP, 0);

        // disable IA32e
        write_vmcs(vmcs::guest::IA32_EFER_FULL, 0);

        // Disable paging and trap CR0 access
        write_vmcs(vmcs::guest::CR0, 0x1);
        write_vmcs(vmcs::control::CR0_READ_SHADOW, 0x1);
        write_vmcs(vmcs::control::CR0_GUEST_HOST_MASK, !0);

        // write_vmcs(vmcs::control::EXCEPTION_BITMAP, !0);
    }
}

impl AbstractVcpu for VmxVcpu {
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

    fn load_state(&mut self, ipc: &mut IpcBuffer, mut regs: VcpuStateMask) {
        type M = VcpuStateMask;
        let mut take = |m: M| -> bool {
            if regs.contains(m) {
                regs.remove(m);
                true
            } else {
                false
            }
        };
        let mut copy_out = |m: M, field: u32, output: &mut dyn FnMut(u64)| {
            if take(m) && !self.state.valid.contains(m) {
                output(read_vmcs(self.vcpu_cap, ipc, field));
                self.state.valid.insert(m);
            }
        };
        copy_out(M::CR0, vmcs::guest::CR0, &mut |x| self.state.cr0 = x);
        copy_out(M::CR3, vmcs::guest::CR3, &mut |x| self.state.cr3 = x);
        copy_out(M::CR4, vmcs::guest::CR4, &mut |x| self.state.cr4 = x);
        copy_out(M::RFLAGS, vmcs::guest::RFLAGS, &mut |x| {
            self.state.rflags = x
        });
        copy_out(M::ESP, vmcs::guest::RSP, &mut |x| self.state.esp = x);
        copy_out(M::EIP, vmcs::guest::RIP, &mut |x| self.state.eip = x);
        copy_out(
            M::CS_ACCESS_RIGHTS,
            vmcs::guest::CS_ACCESS_RIGHTS,
            &mut |x| self.state.cs_access_rights = x as u32,
        );
        copy_out(M::ACTIVITY_STATE, vmcs::guest::ACTIVITY_STATE, &mut |x| {
            self.state.activity_state = x as u8
        });

        assert!(
            regs.difference(self.state.valid).is_empty(),
            "load_state: unrecognized bits: {:?}",
            regs
        );
    }

    fn commit_state(&mut self, ipc: &mut IpcBuffer, mut regs: VcpuStateMask) {
        type M = VcpuStateMask;
        const WRITE_GROUP: M = M::from_bits_retain(
            M::EAX.bits()
                | M::EBX.bits()
                | M::ECX.bits()
                | M::EDX.bits()
                | M::ESI.bits()
                | M::EDI.bits()
                | M::EBP.bits()
                | M::R8.bits()
                | M::R9.bits()
                | M::R10.bits()
                | M::R11.bits()
                | M::R12.bits()
                | M::R13.bits()
                | M::R14.bits()
                | M::R15.bits(),
        );
        let mut copy_in = |m: M, fields: &[u32], value: u64| {
            if regs.contains(m) {
                regs.remove(m);
                for field in fields {
                    write_vmcs(self.vcpu_cap, ipc, *field, value);
                }
            }
        };
        copy_in(
            M::CR0,
            &[vmcs::guest::CR0, vmcs::control::CR0_READ_SHADOW],
            self.state.cr0,
        );
        copy_in(M::CR3, &[vmcs::guest::CR3], self.state.cr3);
        copy_in(M::CR4, &[vmcs::guest::CR4], self.state.cr4);
        copy_in(M::RFLAGS, &[vmcs::guest::RFLAGS], self.state.rflags);
        copy_in(M::ESP, &[vmcs::guest::RSP], self.state.esp);
        copy_in(
            M::ACTIVITY_STATE,
            &[vmcs::guest::ACTIVITY_STATE],
            self.state.activity_state as _,
        );
        if regs.contains(M::EIP) {
            self.raw_fault.call.eip = self.state.eip;
            regs.remove(M::EIP);
        }

        if regs.intersects(WRITE_GROUP) {
            assert!(regs.union(self.state.valid).contains(WRITE_GROUP));
            let ctx = seL4_VCPUContext {
                eax: self.state.eax,
                ebx: self.state.ebx,
                ecx: self.state.ecx,
                edx: self.state.edx,
                esi: self.state.esi,
                edi: self.state.edi,
                ebp: self.state.ebp,
                r8: self.state.r8,
                r9: self.state.r9,
                r10: self.state.r10,
                r11: self.state.r11,
                r12: self.state.r12,
                r13: self.state.r13,
                r14: self.state.r14,
                r15: self.state.r15,
            };
            let ret = ipc
                .inner_mut()
                .seL4_X86_VCPU_WriteRegisters(self.vcpu_cap.bits(), &ctx);
            assert!(ret == 0, "Failed to commit reg write group");
            regs.remove(WRITE_GROUP);
        }

        assert!(
            regs.is_empty(),
            "commit_state: unrecognized bits: {:?}",
            regs
        );
    }

    fn inject_exception(&mut self, ipc: &mut IpcBuffer, exc: VcpuException) {
        let (vector, ty, error_code): (u64, u64, Option<u32>) = match exc {
            VcpuException::InvalidOpcode => (6, 3, None),
            VcpuException::GeneralProtectionFault(x) => (13, 3, Some(x)),
        };
        self.raw_fault.call.control_entry = vector | (ty << 8) | (1 << 31);
        if let Some(x) = error_code {
            write_vmcs(
                self.vcpu_cap,
                ipc,
                vmcs::control::VMENTRY_EXCEPTION_ERR_CODE,
                x.into(),
            );
            self.raw_fault.call.control_entry |= 1 << 11;
        }
    }

    fn inject_external_interrupt(&mut self, _ipc: &mut IpcBuffer, intr: u8) {
        self.pending_interrupts.activate(intr);
    }

    fn external_interrupt_pending(&self) -> bool {
        !self.pending_interrupts.is_empty()
    }

    fn read_msr(&mut self, ipc: &mut IpcBuffer, msr: u32) -> Option<u64> {
        match msr {
            0xc000_0080 => {
                // efer
                Some(read_vmcs(
                    self.vcpu_cap,
                    ipc,
                    vmcs::guest::IA32_EFER_FULL.into(),
                ))
            }
            x if kernel_handles_msr(x) => {
                let ret = ipc
                    .inner_mut()
                    .seL4_X86_VCPU_ReadMSR(self.vcpu_cap.bits(), msr.into());
                if ret.error != 0 {
                    None
                } else {
                    Some(ret.value)
                }
            }
            _ => None,
        }
    }

    fn write_msr(&mut self, ipc: &mut IpcBuffer, msr: u32, value: u64) -> Option<u64> {
        match msr {
            0xc000_0080 => {
                // efer
                Some(write_vmcs(
                    self.vcpu_cap,
                    ipc,
                    vmcs::guest::IA32_EFER_FULL.into(),
                    value,
                ))
            }
            x if kernel_handles_msr(x) => {
                let ret =
                    ipc.inner_mut()
                        .seL4_X86_VCPU_WriteMSR(self.vcpu_cap.bits(), msr.into(), value);
                if ret.error != 0 {
                    None
                } else {
                    Some(ret.written)
                }
            }
            _ => None,
        }
    }

    fn lgdt(&mut self, ipc: &mut IpcBuffer, base: u64, limit: u16) {
        write_vmcs(self.vcpu_cap, ipc, vmcs::guest::GDTR_BASE.into(), base);
        write_vmcs(
            self.vcpu_cap,
            ipc,
            vmcs::guest::GDTR_LIMIT.into(),
            limit as u64,
        );
    }

    fn enter(&mut self, ipc: &mut IpcBuffer) -> (bool, u64) {
        self.raw_fault.call.control_ppc &=
            !(PrimaryControls::INTERRUPT_WINDOW_EXITING.bits() as u64);
        self.raw_fault.call.control_ppc |= PrimaryControls::HLT_EXITING.bits() as u64;

        if !self.pending_interrupts.is_empty() && self.raw_fault.call.control_entry & (1 << 31) == 0
        {
            let rflags_if = self.raw_fault.rflags & (1 << 9) != 0;
            if rflags_if {
                let intr = self.pending_interrupts.first();
                self.raw_fault.call.control_entry = intr as u64 | (1 << 31);
                // println!("Delivering interrupt {:#}", intr);
                self.pending_interrupts.deactivate(intr);
                self.interrupt_window_requested_at = None;
            } else {
                self.raw_fault.call.control_ppc |=
                    PrimaryControls::INTERRUPT_WINDOW_EXITING.bits() as u64;
                let now = self.timer.time_since_boot();
                match self.interrupt_window_requested_at {
                    None => {
                        self.interrupt_window_requested_at = Some(now);
                    }
                    Some(x) if now - x > Duration::from_secs(10) => {
                        println!(
                            "W: no interrupt window in {:?}, fault={}, vmtime={:?}",
                            now - x,
                            self.fault_counter,
                            self.vm_exec_time,
                        );
                        dump_state(ipc, self);
                        self.interrupt_window_requested_at = Some(now);
                    }
                    Some(_) => {}
                }
            }
        } else {
            self.interrupt_window_requested_at = None;
        }

        // 27.3.1.5 Checks on Guest Non-Register State -> Interruptibility state
        // "Bit 0 (blocking by STI) and bit 1 (blocking by MOV-SS) must both be 0 if the valid bit (bit 31) in the
        //  VM-entry interruption-information field is 1 and the interruption type (bits 10:8) in that field has value 0,
        //  indicating external interrupt, or value 2, indicating non-maskable interrupt (NMI).
        //
        // Triggered by the `sti; hlt;` sequence.
        if self.raw_fault.call.control_entry & (1 << 31) != 0
            && [0, 2].contains(&((self.raw_fault.call.control_entry >> 8) & 0b111))
            && self.raw_fault.guest_int & 0b11 != 0
        {
            write_vmcs(
                self.vcpu_cap,
                ipc,
                vmcs::guest::INTERRUPTIBILITY_STATE.into(),
                self.raw_fault.guest_int & !0b11,
            );
        }

        let start_time = self.timer.time_since_boot();
        let ret = seL4_VMEnter(ipc.inner_mut(), &mut self.raw_fault);
        let end_time = self.timer.time_since_boot();
        self.vm_exec_time += end_time - start_time;
        if !ret.0 {
            self.raw_fault.call.eip = read_vmcs(self.vcpu_cap, ipc, vmcs::guest::RIP.into());
            self.raw_fault.call.control_entry = read_vmcs(
                self.vcpu_cap,
                ipc,
                vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD.into(),
            );
            self.raw_fault.call.control_ppc = read_vmcs(
                self.vcpu_cap,
                ipc,
                vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS.into(),
            );
            self.raw_fault.rflags = read_vmcs(self.vcpu_cap, ipc, vmcs::guest::RFLAGS.into());
            self.raw_fault.guest_int = read_vmcs(
                self.vcpu_cap,
                ipc,
                vmcs::guest::INTERRUPTIBILITY_STATE.into(),
            );
        } else {
            self.fault_counter += 1;
        }

        copy_state(&self.raw_fault, &mut self.state, &mut self.fault, ret.0);
        ret
    }
}

fn copy_state(src: &VmEnterFault, st: &mut VcpuState, fault: &mut VcpuFault, full: bool) {
    type M = VcpuStateMask;
    if full {
        st.eip = src.call.eip;
        st.eax = src.eax;
        st.ebx = src.ebx;
        st.ecx = src.ecx;
        st.edx = src.edx;
        st.esi = src.esi;
        st.edi = src.edi;
        st.ebp = src.ebp;
        st.r8 = src.r8;
        st.r9 = src.r9;
        st.r10 = src.r10;
        st.r11 = src.r11;
        st.r12 = src.r12;
        st.r13 = src.r13;
        st.r14 = src.r14;
        st.r15 = src.r15;
        st.rflags = src.rflags;

        st.valid = M::EIP
            | M::EAX
            | M::EBX
            | M::ECX
            | M::EDX
            | M::ESI
            | M::EDI
            | M::EBP
            | M::R8
            | M::R9
            | M::R10
            | M::R11
            | M::R12
            | M::R13
            | M::R14
            | M::R15
            | M::RFLAGS;

        fault.reason = src.reason;
        fault.qualification = src.qualification;
        fault.instruction_len = src.instruction_len;
        fault.guest_physical = src.guest_physical;
        fault.guest_int = src.guest_int;
    } else {
        st.eip = src.call.eip;
        st.rflags = src.rflags;
        st.valid = M::EIP | M::RFLAGS;

        fault.reason = 0;
    }
}

fn kernel_handles_msr(id: u32) -> bool {
    // #define IA32_LSTAR_MSR          0xC0000082
    // #define IA32_STAR_MSR           0xC0000081
    // #define IA32_CSTAR_MSR          0xC0000083
    // #define IA32_FMASK_MSR          0xC0000084

    id == 0xc000_0082 || id == 0xc000_0081 || id == 0xc000_0083 || id == 0xc000_0084
}
