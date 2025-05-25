use core::{arch::x86_64::CpuidResult, cell::Cell, time::Duration};

use crate::{
    dump::dump_state,
    runtime::{EventLoop, sleep, wait_for_fault},
};
use algorithms::vm::{
    vcpu::{AbstractVcpu, VcpuException, VcpuFault, VcpuState, VcpuStateMask},
    vcpu_decode::{
        IoDirection, IoPortAccess, decode_control_register_access, decode_io_port_access,
        deref_reg_for_cr_access,
    },
};
use alloc::boxed::Box;
use futures::future::Either;
use sel4::{CPtr, IpcBuffer};

pub const DEFAULT_PRIORITY: u8 = 127;

#[derive(Debug, Copy, Clone)]
pub struct MmioRequest {
    pub addr: u64,
    pub size: MmioSize,
    pub write: Option<u64>,
}

pub use ipc::misc::MmioSize;

impl MmioRequest {
    pub fn decode_hypercall(st: &VcpuState) -> MmioRequest {
        let size = match st.eax & 0xf {
            0 => MmioSize::Byte,
            1 => MmioSize::Word,
            2 => MmioSize::Dword,
            _ => unreachable!(),
        };
        let addr = st.ebx;
        let write = if st.eax & 0x10 != 0 {
            Some(st.edx)
        } else {
            None
        };
        MmioRequest { addr, size, write }
    }
}

pub async fn emulate_generic_io_port(evl: &EventLoop) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY + 1, 30, &|_, _| true).await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let io = decode_io_port_access(vcpu.fault());

        let Some(value) = evl.with_ipcbuf(|ipc| pre_ioport_emulation(ipc, vcpu, &io)) else {
            continue;
        };

        if io.port_number >= 0xcf8 && io.port_number <= 0xcff {
            // ignore pci config space
        } else if io.port_number >= 0x60 && io.port_number <= 0x64 {
            // ignore 8042 keyboard controller
        } else {
            println!(
                "Unsupported IO port access: {:#x} {:?}",
                io.port_number, io.direction
            );
        }

        evl.with_ipcbuf(|ipc| post_ioport_emulation(ipc, vcpu, &io, value));
    }
}

pub async fn emulate_passthrough_io_port_range(evl: &EventLoop, start: u16, end: u16, cap: CPtr) {
    let check = &*Box::leak(Box::new(move |_: &VcpuState, fault: &VcpuFault| {
        (start..=end).contains(&decode_io_port_access(fault).port_number)
    }));
    loop {
        wait_for_fault(DEFAULT_PRIORITY, 30, check).await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let io = decode_io_port_access(vcpu.fault());

        let Some(value) = evl.with_ipcbuf(|ipc| pre_ioport_emulation(ipc, vcpu, &io)) else {
            continue;
        };

        let (error, value) = evl.with_ipcbuf(|ipc| match (io.direction, io.bitness) {
            (IoDirection::Out, 8) => (
                ipc.inner_mut()
                    .seL4_X86_IOPort_Out8(cap.bits(), io.port_number as _, value as _),
                0,
            ),
            (IoDirection::Out, 16) => (
                ipc.inner_mut()
                    .seL4_X86_IOPort_Out16(cap.bits(), io.port_number as _, value as _),
                0,
            ),
            (IoDirection::Out, 32) => (
                ipc.inner_mut()
                    .seL4_X86_IOPort_Out32(cap.bits(), io.port_number as _, value as _),
                0,
            ),
            (IoDirection::In, 8) => {
                let ret = ipc
                    .inner_mut()
                    .seL4_X86_IOPort_In8(cap.bits(), io.port_number as _);
                (ret.error, ret.result as u32)
            }
            (IoDirection::In, 16) => {
                let ret = ipc
                    .inner_mut()
                    .seL4_X86_IOPort_In16(cap.bits(), io.port_number as _);
                (ret.error, ret.result as u32)
            }
            (IoDirection::In, 32) => {
                let ret = ipc
                    .inner_mut()
                    .seL4_X86_IOPort_In32(cap.bits(), io.port_number as _);
                (ret.error, ret.result as u32)
            }

            _ => unreachable!(),
        });
        assert_eq!(error, 0, "IO port access failed");

        evl.with_ipcbuf(|ipc| post_ioport_emulation(ipc, vcpu, &io, value as i32));
    }
}

pub async fn emulate_serial(evl: &EventLoop) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY, 30, &|_, fault| {
            (0x3f8..=0x3fd).contains(&decode_io_port_access(fault).port_number)
        })
        .await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let io = decode_io_port_access(vcpu.fault());

        let Some(mut value) = evl.with_ipcbuf(|ipc| pre_ioport_emulation(ipc, vcpu, &io)) else {
            continue;
        };

        match (io.port_number, io.direction) {
            (0x3f8, IoDirection::Out) => {
                if let Ok(s) = core::str::from_utf8(&[value as u8]) {
                    print!("{}", s);
                }
            }
            (0x3f9, IoDirection::Out) => {}
            (0x3fa, IoDirection::Out) => {}
            (0x3fb, IoDirection::Out) => {}
            (0x3fc, IoDirection::Out) => {}
            (0x3fd, IoDirection::Out) => {}
            (0x3fd, IoDirection::In) => {
                // THRE, TEMT
                value = (1 << 5) | (1 << 6);
            }
            _ => {
                println!(
                    "Unsupported serial access on port {:#x}, direction {:?}",
                    io.port_number, io.direction
                );
            }
        }

        evl.with_ipcbuf(|ipc| post_ioport_emulation(ipc, vcpu, &io, value));
    }
}

pub async fn emulate_cr(evl: &EventLoop) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY, 28, &|_, _| true).await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;

        evl.with_ipcbuf(|ipc| {
            let acc = decode_control_register_access(vcpu.fault());

            // only supports write cr0
            if acc.cr_idx != 0 || acc.access_type != 0 {
                vcpu.inject_exception(ipc, VcpuException::InvalidOpcode);
                return;
            }

            let (_, m) = deref_reg_for_cr_access(vcpu.state_mut(), &acc);
            vcpu.load_state(ipc, m | VcpuStateMask::CR0);
            let st = vcpu.state_mut();
            let (gpr_value, _) = deref_reg_for_cr_access(st, &acc);
            let gpr_value = *gpr_value;

            let old_value = st.cr0;
            st.cr0 = gpr_value;
            vcpu.commit_state(ipc, VcpuStateMask::CR0);

            // https://github.com/mirage/xen/blob/master/xen/arch/x86/hvm/hvm.c
            // CR0.PG 0->1
            if gpr_value & (1 << 31) != 0 && old_value & (1 << 31) == 0 {
                let efer = vcpu
                    .read_msr(ipc, 0xc000_0080)
                    .expect("failed to read EFER");
                // EFER_LME
                if efer & (1 << 8) != 0 {
                    vcpu.load_state(ipc, VcpuStateMask::CR4);
                    let cr4 = vcpu.state().cr4;

                    // PAE
                    if cr4 & (1 << 5) != 0 {
                        println!("Enabling EFER.LMA");
                        vcpu.write_msr(ipc, 0xc000_0080, efer | (1 << 10))
                            .expect("failed to write EFER");
                    }
                }
            }
        });
    }
}

pub async fn emulate_rdmsr(evl: &EventLoop) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY + 1, 31, &|_, _| true).await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let instruction_len = vcpu.fault().instruction_len;
        let msr = vcpu.state().ecx;
        evl.with_ipcbuf(|ipc| {
            if let Some(value) = vcpu.read_msr(ipc, msr as u32) {
                let st = vcpu.state_mut();
                st.eax = (value as u32).into();
                st.edx = ((value >> 32) as u32).into();
                st.eip += instruction_len;
                vcpu.commit_state(
                    ipc,
                    VcpuStateMask::EAX | VcpuStateMask::EDX | VcpuStateMask::EIP,
                );
            } else {
                println!("reading unknown MSR: {:#x}", msr);
                vcpu.inject_exception(ipc, VcpuException::GeneralProtectionFault(0));
            }
        });
    }
}

pub async fn emulate_wrmsr(evl: &EventLoop) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY + 1, 32, &|_, _| true).await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let instruction_len = vcpu.fault().instruction_len;
        let st = vcpu.state();
        let msr = st.ecx;
        let value = (st.edx as u64) << 32 | st.eax as u64;
        evl.with_ipcbuf(|ipc| {
            if vcpu.write_msr(ipc, msr as u32, value).is_some() {
                vcpu.state_mut().eip += instruction_len;
                vcpu.commit_state(ipc, VcpuStateMask::EIP);
            } else {
                println!("writing unknown MSR: {:#x} -> {:#}", msr, value);
                dump_state(ipc, vcpu);
                vcpu.inject_exception(ipc, VcpuException::GeneralProtectionFault(0));
            }
        });
    }
}

pub async fn emulate_cpuid(evl: &EventLoop) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY, 10, &|_, _| true).await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let instruction_len = vcpu.fault().instruction_len;
        let st = vcpu.state_mut();
        let leaf = st.eax as u32;
        let sub_leaf = st.ecx as u32;
        let cpuid = if (0x4000_0000..0x4000_0200).contains(&leaf) {
            // mask off kvm/xen detection
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        } else {
            unsafe { core::arch::x86_64::__cpuid_count(leaf, sub_leaf) }
        };

        st.eax = cpuid.eax.into();
        st.ebx = cpuid.ebx.into();
        st.ecx = cpuid.ecx.into();
        st.edx = cpuid.edx.into();
        st.eip += instruction_len;

        if leaf == 1 {
            st.ecx |= 1 << 21; // x2apic
        }
        evl.with_ipcbuf(|ipc| {
            vcpu.commit_state(
                ipc,
                VcpuStateMask::EAX
                    | VcpuStateMask::EBX
                    | VcpuStateMask::ECX
                    | VcpuStateMask::EDX
                    | VcpuStateMask::EIP,
            )
        });
    }
}

pub async fn emulate_xsetbv(evl: &EventLoop) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY, 55, &|_, _| true).await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let instruction_len = vcpu.fault().instruction_len;
        let vcpu = &mut **vcpu;
        let st = vcpu.state_mut();
        let value = (st.edx as u64) << 32 | st.eax as u32 as u64;
        let host_value = unsafe { core::arch::x86_64::_xgetbv(0) };
        println!("ignored xsetbv: {:#x} -> {:#x}", host_value, value);
        st.eip += instruction_len;
        evl.with_ipcbuf(|ipc| vcpu.commit_state(ipc, VcpuStateMask::EIP));
    }
}

pub async fn emulate_pit(evl: &EventLoop) {
    let mut ch2_counter_write_latch = 0u16;
    let mut ch2_counter_write_latch_msb = false;
    let mut ch2_reference = evl.pit().time_since_boot();
    let mut ch2_counter_read_high_latch = 0u8;
    let mut ch2_counter_read_high_latch_valid = false;

    loop {
        wait_for_fault(DEFAULT_PRIORITY, 30, &|_, fault| {
            (0x40..=0x43).contains(&decode_io_port_access(fault).port_number)
        })
        .await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;

        // vcpu.inject_exception(VcpuException::InvalidOpcode);
        let io = decode_io_port_access(vcpu.fault());

        let Some(value) = evl.with_ipcbuf(|ipc| pre_ioport_emulation(ipc, vcpu, &io)) else {
            continue;
        };

        let mut value = value as u8;

        match (io.port_number, io.direction, value) {
            (0x43, IoDirection::Out, 0xb0) => {
                // Channel 2, lobyte/hibyte, interrupt on terminal count
            }
            (0x42, IoDirection::Out, _) => {
                if ch2_counter_write_latch_msb {
                    ch2_counter_write_latch =
                        (ch2_counter_write_latch & 0xff) | ((value as u16) << 8);
                    ch2_reference = evl.pit().time_since_boot();
                } else {
                    ch2_counter_write_latch = (ch2_counter_write_latch & 0xff00) | value as u16;
                }
                ch2_counter_write_latch_msb = !ch2_counter_write_latch_msb;
            }
            (0x42, IoDirection::In, _) => {
                if ch2_counter_read_high_latch_valid {
                    value = ch2_counter_read_high_latch;
                } else {
                    let interval = evl.pit().time_since_boot() - ch2_reference;
                    let interval_counter = interval.as_micros() as u64 * 1_193_182 / 1_000_000;
                    let full_value = ch2_counter_write_latch.wrapping_sub(interval_counter as u16);
                    value = full_value as u8;
                    ch2_counter_read_high_latch = (full_value >> 8) as u8;
                }
                ch2_counter_read_high_latch_valid = !ch2_counter_read_high_latch_valid;
            }
            _ => {
                println!(
                    "Unsupported PIT access on port {:#x}, direction {:?}, value {:#x}",
                    io.port_number, io.direction, value
                );
            }
        }

        evl.with_ipcbuf(|ipc| post_ioport_emulation(ipc, vcpu, &io, value as i8 as i32));
    }
}

pub async fn emulate_x2apic(evl: &EventLoop) {
    let mut ia32_apic_base: u64 = 0;
    let mut spurious_interrupt_vector: u64 = 0;
    let lvt_timer = Cell::new(0x00010000u64);
    let mut lvt_lint0: u64 = 0;
    let mut lvt_lint1: u64 = 0;
    let mut lvt_error: u64 = 0;
    let tmrinitcnt = Cell::new(0u32);
    let tmrcurrent = Cell::new(0u32);
    let tmrcurrent_ref = Cell::new(evl.pit().time_since_boot());
    let tmrdiv = Cell::new(0u32);
    let timer_event = Cell::new(None);

    let snapshot_tmrcurrent = || {
        let div = tmrdiv.get();
        let div = (((div >> 3) & 1) << 2) | (div & 0b11);
        let div: u64 = match div {
            0b000 => 2,
            0b001 => 4,
            0b010 => 8,
            0b011 => 16,
            0b100 => 32,
            0b101 => 64,
            0b110 => 128,
            0b111 => 1,
            _ => unreachable!(),
        };
        let mode = (lvt_timer.get() >> 17) & 0b11;
        let now = evl.pit().time_since_boot();
        let ref_micros_div = (now - tmrcurrent_ref.get()).as_micros() as u64 / div;
        tmrcurrent_ref.set(now);

        if mode == 0 {
            // oneshot
            tmrcurrent.set((tmrcurrent.get() as u64).saturating_sub(ref_micros_div) as u32);
        } else {
            // periodic
            if (tmrcurrent.get() as u64) >= ref_micros_div {
                tmrcurrent.set((tmrcurrent.get() as u64 - ref_micros_div) as u32);
            } else if tmrinitcnt.get() != 0 {
                let new_value = tmrinitcnt.get() as u64
                    - (ref_micros_div - 1 - tmrcurrent.get() as u64) % tmrinitcnt.get() as u64;
                tmrcurrent.set(new_value as u32);
            } else {
                tmrcurrent.set(0);
            }
        }

        if lvt_timer.get() & (1 << 16) != 0 || tmrcurrent.get() == 0 {
            // masked
            timer_event.set(None);
        } else {
            let ref_sleep_micros = tmrcurrent.get() as u64 * div;
            // println!("Setting timer event in {}us", ref_sleep_micros);
            timer_event.set(Some(sleep(Duration::from_micros(ref_sleep_micros))));
        }
    };

    loop {
        let fut_fault = wait_for_fault(DEFAULT_PRIORITY, core::u32::MAX, &|state, fault| {
            (fault.reason == 31 || fault.reason == 32)
                && (state.ecx == 0x1b || (0x0800..=0x0bff).contains(&state.ecx))
        });
        let fut_timer = if let Some(x) = timer_event.take() {
            Either::Left(x)
        } else {
            Either::Right(futures::future::pending())
        };
        let event = futures::future::select(fut_fault, fut_timer).await;
        match event {
            Either::Left(((), timer)) => {
                if let Either::Left(timer) = timer {
                    timer_event.set(Some(timer));
                }
            }
            Either::Right(((), _)) => {
                let intr = lvt_timer.get() & 0xff;
                evl.with_ipcbuf(|ipc| {
                    evl.vcpu()
                        .borrow_mut()
                        .inject_external_interrupt(ipc, intr as u8)
                });
                continue;
            }
        }
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let st = vcpu.state();
        let msr = st.ecx;

        let is_wr = vcpu.fault().reason == 32;
        let mut failed = false;
        let value = if is_wr {
            (st.edx as u64) << 32 | st.eax as u64
        } else {
            0
        };

        let value: u64 = match (msr, is_wr) {
            (0x1b, false) => ia32_apic_base,
            (0x1b, true) => {
                ia32_apic_base = value;
                0
            }

            (0x802, false) => 0,
            (0x803, false) => 0x15 | (6 << 16),

            // EOI
            (0x80b, true) if value == 0 => 0,

            // Spurious Interrupt Vector Register
            (0x80f, false) => spurious_interrupt_vector,
            (0x80f, true) => {
                spurious_interrupt_vector = value;
                0
            }

            // LVT Timer Register
            (0x832, false) => lvt_timer.get(),
            (0x832, true) => {
                snapshot_tmrcurrent();
                lvt_timer.set(value);
                0
            }

            // LVT LINT0 Register
            (0x835, false) => lvt_lint0,
            (0x835, true) => {
                lvt_lint0 = value;
                0
            }

            // LVT LINT1 Register
            (0x836, false) => lvt_lint1,
            (0x836, true) => {
                lvt_lint1 = value;
                0
            }

            // LVT Error Register
            (0x837, false) => lvt_error,
            (0x837, true) => {
                lvt_error = value;
                0
            }

            // Initial Count Register (for Timer)
            (0x838, false) => tmrinitcnt.get() as u64,
            (0x838, true) => {
                tmrinitcnt.set(value as u32);
                tmrcurrent.set(value as u32);
                tmrcurrent_ref.set(evl.pit().time_since_boot());
                snapshot_tmrcurrent();
                0
            }

            // Current Count Register (for Timer)
            (0x839, false) => {
                snapshot_tmrcurrent();
                tmrcurrent.get() as u64
            }

            // Divide Configuration Register (for Timer)
            (0x83e, false) => tmrdiv.get() as u64,
            (0x83e, true) => {
                snapshot_tmrcurrent();
                tmrdiv.set(value as u32);
                0
            }

            _ => {
                failed = true;
                println!(
                    "Unsupported x2APIC access on MSR {:#x}, is_wr: {}, value: {:#x}",
                    msr, is_wr, value,
                );
                0
            }
        };

        evl.with_ipcbuf(|ipc| {
            if failed {
                vcpu.inject_exception(ipc, VcpuException::GeneralProtectionFault(0));
            } else {
                let instruction_len = vcpu.fault().instruction_len;
                let st = vcpu.state_mut();
                let mut m = VcpuStateMask::EIP;
                if !is_wr {
                    m |= VcpuStateMask::EAX | VcpuStateMask::EDX;
                    st.eax = (value as u32).into();
                    st.edx = ((value >> 32) as u32).into();
                }
                st.eip += instruction_len;
                vcpu.commit_state(ipc, m);
            }
        });
    }
}

fn pre_ioport_emulation(
    ipc: &mut IpcBuffer,
    vcpu: &mut dyn AbstractVcpu<Context = IpcBuffer>,
    io: &IoPortAccess,
) -> Option<i32> {
    if io.rep_prefixed || io.str_ins {
        println!("Unsupported IO access with REP or INS/OUTS");
        vcpu.inject_exception(ipc, VcpuException::InvalidOpcode);
        return None;
    }

    Some(if matches!(io.direction, IoDirection::Out) {
        let st = vcpu.state();
        assert!(st.valid.contains(VcpuStateMask::EAX));
        st.eax as i32
    } else {
        0
    })
}

fn post_ioport_emulation(
    ipc: &mut IpcBuffer,
    vcpu: &mut dyn AbstractVcpu<Context = IpcBuffer>,
    io: &IoPortAccess,
    value: i32,
) {
    let mut m = VcpuStateMask::EIP;
    if matches!(io.direction, IoDirection::In) {
        // sign extend
        vcpu.state_mut().eax = value as i64 as u64;
        m |= VcpuStateMask::EAX;
    }

    vcpu.state_mut().eip += vcpu.fault().instruction_len;
    vcpu.commit_state(ipc, m);
}
