use crate::vm::vcpu::VcpuStateMask;

use super::vcpu::{VcpuFault, VcpuState};

#[derive(Clone, Debug)]
pub struct CrAccess {
    pub cr_idx: u8,
    pub access_type: u8,
    pub gpr: u8,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct IoPortAccess {
    pub bitness: u8,
    pub direction: IoDirection,
    pub str_ins: bool,
    pub rep_prefixed: bool,
    pub port_number: u16,
}

#[derive(Copy, Clone, Debug)]
pub enum IoDirection {
    In,
    Out,
}

pub fn decode_control_register_access(fault: &VcpuFault) -> CrAccess {
    let cr_idx = fault.qualification & 0b1111;
    let access_type = (fault.qualification >> 4) & 0b11;
    let gpr = (fault.qualification >> 8) & 0b1111;

    CrAccess {
        cr_idx: cr_idx as u8,
        access_type: access_type as u8,
        gpr: gpr as u8,
    }
}

pub fn deref_reg_for_cr_access<'a>(
    st: &'a mut VcpuState,
    acc: &CrAccess,
) -> (&'a mut u64, VcpuStateMask) {
    type M = VcpuStateMask;
    match acc.gpr {
        0 => (&mut st.eax, M::EAX),
        1 => (&mut st.ecx, M::ECX),
        2 => (&mut st.edx, M::EDX),
        3 => (&mut st.ebx, M::EBX),
        4 => (&mut st.esp, M::ESP),
        5 => (&mut st.ebp, M::EBP),
        6 => (&mut st.esi, M::ESI),
        7 => (&mut st.edi, M::EDI),
        8 => (&mut st.r8, M::R8),
        9 => (&mut st.r9, M::R9),
        10 => (&mut st.r10, M::R10),
        11 => (&mut st.r11, M::R11),
        12 => (&mut st.r12, M::R12),
        13 => (&mut st.r13, M::R13),
        14 => (&mut st.r14, M::R14),
        15 => (&mut st.r15, M::R15),
        _ => panic!("deref_reg_for_cr_access: invalid gpr: {}", acc.gpr),
    }
}

pub const fn decode_io_port_access(fault: &VcpuFault) -> IoPortAccess {
    let direction = if (fault.qualification >> 3) & 1 != 0 {
        IoDirection::In
    } else {
        IoDirection::Out
    };

    let bitness = match fault.qualification & 0b11 {
        0 => 8,
        1 => 16,
        3 => 32,
        _ => panic!("Invalid bitness in IO port access"),
    };
    let str_ins = (fault.qualification >> 4) & 1;
    let rep_prefixed = (fault.qualification >> 5) & 1;
    let port_number = (fault.qualification >> 16) & 0xffff;

    IoPortAccess {
        bitness,
        direction,
        str_ins: str_ins != 0,
        rep_prefixed: rep_prefixed != 0,
        port_number: port_number as u16,
    }
}
