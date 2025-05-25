use core::ffi::c_int;

use sel4::{
    sys::{seL4_IPCBuffer, seL4_Word, syscall_id},
    CPtr, IpcBuffer,
};

#[allow(dead_code)]
pub mod kernel_fault_context {
    pub const SEL4_VMENTER_CALL_EIP_MR: usize = 0;
    pub const SEL4_VMENTER_CALL_CONTROL_PPC_MR: usize = 1;
    pub const SEL4_VMENTER_CALL_CONTROL_ENTRY_MR: usize = 2;

    // In addition to the above message registers, if a VMEnter results in
    // a fault the following constants describe the contents of the message
    // registers that contain fault specific information
    pub const SEL4_VMENTER_FAULT_REASON_MR: usize = 3;
    pub const SEL4_VMENTER_FAULT_QUALIFICATION_MR: usize = 4;
    pub const SEL4_VMENTER_FAULT_INSTRUCTION_LEN_MR: usize = 5;
    pub const SEL4_VMENTER_FAULT_GUEST_PHYSICAL_MR: usize = 6;
    pub const SEL4_VMENTER_FAULT_RFLAGS_MR: usize = 7;
    pub const SEL4_VMENTER_FAULT_GUEST_INT_MR: usize = 8;
    pub const SEL4_VMENTER_FAULT_CR3_MR: usize = 9;
    pub const SEL4_VMENTER_FAULT_EAX: usize = 10;
    pub const SEL4_VMENTER_FAULT_EBX: usize = 11;
    pub const SEL4_VMENTER_FAULT_ECX: usize = 12;
    pub const SEL4_VMENTER_FAULT_EDX: usize = 13;
    pub const SEL4_VMENTER_FAULT_ESI: usize = 14;
    pub const SEL4_VMENTER_FAULT_EDI: usize = 15;
    pub const SEL4_VMENTER_FAULT_EBP: usize = 16;
    pub const SEL4_VMENTER_FAULT_R8: usize = 17;
    pub const SEL4_VMENTER_FAULT_R9: usize = 18;
    pub const SEL4_VMENTER_FAULT_R10: usize = 19;
    pub const SEL4_VMENTER_FAULT_R11: usize = 20;
    pub const SEL4_VMENTER_FAULT_R12: usize = 21;
    pub const SEL4_VMENTER_FAULT_R13: usize = 22;
    pub const SEL4_VMENTER_FAULT_R14: usize = 23;
    pub const SEL4_VMENTER_FAULT_R15: usize = 24;
    pub const SEL4_VMENTER_NUM_FAULT_MSGS: usize = 25;
}

#[derive(Debug, Clone, Default)]
pub struct VmEnterCall {
    pub eip: seL4_Word,
    pub control_ppc: seL4_Word,
    pub control_entry: seL4_Word,
}

/// Represents all the fault information provided when a VMEnter operation results in a fault
#[derive(Debug, Clone, Default)]
pub struct VmEnterFault {
    pub call: VmEnterCall,
    pub reason: seL4_Word,
    pub qualification: seL4_Word,
    pub instruction_len: seL4_Word,
    pub guest_physical: seL4_Word,
    pub rflags: seL4_Word,
    pub guest_int: seL4_Word,
    pub cr3: seL4_Word,
    // CPU registers
    pub eax: seL4_Word,
    pub ebx: seL4_Word,
    pub ecx: seL4_Word,
    pub edx: seL4_Word,
    pub esi: seL4_Word,
    pub edi: seL4_Word,
    pub ebp: seL4_Word,
    pub r8: seL4_Word,
    pub r9: seL4_Word,
    pub r10: seL4_Word,
    pub r11: seL4_Word,
    pub r12: seL4_Word,
    pub r13: seL4_Word,
    pub r14: seL4_Word,
    pub r15: seL4_Word,
}

/// Extracts VMEnter fault information from the IPC buffer
fn gather_vmenter_fault(ipc: &seL4_IPCBuffer, fault: &mut VmEnterFault) {
    use kernel_fault_context::*;
    fault.call.eip = ipc.msg[SEL4_VMENTER_CALL_EIP_MR];
    fault.call.control_ppc = ipc.msg[SEL4_VMENTER_CALL_CONTROL_PPC_MR];
    fault.call.control_entry = ipc.msg[SEL4_VMENTER_CALL_CONTROL_ENTRY_MR];
    fault.reason = ipc.msg[SEL4_VMENTER_FAULT_REASON_MR];
    fault.qualification = ipc.msg[SEL4_VMENTER_FAULT_QUALIFICATION_MR];
    fault.instruction_len = ipc.msg[SEL4_VMENTER_FAULT_INSTRUCTION_LEN_MR];
    fault.guest_physical = ipc.msg[SEL4_VMENTER_FAULT_GUEST_PHYSICAL_MR];
    fault.rflags = ipc.msg[SEL4_VMENTER_FAULT_RFLAGS_MR];
    fault.guest_int = ipc.msg[SEL4_VMENTER_FAULT_GUEST_INT_MR];
    fault.cr3 = ipc.msg[SEL4_VMENTER_FAULT_CR3_MR];
    fault.eax = ipc.msg[SEL4_VMENTER_FAULT_EAX];
    fault.ebx = ipc.msg[SEL4_VMENTER_FAULT_EBX];
    fault.ecx = ipc.msg[SEL4_VMENTER_FAULT_ECX];
    fault.edx = ipc.msg[SEL4_VMENTER_FAULT_EDX];
    fault.esi = ipc.msg[SEL4_VMENTER_FAULT_ESI];
    fault.edi = ipc.msg[SEL4_VMENTER_FAULT_EDI];
    fault.ebp = ipc.msg[SEL4_VMENTER_FAULT_EBP];
    fault.r8 = ipc.msg[SEL4_VMENTER_FAULT_R8];
    fault.r9 = ipc.msg[SEL4_VMENTER_FAULT_R9];
    fault.r10 = ipc.msg[SEL4_VMENTER_FAULT_R10];
    fault.r11 = ipc.msg[SEL4_VMENTER_FAULT_R11];
    fault.r12 = ipc.msg[SEL4_VMENTER_FAULT_R12];
    fault.r13 = ipc.msg[SEL4_VMENTER_FAULT_R13];
    fault.r14 = ipc.msg[SEL4_VMENTER_FAULT_R14];
    fault.r15 = ipc.msg[SEL4_VMENTER_FAULT_R15];
}

#[allow(non_snake_case)]
pub fn seL4_VMEnter(ipc: &mut seL4_IPCBuffer, fault: &mut VmEnterFault) -> (bool, seL4_Word) {
    ipc.msg[kernel_fault_context::SEL4_VMENTER_CALL_EIP_MR] = fault.call.eip;
    ipc.msg[kernel_fault_context::SEL4_VMENTER_CALL_CONTROL_PPC_MR] = fault.call.control_ppc;
    ipc.msg[kernel_fault_context::SEL4_VMENTER_CALL_CONTROL_ENTRY_MR] = fault.call.control_entry;

    let mut mr0 = ipc.msg[0];
    let mut mr1 = ipc.msg[1];
    let mut mr2 = ipc.msg[2];
    let mut mr3 = ipc.msg[3];
    let (fault_code, badge) = sys_send_recv(
        syscall_id::VMEnter,
        0,
        0,
        &mut mr0,
        &mut mr1,
        &mut mr2,
        &mut mr3,
        0,
    );
    ipc.msg[0] = mr0;
    ipc.msg[1] = mr1;
    ipc.msg[2] = mr2;
    ipc.msg[3] = mr3;
    if fault_code != 0 {
        gather_vmenter_fault(ipc, fault);
    }
    (fault_code != 0, badge)
}

fn sys_send_recv(
    sys: c_int,
    dest: seL4_Word,
    info_arg: seL4_Word,
    in_out_mr0: &mut seL4_Word,
    in_out_mr1: &mut seL4_Word,
    in_out_mr2: &mut seL4_Word,
    in_out_mr3: &mut seL4_Word,
    reply: seL4_Word,
) -> (seL4_Word, seL4_Word) {
    let sys = sys as seL4_Word;
    let out_info: seL4_Word;
    let out_badge: seL4_Word;

    unsafe {
        core::arch::asm!(
            "mov r14, rsp",
            "syscall",
            "mov rsp, r14",
            in("rdx") sys,
            inout("rdi") dest => out_badge,
            inout("rsi") info_arg => out_info,
            inout("r10") *in_out_mr0,
            inout("r8") *in_out_mr1,
            inout("r9") *in_out_mr2,
            inout("r15") *in_out_mr3,
            in("r12") reply,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("r14") _,
        );
        (out_info, out_badge)
    }
}

pub fn write_vmcs(vcpu: CPtr, ipc: &mut IpcBuffer, field: u32, value: u64) -> u64 {
    let ret = ipc
        .inner_mut()
        .seL4_X86_VCPU_WriteVMCS(vcpu.bits(), field.into(), value.into());
    assert_eq!(ret.error, 0);
    ret.written
}

pub fn read_vmcs(vcpu: CPtr, ipc: &mut IpcBuffer, field: u32) -> u64 {
    let ret = ipc
        .inner_mut()
        .seL4_X86_VCPU_ReadVMCS(vcpu.bits(), field.into());
    assert_eq!(ret.error, 0);
    ret.value
}
