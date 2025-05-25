use core::{arch::global_asm, convert::Infallible, ptr::addr_of_mut};

use crate::conventions::{SUBPROC_CSPACE, SUBPROC_IPC_BUFFER, SUBPROC_TCB, SUBPROC_VSPACE};
use sel4::{
    cap::{Endpoint, Tcb},
    sys::{
        invocation_label, seL4_Fault_tag::seL4_Fault_VMFault, seL4_VMFault_Msg::seL4_VMFault_IP,
    },
    CNodeCapData, IpcBuffer, MessageInfo, UserContext,
};

#[derive(Copy, Clone)]
#[repr(C, align(16))]
struct StackUnit([u8; 16]);

static mut STACK: [StackUnit; 1024] = [StackUnit([0; 16]); 1024];

extern "C" {
    fn asm_usercopy(dst: *mut u8, src: *const u8, len: usize) -> usize;
    fn asm_usercopy_done(_: Infallible) -> !;
}

#[derive(Copy, Clone, Debug)]
pub struct UserfaultConfig {
    pub priority: u8,
    pub root_cnode_bits: u8,
    pub userfault_tcb_cap: Tcb,
    pub userfault_endpoint_cap: Endpoint,
}

pub fn init(ipc: &mut IpcBuffer, config: &UserfaultConfig) {
    assert!(core::mem::size_of::<IpcBuffer>() <= 2048);
    let child_ipcbuf = unsafe {
        (ipc as *mut IpcBuffer as *mut u8)
            .add(2048)
            .cast::<IpcBuffer>()
    };
    assert_eq!(
        ipc.inner_mut().seL4_TCB_Configure(
            config.userfault_tcb_cap.bits(),
            0,
            SUBPROC_CSPACE.bits(),
            CNodeCapData::new(0, (64 - config.root_cnode_bits) as _).into_word(),
            SUBPROC_VSPACE.bits(),
            0,
            child_ipcbuf as _,
            SUBPROC_IPC_BUFFER.bits(),
        ),
        0
    );
    assert_eq!(
        ipc.inner_mut().seL4_TCB_SetSchedParams(
            config.userfault_tcb_cap.bits(),
            SUBPROC_TCB.bits(),
            config.priority as _,
            config.priority as _,
        ),
        0
    );

    let mut regs = UserContext::default();
    *regs.sp_mut() = unsafe { addr_of_mut!(STACK).add(1).cast::<u8>() } as u64 - 8;
    *regs.pc_mut() = userfault_thread as u64;
    *regs.c_param_mut(0) = child_ipcbuf as u64;
    *regs.c_param_mut(1) = config.userfault_endpoint_cap.bits();
    assert_eq!(
        ipc.inner_mut().seL4_TCB_WriteRegisters(
            config.userfault_tcb_cap.bits(),
            1,
            0,
            (core::mem::size_of_val(regs.inner()) / core::mem::size_of::<usize>()) as u64,
            regs.inner(),
        ),
        0
    );
    assert_eq!(
        ipc.inner_mut().seL4_TCB_SetSpace(
            SUBPROC_TCB.bits(),
            config.userfault_endpoint_cap.bits(),
            SUBPROC_CSPACE.bits(),
            CNodeCapData::new(0, (64 - config.root_cnode_bits) as _).into_word(),
            SUBPROC_VSPACE.bits(),
            0,
        ),
        0
    );

    // selftest
    assert_eq!(read_user_memory(&mut [0], 0x100 as *const u8), Err(1));
    assert_eq!(unsafe { write_user_memory(0x100 as *mut u8, &[0]) }, Err(1));
    let mut buf1 = [0u8; 4];
    let mut buf2 = [0u8; 4];
    assert_eq!(
        unsafe { write_user_memory(buf1.as_mut_ptr(), &[1, 2, 3, 4]) },
        Ok(())
    );
    assert_eq!(buf1, [1, 2, 3, 4]);
    assert_eq!(read_user_memory(&mut buf2, buf1.as_ptr()), Ok(()));
    assert_eq!(buf2, [1, 2, 3, 4]);
}

fn userfault_thread(ipc: &mut IpcBuffer, userfault_endpoint_cap: u64) -> ! {
    let mut msg = ipc.inner_mut().seL4_Recv(userfault_endpoint_cap, ()).0;
    loop {
        if msg.get_label() == seL4_Fault_VMFault
            && (asm_usercopy as u64..asm_usercopy_done as u64)
                .contains(&ipc.msg_regs()[seL4_VMFault_IP as usize])
        {
            let call = MessageInfo::new(invocation_label::TCBWriteRegisters.into(), 0, 0, 3);
            ipc.msg_regs_mut()[0] = 0;
            ipc.msg_regs_mut()[1] = 1; // count
            ipc.msg_regs_mut()[2] = asm_usercopy_done as _; // pc
            ipc.inner_mut()
                .seL4_Call(SUBPROC_TCB.bits(), call.into_inner());
        } else {
            panic!(
                "userfault: label={} mr={:#x?}",
                msg.get_label(),
                &ipc.msg_regs()[..msg.get_length() as usize]
            );
        }
        msg = ipc
            .inner_mut()
            .seL4_ReplyRecv(
                userfault_endpoint_cap,
                MessageInfo::new(0, 0, 0, 0).into_inner(),
                (),
            )
            .0;
    }
}

pub fn read_user_memory(dst: &mut [u8], src: *const u8) -> Result<(), usize> {
    let len = dst.len();
    let ret = unsafe { asm_usercopy(dst.as_mut_ptr(), src, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

pub unsafe fn write_user_memory(dst: *mut u8, src: &[u8]) -> Result<(), usize> {
    let len = src.len();
    let ret = asm_usercopy(dst, src.as_ptr(), len);
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

global_asm!(
    r#"
.global asm_usercopy
.global asm_usercopy_done

// asm_usercopy: copies data from kernel space to user space
// Arguments:
//   rdi: destination pointer (user space)
//   rsi: source pointer (kernel space)
//   rdx: length in bytes
// Returns:
//   rax: number of bytes not copied (0 on success)
asm_usercopy:
    // Initialize counter
    xor     rcx, rcx
    mov     r10, rdx        // Save original length in rbx

    // Check if length is zero
    test    rdx, rdx
    jz      asm_usercopy_done

    // Main copy loop
asm_usercopy_loop:
    // Copy one byte at a time
    movzx   eax, BYTE PTR [rsi + rcx]
    mov     BYTE PTR [rdi + rcx], al

    // Increment counter and check if we're done
    inc     rcx
    cmp     rcx, r10
    jne     asm_usercopy_loop

asm_usercopy_done:
    // Calculate bytes not copied (0 if all copied)
    mov     rax, r10
    sub     rax, rcx
    ret
"#,
);
