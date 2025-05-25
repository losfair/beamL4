#![no_std]
#![no_main]

use core::{ptr::addr_of_mut, sync::atomic::Ordering};

use ipc::{
    conventions::{
        SUBPROC_CSPACE, SUBPROC_ENDPOINT, SUBPROC_IPC_BUFFER, SUBPROC_PREMAPPED_LARGE_PAGE_REGION,
        SUBPROC_TCB, SUBPROC_VSPACE,
    },
    logging::{LogRing, LogserverStartInfo},
    misc::delete_cap,
    msgbuf,
    x86_ioport::outb,
};
use sel4::{
    cap::CNode, CNodeCapData, CPtr, CPtrWithDepth, CapRights, IpcBuffer, MessageInfo, UserContext,
    VmAttributes,
};
use talc::{ErrOnOom, Talc, Talck};

const RECV_CAP: CPtr = CPtr::from_bits(64);
const RING_CAP: CPtr = CPtr::from_bits(65);
const NOTIF_CAP: CPtr = CPtr::from_bits(66);
const SERIAL_IOPORT_CAP: CPtr = CPtr::from_bits(67);
const THREAD_TCB_CAP: CPtr = CPtr::from_bits(68);
const VGA_MMIO_CAP_START: u64 = 69; // 32 slots

#[derive(Copy, Clone)]
#[repr(C, align(16))]
struct StackUnit([u8; 16]);

static mut STACK: [StackUnit; 4096] = [StackUnit([0; 16]); 4096];

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

#[no_mangle]
pub extern "C" fn _start(ipcbuf: &mut IpcBuffer) -> ! {
    let cspace = CNode::from_cptr(SUBPROC_CSPACE);
    // Receive the ring
    ipcbuf.set_recv_slot(&cspace.absolute_cptr(RECV_CAP));
    let (msg, _) = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
    let (msg, littlenode_bits) =
        msgbuf::decode_msg::<LogserverStartInfo>(ipcbuf, MessageInfo::from_inner(msg))
            .expect("Failed to decode message");
    let littlenode_bits = littlenode_bits.expect("Failed to get cnode bits");
    let littlenode = CNode::from_cptr(RECV_CAP);
    let writer_thread_priority = msg.writer_thread_priority;

    assert_eq!(
        msg.page_cap_end.to_native() - msg.page_cap_start.to_native(),
        32
    );
    let page_cap_start = msg.page_cap_start.to_native();

    for (cap, src) in [
        (RING_CAP, msg.ring_cap.to_native()),
        (NOTIF_CAP, msg.notif_rx_cap.to_native()),
        (SERIAL_IOPORT_CAP, msg.serial_ioport_cap.to_native()),
        (THREAD_TCB_CAP, msg.thread_tcb_cap.to_native()),
    ] {
        let dst = cspace.absolute_cptr(cap);
        let src = littlenode.absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            src as u64,
            littlenode_bits.into(),
        ));
        let ret = ipcbuf.inner_mut().seL4_CNode_Move(
            dst.root().bits(),
            dst.path().bits(),
            dst.path().depth() as u8,
            src.root().bits(),
            src.path().bits(),
            src.path().depth() as u8,
        );
        assert_eq!(ret, 0);
    }

    let ring = SUBPROC_PREMAPPED_LARGE_PAGE_REGION.start as *mut LogRing;
    let ret = ipcbuf.inner_mut().seL4_X86_Page_Map(
        RING_CAP.bits(),
        SUBPROC_VSPACE.bits(),
        ring as u64,
        CapRights::read_write().into_inner(),
        VmAttributes::DEFAULT.into_inner(),
    );
    assert_eq!(ret, 0);
    sel4::debug_println!("logserver: ring mapped at {:p}", ring);

    let vgafb = 0xa0000usize as *mut [u8; 0x20000];
    for i in 0..32u64 {
        let dst = cspace.absolute_cptr(CPtr::from_bits(VGA_MMIO_CAP_START + i));
        let src = littlenode.absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            page_cap_start as u64 + i,
            littlenode_bits.into(),
        ));
        let ret = ipcbuf.inner_mut().seL4_CNode_Move(
            dst.root().bits(),
            dst.path().bits(),
            dst.path().depth() as u8,
            src.root().bits(),
            src.path().bits(),
            src.path().depth() as u8,
        );
        assert_eq!(ret, 0);

        let ret = ipcbuf.inner_mut().seL4_X86_Page_Map(
            VGA_MMIO_CAP_START + i,
            SUBPROC_VSPACE.bits(),
            vgafb as u64 + (i * 0x1000),
            CapRights::read_write().into_inner(),
            VmAttributes::CACHE_DISABLED.into_inner(),
        );
        assert_eq!(ret, 0);
    }
    sel4::debug_println!("logserver: vgafb mapped at {:p}", vgafb);

    assert_eq!(delete_cap(cspace, littlenode.cptr()), 0);

    outb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8 + 1, 0x00);
    outb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8 + 3, 0x80);
    outb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8 + 0, 0x01);
    outb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8 + 1, 0x00);
    outb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8 + 3, 0x03);
    outb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8 + 2, 0x00);

    // 80x25 text mode
    // fill the screen with blue
    for i in 0..80 {
        for j in 0..25 {
            let addr = (0xb8000usize + (i * 2) + (j * 160)) as *mut u8;
            unsafe { addr.write_volatile(0x20) };
            unsafe { addr.add(1).write_volatile(0x1F) };
        }
    }

    ipcbuf
        .inner_mut()
        .seL4_Reply(MessageInfo::new(0, 0, 0, 0).into_inner());

    // child ipc buffer
    assert!(core::mem::size_of::<IpcBuffer>() <= 2048);
    let child_ipcbuf = unsafe {
        (ipcbuf as *mut IpcBuffer as *mut u8)
            .add(2048)
            .cast::<IpcBuffer>()
    };
    assert_eq!(
        ipcbuf.inner_mut().seL4_TCB_Configure(
            THREAD_TCB_CAP.bits(),
            0,
            SUBPROC_CSPACE.bits(),
            CNodeCapData::new(0, 56).into_word(),
            SUBPROC_VSPACE.bits(),
            0,
            child_ipcbuf as _,
            SUBPROC_IPC_BUFFER.bits(),
        ),
        0
    );
    assert_eq!(
        ipcbuf.inner_mut().seL4_TCB_SetSchedParams(
            THREAD_TCB_CAP.bits(),
            SUBPROC_TCB.bits(),
            writer_thread_priority as _,
            writer_thread_priority as _,
        ),
        0
    );
    ipcbuf
        .inner_mut()
        .seL4_TCB_SetAffinity(THREAD_TCB_CAP.bits(), 1);

    let ring = unsafe { &*ring };
    let mut ctx = RenderThreadContext { ring, vgafb };
    let mut regs = UserContext::default();
    let stack = unsafe { addr_of_mut!(STACK).add(1).cast::<u8>() } as usize;
    *regs.sp_mut() = stack as u64 - 8;
    *regs.pc_mut() = render_thread as u64;
    *regs.c_param_mut(0) = child_ipcbuf as u64;
    *regs.c_param_mut(1) = &mut ctx as *mut RenderThreadContext as u64;
    assert_eq!(
        ipcbuf.inner_mut().seL4_TCB_WriteRegisters(
            THREAD_TCB_CAP.bits(),
            1,
            0,
            (core::mem::size_of_val(regs.inner()) / core::mem::size_of::<usize>()) as u64,
            regs.inner(),
        ),
        0
    );

    loop {
        let (msg, _) = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
        let len = msg.get_label().min(msg.get_length() * 8);
        let bytes = &ipcbuf.msg_bytes()[..len as usize];
        // for b in bytes {
        //     sel4::debug_put_char(*b);
        // }
        ring.enqueue(bytes);
        ipcbuf.inner_mut().seL4_Signal(NOTIF_CAP.bits());
    }
}

fn vga_print_byte(byte: u8, buffer: &mut [u8; 80 * 25], cursor: &mut usize) {
    if byte == b'\n' || *cursor == 79 {
        // move buffer up a line
        for i in 0..80 * 24 {
            buffer[i] = buffer[i + 80];
        }
        // clear the last line
        for i in 0..80 {
            buffer[80 * 24 + i] = b' ';
        }
        *cursor = 0;
    }

    if byte == b'\r' || byte == b'\n' {
        return;
    }

    // append to last line
    buffer[80 * 24 + *cursor] = byte;
    *cursor += 1;
}

unsafe fn commit_fb(
    fb: *mut [u8; 131072],
    current: &mut [u8; 80 * 25],
    committed: &mut [u8; 80 * 25],
) {
    let fb = fb.cast::<u8>().add(0x18000);
    for row in 0..25 {
        for col in 0..80 {
            let idx = row * 80 + col;
            let byte = current[idx];
            if byte != committed[idx] {
                fb.add(idx * 2).write_volatile(byte);
                fb.add(idx * 2 + 1).write_volatile(0x0F);
                committed[idx] = byte;
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sel4::debug_println!("panic[logserver]: {}", _info);
    sel4::sys::seL4_RecvWithMRsWithoutIPCBuffer(0, None, None, None, None, ());
    loop {
        sel4::r#yield();
    }
}

struct RenderThreadContext<'a> {
    ring: &'a LogRing,
    vgafb: *mut [u8; 0x20000],
}

fn render_thread(ipcbuf: &mut IpcBuffer, ctx: &mut RenderThreadContext<'_>) -> ! {
    // we have 64KB stack, plenty for this
    let mut buffer_current = [0u8; 80 * 25];
    let mut buffer_committed = [0u8; 80 * 25];
    let mut text_cursor = 0usize;

    let mut local_head = 0u32;
    let ring = ctx.ring;
    loop {
        let their_head = ring.head.load(Ordering::SeqCst);
        if their_head == local_head {
            unsafe {
                commit_fb(ctx.vgafb, &mut buffer_current, &mut buffer_committed);
            }
            ipcbuf.inner_mut().seL4_Wait(NOTIF_CAP.bits());
            continue;
        }
        let byte = ring.bytes[local_head as usize % ring.bytes.len()].load(Ordering::Relaxed);
        outb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8, byte.into());
        vga_print_byte(byte, &mut buffer_current, &mut text_cursor);
        local_head += 1;
        ring.used.store(local_head, Ordering::SeqCst);
    }
}
