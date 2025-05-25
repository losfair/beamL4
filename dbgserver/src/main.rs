#![no_std]
#![no_main]

extern crate alloc;

mod shell;

use core::ptr::addr_of_mut;

use alloc::boxed::Box;
use ipc::{
    conventions::{SUBPROC_CSPACE, SUBPROC_ENDPOINT, SUBPROC_TCB},
    dbgsvc::DbgserverStartInfo,
    logging::set_log_endpoint,
    misc::delete_cap,
    msgbuf, println,
    timer::SvcTimer,
    x86_ioport::{inb, outb},
};
use pc_keyboard::{
    layouts::Us104Key, DecodedKey, EventDecoder, HandleControl, ScancodeSet, ScancodeSet1,
};
use sel4::{
    cap::{CNode, Endpoint},
    CPtr, CPtrWithDepth, CapRights, IpcBuffer, MessageInfo,
};
use shell::Shell;
use talc::{ErrOnOom, Span, Talc, Talck};

const RECV_CAP: CPtr = CPtr::from_bits(64);
const I8042_IOPORT_CAP: CPtr = CPtr::from_bits(65);
const I8042_INTERRUPT_CAP: CPtr = CPtr::from_bits(66);
const NOTIF_CAP: CPtr = CPtr::from_bits(67);
const LOGSERVER_ENDPOINT_CAP: CPtr = CPtr::from_bits(68);
const TIMESERVER_ENDPOINT_CAP: CPtr = CPtr::from_bits(69);
const I8042_INTERRUPT_SENDER_CAP: CPtr = CPtr::from_bits(70);
const SERIAL_IOPORT_CAP: CPtr = CPtr::from_bits(71);
const SERIAL_INTERRUPT_CAP: CPtr = CPtr::from_bits(72);
const SERIAL_INTERUPT_SENDER_CAP: CPtr = CPtr::from_bits(73);
pub const HYPERVISOR_CHANNEL_CAP: CPtr = CPtr::from_bits(74);

const I8042_INTERRUPT_SENDER_BADGE: u64 = 1 << 0;
const SERIAL_INTERRUPT_SENDER_BADGE: u64 = 1 << 1;

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

static mut HEAP: [u64; 262144] = [0; 262144];

#[no_mangle]
pub extern "C" fn _start(ipcbuf: &mut IpcBuffer) -> ! {
    unsafe {
        ALLOCATOR
            .lock()
            .claim(Span::from_base_size(
                addr_of_mut!(HEAP) as *mut u8,
                #[allow(static_mut_refs)]
                core::mem::size_of_val(&HEAP),
            ))
            .unwrap();
    }

    let cspace = CNode::from_cptr(SUBPROC_CSPACE);
    // Receive the ring
    ipcbuf.set_recv_slot(&cspace.absolute_cptr(RECV_CAP));
    let (msg, _) = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
    let (msg, littlenode_bits) =
        msgbuf::decode_msg::<DbgserverStartInfo>(ipcbuf, MessageInfo::from_inner(msg))
            .expect("Failed to decode message");
    let tsc_freq_mhz = msg.tsc_freq_mhz.to_native();
    let littlenode_bits = littlenode_bits.expect("Failed to get cnode bits");
    let littlenode = CNode::from_cptr(RECV_CAP);

    for (cap, src) in [
        (I8042_IOPORT_CAP, msg.i8042_ioport_cap),
        (I8042_INTERRUPT_CAP, msg.i8042_interrupt_cap),
        (NOTIF_CAP, msg.notif_rx_cap),
        (LOGSERVER_ENDPOINT_CAP, msg.logserver_endpoint_cap),
        (TIMESERVER_ENDPOINT_CAP, msg.timeserver_endpoint_cap),
        (SERIAL_IOPORT_CAP, msg.serial_ioport_cap),
        (SERIAL_INTERRUPT_CAP, msg.serial_interrupt_cap),
        (HYPERVISOR_CHANNEL_CAP, msg.hypervisor_channel_cap),
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
    assert_eq!(delete_cap(cspace, littlenode.cptr()), 0);
    unsafe {
        set_log_endpoint(Endpoint::from_cptr(LOGSERVER_ENDPOINT_CAP));
    }
    for (sender, badge, interrupt) in [
        (
            I8042_INTERRUPT_SENDER_CAP,
            I8042_INTERRUPT_SENDER_BADGE,
            I8042_INTERRUPT_CAP,
        ),
        (
            SERIAL_INTERUPT_SENDER_CAP,
            SERIAL_INTERRUPT_SENDER_BADGE,
            SERIAL_INTERRUPT_CAP,
        ),
    ] {
        assert_eq!(
            ipcbuf.inner_mut().seL4_CNode_Mint(
                SUBPROC_CSPACE.bits(),
                sender.bits(),
                64,
                SUBPROC_CSPACE.bits(),
                NOTIF_CAP.bits(),
                64,
                CapRights::write_only().into_inner(),
                badge
            ),
            0
        );
        assert_eq!(
            ipcbuf
                .inner_mut()
                .seL4_IRQHandler_SetNotification(interrupt.bits(), sender.bits()),
            0
        );
    }
    ipcbuf
        .inner_mut()
        .seL4_TCB_SetAffinity(SUBPROC_TCB.bits(), 1);

    // Serial interrupt: Received Data Available
    outb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8 + 1, 1);

    let timer = &*Box::leak(Box::new(SvcTimer {
        tsc_freq_mhz,
        cap: Endpoint::from_cptr(TIMESERVER_ENDPOINT_CAP),
    }));
    let mut kbd_decoder = ScancodeSet1::new();
    let mut kbd_event = EventDecoder::new(Us104Key, HandleControl::Ignore);
    let mut sh = Shell::new(timer);
    ipcbuf
        .inner_mut()
        .seL4_Reply(MessageInfo::new(0, 0, 0, 0).into_inner());

    loop {
        let (_, badge) = ipcbuf.inner_mut().seL4_Wait(NOTIF_CAP.bits());

        if badge & I8042_INTERRUPT_SENDER_BADGE != 0 {
            let data = inb(ipcbuf, I8042_IOPORT_CAP, 0x60);
            assert_eq!(
                ipcbuf
                    .inner_mut()
                    .seL4_IRQHandler_Ack(I8042_INTERRUPT_CAP.bits()),
                0
            );
            let Some(key) = kbd_decoder
                .advance_state(data as u8)
                .ok()
                .flatten()
                .and_then(|x| kbd_event.process_keyevent(x))
            else {
                continue;
            };

            match key {
                DecodedKey::RawKey(_) => {}
                DecodedKey::Unicode(x) => {
                    sh.input(ipcbuf, x as u8);
                }
            }
        }

        if badge & SERIAL_INTERRUPT_SENDER_BADGE != 0 {
            let mut data = inb(ipcbuf, SERIAL_IOPORT_CAP, 0x3f8);
            if data == b'\r' {
                data = b'\n';
            }
            assert_eq!(
                ipcbuf
                    .inner_mut()
                    .seL4_IRQHandler_Ack(SERIAL_INTERRUPT_CAP.bits()),
                0
            );
            sh.input(ipcbuf, data);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println!("panic[dbgserver]: {}", _info);
    sel4::sys::seL4_RecvWithMRsWithoutIPCBuffer(0, None, None, None, None, ());
    loop {
        sel4::r#yield();
    }
}
