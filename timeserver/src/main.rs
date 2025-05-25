#![no_std]
#![no_main]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use core::{mem::MaybeUninit, time::Duration};

use algorithms::idalloc::{IdAlloc64, IdAlloc64OffsetLimit, IdAlloc64Trait};
use ipc::{
    conventions::{SUBPROC_CSPACE, SUBPROC_ENDPOINT},
    logging::set_log_endpoint,
    misc::{delete_cap, now_cycles},
    msgbuf::decode_msg,
    println,
    timesvc::{ArchivedTimeserverMsg, TimeserverMsg, TimeserverStartInfo},
    x86_ioport::outb,
};
use scapegoat::SgMap;
use sel4::{
    cap::{CNode, Endpoint, IrqHandler, Notification},
    CPtr, CPtrWithDepth, IpcBuffer, MessageInfo,
};
use talc::{ErrOnOom, Talc, Talck};

extern crate ipc;

const RECV_CAP: CPtr = CPtr::from_bits(64);
const IOPORT_CAP: CPtr = CPtr::from_bits(65);
const IRQ_CAP: IrqHandler = IrqHandler::from_bits(66);
const NOTIF_CAP: Notification = Notification::from_bits(67);
const LOGSERVER_ENDPOINT_CAP: Endpoint = Endpoint::from_bits(68);

const WHEEL_CAP_START: u64 = 128;
const WHEEL_CAP_END: u64 = 256;

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

// (deadline_cycles, id) -> (user_notif_cap, cancellation_token)
static mut WHEEL: MaybeUninit<
    SgMap<(u64, u64), (u64, [u8; 16]), { (WHEEL_CAP_END - WHEEL_CAP_START) as usize }>,
> = MaybeUninit::uninit();
// (cancellation_token, id) -> deadline_cycles
static mut CANCELLATION: MaybeUninit<
    SgMap<([u8; 16], u64), u64, { (WHEEL_CAP_END - WHEEL_CAP_START) as usize }>,
> = MaybeUninit::uninit();
static mut WHEEL_ALLOC: IdAlloc64OffsetLimit<IdAlloc64<2>> = unsafe { core::mem::zeroed() };

#[no_mangle]
pub extern "C" fn _start(ipcbuf: &mut IpcBuffer) -> ! {
    #[allow(static_mut_refs)]
    let wheel = unsafe { WHEEL.write(SgMap::new()) };
    #[allow(static_mut_refs)]
    let cancellation = unsafe { CANCELLATION.write(SgMap::new()) };
    #[allow(static_mut_refs)]
    let wheel_alloc = unsafe { &mut WHEEL_ALLOC };
    wheel_alloc.offset = WHEEL_CAP_START;
    wheel_alloc.limit = WHEEL_CAP_END;

    let cspace = CNode::from_cptr(SUBPROC_CSPACE);
    ipcbuf.set_recv_slot(&cspace.absolute_cptr(RECV_CAP));
    let (msg, _) = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
    let (msg, littlenode_bits) =
        ipc::msgbuf::decode_msg::<TimeserverStartInfo>(ipcbuf, MessageInfo::from_inner(msg))
            .expect("Failed to decode message");
    let notif_badge = msg.notif_badge.to_native();
    let endpoint_badge = msg.endpoint_badge.to_native();
    let cycles_per_us = msg.tsc_frequency_mhz.to_native() as u64;
    let littlenode_bits = littlenode_bits.expect("Failed to get cnode bits");
    let littlenode = CNode::from_cptr(RECV_CAP);
    for (cap, src) in [
        (IOPORT_CAP, msg.pit_ioport_cap.to_native()),
        (IRQ_CAP.cptr(), msg.pit_interrupt_cap.to_native()),
        (NOTIF_CAP.cptr(), msg.notif_cap.to_native()),
        (
            LOGSERVER_ENDPOINT_CAP.cptr(),
            msg.logserver_endpoint_cap.to_native(),
        ),
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

    assert_eq!(delete_cap(cspace, RECV_CAP), 0);

    let ret = ipcbuf
        .inner_mut()
        .seL4_IRQHandler_SetNotification(IRQ_CAP.bits(), NOTIF_CAP.bits());
    assert_eq!(ret, 0);

    unsafe {
        set_log_endpoint(LOGSERVER_ENDPOINT_CAP);
    }

    println!("timeserver: starting up");

    // channel 0, lobyte/hibyte, square wave generator
    outb(ipcbuf, IOPORT_CAP, 0x43, 0b00110110);
    pit_reload(ipcbuf, Duration::from_millis(5));

    ipcbuf
        .inner_mut()
        .seL4_Reply(MessageInfo::new(0, 0, 0, 0).into_inner());

    let mut next_id = 1u64;

    loop {
        let (msg, badge) = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
        let msg = MessageInfo::from_inner(msg);
        let now = now_cycles();

        if badge == notif_badge as u64 {
            assert_eq!(ipcbuf.inner_mut().seL4_IRQHandler_Ack(IRQ_CAP.bits()), 0);
            while let Some((first, _)) = wheel.first_key().copied() {
                if first > now {
                    break;
                }
                let ((deadline_cycles, id), (user_cap, cancellation_token)) =
                    wheel.pop_first().unwrap();
                assert_eq!(
                    cancellation.remove(&(cancellation_token, id)),
                    Some(deadline_cycles)
                );
                let _ = ipcbuf.inner_mut().seL4_Signal(user_cap);
                assert_eq!(delete_cap(cspace, CPtr::from_bits(user_cap)), 0);
                assert!(wheel_alloc.free(user_cap));
            }
        } else if badge == endpoint_badge as u64 {
            let msginfo = msg;
            let Ok((msg, _)) = decode_msg::<TimeserverMsg>(ipcbuf, msginfo.clone()) else {
                println!("timeserver: cannot decode ipc message");
                let _ = delete_cap(cspace, RECV_CAP);
                continue;
            };

            match msg {
                ArchivedTimeserverMsg::Cancel { cancellation_token } => {
                    let cancellation_token = *cancellation_token;
                    if msginfo.extra_caps() != 0 {
                        println!("timeserver: Cancel: invalid message");
                        let _ = delete_cap(cspace, RECV_CAP);
                        continue;
                    }
                    while let Some((&(_, id), &deadline_cycles)) = cancellation
                        .range((cancellation_token, 0)..=(cancellation_token, u64::MAX))
                        .next()
                    {
                        assert!(cancellation.remove(&(cancellation_token, id)).is_some());
                        let user_cap = wheel
                            .remove(&(deadline_cycles, id))
                            .filter(|x| x.1 == cancellation_token)
                            .expect("failed to remove from wheel")
                            .0;
                        assert_eq!(delete_cap(cspace, CPtr::from_bits(user_cap)), 0);
                        assert!(wheel_alloc.free(user_cap));
                    }

                    // do not update PIT registers here - it's probably slower than just letting in an early interrupt
                    continue;
                }
                ArchivedTimeserverMsg::NotifyAfter {
                    duration_us,
                    cancellation_token,
                } => {
                    if msginfo.extra_caps() != 1 || msginfo.caps_unwrapped() != 0 {
                        println!("timeserver: NotifyAfter: invalid message");
                        let _ = delete_cap(cspace, RECV_CAP);
                        continue;
                    }

                    let cancellation_token = *cancellation_token;

                    let deadline_cycles =
                        now.saturating_add(cycles_per_us.saturating_mul(duration_us.to_native()));
                    let id = next_id;
                    next_id += 1;

                    let Some(user_cap) = wheel_alloc.alloc() else {
                        println!("timeserver: out of user caps");
                        let _ = ipcbuf.inner_mut().seL4_Signal(RECV_CAP.bits());
                        assert_eq!(delete_cap(cspace, RECV_CAP), 0);
                        continue;
                    };
                    let dst = cspace.absolute_cptr(CPtr::from_bits(user_cap));
                    let src = cspace.absolute_cptr(RECV_CAP);
                    assert_eq!(
                        ipcbuf.inner_mut().seL4_CNode_Move(
                            cspace.bits(),
                            dst.path().bits(),
                            dst.path().depth() as u8,
                            src.root().bits(),
                            src.path().bits(),
                            src.path().depth() as u8,
                        ),
                        0
                    );
                    let prev_deadline = wheel.first_key().copied().map(|x| x.0);
                    wheel.insert((deadline_cycles, id), (user_cap, cancellation_token));
                    cancellation.insert((cancellation_token, id), deadline_cycles);

                    // skip updating PIT registers if the new deadline is not the earliest
                    if prev_deadline.is_some() && deadline_cycles >= prev_deadline.unwrap() {
                        continue;
                    }
                }
            }
        } else {
            panic!("Unknown badge: {}", badge);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println!("panic[timeserver]: {}", _info);
    sel4::sys::seL4_RecvWithMRsWithoutIPCBuffer(0, None, None, None, None, ());
    loop {
        sel4::r#yield();
    }
}

fn pit_reload(ipcbuf: &mut IpcBuffer, duration: Duration) {
    let value =
        ((duration.as_micros() as u64).saturating_mul(3579545) / 3_000_000).clamp(1, 0xffff) as u16;
    outb(ipcbuf, IOPORT_CAP, 0x40, value as u8);
    outb(ipcbuf, IOPORT_CAP, 0x40, (value >> 8) as u8);
}
