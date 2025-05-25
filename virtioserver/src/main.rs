#![no_std]
#![no_main]
#![allow(incomplete_features, static_mut_refs)]
#![feature(
    generic_const_exprs,
    new_zeroed_alloc,
    maybe_uninit_as_bytes,
    maybe_uninit_slice
)]

extern crate alloc;

mod pipeline;
mod shared;
mod virtq;

use core::{ptr::addr_of_mut, time::Duration};

use ipc::{
    conventions::{SUBPROC_CSPACE, SUBPROC_ENDPOINT, SUBPROC_TCB},
    logging::set_log_endpoint,
    misc::{delete_cap, hw_rng_u64, now_cycles, MmioSize},
    msgbuf::{decode_msg, encode_msg, DirectTransfer},
    println,
    timesvc::TimeserverMsg,
    userfault::UserfaultConfig,
    virtiosvc::{ArchivedVirtioServerReq, VirtioServerReq, VirtioServerStartInfo},
};
use pipeline::{Pipeline, PipelineContext};
use sel4::{cap::CNode, CPtrWithDepth, CapRights, IpcBuffer, MessageInfo};
use shared::*;
use talc::{ErrOnOom, Span, Talc, Talck};

extern crate ipc;

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

static mut HEAP: [u64; 262144] = [0; 262144];

const CSPACE: CNode = CNode::from_cptr(SUBPROC_CSPACE);

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
    ipcbuf.set_recv_slot(&cspace.absolute_cptr(RECV_CAP));
    let (msg, _) = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
    let (msg, littlenode_bits) =
        ipc::msgbuf::decode_msg::<VirtioServerStartInfo>(ipcbuf, MessageInfo::from_inner(msg))
            .expect("Failed to decode message");
    let start_time = now_cycles();
    let priority = msg.priority;
    let root_cnode_bits = msg.root_cnode_bits;
    let notify_off_multiplier = msg.notify_off_multiplier.to_native();
    let cycles_per_us = msg.tsc_frequency_mhz.to_native() as u64;
    let endpoint_badge = msg.endpoint_badge as u64;
    let irq_notif_badge = msg.irq_notif_cap_badge as u64;
    let timer_notif_badge: u64 = 4;
    let virtio_device_id = msg.virtio_device_id.to_native();
    let tsc_freq_mhz = msg.tsc_frequency_mhz.to_native();
    assert_ne!(timer_notif_badge, endpoint_badge);
    assert_ne!(timer_notif_badge, irq_notif_badge);
    let littlenode_bits = littlenode_bits.expect("Failed to get cnode bits");
    let littlenode = CNode::from_cptr(RECV_CAP);

    unsafe {
        DESCRIPTION.0[..msg.description.len()].copy_from_slice(&msg.description.as_bytes());
        DESCRIPTION.1 = msg.description.len();
    }
    for (cap, src) in [
        (LOGSERVER_ENDPOINT_CAP.cptr(), msg.logserver_endpoint_cap),
        (TIMESERVER_ENDPOINT_CAP.cptr(), msg.timeserver_endpoint_cap),
        (IRQ_NOTIF_CAP.cptr(), msg.irq_notif_cap),
        (
            P_COMMON_CFG_4KB_FRAME_CAP.cptr(),
            msg.p_common_cfg_4kb_frame_cap,
        ),
        (
            P_NOTIFY_CFG_4KB_FRAME_CAP.cptr(),
            msg.p_notify_cfg_4kb_frame_cap,
        ),
        (P_ISR_CFG_4KB_FRAME_CAP.cptr(), msg.p_isr_cfg_4kb_frame_cap),
        (
            P_DEVICE_CFG_4KB_FRAME_CAP.cptr(),
            msg.p_device_cfg_4kb_frame_cap,
        ),
        (UNTYPED_2MB_CAP[0].cptr(), msg.untyped_2mb_caps[0]),
        (UNTYPED_2MB_CAP[1].cptr(), msg.untyped_2mb_caps[1]),
        (USERFAULT_TCB_CAP.cptr(), msg.userfault_tcb_cap),
        (USERFAULT_ENDPOINT_CAP.cptr(), msg.endpoint_caps[0]),
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

    unsafe {
        set_log_endpoint(LOGSERVER_ENDPOINT_CAP);
    }

    ipc::userfault::init(
        ipcbuf,
        &UserfaultConfig {
            priority,
            root_cnode_bits,
            userfault_tcb_cap: USERFAULT_TCB_CAP,
            userfault_endpoint_cap: USERFAULT_ENDPOINT_CAP,
        },
    );

    assert_eq!(
        ipcbuf
            .inner_mut()
            .seL4_TCB_BindNotification(SUBPROC_TCB.bits(), IRQ_NOTIF_CAP.bits()),
        0
    );

    assert_eq!(
        ipcbuf.inner_mut().seL4_CNode_Mint(
            SUBPROC_CSPACE.bits(),
            TIMER_NOTIF_SENDER_CAP.bits(),
            64,
            SUBPROC_CSPACE.bits(),
            IRQ_NOTIF_CAP.bits(),
            64,
            CapRights::write_only().into_inner(),
            timer_notif_badge
        ),
        0
    );

    let mut pipeline = Pipeline::new(
        ipcbuf,
        PipelineContext {
            notify_off_multiplier,
            virtio_device_id,
            tsc_freq_mhz,
        },
    );

    pipeline.reset(ipcbuf);
    let init_duration = Duration::from_micros((now_cycles() - start_time) / cycles_per_us);

    println!(
        "virtioserver[{}]: init completed in {:?}",
        self_description(),
        init_duration
    );

    ipcbuf
        .inner_mut()
        .seL4_Reply(MessageInfo::new(0, 0, 0, 0).into_inner());

    let timer_period_us = 20 * 1000;
    let mut cancellation_token = [0u8; 16];
    cancellation_token[0..8].copy_from_slice(hw_rng_u64().to_ne_bytes().as_slice());
    cancellation_token[8..16].copy_from_slice(hw_rng_u64().to_ne_bytes().as_slice());

    let msg = encode_msg(
        ipcbuf,
        &TimeserverMsg::NotifyAfter {
            duration_us: timer_period_us,
            cancellation_token,
        },
        DirectTransfer,
        &[TIMER_NOTIF_SENDER_CAP.cptr()],
    )
    .0;
    ipcbuf
        .inner_mut()
        .seL4_Send(TIMESERVER_ENDPOINT_CAP.bits(), msg.into_inner());

    let mut rawmsg = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
    loop {
        let msg = MessageInfo::from_inner(rawmsg.0);

        if rawmsg.1 == endpoint_badge {
            // IPC call
            let mut recv_cap_consumed = false;
            let reply = if let Ok((req, littlenode_bits)) =
                decode_msg::<VirtioServerReq>(ipcbuf, msg.clone())
            {
                match req {
                    ArchivedVirtioServerReq::OpenSession(x) => {
                        if let Ok(req) = rkyv::deserialize::<_, rkyv::rancor::Error>(x) {
                            pipeline.open_session(
                                ipcbuf,
                                msg.clone(),
                                req,
                                littlenode_bits.unwrap_or_default(),
                                &mut recv_cap_consumed,
                            )
                        } else {
                            None
                        }
                    }
                    ArchivedVirtioServerReq::Mmio {
                        offset,
                        write,
                        size,
                    } => pipeline.mmio(
                        ipcbuf,
                        offset.to_native(),
                        write.as_ref().map(|x| x.to_native()),
                        rkyv::deserialize::<MmioSize, rkyv::rancor::Error>(size).unwrap(),
                    ),
                    ArchivedVirtioServerReq::GetRefillAddress => {
                        pipeline.get_refill_address(ipcbuf)
                    }
                    ArchivedVirtioServerReq::Refill { page_addr } => pipeline.refill(
                        ipcbuf,
                        msg.clone(),
                        page_addr.to_native(),
                        &mut recv_cap_consumed,
                    ),
                }
            } else {
                None
            };
            if !recv_cap_consumed && msg.extra_caps() > 0 {
                delete_cap(CSPACE, RECV_CAP);
            }
            let reply = reply.unwrap_or_else(|| MessageInfo::new(0, 0, 0, 0));

            rawmsg =
                ipcbuf
                    .inner_mut()
                    .seL4_ReplyRecv(SUBPROC_ENDPOINT.bits(), reply.into_inner(), ());
        } else {
            // one or more notifications
            if rawmsg.1 & irq_notif_badge != 0 {
                pipeline.irq_notif(ipcbuf);
            }

            if rawmsg.1 & timer_notif_badge != 0 {
                let msg = encode_msg(
                    ipcbuf,
                    &TimeserverMsg::NotifyAfter {
                        duration_us: timer_period_us,
                        cancellation_token,
                    },
                    DirectTransfer,
                    &[TIMER_NOTIF_SENDER_CAP.cptr()],
                )
                .0;
                ipcbuf
                    .inner_mut()
                    .seL4_Send(TIMESERVER_ENDPOINT_CAP.bits(), msg.into_inner());
                pipeline.timer_notif(ipcbuf);
            }

            rawmsg = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println!("panic[virtioserver[{}]]: {}", self_description(), _info);
    sel4::sys::seL4_RecvWithMRsWithoutIPCBuffer(0, None, None, None, None, ());
    loop {
        sel4::r#yield();
    }
}
