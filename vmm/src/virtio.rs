use core::cell::RefCell;

use algorithms::{
    pagetable::PagingService,
    unialloc::UniAllocTrait,
    vm::vcpu::{VcpuException, VcpuFault, VcpuState, VcpuStateMask},
};
use alloc::boxed::Box;
use futures::future::Either;
use ipc::{
    msgbuf::{CapTransferGarbage, DirectTransfer, WrappedTransfer, encode_msg},
    untyped::UntypedCap,
    virtiosvc::{VirtioOpenSessionReq, VirtioServerReq},
    vmmsvc::VmPagingMode,
};
use sel4::{
    CPtr, FrameObjectType,
    cap::{CNode, Endpoint, Notification},
};

use crate::{
    fault::{DEFAULT_PRIORITY, MmioRequest},
    paging::VmPagingContext,
    runtime::{EventLoop, wait_for_fault},
    vapic::VirtualIoapic,
};

const SMALL_PAGE_SIZE_BITS: usize = FrameObjectType::GRANULE.bits();

enum Event {
    PageRefill,
    Interrupt,
    Vmcall,
}

pub async fn emulate_virtio(
    evl: &EventLoop,
    ua: &RefCell<impl UniAllocTrait<Untyped = UntypedCap>>,
    cspace: CNode,
    viosrv_endpoint: Endpoint,
    guest_mmio_addr: u64,
    guest_interrupt: u8,
    ept: &VmPagingContext<'_>,
    vioapic: &VirtualIoapic,
) {
    let page_refill_notif = Notification::from_bits(
        ua.borrow_mut()
            .get_capalloc()
            .alloc()
            .expect("alloc failed"),
    );
    let page_refill_notif_badge = evl.create_notification(page_refill_notif);

    let interrupt_notif = Notification::from_bits(
        ua.borrow_mut()
            .get_capalloc()
            .alloc()
            .expect("alloc failed"),
    );
    let interrupt_notif_badge = evl.create_notification(interrupt_notif);

    evl.with_ipcbuf(|ipc| {
        let (msg, garbage) = encode_msg(
            ipc,
            &VirtioServerReq::OpenSession(VirtioOpenSessionReq {
                page_refill_notif_sender_cap: 0,
                interrupt_notif_sender_cap: 1,
                large_page: matches!(ept.ps.borrow().config().mode, VmPagingMode::EptLargePage),
            }),
            WrappedTransfer {
                unialloc: ua,
                cspace,
            },
            &[page_refill_notif.cptr(), interrupt_notif.cptr()],
        );
        let reply = ipc
            .inner_mut()
            .seL4_Call(viosrv_endpoint.bits(), msg.into_inner());
        if let Some(x) = garbage {
            x.release(ipc);
        }
        assert_eq!(reply.get_label(), 1);
    });

    let check = &*Box::leak(Box::new(move |state: &VcpuState, _: &VcpuFault| {
        // vmcall, code, addr
        ((0x1000..=0x1002).contains(&state.eax) || (0x1010..=0x1012).contains(&state.eax))
            && (guest_mmio_addr..guest_mmio_addr + (1 << SMALL_PAGE_SIZE_BITS)).contains(&state.ebx)
    }));

    loop {
        let event = match futures::future::select(
            futures::future::select(
                evl.wait_for_notification(page_refill_notif_badge),
                evl.wait_for_notification(interrupt_notif_badge),
            ),
            wait_for_fault(DEFAULT_PRIORITY, 18, check),
        )
        .await
        {
            Either::Left((Either::Left(_), _)) => Event::PageRefill,
            Either::Left((Either::Right(_), _)) => Event::Interrupt,
            Either::Right(_) => Event::Vmcall,
        };
        match event {
            Event::PageRefill => {
                evl.with_ipcbuf(|ipc| {
                    let msg =
                        encode_msg(ipc, &VirtioServerReq::GetRefillAddress, DirectTransfer, &[]).0;
                    let reply = ipc
                        .inner_mut()
                        .seL4_Call(viosrv_endpoint.bits(), msg.into_inner());
                    assert_eq!(reply.get_label(), 1);
                    let page_addrs = ipc.msg_regs()[..reply.get_length() as usize].to_vec();
                    for page_addr in &page_addrs {
                        // XXX: assumes page_cap.0 is the current TCB's root cspace
                        let page_cap = CPtr::from_bits(
                            ept.ps
                                .borrow()
                                .ps_guest_phys_to_page_cap(*page_addr)
                                .unwrap_or_else(|| {
                                    panic!("failed to get page cap for {:#x}", page_addr)
                                })
                                .1,
                        );
                        let msg = encode_msg(
                            ipc,
                            &VirtioServerReq::Refill {
                                page_addr: *page_addr,
                            },
                            DirectTransfer,
                            &[page_cap],
                        )
                        .0;
                        let reply = ipc
                            .inner_mut()
                            .seL4_Call(viosrv_endpoint.bits(), msg.into_inner());
                        assert_eq!(reply.get_label(), 1);
                        // println!("refilled: {:#x}", page_addr);
                    }
                    // println!("refilled batch of size {}", page_addrs.len());
                });
            }
            Event::Interrupt => {
                let local_interrupt = vioapic.redirection_table.borrow()[guest_interrupt as usize];
                if local_interrupt != 0 {
                    evl.with_ipcbuf(|ipc| {
                        evl.vcpu()
                            .borrow_mut()
                            .inject_external_interrupt(ipc, local_interrupt)
                    });
                }
            }
            Event::Vmcall => {
                evl.ack_fault();
                let mut vcpu = evl.vcpu().borrow_mut();
                let vcpu = &mut **vcpu;
                evl.with_ipcbuf(|ipc| vcpu.load_state(ipc, VcpuStateMask::CS_ACCESS_RIGHTS));
                let dpl = vcpu.state().cs_access_rights_dpl();
                if dpl != 0 {
                    evl.with_ipcbuf(|ipc| {
                        vcpu.inject_exception(ipc, VcpuException::GeneralProtectionFault(0))
                    });
                    continue;
                }
                let req = MmioRequest::decode_hypercall(vcpu.state());
                evl.with_ipcbuf(|ipc| {
                    let msg = encode_msg(
                        ipc,
                        &VirtioServerReq::Mmio {
                            offset: (req.addr - guest_mmio_addr) as u32,
                            write: req.write.map(|x| x as u32),
                            size: req.size,
                        },
                        DirectTransfer,
                        &[],
                    )
                    .0;
                    let reply = ipc
                        .inner_mut()
                        .seL4_Call(viosrv_endpoint.bits(), msg.into_inner());
                    assert_eq!(reply.get_label(), 1);

                    let mut mask = VcpuStateMask::EIP;
                    if req.write.is_none() {
                        assert_eq!(reply.get_length(), 1);
                        vcpu.state_mut().eax = ipc.msg_regs()[0] as u64;
                        mask |= VcpuStateMask::EAX;
                    }
                    vcpu.state_mut().eip += vcpu.fault().instruction_len;
                    vcpu.commit_state(ipc, mask);
                });
            }
        }
    }
}
