use core::ptr::addr_of_mut;

use alloc::{boxed::Box, vec::Vec};
use ipc::host_paging::HostPagingContext;
use sel4::{
    cap::{IrqHandler, Notification, Tcb},
    init_thread::slot::{CNODE, IRQ_CONTROL, TCB, VSPACE},
    sys::priorityConstants::seL4_MaxPrio,
    with_ipc_buffer_mut, CNodeCapData, CPtr, CapRights, IpcBuffer, ObjectBlueprint,
    ObjectBlueprintX86, UserContext, VmAttributes,
};

use crate::{alloc_control::AllocState, static_config::allocate_intr_vector};

#[derive(Copy, Clone)]
#[repr(C, align(16))]
struct StackUnit([u8; 16]);

static mut STACK: [StackUnit; 256] = [StackUnit([0; 16]); 256];

struct IrqAggregatorInit {
    notif_vec: Notification,
    irq_handler_vec: &'static [IrqHandler],
    notif_sender_vec: &'static [Notification],
}

pub fn start_irq_aggregator(
    alloc_state: &AllocState,
    host_paging: &HostPagingContext,
    gsi_list: &[u32],
    notif_sender_vec: &'static [Notification],
) {
    assert!(gsi_list.len() <= 64);
    let notif_vec = Notification::from_cptr(alloc_state.alloc_empty_cap());
    alloc_state.alloc_and_retype(&ObjectBlueprint::Notification, notif_vec.cptr());
    let mut irq_handler_vec = Vec::with_capacity(gsi_list.len());
    for (i, &gsi) in gsi_list.iter().enumerate() {
        let irq_handler = IrqHandler::from_cptr(alloc_state.alloc_empty_cap());
        IRQ_CONTROL
            .cap()
            .irq_control_get_ioapic(
                0,
                gsi.into(),
                0,
                0,
                allocate_intr_vector().into(),
                &CNODE.cap().absolute_cptr(irq_handler),
            )
            .expect("Failed to get virtio pci IRQHandler");
        let notif_vec_badged = Notification::from_cptr(alloc_state.alloc_empty_cap());
        CNODE
            .cap()
            .absolute_cptr(notif_vec_badged)
            .mint(
                &CNODE.cap().absolute_cptr(notif_vec),
                CapRights::read_write(),
                1 << i,
            )
            .expect("Failed to mint notification");
        irq_handler
            .irq_handler_set_notification(notif_vec_badged)
            .expect("Failed to set notification for irq");
        irq_handler_vec.push(irq_handler);
    }
    assert_eq!(irq_handler_vec.len(), gsi_list.len());
    let irq_handler_vec = &*Box::leak(irq_handler_vec.into_boxed_slice());

    let init = &*Box::leak(Box::new(IrqAggregatorInit {
        notif_vec,
        irq_handler_vec,
        notif_sender_vec,
    }));

    let tcb_cap = alloc_state.alloc_empty_cap();
    alloc_state.alloc_and_retype(&ObjectBlueprint::Tcb, tcb_cap);
    let tcb_cap = Tcb::from_cptr(tcb_cap);

    let thread_ipc = alloc_state.alloc_empty_cap();
    alloc_state.alloc_and_retype(&ObjectBlueprint::Arch(ObjectBlueprintX86::_4k), thread_ipc);
    let thread_ipc = sel4::cap::_4k::from_cptr(thread_ipc);
    let thread_ipc_addr = with_ipc_buffer_mut(|ipc| host_paging.alloc_unmapped_page(ipc));
    thread_ipc
        .frame_map(
            VSPACE.cap(),
            thread_ipc_addr.addr().get(),
            CapRights::read_write(),
            VmAttributes::DEFAULT,
        )
        .expect("Failed to map thread IPC page");
    tcb_cap
        .tcb_configure(
            CPtr::from_bits(0),
            CNODE.cap(),
            CNodeCapData::new(0, 48),
            VSPACE.cap(),
            thread_ipc_addr.addr().get() as u64,
            thread_ipc,
        )
        .expect("Failed to configure TCB");
    tcb_cap
        .tcb_set_sched_params(TCB.cap(), seL4_MaxPrio as u64, seL4_MaxPrio as u64 - 1)
        .expect("Failed to set TCB priority");
    let mut regs = UserContext::default();
    let stack = unsafe { addr_of_mut!(STACK).add(1).cast::<u8>() } as usize;
    *regs.sp_mut() = stack as u64 - 8;
    *regs.pc_mut() = thread_entry as u64;
    *regs.c_param_mut(0) = thread_ipc_addr.addr().get() as u64;
    *regs.c_param_mut(1) = init as *const IrqAggregatorInit as u64;
    tcb_cap
        .tcb_write_all_registers(true, &mut regs)
        .expect("Failed to write registers");
}

fn thread_entry(ipc: &mut IpcBuffer, init: &'static IrqAggregatorInit) -> ! {
    loop {
        let fired: u64 = ipc.inner_mut().seL4_Wait(init.notif_vec.bits()).1;
        assert!(fired != 0);
        for i in 0..64usize {
            if fired & (1 << i) != 0 {
                let irq_handler = init.irq_handler_vec[i];
                assert_eq!(ipc.inner_mut().seL4_IRQHandler_Ack(irq_handler.bits()), 0);
            }
        }
        for notif_sender in init.notif_sender_vec {
            ipc.inner_mut().seL4_Signal(notif_sender.bits());
        }
    }
}
