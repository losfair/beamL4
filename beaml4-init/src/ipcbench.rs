use core::ptr::addr_of_mut;

use algorithms::{
    idalloc::IdAlloc64Trait,
    unialloc::{UniAllocTrait, UntypedInfoAdapter},
};
use alloc::{sync::Arc, vec::Vec};
use intrusive_collections::LinkedList;
use ipc::{
    host_paging::HostPagingContext,
    msgbuf::{decode_msg, encode_msg, DirectTransfer},
};
use sel4::{
    cap::{Endpoint, Tcb},
    init_thread::slot::{CNODE, TCB, VSPACE},
    sys::priorityConstants::seL4_MaxPrio,
    with_ipc_buffer_mut, CNodeCapData, CPtr, CapRights, IpcBuffer, MessageInfo, ObjectBlueprint,
    ObjectBlueprintX86, UserContext, VmAttributes,
};

use crate::{alloc_control::AllocState, tsc::time_since_boot};

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct TestMsg {
    a: u32,
    b: u32,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct TestReply {
    c: u32,
}

#[derive(Copy, Clone)]
#[repr(C, align(16))]
struct StackUnit([u8; 16]);

static mut STACK: [StackUnit; 256] = [StackUnit([0; 16]); 256];

pub fn benchmark_ipc(alloc_state: &AllocState, host_paging: &HostPagingContext) -> u64 {
    let mut utlist = LinkedList::new(UntypedInfoAdapter::NEW);
    let mut caplist = Vec::with_capacity(16);

    let tcb_cap = alloc_state.alloc_empty_cap();
    caplist.push(tcb_cap);
    utlist.push_back(Arc::new(
        alloc_state.alloc_and_retype(&ObjectBlueprint::Tcb, tcb_cap),
    ));
    let tcb_cap = Tcb::from_cptr(tcb_cap);

    let thread_ipc = alloc_state.alloc_empty_cap();
    caplist.push(thread_ipc);
    utlist.push_back(Arc::new(alloc_state.alloc_and_retype(
        &ObjectBlueprint::Arch(ObjectBlueprintX86::_4k),
        thread_ipc,
    )));
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
        .tcb_set_sched_params(TCB.cap(), seL4_MaxPrio as u64, seL4_MaxPrio as u64)
        .expect("Failed to set TCB priority");

    let endpoint = alloc_state.alloc_empty_cap();
    caplist.push(endpoint);
    utlist.push_back(Arc::new(
        alloc_state.alloc_and_retype(&ObjectBlueprint::Endpoint, endpoint),
    ));

    let mut regs = UserContext::default();
    let stack = unsafe { addr_of_mut!(STACK).add(1).cast::<u8>() } as usize;
    *regs.sp_mut() = stack as u64 - 8;
    *regs.pc_mut() = thread_entry as u64;
    *regs.c_param_mut(0) = thread_ipc_addr.addr().get() as u64;
    *regs.c_param_mut(1) = endpoint.bits() as u64;
    tcb_cap
        .tcb_write_all_registers(true, &mut regs)
        .expect("Failed to write registers");

    // temporarily promote our own priority
    TCB.cap()
        .tcb_set_sched_params(TCB.cap(), seL4_MaxPrio as u64, seL4_MaxPrio as u64)
        .expect("Failed to set TCB priority");
    let start_time = time_since_boot();
    let n = 100000usize;
    let endpoint = Endpoint::from_cptr(endpoint);
    for i in 0..n {
        with_ipc_buffer_mut(|ipc| {
            let (msg, _) = encode_msg(
                ipc,
                &TestMsg {
                    a: i as u32,
                    b: (i + 1) as u32,
                },
                DirectTransfer,
                &[],
            );
            let msg = endpoint.call(msg);
            let (decoded, _) = decode_msg::<TestReply>(ipc, msg).expect("Failed to decode reply");
            assert_eq!(decoded.c, (2 * i + 1) as u32);
        })
    }
    let duration = time_since_boot() - start_time;
    let latency = duration.as_nanos() / n as u128;
    TCB.cap()
        .tcb_set_sched_params(TCB.cap(), seL4_MaxPrio as u64, seL4_MaxPrio as u64 - 1)
        .expect("Failed to set TCB priority");

    CNODE
        .cap()
        .absolute_cptr(tcb_cap)
        .delete()
        .expect("Failed to delete TCB");
    for ut in utlist {
        CNODE
            .cap()
            .absolute_cptr(ut.cap.0)
            .revoke()
            .expect("Failed to revoke ut");
        alloc_state.borrow_mut().free_normal(&ut);
    }
    for cap in caplist {
        assert!(alloc_state.borrow_mut().capalloc.free(cap.bits()));
    }
    assert!(host_paging.free_unmapped_page(thread_ipc_addr));
    latency as u64
}

fn thread_entry(ipc: &mut IpcBuffer, endpoint: u64) -> ! {
    let (mut msg, _) = ipc.inner_mut().seL4_Recv(endpoint, ());
    loop {
        let (msg_, _) = decode_msg::<TestMsg>(ipc, MessageInfo::from_inner(msg))
            .expect("Failed to decode msg (thread)");
        let res = TestReply { c: msg_.a + msg_.b };
        let (msg_, _) = encode_msg(ipc, &res, DirectTransfer, &[]);
        msg = ipc
            .inner_mut()
            .seL4_ReplyRecv(endpoint, msg_.into_inner(), ())
            .0;
    }
}
