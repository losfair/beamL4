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

mod hypercall;
mod loader;
mod shared;
mod vmservice;

use core::{
    cell::RefCell,
    mem::MaybeUninit,
    ptr::addr_of_mut,
    sync::atomic::{AtomicBool, Ordering},
};

use algorithms::{
    idalloc::{IdAlloc64, IdAlloc64OffsetLimit},
    unialloc::{uni_alloc_init, BoxOrStatic, UniAlloc, UniAllocTrait, UntypedInfo},
    vm::vcpu::{AbstractVcpu, VcpuStateMask},
};
use alloc::{boxed::Box, vec::Vec};
use intrusive_collections::LinkedListLink;
use ipc::{
    alloc::alloc_and_retype,
    conventions::{SUBPROC_CSPACE, SUBPROC_ENDPOINT, SUBPROC_TCB, SUBPROC_VSPACE},
    host_paging::HostPagingContext,
    logging::set_log_endpoint,
    misc::delete_cap,
    println,
    timer::SvcTimer,
    untyped::UntypedCap,
    vmmsvc::{VmPagingMode, VmmServerStartInfo},
};
use sel4::{
    cap::{CNode, Endpoint, Notification, Tcb, Untyped, VSpace, PML4},
    CNodeCapData, CPtr, CPtrWithDepth, CapRights, FrameObjectType, IpcBuffer, MessageInfo,
    ObjectBlueprint,
};
use shared::*;
use talc::{ErrOnOom, Span, Talc, Talck};
use vmm::{
    paging::{L0CNodeInfo, VmPagingConfig, VmPagingContext},
    pv::vcpu::{PvVcpu, PvVcpuContext},
    runtime::EventLoop,
    vapic::VirtualIoapic,
    vmx::vcpu::{VmxVcpu, VmxVcpuContext},
};

extern crate ipc;

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

static mut HEAP: [u64; 128 * 1024] = [0; 128 * 1024];
static mut ALLOC_STATE: MaybeUninit<RefCell<UniAlloc<UntypedCap, 2>>> = MaybeUninit::uninit();
static mut ALLOC_STATE_IDALLOC: MaybeUninit<IdAlloc64OffsetLimit<IdAlloc64<2>>> =
    MaybeUninit::uninit();
static mut GUEST_PAGING: MaybeUninit<VmPagingContext<'static>> = MaybeUninit::uninit();
static mut HOST_PAGING: MaybeUninit<HostPagingContext<'static>> = MaybeUninit::uninit();
static mut EVENT_LOOP: MaybeUninit<EventLoop> = MaybeUninit::uninit();
static INIT_DONE: AtomicBool = AtomicBool::new(false);

const CSPACE: CNode = CNode::from_cptr(SUBPROC_CSPACE);

#[no_mangle]
pub extern "C" fn _start(ipcbuf: &mut IpcBuffer) -> ! {
    unsafe {
        ALLOCATOR
            .lock()
            .claim(Span::from_base_size(
                addr_of_mut!(HEAP) as *mut u8,
                core::mem::size_of_val(&HEAP),
            ))
            .unwrap();
    }
    // Pre-initialize decoder tables
    let _ = iced_x86::Decoder::new(64, &[0x90], 0);

    ipcbuf.set_recv_slot(&CSPACE.absolute_cptr(RECV_CAP));
    let (msg, _) = ipcbuf.inner_mut().seL4_Recv(SUBPROC_ENDPOINT.bits(), ());
    let (msg, littlenode_bits) =
        ipc::msgbuf::decode_msg::<VmmServerStartInfo>(ipcbuf, MessageInfo::from_inner(msg))
            .expect("Failed to decode message");
    let root_cnode_bits = msg.cnode_bits;
    let num_untyped = msg.num_untyped.to_native();
    let tsc_freq_mhz = msg.tsc_frequency_mhz.to_native();
    let num_kernel_pages = msg.num_kernel_pages.to_native();
    let viosrv_cap_start = msg.virtio_device_endpoint_cap_start;
    let viosrv_cap_count = msg.num_virtio_devices as usize;
    let has_rtc_ioport_cap = msg.has_rtc_ioport_cap;
    let priority = msg.priority;
    let affinity = msg.affinity.to_native();
    let paging_mode = rkyv::deserialize::<_, rkyv::rancor::Error>(&msg.paging_mode)
        .expect("Failed to deserialize paging mode");
    let littlenode_bits = littlenode_bits.expect("Failed to get cnode bits");
    let littlenode = CNode::from_cptr(RECV_CAP);

    unsafe {
        DESCRIPTION.0[..msg.description.len()].copy_from_slice(&msg.description.as_bytes());
        DESCRIPTION.1 = msg.description.len();
    }
    for (cap, src, copy) in [
        (
            LOGSERVER_ENDPOINT_CAP.cptr(),
            msg.logserver_endpoint_cap,
            true,
        ),
        (
            TIMESERVER_ENDPOINT_CAP.cptr(),
            msg.timeserver_endpoint_cap,
            true,
        ),
        (UNTYPED_BUCKET_CAP.cptr(), msg.untyped_bucket_cap, true),
        (KERNEL_BUCKET_CAP.cptr(), msg.kernel_bucket_cap, true),
        (ASID_POOL_CAP.cptr(), msg.asid_pool_cap, true),
        (RTC_IOPORT_CAP, msg.rtc_ioport_cap, msg.has_rtc_ioport_cap),
        (
            HYPERVISOR_CHANNEL_CAP.cptr(),
            msg.hypervisor_channel_cap,
            true,
        ),
    ] {
        if !copy {
            continue;
        }

        let dst = CSPACE.absolute_cptr(cap);
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

    assert!(root_cnode_bits > 8);
    assert!(root_cnode_bits <= 32);

    let mut empty_cap_start: u64 = 256;
    // copy in untyped caps
    let untyped_bucket_bits = num_untyped.next_power_of_two().trailing_zeros();
    for i in 0..num_untyped as u64 {
        let dst = CSPACE.absolute_cptr(CPtr::from_bits(empty_cap_start));
        let src = UNTYPED_BUCKET_CAP.absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            i,
            untyped_bucket_bits as usize,
        ));
        assert_eq!(
            ipcbuf.inner_mut().seL4_CNode_Move(
                dst.root().bits(),
                dst.path().bits(),
                dst.path().depth() as u8,
                src.root().bits(),
                src.path().bits(),
                src.path().depth() as u8,
            ),
            0
        );
        empty_cap_start += 1;
    }

    let alloc_state;
    let host_paging;

    unsafe {
        set_log_endpoint(LOGSERVER_ENDPOINT_CAP);
        let capalloc = ALLOC_STATE_IDALLOC.assume_init_mut();
        alloc_state = &*ALLOC_STATE.write(RefCell::new(uni_alloc_init(
            || {
                (256..empty_cap_start).map(|i| UntypedInfo {
                    link: LinkedListLink::new(),
                    cap: UntypedCap(Untyped::from_bits(i)),
                    // fake phys addr
                    paddr: i * FrameObjectType::LargePage.bytes() as u64,
                    size_bits: FrameObjectType::LargePage.bits() as u8,
                    is_device: false,
                })
            },
            empty_cap_start,
            1 << root_cnode_bits,
            BoxOrStatic::Static(capalloc),
        )));
        host_paging = HOST_PAGING.write(HostPagingContext::new(
            alloc_state,
            CSPACE,
            PML4::from_cptr(SUBPROC_VSPACE),
            DYNAMIC_PAGES_REGION.start as u64,
            DYNAMIC_PAGES_REGION.end as u64,
        ));
    }
    let mut virtio_sender_caps = Vec::with_capacity(viosrv_cap_count);
    for i in viosrv_cap_start..(viosrv_cap_start + viosrv_cap_count as u8) {
        let dst = alloc_state
            .borrow_mut()
            .get_capalloc()
            .alloc()
            .expect("Failed to allocate cap");
        let dst_abs = CSPACE.absolute_cptr(CPtr::from_bits(dst));
        let src = littlenode.absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            i as u64,
            littlenode_bits.into(),
        ));
        let ret = ipcbuf.inner_mut().seL4_CNode_Move(
            dst_abs.root().bits(),
            dst_abs.path().bits(),
            dst_abs.path().depth() as u8,
            src.root().bits(),
            src.path().bits(),
            src.path().depth() as u8,
        );
        assert_eq!(ret, 0);
        virtio_sender_caps.push(Endpoint::from_bits(dst));
    }

    assert_eq!(delete_cap(CSPACE, RECV_CAP), 0);

    // switch to 2-level cspace (32/32 bits split)
    alloc_and_retype(
        ipcbuf,
        alloc_state,
        CSPACE,
        &ObjectBlueprint::CNode {
            size_bits: L0_CNODE_BITS as _,
        },
        L0_CNODE_CAP.cptr(),
    )
    .expect("Failed to allocate L0 cnode");
    assert_eq!(
        ipcbuf.inner_mut().seL4_CNode_Mint(
            L0_CNODE_CAP.bits(),
            0,
            L0_CNODE_BITS,
            SUBPROC_CSPACE.bits(),
            SUBPROC_CSPACE.bits(),
            64,
            CapRights::read_write().into_inner(),
            CNodeCapData::new(0, 32 - root_cnode_bits as usize).into_word(),
        ),
        0
    );
    assert_eq!(
        ipcbuf.inner_mut().seL4_TCB_SetSpace(
            SUBPROC_TCB.bits(),
            0,
            L0_CNODE_CAP.bits(),
            CNodeCapData::new(0, 32 - L0_CNODE_BITS as usize).into_word(),
            SUBPROC_VSPACE.bits(),
            0
        ),
        0
    );

    println!(
        "enabled 2-level captable with 32/32 split, initial cap start/limit: {} {}",
        empty_cap_start,
        1 << root_cnode_bits
    );

    let alloc_target = alloc_state
        .borrow_mut()
        .total_remaining_normal(21)
        .saturating_sub(8 * 1024 * 1024);
    assert!(alloc_target > 0, "Not enough memory for the guest");
    let paging = VmPagingContext::new(
        alloc_state,
        ASID_POOL_CAP,
        Tcb::from_cptr(SUBPROC_TCB),
        CSPACE,
        VSpace::from_cptr(SUBPROC_VSPACE),
        VmPagingConfig {
            identity_mapping: IDMAP_REGION.start as u64..IDMAP_REGION.end as u64,
            total_memory_bytes: alloc_target,
            mode: paging_mode,
            l0c: L0CNodeInfo {
                cnode: L0_CNODE_CAP,
                real_bits: L0_CNODE_BITS,
                resolve_bits: 32,
                index: 1,
            },
        },
        ipcbuf,
    );
    let paging = &*unsafe { GUEST_PAGING.write(paging) };

    // drop ASID_POOL_CAP - we are going to execute untrusted code
    assert_eq!(delete_cap(CSPACE, ASID_POOL_CAP.cptr()), 0);

    let nanos_boot = loader::load_elf(
        ipcbuf,
        alloc_state,
        paging,
        num_kernel_pages as usize,
        virtio_sender_caps.len(),
    );

    // println!("Patch points: {:x?}", nanos_boot.patch_point_set);

    let timer = &*Box::leak(Box::new(SvcTimer {
        tsc_freq_mhz,
        cap: TIMESERVER_ENDPOINT_CAP,
    }));

    let mut vcpu: Box<dyn AbstractVcpu<Context = IpcBuffer>> =
        if matches!(paging_mode, VmPagingMode::Pv) {
            PvVcpu::new_boxed(
                ipcbuf,
                CSPACE,
                L0CNodeInfo {
                    cnode: L0_CNODE_CAP,
                    real_bits: L0_CNODE_BITS,
                    resolve_bits: 32,
                    index: 2,
                },
                alloc_state,
                paging,
                host_paging,
                nanos_boot.patch_point_set,
                PvVcpuContext {
                    tsc_freq_mhz,
                    affinity,
                    priority,
                },
            )
        } else {
            VmxVcpu::new_boxed(
                ipcbuf,
                CSPACE,
                &mut *alloc_state.borrow_mut(),
                timer,
                VmxVcpuContext {
                    tcb: Tcb::from_cptr(SUBPROC_TCB),
                    rtc_ioport: if has_rtc_ioport_cap {
                        Some(RTC_IOPORT_CAP)
                    } else {
                        None
                    },
                },
            )
        };
    vcpu.state_mut().eip = nanos_boot.entrypoint;
    vcpu.state_mut().ebx = GUEST_START_INFO_PHYS;
    vcpu.state_mut().esp = GUEST_STACK_PHYS;
    vcpu.state_mut().cr0 = 0x80000021; // PE, NE, PG
    vcpu.state_mut().cr3 = GUEST_INITIAL_PT_PML4_PHYS;
    vcpu.state_mut().cr4 = (1 << 4) | (1 << 5); // PAE, PSE
    vcpu.state_mut().rflags = 0x2;
    vcpu.commit_state(ipcbuf, VcpuStateMask::all_writable());
    vcpu.write_msr(ipcbuf, 0xc000_0080, (1 << 8) | (1 << 10));
    println!(
        "VCPU initialized with entrypoint: {:#x}",
        nanos_boot.entrypoint
    );

    let [evl_notif_cap, evl_timer_notif_cap] = [(), ()].map(|()| {
        Notification::from_bits(
            alloc_state
                .borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("Failed to allocate cap"),
        )
    });
    let evl = EventLoop::new(
        ipcbuf,
        timer,
        CSPACE,
        vcpu,
        Tcb::from_cptr(SUBPROC_TCB),
        evl_notif_cap,
        evl_timer_notif_cap,
        alloc_state,
    );
    let evl = unsafe { &*EVENT_LOOP.write(evl) };
    let vioapic = &*Box::leak(VirtualIoapic::new_boxed());

    evl.spawn(vmm::fault::emulate_cr(evl));
    evl.spawn(vmm::fault::emulate_rdmsr(evl));
    evl.spawn(vmm::fault::emulate_wrmsr(evl));
    evl.spawn(vmm::fault::emulate_serial(evl));
    evl.spawn(vmm::fault::emulate_cpuid(evl));
    evl.spawn(vmm::fault::emulate_xsetbv(evl));
    evl.spawn(vmm::fault::emulate_pit(evl));
    evl.spawn(vmm::fault::emulate_generic_io_port(evl));
    evl.spawn(vmm::fault::emulate_x2apic(evl));
    evl.spawn(vmservice::emulate_misc_vmcall(evl));
    evl.spawn(vmservice::emulate_reboot(evl));
    evl.spawn(vmservice::emulate_balloon_vmcall(evl, paging));
    evl.spawn(vioapic.emulate(evl));

    if matches!(paging_mode, VmPagingMode::Pv) && has_rtc_ioport_cap {
        evl.spawn(vmm::fault::emulate_passthrough_io_port_range(
            evl,
            0x70,
            0x71,
            RTC_IOPORT_CAP,
        ));
    }

    // virtio tasks
    {
        let mut guest_phys = GUEST_VIRTIO_MMIO_START;
        let mut guest_interrupt = GUEST_VIRTIO_MMIO_INTERRUPT_BASE;
        for sender in &virtio_sender_caps {
            evl.spawn(vmm::virtio::emulate_virtio(
                evl,
                alloc_state,
                CSPACE,
                *sender,
                guest_phys,
                guest_interrupt,
                paging,
                vioapic,
            ));
            guest_phys += FrameObjectType::GRANULE.bytes() as u64;
            guest_interrupt += 1;
        }
    }

    // set affinity for self
    // this is allowed to fail
    let ret = ipcbuf
        .inner_mut()
        .seL4_TCB_SetAffinity(SUBPROC_TCB.bits(), affinity.into());
    if ret != 0 {
        println!("W: failed to set affinity to {}: error {}", affinity, ret);
    }

    println!("vmmserver: starting up");
    ipcbuf
        .inner_mut()
        .seL4_Reply(MessageInfo::new(0, 0, 0, 0).into_inner());
    INIT_DONE.store(true, Ordering::Relaxed);

    evl.run(ipcbuf);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println!("panic[vmmserver[{}]]: {}", self_description(), _info);
    if !INIT_DONE.load(Ordering::Relaxed) {
        sel4::sys::seL4_ReplyWithMRsWithoutIPCBuffer(
            MessageInfo::new(0, 0, 0, 0).into_inner(),
            None,
            None,
            None,
            None,
        );
    }
    sel4::sys::seL4_RecvWithMRsWithoutIPCBuffer(0, None, None, None, None, ());
    loop {
        sel4::r#yield();
    }
}
