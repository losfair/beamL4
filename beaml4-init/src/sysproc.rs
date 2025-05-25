use core::{iter::once, time::Duration};

use algorithms::{
    idalloc::IdAlloc64Trait,
    unialloc::{UniAllocTrait, UntypedInfo, UntypedInfoAdapter},
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::ToString,
    sync::{Arc, Weak},
    vec::Vec,
};
use intrusive_collections::LinkedList;
use ipc::{
    dbgsvc::DbgserverStartInfo,
    host_paging::HostPagingContext,
    logging::{get_log_endpoint, set_log_endpoint, LogserverStartInfo},
    misc::now_cycles,
    msgbuf::{encode_msg, CapTransferGarbage, UnmanagedTransfer, WrappedTransfer},
    timesvc::TimeserverStartInfo,
    untyped::UntypedCap,
    virtiosvc::VirtioServerStartInfo,
    vmmsvc::{VmPagingMode, VmmServerStartInfo},
};
use sel4::{
    cap::{CNode, Endpoint, LargePage, Notification},
    init_thread::slot::{ASID_POOL, CNODE, IO_PORT_CONTROL, IRQ_CONTROL},
    sys::priorityConstants::{seL4_MaxPrio, seL4_MinPrio},
    with_ipc_buffer_mut, CPtr, CPtrWithDepth, CapRights, FrameObjectType, ObjectBlueprint,
    ObjectBlueprintX86,
};

use crate::{
    acpi_loader::AcpiInfo,
    alloc_control::AllocState,
    elfloader::{start_process, ProcessInfo, SubprocessConfig},
    static_config::{allocate_intr_vector, SELF_START_ADDR},
    tsc::tsc_freq_mhz,
    virtio_pci::VirtioPciDevice,
};

extern "C" {
    static _binary_logserver_elf_start: u8;
    static _binary_logserver_elf_end: u8;
    static _binary_dbgserver_elf_start: u8;
    static _binary_dbgserver_elf_end: u8;
    static _binary_timeserver_elf_start: u8;
    static _binary_timeserver_elf_end: u8;
    static _binary_virtioserver_elf_start: u8;
    static _binary_virtioserver_elf_end: u8;
    static _binary_vmmserver_elf_start: u8;
    static _binary_vmmserver_elf_end: u8;
    static _binary_nanos_elf_start: u8;
    static _binary_nanos_elf_end: u8;
}

pub fn start_logserver(
    alloc_state: &AllocState,
    host_paging: &HostPagingContext,
    serial_ioport_cap: CPtr,
) -> ProcessInfo {
    let logserver_elf = unsafe {
        core::slice::from_raw_parts(
            &_binary_logserver_elf_start as *const u8,
            &_binary_logserver_elf_end as *const u8 as usize
                - &_binary_logserver_elf_start as *const u8 as usize,
        )
    };
    let logserver_priority = (seL4_MaxPrio - 1) as u8;
    let mut logserver = start_process(
        alloc_state,
        host_paging,
        logserver_elf,
        SubprocessConfig {
            priority: logserver_priority,
            badge: 0,
            cnode_bits: 8,
            expose_tcb: true,
        },
    );

    let littlenode_depth_bits = 6usize;
    let littlenode = CNode::from_cptr(alloc_state.alloc_empty_cap());
    let mut littlenode_counter = 0u64;
    let littlenode_ut = Box::new(alloc_state.alloc_and_retype(
        &ObjectBlueprint::CNode {
            size_bits: littlenode_depth_bits,
        },
        littlenode.cptr(),
    ));

    logserver
        .utlist
        .push_back(Arc::new(alloc_state.alloc_and_retype_in(
            &ObjectBlueprint::Arch(ObjectBlueprintX86::LargePage),
            littlenode,
            littlenode_counter as usize,
        )));
    littlenode_counter += 1;

    logserver
        .utlist
        .push_back(Arc::new(alloc_state.alloc_and_retype_in(
            &ObjectBlueprint::Notification,
            littlenode,
            littlenode_counter as usize,
        )));
    littlenode_counter += 1;

    littlenode
        .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
            littlenode_counter,
            littlenode_depth_bits,
        ))
        .copy(
            &CNODE.cap().absolute_cptr(serial_ioport_cap),
            CapRights::read_write(),
        )
        .expect("Failed to copy serial IO port control");
    littlenode_counter += 1;

    logserver
        .utlist
        .push_back(Arc::new(alloc_state.alloc_and_retype_in(
            &ObjectBlueprint::Tcb,
            littlenode,
            littlenode_counter as usize,
        )));
    littlenode_counter += 1;

    let page_cap_start = littlenode_counter;
    for page_addr in (0xa0000..0xc0000u64).step_by(0x1000) {
        let ut = alloc_state
            .alloc_device(page_addr, 12)
            .expect("Failed to allocate VGA MMIO page");
        ut.cap
            .0
            .untyped_retype(
                &ObjectBlueprint::Arch(ObjectBlueprintX86::_4k),
                &CNODE.cap().absolute_cptr(littlenode),
                littlenode_counter as usize,
                1,
            )
            .expect("Failed to retype untyped to page");
        littlenode_counter += 1;
    }
    let page_cap_end = littlenode_counter;

    let (msg, _) = with_ipc_buffer_mut(|ipc| {
        encode_msg(
            ipc,
            &LogserverStartInfo {
                ring_cap: 0,
                notif_rx_cap: 1,
                serial_ioport_cap: 2,
                thread_tcb_cap: 3,
                page_cap_start: page_cap_start as usize,
                page_cap_end: page_cap_end as usize,
                priority: logserver_priority,
                writer_thread_priority: seL4_MinPrio as u8,
            },
            UnmanagedTransfer {
                cnode_bits: littlenode_depth_bits as u8,
                cptr: littlenode.cptr(),
            },
            &[],
        )
    });
    logserver.endpoint_sender.call(msg);
    CNODE
        .cap()
        .absolute_cptr(littlenode_ut.cap.0)
        .revoke()
        .expect("Failed to revoke littlenode");
    alloc_state.borrow_mut().free_normal(&littlenode_ut);
    sel4::debug_println!("logserver memory usage: {} bytes", logserver.total_bytes());
    unsafe {
        set_log_endpoint(logserver.endpoint_sender);
    }

    logserver
}

pub fn start_timeserver(
    alloc_state: &AllocState,
    host_paging: &HostPagingContext,
    acpi: &AcpiInfo,
) -> ProcessInfo {
    let logserver_endpoint =
        get_log_endpoint().expect("Logserver endpoint not set, cannot start timeserver");
    let timeserver_elf = unsafe {
        core::slice::from_raw_parts(
            &_binary_timeserver_elf_start as *const u8,
            &_binary_timeserver_elf_end as *const u8 as usize
                - &_binary_timeserver_elf_start as *const u8 as usize,
        )
    };
    let mut timeserver = start_process(
        alloc_state,
        host_paging,
        timeserver_elf,
        SubprocessConfig {
            priority: (seL4_MaxPrio - 1) as _,
            badge: 1,
            cnode_bits: 8,
            expose_tcb: false,
        },
    );

    let mut caplist = heapless::Vec::<CPtr, 8>::new();
    let mut capdroplist = heapless::Vec::<CPtr, 8>::new();

    let ioport = alloc_state.alloc_empty_cap();

    IO_PORT_CONTROL
        .cap()
        .ioport_control_issue(0x40, 0x47, &CNODE.cap().absolute_cptr(ioport))
        .expect("Failed to issue PIT IO port control");
    caplist.push(ioport).unwrap();
    capdroplist.push(ioport).unwrap();

    let intr_handler = alloc_state.alloc_empty_cap();
    let intr_vector = allocate_intr_vector();
    let gsi = *acpi.ioapic_irq_to_gsi.get(&0).expect("PIT IRQ 0 not found");
    IRQ_CONTROL
        .cap()
        .irq_control_get_ioapic(
            0,
            gsi.into(),
            0,
            0,
            intr_vector.into(),
            &CNODE.cap().absolute_cptr(intr_handler),
        )
        .expect("Failed to get PIT IRQHandler");
    caplist.push(intr_handler).unwrap();
    capdroplist.push(intr_handler).unwrap();

    let notif_unbadged = Notification::from_cptr(alloc_state.alloc_empty_cap());
    let notif = Notification::from_cptr(alloc_state.alloc_empty_cap());
    timeserver.utlist.push_back(Arc::new(
        alloc_state.alloc_and_retype(&ObjectBlueprint::Notification, notif_unbadged.cptr()),
    ));
    CNODE
        .cap()
        .absolute_cptr(notif.cptr())
        .mint(
            &CNODE.cap().absolute_cptr(notif_unbadged.cptr()),
            CapRights::write_only(),
            2,
        )
        .expect("Failed to rebadge notif");

    caplist.push(notif.cptr()).unwrap();
    capdroplist.push(notif.cptr()).unwrap();

    caplist.push(logserver_endpoint.cptr()).unwrap();

    timeserver
        .tcb
        .tcb_bind_notification(notif_unbadged)
        .expect("Failed to bind notification");

    let (msg, garbage) = with_ipc_buffer_mut(|ipc| {
        encode_msg(
            ipc,
            &TimeserverStartInfo {
                pit_ioport_cap: 0,
                pit_interrupt_cap: 1,
                notif_cap: 2,
                logserver_endpoint_cap: 3,

                endpoint_badge: 1,
                notif_badge: 2,

                tsc_frequency_mhz: tsc_freq_mhz(),
            },
            WrappedTransfer {
                unialloc: &alloc_state.ua,
                cspace: CNODE.cap(),
            },
            &caplist,
        )
    });
    timeserver.endpoint_sender.call(msg);
    with_ipc_buffer_mut(|ipc| {
        garbage.unwrap().release(ipc);
    });
    for cap in capdroplist {
        CNODE
            .cap()
            .absolute_cptr(cap)
            .delete()
            .expect("Failed to delete cap");
        assert!(alloc_state.borrow_mut().capalloc.free(cap.bits()));
    }
    sel4::debug_println!(
        "timeserver memory usage: {} bytes",
        timeserver.total_bytes()
    );
    timeserver
}

pub fn start_virtioserver(
    alloc_state: &AllocState,
    host_paging: &HostPagingContext,
    timeserver_endpoint: Endpoint,
    device: &VirtioPciDevice,
    irq_notif_cap: (Notification, usize),
) -> Result<ProcessInfo, &'static str> {
    let endpoint_badge = 1usize;
    assert!(endpoint_badge != irq_notif_cap.1);

    let logserver_endpoint =
        get_log_endpoint().expect("Logserver endpoint not set, cannot start virtioserver");
    let elf = unsafe {
        core::slice::from_raw_parts(
            &_binary_virtioserver_elf_start as *const u8,
            &_binary_virtioserver_elf_end as *const u8 as usize
                - &_binary_virtioserver_elf_start as *const u8 as usize,
        )
    };
    let priority = (seL4_MaxPrio - 1) as u8;
    let cnode_bits: u8 = 14;
    let mut server = start_process(
        alloc_state,
        host_paging,
        elf,
        SubprocessConfig {
            priority,
            badge: endpoint_badge,
            cnode_bits,
            expose_tcb: true,
        },
    );

    let untyped_2mb_caps = [(), ()].map(|_| {
        let cap = alloc_state.alloc_empty_cap();
        server.utlist.push_back(Arc::new(
            alloc_state
                .alloc_and_retype(&ObjectBlueprint::Arch(ObjectBlueprintX86::LargePage), cap),
        ));
        LargePage::from_cptr(cap)
    });

    let endpoint_caps = [()].map(|_| {
        let cap = alloc_state.alloc_empty_cap();
        server.utlist.push_back(Arc::new(
            alloc_state.alloc_and_retype(&ObjectBlueprint::Endpoint, cap),
        ));
        Endpoint::from_cptr(cap)
    });

    let userfault_tcb_cap = alloc_state.alloc_empty_cap();
    server.utlist.push_back(Arc::new(
        alloc_state.alloc_and_retype(&ObjectBlueprint::Tcb, userfault_tcb_cap),
    ));

    let notify_cfg = device.notify_cfg.ok_or_else(|| "notify_cfg not set")?;
    let start_info = VirtioServerStartInfo {
        logserver_endpoint_cap: 0,
        timeserver_endpoint_cap: 1,
        irq_notif_cap: 2,
        userfault_tcb_cap: 3,
        p_common_cfg_4kb_frame_cap: 4,
        p_notify_cfg_4kb_frame_cap: 5,
        p_isr_cfg_4kb_frame_cap: 6,
        p_device_cfg_4kb_frame_cap: 7,

        endpoint_caps: [8],
        untyped_2mb_caps: [9, 10],

        tsc_frequency_mhz: tsc_freq_mhz(),
        description: format!("{}/{}", device.virtio_device_id, device.gsi),
        irq_notif_cap_badge: irq_notif_cap.1 as u8,
        endpoint_badge: endpoint_badge as u8,
        priority,
        root_cnode_bits: cnode_bits,
        notify_off_multiplier: notify_cfg.notify_off_multiplier,
        virtio_device_id: device.virtio_device_id,
    };
    let (msg, garbage) = with_ipc_buffer_mut(|ipc| {
        Ok::<_, &'static str>(encode_msg(
            ipc,
            &start_info,
            WrappedTransfer {
                unialloc: &alloc_state.ua,
                cspace: CNODE.cap(),
            },
            &[
                logserver_endpoint.cptr(),
                timeserver_endpoint.cptr(),
                irq_notif_cap.0.cptr(),
                userfault_tcb_cap,
                device
                    .common_cfg
                    .ok_or_else(|| "common_cfg not set")?
                    .1
                    .cptr(),
                notify_cfg.cap.cptr(),
                device.isr_cfg.ok_or_else(|| "isr_cfg not set")?.1.cptr(),
                device
                    .device_cfg
                    .ok_or_else(|| "device_cfg not set")?
                    .1
                    .cptr(),
                endpoint_caps[0].cptr(),
                untyped_2mb_caps[0].cptr(),
                untyped_2mb_caps[1].cptr(),
            ],
        ))
    })?;
    server.endpoint_sender.call(msg);
    with_ipc_buffer_mut(|ipc| {
        garbage.unwrap().release(ipc);
    });
    for cap in untyped_2mb_caps
        .iter()
        .map(|x| x.cptr())
        .chain(endpoint_caps.iter().map(|x| x.cptr()))
        .chain(once(userfault_tcb_cap))
    {
        CNODE
            .cap()
            .absolute_cptr(cap)
            .delete()
            .expect("Failed to delete cap");
        assert!(alloc_state.borrow_mut().capalloc.free(cap.bits()));
    }

    sel4::debug_println!(
        "virtioserver[{}] memory usage: {} bytes",
        start_info.description,
        server.total_bytes()
    );
    Ok(server)
}

pub struct DbgServerConfig {
    pub hypervisor_channel: Endpoint,
    pub serial_ioport_cap: CPtr,
    pub timeserver_endpoint: Endpoint,
}

pub fn start_dbgserver(
    alloc_state: &AllocState,
    host_paging: &HostPagingContext,
    config: DbgServerConfig,
) -> ProcessInfo {
    let logserver_endpoint =
        get_log_endpoint().expect("Logserver endpoint not set, cannot start dbgserver");
    let elf = unsafe {
        core::slice::from_raw_parts(
            &_binary_dbgserver_elf_start as *const u8,
            &_binary_dbgserver_elf_end as *const u8 as usize
                - &_binary_dbgserver_elf_start as *const u8 as usize,
        )
    };
    let priority = (seL4_MaxPrio - 1) as u8;
    let cnode_bits: u8 = 8;
    let mut server = start_process(
        alloc_state,
        host_paging,
        elf,
        SubprocessConfig {
            priority,
            badge: 0,
            cnode_bits,
            expose_tcb: true,
        },
    );

    let i8042_ioport_cap = alloc_state.alloc_empty_cap();
    let i8042_interrupt_cap = alloc_state.alloc_empty_cap();
    let serial_interrupt_cap = alloc_state.alloc_empty_cap();
    let child_notif_cap = alloc_state.alloc_empty_cap();
    IO_PORT_CONTROL
        .cap()
        .ioport_control_issue(0x60, 0x64, &CNODE.cap().absolute_cptr(i8042_ioport_cap))
        .expect("Failed to issue i8042 IO port control");
    IRQ_CONTROL
        .cap()
        .irq_control_get_ioapic(
            0,
            1,
            1,
            0,
            allocate_intr_vector().into(),
            &CNODE.cap().absolute_cptr(i8042_interrupt_cap),
        )
        .expect("Failed to get i8042 IRQHandler");
    IRQ_CONTROL
        .cap()
        .irq_control_get_ioapic(
            0,
            4,
            1,
            0,
            allocate_intr_vector().into(),
            &CNODE.cap().absolute_cptr(serial_interrupt_cap),
        )
        .expect("Failed to get serial IRQHandler");
    server.utlist.push_back(Arc::new(
        alloc_state.alloc_and_retype(&ObjectBlueprint::Notification, child_notif_cap),
    ));

    let (msg, garbage) = with_ipc_buffer_mut(|ipc| {
        encode_msg(
            ipc,
            &DbgserverStartInfo {
                logserver_endpoint_cap: 0,
                timeserver_endpoint_cap: 1,
                i8042_ioport_cap: 2,
                i8042_interrupt_cap: 3,
                serial_ioport_cap: 4,
                serial_interrupt_cap: 5,
                notif_rx_cap: 6,
                hypervisor_channel_cap: 7,

                priority,
                root_cnode_bits: cnode_bits,
                tsc_freq_mhz: tsc_freq_mhz(),
            },
            WrappedTransfer {
                unialloc: &alloc_state.ua,
                cspace: CNODE.cap(),
            },
            &[
                logserver_endpoint.cptr(),
                config.timeserver_endpoint.cptr(),
                i8042_ioport_cap,
                i8042_interrupt_cap,
                config.serial_ioport_cap,
                serial_interrupt_cap,
                child_notif_cap,
                config.hypervisor_channel.cptr(),
            ],
        )
    });
    server.endpoint_sender.call(msg);
    with_ipc_buffer_mut(|ipc| {
        garbage.unwrap().release(ipc);
    });
    for cap in [
        i8042_ioport_cap,
        i8042_interrupt_cap,
        serial_interrupt_cap,
        child_notif_cap,
    ] {
        CNODE
            .cap()
            .absolute_cptr(cap)
            .delete()
            .expect("Failed to delete cap");
        assert!(alloc_state.borrow_mut().capalloc.free(cap.bits()));
    }
    server
}

pub struct KernelFrameBucket {
    #[allow(dead_code)]
    pub utlist: LinkedList<UntypedInfoAdapter<UntypedCap>>,
    pub cnode: CNode,
    pub num_frames: u32,
}

impl KernelFrameBucket {
    pub fn new(alloc_state: &AllocState, bootinfo: &sel4::BootInfoPtr) -> Self {
        let nanos_elf = unsafe {
            core::slice::from_raw_parts(
                &_binary_nanos_elf_start as *const u8,
                &_binary_nanos_elf_end as *const u8 as usize
                    - &_binary_nanos_elf_start as *const u8 as usize,
            )
        };
        let mut utlist = LinkedList::new(UntypedInfoAdapter::NEW);
        let (cnode, num_frames) =
            collect_self_frame_caps(bootinfo, alloc_state, &mut utlist, nanos_elf);
        Self {
            utlist,
            cnode,
            num_frames,
        }
    }
}

pub struct VmmServer {
    pub proc: ProcessInfo,
    pub untyped_owners: BTreeMap<u64, Weak<UntypedInfo<UntypedCap>>>,
    pub config: VmmServerConfig,
}

pub const MAX_VIRTIO_DEVICES: usize = 32;

#[derive(Clone, Debug)]
pub struct VmmServerConfig {
    pub requested_memory_bytes: u64,
    pub rtc_ioport_cap: Option<CPtr>,
    pub viosrv_senders: Box<heapless::Vec<Endpoint, MAX_VIRTIO_DEVICES>>,
    pub hypervisor_channel: Endpoint,
    pub paging_mode: VmPagingMode,
    pub affinity: u32,
}

pub fn start_vmmserver(
    alloc_state: &AllocState,
    host_paging: &HostPagingContext,
    timeserver_endpoint: Endpoint,
    kernel_frames: &KernelFrameBucket,
    config: VmmServerConfig,
) -> VmmServer {
    let logserver_endpoint =
        get_log_endpoint().expect("Logserver endpoint not set, cannot start vmmserver");
    let priority = (seL4_MinPrio + 2) as u8;

    let requested_large_pages = config
        .requested_memory_bytes
        .div_ceil(1 << FrameObjectType::LARGE_PAGE_BITS);

    // Child will need to copy in untyped caps
    let cnode_bits: u8 = (512 + requested_large_pages)
        .next_power_of_two()
        .trailing_zeros() as u8;
    println!("vmmserver cnode bits: {}", cnode_bits);
    let requested_large_pages = requested_large_pages.saturating_sub(
        ((1u64 << cnode_bits) * 32).div_ceil(FrameObjectType::LargePage.bytes() as u64),
    );
    let start_time = now_cycles();
    let server = start_process(
        alloc_state,
        host_paging,
        unsafe {
            core::slice::from_raw_parts(
                &_binary_vmmserver_elf_start as *const u8,
                &_binary_vmmserver_elf_end as *const u8 as usize
                    - &_binary_vmmserver_elf_start as *const u8 as usize,
            )
        },
        SubprocessConfig {
            priority,
            badge: 0,
            cnode_bits,
            expose_tcb: true,
        },
    );
    let process_image_bytes = server.total_bytes();
    let mut server = VmmServer {
        proc: server,
        untyped_owners: BTreeMap::new(),
        config,
    };

    let untyped_bucket_cap = CNode::from_cptr(alloc_state.alloc_empty_cap());
    let untyped_bucket_ut;
    {
        let cnode_size_bits = requested_large_pages.next_power_of_two().trailing_zeros();
        untyped_bucket_ut = alloc_state.alloc_and_retype(
            &ObjectBlueprint::CNode {
                size_bits: cnode_size_bits as _,
            },
            untyped_bucket_cap.cptr(),
        );
        for i in 0..requested_large_pages {
            // We use `retype` instead of `cnode_copy` here because we want to
            // maintain unique `revoke()` control on the parent ut
            let owner = Arc::new(alloc_state.alloc_and_retype_in(
                &ObjectBlueprint::Untyped {
                    size_bits: FrameObjectType::LARGE_PAGE_BITS,
                },
                untyped_bucket_cap,
                i as usize,
            ));
            server
                .untyped_owners
                .insert(owner.paddr, Arc::downgrade(&owner));
            server.proc.utlist.push_back(owner);
        }
    }

    let start_info = VmmServerStartInfo {
        logserver_endpoint_cap: 0,
        timeserver_endpoint_cap: 1,
        kernel_bucket_cap: 2,
        num_kernel_pages: kernel_frames.num_frames,
        untyped_bucket_cap: 3,
        num_untyped: requested_large_pages as u32,
        asid_pool_cap: 4,
        rtc_ioport_cap: 5,
        has_rtc_ioport_cap: server.config.rtc_ioport_cap.is_some(),
        hypervisor_channel_cap: 6,
        virtio_device_endpoint_cap_start: 7,
        num_virtio_devices: server.config.viosrv_senders.len() as u8,
        tsc_frequency_mhz: tsc_freq_mhz(),
        description: "test".to_string(),
        cnode_bits,
        paging_mode: server.config.paging_mode,
        priority,
        affinity: server.config.affinity,
    };
    let caplist: Vec<CPtr> = [
        logserver_endpoint.cptr(),
        timeserver_endpoint.cptr(),
        kernel_frames.cnode.cptr(),
        untyped_bucket_cap.cptr(),
        ASID_POOL.cap().cptr(),
        server.config.rtc_ioport_cap.unwrap_or(CPtr::from_bits(0)),
        server.config.hypervisor_channel.cptr(),
    ]
    .into_iter()
    .chain(server.config.viosrv_senders.iter().map(|x| x.cptr()))
    .collect::<Vec<_>>();
    let (msg, garbage) = with_ipc_buffer_mut(|ipc| {
        encode_msg(
            ipc,
            &start_info,
            WrappedTransfer {
                unialloc: &alloc_state.ua,
                cspace: CNODE.cap(),
            },
            &caplist,
        )
    });
    server.proc.endpoint_sender.call(msg);
    with_ipc_buffer_mut(|ipc| {
        garbage.unwrap().release(ipc);
        assert_eq!(
            ipc.inner_mut().seL4_CNode_Revoke(
                CNODE.cptr_bits(),
                untyped_bucket_ut.cap.0.bits(),
                64
            ),
            0
        );
        alloc_state.ua.borrow_mut().free_normal(&untyped_bucket_ut);
        assert!(alloc_state
            .ua
            .borrow_mut()
            .capalloc
            .free(untyped_bucket_cap.bits()));
    });
    let end_time = now_cycles();
    let duration = Duration::from_micros((end_time - start_time) / tsc_freq_mhz() as u64);
    println!(
        "vmmserver: kernel_pages: {}, large_pages: {}, process_image_bytes: {}, duration: {:?}",
        kernel_frames.num_frames,
        server.untyped_owners.len(),
        process_image_bytes,
        duration,
    );
    server
}

fn collect_self_frame_caps(
    bootinfo: &sel4::BootInfoPtr,
    alloc_state: &AllocState,
    utlist: &mut LinkedList<UntypedInfoAdapter<UntypedCap>>,
    slice: &[u8],
) -> (CNode, u32) {
    assert!(slice.as_ptr().addr() % FrameObjectType::GRANULE.bytes() == 0);

    let frames = bootinfo.user_image_frames();
    let cap_start = frames.start()
        + (slice.as_ptr() as usize - SELF_START_ADDR as usize) / FrameObjectType::GRANULE.bytes();
    assert!(cap_start < frames.end());
    let cap_end = frames.start()
        + (slice.as_ptr() as usize + slice.len() - SELF_START_ADDR as usize)
            .div_ceil(FrameObjectType::GRANULE.bytes());
    assert!(cap_end <= frames.end());

    let num_caps = (cap_end - cap_start) as u32;
    let cnode_size_bits = num_caps.next_power_of_two().trailing_zeros();
    let cnode = CNode::from_cptr(alloc_state.alloc_empty_cap());
    utlist.push_back(Arc::new(alloc_state.alloc_and_retype(
        &ObjectBlueprint::CNode {
            size_bits: cnode_size_bits as _,
        },
        cnode.cptr(),
    )));

    for (i, frame) in (cap_start..cap_end)
        .map(|x| sel4::cap::_4k::from_bits(x as u64))
        .enumerate()
    {
        cnode
            .absolute_cptr(CPtrWithDepth::from_bits_with_depth(
                i as u64,
                cnode_size_bits as _,
            ))
            .copy(&CNODE.cap().absolute_cptr(frame), CapRights::read_only())
            .expect("Failed to copy frame cap");
    }
    (cnode, num_caps)
}
