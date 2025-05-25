#![no_std]
#![no_main]
#![allow(incomplete_features, static_mut_refs)]
#![feature(
    generic_const_exprs,
    linked_list_retain,
    btree_extract_if,
    pointer_is_aligned_to,
    iter_array_chunks,
    maybe_uninit_as_bytes,
    new_zeroed_alloc,
    maybe_uninit_write_slice
)]

// https://github.com/rust-lang/rust/issues/133199
// > In my case, which was a parent crate crashing because of its dependency
// > to a child crate who used const generics, adding #![feature(generic_const_exprs)]
// > to the parent crate as well fixed the issue.

extern crate alloc;

#[macro_use]
extern crate ipc;

mod acpi_loader;
mod alloc_control;
mod elfloader;
mod ipcbench;
mod pci;
mod static_config;
mod sysproc;
mod tsc;
mod util;
mod virtio_pci;

use core::mem::MaybeUninit;

use algorithms::unialloc::UniAllocTrait;
use alloc::{boxed::Box, vec::Vec};
use alloc_control::AllocState;
use ipc::{
    host_paging::HostPagingContext,
    msgbuf::decode_msg,
    vmmsvc::{VmPagingMode, VmmToInitMsg},
};
use sel4::{
    cap::{Endpoint, Notification},
    init_thread::slot::{CNODE, IO_PORT_CONTROL, TCB, VSPACE},
    sys::priorityConstants::seL4_MaxPrio,
    with_ipc_buffer_mut, CapRights, MessageInfo, ObjectBlueprint,
};
use sel4_root_task::root_task;
use static_config::{HOST_DYNAMIC_SMALL_MAPPING_BASE, HOST_DYNAMIC_SMALL_MAPPING_END};
use sysproc::{DbgServerConfig, KernelFrameBucket, VmmServer, VmmServerConfig, MAX_VIRTIO_DEVICES};
use util::irq_aggregator::start_irq_aggregator;

const MAX_NUM_VMS: usize = 16;

static mut ALLOC_STATE: MaybeUninit<AllocState> = MaybeUninit::uninit();
static mut HOST_PAGING: MaybeUninit<HostPagingContext> = MaybeUninit::uninit();
static mut VM_ARRAY: MaybeUninit<[Option<VmmServer>; MAX_NUM_VMS]> = MaybeUninit::uninit();

const HV_PRIV_BADGE_REBOOT: u64 = 1 << 0;
const HV_PRIV_BADGE_IPCBENCH: u64 = 1 << 1;

#[root_task]
fn main(bootinfo: &sel4::BootInfoPtr) -> ! {
    let alloc_state = &*unsafe { ALLOC_STATE.write(alloc_control::alloc_init(bootinfo)) };
    let host_paging = &*unsafe {
        HOST_PAGING.write(HostPagingContext::new(
            &alloc_state.ua,
            CNODE.cap(),
            VSPACE.cap(),
            HOST_DYNAMIC_SMALL_MAPPING_BASE,
            HOST_DYNAMIC_SMALL_MAPPING_END,
        ))
    };

    tsc::init(bootinfo);

    let serial_ioport_cap = alloc_state.alloc_empty_cap();
    IO_PORT_CONTROL
        .cap()
        .ioport_control_issue(0x3f8, 0x3ff, &CNODE.cap().absolute_cptr(serial_ioport_cap))
        .expect("Failed to issue serial IO port control");

    sysproc::start_logserver(alloc_state, host_paging, serial_ioport_cap);
    sel4_root_task::panicking::set_hook(&|info| {
        println!("init panic:\n{:#}", info);
    });

    println!(
        "Free capability range: [{:#x}..{:#x})",
        alloc_state.ua.borrow().capalloc.offset,
        alloc_state.ua.borrow().capalloc.limit,
    );
    println!(
        "TSC Frequency: {} MHz, time since boot: {:?}",
        tsc::tsc_freq_mhz(),
        tsc::time_since_boot()
    );

    TCB.cap()
        .tcb_set_sched_params(TCB.cap(), seL4_MaxPrio as u64, seL4_MaxPrio as u64 - 1)
        .expect("Failed to set TCB priority");

    let acpi_info = &*Box::leak(Box::new(acpi_loader::init(
        bootinfo,
        alloc_state,
        host_paging,
    )));
    println!("ACPI initialized: {:?}", acpi_info);

    let timesrv = sysproc::start_timeserver(alloc_state, host_paging, acpi_info);

    let pci_devices = pci::pci_scan(alloc_state);
    let virtio_devices = virtio_pci::probe_all(alloc_state, host_paging, &pci_devices, acpi_info);
    // for x in &virtio_devices {
    //     println!("Virtio device: {:#x?}", x);
    // }

    let num_virtio_devices = virtio_devices.iter().count();
    let mut viosrv_senders = Box::new(heapless::Vec::<_, MAX_VIRTIO_DEVICES>::new());
    {
        let mut gsi_list = Vec::with_capacity(num_virtio_devices);
        for x in &virtio_devices {
            if !gsi_list.iter().any(|y| *y == x.gsi) {
                gsi_list.push(x.gsi);
            }
        }

        let mut notif_sender_vec = Vec::with_capacity(num_virtio_devices);
        for dev in &virtio_devices {
            let viosrv_notif_cap = Notification::from_cptr(alloc_state.alloc_empty_cap());
            alloc_state.alloc_and_retype(&ObjectBlueprint::Notification, viosrv_notif_cap.cptr());
            let viosrv_notif_sender_cap = Notification::from_cptr(alloc_state.alloc_empty_cap());
            let viosrv_notif_badge = 2usize;
            CNODE
                .cap()
                .absolute_cptr(viosrv_notif_sender_cap)
                .mint(
                    &CNODE.cap().absolute_cptr(viosrv_notif_cap),
                    CapRights::write_only(),
                    viosrv_notif_badge as _,
                )
                .expect("Failed to mint notification");
            notif_sender_vec.push(viosrv_notif_sender_cap);

            let viosrv = sysproc::start_virtioserver(
                alloc_state,
                host_paging,
                timesrv.endpoint_sender,
                dev,
                (viosrv_notif_cap, viosrv_notif_badge),
            )
            .expect("failed to start viosrv");
            viosrv_senders
                .push(viosrv.endpoint_sender)
                .expect("viosrv_senders overflow");
        }

        let notif_sender_vec = &*Box::leak(notif_sender_vec.into_boxed_slice());
        start_irq_aggregator(alloc_state, host_paging, &gsi_list, notif_sender_vec);
    }

    let rtc_ioport = alloc_state.alloc_empty_cap();
    IO_PORT_CONTROL
        .cap()
        .ioport_control_issue(0x70, 0x71, &CNODE.cap().absolute_cptr(rtc_ioport))
        .expect("Failed to issue RTC IO port control");

    let kernel_frames = KernelFrameBucket::new(alloc_state, bootinfo);
    let hypervisor_channel_endpoint = Endpoint::from_cptr(alloc_state.alloc_empty_cap());
    alloc_state.alloc_and_retype(
        &ObjectBlueprint::Endpoint,
        hypervisor_channel_endpoint.cptr(),
    );

    let hypervisor_channel_sender = Endpoint::from_cptr(alloc_state.alloc_empty_cap());
    CNODE
        .cap()
        .absolute_cptr(hypervisor_channel_sender)
        .mint(
            &CNODE.cap().absolute_cptr(hypervisor_channel_endpoint),
            CapRights::new(true, false, false, true),
            HV_PRIV_BADGE_REBOOT | HV_PRIV_BADGE_IPCBENCH,
        )
        .expect("Failed to mint hypervisor channel sender");

    let _dbgsrv = sysproc::start_dbgserver(
        alloc_state,
        host_paging,
        DbgServerConfig {
            serial_ioport_cap,
            timeserver_endpoint: timesrv.endpoint_sender,
            hypervisor_channel: hypervisor_channel_sender,
        },
    );

    let vm_array = unsafe { VM_ARRAY.write([const { None }; MAX_NUM_VMS]) };

    let start_vmm = |config: VmmServerConfig| {
        sysproc::start_vmmserver(
            alloc_state,
            host_paging,
            timesrv.endpoint_sender,
            &kernel_frames,
            config,
        )
    };

    let calculate_max_vm_mem = || {
        alloc_state
            .ua
            .borrow_mut()
            .total_remaining_normal(21)
            .saturating_sub(8 * 1024 * 1024)
    };
    vm_array[0] = Some(start_vmm(VmmServerConfig {
        requested_memory_bytes: calculate_max_vm_mem(),
        rtc_ioport_cap: Some(rtc_ioport),
        viosrv_senders,
        hypervisor_channel: hypervisor_channel_sender,
        paging_mode: VmPagingMode::Pv,
        affinity: 0,
    }));

    let mut reply: Option<MessageInfo> = None;
    let mut first = true;
    loop {
        let (msg, badge) = if first {
            first = false;
            hypervisor_channel_endpoint.recv(())
        } else {
            let reply = reply.take().unwrap_or_else(|| MessageInfo::new(0, 0, 0, 0));
            hypervisor_channel_endpoint.reply_recv(reply, ())
        };

        let Some(req) = with_ipc_buffer_mut(|ipc| {
            decode_msg::<VmmToInitMsg>(ipc, msg)
                .ok()
                .and_then(|x| rkyv::deserialize::<_, rkyv::rancor::Error>(x.0).ok())
        }) else {
            continue;
        };

        let sender_index = (badge >> 32) as u32;
        let badge = badge & 0xFFFFFFFF;
        match req {
            VmmToInitMsg::Reboot { index }
                if (badge & HV_PRIV_BADGE_REBOOT != 0 && (index as usize) < MAX_NUM_VMS)
                    || index == u32::MAX =>
            {
                let index = if index == u32::MAX {
                    sender_index
                } else {
                    index
                };
                let vmmsrv = vm_array[index as usize].take();
                if let Some(vmmsrv) = vmmsrv {
                    let mut config = vmmsrv.config;
                    vmmsrv.proc.destroy(alloc_state);

                    // Special case for vm 0: always give it all available memory
                    if index == 0 {
                        config.requested_memory_bytes = calculate_max_vm_mem();
                    }

                    vm_array[index as usize] = Some(start_vmm(config));
                    reply = Some(MessageInfo::new(1, 0, 0, 0));
                }
            }
            VmmToInitMsg::Kill { index }
                if (badge & HV_PRIV_BADGE_REBOOT != 0 && (index as usize) < MAX_NUM_VMS)
                    || index == u32::MAX =>
            {
                let index = if index == u32::MAX {
                    sender_index
                } else {
                    index
                };
                let vmmsrv = vm_array[index as usize].take();
                if let Some(vmmsrv) = vmmsrv {
                    vmmsrv.proc.destroy(alloc_state);
                    reply = Some(MessageInfo::new(1, 0, 0, 0));
                }
            }
            VmmToInitMsg::IpcBench if badge & HV_PRIV_BADGE_IPCBENCH != 0 => {
                let latency = ipcbench::benchmark_ipc(alloc_state, host_paging);
                with_ipc_buffer_mut(|ipc| {
                    ipc.msg_regs_mut()[0] = latency;
                });
                reply = Some(MessageInfo::new(1, 0, 0, 1));
            }
            VmmToInitMsg::SetMode { index, mode }
                if (badge & HV_PRIV_BADGE_REBOOT != 0 && (index as usize) < MAX_NUM_VMS)
                    || index == u32::MAX =>
            {
                let index = if index == u32::MAX {
                    sender_index
                } else {
                    index
                };
                if let Some(vmmsrv) = &mut vm_array[index as usize] {
                    vmmsrv.config.paging_mode = mode;
                    reply = Some(MessageInfo::new(1, 0, 0, 0));
                }
            }
            VmmToInitMsg::SetAffinity { index, affinity }
                if (badge & HV_PRIV_BADGE_REBOOT != 0 && (index as usize) < MAX_NUM_VMS)
                    || index == u32::MAX =>
            {
                let index = if index == u32::MAX {
                    sender_index
                } else {
                    index
                };
                if let Some(vmmsrv) = &mut vm_array[index as usize] {
                    vmmsrv.config.affinity = affinity;
                    reply = Some(MessageInfo::new(1, 0, 0, 0));
                }
            }
            VmmToInitMsg::GpaLargeUnmap { paddr } => {
                let index = sender_index;
                let Some(vmmsrv) = vm_array[index as usize].as_mut() else {
                    continue;
                };
                let Some(x) = vmmsrv.untyped_owners.remove(&paddr) else {
                    continue;
                };
                let x = x.upgrade().expect("Failed to upgrade weak reference");
                assert!(x.link.is_linked());
                let mut cursor = unsafe { vmmsrv.proc.utlist.cursor_mut_from_ptr(&*x) };
                let ut = cursor.remove().expect("Failed to remove untyped");
                CNODE
                    .cap()
                    .absolute_cptr(ut.cap.0)
                    .revoke()
                    .expect("Failed to revoke untyped");
                alloc_state.borrow_mut().free_normal(&ut);
                vmmsrv.config.requested_memory_bytes = vmmsrv
                    .config
                    .requested_memory_bytes
                    .checked_sub(1 << ut.size_bits)
                    .expect("Failed to update requested memory bytes");
                // println!("Unmap GPA {:#x} from VM {}", paddr, index);
                reply = Some(MessageInfo::new(1, 0, 0, 0));
            }
            _ => {}
        }
    }
}
