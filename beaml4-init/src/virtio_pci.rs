use core::{
    mem::MaybeUninit,
    ptr::{addr_of_mut, read_volatile, write_volatile, NonNull},
};

use alloc::sync::Arc;
use intrusive_collections::{intrusive_adapter, LinkedList, LinkedListAtomicLink};
use sel4::{
    init_thread::slot::{CNODE, VSPACE},
    with_ipc_buffer_mut, CapRights, ObjectBlueprint, ObjectBlueprintX86, VmAttributes,
};

use crate::{
    acpi_loader::AcpiInfo,
    alloc_control::AllocState,
    pci::{Pci, PciDevice},
};
use ipc::host_paging::{HostPagingContext, SMALL_PAGE_SIZE_BITS};

const DEBUG: bool = false;

#[derive(Debug)]
#[repr(C)]
struct VirtioPciCap {
    cap_vndr: u8,
    cap_next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar: u8,
    id: u8,
    padding: [u8; 2],
    offset: u32,
    length: u32,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct VirtioPciDevice {
    pub link: LinkedListAtomicLink,
    pub inner: Arc<PciDevice>,
    pub virtio_device_id: u16,
    pub common_cfg: Option<(NonNull<VirtioPciCommonCfg>, sel4::cap::_4k)>,
    pub notify_cfg: Option<VirtioNotifyCfgRef>,
    pub isr_cfg: Option<(NonNull<u8>, sel4::cap::_4k)>,
    pub device_cfg: Option<(NonNull<u8>, sel4::cap::_4k)>,
    pub queue_size_max: u16,
    pub gsi: u32,
}

unsafe impl Send for VirtioPciDevice {}
unsafe impl Sync for VirtioPciDevice {}

#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
pub struct VirtioNotifyCfgRef {
    pub inner: NonNull<()>,
    pub notify_off_multiplier: u32,
    pub cap: sel4::cap::_4k,
}

#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
pub enum VirtioPciCfg {
    Mem {
        base: u64,
        prefetchable: bool,
        length: u32,
    },
    Io {
        base: u32,
        length: u32,
    },
}

#[derive(Debug)]
#[repr(C)]
#[allow(dead_code)]
pub struct VirtioPciCommonCfg {
    pub device_feature_select: u32,
    pub device_feature: u32,
    pub driver_feature_select: u32,
    pub driver_feature: u32,
    pub config_msix_vector: u16,
    pub num_queues: u16,
    pub device_status: u8,
    pub config_generation: u8,

    pub queue_select: u16,
    pub queue_size: u16,
    pub queue_msix_vector: u16,
    pub queue_enable: u16,
    pub queue_notify_off: u16,
    pub queue_desc: u64,
    pub queue_driver: u64,
    pub queue_device: u64,
    pub queue_notify_data: u16,
    pub queue_reset: u16,
}

intrusive_adapter!(pub VirtioPciDeviceAdapter = Arc<VirtioPciDevice>: VirtioPciDevice { link: LinkedListAtomicLink });

pub fn probe_all(
    alloc_state: &AllocState,
    host_paging: &HostPagingContext,
    pci: &Pci,
    acpi_info: &AcpiInfo,
) -> LinkedList<VirtioPciDeviceAdapter> {
    let mut cursor = pci.devices.cursor();
    let mut output = LinkedList::new(VirtioPciDeviceAdapter::new());
    loop {
        cursor.move_next();
        let Some(device) = cursor.get() else {
            break;
        };

        if device.vendor_id != 0x1af4 || !(0x1000..=0x107f).contains(&device.device_id) {
            continue;
        }

        let status = pci.config_read_word(device, 0x6);
        if status & (1 << 4) == 0 {
            // no capability list
            continue;
        }

        let virtio_device_id = if device.device_id >= 0x1040 {
            device.device_id - 0x1040
        } else {
            match device.device_id {
                0x1000 => 1,
                0x1001 => 2,
                0x1004 => 8, // scsi host
                _ => 0,
            }
        };
        if DEBUG {
            println!(
                "Found virtio device: bus {:#x}, slot {:#x}, vendor {:#x}, device {:#x}, virtio device id {:#x}",
                device.bus,
                device.slot,
                device.vendor_id,
                device.device_id,
                virtio_device_id
            );
        }
        if virtio_device_id == 0 {
            continue;
        }
        let mut cap_ptr = pci.config_read_word(device, 0x34) as u8;

        let gsi = acpi_info
            .ioapic_irq_to_gsi
            .get(&device.interrupt_line)
            .copied()
            .unwrap_or(device.interrupt_line as u32);
        let mut newdev = VirtioPciDevice {
            link: LinkedListAtomicLink::new(),
            inner: cursor.clone_pointer().unwrap(),
            virtio_device_id,
            common_cfg: None,
            notify_cfg: None,
            isr_cfg: None,
            device_cfg: None,
            queue_size_max: 0,
            gsi,
        };

        while cap_ptr != 0 {
            let mut cap = MaybeUninit::<VirtioPciCap>::zeroed();
            let bytes = cap.as_bytes_mut();
            for (i, [a, b, c, d]) in bytes.iter_mut().array_chunks().enumerate() {
                let w = pci.config_read_dword(device, cap_ptr);
                a.write(w as u8);
                b.write((w >> 8) as u8);
                c.write((w >> 16) as u8);
                d.write((w >> 24) as u8);
                cap_ptr += 4;

                if i == 0
                    && (w as u8 != 9
                        || ((w >> 16) as u8 as usize) < core::mem::size_of::<VirtioPciCap>())
                {
                    break;
                }
            }
            let cap = unsafe { cap.assume_init() };
            let old_cap_ptr = cap_ptr;
            cap_ptr = cap.cap_next;
            // println!("Virtio cap: {:?}", cap);

            if cap.bar > 5 {
                continue;
            }

            let bar = pci.config_read_dword(device, 0x10 + cap.bar * 4);
            let bar = if bar & 1 == 0 {
                let ty = (bar >> 1) & 0b11;
                let prefetchable = (bar >> 3) & 1;
                match ty {
                    0 => VirtioPciCfg::Mem {
                        base: (bar & 0xffff_fff0) as u64 + cap.offset as u64,
                        prefetchable: prefetchable != 0,
                        length: cap.length,
                    },
                    2 => {
                        let high_half = pci.config_read_dword(device, 0x14 + cap.bar * 4);
                        VirtioPciCfg::Mem {
                            base: ((bar & 0xffff_fff0) as u64 | ((high_half as u64) << 32))
                                + cap.offset as u64,
                            prefetchable: prefetchable != 0,
                            length: cap.length,
                        }
                    }
                    _ => {
                        println!("Unknown BAR type {:#x}", ty);
                        continue;
                    }
                }
            } else {
                VirtioPciCfg::Io {
                    base: (bar & 0xffff_fffc) + cap.offset as u32,
                    length: cap.length,
                }
            };

            let VirtioPciCfg::Mem {
                base,
                prefetchable: _,
                length,
            } = bar
            else {
                // println!("IO BAR is not supported: {:#x?}", bar);
                continue;
            };

            if length as usize != 1usize << SMALL_PAGE_SIZE_BITS {
                // println!("BAR length is not supported: {:#x?}", bar);
                continue;
            }

            let map_it = || {
                let page = with_ipc_buffer_mut(|ipc| host_paging.alloc_unmapped_page(ipc));
                let Some(mem_region) = alloc_state.alloc_device(base, SMALL_PAGE_SIZE_BITS) else {
                    println!("Failed to allocate virtio device MMIO page");
                    return None;
                };
                let frame = alloc_state.alloc_empty_cap();
                mem_region
                    .cap
                    .0
                    .untyped_retype(
                        &ObjectBlueprint::Arch(ObjectBlueprintX86::_4k),
                        &CNODE.cap().absolute_cptr(CNODE.cptr()),
                        frame.bits() as usize,
                        1,
                    )
                    .expect("Failed to retype untyped to page");
                sel4::cap::_4k::from_cptr(frame)
                    .frame_map(
                        VSPACE.cap(),
                        page.addr().get(),
                        CapRights::read_write(),
                        VmAttributes::CACHE_DISABLED,
                    )
                    .expect("Failed to map virtio device MMIO page to vspace");
                if DEBUG {
                    println!(
                        "Virtio device MMIO mapped: type {}, {:#x} -> {:#x}",
                        cap.cfg_type,
                        base,
                        page.addr().get()
                    );
                }
                Some((page, sel4::cap::_4k::from_cptr(frame)))
            };

            match cap.cfg_type {
                1 => {
                    // VIRTIO_PCI_CAP_COMMON_CFG
                    newdev.common_cfg = map_it().map(|x| (x.0.cast(), x.1));
                }
                2 => {
                    // VIRTIO_PCI_CAP_NOTIFY_CFG
                    newdev.notify_cfg = map_it().map(|x| VirtioNotifyCfgRef {
                        inner: x.0.cast(),
                        notify_off_multiplier: pci.config_read_dword(device, old_cap_ptr),
                        cap: x.1,
                    });
                }
                3 => {
                    // VIRTIO_PCI_CAP_ISR_CFG
                    newdev.isr_cfg = map_it().map(|x| (x.0.cast(), x.1));
                }
                4 => {
                    // VIRTIO_PCI_CAP_DEVICE_CFG
                    newdev.device_cfg = map_it().map(|x| (x.0.cast(), x.1));
                }
                _ => {}
            }
        }

        if newdev.common_cfg.is_none() {
            println!("ignoring virtio device without common cfg: {:x?}", newdev);
            continue;
        }
        if newdev.notify_cfg.is_none() {
            println!("ignoring virtio device without notify cfg: {:x?}", newdev);
            continue;
        }
        if newdev.isr_cfg.is_none() {
            println!("ignoring virtio device without isr cfg: {:x?}", newdev);
            continue;
        }

        // read max queue size
        unsafe {
            let common_cfg = newdev.common_cfg.unwrap().0.as_ptr();
            write_volatile(addr_of_mut!((*common_cfg).queue_select), 0);
            newdev.queue_size_max = read_volatile(addr_of_mut!((*common_cfg).queue_size));
        }

        if newdev.queue_size_max > 256 {
            println!("clamping virtio device queue size to 256: {:x?}", newdev);
            newdev.queue_size_max = 256;
        }

        output.push_back(Arc::new(newdev));
    }
    output
}
