use alloc::sync::Arc;
use intrusive_collections::{intrusive_adapter, LinkedList, LinkedListAtomicLink};
use sel4::{
    init_thread::slot::{CNODE, IO_PORT_CONTROL},
    with_ipc_buffer_mut, CPtr,
};

use crate::alloc_control::AllocState;
use ipc::x86_ioport::{inl, outl};

#[derive(Debug)]
pub struct PciDevice {
    pub link: LinkedListAtomicLink,
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub device_id: u16,
    pub vendor_id: u16,
    pub interrupt_line: u8,
    pub _interrupt_pin: u8,
}

intrusive_adapter!(pub PciDeviceAdapter = Arc<PciDevice>: PciDevice { link: LinkedListAtomicLink });

pub struct Pci {
    pub ioport: CPtr,
    pub devices: LinkedList<PciDeviceAdapter>,
}

pub fn pci_scan(alloc: &AllocState) -> Pci {
    let ioport = alloc.alloc_empty_cap();

    IO_PORT_CONTROL
        .cap()
        .ioport_control_issue(0xcf8, 0xcff, &CNODE.cap().absolute_cptr(ioport))
        .expect("Failed to issue PCI IO port control");

    let mut output = LinkedList::new(PciDeviceAdapter::NEW);
    for bus in 0..=255u8 {
        for slot in 0..=31u8 {
            if let Some(device) = check_device(ioport, bus, slot) {
                println!(
                    "Found PCI device: bus {:#x}, slot {:#x}, vendor {:#x}, device {:#x}",
                    bus, slot, device.vendor_id, device.device_id
                );
                output.push_back(Arc::new(device));
            }
        }
    }

    Pci {
        ioport,
        devices: output,
    }
}

#[allow(dead_code)]
impl Pci {
    pub fn config_read_dword(&self, device: &PciDevice, offset: u8) -> u32 {
        pci_config_read_dword(self.ioport, device.bus, device.slot, device.func, offset)
    }

    pub fn config_read_word(&self, device: &PciDevice, offset: u8) -> u16 {
        pci_config_read_word(self.ioport, device.bus, device.slot, device.func, offset)
    }

    pub fn config_write_dword(&self, device: &PciDevice, offset: u8, value: u32) {
        pci_config_write_dword(
            self.ioport,
            device.bus,
            device.slot,
            device.func,
            offset,
            value,
        );
    }
}

pub fn pci_config_read_dword(cap: CPtr, bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let address = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | (offset as u32 & 0xfc)
        | 0x80000000;

    with_ipc_buffer_mut(|ipc| {
        outl(ipc, cap, 0xcf8, address);
        inl(ipc, cap, 0xcfc)
    })
}

pub fn pci_config_read_word(cap: CPtr, bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
    let dword = pci_config_read_dword(cap, bus, slot, func, offset);
    (dword >> ((offset & 2) * 8)) as u16
}

pub fn pci_config_write_dword(cap: CPtr, bus: u8, slot: u8, func: u8, offset: u8, value: u32) {
    let address = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | (offset as u32 & 0xfc)
        | 0x80000000;

    with_ipc_buffer_mut(|ipc| {
        outl(ipc, cap, 0xcf8, address);
        outl(ipc, cap, 0xcfc, value);
    });
}

fn check_device(cap: CPtr, bus: u8, slot: u8) -> Option<PciDevice> {
    let dword = pci_config_read_dword(cap, bus, slot, 0, 0);
    let vendor_id = (dword & 0xffff) as u16;
    let device_id = ((dword >> 16) & 0xffff) as u16;
    if vendor_id == 0xffff {
        return None; // Device doesn't exist
    }
    let interrupt_line_and_pin = pci_config_read_word(cap, bus, slot, 0, 0x3c);
    let interrupt_line = (interrupt_line_and_pin & 0xff) as u8;
    let interrupt_pin = ((interrupt_line_and_pin >> 8) & 0xff) as u8;
    Some(PciDevice {
        link: LinkedListAtomicLink::new(),
        bus,
        slot,
        func: 0,
        device_id,
        vendor_id,
        interrupt_line,
        _interrupt_pin: interrupt_pin,
    })
}
