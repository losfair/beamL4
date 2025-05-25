#![allow(dead_code)]

use sel4::{CPtr, IpcBuffer};

pub fn outb(ipc: &mut IpcBuffer, cap: CPtr, port: u16, value: u8) {
    let ret = ipc
        .inner_mut()
        .seL4_X86_IOPort_Out8(cap.bits(), port.into(), value.into());
    assert_eq!(ret, 0);
}

pub fn outw(ipc: &mut IpcBuffer, cap: CPtr, port: u16, value: u16) {
    let ret = ipc
        .inner_mut()
        .seL4_X86_IOPort_Out16(cap.bits(), port.into(), value.into());
    assert_eq!(ret, 0);
}

pub fn outl(ipc: &mut IpcBuffer, cap: CPtr, port: u16, value: u32) {
    let ret = ipc
        .inner_mut()
        .seL4_X86_IOPort_Out32(cap.bits(), port.into(), value.into());
    assert_eq!(ret, 0);
}

pub fn inb(ipc: &mut IpcBuffer, cap: CPtr, port: u16) -> u8 {
    let ret = ipc.inner_mut().seL4_X86_IOPort_In8(cap.bits(), port.into());
    assert_eq!(ret.error, 0);
    ret.result as u8
}

pub fn inw(ipc: &mut IpcBuffer, cap: CPtr, port: u16) -> u16 {
    let ret = ipc
        .inner_mut()
        .seL4_X86_IOPort_In16(cap.bits(), port.into());
    assert_eq!(ret.error, 0);
    ret.result as u16
}

pub fn inl(ipc: &mut IpcBuffer, cap: CPtr, port: u16) -> u32 {
    let ret = ipc
        .inner_mut()
        .seL4_X86_IOPort_In32(cap.bits(), port.into());
    assert_eq!(ret.error, 0);
    ret.result as u32
}
