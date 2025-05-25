use core::ops::Range;

use sel4::{
    cap::{Endpoint, LargePage, Notification, Tcb},
    CPtr,
};

pub static mut DESCRIPTION: ([u8; 128], usize) = ([0; 128], 0);
pub const RECV_CAP: CPtr = CPtr::from_bits(64);
pub const LOGSERVER_ENDPOINT_CAP: Endpoint = Endpoint::from_bits(65);
pub const TIMESERVER_ENDPOINT_CAP: Endpoint = Endpoint::from_bits(66);
pub const IRQ_NOTIF_CAP: Notification = Notification::from_bits(67);
pub const P_COMMON_CFG_4KB_FRAME_CAP: sel4::cap::_4k = sel4::cap::_4k::from_bits(68);
pub const P_NOTIFY_CFG_4KB_FRAME_CAP: sel4::cap::_4k = sel4::cap::_4k::from_bits(69);
pub const P_ISR_CFG_4KB_FRAME_CAP: sel4::cap::_4k = sel4::cap::_4k::from_bits(70);
pub const P_DEVICE_CFG_4KB_FRAME_CAP: sel4::cap::_4k = sel4::cap::_4k::from_bits(71);
pub const UNTYPED_2MB_CAP: [LargePage; 2] = [LargePage::from_bits(72), LargePage::from_bits(73)];
pub const USERFAULT_TCB_CAP: Tcb = Tcb::from_bits(74);
pub const USERFAULT_ENDPOINT_CAP: Endpoint = Endpoint::from_bits(75);
pub const CURRENT_PAGE_REFILL_NOTIF_SENDER_CAP: Notification = Notification::from_bits(76);
pub const CURRENT_INTERRUPT_NOTIF_SENDER_CAP: Notification = Notification::from_bits(77);
pub const TIMER_NOTIF_SENDER_CAP: Notification = Notification::from_bits(78);
pub const REMOTE_MAPPING_CAP_RANGE: Range<u32> = 128..12288;

pub fn self_description() -> &'static str {
    unsafe { core::str::from_utf8_unchecked(&DESCRIPTION.0[..DESCRIPTION.1]) }
}
