use core::ops::Range;

use sel4::{
    cap::{AsidPool, CNode, Endpoint},
    CPtr,
};

pub static mut DESCRIPTION: ([u8; 128], usize) = ([0; 128], 0);
pub const RECV_CAP: CPtr = CPtr::from_bits(64);
pub const LOGSERVER_ENDPOINT_CAP: Endpoint = Endpoint::from_bits(65);
pub const TIMESERVER_ENDPOINT_CAP: Endpoint = Endpoint::from_bits(66);
pub const UNTYPED_BUCKET_CAP: CNode = CNode::from_bits(67);
pub const KERNEL_BUCKET_CAP: CNode = CNode::from_bits(68);
pub const ASID_POOL_CAP: AsidPool = AsidPool::from_bits(69);
pub const RTC_IOPORT_CAP: CPtr = CPtr::from_bits(70);
pub const HYPERVISOR_CHANNEL_CAP: Endpoint = Endpoint::from_bits(71);
pub const L0_CNODE_CAP: CNode = CNode::from_bits(72);

pub const DYNAMIC_PAGES_REGION: Range<usize> = 0x10_c000_0000..0x11_0000_0000;
pub const ELF_LOAD_REGION: Range<usize> = 0x20_0000_0000..0x21_0000_0000;
pub const IDMAP_REGION: Range<usize> = 0x80_0000_0000..0x880_0000_0000;
pub const L0_CNODE_BITS: u8 = 4;

pub const GUEST_STACK_PHYS: u64 = 0x4000;
pub const GUEST_START_INFO_PHYS: u64 = 0x5000;
pub const GUEST_INITIAL_PT_PML4_PHYS: u64 = 0xf000;
pub const GUEST_INITIAL_PT_PDPT_PHYS: u64 = 0xe000;
pub const GUEST_INITIAL_PT_PD_PHYS: u64 = 0xd000;
pub const GUEST_RAMDISK_PHYS: u64 = 0x1100_0000;
pub const GUEST_VIRTIO_MMIO_START: u64 = 0xc100_0000;
pub const GUEST_VIRTIO_MMIO_INTERRUPT_BASE: u8 = 0x40;

pub fn self_description() -> &'static str {
    unsafe { core::str::from_utf8_unchecked(&DESCRIPTION.0[..DESCRIPTION.1]) }
}
