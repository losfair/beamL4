use core::sync::atomic::{AtomicU64, Ordering};

pub const STATIC_CAP_BASE: u64 = 0xf000;

pub const SELF_START_ADDR: u64 = 0x200000;

pub const HOST_DYNAMIC_SMALL_MAPPING_BASE: u64 = 0x1_0000_0000;
pub const HOST_DYNAMIC_SMALL_MAPPING_END: u64 = 0x1_4000_0000;

pub static NEXT_INTR_VECTOR: AtomicU64 = AtomicU64::new(0);

pub fn allocate_intr_vector() -> u8 {
    u8::try_from(NEXT_INTR_VECTOR.fetch_add(1, Ordering::Relaxed)).expect("intr vector overflow")
}
