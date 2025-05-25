use core::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use sel4::sys::seL4_BootInfoID;

use crate::util::bootinfo::find_bootinfo_entry;

static TSC_FREQ_MHZ: AtomicU32 = AtomicU32::new(0);

pub fn init(bi: &sel4::BootInfoPtr) {
    let data = find_bootinfo_entry(bi, seL4_BootInfoID::SEL4_BOOTINFO_HEADER_X86_TSC_FREQ)
        .expect("Failed to find TSC frequency in bootinfo");
    assert_eq!(data.len(), 4);
    TSC_FREQ_MHZ.store(
        u32::from_le_bytes(data.try_into().unwrap()),
        Ordering::Relaxed,
    );
}

pub fn tsc_freq_mhz() -> u32 {
    TSC_FREQ_MHZ.load(Ordering::Relaxed)
}

pub fn time_since_boot() -> Duration {
    let mut aux = 0u32;
    let tsc = unsafe { core::arch::x86_64::__rdtscp(&mut aux) };
    let us = tsc / tsc_freq_mhz() as u64;
    Duration::from_micros(us)
}
