use core::{
    fmt::Write,
    sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
};

use sel4::{FrameObjectType, MessageInfo, cap::Endpoint};

static NOTIF_ENDPOINT: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
pub struct LogRing {
    pub bytes: [AtomicU8; FrameObjectType::LargePage.bytes() - 8],
    pub head: AtomicU32,
    pub used: AtomicU32,
}

#[derive(Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct LogserverStartInfo {
    pub ring_cap: usize,
    pub notif_rx_cap: usize,
    pub serial_ioport_cap: usize,
    pub thread_tcb_cap: usize,
    pub page_cap_start: usize,
    pub page_cap_end: usize,
    pub priority: u8,
    pub writer_thread_priority: u8,
}

impl LogRing {
    pub fn enqueue(&self, data: &[u8]) -> usize {
        // we assume unique write ownership on the ring buffer
        for (i, &b) in data.iter().enumerate() {
            let head = self.head.load(Ordering::Relaxed);

            if head.wrapping_sub(self.used.load(Ordering::Relaxed)) >= self.bytes.len() as u32 {
                // Buffer is full, drop
                return data.len() - i;
            }

            self.bytes[head as usize % self.bytes.len()].store(b, Ordering::Relaxed);

            // in case of concurrent access, don't do weird stuff
            let _ = self.head.compare_exchange(
                head,
                head.wrapping_add(1),
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
        }
        0
    }
}

pub unsafe fn set_log_endpoint(endpoint: Endpoint) {
    NOTIF_ENDPOINT.store(endpoint.bits(), Ordering::Relaxed);
}

pub fn get_log_endpoint() -> Option<Endpoint> {
    let endpoint = NOTIF_ENDPOINT.load(Ordering::Relaxed);
    if endpoint == 0 {
        None
    } else {
        Some(Endpoint::from_bits(endpoint))
    }
}

pub struct AsyncLogger;

impl Write for AsyncLogger {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let endpoint = NOTIF_ENDPOINT.load(Ordering::Relaxed);
        if endpoint == 0 {
            sel4::DebugWrite.write_str(s)
        } else {
            for chunk in s.as_bytes().chunks(core::mem::size_of::<usize>() * 4) {
                let mut chunk_array = [0u8; core::mem::size_of::<usize>() * 4];
                chunk_array[..chunk.len()].copy_from_slice(chunk);
                let chunk_array = unsafe {
                    core::mem::transmute::<
                        [u8; core::mem::size_of::<usize>() * 4],
                        [[u8; core::mem::size_of::<usize>()]; 4],
                    >(chunk_array)
                };
                let num_mr = chunk.len().div_ceil(core::mem::size_of::<usize>());
                sel4::sys::seL4_SendWithMRsWithoutIPCBuffer(
                    endpoint,
                    MessageInfo::new(chunk.len() as _, 0, 0, num_mr as _).into_inner(),
                    Some(u64::from_ne_bytes(chunk_array[0])),
                    Some(u64::from_ne_bytes(chunk_array[1])),
                    Some(u64::from_ne_bytes(chunk_array[2])),
                    Some(u64::from_ne_bytes(chunk_array[3])),
                );
            }
            Ok(())
        }
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        let _ = core::fmt::write(&mut $crate::logging::AsyncLogger, format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! println {
    () => ($crate::println!(""));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
