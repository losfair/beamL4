#[derive(Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug)]
#[rkyv(derive(Debug))]
pub struct TimeserverStartInfo {
    pub pit_ioport_cap: usize,
    pub pit_interrupt_cap: usize,
    pub notif_cap: usize,
    pub logserver_endpoint_cap: usize,
    pub endpoint_badge: usize,
    pub notif_badge: usize,
    pub tsc_frequency_mhz: u32,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug)]
#[rkyv(derive(Debug))]
pub enum TimeserverMsg {
    NotifyAfter {
        duration_us: u64,
        cancellation_token: [u8; 16],
    },
    Cancel {
        cancellation_token: [u8; 16],
    },
}
