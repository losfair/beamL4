#[derive(Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DbgserverStartInfo {
    pub logserver_endpoint_cap: u8,
    pub timeserver_endpoint_cap: u8,
    pub i8042_ioport_cap: u8,
    pub i8042_interrupt_cap: u8,
    pub serial_ioport_cap: u8,
    pub serial_interrupt_cap: u8,
    pub notif_rx_cap: u8,
    pub hypervisor_channel_cap: u8,

    pub priority: u8,
    pub root_cnode_bits: u8,
    pub tsc_freq_mhz: u32,
}
