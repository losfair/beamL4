use alloc_::string::String;

use crate::misc::MmioSize;

#[derive(Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug)]
#[rkyv(derive(Debug))]
pub struct VirtioServerStartInfo {
    pub logserver_endpoint_cap: u8,
    pub timeserver_endpoint_cap: u8,
    pub irq_notif_cap: u8,
    pub userfault_tcb_cap: u8,

    pub p_common_cfg_4kb_frame_cap: u8,
    pub p_notify_cfg_4kb_frame_cap: u8,
    pub p_isr_cfg_4kb_frame_cap: u8,
    pub p_device_cfg_4kb_frame_cap: u8,

    pub endpoint_caps: [u8; 1],
    pub untyped_2mb_caps: [u8; 2],

    pub description: String,
    pub tsc_frequency_mhz: u32,
    pub irq_notif_cap_badge: u8,
    pub endpoint_badge: u8,
    pub priority: u8,
    pub root_cnode_bits: u8,
    pub notify_off_multiplier: u32,
    pub virtio_device_id: u16,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug)]
#[rkyv(derive(Debug))]
pub enum VirtioServerReq {
    OpenSession(VirtioOpenSessionReq),
    GetRefillAddress,
    Refill {
        page_addr: u64,
    },
    Mmio {
        offset: u32,
        write: Option<u32>,
        size: MmioSize,
    },
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug)]
#[rkyv(derive(Debug))]
pub struct VirtioOpenSessionReq {
    pub page_refill_notif_sender_cap: u8,
    pub interrupt_notif_sender_cap: u8,
    pub large_page: bool,
}
