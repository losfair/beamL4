pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

#[derive(Debug)]
#[repr(C)]
#[allow(dead_code)]
pub struct VirtioPciCommonCfg {
    pub device_feature_select: u32,
    pub device_feature: u32,
    pub driver_feature_select: u32,
    pub driver_feature: u32,
    pub config_msix_vector: u16,
    pub num_queues: u16,
    pub device_status: u8,
    pub config_generation: u8,

    pub queue_select: u16,
    pub queue_size: u16,
    pub queue_msix_vector: u16,
    pub queue_enable: u16,
    pub queue_notify_off: u16,
    pub queue_desc: u64,
    pub queue_driver: u64,
    pub queue_device: u64,
    pub queue_notify_data: u16,
    pub queue_reset: u16,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 256],
    pub used_event: u16,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; 256],
    pub avail_event: u16,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}
