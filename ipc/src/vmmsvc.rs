use alloc_::string::String;
use sel4::FrameObjectType;

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug)]
#[rkyv(derive(Debug))]
pub struct VmmServerStartInfo {
    pub logserver_endpoint_cap: u8,
    pub timeserver_endpoint_cap: u8,
    pub untyped_bucket_cap: u8,
    pub num_untyped: u32,
    pub kernel_bucket_cap: u8,
    pub num_kernel_pages: u32,
    pub asid_pool_cap: u8,
    pub rtc_ioport_cap: u8,
    pub has_rtc_ioport_cap: bool,
    pub hypervisor_channel_cap: u8,
    pub virtio_device_endpoint_cap_start: u8,
    pub num_virtio_devices: u8,

    pub tsc_frequency_mhz: u32,
    pub description: String,
    pub cnode_bits: u8,
    pub paging_mode: VmPagingMode,
    pub priority: u8,
    pub affinity: u32,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug)]
#[rkyv(derive(Debug))]
pub enum VmmToInitMsg {
    Reboot { index: u32 },
    Kill { index: u32 },
    IpcBench,
    SetMode { index: u32, mode: VmPagingMode },
    SetAffinity { index: u32, affinity: u32 },
    GpaLargeUnmap { paddr: u64 },
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
#[rkyv(derive(Debug))]
pub enum VmPagingMode {
    EptLargePage,
    EptSmallPage,
    Pv,
}

impl VmPagingMode {
    pub fn frame_object_type(&self) -> FrameObjectType {
        match self {
            VmPagingMode::EptLargePage => FrameObjectType::LargePage,
            VmPagingMode::EptSmallPage | VmPagingMode::Pv => FrameObjectType::_4k,
        }
    }
}
