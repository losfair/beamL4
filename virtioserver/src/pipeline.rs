use core::{
    alloc::Layout,
    mem::{offset_of, MaybeUninit},
    ptr::{addr_of, addr_of_mut, read_volatile, write_volatile, NonNull},
    usize,
};

use algorithms::idalloc::{IdAlloc64, IdAlloc64OffsetLimit, IdAlloc64Trait};
use alloc::{boxed::Box, collections::BTreeMap};
use ipc::{
    conventions::{
        SUBPROC_CSPACE, SUBPROC_PREMAPPED_HIGH_REGION, SUBPROC_PREMAPPED_LARGE_PAGE_REGION,
        SUBPROC_VSPACE,
    },
    misc::{delete_cap, now_cycles, MmioSize},
    println,
    userfault::{read_user_memory, write_user_memory},
    virtiosvc::VirtioOpenSessionReq,
};
use sel4::{cap::CNode, CPtr, CapRights, FrameObjectType, IpcBuffer, MessageInfo, VmAttributes};
use talc::{ErrOnOom, Span, Talc};

use crate::{
    shared::{
        self_description, CURRENT_INTERRUPT_NOTIF_SENDER_CAP, CURRENT_PAGE_REFILL_NOTIF_SENDER_CAP,
        P_COMMON_CFG_4KB_FRAME_CAP, P_DEVICE_CFG_4KB_FRAME_CAP, P_ISR_CFG_4KB_FRAME_CAP,
        P_NOTIFY_CFG_4KB_FRAME_CAP, RECV_CAP, REMOTE_MAPPING_CAP_RANGE, UNTYPED_2MB_CAP,
    },
    virtq::{
        VirtioPciCommonCfg, VirtqAvail, VirtqDesc, VirtqUsed, VirtqUsedElem, VIRTQ_DESC_F_INDIRECT,
        VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    },
};

const LARGE_PAGE_SIZE: usize = FrameObjectType::LargePage.bytes();
const SMALL_PAGE_SIZE: usize = FrameObjectType::_4k.bytes();
const CSPACE: CNode = CNode::from_cptr(SUBPROC_CSPACE);
const MAX_QUEUES: usize = 4;
const VIRTIO_F_RING_INDIRECT_DESC: u32 = 1 << 28;
const VIRTIO_F_RING_EVENT_IDX: u32 = 1 << 29;

const DEBUG: bool = false;

struct Region {
    allocator: Talc<ErrOnOom>,
    virtual_base: usize,
    physical_base: usize,
}

impl Region {
    fn contains_physical(&self, paddr: usize) -> bool {
        paddr >= self.physical_base && paddr < self.physical_base + LARGE_PAGE_SIZE
    }
}

struct DescHandle {
    desc_ptr: *mut VirtqDesc,
    desc: VirtqDesc,
    id: usize,
    region_index: usize,
}

static mut REMOTE_MAPPINGS_IDALLOC: IdAlloc64OffsetLimit<IdAlloc64<3>> = IdAlloc64OffsetLimit {
    inner: IdAlloc64::new(),
    offset: 0,
    limit: (REMOTE_MAPPING_CAP_RANGE.end - REMOTE_MAPPING_CAP_RANGE.start) as u64,
};

pub struct Pipeline {
    common_cfg: *mut VirtioPciCommonCfg,
    notify_cfg: *mut [u8; 4096],
    isr_cfg: *mut [u8; 4096],
    device_cfg: *mut [u8; 4096],
    notify_off_multiplier: u32,
    alloc: heapless::Vec<Region, { UNTYPED_2MB_CAP.len() }>,
    remote_mappings_start_4k: *mut u8,
    remote_mappings_start_2m: *mut u8,
    remote_mappings: BTreeMap<u64, RemoteMapping>,
    remote_mappings_idalloc: &'static mut IdAlloc64OffsetLimit<IdAlloc64<3>>,
    remote_large_page_enabled: bool,
    pending_refill_address: usize,
    pending_fault: bool,
    remote_selected_queue: u8,
    num_queues: u16,
    queues: Box<[Queue; MAX_QUEUES]>,
    interrupt_pending: bool,
    virtio_device_id: u16,
    tsc_freq_mhz: u32,
}

#[repr(C)]
struct Queue {
    descriptor_table_4kb: *mut [VirtqDesc; 256],
    avail_ring_4kb: *mut VirtqAvail,
    used_ring_4kb: *mut VirtqUsed,
    notify_off: u16,
    max_size: u16,
    enable: bool,
    seen_used_idx: u16,
    remote: RemoteQueue,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct RemoteQueue {
    desc_phys: u64,
    avail_phys: u64,
    used_phys: u64,
}

#[derive(Default)]
struct RemoteMapping {
    remote_addr: u64,
    last_used_tsc: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct PipelineContext {
    pub notify_off_multiplier: u32,
    pub virtio_device_id: u16,
    pub tsc_freq_mhz: u32,
}

impl Pipeline {
    pub fn new(ipc: &mut IpcBuffer, ctx: PipelineContext) -> Self {
        let common_cfg = SUBPROC_PREMAPPED_HIGH_REGION.start as *mut [u8; 4096];
        let notify_cfg = unsafe { common_cfg.add(1) };
        let isr_cfg = unsafe { notify_cfg.add(1) };
        let device_cfg = unsafe { isr_cfg.add(1) };

        let remote_mappings_start_4k = unsafe { device_cfg.add(2) }.cast::<u8>();

        assert_eq!(
            ipc.inner_mut().seL4_X86_Page_Map(
                P_COMMON_CFG_4KB_FRAME_CAP.bits(),
                SUBPROC_VSPACE.bits(),
                common_cfg.addr() as _,
                CapRights::read_write().into_inner(),
                VmAttributes::CACHE_DISABLED.into_inner()
            ),
            0
        );
        assert_eq!(
            ipc.inner_mut().seL4_X86_Page_Map(
                P_NOTIFY_CFG_4KB_FRAME_CAP.bits(),
                SUBPROC_VSPACE.bits(),
                notify_cfg.addr() as _,
                CapRights::read_write().into_inner(),
                VmAttributes::CACHE_DISABLED.into_inner()
            ),
            0
        );
        assert_eq!(
            ipc.inner_mut().seL4_X86_Page_Map(
                P_ISR_CFG_4KB_FRAME_CAP.bits(),
                SUBPROC_VSPACE.bits(),
                isr_cfg.addr() as _,
                CapRights::read_write().into_inner(),
                VmAttributes::CACHE_DISABLED.into_inner()
            ),
            0
        );
        assert_eq!(
            ipc.inner_mut().seL4_X86_Page_Map(
                P_DEVICE_CFG_4KB_FRAME_CAP.bits(),
                SUBPROC_VSPACE.bits(),
                device_cfg.addr() as _,
                CapRights::read_write().into_inner(),
                VmAttributes::CACHE_DISABLED.into_inner()
            ),
            0
        );

        let mut lp_top = SUBPROC_PREMAPPED_LARGE_PAGE_REGION.start;
        let mut alloc = heapless::Vec::new();

        let mut queues: Box<[Queue; MAX_QUEUES]> = unsafe { Box::new_zeroed().assume_init() };

        for (i, cap) in UNTYPED_2MB_CAP.iter().enumerate() {
            assert_eq!(
                ipc.inner_mut().seL4_X86_Page_Map(
                    cap.bits(),
                    SUBPROC_VSPACE.bits(),
                    lp_top as _,
                    CapRights::read_write().into_inner(),
                    VmAttributes::DEFAULT.into_inner(),
                ),
                0
            );

            let physical_addr = ipc.inner_mut().seL4_X86_Page_GetAddress(cap.bits());
            assert_eq!(physical_addr.error, 0);

            let offset: usize = if i == 0 {
                for i in 0..MAX_QUEUES {
                    let base = lp_top + i * 3 * 4096;
                    queues[i].descriptor_table_4kb = base as *mut [VirtqDesc; 256];
                    queues[i].avail_ring_4kb = (base + 4096) as *mut VirtqAvail;
                    queues[i].used_ring_4kb = (base + 8192) as *mut VirtqUsed;
                }
                MAX_QUEUES * 3 * 4096
            } else {
                0
            };
            let mut a = Talc::new(ErrOnOom);
            unsafe {
                a.claim(Span::from_base_size(
                    (lp_top + offset) as *mut u8,
                    LARGE_PAGE_SIZE - offset,
                ))
                .expect("Failed to claim memory for allocator");
            }
            alloc
                .push(Region {
                    allocator: a,
                    virtual_base: lp_top,
                    physical_base: physical_addr.paddr as usize,
                })
                .ok()
                .unwrap();
            lp_top += LARGE_PAGE_SIZE;
        }

        assert!(lp_top > SUBPROC_PREMAPPED_LARGE_PAGE_REGION.start);
        let remote_mappings_start_2m = lp_top as *mut u8;

        let common_cfg = common_cfg.cast::<VirtioPciCommonCfg>();

        // read queue parameters
        let num_queues;
        unsafe {
            num_queues = addr_of_mut!((*common_cfg).num_queues).read_volatile();
            assert!(num_queues as usize <= MAX_QUEUES);

            for i in 0..num_queues as usize {
                addr_of_mut!((*common_cfg).queue_select).write_volatile(i as u16);
                let queue = &mut queues[i];
                queue.notify_off = addr_of_mut!((*common_cfg).queue_notify_off).read_volatile();
                queue.max_size = addr_of_mut!((*common_cfg).queue_size)
                    .read_volatile()
                    .min(256) as u16;
            }

            addr_of_mut!((*common_cfg).queue_select).write_volatile(0);
        }
        println!(
            "virtioserver[{}]: mapped {} bytes, {} queues",
            self_description(),
            lp_top - SUBPROC_PREMAPPED_LARGE_PAGE_REGION.start,
            num_queues,
        );

        Self {
            common_cfg,
            notify_cfg,
            isr_cfg,
            device_cfg,
            notify_off_multiplier: ctx.notify_off_multiplier,
            alloc,
            remote_mappings_start_4k,
            remote_mappings_start_2m,
            remote_mappings: BTreeMap::new(),
            remote_mappings_idalloc: unsafe { &mut REMOTE_MAPPINGS_IDALLOC },
            remote_large_page_enabled: false,
            pending_refill_address: core::usize::MAX,
            pending_fault: false,
            remote_selected_queue: 0,
            num_queues,
            queues,
            interrupt_pending: false,
            virtio_device_id: ctx.virtio_device_id,
            tsc_freq_mhz: ctx.tsc_freq_mhz,
        }
    }

    pub fn open_session(
        &mut self,
        ipc: &mut IpcBuffer,
        msg: MessageInfo,
        req: VirtioOpenSessionReq,
        littlenode_bits: u8,
        _recv_cap_consumed: &mut bool,
    ) -> Option<MessageInfo> {
        self.reset(ipc);
        delete_cap(CSPACE, CURRENT_PAGE_REFILL_NOTIF_SENDER_CAP.cptr());
        delete_cap(CSPACE, CURRENT_INTERRUPT_NOTIF_SENDER_CAP.cptr());
        if msg.extra_caps() != 1
            || msg.caps_unwrapped() != 0
            || ipc.inner_mut().seL4_CNode_Move(
                SUBPROC_CSPACE.bits(),
                CURRENT_PAGE_REFILL_NOTIF_SENDER_CAP.bits(),
                64,
                RECV_CAP.bits(),
                req.page_refill_notif_sender_cap as u64,
                littlenode_bits,
            ) != 0
            || ipc.inner_mut().seL4_CNode_Move(
                SUBPROC_CSPACE.bits(),
                CURRENT_INTERRUPT_NOTIF_SENDER_CAP.bits(),
                64,
                RECV_CAP.bits(),
                req.interrupt_notif_sender_cap as u64,
                littlenode_bits,
            ) != 0
        {
            return None;
        }
        self.remote_large_page_enabled = req.large_page;
        Some(MessageInfo::new(1, 0, 0, 0))
    }

    pub fn mmio(
        &mut self,
        ipc: &mut IpcBuffer,
        offset: u32,
        write: Option<u32>,
        size: MmioSize,
    ) -> Option<MessageInfo> {
        let mut read_value = 0u32;

        if DEBUG {
            println!(
                "virtioserver[{}]: mmio {:x?}",
                self_description(),
                (offset, write, size)
            );
        }
        match (offset, write, size) {
            (0x000, None, MmioSize::Dword) => {
                // MagicValue
                read_value = 0x74726976;
            }
            (0x004, None, MmioSize::Dword) => {
                // Version
                read_value = 0x2;
            }
            (0x008, None, MmioSize::Dword) => {
                // DeviceID
                read_value = self.virtio_device_id as u32;
            }
            (0x00c, None, MmioSize::Dword) => {
                // VendorID
                read_value = 0x1af4;
            }
            (0x010, None, MmioSize::Dword) => {
                // DeviceFeatures
                read_value =
                    unsafe { addr_of_mut!((*self.common_cfg).device_feature).read_volatile() };
                read_value &= !VIRTIO_F_RING_EVENT_IDX;
                read_value &= !VIRTIO_F_RING_INDIRECT_DESC;
            }
            (0x014, Some(x), MmioSize::Dword) => unsafe {
                // DeviceFeaturesSel
                addr_of_mut!((*self.common_cfg).device_feature_select).write_volatile(x as u32);
            },
            (0x020, Some(x), MmioSize::Dword) => unsafe {
                // DriverFeatures
                addr_of_mut!((*self.common_cfg).driver_feature).write_volatile(x as u32);
            },
            (0x024, Some(x), MmioSize::Dword) => unsafe {
                // DriverFeaturesSel
                addr_of_mut!((*self.common_cfg).driver_feature_select).write_volatile(x as u32);
            },
            (0x030, Some(x), MmioSize::Dword | MmioSize::Word) => unsafe {
                // QueueSel
                if (x as usize) < self.num_queues as usize {
                    self.remote_selected_queue = x as u8;
                    addr_of_mut!((*self.common_cfg).queue_select).write_volatile(x as u16);
                }
            },
            (0x034, None, MmioSize::Dword | MmioSize::Word) => {
                // QueueNumMax
                read_value = self.queues[self.remote_selected_queue as usize].max_size as u32;
            }
            (0x038, Some(x), MmioSize::Dword | MmioSize::Word) => unsafe {
                // QueueNum
                let size = x as u16;
                if size <= 256 {
                    addr_of_mut!((*self.common_cfg).queue_size).write_volatile(size);
                }
            },
            (0x044, Some(x), MmioSize::Dword | MmioSize::Word) => unsafe {
                // QueueReady
                self.queues[self.remote_selected_queue as usize].enable = x != 0;
                addr_of_mut!((*self.common_cfg).queue_enable).write_volatile(x as u16);
            },
            (0x044, None, MmioSize::Dword | MmioSize::Word) => unsafe {
                // QueueReady
                read_value = addr_of_mut!((*self.common_cfg).queue_enable).read_volatile() as u32;
            },
            (0x050, Some(_selected_queue), MmioSize::Dword | MmioSize::Word) => {
                // QueueNotify
                unsafe {
                    self.process_queues(ipc);
                }
            }
            (0x060, None, MmioSize::Dword | MmioSize::Word | MmioSize::Byte) => {
                // InterruptStatus
                read_value = if self.interrupt_pending { 1 } else { 0 };
            }
            (0x064, Some(_), MmioSize::Dword | MmioSize::Word) => {
                // InterruptACK
                // NOP - The PCI protocol auto-deasserts on 0x060 read
                if DEBUG && self.interrupt_pending {
                    println!("virtioserver[{}]: ack interrupt", self_description());
                }
                self.interrupt_pending = false;
            }
            (0x070, None, MmioSize::Dword | MmioSize::Word | MmioSize::Byte) => unsafe {
                // Status
                read_value = addr_of_mut!((*self.common_cfg).device_status).read_volatile() as u32;
            },
            (0x070, Some(x), MmioSize::Dword | MmioSize::Word | MmioSize::Byte) => unsafe {
                // Status
                if x == 0 {
                    println!("virtioserver[{}]: reset", self_description());
                    self.reset(ipc);
                } else {
                    addr_of_mut!((*self.common_cfg).device_status).write_volatile(x as u8);
                }
            },
            (0x080, Some(x), MmioSize::Dword) => {
                // QueueDescLow
                let q = &mut self.queues[self.remote_selected_queue as usize];
                q.remote.desc_phys = ((q.remote.desc_phys >> 32) << 32) | (x as u64);
            }
            (0x084, Some(x), MmioSize::Dword) => {
                // QueueDescHigh
                let q = &mut self.queues[self.remote_selected_queue as usize];
                q.remote.desc_phys = (q.remote.desc_phys & 0xffff_ffff) | ((x as u64) << 32);
            }
            (0x090, Some(x), MmioSize::Dword) => {
                // QueueDriverLow
                let q = &mut self.queues[self.remote_selected_queue as usize];
                q.remote.avail_phys = ((q.remote.avail_phys >> 32) << 32) | (x as u64);
            }
            (0x094, Some(x), MmioSize::Dword) => {
                // QueueDriverHigh
                let q = &mut self.queues[self.remote_selected_queue as usize];
                q.remote.avail_phys = (q.remote.avail_phys & 0xffff_ffff) | ((x as u64) << 32);
            }
            (0x0a0, Some(x), MmioSize::Dword) => {
                // QueueDeviceLow
                let q = &mut self.queues[self.remote_selected_queue as usize];
                q.remote.used_phys = ((q.remote.used_phys >> 32) << 32) | (x as u64);
            }
            (0x0a4, Some(x), MmioSize::Dword) => {
                // QueueDeviceHigh
                let q = &mut self.queues[self.remote_selected_queue as usize];
                q.remote.used_phys = (q.remote.used_phys & 0xffff_ffff) | ((x as u64) << 32);
            }
            (off, value, size) if off >= 0x100 && off < 0x1100 => unsafe {
                let cfg: *mut u8 = self.device_cfg.cast();
                let off = (off - 0x100) as usize;
                match value {
                    Some(value) => match size {
                        MmioSize::Byte => {
                            write_volatile(cfg.add(off), value as u8);
                        }
                        MmioSize::Word if off % 2 == 0 => {
                            write_volatile(cfg.add(off).cast::<u16>(), value as u16);
                        }
                        MmioSize::Dword if off % 4 == 0 => {
                            write_volatile(cfg.add(off).cast::<u32>(), value as u32);
                        }
                        _ => {}
                    },
                    None => match size {
                        MmioSize::Byte => {
                            read_value = read_volatile(cfg.add(off)) as u32;
                        }
                        MmioSize::Word if off % 2 == 0 => {
                            read_value = read_volatile(cfg.add(off).cast::<u16>()) as u32;
                        }
                        MmioSize::Dword if off % 4 == 0 => {
                            read_value = read_volatile(cfg.add(off).cast::<u32>()) as u32;
                        }
                        _ => {}
                    },
                }
            },

            _ => {
                println!(
                    "virtio_mmio: unknown operation {:x?}",
                    (offset, write, size)
                );
            }
        }

        Some(if write.is_some() {
            MessageInfo::new(1, 0, 0, 0)
        } else {
            ipc.msg_regs_mut()[0] = read_value as u64;
            MessageInfo::new(1, 0, 0, 1)
        })
    }

    pub fn get_refill_address(&mut self, ipc: &mut IpcBuffer) -> Option<MessageInfo> {
        ipc.msg_regs_mut()[0] = self.pending_refill_address as u64;
        Some(MessageInfo::new(1, 0, 0, 1))
    }

    pub fn refill(
        &mut self,
        ipc: &mut IpcBuffer,
        msg: MessageInfo,
        page_addr: u64,
        recv_cap_consumed: &mut bool,
    ) -> Option<MessageInfo> {
        if page_addr != self.pending_refill_address as u64
            || msg.extra_caps() != 1
            || msg.caps_unwrapped() != 0
        {
            println!(
                "invalid refill: page_addr: {:#x}, pending_refill_address: {:#x}",
                page_addr, self.pending_refill_address
            );
            return None;
        }
        *recv_cap_consumed = true;
        match self.insert_page(ipc, page_addr as usize, sel4::cap::_4k::from_cptr(RECV_CAP)) {
            Ok(()) => {
                self.pending_refill_address = core::usize::MAX;
                unsafe {
                    self.process_queues(ipc);
                }
                Some(MessageInfo::new(1, 0, 0, 0))
            }
            Err(()) => {
                println!("failed to insert page");
                None
            }
        }
    }

    pub fn irq_notif(&mut self, ipc: &mut IpcBuffer) {
        // println!("virtioserver[{}]: irq notif", self_description());
        unsafe {
            if self.isr_cfg.cast::<u32>().read_volatile() != 0 {
                self.process_queues(ipc);
            }
        }
    }

    pub fn timer_notif(&mut self, ipc: &mut IpcBuffer) {
        // println!("virtioserver[{}]: timer notif", self_description());
        unsafe {
            self.process_queues(ipc);
        }
    }

    unsafe fn process_queues(&mut self, ipc: &mut IpcBuffer) {
        if self.pending_refill_address != core::usize::MAX || self.pending_fault {
            return;
        }

        let did_interrupt_pending = self.interrupt_pending;

        for i in 0..self.num_queues as usize {
            if !self.queues[i].enable {
                continue;
            }
            if !self.process_used(ipc, i) {
                break;
            }
            if !self.process_avail(ipc, i) {
                break;
            }
        }

        if !did_interrupt_pending && self.interrupt_pending {
            ipc.inner_mut()
                .seL4_Signal(CURRENT_INTERRUPT_NOTIF_SENDER_CAP.bits());
        }
    }

    unsafe fn foreach_desc(
        &mut self,
        mut id: usize,
        queue_index: usize,
        mut cb: impl FnMut(&mut Self, DescHandle) -> bool,
    ) -> bool {
        let mut iterations = 0usize;
        loop {
            if iterations > 256 {
                println!(
                    "virtioserver[{}]: too many iterations in foreach_desc",
                    self_description()
                );
                self.pending_fault = true;
                return false;
            }
            iterations += 1;

            if id >= 256 {
                self.pending_fault = true;
                return false;
            }
            let desc_ptr = self.queues[queue_index]
                .descriptor_table_4kb
                .cast::<VirtqDesc>()
                .add(id as usize);
            let desc = desc_ptr.read_volatile();
            let region_index = self
                .alloc
                .iter()
                .position(|x| x.contains_physical(desc.addr as usize))
                .expect("Failed to find region for descriptor");

            if !cb(
                self,
                DescHandle {
                    desc_ptr,
                    desc,
                    id,
                    region_index,
                },
            ) {
                return false;
            }

            if desc.flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            id = desc.next as usize;
        }
        true
    }

    unsafe fn process_used(&mut self, ipc: &mut IpcBuffer, queue_index: usize) -> bool {
        let used_ring = self.queues[queue_index].used_ring_4kb;
        core::arch::x86_64::_mm_mfence();

        // copy flags
        if !self.usermem_write(
            ipc,
            (self.queues[queue_index].remote.used_phys + offset_of!(VirtqUsed, flags) as u64)
                as usize,
            core::slice::from_raw_parts((&(*used_ring).flags) as *const u16 as *const u8, 2),
        ) {
            return false;
        }

        while self.queues[queue_index].seen_used_idx != addr_of!((*used_ring).idx).read_volatile() {
            let elem_index = self.queues[queue_index].seen_used_idx as usize % 256;
            let elem = addr_of_mut!((*used_ring).ring)
                .cast::<VirtqUsedElem>()
                .add(elem_index)
                .read_volatile();

            // Copy out descriptor payloads
            if !self.foreach_desc(elem.id as usize, queue_index, |me, h| {
                let region = &me.alloc[h.region_index];
                let slice = core::slice::from_raw_parts(
                    (h.desc.addr as usize - region.physical_base + region.virtual_base)
                        as *const u8,
                    h.desc.len as usize,
                );

                if h.desc.flags & VIRTQ_DESC_F_WRITE != 0 {
                    let mut remote_desc = MaybeUninit::<VirtqDesc>::zeroed();
                    if !me.usermem_read(
                        ipc,
                        (me.queues[queue_index].remote.desc_phys
                            + h.id as u64 * core::mem::size_of::<VirtqDesc>() as u64)
                            as usize,
                        remote_desc.as_bytes_mut().assume_init_mut(),
                    ) {
                        return false;
                    }
                    let remote_desc = remote_desc.assume_init();
                    let len = remote_desc.len.min(h.desc.len);
                    if !me.usermem_write(ipc, remote_desc.addr as _, &slice[..len as usize]) {
                        return false;
                    }
                }

                true
            }) {
                return false;
            }

            let next_idx: u16 = self.queues[queue_index].seen_used_idx.wrapping_add(1);

            // Copy out queue element
            if !self.usermem_write(
                ipc,
                (self.queues[queue_index].remote.used_phys
                    + offset_of!(VirtqUsed, ring) as u64
                    + elem_index as u64 * core::mem::size_of::<VirtqUsedElem>() as u64)
                    as usize,
                MaybeUninit::new(elem).as_bytes().assume_init_ref(),
            ) {
                return false;
            }

            core::arch::x86_64::_mm_sfence();

            if !self.usermem_write(
                ipc,
                (self.queues[queue_index].remote.used_phys + offset_of!(VirtqUsed, idx) as u64)
                    as usize,
                &next_idx.to_ne_bytes(),
            ) {
                return false;
            }

            // Free local descriptor
            if !self.foreach_desc(elem.id as usize, queue_index, |me, h| {
                h.desc_ptr.write_volatile(VirtqDesc::default());
                let region = &mut me.alloc[h.region_index];
                region.allocator.free(
                    NonNull::new_unchecked(
                        (h.desc.addr as usize - region.physical_base + region.virtual_base)
                            as *mut u8,
                    ),
                    Layout::from_size_align(h.desc.len as usize, 1).unwrap(),
                );
                true
            }) {
                return false;
            }

            self.queues[queue_index].seen_used_idx = next_idx;

            if DEBUG && !self.interrupt_pending {
                println!(
                    "virtioserver[{}]: interrupt pending for queue {}",
                    self_description(),
                    queue_index
                );
            }
            self.interrupt_pending = true;
        }

        true
    }

    unsafe fn process_avail(&mut self, ipc: &mut IpcBuffer, queue_index: usize) -> bool {
        let avail_ring = self.queues[queue_index].avail_ring_4kb;
        let mut doorbell = false;

        // copy flags
        if !self.usermem_read(
            ipc,
            (self.queues[queue_index].remote.avail_phys + offset_of!(VirtqAvail, flags) as u64)
                as usize,
            core::slice::from_raw_parts_mut((&mut (*avail_ring).flags) as *mut u16 as *mut u8, 2),
        ) {
            return false;
        }

        loop {
            let mut remote_idx = [0u8; 2];
            if !self.usermem_read(
                ipc,
                (self.queues[queue_index].remote.avail_phys + offset_of!(VirtqAvail, idx) as u64)
                    as usize,
                &mut remote_idx,
            ) {
                return false;
            }
            let remote_idx = u16::from_ne_bytes(remote_idx);
            let seen_avail_idx = addr_of_mut!((*avail_ring).idx).read_volatile();
            if seen_avail_idx == remote_idx {
                break;
            }
            let elem_index = seen_avail_idx as usize % 256;
            let mut desc_index = [0u8; 2];
            if !self.usermem_read(
                ipc,
                (self.queues[queue_index].remote.avail_phys
                    + offset_of!(VirtqAvail, ring) as u64
                    + elem_index as u64 * core::mem::size_of::<u16>() as u64)
                    as usize,
                &mut desc_index,
            ) {
                return false;
            }
            let first_desc_index = u16::from_ne_bytes(desc_index);
            let mut desc_index = first_desc_index;

            let mut iterations = 0usize;
            loop {
                if iterations > 256 {
                    println!(
                        "virtioserver[{}]: too many iterations in process_avail",
                        self_description()
                    );
                    self.pending_fault = true;
                    return false;
                }
                iterations += 1;

                if desc_index >= 256 {
                    self.pending_fault = true;
                    return false;
                }

                let mut remote_desc = MaybeUninit::<VirtqDesc>::zeroed();
                if !self.usermem_read(
                    ipc,
                    (self.queues[queue_index].remote.desc_phys
                        + desc_index as u64 * core::mem::size_of::<VirtqDesc>() as u64)
                        as usize,
                    remote_desc.as_bytes_mut().assume_init_mut(),
                ) {
                    return false;
                }
                let remote_desc = remote_desc.assume_init();

                if remote_desc.flags & VIRTQ_DESC_F_INDIRECT != 0 {
                    println!(
                        "virtioserver[{}]: indirect descriptor not supported",
                        self_description()
                    );
                    self.pending_fault = true;
                    return false;
                }
                let desc_ptr = self.queues[queue_index]
                    .descriptor_table_4kb
                    .cast::<VirtqDesc>()
                    .add(desc_index as usize);

                if (*desc_ptr).addr == 0 || (*desc_ptr).len != remote_desc.len {
                    // previous buffer is still alive - we cannot deallocate it safely!
                    if (*desc_ptr).addr != 0 {
                        println!(
                            "virtioserver[{}]: descriptor {} is still alive, paddr {:#x}, len {}",
                            self_description(),
                            desc_index,
                            (*desc_ptr).addr,
                            (*desc_ptr).len
                        );
                        self.pending_fault = true;
                        return false;
                    }

                    // alloc shadow buffer
                    let mut shadow_buf = None;
                    let mut shadow_buf_phys = 0;
                    for region in &mut self.alloc {
                        if let Ok(ptr) = region
                            .allocator
                            .malloc(Layout::from_size_align(remote_desc.len as usize, 1).unwrap())
                        {
                            shadow_buf = Some(ptr);
                            shadow_buf_phys =
                                ptr.addr().get() - region.virtual_base + region.physical_base;
                            break;
                        }
                    }
                    if shadow_buf.is_none() {
                        println!(
                            "virtioserver[{}]: failed to allocate shadow buffer for avail desc, len {}",
                            self_description(),
                            remote_desc.len
                        );
                        self.pending_fault = true;
                        return false;
                    };

                    desc_ptr.write_volatile(VirtqDesc {
                        addr: shadow_buf_phys as u64,
                        ..remote_desc
                    });
                }

                // Copy in data
                let region = self
                    .alloc
                    .iter_mut()
                    .find(|x| x.contains_physical((*desc_ptr).addr as usize))
                    .expect("Failed to find region for descriptor");
                let vaddr = ((*desc_ptr).addr as usize - region.physical_base + region.virtual_base)
                    as *mut u8;
                let slice = core::slice::from_raw_parts_mut(vaddr, (*desc_ptr).len as usize);
                if !self.usermem_read(ipc, remote_desc.addr as usize, slice) {
                    return false;
                }

                // if DEBUG {
                //     println!(
                //         "virtioserver[{}]: populated avail desc at index {}",
                //         self_description(),
                //         desc_index,
                //     );
                // }

                if remote_desc.flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
                desc_index = remote_desc.next;
            }

            // Write queue element
            addr_of_mut!((*avail_ring).ring)
                .cast::<u16>()
                .add(elem_index)
                .write_volatile(first_desc_index);

            core::arch::x86_64::_mm_sfence();
            addr_of_mut!((*avail_ring).idx).write_volatile(seen_avail_idx.wrapping_add(1));
            doorbell = true;
        }

        if doorbell {
            let notify_addr = self.notify_cfg.cast::<u8>().add(
                self.queues[queue_index].notify_off as usize * self.notify_off_multiplier as usize,
            );
            core::arch::x86_64::_mm_mfence();
            notify_addr.cast::<u32>().write_volatile(queue_index as u32);
            if DEBUG {
                println!(
                    "virtioserver[{}]: doorbell for queue {}",
                    self_description(),
                    queue_index
                );
            }
        }

        true
    }

    fn usermem_read(&mut self, ipc: &mut IpcBuffer, start: usize, output: &mut [u8]) -> bool {
        let mut cursor = 0usize;
        let end = start.saturating_add(output.len());
        output.fill(0);
        let mut fault = false;
        let ret = self.usermem(start, end, |_, buf, len| {
            if let Err(remaining) =
                read_user_memory(&mut output[cursor..cursor + len], buf.as_ptr())
            {
                println!(
                    "user memory read failed @ {:p}, remaining {}/{}",
                    buf.as_ptr(),
                    remaining,
                    len
                );
                fault = true;
                return false;
            }
            cursor += len;
            true
        });

        if fault {
            self.pending_fault = true;
            return false;
        }

        if let Err(page_addr) = ret {
            self.pending_refill_address = page_addr;
            if DEBUG {
                println!(
                    "virtioserver[{}]: refill (r) @ {:#x}",
                    self_description(),
                    page_addr
                );
            }
            ipc.inner_mut()
                .seL4_Signal(CURRENT_PAGE_REFILL_NOTIF_SENDER_CAP.bits());
            false
        } else {
            true
        }
    }

    fn usermem_write(&mut self, ipc: &mut IpcBuffer, start: usize, input: &[u8]) -> bool {
        let mut cursor = 0usize;
        let end = start.saturating_add(input.len());
        let mut fault = false;
        let ret = self.usermem(start, end, |_, buf, len: usize| {
            if let Err(remaining) =
                unsafe { write_user_memory(buf.as_ptr(), &input[cursor..cursor + len]) }
            {
                println!(
                    "user memory write failed @ {:p}, remaining {}/{}",
                    buf.as_ptr(),
                    remaining,
                    len
                );
                fault = true;
                return false;
            }
            cursor += len;
            true
        });

        if fault {
            self.pending_fault = true;
            return false;
        }

        if let Err(page_addr) = ret {
            self.pending_refill_address = page_addr;
            if DEBUG {
                println!(
                    "virtioserver[{}]: refill (w) @ {:#x}",
                    self_description(),
                    page_addr
                );
            }
            ipc.inner_mut()
                .seL4_Signal(CURRENT_PAGE_REFILL_NOTIF_SENDER_CAP.bits());
            false
        } else {
            true
        }
    }

    fn usermem(
        &mut self,
        start: usize,
        end: usize,
        mut cb: impl FnMut(&mut Self, NonNull<u8>, usize) -> bool,
    ) -> Result<(), usize> {
        assert!(end > start);
        // println!("usermem[{}]: {:#x} - {:#x}", self_description(), start, end);
        // do not do dynamic division
        let (start_page, end_page) = if self.remote_large_page_enabled {
            (
                start / LARGE_PAGE_SIZE,
                (end + LARGE_PAGE_SIZE - 1) / LARGE_PAGE_SIZE,
            )
        } else {
            (
                start / SMALL_PAGE_SIZE,
                (end + SMALL_PAGE_SIZE - 1) / SMALL_PAGE_SIZE,
            )
        };
        let page_size_bits = if self.remote_large_page_enabled {
            FrameObjectType::LargePage.bits()
        } else {
            FrameObjectType::_4k.bits()
        };
        for page_idx in start_page..end_page {
            let page_addr = page_idx << page_size_bits;
            let rw_start = page_addr.max(start) - page_addr;
            let rw_end = (page_addr + (1 << page_size_bits)).min(end) - page_addr;
            if rw_start == rw_end {
                continue;
            }
            assert!(rw_start < rw_end);
            let buf = self.try_lookup(page_addr).ok_or(page_addr)?;
            if !cb(self, unsafe { buf.add(rw_start) }, rw_end - rw_start) {
                break;
            }
        }
        Ok(())
    }

    fn shootdown_all(&mut self) {
        for (k, _) in core::mem::take(&mut self.remote_mappings) {
            delete_cap(
                CSPACE,
                CPtr::from_bits(REMOTE_MAPPING_CAP_RANGE.start as u64 + k),
            );
        }
        unsafe {
            core::ptr::write_bytes(&mut self.remote_mappings_idalloc.inner, 0u8, 1);
        }
    }

    fn insert_page(
        &mut self,
        ipc: &mut IpcBuffer,
        page_addr: usize,
        remote_page_cap: sel4::cap::_4k,
    ) -> Result<(), ()> {
        let selected_idx = match self.remote_mappings_idalloc.alloc() {
            Some(x) => x,
            None => {
                // shoot down everything before 1 sec ago!
                let cutoff_ts = now_cycles() - self.tsc_freq_mhz as u64 * 1_000_000;
                self.remote_mappings.retain(|k, v| {
                    if v.last_used_tsc > cutoff_ts {
                        true
                    } else {
                        assert!(self.remote_mappings_idalloc.free(*k));
                        delete_cap(
                            CSPACE,
                            CPtr::from_bits(REMOTE_MAPPING_CAP_RANGE.start as u64 + *k),
                        );
                        false
                    }
                });
                match self.remote_mappings_idalloc.alloc() {
                    Some(x) => x,
                    None => {
                        println!("WARNING: no free mapping slots after eviction, shooting down everything");
                        self.shootdown_all();
                        self.remote_mappings_idalloc.alloc().unwrap()
                    }
                }
            }
        };
        let base = if self.remote_large_page_enabled {
            self.remote_mappings_start_2m
        } else {
            self.remote_mappings_start_4k
        };
        let page_size_bits = if self.remote_large_page_enabled {
            FrameObjectType::LargePage.bits()
        } else {
            FrameObjectType::_4k.bits()
        };
        let cap_slot = REMOTE_MAPPING_CAP_RANGE.start as u64 + selected_idx as u64;
        let addr =
            unsafe { NonNull::new_unchecked(base.add((selected_idx as usize) << page_size_bits)) };
        if ipc.inner_mut().seL4_CNode_Move(
            SUBPROC_CSPACE.bits(),
            cap_slot,
            64,
            SUBPROC_CSPACE.bits(),
            remote_page_cap.bits(),
            64,
        ) != 0
            || ipc.inner_mut().seL4_X86_Page_Map(
                cap_slot,
                SUBPROC_VSPACE.bits(),
                addr.addr().get() as _,
                CapRights::read_write().into_inner(),
                VmAttributes::DEFAULT.into_inner(),
            ) != 0
        {
            delete_cap(CSPACE, remote_page_cap.cptr());
            delete_cap(CSPACE, CPtr::from_bits(cap_slot));
            assert!(self.remote_mappings_idalloc.free(selected_idx));
            return Err(());
        }
        self.remote_mappings.insert(
            selected_idx,
            RemoteMapping {
                remote_addr: page_addr as u64,
                last_used_tsc: now_cycles(),
            },
        );
        Ok(())
    }

    fn try_lookup(&mut self, page_addr: usize) -> Option<NonNull<u8>> {
        if let Some(x) = self
            .remote_mappings
            .iter_mut()
            .find(|x| x.1.remote_addr == page_addr as u64)
        {
            x.1.last_used_tsc = now_cycles();
            let base = if self.remote_large_page_enabled {
                self.remote_mappings_start_2m
            } else {
                self.remote_mappings_start_4k
            };
            let page_size_bits = if self.remote_large_page_enabled {
                FrameObjectType::LargePage.bits()
            } else {
                FrameObjectType::_4k.bits()
            };
            Some(unsafe { NonNull::new_unchecked(base.add(((*x.0) as usize) << page_size_bits)) })
        } else {
            None
        }
    }

    pub fn reset(&mut self, _ipc: &mut IpcBuffer) {
        unsafe {
            let status = addr_of_mut!((*self.common_cfg).device_status);
            status.write_volatile(0);
            assert_eq!(status.read_volatile(), 0);

            let first_region_phys = self.alloc[0].physical_base;
            let first_region_virt = self.alloc[0].virtual_base;

            for (queue_index, queue) in self.queues.iter_mut().enumerate() {
                for desc in &mut *queue.descriptor_table_4kb {
                    if desc.addr != 0 {
                        let region = self
                            .alloc
                            .iter_mut()
                            .find(|x| {
                                desc.addr as usize >= x.physical_base
                                    && (desc.addr as usize) < x.physical_base + LARGE_PAGE_SIZE
                            })
                            .expect("Failed to find region for descriptor");
                        region.allocator.free(
                            NonNull::new_unchecked(
                                (desc.addr as usize - region.physical_base + region.virtual_base)
                                    as *mut _,
                            ),
                            Layout::from_size_align(desc.len as usize, 1).unwrap(),
                        );
                        core::ptr::write(desc, VirtqDesc::default());
                    }
                }
                addr_of_mut!((*queue.avail_ring_4kb).idx).write_volatile(0);
                addr_of_mut!((*queue.used_ring_4kb).idx).write_volatile(0);
                queue.seen_used_idx = 0;
                queue.enable = false;
                core::ptr::write_bytes(&mut queue.remote, 0u8, 1);

                addr_of_mut!((*self.common_cfg).queue_select).write_volatile(queue_index as u16);
                split_write_64(
                    addr_of_mut!((*self.common_cfg).queue_desc),
                    queue.descriptor_table_4kb.addr() as u64 - first_region_virt as u64
                        + first_region_phys as u64,
                );
                split_write_64(
                    addr_of_mut!((*self.common_cfg).queue_driver),
                    queue.avail_ring_4kb.addr() as u64 - first_region_virt as u64
                        + first_region_phys as u64,
                );
                split_write_64(
                    addr_of_mut!((*self.common_cfg).queue_device),
                    queue.used_ring_4kb.addr() as u64 - first_region_virt as u64
                        + first_region_phys as u64,
                );
            }
            addr_of_mut!((*self.common_cfg).queue_select).write_volatile(0);
        }

        self.shootdown_all();

        self.pending_refill_address = core::usize::MAX;
        self.pending_fault = false;
        self.remote_selected_queue = 0;
        self.interrupt_pending = false;
    }
}

unsafe fn split_write_64(ptr: *mut u64, value: u64) {
    let ptr = ptr.cast::<u32>();
    ptr.write_volatile(value as u32);
    ptr.add(1).write_volatile((value >> 32) as u32);
}
