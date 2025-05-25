use core::{cell::RefCell, ops::Range, panic};

use algorithms::{
    pagetable::{PageTableManager, PagingService},
    unialloc::UniAllocTrait,
};
use ipc::{
    alloc::{alloc_and_retype, alloc_and_retype_with_blackhole},
    cap_blackhole::CapBlackhole,
    untyped::{UntypedCap, UntypedCapContext},
    vmmsvc::VmPagingMode,
};
use sel4::{
    CNodeCapData, CPtr, CapRights, IpcBuffer, ObjectBlueprint, ObjectBlueprintX64,
    ObjectBlueprintX86, VmAttributes,
    cap::{AsidPool, CNode, Tcb, VSpace},
    sys::seL4_SlotBits,
};

pub type VmPageTableManager = PageTableManager<ShadowedPagingStructure, 4, 9, 12>;

pub const GUEST_LOW_ADDRESS_MAPPING_END: u64 = 0x1000_0000;
pub const GUEST_HIGH_ADDRESS_MAPPING_START: u64 = 0x20_0000_0000;

#[derive(Clone, Debug)]
pub struct VmPagingConfig {
    pub identity_mapping: Range<u64>,
    pub total_memory_bytes: u64,
    pub mode: VmPagingMode,
    pub l0c: L0CNodeInfo,
}

pub struct VmPagingContext<'a> {
    pub ptm: RefCell<VmPageTableManager>,
    pub ps: RefCell<VmPagingService<'a>>,
    pub low_region: Range<u64>,
    pub high_region: Option<Range<u64>>,
}

#[derive(Copy, Clone, Debug)]
pub struct L0CNodeInfo {
    pub cnode: CNode,
    pub real_bits: u8,
    pub resolve_bits: u8,
    pub index: u64,
}

impl L0CNodeInfo {
    pub fn valid_cptr_bits(&self) -> u8 {
        64 + self.real_bits - self.resolve_bits
    }
}

pub struct VmPagingService<'a> {
    ua: &'a RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
    cspace: CNode,
    vmpml4: CPtr,
    hostpml4: VSpace,
    config: VmPagingConfig,
    blackhole: CapBlackhole<'a>,
    alloc_total: u64,
}

impl<'a> VmPagingService<'a> {
    pub fn config(&self) -> &VmPagingConfig {
        &self.config
    }

    pub fn vmpml4(&self) -> VSpace {
        VSpace::from_cptr(self.vmpml4)
    }

    pub fn blackhole(&self) -> &CapBlackhole<'a> {
        &self.blackhole
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ShadowedPagingStructure {
    pub host: CPtr,
    pub guest: CPtr,
}

impl<'a> VmPagingContext<'a> {
    pub fn new(
        ua: &'a RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
        asid_pool: AsidPool,
        tcb: Tcb,
        cspace: CNode,
        vspace: VSpace,
        mut config: VmPagingConfig,
        ipc: &mut IpcBuffer,
    ) -> Self {
        let vmpml4 = CPtr::from_bits(
            ua.borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("Failed to alloc cap"),
        );
        match config.mode {
            VmPagingMode::EptSmallPage | VmPagingMode::EptLargePage => {
                let ut = UntypedCapContext::with(ipc, cspace, |ctx| {
                    ua.borrow_mut()
                        .try_alloc(ctx, sel4::sys::seL4_X86_EPTPML4Bits as usize)
                })
                .expect("Failed to alloc ut");
                assert_eq!(
                    ipc.inner_mut().seL4_Untyped_Retype(
                        ut.cap.0.bits(),
                        sel4::sys::_object::seL4_X86_EPTPML4Object as _,
                        sel4::sys::seL4_X86_EPTPML4Bits as _,
                        cspace.bits(),
                        cspace.bits(),
                        64,
                        vmpml4.bits(),
                        1,
                    ),
                    0,
                    "Failed to retype untyped to eptpml4"
                );
            }
            VmPagingMode::Pv => {
                alloc_and_retype(
                    ipc,
                    ua,
                    cspace,
                    &ObjectBlueprint::Arch(ObjectBlueprintX86::SeL4Arch(ObjectBlueprintX64::PML4)),
                    vmpml4,
                )
                .expect("Failed to retype untyped to pml4");
            }
        }

        assert_eq!(
            ipc.inner_mut()
                .seL4_X86_ASIDPool_Assign(asid_pool.bits(), vmpml4.bits()),
            0,
            "Failed to assign VMPT root to ASID pool"
        );

        let estimated_page_caps = config
            .total_memory_bytes
            .div_ceil(config.mode.frame_object_type().bytes() as u64)
            * 2;

        // how many 2MB regions do we need for sub cnodes?
        let two_mb_cnode_bits = (21 - seL4_SlotBits) as u8;
        let num_sub_cnodes = estimated_page_caps.div_ceil(1 << two_mb_cnode_bits) as usize;
        let sub_cnodes_container_bits =
            (num_sub_cnodes.next_power_of_two().trailing_zeros() as u8).max(1);
        let sub_cnodes_container = CPtr::from_bits(
            ua.borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("Failed to alloc cap"),
        );
        alloc_and_retype(
            ipc,
            ua,
            cspace,
            &ObjectBlueprint::CNode {
                size_bits: sub_cnodes_container_bits as usize,
            },
            sub_cnodes_container,
        )
        .expect("Failed to retype untyped to sub cnodes container");
        assert_eq!(
            ipc.inner_mut().seL4_CNode_Mint(
                config.l0c.cnode.bits(),
                config.l0c.index,
                config.l0c.real_bits,
                cspace.bits(),
                sub_cnodes_container.bits(),
                64,
                CapRights::read_write().into_inner(),
                CNodeCapData::new(
                    0,
                    (64 - config.l0c.resolve_bits - sub_cnodes_container_bits - two_mb_cnode_bits)
                        as usize,
                )
                .into_word(),
            ),
            0
        );

        for i in 0..num_sub_cnodes {
            let sub_cnode = CPtr::from_bits(
                ua.borrow_mut()
                    .get_capalloc()
                    .alloc()
                    .expect("Failed to alloc cap"),
            );
            alloc_and_retype(
                ipc,
                ua,
                cspace,
                &ObjectBlueprint::CNode {
                    size_bits: two_mb_cnode_bits as usize,
                },
                sub_cnode,
            )
            .expect("Failed to retype untyped to sub cnode");
            assert_eq!(
                ipc.inner_mut().seL4_CNode_Move(
                    sub_cnodes_container.bits(),
                    i as u64,
                    sub_cnodes_container_bits,
                    cspace.bits(),
                    sub_cnode.bits(),
                    64,
                ),
                0
            );
            assert!(ua.borrow_mut().get_capalloc().free(sub_cnode.bits()));
        }

        println!("mapped {} sub cnodes", num_sub_cnodes);

        let mut ptm: VmPageTableManager = PageTableManager::new();
        // cap overhead + paging overhead
        config.total_memory_bytes = config
            .total_memory_bytes
            .saturating_sub((num_sub_cnodes << 21) as u64)
            * 995
            / 1000;
        if config.total_memory_bytes == 0 {
            panic!("Not enough memory for VM");
        }
        println!("{} bytes available for VM", config.total_memory_bytes);

        let mut ept_ps = VmPagingService {
            ua: ua,
            cspace,
            vmpml4: vmpml4,
            hostpml4: vspace,
            config,
            blackhole: CapBlackhole::new(ipc, cspace, ua),
            alloc_total: 0,
        };

        let mut alloc_total = 0u64;
        let mut low_end = 0u64;
        let mut high_end = GUEST_HIGH_ADDRESS_MAPPING_START;
        let mut buffered_alloc = BufferedAlloc {
            current_2mb_untyped: CPtr::from_bits(0),
            remaining_frames: 0,
            cap_offset: ept_ps.config.l0c.index << (64 - ept_ps.config.l0c.resolve_bits),
            sub_cnodes_container: CNode::from_cptr(sub_cnodes_container),
            sub_cnodes_container_bits,
        };
        loop {
            let blueprint = match ept_ps.config.mode {
                VmPagingMode::EptSmallPage | VmPagingMode::Pv => {
                    ObjectBlueprint::Arch(ObjectBlueprintX86::_4k)
                }
                VmPagingMode::EptLargePage => ObjectBlueprint::Arch(ObjectBlueprintX86::LargePage),
            };
            let size = 1u64 << blueprint.physical_size_bits();
            if alloc_total + size > ept_ps.config.total_memory_bytes {
                break;
            }

            let high = alloc_total >= GUEST_LOW_ADDRESS_MAPPING_END;

            let guest_phys = if high {
                alloc_total - GUEST_LOW_ADDRESS_MAPPING_END + GUEST_HIGH_ADDRESS_MAPPING_START
            } else {
                alloc_total
            };

            let pt_level = match ept_ps.config.mode {
                VmPagingMode::EptSmallPage | VmPagingMode::Pv => 3,
                VmPagingMode::EptLargePage => 2,
            };
            buffered_alloc.alloc_pair(
                ipc,
                &mut ptm,
                &mut ept_ps,
                pt_level,
                guest_phys,
                blueprint,
                |ipc, ept_ps: &mut VmPagingService, idmap_page: CPtr| {
                    assert_eq!(
                        ipc.inner_mut().seL4_X86_Page_Map(
                            idmap_page.bits(),
                            ept_ps.hostpml4.bits(),
                            ept_ps.config.identity_mapping.start + guest_phys,
                            CapRights::read_write().into_inner(),
                            VmAttributes::DEFAULT.into_inner()
                        ),
                        0
                    );
                },
            );
            alloc_total += size;
            if high {
                high_end = guest_phys + size;
            } else {
                low_end = guest_phys + size;
            }
        }
        println!(
            "Mapped {}MB out of {} bytes to [0, {:#x}), [{:#x}, {:#x})",
            alloc_total / (1024 * 1024),
            ept_ps.config.total_memory_bytes,
            low_end,
            GUEST_HIGH_ADDRESS_MAPPING_START,
            high_end
        );
        ept_ps.alloc_total = alloc_total;

        if !matches!(ept_ps.config.mode, VmPagingMode::Pv) {
            assert_eq!(
                ipc.inner_mut()
                    .seL4_TCB_SetEPTRoot(tcb.bits(), vmpml4.bits()),
                0,
                "Failed to set EPT root for TCB"
            );
        }

        VmPagingContext {
            ptm: RefCell::new(ptm),
            ps: RefCell::new(ept_ps),
            low_region: 0u64..low_end,
            high_region: if high_end == GUEST_HIGH_ADDRESS_MAPPING_START {
                None
            } else {
                Some(GUEST_HIGH_ADDRESS_MAPPING_START..high_end)
            },
        }
    }
}
impl<'a> PagingService<ShadowedPagingStructure> for VmPagingService<'a> {
    type Context = IpcBuffer;

    fn ps_alloc(&mut self, ipc: &mut IpcBuffer, level: u8) -> ShadowedPagingStructure {
        let mut alloc_it = |guest_bits: u64,
                            guest_object_type: u64,
                            host_blueprint: ObjectBlueprint|
         -> ShadowedPagingStructure {
            let host = CPtr::from_bits(
                self.ua
                    .borrow_mut()
                    .get_capalloc()
                    .alloc()
                    .expect("Failed to alloc cap"),
            );
            let guest = if matches!(self.config.mode, VmPagingMode::Pv) {
                CPtr::from_bits(0)
            } else {
                CPtr::from_bits(
                    self.ua
                        .borrow_mut()
                        .get_capalloc()
                        .alloc()
                        .expect("Failed to alloc cap"),
                )
            };

            if !matches!(self.config.mode, VmPagingMode::Pv) {
                let mut dead_caps = heapless::Vec::new();
                let guest_ut = UntypedCapContext::with(ipc, self.cspace, |ctx| {
                    self.ua
                        .borrow_mut()
                        .try_alloc_recycling_caps(ctx, guest_bits as usize, Some(&mut dead_caps))
                        .expect("Failed to alloc guest ut")
                });
                assert_eq!(
                    ipc.inner_mut().seL4_Untyped_Retype(
                        guest_ut.cap.0.bits(),
                        guest_object_type,
                        guest_bits,
                        self.cspace.bits(),
                        self.cspace.bits(),
                        64,
                        guest.bits(),
                        1,
                    ),
                    0,
                    "Failed to retype untyped"
                );
                for x in dead_caps {
                    self.blackhole.dispose_and_free(ipc, CPtr::from_bits(x));
                }
                self.blackhole.dispose_and_free(ipc, guest_ut.cap.0.cptr());
            }

            let host_ut = alloc_and_retype_with_blackhole(
                ipc,
                self.ua,
                self.cspace,
                &host_blueprint,
                host,
                Some(&self.blackhole),
            )
            .expect("Failed to alloc host ut");
            self.blackhole.dispose_and_free(ipc, host_ut.cap.0.cptr());
            ShadowedPagingStructure { host, guest }
        };
        match level {
            1 => alloc_it(
                sel4::sys::seL4_X86_EPTPDPTBits.into(),
                sel4::sys::_object::seL4_X86_EPTPDPTObject.into(),
                ObjectBlueprint::Arch(ObjectBlueprintX86::SeL4Arch(ObjectBlueprintX64::PDPT)),
            ),
            2 => alloc_it(
                sel4::sys::seL4_X86_EPTPDBits.into(),
                sel4::sys::_object::seL4_X86_EPTPDObject.into(),
                ObjectBlueprint::Arch(ObjectBlueprintX86::PageDirectory),
            ),
            3 => alloc_it(
                sel4::sys::seL4_X86_EPTPTBits.into(),
                sel4::sys::_object::seL4_X86_EPTPTObject.into(),
                ObjectBlueprint::Arch(ObjectBlueprintX86::PageTable),
            ),
            _ => unreachable!(),
        }
    }

    fn ps_map(&mut self, ipc: &mut IpcBuffer, cap: &ShadowedPagingStructure, addr: u64, level: u8) {
        if false {
            println!(
                "ps_map: level {}, addr {:#x}, host {:#x}, guest {:#x}",
                level,
                addr,
                cap.host.bits(),
                cap.guest.bits()
            );
        }
        match level {
            1 => {
                let size = 512 * 1024 * 1024 * 1024;
                assert!(addr & (size - 1) == 0);
                assert!(addr + size >= addr);
                assert!(
                    addr + size
                        <= self.config.identity_mapping.end - self.config.identity_mapping.start
                );

                if !matches!(self.config.mode, VmPagingMode::Pv) {
                    assert_eq!(
                        ipc.inner_mut().seL4_X86_EPTPDPT_Map(
                            cap.guest.bits(),
                            self.vmpml4.bits(),
                            addr,
                            sel4::sys::seL4_X86_EPT_VMAttributes::seL4_X86_EPT_Default_VMAttributes,
                        ),
                        0,
                        "Failed to map eptpdpt to eptpml4"
                    );
                    self.blackhole.dispose_and_free(ipc, cap.guest);
                }

                assert_eq!(
                    ipc.inner_mut().seL4_X86_PDPT_Map(
                        cap.host.bits(),
                        self.hostpml4.bits(),
                        self.config.identity_mapping.start + addr,
                        VmAttributes::DEFAULT.into_inner(),
                    ),
                    0
                );
                self.blackhole.dispose_and_free(ipc, cap.host);
            }
            2 => {
                let size = 1024 * 1024 * 1024;
                assert!(addr & (size - 1) == 0);
                assert!(addr + size >= addr);
                assert!(
                    addr + size
                        <= self.config.identity_mapping.end - self.config.identity_mapping.start
                );
                if !matches!(self.config.mode, VmPagingMode::Pv) {
                    assert_eq!(
                        ipc.inner_mut().seL4_X86_EPTPD_Map(
                            cap.guest.bits(),
                            self.vmpml4.bits(),
                            addr,
                            sel4::sys::seL4_X86_EPT_VMAttributes::seL4_X86_EPT_Default_VMAttributes,
                        ),
                        0,
                        "Failed to map eptpd to eptpml4"
                    );
                    self.blackhole.dispose_and_free(ipc, cap.guest);
                }

                assert_eq!(
                    ipc.inner_mut().seL4_X86_PageDirectory_Map(
                        cap.host.bits(),
                        self.hostpml4.bits(),
                        self.config.identity_mapping.start + addr,
                        VmAttributes::DEFAULT.into_inner(),
                    ),
                    0
                );
                self.blackhole.dispose_and_free(ipc, cap.host);
            }
            3 => {
                let size = 2 * 1024 * 1024;
                assert!(addr & (size - 1) == 0);
                assert!(addr + size >= addr);
                assert!(
                    addr + size
                        <= self.config.identity_mapping.end - self.config.identity_mapping.start
                );
                if !matches!(self.config.mode, VmPagingMode::Pv) {
                    assert_eq!(
                        ipc.inner_mut().seL4_X86_EPTPT_Map(
                            cap.guest.bits(),
                            self.vmpml4.bits(),
                            addr,
                            sel4::sys::seL4_X86_EPT_VMAttributes::seL4_X86_EPT_Default_VMAttributes,
                        ),
                        0,
                        "Failed to map eptpt to eptpml4"
                    );
                    self.blackhole.dispose_and_free(ipc, cap.guest);
                }

                assert_eq!(
                    ipc.inner_mut().seL4_X86_PageTable_Map(
                        cap.host.bits(),
                        self.hostpml4.bits(),
                        self.config.identity_mapping.start + addr,
                        VmAttributes::DEFAULT.into_inner(),
                    ),
                    0
                );
                self.blackhole.dispose_and_free(ipc, cap.host);
            }
            _ => unreachable!(),
        }
    }

    fn ps_unmap(&mut self, _ipc: &mut IpcBuffer, _cap: &ShadowedPagingStructure) {
        todo!()
    }

    fn ps_free(&mut self, _ipc: &mut IpcBuffer, _cap: &ShadowedPagingStructure) {
        todo!()
    }

    fn ps_guest_phys_to_page_cap(&self, guest_phys: u64) -> Option<(u64, u64, u8)> {
        let linear = if guest_phys >= GUEST_HIGH_ADDRESS_MAPPING_START {
            guest_phys - GUEST_HIGH_ADDRESS_MAPPING_START + GUEST_LOW_ADDRESS_MAPPING_END
        } else {
            guest_phys
        } as usize;
        if linear >= self.alloc_total as usize {
            return None;
        }
        let index = linear >> self.config.mode.frame_object_type().bits();
        let cptr =
            (self.config.l0c.index << (64 - self.config.l0c.resolve_bits)) + index as u64 * 2;
        let depth = 64 + self.config.l0c.real_bits - self.config.l0c.resolve_bits;
        Some((self.config.l0c.cnode.bits(), cptr, depth))
    }
}

struct BufferedAlloc {
    current_2mb_untyped: CPtr,
    remaining_frames: u32,
    cap_offset: u64,
    sub_cnodes_container: CNode,
    sub_cnodes_container_bits: u8,
}

impl BufferedAlloc {
    fn alloc_pair(
        &mut self,
        ipc: &mut IpcBuffer,
        ptm: &mut VmPageTableManager,
        ps: &mut VmPagingService,
        level: u8,
        guest_phys: u64,
        blueprint: ObjectBlueprint,
        do_idmap: impl FnOnce(&mut IpcBuffer, &mut VmPagingService, CPtr),
    ) -> CPtr {
        let required_frames: u32 = match blueprint {
            ObjectBlueprint::Arch(ObjectBlueprintX86::LargePage) => 512,
            ObjectBlueprint::Arch(ObjectBlueprintX86::_4k) => 1,
            _ => panic!("Unsupported blueprint"),
        };
        if self.remaining_frames < required_frames {
            if self.current_2mb_untyped.bits() != 0 {
                ps.blackhole.dispose_and_free(ipc, self.current_2mb_untyped);
            }
            let ut = UntypedCapContext::with(ipc, ps.cspace, |ctx| {
                ps.ua
                    .borrow_mut()
                    .try_alloc(ctx, 21)
                    .expect("Failed to alloc untyped")
            });
            self.current_2mb_untyped = ut.cap.0.cptr();
            // println!(
            //     "allocating 2MB untyped {:#x}, guest_phys {:#x}",
            //     self.current_2mb_untyped.bits(),
            //     guest_phys,
            // );
            self.remaining_frames = 512;
        }
        let guest_page = CPtr::from_bits(self.cap_offset);
        self.cap_offset += 1;
        let index_bits = (21 - seL4_SlotBits) as u8;
        // println!(
        //     "page retype: index_bits {}, cptr {:#x}",
        //     index_bits,
        //     guest_page.bits(),
        // );
        let ret = ipc.inner_mut().seL4_Untyped_Retype(
            self.current_2mb_untyped.bits(),
            blueprint.ty().into_sys() as u64,
            0,
            self.sub_cnodes_container.bits(),
            guest_page.bits() >> index_bits,
            self.sub_cnodes_container_bits as _,
            guest_page.bits() & ((1 << index_bits) - 1),
            1,
        );
        assert_eq!(ret, 0, "Failed to retype untyped in alloc_pair");
        self.remaining_frames -= required_frames;
        ptm.allocate(ipc, guest_phys, level, ps)
            .expect("Failed to allocate paging structures");
        let idmap_page = if matches!(
            ps.config.mode,
            VmPagingMode::EptLargePage | VmPagingMode::EptSmallPage
        ) {
            let idmap_page = CPtr::from_bits(self.cap_offset);
            self.cap_offset += 1;
            assert_eq!(
                ipc.inner_mut().seL4_CNode_Copy(
                    self.sub_cnodes_container.bits(),
                    idmap_page.bits(),
                    self.sub_cnodes_container_bits + index_bits,
                    self.sub_cnodes_container.bits(),
                    guest_page.bits(),
                    self.sub_cnodes_container_bits + index_bits,
                    CapRights::read_write().into_inner(),
                ),
                0
            );
            assert_eq!(
                ipc.inner_mut().seL4_X86_Page_MapEPT(
                    guest_page.bits(),
                    ps.vmpml4.bits(),
                    guest_phys,
                    CapRights::read_write().into_inner(),
                    sel4::sys::seL4_X86_EPT_VMAttributes::seL4_X86_EPT_Default_VMAttributes,
                ),
                0,
                "Failed to map page to eptpml4"
            );
            idmap_page
        } else {
            self.cap_offset += 1;
            guest_page
        };

        do_idmap(ipc, ps, idmap_page);
        guest_page
    }
}
