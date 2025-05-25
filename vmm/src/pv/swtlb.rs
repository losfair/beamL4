use core::{
    cell::{Cell, RefCell},
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering},
};

use algorithms::{pagetable::PagingService, unialloc::UniAllocTrait};
use intrusive_collections::{
    KeyAdapter, LinkedList, LinkedListAtomicLink, RBTree, RBTreeAtomicLink, intrusive_adapter,
};
use ipc::{
    alloc::alloc_and_retype_with_blackhole,
    cap_blackhole::CapBlackhole,
    untyped::{UntypedCap, UntypedCapContext},
};
use sel4::{
    CNodeCapData, CPtr, CapRights, IpcBuffer, ObjectBlueprint, ObjectBlueprintX64,
    ObjectBlueprintX86, VmAttributes,
    cap::{CNode, PML4},
};

use crate::paging::L0CNodeInfo;

use super::ptw::PageTableWalker;

const PAGE_SIZE: usize = 4096; // 4 KiB
const PT_COVERAGE: usize = 512 * PAGE_SIZE; // 2 MiB (512 pages per PT)
const PD_COVERAGE: usize = 512 * PT_COVERAGE; // 1 GiB (512 PTs per PD)
const PDPT_COVERAGE: usize = 512 * PD_COVERAGE; // 512 GiB (512 PDs per PDPT)
pub const GUEST_TOP: u64 = 0x7f80_0000_0000; // reserve the topmost pdpt

const MAX_ACTIVE_COUNTERS: [usize; 4] = [512, 512, 2048, 16384];
const TOTAL_PAGING_STRUCTURES: usize = const_sum(MAX_ACTIVE_COUNTERS);
const SUB_CNODE_BITS: u8 = TOTAL_PAGING_STRUCTURES.next_power_of_two().trailing_zeros() as u8;

static mut PAGING_STRUCTURES: [MaybeUninit<SwtlbPagingStructure>; TOTAL_PAGING_STRUCTURES] =
    [const { MaybeUninit::uninit() }; TOTAL_PAGING_STRUCTURES];
static NEXT_PAGING_STRUCTURE: AtomicUsize = AtomicUsize::new(0);

const fn const_sum<const N: usize>(arr: [usize; N]) -> usize {
    let mut sum = 0;
    let mut i = 0usize;
    while i < N {
        sum += arr[i];
        i += 1;
    }
    sum
}

fn alloc_paging_structure(x: SwtlbPagingStructure) -> &'static SwtlbPagingStructure {
    let idx = NEXT_PAGING_STRUCTURE.fetch_add(1, Ordering::Relaxed);
    assert!(idx < TOTAL_PAGING_STRUCTURES);
    unsafe { PAGING_STRUCTURES[idx].write(x) }
}

pub struct Swtlb {
    // PDPT, PD, PT
    pools: [LinkedList<SwtlbPagingStructurePoolAdapter>; 3],
    leaf_pool: LinkedList<SwtlbPagingStructurePoolAdapter>,
    active_counters: [u64; 4],
    pml4: &'static SwtlbPagingStructure,
    syscall_counter: u64,
    l0c: L0CNodeInfo,
    blackhole: CapBlackhole<'static>,
    cap_offset: u64,
}

pub struct SwtlbPagingStructure {
    pool_link: LinkedListAtomicLink,
    child_link: RBTreeAtomicLink,
    child_index: Cell<u16>,
    cap: CPtr,
    children: RefCell<RBTree<SwtlbPagingStructureChildAdapter>>,
}

#[derive(Copy, Clone, Debug)]
pub enum WriteProtect {
    Enable,
    Ignore,
}

intrusive_adapter!(SwtlbPagingStructurePoolAdapter = &'static SwtlbPagingStructure: SwtlbPagingStructure { pool_link: LinkedListAtomicLink });
intrusive_adapter!(SwtlbPagingStructureChildAdapter = &'static SwtlbPagingStructure: SwtlbPagingStructure { child_link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for SwtlbPagingStructureChildAdapter {
    type Key = u16;

    fn get_key(&self, value: &'a SwtlbPagingStructure) -> Self::Key {
        value.child_index.get()
    }
}

impl Swtlb {
    pub fn new(
        ipc: &mut IpcBuffer,
        pml4cap: PML4,
        ua: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
        blackhole: CapBlackhole<'static>,
        l0c: L0CNodeInfo,
    ) -> Self {
        let pml4 = alloc_paging_structure(SwtlbPagingStructure {
            pool_link: LinkedListAtomicLink::new(),
            child_link: RBTreeAtomicLink::new(),
            child_index: Cell::new(0),
            cap: pml4cap.cptr(),
            children: RefCell::new(RBTree::new(SwtlbPagingStructureChildAdapter::new())),
        });
        let pools = [
            LinkedList::new(SwtlbPagingStructurePoolAdapter::new()),
            LinkedList::new(SwtlbPagingStructurePoolAdapter::new()),
            LinkedList::new(SwtlbPagingStructurePoolAdapter::new()),
        ];
        let cap_offset = l0c.index << (64 - l0c.resolve_bits);

        let sub_cnode =
            CNode::from_bits(ua.borrow_mut().get_capalloc().alloc().expect("alloc cap"));
        let ut = alloc_and_retype_with_blackhole(
            ipc,
            ua,
            blackhole.cspace,
            &ObjectBlueprint::CNode {
                size_bits: SUB_CNODE_BITS as usize,
            },
            sub_cnode.cptr(),
            Some(&blackhole),
        )
        .expect("alloc_and_retype failed");
        assert_eq!(
            ipc.inner_mut().seL4_CNode_Mutate(
                l0c.cnode.bits(),
                l0c.index,
                l0c.real_bits,
                blackhole.cspace.bits(),
                sub_cnode.bits(),
                64,
                CNodeCapData::new(0, (64 - l0c.resolve_bits - SUB_CNODE_BITS).into()).into_word(),
            ),
            0
        );
        assert!(ua.borrow_mut().get_capalloc().free(sub_cnode.bits()));
        blackhole.dispose_and_free(ipc, ut.cap.0.cptr());

        Self {
            pools,
            leaf_pool: LinkedList::new(SwtlbPagingStructurePoolAdapter::new()),
            active_counters: [0; 4],
            pml4,
            syscall_counter: 0,
            l0c,
            blackhole,
            cap_offset,
        }
    }

    pub fn syscall_counter(&self) -> u64 {
        self.syscall_counter
    }

    pub fn populate(
        &mut self,
        ipc: &mut IpcBuffer,
        ua: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
        ptw: &PageTableWalker,
        va: usize,
        wp: WriteProtect,
    ) -> bool {
        assert!(va & (PAGE_SIZE - 1) == 0);
        let Some(end_va) = va.checked_add(PAGE_SIZE) else {
            return false;
        };
        if end_va > GUEST_TOP as usize {
            return false;
        }

        let Some((guest_phys, rights)) = ptw.try_lookup_guest_phys(va) else {
            return false;
        };
        let rights = match wp {
            WriteProtect::Enable => rights,
            WriteProtect::Ignore => CapRights::read_write(),
        };

        if self
            .active_counters
            .iter()
            .zip(MAX_ACTIVE_COUNTERS)
            .any(|(a, m)| *a >= m as u64)
        {
            println!("will overflow, flushing swtlb: {:?}", self.active_counters);
            self.shootdown(ipc, ua, 0, GUEST_TOP as usize);
            assert_eq!(self.active_counters, [0; 4]);
        }

        let parent = self.pml4;
        let n = va / PDPT_COVERAGE;
        assert!(n < 512);
        let parent = parent
            .children
            .borrow_mut()
            .entry(&(n as u16))
            .or_insert_with(|| {
                let ps = self.pools[0].pop_front().unwrap_or_else(|| {
                    SwtlbPagingStructure::alloc(
                        ipc,
                        ua,
                        self.l0c,
                        &self.blackhole,
                        &mut self.cap_offset,
                        ObjectBlueprint::Arch(ObjectBlueprintX86::SeL4Arch(
                            ObjectBlueprintX64::PDPT,
                        )),
                    )
                });
                ps.child_index.set(n as u16);
                assert_eq!(
                    ipc.inner_mut().seL4_X86_PDPT_Map(
                        ps.cap.bits(),
                        self.pml4.cap.bits(),
                        (va & !(PDPT_COVERAGE - 1)) as u64,
                        VmAttributes::DEFAULT.into_inner(),
                    ),
                    0
                );
                self.active_counters[0] += 1;
                ps
            })
            .as_cursor()
            .clone_pointer()
            .unwrap();

        let n = (va % PDPT_COVERAGE) / PD_COVERAGE;
        assert!(n < 512);
        let parent = parent
            .children
            .borrow_mut()
            .entry(&(n as u16))
            .or_insert_with(|| {
                let ps = self.pools[1].pop_front().unwrap_or_else(|| {
                    SwtlbPagingStructure::alloc(
                        ipc,
                        ua,
                        self.l0c,
                        &self.blackhole,
                        &mut self.cap_offset,
                        ObjectBlueprint::Arch(ObjectBlueprintX86::PageDirectory),
                    )
                });
                ps.child_index.set(n as u16);
                assert_eq!(
                    ipc.inner_mut().seL4_X86_PageDirectory_Map(
                        ps.cap.bits(),
                        self.pml4.cap.bits(),
                        (va & !(PD_COVERAGE - 1)) as u64,
                        VmAttributes::DEFAULT.into_inner(),
                    ),
                    0
                );
                self.active_counters[1] += 1;
                ps
            })
            .as_cursor()
            .clone_pointer()
            .unwrap();

        let n = (va % PD_COVERAGE) / PT_COVERAGE;
        assert!(n < 512);
        let parent = parent
            .children
            .borrow_mut()
            .entry(&(n as u16))
            .or_insert_with(|| {
                let ps = self.pools[2].pop_front().unwrap_or_else(|| {
                    SwtlbPagingStructure::alloc(
                        ipc,
                        ua,
                        self.l0c,
                        &self.blackhole,
                        &mut self.cap_offset,
                        ObjectBlueprint::Arch(ObjectBlueprintX86::PageTable),
                    )
                });
                ps.child_index.set(n as u16);
                assert_eq!(
                    ipc.inner_mut().seL4_X86_PageTable_Map(
                        ps.cap.bits(),
                        self.pml4.cap.bits(),
                        (va & !(PT_COVERAGE - 1)) as u64,
                        VmAttributes::DEFAULT.into_inner(),
                    ),
                    0
                );
                self.active_counters[2] += 1;
                ps
            })
            .as_cursor()
            .clone_pointer()
            .unwrap();

        let n = (va % PT_COVERAGE) / PAGE_SIZE;
        assert!(n < 512);
        parent
            .children
            .borrow_mut()
            .entry(&(n as u16))
            .or_insert_with(|| {
                let ps = self.leaf_pool.pop_front().unwrap_or_else(|| {
                    let cap = CPtr::from_bits(self.cap_offset);
                    self.cap_offset += 1;
                    alloc_paging_structure(SwtlbPagingStructure {
                        pool_link: LinkedListAtomicLink::new(),
                        child_link: RBTreeAtomicLink::new(),
                        child_index: Cell::new(0xffff),
                        cap,
                        children: RefCell::new(
                            RBTree::new(SwtlbPagingStructureChildAdapter::new()),
                        ),
                    })
                });
                ps.child_index.set(n as u16);

                let page_cap = ptw
                    .paging
                    .ps
                    .borrow()
                    .ps_guest_phys_to_page_cap(guest_phys)
                    .unwrap_or_else(|| {
                        panic!("failed to get page cap from guest phys: {:#x}", guest_phys)
                    });
                assert_eq!(
                    ipc.inner_mut().seL4_CNode_Copy(
                        self.l0c.cnode.bits(),
                        ps.cap.bits(),
                        self.l0c.valid_cptr_bits(),
                        page_cap.0,
                        page_cap.1,
                        page_cap.2,
                        rights.clone().into_inner(),
                    ),
                    0
                );
                assert_eq!(
                    ipc.inner_mut().seL4_X86_Page_Map(
                        ps.cap.bits(),
                        self.pml4.cap.bits(),
                        va as u64,
                        rights.into_inner(),
                        VmAttributes::DEFAULT.into_inner(),
                    ),
                    0
                );
                self.active_counters[3] += 1;
                // println!("populate: {:#x} -> phys:{:#x}", va as u64, guest_phys);
                ps
            });
        true
    }

    pub fn shootdown(
        &mut self,
        ipc: &mut IpcBuffer,
        ua: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
        start_va: usize,
        end_va: usize,
    ) {
        // println!("shootdown: {:#x} - {:#x}", start_va, end_va);
        let mut va = start_va;
        while va < end_va {
            let parent = self.pml4;

            let n = va / PDPT_COVERAGE;
            assert!(n < 512);
            if va & (PDPT_COVERAGE - 1) == 0 && va + PDPT_COVERAGE <= end_va {
                let child = parent.children.borrow_mut().find_mut(&(n as u16)).remove();
                if let Some(child) = child {
                    self.repool(ipc, ua, child, 0);
                }
                va += PDPT_COVERAGE;
                continue;
            }
            let parent_pdpt = match parent.children.borrow().find(&(n as u16)).clone_pointer() {
                Some(x) => x,
                None => {
                    va += PAGE_SIZE;
                    continue;
                }
            };

            let n = (va % PDPT_COVERAGE) / PD_COVERAGE;
            assert!(n < 512);
            if va & (PD_COVERAGE - 1) == 0 && va + PD_COVERAGE <= end_va {
                let child = parent_pdpt
                    .children
                    .borrow_mut()
                    .find_mut(&(n as u16))
                    .remove();
                if let Some(child) = child {
                    self.repool(ipc, ua, child, 1);
                }
                va += PD_COVERAGE;
                continue;
            }
            let parent_pd = match parent_pdpt
                .children
                .borrow()
                .find(&(n as u16))
                .clone_pointer()
            {
                Some(x) => x,
                None => {
                    va += PAGE_SIZE;
                    continue;
                }
            };

            let n = (va % PD_COVERAGE) / PT_COVERAGE;
            assert!(n < 512);
            if va & (PT_COVERAGE - 1) == 0 && va + PT_COVERAGE <= end_va {
                let child = parent_pd
                    .children
                    .borrow_mut()
                    .find_mut(&(n as u16))
                    .remove();
                if let Some(child) = child {
                    self.repool(ipc, ua, child, 2);
                }
                va += PT_COVERAGE;
                continue;
            }
            let parent_pt = match parent_pd
                .children
                .borrow()
                .find(&(n as u16))
                .clone_pointer()
            {
                Some(x) => x,
                None => {
                    va += PAGE_SIZE;
                    continue;
                }
            };
            let n = (va % PT_COVERAGE) / PAGE_SIZE;
            assert!(n < 512);
            let Some(leaf) = parent_pt
                .children
                .borrow_mut()
                .find_mut(&(n as u16))
                .remove()
            else {
                va += PAGE_SIZE;
                continue;
            };
            self.repool(ipc, ua, leaf, 3);

            if parent_pt.children.borrow().is_empty() {
                parent_pd
                    .children
                    .borrow_mut()
                    .find_mut(&(parent_pt.child_index.get()))
                    .remove();
                // println!("repooling PT @ {:#x}", va & !(PT_COVERAGE - 1));
                self.repool(ipc, ua, parent_pt, 2);
            }

            if parent_pd.children.borrow().is_empty() {
                parent_pdpt
                    .children
                    .borrow_mut()
                    .find_mut(&(parent_pd.child_index.get()))
                    .remove();
                // println!("repooling PD @ {:#x}", va & !(PD_COVERAGE - 1));
                self.repool(ipc, ua, parent_pd, 1);
            }

            va += PAGE_SIZE;
        }
    }

    fn repool(
        &mut self,
        ipc: &mut IpcBuffer,
        ua: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
        ps: &'static SwtlbPagingStructure,
        level: u8,
    ) {
        self.syscall_counter += 1;
        assert!(self.active_counters[level as usize] > 0);
        self.active_counters[level as usize] -= 1;
        if level == 3 {
            // leaf
            // cap can be reused
            assert_eq!(
                ipc.inner_mut().seL4_CNode_Delete(
                    self.l0c.cnode.bits(),
                    ps.cap.bits(),
                    self.l0c.valid_cptr_bits()
                ),
                0
            );
            self.leaf_pool.push_back(ps);
        } else {
            let ret = match level {
                0 => ipc.inner_mut().seL4_X86_PDPT_Unmap(ps.cap.bits()),
                1 => ipc.inner_mut().seL4_X86_PageDirectory_Unmap(ps.cap.bits()),
                2 => ipc.inner_mut().seL4_X86_PageTable_Unmap(ps.cap.bits()),
                _ => unreachable!(),
            };
            assert_eq!(ret, 0, "failed to unmap paging structure");
            let children = core::mem::take(&mut *ps.children.borrow_mut());
            self.pools[level as usize].push_back(ps);
            for child in children {
                self.repool(ipc, ua, child, level + 1);
            }
        }
    }
}

impl SwtlbPagingStructure {
    fn alloc(
        ipc: &mut IpcBuffer,
        ua: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
        l0c: L0CNodeInfo,
        blackhole: &CapBlackhole<'static>,
        cap_offset: &mut u64,
        blueprint: ObjectBlueprint,
    ) -> &'static Self {
        let cap = CPtr::from_bits(*cap_offset);
        *cap_offset += 1;

        let mut dead_caps = heapless::Vec::new();
        let ut = UntypedCapContext::with(ipc, blackhole.cspace, |ctx| {
            ua.borrow_mut().try_alloc_recycling_caps(
                ctx,
                blueprint.physical_size_bits(),
                Some(&mut dead_caps),
            )
        })
        .expect("alloc failed");
        for x in dead_caps {
            blackhole.dispose_and_free(ipc, CPtr::from_bits(x));
        }
        assert_eq!(
            ipc.inner_mut().seL4_Untyped_Retype(
                ut.cap.0.bits(),
                blueprint.ty().into_sys().into(),
                blueprint.api_size_bits().unwrap_or_default() as _,
                l0c.cnode.bits(),
                l0c.index,
                l0c.real_bits.into(),
                cap.bits() & ((1 << SUB_CNODE_BITS) - 1),
                1,
            ),
            0
        );
        blackhole.dispose_and_free(ipc, ut.cap.0.cptr());
        alloc_paging_structure(SwtlbPagingStructure {
            pool_link: LinkedListAtomicLink::new(),
            child_link: RBTreeAtomicLink::new(),
            child_index: Cell::new(0xffff),
            cap,
            children: RefCell::new(RBTree::new(SwtlbPagingStructureChildAdapter::new())),
        })
    }
}
