use core::{cell::RefCell, ptr::NonNull};

use crate::{alloc::alloc_and_retype, untyped::UntypedCap};
use algorithms::{
    idalloc::{IdAlloc64, IdAlloc64OffsetLimit, IdAlloc64Trait},
    pagetable::{PageTableManager, PagingService},
    unialloc::{UniAllocTrait, UntypedInfoAdapter},
};
use alloc_::sync::Arc;
use intrusive_collections::LinkedList;
use sel4::{
    cap::{CNode, VSpace},
    CPtr, FrameObjectType, IpcBuffer, ObjectBlueprint, ObjectBlueprintX64, ObjectBlueprintX86,
    VmAttributes,
};

pub const SMALL_PAGE_SIZE_BITS: usize = FrameObjectType::GRANULE.bits();

pub type HostPageTableManager = PageTableManager<HostPagingStructure, 4, 9, 12>;

pub struct HostPagingContext<'a> {
    inner: RefCell<HostPagingContextInner<'a>>,
}

struct HostPagingContextInner<'a> {
    ptm: HostPageTableManager,
    ps: HostPagingService<'a>,
    bitmap: IdAlloc64OffsetLimit<IdAlloc64<2>>,
}

pub struct HostPagingService<'a> {
    pub alloc: &'a RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
    pub cspace: CNode,
    pub hostpml4: VSpace,
    pub skip_pdpt: bool,
    pub utlist: LinkedList<UntypedInfoAdapter<UntypedCap>>,
}

#[derive(Clone, Copy, Debug)]
pub struct HostPagingStructure {
    pub cap: CPtr,
}

impl<'a> PagingService<HostPagingStructure> for HostPagingService<'a> {
    type Context = IpcBuffer;

    fn ps_alloc(&mut self, ipc: &mut IpcBuffer, level: u8) -> HostPagingStructure {
        let mut alloc_it = |host_blueprint: ObjectBlueprint| -> HostPagingStructure {
            let cap = CPtr::from_bits(
                self.alloc
                    .borrow_mut()
                    .get_capalloc()
                    .alloc()
                    .expect("alloc failed"),
            );
            let ut = alloc_and_retype(ipc, self.alloc, self.cspace, &host_blueprint, cap)
                .expect("alloc_and_retype failed");
            self.utlist.push_back(Arc::new(ut));
            HostPagingStructure { cap }
        };
        match level {
            1 => {
                if !self.skip_pdpt {
                    alloc_it(ObjectBlueprint::Arch(ObjectBlueprintX86::SeL4Arch(
                        ObjectBlueprintX64::PDPT,
                    )))
                } else {
                    HostPagingStructure {
                        cap: CPtr::from_bits(0),
                    }
                }
            }
            2 => alloc_it(ObjectBlueprint::Arch(ObjectBlueprintX86::PageDirectory)),
            3 => alloc_it(ObjectBlueprint::Arch(ObjectBlueprintX86::PageTable)),
            _ => unreachable!(),
        }
    }

    fn ps_map(&mut self, ipc: &mut IpcBuffer, cap: &HostPagingStructure, addr: u64, level: u8) {
        match level {
            1 => {
                if !self.skip_pdpt {
                    let size = 512 * 1024 * 1024 * 1024;
                    assert!(addr & (size - 1) == 0);
                    assert_eq!(
                        ipc.inner_mut().seL4_X86_PDPT_Map(
                            cap.cap.bits(),
                            self.hostpml4.bits(),
                            addr,
                            VmAttributes::DEFAULT.into_inner()
                        ),
                        0
                    );
                }
            }
            2 => {
                let size = 1024 * 1024 * 1024;
                assert!(addr & (size - 1) == 0);
                assert_eq!(
                    ipc.inner_mut().seL4_X86_PageDirectory_Map(
                        cap.cap.bits(),
                        self.hostpml4.bits(),
                        addr,
                        VmAttributes::DEFAULT.into_inner()
                    ),
                    0
                );
            }
            3 => {
                let size = 2 * 1024 * 1024;
                assert!(addr & (size - 1) == 0);
                assert_eq!(
                    ipc.inner_mut().seL4_X86_PageTable_Map(
                        cap.cap.bits(),
                        self.hostpml4.bits(),
                        addr,
                        VmAttributes::DEFAULT.into_inner()
                    ),
                    0
                );
            }
            _ => unreachable!(),
        }
    }

    fn ps_unmap(&mut self, _ipc: &mut IpcBuffer, _cap: &HostPagingStructure) {
        todo!()
    }

    fn ps_free(&mut self, _ipc: &mut IpcBuffer, _cap: &HostPagingStructure) {
        todo!()
    }
}

impl<'a> HostPagingContext<'a> {
    pub fn new(
        ua: &'a RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
        cspace: CNode,
        hostpml4: VSpace,
        start_address: u64,
        end_address: u64,
    ) -> Self {
        let ptm: HostPageTableManager = PageTableManager::new();
        let ps = HostPagingService {
            alloc: ua,
            cspace,
            hostpml4,
            skip_pdpt: true,
            utlist: LinkedList::new(UntypedInfoAdapter::NEW),
        };
        assert!(start_address & ((1 << SMALL_PAGE_SIZE_BITS) - 1) == 0);
        assert!(end_address & ((1 << SMALL_PAGE_SIZE_BITS) - 1) == 0);
        assert!(end_address > start_address);
        let bitmap = IdAlloc64OffsetLimit {
            inner: IdAlloc64::new(),
            offset: start_address >> SMALL_PAGE_SIZE_BITS,
            limit: end_address >> SMALL_PAGE_SIZE_BITS,
        };
        Self {
            inner: RefCell::new(HostPagingContextInner { ptm, ps, bitmap }),
        }
    }

    pub fn hostpml4(&self) -> VSpace {
        self.inner.borrow().ps.hostpml4
    }

    pub fn with_ptm_ps<R>(
        &mut self,
        cb: impl FnOnce(&mut HostPageTableManager, &mut HostPagingService) -> R,
    ) -> R {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;
        cb(&mut inner.ptm, &mut inner.ps)
    }

    pub fn alloc_unmapped_page(
        &self,
        ipc: &mut IpcBuffer,
    ) -> NonNull<[u8; 1 << SMALL_PAGE_SIZE_BITS]> {
        self.alloc_unmapped_page_at(ipc, None)
    }

    pub fn alloc_unmapped_page_at(
        &self,
        ipc: &mut IpcBuffer,
        vaddr: Option<u64>,
    ) -> NonNull<[u8; 1 << SMALL_PAGE_SIZE_BITS]> {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;
        let vaddr = if let Some(vaddr) = vaddr {
            assert!(vaddr & ((1 << SMALL_PAGE_SIZE_BITS) - 1) == 0);
            assert!(
                inner.bitmap.alloc_at(vaddr >> SMALL_PAGE_SIZE_BITS),
                "Failed to allocate page virtual address"
            );
            vaddr
        } else {
            inner
                .bitmap
                .alloc()
                .expect("Failed to allocate page virtual address")
                << SMALL_PAGE_SIZE_BITS
        };
        inner
            .ptm
            .allocate(ipc, vaddr, 3, &mut inner.ps)
            .expect("Failed to allocate paging structures");
        NonNull::new(vaddr as *mut _).expect("Failed to convert vaddr to pointer")
    }

    pub fn free_unmapped_page(&self, page: NonNull<[u8; 1 << SMALL_PAGE_SIZE_BITS]>) -> bool {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;
        let vaddr = page.as_ptr() as u64;
        assert!(vaddr & ((1 << SMALL_PAGE_SIZE_BITS) - 1) == 0);
        if inner.bitmap.free(vaddr >> SMALL_PAGE_SIZE_BITS) {
            inner
                .ptm
                .free_leaf(vaddr, 3)
                .expect("Failed to free paging structures");
            true
        } else {
            false
        }
    }
}
