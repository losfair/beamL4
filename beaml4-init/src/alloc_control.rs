use core::{cell::RefCell, ops::Deref};

use algorithms::{
    idalloc::{IdAlloc64OffsetLimit, IdAlloc64Trait},
    unialloc::{uni_alloc_init, BoxOrStatic, UniAlloc, UniAllocTrait, UntypedInfo},
};
use intrusive_collections::LinkedListLink;
use ipc::untyped::{UntypedCap, UntypedCapContext};
use sel4::{cap::CNode, init_thread::slot::CNODE, with_ipc_buffer_mut, CPtr, Cap, ObjectBlueprint};

use crate::static_config::STATIC_CAP_BASE;
use talc::{ErrOnOom, Span, Talc, Talck};

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

static mut HEAP: [u64; 262144] = [0; 262144];

pub struct AllocState {
    pub ua: RefCell<UniAlloc<UntypedCap, 3>>,
}

pub fn alloc_init(bootinfo: &sel4::BootInfoPtr) -> AllocState {
    #[allow(static_mut_refs)]
    unsafe {
        ALLOCATOR
            .try_lock()
            .unwrap()
            .claim(Span::from_base_size(
                HEAP.as_mut_ptr().cast(),
                HEAP.len() * core::mem::size_of::<u64>(),
            ))
            .expect("claim RustHeap failed");
    }
    let untyped = bootinfo.untyped();
    assert_eq!(untyped.len(), bootinfo.untyped_list().len());
    let ua = uni_alloc_init(
        || {
            untyped
                .range()
                .zip(bootinfo.untyped_list())
                .map(|(cap, desc)| UntypedInfo {
                    link: LinkedListLink::new(),
                    cap: UntypedCap(Cap::from_bits(cap as _)),
                    paddr: desc.paddr() as u64,
                    size_bits: desc.size_bits() as u8,
                    is_device: desc.is_device(),
                })
        },
        bootinfo.empty().start() as u64,
        STATIC_CAP_BASE,
        BoxOrStatic::Boxed(IdAlloc64OffsetLimit::new_boxed(0, 0)),
    );
    if false {
        for ((size_bits, paddr), cap) in &ua.untyped_normal {
            println!(
                "untyped_normal: {} bits at {:#x}, cap {}",
                size_bits,
                paddr,
                cap.0.bits()
            );
        }
        for (paddr, (cap, size_bits)) in &ua.untyped_device {
            println!(
                "untyped_device @ {:#x}: {} bits (cap {:#x})",
                paddr,
                size_bits,
                cap.0.bits()
            );
        }
    }

    AllocState {
        ua: RefCell::new(ua),
    }
}

impl Deref for AllocState {
    type Target = RefCell<UniAlloc<UntypedCap, 3>>;

    fn deref(&self) -> &Self::Target {
        &self.ua
    }
}

impl AllocState {
    pub fn alloc_empty_cap(&self) -> CPtr {
        CPtr::from_bits(
            self.ua
                .borrow_mut()
                .capalloc
                .alloc()
                .expect("alloc_empty_cap: capalloc failed"),
        )
    }

    pub fn try_alloc(&self, requested_size_bits: usize) -> Option<UntypedInfo<UntypedCap>> {
        with_ipc_buffer_mut(|ipc| {
            UntypedCapContext::with(ipc, CNODE.cap(), |ctx| {
                self.borrow_mut().try_alloc(ctx, requested_size_bits)
            })
        })
    }

    pub fn alloc(&self, requested_size_bits: usize) -> UntypedInfo<UntypedCap> {
        self.try_alloc(requested_size_bits)
            .unwrap_or_else(|| panic!("alloc: failed to allocate {} bits", requested_size_bits))
    }

    pub fn alloc_and_retype(
        &self,
        blueprint: &ObjectBlueprint,
        cap: CPtr,
    ) -> UntypedInfo<UntypedCap> {
        self.alloc_and_retype_in(blueprint, CNODE.cap(), cap.bits() as usize)
    }

    pub fn alloc_and_retype_in(
        &self,
        blueprint: &ObjectBlueprint,
        cspace: CNode,
        offset: usize,
    ) -> UntypedInfo<UntypedCap> {
        let ut = self.alloc(blueprint.physical_size_bits());
        ut.cap
            .0
            .untyped_retype(
                blueprint,
                &CNODE.cap().absolute_cptr(cspace.cptr()),
                offset,
                1,
            )
            .expect("untyped_retype failed");
        ut
    }

    pub fn alloc_device(
        &self,
        requested_paddr: u64,
        requested_size_bits: usize,
    ) -> Option<UntypedInfo<UntypedCap>> {
        with_ipc_buffer_mut(|ipc| {
            UntypedCapContext::with(ipc, CNODE.cap(), |ctx| {
                self.borrow_mut()
                    .alloc_device(ctx, requested_paddr, requested_size_bits)
            })
        })
    }
}
