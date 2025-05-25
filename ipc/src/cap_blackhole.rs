use core::cell::{Cell, RefCell};

use algorithms::unialloc::UniAllocTrait;
use sel4::{cap::CNode, CPtr, IpcBuffer, ObjectBlueprint};

use crate::{alloc::alloc_and_retype, untyped::UntypedCap};

const CNODE_BITS: u8 = 16;
const SLOTS_PER_CNODE: u64 = 1 << CNODE_BITS;

pub struct CapBlackhole<'a> {
    pub head: Cell<CNode>,
    pub cursor: Cell<u64>,
    pub cspace: CNode,
    pub ua: &'a RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
}

impl<'a> CapBlackhole<'a> {
    pub fn new(
        ipc: &mut IpcBuffer,
        cspace: CNode,
        ua: &'a RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
    ) -> Self {
        let head = CPtr::from_bits(
            ua.borrow_mut()
                .get_capalloc()
                .alloc()
                .expect("alloc failed"),
        );
        alloc_and_retype(
            ipc,
            ua,
            cspace,
            &ObjectBlueprint::CNode {
                size_bits: CNODE_BITS as usize,
            },
            head,
        )
        .expect("alloc_and_retype failed");
        Self {
            head: Cell::new(CNode::from_cptr(head)),
            cursor: Cell::new(0),
            cspace,
            ua,
        }
    }

    pub fn dispose_and_free(&self, ipc: &mut IpcBuffer, cap: CPtr) -> bool {
        if self.cursor.get() == SLOTS_PER_CNODE {
            // chain
            let new_head = CPtr::from_bits(
                self.ua
                    .borrow_mut()
                    .get_capalloc()
                    .alloc()
                    .expect("alloc failed"),
            );
            alloc_and_retype(
                ipc,
                self.ua,
                self.cspace,
                &ObjectBlueprint::CNode {
                    size_bits: CNODE_BITS as usize,
                },
                new_head,
            )
            .expect("alloc_and_retype failed");
            assert_eq!(
                ipc.inner_mut().seL4_CNode_Move(
                    new_head.bits(),
                    0,
                    CNODE_BITS,
                    self.cspace.bits(),
                    self.head.get().bits(),
                    64
                ),
                0
            );
            assert!(self
                .ua
                .borrow_mut()
                .get_capalloc()
                .free(self.head.get().bits()));
            self.head.set(CNode::from_cptr(new_head));
            self.cursor.set(1);
        }

        assert_eq!(
            ipc.inner_mut().seL4_CNode_Move(
                self.head.get().bits(),
                self.cursor.get(),
                CNODE_BITS,
                self.cspace.bits(),
                cap.bits(),
                64,
            ),
            0
        );
        self.cursor.set(self.cursor.get() + 1);
        self.ua.borrow_mut().get_capalloc().free(cap.bits())
    }
}
