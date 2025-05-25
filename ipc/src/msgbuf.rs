use core::cell::RefCell;

use algorithms::unialloc::{AbstractUntyped, UniAllocTrait, UntypedInfo};
use rkyv::{
    api::high::{to_bytes_in, HighValidator},
    bytecheck::CheckBytes,
    rancor::Strategy,
    ser::{allocator::ArenaHandle, sharing::Share, writer::Buffer, Serializer},
    Archive,
};
use sel4::{cap::CNode, sys::seL4_Word, AbsoluteCPtr, CPtr, CapRights, IpcBuffer, MessageInfo};

use crate::untyped::UntypedCapContext;

const WORD_SIZE: usize = core::mem::size_of::<usize>();

mod private {
    pub trait Sealed {}
}

pub trait CapTransferMode: private::Sealed {
    type Garbage: CapTransferGarbage;

    fn prepare_transfer<F: Fn() -> (C, usize), C: Iterator<Item = CPtr>>(
        self,
        ipc: &mut IpcBuffer,
        caps: F,
    ) -> (Option<CPtr>, u8, Option<Self::Garbage>);
}

pub trait CapTransferGarbage {
    fn release(self, ipc: &mut IpcBuffer);
}

impl CapTransferGarbage for () {
    fn release(self, _: &mut IpcBuffer) {}
}

pub struct DirectTransfer;
impl private::Sealed for DirectTransfer {}
impl CapTransferMode for DirectTransfer {
    type Garbage = ();
    fn prepare_transfer<F: Fn() -> (C, usize), C: Iterator<Item = CPtr>>(
        self,
        _ipc: &mut IpcBuffer,
        caps: F,
    ) -> (Option<CPtr>, u8, Option<Self::Garbage>) {
        let mut caps = caps();
        if caps.1 == 0 {
            return (None, 0, None);
        }
        assert_eq!(caps.1, 1, "DirectTransfer requires exactly one cap");
        (Some(caps.0.next().unwrap()), 0, Some(()))
    }
}

pub struct UnmanagedTransfer {
    pub cptr: CPtr,
    pub cnode_bits: u8,
}
impl private::Sealed for UnmanagedTransfer {}
impl CapTransferMode for UnmanagedTransfer {
    type Garbage = ();
    fn prepare_transfer<F: Fn() -> (C, usize), C: Iterator<Item = CPtr>>(
        self,
        _ipc: &mut IpcBuffer,
        caps: F,
    ) -> (Option<CPtr>, u8, Option<Self::Garbage>) {
        let caps = caps();
        assert_eq!(caps.1, 0, "UnmanagedTransfer requires zero caps");
        (Some(self.cptr), self.cnode_bits, None)
    }
}

pub struct WrappedTransfer<'a, A: ?Sized> {
    pub unialloc: &'a RefCell<A>,
    pub cspace: CNode,
}

pub struct WrappedTransferGarbage<'a, A: UniAllocTrait + ?Sized> {
    unialloc: &'a RefCell<A>,
    cnode_ut: UntypedInfo<A::Untyped>,
    cnode: CNode,
    ut_abs: AbsoluteCPtr,
}
impl<'a, A: ?Sized> private::Sealed for WrappedTransfer<'a, A> {}
impl<
        'a,
        A: UniAllocTrait<Untyped = U> + ?Sized,
        U: AbstractUntyped<Context = UntypedCapContext>,
    > CapTransferMode for WrappedTransfer<'a, A>
{
    type Garbage = WrappedTransferGarbage<'a, A>;
    fn prepare_transfer<F: Fn() -> (C, usize), C: Iterator<Item = CPtr>>(
        self,
        ipc: &mut IpcBuffer,
        caps: F,
    ) -> (Option<CPtr>, u8, Option<Self::Garbage>) {
        let caps = caps();
        if caps.1 == 0 {
            return (None, 0, None);
        }

        let cnode_bits = (WORD_SIZE * 8 - (caps.1 - 1).leading_zeros() as usize).max(1);
        let cnode_ut = UntypedCapContext::with(ipc, self.cspace, |ctx| {
            self.unialloc
                .borrow_mut()
                .try_alloc(ctx, cnode_bits + sel4::sys::seL4_SlotBits as usize)
                .expect("WrappedTransfer: failed to allocate cnode untyped")
        });
        let ut_abs = self
            .cspace
            .absolute_cptr(CPtr::from_bits(cnode_ut.cap.to_cptr_bits()));
        let cnode = self
            .unialloc
            .borrow_mut()
            .get_capalloc()
            .alloc()
            .expect("WrappedTransfer: failed to allocate cnode cap");
        let ret = ipc.inner_mut().seL4_Untyped_Retype(
            cnode_ut.cap.to_cptr_bits(),
            sel4::sys::api_object::seL4_CapTableObject as _,
            cnode_bits as _,
            self.cspace.bits(),
            self.cspace.bits(),
            (WORD_SIZE * 8) as _,
            cnode,
            1,
        );
        assert_eq!(ret, 0, "WrappedTransfer: failed to retype cnode");

        for (i, cap) in caps.0.enumerate() {
            if cap.bits() == 0 {
                continue;
            }
            let src = self.cspace.absolute_cptr(cap);
            let ret = ipc.inner_mut().seL4_CNode_Copy(
                cnode,
                i as _,
                cnode_bits as _,
                src.root().bits(),
                src.path().bits(),
                src.path().depth() as _,
                CapRights::new(true, true, true, true).into_inner(),
            );
            assert_eq!(ret, 0, "WrappedTransfer: failed to copy cap");
        }
        (
            Some(CPtr::from_bits(cnode)),
            cnode_bits as u8,
            Some(WrappedTransferGarbage {
                unialloc: self.unialloc,
                cnode_ut,
                cnode: CNode::from_bits(cnode),
                ut_abs,
            }),
        )
    }
}

impl<'a, A: UniAllocTrait + ?Sized> CapTransferGarbage for WrappedTransferGarbage<'a, A> {
    fn release(self, ipc: &mut IpcBuffer) {
        let ret = ipc.inner_mut().seL4_CNode_Revoke(
            self.ut_abs.root().bits(),
            self.ut_abs.path().bits(),
            self.ut_abs.path().depth() as u8,
        );
        assert_eq!(ret, 0);

        self.unialloc
            .borrow_mut()
            .get_capalloc()
            .free(self.cnode.cptr().bits());
        self.unialloc.borrow_mut().free_normal(&self.cnode_ut);
    }
}

pub fn encode_msg<
    T: for<'a, 'b> rkyv::Serialize<
        Strategy<Serializer<Buffer<'a>, ArenaHandle<'b>, Share>, rkyv::rancor::Error>,
    >,
    M: CapTransferMode,
>(
    ipc: &mut IpcBuffer,
    value: &T,
    mode: M,
    caps: &[CPtr],
) -> (MessageInfo, Option<M::Garbage>) {
    encode_msg_it(ipc, value, mode, || (caps.iter().copied(), caps.len()))
}

pub fn encode_msg_it<
    T: for<'a, 'b> rkyv::Serialize<
        Strategy<Serializer<Buffer<'a>, ArenaHandle<'b>, Share>, rkyv::rancor::Error>,
    >,
    M: CapTransferMode,
    C: Iterator<Item = CPtr>,
>(
    ipc: &mut IpcBuffer,
    value: &T,
    mode: M,
    caps: impl Fn() -> (C, usize),
) -> (MessageInfo, Option<M::Garbage>) {
    let (cap, maybe_cnode_bits, garbage) = mode.prepare_transfer(ipc, caps);
    assert!(maybe_cnode_bits < 32);

    let bytes = ipc.msg_bytes_mut();
    let written = to_bytes_in(value, Buffer::from(bytes))
        .expect("msgbuf::prepare_msg: serialization failed")
        .len();
    // range: 0..WORD_SIZE
    let empty_space = if written % WORD_SIZE == 0 {
        0
    } else {
        WORD_SIZE - written % WORD_SIZE
    };

    let label = (T::TYPE_HASH as usize) << (WORD_SIZE.trailing_zeros() + 5)
        | ((maybe_cnode_bits as usize) << WORD_SIZE.trailing_zeros())
        | empty_space;
    let label = if WORD_SIZE == 4 {
        label & ((1 << 20) - 1)
    } else {
        label & ((1 << 52) - 1)
    };
    let msginfo = MessageInfo::new(
        label as seL4_Word,
        0,
        if cap.is_some() { 1 } else { 0 },
        written.div_ceil(WORD_SIZE),
    );
    if let Some(cap) = cap {
        ipc.caps_or_badges_mut()[0] = cap.bits();
    }
    (msginfo, garbage)
}

pub fn decode_msg<'a, T: Archive>(
    ipc: &'a IpcBuffer,
    msginfo: MessageInfo,
) -> Result<(&'a T::Archived, Option<u8>), &'static str>
where
    T::Archived: for<'b> CheckBytes<HighValidator<'b, rkyv::rancor::Error>>,
{
    let label = msginfo.label() as usize;
    let type_hash_bits: usize =
        (if WORD_SIZE == 4 { 20 } else { 52 }) - (WORD_SIZE.trailing_zeros() as usize + 5);
    if label >> (WORD_SIZE.trailing_zeros() + 5)
        != (T::TYPE_HASH & ((1 << type_hash_bits) - 1)) as usize
    {
        sel4::debug_println!(
            "type hash mismatch: {:x} != {:x}",
            label >> (WORD_SIZE.trailing_zeros() + 5),
            T::TYPE_HASH & ((1 << type_hash_bits) - 1)
        );
        return Err("type hash mismatch");
    }
    let cnode_bits = (label >> WORD_SIZE.trailing_zeros()) & 31;
    let empty_space = label & (WORD_SIZE - 1);
    let payload = &ipc.msg_bytes()[..(msginfo.length() * WORD_SIZE).saturating_sub(empty_space)];
    let payload = rkyv::access::<T::Archived, rkyv::rancor::Error>(payload)
        .map_err(|_| "failed to access payload")?;
    let mut capinfo = None;
    if msginfo.extra_caps() > 0
        && msginfo
            .extra_caps()
            .saturating_sub(msginfo.caps_unwrapped().count_ones() as usize)
            > 0
    {
        capinfo = Some(cnode_bits as u8);
    }
    Ok((payload, capinfo))
}

trait TypeHash {
    const TYPE_HASH: u64;
}

impl<T: ?Sized> TypeHash for T {
    const TYPE_HASH: u64 = xxhash_rust::const_xxh3::xxh3_64(core::any::type_name::<T>().as_bytes());
}
