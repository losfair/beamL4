use core::{
    cell::RefCell,
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use intrusive_collections::{intrusive_adapter, LinkedListLink};

use crate::idalloc::{num_slots_for_levels, IdAlloc64, IdAlloc64OffsetLimit, IdAlloc64Trait};

#[derive(Clone, Debug)]
pub struct UntypedInfo<U> {
    pub link: LinkedListLink,
    pub cap: U,
    pub paddr: u64,
    pub size_bits: u8,
    pub is_device: bool,
}

intrusive_adapter!(pub UntypedInfoAdapter<U> = Arc<UntypedInfo<U>>: UntypedInfo<U> { link: LinkedListLink });

pub type SplitUntypedAndDelete<U> = fn(
    info: UntypedInfo<U>,
    empty_start: &mut u64,
    target_size_bits: usize,
    on_delete: &mut dyn FnMut(UntypedInfo<U>),
    on_new: &mut dyn FnMut(UntypedInfo<U>, UntypedInfo<U>) -> UntypedInfo<U>,
) -> UntypedInfo<U>;

pub struct UniAlloc<U, const NUM_LEVELS: u32>
where
    [(); num_slots_for_levels(NUM_LEVELS)]:,
    [(); NUM_LEVELS as usize]:,
{
    // (size_bits, paddr) -> cap
    pub untyped_normal: BTreeMap<(u8, u64), U>,

    // phys_addr -> (cap, size_bits)
    pub untyped_device: BTreeMap<u64, (U, u8)>,

    pub capalloc: BoxOrStatic<IdAlloc64OffsetLimit<IdAlloc64<NUM_LEVELS>>>,
    buffer_cap_twin: u64,
}

pub enum BoxOrStatic<T: 'static> {
    Boxed(Box<T>),
    Static(&'static mut T),
}

impl<T: 'static> Deref for BoxOrStatic<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            BoxOrStatic::Boxed(boxed) => boxed,
            BoxOrStatic::Static(static_ref) => static_ref,
        }
    }
}

impl<T: 'static> DerefMut for BoxOrStatic<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            BoxOrStatic::Boxed(boxed) => boxed,
            BoxOrStatic::Static(static_ref) => static_ref,
        }
    }
}

pub trait UniAllocTrait {
    type Untyped: AbstractUntyped;

    fn get_capalloc(&mut self) -> &mut dyn IdAlloc64Trait;
    fn try_alloc(
        &mut self,
        context: &mut <Self::Untyped as AbstractUntyped>::Context,
        requested_size_bits: usize,
    ) -> Option<UntypedInfo<Self::Untyped>>;
    fn try_alloc_recycling_caps(
        &mut self,
        context: &mut <Self::Untyped as AbstractUntyped>::Context,
        requested_size_bits: usize,
        dead_caps: Option<&mut heapless::Vec<u64, 16>>,
    ) -> Option<UntypedInfo<Self::Untyped>>;
    fn free_device(&mut self, ut: &UntypedInfo<Self::Untyped>);
    fn free_normal(&mut self, ut: &UntypedInfo<Self::Untyped>);
    fn total_remaining_normal(&self, min_size_bits: u8) -> u64;
    fn total_regions(&self) -> usize;
}

pub trait AbstractUntyped {
    type Context;

    fn from_cptr_bits(bits: u64) -> Self;
    fn to_cptr_bits(&self) -> u64;
    fn untyped_split(&self, context: &mut Self::Context, output_size_bits: u8, output_start: u64);
    fn relocate(&self, context: &mut Self::Context, target: u64);
}

pub fn uni_alloc_init<
    U: Copy + Debug + Eq + PartialEq + AbstractUntyped,
    I: Iterator<Item = UntypedInfo<U>>,
    const NUM_LEVELS: u32,
>(
    untyped_list: impl Fn() -> I,
    mut empty_start: u64,
    cap_limit: u64,
    mut capalloc: BoxOrStatic<IdAlloc64OffsetLimit<IdAlloc64<NUM_LEVELS>>>,
) -> UniAlloc<U, NUM_LEVELS>
where
    [(); num_slots_for_levels(NUM_LEVELS)]:,
    [(); NUM_LEVELS as usize]:,
{
    let buffer_cap_twin = empty_start;
    empty_start += 2;

    capalloc.offset = empty_start;
    capalloc.limit = cap_limit;

    let mut output = UniAlloc {
        untyped_normal: BTreeMap::new(),
        untyped_device: BTreeMap::new(),
        capalloc,
        buffer_cap_twin,
    };

    for info in untyped_list() {
        if info.is_device {
            output
                .untyped_device
                .insert(info.paddr, (info.cap, info.size_bits));
        } else {
            output
                .untyped_normal
                .insert((info.size_bits, info.paddr), info.cap);
        }
    }
    output
}

impl<U: Copy + AbstractUntyped + Eq + PartialEq, const NUM_LEVELS: u32> UniAlloc<U, NUM_LEVELS>
where
    [(); num_slots_for_levels(NUM_LEVELS)]:,
    [(); NUM_LEVELS as usize]:,
{
    pub fn alloc_device(
        &mut self,
        context: &mut U::Context,
        requested_paddr: u64,
        requested_size_bits: usize,
    ) -> Option<UntypedInfo<U>> {
        let invariant = |region_paddr: u64, region_size_bits: u8| -> bool {
            requested_paddr >= region_paddr
                && requested_paddr + (1 << requested_size_bits)
                    <= region_paddr + (1 << region_size_bits)
        };

        assert!(requested_size_bits > 0 && requested_size_bits < 32);
        assert!(requested_paddr & ((1 << requested_size_bits) - 1) == 0);

        let (region_paddr, (region_cap, region_size_bits)): (u64, (U, u8)) = self
            .untyped_device
            .range(..=requested_paddr)
            .last()
            .map(|x| (*x.0, *x.1))?;

        if !invariant(region_paddr, region_size_bits) {
            return None;
        }

        let untyped_device = RefCell::new(&mut self.untyped_device);
        let ret = split_untyped_and_delete(
            context,
            UntypedInfo {
                link: LinkedListLink::new(),
                cap: region_cap,
                paddr: region_paddr,
                size_bits: region_size_bits,
                is_device: true,
            },
            Some(self.buffer_cap_twin),
            requested_size_bits,
            &mut *self.capalloc,
            |_, info, _| {
                let deleted = untyped_device.borrow_mut().remove(&info.paddr).is_some();
                assert!(deleted);
            },
            |_, a, b| {
                let inserted = untyped_device
                    .borrow_mut()
                    .insert(a.paddr, (a.cap, a.size_bits))
                    .is_none();
                assert!(inserted);

                let inserted = untyped_device
                    .borrow_mut()
                    .insert(b.paddr, (b.cap, b.size_bits))
                    .is_none();
                assert!(inserted);

                let ret = if requested_paddr >= b.paddr { b } else { a };
                assert!(invariant(ret.paddr, ret.size_bits));
                ret
            },
        );
        Some(ret)
    }
}

impl<U: Copy + AbstractUntyped + Eq + PartialEq, const NUM_LEVELS: u32> UniAllocTrait
    for UniAlloc<U, NUM_LEVELS>
where
    [(); num_slots_for_levels(NUM_LEVELS)]:,
    [(); NUM_LEVELS as usize]:,
{
    type Untyped = U;

    fn get_capalloc(&mut self) -> &mut dyn IdAlloc64Trait {
        &mut *self.capalloc
    }

    fn try_alloc(
        &mut self,
        context: &mut U::Context,
        requested_size_bits: usize,
    ) -> Option<UntypedInfo<U>> {
        self.try_alloc_recycling_caps(context, requested_size_bits, None)
    }

    fn try_alloc_recycling_caps(
        &mut self,
        context: &mut U::Context,
        requested_size_bits: usize,
        mut dead_caps: Option<&mut heapless::Vec<u64, 16>>,
    ) -> Option<UntypedInfo<U>> {
        for size_bits in requested_size_bits..63 {
            let Some((&key, &cap)) = self
                .untyped_normal
                .range((size_bits as u8, 0)..=(size_bits as u8, u64::MAX))
                .next()
            else {
                continue;
            };
            let paddr = key.1;
            let info = UntypedInfo {
                link: LinkedListLink::new(),
                cap,
                paddr,
                size_bits: size_bits as u8,
                is_device: false,
            };
            let untyped = RefCell::new(&mut self.untyped_normal);
            let ret = split_untyped_and_delete(
                context,
                info,
                Some(self.buffer_cap_twin),
                requested_size_bits,
                &mut *self.capalloc,
                |_, info, leaf| {
                    let did_remove = untyped.borrow_mut().remove(&(info.size_bits, info.paddr));
                    assert!(did_remove.is_some());
                    if !leaf {
                        if let Some(dead_caps) = &mut dead_caps {
                            dead_caps.push(info.cap.to_cptr_bits()).ok();
                        }
                    }
                },
                |_, a, b| {
                    for info in [&a, &b] {
                        let old = untyped
                            .borrow_mut()
                            .insert((info.size_bits, info.paddr), info.cap);
                        assert!(old.is_none());
                    }
                    b
                },
            );
            return Some(ret);
        }
        None
    }

    fn total_regions(&self) -> usize {
        self.untyped_normal.len() + self.untyped_device.len()
    }

    fn free_device(&mut self, ut: &UntypedInfo<U>) {
        assert!(ut.is_device);
        assert!(self
            .untyped_device
            .range(..=ut.paddr)
            .last()
            .filter(|x| x.0 + (1 << x.1 .1) > ut.paddr)
            .is_none());
        assert!(self
            .untyped_device
            .range(ut.paddr..)
            .next()
            .filter(|x| *x.0 < ut.paddr + (1 << ut.size_bits))
            .is_none());
        let inserted = self
            .untyped_device
            .insert(ut.paddr, (ut.cap, ut.size_bits))
            .is_none();
        assert!(inserted);
    }

    fn free_normal(&mut self, ut: &UntypedInfo<U>) {
        assert!(!ut.is_device);
        let old = self.untyped_normal.insert((ut.size_bits, ut.paddr), ut.cap);
        assert!(old.is_none());
    }

    fn total_remaining_normal(&self, min_size_bits: u8) -> u64 {
        self.untyped_normal
            .iter()
            .filter(|x| x.0 .0 >= min_size_bits)
            .map(|((size_bits, _), _)| 1u64 << size_bits)
            .sum::<u64>()
    }
}

fn split_untyped_and_delete<U: Copy + AbstractUntyped>(
    context: &mut U::Context,
    mut info: UntypedInfo<U>,
    buffer_cap_twin: Option<u64>,
    target_size_bits: usize,
    alloc: &mut impl IdAlloc64Trait,
    mut on_delete: impl FnMut(&mut U::Context, &UntypedInfo<U>, bool),
    mut on_new: impl FnMut(&mut U::Context, UntypedInfo<U>, UntypedInfo<U>) -> UntypedInfo<U>,
) -> UntypedInfo<U> {
    while (info.size_bits as usize) > target_size_bits {
        let mut need_move = false;

        let left = alloc
            .alloc()
            .expect("split_untyped_and_delete: id alloc failed");
        let right = if alloc.alloc_at(left + 1) {
            left + 1
        } else {
            need_move = true;
            alloc
                .alloc()
                .expect("split_untyped_and_delete: id alloc failed")
        };

        info.cap.untyped_split(
            context,
            info.size_bits - 1,
            if need_move {
                buffer_cap_twin.expect("split_untyped_and_delete: buffer_cap_twin is None")
            } else {
                left
            },
        );

        on_delete(context, &info, false);

        if need_move {
            U::from_cptr_bits(buffer_cap_twin.unwrap()).relocate(context, left);
            U::from_cptr_bits(buffer_cap_twin.unwrap() + 1).relocate(context, right);
        }

        let next = on_new(
            context,
            UntypedInfo {
                link: LinkedListLink::new(),
                cap: U::from_cptr_bits(left),
                paddr: info.paddr,
                size_bits: info.size_bits - 1,
                is_device: info.is_device,
            },
            UntypedInfo {
                link: LinkedListLink::new(),
                cap: U::from_cptr_bits(right),
                paddr: info.paddr + (1u64 << (info.size_bits - 1)),
                size_bits: info.size_bits - 1,
                is_device: info.is_device,
            },
        );
        info = next;
    }

    on_delete(context, &info, true);
    info
}
