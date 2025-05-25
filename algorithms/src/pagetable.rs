use alloc::{boxed::Box, collections::BTreeMap};
use intrusive_collections::{intrusive_adapter, LinkedList, LinkedListLink};

pub trait PagingService<C> {
    type Context;

    fn ps_alloc(&mut self, context: &mut Self::Context, level: u8) -> C;
    fn ps_map(&mut self, context: &mut Self::Context, cap: &C, addr: u64, level: u8);
    fn ps_unmap(&mut self, context: &mut Self::Context, cap: &C);
    fn ps_free(&mut self, context: &mut Self::Context, cap: &C);
    fn ps_guest_phys_to_page_cap(&self, _guest_phys: u64) -> Option<(u64, u64, u8)> {
        None
    }
}

pub struct PageTableManager<
    C,
    const NUM_LEVELS: u32,
    const LEVEL_SIZE_BITS: u32,
    const LEAF_SIZE_BITS: u32,
> where
    [(); (NUM_LEVELS - 1) as usize]:,
    [(); NUM_LEVELS as usize]:,
{
    pools: [LinkedList<PagingStructureAdapter<C>>; (NUM_LEVELS - 1) as usize],
    mapped: [BTreeMap<u64, Option<Box<PagingStructure<C>>>>; (NUM_LEVELS - 1) as usize],
}

struct PagingStructure<C> {
    link: LinkedListLink,
    cap: C,
}

intrusive_adapter!(PagingStructureAdapter<C> = Box<PagingStructure<C>>: PagingStructure<C> { link: LinkedListLink });

#[derive(Debug, Clone)]
pub enum PagingAllocateError {
    AddressNotAligned,
    InLargePage,
    SlotUsed,
}

#[derive(Debug, Clone)]
pub enum PagingFreeError {
    AddressNotAligned,
    InLargePage,
    ContainsPagingStructure,
    NotFound,
}

impl<C, const NUM_LEVELS: u32, const LEVEL_SIZE_BITS: u32, const LEAF_SIZE_BITS: u32>
    PageTableManager<C, NUM_LEVELS, LEVEL_SIZE_BITS, LEAF_SIZE_BITS>
where
    [(); (NUM_LEVELS - 1) as usize]:,
    [(); 1usize << (NUM_LEVELS - 1)]:,
    [(); NUM_LEVELS as usize]:,
{
    pub const fn new() -> Self {
        Self {
            pools: [const { LinkedList::new(PagingStructureAdapter::NEW) };
                (NUM_LEVELS - 1) as usize],
            mapped: [const { BTreeMap::new() }; (NUM_LEVELS - 1) as usize],
        }
    }

    pub fn allocate<PS: PagingService<C>>(
        &mut self,
        ctx: &mut PS::Context,
        addr: u64,
        level: u8,
        ps: &mut PS,
    ) -> Result<(), PagingAllocateError> {
        assert!((level as u32) < NUM_LEVELS);
        let zero_bits = (NUM_LEVELS - 1 - level as u32) * LEVEL_SIZE_BITS + LEAF_SIZE_BITS;
        if addr & ((1 << zero_bits) - 1) as u64 != 0 {
            return Err(PagingAllocateError::AddressNotAligned);
        }

        // validate
        for level in 0..level as u32 {
            let zero_bits = (NUM_LEVELS - 1 - level) * LEVEL_SIZE_BITS + LEAF_SIZE_BITS;
            let addr = addr & !((1u64 << zero_bits) - 1);
            if let Some(None) = &self.mapped[level as usize].get(&addr) {
                return Err(PagingAllocateError::InLargePage);
            }
        }

        if level as u32 != NUM_LEVELS - 1 {
            if self.mapped[level as usize].get(&addr).is_some() {
                return Err(PagingAllocateError::SlotUsed);
            }
        }

        // execute
        for level in 0..level as u32 {
            let zero_bits = (NUM_LEVELS - 1 - level) * LEVEL_SIZE_BITS + LEAF_SIZE_BITS;
            let addr = addr & !((1u64 << zero_bits) - 1);
            self.mapped[level as usize].entry(addr).or_insert_with(|| {
                let pstruct = self.pools[level as usize].pop_front().unwrap_or_else(|| {
                    let cap = ps.ps_alloc(ctx, (level + 1) as u8);
                    Box::new(PagingStructure {
                        link: LinkedListLink::new(),
                        cap,
                    })
                });
                ps.ps_map(ctx, &pstruct.cap, addr, (level + 1) as u8);
                Some(pstruct)
            });
        }

        if level as u32 != NUM_LEVELS - 1 {
            self.mapped[level as usize].insert(addr, None);
        }

        Ok(())
    }

    pub fn free_leaf(&mut self, addr: u64, level: u8) -> Result<(), PagingFreeError> {
        assert!((level as u32) < NUM_LEVELS);
        let zero_bits = (NUM_LEVELS - 1 - level as u32) * LEVEL_SIZE_BITS + LEAF_SIZE_BITS;
        if addr & ((1 << zero_bits) - 1) as u64 != 0 {
            return Err(PagingFreeError::AddressNotAligned);
        }

        // validate
        for level in 0..level as u32 {
            let zero_bits = (NUM_LEVELS - 1 - level) * LEVEL_SIZE_BITS + LEAF_SIZE_BITS;
            let addr = addr & !((1u64 << zero_bits) - 1);
            if let Some(None) = &self.mapped[level as usize].get(&addr) {
                return Err(PagingFreeError::InLargePage);
            }
        }

        if level as u32 != NUM_LEVELS - 1 {
            match self.mapped[level as usize].get(&addr) {
                Some(Some(_)) => Err(PagingFreeError::ContainsPagingStructure),
                Some(None) => {
                    self.mapped[level as usize].remove(&addr);
                    Ok(())
                }
                None => Err(PagingFreeError::NotFound),
            }
        } else {
            Ok(())
        }
    }

    pub fn paging_structures(&self) -> impl Iterator<Item = &C> {
        self.pools
            .iter()
            .flat_map(|pool| pool.iter().map(|p| &p.cap))
            .chain(
                self.mapped
                    .iter()
                    .flat_map(|map| map.values())
                    .filter_map(|p| p.as_ref())
                    .map(|p| &p.cap),
            )
    }
}
