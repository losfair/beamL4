use alloc::boxed::Box;

pub const fn num_slots_for_levels(levels: u32) -> usize {
    (64usize.pow(levels) - 1) / 63
}

pub struct IdAlloc64<const NUM_LEVELS: u32>
where
    [(); num_slots_for_levels(NUM_LEVELS)]:,
{
    slots: [u64; num_slots_for_levels(NUM_LEVELS)],
}

pub trait IdAlloc64Trait {
    fn alloc(&mut self) -> Option<u64>;
    fn alloc_at(&mut self, id: u64) -> bool;
    fn free(&mut self, id: u64) -> bool;
    fn contains(&self, id: u64) -> bool;
}

pub struct IdAlloc64OffsetLimit<T: IdAlloc64Trait> {
    pub inner: T,
    pub offset: u64,
    pub limit: u64,
}

impl<T: IdAlloc64Trait> IdAlloc64Trait for IdAlloc64OffsetLimit<T> {
    fn alloc(&mut self) -> Option<u64> {
        let ret = self.inner.alloc().map(|x| x + self.offset)?;
        if ret >= self.limit {
            self.inner.free(ret);
            return None;
        }
        Some(ret)
    }

    fn alloc_at(&mut self, id: u64) -> bool {
        if id < self.offset || id >= self.limit {
            return false;
        }
        self.inner.alloc_at(id - self.offset)
    }

    fn free(&mut self, id: u64) -> bool {
        if id < self.offset || id >= self.limit {
            return false;
        }
        self.inner.free(id - self.offset)
    }

    fn contains(&self, id: u64) -> bool {
        if id < self.offset || id >= self.limit {
            return false;
        }
        self.inner.contains(id - self.offset)
    }
}

impl<const NUM_LEVELS: u32> IdAlloc64OffsetLimit<IdAlloc64<NUM_LEVELS>>
where
    [(); num_slots_for_levels(NUM_LEVELS)]:,
    [(); NUM_LEVELS as usize]:,
{
    pub fn new_boxed(offset: u64, limit: u64) -> Box<Self> {
        let mut ret: Box<Self> = unsafe { Box::new_zeroed().assume_init() };
        ret.offset = offset;
        ret.limit = limit;
        ret
    }
}

impl<const NUM_LEVELS: u32> IdAlloc64<NUM_LEVELS>
where
    [(); num_slots_for_levels(NUM_LEVELS)]:,
    [(); NUM_LEVELS as usize]:,
{
    pub fn from_raw(ptr: *mut [u8]) -> *mut Self {
        let base = ptr as *mut u8;
        assert!(ptr.len() == core::mem::size_of::<Self>());
        assert!(base as usize & (core::mem::align_of::<Self>() - 1) == 0);
        base as *mut Self
    }

    pub const fn new() -> Self {
        unsafe { core::mem::zeroed() }
    }

    pub fn new_boxed() -> Box<Self> {
        unsafe { Box::new_zeroed().assume_init() }
    }

    fn trace(
        &self,
        id: u64,
        require_current_state: bool,
    ) -> Option<[(usize, usize); NUM_LEVELS as usize]> {
        if id >> (NUM_LEVELS * 6) != 0 {
            return None;
        }

        let mut current_index = 0usize;
        let mut trace = [(0usize, 0usize); NUM_LEVELS as usize];
        let mut offset = 0usize;
        let mut mul = 1usize;

        for i in 0..NUM_LEVELS {
            let bit_position = ((id >> ((NUM_LEVELS - 1 - i) * 6)) & 63) as usize;
            trace[i as usize] = (current_index, bit_position);
            offset += mul;

            if i + 1 != NUM_LEVELS {
                current_index = offset
                    + (0..i + 1)
                        .map(|j| trace[j as usize].1 * 64usize.pow(i - j))
                        .sum::<usize>();
            }

            mul *= 64;
        }
        assert_eq!(offset, self.slots.len());
        let last = trace[NUM_LEVELS as usize - 1];
        if (self.slots[last.0] & (1 << last.1) != 0) != require_current_state {
            return None;
        }
        Some(trace)
    }
}

impl<const NUM_LEVELS: u32> IdAlloc64Trait for IdAlloc64<NUM_LEVELS>
where
    [(); num_slots_for_levels(NUM_LEVELS)]:,
    [(); NUM_LEVELS as usize]:,
{
    fn alloc(&mut self) -> Option<u64> {
        let mut current_index = 0usize;
        let mut trace = [(0usize, 0usize); NUM_LEVELS as usize];
        let mut offset = 0usize;
        let mut mul = 1usize;
        let mut output = 0u64;

        for i in 0..NUM_LEVELS {
            let first_free = self.slots[current_index].trailing_ones() as usize;
            if first_free == 64 {
                return None;
            }
            trace[i as usize] = (current_index, first_free);
            output = (output << 6) | first_free as u64;
            offset += mul;

            if i + 1 != NUM_LEVELS {
                // current_index = offset + prev_free * mul + first_free;
                current_index = offset
                    + (0..i + 1)
                        .map(|j| trace[j as usize].1 * 64usize.pow(i - j))
                        .sum::<usize>();
            }

            mul *= 64;
        }
        assert_eq!(offset, self.slots.len());

        for (offset, bit) in trace.into_iter().rev() {
            self.slots[offset] |= 1 << bit;
            if self.slots[offset] != u64::MAX {
                break;
            }
        }
        Some(output)
    }

    fn alloc_at(&mut self, id: u64) -> bool {
        let Some(trace) = self.trace(id, false) else {
            return false;
        };

        for (offset, bit) in trace.into_iter().rev() {
            self.slots[offset] |= 1 << bit;
            if self.slots[offset] != u64::MAX {
                break;
            }
        }
        true
    }

    fn free(&mut self, id: u64) -> bool {
        let Some(trace) = self.trace(id, true) else {
            return false;
        };

        for (offset, bit) in trace.into_iter().rev() {
            let prev = self.slots[offset];
            self.slots[offset] &= !(1 << bit);
            if prev != u64::MAX {
                break;
            }
        }
        true
    }

    fn contains(&self, id: u64) -> bool {
        self.trace(id, true).is_some()
    }
}

#[cfg(test)]
mod test {
    use alloc::collections::BTreeSet;
    use rand::Rng;

    use super::*;

    use std::prelude::rust_2021::*;

    #[test]
    fn max_alloc() {
        let mut idalloc = IdAlloc64::<3>::new_boxed();
        for i in 0..262144 {
            assert_eq!(idalloc.alloc(), Some(i), "i = {}", i);
        }
        assert!(idalloc.alloc().is_none());
    }

    #[test]
    fn max_alloc_4() {
        let mut idalloc = IdAlloc64::<4>::new_boxed();
        for i in 0..16777216 {
            assert_eq!(idalloc.alloc(), Some(i), "i = {}", i);
        }
    }

    #[test]
    fn double_free_and_alloc_at() {
        let mut idalloc = IdAlloc64::<3>::new_boxed();
        for i in 0..913 {
            assert_eq!(idalloc.alloc(), Some(i), "i = {}", i);
        }
        assert!(idalloc.free(571));
        assert!(!idalloc.free(571));

        assert!(idalloc.alloc_at(571));
        assert!(!idalloc.alloc_at(571));
        assert!(!idalloc.alloc_at(572));
        assert!(idalloc.free(572));
        assert!(idalloc.alloc_at(10000));
        assert!(!idalloc.alloc_at(10000));
        assert!(idalloc.alloc() == Some(572));
    }

    #[test]
    fn randomized_compare() {
        let mut idalloc = IdAlloc64::<3>::new_boxed();
        let mut next_alloc = 0u64;
        let mut free_pool = BTreeSet::new();
        let mut allocated: Vec<u64> = Vec::new();

        for _ in 0..262144 {
            let op = rand::thread_rng().gen_range(0..5);
            match op {
                0 | 1 => {
                    let id = idalloc.alloc().unwrap();

                    let naive_id = if let Some(x) = free_pool.pop_first() {
                        x
                    } else {
                        let x = next_alloc;
                        next_alloc += 1;
                        x
                    };
                    assert_eq!(id, naive_id);
                    allocated.push(id);
                }
                2 | 3 => {
                    let naive_id = if let Some(x) = free_pool.pop_first() {
                        x
                    } else {
                        let x = next_alloc;
                        next_alloc += 1;
                        x
                    };
                    assert!(idalloc.alloc_at(naive_id));
                    allocated.push(naive_id);
                }
                4 => {
                    if allocated.is_empty() {
                        continue;
                    }
                    let id =
                        allocated.swap_remove(rand::thread_rng().gen_range(0..allocated.len()));
                    assert!(idalloc.free(id));
                    assert!(id < next_alloc && free_pool.insert(id));
                }
                _ => unreachable!(),
            }
        }
    }
}
