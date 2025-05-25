use core::ptr::NonNull;

use sel4::{CapRights, FrameObjectType};
use x86::bits64::paging::{PDEntry, PDPTEntry, PML4Entry, PTEntry};

use crate::paging::VmPagingContext;

const SMALL_PAGE_SIZE: usize = FrameObjectType::_4k.bytes();

pub struct PageTableWalker {
    pub paging: &'static VmPagingContext<'static>,
    pub cr3: u64,
}

impl PageTableWalker {
    pub fn try_read(&self, start: usize, output: &mut [u8]) -> Result<(), usize> {
        let mut cursor = 0usize;
        let end = start.checked_add(output.len()).unwrap_or_else(|| {
            panic!(
                "ptw read failed: overflow for {:#x}+{:#x}",
                start,
                output.len(),
            )
        });
        self.usermem(start, end, |buf, len| {
            assert!(len <= output.len() - cursor);
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), output[cursor..].as_mut_ptr(), len);
            }
            cursor += len;
            true
        })
    }

    pub fn read(&self, start: usize, output: &mut [u8]) {
        self.try_read(start, output).unwrap_or_else(|bad_addr| {
            let end = start + output.len();
            panic!(
                "ptw read failed at page {:#x} for {:#x} - {:#x}",
                bad_addr, start, end
            )
        })
    }

    pub fn write(&self, start: usize, input: &[u8]) {
        let mut cursor = 0usize;
        let end = start.checked_add(input.len()).unwrap_or_else(|| {
            panic!(
                "ptw write failed: overflow for {:#x}+{:#x}",
                start,
                input.len(),
            )
        });
        self.usermem(start, end, |buf, len: usize| {
            assert!(len <= input.len() - cursor);
            unsafe {
                core::ptr::copy_nonoverlapping(input[cursor..].as_ptr(), buf.as_ptr(), len);
            }
            cursor += len;
            true
        })
        .unwrap_or_else(|bad_addr| {
            panic!(
                "ptw write failed at page {:#x} for {:#x} - {:#x}",
                bad_addr, start, end
            )
        })
    }

    pub fn usermem(
        &self,
        start: usize,
        end: usize,
        mut cb: impl FnMut(NonNull<u8>, usize) -> bool,
    ) -> Result<(), usize> {
        assert!(end > start);
        // println!("usermem[{}]: {:#x} - {:#x}", self_description(), start, end);
        // do not do dynamic division
        let (start_page, end_page) = (
            start / SMALL_PAGE_SIZE,
            (end + SMALL_PAGE_SIZE - 1) / SMALL_PAGE_SIZE,
        );
        let page_size_bits = FrameObjectType::_4k.bits();
        for page_idx in start_page..end_page {
            let page_addr = page_idx << page_size_bits;
            let rw_start = page_addr.max(start) - page_addr;
            let rw_end = (page_addr + (1 << page_size_bits)).min(end) - page_addr;
            if rw_start == rw_end {
                continue;
            }
            assert!(rw_start < rw_end);
            let buf = self.try_lookup(page_addr).ok_or(page_addr)?;
            if !cb(unsafe { buf.add(rw_start) }, rw_end - rw_start) {
                break;
            }
        }
        Ok(())
    }

    pub fn try_lookup(&self, page_addr: usize) -> Option<NonNull<u8>> {
        let idmap = self.paging.ps.borrow().config().identity_mapping.start;
        self.try_lookup_guest_phys(page_addr)
            .map(|x| NonNull::new((idmap + x.0) as *mut u8).unwrap())
    }

    pub fn try_lookup_guest_phys(&self, page_addr: usize) -> Option<(u64, CapRights)> {
        let mut writable = true;
        let idmap = self.paging.ps.borrow().config().identity_mapping.start;
        let mut table = self.cr3;
        for i in 0..5 {
            if table & (SMALL_PAGE_SIZE - 1) as u64 != 0 {
                return None;
            }
            let mut ok = false;
            if table >= self.paging.low_region.start && table < self.paging.low_region.end {
                ok = true;
            } else if let Some(high) = &self.paging.high_region {
                if table >= high.start && table < high.end {
                    ok = true;
                }
            }

            if !ok {
                return None;
            }

            if i == 4 {
                return Some((
                    table + (page_addr & (FrameObjectType::_4k.bytes() - 1)) as u64,
                    if writable {
                        CapRights::read_write()
                    } else {
                        CapRights::read_only()
                    },
                ));
            }

            let table_data = unsafe { &*((idmap + table) as *const [u64; 512]) };
            let table_index = (page_addr >> ((3 - i) * 9 + 12)) & 511;
            let pte = table_data[table_index];

            match i {
                0 => {
                    let pte = PML4Entry(pte);
                    // println!("PML4: {:#x} -> {:#x} ({:?})", table, pte.address().0, pte);
                    if !pte.is_present() {
                        return None;
                    }
                    if !pte.is_writeable() {
                        writable = false;
                    }
                    table = pte.address().0;
                }
                1 => {
                    let pte = PDPTEntry(pte);
                    // println!("PDPT: {:#x} -> {:#x} ({:?})", table, pte.address().0, pte);
                    if !pte.is_present() {
                        return None;
                    }
                    if !pte.is_writeable() {
                        writable = false;
                    }
                    if pte.is_page() {
                        // huge page
                        return Some((
                            pte.address().0
                                + (page_addr & (FrameObjectType::HugePage.bytes() - 1)) as u64,
                            if writable {
                                CapRights::read_write()
                            } else {
                                CapRights::read_only()
                            },
                        ));
                    }
                    table = pte.address().0;
                }
                2 => {
                    let pte = PDEntry(pte);
                    // println!("PD: {:#x} -> {:#x} ({:?})", table, pte.address().0, pte);
                    if !pte.is_present() {
                        return None;
                    }
                    if !pte.is_writeable() {
                        writable = false;
                    }
                    if pte.is_page() {
                        // large page
                        return Some((
                            pte.address().0
                                + (page_addr & (FrameObjectType::LargePage.bytes() - 1)) as u64,
                            if writable {
                                CapRights::read_write()
                            } else {
                                CapRights::read_only()
                            },
                        ));
                    }

                    table = pte.address().0;
                }
                3 => {
                    let pte = PTEntry(pte);
                    // println!("PT: {:#x} -> {:#x} ({:?})", table, pte.address().0, pte);
                    if !pte.is_present() {
                        return None;
                    }
                    if !pte.is_writeable() {
                        writable = false;
                    }
                    table = pte.address().0;
                }
                _ => unreachable!(),
            }
        }

        unreachable!()
    }
}
