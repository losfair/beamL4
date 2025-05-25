use core::ops::Range;

use sel4::CPtr;

pub const SUBPROC_ENDPOINT: CPtr = CPtr::from_bits(1);
pub const SUBPROC_VSPACE: CPtr = CPtr::from_bits(2);
pub const SUBPROC_CSPACE: CPtr = CPtr::from_bits(3);
pub const SUBPROC_TCB: CPtr = CPtr::from_bits(4);
pub const SUBPROC_IPC_BUFFER: CPtr = CPtr::from_bits(5);
pub const SUBPROC_PREMAPPED_LOW_REGION: Range<usize> = 0..0x20_0000;
pub const SUBPROC_PREMAPPED_HIGH_REGION: Range<usize> = 0x2000_0000..0x2400_0000;
pub const SUBPROC_PREMAPPED_LARGE_PAGE_REGION: Range<usize> = 0x4000_0000..0x8000_0000;
