use core::arch::x86_64::_rdrand64_step;

use sel4::{cap::CNode, sys::invocation_label, CPtr, MessageInfo};

pub fn hw_rng_u64() -> u64 {
    let mut out = 0u64;
    unsafe {
        while _rdrand64_step(&mut out) == 0 {
            sel4::sys::seL4_Yield();
        }
    }
    out
}

pub fn now_cycles() -> u64 {
    let mut aux = 0;
    unsafe { core::arch::x86_64::__rdtscp(&mut aux) }
}

pub fn delete_cap(cspace: CNode, cap: CPtr) -> u32 {
    let cap = cspace.absolute_cptr(cap);

    // do not pollute ipc buffer
    let msg = MessageInfo::new(invocation_label::CNodeDelete.into(), 0, 0, 2);
    sel4::sys::seL4_CallWithMRsWithoutIPCBuffer(
        cap.root().bits(),
        msg.into_inner(),
        Some(&mut cap.path().bits()),
        Some(&mut (cap.path().depth() as u64)),
        None,
        None,
    )
    .get_label() as u32
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Copy, Clone)]
#[rkyv(derive(Debug))]
pub enum MmioSize {
    Byte,
    Word,
    Dword,
}
