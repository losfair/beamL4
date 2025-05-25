use alloc::collections::BTreeMap;

#[derive(Debug)]
pub struct PatchPointSet {
    // paddr -> (patchpoint, insn_len)
    pub patch_points: BTreeMap<u64, (PatchPoint, u8)>,
}

#[derive(Debug, Copy, Clone)]
pub enum PatchPoint {
    Vmcall,
    Pushfw,
    Pushfd,
    Pushfq,
    Popfw,
    Popfd,
    Popfq,
    Invlpg,
    SidtRax,
    Cpuid,
    Iretq,
}
