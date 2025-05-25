use core::cell::RefCell;

use algorithms::unialloc::{UniAllocTrait, UntypedInfo};
use sel4::{cap::CNode, CPtr, IpcBuffer, ObjectBlueprint};

use crate::{
    cap_blackhole::CapBlackhole,
    untyped::{UntypedCap, UntypedCapContext},
};

#[must_use]
pub fn alloc_and_retype(
    ipc: &mut IpcBuffer,
    ua: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
    cspace: CNode,
    blueprint: &ObjectBlueprint,
    cap: CPtr,
) -> Option<UntypedInfo<UntypedCap>> {
    alloc_and_retype_with_blackhole(ipc, ua, cspace, blueprint, cap, None)
}

pub fn alloc_and_retype_with_blackhole(
    ipc: &mut IpcBuffer,
    ua: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
    cspace: CNode,
    blueprint: &ObjectBlueprint,
    cap: CPtr,
    cap_blackhole: Option<&CapBlackhole<'_>>,
) -> Option<UntypedInfo<UntypedCap>> {
    let mut dead_caps = heapless::Vec::new();
    let ut = UntypedCapContext::with(ipc, cspace, |ctx| {
        ua.borrow_mut().try_alloc_recycling_caps(
            ctx,
            blueprint.physical_size_bits(),
            Some(&mut dead_caps),
        )
    })?;
    if let Some(cap_blackhole) = cap_blackhole {
        for x in dead_caps {
            cap_blackhole.dispose_and_free(ipc, CPtr::from_bits(x));
        }
    }
    let cspace_abs = cspace.absolute_cptr(cspace.cptr());
    let ret = ipc.inner_mut().seL4_Untyped_Retype(
        ut.cap.0.bits(),
        blueprint.ty().into_sys().into(),
        blueprint.api_size_bits().unwrap_or(0) as _,
        cspace_abs.root().bits(),
        cspace_abs.path().bits(),
        cspace_abs.path().depth() as _,
        cap.bits(),
        1,
    );
    assert_eq!(ret, 0, "untyped_retype failed");
    Some(ut)
}
