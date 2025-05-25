use algorithms::unialloc::AbstractUntyped;
use sel4::{
    cap::{CNode, Untyped},
    CPtr, IpcBuffer,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UntypedCap(pub Untyped);

pub struct UntypedCapContext {
    ipc: *mut IpcBuffer,
    cspace: CNode,
}

impl UntypedCapContext {
    pub fn with<T>(ipc: &mut IpcBuffer, cspace: CNode, cb: impl FnOnce(&mut Self) -> T) -> T {
        let mut context = Self { ipc, cspace };
        cb(&mut context)
    }

    pub fn ipc(&mut self) -> &mut IpcBuffer {
        unsafe { &mut *self.ipc }
    }
}

impl AbstractUntyped for UntypedCap {
    type Context = UntypedCapContext;

    fn from_cptr_bits(bits: u64) -> Self {
        Self(Untyped::from_bits(bits))
    }

    fn to_cptr_bits(&self) -> u64 {
        self.0.bits()
    }

    fn untyped_split(&self, ctx: &mut UntypedCapContext, output_size_bits: u8, output_start: u64) {
        let cspace = ctx.cspace.absolute_cptr_for_self();
        let ipc = ctx.ipc();

        let ret = ipc.inner_mut().seL4_Untyped_Retype(
            self.0.bits(),
            sel4::sys::api_object::seL4_UntypedObject.into(),
            output_size_bits as _,
            cspace.root().bits(),
            cspace.path().bits(),
            cspace.path().depth() as _,
            output_start as _,
            2,
        );
        assert_eq!(ret, 0, "untyped_retype failed");
    }

    fn relocate(&self, ctx: &mut UntypedCapContext, target: u64) {
        let dst = ctx.cspace.absolute_cptr(CPtr::from_bits(target));
        let src = ctx.cspace.absolute_cptr(self.0.cptr());
        let ipc = ctx.ipc();
        let ret = ipc.inner_mut().seL4_CNode_Move(
            dst.root().bits(),
            dst.path().bits(),
            dst.path().depth() as _,
            src.root().bits(),
            src.path().bits(),
            src.path().depth() as _,
        );
        assert_eq!(ret, 0, "seL4_CNode_Move failed");
    }
}
