use core::any::Any;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct VcpuStateMask: u64 {
        const EIP = 1 << 0;
        const ESP = 1 << 1;
        const RFLAGS = 1 << 2;
        const EAX = 1 << 3;
        const EBX = 1 << 4;
        const ECX = 1 << 5;
        const EDX = 1 << 6;
        const ESI = 1 << 7;
        const EDI = 1 << 8;
        const EBP = 1 << 9;
        const R8 = 1 << 10;
        const R9 = 1 << 11;
        const R10 = 1 << 12;
        const R11 = 1 << 13;
        const R12 = 1 << 14;
        const R13 = 1 << 15;
        const R14 = 1 << 16;
        const R15 = 1 << 17;
        const CR0 = 1 << 18;
        const CR3 = 1 << 19;
        const CR4 = 1 << 20;
        const CS_ACCESS_RIGHTS = 1 << 21;
        const ACTIVITY_STATE = 1 << 22;
    }
}

impl VcpuStateMask {
    pub fn all_writable() -> Self {
        Self::all() - Self::CS_ACCESS_RIGHTS - Self::ACTIVITY_STATE
    }

    pub fn reg_state() -> Self {
        Self::all() - Self::CS_ACCESS_RIGHTS - Self::ACTIVITY_STATE
    }
}

#[derive(Debug, Clone, Default)]
pub struct VcpuFault {
    pub reason: u64,
    pub qualification: u64,
    pub instruction_len: u64,
    pub guest_physical: u64,
    pub guest_int: u64,
}

#[derive(Debug, Clone, Default)]
pub struct VcpuState {
    pub valid: VcpuStateMask,

    // GPR
    pub eip: u64,
    pub esp: u64,
    pub rflags: u64,
    pub eax: u64,
    pub ebx: u64,
    pub ecx: u64,
    pub edx: u64,
    pub esi: u64,
    pub edi: u64,
    pub ebp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // control registers
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,

    pub cs_access_rights: u32,

    pub activity_state: u8,
}

impl VcpuState {
    pub fn cs_access_rights_dpl(&self) -> u8 {
        ((self.cs_access_rights >> 5) & 0b11) as u8
    }
}

#[derive(Default, Copy, Clone, Debug)]
pub struct InterruptBitmap {
    pub lo: u128,
    pub hi: u128,
}

impl InterruptBitmap {
    pub fn is_empty(&self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    pub fn first(&self) -> u8 {
        let idx = self.lo.trailing_zeros();
        if idx != 128 {
            return idx as u8;
        }

        let idx = self.hi.trailing_zeros();
        if idx != 128 {
            return idx as u8 + 128;
        }

        panic!("first() called on empty InterruptBitmap");
    }

    pub fn activate(&mut self, intr: u8) {
        if intr < 128 {
            self.lo |= 1 << intr;
        } else {
            self.hi |= 1 << (intr - 128);
        }
    }

    pub fn deactivate(&mut self, intr: u8) {
        if intr < 128 {
            self.lo &= !(1 << intr);
        } else {
            self.hi &= !(1 << (intr - 128));
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum VcpuException {
    InvalidOpcode,
    GeneralProtectionFault(u32),
}

pub trait AbstractVcpu: Any {
    type Context;

    fn state(&self) -> &VcpuState;
    fn state_mut(&mut self) -> &mut VcpuState;
    fn fault(&self) -> &VcpuFault;
    fn fault_mut(&mut self) -> &mut VcpuFault;
    fn load_state(&mut self, context: &mut Self::Context, regs: VcpuStateMask);
    fn commit_state(&mut self, context: &mut Self::Context, regs: VcpuStateMask);

    fn inject_exception(&mut self, context: &mut Self::Context, exc: VcpuException);
    fn inject_external_interrupt(&mut self, context: &mut Self::Context, intr: u8);
    fn external_interrupt_pending(&self) -> bool;

    fn read_msr(&mut self, context: &mut Self::Context, msr: u32) -> Option<u64>;
    fn write_msr(&mut self, context: &mut Self::Context, msr: u32, value: u64) -> Option<u64>;

    fn lgdt(&mut self, context: &mut Self::Context, base: u64, limit: u16);

    fn enter(&mut self, context: &mut Self::Context) -> (bool, u64);
}
