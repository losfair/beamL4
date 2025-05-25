use algorithms::vm::vcpu::{AbstractVcpu, VcpuStateMask};

#[rustfmt::skip]
pub fn dump_state<C: 'static>(ctx: &mut C, vcpu: &mut dyn AbstractVcpu<Context = C>) {
    type M = VcpuStateMask;

    vcpu.load_state(
        ctx,
        M::CR0 |
        M::CR3 |
        M::CR4 |
        M::RFLAGS |
        M::ESP |
        M::EIP | M::ACTIVITY_STATE
    );
    let efer = vcpu.read_msr(ctx, 0xC0000080).expect("Failed to read EFER");
    let st = vcpu.state();
    println!("VCPU state:");
    print!(  "  CR0:       {:#018x}", st.cr0);
    println!("  CR3:       {:#018x}", st.cr3);
    print!(  "  CR4:       {:#018x}", st.cr4);
    println!("  EFER:      {:#018x}", efer);
    print!(  "  RFLAGS:    {:#018x}", st.rflags);
    println!("  RIP:       {:#018x}", st.eip);
    print!(  "  RSP:       {:#018x}", st.esp);
    println!("  RAX:       {:#018x}", st.eax);
    print!(  "  RBX:       {:#018x}", st.ebx);
    println!("  RCX:       {:#018x}", st.ecx);
    print!(  "  RDX:       {:#018x}", st.edx);
    println!("  RSI:       {:#018x}", st.esi);
    print!(  "  RDI:       {:#018x}", st.edi);
    println!("  RBP:       {:#018x}", st.ebp);
    print!(  "  R8:        {:#018x}", st.r8);
    println!("  R9:        {:#018x}", st.r9);
    print!(  "  R10:       {:#018x}", st.r10);
    println!("  R11:       {:#018x}", st.r11);
    print!(  "  R12:       {:#018x}", st.r12);
    println!("  R13:       {:#018x}", st.r13);
    print!(  "  R14:       {:#018x}", st.r14);
    println!("  R15:       {:#018x}", st.r15);
    println!("  Activity:  {:#018x}", st.activity_state);
}
