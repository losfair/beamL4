.globl do_vmcall
do_vmcall:
    movq %rbx, %r10
    movq %rdi, %rax
    movq %rsi, %rbx
    movq %rdx, %r11
    movq %rcx, %rdx
    movq %r11, %rcx
    movq %r8, %rsi
    vmcall
    movq %r10, %rbx
    ret
