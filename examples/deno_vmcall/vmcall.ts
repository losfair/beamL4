/*
0000000000000000 <do_vmcall>:
   0:   49 89 da                mov    %rbx,%r10
   3:   48 89 f8                mov    %rdi,%rax
   6:   48 89 f3                mov    %rsi,%rbx
   9:   49 89 d3                mov    %rdx,%r11
   c:   48 89 ca                mov    %rcx,%rdx
   f:   4c 89 d9                mov    %r11,%rcx
  12:   4c 89 c6                mov    %r8,%rsi
  15:   0f 01 c1                vmcall
  18:   4c 89 d3                mov    %r10,%rbx
  1b:   c3                      ret
*/
const doVmcall_code = new Uint8Array([
    0x49, 0x89, 0xda, // mov %rbx,%r10
    0x48, 0x89, 0xf8, // mov %rdi,%rax
    0x48, 0x89, 0xf3, // mov %rsi,%rbx
    0x49, 0x89, 0xd3, // mov %rdx,%r11
    0x48, 0x89, 0xca, // mov %rcx,%rdx
    0x4c, 0x89, 0xd9, // mov %r11,%rcx
    0x4c, 0x89, 0xc6, // mov %r8,%rsi
    0x0f, 0x01, 0xc1, // vmcall
    0x4c, 0x89, 0xd3, // mov %r10,%rbx
    0xc3,             // ret
])

export const vmcallLibcSymbols = Object.freeze({
    mmap: {
        parameters: [
            "u32",
            "u32",
            "u32",
            "u32",
            "i32",
            "i32",
        ],
        result: "pointer",
    },
    mprotect: {
        parameters: [
            "pointer",
            "u32",
            "u32",
        ],
        result: "i32",
    }
}) satisfies Readonly<Deno.ForeignLibraryInterface>;

export const vmcallSymbol = Object.freeze({
    parameters: ["u64", "u64", "u64", "u64", "u64"] as const,
    result: "u64",
}) satisfies Readonly<Deno.ForeignFunction>;

export class Vmcall {
    libc: Deno.DynamicLibrary<typeof vmcallLibcSymbols>;
    vmcall: Deno.UnsafeFnPointer<typeof vmcallSymbol>;

    constructor() {
        this.libc = Deno.dlopen("libc.so.6", vmcallLibcSymbols);
        const codePage = this.libc.symbols.mmap(
            0,
            4096,
            1 | 2, // PROT_READ | PROT_WRITE
            0x20 | 0x02, // MAP_ANONYMOUS | MAP_PRIVATE
            -1,
            0);
        if (codePage === null) {
            throw new Error("Failed to allocate memory");
        }
        new Uint8Array(Deno.UnsafePointerView.getArrayBuffer(codePage, 4096), 0, doVmcall_code.length)
            .set(doVmcall_code);
        const ret = this.libc.symbols.mprotect(
            codePage,
            4096,
            1 | 4, // PROT_READ | PROT_EXEC
        );
        if (ret !== 0) {
            throw new Error("Failed to mprotect");
        }
        this.vmcall = new Deno.UnsafeFnPointer(codePage as Deno.PointerObject<typeof vmcallSymbol>, vmcallSymbol);
    }
}