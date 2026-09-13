//! Stack probing for the UEFI loader.
//!
//! The built-in `x86_64-unknown-uefi` target inherits Windows' convention: a function
//! whose frame is larger than a page calls a probe first, which touches every page
//! the frame will occupy, in order, so that a guard page below the stack is hit
//! rather than jumped over. The kernel's own target specifications ask for inline
//! probes and never call this. The loader's target cannot be changed without a
//! hand-written specification, which is exactly what `docs/bootloader.md` promises the
//! loader does not need.
//!
//! The contract is the one LLVM emits calls for: the frame size arrives in `rax`, and
//! every register must survive except `r11` and the flags. The probe walks down from
//! the caller's stack pointer a page at a time, touching each page, and leaves `rsp`
//! as it found it: the caller subtracts the frame itself.
//!
//! UEFI firmware runs boot applications on a fully committed stack, so today no probe
//! ever lands on a guard. It is here because a missing symbol is a link failure the
//! first time a loader function grows a large local, and a probe that does nothing
//! would be a lie waiting for firmware that does guard its stacks.

/// # Safety
/// Called only by code LLVM generates, with the frame size in `rax`.
#[unsafe(naked)]
#[rustc_std_internal_symbol]
pub unsafe extern "C" fn __rust_probestack() {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "mov r11, rax",
        // The page at rsp is already touched by the call's return address.
        "cmp r11, 0x1000",
        "jna 3f",
        "2:",
        "sub rsp, 0x1000",
        "test qword ptr [rsp + 8], rsp",
        "sub r11, 0x1000",
        "cmp r11, 0x1000",
        "ja 2b",
        "3:",
        "sub rsp, r11",
        "test qword ptr [rsp + 8], rsp",
        // Restore the stack pointer: the caller allocates the frame itself.
        "mov rsp, rbp",
        "pop rbp",
        "ret",
    );
}
