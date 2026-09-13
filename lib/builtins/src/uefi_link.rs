//! Symbols a UEFI link demands and no UEFI loader of ours calls.
//!
//! The UEFI targets link with lld-link, which has a rule the kernel's ELF linker does
//! not. ELF lld only reports an undefined symbol that live code references. lld-link
//! reports every undefined symbol in every object it pulls in, *before* `/OPT:REF`
//! discards the unreferenced functions. `core` puts integer and float formatting in the
//! same objects, so the first `write!` of an integer pulls in `f32` comparisons,
//! `f64` division and `u128` division. Nothing calls them, but every one of them must
//! resolve.
//!
//! Upstream `compiler_builtins` resolves them with real software-float code. This crate
//! refuses to grow that code for functions no loader runs. Each symbol below instead
//! resolves to an instruction that traps, followed by a marker string:
//!
//! - **Uncalled**, `/OPT:REF` removes the stub along with the dead float code that referenced it,
//!   and the image contains neither.
//! - **Called**, the stub survives and so does its marker. kbuild scans every UEFI image it links
//!   for the marker and fails the build, naming this file. So a stub never ships in a live code
//!   path: a loader that starts using floats fails its build, not its boot.
//!
//! `_fltused` is the exception: it is a data marker the MSVC ABI expects of any object
//! that touches floating point, not a function, and zero is its only meaning.

/// Must match `kbuild/src/main.rs`, which searches linked UEFI images for it.
macro_rules! trap_stubs {
    ($($name:ident),* $(,)?) => {
        $(
            /// Traps. See the module documentation: this must never be reachable.
            #[unsafe(no_mangle)]
            #[unsafe(naked)]
            pub unsafe extern "C" fn $name() {
                core::arch::naked_asm!("ud2", ".ascii \"KBUILD-UNREACHABLE-INTRINSIC\"");
            }
        )*
    };
}

trap_stubs!(
    __divdf3,
    __divsf3,
    __extendhfsf2,
    __floatdidf,
    __floatdisf,
    __gedf2,
    __gesf2,
    __gtdf2,
    __gtsf2,
    __ledf2,
    __lesf2,
    __ltdf2,
    __ltsf2,
    __muldf3,
    __mulsf3,
    __nedf2,
    __nesf2,
    __truncsfhf2,
    __udivti3,
    __unorddf2,
    __unordsf2,
    fmaximum_num,
    fmaximum_numf,
    fminimum_num,
    fminimum_numf,
);

#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;
