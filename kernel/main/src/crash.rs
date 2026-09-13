//! Deliberate crashes, for checking that crash reports decode.
//!
//! Selected by the `CRASH_TEST` choice. Each crash happens two calls deep in functions
//! that are never inlined, so a symbolized backtrace has known names to show:
//! `crash::nested_panic` or `crash::nested_fault`, called from `crash::outer`. CI
//! greps for those names.

/// Crash now if the configuration asks for it; otherwise do nothing.
pub fn if_configured() {
    if kconfig::CRASH_PANIC || kconfig::CRASH_FAULT {
        outer();
    }
}

#[inline(never)]
fn outer() {
    if kconfig::CRASH_PANIC {
        nested_panic();
    }
    nested_fault();
}

#[inline(never)]
fn nested_panic() -> ! {
    panic!("deliberate panic (CRASH_PANIC)");
}

#[inline(never)]
fn nested_fault() -> ! {
    arch::backtrace::undefined_instruction()
}
