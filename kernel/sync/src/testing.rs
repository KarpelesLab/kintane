//! Helpers shared by this unit's host tests. Compiled only under `cfg(test)`.

use std::sync::{Mutex, MutexGuard};

use hal::Arch;

/// Serialises the tests that observe interrupt state.
///
/// The mock architectures keep their interrupt flag in a process-wide static
/// (`hal/src/mock.rs`), and the test harness runs tests on several threads. Without
/// this, a test asserting "interrupts are enabled here" would occasionally observe
/// another test's critical section. `docs/testing.md` is explicit that a flaky test is
/// treated as a real bug rather than retried, so the shared state is serialised rather
/// than hoped about.
static SERIAL: Mutex<()> = Mutex::new(());

/// Take the interrupt-state test lock for the rest of the current test.
pub fn serial() -> MutexGuard<'static, ()> {
    match SERIAL.lock() {
        Ok(g) => g,
        // A test that failed while holding this poisoned the mutex. The data is `()`,
        // so there is nothing to be inconsistent, and the remaining tests are more
        // useful run than skipped.
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Whether interrupts are currently enabled on the mock machine `A`.
///
/// The mocks expose their flag only through `irq_save`, which also masks, so reading
/// it means saving and immediately restoring. That is exactly what a nesting-correct
/// guard does, and it leaves the state as it found it.
pub fn interrupts_enabled<A: Arch<IrqState = bool>>() -> bool {
    let state = A::irq_save();
    // SAFETY: `state` came from the `irq_save` one line above, on this thread, and is
    // restored exactly once.
    unsafe { A::irq_restore(state) };
    state
}
