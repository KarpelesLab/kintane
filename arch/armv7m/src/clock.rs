//! SysTick as the kernel's clock source, and the timer interrupts the clock check waits
//! through.
//!
//! SysTick is a 24-bit down-counter with no free-running register: `CVR` counts from
//! `RVR` to zero, reloads, and pends the SysTick exception. A clock is built from it the
//! way the counter leaves no choice about: the reload set to the full 24 bits, the
//! exception counting wraps, and a read combining the wraps with how far down this lap
//! has got.
//!
//! The one race is a wrap that has happened but whose exception has not run, because the
//! reader masks it. `ICSR.PENDSTSET` says so. [`SysTick::read`] samples it on both sides
//! of reading `CVR` and counts the wrap if it is pending, re-reading the counter if the
//! wrap landed between the samples, so a read is never a lap behind.
//!
//! **Zero is not where a lap ends.** The counter pends its exception on reaching zero and
//! reloads on the tick after, so a zero with the exception pending is the last count of
//! the lap, not the first of the next. And a counter just enabled holds the zero its
//! clearing wrote, and reloads from it *without* pending anything, because it did not
//! count down to it. The first version of this clock read that zero as a lap nearly
//! complete, and the next read, after the reload, as a lap barely begun: time stepped
//! back by a lap. The interrupt selftest measured its one-second deadline from such a
//! read about one boot in twenty-five, found it long passed, and reported that the timer
//! never fired. [`start`] therefore waits out that first reload before anything reads.

use hal::{Arch, ClockSource};

use crate::counter::Counter;
use crate::{Armv7m, scs, tick, timer};

/// `SYST_CSR.ENABLE`, `.TICKINT` and `.CLKSOURCE` (the processor clock).
const CSR_RUN: u32 = (1 << 0) | (1 << 1) | (1 << 2);

/// The full 24 bits: one lap is 2^24 counts.
pub const RELOAD: u32 = 0x00FF_FFFF;

/// The AN385's system clock, which drives the Cortex-M3 and so SysTick's processor-clock
/// source.
pub const FREQUENCY: u64 = 25_000_000;

/// Laps SysTick has completed, counted by its exception.
pub static WRAPS: Counter = Counter::new();

/// The SysTick exception: one more lap.
#[unsafe(no_mangle)]
extern "C" fn armv7m_systick() {
    WRAPS.increment();
}

/// SysTick as a monotonic count.
pub struct SysTick;

pub static COUNTER: SysTick = SysTick;

impl ClockSource for SysTick {
    fn name(&self) -> &'static str {
        "systick"
    }

    fn read(&self) -> u64 {
        start();
        let irq = Armv7m::irq_save();
        // SAFETY: SCS registers every ARMv7-M core has; reading ICSR and CVR has no side
        // effects. Masked, so the wrap count cannot change between the samples.
        let ticks = unsafe {
            let wraps = WRAPS.get_masked();
            let before = scs::read(scs::ICSR) & scs::ICSR_PENDSTSET != 0;
            let mut value = scs::read(scs::SYST_CVR) & RELOAD;
            let after = scs::read(scs::ICSR) & scs::ICSR_PENDSTSET != 0;
            if after && !before {
                // The wrap came between the samples; `value` may be from either lap.
                value = scs::read(scs::SYST_CVR) & RELOAD;
            }
            // A pending wrap is a completed lap once the counter has reloaded past zero.
            let laps = wraps + u64::from(after && value != 0);
            laps * (u64::from(RELOAD) + 1) + u64::from(RELOAD - value)
        };
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Armv7m::irq_restore(irq) };
        ticks
    }

    /// Computed in 64 bits: laps times a lap plus the lap's progress. At 25 MHz that
    /// outlasts the machine.
    fn bits(&self) -> u32 {
        64
    }

    fn frequency_hz(&self) -> u64 {
        FREQUENCY
    }
}

/// The longest the first reload is waited for. At 25 MHz it is one clock period; the
/// bound is for a SysTick that is not counting at all.
const RELOAD_SPINS: u32 = 1_000_000;

/// Start SysTick running laps, if it is not already. Idempotent, and cheap once running.
///
/// Returns once the counter has left the zero that enabling it starts from; see the
/// module documentation for why a read must never see that zero.
pub fn start() {
    // SAFETY: SYST_CSR is always present; reading it clears only COUNTFLAG, which
    // nothing here uses.
    if unsafe { scs::read(scs::SYST_CSR) } & CSR_RUN == CSR_RUN {
        return;
    }
    let irq = Armv7m::irq_save();
    // SAFETY: masked. The reload is written before the counter is cleared and enabled,
    // as the ARM ARM asks, and writing CVR sets it to zero.
    unsafe {
        scs::write(scs::SYST_CSR, 0);
        scs::write(scs::SYST_RVR, RELOAD);
        scs::write(scs::SYST_CVR, 0);
        scs::write(scs::SYST_CSR, CSR_RUN);
        let mut spins = 0;
        while scs::read(scs::SYST_CVR) & RELOAD == 0 && spins < RELOAD_SPINS {
            core::hint::spin_loop();
            spins += 1;
        }
    }
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Armv7m::irq_restore(irq) };
}

/// The machine's clock source.
pub fn clock_source() -> Option<&'static dyn ClockSource> {
    Some(&COUNTER)
}

/// Timer interrupts during the wait are this fraction of a second apart: 2 ms.
pub const PERIOD_DIVISOR: u64 = 500;

/// Busy-wait with interrupts enabled until `wanted` timer interrupts have been taken.
///
/// Returns how many were taken and the nominal interval between them in nanoseconds.
/// Each comes from its own one-shot, since the handler disarms the timer every time.
/// Bounded by SysTick, so a timer that never fires is a short count, not a hang.
/// Leaves interrupts masked and the timer disabled.
pub fn spin_with_timer_interrupts(wanted: u64) -> (u64, u64) {
    let period = (timer::FREQUENCY / PERIOD_DIVISOR).max(1);
    let period_ns = period * 1_000_000_000 / timer::FREQUENCY;
    let start = tick::ticks();

    timer::set_enabled(true);
    let limit = COUNTER
        .read()
        .wrapping_add(FREQUENCY / PERIOD_DIVISOR * wanted * 10);
    let mut taken = 0;
    while taken < wanted {
        let before = tick::ticks();
        // Masked on entry — the caller's state — and again at the bottom of each round.
        let _ = Armv7m::irq_save();
        // SAFETY: masked for the writes, and the handler disarms it again.
        unsafe { timer::arm(period as u32) };
        // SAFETY: the vector table is installed and the only enabled interrupt is the
        // timer, whose handler disarms and counts it; masked again below.
        unsafe { tick::enable_interrupts() };
        while tick::ticks() == before && COUNTER.read() < limit {
            core::hint::spin_loop();
        }
        let _ = Armv7m::irq_save();
        if tick::ticks() == before {
            break;
        }
        taken = tick::ticks().wrapping_sub(start);
    }
    tick::stop();
    (tick::ticks().wrapping_sub(start), period_ns)
}
