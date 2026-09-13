//! The time-stamp counter as the kernel's clock source, calibrated against the PIT.
//!
//! The TSC is the cheapest counter on a PC: one instruction, no port I/O, 64 bits. Its
//! weakness is that nothing tells the kernel how fast it counts. CPUID leaf 0x15 can on
//! recent Intel parts, but not on AMD, not on older parts, and not under most
//! emulators. So the rate is measured. PIT channel 2 counts down a known interval from
//! its fixed 1.193182 MHz input, and the TSC is read at either end.
//!
//! Channel 2 and not channel 0, because channel 0 drives IRQ 0 and belongs to whoever
//! owns the tick. Channel 2's output can be polled through port 0x61 with no interrupt
//! at all, which is why every PC kernel calibrates this way. Its other use is the PC
//! speaker, which is switched off for the measurement.
//!
//! What this does not establish: that the TSC keeps counting at that rate across CPUs
//! and power states. That needs CPUID's "invariant TSC" bit, and it matters once there
//! is more than one CPU or a deep idle state. Neither exists yet. The clock code
//! already holds time still if the counter steps backwards.
//!
//! Reference: Intel 8254 datasheet; the PC/AT port 0x61 wiring.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hal::{ClockSource, IrqNumber};

use crate::serial::{inb, outb};
use crate::{interrupt, pit};

/// Channel 2's counter port.
const CHANNEL2: u16 = 0x42;
/// The mode/command register.
const COMMAND: u16 = 0x43;
/// Command byte: channel 2, low byte then high byte, mode 0 (count down once), binary.
const CMD_CHANNEL2_ONESHOT: u8 = 0xB0;
/// System control port B: bit 0 gates channel 2, bit 1 connects it to the speaker, and
/// bit 5 reads channel 2's output.
const PORT_B: u16 = 0x61;
const GATE2: u8 = 1 << 0;
const SPEAKER: u8 = 1 << 1;
const OUT2: u8 = 1 << 5;

/// The calibration interval: 50 ms of PIT input cycles, which fits the 16-bit counter.
/// Longer is more accurate, and 50 ms of boot time is already noticeable.
const CALIBRATION_COUNT: u64 = pit::INPUT_HZ as u64 / 20;

/// Port reads allowed while waiting for channel 2. A PIT that never raises its output
/// fails calibration instead of hanging boot. Emulated port I/O is slow, and this is
/// still far more than 50 ms of polling.
const POLL_LIMIT: u64 = 20_000_000;

/// Plausible TSC rates. Anything outside this range means the measurement went wrong.
const MIN_HZ: u64 = 1_000_000;
const MAX_HZ: u64 = 100_000_000_000;

/// Measured rate in Hz. Zero until calibrated, and forever zero if calibration failed.
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
/// Set once calibration has been attempted, so failure is not retried every call.
static CALIBRATED: AtomicBool = AtomicBool::new(false);

/// The time-stamp counter. Private, so the only way to reach one is through
/// [`clock_source`], which checks that the instruction exists first.
struct Tsc;

static TSC: Tsc = Tsc;

fn rdtsc() -> u64 {
    // SAFETY: RDTSC is unprivileged unless CR4.TSD is set, which this kernel never
    // does, and it is only reached after CPUID reported the instruction exists.
    unsafe { core::arch::x86::_rdtsc() }
}

impl ClockSource for Tsc {
    fn name(&self) -> &'static str {
        "tsc"
    }

    fn read(&self) -> u64 {
        rdtsc()
    }

    fn bits(&self) -> u32 {
        64
    }

    fn frequency_hz(&self) -> u64 {
        TSC_HZ.load(Ordering::Relaxed)
    }
}

/// CPUID leaf 1, EDX bit 4.
fn has_tsc() -> bool {
    // CPUID and its leaf 1 exist on every CPU this port boots: the boot code already
    // requires SSE, which is newer than both.
    let leaf1 = core::arch::x86::__cpuid(1);
    leaf1.edx & (1 << 4) != 0
}

/// Time `CALIBRATION_COUNT` PIT input cycles in TSC ticks, and derive the TSC rate.
fn calibrate() -> Option<u64> {
    if !has_tsc() {
        return None;
    }
    let count = CALIBRATION_COUNT as u16;
    // SAFETY: port 0x61 and PIT channel 2 have no other user in this kernel, and the
    // command byte plus the two count bytes are written with nothing between them that
    // touches the PIT. Channel 0's reload value is unaffected: the command byte selects
    // channel 2 only. The speaker bit is cleared, so the only effect outside the
    // measurement is silence.
    let (t0, t1, done) = unsafe {
        let b = inb(PORT_B);
        outb(PORT_B, (b & !SPEAKER) | GATE2);
        outb(COMMAND, CMD_CHANNEL2_ONESHOT);
        outb(CHANNEL2, (count & 0xff) as u8);
        outb(CHANNEL2, (count >> 8) as u8);
        let t0 = rdtsc();
        let mut polls = 0;
        while inb(PORT_B) & OUT2 == 0 && polls < POLL_LIMIT {
            polls += 1;
        }
        let t1 = rdtsc();
        outb(PORT_B, b & !(SPEAKER | GATE2));
        (t0, t1, polls < POLL_LIMIT)
    };
    if !done || t1 <= t0 {
        return None;
    }
    // Hz = ticks * PIT input rate / PIT cycles. The multiply overflows only for a counter
    // hundreds of terahertz fast, and then the calibration fails rather than wraps.
    let hz = (t1 - t0).checked_mul(u64::from(pit::INPUT_HZ))? / CALIBRATION_COUNT;
    (MIN_HZ..=MAX_HZ).contains(&hz).then_some(hz)
}

/// The machine's clock source, calibrating it on the first call.
///
/// `None` if the CPU has no TSC or the calibration did not produce a plausible rate.
/// The first call takes 50 ms and must come from the boot path, with nothing else
/// programming the PIT.
pub fn clock_source() -> Option<&'static dyn ClockSource> {
    if !CALIBRATED.swap(true, Ordering::Relaxed) {
        if let Some(hz) = calibrate() {
            TSC_HZ.store(hz, Ordering::Relaxed);
        }
    }
    (TSC_HZ.load(Ordering::Relaxed) != 0).then_some(&TSC as &dyn ClockSource)
}

/// Timer interrupt rate during the wait. The same rate `interrupt_selftest` uses, set
/// again here so the period reported is one this code chose.
const SPIN_HZ: u32 = 1000;

/// Spins allowed while waiting. Ten ticks at 1 kHz take about 10 ms. Under QEMU's TCG
/// this budget lasts about five seconds, so a timer that never fires fails the check in
/// seconds and does not run into the harness's timeout. (Measured: 400 million spins
/// took 41 s.)
const SPIN_LIMIT: u64 = 50_000_000;

/// Busy-wait with interrupts enabled until `wanted` timer interrupts have been taken.
///
/// Returns how many were taken and the nominal interval between them in nanoseconds.
/// Reprograms PIT channel 0 to 1 kHz, which is how `interrupt_selftest` leaves it, and
/// leaves IRQ 0 masked and interrupts disabled again. Bounded, so a timer that stops
/// shows up as a short count, not a hang.
pub fn spin_with_timer_interrupts(wanted: u64) -> (u64, u64) {
    interrupt::init();
    let chip = interrupt::irq_chip();
    let timer = IrqNumber(0);

    // SAFETY: interrupts are masked by the caller's contract, and nothing else
    // programs channel 0 while this runs.
    let divisor = unsafe { pit::start_periodic(SPIN_HZ) };
    // A divisor of 0 means 65536 in the chip's arithmetic.
    let cycles = if divisor == 0 {
        65_536
    } else {
        u64::from(divisor)
    };
    let period_ns = cycles * 1_000_000_000 / u64::from(pit::INPUT_HZ);

    let before = interrupt::TICKS.load(Ordering::Relaxed);
    let target = before.saturating_add(wanted);
    chip.enable(timer);
    // SAFETY: the IDT is loaded and the only unmasked line is the timer, whose handler
    // counts and acknowledges it.
    unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };
    let mut spins = 0;
    while interrupt::TICKS.load(Ordering::Relaxed) < target && spins < SPIN_LIMIT {
        spins += 1;
        core::hint::spin_loop();
    }
    // SAFETY: masking interrupts is always sound.
    unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)) };
    chip.disable(timer);

    (
        interrupt::TICKS
            .load(Ordering::Relaxed)
            .saturating_sub(before),
        period_ns,
    )
}
