//! The console UART's receive interrupt, proved end to end on the machine.
//!
//! Every link has to be real for bytes to arrive here: the device model bound the driver
//! from what firmware described, the platform translated its interrupt and registered the
//! handler in the device model's table, the controller routes the line to this CPU, the
//! architecture's interrupt path hands device lines to the table, and the handler queued
//! what the part received. The check prints a prompt, the harness types a known string
//! (`kbuild/src/qemu.rs`, `SERIAL_PROBES`), and the bytes must come back through all of it.
//!
//! It fails if any byte is missing or wrong, if no receive interrupt ran, if the
//! interrupts were not dispatched through the device model, or if any interrupt reached
//! a line with no handler. It never concludes success from nothing having gone wrong: a
//! round that sees no bytes fails, whatever the reason.
//!
//! Where the platform can take the console away, it does, between the two rounds: unbind
//! the driver, which must unregister its handler and give back its resources, and bind
//! it again. The second round then proves the rebound driver receives the same way.

use arch::Cpu;
use hal::{Arch, EarlyConsole};
use time::Clock;

use crate::Check;

/// The prompts the check prints and the strings the harness types at them. Must match
/// `SERIAL_PROBES` in `kbuild/src/qemu.rs` byte for byte.
const PROBES: [(&str, &[u8]); 2] = [
    ("serial probe 1: waiting for input", b"kintane-probe-1"),
    ("serial probe 2: waiting for input", b"kintane-probe-2"),
];

/// How long a round waits for its bytes. Generous, because a busy CI host delays QEMU's
/// console by whole seconds; a round that gets its bytes ends as soon as it has them.
const WAIT_NS: u64 = 15_000_000_000;

pub fn check(c: &dyn EarlyConsole) -> Check {
    if !kconfig::SERIAL_IRQ_TEST {
        c.write_str("skipped: SERIAL_IRQ_TEST=n");
        return Check::Skipped;
    }
    let Some(line) = platform::console_line() else {
        c.write_str("skipped: no console on this platform receives on interrupt");
        return Check::Skipped;
    };
    c.write_str("console receives on line ");
    write_u64(c, u64::from(line));

    let first = round(c, 0);
    // SAFETY: from the boot path, masked, after discovery and before anything else uses
    // the console driver's binding: `rebind_console`'s contract.
    let rebound = unsafe { platform::rebind_console(c) };
    let second = match rebound {
        Some(true) => round(c, 1),
        Some(false) => false,
        None => {
            c.write_str("\n             not rebound: the console driver is not removable here");
            true
        }
    };
    let ok = first && rebound.unwrap_or(true) && second;
    c.write_str(if ok {
        "\n             ok"
    } else {
        "\n             FAILED"
    });
    Check::from_ok(ok)
}

/// One round: prompt, wait with interrupts enabled, and judge what arrived.
fn round(c: &dyn EarlyConsole, index: usize) -> bool {
    let Some(&(prompt, expected)) = PROBES.get(index) else {
        return false;
    };
    // Whatever is queued already arrived before this round asked for anything.
    while platform::console_read().is_some() {}
    let (irqs_before, bytes_before) = platform::console_received();
    let (dispatched_before, unhandled_before) = platform::device_interrupts();

    c.write_str("\n             ");
    c.write_str(prompt);
    c.write_str("\n");

    let waited = wait_for(expected.len() as u32, bytes_before);

    let mut got = [0u8; 32];
    let mut n = 0;
    while let Some(b) = platform::console_read() {
        if let Some(slot) = got.get_mut(n) {
            *slot = b;
        }
        n += 1;
    }
    let (irqs_after, bytes_after) = platform::console_received();
    let (dispatched_after, unhandled_after) = platform::device_interrupts();
    let irqs = irqs_after.wrapping_sub(irqs_before);
    let bytes = bytes_after.wrapping_sub(bytes_before);
    let dispatched = dispatched_after.wrapping_sub(dispatched_before);
    let unhandled = unhandled_after.wrapping_sub(unhandled_before);

    c.write_str("             probe ");
    write_u64(c, index as u64 + 1);
    c.write_str(": ");
    write_u64(c, u64::from(bytes));
    c.write_str(" bytes in ");
    write_u64(c, u64::from(irqs));
    c.write_str(" receive interrupts, ");
    write_u64(c, dispatched);
    c.write_str(" dispatched through the device model, ");
    write_u64(c, unhandled);
    c.write_str(" unhandled");

    let intact = got.get(..n) == Some(expected);
    match waited {
        None => {
            c.write_str(", NO CLOCK TO WAIT BY");
            false
        }
        Some(_) if !intact => {
            c.write_str(", RECEIVED ");
            c.write_bytes(got.get(..n.min(got.len())).unwrap_or(&[]));
            c.write_str(" INSTEAD OF ");
            c.write_bytes(expected);
            false
        }
        Some(_) if irqs == 0 => {
            c.write_str(", BYTES WITHOUT A RECEIVE INTERRUPT");
            false
        }
        Some(_) if dispatched == 0 => {
            c.write_str(", NOT DISPATCHED THROUGH THE DEVICE MODEL");
            false
        }
        Some(_) if unhandled != 0 => {
            c.write_str(", AN INTERRUPT REACHED NO HANDLER");
            false
        }
        Some(_) => true,
    }
}

/// Wait with interrupts enabled until `want` more bytes than `before` have been received,
/// or [`WAIT_NS`] passes. `None` when there is no clock to bound the wait with, which fails
/// the round rather than spinning for ever.
fn wait_for(want: u32, before: u32) -> Option<()> {
    let src = arch::clock_source()?;
    let mut clock = Clock::from_source(src).ok()?;
    let start = clock.advance(src.read());
    // SAFETY: the interrupt path is up (the interrupt selftest ran), the only device line
    // unmasked is the console's, whose handler is registered, and the scheduler's hook is
    // not installed yet, so an interrupt taken here returns to this loop.
    unsafe { arch::tick::enable_interrupts() };
    loop {
        let (_, bytes) = platform::console_received();
        if bytes.wrapping_sub(before) >= want {
            break;
        }
        let now = clock.advance(src.read());
        if now.saturating_duration_since(start).as_nanos() >= WAIT_NS {
            break;
        }
        core::hint::spin_loop();
    }
    // Masked again for the rest of bring-up. The previous state is discarded on purpose:
    // it is "enabled", and bring-up runs masked.
    let _ = Cpu::irq_save();
    Some(())
}

fn write_u64(c: &dyn EarlyConsole, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    c.write_bytes(&buf[i..]);
}
