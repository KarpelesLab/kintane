//! Lock-order checking's findings, printed, and turned into part of the boot verdict.
//!
//! `sync::lockdep` records what it finds and prints nothing, because printing is not
//! something a lock may do. This is where the kernel asks. In a build with checking on,
//! which is every debug build by default, any violation fails the boot. A lock-order
//! bug found at boot and only logged is one that ships.
//!
//! `LOCKDEP_ABBA_TEST` inverts the expectation, to prove the path from a real
//! inversion to a failed verdict works. Two kernel threads take two locks in opposite
//! orders ([`abba`]), and the verdict passes only if exactly that inversion was
//! reported.

use core::sync::atomic::{AtomicBool, Ordering};

use arch::Cpu;
use hal::{Arch, EarlyConsole};
use sync::SpinLock;
use sync::lockdep::{self, LockClass, Violation};
use time::Duration;

use crate::preempt::{self, begin, exit_thread, sleep_until};
use crate::{Check, timekeeping, write_usize};

static TEST_A: LockClass = LockClass::new("test.abba.a");
static TEST_B: LockClass = LockClass::new("test.abba.b");

static LOCK_A: SpinLock<(), Cpu> = SpinLock::with_class((), &TEST_A);
static LOCK_B: SpinLock<(), Cpu> = SpinLock::with_class((), &TEST_B);

static FIRST_DONE: AtomicBool = AtomicBool::new(false);
static SECOND_DONE: AtomicBool = AtomicBool::new(false);

/// Takes A, then B.
extern "C" fn first(_: usize) -> ! {
    begin();
    {
        let _a = LOCK_A.lock_irqsave();
        let _b = LOCK_B.lock_irqsave();
    }
    FIRST_DONE.store(true, Ordering::Relaxed);
    exit_thread()
}

/// Takes B, then A: the inversion. Runs after `first` has released both, so the order
/// is wrong and nothing deadlocks.
extern "C" fn second(_: usize) -> ! {
    begin();
    {
        let _b = LOCK_B.lock_irqsave();
        let _a = LOCK_A.lock_irqsave();
    }
    SECOND_DONE.store(true, Ordering::Relaxed);
    exit_thread()
}

/// Run the two threads, `first` at the higher priority so it finishes before `second`
/// starts. Called from `shared::run`, on the boot thread, with the scheduler running.
pub fn abba(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  abba test  ");
    let irq = Cpu::irq_save();
    let a = preempt::spawn(1, first, 0, 7);
    let b = preempt::spawn(2, second, 0, 6);
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    let (Some(a), Some(b)) = (a, b) else {
        c.write_str("spawn refused");
        return Check::Failed;
    };
    sleep_until(timekeeping::now().saturating_add(Duration::from_nanos(30_000_000)));
    let finished = FIRST_DONE.load(Ordering::Relaxed) && SECOND_DONE.load(Ordering::Relaxed);
    let reaped = preempt::reap(a) & preempt::reap(b);
    c.write_str(if finished && reaped {
        "A then B, then B then A, on two threads"
    } else {
        "THE THREADS DID NOT FINISH"
    });
    Check::from_ok(finished && reaped)
}

/// Print what lock-order checking found and judge it.
pub fn verdict(c: &dyn EarlyConsole) -> Check {
    if !lockdep::ENABLED {
        c.write_str("not built in (DEBUG_LOCKDEP=n)");
        return Check::Skipped;
    }
    let report = lockdep::report::<Cpu>();
    write_usize(c, report.count);
    c.write_str(" violations");
    if let Some(v) = report.first {
        c.write_str(", first: ");
        describe(c, v);
    }

    let expected = Violation::Inversion {
        held: TEST_B.name(),
        acquiring: TEST_A.name(),
    };
    let ok = if kconfig::LOCKDEP_ABBA_TEST {
        c.write_str(" (expected the test's inversion)");
        report.count == 1 && report.first == Some(expected)
    } else {
        report.count == 0
    };
    c.write_str(if ok { " ok" } else { " FAILED" });
    Check::from_ok(ok)
}

fn describe(c: &dyn EarlyConsole, v: Violation) {
    match v {
        Violation::Inversion { held, acquiring } => {
            c.write_str("took ");
            c.write_str(acquiring);
            c.write_str(" while holding ");
            c.write_str(held);
            c.write_str(", the reverse of an order already seen");
        }
        Violation::Recursive { class } => {
            c.write_str("recursive acquisition of ");
            c.write_str(class);
        }
        Violation::SameClass { class } => {
            c.write_str("two locks of class ");
            c.write_str(class);
            c.write_str(" nested");
        }
        Violation::TooDeep { class } => {
            c.write_str("too many locks held taking ");
            c.write_str(class);
        }
        Violation::TooManyClasses { class } => {
            c.write_str("too many classes to track ");
            c.write_str(class);
        }
        Violation::Unbalanced { class } => {
            c.write_str("release of an untracked ");
            c.write_str(class);
        }
    }
}
