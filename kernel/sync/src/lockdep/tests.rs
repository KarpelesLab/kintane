//! Two halves: the tracker's logic, on private `Tracker` values with no global state;
//! and the wiring, through real `SpinLock`s and `IrqLock`s on both mock profiles, which
//! report to the global tracker and so run one at a time from a reset.

use std::panic::{self, AssertUnwindSafe};

use hal::Arch;
use hal::mock::{MockFull, MockTiny};

use super::*;
use crate::testing::serial;
use crate::{IrqLock, SpinLock};

/// Enough distinct classes to exhaust the table. Elements of one static array have
/// distinct addresses, which is all a class needs.
static CLASSES: [LockClass; MAX_CLASSES + 4] = [const { LockClass::new("many") }; MAX_CLASSES + 4];

static A: LockClass = LockClass::new("a");
static B: LockClass = LockClass::new("b");
static C: LockClass = LockClass::new("c");
static D: LockClass = LockClass::new("d");

// ---- the tracker ----------------------------------------------------------------------

#[test]
fn a_consistent_order_is_never_reported() {
    let mut t = Tracker::new();
    for _ in 0..3 {
        t.acquire(&A, 1).unwrap();
        t.acquire(&B, 2).unwrap();
        t.acquire(&C, 3).unwrap();
        t.release(&C, 3).unwrap();
        t.release(&B, 2).unwrap();
        t.release(&A, 1).unwrap();
        // Skipping a level is consistent too: A then C was implied by A, B, C.
        t.acquire(&A, 1).unwrap();
        t.acquire(&C, 3).unwrap();
        t.release(&C, 3).unwrap();
        t.release(&A, 1).unwrap();
    }
    assert_eq!(
        t.report(),
        Report {
            count: 0,
            first: None
        }
    );
    assert_eq!(t.depth(), 0);
}

#[test]
fn abba_is_reported_without_the_deadlock_happening() {
    let mut t = Tracker::new();
    // One path: A then B. Released completely before the other path runs, so the two
    // never overlap in time. The inversion is still a deadlock waiting for two CPUs.
    t.acquire(&A, 1).unwrap();
    t.acquire(&B, 2).unwrap();
    t.release(&B, 2).unwrap();
    t.release(&A, 1).unwrap();

    t.acquire(&B, 2).unwrap();
    let inverted = Violation::Inversion {
        held: "b",
        acquiring: "a",
    };
    assert_eq!(t.acquire(&A, 1), Err(inverted));
    // Held either way, so it is pushed and its release balances.
    assert_eq!(t.depth(), 2);
    t.release(&A, 1).unwrap();
    t.release(&B, 2).unwrap();
    assert_eq!(
        t.report(),
        Report {
            count: 1,
            first: Some(inverted)
        }
    );

    // The inverted edge was not recorded, so the original order is still clean.
    t.acquire(&A, 1).unwrap();
    t.acquire(&B, 2).unwrap();
    assert_eq!(t.report().count, 1);
}

#[test]
fn an_inversion_through_intermediate_classes_is_reported() {
    let mut t = Tracker::new();
    for (outer, inner) in [(&A, &B), (&B, &C), (&C, &D)] {
        t.acquire(outer, 1).unwrap();
        t.acquire(inner, 2).unwrap();
        t.release(inner, 2).unwrap();
        t.release(outer, 1).unwrap();
    }
    // A, B, C and D were never all held together, but A before D follows.
    t.acquire(&D, 4).unwrap();
    assert_eq!(
        t.acquire(&A, 1),
        Err(Violation::Inversion {
            held: "d",
            acquiring: "a"
        })
    );
}

#[test]
fn an_inversion_between_classes_above_bit_32_is_reported() {
    // Where a shift or mask truncated to 32 bits would lose the edge.
    let mut t = Tracker::new();
    for (i, class) in CLASSES.iter().take(48).enumerate() {
        t.acquire(class, i).unwrap();
        t.release(class, i).unwrap();
    }
    let (outer, inner) = (&CLASSES[40], &CLASSES[47]);
    t.acquire(outer, 1).unwrap();
    t.acquire(inner, 2).unwrap();
    t.release(inner, 2).unwrap();
    t.release(outer, 1).unwrap();
    t.acquire(inner, 2).unwrap();
    assert!(matches!(t.acquire(outer, 1), Err(Violation::Inversion { .. })));
}

#[test]
fn taking_a_held_lock_again_is_recursion_and_is_not_pushed() {
    let mut t = Tracker::new();
    t.acquire(&A, 7).unwrap();
    assert_eq!(t.acquire(&A, 7), Err(Violation::Recursive { class: "a" }));
    assert_eq!(t.depth(), 1);
    t.release(&A, 7).unwrap();
    assert_eq!(t.depth(), 0);
    assert_eq!(t.report().count, 1);
}

#[test]
fn two_instances_of_one_class_nested_are_reported() {
    let mut t = Tracker::new();
    t.acquire(&A, 1).unwrap();
    assert_eq!(t.acquire(&A, 2), Err(Violation::SameClass { class: "a" }));
    t.release(&A, 1).unwrap();
    t.release(&A, 2).unwrap();
    assert_eq!(t.depth(), 0);
}

#[test]
fn releases_need_not_be_in_order() {
    let mut t = Tracker::new();
    t.acquire(&A, 1).unwrap();
    t.acquire(&B, 2).unwrap();
    t.acquire(&C, 3).unwrap();
    t.release(&A, 1).unwrap();
    t.release(&C, 3).unwrap();
    assert_eq!(t.depth(), 1);
    t.release(&B, 2).unwrap();
    assert_eq!(t.report().count, 0);
}

#[test]
fn a_try_lock_is_not_checked_but_what_it_holds_is() {
    let mut t = Tracker::new();
    t.acquire(&A, 1).unwrap();
    t.acquire(&B, 2).unwrap();
    t.release(&B, 2).unwrap();
    t.release(&A, 1).unwrap();

    // B then try A: cannot block, so not an inversion.
    t.acquire(&B, 2).unwrap();
    t.acquire_try(&A, 1).unwrap();
    // C under that A is recorded as after A, and so after B too.
    t.acquire(&C, 3).unwrap();
    t.release(&C, 3).unwrap();
    t.release(&A, 1).unwrap();
    t.release(&B, 2).unwrap();
    assert_eq!(t.report().count, 0);

    t.acquire(&C, 3).unwrap();
    assert!(matches!(t.acquire(&B, 2), Err(Violation::Inversion { .. })));
}

#[test]
fn holding_too_many_is_reported_and_stays_balanced() {
    let mut t = Tracker::new();
    for (i, class) in CLASSES.iter().take(MAX_HELD).enumerate() {
        t.acquire(class, i).unwrap();
    }
    let extra = CLASSES.get(MAX_HELD).unwrap();
    assert_eq!(t.acquire(extra, 99), Err(Violation::TooDeep { class: "many" }));
    assert_eq!(t.depth(), MAX_HELD);

    // The untracked lock's release is absorbed rather than reported as unbalanced.
    t.release(extra, 99).unwrap();
    for (i, class) in CLASSES.iter().take(MAX_HELD).enumerate() {
        t.release(class, i).unwrap();
    }
    assert_eq!(t.depth(), 0);
    assert_eq!(t.report().count, 1);
}

#[test]
fn too_many_classes_is_reported_and_the_rest_still_work() {
    let mut t = Tracker::new();
    for class in CLASSES.iter().take(MAX_CLASSES) {
        t.acquire(class, 1).unwrap();
        t.release(class, 1).unwrap();
    }
    let extra = CLASSES.get(MAX_CLASSES).unwrap();
    assert_eq!(t.acquire(extra, 1), Err(Violation::TooManyClasses { class: "many" }));
    t.release(extra, 1).unwrap();
    assert_eq!(t.report().count, 1);

    // Classes already known are still checked.
    let (x, y) = (&CLASSES[0], &CLASSES[1]);
    t.acquire(x, 1).unwrap();
    t.acquire(y, 2).unwrap();
    t.release(y, 2).unwrap();
    t.release(x, 1).unwrap();
    t.acquire(y, 2).unwrap();
    assert!(matches!(t.acquire(x, 1), Err(Violation::Inversion { .. })));
}

#[test]
fn a_release_never_taken_is_unbalanced() {
    let mut t = Tracker::new();
    assert_eq!(t.release(&A, 1), Err(Violation::Unbalanced { class: "a" }));
    t.acquire(&A, 1).unwrap();
    assert_eq!(t.release(&A, 2), Err(Violation::Unbalanced { class: "a" }));
}

#[test]
fn the_first_violation_is_kept() {
    let mut t = Tracker::new();
    t.acquire(&A, 1).unwrap();
    let _ = t.acquire(&A, 1);
    let _ = t.acquire(&A, 2);
    assert_eq!(
        t.report(),
        Report {
            count: 2,
            first: Some(Violation::Recursive { class: "a" })
        }
    );
}

// ---- through real locks ---------------------------------------------------------------

/// Violations the global tracker should have seen, given what a test provoked.
fn expected(provoked: usize) -> usize {
    if ENABLED { provoked } else { 0 }
}

/// Run `f` expecting the mock CPU to stop, which the mocks express as a panic.
fn stops(f: impl FnOnce()) -> bool {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let stopped = panic::catch_unwind(AssertUnwindSafe(f)).is_err();
    panic::set_hook(previous);
    stopped
}

#[test]
fn the_build_says_whether_checking_is_on() {
    assert_eq!(ENABLED, kconfig::DEBUG_LOCKDEP);
    assert_eq!(size_of::<ClassTag>() != 0, ENABLED);
}

#[test]
fn abba_through_spinlocks_is_reported_full() {
    static X: LockClass = LockClass::new("full.x");
    static Y: LockClass = LockClass::new("full.y");
    let _s = serial();
    reset::<MockFull>();

    let x: SpinLock<u32, MockFull> = SpinLock::with_class(0, &X);
    let y: SpinLock<u32, MockFull> = SpinLock::with_class(0, &Y);
    {
        let _gx = x.lock();
        let _gy = y.lock_irqsave();
    }
    assert_eq!(report::<MockFull>().count, 0);
    {
        let _gy = y.lock();
        let _gx = x.lock();
    }
    let r = report::<MockFull>();
    assert_eq!(r.count, expected(1));
    if ENABLED {
        let inverted = Violation::Inversion {
            held: "full.y",
            acquiring: "full.x",
        };
        assert_eq!(r.first, Some(inverted));
    }
}

#[test]
fn abba_through_irq_locks_is_reported_tiny() {
    static X: LockClass = LockClass::new("tiny.x");
    static Y: LockClass = LockClass::new("tiny.y");
    let _s = serial();
    reset::<MockTiny>();

    let x: IrqLock<u32, MockTiny> = IrqLock::with_class(0, &X);
    let y: IrqLock<u32, MockTiny> = IrqLock::with_class(0, &Y);
    {
        let _gx = x.lock();
        let _gy = y.lock();
    }
    {
        let _gy = y.lock();
        let _gx = x.lock();
    }
    assert_eq!(report::<MockTiny>().count, expected(1));
}

#[test]
fn a_consistent_order_through_real_locks_is_clean_full() {
    static X: LockClass = LockClass::new("full.outer");
    static Y: LockClass = LockClass::new("full.inner");
    let _s = serial();
    reset::<MockFull>();

    let x: SpinLock<u32, MockFull> = SpinLock::with_class(0, &X);
    let y: SpinLock<u32, MockFull> = SpinLock::with_class(0, &Y);
    for _ in 0..4 {
        let _gx = x.lock_irqsave();
        let _gy = y.lock();
        assert!(y.try_lock().is_none(), "a failed try_lock records nothing");
    }
    let _gy = y.lock();
    assert!(x.try_lock().is_some(), "a try_lock against the order cannot deadlock");
    assert_eq!(
        report::<MockFull>(),
        Report {
            count: 0,
            first: None
        }
    );
}

#[test]
fn a_consistent_order_through_real_locks_is_clean_tiny() {
    static X: LockClass = LockClass::new("tiny.outer");
    static Y: LockClass = LockClass::new("tiny.inner");
    let _s = serial();
    reset::<MockTiny>();

    let x: IrqLock<u32, MockTiny> = IrqLock::with_class(0, &X);
    let y: IrqLock<u32, MockTiny> = IrqLock::with_class(0, &Y);
    for _ in 0..4 {
        let _gx = x.lock();
        let _gy = y.lock();
    }
    let _gy = y.lock();
    assert!(x.try_lock().is_some());
    assert_eq!(
        report::<MockTiny>(),
        Report {
            count: 0,
            first: None
        }
    );
}

#[test]
fn re_taking_a_held_spinlock_stops_instead_of_hanging_full() {
    static X: LockClass = LockClass::new("full.self");
    let _s = serial();
    reset::<MockFull>();

    let x: SpinLock<u32, MockFull> = SpinLock::with_class(0, &X);
    // Without checking this would spin for ever, so the test only runs when it is on.
    if !ENABLED {
        return;
    }
    let held = x.lock();
    assert!(stops(|| drop(x.lock())));
    drop(held);
    let r = report::<MockFull>();
    assert_eq!(r.first, Some(Violation::Recursive { class: "full.self" }));
    // The tracker is not left busy or unbalanced by the stop.
    drop(x.lock());
    assert_eq!(report::<MockFull>().count, 1);
}

#[test]
fn re_taking_a_held_irq_lock_is_recorded_before_the_stop_tiny() {
    static X: LockClass = LockClass::new("tiny.self");
    let _s = serial();
    reset::<MockTiny>();

    let x: IrqLock<u32, MockTiny> = IrqLock::with_class(0, &X);
    let held = x.lock();
    assert!(stops(|| drop(x.lock())));
    drop(held);
    assert_eq!(report::<MockTiny>().count, expected(1));
    drop(x.lock());
    assert_eq!(report::<MockTiny>().count, expected(1));
}

#[test]
fn nesting_too_deep_is_reported_full() {
    let _s = serial();
    reset::<MockFull>();
    fn take(locks: &[SpinLock<u32, MockFull>]) {
        if let Some((first, rest)) = locks.split_first() {
            let _g = first.lock();
            take(rest);
        }
    }
    let locks: Vec<SpinLock<u32, MockFull>> = CLASSES
        .iter()
        .take(MAX_HELD + 1)
        .map(|c| SpinLock::with_class(0, c))
        .collect();
    take(&locks);
    let r = report::<MockFull>();
    assert_eq!(r.count, expected(1));
    if ENABLED {
        assert_eq!(r.first, Some(Violation::TooDeep { class: "many" }));
    }
    // Balanced afterwards: the next nesting is clean.
    take(&locks[..2]);
    assert_eq!(report::<MockFull>().count, expected(1));
}

#[test]
fn nesting_too_deep_is_reported_tiny() {
    let _s = serial();
    reset::<MockTiny>();
    fn take(locks: &[IrqLock<u32, MockTiny>]) {
        if let Some((first, rest)) = locks.split_first() {
            let _g = first.lock();
            take(rest);
        }
    }
    let locks: Vec<IrqLock<u32, MockTiny>> = CLASSES
        .iter()
        .take(MAX_HELD + 1)
        .map(|c| IrqLock::with_class(0, c))
        .collect();
    take(&locks);
    assert_eq!(report::<MockTiny>().count, expected(1));
    take(&locks[..2]);
    assert_eq!(report::<MockTiny>().count, expected(1));
}

#[test]
fn contention_between_two_cpus_is_not_recursion_full() {
    // The regression that split the held stack from the shared order: with one stack
    // for everything, the second thread's wait for a lock the first holds looked like
    // the first re-taking its own lock, and the mock CPU was stopped.
    static X: LockClass = LockClass::new("full.contended");

    // The mock keeps one interrupt flag for the whole process, so four threads saving
    // and restoring it interleave and can leave it masked. Nothing on a real CPU
    // resembles that. Put it back when this test ends, by any route, so that a failure
    // here is not also reported by every later test that checks the flag.
    struct Unmask;
    impl Drop for Unmask {
        fn drop(&mut self) {
            // SAFETY: a mock flag, restored under `serial()`, which excludes every test
            // that reads it.
            unsafe { MockFull::irq_restore(true) };
        }
    }
    let _s = serial();
    let _unmask = Unmask;
    reset::<MockFull>();

    let x: SpinLock<usize, MockFull> = SpinLock::with_class(0, &X);
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                for _ in 0..2_000 {
                    *x.lock_irqsave() += 1;
                }
            });
        }
    });
    assert_eq!(*x.lock(), 8_000);
    assert_eq!(report::<MockFull>().count, 0);
}

#[test]
fn a_lock_without_a_class_is_not_seen() {
    let _s = serial();
    reset::<MockFull>();
    let x: SpinLock<u32, MockFull> = SpinLock::new(0);
    let y: SpinLock<u32, MockFull> = SpinLock::new(0);
    {
        let _gx = x.lock();
        let _gy = y.lock();
    }
    {
        let _gy = y.lock();
        let _gx = x.lock();
    }
    assert_eq!(report::<MockFull>().count, 0);
}
