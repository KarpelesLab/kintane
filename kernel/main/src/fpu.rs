//! Floating-point state across a context switch: the check that `hal::HasFpu` is real.
//!
//! # What runs
//!
//! `user/fptest`, the only program built for the architecture's hard-float target, in three
//! phases.
//!
//! **Arithmetic**, on one thread. It multiplies, adds, divides and converts, and exits with a
//! code this check grades. That is what proves the *enable bits* work at run time: on x86_64
//! an SSE instruction raises `#UD` unless boot set `CR4.OSFXSR` and cleared `CR0.EM`, and
//! until this check existed nothing in a guest had ever executed one — the program was built
//! and disassembled, never run.
//!
//! **Two threads holding different values**, twice. One graded thread loads eight vector
//! registers, yields sixty-four times, and requires every register to still hold what it put
//! there. Beside it, in the same process, a second thread holds a *different* pattern in the
//! same registers and yields for as long as it is left alive. Where there are two CPUs they
//! are pinned apart, so the graded thread's registers must survive another CPU using those
//! same registers at the same moment, not merely its own preemption. The phase runs twice with
//! the two seeds swapped, so each pattern is the graded one in turn.
//!
//! Only the graded thread exits: a process carries one exit code, and two threads racing to
//! set it would leave this check grading whichever won. The noise thread is reaped when the
//! process is torn down.
//!
//! # What must hold
//!
//! * The arithmetic thread exits with [`ARITH_SUCCESS`].
//! * Both graded threads exit with [`PATTERN_SUCCESS`]. A thread whose registers were clobbered
//!   exits [`LOST`]` + n`, naming the first register that came back wrong, and this check prints
//!   which.
//! * Every thread ends within [`PATIENCE`], so a kernel that cannot run them fails by the clock
//!   rather than hanging.
//! * Every object and frame is back once the processes are torn down.

use hal::EarlyConsole;
use time::Duration;

use crate::preempt::{self, sleep_until};
use crate::{Check, objects, spawn, timekeeping, userproc, write_hex, write_usize};

/// The program's modes and codes. Mirrors `user/fptest/src/main.rs`; the two are one contract.
const MODE_ARITH: usize = 0;
const MODE_PATTERN: usize = 1;
const MODE_NOISE: usize = 2;
const ARITH_SUCCESS: u64 = 0x77;
const PATTERN_SUCCESS: u64 = 0x78;
/// The first of eight codes naming a register that came back wrong.
const LOST: u64 = 210;
/// Vector registers the program holds, and so the number of codes [`LOST`] covers.
const REGS: u64 = 8;

/// The process slot, and the scheduler stack slots its threads run on. Reused from the checks
/// before this one, which have torn their processes down and reaped their threads.
const SLOT: usize = 0;
const STACKS: [usize; 3] = [1, 2, 3];

/// The longest a phase's threads get, from their start.
const PATIENCE: Duration = Duration::from_nanos(5_000_000_000);
/// How often the check looks.
const POLL: Duration = Duration::from_nanos(5_000_000);

/// The embedded hard-float program, as `user/child` is embedded. `kbuild` links `user/fptest`
/// for this architecture's hard-float specification and names its path in the variable; see
/// the `float = "hard"` unit key and docs/targets.md.
static FPTEST_ELF: &[u8] = include_bytes!(env!("KINTANE_USER_USERFP"));

/// What one phase came to.
struct Phase {
    started: bool,
    code: Option<u64>,
    ended: bool,
}

impl Phase {
    /// Whether the phase ran to its end and the graded thread exited with `want`.
    fn ok(&self, want: u64) -> bool {
        self.started && self.ended && self.code == Some(want)
    }
}

/// Run the check. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  fpu        ");
    objects::init();
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        c.write_str("skipped: no frames for processes");
        return Check::Skipped;
    }
    let Some(program) = userproc::parse(FPTEST_ELF) else {
        c.write_str("the hard-float program does not load");
        return Check::Failed;
    };
    let frames_before = free_frames();
    let objects_before = objects::live();

    // Arithmetic first: if the enable bits are wrong every later phase fails too, and this
    // one says so in one code rather than as eight lost registers.
    let arith = run(&program, [MODE_ARITH, 0, 0, 0], None);
    // Then each pattern graded in turn, against the other held beside it.
    let first = run(&program, [MODE_PATTERN, 0, 0, 0], Some([MODE_NOISE, 1, 0, 0]));
    let second = run(&program, [MODE_PATTERN, 1, 0, 0], Some([MODE_NOISE, 0, 0, 0]));

    let frames = frames_before.saturating_sub(free_frames());
    let leaked = objects::live().saturating_sub(objects_before);

    match arith.code {
        Some(ARITH_SUCCESS) => c.write_str("arithmetic ran in a hard-float program"),
        Some(other) => {
            c.write_str("the arithmetic thread exited ");
            write_hex(c, other);
            c.write_str(", WRONG");
        }
        None if !arith.started => c.write_str("THE ARITHMETIC THREAD NEVER STARTED"),
        None => c.write_str("THE ARITHMETIC THREAD NEVER EXITED"),
    }

    let held = first.ok(PATTERN_SUCCESS) && second.ok(PATTERN_SUCCESS);
    c.write_str("; ");
    if held {
        c.write_str("eight vector registers held across 64 yields beside a thread holding ");
        c.write_str("others, both ways round");
    } else {
        c.write_str("REGISTERS DID NOT SURVIVE THE SWITCH: ");
        report(c, "first", &first);
        c.write_str(", ");
        report(c, "second", &second);
    }

    if !arith.ended || !first.ended || !second.ended {
        c.write_str("; A THREAD NEVER ENDED, its process left in place");
    }
    c.write_str("; ");
    write_usize(c, leaked);
    c.write_str(if leaked == 0 {
        " objects left"
    } else {
        " OBJECTS LEAKED"
    });
    c.write_str(", ");
    write_usize(c, frames);
    c.write_str(if frames == 0 {
        " frames left ok"
    } else {
        " FRAMES LEAKED"
    });
    Check::from_ok(arith.ok(ARITH_SUCCESS) && held && leaked == 0 && frames == 0)
}

/// Name what one graded thread reported: its success, the register it lost, or nothing.
fn report(c: &dyn EarlyConsole, which: &str, phase: &Phase) {
    c.write_str(which);
    match phase.code {
        Some(PATTERN_SUCCESS) => c.write_str(" ok"),
        Some(n) if (LOST..LOST + REGS).contains(&n) => {
            c.write_str(" lost register ");
            write_usize(c, (n - LOST) as usize);
        }
        Some(other) => {
            c.write_str(" exited ");
            write_hex(c, other);
        }
        None if !phase.started => c.write_str(" never started"),
        None => c.write_str(" never exited"),
    }
}

/// Build the process, start the graded thread and any noise thread beside it, wait for the
/// graded one to exit, and tear the process down.
///
/// The noise thread never exits by itself; it ends when the graded thread's exit ends the
/// process, which is what `end_threads` waits for.
fn run(program: &elf::Program, graded: [usize; 4], noise: Option<[usize; 4]>) -> Phase {
    let miss = Phase {
        started: false,
        code: None,
        ended: true,
    };
    spawn::use_stacks(&STACKS);
    if userproc::build(SLOT, program).is_none() {
        return miss;
    }
    let Some(p) = userproc::slot(SLOT) else {
        return miss;
    };
    p.image = Some(FPTEST_ELF);
    let Some(main) = userproc::start(SLOT, 0, graded) else {
        userproc::teardown(SLOT);
        return miss;
    };
    let other = match noise {
        Some(args) => match userproc::start(SLOT, 0, args) {
            Some(id) => Some(id),
            None => {
                let ended = spawn::end_threads();
                if ended {
                    userproc::teardown(SLOT);
                }
                return Phase {
                    started: false,
                    code: None,
                    ended,
                };
            }
        },
        None => None,
    };
    let cpus = preempt::stats().cpus.max(1);
    if let (Some(id), true) = (other, cpus >= 2) {
        // Apart, so the graded thread's registers must survive another CPU holding its own
        // values in them at the same moment, not only this thread being preempted.
        let _ = preempt::set_affinity(main, 1);
        let _ = preempt::set_affinity(id, 1 << (1 % cpus));
    }

    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while preempt::alive(main) && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    let exited = !preempt::alive(main);
    // Unpinned whatever happened, so a thread still starting can reach its end.
    let _ = preempt::set_affinity(main, u64::MAX);
    if let Some(id) = other {
        let _ = preempt::set_affinity(id, u64::MAX);
    }
    // The graded thread's exit is the process's, and it is the only thread that exits.
    let code = if exited {
        userproc::slot(SLOT).and_then(|p| p.exit)
    } else {
        None
    };
    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
    Phase {
        started: true,
        code,
        ended,
    }
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}
