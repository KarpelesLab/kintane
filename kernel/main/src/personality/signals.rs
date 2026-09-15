//! Signals for Linux processes: dispositions, masks, pending sets, and delivery.
//!
//! # Who holds what
//!
//! As Linux divides it: a process has one disposition per signal ([`ACTIONS`]) and a set of
//! signals sent to the process as a whole ([`PROCESS_PENDING`]); each thread has a mask and a
//! set of signals sent to it ([`THREAD_SIGNALS`]). A thread gets its entry the first time it
//! makes a call. A `clone`d thread is given one at `clone`, with the mask of the thread that
//! made it, and a `fork`ed process's first thread starts with the forking thread's mask and the
//! parent's dispositions. `execve` resets every handler to the default and keeps the rest.
//!
//! # Delivery
//!
//! A signal is delivered on the way out of a system call ([`deliver`]), where the thread's
//! registers are at hand: the lowest-numbered one that is pending and not masked, the thread's
//! own before its process's. An ignored one is discarded; one whose action ends the process
//! ends it, reporting the signal to `wait4`; one with a handler gets a frame on the thread's
//! stack (`linux::signal::build`) and the call returns into the handler instead, with the
//! handler's mask added. `rt_sigreturn` reads the frame back, refuses one the program has made
//! unsafe, and resumes where the handler interrupted.
//!
//! A thread spinning in user mode is not interrupted to run a handler: its signal waits for
//! its next system call. The interrupt path has no registers to build a frame from. A signal
//! whose action ends the process does not wait: it is acted on when it is sent, and the
//! process's threads end the way an `exit_group` ends them, spinning ones included.
//!
//! # Blocking calls
//!
//! A pipe read or write, a futex wait and `wait4` look at [`interrupting`] each time they wake,
//! and end with `EINTR` when a signal that is not ignored is deliverable; sending one wakes the
//! personality's wait queues, so a blocked thread looks. If the handler has `SA_RESTART`, or no
//! handler runs after all — the signal went to another thread, or turned out to be ignored — the
//! call returns to its own system call instruction with its arguments, and runs again.
//!
//! # Not built
//!
//! Stopping: `SIGSTOP` is refused by `kill` and `tgkill`, and the other stop signals' default
//! action does nothing. Alternate signal stacks: `sigaltstack` reports none and refuses to set
//! one. `rt_sigsuspend`, `rt_sigtimedwait` and `signalfd`.
//!
//! Floating-point state is not saved in the frame, and cannot honestly be until `hal::HasFpu`
//! exists: no context switch on either port saves those registers either, so a handler is not
//! the only thing that changes them under the code it interrupted.
//! `linux::signal::restore` refuses a frame that carries such state rather than reading past it.
//!
//! # Queued signals
//!
//! A signal from [`RT_FIRST`] up queues: three sent are three delivered, oldest first, each with
//! the value `rt_sigqueueinfo` gave it. Below that a signal is one bit, so a second before the
//! first is delivered is the same signal arriving once, keeping the first sender's value. A
//! process may hold [`RT_QUEUED`] entries at once, and a send past that is refused with `EAGAIN`
//! rather than dropped.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use hal::user::UserRegisters;
use hal::{EarlyConsole, HasFpu, HasUserMode};
use linux::Failure;
use linux::signal::{self as sig, Action, Delivery, Effect};
use sched::ThreadId;
use sync::SpinLock;
use sync::lockdep::LockClass;

use super::{ABI, ENDED, PARENT, STATUS};
use crate::userproc::{self, MAX_PROCS};
use crate::{Check, preempt, write_hex, write_usize};

const _: () = assert!(
    hal::user::REGISTER_WORDS == sig::REGISTER_WORDS,
    "hal and kernel/linux disagree on how many words a context is"
);

type Words = [u64; sig::REGISTER_WORDS];

const USER_START: u64 = <Cpu as HasUserMode>::USER_START as u64;
const USER_END: u64 = <Cpu as HasUserMode>::USER_END as u64;

/// Where this port's frame keeps the saved floating-point state, and how much of it there is.
const FPU_AT: usize = ABI.fpu_at();
const FPU_BYTES: usize = ABI.fpu_bytes();

const _: () = {
    // The frame's idea of the image and the port's must be one number. `kernel/linux` depends
    // on nothing and cannot ask the architecture, so it writes the size down; this is where the
    // two meet. A port whose image changed without the layout following would otherwise write
    // a short record and read back a long one.
    assert!(FPU_BYTES == <Cpu as HasFpu>::FPU_BYTES);
    // Both lie inside the bytes `rt_sigreturn` reads back, which is what makes it safe to take
    // the state from the same buffer `restore` validated.
    assert!(FPU_AT + FPU_BYTES <= ABI.restore_len());
};
const SIGNALS: usize = sig::NSIG as usize;

// ---- state -------------------------------------------------------------------------------

/// Threads of Linux processes that can hold signal state at once.
const THREADS: usize = 16;
/// An entry no thread holds, and one a thread is claiming.
const FREE: u32 = u32::MAX;
const CLAIMING: u32 = u32::MAX - 1;
/// The key of a thread the boot-time slice runs, which has no identity on the scheduler: one
/// per process slot, above every thread id the scheduler hands out.
const SLICE_KEY: u32 = 0x8000_0000;

/// One thread's signal state.
struct ThreadSignals {
    /// The thread's key ([`key`]), or [`FREE`].
    key: AtomicU32,
    slot: AtomicUsize,
    tid: AtomicU64,
    mask: AtomicU64,
    pending: AtomicU64,
    /// The address the last fault on this thread took, which `si_addr` reports.
    fault: AtomicU64,
    /// The instruction that fault was taken at, and how many faults in a row have been taken
    /// there. A handler that returns without fixing what it was sent for returns to the same
    /// instruction, which faults again at once; see [`REFAULTS`].
    fault_pc: AtomicU64,
    refaults: AtomicU32,
}

static THREAD_SIGNALS: [ThreadSignals; THREADS] = [const {
    ThreadSignals {
        key: AtomicU32::new(FREE),
        slot: AtomicUsize::new(0),
        tid: AtomicU64::new(0),
        mask: AtomicU64::new(0),
        pending: AtomicU64::new(0),
        fault: AtomicU64::new(0),
        fault_pc: AtomicU64::new(0),
        refaults: AtomicU32::new(0),
    }
}; THREADS];

/// How many times a thread may fault at one instruction with a handler for it before the
/// kernel stops running that handler and lets the signal end the process.
///
/// Linux leaves this to the program: a handler that returns without fixing the fault faults
/// again, forever. A kernel whose boot checks must finish cannot spin like that, so the
/// process ends instead, reported as ended by the signal — and the count is per instruction,
/// so a handler that fixes one fault and meets another somewhere else starts over.
const REFAULTS: u32 = 16;

static ACTION_CLASS: LockClass = LockClass::new("linux.sigaction");
/// Each process's dispositions. Held only to read or write them, and nothing is taken inside.
static ACTIONS: SpinLock<[[Action; SIGNALS]; MAX_PROCS], Cpu> =
    SpinLock::with_class([[Action::DEFAULT; SIGNALS]; MAX_PROCS], &ACTION_CLASS);
/// Signals sent to each process as a whole.
static PROCESS_PENDING: [AtomicU64; MAX_PROCS] = [const { AtomicU64::new(0) }; MAX_PROCS];
/// The mask each process's first thread starts with: its forking parent thread's.
static FIRST_MASK: [AtomicU64; MAX_PROCS] = [const { AtomicU64::new(0) }; MAX_PROCS];
/// The pid that last sent each process each signal, zero for the kernel: `siginfo`'s `si_pid`.
static SENDER: [[AtomicU32; SIGNALS]; MAX_PROCS] =
    [const { [const { AtomicU32::new(0) }; SIGNALS] }; MAX_PROCS];

/// Signals from this number up queue: three sent are three delivered. Below it a signal is one
/// bit, so a second before the first is delivered is the same signal arriving once.
const RT_FIRST: u64 = 32;
/// Entries a process may have queued at once, across every signal. Linux bounds this per user
/// with `RLIMIT_SIGPENDING`; there is one user here, so it is per process and fixed.
const RT_QUEUED: usize = 8;

/// One queued signal: what `rt_sigqueueinfo` kept for a delivery that has not happened yet.
struct Queued {
    /// The signal, or zero for a slot nothing holds.
    signo: AtomicU32,
    /// The sender's pid, and the word it queued, which `si_value` carries.
    pid: AtomicU32,
    value: AtomicU64,
    /// When it was queued. Lower is older, so one number's entries come back in order.
    seq: AtomicU64,
}

static RT_QUEUE: [[Queued; RT_QUEUED]; MAX_PROCS] = [const {
    [const {
        Queued {
            signo: AtomicU32::new(0),
            pid: AtomicU32::new(0),
            value: AtomicU64::new(0),
            seq: AtomicU64::new(0),
        }
    }; RT_QUEUED]
}; MAX_PROCS];

/// Stamps [`Queued::seq`], so the order entries went in is the order they come out.
static RT_SEQ: AtomicU64 = AtomicU64::new(1);

/// Queued signals delivered, and the sends refused because the queue was full.
static RT_DELIVERED: AtomicU64 = AtomicU64::new(0);
static RT_REFUSED: AtomicU64 = AtomicU64::new(0);

/// Keep `signo` for `target` with `value`, from `from`.
///
/// A signal below [`RT_FIRST`] that is already queued is not queued again: it is one bit
/// pending, so the value that arrives is the first sender's, which is what coalescing means. A
/// real-time signal is queued until [`RT_QUEUED`] entries are held, and then refused with
/// `EAGAIN` rather than dropped, so a sender learns the difference.
fn queue(target: usize, signo: u64, from: u32, value: u64) -> Result<(), Failure> {
    let slots = &RT_QUEUE[target];
    let holds = |q: &Queued| u64::from(q.signo.load(Ordering::Acquire)) == signo;
    if signo < RT_FIRST && slots.iter().any(holds) {
        return Ok(());
    }
    let free = slots.iter().find(|q| {
        q.signo
            .compare_exchange(0, signo as u32, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    });
    let Some(q) = free else {
        RT_REFUSED.fetch_add(1, Ordering::Relaxed);
        return Err(Failure::TryAgain);
    };
    q.pid.store(from, Ordering::Release);
    q.value.store(value, Ordering::Release);
    q.seq
        .store(RT_SEQ.fetch_add(1, Ordering::AcqRel), Ordering::Release);
    Ok(())
}

/// Take the oldest entry `target` has for `signo`, if it has one: the sender and the value.
///
/// The pending bit is put back when another entry of that number is still held, so the next
/// delivery finds it. Called from [`enter_handler`], which every delivery goes through.
fn pop_queued(target: usize, signo: u64) -> Option<(u32, u64)> {
    let slots = &RT_QUEUE[target];
    let holds = |q: &&Queued| u64::from(q.signo.load(Ordering::Acquire)) == signo;
    let oldest = slots
        .iter()
        .filter(holds)
        .min_by_key(|q| q.seq.load(Ordering::Acquire))?;
    let taken = (oldest.pid.load(Ordering::Acquire), oldest.value.load(Ordering::Acquire));
    oldest.signo.store(0, Ordering::Release);
    if slots.iter().any(|q| holds(&q)) {
        PROCESS_PENDING[target].fetch_or(sig::bit(signo), Ordering::AcqRel);
    }
    RT_DELIVERED.fetch_add(1, Ordering::Relaxed);
    Some(taken)
}

/// Drop what `slot` has queued of `signo`, or of every signal when `signo` is `None`: a signal
/// set to be ignored is discarded wherever it waits, and a process that goes away takes its
/// queue with it.
fn forget_queued(slot: usize, signo: Option<u64>) {
    for q in &RT_QUEUE[slot] {
        let held = u64::from(q.signo.load(Ordering::Acquire));
        if held != 0 && signo.is_none_or(|s| s == held) {
            q.signo.store(0, Ordering::Release);
        }
    }
}

/// Handlers entered, frames `rt_sigreturn` accepted, blocked calls a signal ended, and
/// processes a signal ended.
static HANDLED: AtomicU64 = AtomicU64::new(0);
static RETURNED: AtomicU64 = AtomicU64::new(0);
static INTERRUPTED: AtomicU64 = AtomicU64::new(0);
static SIGNAL_ENDS: AtomicU64 = AtomicU64::new(0);

fn key(slot: usize) -> u32 {
    preempt::current_thread().map_or(SLICE_KEY | slot as u32, ThreadId::raw)
}

fn held(t: &ThreadSignals) -> bool {
    !matches!(t.key.load(Ordering::Acquire), FREE | CLAIMING)
}

fn claim(key: u32, slot: usize, tid: u64, mask: u64) -> Option<&'static ThreadSignals> {
    let t = THREAD_SIGNALS.iter().find(|t| {
        t.key
            .compare_exchange(FREE, CLAIMING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    })?;
    t.slot.store(slot, Ordering::Release);
    t.tid.store(tid, Ordering::Release);
    t.mask.store(mask & !sig::UNBLOCKABLE, Ordering::Release);
    t.pending.store(0, Ordering::Release);
    // Last, so no one looking for the key finds the entry half made.
    t.key.store(key, Ordering::Release);
    Some(t)
}

/// The calling thread's entry, made for it if it has none. `None` only when every entry is
/// held, in which case the thread's signals wait for one.
fn mine(slot: usize) -> Option<&'static ThreadSignals> {
    let k = key(slot);
    if let Some(t) = THREAD_SIGNALS
        .iter()
        .find(|t| t.key.load(Ordering::Acquire) == k)
    {
        if t.slot.load(Ordering::Acquire) == slot {
            return Some(t);
        }
        // A thread that ended without saying so, whose id the scheduler has since given to a
        // thread of another process.
        t.key.store(FREE, Ordering::Release);
    }
    claim(k, slot, super::tid(slot), FIRST_MASK[slot].load(Ordering::Acquire))
}

fn action_of(slot: usize, signo: u64) -> Action {
    ACTIONS.lock_irqsave()[slot][(signo - 1) as usize]
}

/// Take the lowest signal in `set` that `allowed` lets through, clearing it.
fn take(set: &AtomicU64, allowed: u64) -> Option<u64> {
    set.try_update(Ordering::AcqRel, Ordering::Acquire, |p| {
        let d = p & allowed;
        (d != 0).then_some(p & !(d & d.wrapping_neg()))
    })
    .ok()
    .map(|before| u64::from((before & allowed).trailing_zeros()) + 1)
}

// ---- the lifecycle hooks -------------------------------------------------------------------

/// A thread `clone` started in `slot` as `thread`, with tid `tid`: it starts with the calling
/// thread's mask and nothing pending.
pub(super) fn cloned(slot: usize, thread: ThreadId, tid: u64) {
    let mask = mine(slot).map_or(0, |t| t.mask.load(Ordering::Acquire));
    if let Some(stale) = THREAD_SIGNALS
        .iter()
        .find(|t| t.key.load(Ordering::Acquire) == thread.raw())
    {
        stale.key.store(FREE, Ordering::Release);
    }
    let _ = claim(thread.raw(), slot, tid, mask);
}

/// `fork` made `child` from `parent`: the parent's dispositions, the forking thread's mask,
/// and nothing pending.
pub(super) fn forked(parent: usize, child: usize) {
    let mask = mine(parent).map_or(0, |t| t.mask.load(Ordering::Acquire));
    forget_threads(child);
    // A child inherits nothing pending, and so none of the parent's queued signals.
    forget_queued(child, None);
    FIRST_MASK[child].store(mask, Ordering::Release);
    PROCESS_PENDING[child].store(0, Ordering::Release);
    let mut actions = ACTIONS.lock_irqsave();
    actions[child] = actions[parent];
}

/// `execve` replaced `slot`'s program: every handler is reset to the default, since the new
/// program has no such code. An ignored signal stays ignored.
pub(super) fn executed(slot: usize) {
    for a in ACTIONS.lock_irqsave()[slot].iter_mut() {
        if a.handler != sig::SIG_IGN {
            *a = Action::DEFAULT;
        }
    }
}

/// The calling thread of `slot` is ending alone.
pub(super) fn thread_ended(slot: usize) {
    let k = key(slot);
    if let Some(t) = THREAD_SIGNALS
        .iter()
        .find(|t| t.key.load(Ordering::Acquire) == k && t.slot.load(Ordering::Acquire) == slot)
    {
        t.key.store(FREE, Ordering::Release);
    }
}

/// `slot`'s process is torn down: nothing of its signals is left.
pub(super) fn release(slot: usize) {
    forget_threads(slot);
    forget_queued(slot, None);
    PROCESS_PENDING[slot].store(0, Ordering::Release);
    FIRST_MASK[slot].store(0, Ordering::Release);
    for s in &SENDER[slot] {
        s.store(0, Ordering::Release);
    }
    ACTIONS.lock_irqsave()[slot] = [Action::DEFAULT; SIGNALS];
}

fn forget_threads(slot: usize) {
    for t in &THREAD_SIGNALS {
        if held(t) && t.slot.load(Ordering::Acquire) == slot {
            t.key.store(FREE, Ordering::Release);
        }
    }
}

/// `child`'s last thread has gone and its status is recorded: its parent, if it has one, is
/// sent `SIGCHLD`.
pub(super) fn child_ended(child: usize) {
    let parent = PARENT[child].load(Ordering::Acquire);
    if parent != 0 {
        let _ = send_process(parent - 1, sig::SIGCHLD, super::pid(child) as u32);
    }
}

// ---- sending ------------------------------------------------------------------------------

/// End process `slot` for `signo`, now: its threads end as an `exit_group` ends them.
fn end_by(slot: usize, signo: u64) {
    SIGNAL_ENDS.fetch_add(1, Ordering::Relaxed);
    userproc::end_process(slot, sig::exit_code(signo));
}

/// Wear `mask` until the wait ends, returning the mask to put back: what `ppoll`, `pselect6`
/// and `epoll_pwait` do, so a signal the program blocks outside the wait can still end it.
/// `None` for a thread with no signal state, which has nothing to swap.
///
/// The two unblockable signals stay unblocked, as they do for `rt_sigprocmask`.
pub(super) fn wear_mask(slot: usize, mask: u64) -> Option<u64> {
    let t = mine(slot)?;
    let old = t.mask.load(Ordering::Acquire);
    t.mask.store(mask & !sig::UNBLOCKABLE, Ordering::Release);
    Some(old)
}

/// Put back the mask [`wear_mask`] took off, once the wait is over.
pub(super) fn restore_mask(slot: usize, old: u64) {
    if let Some(t) = mine(slot) {
        t.mask.store(old & !sig::UNBLOCKABLE, Ordering::Release);
    }
}

/// Whether every thread of `slot` masks `bit`, so a process-wide signal must wait.
fn masked_everywhere(slot: usize, bit: u64) -> bool {
    let mut any = false;
    for t in THREAD_SIGNALS
        .iter()
        .filter(|t| held(t) && t.slot.load(Ordering::Acquire) == slot)
    {
        any = true;
        if t.mask.load(Ordering::Acquire) & bit == 0 {
            return false;
        }
    }
    any || FIRST_MASK[slot].load(Ordering::Acquire) & bit != 0
}

fn send_process(target: usize, signo: u64, from: u32) -> Result<u64, Failure> {
    if signo == 0 {
        return Ok(0);
    }
    let bit = sig::bit(signo);
    match sig::effect(signo, &action_of(target, signo)) {
        Effect::Ignore => {}
        Effect::Terminate if signo == sig::SIGKILL || !masked_everywhere(target, bit) => {
            end_by(target, signo)
        }
        Effect::Terminate | Effect::Handle => {
            SENDER[target][(signo - 1) as usize].store(from, Ordering::Release);
            PROCESS_PENDING[target].fetch_or(bit, Ordering::AcqRel);
            super::wake_all_waiters();
        }
    }
    Ok(0)
}

fn send_thread(target: usize, t: &ThreadSignals, signo: u64, from: u32) {
    let bit = sig::bit(signo);
    match sig::effect(signo, &action_of(target, signo)) {
        Effect::Ignore => {}
        Effect::Terminate if signo == sig::SIGKILL || t.mask.load(Ordering::Acquire) & bit == 0 => {
            end_by(target, signo)
        }
        Effect::Terminate | Effect::Handle => {
            SENDER[target][(signo - 1) as usize].store(from, Ordering::Release);
            t.pending.fetch_or(bit, Ordering::AcqRel);
            super::wake_all_waiters();
        }
    }
}

/// Raise `signo` on the calling thread of `slot`, from the kernel: `SIGPIPE` for a write no one
/// can read. Delivered on the way out of the call that raised it.
pub(super) fn raise_self(slot: usize, signo: u64) {
    if sig::effect(signo, &action_of(slot, signo)) == Effect::Ignore {
        return;
    }
    if let Some(t) = mine(slot) {
        SENDER[slot][(signo - 1) as usize].store(0, Ordering::Release);
        t.pending.fetch_or(sig::bit(signo), Ordering::AcqRel);
    }
}

/// The calling thread's entry if it already has one, without making it one. What the paths
/// that must not claim an entry — a thread of a process that is not Linux at all — look
/// through.
fn existing(slot: usize) -> Option<&'static ThreadSignals> {
    let k = key(slot);
    THREAD_SIGNALS
        .iter()
        .find(|t| t.key.load(Ordering::Acquire) == k && t.slot.load(Ordering::Acquire) == slot)
}

/// Whether the calling thread of `slot` has a signal to act on: pending, not masked, not
/// ignored. What a blocking call looks at when it wakes.
pub(super) fn interrupting(slot: usize) -> bool {
    let (mask, pending) = existing(slot)
        .map_or((FIRST_MASK[slot].load(Ordering::Acquire), 0), |t| {
            (t.mask.load(Ordering::Acquire), t.pending.load(Ordering::Acquire))
        });
    let deliverable = (pending | PROCESS_PENDING[slot].load(Ordering::Acquire)) & !mask;
    if deliverable == 0 {
        return false;
    }
    let actions = ACTIONS.lock_irqsave();
    (1..=sig::NSIG).any(|s| {
        deliverable & sig::bit(s) != 0
            && sig::effect(s, &actions[slot][(s - 1) as usize]) != Effect::Ignore
    })
}

/// Count a call that blocked and was ended by a signal.
pub(super) fn blocked_call_interrupted() {
    INTERRUPTED.fetch_add(1, Ordering::Relaxed);
}

// ---- delivery -----------------------------------------------------------------------------

/// Deliver what the calling thread of `slot` has pending, on the way out of the call in
/// `frame`, which returned `result` and was made with the registers `entry`. See the module
/// documentation.
pub(super) fn deliver(
    slot: usize,
    frame: &mut <Cpu as HasUserMode>::SyscallFrame,
    entry: &Words,
    result: Result<u64, Failure>,
) {
    let interrupted = result == Err(Failure::Interrupted);
    if let Some(me) = mine(slot) {
        loop {
            let mask = me.mask.load(Ordering::Acquire);
            let Some(signo) =
                take(&me.pending, !mask).or_else(|| take(&PROCESS_PENDING[slot], !mask))
            else {
                break;
            };
            let action = action_of(slot, signo);
            match sig::effect(signo, &action) {
                Effect::Ignore => {}
                Effect::Terminate => {
                    SIGNAL_ENDS.fetch_add(1, Ordering::Relaxed);
                    super::exit_group(slot, sig::exit_code(signo))
                }
                Effect::Handle => {
                    handle(slot, me, frame, entry, interrupted, signo, action, mask);
                    return;
                }
            }
        }
    }
    // No handler ran, so a call a signal interrupted runs again.
    if interrupted {
        Cpu::set_registers(frame, &UserRegisters::from_words(&restarted(entry)));
    }
}

/// The registers `entry` with the program counter back on the system call instruction.
fn restarted(entry: &Words) -> Words {
    let mut ctx = *entry;
    let pc = ABI.pc_word();
    ctx[pc] = ctx[pc].wrapping_sub(ABI.syscall_len());
    ctx
}

/// Handlers entered on the way out of an interrupt rather than a system call, and handlers
/// entered for a fault the thread took.
static ASYNC: AtomicU64 = AtomicU64::new(0);
static FAULTED: AtomicU64 = AtomicU64::new(0);

/// The exit code the last fault decided for each process, for [`fault_exit_code`]. Zero until
/// a fault raises a signal nothing handles.
static LAST_FAULT: [AtomicU64; MAX_PROCS] = [const { AtomicU64::new(0) }; MAX_PROCS];

/// The code a trap that ended `slot` is recorded with, when a fault chose one: `SIGFPE` for a
/// division by zero rather than the `SIGSEGV` every trap used to report.
pub(super) fn fault_exit_code(slot: usize) -> Option<u64> {
    let code = LAST_FAULT[slot].load(Ordering::Acquire);
    (code != 0).then_some(code)
}

/// The address `si_addr` reports for `signo`: the one the thread's last fault took, and
/// nothing for a signal a fault did not raise, whose bytes hold the sender's pid instead.
fn fault_addr(slot: usize, signo: u64) -> Option<u64> {
    if !sig::from_fault(signo) {
        return None;
    }
    existing(slot).map(|t| t.fault.load(Ordering::Acquire))
}

/// Put the thread of `slot`, whose registers are `ctx`, into `action`'s handler for `signo`:
/// the frame on its stack and the registers it starts the handler with, or `None` when the
/// frame could not be written.
///
/// Every delivery goes through here, from a system call, an interrupt or a fault alike; what
/// differs between them is only which registers `ctx` holds.
fn enter_handler(
    slot: usize,
    me: &ThreadSignals,
    ctx: &Words,
    signo: u64,
    action: Action,
    mask: u64,
) -> Option<Words> {
    use sig::flags::{SA_NODEFER, SA_RESETHAND};
    // A signal `rt_sigqueueinfo` queued carries its sender's own value; every other kind takes
    // the last sender the process recorded for that number.
    let queued = pop_queued(slot, signo);
    let from = queued
        .map_or_else(|| SENDER[slot][(signo - 1) as usize].load(Ordering::Acquire), |(pid, _)| pid);
    let value = queued.map_or(0, |(_, value)| value);
    let code = if queued.is_some() {
        sig::SI_QUEUE
    } else if signo == sig::SIGCHLD {
        // CLD_EXITED: the only change a child reports here.
        1
    } else if sig::from_fault(signo) {
        sig::SI_KERNEL
    } else if from != 0 {
        sig::SI_USER
    } else {
        sig::SI_KERNEL
    };
    let d = Delivery {
        sig: signo,
        action,
        old_mask: mask,
        code,
        pid: from,
        addr: fault_addr(slot, signo),
        value,
    };
    let mut built = sig::build(ABI, ctx, &d, USER_START, USER_END).ok()?;
    // The interrupted thread's floating-point registers, into the frame before it is written.
    // They are live at this moment — the thread is in a system call, a fault or an interrupt,
    // and nothing has reloaded them — so this is the one place they can be taken from. A switch
    // after this point carries them as it always did; see `hal::HasFpu`.
    Cpu::save_live(&mut built.head[FPU_AT..FPU_AT + FPU_BYTES]);
    if !write_frame(&built) {
        return None;
    }
    let mut blocked = mask | action.mask;
    if action.flags & SA_NODEFER == 0 {
        blocked |= sig::bit(signo);
    }
    me.mask
        .store(blocked & !sig::UNBLOCKABLE, Ordering::Release);
    if action.flags & SA_RESETHAND != 0 {
        ACTIONS.lock_irqsave()[slot][(signo - 1) as usize] = Action::DEFAULT;
    }
    HANDLED.fetch_add(1, Ordering::Relaxed);
    Some(built.regs)
}

#[allow(clippy::too_many_arguments)]
fn handle(
    slot: usize,
    me: &ThreadSignals,
    frame: &mut <Cpu as HasUserMode>::SyscallFrame,
    entry: &Words,
    interrupted: bool,
    signo: u64,
    action: Action,
    mask: u64,
) {
    use sig::flags::SA_RESTART;
    // What the handler returns to: the call again, or its answer.
    let ctx = if interrupted && action.flags & SA_RESTART != 0 {
        restarted(entry)
    } else {
        Cpu::registers(frame).to_words()
    };
    let Some(regs) = enter_handler(slot, me, &ctx, signo, action, mask) else {
        // No room below the stack for the frame, or not memory the thread can write: Linux's
        // answer is SIGSEGV, which ends the process.
        SIGNAL_ENDS.fetch_add(1, Ordering::Relaxed);
        super::exit_group(slot, sig::exit_code(sig::SIGSEGV))
    };
    Cpu::set_registers(frame, &UserRegisters::from_words(&regs));
}

/// Deliver what the thread of `slot` has pending to the registers an interrupt took it out of
/// user mode with. `true` when `regs` is a handler's now.
///
/// This is the path a thread spinning in user mode is reached by: it calls nothing, so nothing
/// else ever returns to it with its registers in the kernel's hands. Called on the way back to
/// user code, so the context it changes is the program's own and no lock taken here can be one
/// that context held.
pub(super) fn deliver_interrupted(slot: usize, regs: &mut Words) -> bool {
    // Lock-free and cheap first: most interrupts of most threads have nothing to deliver, and
    // a thread of a process that is not Linux at all never has an entry to look at.
    let entry = existing(slot);
    let pending = entry.map_or(0, |t| t.pending.load(Ordering::Acquire))
        | PROCESS_PENDING[slot].load(Ordering::Acquire);
    if pending == 0 {
        return false;
    }
    let Some(me) = entry.or_else(|| mine(slot)) else {
        return false;
    };
    loop {
        let mask = me.mask.load(Ordering::Acquire);
        let Some(signo) = take(&me.pending, !mask).or_else(|| take(&PROCESS_PENDING[slot], !mask))
        else {
            return false;
        };
        let action = action_of(slot, signo);
        match sig::effect(signo, &action) {
            Effect::Ignore => {}
            Effect::Terminate => {
                SIGNAL_ENDS.fetch_add(1, Ordering::Relaxed);
                super::exit_group(slot, sig::exit_code(signo))
            }
            Effect::Handle => {
                let Some(next) = enter_handler(slot, me, regs, signo, action, mask) else {
                    SIGNAL_ENDS.fetch_add(1, Ordering::Relaxed);
                    super::exit_group(slot, sig::exit_code(sig::SIGSEGV))
                };
                *regs = next;
                ASYNC.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }
}

/// A trap the thread of `slot` took raised `signo`, at `addr`. `true` when a handler runs and
/// `regs` is now that handler's; `false` when the trap must end the process, which is what the
/// port does with it.
///
/// A fault's signal cannot be held off the way a sent one can: the instruction that raised it
/// runs again the moment the thread does. A masked or ignored one therefore ends the process,
/// as it does on Linux, and so does a handler that has returned to the same instruction
/// [`REFAULTS`] times without fixing what it was sent for.
pub(super) fn on_fault(slot: usize, signo: u64, addr: u64, regs: &mut Words) -> bool {
    LAST_FAULT[slot].store(sig::exit_code(signo), Ordering::Release);
    let action = action_of(slot, signo);
    if sig::effect(signo, &action) != Effect::Handle {
        return false;
    }
    let Some(me) = mine(slot) else {
        return false;
    };
    let mask = me.mask.load(Ordering::Acquire);
    if mask & sig::bit(signo) != 0 {
        return false;
    }
    let pc = regs[ABI.pc_word()];
    let again = me.fault_pc.swap(pc, Ordering::AcqRel) == pc;
    let refaults = if again {
        me.refaults.fetch_add(1, Ordering::AcqRel) + 1
    } else {
        me.refaults.store(0, Ordering::Release);
        0
    };
    if refaults >= REFAULTS {
        return false;
    }
    me.fault.store(addr, Ordering::Release);
    let Some(next) = enter_handler(slot, me, regs, signo, action, mask) else {
        return false;
    };
    *regs = next;
    FAULTED.fetch_add(1, Ordering::Relaxed);
    true
}

/// Write a frame to the calling thread's stack. `false` if any of it could not be.
fn write_frame(b: &sig::Built) -> bool {
    if super::to_user(b.at, &b.head[..b.head_len]).is_err() {
        return false;
    }
    let zeros = [0u8; 256];
    let mut done = 0;
    while done < b.zeros {
        let n = (b.zeros - done).min(zeros.len());
        if super::to_user(b.at + (b.head_len + done) as u64, &zeros[..n]).is_err() {
            return false;
        }
        done += n;
    }
    b.record
        .is_none_or(|(at, bytes)| super::to_user(at, &bytes).is_ok())
}

// ---- the calls ----------------------------------------------------------------------------

pub(super) fn sigaction(
    slot: usize,
    signo: u64,
    act: u64,
    old: u64,
    size: u64,
) -> Result<u64, Failure> {
    use sig::flags::SA_RESTORER;
    if size != sig::SIGSET_BYTES || signo == 0 || signo > sig::NSIG {
        return Err(Failure::InvalidArgument);
    }
    let new = if act == 0 {
        None
    } else {
        if sig::bit(signo) & sig::UNBLOCKABLE != 0 {
            return Err(Failure::InvalidArgument);
        }
        let mut bytes = [0u8; sig::ACTION_BYTES];
        super::from_user(act, &mut bytes)?;
        let a = Action::from_bytes(&bytes);
        // The kernel has no trampoline of its own for a handler to return through, so a
        // handler must name its restorer, as x86_64 Linux requires too.
        if !matches!(a.handler, sig::SIG_DFL | sig::SIG_IGN) && a.flags & SA_RESTORER == 0 {
            return Err(Failure::InvalidArgument);
        }
        Some(Action {
            mask: a.mask & !sig::UNBLOCKABLE,
            ..a
        })
    };
    let before = {
        let mut actions = ACTIONS.lock_irqsave();
        let entry = &mut actions[slot][(signo - 1) as usize];
        let before = *entry;
        if let Some(a) = new {
            *entry = a;
        }
        before
    };
    // A signal set to be ignored is discarded wherever it is pending.
    if let Some(a) = new
        && sig::effect(signo, &a) == Effect::Ignore
    {
        let bit = sig::bit(signo);
        PROCESS_PENDING[slot].fetch_and(!bit, Ordering::AcqRel);
        forget_queued(slot, Some(signo));
        for t in THREAD_SIGNALS
            .iter()
            .filter(|t| held(t) && t.slot.load(Ordering::Acquire) == slot)
        {
            t.pending.fetch_and(!bit, Ordering::AcqRel);
        }
    }
    if old != 0 {
        super::to_user(old, &before.to_bytes())?;
    }
    Ok(0)
}

pub(super) fn procmask(
    slot: usize,
    how: u64,
    set: u64,
    old: u64,
    size: u64,
) -> Result<u64, Failure> {
    if size != sig::SIGSET_BYTES {
        return Err(Failure::InvalidArgument);
    }
    let me = mine(slot).ok_or(Failure::TryAgain)?;
    let before = me.mask.load(Ordering::Acquire);
    if set != 0 {
        let mut bytes = [0u8; 8];
        super::from_user(set, &mut bytes)?;
        let set = u64::from_le_bytes(bytes);
        let after = match how {
            sig::SIG_BLOCK => before | set,
            sig::SIG_UNBLOCK => before & !set,
            sig::SIG_SETMASK => set,
            _ => return Err(Failure::InvalidArgument),
        };
        me.mask.store(after & !sig::UNBLOCKABLE, Ordering::Release);
    }
    if old != 0 {
        super::to_user(old, &before.to_le_bytes())?;
    }
    Ok(0)
}

pub(super) fn pending(slot: usize, set: u64, size: u64) -> Result<u64, Failure> {
    if size > sig::SIGSET_BYTES {
        return Err(Failure::InvalidArgument);
    }
    let me = mine(slot).ok_or(Failure::TryAgain)?;
    let pending = (me.pending.load(Ordering::Acquire)
        | PROCESS_PENDING[slot].load(Ordering::Acquire))
        & me.mask.load(Ordering::Acquire);
    super::to_user(set, &pending.to_le_bytes()[..size as usize])?;
    Ok(0)
}

/// `sigaltstack`: there is never an alternate stack, which is what a query is told, and setting
/// one is refused.
pub(super) fn altstack(ss: u64, old: u64) -> Result<u64, Failure> {
    if ss != 0 {
        let mut bytes = [0u8; sig::STACK_T_BYTES];
        super::from_user(ss, &mut bytes)?;
        let flags = i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if flags & sig::SS_DISABLE == 0 {
            arch::EARLY.write_str("linux: sigaltstack with a stack is not implemented\n");
            return Err(Failure::NotImplemented);
        }
    }
    if old != 0 {
        let mut bytes = [0u8; sig::STACK_T_BYTES];
        bytes[8..12].copy_from_slice(&sig::SS_DISABLE.to_le_bytes());
        super::to_user(old, &bytes)?;
    }
    Ok(0)
}

/// A signal number `kill` and `tgkill` accept: 0, the existence check, to 64. `SIGSTOP` is
/// refused, since nothing here can stop a process.
fn sendable(signo: u64) -> Result<(), Failure> {
    if signo > sig::NSIG || signo == sig::SIGSTOP {
        Err(Failure::InvalidArgument)
    } else {
        Ok(())
    }
}

/// The slot of the live Linux process `pid_arg` names. Process groups, and "every process",
/// are refused: there are none.
fn target_of(pid_arg: u64) -> Result<usize, Failure> {
    let pid = pid_arg as i64;
    if pid <= 0 {
        return Err(Failure::InvalidArgument);
    }
    let target = usize::try_from(pid - 1)
        .ok()
        .filter(|&s| s < MAX_PROCS)
        .ok_or(Failure::NoProcess)?;
    let linux = super::locked(target, |_, _| Ok(())).is_ok();
    if linux && STATUS[target].load(Ordering::Acquire) & ENDED == 0 {
        Ok(target)
    } else {
        Err(Failure::NoProcess)
    }
}

/// `kill`: every Linux process may signal every other; there is one user.
pub(super) fn kill(slot: usize, pid_arg: u64, signo: u64) -> Result<u64, Failure> {
    sendable(signo)?;
    let target = target_of(pid_arg)?;
    send_process(target, signo, super::pid(slot) as u32)
}

pub(super) fn tgkill(slot: usize, tgid: u64, tid: u64, signo: u64) -> Result<u64, Failure> {
    sendable(signo)?;
    if tid as i64 <= 0 {
        return Err(Failure::InvalidArgument);
    }
    let target = target_of(tgid)?;
    let from = super::pid(slot) as u32;
    let thread = THREAD_SIGNALS.iter().find(|t| {
        held(t) && t.slot.load(Ordering::Acquire) == target && t.tid.load(Ordering::Acquire) == tid
    });
    match thread {
        Some(t) => {
            if signo != 0 {
                send_thread(target, t, signo, from);
            }
            Ok(0)
        }
        // A process's first thread that has made no call yet has no entry: its tid is the pid,
        // and the process as a whole takes the signal.
        None if tid == tgid => send_process(target, signo, from),
        None => Err(Failure::NoProcess),
    }
}

/// `rt_sigqueueinfo`: send `signo` to a process with a value its handler reads as `si_value`.
///
/// The `siginfo` is the sender's, so only its `si_code` and `si_value` are taken, and only
/// `SI_QUEUE` is accepted: a sender may not claim the kernel raised a signal, nor that some
/// other process sent it. A real-time signal queues; anything else coalesces, as it does
/// everywhere else here.
pub(super) fn rt_sigqueueinfo(
    slot: usize,
    pid_arg: u64,
    signo: u64,
    info: u64,
) -> Result<u64, Failure> {
    sendable(signo)?;
    let target = target_of(pid_arg)?;
    // si_code at 8 and si_value at 24, where `linux::signal`'s `info` lays them out.
    let mut bytes = [0u8; 32];
    super::from_user(info, &mut bytes)?;
    let code = i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if code != sig::SI_QUEUE {
        return Err(Failure::InvalidArgument);
    }
    if signo == 0 {
        return Ok(0);
    }
    // A signal the target ignores is discarded where it is sent, so nothing is queued for a
    // delivery that will never happen.
    if sig::effect(signo, &action_of(target, signo)) == Effect::Ignore {
        return Ok(0);
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[24..32]);
    let from = super::pid(slot) as u32;
    queue(target, signo, from, u64::from_le_bytes(value))?;
    send_process(target, signo, from)
}

/// `rt_sigreturn`: resume what the handler interrupted, from the frame below the stack pointer.
/// A frame that cannot be read or that [`sig::restore`] refuses ends the process with
/// `SIGSEGV`, as Linux's bad frame does.
pub(super) fn sigreturn(
    slot: usize,
    frame: &mut <Cpu as HasUserMode>::SyscallFrame,
) -> Result<u64, Failure> {
    let ctx = Cpu::registers(frame).to_words();
    let len = ABI.restore_len();
    let mut bytes = [0u8; sig::HEAD_BYTES];
    let restored = ABI
        .frame_at(ctx[ABI.sp_word()])
        .ok()
        .filter(|&at| super::from_user(at, &mut bytes[..len]).is_ok())
        .and_then(|at| sig::restore(ABI, &bytes[..len], at, USER_START, USER_END).ok());
    let Some(r) = restored else {
        SIGNAL_ENDS.fetch_add(1, Ordering::Relaxed);
        super::exit_group(slot, sig::exit_code(sig::SIGSEGV))
    };
    if let Some(me) = mine(slot) {
        me.mask.store(r.mask, Ordering::Release);
    }
    // The frame's floating-point state, back into the registers. These are the program's own
    // bytes and it may have changed them, deliberately or by accident — which is the point: a
    // handler that edits the saved state changes what the interrupted code sees, exactly as it
    // can with any other register in the frame. `restore` has already accepted the frame, so
    // the record is the one this kernel wrote and these bytes are inside what it validated.
    Cpu::load_live(&bytes[FPU_AT..FPU_AT + FPU_BYTES]);
    Cpu::set_registers(frame, &UserRegisters::from_words(&r.regs));
    RETURNED.fetch_add(1, Ordering::Relaxed);
    // The return register, which the table sets last, is the one the frame holds.
    Ok(r.regs[0])
}

// ---- the check ----------------------------------------------------------------------------

/// `argv` for the program's floating-point mode, and its exit code when every step behaved;
/// mirror `user/linux-hello/src/main.rs`.
const FP_ARGV: [&[u8]; 2] = [b"hello", b"fp"];
const FP_SUCCESS: u64 = 60;
/// What that mode does at least: two handlers that return, and one child ended by a signal —
/// the one whose `rt_sigreturn` handed back a frame this kernel refused.
const FP_HANDLERS: u64 = 2;

/// `argv` for the program's signals mode, and its exit code when every step behaved; mirror
/// `user/linux-hello/src/main.rs`.
const SIGNALS_ARGV: [&[u8]; 2] = [b"hello", b"signals"];
const SIGNALS_SUCCESS: u64 = 47;
/// What the mode does at least: four handlers (one that zeroes every callee-saved register, one
/// for a signal it unblocks, one that interrupts a blocked read, one for `SIGCHLD`), and three
/// children ended by a default action (`SIGPIPE`, `SIGTERM`, `SIGKILL`).
const HANDLERS: u64 = 4;
const ENDS: u64 = 3;

fn counters() -> [u64; 4] {
    [&HANDLED, &RETURNED, &INTERRUPTED, &SIGNAL_ENDS].map(|n| n.load(Ordering::Relaxed))
}

/// `argv` for the program's faults mode, and its exit code when every step behaved; mirror
/// `user/linux-hello/src/main.rs`.
const FAULTS_ARGV: [&[u8]; 2] = [b"hello", b"faults"];
const FAULTS_SUCCESS: u64 = 54;
/// What that mode does at least: one handler entered from an interrupt, for a thread that only
/// spins, and two from faults it raised itself — the store with no mapping and the
/// architecture's arithmetic trap.
const ASYNC_HANDLERS: u64 = 1;
const FAULT_HANDLERS: u64 = 2;

/// `argv` for the program's real-time mode, and its exit code when every step behaved; mirror
/// `user/linux-hello/src/main.rs`.
const RTSIG_ARGV: [&[u8]; 2] = [b"hello", b"rtsig"];
const RTSIG_SUCCESS: u64 = 56;
/// What that mode has delivered: the queue's depth, with one more send refused.
const RT_DELIVERIES: u64 = 8;

/// Run the program in its real-time mode and grade it: everything queued is delivered, in the
/// order a real kernel promises, and a full queue refuses a send rather than dropping it. On the
/// boot thread, after the faults run, whose slot and stacks it reuses.
pub(super) fn rtsig_check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  linux rt   ");
    let before = [&RT_DELIVERED, &RT_REFUSED].map(|n| n.load(Ordering::Relaxed));
    let run = match super::run_mode(&RTSIG_ARGV) {
        Ok(run) => run,
        Err((check, why)) => {
            c.write_str(why);
            return check;
        }
    };
    let after = [&RT_DELIVERED, &RT_REFUSED].map(|n| n.load(Ordering::Relaxed));
    let [delivered, refused] = [0, 1].map(|i| after[i] - before[i]);
    match (run.started, run.code) {
        (false, _) => c.write_str("the program NEVER STARTED"),
        (true, None) => c.write_str("the program NEVER EXITED"),
        (true, Some(RTSIG_SUCCESS)) => c.write_str(
            "queued three deep and delivered in order, lowest number first, a full queue refused",
        ),
        (true, Some(code)) => {
            c.write_str("the program exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
    }
    c.write_str("; ");
    write_usize(c, delivered as usize);
    c.write_str(" queued signals delivered, ");
    write_usize(c, refused as usize);
    c.write_str(" refused when full");
    let counted = delivered >= RT_DELIVERIES && refused >= 1;
    if !counted {
        c.write_str("; NOT WHAT THE MODE DOES");
    }
    let clean = super::report_run(c, &run);
    Check::from_ok(run.code == Some(RTSIG_SUCCESS) && counted && clean)
}

/// Run the program in its floating-point mode and grade it. On the boot thread, after the
/// real-time run, whose slot and stacks it reuses.
///
/// This is the check that says the frame's floating-point state is *carried* rather than merely
/// shaped. Every other Linux check passes with `save_live` and `load_live` as no-ops, because no
/// other mode puts a value in a vector register and looks at it again: the frame would still be
/// the right size, the record would still be well-formed, and the bytes would still be zero.
/// The three things graded here are the three that a no-op fails.
pub(super) fn fp_check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  linux fp   ");
    let before = [&HANDLED, &RETURNED, &SIGNAL_ENDS].map(|n| n.load(Ordering::Relaxed));
    let run = match super::run_mode(&FP_ARGV) {
        Ok(run) => run,
        Err((check, why)) => {
            c.write_str(why);
            return check;
        }
    };
    let after = [&HANDLED, &RETURNED, &SIGNAL_ENDS].map(|n| n.load(Ordering::Relaxed));
    let [handled, returned, ends] = [0, 1, 2].map(|i| after[i] - before[i]);
    match (run.started, run.code) {
        (false, _) => c.write_str("the program NEVER STARTED"),
        (true, None) => c.write_str("the program NEVER EXITED"),
        (true, Some(FP_SUCCESS)) => c.write_str(
            "registers held across a handler that used them, a handler's edit of the saved state honoured, a malformed record refused",
        ),
        (true, Some(code)) => {
            c.write_str("the program exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
    }
    c.write_str("; ");
    write_usize(c, handled as usize);
    c.write_str(" handlers run, ");
    write_usize(c, returned as usize);
    c.write_str(" returned, ");
    write_usize(c, ends as usize);
    c.write_str(" ended by a refused frame");
    // The corrupting child's handler runs and never returns, so a run that behaved has one more
    // handler than it has returns, and exactly one process ended by the signal that refusal
    // raises. A kernel that accepted the malformed frame would return three times and end none.
    let counted = handled >= FP_HANDLERS + 1 && returned >= FP_HANDLERS && ends >= 1;
    if !counted {
        c.write_str("; NOT WHAT THE MODE DOES");
    }
    let clean = super::report_run(c, &run);
    Check::from_ok(run.code == Some(FP_SUCCESS) && counted && clean)
}

/// Run the program in its faults mode and grade it: a handler entered for a thread that makes
/// no system call, and handlers for the faults the program raises itself. On the boot thread,
/// after the signals run, whose slot and stacks it reuses.
pub(super) fn faults_check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  linux flt  ");
    let before = [&ASYNC, &FAULTED, &HANDLED, &RETURNED].map(|n| n.load(Ordering::Relaxed));
    let run = match super::run_mode(&FAULTS_ARGV) {
        Ok(run) => run,
        Err((check, why)) => {
            c.write_str(why);
            return check;
        }
    };
    let after = [&ASYNC, &FAULTED, &HANDLED, &RETURNED].map(|n| n.load(Ordering::Relaxed));
    let [asynchronous, faulted, handled, returned] = [0, 1, 2, 3].map(|i| after[i] - before[i]);
    match (run.started, run.code) {
        (false, _) => c.write_str("the program NEVER STARTED"),
        (true, None) => c.write_str("the program NEVER EXITED"),
        (true, Some(FAULTS_SUCCESS)) => c.write_str(
            "a spinning thread took its handler, SIGSEGV was fixed from si_addr, the arithmetic trap stepped over",
        ),
        (true, Some(code)) => {
            c.write_str("the program exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
    }
    c.write_str("; ");
    write_usize(c, asynchronous as usize);
    c.write_str(" from an interrupt, ");
    write_usize(c, faulted as usize);
    c.write_str(" from a fault, ");
    write_usize(c, returned as usize);
    c.write_str(" of ");
    write_usize(c, handled as usize);
    c.write_str(" returned");
    let counted =
        asynchronous >= ASYNC_HANDLERS && faulted >= FAULT_HANDLERS && returned == handled;
    if !counted {
        c.write_str("; NOT WHAT THE MODE DOES");
    }
    let clean = super::report_run(c, &run);
    Check::from_ok(run.code == Some(FAULTS_SUCCESS) && counted && clean)
}

/// Run the program in its signals mode with the scheduler, and grade it. On the boot thread,
/// after the `linux mt` run, whose slot and stacks it reuses.
pub(super) fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  linux sig  ");
    let before = counters();
    let run = match super::run_mode(&SIGNALS_ARGV) {
        Ok(run) => run,
        Err((check, why)) => {
            c.write_str(why);
            return check;
        }
    };
    let after = counters();
    let [handled, returned, interrupted, ends] = [0, 1, 2, 3].map(|i| after[i] - before[i]);
    match (run.started, run.code) {
        (false, _) => c.write_str("the program NEVER STARTED"),
        (true, None) => c.write_str("the program NEVER EXITED"),
        (true, Some(SIGNALS_SUCCESS)) => {
            c.write_str("handlers, masks, EINTR, SIGCHLD, SIGPIPE and default actions ok")
        }
        (true, Some(code)) => {
            c.write_str("the program exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
    }
    c.write_str("; ");
    write_usize(c, handled as usize);
    c.write_str(" handlers run, ");
    write_usize(c, returned as usize);
    c.write_str(" returned, ");
    write_usize(c, interrupted as usize);
    c.write_str(" blocked calls interrupted, ");
    write_usize(c, ends as usize);
    c.write_str(" processes ended by a signal");
    let counted = handled >= HANDLERS && returned == handled && interrupted > 0 && ends >= ENDS;
    if !counted {
        c.write_str("; NOT WHAT THE MODE DOES");
    }
    let clean = super::report_run(c, &run);
    Check::from_ok(run.code == Some(SIGNALS_SUCCESS) && counted && clean)
}
