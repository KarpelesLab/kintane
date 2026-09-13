//! Lock-order checking, for debug builds.
//!
//! Two paths that take the same two locks in opposite orders deadlock the first time
//! they run at the same moment on two CPUs, and that can take months. The validator
//! turns that into a report the first time *both orders have ever been seen*, which
//! they usually are in the first test run. It does not need the paths to race.
//!
//! # What is checked
//!
//! Every lock that is given a [`LockClass`] reports its acquisitions and releases here.
//! A class names a *role* ("a channel's state"), not an instance, because an ordering
//! rule is about roles: every channel lock relates to every handle-table lock the same
//! way.
//!
//! - **Inversion.** Taking class `C` while holding class `H` records "`C` after `H`", and so does
//!   everything that follows by transitivity: if `B` was taken under `A` and `C` under `B`, then
//!   `C` is after `A`. Taking `H` while holding `C` after that point is reported. The cycle can be
//!   any length, and it does not matter whether the two orders ever met in time.
//! - **Recursion.** Taking a lock instance that this context already holds. On [`crate::SpinLock`]
//!   that is a silent deadlock and on [`crate::IrqLock`] a halt, so it is recorded and then the CPU
//!   is stopped ([`hal::Arch::halt`]): a stop that has left a report is better than a hang that has
//!   not.
//! - **Two instances of one class nested.** No order between two channels is recorded, so nesting
//!   them cannot be proved consistent and is reported. A subsystem that legitimately nests one
//!   class (hand-over-hand traversal) will need a subclass annotation; none does yet.
//! - **Exhaustion.** More than [`MAX_HELD`] locks held at once, or more than [`MAX_CLASSES`]
//!   classes. Both are reported, and the lock that did not fit is left untracked rather than
//!   guessed at.
//!
//! Only ordering violations and recursion are errors in the code under test. The other
//! two report limits of the checker.
//!
//! Nothing is checked for a `try_lock`. It cannot block, so it cannot be half of a
//! deadlock. It is still pushed on the held stack, because a lock taken *under* it can.
//!
//! # Cost
//!
//! Selected by `DEBUG_LOCKDEP`, which defaults to `DEBUG_BUILD`. When it is off, a
//! lock's class tag is a zero-sized type, so no lock grows by a byte, and every entry
//! point returns before touching anything. [`ENABLED`] is a `const bool` rather than a
//! `cfg` so that the checking code is type-checked in every configuration, the way
//! `kalloc`'s poisoning is. Only the tag's *type* is chosen by `cfg`, at module level,
//! and a const assertion below fails the build if the two ever disagree.
//!
//! When it is on, the state is about 1.3 KiB on a 64-bit target: the class table, a
//! 64×64 reachability bitmap and the held stack. Each tracked acquisition scans at most
//! [`MAX_CLASSES`] class pointers and [`MAX_HELD`] held entries, with interrupts masked.
//!
//! # Two kinds of state
//!
//! **The order** — which classes have been seen after which — is a fact about the
//! code, not about any one CPU, so there is one, shared, updated under a flag with
//! interrupts masked.
//!
//! **The held stack** — what this context holds right now — belongs to one context.
//! Interrupt handlers share it with the code they interrupt, which is right: a handler
//! taking `B` while the interrupted code holds `A` *is* an `A`-then-`B` ordering, and it
//! deadlocks against a `B`-then-`A` path on another CPU exactly as a nested call would.
//! Two CPUs must not share it. The first version shared one stack among everything, and
//! `ipc`'s concurrent sender-and-receiver test found that the same day: the receiver's
//! acquisition of a channel lock the sender held was reported as the receiver
//! re-taking its own lock, and the mock CPU was stopped.
//!
//! So where the stack lives is chosen by build:
//!
//! - **Kernel images:** one stack per CPU, in [`crate::percpu::PerCpu`] storage indexed by
//!   [`hal::Arch::cpu_index`]. There is one slot per configured CPU (`NR_CPUS`), and a CPU with no
//!   slot has its locks go untracked rather than recorded on another CPU's stack. The SMP bring-up
//!   check on aarch64 proves the stacks are separate: one CPU holds a lock while another takes a
//!   second one, which a shared stack records as an ordering that a later, legitimate nesting then
//!   reports as an inversion.
//! - **Host tests** (`MOCK_ARCH`): one stack per thread, since a host thread is what a CPU is to
//!   the tests. The tracker logic is the same code either way; only the storage differs.
//!
//! # Re-entrancy
//!
//! The shared state is updated with interrupts masked, so no handler on this CPU can
//! interleave with an update. What masking cannot stop is a non-maskable interrupt or
//! an exception inside the update. The update neither faults nor calls out, and **no
//! lock may be taken from NMI context**, which is already a kernel-wide rule. On a
//! machine with no compare-and-swap, a re-entry is detected and the nested acquisition
//! goes untracked. With CAS, a re-entry on one CPU cannot be told apart from contention
//! between two, so it spins.

use core::cell::UnsafeCell;
use core::mem::size_of;
use core::ptr;

use hal::Arch;

use crate::irq::IrqGuard;

/// Whether lock-order checking is built in.
pub const ENABLED: bool = kconfig::DEBUG_LOCKDEP;

/// Distinct lock classes the checker can tell apart. One bit each in a `u64`.
pub const MAX_CLASSES: usize = 64;

/// Locks one context can hold at once and still be checked.
pub const MAX_HELD: usize = 16;

/// A role a lock plays, for ordering purposes.
///
/// Declare each class as a `static`, never a `const`. Classes are compared by address,
/// and a `const` is a value copied to every use, so two uses need not share an address.
///
/// ```ignore
/// pub static CHANNEL: LockClass = LockClass::new("ipc.channel");
/// ```
pub struct LockClass {
    name: &'static str,
}

impl LockClass {
    pub const fn new(name: &'static str) -> LockClass {
        LockClass { name }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }
}

/// What the checker found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Violation {
    /// `acquiring` was taken while `held` was held, but `held` has been taken after
    /// `acquiring` before, directly or through other classes.
    Inversion {
        held: &'static str,
        acquiring: &'static str,
    },
    /// A lock this context already holds was taken again.
    Recursive { class: &'static str },
    /// A second lock of a class this context already holds was taken.
    SameClass { class: &'static str },
    /// [`MAX_HELD`] locks were already held; this one is not tracked.
    TooDeep { class: &'static str },
    /// [`MAX_CLASSES`] classes are already known; this one is not tracked.
    TooManyClasses { class: &'static str },
    /// A release of a lock the checker never saw taken. A bug in the checker.
    Unbalanced { class: &'static str },
}

/// A summary of what has been found so far.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    /// Violations recorded since boot.
    pub count: usize,
    /// The first one, which is usually the cause of the rest.
    pub first: Option<Violation>,
}

// ---- the tracker ----------------------------------------------------------------------

/// The shared half: classes, the order seen between them, and what has been reported.
struct Order {
    classes: [Option<&'static LockClass>; MAX_CLASSES],
    known: usize,
    /// `after[x]` has bit `y` set when class `y` has been taken while `x` was held,
    /// directly or transitively. Kept closed under transitivity as edges are added, so
    /// checking an acquisition is one bit test per held lock.
    after: [u64; MAX_CLASSES],
    count: usize,
    first: Option<Violation>,
}

#[derive(Clone, Copy)]
struct Held {
    class: u8,
    instance: usize,
}

/// The per-context half: what is held right now.
struct Stack {
    held: [Held; MAX_HELD],
    depth: usize,
    /// Acquisitions that were not pushed (too deep, too many classes) and not yet
    /// released. A release the stack does not know is one of these.
    untracked: usize,
}

/// The checker's state for one context, as a plain value.
///
/// The kernel reaches the shared order and each context's stack through [`acquire`],
/// [`release`] and [`report`]. A `Tracker` holds one of each and runs the same logic,
/// which is how that logic is tested without global state.
pub struct Tracker {
    order: Order,
    stack: Stack,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    pub const fn new() -> Tracker {
        Tracker {
            order: Order::new(),
            stack: Stack::new(),
        }
    }

    /// Record a blocking acquisition of `instance`, of class `class`, and check it
    /// against everything held.
    ///
    /// The lock is pushed even when an ordering violation is reported, since it is
    /// about to be held either way. The inverted edge is not recorded: it would close
    /// a cycle, after which every acquisition of those classes would report.
    pub fn acquire(&mut self, class: &'static LockClass, instance: usize) -> Result<(), Violation> {
        take(&mut self.order, &mut self.stack, class, instance, true)
    }

    /// Record a successful `try_lock`. Nothing is checked, since it did not wait;
    /// the lock is pushed, since what is taken under it can.
    pub fn acquire_try(
        &mut self,
        class: &'static LockClass,
        instance: usize,
    ) -> Result<(), Violation> {
        take(&mut self.order, &mut self.stack, class, instance, false)
    }

    /// Record a release. Releases need not be in reverse order of acquisition.
    pub fn release(&mut self, class: &'static LockClass, instance: usize) -> Result<(), Violation> {
        release_in(&mut self.order, &mut self.stack, class, instance)
    }

    /// Locks currently held and tracked.
    pub fn depth(&self) -> usize {
        self.stack.depth
    }

    pub fn report(&self) -> Report {
        self.order.report()
    }
}

impl Order {
    const fn new() -> Order {
        Order {
            classes: [None; MAX_CLASSES],
            known: 0,
            after: [0; MAX_CLASSES],
            count: 0,
            first: None,
        }
    }

    fn report(&self) -> Report {
        Report {
            count: self.count,
            first: self.first,
        }
    }

    /// Record "`to` taken while `from` held", and keep `after` transitively closed:
    /// every class that reaches `from` now reaches `to` and everything after `to`.
    fn add_edge(&mut self, from: usize, to: usize) {
        let gained = self.after[to] | (1 << to);
        let from_bit = 1u64 << from;
        for x in 0..self.known {
            if x == from || self.after[x] & from_bit != 0 {
                self.after[x] |= gained;
            }
        }
    }

    fn register(&mut self, class: &'static LockClass) -> Option<usize> {
        if let Some(i) = self.index_of(class) {
            return Some(i);
        }
        let slot = self.classes.get_mut(self.known)?;
        *slot = Some(class);
        self.known += 1;
        Some(self.known - 1)
    }

    fn index_of(&self, class: &'static LockClass) -> Option<usize> {
        self.classes
            .get(..self.known)
            .unwrap_or(&[])
            .iter()
            .position(|c| c.is_some_and(|c| ptr::eq(c, class)))
    }

    fn found(&mut self, v: Violation) -> Result<(), Violation> {
        self.count = self.count.saturating_add(1);
        if self.first.is_none() {
            self.first = Some(v);
        }
        Err(v)
    }
}

impl Stack {
    const fn new() -> Stack {
        Stack {
            held: [Held {
                class: 0,
                instance: 0,
            }; MAX_HELD],
            depth: 0,
            untracked: 0,
        }
    }

    fn held(&self) -> &[Held] {
        self.held.get(..self.depth).unwrap_or(&[])
    }
}

// Indexing below is into `after` and `classes` by class indices, which `register` only
// hands out below `MAX_CLASSES`, and into `held` below `depth`, which never exceeds
// `MAX_HELD`. None of it can panic, and `with_global` relies on that.

fn take(
    order: &mut Order,
    stack: &mut Stack,
    class: &'static LockClass,
    instance: usize,
    check: bool,
) -> Result<(), Violation> {
    let Some(index) = order.register(class) else {
        stack.untracked += 1;
        return order.found(Violation::TooManyClasses { class: class.name });
    };

    // Recursion first, before anything is recorded: the caller stops the CPU rather
    // than take the lock, so nothing about this acquisition should stick.
    if stack
        .held()
        .iter()
        .any(|h| usize::from(h.class) == index && h.instance == instance)
    {
        return order.found(Violation::Recursive { class: class.name });
    }

    let mut verdict = Ok(());
    let bit = 1u64 << index;
    for h in stack.held().iter().filter(|_| check) {
        let held = usize::from(h.class);
        if held == index {
            verdict = verdict.and(Err(Violation::SameClass { class: class.name }));
        } else if order.after[index] & (1 << held) != 0 {
            let name = order.classes[held].map_or("?", |c| c.name);
            verdict = verdict.and(Err(Violation::Inversion {
                held: name,
                acquiring: class.name,
            }));
        } else if order.after[held] & bit == 0 {
            order.add_edge(held, index);
        }
    }

    let Some(slot) = stack.held.get_mut(stack.depth) else {
        stack.untracked += 1;
        return order.found(Violation::TooDeep { class: class.name });
    };
    *slot = Held {
        class: index as u8,
        instance,
    };
    stack.depth += 1;

    match verdict {
        Ok(()) => Ok(()),
        Err(v) => order.found(v),
    }
}

fn release_in(
    order: &mut Order,
    stack: &mut Stack,
    class: &'static LockClass,
    instance: usize,
) -> Result<(), Violation> {
    let at = order.index_of(class).and_then(|index| {
        stack
            .held()
            .iter()
            .rposition(|h| usize::from(h.class) == index && h.instance == instance)
    });
    match at {
        Some(at) => {
            stack.held.copy_within(at + 1..stack.depth, at);
            stack.depth -= 1;
            Ok(())
        }
        None => match stack.untracked.checked_sub(1) {
            Some(n) => {
                stack.untracked = n;
                Ok(())
            }
            None => order.found(Violation::Unbalanced { class: class.name }),
        },
    }
}

// ---- the class a lock carries ---------------------------------------------------------

/// The class a lock carries: `Option<&'static LockClass>` when checking is built in,
/// and nothing at all when it is not.
#[cfg(CONFIG_DEBUG_LOCKDEP)]
mod tag {
    use super::LockClass;

    pub struct ClassTag(Option<&'static LockClass>);

    impl ClassTag {
        pub const fn new(class: Option<&'static LockClass>) -> ClassTag {
            ClassTag(class)
        }

        pub fn get(&self) -> Option<&'static LockClass> {
            self.0
        }
    }
}

#[cfg(not(CONFIG_DEBUG_LOCKDEP))]
mod tag {
    use super::LockClass;

    pub struct ClassTag;

    impl ClassTag {
        pub const fn new(_class: Option<&'static LockClass>) -> ClassTag {
            ClassTag
        }

        pub fn get(&self) -> Option<&'static LockClass> {
            None
        }
    }
}

pub use tag::ClassTag;

// The `cfg` that picks the tag and the `const` that gates the code come from the same
// symbol. If they ever disagree, checking is silently half on, and that is a build error.
const _: () = assert!(ENABLED == (size_of::<ClassTag>() != 0));

// ---- where the state lives ------------------------------------------------------------

/// Exclusion for the shared order, beyond the interrupt mask. With CAS, a flag other
/// CPUs spin on. Without, there is only one CPU, so the flag detects re-entry.
#[cfg(target_has_atomic = "8")]
mod busy {
    use core::hint::spin_loop;
    use core::sync::atomic::{AtomicBool, Ordering};

    pub struct Busy(AtomicBool);

    impl Busy {
        pub const fn new() -> Busy {
            Busy(AtomicBool::new(false))
        }

        pub fn enter(&self) -> bool {
            // `Acquire` on success, pairing with the `Release` in `leave`, so the
            // state the previous holder wrote is visible here.
            while self
                .0
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                spin_loop();
            }
            true
        }

        pub fn leave(&self) {
            self.0.store(false, Ordering::Release);
        }
    }
}

#[cfg(not(target_has_atomic = "8"))]
mod busy {
    use core::sync::atomic::{AtomicBool, Ordering};

    pub struct Busy(AtomicBool);

    impl Busy {
        pub const fn new() -> Busy {
            Busy(AtomicBool::new(false))
        }

        /// False when the tracker is re-entered from inside its own update, which with
        /// interrupts masked on a single CPU means an NMI or an exception.
        pub fn enter(&self) -> bool {
            if self.0.load(Ordering::Acquire) {
                return false;
            }
            self.0.store(true, Ordering::Relaxed);
            true
        }

        pub fn leave(&self) {
            self.0.store(false, Ordering::Release);
        }
    }
}

/// A kernel image's held stacks: one per CPU, in per-CPU storage.
#[cfg(not(CONFIG_MOCK_ARCH))]
mod context {
    use core::cell::UnsafeCell;

    use hal::Arch;

    use super::Stack;
    use crate::percpu::{PerCpu, Pinned};

    struct Cell(UnsafeCell<Stack>);

    // SAFETY: reached only through `with_stack`, whose callers hold the tracker's `busy`
    // flag with interrupts masked. `busy` admits one holder across every CPU, so even two
    // CPUs that wrongly shared a slot would take turns at it rather than race.
    unsafe impl Sync for Cell {}

    /// Slots: the configuration's CPU count, and one on a build without SMP. The only
    /// bound this module has is `Arch`, so the count cannot come from `HasSmp::MAX_CPUS`.
    /// It does not need to: no CPU at or past `NR_CPUS` is ever started.
    const CPUS: usize = if kconfig::NR_CPUS > 1 {
        kconfig::NR_CPUS
    } else {
        1
    };

    static STACKS: PerCpu<Cell, CPUS> =
        PerCpu::sized([const { Cell(UnsafeCell::new(Stack::new())) }; CPUS]);

    /// Run `f` on the running CPU's stack. `None` for a CPU with no slot, whose locks go
    /// untracked rather than being recorded as another CPU's.
    ///
    /// # Safety
    /// The caller holds the tracker's `busy` flag with interrupts masked.
    pub(super) unsafe fn with_stack<A: Arch, R>(f: impl FnOnce(&mut Stack) -> R) -> Option<R> {
        let pin = Pinned::<A>::new();
        let cell = STACKS.get(&pin)?;
        // SAFETY: by the caller's contract, nothing else reaches any stack meanwhile, and
        // the reference does not escape `f`.
        Some(f(unsafe { &mut *cell.0.get() }))
    }
}

/// A host test build's held stacks: one per thread, since each test thread plays a CPU.
#[cfg(CONFIG_MOCK_ARCH)]
mod context {
    extern crate std;

    use core::cell::RefCell;

    use super::Stack;

    std::thread_local! {
        static STACK: RefCell<Stack> = const { RefCell::new(Stack::new()) };
    }

    /// # Safety
    /// None needed here; the signature matches the kernel's version.
    pub(super) unsafe fn with_stack<A, R>(f: impl FnOnce(&mut Stack) -> R) -> Option<R> {
        Some(STACK.with_borrow_mut(f))
    }
}

struct Global {
    busy: busy::Busy,
    order: UnsafeCell<Order>,
}

// SAFETY: `order` is reached only through `with_global`, which holds `busy` with
// interrupts masked. `busy` admits one holder at a time: with CAS by compare-exchange,
// and without CAS because there is one CPU, its interrupts are masked, and a re-entry
// is refused rather than admitted.
unsafe impl Sync for Global {}

static GLOBAL: Global = Global {
    busy: busy::Busy::new(),
    order: UnsafeCell::new(Order::new()),
};

/// Run `f` on the shared order and this context's stack, or return `None` if they are
/// being updated underneath this call (see "Re-entrancy" in the module docs).
fn with_global<A: Arch, R>(f: impl FnOnce(&mut Order, &mut Stack) -> R) -> Option<R> {
    let _irq = IrqGuard::<A>::mask();
    if !GLOBAL.busy.enter() {
        return None;
    }
    // SAFETY: `busy` is held and interrupts are masked, which is the contract of both
    // `order` (see the `Sync` impl) and `with_stack`. Neither reference escapes `f`,
    // which is tracker code and does not panic, so `leave` below always runs.
    let r = unsafe { context::with_stack::<A, _>(|stack| f(&mut *GLOBAL.order.get(), stack)) };
    GLOBAL.busy.leave();
    r
}

/// A blocking acquisition of the lock at `instance`. Called before the lock is taken,
/// so that recursion is caught before it deadlocks.
#[inline]
pub fn acquire<A: Arch>(tag: &ClassTag, instance: usize) {
    if !ENABLED {
        return;
    }
    let Some(class) = tag.get() else {
        return;
    };
    let verdict = with_global::<A, _>(|order, stack| take(order, stack, class, instance, true));
    if let Some(Err(Violation::Recursive { .. })) = verdict {
        // Outside `with_global`, so the tracker is not left busy by a halt that unwinds
        // (a host test's) or that a debugger resumes past.
        A::halt();
    }
}

/// A successful `try_lock` of the lock at `instance`.
#[inline]
pub fn acquire_try<A: Arch>(tag: &ClassTag, instance: usize) {
    if !ENABLED {
        return;
    }
    if let Some(class) = tag.get() {
        let _ = with_global::<A, _>(|order, stack| take(order, stack, class, instance, false));
    }
}

/// The release of the lock at `instance`. Called before the lock is released.
#[inline]
pub fn release<A: Arch>(tag: &ClassTag, instance: usize) {
    if !ENABLED {
        return;
    }
    if let Some(class) = tag.get() {
        let _ = with_global::<A, _>(|order, stack| release_in(order, stack, class, instance));
    }
}

/// What the checker has found since boot. `count == 0` in a build without checking.
pub fn report<A: Arch>() -> Report {
    let none = Report {
        count: 0,
        first: None,
    };
    if !ENABLED {
        return none;
    }
    with_global::<A, _>(|order, _| order.report()).unwrap_or(none)
}

/// Start the shared order and this thread's stack again, for tests that need known
/// state.
#[cfg(test)]
pub(crate) fn reset<A: Arch>() {
    let _ = with_global::<A, _>(|order, stack| {
        *order = Order::new();
        *stack = Stack::new();
    });
}

#[cfg(test)]
mod tests;
