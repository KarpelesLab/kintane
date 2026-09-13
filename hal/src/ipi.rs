//! Inter-processor interrupts: what the SMP scheduler and TLB shootdown ask of a port.
//!
//! The kernel needs exactly three things from another CPU, and each is a kind of
//! interrupt the port routes through whatever its interrupt controller offers (SGIs on a
//! GIC, fixed vectors on an APIC):
//!
//! * [`Ipi::Call`] runs a function there and brings the result back. A boot-path facility, for
//!   checks that must run code on a particular CPU.
//! * [`Ipi::Reschedule`] makes that CPU re-evaluate what it runs. It carries no payload. The port
//!   calls the scheduler's hook after taking it, exactly as after a timer tick, so a wake-up that
//!   placed a thread on an idle or lower-priority CPU takes effect now rather than at that CPU's
//!   next timer interrupt, which on a tickless CPU may be seconds away.
//! * [`Ipi::TlbFlush`] makes that CPU run the kernel's shootdown handler, which reads what to
//!   invalidate from shared state and acknowledges. It runs in interrupt context and must not
//!   switch threads.
//!
//! A port with more than one CPU implements [`HasIpi`]. It is the contract a second SMP
//! port plugs into: nothing in the kernel names `arch::smp` functions that this trait does
//! not also name.

use crate::HasSmp;

/// Which inter-processor interrupt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ipi {
    /// Run a function on the target; see [`HasIpi::call_on`].
    Call,
    /// Make the target reschedule.
    Reschedule,
    /// Make the target run the shootdown handler.
    TlbFlush,
}

/// A port that can interrupt its other CPUs.
pub trait HasIpi: HasSmp {
    /// Whether logical CPU `cpu` has come up and can take IPIs.
    fn cpu_online(cpu: usize) -> bool;

    /// Raise `ipi` on logical CPU `cpu`. `false` if that CPU cannot be addressed, which
    /// includes a CPU that is not online. Callable with interrupts masked, from any CPU.
    fn send_ipi(cpu: usize, ipi: Ipi) -> bool;

    /// Run `f(arg)` on CPU `cpu` in interrupt context and wait for the result. `None` if
    /// the CPU cannot be reached or did not answer in time. Boot-path only.
    fn call_on(cpu: usize, f: fn(u64) -> u64, arg: u64) -> Option<u64>;

    /// The function every [`Ipi::TlbFlush`] runs, or `None` to ignore them.
    fn set_tlb_flush_handler(handler: Option<fn()>);

    /// The function [`crate::HasPageTables::flush_tlb`] calls after invalidating locally,
    /// with the same argument, so the kernel can extend the invalidation to every other
    /// CPU before it relies on it. `None` keeps flushes local, which is correct only while
    /// no other CPU can hold a translation the flush is about.
    fn set_tlb_shootdown(hook: Option<fn(Option<usize>)>);

    /// Invalidate `addr` (`None` for everything) on this CPU only, without calling the
    /// shootdown hook: what a target does when a shootdown reaches it.
    ///
    /// # Safety
    /// As [`crate::HasPageTables::flush_tlb`].
    unsafe fn flush_tlb_local(addr: Option<usize>);

    /// Hand every online secondary to `entry`. Each leaves its bring-up idle loop at its
    /// next wake-up and calls `entry(its logical index)`, which never returns, with
    /// interrupts masked. The port stops treating the secondary's timer as its own from
    /// then on: timer interrupts and reschedule IPIs on it reach the scheduler's hook.
    ///
    /// # Safety
    /// Once, from the boot CPU, after the scheduler that `entry` joins exists.
    unsafe fn release_secondaries(entry: fn(usize) -> !);
}
