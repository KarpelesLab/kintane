//! Unprivileged execution: what an architecture provides so the kernel can run a process.
//!
//! A port that implements [`HasUserMode`] can enter user mode on a thread, take a system
//! call or a fault from it, and copy bytes across the boundary without trusting the
//! pointer it was given. Everything else about a process (its address space, its handles,
//! what a system call does) is the kernel's, and is the same on every port.
//!
//! # The address split
//!
//! Every port that has this places user memory in `[USER_START, USER_END)`, one
//! top-level page-table entry above the kernel's, and the kernel in the entry below. A
//! process's root table is a copy of the kernel's with that one entry its own, so the
//! kernel half is shared by every address space by construction: an interrupt that
//! arrives while a process runs finds the kernel mapped, and a switch between processes
//! changes nothing the kernel reads.
//!
//! # A thread that runs user code
//!
//! Is a kernel thread whose entry calls [`HasUserMode::enter_user`]. From then on its
//! kernel stack is where every trap from its user code lands, and its saved context
//! carries the address space the port loads when it switches to it
//! ([`HasUserMode::bind`]). A kernel thread's context carries none, and a switch to it
//! loads the kernel's own root, so no kernel thread ever runs on tables a process might
//! free.

use crate::fault::PageFault;
use crate::{HasContextSwitch, HasPageTables, KernAddr, PhysAddr, UserAddr};

/// The saved register state of a system call, as the port's entry left it.
pub trait SyscallFrame {
    /// The system call number.
    fn number(&self) -> u64;
    /// The six argument registers, in ABI order.
    fn args(&self) -> [u64; 6];
    /// Set the two return registers: status, then value.
    fn set_result(&mut self, status: u64, value: u64);
    /// Set the one register a Linux system call returns in (`rax`, `x0`), leaving the second
    /// return register as the caller had it: Linux returns a value or a negated errno in one
    /// register and preserves the rest.
    fn set_return(&mut self, value: u64);
}

/// Why a user thread must stop: a trap its process did not ask for and the kernel could
/// not resolve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserTrap {
    /// A page fault [`UserHooks::fault`] declined.
    Page {
        fault: PageFault,
        /// The instruction that faulted.
        pc: usize,
    },
    /// Any other exception: an undefined instruction, a protection fault, a trap the
    /// process may not raise. `code` is the port's own (the vector on x86, the exception
    /// class on aarch64), for the report only.
    Exception { code: u64, pc: usize },
    /// A system call left the thread with a return address the port will not return to.
    BadReturn { pc: usize },
}

/// The kernel's side of the boundary, installed once with [`HasUserMode::install`].
pub struct UserHooks<F> {
    /// Run a system call. On return the port resumes the caller with whatever
    /// [`SyscallFrame::set_result`] left.
    pub syscall: fn(&mut F),
    /// Resolve a page fault at a user address: against the faulting process's address
    /// space, whether the fault came from its user code or from the kernel copying on its
    /// behalf. `true` retries the access.
    pub fault: fn(PageFault) -> bool,
    /// End the current user thread for `trap`. Called from the trap handler, on the
    /// thread's kernel stack, with interrupts masked; it must not return.
    pub kill: fn(UserTrap) -> !,
}

/// A user address could not be copied from or to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CopyFault;

/// The architecture can run unprivileged code.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no userspace port",
    label = "requires user mode and a system call entry",
    note = "USERSPACE depends on an architecture that implements hal::HasUserMode"
)]
pub trait HasUserMode: HasPageTables + HasContextSwitch {
    /// First address of the user half. Page-aligned.
    const USER_START: usize;
    /// One past the last address of the user half. Page-aligned.
    const USER_END: usize;
    /// `e_machine` of the programs this port runs.
    const ELF_MACHINE: u16;

    type SyscallFrame: SyscallFrame;

    /// Install the kernel's hooks and turn the system call entry on. `kernel_root` is the
    /// kernel's own address space, which a switch to a thread with no bound space loads.
    ///
    /// # Safety
    /// Once, with interrupts masked, on the running kernel address space, before any thread
    /// enters user mode.
    unsafe fn install(hooks: UserHooks<Self::SyscallFrame>, kernel_root: PhysAddr);

    /// Record in a thread's saved context the kernel stack its traps land on and the
    /// address space to load when it is switched to.
    fn bind(ctx: &mut Self::Context, kernel_stack_top: KernAddr, root: PhysAddr);

    /// Leave the kernel for user code at `entry` with stack pointer `stack` and the first
    /// four argument registers set to `args`. Every other register is cleared. The kernel
    /// stack is reset to `kernel_stack_top`, which must be the one the thread was bound to.
    ///
    /// # Safety
    /// On a thread bound with [`HasUserMode::bind`] whose address space is loaded and maps
    /// `entry` executable and `stack` writable for user code.
    unsafe fn enter_user(
        entry: usize,
        stack: usize,
        args: [usize; 4],
        kernel_stack_top: KernAddr,
    ) -> !;

    /// Copy `dst.len()` bytes from user address `src`. Fails, without faulting the kernel,
    /// if any byte is outside the user half or is not readable once
    /// [`UserHooks::fault`] has had its chance.
    ///
    /// # Safety
    /// The address space of the process `src` belongs to must be loaded.
    unsafe fn copy_from_user(dst: &mut [u8], src: UserAddr) -> Result<(), CopyFault>;

    /// Copy `src` to user address `dst`, with the same guarantees.
    ///
    /// # Safety
    /// As [`HasUserMode::copy_from_user`].
    unsafe fn copy_to_user(dst: UserAddr, src: &[u8]) -> Result<(), CopyFault>;

    /// Set the running CPU's user thread pointer: `FS` base on x86_64, `TPIDR_EL0` on aarch64.
    /// What a Linux process's `arch_prctl(ARCH_SET_FS)` asks for.
    ///
    /// Not yet part of a thread's saved context: a switch to another thread does not change
    /// it. So a caller must reset it when the process that set it is done, and a process that
    /// sets it must not share a CPU with another that relies on it.
    ///
    /// # Safety
    /// On the CPU the process runs on, with interrupts masked or from its own system call.
    unsafe fn set_tls(value: usize);
}

/// Whether `[addr, addr + len)` lies in the user half. The first check of every copy, so
/// that no copy ever starts on a kernel address.
pub fn user_range<A: HasUserMode>(addr: usize, len: usize) -> bool {
    addr >= A::USER_START && addr.checked_add(len).is_some_and(|end| end <= A::USER_END)
}
