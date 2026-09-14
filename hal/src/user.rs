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

/// A user thread's registers in full: what a system call interrupted, and what a thread is
/// resumed with. What a Linux `fork` or `clone` copies into the new thread, and what an
/// `execve` replaces.
pub trait UserRegisters: Copy {
    /// Registers that start a program at `pc` on stack `sp`, with every other register zero
    /// and the flags a program starts with.
    fn start(pc: usize, sp: usize) -> Self;
    /// Set the register a system call returns in (`rax`, `x0`).
    fn set_return(&mut self, value: u64);
    /// Set the stack pointer.
    fn set_stack(&mut self, sp: usize);
    /// The address the thread resumes at.
    fn pc(&self) -> usize;
    /// Every register as a word, in the port's own order, which its `Registers` documents; a
    /// port with fewer than [`REGISTER_WORDS`] leaves the rest zero. What a kernel that keeps a
    /// context in user memory reads and writes: a Linux signal frame.
    fn to_words(&self) -> [u64; REGISTER_WORDS];
    /// Registers from words in that order. Nothing is checked here: a context returns to user
    /// code only through [`HasUserMode::set_registers`] or [`HasUserMode::resume_user`], which
    /// sanitise its address and its flags.
    fn from_words(words: &[u64; REGISTER_WORDS]) -> Self;
}

/// Words [`UserRegisters::to_words`] gives: aarch64's thirty-one general registers, its stack
/// pointer, program counter and processor state.
pub const REGISTER_WORDS: usize = 34;

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
    /// Called on the way back to user code from an interrupt that arrived while it ran —
    /// after the interrupt's own handling, its acknowledgement and the scheduler's hook — on
    /// the thread's kernel stack, with interrupts masked. It may end the thread rather than
    /// return: that is how a thread spinning in user mode, which makes no system call, is
    /// stopped when its process ends.
    pub interrupted: fn(),
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
    /// The thread pointer is part of a user thread's saved context: a switch away from a
    /// thread bound with [`HasUserMode::bind`] saves it, and a switch to one loads it. So a
    /// value set here stays with the calling thread wherever it next runs, and no other
    /// thread sees it.
    ///
    /// # Safety
    /// On the CPU the thread runs on, with interrupts masked or from its own system call.
    unsafe fn set_tls(value: usize);

    /// The running CPU's user thread pointer, as [`HasUserMode::set_tls`] or the program
    /// itself last left it. What a `fork` gives the child.
    ///
    /// # Safety
    /// As [`HasUserMode::set_tls`].
    unsafe fn tls() -> usize;

    /// A user thread's registers in full.
    type UserRegisters: UserRegisters;

    /// The registers of the thread that made the system call in `frame`, as it will see them
    /// when the call returns.
    fn registers(frame: &Self::SyscallFrame) -> Self::UserRegisters;

    /// Make the system call in `frame` return to `regs` rather than to where it was made.
    /// The address must be one [`HasUserMode::USER_START`]..[`HasUserMode::USER_END`] holds,
    /// and a caller checks it: the port returns to it.
    fn set_registers(frame: &mut Self::SyscallFrame, regs: &Self::UserRegisters);

    /// Leave the kernel for user code with every register as `regs` has it. The flags are
    /// sanitised to user mode with interrupts enabled. The kernel stack is reset to
    /// `kernel_stack_top`, as [`HasUserMode::enter_user`] does.
    ///
    /// # Safety
    /// As [`HasUserMode::enter_user`], for `regs`' address and stack pointer.
    unsafe fn resume_user(regs: &Self::UserRegisters, kernel_stack_top: KernAddr) -> !;
}

/// Whether `[addr, addr + len)` lies in the user half. The first check of every copy, so
/// that no copy ever starts on a kernel address.
pub fn user_range<A: HasUserMode>(addr: usize, len: usize) -> bool {
    addr >= A::USER_START && addr.checked_add(len).is_some_and(|end| end <= A::USER_END)
}
