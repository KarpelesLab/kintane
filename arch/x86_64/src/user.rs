//! Ring 3 on x86_64: the `syscall` entry, the return to user, and the user-memory copies.
//!
//! # The four things the kernel needs from the CPU
//!
//! 1. **Segments for ring 3.** `gdt.rs` carries a user code and a user data descriptor, in the
//!    order `SYSRET` requires. Nothing else about segmentation matters in long mode.
//! 2. **A kernel stack per privilege change.** `TSS.rsp0` is loaded by the CPU when a trap is taken
//!    from ring 3, so a fault in user code lands on the thread's kernel stack. `SYSCALL` does *not*
//!    switch the stack; [`syscall_entry`] does it, from a saved kernel-stack pointer.
//! 3. **The `syscall` fast path.** `LSTAR` is the entry, `STAR` the segment selectors, `SFMASK` the
//!    flags cleared on entry (interrupts among them, so the entry runs masked). `EFER.SCE` turns
//!    the instruction on.
//! 4. **A way back.** `SYSRET` for a return from a system call, `iretq` for the first entry into
//!    user mode and for resuming after a fault.
//!
//! # The `swapgs` discipline, and why there is none yet
//!
//! On a machine with per-CPU state reached through `GS`, the entry's first act is
//! `swapgs`, so a kernel `GS` base replaces the user one before any `gs:`-relative access,
//! and its last act before `sysret` swaps back. This port has one CPU and no per-CPU `GS`,
//! so the entry keeps the kernel stack in a plain global and does no `swapgs`. When the
//! SMP work gives each CPU a `GS` base, the saved user stack and the kernel stack move
//! into that per-CPU block and the entry gains a `swapgs` at each end; the entry is shaped
//! for that — it touches exactly two globals, which become two `gs:` offsets.
//!
//! # The `SYSRET` canonical-address hazard
//!
//! `sysretq` puts `RCX` into `RIP` without checking that it is canonical, and a
//! non-canonical `RIP` at CPL 3 is a `#GP` *in ring 0* on some CPUs — an escalation.
//! [`return_to_user`] therefore returns through `iretq`, which does check, on any path
//! where the user `RIP` is not one the kernel itself put there. The `syscall` return does
//! use `sysretq`, because there the return address is the one the CPU saved into `RCX` on
//! entry, which was canonical by construction.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use hal::user::{CopyFault, SyscallFrame as SyscallFrameTrait, UserHooks, UserTrap};
use hal::{Arch, KernAddr, PhysAddr, UserAddr};

use crate::X86_64;
use crate::gdt::{self, USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::paging::{self, USER_BIT, WRITABLE};

/// The user half: `[USER_START, USER_END)`, the second 512 GiB, which is the top-level
/// page-table entry above the kernel's. `link.ld` for a user program links there.
pub const USER_START: usize = 1 << 39;
pub const USER_END: usize = 2 << 39;

/// The saved registers of a `syscall`, as [`syscall_entry`] pushes them. `repr(C)` and
/// the assembly offsets are one layout in two languages.
#[repr(C)]
pub struct SyscallFrame {
    /// The number, in the slot the status is written back to.
    nr: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    r10: u64,
    r8: u64,
    r9: u64,
    /// User return address, saved by `syscall` into `rcx`.
    rip: u64,
    /// User flags, saved by `syscall` into `r11`.
    rflags: u64,
}

impl SyscallFrameTrait for SyscallFrame {
    fn number(&self) -> u64 {
        self.nr
    }
    fn args(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }
    fn set_result(&mut self, status: u64, value: u64) {
        // Status returns in the number's register (`rax`), value in `rdx`.
        self.nr = status;
        self.rdx = value;
    }
}

/// The running thread's kernel stack top, loaded by [`syscall_entry`]. One global on this
/// uniprocessor port; a `gs:` offset once there is per-CPU state. Set by [`bind_current`]
/// and [`X86_64::enter_user`].
static KERNEL_RSP: AtomicU64 = AtomicU64::new(0);
/// Where [`syscall_entry`] stashes the user stack pointer across the call.
static USER_RSP: AtomicU64 = AtomicU64::new(0);

/// The installed hooks. `syscall` and `kill` are called through it; `fault` is used by the
/// page-fault path and the user copies.
struct Hooks(UnsafeCell<Option<UserHooks<SyscallFrame>>>);
// SAFETY: written once by `install` before any user thread runs, read-only afterwards.
unsafe impl Sync for Hooks {}
static HOOKS: Hooks = Hooks(UnsafeCell::new(None));

/// The kernel's own root, loaded on a switch to a thread that runs no user code.
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);

fn hooks() -> Option<&'static UserHooks<SyscallFrame>> {
    // SAFETY: see `Hooks`.
    unsafe { (*HOOKS.0.get()).as_ref() }
}

/// Route a page fault taken in ring 3 to the process's address space; `true` retries.
pub(crate) fn user_fault(fault: hal::fault::PageFault) -> bool {
    hooks().is_some_and(|h| (h.fault)(fault))
}

/// End the user thread now running, for `trap`. Never returns.
pub(crate) fn kill(trap: UserTrap) -> ! {
    match hooks() {
        Some(h) => (h.kill)(trap),
        None => X86_64::halt(),
    }
}

/// The Rust side of the `syscall` entry: run the installed handler on `frame`.
#[unsafe(no_mangle)]
extern "C" fn x86_64_syscall(frame: *mut SyscallFrame) {
    // SAFETY: `frame` points at the register block `syscall_entry` just pushed onto the
    // kernel stack, live for this call and aliased by nothing.
    let frame = unsafe { &mut *frame };
    match hooks() {
        Some(h) => (h.syscall)(frame),
        None => frame.set_result(12, 0), // 12 = abi::Error::Unsupported
    }
}

core::arch::global_asm!(
    r#"
.section .text, "ax"
.globl __syscall_entry
__syscall_entry:
    // Interrupts are already off: SFMASK cleared IF on entry. Swap to the kernel stack,
    // saving the user one. (No swapgs: see the module comment.)
    mov     [rip + {user_rsp}], rsp
    mov     rsp, [rip + {kernel_rsp}]

    // Build a SyscallFrame. Push order is reverse of the struct, so rax (the number) ends
    // up at the lowest address, which is where rsp points and where the struct begins.
    push    r11                 // rflags, saved by syscall
    push    rcx                 // rip, saved by syscall
    push    r9
    push    r8
    push    r10
    push    rdx
    push    rsi
    push    rdi
    push    rax                 // number

    mov     rdi, rsp
    call    x86_64_syscall

    pop     rax                 // status (written into the number slot)
    pop     rdi
    pop     rsi
    pop     rdx                 // value
    pop     r10
    pop     r8
    pop     r9
    pop     rcx                 // user rip
    pop     r11                 // user rflags
    mov     rsp, [rip + {user_rsp}]
    sysretq
"#,
    user_rsp = sym USER_RSP,
    kernel_rsp = sym KERNEL_RSP,
);

unsafe extern "C" {
    fn __syscall_entry();
}

const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;
const EFER_SCE: u64 = 1 << 0;
/// Clear the interrupt flag and the direction flag on entry.
const SFMASK: u64 = (1 << 9) | (1 << 10);

/// Turn on `syscall`, and point it at [`syscall_entry`].
///
/// # Safety
/// Once, on the boot CPU with interrupts masked, after the GDT is loaded.
unsafe fn init_syscall() {
    // STAR[47:32] = kernel code (syscall loads CS = this, SS = this + 8 = kernel data).
    // STAR[63:48] = kernel data (sysret loads CS = this + 16 = user code, SS = this + 8 =
    // user data). This is exactly why gdt.rs orders the four descriptors as it does.
    let star =
        (u64::from(gdt::KERNEL_CODE_SELECTOR) << 32) | (u64::from(gdt::KERNEL_DATA_SELECTOR) << 48);
    // SAFETY: writing these architectural MSRs is defined at CPL 0; `__syscall_entry` is a
    // real, mapped entry point, and `EFER` already has LME set from boot, so OR-ing SCE
    // changes only the `syscall` enable.
    unsafe {
        paging::write_msr(MSR_STAR, star);
        let entry: unsafe extern "C" fn() = __syscall_entry;
        paging::write_msr(MSR_LSTAR, entry as usize as u64);
        paging::write_msr(MSR_SFMASK, SFMASK);
        paging::write_msr(MSR_EFER, paging::read_msr(MSR_EFER) | EFER_SCE);
    }
}

impl hal::HasUserMode for X86_64 {
    const USER_START: usize = USER_START;
    const USER_END: usize = USER_END;
    const ELF_MACHINE: u16 = 62; // EM_X86_64

    type SyscallFrame = SyscallFrame;

    unsafe fn install(hooks: UserHooks<Self::SyscallFrame>, kernel_root: PhysAddr) {
        // SAFETY: see `Hooks`; the caller guarantees this runs once before any user thread.
        unsafe { *HOOKS.0.get() = Some(hooks) };
        KERNEL_ROOT.store(kernel_root.raw(), Ordering::Relaxed);
        // SAFETY: caller's obligation — boot CPU, masked, GDT loaded.
        unsafe { init_syscall() };
    }

    fn bind(ctx: &mut Self::Context, kernel_stack_top: KernAddr, root: PhysAddr) {
        ctx.user_kernel_stack = kernel_stack_top.raw() as u64;
        ctx.user_root = root.raw();
    }

    unsafe fn enter_user(
        entry: usize,
        stack: usize,
        args: [usize; 4],
        kernel_stack_top: KernAddr,
    ) -> ! {
        // Traps from ring 3, and the syscall entry, both return to this stack.
        // SAFETY: the TSS is loaded and interrupts are masked (a thread enters user mode
        // from its own kernel context with them masked); `top` is this thread's kernel
        // stack.
        unsafe { gdt::set_kernel_stack(kernel_stack_top.raw() as u64) };
        KERNEL_RSP.store(kernel_stack_top.raw() as u64, Ordering::Relaxed);
        // SAFETY: an `iretq` into ring 3 with a frame this builds; the segment selectors
        // are the ring-3 pair, RFLAGS has IF set so user code runs with interrupts on, and
        // `entry`/`stack` are in the process's mapped user half. Every register not carrying
        // an argument is cleared, so nothing kernel-side leaks into the process.
        unsafe {
            core::arch::asm!(
                "push {ss}",
                "push {rsp}",
                "push {rflags}",
                "push {cs}",
                "push {rip}",
                "xor rax, rax",
                "xor rbx, rbx",
                "xor rbp, rbp",
                "xor r8, r8",
                "xor r9, r9",
                "xor r10, r10",
                "xor r11, r11",
                "xor r12, r12",
                "xor r13, r13",
                "xor r14, r14",
                "xor r15, r15",
                "iretq",
                ss = in(reg) u64::from(USER_DATA_SELECTOR),
                rsp = in(reg) stack as u64,
                rflags = in(reg) 0x202u64,
                cs = in(reg) u64::from(USER_CODE_SELECTOR),
                rip = in(reg) entry as u64,
                in("rdi") args[0] as u64,
                in("rsi") args[1] as u64,
                in("rdx") args[2] as u64,
                in("rcx") args[3] as u64,
                options(noreturn),
            )
        }
    }

    unsafe fn copy_from_user(dst: &mut [u8], src: UserAddr) -> Result<(), CopyFault> {
        prepare(src.raw(), dst.len(), false)?;
        // SAFETY: `prepare` proved every page is present and user-accessible, so this reads
        // only mapped memory; the process address space is loaded.
        unsafe {
            core::ptr::copy_nonoverlapping(src.raw() as *const u8, dst.as_mut_ptr(), dst.len())
        };
        Ok(())
    }

    unsafe fn copy_to_user(dst: UserAddr, src: &[u8]) -> Result<(), CopyFault> {
        prepare(dst.raw(), src.len(), true)?;
        // SAFETY: `prepare` proved every page is present and writable for the user; the
        // process address space is loaded.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst.raw() as *mut u8, src.len()) };
        Ok(())
    }
}

/// Prove `[addr, addr+len)` is in the user half and every page is present and, for a
/// write, user-writable — faulting each page in through the hook first.
///
/// This is the choice made instead of exception-table fixups: because all user memory is
/// backed by the process's `Vm`, a page that is legitimately absent is one the fault hook
/// will map, and one it will not map is an address the copy must refuse. Resolving up
/// front means the copy itself touches only present pages and cannot fault the kernel, so
/// no fixup table is needed. A page the hook maps and a later check still finds absent is
/// a hook that lied, and is refused.
fn prepare(addr: usize, len: usize, write: bool) -> Result<(), CopyFault> {
    if len == 0 {
        return Ok(());
    }
    if !hal::user::user_range::<X86_64>(addr, len) {
        return Err(CopyFault);
    }
    let page = <X86_64 as hal::Arch>::PAGE_SIZE;
    let last = addr.checked_add(len - 1).ok_or(CopyFault)?;
    let mut p = addr & !(page - 1);
    loop {
        if !page_ready(p, write) {
            let access = if write {
                hal::fault::Access::Write
            } else {
                hal::fault::Access::Read
            };
            if !user_fault(hal::fault::PageFault { addr: p, access }) || !page_ready(p, write) {
                return Err(CopyFault);
            }
        }
        if p >= (last & !(page - 1)) {
            return Ok(());
        }
        p += page;
    }
}

/// Whether the page at `va` is present, user-accessible, and writable if `write`.
fn page_ready(va: usize, write: bool) -> bool {
    match paging::user_leaf_bits(va) {
        Some(bits) => bits & USER_BIT != 0 && (!write || bits & WRITABLE != 0),
        None => false,
    }
}

/// Set the current thread's kernel stack and process root, for a switch that returns into
/// its user code. On this single-process slice the root is loaded once by `enter_user`;
/// this exists for the switch path a second process will need.
///
/// # Safety
/// On the thread being switched to, with interrupts masked.
#[allow(dead_code)]
pub(crate) unsafe fn bind_current(ctx: &crate::context::Context) {
    if ctx.user_kernel_stack != 0 {
        KERNEL_RSP.store(ctx.user_kernel_stack, Ordering::Relaxed);
        // SAFETY: the TSS is loaded; caller guarantees masked, on the target thread.
        unsafe { gdt::set_kernel_stack(ctx.user_kernel_stack) };
    }
}
