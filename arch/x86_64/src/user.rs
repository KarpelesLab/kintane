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
//! # The `swapgs` discipline
//!
//! Each CPU's `GS` base names its block (`smp.rs`). While the kernel runs, `GS` is that block
//! and `MSR_KERNEL_GS_BASE` holds the user value; while user code runs, the two are
//! exchanged. So every way into ring 3 swaps once on the way out, and every way back swaps
//! once on the way in:
//!
//! * [`syscall_entry`] swaps first, before any `gs:` access, and swaps back just before `sysretq`;
//! * an interrupt or exception from ring 3 swaps at the top of its handler and, if it returns, at
//!   the bottom (`smp::gs_enter`, `smp::gs_leave`);
//! * [`X86_64::enter_user`] swaps just before its `iretq`.
//!
//! The kernel stack a `syscall` switches to is the running CPU's `kernel_rsp`, reached through
//! `GS`, and installed together with `TSS.rsp0` whenever a user thread starts or is switched
//! to on that CPU. The user stack pointer is parked in the block for the two instructions it
//! takes to reach the kernel stack, then pushed there, so a system call that blocks and
//! resumes on another CPU returns to the right stack. User code can load its own `GS`
//! selector; the only descriptors it can name have a zero base, and the swap on entry takes
//! whatever base it left out of the kernel's way.
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
    fn set_return(&mut self, value: u64) {
        // Linux returns in `rax` alone and preserves `rdx`.
        self.nr = value;
    }
}

/// The installed hooks. `syscall` and `kill` are called through it; `fault` is used by the
/// page-fault path and the user copies.
struct Hooks(UnsafeCell<Option<UserHooks<SyscallFrame>>>);
// SAFETY: written once by `install` before any user thread runs, read-only afterwards.
unsafe impl Sync for Hooks {}
static HOOKS: Hooks = Hooks(UnsafeCell::new(None));

/// The kernel's own root, loaded on a switch to a thread that runs no user code.
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);

/// Load the address space a thread that is about to run needs: its own if it runs user
/// code (`root`, as `bind` recorded it), otherwise the kernel's.
///
/// Called by the context switch, which is where a thread's address space has to arrive: a
/// user thread may resume on a different CPU from the one it left, and the space must
/// follow it there. Nothing happens before `install` has recorded the kernel root, so a
/// kernel built without userspace never writes CR3 here, and nothing happens when the
/// wanted space is already loaded, so a kernel-to-kernel switch costs one register read
/// rather than the TLB flush a CR3 write is.
pub(crate) unsafe fn load_space(root: u64) {
    let want = if root != 0 {
        root
    } else {
        KERNEL_ROOT.load(Ordering::Relaxed)
    };
    if want == 0 || <X86_64 as hal::HasPageTables>::root().raw() == want {
        return;
    }
    // SAFETY: `want` is either the kernel root `install` recorded or a root `bind`
    // recorded for the thread being resumed, and every root maps the kernel half
    // identically, so the code and stack running this switch stay mapped across the write.
    unsafe { <X86_64 as hal::HasPageTables>::set_root(PhysAddr::new(want)) };
}

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

/// On the way out of an interrupt handler: if the interrupt arrived in ring 3, give the
/// kernel the chance to end the thread instead of returning to it. Called after the
/// handler's EOI and scheduler hook, with `GS` still the kernel's.
pub(crate) fn interrupted(from_user: bool) {
    if from_user && let Some(h) = hooks() {
        (h.interrupted)();
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
    // Interrupts are already off: SFMASK cleared IF on entry. The kernel's GS first, then
    // the kernel stack, parking the user one in this CPU's block only until it is pushed.
    swapgs
    mov     gs:[{user_rsp}], rsp
    mov     rsp, gs:[{kernel_rsp}]
    push    qword ptr gs:[{user_rsp}]

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
    pop     rsp                 // user stack, from this thread's own kernel stack
    swapgs
    sysretq
"#,
    user_rsp = const crate::smp::USER_RSP_OFFSET,
    kernel_rsp = const crate::smp::KERNEL_RSP_OFFSET,
);

unsafe extern "C" {
    fn __syscall_entry();
}

const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;
const MSR_FS_BASE: u32 = 0xC000_0100;
const EFER_SCE: u64 = 1 << 0;
/// Clear the interrupt flag and the direction flag on entry.
const SFMASK: u64 = (1 << 9) | (1 << 10);

/// Turn on `syscall` on the running CPU, and point it at [`syscall_entry`].
///
/// The four MSRs are per CPU, so this runs on the boot CPU from `install` and on each
/// secondary as it comes up (`smp::set_cpu_init`).
///
/// # Safety
/// Once per CPU, on that CPU with interrupts masked, after its GDT is loaded.
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
        // Every secondary started from here on sets its own MSRs the same way.
        crate::smp::set_cpu_init(init_syscall);
    }

    fn bind(ctx: &mut Self::Context, kernel_stack_top: KernAddr, root: PhysAddr) {
        ctx.user_kernel_stack = kernel_stack_top.raw() as u64;
        ctx.user_root = root.raw();
    }

    unsafe fn set_tls(value: usize) {
        // SAFETY: writing `IA32_FS_BASE` is defined at CPL 0. The kernel addresses its per-CPU
        // data through `GS`, never `FS`, so this changes nothing the kernel reads.
        unsafe { paging::write_msr(MSR_FS_BASE, value as u64) };
    }

    unsafe fn enter_user(
        entry: usize,
        stack: usize,
        args: [usize; 4],
        kernel_stack_top: KernAddr,
    ) -> ! {
        // Traps from ring 3, and the syscall entry, both land on this stack, on this CPU.
        // SAFETY: the TSS is loaded and interrupts are masked (a thread enters user mode
        // from its own kernel context with them masked); `top` is this thread's kernel
        // stack.
        unsafe { crate::smp::install_kernel_stack(kernel_stack_top.raw() as u64) };
        // SAFETY: an `iretq` into ring 3 with a frame this builds; the segment selectors
        // are the ring-3 pair, RFLAGS has IF set so user code runs with interrupts on, and
        // `entry`/`stack` are in the process's mapped user half. Every register not carrying
        // an argument is cleared, so nothing kernel-side leaks into the process. The
        // `swapgs` puts the CPU's `GS` pair in the user arrangement, the last thing before
        // ring 3; interrupts stay masked from it to the `iretq`.
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
                "swapgs",
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
