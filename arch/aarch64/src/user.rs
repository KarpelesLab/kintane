//! EL0 on aarch64: the `svc` entry, the return to user, and the user-memory copies.
//!
//! Far less machinery than x86 asks for. There are no segments and no fast-path MSRs:
//! `svc #0` is always a valid instruction, and the CPU's exception mechanism does the
//! privilege change. A trap from EL0 lands in the "lower EL, AArch64" quarter of the
//! vector table already installed, on `SP_EL1`, which is the user thread's kernel stack —
//! so no separate `rsp0` to program. What this file adds is the four pieces the abstract
//! contract names:
//!
//! 1. **A drop to EL0.** [`X86_64::enter_user`]'s counterpart sets `SP_EL0`, `ELR_EL1` and a
//!    `SPSR_EL1` selecting EL0t, then `eret`.
//! 2. **A system-call decode.** [`exception`](crate::exception) hands a `svc` from EL0 here as a
//!    [`SyscallFrame`] over the saved registers: `x8` the number, `x0`–`x5` the arguments,
//!    `x0`/`x1` the two return registers.
//! 3. **Fault routing.** A data or instruction abort from EL0 goes to the process's address space
//!    or kills the process; the kernel is never halted for a program's fault.
//! 4. **User copies.** [`X86_64::copy_from_user`]'s counterpart validates and faults in every page
//!    before touching it, so the copy cannot fault the kernel. See that port for why this is chosen
//!    over an exception-fixup table.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use hal::user::{CopyFault, SyscallFrame as SyscallFrameTrait, UserHooks, UserTrap};
use hal::{Arch, KernAddr, PhysAddr, UserAddr};

use crate::exception::TrapFrame;
use crate::{Aarch64, paging};

/// The user half: the second 512 GiB, one top-level `TTBR0` entry above the kernel's.
pub const USER_START: usize = 1 << 39;
pub const USER_END: usize = 2 << 39;

/// A system call's saved registers, borrowed from the exception frame.
pub struct SyscallFrame {
    frame: *mut TrapFrame,
}

impl SyscallFrameTrait for SyscallFrame {
    fn number(&self) -> u64 {
        // SAFETY: `frame` is the live exception frame for this call; `x8` is the number.
        unsafe { (*self.frame).x[8] }
    }
    fn args(&self) -> [u64; 6] {
        // SAFETY: as above; `x0`–`x5` are the argument registers.
        let x = unsafe { &(*self.frame).x };
        [x[0], x[1], x[2], x[3], x[4], x[5]]
    }
    fn set_result(&mut self, status: u64, value: u64) {
        // SAFETY: as above; the epilogue restores `x0`/`x1` from the frame on `eret`.
        unsafe {
            (*self.frame).x[0] = status;
            (*self.frame).x[1] = value;
        }
    }
    fn set_return(&mut self, value: u64) {
        // SAFETY: as above; Linux returns in `x0` alone.
        unsafe { (*self.frame).x[0] = value };
    }
}

/// A user thread's registers, for `fork`, `clone` and `execve`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Registers {
    x: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

/// The condition flags, the only part of `SPSR_EL1` a user thread chooses. The rest selects
/// EL0t with interrupts unmasked, which is zero.
const USER_PSTATE: u64 = 0xf000_0000;

/// `pc` if it lies in the user half, zero otherwise, where a return faults at EL0 and ends
/// the process rather than anything else.
fn user_pc(pc: u64) -> u64 {
    if hal::user::user_range::<Aarch64>(pc as usize, 1) {
        pc
    } else {
        0
    }
}

impl hal::user::UserRegisters for Registers {
    fn start(pc: usize, sp: usize) -> Self {
        Registers {
            x: [0; 31],
            sp: sp as u64,
            pc: pc as u64,
            pstate: 0,
        }
    }
    fn set_return(&mut self, value: u64) {
        self.x[0] = value;
    }
    fn set_stack(&mut self, sp: usize) {
        self.sp = sp as u64;
    }
    fn pc(&self) -> usize {
        self.pc as usize
    }
}

/// The running CPU's `TPIDR_EL0`.
///
/// # Safety
/// At EL1; the value belongs to whichever user thread last ran here.
pub(crate) unsafe fn read_tpidr_el0() -> u64 {
    let v: u64;
    // SAFETY: `TPIDR_EL0` is readable at EL1.
    unsafe { core::arch::asm!("mrs {v}, tpidr_el0", v = out(reg) v, options(nostack)) };
    v
}

/// Set the running CPU's `TPIDR_EL0`.
///
/// # Safety
/// At EL1, for the user thread about to run here.
pub(crate) unsafe fn write_tpidr_el0(value: u64) {
    // SAFETY: `TPIDR_EL0` is writable at EL1 and read by nothing the kernel does.
    unsafe { core::arch::asm!("msr tpidr_el0, {v}", v = in(reg) value, options(nostack)) };
}

/// The installed hooks.
struct Hooks(UnsafeCell<Option<UserHooks<SyscallFrame>>>);
// SAFETY: written once by `install` before any user thread runs, read-only afterwards.
unsafe impl Sync for Hooks {}
static HOOKS: Hooks = Hooks(UnsafeCell::new(None));
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);

fn hooks() -> Option<&'static UserHooks<SyscallFrame>> {
    // SAFETY: see `Hooks`.
    unsafe { (*HOOKS.0.get()).as_ref() }
}

/// Load the address space a thread that is about to run needs: its own if it runs user
/// code (`root`, as `bind` recorded it), otherwise the kernel's.
///
/// Called by the context switch, which is where a thread's address space has to arrive: a
/// user thread may resume on a different CPU from the one it left, and the space must
/// follow it there. Nothing happens before `install` has recorded the kernel root, so a
/// kernel built without userspace never writes `TTBR0_EL1` here, and nothing happens when
/// the wanted space is already loaded, so a kernel-to-kernel switch costs one system
/// register read rather than the invalidation `set_root` ends with.
pub(crate) unsafe fn load_space(root: u64) {
    let want = if root != 0 {
        root
    } else {
        KERNEL_ROOT.load(Ordering::Relaxed)
    };
    if want == 0 || <Aarch64 as hal::HasPageTables>::root().raw() == want {
        return;
    }
    // SAFETY: `want` is either the kernel root `install` recorded or a root `bind`
    // recorded for the thread being resumed, and every root maps the kernel half
    // identically, so the code and stack running this switch stay mapped across the write.
    unsafe { <Aarch64 as hal::HasPageTables>::set_root(PhysAddr::new(want)) };
}

/// A `svc` or a fault from EL0, routed from the exception handler. Returns to resume the
/// process (a resolved fault, or a system call whose result is now in the frame); does not
/// return when it kills the process.
///
/// # Safety
/// `frame` is the live exception frame for a trap taken from EL0.
pub(crate) unsafe fn on_lower_sync(esr: u64, far: u64, frame: *mut TrapFrame) {
    let ec = (esr >> 26) & 0x3f;
    match ec {
        // SVC from AArch64: a system call.
        0x15 => {
            if let Some(h) = hooks() {
                let mut sf = SyscallFrame { frame };
                (h.syscall)(&mut sf);
            }
        }
        // Data abort (0x24) or instruction abort (0x20) from a lower EL: a user page fault.
        0x24 | 0x20 => {
            let access = if ec == 0x20 {
                hal::fault::Access::Execute
            } else if esr & (1 << 6) != 0 {
                hal::fault::Access::Write
            } else {
                hal::fault::Access::Read
            };
            #[allow(clippy::as_conversions)]
            let fault = hal::fault::PageFault {
                addr: far as usize,
                access,
            };
            if hooks().is_some_and(|h| (h.fault)(fault)) {
                return;
            }
            // SAFETY: `elr` is the faulting instruction; the frame is live.
            let pc = unsafe { (*frame).elr } as usize;
            kill(UserTrap::Page { fault, pc });
        }
        // Any other exception from EL0 is the process's problem.
        _ => {
            // SAFETY: the frame is live.
            let pc = unsafe { (*frame).elr } as usize;
            kill(UserTrap::Exception { code: ec, pc });
        }
    }
}

/// Route a user page fault taken while the kernel copies on the process's behalf.
pub(crate) fn user_fault(fault: hal::fault::PageFault) -> bool {
    hooks().is_some_and(|h| (h.fault)(fault))
}

/// End the running user thread. Never returns.
fn kill(trap: UserTrap) -> ! {
    match hooks() {
        Some(h) => (h.kill)(trap),
        None => Aarch64::halt(),
    }
}

/// On the way out of an IRQ taken from EL0: give the kernel the chance to end the thread
/// instead of returning to it. Called after dispatch, so after every EOI and the scheduler's
/// hook.
pub(crate) fn interrupted() {
    if let Some(h) = hooks() {
        (h.interrupted)();
    }
}

impl hal::HasUserMode for Aarch64 {
    const USER_START: usize = USER_START;
    const USER_END: usize = USER_END;
    const ELF_MACHINE: u16 = 183; // EM_AARCH64

    type SyscallFrame = SyscallFrame;

    unsafe fn install(hooks: UserHooks<Self::SyscallFrame>, kernel_root: PhysAddr) {
        // SAFETY: see `Hooks`; caller guarantees once, before any user thread.
        unsafe { *HOOKS.0.get() = Some(hooks) };
        KERNEL_ROOT.store(kernel_root.raw(), Ordering::Relaxed);
    }

    fn bind(ctx: &mut Self::Context, kernel_stack_top: KernAddr, root: PhysAddr) {
        // On aarch64 the trap from EL0 uses SP_EL1, which is the thread's current kernel
        // SP, so nothing extra need be programmed; the fields are recorded for a future
        // switch that changes address spaces.
        ctx.user_kernel_stack = kernel_stack_top.raw() as u64;
        ctx.user_root = root.raw();
    }

    unsafe fn set_tls(value: usize) {
        // SAFETY: `TPIDR_EL0` is EL0's thread pointer, writable at EL1 and read by nothing the
        // kernel does.
        unsafe { write_tpidr_el0(value as u64) };
    }

    unsafe fn tls() -> usize {
        // SAFETY: as above.
        unsafe { read_tpidr_el0() as usize }
    }

    type UserRegisters = Registers;

    fn registers(frame: &SyscallFrame) -> Registers {
        // SAFETY: `frame` is the live exception frame of this system call.
        let f = unsafe { &*frame.frame };
        Registers {
            x: f.x,
            sp: f.sp_el0,
            pc: f.elr,
            pstate: f.spsr,
        }
    }

    fn set_registers(frame: &mut SyscallFrame, regs: &Registers) {
        // SAFETY: as above; the epilogue restores every one of these on `eret`.
        let f = unsafe { &mut *frame.frame };
        f.x = regs.x;
        f.sp_el0 = regs.sp;
        f.elr = user_pc(regs.pc);
        f.spsr = regs.pstate & USER_PSTATE;
    }

    unsafe fn resume_user(regs: &Registers, _kernel_stack_top: KernAddr) -> ! {
        let pc = user_pc(regs.pc);
        let pstate = regs.pstate & USER_PSTATE;
        // SAFETY: `eret` to EL0t, as in `enter_user`, with every general register loaded from
        // `regs`. `x30` holds the address of `regs` until it is loaded itself, last.
        unsafe {
            core::arch::asm!(
                "msr sp_el0, {sp}",
                "msr elr_el1, {pc}",
                "msr spsr_el1, {pstate}",
                "ldp x0, x1, [x30, #0]",
                "ldp x2, x3, [x30, #16]",
                "ldp x4, x5, [x30, #32]",
                "ldp x6, x7, [x30, #48]",
                "ldp x8, x9, [x30, #64]",
                "ldp x10, x11, [x30, #80]",
                "ldp x12, x13, [x30, #96]",
                "ldp x14, x15, [x30, #112]",
                "ldp x16, x17, [x30, #128]",
                "ldp x18, x19, [x30, #144]",
                "ldp x20, x21, [x30, #160]",
                "ldp x22, x23, [x30, #176]",
                "ldp x24, x25, [x30, #192]",
                "ldp x26, x27, [x30, #208]",
                "ldp x28, x29, [x30, #224]",
                "ldr x30, [x30, #240]",
                "isb",
                "eret",
                sp = in(reg) regs.sp,
                pc = in(reg) pc,
                pstate = in(reg) pstate,
                in("x30") core::ptr::from_ref(regs),
                options(noreturn, nostack),
            )
        }
    }

    unsafe fn enter_user(
        entry: usize,
        stack: usize,
        args: [usize; 4],
        _kernel_stack_top: KernAddr,
    ) -> ! {
        // SAFETY: `eret` to EL0t. `SPSR_EL1 = 0` selects EL0t with DAIF clear, so the
        // process runs with interrupts enabled; `SP_EL0` and `ELR_EL1` are the process's
        // mapped user stack and entry. Every register not carrying an argument is cleared.
        unsafe {
            core::arch::asm!(
                "msr sp_el0, {stack}",
                "msr elr_el1, {entry}",
                "msr spsr_el1, xzr",
                "mov x0, {a0}",
                "mov x1, {a1}",
                "mov x2, {a2}",
                "mov x3, {a3}",
                "mov x4, xzr",
                "mov x5, xzr",
                "mov x6, xzr",
                "mov x7, xzr",
                "mov x8, xzr",
                "mov x29, xzr",
                "mov x30, xzr",
                "isb",
                "eret",
                stack = in(reg) stack as u64,
                entry = in(reg) entry as u64,
                a0 = in(reg) args[0] as u64,
                a1 = in(reg) args[1] as u64,
                a2 = in(reg) args[2] as u64,
                a3 = in(reg) args[3] as u64,
                options(noreturn, nostack),
            )
        }
    }

    unsafe fn copy_from_user(dst: &mut [u8], src: UserAddr) -> Result<(), CopyFault> {
        prepare(src.raw(), dst.len(), false)?;
        // SAFETY: `prepare` proved every page present and user-readable; the process space
        // is loaded.
        unsafe {
            core::ptr::copy_nonoverlapping(src.raw() as *const u8, dst.as_mut_ptr(), dst.len())
        };
        Ok(())
    }

    unsafe fn copy_to_user(dst: UserAddr, src: &[u8]) -> Result<(), CopyFault> {
        prepare(dst.raw(), src.len(), true)?;
        // SAFETY: `prepare` proved every page present and user-writable; the process space
        // is loaded.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst.raw() as *mut u8, src.len()) };
        Ok(())
    }
}

/// Prove `[addr, addr+len)` is user memory, present and (for a write) writable, faulting
/// each page in first. See the x86 port for why this replaces exception fixups.
fn prepare(addr: usize, len: usize, write: bool) -> Result<(), CopyFault> {
    if len == 0 {
        return Ok(());
    }
    if !hal::user::user_range::<Aarch64>(addr, len) {
        return Err(CopyFault);
    }
    let page = <Aarch64 as Arch>::PAGE_SIZE;
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

fn page_ready(va: usize, write: bool) -> bool {
    match paging::user_leaf_flags(va) {
        Some(f) => {
            f.contains(hal::PageFlags::USER) && (!write || f.contains(hal::PageFlags::WRITE))
        }
        None => false,
    }
}
