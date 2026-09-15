//! `fptest`: arithmetic on doubles, and vector registers held across a context switch, in a
//! program built for the hard-float target.
//!
//! Two things are proved here, and they are different.
//!
//! **That the instructions exist at all.** Every other program is built for the kernel's own
//! specification, which disables floating point, so `a * b` becomes a call to `__muldf3` and
//! no floating-point register is ever named. This program is built for
//! `targets/<arch>-kintane-hf.json`, where the same expression is `mulsd` on x86_64 and `fmul`
//! on aarch64; `kbuild`'s `fpregs` test disassembles the linked program and requires such an
//! instruction to be there. That much predates `hal::HasFpu`.
//!
//! **That the kernel keeps them.** [`pattern`] loads eight vector registers with values no
//! other thread uses, yields — which is a context switch, and with another CPU a genuine
//! concurrent one — and reads them back. The kernel runs a second thread of this program
//! beside it in [`MODE_NOISE`], holding a different pattern in the same registers for as long
//! as it is left alive. Without `hal::HasFpu` neither thread's registers survive the other's
//! turn.
//!
//! # Why one assembly block, and not Rust
//!
//! The obvious version — set eight `f64` locals, call `thread_yield`, compare — proves
//! nothing. Nothing obliges the compiler to keep those values in vector registers across a
//! call; it may spill them to the stack and reload them afterwards, and then the check passes
//! whether or not the kernel saved a single register. The load, the system call and the
//! read-back are therefore one `asm!` block, where the registers are named and the trap sits
//! between the write and the read. The call is issued directly rather than through `abi` for
//! the same reason: a Rust call between the load and the read is a licence to spill.
//!
//! # One process, two threads
//!
//! The kernel starts both threads (`kernel/main/src/fpu.rs`). This program creates none: a
//! thread needs a handle to a process, and this one is given none. Only the graded thread
//! exits — a process carries one exit code, so the noise thread must not race it for that
//! code, and it is reaped when the process is torn down.

#![no_std]
#![no_main]

use abi::call;

/// Every arithmetic step behaved.
const SUCCESS: u64 = 0x77;
/// Every register came back holding what this thread put in it.
const PATTERN_SUCCESS: u64 = 0x78;
/// The first of eight codes naming a register that came back wrong: `LOST + n`.
const LOST: u64 = 210;

/// Modes, chosen by the kernel's check.
const MODE_ARITH: usize = 0;
const MODE_PATTERN: usize = 1;
const MODE_NOISE: usize = 2;

/// Vector registers the pattern uses, and 64-bit words in each.
const REGS: usize = 8;
const LANES: usize = 2;

/// Yields the graded thread makes between writing the registers and reading them back. More
/// than one, so it must survive every round trip rather than a single lucky one.
const ROUNDS: u64 = 64;

/// Sixteen-byte aligned, because the vector loads and stores below require it.
#[repr(C, align(16))]
struct Vectors([u64; REGS * LANES]);

/// Where the kernel enters. `mode` picks what to do; `a` seeds the pattern.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(mode: usize, a: usize, _b: usize, _c: usize) -> ! {
    let code = match mode {
        MODE_ARITH => run(),
        MODE_PATTERN => pattern(a as u64, ROUNDS),
        // Never finishes its yields, so it never reaches an exit of its own: the kernel ends
        // it by tearing the process down once the graded thread has exited. A code here at
        // all means the loop ended, which it cannot.
        MODE_NOISE => pattern(a as u64, u64::MAX).wrapping_add(0x1000),
        _ => 0xbad0,
    };
    exit(code)
}

fn exit(code: u64) -> ! {
    let _ = call::process_exit(code);
    // Unreachable unless the kernel returned from an exit, which its check sees as a process
    // that never ended.
    loop {
        let _ = call::thread_yield();
    }
}

/// Fill eight vector registers with values derived from `seed`, yield `rounds` times, and
/// require every register to still hold what it was given.
///
/// Returns [`PATTERN_SUCCESS`], or `LOST + n` naming the first register that came back wrong.
fn pattern(seed: u64, rounds: u64) -> u64 {
    let mut want = Vectors([0; REGS * LANES]);
    for (i, slot) in want.0.iter_mut().enumerate() {
        // Distinct per register, per lane, and per thread: a register restored from a
        // neighbour's slot, or from the other thread's, differs in every byte that matters.
        *slot = 0x5eed_0000_0000_0000 ^ (seed << 40) ^ ((i as u64) << 8) ^ (i as u64);
    }
    let mut got = Vectors([0; REGS * LANES]);

    // SAFETY: both buffers are 16-aligned and `REGS * LANES` words long, which is exactly
    // what the eight vector transfers read and write.
    unsafe { hold_across_yield(&want, &mut got, rounds) };

    for i in 0..REGS {
        if got.0[i * LANES] != want.0[i * LANES] || got.0[i * LANES + 1] != want.0[i * LANES + 1] {
            return LOST + i as u64;
        }
    }
    PATTERN_SUCCESS
}

/// Load `want` into xmm0-xmm7, yield `rounds` times without touching them, then store them to
/// `got`.
///
/// The moves are `movaps`, which require their operand to be 16-byte aligned, and that is
/// deliberate: they are a second guard on the stack a thread is entered with. The first time
/// this ran, every one of these threads died of `#GP` — not here, but on a `movaps` the
/// compiler emitted by itself to zero `Vectors`, because a thread started on a 16-byte aligned
/// stack pointer while `_start`, an `extern "C"` function, is compiled expecting the eight-byte
/// gap a call would have left. `HasUserMode::ENTRY_SP_BIAS` leaves it now. Unaligned moves
/// here would have hidden nothing — the compiler's own aligned stores fault first — so there
/// is no reason to weaken these. See docs/userspace-abi.md.
///
/// # Safety
/// `want` and `got` must be 16-byte aligned and hold `REGS * LANES` words.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn hold_across_yield(want: &Vectors, got: &mut Vectors, rounds: u64) {
    // SAFETY: the caller's contract. `rax`, `rcx`, `r11` and `rdx` are declared clobbered —
    // `syscall` overwrites `rcx` and `r11`, and the kernel returns in `rax` and `rdx` — so the
    // register allocator keeps the operands out of them. Every other general register the
    // kernel preserves across the trap, which is what lets the counter live in one.
    unsafe {
        core::arch::asm!(
            "movaps xmm0, xmmword ptr [{want} + 0x00]",
            "movaps xmm1, xmmword ptr [{want} + 0x10]",
            "movaps xmm2, xmmword ptr [{want} + 0x20]",
            "movaps xmm3, xmmword ptr [{want} + 0x30]",
            "movaps xmm4, xmmword ptr [{want} + 0x40]",
            "movaps xmm5, xmmword ptr [{want} + 0x50]",
            "movaps xmm6, xmmword ptr [{want} + 0x60]",
            "movaps xmm7, xmmword ptr [{want} + 0x70]",
            "2:",
            "mov rax, 2",
            "syscall",
            "dec {n}",
            "jnz 2b",
            "movaps xmmword ptr [{got} + 0x00], xmm0",
            "movaps xmmword ptr [{got} + 0x10], xmm1",
            "movaps xmmword ptr [{got} + 0x20], xmm2",
            "movaps xmmword ptr [{got} + 0x30], xmm3",
            "movaps xmmword ptr [{got} + 0x40], xmm4",
            "movaps xmmword ptr [{got} + 0x50], xmm5",
            "movaps xmmword ptr [{got} + 0x60], xmm6",
            "movaps xmmword ptr [{got} + 0x70], xmm7",
            want = in(reg) want.0.as_ptr(),
            got = in(reg) got.0.as_mut_ptr(),
            n = inout(reg) rounds => _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r11") _,
            options(nostack),
        );
    }
}

/// As the x86_64 version, with `svc` and the q registers.
///
/// # Safety
/// `want` and `got` must be 16-byte aligned and hold `REGS * LANES` words.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe fn hold_across_yield(want: &Vectors, got: &mut Vectors, rounds: u64) {
    // SAFETY: the caller's contract. `x8` carries the call number and `x0`/`x1` are the
    // kernel's return registers, so all three are declared clobbered; every other general
    // register is restored across `svc`, which is what lets the counter live in one.
    unsafe {
        core::arch::asm!(
            "ldp q0, q1, [{want}, #0x00]",
            "ldp q2, q3, [{want}, #0x20]",
            "ldp q4, q5, [{want}, #0x40]",
            "ldp q6, q7, [{want}, #0x60]",
            "2:",
            "mov x8, #2",
            "svc #0",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            "stp q0, q1, [{got}, #0x00]",
            "stp q2, q3, [{got}, #0x20]",
            "stp q4, q5, [{got}, #0x40]",
            "stp q6, q7, [{got}, #0x60]",
            want = in(reg) want.0.as_ptr(),
            got = in(reg) got.0.as_mut_ptr(),
            n = inout(reg) rounds => _,
            out("x0") _,
            out("x1") _,
            out("x8") _,
            options(nostack),
        );
    }
}

/// Doubled through a call boundary, which is where the ABI itself carries a float: on x86_64
/// the argument and the result travel in `xmm0`, not in a general register.
#[inline(never)]
fn twice(x: f64) -> f64 {
    core::hint::black_box(x) * 2.0
}

/// Every arithmetic step, in order. Returns [`SUCCESS`], or the number of the first step that
/// failed.
///
/// Every value goes through [`core::hint::black_box`] first. Without that the constant folder
/// computes the answers at compile time, the program ships with no arithmetic in it, and both
/// this program and the disassembly check pass while proving nothing.
fn run() -> u64 {
    let a = core::hint::black_box(2.5f64);
    let b = core::hint::black_box(4.0f64);

    // 200: a multiply. 2.5 and 4.0 are exact in binary, and so is 10.0, so this is an equality
    // a correct implementation cannot miss by a rounding step.
    let product = core::hint::black_box(a * b);
    if product != 10.0 {
        return 200;
    }
    // 201: an add on that result.
    let sum = core::hint::black_box(product + 0.5);
    if sum != 10.5 {
        return 201;
    }
    // 202: a divide, still exact: 10.5 / 2 is representable.
    if core::hint::black_box(sum / 2.0) != 5.25 {
        return 202;
    }
    // 203: a subtract that reaches zero, so a sign error shows.
    if core::hint::black_box(sum - 10.5) != 0.0 {
        return 203;
    }
    // 204: the ABI's own floating-point path, across a call the optimiser may not inline.
    if twice(sum) != 21.0 {
        return 204;
    }
    // 205: single precision, a different register width on both ports.
    let s = core::hint::black_box(1.5f32);
    if core::hint::black_box(s * 3.0) != 4.5 {
        return 205;
    }
    // 206: conversion both ways, which is its own instruction rather than arithmetic.
    let n = core::hint::black_box(7i32);
    let f = core::hint::black_box(f64::from(n) / 2.0);
    if f != 3.5 || core::hint::black_box(f as i32) != 3 {
        return 206;
    }
    SUCCESS
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(0xdead)
}
