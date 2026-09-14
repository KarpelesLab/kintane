//! `fptest`: arithmetic on doubles, in a program built for the hard-float target.
//!
//! The point is not the arithmetic — it is that the instructions doing it exist. Every
//! other program here is built for the kernel's own target specification, which disables
//! floating point, so `a * b` becomes a call to `__muldf3` in `compiler_builtins` and no
//! floating-point register is ever named. This program is built for
//! `targets/<target>-hf.json` instead, where the same expression is `mulsd` on x86_64 and
//! `fmul` on aarch64. `kbuild`'s `fpregs` test disassembles the linked program and requires
//! such a register to be there, so a silent return to soft float fails the build rather
//! than quietly passing this program.
//!
//! Every value goes through [`core::hint::black_box`] before it is used. Without that the
//! constant folder computes the answers at compile time, the program ships with no
//! arithmetic in it at all, and both this program and the disassembly check would pass
//! while proving nothing.
//!
//! # One thread, deliberately
//!
//! Nothing saves floating-point registers across a context switch: `hal::HasFpu` is
//! unimplemented on every port, and `arch/aarch64/src/context.rs` asserts at compile time
//! that the kernel itself cannot name one. So two threads using these registers would
//! clobber each other with no diagnostic. This program uses them on the thread the kernel
//! starts it on and exits; it creates no second thread, and nothing built for this target
//! may until that trait exists. See docs/targets.md.

#![no_std]
#![no_main]

use abi::call;

/// Every step behaved.
const SUCCESS: u64 = 0x77;

/// Where the kernel enters. It passes a mode in the first argument register, as it does to
/// every native program; this one has a single mode and ignores it.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(_mode: usize, _a: usize, _b: usize, _c: usize) -> ! {
    exit(run())
}

fn exit(code: u64) -> ! {
    let _ = call::process_exit(code);
    // Unreachable unless the kernel returned from an exit, which the kernel's check sees
    // as a process that never ended.
    loop {
        let _ = call::thread_yield();
    }
}

/// Doubled through a call boundary, which is where the ABI itself carries a float: on
/// x86_64 the argument and the result travel in `xmm0`, not in a general register.
#[inline(never)]
fn twice(x: f64) -> f64 {
    core::hint::black_box(x) * 2.0
}

/// Every step, in order. Returns [`SUCCESS`], or the number of the first step that failed.
fn run() -> u64 {
    let a = core::hint::black_box(2.5f64);
    let b = core::hint::black_box(4.0f64);

    // 200: a multiply. 2.5 and 4.0 are exact in binary, and so is 10.0, so this is an
    // equality a correct implementation cannot miss by a rounding step.
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
