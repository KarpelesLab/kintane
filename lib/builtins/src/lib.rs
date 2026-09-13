//! Compiler intrinsics.
//!
//! rustc requires a crate named `compiler_builtins` when linking a `no_std` binary:
//! it is where calls the code generator emits — `memcpy` for a struct move, `memset`
//! for a zeroed array — are expected to resolve.
//!
//! We provide our own rather than building the upstream crate, for two reasons. It
//! has a `build.rs` we cannot run without cargo, and D8 keeps third-party code out of
//! the kernel. The cost is that this file must grow as the kernel starts using
//! operations LLVM lowers to intrinsic calls — 128-bit division and software float
//! being the usual ones. Each addition is a deliberate, reviewed piece of work rather
//! than a dependency bump.
//!
//! These are the classic byte-at-a-time definitions. They are correct and slow;
//! replacing them with word-at-a-time versions is a Phase 1 task, and one that wants
//! a benchmark rather than an assumption.

#![no_std]
#![feature(compiler_builtins)]
#![compiler_builtins]
#![feature(rustc_attrs)]
#![allow(internal_features)]

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
mod probestack;
#[cfg(target_os = "uefi")]
mod uefi_link;

use core::ffi::c_void;

/// # Safety
/// `dest` and `src` must be valid for `n` bytes and must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let (dest, src) = (dest.cast::<u8>(), src.cast::<u8>());
    let mut i = 0;
    while i < n {
        // SAFETY: the caller guarantees both pointers are valid for `n` bytes, and
        // `i` is strictly less than `n` on every iteration.
        unsafe { *dest.add(i) = *src.add(i) };
        i += 1;
    }
    dest.cast()
}

/// # Safety
/// `dest` and `src` must be valid for `n` bytes. They may overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let (dest, src) = (dest.cast::<u8>(), src.cast::<u8>());
    // Copy in whichever direction does not clobber source bytes still to be read.
    if (dest as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            // SAFETY: as for memcpy; ascending order is safe when dest precedes src.
            unsafe { *dest.add(i) = *src.add(i) };
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            // SAFETY: descending order is safe when dest follows src.
            unsafe { *dest.add(i) = *src.add(i) };
        }
    }
    dest.cast()
}

/// # Safety
/// `dest` must be valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let dest = dest.cast::<u8>();
    let byte = c as u8;
    let mut i = 0;
    while i < n {
        // SAFETY: the caller guarantees `dest` is valid for `n` bytes.
        unsafe { *dest.add(i) = byte };
        i += 1;
    }
    dest.cast()
}

/// # Safety
/// Both pointers must be valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    let (a, b) = (a.cast::<u8>(), b.cast::<u8>());
    let mut i = 0;
    while i < n {
        // SAFETY: the caller guarantees both pointers are valid for `n` bytes.
        let (x, y) = unsafe { (*a.add(i), *b.add(i)) };
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

/// # Safety
/// Both pointers must be valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    // SAFETY: same contract as memcmp, which this delegates to.
    unsafe { memcmp(a, b, n) }
}

// ---- 64-bit division on 32-bit targets ---------------------------------------------
//
// A `u64 / u64` or `u64 % u64` on a 32-bit target is not an instruction; LLVM lowers it
// to a call into the runtime library. The header of this file warned that it would have
// to grow for exactly this, and then it did not — until the shared page-table walker
// computed `phys % size` with a size that varies per level, which cannot be folded into
// a shift, and i686 stopped linking with `undefined symbol: __umoddi3`.
//
// The masks that replaced that division fixed the instance. These fix the class: the
// next 64-bit division anywhere in the kernel should cost a few nanoseconds on i686, not
// a broken link on one architecture discovered after the fact.
//
// On 64-bit targets nothing references these and the linker discards them.
//
// **These must not use `/` or `%` on 64-bit operands**, or they call themselves. Binary
// long division uses only shifts, comparison and subtraction — and on x86, variable
// 64-bit shifts are SHLD/SHRD instructions rather than library calls, so this does not
// merely move the problem.

/// Unsigned 64-bit divide-with-remainder by shift and subtract.
///
/// Division by zero is unreachable from Rust, which checks before calling the
/// intrinsic, and undefined in C. Returning zeros rather than looping or faulting keeps
/// this free of panics, which the kernel does not allow.
fn udivmod64(n: u64, d: u64) -> (u64, u64) {
    if d == 0 {
        return (0, 0);
    }
    // Fast path: both fit in 32 bits, which is the common case and a native division.
    if n >> 32 == 0 && d >> 32 == 0 {
        let (n32, d32) = (n as u32, d as u32);
        return ((n32 / d32) as u64, (n32 % d32) as u64);
    }
    let mut q = 0u64;
    let mut r = 0u64;
    let mut i = 64u32;
    while i > 0 {
        i -= 1;
        r = (r << 1) | ((n >> i) & 1);
        if r >= d {
            r -= d;
            q |= 1u64 << i;
        }
    }
    (q, r)
}

#[unsafe(no_mangle)]
pub extern "C" fn __udivdi3(n: u64, d: u64) -> u64 {
    udivmod64(n, d).0
}

#[unsafe(no_mangle)]
pub extern "C" fn __umoddi3(n: u64, d: u64) -> u64 {
    udivmod64(n, d).1
}

#[unsafe(no_mangle)]
pub extern "C" fn __divdi3(a: i64, b: i64) -> i64 {
    // Truncating toward zero: divide the magnitudes, negate if exactly one operand was
    // negative. `unsigned_abs` handles i64::MIN, whose magnitude does not fit in i64.
    let (q, _) = udivmod64(a.unsigned_abs(), b.unsigned_abs());
    if (a < 0) != (b < 0) {
        (q as i64).wrapping_neg()
    } else {
        q as i64
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __moddi3(a: i64, b: i64) -> i64 {
    // The remainder takes the sign of the dividend, matching Rust's `%`.
    let (_, r) = udivmod64(a.unsigned_abs(), b.unsigned_abs());
    if a < 0 {
        (r as i64).wrapping_neg()
    } else {
        r as i64
    }
}
