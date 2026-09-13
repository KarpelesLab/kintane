//! The Arm run-time ABI's helpers: what LLVM calls on 32-bit Arm instead of `memcpy`,
//! `memset` and `__udivdi3`.
//!
//! The Arm EABI names its own memory and division helpers (IHI 0043, "Run-time ABI for
//! the Arm Architecture"), and LLVM emits calls to them for Arm targets, not to the C
//! names above. They differ in more than name: `__aeabi_memset` takes its fill byte
//! *last*, the `4` and `8` variants promise word-aligned pointers (which byte loops need
//! not use), none of them returns the destination, and `__aeabi_uldivmod` returns both
//! the quotient and the remainder in registers `r0`–`r3`, a shape no `extern "C"` Rust
//! function can return. That last one is therefore a few lines of assembly around the
//! same shift-and-subtract division the rest of this crate uses.
//!
//! Integer division by 32 bits needs nothing here: every ARMv7-M core has `UDIV` and
//! `SDIV`, and the target spec's CPU says so.

use core::ffi::c_void;

use crate::udivmod64;

// The helpers below do not call `memcpy`, `memmove` or `memset`. On Arm, LLVM lowers a
// call to those names into the `__aeabi_` forms — a `memset` with a zero byte becomes
// `__aeabi_memclr` — so `__aeabi_memclr` calling `memset` compiled into a call to itself,
// and the first zeroed array recursed until the stack ran out. Writing the loop out was
// not enough either: LLVM recognised the loop as a `memset` and emitted the same call.
// The crate's `#![no_builtins]` is what stops both.

/// Copy `n` bytes upward.
///
/// # Safety
/// As `memcpy`.
unsafe fn copy_up(dest: *mut c_void, src: *const c_void, n: usize) {
    let (dest, src) = (dest.cast::<u8>(), src.cast::<u8>());
    let mut i = 0;
    while i < n {
        // SAFETY: the caller guarantees both pointers are valid for `n` bytes.
        unsafe { *dest.add(i) = *src.add(i) };
        i += 1;
    }
}

/// Copy `n` bytes in whichever direction the overlap allows.
///
/// # Safety
/// As `memmove`.
unsafe fn copy_either(dest: *mut c_void, src: *const c_void, n: usize) {
    if (dest as usize) < (src as usize) {
        // SAFETY: ascending order is safe when dest precedes src.
        unsafe { copy_up(dest, src, n) };
        return;
    }
    let (dest, src) = (dest.cast::<u8>(), src.cast::<u8>());
    let mut i = n;
    while i > 0 {
        i -= 1;
        // SAFETY: descending order is safe when dest follows src.
        unsafe { *dest.add(i) = *src.add(i) };
    }
}

/// Fill `n` bytes.
///
/// # Safety
/// `dest` must be valid for `n` bytes.
unsafe fn fill(dest: *mut c_void, byte: u8, n: usize) {
    let dest = dest.cast::<u8>();
    let mut i = 0;
    while i < n {
        // SAFETY: the caller guarantees `dest` is valid for `n` bytes.
        unsafe { *dest.add(i) = byte };
        i += 1;
    }
}

/// # Safety
/// As `memcpy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memcpy(dest: *mut c_void, src: *const c_void, n: usize) {
    // SAFETY: the caller's contract is memcpy's.
    unsafe { copy_up(dest, src, n) };
}

/// # Safety
/// As `memcpy`, with both pointers word-aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memcpy4(dest: *mut c_void, src: *const c_void, n: usize) {
    // SAFETY: as above.
    unsafe { copy_up(dest, src, n) };
}

/// # Safety
/// As `memcpy`, with both pointers aligned to 8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memcpy8(dest: *mut c_void, src: *const c_void, n: usize) {
    // SAFETY: as above.
    unsafe { copy_up(dest, src, n) };
}

/// # Safety
/// As `memmove`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memmove(dest: *mut c_void, src: *const c_void, n: usize) {
    // SAFETY: the caller's contract is memmove's.
    unsafe { copy_either(dest, src, n) };
}

/// # Safety
/// As `memmove`, with both pointers word-aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memmove4(dest: *mut c_void, src: *const c_void, n: usize) {
    // SAFETY: as above.
    unsafe { copy_either(dest, src, n) };
}

/// # Safety
/// As `memmove`, with both pointers aligned to 8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memmove8(dest: *mut c_void, src: *const c_void, n: usize) {
    // SAFETY: as above.
    unsafe { copy_either(dest, src, n) };
}

/// Note the order: length, then fill byte.
///
/// # Safety
/// As `memset`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memset(dest: *mut c_void, n: usize, c: i32) {
    // SAFETY: the caller's contract is memset's.
    unsafe { fill(dest, c as u8, n) };
}

/// # Safety
/// As `memset`, with `dest` word-aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memset4(dest: *mut c_void, n: usize, c: i32) {
    // SAFETY: as above.
    unsafe { fill(dest, c as u8, n) };
}

/// # Safety
/// As `memset`, with `dest` aligned to 8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memset8(dest: *mut c_void, n: usize, c: i32) {
    // SAFETY: as above.
    unsafe { fill(dest, c as u8, n) };
}

/// # Safety
/// `dest` must be valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memclr(dest: *mut c_void, n: usize) {
    // SAFETY: the caller's contract is memset's with a zero byte.
    unsafe { fill(dest, 0, n) };
}

/// # Safety
/// As `__aeabi_memclr`, with `dest` word-aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memclr4(dest: *mut c_void, n: usize) {
    // SAFETY: as above.
    unsafe { fill(dest, 0, n) };
}

/// # Safety
/// As `__aeabi_memclr`, with `dest` aligned to 8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __aeabi_memclr8(dest: *mut c_void, n: usize) {
    // SAFETY: as above.
    unsafe { fill(dest, 0, n) };
}

// `__aeabi_uldivmod(n: u64, d: u64)` and `__aeabi_ldivmod(n: i64, d: i64)`: quotient in
// r0:r1 and remainder in r2:r3. The arguments arrive in r0:r1 and r2:r3 already, so each
// wrapper only adds the fifth argument, a pointer to room for the result, on the stack
// where AAPCS puts it, and loads the result back into the four registers.
core::arch::global_asm!(
    r#"
.syntax unified
.thumb

.section .text.aeabi_divmod, "ax"

.globl __aeabi_uldivmod
.type __aeabi_uldivmod, %function
.thumb_func
__aeabi_uldivmod:
    push    {{r4, lr}}
    sub     sp, sp, #24
    add     r4, sp, #8
    str     r4, [sp]
    bl      kintane_uldivmod_into
    ldr     r0, [sp, #8]
    ldr     r1, [sp, #12]
    ldr     r2, [sp, #16]
    ldr     r3, [sp, #20]
    add     sp, sp, #24
    pop     {{r4, pc}}

.globl __aeabi_ldivmod
.type __aeabi_ldivmod, %function
.thumb_func
__aeabi_ldivmod:
    push    {{r4, lr}}
    sub     sp, sp, #24
    add     r4, sp, #8
    str     r4, [sp]
    bl      kintane_ldivmod_into
    ldr     r0, [sp, #8]
    ldr     r1, [sp, #12]
    ldr     r2, [sp, #16]
    ldr     r3, [sp, #20]
    add     sp, sp, #24
    pop     {{r4, pc}}
"#
);

/// The unsigned half of `__aeabi_uldivmod`: quotient and remainder into `out`.
///
/// # Safety
/// `out` must be valid for writing two `u64`s.
#[unsafe(no_mangle)]
unsafe extern "C" fn kintane_uldivmod_into(n: u64, d: u64, out: *mut [u64; 2]) {
    let (q, r) = udivmod64(n, d);
    // SAFETY: the caller's contract; the wrapper points it at 16 bytes of its own frame.
    unsafe { *out = [q, r] };
}

/// The signed half of `__aeabi_ldivmod`, truncating toward zero like `__divdi3` and
/// `__moddi3`.
///
/// # Safety
/// As [`kintane_uldivmod_into`].
#[unsafe(no_mangle)]
unsafe extern "C" fn kintane_ldivmod_into(n: i64, d: i64, out: *mut [i64; 2]) {
    let (q, r) = udivmod64(n.unsigned_abs(), d.unsigned_abs());
    let q = if (n < 0) != (d < 0) {
        (q as i64).wrapping_neg()
    } else {
        q as i64
    };
    let r = if n < 0 {
        (r as i64).wrapping_neg()
    } else {
        r as i64
    };
    // SAFETY: as above.
    unsafe { *out = [q, r] };
}

// 64-bit shifts. At opt-level "z" LLVM calls these rather than open-coding a shift of a
// 64-bit value on a 32-bit core. **They must not shift a `u64` themselves**, or they call
// themselves, the trap `__udivdi3`'s comment in `lib.rs` describes for division; each is
// written on the two 32-bit halves.

/// `n << shift`, for `shift` in `0..64`.
#[unsafe(no_mangle)]
pub extern "C" fn __aeabi_llsl(n: u64, shift: i32) -> u64 {
    let (hi, lo) = ((n >> 32) as u32, n as u32);
    let s = (shift as u32) & 63;
    let (hi, lo) = if s == 0 {
        (hi, lo)
    } else if s < 32 {
        ((hi << s) | (lo >> (32 - s)), lo << s)
    } else {
        (lo << (s - 32), 0)
    };
    u64::from(lo) | (u64::from(hi) << 32u32)
}

/// Logical `n >> shift`, for `shift` in `0..64`.
#[unsafe(no_mangle)]
pub extern "C" fn __aeabi_llsr(n: u64, shift: i32) -> u64 {
    let (hi, lo) = ((n >> 32u32) as u32, n as u32);
    let s = (shift as u32) & 63;
    let (hi, lo) = if s == 0 {
        (hi, lo)
    } else if s < 32 {
        (hi >> s, (lo >> s) | (hi << (32 - s)))
    } else {
        (0, hi >> (s - 32))
    };
    u64::from(lo) | (u64::from(hi) << 32u32)
}

/// Arithmetic `n >> shift`, for `shift` in `0..64`.
#[unsafe(no_mangle)]
pub extern "C" fn __aeabi_lasr(n: i64, shift: i32) -> i64 {
    let (hi, lo) = (((n as u64) >> 32u32) as u32 as i32, n as u32);
    let s = (shift as u32) & 63;
    let (hi, lo) = if s == 0 {
        (hi, lo)
    } else if s < 32 {
        (hi >> s, (lo >> s) | ((hi as u32) << (32 - s)))
    } else {
        (hi >> 31, (hi >> (s - 32)) as u32)
    };
    (u64::from(lo) | (u64::from(hi as u32) << 32u32)) as i64
}
