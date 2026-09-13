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
#![allow(internal_features)]

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
