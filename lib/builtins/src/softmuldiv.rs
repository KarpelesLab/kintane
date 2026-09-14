//! Multiply and divide for a core that has neither instruction.
//!
//! rv32imac has the M extension, so LLVM emits `mul`, `div` and `rem` and nothing here
//! is ever called. **rv32i is the base ISA and has none of them**: every `*`, `/` and `%`
//! on an integer — including the ones `core` uses inside `write_usize`, a slab's size
//! classes or a frame count — becomes a call into the runtime library, by the same
//! libgcc names every toolchain uses. The first rv32i link failed on `__muldi3`, from a
//! `u64` multiply inside the kernel heap's own statistics.
//!
//! This is the same class of debt `aeabi.rs` records for 32-bit Arm, and it belongs to
//! the ISA rather than to the port: a Cortex-M0 or an MSP430 would want exactly these.
//! The module is compiled for `riscv32` because that is where it is needed today; on
//! rv32imac the linker discards every one of them.
//!
//! **None of these may use the operator it implements**, or it calls itself: the trap
//! `__udivdi3` in `lib.rs` describes for 64-bit division, one width down. Multiplication
//! is shift-and-add, division is shift-and-subtract, and both use only operations rv32i
//! has: shifts by a register, comparison, and add with carry recovered from
//! `overflowing_add`.

/// `a * b` as a 64-bit product in `(high, low)` halves.
///
/// Shift-and-add over the set bits of `b`. `a << i` and `a >> (32 - i)` are single
/// instructions on rv32i; the `i == 0` arm exists because shifting a `u32` by 32 is not a
/// shift at all in Rust, it is a panic in debug and nonsense in release.
fn mul_wide(a: u32, b: u32) -> (u32, u32) {
    let (mut hi, mut lo) = (0u32, 0u32);
    let mut i = 0u32;
    while i < 32 {
        if (b >> i) & 1 == 1 {
            let part_lo = a << i;
            let part_hi = if i == 0 { 0 } else { a >> (32 - i) };
            let (sum, carry) = lo.overflowing_add(part_lo);
            lo = sum;
            hi = hi.wrapping_add(part_hi).wrapping_add(carry as u32);
        }
        i += 1;
    }
    (hi, lo)
}

/// Wrapping 32-bit multiply. Signed and unsigned multiplication agree in the low word,
/// which is why one symbol serves `i32` and `u32` alike.
#[unsafe(no_mangle)]
pub extern "C" fn __mulsi3(a: u32, b: u32) -> u32 {
    mul_wide(a, b).1
}

/// Wrapping 64-bit multiply, from four 32-bit partial products.
///
/// Only the low 64 bits are kept, so the two cross terms need just their low words and
/// the high halves' product does not contribute at all. The `<< 32` is a constant shift,
/// which LLVM splits across the register pair rather than calling a shift helper.
#[unsafe(no_mangle)]
pub extern "C" fn __muldi3(a: u64, b: u64) -> u64 {
    let (ah, al) = ((a >> 32) as u32, a as u32);
    let (bh, bl) = ((b >> 32) as u32, b as u32);
    let (hi, lo) = mul_wide(al, bl);
    let hi = hi
        .wrapping_add(mul_wide(al, bh).1)
        .wrapping_add(mul_wide(ah, bl).1);
    u64::from(lo) | (u64::from(hi) << 32)
}

/// Unsigned 32-bit divide-with-remainder by shift and subtract.
///
/// Division by zero returns zeros for the reason `udivmod64` gives: Rust checks before
/// it calls, C leaves it undefined, and the kernel does not allow a panic here.
fn udivmod32(n: u32, d: u32) -> (u32, u32) {
    if d == 0 {
        return (0, 0);
    }
    let (mut q, mut r) = (0u32, 0u32);
    let mut i = 32u32;
    while i > 0 {
        i -= 1;
        r = (r << 1) | ((n >> i) & 1);
        if r >= d {
            r -= d;
            q |= 1u32 << i;
        }
    }
    (q, r)
}

#[unsafe(no_mangle)]
pub extern "C" fn __udivsi3(n: u32, d: u32) -> u32 {
    udivmod32(n, d).0
}

#[unsafe(no_mangle)]
pub extern "C" fn __umodsi3(n: u32, d: u32) -> u32 {
    udivmod32(n, d).1
}

/// Truncating toward zero, like Rust's `/`: divide the magnitudes and negate if exactly
/// one operand was negative. `unsigned_abs` handles `i32::MIN`, whose magnitude does not
/// fit in an `i32`.
#[unsafe(no_mangle)]
pub extern "C" fn __divsi3(a: i32, b: i32) -> i32 {
    let (q, _) = udivmod32(a.unsigned_abs(), b.unsigned_abs());
    if (a < 0) != (b < 0) {
        (q as i32).wrapping_neg()
    } else {
        q as i32
    }
}

/// The remainder takes the sign of the dividend, matching Rust's `%`.
#[unsafe(no_mangle)]
pub extern "C" fn __modsi3(a: i32, b: i32) -> i32 {
    let (_, r) = udivmod32(a.unsigned_abs(), b.unsigned_abs());
    if a < 0 {
        (r as i32).wrapping_neg()
    } else {
        r as i32
    }
}

// 64-bit shifts by a variable amount, which a 32-bit core has no instruction for either.
// Written on the two halves, never by shifting the `u64` itself, for the same reason as
// everything above. These are the generic names; `aeabi.rs` has Arm's spelling of the
// same three.

/// `n << shift`, for `shift` in `0..64`.
#[unsafe(no_mangle)]
pub extern "C" fn __ashldi3(n: u64, shift: u32) -> u64 {
    let (hi, lo) = ((n >> 32) as u32, n as u32);
    let s = shift & 63;
    let (hi, lo) = if s == 0 {
        (hi, lo)
    } else if s < 32 {
        ((hi << s) | (lo >> (32 - s)), lo << s)
    } else {
        (lo << (s - 32), 0)
    };
    u64::from(lo) | (u64::from(hi) << 32)
}

/// Logical `n >> shift`, for `shift` in `0..64`.
#[unsafe(no_mangle)]
pub extern "C" fn __lshrdi3(n: u64, shift: u32) -> u64 {
    let (hi, lo) = ((n >> 32) as u32, n as u32);
    let s = shift & 63;
    let (hi, lo) = if s == 0 {
        (hi, lo)
    } else if s < 32 {
        (hi >> s, (lo >> s) | (hi << (32 - s)))
    } else {
        (0, hi >> (s - 32))
    };
    u64::from(lo) | (u64::from(hi) << 32)
}

/// Arithmetic `n >> shift`, for `shift` in `0..64`: the sign bit is replicated.
#[unsafe(no_mangle)]
pub extern "C" fn __ashrdi3(n: i64, shift: u32) -> i64 {
    let (hi, lo) = (((n as u64) >> 32) as u32 as i32, n as u32);
    let s = shift & 63;
    let (hi, lo) = if s == 0 {
        (hi, lo)
    } else if s < 32 {
        (hi >> s, (lo >> s) | ((hi as u32) << (32 - s)))
    } else {
        (hi >> 31, (hi >> (s - 32)) as u32)
    };
    (u64::from(lo) | (u64::from(hi as u32) << 32)) as i64
}
