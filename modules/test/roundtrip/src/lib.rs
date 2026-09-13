//! A module that exercises everything the loader does, so the boot check can see it work.
//!
//! On init it writes a line through the kernel, then registers a callback, which pins it.
//! The callback keeps a running total in `.data` and folds in a table from `.rodata`, so a
//! call that returns the right value has gone through relocated text, relocated read-only
//! data and writable data, all at their loaded addresses. On exit it checks the callback
//! was unregistered first, and says so.

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

use module::abi::imports::{kt_log, kt_register_callback};

/// Starts non-zero so it lands in `.data`, not `.bss`: both regions get exercised.
static TOTAL: AtomicU64 = AtomicU64::new(40);
static CALLS: AtomicU64 = AtomicU64::new(0);
static WEIGHTS: [u64; 4] = [1, 10, 100, 1000];

fn log(s: &str) {
    // SAFETY: `kt_log` reads `len` bytes from `ptr`, which `s` provides.
    unsafe { kt_log(s.as_ptr(), s.len()) }
}

/// `TOTAL += x * WEIGHTS[calls % 4]`, returning the new total.
extern "C" fn callback(x: u64) -> u64 {
    let n = CALLS.fetch_add(1, Ordering::Relaxed) as usize;
    let weight = WEIGHTS[n % WEIGHTS.len()];
    TOTAL.fetch_add(x * weight, Ordering::Relaxed) + x * weight
}

fn init(id: u32) -> i32 {
    log("test-roundtrip: init");
    // SAFETY: `callback` lives in this module's text, which the registration pins.
    unsafe { kt_register_callback(id, callback) }
}

fn exit(_id: u32) {
    log("test-roundtrip: exit");
}

module::module!(init = init, exit = exit);
