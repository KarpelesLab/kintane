//! Writing into memory the allocator owns: debug poison on free, zeroing on request.
//!
//! Two operations, in one file, because they are the same kind of write — a bulk
//! store into bytes `kalloc` owns and does not otherwise interpret — and keeping
//! them together means there is one place to look for "where does this unit write to
//! the heap".
//!
//! # Poisoning
//!
//! Freed memory is filled with [`FREED`] when [`ENABLED`] is set, which it is when
//! `DEBUG_BUILD` is on (that symbol's help text in `config/main.kcfg` already
//! promises "poisoned allocations"; this is that promise). The point is to turn
//! use-after-free from a silent read of plausible-looking stale data into something
//! that is obvious in a register dump, and to make a dangling pointer fault or
//! misbehave near the point of the bug rather than an hour later.
//!
//! [`FREED`] is `0xDE` repeated, so a word reads `0xDEDEDEDE`: recognisable at a
//! glance, not a valid small integer, not a plausible ASCII string, and — this is
//! the part that matters — a wildly misaligned and non-canonical address on every
//! target we build for, so dereferencing a poisoned pointer faults instead of
//! landing somewhere real.
//!
//! # Why a `const bool` and not a `cfg`
//!
//! `docs/coding-standards.md` forbids `cfg` inside a function body, and `kbuild
//! lint` enforces it. `kconfig::DEBUG_BUILD` is a `const bool`, so the branch below
//! is ordinary code the compiler type-checks in every configuration and then folds
//! away in the one where it is false. A `#[cfg]` would delete the text instead, and
//! the release build would stop compiling this file at all — which is how poisoning
//! code rots until the day someone turns it on.

// Re-enabled for the two `write_bytes` calls. There is no safe way to fill memory
// reached through a raw pointer; what makes it sound is the caller's contract,
// stated on each function, and the fact that both callers derive the pointer from a
// block they have just proved they own.
#![allow(unsafe_code)]

use core::ptr::NonNull;

/// The byte written over freed memory. `0xDEDEDEDE` as a word.
pub const FREED: u8 = 0xDE;

/// Whether poisoning happens in this build.
///
/// Public so that a test can assert the behaviour it is actually going to get rather
/// than the behaviour it hopes for, and so that a caller doing its own poisoning
/// (a collection clearing a buffer it is about to reuse) uses the same switch.
pub const ENABLED: bool = kconfig::DEBUG_BUILD;

/// Fill a freed block with [`FREED`], if this build poisons.
///
/// A no-op when [`ENABLED`] is false, and a no-op for a zero-length block.
///
/// # Safety
/// `ptr` must be valid for writes of `len` bytes, and the block must be dead: the
/// allocator must have already removed it from its live set, and no reference into
/// it may still be in use. Calling this on a block that is still owned by somebody
/// destroys their data — which is exactly why the `dealloc` functions that call it
/// are themselves `unsafe`.
pub unsafe fn fill_freed(ptr: NonNull<u8>, len: usize) {
    if !ENABLED || len == 0 {
        return;
    }
    // SAFETY: the caller guarantees `ptr` is valid for `len` bytes and that the
    // block is dead, so there is no live reference to alias and nothing to preserve.
    // `write_bytes` on `u8` has no alignment requirement beyond 1.
    unsafe { core::ptr::write_bytes(ptr.as_ptr(), FREED, len) };
}

/// Zero a block, for [`crate::AllocFlags::ZERO`].
///
/// Unconditional: this one is a caller's request, not a debug aid, so it happens in
/// every build.
///
/// # Safety
/// `ptr` must be valid for writes of `len` bytes and the block must not be aliased —
/// which holds at the moment of allocation, because the allocator has just carved it
/// out and has not yet returned it to anybody.
pub unsafe fn fill_zero(ptr: NonNull<u8>, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: as above; the caller has just taken exclusive ownership of the block.
    unsafe { core::ptr::write_bytes(ptr.as_ptr(), 0, len) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_poison_byte_is_a_hostile_pointer() {
        // The property that makes 0xDE worth choosing: a word of it is not a usable
        // address on any target we build for, so a poisoned pointer faults rather
        // than pointing somewhere plausible.
        let word = u64::from_ne_bytes([FREED; 8]);
        assert_ne!(word, 0);
        assert!(word % 8 != 0, "must not look like an aligned pointer");
        let half = u32::from_ne_bytes([FREED; 4]);
        assert!(half % 4 != 0, "and not on a 32-bit target either");
    }

    #[test]
    fn poisoning_follows_the_config_symbol_rather_than_a_cfg() {
        // Not an assertion about which build this is — an assertion that the switch
        // is the configuration symbol, so that turning DEBUG_BUILD off turns
        // poisoning off without deleting any of this file from the build.
        assert_eq!(ENABLED, kconfig::DEBUG_BUILD);
    }

    #[test]
    #[allow(unsafe_code)]
    fn filling_writes_what_it_says() {
        let mut buf = [0x11u8; 16];
        let ptr = match NonNull::new(buf.as_mut_ptr()) {
            Some(p) => p,
            None => panic!("a local array is never at address zero"),
        };
        // SAFETY: `buf` is a live local of 16 bytes, borrowed mutably here and
        // nowhere else for the duration of the call.
        unsafe { fill_zero(ptr, 16) };
        assert!(buf.iter().all(|b| *b == 0));

        // SAFETY: as above.
        unsafe { fill_freed(ptr, 16) };
        let want = if ENABLED { FREED } else { 0 };
        assert!(buf.iter().all(|b| *b == want), "poisoning must follow ENABLED exactly");
    }

    #[test]
    #[allow(unsafe_code)]
    fn a_zero_length_fill_touches_nothing() {
        let mut buf = [0x11u8; 4];
        let ptr = match NonNull::new(buf.as_mut_ptr()) {
            Some(p) => p,
            None => panic!("a local array is never at address zero"),
        };
        // SAFETY: length zero; nothing is written.
        unsafe { fill_freed(ptr, 0) };
        // SAFETY: as above.
        unsafe { fill_zero(ptr, 0) };
        assert_eq!(buf, [0x11u8; 4]);
    }
}
