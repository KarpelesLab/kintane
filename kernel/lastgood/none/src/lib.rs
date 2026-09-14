//! `lastgood` for images no counting loader starts.
//!
//! One of the units providing this name, alongside `kernel/lastgood/uefi`; see there for
//! what confirming a boot means. No loader counted this boot, so `kmain` asks the same
//! question on every port and the answer here is the verdict it already had.

#![no_std]

use hal::EarlyConsole;

/// Nothing to confirm to. The verdict stands as it is, and nothing is printed: there is no
/// counter to report on.
pub fn settle(_c: &dyn EarlyConsole, _boot_arg: u64, verdict: bool) -> bool {
    verdict
}
