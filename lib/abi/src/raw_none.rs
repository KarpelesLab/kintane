//! No system call trap: this architecture has no userspace port.

use crate::Error;

/// Every call is `Unsupported`.
///
/// # Safety
/// None required; `unsafe` so the signature matches the ports that trap.
pub(crate) unsafe fn invoke(nr: u64, a: [u64; 6]) -> Result<u64, Error> {
    let _ = (nr, a);
    Err(Error::Unsupported)
}
