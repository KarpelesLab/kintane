//! The system call trap on aarch64: `svc #0`.

use crate::Error;

/// Trap into the kernel with system call `nr`.
///
/// # Safety
/// Only meaningful from EL0 of a KinTane process. `svc` is always a valid instruction to
/// execute; what the kernel does with the arguments is its own business.
#[inline]
pub(crate) unsafe fn invoke(nr: u64, a: [u64; 6]) -> Result<u64, Error> {
    let status: u64;
    let value: u64;
    // SAFETY: the kernel's lower-EL synchronous entry saves every general register and
    // restores all of them except the two return registers.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a[0] => status,
            inlateout("x1") a[1] => value,
            in("x2") a[2],
            in("x3") a[3],
            in("x4") a[4],
            in("x5") a[5],
            options(nostack),
        );
    }
    crate::decode(status, value)
}
