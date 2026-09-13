//! The system call trap on x86_64: `syscall`.

use crate::Error;

/// Trap into the kernel with system call `nr`.
///
/// # Safety
/// Only meaningful from ring 3 of a KinTane process. `syscall` itself is always a valid
/// instruction to execute; what the kernel does with the arguments is its own business.
#[inline]
pub(crate) unsafe fn invoke(nr: u64, a: [u64; 6]) -> Result<u64, Error> {
    let status: u64;
    let value: u64;
    // SAFETY: the kernel's syscall entry preserves every register except the two return
    // registers and the two `syscall` itself overwrites (`rcx` with the return address,
    // `r11` with the flags), which is exactly what is declared clobbered here.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => status,
            in("rdi") a[0],
            in("rsi") a[1],
            inlateout("rdx") a[2] => value,
            in("r10") a[3],
            in("r8") a[4],
            in("r9") a[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    crate::decode(status, value)
}
