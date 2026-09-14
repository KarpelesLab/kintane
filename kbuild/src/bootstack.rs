//! The boot stack a kernel image reserves is the one its configuration asks for.
//!
//! `BOOT_STACK_KIB` sizes the stack the first thread of execution runs on, and each port's
//! linker script reserves it. Until the eighth round only ARMv7-M did: x86_64, aarch64, i686
//! and riscv32 reserved a fixed 16 KiB in their boot assembly, so a configuration that asked
//! for 32 KiB built, booted, and overflowed a stack of the old size. Each script now asserts
//! its own reservation, but a script that forgot the option would forget the assertion too.
//! So kbuild checks every linked kernel from the outside, from the symbols every port
//! defines: `__stack_bottom` and `__stack_top` must be `BOOT_STACK_KIB` apart, rounded up to
//! at most one page.
//!
//! The default configuration cannot catch a port that hard-codes the default size; a build
//! with another size can, which is why CI builds every preset with one.

use std::path::Path;
use std::process::Command;

/// The largest page any port rounds its boot stack up to.
const PAGE: u64 = 4096;

/// Check `nm`'s listing of a linked kernel against a configured size of `kib` KiB.
pub fn check_listing(listing: &str, kib: i64) -> Result<u64, String> {
    let find = |name: &str| {
        listing.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            let addr = fields.next()?;
            let _kind = fields.next()?;
            (fields.next()? == name)
                .then(|| u64::from_str_radix(addr, 16).ok())
                .flatten()
        })
    };
    let (Some(bottom), Some(top)) = (find("__stack_bottom"), find("__stack_top")) else {
        return Err(
            "the kernel image defines no __stack_bottom and __stack_top, so its boot stack \
             cannot be checked against BOOT_STACK_KIB"
                .into(),
        );
    };
    let wanted = u64::try_from(kib).map_err(|_| format!("BOOT_STACK_KIB is {kib}"))? * 1024;
    let reserved = top.saturating_sub(bottom);
    if reserved < wanted || reserved >= wanted + PAGE {
        return Err(format!(
            "the kernel image reserves a {reserved}-byte boot stack \
             ({bottom:#x}..{top:#x}), but BOOT_STACK_KIB asks for {wanted} bytes: its port \
             does not size the boot stack from the configuration"
        ));
    }
    Ok(reserved)
}

/// Run `nm` on `linked` and check its boot stack. See the module documentation.
pub fn verify(nm: &Path, linked: &Path, kib: i64) -> Result<u64, String> {
    let out = Command::new(nm)
        .arg("--defined-only")
        .arg(linked)
        .output()
        .map_err(|e| format!("cannot run llvm-nm: {e}"))?;
    if !out.status.success() {
        return Err(format!("llvm-nm failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    check_listing(&String::from_utf8_lossy(&out.stdout), kib)
}

#[cfg(test)]
mod tests {
    use super::check_listing;

    fn listing(bottom: u64, top: u64) -> String {
        format!(
            "{bottom:016x} B __stack_bottom\n{top:016x} B __stack_top\n0000000000100000 T _start\n"
        )
    }

    #[test]
    fn a_stack_of_the_configured_size_passes() {
        assert_eq!(check_listing(&listing(0x1000, 0x9000), 32), Ok(0x8000));
        // ARMv7-M reserves exactly what it is asked for, a page-less 1 KiB granularity.
        assert_eq!(check_listing(&listing(0x2000_0000, 0x2000_0400), 1), Ok(0x400));
    }

    #[test]
    fn a_size_rounded_up_to_a_page_passes() {
        assert_eq!(check_listing(&listing(0x1000, 0x4000), 10), Ok(0x3000));
    }

    #[test]
    fn a_port_that_ignores_the_configuration_fails() {
        // The fixed 16 KiB every port but ARMv7-M used to reserve, asked for 32 or 8.
        let fixed = listing(0x1000, 0x5000);
        assert!(
            check_listing(&fixed, 32)
                .unwrap_err()
                .contains("does not size")
        );
        assert!(
            check_listing(&fixed, 8)
                .unwrap_err()
                .contains("does not size")
        );
        // ...which the default cannot tell apart, and CI's non-default build can.
        assert!(check_listing(&fixed, 16).is_ok());
    }

    #[test]
    fn an_image_without_the_symbols_fails() {
        let e = check_listing("0000000000100000 T _start\n", 16).unwrap_err();
        assert!(e.contains("defines no __stack_bottom"), "{e}");
    }
}
