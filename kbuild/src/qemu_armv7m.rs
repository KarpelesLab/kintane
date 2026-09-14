//! The QEMU machine for ARMv7-M: `mps2-an385`, a Cortex-M3.
//!
//! Kept apart from `qemu.rs` so the port's harness is one file. QEMU's M-profile
//! `-kernel` loads the ELF's segments at their load addresses — which puts `.data`'s
//! initial copy in code memory, as the image expects — and resets the core, which then
//! reads its stack pointer and reset vector from address 0. There is no `-append`: no
//! loader runs, so there is nowhere for a command line to arrive, and the kernel's comes
//! from the build (`boot/info-board`).

use std::path::Path;

use crate::kcfg::Resolution;
use crate::qemu::Machine;

pub fn machine(res: &Resolution, image: &Path, log: &Path) -> Machine {
    let s = |x: &str| x.to_string();
    Machine {
        binary: "qemu-system-arm",
        args: vec![
            s("-machine"),
            s("mps2-an385"),
            s("-kernel"),
            image.display().to_string(),
            // The result channel, as on aarch64.
            s("-semihosting-config"),
            s("enable=on,target=native"),
            s("-serial"),
            s("stdio"),
            s("-display"),
            s("none"),
            s("-no-reboot"),
            s("-d"),
            s("int,guest_errors"),
            s("-D"),
            log.display().to_string(),
        ],
        // SYS_EXIT_EXTENDED with code 0 exits QEMU with status 0.
        success_code: 0,
        input: res.str("BOOT_TEST_KEYS").as_bytes().to_vec(),
        serial_probe: res.is_on("SERIAL_IRQ_TEST"),
    }
}
