//! Running a built image under QEMU.
//!
//! One canonical invocation per target, derived from the configuration rather than
//! typed by hand. See `docs/testing.md` — in particular the result channels, which
//! exist so that a test's verdict never has to be scraped out of console output.

use std::path::Path;
use std::process::Command;

use crate::kcfg::Resolution;

pub struct Machine {
    pub binary: &'static str,
    pub args: Vec<String>,
    /// Exit code QEMU reports when the guest signalled success.
    pub success_code: i32,
}

pub fn machine_for(res: &Resolution, image: &Path, log: &Path) -> Result<Machine, String> {
    let s = |x: &str| x.to_string();
    let mem = format!("{}M", {
        let m = res.int("QEMU_MEMORY_MB");
        if m > 0 { m } else { 128 }
    });
    let cpu = {
        let c = res.str("QEMU_CPU");
        if c.is_empty() {
            "max".to_string()
        } else {
            c.to_string()
        }
    };

    if res.is_on("ARCH_X86_64") {
        // isa-debug-exit reports (value << 1) | 1, so the guest can never produce 0
        // and "QEMU exited for its own reasons" is never mistaken for a pass.
        return Ok(Machine {
            binary: "qemu-system-x86_64",
            args: vec![
                s("-machine"),
                s("q35"),
                s("-cpu"),
                cpu,
                s("-m"),
                mem,
                s("-kernel"),
                image.display().to_string(),
                s("-device"),
                s("isa-debug-exit,iobase=0xf4,iosize=0x04"),
                s("-serial"),
                s("stdio"),
                s("-display"),
                s("none"),
                // A triple fault must be a visible failure, not a reboot loop that
                // reads as a timeout.
                //
                // Note the absence of -no-shutdown, which looks like it belongs here
                // and does not: it keeps QEMU alive across a guest shutdown, which
                // suppresses isa-debug-exit and turns every passing test into a
                // timeout.
                s("-no-reboot"),
                // Exception and guest-error tracing goes to a file, not stderr, so a
                // failure leaves evidence without burying the console output.
                s("-d"),
                s("int,guest_errors"),
                s("-D"),
                log.display().to_string(),
            ],
            success_code: (0x10 << 1) | 1,
        });
    }

    if res.is_on("ARCH_I686") {
        return Ok(Machine {
            binary: "qemu-system-i386",
            args: vec![
                // i440FX rather than q35: this target exists for legacy PCs, and
                // testing it on a modern chipset would defeat the point.
                s("-machine"),
                s("pc"),
                s("-cpu"),
                cpu,
                s("-m"),
                mem,
                s("-kernel"),
                image.display().to_string(),
                s("-device"),
                s("isa-debug-exit,iobase=0xf4,iosize=0x04"),
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
            success_code: (0x10 << 1) | 1,
        });
    }

    if res.is_on("ARCH_AARCH64") {
        return Ok(Machine {
            binary: "qemu-system-aarch64",
            args: vec![
                s("-machine"),
                s("virt,gic-version=3"),
                s("-cpu"),
                cpu,
                s("-m"),
                mem,
                s("-kernel"),
                image.display().to_string(),
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
            success_code: 0,
        });
    }

    Err("no QEMU machine is defined for this configuration".into())
}

pub struct Outcome {
    pub code: Option<i32>,
    pub passed: bool,
}

pub fn run(m: &Machine, timeout_secs: u64) -> Result<Outcome, String> {
    let mut child = Command::new(m.binary)
        .args(&m.args)
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}\nis QEMU installed?", m.binary))?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code();
                return Ok(Outcome {
                    code,
                    passed: code == Some(m.success_code),
                });
            }
            Ok(None) => {
                if start.elapsed().as_secs() >= timeout_secs {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "timed out after {timeout_secs}s with no exit signal from the guest"
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(format!("waiting for QEMU: {e}")),
        }
    }
}
