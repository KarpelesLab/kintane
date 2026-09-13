//! Running a built image under QEMU.
//!
//! One canonical invocation per target, derived from the configuration rather than
//! typed by hand. See `docs/testing.md` — in particular the result channels, which
//! exist so that a test's verdict never has to be scraped out of console output.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

    if res.is_on("ARCH_X86_64") && res.is_on("BOOT_KINBOOT") {
        // The firmware path: OVMF boots the disk image's EFI system partition, which
        // starts kinboot-efi, which starts the kernel. No -kernel: QEMU's own loader is
        // exactly what this configuration exists to not use.
        let fw = uefi_firmware(log.parent().unwrap_or(Path::new(".")))?;
        let mut args = vec![
            s("-machine"),
            s("q35"),
            s("-cpu"),
            cpu,
            s("-m"),
            mem,
            s("-drive"),
            format!("if=pflash,format=raw,unit=0,readonly=on,file={}", fw.code.display()),
        ];
        if let Some(vars) = &fw.vars {
            args.push(s("-drive"));
            args.push(format!("if=pflash,format=raw,unit=1,file={}", vars.display()));
        }
        args.extend([
            // snapshot=on: the guest writes to an overlay, so the image on disk stays
            // the bytes the build produced.
            s("-drive"),
            format!("format=raw,snapshot=on,file={}", image.display()),
            s("-device"),
            s("isa-debug-exit,iobase=0xf4,iosize=0x04"),
            s("-serial"),
            s("stdio"),
            s("-display"),
            s("none"),
            s("-no-reboot"),
            // Guest errors only, not every interrupt: the firmware takes thousands of
            // timer interrupts before the kernel runs, and logging each one would bury
            // the kernel's few in megabytes of OVMF.
            s("-d"),
            s("guest_errors,cpu_reset"),
            s("-D"),
            log.display().to_string(),
        ]);
        return Ok(Machine {
            binary: "qemu-system-x86_64",
            args,
            success_code: (0x10 << 1) | 1,
        });
    }

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
            ]
            .into_iter()
            .chain(x86_boot_media(res, image))
            .collect(),
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
            ]
            .into_iter()
            .chain(x86_boot_media(res, image))
            .collect(),
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

/// How an x86 guest gets its kernel: straight from QEMU's multiboot loader, or from a
/// raw disk through the BIOS and `kinboot-bios`, with no `-kernel` at all.
///
/// The disk boot adds `-boot reboot-timeout=0`. When the BIOS finds nothing bootable, or
/// the loader gives up through INT 18h, SeaBIOS then reboots at once instead of after 60
/// seconds, and `-no-reboot` turns that reboot into an exit with status 0, which is never
/// the success code. So a broken disk is a failure the harness sees within a second,
/// not a timeout.
fn x86_boot_media(res: &Resolution, image: &Path) -> Vec<String> {
    if res.is_on(crate::bios::SYMBOL) {
        vec![
            "-drive".into(),
            format!("format=raw,file={}", image.display()),
            "-boot".into(),
            "reboot-timeout=0".into(),
        ]
    } else {
        vec!["-kernel".into(), image.display().to_string()]
    }
}

/// UEFI firmware for an x86_64 guest: the code image, and a fresh copy of a variable
/// store if the firmware has a separate one.
struct Firmware {
    code: PathBuf,
    vars: Option<PathBuf>,
}

/// Find OVMF. Firmware is a system package rather than part of the pinned toolchain, and
/// every distribution puts it somewhere else, so this looks in the known places:
///
/// - `KINTANE_OVMF_CODE` (and optionally `KINTANE_OVMF_VARS`), for anything else;
/// - the edk2 build QEMU itself ships, next to the `qemu-system-x86_64` on `PATH` —
///   Homebrew's, for one;
/// - Debian and Ubuntu's `ovmf` package, Fedora's `edk2-ovmf`, Arch's `edk2-ovmf`.
///
/// The variable store is copied into the build directory for every boot, so a run never
/// inherits boot entries or settings a previous one wrote.
fn uefi_firmware(scratch: &Path) -> Result<Firmware, String> {
    let mut candidates: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    if let Some(code) = std::env::var_os("KINTANE_OVMF_CODE") {
        candidates.push((code.into(), std::env::var_os("KINTANE_OVMF_VARS").map(Into::into)));
    }
    if let Some(bin) = find_on_path("qemu-system-x86_64") {
        let dirs = [Some(bin.clone()), std::fs::canonicalize(&bin).ok()];
        for b in dirs.into_iter().flatten() {
            if let Some(share) = b
                .parent()
                .and_then(Path::parent)
                .map(|p| p.join("share/qemu"))
            {
                candidates.push((
                    share.join("edk2-x86_64-code.fd"),
                    Some(share.join("edk2-i386-vars.fd")),
                ));
            }
        }
    }
    for (code, vars) in [
        ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
        ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
        ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
        ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ] {
        candidates.push((code.into(), Some(vars.into())));
    }

    let Some((code, vars)) = candidates.iter().find(|(code, _)| code.is_file()) else {
        let tried: Vec<String> = candidates
            .iter()
            .map(|(c, _)| c.display().to_string())
            .collect();
        return Err(format!(
            "no UEFI firmware (OVMF) found for x86_64\n  tried:\n    {}\n  \
             install the `ovmf` package, or set KINTANE_OVMF_CODE to the firmware image",
            tried.join("\n    ")
        ));
    };
    let vars = match vars.as_ref().filter(|v| v.is_file()) {
        Some(template) => {
            std::fs::create_dir_all(scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
            let copy = scratch.join("ovmf-vars.fd");
            std::fs::copy(template, &copy).map_err(|e| {
                format!("copying {} to {}: {e}", template.display(), copy.display())
            })?;
            Some(copy)
        }
        None => None,
    };
    Ok(Firmware {
        code: code.clone(),
        vars,
    })
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

pub struct Outcome {
    pub code: Option<i32>,
    pub passed: bool,
    /// The guest never signalled and was killed.
    pub timed_out: bool,
    /// Everything the guest wrote to its serial console.
    ///
    /// Kept for decoding a backtrace after the fact, never for deciding the verdict,
    /// which is the exit status alone.
    pub console: Vec<u8>,
}

/// Boot, passing the console through as it arrives and keeping a copy.
///
/// A guest that never signals is killed after `timeout_secs` and reported through
/// `timed_out` rather than as an error, because the console it printed first is exactly
/// what explains the hang: a fault report halts the CPU and never reaches the exit port.
pub fn run(m: &Machine, timeout_secs: u64) -> Result<Outcome, String> {
    let mut child = Command::new(m.binary)
        .args(&m.args)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}\nis QEMU installed?", m.binary))?;

    let mut pipe = child
        .stdout
        .take()
        .ok_or("QEMU's console was not captured")?;
    let tee = std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 4096];
        let mut out = std::io::stdout();
        // Ends when QEMU exits or is killed and its end of the pipe closes.
        while let Ok(n) = pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
            kept.extend_from_slice(&buf[..n]);
        }
        kept
    });

    let start = std::time::Instant::now();
    let (code, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status.code(), false),
            Ok(None) => {
                if start.elapsed().as_secs() >= timeout_secs {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (None, true);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(format!("waiting for QEMU: {e}")),
        }
    };
    let console = tee.join().unwrap_or_default();
    Ok(Outcome {
        code,
        passed: !timed_out && code == Some(m.success_code),
        timed_out,
        console,
    })
}
