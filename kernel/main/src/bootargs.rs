//! The kernel command line and the boot mode it selects.
//!
//! Read once, from whatever the configuration's `bootinfo` provider says the loader left:
//! the boot protocol's command line tag, a Multiboot command line, or `/chosen`'s
//! `bootargs`. Parsed with `cmdline`, the same grammar the loaders compose it with.
//!
//! # What the mode changes today
//!
//! `docs/bootloader.md#modes` defines safe mode as a list, and most of that list is about
//! subsystems that do not exist yet: secondary CPUs, driver isolation, loadable modules,
//! power management. What exists is the part about output. In `safe` and `recovery` mode
//! this module prints the loader's memory map region by region before anything is built
//! on it. That is the information a person debugging a machine that will not boot needs
//! first, and it is too long for every boot. The rest of the list is recorded in the
//! document as what each of those subsystems must honour when it arrives.
//!
//! # The check
//!
//! With `BOOT_ARGS_CHECK`, which test builds have, the boot fails unless the kernel was
//! given `mode=BOOT_EXPECT_MODE` and exactly the words of `CMDLINE`. The build writes that
//! line into every boot path, so a line lost or changed anywhere between the build and
//! the kernel is a failed boot rather than a boot that silently ignored its arguments.

use boot_protocol::{MemoryKind, MemoryRegion};
use cmdline::{Args, Mode};
use hal::EarlyConsole;

use crate::{Check, MAX_REGIONS, write_hex, write_usize};

/// Read, report and check the command line.
pub fn check(c: &dyn EarlyConsole, boot_arg: u64) -> Check {
    let mut buf = [0u8; cmdline::MAX_LINE];
    // SAFETY: `boot_arg` is the value the architecture's boot code passed to `kmain`, and
    // the loader's memory is still identity-mapped this early: `command_line`'s contract,
    // which is the same as `memory_regions`'.
    let n = match unsafe { bootinfo::command_line(boot_arg, &mut buf) } {
        Ok(Some(n)) => n,
        Ok(None) => {
            c.write_str("none passed");
            return missing();
        }
        Err(e) => {
            c.write_str(match e {
                bootinfo::Error::NoLoader => "no loader to read one from",
                bootinfo::Error::Malformed { .. } | bootinfo::Error::TooManyRegions { .. } => {
                    "MALFORMED"
                }
                bootinfo::Error::NoMemoryMap => "unreadable",
            });
            return missing();
        }
    };
    let line = &buf[..n];
    c.write_bytes(line);

    let args = match Args::parse(line) {
        Ok(args) => args,
        Err(e) => {
            c.write_str("\n  boot mode  REFUSED: ");
            describe(c, e);
            return Check::Failed;
        }
    };
    let mode = args.mode();
    c.write_str("\n  boot mode  ");
    c.write_str(mode.name());

    let verdict = if kconfig::BOOT_ARGS_CHECK {
        expected(c, &args)
    } else {
        Check::Passed
    };
    if mode.is_conservative() {
        verbose_memory_map(c, boot_arg);
    }
    verdict
}

/// A boot with no command line: a failure when the build wrote one, since then it was
/// lost on the way; otherwise the kernel's defaults, which is normal mode.
fn missing() -> Check {
    if kconfig::BOOT_ARGS_CHECK {
        Check::Failed
    } else {
        Check::Passed
    }
}

/// Whether `args` is `mode=BOOT_EXPECT_MODE` followed by exactly the words of `CMDLINE`.
fn expected(c: &dyn EarlyConsole, args: &Args<'_>) -> Check {
    let Ok(wanted) = Args::parse(kconfig::CMDLINE.as_bytes()) else {
        c.write_str(", but CMDLINE in the configuration does not parse");
        return Check::Failed;
    };
    let mode_ok = args.mode().name() == kconfig::BOOT_EXPECT_MODE;
    let got = args.words().filter(|w| w.key != b"mode");
    let mut want = wanted.words();
    let words_ok = got
        .map(Some)
        .chain(core::iter::once(None))
        .zip(want.by_ref().map(Some).chain(core::iter::once(None)))
        .all(|(g, w)| g.map(|g| (g.key, g.value)) == w.map(|w| (w.key, w.value)));
    if mode_ok && words_ok {
        c.write_str(", as built");
        return Check::Passed;
    }
    c.write_str(", EXPECTED mode=");
    c.write_str(kconfig::BOOT_EXPECT_MODE);
    if !kconfig::CMDLINE.is_empty() {
        c.write_str(" ");
        c.write_str(kconfig::CMDLINE);
    }
    Check::Failed
}

fn describe(c: &dyn EarlyConsole, e: cmdline::Error) {
    use cmdline::Error::*;
    let (what, offset) = match e {
        TooLong => ("too long", None),
        BadByte { offset } => ("a byte outside printable ASCII", Some(offset)),
        BadKey { offset } => ("a malformed word", Some(offset)),
        UnterminatedQuote { offset } => ("an unterminated quote", Some(offset)),
        TrailingAfterQuote { offset } => ("text after a closing quote", Some(offset)),
        UnknownMode { offset } => ("an unknown mode", Some(offset)),
        RepeatedMode { offset } => ("mode= given twice", Some(offset)),
    };
    c.write_str(what);
    if let Some(at) = offset {
        c.write_str(" at byte ");
        write_usize(c, at);
    }
}

/// Safe mode's verbose output: every region the loader reported.
fn verbose_memory_map(c: &dyn EarlyConsole, boot_arg: u64) {
    let mut regions = [MemoryRegion {
        start: 0,
        len: 0,
        kind: 0,
        _reserved: 0,
    }; MAX_REGIONS];
    c.write_str(" (conservative: the loader's memory map follows)");
    // SAFETY: as in `check`; `memory` makes the same call with the same argument next.
    let Ok(n) = (unsafe { bootinfo::memory_regions(boot_arg, &mut regions) }) else {
        c.write_str("\n    no memory map; the memory line below says why");
        return;
    };
    for r in &regions[..n] {
        c.write_str("\n    ");
        write_hex(c, r.start);
        c.write_str(" + ");
        write_hex(c, r.len);
        c.write_str(" ");
        c.write_str(kind_name(r.kind));
    }
}

fn kind_name(kind: u32) -> &'static str {
    const KINDS: [(MemoryKind, &str); 7] = [
        (MemoryKind::Usable, "usable"),
        (MemoryKind::Reserved, "reserved"),
        (MemoryKind::AcpiReclaimable, "acpi reclaimable"),
        (MemoryKind::AcpiNvs, "acpi nvs"),
        (MemoryKind::Bad, "bad"),
        (MemoryKind::KernelImage, "kernel image"),
        (MemoryKind::BootData, "boot data"),
    ];
    KINDS
        .iter()
        .find(|(k, _)| *k as u32 == kind)
        .map_or("unknown", |(_, name)| name)
}

/// The mode names the configuration may expect, checked at build time against the
/// parser's, so a typo in BOOT_EXPECT_MODE is a compile error and not a boot that can
/// never pass.
const _: () = {
    let want = kconfig::BOOT_EXPECT_MODE.as_bytes();
    let mut i = 0;
    let mut found = want.is_empty();
    while i < Mode::ALL.len() {
        let name = Mode::ALL[i].name().as_bytes();
        if name.len() == want.len() {
            let mut j = 0;
            while j < name.len() && name[j] == want[j] {
                j += 1;
            }
            found |= j == name.len();
        }
        i += 1;
    }
    assert!(found, "BOOT_EXPECT_MODE is not a boot mode name");
};
