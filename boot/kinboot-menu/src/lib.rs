//! Boot entries, and the menu a KinTane loader shows before it boots one.
//!
//! # The entry list
//!
//! `docs/bootloader.md` asks for "a declarative entry list on the boot medium, where each
//! entry names a kernel, a mode, and optional extra command line", and for nothing that
//! is evaluated. This is that list:
//!
//! ```text
//! # comments and blank lines are ignored
//! timeout 5               seconds before the default boots; 0 boots it at once
//! default normal          the entry booted when nobody chooses; the first if absent
//! on-failure firmware     firmware | reboot: what a loader does when a boot fails
//!
//! entry normal            starts an entry; names are [a-z0-9-], at most 16 bytes
//! title KinTane           the rest of the line, as the menu shows it
//! mode normal             normal | safe | recovery; normal if absent
//! cmdline quiet x=1       the rest of the line, appended after `mode=`
//! kernel \KINTANE\K2.ELF  a kernel other than the loader's default (UEFI only)
//!
//! entry other-os
//! title Another system
//! chain-file \EFI\OTHER\BOOTX64.EFI   start another EFI application (UEFI)
//! chain-partition 2                   boot partition 2's boot record (BIOS)
//! ```
//!
//! Settings come before the first entry. An entry either starts the kernel (`mode`,
//! `cmdline`, `kernel`) or chainloads (`chain-file` or `chain-partition`), never both.
//! Anything else is an [`Error`] with a line number. A loader shows the error and falls
//! back to booting its built-in default rather than refusing to boot, because a machine
//! whose menu file has a typo must still start.
//!
//! # The menu
//!
//! [`Menu`] is the whole interaction as a state machine: keys and clock ticks go in, and
//! at some point an entry to boot comes out. The loaders poll their keyboard and serial
//! port ten times a second and feed what they read. The digit keys `1` to `9` boot that
//! entry at once. Up and down move the selection, Enter boots it, and any key stops the
//! countdown, so a person who has started choosing is not overtaken by the timeout.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

pub use cmdline::Mode;

/// Entries a list may hold: as many as there are digit keys to pick them with.
pub const MAX_ENTRIES: usize = 9;
/// The largest list a loader reads. A list claiming more is refused, not truncated.
pub const MAX_FILE: usize = 4096;
/// The longest countdown accepted, in seconds.
pub const MAX_TIMEOUT: u32 = 600;
/// Longest entry name.
pub const MAX_NAME: usize = 16;
/// How often a loader calls [`Menu::tick`]. Loaders poll at this rate because it is fast
/// enough that a key never waits noticeably, and slow enough that polling costs nothing.
pub const TICKS_PER_SECOND: u32 = 10;

/// What a loader does when the selected entry cannot be booted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OnFailure {
    /// Hand control back to the firmware, which moves on to its next boot option.
    Firmware,
    /// Reset the machine and try the whole boot again.
    Reboot,
}

/// What an entry boots.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target<'a> {
    /// The KinTane kernel.
    Kernel {
        mode: Mode,
        /// Extra command line, without `mode=`; possibly empty.
        cmdline: &'a [u8],
        /// A kernel path other than the loader's default.
        path: Option<&'a [u8]>,
    },
    /// Another EFI application, by path on the boot partition.
    ChainFile(&'a [u8]),
    /// The boot record of a partition on the boot disk, numbered 1 to 4.
    ChainPartition(u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    /// The name if the entry has no `title`.
    pub title: &'a [u8],
    pub target: Target<'a>,
}

/// A problem with the list, and the line it is on, counting from 1. Line 0 is the file
/// as a whole.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Error {
    pub line: u32,
    pub kind: ErrorKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrorKind {
    TooLarge,
    /// A byte outside printable ASCII, tab and line endings.
    BadByte,
    UnknownKey,
    MissingValue,
    /// A setting after the first entry.
    SettingAfterEntry,
    /// An entry key before the first entry.
    OutsideEntry,
    BadName,
    DuplicateName,
    TooManyEntries,
    BadNumber,
    UnknownMode,
    UnknownFailureAction,
    /// `mode=` inside `cmdline`: the entry's `mode` is the only place a mode is set.
    ModeInCmdline,
    /// A `cmdline` the kernel's parser would refuse.
    BadCmdline,
    /// A key given twice in one entry.
    Repeated,
    /// Kernel settings and chainloading in one entry.
    MixedTarget,
    NoEntries,
    /// `default` names no entry.
    UnknownDefault,
}

/// A validated entry list.
#[derive(Clone, Copy, Debug)]
pub struct Config<'a> {
    entries: [Option<Entry<'a>>; MAX_ENTRIES],
    len: usize,
    pub default: usize,
    pub timeout_secs: u32,
    pub on_failure: OnFailure,
}

/// What the lines of an entry said, before they are known to be consistent.
#[derive(Clone, Copy, Default)]
struct Draft<'a> {
    name: &'a [u8],
    title: Option<&'a [u8]>,
    mode: Option<Mode>,
    cmdline: Option<&'a [u8]>,
    kernel: Option<&'a [u8]>,
    chain_file: Option<&'a [u8]>,
    chain_partition: Option<u8>,
    /// Line the entry started on, for errors about the entry as a whole.
    line: u32,
}

impl<'a> Draft<'a> {
    fn finish(self) -> Result<Entry<'a>, Error> {
        let kernelish = self.mode.is_some() || self.cmdline.is_some() || self.kernel.is_some();
        let chains =
            usize::from(self.chain_file.is_some()) + usize::from(self.chain_partition.is_some());
        let err = |kind| Error {
            line: self.line,
            kind,
        };
        let target = match (self.chain_file, self.chain_partition) {
            _ if chains > 1 || (chains == 1 && kernelish) => {
                return Err(err(ErrorKind::MixedTarget));
            }
            (Some(path), None) => Target::ChainFile(path),
            (None, Some(n)) => Target::ChainPartition(n),
            _ => Target::Kernel {
                mode: self.mode.unwrap_or(Mode::Normal),
                cmdline: self.cmdline.unwrap_or(b""),
                path: self.kernel,
            },
        };
        Ok(Entry {
            name: self.name,
            title: self.title.unwrap_or(self.name),
            target,
        })
    }
}

fn is_file_byte(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\r') || (0x20..=0x7E).contains(&b)
}

fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r')
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s
        && is_blank(*first)
    {
        s = rest;
    }
    while let [rest @ .., last] = s
        && is_blank(*last)
    {
        s = rest;
    }
    s
}

fn number(s: &[u8], max: u32) -> Option<u32> {
    if s.is_empty() || s.len() > 4 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let v = s.iter().fold(0u32, |v, &d| v * 10 + u32::from(d - b'0'));
    (v <= max).then_some(v)
}

impl<'a> Config<'a> {
    /// Validate a whole entry list.
    pub fn parse(file: &'a [u8]) -> Result<Config<'a>, Error> {
        let whole = |kind| Error { line: 0, kind };
        if file.len() > MAX_FILE {
            return Err(whole(ErrorKind::TooLarge));
        }
        let mut config = Config {
            entries: [None; MAX_ENTRIES],
            len: 0,
            default: 0,
            timeout_secs: 0,
            on_failure: OnFailure::Firmware,
        };
        let mut default_name: Option<(&[u8], u32)> = None;
        let mut draft: Option<Draft<'a>> = None;

        for (index, raw) in file.split(|&b| b == b'\n').enumerate() {
            let line = u32::try_from(index + 1).unwrap_or(u32::MAX);
            let err = |kind| Error { line, kind };
            if !raw.iter().all(|&b| is_file_byte(b)) {
                return Err(err(ErrorKind::BadByte));
            }
            let text = trim(raw);
            if text.is_empty() || text[0] == b'#' {
                continue;
            }
            let split = text.iter().position(|&b| is_blank(b)).unwrap_or(text.len());
            let (key, value) = (&text[..split], trim(&text[split..]));
            let need = |v: &'a [u8]| {
                if v.is_empty() {
                    Err(err(ErrorKind::MissingValue))
                } else {
                    Ok(v)
                }
            };

            match key {
                b"timeout" | b"default" | b"on-failure" if draft.is_some() || config.len > 0 => {
                    return Err(err(ErrorKind::SettingAfterEntry));
                }
                b"timeout" => {
                    config.timeout_secs =
                        number(need(value)?, MAX_TIMEOUT).ok_or(err(ErrorKind::BadNumber))?;
                }
                b"default" => default_name = Some((need(value)?, line)),
                b"on-failure" => {
                    config.on_failure = match need(value)? {
                        b"firmware" => OnFailure::Firmware,
                        b"reboot" => OnFailure::Reboot,
                        _ => return Err(err(ErrorKind::UnknownFailureAction)),
                    };
                }
                b"entry" => {
                    let name = need(value)?;
                    let valid = name.len() <= MAX_NAME
                        && name
                            .iter()
                            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
                    if !valid {
                        return Err(err(ErrorKind::BadName));
                    }
                    if let Some(d) = draft.take() {
                        config.push(d.finish()?, line)?;
                    }
                    if config.entries().any(|e| e.name == name) {
                        return Err(err(ErrorKind::DuplicateName));
                    }
                    draft = Some(Draft {
                        name,
                        line,
                        ..Draft::default()
                    });
                }
                _ => {
                    let d = draft.as_mut().ok_or(match key {
                        b"title" | b"mode" | b"cmdline" | b"kernel" | b"chain-file"
                        | b"chain-partition" => err(ErrorKind::OutsideEntry),
                        _ => err(ErrorKind::UnknownKey),
                    })?;
                    let once = |slot_set: bool| {
                        if slot_set {
                            Err(err(ErrorKind::Repeated))
                        } else {
                            Ok(())
                        }
                    };
                    match key {
                        b"title" => {
                            once(d.title.is_some())?;
                            d.title = Some(need(value)?);
                        }
                        b"mode" => {
                            once(d.mode.is_some())?;
                            d.mode = Some(
                                Mode::from_name(need(value)?).ok_or(err(ErrorKind::UnknownMode))?,
                            );
                        }
                        b"cmdline" => {
                            once(d.cmdline.is_some())?;
                            let args = cmdline::Args::parse(value)
                                .map_err(|_| err(ErrorKind::BadCmdline))?;
                            if args.has("mode") {
                                return Err(err(ErrorKind::ModeInCmdline));
                            }
                            d.cmdline = Some(value);
                        }
                        b"kernel" => {
                            once(d.kernel.is_some())?;
                            d.kernel = Some(need(value)?);
                        }
                        b"chain-file" => {
                            once(d.chain_file.is_some())?;
                            d.chain_file = Some(need(value)?);
                        }
                        b"chain-partition" => {
                            once(d.chain_partition.is_some())?;
                            let n = number(need(value)?, 4)
                                .filter(|&n| n >= 1)
                                .ok_or(err(ErrorKind::BadNumber))?;
                            d.chain_partition = Some(n as u8);
                        }
                        _ => return Err(err(ErrorKind::UnknownKey)),
                    }
                }
            }
        }
        if let Some(d) = draft.take() {
            let line = d.line;
            config.push(d.finish()?, line)?;
        }
        if config.len == 0 {
            return Err(whole(ErrorKind::NoEntries));
        }
        if let Some((name, line)) = default_name {
            let index = config.entries().position(|e| e.name == name);
            config.default = index.ok_or(Error {
                line,
                kind: ErrorKind::UnknownDefault,
            })?;
        }
        Ok(config)
    }

    fn push(&mut self, entry: Entry<'a>, line: u32) -> Result<(), Error> {
        let slot = self.entries.get_mut(self.len).ok_or(Error {
            line,
            kind: ErrorKind::TooManyEntries,
        })?;
        *slot = Some(entry);
        self.len += 1;
        Ok(())
    }

    /// Every entry, in file order.
    pub fn entries(&self) -> impl Iterator<Item = Entry<'a>> + '_ {
        self.entries[..self.len].iter().flatten().copied()
    }

    pub fn entry(&self, index: usize) -> Option<Entry<'a>> {
        self.entries.get(..self.len)?.get(index).copied().flatten()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A key, as far as the menu cares. Loaders translate their keyboard's codes into these.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    /// `1` to `9`.
    Digit(u8),
    Enter,
    Up,
    Down,
    Other,
}

impl Key {
    /// A byte read from a serial console. Arrow keys arrive as escape sequences, which a
    /// byte-at-a-time reader cannot tell from a lone Escape, so on a serial line the
    /// digits are the way to choose; the `k`/`j` and `-`/`+` pairs also move.
    pub fn from_ascii(b: u8) -> Key {
        match b {
            b'1'..=b'9' => Key::Digit(b - b'0'),
            b'\r' | b'\n' => Key::Enter,
            b'k' | b'-' => Key::Up,
            b'j' | b'+' => Key::Down,
            _ => Key::Other,
        }
    }
}

/// What a loader should do after feeding the menu a key or a tick.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Keep polling.
    Wait,
    /// The selection moved; show it.
    Moved(usize),
    /// Boot this entry.
    Boot(usize),
}

/// The menu's state: which entry is selected and how much of the countdown is left.
#[derive(Clone, Copy, Debug)]
pub struct Menu {
    len: usize,
    selected: usize,
    /// Ticks until the selection boots; `None` once a key has stopped the countdown.
    remaining: Option<u32>,
}

impl Menu {
    pub fn new(config: &Config<'_>) -> Menu {
        Menu {
            len: config.len,
            selected: config.default,
            remaining: Some(config.timeout_secs.saturating_mul(TICKS_PER_SECOND)),
        }
    }

    /// Called once, after the menu has been shown and before the first poll. With a zero
    /// timeout the default boots here, without waiting for a key.
    pub fn start(&self) -> Step {
        match self.remaining {
            Some(0) => Step::Boot(self.selected),
            _ => Step::Wait,
        }
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Whether the countdown is still running.
    pub fn counting(&self) -> bool {
        self.remaining.is_some()
    }

    /// Seconds left on the countdown, rounded up, for display.
    pub fn seconds_left(&self) -> Option<u32> {
        self.remaining.map(|t| t.div_ceil(TICKS_PER_SECOND))
    }

    /// One poll interval has passed.
    pub fn tick(&mut self) -> Step {
        match self.remaining {
            Some(0 | 1) => {
                self.remaining = Some(0);
                Step::Boot(self.selected)
            }
            Some(t) => {
                self.remaining = Some(t - 1);
                Step::Wait
            }
            None => Step::Wait,
        }
    }

    pub fn key(&mut self, key: Key) -> Step {
        self.remaining = None;
        match key {
            Key::Digit(d) if usize::from(d) >= 1 && usize::from(d) <= self.len => {
                self.selected = usize::from(d) - 1;
                Step::Boot(self.selected)
            }
            Key::Enter => Step::Boot(self.selected),
            Key::Up if self.selected > 0 => {
                self.selected -= 1;
                Step::Moved(self.selected)
            }
            Key::Down if self.selected + 1 < self.len => {
                self.selected += 1;
                Step::Moved(self.selected)
            }
            _ => Step::Wait,
        }
    }
}

/// Show the menu: one line per entry, the selected one marked, then how to choose.
///
/// Through a callback rather than `core::fmt`, because the BIOS loader has a 32 KiB
/// budget and the formatting machinery would take a large part of it.
pub fn render(config: &Config<'_>, menu: &Menu, out: &mut dyn FnMut(&[u8])) {
    out(b"\r\nkinboot: boot menu\r\n");
    for (i, e) in config.entries().enumerate() {
        out(if i == menu.selected() { b" * " } else { b"   " });
        out(&[b'1' + i as u8, b')', b' ']);
        out(e.title);
        match e.target {
            Target::Kernel { mode, .. } => {
                out(b"  [");
                out(mode.name().as_bytes());
                out(b"]");
            }
            Target::ChainFile(_) | Target::ChainPartition(_) => out(b"  [chainload]"),
        }
        out(b"\r\n");
    }
    if menu.seconds_left() == Some(0) {
        out(b"booting the marked entry\r\n");
        return;
    }
    out(b"1-");
    out(&[b'0' + config.len() as u8]);
    out(b" boots an entry, Enter the marked one");
    if let Some(s) = menu.seconds_left() {
        out(b"; the marked one boots in ");
        let mut digits = [0u8; 10];
        out(decimal(s, &mut digits));
        out(b" s");
    }
    out(b"\r\n");
}

/// `v` in decimal, written into the end of `buf`.
pub fn decimal(mut v: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

/// The kernel command line an entry hands over: `mode=` and then its own `cmdline`.
/// `None` for a chainload entry, or if `out` is too small.
pub fn kernel_command_line(entry: &Entry<'_>, out: &mut [u8]) -> Option<usize> {
    match entry.target {
        Target::Kernel { mode, cmdline, .. } => cmdline::compose(mode, cmdline, out),
        _ => None,
    }
}
