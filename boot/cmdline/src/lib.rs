//! The kernel command line.
//!
//! # Grammar
//!
//! ```text
//! line   = [ word *( space word ) ]
//! word   = key [ "=" value ]
//! key    = 1*( printable ASCII except space, `=` and `"` )
//! value  = *( printable ASCII except space and `"` )
//!        | `"` *( printable ASCII except `"` ) `"`
//! space  = 1*( " " | "\t" | "\n" | "\r" )
//! ```
//!
//! Deliberately small. A command line is typed by a person at a boot menu or written
//! into a boot entry, so it has to be readable and has to fail loudly. Anything outside
//! the grammar is an [`Error`] naming its byte offset, never a word silently skipped:
//! a kernel that ignored half its arguments would boot a configuration nobody chose.
//!
//! Unknown keys are not errors. A newer loader may pass arguments an older kernel does
//! not know, and the protocol's compatibility rules (`docs/bootloader.md`) say the older
//! kernel must still boot.
//!
//! Words are byte slices, not `str`. The grammar admits only ASCII, so nothing is lost,
//! and the BIOS loader links this crate into a 32 KiB stage 2. `str` slicing brings in
//! `core`'s panic formatting and Unicode tables, which cost that stage 2 more than 4 KiB
//! the first time it was built.
//!
//! # Keys this crate interprets
//!
//! Only `mode`, because the loaders and the kernel must agree on it: [`Mode`].
//! Everything else is the business of whichever subsystem reads it, through
//! [`Args::get`] and [`Args::words`].

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

/// The longest line accepted, matching `boot_protocol::tags::MAX_COMMAND_LINE`.
pub const MAX_LINE: usize = 1024;

/// How the kernel should behave, chosen at the boot menu.
///
/// Each is defined by what it changes, in `docs/bootloader.md#modes`, because a safe mode
/// nobody has enumerated is not a feature.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// The configured kernel, as built.
    Normal,
    /// The conservative configuration: fewer moving parts, more output.
    Safe,
    /// Safe, and in addition nothing that writes to storage.
    Recovery,
}

impl Mode {
    /// Every mode, in menu order.
    pub const ALL: [Mode; 3] = [Mode::Normal, Mode::Safe, Mode::Recovery];

    /// The name used in `mode=` and in boot entries.
    pub const fn name(self) -> &'static str {
        match self {
            Mode::Normal => "normal",
            Mode::Safe => "safe",
            Mode::Recovery => "recovery",
        }
    }

    pub fn from_name(name: &[u8]) -> Option<Mode> {
        Mode::ALL.into_iter().find(|m| m.name().as_bytes() == name)
    }

    /// Whether the conservative behaviour applies. Recovery includes everything safe
    /// mode does.
    pub const fn is_conservative(self) -> bool {
        !matches!(self, Mode::Normal)
    }
}

/// Why a line was refused. Offsets are bytes from the start of the line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Longer than [`MAX_LINE`].
    TooLong,
    /// A byte outside printable ASCII and the separators.
    BadByte { offset: usize },
    /// A word that starts with `=`, or has a quote anywhere but around a whole value.
    BadKey { offset: usize },
    /// A quoted value with no closing quote.
    UnterminatedQuote { offset: usize },
    /// A closing quote followed by something other than a separator.
    TrailingAfterQuote { offset: usize },
    /// `mode=` with a value that is not a [`Mode`] name.
    UnknownMode { offset: usize },
    /// `mode=` given more than once. Last-one-wins would let an entry's own mode be
    /// overridden by an appended argument without anyone seeing it happen.
    RepeatedMode { offset: usize },
}

/// One `key` or `key=value` word.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Word<'a> {
    pub key: &'a [u8],
    /// `None` for a bare flag. `Some(b"")` for `key=`.
    pub value: Option<&'a [u8]>,
    /// Byte offset of the word in the line.
    pub offset: usize,
}

/// A validated command line.
#[derive(Clone, Copy, Debug)]
pub struct Args<'a> {
    line: &'a [u8],
    mode: Mode,
}

impl<'a> Args<'a> {
    /// Validate `line` completely, so every later lookup is infallible.
    pub fn parse(line: &'a [u8]) -> Result<Args<'a>, Error> {
        if line.len() > MAX_LINE {
            return Err(Error::TooLong);
        }
        if let Some(offset) = line.iter().position(|&b| !is_text(b)) {
            return Err(Error::BadByte { offset });
        }
        let mut mode = None;
        let mut rest = Scanner { line, at: 0 };
        while let Some(word) = rest.next_word()? {
            if word.key == b"mode" {
                if mode.is_some() {
                    return Err(Error::RepeatedMode {
                        offset: word.offset,
                    });
                }
                let value = word.value.unwrap_or(b"");
                mode = Some(Mode::from_name(value).ok_or(Error::UnknownMode {
                    offset: word.offset,
                })?);
            }
        }
        Ok(Args {
            line,
            mode: mode.unwrap_or(Mode::Normal),
        })
    }

    /// The line as given.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.line
    }

    /// The boot mode: `mode=` if present, otherwise [`Mode::Normal`].
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Every word, in order.
    pub fn words(&self) -> Words<'a> {
        Words(Scanner {
            line: self.line,
            at: 0,
        })
    }

    /// The value of the first `key=value` word with this key. A bare flag has no value;
    /// see [`Args::has`].
    pub fn get(&self, key: &str) -> Option<&'a [u8]> {
        self.words()
            .find(|w| w.key == key.as_bytes())
            .and_then(|w| w.value)
    }

    /// Whether `key` appears at all, as a flag or with a value.
    pub fn has(&self, key: &str) -> bool {
        self.words().any(|w| w.key == key.as_bytes())
    }
}

/// The words of a validated line.
pub struct Words<'a>(Scanner<'a>);

impl<'a> Iterator for Words<'a> {
    type Item = Word<'a>;

    fn next(&mut self) -> Option<Word<'a>> {
        // The line was validated in full by `Args::parse`, so a scan error cannot happen
        // here; ending the iteration is the conservative answer if one somehow did.
        self.0.next_word().ok().flatten()
    }
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn is_text(b: u8) -> bool {
    is_space(b) || (0x21..=0x7E).contains(&b)
}

struct Scanner<'a> {
    line: &'a [u8],
    at: usize,
}

impl<'a> Scanner<'a> {
    fn next_word(&mut self) -> Result<Option<Word<'a>>, Error> {
        let b = self.line;
        while self.at < b.len() && is_space(b[self.at]) {
            self.at += 1;
        }
        if self.at == b.len() {
            return Ok(None);
        }
        let start = self.at;
        let key_end = (start..b.len())
            .find(|&i| is_space(b[i]) || b[i] == b'=')
            .unwrap_or(b.len());
        if key_end == start || b[start..key_end].contains(&b'"') {
            return Err(Error::BadKey { offset: start });
        }
        let key = &b[start..key_end];
        if key_end == b.len() || b[key_end] != b'=' {
            self.at = key_end;
            return Ok(Some(Word {
                key,
                value: None,
                offset: start,
            }));
        }
        let value_start = key_end + 1;
        let value = if b.get(value_start) == Some(&b'"') {
            let close = (value_start + 1..b.len()).find(|&i| b[i] == b'"').ok_or(
                Error::UnterminatedQuote {
                    offset: value_start,
                },
            )?;
            if close + 1 < b.len() && !is_space(b[close + 1]) {
                return Err(Error::TrailingAfterQuote { offset: close + 1 });
            }
            self.at = close + 1;
            &b[value_start + 1..close]
        } else {
            let end = (value_start..b.len())
                .find(|&i| is_space(b[i]))
                .unwrap_or(b.len());
            if b[value_start..end].contains(&b'"') {
                return Err(Error::BadKey { offset: start });
            }
            self.at = end;
            &b[value_start..end]
        };
        Ok(Some(Word {
            key,
            value: Some(value),
            offset: start,
        }))
    }
}

/// Write `mode=<mode>`, then a space and `extra` if `extra` is not blank, into `out`,
/// returning the length. This is how a loader turns a boot entry into the line it hands
/// over, kept beside the grammar so the two cannot drift.
///
/// `None` if `out` is too short or the result would be longer than [`MAX_LINE`].
pub fn compose(mode: Mode, extra: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut n = 0;
    let mut put = |bytes: &[u8]| -> Option<()> {
        let end = n + bytes.len();
        out.get_mut(n..end)?.copy_from_slice(bytes);
        n = end;
        Some(())
    };
    put(b"mode=")?;
    put(mode.name().as_bytes())?;
    let extra = trim(extra);
    if !extra.is_empty() {
        put(b" ")?;
        put(extra)?;
    }
    (n <= MAX_LINE).then_some(n)
}

/// `s` without leading and trailing separators.
pub fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s
        && is_space(*first)
    {
        s = rest;
    }
    while let [rest @ .., last] = s
        && is_space(*last)
    {
        s = rest;
    }
    s
}
