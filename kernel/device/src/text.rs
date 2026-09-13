//! Fixed-capacity text, for the names and `compatible` lists enumerators other than the
//! device tree have to write themselves.
//!
//! A device-tree node's name and `compatible` are slices of the blob. A PCI function or
//! a MADT entry has no such bytes, so its enumerator formats them, and the node borrows
//! them from the record that owns them. That is why the buffer is inline and `Copy`: the
//! records live in caller storage like everything else in the model.

use core::fmt;

/// Up to `N` bytes of formatted text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Text<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> Text<N> {
    pub const EMPTY: Text<N> = Text {
        bytes: [0; N],
        len: 0,
    };

    /// Format `args`. `None` when the result does not fit, which is an enumerator's bug
    /// to fix in its buffer size, never a truncated name to bind a driver against.
    pub fn format(args: fmt::Arguments<'_>) -> Option<Text<N>> {
        let mut t = Text::EMPTY;
        fmt::write(&mut t, args).ok()?;
        Some(t)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let start = usize::from(self.len);
        let end = start.checked_add(s.len()).ok_or(fmt::Error)?;
        let len = u8::try_from(end).map_err(|_| fmt::Error)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = len;
        Ok(())
    }
}

impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.as_bytes().escape_ascii())
    }
}
