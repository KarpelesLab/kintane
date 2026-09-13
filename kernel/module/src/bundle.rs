//! The module bundle: several modules in one blob, the way a loader hands them over.
//!
//! kbuild writes it (`kbuild/src/modules.rs`, `bundle_bytes`): `KTBUNDL1`, the entry count
//! and total length as little-endian `u32`s, one 48-byte entry per module (a NUL-padded
//! 40-byte name, then the module's offset from the start of the bundle and its length),
//! then the modules. Read here like any other input from outside the kernel: every entry
//! is checked against the bundle before a module is handed out.

const MAGIC: &[u8; 8] = b"KTBUNDL1";
const HEADER: usize = 16;
const NAME_LEN: usize = 40;
const ENTRY: usize = NAME_LEN + 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BundleError {
    /// Not a bundle, or shorter than its header says.
    NotABundle,
    /// Entry `index` points outside the bundle, or has a name that is not UTF-8.
    BadEntry { index: usize },
}

#[derive(Clone, Copy, Debug)]
pub struct Bundle<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> Bundle<'a> {
    /// Check the header and every entry. `bytes` may be longer than the bundle, as a boot
    /// module rounded up to a page is.
    pub fn parse(bytes: &'a [u8]) -> Result<Bundle<'a>, BundleError> {
        if bytes.get(..8) != Some(MAGIC) {
            return Err(BundleError::NotABundle);
        }
        let u32_at = |at: usize| {
            bytes
                .get(at..at + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap_or([0; 4])) as usize)
        };
        let count = u32_at(8).ok_or(BundleError::NotABundle)?;
        let total = u32_at(12).ok_or(BundleError::NotABundle)?;
        let table_end = count
            .checked_mul(ENTRY)
            .and_then(|t| t.checked_add(HEADER))
            .ok_or(BundleError::NotABundle)?;
        if total > bytes.len() || table_end > total {
            return Err(BundleError::NotABundle);
        }
        let bundle = Bundle {
            bytes: &bytes[..total],
            count,
        };
        for i in 0..count {
            bundle.entry(i)?;
        }
        Ok(bundle)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Module `index`: its name and bytes.
    pub fn entry(&self, index: usize) -> Result<(&'a str, &'a [u8]), BundleError> {
        let bad = BundleError::BadEntry { index };
        if index >= self.count {
            return Err(bad);
        }
        let e = &self.bytes[HEADER + index * ENTRY..HEADER + (index + 1) * ENTRY];
        let name = &e[..NAME_LEN];
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(NAME_LEN)];
        let name = core::str::from_utf8(name).map_err(|_| bad)?;
        let offset = u32::from_le_bytes(e[40..44].try_into().map_err(|_| bad)?) as usize;
        let len = u32::from_le_bytes(e[44..48].try_into().map_err(|_| bad)?) as usize;
        let table_end = HEADER + self.count * ENTRY;
        if offset < table_end {
            return Err(bad);
        }
        let module = self
            .bytes
            .get(offset..offset.checked_add(len).ok_or(bad)?)
            .ok_or(bad)?;
        Ok((name, module))
    }

    /// The module named `name`.
    pub fn get(&self, name: &str) -> Option<&'a [u8]> {
        (0..self.count)
            .filter_map(|i| self.entry(i).ok())
            .find(|(n, _)| *n == name)
            .map(|(_, b)| b)
    }
}
