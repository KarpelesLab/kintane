//! Decoding AML's encodings, and loading a table's declarations into the namespace.
//!
//! Loading walks the table's term list and records every named object with where its
//! definition is. Nothing is evaluated: a `Name`'s data object is read the first time it is
//! used, and a method's body when it is called. Only an operation region's offset and length
//! are read here, and they must be constants.

use super::*;
use crate::HEADER_LEN;

/// Segments in one name string. Real names have three or four.
pub(super) const MAX_SEGS: usize = 8;

/// How deeply `Scope` and `Device` may nest in a table.
const MAX_SCOPE_DEPTH: usize = 32;

/// A table's bytes, with its index for errors.
#[derive(Clone, Copy)]
pub(super) struct Code<'t> {
    pub bytes: &'t [u8],
    pub table: u8,
}

/// A decoded NameString (ACPI 6.5 §20.2.2).
#[derive(Clone, Copy, Debug)]
pub(super) struct NameString {
    pub root: bool,
    pub parents: u8,
    pub segs: [NameSeg; MAX_SEGS],
    pub len: u8,
}

impl NameString {
    pub fn single(seg: NameSeg) -> NameString {
        let mut segs = [[0; 4]; MAX_SEGS];
        segs[0] = seg;
        NameString {
            root: false,
            parents: 0,
            segs,
            len: 1,
        }
    }
}

/// Whether `b` can begin a name string.
pub(super) fn is_name_lead(b: u8) -> bool {
    matches!(b, b'\\' | b'^' | b'_' | b'A'..=b'Z' | 0x2e | 0x2f)
}

impl<'t> Code<'t> {
    pub fn truncated(&self, at: usize) -> Error {
        Error::Truncated {
            table: self.table,
            offset: at as u32,
        }
    }

    pub fn unsupported(&self, at: usize) -> Error {
        Error::Unsupported {
            table: self.table,
            offset: at as u32,
        }
    }

    pub fn unknown(&self, at: usize, opcode: u16) -> Error {
        Error::UnknownOpcode {
            table: self.table,
            offset: at as u32,
            opcode,
        }
    }

    pub fn byte(&self, at: usize) -> Result<u8, Error> {
        self.bytes.get(at).copied().ok_or(self.truncated(at))
    }

    pub fn slice(&self, at: usize, len: usize) -> Result<&'t [u8], Error> {
        at.checked_add(len)
            .and_then(|end| self.bytes.get(at..end))
            .ok_or(self.truncated(at))
    }

    /// A PkgLength at `at`: its value, and how many bytes it took.
    pub fn pkg_length(&self, at: usize) -> Result<(usize, usize), Error> {
        let lead = self.byte(at)?;
        let follow = usize::from(lead >> 6);
        if follow == 0 {
            return Ok((usize::from(lead & 0x3f), 1));
        }
        let mut v = usize::from(lead & 0x0f);
        for k in 0..follow {
            v |= usize::from(self.byte(at + 1 + k)?) << (4 + 8 * k);
        }
        Ok((v, 1 + follow))
    }

    /// The end of an object whose PkgLength is at `at`, which must not pass `limit`, and
    /// where its contents begin.
    pub fn pkg_end(&self, at: usize, limit: usize) -> Result<(usize, usize), Error> {
        let (len, n) = self.pkg_length(at)?;
        let end = at.checked_add(len).ok_or(self.truncated(at))?;
        if len < n || end > limit.min(self.bytes.len()) {
            return Err(self.truncated(at));
        }
        Ok((end, at + n))
    }

    pub fn name_seg(&self, at: usize) -> Result<NameSeg, Error> {
        let s = self.slice(at, 4)?;
        let lead = matches!(s[0], b'A'..=b'Z' | b'_');
        let rest = s[1..]
            .iter()
            .all(|c| matches!(c, b'A'..=b'Z' | b'0'..=b'9' | b'_'));
        if !(lead && rest) {
            return Err(self.unsupported(at));
        }
        Ok([s[0], s[1], s[2], s[3]])
    }

    /// A NameString at `at`, and where it ends.
    pub fn name_string(&self, at: usize) -> Result<(NameString, usize), Error> {
        let mut p = at;
        let mut name = NameString {
            root: false,
            parents: 0,
            segs: [[0; 4]; MAX_SEGS],
            len: 0,
        };
        if self.byte(p)? == b'\\' {
            name.root = true;
            p += 1;
        } else {
            while self.byte(p)? == b'^' {
                name.parents = name.parents.checked_add(1).ok_or(self.unsupported(at))?;
                p += 1;
            }
        }
        let count = match self.byte(p)? {
            0x00 => {
                return Ok((name, p + 1));
            }
            0x2e => {
                p += 1;
                2
            }
            0x2f => {
                let count = usize::from(self.byte(p + 1)?);
                p += 2;
                count
            }
            _ => 1,
        };
        if count > MAX_SEGS {
            return Err(self.unsupported(at));
        }
        for k in 0..count {
            name.segs[k] = self.name_seg(p + 4 * k)?;
        }
        name.len = count as u8;
        Ok((name, p + 4 * count))
    }

    /// A constant integer at `at`, and where it ends, or `None` if there is none there.
    /// `ones` is what `OnesOp` means in this table.
    pub fn integer_const(&self, at: usize, ones: u64) -> Result<Option<(u64, usize)>, Error> {
        let le = |len: usize| -> Result<u64, Error> {
            let b = self.slice(at + 1, len)?;
            Ok(b.iter()
                .enumerate()
                .fold(0, |v, (i, &x)| v | (u64::from(x) << (8 * i))))
        };
        Ok(Some(match self.byte(at)? {
            0x00 => (0, at + 1),
            0x01 => (1, at + 1),
            0xff => (ones, at + 1),
            0x0a => (le(1)?, at + 2),
            0x0b => (le(2)?, at + 3),
            0x0c => (le(4)?, at + 5),
            0x0e => (le(8)?, at + 9),
            _ => return Ok(None),
        }))
    }

    /// Where the data object at `at` ends: a constant, string, buffer, package, revision or
    /// name reference.
    pub fn skip_data(&self, at: usize, limit: usize) -> Result<usize, Error> {
        if let Some((_, next)) = self.integer_const(at, u64::MAX)? {
            return Ok(next);
        }
        match self.byte(at)? {
            0x0d => {
                let rest = self
                    .bytes
                    .get(at + 1..limit.min(self.bytes.len()))
                    .ok_or(self.truncated(at))?;
                let nul = rest
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(self.truncated(at))?;
                Ok(at + 1 + nul + 1)
            }
            0x11..=0x13 => Ok(self.pkg_end(at + 1, limit)?.0),
            0x5b if self.byte(at + 1)? == 0x30 => Ok(at + 2),
            b if is_name_lead(b) => Ok(self.name_string(at)?.1),
            _ => Err(self.unsupported(at)),
        }
    }

    fn constant(&self, at: usize) -> Result<(u64, usize), Error> {
        self.integer_const(at, u64::MAX)?
            .ok_or(self.unsupported(at))
    }
}

/// What a field list's names are fields of.
#[derive(Clone, Copy)]
enum FieldOf {
    Region(NodeId),
    Other,
}

impl<'t, 's, H: Host> Interpreter<'t, 's, H> {
    /// Load a DSDT or SSDT: record every object it declares.
    ///
    /// A table that fails to load adds nothing to the namespace.
    pub fn load(&mut self, table: Sdt<'t>) -> Result<(), Error> {
        if !matches!(&table.signature(), b"DSDT" | b"SSDT") {
            return Err(Error::NotAml);
        }
        if self.n_tables == MAX_TABLES {
            return Err(Error::TooManyTables);
        }
        let bytes = table.bytes();
        let code = Code {
            bytes,
            table: self.n_tables as u8,
        };
        // Integers are 32 bits in a table of revision 1 and below (ACPI 6.5 §5.2.11.1).
        self.tables[self.n_tables] = (bytes, table.revision() >= 2);
        self.n_tables += 1;
        let mark = self.n_nodes;
        let loaded = self.load_terms(code, HEADER_LEN, bytes.len(), NodeId::ROOT, 0);
        if loaded.is_err() {
            self.n_nodes = mark;
            self.n_tables -= 1;
        }
        loaded
    }

    fn load_terms(
        &mut self,
        code: Code<'t>,
        mut at: usize,
        end: usize,
        scope: NodeId,
        depth: usize,
    ) -> Result<(), Error> {
        if depth > MAX_SCOPE_DEPTH {
            return Err(Error::TooDeep);
        }
        let nothing = Object::Uninitialized;
        while at < end {
            let next = match code.byte(at)? {
                // Scope
                0x10 => {
                    let (body_end, p) = code.pkg_end(at + 1, end)?;
                    let (name, p) = code.name_string(p)?;
                    let node = self.resolve(scope, &name).ok_or(Error::NotFound)?;
                    self.load_terms(code, p, body_end, node, depth + 1)?;
                    body_end
                }
                // Name
                0x08 => {
                    let (name, p) = code.name_string(at + 1)?;
                    let next = code.skip_data(p, end)?;
                    let kind = Kind::Name { at: p as u32 };
                    self.create(code, at, scope, &name, kind, nothing)?;
                    next
                }
                // Method
                0x14 => {
                    let (body_end, p) = code.pkg_end(at + 1, end)?;
                    let (name, p) = code.name_string(p)?;
                    let flags = code.byte(p)?;
                    let kind = Kind::Method {
                        at: (p + 1) as u32,
                        end: body_end as u32,
                        flags,
                    };
                    self.create(code, at, scope, &name, kind, nothing)?;
                    body_end
                }
                // Alias
                0x06 => {
                    let (source, p) = code.name_string(at + 1)?;
                    let (alias, p) = code.name_string(p)?;
                    let target = self.resolve(scope, &source).ok_or(Error::NotFound)?;
                    let kind = Kind::Alias { target: target.0 };
                    self.create(code, at, scope, &alias, kind, nothing)?;
                    p
                }
                // External: a declaration for the compiler, nothing to record.
                0x15 => code.name_string(at + 1)?.1 + 2,
                0x5b => self.load_extended(code, at, end, scope, depth)?,
                // Executable code at table level is legal AML, and not run here.
                op @ (0x70..=0x9f | 0xa0..=0xa5) => {
                    let _ = op;
                    return Err(code.unsupported(at));
                }
                op => return Err(code.unknown(at, u16::from(op))),
            };
            if next > end {
                return Err(code.truncated(at));
            }
            at = next;
        }
        Ok(())
    }

    fn load_extended(
        &mut self,
        code: Code<'t>,
        at: usize,
        end: usize,
        scope: NodeId,
        depth: usize,
    ) -> Result<usize, Error> {
        let nothing = Object::Uninitialized;
        let ext = code.byte(at + 1)?;
        Ok(match ext {
            // Device, Processor, PowerResource, ThermalZone: a scope with a header.
            0x82..=0x85 => {
                let (body_end, p) = code.pkg_end(at + 2, end)?;
                let (name, p) = code.name_string(p)?;
                let (kind, skip) = match ext {
                    0x82 => (Kind::Device, 0),
                    0x83 => (Kind::Processor, 6),
                    0x84 => (Kind::PowerResource, 3),
                    _ => (Kind::ThermalZone, 0),
                };
                let node = self.create(code, at, scope, &name, kind, nothing)?;
                self.load_terms(code, p + skip, body_end, node, depth + 1)?;
                body_end
            }
            // OperationRegion
            0x80 => {
                let (name, p) = code.name_string(at + 2)?;
                let space = code.byte(p)?;
                let (offset, p) = code.constant(p + 1)?;
                let (len, p) = code.constant(p)?;
                let kind = Kind::Region { space, offset, len };
                self.create(code, at, scope, &name, kind, nothing)?;
                p
            }
            // Field
            0x81 => {
                let (body_end, p) = code.pkg_end(at + 2, end)?;
                let (region, p) = code.name_string(p)?;
                let region = self.resolve(scope, &region).ok_or(Error::NotFound)?;
                if !matches!(self.kind(region)?, Kind::Region { .. }) {
                    return Err(Error::WrongType);
                }
                let flags = code.byte(p)?;
                self.load_fields(code, p + 1, body_end, scope, flags, FieldOf::Region(region))?;
                body_end
            }
            // IndexField
            0x86 => {
                let (body_end, p) = code.pkg_end(at + 2, end)?;
                let (_, p) = code.name_string(p)?;
                let (_, p) = code.name_string(p)?;
                let flags = code.byte(p)?;
                self.load_fields(code, p + 1, body_end, scope, flags, FieldOf::Other)?;
                body_end
            }
            // BankField
            0x87 => {
                let (body_end, p) = code.pkg_end(at + 2, end)?;
                let (_, p) = code.name_string(p)?;
                let (_, p) = code.name_string(p)?;
                let (_, p) = code.constant(p)?;
                let flags = code.byte(p)?;
                self.load_fields(code, p + 1, body_end, scope, flags, FieldOf::Other)?;
                body_end
            }
            // Mutex
            0x01 => {
                let (name, p) = code.name_string(at + 2)?;
                self.create(code, at, scope, &name, Kind::Mutex, nothing)?;
                p + 1
            }
            // Event
            0x02 => {
                let (name, p) = code.name_string(at + 2)?;
                self.create(code, at, scope, &name, Kind::Event, nothing)?;
                p
            }
            // DataRegion
            0x88 => {
                let (name, p) = code.name_string(at + 2)?;
                let p = code.skip_data(p, end)?;
                let p = code.skip_data(p, end)?;
                let p = code.skip_data(p, end)?;
                self.create(code, at, scope, &name, Kind::DataRegion, nothing)?;
                p
            }
            _ => return Err(code.unknown(at, 0x5b00 | u16::from(ext))),
        })
    }

    /// A field list: named fields, reserved gaps and access changes (ACPI 6.5 §20.2.5.2).
    fn load_fields(
        &mut self,
        code: Code<'t>,
        mut at: usize,
        end: usize,
        scope: NodeId,
        mut flags: u8,
        of: FieldOf,
    ) -> Result<(), Error> {
        let mut bit: u32 = 0;
        while at < end {
            match code.byte(at)? {
                // ReservedField: a gap of so many bits.
                0x00 => {
                    let (bits, n) = code.pkg_length(at + 1)?;
                    bit = bit
                        .checked_add(u32::try_from(bits).map_err(|_| code.truncated(at))?)
                        .ok_or(code.truncated(at))?;
                    at += 1 + n;
                }
                // AccessField: a new access type for the fields after it.
                0x01 => {
                    flags = (flags & !0x0f) | (code.byte(at + 1)? & 0x0f);
                    at += 3;
                }
                // ExtendedAccessField.
                0x03 => {
                    flags = (flags & !0x0f) | (code.byte(at + 1)? & 0x0f);
                    at += 4;
                }
                // ConnectField: a GPIO or serial bus connection.
                0x02 => return Err(code.unsupported(at)),
                _ => {
                    let seg = code.name_seg(at)?;
                    let (bits, n) = code.pkg_length(at + 4)?;
                    let width = u32::try_from(bits).map_err(|_| code.truncated(at))?;
                    let kind = match of {
                        FieldOf::Region(region) => Kind::Field {
                            region: region.0,
                            bit_offset: bit,
                            bit_width: width,
                            flags,
                        },
                        FieldOf::Other => Kind::OtherField,
                    };
                    let name = NameString::single(seg);
                    self.create(code, at, scope, &name, kind, Object::Uninitialized)?;
                    bit = bit.checked_add(width).ok_or(code.truncated(at))?;
                    at += 4 + n;
                }
            }
        }
        if at != end {
            return Err(code.truncated(at));
        }
        Ok(())
    }
}
