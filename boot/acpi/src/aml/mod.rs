//! A small, bounded AML interpreter: enough of the ACPI namespace to say where a PCI
//! function's interrupt pin arrives.
//!
//! On a PC with an I/O APIC, which global system interrupt a PCI pin drives is written only
//! in the DSDT's namespace, as AML: a `_PRT` under each host bridge and bridge, whose
//! entries name either the interrupt itself or a PCI interrupt link device whose `_CRS`
//! does (ACPI 6.5 §6.2.13, §6.2.2). This module loads DSDTs and SSDTs into a namespace
//! and evaluates what that question needs; [`Interpreter::route_pin`] asks it.
//!
//! # What is implemented
//!
//! - **Loading**: `Scope`, `Device`, `Processor`, `PowerResource`, `ThermalZone`, `Name`, `Method`,
//!   `OperationRegion` (with constant offset and length), `Field`, `IndexField` and `BankField`
//!   (their names only), `Mutex`, `Event`, `Alias`, `External`, `DataRegion`.
//! - **Data**: integers (32-bit in a revision 1 table, 64-bit from revision 2), strings, buffers,
//!   packages and variable packages, and names in packages as references.
//! - **Execution**: method invocation with arguments and locals; `If`/`Else`, `While`, `Break`,
//!   `Continue`, `Return`; `Store`; integer arithmetic, shifts, bitwise and logical operators and
//!   comparisons; `Index` (also as a store target), `DerefOf`, `SizeOf`; `Create*Field` over
//!   buffers; `Name` inside a method; `Notify`, `Acquire` and `Release` as no-ops, since nothing
//!   here runs concurrently.
//! - **Fields** over `SystemMemory`, `SystemIO` and `PCI_Config` regions, read and written through
//!   [`Host`], honouring access width and update rule.
//!
//! Everything else is an error naming the table and the byte offset: an opcode the
//! interpreter does not know is [`Error::UnknownOpcode`], one it knows but does not implement
//! is [`Error::Unsupported`]. Neither panics.
//!
//! # Bounded
//!
//! AML is firmware's code, run with the kernel's authority on the boot path, and it can loop.
//! Every evaluation has a step budget ([`Interpreter::set_budget`]), and expression nesting
//! and call depth are capped, so a method that never returns is [`Error::Budget`] rather than
//! a hang. There is no allocator: the namespace, package cells and buffer bytes live in
//! storage the caller provides ([`Storage`]), bump-allocated and never freed, and running out
//! is [`Error::NoNodes`] or [`Error::NoMemory`]. Objects a method creates are dropped when it
//! returns; the heap is not, so what an evaluation returns stays readable.

mod eval;
mod load;
mod resource;
mod route;
#[cfg(test)]
mod tests;

use load::{Code, NameString};
pub use resource::{Interrupt, interrupt_template, nth_interrupt};
pub use route::{Route, eisa_id};

use crate::Sdt;

/// One segment of a name: four characters, padded with `_`.
pub type NameSeg = [u8; 4];

/// A node in the namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId(u16);

impl NodeId {
    /// The root, `\`.
    pub const ROOT: NodeId = NodeId(0);

    fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// Tables one interpreter loads: the DSDT and its SSDTs.
pub const MAX_TABLES: usize = 16;

/// The default number of steps one evaluation may take. QEMU's `_PRT` and link methods take
/// under two thousand; a firmware loop that has not finished in this many has not got
/// stuck on a slow device, it has got stuck.
pub const DEFAULT_BUDGET: u32 = 100_000;

/// Why loading or evaluating failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An opcode the interpreter does not know, at `offset` into loaded table `table`.
    UnknownOpcode {
        table: u8,
        offset: u32,
        opcode: u16,
    },
    /// A construct the interpreter recognises and does not implement.
    Unsupported {
        table: u8,
        offset: u32,
    },
    /// An encoding that runs past its table or the object enclosing it.
    Truncated {
        table: u8,
        offset: u32,
    },
    /// A second object with a name already taken in its scope.
    AlreadyExists {
        table: u8,
        offset: u32,
    },
    /// A name that resolves to nothing.
    NotFound,
    /// An operation applied to an object it does not apply to, or a method given the wrong
    /// number of arguments.
    WrongType,
    /// An index past the end of a package, buffer, field or region.
    BadIndex,
    DivideByZero,
    /// No room left for another namespace node.
    NoNodes,
    /// No room left for package cells or buffer bytes.
    NoMemory,
    /// More than [`MAX_TABLES`] tables loaded.
    TooManyTables,
    /// A table that is not a DSDT or SSDT.
    NotAml,
    /// The evaluation took more steps than its budget.
    Budget,
    /// Expressions nested, or methods called, deeper than the interpreter allows.
    TooDeep,
    /// The host refused a field access.
    Host,
    /// A resource template that is malformed, or holds no interrupt where one was needed.
    BadResource,
    /// No `_PRT` entry routes the pin asked about.
    NoRoute,
}

/// An AML object, as evaluation produces it. `Copy`: what it holds beyond a scalar is a
/// reference into a loaded table or into the interpreter's storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Object {
    Uninitialized,
    Integer(u64),
    String(Bytes),
    Buffer(Bytes),
    Package(Package),
    /// A namespace node: a name in a package, such as a `_PRT` entry's link device, or a
    /// device evaluated as a value.
    Reference(NodeId),
}

/// Where a string's or buffer's bytes are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bytes {
    /// In a loaded table, which is immutable. Strings only.
    Table { table: u8, start: u32, len: u32 },
    /// In the interpreter's byte storage. Every buffer, since buffers can be written.
    Heap { start: u32, len: u32 },
}

/// Where a package's elements are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Package {
    /// A package literal in a table, its elements decoded as they are read, with names in it
    /// resolved from `scope`. Copied into cells the first time an element is stored into.
    Table { table: u8, at: u32, scope: NodeId },
    /// Cells in the interpreter's storage.
    Heap { start: u32, len: u32 },
}

/// A namespace node.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    parent: u16,
    name: NameSeg,
    table: u8,
    kind: Kind,
    value: Object,
}

impl Node {
    pub const EMPTY: Node = Node {
        parent: 0,
        name: *b"____",
        table: 0,
        kind: Kind::Scope,
        value: Object::Uninitialized,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Scope,
    Device,
    Processor,
    PowerResource,
    ThermalZone,
    /// A `Name` whose data object has not been evaluated yet: it is at `at` in the node's table.
    Name {
        at: u32,
    },
    /// A named object whose value is the node's `value`.
    Value,
    Method {
        at: u32,
        end: u32,
        flags: u8,
    },
    Region {
        space: u8,
        offset: u64,
        len: u64,
    },
    Field {
        region: u16,
        bit_offset: u32,
        bit_width: u32,
        flags: u8,
    },
    /// A field of an `IndexField` or `BankField`: named, and not readable here.
    OtherField,
    /// A field of the buffer in the node's `value`.
    BufferField {
        bit_offset: u64,
        bit_width: u32,
    },
    Mutex,
    Event,
    DataRegion,
    Alias {
        target: u16,
    },
}

/// The operation region spaces fields are read and written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Space {
    Memory,
    Io,
    /// The configuration space of one function; the address is the register offset.
    PciConfig {
        bus: u8,
        device: u8,
        function: u8,
    },
}

/// What the interpreter reaches the machine through. A field access is `bits` wide: 8, 16,
/// 32 or 64. `None` refuses it, and the evaluation fails with [`Error::Host`].
pub trait Host {
    fn read(&mut self, space: Space, address: u64, bits: u8) -> Option<u64>;
    fn write(&mut self, space: Space, address: u64, bits: u8, value: u64) -> Option<()>;
}

/// The memory an interpreter works in. Nodes hold the namespace; cells hold package elements;
/// bytes hold buffers.
pub struct Storage<'s> {
    pub nodes: &'s mut [Node],
    pub cells: &'s mut [Object],
    pub bytes: &'s mut [u8],
}

/// The scopes every namespace has before a table is loaded (ACPI 6.5 §5.3.1).
const PREDEFINED: [NameSeg; 5] = [*b"_GPE", *b"_PR_", *b"_SB_", *b"_SI_", *b"_TZ_"];

/// A loaded namespace and the machinery to evaluate it.
pub struct Interpreter<'t, 's, H: Host> {
    /// Each loaded table's bytes, and whether its integers are 64-bit.
    tables: [(&'t [u8], bool); MAX_TABLES],
    n_tables: usize,
    nodes: &'s mut [Node],
    n_nodes: usize,
    cells: &'s mut [Object],
    n_cells: usize,
    bytes: &'s mut [u8],
    n_bytes: usize,
    host: H,
    limit: u32,
    budget: u32,
    nest: u16,
    calls: u8,
}

impl<'t, 's, H: Host> Interpreter<'t, 's, H> {
    /// An empty namespace: the root and the predefined scopes.
    pub fn new(storage: Storage<'s>, host: H) -> Result<Interpreter<'t, 's, H>, Error> {
        let mut i = Interpreter {
            tables: [(&[], true); MAX_TABLES],
            n_tables: 0,
            nodes: storage.nodes,
            n_nodes: 0,
            cells: storage.cells,
            n_cells: 0,
            bytes: storage.bytes,
            n_bytes: 0,
            host,
            limit: DEFAULT_BUDGET,
            budget: DEFAULT_BUDGET,
            nest: 0,
            calls: 0,
        };
        i.push(Node {
            name: *b"\\___",
            ..Node::EMPTY
        })?;
        for name in PREDEFINED {
            i.push(Node {
                name,
                ..Node::EMPTY
            })?;
        }
        Ok(i)
    }

    /// Steps each later evaluation may take.
    pub fn set_budget(&mut self, steps: u32) {
        self.limit = steps;
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Nodes in the namespace, the root included.
    pub fn node_count(&self) -> usize {
        self.n_nodes
    }

    /// Every node, in the order it was created.
    pub fn all_nodes(&self) -> impl Iterator<Item = NodeId> + '_ {
        (0..self.n_nodes).filter_map(|i| u16::try_from(i).ok().map(NodeId))
    }

    /// The node at an absolute path such as `\_SB.PCI0._PRT`. Short segments are padded with
    /// `_`, as ASL pads them.
    pub fn find(&self, path: &str) -> Option<NodeId> {
        let path = path.strip_prefix('\\').unwrap_or(path);
        if path.is_empty() {
            return Some(NodeId::ROOT);
        }
        path.split('.').try_fold(NodeId::ROOT, |node, segment| {
            let bytes = segment.as_bytes();
            if bytes.is_empty() || bytes.len() > 4 {
                return None;
            }
            let mut seg = *b"____";
            seg[..bytes.len()].copy_from_slice(bytes);
            self.child(node, &seg)
        })
    }

    /// The child of `parent` named `name`.
    pub fn child(&self, parent: NodeId, name: &NameSeg) -> Option<NodeId> {
        // Newest first, so a method's own objects are found before anything older.
        (1..self.n_nodes)
            .rev()
            .find(|&i| {
                let n = &self.nodes[i];
                usize::from(n.parent) == parent.index() && &n.name == name
            })
            .and_then(|i| u16::try_from(i).ok().map(NodeId))
    }

    /// The children of `parent`.
    pub fn children(&self, parent: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        (1..self.n_nodes)
            .filter(move |&i| usize::from(self.nodes[i].parent) == parent.index())
            .filter_map(|i| u16::try_from(i).ok().map(NodeId))
    }

    pub fn name(&self, node: NodeId) -> NameSeg {
        self.nodes.get(node.index()).map_or(*b"____", |n| n.name)
    }

    /// The scope `node` is in. `None` for the root.
    pub fn parent(&self, node: NodeId) -> Option<NodeId> {
        if node == NodeId::ROOT {
            return None;
        }
        self.nodes.get(node.index()).map(|n| NodeId(n.parent))
    }

    /// The argument count of `node`, if it is a method.
    pub fn method_args(&self, node: NodeId) -> Option<usize> {
        match self.nodes.get(node.index())?.kind {
            Kind::Method { flags, .. } => Some(usize::from(flags & 7)),
            _ => None,
        }
    }

    pub fn is_device(&self, node: NodeId) -> bool {
        self.nodes
            .get(node.index())
            .is_some_and(|n| n.kind == Kind::Device)
    }

    fn kind(&self, node: NodeId) -> Result<Kind, Error> {
        self.nodes
            .get(node.index())
            .filter(|_| node.index() < self.n_nodes)
            .map(|n| n.kind)
            .ok_or(Error::NotFound)
    }

    fn push(&mut self, node: Node) -> Result<NodeId, Error> {
        let id = u16::try_from(self.n_nodes).map_err(|_| Error::NoNodes)?;
        let slot = self.nodes.get_mut(self.n_nodes).ok_or(Error::NoNodes)?;
        *slot = node;
        self.n_nodes += 1;
        Ok(NodeId(id))
    }

    /// Resolve `name` as written in `scope`: an absolute or parent-prefixed name, or a path
    /// of several segments, from where it says; a single segment by searching `scope` and
    /// then each enclosing scope up to the root (ACPI 6.5 §5.3).
    fn resolve(&self, scope: NodeId, name: &NameString) -> Option<NodeId> {
        let mut base = if name.root { NodeId::ROOT } else { scope };
        for _ in 0..name.parents {
            base = self.parent(base)?;
        }
        let segs = name.segs.get(..usize::from(name.len))?;
        let found = if name.root || name.parents > 0 || segs.len() != 1 {
            segs.iter().try_fold(base, |n, s| self.child(n, s))?
        } else {
            let mut s = base;
            loop {
                if let Some(n) = self.child(s, &segs[0]) {
                    break n;
                }
                s = self.parent(s)?;
            }
        };
        Some(match self.nodes[found.index()].kind {
            Kind::Alias { target } => NodeId(target),
            _ => found,
        })
    }

    /// Create the object `name` declares in `scope`. The last segment is the new name; the
    /// ones before it must already exist.
    fn create(
        &mut self,
        code: Code<'t>,
        at: usize,
        scope: NodeId,
        name: &NameString,
        kind: Kind,
        value: Object,
    ) -> Result<NodeId, Error> {
        let len = usize::from(name.len);
        let (last, path) = name.segs[..len].split_last().ok_or(Error::NotFound)?;
        let mut parent = if name.root { NodeId::ROOT } else { scope };
        for _ in 0..name.parents {
            parent = self.parent(parent).ok_or(Error::NotFound)?;
        }
        for seg in path {
            parent = self.child(parent, seg).ok_or(Error::NotFound)?;
        }
        if self.child(parent, last).is_some() {
            return Err(Error::AlreadyExists {
                table: code.table,
                offset: at as u32,
            });
        }
        self.push(Node {
            parent: parent.0,
            name: *last,
            table: code.table,
            kind,
            value,
        })
    }

    fn alloc_bytes(&mut self, len: usize) -> Result<Bytes, Error> {
        let start = self.n_bytes;
        let end = start.checked_add(len).ok_or(Error::NoMemory)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(Error::NoMemory)?
            .fill(0);
        self.n_bytes = end;
        Ok(Bytes::Heap {
            start: u32::try_from(start).map_err(|_| Error::NoMemory)?,
            len: u32::try_from(len).map_err(|_| Error::NoMemory)?,
        })
    }

    fn alloc_cells(&mut self, len: usize) -> Result<(usize, u32), Error> {
        let start = self.n_cells;
        let end = start.checked_add(len).ok_or(Error::NoMemory)?;
        self.cells
            .get_mut(start..end)
            .ok_or(Error::NoMemory)?
            .fill(Object::Uninitialized);
        self.n_cells = end;
        Ok((start, u32::try_from(len).map_err(|_| Error::NoMemory)?))
    }

    /// A buffer holding `bytes`, to pass as a method argument.
    pub fn new_buffer(&mut self, bytes: &[u8]) -> Result<Object, Error> {
        let heap = self.alloc_bytes(bytes.len())?;
        if let Bytes::Heap { start, .. } = heap {
            let start = start as usize;
            self.bytes[start..start + bytes.len()].copy_from_slice(bytes);
        }
        Ok(Object::Buffer(heap))
    }

    /// The bytes of a string or buffer.
    pub fn buffer(&self, object: Object) -> Result<&[u8], Error> {
        let bytes = match object {
            Object::String(b) | Object::Buffer(b) => b,
            _ => return Err(Error::WrongType),
        };
        match bytes {
            Bytes::Table { table, start, len } => {
                let (t, _) = self.tables.get(usize::from(table)).ok_or(Error::NotFound)?;
                t.get(start as usize..(start as usize).saturating_add(len as usize))
            }
            Bytes::Heap { start, len } => self
                .bytes
                .get(start as usize..(start as usize).saturating_add(len as usize)),
        }
        .ok_or(Error::BadIndex)
    }

    /// An object as an integer, converting a buffer (its first eight bytes, little-endian)
    /// or a string (hexadecimal) as AML's implicit conversion does.
    pub fn integer(&self, object: Object) -> Result<u64, Error> {
        match object {
            Object::Integer(v) => Ok(v),
            Object::Buffer(_) => {
                let b = self.buffer(object)?;
                Ok(b.iter()
                    .take(8)
                    .enumerate()
                    .fold(0, |v, (i, &x)| v | (u64::from(x) << (8 * i))))
            }
            Object::String(_) => {
                let s = self.buffer(object)?;
                let s = s
                    .strip_prefix(b"0x")
                    .or_else(|| s.strip_prefix(b"0X"))
                    .unwrap_or(s);
                let mut v = 0u64;
                for &c in s.iter().take(16) {
                    let digit = match c {
                        b'0'..=b'9' => c - b'0',
                        b'a'..=b'f' => c - b'a' + 10,
                        b'A'..=b'F' => c - b'A' + 10,
                        _ => break,
                    };
                    v = (v << 4) | u64::from(digit);
                }
                Ok(v)
            }
            _ => Err(Error::WrongType),
        }
    }
}
