//! Nodes: what every enumerator produces and every driver reads.
//!
//! A [`DeviceTree`] is built once from a validated [`fdt::Fdt`] into storage the caller
//! provides, and is read-only from then on. Nothing is copied out of the blob: a node
//! holds slices of the properties a driver can ask about, and the questions — which
//! addresses, which interrupts, which controller — are answered on demand from those
//! slices, with every cell count checked.
//!
//! It is a separate representation rather than a thin wrapper over `boot/fdt`'s token
//! stream because the device tree is only one of the enumerators. A driver binds to a
//! node and claims its resources, and should not learn which firmware described the
//! node.
//!
//! # Nodes from somewhere other than a device tree
//!
//! PCI enumeration and firmware tables such as ACPI's MADT produce nodes too, through
//! [`Builder`]. Such a node's [`Origin`] borrows the record that describes it, a
//! [`crate::pci::Function`] or a [`crate::table::Described`], and its name and
//! `compatible` list are that record's. Its register windows are CPU physical addresses
//! the enumerator already read: a BAR, a MADT address. So [`DeviceTree::mmio`] returns
//! them without the `ranges` walk, which only means something for a device tree.
//! Everything else is the same. Binding goes by `compatible`, claims go through the
//! same ledger, and a parent precedes its children, so a function behind a PCI bridge is
//! the bridge node's child.
//!
//! A record a firmware table or the platform declares may carry one interrupt line and a
//! range of I/O ports. [`DeviceTree::interrupt`] returns that line as a one-cell specifier
//! whose controller is the root, and [`DeviceTree::ports`] the range. A PCI function's
//! interrupts are still not modelled: its pin is in its record, but turning a pin into a
//! controller input needs the ACPI `_PRT` or an `interrupt-map`, and `interrupt` reports
//! no entry rather than guess.
//!
//! # Cell counts
//!
//! `#address-cells` and `#size-cells` describe a node's *children*, and are read from
//! the parent when interpreting a child's `reg` (Devicetree Specification v0.4, §2.3.5).
//! They are **not inherited**: the specification says so in as many words, and a
//! parent that omits them has the defaults of two and one, whatever its own parent
//! said. Linux's `of_n_addr_cells` walks upwards instead, a legacy behaviour it warns
//! about; a tree that only works under that walk is malformed, and this reads it the
//! way the specification does.
//!
//! `interrupt-parent` **is** inherited (§2.4.1): a node without one uses its nearest
//! ancestor's. That is the other half of "correct defaults and inheritance", and the
//! two are easy to confuse.
//!
//! # Addresses
//!
//! A `reg` address is on the parent's bus. It becomes a CPU physical address by walking
//! up through each ancestor's `ranges` (§2.3.8): an empty `ranges` is an identity
//! mapping, a `ranges` that does not cover the address means the region is not visible
//! to the CPU, and a missing `ranges` means the bus is not memory-mapped at all — a
//! `/cpus` node's `reg` is a CPU number, not an address, and asking for it as one is an
//! error rather than an MMIO window at physical zero.

use fdt::{Fdt, Token};

use crate::pci::Function;
use crate::table::Described;

/// The deepest nesting a tree may have. `boot/fdt` enforces the same limit while
/// validating, so a tree it accepted always fits.
pub const MAX_DEPTH: usize = fdt::MAX_DEPTH;

/// The widest cell count interpreted as a number: 64 bits. Wider values are accepted
/// only when their high cells are zero.
const MAX_CELLS: u32 = 4;

/// Defaults for a node that does not declare its children's cell counts (§2.3.5).
const DEFAULT_ADDRESS_CELLS: u32 = 2;
const DEFAULT_SIZE_CELLS: u32 = 1;

/// A node's index in its [`DeviceTree`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct NodeId(u16);

impl NodeId {
    /// The root is always the first node.
    pub const ROOT: NodeId = NodeId(0);

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A property that must be exactly one cell.
///
/// A malformed one keeps the offset of its token, so the question that needed it can
/// report where rather than guess a value — and only that question fails: a bad
/// `#interrupt-cells` does not make a node's `reg` unreadable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cell {
    Absent,
    Value(u32),
    Malformed { offset: usize },
}

impl Cell {
    fn read(value: &[u8], offset: usize) -> Cell {
        match value {
            [a, b, c, d] => Cell::Value(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Cell::Malformed { offset },
        }
    }

    /// The value, `None` when absent.
    fn get(self) -> Result<Option<u32>, Error> {
        match self {
            Cell::Absent => Ok(None),
            Cell::Value(v) => Ok(Some(v)),
            Cell::Malformed { offset } => Err(Error::BadCellProperty { offset }),
        }
    }
}

/// One node, as the properties a driver can ask about.
///
/// Holds slices of the blob and indices into the tree; no interpretation happens until
/// something asks. The blob-relative `offset` is carried so that an error about a node
/// names the byte a human can find with `fdtdump`.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a> {
    name: &'a [u8],
    parent: Option<NodeId>,
    offset: usize,
    compatible: &'a [u8],
    reg: Option<&'a [u8]>,
    ranges: Option<&'a [u8]>,
    interrupts: Option<&'a [u8]>,
    status: Option<&'a [u8]>,
    stdout_path: Option<&'a [u8]>,
    clocks: Option<&'a [u8]>,
    clock_frequency: Option<&'a [u8]>,
    interrupt_parent: Cell,
    phandle: Cell,
    address_cells: Cell,
    size_cells: Cell,
    interrupt_cells: Cell,
    clock_cells: Cell,
    interrupt_controller: bool,
    interrupt_map: bool,
    origin: Origin<'a>,
}

/// Which enumerator produced a node, and the record it borrows when that was not a
/// device tree.
#[derive(Clone, Copy, Debug)]
pub enum Origin<'a> {
    /// A device-tree node: every property the model reads is a slice of the blob.
    DeviceTree,
    /// A function PCI enumeration found.
    Pci(&'a Function),
    /// A device a firmware table describes.
    Table(&'a Described),
}

impl<'a> Node<'a> {
    /// An unused slot, for sizing the caller's storage.
    pub const EMPTY: Node<'static> = Node {
        name: &[],
        parent: None,
        offset: 0,
        compatible: &[],
        reg: None,
        ranges: None,
        interrupts: None,
        status: None,
        stdout_path: None,
        clocks: None,
        clock_frequency: None,
        interrupt_parent: Cell::Absent,
        phandle: Cell::Absent,
        address_cells: Cell::Absent,
        size_cells: Cell::Absent,
        interrupt_cells: Cell::Absent,
        clock_cells: Cell::Absent,
        interrupt_controller: false,
        interrupt_map: false,
        origin: Origin::DeviceTree,
    };

    /// Which enumerator produced this node.
    pub fn origin(&self) -> Origin<'a> {
        self.origin
    }

    /// The node name, unit address included: `pl011@9000000`. Empty for the root.
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    pub fn parent(&self) -> Option<NodeId> {
        self.parent
    }

    /// Where the node begins in the blob.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The node's `phandle`, when it has a well-formed one.
    pub fn phandle(&self) -> Option<u32> {
        self.phandle.get().ok().flatten()
    }

    pub fn is_interrupt_controller(&self) -> bool {
        self.interrupt_controller
    }

    /// The `compatible` strings, most specific first (§2.3.1).
    pub fn compatible(&self) -> Strings<'a> {
        Strings {
            rest: self.compatible,
        }
    }

    /// Whether any `compatible` entry is exactly `what`.
    pub fn is_compatible(&self, what: &str) -> bool {
        self.compatible().any(|s| s == what.as_bytes())
    }

    /// `status` absent, `"okay"` or `"ok"` (§2.3.4). Anything else — `"disabled"`,
    /// `"fail"`, a malformed value — is not available, and a driver is not bound to it.
    pub fn is_available(&self) -> bool {
        match self.status {
            None => true,
            Some(v) => matches!(one_string(v), Some(b"okay") | Some(b"ok")),
        }
    }

    /// The `clock-frequency` of a fixed clock, in hertz, when it is one or two cells.
    pub fn clock_frequency(&self) -> Option<u64> {
        let v = self.clock_frequency?;
        if v.len() != 4 && v.len() != 8 {
            return None;
        }
        cells_value(v).ok()
    }

    fn record(&mut self, name: &[u8], value: &'a [u8], offset: usize) {
        let cell = Cell::read(value, offset);
        match name {
            b"compatible" => self.compatible = value,
            b"reg" => self.reg = Some(value),
            b"ranges" => self.ranges = Some(value),
            b"interrupts" => self.interrupts = Some(value),
            b"status" => self.status = Some(value),
            b"stdout-path" => self.stdout_path = Some(value),
            b"clocks" => self.clocks = Some(value),
            b"clock-frequency" => self.clock_frequency = Some(value),
            b"interrupt-controller" => self.interrupt_controller = true,
            b"interrupt-map" => self.interrupt_map = true,
            b"phandle" | b"linux,phandle" => self.phandle = cell,
            b"interrupt-parent" => self.interrupt_parent = cell,
            b"#address-cells" => self.address_cells = cell,
            b"#size-cells" => self.size_cells = cell,
            b"#interrupt-cells" => self.interrupt_cells = cell,
            b"#clock-cells" => self.clock_cells = cell,
            _ => {}
        }
    }
}

/// Iterator over a NUL-separated string list.
#[derive(Clone, Copy)]
pub struct Strings<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Strings<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        // Each pass consumes at least one byte or ends the walk. An unterminated final
        // entry is still returned: `compatible` is written by firmware, and dropping the
        // most general entry of a list because its NUL is missing would unbind a device
        // for a formatting slip.
        while !self.rest.is_empty() {
            let len = self
                .rest
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(self.rest.len());
            let (s, tail) = self.rest.split_at(len);
            self.rest = tail.get(1..).unwrap_or(&[]);
            if !s.is_empty() {
                return Some(s);
            }
        }
        None
    }
}

/// Why a question about the tree could not be answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The blob itself is malformed; `boot/fdt` says where.
    Fdt(fdt::Error),
    /// More nodes than the caller's storage holds.
    TooManyNodes { capacity: usize },
    /// A cell-count, phandle or interrupt-parent property that is not exactly one cell,
    /// or a controller with no `#interrupt-cells` at all.
    BadCellProperty { offset: usize },
    /// A cell count too wide to interpret, or zero where zero means nothing.
    UnsupportedCells { node: NodeId, cells: u32 },
    /// A `reg`, `ranges` or `interrupts` whose length is not a whole number of entries.
    BadLength {
        node: NodeId,
        len: usize,
        entry: usize,
    },
    /// A value that needs more than 64 bits.
    ValueTooWide { node: NodeId },
    /// No entry at this index.
    NoSuchEntry { node: NodeId, index: usize },
    /// An ancestor bus has no `ranges`, so its children's addresses are not CPU addresses.
    NotMemoryMapped { node: NodeId, bus: NodeId },
    /// An ancestor's `ranges` does not cover the address.
    Untranslatable {
        node: NodeId,
        bus: NodeId,
        address: u64,
    },
    /// A region whose end does not fit in 64 bits.
    RegionOverflow { node: NodeId },
    /// No interrupt parent anywhere up the tree.
    NoInterruptParent { node: NodeId },
    /// A phandle that names no node.
    NoSuchPhandle { node: NodeId, phandle: u32 },
    /// The interrupt parent is a nexus (`interrupt-map`), which is not interpreted yet.
    InterruptNexus { node: NodeId, nexus: NodeId },
    /// The interrupt parent does not say it is an interrupt controller.
    NotAnInterruptController { node: NodeId, parent: NodeId },
    /// A [`Builder`] was asked to add a node under one it has not added.
    UnknownParent { parent: NodeId },
}

impl From<fdt::Error> for Error {
    fn from(e: fdt::Error) -> Error {
        Error::Fdt(e)
    }
}

/// A device tree's nodes, built once and read thereafter.
///
/// Called a tree whichever enumerator filled it: it is the machine's device hierarchy,
/// and a flattened device tree is one way of being told it.
pub struct DeviceTree<'a, 's> {
    /// The blob, when the nodes came from one. Only aliases need it.
    fdt: Option<Fdt<'a>>,
    nodes: &'s [Node<'a>],
}

/// Builds a tree from enumerators other than a device tree: PCI, firmware tables.
///
/// Nodes are added parent first, as [`DeviceTree::build`] stores them, so every question
/// that walks up the tree works the same on the result.
pub struct Builder<'a, 's> {
    nodes: &'s mut [Node<'a>],
    len: usize,
}

impl<'a, 's> Builder<'a, 's> {
    /// Start a tree in `storage`, with an empty root.
    ///
    /// # Errors
    /// [`Error::TooManyNodes`] when `storage` cannot hold even the root.
    pub fn new(storage: &'s mut [Node<'a>]) -> Result<Builder<'a, 's>, Error> {
        let capacity = storage.len();
        let root = storage
            .first_mut()
            .ok_or(Error::TooManyNodes { capacity })?;
        *root = Node::EMPTY;
        Ok(Builder {
            nodes: storage,
            len: 1,
        })
    }

    /// Add a node under `parent`. `name` and `compatible` are usually the record's own.
    ///
    /// # Errors
    /// [`Error::UnknownParent`] for a parent this builder has not added, and
    /// [`Error::TooManyNodes`] when the storage is full.
    pub fn add(
        &mut self,
        parent: NodeId,
        name: &'a [u8],
        compatible: &'a [u8],
        origin: Origin<'a>,
    ) -> Result<NodeId, Error> {
        if parent.index() >= self.len {
            return Err(Error::UnknownParent { parent });
        }
        let capacity = self.nodes.len().min(usize::from(u16::MAX));
        let index = u16::try_from(self.len)
            .ok()
            .filter(|&i| usize::from(i) < capacity)
            .ok_or(Error::TooManyNodes { capacity })?;
        let slot = self
            .nodes
            .get_mut(self.len)
            .ok_or(Error::TooManyNodes { capacity })?;
        *slot = Node {
            name,
            parent: Some(parent),
            compatible,
            origin,
            ..Node::EMPTY
        };
        self.len += 1;
        Ok(NodeId(index))
    }

    /// How many nodes have been added, the root included.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn finish(self) -> DeviceTree<'a, 's> {
        let nodes: &'s [Node<'a>] = self.nodes;
        DeviceTree {
            fdt: None,
            nodes: nodes.get(..self.len).unwrap_or(&[]),
        }
    }
}

impl<'a, 's> DeviceTree<'a, 's> {
    /// Build the nodes of `fdt` into `storage`.
    ///
    /// Nodes are stored in tree order, so a parent always precedes its children and the
    /// root is [`NodeId::ROOT`]. Every property the model reads is recorded; nothing is
    /// interpreted, so a malformed `reg` on a device nobody binds is not a reason to
    /// refuse the machine.
    ///
    /// # Errors
    /// [`Error::TooManyNodes`] when `storage` is too small, and any error the token walk
    /// reports — though a tree `Fdt::new` accepted has none.
    pub fn build(fdt: &Fdt<'a>, storage: &'s mut [Node<'a>]) -> Result<DeviceTree<'a, 's>, Error> {
        let capacity = storage.len().min(usize::from(u16::MAX));
        let mut n = 0usize;
        // The open node at each depth: `open[d - 1]` for depth `d`.
        let mut open = [NodeId::ROOT; MAX_DEPTH];

        for token in fdt.tokens() {
            match token? {
                Token::BeginNode {
                    name,
                    depth,
                    offset,
                } => {
                    let (Some(slot), Ok(index)) = (storage.get_mut(n), u16::try_from(n)) else {
                        return Err(Error::TooManyNodes { capacity });
                    };
                    if n >= capacity {
                        return Err(Error::TooManyNodes { capacity });
                    }
                    let id = NodeId(index);
                    let parent = depth.checked_sub(2).and_then(|i| open.get(i)).copied();
                    if let Some(open_slot) = depth.checked_sub(1).and_then(|i| open.get_mut(i)) {
                        *open_slot = id;
                    }
                    *slot = Node {
                        name,
                        parent,
                        offset,
                        ..Node::EMPTY
                    };
                    n += 1;
                }
                Token::Property {
                    name,
                    value,
                    depth,
                    offset,
                } => {
                    let owner = depth.checked_sub(1).and_then(|i| open.get(i)).copied();
                    if let Some(node) = owner.and_then(|id| storage.get_mut(id.index())) {
                        node.record(name, value, offset);
                    }
                }
                Token::EndNode { .. } => {}
            }
        }

        let nodes = storage.get(..n).unwrap_or(&[]);
        Ok(DeviceTree {
            fdt: Some(*fdt),
            nodes,
        })
    }

    /// Every node, in tree order.
    pub fn ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        // `build` stored at most `u16::MAX` nodes, so every index converts.
        (0..self.nodes.len()).filter_map(|i| u16::try_from(i).ok().map(NodeId))
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The node `id` names. Ids come from this tree, so this cannot miss for one of its
    /// own; an id from another tree gets an empty node rather than a wild read.
    pub fn node(&self, id: NodeId) -> &Node<'a> {
        self.nodes.get(id.index()).unwrap_or(&Node::EMPTY)
    }

    /// The children of `id`, in tree order.
    pub fn children(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.ids().filter(move |&c| self.node(c).parent == Some(id))
    }

    /// The node whose `phandle` is `phandle`.
    pub fn by_phandle(&self, phandle: u32) -> Option<NodeId> {
        self.ids()
            .find(|&id| self.node(id).phandle == Cell::Value(phandle))
    }

    /// The node at an absolute path such as `/pl011@9000000`, or an alias name.
    ///
    /// A path component without a unit address matches a node whose name is that
    /// component followed by `@`, as §2.2.3 allows when it is unambiguous; the first such
    /// node is taken.
    pub fn find(&self, path: &[u8]) -> Option<NodeId> {
        if path.first() != Some(&b'/') {
            return self.alias(path);
        }
        let mut at = NodeId::ROOT;
        for component in path.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            at = self.children(at).find(|&c| {
                let name = self.node(c).name;
                name == component
                    || (name.starts_with(component) && name.get(component.len()) == Some(&b'@'))
            })?;
        }
        Some(at)
    }

    /// Resolve an alias through the properties of `/aliases` (§3.3).
    ///
    /// Aliases are the one kind of property the nodes do not record — their names are the
    /// data — so this walks the blob's tokens for them. It is rare, and bounded by the
    /// structure block, which is already known to be well-formed.
    fn alias(&self, name: &[u8]) -> Option<NodeId> {
        let mut in_aliases = false;
        for token in self.fdt.as_ref()?.tokens() {
            match token.ok()? {
                Token::BeginNode { name: n, depth, .. } => {
                    in_aliases = depth == 2 && n == b"aliases";
                }
                Token::Property {
                    name: n,
                    value,
                    depth,
                    ..
                } if in_aliases && depth == 2 && n == name => {
                    let path = one_string(value)?;
                    // An alias must hold a full path, which is what stops this recursing.
                    return (path.first() == Some(&b'/'))
                        .then(|| self.find(path))
                        .flatten();
                }
                Token::EndNode { depth, .. } if depth == 2 => in_aliases = false,
                _ => {}
            }
        }
        None
    }

    /// The console the firmware chose: `/chosen`'s `stdout-path`, options after `:`
    /// removed (§3.6). Either a path or an alias.
    pub fn stdout(&self) -> Option<NodeId> {
        let chosen = self.find(b"/chosen")?;
        let value = one_string(self.node(chosen).stdout_path?)?;
        let path = value.split(|&b| b == b':').next()?;
        self.find(path)
    }

    /// `#address-cells` for `id`'s children: its own, or the default. Never inherited.
    fn address_cells(&self, id: NodeId) -> Result<u32, Error> {
        Ok(self
            .node(id)
            .address_cells
            .get()?
            .unwrap_or(DEFAULT_ADDRESS_CELLS))
    }

    /// `#size-cells` for `id`'s children: its own, or the default. Never inherited.
    fn size_cells(&self, id: NodeId) -> Result<u32, Error> {
        Ok(self
            .node(id)
            .size_cells
            .get()?
            .unwrap_or(DEFAULT_SIZE_CELLS))
    }

    /// The `reg` entries of `id` as raw bus values, with the entry width.
    fn reg_entries(&self, id: NodeId) -> Result<(&'a [u8], u32, usize), Error> {
        let none = Error::NoSuchEntry { node: id, index: 0 };
        let bus = self.node(id).parent.ok_or(none)?;
        let reg = self.node(id).reg.ok_or(none)?;
        let ac = self.address_cells(bus)?;
        let sc = self.size_cells(bus)?;
        let entry = entry_bytes(id, &[ac, sc])?;
        if reg.len() % entry != 0 {
            return Err(Error::BadLength {
                node: id,
                len: reg.len(),
                entry,
            });
        }
        Ok((reg, ac, entry))
    }

    /// How many register windows `id` has: `reg` entries for a device-tree node, assigned
    /// memory BARs for a PCI function, the record's windows for a described device. Zero
    /// when it has none or they cannot be read.
    pub fn mmio_count(&self, id: NodeId) -> usize {
        match self.node(id).origin {
            Origin::DeviceTree => self
                .reg_entries(id)
                .map(|(reg, _, entry)| reg.len() / entry)
                .unwrap_or(0),
            Origin::Pci(f) => (0..6).take_while(|&i| f.memory_bar(i).is_some()).count(),
            Origin::Table(d) => d.windows().len(),
        }
    }

    /// The `index`th register window of `id`, as a CPU physical `(address, length)`.
    ///
    /// For a device-tree node that is its `index`th `reg` entry, translated up through
    /// the ancestors' `ranges`. For a PCI function it is the `index`th memory BAR that
    /// firmware assigned, I/O BARs not counted; for a described device, its record's
    /// `index`th window.
    ///
    /// # Errors
    /// Whatever makes the entry uninterpretable or invisible to the CPU; see [`Error`].
    pub fn mmio(&self, id: NodeId, index: usize) -> Result<(u64, u64), Error> {
        let window = match self.node(id).origin {
            Origin::DeviceTree => None,
            Origin::Pci(f) => Some(f.memory_bar(index)),
            Origin::Table(d) => Some(d.windows().get(index).copied()),
        };
        if let Some(window) = window {
            let (phys, len) = window.ok_or(Error::NoSuchEntry { node: id, index })?;
            if phys.checked_add(len).is_none() {
                return Err(Error::RegionOverflow { node: id });
            }
            return Ok((phys, len));
        }
        let (reg, ac, entry) = self.reg_entries(id)?;
        let raw = reg
            .chunks_exact(entry)
            .nth(index)
            .ok_or(Error::NoSuchEntry { node: id, index })?;
        let (addr, size) = raw
            .split_at_checked(cell_bytes(ac))
            .ok_or(Error::NoSuchEntry { node: id, index })?;
        let too_wide = |()| Error::ValueTooWide { node: id };
        let address = cells_value(addr).map_err(too_wide)?;
        let len = cells_value(size).map_err(too_wide)?;
        let bus = self
            .node(id)
            .parent
            .ok_or(Error::NoSuchEntry { node: id, index })?;
        let phys = self.translate(id, bus, address)?;
        if phys.checked_add(len).is_none() {
            return Err(Error::RegionOverflow { node: id });
        }
        Ok((phys, len))
    }

    /// Translate `address` on the bus `bus` (the parent of `node`) up to the CPU.
    ///
    /// Bounded by the depth of the tree: each step moves to a parent, and parents precede
    /// children.
    fn translate(&self, node: NodeId, mut bus: NodeId, mut address: u64) -> Result<u64, Error> {
        while let Some(grandparent) = self.node(bus).parent {
            let ranges = self
                .node(bus)
                .ranges
                .ok_or(Error::NotMemoryMapped { node, bus })?;
            if !ranges.is_empty() {
                address = self.through_ranges(node, bus, grandparent, ranges, address)?;
            }
            bus = grandparent;
        }
        Ok(address)
    }

    /// Map `address` through one non-empty `ranges` of `bus`.
    fn through_ranges(
        &self,
        node: NodeId,
        bus: NodeId,
        grandparent: NodeId,
        ranges: &[u8],
        address: u64,
    ) -> Result<u64, Error> {
        let child = self.address_cells(bus)?;
        let parent = self.address_cells(grandparent)?;
        let size = self.size_cells(bus)?;
        let entry = entry_bytes(bus, &[child, parent, size])?;
        if ranges.len() % entry != 0 {
            return Err(Error::BadLength {
                node: bus,
                len: ranges.len(),
                entry,
            });
        }
        let too_wide = |()| Error::ValueTooWide { node: bus };
        for e in ranges.chunks_exact(entry) {
            let malformed = Error::BadLength {
                node: bus,
                len: ranges.len(),
                entry,
            };
            let (c, rest) = e.split_at_checked(cell_bytes(child)).ok_or(malformed)?;
            let (p, s) = rest.split_at_checked(cell_bytes(parent)).ok_or(malformed)?;
            let c = cells_value(c).map_err(too_wide)?;
            let p = cells_value(p).map_err(too_wide)?;
            let s = cells_value(s).map_err(too_wide)?;
            if let Some(off) = address.checked_sub(c).filter(|&off| off < s) {
                return off
                    .checked_add(p)
                    .ok_or(Error::RegionOverflow { node: bus });
            }
        }
        Err(Error::Untranslatable { node, bus, address })
    }

    /// The interrupt parent of `id`: its own `interrupt-parent`, or its nearest
    /// ancestor's (§2.4.1).
    ///
    /// # Errors
    /// [`Error::NoInterruptParent`] if none is declared up to the root,
    /// [`Error::NoSuchPhandle`] if the declared one names nothing, and
    /// [`Error::InterruptNexus`] or [`Error::NotAnInterruptController`] if it names a node
    /// that cannot take an interrupt specifier directly.
    pub fn interrupt_parent(&self, id: NodeId) -> Result<NodeId, Error> {
        let mut at = Some(id);
        // Bounded: each step moves to a parent, and parents precede children.
        while let Some(n) = at {
            let node = self.node(n);
            if let Some(phandle) = node.interrupt_parent.get()? {
                let parent = self
                    .by_phandle(phandle)
                    .ok_or(Error::NoSuchPhandle { node: id, phandle })?;
                let p = self.node(parent);
                if p.interrupt_map {
                    return Err(Error::InterruptNexus {
                        node: id,
                        nexus: parent,
                    });
                }
                if !p.interrupt_controller {
                    return Err(Error::NotAnInterruptController { node: id, parent });
                }
                return Ok(parent);
            }
            at = node.parent;
        }
        Err(Error::NoInterruptParent { node: id })
    }

    /// How many `interrupts` entries `id` has. Zero when it has none or they cannot be
    /// read.
    pub fn interrupt_count(&self, id: NodeId) -> usize {
        let Some(raw) = self.node(id).interrupts else {
            return 0;
        };
        match self.interrupt_cells_of(id) {
            Ok((_, cells)) if raw.len() % (cells as usize * 4) == 0 => {
                raw.len() / (cells as usize * 4)
            }
            _ => 0,
        }
    }

    /// The controller of `id`'s interrupts and its `#interrupt-cells`.
    fn interrupt_cells_of(&self, id: NodeId) -> Result<(NodeId, u32), Error> {
        let controller = self.interrupt_parent(id)?;
        // Required on a controller (§2.4.2.2); there is no default to fall back on.
        let cells = self
            .node(controller)
            .interrupt_cells
            .get()?
            .ok_or(Error::BadCellProperty {
                offset: self.node(controller).offset,
            })?;
        if cells == 0 || cells as usize > Specifier::MAX_CELLS {
            return Err(Error::UnsupportedCells {
                node: controller,
                cells,
            });
        }
        Ok((controller, cells))
    }

    /// The `index`th range of I/O ports of `id`, as `(base, length)`.
    ///
    /// Only a device a firmware table or the platform describes has ports: a device-tree
    /// node's `reg` is memory on every binding this model reads. The platform's own
    /// controller is what gives the range meaning, exactly as for a window.
    pub fn ports(&self, id: NodeId, index: usize) -> Result<(u16, u16), Error> {
        let ports = match self.node(id).origin {
            Origin::Table(d) if index == 0 => d.ports(),
            _ => None,
        };
        ports.ok_or(Error::NoSuchEntry { node: id, index })
    }

    /// The `index`th interrupt of `id`: its controller, and the specifier cells whose
    /// meaning that controller defines.
    ///
    /// A device a firmware table describes carries the line itself rather than cells to
    /// interpret, so its specifier is that one number, and its controller is the root:
    /// the platform has exactly one, and no table names it as a node.
    pub fn interrupt(&self, id: NodeId, index: usize) -> Result<Specifier, Error> {
        // A PCI function's interrupt, as firmware routed it: the line it programmed into the
        // function's interrupt-line register, as one cell. Meaningful only on the controller
        // firmware routed for, which this model cannot know — the platform decides whether
        // it trusts the line (an 8259A machine does, since that is the controller firmware
        // routed for; one with an I/O APIC does not, since PCI interrupts reach it elsewhere).
        // A function with no pin, or a line firmware left unassigned, has no interrupt.
        if let Origin::Pci(f) = self.node(id).origin {
            let line = u32::from(f.interrupt_line);
            if index != 0 || f.interrupt_pin == 0 || !(1..=15).contains(&line) {
                return Err(Error::NoSuchEntry { node: id, index });
            }
            return Specifier::new(NodeId::ROOT, &[line])
                .ok_or(Error::NoSuchEntry { node: id, index });
        }
        if let Origin::Table(d) = self.node(id).origin {
            let line = d
                .interrupt()
                .filter(|_| index == 0)
                .ok_or(Error::NoSuchEntry { node: id, index })?;
            return Specifier::new(NodeId::ROOT, &[line])
                .ok_or(Error::NoSuchEntry { node: id, index });
        }
        let raw = self
            .node(id)
            .interrupts
            .ok_or(Error::NoSuchEntry { node: id, index })?;
        let (controller, cells) = self.interrupt_cells_of(id)?;
        let entry = cells as usize * 4;
        if raw.len() % entry != 0 {
            return Err(Error::BadLength {
                node: id,
                len: raw.len(),
                entry,
            });
        }
        let chunk = raw
            .chunks_exact(entry)
            .nth(index)
            .ok_or(Error::NoSuchEntry { node: id, index })?;
        let mut spec = Specifier {
            controller,
            cells: [0; Specifier::MAX_CELLS],
            len: cells as u8,
        };
        for (slot, c) in spec.cells.iter_mut().zip(chunk.chunks_exact(4)) {
            if let Ok(bytes) = <[u8; 4]>::try_from(c) {
                *slot = u32::from_be_bytes(bytes);
            }
        }
        Ok(spec)
    }

    /// The provider the `index`th entry of `id`'s `clocks` names.
    ///
    /// Each entry is a phandle followed by as many cells as that provider's
    /// `#clock-cells` says, so entries can differ in width and the walk has to read every
    /// provider on the way. `None` when an entry cannot be read.
    pub fn clock(&self, id: NodeId, index: usize) -> Option<NodeId> {
        let mut rest = self.node(id).clocks?;
        let mut i = 0;
        // Bounded: every pass consumes at least the four-byte phandle.
        while let Some((phandle, tail)) = rest.split_first_chunk::<4>() {
            let provider = self.by_phandle(u32::from_be_bytes(*phandle))?;
            if i == index {
                return Some(provider);
            }
            let skip = cell_bytes(self.node(provider).clock_cells.get().ok()??);
            rest = tail.get(skip..)?;
            i += 1;
        }
        None
    }

    /// Any property of `id`, by name, as its raw bytes.
    ///
    /// For the properties the model does not record, because only one consumer asks: a CPU
    /// node's `enable-method`, the PSCI node's `method`. Walks the blob's tokens from the
    /// node's own `BeginNode`, which is bounded by the node's properties, since a node's
    /// properties precede its children (§5.4.1).
    pub fn property(&self, id: NodeId, name: &[u8]) -> Option<&'a [u8]> {
        let begin = self.node(id).offset;
        // `None` for a tree built from firmware tables rather than a blob, which has no
        // properties beyond what its nodes record.
        let mut tokens = self.fdt.as_ref()?.tokens();
        let _ = tokens
            .find(|t| matches!(t, Ok(Token::BeginNode { offset, .. }) if *offset == begin))?;
        for token in tokens {
            match token.ok()? {
                Token::Property { name: n, value, .. } if n == name => return Some(value),
                Token::Property { .. } => {}
                _ => return None,
            }
        }
        None
    }

    /// A property of `id` holding exactly one string, without its terminating NUL.
    pub fn string(&self, id: NodeId, name: &[u8]) -> Option<&'a [u8]> {
        one_string(self.property(id, name)?)
    }

    /// The `index`th `reg` address of `id` exactly as written, on its parent's bus and not
    /// translated.
    ///
    /// For buses whose `reg` is an identifier rather than a location, where [`Self::mmio`]
    /// rightly refuses: under `/cpus`, a CPU's `reg` is its hardware ID, an MPIDR affinity
    /// value on Arm (Devicetree Specification §3.8).
    pub fn reg_address(&self, id: NodeId, index: usize) -> Result<u64, Error> {
        let (reg, ac, entry) = self.reg_entries(id)?;
        let raw = reg
            .chunks_exact(entry)
            .nth(index)
            .ok_or(Error::NoSuchEntry { node: id, index })?;
        let addr = raw
            .get(..cell_bytes(ac))
            .ok_or(Error::NoSuchEntry { node: id, index })?;
        cells_value(addr).map_err(|()| Error::ValueTooWide { node: id })
    }
}

/// An interrupt as its controller describes it: the controller and its cells.
///
/// The model does not know what the cells mean — for a GIC they are type, number and
/// flags, for a PLIC one source number — so turning a specifier into an interrupt line
/// is the controller driver's job.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Specifier {
    pub controller: NodeId,
    cells: [u32; Specifier::MAX_CELLS],
    len: u8,
}

impl Specifier {
    /// The widest `#interrupt-cells` interpreted. Four covers every controller binding in
    /// mainline Linux except a handful of nexus-like cascades.
    pub const MAX_CELLS: usize = 4;

    /// A specifier built by hand, for a controller's own tests.
    pub fn new(controller: NodeId, cells: &[u32]) -> Option<Specifier> {
        let mut s = Specifier {
            controller,
            cells: [0; Specifier::MAX_CELLS],
            len: u8::try_from(cells.len()).ok()?,
        };
        s.cells.get_mut(..cells.len())?.copy_from_slice(cells);
        Some(s)
    }

    pub fn cells(&self) -> &[u32] {
        self.cells.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// A property holding exactly one string: the bytes before its single terminating NUL.
fn one_string(value: &[u8]) -> Option<&[u8]> {
    let s = value.strip_suffix(&[0])?;
    (!s.contains(&0)).then_some(s)
}

/// Bytes in `cells` cells. Every count reaching here was checked against [`MAX_CELLS`]
/// or came from a `u32` property small enough to have been.
fn cell_bytes(cells: u32) -> usize {
    (cells as usize).saturating_mul(4)
}

/// Bytes in one entry made of these cell counts, refusing counts too wide to read.
fn entry_bytes(node: NodeId, counts: &[u32]) -> Result<usize, Error> {
    let mut total = 0usize;
    for &cells in counts {
        if cells > MAX_CELLS {
            return Err(Error::UnsupportedCells { node, cells });
        }
        total += cell_bytes(cells);
    }
    if total == 0 {
        // A zero-width entry would let a property of any length hold infinitely many.
        return Err(Error::UnsupportedCells { node, cells: 0 });
    }
    Ok(total)
}

/// A big-endian multi-cell value as a `u64`, refusing one whose high cells are set.
fn cells_value(bytes: &[u8]) -> Result<u64, ()> {
    let mut value = 0u64;
    for cell in bytes.chunks_exact(4) {
        let bytes = <[u8; 4]>::try_from(cell).map_err(|_| ())?;
        if value >> 32 != 0 {
            return Err(());
        }
        value = (value << 32) | u64::from(u32::from_be_bytes(bytes));
    }
    Ok(value)
}
