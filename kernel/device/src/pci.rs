//! PCI and PCI Express enumeration.
//!
//! PCI is a bus the kernel discovers by asking it. Every function has a 256-byte (PCI)
//! or 4 KiB (PCI Express) configuration space. What changes between machines is how that
//! space is reached: through memory-mapped ECAM windows the MCFG table describes, or
//! through the two I/O ports of configuration mechanism #1 on a PC that predates them.
//! That difference is [`ConfigSpace`], implemented by the platform. Everything above it
//! is here, generic, and host-tested against a model bus:
//!
//! - [`enumerate`] walks buses from the segment's first, every device and, for multi-function
//!   devices, every function, and follows bridges to the buses behind them.
//! - Each function's identity is read: vendor, device, class, subsystem, interrupt pin and line.
//! - Each base address register is sized without being left disturbed.
//! - A [`Function`] records what was found, including a `compatible` list so the device model binds
//!   PCI drivers the same way it binds device-tree drivers.
//!
//! # `compatible` for a function
//!
//! A PCI function carries no strings, so they are made the way the Open Firmware PCI bus
//! binding (IEEE 1275, as Linux's `of_pci` reads it) makes them, most specific first:
//! `pciVVVV,DDDD`, then `pciclass,CCSSPP`, then `pciclass,CCSS`. A driver for one chip
//! lists the first form; a driver for every AHCI controller lists `pciclass,010601`.
//!
//! # Sizing a BAR without disturbing it
//!
//! A BAR's size is learned by writing all ones to it and reading back which bits stuck.
//! For that moment the device decodes at a nonsense address, so memory and I/O decoding
//! are turned off in the command register first and restored afterwards, along with the
//! BAR's original value. Host bridges are the exception, as they are in Linux: turning off
//! a host bridge's decoding can take the path to every other device with it.
//! [`Function::original_bars`] keeps the values read before sizing, and [`verify_restored`]
//! checks that configuration space still holds them. The kernel runs that check once
//! enumeration is done, because a BAR left at all ones works until a driver maps it.
//!
//! # Resource assignment
//!
//! BARs are read as firmware assigned them, and on a machine whose firmware did assign them
//! that is the whole story. Not every machine has firmware: QEMU's `virt` booted with
//! `-kernel` runs none, so every BAR is implemented, sizes correctly, and decodes nowhere —
//! a driver bound to such a function would map address zero. [`assign_memory_bars`] places
//! the registers that read zero, from an arena the caller takes out of the window its bridge
//! forwards, and leaves every register firmware did assign exactly as it was.
//!
//! # What is not here
//!
//! MSI, and hot-plug. I/O-space assignment: nothing on the ports this kernel runs on needs
//! a device behind an I/O BAR, and a window that is 64 KiB for a whole machine is worth
//! handing out only when something asks.
//!
//! # Capabilities
//!
//! A function may carry a linked list of capability structures, which is how it says what
//! it can do beyond the header: MSI-X, PCI Express, and — for virtio — where in its BARs
//! each of its register structures lives. [`capabilities`] walks that list. It reads
//! nothing unless the status register says the list exists, and the walk is bounded by the
//! number of structures configuration space could hold, so a device whose list loops is
//! read once rather than for ever.
//!
//! # Interrupt routing
//!
//! The interrupt pin is recorded here, and turning it into a system interrupt is the
//! platform's, because the answer is machine knowledge this crate does not have: the ACPI
//! `_PRT`, which is AML, or the device tree's `interrupt-map`. [`Function::interrupt_line`]
//! is what firmware routed, which is the answer on a machine whose interrupt controller is
//! the one firmware routed for. See `docs/architecture.md`.

use core::fmt;

use crate::text::Text;

/// Where a function is: bus, device and function number, within one segment.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Address {
    pub const fn new(bus: u8, device: u8, function: u8) -> Address {
        Address {
            bus,
            device,
            function,
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{:x}", self.bus, self.device, self.function)
    }
}

/// Access to configuration space.
///
/// Reads and writes are 32 bits wide at offsets that are multiples of four, which is the
/// one width every mechanism supports. Narrower fields are taken from the 32-bit value.
pub trait ConfigSpace {
    /// The 32-bit register at `offset` of `at`. A function that does not exist reads as
    /// all ones, as the hardware reports it.
    fn read(&self, at: Address, offset: u16) -> u32;

    fn write(&self, at: Address, offset: u16, value: u32);
}

/// Configuration space offsets (PCI Local Bus Specification 3.0, §6.1).
mod reg {
    pub const ID: u16 = 0x00;
    pub const COMMAND: u16 = 0x04;
    pub const CLASS: u16 = 0x08;
    pub const HEADER: u16 = 0x0c;
    pub const BAR0: u16 = 0x10;
    /// Type 1 header: primary, secondary and subordinate bus numbers.
    pub const BUS_NUMBERS: u16 = 0x18;
    /// Type 0 header: subsystem vendor and subsystem ID.
    pub const SUBSYSTEM: u16 = 0x2c;
    pub const INTERRUPT: u16 = 0x3c;
    /// Type 0 header: where the capability list begins, when the status says there is one.
    pub const CAPABILITY_POINTER: u16 = 0x34;

    pub const COMMAND_IO: u32 = 1 << 0;
    pub const COMMAND_MEMORY: u32 = 1 << 1;
    /// Status bit 4, in the upper half of the command register's word.
    pub const STATUS_CAPABILITIES: u32 = 1 << 20;
}

/// The class code of a host bridge, `06/00`.
pub const CLASS_HOST_BRIDGE: (u8, u8) = (0x06, 0x00);

/// What a base address register decodes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bar {
    /// Not implemented, or the upper half of the 64-bit BAR before it.
    None,
    Memory {
        base: u64,
        size: u64,
        prefetchable: bool,
        /// A 64-bit BAR, which also uses the next register.
        wide: bool,
    },
    Io {
        base: u32,
        size: u32,
    },
}

/// The bus numbers behind a bridge.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BusRange {
    pub secondary: u8,
    pub subordinate: u8,
}

/// One function, as enumeration found it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Function {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    /// The header layout: 0 for an endpoint, 1 for a PCI-to-PCI bridge, 2 for CardBus.
    pub header_type: u8,
    /// Zero for a bridge, which has no subsystem fields.
    pub subsystem_vendor: u16,
    pub subsystem: u16,
    /// 1 to 4 for INTA# to INTD#, 0 for none.
    pub interrupt_pin: u8,
    /// What firmware wrote into the line register. Advisory: meaningful only on the
    /// interrupt controller firmware routed it for.
    pub interrupt_line: u8,
    pub bars: [Bar; 6],
    /// The buses behind this function, when it is a bridge.
    pub bridge: Option<BusRange>,
    /// The index, in the same enumeration's output, of the bridge this function is
    /// behind. `None` on the segment's first bus.
    pub parent: Option<u16>,
    /// The command register and BARs as they read before sizing.
    original_command: u16,
    original_bars: [u32; 6],
    name: Text<8>,
    compatible: Text<48>,
    /// The function's capability list, as far as [`MAX_CAPABILITIES`].
    ///
    /// Read here, during enumeration, because this is where configuration space is
    /// reachable: a driver is handed the node its `Origin::Pci` borrows, and has no way
    /// back to the bus. A device that says where its registers are — which is how virtio
    /// describes itself — is therefore readable by the driver that binds to it.
    capabilities: [Capability; MAX_CAPABILITIES],
    capability_count: u8,
}

/// Capabilities recorded per function. Long enough for the handful a real device carries:
/// virtio's five, PCI Express, MSI-X and power management together are under a dozen.
pub const MAX_CAPABILITIES: usize = 12;

impl Function {
    /// An unused slot, for sizing the caller's storage.
    pub const EMPTY: Function = Function {
        address: Address::new(0, 0, 0),
        vendor: 0xffff,
        device: 0xffff,
        class: 0,
        subclass: 0,
        prog_if: 0,
        revision: 0,
        header_type: 0,
        subsystem_vendor: 0,
        subsystem: 0,
        interrupt_pin: 0,
        interrupt_line: 0,
        bars: [Bar::None; 6],
        bridge: None,
        parent: None,
        original_command: 0,
        original_bars: [0; 6],
        name: Text::EMPTY,
        compatible: Text::EMPTY,
        capabilities: [Capability::EMPTY; MAX_CAPABILITIES],
        capability_count: 0,
    };

    /// `bb:dd.f`.
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// The `compatible` list: see the module documentation.
    pub fn compatible(&self) -> &[u8] {
        self.compatible.as_bytes()
    }

    pub fn is_host_bridge(&self) -> bool {
        (self.class, self.subclass) == CLASS_HOST_BRIDGE
    }

    /// The BAR registers as they read before sizing.
    pub fn original_bars(&self) -> &[u32] {
        self.original_bars
            .get(..bar_count(self.header_type))
            .unwrap_or(&[])
    }

    /// The function's capability list, as enumeration read it.
    ///
    /// Empty when the function has none, or when it has more than [`MAX_CAPABILITIES`],
    /// in which case the first that many are here: a driver looking for its own reads
    /// what was recorded and finds nothing rather than reading a bus it cannot reach.
    pub fn capabilities(&self) -> &[Capability] {
        self.capabilities
            .get(..usize::from(self.capability_count))
            .unwrap_or(&[])
    }

    /// Base address register `number`, as a CPU physical `(base, size)`, if it decodes
    /// memory and firmware assigned it.
    ///
    /// By the register's own number, 0 to 5, which is how a device refers to its BARs:
    /// virtio's capabilities name one that way. That is *not* [`Self::memory_bar`]'s
    /// index, which counts only the memory BARs: a device whose BAR 0 decodes I/O — the
    /// transitional virtio layout — has its first memory BAR at a number greater than its
    /// index, and claiming by the wrong one maps another device's window.
    pub fn bar_by_number(&self, number: u8) -> Option<(u64, u64)> {
        match self.bars.get(usize::from(number))? {
            Bar::Memory { base, size, .. } if *base != 0 => Some((*base, *size)),
            _ => None,
        }
    }

    /// Which of [`Self::memory_bar`]'s indices BAR `number` is, so a claim made by index
    /// reaches the register the device named.
    pub fn memory_bar_index(&self, number: u8) -> Option<usize> {
        let upto = self.bars.get(..usize::from(number))?;
        self.bar_by_number(number)?;
        Some(
            upto.iter()
                .filter(|b| matches!(b, Bar::Memory { base, .. } if *base != 0))
                .count(),
        )
    }

    /// The `index`th memory BAR with an assigned base, as a CPU physical `(base, size)`.
    /// I/O BARs are not memory and are not counted.
    pub fn memory_bar(&self, index: usize) -> Option<(u64, u64)> {
        self.bars
            .iter()
            .filter_map(|b| match *b {
                Bar::Memory { base, size, .. } if base != 0 => Some((base, size)),
                _ => None,
            })
            .nth(index)
    }
}

/// Why enumeration stopped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// More functions than the caller's storage holds.
    TooManyFunctions { capacity: usize },
    /// A name or `compatible` list did not fit its buffer.
    Text,
}

/// Why [`verify_restored`] failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disturbed {
    Command {
        at: Address,
        was: u16,
        now: u16,
    },
    Bar {
        at: Address,
        index: usize,
        was: u32,
        now: u32,
    },
}

/// Why [`assign_memory_bars`] could not place a register.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unplaced {
    /// The arena ran out: `need` bytes, aligned to `align`, did not fit what was left.
    NoRoom {
        at: Address,
        index: usize,
        need: u64,
        left: u64,
    },
    /// A 64-bit register whose upper half would be non-zero cannot be placed from a
    /// 32-bit arena, and this assigns only from the bridge's 32-bit window.
    TooHigh { at: Address, index: usize },
}

/// Assign addresses to the memory BARs that have none, from `arena`.
///
/// This is the job firmware does on a machine that has any. QEMU's `virt` booted with
/// `-kernel` runs none, so every BAR reads back zero: the register is implemented, sizing
/// reports its width, and nothing has ever told the device where to decode. A driver bound
/// to such a function would map address zero.
///
/// Only registers reading zero are placed, so a machine whose firmware did assign them is
/// left exactly as it was — the assignment is a repair for the case where nobody did it,
/// not a policy this kernel imposes over one that exists.
///
/// Host bridges are skipped, as they are in [`size_bars`]: a bridge's own BARs are not
/// device registers to place, and touching its decoding can take the path to everything
/// behind it.
///
/// `arena` is CPU physical, must lie inside the window the bridge forwards, and must be
/// mapped by the caller's address space before any driver reads a register. Each register
/// is placed at its natural alignment, which is what the decoder requires: a BAR of size
/// `n` ignores the low `log2(n)` bits of the address written to it.
///
/// On success the function's recorded [`Bar`] and its `original_bars` both hold the
/// assigned value, so [`verify_restored`] called afterwards agrees with the hardware.
/// Memory decoding is left **off**: enabling it belongs to the driver that claims the
/// window, and a device decoding before anything owns it answers reads nobody expects.
pub fn assign_memory_bars(
    cfg: &impl ConfigSpace,
    functions: &mut [Function],
    arena_base: u64,
    arena_len: u64,
) -> Result<usize, Unplaced> {
    let mut cursor = arena_base;
    let end = arena_base.saturating_add(arena_len);
    let mut placed = 0;
    for f in functions.iter_mut() {
        if f.is_host_bridge() {
            continue;
        }
        let at = f.address;
        let count = bar_count(f.header_type);
        let mut i = 0;
        // Bounded: advances by one or two registers a pass, as `size_bars` does.
        while i < count {
            let (size, wide) = match f.bars.get(i) {
                Some(&Bar::Memory {
                    base, size, wide, ..
                }) if base == 0 && size != 0 => (size, wide),
                Some(&Bar::Memory { wide, .. }) => {
                    i += if wide { 2 } else { 1 };
                    continue;
                }
                _ => {
                    i += 1;
                    continue;
                }
            };
            // Natural alignment: the decoder ignores the low bits, so an address that is
            // not a multiple of the size decodes somewhere else.
            let aligned = cursor.next_multiple_of(size);
            if aligned.saturating_add(size) > end {
                return Err(Unplaced::NoRoom {
                    at,
                    index: i,
                    need: size,
                    left: end.saturating_sub(cursor),
                });
            }
            if !wide && aligned > u64::from(u32::MAX) {
                return Err(Unplaced::TooHigh { at, index: i });
            }
            let offset = reg::BAR0 + 4 * i as u16;
            let low_was = f.original_bars.get(i).copied().unwrap_or(0);
            // The low four bits are the register's type, not address, and are read-only.
            let low = (aligned as u32 & !0xf) | (low_was & 0xf);
            cfg.write(at, offset, low);
            if let Some(slot) = f.original_bars.get_mut(i) {
                *slot = low;
            }
            if wide {
                let high = (aligned >> 32) as u32;
                cfg.write(at, offset + 4, high);
                if let Some(slot) = f.original_bars.get_mut(i + 1) {
                    *slot = high;
                }
            }
            if let Some(Bar::Memory { base, .. }) = f.bars.get_mut(i) {
                *base = aligned;
            }
            cursor = aligned.saturating_add(size);
            placed += 1;
            i += if wide { 2 } else { 1 };
        }
    }
    Ok(placed)
}

/// How many BARs a header layout has.
fn bar_count(header_type: u8) -> usize {
    match header_type {
        0 => 6,
        1 => 2,
        _ => 0,
    }
}

/// Every function on buses `first..=last`, reached from `first` and through bridges,
/// written to `out`. Returns how many.
///
/// Buses are visited breadth first, so a bridge always precedes the functions behind it
/// and [`Function::parent`] always names an earlier entry. A bus is visited at most once,
/// whatever bridges claim, so misprogrammed bus numbers cannot loop the walk, and a
/// bridge whose secondary bus is outside `first..=last` is recorded but not followed.
///
/// # Errors
/// [`Error::TooManyFunctions`] when `out` fills: a partial enumeration is not a machine to
/// bind drivers against.
pub fn enumerate(
    cfg: &impl ConfigSpace,
    first: u8,
    last: u8,
    out: &mut [Function],
) -> Result<usize, Error> {
    let mut queue = BusQueue::new(first, last);
    queue.push(first, None);

    let mut n = 0usize;
    // Bounded: each bus is queued at most once, and there are 256.
    while let Some((bus, parent)) = queue.pop() {
        for device in 0..32 {
            let at = Address::new(bus, device, 0);
            if vendor(cfg, at) == 0xffff {
                continue;
            }
            let multifunction = cfg.read(at, reg::HEADER) >> 16 & 0x80 != 0;
            let functions = if multifunction { 8 } else { 1 };
            for function in 0..functions {
                let at = Address::new(bus, device, function);
                if vendor(cfg, at) == 0xffff {
                    continue;
                }
                let capacity = out.len();
                let slot = out.get_mut(n).ok_or(Error::TooManyFunctions { capacity })?;
                *slot = read_function(cfg, at, parent)?;
                if let Some(range) = slot.bridge {
                    queue.push(range.secondary, u16::try_from(n).ok());
                }
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Buses still to walk, each at most once.
struct BusQueue {
    first: u8,
    last: u8,
    visited: [u64; 4],
    entries: [(u8, Option<u16>); 256],
    head: usize,
    tail: usize,
}

impl BusQueue {
    fn new(first: u8, last: u8) -> BusQueue {
        BusQueue {
            first,
            last,
            visited: [0; 4],
            entries: [(0, None); 256],
            head: 0,
            tail: 0,
        }
    }

    /// Queue `bus`, reached through the function at index `parent`, unless it is outside
    /// the segment or has been queued before.
    fn push(&mut self, bus: u8, parent: Option<u16>) {
        if !(self.first..=self.last).contains(&bus) {
            return;
        }
        let (word, bit) = (usize::from(bus) / 64, u32::from(bus) % 64);
        let (Some(seen), Some(slot)) =
            (self.visited.get_mut(word), self.entries.get_mut(self.tail))
        else {
            return;
        };
        if *seen & (1 << bit) != 0 {
            return;
        }
        *seen |= 1 << bit;
        *slot = (bus, parent);
        self.tail += 1;
    }

    fn pop(&mut self) -> Option<(u8, Option<u16>)> {
        if self.head >= self.tail {
            return None;
        }
        let next = *self.entries.get(self.head)?;
        self.head += 1;
        Some(next)
    }
}

/// Check that configuration space still holds what enumeration read before sizing.
pub fn verify_restored(cfg: &impl ConfigSpace, functions: &[Function]) -> Result<(), Disturbed> {
    for f in functions {
        // Only the decode bits are compared: the rest of the command register is the
        // driver's, and nothing has been bound yet, but status-changing bits are not what
        // sizing touches.
        let decode = (reg::COMMAND_IO | reg::COMMAND_MEMORY) as u16;
        let now = cfg.read(f.address, reg::COMMAND) as u16;
        if now & decode != f.original_command & decode {
            return Err(Disturbed::Command {
                at: f.address,
                was: f.original_command,
                now,
            });
        }
        for (index, &was) in f.original_bars().iter().enumerate() {
            let now = cfg.read(f.address, reg::BAR0 + 4 * index as u16);
            if now != was {
                return Err(Disturbed::Bar {
                    at: f.address,
                    index,
                    was,
                    now,
                });
            }
        }
    }
    Ok(())
}

/// One capability in a function's list.
///
/// `words` is the structure itself, as far as [`CAPABILITY_WORDS`], so a driver can read
/// its own capability without reaching configuration space: enumeration is the only place
/// that has it. virtio's vendor capability is five words, which is what fixes the bound.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capability {
    /// 0x05 MSI, 0x09 vendor-specific, 0x10 PCI Express, 0x11 MSI-X.
    pub id: u8,
    /// Where the structure begins in configuration space.
    pub offset: u16,
    /// The structure's first words, the one holding `id` included.
    pub words: [u32; CAPABILITY_WORDS],
}

/// Words of each capability structure that are recorded. virtio's vendor capability is
/// five, MSI-X's is three.
pub const CAPABILITY_WORDS: usize = 6;

impl Capability {
    pub const EMPTY: Capability = Capability {
        id: 0,
        offset: 0,
        words: [0; CAPABILITY_WORDS],
    };

    /// The byte at `offset` bytes into the structure.
    pub fn byte(&self, offset: usize) -> u8 {
        (self.word(offset / 4) >> (8 * (offset % 4))) as u8
    }

    /// The `index`th word of the structure. Past what was recorded, zero.
    pub fn word(&self, index: usize) -> u32 {
        self.words.get(index).copied().unwrap_or(0)
    }
}

/// The vendor-specific capability ID, which is how virtio describes where its register
/// structures live.
pub const CAP_VENDOR: u8 = 0x09;

/// Every capability of `at`, in list order, written to `out`. Returns how many.
///
/// Nothing is read unless the status register says the list exists. The walk stops at the
/// end of the list, when `out` fills, or after as many structures as configuration space
/// could hold — the bound that makes a device with a looping list finite rather than a
/// kernel that does not return.
pub fn capabilities(cfg: &impl ConfigSpace, at: Address, out: &mut [Capability]) -> usize {
    if cfg.read(at, reg::COMMAND) & reg::STATUS_CAPABILITIES == 0 {
        return 0;
    }
    // A capability begins on a four-byte boundary, so the pointer's low two bits are
    // reserved and masked away rather than trusted.
    let mut offset = (cfg.read(at, reg::CAPABILITY_POINTER) & 0xfc) as u16;
    let mut n = 0;
    // Bounded: 0x40..0x100 holds at most 48 four-byte-aligned structures.
    for _ in 0..48 {
        let Some(slot) = out.get_mut(n) else { break };
        if !(0x40..=0xfc).contains(&offset) {
            break;
        }
        let mut words = [0u32; CAPABILITY_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            // A capability that runs past configuration space is read as far as it fits;
            // the reserved words beyond read all-ones, as an absent register does.
            let at_word = offset + 4 * i as u16;
            *w = if at_word <= 0xfc {
                cfg.read(at, at_word)
            } else {
                0
            };
        }
        let word = words[0];
        *slot = Capability {
            id: word as u8,
            offset,
            words,
        };
        n += 1;
        offset = ((word >> 8) & 0xfc) as u16;
    }
    n
}

fn vendor(cfg: &impl ConfigSpace, at: Address) -> u16 {
    cfg.read(at, reg::ID) as u16
}

fn read_function(
    cfg: &impl ConfigSpace,
    at: Address,
    parent: Option<u16>,
) -> Result<Function, Error> {
    let id = cfg.read(at, reg::ID);
    let class = cfg.read(at, reg::CLASS);
    let header = cfg.read(at, reg::HEADER);
    let header_type = (header >> 16) as u8 & 0x7f;
    let interrupt = cfg.read(at, reg::INTERRUPT);
    let (vendor, device) = (id as u16, (id >> 16) as u16);
    let (class_code, subclass, prog_if, revision) =
        ((class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8, class as u8);
    let (subsystem_vendor, subsystem) = if header_type == 0 {
        let s = cfg.read(at, reg::SUBSYSTEM);
        (s as u16, (s >> 16) as u16)
    } else {
        (0, 0)
    };
    let bridge = (header_type == 1).then(|| {
        let buses = cfg.read(at, reg::BUS_NUMBERS);
        BusRange {
            secondary: (buses >> 8) as u8,
            subordinate: (buses >> 16) as u8,
        }
    });

    let count = bar_count(header_type);
    let mut original_bars = [0u32; 6];
    for (i, slot) in original_bars.iter_mut().enumerate().take(count) {
        *slot = cfg.read(at, reg::BAR0 + 4 * i as u16);
    }
    let original_command = cfg.read(at, reg::COMMAND) as u16;
    let bars =
        size_bars(cfg, at, count, &original_bars, (class_code, subclass) != CLASS_HOST_BRIDGE);

    let mut capabilities = [Capability::EMPTY; MAX_CAPABILITIES];
    let capability_count = self::capabilities(cfg, at, &mut capabilities) as u8;

    let name = Text::format(format_args!("{at:?}")).ok_or(Error::Text)?;
    let compatible = Text::format(format_args!(
        "pci{vendor:04x},{device:04x}\0pciclass,{class_code:02x}{subclass:02x}{prog_if:02x}\0\
         pciclass,{class_code:02x}{subclass:02x}\0"
    ))
    .ok_or(Error::Text)?;

    Ok(Function {
        address: at,
        vendor,
        device,
        class: class_code,
        subclass,
        prog_if,
        revision,
        header_type,
        subsystem_vendor,
        subsystem,
        interrupt_pin: (interrupt >> 8) as u8,
        interrupt_line: interrupt as u8,
        bars,
        bridge,
        parent,
        original_command,
        original_bars,
        name,
        compatible,
        capabilities,
        capability_count,
    })
}

/// Size the first `count` BARs of `at`, restoring each and the command register.
fn size_bars(
    cfg: &impl ConfigSpace,
    at: Address,
    count: usize,
    original: &[u32; 6],
    quiesce: bool,
) -> [Bar; 6] {
    let mut bars = [Bar::None; 6];
    if count == 0 {
        return bars;
    }
    let command = cfg.read(at, reg::COMMAND);
    // Status is the register's upper half and its bits clear when written with ones, so
    // the write carries only the command half.
    let decode_off = command & 0xffff & !(reg::COMMAND_IO | reg::COMMAND_MEMORY);
    if quiesce {
        cfg.write(at, reg::COMMAND, decode_off);
    }

    let mut i = 0;
    // Bounded: advances by one or two registers a pass.
    while i < count {
        let offset = reg::BAR0 + 4 * i as u16;
        let was = original.get(i).copied().unwrap_or(0);
        cfg.write(at, offset, 0xffff_ffff);
        let low = cfg.read(at, offset);
        cfg.write(at, offset, was);

        if was & 1 != 0 {
            // I/O. A 16-bit decoder leaves the upper half zero; the size is only over the
            // bits it implements.
            let mask = low & !0x3;
            if mask != 0 {
                let implemented = if mask >> 16 == 0 {
                    mask | 0xffff_0000
                } else {
                    mask
                };
                if let Some(slot) = bars.get_mut(i) {
                    *slot = Bar::Io {
                        base: was & !0x3,
                        size: (!implemented).wrapping_add(1),
                    };
                }
            }
            i += 1;
            continue;
        }

        let wide = (was >> 1) & 0x3 == 0x2 && i + 1 < count;
        let prefetchable = was & 0x8 != 0;
        let (high_was, high) = if wide {
            let high_offset = offset + 4;
            let high_was = original.get(i + 1).copied().unwrap_or(0);
            cfg.write(at, high_offset, 0xffff_ffff);
            let high = cfg.read(at, high_offset);
            cfg.write(at, high_offset, high_was);
            (high_was, high)
        } else {
            // A 32-bit BAR decodes nothing above four gigabytes.
            (0, 0xffff_ffff)
        };
        let mask = (u64::from(high) << 32) | u64::from(low & !0xf);
        let base = (u64::from(high_was) << 32) | u64::from(was & !0xf);
        if low & !0xf != 0 || (wide && high != 0) {
            if let Some(slot) = bars.get_mut(i) {
                *slot = Bar::Memory {
                    base,
                    size: (!mask).wrapping_add(1),
                    prefetchable,
                    wide,
                };
            }
        }
        i += if wide { 2 } else { 1 };
    }

    if quiesce {
        cfg.write(at, reg::COMMAND, command & 0xffff);
    }
    bars
}
