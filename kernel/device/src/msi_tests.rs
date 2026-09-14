//! Host tests for message-signalled interrupts: decoding the capabilities, enabling them
//! through a configuration space that behaves like the hardware's, and the MSI-X table over
//! a buffer standing in for a claimed window.

use std::cell::RefCell;

use super::msi::{
    self, CAP_MSI, CAP_MSIX, ENTRY_BYTES, MsiCapability, MsixCapability, MsixTable, VECTOR_TAG,
};
use super::pci::{Address, CAPABILITY_WORDS, Capability, ConfigSpace};
use super::registers::Registers;

const AT: Address = Address {
    bus: 0,
    device: 3,
    function: 0,
};

/// One function's configuration space, as 64 words, recording every write.
struct Config {
    words: RefCell<[u32; 64]>,
    writes: RefCell<Vec<(u16, u32)>>,
    /// Bits of each word that take a write; the rest keep what was there.
    writable: [u32; 64],
}

impl Config {
    fn new() -> Config {
        Config {
            words: RefCell::new([0; 64]),
            writes: RefCell::new(Vec::new()),
            writable: [u32::MAX; 64],
        }
    }

    fn word(&self, offset: u16) -> u32 {
        self.words.borrow()[usize::from(offset) / 4]
    }

    fn set(&self, offset: u16, value: u32) {
        self.words.borrow_mut()[usize::from(offset) / 4] = value;
    }
}

impl ConfigSpace for Config {
    fn read(&self, at: Address, offset: u16) -> u32 {
        assert_eq!(at, AT, "a read of another function");
        self.word(offset)
    }

    fn write(&self, at: Address, offset: u16, value: u32) {
        assert_eq!(at, AT, "a write to another function");
        assert_eq!(offset % 4, 0, "configuration space is written a word at a time");
        let i = usize::from(offset) / 4;
        let keep = !self.writable[i];
        let mut words = self.words.borrow_mut();
        words[i] = (words[i] & keep) | (value & self.writable[i]);
        self.writes.borrow_mut().push((offset, value));
    }
}

fn capability(id: u8, offset: u16, words: &[u32]) -> Capability {
    let mut w = [0u32; CAPABILITY_WORDS];
    w[..words.len()].copy_from_slice(words);
    w[0] = (w[0] & !0xff) | u32::from(id);
    Capability {
        id,
        offset,
        words: w,
    }
}

/// QEMU's virtio-blk-pci: two vectors, table in BAR 1 at offset 0, pending bits at 0x800.
fn virtio_msix() -> Capability {
    // Control: table size 2 encoded as 1; next pointer 0x84 in bits 15:8.
    capability(CAP_MSIX, 0x98, &[(1 << 16) | 0x8400, 0x0000_0001, 0x0000_0801])
}

#[test]
fn an_msix_capability_decodes_its_table_size_as_n_minus_one() {
    let cap = MsixCapability::read(&virtio_msix()).unwrap();
    assert_eq!(cap.table_size, 2);
    assert_eq!((cap.table_bar, cap.table_offset), (1, 0));
    assert_eq!((cap.pba_bar, cap.pba_offset), (1, 0x800));
    assert!(!cap.enabled && !cap.function_masked);
    assert_eq!(cap.table_bytes(), 2 * ENTRY_BYTES);

    // The largest table the encoding allows, and the offset bits kept apart from the BAR.
    let big = capability(CAP_MSIX, 0x40, &[0x7ff << 16, 0x0000_3004, 0x0000_2005]);
    let big = MsixCapability::read(&big).unwrap();
    assert_eq!(big.table_size, 2048);
    assert_eq!((big.table_bar, big.table_offset), (4, 0x3000));
    assert_eq!((big.pba_bar, big.pba_offset), (5, 0x2000));
}

#[test]
fn an_msix_table_in_a_reserved_bar_is_refused() {
    for bir in [6u32, 7] {
        let cap = capability(CAP_MSIX, 0x40, &[0, bir, 1]);
        assert_eq!(MsixCapability::read(&cap), None, "BAR indicator {bir}");
    }
    let pba = capability(CAP_MSIX, 0x40, &[0, 1, 7]);
    assert_eq!(MsixCapability::read(&pba), None);
}

#[test]
fn another_capability_is_not_mistaken_for_msix_or_msi() {
    let vendor = capability(0x09, 0x84, &[0x0010_0000]);
    assert_eq!(MsixCapability::read(&vendor), None);
    assert_eq!(MsiCapability::read(&vendor), None);
}

#[test]
fn enabling_msix_clears_the_function_mask_and_keeps_the_list_pointer() {
    let cfg = Config::new();
    let cap = MsixCapability::read(&virtio_msix()).unwrap();
    // Firmware left the function masked and the ID and next pointer are what they are.
    cfg.set(cap.offset, (1 << 16) | (1 << 30) | 0x8411);
    assert!(msi::set_msix_enabled(&cfg, AT, &cap, true));
    let word = cfg.word(cap.offset);
    assert_ne!(word & (1 << 31), 0, "enabled");
    assert_eq!(word & (1 << 30), 0, "the function-wide mask is cleared");
    assert_eq!(word & 0xffff, 0x8411, "the ID and the next pointer are written back as read");
    assert_eq!(word & (0x7ff << 16), 1 << 16, "the table size is untouched");

    assert!(msi::set_msix_enabled(&cfg, AT, &cap, false));
    assert_eq!(cfg.word(cap.offset) & (1 << 31), 0);
}

#[test]
fn a_bus_master_keeps_the_rest_of_its_command_register() {
    let cfg = Config::new();
    // Memory decode on, bus mastering off: how QEMU leaves a function no firmware drove.
    cfg.set(0x04, 0x0010_0002);
    assert!(msi::set_bus_master(&cfg, AT));
    assert_eq!(cfg.word(0x04), 0x0010_0006, "only the bus master bit is added");

    let mut stuck = Config::new();
    stuck.writable[1] = !(1 << 2);
    assert!(!msi::set_bus_master(&stuck, AT), "a function that refuses it reports failure");
}

#[test]
fn enabling_msix_on_a_function_that_ignores_it_reports_failure() {
    let mut cfg = Config::new();
    let cap = MsixCapability::read(&virtio_msix()).unwrap();
    // The control register does not take the enable bit.
    cfg.writable[usize::from(cap.offset) / 4] = !(1 << 31);
    assert!(!msi::set_msix_enabled(&cfg, AT, &cap, true));
}

#[test]
fn msi_puts_the_data_register_where_the_address_width_says() {
    let cfg = Config::new();
    let narrow = MsiCapability::read(&capability(CAP_MSI, 0x50, &[0])).unwrap();
    assert!(!narrow.address_64);
    assert!(msi::program_msi(&cfg, AT, &narrow, 0xfee0_1000, 0x41));
    assert_eq!(cfg.word(0x54), 0xfee0_1000);
    assert_eq!(cfg.word(0x58) & 0xffff, 0x41, "32-bit: data at +8");
    assert_ne!(cfg.word(0x50) & (1 << 16), 0, "enabled");
    assert_eq!(cfg.word(0x50) & (0b111 << 20), 0, "one vector");

    let cfg = Config::new();
    let wide = MsiCapability::read(&capability(CAP_MSI, 0x60, &[1 << 23])).unwrap();
    assert!(wide.address_64);
    assert!(msi::program_msi(&cfg, AT, &wide, 0x1_fee0_0000, 0x42));
    assert_eq!((cfg.word(0x64), cfg.word(0x68)), (0xfee0_0000, 1));
    assert_eq!(cfg.word(0x6c) & 0xffff, 0x42, "64-bit: data at +12");
}

#[test]
fn msi_is_disabled_while_its_message_changes() {
    let cfg = Config::new();
    let cap = MsiCapability::read(&capability(CAP_MSI, 0x50, &[1 << 16])).unwrap();
    cfg.set(0x50, 1 << 16);
    assert!(msi::program_msi(&cfg, AT, &cap, 0xfee0_0000, 0x40));
    let writes = cfg.writes.borrow();
    let first_control = writes.iter().position(|w| w.0 == 0x50).unwrap();
    let address = writes.iter().position(|w| w.0 == 0x54).unwrap();
    assert!(first_control < address, "disabled before the address was written");
    assert_eq!(writes[first_control].1 & (1 << 16), 0);
}

#[test]
fn msi_refuses_a_64_bit_address_it_cannot_hold() {
    let cfg = Config::new();
    let cap = MsiCapability::read(&capability(CAP_MSI, 0x50, &[0])).unwrap();
    assert!(!msi::program_msi(&cfg, AT, &cap, 0x1_0000_0000, 0x40));
    assert!(cfg.writes.borrow().is_empty(), "nothing written");
}

#[test]
fn a_vector_specifier_round_trips_and_a_line_is_not_a_vector() {
    assert_eq!(msi::vector_of(&[msi::specifier_cell(0)]), Some(0));
    assert_eq!(msi::vector_of(&[msi::specifier_cell(7)]), Some(7));
    assert_eq!(msi::vector_of(&[11]), None, "an ISA line");
    assert_eq!(msi::vector_of(&[VECTOR_TAG, 0]), None, "more than one cell");
    assert_eq!(msi::vector_of(&[]), None);
}

/// A buffer standing in for a claimed window, and the table over it.
fn table(words: usize, offset: usize, entries: u16) -> (Box<[u32]>, Option<MsixTable>) {
    let mut buf = vec![0u32; words].into_boxed_slice();
    // Every entry starts masked, as the specification requires of the hardware.
    for e in 0..usize::from(entries) {
        let control = (offset + e * ENTRY_BYTES + 12) / 4;
        if control < words {
            buf[control] = 1;
        }
    }
    // SAFETY: the buffer outlives the table in every test, and is `words * 4` bytes of `u32`.
    #[allow(unsafe_code)]
    let regs = unsafe { Registers::from_raw(buf.as_mut_ptr() as usize, words * 4) };
    let t = MsixTable::new(regs, offset, entries);
    (buf, t)
}

#[test]
fn a_table_that_does_not_fit_its_window_is_refused() {
    assert!(table(8, 0, 2).1.is_some(), "two entries in 32 bytes fit");
    assert!(table(8, 4, 2).1.is_none(), "not from 4");
    assert!(table(8, 0, 0).1.is_none(), "empty");
    assert!(table(16, 2, 1).1.is_none(), "not on a register boundary");
}

#[test]
fn a_message_is_written_only_to_a_masked_entry() {
    let (buf, t) = table(16, 16, 2);
    let t = t.unwrap();
    assert_eq!(t.is_masked(0), Some(true));
    assert!(t.set_message(0, 0xfee0_1000, 0x30));
    assert_eq!(t.message(0), Some((0xfee0_1000, 0x30)));
    assert_eq!((buf[4], buf[5], buf[6]), (0xfee0_1000, 0, 0x30), "at the table's offset");

    assert!(t.unmask(0));
    assert!(!t.set_message(0, 0xfee0_2000, 0x31), "unmasked: refused");
    assert_eq!(t.message(0), Some((0xfee0_1000, 0x30)), "and nothing written");
    drop(buf);
}

#[test]
fn retargeting_masks_writes_and_unmasks() {
    let (_buf, t) = table(8, 0, 2);
    let t = t.unwrap();
    assert!(t.retarget(1, 0xfee0_0000, 0x40));
    assert_eq!(t.message(1), Some((0xfee0_0000, 0x40)));
    assert_eq!(t.is_masked(1), Some(false));
    assert!(t.retarget(1, 0xfee0_1000, 0x40));
    assert_eq!(t.message(1), Some((0xfee0_1000, 0x40)));
    assert_eq!(t.is_masked(0), Some(true), "entry 0 untouched");
}

#[test]
fn an_entry_past_the_table_is_neither_read_nor_written() {
    let (buf, t) = table(12, 0, 2);
    let t = t.unwrap();
    assert_eq!(t.is_masked(2), None);
    assert_eq!(t.message(2), None);
    assert!(!t.mask(2) && !t.unmask(2));
    assert!(!t.set_message(2, 1, 1) && !t.retarget(2, 1, 1));
    assert!(buf[8..].iter().all(|w| *w == 0), "past the table, nothing written");
}
