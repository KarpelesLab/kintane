//! The walk against synthetic stacks: well-formed, corrupt and looping, at both word
//! sizes the ports use.

use std::cell::Cell;

use hal::ImageSections;

use crate::*;

/// A fake stack: `bytes` mapped at `base`, little-endian words of `word` bytes.
///
/// Counts reads, so a test can show the walk did not touch memory it had not checked,
/// and refuses anything outside what it holds, so an out-of-bounds read is visible as
/// `Unreadable` rather than as a crash of the test binary.
struct Stack {
    base: usize,
    word: usize,
    bytes: Vec<u8>,
    reads: Cell<usize>,
    out_of_range: Cell<usize>,
}

impl Stack {
    fn new(base: usize, word: usize, words: usize) -> Stack {
        Stack {
            base,
            word,
            bytes: vec![0; words * word],
            reads: Cell::new(0),
            out_of_range: Cell::new(0),
        }
    }

    fn end(&self) -> usize {
        self.base + self.bytes.len()
    }

    fn put(&mut self, addr: usize, v: usize) {
        let off = addr - self.base;
        let le = (v as u64).to_le_bytes();
        self.bytes[off..off + self.word].copy_from_slice(&le[..self.word]);
    }

    /// A frame record at `fp`: saved frame pointer, then return address.
    fn record(&mut self, fp: usize, saved: usize, ra: usize) {
        self.put(fp, saved);
        self.put(fp + self.word, ra);
    }

    fn layout(&self) -> Layout {
        Layout::frame_record(self.word)
    }
}

impl Memory for Stack {
    fn read_word(&self, addr: usize) -> Option<usize> {
        self.reads.set(self.reads.get() + 1);
        if addr < self.base || addr + self.word > self.end() {
            self.out_of_range.set(self.out_of_range.get() + 1);
            return None;
        }
        let off = addr - self.base;
        let mut le = [0u8; 8];
        le[..self.word].copy_from_slice(&self.bytes[off..off + self.word]);
        Some(u64::from_le_bytes(le) as usize)
    }
}

fn walk(s: &Stack, fp: usize) -> (Vec<usize>, Option<Stop>) {
    let mut w = Walk::new(s, s.layout(), s.base, s.end(), fp);
    let ras: Vec<usize> = w.by_ref().collect();
    (ras, w.stop())
}

/// Three frames ending at the null frame `_start` plants, at both word sizes.
fn well_formed(word: usize) {
    let base = 0x1000;
    let mut s = Stack::new(base, word, 64);
    let (a, b, c) = (base + 4 * word, base + 10 * word, base + 20 * word);
    s.record(a, b, 0x100_111);
    s.record(b, c, 0x100_222);
    s.record(c, 0, 0x100_333);

    let (ras, stop) = walk(&s, a);
    assert_eq!(ras, [0x100_111, 0x100_222, 0x100_333]);
    assert_eq!(stop, Some(Stop::NullFrame));
    assert_eq!(s.out_of_range.get(), 0);
}

#[test]
fn synthetic_stack_64() {
    well_formed(8);
}

#[test]
fn synthetic_stack_32() {
    well_formed(4);
}

#[test]
fn a_null_frame_pointer_is_an_empty_backtrace() {
    let s = Stack::new(0x1000, 8, 8);
    let (ras, stop) = walk(&s, 0);
    assert!(ras.is_empty());
    assert_eq!(stop, Some(Stop::NullFrame));
    assert_eq!(s.reads.get(), 0);
}

#[test]
fn a_misaligned_frame_pointer_stops_before_reading() {
    let mut s = Stack::new(0x1000, 8, 16);
    s.record(0x1010, 0x1023, 0xaaaa);
    let (ras, stop) = walk(&s, 0x1010);
    assert_eq!(ras, [0xaaaa]);
    assert_eq!(stop, Some(Stop::Misaligned));
    // Two reads for the good record, none for the misaligned one.
    assert_eq!(s.reads.get(), 2);
}

#[test]
fn corrupted_saved_frame_pointer_leaves_the_stack() {
    let mut s = Stack::new(0x1000, 8, 16);
    // A saved frame pointer overwritten with something that looks like data.
    s.record(0x1010, 0xdead_beef_0000, 0xaaaa);
    let (ras, stop) = walk(&s, 0x1010);
    assert_eq!(ras, [0xaaaa]);
    assert_eq!(stop, Some(Stop::OutsideStack));
    assert_eq!(s.out_of_range.get(), 0, "the walk read outside the stack");
}

#[test]
fn a_record_straddling_the_top_of_the_stack_is_outside_it() {
    let s = Stack::new(0x1000, 8, 16);
    // The saved frame pointer would be in bounds; the return address would not.
    let fp = s.end() - 8;
    let (ras, stop) = walk(&s, fp);
    assert!(ras.is_empty());
    assert_eq!(stop, Some(Stop::OutsideStack));
    assert_eq!(s.reads.get(), 0);
}

#[test]
fn a_frame_pointer_below_the_stack_is_outside_it() {
    let s = Stack::new(0x1000, 8, 16);
    let (_, stop) = walk(&s, 0x800);
    assert_eq!(stop, Some(Stop::OutsideStack));
    assert_eq!(s.reads.get(), 0);
}

#[test]
fn a_frame_pointer_at_the_top_of_the_address_space_does_not_wrap() {
    // `fp + span` overflows. Wrapping arithmetic would make it a small address that
    // passes the upper bound check.
    let s = Stack::new(0, 8, 16);
    let mut w = Walk::new(&s, s.layout(), 0, usize::MAX, usize::MAX - 7);
    assert_eq!(w.next(), None);
    assert_eq!(w.stop(), Some(Stop::OutsideStack));
    assert_eq!(s.reads.get(), 0);
}

#[test]
fn looping_stack_terminates() {
    let mut s = Stack::new(0x1000, 8, 32);
    // A -> B -> A: plausible records forming a cycle.
    s.record(0x1010, 0x1040, 0xaaaa);
    s.record(0x1040, 0x1010, 0xbbbb);
    let (ras, stop) = walk(&s, 0x1010);
    assert_eq!(ras, [0xaaaa, 0xbbbb]);
    assert_eq!(stop, Some(Stop::NotIncreasing));
}

#[test]
fn a_frame_that_points_at_itself_terminates() {
    let mut s = Stack::new(0x1000, 8, 16);
    s.record(0x1010, 0x1010, 0xaaaa);
    let (ras, stop) = walk(&s, 0x1010);
    assert_eq!(ras, [0xaaaa]);
    assert_eq!(stop, Some(Stop::NotIncreasing));
}

#[test]
fn a_long_increasing_chain_hits_the_depth_limit() {
    let words = 2 * (MAX_DEPTH + 8) + 2;
    let mut s = Stack::new(0x1000, 8, words);
    for i in 0..MAX_DEPTH + 8 {
        let fp = 0x1000 + i * 16;
        s.record(fp, fp + 16, 0x1000 + i);
    }
    let (ras, stop) = walk(&s, 0x1000);
    assert_eq!(ras.len(), MAX_DEPTH);
    assert_eq!(stop, Some(Stop::DepthLimit));
}

#[test]
fn an_unreadable_frame_is_reported_not_crossed() {
    // Bounds that claim more than the reader holds: the reader's own check is the one
    // that fires.
    let mut s = Stack::new(0x1000, 8, 4);
    s.record(0x1000, 0x1020, 0xaaaa);
    let mut w = Walk::new(&s, s.layout(), 0x1000, 0x2000, 0x1000);
    assert_eq!(w.next(), Some(0xaaaa));
    assert_eq!(w.next(), None);
    assert_eq!(w.stop(), Some(Stop::Unreadable));
}

#[test]
fn stacks_exclude_a_guard_inside_the_data() {
    // aarch64 and i686: data, guard, stack.
    let s = ImageSections {
        text: (0x1000, 0x2000),
        rodata: (0x2000, 0x3000),
        data: (0x3000, 0x9000),
        stack_guard: (0x5000, 0x6000),
    };
    assert_eq!(image_stacks(&s), [(0x3000, 0x5000), (0x6000, 0x9000)]);
}

#[test]
fn stacks_keep_all_data_when_the_guard_is_outside_it() {
    // x86_64: guard, then data beginning with the stack.
    let s = ImageSections {
        text: (0x1000, 0x2000),
        rodata: (0x2000, 0x3000),
        data: (0x4000, 0x9000),
        stack_guard: (0x3000, 0x4000),
    };
    assert_eq!(image_stacks(&s)[0], (0x4000, 0x9000));
    assert_eq!(image_stacks(&s)[1], (0, 0));
}

#[test]
fn region_refuses_reads_outside_it() {
    let words = [0x1111usize, 0x2222];
    let lo = words.as_ptr() as usize;
    let hi = lo + core::mem::size_of_val(&words);
    // SAFETY: `words` is live for the whole test.
    let r = unsafe { Region::new(lo, hi) };
    assert_eq!(r.read_word(lo), Some(0x1111));
    assert_eq!(r.read_word(lo + core::mem::size_of::<usize>()), Some(0x2222));
    assert_eq!(r.read_word(lo + 1 + core::mem::size_of::<usize>()), None);
    assert_eq!(r.read_word(lo - 1), None);
    assert_eq!(r.read_word(usize::MAX - 2), None);
}
