//! A bounded frame-pointer unwinder, for panic and fault reports.
//!
//! Every kernel crate is built with `-C force-frame-pointers=yes`, so each function
//! that has a frame keeps a *frame record* on the stack: the caller's frame pointer
//! and the return address into the caller, at fixed offsets from its own frame
//! pointer. Following the saved frame pointers from record to record gives the chain
//! of return addresses. That is the whole algorithm. Everything else in this crate is
//! about following that chain on a stack that may be corrupt, because a backtrace is
//! wanted most when the stack is the thing that went wrong.
//!
//! # What the walk refuses to do
//!
//! It never reads memory it has not first shown to be inside the stack it was given.
//! It stops, and says why, on:
//!
//! * a null frame pointer — the normal end, because every port's `_start` zeroes it;
//! * a frame pointer that is not a multiple of the word size;
//! * a frame record that does not lie entirely inside the stack bounds;
//! * a frame pointer that does not increase — stacks grow down, so a caller's record is always
//!   above its callee's, and a chain that goes sideways or down is a loop or garbage;
//! * a depth limit, so a chain that stays plausible for ever still ends.
//!
//! The monotonic rule is what makes a looping stack terminate: a cycle has to come back
//! down at some point. The depth limit covers a long, strictly increasing chain of
//! garbage that never leaves the bounds.
//!
//! # What it prints
//!
//! Raw addresses, one per line, in a format meant for `kbuild symbolize` to grep:
//!
//! ```text
//! backtrace:
//!   bt build 3f2a…(40 hex digits)
//!   bt pc 0x0000000000104f2a
//!   bt 0 0x0000000000103512
//!   bt 1 0x00000000001034f0
//!   bt end: null frame
//! ```
//!
//! `build` is the image's build ID (`lib/buildid`), so a report can only be decoded against
//! the symbols of the build that printed it. `pc` is an exact address: the instruction
//! that faulted. The numbered entries are
//! return addresses, one instruction past a call, and the symbolizer looks up the byte
//! before each. The image carries no symbols. They are in the separate symbol bundle
//! kbuild writes next to it, which is what lets a report from a stripped image be
//! decoded later (`docs/build-system.md#deliverables`).
//!
//! The crate depends only on `hal`, and not on any architecture. The frame layout is a
//! value the port supplies, and memory is reached through [`Memory`]. So the walk runs
//! on the host against synthetic stacks, including corrupt ones.

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
mod tests;

use hal::{EarlyConsole, ImageSections};

/// Where a frame record keeps its two words, relative to the frame pointer.
///
/// Signed, because not every ABI puts the record at or above the frame pointer. The
/// RISC-V psABI points `s0` at the *top* of the frame — the caller's stack pointer on
/// entry — and keeps the record in the two words just below it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    /// Size of a saved frame pointer and of a return address, in bytes.
    pub word: usize,
    /// Offset of the caller's saved frame pointer.
    pub saved_fp: isize,
    /// Offset of the return address into the caller.
    pub return_address: isize,
}

impl Layout {
    /// The saved frame pointer at the frame pointer, the return address one word above
    /// it. `push rbp; mov rbp, rsp` on x86_64, the same with `ebp` on i686, and the
    /// `{x29, x30}` pair that AAPCS64 requires `x29` to point at.
    pub const fn frame_record(word: usize) -> Layout {
        Layout {
            word,
            saved_fp: 0,
            return_address: word as isize,
        }
    }

    /// The record in the two words below the frame pointer: the return address at
    /// `fp - word`, the saved frame pointer at `fp - 2 * word`. RISC-V's shape.
    pub const fn record_below(word: usize) -> Layout {
        Layout {
            word,
            saved_fp: -2 * (word as isize),
            return_address: -(word as isize),
        }
    }

    /// Offset of the record's lowest byte from the frame pointer.
    const fn lowest(&self) -> isize {
        if self.saved_fp < self.return_address {
            self.saved_fp
        } else {
            self.return_address
        }
    }

    /// Bytes from the record's lowest byte to its end.
    fn span(&self) -> usize {
        let hi = if self.saved_fp > self.return_address {
            self.saved_fp
        } else {
            self.return_address
        };
        (hi - self.lowest()).unsigned_abs() + self.word
    }

    /// The address of the record's lowest byte for frame pointer `fp`, or `None` if it
    /// would wrap. A stack is looked up by an address inside it, and with the record
    /// below the frame pointer the outermost frame's `fp` is one past the stack's top.
    pub fn record_start(&self, fp: usize) -> Option<usize> {
        fp.checked_add_signed(self.lowest())
    }
}

/// Read access to the memory a stack lives in.
///
/// Returns `None` rather than faulting for an address it cannot read. The walk checks
/// bounds before it asks, so an implementation that is also bounds-checked gives two
/// independent guards.
pub trait Memory {
    /// The word at `addr`, `layout.word` bytes wide, in the target's byte order.
    fn read_word(&self, addr: usize) -> Option<usize>;
}

/// Why a walk ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stop {
    /// The frame pointer was zero: the outermost frame, and the one normal ending.
    NullFrame,
    /// The frame pointer was not a multiple of the word size.
    Misaligned,
    /// The frame record was not entirely inside the stack.
    OutsideStack,
    /// The saved frame pointer did not lie above the frame that saved it.
    NotIncreasing,
    /// The memory reader could not read an address the bounds allowed.
    Unreadable,
    /// The walk reached its depth limit.
    DepthLimit,
}

impl Stop {
    pub const fn describe(self) -> &'static str {
        match self {
            Stop::NullFrame => "null frame",
            Stop::Misaligned => "misaligned frame pointer",
            Stop::OutsideStack => "frame outside the stack",
            Stop::NotIncreasing => "frame pointer did not increase",
            Stop::Unreadable => "unreadable frame",
            Stop::DepthLimit => "depth limit",
        }
    }
}

/// Frames reported before a walk gives up. Enough for any real kernel call chain; a
/// deeper one is recursion, and its first frames are the part worth reading.
pub const MAX_DEPTH: usize = 32;

/// A walk up a frame-pointer chain, yielding return addresses, innermost first.
///
/// After the iterator ends, [`Walk::stop`] says why.
pub struct Walk<'m, M: Memory> {
    mem: &'m M,
    layout: Layout,
    /// `[lo, hi)`: the stack the walk may read.
    lo: usize,
    hi: usize,
    fp: usize,
    /// The frame pointer of the record last read, to check the chain climbs.
    prev: Option<usize>,
    depth: usize,
    stop: Option<Stop>,
}

impl<'m, M: Memory> Walk<'m, M> {
    /// Walk from frame pointer `fp`, reading only inside `[lo, hi)`.
    pub fn new(mem: &'m M, layout: Layout, lo: usize, hi: usize, fp: usize) -> Self {
        Walk {
            mem,
            layout,
            lo,
            hi,
            fp,
            prev: None,
            depth: 0,
            stop: None,
        }
    }

    /// Why the walk ended, once it has.
    pub fn stop(&self) -> Option<Stop> {
        self.stop
    }

    fn end(&mut self, why: Stop) -> Option<usize> {
        self.stop = Some(why);
        None
    }
}

impl<M: Memory> Iterator for Walk<'_, M> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.stop.is_some() {
            return None;
        }
        let fp = self.fp;
        if fp == 0 {
            return self.end(Stop::NullFrame);
        }
        if self.prev.is_some_and(|p| fp <= p) {
            return self.end(Stop::NotIncreasing);
        }
        if self.depth >= MAX_DEPTH {
            return self.end(Stop::DepthLimit);
        }
        if self.layout.word == 0 || fp % self.layout.word != 0 {
            return self.end(Stop::Misaligned);
        }
        // Checked arithmetic: a frame pointer near either end of the address space must be
        // rejected, not wrapped around into an address that happens to pass.
        let inside = self.layout.record_start(fp).is_some_and(|start| {
            start >= self.lo
                && start
                    .checked_add(self.layout.span())
                    .is_some_and(|end| end <= self.hi)
        });
        if !inside {
            return self.end(Stop::OutsideStack);
        }

        // Neither wraps: both words lie inside the record just checked.
        let (Some(ra), Some(saved)) = (
            self.mem
                .read_word(fp.wrapping_add_signed(self.layout.return_address)),
            self.mem
                .read_word(fp.wrapping_add_signed(self.layout.saved_fp)),
        ) else {
            return self.end(Stop::Unreadable);
        };

        self.prev = Some(fp);
        self.fp = saved;
        self.depth += 1;
        Some(ra)
    }
}

/// Memory the kernel reads directly: one address range, checked on every read.
pub struct Region {
    lo: usize,
    hi: usize,
}

impl Region {
    /// # Safety
    /// Every byte of `[lo, hi)` must be mapped and readable for as long as this value
    /// exists, and must hold data the reader may observe — a stack that is being
    /// unwound, which nothing else is writing.
    pub const unsafe fn new(lo: usize, hi: usize) -> Region {
        Region { lo, hi }
    }
}

impl Memory for Region {
    fn read_word(&self, addr: usize) -> Option<usize> {
        let end = addr.checked_add(core::mem::size_of::<usize>())?;
        if addr < self.lo || end > self.hi {
            return None;
        }
        // SAFETY: `[addr, end)` is inside `[lo, hi)`, which the constructor's caller
        // promised is readable. Unaligned, because the bound check does not establish
        // alignment and a misaligned read must not become undefined behaviour.
        Some(unsafe { core::ptr::read_unaligned(addr as *const usize) })
    }
}

/// The stack regions of the image: its read-write data, less the guard page.
///
/// Every stack the kernel has outside the thread-stack array is in there: the boot
/// stack, the x86_64 `#DF` stack, and the context-switch selftest's thread stacks. The
/// guard page is cut out because it is meant to be unmapped, and reading it would fault
/// inside the fault report. What is left may be two pieces. The thread-stack array is not
/// cut out here; [`stack_bounds`] handles it.
pub fn image_stacks(s: &ImageSections) -> [(usize, usize); 2] {
    let as_usize = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
    let (lo, hi) = (as_usize(s.data.0), as_usize(s.data.1));
    let (glo, ghi) = (as_usize(s.stack_guard.0), as_usize(s.stack_guard.1));
    if glo >= ghi || ghi <= lo || glo >= hi {
        // No guard, or not inside the data: nothing to cut out.
        return [(lo, hi), (0, 0)];
    }
    [(lo, glo.max(lo)), (ghi.min(hi), hi)]
}

/// The one stack a walk starting at `fp` may read, as `[lo, hi)`.
///
/// A walk is confined to it, so a chain cannot cross a guard page in either direction.
/// A frame pointer on a thread stack is confined to that slot's stack. Anywhere else in
/// the data it is confined to the piece of [`image_stacks`] it is in, less the whole
/// thread-stack array: the array's guard pages are unmapped too, and a corrupt chain on
/// the boot stack that pointed into one would otherwise fault inside the report.
pub fn stack_bounds(s: &ImageSections, fp: usize) -> Option<(usize, usize)> {
    let as_usize = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
    let t = &s.thread_stacks;
    let fp64 = fp as u64;
    if let Some(i) = t.slot_of(fp64) {
        let (lo, hi) = t.stack_range(i)?;
        return (lo..hi)
            .contains(&fp64)
            .then(|| (as_usize(lo), as_usize(hi)));
    }
    let (tlo, thi) = if t.count() > 0 {
        (as_usize(t.start), as_usize(t.end))
    } else {
        (0, 0)
    };
    image_stacks(s)
        .into_iter()
        .filter(|(lo, hi)| (*lo..*hi).contains(&fp))
        .map(|(lo, hi)| {
            // The array is an interval inside the piece; keep the side `fp` is on.
            if tlo < thi && tlo < hi && thi > lo {
                if fp < tlo {
                    (lo, tlo)
                } else {
                    (thi.max(lo), hi)
                }
            } else {
                (lo, hi)
            }
        })
        .find(|(lo, hi)| (*lo..*hi).contains(&fp))
}

/// Print a backtrace from frame pointer `fp`, confined to the image's stacks.
///
/// `pc`, when given, is printed first as the exact faulting instruction. `skip` frames
/// are walked and checked but not printed: the report's own frames, which say only
/// that a report was made.
///
/// # Safety
/// The regions `stack_bounds(sections, _)` returns must be mapped and readable, which is
/// the case for as long as the kernel's image is mapped at all.
pub unsafe fn print(
    c: &dyn EarlyConsole,
    layout: Layout,
    sections: &ImageSections,
    fp: usize,
    pc: Option<usize>,
    skip: usize,
) {
    c.write_str("\nbacktrace:\n  bt build ");
    buildid::write(c);
    c.write_str("\n");
    if let Some(pc) = pc {
        c.write_str("  bt pc ");
        write_addr(c, pc);
        c.write_str("\n");
    }
    let found = layout
        .record_start(fp)
        .and_then(|at| stack_bounds(sections, at));
    let Some((lo, hi)) = found else {
        c.write_str("  bt end: frame pointer ");
        write_addr(c, fp);
        c.write_str(" is not in any known stack\n");
        return;
    };
    if layout.word != core::mem::size_of::<usize>() {
        // `Region` reads native words; a layout that disagrees would read garbage.
        c.write_str("  bt end: frame layout does not match the pointer width\n");
        return;
    }
    // SAFETY: forwarded from this function's contract.
    let mem = unsafe { Region::new(lo, hi) };
    let mut walk = Walk::new(&mem, layout, lo, hi, fp);
    let mut n = 0usize;
    for ra in walk.by_ref() {
        if n >= skip {
            c.write_str("  bt ");
            write_dec(c, n - skip);
            c.write_str(" ");
            write_addr(c, ra);
            c.write_str("\n");
        }
        n += 1;
    }
    c.write_str("  bt end: ");
    c.write_str(walk.stop().map(Stop::describe).unwrap_or("?"));
    c.write_str("\n");
}

/// What a walk over the kernel's own stack found, for a check to judge.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Chain {
    /// Return addresses read.
    pub frames: usize,
    /// Why the walk ended.
    pub stop: Stop,
    /// The first return address outside `.text`, if any. A frame-pointer chain whose
    /// return addresses are not code has been followed through something that is not
    /// a frame record.
    pub stray: Option<usize>,
}

/// Walk from `fp` over the image's stacks without printing, for a selftest.
///
/// # Safety
/// As for [`print`].
pub unsafe fn chain(layout: Layout, sections: &ImageSections, fp: usize) -> Chain {
    let as_usize = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
    let text = as_usize(sections.text.0)..as_usize(sections.text.1);
    let found = layout
        .record_start(fp)
        .and_then(|at| stack_bounds(sections, at));
    let Some((lo, hi)) = found else {
        return Chain {
            frames: 0,
            stop: Stop::OutsideStack,
            stray: None,
        };
    };
    // SAFETY: forwarded from this function's contract.
    let mem = unsafe { Region::new(lo, hi) };
    let mut walk = Walk::new(&mem, layout, lo, hi, fp);
    let mut stray = None;
    let mut frames = 0;
    for ra in walk.by_ref() {
        frames += 1;
        if stray.is_none() && !text.contains(&ra) {
            stray = Some(ra);
        }
    }
    Chain {
        frames,
        stop: walk.stop().unwrap_or(Stop::DepthLimit),
        stray,
    }
}

/// An address at full pointer width, so every line of a report has the same shape.
fn write_addr(c: &dyn EarlyConsole, v: usize) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digits = core::mem::size_of::<usize>() * 2;
    let mut buf = [0u8; 2 + 16];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..digits {
        let shift = (digits - 1 - i) * 4;
        buf[2 + i] = DIGITS[(v >> shift) & 0xf];
    }
    c.write_bytes(&buf[..2 + digits]);
}

fn write_dec(c: &dyn EarlyConsole, mut v: usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    c.write_bytes(&buf[i..]);
}
