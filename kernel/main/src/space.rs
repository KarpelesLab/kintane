//! Building the kernel's own address space, with W^X over the image.
//!
//! This is the first real user of the shared walker: real frames from the frame
//! allocator, real section boundaries from the linker, on the actual machine. Up to
//! now each port built a bootstrap map in its own private code, because an `arch`
//! unit may not depend on a `core` unit and therefore cannot reach `mm::paged`. The
//! kernel image can reach both, so this is where the two halves meet.
//!
//! # Why it is built and checked but not activated
//!
//! Installing a new set of tables is the single most unrecoverable thing a kernel can
//! get wrong: the instruction after the switch has to be fetchable from the map that
//! was just installed, and if it is not there is no fault handler, no console, and no
//! evidence. So the space is built, every claim about it is verified through
//! [`AddressSpace::translate`], and the result is reported — while the machine keeps
//! running on the bootstrap tables it arrived on.
//!
//! That ordering is deliberate rather than timid. Verifying a map by walking it
//! proves the same things activation would, minus the part that cannot be undone, and
//! it can be done on every port on the same day the ports gain section symbols.
//! Activation is gated behind `ACTIVATE_KERNEL_SPACE` and needs one more thing first:
//! every device the kernel touches has to be in the map, which is per-port knowledge
//! — on x86 the console is an I/O port and needs nothing, on aarch64 it is MMIO at a
//! fixed address and needs a device mapping.

use hal::paging::{HasPageTables, ImageSections, MapError, PageFlags};
use hal::{Arch, EarlyConsole, PhysAddr};
use mm::frame::Frame;
use mm::paged::{AddressSpace, FrameSource};
use mm::phys::FrameAllocator;
use mm::DirectMap;

/// Adapts the frame allocator to what the walker needs.
///
/// The walker asks for *zeroed* frames because an absent entry is all-zero on every
/// architecture we support, so a zeroed frame is a valid empty table. The frame
/// allocator does not zero — it hands out whatever was there — so the zeroing happens
/// here, through the direct map, which is the only way to touch a physical frame.
pub struct Frames<'a, 'store, A: Arch> {
    pub alloc: &'a mut FrameAllocator<'store, A>,
    pub direct: DirectMap,
}

impl<A: Arch> FrameSource for Frames<'_, '_, A> {
    fn alloc_zeroed(&mut self) -> Result<PhysAddr, MapError> {
        let frame = self
            .alloc
            .alloc_frame()
            .map_err(|_| MapError::OutOfFrames)?;
        // A frame outside the direct map cannot be zeroed, and therefore cannot be a
        // page table — there is no way to write to it. That is reachable on a 32-bit
        // kernel with more RAM than address space, where the direct map necessarily
        // covers only part of physical memory. Give the frame back rather than leak
        // it, and report, so the caller fails loudly instead of mapping something it
        // could not initialise.
        let ptr = match self.direct.ptr_to_phys(frame.start()) {
            Ok(p) => p,
            Err(_) => {
                let _ = self.alloc.free_frame(frame);
                return Err(MapError::BadPhysAddr);
            }
        };
        // SAFETY: the frame was just handed to us by the allocator, so nothing else
        // owns it, and `ptr_to_phys` succeeded so it lies inside the direct map and is
        // writable for a whole page.
        unsafe { core::ptr::write_bytes(ptr.as_ptr(), 0, A::PAGE_SIZE) };
        Ok(frame.start())
    }

    fn free(&mut self, frame: PhysAddr) {
        if let Ok(f) = Frame::<A>::from_start(frame) {
            let _ = self.alloc.free_frame(f);
        }
    }
}

/// One contiguous run of physical memory and how it should be mapped.
#[derive(Clone, Copy)]
struct Segment {
    start: u64,
    end: u64,
    flags: PageFlags,
    what: &'static str,
}

/// At most: below-image, text, rodata, data-before-guard, data-after-guard,
/// above-image. The guard page is a hole rather than an entry.
const MAX_SEGMENTS: usize = 8;

/// Build the kernel address space and check it. Returns true if every claim held.
pub fn build_and_verify<A: HasPageTables>(
    c: &dyn EarlyConsole,
    alloc: &mut FrameAllocator<'_, A>,
    direct: DirectMap,
    sections: ImageSections,
) -> bool {
    let mut frames = Frames { alloc, direct };
    let mut space = match AddressSpace::<A>::new(direct, &mut frames) {
        Ok(s) => s,
        Err(_) => {
            c.write_str("no frame for the root table");
            return false;
        }
    };

    let mut segs = [Segment {
        start: 0,
        end: 0,
        flags: PageFlags::empty(),
        what: "",
    }; MAX_SEGMENTS];
    let n = match plan(&mut segs, direct, sections, A::PAGE_SIZE as u64) {
        Ok(n) => n,
        Err(m) => {
            c.write_str(m);
            return false;
        }
    };

    for seg in segs.iter().take(n) {
        let len = (seg.end - seg.start) as usize;
        if len == 0 {
            continue;
        }
        // Identity for now: the direct map is identity on every port today, so the
        // virtual address equals the physical one. `DirectMap::to_virt` is asked
        // rather than assumed, so the day that stops being true this fails loudly
        // instead of mapping the wrong thing.
        let virt = match direct.to_virt(PhysAddr::new(seg.start)) {
            Ok(v) => v.raw(),
            Err(_) => {
                c.write_str("segment outside the direct map");
                return false;
            }
        };
        if let Err(e) = space.map(virt, PhysAddr::new(seg.start), len, seg.flags, &mut frames) {
            c.write_str("\n             map ");
            c.write_str(seg.what);
            c.write_str(" failed: ");
            c.write_str(describe(e));
            return false;
        }
    }

    check(c, &space, direct, sections, &segs[..n])
}
/// Accumulates the runs to map, keeping them contiguous and non-overlapping.
///
/// Section boundaries come from a linker script and need not be page-aligned —
/// `__kernel_end` in particular almost never is. Each run is rounded outward to whole
/// pages and then clamped to begin where the previous one ended. Clamping in that
/// direction matters: where two sections share a page the *earlier* one keeps it, so
/// a page holding the tail of `.text` and the head of `.rodata` stays
/// executable-and-read-only rather than becoming writable.
struct Planner<'a> {
    out: &'a mut [Segment],
    n: usize,
    watermark: u64,
    page: u64,
}

impl Planner<'_> {
    fn push(&mut self, start: u64, end: u64, flags: PageFlags, what: &'static str) {
        let lo = ((start / self.page) * self.page).max(self.watermark);
        let hi = end.div_ceil(self.page) * self.page;
        if hi > lo && self.n < self.out.len() {
            self.out[self.n] = Segment {
                start: lo,
                end: hi,
                flags,
                what,
            };
            self.n += 1;
            self.watermark = hi;
        }
    }

    /// Leave a hole: the next run starts no earlier than `at`.
    fn hole_until(&mut self, at: u64) {
        self.watermark = self.watermark.max(at);
    }
}

/// Turn the direct map and the image's sections into a list of runs to map.
///
/// The direct map covers the image, so the image's own ranges have to be cut out of
/// it rather than mapped over it: overlapping is `AlreadyMapped` by design, because an
/// accidental overlap is a bug. Cutting also has a second effect worth having — the
/// surrounding memory can still use huge pages while the image is mapped at 4 KiB,
/// which is the granularity a per-section split needs.
fn plan(
    out: &mut [Segment],
    direct: DirectMap,
    s: ImageSections,
    page: u64,
) -> Result<usize, &'static str> {
    let dm_start = direct.phys_base().raw();
    let dm_end = dm_start + direct.len();
    let mut p = Planner {
        out,
        n: 0,
        watermark: 0,
        page,
    };

    if !s.is_split() {
        // The port has not carved its image up. Say so by mapping it the only way
        // that is then correct — one read-write-execute blob — rather than guessing
        // boundaries that would be wrong in a way nothing would notice.
        let (start, end) = s.text;
        p.push(dm_start, start.min(dm_end), PageFlags::KERNEL_DATA, "below image");
        p.push(
            start,
            end,
            PageFlags::KERNEL_DATA | PageFlags::EXECUTE,
            "image (unsplit)",
        );
        p.push(end, dm_end, PageFlags::KERNEL_DATA, "above image");
        return Ok(p.n);
    }

    let img_start = s.text.0.min(s.rodata.0).min(s.data.0);
    let img_end = s.text.1.max(s.rodata.1).max(s.data.1);
    if img_start < dm_start || img_end > dm_end {
        return Err("image lies outside the direct map");
    }

    p.push(dm_start, img_start, PageFlags::KERNEL_DATA, "below image");
    p.push(s.text.0, s.text.1, PageFlags::KERNEL_TEXT, "text");
    p.push(s.rodata.0, s.rodata.1, PageFlags::KERNEL_RODATA, "rodata");

    // Data, minus the guard page. The guard is not mapped at all; that hole is the
    // entire mechanism.
    if s.has_stack_guard() {
        let (g0, g1) = s.stack_guard;
        // Rounded *inward*, so rounding can only make the hole smaller and never
        // swallow a page of real data beside it.
        let g0 = g0.div_ceil(page) * page;
        let g1 = (g1 / page) * page;
        p.push(s.data.0, g0.min(s.data.1), PageFlags::KERNEL_DATA, "data");
        p.hole_until(g1);
        p.push(g1.max(s.data.0), s.data.1, PageFlags::KERNEL_DATA, "data above guard");
    } else {
        p.push(s.data.0, s.data.1, PageFlags::KERNEL_DATA, "data");
    }

    p.push(img_end, dm_end, PageFlags::KERNEL_DATA, "above image");
    Ok(p.n)
}

/// Walk the finished tables and confirm they say what was intended.
fn check<A: HasPageTables>(
    c: &dyn EarlyConsole,
    space: &AddressSpace<A>,
    direct: DirectMap,
    s: ImageSections,
    segs: &[Segment],
) -> bool {
    let virt_of = |p: u64| direct.to_virt(PhysAddr::new(p)).map(|v| v.raw()).ok();
    let mut ok = true;

    // Every segment's first and last byte resolves to the frame it was mapped from.
    for seg in segs {
        for probe in [seg.start, seg.end - 1] {
            let Some(v) = virt_of(probe) else {
                ok = false;
                continue;
            };
            match space.translate(v) {
                Some((phys, _)) if phys.raw() == probe => {}
                _ => {
                    c.write_str("\n             translate failed in ");
                    c.write_str(seg.what);
                    ok = false;
                }
            }
        }
    }

    if !s.is_split() {
        c.write_str("image unsplit (no W^X yet), direct map verified");
        return ok;
    }

    // The property W^X exists for: nothing is both writable and executable.
    for seg in segs {
        if seg.flags.contains(PageFlags::WRITE) && seg.flags.contains(PageFlags::EXECUTE) {
            c.write_str("\n             W^X violated in ");
            c.write_str(seg.what);
            ok = false;
        }
    }

    // Read the permissions back out of the tables rather than trusting the plan: the
    // architecture encoded them, and an encoding that loses a bit would otherwise go
    // unnoticed until something failed to fault.
    let probe = |addr: u64, want: PageFlags, deny: PageFlags, what: &'static str| -> bool {
        let Some(v) = virt_of(addr) else { return false };
        match space.translate(v) {
            // `intersects`, not `contains`: the question is whether *anything*
            // forbidden is present, not whether all of it is.
            Some((_, f)) if f.contains(want) && !f.intersects(deny) => true,
            Some((_, f)) => {
                c.write_str("\n             ");
                c.write_str(what);
                c.write_str(" has wrong permissions: ");
                write_flags(c, f);
                false
            }
            None => false,
        }
    };

    ok &= probe(
        s.text.0,
        PageFlags::EXECUTE,
        PageFlags::WRITE,
        "text",
    );
    ok &= probe(
        s.rodata.0,
        PageFlags::READ,
        PageFlags::WRITE | PageFlags::EXECUTE,
        "rodata",
    );
    ok &= probe(
        s.data.0,
        PageFlags::WRITE,
        PageFlags::EXECUTE,
        "data",
    );

    // The guard page must not resolve at all. This is the whole point of it: an
    // overflow has to fault rather than quietly write to whatever is below.
    if s.has_stack_guard() {
        match virt_of(s.stack_guard.0).and_then(|v| space.translate(v)) {
            None => {}
            Some(_) => {
                c.write_str("\n             stack guard is mapped, so it guards nothing");
                ok = false;
            }
        }
        c.write_str("W^X over ");
    } else {
        c.write_str("W^X (no guard page on this port) over ");
    }

    write_kib(c, s.text.1 - s.text.0);
    c.write_str(" text, ");
    write_kib(c, s.rodata.1 - s.rodata.0);
    c.write_str(" rodata, ");
    write_kib(c, s.data.1 - s.data.0);
    c.write_str(" data");
    ok
}

fn describe(e: MapError) -> &'static str {
    match e {
        MapError::NotCanonical => "not canonical",
        MapError::Misaligned => "misaligned",
        MapError::AlreadyMapped => "already mapped",
        MapError::NotMapped => "not mapped",
        MapError::OutOfFrames => "out of frames",
        MapError::WouldSplit => "would split a huge page",
        MapError::BadPhysAddr => "bad physical address",
    }
}

fn write_flags(c: &dyn EarlyConsole, f: PageFlags) {
    c.write_str(if f.contains(PageFlags::READ) { "r" } else { "-" });
    c.write_str(if f.contains(PageFlags::WRITE) { "w" } else { "-" });
    c.write_str(if f.contains(PageFlags::EXECUTE) { "x" } else { "-" });
}

fn write_kib(c: &dyn EarlyConsole, bytes: u64) {
    let mut v = bytes.div_ceil(1024);
    if v == 0 {
        c.write_bytes(b"0");
    } else {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        c.write_bytes(&buf[i..]);
    }
    c.write_bytes(b"K");
}
