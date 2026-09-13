//! Building the kernel's own address space, with W^X over the image.
//!
//! This is the first real user of the shared walker: real frames from the frame
//! allocator, real section boundaries from the linker, on the actual machine. Up to
//! now each port built a bootstrap map in its own private code, because an `arch`
//! unit may not depend on a `core` unit and therefore cannot reach `mm::paged`. The
//! kernel image can reach both, so this is where the two halves meet.
//!
//! # Verified before it is installed
//!
//! Installing a new set of tables is the single most unrecoverable thing a kernel can
//! get wrong: the instruction after the switch has to be fetchable from the map that
//! was just installed, and if it is not there is no fault handler, no console, and no
//! evidence. So every claim about the space is verified through
//! [`AddressSpace::translate`] first, and the caller installs it only if all of them
//! held. A space that fails verification is reported and never becomes live.
//!
//! For a while the space was built, verified, and then left unused, with the machine
//! still running on its bootstrap tables. That proved the tables were right and
//! protected nothing: the guard page was a hole in a map the CPU was not using. What
//! it lacked was the devices. RAM and the image are described by the memory map and the
//! linker script. A device is described by neither, and a device left out is a fault on
//! the first register access after the switch. On aarch64, where the console is MMIO,
//! that fault has nowhere to print. Each port now names its windows through
//! `arch::kspace::device_windows`, and they are mapped here with everything else.

use hal::paging::{DeviceWindow, HasPageTables, ImageSections, MapError, PageFlags};
use hal::{Arch, EarlyConsole, PhysAddr};
use mm::DirectMap;
use mm::frame::Frame;
use mm::paged::{AddressSpace, FrameSource};
use mm::phys::FrameAllocator;

/// Adapts the frame allocator to what the walker needs.
///
/// The walker asks for *zeroed* frames because an absent entry is all-zero on every
/// architecture we support, so a zeroed frame is a valid empty table. The frame
/// allocator does not zero — it hands out whatever was there — so the zeroing happens
/// here, through the direct map, which is the only way to touch a physical frame.
pub struct Frames<'a, 'store, A: Arch> {
    pub alloc: &'a mut FrameAllocator<'store, A>,
    pub direct: DirectMap,
    /// The lowest and highest-ending frame handed out, as `[lo, hi)`. Once the space is
    /// live these frames are the running page tables, and anything else that builds a
    /// frame pool from the loader's map has to be told to keep out of them.
    pub span: (u64, u64),
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
        let (lo, hi) = self.span;
        let start = frame.start().raw();
        let end = start + A::PAGE_SIZE as u64;
        self.span = if lo == hi {
            (start, end)
        } else {
            (lo.min(start), hi.max(end))
        };
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

/// At most: below-image, text, rodata, data-before-guard, data-after-guard, one run per
/// thread stack, and above-image. Guard pages are holes rather than entries.
const MAX_SEGMENTS: usize = 8 + MAX_THREAD_STACKS;

/// Thread stacks the planner will cut guard pages for. A port that lays out more is
/// refused, not silently left with unguarded stacks.
const MAX_THREAD_STACKS: usize = 16;

/// A kernel address space that passed verification and has not been installed yet.
pub struct Verified<A: HasPageTables> {
    pub space: AddressSpace<A>,
    /// `[lo, hi)` around every frame its tables occupy.
    pub tables: (u64, u64),
}

/// Build the kernel address space and check it.
///
/// `devices` are mapped beside the direct map, and every address in `must_reach` has to
/// translate: those are things the kernel reads after the switch that neither the
/// memory map nor the image accounts for, such as the loader's boot information. Returns
/// the space only if every claim held, so a caller cannot install one that did not.
pub fn build_and_verify<A: HasPageTables>(
    c: &dyn EarlyConsole,
    alloc: &mut FrameAllocator<'_, A>,
    direct: DirectMap,
    sections: ImageSections,
    devices: &[DeviceWindow],
    must_reach: &[u64],
) -> Option<Verified<A>> {
    let mut frames = Frames {
        alloc,
        direct,
        span: (0, 0),
    };
    let mut space = match AddressSpace::<A>::new(direct, &mut frames) {
        Ok(s) => s,
        Err(_) => {
            c.write_str("no frame for the root table");
            return None;
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
            return None;
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
                return None;
            }
        };
        if let Err(e) = space.map(virt, PhysAddr::new(seg.start), len, seg.flags, &mut frames) {
            c.write_str("\n             map ");
            c.write_str(seg.what);
            c.write_str(" failed: ");
            c.write_str(describe(e));
            return None;
        }
    }

    if !map_devices(c, &mut space, &mut frames, devices) {
        return None;
    }

    let mut ok = check(c, &space, direct, sections, &segs[..n]);
    ok &= check_devices(c, &space, devices);
    for &addr in must_reach {
        let reached = usize::try_from(addr).ok().and_then(|v| space.translate(v));
        if reached.map(|(p, _)| p.raw()) != Some(addr) {
            c.write_str("\n             boot data at ");
            write_kib(c, addr / 1024);
            c.write_str(" is outside the kernel space");
            ok = false;
        }
    }
    let tables = frames.span;
    ok.then_some(Verified { space, tables })
}

/// Map each device window at its own physical address, never executable.
///
/// Rounded outward to whole pages: a register block that starts mid-page still needs
/// the whole page mapped, and a device window is not a place where rounding can grant
/// anything to a neighbour, because nothing else is mapped beside it.
fn map_devices<A: HasPageTables>(
    c: &dyn EarlyConsole,
    space: &mut AddressSpace<A>,
    frames: &mut Frames<'_, '_, A>,
    devices: &[DeviceWindow],
) -> bool {
    let mask = A::PAGE_SIZE as u64 - 1;
    for d in devices {
        let start = d.phys & !mask;
        let end = d.phys.saturating_add(d.len).saturating_add(mask) & !mask;
        let (Ok(virt), Ok(len)) = (usize::try_from(start), usize::try_from(end - start)) else {
            c.write_str("\n             device ");
            c.write_str(d.what);
            c.write_str(" is not addressable");
            return false;
        };
        let flags = PageFlags::KERNEL_DATA | PageFlags::DEVICE;
        if let Err(e) = space.map(virt, PhysAddr::new(start), len, flags, frames) {
            c.write_str("\n             map device ");
            c.write_str(d.what);
            c.write_str(" failed: ");
            c.write_str(describe(e));
            return false;
        }
    }
    true
}

/// Every device window reads back as device memory, writable and not executable.
fn check_devices<A: HasPageTables>(
    c: &dyn EarlyConsole,
    space: &AddressSpace<A>,
    devices: &[DeviceWindow],
) -> bool {
    let mut ok = true;
    for d in devices {
        let last = d.phys + d.len.max(1) - 1;
        for probe in [d.phys, last] {
            let seen = usize::try_from(probe).ok().and_then(|v| space.translate(v));
            let right = match seen {
                Some((p, f)) => {
                    // Execute is only demanded off where the CPU can express it, for the
                    // reason `check` gives.
                    p.raw() == probe
                        && f.contains(PageFlags::DEVICE | PageFlags::WRITE)
                        && !(A::can_forbid_execute() && f.contains(PageFlags::EXECUTE))
                }
                None => false,
            };
            if !right {
                c.write_str("\n             device ");
                c.write_str(d.what);
                c.write_str(" is not mapped as device memory");
                ok = false;
            }
        }
    }
    ok
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
        // Masks, not division: `page` is a power of two, and u64 division on a 32-bit
        // target is a runtime-library call. This one happens to fold into a shift
        // today because the page size is a constant; relying on that for a link to
        // succeed is how the previous one broke.
        let mask = self.page - 1;
        let lo = (start & !mask).max(self.watermark);
        let hi = end.saturating_add(mask) & !mask;
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
    // Page zero is never mapped, so a null pointer faults on every port rather than
    // reading whatever the machine keeps there. On a PC that is the real-mode interrupt
    // vector table; nothing reads it after boot, and the frame allocator never hands it
    // out (`LOW_MEMORY`). Starting the watermark above it is the whole mechanism.
    let mut p = Planner {
        out,
        n: 0,
        watermark: page,
        page,
    };

    if !s.is_split() {
        // The port has not carved its image up. Say so by mapping it the only way
        // that is then correct — one read-write-execute blob — rather than guessing
        // boundaries that would be wrong in a way nothing would notice.
        let (start, end) = s.text;
        p.push(dm_start, start.min(dm_end), PageFlags::KERNEL_DATA, "below image");
        p.push(start, end, PageFlags::KERNEL_DATA | PageFlags::EXECUTE, "image (unsplit)");
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

    // Data, minus every guard page: the boot stack's and one per thread stack. A guard
    // is not mapped at all; that hole is the entire mechanism. The holes are visited in
    // address order, and each is rounded *inward*, so rounding can only make a hole
    // smaller and never swallow a page of real data beside it.
    let t = s.thread_stacks;
    if t.count() > MAX_THREAD_STACKS {
        return Err("more thread stacks than the planner cuts guards for");
    }
    let mut holes = [(0u64, 0u64); 1 + MAX_THREAD_STACKS];
    let mut nh = 0;
    if s.has_stack_guard() {
        holes[nh] = s.stack_guard;
        nh += 1;
    }
    for i in 0..t.count() {
        if let Some(g) = t.guard_range(i) {
            holes[nh] = g;
            nh += 1;
        }
    }
    holes[..nh].sort_unstable();
    let mask = page - 1;
    let mut from = s.data.0;
    for &(g0, g1) in &holes[..nh] {
        let g0 = g0.saturating_add(mask) & !mask;
        let g1 = g1 & !mask;
        if g1 <= g0 || g1 <= s.data.0 || g0 >= s.data.1 {
            // Outside the data, as the x86_64 boot guard is, or less than a page.
            continue;
        }
        p.push(from, g0, PageFlags::KERNEL_DATA, "data");
        p.hole_until(g1);
        from = g1;
    }
    p.push(from.max(s.data.0), s.data.1, PageFlags::KERNEL_DATA, "data");

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

    // Where the CPU cannot forbid execution, every mapping reads back executable no
    // matter what was requested. That is a limit of the machine, not a bug in the
    // kernel, and failing on it would produce a failure nobody can fix. So the
    // no-execute half is only demanded when it can be delivered — and the report says
    // plainly which half is holding, so a partial guarantee is never read as a full one.
    let nx = A::can_forbid_execute();
    let exec_deny = if nx {
        PageFlags::EXECUTE
    } else {
        PageFlags::empty()
    };

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

    ok &= probe(s.text.0, PageFlags::EXECUTE, PageFlags::WRITE, "text");
    ok &= probe(s.rodata.0, PageFlags::READ, PageFlags::WRITE.union(exec_deny), "rodata");
    ok &= probe(s.data.0, PageFlags::WRITE, exec_deny, "data");

    // Nor may page zero, so that a null dereference is a fault.
    if space.translate(0).is_some() {
        c.write_str("\n             page 0 is mapped, so a null pointer reads memory");
        ok = false;
    }

    // Every thread stack's guard must not resolve, and the stack above it must. Counted
    // rather than reported per slot: one wrong rule gets every slot wrong the same way.
    let t = s.thread_stacks;
    let (mut guards_mapped, mut stacks_unmapped) = (0, 0);
    for i in 0..t.count() {
        let (Some((g, _)), Some((bottom, top))) = (t.guard_range(i), t.stack_range(i)) else {
            continue;
        };
        if virt_of(g).and_then(|v| space.translate(v)).is_some() {
            guards_mapped += 1;
        }
        let writable = |a: u64| {
            virt_of(a)
                .and_then(|v| space.translate(v))
                .is_some_and(|(_, f)| f.contains(PageFlags::WRITE))
        };
        if !writable(bottom) || !writable(top - 1) {
            stacks_unmapped += 1;
        }
    }
    if guards_mapped > 0 {
        c.write_str("\n             thread stack guards mapped: ");
        crate::write_usize(c, guards_mapped);
        ok = false;
    }
    if stacks_unmapped > 0 {
        c.write_str("\n             thread stacks not mapped writable: ");
        crate::write_usize(c, stacks_unmapped);
        ok = false;
    }

    // Errors above end mid-line; the summary gets its own line after any of them, so a
    // failure reads as a list of problems followed by what was checked rather than
    // running the last permission string into the summary.
    if !ok {
        c.write_str("\n             ");
    }

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
        c.write_str(if nx {
            "W^X over "
        } else {
            "no-write only (CPU has no NX) over "
        });
    } else {
        c.write_str(if nx {
            "W^X (no guard page on this port) over "
        } else {
            "no-write only (CPU has no NX, no guard page) over "
        });
    }

    write_kib(c, s.text.1 - s.text.0);
    c.write_str(" text, ");
    write_kib(c, s.rodata.1 - s.rodata.0);
    c.write_str(" rodata, ");
    write_kib(c, s.data.1 - s.data.0);
    c.write_str(" data");
    if t.count() > 0 {
        c.write_str(", ");
        crate::write_usize(c, t.count());
        c.write_str(" guarded thread stacks");
    }
    ok
}

/// Walk the tables the CPU is actually using, found through its root register.
///
/// Everything [`check`] established was about a data structure. This asks the same
/// questions of whatever the register names, so a switch that silently did not happen,
/// or happened to some other table, fails here rather than passing on the strength of a
/// structure nobody installed.
pub fn check_live<A: HasPageTables>(
    c: &dyn EarlyConsole,
    direct: DirectMap,
    s: ImageSections,
) -> bool {
    // SAFETY: `A::root()` is the table the caller just installed, which was built through
    // `direct` and is reachable through it; nothing modifies it while this runs.
    let live = unsafe { AddressSpace::<A>::from_root(A::root(), direct) };
    let at = |addr: u64| usize::try_from(addr).ok().and_then(|v| live.translate(v));
    let mut ok = true;

    let text = at(s.text.0);
    if !text.is_some_and(|(_, f)| f.contains(PageFlags::EXECUTE) && !f.contains(PageFlags::WRITE)) {
        c.write_str("live text is not read-execute, ");
        ok = false;
    }
    if !s.is_split() {
        c.write_str("image unsplit");
        return ok;
    }
    if !at(s.rodata.0).is_some_and(|(_, f)| !f.contains(PageFlags::WRITE)) {
        c.write_str("live rodata is writable, ");
        ok = false;
    }
    if at(0).is_some() {
        c.write_str("live page 0 is MAPPED, ");
        ok = false;
    }
    let t = s.thread_stacks;
    let thread_guards_mapped = (0..t.count())
        .filter_map(|i| t.guard_range(i))
        .any(|(g, _)| at(g).is_some());
    if thread_guards_mapped {
        c.write_str("a live thread stack guard is MAPPED, ");
        ok = false;
    }
    if s.has_stack_guard() {
        if at(s.stack_guard.0).is_some() {
            c.write_str("live guard page is MAPPED");
            ok = false;
        } else {
            c.write_str("guard pages and page 0 unmapped in the live tables");
        }
    } else {
        c.write_str("no guard page on this port");
    }
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
    c.write_str(if f.contains(PageFlags::READ) {
        "r"
    } else {
        "-"
    });
    c.write_str(if f.contains(PageFlags::WRITE) {
        "w"
    } else {
        "-"
    });
    c.write_str(if f.contains(PageFlags::EXECUTE) {
        "x"
    } else {
        "-"
    });
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
