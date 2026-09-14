//! The kernel image entry point.
//!
//! Phase 0: bring up the early console, say who we are, and stop. Everything the
//! banner prints comes from either the `hal` traits or the generated configuration,
//! so it is a live check that both paths work rather than a hardcoded string.

#![no_std]
#![no_main]
// A shared mutable static with a documented invariant. `static mut` is forbidden by
// docs/coding-standards.md; this is the replacement it names.
#![feature(sync_unsafe_cell)]

mod bootargs;
mod clock;
mod crash;
#[cfg(CONFIG_MM_PAGED)]
mod demand;
mod epoch;
mod heap;
mod kheap;
mod lockcheck;
#[cfg(CONFIG_MM_PAGED)]
mod modules;
// The scheduler's multiprocessor half: a run queue per CPU, the scheduler lock, IPIs and
// TLB shootdown with `SMP`; a stub costing nothing without it. Shootdown rides on the
// paged memory model, so a flat kernel is uniprocessor here whatever `SMP` says.
#[cfg(all(CONFIG_SMP, CONFIG_MM_PAGED))]
#[path = "mp_smp.rs"]
mod mp;
#[cfg(not(all(CONFIG_SMP, CONFIG_MM_PAGED)))]
#[path = "mp_up.rs"]
mod mp;
mod persist;
mod preempt;
mod serial;
mod shared;
#[cfg(all(CONFIG_SMP, CONFIG_MM_PAGED))]
mod shootdown;
#[cfg(CONFIG_MM_PAGED)]
mod space;
// The stress run on a paged kernel; on a flat one, the same calls doing nothing.
#[cfg(CONFIG_MM_PAGED)]
mod stress;
#[cfg(CONFIG_MM_FLAT)]
#[path = "stress_off.rs"]
mod stress;
// The driver-isolation prototype where a domain can exist; elsewhere the same call doing
// nothing. See `docs/isolation.md`.
#[cfg(CONFIG_DRIVER_ISOLATION)]
mod isolation;
#[cfg(not(CONFIG_DRIVER_ISOLATION))]
#[path = "isolation_off.rs"]
mod isolation;
// Confining the disk's DMA with a VT-d IOMMU; without one, the same calls doing nothing.
#[cfg(CONFIG_IOMMU)]
mod iommu;
#[cfg(not(CONFIG_IOMMU))]
#[path = "iommu_off.rs"]
mod iommu;
// The block check on a paged kernel; on a flat one, the same call doing nothing.
#[cfg(CONFIG_MM_PAGED)]
mod block;
#[cfg(CONFIG_MM_FLAT)]
#[path = "block_off.rs"]
mod block;
#[cfg(CONFIG_MM_PAGED)]
mod net;
#[cfg(CONFIG_MM_FLAT)]
#[path = "net_off.rs"]
mod net;
// The filesystem check on a paged kernel; on a flat one, the same call doing nothing.
#[cfg(CONFIG_MM_PAGED)]
mod fs;
#[cfg(CONFIG_MM_FLAT)]
#[path = "fs_off.rs"]
mod fs;
mod timekeeping;
// The native userspace slice: only on a paged kernel with a userspace port.
#[cfg(CONFIG_USERSPACE)]
mod objects;
#[cfg(CONFIG_USERSPACE)]
mod procs;
#[cfg(CONFIG_USERSPACE)]
mod spawn;
#[cfg(CONFIG_USERSPACE)]
mod userproc;
#[cfg(CONFIG_USERSPACE)]
mod wait;
#[cfg(CONFIG_USERSPACE)]
mod waits;
// ABI_LINUX depends on USERSPACE, so the personality is only ever built on a process.
#[cfg(CONFIG_ABI_LINUX)]
mod personality;
#[cfg(not(CONFIG_ABI_LINUX))]
#[path = "personality_off.rs"]
mod personality;

// The memory model's part of bring-up: the kernel address space, demand paging and the
// test modes that need a guard page on a paged kernel; the flat region allocator on one
// without an MMU. Selected here, once, at module level, which is where `cfg` belongs. The
// rest of `kmain` calls `model::` and never learns which it got.
#[cfg(CONFIG_MM_PAGED)]
#[path = "model_paged.rs"]
mod model;
#[cfg(CONFIG_MM_FLAT)]
#[path = "model_flat.rs"]
mod model;

use core::cell::SyncUnsafeCell;

use arch::Cpu;
use model::Live;

/// The lock family for state the whole kernel shares. Named once, here, because the image
/// is the one place allowed to name the architecture. See `sync::family`.
///
/// A ticket spinlock where the target has compare-and-swap, which is every port that can
/// have a second CPU. A core with no atomic instructions at all — rv32i — cannot have
/// one, and cannot have a second CPU either, so there interrupt masking *is* the lock.
#[cfg(target_has_atomic = "32")]
type Locks = sync::Spin<Cpu>;
#[cfg(not(target_has_atomic = "32"))]
type Locks = sync::Irq<Cpu>;
use boot_protocol::{MemoryKind, MemoryRegion};
use hal::{Arch, EarlyConsole};
use mm::phys::{FrameAllocator, bitmap_bytes};

/// A 64-bit counter the image's checks can keep in a `static`: the real atomic where the
/// target has one.
#[cfg(target_has_atomic = "64")]
type AtomicU64 = core::sync::atomic::AtomicU64;
/// On a uniprocessor without 64-bit atomics — rv32imac has none — a `u64` read and written
/// with interrupts masked, which has the same methods.
#[cfg(not(target_has_atomic = "64"))]
type AtomicU64 = sync::IrqU64<Cpu>;

/// Counters and flags the image's checks keep in a `static` and update from a handler.
///
/// The real atomics where the target has a read-modify-write to do it in one instruction.
/// On rv32i it has none at any width: a naturally aligned word still loads and stores
/// atomically, so `core`'s types exist, but `fetch_add`, `fetch_or` and `swap` do not.
/// The masked stand-ins have the same methods, which is what lets the code above this
/// line be written once.
#[cfg(target_has_atomic = "32")]
type AtomicU32 = core::sync::atomic::AtomicU32;
#[cfg(not(target_has_atomic = "32"))]
type AtomicU32 = sync::IrqU32<Cpu>;
#[cfg(target_has_atomic = "ptr")]
type AtomicUsize = core::sync::atomic::AtomicUsize;
#[cfg(not(target_has_atomic = "ptr"))]
type AtomicUsize = sync::IrqUsize<Cpu>;
#[cfg(target_has_atomic = "8")]
type AtomicBool = core::sync::atomic::AtomicBool;
#[cfg(not(target_has_atomic = "8"))]
type AtomicBool = sync::IrqBool<Cpu>;

/// A value built once and then shared: through a compare-and-swap claim where there is
/// one, and through interrupt masking on a uniprocessor that has none.
#[cfg(target_has_atomic = "8")]
type BootOnce<T> = sync::CasOnce<T, Cpu>;
#[cfg(not(target_has_atomic = "8"))]
type BootOnce<T> = sync::IrqOnce<T, Cpu>;

/// Entry from the architecture's boot code, which has already established a stack,
/// whatever execution mode the target needs, and an identity mapping.
///
/// `boot_arg` is whatever the platform's loader left in the first argument register:
/// the multiboot info pointer on x86, a device tree pointer on aarch64 and riscv32, or
/// the boot protocol's own structure when kinboot-efi started the image. The
/// configuration's `bootinfo` provider knows which.
///
/// # Safety
/// Called exactly once, by the architecture's boot code, with interrupts masked.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(boot_arg: u64) -> ! {
    // SAFETY: first and only initialisation of COM1, before any other writer exists.
    unsafe { arch::EARLY.init() };

    let (boot, live) = banner(boot_arg);
    let c = &arch::EARLY;

    model::test_modes(c, boot);

    // In a production image this is the no-op provider and folds away entirely; the
    // test image gets the real one. Which is linked is a configuration question, so
    // there is no cfg here.
    //
    // The kernel's live page tables are reserved as well. The suite builds its own frame
    // pool from the loader's map, and that map does not know those frames are in use:
    // without this its first allocation is a page table, and its read/write check
    // overwrites a translation the CPU is running on.
    let (img_start, img_end) = arch::image_range();
    let reserved = [
        (0, LOW_MEMORY),
        (img_start, img_end.saturating_sub(img_start)),
        (live.tables.0, live.tables.1.saturating_sub(live.tables.0)),
        // The kernel heap lives on after boot, and its frames hold live objects.
        kheap::region(),
        // So do the stress run's pools, in an image that has them.
        stress::region(),
        // And the frames the scheduled processes are built from.
        model::process_region(),
    ];
    let ok = selftest::run_all::<Cpu>(c, boot_arg, &reserved);
    if selftest::PRESENT {
        c.write_str("\n");
    }

    // The suite writes to frames it allocates. Walk the live tables again afterwards,
    // so that a frame pool which overlaps them is a failure rather than a latent
    // corruption: x86 keeps running on cached translations after an entry is
    // overwritten, and the damage would surface much later, somewhere else.
    let intact = live.still_intact(c);

    crash::if_configured();

    // Both halves gate the exit status. Until this line existed, only the in-kernel
    // suite did: the banner computed verdicts for paging, interrupts, memory and the
    // kernel address space, printed them, and discarded all four — so a W^X regression
    // printed FAILED and still exited as a pass. A check that cannot change the outcome
    // is a log line.
    let verdict = ok && boot != Check::Failed && intact;
    // A loader that counts boots hears from here whether this one worked; one that fell
    // back to safe mode is held to having done so. Every other image's verdict stands.
    let verdict = lastgood::settle(c, boot_arg, verdict);

    // A test image reports and stops. A stress image, and any image with no channel to
    // report through, goes on: everything above assumed one masked boot thread and has
    // finished, so from here the scheduler owns the CPU.
    if kconfig::QEMU_EXIT && !kconfig::STRESS_TEST {
        finish(verdict);
    }
    if !verdict {
        c.write_str("\nbring-up failed; not starting the scheduler\n");
        finish(false);
    }
    persist::run(c)
}

/// The outcome of a bring-up check.
///
/// Three states rather than a bool, for the same reason the in-kernel suite reports
/// "skip" separately: a check that could not run is a different claim from one that
/// ran and passed. Folding "skipped" into "passed" hides coverage that is missing;
/// folding it into "failed" turns a known, reported gap — aarch64 has no memory map yet
/// — into a red build nobody can fix.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Check {
    Passed,
    Skipped,
    Failed,
}

impl Check {
    fn from_ok(ok: bool) -> Check {
        if ok { Check::Passed } else { Check::Failed }
    }

    /// Combine two outcomes: any failure wins, then any skip.
    fn and(self, other: Check) -> Check {
        match (self, other) {
            (Check::Failed, _) | (_, Check::Failed) => Check::Failed,
            (Check::Skipped, _) | (_, Check::Skipped) => Check::Skipped,
            _ => Check::Passed,
        }
    }
}

// How the kernel stops depends on the configuration, so the choice is made once, at
// module level, where `cfg` belongs. Writing it as two `cfg`s inside `kmain` was the
// first thing `kbuild lint` caught — in this file, which is a fair indication that
// the rule needs a checker rather than good intentions.

/// Stop, reporting the outcome through the emulator's result channel.
#[cfg(CONFIG_QEMU_EXIT)]
fn finish(ok: bool) -> ! {
    arch::exit_emulator(ok)
}

/// Stop. A production image has no channel to report through and simply halts.
#[cfg(not(CONFIG_QEMU_EXIT))]
fn finish(_ok: bool) -> ! {
    Cpu::halt()
}

/// The bring-up report. Returns its verdict and the kernel address space it installed.
fn banner(boot_arg: u64) -> (Check, Live) {
    let c = &arch::EARLY;
    c.write_str("\nKinTane\n");
    c.write_str("  build id   ");
    buildid::write(c);
    c.write_str("\n  arch       ");
    c.write_str(Cpu::NAME);
    c.write_str("\n  page size  ");
    write_usize(c, Cpu::PAGE_SIZE);
    c.write_str("\n  paging     ");
    model::write_translation(c);
    c.write_str("\n  boot arg   ");
    write_hex(c, boot_arg);

    c.write_str("\n  config     SMP=");
    c.write_str(if kconfig::SMP { "y" } else { "n" });
    c.write_str(" MM_PAGED=");
    c.write_str(if kconfig::MM_PAGED { "y" } else { "n" });
    c.write_str(" DEBUG=");
    c.write_str(if kconfig::DEBUG_BUILD { "y" } else { "n" });
    // Early, while the loader's memory is certainly still where it left it, and before the
    // memory map is built on, so safe mode's verbose map comes before anything uses it.
    c.write_str("\n  cmdline    ");
    let args = bootargs::check(c, boot_arg);
    // Before `memory`, because the kernel's address space maps the device windows the
    // drivers found here claim, and before interrupts, because this is where the
    // interrupt controller is bound. Before `pagetable` too, because that check leaves
    // its own tables installed, which identity-map only the first gigabyte: discovery on
    // a PC reads the PCI Express window and the APICs just below 4 GiB, and on those
    // tables it read RAM aliases instead, as 32 functions all of vendor zero.
    c.write_str("\n  devices    ");
    // SAFETY: once, with interrupts masked, on the boot identity map, with `boot_arg` as
    // the boot code passed it — `discover`'s contract on every provider.
    let devices = match unsafe { platform::discover(c, boot_arg) } {
        None => Check::Skipped,
        Some(ok) => Check::from_ok(ok),
    };

    // Before `memory`, because this is where the architecture turns on the features
    // the kernel's own address space depends on — NXE among them. Building that space
    // first produced data mappings with no NX, which the space's own check caught.
    c.write_str("\n  pagetable  ");
    let paging = model::paging_selftest(c);

    let (mem, live) = memory(c, boot_arg);

    c.write_str("\n  interrupts ");
    // The architecture brings up its own interrupt path; the image only reports the
    // verdict. Nothing here names a machine.
    let irq_ok = arch::interrupt_selftest(c);
    c.write_str(if irq_ok { " ok" } else { "" });

    c.write_str("\n  threads    ");
    // Gating now that every port switches. Until all three had it, a missing context
    // switch was an honest gap rather than a regression; from here, one breaking is a
    // failure. Every register falsification the ports ran exited 33 before this line,
    // which is precisely the kind of check that cannot change an outcome.
    let switch_ok = arch::context_switch_selftest(c);

    // After interrupts, because the check waits through timer interrupts.
    c.write_str("\n  clock      ");
    let clock = clock::check(c);

    // After the clock, which bounds its wait, and before preemption installs the tick's
    // hook: a device interrupt taken while it waits must return to it.
    c.write_str("\n  serial     ");
    let serial = serial::check(c);
    // For the same reason as the serial check, and after it: the disk's interrupt is taken
    // while this waits, before the tick's hook is installed.
    c.write_str("\n  block irq  ");
    let block_irq = block::interrupt_check(c);
    // After it, and for the same reason: the remapped interrupt is taken while this waits.
    c.write_str("\n  remap      ");
    let remap = block::remap_check(c);
    // For the same reason again: the card's receive interrupt is taken while this waits.
    c.write_str("\n  net        ");
    let net = net::check(c);
    c.write_str("\n  preempt    ");
    // Built on both of the above, so it runs only when both passed. Their failures
    // already gate the verdict, and a scheduler check on a broken switch or a silent
    // timer would hang rather than report.
    let preempt = if irq_ok && switch_ok {
        preempt::demonstrate(c)
    } else {
        c.write_str("skipped: needs working interrupts and context switch");
        Check::Skipped
    };

    c.write_str("\n  backtrace  ");
    let backtrace_ok = backtrace_check(c);

    c.write_str("\n  smp        ");
    // SAFETY: once, masked, after the kernel space and interrupt path are up and the
    // preemption check has stopped the tick: `start_secondaries`'s contract.
    let smp = unsafe { platform::start_secondaries(c) }.map_or(Check::Skipped, Check::from_ok);
    // After the secondaries are up, because it moves the disk's interrupt to one of them.
    c.write_str("\n  block cpu  ");
    let block_cpu = block::cpu_check(c);

    // After the secondaries are up, whose readers it races.
    c.write_str("\n  epoch      ");
    let epochs = epoch::check(c);
    // With the secondaries up and nothing scheduled on them yet.
    c.write_str("\n  shootdown  ");
    let shootdown = mp::check_shootdown(c, live);

    // Last, so it sees every lock the checks above took.
    c.write_str("\n  lockdep    ");
    let lockdep = lockcheck::verdict(c);

    c.write_str("\n\nreached kmain\n");
    let verdict = paging
        .and(args)
        .and(devices)
        .and(mem)
        .and(Check::from_ok(irq_ok))
        .and(Check::from_ok(switch_ok))
        .and(clock)
        .and(serial)
        .and(block_irq)
        .and(remap)
        .and(net)
        .and(preempt)
        .and(Check::from_ok(backtrace_ok))
        .and(smp)
        .and(block_cpu)
        .and(epochs)
        .and(shootdown)
        .and(lockdep);
    (verdict, live)
}

/// Walk the frame-pointer chain from here and check it is the one boot built.
///
/// A crash report is read only after something has gone wrong, so an unwinder that
/// quietly stopped working would be found at the worst possible moment. This walks the
/// live chain on every boot and requires what a working one must show: it reaches the
/// null frame `_start` planted, through at least the frames between here and `kmain`,
/// and every return address it read is inside `.text`.
fn backtrace_check(c: &dyn EarlyConsole) -> bool {
    let chain = arch::backtrace::chain();
    write_usize(c, chain.frames);
    c.write_str(" frames to ");
    c.write_str(chain.stop.describe());
    // `chain`, `backtrace_check`, `banner` and `kmain`, less whatever the optimiser
    // was allowed to fold together. Two is the floor that still proves a walk
    // happened past the frame that started it.
    let ok = chain.stop == unwind::Stop::NullFrame && chain.frames >= 2 && chain.stray.is_none();
    if let Some(ra) = chain.stray {
        c.write_str(", return address outside .text: ");
        write_hex(c, ra as u64);
    }
    c.write_str(if ok { " ok" } else { " FAILED" });
    ok
}

/// Room for the loader's memory map. QEMU reports a handful of regions; real
/// firmware reports more, and running out is reported rather than silently truncating
/// — a short memory map is one the allocator would act on.
const MAX_REGIONS: usize = 64;

/// Backing store for the frame allocator's bitmaps. 32 KiB covers a 512 MiB usable
/// span at a 4 KiB page (two bits per frame, two arrays). Too small is an error the
/// caller prints, never a truncated pool.
const STORE_BYTES: usize = kconfig::FRAME_BITMAP_KIB * 1024;

/// Memory below this is never handed out on a PC: real-mode interrupt vectors, the
/// BIOS data area, and whatever firmware left behind. Reserving it where it is not
/// RAM — aarch64 starts at 0x4000_0000 — costs nothing, because reserving frames
/// outside the pool reserves none.
const LOW_MEMORY: u64 = 1024 * 1024;

/// SAFETY INVARIANT: written only from `memory`, which runs once, on one CPU, before
/// any other task exists. When SMP arrives this becomes a per-CPU or locked
/// allocation and this static goes away.
static STORE: SyncUnsafeCell<[u8; STORE_BYTES]> = SyncUnsafeCell::new([0; STORE_BYTES]);

/// Report what the loader said about memory, then prove the frame allocator works on
/// it by handing out a frame and giving it back. Also returns the kernel address space
/// the memory model's `kernel_space` installed.
fn memory(c: &dyn EarlyConsole, boot_arg: u64) -> (Check, Live) {
    c.write_str("\n  memory map ");
    c.write_str(bootinfo::SOURCE);

    let mut regions = [MemoryRegion {
        start: 0,
        len: 0,
        kind: 0,
        _reserved: 0,
    }; MAX_REGIONS];
    // SAFETY: `boot_arg` is the value the architecture's boot code passed to `kmain`,
    // which is exactly the contract `memory_regions` states. The structure it names is
    // in loader memory, which is still mapped and not yet reclaimed.
    let n = match unsafe { bootinfo::memory_regions(boot_arg, &mut regions) } {
        Ok(n) => n,
        Err(e) => {
            c.write_str(" (");
            c.write_str(match e {
                bootinfo::Error::NoLoader => "no loader",
                bootinfo::Error::NoMemoryMap => "no map",
                bootinfo::Error::Malformed { .. } => "malformed",
                bootinfo::Error::TooManyRegions { .. } => "too many regions",
            });
            c.write_str(")");
            // A port with no map source yet skips. A map that is present and broken fails,
            // and so does a missing one in a configuration built for a KinTane loader:
            // there the handover *is* the thing under test, and a boot that lost it must not
            // exit as a pass.
            let broken = matches!(
                e,
                bootinfo::Error::Malformed { .. } | bootinfo::Error::TooManyRegions { .. }
            );
            let verdict = if broken || kconfig::BOOT_KINBOOT {
                Check::Failed
            } else {
                Check::Skipped
            };
            return (verdict, Live::NONE);
        }
    };

    let usable: u64 = regions[..n]
        .iter()
        .filter(|r| r.kind == MemoryKind::Usable as u32)
        .map(|r| r.len)
        .sum();
    c.write_str(", ");
    write_usize(c, n);
    c.write_str(" regions, ");
    write_usize(c, (usable / (1024 * 1024)) as usize);
    c.write_str(" MiB usable");

    let needed = match bitmap_bytes::<Cpu>(&regions[..n]) {
        Ok(b) => b,
        Err(_) => {
            c.write_str("\n  frames     unusable map");
            return (Check::Failed, Live::NONE);
        }
    };
    if needed > STORE_BYTES {
        c.write_str("\n  frames     need ");
        write_usize(c, needed);
        c.write_str(" bytes of bitmap, have ");
        write_usize(c, STORE_BYTES);
        c.write_str(" (raise FRAME_BITMAP_KIB)");
        return (Check::Failed, Live::NONE);
    }

    // SAFETY: the only write to STORE, from the single-threaded boot path before any
    // other execution context exists (see the invariant on the static). `needed` was
    // checked against STORE_BYTES above, so the slice is within the allocation.
    // Built from the raw pointer rather than by indexing through it, which would
    // create a reference to the whole array first.
    let store: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(STORE.get().cast::<u8>(), needed) };
    let mut frames = match FrameAllocator::<Cpu>::new(&regions[..n], store) {
        Ok(f) => f,
        Err(_) => {
            c.write_str("\n  frames     allocator rejected the map");
            return (Check::Failed, Live::NONE);
        }
    };

    // The loader's map describes the machine, not what is already living in it.
    // Nothing in it says "the kernel is here", and the low megabyte on a PC holds the
    // interrupt vector table and BIOS data. Both must be taken out of the pool before
    // a single frame is handed out — without this the allocator's first answer is
    // physical zero, which is exactly what it was before this reservation existed.
    let (img_start, img_end) = arch::image_range();
    let reserved_low = frames
        .reserve(hal::PhysAddr::new(0), LOW_MEMORY)
        .unwrap_or(0);
    let reserved_img = frames
        .reserve(hal::PhysAddr::new(img_start), img_end.saturating_sub(img_start))
        .unwrap_or(0);

    let stats = frames.stats();
    c.write_str("\n  reserved   ");
    write_usize(c, reserved_low);
    c.write_str(" low + ");
    write_usize(c, reserved_img);
    c.write_str(" image frames");
    c.write_str("\n  frames     ");
    write_usize(c, stats.total);
    c.write_str(" total, ");
    write_usize(c, stats.free);
    c.write_str(" free");

    let (space, live) = model::kernel_space(c, &mut frames, &regions[..n], boot_arg);
    // Re-read: building the kernel space consumed frames for its tables, so the
    // accounting check below has to compare against the books as they are now.
    let stats = frames.stats();

    // Hand out a frame and give it back. Cheap, and it distinguishes "the allocator
    // was constructed" from "the allocator works".
    let alloc = match frames.alloc_frame() {
        Ok(f) => {
            c.write_str("\n  alloc      ");
            write_hex(c, f.start().raw());
            let after = frames.stats().free;
            match frames.free_frame(f) {
                Ok(()) if frames.stats().free == stats.free && after == stats.free - 1 => {
                    c.write_str(" ok");
                    Check::Passed
                }
                _ => {
                    c.write_str(" BOOKKEEPING WRONG");
                    Check::Failed
                }
            }
        }
        Err(_) => {
            c.write_str("\n  alloc      exhausted");
            Check::Failed
        }
    };

    let space = space
        .and(alloc)
        .and(heap::bring_up(c, &mut frames, &regions[..n]))
        .and(model::demand_check(c, &mut frames, live))
        .and(model::module_check(c, &mut frames, live, boot_arg))
        .and(model::userspace_check(c, &mut frames, live))
        .and(kheap::install(c, &mut frames, &regions[..n]))
        .and(block::check(c, &mut frames, live))
        .and(net::bring_up(c, &mut frames, live))
        .and(fs::check(c, &mut frames, live))
        .and(personality::check(c, &mut frames, live))
        .and(stress::reserve(c, &mut frames, &regions[..n], live))
        .and(model::process_reserve(&mut frames, live));
    (space, live)
}

/// The largest region of physical memory the kernel will address directly.
///
/// Capped rather than "all of it" because a 32-bit kernel has less address space than
/// a large machine has RAM — the i686-large preset boots 5 GiB — and because the
/// direct map is what makes a physical frame writable at all. A frame outside it
/// cannot hold a page table, which `Frames::alloc_zeroed` reports rather than
/// pretends about.
const DIRECT_MAP_MAX: u64 = 1024 * 1024 * 1024;

fn write_usize(c: &dyn EarlyConsole, mut v: usize) {
    if v == 0 {
        c.write_bytes(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    c.write_bytes(&buf[i..]);
}

fn write_hex(c: &dyn EarlyConsole, v: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = DIGITS[((v >> (60 - i * 4)) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

/// Panics in the core are fatal. There is no pretending otherwise: print what we can
/// and stop.
///
/// The backtrace is raw return addresses. `kbuild run` and `kbuild test --target`
/// symbolize it against the separate symbol bundle when the guest stops, and
/// `kbuild symbolize` does the same for a saved log.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let c = &arch::EARLY;
    c.write_str("\n\nkernel panic: ");
    if let Some(loc) = info.location() {
        c.write_str(loc.file());
        c.write_str(":");
        write_usize(c, loc.line() as usize);
    } else {
        c.write_str("<no location>");
    }
    c.write_str("\n");
    // Skip nothing: the handler's own return address is into `core::panicking`, and
    // the frames after that are the ones that panicked.
    arch::backtrace::print(c, None, 0);
    finish(false)
}
