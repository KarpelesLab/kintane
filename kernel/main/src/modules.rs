//! Loadable modules on a paged kernel, checked at boot.
//!
//! The loader itself is `kernel/module`, and is tested on the host. What only the running
//! kernel can show is here:
//!
//! 1. **The bundle arrives.** The loader passes kbuild's module bundle as a boot module, and the
//!    memory map kept it out of the frame allocator's reach.
//! 2. **A module loads and runs.** Its regions are mapped in a window of the live kernel space,
//!    written, relocated, and then sealed: text executable and read-only, read-only data read-only,
//!    data writable and not executable, each read back from the live tables. Its init calls back
//!    into the kernel through the export table, and a callback it registers returns the value only
//!    correctly relocated text, read-only data and data can produce.
//! 3. **A referenced module cannot unload.** The callback holds a reference; unloading is refused
//!    until the kernel drops it.
//! 4. **Unloading gives everything back.** Exit runs, the regions are unmapped, their frames and
//!    every page table the mapping needed are freed, and the frame allocator's free count returns
//!    to exactly what it was before the first load.
//! 5. **A module for another configuration is refused, naming the symbol**, and one built against
//!    another interface is refused naming the function, both before any memory is allocated for
//!    them.
//!
//! Modules do not outlive the check. A kernel that loads them for good needs the registry
//! and the export state under the kernel's lock, and a long-lived home for the window;
//! that is the work after this.

use core::cell::SyncUnsafeCell;

use arch::Cpu;
use hal::paging::PageFlags;
use hal::{Arch, EarlyConsole, HasPageTables, PhysAddr};
use mm::DirectMap;
use mm::paged::{AddressSpace, FrameSource};
use mm::phys::FrameAllocator;
use module::load::{self, Kernel, LoadError, Loaded, Memory, Placement, Region};
use module::{Bundle, Export, Mismatch, ModuleId, Registry, RegistryError};

use crate::demand::KernelFrames;
use crate::{Check, Live, finish, write_hex, write_usize};

/// The ELF machine this kernel loads modules for. `MODULES` depends on x86-64.
const MACHINE: u16 = module::elf::EM_X86_64;

/// Modules loaded at once.
const SLOTS: usize = 4;
/// Section headers a module may have.
const SECTIONS: usize = 1024;
/// Address space set aside for one module's regions.
const MODULE_SPAN: usize = 64 * 1024 * 1024;

/// What the exported functions reach.
struct State {
    registry: Registry<SLOTS>,
    /// One registered callback per slot, with the id that registered it.
    callbacks: [Option<(u32, extern "C" fn(u64) -> u64)>; SLOTS],
}

/// SAFETY INVARIANT: used only on the boot CPU with interrupts masked, while [`check`]
/// runs, through [`with_state`], whose borrow never spans a call into module code. The
/// exported functions run inside such calls, so each of their borrows begins and ends
/// while no other is live.
static STATE: SyncUnsafeCell<State> = SyncUnsafeCell::new(State {
    registry: Registry::new(),
    callbacks: [None; SLOTS],
});

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    // SAFETY: see the invariant on `STATE`.
    f(unsafe { &mut *STATE.get() })
}

// ---- the kernel's exports --------------------------------------------------------------

/// Write a module's line to the console, indented under the check's.
#[unsafe(no_mangle)]
pub extern "C" fn kt_log(ptr: *const u8, len: usize) {
    // Bounded, so a module passing a wild length prints a screenful, not all of memory.
    // SAFETY: the interface requires `len` readable bytes at `ptr`.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len.min(256)) };
    let c = &arch::EARLY;
    c.write_str("\n             [");
    c.write_bytes(bytes);
    c.write_str("]");
}

#[unsafe(no_mangle)]
pub extern "C" fn kt_register_callback(module: u32, callback: extern "C" fn(u64) -> u64) -> i32 {
    let id = ModuleId::from_raw(module);
    with_state(|s| {
        let free = s.callbacks.iter().position(Option::is_none);
        if s.callbacks.iter().flatten().any(|(m, _)| *m == module) {
            return -1;
        }
        let Some(slot) = free else { return -2 };
        // The reference that stops the module unloading while its text is reachable.
        if s.registry.acquire(id).is_err() {
            return -3;
        }
        s.callbacks[slot] = Some((module, callback));
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn kt_unregister_callback(module: u32) -> i32 {
    with_state(|s| {
        let Some(slot) = s
            .callbacks
            .iter()
            .position(|c| matches!(c, Some((m, _)) if *m == module))
        else {
            return -1;
        };
        s.callbacks[slot] = None;
        match s.registry.release(ModuleId::from_raw(module)) {
            Ok(()) => 0,
            Err(_) => -2,
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn kt_panic(ptr: *const u8, len: usize) -> ! {
    let c = &arch::EARLY;
    c.write_str("\n\nmodule panic: ");
    // SAFETY: as for `kt_log`.
    c.write_bytes(unsafe { core::slice::from_raw_parts(ptr, len.min(256)) });
    c.write_str("\n");
    finish(false)
}

fn exports() -> [Export; 4] {
    [
        module::export!(module::abi, kt_log),
        module::export!(module::abi, kt_register_callback),
        module::export!(module::abi, kt_unregister_callback),
        module::export!(module::abi, kt_panic),
    ]
}

// ---- module memory ---------------------------------------------------------------------

/// A module's three regions, mapped in the live kernel space.
struct Mapped<'f, 'a> {
    space: &'f mut AddressSpace<Cpu>,
    frames: &'f mut KernelFrames<'a>,
    /// Where this module's span starts.
    base: usize,
    regions: [(usize, usize); 3],
}

impl Mapped<'_, '_> {
    /// Unmap every page of every region and free its frame. Tables left empty go back
    /// through the frame source as the unmap empties them.
    fn release(&mut self) {
        let page = Cpu::PAGE_SIZE;
        for (base, len) in self.regions {
            for at in (base..base + len).step_by(page) {
                let Some((phys, _)) = self.space.translate(at) else {
                    continue;
                };
                if self.space.unmap(at, page, self.frames).is_ok() {
                    self.frames.free(phys);
                }
            }
        }
        self.regions = [(0, 0); 3];
    }

    /// Set each region's final protection.
    fn seal(&mut self) -> Result<(), hal::paging::MapError> {
        for (r, flags) in [
            (Region::Text, PageFlags::KERNEL_TEXT),
            (Region::Rodata, PageFlags::KERNEL_RODATA),
            (Region::Data, PageFlags::KERNEL_DATA),
        ] {
            let (base, len) = self.regions[r as usize];
            if len != 0 {
                self.space.protect(base, len, flags)?;
            }
        }
        Ok(())
    }

    /// Whether the live tables say what `seal` set: text executable and not writable,
    /// read-only data neither, data writable and not executable.
    fn sealed(&self) -> bool {
        let want = |r: Region, write: bool, exec: bool| {
            let (base, len) = self.regions[r as usize];
            (base..base + len).step_by(Cpu::PAGE_SIZE).all(|at| {
                self.space.translate(at).is_some_and(|(_, f)| {
                    f.contains(PageFlags::WRITE) == write
                        && (f.contains(PageFlags::EXECUTE) == exec || !Cpu::can_forbid_execute())
                })
            })
        };
        want(Region::Text, false, true)
            && want(Region::Rodata, false, false)
            && want(Region::Data, true, false)
    }
}

impl Memory for Mapped<'_, '_> {
    fn allocate(&mut self, sizes: [u64; 3]) -> Result<[u64; 3], LoadError<'static>> {
        let page = Cpu::PAGE_SIZE;
        let mut at = self.base;
        let mut bases = [0u64; 3];
        for r in Region::ALL {
            let len = (sizes[r as usize] as usize).next_multiple_of(page);
            if at + len > self.base + MODULE_SPAN {
                self.release();
                return Err(LoadError::TooLarge);
            }
            self.regions[r as usize] = (at, 0);
            for off in (0..len).step_by(page) {
                let mapped = self.frames.alloc_zeroed().and_then(|phys| {
                    self.space
                        .map(at + off, phys, page, PageFlags::KERNEL_DATA, self.frames)
                        .inspect_err(|_| self.frames.free(phys))
                });
                if mapped.is_err() {
                    self.release();
                    return Err(LoadError::OutOfMemory);
                }
                self.regions[r as usize].1 = off + page;
            }
            bases[r as usize] = at as u64;
            // A guard page between regions, so one region's overrun faults.
            at += len + page;
        }
        Ok(bases)
    }

    fn bytes(&mut self, r: Region) -> &mut [u8] {
        let (base, len) = self.regions[r as usize];
        // SAFETY: `allocate` mapped `len` bytes at `base` writable, and nothing else refers
        // to them until the module runs.
        unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) }
    }
}

// ---- the check -------------------------------------------------------------------------

/// SAFETY INVARIANT: used only by [`load_one`], one call at a time, on the boot CPU.
static PLACEMENTS: SyncUnsafeCell<[Placement; SECTIONS]> = SyncUnsafeCell::new([None; SECTIONS]);

pub fn check(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'static, Cpu>,
    live: Live,
    boot_arg: u64,
) -> Check {
    c.write_str("\n  modules    ");
    if !kconfig::MODULES {
        c.write_str("skipped: MODULES=n");
        return Check::Skipped;
    }
    if !kconfig::MODULE_TEST.present() {
        c.write_str("loader built in, no test modules in this image");
        return Check::Skipped;
    }
    let Some(direct) = live.direct else {
        c.write_str("skipped: no kernel address space is live");
        return Check::Skipped;
    };
    // SAFETY: the loader's structures are still mapped; the direct map covers them.
    let Some((start, len)) = (unsafe { bootinfo::module_bundle(boot_arg) }) else {
        if bootinfo::MODULE_BUNDLES {
            c.write_str("NO MODULE BUNDLE, though this handover carries one");
            return Check::Failed;
        }
        c.write_str("skipped: this loader passes no module bundle yet");
        return Check::Skipped;
    };
    let Some(bytes) = direct_bytes(direct, start, len) else {
        c.write_str("bundle outside the direct map at ");
        write_hex(c, start);
        return Check::Failed;
    };
    let bundle = match Bundle::parse(bytes) {
        Ok(b) => b,
        Err(e) => {
            c.write_str("the boot module is not a module bundle: ");
            c.write_str(if matches!(e, module::BundleError::NotABundle) {
                "bad header"
            } else {
                "bad entry"
            });
            return Check::Failed;
        }
    };
    let Some(window) = crate::demand::window(direct) else {
        c.write_str("no free window for module text");
        return Check::Failed;
    };
    // Half a gigabyte into the demand check's gigabyte, which it has given back. Below
    // 2 GiB, because the kernel's code model is `small`: a module's absolute 32-bit
    // relocations must reach it. The loader refuses rather than truncates if they cannot.
    let base = window + 512 * 1024 * 1024;
    write_usize(c, bundle.len());
    c.write_str(" in the bundle at ");
    write_hex(c, start);

    // SAFETY: the root is the table `kernel_space` installed through `direct`; nothing else
    // edits it while the check runs.
    let mut space =
        unsafe { AddressSpace::<Cpu>::from_root(<Cpu as HasPageTables>::root(), direct) };
    let mut kf = KernelFrames {
        alloc: frames,
        direct,
    };
    let before = kf.alloc.stats().free;
    let exports = exports();
    let kernel = Kernel {
        machine: MACHINE,
        identity_hash: &kconfig::MODULE_IDENTITY_HASH,
        identity_text: kconfig::MODULE_IDENTITY,
        exports: &exports,
    };

    let roundtrip = roundtrip(c, &bundle, &kernel, &mut space, &mut kf, base);
    let after = kf.alloc.stats().free;
    c.write_str("\n             ");
    write_usize(c, before.saturating_sub(after));
    c.write_str(" frames left");
    let refusals = refusals(c, &bundle, &kernel, &mut space, &mut kf, base);
    let clean = with_state(|s| s.registry.is_empty() && s.callbacks.iter().all(Option::is_none));
    let ok = roundtrip && after == before && refusals && clean && kf.alloc.stats().free == before;
    c.write_str(if ok { " ok" } else { " FAILED" });
    Check::from_ok(ok)
}

fn direct_bytes(direct: DirectMap, start: u64, len: u64) -> Option<&'static [u8]> {
    let end = start.checked_add(len.checked_sub(1)?)?;
    if !direct.covers_phys(PhysAddr::new(start)) || !direct.covers_phys(PhysAddr::new(end)) {
        return None;
    }
    let p = direct.ptr_to_phys(PhysAddr::new(start)).ok()?;
    // SAFETY: the direct map covers every byte, and the memory map marked the bundle as
    // boot data, so no allocation hands its frames out while this slice is alive.
    Some(unsafe { core::slice::from_raw_parts(p.as_ptr(), usize::try_from(len).ok()?) })
}

/// A module in memory.
struct Handle {
    id: ModuleId,
    loaded: Loaded,
    regions: [(usize, usize); 3],
}

fn load_one<'b>(
    bytes: &'b [u8],
    kernel: &Kernel<'b>,
    space: &mut AddressSpace<Cpu>,
    frames: &mut KernelFrames<'_>,
    base: usize,
) -> Result<Handle, LoadError<'b>> {
    let mut mem = Mapped {
        space,
        frames,
        base,
        regions: [(0, 0); 3],
    };
    // SAFETY: see the invariant on `PLACEMENTS`.
    let placements = unsafe { &mut *PLACEMENTS.get() };
    let loaded = match load::load(bytes, kernel, placements, &mut mem) {
        Ok(l) => l,
        Err(e) => {
            mem.release();
            return Err(e);
        }
    };
    if mem.seal().is_err() || !mem.sealed() {
        mem.release();
        return Err(LoadError::Unsupported(
            "the live tables did not take the module's protections",
        ));
    }
    let Ok(id) = with_state(|s| s.registry.insert()) else {
        mem.release();
        return Err(LoadError::TooLarge);
    };
    // SAFETY: `init` is `kt_module_init` in text just relocated for this kernel and sealed
    // executable, and `module!` defines it as `extern "C" fn(u32) -> i32`.
    let init: extern "C" fn(u32) -> i32 = unsafe { core::mem::transmute(loaded.init as usize) };
    if init(id.raw()) != 0 {
        let _ = with_state(|s| {
            s.registry
                .begin_unload(id)
                .and_then(|()| s.registry.remove(id))
        });
        mem.release();
        return Err(LoadError::Unsupported("the module's init refused"));
    }
    Ok(Handle {
        id,
        loaded,
        regions: mem.regions,
    })
}

fn unload(
    h: &Handle,
    space: &mut AddressSpace<Cpu>,
    frames: &mut KernelFrames<'_>,
) -> Result<(), RegistryError> {
    with_state(|s| s.registry.begin_unload(h.id))?;
    if let Some(exit) = h.loaded.exit {
        // SAFETY: as for `init`; `module!` defines `kt_module_exit` as `extern "C" fn(u32)`.
        let exit: extern "C" fn(u32) = unsafe { core::mem::transmute(exit as usize) };
        exit(h.id.raw());
    }
    let mut mem = Mapped {
        space,
        frames,
        base: 0,
        regions: h.regions,
    };
    mem.release();
    with_state(|s| s.registry.remove(h.id))
}

/// Load the round-trip module, call it, fail to unload it, release it, unload it.
fn roundtrip(
    c: &dyn EarlyConsole,
    bundle: &Bundle<'_>,
    kernel: &Kernel<'_>,
    space: &mut AddressSpace<Cpu>,
    frames: &mut KernelFrames<'_>,
    base: usize,
) -> bool {
    c.write_str("\n             test-roundtrip: ");
    let Some(bytes) = bundle.get("test-roundtrip") else {
        c.write_str("NOT IN THE BUNDLE");
        return false;
    };
    let h = match load_one(bytes, kernel, space, frames, base) {
        Ok(h) => h,
        Err(e) => {
            c.write_str("REFUSED: ");
            write_error(c, &e);
            return false;
        }
    };
    c.write_str("\n             loaded at ");
    write_hex(c, h.regions[0].0 as u64);
    c.write_str(", ");
    write_usize(c, h.loaded.relocations);
    c.write_str(" relocations, W^X sealed; ");

    let callback = with_state(|s| {
        s.callbacks
            .iter()
            .flatten()
            .find(|(m, _)| *m == h.id.raw())
            .map(|(_, f)| *f)
    });
    let Some(callback) = callback else {
        c.write_str("NO CALLBACK REGISTERED");
        return false;
    };
    // 40 + 2×1, then + 3×10: `.data`'s initial total, `.rodata`'s weights, both calls.
    let (first, second) = (callback(2), callback(3));
    write_usize(c, first as usize);
    c.write_str(", ");
    write_usize(c, second as usize);
    let called = first == 42 && second == 72;
    if !called {
        c.write_str(" WRONG (want 42, 72)");
    }

    let refused = matches!(unload(&h, space, frames), Err(RegistryError::Busy { refs: 1 }));
    c.write_str(if refused {
        "; unload refused while referenced"
    } else {
        "; UNLOAD NOT REFUSED WHILE REFERENCED"
    });
    if !refused {
        return false;
    }
    let released = kt_unregister_callback(h.id.raw()) == 0;
    let unloaded = unload(&h, space, frames).is_ok();
    c.write_str(if released && unloaded {
        "; unloaded"
    } else {
        "; UNLOAD FAILED"
    });
    called && released && unloaded
}

/// The two modules that must be refused, and why.
fn refusals(
    c: &dyn EarlyConsole,
    bundle: &Bundle<'_>,
    kernel: &Kernel<'_>,
    space: &mut AddressSpace<Cpu>,
    frames: &mut KernelFrames<'_>,
    base: usize,
) -> bool {
    let mut ok = true;
    for (name, expect) in [
        ("test-other-config", "config"),
        ("test-other-interface", "interface"),
    ] {
        c.write_str("\n             ");
        c.write_str(name);
        c.write_str(": ");
        let Some(bytes) = bundle.get(name) else {
            c.write_str("NOT IN THE BUNDLE");
            ok = false;
            continue;
        };
        let before = frames.alloc.stats().free;
        match load_one(bytes, kernel, space, frames, base) {
            Ok(h) => {
                c.write_str("LOADED, and must not have");
                let _ = unload(&h, space, frames);
                ok = false;
            }
            Err(e) => {
                c.write_str("refused, ");
                write_error(c, &e);
                let right = match (expect, e) {
                    ("config", LoadError::Identity(Mismatch::Config { symbol, .. })) => {
                        symbol == "DEBUG_BUILD"
                    }
                    ("interface", LoadError::InterfaceMismatch { name, .. }) => {
                        name == b"kt_register_callback"
                    }
                    _ => false,
                };
                if !right {
                    c.write_str(" (WRONG REASON)");
                }
                if frames.alloc.stats().free != before {
                    c.write_str(" (FRAMES TAKEN)");
                    ok = false;
                }
                ok &= right;
            }
        }
    }
    ok
}

fn write_error(c: &dyn EarlyConsole, e: &LoadError<'_>) {
    let name = |c: &dyn EarlyConsole, n: &[u8]| c.write_bytes(n);
    match *e {
        LoadError::Identity(Mismatch::Config {
            symbol,
            module,
            kernel,
        }) => {
            c.write_str("built with ");
            c.write_str(symbol);
            c.write_str("=");
            c.write_str(if module.is_empty() {
                "(absent)"
            } else {
                module
            });
            c.write_str(", kernel has ");
            c.write_str(if kernel.is_empty() {
                "(absent)"
            } else {
                kernel
            });
        }
        LoadError::Identity(Mismatch::Toolchain { module, .. }) => {
            c.write_str("built by another toolchain: ");
            c.write_str(module);
        }
        LoadError::Identity(Mismatch::Target) => c.write_str("built for another target"),
        LoadError::Identity(_) => c.write_str("identity malformed or corrupt"),
        LoadError::InterfaceMismatch { name: n, .. } => {
            name(c, n);
            c.write_str(" is not the kernel's interface");
        }
        LoadError::Unexported { name: n } => {
            name(c, n);
            c.write_str(" is not exported");
        }
        LoadError::Undeclared { name: n } => {
            name(c, n);
            c.write_str(" is imported without an interface record");
        }
        LoadError::WrongMachine { .. } => c.write_str("built for another machine"),
        LoadError::Reloc(_) => c.write_str("a relocation could not be applied"),
        LoadError::Unsupported(what) | LoadError::Incomplete(what) => c.write_str(what),
        LoadError::Elf(_) => c.write_str("not a valid relocatable object"),
        LoadError::OutOfMemory => c.write_str("out of memory"),
        _ => c.write_str("malformed"),
    }
}
