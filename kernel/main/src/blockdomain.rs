//! The disk, served from an isolated driver domain (only with `BLOCK_DOMAIN`).
//!
//! This joins the two halves `docs/isolation.md` kept apart: a driver body in a ring-3 domain
//! (aarch64's register prototype) and a DMA-capable driver confined by an IOMMU (x86_64,
//! in-kernel). Here, on x86_64, the DMA-capable driver runs *in the domain*.
//!
//! Once the scheduler is up, the kernel hands the disk to `user/blkdomain`, an unprivileged
//! process whose address space holds its program, its stack, two channels, a setup page, and
//! three mappings of the grant:
//!
//! * the device's **register window**, as device memory — a register access there is the same
//!   load the kernel would make, in ring 3;
//! * the device's **DMA buffer**, the very grant the IOMMU already confines the device to, so the
//!   rings and bounce buffers the domain builds are exactly what VT-d lets the device reach;
//! * **data pages** shared with the kernel, that a request's bytes move through — the CPU copies
//!   them to and from the engine's bounce buffers, so they are never device-visible and need no
//!   IOMMU mapping.
//!
//! The kernel's block layer is the domain's client, over a channel: it sends a [`Request`] and
//! reads a [`Reply`]. The disk's MSI-X interrupt is taken by the kernel's handler, which
//! forwards it to the domain as an [`Interrupt`] message ([`forward_interrupt`]) — the
//! interrupt-as-a-message path the roadmap named as missing. The domain never drains the ring
//! on its own; a completion it collects was announced by an interrupt the kernel delivered.
//!
//! # What this proves, and what it does not
//!
//! The same driver source — `virtio_blk_core` — serves the block check here and in the kernel,
//! and both are in CI (`x86_64-iommu` in-kernel, `x86_64-isolated` in a domain). A domain that
//! aims a DMA outside its grant is stopped by VT-d and logged; a domain whose driver faults is
//! killed alone and the disk marked failed; a fresh domain serves again. Afterwards the disk is
//! handed back to the kernel, so the stress run and the filesystem find it working.
//!
//! It does **not** yet use VT-d **interrupt remapping**: the interrupt is delivered to the
//! kernel and forwarded in software. Where remapping would slot in is at [`forward_interrupt`]'s
//! comment — the remapping table would target the message at the domain directly, and the
//! kernel handler would only acknowledge. That table is another fork's work (`drivers/iommu/vtd`,
//! `intremap=on` is already enabled on the machine so it can build on it).

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use hal::{Arch, EarlyConsole, HasUserMode, KernAddr, PhysAddr};
use mm::frame::{Frame, FrameRange};
use mm::paged::FrameSource;
use mm::vm::{Backing, Region};
use sched::ThreadId;
use sync::SpinLock;
use sync::lockdep::LockClass;
use time::Duration;
use virtio_blk_core::domain::{Facts, Interrupt, Op, Reply, Request, Setup, status};

use crate::preempt::{self, sleep_until};
use crate::userproc::{self, KernelEnd};
use crate::{Check, block, iommu, timekeeping, write_usize};
use ::block::testdisk;

/// Guarded stack slots this check claims: one, for the domain's thread, reused across the
/// domains it starts.
pub const STACKS: usize = 1;

/// The process slot the domain runs in. `userproc::MAX_PROCS` is four; the scheduled process
/// checks use 0–2 and tear them down before this runs, and the aarch64 register prototype
/// (skipped here) would use 3, so 3 is free.
const SLOT: usize = 3;

/// Where the grant and the shared pages go in the domain's address space: well inside the
/// user half, above the program's own segments, spaced so a reader is not misled.
fn base_va() -> usize {
    <Cpu as HasUserMode>::USER_START + 0x6000_0000
}
fn window_va() -> usize {
    base_va()
}
fn dma_va() -> usize {
    base_va() + 0x0100_0000
}
fn data_va() -> usize {
    base_va() + 0x0200_0000
}
fn setup_va() -> usize {
    base_va() + 0x0300_0000
}

/// Pages the shared data region spans: enough for one request's data. A request is at most
/// the device's `max_transfer` (15 sectors under QEMU), well under this.
const DATA_PAGES: usize = 4;

/// How long to wait for a domain's reply, a domain to become ready, or a domain to die.
const REPLY_WAIT: Duration = Duration::from_nanos(3_000_000_000);
const DRAIN: Duration = Duration::from_nanos(3_000_000_000);

/// The scheduler stack slot the domain thread runs on, claimed once and reused.
static STACK: AtomicUsize = AtomicUsize::new(usize::MAX);
/// What a domain thread enters user mode with, read by [`domain_entry`].
static ENTRY: AtomicUsize = AtomicUsize::new(0);
static ARGS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static STACK_TOP: AtomicUsize = AtomicUsize::new(0);

// ---- interrupt forwarding -------------------------------------------------------------

/// The kernel end of the domain's interrupt channel, and the running interrupt count. The
/// handler owns this while a domain is being served; it is `None` otherwise.
struct Forward {
    end: KernelEnd,
    count: u64,
}

static FORWARD_CLASS: LockClass = LockClass::new("blockdomain.forward");
static FORWARD: SpinLock<Option<Forward>, Cpu> = SpinLock::with_class(None, &FORWARD_CLASS);

/// Interrupt messages the handler managed to forward, and ones it could not because the
/// domain's inbox was full — harmless, because the count each message carries is cumulative,
/// so the next delivered message brings the domain up to date.
static FORWARDED: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Forward the disk's interrupt to the domain as a message. Called from the interrupt
/// handler while [`block::forward_interrupts`] is on. `true` if a domain owns the interrupt.
///
/// Where VT-d interrupt remapping would slot in: with a remapping table, the device's MSI
/// would be steered to the domain without this software hop, and the kernel handler would only
/// acknowledge. Until that table exists (another fork), the interrupt lands in the kernel and
/// is forwarded here.
pub fn forward_interrupt() -> bool {
    let mut held = FORWARD.lock_irqsave();
    let Some(fwd) = held.as_mut() else {
        return false;
    };
    fwd.count += 1;
    let msg = Interrupt {
        count: fwd.count,
        stamp: timekeeping::now().as_nanos(),
    };
    // A full inbox means a message is already queued that will wake the domain; it drains
    // every completion when it does, and the cumulative count keeps it correct.
    if fwd.end.send(&msg.encode()).is_ok() {
        FORWARDED.fetch_add(1, Ordering::Relaxed);
    } else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    true
}

// ---- the check ------------------------------------------------------------------------

/// Run the disk from a domain and report. On the boot thread, with the scheduler running,
/// after the disk is up in the kernel and confined by the IOMMU.
pub fn check(c: &dyn EarlyConsole) -> Check {
    if !kconfig::IOMMU {
        c.write_str("skipped: the disk is not behind an IOMMU to confine a domain");
        return Check::Skipped;
    }
    let Some((_, dma_phys, dma_len)) = block::grant() else {
        c.write_str("skipped: no disk to hand to a domain");
        return Check::Skipped;
    };
    let (_window_phys, window_len) = match virtio_blk::window() {
        Some(w) => w,
        None => {
            c.write_str("NO DISK WINDOW TO GRANT");
            return Check::Failed;
        }
    };
    let Some((layout, bar, device_id)) = virtio_blk::pci_layout() else {
        c.write_str("THE DISK IS NOT ON PCI");
        return Check::Failed;
    };
    let vector = match virtio_blk::msix_entry()
        .filter(|_| platform::block_line().is_some_and(platform::interrupt_is_msi))
    {
        Some(v) => v,
        None => {
            // A polled domain is exactly what this host refuses; the in-kernel path handles a
            // polled disk, but a domain would have to poll the ring, which defeats the point.
            c.write_str("skipped: the disk's interrupt is not one that can reach a domain");
            return Check::Skipped;
        }
    };

    let setup = Setup {
        window: window_va() as u64,
        window_len,
        dma_virt: dma_va() as u64,
        dma_phys,
        dma_len: dma_len as u64,
        data_virt: data_va() as u64,
        data_len: (DATA_PAGES * Cpu::PAGE_SIZE) as u64,
        vector,
        bar,
        device_id,
        layout,
    };

    // The setup page and the data pages, allocated once and reused by every domain this check
    // starts, so a teardown between domains does not churn frames. Freed at the end.
    if !alloc_shared() {
        c.write_str("NO SHARED PAGES FOR THE DOMAIN");
        free_shared();
        return Check::Failed;
    }

    // The disk is the domain's now: its interrupt is forwarded, not collected in the kernel.
    block::forward_interrupts(true);
    let verdict = run(c, &setup, dma_phys, dma_len);
    block::forward_interrupts(false);
    forward_end(None);
    free_shared();

    // Hand the disk back to the kernel, whatever happened, so the stress run and the
    // filesystem find it working.
    if !block::restart_in_kernel(c) {
        c.write_str("; THE DISK DID NOT COME BACK TO THE KERNEL");
        return Check::Failed;
    }
    c.write_str("; disk back in the kernel");
    verdict
}

fn run(c: &dyn EarlyConsole, setup: &Setup, dma_phys: u64, dma_len: usize) -> Check {
    // First domain: bring the disk up, serve every block check, and prove the IOMMU stops a
    // DMA it aims outside its grant.
    let mut client = match start_domain(c, setup) {
        Ok(client) => client,
        Err(why) => {
            c.write_str("; ");
            c.write_str(why);
            teardown();
            return Check::Failed;
        }
    };
    let facts = client.facts;
    write_usize(c, facts.capacity as usize);
    c.write_str(" sectors of ");
    write_usize(c, facts.block_size as usize);
    c.write_str(" bytes, ");
    write_usize(c, facts.max_transfer as usize);
    c.write_str(" per request, in a domain");

    let mut ok = facts.block_size as usize == testdisk::SECTOR
        && facts.capacity == testdisk::SECTORS
        && facts.uses_msix
        && facts.platform_iommu;
    if !ok {
        c.write_str("; NOT THE TEST DISK BEHIND VT-d ON MSI-X");
    }
    ok = ok && functional(c, &mut client, &facts);
    // The interrupt accounting, read after the functional run and before the rogue DMA — a
    // blocked rogue deliberately leaves a descriptor outstanding, so cleanliness is asked of
    // the functional run, where nothing should be left behind. Every completion the domain
    // collected followed an interrupt message: it never drains the ring on its own.
    let last = client.last;
    report_interrupts(c, &last);
    if last.submitted != last.completions || last.messages == 0 {
        c.write_str("; A COMPLETION ARRIVED WITHOUT AN INTERRUPT");
        ok = false;
    }
    if !last.clean {
        c.write_str("; A DESCRIPTOR LEAKED");
        ok = false;
    }
    ok = contain_rogue(c, &mut client, dma_phys, dma_len) && ok;
    stop(&mut client);
    teardown();

    // Containment of a faulting *domain*: kill one, mark the disk failed, start another that
    // serves again.
    ok = ok && restart_after_fault(c, setup);
    Check::from_ok(ok)
}

/// The block check, served by the domain: the same reads, write, flush and refusals the
/// in-kernel `block::run_checks` makes.
fn functional(c: &dyn EarlyConsole, client: &mut Client, facts: &Facts) -> bool {
    // Sector 0's header.
    let Some(sector0) = client.read(0, 1) else {
        return failed(c, "reading sector 0 in the domain");
    };
    if testdisk::header(sector0) != Some(testdisk::SECTORS) {
        c.write_str("; SECTOR 0 IS NOT THE TEST DISK'S HEADER");
        return false;
    }

    // Sectors 1..32, split into pieces the device takes, each verified.
    let mut lba = 1u64;
    while lba <= 32 {
        let blocks = (33 - lba).min(facts.max_transfer);
        let Some(data) = client.read(lba, blocks as u32) else {
            return failed(c, "reading sectors 1-32 in the domain");
        };
        for (i, sector) in data.chunks_exact(testdisk::SECTOR).enumerate() {
            if let Some(at) = testdisk::first_mismatch(lba + i as u64, sector) {
                c.write_str("; SECTOR ");
                write_usize(c, (lba + i as u64) as usize);
                c.write_str(" DIFFERS AT BYTE ");
                write_usize(c, at);
                return false;
            }
        }
        lba += blocks;
    }
    c.write_str("; 32 sectors read back the pattern");

    // Write the scratch area, flush, read it back.
    let mut scratch = [0u8; 8 * testdisk::SECTOR];
    for (i, b) in scratch.iter_mut().enumerate() {
        *b = testdisk::pattern(testdisk::SCRATCH_START ^ 0xa5a5, i);
    }
    if !client.write(testdisk::SCRATCH_START, &scratch) {
        return failed(c, "writing the scratch area in the domain");
    }
    if !client.flush() {
        return failed(c, "flushing in the domain");
    }
    let Some(back) = client.read(testdisk::SCRATCH_START, 8) else {
        return failed(c, "reading the scratch area back in the domain");
    };
    if back != scratch {
        c.write_str("; THE SCRATCH WRITE DID NOT READ BACK");
        return false;
    }
    // The sector before the scratch area still holds the pattern.
    let Some(before) = client.read(testdisk::SCRATCH_START - 1, 1) else {
        return failed(c, "reading below the scratch area in the domain");
    };
    if testdisk::first_mismatch(testdisk::SCRATCH_START - 1, before).is_some() {
        c.write_str("; THE WRITE LANDED BELOW THE SCRATCH AREA");
        return false;
    }
    c.write_str("; a write read back after a flush");

    // A read past the end, with the domain's range check skipped, so the *device* refuses it
    // and the refusal comes back as an error rather than a success.
    let reply = client.request(Request {
        op: Op::ReadPastEnd,
        blocks: 1,
        lba: 0,
        addr: 0,
    });
    match reply.map(|r| r.status) {
        Some(status::DEVICE) => c.write_str("; the device's own refusal was an error"),
        Some(status::OK) => {
            c.write_str("; THE DEVICE ANSWERED A READ PAST ITS END");
            return false;
        }
        _ => return failed(c, "the device's refusal came back the wrong way"),
    }

    // A stretch of reads, to show nothing leaks; the final reply's counts are checked by the
    // caller.
    for i in 0..64u64 {
        if client.read(1 + i, 1).is_none() {
            return failed(c, "a repeated read in the domain");
        }
    }
    true
}

/// A DMA the domain aims outside its grant must be stopped by VT-d and logged, and the target
/// left untouched — the disk-domain equivalent of `block::iommu_checks`, driven from inside
/// the domain rather than by the kernel.
fn contain_rogue(c: &dyn EarlyConsole, client: &mut Client, dma_phys: u64, dma_len: usize) -> bool {
    // A canary frame outside the grant, filled with a sentinel the device would overwrite.
    let Some(canary) = userproc::with_frames(|f| f.alloc.alloc_frame().ok()).flatten() else {
        c.write_str("; NO CANARY FRAME");
        return false;
    };
    let cphys = canary.start().raw();
    let Some(cp) = userproc::direct_ptr(canary.start()) else {
        c.write_str("; CANARY OUTSIDE THE DIRECT MAP");
        return false;
    };
    const SENTINEL: u8 = 0x5a;
    for i in 0..testdisk::SECTOR {
        // SAFETY: `cp` is the canary frame through the direct map, a whole page; a sector of
        // it is in bounds. Volatile, because the device may try to write it.
        unsafe { cp.add(i).write_volatile(SENTINEL) };
    }
    // The grant translates and the canary does not: the device is confined to exactly the
    // grant.
    if !iommu::domain_maps(dma_phys) || iommu::domain_maps(cphys) {
        c.write_str("; THE IOMMU DOMAIN DOES NOT MAP EXACTLY THE GRANT");
        return false;
    }
    let _ = dma_len;

    let before = iommu::take_fault();
    let _ = before; // drain any earlier fault so the one we read is ours.
    let reply = client.request(Request {
        op: Op::RogueDma,
        blocks: 1,
        lba: 0,
        addr: cphys,
    });
    let fault = iommu::take_fault();
    let mut untouched = true;
    for i in 0..testdisk::SECTOR {
        // SAFETY: as the fill above.
        if unsafe { cp.add(i).read_volatile() } != SENTINEL {
            untouched = false;
            break;
        }
    }

    // The canary has served its purpose; the fault naming it has been read.
    userproc::with_frames(|f| f.free(canary.start()));

    // The request may come back used — the device writes its status byte inside the grant —
    // while the *data* write to the canary faulted. What proves containment is the fault log
    // and the untouched canary, not whether the descriptor was returned.
    let _ = reply;
    let stopped = match fault {
        Some((f, source)) if f.address == cphys && f.write => {
            c.write_str("; the domain's out-of-grant DMA stopped at ");
            write_hex(c, f.address);
            c.write_str(" from ");
            write_hex(c, u64::from(source));
            true
        }
        Some((f, _)) => {
            c.write_str("; A FAULT AT ");
            write_hex(c, f.address);
            c.write_str(" BUT NOT THE ROGUE ONE");
            false
        }
        None => {
            c.write_str("; THE DOMAIN'S ROGUE DMA WAS NOT STOPPED");
            false
        }
    };
    if !untouched {
        c.write_str("; THE CANARY WAS OVERWRITTEN");
    }
    stopped && untouched
}

/// A domain whose driver faults is killed alone; the disk is marked failed; a fresh domain
/// serves a read again.
fn restart_after_fault(c: &dyn EarlyConsole, setup: &Setup) -> bool {
    let mut client = match start_domain(c, setup) {
        Ok(client) => client,
        Err(why) => {
            c.write_str("; the replacement domain FAILED: ");
            c.write_str(why);
            teardown();
            return false;
        }
    };
    // Make it fault: it reaches past its grant, and the MMU — not a bounds check in the
    // driver — kills it. No reply is expected.
    let _ = client.send(Request {
        op: Op::Fault,
        blocks: 0,
        lba: 0,
        addr: 0,
    });
    if !wait_dead(client.thread) {
        c.write_str("; A FAULTING DOMAIN WAS NOT KILLED");
        stop(&mut client);
        teardown();
        return false;
    }
    let killed = userproc::slot(SLOT).and_then(|p| p.exit) == Some(userproc::KILLED);
    let _ = preempt::reap(client.thread);
    teardown();
    if !killed {
        c.write_str("; THE FAULTING DOMAIN DID NOT DIE AS KILLED");
        return false;
    }
    c.write_str("; a faulting domain was killed, disk marked failed");

    // A fresh domain over the same grant serves a read again — the host survived the fault.
    let mut fresh = match start_domain(c, setup) {
        Ok(client) => client,
        Err(why) => {
            c.write_str("; a fresh domain did not start: ");
            c.write_str(why);
            teardown();
            return false;
        }
    };
    let served = match fresh.read(0, 1) {
        Some(sector0) => testdisk::header(sector0) == Some(testdisk::SECTORS),
        None => false,
    };
    stop(&mut fresh);
    teardown();
    if served {
        c.write_str("; a new domain served a read");
    } else {
        c.write_str("; THE NEW DOMAIN DID NOT SERVE A READ");
    }
    served
}

// ---- the client (the kernel's block layer, over the channel) --------------------------

/// The kernel's side of one domain: the request channel's kernel end, the domain's thread,
/// where its data pages are, what its bring-up reported, and its latest counts.
struct Client {
    requests: KernelEnd,
    thread: ThreadId,
    data_kvirt: usize,
    data_len: usize,
    facts: Facts,
    last: Reply,
}

impl Client {
    /// Send `req` and wait for the reply.
    fn request(&mut self, req: Request) -> Option<Reply> {
        if self.requests.send(&req.encode()).is_err() {
            return None;
        }
        let mut buf = [0u8; 64];
        let deadline = Some(timekeeping::now().saturating_add(REPLY_WAIT));
        let got = self.requests.recv(&mut buf, deadline).ok()?;
        let reply = Reply::decode(&buf[..got])?;
        self.last = reply;
        Some(reply)
    }

    /// Send `req` without waiting for a reply, for the deliberate fault.
    fn send(&mut self, req: Request) -> bool {
        self.requests.send(&req.encode()).is_ok()
    }

    /// Read `blocks` at `lba` and return the data pages holding them, or `None` on any error.
    fn read(&mut self, lba: u64, blocks: u32) -> Option<&[u8]> {
        let reply = self.request(Request {
            op: Op::Read,
            blocks,
            lba,
            addr: 0,
        })?;
        if reply.status != status::OK {
            return None;
        }
        let len = blocks as usize * self.facts.block_size as usize;
        (len <= self.data_len).then(|| self.data(len))
    }

    /// Write `from` at `lba` through the data pages.
    fn write(&mut self, lba: u64, from: &[u8]) -> bool {
        if from.len() > self.data_len || self.facts.block_size == 0 {
            return false;
        }
        self.data_mut(from.len()).copy_from_slice(from);
        let blocks = (from.len() / self.facts.block_size as usize) as u32;
        matches!(
            self.request(Request {
                op: Op::Write,
                blocks,
                lba,
                addr: 0,
            })
            .map(|r| r.status),
            Some(status::OK)
        )
    }

    fn flush(&mut self) -> bool {
        matches!(
            self.request(Request {
                op: Op::Flush,
                blocks: 0,
                lba: 0,
                addr: 0,
            })
            .map(|r| r.status),
            Some(status::OK)
        )
    }

    /// The first `len` bytes of the shared data pages, through the kernel's direct map.
    fn data(&self, len: usize) -> &[u8] {
        // SAFETY: `data_kvirt` is the data region through the direct map, `data_len` bytes,
        // and the domain has replied, so it is not writing them now. `len` is within them.
        unsafe { core::slice::from_raw_parts(self.data_kvirt as *const u8, len) }
    }

    fn data_mut(&mut self, len: usize) -> &mut [u8] {
        // SAFETY: as `data`; the domain is waiting for the next request, so nothing else
        // touches the region.
        unsafe { core::slice::from_raw_parts_mut(self.data_kvirt as *mut u8, len) }
    }
}

/// Ask a served domain to stop and end. Best effort: teardown reclaims it either way.
fn stop(client: &mut Client) {
    let _ = client.request(Request {
        op: Op::Stop,
        blocks: 0,
        lba: 0,
        addr: 0,
    });
    let _ = wait_dead(client.thread);
    let _ = preempt::reap(client.thread);
}

// ---- building and starting a domain ---------------------------------------------------

/// Build a domain over the grant, spawn it, and wait for its ready (or failure) reply.
fn start_domain(c: &dyn EarlyConsole, setup: &Setup) -> Result<Client, &'static str> {
    let _ = c;
    let program = program().ok_or("the embedded domain program does not load")?;
    let root = build_domain(setup)?;

    // The two channels: requests (the kernel is the client) and interrupts (the kernel
    // forwards). Both handles are in the domain's table; their kernel ends are ours.
    let (req_handle, req_end) =
        userproc::kernel_channel(SLOT).ok_or("no request channel for the domain")?;
    let (irq_handle, irq_end) =
        userproc::kernel_channel(SLOT).ok_or("no interrupt channel for the domain")?;
    forward_end(Some(irq_end));

    let data = map_grant(setup)?;

    ARGS[0].store(req_handle.raw() as usize, Ordering::Relaxed);
    ARGS[1].store(irq_handle.raw() as usize, Ordering::Relaxed);
    ARGS[2].store(setup_va(), Ordering::Relaxed);
    ARGS[3].store(0, Ordering::Relaxed);
    ENTRY.store(program.entry as usize, Ordering::Relaxed);

    let stack = stack().ok_or("no guarded stack for the domain's thread")?;
    let thread = spawn(stack, root).ok_or("the domain's thread could not be spawned")?;

    let mut client = Client {
        requests: req_end,
        thread,
        data_kvirt: data,
        data_len: DATA_PAGES * Cpu::PAGE_SIZE,
        facts: Facts {
            block_size: 0,
            capacity: 0,
            max_transfer: 0,
            read_only: false,
            flush_supported: false,
            platform_iommu: false,
            uses_msix: false,
        },
        last: Reply::default(),
    };

    // The first message is the domain's bring-up: its facts, or which step failed.
    let mut buf = [0u8; 64];
    let deadline = Some(timekeeping::now().saturating_add(REPLY_WAIT));
    let got = client
        .requests
        .recv(&mut buf, deadline)
        .map_err(|_| "the domain did not report bring-up")?;
    if let Some(facts) = Facts::decode(&buf[..got]) {
        client.facts = facts;
        Ok(client)
    } else {
        Err("the domain could not bring the disk up")
    }
}

/// Build the domain's address space with the program, and reserve and fill its setup page.
/// Returns its root.
fn build_domain(setup: &Setup) -> Result<PhysAddr, &'static str> {
    let program = program().ok_or("the embedded domain program does not load")?;
    let root =
        userproc::build(SLOT, &program).ok_or("the domain's address space could not be built")?;
    let setup_frame = PhysAddr::new(SETUP_FRAME.load(Ordering::Relaxed));
    let p = userproc::slot(SLOT).ok_or("the domain's slot is empty after building it")?;
    p.vm
        .reserve(Region {
            start: setup_va(),
            len: Cpu::PAGE_SIZE,
            flags: userproc::user_rw(),
            backing: Backing::Physical { base: setup_frame },
            huge: false,
        })
        .map_err(|_| "the setup page could not be mapped into the domain")?;
    // Write the setup for the domain to read.
    let ptr = userproc::direct_ptr(setup_frame).ok_or("the setup page is unreachable")?;
    for (i, b) in setup.encode().iter().enumerate() {
        // SAFETY: `ptr` is the setup frame through the direct map, a whole page; `SETUP_BYTES`
        // is far less. Volatile, because the reader is another address space.
        unsafe { ptr.add(i).write_volatile(*b) };
    }
    Ok(root)
}

/// Map the grant and data pages into the domain, and return the kernel's pointer to the data.
fn map_grant(setup: &Setup) -> Result<usize, &'static str> {
    // The data pages: a contiguous run the kernel reaches through its direct map and the
    // domain through a mapping of its own. Not device-visible, so no IOMMU mapping.
    let data_phys = PhysAddr::new(DATA_PHYS.load(Ordering::Relaxed));
    let data_kvirt = userproc::direct_ptr(data_phys).ok_or("the data pages are unreachable")? as usize;

    let p = userproc::slot(SLOT).ok_or("the domain's slot is empty before its grant")?;
    // The register window, as device memory.
    let page = Cpu::PAGE_SIZE as u64;
    let win_off = setup.window & (page - 1);
    // The window VA the domain was told already points inside its page; map from the page.
    let win_base = PhysAddr::new(window_phys() - win_off);
    let win_pages = ((win_off + setup.window_len).next_multiple_of(page)) as usize;
    p.vm
        .reserve(Region {
            start: window_va() - win_off as usize,
            len: win_pages,
            flags: userproc::user_device(),
            backing: Backing::Physical { base: win_base },
            huge: false,
        })
        .map_err(|_| "the register window could not be mapped into the domain")?;
    // The DMA buffer: exactly the grant the IOMMU confines the device to.
    p.vm
        .reserve(Region {
            start: dma_va(),
            len: setup.dma_len as usize,
            flags: userproc::user_rw(),
            backing: Backing::Physical {
                base: PhysAddr::new(setup.dma_phys),
            },
            huge: false,
        })
        .map_err(|_| "the DMA grant could not be mapped into the domain")?;
    // The data pages.
    p.vm
        .reserve(Region {
            start: data_va(),
            len: DATA_PAGES * Cpu::PAGE_SIZE,
            flags: userproc::user_rw(),
            backing: Backing::Physical { base: data_phys },
            huge: false,
        })
        .map_err(|_| "the data pages could not be mapped into the domain")?;
    Ok(data_kvirt)
}

/// The disk's register window, physical: what [`map_grant`] maps and what `Setup::window` was
/// derived from.
fn window_phys() -> u64 {
    virtio_blk::window().map_or(0, |(phys, _)| phys)
}

/// Set or clear the interrupt channel's kernel end the handler forwards on.
fn forward_end(end: Option<KernelEnd>) {
    let mut held = FORWARD.lock_irqsave();
    *held = end.map(|end| Forward { end, count: 0 });
}

/// The setup page and the data pages, shared by every domain this check starts: allocated
/// once by [`alloc_shared`] and freed once by [`free_shared`], because rebuilding the domain
/// between runs remaps the same frames rather than allocating new ones.
static SETUP_FRAME: AtomicU64 = AtomicU64::new(0);
static DATA_PHYS: AtomicU64 = AtomicU64::new(0);

/// Allocate the setup page and the data run. `false` if either could not be had.
fn alloc_shared() -> bool {
    let setup = userproc::with_frames(|f| f.alloc.alloc_frame().ok())
        .flatten()
        .map(|frame| frame.start());
    let data = userproc::with_frames(|f| f.alloc.alloc_contiguous(DATA_PAGES).ok())
        .flatten()
        .map(|run| run.start().start());
    match (setup, data) {
        (Some(s), Some(d)) => {
            SETUP_FRAME.store(s.raw(), Ordering::Relaxed);
            DATA_PHYS.store(d.raw(), Ordering::Relaxed);
            true
        }
        (s, d) => {
            if let Some(s) = s {
                userproc::with_frames(|f| f.free(s));
            }
            if let Some(d) = d {
                free_run(d);
            }
            false
        }
    }
}

/// Give the setup page and the data run back.
fn free_shared() {
    let setup = SETUP_FRAME.swap(0, Ordering::Relaxed);
    if setup != 0 {
        userproc::with_frames(|f| f.free(PhysAddr::new(setup)));
    }
    let data = DATA_PHYS.swap(0, Ordering::Relaxed);
    if data != 0 {
        free_run(PhysAddr::new(data));
    }
}

/// Free the [`DATA_PAGES`]-frame run that begins at `start`.
fn free_run(start: PhysAddr) {
    userproc::with_frames(|f| {
        if let Ok(range) =
            Frame::<Cpu>::from_start(start).and_then(|frame| FrameRange::new(frame, DATA_PAGES))
        {
            let _ = f.alloc.free_contiguous(range);
        }
    });
}

/// Give the domain's slot back. The grant, the register window, and the shared pages are not
/// freed here: the first two are the disk's, and the shared pages outlive one domain.
fn teardown() {
    forward_end(None);
    userproc::teardown(SLOT);
}

/// The stack slot domain threads run on: claimed once, reused after, because the previous
/// domain's thread is always reaped before the next is spawned.
fn stack() -> Option<usize> {
    let have = STACK.load(Ordering::Relaxed);
    if have != usize::MAX {
        return Some(have);
    }
    let claimed = preempt::claim_stacks(&["block driver domain"])?;
    STACK.store(claimed, Ordering::Relaxed);
    Some(claimed)
}

fn spawn(stack: usize, root: PhysAddr) -> Option<ThreadId> {
    preempt::spawn_prepared(stack, domain_entry, 0, 4, |ctx, top| {
        STACK_TOP.store(top.raw(), Ordering::Relaxed);
        <Cpu as HasUserMode>::bind(ctx, top, root);
    })
}

/// The domain thread's kernel entry: fill the program in, then drop to user mode.
extern "C" fn domain_entry(_: usize) -> ! {
    preempt::begin();
    let filled = program().and_then(|p| userproc::install_program(&p));
    if filled.is_none() {
        if let Some(p) = userproc::current() {
            p.exit = Some(0x10ad);
        }
        preempt::exit_thread()
    }
    let args = ARGS.each_ref().map(|a| a.load(Ordering::Relaxed));
    let top = STACK_TOP.load(Ordering::Relaxed);
    let _ = Cpu::irq_save();
    // SAFETY: `spawn` bound this thread to `top` and its process's root before any CPU could
    // switch to it, the program is filled in, and its stack is mapped; masked.
    unsafe {
        Cpu::enter_user(
            ENTRY.load(Ordering::Relaxed),
            userproc::user_stack_pointer(),
            args,
            KernAddr::new(top),
        )
    }
}

/// Wait up to [`DRAIN`] for `id` to exit.
fn wait_dead(id: ThreadId) -> bool {
    let give_up = timekeeping::now().saturating_add(DRAIN);
    while preempt::alive(id) {
        if timekeeping::now() >= give_up {
            return false;
        }
        sleep_until(timekeeping::now().saturating_add(Duration::from_nanos(2_000_000)));
    }
    true
}

fn report_interrupts(c: &dyn EarlyConsole, last: &Reply) {
    c.write_str("; ");
    write_usize(c, last.submitted as usize);
    c.write_str(" requests, ");
    write_usize(c, last.completions as usize);
    c.write_str(" completions in ");
    write_usize(c, last.messages as usize);
    c.write_str(" interrupt messages");
    if last.messages > 0 {
        c.write_str(" (");
        write_usize(c, (last.latency_total / last.messages) as usize);
        c.write_str(" ns mean, ");
        write_usize(c, last.latency_max as usize);
        c.write_str(" ns worst forward)");
    }
    let dropped = DROPPED.load(Ordering::Relaxed);
    if dropped != 0 {
        c.write_str(", ");
        write_usize(c, dropped as usize);
        c.write_str(" coalesced");
    }
}

fn failed(c: &dyn EarlyConsole, what: &str) -> bool {
    c.write_str("; ");
    c.write_str(what);
    c.write_str(" FAILED");
    false
}

fn write_hex(c: &dyn EarlyConsole, value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = HEX[((value >> (60 - 4 * i)) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

/// The embedded domain program, linked for this target and embedded by kbuild; see
/// `user/blkdomain`.
static DOMAIN_ELF: &[u8] = include_bytes!(env!("KINTANE_USER_BLKDOMAIN"));

fn program() -> Option<elf::Program<'static>> {
    elf::Program::parse(
        DOMAIN_ELF,
        <Cpu as HasUserMode>::ELF_MACHINE,
        (<Cpu as HasUserMode>::USER_START as u64, <Cpu as HasUserMode>::USER_END as u64),
        Cpu::PAGE_SIZE as u64,
    )
    .ok()
}
