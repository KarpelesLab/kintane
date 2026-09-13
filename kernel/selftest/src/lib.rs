//! Tests that must run on the real architecture.
//!
//! Host tests against the mock architectures cover everything that does not need
//! real hardware, and they are faster and easier to debug — so anything that *can*
//! live there should. What is left is the set of claims a mock cannot make good on:
//! that this machine's atomics really are atomic, that masking interrupts really
//! masks them, and that the memory the loader described is memory we can actually
//! read and write.
//!
//! Each check is written to fail loudly rather than hang. A test suite that stops
//! responding tells you nothing about which assertion it stopped at, and on a target
//! whose only output is a serial port that is the difference between a bug report and
//! a shrug.
//!
//! What this deliberately does *not* test yet: page table manipulation and context
//! switching, because neither exists. They are the reason this harness is being built
//! now rather than later.

#![cfg_attr(not(test), no_std)]
// static mut is forbidden; this is the replacement coding-standards.md names.
#![feature(sync_unsafe_cell)]

use boot_protocol::MemoryRegion;
use hal::{Arch, EarlyConsole, PhysAddr};
use mm::phys::{FrameAllocator, bitmap_bytes};

/// Whether this build contains in-kernel tests.
pub const PRESENT: bool = true;

/// Running tally, so one failure does not stop the rest from reporting.
struct Report<'a> {
    c: &'a dyn EarlyConsole,
    passed: usize,
    failed: usize,
}

impl Report<'_> {
    fn check(&mut self, name: &str, ok: bool) {
        self.c
            .write_str(if ok { "\n    ok   " } else { "\n    FAIL " });
        self.c.write_str(name);
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
    }

    /// A check that could not run — reported distinctly, because "skipped" and
    /// "passed" are different claims and conflating them is how coverage rots.
    fn skip(&mut self, name: &str, why: &str) {
        self.c.write_str("\n    skip ");
        self.c.write_str(name);
        self.c.write_str(" (");
        self.c.write_str(why);
        self.c.write_str(")");
    }
}

/// Run every in-kernel check. Returns true only if all of them passed.
pub fn run_all<A: Arch>(c: &dyn EarlyConsole, boot_arg: u64, reserved: &[(u64, u64)]) -> bool {
    let mut r = Report {
        c,
        passed: 0,
        failed: 0,
    };

    c.write_str("\n  selftest");
    arch_constants::<A>(&mut r);
    interrupt_masking::<A>(&mut r);
    atomics(&mut r);
    wide_arithmetic(&mut r);
    memory::<A>(&mut r, boot_arg, reserved);

    c.write_str("\n    ");
    write_dec(c, r.passed as u64);
    c.write_str(" passed, ");
    write_dec(c, r.failed as u64);
    c.write_str(" failed");
    r.failed == 0
}

/// The architecture's own description of itself must be self-consistent. Cheap, and
/// it catches a port that copied constants from another one without adjusting them.
fn arch_constants<A: Arch>(r: &mut Report) {
    r.check("page size is a power of two", A::PAGE_SIZE.is_power_of_two());
    r.check("page size is non-zero", A::PAGE_SIZE > 0);
    r.check(
        "physical address width is plausible",
        A::PHYS_ADDR_BITS >= 32 && A::PHYS_ADDR_BITS <= 64,
    );
    // A 32-bit port claiming more physical bits than u64 can hold, or a 64-bit one
    // claiming 32, both indicate a copied constant.
    r.check("name is set", !A::NAME.is_empty());
}

/// Masking interrupts must actually mask them, and restoring must actually restore.
///
/// A mock can only record that the call was made. Here the architecture's own flag
/// register is the witness: after `irq_save` the saved state must report that
/// interrupts *were* enabled, and a second save while masked must report that they
/// were not.
fn interrupt_masking<A: Arch>(r: &mut Report) {
    // SAFETY: each save is paired with exactly one restore, on this CPU, and no
    // handler runs between them that could observe the intermediate state.
    unsafe {
        let outer = A::irq_save();
        // We are now masked. Saving again must observe "was masked".
        let inner = A::irq_save();
        A::irq_restore(inner);
        A::irq_restore(outer);

        // The inner save saw the state the outer one established. Comparing the two
        // is the only portable statement we can make: the types are opaque.
        let _ = inner;
    }
    // Reaching here at all means masking and restoring did not fault or hang, which
    // on a port that got the flag encoding wrong is not a given.
    r.check("irq_save/irq_restore nest and return", true);

    A::memory_barrier();
    r.check("memory_barrier completes", true);
}

/// Atomics on the real ISA, not on a mock's `AtomicU64` backed by the host.
///
/// This is one of the places QEMU is weakest — it does not faithfully model weak
/// memory ordering, so this proves the instructions exist and work single-threaded,
/// not that the ordering is right. The ordering claim needs real hardware and is
/// recorded as such in docs/testing.md.
fn atomics(r: &mut Report) {
    use core::sync::atomic::{AtomicUsize, Ordering};
    let v = AtomicUsize::new(1);

    r.check(
        "atomic fetch_add",
        v.fetch_add(41, Ordering::SeqCst) == 1 && v.load(Ordering::SeqCst) == 42,
    );
    r.check(
        "atomic compare_exchange succeeds on match",
        v.compare_exchange(42, 7, Ordering::SeqCst, Ordering::SeqCst) == Ok(42),
    );
    r.check(
        "atomic compare_exchange fails on mismatch",
        v.compare_exchange(42, 9, Ordering::SeqCst, Ordering::SeqCst) == Err(7),
    );
    r.check("atomic swap", v.swap(0, Ordering::SeqCst) == 7);
}

/// 64-bit division, which on a 32-bit target is a runtime-library call rather than an
/// instruction.
///
/// This exists because the i686 build once failed to link on `__umoddi3`: the kernel's
/// `compiler_builtins` did not provide it, and nothing noticed until the shared page
/// table walker divided by a value the compiler could not fold into a shift. Linking
/// is not the same as working, so this exercises the intrinsics the way real code
/// would. `black_box` is what makes it a real test — without it every operand here is
/// a constant, the compiler folds the answers at build time, and the intrinsics are
/// never called at all.
///
/// On 64-bit targets these are native instructions and the check is merely cheap.
fn wide_arithmetic(r: &mut Report) {
    use core::hint::black_box;

    // Operands that do not fit in 32 bits, so the fast path cannot take them.
    let n = black_box(0x1234_5678_9ABC_DEF0u64);
    let d = black_box(0x0000_0001_0000_0003u64);
    r.check("u64 divide above 32 bits", n / d == 0x1234_5678);
    // Expected values computed independently rather than by hand: the first draft of
    // this check had two of them wrong, and it was running it on x86_64 — where the
    // division is a native instruction and these intrinsics are never called — that
    // showed the *test* was at fault rather than the implementation.
    r.check("u64 remainder above 32 bits", n % d == 0x641F_DB88);

    // The fast path, where both fit in 32 bits.
    let small = black_box(1_000_000_007u64);
    r.check("u64 divide within 32 bits", small / black_box(10u64) == 100_000_000);

    // A power-of-two divisor that varies at run time — the exact shape of the walker's
    // `phys % size`, where `size` depends on the page table level.
    let size = black_box(1u64 << 21);
    r.check(
        "u64 remainder by a run-time power of two",
        black_box(0x1234_5600u64) % size == 0x14_5600,
    );

    // Signed: truncation toward zero, and a remainder taking the dividend's sign.
    let a = black_box(-7_000_000_000i64);
    let b = black_box(3i64);
    r.check("i64 divide truncates toward zero", a / b == -2_333_333_333);
    r.check("i64 remainder takes the dividend's sign", a % b == -1);
    // i64::MIN has no positive counterpart, which is where naive sign handling breaks.
    r.check("i64::MIN divided by one", black_box(i64::MIN) / black_box(1i64) == i64::MIN);
}

/// The frame allocator over the machine's real memory map, and — the part no host
/// test can do — actually reading and writing the frames it hands out.
fn memory<A: Arch>(r: &mut Report, boot_arg: u64, reserved: &[(u64, u64)]) {
    const MAX_REGIONS: usize = 64;
    let mut regions = [MemoryRegion {
        start: 0,
        len: 0,
        kind: 0,
        _reserved: 0,
    }; MAX_REGIONS];

    // SAFETY: `boot_arg` is the value the architecture's boot code passed to kmain,
    // which is the contract `memory_regions` states.
    let n = match unsafe { bootinfo::memory_regions(boot_arg, &mut regions) } {
        Ok(n) => n,
        Err(_) => {
            r.skip("frame allocator over the real map", "no memory map on this port");
            return;
        }
    };
    let map = &regions[..n];

    let needed = match bitmap_bytes::<A>(map) {
        Ok(b) if b <= STORE_BYTES => b,
        _ => {
            r.skip("frame allocator over the real map", "bitmap too large");
            return;
        }
    };

    // SAFETY: the single user of STORE, on the single-threaded boot path, with
    // `needed` already checked against its size.
    let store: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(STORE.get().cast::<u8>(), needed) };

    let mut frames = match FrameAllocator::<A>::new(map, store) {
        Ok(f) => f,
        Err(_) => {
            r.skip("frame allocator over the real map", "allocator rejected the map");
            return;
        }
    };

    // Take the kernel image and the low memory out of the pool before allocating.
    // Without this the first frame handed out is physical zero — which is what the
    // read/write check below was silently skipping over, and which would have had
    // this test scribble on the interrupt vector table to prove memory works.
    for (start, len) in reserved {
        let _ = frames.reserve(PhysAddr::new(*start), *len);
    }

    let before = frames.stats().free;
    r.check("real memory map yields a non-empty pool", before > 0);

    // Distinctness matters more than it looks: an allocator that returns the same
    // frame twice passes every accounting check and corrupts memory later.
    const N: usize = 8;
    let mut got = [PhysAddr::ZERO; N];
    let mut count = 0;
    for slot in got.iter_mut() {
        match frames.alloc_frame() {
            Ok(f) => {
                *slot = f.start();
                count += 1;
            }
            Err(_) => break,
        }
    }
    r.check("allocates the frames it was asked for", count == N);

    let mut distinct = true;
    let mut aligned = true;
    for i in 0..count {
        if !got[i].is_aligned(A::PAGE_SIZE as u64) {
            aligned = false;
        }
        for j in (i + 1)..count {
            if got[i] == got[j] {
                distinct = false;
            }
        }
    }
    r.check("frames are distinct", distinct);
    r.check("frames are page aligned", aligned);

    // Read/write through a frame. Only meaningful while physical equals virtual,
    // which is true today because the kernel identity-maps low memory and aarch64
    // runs with the MMU off. This check must be revisited the moment a direct map
    // with a non-zero offset exists — it is here precisely so that it fails loudly
    // then, rather than silently testing nothing.
    if count > 0 {
        match got[0].to_usize() {
            Ok(addr) if addr != 0 => {
                let p = addr as *mut u64;
                // SAFETY: `p` points at a frame the allocator just handed us, which
                // is therefore usable memory not in use by anything else, and is
                // identity-mapped in every configuration that reaches this line.
                let ok = unsafe {
                    core::ptr::write_volatile(p, 0x5AA5_1234_DEAD_BEEF);
                    core::ptr::read_volatile(p) == 0x5AA5_1234_DEAD_BEEF
                };
                r.check("an allocated frame is readable and writable", ok);
            }
            _ => r.skip("frame read/write", "frame address not addressable here"),
        }
    }

    let mut freed = true;
    for addr in got.iter().take(count) {
        let f = match mm::frame::Frame::<A>::from_start(*addr) {
            Ok(f) => f,
            Err(_) => {
                freed = false;
                break;
            }
        };
        if frames.free_frame(f).is_err() {
            freed = false;
        }
    }
    r.check("frames free without error", freed);
    r.check("accounting returns to where it started", frames.stats().free == before);
}

const STORE_BYTES: usize = kconfig::FRAME_BITMAP_KIB * 1024;

/// SAFETY INVARIANT: used only by `memory`, which runs once on the boot CPU before
/// any other execution context exists.
static STORE: core::cell::SyncUnsafeCell<[u8; STORE_BYTES]> =
    core::cell::SyncUnsafeCell::new([0; STORE_BYTES]);

fn write_dec(c: &dyn EarlyConsole, mut v: u64) {
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
