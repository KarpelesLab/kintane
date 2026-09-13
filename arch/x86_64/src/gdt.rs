//! The runtime GDT and the task state segment that carries the #DF stack.
//!
//! ## Why there is a second GDT
//!
//! `boot.rs` builds a two-entry GDT in assembly — a null descriptor and a 64-bit code
//! segment — because long mode cannot be entered without one. That table is enough to
//! run code and not enough to *survive a broken stack*, and the difference is this
//! file.
//!
//! Long mode kept almost nothing of the 286's segmentation, but it kept the task
//! state segment, repurposed: no hardware task switching, no register save area, just
//! two tables of stack pointers. The one that matters here is the **interrupt stack
//! table**, seven addresses an IDT gate may select by index. A gate with a non-zero
//! IST index makes the CPU load RSP from that slot *before* it pushes anything —
//! unconditionally, including when the interrupt did not change privilege level, which
//! is the case a 32-bit CPU had no answer for at all.
//!
//! ## Why #DF specifically
//!
//! A double fault means the CPU faulted while delivering a fault. The commonest way to
//! reach it is a stack that can no longer be pushed to: the first fault is whatever
//! touched the bad stack, and delivering *that* fault needs a push, which faults again.
//! Without an IST the same is true of #DF's own delivery, so the CPU gives up and
//! triple-faults — and a triple fault is a machine reset with no report, which means
//! the single failure mode that most needs a diagnostic is the one that destroys the
//! evidence of itself. An IST breaks the cycle by not using the broken stack.
//!
//! #DF is the only gate given an IST here. #NMI, #MC and #BP are the other traditional
//! candidates, and each is a judgement about re-entrancy rather than about stacks: an
//! IST stack is a *single* stack, so a second interrupt on the same index overwrites
//! the first one's frame. That is acceptable for #DF because #DF does not return.
//! Giving NMI an IST is right once there is an NMI handler that can be re-entered
//! safely, and wrong before then; the slots are left free rather than filled
//! speculatively.
//!
//! ## Layout and why it is not larger
//!
//! Four slots: null, the 64-bit code segment, and the TSS descriptor, which is a
//! *system* descriptor and so occupies two slots rather than one. The code descriptor
//! is bit-for-bit the one `boot.rs` installed, at the same index, so `CS` stays valid
//! across the `lgdt` with no far jump — and it must exist, because every `iret` out of
//! an interrupt reloads `CS` from the stack and re-reads this table.
//!
//! No data segment is defined. In 64-bit mode `DS`/`ES`/`SS` are ignored for
//! addressing and the boot path loads them with the null selector; the descriptors
//! that will be needed are the ring-3 pair, and those arrive with userspace, together
//! with `rsp0` in the TSS below, which is meaningless until there is a ring to come
//! back from.
//!
//! ## What this was verified against, and the gap it exposed
//!
//! Two throwaway experiments under QEMU with `-d int`, neither of which survives in
//! the tree:
//!
//! 1. **RSP pointed past the end of the identity map, then pushed.** The trace reads
//!    `check_exception old: 0xffffffff new 0xe` (a #PF on the write), then `check_exception old:
//!    0xe new 0xe` escalating to `v=08`, and the #DF report comes out over the serial console
//!    naming `rsp 0x0000000080000000` and `cr2 0x000000007ffffff8`. With the IST index changed to 0
//!    and nothing else touched, the same run ends `check_exception old: 0x8 new 0xe` — the double
//!    fault could not be delivered either — and QEMU shuts down with no output at all. That is the
//!    mechanism working, and the control confirming it is the IST that made the difference.
//!
//! 2. **A genuine unbounded recursion off the boot stack**, which at the time did *not* produce a
//!    clean report, for a reason worth recording. `boot.rs` then put `pml4`, `pdpt` and `pd` in
//!    `.bss` immediately *below* `stack_bottom`, and there was no guard page. So an overflowing
//!    stack walked straight into the page tables the machine was running on and unmapped
//!    everything, including this file's IST stack, which is in the same `.bss`. The run ended in an
//!    endless #PF/#DF alternation rather than a report.
//!
//! The IST was therefore necessary and not sufficient. What makes a stack overflow
//! *diagnosable* rather than merely survivable is a guard page below the stack, so that
//! the overflow faults at a boundary instead of eating whatever is underneath.
//!
//! That half now exists. `link.ld` puts the boot stack first in the writable region
//! with a page below it that belongs to no output section, reported through
//! `image_sections()` as `stack_guard` and left unmapped by the kernel address space
//! builder; the page tables moved above the stack, into `.bss`. An overflow's first
//! push past `__stack_bottom` now lands on an unmapped page and this file's IST carries
//! the report — which is to say experiment 2 has been turned into experiment 1.
//!
//! ## Per-CPU
//!
//! One GDT, one TSS and one #DF stack per CPU, indexed by the CPU's logical number. Two
//! CPUs sharing an IST stack would have the second's double fault overwrite the first's
//! frame, and a TSS is marked busy by the `ltr` that loads it, so a second CPU loading the
//! first's is #GP. The boot CPU's #DF stack keeps its 16 KiB. A secondary's is 8 KiB,
//! because every CPU the port could start pays for its stack in `.bss` whether or not it
//! is started, and what the #DF handler needs is a report and a bounded backtrace, a few
//! hundred bytes of frames. The IDT stays shared: every CPU loads the same one.
//!
//! Reference: Intel SDM Vol. 3A, §7.7 (64-bit TSS format), §6.14.5 (the interrupt
//! stack table), and §3.5.2 / figure 8-4 (the system-segment descriptor, and why it is
//! sixteen bytes in long mode).

use core::cell::UnsafeCell;
use core::mem::size_of;

use crate::smp::MAX_CPUS;

/// The 64-bit code segment descriptor, identical to the one `boot.rs` loads.
///
/// Executable (43), a code/data rather than a system descriptor (44), present (47),
/// and 64-bit (53). Base and limit are absent from the encoding's point of view — in
/// long mode the CPU ignores both and this segment covers everything.
const CODE64: u64 = (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53);

/// Index of the code segment. Must match `boot.rs`, whose far jump put `0x08` in `CS`.
const CODE_INDEX: usize = 1;
/// Index of the TSS descriptor, which occupies this slot and the next.
const TSS_INDEX: usize = 2;

/// The selector `ltr` is given: index 2, table GDT, RPL 0.
pub const TSS_SELECTOR: u16 = (TSS_INDEX as u16) << 3;

/// The IST slot the #DF gate selects, as an index into [`Tss::ist`].
const DF_IST_SLOT: usize = 0;

/// The IST *index* as an IDT gate encodes it: one-based, because zero in that field
/// means "no IST, use the normal stack".
pub const DF_IST_INDEX: u8 = (DF_IST_SLOT as u8) + 1;

/// Size of the dedicated double-fault stack.
///
/// 16 KiB, the same as the boot stack. The handler itself needs a few hundred bytes —
/// it formats a fixed report through a polled UART and halts — so this is sized for
/// what a future one might do (walk a stack, consult a page table) rather than for
/// what it does now. Undersizing it would be a particularly bad joke: a double-fault
/// handler that overflows its own stack triple-faults exactly like the case it exists
/// to diagnose.
const DF_STACK_BYTES: usize = 16 * 1024;

/// A secondary CPU's #DF stack; see the module documentation for why it is smaller.
const SECONDARY_DF_STACK_BYTES: usize = 8 * 1024;

/// A stack, aligned so the CPU's 16-byte alignment of RSP on IST entry never has to
/// move the pointer out of the object.
///
/// The `UnsafeCell` is load-bearing and was not there at first. Without it this is an
/// immutable static of zeroes, and the linker puts it in `.rodata` — verified by
/// reading the section headers, where the stack top landed at `0x10b420` inside a
/// `.rodata` spanning `0x107000..0x10b980`. Nothing complains today, because the boot
/// identity map is 2 MiB pages with the writable bit set and no NX, so `.rodata` is
/// only a name. It stops being only a name the moment real page protections exist, and
/// what breaks then is the CPU pushing the double-fault frame onto a read-only page —
/// which is a triple fault, in the handler whose entire purpose is to not triple-fault.
/// Interior mutability puts it in `.bss`, which is what it is.
#[repr(C, align(16))]
struct Stack<const N: usize>(UnsafeCell<[u8; N]>);

// SAFETY: this static is never read or written by Rust code — only its address is
// taken, and only to be handed to the CPU as a stack pointer. The CPU is the sole
// writer, one delivery at a time on the one CPU whose TSS names it, and #DF does not
// return.
unsafe impl<const N: usize> Sync for Stack<N> {}

/// Backing store for the double-fault stack.
///
/// Still no guard page below *this* one. The boot stack has one — `link.ld` places it
/// and `image_sections()` reports it — but this stack is an ordinary `.bss` static
/// surrounded by other `.bss` statics, and carving a hole around it means the linker
/// script placing it too, which is the shape a per-CPU stack allocator will want
/// anyway. Overflowing the double-fault stack is a triple fault either way; a guard
/// page would turn it into a #PF the handler cannot service, which is not obviously
/// better. Revisit when there is more than one CPU and stacks stop being statics.
static DF_STACK: Stack<DF_STACK_BYTES> = Stack(UnsafeCell::new([0; DF_STACK_BYTES]));

/// The secondaries' #DF stacks, CPU 1 in slot 0.
static SECONDARY_DF_STACKS: [Stack<SECONDARY_DF_STACK_BYTES>; MAX_CPUS - 1] =
    [const { Stack(UnsafeCell::new([0; SECONDARY_DF_STACK_BYTES])) }; MAX_CPUS - 1];

/// The top of CPU `cpu`'s #DF stack, or `None` past [`MAX_CPUS`].
fn df_stack_top_for(cpu: usize) -> Option<u64> {
    if cpu == 0 {
        return Some(DF_STACK.0.get() as usize as u64 + DF_STACK_BYTES as u64);
    }
    let stack = SECONDARY_DF_STACKS.get(cpu - 1)?;
    Some(stack.0.get() as usize as u64 + SECONDARY_DF_STACK_BYTES as u64)
}

/// The 64-bit task state segment.
///
/// Nothing in it is a task's state, despite the name: long mode kept the structure and
/// discarded the meaning. `packed(4)` because the architecture places eight-byte stack
/// pointers at four-byte-aligned offsets — `rsp0` is at offset 4 — so the natural Rust
/// layout would insert padding the CPU does not expect.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct Tss {
    reserved0: u32,
    /// Stack to switch to on entry to ring 0 from a lower ring. Unused while the
    /// kernel is the only thing running; set when userspace exists.
    rsp: [u64; 3],
    reserved1: u64,
    /// The interrupt stack table. Slot `n` here is IST index `n + 1` in a gate.
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// Offset from the base of the TSS to the I/O permission bitmap.
    ///
    /// Set to the size of the TSS, which is past its limit: the architecture reads
    /// that as "no bitmap", and every `in`/`out` from ring 3 faults. The alternative —
    /// leaving it zero — points the CPU at the start of the TSS and makes the first
    /// bytes of this structure an I/O permission map, which is a way to grant
    /// userspace port access by accident.
    iomap_base: u16,
}

/// The TSS as a static with interior mutability, on the same invariant as the IDT.
struct TssCell(UnsafeCell<Tss>);

// SAFETY: single-writer-then-frozen, per CPU. `init_cpu` is the only writer of CPU `n`'s
// cell, runs once on CPU `n` with interrupts masked and before `ltr` makes that CPU care
// what is in here, and no other CPU ever touches that cell. After that the structure is
// read by hardware only — the CPU reads an IST slot when it delivers #DF.
unsafe impl Sync for TssCell {}

static TSS: [TssCell; MAX_CPUS] = [const {
    TssCell(UnsafeCell::new(Tss {
        reserved0: 0,
        rsp: [0; 3],
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        // Cannot be `size_of::<Tss>()` in a const initialiser without naming the type
        // twice; the assertion below checks the two agree.
        iomap_base: 104,
    }))
}; MAX_CPUS];

const _: () = assert!(
    size_of::<Tss>() == 104,
    "the 64-bit TSS is architecturally 104 bytes; a different size means the field \
     offsets no longer match what the CPU reads"
);

/// The table. Four `u64` slots: null, code, and the two halves of the TSS descriptor.
#[repr(C, align(16))]
struct Gdt([u64; 4]);

/// The GDT as a static with interior mutability, on the same invariant as the TSS.
struct GdtCell(UnsafeCell<Gdt>);

// SAFETY: as `TssCell` — written once by `init` before `lgdt`, read by hardware only
// afterwards, and no concurrency exists at that point in boot.
unsafe impl Sync for GdtCell {}

static GDT: [GdtCell; MAX_CPUS] = [const { GdtCell(UnsafeCell::new(Gdt([0; 4]))) }; MAX_CPUS];

/// The operand of `lgdt`: a 16-bit limit followed by a 64-bit base, unpadded.
#[repr(C, packed(2))]
struct Gdtr {
    limit: u16,
    base: u64,
}

/// Build the two halves of a 64-bit system-segment descriptor for `base`/`limit`.
///
/// Returned as `(low, high)` because the descriptor spans two GDT slots: the low half
/// has the same shape as a 32-bit one and the high half is the upper 32 bits of the
/// base with the rest reserved. That extension is the only change long mode made to
/// the descriptor format, and it applies to system descriptors only — which is why a
/// code segment stays eight bytes and this does not.
fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    // Present, DPL 0, system descriptor, type 9 = available 64-bit TSS. Type 11 is the
    // *busy* variant, which the CPU writes back when `ltr` loads this descriptor;
    // presenting a busy TSS to `ltr` is #GP, so it must be 9 here.
    const AVAILABLE_TSS64: u64 = 0x89;

    let low = (u64::from(limit) & 0xffff)
        | ((base & 0xff_ffff) << 16)
        | (AVAILABLE_TSS64 << 40)
        | (((u64::from(limit) >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    let high = base >> 32;
    (low, high)
}

/// Install the boot CPU's GDT and TSS, and point its task register at them.
///
/// # Safety
/// As [`init_cpu`], on the boot CPU.
pub unsafe fn init() {
    // SAFETY: forwarded.
    let _ = unsafe { init_cpu(0) };
}

/// Install CPU `cpu`'s GDT and TSS, and point its task register at them. `false` past
/// [`MAX_CPUS`].
///
/// After this returns, a gate with IST index [`DF_IST_INDEX`] will switch to this CPU's
/// dedicated stack on delivery. `CS` is not reloaded and does not need to be: the code
/// descriptor at index 1 is the one it already refers to, on the boot CPU from `boot.rs`
/// and on a secondary from its trampoline.
///
/// # Safety
/// Must be called once per CPU, on that CPU, with interrupts masked, before any gate that
/// names an IST index can be delivered to it. Replacing the GDT out from under running
/// code is otherwise undefined: the CPU keeps the descriptors it has already loaded in its
/// hidden registers, so a mismatched table is not detected until the next `iret` or far
/// transfer, at which point the failure is a #GP inside the fault path.
pub unsafe fn init_cpu(cpu: usize) -> bool {
    // The stack grows down, so the IST slot holds the address one past the end of the
    // buffer. The raw pointer is never dereferenced here: this address is deliberately
    // out of bounds and only ever used by hardware as a starting point to subtract
    // from.
    let (Some(stack_top), Some(tss_cell), Some(gdt_cell)) =
        (df_stack_top_for(cpu), TSS.get(cpu), GDT.get(cpu))
    else {
        return false;
    };

    // SAFETY: upholds the TssCell invariant — the caller guarantees this runs once, on
    // this CPU, with interrupts masked and before `ltr` below, so this `&mut` is the only
    // live reference and no hardware is reading the structure yet.
    let tss = unsafe { &mut *tss_cell.0.get() };
    let mut ist = [0u64; 7];
    ist[DF_IST_SLOT] = stack_top;
    tss.ist = ist;
    tss.iomap_base = size_of::<Tss>() as u16;

    let tss_base = tss_cell.0.get() as u64;
    // The limit is inclusive, and must cover the whole structure: a TSS whose limit is
    // shorter than 104 bytes is #TS on the first access the CPU makes past it.
    let (tss_low, tss_high) = tss_descriptor(tss_base, (size_of::<Tss>() - 1) as u32);

    // SAFETY: upholds the GdtCell invariant, for the same reasons as the TSS above —
    // written before the `lgdt` that makes the CPU care.
    let gdt = unsafe { &mut *gdt_cell.0.get() };
    let mut table = [0u64; 4];
    table[CODE_INDEX] = CODE64;
    table[TSS_INDEX] = tss_low;
    table[TSS_INDEX + 1] = tss_high;
    gdt.0 = table;

    let gdtr = Gdtr {
        limit: (size_of::<Gdt>() - 1) as u16,
        base: gdt_cell.0.get() as u64,
    };

    // SAFETY: `lgdt` copies ten bytes from a live, correctly shaped local into GDTR,
    // and the table it names is a static that outlives everything. The table's index 1
    // holds the identical code descriptor `CS` was loaded from, so the selector the
    // CPU is executing under stays valid; `ltr` then loads the task register from
    // index 2, which the two writes above have just filled with an available — not
    // busy — 64-bit TSS descriptor. Neither instruction transfers control.
    unsafe {
        core::arch::asm!(
            "lgdt [{gdtr}]",
            "ltr {sel:x}",
            gdtr = in(reg) &gdtr,
            sel = in(reg) TSS_SELECTOR,
            options(readonly, nostack, preserves_flags),
        );
    }
    true
}

/// Whether the running CPU has CPU `cpu`'s own tables loaded: its GDTR names `cpu`'s GDT,
/// and that GDT's task descriptor names `cpu`'s TSS, whose #DF slot is `cpu`'s stack.
///
/// Read from the CPU with `sgdt`, so a CPU that loaded another CPU's tables, which `ltr`
/// does not refuse once the descriptor is rewritten as available, is caught: the two would
/// share one #DF stack, and the second double fault would overwrite the first's frame.
pub fn owns_tables(cpu: usize) -> bool {
    let (Some(gdt_cell), Some(tss_cell), Some(top)) =
        (GDT.get(cpu), TSS.get(cpu), df_stack_top_for(cpu))
    else {
        return false;
    };
    let mut gdtr = Gdtr { limit: 0, base: 0 };
    // SAFETY: `sgdt` stores ten bytes into its operand, which is a live, correctly shaped
    // local; it has no other effect and is unprivileged.
    unsafe {
        core::arch::asm!(
            "sgdt [{}]",
            in(reg) &mut gdtr,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: shared reads of structures written only by `init_cpu`, which has returned.
    let (gdt, tss) = unsafe { (&*gdt_cell.0.get(), &*tss_cell.0.get()) };
    let low = gdt.0[TSS_INDEX];
    let high = gdt.0[TSS_INDEX + 1];
    let base = (low >> 16) & 0xff_ffff | ((low >> 56) << 24) | (high << 32);
    let ist = tss.ist;
    let loaded = gdtr.base;
    loaded == gdt_cell.0.get() as u64
        && base == tss_cell.0.get() as u64
        && ist[DF_IST_SLOT] == top
        && task_register() == TSS_SELECTOR
}

/// The selector currently in the task register.
///
/// Read back rather than assumed, so the selftest can report that the TSS is loaded as
/// an observation. Zero means `ltr` has not run, and therefore that the #DF gate's IST
/// index names a slot the CPU has no table to find.
pub fn task_register() -> u16 {
    let tr: u16;
    // SAFETY: `str` reads the task register's selector into its operand. It has no
    // side effects and is unprivileged.
    unsafe {
        core::arch::asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    tr
}

/// The address the CPU will load into RSP when it delivers #DF.
///
/// Read back out of the TSS for the same reason as [`task_register`]: the selftest
/// reports what the hardware will actually do, not what this module intended.
pub fn df_stack_top() -> u64 {
    df_stack_top_of(0)
}

/// The address CPU `cpu`'s TSS says the CPU will load into RSP when it delivers #DF. Zero
/// for a CPU whose TSS was never built.
pub fn df_stack_top_of(cpu: usize) -> u64 {
    let Some(cell) = TSS.get(cpu) else {
        return 0;
    };
    // SAFETY: a shared read of a structure that, by the TssCell invariant, is written
    // only by `init_cpu` and afterwards never again. No `&mut` can be live here, because
    // `init_cpu` does not return while holding one.
    let tss = unsafe { &*cell.0.get() };
    // Copied out whole: the field is in a `packed` structure, so indexing it in place
    // would form a reference the alignment rules forbid.
    let ist = tss.ist;
    ist[DF_IST_SLOT]
}
