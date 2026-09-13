//! The runtime GDT, and the double-fault task that reports a stack overflow.
//!
//! ## The problem a task gate solves here
//!
//! A recursion that reaches a guard page faults on a push. Delivering that #PF needs a
//! push onto the same stack, which faults again, so the CPU raises #DF, and delivering
//! #DF through an interrupt gate needs a push onto that same stack a third time. That one
//! faults too, and a fault while delivering #DF is a triple fault: a machine reset with no
//! report. x86-64 breaks the cycle with an IST slot, a stack pointer the CPU loads before
//! it pushes anything. A 32-bit gate descriptor has no IST field (see `idt.rs`).
//!
//! What 32-bit protected mode has instead is the task gate. A task gate names a TSS rather
//! than a handler. Delivering through one is a hardware task switch: the CPU saves the
//! interrupted state into the current task's TSS, then loads *every* register from the
//! target TSS, `ESP` included, and only then pushes the error code, onto the stack it just
//! loaded. Nothing is pushed on the broken stack at all. That is the whole mechanism, and
//! it is why #DF is the one vector that uses it: no other vector here needs a stack of its
//! own, and a task gate cannot be returned through the way an interrupt gate can.
//!
//! ## What the switch needs
//!
//! * **A current task.** The switch saves the outgoing state into the TSS that `TR` names, so `TR`
//!   must name one before the first double fault. [`init`] loads [`MAIN_TSS_SELECTOR`], a TSS whose
//!   only use is to receive that save. The report reads the interrupted `EIP`, `ESP` and `EBP` back
//!   out of it, which is how it prints the faulting instruction and walks the overflowed stack from
//!   another one.
//! * **A writable GDT.** `ltr` sets the busy bit in the main TSS's descriptor, and the task switch
//!   sets it in the double-fault TSS's. `boot.rs`'s table is in `.rodata`, which the kernel address
//!   space maps read-only with `CR0.WP` set, so the CPU's own write would fault. The table here is
//!   an interior-mutable static, which the linker places with the writable data.
//! * **The right `CR3`.** A task switch loads `CR3` from the target TSS, so the double-fault task
//!   must name the tables the kernel is running on, not the ones that were live when this was set
//!   up. `paging::set_root` calls [`follow_root`] every time the root changes.
//!
//! ## Layout
//!
//! Five descriptors: null, flat 32-bit ring-0 code and data bit-for-bit as `boot.rs` built
//! them and at the same selectors, so the cached `CS` and data segments stay accurate across
//! the `lgdt` and every `iret` reloads `CS` from an identical descriptor, then the two TSS
//! descriptors. A 32-bit system descriptor is eight bytes, one slot each.
//!
//! One GDT, two TSSes, one double-fault stack, all statics, which is correct for as long as
//! `HasSmp::cpu_id` returns a constant 0; SMP needs one of each per CPU.
//!
//! Reference: Intel SDM Vol. 3A, §8.2 (the TSS and its descriptor), §8.3 (task switching),
//! §6.11 (task gates in the IDT), and §6.15 "Interrupt 8".

use core::cell::UnsafeCell;
use core::mem::size_of;

/// Flat 4 GiB ring-0 32-bit code, identical to the descriptor `boot.rs` loads at `0x08`.
const CODE32: u64 = 0x00CF_9A00_0000_FFFF;
/// Flat 4 GiB ring-0 writable data, identical to the descriptor `boot.rs` loads at `0x10`.
const DATA32: u64 = 0x00CF_9200_0000_FFFF;

const CODE_SELECTOR: u32 = 0x08;
const DATA_SELECTOR: u32 = 0x10;

/// The TSS the kernel runs as, loaded into `TR`: index 3, GDT, RPL 0.
pub const MAIN_TSS_SELECTOR: u16 = 3 << 3;
/// The TSS the #DF task gate names: index 4, GDT, RPL 0.
pub const DF_TSS_SELECTOR: u16 = 4 << 3;

/// A 32-bit TSS: 104 bytes, every field a 32-bit slot whose unused upper bits are zero.
#[repr(C)]
struct Tss([u32; 26]);

// Slot indices, SDM Vol. 3A figure 8-2.
const CR3: usize = 7;
const EIP: usize = 8;
const EFLAGS: usize = 9;
const ESP: usize = 14;
const EBP: usize = 15;
const ES: usize = 18;
const CS: usize = 19;
const SS: usize = 20;
const DS: usize = 21;
const FS: usize = 22;
const GS: usize = 23;
/// Low half: the debug-trap bit. High half: the I/O map base.
const IOMAP: usize = 25;

/// A TSS is exactly this many bytes, and the descriptor's limit is one less.
const TSS_BYTES: u32 = size_of::<Tss>() as u32;

/// Stack for the double-fault task. It holds the report and the backtrace walk, both of
/// which are shallow; it is never entered twice, because #DF does not return.
const DF_STACK_BYTES: usize = 16 * 1024;

struct Tables {
    gdt: [u64; 5],
    main: Tss,
    df: Tss,
}

/// The descriptor table and both task state segments.
struct TablesCell(UnsafeCell<Tables>);

// SAFETY: written by `init` and `follow_root` only, each on the one CPU with interrupts
// masked (the callers' contracts), and otherwise read by the CPU itself: the GDT on every
// segment load and task switch, the TSSes on a task switch. `double_fault_task` reads the
// main TSS after a switch wrote it, from the only running context.
unsafe impl Sync for TablesCell {}

static TABLES: TablesCell = TablesCell(UnsafeCell::new(Tables {
    gdt: [0, CODE32, DATA32, 0, 0],
    main: Tss([0; 26]),
    df: Tss([0; 26]),
}));

#[repr(C, align(16))]
struct Stack(UnsafeCell<[u8; DF_STACK_BYTES]>);

// SAFETY: only its address is taken; the CPU uses it as the double-fault task's stack.
unsafe impl Sync for Stack {}

static DF_STACK: Stack = Stack(UnsafeCell::new([0; DF_STACK_BYTES]));

/// The operand of `lgdt`: a 16-bit limit and a 32-bit base.
#[repr(C, packed(2))]
struct Gdtr {
    limit: u16,
    base: u32,
}

/// An available 32-bit TSS descriptor for `size` bytes at `base`: type 0x9, present, DPL 0,
/// byte granularity.
fn tss_descriptor(base: u32, size: u32) -> u64 {
    let limit = u64::from(size - 1);
    let base = u64::from(base);
    (limit & 0xffff)
        | ((base & 0xff_ffff) << 16)
        | (0x89 << 40)
        | (((limit >> 16) & 0xf) << 48)
        | ((base >> 24) << 56)
}

core::arch::global_asm!(
    r#"
// Entered by a hardware task switch, with every register loaded from the double-fault
// TSS: this stack, interrupts masked, the kernel's CR3. The CPU pushed the error code
// here after loading ESP, which is the point of arriving this way.
//
// `clts` first. Every hardware task switch sets CR0.TS, so that an OS doing lazy FPU
// switching gets a #NM before the new task touches the FPU. This target cannot avoid
// SSE (see `boot.rs`), so without it the report's first `movaps` raises #NM, whose
// handler uses SSE too, and the recursion eats this stack and then the data below it.
// That is not a hypothesis; it is what the first version of this file did.
.section .text.df_task, "ax"
.globl i686_df_task_entry
i686_df_task_entry:
    clts
    popl    %eax
    xorl    %ebp, %ebp
    andl    $-16, %esp
    subl    $12, %esp
    pushl   %eax
    call    i686_double_fault_task
.Ldf_hang:
    cli
    hlt
    jmp     .Ldf_hang
"#,
    options(att_syntax)
);

unsafe extern "C" {
    fn i686_df_task_entry();
}

/// Load the runtime GDT and `TR`, and prepare the double-fault task.
///
/// # Safety
/// Once, on the boot CPU, with interrupts masked, before the #DF task gate is installed.
pub unsafe fn init() {
    let t = TABLES.0.get();
    // SAFETY: the `TablesCell` contract: once, masked, single CPU, and no reference to the
    // tables is live anywhere else.
    let t = unsafe { &mut *t };
    let main = &raw const t.main as u32;
    let df = &raw const t.df as u32;
    t.gdt[3] = tss_descriptor(main, TSS_BYTES);
    t.gdt[4] = tss_descriptor(df, TSS_BYTES);

    // No I/O permission bitmap: a base at or past the limit means none, which only matters
    // below the IOPL, and nothing runs there.
    t.main.0[IOMAP] = TSS_BYTES << 16;
    t.df.0[IOMAP] = TSS_BYTES << 16;

    t.df.0[CR3] = crate::paging::read_cr3();
    t.df.0[EIP] = i686_df_task_entry as *const () as usize as u32;
    // Reserved bit 1 set, IF clear: the report runs masked.
    t.df.0[EFLAGS] = 0x2;
    t.df.0[ESP] = DF_STACK.0.get() as u32 + DF_STACK_BYTES as u32;
    t.df.0[CS] = CODE_SELECTOR;
    for seg in [SS, DS, ES, FS, GS] {
        t.df.0[seg] = DATA_SELECTOR;
    }

    let gdtr = Gdtr {
        limit: (size_of::<[u64; 5]>() - 1) as u16,
        base: t.gdt.as_ptr() as u32,
    };
    // SAFETY: the new table holds the same code and data descriptors at the same
    // selectors as the one being replaced, so every cached segment stays accurate and the
    // next reload of any of them finds an identical descriptor. `ltr` names an available
    // TSS descriptor just written, and marks it busy in this writable table.
    unsafe {
        core::arch::asm!(
            "lgdt [{gdtr}]",
            "ltr {sel:x}",
            gdtr = in(reg) &gdtr,
            sel = in(reg) MAIN_TSS_SELECTOR,
            options(nostack, preserves_flags)
        );
    }
}

/// Make the double-fault task run on `root`, the page table root being installed now.
///
/// Called by `paging::set_root` before `CR3` is loaded, so there is no window in which a
/// double fault would switch to tables that are no longer live.
pub fn follow_root(root: u32) {
    // SAFETY: a single slot write, by the one CPU, under `set_root`'s contract. The CPU only
    // reads this slot on a task switch to the double-fault task, which cannot be running
    // (it never returns).
    unsafe { (*TABLES.0.get()).df.0[CR3] = root };
}

/// The task register, read back from the CPU.
pub fn task_register() -> u16 {
    let tr: u32;
    // SAFETY: `str` copies the task register selector and has no side effects.
    unsafe {
        core::arch::asm!("str {:e}", out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    tr as u16
}

/// The top of the double-fault task's stack, and the `CR3` it will load.
pub fn df_task() -> (u32, u32) {
    // SAFETY: reads of two slots written by `init` and `follow_root`, from the one CPU.
    let df = unsafe { &(*TABLES.0.get()).df };
    (df.0[ESP], df.0[CR3])
}

/// Runs as the double-fault task. Reads the interrupted state the switch saved and reports.
#[unsafe(no_mangle)]
extern "C" fn i686_double_fault_task(code: u32) -> ! {
    // SAFETY: the task switch that brought us here wrote the interrupted state into the
    // main TSS and nothing has run since. Read, never written.
    let main = unsafe { &(*TABLES.0.get()).main };
    crate::exception::double_fault_task(
        code,
        crate::exception::Interrupted {
            eip: main.0[EIP],
            cs: main.0[CS],
            eflags: main.0[EFLAGS],
            esp: main.0[ESP],
            ebp: main.0[EBP],
        },
    )
}
