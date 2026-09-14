//! `init`: the first native userspace program, and the kernel's test of its own ABI.
//!
//! One program with four modes, chosen by the kernel in the first argument register,
//! because each mode needs exactly the same loader, the same system call path and the
//! same process setup, and what differs is only what the program then tries.
//!
//! * [`MODE_MAIN`] exercises the vertical slice: maps memory and uses it, writes to the debug
//!   console, is refused a write through a console handle without `WRITE`, is refused a copy from a
//!   bad pointer without the kernel faulting, creates a channel and loops a message through it,
//!   closes it, and finally exchanges a message with a kernel thread over the channel the kernel
//!   installed. It exits with [`SUCCESS`], or with a code naming the first step that went wrong.
//! * [`MODE_FORGE`] is given no handles at all, only the raw values of another process's handles as
//!   numbers. It tries to use them, and a handle value it did not receive must be as good as no
//!   handle. It exits with the number of refusals.
//! * [`MODE_FAULT`] writes to the address the kernel passes, which is kernel memory. It must be
//!   killed there, so reaching the exit call is itself the failure.
//! * [`MODE_WORKER`] runs alongside other processes on the scheduler until the kernel tells it to
//!   stop, writing a signature to the private address every worker shares and reading it back on
//!   every pass; see [`worker`]. It exits with [`SUCCESS`], or with a code saying it read memory
//!   that was not its own.
//!
//! No step here decides whether the kernel is right. The program reports what it saw,
//! and the kernel's check compares that with what it expected, so a kernel that lies to
//! the program cannot also be the one grading it.

#![no_std]
#![no_main]

use abi::{Error, Handle, UserPtr, call};

/// Exercise everything; see the module comment.
const MODE_MAIN: usize = 0;
/// Try another process's handle values.
const MODE_FORGE: usize = 1;
/// Write to kernel memory.
const MODE_FAULT: usize = 2;
/// Run alongside another process until told to stop; see [`worker`].
const MODE_WORKER: usize = 3;

/// [`MODE_MAIN`]'s exit code when every step behaved.
pub const SUCCESS: u64 = 0x2a;

/// A worker's exit code when its private page held another process's signature.
const WORKER_STOLEN: u64 = 0x5701;
/// Passes between a worker's system calls. Small enough that the kernel sees a worker
/// within a slice of it starting, large enough that the calls are not the workload.
const YIELD_EVERY: u64 = 64;

/// Words of the page a worker shares with the kernel. The kernel writes [`W_STOP`]; the
/// worker writes the rest.
const W_PASSES: usize = 0;
const W_STOP: usize = 1;
const W_SEEN: usize = 2;

/// The message the kernel's peer answers.
const PING: &[u8; 4] = b"ping";
/// The answer.
const PONG: &[u8; 4] = b"pong";

/// Pages the memory step maps.
const MAP_PAGES: usize = 4;
const PAGE: usize = 4096;

/// An address in the user half that no region covers.
const UNMAPPED: u64 = 0x80_7000_0000;

/// Where the kernel enters. The four arguments are the first four argument registers.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(mode: usize, a: usize, b: usize, c: usize) -> ! {
    let code = match mode {
        MODE_MAIN => main(handle(a), handle(b), handle(c)),
        MODE_FORGE => forge(a, b),
        MODE_FAULT => fault(a),
        MODE_WORKER => worker(a, b, c as u64),
        _ => 0xbad0,
    };
    exit(code)
}

fn handle(raw: usize) -> Handle {
    Handle(raw as u32)
}

fn exit(code: u64) -> ! {
    let _ = call::process_exit(code);
    // Unreachable unless the kernel returned from an exit, which the kernel's check sees
    // as a process that never ended.
    loop {
        let _ = call::thread_yield();
    }
}

/// Every step, in order. Returns [`SUCCESS`], or `0x100 + step` for the first that failed.
fn main(console: Handle, console_ro: Handle, channel: Handle) -> u64 {
    // `talk_to_the_kernel` is defined but not run here: it needs a kernel thread holding the
    // channel's peer, which needs the scheduler, and this slice runs one process at a time
    // with no scheduler. It moves into the sequence when the process runs scheduled.
    let _ = talk_to_the_kernel;
    let steps: [fn(Handle, Handle, Handle) -> bool; 5] = [
        memory,
        console_write,
        console_needs_write,
        bad_pointers_are_refused,
        own_channel,
    ];
    for (i, step) in steps.iter().enumerate() {
        if !step(console, console_ro, channel) {
            return 0x100 + i as u64;
        }
    }
    SUCCESS
}

/// Map pages, fill them, and read every byte back.
fn memory(_: Handle, _: Handle, _: Handle) -> bool {
    let Ok(addr) = call::vm_map(MAP_PAGES * PAGE) else {
        return false;
    };
    let base = addr as *mut u8;
    for i in 0..MAP_PAGES * PAGE {
        // SAFETY: inside the region `vm_map` just returned, which is readable and writable
        // and faults its pages in on first touch.
        unsafe { base.add(i).write_volatile((i % 251) as u8) };
    }
    // SAFETY: as above.
    (0..MAP_PAGES * PAGE).all(|i| unsafe { base.add(i).read_volatile() } == (i % 251) as u8)
}

fn console_write(console: Handle, _: Handle, _: Handle) -> bool {
    let msg = b"hello from userspace\n";
    call::debug_write(console, UserPtr(msg.as_ptr() as u64), msg.len()) == Ok(msg.len() as u64)
}

/// The same console, through a handle without `WRITE`.
fn console_needs_write(_: Handle, console_ro: Handle, _: Handle) -> bool {
    let msg = b"this must not appear\n";
    call::debug_write(console_ro, UserPtr(msg.as_ptr() as u64), msg.len())
        == Err(Error::AccessDenied)
}

/// A pointer below the user half, and one inside it that nothing maps. The first is
/// refused by the range check, the second only once the kernel's copy faults.
fn bad_pointers_are_refused(console: Handle, _: Handle, _: Handle) -> bool {
    call::debug_write(console, UserPtr(0x10), 5) == Err(Error::Fault)
        && call::debug_write(console, UserPtr(UNMAPPED), 5) == Err(Error::Fault)
        // A length that wraps the address space.
        && call::debug_write(console, UserPtr(UNMAPPED), usize::MAX) != Ok(0)
}

/// Create a channel, send through one end, receive on the other, close both, and check a
/// closed handle is dead.
fn own_channel(_: Handle, _: Handle, _: Handle) -> bool {
    let mut pair = [0u8; 8];
    if call::channel_create(UserPtr(pair.as_mut_ptr() as u64)) != Ok(0) {
        return false;
    }
    let a = Handle(u32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]));
    let b = Handle(u32::from_le_bytes([pair[4], pair[5], pair[6], pair[7]]));
    let msg = b"loop";
    if call::channel_write(a, UserPtr(msg.as_ptr() as u64), msg.len()) != Ok(0) {
        return false;
    }
    let mut got = [0u8; 8];
    let read = call::channel_read(b, UserPtr(got.as_mut_ptr() as u64), got.len());
    if read != Ok(4) || &got[..4] != msg {
        return false;
    }
    call::handle_close(a) == Ok(0)
        && call::handle_close(b) == Ok(0)
        && call::channel_write(a, UserPtr(msg.as_ptr() as u64), msg.len()) == Err(Error::BadHandle)
}

/// Send `ping` to the kernel's peer and wait for `pong`.
fn talk_to_the_kernel(_: Handle, _: Handle, channel: Handle) -> bool {
    if call::channel_write(channel, UserPtr(PING.as_ptr() as u64), PING.len()) != Ok(0) {
        return false;
    }
    let mut got = [0u8; 16];
    loop {
        match call::channel_read(channel, UserPtr(got.as_mut_ptr() as u64), got.len()) {
            Ok(4) => return &got[..4] == PONG,
            Err(Error::ShouldWait) => {
                let _ = call::thread_yield();
            }
            _ => return false,
        }
    }
}

/// Use handle values this process was never given. Returns how many attempts were refused
/// as bad handles, or `0x200 + attempt` for the first that got any other answer.
fn forge(channel: usize, console: usize) -> u64 {
    let msg = b"forged\n";
    let ptr = UserPtr(msg.as_ptr() as u64);
    let mut buf = [0u8; 8];
    let attempts = [
        call::debug_write(handle(console), ptr, msg.len()),
        call::channel_write(handle(channel), ptr, msg.len()),
        call::channel_read(handle(channel), UserPtr(buf.as_mut_ptr() as u64), buf.len()),
        call::handle_close(handle(channel)),
        call::debug_write(Handle(0), ptr, msg.len()),
        call::channel_write(Handle(1), ptr, msg.len()),
    ];
    for (i, result) in attempts.iter().enumerate() {
        if *result != Err(Error::BadHandle) {
            return 0x200 + i as u64;
        }
    }
    attempts.len() as u64
}

/// Run until the kernel says stop, proving as it goes that its own memory is its own.
///
/// The kernel gives every worker the same private address and a signature of its own. The
/// worker writes the signature there once, and from then on every pass reads it back and
/// publishes what it saw, so a kernel that let two processes share one address space is
/// caught by the process that finds the other's signature rather than by the kernel
/// checking its own tables. `shared` is a page of the worker's own that the kernel can
/// read while the worker runs; it is how progress is observed without stopping anything.
fn worker(shared: usize, private: usize, signature: u64) -> u64 {
    let mine = private as *mut u64;
    let shared = shared as *mut u64;
    // SAFETY: both addresses are mapped read-write for this process — the kernel reserved
    // them before it entered the program — and nothing else in the process touches them.
    unsafe {
        mine.write_volatile(signature);
        let mut passes: u64 = 0;
        loop {
            let seen = mine.read_volatile();
            shared.add(W_SEEN).write_volatile(seen);
            if seen != signature {
                return WORKER_STOLEN;
            }
            passes = passes.wrapping_add(1);
            shared.add(W_PASSES).write_volatile(passes);
            if shared.add(W_STOP).read_volatile() != 0 {
                return SUCCESS;
            }
            // Trap now and then: the kernel records which CPU serves the call, which is how
            // a migration becomes visible, and a thread that never left user mode would
            // give the scheduler nothing to preempt on a machine with one CPU.
            if passes % YIELD_EVERY == 0 {
                let _ = call::thread_yield();
            }
        }
    }
}

/// Write to `target`, which is kernel memory. The kernel must end the process here.
fn fault(target: usize) -> u64 {
    // SAFETY: not safe, and not meant to be: this is the access the kernel must refuse.
    unsafe { (target as *mut u8).write_volatile(0x5a) };
    0x300
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(0xdead)
}
