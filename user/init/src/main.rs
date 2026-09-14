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
//! * [`MODE_SPAWN`] builds a process out of an image and talks to it; see [`spawn`].
//! * [`MODE_WAITS`] waits on the kernel's objects — timeouts, timers, an event, a channel — with a
//!   second thread of its own, moves a handle with fewer rights, and reads a file through the
//!   kernel's file service; see [`waits`].
//! * [`MODE_PAIR`] and [`MODE_PAIR_PEER`] are two threads of one process passing a counter back and
//!   forth, each blocking for the other; the stress run pins them to two CPUs. See [`pair`].
//! * [`MODE_SPIN`] and [`MODE_SPINNER`] are two threads of one process: the second spins in user
//!   mode for ever, and the first ends the process under it. See [`spin`].
//! * [`MODE_FILES`] reads a file through the kernel's file server, as a process that is not the
//!   first the server has served; see [`files`].
//! * [`MODE_WRITE`] writes the test disk through the file server on one connection, and is refused
//!   on another the kernel made read-only; see [`write_files`].
//! * [`MODE_POLL`] waits on several objects at once — a channel, an event and a completion queue —
//!   and asks the kernel, over that channel, to make one of them ready after a delay it chooses;
//!   see [`poll_wait`].
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
/// Create a process and talk to it; see [`spawn`].
const MODE_SPAWN: usize = 4;
/// Wait on the kernel's objects, with a second thread and a file service; see [`waits`].
const MODE_WAITS: usize = 5;
/// Pass a counter to a second thread and back, blocking each time; see [`pair`].
const MODE_PAIR: usize = 6;
/// The second thread of [`MODE_PAIR`]; see [`peer`].
const MODE_PAIR_PEER: usize = 7;
/// End the process under a thread spinning in user mode; see [`spin`].
const MODE_SPIN: usize = 8;
/// Spin in user mode for ever; see [`spinner`].
const MODE_SPINNER: usize = 9;
/// Read a file through the kernel's file server; see [`files`].
const MODE_FILES: usize = 10;
/// Write files through the kernel's file server; see [`write_files`].
const MODE_WRITE: usize = 11;
/// Wait on several objects at once; see the module comment.
const MODE_POLL: usize = 12;

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
        MODE_SPAWN => spawn(handle(a), handle(b)),
        MODE_WAITS => waits(handle(a), handle(b), handle(c)),
        MODE_PAIR => pair(handle(a)),
        MODE_PAIR_PEER => peer(handle(a)),
        MODE_SPIN => spin(handle(a)),
        MODE_SPINNER => spinner(handle(a)),
        MODE_FILES => files(handle(a), handle(b)),
        MODE_WRITE => write_files(handle(a), handle(b), handle(c)),
        MODE_POLL => poll_wait(handle(a), handle(b), handle(c)),
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

/// Build a process out of an image, give it an endpoint, and talk to it.
///
/// The kernel hands this mode two handles and nothing else: `image`, the bytes of another
/// program, and `console`. Everything else — the child process, its memory, its thread, the
/// queue its exit arrives on — this program creates. Returns [`SPAWN_SUCCESS`], or
/// `0x400 + step` for the first step that did not behave.
fn spawn(image: Handle, console: Handle) -> u64 {
    let _ = rt::print(console, b"init: creating a process\n");
    let Ok((mine, theirs)) = rt::channel() else {
        return 0x400;
    };
    // Types and rights are checked, not assumed, and a refusal is an answer rather than a
    // fault. A console is not an image and an image is not a process, so each is refused
    // as the wrong kind of object: the table checks an object's kind before its rights.
    if call::process_create(console) != Err(Error::WrongType) {
        return 0x410;
    }
    if call::thread_create(image, 0, 0) != Err(Error::WrongType) {
        return 0x411;
    }
    let Ok(child) = rt::Process::create(image) else {
        return 0x401;
    };
    // The image is a memory region, the right kind to map, but this program holds it with
    // READ only. Mapping needs MAP, so this is refused for lack of a right — the one
    // refusal here that is about authority rather than type.
    if call::vm_map_in(child.handle, image) != Err(Error::AccessDenied) {
        return 0x412;
    }
    // The child's own value for the endpoint. A handle value means nothing outside the
    // table it belongs to, so this is what the child must be told to use.
    let Ok(endpoint) = child.give(theirs) else {
        return 0x402;
    };
    let Ok(queue) = rt::completion_queue() else {
        return 0x403;
    };
    if child.wait_on(queue, CHILD_KEY).is_err() {
        return 0x404;
    }
    if child.start(u64::from(endpoint.0)).is_err() {
        return 0x405;
    }
    // The child speaks first, and waits for the answer before it exits. A parent waiting
    // for a child's message also watches for the child's death: a child that ends without
    // speaking would otherwise leave this waiting forever on a channel whose other end it
    // never closed. Its exit arrives on the queue, and is reported with its own code
    // folded in, so a failure names the step in the child that caused it.
    let mut buf = [0u8; 16];
    loop {
        // `rt::starts_with` rather than `&buf[..n]`: slicing by a range instantiates
        // `core`'s panicking index path, which a program linked in the user half cannot
        // reach. See the note in `lib/rt`.
        match rt::try_recv(mine, &mut buf) {
            Ok(n) if rt::starts_with(&buf, n, CHILD_HELLO) => break,
            Ok(_) => return 0x406,
            Err(Error::ShouldWait) => {}
            Err(_) => return 0x40a,
        }
        match rt::try_completion(queue) {
            Ok(c) if c.key == CHILD_KEY => return CHILD_DIED_SILENT | (c.value & 0xffff),
            Ok(_) | Err(Error::ShouldWait) => {}
            Err(_) => return 0x40b,
        }
        rt::yield_now();
    }
    if rt::send(mine, CHILD_REPLY).is_err() {
        return 0x407;
    }
    let Ok(code) = child.join(WAKE_NS) else {
        return 0x408;
    };
    if code != CHILD_SUCCESS {
        return 0x409;
    }
    // The exit asked for on the queue arrives too, with the same code.
    match rt::completion_wait_timeout(queue, WAKE_NS) {
        Ok(c) if c.key == CHILD_KEY && c.value == code => {}
        _ => return 0x40c,
    }
    let _ = rt::print(console, b"init: the process it created exited as expected\n");
    SPAWN_SUCCESS
}

/// What the child says, what it is told, and the code it exits with. One contract with
/// `user/child/src/main.rs`.
const CHILD_HELLO: &[u8; 5] = b"hello";
const CHILD_REPLY: &[u8; 5] = b"there";
const CHILD_SUCCESS: u64 = 0x3c;
/// The key `init` files the child's exit under, so a completion queue that answered
/// something else is not mistaken for the child.
const CHILD_KEY: u64 = 0x9001;
/// [`MODE_SPAWN`]'s exit code when the child ended before it said hello, with the low
/// sixteen bits of the child's own exit code in the low bits — so a failure in the child
/// is reported as *which* failure, not as a parent that waited in vain.
const CHILD_DIED_SILENT: u64 = 0x4_0000;
/// [`MODE_SPAWN`]'s exit code when every step behaved.
const SPAWN_SUCCESS: u64 = 0x5a;

// ---- waiting ------------------------------------------------------------------------------

/// [`MODE_WAITS`]' exit code when every step behaved. Mirrors `kernel/main/src/waits.rs`.
const WAITS_SUCCESS: u64 = 0x6b;
/// [`MODE_PAIR`]'s.
const PAIR_SUCCESS: u64 = 0x6c;
/// [`MODE_SPIN`]'s. Mirrors `kernel/main/src/sibling.rs`.
const SPIN_SUCCESS: u64 = 0x6d;
/// How long [`spin`] lets the spinner spin before ending the process under it.
const SPIN_SETTLE_NS: u64 = 20_000_000;
/// [`MODE_FILES`]'. Mirrors `kernel/main/src/fileserver.rs`.
const FILES_SUCCESS: u64 = 0x6e;

/// Read `/HELLO.TXT` through the file server `service` names, as [`MODE_WAITS`] does. Returns
/// [`FILES_SUCCESS`], or the code of the step that did not behave.
fn files(console: Handle, service: Handle) -> u64 {
    match read_through_the_service(console, service) {
        Ok(()) => FILES_SUCCESS,
        Err(code) => code,
    }
}

/// The timeout the timing steps use.
const TIMEOUT_NS: u64 = 30_000_000;
/// How late a timeout may end. Generous, because an emulated CPU can be descheduled by its
/// host, and still far below what a wait that only ended at some unrelated later event
/// would take.
const LATE_NS: u64 = 500_000_000;
/// The timeout on a wait that should end by a wake: long enough that running out means the
/// wake was lost.
const WAKE_NS: u64 = 2_000_000_000;
/// How long a wait that a wake should end may take before the wake counts as lost. A wait
/// whose wake never came still ends at its timeout and finds what it waited for there, so
/// without this bound a lost wake-up would look like a slow success.
const LOST_NS: u64 = 1_000_000_000;

/// Receive on `channel`, as a wait a wake must end: `TimedOut` if the message took
/// [`LOST_NS`] or longer to be received.
fn recv_promptly(channel: Handle, buf: &mut [u8]) -> Result<usize, Error> {
    let start = rt::now_ns();
    let got = rt::recv_timeout(channel, buf, WAKE_NS)?;
    if rt::now_ns().wrapping_sub(start) >= LOST_NS {
        return Err(Error::TimedOut);
    }
    Ok(got)
}

/// Wait for `event`'s signal, as a wait a wake must end; see [`recv_promptly`].
fn wait_promptly(event: &rt::Event) -> bool {
    let start = rt::now_ns();
    event.wait(WAKE_NS).is_ok() && rt::now_ns().wrapping_sub(start) < LOST_NS
}

const KEY_ONESHOT: u64 = 0x71;
const KEY_PERIODIC: u64 = 0x72;

/// What the test disk's `/HELLO.TXT` holds.
const HELLO: &[u8] = b"hello from the KinTane test disk\n";

/// Wait on the kernel's objects. Returns [`WAITS_SUCCESS`], or `0x500 + step` for the first
/// that did not behave.
///
/// `me` is a handle to this process, which is what starting a thread in it takes. `files` is
/// a channel to the kernel's file service, or zero when there is no volume to serve.
fn waits(console: Handle, me: Handle, files: Handle) -> u64 {
    let _ = rt::print(console, b"init: waiting on the kernel\n");
    let Ok(queue) = rt::completion_queue() else {
        return 0x500;
    };
    if !times_out_on_time(queue) {
        return 0x501;
    }
    if !process_wait_times_out(me, queue) {
        return 0x502;
    }
    let steps = [
        timers(queue),
        two_threads(me),
        rights_narrow(),
        if files.0 == 0 {
            Ok(())
        } else {
            read_through_the_service(console, files)
        },
    ];
    for step in steps {
        if let Err(code) = step {
            return code;
        }
    }
    WAITS_SUCCESS
}

/// A poll answers at once, and a wait that runs out does so on time: not early, and not
/// long after.
fn times_out_on_time(queue: Handle) -> bool {
    if rt::completion_wait_timeout(queue, rt::NO_WAIT) != Err(Error::ShouldWait) {
        return false;
    }
    let start = rt::now_ns();
    let result = rt::completion_wait_timeout(queue, TIMEOUT_NS);
    let took = rt::now_ns().wrapping_sub(start);
    result == Err(Error::TimedOut) && took >= TIMEOUT_NS && took < TIMEOUT_NS + LATE_NS
}

/// A wait for a process runs out on time, as every other wait does. The process waited for is
/// this one, which cannot end while its own thread waits. Arming a queue takes no timeout.
fn process_wait_times_out(me: Handle, queue: Handle) -> bool {
    let this = rt::Process { handle: me };
    if this.join(rt::NO_WAIT) != Err(Error::ShouldWait) {
        return false;
    }
    if call::process_wait(me, queue, 1, TIMEOUT_NS) != Err(Error::InvalidArgument) {
        return false;
    }
    let start = rt::now_ns();
    let result = this.join(TIMEOUT_NS);
    let took = rt::now_ns().wrapping_sub(start);
    result == Err(Error::TimedOut) && took >= TIMEOUT_NS && took < TIMEOUT_NS + LATE_NS
}

/// A one-shot timer delivers once, on time; a periodic one keeps delivering until it is
/// cancelled, and then stops.
fn timers(queue: Handle) -> Result<(), u64> {
    let once = rt::Timer::create(queue, KEY_ONESHOT).map_err(|_| 0x510u64)?;
    let start = rt::now_ns();
    once.set(TIMEOUT_NS, 0).map_err(|_| 0x511u64)?;
    match rt::completion_wait_timeout(queue, WAKE_NS) {
        Ok(c) if c.key == KEY_ONESHOT && c.value == 1 => {}
        _ => return Err(0x512),
    }
    let took = rt::now_ns().wrapping_sub(start);
    if took < TIMEOUT_NS || took >= TIMEOUT_NS + LATE_NS {
        return Err(0x513);
    }
    if rt::completion_wait_timeout(queue, TIMEOUT_NS) != Err(Error::TimedOut) {
        return Err(0x514);
    }
    let every = rt::Timer::create(queue, KEY_PERIODIC).map_err(|_| 0x515u64)?;
    every.set(10_000_000, 10_000_000).map_err(|_| 0x516u64)?;
    let mut expirations = 0;
    while expirations < 3 {
        match rt::completion_wait_timeout(queue, WAKE_NS) {
            Ok(c) if c.key == KEY_PERIODIC && c.value >= 1 => expirations += c.value,
            _ => return Err(0x517),
        }
    }
    every.cancel().map_err(|_| 0x518u64)?;
    if rt::completion_wait_timeout(queue, TIMEOUT_NS) != Err(Error::TimedOut) {
        return Err(0x519);
    }
    if call::handle_close(every.handle).is_err() || call::handle_close(once.handle).is_err() {
        return Err(0x51a);
    }
    Ok(())
}

/// What two threads of this process share: a page one maps and both address.
#[repr(C)]
struct Meeting {
    event: u32,
    channel: u32,
    written: u64,
}

const MEETING_MAGIC: u64 = 0x7e57_0000_0000_5eed;

/// Start a second thread in this process. It writes to a page this thread mapped and
/// signals an event, which wakes this thread; then it blocks receiving on a channel until
/// this thread sends, and answers.
fn two_threads(me: Handle) -> Result<(), u64> {
    let page = call::vm_map(PAGE).map_err(|_| 0x520u64)?;
    let event = rt::Event::create().map_err(|_| 0x521u64)?;
    let (mine, theirs) = rt::channel().map_err(|_| 0x522u64)?;
    if event.wait(rt::NO_WAIT) != Err(Error::ShouldWait) {
        return Err(0x523);
    }
    let meeting = page as *mut Meeting;
    // SAFETY: the page `vm_map` just returned, readable and writable, and no other thread
    // exists yet to touch it.
    unsafe {
        meeting.write_volatile(Meeting {
            event: event.handle.0,
            channel: theirs.0,
            written: 0,
        })
    };
    let this = rt::Process { handle: me };
    let entry = second_thread as extern "C" fn(usize, usize, usize, usize) -> !;
    if this.start_at(entry as usize as u64, page).is_err() {
        return Err(0x524);
    }
    if !wait_promptly(&event) {
        return Err(0x525);
    }
    // The second thread's write, seen here at the address it wrote to: one address space.
    // SAFETY: as above; the other thread wrote this word before it signalled, and does not
    // write it again.
    if unsafe { core::ptr::addr_of!((*meeting).written).read_volatile() } != MEETING_MAGIC {
        return Err(0x526);
    }
    // Give it time to block in its receive, so what follows is a wake rather than a message
    // already waiting when it looks. Nothing signals the event meanwhile.
    if event.wait(TIMEOUT_NS) != Err(Error::TimedOut) {
        return Err(0x527);
    }
    if rt::send(mine, b"wake").is_err() {
        return Err(0x528);
    }
    let mut buf = [0u8; 8];
    match recv_promptly(mine, &mut buf) {
        Ok(n) if rt::starts_with(&buf, n, b"woke") => {}
        _ => return Err(0x529),
    }
    // It signals once more as it ends its thread.
    if !wait_promptly(&event) {
        return Err(0x52a);
    }
    Ok(())
}

/// The second thread [`two_threads`] starts, handed the page they share.
extern "C" fn second_thread(page: usize, _: usize, _: usize, _: usize) -> ! {
    let meeting = page as *mut Meeting;
    // SAFETY: the page the first thread mapped and filled in before starting this one.
    let (event, channel) = unsafe {
        (
            core::ptr::addr_of!((*meeting).event).read_volatile(),
            core::ptr::addr_of!((*meeting).channel).read_volatile(),
        )
    };
    // SAFETY: as above; the first thread reads this word only after the signal below.
    unsafe { core::ptr::addr_of_mut!((*meeting).written).write_volatile(MEETING_MAGIC) };
    let event = rt::Event {
        handle: Handle(event),
    };
    let _ = event.signal();
    let mut buf = [0u8; 8];
    let code = match recv_promptly(Handle(channel), &mut buf) {
        Ok(n) if rt::starts_with(&buf, n, b"wake") => match rt::send(Handle(channel), b"woke") {
            Ok(()) => 0,
            Err(_) => 2,
        },
        _ => 1,
    };
    let _ = event.signal();
    rt::exit_thread(code)
}

/// Move a handle across a channel with fewer rights, and check the receiver holds exactly
/// those, the sender holds nothing, and a send that cannot move everything moves nothing.
fn rights_narrow() -> Result<(), u64> {
    let (a, b) = rt::channel().map_err(|_| 0x530u64)?;
    let event = rt::Event::create().map_err(|_| 0x531u64)?;
    let mut buf = [0u8; 8];
    let mut got = [Handle(0); 2];
    // A handle this program does not hold cannot be sent, and the refusal takes the other
    // handle in the same message with it: nothing arrives, and the event is still here.
    let forged = Handle(0x7fff_0001);
    let refused =
        rt::send_handles(a, b"no", &[(event.handle, abi::rights::ALL), (forged, abi::rights::ALL)]);
    if refused != Err(Error::BadHandle) {
        return Err(0x532);
    }
    if rt::recv_with_handles(b, &mut buf, &mut got, rt::NO_WAIT) != Err(Error::ShouldWait) {
        return Err(0x533);
    }
    if event.signal().is_err() {
        return Err(0x534);
    }
    // Moved with WAIT alone.
    if rt::send_handles(a, b"cap", &[(event.handle, abi::rights::WAIT)]).is_err() {
        return Err(0x535);
    }
    // Moved, not copied: this program's handle is gone.
    if event.signal() != Err(Error::BadHandle) {
        return Err(0x536);
    }
    match rt::recv_with_handles(b, &mut buf, &mut got, WAKE_NS) {
        Ok(r) if r.handles == 1 && rt::starts_with(&buf, r.bytes, b"cap") => {}
        _ => return Err(0x537),
    }
    let [first, _] = got;
    let narrowed = rt::Event { handle: first };
    // It carries WAIT, and the signal sent before the move is still there to consume...
    if narrowed.wait(rt::NO_WAIT).is_err() {
        return Err(0x538);
    }
    // ...and it does not carry SIGNAL.
    if narrowed.signal() != Err(Error::AccessDenied) {
        return Err(0x539);
    }
    for h in [a, b, first] {
        if call::handle_close(h).is_err() {
            return Err(0x53a);
        }
    }
    Ok(())
}

/// Read `/HELLO.TXT` through the file service, sixteen bytes at a time, and print it.
fn read_through_the_service(console: Handle, files: Handle) -> Result<(), u64> {
    let mut buf = [0u8; vfsproto::MESSAGE];
    let open = vfsproto::open(b"/HELLO.TXT").ok_or(0x540u64)?;
    let file = match ask(files, open.as_bytes(), &mut buf) {
        Some(r) if r.status == vfsproto::Status::Ok => r.a,
        _ => return Err(0x541),
    };
    let mut contents = [0u8; 64];
    let mut len = 0;
    loop {
        let reply = match ask(files, vfsproto::read(file, 16).as_bytes(), &mut buf) {
            Some(r) if r.status == vfsproto::Status::Ok => r,
            _ => return Err(0x542),
        };
        if reply.data.is_empty() {
            break;
        }
        for byte in reply.data {
            let Some(slot) = contents.get_mut(len) else {
                return Err(0x543);
            };
            *slot = *byte;
            len += 1;
        }
    }
    match ask(files, vfsproto::close(file).as_bytes(), &mut buf) {
        Some(r) if r.status == vfsproto::Status::Ok => {}
        _ => return Err(0x544),
    }
    if !rt::starts_with(&contents, len, HELLO) {
        return Err(0x545);
    }
    // A file that is not there is refused, not invented.
    let missing = vfsproto::open(b"/NOPE.TXT").ok_or(0x546u64)?;
    match ask(files, missing.as_bytes(), &mut buf) {
        Some(r) if r.status == vfsproto::Status::NotFound => {}
        _ => return Err(0x547),
    }
    let _ = rt::print(console, b"init: through the file service: ");
    let _ = rt::print(console, contents.get(..len).unwrap_or(&[]));
    Ok(())
}

/// [`MODE_WRITE`]'s exit code when every step behaved. Mirrors `kernel/main/src/fileserver.rs`.
const WRITE_SUCCESS: u64 = 0x6f;
/// What the write mode leaves on the disk; mirrors `NATIVE_OUT_PATH`, `NATIVE_OUT_LEN`,
/// `NATIVE_OUT_SEED` and `out_byte` in `kernel/block/src/testdisk.rs`.
const NATIVE_OUT: &[u8] = b"/KINTANE/NATIVE.OUT";
const NATIVE_OUT_LEN: usize = 1000;
const NATIVE_OUT_SEED: u8 = 0x4e;
/// The seed of the bytes the write mode writes and removes again.
const TEMP_SEED: u8 = 0x21;
const TEMP_LEN: usize = 1200;

fn out_byte(seed: u8, i: usize) -> u8 {
    let x = (i as u32).wrapping_mul(2_654_435_761) ^ u32::from(seed).wrapping_mul(0x9E37_79B9);
    (x >> 23) as u8 ^ seed
}

/// Write the test disk through the file server: `rw` is a connection that may write, `ro` one
/// that may not. Returns [`WRITE_SUCCESS`], or `0x900 + step` for the first step that did not
/// behave.
fn write_files(console: Handle, rw: Handle, ro: Handle) -> u64 {
    match write_through_the_service(rw, ro) {
        Ok(()) => {
            // The kernel's check goes on with the same line.
            let _ = rt::print(console, b"init: wrote the disk through the file service; ");
            WRITE_SUCCESS
        }
        Err(code) => code,
    }
}

/// Send `request` and require `want`: the reply's `a` and `b`, or `step`.
fn expect_status(
    service: Handle,
    request: Option<vfsproto::Message>,
    want: vfsproto::Status,
    step: u64,
    buf: &mut [u8; vfsproto::MESSAGE],
) -> Result<(u8, u8), u64> {
    let request = request.ok_or(step)?;
    match ask(service, request.as_bytes(), buf) {
        Some(r) if r.status == want => Ok((r.a, r.b)),
        _ => Err(step),
    }
}

/// Write `len` bytes of `seed`'s to `file`, a message at a time.
fn write_seeded(
    service: Handle,
    file: u8,
    seed: u8,
    len: usize,
    step: u64,
    buf: &mut [u8; vfsproto::MESSAGE],
) -> Result<(), u64> {
    let mut chunk = [0u8; vfsproto::PAYLOAD];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(vfsproto::PAYLOAD);
        for (i, b) in chunk.iter_mut().take(n).enumerate() {
            *b = out_byte(seed, done + i);
        }
        let data = chunk.get(..n).ok_or(step)?;
        let (_, wrote) = expect_status(service, vfsproto::write(file, data), OK, step, buf)?;
        if usize::from(wrote) != n {
            return Err(step);
        }
        done += n;
    }
    Ok(())
}

/// Read `file` from where it is to its end, requiring `seed`'s bytes. How many there were.
fn read_seeded(
    service: Handle,
    file: u8,
    seed: u8,
    step: u64,
    buf: &mut [u8; vfsproto::MESSAGE],
) -> Result<usize, u64> {
    let mut offset = 0usize;
    loop {
        let reply = match ask(service, vfsproto::read(file, 60).as_bytes(), buf) {
            Some(r) if r.status == OK => r,
            _ => return Err(step),
        };
        if reply.data.is_empty() {
            return Ok(offset);
        }
        for (i, &b) in reply.data.iter().enumerate() {
            if b != out_byte(seed, offset + i) {
                return Err(step);
            }
        }
        offset += reply.data.len();
    }
}

const OK: vfsproto::Status = vfsproto::Status::Ok;

fn write_through_the_service(rw: Handle, ro: Handle) -> Result<(), u64> {
    use vfsproto::{Status, flags};
    const TEMP: &[u8] = b"/KINTANE/NWTMP.TXT";
    const RENAMED: &[u8] = b"/KINTANE/NWREN.TXT";
    const DIR: &[u8] = b"/KINTANE/NWDIR";
    let mut buf = [0u8; vfsproto::MESSAGE];
    let b = &mut buf;

    // 1–2: create exclusively and write, a message at a time.
    let create = flags::WRITE | flags::CREATE | flags::EXCLUSIVE;
    let (file, _) = expect_status(rw, vfsproto::open_with(TEMP, create), OK, 0x901, b)?;
    write_seeded(rw, file, TEMP_SEED, TEMP_LEN, 0x902, b)?;
    // 3–4: back to the start, and every byte reads back.
    expect_status(rw, Some(vfsproto::seek(file, 0)), OK, 0x903, b)?;
    if read_seeded(rw, file, TEMP_SEED, 0x904, b)? != TEMP_LEN {
        return Err(0x904);
    }
    // 5: truncated, only what is left reads back.
    expect_status(rw, Some(vfsproto::truncate(file, 90)), OK, 0x905, b)?;
    expect_status(rw, Some(vfsproto::seek(file, 0)), OK, 0x905, b)?;
    if read_seeded(rw, file, TEMP_SEED, 0x905, b)? != 90 {
        return Err(0x905);
    }
    // 6: a second exclusive create is refused.
    expect_status(rw, vfsproto::open_with(TEMP, create), Status::Exists, 0x906, b)?;
    expect_status(rw, Some(vfsproto::close(file)), OK, 0x906, b)?;
    // 7: a directory, made once.
    expect_status(rw, vfsproto::mkdir(DIR), OK, 0x907, b)?;
    expect_status(rw, vfsproto::mkdir(DIR), Status::Exists, 0x907, b)?;
    // 8: renamed, the old name is gone.
    expect_status(rw, vfsproto::rename(TEMP, RENAMED), OK, 0x908, b)?;
    expect_status(rw, vfsproto::open(TEMP), Status::NotFound, 0x908, b)?;
    // 9: both removed.
    expect_status(rw, vfsproto::unlink(DIR), OK, 0x909, b)?;
    expect_status(rw, vfsproto::unlink(RENAMED), OK, 0x909, b)?;
    expect_status(rw, vfsproto::open(RENAMED), Status::NotFound, 0x909, b)?;
    // 10: the read-only connection writes nothing, whatever it asks.
    expect_status(ro, vfsproto::mkdir(b"/KINTANE/NOPE"), Status::ReadOnly, 0x90a, b)?;
    let make = flags::WRITE | flags::CREATE;
    expect_status(ro, vfsproto::open_with(NATIVE_OUT, make), Status::ReadOnly, 0x90a, b)?;
    // 11: a file opened to read is not written, even on the writable connection.
    let (hello, _) = expect_status(rw, vfsproto::open(b"/HELLO.TXT"), OK, 0x90b, b)?;
    expect_status(rw, vfsproto::write(hello, b"x"), Status::ReadOnly, 0x90b, b)?;
    expect_status(rw, Some(vfsproto::close(hello)), OK, 0x90b, b)?;
    // 12: the file kbuild reads after the guest exits, synced.
    let replace = flags::WRITE | flags::CREATE | flags::TRUNCATE;
    let (out, _) = expect_status(rw, vfsproto::open_with(NATIVE_OUT, replace), OK, 0x90c, b)?;
    write_seeded(rw, out, NATIVE_OUT_SEED, NATIVE_OUT_LEN, 0x90c, b)?;
    expect_status(rw, Some(vfsproto::sync()), OK, 0x90c, b)?;
    expect_status(rw, Some(vfsproto::close(out)), OK, 0x90c, b)?;
    Ok(())
}

/// Send `request` to the file service and wait for its reply, read into `buf`.
fn ask<'a>(service: Handle, request: &[u8], buf: &'a mut [u8]) -> Option<vfsproto::Reply<'a>> {
    rt::send(service, request).ok()?;
    let n = rt::recv_timeout(service, buf, WAKE_NS).ok()?;
    vfsproto::parse_reply(buf.get(..n)?)
}

/// Wait for [`spinner`] to start, let it spin, and end the process under it. Returns
/// [`SPIN_SUCCESS`], or `0x80x` for a step that did not behave. Whether the spinner ended too
/// is for the kernel to see: nothing here could tell.
fn spin(started: Handle) -> u64 {
    let started = rt::Event { handle: started };
    if !wait_promptly(&started) {
        return 0x801;
    }
    // Long enough for the spinner to be deep in its loop, preempted here or running elsewhere.
    if started.wait(SPIN_SETTLE_NS) != Err(Error::TimedOut) {
        return 0x802;
    }
    SPIN_SUCCESS
}

/// Say this thread has started, then spin in user mode for ever without entering the kernel
/// again. Only the kernel can end it.
fn spinner(started: Handle) -> ! {
    let _ = call::event_signal(started);
    let mut spins = 0u64;
    loop {
        spins = core::hint::black_box(spins.wrapping_add(1));
    }
}

/// Pass a counter to [`peer`] and back until a tenth of a second has gone, blocking in the
/// kernel for every answer. The kernel pins the two threads to two CPUs, so each answer is a
/// wake from another CPU. A receive that times out is a wake-up the kernel lost.
fn pair(channel: Handle) -> u64 {
    let start = rt::now_ns();
    let mut rounds = 0u64;
    loop {
        if rt::send(channel, &rounds.to_le_bytes()).is_err() {
            return 0x602;
        }
        let mut buf = [0u8; 8];
        match recv_promptly(channel, &mut buf) {
            Ok(8) => {}
            Err(Error::TimedOut) => return 0x603,
            _ => return 0x604,
        }
        if u64::from_le_bytes(buf) != rounds + 1 {
            return 0x605;
        }
        rounds += 1;
        if rounds >= 8 && rt::now_ns().wrapping_sub(start) >= 100_000_000 {
            break;
        }
    }
    if rt::send(channel, &u64::MAX.to_le_bytes()).is_err() {
        return 0x606;
    }
    let mut buf = [0u8; 8];
    match recv_promptly(channel, &mut buf) {
        Ok(8) if u64::from_le_bytes(buf) == u64::MAX => PAIR_SUCCESS,
        _ => 0x607,
    }
}

/// [`pair`]'s other half: answer each counter with the next, and every fourth time make the
/// other thread wait first, with a timed wait on an event nothing signals.
fn peer(channel: Handle) -> u64 {
    let Ok(pause) = rt::Event::create() else {
        return 0x611;
    };
    loop {
        let mut buf = [0u8; 8];
        match recv_promptly(channel, &mut buf) {
            Ok(8) => {}
            Err(Error::TimedOut) => return 0x613,
            _ => return 0x614,
        }
        let n = u64::from_le_bytes(buf);
        if n == u64::MAX {
            let _ = rt::send(channel, &buf);
            rt::exit_thread(0)
        }
        if n % 4 == 0 && pause.wait(1_000_000) != Err(Error::TimedOut) {
            return 0x615;
        }
        if rt::send(channel, &(n + 1).to_le_bytes()).is_err() {
            return 0x616;
        }
    }
}

/// Write to `target`, which is kernel memory. The kernel must end the process here.
fn fault(target: usize) -> u64 {
    // SAFETY: not safe, and not meant to be: this is the access the kernel must refuse.
    unsafe { (target as *mut u8).write_volatile(0x5a) };
    0x300
}

// ---- waiting on several objects at once ---------------------------------------------------

/// What [`poll_wait`] exits with when every step behaved.
const POLL_SUCCESS: u64 = 0x70;

/// What the kernel's check is asked to make ready, and how long from now. One byte and a
/// little-endian `u32` of microseconds; the kernel mirrors these in `kernel/main/src/readiness.rs`.
const ASK_EVENT: u8 = b'E';
const ASK_CHANNEL: u8 = b'C';

/// Rounds of the race: each asks for the event after a delay that grows, so some land while the
/// wait is still looking at its set and some after it has blocked.
const RACE_ROUNDS: u32 = 16;
/// How much later each round asks for its wake, in microseconds.
const RACE_STEP_US: u32 = 120;

/// The longest any wait here may take, and the timeout the one that must run out is given.
const POLL_PATIENCE_NS: u64 = 5_000_000_000;
const POLL_TIMEOUT_NS: u64 = 30_000_000;

/// Ask the kernel's check for `what` in `delay_us`, over the channel it holds the other end of.
fn poll_ask(channel: Handle, what: u8, delay_us: u32) -> bool {
    let mut message = [0u8; 5];
    message[0] = what;
    let bytes = delay_us.to_le_bytes();
    let mut i = 0;
    while i < 4 {
        if let (Some(to), Some(from)) = (message.get_mut(1 + i), bytes.get(i)) {
            *to = *from;
        }
        i += 1;
    }
    rt::send(channel, &message).is_ok()
}

/// Wait on a channel, an event and a completion queue at once; see the module comment. The
/// kernel makes exactly one of them ready at a time, at a moment this program asks for, so
/// what comes back says which — and a wake that lands between the wait's two looks at its set
/// must not be lost.
fn poll_wait(console: Handle, channel: Handle, event: Handle) -> u64 {
    let Ok(queue) = rt::completion_queue() else {
        return 0x700;
    };
    let Ok(timer) = rt::Timer::create(queue, 0x7017) else {
        return 0x701;
    };
    let set = [
        rt::Watch {
            handle: channel,
            interest: rt::ready::READ,
        },
        rt::Watch {
            handle: event,
            interest: rt::ready::READ,
        },
        rt::Watch {
            handle: queue,
            interest: rt::ready::READ,
        },
    ];
    let mut ready = [0u32; 3];

    // 0x710: nothing is ready, so the wait runs out — and not before its timeout.
    let start = rt::now_ns();
    let waited = rt::wait_any(&set, &mut ready, POLL_TIMEOUT_NS);
    let took = rt::now_ns().wrapping_sub(start);
    if waited != Err(Error::TimedOut) || took < POLL_TIMEOUT_NS {
        return 0x710;
    }
    // 0x711: a zero timeout answers at once with nothing ready.
    if rt::wait_any(&set, &mut ready, rt::NO_WAIT) != Err(Error::ShouldWait) {
        return 0x711;
    }

    // 0x712-0x714: the event, asked for and then waited on, is the member that comes back.
    if !poll_ask(channel, ASK_EVENT, 0) {
        return 0x712;
    }
    match rt::wait_any(&set, &mut ready, POLL_PATIENCE_NS) {
        Ok(1) => {}
        _ => return 0x713,
    }
    if ready[1] & rt::ready::READ == 0 || ready[0] != 0 || ready[2] != 0 {
        return 0x714;
    }
    // Consuming it makes it unready again, which is what the next rounds rely on.
    let signalled = rt::Event { handle: event };
    if signalled.wait(rt::NO_WAIT).is_err() {
        return 0x715;
    }

    // 0x716-0x718: the channel, the same way. Its message is read, so it is unready after.
    if !poll_ask(channel, ASK_CHANNEL, 0) {
        return 0x716;
    }
    match rt::wait_any(&set, &mut ready, POLL_PATIENCE_NS) {
        Ok(1) => {}
        _ => return 0x717,
    }
    if ready[0] & rt::ready::READ == 0 {
        return 0x718;
    }
    let mut buf = [0u8; 8];
    if rt::try_recv(channel, &mut buf).is_err() {
        return 0x719;
    }

    // 0x71a-0x71b: a timer's completion, which nothing wakes the queue for: the wait must look
    // again when the timer falls due, or it would sleep through it.
    if timer.set(POLL_TIMEOUT_NS, 0).is_err() {
        return 0x71a;
    }
    match rt::wait_any(&set, &mut ready, POLL_PATIENCE_NS) {
        Ok(1) if ready[2] & rt::ready::READ != 0 => {}
        _ => return 0x71b,
    }
    if rt::try_completion(queue).is_err() {
        return 0x71c;
    }

    // 0x720: the race. Each round asks for the event a little later than the last, so the wake
    // lands at every stage of the wait: before it looks, between its two looks, and after it has
    // blocked. A lost wake is a round that never ends.
    let mut round = 0;
    while round < RACE_ROUNDS {
        if !poll_ask(channel, ASK_EVENT, round * RACE_STEP_US) {
            return 0x720;
        }
        match rt::wait_any(&set, &mut ready, POLL_PATIENCE_NS) {
            Ok(n) if n >= 1 && ready[1] & rt::ready::READ != 0 => {}
            _ => return 0x721 + round as u64,
        }
        if signalled.wait(rt::NO_WAIT).is_err() {
            return 0x740 + round as u64;
        }
        round += 1;
    }

    let _ = rt::print(console, b"init: waited on a channel, an event and a timer at once\n");
    POLL_SUCCESS
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(0xdead)
}
