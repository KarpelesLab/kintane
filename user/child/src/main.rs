//! The program `init` creates: proof that a process can be built by a program rather than
//! by the kernel.
//!
//! It is given exactly one thing — the value of a channel endpoint in its own table, in its
//! first argument register — and it has nothing else: no console, no image, no handle it
//! was not handed. What it does with that is the whole program: say hello, wait for the
//! reply, and exit with a code its parent checks.
//!
//! Every failure exits with a distinct code, because the parent reports the child's code
//! and the kernel's check reports the parent's. A wrong answer therefore names the step
//! that produced it rather than arriving as a single failed boot.

#![no_std]
#![no_main]

use rt::{Error, Handle, UserPtr, call};

/// What the child says, and what it expects back.
const HELLO: &[u8; 5] = b"hello";
const REPLY: &[u8; 5] = b"there";

/// Exit codes. `SUCCESS` is what the parent requires; the rest say where it stopped.
const SUCCESS: u64 = 0x3c;
const NO_ENDPOINT: u64 = 0x3c01;
const SEND_FAILED: u64 = 0x3c02;
const RECV_FAILED: u64 = 0x3c03;
const WRONG_REPLY: u64 = 0x3c04;
const FORGED: u64 = 0x3c05;

/// The kernel enters here with the arguments [`rt::Process::start`] asked for: the child's
/// own value for the endpoint its parent gave it.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(endpoint: usize, _: usize, _: usize, _: usize) -> ! {
    rt::exit(run(Handle(endpoint as u32)))
}

fn run(endpoint: Handle) -> u64 {
    if endpoint.0 == 0 {
        return NO_ENDPOINT;
    }
    if !forged_handles_are_refused(endpoint) {
        return FORGED;
    }
    if rt::send(endpoint, HELLO).is_err() {
        return SEND_FAILED;
    }
    let mut buf = [0u8; 16];
    let got = match rt::recv(endpoint, &mut buf) {
        Ok(n) => n,
        Err(_) => return RECV_FAILED,
    };
    // `rt::starts_with` rather than `&buf[..got]`: see the note on slice indexing in
    // `lib/rt`. A range slice here links against `core`'s panicking path, which is too far
    // away to reach from the user half.
    if !rt::starts_with(&buf, got, REPLY) {
        return WRONG_REPLY;
    }
    SUCCESS
}

/// This process holds exactly one handle. Every other value names nothing in its table —
/// whatever that value might mean in its parent's — and each use must be refused as a bad
/// handle, before the kernel so much as looks at what kind of object it would have been.
///
/// That is the ABI's claim that a process has no authority except through handles it
/// holds, tested by the process that holds the least.
fn forged_handles_are_refused(endpoint: Handle) -> bool {
    let mut out = [0u8; 16];
    // Small indexes, and values with a generation in the high bits, as a guess at another
    // table's handle would be.
    for guess in [1u32, 2, 3, 4, 0x0001_0001, 0x0002_0002] {
        if guess == endpoint.0 {
            continue;
        }
        let forged = Handle(guess);
        if call::process_create(forged) != Err(Error::BadHandle)
            || call::thread_create(forged, 0, 0) != Err(Error::BadHandle)
            || call::completion_poll(forged, UserPtr(out.as_mut_ptr() as u64))
                != Err(Error::BadHandle)
        {
            return false;
        }
    }
    true
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    rt::exit(0xdead)
}
