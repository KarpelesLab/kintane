//! TCP, alongside everything else.
//!
//! One thread makes TCP round trips with kbuild's TCP service, over and over, through the card
//! and stack the boot's net check brought up: connect, send a request, read the reply, and close
//! — the kernel first on odd rounds, kbuild first on even ones. kbuild drops the first data
//! segment of every connection once, so every round has a retransmission in it, which the
//! heartbeat counts. A round that fails is tried again, twice, and a third failure fails the run.
//!
//! At a checkpoint it holds no connection, so the network's audit finds every stack buffer in the
//! pool; this workload's own audit adds that no connection holds a ring and that the pool's books
//! agree with what connections hold.
//!
//! Present only when the net check heard kbuild announce its TCP port. On a machine without, the
//! workload is not spawned, and its slot reads as parked holding nothing.

use core::sync::atomic::{AtomicU64, Ordering};

use arch::Cpu;
use sync::{LockClass, SpinLock};

use super::{Parked, Workload, after_ms, checkpoint, fail, park_requested, progress};
use crate::preempt::{begin, sleep_until};

/// How long one step of a round waits, and how many tries a round gets.
const TIMEOUT_NS: u64 = 2_000_000_000;
const TRIES: u32 = 3;

/// The pause between polls while a round waits, and between rounds: paced as the datagram
/// workload is, for the same reason.
const POLL_MS: u64 = 5;
const ROUND_MS: u64 = 25;

static ROUNDS: AtomicU64 = AtomicU64::new(0);
static RETRANSMITS: AtomicU64 = AtomicU64::new(0);
static RETRIES: AtomicU64 = AtomicU64::new(0);

/// Why the latest round that had to be tried again failed, for the heartbeat: a retried round
/// is allowed, and one whose reason goes unrecorded cannot be told from a flaw.
static LAST_RETRY: SpinLock<Option<&'static str>, Cpu> =
    SpinLock::with_class(None, &LAST_RETRY_CLASS);
static LAST_RETRY_CLASS: LockClass = LockClass::new("stress.tcp.retry");

/// Why the latest failed try failed, if one has.
pub fn last_retry() -> Option<&'static str> {
    *LAST_RETRY.lock_irqsave()
}

/// Whether the machine has the card and kbuild's TCP port this workload uses.
pub fn present() -> bool {
    crate::net::nic().is_some() && crate::net::tcp_port().is_some()
}

/// Round trips completed, data segments retransmitted in them, and rounds tried again, for the
/// heartbeat.
pub fn counts() -> (u64, u64, u64) {
    (
        ROUNDS.load(Ordering::Relaxed),
        RETRANSMITS.load(Ordering::Relaxed),
        RETRIES.load(Ordering::Relaxed),
    )
}

/// Ready to run: no connection holds a buffer before anything starts.
pub fn setup() -> Result<(), &'static str> {
    if !present() {
        return Ok(());
    }
    crate::net::tcp_audit().map_err(|_| "a TCP connection holds buffers before the run")
}

/// No connection holds a buffer. Called with the thread parked.
pub fn audit() -> Result<(), &'static str> {
    if !present() {
        return Ok(());
    }
    crate::net::tcp_audit()
}

fn now() -> u64 {
    crate::timekeeping::now().as_nanos()
}

fn nap() {
    sleep_until(after_ms(POLL_MS));
}

pub extern "C" fn worker(_: usize) -> ! {
    begin();
    let w = Workload::Tcp;
    let (Some(card), Some(port)) = (crate::net::nic(), crate::net::tcp_port()) else {
        fail(w, "spawned without a network");
        loop {
            sleep_until(after_ms(1000));
        }
    };
    let mut clock: fn() -> u64 = now;
    let mut round = 0u32;
    loop {
        if park_requested() {
            // Between rounds no connection is held: the books must show that.
            checkpoint(w, Parked::Empty);
        }
        round = round.wrapping_add(1);
        let guest_closes = round % 2 == 1;
        let mut done = false;
        for i in 0..TRIES {
            let result =
                crate::net::tcp_round(card, port, guest_closes, round, TIMEOUT_NS, &mut clock, nap);
            let why = match result {
                Ok(r) if r.closed => {
                    ROUNDS.fetch_add(1, Ordering::Relaxed);
                    RETRANSMITS.fetch_add(r.retransmits, Ordering::Relaxed);
                    done = true;
                    break;
                }
                Ok(_) => "a connection did not end where its close order leads",
                Err(why) => why,
            };
            *LAST_RETRY.lock_irqsave() = Some(why);
            if i + 1 < TRIES {
                RETRIES.fetch_add(1, Ordering::Relaxed);
            }
        }
        if !done {
            fail(w, "a TCP round trip with kbuild failed three times");
        }
        progress(w);
        sleep_until(after_ms(ROUND_MS));
    }
}
