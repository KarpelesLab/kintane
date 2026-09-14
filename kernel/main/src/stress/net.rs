//! The network, alongside everything else.
//!
//! One thread pings the gateway and makes a UDP round trip with kbuild, over and over,
//! through the card and stack the boot's net check brought up and left running. Each
//! exchange is a request and the reply that names it. A lost one is tried again, twice,
//! since a datagram network owes nobody delivery, and a third loss fails the run. Where the
//! card's interrupt is wired the thread runs it interrupt-driven, so a lost receive
//! interrupt is a lost reply here as well.
//!
//! At a checkpoint it holds nothing, so every stack buffer must be back in the pool and
//! every receive buffer with the card or holding a frame — whatever arrives while it is
//! parked, since kbuild keeps probing.
//!
//! Present only when the check completed its round trips, which is what gave it kbuild's
//! address. On a machine without, the workload is not spawned, and its slot reads as
//! parked holding nothing.

use core::sync::atomic::{AtomicU64, Ordering};

use super::{Parked, Workload, after_ms, checkpoint, fail, park_requested, progress};
use crate::preempt::{begin, sleep_until};

/// How long one try waits for its reply, and how many tries an exchange gets.
const TIMEOUT_NS: u64 = 1_000_000_000;
const TRIES: u32 = 3;

static PINGS: AtomicU64 = AtomicU64::new(0);
static ROUNDS: AtomicU64 = AtomicU64::new(0);
static RETRIES: AtomicU64 = AtomicU64::new(0);

/// Whether the machine has the card and kbuild's address this workload uses.
pub fn present() -> bool {
    crate::net::nic().is_some() && crate::net::peer().is_some()
}

/// Echo replies received, datagram round trips completed, and tries that had to be made
/// again, for the heartbeat.
pub fn counts() -> (u64, u64, u64) {
    (
        PINGS.load(Ordering::Relaxed),
        ROUNDS.load(Ordering::Relaxed),
        RETRIES.load(Ordering::Relaxed),
    )
}

/// Ready to run: the books balanced before anything starts.
pub fn setup() -> Result<(), &'static str> {
    if !present() {
        return Ok(());
    }
    crate::net::audit().map_err(|_| "the network's books do not balance before the run")
}

/// Every buffer back. Called with the thread parked.
pub fn audit() -> Result<(), &'static str> {
    if !present() {
        return Ok(());
    }
    crate::net::audit()
}

fn now() -> u64 {
    crate::timekeeping::now().as_nanos()
}

fn nap() {
    sleep_until(after_ms(1));
}

pub extern "C" fn worker(_: usize) -> ! {
    begin();
    let w = Workload::Net;
    let (Some(card), Some(peer)) = (crate::net::nic(), crate::net::peer()) else {
        fail(w, "spawned without a network");
        loop {
            sleep_until(after_ms(1000));
        }
    };
    card.set_interrupt_driven(platform::net_line().is_some());
    let mut clock: fn() -> u64 = now;
    let mut seq = 0u16;
    let mut round = 0u32;
    loop {
        if park_requested() {
            // Between exchanges nothing is held: the books must show that.
            checkpoint(w, Parked::Empty);
        }

        seq = seq.wrapping_add(1);
        if retried(|| crate::net::ping(card, seq, TIMEOUT_NS, &mut clock, nap)) {
            PINGS.fetch_add(1, Ordering::Relaxed);
        } else {
            fail(w, "an echo request to the gateway went unanswered three times");
        }

        round = round.wrapping_add(1);
        if retried(|| crate::net::udp_round(card, peer, round, TIMEOUT_NS, &mut clock, nap)) {
            ROUNDS.fetch_add(1, Ordering::Relaxed);
        } else {
            fail(w, "a datagram round trip with kbuild failed three times");
        }

        progress(w);
        sleep_until(after_ms(1));
    }
}

/// Run `exchange` until it succeeds, [`TRIES`] times at most.
fn retried(mut exchange: impl FnMut() -> bool) -> bool {
    for i in 0..TRIES {
        if exchange() {
            return true;
        }
        if i + 1 < TRIES {
            RETRIES.fetch_add(1, Ordering::Relaxed);
        }
    }
    false
}
