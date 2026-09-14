//! Where the receive interrupt puts what arrived, on a machine with atomics.

use core::sync::atomic::{AtomicU32, Ordering};

use device::Fifo;

/// Whether this build receives on interrupt.
pub const RECEIVES: bool = true;

/// Bytes waiting for a reader. One PL011, so one queue.
pub type Queue = Fifo<64>;

pub static QUEUE: Queue = Queue::new();

/// Receive interrupts taken, whether or not they carried a byte.
static INTERRUPTS: AtomicU32 = AtomicU32::new(0);
/// Bytes taken off the wire by the handler.
static BYTES: AtomicU32 = AtomicU32::new(0);

pub fn record(bytes: usize) {
    INTERRUPTS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(bytes as u32, Ordering::Relaxed);
}

pub fn interrupts() -> u32 {
    INTERRUPTS.load(Ordering::Relaxed)
}

pub fn bytes() -> u32 {
    BYTES.load(Ordering::Relaxed)
}

pub fn pop() -> Option<u8> {
    QUEUE.pop()
}

pub fn dropped() -> u32 {
    QUEUE.dropped()
}
