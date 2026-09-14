//! A machine with no atomics has no queue to share with an interrupt handler, and so no
//! interrupt-driven receive: the driver transmits only there, and never offers an
//! interrupt to wire up.

/// Whether this build receives on interrupt.
pub const RECEIVES: bool = false;

/// Throws bytes away. Nothing on such a machine drains the receiver, since no handler
/// runs.
pub struct Queue;

impl Queue {
    pub fn push(&self, _byte: u8) -> bool {
        false
    }
}

pub static QUEUE: Queue = Queue;

pub fn record(_bytes: usize) {}

pub fn record_stray() {}

pub fn interrupts() -> u32 {
    0
}

pub fn bytes() -> u32 {
    0
}

pub fn stray() -> u32 {
    0
}

pub fn pop() -> Option<u8> {
    None
}

pub fn dropped() -> u32 {
    0
}
