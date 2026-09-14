//! The frame buffer pool: the only memory the stack moves frames through.
//!
//! A fixed number of Ethernet-sized buffers, taken and given back by index. The books
//! count every take and every give, so an owner can prove at a quiet moment that nothing
//! is held — the leak a receive path that forgets to return a buffer would show as a pool
//! that slowly empties and then drops every frame.

use crate::wire::FRAME_MAX;

/// Buffers in the pool. A poll holds two at most, one frame received and one reply being
/// built, and two more are headroom for a caller that sends while a poll is not running.
/// Beyond those four, two per TCP connection: its receive and send rings, held for as long as
/// the connection carries data (see `tcp`).
pub const BUFFERS: usize = 4 + 2 * crate::tcp::CONNECTIONS;

pub struct Pool {
    buffers: [[u8; FRAME_MAX]; BUFFERS],
    held: [bool; BUFFERS],
    taken: u64,
    returned: u64,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    pub const fn new() -> Pool {
        Pool {
            buffers: [[0; FRAME_MAX]; BUFFERS],
            held: [false; BUFFERS],
            taken: 0,
            returned: 0,
        }
    }

    /// Take a free buffer.
    pub fn take(&mut self) -> Option<usize> {
        let i = self.held.iter().position(|h| !h)?;
        self.held[i] = true;
        self.taken += 1;
        Some(i)
    }

    /// Give buffer `i` back. `false` for one that was not taken, which is a double give and
    /// is refused rather than counted, so the books stay honest.
    pub fn give(&mut self, i: usize) -> bool {
        match self.held.get_mut(i) {
            Some(held) if *held => {
                *held = false;
                self.returned += 1;
                true
            }
            _ => false,
        }
    }

    /// The contents of a held buffer.
    pub fn buffer(&mut self, i: usize) -> Option<&mut [u8; FRAME_MAX]> {
        if !*self.held.get(i)? {
            return None;
        }
        self.buffers.get_mut(i)
    }

    /// Two different held buffers at once: a frame being read and the reply being written.
    pub fn pair(
        &mut self,
        a: usize,
        b: usize,
    ) -> Option<(&mut [u8; FRAME_MAX], &mut [u8; FRAME_MAX])> {
        if a == b || !*self.held.get(a)? || !*self.held.get(b)? {
            return None;
        }
        let (low, high) = (a.min(b), a.max(b));
        let (left, right) = self.buffers.split_at_mut(high);
        let (lo, hi) = (&mut left[low], &mut right[0]);
        Some(if a < b { (lo, hi) } else { (hi, lo) })
    }

    pub fn in_use(&self) -> usize {
        self.held.iter().filter(|h| **h).count()
    }

    /// Buffers taken and given back since the pool was made.
    pub fn books(&self) -> (u64, u64) {
        (self.taken, self.returned)
    }

    /// Nothing held, and every take matched by a give.
    pub fn balanced(&self) -> bool {
        self.in_use() == 0 && self.taken == self.returned
    }
}
