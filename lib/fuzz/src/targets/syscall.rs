//! System call dispatch: the argument registers a user program controls.
//!
//! Everything else here is a parser. This is the ABI boundary: six registers a program
//! fills with whatever it likes, a number that may name no call at all, and a kernel that
//! must answer every one of them with a value rather than a fault.
//!
//! # Table-driven, so new calls are fuzzed the day they are added
//!
//! The numbers and arities come from [`abi::TABLE`], which the `syscalls!` macro generates
//! from the same declaration the kernel and userspace both use. A call added to that table
//! is fuzzed by this target without anyone editing this file: the generator picks numbers
//! from the table, and the dispatcher decodes their arguments itself.
//!
//! What a new call *does* need is a method on the mock handler below, because `Handler` is
//! a trait with one method per call. That is a compile error naming the missing method,
//! which is the right way for this to break: a silently unimplemented call would be a
//! syscall nobody fuzzed.
//!
//! # What is checked
//!
//! * **Dispatch always answers.** A value or an [`abi::Error`]; never a panic.
//! * **An unknown number is an error, not a handler call.** The mock records every call it
//!   receives, and a number outside the table must leave that record untouched.
//! * **Arguments are decoded before the handler runs.** A handle that cannot be decoded must end
//!   the call without the handler seeing it, which the mock also records.

use alloc::vec::Vec;

use abi::{Error, Handle, Handler, TABLE, UserPtr, dispatch};

use crate::{Mutator, Rng};

/// A kernel side that does nothing but remember what it was asked.
///
/// It answers some calls with an error and some with a value, chosen by the arguments, so
/// both paths through `dispatch` are taken.
#[derive(Default)]
struct Mock {
    calls: usize,
    last: u64,
}

impl Handler for Mock {
    fn process_exit(&mut self, code: u64) -> Result<u64, Error> {
        self.calls += 1;
        self.last = code;
        Ok(0)
    }

    fn thread_exit(&mut self, code: u64) -> Result<u64, Error> {
        self.calls += 1;
        self.last = code;
        Ok(0)
    }

    fn thread_yield(&mut self) -> Result<u64, Error> {
        self.calls += 1;
        Ok(0)
    }

    fn debug_write(&mut self, console: Handle, bytes: UserPtr, len: usize) -> Result<u64, Error> {
        self.calls += 1;
        // A real kernel checks rights, then copies. Both failure modes are answers.
        if len > 4096 {
            return Err(Error::TooLarge);
        }
        let _ = (console, bytes);
        Ok(len as u64)
    }

    fn vm_map(&mut self, len: usize) -> Result<u64, Error> {
        self.calls += 1;
        len.checked_next_multiple_of(4096)
            .map(|l| l as u64)
            .ok_or(Error::InvalidArgument)
    }

    fn channel_create(&mut self, out: UserPtr) -> Result<u64, Error> {
        self.calls += 1;
        let _ = out;
        Ok(0)
    }

    fn channel_write(&mut self, channel: Handle, bytes: UserPtr, len: usize) -> Result<u64, Error> {
        self.calls += 1;
        let _ = (channel, bytes);
        if len > 4096 {
            Err(Error::TooLarge)
        } else {
            Ok(len as u64)
        }
    }

    fn channel_read(&mut self, channel: Handle, buf: UserPtr, cap: usize) -> Result<u64, Error> {
        self.calls += 1;
        let _ = (channel, buf, cap);
        Err(Error::ShouldWait)
    }

    fn handle_close(&mut self, handle: Handle) -> Result<u64, Error> {
        self.calls += 1;
        let _ = handle;
        Ok(0)
    }

    // The construction calls the object layer added. Like the rest, each answers with a value
    // or an error chosen by its arguments, so `dispatch` takes both paths for every one.

    fn process_create(&mut self, image: Handle) -> Result<u64, Error> {
        self.calls += 1;
        let _ = image;
        Ok(1)
    }

    fn process_transfer(&mut self, process: Handle, handle: Handle) -> Result<u64, Error> {
        self.calls += 1;
        let _ = (process, handle);
        Ok(2)
    }

    fn thread_create(&mut self, process: Handle, entry: u64, arg: u64) -> Result<u64, Error> {
        self.calls += 1;
        self.last = arg;
        let _ = process;
        // A real kernel refuses an entry outside the process's user half.
        if entry >= 0x0000_8000_0000_0000 {
            Err(Error::InvalidArgument)
        } else {
            Ok(3)
        }
    }

    fn process_wait(&mut self, process: Handle, queue: Handle, cookie: u64) -> Result<u64, Error> {
        self.calls += 1;
        self.last = cookie;
        let _ = (process, queue);
        Ok(0)
    }

    fn completion_create(&mut self) -> Result<u64, Error> {
        self.calls += 1;
        Ok(4)
    }

    fn completion_poll(&mut self, queue: Handle, out: UserPtr) -> Result<u64, Error> {
        self.calls += 1;
        let _ = (queue, out);
        Err(Error::ShouldWait)
    }

    fn vm_region_create(&mut self, len: usize) -> Result<u64, Error> {
        self.calls += 1;
        len.checked_next_multiple_of(4096)
            .filter(|&l| l != 0)
            .map(|l| l as u64)
            .ok_or(Error::InvalidArgument)
    }

    fn vm_map_in(&mut self, process: Handle, region: Handle) -> Result<u64, Error> {
        self.calls += 1;
        let _ = (process, region);
        Ok(0)
    }

    // The waiting calls. A timeout of zero polls and anything else would block in a kernel,
    // so the mock answers by the timeout: a poll finds nothing, a wait runs out.

    fn channel_send(
        &mut self,
        channel: Handle,
        bytes: UserPtr,
        len: usize,
        handles: UserPtr,
        count: usize,
    ) -> Result<u64, Error> {
        self.calls += 1;
        let _ = (channel, bytes, handles);
        if len > 64 || count > 2 {
            Err(Error::TooLarge)
        } else {
            Ok(0)
        }
    }

    fn channel_recv(
        &mut self,
        channel: Handle,
        buf: UserPtr,
        cap: usize,
        handles: UserPtr,
        hcap: usize,
        timeout_ns: u64,
    ) -> Result<u64, Error> {
        self.calls += 1;
        self.last = timeout_ns;
        let _ = (channel, buf, cap, handles, hcap);
        Err(if timeout_ns == 0 {
            Error::ShouldWait
        } else {
            Error::TimedOut
        })
    }

    fn completion_wait(
        &mut self,
        queue: Handle,
        out: UserPtr,
        timeout_ns: u64,
    ) -> Result<u64, Error> {
        self.calls += 1;
        self.last = timeout_ns;
        let _ = (queue, out);
        Err(if timeout_ns == 0 {
            Error::ShouldWait
        } else {
            Error::TimedOut
        })
    }

    fn event_create(&mut self) -> Result<u64, Error> {
        self.calls += 1;
        Ok(5)
    }

    fn event_signal(&mut self, event: Handle) -> Result<u64, Error> {
        self.calls += 1;
        let _ = event;
        Ok(0)
    }

    fn event_wait(&mut self, event: Handle, timeout_ns: u64) -> Result<u64, Error> {
        self.calls += 1;
        self.last = timeout_ns;
        let _ = event;
        Err(Error::TimedOut)
    }

    fn timer_create(&mut self, queue: Handle, key: u64) -> Result<u64, Error> {
        self.calls += 1;
        self.last = key;
        let _ = queue;
        Ok(6)
    }

    fn timer_set(&mut self, timer: Handle, delay_ns: u64, period_ns: u64) -> Result<u64, Error> {
        self.calls += 1;
        let _ = (timer, delay_ns);
        self.last = period_ns;
        Ok(0)
    }

    fn timer_cancel(&mut self, timer: Handle) -> Result<u64, Error> {
        self.calls += 1;
        let _ = timer;
        Ok(0)
    }

    fn clock_now(&mut self) -> Result<u64, Error> {
        self.calls += 1;
        Ok(self.calls as u64)
    }
}

/// Each record is a number and six argument words: 8 bytes for the number, 48 for the
/// arguments.
const RECORD: usize = 8 + 6 * 8;

pub fn generate(rng: &mut Rng, _seeds: &[Vec<u8>]) -> Vec<u8> {
    let calls = 1 + rng.below(16);
    let mut bytes: Vec<u8> = Vec::with_capacity(calls * RECORD);
    for _ in 0..calls {
        // Mostly numbers from the table, so the argument decoders are reached; sometimes
        // one that names no call, which must be refused.
        let nr = if rng.one_in(4) {
            rng.next_u64()
        } else {
            TABLE[rng.below(TABLE.len())].0
        };
        bytes.extend_from_slice(&nr.to_le_bytes());
        for _ in 0..6 {
            // Values an argument decoder cares about: a null pointer, a kernel address, a
            // huge length, a handle that cannot exist.
            let v = match rng.below(6) {
                0 => 0,
                1 => u64::MAX,
                2 => 0xffff_8000_0000_0000,
                3 => u64::from(rng.interesting_u32()),
                4 => rng.next_u64(),
                _ => rng.below(64) as u64,
            };
            bytes.extend_from_slice(&v.to_le_bytes());
        }
    }
    if !rng.one_in(8) {
        Mutator::mutate(rng, &mut bytes);
    }
    bytes
}

pub fn run(input: &[u8]) {
    let mut mock = Mock::default();
    let known: Vec<u64> = TABLE.iter().map(|(nr, _, _)| *nr).collect();

    let mut at = 0usize;
    while at + RECORD <= input.len() {
        let nr = u64::from_le_bytes(input[at..at + 8].try_into().unwrap_or([0; 8]));
        let mut args = [0u64; 6];
        for (i, slot) in args.iter_mut().enumerate() {
            let from = at + 8 + i * 8;
            *slot = u64::from_le_bytes(input[from..from + 8].try_into().unwrap_or([0; 8]));
        }
        at += RECORD;

        let before = mock.calls;
        let result = dispatch(&mut mock, nr, args);

        if !known.contains(&nr) {
            // An unknown number must be refused by dispatch itself. A handler that ran
            // would mean the number reached code that does not exist for it.
            assert_eq!(result, Err(Error::NoSuchCall), "number {nr} was not refused");
            assert_eq!(mock.calls, before, "number {nr} reached a handler");
        } else {
            // A known number either ran its handler or failed decoding an argument first.
            // Either is an answer; what must not happen is neither.
            assert!(
                mock.calls == before + 1 || result.is_err(),
                "call {nr} neither ran nor failed"
            );
        }
    }
}
