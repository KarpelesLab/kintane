use std::vec::Vec;

use super::*;

/// Records every call it receives, and answers with a value derived from its arguments.
#[derive(Default)]
struct Recorder {
    calls: Vec<(&'static str, Vec<u64>)>,
}

impl Handler for Recorder {
    fn process_exit(&mut self, code: u64) -> Result<u64, Error> {
        self.calls.push(("process_exit", vec![code]));
        Ok(0)
    }
    fn thread_exit(&mut self, code: u64) -> Result<u64, Error> {
        self.calls.push(("thread_exit", vec![code]));
        Ok(0)
    }
    fn thread_yield(&mut self) -> Result<u64, Error> {
        self.calls.push(("thread_yield", vec![]));
        Ok(0)
    }
    fn debug_write(&mut self, console: Handle, bytes: UserPtr, len: usize) -> Result<u64, Error> {
        self.calls
            .push(("debug_write", vec![u64::from(console.0), bytes.0, len as u64]));
        Ok(len as u64)
    }
    fn vm_map(&mut self, len: usize) -> Result<u64, Error> {
        self.calls.push(("vm_map", vec![len as u64]));
        Ok(0x1000)
    }
    fn channel_create(&mut self, out: UserPtr) -> Result<u64, Error> {
        self.calls.push(("channel_create", vec![out.0]));
        Ok(0)
    }
    fn channel_write(&mut self, channel: Handle, bytes: UserPtr, len: usize) -> Result<u64, Error> {
        self.calls
            .push(("channel_write", vec![u64::from(channel.0), bytes.0, len as u64]));
        Err(Error::Full)
    }
    fn channel_read(&mut self, channel: Handle, buf: UserPtr, cap: usize) -> Result<u64, Error> {
        self.calls
            .push(("channel_read", vec![u64::from(channel.0), buf.0, cap as u64]));
        Err(Error::ShouldWait)
    }
    fn handle_close(&mut self, handle: Handle) -> Result<u64, Error> {
        self.calls.push(("handle_close", vec![u64::from(handle.0)]));
        Ok(0)
    }
    fn process_create(&mut self, image: Handle) -> Result<u64, Error> {
        self.calls
            .push(("process_create", vec![u64::from(image.0)]));
        Ok(0)
    }
    fn process_transfer(&mut self, process: Handle, handle: Handle) -> Result<u64, Error> {
        self.calls
            .push(("process_transfer", vec![u64::from(process.0), u64::from(handle.0)]));
        Ok(0)
    }
    fn thread_create(&mut self, process: Handle, entry: u64, arg: u64) -> Result<u64, Error> {
        self.calls
            .push(("thread_create", vec![u64::from(process.0), entry, arg]));
        Ok(0)
    }
    fn process_wait(
        &mut self,
        process: Handle,
        completion: Handle,
        key: u64,
    ) -> Result<u64, Error> {
        self.calls
            .push(("process_wait", vec![u64::from(process.0), u64::from(completion.0), key]));
        Ok(0)
    }
    fn completion_create(&mut self) -> Result<u64, Error> {
        self.calls.push(("completion_create", vec![]));
        Ok(0)
    }
    fn completion_poll(&mut self, completion: Handle, out: UserPtr) -> Result<u64, Error> {
        self.calls
            .push(("completion_poll", vec![u64::from(completion.0), out.0]));
        Err(Error::ShouldWait)
    }
    fn vm_region_create(&mut self, len: usize) -> Result<u64, Error> {
        self.calls.push(("vm_region_create", vec![len as u64]));
        Ok(0)
    }
    fn vm_map_in(&mut self, process: Handle, region: Handle) -> Result<u64, Error> {
        self.calls
            .push(("vm_map_in", vec![u64::from(process.0), u64::from(region.0)]));
        Ok(0x2000)
    }
}

#[test]
fn numbers_are_unique_and_the_table_agrees_with_them() {
    let mut seen: Vec<u64> = TABLE.iter().map(|(n, _, _)| *n).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), TABLE.len(), "two calls share a number");
    assert_eq!(number::debug_write, 3);
    assert!(TABLE.contains(&(number::channel_read, "channel_read", 3)));
    assert!(TABLE.contains(&(number::thread_yield, "thread_yield", 0)));
}

#[test]
fn the_construction_calls_take_the_arguments_the_abi_documents() {
    // A process is built piece by piece, and each piece is named by a handle the caller
    // already holds; the argument counts are the shape of that contract.
    assert!(TABLE.contains(&(number::process_create, "process_create", 1)));
    assert!(TABLE.contains(&(number::process_transfer, "process_transfer", 2)));
    assert!(TABLE.contains(&(number::thread_create, "thread_create", 3)));
    assert!(TABLE.contains(&(number::process_wait, "process_wait", 3)));
    assert!(TABLE.contains(&(number::completion_create, "completion_create", 0)));
    assert!(TABLE.contains(&(number::completion_poll, "completion_poll", 2)));
    assert!(TABLE.contains(&(number::vm_region_create, "vm_region_create", 1)));
    assert!(TABLE.contains(&(number::vm_map_in, "vm_map_in", 2)));

    let mut r = Recorder::default();
    let out = dispatch(&mut r, number::process_wait, [4, 9, 0x9001, 0, 0, 0]);
    assert_eq!(out, Ok(0));
    assert_eq!(r.calls, vec![("process_wait", vec![4, 9, 0x9001])]);
}

#[test]
fn dispatch_decodes_arguments_in_order_and_calls_the_named_method() {
    let mut r = Recorder::default();
    let out = dispatch(&mut r, number::debug_write, [7, 0x8000_0000_1000, 21, 9, 9, 9]);
    assert_eq!(out, Ok(21));
    assert_eq!(r.calls, vec![("debug_write", vec![7, 0x8000_0000_1000, 21])]);

    let out = dispatch(&mut r, number::channel_read, [3, 0x10, 64, 0, 0, 0]);
    assert_eq!(out, Err(Error::ShouldWait));
    assert_eq!(r.calls.last(), Some(&("channel_read", vec![3, 0x10, 64])));
}

#[test]
fn every_number_in_the_table_reaches_a_method_and_no_other_does() {
    for (nr, name, _) in TABLE {
        let mut r = Recorder::default();
        let _ = dispatch(&mut r, *nr, [0; 6]);
        assert_eq!(r.calls.len(), 1, "{name}");
        assert_eq!(r.calls[0].0, *name, "number {nr} reached the wrong method");
    }
    let mut r = Recorder::default();
    let unknown = TABLE.iter().map(|(n, _, _)| n).max().unwrap() + 1;
    assert_eq!(dispatch(&mut r, unknown, [0; 6]), Err(Error::NoSuchCall));
    assert_eq!(dispatch(&mut r, u64::MAX, [0; 6]), Err(Error::NoSuchCall));
    assert!(r.calls.is_empty(), "an unknown number must not run anything");
}

#[test]
fn an_argument_that_does_not_decode_ends_the_call_before_the_handler() {
    let mut r = Recorder::default();
    // A handle is 32 bits; bit 32 set cannot name one.
    let wide = 1u64 << 32 | 5;
    assert_eq!(
        dispatch(&mut r, number::handle_close, [wide, 0, 0, 0, 0, 0]),
        Err(Error::BadHandle)
    );
    assert!(r.calls.is_empty());
}

#[test]
fn results_round_trip_through_the_two_registers() {
    for e in Error::ALL {
        let (status, value) = encode(Err(e));
        assert_ne!(status, 0, "{e:?} encodes as success");
        assert_eq!(value, 0);
        assert_eq!(decode(status, value), Err(e));
    }
    assert_eq!(encode(Ok(u64::MAX)), (0, u64::MAX));
    assert_eq!(decode(0, 42), Ok(42));
    assert_eq!(decode(0x7777, 0), Err(Error::Unknown));
}

#[test]
fn error_codes_are_distinct() {
    let mut codes: Vec<u64> = Error::ALL.iter().map(|e| e.code()).collect();
    codes.push(Error::Unknown.code());
    let n = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), n);
}
