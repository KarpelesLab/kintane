//! What the decoders do with bytes a program chose, including the ones Linux refuses.

use super::*;
use crate::Abi;

#[test]
fn a_pollfd_is_a_descriptor_and_the_events_asked_for() {
    let bytes = [7, 0, 0, 0, POLLIN as u8, 0, 0xff, 0xff];
    assert_eq!(
        parse_pollfd(&bytes),
        PollFd {
            fd: 7,
            events: POLLIN
        }
    );
    // The `revents` half is the kernel's to write: whatever it held is not read back.
    assert_eq!(REVENTS_AT, 6);
}

#[test]
fn a_negative_descriptor_is_skipped() {
    let bytes = [0xff, 0xff, 0xff, 0xff, POLLIN as u8, 0, 0, 0];
    let entry = parse_pollfd(&bytes);
    assert_eq!(entry.fd, -1);
    assert!(!entry.is_asked());
}

#[test]
fn an_answer_holds_what_was_asked_for_and_the_three_always_told() {
    // Asked for readable, and the descriptor hung up: both are reported.
    assert_eq!(revents(POLLIN, POLLIN | POLLHUP), POLLIN | POLLHUP);
    // Writable happened but was not asked about: not reported.
    assert_eq!(revents(POLLIN, POLLOUT), 0);
    // An error is reported whether or not it was asked about.
    assert_eq!(revents(0, POLLERR), POLLERR);
    assert_eq!(revents(0, POLLNVAL), POLLNVAL);
}

#[test]
fn only_events_this_kernel_reports_may_be_asked_for() {
    assert!(askable(POLLIN | POLLOUT | POLLRDHUP));
    assert!(askable(0));
    // An event nothing here ever reports would be a wait that never ends.
    assert!(!askable(0x4000));
}

#[test]
fn a_select_bitmap_names_descriptors_least_significant_bit_first() {
    let mut set = [0u8; FD_SET_BYTES];
    fd_set(&mut set, 0);
    fd_set(&mut set, 9);
    assert_eq!(set[0], 1);
    assert_eq!(set[1], 2);
    assert!(fd_isset(&set, 0));
    assert!(fd_isset(&set, 9));
    assert!(!fd_isset(&set, 1));
    // Past the bitmap is not set and not named, rather than a panic.
    assert!(!fd_isset(&set, FD_SET_BITS + 1));
    fd_set(&mut set, FD_SET_BITS + 1);
}

#[test]
fn a_select_past_the_bitmap_is_refused() {
    assert_eq!(fd_set_bytes(0), Ok(0));
    assert_eq!(fd_set_bytes(1), Ok(1));
    assert_eq!(fd_set_bytes(9), Ok(2));
    assert_eq!(fd_set_bytes(FD_SET_BITS as u64), Ok(FD_SET_BYTES));
    assert_eq!(
        fd_set_bytes(FD_SET_BITS as u64 + 1),
        Err(Failure::InvalidArgument)
    );
    assert_eq!(fd_set_bytes(u64::MAX), Err(Failure::InvalidArgument));
}

#[test]
fn an_epoll_event_is_packed_on_x86_64_and_aligned_on_aarch64() {
    assert_eq!(event_bytes(Abi::X86_64), 12);
    assert_eq!(event_bytes(Abi::Aarch64), 16);
    let event = EpollEvent {
        events: EPOLLIN,
        data: 0x0102_0304_0506_0708,
    };
    for abi in [Abi::X86_64, Abi::Aarch64] {
        let bytes = write_event(abi, event);
        assert_eq!(parse_event(abi, &bytes), Some(event), "{abi:?}");
        // The data word sits where that ABI puts it, and nowhere else.
        let at = match abi {
            Abi::X86_64 => 4,
            Abi::Aarch64 => 8,
        };
        assert_eq!(bytes[at], 0x08, "{abi:?}");
    }
}

#[test]
fn an_epoll_event_shorter_than_its_abi_is_not_read() {
    let short = [0u8; 11];
    assert_eq!(parse_event(Abi::X86_64, &short), None);
    assert_eq!(parse_event(Abi::Aarch64, &[0u8; 15]), None);
    assert_eq!(parse_event(Abi::X86_64, &[]), None);
}

#[test]
fn epoll_and_poll_number_their_events_the_same_way() {
    assert_eq!(poll_events(EPOLLIN), POLLIN);
    assert_eq!(poll_events(EPOLLOUT), POLLOUT);
    assert_eq!(poll_events(EPOLLRDHUP), POLLRDHUP);
    assert_eq!(epoll_events(POLLHUP), EPOLLHUP);
    // The two flags that are refused are not `poll` events at all.
    assert_eq!(poll_events(EPOLLET), 0);
    assert_eq!(poll_events(EPOLLONESHOT), 0);
}

#[test]
fn a_poll_timeout_is_milliseconds_and_a_negative_one_is_forever() {
    assert_eq!(timeout_ms(0), Some(0));
    assert_eq!(timeout_ms(5), Some(5_000_000));
    assert_eq!(timeout_ms(-1i64 as u64), None);
    assert_eq!(timeout_ms(-1000i64 as u64), None);
    // A count that would overflow nanoseconds saturates rather than wrapping to a short wait.
    assert_eq!(timeout_ms(u64::MAX >> 1), Some(u64::MAX));
}

#[test]
fn a_timespec_is_seconds_and_nanoseconds() {
    let mut bytes = [0u8; TIMESPEC_BYTES];
    bytes[..8].copy_from_slice(&2i64.to_le_bytes());
    bytes[8..].copy_from_slice(&500_000_000i64.to_le_bytes());
    assert_eq!(timespec_ns(&bytes), Ok(2_500_000_000));
}

#[test]
fn a_timespec_linux_refuses_is_refused_here() {
    let mut bytes = [0u8; TIMESPEC_BYTES];
    bytes[..8].copy_from_slice(&(-1i64).to_le_bytes());
    assert_eq!(timespec_ns(&bytes), Err(Failure::InvalidArgument));
    let mut bytes = [0u8; TIMESPEC_BYTES];
    bytes[8..].copy_from_slice(&1_000_000_000i64.to_le_bytes());
    assert_eq!(timespec_ns(&bytes), Err(Failure::InvalidArgument));
    let mut bytes = [0u8; TIMESPEC_BYTES];
    bytes[8..].copy_from_slice(&(-5i64).to_le_bytes());
    assert_eq!(timespec_ns(&bytes), Err(Failure::InvalidArgument));
}

#[test]
fn a_timeval_is_seconds_and_microseconds() {
    let mut bytes = [0u8; TIMESPEC_BYTES];
    bytes[..8].copy_from_slice(&1i64.to_le_bytes());
    bytes[8..].copy_from_slice(&250_000i64.to_le_bytes());
    assert_eq!(timeval_ns(&bytes), Ok(1_250_000_000));
    // A microsecond field past a second is refused, as Linux refuses it.
    let mut bytes = [0u8; TIMESPEC_BYTES];
    bytes[8..].copy_from_slice(&1_000_000i64.to_le_bytes());
    assert_eq!(timeval_ns(&bytes), Err(Failure::InvalidArgument));
}
