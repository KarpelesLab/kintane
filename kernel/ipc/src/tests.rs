//! Host tests, run against both mock profiles.
//!
//! Every scenario is generic over the lock family and instantiated twice: `_full` with
//! [`Spin<MockFull>`] and `_tiny` with [`Irq<MockTiny>`]. The other two pairings do not
//! compile — `MockTiny` has no CAS for a spinlock, `MockFull` has not asserted it is a
//! uniprocessor — and that absence is the capability bound doing its job.
//!
//! The mocks keep the interrupt flag in a process-wide static, and every channel
//! operation masks interrupts, so the tests run one at a time.
//!
//! Most of the weight is on handle conservation, because that is what is most likely to
//! be wrong: a reference in zero places leaks its object, in two it breaks the
//! capability model. `World` at the bottom checks it after every step of a long
//! randomised run, counting entries in every table and every queue.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use hal::Arch;
use hal::mock::{MockFull, MockTiny};
use kobject::handle::{self, Entry, Handle, HandleTable};
use kobject::{ObjectId, ObjectIds, ObjectType, Rights};

use crate::*;

type Full = Spin<MockFull>;
type Tiny = Irq<MockTiny>;

/// Depth `D`, 8 bytes and 2 handles per message.
type Chan<L, const D: usize = 2> = Channel<L, D, 8, 2>;

const MOVABLE: Rights = Rights::READ.union(Rights::TRANSFER);

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    match SERIAL.lock() {
        Ok(g) => g,
        // A failed test poisoned it; the data is `()`, so nothing is inconsistent.
        Err(poisoned) => poisoned.into_inner(),
    }
}

macro_rules! both {
    ($($scenario:ident => $full:ident, $tiny:ident;)*) => {$(
        #[test]
        fn $full() {
            let _s = serial();
            $scenario::<Full>();
        }
        #[test]
        fn $tiny() {
            let _s = serial();
            $scenario::<Tiny>();
        }
    )*};
}

// ---- helpers ------------------------------------------------------------------------

fn install<const N: usize>(t: &mut HandleTable<N>, e: Entry) -> Handle {
    t.insert(e.object, e.kind, e.rights).unwrap()
}

/// A channel with endpoint A installed in `ta` and B in `tb`.
fn open<L: LockFamily, const D: usize, const NA: usize, const NB: usize>(
    ids: &ObjectIds,
    ta: &mut HandleTable<NA>,
    tb: &mut HandleTable<NB>,
) -> (Chan<L, D>, Handle, Handle) {
    let (ch, [a, b]) = Chan::<L, D>::new(ids, ENDPOINT_RIGHTS);
    let ha = install(ta, a);
    let hb = install(tb, b);
    (ch, ha, hb)
}

/// A stand-in for some other kernel object, installed with `rights`.
fn event<const N: usize>(ids: &ObjectIds, t: &mut HandleTable<N>, rights: Rights) -> Handle {
    t.insert(ids.next(), ObjectType::Event, rights).unwrap()
}

type Got = (Vec<u8>, Vec<Handle>);

fn recv<L: LockFamily, const D: usize, const N: usize>(
    ch: &Chan<L, D>,
    t: &mut HandleTable<N>,
    h: Handle,
) -> Result<Got, Error> {
    let mut bytes = [0u8; 8];
    let mut handles = [Handle::from_raw(0); 2];
    let r = ch.receive(t, h, &mut bytes, &mut handles)?;
    Ok((bytes[..r.bytes].to_vec(), handles[..r.handles].to_vec()))
}

fn snapshot<const N: usize>(t: &HandleTable<N>) -> Vec<Entry> {
    t.entries().collect()
}

fn queued<L: LockFamily, const D: usize>(ch: &Chan<L, D>) -> Vec<(Side, Entry)> {
    let mut v = Vec::new();
    ch.for_each_queued(|s, e| v.push((s, e)));
    v
}

/// How many entries naming `object` exist across `tables` and `chans`' queues.
fn copies<L: LockFamily, const D: usize>(
    object: ObjectId,
    tables: &[&[Entry]],
    chans: &[&Chan<L, D>],
) -> usize {
    let in_tables = tables
        .iter()
        .flat_map(|t| t.iter())
        .filter(|e| e.object == object)
        .count();
    let in_queues: usize = chans
        .iter()
        .map(|c| queued(c).iter().filter(|(_, e)| e.object == object).count())
        .sum();
    in_tables + in_queues
}

fn no_sink(e: Entry) {
    panic!("nothing should have been undeliverable, got {e:?}");
}

// ---- messages ------------------------------------------------------------------------

both! {
    round_trip => round_trip_full, round_trip_tiny;
    fifo_order_survives_wraparound => fifo_order_survives_wraparound_full,
        fifo_order_survives_wraparound_tiny;
    a_full_queue_refuses_rather_than_overwrites => a_full_queue_refuses_rather_than_overwrites_full,
        a_full_queue_refuses_rather_than_overwrites_tiny;
    oversize_messages_are_refused => oversize_messages_are_refused_full,
        oversize_messages_are_refused_tiny;
    a_small_buffer_leaves_the_message_queued => a_small_buffer_leaves_the_message_queued_full,
        a_small_buffer_leaves_the_message_queued_tiny;
    endpoint_rights_gate_each_operation => endpoint_rights_gate_each_operation_full,
        endpoint_rights_gate_each_operation_tiny;
}

fn round_trip<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);

    assert_eq!(recv(&ch, &mut tb, hb), Err(Error::Empty));
    ch.send(&mut ta, ha, b"ping", &[]).unwrap();
    assert_eq!(ch.status(&tb, hb).unwrap().queued, 1);
    assert_eq!(recv(&ch, &mut tb, hb).unwrap(), (b"ping".to_vec(), vec![]));

    // Both directions, and a zero-length message is still a message.
    ch.send(&mut tb, hb, b"pong", &[]).unwrap();
    ch.send(&mut tb, hb, b"", &[]).unwrap();
    assert_eq!(recv(&ch, &mut ta, ha).unwrap().0, b"pong");
    assert_eq!(recv(&ch, &mut ta, ha).unwrap().0, b"");
    assert_eq!(recv(&ch, &mut ta, ha), Err(Error::Empty));
    assert_eq!(recv(&ch, &mut tb, hb), Err(Error::Empty));
}

fn fifo_order_survives_wraparound<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 3, 8, 8>(&ids, &mut ta, &mut tb);

    // Interleaved so the ring's head moves past the end of the storage several times.
    let mut next_out = 0u8;
    let mut next_in = 0u8;
    for round in 0..20 {
        for _ in 0..(1 + round % 3) {
            match ch.send(&mut ta, ha, &[next_out], &[]) {
                Ok(()) => next_out += 1,
                Err(Error::Full) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
        for _ in 0..(1 + (round + 1) % 3) {
            match recv(&ch, &mut tb, hb) {
                Ok((b, _)) => {
                    assert_eq!(b, [next_in], "out of order");
                    next_in += 1;
                }
                Err(Error::Empty) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
    }
    // Bounded, so a receive that never dequeued fails here instead of looping for ever.
    for _ in 0..=3 {
        let Ok((b, _)) = recv(&ch, &mut tb, hb) else {
            break;
        };
        assert_eq!(b, [next_in]);
        next_in += 1;
    }
    assert_eq!(next_in, next_out, "every message sent was received exactly once");
    assert!(next_out > 20, "the test should actually have wrapped");
}

fn a_full_queue_refuses_rather_than_overwrites<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);

    ch.send(&mut ta, ha, b"1", &[]).unwrap();
    assert!(ch.status(&ta, ha).unwrap().writable);
    ch.send(&mut ta, ha, b"2", &[]).unwrap();
    assert!(!ch.status(&ta, ha).unwrap().writable);
    assert_eq!(ch.send(&mut ta, ha, b"3", &[]), Err(Error::Full));
    assert_eq!(ch.send(&mut ta, ha, b"3", &[]), Err(Error::Full));

    // The other direction has its own inbox and is unaffected.
    ch.send(&mut tb, hb, b"back", &[]).unwrap();

    assert_eq!(recv(&ch, &mut tb, hb).unwrap().0, b"1", "not overwritten");
    ch.send(&mut ta, ha, b"3", &[]).unwrap();
    assert_eq!(recv(&ch, &mut tb, hb).unwrap().0, b"2");
    assert_eq!(recv(&ch, &mut tb, hb).unwrap().0, b"3");
    assert_eq!(recv(&ch, &mut ta, ha).unwrap().0, b"back");
}

fn oversize_messages_are_refused<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let hs: Vec<Handle> = (0..3).map(|_| event(&ids, &mut ta, MOVABLE)).collect();
    let before = snapshot(&ta);

    assert_eq!(
        ch.send(&mut ta, ha, &[0; 9], &[]),
        Err(Error::TooLarge {
            bytes: 9,
            handles: 0
        })
    );
    let three: Vec<Transfer> = hs.iter().map(|h| Transfer::whole(*h)).collect();
    assert_eq!(
        ch.send(&mut ta, ha, b"", &three),
        Err(Error::TooLarge {
            bytes: 0,
            handles: 3
        })
    );
    assert_eq!(snapshot(&ta), before);
    assert_eq!(recv(&ch, &mut tb, hb), Err(Error::Empty));
    // Exactly at the limit is fine.
    ch.send(&mut ta, ha, &[7; 8], &three[..2]).unwrap();
    assert_eq!(recv(&ch, &mut tb, hb).unwrap().0, [7; 8]);
}

fn a_small_buffer_leaves_the_message_queued<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let h = event(&ids, &mut ta, MOVABLE);
    ch.send(&mut ta, ha, b"hello", &[Transfer::whole(h)])
        .unwrap();
    let in_flight = queued(&ch);
    let tb_before = snapshot(&tb);

    let mut small = [0u8; 4];
    let mut hs = [Handle::from_raw(0); 2];
    let too_small = Err(Error::BufferTooSmall {
        bytes: 5,
        handles: 1,
    });
    assert_eq!(ch.receive(&mut tb, hb, &mut small, &mut hs), too_small);
    let mut bytes = [0u8; 8];
    assert_eq!(ch.receive(&mut tb, hb, &mut bytes, &mut []), too_small);
    assert_eq!(queued(&ch), in_flight);
    assert_eq!(snapshot(&tb), tb_before);

    let (b, got) = recv(&ch, &mut tb, hb).unwrap();
    assert_eq!((b.as_slice(), got.len()), (&b"hello"[..], 1));
}

fn endpoint_rights_gate_each_operation<L: LockFamily>() {
    let ids = ObjectIds::new();
    let mut t = HandleTable::<8>::new();
    let (ch, [a, b]) = Chan::<L>::new(&ids, ENDPOINT_RIGHTS);
    let read_only = t.insert(a.object, a.kind, Rights::READ).unwrap();
    let write_only = t.insert(b.object, b.kind, Rights::WRITE).unwrap();

    assert_eq!(
        ch.send(&mut t, read_only, b"x", &[]),
        Err(Error::Endpoint(handle::Error::AccessDenied {
            required: Rights::WRITE,
            held: Rights::READ
        }))
    );
    ch.send(&mut t, write_only, b"x", &[]).unwrap();
    assert_eq!(
        recv(&ch, &mut t, write_only),
        Err(Error::Endpoint(handle::Error::AccessDenied {
            required: Rights::READ,
            held: Rights::WRITE
        }))
    );
    assert_eq!(recv(&ch, &mut t, read_only).unwrap().0, b"x");
    assert!(matches!(ch.status(&t, read_only), Err(Error::Endpoint(_))), "WAIT needed");
    assert!(matches!(
        ch.duplicate(&mut t, read_only, Rights::ALL),
        Err(Error::Endpoint(handle::Error::AccessDenied { .. }))
    ));

    // Not a channel at all.
    let ev = event(&ids, &mut t, Rights::ALL);
    assert!(matches!(
        ch.send(&mut t, ev, b"", &[]),
        Err(Error::Endpoint(handle::Error::WrongType { .. }))
    ));
    // Some other channel's endpoint.
    let (other, [oa, _ob]) = Chan::<L>::new(&ids, ENDPOINT_RIGHTS);
    let hoa = install(&mut t, oa);
    assert_eq!(ch.send(&mut t, hoa, b"", &[]), Err(Error::NotThisChannel));
    // A closed handle.
    t.close(read_only).unwrap();
    assert_eq!(recv(&ch, &mut t, read_only), Err(Error::Endpoint(handle::Error::BadHandle)));
    let _ = other;
}

// ---- handle transfer ----------------------------------------------------------------

both! {
    a_transfer_moves_exactly_one_handle => a_transfer_moves_exactly_one_handle_full,
        a_transfer_moves_exactly_one_handle_tiny;
    rights_narrow_in_transit_and_never_widen => rights_narrow_in_transit_and_never_widen_full,
        rights_narrow_in_transit_and_never_widen_tiny;
    a_send_to_a_full_queue_leaves_every_handle_in_place =>
        a_send_to_a_full_queue_leaves_every_handle_in_place_full,
        a_send_to_a_full_queue_leaves_every_handle_in_place_tiny;
    a_receive_into_a_full_table_leaves_the_message_intact =>
        a_receive_into_a_full_table_leaves_the_message_intact_full,
        a_receive_into_a_full_table_leaves_the_message_intact_tiny;
    one_bad_handle_fails_the_whole_list => one_bad_handle_fails_the_whole_list_full,
        one_bad_handle_fails_the_whole_list_tiny;
    a_handle_without_transfer_is_refused => a_handle_without_transfer_is_refused_full,
        a_handle_without_transfer_is_refused_tiny;
    a_channel_cannot_carry_its_own_endpoints => a_channel_cannot_carry_its_own_endpoints_full,
        a_channel_cannot_carry_its_own_endpoints_tiny;
    another_channels_endpoint_travels_as_a_capability =>
        another_channels_endpoint_travels_as_a_capability_full,
        another_channels_endpoint_travels_as_a_capability_tiny;
}

fn a_transfer_moves_exactly_one_handle<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let keep = event(&ids, &mut ta, MOVABLE);
    let h = event(&ids, &mut ta, MOVABLE);
    let sent = ta.get(h).unwrap();
    let kept = ta.get(keep).unwrap();
    let (a_len, b_len) = (ta.len(), tb.len());

    ch.send(&mut ta, ha, b"take", &[Transfer::whole(h)])
        .unwrap();

    // Gone from the sender, and only that one.
    assert_eq!(ta.get(h), Err(handle::Error::BadHandle));
    assert_eq!(ta.get(keep), Ok(kept));
    assert_eq!(ta.len(), a_len - 1);
    // In flight: in the queue, in no table.
    assert_eq!(queued(&ch), vec![(Side::B, sent)]);
    assert_eq!(tb.len(), b_len);
    assert_eq!(copies(sent.object, &[&snapshot(&ta), &snapshot(&tb)], &[&ch]), 1);

    let (bytes, got) = recv(&ch, &mut tb, hb).unwrap();
    assert_eq!((bytes.as_slice(), got.len()), (&b"take"[..], 1));
    assert_eq!(tb.get(got[0]), Ok(sent));
    assert_eq!(tb.len(), b_len + 1);
    assert!(queued(&ch).is_empty(), "the queue kept no copy");
    assert_eq!(copies(sent.object, &[&snapshot(&ta), &snapshot(&tb)], &[&ch]), 1);
}

fn rights_narrow_in_transit_and_never_widen<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let held = MOVABLE.union(Rights::MAP);
    let narrowed = event(&ids, &mut ta, held);
    let whole = event(&ids, &mut ta, held);

    ch.send(
        &mut ta,
        ha,
        b"",
        &[
            Transfer::narrowed(narrowed, Rights::READ),
            Transfer::narrowed(whole, Rights::ALL),
        ],
    )
    .unwrap();
    let (_, got) = recv(&ch, &mut tb, hb).unwrap();
    assert_eq!(tb.get(got[0]).unwrap().rights, Rights::READ);
    // Asking for ALL yields what was held and no more.
    assert_eq!(tb.get(got[1]).unwrap().rights, held);
    assert!(!tb.get(got[1]).unwrap().rights.contains(Rights::WRITE));
}

fn a_send_to_a_full_queue_leaves_every_handle_in_place<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    ch.send(&mut ta, ha, b"1", &[]).unwrap();
    ch.send(&mut ta, ha, b"2", &[]).unwrap();

    let h1 = event(&ids, &mut ta, MOVABLE);
    let h2 = event(&ids, &mut ta, MOVABLE);
    let (e1, e2) = (ta.get(h1).unwrap(), ta.get(h2).unwrap());
    let before = snapshot(&ta);
    let list = [Transfer::whole(h1), Transfer::narrowed(h2, Rights::READ)];

    assert_eq!(ch.send(&mut ta, ha, b"3", &list), Err(Error::Full));

    // The same handle values still name the same entries with the same rights.
    assert_eq!(ta.get(h1), Ok(e1));
    assert_eq!(ta.get(h2), Ok(e2));
    assert_eq!(snapshot(&ta), before);
    assert!(queued(&ch).is_empty());
    assert_eq!(ch.status(&tb, hb).unwrap().queued, 2);

    // And once there is room, the same handles go.
    recv(&ch, &mut tb, hb).unwrap();
    ch.send(&mut ta, ha, b"3", &list).unwrap();
    assert_eq!(ta.get(h1), Err(handle::Error::BadHandle));
    assert_eq!(ta.get(h2), Err(handle::Error::BadHandle));
    recv(&ch, &mut tb, hb).unwrap();
    let (_, got) = recv(&ch, &mut tb, hb).unwrap();
    assert_eq!(tb.get(got[0]).unwrap().object, e1.object);
    assert_eq!(tb.get(got[1]).unwrap().object, e2.object);
}

fn a_receive_into_a_full_table_leaves_the_message_intact<L: LockFamily>() {
    let ids = ObjectIds::new();
    let mut ta = HandleTable::<8>::new();
    // Room for the endpoint and two more.
    let mut tb = HandleTable::<3>::new();
    let (ch, ha, hb) = open::<L, 2, 8, 3>(&ids, &mut ta, &mut tb);
    let filler1 = event(&ids, &mut tb, Rights::READ);
    let filler2 = event(&ids, &mut tb, Rights::READ);

    let h1 = event(&ids, &mut ta, MOVABLE);
    let h2 = event(&ids, &mut ta, MOVABLE);
    let (e1, e2) = (ta.get(h1).unwrap(), ta.get(h2).unwrap());
    ch.send(&mut ta, ha, b"two", &[Transfer::whole(h1), Transfer::whole(h2)])
        .unwrap();
    let in_flight = queued(&ch);
    assert_eq!(in_flight, vec![(Side::B, e1), (Side::B, e2)]);

    let conserved = |ta: &HandleTable<8>, tb: &HandleTable<3>, ch: &Chan<L>| {
        for e in [e1, e2] {
            assert_eq!(copies(e.object, &[&snapshot(ta), &snapshot(tb)], &[ch]), 1);
        }
    };
    let no_room = Err(Error::NoRoom {
        handles: 2,
        error: handle::Error::TableFull,
    });

    // No room at all.
    let tb_before = snapshot(&tb);
    assert_eq!(recv(&ch, &mut tb, hb), no_room);
    assert_eq!(snapshot(&tb), tb_before);
    assert_eq!(queued(&ch), in_flight);
    conserved(&ta, &tb, &ch);

    // Room for one of the two: the first is installed, the second fails, and the first
    // must be taken back out.
    tb.close(filler1).unwrap();
    let tb_before = snapshot(&tb);
    assert_eq!(recv(&ch, &mut tb, hb), no_room);
    assert_eq!(snapshot(&tb), tb_before, "the partial install was rolled back");
    assert_eq!(tb.len(), 2);
    assert_eq!(queued(&ch), in_flight);
    conserved(&ta, &tb, &ch);
    assert_eq!(ch.status(&tb, hb).unwrap().queued, 1);

    // Room for both.
    tb.close(filler2).unwrap();
    let (bytes, got) = recv(&ch, &mut tb, hb).unwrap();
    assert_eq!(bytes, b"two");
    assert_eq!(tb.get(got[0]), Ok(e1));
    assert_eq!(tb.get(got[1]), Ok(e2));
    assert!(queued(&ch).is_empty());
    conserved(&ta, &tb, &ch);
}

fn one_bad_handle_fails_the_whole_list<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let good = event(&ids, &mut ta, MOVABLE);
    let untransferable = event(&ids, &mut ta, Rights::READ);
    let stale = event(&ids, &mut ta, MOVABLE);
    ta.close(stale).unwrap();
    let before = snapshot(&ta);

    // The good handle is first, so a send that moved handles as it validated them
    // would already have moved it by the time it found the bad one.
    assert_eq!(
        ch.send(&mut ta, ha, b"", &[Transfer::whole(good), Transfer::whole(untransferable)]),
        Err(Error::Transfer {
            index: 1,
            error: handle::Error::AccessDenied {
                required: Rights::TRANSFER,
                held: Rights::READ
            }
        })
    );
    assert_eq!(snapshot(&ta), before);

    assert_eq!(
        ch.send(&mut ta, ha, b"", &[Transfer::whole(good), Transfer::whole(stale)]),
        Err(Error::Transfer {
            index: 1,
            error: handle::Error::BadHandle
        })
    );
    assert_eq!(snapshot(&ta), before);

    // The same handle twice: validating one at a time, both would pass, and the second
    // `transfer_out` would then fail after the first had moved.
    assert_eq!(
        ch.send(&mut ta, ha, b"", &[Transfer::whole(good), Transfer::whole(good)]),
        Err(Error::DuplicateTransfer { index: 1 })
    );
    assert_eq!(snapshot(&ta), before);
    assert!(ta.get(good).is_ok());
    assert!(queued(&ch).is_empty());
    assert_eq!(recv(&ch, &mut tb, hb), Err(Error::Empty));
}

fn a_handle_without_transfer_is_refused<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let everything_but = event(&ids, &mut ta, Rights::ALL.without(Rights::TRANSFER));
    let entry = ta.get(everything_but).unwrap();

    assert!(matches!(
        ch.send(&mut ta, ha, b"", &[Transfer::whole(everything_but)]),
        Err(Error::Transfer {
            index: 0,
            error: handle::Error::AccessDenied { .. }
        })
    ));
    assert_eq!(ta.get(everything_but), Ok(entry));
    assert_eq!(recv(&ch, &mut tb, hb), Err(Error::Empty));
}

fn a_channel_cannot_carry_its_own_endpoints<L: LockFamily>() {
    let ids = ObjectIds::new();
    let mut t = HandleTable::<8>::new();
    let (ch, ha, hb) = {
        let mut t2 = HandleTable::<8>::new();
        let (ch, ha, hb_elsewhere) = open::<L, 2, 8, 8>(&ids, &mut t, &mut t2);
        // Move B into the same table, through the channel's own accounting: the
        // handle leaves t2 and appears in t.
        let e = t2.transfer_out(hb_elsewhere).unwrap();
        (ch, ha, install(&mut t, e))
    };
    let dup = ch.duplicate(&mut t, ha, Rights::ALL).unwrap();
    let before = snapshot(&t);

    // Its own sending endpoint, a duplicate of it, and its peer: each would leave an
    // endpoint whose only reference is in a queue only that endpoint can drain.
    for (index, list) in [
        (0, vec![Transfer::whole(ha)]),
        (0, vec![Transfer::whole(dup)]),
        (0, vec![Transfer::whole(hb)]),
    ] {
        assert_eq!(ch.send(&mut t, ha, b"", &list), Err(Error::WouldCycle { index }));
        assert_eq!(snapshot(&t), before);
    }
    assert!(queued(&ch).is_empty());
    assert_eq!((ch.references(Side::A), ch.references(Side::B)), (2, 1));

    // Nothing leaked: closing the handles closes both endpoints.
    ch.close(&mut t, dup, no_sink).unwrap();
    ch.close(&mut t, ha, no_sink).unwrap();
    ch.close(&mut t, hb, no_sink).unwrap();
    assert!(!ch.is_open(Side::A) && !ch.is_open(Side::B));
    assert!(t.is_empty());
}

fn another_channels_endpoint_travels_as_a_capability<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb, mut tc) =
        (HandleTable::<8>::new(), HandleTable::<8>::new(), HandleTable::<8>::new());
    let (c1, a1, b1) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let (c2, a2, b2) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tc);

    // Hand C2's A end to whoever holds C1's B end.
    c1.send(&mut ta, a1, b"c2", &[Transfer::whole(a2)]).unwrap();
    assert_eq!(c2.references(Side::A), 1, "moving a reference does not change the count");
    assert!(c2.is_open(Side::A));
    let (_, got) = recv(&c1, &mut tb, b1).unwrap();
    let a2_in_b = got[0];

    // The new holder can use it; the old one cannot.
    assert!(matches!(c2.send(&mut ta, a2, b"x", &[]), Err(Error::Endpoint(_))));
    c2.send(&mut tb, a2_in_b, b"from b", &[]).unwrap();
    assert_eq!(recv(&c2, &mut tc, b2).unwrap().0, b"from b");
}

// ---- lifetime and closure -----------------------------------------------------------

both! {
    peer_closure_is_observed_after_draining => peer_closure_is_observed_after_draining_full,
        peer_closure_is_observed_after_draining_tiny;
    undelivered_handles_are_handed_back_on_close =>
        undelivered_handles_are_handed_back_on_close_full,
        undelivered_handles_are_handed_back_on_close_tiny;
    closing_cascades_through_an_in_flight_endpoint =>
        closing_cascades_through_an_in_flight_endpoint_full,
        closing_cascades_through_an_in_flight_endpoint_tiny;
    an_endpoint_stays_open_while_any_duplicate_does =>
        an_endpoint_stays_open_while_any_duplicate_does_full,
        an_endpoint_stays_open_while_any_duplicate_does_tiny;
    releases_are_checked => releases_are_checked_full, releases_are_checked_tiny;
    outside_a_set_a_cycle_across_two_channels_leaks =>
        outside_a_set_a_cycle_across_two_channels_leaks_full,
        outside_a_set_a_cycle_across_two_channels_leaks_tiny;
}

// ---- cycles, collected by a set -------------------------------------------------------

both! {
    a_cycle_across_two_channels_is_collected => a_cycle_across_two_channels_is_collected_full,
        a_cycle_across_two_channels_is_collected_tiny;
    a_live_chain_is_not_collected => a_live_chain_is_not_collected_full,
        a_live_chain_is_not_collected_tiny;
    a_cycle_through_three_channels_is_collected =>
        a_cycle_through_three_channels_is_collected_full,
        a_cycle_through_three_channels_is_collected_tiny;
    other_objects_in_a_collected_inbox_go_to_the_sink =>
        other_objects_in_a_collected_inbox_go_to_the_sink_full,
        other_objects_in_a_collected_inbox_go_to_the_sink_tiny;
    a_finished_channels_slot_is_reused => a_finished_channels_slot_is_reused_full,
        a_finished_channels_slot_is_reused_tiny;
}

type Set<L> = ChannelSet<L, 4, 2, 8, 2>;

/// A channel created in `set`, with endpoint A installed in `ta` and B in `tb`.
fn open_in<L: LockFamily, const NA: usize, const NB: usize>(
    set: &mut Set<L>,
    ids: &ObjectIds,
    ta: &mut HandleTable<NA>,
    tb: &mut HandleTable<NB>,
) -> (usize, Handle, Handle) {
    let (i, [a, b]) = set.create(ids, ENDPOINT_RIGHTS).unwrap();
    (i, install(ta, a), install(tb, b))
}

fn a_cycle_across_two_channels_is_collected<L: LockFamily>() {
    let ids = ObjectIds::new();
    let mut set = Set::<L>::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (c1, a1, b1) = open_in(&mut set, &ids, &mut ta, &mut tb);
    let (c2, a2, b2) = open_in(&mut set, &ids, &mut ta, &mut tb);

    let ch1 = set.channel(c1).unwrap();
    let ch2 = set.channel(c2).unwrap();
    ch1.send(&mut tb, b1, b"", &[Transfer::whole(b2)]).unwrap(); // b2 now in a1's inbox
    ch2.send(&mut ta, a2, b"", &[Transfer::whole(a1)]).unwrap(); // a1 now in b2's inbox

    // a1 and b2 are unreachable already: b1 and a2 can send into their inboxes, but nothing
    // can receive from them. The first close anywhere in the set finds that.
    let first = set.close(&mut ta, a2, no_sink).unwrap();
    assert_eq!(
        first,
        Collected {
            rounds: 1,
            closed: 2,
            messages: 2
        }
    );
    let ch1 = set.channel(c1).unwrap();
    let ch2 = set.channel(c2).unwrap();
    assert!(!ch1.is_open(Side::A) && !ch2.is_open(Side::B), "the cycle was collected");
    assert_eq!(ch1.references(Side::A), 0);
    assert_eq!(ch2.references(Side::B), 0);
    assert!(queued(ch1).is_empty() && queued(ch2).is_empty());
    assert!(ch1.status(&tb, b1).unwrap().peer_closed, "b1 sees its peer gone");

    let last = set.close(&mut tb, b1, no_sink).unwrap();
    assert_eq!(last, Collected::default());
    assert!(ta.is_empty() && tb.is_empty());
}

fn a_live_chain_is_not_collected<L: LockFamily>() {
    let ids = ObjectIds::new();
    let mut set = Set::<L>::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (c1, a1, b1) = open_in(&mut set, &ids, &mut ta, &mut tb);
    let (c2, a2, b2) = open_in(&mut set, &ids, &mut ta, &mut tb);

    // b2 travels in a1's inbox, and a1 stays in a table: the chain hangs off a live handle.
    set.channel(c1)
        .unwrap()
        .send(&mut tb, b1, b"", &[Transfer::whole(b2)])
        .unwrap();
    let got = set.close(&mut tb, b1, no_sink).unwrap();
    assert_eq!(got, Collected::default(), "reachable through a1");
    let got = set.close(&mut ta, a2, no_sink).unwrap();
    assert_eq!(got, Collected::default(), "b2's peer closing does not strand b2");
    assert!(set.channel(c2).unwrap().is_open(Side::B));

    // And it is really reachable: a1 receives b2.
    let (_, handles) = recv(set.channel(c1).unwrap(), &mut ta, a1).unwrap();
    assert_eq!(handles.len(), 1);
    assert_eq!(ta.get(handles[0]).unwrap().object, set.channel(c2).unwrap().id(Side::B));
}

fn a_cycle_through_three_channels_is_collected<L: LockFamily>() {
    let ids = ObjectIds::new();
    let mut set = Set::<L>::new();
    let mut t = HandleTable::<16>::new();
    let mut ends = [(0, Handle::from_raw(0), Handle::from_raw(0)); 3];
    for e in &mut ends {
        let (i, [a, b]) = set.create(&ids, ENDPOINT_RIGHTS).unwrap();
        *e = (i, install(&mut t, a), install(&mut t, b));
    }
    // Channel k's A endpoint travels in channel k+1's A inbox (sent from its B side).
    for k in 0..3 {
        let (next, _, next_b) = ends[(k + 1) % 3];
        let (_, a, _) = ends[k];
        set.channel(next)
            .unwrap()
            .send(&mut t, next_b, b"", &[Transfer::whole(a)])
            .unwrap();
    }
    let mut closed = 0;
    for (_, _, b) in ends {
        closed += set.close(&mut t, b, no_sink).unwrap().closed;
    }
    assert!(t.is_empty());
    for (i, _, _) in ends {
        assert!(!set.channel(i).unwrap().is_open(Side::A), "channel {i} leaked");
    }
    assert_eq!(closed, 3, "each A endpoint closed by the collector, once");
}

fn other_objects_in_a_collected_inbox_go_to_the_sink<L: LockFamily>() {
    let ids = ObjectIds::new();
    let mut set = Set::<L>::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (c1, a1, b1) = open_in(&mut set, &ids, &mut ta, &mut tb);
    let (c2, a2, b2) = open_in(&mut set, &ids, &mut ta, &mut tb);
    let ev = event(&ids, &mut tb, MOVABLE);
    let ev_id = tb.get(ev).unwrap().object;

    set.channel(c1)
        .unwrap()
        .send(&mut tb, b1, b"", &[Transfer::whole(b2), Transfer::whole(ev)])
        .unwrap();
    set.channel(c2)
        .unwrap()
        .send(&mut ta, a2, b"", &[Transfer::whole(a1)])
        .unwrap();

    let mut sunk = Vec::new();
    set.close(&mut ta, a2, |e| sunk.push(e)).unwrap();
    set.close(&mut tb, b1, |e| sunk.push(e)).unwrap();
    assert_eq!(sunk.len(), 1, "the event, exactly once");
    assert_eq!(sunk[0].object, ev_id);
}

fn a_finished_channels_slot_is_reused<L: LockFamily>() {
    let ids = ObjectIds::new();
    let mut set = ChannelSet::<L, 1, 2, 8, 2>::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (i, [a, b]) = set.create(&ids, ENDPOINT_RIGHTS).unwrap();
    assert_eq!(set.create(&ids, ENDPOINT_RIGHTS).err(), Some(SetFull));
    let (ha, hb) = (install(&mut ta, a), install(&mut tb, b));
    set.close(&mut ta, ha, no_sink).unwrap();
    assert_eq!(set.create(&ids, ENDPOINT_RIGHTS).err(), Some(SetFull), "B is still open");
    set.close(&mut tb, hb, no_sink).unwrap();
    let (j, [a2, b2]) = set.create(&ids, ENDPOINT_RIGHTS).unwrap();
    assert_eq!(i, j);
    set.release(a2, no_sink).unwrap();
    set.release(b2, no_sink).unwrap();
}

fn peer_closure_is_observed_after_draining<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);

    ch.send(&mut ta, ha, b"one", &[]).unwrap();
    ch.send(&mut ta, ha, b"two", &[]).unwrap();
    ch.send(&mut tb, hb, b"unread", &[]).unwrap();
    assert!(!ch.status(&tb, hb).unwrap().peer_closed);

    ch.close(&mut ta, ha, no_sink).unwrap();
    assert!(!ch.is_open(Side::A));

    let st = ch.status(&tb, hb).unwrap();
    assert!(st.peer_closed && !st.writable);
    assert_eq!(st.queued, 2, "what was sent before closing is still deliverable");

    // Sending into a closed peer moves nothing.
    let h = event(&ids, &mut tb, MOVABLE);
    let before = snapshot(&tb);
    assert_eq!(ch.send(&mut tb, hb, b"x", &[Transfer::whole(h)]), Err(Error::PeerClosed));
    assert_eq!(snapshot(&tb), before);

    assert_eq!(recv(&ch, &mut tb, hb).unwrap().0, b"one");
    assert_eq!(recv(&ch, &mut tb, hb).unwrap().0, b"two");
    // Distinct from Empty, and it stays that way.
    assert_eq!(recv(&ch, &mut tb, hb), Err(Error::PeerClosed));
    assert_eq!(recv(&ch, &mut tb, hb), Err(Error::PeerClosed));

    ch.close(&mut tb, hb, no_sink).unwrap();
    assert!(queued(&ch).is_empty());
}

fn undelivered_handles_are_handed_back_on_close<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);

    let to_b: Vec<Handle> = (0..3).map(|_| event(&ids, &mut ta, MOVABLE)).collect();
    let to_b_entries: Vec<Entry> = to_b.iter().map(|h| ta.get(*h).unwrap()).collect();
    ch.send(&mut ta, ha, b"m1", &[Transfer::whole(to_b[0]), Transfer::whole(to_b[1])])
        .unwrap();
    ch.send(&mut ta, ha, b"m2", &[Transfer::whole(to_b[2])])
        .unwrap();

    let to_a = event(&ids, &mut tb, MOVABLE);
    let to_a_entry = tb.get(to_a).unwrap();
    ch.send(&mut tb, hb, b"m3", &[Transfer::whole(to_a)])
        .unwrap();

    // B closes with two messages it never read. Their three handles come back, each
    // once; the message B sent to A is untouched.
    let mut returned = Vec::new();
    ch.close(&mut tb, hb, |e| returned.push(e)).unwrap();
    assert_eq!(returned, to_b_entries);
    assert_eq!(queued(&ch), vec![(Side::A, to_a_entry)]);

    // A still receives what B sent before it went.
    let (bytes, got) = recv(&ch, &mut ta, ha).unwrap();
    assert_eq!(bytes, b"m3");
    assert_eq!(ta.get(got[0]), Ok(to_a_entry));
    assert_eq!(recv(&ch, &mut ta, ha), Err(Error::PeerClosed));

    ch.close(&mut ta, ha, no_sink).unwrap();
    assert!(queued(&ch).is_empty(), "both ends closed: nothing may remain anywhere");
}

fn closing_cascades_through_an_in_flight_endpoint<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb, mut tc) =
        (HandleTable::<8>::new(), HandleTable::<8>::new(), HandleTable::<8>::new());
    let (c1, a1, b1) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let (c2, a2, b2) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tc);
    let a2_entry = ta.get(a2).unwrap();

    // C2's A end is in flight to C1's B end, which closes without reading it.
    c1.send(&mut ta, a1, b"", &[Transfer::whole(a2)]).unwrap();
    assert!(!c2.status(&tc, b2).unwrap().peer_closed, "an in-flight reference keeps it open");

    let mut returned = Vec::new();
    c1.close(&mut tb, b1, |e| returned.push(e)).unwrap();
    assert_eq!(returned, vec![a2_entry]);
    assert!(c2.is_open(Side::A), "handed back, not yet released");

    // Releasing the last reference closes it, and C2's other end finds out.
    c2.release(returned[0], no_sink).unwrap();
    assert!(!c2.is_open(Side::A));
    assert_eq!(recv(&c2, &mut tc, b2), Err(Error::PeerClosed));
}

fn an_endpoint_stays_open_while_any_duplicate_does<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<3>::new(), HandleTable::<8>::new());
    let (ch, ha, hb) = open::<L, 2, 3, 8>(&ids, &mut ta, &mut tb);

    let dup = ch
        .duplicate(&mut ta, ha, Rights::READ.union(Rights::WRITE))
        .unwrap();
    assert_eq!(ch.references(Side::A), 2);
    assert_eq!(ta.get(dup).unwrap().rights, Rights::READ.union(Rights::WRITE));

    // A full table refuses the duplicate and leaves the count alone.
    let _filler = event(&ids, &mut ta, Rights::READ);
    assert_eq!(
        ch.duplicate(&mut ta, ha, Rights::ALL),
        Err(Error::Endpoint(handle::Error::TableFull))
    );
    assert_eq!(ch.references(Side::A), 2);

    ch.close(&mut ta, ha, no_sink).unwrap();
    assert!(ch.is_open(Side::A));
    assert!(!ch.status(&tb, hb).unwrap().peer_closed);
    ch.send(&mut ta, dup, b"still", &[]).unwrap();

    ch.close(&mut ta, dup, no_sink).unwrap();
    assert!(!ch.is_open(Side::A));
    assert_eq!(recv(&ch, &mut tb, hb).unwrap().0, b"still");
    assert_eq!(recv(&ch, &mut tb, hb), Err(Error::PeerClosed));
}

fn releases_are_checked<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (ch, [a, b]) = Chan::<L>::new(&ids, ENDPOINT_RIGHTS);
    let (other, [oa, ob]) = Chan::<L>::new(&ids, ENDPOINT_RIGHTS);

    assert_eq!(ch.release(oa, no_sink), Err(Error::NotThisChannel));
    let not_a_channel = Entry {
        object: ids.next(),
        kind: ObjectType::Event,
        rights: Rights::ALL,
    };
    assert!(matches!(
        ch.release(not_a_channel, no_sink),
        Err(Error::Endpoint(handle::Error::WrongType { .. }))
    ));

    // The creator's entries could not be installed anywhere: releasing them is how the
    // endpoints get closed rather than held open for ever.
    ch.release(a, no_sink).unwrap();
    assert!(!ch.is_open(Side::A) && ch.is_open(Side::B));
    assert_eq!(ch.release(a, no_sink), Err(Error::NotHeld), "double release");
    ch.release(b, no_sink).unwrap();
    assert_eq!(ch.release(b, no_sink), Err(Error::NotHeld));

    other.release(oa, no_sink).unwrap();
    other.release(ob, no_sink).unwrap();
}

/// Channels used on their own, outside a [`ChannelSet`], have nobody to see a cycle across
/// them: the limitation the crate docs describe, pinned. Conservation still holds — every
/// reference is in exactly one place — but the place is a queue that only the other,
/// equally unreachable, endpoint could drain.
fn outside_a_set_a_cycle_across_two_channels_leaks<L: LockFamily>() {
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<8>::new());
    let (c1, a1, b1) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);
    let (c2, a2, b2) = open::<L, 2, 8, 8>(&ids, &mut ta, &mut tb);

    c1.send(&mut tb, b1, b"", &[Transfer::whole(b2)]).unwrap(); // b2 now in a1's inbox
    c2.send(&mut ta, a2, b"", &[Transfer::whole(a1)]).unwrap(); // a1 now in b2's inbox
    c2.close(&mut ta, a2, no_sink).unwrap();
    c1.close(&mut tb, b1, no_sink).unwrap();

    assert!(ta.is_empty() && tb.is_empty(), "no process holds anything");
    assert!(c1.is_open(Side::A) && c2.is_open(Side::B), "yet both are alive: leaked");
    assert_eq!(copies(c1.id(Side::A), &[], &[&c1, &c2]), 1);
    assert_eq!(copies(c2.id(Side::B), &[], &[&c1, &c2]), 1);
}

// ---- locking ------------------------------------------------------------------------

fn interrupts_enabled<A: Arch<IrqState = bool>>() -> bool {
    let state = A::irq_save();
    #[allow(unsafe_code)]
    // SAFETY: `state` came from the `irq_save` one line above, on this thread, and is
    // restored exactly once.
    unsafe {
        A::irq_restore(state)
    };
    state
}

/// Every operation, including its error paths, gives the interrupts back — and a close's
/// sink runs outside the critical section, where it may call into the same channel.
fn interrupts_come_back<L: LockFamily, A: Arch<IrqState = bool>>() {
    assert!(interrupts_enabled::<A>());
    let ids = ObjectIds::new();
    let (mut ta, mut tb) = (HandleTable::<8>::new(), HandleTable::<2>::new());
    let (ch, ha, hb) = open::<L, 2, 8, 2>(&ids, &mut ta, &mut tb);
    let _filler = event(&ids, &mut tb, Rights::READ);

    let h = event(&ids, &mut ta, MOVABLE);
    ch.send(&mut ta, ha, b"1", &[Transfer::whole(h)]).unwrap();
    ch.send(&mut ta, ha, b"2", &[]).unwrap();
    assert_eq!(ch.send(&mut ta, ha, b"3", &[]), Err(Error::Full));
    assert!(interrupts_enabled::<A>());
    assert!(matches!(recv(&ch, &mut tb, hb), Err(Error::NoRoom { .. })));
    assert!(interrupts_enabled::<A>());
    assert_eq!(recv(&ch, &mut ta, ha), Err(Error::Empty));
    assert!(interrupts_enabled::<A>());

    let mut returned = 0;
    ch.close(&mut tb, hb, |_| {
        // On `Irq` a sink run under the lock would stop the CPU here (a panic on the
        // mock); on `Spin` it would deadlock. Neither happens, and interrupts are on.
        assert!(interrupts_enabled::<A>());
        assert!(!ch.is_open(Side::B));
        returned += 1;
    })
    .unwrap();
    assert_eq!(returned, 1);
    assert!(interrupts_enabled::<A>());
}

#[test]
fn interrupts_come_back_full() {
    let _s = serial();
    interrupts_come_back::<Full, MockFull>();
}

#[test]
fn interrupts_come_back_tiny() {
    let _s = serial();
    interrupts_come_back::<Tiny, MockTiny>();
}

/// Only the full profile has more than one thread of execution to race with.
#[test]
fn a_concurrent_sender_and_receiver_lose_and_reorder_nothing_full() {
    let _s = serial();
    const COUNT: u64 = 3000;
    const FIRST: u64 = 1 << 40;

    let ids = ObjectIds::new();
    let (ch, [a, b]) = Channel::<Full, 4, 8, 1>::new(&ids, ENDPOINT_RIGHTS);
    let ch = &ch;

    // Set when a thread ends by any route, including a panic. Without them a sender that
    // died before closing would leave the receiver waiting for a `PeerClosed` that never
    // comes — or a receiver that died would leave the sender retrying `Full` — and a
    // broken channel would hang the suite rather than fail it.
    struct Finished<'a>(&'a AtomicBool);
    impl Drop for Finished<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let sender_finished = &AtomicBool::new(false);
    let receiver_finished = &AtomicBool::new(false);

    std::thread::scope(|s| {
        s.spawn(move || {
            let _finished = Finished(sender_finished);
            let mut ta = HandleTable::<4>::new();
            let ha = install(&mut ta, a);
            for i in 0..COUNT {
                let obj = ObjectId::from_raw(FIRST + i);
                let h = ta.insert(obj, ObjectType::Event, MOVABLE).unwrap();
                loop {
                    match ch.send(&mut ta, ha, &i.to_le_bytes(), &[Transfer::whole(h)]) {
                        Ok(()) => break,
                        Err(Error::Full) if receiver_finished.load(Ordering::SeqCst) => {
                            panic!("the receiver ended with messages still to send")
                        }
                        Err(Error::Full) => std::thread::yield_now(),
                        Err(e) => panic!("{e:?}"),
                    }
                }
            }
            ch.close(&mut ta, ha, no_sink).unwrap();
            assert!(ta.is_empty());
        });
        s.spawn(move || {
            let _finished = Finished(receiver_finished);
            let mut tb = HandleTable::<4>::new();
            let hb = install(&mut tb, b);
            let mut expected = 0u64;
            let mut bytes = [0u8; 8];
            let mut hs = [Handle::from_raw(0); 1];
            loop {
                let finished_before = sender_finished.load(Ordering::SeqCst);
                match ch.receive(&mut tb, hb, &mut bytes, &mut hs) {
                    Ok(r) => {
                        assert_eq!((r.bytes, r.handles), (8, 1));
                        assert_eq!(u64::from_le_bytes(bytes), expected);
                        let e = tb.close(hs[0]).unwrap();
                        assert_eq!(e.object, ObjectId::from_raw(FIRST + expected));
                        expected += 1;
                    }
                    // The flag was read before this receive, and once it is set the
                    // sender sends and closes nothing more, so `Empty` is final.
                    Err(Error::Empty) if finished_before => {
                        panic!("the sender ended without closing its endpoint")
                    }
                    Err(Error::Empty) => std::thread::yield_now(),
                    Err(Error::PeerClosed) => break,
                    Err(e) => panic!("{e:?}"),
                }
            }
            assert_eq!(expected, COUNT, "PeerClosed only after everything was drained");
            ch.close(&mut tb, hb, no_sink).unwrap();
        });
    });
    assert!(queued_any(ch).is_empty());

    // Two threads saving and restoring one process-wide mock flag can interleave and
    // leave it cleared; put it back for the tests that assert on it.
    #[allow(unsafe_code)]
    // SAFETY: the mock's flag is a plain atomic with no CPU behind it; setting it to
    // "enabled" with no guard outstanding (both threads have joined) is the state every
    // test starts from.
    unsafe {
        MockFull::irq_restore(true)
    };
}

fn queued_any<L: LockFamily, const D: usize, const B: usize, const H: usize>(
    ch: &Channel<L, D, B, H>,
) -> Vec<(Side, Entry)> {
    let mut v = Vec::new();
    ch.for_each_queued(|s, e| v.push((s, e)));
    v
}

// ---- conservation under a randomised workload ---------------------------------------

both! {
    every_reference_is_in_exactly_one_place => every_reference_is_in_exactly_one_place_full,
        every_reference_is_in_exactly_one_place_tiny;
}

/// Three processes, a handful of channels and events, and a long random sequence of
/// every operation — most of which fail, because the handles and buffers are chosen at
/// random. After every step, every entry in every table and every queue is counted, and
/// every object must be found exactly as many times as it has references.
///
/// It also checks the stronger "exactly where it was" property: the test tracks each
/// process's handle *values*, updates them only on success, and requires every tracked
/// value to still resolve and the table to hold nothing else.
struct World<L: LockFamily> {
    ids: ObjectIds,
    chans: Vec<Chan<L>>,
    tables: Vec<HandleTable<8>>,
    held: Vec<Vec<Handle>>,
    /// Outstanding references per event object.
    events: BTreeMap<ObjectId, u32>,
    rng: u64,
    outcomes: BTreeMap<&'static str, usize>,
}

impl<L: LockFamily> World<L> {
    fn new(seed: u64) -> Self {
        World {
            ids: ObjectIds::new(),
            chans: Vec::new(),
            tables: (0..3).map(|_| HandleTable::new()).collect(),
            held: vec![Vec::new(); 3],
            events: BTreeMap::new(),
            rng: seed | 1,
            outcomes: BTreeMap::new(),
        }
    }

    fn rand(&mut self, n: usize) -> usize {
        // xorshift64: deterministic, so a failure reproduces from its seed.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng % n.max(1) as u64) as usize
    }

    fn tally(&mut self, what: &'static str) {
        *self.outcomes.entry(what).or_default() += 1;
    }

    fn chan_of(&self, e: Entry) -> Option<usize> {
        if e.kind != ObjectType::Channel {
            return None;
        }
        self.chans
            .iter()
            .position(|c| c.side_of(e.object).is_some())
    }

    /// Release references nobody can receive, as an object store would: iteratively.
    fn dispose(&mut self, mut work: Vec<Entry>) {
        while let Some(e) = work.pop() {
            match self.chan_of(e) {
                Some(c) => self.chans[c].release(e, |x| work.push(x)).unwrap(),
                None => {
                    let refs = self.events.get_mut(&e.object).unwrap();
                    *refs = refs.checked_sub(1).unwrap();
                }
            }
        }
    }

    fn random_handle(&mut self, t: usize) -> Option<(usize, Handle)> {
        if self.held[t].is_empty() {
            return None;
        }
        let i = self.rand(self.held[t].len());
        Some((i, self.held[t][i]))
    }

    fn random_mask(&mut self) -> Rights {
        [
            Rights::ALL,
            Rights::READ,
            MOVABLE,
            ENDPOINT_RIGHTS.without(Rights::TRANSFER),
        ][self.rand(4)]
    }

    /// A handle to use as an endpoint: usually one that is, occasionally anything, so
    /// the wrong-type paths stay exercised without drowning the interesting ones.
    fn random_endpoint(&mut self, t: usize) -> Option<Handle> {
        let endpoints: Vec<Handle> = self.held[t]
            .iter()
            .copied()
            .filter(|h| {
                self.tables[t]
                    .get(*h)
                    .is_ok_and(|e| e.kind == ObjectType::Channel)
            })
            .collect();
        if endpoints.is_empty() || self.rand(16) == 0 {
            return self.random_handle(t).map(|(_, h)| h);
        }
        Some(endpoints[self.rand(endpoints.len())])
    }

    /// The channel an operation on `h` in table `t` should address: its own if it is an
    /// endpoint, otherwise any, so the wrong-channel paths are exercised too.
    fn chan_for(&mut self, t: usize, h: Handle) -> Option<usize> {
        if self.chans.is_empty() {
            return None;
        }
        let e = self.tables[t].get(h).unwrap();
        Some(match self.chan_of(e) {
            Some(c) if self.rand(16) != 0 => c,
            _ => self.rand(self.chans.len()),
        })
    }

    fn step(&mut self) {
        let t = self.rand(self.tables.len());
        match self.rand(10) {
            0 => {
                if self.held[t].len() >= 5 {
                    return;
                }
                let rights = if self.rand(4) == 0 {
                    Rights::READ
                } else {
                    MOVABLE
                };
                let id = self.ids.next();
                if let Ok(h) = self.tables[t].insert(id, ObjectType::Event, rights) {
                    self.events.insert(id, 1);
                    self.held[t].push(h);
                }
            }
            1 => {
                let open = self
                    .chans
                    .iter()
                    .filter(|c| c.is_open(Side::A) || c.is_open(Side::B))
                    .count();
                if open >= 4 || self.chans.len() >= 64 {
                    return;
                }
                let rights = [
                    ENDPOINT_RIGHTS,
                    ENDPOINT_RIGHTS,
                    ENDPOINT_RIGHTS.without(Rights::TRANSFER),
                    ENDPOINT_RIGHTS.without(Rights::WRITE),
                ][self.rand(4)];
                let (ch, entries) = Chan::<L>::new(&self.ids, rights);
                self.chans.push(ch);
                for e in entries {
                    let t = self.rand(self.tables.len());
                    match self.tables[t].insert(e.object, e.kind, e.rights) {
                        Ok(h) => self.held[t].push(h),
                        Err(_) => self.dispose(vec![e]),
                    }
                }
            }
            2..=4 => {
                let Some(ep) = self.random_endpoint(t) else {
                    return;
                };
                let Some(c) = self.chan_for(t, ep) else {
                    return;
                };
                let mut list = Vec::new();
                let count = if self.rand(16) == 0 { 3 } else { self.rand(3) };
                for _ in 0..count {
                    if let Some((_, h)) = self.random_handle(t) {
                        let mask = if self.rand(4) == 0 {
                            self.random_mask()
                        } else {
                            Rights::ALL
                        };
                        list.push(Transfer::narrowed(h, mask));
                    }
                }
                let len = if self.rand(16) == 0 { 9 } else { self.rand(9) };
                match self.chans[c].send(&mut self.tables[t], ep, &[0xA5; 9][..len], &list) {
                    Ok(()) => {
                        self.tally("send ok");
                        for tr in &list {
                            let at = self.held[t].iter().position(|h| *h == tr.handle).unwrap();
                            self.held[t].swap_remove(at);
                        }
                    }
                    Err(e) => {
                        // Failures discovered only after validation passed are the ones
                        // a move-then-check send would get wrong; count them separately
                        // so the run can prove it reached them.
                        match e {
                            Error::Full if !list.is_empty() => self.tally("full, with handles"),
                            Error::PeerClosed if !list.is_empty() => {
                                self.tally("peer closed, with handles")
                            }
                            _ => {}
                        }
                        self.tally(error_name(e));
                    }
                }
            }
            5 | 6 => {
                let Some(ep) = self.random_endpoint(t) else {
                    return;
                };
                let Some(c) = self.chan_for(t, ep) else {
                    return;
                };
                let mut bytes = [0u8; 8];
                let mut hs = [Handle::from_raw(0); 2];
                let hn = if self.rand(8) == 0 { self.rand(2) } else { 2 };
                match self.chans[c].receive(&mut self.tables[t], ep, &mut bytes, &mut hs[..hn]) {
                    Ok(r) => {
                        self.tally("receive ok");
                        self.held[t].extend_from_slice(&hs[..r.handles]);
                    }
                    Err(e) => self.tally(error_name(e)),
                }
            }
            7 => {
                let Some((i, h)) = self.random_handle(t) else {
                    return;
                };
                let e = self.tables[t].get(h).unwrap();
                match self.chan_of(e) {
                    // Endpoints are closed less often than events, or every channel dies
                    // young and the run is mostly `PeerClosed`.
                    Some(_) if self.rand(3) != 0 => {}
                    Some(c) => {
                        let mut work = Vec::new();
                        self.chans[c]
                            .close(&mut self.tables[t], h, |x| work.push(x))
                            .unwrap();
                        self.held[t].swap_remove(i);
                        self.tally("close endpoint");
                        self.dispose(work);
                    }
                    None => {
                        self.tables[t].close(h).unwrap();
                        self.held[t].swap_remove(i);
                        self.dispose(vec![e]);
                    }
                }
            }
            8 if self.held[t].len() < 6 => {
                let Some((_, h)) = self.random_handle(t) else {
                    return;
                };
                let e = self.tables[t].get(h).unwrap();
                if let Some(c) = self.chan_of(e) {
                    let mask = if self.rand(4) == 0 {
                        self.random_mask()
                    } else {
                        Rights::ALL
                    };
                    match self.chans[c].duplicate(&mut self.tables[t], h, mask) {
                        Ok(d) => self.held[t].push(d),
                        Err(e) => self.tally(error_name(e)),
                    }
                }
            }
            _ => {}
        }
    }

    fn check(&self) {
        let mut seen: BTreeMap<ObjectId, u32> = BTreeMap::new();
        for (table, held) in self.tables.iter().zip(&self.held) {
            assert_eq!(table.len(), held.len(), "a table holds something untracked");
            for h in held {
                let e = table
                    .get(*h)
                    .unwrap_or_else(|err| panic!("{h:?} moved: {err:?}"));
                *seen.entry(e.object).or_default() += 1;
            }
        }
        for ch in &self.chans {
            ch.for_each_queued(|_, e| *seen.entry(e.object).or_default() += 1);
        }
        for ch in &self.chans {
            for side in [Side::A, Side::B] {
                let refs = ch.references(side);
                let found = seen.remove(&ch.id(side)).unwrap_or(0);
                assert_eq!(found, refs, "endpoint {:?} copies vs references", ch.id(side));
                assert_eq!(ch.is_open(side), refs > 0);
            }
        }
        for (id, refs) in &self.events {
            assert_eq!(seen.remove(id).unwrap_or(0), *refs, "event {id:?}");
        }
        assert!(seen.is_empty(), "entries naming objects nobody created: {seen:?}");
    }

    fn teardown(&mut self) {
        for t in 0..self.tables.len() {
            while let Some(&h) = self.held[t].last() {
                let e = self.tables[t].get(h).unwrap();
                match self.chan_of(e) {
                    Some(c) => {
                        let mut work = Vec::new();
                        self.chans[c]
                            .close(&mut self.tables[t], h, |x| work.push(x))
                            .unwrap();
                        self.held[t].pop();
                        self.dispose(work);
                    }
                    None => {
                        self.tables[t].close(h).unwrap();
                        self.held[t].pop();
                        self.dispose(vec![e]);
                    }
                }
                self.check();
            }
        }
    }
}

fn error_name(e: Error) -> &'static str {
    match e {
        Error::Endpoint(_) => "endpoint",
        Error::NotThisChannel => "not this channel",
        Error::Closed => "closed",
        Error::TooLarge { .. } => "too large",
        Error::Transfer { .. } => "transfer",
        Error::DuplicateTransfer { .. } => "duplicate transfer",
        Error::WouldCycle { .. } => "would cycle",
        Error::Full => "full",
        Error::PeerClosed => "peer closed",
        Error::Empty => "empty",
        Error::BufferTooSmall { .. } => "buffer too small",
        Error::NoRoom { .. } => "no room",
        Error::TooManyRefs => "too many refs",
        Error::NotHeld => "not held",
    }
}

fn every_reference_is_in_exactly_one_place<L: LockFamily>() {
    let mut totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for seed in [0x5EED, 0xC0FFEE, 0xDEAD_BEEF, 42, 7_777_777] {
        let mut w = World::<L>::new(seed);
        for _ in 0..4000 {
            w.step();
            w.check();
        }
        w.teardown();
        assert!(w.tables.iter().all(|t| t.is_empty()));
        w.check();
        for (k, v) in w.outcomes {
            *totals.entry(k).or_default() += v;
        }
    }
    // The run is only evidence if the interesting paths were actually taken.
    for path in [
        "send ok",
        "receive ok",
        "close endpoint",
        "full",
        "no room",
        "transfer",
        "would cycle",
        "peer closed",
        "empty",
        "buffer too small",
        "full, with handles",
        "peer closed, with handles",
    ] {
        assert!(
            totals.get(path).copied().unwrap_or(0) > 0,
            "never exercised: {path}: {totals:?}"
        );
    }
}
