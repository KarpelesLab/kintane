//! Host tests for epoch-based reclamation.
//!
//! Nodes live in an arena that is never freed, and "reclaiming" one writes a poison value
//! into it. So a node reclaimed while a reader still holds it is not undefined behaviour
//! here, which a real free would be: the reader sees the poison and the test fails.
//!
//! Every test holds `serial()`, because the reclaim function is a plain `fn` and counts
//! through a static.

use std::boxed::Box;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::vec::Vec;

use hal::mock::{MOCK_CPUS, MockFull, MockTiny, set_cpu};

use super::*;
use crate::testing::serial;
use crate::{Irq, Spin};

const POISON: u64 = 0xdead_dead_dead_dead;

struct Node {
    value: AtomicU64,
}

static RECLAIMED: AtomicUsize = AtomicUsize::new(0);

/// The reclaim function every test uses: poison the node, count it.
unsafe fn poison(p: *mut ()) {
    // SAFETY: every pointer retired in these tests points into an arena that is never
    // freed.
    let node = unsafe { &*(p as *const Node) };
    node.value.store(POISON, Ordering::SeqCst);
    RECLAIMED.fetch_add(1, Ordering::SeqCst);
}

/// `n` nodes holding their own index, for the life of the test binary. Leaked, like every
/// collector and pointer the threaded tests share, so that each thread holds `'static`
/// references.
fn arena(n: usize) -> &'static [Node] {
    let nodes: Vec<Node> = (0..n)
        .map(|i| Node {
            value: AtomicU64::new(i as u64),
        })
        .collect();
    Box::leak(nodes.into_boxed_slice())
}

fn leak<T>(t: T) -> &'static T {
    Box::leak(Box::new(t))
}

fn node(nodes: &'static [Node], i: usize) -> *mut Node {
    core::ptr::from_ref(&nodes[i]).cast_mut()
}

fn erased(nodes: &'static [Node], i: usize) -> *mut () {
    node(nodes, i).cast()
}

type Full<const BAG: usize> = Collector<MockFull, Spin<MockFull>, MOCK_CPUS, BAG>;

#[test]
fn a_node_is_reclaimed_two_epochs_after_retirement_and_no_sooner() {
    let _s = serial();
    RECLAIMED.store(0, Ordering::SeqCst);
    let nodes = arena(1);
    let c: Full<8> = Collector::new();

    let g = c.pin().unwrap();
    // SAFETY: the node is in no structure, and `poison` meets the contract.
    unsafe { c.retire(&g, erased(nodes, 0), poison) }.unwrap();
    // The guard is at the retirement epoch, so it allows exactly one advance.
    assert_eq!(c.collect(&g), 0, "one epoch later is too soon");
    assert_eq!(c.epoch(), 1);
    assert_eq!(c.collect(&g), 0, "and the guard holds the second advance");
    drop(g);
    assert_eq!(nodes[0].value.load(Ordering::SeqCst), 0);

    let g = c.pin().unwrap();
    assert_eq!(c.collect(&g), 1, "two epochs: reclaimed");
    drop(g);
    assert_eq!(nodes[0].value.load(Ordering::SeqCst), POISON);
    assert_eq!(
        c.stats(),
        Stats {
            epoch: 2,
            retired: 1,
            reclaimed: 1,
            pending: 0
        }
    );
}

#[test]
fn a_reader_keeps_a_node_alive_across_a_concurrent_unlink() {
    let _s = serial();
    RECLAIMED.store(0, Ordering::SeqCst);
    let nodes = arena(2);
    let c: &'static Full<8> = leak(Collector::new());
    // SAFETY: both nodes live in the arena, which is never freed.
    let head = leak(unsafe { EpochPtr::new(node(nodes, 0), c) });

    let loaded = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let reader = {
        let (loaded, release) = (Arc::clone(&loaded), Arc::clone(&release));
        thread::spawn(move || {
            set_cpu(1);
            let g = c.pin().unwrap();
            let n = head.load(&g).unwrap();
            loaded.wait();
            // The writer unlinks this node and tries hard to reclaim it meanwhile.
            release.wait();
            let seen = n.value.load(Ordering::SeqCst);
            drop(g);
            seen
        })
    };

    loaded.wait();
    let g = c.pin().unwrap();
    // SAFETY: this thread is the only writer; node 1 lives in the arena.
    unsafe { head.replace(node(nodes, 1), poison, &g) }.unwrap();
    drop(g);
    for _ in 0..STALL_ATTEMPTS * 2 {
        assert_eq!(c.flush().err().map(|(cpu, _)| cpu), Some(1), "CPU 1 holds the epoch");
    }
    assert_eq!(RECLAIMED.load(Ordering::SeqCst), 0, "reclaimed under a live reader");
    let stall = c.stall().expect("a reader pinned this long is reported");
    assert_eq!(stall.cpu, 1);
    assert!(stall.attempts >= STALL_ATTEMPTS);

    release.wait();
    assert_eq!(reader.join().unwrap(), 0, "the reader saw its node intact");
    assert_eq!(c.flush(), Ok(1));
    assert_eq!(nodes[0].value.load(Ordering::SeqCst), POISON);
    assert!(c.stall().is_none(), "an advance clears the report");
}

#[test]
fn a_stalled_participant_is_reported_and_a_full_bag_refuses() {
    let _s = serial();
    RECLAIMED.store(0, Ordering::SeqCst);
    const BAG: usize = 4;
    let nodes = arena(BAG + 1);
    let c: &'static Full<BAG> = leak(Collector::new());

    let pinned = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let reader = {
        let (pinned, release) = (Arc::clone(&pinned), Arc::clone(&release));
        thread::spawn(move || {
            set_cpu(2);
            let g = c.pin().unwrap();
            pinned.wait();
            release.wait();
            drop(g);
        })
    };
    pinned.wait();

    // The reader is pinned at epoch 0, which allows one advance and holds every one after.
    // Enough failures to count as a stall before the bag fills.
    for _ in 0..STALL_ATTEMPTS {
        let _ = c.try_advance();
    }
    let g = c.pin().unwrap();
    for i in 0..BAG {
        // SAFETY: arena nodes in no structure.
        unsafe { c.retire(&g, erased(nodes, i), poison) }.unwrap();
    }
    // SAFETY: as above.
    let refused = unsafe { c.retire(&g, erased(nodes, BAG), poison) };
    drop(g);
    match refused {
        Err(RetireError::Stalled(s)) => {
            assert_eq!(s.cpu, 2);
            assert_eq!(s.pinned_at, 0);
            assert!(s.attempts >= STALL_ATTEMPTS);
        }
        other => panic!("a full bag behind a stalled CPU must say so, got {other:?}"),
    }
    assert_eq!(c.stats().pending, BAG as u64, "the refused node was not taken");
    assert_eq!(RECLAIMED.load(Ordering::SeqCst), 0);

    release.wait();
    reader.join().unwrap();
    assert_eq!(c.flush(), Ok(BAG));
    assert_eq!(nodes[BAG].value.load(Ordering::SeqCst), BAG as u64, "still the caller's");
}

#[test]
fn readers_on_every_cpu_never_see_a_reclaimed_node() {
    let _s = serial();
    RECLAIMED.store(0, Ordering::SeqCst);
    const WRITES: usize = 20_000;
    let nodes = arena(WRITES + 1);
    let c: &'static Full<16> = leak(Collector::new());
    // SAFETY: arena nodes, which are never freed.
    let head = leak(unsafe { EpochPtr::new(node(nodes, 0), c) });
    let stop = leak(AtomicBool::new(false));
    let poisoned = leak(AtomicUsize::new(0));
    let reads = leak(AtomicUsize::new(0));

    let readers: Vec<_> = (1..MOCK_CPUS)
        .map(|cpu| {
            thread::spawn(move || {
                set_cpu(cpu);
                while !stop.load(Ordering::Relaxed) {
                    let g = c.pin().unwrap();
                    let n = head.load(&g).unwrap();
                    let first = n.value.load(Ordering::SeqCst);
                    std::hint::spin_loop();
                    let again = n.value.load(Ordering::SeqCst);
                    if first == POISON || again == POISON {
                        poisoned.fetch_add(1, Ordering::Relaxed);
                    }
                    drop(g);
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    for i in 1..=WRITES {
        let g = c.pin().unwrap();
        loop {
            // SAFETY: the only writer; an arena node.
            match unsafe { head.replace(node(nodes, i), poison, &g) } {
                Ok(()) => break,
                // Readers pin and unpin constantly: a full bag clears as soon as they move.
                Err(RetireError::Full | RetireError::Stalled(_)) => thread::yield_now(),
                Err(e) => panic!("{e:?}"),
            }
        }
        c.collect(&g);
        drop(g);
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    while c.stats().pending > 0 {
        c.flush().unwrap();
    }

    assert_eq!(poisoned.load(Ordering::Relaxed), 0, "a reader saw a reclaimed node");
    assert!(reads.load(Ordering::Relaxed) > 0);
    let s = c.stats();
    assert_eq!(s.retired, WRITES as u64);
    assert_eq!(s.reclaimed, WRITES as u64);
    assert_eq!(RECLAIMED.load(Ordering::SeqCst), WRITES);
}

#[test]
fn guards_nest_and_only_the_outermost_unpins() {
    let _s = serial();
    let c: Full<4> = Collector::new();
    let outer = c.pin().unwrap();
    let inner = c.pin().unwrap();
    drop(inner);
    // Still pinned at epoch 0: one advance to 1 is allowed, the next is not.
    assert_eq!(c.try_advance(), Ok(1));
    assert_eq!(c.try_advance(), Err((0, 0)));
    drop(outer);
    assert_eq!(c.try_advance(), Ok(2));
}

#[test]
fn a_cpu_without_a_slot_cannot_pin() {
    let _s = serial();
    let c: Collector<MockFull, Spin<MockFull>, 2, 4> = Collector::sized();
    set_cpu(3);
    let refused = c.pin().is_none();
    set_cpu(0);
    assert!(refused, "CPU 3 must not borrow another CPU's participant");
    assert!(c.pin().is_some());
}

#[test]
fn a_uniprocessor_collector_reclaims_after_the_last_unpin() {
    let _s = serial();
    RECLAIMED.store(0, Ordering::SeqCst);
    let nodes = arena(1);
    let c: Collector<MockTiny, Irq<MockTiny>, 1, 4> = Collector::uniprocessor();
    let g = c.pin().unwrap();
    // SAFETY: an arena node in no structure.
    unsafe { c.retire(&g, erased(nodes, 0), poison) }.unwrap();
    // Pinned at the retirement epoch: this CPU allows one advance and then holds the next.
    assert_eq!(c.collect(&g), 0);
    assert_eq!(c.collect(&g), 0);
    drop(g);
    assert_eq!(c.flush(), Ok(1));
    assert_eq!(RECLAIMED.load(Ordering::SeqCst), 1);
}

#[test]
fn a_guard_from_another_collector_is_refused() {
    let _s = serial();
    let nodes = arena(2);
    let a: Full<4> = Collector::new();
    let b: Full<4> = Collector::new();
    // SAFETY: arena nodes.
    let head = unsafe { EpochPtr::new(node(nodes, 0), &a) };
    let gb = b.pin().unwrap();
    assert!(head.load(&gb).is_none());
    // SAFETY: the only writer; an arena node.
    let refused = unsafe { head.replace(node(nodes, 1), poison, &gb) };
    assert_eq!(refused, Err(RetireError::ForeignGuard));
    drop(gb);
    let ga = a.pin().unwrap();
    assert_eq!(head.load(&ga).unwrap().value.load(Ordering::SeqCst), 0, "unchanged");
}
