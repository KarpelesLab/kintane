//! Fuzzing the parsers that read untrusted input.
//!
//! Every one of these parsers is handed bytes the kernel did not write: a device tree from
//! firmware, ACPI tables from firmware, an ELF from a disk, a boot protocol structure from
//! a loader, a menu file from the boot medium, PCI configuration space from a device, and
//! a virtqueue the device writes into while the driver reads it. A parser that panics on
//! any of them is a kernel that dies at boot with no console; a parser that loops is a
//! machine that never boots at all.
//!
//! # What this checks
//!
//! For every target, on every input:
//!
//! * **It answers.** Either a value or an error, never a panic, and never an abort.
//! * **It finishes.** The driver watchdogs each iteration, so a loop is a failure with a seed
//!   rather than a run that never ends.
//! * **It stays inside its buffer.** Rust's bounds checks make an out-of-bounds read a panic, which
//!   is the first rule; `#![deny(unsafe_code)]` here keeps that true of the harness itself.
//!
//! What it does not check is whether the answer is *right*. That is what the parsers' own
//! tests are for, and they are the ones with fixtures whose contents are known.
//!
//! # Why structure-aware, and why a seed corpus
//!
//! Coverage-guided fuzzing (libFuzzer, AFL) needs the compiler to instrument every branch
//! and a runtime to read the counters back. kbuild drives `rustc` directly, has no
//! sanitizer runtime, and the kernel crates are `no_std`; instrumentation is not available
//! here. Random bytes would then spend their whole budget being rejected by the first
//! length check, which tests one branch very thoroughly.
//!
//! So the generators do what coverage cannot: they know the shape of what they produce.
//! Two kinds, by format:
//!
//! * **Built** — the boot protocol's tags, ELF, a menu file, PCI configuration space, a virtqueue.
//!   Small enough to construct: the generator builds a structurally valid one from the seed, then
//!   corrupts it.
//! * **Seeded** — device trees, ACPI tables, a relocatable module. Formats with internal offsets,
//!   string tables and checksums, where a generator that built one from nothing would be a second
//!   implementation of the thing under test. These start from real artifacts in
//!   `corpus/<target>/seed-*.bin` and mutate them.
//!
//! Mutations are structure-aware in both cases: [`Mutator`] flips bits, but it also
//! rewrites whole little-endian words, which is what a length, an offset or a count is in
//! every one of these formats. A byte flip inside a 32-bit length usually makes it absurd;
//! replacing the word with another plausible length is what reaches the code after it.
//!
//! # The corpus
//!
//! `corpus/<target>/` holds the seeds and every input that ever failed, minimised.
//! `kbuild fuzz --smoke` replays the whole directory in seconds, so a crasher that is
//! fixed once cannot come back unnoticed. The corpus is committed: it is the part of a
//! fuzzing campaign worth keeping.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub mod targets;

/// A seeded generator. xorshift64*, which is small, has no state to carry between runs and
/// is exactly reproducible from its seed — the property that matters here, because a
/// failure is reported as a seed and an iteration and has to be reproducible from them.
///
/// Not for anything that needs unpredictability.
pub struct Rng(u64);

impl Rng {
    /// A zero seed would make xorshift produce zeros for ever, so it is replaced.
    pub fn new(seed: u64) -> Rng {
        Rng(if seed == 0 {
            0x2545_f491_4f6c_dd1d
        } else {
            seed
        })
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// A number below `n`. Zero when `n` is zero, so a caller need not special-case an
    /// empty range.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// True one time in `n`.
    pub fn one_in(&mut self, n: u64) -> bool {
        n != 0 && self.next_u64() % n == 0
    }

    /// One of `choices`, or the first when it is empty.
    pub fn pick<'c, T>(&mut self, choices: &'c [T]) -> &'c T {
        &choices[self.below(choices.len())]
    }

    /// A length that is interesting rather than uniform: the boundaries a length check is
    /// written against, and only sometimes something in between.
    pub fn interesting_len(&mut self, max: usize) -> usize {
        let edges = [0usize, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 255, 256];
        if self.one_in(2) {
            let v = *self.pick(&edges);
            v.min(max)
        } else {
            self.below(max.saturating_add(1))
        }
    }

    /// A word that a length, offset or count field is often wrong in an interesting way.
    pub fn interesting_u32(&mut self) -> u32 {
        let edges: [u32; 12] = [
            0,
            1,
            2,
            4,
            8,
            0x7f,
            0x80,
            0xff,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            0xffff_ffff,
        ];
        if self.one_in(3) {
            self.next_u32()
        } else {
            *self.pick(&edges)
        }
    }
}

/// Corruptions applied to bytes that are already structurally valid.
///
/// Every one keeps the buffer the same length or shortens it, so a mutated input stays a
/// plausible one: a parser is reached through its length checks, not around them.
pub struct Mutator;

impl Mutator {
    /// Apply between one and four mutations to `bytes`.
    pub fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>) {
        let rounds = 1 + rng.below(4);
        for _ in 0..rounds {
            Mutator::once(rng, bytes);
        }
    }

    fn once(rng: &mut Rng, bytes: &mut Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        match rng.below(6) {
            // A single bit, which is what a corrupted medium does.
            0 => {
                let i = rng.below(bytes.len());
                bytes[i] ^= 1 << rng.below(8);
            }
            // A whole byte to an edge value.
            1 => {
                let i = rng.below(bytes.len());
                bytes[i] = *rng.pick(&[0x00u8, 0x01, 0x7f, 0x80, 0xff]);
            }
            // A little-endian word: a length, an offset or a count in every format here.
            2 | 3 => {
                if bytes.len() >= 4 {
                    let i = rng.below(bytes.len() - 3);
                    let v = rng.interesting_u32();
                    bytes[i..i + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
            // The same, big-endian: a device tree is big-endian throughout.
            4 => {
                if bytes.len() >= 4 {
                    let i = rng.below(bytes.len() - 3);
                    let v = rng.interesting_u32();
                    bytes[i..i + 4].copy_from_slice(&v.to_be_bytes());
                }
            }
            // Truncation, which is the one every one of these parsers must survive and the
            // one a bit flip never produces.
            _ => {
                let keep = rng.below(bytes.len());
                bytes.truncate(keep);
            }
        }
    }
}

/// One thing that can be fuzzed.
///
/// `generate` produces an input from a seed, and `run` feeds it to the code under test.
/// `run` must not panic for any input: that is the whole property. It returns nothing,
/// because whether the parse succeeded is not what is being checked.
pub struct Target {
    pub name: &'static str,
    /// What this target reads, for the report and the documentation.
    pub what: &'static str,
    /// Seeds are files under `corpus/<name>/`; a target whose generator builds its own
    /// input from nothing needs none.
    pub needs_seeds: bool,
    pub generate: fn(&mut Rng, seeds: &[Vec<u8>]) -> Vec<u8>,
    pub run: fn(&[u8]),
    /// Whether the parser takes `input` past its top-level check: the magic, the header,
    /// the outer length.
    ///
    /// Not a correctness property. It is how a campaign shows it tested the parser rather
    /// than only its rejection of garbage — a fuzzer whose inputs all fail the first length
    /// check has spent its whole budget on one branch. `None` for a target that is not a
    /// parser with a reject gate: PCI enumeration, a virtqueue and syscall dispatch answer
    /// every input, so there is no rate to report.
    pub accepts: Option<fn(&[u8]) -> bool>,
}

/// Every target, in one table so the driver, the smoke run and the documentation agree.
pub const TARGETS: &[Target] = targets::TARGETS;

/// The target of that name.
pub fn target(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|t| t.name == name)
}

/// Shrink `input` while `fails` still holds, so what lands in the corpus is the smallest
/// input that still shows the bug.
///
/// Two passes, each repeated while it helps: cut the tail, then zero a run of bytes. Both
/// only ever make the input smaller or simpler, so the loop terminates; the bound is there
/// because `fails` is arbitrary code and a shrink pass that flaps would otherwise not end.
pub fn shrink(input: &[u8], fails: &mut dyn FnMut(&[u8]) -> bool) -> Vec<u8> {
    let mut best: Vec<u8> = input.to_vec();
    for _ in 0..64 {
        let before = best.len();

        // Halve the tail, then quarter it, and so on: a length-prefixed format usually
        // fails on its header, and this finds that in log(n) tries rather than n.
        let mut cut = best.len() / 2;
        while cut > 0 {
            let candidate = &best[..best.len() - cut];
            if fails(candidate) {
                best = candidate.to_vec();
            } else {
                cut /= 2;
            }
        }

        // Then flatten runs of bytes to zero, longest first: what remains is the bytes the
        // failure actually depends on.
        let mut run = 16.min(best.len());
        while run > 0 {
            let mut i = 0;
            while i + run <= best.len() {
                let mut candidate = best.clone();
                if candidate[i..i + run].iter().all(|&b| b == 0) {
                    i += run;
                    continue;
                }
                for b in &mut candidate[i..i + run] {
                    *b = 0;
                }
                if fails(&candidate) {
                    best = candidate;
                }
                i += run;
            }
            run /= 2;
        }

        if best.len() == before {
            break;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_reproduces_its_sequence_exactly() {
        let mut a = Rng::new(12345);
        let mut b = Rng::new(12345);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        // A different seed must not follow the same sequence, or a failing seed would say
        // nothing about which input failed.
        let mut c = Rng::new(12346);
        let mut d = Rng::new(12345);
        assert!((0..8).any(|_| c.next_u64() != d.next_u64()));
    }

    #[test]
    fn a_zero_seed_still_generates() {
        let mut rng = Rng::new(0);
        let first = rng.next_u64();
        assert_ne!(first, 0, "xorshift from zero stays zero for ever");
        assert!((0..16).any(|_| rng.next_u64() != first));
    }

    #[test]
    fn below_stays_below_and_handles_an_empty_range() {
        let mut rng = Rng::new(7);
        assert_eq!(rng.below(0), 0, "an empty range must not divide by zero");
        for n in [1usize, 2, 3, 17, 256] {
            for _ in 0..200 {
                assert!(rng.below(n) < n);
            }
        }
    }

    #[test]
    fn mutation_never_grows_an_input() {
        // The generators build inputs that are structurally valid up to their length
        // fields; a mutation that appended bytes would make a length field disagree with
        // the buffer for a reason the parser is not being tested on.
        let mut rng = Rng::new(99);
        for _ in 0..500 {
            let mut bytes: Vec<u8> = (0..64u8).collect();
            let before = bytes.len();
            Mutator::mutate(&mut rng, &mut bytes);
            assert!(bytes.len() <= before);
        }
    }

    #[test]
    fn mutation_leaves_an_empty_input_alone() {
        let mut rng = Rng::new(5);
        let mut bytes: Vec<u8> = Vec::new();
        Mutator::mutate(&mut rng, &mut bytes);
        assert!(bytes.is_empty());
    }

    #[test]
    fn shrinking_finds_the_byte_the_failure_depends_on() {
        // Fails only when the marker is present, so the smallest failing input is the
        // marker itself and nothing else.
        let mut input: Vec<u8> = (0..200u8).map(|i| i.wrapping_mul(7)).collect();
        input[137] = 0xde;
        let mut fails = |b: &[u8]| b.contains(&0xde);
        let small = shrink(&input, &mut fails);
        assert!(fails(&small), "the shrunk input must still fail");
        assert!(small.len() < input.len(), "nothing was shrunk");
        assert!(small.len() <= 138, "shrunk to {} bytes", small.len());
    }

    #[test]
    fn shrinking_an_input_that_does_not_fail_returns_it_unchanged() {
        let input: Vec<u8> = (0..32u8).collect();
        let mut never = |_: &[u8]| false;
        assert_eq!(shrink(&input, &mut never), input);
    }

    #[test]
    fn every_target_survives_a_short_campaign_in_process() {
        // `kbuild fuzz` runs campaigns in a separate driver with a watchdog. This is the
        // in-process floor under it: a few iterations of every target, so `kbuild test`
        // alone catches a target whose generator or runner panics on inputs it makes
        // itself. Seeded targets get no seeds here and generate empty inputs, which is a
        // case their runners must survive too.
        for t in TARGETS {
            for i in 0..32u64 {
                let mut rng = Rng::new(0x5eed ^ i);
                let input = (t.generate)(&mut rng, &[]);
                (t.run)(&input);
            }
        }
    }

    #[test]
    fn built_generators_get_past_the_first_check_far_more_often_than_random_bytes() {
        // The claim that justifies structure-aware generation, as a check: generated
        // inputs get past a parser's magic and outer lengths, where random bytes almost
        // never do. Only the built targets are measured here, because the seeded ones need
        // their seed files and a host test has none; `kbuild fuzz` reports those rates.
        const N: usize = 400;
        for name in ["elf", "bootproto", "menu"] {
            let t = target(name).unwrap();
            let accepts = t.accepts.expect("a built parser target has an accept gate");
            let mut rng = Rng::new(0xacce_97ed);
            let generated = (0..N)
                .filter(|_| accepts(&(t.generate)(&mut rng, &[])))
                .count();
            let random = (0..N)
                .filter(|_| {
                    let len = 16 + rng.below(512);
                    let bytes: Vec<u8> = (0..len).map(|_| rng.next_u32() as u8).collect();
                    accepts(&bytes)
                })
                .count();
            assert!(
                generated * 10 >= N,
                "{name}: only {generated} of {N} generated inputs got past the first check"
            );
            assert!(
                generated > random * 4,
                "{name}: {generated} generated inputs parsed, against {random} random ones"
            );
        }
    }

    #[test]
    fn every_target_has_a_name_and_a_description() {
        assert!(!TARGETS.is_empty());
        for t in TARGETS {
            assert!(!t.name.is_empty());
            assert!(!t.what.is_empty(), "{} has no description", t.name);
            assert!(target(t.name).is_some(), "{} is not findable by its own name", t.name);
        }
        // Names are what `kbuild fuzz --target` takes; two targets of one name would make
        // one of them unreachable.
        for (i, t) in TARGETS.iter().enumerate() {
            assert!(
                !TARGETS[..i].iter().any(|o| o.name == t.name),
                "two targets are called {}",
                t.name
            );
        }
    }
}
