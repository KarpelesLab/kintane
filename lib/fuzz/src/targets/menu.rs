//! The boot menu's entry list: a text file read from the boot medium.
//!
//! Untrusted in the way text is: the loader reads whatever is on the ESP or in the disk's
//! entry-list sectors, and a person edits that file by hand. The parser's contract is that
//! anything it cannot read is an error with a line number, never a panic, because a loader
//! that dies on a typo is a machine that will not boot at all.
//!
//! # Valid first, then one mistake
//!
//! The generator writes a file `Config::parse` accepts — settings before the first entry,
//! a default that names an entry that exists, unique names, one boot method per entry — and
//! then, a third of the time, makes one mistake a person makes: a setting after an entry, a
//! duplicate name, a key repeated, a mode that does not exist, a partition out of range.
//!
//! The first version drew every line independently from lists that were half mistakes, so
//! nearly every file had several, and the parser refused it at the first; only 5% of its
//! inputs got past the top-level check. Most of what the fuzzer ran was the same few error
//! returns.
//!
//! The menu *state machine* is fuzzed with the parsed configuration: keys and clock ticks
//! in whatever order, because a loader feeds it whatever a person presses.

use alloc::vec::Vec;

use kinboot_menu::{Config, Key, Menu, Step};

use crate::{Mutator, Rng};

/// Names the generator gives entries: valid, and distinct from each other.
const NAMES: [&[u8]; 6] = [
    b"normal",
    b"safe",
    b"recovery",
    b"other-os",
    b"k2",
    b"fallback-1",
];

/// Keys a loader can deliver, including ones no menu defines.
fn key(rng: &mut Rng) -> Key {
    let bytes: [u8; 12] = [
        b'1', b'2', b'9', b'0', b'j', b'k', b'\r', b'\n', 0x1b, b'[', b'A', b'x',
    ];
    Key::from_ascii(*rng.pick(&bytes))
}

pub fn generate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = if !seeds.is_empty() && rng.one_in(4) {
        rng.pick(seeds).clone()
    } else {
        build(rng)
    };
    // Byte-level corruption half the time. A hand-edited file is wrong a line at a time,
    // which `build` models; a corrupted medium is wrong a byte at a time, which this does.
    if rng.one_in(2) {
        Mutator::mutate(rng, &mut bytes);
    }
    bytes
}

/// A file built from the grammar: valid, then with at most one deliberate mistake.
fn build(rng: &mut Rng) -> Vec<u8> {
    let count = 1 + rng.below(4);
    let offset = rng.below(NAMES.len());
    let names: Vec<&[u8]> = (0..count)
        .map(|i| NAMES[(offset + i) % NAMES.len()])
        .collect();

    let mut lines: Vec<Vec<u8>> = Vec::new();
    if rng.one_in(2) {
        let t: [&[u8]; 3] = [b"0", b"5", b"30"];
        lines.push([b"timeout ", *rng.pick(&t)].concat());
    }
    if rng.one_in(2) {
        lines.push([b"default ", names[rng.below(count)]].concat());
    }
    if rng.one_in(3) {
        let f: [&[u8]; 2] = [b"firmware", b"reboot"];
        lines.push([b"on-failure ", *rng.pick(&f)].concat());
    }

    let first_entry = lines.len();
    for name in &names {
        lines.push([b"entry ", *name].concat());
        if !rng.one_in(4) {
            lines.push(b"title KinTane".to_vec());
        }
        if rng.one_in(3) {
            if rng.one_in(2) {
                let p: [&[u8]; 4] = [b"1", b"2", b"3", b"4"];
                lines.push([b"chain-partition ", *rng.pick(&p)].concat());
            } else {
                lines.push(br"chain-file \EFI\OTHER\BOOTX64.EFI".to_vec());
            }
        } else {
            let m: [&[u8]; 3] = [b"normal", b"safe", b"recovery"];
            lines.push([b"mode ", *rng.pick(&m)].concat());
            if rng.one_in(2) {
                lines.push(b"cmdline quiet kintane.canary=1".to_vec());
            }
            if rng.one_in(4) {
                lines.push(br"kernel \KINTANE\K2.ELF".to_vec());
            }
        }
    }

    if rng.one_in(3) {
        let after = first_entry + 1;
        match rng.below(12) {
            0 => lines.insert(0, b"timeout -1".to_vec()),
            1 => lines.insert(0, b"default nosuch".to_vec()),
            2 => lines.insert(0, b"on-failure explode".to_vec()),
            // A setting after an entry has begun.
            3 => lines.push(b"timeout 5".to_vec()),
            4 => lines.push([b"entry ", names[0]].concat()),
            5 => lines[first_entry] = b"entry BAD_Name".to_vec(),
            6 => lines.insert(after, b"colour blue".to_vec()),
            7 => {
                lines.insert(after, b"title again".to_vec());
                lines.insert(after, b"title twice".to_vec());
            }
            // A boot method and a chainload in one entry.
            8 => {
                lines.insert(after, b"chain-partition 2".to_vec());
                lines.insert(after, b"mode safe".to_vec());
            }
            9 => lines.insert(after, b"chain-partition 9".to_vec()),
            10 => lines.insert(after, b"cmdline mode=safe".to_vec()),
            // No entries at all.
            _ => lines.truncate(first_entry),
        }
    }

    let mut out: Vec<u8> = Vec::new();
    for line in lines {
        out.extend_from_slice(&line);
        out.push(b'\n');
    }
    out
}

pub fn run(input: &[u8]) {
    let Ok(config) = Config::parse(input) else {
        return;
    };
    let _ = config.len();
    let _ = config.is_empty();
    for entry in config.entries() {
        let _ = entry.name.len();
        let _ = entry.title.len();
    }
    for i in 0..config.len().saturating_add(2) {
        let _ = config.entry(i);
    }

    // The menu, driven the way a loader drives it: a tick or a key, over and over. The
    // sequence is derived from the input, so a failing corpus file replays exactly.
    let mut menu = Menu::new(&config);
    let mut rng = Rng::new(input.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x1000_0000_01b3)
    }));
    let _ = menu.start();
    for _ in 0..64 {
        let step = if rng.one_in(3) {
            menu.tick()
        } else {
            menu.key(key(&mut rng))
        };
        let _ = menu.selected();
        let _ = menu.counting();
        let _ = menu.seconds_left();
        if let Step::Boot(index) = step {
            // What a loader does next: look the chosen entry up. An index the menu returned
            // must be one the configuration has.
            let _ = config.entry(index);
            break;
        }
    }
}
