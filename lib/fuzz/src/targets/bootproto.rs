//! The boot protocol's tag stream: what a loader hands the kernel.
//!
//! The kernel reads this before it has a console on some ports, so a panic here is a
//! machine that stops with nothing printed. The generator builds a structurally valid
//! structure with the crate's own [`Builder`] — which is what a loader uses, so what comes
//! out is the shape the kernel really sees — and then corrupts it.
//!
//! Corrupting the *header* matters as much as corrupting a tag: `header_size` and
//! `tags_size` are what the kernel slices the structure by, and the first version of this
//! file's mutation step left them alone, which never reached the tag walk with a
//! disagreeing length.

use alloc::vec;
use alloc::vec::Vec;

use boot_protocol::tags::{self, Builder};
use boot_protocol::{Firmware, MemoryKind, MemoryRegion, TagKind};

use crate::{Mutator, Rng};

/// Build a structure a loader could have written, then corrupt it.
pub fn generate(rng: &mut Rng, _seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let len = build(rng, &mut buf);
    let mut bytes = buf[..len].to_vec();
    // Sometimes hand the parser exactly what a loader wrote: the valid case has to stay
    // reachable, or the fuzzer only ever tests the rejection paths.
    if !rng.one_in(8) {
        Mutator::mutate(rng, &mut bytes);
    }
    bytes
}

/// Fill `buf` with a valid structure and return its length.
fn build(rng: &mut Rng, buf: &mut [u8]) -> usize {
    let Ok(mut b) = Builder::new(buf) else {
        return 0;
    };

    if !rng.one_in(6) {
        let regions = 1 + rng.below(8);
        if let Ok(mut map) = b.memory_map(regions) {
            let mut start = 0x1000u64;
            for _ in 0..regions {
                let len = (1 + rng.below(64) as u64) * 0x1000;
                let kind = *rng.pick(&[
                    MemoryKind::Usable,
                    MemoryKind::Reserved,
                    MemoryKind::KernelImage,
                    MemoryKind::BootData,
                ]);
                let _ = map.push(MemoryRegion {
                    start,
                    len,
                    kind: kind as u32,
                    _reserved: 0,
                });
                start = start.wrapping_add(len).wrapping_add(0x1000);
            }
            map.close();
        }
    }
    if !rng.one_in(4) {
        let _ = b.acpi_rsdp(0xe_0000 + rng.next_u64() % 0x1_0000);
    }
    if !rng.one_in(4) {
        let lines: [&[u8]; 4] = [
            b"",
            b"mode=normal",
            b"mode=safe kintane.canary=cmdline-intact",
            b"mode=recovery quiet",
        ];
        let _ = b.command_line(rng.pick(&lines));
    }
    if !rng.one_in(4) {
        let f = *rng.pick(&[
            Firmware::Unknown,
            Firmware::Bios,
            Firmware::Uefi,
            Firmware::Static,
        ]);
        let _ = b.firmware(f);
    }
    if !rng.one_in(4) {
        let _ = b.kernel_range(0x10_0000, (1 + rng.below(64) as u64) * 0x1000);
    }
    // Tags this version of the kernel does not read: a framebuffer, a boot device, an
    // entropy seed. The compatibility rules say a kernel steps over what it does not know,
    // and stepping over uses the tag's own size field — the one a mutation then corrupts.
    if rng.one_in(3) {
        let kind = *rng.pick(&[
            TagKind::Framebuffer,
            TagKind::BootDevice,
            TagKind::EntropySeed,
            TagKind::DeviceTree,
            TagKind::Module,
        ]);
        let payload_len = rng.interesting_len(64);
        let payload: Vec<u8> = (0..payload_len).map(|_| rng.next_u32() as u8).collect();
        let _ = b.tag(kind, &payload);
    }
    b.finish()
}

/// Parse, then read everything a kernel reads. Reading only the header would leave the tag
/// walk — where the offsets are — untested.
pub fn run(input: &[u8]) {
    // The kernel reads the header first, from an address, before it can bound a slice.
    let _ = tags::header(input);

    let Ok(parsed) = tags::parse(input) else {
        return;
    };
    for tag in parsed.tags() {
        match tag {
            Ok(t) => {
                let _ = (t.kind, t.payload.len(), t.offset);
            }
            Err(_) => break,
        }
    }
    if let Ok(Some(map)) = parsed.memory_map() {
        let _ = map.len();
        for region in map {
            let _ = region.start.checked_add(region.len);
        }
    }
    let _ = parsed.acpi_rsdp();
    let _ = parsed.command_line();
    let _ = parsed.firmware();
    let _ = parsed.kernel_range();
    let _ = parsed.header.total_size();
}
