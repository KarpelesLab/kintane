//! Signal frames: what `rt_sigreturn` reads back from a Linux thread's stack.
//!
//! The frame is the program's memory, so every byte of it is the program's to write: a
//! handler may change the saved registers on purpose, and a bug may scribble over them. The
//! contract of `linux::signal::restore` is that no bytes whatever come back as a context a
//! return to user mode could not carry — a return address outside the user half, flags or a
//! processor state that are not a program's own — and that the mask it gives never blocks the
//! two signals nothing blocks.
//!
//! Half the inputs are frames `build` laid out from a random context and then corrupted, so the
//! reader is exercised past its length check; the rest are arbitrary bytes. The first byte picks
//! the architecture.

use alloc::vec::Vec;

use linux::Abi;
use linux::signal::{self, Action, Delivery};

use crate::{Mutator, Rng};

/// The user half both ports have: the second 512 GiB.
const USER_START: u64 = 1 << 39;
const USER_END: u64 = 2 << 39;

fn abi(tag: u8) -> Abi {
    if tag & 1 == 0 {
        Abi::X86_64
    } else {
        Abi::Aarch64
    }
}

pub fn generate(rng: &mut Rng, _seeds: &[Vec<u8>]) -> Vec<u8> {
    let tag = (rng.next_u32() & 1) as u8;
    let abi = abi(tag);
    let mut bytes = Vec::with_capacity(1 + signal::HEAD_BYTES);
    bytes.push(tag);
    if rng.one_in(2) {
        let len = rng.interesting_len(signal::HEAD_BYTES);
        bytes.extend((0..len).map(|_| rng.next_u32() as u8));
        return bytes;
    }
    let mut ctx = [0u64; signal::REGISTER_WORDS];
    for w in &mut ctx {
        *w = rng.next_u64();
    }
    let pc = USER_START + rng.next_u64() % (USER_END - USER_START);
    ctx[abi.pc_word()] = pc;
    // The stack that puts `build`'s frame at the address `frame_at` reports for this tag, so a
    // generated frame's `fpstate` pointer is the one `restore` will check for. Without this
    // every generated x86_64 frame would be refused on the pointer before reaching anything
    // else, and the target would fuzz one branch.
    ctx[abi.sp_word()] = stack_for(tag);
    let d = Delivery {
        sig: 1 + rng.next_u64() % signal::NSIG,
        action: Action {
            handler: pc,
            flags: signal::flags::SA_RESTORER,
            restorer: pc,
            mask: rng.next_u64(),
        },
        old_mask: rng.next_u64(),
        code: signal::SI_USER,
        pid: rng.next_u32(),
        // Half the frames are a fault's, whose `siginfo` carries the faulting address where
        // the others carry a pid.
        addr: rng.one_in(2).then(|| rng.next_u64()),
        value: rng.next_u64(),
    };
    if let Ok(built) = signal::build(abi, &ctx, &d, USER_START, USER_END) {
        let mut head = built.head;
        // A third of the built frames corrupt the floating-point field, which `restore` must
        // refuse: the pointer on x86_64, the `fpsimd_context` header on aarch64. Both are
        // fields a program would use to aim the kernel at memory of its choosing, so a frame
        // whose field is anything but the one `build` wrote must not come back accepted.
        if rng.one_in(3) {
            let at = match abi {
                Abi::X86_64 => signal::FPSTATE_AT,
                Abi::Aarch64 => signal::RECORD_AT,
            };
            head[at..at + 8].copy_from_slice(&rng.next_u64().to_le_bytes());
        }
        bytes.extend_from_slice(&head[..abi.restore_len()]);
    }
    Mutator::mutate(rng, &mut bytes);
    bytes
}

/// The stack pointer a generated frame is built from, which the tag varies so that inputs do
/// not all land on one address.
fn stack_for(tag: u8) -> u64 {
    USER_START + 0x10_0000 + u64::from(tag >> 1) * 16
}

/// Where the input says its frame was read from.
///
/// The address is part of the input, not a constant, because x86_64's `fpstate` pointer is
/// checked *against* it: with a fixed address the pointer check could only ever be approached
/// from one side, and an input that moves both together is the one that would find a check
/// comparing them loosely.
///
/// It is obtained by asking `build` where it put the frame rather than by inverting `build`'s
/// arithmetic here. Inverting it would be a second copy of the red zone, the alignment and the
/// frame size — three numbers that would then have to be kept in step with the layout by hand.
fn frame_at(tag: u8) -> u64 {
    let abi = abi(tag);
    let mut ctx = [0u64; signal::REGISTER_WORDS];
    ctx[abi.pc_word()] = USER_START + 0x4242;
    ctx[abi.sp_word()] = stack_for(tag);
    let d = Delivery {
        sig: 1,
        action: Action {
            handler: USER_START + 0x4242,
            flags: signal::flags::SA_RESTORER,
            restorer: USER_START + 0x4242,
            mask: 0,
        },
        old_mask: 0,
        code: signal::SI_USER,
        pid: 0,
        addr: None,
        value: 0,
    };
    match signal::build(abi, &ctx, &d, USER_START, USER_END) {
        Ok(b) => b.at,
        // No frame fits that stack, so no input built from it will be accepted either; any
        // address does, since `restore` will refuse on length or on the pointer regardless.
        Err(_) => stack_for(tag),
    }
}

pub fn run(input: &[u8]) {
    let Some((&tag, frame)) = input.split_first() else {
        return;
    };
    let abi = abi(tag);
    let at = frame_at(tag);
    if let Ok(r) = signal::restore(abi, frame, at, USER_START, USER_END) {
        assert!(
            signal::is_user_context(abi, &r.regs, USER_START, USER_END),
            "{abi:?}: a frame restored a context no return to user mode may carry: {:x?}",
            r.regs
        );
        assert_eq!(
            r.mask & signal::UNBLOCKABLE,
            0,
            "{abi:?}: a restored mask blocks SIGKILL or SIGSTOP"
        );
        // The frame carries floating-point state now, so the invariant is no longer "no state
        // was claimed" but "the state is the one this kernel wrote". An accepted frame whose
        // pointer names anywhere else would have the kernel read memory the program chose; an
        // accepted record of another size would have it walk a chain of the program's length.
        let fp_at = match abi {
            Abi::X86_64 => signal::FPSTATE_AT,
            Abi::Aarch64 => signal::RECORD_AT,
        };
        let wanted = match abi {
            Abi::X86_64 => at + signal::FPU_AT[0] as u64,
            Abi::Aarch64 => u64::from(signal::FPSIMD_MAGIC) | ((signal::FPSIMD_SIZE as u64) << 32),
        };
        if let Some(w) = frame.get(fp_at..fp_at + 8) {
            let claimed = u64::from_le_bytes(w.try_into().expect("eight bytes"));
            assert_eq!(
                claimed, wanted,
                "{abi:?}: a frame was accepted whose floating-point field is not the one \
                 `build` writes (frame at {at:#x})"
            );
        }
    }
}

/// A frame `restore` takes.
pub fn accepts(input: &[u8]) -> bool {
    input.split_first().is_some_and(|(&tag, frame)| {
        signal::restore(abi(tag), frame, frame_at(tag), USER_START, USER_END).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed seeds are what their names say.
    ///
    /// Replaying a seed cannot tell an accepted frame from a refused one: [`run`] returns early
    /// when `restore` refuses and asserts nothing, so a seed that is silently refused replays
    /// as "no failure" while exercising none of the code it was committed for. That is how the
    /// seed this pair replaced had come to test nothing — it was built for a 600-byte frame and
    /// the frame is 1128 bytes now, so it died on the length check — and it is worth a test
    /// rather than a second round of the same mistake.
    #[test]
    fn the_committed_seeds_are_accepted_and_refused_as_their_names_say() {
        let good = include_bytes!("../../corpus/sigframe/seed-fpsimd-well-formed.bin");
        let bad = include_bytes!("../../corpus/sigframe/seed-fpsimd-bad-size.bin");
        assert!(accepts(good), "the well-formed seed is refused, so it exercises nothing");
        assert!(!accepts(bad), "the malformed seed is accepted, so it checks nothing");
        // The two differ only in the record's size field, so what the second one catches is
        // the size check and nothing else.
        assert_eq!(good.len(), bad.len());
        assert_eq!(
            good.iter().zip(bad.iter()).filter(|(a, b)| a != b).count(),
            1,
            "the seeds differ somewhere other than the record's size"
        );
        // And the invariant holds on both, which is what a replay checks.
        run(good);
        run(bad);
    }
}
