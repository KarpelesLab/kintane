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
    ctx[abi.sp_word()] = USER_START + 0x10_0000 + rng.next_u64() % 0x1000_0000;
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
        // A third of the built frames claim saved floating-point state, which `restore` must
        // refuse: the pointer on x86_64, the first reserved record on aarch64.
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

pub fn run(input: &[u8]) {
    let Some((&tag, frame)) = input.split_first() else {
        return;
    };
    let abi = abi(tag);
    if let Ok(r) = signal::restore(abi, frame, USER_START, USER_END) {
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
        let fp_at = match abi {
            Abi::X86_64 => signal::FPSTATE_AT,
            Abi::Aarch64 => signal::RECORD_AT,
        };
        if let Some(w) = frame.get(fp_at..fp_at + 8) {
            let claimed = u64::from_le_bytes(w.try_into().expect("eight bytes"));
            assert_eq!(claimed, 0, "{abi:?}: a frame claiming floating-point state was accepted");
        }
    }
}

/// A frame `restore` takes.
pub fn accepts(input: &[u8]) -> bool {
    input
        .split_first()
        .is_some_and(|(&tag, frame)| signal::restore(abi(tag), frame, USER_START, USER_END).is_ok())
}
