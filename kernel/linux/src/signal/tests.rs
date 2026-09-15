use super::*;

const START: u64 = 1 << 39;
const END: u64 = 2 << 39;

fn delivery(sig: u64) -> Delivery {
    Delivery {
        sig,
        action: Action {
            handler: START + 0x1000,
            flags: flags::SA_RESTORER,
            restorer: START + 0x2000,
            mask: bit(SIGUSR2),
        },
        old_mask: bit(SIGTERM) | bit(SIGCHLD),
        code: SI_USER,
        pid: 3,
        addr: None,
        value: 0,
    }
}

/// The same delivery, as a fault raises it: `si_addr` in place of the sender's pid.
fn fault_delivery(sig: u64, addr: u64) -> Delivery {
    Delivery {
        code: SI_KERNEL,
        pid: 0,
        addr: Some(addr),
        ..delivery(sig)
    }
}

/// A context with every word distinct and in range, as a thread in a system call has.
fn context(abi: Abi) -> [u64; REGISTER_WORDS] {
    let mut ctx = [0u64; REGISTER_WORDS];
    for (i, w) in ctx.iter_mut().enumerate() {
        *w = 0x1111_0000_0000_0000 + i as u64;
    }
    ctx[abi.pc_word()] = START + 0x4242;
    ctx[abi.sp_word()] = START + 0x10_0000 - 3;
    match abi {
        Abi::X86_64 => {
            ctx[16] = 0x246;
            // A port with fewer registers than words leaves the rest zero.
            ctx[18..].fill(0);
        }
        Abi::Aarch64 => ctx[33] = 0x6000_0000,
    }
    ctx
}

/// The frame's bytes as `rt_sigreturn` reads them, for a handler that returned normally.
fn frame_bytes(abi: Abi, built: &Built) -> ([u8; HEAD_BYTES], usize, u64) {
    let sp = match abi {
        // The handler's `ret` popped the return address into the restorer.
        Abi::X86_64 => built.at + 8,
        Abi::Aarch64 => built.at,
    };
    (built.head, abi.restore_len(), sp)
}

#[test]
fn sigkill_and_sigstop_take_no_disposition_and_the_defaults_are_linuxs() {
    let handler = Action {
        handler: START,
        ..Action::DEFAULT
    };
    let ignore = Action {
        handler: SIG_IGN,
        ..Action::DEFAULT
    };
    assert_eq!(effect(SIGKILL, &handler), Effect::Terminate);
    assert_eq!(effect(SIGKILL, &ignore), Effect::Terminate);
    // Stopping is not implemented, so a stop is ignored, handler or not.
    assert_eq!(effect(SIGSTOP, &handler), Effect::Ignore);
    assert_eq!(effect(SIGTSTP, &Action::DEFAULT), Effect::Ignore);
    assert_eq!(effect(SIGTSTP, &handler), Effect::Handle);
    assert_eq!(effect(SIGCHLD, &Action::DEFAULT), Effect::Ignore);
    assert_eq!(effect(SIGSEGV, &Action::DEFAULT), Effect::Terminate);
    assert_eq!(effect(SIGTERM, &ignore), Effect::Ignore);
    assert_eq!(effect(SIGUSR1, &handler), Effect::Handle);
    assert_eq!(effect(40, &Action::DEFAULT), Effect::Terminate);
    assert_eq!(default_action(SIGABRT), Default::Core);
    assert_eq!(UNBLOCKABLE, (1 << 8) | (1 << 18));
    assert_eq!(bit(0), 0);
    assert_eq!(bit(NSIG + 1), 0);
    assert_eq!(bit(NSIG), 1 << 63);
}

#[test]
fn an_action_reads_back_as_written_and_a_signal_exit_is_told_apart() {
    let a = delivery(SIGUSR1).action;
    assert_eq!(Action::from_bytes(&a.to_bytes()), a);
    assert_eq!(exit_signal(exit_code(SIGTERM)), Some(SIGTERM));
    assert_eq!(status(SIGTERM), 15);
    // Codes a program chooses, and the kernel's "killed", are not signals.
    for code in [0, 7, 255, 0x5349_474e, u64::MAX] {
        assert_eq!(exit_signal(code), None, "{code:#x}");
    }
}

#[test]
fn an_x86_64_frame_is_laid_out_as_linux_lays_it_and_reads_back() {
    let abi = Abi::X86_64;
    let ctx = context(abi);
    let d = delivery(SIGUSR1);
    let b = build(abi, &ctx, &d, START, END).expect("room");
    // Below the red zone, and aligned as a call leaves the stack.
    assert!(b.at + x86::FRAME as u64 <= ctx[x86::RSP] - x86::RED_ZONE);
    assert_eq!((b.at + 8) % 16, 0);
    // The frame ends in the `FXSAVE` area the `fpstate` pointer names.
    assert_eq!(b.head_len, 952);
    assert_eq!(b.zeros, 0);
    assert_eq!(
        u64::from_le_bytes(array8(&b.head, x86::FPSTATE)),
        b.at + 440,
        "the fpstate pointer names the area in this frame"
    );
    assert!(b.record.is_none());
    // The return address is the restorer; siginfo names the signal and its sender.
    assert_eq!(u64::from_le_bytes(array8(&b.head, 0)), d.action.restorer);
    assert_eq!(&b.head[312..316], &(SIGUSR1 as u32).to_le_bytes());
    assert_eq!(&b.head[328..332], &3u32.to_le_bytes());
    // sigcontext: r8 first, rip at word 16, eflags at 17; uc_sigmask at 304.
    assert_eq!(u64::from_le_bytes(array8(&b.head, 48)), ctx[7]);
    assert_eq!(u64::from_le_bytes(array8(&b.head, 48 + 16 * 8)), ctx[x86::RIP]);
    assert_eq!(u64::from_le_bytes(array8(&b.head, 304)), d.old_mask);
    // The handler's registers.
    assert_eq!(b.regs[x86::RIP], d.action.handler);
    assert_eq!(b.regs[x86::RSP], b.at);
    assert_eq!(b.regs[x86::RDI], SIGUSR1);
    assert_eq!(b.regs[x86::RSI], b.at + 312);
    assert_eq!(b.regs[x86::RDX], b.at + 8);
    assert_eq!(b.regs[x86::RFLAGS] & x86::DF, 0);

    let (bytes, len, sp) = frame_bytes(abi, &b);
    assert_eq!(abi.frame_at(sp), Ok(b.at));
    let r = restore(abi, &bytes[..len], b.at, START, END).expect("a frame this built");
    assert_eq!(r.regs, ctx);
    assert_eq!(r.mask, d.old_mask);
}

#[test]
fn an_aarch64_frame_is_laid_out_as_linux_lays_it_and_reads_back() {
    let abi = Abi::Aarch64;
    let ctx = context(abi);
    let d = delivery(SIGUSR2);
    let b = build(abi, &ctx, &d, START, END).expect("room");
    assert_eq!(b.at % 16, 0);
    assert_eq!(b.head_len + b.zeros, 4688);
    let (record_at, record) = b.record.expect("a frame record");
    assert_eq!(record_at, b.at + 4688);
    assert!(record_at + 16 <= ctx[a64::W_SP]);
    assert_eq!(u64::from_le_bytes(array8(&record, 0)), ctx[29]);
    assert_eq!(u64::from_le_bytes(array8(&record, 8)), ctx[30]);
    assert_eq!(&b.head[0..4], &(SIGUSR2 as u32).to_le_bytes());
    // regs[0] at 312, sp at 560, pc at 568, pstate at 576; uc_sigmask at 168.
    assert_eq!(u64::from_le_bytes(array8(&b.head, 312)), ctx[0]);
    assert_eq!(u64::from_le_bytes(array8(&b.head, 568)), ctx[a64::W_PC]);
    assert_eq!(u64::from_le_bytes(array8(&b.head, 168)), d.old_mask);
    assert_eq!(b.regs[a64::W_PC], d.action.handler);
    assert_eq!(b.regs[a64::W_SP], b.at);
    assert_eq!(b.regs[a64::X29], record_at);
    assert_eq!(b.regs[a64::X30], d.action.restorer);
    assert_eq!([b.regs[0], b.regs[1], b.regs[2]], [SIGUSR2, b.at, b.at + 128]);

    let (bytes, len, sp) = frame_bytes(abi, &b);
    assert_eq!(abi.frame_at(sp), Ok(b.at));
    let r = restore(abi, &bytes[..len], b.at, START, END).expect("a frame this built");
    assert_eq!(r.regs, ctx);
    assert_eq!(r.mask, d.old_mask);
}

#[test]
fn a_faults_siginfo_carries_the_address_where_a_sent_signals_carries_a_pid() {
    // The two fields share their bytes, so what a handler reads depends on which signal it
    // was sent: `si_addr` for a fault, `si_pid` for a signal a process sent.
    for (abi, info_at) in [(Abi::X86_64, 312), (Abi::Aarch64, 0)] {
        let ctx = context(abi);
        let addr = START + 0x9_1000;
        let f = build(abi, &ctx, &fault_delivery(SIGSEGV, addr), START, END).expect("room");
        assert_eq!(&f.head[info_at..info_at + 4], &(SIGSEGV as u32).to_le_bytes(), "{abi:?}");
        assert_eq!(&f.head[info_at + 8..info_at + 12], &SI_KERNEL.to_le_bytes(), "{abi:?}");
        assert_eq!(u64::from_le_bytes(array8(&f.head, info_at + 16)), addr, "{abi:?}");

        let sent = build(abi, &ctx, &delivery(SIGUSR1), START, END).expect("room");
        assert_eq!(&sent.head[info_at + 16..info_at + 20], &3u32.to_le_bytes(), "{abi:?}");
        // A fault's signal is one a fault raises; one a process sent is not.
        assert!(from_fault(SIGSEGV) && from_fault(SIGFPE) && from_fault(SIGILL));
        assert!(!from_fault(SIGUSR1) && !from_fault(SIGCHLD) && !from_fault(SIGKILL));
    }
}

#[test]
fn a_frame_the_program_changed_cannot_return_anywhere_a_program_may_not() {
    for abi in [Abi::X86_64, Abi::Aarch64] {
        let ctx = context(abi);
        let b = build(abi, &ctx, &delivery(SIGUSR1), START, END).unwrap();
        let len = abi.restore_len();
        let pc_at = match abi {
            Abi::X86_64 => 48 + 16 * 8,
            Abi::Aarch64 => 568,
        };
        for bad in [0, START - 1, END, u64::MAX, 0xffff_8000_0000_0000] {
            let mut bytes = b.head;
            bytes[pc_at..pc_at + 8].copy_from_slice(&bad.to_le_bytes());
            assert_eq!(
                restore(abi, &bytes[..len], b.at, START, END),
                Err(BadFrame::BadReturn),
                "{abi:?} {bad:#x}"
            );
        }
        assert_eq!(restore(abi, &b.head[..len - 1], b.at, START, END), Err(BadFrame::Short));
        // A mask that blocks the unblockable is given back without them.
        let mask_at = match abi {
            Abi::X86_64 => 304,
            Abi::Aarch64 => 168,
        };
        let mut bytes = b.head;
        bytes[mask_at..mask_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(restore(abi, &bytes[..len], b.at, START, END).unwrap().mask, !UNBLOCKABLE);
    }
    // x86_64: flags beyond a program's own are dropped, and interrupts stay on.
    let abi = Abi::X86_64;
    let b = build(abi, &context(abi), &delivery(SIGUSR1), START, END).unwrap();
    let mut bytes = b.head;
    let flags_at = 48 + 17 * 8;
    bytes[flags_at..flags_at + 8].copy_from_slice(&0x3000u64.to_le_bytes());
    let r = restore(abi, &bytes[..abi.restore_len()], b.at, START, END).unwrap();
    assert_eq!(r.regs[16], 0x202);
    assert!(is_user_context(abi, &r.regs, START, END));
    // aarch64: a state that is not EL0 is refused outright, and so is a misaligned frame.
    let abi = Abi::Aarch64;
    let b = build(abi, &context(abi), &delivery(SIGUSR1), START, END).unwrap();
    for state in [0x5u64, 0x3c5, 0x6000_0004] {
        let mut bytes = b.head;
        bytes[576..584].copy_from_slice(&state.to_le_bytes());
        let len = abi.restore_len();
        assert_eq!(
            restore(abi, &bytes[..len], b.at, START, END),
            Err(BadFrame::BadState),
            "{state:#x}"
        );
    }
    assert_eq!(abi.frame_at(START + 7), Err(BadFrame::Misaligned));
}

#[test]
fn a_stack_with_no_room_below_it_takes_no_frame() {
    for abi in [Abi::X86_64, Abi::Aarch64] {
        let mut ctx = context(abi);
        ctx[abi.sp_word()] = START + 64;
        assert_eq!(
            build(abi, &ctx, &delivery(SIGUSR1), START, END),
            Err(BadFrame::NoRoom),
            "{abi:?}"
        );
        ctx[abi.sp_word()] = 16;
        assert_eq!(
            build(abi, &ctx, &delivery(SIGUSR1), START, END),
            Err(BadFrame::NoRoom),
            "{abi:?}"
        );
    }
}

#[test]
fn a_frame_carries_floating_point_state_and_only_the_one_this_kernel_wrote() {
    // The frame now carries those registers, so a well-formed one is accepted — and every
    // other shape of the same field is refused. The frame is the program's to write, so this
    // is the field a program would use to point the kernel somewhere of its choosing.
    for (abi, at) in [(Abi::X86_64, x86::FPSTATE), (Abi::Aarch64, a64::RECORD)] {
        let ctx = context(abi);
        let b = build(abi, &ctx, &delivery(SIGUSR1), START, END).expect("room");
        let len = abi.restore_len();
        // What `build` writes: x86_64's pointer names the area in this frame, and aarch64's
        // record is a `fpsimd_context` header — Linux's magic and Linux's size.
        let written = u64::from_le_bytes(array8(&b.head, at));
        let good = match abi {
            Abi::X86_64 => b.at + x86::FPSTATE_AREA as u64,
            Abi::Aarch64 => u64::from(a64::FPSIMD_MAGIC) | ((a64::FPSIMD_SIZE as u64) << 32),
        };
        assert_eq!(written, good, "{abi:?}");
        restore(abi, &b.head[..len], b.at, START, END).expect("a frame this built");

        // Null is no longer "no state claimed" — it is a malformed frame, because every frame
        // this kernel writes carries the state. The old refusal accepted null; this must not.
        // 0x4650_5342 is the bare magic with a zero size: the right name, the wrong shape.
        for claimed in [0u64, 1, START + 0x1000, u64::MAX, 0x4650_5342] {
            if claimed == good {
                continue;
            }
            let mut bytes = b.head;
            bytes[at..at + 8].copy_from_slice(&claimed.to_le_bytes());
            assert_eq!(
                restore(abi, &bytes[..len], b.at, START, END),
                Err(BadFrame::FpState),
                "{abi:?} {claimed:#x}"
            );
        }
    }

    // x86_64's pointer is checked against the address the frame was read from, so the same
    // bytes restored as if they came from elsewhere are refused: a program cannot move the
    // area by lying about where its frame is.
    let abi = Abi::X86_64;
    let b = build(abi, &context(abi), &delivery(SIGUSR1), START, END).expect("room");
    let len = abi.restore_len();
    assert_eq!(
        restore(abi, &b.head[..len], b.at + 16, START, END),
        Err(BadFrame::FpState),
        "a pointer is only good for the frame it was built for"
    );

    // aarch64: a record naming a size other than `fpsimd_context`'s is refused, magic or no.
    let abi = Abi::Aarch64;
    let b = build(abi, &context(abi), &delivery(SIGUSR1), START, END).expect("room");
    let len = abi.restore_len();
    for size in [0u32, 0x10, a64::FPSIMD_SIZE as u32 - 1, u32::MAX] {
        let mut bytes = b.head;
        bytes[a64::RECORD..a64::RECORD + 4].copy_from_slice(&a64::FPSIMD_MAGIC.to_le_bytes());
        bytes[a64::RECORD + 4..a64::RECORD + 8].copy_from_slice(&size.to_le_bytes());
        assert_eq!(
            restore(abi, &bytes[..len], b.at, START, END),
            Err(BadFrame::FpState),
            "size {size:#x}"
        );
    }
}

#[test]
fn a_queued_signals_value_follows_its_sender_in_the_siginfo() {
    for (abi, info_at) in [(Abi::X86_64, 312), (Abi::Aarch64, 0)] {
        let ctx = context(abi);
        let d = Delivery {
            code: SI_QUEUE,
            value: 0x5151_5151_2727_2727,
            ..delivery(SIGUSR1)
        };
        let b = build(abi, &ctx, &d, START, END).expect("room");
        assert_eq!(&b.head[info_at + 8..info_at + 12], &SI_QUEUE.to_le_bytes(), "{abi:?}");
        assert_eq!(&b.head[info_at + 16..info_at + 20], &3u32.to_le_bytes(), "{abi:?}");
        assert_eq!(u64::from_le_bytes(array8(&b.head, info_at + 24)), d.value, "{abi:?}");
        // A signal that was not queued writes no value at all, leaving those bytes zero.
        let plain = build(abi, &ctx, &delivery(SIGUSR1), START, END).expect("room");
        assert_eq!(u64::from_le_bytes(array8(&plain.head, info_at + 24)), 0, "{abi:?}");
    }
}
