//! Host tests: source-override routing, redirection entries, the local APIC's bring-up
//! and timer arithmetic, and the command sequence that starts a CPU, over register banks
//! that record what was written.

#![allow(unsafe_code)]

use std::cell::Cell;
use std::sync::Mutex;

use hal::{ClockSource, EventTimer, IrqChip, IrqNumber};

use super::io::{self, IoApic, IoRegisters, Override};
use super::local::{self, LocalRegisters};
use super::*;

/// A local APIC: a page of registers, a log of interrupt commands, and a timer whose
/// current count a test sets.
struct FakeLocal {
    regs: Mutex<Vec<u32>>,
    commands: Mutex<Vec<(u32, u32)>>,
    id: u32,
    accept: bool,
}

impl FakeLocal {
    fn new(id: u32) -> FakeLocal {
        FakeLocal {
            regs: Mutex::new(vec![0; 0x100]),
            commands: Mutex::new(Vec::new()),
            id,
            accept: true,
        }
    }

    fn get(&self, offset: usize) -> u32 {
        self.regs.lock().unwrap()[offset / 4]
    }
}

impl LocalRegisters for FakeLocal {
    fn read(&self, offset: usize) -> u32 {
        self.get(offset)
    }

    fn write(&self, offset: usize, value: u32) {
        self.regs.lock().unwrap()[offset / 4] = value;
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn command(&self, dest: u32, low: u32) -> bool {
        self.commands.lock().unwrap().push((dest, low));
        self.accept
    }

    fn enter_mode(&self) -> bool {
        true
    }
}

/// An I/O APIC's internal registers, with a version register saying `entries` entries.
struct FakeIo {
    regs: Mutex<Vec<u32>>,
}

impl FakeIo {
    fn new(entries: u32) -> FakeIo {
        let mut regs = vec![0xdead_beef; 0x100];
        regs[1] = 0x11 | ((entries - 1) << 16);
        FakeIo {
            regs: Mutex::new(regs),
        }
    }
}

impl IoRegisters for FakeIo {
    fn read(&self, index: u32) -> u32 {
        self.regs.lock().unwrap()[index as usize]
    }

    fn write(&self, index: u32, value: u32) {
        self.regs.lock().unwrap()[index as usize] = value;
    }
}

const VECTORS: Vectors = Vectors {
    irq_base: 32,
    timer: 0xef,
    spurious: 0xff,
};

/// QEMU's `pc` and `q35` overrides: the PIT on GSI 2, and the PCI-routed ISA lines
/// level-triggered active high.
const QEMU_OVERRIDES: [Override; 5] = [
    Override {
        source: 0,
        gsi: 2,
        flags: 0,
    },
    Override {
        source: 5,
        gsi: 5,
        flags: 0xd,
    },
    Override {
        source: 9,
        gsi: 9,
        flags: 0xd,
    },
    Override {
        source: 10,
        gsi: 10,
        flags: 0xd,
    },
    Override {
        source: 11,
        gsi: 11,
        flags: 0xd,
    },
];

type Fake = Controller<FakeLocal, FakeIo>;

fn controller(io: [Option<IoApic<FakeIo>>; MAX_IO_APICS]) -> Fake {
    Controller::new(FakeLocal::new(3), io, &QEMU_OVERRIDES, VECTORS).unwrap()
}

fn one_io_apic() -> [Option<IoApic<FakeIo>>; MAX_IO_APICS] {
    [Some(IoApic::new(FakeIo::new(24), 0)), None, None, None]
}

#[test]
fn an_isa_irq_without_an_override_is_its_own_gsi_edge_high() {
    assert_eq!(io::route(4, &QEMU_OVERRIDES), (4, false, false));
}

#[test]
fn overrides_move_the_timer_and_set_level_lines() {
    assert_eq!(io::route(0, &QEMU_OVERRIDES), (2, false, false));
    assert_eq!(io::route(9, &QEMU_OVERRIDES), (9, false, true));
    let low_edge = [Override {
        source: 7,
        gsi: 20,
        flags: 0b0111,
    }];
    assert_eq!(io::route(7, &low_edge), (20, true, false));
}

#[test]
fn redirection_entries_put_every_field_where_the_datasheet_does() {
    let e = io::redirection(0x21, 5, true, true, false);
    assert_eq!(e & 0xff, 0x21);
    assert_eq!(e >> 56, 5);
    assert_ne!(e & io::ACTIVE_LOW, 0);
    assert_ne!(e & io::LEVEL, 0);
    assert_eq!(e & io::MASKED, 0);
    // Fixed delivery and physical destination: bits 8..12 clear.
    assert_eq!(e & 0xf00, 0);
    assert_ne!(io::redirection(0x21, 5, false, false, true) & io::MASKED, 0);
}

#[test]
fn a_pci_gsi_is_routed_with_the_polarity_and_trigger_it_was_given() {
    let c = controller(one_io_apic());
    // q35's disk: GSI 23, level-triggered, active high, on the first message line's vector.
    assert!(c.route_gsi(23, 48, false, true, false));
    let expected = Redirection {
        vector: 48,
        destination: 3,
        masked: false,
        level: true,
        active_low: false,
    };
    assert_eq!(c.redirection_entry(23), Some(expected));
    assert!(c.route_gsi(22, 49, true, true, true));
    let e = c.redirection_entry(22).unwrap();
    assert!(e.active_low && e.masked && e.level);
    assert_eq!(e.vector, 49);
    // No I/O APIC serves GSI 24, and ISA IRQs own GSIs 2 and 9.
    assert!(!c.route_gsi(24, 48, false, true, false));
    assert!(!c.route_gsi(2, 48, false, true, false));
    assert!(!c.route_gsi(9, 48, false, true, false));
    assert_eq!(c.redirection_entry(24), None);
}

#[test]
fn construction_masks_every_entry_and_prepares_the_boot_cpu() {
    let c = controller(one_io_apic());
    let apic = c.io[0].as_ref().unwrap();
    assert_eq!(apic.entries(), 24);
    for i in 0..24 {
        assert_eq!(apic.get(i), io::MASKED, "entry {i}");
    }
    assert_eq!(c.boot_id(), 3);
    let l = &c.local;
    assert_eq!(l.get(local::SVR), local::SOFTWARE_ENABLE | 0xff);
    assert_eq!(l.get(local::LVT_LINT0) & local::MASKED, local::MASKED);
    assert_eq!(l.get(local::LVT_LINT1) & local::MASKED, local::MASKED);
    assert_eq!(l.get(local::LVT_TIMER), local::MASKED | 0xef);
    assert_eq!(l.get(local::TIMER_DIVIDE), local::DIVIDE_16);
    assert_eq!(l.get(local::TPR), 0);
}

#[test]
fn enabling_irq0_unmasks_gsi2_on_vector_32_for_the_boot_cpu() {
    let c = controller(one_io_apic());
    c.enable(IrqNumber(0));
    let apic = c.io[0].as_ref().unwrap();
    let e = apic.get(2);
    assert_eq!(e & 0xff, 32);
    assert_eq!(e & io::MASKED, 0);
    assert_eq!(e >> 56, 3);
    // GSI 0, which IRQ 0 is not on, stays masked.
    assert_eq!(apic.get(0), io::MASKED);
    c.disable(IrqNumber(0));
    assert_ne!(apic.get(2) & io::MASKED, 0);
    assert_eq!(apic.get(2) & 0xff, 32, "masking keeps the vector");
}

#[test]
fn a_gsi_is_found_on_the_io_apic_that_serves_it() {
    let io = [
        Some(IoApic::new(FakeIo::new(8), 0)),
        Some(IoApic::new(FakeIo::new(8), 8)),
        None,
        None,
    ];
    let c = Controller::new(FakeLocal::new(0), io, &[], VECTORS).unwrap();
    c.enable(IrqNumber(10));
    assert_eq!(c.io[1].as_ref().unwrap().get(2) & 0xff, 42);
    assert_eq!(c.io[1].as_ref().unwrap().get(2) & io::MASKED, 0);
    assert_eq!(c.io_apics(), 2);
}

#[test]
fn interrupts_past_isa_are_not_routed() {
    let c = controller(one_io_apic());
    c.enable(IrqNumber(16));
    let apic = c.io[0].as_ref().unwrap();
    assert!((0..24).all(|i| apic.get(i) == io::MASKED));
}

#[test]
fn eoi_and_ipis_go_to_the_local_apic() {
    let c = controller(one_io_apic());
    c.local.write(local::EOI, 0x55);
    c.eoi(IrqNumber(0));
    assert_eq!(c.local.get(local::EOI), 0);
    c.send_ipi(IrqNumber(0xf1), 2);
    let cmds = c.local.commands.lock().unwrap().clone();
    assert_eq!(cmds, vec![(2, local::FIXED | local::ASSERT | 0xf1)]);
    assert_eq!(c.claim(), None);
}

#[test]
fn init_cpu_reports_the_calling_cpus_id() {
    let c = controller(one_io_apic());
    // SAFETY: a fake; nothing is masked because nothing is real.
    assert_eq!(unsafe { c.init_cpu() }, Some(3));
}

#[test]
fn timer_counts_round_up_and_are_never_zero() {
    // QEMU's rate at divide-by-16: one count per 16 ns.
    let rate = 62_500_000;
    assert_eq!(local::count_for(16, rate), 1);
    assert_eq!(local::count_for(17, rate), 2);
    assert_eq!(local::count_for(0, rate), 1);
    assert_eq!(local::count_for(1_000_000_000, rate), 62_500_000);
    // Past the reach, the whole counter.
    assert_eq!(local::count_for(u64::MAX, rate), u32::MAX);
    assert_eq!(local::reach_ns(rate), 68_719_476_720);
    assert_eq!(local::reach_ns(0), 0);
    assert!(local::ns_for(local::count_for(10_000_000, rate), rate) >= 10_000_000);
}

#[test]
fn timer_rates_come_from_the_clock() {
    // 62 500 counts over 1 ms of a 1 GHz clock.
    assert_eq!(local::rate_per_second(62_500, 1_000_000, 1_000_000_000), Some(62_500_000));
    assert_eq!(local::rate_per_second(0, 1_000_000, 1_000_000_000), None);
    assert_eq!(local::rate_per_second(1, 0, 1_000_000_000), None);
    assert_eq!(local::rate_per_second(u64::MAX, 1, 2), None);
}

#[test]
fn arming_programs_one_shot_and_periodic_modes() {
    let mut c = controller(one_io_apic());
    c.rate = 62_500_000;
    // SAFETY: a fake.
    unsafe { c.arm_ns(1_000_000) };
    assert_eq!(c.local.get(local::LVT_TIMER), 0xef, "one-shot, unmasked");
    assert_eq!(c.local.get(local::TIMER_INITIAL), 62_500);
    // SAFETY: a fake.
    let period = unsafe { c.start_periodic_ns(10_000_000) };
    assert_eq!(period, Some(10_000_000));
    assert_eq!(c.local.get(local::LVT_TIMER), local::PERIODIC | 0xef);
    assert_eq!(c.local.get(local::TIMER_INITIAL), 625_000);
    c.stop();
    assert_eq!(c.local.get(local::TIMER_INITIAL), 0);
    assert_ne!(c.local.get(local::LVT_TIMER) & local::MASKED, 0);
    assert_eq!(c.reach_ns(), 68_719_476_720);
}

#[test]
fn an_unmeasured_timer_arms_nothing() {
    let c = controller(one_io_apic());
    // SAFETY: a fake.
    unsafe { c.arm_ns(1_000) };
    assert_eq!(c.local.get(local::TIMER_INITIAL), 0);
    // SAFETY: a fake.
    assert_eq!(unsafe { c.start_periodic_ns(1_000) }, None);
    assert_eq!(c.reach_ns(), 0);
}

/// A clock that advances a fixed step per read, and lets the fake timer count down with it.
struct SteppingClock<'a> {
    now: Cell<u64>,
    step: u64,
    hz: u64,
    timer: &'a FakeLocal,
    /// Timer counts per clock tick.
    counts_per_tick: u64,
}

// SAFETY: `ClockSource` requires `Sync`, and a `SteppingClock` never leaves the test that
// made it, so its cell is only ever touched from that test's thread.
unsafe impl Sync for SteppingClock<'_> {}

impl ClockSource for SteppingClock<'_> {
    fn name(&self) -> &'static str {
        "stepping"
    }

    fn read(&self) -> u64 {
        let now = self.now.get() + self.step;
        self.now.set(now);
        let initial = self.timer.get(local::TIMER_INITIAL);
        if initial != 0 {
            let counted = (now * self.counts_per_tick).min(u64::from(initial));
            self.timer
                .write(local::TIMER_CURRENT, initial - counted as u32);
        }
        now
    }

    fn bits(&self) -> u32 {
        64
    }

    fn frequency_hz(&self) -> u64 {
        self.hz
    }
}

#[test]
fn calibration_measures_the_rate_against_the_clock() {
    let mut c = controller(one_io_apic());
    // Borrow the fake register bank for the clock through a second fake that shares
    // nothing: the controller owns its local APIC, so the clock reads it by pointer.
    let local_ptr: *const FakeLocal = &c.local;
    // SAFETY: `c` outlives the clock, and neither is moved while the clock exists.
    let timer = unsafe { &*local_ptr };
    let clock = SteppingClock {
        now: Cell::new(0),
        step: 1_000,
        hz: 1_000_000_000,
        timer,
        counts_per_tick: 1,
    };
    let rate = c.calibrate(&clock).unwrap();
    // One count per nanosecond of a 1 GHz clock is 10^9 per second, give or take the reads.
    assert!((990_000_000..=1_010_000_000).contains(&rate), "{rate}");
    assert_eq!(c.rate(), rate);
    assert_eq!(c.local.get(local::TIMER_INITIAL), 0, "calibration stops the timer");
    assert_ne!(c.local.get(local::LVT_TIMER) & local::MASKED, 0, "and never unmasked it");
}

#[test]
fn a_stopped_clock_fails_calibration() {
    let mut c = controller(one_io_apic());
    struct Stopped;
    impl ClockSource for Stopped {
        fn name(&self) -> &'static str {
            "stopped"
        }
        fn read(&self) -> u64 {
            7
        }
        fn bits(&self) -> u32 {
            64
        }
        fn frequency_hz(&self) -> u64 {
            1_000
        }
    }
    assert_eq!(c.calibrate(&Stopped), None);
    assert_eq!(c.rate(), 0);
}

#[test]
fn starting_a_cpu_sends_init_then_one_startup_when_the_first_works() {
    let c = controller(one_io_apic());
    let waits = Mutex::new(Vec::new());
    let polls = Cell::new(0);
    let ok = c.start_cpu(7, 0x01, &|us| waits.lock().unwrap().push(us), &|| {
        polls.set(polls.get() + 1);
        polls.get() > 1
    });
    assert!(ok);
    let cmds = c.local.commands.lock().unwrap().clone();
    assert_eq!(
        cmds,
        vec![
            (7, local::INIT | local::ASSERT),
            (7, local::STARTUP | local::ASSERT | 0x01),
        ]
    );
    assert_eq!(waits.lock().unwrap()[0], 10_000, "INIT is held for ten milliseconds");
}

#[test]
fn a_cpu_that_does_not_start_gets_a_second_startup_ipi() {
    let c = controller(one_io_apic());
    assert!(c.start_cpu(1, 0x02, &|_| {}, &|| false));
    let cmds = c.local.commands.lock().unwrap().clone();
    assert_eq!(cmds.len(), 3);
    assert_eq!(cmds[2], (1, local::STARTUP | local::ASSERT | 0x02));
}

#[test]
fn a_refused_command_stops_the_sequence() {
    let mut l = FakeLocal::new(0);
    l.accept = false;
    let c = Controller::new(l, one_io_apic(), &[], VECTORS).unwrap();
    assert!(!c.start_cpu(1, 0x01, &|_| {}, &|| false));
    assert_eq!(c.local.commands.lock().unwrap().len(), 1);
}

#[test]
fn too_many_overrides_are_refused() {
    let many = [Override::EMPTY; MAX_OVERRIDES + 1];
    assert!(Controller::new(FakeLocal::new(0), one_io_apic(), &many, VECTORS).is_none());
}
