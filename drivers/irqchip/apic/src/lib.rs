//! The x86 Advanced Programmable Interrupt Controller: the local APIC every CPU has, and
//! the I/O APICs that route device interrupts to them, bound from the ACPI MADT.
//!
//! The successor to the 8259A pair, and on a PC with more than one CPU the only choice: an
//! 8259A can interrupt one CPU, has no inter-processor interrupts, and has no timer. This
//! driver provides all three through the traits the architecture's interrupt path holds.
//!
//! * [`hal::IrqChip`]: device lines through the I/O APIC, end-of-interrupt and IPIs through the
//!   local APIC, and [`IrqChip::init_cpu`] preparing each CPU's own local APIC.
//! * [`hal::EventTimer`]: the local APIC timer, one-shot or periodic, on the CPU that arms it.
//! * [`Apic::start_cpu`]: INIT and startup IPIs, the one thing the architecture's SMP bring-up
//!   cannot do through a generic interface.
//!
//! # Vectors
//!
//! The architecture owns the vector numbers and passes them in ([`Vectors`]), because the
//! IDT is its table. ISA IRQ `n` is delivered on `irq_base + n`, which is where the 8259A
//! put it too, so the architecture's per-line entry points serve either controller. An IPI
//! is raised on the vector [`IrqChip::send_ipi`] is given.
//!
//! # What is deliberately not here
//!
//! No interrupts above ISA IRQ 15: PCI interrupts need `_PRT` from the ACPI namespace, and
//! MSI needs capabilities, and neither exists yet. Every device interrupt is delivered to
//! the boot CPU. No logical destination mode, no interrupt remapping.
//!
//! Reference: Intel SDM Vol. 3A, chapter 11; Intel 82093AA I/O APIC datasheet; ACPI 6.5
//! §5.2.12.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod io;
pub mod local;
pub mod msi;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod msr;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[path = "msr_none.rs"]
mod msr;

use device::table::Kind;
use device::{BootCell, Bound, Driver, Mmio, Origin, Probe, ProbeError, Registers};
use hal::{ClockSource, EventTimer, IrqChip, IrqNumber};
pub use io::Override;
use io::{IoApic, MmioIo};
use local::{LocalRegisters, MmioLocal, X2Local};

/// I/O APICs driven. A PC has one; large servers a handful.
pub const MAX_IO_APICS: usize = 4;
/// Interrupt source overrides kept. There are sixteen ISA IRQs to override.
pub const MAX_OVERRIDES: usize = 16;
/// ISA IRQs this controller routes.
pub const ISA_IRQS: u32 = 16;

/// How long the timer is measured against the clock source: a tenth of a second's clock
/// ticks divided by this. Ten milliseconds is thousands of counts on any real APIC.
const CALIBRATION_DIVISOR: u64 = 100;
/// Clock reads allowed while measuring, so a clock that stopped fails calibration.
const CALIBRATION_POLLS: u64 = 200_000_000;

/// The vector numbers the architecture's IDT uses for this controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vectors {
    /// ISA IRQ 0's vector; IRQ `n` is `irq_base + n`.
    pub irq_base: u8,
    /// The local APIC timer's vector.
    pub timer: u8,
    /// The spurious-interrupt vector. Never acknowledged.
    pub spurious: u8,
}

/// An I/O APIC redirection entry, as [`Controller::redirection_entry`] reads it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirection {
    pub vector: u8,
    /// The physical destination: one local APIC's ID.
    pub destination: u8,
    pub masked: bool,
    pub level: bool,
    pub active_low: bool,
}

/// The local APIC, reached one of two ways; see [`local`].
pub enum Local {
    Mmio(MmioLocal),
    X2(X2Local),
}

impl LocalRegisters for Local {
    fn read(&self, offset: usize) -> u32 {
        match self {
            Local::Mmio(l) => l.read(offset),
            Local::X2(l) => l.read(offset),
        }
    }

    fn write(&self, offset: usize, value: u32) {
        match self {
            Local::Mmio(l) => l.write(offset, value),
            Local::X2(l) => l.write(offset, value),
        }
    }

    fn id(&self) -> u32 {
        match self {
            Local::Mmio(l) => l.id(),
            Local::X2(l) => l.id(),
        }
    }

    fn command(&self, dest: u32, low: u32) -> bool {
        match self {
            Local::Mmio(l) => l.command(dest, low),
            Local::X2(l) => l.command(dest, low),
        }
    }

    fn enter_mode(&self) -> bool {
        match self {
            Local::Mmio(l) => l.enter_mode(),
            Local::X2(l) => l.enter_mode(),
        }
    }
}

/// The whole controller: the local APIC, the I/O APICs, and how ISA IRQs reach them.
///
/// Generic over register access so the host tests can drive it; the kernel's is
/// [`Apic`].
pub struct Controller<L: LocalRegisters, R: io::IoRegisters> {
    local: L,
    io: [Option<IoApic<R>>; MAX_IO_APICS],
    overrides: [Override; MAX_OVERRIDES],
    n_overrides: usize,
    vectors: Vectors,
    /// The boot CPU's APIC ID, where every device interrupt is delivered.
    boot_id: u32,
    /// Timer counts per second at divide-by-16. Zero when unmeasured.
    rate: u64,
}

/// The controller as the kernel builds it.
pub type Apic = Controller<Local, MmioIo>;

impl<L: LocalRegisters, R: io::IoRegisters> Controller<L, R> {
    /// A controller over `local` and the I/O APICs in `io`, with `overrides` applied to ISA
    /// IRQs. Prepares the calling CPU's local APIC and masks every redirection entry, but
    /// measures nothing: see [`Controller::calibrate`].
    ///
    /// `None` when there are more overrides than [`MAX_OVERRIDES`], or the local APIC cannot
    /// enter the mode its access needs.
    pub fn new(
        local: L,
        io: [Option<IoApic<R>>; MAX_IO_APICS],
        overrides: &[Override],
        vectors: Vectors,
    ) -> Option<Controller<L, R>> {
        if overrides.len() > MAX_OVERRIDES || !local.enter_mode() {
            return None;
        }
        let mut kept = [Override::EMPTY; MAX_OVERRIDES];
        kept[..overrides.len()].copy_from_slice(overrides);
        for apic in io.iter().flatten() {
            apic.mask_all();
        }
        let boot_id = local::prepare_cpu(&local, vectors.spurious, vectors.timer);
        Some(Controller {
            local,
            io,
            overrides: kept,
            n_overrides: overrides.len(),
            vectors,
            boot_id,
            rate: 0,
        })
    }

    /// Measure the timer against `clock`, on the calling CPU with its interrupts masked.
    /// Returns the rate in counts per second, or `None` when it could not be measured, in
    /// which case the timer's reach is zero.
    pub fn calibrate(&mut self, clock: &dyn ClockSource) -> Option<u64> {
        let hz = clock.frequency_hz();
        let wait = hz / CALIBRATION_DIVISOR;
        if wait == 0 {
            return None;
        }
        let l = &self.local;
        l.write(local::TIMER_DIVIDE, local::DIVIDE_16);
        l.write(local::LVT_TIMER, local::MASKED | u32::from(self.vectors.timer));
        let t0 = clock.read();
        l.write(local::TIMER_INITIAL, u32::MAX);
        let mut polls = 0;
        while clock.read().wrapping_sub(t0) < wait && polls < CALIBRATION_POLLS {
            polls += 1;
        }
        let current = l.read(local::TIMER_CURRENT);
        let t1 = clock.read();
        l.write(local::TIMER_INITIAL, 0);
        let counted = u64::from(u32::MAX - current);
        let rate = local::rate_per_second(counted, t1.wrapping_sub(t0), hz)?;
        self.rate = rate;
        Some(rate)
    }

    /// The boot CPU's APIC ID.
    pub fn boot_id(&self) -> u32 {
        self.boot_id
    }

    /// The timer's measured rate, in counts per second. Zero when unmeasured.
    pub fn rate(&self) -> u64 {
        self.rate
    }

    /// How many I/O APICs this controller drives.
    pub fn io_apics(&self) -> usize {
        self.io.iter().flatten().count()
    }

    /// The I/O APIC serving `gsi`, and the entry index there.
    fn entry_for(&self, gsi: u32) -> Option<(&IoApic<R>, u32)> {
        self.io
            .iter()
            .flatten()
            .find_map(|a| a.index_of(gsi).map(|i| (a, i)))
    }

    /// Write the redirection entry for ISA IRQ `irq`, masked or not.
    fn route_isa(&self, irq: IrqNumber, masked: bool) {
        if irq.0 >= ISA_IRQS {
            return;
        }
        let isa = irq.0 as u8;
        let overrides = &self.overrides[..self.n_overrides];
        let (gsi, active_low, level) = io::route(isa, overrides);
        let Some((apic, index)) = self.entry_for(gsi) else {
            return;
        };
        let vector = self.vectors.irq_base.wrapping_add(isa);
        apic.set(index, io::redirection(vector, self.boot_id, active_low, level, masked));
    }

    /// Route global system interrupt `gsi` to `vector` on the boot CPU, with the polarity
    /// and trigger its source has, masked or not.
    ///
    /// For a PCI interrupt, whose GSI, polarity and trigger firmware gives in `_PRT` and a
    /// link device's `_CRS`, not as an ISA override. The caller chose the vector, and owns
    /// unmasking and masking the entry. `false` when no I/O APIC serves `gsi`, or when an
    /// ISA IRQ is routed there, whose entry [`IrqChip::enable`] writes.
    pub fn route_gsi(
        &self,
        gsi: u32,
        vector: u8,
        active_low: bool,
        level: bool,
        masked: bool,
    ) -> bool {
        let overrides = &self.overrides[..self.n_overrides];
        if (0..ISA_IRQS as u8).any(|isa| io::route(isa, overrides).0 == gsi) {
            return false;
        }
        let Some((apic, index)) = self.entry_for(gsi) else {
            return false;
        };
        apic.set(index, io::redirection(vector, self.boot_id, active_low, level, masked));
        true
    }

    /// The redirection entry for `gsi`, read back from the I/O APIC serving it.
    pub fn redirection_entry(&self, gsi: u32) -> Option<Redirection> {
        let (apic, index) = self.entry_for(gsi)?;
        let e = apic.get(index);
        Some(Redirection {
            vector: e as u8,
            destination: (e >> 56) as u8,
            masked: e & io::MASKED != 0,
            level: e & io::LEVEL != 0,
            active_low: e & io::ACTIVE_LOW != 0,
        })
    }

    /// INIT and startup IPIs for the CPU whose APIC ID is `apic_id`, with the startup
    /// vector naming the page its first instruction is on (vector `v` starts it at
    /// `v * 0x1000`).
    ///
    /// The sequence of the Intel MultiProcessor Specification, §B.4: INIT, a ten-millisecond
    /// wait, then up to two startup IPIs, skipping the second when `started` says the first
    /// worked. `wait_us` busy-waits the given number of microseconds. Returns whether every
    /// command was accepted, which says nothing about whether the CPU came up; `started` is
    /// the caller's to ask afterwards.
    pub fn start_cpu(
        &self,
        apic_id: u32,
        vector: u8,
        wait_us: &dyn Fn(u64),
        started: &dyn Fn() -> bool,
    ) -> bool {
        if !self.local.command(apic_id, local::INIT | local::ASSERT) {
            return false;
        }
        wait_us(10_000);
        for _ in 0..2 {
            if started() {
                break;
            }
            let sipi = local::STARTUP | local::ASSERT | u32::from(vector);
            if !self.local.command(apic_id, sipi) {
                return false;
            }
            wait_us(1_000);
        }
        true
    }
}

#[allow(unsafe_code)]
impl<L, R> IrqChip for Controller<L, R>
where
    L: LocalRegisters + Sync,
    R: io::IoRegisters + Sync,
{
    unsafe fn init(&self) {
        // Nothing left: `new` prepared the boot CPU and masked every entry before the
        // controller could be published, so it is initialised by construction.
    }

    fn enable(&self, irq: IrqNumber) {
        self.route_isa(irq, false);
    }

    fn disable(&self, irq: IrqNumber) {
        self.route_isa(irq, true);
    }

    /// Always `None`. The CPU dispatched through the vector the interrupt was routed to, so
    /// there is nothing to ask: the local APIC has no acknowledge register, and its
    /// in-service bits are what the end-of-interrupt write clears.
    fn claim(&self) -> Option<IrqNumber> {
        None
    }

    fn eoi(&self, _irq: IrqNumber) {
        // Non-specific: the highest in-service vector is cleared, which is the one being
        // handled, since handlers do not nest.
        self.local.write(local::EOI, 0);
    }

    fn name(&self) -> &'static str {
        "I/O APIC + local APIC"
    }

    unsafe fn init_cpu(&self) -> Option<u64> {
        if !self.local.enter_mode() {
            return None;
        }
        let id = local::prepare_cpu(&self.local, self.vectors.spurious, self.vectors.timer);
        Some(u64::from(id))
    }

    fn send_ipi(&self, irq: IrqNumber, target: u64) {
        let Ok(vector) = u8::try_from(irq.0) else {
            return;
        };
        let _ = self
            .local
            .command(target as u32, local::FIXED | local::ASSERT | u32::from(vector));
    }
}

#[allow(unsafe_code)]
impl<L, R> EventTimer for Controller<L, R>
where
    L: LocalRegisters + Sync,
    R: io::IoRegisters + Sync,
{
    fn name(&self) -> &'static str {
        "local APIC timer"
    }

    fn reach_ns(&self) -> u64 {
        local::reach_ns(self.rate)
    }

    unsafe fn arm_ns(&self, ns: u64) {
        if self.rate == 0 {
            return;
        }
        let count = local::count_for(ns, self.rate);
        // The vector and mode first: writing the initial count is what starts the count.
        self.local
            .write(local::LVT_TIMER, u32::from(self.vectors.timer));
        self.local.write(local::TIMER_INITIAL, count);
    }

    unsafe fn start_periodic_ns(&self, ns: u64) -> Option<u64> {
        if self.rate == 0 {
            return None;
        }
        let count = local::count_for(ns, self.rate);
        self.local
            .write(local::LVT_TIMER, local::PERIODIC | u32::from(self.vectors.timer));
        self.local.write(local::TIMER_INITIAL, count);
        Some(local::ns_for(count, self.rate))
    }

    fn stop(&self) {
        self.local
            .write(local::LVT_TIMER, local::MASKED | u32::from(self.vectors.timer));
        self.local.write(local::TIMER_INITIAL, 0);
    }
}

// ---- binding ---------------------------------------------------------------------------

/// The local APIC's driver. It claims the register window, so the kernel maps it whether or
/// not x2APIC mode ends up reaching the registers another way.
pub struct LocalApicDriver;
pub static LOCAL_DRIVER: LocalApicDriver = LocalApicDriver;

/// An I/O APIC's driver. One node each; up to [`MAX_IO_APICS`].
pub struct IoApicDriver;
pub static IO_DRIVER: IoApicDriver = IoApicDriver;

static LOCAL_CLAIM: BootCell<Mmio> = BootCell::new();
static IO_CLAIMS: [BootCell<(Mmio, u32)>; MAX_IO_APICS] = [const { BootCell::new() }; MAX_IO_APICS];
/// The controller [`install`] built.
static CHIP: BootCell<Apic> = BootCell::new();

impl Driver for LocalApicDriver {
    fn name(&self) -> &'static str {
        "local APIC"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["acpi,local-apic"]
    }

    #[allow(unsafe_code)]
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        let window = p.claim_mmio(0, "local APIC")?;
        // SAFETY: probe runs during single-threaded boot, `BootCell::set`'s whole contract.
        unsafe { LOCAL_CLAIM.set(window) }
            .map(|_| ())
            .map_err(|_| ProbeError::Declined("a local APIC is already bound"))
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        // Brought up by `install`, which needs the source overrides and the vectors, which
        // neither this node nor this driver knows.
        Ok(())
    }
}

impl Driver for IoApicDriver {
    fn name(&self) -> &'static str {
        "I/O APIC"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["acpi,io-apic"]
    }

    #[allow(unsafe_code)]
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        let gsi_base = match p.tree().node(p.node()).origin() {
            Origin::Table(d) => match d.kind {
                Kind::IoInterruptController { gsi_base, .. } => gsi_base,
                _ => return Err(ProbeError::Declined("not an I/O interrupt controller")),
            },
            _ => return Err(ProbeError::Declined("an I/O APIC is described by the MADT")),
        };
        let window = p.claim_mmio(0, "I/O APIC")?;
        let mut value = Some((window, gsi_base));
        for cell in &IO_CLAIMS {
            let Some(v) = value.take() else { break };
            // SAFETY: single-threaded boot, as above. A full cell hands the value back.
            value = unsafe { cell.set(v) }.err();
        }
        match value {
            None => Ok(()),
            Some(_) => Err(ProbeError::Declined("more I/O APICs than this driver keeps")),
        }
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

/// What [`install`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// No x2APIC and no local APIC window was bound.
    NoLocalApic,
    /// No I/O APIC was bound.
    NoIoApic,
    /// A window does not fit the address space.
    Unaddressable,
    /// More overrides than [`MAX_OVERRIDES`], or the local APIC would not enter its mode.
    Refused,
    /// Already installed.
    Again,
}

/// Build the controller from what the drivers bound: prepare the boot CPU's local APIC,
/// mask every I/O APIC entry, and measure the timer against `clock` when there is one.
///
/// Uses x2APIC mode when the CPU has it and `allow_x2apic` is set.
///
/// # Safety
/// Once, during single-threaded boot with interrupts masked, after the drivers probed.
/// Every window they claimed must be mapped at its physical address for as long as the
/// controller is used, as every claimed window is.
#[allow(unsafe_code)]
pub unsafe fn install(
    overrides: &[Override],
    vectors: Vectors,
    clock: Option<&dyn ClockSource>,
    allow_x2apic: bool,
) -> Result<&'static Apic, InstallError> {
    let local = if allow_x2apic && msr::x2apic_supported() {
        Local::X2(X2Local)
    } else {
        let window = LOCAL_CLAIM.get().ok_or(InstallError::NoLocalApic)?;
        // SAFETY: a claimed window, mapped by the caller's contract.
        Local::Mmio(MmioLocal(
            unsafe { Registers::new(window) }.ok_or(InstallError::Unaddressable)?,
        ))
    };
    let mut io: [Option<IoApic<MmioIo>>; MAX_IO_APICS] = [const { None }; MAX_IO_APICS];
    for (slot, (window, gsi_base)) in io
        .iter_mut()
        .zip(IO_CLAIMS.iter().filter_map(BootCell::get))
    {
        // SAFETY: as above.
        let regs = unsafe { Registers::new(window) }.ok_or(InstallError::Unaddressable)?;
        *slot = Some(IoApic::new(MmioIo(regs), *gsi_base));
    }
    if io.iter().all(Option::is_none) {
        return Err(InstallError::NoIoApic);
    }
    let mut chip = Controller::new(local, io, overrides, vectors).ok_or(InstallError::Refused)?;
    if let Some(clock) = clock {
        let _ = chip.calibrate(clock);
    }
    // SAFETY: single-threaded boot, the caller's contract.
    unsafe { CHIP.set(chip) }.map_err(|_| InstallError::Again)
}

/// The controller [`install`] built, once it has.
pub fn installed() -> Option<&'static Apic> {
    CHIP.get()
}

/// Whether the installed controller reaches its local APICs in x2APIC mode.
pub fn is_x2apic(apic: &Apic) -> bool {
    matches!(apic.local, Local::X2(_))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod msi_tests;
