//! Where a PCI function's interrupt pin arrives: `_PRT`, bridges, and interrupt link devices
//! (ACPI 6.5 §6.2.13, §6.2.16).

use super::*;

/// A PCI function's interrupt, as the namespace routes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// The global system interrupt the pin drives.
    pub gsi: u32,
    pub active_low: bool,
    pub level: bool,
    /// The interrupt link device the `_PRT` entry named, when it named one rather than the
    /// interrupt itself.
    pub link: Option<NodeId>,
    /// The host bridge or bridge whose `_PRT` answered.
    pub bridge: NodeId,
    /// The pin that `_PRT` was asked about, 0 for INTA#, after any swizzle through bridges.
    pub pin: u8,
}

/// Bridges between a host bridge and a function, plus the function. Real machines have two
/// or three.
const MAX_HOPS: usize = 8;

/// A compressed EISA ID, such as `PNP0A03`, as `EISAID` encodes it into an integer.
pub const fn eisa_id(id: &[u8; 7]) -> u32 {
    const fn letter(c: u8) -> u32 {
        (c.wrapping_sub(b'@') & 0x1f) as u32
    }
    const fn hex(c: u8) -> u32 {
        match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'A'..=b'F' => (c - b'A' + 10) as u32,
            _ => 0,
        }
    }
    let v = (letter(id[0]) << 26)
        | (letter(id[1]) << 21)
        | (letter(id[2]) << 16)
        | (hex(id[3]) << 12)
        | (hex(id[4]) << 8)
        | (hex(id[5]) << 4)
        | hex(id[6]);
    v.swap_bytes()
}

impl<'t, 's, H: Host> Interpreter<'t, 's, H> {
    /// Tell firmware that interrupts are routed through the I/O APIC, by evaluating
    /// `\_PIC(1)`. Firmware whose `_PRT` depends on it returns the PIC's table until this is
    /// done, as QEMU's q35 does. `false` when there is no `_PIC`.
    pub fn select_apic_mode(&mut self) -> Result<bool, Error> {
        match self.child(NodeId::ROOT, b"_PIC") {
            Some(pic) => self.evaluate(pic, &[Object::Integer(1)]).map(|_| true),
            None => Ok(false),
        }
    }

    /// The host bridge whose bus is `bus`: a device with a `_HID` or `_CID` of a PCI host
    /// bridge, and a `_BBN` of `bus` or none when `bus` is zero.
    pub fn host_bridge(&mut self, bus: u8) -> Result<Option<NodeId>, Error> {
        for node in 1..self.n_nodes {
            let node = NodeId(node as u16);
            if !self.is_device(node) {
                continue;
            }
            self.fresh();
            // A device whose identification cannot be evaluated is not the bridge asked for;
            // it is not a reason to fail routing every other device.
            if !self.is_host_bridge(node).unwrap_or(false) {
                continue;
            }
            let bbn = match self.evaluate_child(node, b"_BBN", &[])? {
                Some(v) => self.integer(v)?,
                None => 0,
            };
            if bbn == u64::from(bus) {
                return Ok(Some(node));
            }
        }
        Ok(None)
    }

    /// The device under `parent` whose `_ADR` names `device` and `function`.
    pub fn device_at(
        &mut self,
        parent: NodeId,
        device: u8,
        function: u8,
    ) -> Result<Option<NodeId>, Error> {
        let want = (u64::from(device) << 16) | u64::from(function);
        for node in 1..self.n_nodes {
            let node = NodeId(node as u16);
            if self.parent(node) != Some(parent) || !self.is_device(node) {
                continue;
            }
            if let Some(adr) = self.evaluate_child(node, b"_ADR", &[])? {
                if self.integer(adr)? == want {
                    return Ok(Some(node));
                }
            }
        }
        Ok(None)
    }

    /// Route interrupt pin `pin` (1 for INTA# to 4 for INTD#, as the configuration register
    /// holds it) of the function at the end of `path` under the host bridge of `bus`.
    ///
    /// `path` is `(device, function)` for each bridge from the host bridge down, then the
    /// function itself. The `_PRT` of the bus the function is on answers when there is one;
    /// where a bridge has none, the pin is swizzled onto the bridge's own
    /// (`(pin + device) % 4`, PCI-to-PCI Bridge Architecture Specification §9.1) and the
    /// question moves up a bus.
    ///
    /// An entry naming no link device (source `0`) is the GSI itself, level-triggered and
    /// active low as PCI interrupts are. One naming a link device is what its `_CRS` says;
    /// a link with nothing assigned is given its first `_PRS` choice through `_SRS`, and
    /// `_CRS` must then agree.
    pub fn route_pin(&mut self, bus: u8, path: &[(u8, u8)], pin: u8) -> Result<Route, Error> {
        if !(1..=4).contains(&pin) || path.is_empty() || path.len() > MAX_HOPS {
            return Err(Error::NoRoute);
        }
        let host = self.host_bridge(bus)?.ok_or(Error::NoRoute)?;
        let mut owners = [None; MAX_HOPS];
        owners[0] = Some(host);
        for k in 1..path.len() {
            owners[k] = match owners[k - 1] {
                Some(owner) => self.device_at(owner, path[k - 1].0, path[k - 1].1)?,
                None => None,
            };
        }
        let mut pin = pin - 1;
        for k in (0..path.len()).rev() {
            let device = path[k].0;
            if let Some(owner) = owners[k] {
                if let Some(prt) = self.child(owner, b"_PRT") {
                    let table = self.evaluate(prt, &[])?;
                    return self.route_entry(owner, table, device, pin);
                }
            }
            pin = (pin + device % 4) % 4;
        }
        Err(Error::NoRoute)
    }

    fn route_entry(
        &mut self,
        bridge: NodeId,
        table: Object,
        device: u8,
        pin: u8,
    ) -> Result<Route, Error> {
        let count = self.package_len(table)?;
        for i in 0..count {
            let entry = self.element(table, i)?;
            let address = self.element(entry, 0)?;
            let address = self.integer(address)?;
            let entry_pin = self.element(entry, 1)?;
            let entry_pin = self.integer(entry_pin)?;
            if (address >> 16) & 0xffff != u64::from(device) || entry_pin != u64::from(pin) {
                continue;
            }
            let source = self.element(entry, 2)?;
            let index = self.element(entry, 3)?;
            let index = self.integer(index)?;
            return match source {
                Object::Integer(0) => Ok(Route {
                    gsi: u32::try_from(index).map_err(|_| Error::BadResource)?,
                    active_low: true,
                    level: true,
                    link: None,
                    bridge,
                    pin,
                }),
                Object::Reference(link) => {
                    let index = usize::try_from(index).map_err(|_| Error::BadResource)?;
                    let irq = self.link_interrupt(link, index)?;
                    Ok(Route {
                        gsi: irq.number,
                        active_low: irq.active_low,
                        level: irq.level,
                        link: Some(link),
                        bridge,
                        pin,
                    })
                }
                // A name that resolved to nothing when the package was read.
                Object::String(_) => Err(Error::NotFound),
                _ => Err(Error::BadResource),
            };
        }
        Err(Error::NoRoute)
    }

    /// The interrupt a link device is set to, choosing and committing one if it has none.
    fn link_interrupt(&mut self, link: NodeId, index: usize) -> Result<Interrupt, Error> {
        let current = self.current_interrupt(link, index)?;
        if let Some(irq) = current.filter(|irq| irq.number != 0) {
            return Ok(irq);
        }
        let prs = self
            .evaluate_child(link, b"_PRS", &[])?
            .ok_or(Error::NotFound)?;
        let choice = nth_interrupt(self.buffer(prs)?, 0)?.ok_or(Error::BadResource)?;
        let template = self.new_buffer(&interrupt_template(choice))?;
        self.evaluate_child(link, b"_SRS", &[template])?
            .ok_or(Error::NotFound)?;
        match self.current_interrupt(link, index)? {
            Some(irq) if irq.number == choice.number => Ok(irq),
            _ => Err(Error::NoRoute),
        }
    }

    fn current_interrupt(
        &mut self,
        link: NodeId,
        index: usize,
    ) -> Result<Option<Interrupt>, Error> {
        let crs = self
            .evaluate_child(link, b"_CRS", &[])?
            .ok_or(Error::NotFound)?;
        nth_interrupt(self.buffer(crs)?, index)
    }
}
