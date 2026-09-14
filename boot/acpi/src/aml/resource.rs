//! The interrupt descriptors of a resource template (ACPI 6.5 §6.4), as a link device's `_CRS`
//! and `_PRS` return them and its `_SRS` takes them.

use super::Error;

/// One interrupt a resource template lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupt {
    /// The global system interrupt, or the ISA IRQ for a small IRQ descriptor.
    pub number: u32,
    pub active_low: bool,
    pub level: bool,
    pub shared: bool,
}

/// Small item: IRQ descriptor, two or three bytes.
const SMALL_IRQ: u8 = 0x04;
/// Small item: end tag.
const SMALL_END: u8 = 0x0f;
/// Large item: extended interrupt descriptor.
const LARGE_EXTENDED_INTERRUPT: u8 = 0x09;

/// Interrupt `index` of `template`, counting every interrupt of every descriptor in order.
/// `None` when the template ends first. A template that runs past its bytes, or has no end
/// tag, is [`Error::BadResource`].
pub fn nth_interrupt(template: &[u8], index: usize) -> Result<Option<Interrupt>, Error> {
    let mut at = 0;
    let mut seen = 0;
    while let Some(&tag) = template.get(at) {
        if tag & 0x80 == 0 {
            let len = usize::from(tag & 0x07);
            let body = template
                .get(at + 1..at + 1 + len)
                .ok_or(Error::BadResource)?;
            match (tag >> 3) & 0x0f {
                SMALL_END => return Ok(None),
                SMALL_IRQ => {
                    let [lo, hi, ..] = *body else {
                        return Err(Error::BadResource);
                    };
                    // Without the flags byte: edge-triggered, active high (§6.4.2.1).
                    let flags = body.get(2).copied().unwrap_or(0x01);
                    let mask = u16::from_le_bytes([lo, hi]);
                    for irq in 0..16 {
                        if mask & (1 << irq) == 0 {
                            continue;
                        }
                        if seen == index {
                            return Ok(Some(Interrupt {
                                number: irq,
                                level: flags & 0x01 == 0,
                                active_low: flags & 0x08 != 0,
                                shared: flags & 0x10 != 0,
                            }));
                        }
                        seen += 1;
                    }
                }
                _ => {}
            }
            at += 1 + len;
        } else {
            let header = template.get(at + 1..at + 3).ok_or(Error::BadResource)?;
            let len = usize::from(u16::from_le_bytes([header[0], header[1]]));
            let body = template
                .get(at + 3..at + 3 + len)
                .ok_or(Error::BadResource)?;
            if tag & 0x7f == LARGE_EXTENDED_INTERRUPT {
                let [flags, count, ..] = *body else {
                    return Err(Error::BadResource);
                };
                let count = usize::from(count);
                if 2 + 4 * count > len {
                    return Err(Error::BadResource);
                }
                if index < seen + count {
                    let k = 2 + 4 * (index - seen);
                    let number =
                        u32::from_le_bytes([body[k], body[k + 1], body[k + 2], body[k + 3]]);
                    return Ok(Some(Interrupt {
                        number,
                        level: flags & 0x02 == 0,
                        active_low: flags & 0x04 != 0,
                        shared: flags & 0x08 != 0,
                    }));
                }
                seen += count;
            }
            at += 3 + len;
        }
    }
    Err(Error::BadResource)
}

/// A resource template holding one extended interrupt descriptor for `irq`, as a link
/// device's `_SRS` takes the choice made from its `_PRS`.
pub fn interrupt_template(irq: Interrupt) -> [u8; 11] {
    let mut flags = 0x01; // resource consumer
    if !irq.level {
        flags |= 0x02;
    }
    if irq.active_low {
        flags |= 0x04;
    }
    if irq.shared {
        flags |= 0x08;
    }
    let n = irq.number.to_le_bytes();
    [
        0x80 | LARGE_EXTENDED_INTERRUPT,
        0x06,
        0x00,
        flags,
        0x01,
        n[0],
        n[1],
        n[2],
        n[3],
        // End tag, with a zero checksum, which means "not checked".
        0x79,
        0x00,
    ]
}
