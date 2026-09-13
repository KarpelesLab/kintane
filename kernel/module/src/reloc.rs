//! Applying relocations.
//!
//! `docs/modules.md` put this in `arch/<name>/module.rs`, as the one per-architecture part of
//! the loader. It is per *ELF machine* rather than per running architecture, and it is pure
//! arithmetic on bytes: which value, computed how, written into how many bits. So it lives
//! here, selected by the object's `e_machine`, where every type can be tested on the host
//! against hand-computed values. The running kernel's only per-architecture decision is
//! which machine it accepts.
//!
//! The notation is the ABI documents': `S` is the symbol's address, `A` the addend, `P` the
//! address of the place being relocated. A value that does not fit its field is refused,
//! never truncated. A truncated `R_X86_64_PC32` is a call into the middle of some other
//! function, found at run time or never.

use crate::elf::{EM_AARCH64, EM_X86_64};

/// Why a relocation could not be applied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelocError {
    /// A type this loader does not implement, named by machine and number.
    Unsupported { machine: u16, kind: u32 },
    /// The value does not fit the field.
    Overflow { kind: u32, offset: u64 },
    /// The place lies outside the section being relocated.
    OutOfSection { offset: u64 },
    /// An AArch64 branch or page-relative target that is not aligned as the field requires.
    Misaligned { kind: u32, offset: u64 },
}

pub mod x86_64 {
    pub const R_NONE: u32 = 0;
    pub const R_64: u32 = 1;
    pub const R_PC32: u32 = 2;
    pub const R_PLT32: u32 = 4;
    pub const R_GOTPCREL: u32 = 9;
    pub const R_32: u32 = 10;
    pub const R_32S: u32 = 11;
    pub const R_PC64: u32 = 24;
    pub const R_GOTPCRELX: u32 = 41;
    pub const R_REX_GOTPCRELX: u32 = 42;
}

pub mod aarch64 {
    pub const R_NONE: u32 = 0;
    pub const R_ABS64: u32 = 257;
    pub const R_ABS32: u32 = 258;
    pub const R_PREL64: u32 = 260;
    pub const R_PREL32: u32 = 261;
    pub const R_ADR_PREL_PG_HI21: u32 = 275;
    pub const R_ADD_ABS_LO12_NC: u32 = 277;
    pub const R_LDST8_ABS_LO12_NC: u32 = 278;
    pub const R_JUMP26: u32 = 282;
    pub const R_CALL26: u32 = 283;
    pub const R_LDST16_ABS_LO12_NC: u32 = 284;
    pub const R_LDST32_ABS_LO12_NC: u32 = 285;
    pub const R_LDST64_ABS_LO12_NC: u32 = 286;
    pub const R_LDST128_ABS_LO12_NC: u32 = 299;
}

/// Apply relocation `kind` for `machine` at `offset` within `section`, which will run at
/// address `section_addr`. `s` is the symbol's address and `a` the addend.
pub fn apply(
    machine: u16,
    kind: u32,
    section: &mut [u8],
    section_addr: u64,
    offset: u64,
    s: u64,
    a: i64,
) -> Result<(), RelocError> {
    let p = section_addr.wrapping_add(offset);
    let sa = s.wrapping_add(a as u64);
    match machine {
        EM_X86_64 => apply_x86_64(kind, section, offset, sa, p),
        EM_AARCH64 => apply_aarch64(kind, section, offset, sa, p),
        _ => Err(RelocError::Unsupported { machine, kind }),
    }
}

fn place<const N: usize>(section: &mut [u8], offset: u64) -> Result<&mut [u8; N], RelocError> {
    let bad = RelocError::OutOfSection { offset };
    let at = usize::try_from(offset).map_err(|_| bad)?;
    section
        .get_mut(at..at.checked_add(N).ok_or(bad)?)
        .and_then(|b| b.try_into().ok())
        .ok_or(bad)
}

fn apply_x86_64(
    kind: u32,
    section: &mut [u8],
    offset: u64,
    sa: u64,
    p: u64,
) -> Result<(), RelocError> {
    use x86_64::*;
    let overflow = RelocError::Overflow { kind, offset };
    match kind {
        R_NONE => {}
        R_64 => *place::<8>(section, offset)? = sa.to_le_bytes(),
        R_PC64 => *place::<8>(section, offset)? = sa.wrapping_sub(p).to_le_bytes(),
        R_PC32 | R_PLT32 => {
            // A PLT is not needed: the loader resolves the call straight to its target,
            // which is what a `PLT32` against a defined symbol means.
            let v = i32::try_from(sa.wrapping_sub(p) as i64).map_err(|_| overflow)?;
            *place::<4>(section, offset)? = v.to_le_bytes();
        }
        R_32 => {
            let v = u32::try_from(sa).map_err(|_| overflow)?;
            *place::<4>(section, offset)? = v.to_le_bytes();
        }
        R_32S => {
            let v = i32::try_from(sa as i64).map_err(|_| overflow)?;
            *place::<4>(section, offset)? = v.to_le_bytes();
        }
        // GOT-relative types need a GOT, and the module build's static relocation model
        // does not produce them. Refused by name, so a module that needs one says so.
        _ => {
            return Err(RelocError::Unsupported {
                machine: EM_X86_64,
                kind,
            });
        }
    }
    Ok(())
}

fn apply_aarch64(
    kind: u32,
    section: &mut [u8],
    offset: u64,
    sa: u64,
    p: u64,
) -> Result<(), RelocError> {
    use aarch64::*;
    let overflow = RelocError::Overflow { kind, offset };
    let patch = |section: &mut [u8], mask: u32, bits: u32| -> Result<(), RelocError> {
        let insn = place::<4>(section, offset)?;
        let old = u32::from_le_bytes(*insn);
        *insn = ((old & !mask) | (bits & mask)).to_le_bytes();
        Ok(())
    };
    match kind {
        R_NONE => {}
        R_ABS64 => *place::<8>(section, offset)? = sa.to_le_bytes(),
        R_PREL64 => *place::<8>(section, offset)? = sa.wrapping_sub(p).to_le_bytes(),
        R_ABS32 => {
            // Either signed or unsigned interpretation must fit, per the AArch64 ELF ABI.
            let v = sa as i64;
            if !(i32::MIN as i64..=u32::MAX as i64).contains(&v) {
                return Err(overflow);
            }
            *place::<4>(section, offset)? = (v as u32).to_le_bytes();
        }
        R_PREL32 => {
            let v = sa.wrapping_sub(p) as i64;
            if !(i32::MIN as i64..=u32::MAX as i64).contains(&v) {
                return Err(overflow);
            }
            *place::<4>(section, offset)? = (v as u32).to_le_bytes();
        }
        R_CALL26 | R_JUMP26 => {
            let v = sa.wrapping_sub(p) as i64;
            if v & 3 != 0 {
                return Err(RelocError::Misaligned { kind, offset });
            }
            // ±128 MiB: 26 bits of instruction count.
            if !(-(1 << 27)..(1 << 27)).contains(&v) {
                return Err(overflow);
            }
            patch(section, 0x03ff_ffff, (v >> 2) as u32)?;
        }
        R_ADR_PREL_PG_HI21 => {
            let v = ((sa & !0xfff) as i64).wrapping_sub((p & !0xfff) as i64) >> 12;
            if !(-(1 << 20)..(1 << 20)).contains(&v) {
                return Err(overflow);
            }
            let v = v as u32;
            // immlo in bits 29-30, immhi in bits 5-23.
            patch(
                section,
                0x6000_0000 | 0x00ff_ffe0,
                ((v & 3) << 29) | (((v >> 2) & 0x7ffff) << 5),
            )?;
        }
        R_ADD_ABS_LO12_NC | R_LDST8_ABS_LO12_NC => {
            patch(section, 0xfff << 10, ((sa & 0xfff) as u32) << 10)?;
        }
        R_LDST16_ABS_LO12_NC
        | R_LDST32_ABS_LO12_NC
        | R_LDST64_ABS_LO12_NC
        | R_LDST128_ABS_LO12_NC => {
            let shift = match kind {
                R_LDST16_ABS_LO12_NC => 1,
                R_LDST32_ABS_LO12_NC => 2,
                R_LDST64_ABS_LO12_NC => 3,
                _ => 4,
            };
            let lo = sa & 0xfff;
            if lo & ((1 << shift) - 1) != 0 {
                return Err(RelocError::Misaligned { kind, offset });
            }
            patch(section, 0xfff << 10, ((lo >> shift) as u32) << 10)?;
        }
        _ => {
            return Err(RelocError::Unsupported {
                machine: EM_AARCH64,
                kind,
            });
        }
    }
    Ok(())
}
