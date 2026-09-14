//! The last-known-good boot counter: the loader's half.
//!
//! Every boot is counted before it is attempted, in a non-volatile EFI variable, and the
//! kernel deletes the variable once its bring-up verdict is a pass
//! (`kernel/lastgood/uefi`). So the count is the number of boots in a row that never got
//! that far, however each one failed: a panic, a fault, a hang someone reset, a kernel
//! that never reached its first line. Past `FAILURES_BEFORE_SAFE` of them, the loader
//! starts the next boot in safe mode. See `docs/bootloader.md#failure-handling`.
//!
//! Counting happens first, before anything else in the boot path can fail, because a
//! boot that fails before it is counted is one the fallback never hears about.

use boot_protocol::uefi::boot_counter::{ATTRIBUTES, FAILURES_BEFORE_SAFE, NAME, VENDOR};

use crate::{Guid, Status, SystemTable};

/// This boot, as the counter saw it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attempt {
    /// This boot's number since the last confirmed one, counting from 1.
    pub number: u32,
    /// Whether enough boots before it went unconfirmed that this one is safe mode.
    pub safe: bool,
}

/// Count this boot, and say whether it is to be safe mode.
///
/// A variable of a size this code never writes is not a count, and is started over rather
/// than guessed at: the worst that does is give a failing kernel a few more tries before
/// the fallback.
///
/// # Safety
/// `st` must be the system table the firmware passed, with boot services not yet exited.
pub unsafe fn count(st: &SystemTable) -> Result<Attempt, Status> {
    // SAFETY: runtime services are live while boot services are, per the caller.
    let rt = unsafe { &*st.runtime_services };
    let name = NAME;
    let vendor = Guid(VENDOR.0, VENDOR.1, VENDOR.2, VENDOR.3);
    let mut bytes = [0u8; 4];
    let mut size = bytes.len();
    let mut attributes = 0u32;
    // SAFETY: a terminated name, a GUID and a buffer of `size` bytes, all on this stack.
    let s = unsafe {
        (rt.get_variable)(
            name.as_ptr(),
            &vendor,
            &mut attributes,
            &mut size,
            bytes.as_mut_ptr().cast(),
        )
    };
    let before = match s {
        Status::SUCCESS if size == bytes.len() => u32::from_le_bytes(bytes),
        Status::SUCCESS | Status::BUFFER_TOO_SMALL | Status::NOT_FOUND => 0,
        s => return Err(s),
    };
    let number = before.saturating_add(1);
    let data = number.to_le_bytes();
    // SAFETY: as above, with `data.len()` bytes of data to store.
    let s = unsafe {
        (rt.set_variable)(name.as_ptr(), &vendor, ATTRIBUTES, data.len(), data.as_ptr().cast())
    };
    s.ok()?;
    Ok(Attempt {
        number,
        safe: before >= FAILURES_BEFORE_SAFE,
    })
}
