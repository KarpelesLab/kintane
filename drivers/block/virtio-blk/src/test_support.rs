//! The block half of the fake device: virtio-blk requests answered against a RAM disk.
//!
//! The device side of a queue is shared with every virtio driver (`virtio::fake`); what a
//! block device does with a chain is this driver's, so it lives here.

pub use virtio::fake::{Backing, FakeDevice, View};

/// Answer one virtio-blk request against `disk`, as QEMU's device would.
///
/// Returns `false` if the driver published nothing. The status byte is the last
/// buffer of the chain, and the request header the first, which is the layout virtio
/// 1.1 §5.2.6 requires and this therefore checks.
pub fn serve_block(device: &mut FakeDevice, disk: &mut [u8], fail: bool) -> bool {
    const SECTOR: usize = 512;
    let Some(chain) = device.take_available() else {
        return false;
    };
    assert!(chain.buffers.len() >= 2, "a request is at least a header and a status");
    let header = chain.buffers[0];
    assert_eq!(header.len, 16, "the header is 16 bytes");
    assert!(!header.device_writes, "the device reads the header");
    let h = device.region(header.phys, 16);
    let kind = h.read32(0);
    let sector = u64::from(h.read32(8)) | (u64::from(h.read32(12)) << 32);

    let status = *chain.buffers.last().expect("checked above");
    assert_eq!(status.len, 1, "the status is one byte");
    assert!(status.device_writes, "the device writes the status");

    let data = &chain.buffers[1..chain.buffers.len() - 1];
    let mut at = usize::try_from(sector).unwrap() * SECTOR;
    let mut written = 0u32;
    let mut ok = true;
    for buf in data {
        let len = buf.len as usize;
        let region = device.region(buf.phys, len);
        match kind {
            // VIRTIO_BLK_T_IN: the device writes the data.
            0 => {
                assert!(buf.device_writes, "a read's data buffer must be device-writable");
                if at + len > disk.len() {
                    ok = false;
                    break;
                }
                let bytes: Vec<u8> = disk[at..at + len].to_vec();
                region.write_bytes(0, &bytes);
                written += buf.len;
            }
            // VIRTIO_BLK_T_OUT: the device reads it.
            1 => {
                assert!(!buf.device_writes, "a write's data buffer must be device-readable");
                if at + len > disk.len() {
                    ok = false;
                    break;
                }
                let mut bytes = vec![0u8; len];
                region.read_bytes(0, &mut bytes);
                disk[at..at + len].copy_from_slice(&bytes);
            }
            // VIRTIO_BLK_T_FLUSH: nothing to do for a RAM disk.
            4 => {}
            _ => ok = false,
        }
        at += len;
    }
    let status_region = device.region(status.phys, 1);
    // 0 is OK, 1 is IOERR (virtio 1.1 §5.2.6).
    status_region.write8(0, if ok && !fail { 0 } else { 1 });
    device.complete(chain.head, written + 1);
    true
}
