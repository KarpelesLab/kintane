#!/usr/bin/env python3
"""Extract the RSDP and every table the root table lists from a QEMU physical memory dump.

Output records, little-endian: u64 physical address, u32 length, then the bytes. The RSDP
is the first record. Tables referenced from inside other tables (the FADT's DSDT and FACS)
are included too, so the fixture is the firmware's whole ACPI table set.
"""
import struct
import sys

mem = open(sys.argv[1], "rb").read()
out = open(sys.argv[2], "wb")


def cksum(b):
    return sum(b) & 0xFF


rsdp = None
for addr in range(0xE0000, 0x100000, 16):
    if mem[addr:addr + 8] == b"RSD PTR " and cksum(mem[addr:addr + 20]) == 0:
        rsdp = addr
        break
if rsdp is None:
    # UEFI firmware publishes the RSDP through the system table, not the BIOS area.
    addr = mem.find(b"RSD PTR ")
    while addr >= 0:
        if cksum(mem[addr:addr + 20]) == 0 and mem[addr + 15] >= 2 \
                and cksum(mem[addr:addr + 36]) == 0:
            rsdp = addr
            break
        addr = mem.find(b"RSD PTR ", addr + 1)
assert rsdp is not None, "no RSDP"
rev = mem[rsdp + 15]
rlen = struct.unpack_from("<I", mem, rsdp + 20)[0] if rev >= 2 else 20
records = [(rsdp, mem[rsdp:rsdp + rlen])]
print(f"RSDP at {rsdp:#x} rev {rev}")

seen = set()


def table(addr):
    if addr == 0 or addr in seen or addr + 8 > len(mem):
        return
    seen.add(addr)
    sig = mem[addr:addr + 4]
    if sig == b"FACS":
        ln = struct.unpack_from("<I", mem, addr + 4)[0]
    else:
        ln = struct.unpack_from("<I", mem, addr + 4)[0]
    body = mem[addr:addr + ln]
    records.append((addr, body))
    print(f"  {sig.decode()} at {addr:#x} len {ln}")
    if sig == b"FACP":
        if ln >= 44:
            table(struct.unpack_from("<I", mem, addr + 36)[0])  # FACS
            table(struct.unpack_from("<I", mem, addr + 40)[0])  # DSDT
    return sig


rsdt = struct.unpack_from("<I", mem, rsdp + 16)[0]
xsdt = struct.unpack_from("<Q", mem, rsdp + 24)[0] if rev >= 2 else 0
for root, width in ((rsdt, 4), (xsdt, 8)):
    if root == 0:
        continue
    table(root)
    ln = struct.unpack_from("<I", mem, root + 4)[0]
    for off in range(36, ln, width):
        fmt = "<I" if width == 4 else "<Q"
        table(struct.unpack_from(fmt, mem, root + off)[0])

for addr, body in records:
    out.write(struct.pack("<QI", addr, len(body)))
    out.write(body)
