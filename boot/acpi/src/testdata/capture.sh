#!/bin/zsh
# Dump QEMU guest physical memory once firmware has built its ACPI tables, and extract
# the tables into the fixture format the `acpi` unit's host tests read.
#
# No kernel runs: the firmware builds the tables and then fails to find anything to boot,
# and memory is saved through the monitor while it waits. Run from anywhere; writes
# `q35.bin`, `pc.bin` and `q35-ovmf.bin` beside this script.
set -e
cd "$(dirname "$0")"
QEMU_SHARE=$(dirname $(dirname $(command -v qemu-system-x86_64)))/share/qemu
run() {
  bin=$1; mach=$2; out=$3; wait=$4; shift 4
  rm -f $out.fifo; mkfifo $out.fifo
  $bin -machine $mach -smp 2 -m 128M -display none -serial none -monitor stdio "$@" \
    < $out.fifo > $out.log 2>&1 &
  pid=$!
  exec 3> $out.fifo
  sleep $wait
  # A relative name: the monitor parses `/` in an unquoted argument as division.
  print -u3 "pmemsave 0 134217728 \"$out.mem\""
  sleep 3
  print -u3 "quit"
  exec 3>&-
  wait $pid
  rm -f $out.fifo $out.log
  python3 extract.py $out.mem $out.bin
  rm -f $out.mem
}
# The same bridge and test device the x86 presets add (QEMU_PCI_TEST_DEVICE).
run qemu-system-x86_64 q35 q35 4 \
  -device pcie-root-port,id=kt_rp,chassis=1 -device pci-testdev,bus=kt_rp
run qemu-system-i386 pc pc 4 \
  -device pci-bridge,id=kt_br,chassis_nr=1 -device pci-testdev,bus=kt_br,addr=3
cp $QEMU_SHARE/edk2-i386-vars.fd ovmf-vars.fd
run qemu-system-x86_64 q35 q35-ovmf 15 \
  -drive if=pflash,format=raw,unit=0,readonly=on,file=$QEMU_SHARE/edk2-x86_64-code.fd \
  -drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
  -device pcie-root-port,id=kt_rp,chassis=1 -device pci-testdev,bus=kt_rp
rm -f ovmf-vars.fd
