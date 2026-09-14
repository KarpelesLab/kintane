#!/bin/zsh
cd /Users/magicaltux/projects/kintane/.claude/worktrees/agent-a7e84754da1434495
K=./kbuild/target/release/kbuild
cargo build --release --manifest-path kbuild/Cargo.toml >/dev/null 2>&1 || { echo "  KBUILD DOES NOT BUILD"; exit 1; }
cargo test --release --manifest-path kbuild/Cargo.toml 2>&1 | grep -E '^test result|^error' | sed 's/^/  kbuild-tests /'
$K test --preset x86_64-qemu > build/v-host.log 2>&1; echo "  host rc=$? $(grep -E 'unit\(s\):' build/v-host.log)"
for p in x86_64-qemu i686-qemu i686-large aarch64-virt i686-bios x86_64-bios x86_64-efi aarch64-virt-smp riscv32-virt armv7m-mps2 x86_64-qemu-smp armv7m-tiny aarch64-virt-gicv3 riscv32i-virt x86_64-efistub x86_64-iommu x86_64-isolated x86_64-isolated-smp; do
  $K run --preset $p --timeout 60 > build/v-run-$p.log 2>&1; echo "  boot      $p rc=$?"
done
for p in x86_64-qemu i686-qemu aarch64-virt i686-bios x86_64-bios x86_64-efi aarch64-virt-smp riscv32-virt armv7m-mps2 x86_64-qemu-smp armv7m-tiny aarch64-virt-gicv3 riscv32i-virt x86_64-efistub x86_64-iommu x86_64-isolated x86_64-isolated-smp; do
  $K test --target --preset $p --timeout 60 > build/v-kt-$p.log 2>&1; echo "  in-kernel $p rc=$? $(grep -aoE '[0-9]+ passed, [0-9]+ failed[^\n]*' build/v-kt-$p.log | tail -1)"
done
$K lint 2>&1 | tail -1
$K portability > build/v-port.log 2>&1; echo "  portability rc=$? $(grep -c 'units build' build/v-port.log) machines"
for f in $(git ls-files '*.rs' | grep -v '^kbuild/'); do rustup run nightly rustfmt --check --edition 2024 $f >/dev/null 2>&1 || echo "  unformatted: $f"; done
(cd kbuild && cargo fmt --check >/dev/null 2>&1 || echo "  kbuild unformatted")
for p in x86_64-qemu i686-qemu i686-large aarch64-virt i686-bios x86_64-bios x86_64-efi aarch64-virt-smp; do
  $K run --preset $p --set QEMU_EXIT=y --set STACK_GUARD_TEST=y --timeout 60 > build/v-guard-$p.log 2>&1; echo "  guard     $p rc=$?"
done
for spec in x86_64-qemu:FAULT i686-qemu:PANIC aarch64-virt:FAULT aarch64-virt:PANIC riscv32-virt:PANIC armv7m-mps2:FAULT riscv32i-virt:PANIC; do p=${spec%%:*}; k=${spec#*:}
  $K run --preset $p --set CRASH_$k=y --timeout 20 > build/v-crash-$p-$k.log 2>&1
  if grep -q 'symbolized backtrace' build/v-crash-$p-$k.log && grep -q 'kintane::crash::outer' build/v-crash-$p-$k.log && grep -q 'kernel/main/src/crash.rs:' build/v-crash-$p-$k.log; then echo "  crash     $p $k decoded"; else echo "  crash     $p $k NOT DECODED"; fi
done
for p in x86_64-qemu i686-qemu aarch64-virt; do
  $K run --preset $p --set QEMU_EXIT=y --set LOCKDEP_ABBA_TEST=y --timeout 60 > build/v-abba-$p.log 2>&1; echo "  abba      $p rc=$?"
done
for p in x86_64-qemu i686-qemu aarch64-virt i686-bios; do
  $K run --preset $p --set QEMU_EXIT=y --set THREAD_STACK_GUARD_TEST=y --timeout 60 > build/v-tguard-$p.log 2>&1; echo "  tguard    $p rc=$?"
  $K run --preset $p --set QEMU_EXIT=y --set NULL_DEREF_TEST=y --timeout 60 > build/v-null-$p.log 2>&1; echo "  null      $p rc=$?"
done
(cd /Users/magicaltux/projects/kintane/.claude/worktrees/agent-a7e84754da1434495 && ./kbuild/target/release/kbuild test --preset x86_64-efi > build/v-host-efi.log 2>&1; echo "  host-efi rc=$? $(grep -E "unit\(s\):" build/v-host-efi.log)")
for p in x86_64-qemu i686-qemu aarch64-virt x86_64-efi aarch64-virt-smp riscv32-virt i686-bios armv7m-mps2; do
  $K run --preset $p --set BOOT_MODE_SAFE=y --timeout 90 > build/v-safe-$p.log 2>&1; rc=$?
  grep -q "conservative: the loader's memory map follows" build/v-safe-$p.log && echo "  safe      $p rc=$rc" || echo "  safe      $p rc=$rc NO SAFE EFFECT"
done
for p in i686-bios x86_64-efi; do $K run --preset $p --set BOOT_MENU_TIMEOUT=30 --set BOOT_TEST_KEYS=2 --set BOOT_EXPECT_MODE=safe --timeout 120 > build/v-menu-$p.log 2>&1; echo "  menu      $p rc=$?"; done
for p in i686-bios x86_64-bios x86_64-efi; do $K run --preset $p --set CHAIN_TEST=y --timeout 120 > build/v-chain-$p.log 2>&1; echo "  chain     $p rc=$?"; done
for p in x86_64-qemu i686-qemu aarch64-virt aarch64-virt-smp x86_64-qemu-smp; do $K stress --preset $p --duration 20s > build/v-stress-$p.log 2>&1; echo "  stress    $p rc=$? $(grep -ac 'audit' build/v-stress-$p.log) audit lines"; done
for p in $(ls config/presets | sed "s/.preset//"); do $K size --preset $p > build/v-size-$p.log 2>&1 || echo "  size      $p OVER BUDGET or error"; done
for p in x86_64-qemu-smp aarch64-virt-smp; do $K stress --preset $p --set QEMU_CPUS=8 --duration 20s > build/v-stress8-$p.log 2>&1; echo "  stress8   $p rc=$? $(grep -ac 'audit' build/v-stress8-$p.log) audit lines"; done
for p in riscv32-virt riscv32i-virt; do for m in STACK_GUARD_TEST THREAD_STACK_GUARD_TEST; do $K run --preset $p --set QEMU_EXIT=y --set $m=y --timeout 60 > build/v-pmp-$p-$m.log 2>&1; echo "  pmp       $p $m rc=$?"; done; done
$K run --preset x86_64-efistub --set BOOT_COUNTER_TEST=y --timeout 300 > build/v-counter.log 2>&1; echo "  counter   x86_64-efistub rc=$?"
