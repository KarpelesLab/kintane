//! Running a built image under QEMU.
//!
//! One canonical invocation per target, derived from the configuration rather than
//! typed by hand. See `docs/testing.md` — in particular the result channels, which
//! exist so that a test's verdict never has to be scraped out of console output.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::kcfg::Resolution;

pub struct Machine {
    pub binary: &'static str,
    pub args: Vec<String>,
    /// Exit code QEMU reports when the guest signalled success.
    pub success_code: i32,
    /// Bytes typed on the guest's serial console as it starts: `BOOT_TEST_KEYS`.
    pub input: Vec<u8>,
    /// Whether to answer the kernel's serial receive check (`SERIAL_IRQ_TEST`): type each
    /// of [`SERIAL_PROBES`] when the kernel prints its prompt.
    pub serial_probe: bool,
    /// The loopback ports the kernel's network check (`QEMU_NET_TEST`) is reached on, which
    /// [`run_watched`] serves: see [`udp_peer`], [`tcp_service`] and [`relay`].
    pub net_port: Option<NetPorts>,
}

pub fn machine_for(res: &Resolution, image: &Path, log: &Path) -> Result<Machine, String> {
    // A kernel built for fewer CPUs than the guest has starts only the first `NR_CPUS`, so
    // its SMP checks would pass or fail on a machine other than the one asked for. Only
    // with SMP: a uniprocessor PC build is given two CPUs on purpose, so its firmware
    // describes more than one and a MADT walk that stops early cannot pass.
    if res.is_on("SMP") && res.int("QEMU_CPUS") > res.int("NR_CPUS") {
        return Err(format!(
            "QEMU_CPUS={} is more than NR_CPUS={}: the kernel would start only {} of them\n  \
             raise NR_CPUS, which also sizes the thread-stack array, or lower QEMU_CPUS",
            res.int("QEMU_CPUS"),
            res.int("NR_CPUS"),
            res.int("NR_CPUS")
        ));
    }
    let s = |x: &str| x.to_string();
    let net_port = net_port(res)?;
    let mem = format!("{}M", {
        let m = res.int("QEMU_MEMORY_MB");
        if m > 0 { m } else { 128 }
    });
    let cpu = {
        let c = res.str("QEMU_CPU");
        if c.is_empty() {
            "max".to_string()
        } else {
            c.to_string()
        }
    };

    if res.is_on("ARCH_X86_64") && (res.is_on("KINBOOT_EFI") || res.is_on("KINBOOT_STUB")) {
        // The firmware path: OVMF boots the disk image's EFI system partition. With
        // KINBOOT_EFI that starts kinboot-efi, which starts the kernel; with KINBOOT_STUB
        // the application it starts is the kernel. No -kernel either way: QEMU's own
        // loader is exactly what these configurations exist to not use.
        let fw = uefi_firmware(log.parent().unwrap_or(Path::new(".")))?;
        // No `phys-bits` override, on purpose. OVMF places its 64-bit PCI window from the
        // CPU's address width, and at TCG's 40 bits a 64-bit BAR — virtio-pci's is one —
        // lands at 768 GiB, inside x86_64's user half. That is the machine that showed
        // device windows must not be mapped at their physical address, where such a BAR is
        // a top-level entry every process mirrors. The kernel maps them in the device
        // window above the user half now, and this run is what keeps that true.
        let mut args = vec![
            s("-machine"),
            s("q35"),
            s("-cpu"),
            cpu.clone(),
            s("-m"),
            mem,
            s("-drive"),
            format!("if=pflash,format=raw,unit=0,readonly=on,file={}", fw.code.display()),
        ];
        if let Some(vars) = &fw.vars {
            args.push(s("-drive"));
            args.push(format!("if=pflash,format=raw,unit=1,file={}", vars.display()));
        }
        args.extend([
            // snapshot=on: the guest writes to an overlay, so the image on disk stays
            // the bytes the build produced.
            s("-drive"),
            format!("format=raw,snapshot=on,file={}", image.display()),
        ]);
        args.extend(x86_platform(res, "q35", image, net_port));
        args.extend([
            s("-device"),
            s("isa-debug-exit,iobase=0xf4,iosize=0x04"),
            s("-serial"),
            s("stdio"),
            s("-display"),
            s("none"),
            // Guest errors only, not every interrupt: the firmware takes thousands of
            // timer interrupts before the kernel runs, and logging each one would bury
            // the kernel's few in megabytes of OVMF.
            s("-d"),
            s("guest_errors,cpu_reset"),
            s("-D"),
            log.display().to_string(),
        ]);
        // A reset ends the run, except in the boot counter test, which is a sequence of
        // boots of one machine: its variable store must live through the resets it counts.
        if !res.is_on("BOOT_COUNTER_TEST") {
            args.push(s("-no-reboot"));
        }
        return Ok(Machine {
            binary: "qemu-system-x86_64",
            args,
            success_code: (0x10 << 1) | 1,
            input: res.str("BOOT_TEST_KEYS").as_bytes().to_vec(),
            serial_probe: res.is_on("SERIAL_IRQ_TEST"),
            net_port,
        });
    }

    if res.is_on("ARCH_X86_64") {
        // With an IOMMU, interrupt remapping needs the split irqchip: the I/O APIC is
        // emulated in userspace so remapped interrupts pass through the IOMMU.
        let machine = if res.is_on("IOMMU") {
            "q35,kernel-irqchip=split"
        } else {
            "q35"
        };
        // isa-debug-exit reports (value << 1) | 1, so the guest can never produce 0
        // and "QEMU exited for its own reasons" is never mistaken for a pass.
        return Ok(Machine {
            binary: "qemu-system-x86_64",
            args: vec![
                s("-machine"),
                s(machine),
                s("-cpu"),
                cpu,
                s("-m"),
                mem,
                s("-device"),
                s("isa-debug-exit,iobase=0xf4,iosize=0x04"),
                s("-serial"),
                s("stdio"),
                s("-display"),
                s("none"),
                // A triple fault must be a visible failure, not a reboot loop that
                // reads as a timeout.
                //
                // Note the absence of -no-shutdown, which looks like it belongs here
                // and does not: it keeps QEMU alive across a guest shutdown, which
                // suppresses isa-debug-exit and turns every passing test into a
                // timeout.
                s("-no-reboot"),
                // Exception and guest-error tracing goes to a file, not stderr, so a
                // failure leaves evidence without burying the console output.
                s("-d"),
                s("int,guest_errors"),
                s("-D"),
                log.display().to_string(),
            ]
            .into_iter()
            .chain(x86_platform(res, "q35", image, net_port))
            .chain(x86_boot_media(res, image))
            .collect(),
            success_code: (0x10 << 1) | 1,
            input: res.str("BOOT_TEST_KEYS").as_bytes().to_vec(),
            serial_probe: res.is_on("SERIAL_IRQ_TEST"),
            net_port,
        });
    }

    if res.is_on("ARCH_I686") {
        return Ok(Machine {
            binary: "qemu-system-i386",
            args: vec![
                // i440FX rather than q35: this target exists for legacy PCs, and
                // testing it on a modern chipset would defeat the point.
                s("-machine"),
                s("pc"),
                s("-cpu"),
                cpu,
                s("-m"),
                mem,
                s("-device"),
                s("isa-debug-exit,iobase=0xf4,iosize=0x04"),
                s("-serial"),
                s("stdio"),
                s("-display"),
                s("none"),
                s("-no-reboot"),
                s("-d"),
                s("int,guest_errors"),
                s("-D"),
                log.display().to_string(),
            ]
            .into_iter()
            .chain(x86_platform(res, "pc", image, net_port))
            .chain(x86_boot_media(res, image))
            .collect(),
            success_code: (0x10 << 1) | 1,
            input: res.str("BOOT_TEST_KEYS").as_bytes().to_vec(),
            serial_probe: res.is_on("SERIAL_IRQ_TEST"),
            net_port,
        });
    }

    if res.is_on("ARCH_AARCH64") {
        // `-smp` only when asked, so a one-CPU preset's command line is what it was.
        let smp = match res.int("QEMU_CPUS") {
            n if n > 1 => vec![s("-smp"), n.to_string()],
            _ => Vec::new(),
        };
        return Ok(Machine {
            binary: "qemu-system-aarch64",
            args: [
                s("-machine"),
                s("virt,gic-version=3"),
                s("-cpu"),
                cpu,
                s("-m"),
                mem,
            ]
            .into_iter()
            .chain(smp)
            .chain(block_disk(res, image, "virtio-blk-device"))
            .chain(net_card(res, "virtio-net-device", net_port))
            .chain([
                s("-kernel"),
                image.display().to_string(),
                // QEMU writes this into the device tree's `/chosen/bootargs`.
                s("-append"),
                crate::bootcfg::kernel_command_line(res),
                s("-semihosting-config"),
                s("enable=on,target=native"),
                s("-serial"),
                s("stdio"),
                s("-display"),
                s("none"),
                s("-no-reboot"),
                s("-d"),
                s("int,guest_errors"),
                s("-D"),
                log.display().to_string(),
            ])
            .collect(),
            success_code: 0,
            input: res.str("BOOT_TEST_KEYS").as_bytes().to_vec(),
            serial_probe: res.is_on("SERIAL_IRQ_TEST"),
            net_port,
        });
    }

    if res.is_on("ARCH_RISCV32") {
        // The hart. rv32imac runs on `virt`'s default. The no-atomics image must run on a
        // hart that refuses what it avoids, so it gets `rv32` with the A extension switched
        // off — and Zawrs, which QEMU refuses to keep without it — and M and C with them:
        // an atomic, multiply, divide or compressed instruction is then illegal. Not
        // `-cpu rv32i`: QEMU's `rv32i` model has no Zicsr either, and a machine-mode kernel
        // cannot run without CSRs; its first instruction, `csrw mie, zero`, traps.
        let cpu = if res.is_on("RISCV32_NO_ATOMICS") {
            vec![
                s("-cpu"),
                s(concat!(
                    "rv32,a=false,zawrs=false,",
                    "m=false,zmmul=false,",
                    "c=false,zca=false,zcf=false,zcd=false"
                )),
            ]
        } else {
            Vec::new()
        };
        return Ok(Machine {
            binary: "qemu-system-riscv32",
            args: [
                // No firmware: the reset vector jumps straight to the image in M-mode,
                // with the hart ID in a0 and the device tree in a1. `virt` always has
                // the sifive_test finisher, which is the result channel.
                s("-machine"),
                s("virt"),
            ]
            .into_iter()
            .chain(cpu)
            .chain([
                s("-bios"),
                s("none"),
                s("-m"),
                mem,
                s("-kernel"),
                image.display().to_string(),
                // QEMU writes this into the device tree's `/chosen/bootargs`.
                s("-append"),
                crate::bootcfg::kernel_command_line(res),
                s("-serial"),
                s("stdio"),
                s("-display"),
                s("none"),
                s("-no-reboot"),
                s("-d"),
                s("int,guest_errors"),
                s("-D"),
                log.display().to_string(),
            ])
            .collect(),
            // sifive_test's pass value powers off with status 0, like aarch64's
            // semihosting, and the harness treats a timeout as a failure for the same
            // reason.
            success_code: 0,
            input: res.str("BOOT_TEST_KEYS").as_bytes().to_vec(),
            serial_probe: res.is_on("SERIAL_IRQ_TEST"),
            net_port: None,
        });
    }

    if res.is_on("ARCH_ARMV7M") {
        return Ok(crate::qemu_armv7m::machine(res, image, log));
    }

    Err("no QEMU machine is defined for this configuration".into())
}

/// The test disk, attached to a virtio-blk device of the given kind, when the
/// configuration asks for it.
///
/// `snapshot=on` keeps a run's writes off the file, so every boot reads the bytes kbuild
/// wrote and the image stays reproducible. On `virt` a `virtio-blk-device` lands in one of
/// the memory-mapped virtio slots the device tree already lists; which one is for the
/// kernel's enumeration to find out, not for this command line to promise.
fn block_disk(res: &Resolution, image: &Path, device: &str) -> Vec<String> {
    if !res.is_on(crate::testdisk::SYMBOL) {
        return Vec::new();
    }
    let disk = crate::testdisk::beside(image);
    // With an IOMMU in front of it, the device's DMA goes through the platform IOMMU: it
    // negotiates VIRTIO_F_ACCESS_PLATFORM and treats descriptor addresses as device
    // addresses the IOMMU translates. QEMU refuses the handshake unless `iommu_platform=on`
    // is set on a PCI virtio device here.
    let device = if res.is_on("IOMMU") && device.starts_with("virtio-blk-pci") {
        format!("{device},iommu_platform=on")
    } else {
        device.to_string()
    };
    let mut args = vec![
        "-drive".to_string(),
        format!("file={},if=none,id=kt_disk,format=raw,snapshot=on", disk.display()),
        "-device".to_string(),
        format!("{device},drive=kt_disk"),
    ];
    // QEMU's memory-mapped virtio transport presents the legacy (version 1) register
    // layout unless told otherwise, and the driver speaks only virtio 1.x. Found when the
    // first boot with a disk attached reported the slot as legacy and bound nothing.
    if device == "virtio-blk-device" {
        args.extend([
            "-global".to_string(),
            "virtio-mmio.force-legacy=false".to_string(),
        ]);
    }
    args
}

/// The processors and devices an x86 guest's firmware describes, beyond the chipset's
/// own: `-smp` from `QEMU_CPUS`, with `QEMU_PCI_TEST_DEVICE` a pci-testdev behind a
/// bridge (a PCI Express root port on q35, a PCI-to-PCI bridge on pc), which enumeration
/// finds only by following the bridge, with `QEMU_BLOCK_TEST` the test disk on a PCI
/// virtio-blk function, and with `QEMU_NET_TEST` a virtio-net function on the user-mode
/// network. `docs/testing.md` lists what the kernel checks.
///
/// `disable-legacy=on`: the driver speaks virtio 1.x, and a transitional device would
/// offer the legacy interface as well. Saying so here makes the device modern-only, which
/// is what the driver's refusal of a legacy device would otherwise turn into a boot
/// failure — the same trap the memory-mapped transport hit with `force-legacy`.
fn x86_platform(
    res: &Resolution,
    chipset: &str,
    image: &Path,
    net_port: Option<NetPorts>,
) -> Vec<String> {
    let mut args = vec!["-smp".to_string(), res.int("QEMU_CPUS").max(1).to_string()];
    // The IOMMU device must be created before the PCI devices it governs, so it goes first.
    // `intremap=on` needs the split irqchip the machine line asks for.
    if res.is_on("IOMMU") {
        args.extend(["-device".to_string(), "intel-iommu,intremap=on".to_string()]);
    }
    args.extend(block_disk(res, image, "virtio-blk-pci,disable-legacy=on"));
    // On `pc`, slot 0x1e: the chipset routes its INTA to a different line from the disk's
    // function, and a line has one handler (`device::Handlers`), so the two cannot share.
    // On q35 no PCI line is trusted (`PCI_LINE_TRUSTED`) and the card is polled wherever
    // it lands.
    let nic = if chipset == "q35" {
        "virtio-net-pci,disable-legacy=on,romfile="
    } else {
        "virtio-net-pci,disable-legacy=on,romfile=,addr=0x1e"
    };
    args.extend(net_card(res, nic, net_port));
    if res.is_on("QEMU_PCI_TEST_DEVICE") {
        let (bridge, device) = if chipset == "q35" {
            ("pcie-root-port,id=kt_bridge,chassis=1", "pci-testdev,bus=kt_bridge")
        } else {
            ("pci-bridge,id=kt_bridge,chassis_nr=1", "pci-testdev,bus=kt_bridge,addr=3")
        };
        args.extend([
            "-device".to_string(),
            bridge.to_string(),
            "-device".to_string(),
            device.to_string(),
        ]);
    }
    args
}

/// The guest port the kernel's network check listens on, and the messages it exchanges with
/// [`udp_peer`]: `kernel/main/src/net.rs`'s `PORT`, `PROBE`, `ECHO` and `ACK`.
const NET_GUEST_PORT: u16 = 5555;
const NET_PROBE: &[u8] = b"kintane-udp-probe";
const NET_ECHO: &[u8] = b"kintane-udp-echo ";
const NET_ACK: &[u8] = b"kintane-udp-ack ";

/// How often [`udp_peer`] sends its probe.
const NET_PROBE_EVERY: std::time::Duration = std::time::Duration::from_millis(250);

/// [`tcp_service`]'s protocol, and the datagram that tells the guest its port:
/// `kernel/main/src/net.rs`'s `TCP_ANNOUNCE`, `TCP_REQUEST` and `TCP_REPLY`.
const NET_TCP_ANNOUNCE: &[u8] = b"kintane-tcp-port ";
const NET_TCP_REQUEST: &[u8] = b"kintane-tcp-request ";
const NET_TCP_REPLY: &[u8] = b"kintane-tcp-reply ";

/// The loopback ports a run with a network card is served on: the UDP port QEMU forwards to
/// the guest, the TCP port of [`tcp_service`], which the guest reaches at the gateway's
/// address, and the two ports of [`relay`], which QEMU connects to.
#[derive(Clone, Copy, Debug)]
pub struct NetPorts {
    pub udp: u16,
    pub tcp: u16,
    pub relay_out: u16,
    pub relay_in: u16,
}

/// Free loopback ports for the guest's network check, when the configuration attaches a card.
///
/// Found by binding port 0 and letting the sockets go, so another process could take one in
/// between. Binding it again then fails, or QEMU refuses to start, and either says why, which
/// is a visible failure rather than a wrong answer. The three TCP ports are held together
/// while they are found, so they are three different ports.
fn net_port(res: &Resolution) -> Result<Option<NetPorts>, String> {
    if !res.is_on("QEMU_NET_TEST") {
        return Ok(None);
    }
    let udp = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map_err(|e| format!("no loopback UDP port for the network check: {e}"))?
        .port();
    let tcp = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("no loopback TCP port for the network check: {e}"))
    };
    let port = |l: &std::net::TcpListener| {
        l.local_addr()
            .map(|a| a.port())
            .map_err(|e| format!("no loopback TCP port for the network check: {e}"))
    };
    let (service, out, inject) = (tcp()?, tcp()?, tcp()?);
    Ok(Some(NetPorts {
        udp,
        tcp: port(&service)?,
        relay_out: port(&out)?,
        relay_in: port(&inject)?,
    }))
}

/// A virtio-net card of the given kind on QEMU's user-mode network, when the configuration
/// asks for one.
///
/// `-netdev user` is QEMU's own NAT: no privileges and no host network, and its gateway,
/// 10.0.2.2, answers ARP and echo requests itself. `hostfwd` forwards the loopback UDP port
/// to the guest's check, which is how [`udp_peer`] reaches it; a TCP connection the guest
/// makes to the gateway's address reaches the host's loopback interface, which is how it
/// reaches [`tcp_service`]. `romfile=` on the PCI card leaves out its boot ROM, so firmware
/// does not offer to boot from the network.
///
/// Every frame the card sends goes through [`relay`] before QEMU's network sees it: two
/// `filter-redirector`s on the network, one handing frames to kbuild on a socket and one
/// taking them back from another. The injecting filter is declared first. Frames a guest
/// sends pass a network's filters last to first, so they meet the redirecting filter first,
/// and what the injecting one passes on goes to the network rather than round again.
fn net_card(res: &Resolution, device: &str, ports: Option<NetPorts>) -> Vec<String> {
    let Some(ports) = ports else {
        return Vec::new();
    };
    let mut args = vec![
        "-netdev".to_string(),
        format!("user,id=kt_net,hostfwd=udp:127.0.0.1:{}-:{NET_GUEST_PORT}", ports.udp),
        "-chardev".to_string(),
        format!("socket,id=kt_relay_out,host=127.0.0.1,port={}", ports.relay_out),
        "-chardev".to_string(),
        format!("socket,id=kt_relay_in,host=127.0.0.1,port={}", ports.relay_in),
        "-object".to_string(),
        "filter-redirector,id=kt_net_in,netdev=kt_net,queue=rx,indev=kt_relay_in".to_string(),
        "-object".to_string(),
        "filter-redirector,id=kt_net_out,netdev=kt_net,queue=rx,outdev=kt_relay_out".to_string(),
        "-device".to_string(),
        format!("{device},netdev=kt_net"),
    ];
    // As for the disk, the memory-mapped transport is legacy unless told otherwise; once is
    // enough when the disk's arguments already say it.
    if device == "virtio-net-device" && !res.is_on(crate::testdisk::SYMBOL) {
        args.extend([
            "-global".to_string(),
            "virtio-mmio.force-legacy=false".to_string(),
        ]);
    }
    args
}

/// kbuild's side of the kernel's network check: a UDP peer on the loopback interface.
///
/// From the moment QEMU starts until `stop`, it sends [`NET_PROBE`] to the forwarded port
/// four times a second, so a probe is waiting whenever the check first looks. Nothing reads
/// the console for it: a probe that arrives before the guest listens is dropped, and the
/// next one comes a quarter of a second later. Every `NET_ECHO <n>` that comes back is
/// answered with `NET_ACK <n>`, which is what makes the check a round trip rather than a
/// delivery in one direction. Each probe is followed by [`NET_TCP_ANNOUNCE`] and the port of
/// [`tcp_service`], which the guest cannot otherwise know.
///
/// It answers; it does not judge. The verdict is still the guest's exit code.
fn udp_peer(
    port: u16,
    tcp_port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use std::io::ErrorKind;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    std::thread::spawn(move || {
        let Ok(socket) = std::net::UdpSocket::bind("127.0.0.1:0") else {
            return;
        };
        if socket.connect(("127.0.0.1", port)).is_err()
            || socket
                .set_read_timeout(Some(Duration::from_millis(50)))
                .is_err()
        {
            return;
        }
        let mut last: Option<Instant> = None;
        let mut buf = [0u8; 512];
        let announce = [NET_TCP_ANNOUNCE, tcp_port.to_string().as_bytes()].concat();
        while !stop.load(Ordering::Relaxed) {
            if last.is_none_or(|t| t.elapsed() >= NET_PROBE_EVERY) {
                let _ = socket.send(NET_PROBE);
                let _ = socket.send(&announce);
                last = Some(Instant::now());
            }
            match socket.recv(&mut buf) {
                Ok(n) => {
                    if let Some(number) = buf[..n].strip_prefix(NET_ECHO) {
                        let _ = socket.send(&[NET_ACK, number].concat());
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                // Refused, most likely: QEMU has not bound the port yet. Go round again.
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    })
}

/// kbuild's side of the kernel's TCP checks: a TCP service on the loopback interface.
///
/// The guest connects to the gateway's address at this port, which QEMU's user network turns
/// into a connection to the host's loopback interface. Each connection is answered by
/// [`serve_tcp`] on a thread of its own, until `stop`.
fn tcp_service(
    listener: std::net::TcpListener,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use std::sync::atomic::Ordering;
    std::thread::spawn(move || {
        if listener.set_nonblocking(true).is_err() {
            return;
        }
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    std::thread::spawn(move || serve_tcp(stream));
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    })
}

/// Answer one connection: read a `NET_TCP_REQUEST <mode> <tag>` line and write the same line
/// back with `NET_TCP_REPLY` in front, then close in the order the mode asks. `peer-closes`
/// closes this end at once; `guest-closes` waits for the guest's close first. Either way the
/// connection is dropped only once the guest has closed its end too, so both closes are
/// orderly.
fn serve_tcp(mut stream: std::net::TcpStream) {
    use std::time::Duration;
    let ready = stream.set_nonblocking(false).is_ok()
        && stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .is_ok();
    if !ready {
        return;
    }
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\n") {
        if request.len() > 256 || !matches!(stream.read(&mut byte), Ok(1)) {
            return;
        }
        request.push(byte[0]);
    }
    let Some(rest) = request.strip_prefix(NET_TCP_REQUEST) else {
        return;
    };
    if stream.write_all(&[NET_TCP_REPLY, rest].concat()).is_err() {
        return;
    }
    if rest.starts_with(b"peer-closes ") {
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
    // The guest sends nothing after its request: the next read is its close.
    let mut rest = [0u8; 256];
    while matches!(stream.read(&mut rest), Ok(n) if n > 0) {}
}

/// kbuild's relay between the card and QEMU's network: every frame the guest sends arrives on
/// `from_guest`'s connection, framed as QEMU's `filter-redirector` frames it (a big-endian
/// `u32` length, then the frame), and goes back out on `to_network`'s the same way. All but
/// one kind: the first data segment of each connection to [`tcp_service`], which is dropped the
/// first time it is seen, so the guest must send it again. That is what makes a retransmission
/// something the kernel's checks can require rather than hope for.
///
/// Ends when QEMU closes its end, or at `stop` if QEMU never connected.
fn relay(
    from_guest: std::net::TcpListener,
    to_network: std::net::TcpListener,
    tcp_port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let Some(mut from_guest) = accept_until(&from_guest, &stop) else {
            return;
        };
        let Some(mut to_network) = accept_until(&to_network, &stop) else {
            return;
        };
        let mut connections = std::collections::HashMap::new();
        let mut len = [0u8; 4];
        let mut frame = vec![0u8; 1 << 16];
        while from_guest.read_exact(&mut len).is_ok() {
            let n = u32::from_be_bytes(len) as usize;
            if n > frame.len() || from_guest.read_exact(&mut frame[..n]).is_err() {
                break;
            }
            if first_data_segment(&frame[..n], tcp_port, &mut connections) {
                continue;
            }
            let passed = to_network
                .write_all(&len)
                .and_then(|()| to_network.write_all(&frame[..n]));
            if passed.is_err() {
                break;
            }
        }
    })
}

/// The first connection `listener` takes, or `None` if `stop` comes first.
fn accept_until(
    listener: &std::net::TcpListener,
    stop: &std::sync::atomic::AtomicBool,
) -> Option<std::net::TcpStream> {
    use std::sync::atomic::Ordering;
    listener.set_nonblocking(true).ok()?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                // An accepted socket inherits non-blocking mode on some hosts.
                stream.set_nonblocking(false).ok()?;
                let _ = stream.set_nodelay(true);
                return Some(stream);
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    None
}

/// Whether `frame` is the first data segment of a connection to `tcp_port`, seen for the first
/// time: the one frame [`relay`] drops. `connections` maps a guest port to the initial sequence
/// number its latest SYN carried and whether that connection's first data segment has been
/// dropped yet.
fn first_data_segment(
    frame: &[u8],
    tcp_port: u16,
    connections: &mut std::collections::HashMap<u16, (u32, bool)>,
) -> bool {
    let be16 = |at: usize| {
        frame
            .get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    };
    let (Some(0x0800), Some(&version_ihl), Some(&6)) = (be16(12), frame.get(14), frame.get(23))
    else {
        return false;
    };
    let ihl = usize::from(version_ihl & 0x0f) * 4;
    let tcp = 14 + ihl;
    if be16(tcp + 2) != Some(tcp_port) {
        return false;
    }
    let (Some(total), Some(src), Some(seq), Some(&offset), Some(&flags)) = (
        be16(16),
        be16(tcp),
        frame
            .get(tcp + 4..tcp + 8)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
        frame.get(tcp + 12),
        frame.get(tcp + 13),
    ) else {
        return false;
    };
    let payload = usize::from(total).saturating_sub(ihl + usize::from(offset >> 4) * 4);
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    if flags & (SYN | ACK) == SYN {
        connections.insert(src, (seq, false));
        return false;
    }
    match connections.get_mut(&src) {
        Some((isn, dropped)) if payload > 0 && !*dropped && seq == isn.wrapping_add(1) => {
            *dropped = true;
            true
        }
        _ => false,
    }
}

/// How an x86 guest gets its kernel: straight from QEMU's multiboot loader, or from a
/// raw disk through the BIOS and `kinboot-bios`, with no `-kernel` at all.
///
/// The disk boot adds `-boot reboot-timeout=0`. When the BIOS finds nothing bootable, or
/// the loader gives up through INT 18h, SeaBIOS then reboots at once instead of after 60
/// seconds, and `-no-reboot` turns that reboot into an exit with status 0, which is never
/// the success code. So a broken disk is a failure the harness sees within a second,
/// not a timeout.
fn x86_boot_media(res: &Resolution, image: &Path) -> Vec<String> {
    if res.is_on(crate::bios::SYMBOL) {
        vec![
            "-drive".into(),
            format!("format=raw,file={}", image.display()),
            "-boot".into(),
            "reboot-timeout=0".into(),
        ]
    } else {
        // QEMU's multiboot loader passes this after the image's file name, as GRUB would;
        // `boot/info-multiboot` drops that leading path.
        let mut args = vec![
            "-kernel".into(),
            image.display().to_string(),
            "-append".into(),
            crate::bootcfg::kernel_command_line(res),
        ];
        // The module bundle, as a multiboot boot module: QEMU loads it into guest memory
        // and lists it in the handover, the way GRUB does with a `module` line.
        let bundle = image.with_file_name(crate::modules::BUNDLE);
        if res.is_on("MODULES") && bundle.exists() {
            args.push("-initrd".into());
            args.push(bundle.display().to_string());
        }
        args
    }
}

/// UEFI firmware for an x86_64 guest: the code image, and a fresh copy of a variable
/// store if the firmware has a separate one.
struct Firmware {
    code: PathBuf,
    vars: Option<PathBuf>,
}

/// Find OVMF. Firmware is a system package rather than part of the pinned toolchain, and
/// every distribution puts it somewhere else, so this looks in the known places:
///
/// - `KINTANE_OVMF_CODE` (and optionally `KINTANE_OVMF_VARS`), for anything else;
/// - the edk2 build QEMU itself ships, next to the `qemu-system-x86_64` on `PATH` — Homebrew's, for
///   one;
/// - Debian and Ubuntu's `ovmf` package, Fedora's `edk2-ovmf`, Arch's `edk2-ovmf`.
///
/// The variable store is copied into the build directory for every boot, so a run never
/// inherits boot entries or settings a previous one wrote.
fn uefi_firmware(scratch: &Path) -> Result<Firmware, String> {
    let mut candidates: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    if let Some(code) = std::env::var_os("KINTANE_OVMF_CODE") {
        candidates.push((code.into(), std::env::var_os("KINTANE_OVMF_VARS").map(Into::into)));
    }
    if let Some(bin) = find_on_path("qemu-system-x86_64") {
        let dirs = [Some(bin.clone()), std::fs::canonicalize(&bin).ok()];
        for b in dirs.into_iter().flatten() {
            if let Some(share) = b
                .parent()
                .and_then(Path::parent)
                .map(|p| p.join("share/qemu"))
            {
                candidates.push((
                    share.join("edk2-x86_64-code.fd"),
                    Some(share.join("edk2-i386-vars.fd")),
                ));
            }
        }
    }
    for (code, vars) in [
        ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
        ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
        ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
        ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ] {
        candidates.push((code.into(), Some(vars.into())));
    }

    let Some((code, vars)) = candidates.iter().find(|(code, _)| code.is_file()) else {
        let tried: Vec<String> = candidates
            .iter()
            .map(|(c, _)| c.display().to_string())
            .collect();
        return Err(format!(
            "no UEFI firmware (OVMF) found for x86_64\n  tried:\n    {}\n  \
             install the `ovmf` package, or set KINTANE_OVMF_CODE to the firmware image",
            tried.join("\n    ")
        ));
    };
    let vars = match vars.as_ref().filter(|v| v.is_file()) {
        Some(template) => {
            std::fs::create_dir_all(scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
            let copy = scratch.join("ovmf-vars.fd");
            std::fs::copy(template, &copy).map_err(|e| {
                format!("copying {} to {}: {e}", template.display(), copy.display())
            })?;
            Some(copy)
        }
        None => None,
    };
    Ok(Firmware {
        code: code.clone(),
        vars,
    })
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

pub struct Outcome {
    pub code: Option<i32>,
    pub passed: bool,
    /// The guest never signalled and was killed.
    pub timed_out: bool,
    /// Everything the guest wrote to its serial console.
    ///
    /// Kept for decoding a backtrace after the fact, never for deciding the verdict,
    /// which is the exit status alone.
    pub console: Vec<u8>,
    /// Why a [`Watch`] killed the guest, when one did.
    pub hung: Option<String>,
}

/// A liveness watch on the guest's console: a line the guest must keep printing.
///
/// This is the one place the harness reads console output, and it reads it only to
/// decide that the guest is *stuck*, never that it passed. A stuck guest cannot say so
/// through the exit channel, and waiting for the overall timeout of a run meant to last
/// a day is not an answer.
pub struct Watch {
    /// Bytes that mark one heartbeat.
    pub marker: &'static [u8],
    /// The first heartbeat must arrive within this many seconds of starting QEMU.
    pub first_within: u64,
    /// Each later heartbeat must arrive within this many seconds of the one before.
    pub every_within: u64,
}

/// Counts occurrences of a marker in a byte stream that arrives in arbitrary chunks, so
/// a marker split across two reads is still counted once.
pub struct MarkerCounter {
    marker: &'static [u8],
    /// The last `marker.len() - 1` bytes seen, which a marker could continue from.
    tail: Vec<u8>,
    pub count: u64,
}

impl MarkerCounter {
    pub fn new(marker: &'static [u8]) -> Self {
        MarkerCounter {
            marker,
            tail: Vec::new(),
            count: 0,
        }
    }

    /// Feed one chunk; returns how many markers ended inside it.
    pub fn feed(&mut self, chunk: &[u8]) -> u64 {
        if self.marker.is_empty() {
            return 0;
        }
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(chunk);
        let found = window
            .windows(self.marker.len())
            .filter(|w| *w == self.marker)
            .count() as u64;
        let keep = (self.marker.len() - 1).min(window.len());
        self.tail = window[window.len() - keep..].to_vec();
        // A marker can only lie wholly inside the kept tail if it was already counted,
        // and the tail is one byte shorter than the marker, so none is counted twice.
        self.count += found;
        found
    }
}

/// What a KinTane loader prints when its menu is ready for a key: the line
/// `kinboot_menu::render` ends the entry list with, which that crate's tests pin.
const MENU_PROMPT: &[u8] = b"boots an entry, Enter the marked one";

/// What the kernel's serial receive check prints while it waits, and what to type when
/// it does. The prompts and strings are `kernel/main/src/serial.rs`'s `PROBES`; the
/// kernel compares what its receive interrupt queued against the same bytes.
pub const SERIAL_PROBES: &[(&[u8], &[u8])] = &[
    (b"serial probe 1: waiting for input", b"kintane-probe-1"),
    (b"serial probe 2: waiting for input", b"kintane-probe-2"),
];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Boot, passing the console through as it arrives and keeping a copy.
///
/// A guest that never signals is killed after `timeout_secs` and reported through
/// `timed_out` rather than as an error, because the console it printed first is exactly
/// what explains the hang: a fault report halts the CPU and never reaches the exit port.
///
/// With a liveness [`Watch`], a guest that stops printing its heartbeat is killed as
/// well, and reported through `hung`.
pub fn run_watched(
    m: &Machine,
    timeout_secs: u64,
    watch: Option<Watch>,
) -> Result<Outcome, String> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    // The network check's TCP service and relay listen before QEMU starts: QEMU connects to
    // the relay's two sockets as it starts, and stops if either refuses.
    let stop_peer = Arc::new(AtomicBool::new(false));
    let mut peers = Vec::new();
    if let Some(ports) = m.net_port {
        let listen = |port: u16| {
            std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
                format!("cannot listen on loopback port {port} for the network check: {e}")
            })
        };
        let service = listen(ports.tcp)?;
        let (from_guest, to_network) = (listen(ports.relay_out)?, listen(ports.relay_in)?);
        peers.push(tcp_service(service, stop_peer.clone()));
        peers.push(relay(from_guest, to_network, ports.tcp, stop_peer.clone()));
    }

    let mut child = Command::new(m.binary)
        .args(&m.args)
        .stdin(if m.input.is_empty() && !m.serial_probe {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| {
            stop_peer.store(true, Ordering::Relaxed);
            format!("cannot start {}: {e}\nis QEMU installed?", m.binary)
        })?;

    // Typed when the guest asks, not at once. Bytes sent before then are lost: firmware
    // and the loader both reset the UART's receive FIFO when they program it, which the
    // first version of this, typing the menu keys immediately, ran into. So each is typed
    // when its prompt appears: the menu keys at the loader's menu, and each serial probe
    // when the kernel's receive check says it is waiting. The pipe stays open until QEMU
    // exits, because an end of file on `-serial stdio` is not something a guest expects.
    let mut stdin = child.stdin.take();
    let mut pending: Vec<(&'static [u8], Vec<u8>)> = Vec::new();
    if !m.input.is_empty() {
        pending.push((MENU_PROMPT, m.input.clone()));
    }
    if m.serial_probe {
        pending.extend(
            SERIAL_PROBES
                .iter()
                .map(|&(prompt, bytes)| (prompt, bytes.to_vec())),
        );
    }

    let mut pipe = child
        .stdout
        .take()
        .ok_or("QEMU's console was not captured")?;
    if let Some(ports) = m.net_port {
        peers.push(udp_peer(ports.udp, ports.tcp, stop_peer.clone()));
    }
    let start = std::time::Instant::now();
    // Heartbeats seen, and when the last arrived, in milliseconds since `start`.
    let beats = Arc::new(AtomicU64::new(0));
    let last_beat = Arc::new(AtomicU64::new(0));
    let marker = watch.as_ref().map_or(&b""[..], |w| w.marker);
    let tee = {
        let (beats, last_beat) = (beats.clone(), last_beat.clone());
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buf = [0u8; 4096];
            let mut out = std::io::stdout();
            let mut counter = MarkerCounter::new(marker);
            // Ends when QEMU exits or is killed and its end of the pipe closes.
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = out.write_all(&buf[..n]);
                let _ = out.flush();
                kept.extend_from_slice(&buf[..n]);
                if counter.feed(&buf[..n]) > 0 {
                    last_beat.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                    beats.store(counter.count, Ordering::Relaxed);
                }
                if !pending.is_empty() {
                    // Only what just arrived, plus enough before it to hold a prompt split
                    // across reads: scanning everything kept would make a long run quadratic.
                    let reach = n + pending.iter().map(|(p, _)| p.len()).max().unwrap_or(0);
                    let recent = &kept[kept.len().saturating_sub(reach)..];
                    pending.retain(|(prompt, bytes)| {
                        if !contains(recent, prompt) {
                            return true;
                        }
                        if let Some(pipe) = stdin.as_mut() {
                            let _ = pipe.write_all(bytes);
                            let _ = pipe.flush();
                        }
                        false
                    });
                }
            }
            drop(stdin);
            kept
        })
    };

    let mut hung = None;
    let (code, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status.code(), false),
            Ok(None) => {
                let elapsed = start.elapsed();
                if let Some(w) = &watch {
                    let seen = beats.load(Ordering::Relaxed);
                    let since = (elapsed.as_millis() as u64)
                        .saturating_sub(last_beat.load(Ordering::Relaxed));
                    let stuck = if seen == 0 {
                        (elapsed.as_secs() >= w.first_within).then(|| {
                            format!("no heartbeat within {}s of starting the guest", w.first_within)
                        })
                    } else {
                        (since >= w.every_within * 1000).then(|| {
                            format!(
                                "no heartbeat for {}s after heartbeat {seen}; the guest is hung",
                                w.every_within
                            )
                        })
                    };
                    if stuck.is_some() {
                        hung = stuck;
                        let _ = child.kill();
                        let _ = child.wait();
                        break (None, false);
                    }
                }
                if elapsed.as_secs() >= timeout_secs {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (None, true);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(format!("waiting for QEMU: {e}")),
        }
    };
    stop_peer.store(true, Ordering::Relaxed);
    // The relay ends when QEMU closes its sockets, which its exit has done by now.
    for peer in peers {
        let _ = peer.join();
    }
    let console = tee.join().unwrap_or_default();
    Ok(Outcome {
        code,
        passed: !timed_out && hung.is_none() && code == Some(m.success_code),
        timed_out,
        console,
        hung,
    })
}

#[cfg(test)]
mod tests {
    use super::MarkerCounter;

    /// An Ethernet frame holding an IPv4 TCP segment with no options.
    fn segment(src_port: u16, dst_port: u16, seq: u32, flags: u8, payload: usize) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20 + payload];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((40 + payload) as u16).to_be_bytes());
        f[23] = 6;
        f[34..36].copy_from_slice(&src_port.to_be_bytes());
        f[36..38].copy_from_slice(&dst_port.to_be_bytes());
        f[38..42].copy_from_slice(&seq.to_be_bytes());
        f[46] = 0x50;
        f[47] = flags;
        f
    }

    #[test]
    fn the_relay_drops_each_connections_first_data_segment_once() {
        use super::first_data_segment as drop;
        let mut seen = std::collections::HashMap::new();
        let port = 4000;
        assert!(!drop(&segment(50000, port, 99, 0x02, 0), port, &mut seen), "a SYN passes");
        assert!(!drop(&segment(50000, port, 100, 0x10, 0), port, &mut seen), "an ACK passes");
        assert!(drop(&segment(50000, port, 100, 0x18, 5), port, &mut seen), "the first data");
        assert!(!drop(&segment(50000, port, 100, 0x18, 5), port, &mut seen), "its resend");
        assert!(!drop(&segment(50000, port, 105, 0x18, 5), port, &mut seen), "later data");
        assert!(!drop(&segment(50001, 80, 100, 0x18, 5), port, &mut seen), "another service");
        assert!(!drop(&segment(50000, port, 7, 0x02, 0), port, &mut seen), "a new connection");
        assert!(drop(&segment(50000, port, 8, 0x18, 5), port, &mut seen), "is dropped from");
        assert!(!drop(&[0u8; 20], port, &mut seen), "a runt passes, unread");
    }

    #[test]
    fn a_marker_split_across_chunks_counts_once() {
        let mut c = MarkerCounter::new(b"beat");
        assert_eq!(c.feed(b"xxbe"), 0);
        assert_eq!(c.feed(b"at yy be"), 1);
        assert_eq!(c.feed(b"a"), 0);
        assert_eq!(c.feed(b"t"), 1);
        assert_eq!(c.count, 2);
    }

    #[test]
    fn markers_inside_one_chunk_and_at_its_end_count_once_each() {
        let mut c = MarkerCounter::new(b"beat");
        assert_eq!(c.feed(b"beat beatbeat"), 3);
        // The tail kept from the chunk above must not recount its last marker.
        assert_eq!(c.feed(b""), 0);
        assert_eq!(c.feed(b"x"), 0);
        assert_eq!(c.count, 3);
    }

    #[test]
    fn an_empty_marker_never_matches() {
        let mut c = MarkerCounter::new(b"");
        assert_eq!(c.feed(b"anything"), 0);
    }
}
