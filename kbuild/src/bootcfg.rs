//! Boot entries and the kernel command line, from the configuration.
//!
//! Every boot path gets the same arguments. A KinTane loader reads them from the entry
//! list this module writes onto its boot medium (`boot/kinboot-menu` defines the format).
//! A `-kernel` boot gets [`kernel_command_line`] through QEMU's `-append`.
//!
//! The format is not parsed here. kbuild depends on nothing in the kernel tree, so the
//! writer and the loaders' parser are pinned to each other through two files in
//! `boot/kinboot-menu/testdata`. The tests below require this module to write exactly those
//! bytes, and that crate's tests require its parser to read them as meant, so a change on
//! either side that the other does not follow fails a test.

use crate::kcfg::Resolution;

/// What the chainload test entry boots, if the configuration has one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Chain {
    None,
    /// An EFI application on the boot partition.
    File(&'static str),
    /// A partition's boot record, numbered from 1.
    Partition(u8),
}

/// The name of the chainload test entry.
pub const CHAIN_ENTRY: &str = "chain-test";

/// The inputs to an entry list, separate from a [`Resolution`] so tests can state them.
#[derive(Clone, Copy, Debug)]
pub struct Entries<'a> {
    pub timeout: i64,
    pub default: &'a str,
    pub on_failure: &'a str,
    pub cmdline: &'a str,
    pub chain: Chain,
}

/// The boot mode the configuration defaults to, as `mode=` spells it.
pub fn mode_name(res: &Resolution) -> &'static str {
    if res.is_on("BOOT_MODE_SAFE") {
        "safe"
    } else if res.is_on("BOOT_MODE_RECOVERY") {
        "recovery"
    } else {
        "normal"
    }
}

/// The line a boot without a KinTane loader passes: what the default entry would.
pub fn kernel_command_line(res: &Resolution) -> String {
    let extra = res.str("CMDLINE").trim();
    if extra.is_empty() {
        format!("mode={}", mode_name(res))
    } else {
        format!("mode={} {extra}", mode_name(res))
    }
}

/// The entry list for this configuration.
///
/// Test builds, which have `QEMU_EXIT`, fail by rebooting: under `-no-reboot` that ends
/// the run within a second, where handing back to the firmware would leave OVMF trying
/// its other boot options until the harness timed out.
pub fn entry_list(res: &Resolution, chain: Chain) -> String {
    let chain = if res.is_on("CHAIN_TEST") {
        chain
    } else {
        Chain::None
    };
    render(&Entries {
        timeout: res.int("BOOT_MENU_TIMEOUT"),
        default: if chain == Chain::None {
            mode_name(res)
        } else {
            CHAIN_ENTRY
        },
        on_failure: if res.is_on("QEMU_EXIT") {
            "reboot"
        } else {
            "firmware"
        },
        cmdline: res.str("CMDLINE"),
        chain,
    })
}

pub fn render(e: &Entries<'_>) -> String {
    let mut out = String::from(
        "# kinboot boot entries, written by kbuild. See docs/bootloader.md#boot-options.\n",
    );
    out.push_str(&format!(
        "timeout {}\ndefault {}\non-failure {}\n",
        e.timeout, e.default, e.on_failure
    ));
    let cmdline = e.cmdline.trim();
    for (name, title) in [
        ("normal", "KinTane"),
        ("safe", "KinTane (safe mode)"),
        ("recovery", "KinTane (recovery)"),
    ] {
        out.push_str(&format!("\nentry {name}\ntitle {title}\nmode {name}\n"));
        if !cmdline.is_empty() {
            out.push_str(&format!("cmdline {cmdline}\n"));
        }
    }
    match e.chain {
        Chain::None => {}
        Chain::File(path) => out
            .push_str(&format!("\nentry {CHAIN_ENTRY}\ntitle Chainload test\nchain-file {path}\n")),
        Chain::Partition(n) => out.push_str(&format!(
            "\nentry {CHAIN_ENTRY}\ntitle Chainload test\nchain-partition {n}\n"
        )),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_uefi_test_list_the_loaders_parser_is_tested_against() {
        let written = render(&Entries {
            timeout: 0,
            default: "normal",
            on_failure: "reboot",
            cmdline: "kintane.canary=cmdline-intact",
            chain: Chain::None,
        });
        assert_eq!(written, include_str!("../../boot/kinboot-menu/testdata/efi-test.cfg"));
    }

    #[test]
    fn writes_the_bios_chain_list_the_loaders_parser_is_tested_against() {
        let written = render(&Entries {
            timeout: 5,
            default: CHAIN_ENTRY,
            on_failure: "firmware",
            cmdline: "  ",
            chain: Chain::Partition(2),
        });
        assert_eq!(written, include_str!("../../boot/kinboot-menu/testdata/bios-chain.cfg"));
    }
}
