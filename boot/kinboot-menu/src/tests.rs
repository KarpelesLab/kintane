use crate::*;

/// The two lists kbuild writes, pinned from both sides: kbuild's own tests require it to
/// produce these bytes, and these tests require the loaders' parser to read them as meant.
const EFI_TEST: &[u8] = include_bytes!("../testdata/efi-test.cfg");
const BIOS_CHAIN: &[u8] = include_bytes!("../testdata/bios-chain.cfg");

fn kinds(text: &str) -> ErrorKind {
    Config::parse(text.as_bytes()).unwrap_err().kind
}

fn line_of(text: &str) -> u32 {
    Config::parse(text.as_bytes()).unwrap_err().line
}

#[test]
fn the_list_kbuild_writes_for_uefi_reads_as_meant() {
    let c = Config::parse(EFI_TEST).unwrap();
    assert_eq!(c.len(), 3);
    assert_eq!((c.timeout_secs, c.default, c.on_failure), (0, 0, OnFailure::Reboot));
    let modes: Vec<_> = c
        .entries()
        .map(|e| match e.target {
            Target::Kernel {
                mode,
                cmdline,
                path,
            } => {
                assert_eq!(cmdline, b"kintane.canary=cmdline-intact");
                assert_eq!(path, None);
                mode
            }
            other => panic!("unexpected target {other:?}"),
        })
        .collect();
    assert_eq!(modes, [Mode::Normal, Mode::Safe, Mode::Recovery]);
    assert_eq!(c.entry(1).unwrap().title, b"KinTane (safe mode)");
}

#[test]
fn the_list_kbuild_writes_for_a_bios_chain_test_reads_as_meant() {
    let c = Config::parse(BIOS_CHAIN).unwrap();
    assert_eq!(c.len(), 4);
    assert_eq!((c.timeout_secs, c.default, c.on_failure), (5, 3, OnFailure::Firmware));
    assert_eq!(c.entry(3).unwrap().target, Target::ChainPartition(2));
    assert_eq!(
        c.entry(0).unwrap().target,
        Target::Kernel {
            mode: Mode::Normal,
            cmdline: b"",
            path: None
        }
    );
}

#[test]
fn an_entry_hands_over_its_mode_then_its_command_line() {
    let c = Config::parse(EFI_TEST).unwrap();
    let mut out = [0u8; 128];
    let n = kernel_command_line(&c.entry(1).unwrap(), &mut out).unwrap();
    assert_eq!(&out[..n], b"mode=safe kintane.canary=cmdline-intact");
    let chain = Config::parse(BIOS_CHAIN).unwrap();
    assert_eq!(kernel_command_line(&chain.entry(3).unwrap(), &mut out), None);
}

#[test]
fn defaults_apply_when_settings_are_absent() {
    let c = Config::parse(b"entry a\nentry b\ntitle Bee\n").unwrap();
    assert_eq!((c.default, c.timeout_secs, c.on_failure), (0, 0, OnFailure::Firmware));
    assert_eq!(c.entry(0).unwrap().title, b"a", "the name stands in for a title");
    assert_eq!(c.entry(1).unwrap().title, b"Bee");
    let kernel = Config::parse(b"entry k\nkernel \\KINTANE\\OTHER.ELF\n").unwrap();
    assert_eq!(
        kernel.entry(0).unwrap().target,
        Target::Kernel {
            mode: Mode::Normal,
            cmdline: b"",
            path: Some(b"\\KINTANE\\OTHER.ELF")
        }
    );
}

#[test]
fn comments_blank_lines_and_crlf_are_ignored() {
    let c = Config::parse(b"# hello\r\n\r\n  timeout 3 \r\nentry x\r\n  mode safe\r\n").unwrap();
    assert_eq!(c.timeout_secs, 3);
    assert!(matches!(
        c.entry(0).unwrap().target,
        Target::Kernel {
            mode: Mode::Safe,
            ..
        }
    ));
}

#[test]
fn every_mistake_is_named_with_its_line() {
    assert_eq!(kinds("entry a\ntimeout 1\n"), ErrorKind::SettingAfterEntry);
    assert_eq!(line_of("entry a\ntimeout 1\n"), 2);
    assert_eq!(kinds("title x\n"), ErrorKind::OutsideEntry);
    assert_eq!(kinds("bogus 1\n"), ErrorKind::UnknownKey);
    assert_eq!(kinds("entry a\nbogus 1\n"), ErrorKind::UnknownKey);
    assert_eq!(kinds("timeout\n"), ErrorKind::MissingValue);
    assert_eq!(kinds("timeout -1\nentry a\n"), ErrorKind::BadNumber);
    assert_eq!(kinds("timeout 601\nentry a\n"), ErrorKind::BadNumber);
    assert_eq!(kinds("on-failure panic\nentry a\n"), ErrorKind::UnknownFailureAction);
    assert_eq!(kinds("entry Bad\n"), ErrorKind::BadName);
    assert_eq!(kinds("entry aaaaaaaaaaaaaaaaa\n"), ErrorKind::BadName);
    assert_eq!(kinds("entry a\nentry a\n"), ErrorKind::DuplicateName);
    assert_eq!(kinds("entry a\nmode turbo\n"), ErrorKind::UnknownMode);
    assert_eq!(kinds("entry a\nmode safe\nmode safe\n"), ErrorKind::Repeated);
    assert_eq!(kinds("entry a\ncmdline mode=safe\n"), ErrorKind::ModeInCmdline);
    assert_eq!(kinds("entry a\ncmdline x=\"open\n"), ErrorKind::BadCmdline);
    assert_eq!(kinds("entry a\nchain-partition 5\n"), ErrorKind::BadNumber);
    assert_eq!(kinds("entry a\nchain-partition 0\n"), ErrorKind::BadNumber);
    assert_eq!(kinds("entry a\nmode safe\nchain-partition 1\n"), ErrorKind::MixedTarget);
    assert_eq!(line_of("entry a\nmode safe\nchain-partition 1\n"), 1);
    assert_eq!(
        kinds("entry a\nchain-file \\X.EFI\nchain-partition 1\n"),
        ErrorKind::MixedTarget
    );
    assert_eq!(kinds("# nothing\n"), ErrorKind::NoEntries);
    assert_eq!(kinds("default b\nentry a\n"), ErrorKind::UnknownDefault);
    assert_eq!(kinds("entry a\ntitle caf\u{e9}\n"), ErrorKind::BadByte);
    let ten: String = (0..10).map(|i| format!("entry e{i}\n")).collect();
    assert_eq!(kinds(&ten), ErrorKind::TooManyEntries);
    let huge = vec![b'#'; MAX_FILE + 1];
    assert_eq!(Config::parse(&huge).unwrap_err().kind, ErrorKind::TooLarge);
}

fn three(timeout: u32) -> Vec<u8> {
    format!("timeout {timeout}\ndefault b\nentry a\nentry b\nentry c\n").into_bytes()
}

#[test]
fn a_zero_timeout_boots_the_default_without_waiting() {
    let text = three(0);
    let c = Config::parse(&text).unwrap();
    assert_eq!(Menu::new(&c).start(), Step::Boot(1));
}

#[test]
fn the_countdown_boots_the_default_after_exactly_its_timeout() {
    let text = three(2);
    let c = Config::parse(&text).unwrap();
    let mut m = Menu::new(&c);
    assert_eq!(m.start(), Step::Wait);
    for _ in 0..2 * TICKS_PER_SECOND - 1 {
        assert_eq!(m.tick(), Step::Wait);
    }
    assert_eq!(m.tick(), Step::Boot(1));
}

#[test]
fn a_digit_boots_that_entry_and_an_out_of_range_digit_does_nothing() {
    let text = three(5);
    let c = Config::parse(&text).unwrap();
    let mut m = Menu::new(&c);
    assert_eq!(m.key(Key::Digit(9)), Step::Wait);
    assert_eq!(m.key(Key::Digit(3)), Step::Boot(2));
}

#[test]
fn any_key_stops_the_countdown_so_a_chooser_is_not_overtaken() {
    let text = three(1);
    let c = Config::parse(&text).unwrap();
    let mut m = Menu::new(&c);
    assert_eq!(m.key(Key::Other), Step::Wait);
    assert!(!m.counting());
    for _ in 0..100 {
        assert_eq!(m.tick(), Step::Wait);
    }
    assert_eq!(m.key(Key::Up), Step::Moved(0));
    assert_eq!(m.key(Key::Up), Step::Wait, "already at the top");
    assert_eq!(m.key(Key::Down), Step::Moved(1));
    assert_eq!(m.key(Key::Down), Step::Moved(2));
    assert_eq!(m.key(Key::Down), Step::Wait, "already at the bottom");
    assert_eq!(m.key(Key::Enter), Step::Boot(2));
}

#[test]
fn serial_bytes_map_to_keys() {
    assert_eq!(Key::from_ascii(b'2'), Key::Digit(2));
    assert_eq!(Key::from_ascii(b'0'), Key::Other);
    assert_eq!(Key::from_ascii(b'\r'), Key::Enter);
    assert_eq!(Key::from_ascii(b'j'), Key::Down);
    assert_eq!(Key::from_ascii(b'k'), Key::Up);
    assert_eq!(Key::from_ascii(0x1B), Key::Other);
}

#[test]
fn the_menu_shows_every_entry_the_mark_and_the_countdown() {
    let c = Config::parse(BIOS_CHAIN).unwrap();
    let m = Menu::new(&c);
    let mut shown = Vec::new();
    render(&c, &m, &mut |b| shown.extend_from_slice(b));
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.contains("   1) KinTane  [normal]\r\n"), "{shown}");
    assert!(shown.contains("   2) KinTane (safe mode)  [safe]\r\n"), "{shown}");
    assert!(shown.contains(" * 4) Chainload test  [chainload]\r\n"), "{shown}");
    assert!(shown.contains("1-4 boots an entry"), "{shown}");
    // kbuild types BOOT_TEST_KEYS when it sees this text (MENU_PROMPT in kbuild/src/qemu.rs);
    // changing the wording here without changing it there loses every typed key.
    assert!(shown.contains("boots an entry, Enter the marked one"), "{shown}");
    assert!(shown.contains("boots in 5 s"), "{shown}");
}

#[test]
fn decimal_formats_the_extremes() {
    let mut buf = [0u8; 10];
    assert_eq!(decimal(0, &mut buf), b"0");
    assert_eq!(decimal(u32::MAX, &mut buf), b"4294967295");
}
