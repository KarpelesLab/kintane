use crate::*;

fn words(line: &str) -> Vec<(String, Option<String>)> {
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).unwrap();
    Args::parse(line.as_bytes())
        .unwrap()
        .words()
        .map(|w| (text(w.key), w.value.map(text)))
        .collect()
}

#[test]
fn flags_values_and_quoted_values() {
    assert_eq!(
        words("  quiet mode=safe  console=\"ttyS0 115200\"\tempty= "),
        vec![
            ("quiet".into(), None),
            ("mode".into(), Some("safe".into())),
            ("console".into(), Some("ttyS0 115200".into())),
            ("empty".into(), Some(String::new())),
        ]
    );
    assert_eq!(words(""), vec![]);
    assert_eq!(words(" \r\n "), vec![]);
}

#[test]
fn the_mode_defaults_to_normal_and_is_read_from_mode() {
    assert_eq!(Args::parse(b"").unwrap().mode(), Mode::Normal);
    assert_eq!(Args::parse(b"x=1 mode=recovery").unwrap().mode(), Mode::Recovery);
    assert!(Mode::Safe.is_conservative() && Mode::Recovery.is_conservative());
    assert!(!Mode::Normal.is_conservative());
    for m in Mode::ALL {
        assert_eq!(Mode::from_name(m.name().as_bytes()), Some(m));
    }
}

#[test]
fn an_unknown_or_repeated_mode_is_an_error_not_a_guess() {
    assert_eq!(Args::parse(b"mode=turbo").unwrap_err(), Error::UnknownMode { offset: 0 });
    assert_eq!(Args::parse(b"a mode").unwrap_err(), Error::UnknownMode { offset: 2 });
    assert_eq!(
        Args::parse(b"mode=safe mode=normal").unwrap_err(),
        Error::RepeatedMode { offset: 10 }
    );
}

#[test]
fn unknown_keys_are_kept_for_whoever_reads_them() {
    let a = Args::parse(b"mode=safe kintane.future=7 verbose").unwrap();
    assert_eq!(a.get("kintane.future"), Some(&b"7"[..]));
    assert!(a.has("verbose"));
    assert_eq!(a.get("verbose"), None, "a flag has no value");
    assert_eq!(a.get("absent"), None);
}

#[test]
fn malformed_lines_name_the_offending_byte() {
    assert_eq!(Args::parse(b"ok \x01").unwrap_err(), Error::BadByte { offset: 3 });
    assert_eq!(Args::parse("é".as_bytes()).unwrap_err(), Error::BadByte { offset: 0 });
    assert_eq!(Args::parse(b"a =b").unwrap_err(), Error::BadKey { offset: 2 });
    assert_eq!(Args::parse(b"k\"ey=1").unwrap_err(), Error::BadKey { offset: 0 });
    assert_eq!(Args::parse(b"a=b\"c").unwrap_err(), Error::BadKey { offset: 0 });
    assert_eq!(Args::parse(b"x=\"open").unwrap_err(), Error::UnterminatedQuote { offset: 2 });
    assert_eq!(Args::parse(b"x=\"a\"b").unwrap_err(), Error::TrailingAfterQuote { offset: 5 });
    assert_eq!(Args::parse(&[b'a'; MAX_LINE + 1]).unwrap_err(), Error::TooLong);
    assert!(Args::parse(&[b'a'; MAX_LINE]).is_ok());
}

#[test]
fn compose_writes_what_parse_reads_back() {
    let mut out = [0u8; 64];
    let n = compose(Mode::Safe, b"  kintane.canary=x  ", &mut out).unwrap();
    assert_eq!(&out[..n], b"mode=safe kintane.canary=x");
    let a = Args::parse(&out[..n]).unwrap();
    assert_eq!(a.mode(), Mode::Safe);
    assert_eq!(a.get("kintane.canary"), Some(&b"x"[..]));

    let n = compose(Mode::Normal, b"", &mut out).unwrap();
    assert_eq!(&out[..n], b"mode=normal");

    let mut small = [0u8; 10];
    assert_eq!(compose(Mode::Recovery, b"", &mut small), None);
}
