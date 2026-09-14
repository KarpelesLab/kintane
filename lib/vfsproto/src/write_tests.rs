//! The writing half of the protocol: every request round-trips, and what does not fit or does
//! not parse is refused rather than guessed at.

use crate::*;

#[test]
fn every_writing_request_reads_back_as_itself() {
    let open = open_with(b"/A.TXT", flags::WRITE | flags::CREATE).unwrap();
    assert_eq!(
        parse_request(open.as_bytes()),
        Some(Request::Open {
            path: b"/A.TXT",
            flags: flags::WRITE | flags::CREATE
        })
    );
    let w = write(3, b"bytes").unwrap();
    assert_eq!(
        parse_request(w.as_bytes()),
        Some(Request::Write {
            file: 3,
            data: b"bytes"
        })
    );
    assert_eq!(
        parse_request(seek(2, 70_000).as_bytes()),
        Some(Request::Seek {
            file: 2,
            offset: 70_000
        })
    );
    assert_eq!(
        parse_request(truncate(1, 5).as_bytes()),
        Some(Request::Truncate { file: 1, len: 5 })
    );
    assert_eq!(
        parse_request(unlink(b"/A.TXT").unwrap().as_bytes()),
        Some(Request::Unlink { path: b"/A.TXT" })
    );
    assert_eq!(
        parse_request(mkdir(b"/D").unwrap().as_bytes()),
        Some(Request::Mkdir { path: b"/D" })
    );
    assert_eq!(
        parse_request(rename(b"/D/A", b"/D/B").unwrap().as_bytes()),
        Some(Request::Rename {
            from: b"/D/A",
            to: b"/D/B"
        })
    );
    assert_eq!(parse_request(sync().as_bytes()), Some(Request::Sync));
}

#[test]
fn only_requests_that_change_the_volume_count_as_writes() {
    let reads = [
        open(b"/A").unwrap(),
        open_with(b"/A", flags::APPEND).unwrap(),
        read(0, 8),
        close(0),
        seek(0, 1),
        sync(),
    ];
    for m in reads {
        assert!(!parse_request(m.as_bytes()).unwrap().writes(), "{m:?}");
    }
    let writes = [
        open_with(b"/A", flags::WRITE).unwrap(),
        open_with(b"/A", flags::CREATE).unwrap(),
        open_with(b"/A", flags::TRUNCATE).unwrap(),
        write(0, b"x").unwrap(),
        truncate(0, 0),
        unlink(b"/A").unwrap(),
        mkdir(b"/A").unwrap(),
        rename(b"/A", b"/B").unwrap(),
    ];
    for m in writes {
        assert!(parse_request(m.as_bytes()).unwrap().writes(), "{m:?}");
    }
}

#[test]
fn what_does_not_fit_or_parse_is_refused() {
    assert!(write(0, &[0u8; PAYLOAD + 1]).is_none());
    assert!(open_with(b"/A", 0x80).is_none(), "an undefined flag");
    assert!(rename(&[b'a'; 30], &[b'b'; 30]).is_none(), "61 bytes with the separator");
    assert!(rename(b"a\0b", b"c").is_none());
    assert!(rename(b"", b"c").is_none());
    // A rename with no separator, a seek whose offset is not eight bytes, a write of nothing.
    assert_eq!(parse_request(&[9, 0, 0, 3, b'a', b'b', b'c']), None);
    assert_eq!(parse_request(&[5, 0, 0, 2, 1, 2]), None);
    assert_eq!(parse_request(&[4, 0, 0, 0]), None);
    assert_eq!(parse_request(&[1, 0, 0x40, 1, b'/']), None);
    assert_eq!(parse_request(&[10, 0, 1, 0]), None, "sync takes no arguments");
}

#[test]
fn a_write_reply_carries_the_count() {
    let r = written(4, 60);
    let parsed = parse_reply(r.as_bytes()).unwrap();
    assert_eq!((parsed.status, parsed.a, parsed.b), (Status::Ok, 4, 60));
    for s in [
        Status::ReadOnly,
        Status::Exists,
        Status::NoSpace,
        Status::NotEmpty,
        Status::WrongKind,
        Status::BadName,
    ] {
        assert_eq!(parse_reply(status(s, 0).as_bytes()).unwrap().status, s);
    }
}
