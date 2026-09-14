use super::*;

#[test]
fn a_request_reads_back_as_itself() {
    let m = open(b"/HELLO.TXT").unwrap();
    assert_eq!(
        parse_request(m.as_bytes()),
        Some(Request::Open {
            path: b"/HELLO.TXT"
        })
    );
    let m = read(3, 40);
    assert_eq!(parse_request(m.as_bytes()), Some(Request::Read { file: 3, max: 40 }));
    let m = close(3);
    assert_eq!(parse_request(m.as_bytes()), Some(Request::Close { file: 3 }));
}

#[test]
fn a_reply_reads_back_as_itself() {
    let m = reply(Status::Ok, 2, b"hello").unwrap();
    assert_eq!(
        parse_reply(m.as_bytes()),
        Some(Reply {
            status: Status::Ok,
            a: 2,
            data: b"hello"
        })
    );
}

#[test]
fn nothing_larger_than_one_message_is_built() {
    assert!(open(&[b'a'; PAYLOAD]).is_some());
    assert!(open(&[b'a'; PAYLOAD + 1]).is_none());
    assert!(reply(Status::Ok, 0, &[0; PAYLOAD + 1]).is_none());
    // A read asking for more than a message holds is capped, not refused.
    assert_eq!(
        parse_request(read(1, 255).as_bytes()),
        Some(Request::Read {
            file: 1,
            max: PAYLOAD as u8
        })
    );
}

#[test]
fn malformed_messages_are_refused_not_guessed() {
    assert_eq!(parse_request(&[]), None);
    assert_eq!(parse_request(&[1, 0, 0]), None, "short header");
    assert_eq!(parse_request(&[1, 0, 0, 5, b'a']), None, "length disagrees");
    assert_eq!(parse_request(&[1, 0, 0, 0]), None, "an open of no path");
    assert_eq!(parse_request(&[2, 0, 0, 1, b'x']), None, "a read with a payload");
    assert_eq!(parse_request(&[9, 0, 0, 0]), None, "an unknown operation");
    assert_eq!(parse_reply(&[42, 0, 0, 0]), None, "an unknown status");
    let bytes = [0xffu8; MESSAGE];
    for len in 0..=MESSAGE {
        let _ = parse_request(&bytes[..len]);
        let _ = parse_reply(&bytes[..len]);
    }
}
