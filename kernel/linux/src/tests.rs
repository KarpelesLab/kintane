use std::vec::Vec;

use super::*;

#[test]
fn every_dispatched_number_has_the_name_the_table_gives_it() {
    for (number, expected) in nr::IMPLEMENTED {
        assert_eq!(
            name(TABLE_X86_64, number),
            Some(expected),
            "the constant for {expected} is {number}, which the table names otherwise"
        );
    }
}

#[test]
fn the_table_names_an_unimplemented_call_and_not_an_absent_number() {
    assert_eq!(name(TABLE_X86_64, 318), Some("getrandom"));
    assert_eq!(name(TABLE_X86_64, 999), None);
    // A number listed only for another ABI is not a 64-bit call.
    assert_eq!(name("512\tx32\trt_sigaction\tcompat_sys_rt_sigaction", 512), None);
}

#[test]
fn errors_travel_as_negated_linux_numbers() {
    assert_eq!(ret(Ok(17)), 17);
    assert_eq!(ret(Err(Failure::NotFound)) as i64, -2);
    assert_eq!(ret(Err(Failure::BadDescriptor)) as i64, -9);
    assert_eq!(ret(Err(Failure::NotImplemented)) as i64, -38);
    // Every error lands in the range Linux reserves for them, so a C library that tests
    // `(unsigned long)r > -4096UL` sees an error.
    for f in [
        Failure::NotFound,
        Failure::NotADirectory,
        Failure::IsADirectory,
        Failure::NameTooLong,
        Failure::BadDescriptor,
        Failure::TooManyOpen,
        Failure::Fault,
        Failure::InvalidArgument,
        Failure::NoMemory,
        Failure::ReadOnly,
        Failure::AccessDenied,
        Failure::Io,
        Failure::NoSpace,
        Failure::NotImplemented,
    ] {
        assert!(ret(Err(f)) > (-4096i64) as u64, "{f:?} is not in the error range");
    }
}

/// Read what `initial_stack` wrote the way a program's start-up code does.
struct Parsed {
    argc: u64,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    auxv: Vec<(u64, u64)>,
}

fn word(buf: &[u8], bottom: u64, addr: u64) -> u64 {
    let at = (addr - bottom) as usize;
    u64::from_le_bytes(buf[at..at + 8].try_into().unwrap())
}

fn cstr(buf: &[u8], bottom: u64, addr: u64) -> Vec<u8> {
    let at = (addr - bottom) as usize;
    buf[at..].iter().take_while(|&&b| b != 0).copied().collect()
}

fn parse(buf: &[u8], top: u64, sp: u64) -> Parsed {
    let bottom = top - buf.len() as u64;
    let mut at = sp;
    let argc = word(buf, bottom, at);
    at += 8;
    let mut argv = Vec::new();
    loop {
        let p = word(buf, bottom, at);
        at += 8;
        if p == 0 {
            break;
        }
        argv.push(cstr(buf, bottom, p));
    }
    let mut envp = Vec::new();
    loop {
        let p = word(buf, bottom, at);
        at += 8;
        if p == 0 {
            break;
        }
        envp.push(cstr(buf, bottom, p));
    }
    let mut auxv = Vec::new();
    loop {
        let k = word(buf, bottom, at);
        let v = word(buf, bottom, at + 8);
        at += 16;
        auxv.push((k, v));
        if k == AT_NULL {
            break;
        }
    }
    Parsed {
        argc,
        argv,
        envp,
        auxv,
    }
}

#[test]
fn a_start_up_stack_reads_back_as_linux_start_up_code_reads_it() {
    let mut buf = vec![0u8; 4096];
    let top = 0x80_0000_1000u64;
    let random = *b"0123456789abcdef";
    let info = StartInfo {
        argv: &[b"hello", b"--flag"],
        envp: &[b"KINTANE=1"],
        auxv: &[(AT_PAGESZ, 4096), (AT_ENTRY, 0x80_0040_0000)],
        random,
    };
    let sp = initial_stack(&mut buf, top, &info).unwrap();
    assert_eq!(sp % 16, 0, "the stack pointer must be 16-byte aligned at entry");
    assert!(sp >= top - buf.len() as u64 && sp < top);

    let p = parse(&buf, top, sp);
    assert_eq!(p.argc, 2);
    assert_eq!(p.argv, [b"hello".to_vec(), b"--flag".to_vec()]);
    assert_eq!(p.envp, [b"KINTANE=1".to_vec()]);
    let get = |key| p.auxv.iter().find(|&&(k, _)| k == key).map(|&(_, v)| v);
    assert_eq!(get(AT_PAGESZ), Some(4096));
    assert_eq!(get(AT_ENTRY), Some(0x80_0040_0000));
    assert_eq!(p.auxv.last(), Some(&(AT_NULL, 0)), "the vector ends in AT_NULL");

    let bottom = top - buf.len() as u64;
    let r = get(AT_RANDOM).expect("AT_RANDOM is always present");
    let at = (r - bottom) as usize;
    assert_eq!(&buf[at..at + 16], &random, "AT_RANDOM points at the sixteen bytes");
    let execfn = get(AT_EXECFN).expect("AT_EXECFN is present when argv[0] is");
    assert_eq!(cstr(&buf, bottom, execfn), b"hello");
}

#[test]
fn a_stack_too_small_or_a_string_with_a_nul_is_refused() {
    let info = StartInfo {
        argv: &[b"hello"],
        envp: &[],
        auxv: &[(AT_PAGESZ, 4096)],
        random: [0; 16],
    };
    let mut tiny = [0u8; 32];
    assert_eq!(initial_stack(&mut tiny, 0x1000, &info), Err(StackError::TooSmall));

    let bad = StartInfo {
        argv: &[b"hel\0lo"],
        envp: &[],
        auxv: &[],
        random: [0; 16],
    };
    let mut buf = [0u8; 512];
    assert_eq!(initial_stack(&mut buf, 0x1000, &bad), Err(StackError::EmbeddedNul));
}

#[test]
fn the_stack_pointer_is_aligned_whatever_the_strings_add_up_to() {
    for extra in 0..40usize {
        let arg = vec![b'a'; extra + 1];
        let argv: [&[u8]; 1] = [&arg];
        let info = StartInfo {
            argv: &argv,
            envp: &[],
            auxv: &[(AT_PAGESZ, 4096)],
            random: [7; 16],
        };
        let mut buf = vec![0u8; 1024];
        let top = 0x80_0000_2000u64 - extra as u64 * 3;
        let sp = initial_stack(&mut buf, top, &info).unwrap();
        assert_eq!(sp % 16, 0, "misaligned with a {extra}-byte argument");
        assert_eq!(parse(&buf, top, sp).argv, [arg]);
    }
}

#[test]
fn stat_and_utsname_have_linux_layouts() {
    let s = stat_bytes(FileKind::Regular, 1000, 7);
    assert_eq!(u64::from_le_bytes(s[8..16].try_into().unwrap()), 7);
    assert_eq!(u32::from_le_bytes(s[24..28].try_into().unwrap()), 0o100444);
    assert_eq!(u64::from_le_bytes(s[48..56].try_into().unwrap()), 1000);
    assert_eq!(u64::from_le_bytes(s[64..72].try_into().unwrap()), 2);

    let u = utsname("x86_64");
    assert_eq!(&u[0..6], b"Linux\0");
    assert_eq!(&u[130..130 + RELEASE.len()], RELEASE.as_bytes());
    assert_eq!(&u[260..267], b"x86_64\0");
}
