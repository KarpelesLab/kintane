//! The wire formats: parsing what arrives and writing what leaves.
//!
//! Every parser takes bytes a device handed over and returns either a view into them or an
//! error value. None of them panics on any input: lengths are checked before every field is
//! read, and a length field is only believed after it is checked against the bytes that
//! are actually there. `lib/fuzz` holds them to that.
//!
//! Every writer takes a caller's buffer and returns how much it wrote, or an error when the
//! buffer is too small. Nothing allocates.

/// A hardware (Ethernet) address.
pub type Mac = [u8; 6];

/// An IPv4 address, in network order.
pub type Ipv4Addr = [u8; 4];

/// The Ethernet broadcast address.
pub const BROADCAST: Mac = [0xff; 6];

pub const ETH_HEADER: usize = 14;
/// The largest payload an untagged Ethernet frame carries.
pub const ETH_MTU: usize = 1500;
/// The largest frame the stack sends or accepts, without the frame check sequence, which
/// the device adds and strips.
pub const FRAME_MAX: usize = ETH_HEADER + ETH_MTU;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// An ARP packet for IPv4 over Ethernet.
pub const ARP_LEN: usize = 28;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;
const ARP_HTYPE_ETHERNET: u16 = 1;

/// The IPv4 header without options: all this stack writes.
pub const IPV4_HEADER: usize = 20;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_UDP: u8 = 17;
/// Don't fragment: everything this stack sends fits one frame.
const IPV4_DF: u16 = 0x4000;
/// More fragments, and the fragment offset: either set means this is a fragment.
const IPV4_FRAGMENT: u16 = 0x3fff;
/// More fragments follow this one.
const IPV4_MF: u16 = 0x2000;
/// Where this fragment's payload belongs, in eight-byte units.
const IPV4_OFFSET: u16 = 0x1fff;

pub const ICMP_HEADER: usize = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

pub const UDP_HEADER: usize = 8;

pub const PROTO_TCP: u8 = 6;
/// The TCP header without options.
pub const TCP_HEADER: usize = 20;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
/// The maximum segment size option, the one option this stack writes or reads.
const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;

/// Why bytes were not a packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    /// Fewer bytes than the header needs.
    Short,
    /// An ARP packet for something other than IPv4 over Ethernet.
    NotIpv4OverEthernet,
    /// An ARP operation other than request or reply.
    ArpOperation(u16),
    /// The IP version is not 4.
    NotIpv4,
    /// The IPv4 header length is below the minimum or past the bytes there are.
    BadHeaderLength,
    /// The IPv4 total length is shorter than its header or longer than the frame.
    BadTotalLength,
    /// A checksum that does not verify.
    BadChecksum,
    /// An IPv4 fragment, which this stack does not reassemble.
    Fragmented,
    /// An ICMP message other than an echo request or reply.
    NotEcho,
    /// A UDP length field shorter than its header or longer than the packet.
    BadUdpLength,
    /// A TCP data offset shorter than its header or longer than the segment, or an option
    /// whose length runs past the header.
    BadTcpHeader,
    /// The caller's buffer cannot hold what was asked for.
    TooLarge,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn mac_at(b: &[u8], at: usize) -> Option<Mac> {
    b.get(at..at + 6)?.try_into().ok()
}

fn ip_at(b: &[u8], at: usize) -> Option<Ipv4Addr> {
    b.get(at..at + 4)?.try_into().ok()
}

/// The Internet checksum (RFC 1071) over several parts, as if they were one run of bytes.
///
/// A part of odd length carries its last byte into the next part, so a pseudo-header and a
/// payload of any length sum exactly as their concatenation would. Verifying a header that
/// contains its own checksum yields 0.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry: Option<u8> = None;
    for part in parts {
        for &byte in part.iter() {
            match carry.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, byte])),
                None => carry = Some(byte),
            }
        }
    }
    if let Some(high) = carry {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An Ethernet frame's header, and a view of its payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ethernet<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_ethernet(frame: &[u8]) -> Result<Ethernet<'_>, WireError> {
    let short = WireError::Short;
    Ok(Ethernet {
        dst: mac_at(frame, 0).ok_or(short)?,
        src: mac_at(frame, 6).ok_or(short)?,
        ethertype: be16(frame, 12).ok_or(short)?,
        payload: frame.get(ETH_HEADER..).ok_or(short)?,
    })
}

/// Write an Ethernet header at the start of `buf`.
pub fn write_ethernet(buf: &mut [u8], dst: Mac, src: Mac, ethertype: u16) -> Result<(), WireError> {
    let header = buf.get_mut(..ETH_HEADER).ok_or(WireError::TooLarge)?;
    header[..6].copy_from_slice(&dst);
    header[6..12].copy_from_slice(&src);
    header[12..14].copy_from_slice(&ethertype.to_be_bytes());
    Ok(())
}

/// An ARP packet for IPv4 over Ethernet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Arp {
    pub operation: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4Addr,
    pub target_mac: Mac,
    pub target_ip: Ipv4Addr,
}

pub fn parse_arp(p: &[u8]) -> Result<Arp, WireError> {
    if p.len() < ARP_LEN {
        return Err(WireError::Short);
    }
    let short = WireError::Short;
    let htype = be16(p, 0).ok_or(short)?;
    let ptype = be16(p, 2).ok_or(short)?;
    if htype != ARP_HTYPE_ETHERNET || ptype != ETHERTYPE_IPV4 || p[4] != 6 || p[5] != 4 {
        return Err(WireError::NotIpv4OverEthernet);
    }
    let operation = be16(p, 6).ok_or(short)?;
    if operation != ARP_REQUEST && operation != ARP_REPLY {
        return Err(WireError::ArpOperation(operation));
    }
    Ok(Arp {
        operation,
        sender_mac: mac_at(p, 8).ok_or(short)?,
        sender_ip: ip_at(p, 14).ok_or(short)?,
        target_mac: mac_at(p, 18).ok_or(short)?,
        target_ip: ip_at(p, 24).ok_or(short)?,
    })
}

/// Write an ARP packet into `buf`; returns its length.
pub fn write_arp(buf: &mut [u8], arp: &Arp) -> Result<usize, WireError> {
    let p = buf.get_mut(..ARP_LEN).ok_or(WireError::TooLarge)?;
    p[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    p[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    p[4] = 6;
    p[5] = 4;
    p[6..8].copy_from_slice(&arp.operation.to_be_bytes());
    p[8..14].copy_from_slice(&arp.sender_mac);
    p[14..18].copy_from_slice(&arp.sender_ip);
    p[18..24].copy_from_slice(&arp.target_mac);
    p[24..28].copy_from_slice(&arp.target_ip);
    Ok(ARP_LEN)
}

/// An IPv4 packet's header, and a view of its payload bounded by its total length.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv4<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub payload: &'a [u8],
}

/// Where a packet's bytes sit in the datagram they are one fragment of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fragment {
    /// The identification field: fragments of one datagram share it, along with the
    /// addresses and the protocol.
    pub id: u16,
    /// Where this fragment's payload starts in the whole datagram, in bytes. The field on
    /// the wire counts eight-byte units, so this is always a multiple of eight.
    pub offset: usize,
    /// Another fragment follows this one; the one without it ends the datagram.
    pub more: bool,
}

/// Parse an IPv4 packet. The header checksum is verified before any field is trusted, and a
/// fragment is refused: [`parse_ipv4_part`] is what takes one, and `stack` reassembles.
pub fn parse_ipv4(p: &[u8]) -> Result<Ipv4<'_>, WireError> {
    match parse_ipv4_part(p)? {
        (ip, None) => Ok(ip),
        (_, Some(_)) => Err(WireError::Fragmented),
    }
}

/// Parse an IPv4 packet whether or not it is a fragment of a larger datagram: the header, the
/// payload *these* bytes carry, and where that payload belongs in the datagram when they are
/// one fragment of several.
///
/// Everything [`parse_ipv4`] checks is checked here: the version, the header length against
/// the bytes there, the total length against both, and the header checksum before any field
/// is trusted. A fragment's payload is its own bytes; putting the datagram back together is
/// the stack's business, because it is what owns the memory to do it in.
pub fn parse_ipv4_part(p: &[u8]) -> Result<(Ipv4<'_>, Option<Fragment>), WireError> {
    let first = *p.first().ok_or(WireError::Short)?;
    if first >> 4 != 4 {
        return Err(WireError::NotIpv4);
    }
    let header = usize::from(first & 0x0f) * 4;
    if header < IPV4_HEADER || header > p.len() {
        return Err(WireError::BadHeaderLength);
    }
    let total = usize::from(be16(p, 2).ok_or(WireError::Short)?);
    if total < header || total > p.len() {
        return Err(WireError::BadTotalLength);
    }
    if checksum(&[&p[..header]]) != 0 {
        return Err(WireError::BadChecksum);
    }
    let short = WireError::Short;
    let flags = be16(p, 6).ok_or(short)?;
    let fragment = (flags & IPV4_FRAGMENT != 0).then(|| Fragment {
        id: be16(p, 4).unwrap_or(0),
        offset: usize::from(flags & IPV4_OFFSET) * 8,
        more: flags & IPV4_MF != 0,
    });
    Ok((
        Ipv4 {
            ttl: *p.get(8).ok_or(short)?,
            protocol: *p.get(9).ok_or(short)?,
            src: ip_at(p, 12).ok_or(short)?,
            dst: ip_at(p, 16).ok_or(short)?,
            payload: &p[header..total],
        },
        fragment,
    ))
}

/// Write a 20-byte IPv4 header for a payload of `payload_len`, with its checksum.
pub fn write_ipv4(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    id: u16,
    payload_len: usize,
) -> Result<usize, WireError> {
    let total = u16::try_from(IPV4_HEADER + payload_len).map_err(|_| WireError::TooLarge)?;
    let h = buf.get_mut(..IPV4_HEADER).ok_or(WireError::TooLarge)?;
    h[0] = 0x45;
    h[1] = 0;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h[6..8].copy_from_slice(&IPV4_DF.to_be_bytes());
    h[8] = 64;
    h[9] = protocol;
    h[10..12].copy_from_slice(&[0, 0]);
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    let sum = checksum(&[h]);
    h[10..12].copy_from_slice(&sum.to_be_bytes());
    Ok(IPV4_HEADER)
}

/// An ICMP echo request or reply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Echo<'a> {
    /// [`ICMP_ECHO_REQUEST`] or [`ICMP_ECHO_REPLY`].
    pub kind: u8,
    pub id: u16,
    pub seq: u16,
    pub data: &'a [u8],
}

pub fn parse_icmp_echo(p: &[u8]) -> Result<Echo<'_>, WireError> {
    if p.len() < ICMP_HEADER {
        return Err(WireError::Short);
    }
    if checksum(&[p]) != 0 {
        return Err(WireError::BadChecksum);
    }
    let kind = p[0];
    if (kind != ICMP_ECHO_REQUEST && kind != ICMP_ECHO_REPLY) || p[1] != 0 {
        return Err(WireError::NotEcho);
    }
    let short = WireError::Short;
    Ok(Echo {
        kind,
        id: be16(p, 4).ok_or(short)?,
        seq: be16(p, 6).ok_or(short)?,
        data: &p[ICMP_HEADER..],
    })
}

/// Write an ICMP echo message into `buf`; returns its length.
pub fn write_icmp_echo(
    buf: &mut [u8],
    kind: u8,
    id: u16,
    seq: u16,
    data: &[u8],
) -> Result<usize, WireError> {
    let len = ICMP_HEADER + data.len();
    let m = buf.get_mut(..len).ok_or(WireError::TooLarge)?;
    m[0] = kind;
    m[1] = 0;
    m[2..4].copy_from_slice(&[0, 0]);
    m[4..6].copy_from_slice(&id.to_be_bytes());
    m[6..8].copy_from_slice(&seq.to_be_bytes());
    m[ICMP_HEADER..].copy_from_slice(data);
    let sum = checksum(&[m]);
    m[2..4].copy_from_slice(&sum.to_be_bytes());
    Ok(len)
}

/// A UDP datagram's ports, and a view of its payload bounded by its length field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// The IPv4 pseudo-header UDP's and TCP's checksums cover.
fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, len: u16) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0..4].copy_from_slice(&src);
    h[4..8].copy_from_slice(&dst);
    h[9] = protocol;
    h[10..12].copy_from_slice(&len.to_be_bytes());
    h
}

/// Parse a UDP datagram carried from `src` to `dst`. A zero checksum means the sender did
/// not compute one, which IPv4 allows; any other is verified.
pub fn parse_udp(p: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Result<Udp<'_>, WireError> {
    if p.len() < UDP_HEADER {
        return Err(WireError::Short);
    }
    let short = WireError::Short;
    let len = be16(p, 4).ok_or(short)?;
    let n = usize::from(len);
    if n < UDP_HEADER || n > p.len() {
        return Err(WireError::BadUdpLength);
    }
    if be16(p, 6).ok_or(short)? != 0
        && checksum(&[&pseudo_header(src, dst, PROTO_UDP, len), &p[..n]]) != 0
    {
        return Err(WireError::BadChecksum);
    }
    Ok(Udp {
        src_port: be16(p, 0).ok_or(short)?,
        dst_port: be16(p, 2).ok_or(short)?,
        payload: &p[UDP_HEADER..n],
    })
}

/// Write a UDP datagram, with its checksum, into `buf`; returns its length.
pub fn write_udp(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<usize, WireError> {
    let n = UDP_HEADER + payload.len();
    let len = u16::try_from(n).map_err(|_| WireError::TooLarge)?;
    let d = buf.get_mut(..n).ok_or(WireError::TooLarge)?;
    d[0..2].copy_from_slice(&src_port.to_be_bytes());
    d[2..4].copy_from_slice(&dst_port.to_be_bytes());
    d[4..6].copy_from_slice(&len.to_be_bytes());
    d[6..8].copy_from_slice(&[0, 0]);
    d[UDP_HEADER..].copy_from_slice(payload);
    let sum = match checksum(&[&pseudo_header(src, dst, PROTO_UDP, len), d]) {
        // Zero on the wire means "no checksum", so a sum that works out to zero is sent as
        // its other ones'-complement representation (RFC 768).
        0 => 0xffff,
        s => s,
    };
    d[6..8].copy_from_slice(&sum.to_be_bytes());
    Ok(n)
}

/// A TCP segment's header fields, and a view of its payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// The low eight flag bits: [`TCP_FIN`], [`TCP_SYN`], [`TCP_RST`], [`TCP_PSH`],
    /// [`TCP_ACK`], and URG, ECE and CWR, which this stack ignores.
    pub flags: u8,
    pub window: u16,
    /// The maximum segment size option, where the segment carries a well-formed one.
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

/// Parse a TCP segment carried from `src` to `dst`. The checksum, which TCP makes mandatory,
/// is verified over the pseudo-header before any field is trusted, and every option's length
/// is checked against the header it sits in.
pub fn parse_tcp(p: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Result<Tcp<'_>, WireError> {
    if p.len() < TCP_HEADER {
        return Err(WireError::Short);
    }
    let len = u16::try_from(p.len()).map_err(|_| WireError::BadTcpHeader)?;
    let short = WireError::Short;
    let offset = usize::from(*p.get(12).ok_or(short)? >> 4) * 4;
    if offset < TCP_HEADER || offset > p.len() {
        return Err(WireError::BadTcpHeader);
    }
    if checksum(&[&pseudo_header(src, dst, PROTO_TCP, len), p]) != 0 {
        return Err(WireError::BadChecksum);
    }
    let mut mss = None;
    let mut at = TCP_HEADER;
    while at < offset {
        match p[at] {
            TCP_OPT_END => break,
            TCP_OPT_NOP => at += 1,
            kind => {
                let n = usize::from(*p.get(at + 1).ok_or(WireError::BadTcpHeader)?);
                if n < 2 || at + n > offset {
                    return Err(WireError::BadTcpHeader);
                }
                if kind == TCP_OPT_MSS && n == 4 {
                    mss = be16(p, at + 2);
                }
                at += n;
            }
        }
    }
    Ok(Tcp {
        src_port: be16(p, 0).ok_or(short)?,
        dst_port: be16(p, 2).ok_or(short)?,
        seq: u32::from_be_bytes(p.get(4..8).ok_or(short)?.try_into().map_err(|_| short)?),
        ack: u32::from_be_bytes(p.get(8..12).ok_or(short)?.try_into().map_err(|_| short)?),
        flags: *p.get(13).ok_or(short)?,
        window: be16(p, 14).ok_or(short)?,
        mss,
        payload: &p[offset..],
    })
}

/// The header fields of a segment to write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// Written as the one option, padded to a whole header word; on a SYN only, by custom.
    pub mss: Option<u16>,
}

/// The length of the header [`write_tcp`] writes for `h`, options included.
pub const fn tcp_header_len(h: &TcpHeader) -> usize {
    TCP_HEADER + if h.mss.is_some() { 4 } else { 0 }
}

/// Write a TCP segment, with its checksum, into `buf`; returns its length.
pub fn write_tcp(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    h: &TcpHeader,
    payload: &[u8],
) -> Result<usize, WireError> {
    let header = tcp_header_len(h);
    buf.get_mut(header..header + payload.len())
        .ok_or(WireError::TooLarge)?
        .copy_from_slice(payload);
    write_tcp_header(buf, src, dst, h, payload.len())
}

/// Write a TCP header, and the checksum, in front of `payload_len` bytes the caller has
/// already placed at [`tcp_header_len`] in `buf`: how a payload copied straight out of a
/// connection's ring is sent without a second copy. Returns the segment's length.
pub fn write_tcp_header(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    h: &TcpHeader,
    payload_len: usize,
) -> Result<usize, WireError> {
    let header = tcp_header_len(h);
    let n = header + payload_len;
    let len = u16::try_from(n).map_err(|_| WireError::TooLarge)?;
    let s = buf.get_mut(..n).ok_or(WireError::TooLarge)?;
    s[0..2].copy_from_slice(&h.src_port.to_be_bytes());
    s[2..4].copy_from_slice(&h.dst_port.to_be_bytes());
    s[4..8].copy_from_slice(&h.seq.to_be_bytes());
    s[8..12].copy_from_slice(&h.ack.to_be_bytes());
    s[12] = ((header / 4) as u8) << 4;
    s[13] = h.flags;
    s[14..16].copy_from_slice(&h.window.to_be_bytes());
    s[16..20].copy_from_slice(&[0, 0, 0, 0]);
    if let Some(mss) = h.mss {
        s[20] = TCP_OPT_MSS;
        s[21] = 4;
        s[22..24].copy_from_slice(&mss.to_be_bytes());
    }
    let sum = checksum(&[&pseudo_header(src, dst, PROTO_TCP, len), s]);
    s[16..18].copy_from_slice(&sum.to_be_bytes());
    Ok(n)
}

/// Every layer of a frame this stack understands, parsed as far as it goes: what a fuzzer
/// drives, and what a caller that only wants to classify a frame can use without a stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Frame<'a> {
    Arp(Arp),
    Echo(Ipv4<'a>, Echo<'a>),
    Udp(Ipv4<'a>, Udp<'a>),
    Tcp(Ipv4<'a>, Tcp<'a>),
    /// An IPv4 packet for a protocol this stack does not speak.
    OtherIpv4(Ipv4<'a>),
    /// An Ethernet frame of a type this stack does not speak.
    OtherEthernet(u16),
}

/// Parse a whole frame, down to the deepest layer this stack understands.
pub fn parse_frame(frame: &[u8]) -> Result<(Ethernet<'_>, Frame<'_>), WireError> {
    let eth = parse_ethernet(frame)?;
    let inner = match eth.ethertype {
        ETHERTYPE_ARP => Frame::Arp(parse_arp(eth.payload)?),
        ETHERTYPE_IPV4 => {
            let ip = parse_ipv4(eth.payload)?;
            match ip.protocol {
                PROTO_ICMP => Frame::Echo(ip, parse_icmp_echo(ip.payload)?),
                PROTO_UDP => Frame::Udp(ip, parse_udp(ip.payload, ip.src, ip.dst)?),
                PROTO_TCP => Frame::Tcp(ip, parse_tcp(ip.payload, ip.src, ip.dst)?),
                _ => Frame::OtherIpv4(ip),
            }
        }
        other => Frame::OtherEthernet(other),
    };
    Ok((eth, inner))
}
