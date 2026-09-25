//! IP-packet pump over smoltcp wire types (no sockets/timers/privileges).
//!
//! The TUN device yields raw IP packets; the pump parses them into TCP
//! segments / UDP datagrams (which become OPEN + DATA frames upstream) and
//! builds reply packets back. Checksums are verified on parse (except a
//! zero UDP checksum, which RFC 768 allows to mean "none") and filled on
//! build. Socket state machines are a follow-up; this codec is their
//! foundation.

use std::net::Ipv4Addr;

use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, TcpSeqNumber, UdpPacket,
};

use crate::{NetstackError, Result};

/// Parsed L4 payload of an IPv4 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedPayload {
    /// TCP segment.
    Tcp(TcpSegment),
    /// UDP datagram.
    Udp(UdpSegment),
}

/// Parsed IPv4 packet with owned payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// L4 payload.
    pub payload: ParsedPayload,
}

impl ParsedPacket {
    /// TCP view, if applicable.
    #[must_use]
    pub fn tcp(&self) -> Option<&TcpSegment> {
        match &self.payload {
            ParsedPayload::Tcp(seg) => Some(seg),
            _ => None,
        }
    }

    /// UDP view, if applicable.
    #[must_use]
    pub fn udp(&self) -> Option<&UdpSegment> {
        match &self.payload {
            ParsedPayload::Udp(dgram) => Some(dgram),
            _ => None,
        }
    }
}

/// Parsed TCP segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// SYN flag.
    pub syn: bool,
    /// ACK flag.
    pub ack: bool,
    /// PSH flag.
    pub psh: bool,
    /// RST flag.
    pub rst: bool,
    /// FIN flag.
    pub fin: bool,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number.
    pub ack_num: u32,
    /// Segment payload.
    pub payload: Vec<u8>,
}

/// Parsed UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpSegment {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Datagram payload.
    pub payload: Vec<u8>,
}

/// Wrap std addresses for smoltcp checksums.
fn ip_addr(ip: Ipv4Addr) -> IpAddress {
    let o = ip.octets();
    IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))
}

/// Parse one raw IPv4 packet, verifying checksums. Fails closed.
pub fn parse_ipv4_packet(raw: &[u8]) -> Result<ParsedPacket> {
    let ip = Ipv4Packet::new_checked(raw)
        .map_err(|_| NetstackError::InvalidPacket("truncated ip".to_string()))?;
    if ip.version() != 4 {
        return Err(NetstackError::InvalidPacket(format!(
            "bad version {}",
            ip.version()
        )));
    }
    if ip.total_len() as usize > raw.len() {
        return Err(NetstackError::InvalidPacket("short buffer".to_string()));
    }
    if !ip.verify_checksum() {
        return Err(NetstackError::InvalidPacket("bad ip checksum".to_string()));
    }
    let src = Ipv4Addr::from(ip.src_addr());
    let dst = Ipv4Addr::from(ip.dst_addr());
    let body = &raw[ip.header_len() as usize..ip.total_len() as usize];
    let payload = match ip.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(body)
                .map_err(|_| NetstackError::InvalidPacket("truncated tcp".to_string()))?;
            if !tcp.verify_checksum(&ip_addr(src), &ip_addr(dst)) {
                return Err(NetstackError::InvalidPacket("bad tcp checksum".to_string()));
            }
            let header = tcp.header_len() as usize;
            if header > body.len() {
                return Err(NetstackError::InvalidPacket("bad tcp header".to_string()));
            }
            ParsedPayload::Tcp(TcpSegment {
                src_port: tcp.src_port(),
                dst_port: tcp.dst_port(),
                syn: tcp.syn(),
                ack: tcp.ack(),
                psh: tcp.psh(),
                rst: tcp.rst(),
                fin: tcp.fin(),
                seq: tcp.seq_number().0 as u32,
                ack_num: tcp.ack_number().0 as u32,
                payload: body[header..].to_vec(),
            })
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(body)
                .map_err(|_| NetstackError::InvalidPacket("truncated udp".to_string()))?;
            // RFC 768: zero checksum means "none" on IPv4.
            if udp.checksum() != 0 && !udp.verify_checksum(&ip_addr(src), &ip_addr(dst)) {
                return Err(NetstackError::InvalidPacket("bad udp checksum".to_string()));
            }
            ParsedPayload::Udp(UdpSegment {
                src_port: udp.src_port(),
                dst_port: udp.dst_port(),
                payload: udp.payload().to_vec(),
            })
        }
        other => {
            return Err(NetstackError::InvalidPacket(format!(
                "unsupported protocol {other:?}"
            )));
        }
    };
    Ok(ParsedPacket { src, dst, payload })
}

/// Build one IPv4/TCP packet with valid checksums (no options).
#[must_use]
pub fn build_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
    psh: bool,
    seq: u32,
    ack_num: u32,
    payload: &[u8],
) -> Vec<u8> {
    build_tcp_packet_full(
        src, dst, src_port, dst_port, syn, ack, psh, false, false, seq, ack_num, payload,
    )
}

/// Build one IPv4/TCP packet with full flag control (close path needs FIN).
///
/// `build_tcp_packet` covers the common case so its 25 existing call sites
/// stay untouched; this variant is for SYN-ACK/FIN/RST construction.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet_full(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
    psh: bool,
    fin: bool,
    rst: bool,
    seq: u32,
    ack_num: u32,
    payload: &[u8],
) -> Vec<u8> {
    const IPV4_HEADER: usize = 20;
    const TCP_HEADER: usize = 20;
    let total = IPV4_HEADER + TCP_HEADER + payload.len();
    assert!(total <= 65535, "packet too large for IPv4");
    let mut buf = vec![0u8; total];
    // `new_checked` rejects data-offset < 20: preset it (5 words, no options)
    // before wrapping; `set_header_len` below keeps it consistent.
    buf[IPV4_HEADER + 12] = 0x50;
    {
        let mut tcp = TcpPacket::new_checked(&mut buf[IPV4_HEADER..]).expect("sized tcp buffer");
        tcp.clear_flags();
        tcp.set_src_port(src_port);
        tcp.set_dst_port(dst_port);
        tcp.set_seq_number(TcpSeqNumber(seq as i32));
        tcp.set_ack_number(TcpSeqNumber(ack_num as i32));
        tcp.set_header_len(TCP_HEADER as u8);
        tcp.set_window_len(65535);
        tcp.set_syn(syn);
        tcp.set_ack(ack);
        tcp.set_psh(psh);
        tcp.set_fin(fin);
        tcp.set_rst(rst);
        tcp.payload_mut()[..payload.len()].copy_from_slice(payload);
        tcp.fill_checksum(&ip_addr(src), &ip_addr(dst));
    }
    {
        let mut ip = Ipv4Packet::new_checked(&mut buf[..]).expect("sized ip buffer");
        ip.set_version(4);
        ip.set_header_len(IPV4_HEADER as u8);
        ip.set_total_len(total as u16);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(src.into());
        ip.set_dst_addr(dst.into());
        ip.fill_checksum();
    }
    buf
}

/// Build one IPv4/UDP packet with valid checksums.
#[must_use]
pub fn build_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    const IPV4_HEADER: usize = 20;
    const UDP_HEADER: usize = 8;
    let total = IPV4_HEADER + UDP_HEADER + payload.len();
    assert!(total <= 65535, "packet too large for IPv4");
    let mut buf = vec![0u8; total];
    // No `set_length` in 0.10: length field is bytes 4..6 of the header,
    // written before wrapping (the wrapper borrows the buffer).
    let udp_len = (UDP_HEADER + payload.len()) as u16;
    buf[IPV4_HEADER + 4..IPV4_HEADER + 6].copy_from_slice(&udp_len.to_be_bytes());
    {
        let mut udp = UdpPacket::new_checked(&mut buf[IPV4_HEADER..]).expect("sized udp buffer");
        udp.set_src_port(src_port);
        udp.set_dst_port(dst_port);
        udp.payload_mut()[..payload.len()].copy_from_slice(payload);
        udp.fill_checksum(&ip_addr(src), &ip_addr(dst));
    }
    {
        let mut ip = Ipv4Packet::new_checked(&mut buf[..]).expect("sized ip buffer");
        ip.set_version(4);
        ip.set_header_len(IPV4_HEADER as u8);
        ip.set_total_len(total as u16);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(src.into());
        ip.set_dst_addr(dst.into());
        ip.fill_checksum();
    }
    buf
}
