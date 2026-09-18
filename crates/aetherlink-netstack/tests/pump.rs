//! TDD RED: IP-packet ↔ flow-segment pump over smoltcp wire types.
//!
//! The TUN device yields raw IP packets; the pump parses them into
//! TCP segments / UDP datagrams (→ OPEN + DATA frames) and builds reply
//! packets back. Checksums verified on parse, filled on build. No sockets,
//! no timers, no privileges needed here.

use std::net::Ipv4Addr;

use aetherlink_netstack::smoltcp_wrapper::{build_tcp_packet, build_udp_packet, parse_ipv4_packet};

fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

#[test]
fn parse_tcp_syn_fields() {
    // Given: SYN built by the pump itself
    let raw = build_tcp_packet(
        v4(10, 0, 0, 2),
        v4(93, 184, 216, 34),
        40001,
        443,
        true,
        false,
        false,
        0x1122_3344,
        0,
        &[],
    );
    // When: parsed back
    let pkt = parse_ipv4_packet(&raw).expect("parse");
    // Then: every field survives the roundtrip.
    assert_eq!((pkt.src, pkt.dst), (v4(10, 0, 0, 2), v4(93, 184, 216, 34)));
    let seg = pkt.tcp().expect("tcp segment");
    assert_eq!((seg.src_port, seg.dst_port), (40001, 443));
    assert!(seg.syn && !seg.ack && !seg.psh && !seg.rst && !seg.fin);
    assert_eq!(seg.seq, 0x1122_3344);
    assert!(seg.payload.is_empty());
}

#[test]
fn parse_udp_dns_query_transparent() {
    // Given: DNS query bytes as UDP payload
    let query = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    let raw = build_udp_packet(v4(10, 0, 0, 2), v4(10, 255, 0, 1), 53001, 53, query);
    // When: parsed back
    let pkt = parse_ipv4_packet(&raw).expect("parse");
    // Then: ports + payload byte-identical (DNS transparency).
    assert_eq!((pkt.src, pkt.dst), (v4(10, 0, 0, 2), v4(10, 255, 0, 1)));
    let dgram = pkt.udp().expect("udp datagram");
    assert_eq!((dgram.src_port, dgram.dst_port), (53001, 53));
    assert_eq!(dgram.payload, query);
}

#[test]
fn tcp_reply_swaps_endpoints() {
    // Given: inbound SYN-ACK built as a reply
    let raw = build_tcp_packet(
        v4(93, 184, 216, 34),
        v4(10, 0, 0, 2),
        443,
        40001,
        true,
        true,
        false,
        0x5566_7788,
        0x1122_3345,
        &[],
    );
    // When: parsed back → Then: swapped endpoints, SYN+ACK set.
    let pkt = parse_ipv4_packet(&raw).expect("parse");
    assert_eq!((pkt.src, pkt.dst), (v4(93, 184, 216, 34), v4(10, 0, 0, 2)));
    let seg = pkt.tcp().expect("tcp");
    assert!(seg.syn && seg.ack);
    assert_eq!(seg.seq, 0x5566_7788);
    assert_eq!(seg.ack_num, 0x1122_3345);
}

#[test]
fn tcp_data_payload_roundtrip() {
    // Given: PSH+ACK with payload
    let raw = build_tcp_packet(
        v4(10, 0, 0, 2),
        v4(93, 184, 216, 34),
        40001,
        443,
        false,
        true,
        true,
        1000,
        5000,
        b"GET / HTTP/1.0\r\n\r\n",
    );
    // When/Then: payload survives untouched.
    let pkt = parse_ipv4_packet(&raw).expect("parse");
    let seg = pkt.tcp().expect("tcp");
    assert!(seg.psh && seg.ack && !seg.syn);
    assert_eq!(seg.payload, b"GET / HTTP/1.0\r\n\r\n");
}

#[test]
fn rejects_non_ipv4_and_truncated() {
    // Given: version-6 first nibble → Then: BadVersion.
    let mut bad = build_udp_packet(v4(10, 0, 0, 2), v4(10, 255, 0, 1), 1, 53, b"q");
    bad[0] = (6 << 4) | (bad[0] & 0x0F);
    assert!(parse_ipv4_packet(&bad).is_err());
    // Given: truncated buffer → Then: Err, never a panic.
    assert!(parse_ipv4_packet(&[0u8; 10]).is_err());
    assert!(parse_ipv4_packet(&[]).is_err());
}

#[test]
fn rejects_tampered_tcp_checksum() {
    // Given: valid SYN with one flipped payload/checksum byte
    let mut raw = build_tcp_packet(
        v4(10, 0, 0, 2),
        v4(93, 184, 216, 34),
        40001,
        443,
        true,
        false,
        false,
        1,
        0,
        b"tamper-me",
    );
    let last = raw.len() - 1;
    raw[last] ^= 0xFF;
    // When/Then: checksum verification fails closed.
    assert!(parse_ipv4_packet(&raw).is_err());
}
