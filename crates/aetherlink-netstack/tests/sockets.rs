//! TDD RED: socket-level pump over smoltcp (no privileges).
//!
//! A `SocketPump` owns Interface + loopback-style device + sockets: TUN
//! bytes go in via `inject`, stack replies come out via `take_tx`,
//! flow events via `poll_step`. TCP handshake, data, UDP echo and RST
//! for closed ports — all without root.

use std::net::Ipv4Addr;

use aetherlink_netstack::smoltcp_wrapper::{build_tcp_packet, build_udp_packet, parse_ipv4_packet};
use aetherlink_netstack::sockets::{PumpEvent, SocketPump};

fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

const TUN: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 2);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);

#[test]
fn tcp_handshake_accepts_and_data_flows() {
    // Given: pump listening like a TUN stack would
    let mut pump = SocketPump::new(TUN);
    let h = pump.tcp_listen(8080);
    // When: SYN arrives from the app side
    pump.inject(&build_tcp_packet(
        PEER,
        TUN,
        40001,
        8080,
        true,
        false,
        false,
        1000,
        0,
        &[],
    ));
    pump.poll_step(50);
    // Then: SYN-ACK goes back toward TUN.
    let tx = pump.take_tx();
    assert!(!tx.is_empty(), "SYN-ACK must be emitted");
    let pkt = parse_ipv4_packet(&tx[0]).expect("parse syn-ack");
    let seg = pkt.tcp().expect("tcp");
    assert_eq!((seg.src_port, seg.dst_port), (8080, 40001));
    assert!(seg.syn && seg.ack, "must be SYN-ACK");
    let server_seq = seg.seq;
    // When: ACK + PSH data completes the handshake and sends bytes
    pump.inject(&build_tcp_packet(
        PEER,
        TUN,
        40001,
        8080,
        false,
        true,
        false,
        1001,
        server_seq + 1,
        &[],
    ));
    pump.inject(&build_tcp_packet(
        PEER,
        TUN,
        40001,
        8080,
        false,
        true,
        true,
        1001,
        server_seq + 1,
        b"hello",
    ));
    let events = pump.poll_step(50);
    // Then: accepted + data events surface.
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PumpEvent::TcpAccepted { .. })),
        "accepted, got {events:?}"
    );
    let data: Vec<u8> = events
        .iter()
        .filter_map(|e| match e {
            PumpEvent::TcpData { handle, data } if *handle == h => Some(data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(data, b"hello");
}

#[test]
fn tcp_send_emits_packet_toward_tun() {
    // Given: established flow from the previous scenario shape
    let mut pump = SocketPump::new(TUN);
    let h = pump.tcp_listen(8080);
    pump.inject(&build_tcp_packet(
        PEER,
        TUN,
        40001,
        8080,
        true,
        false,
        false,
        1000,
        0,
        &[],
    ));
    pump.poll_step(50);
    // drain the SYN-ACK first, learning the server sequence number
    let tx = pump.take_tx();
    let synack = parse_ipv4_packet(&tx[0]).expect("parse syn-ack");
    let server_seq = synack.tcp().expect("tcp").seq;
    pump.inject(&build_tcp_packet(
        PEER,
        TUN,
        40001,
        8080,
        false,
        true,
        false,
        1001,
        server_seq + 1,
        &[],
    ));
    pump.poll_step(50);
    // When: stack sends reply bytes
    pump.tcp_send(h, b"world").expect("send");
    pump.poll_step(50);
    // Then: a DATA packet toward TUN appears.
    let tx = pump.take_tx();
    let datas: Vec<Vec<u8>> = tx
        .iter()
        .filter_map(|raw| {
            parse_ipv4_packet(raw)
                .ok()
                .and_then(|p| p.tcp().map(|s| s.payload.clone()))
        })
        .filter(|p| !p.is_empty())
        .collect();
    assert!(
        datas.iter().any(|p| p == b"world"),
        "world must go out, got {datas:?}"
    );
}

#[test]
fn udp_datagram_roundtrip() {
    // Given: bound UDP socket (e.g. virtual DNS)
    let mut pump = SocketPump::new(TUN);
    let h = pump.udp_bind(53);
    // When: query arrives
    let query = b"\xab\xcd\x01\x00query";
    pump.inject(&build_udp_packet(PEER, TUN, 53001, 53, query));
    let events = pump.poll_step(50);
    // Then: datagram event with transparent payload + source.
    let found = events.iter().any(|e| match e {
        PumpEvent::UdpDatagram { handle, data, from } => {
            *handle == h && data == query && from.ip() == PEER && from.port() == 53001
        }
        _ => false,
    });
    assert!(found, "datagram event, got {events:?}");
    // When: replying → Then: packet toward TUN with swapped ports.
    pump.udp_send(
        h,
        b"\xab\xcd\x81\x80answer",
        "10.0.0.9:53001".parse().expect("sa"),
    )
    .expect("udp send");
    pump.poll_step(50);
    let tx = pump.take_tx();
    let pkt = parse_ipv4_packet(&tx[0]).expect("parse reply");
    let dgram = pkt.udp().expect("udp");
    assert_eq!((dgram.src_port, dgram.dst_port), (53, 53001));
    assert_eq!(dgram.payload, b"\xab\xcd\x81\x80answer");
}

#[test]
fn closed_port_gets_rst() {
    // Given: pump with nothing listening
    let mut pump = SocketPump::new(TUN);
    // When: SYN to a closed port
    pump.inject(&build_tcp_packet(
        PEER,
        TUN,
        40001,
        9999,
        true,
        false,
        false,
        7,
        0,
        &[],
    ));
    pump.poll_step(50);
    // Then: RST back (fail closed, never swallowed).
    let tx = pump.take_tx();
    assert!(!tx.is_empty(), "RST must be emitted");
    let pkt = parse_ipv4_packet(&tx[0]).expect("parse rst");
    let seg = pkt.tcp().expect("tcp");
    assert!(seg.rst, "must be RST, got syn={} ack={}", seg.syn, seg.ack);
}
