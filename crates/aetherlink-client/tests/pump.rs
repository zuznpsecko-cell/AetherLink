//! TDD RED (Phase W3): TUN<->mux DataPump bridge over a fake TUN.
//!
//! No privileges needed: `FakeTun` implements `TunPackets` in memory.
//! Tests prove stateless packet<->frame mapping (TCP SYN -> OPEN+DATA,
//! UDP DNS -> OPEN+DATAGRAM), the reverse path (mux -> IP packet into TUN),
//! and fail-closed behavior on tamper/truncation.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use aetherlink_client::pump::DataPump;
use aetherlink_frame::codec::FrameHeader;
use aetherlink_mux::manager::MuxManager;
use aetherlink_netstack::smoltcp_wrapper::{build_tcp_packet, build_udp_packet};
use aetherlink_netstack::tun::TunPackets;

const KEY: [u8; 32] = [7u8; 32];
const PAD: usize = 128;

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 2);
const SERVER_DST: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const DNS_UPSTREAM: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

/// In-memory TUN stand-in: `feed` pushes inbound, `outbound` drains writes.
#[derive(Debug, Default)]
struct FakeTun {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

impl FakeTun {
    fn with_packets(pkts: Vec<Vec<u8>>) -> Self {
        Self {
            inbound: pkts.into(),
            outbound: Vec::new(),
        }
    }
}

impl TunPackets for FakeTun {
    fn try_recv(&mut self) -> aetherlink_netstack::Result<Option<Vec<u8>>> {
        Ok(self.inbound.pop_front())
    }

    fn send_packet(&mut self, pkt: &[u8]) -> aetherlink_netstack::Result<()> {
        self.outbound.push(pkt.to_vec());
        Ok(())
    }
}

#[test]
fn tcp_syn_becomes_open_plus_data() {
    // Given: TCP SYN from TUN toward an external target
    let syn = build_tcp_packet(
        CLIENT_IP,
        SERVER_DST,
        40000,
        443,
        true,
        false,
        false,
        1000,
        0,
        &[],
    );
    let mut tun = FakeTun::with_packets(vec![syn]);
    let mut pump = DataPump::new(KEY, PAD);
    // When: polling once
    let frames = pump.poll_once(&mut tun).expect("poll");
    // Then: OPEN_TCP (seq 0) + DATA frames, both parseable server-side
    assert_eq!(frames.len(), 2, "SYN must yield OPEN + DATA");
    let mut server = MuxManager::new();
    let tcp = MuxManager::parse_open_tcp(&KEY, &frames[0].header, &frames[0].ciphertext)
        .expect("open parses");
    assert_eq!(tcp.addr, SERVER_DST.to_string());
    assert_eq!(tcp.port, 443);
    server
        .register_inbound(tcp.id, &tcp.addr, tcp.port, false)
        .expect("register");
    let data_hdr = FrameHeader {
        length: frames[1].header.length,
        frame_type: frames[1].header.frame_type,
        flags: 0,
        stream_id: tcp.id,
        sequence: frames[1].header.sequence,
    };
    assert!(server
        .open_data(&KEY, &data_hdr, &frames[1].ciphertext)
        .is_ok());
}

#[test]
fn udp_dns_becomes_open_plus_datagram() {
    // Given: UDP DNS query from TUN toward upstream
    let query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01];
    let udp = build_udp_packet(CLIENT_IP, DNS_UPSTREAM, 53000, 53, &query);
    let mut tun = FakeTun::with_packets(vec![udp]);
    let mut pump = DataPump::new(KEY, PAD);
    // When: polling once
    let frames = pump.poll_once(&mut tun).expect("poll");
    // Then: OPEN_UDP (seq 0) + DATAGRAM frames, both parseable server-side
    assert_eq!(frames.len(), 2, "UDP must yield OPEN + DATAGRAM");
    let mut server = MuxManager::new();
    let flow = MuxManager::parse_open_udp(&KEY, &frames[0].header, &frames[0].ciphertext)
        .expect("open parses");
    assert_eq!(flow.addr, DNS_UPSTREAM.to_string());
    assert_eq!(flow.port, 53);
    server
        .register_inbound(flow.id, &flow.addr, flow.port, true)
        .expect("register");
    let dgram_hdr = FrameHeader {
        length: frames[1].header.length,
        frame_type: frames[1].header.frame_type,
        flags: 0,
        stream_id: flow.id,
        sequence: frames[1].header.sequence,
    };
    let payload = server
        .open_datagram(&KEY, &dgram_hdr, &frames[1].ciphertext)
        .expect("datagram opens");
    assert_eq!(payload, query);
}

#[test]
fn mux_data_becomes_tcp_packet_in_tun() {
    // Given: established TCP flow via a prior SYN poll
    let syn = build_tcp_packet(
        CLIENT_IP,
        SERVER_DST,
        40001,
        80,
        true,
        false,
        false,
        2000,
        0,
        &[],
    );
    let mut tun = FakeTun::with_packets(vec![syn]);
    let mut pump = DataPump::new(KEY, PAD);
    let frames = pump.poll_once(&mut tun).expect("poll");
    let id = frames[0].header.stream_id;
    // When: server reply bytes arrive via mux (sealed by a peer mux)
    let mut peer = MuxManager::new();
    peer.register_inbound(id, &SERVER_DST.to_string(), 80, false)
        .expect("register");
    let reply = b"hello-back";
    // Seal with matching (id, seq): peer starts at seq 1 like the pump side.
    let sealed = peer.seal_data(&KEY, id, reply, PAD).expect("seal");
    pump.receive_mux(&sealed.header, &sealed.ciphertext, &mut tun)
        .expect("inject");
    // Then: one TCP packet toward TUN carries the payload
    assert_eq!(tun.outbound.len(), 1);
    let parsed = aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(&tun.outbound[0])
        .expect("valid ip");
    assert_eq!(parsed.dst, CLIENT_IP);
    let seg = parsed.tcp().expect("tcp");
    assert_eq!(seg.dst_port, 40001);
    assert_eq!(seg.payload, reply);
}

#[test]
fn mux_datagram_becomes_udp_packet_in_tun() {
    // Given: established UDP flow via a prior poll
    let query = vec![0xAA, 0xBB, 0x01, 0x00];
    let udp = build_udp_packet(CLIENT_IP, DNS_UPSTREAM, 53001, 53, &query);
    let mut tun = FakeTun::with_packets(vec![udp]);
    let mut pump = DataPump::new(KEY, PAD);
    let frames = pump.poll_once(&mut tun).expect("poll");
    let id = frames[0].header.stream_id;
    // When: DNS answer arrives via mux
    let mut peer = MuxManager::new();
    peer.register_inbound(id, &DNS_UPSTREAM.to_string(), 53, true)
        .expect("register");
    let answer = vec![0xAA, 0xBB, 0x81, 0x80];
    let sealed = peer.seal_datagram(&KEY, id, &answer, PAD).expect("seal");
    pump.receive_mux(&sealed.header, &sealed.ciphertext, &mut tun)
        .expect("inject");
    // Then: one UDP packet toward TUN carries the answer
    assert_eq!(tun.outbound.len(), 1);
    let parsed = aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(&tun.outbound[0])
        .expect("valid ip");
    assert_eq!(parsed.dst, CLIENT_IP);
    let dgram = parsed.udp().expect("udp");
    assert_eq!(dgram.dst_port, 53001);
    assert_eq!(dgram.payload, answer);
}

#[test]
fn tampered_frame_fails_closed_without_tun_write() {
    // Given: established flow + a tampered mux frame
    let syn = build_tcp_packet(
        CLIENT_IP,
        SERVER_DST,
        40002,
        443,
        true,
        false,
        false,
        3000,
        0,
        &[],
    );
    let mut tun = FakeTun::with_packets(vec![syn]);
    let mut pump = DataPump::new(KEY, PAD);
    let frames = pump.poll_once(&mut tun).expect("poll");
    let mut bad = frames[1].clone();
    bad.ciphertext[0] ^= 0xFF;
    // When: injecting the tampered frame -> Then: Err, nothing written to TUN
    assert!(pump
        .receive_mux(&bad.header, &bad.ciphertext, &mut tun)
        .is_err());
    assert!(tun.outbound.is_empty(), "tamper must not reach TUN");
}

#[test]
fn truncated_ip_packet_is_dropped() {
    // Given: garbage bytes in TUN
    let mut tun = FakeTun::with_packets(vec![vec![0x45, 0x00, 0x00]]);
    let mut pump = DataPump::new(KEY, PAD);
    // When: polling -> Then: dropped, no frames, no panic
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert!(frames.is_empty());
}

#[test]
fn link_local_discovery_never_enters_tunnel() {
    // Given: LLMNR + mDNS + NetBIOS + SSDP packets from TUN
    let llmnr = build_udp_packet(
        CLIENT_IP,
        Ipv4Addr::new(224, 0, 0, 252),
        55000,
        5355,
        b"llmnr?",
    );
    let mdns = build_udp_packet(
        CLIENT_IP,
        Ipv4Addr::new(224, 0, 0, 251),
        5353,
        5353,
        b"mdns?",
    );
    let netbios = build_udp_packet(CLIENT_IP, Ipv4Addr::new(10, 255, 0, 3), 137, 137, b"nbns?");
    let ssdp = build_udp_packet(
        CLIENT_IP,
        Ipv4Addr::new(239, 255, 255, 250),
        1900,
        1900,
        b"ssdp?",
    );
    let mut tun = FakeTun::with_packets(vec![llmnr, mdns, netbios, ssdp]);
    let mut pump = DataPump::new(KEY, PAD);
    // When: polling -> Then: nothing sealed (link-local by design, TTL 1).
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert!(frames.is_empty());
}

#[test]
fn unicast_dns_still_flows() {
    // Given: ordinary DNS query to the virtual resolver
    let query = build_udp_packet(CLIENT_IP, Ipv4Addr::new(10, 255, 0, 1), 54000, 53, b"q?");
    let mut tun = FakeTun::with_packets(vec![query]);
    let mut pump = DataPump::new(KEY, PAD);
    // When: polling -> Then: OPEN + DATAGRAM as before.
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert_eq!(frames.len(), 2);
}
