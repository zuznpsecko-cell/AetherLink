//! TDD RED (Phase I3-tail): client-side TCP termination in DataPump.
//!
//! The pump ends TCP itself (SYN→SYN-ACK, sequence tracking, FIN/RST) and
//! only payload crosses the mux. FakeTun in memory, no privileges. Server
//! replies return as TCP segments with a correct sequence chain.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use aetherlink_client::pump::DataPump;
use aetherlink_frame::codec::FrameHeader;
use aetherlink_mux::manager::MuxManager;
use aetherlink_netstack::smoltcp_wrapper::{
    build_tcp_packet, build_tcp_packet_full, parse_ipv4_packet, ParsedPacket,
};
use aetherlink_netstack::tun::TunPackets;

const KEY: [u8; 32] = [11u8; 32];
const PAD: usize = 128;
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 2);
const DST: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

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

    fn take_outbound(&mut self) -> Vec<ParsedPacket> {
        self.outbound
            .drain(..)
            .map(|raw| parse_ipv4_packet(&raw).expect("pump emits valid ip"))
            .collect()
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

fn syn(seq: u32) -> Vec<u8> {
    build_tcp_packet(CLIENT_IP, DST, 41000, 80, true, false, false, seq, 0, &[])
}

fn advance(pump: &mut DataPump, tun: &mut FakeTun) {
    pump.poll_once(tun).expect("poll");
}

/// Full handshake, returns (client_isn, server_iss).
fn handshake(pump: &mut DataPump, tun: &mut FakeTun, isn: u32) -> (u32, u32) {
    // Given: SYN in TUN
    tun.inbound.push_back(syn(isn));
    // When: polling -> Then: SYN-ACK out to TUN, nothing upstream yet.
    let frames = pump.poll_once(tun).expect("poll");
    assert!(frames.is_empty(), "handshake emits no mux frames");
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1, "exactly one SYN-ACK");
    let seg = out[0].tcp().expect("tcp");
    assert!(seg.syn && seg.ack && !seg.psh);
    assert_eq!(seg.ack_num, isn.wrapping_add(1));
    assert_eq!(seg.dst_port, 41000);
    let iss = seg.seq;
    // When: ACK completes -> Then: silence (pure ACK, no new flow yet).
    let ack = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        false,
        isn.wrapping_add(1),
        iss.wrapping_add(1),
        &[],
    );
    tun.inbound.push_back(ack);
    let frames = pump.poll_once(tun).expect("poll");
    assert!(frames.is_empty());
    assert!(tun.take_outbound().is_empty());
    (isn, iss)
}

#[test]
fn syn_gets_synack_without_mux_frames() {
    // Given: fresh pump + SYN
    let mut tun = FakeTun::with_packets(vec![syn(1000)]);
    let mut pump = DataPump::new(KEY, PAD);
    // When: polling -> Then: SYN-ACK to TUN, zero frames upstream.
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert!(frames.is_empty());
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    let seg = out[0].tcp().expect("tcp");
    assert!(seg.syn && seg.ack);
    assert_eq!(seg.ack_num, 1001);
}

#[test]
fn retransmitted_syn_resends_synack() {
    // Given: handshake done (SYN-ACK emitted, outbound drained)
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    handshake(&mut pump, &mut tun, 2000);
    // When: same SYN again (lost SYN-ACK) -> Then: SYN-ACK re-emitted.
    tun.inbound.push_back(syn(2000));
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert!(frames.is_empty());
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    assert!(out[0].tcp().expect("tcp").syn);
}

#[test]
fn established_data_opens_mux_once() {
    // Given: established flow
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    let (isn, iss) = handshake(&mut pump, &mut tun, 3000);
    // When: PSH with payload -> Then: OPEN_TCP + DATA, parseable server-side.
    let data = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        true,
        isn.wrapping_add(1),
        iss.wrapping_add(1),
        b"GET / HTTP/1.0\r\n\r\n",
    );
    tun.inbound.push_back(data);
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert_eq!(frames.len(), 2, "OPEN + first DATA");
    let mut server = MuxManager::new();
    let tcp = MuxManager::parse_open_tcp(&KEY, &frames[0].header, &frames[0].ciphertext)
        .expect("open parses");
    assert_eq!(tcp.addr, DST.to_string());
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
    let pt = server
        .open_data(&KEY, &data_hdr, &frames[1].ciphertext)
        .expect("data opens");
    assert_eq!(pt, b"GET / HTTP/1.0\r\n\r\n");
}

#[test]
fn server_reply_returns_with_sequence_chain() {
    // Given: established flow with one client payload already upstream
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    let (isn, iss) = handshake(&mut pump, &mut tun, 4000);
    let data = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        true,
        isn.wrapping_add(1),
        iss.wrapping_add(1),
        b"ping",
    );
    tun.inbound.push_back(data);
    let frames = pump.poll_once(&mut tun).expect("poll");
    let id = frames[0].header.stream_id;
    // When: two mux DATA replies arrive -> Then: two TCP segments, seq chain.
    let mut peer = MuxManager::new();
    peer.register_inbound(id, &DST.to_string(), 80, false)
        .expect("register");
    for reply in [b"one".as_slice(), b"two".as_slice()] {
        let sealed = peer.seal_data(&KEY, id, reply, PAD).expect("seal");
        pump.receive_mux(&sealed.header, &sealed.ciphertext, &mut tun)
            .expect("inject");
    }
    let out = tun.take_outbound();
    assert_eq!(out.len(), 2);
    let first = out[0].tcp().expect("tcp");
    let second = out[1].tcp().expect("tcp");
    assert!(first.psh && first.ack);
    assert_eq!(first.payload, b"one");
    assert_eq!(first.dst_port, 41000);
    assert_eq!(
        second.seq,
        first.seq.wrapping_add(first.payload.len() as u32)
    );
    assert_eq!(second.payload, b"two");
    assert_eq!(second.ack_num, isn.wrapping_add(1).wrapping_add(4));
}

#[test]
fn app_fin_closes_flow_with_fin_ack() {
    // Given: established flow
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    let (isn, iss) = handshake(&mut pump, &mut tun, 5000);
    // When: FIN (no payload) -> Then: FIN+ACK out to TUN, flow forgotten
    // (later packets for it are dropped, no mux frames ever again).
    let fin = build_tcp_packet_full(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        false,
        true,
        false,
        isn.wrapping_add(1),
        iss.wrapping_add(1),
        &[],
    );
    tun.inbound.push_back(fin);
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert!(frames.is_empty());
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    let seg = out[0].tcp().expect("tcp");
    assert!(seg.fin && seg.ack);
    assert_eq!(seg.ack_num, isn.wrapping_add(2));
    // And: stragglers for the closed flow are dropped silently.
    let stray = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        true,
        isn.wrapping_add(1),
        iss.wrapping_add(1),
        b"late",
    );
    tun.inbound.push_back(stray);
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert!(frames.is_empty());
    assert!(tun.take_outbound().is_empty());
}

#[test]
fn app_rst_forgets_flow_silently() {
    // Given: established flow
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    handshake(&mut pump, &mut tun, 6000);
    // When: RST arrives -> Then: nothing emitted, flow gone (no mux RST:
    // the server would treat Rst frames as loop-fatal).
    let rst = build_tcp_packet_full(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        false,
        false,
        false,
        true,
        6001,
        0,
        &[],
    );
    tun.inbound.push_back(rst);
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert!(frames.is_empty());
    assert!(tun.take_outbound().is_empty());
}
