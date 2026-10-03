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
    let _ = tun.take_outbound(); // prompt self-ack (not part of reply chain)
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
    // When: FIN (no payload) -> Then: FIN+ACK out to TUN and the flow is
    // half-closed: this flow never opened a mux stream, so nothing goes
    // upstream and later packets for it are dropped silently.
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
    // When: RST arrives -> Then: nothing emitted, flow gone. No mux RST
    // frame is ever sent (the server treats Rst as loop-fatal); a flow
    // that already has a stream tells the relay with an empty DATA
    // instead (see app_fin_announces_half_close_and_still_delivers_the_answer).
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

/// TunPackets wrapper failing the next send_packet on demand (wintun ring
/// full under flood). A failed send must never desync the flow tables.
struct FlakyTun {
    inner: FakeTun,
    fail_send: bool,
}

impl TunPackets for FlakyTun {
    fn try_recv(&mut self) -> aetherlink_netstack::Result<Option<Vec<u8>>> {
        self.inner.try_recv()
    }

    fn send_packet(&mut self, pkt: &[u8]) -> aetherlink_netstack::Result<()> {
        if self.fail_send {
            self.fail_send = false;
            return Err(aetherlink_netstack::NetstackError::InvalidPacket(
                "injected send failure".to_string(),
            ));
        }
        self.inner.send_packet(pkt)
    }
}

#[test]
fn failed_sends_keep_tables_consistent() {
    // Given: established flow with mux id allocated (one payload upstream)
    let mut tun = FlakyTun {
        inner: FakeTun::with_packets(vec![syn(7000)]),
        fail_send: false,
    };
    let mut pump = DataPump::new(KEY, PAD);
    assert!(pump.poll_once(&mut tun).expect("poll").is_empty());
    let out = tun.inner.take_outbound();
    assert_eq!(out.len(), 1);
    let iss = out[0].tcp().expect("tcp").seq;
    let ack = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        false,
        7001,
        iss.wrapping_add(1),
        &[],
    );
    tun.inner.inbound.push_back(ack);
    assert!(pump.poll_once(&mut tun).expect("poll").is_empty());
    let data = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        true,
        7001,
        iss.wrapping_add(1),
        b"hi",
    );
    tun.inner.inbound.push_back(data);
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert_eq!(frames.len(), 2);
    let id = frames[0].header.stream_id;
    let _ = tun.inner.take_outbound(); // prompt self-ack
                                       // When: duplicate SYN while the TUN send fails (ring full)
    tun.fail_send = true;
    tun.inner.inbound.push_back(syn(7000));
    // Then: clean Err, no panic — and the flow still works after.
    assert!(pump.poll_once(&mut tun).is_err());
    let mut peer = MuxManager::new();
    peer.register_inbound(id, &DST.to_string(), 80, false)
        .expect("register");
    let one = peer.seal_data(&KEY, id, b"one", PAD).expect("seal");
    pump.receive_mux(&one.header, &one.ciphertext, &mut tun)
        .expect("flow survived failed resend");
    assert_eq!(tun.inner.take_outbound().len(), 1);
    // When: a mux reply fails its TUN send -> Then: Err, flow survives again.
    tun.fail_send = true;
    let two = peer.seal_data(&KEY, id, b"two", PAD).expect("seal");
    assert!(pump
        .receive_mux(&two.header, &two.ciphertext, &mut tun)
        .is_err());
    let three = peer.seal_data(&KEY, id, b"three", PAD).expect("seal");
    pump.receive_mux(&three.header, &three.ciphertext, &mut tun)
        .expect("flow survived failed inject");
    let out = tun.inner.take_outbound();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].tcp().expect("tcp").payload, b"three");
}

#[test]
fn retransmitted_data_is_dropped_without_recount() {
    // Given: established flow, one payload ("hi") already upstream
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    let (isn, iss) = handshake(&mut pump, &mut tun, 8000);
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
        b"hi",
    );
    tun.inbound.push_back(data);
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert_eq!(frames.len(), 2);
    let id = frames[0].header.stream_id;
    let _ = tun.take_outbound(); // prompt self-ack (dup must add nothing)
                                 // When: the same segment retransmitted (app RTO, no answer yet)
    let dup = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        true,
        isn.wrapping_add(1),
        iss.wrapping_add(1),
        b"hi",
    );
    tun.inbound.push_back(dup);
    // Then: dropped silently — no second upstream copy, no recount.
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert!(frames.is_empty());
    assert!(tun.take_outbound().is_empty());
    // And: the next server reply still acks exactly isn+1+2.
    let mut peer = MuxManager::new();
    peer.register_inbound(id, &DST.to_string(), 80, false)
        .expect("register");
    let sealed = peer.seal_data(&KEY, id, b"ok", PAD).expect("seal");
    pump.receive_mux(&sealed.header, &sealed.ciphertext, &mut tun)
        .expect("inject");
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].tcp().expect("tcp").ack_num,
        isn.wrapping_add(1).wrapping_add(2)
    );
}

#[test]
fn forwarded_data_emits_prompt_ack() {
    // Given: established flow (split-TCP must ack hop-by-hop: the app
    // stalls past cwnd if ACKs only piggyback on target replies, seen
    // live as 3KB/s bulk upload then stall)
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    let (isn, _iss) = handshake(&mut pump, &mut tun, 9000);
    let data = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        true,
        isn.wrapping_add(1),
        70000,
        b"hi",
    );
    tun.inbound.push_back(data);
    // When: payload forwarded upstream
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert_eq!(frames.len(), 2);
    // Then: a pure ACK is injected immediately (no SYN/FIN, no payload).
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    let seg = out[0].tcp().expect("tcp");
    assert!(seg.ack && !seg.syn && !seg.fin && !seg.rst);
    assert_eq!(seg.ack_num, isn.wrapping_add(1).wrapping_add(2));
    assert!(seg.payload.is_empty());
}

/// Build a data segment from the app (`CLIENT_IP:port` -> `DST:80`).
fn data_at(port: u16, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    build_tcp_packet(
        CLIENT_IP, DST, port, 80, false, true, true, seq, ack, payload,
    )
}

#[test]
fn app_fin_announces_half_close_and_still_delivers_the_answer() {
    // Given: established flow with one payload upstream
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    let (isn, iss) = handshake(&mut pump, &mut tun, 11000);
    tun.inbound.push_back(data_at(
        41000,
        isn.wrapping_add(1),
        iss.wrapping_add(1),
        b"hi",
    ));
    let frames = pump.poll_once(&mut tun).expect("poll");
    assert_eq!(frames.len(), 2);
    let id = frames[0].header.stream_id;
    let _ = tun.take_outbound(); // prompt self-ack
    let mut peer = MuxManager::new();
    peer.register_inbound(id, &DST.to_string(), 80, false)
        .expect("register");

    // When: the app FINs (request complete, send side closed)
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
        isn.wrapping_add(3),
        iss.wrapping_add(1),
        &[],
    );
    tun.inbound.push_back(fin);
    let frames = pump.poll_once(&mut tun).expect("poll");
    // Then: the app gets its FIN-ACK ...
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    assert!(out[0].tcp().expect("tcp").fin);
    // ... and the relay hears the half-close (one empty DATA), so the
    // target socket is released instead of hanging to its own timeout.
    assert_eq!(frames.len(), 1, "exactly the close signal");
    assert_eq!(frames[0].header.stream_id, id);
    let closed = peer
        .open_data(&KEY, &frames[0].header, &frames[0].ciphertext)
        .expect("close signal opens");
    assert!(closed.is_empty(), "empty DATA = half-close");

    // And: the answer still reaches the app (half-close is not a teardown).
    let reply = peer.seal_data(&KEY, id, b"ok", PAD).expect("seal reply");
    pump.receive_mux(&reply.header, &reply.ciphertext, &mut tun)
        .expect("answer injected");
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].tcp().expect("tcp").payload, b"ok");

    // And: the peer's own close ends the flow (FIN to the app, id freed).
    let over = peer.seal_data(&KEY, id, b"", PAD).expect("seal close");
    pump.receive_mux(&over.header, &over.ciphertext, &mut tun)
        .expect("close injected");
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    assert!(out[0].tcp().expect("tcp").fin);
    let after = peer.seal_data(&KEY, id, b"late", PAD).expect("seal late");
    assert!(
        pump.receive_mux(&after.header, &after.ciphertext, &mut tun)
            .is_err(),
        "flow is gone once both sides closed"
    );
}

#[test]
fn peer_close_fins_the_app_socket() {
    // Given: established flow with payload upstream
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    let (isn, iss) = handshake(&mut pump, &mut tun, 12000);
    tun.inbound.push_back(data_at(
        41000,
        isn.wrapping_add(1),
        iss.wrapping_add(1),
        b"hi",
    ));
    let frames = pump.poll_once(&mut tun).expect("poll");
    let id = frames[0].header.stream_id;
    let _ = tun.take_outbound();
    let mut peer = MuxManager::new();
    peer.register_inbound(id, &DST.to_string(), 80, false)
        .expect("register");
    // When: the relay reports the stream is over (empty DATA)
    let over = peer.seal_data(&KEY, id, b"", PAD).expect("seal close");
    pump.receive_mux(&over.header, &over.ciphertext, &mut tun)
        .expect("close injected");
    // Then: the app's socket is closed, not left to hang.
    let out = tun.take_outbound();
    assert_eq!(out.len(), 1);
    let seg = out[0].tcp().expect("tcp");
    assert!(seg.fin && seg.ack);
    assert_eq!(seg.ack_num, isn.wrapping_add(1).wrapping_add(2));
}

#[test]
fn finished_flows_free_their_stream_ids() {
    // Given: a long-lived session (the mux has 4096 ids; a browser burns
    // far more than that over one session, and the pump used to die there)
    let mut tun = FakeTun::default();
    let mut pump = DataPump::new(KEY, PAD);
    let mut peer = MuxManager::new();
    let flows = 4200u16;
    for i in 0..flows {
        let port = 41000u16.wrapping_add(i);
        let isn = 20_000 + u32::from(i);
        // SYN -> SYN-ACK
        tun.inbound.push_back(build_tcp_packet_full(
            CLIENT_IP,
            DST,
            port,
            80,
            true,
            false,
            false,
            false,
            false,
            isn,
            0,
            &[],
        ));
        let frames = pump.poll_once(&mut tun).expect("syn accepted");
        assert!(frames.is_empty());
        let out = tun.take_outbound();
        let iss = out[0].tcp().expect("tcp").seq;
        // ACK -> established, then one payload byte upstream.
        tun.inbound.push_back(build_tcp_packet_full(
            CLIENT_IP,
            DST,
            port,
            80,
            false,
            true,
            false,
            false,
            false,
            isn.wrapping_add(1),
            iss.wrapping_add(1),
            &[],
        ));
        let _ = pump.poll_once(&mut tun).expect("ack accepted");
        tun.inbound.push_back(data_at(
            port,
            isn.wrapping_add(1),
            iss.wrapping_add(1),
            b"x",
        ));
        let frames = pump.poll_once(&mut tun).expect("payload forwarded");
        assert_eq!(frames.len(), 2, "OPEN + DATA on flow {i}");
        let id = frames[0].header.stream_id;
        let _ = tun.take_outbound();
        // FIN -> half-close announced upstream.
        tun.inbound.push_back(build_tcp_packet_full(
            CLIENT_IP,
            DST,
            port,
            80,
            false,
            true,
            false,
            true,
            false,
            isn.wrapping_add(2),
            iss.wrapping_add(1),
            &[],
        ));
        let frames = pump.poll_once(&mut tun).expect("fin accepted");
        assert_eq!(frames.len(), 1, "close signal on flow {i}");
        let _ = tun.take_outbound();
        // Relay closes too: the flow and its id are both released.
        peer.register_inbound(id, &DST.to_string(), 80, false)
            .expect("register");
        let over = peer.seal_data(&KEY, id, b"", PAD).expect("seal close");
        pump.receive_mux(&over.header, &over.ciphertext, &mut tun)
            .expect("close injected");
        let _ = tun.take_outbound();
        let _ = peer.close(id);
    }
    // Then: the session still opens new streams past the old cap.
    tun.inbound.push_back(syn(900_000));
    let frames = pump.poll_once(&mut tun).expect("pump alive");
    assert!(frames.is_empty());
    let out = tun.take_outbound();
    let iss = out[0].tcp().expect("tcp").seq;
    tun.inbound.push_back(build_tcp_packet_full(
        CLIENT_IP,
        DST,
        41000,
        80,
        false,
        true,
        false,
        false,
        false,
        900_001,
        iss.wrapping_add(1),
        &[],
    ));
    let _ = pump.poll_once(&mut tun).expect("handshake completes");
    tun.inbound
        .push_back(data_at(41000, 900_001, iss.wrapping_add(1), b"still here"));
    let frames = pump.poll_once(&mut tun).expect("new flow forwards");
    assert_eq!(frames.len(), 2, "OPEN + DATA after {flows} finished flows");
}
