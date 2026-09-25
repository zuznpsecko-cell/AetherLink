//! TDD RED (Phase W4): pump threads bridging TUN<->wire.
//!
//! localhost TCP stands in for the TLS stream (same framing: 24B header +
//! ciphertext via `write_sealed`/`read_sealed`); no privileges needed.
//! Tests prove both directions move bytes and `stop()` joins cleanly.

use std::collections::VecDeque;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aetherlink_client::threads::{read_sealed, spawn_pump};
use aetherlink_frame::codec::FrameHeader;
use aetherlink_mux::manager::MuxManager;
use aetherlink_netstack::smoltcp_wrapper::{build_tcp_packet, build_udp_packet, parse_ipv4_packet};
use aetherlink_netstack::tun::TunPackets;

const KEY: [u8; 32] = [9u8; 32];
const PAD: usize = 128;
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 2);
const DST: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

/// In-memory TUN stand-in, thread-safe via the outer `Mutex`.
#[derive(Debug, Default)]
struct FakeTun {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
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

fn tun_with(packets: Vec<Vec<u8>>) -> Arc<Mutex<FakeTun>> {
    Arc::new(Mutex::new(FakeTun {
        inbound: packets.into(),
        outbound: Vec::new(),
    }))
}

fn loopback_pair() -> (TcpStream, TcpStream) {
    // Given: connected localhost pair
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    server
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    (client, server)
}

/// Wait for the pump thread's SYN-ACK in TUN, return its sequence number.
fn poll_synack(tun: &Arc<Mutex<FakeTun>>) -> u32 {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let mut guard = tun.lock().expect("lock");
            if let Some(raw) = guard.outbound.pop() {
                let parsed = parse_ipv4_packet(&raw).expect("valid ip");
                let seg = parsed.tcp().expect("tcp");
                assert!(seg.syn && seg.ack, "pump answers SYN with SYN-ACK");
                return seg.seq;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no SYN-ACK from pump thread"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn tun_packets_reach_the_wire() {
    // Given: SYN queued in TUN + pump on a loopback stream
    let syn = build_tcp_packet(CLIENT_IP, DST, 41000, 443, true, false, false, 5000, 0, &[]);
    let tun = tun_with(vec![syn]);
    let (client_side, server_side) = loopback_pair();
    let _handle = spawn_pump(Arc::clone(&tun), client_side, KEY, KEY, PAD).expect("spawn");
    // When: handshake completes against the pump, then payload flows
    let iss = poll_synack(&tun);
    let ack = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        443,
        false,
        true,
        false,
        5001,
        iss.wrapping_add(1),
        &[],
    );
    let data = build_tcp_packet(
        CLIENT_IP,
        DST,
        41000,
        443,
        false,
        true,
        true,
        5001,
        iss.wrapping_add(1),
        b"hello",
    );
    {
        let mut guard = tun.lock().expect("lock");
        guard.inbound.push_back(ack);
        guard.inbound.push_back(data);
    }
    // Then: OPEN_TCP + DATA arrive server-side
    let (h1, c1) = read_sealed(&mut &server_side).expect("frame 1");
    let (h2, c2) = read_sealed(&mut &server_side).expect("frame 2");
    // Then: OPEN_TCP + DATA, both open server-side with the session key
    let mut server_mux = MuxManager::new();
    let tcp = MuxManager::parse_open_tcp(&KEY, &h1, &c1).expect("open parses");
    assert_eq!(tcp.addr, DST.to_string());
    server_mux
        .register_inbound(tcp.id, &tcp.addr, tcp.port, false)
        .expect("register");
    let data_hdr = FrameHeader {
        length: h2.length,
        frame_type: h2.frame_type,
        flags: 0,
        stream_id: tcp.id,
        sequence: h2.sequence,
    };
    assert!(server_mux.open_data(&KEY, &data_hdr, &c2).is_ok());
    let _ = h1;
}

#[test]
fn wire_bytes_land_in_tun() {
    // Given: UDP flow established so the pump knows the 5-tuple
    let query = vec![0x11, 0x22, 0x01, 0x00];
    let udp = build_udp_packet(CLIENT_IP, DST, 53010, 53, &query);
    let tun = tun_with(vec![udp]);
    let (client_side, server_side) = loopback_pair();
    let _handle = spawn_pump(Arc::clone(&tun), client_side, KEY, KEY, PAD).expect("spawn");
    // Drain the OPEN+DATAGRAM the pump emits for the flow.
    let (h1, c1) = read_sealed(&mut &server_side).expect("open");
    let (h2, c2) = read_sealed(&mut &server_side).expect("datagram");
    let mut server_mux = MuxManager::new();
    let flow = MuxManager::parse_open_udp(&KEY, &h1, &c1).expect("open parses");
    server_mux
        .register_inbound(flow.id, &flow.addr, flow.port, true)
        .expect("register");
    let dh = FrameHeader {
        length: h2.length,
        frame_type: h2.frame_type,
        flags: 0,
        stream_id: flow.id,
        sequence: h2.sequence,
    };
    server_mux
        .open_datagram(&KEY, &dh, &c2)
        .expect("datagram opens");
    // When: server answers via its own mux on the same id
    let answer = vec![0x11, 0x22, 0x81, 0x80];
    let sealed = server_mux
        .seal_datagram(&KEY, flow.id, &answer, PAD)
        .expect("seal");
    let mut hb = Vec::new();
    {
        let mut buf = bytes::BytesMut::new();
        sealed.header.encode(&mut buf);
        hb.extend_from_slice(&buf);
    }
    let mut writer = &server_side;
    writer.write_all(&hb).expect("header");
    writer.write_all(&sealed.ciphertext).expect("body");
    writer.flush().expect("flush");
    // Then: answer packet appears in TUN (poll with deadline)
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let guard = tun.lock().expect("lock");
            if !guard.outbound.is_empty() {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(&guard.outbound[0])
                        .expect("valid ip");
                assert_eq!(parsed.dst, CLIENT_IP);
                assert_eq!(parsed.udp().expect("udp").payload, answer);
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "answer never reached TUN"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn stop_joins_threads_and_is_idempotent() {
    // Given: running pump with no traffic
    let tun = tun_with(vec![]);
    let (client_side, _server_side) = loopback_pair();
    let mut handle = spawn_pump(tun, client_side, KEY, KEY, PAD).expect("spawn");
    // When: stopping twice -> Then: both Ok, threads joined
    handle.stop();
    handle.stop();
}

#[test]
fn client_down_stops_pump() {
    // Given: client with an attached pump
    let tun = tun_with(vec![]);
    let (client_side, _server_side) = loopback_pair();
    let config = aetherlink_client::config::ClientConfig::parse(&serde_json::json!({
        "server_addr": "example.com:443",
        "psk": "test-psk-32-bytes-long-exactly!!",
        "dns_mode": "tunnel",
    }))
    .expect("test config");
    let mut client = aetherlink_client::Client::new_config(config);
    client
        .start_pump(tun, client_side, KEY, KEY)
        .expect("start pump");
    // When: going down -> Then: pump stopped, client down, second down safe
    client.down().expect("down stops pump");
    assert!(!client.is_up());
    client.down().expect("second down safe");
}
