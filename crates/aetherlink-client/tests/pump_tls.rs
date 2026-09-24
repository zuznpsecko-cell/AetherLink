//! TDD RED (Phase W4-tls): pump threads inside a real TLS stream.
//!
//! localhost TLS (rcgen + handshake, same as `connect.rs`) stands in for the
//! production transport; no privileges needed. Tests prove TUN bytes reach
//! the wire sealed under session keys and wire bytes land back in TUN.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aetherlink_client::threads::spawn_pump_tls;
use aetherlink_crypto::auth::NonceCache;
use aetherlink_frame::codec::FrameHeader;
use aetherlink_netstack::smoltcp_wrapper::build_tcp_packet;
use aetherlink_netstack::tun::TunPackets;

mod tls_accept_all;

use tls_accept_all::AcceptAll;

const PSK: &[u8] = b"phase-w4-tls-test-psk-32-bytes-long!";
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

fn test_config(addr: &str) -> aetherlink_client::config::ClientConfig {
    aetherlink_client::config::ClientConfig::parse(&serde_json::json!({
        "server_addr": addr,
        "psk": String::from_utf8_lossy(PSK),
        "dns_mode": "tunnel",
    }))
    .expect("test config")
}

#[test]
fn tls_pump_moves_bytes_both_ways() {
    // Given: TLS server that opens whatever the client announces, then
    // answers every DATA with its payload uppercased... (echo, verbatim)
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        key.cert.der().to_vec(),
    )];
    let key_der = key.key_pair.serialize_der();
    let server_cfg =
        Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("server cfg"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let cache = NonceCache::new();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = aetherlink_core::tls::accept_tls(sock, &server_cfg).expect("server tls");
        let mut sess = aetherlink_core::session::handshake_server(&mut stream, PSK, &cache)
            .expect("server hs");
        // Serve exactly one flow: OPEN_TCP -> register, DATA -> echo back.
        let (open_h, open_c) = read_one(&mut stream);
        let tcp = aetherlink_mux::manager::MuxManager::parse_open_tcp(
            sess.keys.rx_key(),
            &open_h,
            &open_c,
        )
        .expect("open parses");
        sess.mux
            .register_inbound(tcp.id, &tcp.addr, tcp.port, false)
            .expect("register");
        let (data_h, data_c) = read_one(&mut stream);
        let pt = sess
            .mux
            .open_data(sess.keys.rx_key(), &data_h, &data_c)
            .expect("open");
        let sealed = sess
            .mux
            .seal_data(sess.keys.tx_key(), tcp.id, &pt, PAD)
            .expect("seal");
        write_one(&mut stream, &sealed.header, &sealed.ciphertext);
        // Keep the stream open until the client goes away (EOF for the test).
        let mut one = [0u8; 1];
        let _ = stream.read(&mut one);
    });

    // ...and a client TUN holding one SYN with a "hello" payload
    let syn = build_tcp_packet(
        CLIENT_IP, DST, 42000, 443, true, false, true, 7000, 0, b"hello",
    );
    let tun = Arc::new(Mutex::new(FakeTun {
        inbound: vec![syn].into(),
        outbound: Vec::new(),
    }));
    // When: connecting for real, then pumping inside the TLS stream
    let tunnel = aetherlink_client::lifecycle::connect(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
    )
    .expect("connect");
    let mut handle = spawn_pump_tls(Arc::clone(&tun), tunnel, PAD).expect("spawn");
    // Then: echo payload lands back in TUN as a TCP packet
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        {
            let guard = tun.lock().expect("lock");
            if !guard.outbound.is_empty() {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(&guard.outbound[0])
                        .expect("valid ip");
                assert_eq!(parsed.dst, CLIENT_IP);
                assert_eq!(parsed.tcp().expect("tcp").payload, b"hello");
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "echo never reached TUN"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    handle.stop();
    server.join().expect("server thread");
}

#[test]
fn tls_pump_stop_is_idempotent() {
    // Given: live TLS session with an empty TUN
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        key.cert.der().to_vec(),
    )];
    let key_der = key.key_pair.serialize_der();
    let server_cfg =
        Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("server cfg"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let cache = NonceCache::new();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = aetherlink_core::tls::accept_tls(sock, &server_cfg).expect("server tls");
        let _sess = aetherlink_core::session::handshake_server(&mut stream, PSK, &cache)
            .expect("server hs");
        let mut one = [0u8; 1];
        let _ = stream.read(&mut one);
    });
    let tun = Arc::new(Mutex::new(FakeTun::default()));
    let tunnel = aetherlink_client::lifecycle::connect(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
    )
    .expect("connect");
    let mut handle = spawn_pump_tls(tun, tunnel, PAD).expect("spawn");
    // When: stopping twice -> Then: both Ok
    handle.stop();
    handle.stop();
    server.join().expect("server thread");
}

/// Read one sealed frame from a TLS stream (test-side helper).
fn read_one(stream: &mut aetherlink_core::tls::ServerTlsStream) -> (FrameHeader, Vec<u8>) {
    let mut hb = [0u8; aetherlink_frame::FRAME_HEADER_SIZE];
    stream.read_exact(&mut hb).expect("read header");
    let mut hbuf = bytes::BytesMut::from(&hb[..]);
    let header = FrameHeader::decode(&mut hbuf).expect("decode header");
    let mut ct = vec![0u8; header.length as usize];
    stream.read_exact(&mut ct).expect("read ct");
    (header, ct)
}

/// Write one sealed frame into a TLS stream (test-side helper).
fn write_one(
    stream: &mut aetherlink_core::tls::ServerTlsStream,
    header: &FrameHeader,
    ciphertext: &[u8],
) {
    let mut out = bytes::BytesMut::new();
    header.encode(&mut out);
    stream.write_all(&out).expect("write header");
    stream.write_all(ciphertext).expect("write ct");
    stream.flush().expect("flush");
}

#[test]
fn attach_pump_wires_tun_through_tls_session() {
    // Given: TLS server echoing DATA like a tunnel endpoint
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        key.cert.der().to_vec(),
    )];
    let key_der = key.key_pair.serialize_der();
    let server_cfg =
        Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("server cfg"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let cache = NonceCache::new();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = aetherlink_core::tls::accept_tls(sock, &server_cfg).expect("server tls");
        let mut sess = aetherlink_core::session::handshake_server(&mut stream, PSK, &cache)
            .expect("server hs");
        let (open_h, open_c) = read_one(&mut stream);
        let tcp = aetherlink_mux::manager::MuxManager::parse_open_tcp(
            sess.keys.rx_key(),
            &open_h,
            &open_c,
        )
        .expect("open parses");
        sess.mux
            .register_inbound(tcp.id, &tcp.addr, tcp.port, false)
            .expect("register");
        let (data_h, data_c) = read_one(&mut stream);
        let pt = sess
            .mux
            .open_data(sess.keys.rx_key(), &data_h, &data_c)
            .expect("open");
        let sealed = sess
            .mux
            .seal_data(sess.keys.tx_key(), tcp.id, &pt, PAD)
            .expect("seal");
        write_one(&mut stream, &sealed.header, &sealed.ciphertext);
        let mut one = [0u8; 1];
        let _ = stream.read(&mut one);
    });

    // ...and a TUN holding one SYN with payload
    let syn = build_tcp_packet(
        CLIENT_IP,
        DST,
        42001,
        443,
        true,
        false,
        true,
        8000,
        0,
        b"via-attach",
    );
    let tun = Arc::new(Mutex::new(FakeTun {
        inbound: vec![syn].into(),
        outbound: Vec::new(),
    }));
    // When: single-call attach (connect + pump) against the test server
    let config = test_config(&format!("127.0.0.1:{port}"));
    let mut handle = aetherlink_client::lifecycle::attach_pump(
        Arc::clone(&tun),
        &config,
        Some(Arc::new(AcceptAll)),
    )
    .expect("attach");
    // Then: echo returns into TUN as a TCP packet.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        {
            let guard = tun.lock().expect("lock");
            if !guard.outbound.is_empty() {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(&guard.outbound[0])
                        .expect("valid ip");
                assert_eq!(parsed.dst, CLIENT_IP);
                assert_eq!(parsed.tcp().expect("tcp").payload, b"via-attach");
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "echo never reached TUN"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    handle.stop();
    server.join().expect("server thread");
}
