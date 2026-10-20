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
    // Then: echo payload lands back in TUN as a TCP packet (outbound[0]
    // is the pump's own SYN-ACK; the echo arrives behind it).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        {
            let guard = tun.lock().expect("lock");
            let mut found = false;
            for raw in guard.outbound.iter() {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(raw).expect("valid ip");
                assert_eq!(parsed.dst, CLIENT_IP);
                if parsed.tcp().expect("tcp").payload == b"hello" {
                    found = true;
                    break;
                }
            }
            if found {
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
    // Then: echo returns into TUN as a TCP packet (behind our SYN-ACK).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        {
            let guard = tun.lock().expect("lock");
            let mut found = false;
            for raw in guard.outbound.iter() {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(raw).expect("valid ip");
                assert_eq!(parsed.dst, CLIENT_IP);
                if parsed.tcp().expect("tcp").payload == b"via-attach" {
                    found = true;
                    break;
                }
            }
            if found {
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
fn bulk_send_does_not_wait_for_replies() {
    // Given: TLS server that sinks (reads OPEN + 30 DATA, never answers)
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
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = aetherlink_core::tls::accept_tls(sock, &server_cfg).expect("server tls");
        let _sess = aetherlink_core::session::handshake_server(&mut stream, PSK, &cache)
            .expect("server hs");
        let _open = read_one(&mut stream);
        // Then: 30 dripped payloads all land (old loop burned 200ms per
        // turn waiting for replies that never come: ~6s+ of pure wait).
        let t0 = std::time::Instant::now();
        for _ in 0..30 {
            let _data = read_one(&mut stream);
        }
        let dt = t0.elapsed();
        assert!(
            dt < Duration::from_secs(7),
            "30 dripped payloads took {dt:?}, loop waits on wire reads"
        );
        let _ = done_tx.send(());
        let mut one = [0u8; 1];
        let _ = stream.read(&mut one);
    });

    // When: SYN, handshake, then 30 payloads back-to-back
    let syn = build_tcp_packet(CLIENT_IP, DST, 42001, 443, true, false, true, 8000, 0, &[]);
    let tun = Arc::new(Mutex::new(FakeTun {
        inbound: vec![syn].into(),
        outbound: Vec::new(),
    }));
    let tunnel = aetherlink_client::lifecycle::connect(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
    )
    .expect("connect");
    let mut handle = spawn_pump_tls(Arc::clone(&tun), tunnel, PAD).expect("spawn");
    // Complete the handshake from TUN side (parse iss from SYN-ACK).
    let iss = loop {
        {
            let guard = tun.lock().expect("lock");
            if let Some(raw) = guard.outbound.first() {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(raw).expect("valid ip");
                if parsed.tcp().expect("tcp").syn {
                    break parsed.tcp().expect("tcp").seq;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    {
        let mut guard = tun.lock().expect("lock");
        guard.outbound.clear();
        let ack = build_tcp_packet(
            CLIENT_IP,
            DST,
            42001,
            443,
            false,
            true,
            false,
            8001,
            iss.wrapping_add(1),
            &[],
        );
        guard.inbound.push_back(ack);
        // Drip one payload per 150ms (app-limited sender): the loop must
        // not add its 200ms wire-wait per packet on top.
        drop(guard);
        for i in 0..30u32 {
            std::thread::sleep(Duration::from_millis(150));
            let mut guard = tun.lock().expect("lock");
            let data = build_tcp_packet(
                CLIENT_IP,
                DST,
                42001,
                443,
                false,
                true,
                true,
                8001u32.wrapping_add(i.wrapping_mul(16)),
                iss.wrapping_add(1),
                &vec![i as u8; 16],
            );
            guard.inbound.push_back(data);
        }
    }
    done_rx.recv().expect("server got all frames");
    handle.stop();
    server.join().expect("server thread");
}

#[test]
fn full_duplex_upload_and_download_burst_completes_intact() {
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
        let mut uploaded = Vec::new();
        loop {
            let (h, c) = read_one(&mut stream);
            let pt = sess
                .mux
                .open_data(sess.keys.rx_key(), &h, &c)
                .expect("open upload chunk");
            if pt.is_empty() {
                break;
            }
            uploaded.extend_from_slice(&pt);
        }
        // Answer with exact byte count + large payload + clean close!
        let mut reply = (uploaded.len() as u64).to_be_bytes().to_vec();
        reply.extend_from_slice(&vec![0xA5u8; 8192]);
        let s1 = sess
            .mux
            .seal_data(sess.keys.tx_key(), tcp.id, &reply, PAD)
            .expect("seal reply");
        write_one(&mut stream, &s1.header, &s1.ciphertext);
        let s2 = sess
            .mux
            .seal_data(sess.keys.tx_key(), tcp.id, &[], PAD)
            .expect("seal close");
        write_one(&mut stream, &s2.header, &s2.ciphertext);
        let mut one = [0u8; 1];
        let _ = stream.read(&mut one);
        uploaded.len()
    });

    let syn = build_tcp_packet(
        CLIENT_IP,
        DST,
        43001,
        443,
        true,
        false,
        false,
        10_000,
        0,
        &[],
    );
    let tun = Arc::new(Mutex::new(FakeTun {
        inbound: vec![syn].into(),
        outbound: Vec::new(),
    }));
    let tunnel = aetherlink_client::lifecycle::connect(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
    )
    .expect("connect");
    let mut handle = spawn_pump_tls(Arc::clone(&tun), tunnel, PAD).expect("spawn");

    let iss = loop {
        {
            let guard = tun.lock().expect("lock");
            if let Some(raw) = guard.outbound.first() {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(raw).expect("valid ip");
                if parsed.tcp().expect("tcp").syn {
                    break parsed.tcp().expect("tcp").seq;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    };

    // Push 128 x 1360B upload segments + trailing FIN in a burst.
    let seg_body = vec![0x3Cu8; 1360];
    {
        let mut guard = tun.lock().expect("lock");
        guard.outbound.clear();
        guard.inbound.push_back(build_tcp_packet(
            CLIENT_IP,
            DST,
            43001,
            443,
            false,
            true,
            false,
            10_001,
            iss.wrapping_add(1),
            &[],
        ));
        let mut seq = 10_001u32;
        for _ in 0..128 {
            guard.inbound.push_back(build_tcp_packet(
                CLIENT_IP,
                DST,
                43001,
                443,
                false,
                true,
                true,
                seq,
                iss.wrapping_add(1),
                &seg_body,
            ));
            seq = seq.wrapping_add(1360);
        }
        guard
            .inbound
            .push_back(aetherlink_netstack::smoltcp_wrapper::build_tcp_packet_full(
                CLIENT_IP,
                DST,
                43001,
                443,
                false,
                true,
                false,
                true,
                false,
                seq,
                iss.wrapping_add(1),
                &[],
            ));
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut rx_payload = Vec::new();
    loop {
        {
            rx_payload.clear();
            let guard = tun.lock().expect("lock");
            let mut saw_fin = false;
            for raw in &guard.outbound {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(raw).expect("valid ip");
                let seg = parsed.tcp().expect("tcp");
                rx_payload.extend_from_slice(&seg.payload);
                if seg.fin {
                    saw_fin = true;
                }
            }
            if saw_fin {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "full-duplex response + FIN never arrived"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    handle.stop();
    let total_uploaded = server.join().expect("server thread");
    assert_eq!(total_uploaded, 128 * 1360);
    assert_eq!(rx_payload.len(), 8 + 8192);
    let echoed_len = u64::from_be_bytes(rx_payload[..8].try_into().expect("8B"));
    assert_eq!(echoed_len, (128 * 1360) as u64);
}

#[test]
fn multi_record_download_burst_does_not_false_eof() {
    // Regression test: previously `spawn_pump_tls` called `read_tls` up to 32
    // times before draining `reader()`, overflowing rustls's ~16.6 KB
    // `DeframerVecBuffer` on record #5 so `TcpStream::read(&mut [])` returned
    // `Ok(0)` and falsely killed the tunnel with `peer_eof = true`.
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
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();

    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let _ = sock.set_nodelay(true);
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
        let (req_h, req_c) = read_one(&mut stream);
        let req = sess
            .mux
            .open_data(sess.keys.rx_key(), &req_h, &req_c)
            .expect("req");
        assert_eq!(req, b"GET /big\r\n\r\n");

        // Blast 96 separate DATA frames (96 * 1400B = 134.4 KB across >96 TLS
        // records) without pausing, then keep the TLS connection open until
        // the client verifies `handle.is_alive()`!
        let chunk = vec![0xA5u8; 1400];
        for _ in 0..96 {
            let sealed = sess
                .mux
                .seal_data(sess.keys.tx_key(), tcp.id, &chunk, PAD)
                .expect("seal");
            write_one(&mut stream, &sealed.header, &sealed.ciphertext);
        }
        let _ = done_rx.recv_timeout(Duration::from_secs(10));
    });

    let tun = Arc::new(Mutex::new(FakeTun {
        inbound: VecDeque::new(),
        outbound: Vec::new(),
    }));
    let config = test_config(&format!("127.0.0.1:{port}"));
    let mut handle = aetherlink_client::lifecycle::attach_pump(
        Arc::clone(&tun),
        &config,
        Some(Arc::new(AcceptAll)),
    )
    .expect("attach");

    // Local 3-way handshake + GET request
    {
        let mut guard = tun.lock().expect("lock");
        guard.inbound.push_back(build_tcp_packet(
            CLIENT_IP,
            DST,
            44001,
            443,
            true,
            false,
            false,
            5_000_000,
            0,
            &[],
        ));
    }
    let syn_deadline = std::time::Instant::now() + Duration::from_secs(5);
    let iss = loop {
        {
            let guard = tun.lock().expect("lock");
            if let Some(raw) = guard.outbound.first() {
                let parsed =
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(raw).expect("ip");
                let seg = parsed.tcp().expect("tcp");
                if seg.syn && seg.ack {
                    break seg.seq;
                }
            }
        }
        assert!(std::time::Instant::now() < syn_deadline, "no SYN-ACK");
        std::thread::sleep(Duration::from_millis(2));
    };
    {
        let mut guard = tun.lock().expect("lock");
        guard.outbound.clear();
        guard.inbound.push_back(build_tcp_packet(
            CLIENT_IP,
            DST,
            44001,
            443,
            false,
            true,
            false,
            5_000_001,
            iss.wrapping_add(1),
            &[],
        ));
        guard.inbound.push_back(build_tcp_packet(
            CLIENT_IP,
            DST,
            44001,
            443,
            false,
            true,
            true,
            5_000_001,
            iss.wrapping_add(1),
            b"GET /big\r\n\r\n",
        ));
    }

    let expected = 96 * 1400;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut rx_bytes: usize;
    loop {
        {
            let guard = tun.lock().expect("lock");
            rx_bytes = guard
                .outbound
                .iter()
                .map(|raw| {
                    aetherlink_netstack::smoltcp_wrapper::parse_ipv4_packet(raw)
                        .expect("valid ip")
                        .tcp()
                        .expect("tcp")
                        .payload
                        .len()
                })
                .sum();
        }
        if rx_bytes >= expected {
            break;
        }
        assert!(
            handle.is_alive(),
            "pump died prematurely with {:?} after {rx_bytes}/{expected} bytes",
            handle.exit_reason()
        );
        assert!(
            std::time::Instant::now() < deadline,
            "download burst timed out at {rx_bytes}/{expected} bytes"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(rx_bytes, expected);
    assert!(
        handle.is_alive(),
        "pump must still be alive after multi-record burst: {:?}",
        handle.exit_reason()
    );
    assert!(handle.exit_reason().is_none());

    let _ = done_tx.send(());
    handle.stop();
    server.join().expect("server thread");
}
