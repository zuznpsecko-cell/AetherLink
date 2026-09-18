//! TDD RED: AUTH handshake over TLS → traffic keys → mux DATA (Phase A).
//!
//! Wire: PREFACE byte (PROTOCOL_VERSION) + plaintext AUTH frame, then both
//! sides derive keys and speak encrypted mux frames. Wrong PSK, bad version
//! and nonce replay must all fail closed.
//!
//! NOTE on stream registration: the client registers stream ids in its own
//! `MuxManager`; the server registers the same id locally. Cross-side
//! OPEN_TCP negotiation (server auto-registering inbound streams) belongs
//! to Phase B (accept-loop); here both sides open id 1 explicitly.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use aetherlink_core::{session, tls};
use aetherlink_crypto::auth::NonceCache;
use aetherlink_frame::codec::FrameHeader;
use bytes::BufMut;
use bytes::BytesMut;

mod tls_common;
use tls_common::{client_tls_config, server_tls_config};

const PSK: &[u8] = b"phase-a-test-psk-32-bytes-long!!!!";

/// Read one sealed frame (24B header + ciphertext) from a TLS stream.
fn read_sealed(stream: &mut tls::ServerTlsStream) -> (FrameHeader, Vec<u8>) {
    let mut hb = [0u8; aetherlink_frame::FRAME_HEADER_SIZE];
    stream.read_exact(&mut hb).expect("read header");
    let mut buf = BytesMut::from(&hb[..]);
    let header = FrameHeader::decode(&mut buf).expect("decode header");
    let mut ct = vec![0u8; header.length as usize];
    stream.read_exact(&mut ct).expect("read ciphertext");
    (header, ct)
}

/// Write one sealed frame to a TLS stream.
fn write_sealed(stream: &mut tls::ClientTlsStream, header: &FrameHeader, ct: &[u8]) {
    let mut buf = BytesMut::new();
    header.encode(&mut buf);
    stream.write_all(&buf).expect("write header");
    stream.write_all(ct).expect("write ciphertext");
    stream.flush().expect("flush");
}

#[test]
fn full_handshake_then_data_both_directions() {
    // Given: TLS-connected pair + shared PSK
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server_cfg = server_tls_config();
    let cache = NonceCache::new();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = tls::accept_tls(sock, &server_cfg).expect("server tls");
        let mut sess = session::handshake_server(&mut stream, PSK, &cache).expect("server hs");
        // Server opened id 1 locally (see note above).
        sess.mux
            .open_tcp("10.0.0.9", 80)
            .expect("server open stream");
        // When: client DATA arrives over the wire
        let (header, ct) = read_sealed(&mut stream);
        // Then: opens with the derived server-rx key
        let pt = sess
            .mux
            .open_data(sess.keys.rx_key(), &header, &ct)
            .expect("server open");
        assert_eq!(pt, b"hello-server");
        // And the server reply seals under server-tx (= client-rx).
        let sealed = sess
            .mux
            .seal_data(sess.keys.tx_key(), 1, b"hello-client", 128)
            .expect("server seal");
        let mut buf = BytesMut::new();
        sealed.header.encode(&mut buf);
        stream.write_all(&buf).expect("write header");
        stream
            .write_all(&sealed.ciphertext)
            .expect("write ciphertext");
        stream.flush().expect("flush");
    });

    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let name = tls::server_name("localhost").expect("sni");
    let mut stream = tls::connect_tls(sock, name, &client_tls_config()).expect("client tls");
    let nonce = [0xA1u8; 32];
    let mut cli = session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let id = cli
        .mux
        .open_tcp("10.0.0.9", 80)
        .expect("client open stream");
    assert_eq!(id, 1);
    // When: client seals + sends DATA over the wire
    let sealed = cli
        .mux
        .seal_data(cli.keys.tx_key(), id, b"hello-server", 128)
        .expect("client seal");
    write_sealed(&mut stream, &sealed.header, &sealed.ciphertext);
    // Then: server reply opens under client-rx
    let mut hb = [0u8; aetherlink_frame::FRAME_HEADER_SIZE];
    stream.read_exact(&mut hb).expect("read header");
    let mut buf = BytesMut::from(&hb[..]);
    let header = FrameHeader::decode(&mut buf).expect("decode header");
    let mut ct = vec![0u8; header.length as usize];
    stream.read_exact(&mut ct).expect("read ciphertext");
    let back = cli
        .mux
        .open_data(cli.keys.rx_key(), &header, &ct)
        .expect("client open");
    assert_eq!(back, b"hello-client");
    server.join().expect("server thread");
}

#[test]
fn wrong_psk_rejected_both_sides() {
    // Given: server with PSK-A, client with PSK-B
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server_cfg = server_tls_config();
    let cache = NonceCache::new();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = tls::accept_tls(sock, &server_cfg).expect("server tls");
        // When: AUTH token does not verify
        // Then: server fails closed (stream dropped, no tunnel)
        assert!(session::handshake_server(&mut stream, PSK, &cache).is_err());
    });

    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let name = tls::server_name("localhost").expect("sni");
    let mut stream = tls::connect_tls(sock, name, &client_tls_config()).expect("client tls");
    let nonce = [0xB2u8; 32];
    // Server drops the stream after failed verify → client sees EOF.
    assert!(
        session::handshake_client(&mut stream, b"wrong-psk-32-bytes-long-!!!!!!!!!", &nonce)
            .is_err()
    );
    server.join().expect("server thread");
}

#[test]
fn nonce_replay_rejected() {
    // Given: one NonceCache shared across connections
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server_cfg = server_tls_config();
    let cache = NonceCache::new();
    let nonce = [0xC3u8; 32];

    // First handshake succeeds.
    let server = std::thread::spawn({
        let server_cfg = Arc::clone(&server_cfg);
        move || {
            let (sock, _) = listener.accept().expect("accept1");
            let mut stream = tls::accept_tls(sock, &server_cfg).expect("server tls1");
            session::handshake_server(&mut stream, PSK, &cache).expect("first hs ok");
            // Keep the cache alive across both handshakes via the moved value.
            cache
        }
    });
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect1");
    let name = tls::server_name("localhost").expect("sni");
    let mut stream = tls::connect_tls(sock, name, &client_tls_config()).expect("client tls1");
    session::handshake_client(&mut stream, PSK, &nonce).expect("first client hs ok");
    let cache = server.join().expect("server thread");

    // Second handshake with the SAME nonce on a fresh connection.
    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind2");
    let port2 = listener2.local_addr().expect("addr").port();
    let server2 = std::thread::spawn(move || {
        let (sock, _) = listener2.accept().expect("accept2");
        let mut stream = tls::accept_tls(sock, &server_cfg).expect("server tls2");
        // When: nonce already seen → Then: rejected.
        assert!(session::handshake_server(&mut stream, PSK, &cache).is_err());
    });
    let sock = TcpStream::connect(("127.0.0.1", port2)).expect("connect2");
    let name = tls::server_name("localhost").expect("sni");
    let mut stream = tls::connect_tls(sock, name, &client_tls_config()).expect("client tls2");
    assert!(session::handshake_client(&mut stream, PSK, &nonce).is_err());
    server2.join().expect("server thread");
}

#[test]
fn bad_preface_version_rejected() {
    // Given: TLS-connected pair
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server_cfg = server_tls_config();
    let cache = NonceCache::new();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = tls::accept_tls(sock, &server_cfg).expect("server tls");
        // When: version byte != PROTOCOL_VERSION → Then: rejected.
        assert!(session::handshake_server(&mut stream, PSK, &cache).is_err());
    });

    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let name = tls::server_name("localhost").expect("sni");
    let mut stream = tls::connect_tls(sock, name, &client_tls_config()).expect("client tls");
    stream.write_all(&[0xFF]).expect("bad preface");
    stream.flush().expect("flush");
    server.join().expect("server thread");
}
