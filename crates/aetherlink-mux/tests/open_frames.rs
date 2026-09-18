//! TDD RED: OPEN_TCP / OPEN_UDP negotiation frames (Phase I1).
//!
//! The opener seals the dial target once (seq 0, type-distinct nonce, DATA
//! sequencing untouched); the peer parses it back into a descriptor.
//! Wrong types and tampered bytes must fail closed.

use aetherlink_mux::manager::MuxManager;
use aetherlink_mux::stream::TcpStream;
use aetherlink_protocol::FrameType;

fn key() -> Vec<u8> {
    vec![0x77u8; 32]
}

#[test]
fn tcp_open_roundtrip() {
    // Given: locally opened TCP stream
    let mut mux = MuxManager::new();
    let id = mux.open_tcp("93.184.216.34", 443).expect("open");
    // When: sealing + parsing the OPEN frame
    let sealed = mux.seal_open_tcp(&key(), id, 128).expect("seal open");
    // Then: type + zero seq on the wire, descriptor back on parse.
    assert_eq!(sealed.header.frame_type, FrameType::OpenTcp);
    assert_eq!(sealed.header.sequence, 0);
    let target =
        MuxManager::parse_open_tcp(&key(), &sealed.header, &sealed.ciphertext).expect("parse");
    assert_eq!(
        target,
        TcpStream {
            id,
            addr: "93.184.216.34".to_string(),
            port: 443,
        }
    );
}

#[test]
fn udp_open_roundtrip_domain() {
    // Given: locally opened UDP flow to a name
    let mut mux = MuxManager::new();
    let id = mux.open_udp("example.com", 53).expect("open");
    // When: sealing + parsing the OPEN frame
    let sealed = mux.seal_open_udp(&key(), id, 128).expect("seal open");
    assert_eq!(sealed.header.frame_type, FrameType::OpenUdp);
    assert_eq!(sealed.header.sequence, 0);
    // Then: descriptor back, domain preserved.
    let flow =
        MuxManager::parse_open_udp(&key(), &sealed.header, &sealed.ciphertext).expect("parse");
    assert_eq!(flow.id, id);
    assert_eq!(flow.addr, "example.com");
    assert_eq!(flow.port, 53);
}

#[test]
fn open_rejects_wrong_types() {
    // Given: sealed TCP OPEN + sealed DATA
    let mut mux = MuxManager::new();
    let id = mux.open_tcp("10.0.0.9", 80).expect("open");
    let open = mux.seal_open_tcp(&key(), id, 128).expect("seal open");
    let data = mux.seal_data(&key(), id, b"x", 128).expect("seal data");
    // When/Then: cross-type and cross-frame parsing fails.
    assert!(MuxManager::parse_open_udp(&key(), &open.header, &open.ciphertext).is_err());
    assert!(MuxManager::parse_open_tcp(&key(), &data.header, &data.ciphertext).is_err());
}

#[test]
fn open_rejects_tamper() {
    // Given: valid sealed OPEN
    let mut mux = MuxManager::new();
    let id = mux.open_tcp("10.0.0.9", 80).expect("open");
    let mut sealed = mux.seal_open_tcp(&key(), id, 128).expect("seal open");
    // When: flipping a ciphertext byte → Then: rejected.
    let last = sealed.ciphertext.len() - 1;
    sealed.ciphertext[last] ^= 0x01;
    assert!(MuxManager::parse_open_tcp(&key(), &sealed.header, &sealed.ciphertext).is_err());
}

#[test]
fn seal_open_needs_known_id() {
    // Given: fresh manager, id never opened
    let mut mux = MuxManager::new();
    // When/Then: sealing OPEN for it fails (no phantom streams).
    assert!(mux.seal_open_tcp(&key(), 1, 128).is_err());
    assert!(mux.seal_open_udp(&key(), 1, 128).is_err());
}

#[test]
fn open_leaves_data_sequencing_alone() {
    // Given: opened stream
    let mut mux = MuxManager::new();
    let id = mux.open_tcp("10.0.0.9", 80).expect("open");
    // When: OPEN sealed first, then DATA
    mux.seal_open_tcp(&key(), id, 128).expect("seal open");
    let data = mux.seal_data(&key(), id, b"hi", 128).expect("seal data");
    // Then: DATA still starts at seq 1 (OPEN lives in seq 0 + own nonce).
    assert_eq!(data.header.sequence, 1);
}
