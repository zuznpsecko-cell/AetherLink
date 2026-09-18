//! TDD RED: UDP flows + virtual DNS over the mux.
//!
//! Given/When/Then per test. Must FAIL until GREEN implements
//! `flow` datagrams and `dns` virtual-resolver handling.

use aetherlink_mux::dns;
use aetherlink_mux::manager::MuxManager;

// ---------- UDP flows ----------

#[test]
fn udp_open_assigns_client_odd_ids() {
    // Given: fresh manager
    let mut m = MuxManager::new();
    // When: opening two UDP flows
    let id1 = m.open_udp("8.8.8.8", 53).expect("open1");
    let id2 = m.open_udp("1.1.1.1", 53).expect("open2");
    // Then: odd client ids, both open
    assert_eq!(id1, 1);
    assert_eq!(id2, 3);
    assert!(m.is_open(id1));
}

#[test]
fn udp_open_enforces_max_flows() {
    let mut m = MuxManager::with_max(1);
    m.open_udp("8.8.8.8", 53).unwrap();
    assert!(m.open_udp("1.1.1.1", 53).is_err(), "max must reject");
}

#[test]
fn udp_datagram_roundtrip_with_crypto() {
    // Given: open flow + traffic key/nonce base
    let mut m = MuxManager::new();
    let id = m.open_udp("8.8.8.8", 53).unwrap();
    let key = [0x22u8; 32];
    // When: sealing two datagrams (e.g. DNS queries)
    let f1 = m
        .seal_datagram(&key, id, b"\x12\x34\x01\x00", 128)
        .expect("seal1");
    let f2 = m
        .seal_datagram(&key, id, b"\x56\x78\x01\x00", 128)
        .expect("seal2");
    assert_ne!(f1.header.sequence, f2.header.sequence);
    // Then: opening in order yields payloads byte-identical (DNS transparency)
    let p1 = m
        .open_datagram(&key, &f1.header, &f1.ciphertext)
        .expect("open1");
    assert_eq!(p1, b"\x12\x34\x01\x00");
    let p2 = m
        .open_datagram(&key, &f2.header, &f2.ciphertext)
        .expect("open2");
    assert_eq!(p2, b"\x56\x78\x01\x00");
}

#[test]
fn udp_rejects_replay() {
    let mut m = MuxManager::new();
    let id = m.open_udp("8.8.8.8", 53).unwrap();
    let key = [0x33u8; 32];
    let f = m.seal_datagram(&key, id, b"q", 128).unwrap();
    m.open_datagram(&key, &f.header, &f.ciphertext).unwrap();
    assert!(
        m.open_datagram(&key, &f.header, &f.ciphertext).is_err(),
        "duplicate delivery must fail"
    );
}

#[test]
fn udp_close_forbids_further_use() {
    let mut m = MuxManager::new();
    let id = m.open_udp("8.8.8.8", 53).unwrap();
    m.close(id).expect("close");
    assert!(!m.is_open(id));
    let key = [0x44u8; 32];
    assert!(m.seal_datagram(&key, id, b"x", 128).is_err(), "closed flow");
}

// ---------- virtual DNS ----------

#[test]
fn dns_virtual_resolver_identity() {
    // Given: canonical constants
    // When: reading resolver + predicate
    let (ip, port) = dns::virtual_resolver();
    // Then: 10.255.0.1:53 per DECISIONS
    assert_eq!(ip, "10.255.0.1");
    assert_eq!(port, 53);
    assert!(dns::is_virtual_dns("10.255.0.1", 53));
    assert!(!dns::is_virtual_dns("8.8.8.8", 53));
    assert!(!dns::is_virtual_dns("10.255.0.1", 80));
}

#[test]
fn dns_upstream_defaults_to_canonical() {
    // Given: server DNS policy
    // When: reading upstreams
    // Then: primary 1.1.1.1:53, secondary 8.8.8.8:53
    assert_eq!(dns::primary_upstream(), Some("1.1.1.1:53"));
    assert_eq!(dns::upstreams(), &["1.1.1.1:53", "8.8.8.8:53"]);
    assert!(dns::dns_via_tunnel(), "dns_mode is tunnel-only when up");
}

#[test]
fn dns_query_goes_via_tunnel_flow() {
    // Given: virtual resolver flow + raw DNS query bytes
    let mut m = MuxManager::new();
    let (vip, vport) = dns::virtual_resolver();
    let id = m.open_udp(vip, vport).unwrap();
    let key = [0x55u8; 32];
    let query = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    // When: sealed as datagram and opened back
    let f = m.seal_datagram(&key, id, query, 128).unwrap();
    let back = m.open_datagram(&key, &f.header, &f.ciphertext).unwrap();
    // Then: payload transparent, flow targets the virtual resolver
    assert_eq!(back, query);
    let t = m.target(id).expect("flow target");
    assert_eq!(t.addr, vip);
    assert_eq!(t.port, vport);
}
