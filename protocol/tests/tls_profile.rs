//! Golden vectors for the canonical TLS profile (DEC-012, Phase T).
//!
//! These tests freeze the wire-visible TLS choices in `aetherlink_protocol::tls_profile`.
//! Implementor crates (`aetherlink-core`, `aetherlink-server`) must consume
//! exactly these constants; any deviation fails here first.
//!
//! Golden style: literal, deterministic, byte-exact — the same shape as
//! `tests/golden.rs`.

use aetherlink_protocol::tls_profile as p;
use aetherlink_protocol::{ALPN_H2, ALPN_HTTP11};

#[test]
fn client_alpn_order_is_frozen() {
    let want: Vec<&[u8]> = vec![ALPN_H2, ALPN_HTTP11];
    assert_eq!(p::CLIENT_ALPN_ORDER.as_slice(), want.as_slice());
    assert_eq!(ALPN_H2, b"h2");
    assert_eq!(ALPN_HTTP11, b"http/1.1");
}

#[test]
fn server_alpn_order_is_frozen() {
    let want: Vec<&[u8]> = vec![ALPN_HTTP11];
    assert_eq!(p::SERVER_ALPN_ORDER.as_slice(), want.as_slice());
    for alpn in p::SERVER_ALPN_ORDER {
        assert_ne!(alpn, b"h2", "decoy page must speak HTTP/1.1 framing only");
    }
}

#[test]
fn only_tls13_is_allowed() {
    assert_eq!(p::ALLOWED_VERSIONS.len(), 1);
    assert_eq!(p::ALLOWED_VERSIONS[0], "tls13");
}

#[test]
fn allowed_ciphers_are_the_three_mainstream_tls13_suites() {
    let want: [(u16, &str); 3] = [
        (0x1301, "tls13_aes_128_gcm_sha256"),
        (0x1303, "tls13_chacha20_poly1305_sha256"),
        (0x1302, "tls13_aes_256_gcm_sha384"),
    ];
    assert_eq!(p::ALLOWED_13_CIPHERS, want);
}

#[test]
fn forbidden_cipher_banlist_is_nonempty_and_disjoint() {
    assert!(!p::FORBIDDEN_CIPHERS.is_empty());
    for (fid, fname) in p::FORBIDDEN_CIPHERS {
        for (aid, aname) in p::ALLOWED_13_CIPHERS {
            assert_ne!(
                fid, aid,
                "banlist entry '{fname}' collides with allowlisted '{aname}'"
            );
        }
    }
}

#[test]
fn policy_strings_are_frozen() {
    assert_eq!(p::RESUMPTION_POLICY, "tls13-tickets-in-memory-both-sides");
    assert_eq!(
        p::SNI_SOURCE_RULE,
        "config.outer_sni (default: host part of server_addr)"
    );
    assert_eq!(
        p::KX_POLICY,
        "provider-default groups, frozen by handshake probes"
    );
}

#[test]
fn profile_snapshot_is_complete() {
    // The snapshot: everything a passive observer can see is enumerated by
    // these five frozen choices. Adding a new knob must extend this test
    // (and this comment) together.
    assert_eq!(p::CLIENT_ALPN_ORDER.len(), 2);
    assert_eq!(p::SERVER_ALPN_ORDER.len(), 1);
    assert_eq!(p::ALLOWED_VERSIONS.len(), 1);
    assert_eq!(p::ALLOWED_13_CIPHERS.len(), 3);
    assert!(p::RESUMPTION_POLICY.starts_with("tls13-"));
    assert!(p::SNI_SOURCE_RULE.starts_with("config."));
}
