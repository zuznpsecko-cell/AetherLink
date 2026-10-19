//! Canonical TLS profile (DEC-012, Phase T).
//!
//! The single TLS composition used by every data-plane connection, owned by
//! one place: this module freezes the wire-visible choices (ALPN order,
//! cipher allowlist, resumption policy, SNI source rule) so any deviation
//! fails the build through `tests/tls_profile.rs`.
//!
//! Philosophy (DEC-012): the transport must look like ordinary, mainstream
//! TLS — no exotic suites, no custom extensions/values, no per-browser
//! mimicry (that stays a non-goal). The profile is deliberately boring and
//! auditable; boring is what passive observers see on commodity HTTPS.

use crate::{ALPN_H2, ALPN_HTTP11};

/// ALPN the CLIENT offers, in wire priority order (browser-like: h2 first,
/// http/1.1 as generic fallback). The tunnel treats the ALPN choice as an
/// opaque pipe; the order only decides what a passive observer sees.
pub const CLIENT_ALPN_ORDER: [&[u8]; 2] = [ALPN_H2, ALPN_HTTP11];

/// ALPN the SERVER accepts. The unauthenticated fallback speaks raw
/// HTTP/1.1, and browsers enforce negotiated framing — offering `h2` there
/// would break the decoy page in every modern browser.
pub const SERVER_ALPN_ORDER: [&[u8]; 1] = [ALPN_HTTP11];

/// The single permitted protocol version (wire byte 0x0304).
pub const ALLOWED_VERSIONS: [&str; 1] = ["tls13"];

/// Allowed TLS 1.3 cipher suites: (IANA codepoint, name), in priority order.
/// These are exactly the three mainstream TLS 1.3 suites every major browser
/// and commodity server negotiates; nothing exotic is offered.
pub const ALLOWED_13_CIPHERS: [(u16, &str); 3] = [
    (0x1301, "tls13_aes_128_gcm_sha256"),
    (0x1303, "tls13_chacha20_poly1305_sha256"),
    (0x1302, "tls13_aes_256_gcm_sha384"),
];

/// Suites that must never be offered or negotiated (as of the frozen
/// profile). Gate asserts this list stays disjoint from the allowlist; the
/// core constructor refuses anything outside `ALLOWED_13_CIPHERS`.
pub const FORBIDDEN_CIPHERS: [(u16, &str); 2] = [
    (0x00A1, "tls13_ech_grease_placeholder"), // never a real one: custom/ECH-adjacent
    (0x00A2, "tls13_reserved_for_banlist"),
];

/// Uniform resumption policy: TLS 1.3 session tickets on both sides,
/// in-memory storage only, no persistence across runs. A second handshake
/// with the same client config MUST resume (`is_resumed` probe in core
/// tests); a fresh process must not retain tickets.
pub const RESUMPTION_POLICY: &str = "tls13-tickets-in-memory-both-sides";

/// SNI source rule: the SNI is taken exactly from the client config
/// (`outer_sni`, defaulting to the host part of `server_addr`) and never
/// derived from system state, resolved IPs, or internals.
pub const SNI_SOURCE_RULE: &str = "config.outer_sni (default: host part of server_addr)";

/// Key-exchange policy: the crypto provider's default supported groups,
/// no custom ordering or mimicry groups (DEC-012 non-goals).
pub const KX_POLICY: &str = "provider-default groups, frozen by handshake probes";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_orders_are_non_empty_and_distinct() {
        assert!(!CLIENT_ALPN_ORDER.is_empty());
        assert!(!SERVER_ALPN_ORDER.is_empty());
        // Server accepts a subset of what browsers understand; the decoy
        // constraint means the server never offers h2.
        assert!(
            !SERVER_ALPN_ORDER.contains(&ALPN_H2),
            "server must not offer h2 (browsers enforce negotiated framing)"
        );
        assert!(
            CLIENT_ALPN_ORDER.contains(&ALPN_HTTP11),
            "client must keep http/1.1 offered (generic fallback must fit in)"
        );
    }

    #[test]
    fn allowed_ciphers_are_the_three_mainstream_tls13_suites() {
        let ids: Vec<u16> = ALLOWED_13_CIPHERS.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![0x1301, 0x1303, 0x1302]);
    }

    #[test]
    fn forbidden_ciphers_are_disjoint_from_allowed() {
        for (forbidden_id, forbidden_name) in FORBIDDEN_CIPHERS {
            for (allowed_id, allowed_name) in ALLOWED_13_CIPHERS {
                assert_ne!(
                    forbidden_id, allowed_id,
                    "cipher '{forbidden_name}' must not equal allowed '{allowed_name}'"
                );
            }
        }
    }

    #[test]
    fn policy_strings_are_frozen() {
        assert_eq!(RESUMPTION_POLICY, "tls13-tickets-in-memory-both-sides");
        assert_eq!(
            SNI_SOURCE_RULE,
            "config.outer_sni (default: host part of server_addr)"
        );
        assert_eq!(ALLOWED_VERSIONS, ["tls13"]);
    }

    #[test]
    fn alpn_copoints_stay_the_wire_strings() {
        assert_eq!(ALPN_H2, b"h2");
        assert_eq!(ALPN_HTTP11, b"http/1.1");
        assert_eq!(SERVER_ALPN_ORDER[0], ALPN_HTTP11);
        assert_eq!(CLIENT_ALPN_ORDER[0], ALPN_H2);
        assert_eq!(CLIENT_ALPN_ORDER[1], ALPN_HTTP11);
    }
}
