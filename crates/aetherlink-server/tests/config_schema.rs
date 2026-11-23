//! TDD RED: golden server example validates against the real schema.

#[test]
fn server_example_parses() {
    // Given: shipped server example
    let raw = std::fs::read_to_string("../../configs/server.example.yaml").expect("example");
    let doc: serde_json::Value = serde_yaml::from_str(&raw).expect("yaml");
    // When: validated → Then: accepted with canonical upstreams.
    let cfg = aetherlink_server::config::ServerConfig::parse(&doc).expect("valid");
    assert!(cfg.dns_upstream.iter().any(|u| u == "1.1.1.1:53"));
    assert!(!cfg.psk.is_empty());
    assert_eq!(cfg.max_streams, 4096);
    // And: the shipped example carries the egress policy (DEC-021).
    assert!(cfg.egress.denies_private());
    assert!(cfg.egress.check("127.0.0.1".parse().expect("ip")).is_err());
}

#[test]
fn blocklist_flag_defaults_on_and_parses() {
    // Given: minimal config without blocklist keys
    let doc: serde_json::Value = serde_json::json!({
        "server": {
            "listen": "0.0.0.0:443",
            "psk": "test-psk-32-bytes-long-for-tests!!",
            "local_static_root": ".",
        }
    });
    // When: validated -> Then: blocklist on by default, lists empty.
    let cfg = aetherlink_server::config::ServerConfig::parse(&doc).expect("valid");
    assert!(cfg.blocklist_enabled);
    assert!(cfg.blocked_domains.is_empty());
    assert!(cfg.blocked_domains_file.is_none());
    // And: explicit off + custom entries parse through.
    let doc: serde_json::Value = serde_json::json!({
        "server": {
            "listen": "0.0.0.0:443",
            "psk": "test-psk-32-bytes-long-for-tests!!",
            "local_static_root": ".",
            "blocklist_enabled": false,
            "blocked_domains": ["ads.example.com", "full:tracker.example.net"],
        }
    });
    let cfg = aetherlink_server::config::ServerConfig::parse(&doc).expect("valid");
    assert!(!cfg.blocklist_enabled);
    assert_eq!(cfg.blocked_domains.len(), 2);
}

/// `max_connections` bounds concurrent sockets (one thread each). It must be
/// configurable, default sanely, and never be zero — a zero cap would refuse
/// every connection and look like a dead server.
#[test]
fn max_connections_parses_and_defaults() {
    // Given: an explicit value
    let doc: serde_json::Value = serde_json::json!({
        "server": {
            "listen": "0.0.0.0:443",
            "psk": "test-psk-32-bytes-long-for-tests!!",
            "local_static_root": ".",
            "max_connections": 64,
        }
    });
    let cfg = aetherlink_server::config::ServerConfig::parse(&doc).expect("valid");
    assert_eq!(cfg.max_connections, 64);

    // And: omitted -> the documented default.
    let doc: serde_json::Value = serde_json::json!({
        "server": {
            "listen": "0.0.0.0:443",
            "psk": "test-psk-32-bytes-long-for-tests!!",
            "local_static_root": ".",
        }
    });
    let cfg = aetherlink_server::config::ServerConfig::parse(&doc).expect("valid");
    assert_eq!(
        cfg.max_connections,
        aetherlink_server::accept::DEFAULT_MAX_CONNECTIONS
    );

    // And: zero is clamped up, never accepted as "refuse everything".
    let doc: serde_json::Value = serde_json::json!({
        "server": {
            "listen": "0.0.0.0:443",
            "psk": "test-psk-32-bytes-long-for-tests!!",
            "local_static_root": ".",
            "max_connections": 0,
        }
    });
    let cfg = aetherlink_server::config::ServerConfig::parse(&doc).expect("valid");
    assert_eq!(cfg.max_connections, 1, "zero must never disable the server");
}

/// Egress policy defaults matter: a config written before DEC-021 must still
/// be protected, and a typo in a CIDR must fail loudly instead of silently
/// widening what the relay may reach.
#[test]
fn egress_defaults_on_and_parses_overrides() {
    use std::net::IpAddr;
    let minimal = serde_json::json!({
        "server": {
            "listen": "0.0.0.0:443",
            "psk": "test-psk-32-bytes-long-for-tests!!",
            "local_static_root": ".",
        }
    });
    // Given: no `egress` block -> Then: deny_private is on, loopback refused.
    let cfg = aetherlink_server::config::ServerConfig::parse(&minimal).expect("valid");
    assert!(cfg.egress.denies_private());
    assert!(cfg
        .egress
        .check("127.0.0.1".parse::<IpAddr>().expect("ip"))
        .is_err());

    // Given: an explicit opt-out plus CIDRs
    let doc = serde_json::json!({
        "server": {
            "listen": "0.0.0.0:443",
            "psk": "test-psk-32-bytes-long-for-tests!!",
            "local_static_root": ".",
            "egress": {
                "deny_private": false,
                "allow": ["10.1.0.0/16"],
                "deny": ["198.51.99.0/24"],
            },
        }
    });
    // Then: private targets pass again, deny still applies, allow is honoured.
    let cfg = aetherlink_server::config::ServerConfig::parse(&doc).expect("valid");
    assert!(!cfg.egress.denies_private());
    assert!(cfg.egress.check("10.0.0.1".parse().expect("ip")).is_ok());
    assert!(cfg.egress.check("10.1.2.3".parse().expect("ip")).is_ok());
    assert!(cfg
        .egress
        .check("198.51.99.9".parse().expect("ip"))
        .is_err());
}

#[test]
fn malformed_egress_cidr_is_a_config_error() {
    // Given: a typo in the allow list
    let doc = serde_json::json!({
        "server": {
            "listen": "0.0.0.0:443",
            "psk": "test-psk-32-bytes-long-for-tests!!",
            "local_static_root": ".",
            "egress": { "allow": ["10.0.0.0/33"] },
        }
    });
    // Then: hard error, never a silently ignored rule.
    assert!(aetherlink_server::config::ServerConfig::parse(&doc).is_err());
}
