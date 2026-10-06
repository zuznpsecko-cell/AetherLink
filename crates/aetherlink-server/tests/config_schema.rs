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
