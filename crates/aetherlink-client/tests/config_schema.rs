//! TDD RED: golden example configs validate against the real schemas.
//!
//! `configs/*.example.yaml` are the user-facing contract (§8): they must
//! parse through the same code the hosts use, nested shape included.

#[test]
fn client_example_parses() {
    // Given: shipped client example
    let raw = std::fs::read_to_string("../../configs/client.example.yaml").expect("example");
    let doc: serde_json::Value = serde_yaml::from_str(&raw).expect("yaml");
    // When: validated → Then: accepted with tunnel DNS and example server.
    let cfg = aetherlink_client::config::ClientConfig::parse(&doc).expect("valid");
    assert_eq!(cfg.dns_mode, "tunnel");
    assert!(cfg.server_addr.contains("server.example.com"));
    assert!(!cfg.psk.is_empty());
}

/// Characterization guard for the Windows GUI multi-endpoint document: the
/// list is host-only state, and the core must keep reading the mirrored
/// active server from `server_addr`/`outer_sni`/`psk`.
#[test]
fn gui_endpoint_list_is_ignored_by_core() {
    let doc: serde_json::Value = serde_json::json!({
        "client": {
            "active_endpoint": "backup",
            "endpoints": [
                {"name": "home", "server_addr": "home.example.com:443", "psk": "psk-home"},
                {"name": "backup", "server_addr": "backup.example.com:8443", "psk": "psk-backup"}
            ],
            "server_addr": "backup.example.com:8443",
            "outer_sni": "backup.example.com",
            "psk": "psk-backup"
        }
    });
    let cfg = aetherlink_client::config::ClientConfig::parse(&doc).expect("valid");
    assert_eq!(cfg.server_addr, "backup.example.com:8443");
    assert_eq!(cfg.outer_sni, "backup.example.com");
    assert_eq!(cfg.psk, "psk-backup");
}

#[test]
fn nested_file_inherits_root_routing_and_tunnel() {
    // Given: example layout (client: section + root-level sections)
    let doc: serde_json::Value = serde_json::json!({
        "client": {"server_addr": "example.com:443", "psk": "test-psk-32-bytes-long-exactly!!"},
        "full_tunnel": {"mtu": 1350},
        "routing": {"rules": [
            {"name": "up1", "action": "direct", "priority": 40, "when": {"ip": "1.1.1.1"}}
        ]}
    });
    // When: validated -> Then: root sections apply (not silently dropped).
    let cfg = aetherlink_client::config::ClientConfig::parse(&doc).expect("valid");
    assert_eq!(cfg.mtu, 1350);
    assert!(cfg.rules.rules().iter().any(|r| r.name == "up1"));
}
