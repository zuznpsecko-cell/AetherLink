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
