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
