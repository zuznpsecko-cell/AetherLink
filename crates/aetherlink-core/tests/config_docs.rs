//! TDD RED: shared config document parsing (Phase F).
//!
//! One boundary parser for every host: JSON first, YAML fallback, file
//! loading. Garbage must fail in both spellings.

use aetherlink_core::config;

#[test]
fn parses_json_document() {
    // Given: JSON spelling
    let v = config::parse_document(r#"{"a":1}"#).expect("json");
    // Then: value out.
    assert_eq!(v["a"], 1);
}

#[test]
fn parses_yaml_document() {
    // Given: YAML spelling (shipped examples)
    let v = config::parse_document("a: 1\nb:\n  - x\n").expect("yaml");
    assert_eq!(v["a"], 1);
    assert_eq!(v["b"][0], "x");
}

#[test]
fn rejects_garbage_in_both_spellings() {
    // Given: unclosed flow sequence (broken JSON *and* YAML)
    // When/Then: named error, never a panic or default.
    assert!(config::parse_document("[unclosed").is_err());
}

#[test]
fn loads_document_from_file() {
    // Given: temp file with YAML
    let path = std::env::temp_dir().join("aether-config-doc.yaml");
    std::fs::write(&path, "server_addr: example.com:443\n").expect("write");
    // When: loading → Then: parsed value.
    let v = config::load(&path).expect("load");
    assert_eq!(v["server_addr"], "example.com:443");
    std::fs::remove_file(&path).ok();
}
