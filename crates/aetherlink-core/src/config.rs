//! Shared config document boundary: JSON first, YAML fallback, file load.
//!
//! Every host passes file content verbatim; shipped examples are YAML (§8),
//! so both spellings are accepted with one named error. Typed schemas live
//! in the client/server crates; this module owns the untyped document step.

use std::path::Path;

use crate::{CoreError, Result};

/// Parse a config document: JSON first, YAML fallback.
pub fn parse_document(raw: &str) -> Result<serde_json::Value> {
    if let Ok(value) = serde_json::from_str(raw) {
        return Ok(value);
    }
    serde_yaml::from_str(raw)
        .map_err(|e| CoreError::ConfigError(format!("Invalid config (neither JSON nor YAML): {e}")))
}

/// Read + parse a config file.
pub fn load(path: &Path) -> Result<serde_json::Value> {
    let raw = std::fs::read(path).map_err(CoreError::Io)?;
    let text = String::from_utf8(raw)
        .map_err(|e| CoreError::ConfigError(format!("config not UTF-8: {e}")))?;
    parse_document(&text)
}
