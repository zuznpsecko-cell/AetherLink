//! Static web fallback decision (§4.5, G2).
//!
//! Valid AUTH → `"tunnel"` (mux inside TLS).
//! Missing/bad auth → `"static"` (plain web root, no tunnel banner).

use crate::{Result, ServerError};

/// Decide the path for an incoming connection.
pub fn decide(authed: bool) -> Result<&'static str> {
    if authed {
        Ok("tunnel")
    } else {
        Ok("static")
    }
}

/// True when the path serves the static web root (G2: no tunnel surface).
#[must_use]
pub fn is_static(path: &str) -> bool {
    path == "static"
}

/// Guard helper pairing the decision with an error mapping.
pub fn ensure_not_tunnel(path: &str) -> Result<()> {
    if is_static(path) {
        Ok(())
    } else {
        Err(ServerError::FallbackError("tunnel path denied".to_string()))
    }
}
