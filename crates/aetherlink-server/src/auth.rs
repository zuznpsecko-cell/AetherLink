//! Server AUTH verification (§4.2): token over the canonical crypto primitive.
//!
//! The server itself never re-implements HMAC: single Rust stack only.

use crate::{Result, ServerError};

/// Verify `token` for `psk` + `client_nonce` (constant-time).
pub fn verify(psk: &[u8], nonce: &[u8; 32], token: &[u8; 32]) -> Result<()> {
    aetherlink_crypto::auth::verify_auth_token(psk, nonce, token)
        .map_err(|e| ServerError::AuthError(e.to_string()))
}
