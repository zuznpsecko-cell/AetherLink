//! HMAC-SHA256 Authentication Token Generation
//!
//! Implements the AetherLink authentication token as specified:
//! token = HMAC-SHA256(PSK, "aetherlink-auth-v1" || client_nonce[32])

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CryptoError, Result, AUTH_PREFIX, AUTH_TOKEN_SIZE, DEFAULT_NONCE_TTL_SECS, NONCE_SIZE,
};

type HmacSha256 = Hmac<Sha256>;

/// Client nonce (32 bytes)
pub type ClientNonce = [u8; NONCE_SIZE];

/// Authentication token (32 bytes = SHA256 output)
pub type AuthToken = [u8; AUTH_TOKEN_SIZE];

/// Generate authentication token
///
/// # Arguments
/// * `psk` - Pre-shared key (recommended 32+ bytes high entropy)
/// * `client_nonce` - 32-byte client-generated nonce
///
/// # Returns
/// 32-byte HMAC-SHA256 token
///
/// # Algorithm
/// token = HMAC-SHA256(PSK, AUTH_PREFIX || client_nonce)
pub fn generate_auth_token(psk: &[u8], client_nonce: &ClientNonce) -> AuthToken {
    let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC-SHA256 accepts any key size");

    mac.update(AUTH_PREFIX);
    mac.update(client_nonce);

    let result = mac.finalize();
    let mut token = [0u8; AUTH_TOKEN_SIZE];
    token.copy_from_slice(&result.into_bytes());
    token
}

/// Verify authentication token (constant-time comparison)
///
/// # Arguments
/// * `psk` - Pre-shared key
/// * `client_nonce` - Client nonce that was used
/// * `provided_token` - Token to verify
///
/// # Returns
/// `Ok(())` if token matches, `Err(CryptoError::AuthenticationFailed)` otherwise
pub fn verify_auth_token(
    psk: &[u8],
    client_nonce: &ClientNonce,
    provided_token: &AuthToken,
) -> Result<()> {
    let expected_token = generate_auth_token(psk, client_nonce);

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    if expected_token.ct_eq(provided_token).into() {
        Ok(())
    } else {
        Err(CryptoError::AuthenticationFailed(
            "Invalid auth token".to_string(),
        ))
    }
}

/// Generate a cryptographically secure random nonce
pub fn generate_nonce() -> ClientNonce {
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Nonce replay cache entry
#[derive(Clone, Debug)]
pub struct NonceEntry {
    pub nonce: ClientNonce,
    pub timestamp: std::time::Instant,
}

/// Nonce replay cache with TTL-based expiration
///
/// Thread-safe cache that stores recently seen nonces and rejects replays.
/// Entries expire after `ttl_secs` (default 300 seconds / 5 minutes).
pub struct NonceCache {
    entries: std::sync::Mutex<Vec<NonceEntry>>,
    ttl: std::time::Duration,
    max_entries: usize,
}

impl NonceCache {
    /// Create a new nonce cache with default TTL (5 minutes) and max 10000 entries
    pub fn new() -> Self {
        Self::with_config(DEFAULT_NONCE_TTL_SECS, 10000)
    }

    /// Create a new nonce cache with custom TTL and max entries
    pub fn with_config(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::with_capacity(max_entries.min(1000))),
            ttl: std::time::Duration::from_secs(ttl_secs),
            max_entries,
        }
    }

    /// Check if nonce is a replay and insert if not
    ///
    /// Returns `Ok(())` if nonce is fresh (not seen before within TTL),
    /// `Err(CryptoError::AuthenticationFailed)` if nonce is a replay.
    pub fn check_and_insert(&self, nonce: ClientNonce) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        let now = std::time::Instant::now();

        // Remove expired entries
        entries.retain(|e| now.duration_since(e.timestamp) < self.ttl);

        // Check for replay
        if entries.iter().any(|e| e.nonce == nonce) {
            return Err(CryptoError::AuthenticationFailed(
                "Nonce replay detected".to_string(),
            ));
        }

        // Enforce max entries limit
        if entries.len() >= self.max_entries {
            // Remove oldest entry
            entries.remove(0);
        }

        // Insert new nonce
        entries.push(NonceEntry {
            nonce,
            timestamp: now,
        });

        Ok(())
    }

    /// Get current cache size (for testing/monitoring)
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AUTH_PREFIX;

    #[test]
    fn test_generate_auth_token_deterministic() {
        let psk = b"test-psk-32-bytes-long-exactly!!";
        let nonce = [0x42u8; NONCE_SIZE];

        let token1 = generate_auth_token(psk, &nonce);
        let token2 = generate_auth_token(psk, &nonce);

        assert_eq!(token1, token2, "Token generation must be deterministic");
    }

    #[test]
    fn test_different_nonce_different_token() {
        let psk = b"same-psk-for-both-tests";
        let nonce1 = [0x01u8; NONCE_SIZE];
        let nonce2 = [0x02u8; NONCE_SIZE];

        let token1 = generate_auth_token(psk, &nonce1);
        let token2 = generate_auth_token(psk, &nonce2);

        assert_ne!(
            token1, token2,
            "Different nonces must produce different tokens"
        );
    }

    #[test]
    fn test_different_psk_different_token() {
        let psk1 = b"psk-one-32-bytes-long-exactly!!";
        let psk2 = b"psk-two-32-bytes-long-exactly!!";
        let nonce = [0x42u8; NONCE_SIZE];

        let token1 = generate_auth_token(psk1, &nonce);
        let token2 = generate_auth_token(psk2, &nonce);

        assert_ne!(
            token1, token2,
            "Different PSKs must produce different tokens"
        );
    }

    #[test]
    fn test_verify_auth_token_valid() {
        let psk = b"test-psk-32-bytes-long-exactly!!";
        let nonce = [0xABu8; NONCE_SIZE];
        let token = generate_auth_token(psk, &nonce);

        assert!(verify_auth_token(psk, &nonce, &token).is_ok());
    }

    #[test]
    fn test_verify_auth_token_invalid() {
        let psk = b"test-psk-32-bytes-long-exactly!!";
        let nonce = [0xABu8; NONCE_SIZE];
        let mut token = generate_auth_token(psk, &nonce);

        // Corrupt the token
        token[0] ^= 0xFF;

        assert!(verify_auth_token(psk, &nonce, &token).is_err());
    }

    #[test]
    fn test_verify_auth_token_wrong_nonce() {
        let psk = b"test-psk-32-bytes-long-exactly!!";
        let nonce1 = [0x01u8; NONCE_SIZE];
        let nonce2 = [0x02u8; NONCE_SIZE];
        let token = generate_auth_token(psk, &nonce1);

        // Try to verify with different nonce
        assert!(verify_auth_token(psk, &nonce2, &token).is_err());
    }

    #[test]
    fn test_nonce_cache_replay_detection() {
        let cache = NonceCache::new();
        let nonce = [0x42u8; NONCE_SIZE];

        // First use should succeed
        assert!(cache.check_and_insert(nonce).is_ok());

        // Second use should fail (replay)
        assert!(cache.check_and_insert(nonce).is_err());
    }

    #[test]
    fn test_nonce_cache_expiry() {
        let cache = NonceCache::with_config(1, 100); // 1 second TTL
        let nonce = [0x42u8; NONCE_SIZE];

        // Insert nonce
        assert!(cache.check_and_insert(nonce).is_ok());

        // Wait for expiry
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Should be able to use again after expiry
        assert!(cache.check_and_insert(nonce).is_ok());
    }

    #[test]
    fn test_generate_nonce_unique() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Extremely unlikely to be equal (2^256 possibilities)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_auth_prefix_constant() {
        assert_eq!(AUTH_PREFIX, b"aetherlink-auth-v1");
    }
}
