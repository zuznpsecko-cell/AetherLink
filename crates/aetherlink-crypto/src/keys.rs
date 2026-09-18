//! HKDF-SHA256 Key Derivation
//!
//! Implements key derivation for AetherLink session keys using HKDF-SHA256
//! as specified in RFC 5869.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result, AEAD_KEY_SIZE, HKDF_RX_LABEL, HKDF_SALT, HKDF_TX_LABEL};

/// Derived key pair (TX key, RX key)
pub type KeyPair = (AeadKey, AeadKey);

/// AEAD key (32 bytes)
pub type AeadKey = [u8; AEAD_KEY_SIZE];

/// Derive session keys from master secret
///
/// Uses HKDF-SHA256 with fixed salt and labels:
/// - salt = "aetherlink-v1"
/// - TX key label = "tx"
/// - RX key label = "rx"
///
/// # Arguments
/// * `master_secret` - Shared secret from key exchange (32+ bytes recommended)
/// * `salt` - Optional salt (use `HKDF_SALT` for standard derivation)
///
/// # Returns
/// Tuple of (tx_key, rx_key) - both 32 bytes
pub fn derive_keys(master_secret: &[u8], salt: &[u8]) -> KeyPair {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_secret);

    let mut tx_key = [0u8; AEAD_KEY_SIZE];
    let mut rx_key = [0u8; AEAD_KEY_SIZE];

    hkdf.expand(HKDF_TX_LABEL, &mut tx_key)
        .expect("HKDF expand should not fail for valid output length");
    hkdf.expand(HKDF_RX_LABEL, &mut rx_key)
        .expect("HKDF expand should not fail for valid output length");

    (tx_key, rx_key)
}

/// Derive session keys with default AetherLink salt
///
/// Convenience function using the standard salt "aetherlink-v1"
pub fn derive_keys_default(master_secret: &[u8]) -> KeyPair {
    derive_keys(master_secret, HKDF_SALT)
}

/// Derive a single key with custom label
///
/// Useful for deriving additional keys beyond tx/rx (e.g., for different protocols)
pub fn derive_key(master_secret: &[u8], salt: &[u8], label: &[u8]) -> AeadKey {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_secret);
    let mut key = [0u8; AEAD_KEY_SIZE];

    hkdf.expand(label, &mut key)
        .expect("HKDF expand should not fail for valid output length");

    key
}

/// Derive multiple keys with different labels
///
/// Returns a vector of keys for the given labels
pub fn derive_keys_multi(master_secret: &[u8], salt: &[u8], labels: &[&[u8]]) -> Vec<AeadKey> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_secret);
    let mut keys = Vec::with_capacity(labels.len());

    for label in labels {
        let mut key = [0u8; AEAD_KEY_SIZE];
        hkdf.expand(label, &mut key)
            .expect("HKDF expand should not fail for valid output length");
        keys.push(key);
    }

    keys
}

/// Key schedule for a session
///
/// Holds the derived TX and RX keys for a session direction.
/// For the client: TX = client->server, RX = server->client
/// For the server: TX = server->client, RX = client->server
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key for encrypting outgoing frames
    pub tx_key: AeadKey,
    /// Key for decrypting incoming frames
    pub rx_key: AeadKey,
}

impl SessionKeys {
    /// Create new session keys from master secret
    pub fn new(master_secret: &[u8]) -> Self {
        let (tx_key, rx_key) = derive_keys_default(master_secret);
        Self { tx_key, rx_key }
    }

    /// Create new session keys with custom salt
    pub fn new_with_salt(master_secret: &[u8], salt: &[u8]) -> Self {
        let (tx_key, rx_key) = derive_keys(master_secret, salt);
        Self { tx_key, rx_key }
    }

    /// Get TX key (for encryption)
    pub fn tx_key(&self) -> &AeadKey {
        &self.tx_key
    }

    /// Get RX key (for decryption)
    pub fn rx_key(&self) -> &AeadKey {
        &self.rx_key
    }

    /// Swap TX and RX keys (for the other side of the connection)
    pub fn swap(&mut self) {
        std::mem::swap(&mut self.tx_key, &mut self.rx_key);
    }

    /// Create swapped version (for peer perspective)
    pub fn swapped(&self) -> Self {
        Self {
            tx_key: self.rx_key,
            rx_key: self.tx_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AEAD_KEY_SIZE;

    #[test]
    fn test_derive_keys_deterministic() {
        let master = b"shared-master-secret-32-bytes!!";
        let salt = HKDF_SALT;

        let (tx1, rx1) = derive_keys(master, salt);
        let (tx2, rx2) = derive_keys(master, salt);

        assert_eq!(tx1, tx2, "TX key derivation must be deterministic");
        assert_eq!(rx1, rx2, "RX key derivation must be deterministic");
    }

    #[test]
    fn test_tx_rx_keys_different() {
        let master = b"shared-master-secret-32-bytes!!";
        let salt = HKDF_SALT;

        let (tx_key, rx_key) = derive_keys(master, salt);

        assert_ne!(tx_key, rx_key, "TX and RX keys must be different");
    }

    #[test]
    fn test_key_lengths() {
        let master = b"shared-master-secret-32-bytes!!";
        let salt = HKDF_SALT;

        let (tx_key, rx_key) = derive_keys(master, salt);

        assert_eq!(tx_key.len(), AEAD_KEY_SIZE);
        assert_eq!(rx_key.len(), AEAD_KEY_SIZE);
    }

    #[test]
    fn test_different_master_different_keys() {
        let master1 = b"master-secret-one-32-bytes-long!";
        let master2 = b"master-secret-two-32-bytes-long!";
        let salt = HKDF_SALT;

        let (tx1, rx1) = derive_keys(master1, salt);
        let (tx2, rx2) = derive_keys(master2, salt);

        assert_ne!(
            tx1, tx2,
            "Different master secrets must produce different TX keys"
        );
        assert_ne!(
            rx1, rx2,
            "Different master secrets must produce different RX keys"
        );
    }

    #[test]
    fn test_different_salt_different_keys() {
        let master = b"shared-master-secret-32-bytes!!";
        let salt1 = b"salt-one";
        let salt2 = b"salt-two";

        let (tx1, rx1) = derive_keys(master, salt1);
        let (tx2, rx2) = derive_keys(master, salt2);

        assert_ne!(tx1, tx2, "Different salts must produce different TX keys");
        assert_ne!(rx1, rx2, "Different salts must produce different RX keys");
    }

    #[test]
    fn test_derive_key_custom_label() {
        let master = b"shared-master-secret-32-bytes!!";
        let salt = HKDF_SALT;

        let key1 = derive_key(master, salt, b"custom-label-1");
        let key2 = derive_key(master, salt, b"custom-label-2");

        assert_ne!(key1, key2, "Different labels must produce different keys");
        assert_eq!(key1.len(), AEAD_KEY_SIZE);
    }

    #[test]
    fn test_derive_keys_multi() {
        let master = b"shared-master-secret-32-bytes!!";
        let salt = HKDF_SALT;
        let labels: &[&[u8]] = &[b"key1", b"key2", b"key3"];

        let keys = derive_keys_multi(master, salt, labels);

        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].len(), AEAD_KEY_SIZE);
        assert_eq!(keys[1].len(), AEAD_KEY_SIZE);
        assert_eq!(keys[2].len(), AEAD_KEY_SIZE);

        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn test_session_keys_new() {
        let master = b"shared-master-secret-32-bytes!!";
        let keys = SessionKeys::new(master);

        assert_ne!(keys.tx_key, keys.rx_key);
        assert_eq!(keys.tx_key.len(), AEAD_KEY_SIZE);
        assert_eq!(keys.rx_key.len(), AEAD_KEY_SIZE);
    }

    #[test]
    fn test_session_keys_swap() {
        let master = b"shared-master-secret-32-bytes!!";
        let mut keys = SessionKeys::new(master);

        let original_tx = keys.tx_key;
        let original_rx = keys.rx_key;

        keys.swap();

        assert_eq!(keys.tx_key, original_rx);
        assert_eq!(keys.rx_key, original_tx);
    }

    #[test]
    fn test_session_keys_swapped() {
        let master = b"shared-master-secret-32-bytes!!";
        let keys = SessionKeys::new(master);
        let swapped = keys.swapped();

        assert_eq!(swapped.tx_key, keys.rx_key);
        assert_eq!(swapped.rx_key, keys.tx_key);

        // Original unchanged
        assert_eq!(keys.tx_key, swapped.rx_key);
        assert_eq!(keys.rx_key, swapped.tx_key);
    }

    #[test]
    fn test_hkdf_salt_constant() {
        assert_eq!(HKDF_SALT, b"aetherlink-v1");
    }

    #[test]
    fn test_hkdf_labels_constants() {
        assert_eq!(HKDF_TX_LABEL, b"tx");
        assert_eq!(HKDF_RX_LABEL, b"rx");
    }
}
