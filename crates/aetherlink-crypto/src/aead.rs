//! ChaCha20-Poly1305 AEAD Encryption
//!
//! Implements authenticated encryption with associated data (AEAD) using
//! ChaCha20-Poly1305 as specified in RFC 8439.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result, AEAD_KEY_SIZE, AEAD_NONCE_LEN, AEAD_TAG_LEN};

/// AEAD key (32 bytes)
pub type AeadKey = [u8; AEAD_KEY_SIZE];

/// AEAD nonce (12 bytes)
pub type AeadNonce = [u8; AEAD_NONCE_LEN];

/// Encrypt plaintext with ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per key!)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (not encrypted but authenticated)
///
/// # Returns
/// Ciphertext with appended authentication tag (plaintext.len() + 16 bytes)
///
/// # Panics
/// Panics if encryption fails (should not happen with valid inputs)
pub fn encrypt(key: AeadKey, nonce: AeadNonce, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .expect("ChaCha20-Poly1305 encryption should not fail with valid inputs")
}

/// Decrypt ciphertext with ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must match encryption nonce)
/// * `ciphertext` - Encrypted data with appended tag (must be at least 16 bytes)
/// * `aad` - Additional authenticated data (must match encryption AAD)
///
/// # Returns
/// Decrypted plaintext on success
///
/// # Errors
/// Returns `CryptoError::DecryptionFailed` if authentication fails or inputs invalid
pub fn decrypt(key: AeadKey, nonce: AeadNonce, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < AEAD_TAG_LEN {
        return Err(CryptoError::DecryptionFailed(
            "Ciphertext too short".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed("Authentication failed".to_string()))
}

/// Encrypt in-place (modifies buffer)
///
/// Useful for avoiding allocations when encrypting into a pre-allocated buffer.
/// Buffer must have capacity for plaintext + tag.
pub fn encrypt_in_place(
    key: AeadKey,
    nonce: AeadNonce,
    buffer: &mut Vec<u8>,
    aad: &[u8],
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&nonce);

    let payload = Payload {
        msg: buffer.as_slice(),
        aad,
    };

    // We need to encrypt into a separate buffer then copy back
    // because the trait doesn't support true in-place for Vec
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed("Encryption failed".to_string()))?;

    buffer.clear();
    buffer.extend_from_slice(&ciphertext);
    Ok(())
}

/// Decrypt in-place (modifies buffer)
///
/// Buffer contains ciphertext + tag, will be replaced with plaintext.
pub fn decrypt_in_place(
    key: AeadKey,
    nonce: AeadNonce,
    buffer: &mut Vec<u8>,
    aad: &[u8],
) -> Result<()> {
    if buffer.len() < AEAD_TAG_LEN {
        return Err(CryptoError::DecryptionFailed(
            "Ciphertext too short".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&nonce);

    let payload = Payload {
        msg: buffer.as_slice(),
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed("Authentication failed".to_string()))?;

    buffer.clear();
    buffer.extend_from_slice(&plaintext);
    Ok(())
}

/// Generate a random AEAD nonce
///
/// Each nonce must be unique per key! Use this for generating fresh nonces.
pub fn generate_nonce() -> AeadNonce {
    use rand::RngCore;
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Nonce sequence generator for deterministic nonce derivation
///
/// Useful when you need sequential nonces (e.g., frame sequence numbers).
/// Combines a base nonce with a sequence counter.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct NonceSequence {
    base: AeadNonce,
    counter: u32,
}

impl NonceSequence {
    /// Create a new nonce sequence from a base nonce
    pub fn new(base: AeadNonce) -> Self {
        Self { base, counter: 0 }
    }

    /// Get the next nonce in the sequence
    pub fn next(&mut self) -> AeadNonce {
        let mut nonce = self.base;
        // Encode counter in last 4 bytes of nonce (big-endian)
        nonce[8..12].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    /// Get current counter value
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// Reset counter to 0
    pub fn reset(&mut self) {
        self.counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AEAD_TAG_LEN;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x24u8; AEAD_NONCE_LEN];
        let plaintext = b"Hello AetherLink AEAD Test";
        let aad = b"additional-authenticated-data";

        let ciphertext = encrypt(key, nonce, plaintext, aad);

        // Ciphertext = plaintext + 16 byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_LEN);

        let decrypted = decrypt(key, nonce, &ciphertext, aad).expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [0x01u8; AEAD_KEY_SIZE];
        let key2 = [0x02u8; AEAD_KEY_SIZE];
        let nonce = [0x42u8; AEAD_NONCE_LEN];
        let plaintext = b"secret message";
        let aad = b"aad";

        let ciphertext = encrypt(key1, nonce, plaintext, aad);

        assert!(decrypt(key2, nonce, &ciphertext, aad).is_err());
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce1 = [0x01u8; AEAD_NONCE_LEN];
        let nonce2 = [0x02u8; AEAD_NONCE_LEN];
        let plaintext = b"secret message";
        let aad = b"aad";

        let ciphertext = encrypt(key, nonce1, plaintext, aad);

        assert!(decrypt(key, nonce2, &ciphertext, aad).is_err());
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x42u8; AEAD_NONCE_LEN];
        let plaintext = b"secret message";
        let aad1 = b"correct-aad";
        let aad2 = b"wrong-aad";

        let ciphertext = encrypt(key, nonce, plaintext, aad1);

        assert!(decrypt(key, nonce, &ciphertext, aad2).is_err());
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x42u8; AEAD_NONCE_LEN];
        let plaintext = b"secret message";
        let aad = b"aad";

        let mut ciphertext = encrypt(key, nonce, plaintext, aad);

        // Corrupt a byte in the ciphertext (not the tag)
        if ciphertext.len() > AEAD_TAG_LEN {
            ciphertext[0] ^= 0xFF;
        }

        assert!(decrypt(key, nonce, &ciphertext, aad).is_err());
    }

    #[test]
    fn test_decrypt_corrupted_tag_fails() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x42u8; AEAD_NONCE_LEN];
        let plaintext = b"secret message";
        let aad = b"aad";

        let mut ciphertext = encrypt(key, nonce, plaintext, aad);

        // Corrupt the tag (last 16 bytes)
        let tag_start = ciphertext.len() - AEAD_TAG_LEN;
        ciphertext[tag_start] ^= 0xFF;

        assert!(decrypt(key, nonce, &ciphertext, aad).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x24u8; AEAD_NONCE_LEN];
        let plaintext = b"";
        let aad = b"aad";

        let ciphertext = encrypt(key, nonce, plaintext, aad);
        assert_eq!(ciphertext.len(), AEAD_TAG_LEN); // Only tag

        let decrypted = decrypt(key, nonce, &ciphertext, aad).expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x24u8; AEAD_NONCE_LEN];
        let plaintext = vec![0xABu8; 10000]; // 10KB
        let aad = b"aad";

        let ciphertext = encrypt(key, nonce, &plaintext, aad);
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_LEN);

        let decrypted = decrypt(key, nonce, &ciphertext, aad).expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_in_place() {
        let key = [0x42u8; AEAD_KEY_SIZE];
        let nonce = [0x24u8; AEAD_NONCE_LEN];
        let mut buffer = b"plaintext data".to_vec();
        let aad = b"aad";
        let original = buffer.clone();

        encrypt_in_place(key, nonce, &mut buffer, aad).expect("In-place encryption should succeed");

        assert_eq!(buffer.len(), original.len() + AEAD_TAG_LEN);

        // Decrypt back
        decrypt_in_place(key, nonce, &mut buffer, aad).expect("In-place decryption should succeed");
        assert_eq!(buffer, original);
    }

    #[test]
    fn test_nonce_sequence() {
        let base = [0x42u8; AEAD_NONCE_LEN];
        let mut seq = NonceSequence::new(base);

        let n1 = seq.next();
        let n2 = seq.next();
        let n3 = seq.next();

        // First 8 bytes should be same, last 4 should increment
        assert_eq!(&n1[..8], &n2[..8]);
        assert_eq!(&n2[..8], &n3[..8]);

        assert_eq!(u32::from_be_bytes(n1[8..12].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(n2[8..12].try_into().unwrap()), 1);
        assert_eq!(u32::from_be_bytes(n3[8..12].try_into().unwrap()), 2);

        assert_eq!(seq.counter(), 3);
    }

    #[test]
    fn test_generate_nonce_unique() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();

        assert_ne!(n1, n2);
    }
}
