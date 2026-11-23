//! Golden test vectors for AetherLink protocol (integration).
//!
//! These are immutable test vectors that define the canonical protocol behavior.
//! All implementations MUST produce identical outputs for these inputs.

use aetherlink_crypto::{aead, auth, keys};
use aetherlink_protocol::*;

/// Test vector for HMAC-SHA256 auth token generation
/// PSK: "test-psk-32-bytes-long-exactly!!"
/// Nonce: 32 bytes of 0x01
/// Expected: HMAC-SHA256(PSK, "aetherlink-auth-v1" || nonce)
#[test]
fn test_golden_auth_token() {
    let psk = b"test-psk-32-bytes-long-exactly!!";
    let nonce = [0x01u8; NONCE_SIZE];

    let token = auth::generate_auth_token(psk, &nonce);

    // This expected value should be computed once and recorded here
    // For now, we verify the token is deterministic
    let token2 = auth::generate_auth_token(psk, &nonce);
    assert_eq!(token, token2, "Auth token must be deterministic");

    // Different nonce must produce different token
    let nonce2 = [0x02u8; NONCE_SIZE];
    let token3 = auth::generate_auth_token(psk, &nonce2);
    assert_ne!(
        token, token3,
        "Different nonce must produce different token"
    );
}

/// Test vector for ChaCha20-Poly1305 AEAD
#[test]
fn test_golden_aead_encrypt_decrypt() {
    let key = [0x42u8; AEAD_KEY_SIZE];
    let nonce = [0x24u8; AEAD_NONCE_SIZE];
    let plaintext = b"Hello AetherLink Golden Test";
    let aad = b"additional-authenticated-data";

    let ciphertext = aead::encrypt(key, nonce, plaintext, aad);

    // Ciphertext = plaintext + 16 byte tag
    assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_SIZE);

    let decrypted = aead::decrypt(key, nonce, &ciphertext, aad).expect("Decryption should succeed");
    assert_eq!(decrypted, plaintext);

    // Wrong key must fail
    let wrong_key = [0x00u8; AEAD_KEY_SIZE];
    assert!(aead::decrypt(wrong_key, nonce, &ciphertext, aad).is_err());

    // Wrong nonce must fail
    let wrong_nonce = [0x00u8; AEAD_NONCE_SIZE];
    assert!(aead::decrypt(key, wrong_nonce, &ciphertext, aad).is_err());

    // Wrong AAD must fail
    let wrong_aad = b"wrong-aad";
    assert!(aead::decrypt(key, nonce, &ciphertext, wrong_aad).is_err());
}

/// Test vector for HKDF key derivation
#[test]
fn test_golden_hkdf_key_derivation() {
    let master_secret = b"shared-master-secret-32-bytes!!";
    let salt = HKDF_SALT;

    let (tx_key, rx_key) = keys::derive_keys(master_secret, salt);

    // Keys must be different
    assert_ne!(tx_key, rx_key, "TX and RX keys must be different");

    // Keys must be 32 bytes
    assert_eq!(tx_key.len(), AEAD_KEY_SIZE);
    assert_eq!(rx_key.len(), AEAD_KEY_SIZE);

    // Derivation must be deterministic
    let (tx_key2, rx_key2) = keys::derive_keys(master_secret, salt);
    assert_eq!(tx_key, tx_key2);
    assert_eq!(rx_key, rx_key2);
}

/// Test vector for frame encoding/decoding (protocol v2).
///
/// The nonce is derived by the sender from `(id, generation, seq, type)` and
/// is not part of the frame, so this vector passes an explicit generation.
#[test]
fn test_golden_frame_codec() {
    use aetherlink_frame::{codec, types::Frame};

    let key = [0xABu8; AEAD_KEY_SIZE];
    let generation = 9u32;
    let nonce = build_nonce(1, generation, 100, FrameType::Data);

    // Test DATA frame
    let frame = Frame::data(1, 100, b"test payload data".to_vec());
    let encoded = codec::encode_frame(&frame, &key, generation, &nonce, DEFAULT_PAD_MULTIPLE)
        .expect("Encoding should succeed");

    let (decoded, framed_generation) =
        codec::decode_frame(&encoded, &key, &nonce).expect("Decoding should succeed");
    assert_eq!(decoded.frame_type, FrameType::Data);
    assert_eq!(decoded.stream_id, 1);
    assert_eq!(decoded.sequence, 100);
    assert_eq!(
        framed_generation, generation,
        "generation survives the wire"
    );
    assert_eq!(
        decoded.payload,
        aetherlink_frame::types::FramePayload::Data(b"test payload data".to_vec())
    );

    // Test OPEN_TCP frame (seq 0: the generation is the only differentiator)
    let open_nonce = build_nonce(3, generation, 0, FrameType::OpenTcp);
    let frame = Frame::open_tcp(3, 1, "example.com".to_string(), 443);
    let encoded = codec::encode_frame(&frame, &key, generation, &open_nonce, DEFAULT_PAD_MULTIPLE)
        .expect("Encoding should succeed");

    let (decoded, _) =
        codec::decode_frame(&encoded, &key, &open_nonce).expect("Decoding should succeed");
    assert_eq!(decoded.frame_type, FrameType::OpenTcp);
    assert_eq!(decoded.stream_id, 3);

    // A nonce built for another generation must not open the frame: this is
    // exactly the guarantee that a recycled id cannot be decrypted with the
    // previous incarnation's nonce.
    let wrong = build_nonce(3, generation + 1, 0, FrameType::OpenTcp);
    assert!(
        codec::decode_frame(&encoded, &key, &wrong).is_err(),
        "generation is authenticated by the nonce"
    );
}

/// The header layout is the part two independent implementations must agree
/// on, so pin the bytes, not just the roundtrip.
#[test]
fn test_golden_header_layout_v2() {
    use aetherlink_frame::codec::FrameHeader;

    let header = FrameHeader {
        length: 0x010203,
        frame_type: FrameType::OpenTcp,
        flags: 0xAB,
        stream_id: 0x0405,
        sequence: 0x0607_0809,
        generation: 0x0A0B_0C0D,
    };
    let mut buf = bytes::BytesMut::new();
    header.encode(&mut buf);
    assert_eq!(buf.len(), FRAME_HEADER_SIZE, "header stays 24 bytes");
    assert_eq!(
        &buf[..FRAME_HEADER_SIZE - FRAME_HEADER_RANDOM_SIZE],
        &[
            0x01, 0x02, 0x03, // length (24-bit)
            0x01, // type = OpenTcp
            0xAB, // flags
            0x04, 0x05, // stream id
            0x06, 0x07, 0x08, 0x09, // sequence
            0x0A, 0x0B, 0x0C, 0x0D, // generation
        ],
        "v2 header fields must sit at their documented offsets"
    );

    // And: the reserved tail carries no protocol meaning, so decoding gives
    // back exactly the fields above.
    let decoded = FrameHeader::decode(&mut buf).expect("decode");
    assert_eq!(decoded, header);
}

/// Test vector for frame types serialization
#[test]
fn test_golden_frame_types() {
    use aetherlink_frame::types::Frame;

    // DATA frame
    let data_frame = Frame::data(1, 1, b"data".to_vec());
    assert_eq!(data_frame.frame_type, FrameType::Data);

    // OPEN_TCP frame
    let open_tcp = Frame::open_tcp(3, 1, "example.com".to_string(), 443);
    assert_eq!(open_tcp.frame_type, FrameType::OpenTcp);

    // PING frame
    let ping = Frame::ping(5);
    assert_eq!(ping.frame_type, FrameType::Ping);

    // AUTH frame
    let auth_frame = Frame::auth([0x01u8; NONCE_SIZE], [0x02u8; AUTH_TOKEN_SIZE]);
    assert_eq!(auth_frame.frame_type, FrameType::Auth);

    // WINDOW_UPDATE frame
    let window_update = Frame::window_update(7, 1024);
    assert_eq!(window_update.frame_type, FrameType::WindowUpdate);

    // GOAWAY frame
    let goaway = Frame::goaway(0);
    assert_eq!(goaway.frame_type, FrameType::GoAway);

    // RST frame
    let rst = Frame::rst(9, 0);
    assert_eq!(rst.frame_type, FrameType::Rst);

    // OPEN_UDP frame
    let open_udp = Frame::open_udp(11, "8.8.8.8".to_string(), 53);
    assert_eq!(open_udp.frame_type, FrameType::OpenUdp);

    // UDP_DATAGRAM frame
    let udp_datagram = Frame::udp_datagram(13, b"dns query".to_vec());
    assert_eq!(udp_datagram.frame_type, FrameType::UdpDatagram);
}
