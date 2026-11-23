//! Header authentication: the clear-text frame header is AEAD associated data.
//!
//! Before this, `encode_frame`/`decode_frame` passed `aad = &[]`, so every
//! header field was unauthenticated: `stream_id`, `sequence`, `generation`,
//! `flags` and `length` could be edited in flight and the ciphertext still
//! decrypted. That matters beyond generic tampering — `stream_id` selects the
//! TUN flow the plaintext is injected into, and `generation` is the nonce
//! component DEC-014 relies on. An attacker who can rewrite the header can
//! redirect a flow or replay a frame into another incarnation of an id.

use aetherlink_crypto::aead::AeadKey;
use aetherlink_crypto::DEFAULT_PAD_MULTIPLE;
use aetherlink_frame::codec::{
    decode_frame, encode_frame, header_aad, FrameHeader, AAD_HEADER_LEN,
};
use aetherlink_frame::types::Frame;
use aetherlink_protocol::{build_nonce, FrameType, FRAME_HEADER_SIZE};

const KEY: AeadKey = [0x5Au8; 32];
const GENERATION: u32 = 3;

fn seal() -> (FrameHeader, Vec<u8>) {
    let nonce = build_nonce(1, GENERATION, 11, FrameType::Data);
    let frame = Frame::data(1, 11, b"payload".to_vec());
    let wire =
        encode_frame(&frame, &KEY, GENERATION, &nonce, DEFAULT_PAD_MULTIPLE).expect("encode");
    let mut buf = bytes::BytesMut::from(&wire[..]);
    let header = FrameHeader::decode(&mut buf).expect("header");
    (header, wire[FRAME_HEADER_SIZE..].to_vec())
}

/// Flip one bit at `offset` of a sealed frame's clear-text header.
fn tamper(wire_header: &FrameHeader, offset: usize) -> Vec<u8> {
    let mut hb = bytes::BytesMut::new();
    wire_header.encode(&mut hb);
    hb[offset] ^= 0x01;
    hb.to_vec()
}

#[test]
fn aad_covers_every_meaningful_header_field() {
    // Given: a header
    let header = FrameHeader {
        length: 0x010203,
        frame_type: FrameType::Data,
        flags: 0x07,
        stream_id: 0x0405,
        sequence: 0x0607_0809,
        generation: 0x0A0B_0C0D,
    };
    // Then: the AAD is exactly the wire bytes a peer can see, in order.
    assert_eq!(AAD_HEADER_LEN, 15);
    assert_eq!(
        header_aad(&header),
        [
            0x01, 0x02, 0x03, // length
            0x00, // type = FrameType::Data (discriminant 0)
            0x07, // flags
            0x04, 0x05, // stream id
            0x06, 0x07, 0x08, 0x09, // sequence
            0x0A, 0x0B, 0x0C, 0x0D, // generation
        ]
    );
    // And: the 9 random tail bytes are excluded, so two encodings of the same
    // header produce the same AAD (the tail carries no meaning).
    let mut a = bytes::BytesMut::new();
    let mut b = bytes::BytesMut::new();
    header.encode(&mut a);
    header.encode(&mut b);
    assert_ne!(&a[15..], &b[15..], "tail is random");
    assert_eq!(header_aad(&header), header_aad(&header));
}

#[test]
fn untampered_frame_still_roundtrips() {
    let (header, ciphertext) = seal();
    let nonce = build_nonce(1, GENERATION, 11, FrameType::Data);
    let mut wire = bytes::BytesMut::new();
    header.encode(&mut wire);
    wire.extend_from_slice(&ciphertext);
    let (frame, generation) = decode_frame(&wire, &KEY, &nonce).expect("decode");
    assert_eq!(generation, GENERATION);
    assert_eq!(frame.stream_id, 1);
    assert_eq!(
        frame.payload,
        aetherlink_frame::types::FramePayload::Data(b"payload".to_vec())
    );
}

#[test]
fn tampered_header_is_rejected_by_the_aead() {
    let (header, ciphertext) = seal();
    // Offsets: 0..3 length, 3 type, 4 flags, 5..7 stream id, 7..11 sequence,
    // 11..15 generation, 15..24 random tail.
    for (offset, what) in [
        (5usize, "stream id high byte"),
        (6, "stream id low byte"),
        (7, "sequence"),
        (11, "generation"),
    ] {
        let mut wire = bytes::BytesMut::from(&tamper(&header, offset)[..]);
        wire.extend_from_slice(&ciphertext);
        let nonce = build_nonce(1, GENERATION, 11, FrameType::Data);
        assert!(
            decode_frame(&wire, &KEY, &nonce).is_err(),
            "editing the {what} (offset {offset}) must fail authentication"
        );
    }
}

#[test]
fn tampered_reserved_tail_is_accepted() {
    // The random tail is not authenticated on purpose: it carries no
    // meaning, and authenticating it would make the AAD depend on bytes the
    // sender rewrites for every frame anyway.
    let (header, ciphertext) = seal();
    let mut wire = bytes::BytesMut::from(&tamper(&header, 20)[..]);
    wire.extend_from_slice(&ciphertext);
    let nonce = build_nonce(1, GENERATION, 11, FrameType::Data);
    assert!(decode_frame(&wire, &KEY, &nonce).is_ok());
}

#[test]
fn frame_cannot_be_moved_to_another_stream_id() {
    // This is the security-relevant case: same key, same sequence, same
    // payload — only the routing id differs. Without header authentication
    // the frame decrypts and the plaintext lands in another flow.
    let (header, ciphertext) = seal();
    let moved = FrameHeader {
        stream_id: 0x9999,
        ..header.clone()
    };
    let mut wire = bytes::BytesMut::new();
    moved.encode(&mut wire);
    wire.extend_from_slice(&ciphertext);
    let nonce = build_nonce(1, GENERATION, 11, FrameType::Data);
    assert!(
        decode_frame(&wire, &KEY, &nonce).is_err(),
        "stream id is authenticated"
    );
}
