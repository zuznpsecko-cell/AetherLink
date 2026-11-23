//! TDD RED: AEAD nonces must stay unique across recycled stream ids.
//!
//! Protocol v1 derived the nonce from `(stream_id, sequence, type)` while
//! [`MuxManager`] recycles ids on purpose (a session outlives the 16-bit id
//! space; a browser burns thousands of flows a minute). The OPEN frame always
//! uses `sequence = 0`, so the first duplicate under one traffic key was
//! `(id, 0, OpenTcp)` — with the dial target inside the sealed payload.
//!
//! Repeating a ChaCha20-Poly1305 nonce leaks the keystream (XOR of two
//! ciphertexts) and forges Poly1305 tags, so these tests pin the v2 invariant:
//! `generation` advances for every re-incarnation of an id and feeds the nonce.

use std::collections::HashSet;

use aetherlink_mux::manager::{build_nonce_for, seal_frame_with, MuxManager};
use aetherlink_protocol::{build_nonce, FrameType};

const KEY: [u8; 32] = [0x5Au8; 32];

/// Recycle one id through many incarnations and collect every nonce the
/// *sender* would use, exactly as the wire would.
fn nonces_over_recycled_id(incarnations: usize, frame_type: FrameType) -> Vec<[u8; 12]> {
    let mut mux = MuxManager::with_max(1);
    let mut out = Vec::new();
    for _ in 0..incarnations {
        let id = mux.open_tcp("93.184.216.34", 443).expect("open");
        let open = mux.seal_open_tcp(&KEY, id, 128).expect("seal open");
        out.push(build_nonce(
            open.header.stream_id,
            open.header.generation,
            open.header.sequence,
            frame_type,
        ));
        let data = mux.seal_data(&KEY, id, b"payload", 128).expect("seal data");
        out.push(build_nonce(
            data.header.stream_id,
            data.header.generation,
            data.header.sequence,
            FrameType::Data,
        ));
        mux.close(id).expect("close");
    }
    out
}

#[test]
fn open_nonces_never_repeat_across_recycled_ids() {
    // Given: one id recycled far past the point where a bare id/seq scheme
    //        wraps (the v1 hole), sealing an OPEN frame each time
    // When: deriving every nonce the sender uses
    let nonces = nonces_over_recycled_id(600, FrameType::OpenTcp);
    // Then: no nonce is ever emitted twice under the live traffic key.
    let unique: HashSet<[u8; 12]> = nonces.iter().copied().collect();
    assert_eq!(
        nonces.len(),
        unique.len(),
        "duplicate AEAD nonce across recycled stream ids"
    );
}

#[test]
fn data_nonces_never_repeat_across_recycled_ids() {
    // Same shape, DATA frames (sequence restarts at 1 on every incarnation).
    let nonces = nonces_over_recycled_id(600, FrameType::OpenTcp);
    let data_only: Vec<[u8; 12]> = nonces
        .into_iter()
        .filter(|n| n[10] == FrameType::Data as u8)
        .collect();
    let unique: HashSet<[u8; 12]> = data_only.iter().copied().collect();
    assert_eq!(data_only.len(), unique.len(), "duplicate DATA nonce");
}

#[test]
fn recycled_id_gets_a_fresh_generation() {
    // Given: an id that was opened and closed
    let mut mux = MuxManager::with_max(1);
    let first = mux.open_tcp("10.0.0.9", 80).expect("open");
    let g1 = mux
        .seal_open_tcp(&KEY, first, 128)
        .expect("open frame")
        .header.generation;
    mux.close(first).expect("close");
    // When: the allocator recycles it
    let second = mux.open_tcp("10.0.0.9", 80).expect("reopen");
    let g2 = mux
        .seal_open_tcp(&KEY, second, 128)
        .expect("second open frame")
        .header.generation;
    // Then: same id, strictly newer generation.
    assert_eq!(first, second, "test premise: the id was recycled");
    assert_eq!(g1, 0, "the first incarnation starts at generation 0");
    assert!(
        g2 > g1,
        "recycled id must advance the nonce generation (got {g1} then {g2})"
    );
}

#[test]
fn inbound_registration_advances_generation_too() {
    // Given: the server-side path — a peer id registered, then released when
    //        the stream closes (this is what the accept loop does on RST/EOF)
    let mut peer = MuxManager::new();
    peer.register_inbound(7, "10.0.0.9", 80, false)
        .expect("first registration");
    peer.close(7).expect("close");
    // When: the peer re-opens the same id
    peer.register_inbound(7, "10.0.0.9", 80, false)
        .expect("second registration");
    // Then: a frame still carrying the *previous* incarnation's generation is
    //       refused instead of being decrypted into the new window.
    let stale = seal_frame_with(
        &KEY,
        7,
        0, // generation of the first incarnation
        1,
        aetherlink_frame::types::Frame::data(7, 1, b"old".to_vec()),
        128,
    )
    .expect("seal stale frame");
    assert!(
        peer.open_data(&KEY, &stale.header, &stale.ciphertext).is_err(),
        "a frame from a previous incarnation must not open in the new one"
    );
}

#[test]
fn frames_from_a_newer_generation_are_refused_until_registered() {
    // Given: a live inbound id at its first generation
    let mut peer = MuxManager::new();
    peer.register_inbound(9, "10.0.0.9", 80, false)
        .expect("register");
    // When: a frame claims a generation the peer side has not registered yet
    let ahead = seal_frame_with(
        &KEY,
        9,
        1, // a generation this side has not registered
        1,
        aetherlink_frame::types::Frame::data(9, 1, b"new".to_vec()),
        128,
    )
    .expect("seal future frame");
    // Then: refused, never decrypted into the stale window.
    assert!(peer.open_data(&KEY, &ahead.header, &ahead.ciphertext).is_err());
}

#[test]
fn nonce_is_unique_within_one_live_stream() {
    // Given: a single stream sealing many DATA frames in order
    let mut mux = MuxManager::new();
    let id = mux.open_tcp("10.0.0.9", 80).expect("open");
    // When: deriving each frame's nonce
    let mut seen = HashSet::new();
    for _ in 0..2_000 {
        let frame = mux.seal_data(&KEY, id, b"x", 128).expect("seal");
        let nonce = build_nonce(
            frame.header.stream_id,
            frame.header.generation,
            frame.header.sequence,
            FrameType::Data,
        );
        // Then: strictly unique (sequence monotonicity).
        assert!(seen.insert(nonce), "repeated nonce inside one stream");
    }
}

#[test]
fn nonce_layout_is_stable_and_spec_owned() {
    // Given: fixed inputs
    // When: deriving the nonce
    let nonce = build_nonce(0x0102, 0x0304_0506, 0x0708_090A, FrameType::Data);
    // Then: id | generation | sequence | type | 0, big-endian, 12 bytes.
    assert_eq!(
        nonce,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x00, 0x00]
    );
    // And: the mux alias cannot drift from the spec.
    assert_eq!(
        nonce,
        build_nonce_for(0x0102, 0x0304_0506, 0x0708_090A, FrameType::Data)
    );
}

#[test]
fn generation_distinguishes_otherwise_identical_frames() {
    // Given: two frame headers identical except for generation
    let a = build_nonce(5, 0, 0, FrameType::OpenTcp);
    let b = build_nonce(5, 1, 0, FrameType::OpenTcp);
    // Then: different nonces, so the recycled-id OPEN encrypts differently.
    assert_ne!(a, b);
}
