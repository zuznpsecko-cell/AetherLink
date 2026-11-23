//! Replay-window behaviour of the mux: typed rejections, never silent loss.
//!
//! `MuxManager::open` used to report a duplicate or too-old sequence as
//! `MuxError::Internal("replay seq")` — the same variant it used for genuinely
//! broken state. Callers only log, so the practical effect was a silent skip;
//! but anything inspecting the error could not tell "the peer retransmitted"
//! (normal on a lossy path, drop the frame) from "this stream is corrupt"
//! (tear it down). The window itself also updated its anchor only for
//! in-order frames, which is exactly backwards: an out-of-order frame that is
//! accepted must move the anchor, or a later duplicate looks new again.

use aetherlink_frame::codec::FrameHeader;
use aetherlink_frame::types::Frame;
use aetherlink_mux::manager::{seal_frame_with, MuxManager, SealedFrame};
use aetherlink_mux::MuxError;
use aetherlink_protocol::FrameType;

const KEY: [u8; 32] = [0x5Au8; 32];
const PAD: usize = 128;

/// Seal DATA for `id` at an explicit sequence, bypassing the manager's own
/// counter (these tests need to replay and reorder deliberately).
fn seal_at(id: u16, generation: u32, seq: u32, payload: &[u8]) -> SealedFrame {
    let frame = Frame::data(id, seq, payload.to_vec());
    seal_frame_with(&KEY, id, generation, seq, frame, PAD).expect("seal")
}

/// A manager with one live TCP stream, plus that stream's generation.
fn live_stream() -> (MuxManager, u16, u32) {
    let mut mux = MuxManager::with_max(4);
    let id = mux.open_tcp("93.184.216.34", 443).expect("open");
    let generation = mux
        .seal_open_tcp(&KEY, id, PAD)
        .expect("open frame")
        .header
        .generation;
    (mux, id, generation)
}

#[test]
fn duplicate_sequence_is_a_typed_replay_rejection() {
    let (mut mux, id, generation) = live_stream();
    let frame = seal_at(id, generation, 7, b"once");

    assert!(
        mux.open_data(&KEY, &frame.header, &frame.ciphertext).is_ok(),
        "first arrival is accepted"
    );
    // Same frame again: a normal retransmit on a lossy path.
    let err = mux
        .open_data(&KEY, &frame.header, &frame.ciphertext)
        .expect_err("duplicate must be rejected");
    match err {
        MuxError::ReplayDetected { stream_id, seq } => {
            assert_eq!(stream_id, id);
            assert_eq!(seq, 7);
        }
        other => panic!("expected ReplayDetected, got {other:?}"),
    }

    // And: the stream is still usable — a replay must not poison it.
    let next = seal_at(id, generation, 8, b"next");
    assert!(mux.open_data(&KEY, &next.header, &next.ciphertext).is_ok());
}

#[test]
fn stale_generation_is_reported_separately_from_replay() {
    // Given: a second incarnation of an id, so a strictly older generation
    // exists. The first incarnation starts at 0, so `generation - 1` is only
    // meaningful once the id has been recycled — computing it on a fresh id
    // (as this test first did) just yields the same 0 and asserts nothing.
    let mut mux = MuxManager::with_max(4);
    let id = mux.open_tcp("93.184.216.34", 443).expect("open");
    mux.seal_open_tcp(&KEY, id, PAD).expect("first open frame");
    mux.close(id).expect("close first incarnation");

    // When: the id comes back (here via the inbound path the accept loop
    // uses, which is what re-registers a recycled id in practice)
    mux.register_inbound(id, "93.184.216.34", 443, false)
        .expect("re-register");
    let generation = mux
        .seal_open_tcp(&KEY, id, PAD)
        .expect("open frame of the new incarnation")
        .header
        .generation;
    assert_eq!(generation, 1, "premise: the recycled id advanced");

    // And: a frame sealed under the *previous* incarnation's generation
    let old_generation = generation - 1;
    let frame = seal_at(id, old_generation, 1, b"from the past");
    let err = mux
        .open_data(&KEY, &frame.header, &frame.ciphertext)
        .expect_err("stale incarnation must be rejected");

    // Then: the error names the incarnation mismatch, distinct from a replay.
    match err {
        MuxError::StaleGeneration {
            stream_id,
            got,
            expected,
        } => {
            assert_eq!(stream_id, id);
            assert_eq!(got, old_generation);
            assert_eq!(expected, generation);
        }
        other => panic!("expected StaleGeneration, got {other:?}"),
    }
}

#[test]
fn out_of_order_frame_advances_the_anchor() {
    // Given: seq 1 accepted, then seq 5 (a gap: 2..4 lost)
    let (mut mux, id, generation) = live_stream();
    let one = seal_at(id, generation, 1, b"one");
    assert!(mux.open_data(&KEY, &one.header, &one.ciphertext).is_ok());

    let five = seal_at(id, generation, 5, b"five");
    assert!(mux.open_data(&KEY, &five.header, &five.ciphertext).is_ok());

    // Then: replaying seq 1 is behind the anchor and must be rejected — even
    // though seq 1 itself was accepted long ago.
    let err = mux
        .open_data(&KEY, &one.header, &one.ciphertext)
        .expect_err("seq 1 is behind the anchor");
    assert!(matches!(err, MuxError::ReplayDetected { .. }));

    // And: an in-window gap can still be filled (seq 3 was merely delayed).
    let three = seal_at(id, generation, 3, b"three");
    assert!(
        mux.open_data(&KEY, &three.header, &three.ciphertext).is_ok(),
        "a delayed in-window frame must still be accepted"
    );
    // ... but only once.
    assert!(matches!(
        mux.open_data(&KEY, &three.header, &three.ciphertext),
        Err(MuxError::ReplayDetected { .. })
    ));
}

#[test]
fn sequence_zero_data_frame_is_rejected() {
    // seq 0 is reserved for OPEN; seeing it on DATA means a forged header.
    let (mut mux, id, generation) = live_stream();
    let frame = seal_at(id, generation, 0, b"forged");
    let err = mux
        .open_data(&KEY, &frame.header, &frame.ciphertext)
        .expect_err("seq 0 on DATA must be rejected");
    assert!(
        matches!(err, MuxError::Internal(_)),
        "seq 0 is a protocol violation, not a replay: {err:?}"
    );
}

#[test]
fn header_that_does_not_match_the_ciphertext_fails_authentication() {
    // The header is AEAD associated data now, so a header claiming another
    // generation cannot be decrypted with this ciphertext.
    let (mut mux, id, generation) = live_stream();
    let frame = seal_at(id, generation, 2, b"payload");
    let forged = FrameHeader {
        generation: generation + 1,
        ..frame.header.clone()
    };
    assert!(
        mux.open_data(&KEY, &forged, &frame.ciphertext).is_err(),
        "a header that does not match the sealed ciphertext must fail"
    );
    // And: the honest header still opens the same bytes (nothing was consumed
    // by the failed attempt).
    assert!(mux.open_data(&KEY, &frame.header, &frame.ciphertext).is_ok());
}

/// Regression: a sealed datagram must open on the peer side.
///
/// `seal_datagram` builds the nonce from `entry.next_seq` but seals a
/// `Frame::udp_datagram`, whose constructor hard-codes `sequence: 0`. The two
/// disagreed, which was harmless (and therefore invisible) while the header
/// was unauthenticated — once the header became AAD (DEC-016) the receiver
/// rebuilt a different AAD and every datagram failed with "Authentication
/// failed". This is the coverage that was missing: the old UDP test asserted
/// only that the *pump* emitted two frames, never that a peer could open them.
#[test]
fn sealed_datagram_opens_on_the_peer() {
    // Given: a live UDP flow on the sender, mirrored on the receiver
    let mut sender = MuxManager::with_max(4);
    let id = sender.open_udp("1.1.1.1", 53).expect("open udp");
    sender.seal_open_udp(&KEY, id, PAD).expect("open frame");
    let mut receiver = MuxManager::with_max(4);
    receiver
        .register_inbound(id, "1.1.1.1", 53, true)
        .expect("register");
    // When: the sender seals a payload
    let sealed = sender
        .seal_datagram(&KEY, id, b"dns query", PAD)
        .expect("seal");
    // Then: the peer opens exactly those bytes.
    let payload = receiver
        .open_datagram(&KEY, &sealed.header, &sealed.ciphertext)
        .expect("datagram must authenticate");
    assert_eq!(payload, b"dns query");
}

#[test]
fn sealed_tcp_data_opens_on_the_peer() {
    // Same invariant for the TCP path (DATA frames carried the right sequence
    // already; pin it so a future constructor change cannot regress silently).
    let mut sender = MuxManager::with_max(4);
    let id = sender.open_tcp("93.184.216.34", 443).expect("open tcp");
    sender.seal_open_tcp(&KEY, id, PAD).expect("open frame");
    let mut receiver = MuxManager::with_max(4);
    receiver
        .register_inbound(id, "93.184.216.34", 443, false)
        .expect("register");
    for chunk in [b"first".as_slice(), b"second".as_slice()] {
        let sealed = sender.seal_data(&KEY, id, chunk, PAD).expect("seal");
        let payload = receiver
            .open_data(&KEY, &sealed.header, &sealed.ciphertext)
            .expect("data must authenticate");
        assert_eq!(payload, chunk);
    }
}

#[test]
fn unexpected_frame_type_is_not_a_replay() {
    let (mut mux, id, generation) = live_stream();
    let frame = seal_at(id, generation, 3, b"data");
    let mut wrong_type = frame.header.clone();
    wrong_type.frame_type = FrameType::UdpDatagram;
    assert!(
        mux.open_data(&KEY, &wrong_type, &frame.ciphertext).is_err(),
        "a DATA stream must not accept a DATAGRAM frame"
    );
}
