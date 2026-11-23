//! Frame encoding and decoding
//!
//! Implements the AetherLink frame wire format (protocol v2, 24-byte header):
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |          Length (24-bit)      | Type |  Flags  |   Stream ID
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      (16-bit)      |         Sequence (32-bit)                    |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |          Generation (32-bit)  |     Reserved (9 random bytes)
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                    Encrypted Payload + Tag                     |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `generation` is what keeps the AEAD nonce unique once a stream id is
//! recycled; the reserved tail is fresh random per frame and ignored on read
//! (see [`aetherlink_protocol::build_nonce`]).

use bytes::{Buf, BufMut, BytesMut};

use crate::{FrameError, Result, FRAME_HEADER_SIZE};
use aetherlink_crypto::aead::{self, AeadKey, AeadNonce};
use aetherlink_crypto::{AEAD_NONCE_LEN, AEAD_TAG_LEN, DEFAULT_PAD_MULTIPLE, MAX_FRAME_PAYLOAD};
use aetherlink_protocol::{FrameType, FRAME_HEADER_RANDOM_SIZE};
use rand::RngCore;

/// Frame header (unencrypted, 24 bytes)
///
/// The reserved trailer is deliberately **not** part of the value: it carries
/// no protocol meaning (random anti-fingerprint bytes) and the peer ignores
/// it, so comparing headers by their meaningful fields is the useful
/// comparison. `encode` regenerates a fresh random tail on every call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length (including padding and AEAD tag), 24-bit
    pub length: u32,
    /// Frame type
    pub frame_type: FrameType,
    /// Flags (reserved for future use)
    pub flags: u8,
    /// Stream ID (0 for control frames)
    pub stream_id: u16,
    /// Sequence number
    pub sequence: u32,
    /// Stream generation: bumped every time an id is re-registered after
    /// being closed. Feeds the AEAD nonce, so a recycled id never repeats one.
    pub generation: u32,
}

impl FrameHeader {
    /// Encode header to 24 bytes (11 fields + 4 generation + 9 random).
    ///
    /// The 9 reserved bytes are filled with fresh randomness on every call:
    /// they were constant zero in v1, which made every header trivially
    /// fingerprintable, and every reader ignores them by design.
    pub fn encode(&self, buf: &mut BytesMut) {
        // Length (24-bit, big-endian)
        let len = self.length;
        buf.put_u8((len >> 16) as u8);
        buf.put_u8((len >> 8) as u8);
        buf.put_u8(len as u8);

        // Type (8 bits)
        buf.put_u8(self.frame_type as u8);

        // Flags (8 bits)
        buf.put_u8(self.flags);

        // Stream ID (16 bits, big-endian)
        buf.put_u16(self.stream_id);

        // Sequence (32 bits, big-endian)
        buf.put_u32(self.sequence);

        // Generation (32 bits, big-endian): feeds the AEAD nonce.
        buf.put_u32(self.generation);

        // Reserved (9 random bytes, ignored on read).
        let mut tail = [0u8; FRAME_HEADER_RANDOM_SIZE];
        rand::thread_rng().fill_bytes(&mut tail);
        buf.put_slice(&tail);
    }

    /// Decode header from 24 bytes
    pub fn decode(buf: &mut BytesMut) -> Result<Self> {
        if buf.remaining() < FRAME_HEADER_SIZE {
            return Err(FrameError::InsufficientBuffer {
                need: FRAME_HEADER_SIZE,
                have: buf.remaining(),
            });
        }

        // Length (24-bit)
        let len =
            ((buf.get_u8() as u32) << 16) | ((buf.get_u8() as u32) << 8) | (buf.get_u8() as u32);

        // Type
        let frame_type_u8 = buf.get_u8();
        let frame_type = FrameType::try_from(frame_type_u8)
            .map_err(|_| FrameError::InvalidFrameType(frame_type_u8))?;

        // Flags
        let flags = buf.get_u8();

        // Stream ID (16-bit)
        let stream_id = buf.get_u16();

        // Sequence (32-bit)
        let sequence = buf.get_u32();

        // Generation (32 bits): nonce input, never skipped.
        let generation = buf.get_u32();

        // Reserved (9 random bytes, ignored on read by design)
        buf.advance(FRAME_HEADER_RANDOM_SIZE);

        Ok(Self {
            length: len,
            frame_type,
            flags,
            stream_id,
            sequence,
            generation,
        })
    }
}

/// Associated data for one frame: the header fields that must not change.
///
/// The header travels in clear text and used to be excluded from the AEAD
/// (`aad = &[]`), which made it unauthenticated: `length`, `stream_id`,
/// `sequence`, `flags` and `generation` could be edited in flight and the
/// frame would still decrypt. That is not a theoretical gap — `stream_id`
/// decides which TUN flow the plaintext is injected into, and `generation`
/// is the nonce component DEC-014 exists to protect.
///
/// The layout is the wire layout minus the random tail:
/// `length(3) || type(1) || flags(1) || stream_id(2) || sequence(4) || generation(4)`
///
/// The 9 random bytes are deliberately **not** authenticated: they carry no
/// meaning, and excluding them keeps the AAD a pure function of the fields a
/// decoder has already validated.
#[must_use]
pub fn header_aad(header: &FrameHeader) -> [u8; AAD_HEADER_LEN] {
    let len = header.length;
    [
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        header.frame_type as u8,
        header.flags,
        (header.stream_id >> 8) as u8,
        header.stream_id as u8,
        (header.sequence >> 24) as u8,
        (header.sequence >> 16) as u8,
        (header.sequence >> 8) as u8,
        header.sequence as u8,
        (header.generation >> 24) as u8,
        (header.generation >> 16) as u8,
        (header.generation >> 8) as u8,
        header.generation as u8,
    ]
}

/// Length of [`header_aad`]: every header field except the random tail.
pub const AAD_HEADER_LEN: usize = FRAME_HEADER_SIZE - FRAME_HEADER_RANDOM_SIZE;

/// Complete frame (header + encrypted payload)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub encrypted_payload: Vec<u8>, // Includes AEAD tag
}

impl Frame {
    /// Create a new frame with encrypted payload
    pub fn new(header: FrameHeader, encrypted_payload: Vec<u8>) -> Self {
        Self {
            header,
            encrypted_payload,
        }
    }

    /// Get total frame size (header + encrypted payload)
    pub fn total_size(&self) -> usize {
        FRAME_HEADER_SIZE + self.encrypted_payload.len()
    }

    /// Get payload size (without header)
    pub fn payload_size(&self) -> usize {
        self.encrypted_payload.len()
    }
}

/// Calculate padding needed to align to pad_multiple
fn calculate_padding(plaintext_len: usize, pad_multiple: usize) -> usize {
    if pad_multiple == 0 {
        return 0;
    }
    let remainder = plaintext_len % pad_multiple;
    if remainder == 0 {
        0
    } else {
        pad_multiple - remainder
    }
}

/// Encode a frame: payload -> len-prefix -> pad -> encrypt -> prepend header
pub fn encode_frame(
    frame: &crate::types::Frame,
    key: &AeadKey,
    generation: u32,
    nonce: &AeadNonce,
    pad_multiple: usize,
) -> Result<Vec<u8>> {
    // Serialize frame payload (without encryption)
    let plaintext = frame.serialize_payload();

    // Length-prefix so zero padding is unambiguous on decode:
    // framed = [plaintext_len u32 BE][plaintext]
    let plain_len =
        u32::try_from(plaintext.len()).map_err(|_| FrameError::InvalidLength(plaintext.len()))?;
    let mut framed = Vec::with_capacity(4 + plaintext.len());
    framed.extend_from_slice(&plain_len.to_be_bytes());
    framed.extend_from_slice(&plaintext);

    // Calculate padding over the framed buffer
    let padding_len = calculate_padding(framed.len(), pad_multiple);
    let total_plaintext_len = framed.len() + padding_len;

    // Check max size
    if total_plaintext_len > MAX_FRAME_PAYLOAD {
        return Err(FrameError::InvalidLength(total_plaintext_len));
    }

    // Create padded plaintext
    let mut padded = Vec::with_capacity(total_plaintext_len);
    padded.extend_from_slice(&framed);
    padded.extend(vec![0u8; padding_len]); // Zero padding

    // Build header first: its fields are the AEAD associated data, so the
    // ciphertext commits to `stream_id`/`sequence`/`generation`/`flags`. The
    // length is known here because ChaCha20-Poly1305 appends a fixed tag.
    let header = FrameHeader {
        length: (padded.len() + AEAD_TAG_LEN) as u32,
        frame_type: frame.frame_type,
        flags: frame.flags,
        stream_id: frame.stream_id,
        sequence: frame.sequence,
        generation,
    };
    // Encrypt with the header as AAD (the random tail is excluded).
    let ciphertext = aead::encrypt(*key, *nonce, &padded, &header_aad(&header));

    // Encode header + ciphertext
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + ciphertext.len());
    header.encode(&mut buf);
    buf.extend_from_slice(&ciphertext);

    Ok(buf.to_vec())
}

/// Decode a frame: read header -> decrypt -> verify -> deserialize
pub fn decode_frame(
    data: &[u8],
    key: &AeadKey,
    nonce: &AeadNonce,
) -> Result<(crate::types::Frame, u32)> {
    let mut buf = BytesMut::from(data);

    // Decode header
    let header = FrameHeader::decode(&mut buf)?;

    // Check length
    let ciphertext_len = header.length as usize;
    if buf.remaining() < ciphertext_len {
        return Err(FrameError::InsufficientBuffer {
            need: ciphertext_len,
            have: buf.remaining(),
        });
    }

    // Extract ciphertext
    let ciphertext = buf.split_to(ciphertext_len).to_vec();

    // Decrypt: the header is authenticated, so a flipped `stream_id` or
    // `generation` fails here instead of routing plaintext to another flow.
    let padded = aead::decrypt(*key, *nonce, &ciphertext, &header_aad(&header))?;
    let mut padded_buf = BytesMut::from(padded.as_slice());

    // Strip length prefix: [len u32 BE][payload][zero pad]
    if padded_buf.remaining() < 4 {
        return Err(FrameError::InvalidPacket(
            "missing length prefix".to_string(),
        ));
    }
    let plain_len = padded_buf.get_u32() as usize;
    if padded_buf.remaining() < plain_len {
        return Err(FrameError::InvalidPacket(
            "length prefix exceeds buffer".to_string(),
        ));
    }
    let plain = padded_buf.split_to(plain_len).to_vec();

    // Deserialize exact payload bytes (trailing pad ignored)
    let frame = crate::types::Frame::deserialize_payload(
        header.frame_type,
        &plain,
        header.stream_id,
        header.sequence,
        header.flags,
    )?;

    Ok((frame, header.generation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Frame;

    #[test]
    fn test_frame_header_encode_decode() {
        let header = FrameHeader {
            length: 100,
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 42,
            sequence: 1000,
            generation: 7,
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), FRAME_HEADER_SIZE);

        let decoded = FrameHeader::decode(&mut buf).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_carries_generation_on_the_wire() {
        // Given: a header with a non-zero generation
        let header = FrameHeader {
            length: 9,
            frame_type: FrameType::OpenTcp,
            flags: 0,
            stream_id: 0x0102,
            sequence: 0,
            generation: 0x0A0B_0C0D,
        };
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        // Then: it sits at the documented offset, big-endian.
        assert_eq!(
            &buf[aetherlink_protocol::FRAME_GENERATION_OFFSET
                ..aetherlink_protocol::FRAME_GENERATION_OFFSET
                    + aetherlink_protocol::FRAME_GENERATION_SIZE],
            &[0x0A, 0x0B, 0x0C, 0x0D]
        );
    }

    #[test]
    fn reserved_tail_is_fresh_random_per_frame() {
        // Given: the same header encoded twice
        let header = FrameHeader {
            length: 16,
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id: 0,
            sequence: 0,
            generation: 0,
        };
        let (mut a, mut b) = (BytesMut::new(), BytesMut::new());
        header.encode(&mut a);
        header.encode(&mut b);
        // Then: the reserved tail differs (v1 sent 13 constant zero bytes,
        // which made every header trivially fingerprintable) ...
        let start = FRAME_HEADER_SIZE - FRAME_HEADER_RANDOM_SIZE;
        assert_ne!(
            &a[start..], &b[start..],
            "reserved tail must not be a constant"
        );
        // ... and both still decode to the same meaningful header.
        assert_eq!(
            FrameHeader::decode(&mut a).unwrap(),
            FrameHeader::decode(&mut b).unwrap()
        );
    }

    #[test]
    fn decode_without_generation_would_misparse_the_tail() {
        // Documents why v1 and v2 cannot interoperate: a v1 header puts its
        // first reserved byte where v2 expects generation byte 0.
        let header = FrameHeader {
            length: 1,
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 3,
            sequence: 4,
            generation: 0xDEAD_BEEF,
        };
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        let decoded = FrameHeader::decode(&mut buf).unwrap();
        assert_eq!(decoded.generation, 0xDEAD_BEEF);
        assert_ne!(decoded.generation, 0, "v1 peers would read zeros here");
    }

    #[test]
    fn test_encode_decode_data_frame() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let frame = Frame::data(1, 100, b"test payload".to_vec());

        let encoded = encode_frame(&frame, &key, 0, &nonce, DEFAULT_PAD_MULTIPLE).unwrap();
        let (decoded, _) = decode_frame(&encoded, &key, &nonce).unwrap();

        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.stream_id, 1);
        assert_eq!(decoded.sequence, 100);
        assert_eq!(
            decoded.payload,
            crate::types::FramePayload::Data(b"test payload".to_vec())
        );
    }

    #[test]
    fn test_encode_decode_open_tcp() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let frame = Frame::open_tcp(3, 1, "example.com".to_string(), 443);

        let encoded = encode_frame(&frame, &key, 0, &nonce, DEFAULT_PAD_MULTIPLE).unwrap();
        let (decoded, _) = decode_frame(&encoded, &key, &nonce).unwrap();

        assert_eq!(decoded.frame_type, FrameType::OpenTcp);
        assert_eq!(decoded.stream_id, 3);
    }

    #[test]
    fn test_reject_invalid_length() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Create a frame that's too large
        let large_payload = vec![0u8; MAX_FRAME_PAYLOAD + 100];
        let frame = Frame::data(1, 1, large_payload);

        let result = encode_frame(&frame, &key, 0, &nonce, DEFAULT_PAD_MULTIPLE);
        assert!(result.is_err());
    }
}
