//! Frame encoding and decoding
//!
//! Implements the AetherLink frame wire format:
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |          Length (24-bit)      | Type |  Flags  |   Stream ID   
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      (16-bit)      |         Sequence (32-bit)                    |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                    Encrypted Payload + Tag                     |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use bytes::{Buf, BufMut, BytesMut};

use crate::{FrameError, Result, FRAME_HEADER_SIZE};
use aetherlink_crypto::aead::{self, AeadKey, AeadNonce};
use aetherlink_crypto::{AEAD_NONCE_LEN, AEAD_TAG_LEN, DEFAULT_PAD_MULTIPLE, MAX_FRAME_PAYLOAD};
use aetherlink_protocol::FrameType;

/// Frame header (unencrypted, 24 bytes)
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
}

impl FrameHeader {
    /// Encode header to 24 bytes (11 used + 13 reserved zeros).
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

        // Reserved (13 bytes, must be zero)
        buf.put_bytes(0, FRAME_HEADER_SIZE - 11);
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

        // Reserved (13 bytes, ignored on read for forward compat)
        buf.advance(FRAME_HEADER_SIZE - 11);

        Ok(Self {
            length: len,
            frame_type,
            flags,
            stream_id,
            sequence,
        })
    }
}

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

    // Encrypt with AEAD (no AAD for frames - header is not authenticated)
    let ciphertext = aead::encrypt(*key, *nonce, &padded, &[]);

    // Build header
    let header = FrameHeader {
        length: ciphertext.len() as u32, // Includes AEAD tag
        frame_type: frame.frame_type,
        flags: frame.flags,
        stream_id: frame.stream_id,
        sequence: frame.sequence,
    };

    // Encode header + ciphertext
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + ciphertext.len());
    header.encode(&mut buf);
    buf.extend_from_slice(&ciphertext);

    Ok(buf.to_vec())
}

/// Decode a frame: read header -> decrypt -> verify -> deserialize
pub fn decode_frame(data: &[u8], key: &AeadKey, nonce: &AeadNonce) -> Result<crate::types::Frame> {
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

    // Decrypt
    let padded = aead::decrypt(*key, *nonce, &ciphertext, &[])?;
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

    Ok(frame)
}

/// Anti-replay protection for incoming frames
///
/// Tracks sequence numbers per stream and rejects duplicates/out-of-order.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    /// Highest sequence number seen per stream
    highest_seq: std::collections::HashMap<u16, u32>,
    /// Bitmap of recent sequences (for out-of-order detection)
    bitmaps: std::collections::HashMap<u16, u64>,
    /// Window size (power of 2, e.g., 1024)
    window_size: u32,
}

impl ReplayWindow {
    pub fn new(window_size: u32) -> Self {
        assert!(
            window_size.is_power_of_two(),
            "Window size must be power of 2"
        );
        Self {
            highest_seq: std::collections::HashMap::new(),
            bitmaps: std::collections::HashMap::new(),
            window_size,
        }
    }

    /// Check and record a sequence number for a stream
    ///
    /// Returns Ok(()) if sequence is acceptable (new and within window),
    /// Err(FrameError::ReplayDetected) if duplicate or too old.
    pub fn check(&mut self, stream_id: u16, sequence: u32) -> Result<()> {
        let highest = self.highest_seq.entry(stream_id).or_insert(0);
        let bitmap = self.bitmaps.entry(stream_id).or_insert(0);

        if sequence > *highest {
            // New highest sequence
            let advance = sequence - *highest;
            if advance < 64 {
                *bitmap <<= advance;
            } else {
                *bitmap = 0;
            }
            *bitmap |= 1; // Mark current sequence as seen
            *highest = sequence;
            Ok(())
        } else if sequence == *highest {
            // Duplicate of highest
            Err(FrameError::ReplayDetected {
                stream_id,
                seq: sequence,
            })
        } else {
            // Out of order - check if within window.
            // Bit 0 is the highest seq; bit N is highest-N.
            let diff = *highest - sequence;
            // u64 bitmap tracks 64 back; anything older is unverifiable.
            if diff >= self.window_size || diff >= 64 {
                // Too old
                return Err(FrameError::ReplayDetected {
                    stream_id,
                    seq: sequence,
                });
            }
            let bit_pos = diff;
            if (*bitmap >> bit_pos) & 1 == 1 {
                // Already seen
                return Err(FrameError::ReplayDetected {
                    stream_id,
                    seq: sequence,
                });
            }
            // Mark as seen
            *bitmap |= 1 << bit_pos;
            Ok(())
        }
    }

    /// Get current highest sequence for a stream
    pub fn highest(&self, stream_id: u16) -> Option<u32> {
        self.highest_seq.get(&stream_id).copied()
    }

    /// Reset window for a stream (e.g., on stream close)
    pub fn reset_stream(&mut self, stream_id: u16) {
        self.highest_seq.remove(&stream_id);
        self.bitmaps.remove(&stream_id);
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new(1024) // Default anti-replay window ≥ 1024
    }
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
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), FRAME_HEADER_SIZE);

        let decoded = FrameHeader::decode(&mut buf).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_encode_decode_data_frame() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let frame = Frame::data(1, 100, b"test payload".to_vec());

        let encoded = encode_frame(&frame, &key, &nonce, DEFAULT_PAD_MULTIPLE).unwrap();
        let decoded = decode_frame(&encoded, &key, &nonce).unwrap();

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

        let encoded = encode_frame(&frame, &key, &nonce, DEFAULT_PAD_MULTIPLE).unwrap();
        let decoded = decode_frame(&encoded, &key, &nonce).unwrap();

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

        let result = encode_frame(&frame, &key, &nonce, DEFAULT_PAD_MULTIPLE);
        assert!(result.is_err());
    }

    #[test]
    fn test_replay_window_basic() {
        let mut window = ReplayWindow::new(1024);

        // First sequence should be accepted
        assert!(window.check(1, 100).is_ok());

        // Duplicate should be rejected
        assert!(window.check(1, 100).is_err());

        // Higher sequence should be accepted
        assert!(window.check(1, 101).is_ok());

        // Out of order but within window should be accepted
        assert!(window.check(1, 99).is_ok()); // 101 - 99 = 2 < 1024

        // Duplicate of out-of-order should be rejected
        assert!(window.check(1, 99).is_err());
    }

    #[test]
    fn test_replay_window_too_old() {
        let mut window = ReplayWindow::new(1024);

        assert!(window.check(1, 1000).is_ok());

        // Too old (diff >= 1024)
        assert!(window.check(1, 500).is_err());
    }

    #[test]
    fn test_replay_window_per_stream() {
        let mut window = ReplayWindow::new(1024);

        assert!(window.check(1, 100).is_ok());
        assert!(window.check(2, 100).is_ok()); // Different stream, same sequence OK

        assert!(window.check(1, 100).is_err()); // Stream 1 duplicate
        assert!(window.check(2, 100).is_err()); // Stream 2 duplicate
    }
}
