//! AetherLink frame codec
//!
//! This crate provides frame encoding/decoding for the AetherLink protocol.
//! Frame format (24-byte header + encrypted payload):
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

pub mod codec;
pub mod types;

use aetherlink_crypto::CryptoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FrameError {
    #[error(
        "Invalid frame length: {0} (max {})",
        aetherlink_crypto::MAX_FRAME_PAYLOAD
    )]
    InvalidLength(usize),

    #[error("Invalid frame type: {0}")]
    InvalidFrameType(u8),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Invalid stream ID: {0}")]
    InvalidStreamId(u16),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Insufficient buffer: need {need}, have {have}")]
    InsufficientBuffer { need: usize, have: usize },

    #[error("Padding error: {0}")]
    PaddingError(String),

    #[error("Replay detected: sequence {seq} for stream {stream_id}")]
    ReplayDetected { stream_id: u16, seq: u32 },
}

pub type Result<T> = std::result::Result<T, FrameError>;

/// Frame header size in bytes (24 bytes)
pub const FRAME_HEADER_SIZE: usize = 24;

/// Maximum frame size including header
pub const MAX_FRAME_SIZE: usize =
    aetherlink_crypto::MAX_FRAME_PAYLOAD + FRAME_HEADER_SIZE + aetherlink_crypto::AEAD_TAG_LEN;
