//! AetherLink multiplexing layer
//!
//! This crate manages streams (TCP) and flows (UDP) over the AetherLink protocol,
//! including flow control, stream lifecycle, and frame routing.

pub mod dns;
pub mod flow;
pub mod manager;
pub mod stream;

use aetherlink_frame::FrameError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MuxError {
    #[error("Stream not found: {0}")]
    StreamNotFound(u16),

    #[error("Flow not found: {0}")]
    FlowNotFound(u16),

    #[error("Stream already closed: {0}")]
    StreamClosed(u16),

    #[error("Flow already closed: {0}")]
    FlowClosed(u16),

    #[error("Window exhausted for stream {0}")]
    WindowExhausted(u16),

    #[error("Invalid stream ID: {0} (client streams must be odd, server even)")]
    InvalidStreamId(u16),

    #[error("Frame error: {0}")]
    Frame(#[from] FrameError),

    #[error("Internal error: {0}")]
    Internal(String),

    /// A stream id recycled through the whole 32-bit generation space.
    ///
    /// Wrapping here would repeat an AEAD nonce under the live traffic key,
    /// so the manager refuses instead. Reaching this needs 4 billion
    /// re-incarnations of a single id in one session: rekey and reconnect.
    #[error("Nonce space exhausted for stream id: rekey required")]
    NonceSpaceExhausted,

    /// A frame was rejected by the replay window: duplicate or outside it.
    ///
    /// This is a *normal* event on a live tunnel (the peer retransmits after
    /// loss, and UDP duplicates arrive), so callers drop the frame and keep
    /// the flow. It is a distinct variant precisely so it is never confused
    /// with [`MuxError::Internal`], which means the stream state is broken.
    #[error("Replayed frame on stream {stream_id}: seq {seq}")]
    ReplayDetected { stream_id: u16, seq: u32 },

    /// The peer sent a frame for a different incarnation of this stream id.
    ///
    /// Late arrival from a previous life of a recycled id, or a peer that
    /// re-opened the id before this side registered it. Drop the frame.
    #[error("Stale generation on stream {stream_id}: {got} != {expected}")]
    StaleGeneration {
        stream_id: u16,
        got: u32,
        expected: u32,
    },
}

pub type Result<T> = std::result::Result<T, MuxError>;

/// Stream ID allocation: client uses odd, server uses even
pub const CLIENT_STREAM_ID_START: u16 = 1;
pub const SERVER_STREAM_ID_START: u16 = 2;
pub const STREAM_ID_INCREMENT: u16 = 2;
