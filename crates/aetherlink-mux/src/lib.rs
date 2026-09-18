//! AetherLink multiplexing layer
//!
//! This crate manages streams (TCP) and flows (UDP) over the AetherLink protocol,
//! including flow control, stream lifecycle, and frame routing.

pub mod dns;
pub mod flow;
pub mod manager;
pub mod stream;

use aetherlink_frame::{FrameError, Result as FrameResult};
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
}

pub type Result<T> = std::result::Result<T, MuxError>;

/// Stream ID allocation: client uses odd, server uses even
pub const CLIENT_STREAM_ID_START: u16 = 1;
pub const SERVER_STREAM_ID_START: u16 = 2;
pub const STREAM_ID_INCREMENT: u16 = 2;
