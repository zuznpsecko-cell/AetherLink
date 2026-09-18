//! Mux manager: owns TCP streams and UDP flows, seals/opens frames.
//!
//! Ids are client-odd (1, 3, 5, …) shared across streams and flows.
//! Nonce12 = stream(u16 BE) || seq(u32 BE) || type(u8), rest zero —
//! unique per (id, seq, type) under one traffic key.

use std::collections::{HashMap, HashSet};

use aetherlink_crypto::aead::AeadKey;
use aetherlink_frame::codec::{self, FrameHeader};
use aetherlink_frame::types::{Frame, FramePayload};
use aetherlink_frame::FRAME_HEADER_SIZE;
use aetherlink_protocol::FrameType;

use crate::flow;
use crate::stream;
use crate::{MuxError, Result};

/// Anti-replay window per id (FIXED >= 1024).
pub const REPLAY_WINDOW: u32 = 1024;

/// Sealed frame ready for transport.
#[derive(Debug, Clone)]
pub struct SealedFrame {
    /// Header (`length` == `ciphertext.len()`).
    pub header: FrameHeader,
    /// Ciphertext (padded payload + tag).
    pub ciphertext: Vec<u8>,
}

/// Dial target of a stream/flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Destination address.
    pub addr: String,
    /// Destination port.
    pub port: u16,
}

struct Entry {
    is_udp: bool,
    addr: String,
    port: u16,
    next_seq: u32,
    max_seen: u32,
    seen: HashSet<u32>,
}

/// Session manager: TCP streams + UDP flows.
pub struct MuxManager {
    /// Next client id (odd).
    next_id: u16,
    /// Max concurrent streams+flows.
    max: usize,
    entries: HashMap<u16, Entry>,
}

/// Derive AEAD nonce from (id, seq, type). No allocation.
#[must_use]
pub fn build_nonce(id: u16, seq: u32, frame_type: FrameType) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..2].copy_from_slice(&id.to_be_bytes());
    n[2..6].copy_from_slice(&seq.to_be_bytes());
    n[6] = frame_type as u8;
    n
}

fn to_key(key: &[u8]) -> Result<AeadKey> {
    if key.len() != 32 {
        return Err(MuxError::Internal("bad key length".to_string()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(key);
    Ok(k)
}

impl MuxManager {
    /// Create with default max (4096).
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: crate::CLIENT_STREAM_ID_START,
            max: 4096,
            entries: HashMap::new(),
        }
    }

    /// Create with explicit max (tests / `max_streams`).
    #[must_use]
    pub fn with_max(max: usize) -> Self {
        Self {
            next_id: crate::CLIENT_STREAM_ID_START,
            max,
            entries: HashMap::new(),
        }
    }

    fn alloc_id(&mut self) -> Result<u16> {
        if self.entries.len() >= self.max {
            return Err(MuxError::Internal("too many streams".to_string()));
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(crate::STREAM_ID_INCREMENT);
        if self.next_id == 0 {
            self.next_id = crate::CLIENT_STREAM_ID_START;
        }
        Ok(id)
    }

    /// Open TCP stream, returns odd client id.
    pub fn open_tcp(&mut self, addr: &str, port: u16) -> Result<u16> {
        stream::validate_target(addr, port).map_err(|e| MuxError::Internal(e.to_string()))?;
        let id = self.alloc_id()?;
        self.entries.insert(
            id,
            Entry {
                is_udp: false,
                addr: addr.to_string(),
                port,
                next_seq: 1,
                max_seen: 0,
                seen: HashSet::new(),
            },
        );
        Ok(id)
    }

    /// Open UDP flow, returns odd client id.
    pub fn open_udp(&mut self, addr: &str, port: u16) -> Result<u16> {
        flow::validate_target(addr, port).map_err(|e| MuxError::Internal(e.to_string()))?;
        let id = self.alloc_id()?;
        self.entries.insert(
            id,
            Entry {
                is_udp: true,
                addr: addr.to_string(),
                port,
                next_seq: 1,
                max_seen: 0,
                seen: HashSet::new(),
            },
        );
        Ok(id)
    }

    /// Stream/flow open predicate.
    #[must_use]
    pub fn is_open(&self, id: u16) -> bool {
        self.entries.contains_key(&id)
    }

    /// Register an inbound id announced by the peer (server side).
    ///
    /// Cross-side OPEN negotiation (learning the target from an OPEN frame)
    /// belongs to the accept-loop; this call only books the id so DATA and
    /// datagrams for it pass replay checks. Idempotent: re-registering an
    /// existing id is a no-op.
    pub fn register_inbound(&mut self, id: u16, addr: &str, port: u16, is_udp: bool) -> Result<()> {
        if self.entries.contains_key(&id) {
            return Ok(());
        }
        if self.entries.len() >= self.max {
            return Err(MuxError::Internal("too many streams".to_string()));
        }
        if is_udp {
            flow::validate_target(addr, port).map_err(|e| MuxError::Internal(e.to_string()))?;
        } else {
            stream::validate_target(addr, port).map_err(|e| MuxError::Internal(e.to_string()))?;
        }
        self.entries.insert(
            id,
            Entry {
                is_udp,
                addr: addr.to_string(),
                port,
                next_seq: 1,
                max_seen: 0,
                seen: HashSet::new(),
            },
        );
        Ok(())
    }

    /// Dial target of an open id.
    #[must_use]
    pub fn target(&self, id: u16) -> Option<Endpoint> {
        self.entries.get(&id).map(|e| Endpoint {
            addr: e.addr.clone(),
            port: e.port,
        })
    }

    /// Close (RST semantics): further seal/open fail.
    pub fn close(&mut self, id: u16) -> Result<()> {
        self.entries
            .remove(&id)
            .map(|_| ())
            .ok_or(MuxError::StreamNotFound(id))
    }

    fn seal(
        &mut self,
        key: &[u8],
        id: u16,
        frame_type: FrameType,
        frame: Frame,
        pad_multiple: usize,
    ) -> Result<SealedFrame> {
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(MuxError::StreamClosed(id))?;
        if entry.is_udp != (frame_type == FrameType::UdpDatagram) {
            return Err(MuxError::StreamClosed(id));
        }
        let seq = entry.next_seq;
        entry.next_seq = entry.next_seq.wrapping_add(1);
        if entry.next_seq == 0 {
            entry.next_seq = 1;
        }
        let k = to_key(key)?;
        let nonce = build_nonce(id, seq, frame_type);
        let wire = codec::encode_frame(&frame, &k, &nonce, pad_multiple)
            .map_err(|e| MuxError::Internal(e.to_string()))?;
        // Split wire back into header + ciphertext for the caller.
        let header = FrameHeader {
            length: (wire.len() - FRAME_HEADER_SIZE) as u32,
            frame_type,
            flags: 0,
            stream_id: id,
            sequence: seq,
        };
        let ciphertext = wire[FRAME_HEADER_SIZE..].to_vec();
        Ok(SealedFrame { header, ciphertext })
    }

    /// Seal DATA chunk for a TCP stream.
    pub fn seal_data(
        &mut self,
        key: &[u8],
        id: u16,
        plaintext: &[u8],
        pad_multiple: usize,
    ) -> Result<SealedFrame> {
        // Peek next seq without borrowing across the frame build.
        let seq = self
            .entries
            .get(&id)
            .ok_or(MuxError::StreamClosed(id))
            .and_then(|e| {
                if e.is_udp {
                    Err(MuxError::StreamClosed(id))
                } else {
                    Ok(e.next_seq)
                }
            })?;
        let frame = Frame::data(id, seq, plaintext.to_vec());
        self.seal(key, id, FrameType::Data, frame, pad_multiple)
    }

    /// Seal datagram for a UDP flow (payload transparent, e.g. DNS).
    pub fn seal_datagram(
        &mut self,
        key: &[u8],
        id: u16,
        payload: &[u8],
        pad_multiple: usize,
    ) -> Result<SealedFrame> {
        let seq = self
            .entries
            .get(&id)
            .ok_or(MuxError::FlowClosed(id))
            .and_then(|e| {
                if e.is_udp {
                    Ok(e.next_seq)
                } else {
                    Err(MuxError::FlowClosed(id))
                }
            })?;
        let frame = Frame::udp_datagram(id, payload.to_vec());
        let _ = seq;
        self.seal(key, id, FrameType::UdpDatagram, frame, pad_multiple)
    }

    fn open(
        &mut self,
        key: &[u8],
        header: &FrameHeader,
        ciphertext: &[u8],
        expect: FrameType,
    ) -> Result<Vec<u8>> {
        if header.frame_type != expect {
            return Err(MuxError::Internal("wrong frame type".to_string()));
        }
        if header.length as usize != ciphertext.len() {
            return Err(MuxError::Internal("length mismatch".to_string()));
        }
        let entry = self
            .entries
            .get_mut(&header.stream_id)
            .ok_or(MuxError::StreamClosed(header.stream_id))?;
        if entry.is_udp != (expect == FrameType::UdpDatagram) {
            return Err(MuxError::StreamClosed(header.stream_id));
        }
        let seq = header.sequence;
        if seq == 0 {
            return Err(MuxError::Internal("stale seq".to_string()));
        }
        if entry.seen.contains(&seq) {
            return Err(MuxError::Internal("replay seq".to_string()));
        }
        if seq <= entry.max_seen && entry.max_seen - seq >= REPLAY_WINDOW {
            return Err(MuxError::Internal("stale seq".to_string()));
        }
        let k = to_key(key)?;
        let nonce = build_nonce(header.stream_id, seq, expect);
        let mut wire = Vec::with_capacity(FRAME_HEADER_SIZE + ciphertext.len());
        {
            use bytes::BufMut;
            let mut hb = bytes::BytesMut::new();
            header.encode(&mut hb);
            wire.extend_from_slice(&hb);
        }
        wire.extend_from_slice(ciphertext);
        let frame = codec::decode_frame(&wire, &k, &nonce)
            .map_err(|e| MuxError::Internal(e.to_string()))?;
        let payload = match frame.payload {
            FramePayload::Data(v) if expect == FrameType::Data => v,
            FramePayload::UdpDatagram(v) if expect == FrameType::UdpDatagram => v,
            _ => return Err(MuxError::Internal("wrong payload".to_string())),
        };
        if seq > entry.max_seen {
            entry.max_seen = seq;
        }
        entry.seen.insert(seq);
        if entry.seen.len() > (REPLAY_WINDOW as usize) * 2 {
            let min_keep = entry.max_seen.saturating_sub(REPLAY_WINDOW);
            entry.seen.retain(|s| *s >= min_keep);
        }
        Ok(payload)
    }

    /// Open + replay-check DATA frame.
    pub fn open_data(
        &mut self,
        key: &[u8],
        header: &FrameHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.open(key, header, ciphertext, FrameType::Data)
    }

    /// Open + replay-check datagram frame.
    pub fn open_datagram(
        &mut self,
        key: &[u8],
        header: &FrameHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.open(key, header, ciphertext, FrameType::UdpDatagram)
    }
}

impl Default for MuxManager {
    fn default() -> Self {
        Self::new()
    }
}
