//! Mux manager: owns TCP streams and UDP flows, seals/opens frames.
//!
//! Ids are client-odd (1, 3, 5, …) shared across streams and flows.
//! Nonce12 = id(u16 BE) || generation(u32 BE) || seq(u32 BE) || type(u8) ||
//! zero — see [`aetherlink_protocol::build_nonce`], which owns the layout.
//!
//! Why `generation`: ids are recycled, so `(id, seq, type)` alone repeats
//! once a session outlives the 16-bit id space — and the OPEN frame always
//! uses `seq = 0`, so the first duplicate is `(id, 0, OpenTcp)` with the
//! target host/port inside. Repeating an AEAD nonce under one key leaks the
//! keystream and forges Poly1305 tags. `generation` is incremented for an id
//! every time it is re-registered after being closed (`open_tcp`/`open_udp`
//! through `claim_generation`, and [`MuxManager::register_inbound`]), which
//! makes the nonce strictly monotonic per `(id, direction)` for the whole
//! session.

use std::collections::{HashMap, HashSet};

use aetherlink_crypto::aead::AeadKey;
use aetherlink_frame::codec::{self, FrameHeader};
use aetherlink_frame::types::{Frame, FramePayload};
use aetherlink_frame::FRAME_HEADER_SIZE;
use aetherlink_protocol::{build_nonce, FrameType, MAX_STREAM_GENERATION};

use crate::flow::{self, UdpFlow};
use crate::stream::{self, TcpStream};
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
    /// Nonce generation of the live incarnation of this id. Monotonic per
    /// `(id, direction)` for the whole session, so a recycled id can never
    /// repeat a `(generation, sequence)` pair under one traffic key.
    generation: u32,
}

/// Session manager: TCP streams + UDP flows.
pub struct MuxManager {
    /// Next client id (odd).
    next_id: u16,
    /// Max concurrent streams+flows.
    max: usize,
    entries: HashMap<u16, Entry>,
    /// Highest generation ever used for an id, kept after the id closes.
    ///
    /// This is the tombstone that survives recycling: `alloc_id` may hand an
    /// old id out again, but `claim_generation` then starts the new
    /// incarnation at `last_generation[id] + 1`, never at 0. Bounded by the
    /// 16-bit id space, so it cannot outgrow `entries`' possible key set.
    last_generation: HashMap<u16, u32>,
}

/// Derive AEAD nonce from (id, generation, seq, type). No allocation.
///
/// Thin alias for [`aetherlink_protocol::build_nonce`]: the layout lives in
/// the spec crate so both peers cannot drift apart.
#[must_use]
pub fn build_nonce_for(id: u16, generation: u32, seq: u32, frame_type: FrameType) -> [u8; 12] {
    build_nonce(id, generation, seq, frame_type)
}

/// Seal one frame with an explicit `(id, generation, sequence)`.
///
/// Test/embedding helper: it lets a test produce a frame belonging to a
/// *specific* incarnation of an id (including a stale or future one) without
/// owning a manager that holds that state. Production paths always go through
/// [`MuxManager`], which derives the generation from its own bookkeeping.
///
/// # Errors
/// Bad key length, or a payload/length the codec rejects.
///
/// `seq` is authoritative: it is stamped into the sealed frame, so the
/// caller's `Frame::sequence` cannot disagree with the AEAD AAD.
pub fn seal_frame_with(
    key: &[u8],
    id: u16,
    generation: u32,
    seq: u32,
    frame: Frame,
    pad_multiple: usize,
) -> Result<SealedFrame> {
    let frame_type = frame.frame_type;
    // The sealed frame must carry the sequence the nonce was built from,
    // because that sequence is authenticated (DEC-016 AAD).
    let mut frame = frame;
    frame.sequence = seq;
    let k = to_key(key)?;
    let nonce = build_nonce(id, generation, seq, frame_type);
    let wire = codec::encode_frame(&frame, &k, generation, &nonce, pad_multiple)
        .map_err(|e| MuxError::Internal(e.to_string()))?;
    let header = FrameHeader {
        length: (wire.len() - FRAME_HEADER_SIZE) as u32,
        frame_type,
        flags: frame.flags,
        stream_id: id,
        sequence: seq,
        generation,
    };
    Ok(SealedFrame {
        header,
        ciphertext: wire[FRAME_HEADER_SIZE..].to_vec(),
    })
}

/// Next generation for a recycled id: `last + 1`, or a hard error once the
/// 32-bit space is spent (wrapping would repeat a nonce — fail closed).
fn next_generation(last: Option<u32>) -> Result<u32> {
    match last {
        None => Ok(0),
        Some(prev) if prev < MAX_STREAM_GENERATION => Ok(prev + 1),
        Some(_) => Err(MuxError::NonceSpaceExhausted),
    }
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
            last_generation: HashMap::new(),
        }
    }

    /// Create with explicit max (tests / `max_streams`).
    #[must_use]
    pub fn with_max(max: usize) -> Self {
        Self {
            next_id: crate::CLIENT_STREAM_ID_START,
            max,
            entries: HashMap::new(),
            last_generation: HashMap::new(),
        }
    }

    /// Override the concurrent stream/flow limit.
    ///
    /// The manager is constructed before the caller knows its configured
    /// `max_streams` (the session handshake creates it), so the limit is
    /// applied once the config is in scope. Lowering it below the number of
    /// live entries is allowed and only affects new allocations.
    pub fn set_max(&mut self, max: usize) {
        self.max = max;
    }

    /// Configured concurrent stream/flow limit.
    #[must_use]
    pub fn max(&self) -> usize {
        self.max
    }

    /// Next free id. Ids are recycled once a stream closes (a session
    /// outlives thousands of connections), so the cursor skips ids that
    /// are still in use: handing a live id out twice would mix two flows
    /// into one replay window and one route.
    fn alloc_id(&mut self) -> Result<u16> {
        if self.entries.len() >= self.max {
            return Err(MuxError::Internal("too many streams".to_string()));
        }
        for _ in 0..self.max {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(crate::STREAM_ID_INCREMENT);
            if self.next_id == 0 {
                self.next_id = crate::CLIENT_STREAM_ID_START;
            }
            if !self.entries.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(MuxError::Internal("no free stream id".to_string()))
    }

    /// Open TCP stream, returns odd client id.
    pub fn open_tcp(&mut self, addr: &str, port: u16) -> Result<u16> {
        stream::validate_target(addr, port).map_err(|e| MuxError::Internal(e.to_string()))?;
        let id = self.alloc_id()?;
        let generation = self.claim_generation(id)?;
        self.entries.insert(
            id,
            Entry {
                is_udp: false,
                addr: addr.to_string(),
                port,
                next_seq: 1,
                max_seen: 0,
                seen: HashSet::new(),
                generation,
            },
        );
        Ok(id)
    }

    /// Open UDP flow, returns odd client id.
    pub fn open_udp(&mut self, addr: &str, port: u16) -> Result<u16> {
        flow::validate_target(addr, port).map_err(|e| MuxError::Internal(e.to_string()))?;
        let id = self.alloc_id()?;
        let generation = self.claim_generation(id)?;
        self.entries.insert(
            id,
            Entry {
                is_udp: true,
                addr: addr.to_string(),
                port,
                next_seq: 1,
                max_seen: 0,
                seen: HashSet::new(),
                generation,
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
    ///
    /// A recycled id gets the next generation and keeps a per-incarnation
    /// replay window: it tracks `header.generation` from the peer and refuses
    /// frames from an older incarnation instead of decrypting them under the
    /// new one's nonce space.
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
        let generation = self.claim_generation(id)?;
        self.entries.insert(
            id,
            Entry {
                is_udp,
                addr: addr.to_string(),
                port,
                next_seq: 1,
                max_seen: 0,
                seen: HashSet::new(),
                generation,
            },
        );
        Ok(())
    }

    /// Reserve the next nonce generation for `id`.
    ///
    /// Called on every fresh incarnation of an id (locally opened or inbound).
    /// The returned value is folded into the AEAD nonce, so it must advance
    /// monotonically for the lifetime of the session even though the id
    /// itself is recycled.
    fn claim_generation(&mut self, id: u16) -> Result<u32> {
        let generation = next_generation(self.last_generation.get(&id).copied())?;
        self.last_generation.insert(id, generation);
        Ok(generation)
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

    /// Live incarnation generation for `id`, if it is open.
    ///
    /// The accept-loop decodes an unauthenticated OPEN header before it has
    /// any mux state, so it uses this to tell a *retransmitted* OPEN (same
    /// generation: keep the live flow and its replay window) from a genuine
    /// recycle (newer generation: reset and re-dial).
    #[must_use]
    pub fn generation(&self, id: u16) -> Option<u32> {
        self.entries.get(&id).map(|e| e.generation)
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
        let generation = entry.generation;
        // The header sequence must travel *inside* the sealed frame too: it is
        // AEAD associated data (DEC-016), so a `Frame` carrying a different
        // `sequence` than the nonce would make the receiver rebuild a
        // different AAD and fail authentication. `Frame::udp_datagram` sets
        // `sequence: 0` while the nonce uses `next_seq`; that mismatch was
        // invisible only while the header was unauthenticated.
        let mut frame = frame;
        frame.sequence = seq;
        let k = to_key(key)?;
        let nonce = build_nonce(id, generation, seq, frame_type);
        let wire = codec::encode_frame(&frame, &k, generation, &nonce, pad_multiple)
            .map_err(|e| MuxError::Internal(e.to_string()))?;
        // Split wire back into header + ciphertext for the caller.
        let header = FrameHeader {
            length: (wire.len() - FRAME_HEADER_SIZE) as u32,
            frame_type,
            flags: 0,
            stream_id: id,
            sequence: seq,
            generation,
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

    /// Seal an OPEN frame: same wire path as `seal`, but fixed seq 0 with a
    /// type-distinct nonce, so DATA sequencing is untouched.
    fn seal_open(
        &self,
        key: &[u8],
        id: u16,
        frame_type: FrameType,
        frame: Frame,
        pad_multiple: usize,
    ) -> Result<SealedFrame> {
        let entry = self.entries.get(&id).ok_or(MuxError::StreamClosed(id))?;
        if entry.is_udp != (frame_type == FrameType::OpenUdp) {
            return Err(MuxError::StreamClosed(id));
        }
        let generation = entry.generation;
        let k = to_key(key)?;
        // OPEN always uses seq 0, so `generation` is what keeps this nonce
        // unique when the peer recycles the id (the v1 hole). The frame must
        // agree: `Frame::open_udp` sets 0 too, but stamp it so the AAD can
        // never drift from the nonce.
        let mut frame = frame;
        frame.sequence = 0;
        let nonce = build_nonce(id, generation, 0, frame_type);
        let wire = codec::encode_frame(&frame, &k, generation, &nonce, pad_multiple)
            .map_err(|e| MuxError::Internal(e.to_string()))?;
        let header = FrameHeader {
            length: (wire.len() - FRAME_HEADER_SIZE) as u32,
            frame_type,
            flags: 0,
            stream_id: id,
            sequence: 0,
            generation,
        };
        let ciphertext = wire[FRAME_HEADER_SIZE..].to_vec();
        Ok(SealedFrame { header, ciphertext })
    }

    /// Seal OPEN_TCP announcing this stream's dial target to the peer.
    pub fn seal_open_tcp(
        &mut self,
        key: &[u8],
        id: u16,
        pad_multiple: usize,
    ) -> Result<SealedFrame> {
        let (addr, port) = self
            .entries
            .get(&id)
            .ok_or(MuxError::StreamClosed(id))
            .and_then(|e| {
                if e.is_udp {
                    Err(MuxError::StreamClosed(id))
                } else {
                    Ok((e.addr.clone(), e.port))
                }
            })?;
        let frame = Frame::open_tcp(id, 0, addr, port);
        self.seal_open(key, id, FrameType::OpenTcp, frame, pad_multiple)
    }

    /// Seal OPEN_UDP announcing this flow's target to the peer.
    pub fn seal_open_udp(
        &mut self,
        key: &[u8],
        id: u16,
        pad_multiple: usize,
    ) -> Result<SealedFrame> {
        let (addr, port) = self
            .entries
            .get(&id)
            .ok_or(MuxError::FlowClosed(id))
            .and_then(|e| {
                if e.is_udp {
                    Ok((e.addr.clone(), e.port))
                } else {
                    Err(MuxError::FlowClosed(id))
                }
            })?;
        let frame = Frame::open_udp(id, addr, port);
        self.seal_open(key, id, FrameType::OpenUdp, frame, pad_multiple)
    }

    /// Parse a peer's OPEN_TCP into a dial descriptor (no state touched).
    ///
    /// Enforces seq 0: the opener sends exactly one OPEN per id; anything
    /// else is a replay or a confused peer — fail closed.
    pub fn parse_open_tcp(
        key: &[u8],
        header: &FrameHeader,
        ciphertext: &[u8],
    ) -> Result<TcpStream> {
        let frame = Self::open_frame(key, header, ciphertext, FrameType::OpenTcp)?;
        match frame.payload {
            FramePayload::OpenTcp { addr, port, .. } => Ok(TcpStream {
                id: header.stream_id,
                addr,
                port,
            }),
            _ => Err(MuxError::Internal("wrong payload".to_string())),
        }
    }

    /// Parse a peer's OPEN_UDP into a dial descriptor (no state touched).
    pub fn parse_open_udp(key: &[u8], header: &FrameHeader, ciphertext: &[u8]) -> Result<UdpFlow> {
        let frame = Self::open_frame(key, header, ciphertext, FrameType::OpenUdp)?;
        match frame.payload {
            FramePayload::OpenUdp { addr, port, .. } => Ok(UdpFlow {
                id: header.stream_id,
                addr,
                port,
            }),
            _ => Err(MuxError::Internal("wrong payload".to_string())),
        }
    }

    /// Shared OPEN decode: type + length + seq-0 checks, then AEAD open.
    fn open_frame(
        key: &[u8],
        header: &FrameHeader,
        ciphertext: &[u8],
        expect: FrameType,
    ) -> Result<Frame> {
        if header.frame_type != expect {
            return Err(MuxError::Internal("wrong frame type".to_string()));
        }
        if header.length as usize != ciphertext.len() {
            return Err(MuxError::Internal("length mismatch".to_string()));
        }
        if header.sequence != 0 {
            return Err(MuxError::Internal("open must be seq 0".to_string()));
        }
        let k = to_key(key)?;
        // The sender's generation rides in the header, so the OPEN nonce is
        // rebuilt from it — this is what makes a re-opened id decryptable.
        let nonce = build_nonce(header.stream_id, header.generation, 0, expect);
        let mut wire = Vec::with_capacity(FRAME_HEADER_SIZE + ciphertext.len());
        {
            let mut hb = bytes::BytesMut::new();
            header.encode(&mut hb);
            wire.extend_from_slice(&hb);
        }
        wire.extend_from_slice(ciphertext);
        codec::decode_frame(&wire, &k, &nonce)
            .map(|(frame, _generation)| frame)
            .map_err(|e| MuxError::Internal(e.to_string()))
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
        // A DATA/DATAGRAM frame always carries a non-zero sequence, so zero
        // can only be a forged or corrupted header. (The AEAD now covers the
        // header, but keep the check: it is one comparison and states the
        // invariant explicitly rather than relying on a caller.)
        if seq == 0 {
            return Err(MuxError::Internal("data frame with seq 0".to_string()));
        }
        // Generation gate: the peer's generation must match the live
        // incarnation. An older one is a frame from a previous life of this
        // id (late arrival, replay); a newer one means the peer re-opened the
        // id and this side has not registered it yet. Either way the payload
        // must not be decrypted into this incarnation's window.
        if header.generation != entry.generation {
            return Err(MuxError::StaleGeneration {
                stream_id: header.stream_id,
                got: header.generation,
                expected: entry.generation,
            });
        }
        // Replay window, newest-last:
        //  * `seen` catches duplicates inside the window;
        //  * the distance check rejects anything older than `REPLAY_WINDOW`.
        // Both are routine on a lossy path, so they are typed as
        // `ReplayDetected` (drop the frame) rather than `Internal` (which
        // callers treat as stream state corruption).
        if entry.seen.contains(&seq) {
            return Err(MuxError::ReplayDetected {
                stream_id: header.stream_id,
                seq,
            });
        }
        if seq <= entry.max_seen && entry.max_seen - seq >= REPLAY_WINDOW {
            return Err(MuxError::ReplayDetected {
                stream_id: header.stream_id,
                seq,
            });
        }
        let k = to_key(key)?;
        let nonce = build_nonce(header.stream_id, header.generation, seq, expect);
        let mut wire = Vec::with_capacity(FRAME_HEADER_SIZE + ciphertext.len());
        {
            let mut hb = bytes::BytesMut::new();
            header.encode(&mut hb);
            wire.extend_from_slice(&hb);
        }
        wire.extend_from_slice(ciphertext);
        let (frame, _framed_generation) = codec::decode_frame(&wire, &k, &nonce)
            .map_err(|e| MuxError::Internal(e.to_string()))?;
        let payload = match frame.payload {
            FramePayload::Data(v) if expect == FrameType::Data => v,
            FramePayload::UdpDatagram(v) if expect == FrameType::UdpDatagram => v,
            _ => return Err(MuxError::Internal("wrong payload".to_string())),
        };
        // Every accepted frame updates the anchor: an in-window frame that
        // arrives late (`seq < max_seen`) must still be recorded, otherwise a
        // replayed older frame looks like "new" after the window drains.
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
