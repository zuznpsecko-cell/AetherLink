//! TUN<->mux bridge (Phase W3).
//!
//! `DataPump` owns a `MuxManager` plus the 5-tuple<->stream map. TUN bytes
//! go in via `poll_once` (stateless packet<->frame mapping + DNS flow);
//! mux bytes come back via `receive_mux` (DATA/DATAGRAM -> IP packet into
//! TUN). Tamper, unknown ids and non-DATA inbound fail closed: `Err` and
//! nothing is written to TUN.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use aetherlink_frame::codec::FrameHeader;
use aetherlink_mux::manager::{MuxManager, SealedFrame};
use aetherlink_netstack::smoltcp_wrapper::{
    build_tcp_packet_window, build_tcp_synack_mss, build_udp_packet, parse_ipv4_packet,
    ParsedPayload,
};
use aetherlink_netstack::tun::TunPackets;
use aetherlink_protocol::FrameType;

use crate::{ClientError, Result};

/// One tracked flow (client side of the 5-tuple).
#[derive(Debug, Clone, PartialEq, Eq)]
struct FlowInfo {
    client_ip: Ipv4Addr,
    client_port: u16,
    server_ip: Ipv4Addr,
    server_port: u16,
    is_udp: bool,
    /// Last packet seen (UDP flows are reaped when it goes stale; TCP
    /// flows end explicitly, on FIN/RST).
    last_seen: Instant,
}

/// Link-local discovery has no business crossing a VPN (TTL 1 by design):
/// multicast/broadcast destinations, mDNS 5353, LLMNR 5355, NetBIOS 137/138,
/// SSDP 1900. Forwarding them only burns server relay timeouts serially and
/// starves real flows past client timeouts (seen live: nslookup drowning in
/// LLMNR/NetBIOS chatter). DNS (53) and everything else pass through.
fn is_discovery_noise(dst: Ipv4Addr, port: u16) -> bool {
    dst.is_multicast()
        || dst.is_broadcast()
        || dst.is_unspecified()
        || matches!(port, 137 | 138 | 5353 | 5355 | 1900)
}

/// 5-tuple key for the TUN->mux direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    is_udp: bool,
}

/// Client-side TCP termination state per 5-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
    /// SYN seen, SYN-ACK emitted, waiting for the completing ACK.
    SynReceived,
    /// Handshake complete; payload flows to/from mux.
    Established,
    /// The app sent FIN: its bytes are all upstream (relay got a
    /// half-close), but the peer may still be answering, so the flow stays
    /// alive for inbound data until the peer ends or the grace expires.
    HalfClosed,
}

/// Grace period for a half-closed flow: long enough for any target to
/// answer a finished request, short enough that abandoned flows do not
/// pin their mux id (ids are the one scarce resource here).
const HALF_CLOSED_GRACE: Duration = Duration::from_secs(120);

/// Idle time after which a UDP flow is forgotten. DNS and the like come
/// and go in milliseconds; a flow silent this long is over (and its mux
/// id is worth more than the guess that it might return).
const UDP_IDLE_GRACE: Duration = Duration::from_secs(300);

/// How often stale flows are looked for (a poll-time scan, not per packet).
const REAP_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum TCP payload size advertised in `SYN-ACK` and used when chunking
/// downstream server replies into Wintun IPv4 packets (`20 + 20 + 1360 = 1400B`,
/// fitting safely inside the default `1420B` TUN MTU and PPPoE/LTE links).
pub const TCP_MSS: usize = 1360;

/// How many sealed frames may be in flight toward the outer TLS writer at once
/// (`512 * 1360 ≈ 696 KiB` — comfortably fits 8+ concurrent Speedtest TCP
/// streams at full 64 KiB receive window without burst drops while staying
/// tightly bounded against bufferbloat).
const PENDING_FRAMES_MAX: usize = 512;

/// Duplicate ACKs emitted per out-of-order burst to trigger RFC 5681 Fast
/// Retransmit (`DupAckThreshold = 3`) without ACK storms.
const MAX_DUPACKS_PER_GAP: u8 = 4;

/// One terminated TCP flow: the app completes TCP against us, only payload
/// crosses the mux (OPEN once, then DATA per segment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpFlow {
    key: FlowKey,
    /// Mux stream id, allocated on first payload (None until then).
    id: Option<u16>,
    client_ip: Ipv4Addr,
    client_port: u16,
    server_ip: Ipv4Addr,
    server_port: u16,
    /// Maximum segment payload size toward the client (`536..=TCP_MSS`).
    peer_mss: usize,
    /// Client initial sequence (from SYN).
    client_isn: u32,
    /// Our initial sequence (SYN-ACK).
    server_iss: u32,
    /// Next sequence number we will send.
    server_next: u32,
    /// In-order payload bytes admitted from the client so far.
    client_bytes: u32,
    /// Cumulative payload bytes confirmed to the client (monotonically
    /// advances as frames are actually written to the wire).
    acked_bytes: u32,
    /// Duplicate ACKs emitted for the current sequence gap.
    dupacks: u8,
    state: TcpState,
    /// When the app half-closed (`None` while it can still send).
    closed_at: Option<Instant>,
}

impl TcpFlow {
    /// Expected next sequence number from the client (including `+1` once
    /// the client's `FIN` has been accepted).
    #[must_use]
    fn expected_client_seq(&self) -> u32 {
        let fin = u32::from(self.state == TcpState::HalfClosed);
        self.client_isn
            .wrapping_add(1)
            .wrapping_add(self.client_bytes)
            .wrapping_add(fin)
    }

    /// Cumulative `ack_num` to advertise on pure ACKs / window updates.
    #[must_use]
    fn ack_seq(&self) -> u32 {
        let fin = u32::from(self.state == TcpState::HalfClosed);
        self.client_isn
            .wrapping_add(1)
            .wrapping_add(self.acked_bytes)
            .wrapping_add(fin)
    }
}

/// Terminating bridge between TUN packets and sealed mux frames.
pub struct DataPump {
    mux: MuxManager,
    /// Seal key (client->server).
    tx: [u8; 32],
    /// Open key (server->client).
    rx: [u8; 32],
    pad: usize,
    by_tuple: HashMap<FlowKey, u16>,
    by_id: HashMap<u16, FlowInfo>,
    tcp: HashMap<FlowKey, TcpFlow>,
    tcp_by_id: HashMap<u16, FlowKey>,
    iss_next: u32,
    /// Next sweep for stale flows (half-closed TCP, idle UDP).
    next_reap: Instant,
    /// FIFO metadata for every sealed frame returned by `poll_once` that has
    /// not yet been passed to `frames_written`. `Some((fk, target_bytes))`
    /// advances `acked_bytes` as each frame actually enters the TLS socket.
    in_flight: VecDeque<Option<(FlowKey, u32)>>,
    /// Flows whose confirmed bytes deserve an ACK on the next `flush_acks`.
    ack_pending: Vec<FlowKey>,
    /// Flows held back or given a zero window while the upload buffer was full;
    /// reopened immediately once buffer room returns.
    throttled: Vec<FlowKey>,
}

impl DataPump {
    /// Create with one symmetric key (tests, loopback).
    #[must_use]
    pub fn new(key: [u8; 32], pad_multiple: usize) -> Self {
        Self::new_split(key, key, pad_multiple)
    }

    /// Create with session traffic keys (`tx` seals, `rx` opens).
    #[must_use]
    pub fn new_split(tx: [u8; 32], rx: [u8; 32], pad_multiple: usize) -> Self {
        Self {
            mux: MuxManager::new(),
            tx,
            rx,
            pad: pad_multiple,
            by_tuple: HashMap::new(),
            by_id: HashMap::new(),
            tcp: HashMap::new(),
            tcp_by_id: HashMap::new(),
            iss_next: 1_000_000,
            next_reap: Instant::now() + REAP_INTERVAL,
            in_flight: VecDeque::new(),
            ack_pending: Vec::new(),
            throttled: Vec::new(),
        }
    }

    /// Reuse an established session mux (post-handshake) with traffic keys.
    ///
    /// The handshake mux is fresh, so no sequence state is lost; the pump
    /// keeps learning 5-tuples from TUN packets as usual.
    #[must_use]
    pub fn with_mux(mux: MuxManager, tx: [u8; 32], rx: [u8; 32], pad_multiple: usize) -> Self {
        Self {
            mux,
            tx,
            rx,
            pad: pad_multiple,
            by_tuple: HashMap::new(),
            by_id: HashMap::new(),
            tcp: HashMap::new(),
            tcp_by_id: HashMap::new(),
            iss_next: 1_000_000,
            next_reap: Instant::now() + REAP_INTERVAL,
            in_flight: VecDeque::new(),
            ack_pending: Vec::new(),
            throttled: Vec::new(),
        }
    }

    /// Record a frame emitted toward the wire so `in_flight` tracks output 1:1.
    fn push_frame(
        &mut self,
        frames: &mut Vec<SealedFrame>,
        frame: SealedFrame,
        meta: Option<(FlowKey, u32)>,
    ) {
        frames.push(frame);
        self.in_flight.push_back(meta);
    }

    /// Allocate our next server sequence number (deterministic counter).
    fn next_iss(&mut self) -> u32 {
        let iss = self.iss_next;
        self.iss_next = self.iss_next.wrapping_add(1);
        iss
    }

    /// Seal the upstream half-close signal for a flow (one empty DATA).
    ///
    /// An empty payload never occurs on the wire from a live sender (pure
    /// ACKs are filtered out), so the relay can read it unambiguously as
    /// "this stream is finished, shut the target socket down".
    fn close_signal(&mut self, frames: &mut Vec<SealedFrame>, flow: &TcpFlow) {
        let Some(id) = flow.id else {
            return;
        };
        if !self.mux.is_open(id) {
            return;
        }
        match self.mux.seal_data(&self.tx, id, &[], self.pad) {
            Ok(sealed) => self.push_frame(frames, sealed, None),
            Err(e) => {
                aetherlink_netstack::debug_log(&format!(
                    "pump: close signal id={id} seal failed: {e}"
                ));
            }
        }
    }

    /// Forward one in-order payload upstream: OPEN the mux stream on first
    /// sight, then one DATA frame, recording FIFO completion targets so ACKs
    /// advance at true wire drain speed.
    ///
    /// On any failure the flow is put back before returning `Err`, so the
    /// caller must insert it only on success.
    fn seal_payload(
        &mut self,
        fk: &FlowKey,
        flow: &mut TcpFlow,
        payload: &[u8],
    ) -> Result<Vec<SealedFrame>> {
        let mut open_frame = None;
        if flow.id.is_none() {
            let id = match self
                .mux
                .open_tcp(&flow.server_ip.to_string(), flow.server_port)
            {
                Ok(id) => id,
                Err(e) => {
                    self.tcp.insert(*fk, *flow);
                    return Err(e.into());
                }
            };
            aetherlink_netstack::debug_log(&format!(
                "pump: tcp open id={id} -> {dst}:{dport}",
                dst = flow.server_ip,
                dport = flow.server_port,
            ));
            let open = match self.mux.seal_open_tcp(&self.tx, id, self.pad) {
                Ok(f) => f,
                Err(e) => {
                    let _ = self.mux.close(id);
                    self.tcp.insert(*fk, *flow);
                    return Err(e.into());
                }
            };
            self.by_tuple.insert(*fk, id);
            self.by_id.insert(
                id,
                FlowInfo {
                    client_ip: flow.client_ip,
                    client_port: flow.client_port,
                    server_ip: flow.server_ip,
                    server_port: flow.server_port,
                    is_udp: false,
                    last_seen: Instant::now(),
                },
            );
            self.tcp_by_id.insert(id, *fk);
            flow.id = Some(id);
            open_frame = Some(open);
        }
        let id = flow.id.expect("just opened");
        let data = match self.mux.seal_data(&self.tx, id, payload, self.pad) {
            Ok(f) => f,
            Err(e) => {
                self.tcp.insert(*fk, *flow);
                return Err(e.into());
            }
        };
        flow.client_bytes = flow.client_bytes.wrapping_add(payload.len() as u32);
        let mut frames = Vec::with_capacity(2);
        if let Some(open) = open_frame {
            self.push_frame(&mut frames, open, None);
        }
        self.push_frame(&mut frames, data, Some((*fk, flow.client_bytes)));
        Ok(frames)
    }

    /// Window the app may still fill (bytes), from the upload buffer left.
    #[must_use]
    fn adv_window(&self) -> u16 {
        let free = PENDING_FRAMES_MAX.saturating_sub(self.in_flight.len());
        u16::try_from(free.saturating_mul(TCP_MSS)).unwrap_or(u16::MAX)
    }

    fn push_ack(&mut self, fk: FlowKey) {
        if !self.ack_pending.contains(&fk) {
            self.ack_pending.push(fk);
        }
    }

    /// Admission control: is there room in the upload buffer for one more
    /// segment? A refused segment is dropped *without* being confirmed, so
    /// the app retransmits it later and the in-order check accepts it.
    fn admit(&mut self, fk: &FlowKey) -> bool {
        if self.in_flight.len() < PENDING_FRAMES_MAX {
            return true;
        }
        if !self.throttled.contains(fk) {
            self.throttled.push(*fk);
        }
        false
    }

    /// `n` sealed frames have actually been handed to the outer wire writer:
    /// advance cumulative ACK counters for those exact frames and free their
    /// slots in `in_flight`.
    pub fn frames_written(&mut self, n: usize) {
        for _ in 0..n {
            let Some(meta) = self.in_flight.pop_front() else {
                break;
            };
            if let Some((fk, target)) = meta {
                if let Some(flow) = self.tcp.get_mut(&fk) {
                    if (target.wrapping_sub(flow.acked_bytes) as i32) > 0 {
                        flow.acked_bytes = target;
                    }
                    flow.dupacks = 0;
                }
                self.push_ack(fk);
            }
        }
    }

    /// Confirm to the app whatever has left for the server, and reopen the
    /// flows that were held back while the buffer was full.
    pub fn flush_acks(&mut self, tun: &mut dyn TunPackets) {
        let mut flows = std::mem::take(&mut self.ack_pending);
        if !self.throttled.is_empty() && self.adv_window() > 0 {
            for fk in std::mem::take(&mut self.throttled) {
                if !flows.contains(&fk) {
                    flows.push(fk);
                }
            }
        }
        for fk in &flows {
            if let Err(e) = self.emit_ack(fk, tun) {
                aetherlink_netstack::debug_log(&format!("pump: tcp ack send failed: {e}"));
            }
        }
    }

    /// One cumulative ACK toward the app, carrying the current window.
    fn emit_ack(&mut self, fk: &FlowKey, tun: &mut dyn TunPackets) -> Result<()> {
        let win = self.adv_window();
        let Some(flow) = self.tcp.get(fk).copied() else {
            return Ok(());
        };
        if win < TCP_MSS as u16 && !self.throttled.contains(fk) {
            self.throttled.push(*fk);
        }
        let pkt = build_tcp_packet_window(
            flow.server_ip,
            flow.client_ip,
            flow.server_port,
            flow.client_port,
            false,
            true,
            false,
            false,
            false,
            flow.server_next,
            flow.ack_seq(),
            win,
            &[],
        );
        tun.send_packet(&pkt).map_err(|e| e.into())
    }

    /// Emit a SYN-ACK (with explicit MSS and receive window) toward TUN.
    fn send_synack(&self, flow: &TcpFlow, tun: &mut dyn TunPackets) -> Result<()> {
        let synack = build_tcp_synack_mss(
            flow.server_ip,
            flow.client_ip,
            flow.server_port,
            flow.client_port,
            flow.server_iss,
            flow.client_isn.wrapping_add(1),
            self.adv_window(),
            TCP_MSS as u16,
        );
        tun.send_packet(&synack)?;
        Ok(())
    }

    /// Forget a TCP flow everywhere.
    fn forget_tcp(&mut self, fk: &FlowKey, announce: bool) -> Vec<SealedFrame> {
        let mut out = Vec::new();
        let Some(flow) = self.tcp.remove(fk) else {
            return out;
        };
        aetherlink_netstack::debug_log(&format!(
            "pump: tcp flow {}:{} -> {}:{} forgotten (state {:?})",
            flow.client_ip, flow.client_port, flow.server_ip, flow.server_port, flow.state
        ));
        if let Some(id) = flow.id {
            self.tcp_by_id.remove(&id);
            self.by_id.remove(&id);
            self.by_tuple.remove(fk);
            if announce && self.mux.is_open(id) {
                match self.mux.seal_data(&self.tx, id, &[], self.pad) {
                    Ok(sealed) => self.push_frame(&mut out, sealed, None),
                    Err(e) => aetherlink_netstack::debug_log(&format!(
                        "pump: close-signal id={id} seal failed: {e}"
                    )),
                }
            }
            let _ = self.mux.close(id);
        }
        out
    }

    /// Forget half-closed flows whose peer never answered (bounds id use).
    fn reap_half_closed(&mut self, now: Instant) -> Vec<SealedFrame> {
        let mut out = Vec::new();
        let stale: Vec<FlowKey> = self
            .tcp
            .values()
            .filter(|f| {
                f.closed_at
                    .is_some_and(|t| now.duration_since(t) > HALF_CLOSED_GRACE)
            })
            .map(|f| f.key)
            .collect();
        for fk in stale {
            out.extend(self.forget_tcp(&fk, false));
        }
        out
    }

    /// Forget UDP flows that went silent (bounds id use: every DNS query
    /// used to keep its id for the whole session).
    fn reap_idle_udp(&mut self, now: Instant) {
        let stale: Vec<(FlowKey, u16)> = self
            .by_tuple
            .iter()
            .filter(|(fk, id)| {
                fk.is_udp
                    && self
                        .by_id
                        .get(id)
                        .is_some_and(|f| now.duration_since(f.last_seen) > UDP_IDLE_GRACE)
            })
            .map(|(fk, id)| (*fk, *id))
            .collect();
        for (fk, id) in stale {
            self.by_tuple.remove(&fk);
            self.by_id.remove(&id);
            let _ = self.mux.close(id);
        }
    }

    /// Drain all queued TUN packets, returning sealed frames upstream.
    ///
    /// New 5-tuples yield OPEN (seq 0) + first DATA/DATAGRAM; known TCP
    /// flows with empty payload (pure ACKs) yield nothing; truncated or
    /// unsupported packets are dropped fail-closed.
    pub fn poll_once(&mut self, tun: &mut dyn TunPackets) -> Result<Vec<SealedFrame>> {
        // Sweep for finished flows once a second: ids are a scarce
        // resource (the mux caps them) and a session outlives thousands
        // of connections.
        let now = Instant::now();
        let mut out = Vec::new();
        if now >= self.next_reap {
            self.next_reap = now + REAP_INTERVAL;
            out.extend(self.reap_half_closed(now));
            self.reap_idle_udp(now);
        }
        while let Some(raw) = tun.try_recv()? {
            if let Some(frames) = self.pump_one(&raw, tun)? {
                out.extend(frames);
            }
        }
        Ok(out)
    }

    fn pump_one(
        &mut self,
        raw: &[u8],
        tun: &mut dyn TunPackets,
    ) -> Result<Option<Vec<SealedFrame>>> {
        let parsed = match parse_ipv4_packet(raw) {
            Ok(p) => p,
            Err(e) => {
                aetherlink_netstack::debug_log(&format!("pump: drop truncated packet: {e}"));
                return Ok(None);
            }
        };
        match parsed.payload {
            ParsedPayload::Tcp(seg) => {
                if parsed.dst.is_multicast()
                    || parsed.dst.is_broadcast()
                    || parsed.dst.is_unspecified()
                {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: drop tcp to non-unicast {}",
                        parsed.dst
                    ));
                    return Ok(None);
                }
                let fk = FlowKey {
                    src: parsed.src,
                    src_port: seg.src_port,
                    dst: parsed.dst,
                    dst_port: seg.dst_port,
                    is_udp: false,
                };
                // RST forgets the flow and tells the relay to close: an
                // abandoned stream would otherwise hold a socket, a thread
                // and a mux id until the target's own timeout.
                if seg.rst {
                    let frames = self.forget_tcp(&fk, true);
                    return Ok(Some(frames));
                }
                // Bare SYN on an unknown flow opens termination.
                if !self.tcp.contains_key(&fk) {
                    if seg.syn && !seg.ack {
                        let iss = self.next_iss();
                        let peer_mss = seg
                            .mss
                            .map(|m| usize::from(m).clamp(536, TCP_MSS))
                            .unwrap_or(TCP_MSS);
                        let mut flow = TcpFlow {
                            key: fk,
                            id: None,
                            client_ip: parsed.src,
                            client_port: seg.src_port,
                            server_ip: parsed.dst,
                            server_port: seg.dst_port,
                            peer_mss,
                            client_isn: seg.seq,
                            server_iss: iss,
                            server_next: iss.wrapping_add(1),
                            client_bytes: 0,
                            acked_bytes: 0,
                            dupacks: 0,
                            state: TcpState::SynReceived,
                            closed_at: None,
                        };
                        self.send_synack(&flow, tun)?;
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tcp synack {src}:{sport} -> {dst}:{dport} mss={TCP_MSS}",
                            src = parsed.src,
                            sport = seg.src_port,
                            dst = parsed.dst,
                            dport = seg.dst_port,
                        ));
                        // SYN carrying payload (fast-open style): forward it
                        // now instead of waiting for the completing ACK.
                        if !seg.payload.is_empty() {
                            let frames = match self.seal_payload(&fk, &mut flow, &seg.payload) {
                                Ok(frames) => frames,
                                Err(e) => return Err(e),
                            };
                            self.tcp.insert(fk, flow);
                            return Ok(Some(frames));
                        }
                        self.tcp.insert(fk, flow);
                    }
                    return Ok(None);
                }
                // Duplicate SYN (lost SYN-ACK): resend it borrowing only,
                // so a failed send cannot desync the tables.
                if seg.syn && !seg.ack {
                    if let Some(flow) = self.tcp.get(&fk) {
                        if seg.seq == flow.client_isn {
                            let flow = *flow;
                            self.send_synack(&flow, tun)?;
                            return Ok(None);
                        }
                    }
                    return Ok(None);
                }
                let mut flow = self.tcp.remove(&fk).expect("checked above");
                // Completing ACK moves SynReceived -> Established.
                if flow.state == TcpState::SynReceived {
                    if seg.ack && !seg.syn && seg.ack_num == flow.server_iss.wrapping_add(1) {
                        flow.state = TcpState::Established;
                    } else {
                        self.tcp.insert(fk, flow);
                        return Ok(None);
                    }
                }
                // Half-closed: the app already sent FIN; re-ACK retransmitted
                // FINs, ignore late payload, and keep inbound open until the
                // upstream peer finishes answering.
                if flow.state == TcpState::HalfClosed {
                    if seg.fin {
                        let fin_seq = flow
                            .client_isn
                            .wrapping_add(1)
                            .wrapping_add(flow.client_bytes);
                        if seg.seq == fin_seq {
                            let reack = build_tcp_packet_window(
                                flow.server_ip,
                                flow.client_ip,
                                flow.server_port,
                                flow.client_port,
                                false,
                                true,
                                false,
                                flow.id.is_none(),
                                false,
                                flow.server_next,
                                flow.expected_client_seq(),
                                self.adv_window(),
                                &[],
                            );
                            if let Err(e) = tun.send_packet(&reack) {
                                self.tcp.insert(fk, flow);
                                return Err(e.into());
                            }
                        }
                    }
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                // Pure ACKs/keepalives without FIN: silence.
                if seg.payload.is_empty() && !seg.fin {
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                // Strictly validate sequence order BEFORE forwarding payload
                // or accepting FIN:
                // - Future seq (> expected): emit up to 4 Duplicate ACKs so
                //   the OS TCP stack triggers RFC 5681 Fast Retransmit (~1 RTT
                //   instead of a 300-1000ms RTO freeze), and drop out-of-order
                //   FINs until the missing bytes arrive.
                // - Stale seq (< expected): drop without double-counting, and
                //   queue a cumulative ACK refresh for `flush_acks`.
                let expected = flow
                    .client_isn
                    .wrapping_add(1)
                    .wrapping_add(flow.client_bytes);
                if seg.seq != expected {
                    let ahead = seg.seq.wrapping_sub(expected) as i32;
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tcp id={} out-of-order/drop (seq {} vs expected {expected}), dropped",
                        flow.id.unwrap_or(u16::MAX),
                        seg.seq
                    ));
                    if ahead > 0 && flow.dupacks < MAX_DUPACKS_PER_GAP {
                        flow.dupacks += 1;
                        self.tcp.insert(fk, flow);
                        let _ = self.emit_ack(&fk, tun);
                    } else {
                        self.tcp.insert(fk, flow);
                        if ahead < 0 {
                            self.push_ack(fk);
                        }
                    }
                    return Ok(None);
                }
                flow.dupacks = 0;
                // FIN (now verified in-order): forward trailing payload if
                // any, then acknowledge half-close (`ACK` only when an
                // upstream mux stream is open so the OS socket enters
                // `FIN_WAIT_2` and can still receive `HTTP 200 OK` without
                // resetting; `FIN+ACK` when closing an unused bare flow).
                if seg.fin {
                    let mut frames = Vec::new();
                    if !seg.payload.is_empty() {
                        match self.seal_payload(&fk, &mut flow, &seg.payload) {
                            Ok(f) => frames.extend(f),
                            Err(e) => return Err(e),
                        }
                    }
                    let has_upstream = flow.id.is_some();
                    let prev_acked = flow.acked_bytes;
                    flow.acked_bytes = flow.client_bytes;
                    flow.state = TcpState::HalfClosed;
                    flow.closed_at = Some(Instant::now());
                    let ack_pkt = build_tcp_packet_window(
                        flow.server_ip,
                        flow.client_ip,
                        flow.server_port,
                        flow.client_port,
                        false,
                        true,
                        false,
                        !has_upstream,
                        false,
                        flow.server_next,
                        flow.expected_client_seq(),
                        self.adv_window(),
                        &[],
                    );
                    if let Err(e) = tun.send_packet(&ack_pkt) {
                        flow.state = TcpState::Established;
                        flow.closed_at = None;
                        flow.acked_bytes = prev_acked;
                        self.tcp.insert(fk, flow);
                        return Err(e.into());
                    }
                    if !has_upstream {
                        flow.server_next = flow.server_next.wrapping_add(1);
                    } else {
                        self.close_signal(&mut frames, &flow);
                    }
                    self.tcp.insert(fk, flow);
                    return Ok(Some(frames));
                }
                // Upload buffer full: hold back without advancing sequence so
                // the app cleanly retransmits once room reopens.
                if !self.admit(&fk) {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tcp id={} upload buffer full ({} pending), holding",
                        flow.id.unwrap_or(u16::MAX),
                        self.in_flight.len()
                    ));
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                let frames = match self.seal_payload(&fk, &mut flow, &seg.payload) {
                    Ok(frames) => frames,
                    Err(e) => return Err(e),
                };
                self.tcp.insert(fk, flow);
                Ok(Some(frames))
            }
            ParsedPayload::Udp(dgram) => {
                if is_discovery_noise(parsed.dst, dgram.dst_port) {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: drop discovery udp to {}:{}",
                        parsed.dst, dgram.dst_port
                    ));
                    return Ok(None);
                }
                let fk = FlowKey {
                    src: parsed.src,
                    src_port: dgram.src_port,
                    dst: parsed.dst,
                    dst_port: dgram.dst_port,
                    is_udp: true,
                };
                let mut frames = Vec::with_capacity(2);
                if let Some(&id) = self.by_tuple.get(&fk) {
                    if let Some(info) = self.by_id.get_mut(&id) {
                        info.last_seen = Instant::now();
                    }
                    let sealed = self
                        .mux
                        .seal_datagram(&self.tx, id, &dgram.payload, self.pad)?;
                    self.push_frame(&mut frames, sealed, None);
                    Ok(Some(frames))
                } else {
                    let id = self.mux.open_udp(&parsed.dst.to_string(), dgram.dst_port)?;
                    aetherlink_netstack::debug_log(&format!(
                        "pump: new udp {src}:{sport} -> {dst}:{dport} id={id}",
                        src = parsed.src,
                        sport = dgram.src_port,
                        dst = parsed.dst,
                        dport = dgram.dst_port,
                    ));
                    self.by_tuple.insert(fk, id);
                    self.by_id.insert(
                        id,
                        FlowInfo {
                            client_ip: parsed.src,
                            client_port: dgram.src_port,
                            server_ip: parsed.dst,
                            server_port: dgram.dst_port,
                            is_udp: true,
                            last_seen: Instant::now(),
                        },
                    );
                    let open = self.mux.seal_open_udp(&self.tx, id, self.pad)?;
                    let data = self
                        .mux
                        .seal_datagram(&self.tx, id, &dgram.payload, self.pad)?;
                    self.push_frame(&mut frames, open, None);
                    self.push_frame(&mut frames, data, None);
                    Ok(Some(frames))
                }
            }
        }
    }

    /// Inject one mux frame downstream, emitting IP packet(s) into TUN.
    ///
    /// Only DATA (TCP) and DATAGRAM (UDP) are accepted; anything else,
    /// unknown ids, direction mismatches and AEAD failures return `Err`
    /// with nothing written to TUN.
    pub fn receive_mux(
        &mut self,
        header: &FrameHeader,
        ciphertext: &[u8],
        tun: &mut dyn TunPackets,
    ) -> Result<()> {
        match header.frame_type {
            FrameType::Data => {
                let id = header.stream_id;
                let key = *self
                    .tcp_by_id
                    .get(&id)
                    .ok_or_else(|| ClientError::RoutingError(format!("unknown stream {id}")))?;
                let payload = match self.mux.open_data(&self.rx, header, ciphertext) {
                    Ok(payload) => payload,
                    Err(e) => {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: data id={id} open failed: {e}, flow kept"
                        ));
                        return Err(e.into());
                    }
                };
                let mut flow = match self.tcp.remove(&key) {
                    Some(flow) => flow,
                    None => {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: data id={id} without terminated flow, dropped"
                        ));
                        return Err(ClientError::RoutingError(format!(
                            "stream {id} has no terminated flow"
                        )));
                    }
                };
                flow.acked_bytes = flow.client_bytes;
                let ack_num = flow.expected_client_seq();
                let win = self.adv_window();
                // Empty DATA = the relay is done with this stream (clean
                // EOF or a failed relay). Close the app's socket cleanly.
                if payload.is_empty() {
                    aetherlink_netstack::debug_log(&format!("pump: data id={id} closed by peer"));
                    let fin = build_tcp_packet_window(
                        flow.server_ip,
                        flow.client_ip,
                        flow.server_port,
                        flow.client_port,
                        false,
                        true,
                        false,
                        true,
                        false,
                        flow.server_next,
                        ack_num,
                        win,
                        &[],
                    );
                    let _ = tun.send_packet(&fin);
                    flow.server_next = flow.server_next.wrapping_add(1);
                    self.tcp_by_id.remove(&id);
                    self.by_id.remove(&id);
                    self.by_tuple.remove(&key);
                    let _ = self.mux.close(id);
                    return Ok(());
                }
                let mss = flow.peer_mss.max(536);
                let total_chunks = payload.chunks(mss).len();
                for (idx, chunk) in payload.chunks(mss).enumerate() {
                    let pkt = build_tcp_packet_window(
                        flow.server_ip,
                        flow.client_ip,
                        flow.server_port,
                        flow.client_port,
                        false,
                        true,
                        idx + 1 == total_chunks,
                        false,
                        false,
                        flow.server_next,
                        ack_num,
                        win,
                        chunk,
                    );
                    if let Err(e) = tun.send_packet(&pkt) {
                        self.tcp.insert(key, flow);
                        return Err(e.into());
                    }
                    flow.server_next = flow.server_next.wrapping_add(chunk.len() as u32);
                }
                self.tcp.insert(key, flow);
                Ok(())
            }
            FrameType::UdpDatagram => {
                let flow = self.by_id.get(&header.stream_id).ok_or_else(|| {
                    ClientError::RoutingError(format!("unknown flow {}", header.stream_id))
                })?;
                if !flow.is_udp {
                    return Err(ClientError::RoutingError(format!(
                        "flow {} is tcp, got DATAGRAM",
                        header.stream_id
                    )));
                }
                let payload = self.mux.open_datagram(&self.rx, header, ciphertext)?;
                let pkt = build_udp_packet(
                    flow.server_ip,
                    flow.client_ip,
                    flow.server_port,
                    flow.client_port,
                    &payload,
                );
                tun.send_packet(&pkt)?;
                Ok(())
            }
            other => Err(ClientError::RoutingError(format!(
                "inbound frame type {other:?} not allowed"
            ))),
        }
    }
}
