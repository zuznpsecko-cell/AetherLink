//! TUN<->mux bridge (Phase W3).
//!
//! `DataPump` owns a `MuxManager` plus the 5-tuple<->stream map. TUN bytes
//! go in via `poll_once` (stateless packet<->frame mapping + DNS flow);
//! mux bytes come back via `receive_mux` (DATA/DATAGRAM -> IP packet into
//! TUN). Tamper, unknown ids and non-DATA inbound fail closed: `Err` and
//! nothing is written to TUN.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use aetherlink_frame::codec::FrameHeader;
use aetherlink_mux::manager::{MuxManager, SealedFrame};
use aetherlink_netstack::smoltcp_wrapper::{
    build_tcp_packet_full, build_tcp_packet_window, build_udp_packet, parse_ipv4_packet,
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

/// How many sealed frames may be admitted from the app before some of them
/// have actually left for the server (upload buffer, ~1.6MB at a 1460B
/// payload — room for the drain rate to grow past the initial 12Mbps
/// equilibrium without drowning the app in bufferbloat).
///
/// Split-TCP means we ACK the app ourselves, so nothing else stops it from
/// sending at LAN speed into a tunnel that drains an order of magnitude
/// slower: the surplus then has nowhere to go but the bin, and a dropped
/// chunk is unrecoverable (the app's retransmit is rejected as a duplicate
/// by our in-order check — seen live: 20Mbps down, upload 0.00).
const PENDING_FRAMES_MAX: usize = 1024;

/// Nominal payload of one frame, only used to translate the pending-frame
/// budget into a TCP window for the app.
const NOMINAL_FRAME: usize = 1460;

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
    /// Client initial sequence (from SYN).
    client_isn: u32,
    /// Our initial sequence (SYN-ACK).
    server_iss: u32,
    /// Next sequence number we will send.
    server_next: u32,
    /// Payload bytes accepted from the client so far (for ACK numbers).
    client_bytes: u32,
    state: TcpState,
    /// When the app half-closed (`None` while it can still send).
    closed_at: Option<Instant>,
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
    /// Frames admitted from the app that have not been written out yet
    /// (upload buffer; see `PENDING_FRAMES_MAX`).
    pending: usize,
    /// Flows whose admitted bytes deserve an ACK (emitted once written).
    ack_pending: Vec<FlowKey>,
    /// Flows held back because the upload buffer was full; they get a
    /// window update as soon as there is room again.
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
            pending: 0,
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
            pending: 0,
            ack_pending: Vec::new(),
            throttled: Vec::new(),
        }
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
    fn close_signal(&mut self, flow: &TcpFlow) -> Vec<SealedFrame> {
        let Some(id) = flow.id else {
            return Vec::new();
        };
        if !self.mux.is_open(id) {
            return Vec::new();
        }
        match self.mux.seal_data(&self.tx, id, &[], self.pad) {
            Ok(sealed) => vec![sealed],
            Err(e) => {
                aetherlink_netstack::debug_log(&format!(
                    "pump: close signal id={id} seal failed: {e}"
                ));
                Vec::new()
            }
        }
    }

    /// Forward one in-order payload upstream: OPEN the mux stream on first
    /// sight, then one DATA frame, then confirm the bytes to the app.
    ///
    /// On any failure the flow is put back before returning `Err`, so the
    /// caller must insert it only on success.
    fn seal_payload(
        &mut self,
        fk: &FlowKey,
        flow: &mut TcpFlow,
        payload: &[u8],
    ) -> Result<Vec<SealedFrame>> {
        let mut frames = Vec::new();
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
            frames.push(open);
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
        frames.push(data);
        // The ACK is NOT emitted here: it goes out once these bytes have
        // actually been written to the server (see `flush_acks`). Confirming
        // them at admission tells the app to send at LAN speed into a tunnel
        // that drains far slower, and everything that does not fit is lost
        // with no way back — the app's retransmit is rejected here as a
        // duplicate, so the stream never recovers (seen live: upload 0.00).
        self.pending += frames.len();
        self.push_ack(*fk);
        Ok(frames)
    }

    /// Window the app may still fill (bytes), from the upload buffer left.
    #[must_use]
    fn adv_window(&self) -> u16 {
        let free = PENDING_FRAMES_MAX.saturating_sub(self.pending);
        u16::try_from(free.saturating_mul(NOMINAL_FRAME)).unwrap_or(u16::MAX)
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
        if self.pending < PENDING_FRAMES_MAX {
            return true;
        }
        if !self.throttled.contains(fk) {
            self.throttled.push(*fk);
        }
        false
    }

    /// `n` sealed frames have been written to the server: free their room
    /// in the upload buffer.
    pub fn frames_written(&mut self, n: usize) {
        self.pending = self.pending.saturating_sub(n);
    }

    /// Confirm to the app whatever has left for the server, and reopen the
    /// flows that were held back while the buffer was full.
    ///
    /// The window carried by these ACKs is the real one: when the tunnel is
    /// backed up the app is told to stop instead of being left to discover
    /// it by retransmission timeout (the RTO storm of issue 0g).
    pub fn flush_acks(&mut self, tun: &mut dyn TunPackets) {
        let mut flows = std::mem::take(&mut self.ack_pending);
        // Reopen flows held back by a full buffer, but only when there is
        // really room: a zero-window ACK would just be noise. Called every
        // turn, so a flow can never be left waiting with room available.
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
    fn emit_ack(&self, fk: &FlowKey, tun: &mut dyn TunPackets) -> Result<()> {
        let Some(flow) = self.tcp.get(fk) else {
            return Ok(());
        };
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
            flow.client_isn
                .wrapping_add(1)
                .wrapping_add(flow.client_bytes),
            self.adv_window(),
            &[],
        );
        tun.send_packet(&pkt).map_err(|e| e.into())
    }

    /// Emit a SYN-ACK for a terminated flow toward TUN.
    fn send_synack(&self, flow: &TcpFlow, tun: &mut dyn TunPackets) -> Result<()> {
        let synack = build_tcp_packet_full(
            flow.server_ip,
            flow.client_ip,
            flow.server_port,
            flow.client_port,
            true,
            true,
            false,
            false,
            false,
            flow.server_iss,
            flow.client_isn.wrapping_add(1),
            &[],
        );
        tun.send_packet(&synack)?;
        Ok(())
    }

    /// Forget a TCP flow everywhere.
    ///
    /// `announce` emits the upstream half-close (one empty DATA frame) so
    /// the relay can shut its socket: without it every finished connection
    /// keeps a relay thread and socket until the target's own timeout, and
    /// ids are never recycled (the pump dies at the mux cap). It is skipped
    /// when the peer closed first (it already knows).
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
                    Ok(sealed) => out.push(sealed),
                    Err(e) => aetherlink_netstack::debug_log(&format!(
                        "pump: close-signal id={id} seal failed: {e}"
                    )),
                }
            }
            // Free the id: the mux has a hard cap and a session lives far
            // longer than any one connection.
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
                        let mut flow = TcpFlow {
                            key: fk,
                            id: None,
                            client_ip: parsed.src,
                            client_port: seg.src_port,
                            server_ip: parsed.dst,
                            server_port: seg.dst_port,
                            client_isn: seg.seq,
                            server_iss: iss,
                            server_next: iss.wrapping_add(1),
                            client_bytes: 0,
                            state: TcpState::SynReceived,
                            closed_at: None,
                        };
                        self.send_synack(&flow, tun)?;
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tcp synack {src}:{sport} -> {dst}:{dport}",
                            src = parsed.src,
                            sport = seg.src_port,
                            dst = parsed.dst,
                            dport = seg.dst_port,
                        ));
                        self.tcp.insert(fk, flow);
                        // SYN carrying payload (fast-open style): forward it
                        // now instead of waiting for the completing ACK.
                        if !seg.payload.is_empty() {
                            let mut flow = self.tcp.remove(&fk).expect("just inserted");
                            // Any failure below restores the flow first: maps
                            // commit only after all fallible ops succeed, so
                            // the tables can never desync (live panic class).
                            let id = match self
                                .mux
                                .open_tcp(&flow.server_ip.to_string(), flow.server_port)
                            {
                                Ok(id) => id,
                                Err(e) => {
                                    self.tcp.insert(fk, flow);
                                    return Err(e.into());
                                }
                            };
                            let open = match self.mux.seal_open_tcp(&self.tx, id, self.pad) {
                                Ok(f) => f,
                                Err(e) => {
                                    self.tcp.insert(fk, flow);
                                    return Err(e.into());
                                }
                            };
                            let data =
                                match self.mux.seal_data(&self.tx, id, &seg.payload, self.pad) {
                                    Ok(f) => f,
                                    Err(e) => {
                                        self.tcp.insert(fk, flow);
                                        return Err(e.into());
                                    }
                                };
                            self.by_tuple.insert(fk, id);
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
                            self.tcp_by_id.insert(id, fk);
                            flow.id = Some(id);
                            flow.client_bytes =
                                flow.client_bytes.wrapping_add(seg.payload.len() as u32);
                            self.tcp.insert(fk, flow);
                            return Ok(Some(vec![open, data]));
                        }
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
                // FIN: forward whatever payload it carries (some stacks
                // combine FIN with the last bytes), then half-close. The
                // flow is NOT forgotten here: an app that closes its send
                // side still has to receive the answer (every HTTP request
                // sent with `Connection: close`). It dies on the peer's
                // end-of-stream or when the grace period expires.
                if seg.fin {
                    let mut frames = Vec::new();
                    if !seg.payload.is_empty() && flow.state != TcpState::HalfClosed {
                        let expected = flow
                            .client_isn
                            .wrapping_add(1)
                            .wrapping_add(flow.client_bytes);
                        if seg.seq == expected && self.admit(&fk) {
                            match self.seal_payload(&fk, &mut flow, &seg.payload) {
                                Ok(f) => frames.extend(f),
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    let finack = build_tcp_packet_full(
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
                        seg.seq
                            .wrapping_add(seg.payload.len() as u32)
                            .wrapping_add(1),
                        &[],
                    );
                    if let Err(e) = tun.send_packet(&finack) {
                        // Device refused the FIN: keep the flow so the app's
                        // retransmit can close it again.
                        self.tcp.insert(fk, flow);
                        return Err(e.into());
                    }
                    if flow.state != TcpState::HalfClosed {
                        flow.state = TcpState::HalfClosed;
                        flow.closed_at = Some(Instant::now());
                        frames.extend(self.close_signal(&flow));
                    }
                    self.tcp.insert(fk, flow);
                    return Ok(Some(frames));
                }
                // Half-closed: the app is done sending. Stray late payload
                // is ignored; inbound data still flows (see FIN above).
                if flow.state == TcpState::HalfClosed {
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                // Pure ACKs/keepalives: silence.
                if seg.payload.is_empty() {
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                // In-order only: duplicates (app RTO retransmits) and gaps
                // are dropped, never resealed. Resealing duplicates inflates
                // client_bytes, the ACK number then runs past the app send
                // window, and the local stack answers RST (seen live).
                // Gaps resolve via app retransmit of the missing bytes.
                let expected = flow
                    .client_isn
                    .wrapping_add(1)
                    .wrapping_add(flow.client_bytes);
                if seg.seq != expected {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tcp id={} out-of-order/drop (seq {} vs expected {expected}), dropped",
                        flow.id.unwrap_or(u16::MAX),
                        seg.seq
                    ));
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                // Upload buffer full: drop silently (no ACK, no sequence
                // advance) so the app retransmits this very segment once
                // there is room. Confirming it here and losing it later is
                // unrecoverable — the retransmit would be rejected above as
                // a duplicate (seen live: upload measures 0.00).
                if !self.admit(&fk) {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tcp id={} upload buffer full ({} pending), holding",
                        flow.id.unwrap_or(u16::MAX),
                        self.pending
                    ));
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                // Payload: OPEN the mux stream once, then DATA per segment.
                // On error the helper has already restored the flow, so it
                // must not be inserted again (tables stay in sync).
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
                if let Some(&id) = self.by_tuple.get(&fk) {
                    if let Some(info) = self.by_id.get_mut(&id) {
                        info.last_seen = Instant::now();
                    }
                    let sealed = self
                        .mux
                        .seal_datagram(&self.tx, id, &dgram.payload, self.pad)?;
                    Ok(Some(vec![sealed]))
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
                    Ok(Some(vec![open, data]))
                }
            }
        }
    }

    /// Inject one mux frame downstream, emitting an IP packet into TUN.
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
                // Empty DATA = the relay is done with this stream (clean
                // EOF or a failed relay). Close the app's socket instead of
                // leaving it to hang until the app's own timeout: a dead
                // upload is far better than a stalled one (seen live: 0.00
                // on speedtest upload, every stream waiting on nothing).
                if payload.is_empty() {
                    aetherlink_netstack::debug_log(&format!("pump: data id={id} closed by peer"));
                    let fin = build_tcp_packet_full(
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
                        flow.client_isn
                            .wrapping_add(1)
                            .wrapping_add(flow.client_bytes),
                        &[],
                    );
                    let _ = tun.send_packet(&fin);
                    // The flow is already removed above: release its maps
                    // and mux id here. forget_tcp would find nothing and
                    // leak the id until the 4096 cap mutes the session.
                    self.tcp_by_id.remove(&id);
                    self.by_id.remove(&id);
                    self.by_tuple.remove(&key);
                    let _ = self.mux.close(id);
                    return Ok(());
                }
                let pkt = build_tcp_packet_full(
                    flow.server_ip,
                    flow.client_ip,
                    flow.server_port,
                    flow.client_port,
                    false,
                    true,
                    true,
                    false,
                    false,
                    flow.server_next,
                    flow.client_isn
                        .wrapping_add(1)
                        .wrapping_add(flow.client_bytes),
                    &payload,
                );
                flow.server_next = flow.server_next.wrapping_add(payload.len() as u32);
                if let Err(e) = tun.send_packet(&pkt) {
                    // Ring full etc: keep the flow (un-advanced? no — the
                    // sequence advanced, but the app never saw the bytes, so
                    // roll the number back to stay consistent).
                    flow.server_next = flow.server_next.wrapping_sub(payload.len() as u32);
                    self.tcp.insert(key, flow);
                    return Err(e.into());
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
