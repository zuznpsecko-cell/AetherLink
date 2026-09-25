//! TUN<->mux bridge (Phase W3).
//!
//! `DataPump` owns a `MuxManager` plus the 5-tuple<->stream map. TUN bytes
//! go in via `poll_once` (stateless packet<->frame mapping + DNS flow);
//! mux bytes come back via `receive_mux` (DATA/DATAGRAM -> IP packet into
//! TUN). Tamper, unknown ids and non-DATA inbound fail closed: `Err` and
//! nothing is written to TUN.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use aetherlink_frame::codec::FrameHeader;
use aetherlink_mux::manager::{MuxManager, SealedFrame};
use aetherlink_netstack::smoltcp_wrapper::{
    build_tcp_packet_full, build_udp_packet, parse_ipv4_packet, ParsedPayload,
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
}

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
        }
    }

    /// Allocate our next server sequence number (deterministic counter).
    fn next_iss(&mut self) -> u32 {
        let iss = self.iss_next;
        self.iss_next = self.iss_next.wrapping_add(1);
        iss
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

    /// Forget a TCP flow everywhere (RST/FIN path, always silent upstream:
    /// the server treats Rst frames as loop-fatal, so none are ever sent).
    fn forget_tcp(&mut self, fk: &FlowKey) {
        if let Some(flow) = self.tcp.remove(fk) {
            if let Some(id) = flow.id {
                self.tcp_by_id.remove(&id);
                self.by_id.remove(&id);
                self.by_tuple.remove(fk);
            }
        }
    }

    /// Drain all queued TUN packets, returning sealed frames upstream.
    ///
    /// New 5-tuples yield OPEN (seq 0) + first DATA/DATAGRAM; known TCP
    /// flows with empty payload (pure ACKs) yield nothing; truncated or
    /// unsupported packets are dropped fail-closed.
    pub fn poll_once(&mut self, tun: &mut dyn TunPackets) -> Result<Vec<SealedFrame>> {
        let mut out = Vec::new();
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
                // RST always forgets the flow, silently (never RST upstream).
                if seg.rst {
                    self.forget_tcp(&fk);
                    return Ok(None);
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
                            let id = self
                                .mux
                                .open_tcp(&flow.server_ip.to_string(), flow.server_port)?;
                            self.by_tuple.insert(fk, id);
                            self.by_id.insert(
                                id,
                                FlowInfo {
                                    client_ip: flow.client_ip,
                                    client_port: flow.client_port,
                                    server_ip: flow.server_ip,
                                    server_port: flow.server_port,
                                    is_udp: false,
                                },
                            );
                            self.tcp_by_id.insert(id, fk);
                            flow.id = Some(id);
                            flow.client_bytes =
                                flow.client_bytes.wrapping_add(seg.payload.len() as u32);
                            let open = self.mux.seal_open_tcp(&self.tx, id, self.pad)?;
                            let data = self.mux.seal_data(&self.tx, id, &seg.payload, self.pad)?;
                            self.tcp.insert(fk, flow);
                            return Ok(Some(vec![open, data]));
                        }
                    }
                    return Ok(None);
                }
                let mut flow = self.tcp.remove(&fk).expect("checked above");
                // Duplicate SYN (lost SYN-ACK): resend it, keep state.
                if seg.syn && !seg.ack && seg.seq == flow.client_isn {
                    self.send_synack(&flow, tun)?;
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                // Completing ACK moves SynReceived -> Established.
                if flow.state == TcpState::SynReceived {
                    if seg.ack && !seg.syn && seg.ack_num == flow.server_iss.wrapping_add(1) {
                        flow.state = TcpState::Established;
                    } else {
                        self.tcp.insert(fk, flow);
                        return Ok(None);
                    }
                }
                // FIN closes: FIN-ACK out, forget the flow.
                if seg.fin {
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
                    tun.send_packet(&finack)?;
                    self.forget_tcp(&fk);
                    return Ok(None);
                }
                // Pure ACKs/keepalives: silence.
                if seg.payload.is_empty() {
                    self.tcp.insert(fk, flow);
                    return Ok(None);
                }
                // Payload: OPEN the mux stream once, then DATA per segment.
                let mut frames = Vec::new();
                if flow.id.is_none() {
                    let id = self
                        .mux
                        .open_tcp(&flow.server_ip.to_string(), flow.server_port)?;
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tcp open id={id} -> {dst}:{dport}",
                        dst = flow.server_ip,
                        dport = flow.server_port,
                    ));
                    self.by_tuple.insert(fk, id);
                    self.by_id.insert(
                        id,
                        FlowInfo {
                            client_ip: flow.client_ip,
                            client_port: flow.client_port,
                            server_ip: flow.server_ip,
                            server_port: flow.server_port,
                            is_udp: false,
                        },
                    );
                    self.tcp_by_id.insert(id, fk);
                    flow.id = Some(id);
                    frames.push(self.mux.seal_open_tcp(&self.tx, id, self.pad)?);
                }
                let id = flow.id.expect("just opened");
                flow.client_bytes = flow.client_bytes.wrapping_add(seg.payload.len() as u32);
                frames.push(self.mux.seal_data(&self.tx, id, &seg.payload, self.pad)?);
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
                let payload = self.mux.open_data(&self.rx, header, ciphertext)?;
                let mut flow = self.tcp.remove(&key).expect("tcp_by_id consistent");
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
                tun.send_packet(&pkt)?;
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
