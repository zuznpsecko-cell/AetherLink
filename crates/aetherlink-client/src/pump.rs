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
    build_tcp_packet, build_udp_packet, parse_ipv4_packet, ParsedPayload,
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

/// 5-tuple key for the TUN->mux direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    is_udp: bool,
}

/// Stateless bridge between TUN packets and sealed mux frames.
pub struct DataPump {
    mux: MuxManager,
    /// Seal key (client->server).
    tx: [u8; 32],
    /// Open key (server->client).
    rx: [u8; 32],
    pad: usize,
    by_tuple: HashMap<FlowKey, u16>,
    by_id: HashMap<u16, FlowInfo>,
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
            if let Some(frames) = self.pump_one(&raw)? {
                out.extend(frames);
            }
        }
        Ok(out)
    }

    fn pump_one(&mut self, raw: &[u8]) -> Result<Option<Vec<SealedFrame>>> {
        let parsed = match parse_ipv4_packet(raw) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        match parsed.payload {
            ParsedPayload::Tcp(seg) => {
                let fk = FlowKey {
                    src: parsed.src,
                    src_port: seg.src_port,
                    dst: parsed.dst,
                    dst_port: seg.dst_port,
                    is_udp: false,
                };
                if let Some(&id) = self.by_tuple.get(&fk) {
                    if seg.payload.is_empty() {
                        return Ok(None);
                    }
                    let sealed = self.mux.seal_data(&self.tx, id, &seg.payload, self.pad)?;
                    Ok(Some(vec![sealed]))
                } else {
                    let id = self.mux.open_tcp(&parsed.dst.to_string(), seg.dst_port)?;
                    self.by_tuple.insert(fk, id);
                    self.by_id.insert(
                        id,
                        FlowInfo {
                            client_ip: parsed.src,
                            client_port: seg.src_port,
                            server_ip: parsed.dst,
                            server_port: seg.dst_port,
                            is_udp: false,
                        },
                    );
                    let open = self.mux.seal_open_tcp(&self.tx, id, self.pad)?;
                    let data = self.mux.seal_data(&self.tx, id, &seg.payload, self.pad)?;
                    Ok(Some(vec![open, data]))
                }
            }
            ParsedPayload::Udp(dgram) => {
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
                let flow = self.by_id.get(&header.stream_id).ok_or_else(|| {
                    ClientError::RoutingError(format!("unknown stream {}", header.stream_id))
                })?;
                if flow.is_udp {
                    return Err(ClientError::RoutingError(format!(
                        "stream {} is udp, got DATA",
                        header.stream_id
                    )));
                }
                let payload = self.mux.open_data(&self.rx, header, ciphertext)?;
                let pkt = build_tcp_packet(
                    flow.server_ip,
                    flow.client_ip,
                    flow.server_port,
                    flow.client_port,
                    false,
                    true,
                    true,
                    0,
                    0,
                    &payload,
                );
                tun.send_packet(&pkt)?;
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
