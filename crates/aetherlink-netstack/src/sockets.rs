//! Socket-level pump over smoltcp (no sockets API on the OS side needed).
//!
//! [`SocketPump`] owns an `Interface` on a queue device (no privileges:
//! packets are pushed in and drained out in memory), plus TCP/UDP sockets.
//! TUN bytes go in via [`SocketPump::inject`], stack replies come out via
//! [`SocketPump::take_tx`], flow events via [`SocketPump::poll_step`].
//! This is the layer that turns accepted TCP connections and UDP
//! associations into mux streams/flows; the TUN fd itself lands in the
//! platform task.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::storage::{PacketBuffer, PacketMetadata};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use crate::{NetstackError, Result};

/// In-memory TUN stand-in: `inject` pushes, `take_tx` drains.
#[derive(Debug, Default)]
struct QueueDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
}

struct QueueRx {
    buffer: Vec<u8>,
}

impl RxToken for QueueRx {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

struct QueueTx<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for QueueTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inbound.pop_front().map(|buffer| {
            let rx = QueueRx { buffer };
            let tx = QueueTx {
                queue: &mut self.outbound,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx {
            queue: &mut self.outbound,
        })
    }
}

/// Flow event observed since the previous poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PumpEvent {
    /// TCP handshake completed.
    TcpAccepted {
        /// Socket handle for `tcp_send`.
        handle: SocketHandle,
        /// Remote peer.
        peer: SocketAddr,
    },
    /// TCP payload arrived.
    TcpData {
        /// Socket handle.
        handle: SocketHandle,
        /// Payload bytes.
        data: Vec<u8>,
    },
    /// TCP connection closed by either side.
    TcpClosed {
        /// Socket handle.
        handle: SocketHandle,
    },
    /// UDP datagram arrived.
    UdpDatagram {
        /// Socket handle for `udp_send`.
        handle: SocketHandle,
        /// Payload bytes.
        data: Vec<u8>,
        /// Sender.
        from: SocketAddr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SockKind {
    Tcp,
    Udp,
}

/// Userspace TCP/UDP pump without privileges.
pub struct SocketPump {
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    kinds: HashMap<SocketHandle, SockKind>,
    established: HashSet<SocketHandle>,
    now_ms: i64,
    addr: Ipv4Addr,
}

fn std_endpoint(ep: IpEndpoint) -> Option<SocketAddr> {
    match ep.addr {
        IpAddress::Ipv4(addr) => {
            let o = addr.as_bytes();
            Some(SocketAddr::from((
                Ipv4Addr::new(o[0], o[1], o[2], o[3]),
                ep.port,
            )))
        }
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

impl SocketPump {
    /// Create a pump owning `tun_addr/32` (no I/O, no privileges).
    pub fn new(tun_addr: Ipv4Addr) -> Self {
        let mut device = QueueDevice::default();
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        let o = tun_addr.octets();
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(
                    IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])),
                    32,
                ))
                .ok();
        });
        // Replies need a covering route; on an Ip medium there is no ARP,
        // so packets keep their destination and go out as-is.
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(o[0], o[1], o[2], o[3]))
            .ok();
        Self {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            kinds: HashMap::new(),
            established: HashSet::new(),
            now_ms: 0,
            addr: tun_addr,
        }
    }

    /// Listen for TCP (the stack terminates connections itself, TUN-style).
    pub fn tcp_listen(&mut self, port: u16) -> SocketHandle {
        let rx = tcp::SocketBuffer::new(vec![0u8; 65535]);
        let tx = tcp::SocketBuffer::new(vec![0u8; 65535]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket.listen(port).expect("listen port");
        let handle = self.sockets.add(socket);
        self.kinds.insert(handle, SockKind::Tcp);
        handle
    }

    /// Bind a UDP socket (e.g. the virtual DNS resolver port).
    pub fn udp_bind(&mut self, port: u16) -> SocketHandle {
        let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 16], vec![0u8; 65535]);
        let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 16], vec![0u8; 65535]);
        let mut socket = udp::Socket::new(rx, tx);
        socket.bind(port).expect("bind port");
        let handle = self.sockets.add(socket);
        self.kinds.insert(handle, SockKind::Udp);
        handle
    }

    /// Feed raw TUN bytes into the stack (no parsing here).
    pub fn inject(&mut self, raw: &[u8]) {
        self.device.inbound.push_back(raw.to_vec());
    }

    /// Advance the clock, pump packets, collect flow events.
    pub fn poll_step(&mut self, step_ms: i64) -> Vec<PumpEvent> {
        self.now_ms = self.now_ms.saturating_add(step_ms.max(0));
        let now = Instant::from_millis(self.now_ms);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.drain_events()
    }

    /// Take packets the stack emitted toward TUN.
    pub fn take_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.outbound.drain(..).collect()
    }

    /// Send TCP payload on an established flow.
    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> Result<()> {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket
            .send_slice(data)
            .map(|_| ())
            .map_err(|_| NetstackError::InvalidPacket("tcp send blocked".to_string()))
    }

    /// Send a UDP datagram back to `to`.
    pub fn udp_send(&mut self, handle: SocketHandle, data: &[u8], to: SocketAddr) -> Result<()> {
        let endpoint = match to {
            SocketAddr::V4(v4) => {
                let o = v4.ip().octets();
                IpEndpoint::new(
                    IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])),
                    v4.port(),
                )
            }
            SocketAddr::V6(_) => {
                return Err(NetstackError::InvalidPacket(
                    "ipv6 to unsupported".to_string(),
                ));
            }
        };
        let socket = self.sockets.get_mut::<udp::Socket>(handle);
        socket
            .send_slice(data, endpoint)
            .map(|_| ())
            .map_err(|_| NetstackError::InvalidPacket("udp send blocked".to_string()))
    }

    /// Our TUN address (for target matching upstream).
    #[must_use]
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    fn drain_events(&mut self) -> Vec<PumpEvent> {
        let mut out = Vec::new();
        let handles: Vec<SocketHandle> = self.sockets.iter().map(|(h, _)| h).collect();
        for handle in handles {
            match self.kinds.get(&handle) {
                Some(SockKind::Tcp) => self.drain_tcp(handle, &mut out),
                Some(SockKind::Udp) => self.drain_udp(handle, &mut out),
                None => {}
            }
        }
        out
    }

    fn drain_tcp(&mut self, handle: SocketHandle, out: &mut Vec<PumpEvent>) {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        match socket.state() {
            tcp::State::Established => {
                if self.established.insert(handle) {
                    if let Some(peer) = socket.remote_endpoint().and_then(std_endpoint) {
                        out.push(PumpEvent::TcpAccepted { handle, peer });
                    }
                }
                while socket.can_recv() {
                    let mut buf = [0u8; 4096];
                    match socket.recv_slice(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => out.push(PumpEvent::TcpData {
                            handle,
                            data: buf[..n].to_vec(),
                        }),
                    }
                }
            }
            tcp::State::Closed => {
                if self.established.remove(&handle) {
                    out.push(PumpEvent::TcpClosed { handle });
                }
            }
            _ => {}
        }
    }

    fn drain_udp(&mut self, handle: SocketHandle, out: &mut Vec<PumpEvent>) {
        let socket = self.sockets.get_mut::<udp::Socket>(handle);
        while socket.can_recv() {
            match socket.recv() {
                Ok((data, meta)) => {
                    if let Some(from) = std_endpoint(meta.endpoint) {
                        out.push(PumpEvent::UdpDatagram {
                            handle,
                            data: data.to_vec(),
                            from,
                        });
                    }
                }
                Err(_) => break,
            }
        }
    }
}
