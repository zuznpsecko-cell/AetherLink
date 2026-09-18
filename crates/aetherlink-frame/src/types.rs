//! Frame type definitions and serialization
//!
//! Defines all AetherLink frame types and their payload serialization.

use aetherlink_protocol::FrameType;
use bytes::{Buf, BufMut, BytesMut};

pub use aetherlink_protocol::AddrType;

use crate::{FrameError, Result};

/// Complete frame with all types
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u16,
    pub sequence: u32,
    pub payload: FramePayload,
}

impl Frame {
    /// Create DATA frame
    pub fn data(stream_id: u16, sequence: u32, payload: Vec<u8>) -> Self {
        Self {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id,
            sequence,
            payload: FramePayload::Data(payload),
        }
    }

    /// Create OPEN_TCP frame
    pub fn open_tcp(stream_id: u16, sequence: u32, addr: String, port: u16) -> Self {
        // Determine address type
        let addr_type = if addr.parse::<std::net::Ipv4Addr>().is_ok() {
            AddrType::Ipv4
        } else if addr.parse::<std::net::Ipv6Addr>().is_ok() {
            AddrType::Ipv6
        } else {
            AddrType::Domain
        };

        Self {
            frame_type: FrameType::OpenTcp,
            flags: 0,
            stream_id,
            sequence,
            payload: FramePayload::OpenTcp {
                addr_type,
                addr,
                port,
            },
        }
    }

    /// Create PING frame
    pub fn ping(stream_id: u16) -> Self {
        Self {
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id,
            sequence: 0,
            payload: FramePayload::Empty,
        }
    }

    /// Create AUTH frame
    pub fn auth(client_nonce: [u8; 32], token: [u8; 32]) -> Self {
        Self {
            frame_type: FrameType::Auth,
            flags: 0,
            stream_id: 0,
            sequence: 0,
            payload: FramePayload::Auth {
                client_nonce,
                token,
            },
        }
    }

    /// Create WINDOW_UPDATE frame
    pub fn window_update(stream_id: u16, window_size: u32) -> Self {
        Self {
            frame_type: FrameType::WindowUpdate,
            flags: 0,
            stream_id,
            sequence: 0,
            payload: FramePayload::WindowUpdate(window_size),
        }
    }

    /// Create GOAWAY frame
    pub fn goaway(error_code: u32) -> Self {
        Self {
            frame_type: FrameType::GoAway,
            flags: 0,
            stream_id: 0,
            sequence: 0,
            payload: FramePayload::GoAway(error_code),
        }
    }

    /// Create RST frame
    pub fn rst(stream_id: u16, error_code: u32) -> Self {
        Self {
            frame_type: FrameType::Rst,
            flags: 0,
            stream_id,
            sequence: 0,
            payload: FramePayload::Rst(error_code),
        }
    }

    /// Create OPEN_UDP frame
    pub fn open_udp(stream_id: u16, addr: String, port: u16) -> Self {
        let addr_type = if addr.parse::<std::net::Ipv4Addr>().is_ok() {
            AddrType::Ipv4
        } else if addr.parse::<std::net::Ipv6Addr>().is_ok() {
            AddrType::Ipv6
        } else {
            AddrType::Domain
        };

        Self {
            frame_type: FrameType::OpenUdp,
            flags: 0,
            stream_id,
            sequence: 0,
            payload: FramePayload::OpenUdp {
                addr_type,
                addr,
                port,
            },
        }
    }

    /// Create UDP_DATAGRAM frame
    pub fn udp_datagram(stream_id: u16, payload: Vec<u8>) -> Self {
        Self {
            frame_type: FrameType::UdpDatagram,
            flags: 0,
            stream_id,
            sequence: 0,
            payload: FramePayload::UdpDatagram(payload),
        }
    }

    /// Serialize frame payload to bytes (for encryption)
    pub fn serialize_payload(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        self.payload.encode(&mut buf);
        buf.to_vec()
    }

    /// Deserialize frame payload from decrypted bytes
    pub fn deserialize_payload(
        frame_type: FrameType,
        data: &[u8],
        stream_id: u16,
        sequence: u32,
        flags: u8,
    ) -> Result<Self> {
        let mut buf = BytesMut::from(data);
        let payload = FramePayload::decode(frame_type, &mut buf)?;

        Ok(Self {
            frame_type,
            flags,
            stream_id,
            sequence,
            payload,
        })
    }
}

/// Frame payload variants
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FramePayload {
    /// DATA frame: raw application data
    Data(Vec<u8>),
    /// OPEN_TCP frame: address + port
    OpenTcp {
        addr_type: AddrType,
        addr: String,
        port: u16,
    },
    /// PING frame: empty
    Empty,
    /// AUTH frame: client nonce + token
    Auth {
        client_nonce: [u8; 32],
        token: [u8; 32],
    },
    /// WINDOW_UPDATE frame: window size
    WindowUpdate(u32),
    /// GOAWAY frame: error code
    GoAway(u32),
    /// RST frame: error code
    Rst(u32),
    /// OPEN_UDP frame: address + port
    OpenUdp {
        addr_type: AddrType,
        addr: String,
        port: u16,
    },
    /// UDP_DATAGRAM frame: raw UDP payload
    UdpDatagram(Vec<u8>),
}

impl FramePayload {
    /// Encode payload to buffer
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            FramePayload::Data(data) => {
                buf.put_slice(data);
            }
            FramePayload::OpenTcp {
                addr_type,
                addr,
                port,
            } => {
                buf.put_u8(*addr_type as u8);
                // Address: length-prefixed string
                let addr_bytes = addr.as_bytes();
                buf.put_u16(addr_bytes.len() as u16);
                buf.put_slice(addr_bytes);
                buf.put_u16(*port);
            }
            FramePayload::Empty => {
                // Nothing to encode
            }
            FramePayload::Auth {
                client_nonce,
                token,
            } => {
                buf.put_slice(client_nonce);
                buf.put_slice(token);
            }
            FramePayload::WindowUpdate(window_size) => {
                buf.put_u32(*window_size);
            }
            FramePayload::GoAway(error_code) => {
                buf.put_u32(*error_code);
            }
            FramePayload::Rst(error_code) => {
                buf.put_u32(*error_code);
            }
            FramePayload::OpenUdp {
                addr_type,
                addr,
                port,
            } => {
                buf.put_u8(*addr_type as u8);
                let addr_bytes = addr.as_bytes();
                buf.put_u16(addr_bytes.len() as u16);
                buf.put_slice(addr_bytes);
                buf.put_u16(*port);
            }
            FramePayload::UdpDatagram(data) => {
                buf.put_slice(data);
            }
        }
    }

    /// Decode payload from buffer
    fn decode(frame_type: FrameType, buf: &mut BytesMut) -> Result<Self> {
        match frame_type {
            FrameType::Data => {
                let data = buf.to_vec();
                Ok(FramePayload::Data(data))
            }
            FrameType::OpenTcp => {
                if buf.remaining() < 1 + 2 + 2 {
                    return Err(FrameError::InsufficientBuffer {
                        need: 5,
                        have: buf.remaining(),
                    });
                }
                let raw_addr_type = buf.get_u8();
                let addr_type = AddrType::try_from(raw_addr_type)
                    .map_err(|_| FrameError::InvalidFrameType(raw_addr_type))?;
                let addr_len = buf.get_u16() as usize;
                if buf.remaining() < addr_len + 2 {
                    return Err(FrameError::InsufficientBuffer {
                        need: addr_len + 2,
                        have: buf.remaining(),
                    });
                }
                let addr =
                    String::from_utf8(buf.copy_to_bytes(addr_len).to_vec()).map_err(|_| {
                        FrameError::InvalidPacket("Invalid UTF-8 in address".to_string())
                    })?;
                let port = buf.get_u16();
                Ok(FramePayload::OpenTcp {
                    addr_type,
                    addr,
                    port,
                })
            }
            FrameType::Ping => Ok(FramePayload::Empty),
            FrameType::Auth => {
                if buf.remaining() < 32 + 32 {
                    return Err(FrameError::InsufficientBuffer {
                        need: 64,
                        have: buf.remaining(),
                    });
                }
                let mut client_nonce = [0u8; 32];
                let mut token = [0u8; 32];
                client_nonce.copy_from_slice(&buf.copy_to_bytes(32));
                token.copy_from_slice(&buf.copy_to_bytes(32));
                Ok(FramePayload::Auth {
                    client_nonce,
                    token,
                })
            }
            FrameType::WindowUpdate => {
                if buf.remaining() < 4 {
                    return Err(FrameError::InsufficientBuffer {
                        need: 4,
                        have: buf.remaining(),
                    });
                }
                Ok(FramePayload::WindowUpdate(buf.get_u32()))
            }
            FrameType::GoAway => {
                if buf.remaining() < 4 {
                    return Err(FrameError::InsufficientBuffer {
                        need: 4,
                        have: buf.remaining(),
                    });
                }
                Ok(FramePayload::GoAway(buf.get_u32()))
            }
            FrameType::Rst => {
                if buf.remaining() < 4 {
                    return Err(FrameError::InsufficientBuffer {
                        need: 4,
                        have: buf.remaining(),
                    });
                }
                Ok(FramePayload::Rst(buf.get_u32()))
            }
            FrameType::OpenUdp => {
                if buf.remaining() < 1 + 2 + 2 {
                    return Err(FrameError::InsufficientBuffer {
                        need: 5,
                        have: buf.remaining(),
                    });
                }
                let raw_addr_type = buf.get_u8();
                let addr_type = AddrType::try_from(raw_addr_type)
                    .map_err(|_| FrameError::InvalidFrameType(raw_addr_type))?;
                let addr_len = buf.get_u16() as usize;
                if buf.remaining() < addr_len + 2 {
                    return Err(FrameError::InsufficientBuffer {
                        need: addr_len + 2,
                        have: buf.remaining(),
                    });
                }
                let addr =
                    String::from_utf8(buf.copy_to_bytes(addr_len).to_vec()).map_err(|_| {
                        FrameError::InvalidPacket("Invalid UTF-8 in address".to_string())
                    })?;
                let port = buf.get_u16();
                Ok(FramePayload::OpenUdp {
                    addr_type,
                    addr,
                    port,
                })
            }
            FrameType::UdpDatagram => {
                let data = buf.to_vec();
                Ok(FramePayload::UdpDatagram(data))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aetherlink_protocol::FrameType;

    #[test]
    fn test_data_frame_serialization() {
        let frame = Frame::data(1, 100, b"hello".to_vec());
        let serialized = frame.serialize_payload();
        assert_eq!(serialized, b"hello");
    }

    #[test]
    fn test_open_tcp_frame_domain() {
        let frame = Frame::open_tcp(3, 1, "example.com".to_string(), 443);
        let serialized = frame.serialize_payload();

        // Should be: addr_type(1) + addr_len(2) + addr + port(2)
        assert_eq!(serialized[0], AddrType::Domain as u8);
        assert_eq!(u16::from_be_bytes([serialized[1], serialized[2]]), 11); // "example.com".len()
        assert_eq!(&serialized[3..14], b"example.com");
        assert_eq!(u16::from_be_bytes([serialized[14], serialized[15]]), 443);
    }

    #[test]
    fn test_open_tcp_frame_ipv4() {
        let frame = Frame::open_tcp(3, 1, "192.168.1.1".to_string(), 80);
        let serialized = frame.serialize_payload();

        assert_eq!(serialized[0], AddrType::Ipv4 as u8);
    }

    #[test]
    fn test_open_tcp_frame_ipv6() {
        let frame = Frame::open_tcp(3, 1, "::1".to_string(), 80);
        let serialized = frame.serialize_payload();

        assert_eq!(serialized[0], AddrType::Ipv6 as u8);
    }

    #[test]
    fn test_auth_frame_serialization() {
        let nonce = [0x42u8; 32];
        let token = [0x24u8; 32];
        let frame = Frame::auth(nonce, token);
        let serialized = frame.serialize_payload();

        assert_eq!(serialized.len(), 64);
        assert_eq!(&serialized[0..32], &nonce);
        assert_eq!(&serialized[32..64], &token);
    }

    #[test]
    fn test_window_update_frame() {
        let frame = Frame::window_update(1, 1024);
        let serialized = frame.serialize_payload();

        assert_eq!(serialized.len(), 4);
        assert_eq!(
            u32::from_be_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]),
            1024
        );
    }

    #[test]
    fn test_goaway_frame() {
        let frame = Frame::goaway(0);
        let serialized = frame.serialize_payload();

        assert_eq!(serialized.len(), 4);
        assert_eq!(
            u32::from_be_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]),
            0
        );
    }

    #[test]
    fn test_rst_frame() {
        let frame = Frame::rst(5, 7);
        let serialized = frame.serialize_payload();

        assert_eq!(serialized.len(), 4);
        assert_eq!(
            u32::from_be_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]),
            7
        );
    }

    #[test]
    fn test_open_udp_frame() {
        let frame = Frame::open_udp(7, "8.8.8.8".to_string(), 53);
        let serialized = frame.serialize_payload();

        assert_eq!(serialized[0], AddrType::Ipv4 as u8);
        assert_eq!(u16::from_be_bytes([serialized[1], serialized[2]]), 7); // "8.8.8.8".len()
    }

    #[test]
    fn test_udp_datagram_frame() {
        let frame = Frame::udp_datagram(9, b"dns query".to_vec());
        let serialized = frame.serialize_payload();

        assert_eq!(serialized, b"dns query");
    }

    #[test]
    fn test_deserialize_open_tcp() {
        let mut buf = BytesMut::new();
        buf.put_u8(AddrType::Domain as u8);
        buf.put_u16(11);
        buf.put_slice(b"example.com");
        buf.put_u16(443);

        let payload = FramePayload::decode(FrameType::OpenTcp, &mut buf).unwrap();

        match payload {
            FramePayload::OpenTcp {
                addr_type,
                addr,
                port,
            } => {
                assert_eq!(addr_type, AddrType::Domain);
                assert_eq!(addr, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Wrong payload type"),
        }
    }

    #[test]
    fn test_deserialize_auth() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0x42u8; 32]);
        buf.put_slice(&[0x24u8; 32]);

        let payload = FramePayload::decode(FrameType::Auth, &mut buf).unwrap();

        match payload {
            FramePayload::Auth {
                client_nonce,
                token,
            } => {
                assert_eq!(client_nonce, [0x42u8; 32]);
                assert_eq!(token, [0x24u8; 32]);
            }
            _ => panic!("Wrong payload type"),
        }
    }
}
