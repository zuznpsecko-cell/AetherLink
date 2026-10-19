//! AetherLink Protocol Specifications and Golden Tests
//!
//! This crate contains the canonical protocol specifications and golden test vectors
//! that all implementations must conform to. These tests are the source of truth
//! for the AetherLink wire protocol.
//!
//! Golden vectors live in `tests/golden.rs` (integration) so the spec crate
//! itself stays dependency-free of implementor crates.

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Authentication constants
pub const AUTH_PREFIX: &[u8] = b"aetherlink-auth-v1";
pub const NONCE_SIZE: usize = 32;
pub const AUTH_TOKEN_SIZE: usize = 32;

/// AEAD constants
pub const AEAD_KEY_SIZE: usize = 32;
pub const AEAD_NONCE_SIZE: usize = 12;
pub const AEAD_TAG_SIZE: usize = 16;

/// Frame constants
pub const FRAME_HEADER_SIZE: usize = 24;
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;
pub const DEFAULT_PAD_MULTIPLE: usize = 128;

/// Address type for OPEN_TCP/OPEN_UDP frames
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrType {
    Domain = 0,
    Ipv4 = 1,
    Ipv6 = 2,
}

impl From<AddrType> for u8 {
    fn from(t: AddrType) -> u8 {
        t as u8
    }
}

/// Unknown address-type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrTypeError {
    /// Wire value has no address-type mapping.
    UnknownAddrType(u8),
}

impl core::fmt::Display for AddrTypeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownAddrType(v) => write!(f, "unknown address type {v}"),
        }
    }
}

impl std::error::Error for AddrTypeError {}

impl TryFrom<u8> for AddrType {
    type Error = AddrTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AddrType::Domain),
            1 => Ok(AddrType::Ipv4),
            2 => Ok(AddrType::Ipv6),
            _ => Err(AddrTypeError::UnknownAddrType(value)),
        }
    }
}

/// Frame types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0,
    OpenTcp = 1,
    Ping = 2,
    Auth = 3,
    WindowUpdate = 4,
    GoAway = 5,
    Rst = 6,
    OpenUdp = 7,
    UdpDatagram = 8,
    // DNS query/response are regular UDP flows to virtual DNS IP
}

impl From<FrameType> for u8 {
    fn from(t: FrameType) -> u8 {
        t as u8
    }
}

/// Unknown frame-type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameTypeError {
    /// Wire value has no frame-type mapping.
    UnknownFrameType(u8),
}

impl core::fmt::Display for FrameTypeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownFrameType(v) => write!(f, "unknown frame type {v}"),
        }
    }
}

impl std::error::Error for FrameTypeError {}

impl TryFrom<u8> for FrameType {
    type Error = FrameTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FrameType::Data),
            1 => Ok(FrameType::OpenTcp),
            2 => Ok(FrameType::Ping),
            3 => Ok(FrameType::Auth),
            4 => Ok(FrameType::WindowUpdate),
            5 => Ok(FrameType::GoAway),
            6 => Ok(FrameType::Rst),
            7 => Ok(FrameType::OpenUdp),
            8 => Ok(FrameType::UdpDatagram),
            _ => Err(FrameTypeError::UnknownFrameType(value)),
        }
    }
}

/// Key schedule constants
pub const HKDF_SALT: &[u8] = b"aetherlink-v1";
pub const HKDF_TX_LABEL: &[u8] = b"tx";
pub const HKDF_RX_LABEL: &[u8] = b"rx";

/// Default server DNS upstreams
pub const DEFAULT_DNS_UPSTREAMS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53"];

/// Default nonce replay cache TTL (5 minutes)
pub const DEFAULT_NONCE_TTL_SECS: u64 = 300;

/// ALPN protocols
pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Virtual DNS resolver IP (in TUN subnet)
pub const VIRTUAL_DNS_IP: &str = "10.255.0.1";
pub const VIRTUAL_DNS_PORT: u16 = 53;

/// Default TUN subnet
pub const DEFAULT_TUN_SUBNET: &str = "10.255.0.0/30";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_wire_values_are_fixed() {
        assert_eq!(u8::from(FrameType::Data), 0);
        assert_eq!(u8::from(FrameType::OpenTcp), 1);
        assert_eq!(u8::from(FrameType::Ping), 2);
        assert_eq!(u8::from(FrameType::Auth), 3);
        assert_eq!(u8::from(FrameType::WindowUpdate), 4);
        assert_eq!(u8::from(FrameType::GoAway), 5);
        assert_eq!(u8::from(FrameType::Rst), 6);
        assert_eq!(u8::from(FrameType::OpenUdp), 7);
        assert_eq!(u8::from(FrameType::UdpDatagram), 8);
    }

    #[test]
    fn frame_type_try_from_roundtrip() {
        assert_eq!(FrameType::try_from(0), Ok(FrameType::Data));
        assert_eq!(FrameType::try_from(8), Ok(FrameType::UdpDatagram));
    }

    #[test]
    fn frame_type_try_from_rejects_unknown_with_value() {
        assert_eq!(
            FrameType::try_from(9),
            Err(FrameTypeError::UnknownFrameType(9))
        );
        assert_eq!(
            FrameType::try_from(255),
            Err(FrameTypeError::UnknownFrameType(255))
        );
    }

    #[test]
    fn addr_type_wire_values_are_fixed() {
        assert_eq!(u8::from(AddrType::Domain), 0);
        assert_eq!(u8::from(AddrType::Ipv4), 1);
        assert_eq!(u8::from(AddrType::Ipv6), 2);
    }

    #[test]
    fn addr_type_try_from_roundtrip() {
        assert_eq!(AddrType::try_from(0), Ok(AddrType::Domain));
        assert_eq!(AddrType::try_from(1), Ok(AddrType::Ipv4));
        assert_eq!(AddrType::try_from(2), Ok(AddrType::Ipv6));
    }

    #[test]
    fn addr_type_try_from_rejects_unknown_with_value() {
        assert_eq!(
            AddrType::try_from(3),
            Err(AddrTypeError::UnknownAddrType(3))
        );
        assert_eq!(
            AddrType::try_from(255),
            Err(AddrTypeError::UnknownAddrType(255))
        );
    }
}
