//! AetherLink Protocol Specifications and Golden Tests
//!
//! This crate contains the canonical protocol specifications and golden test vectors
//! that all implementations must conform to. These tests are the source of truth
//! for the AetherLink wire protocol.
//!
//! Golden vectors live in `tests/golden.rs` (integration) so the spec crate
//! itself stays dependency-free of implementor crates.

/// Protocol version.
///
/// v2 adds the per-frame `generation` field that makes AEAD nonces unique
/// across recycled stream ids (see [`FRAME_GENERATION_SIZE`] and
/// `aetherlink_mux::manager::build_nonce`). Nonces in v1 were derived from
/// `(stream_id, sequence, type)` while the id space is explicitly recycled,
/// so a long-lived session eventually re-used `(id, 0, OpenTcp)` under one
/// traffic key — a catastrophic AEAD nonce reuse. v1 peers are refused at
/// the preface byte instead of silently failing frame authentication.
pub const PROTOCOL_VERSION: u8 = 2;

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

/// Wire layout of the 24-byte frame header (protocol v2).
///
/// ```text
///   offset  size  field
///   0       3     length      (24-bit BE, payload + padding + AEAD tag)
///   3       1     frame type
///   4       1     flags
///   5       2     stream id   (u16 BE)
///   7       4     sequence    (u32 BE)
///   11      4     generation  (u32 BE, v2)
///   15      9     reserved    (v2: fresh random, ignored on read)
/// ```
///
/// `generation` is what makes the AEAD nonce unique: ids are recycled once a
/// session outlives the 16-bit id space, so `(stream_id, sequence, type)`
/// alone repeats. The random tail carries no protocol meaning; it only keeps
/// the clear-text header from fingerprinting while the reserved bytes are
/// already on the wire (they were 13 zero bytes in v1, so v2 grows nothing).
pub const FRAME_GENERATION_OFFSET: usize = 11;
pub const FRAME_GENERATION_SIZE: usize = 4;
/// Reserved trailer: 4 bytes of `generation` + 9 random bytes.
pub const FRAME_RESERVED_SIZE: usize = FRAME_HEADER_SIZE - FRAME_GENERATION_OFFSET;
/// Random-only part of the reserved trailer.
pub const FRAME_HEADER_RANDOM_SIZE: usize = FRAME_RESERVED_SIZE - FRAME_GENERATION_SIZE;
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;
pub const DEFAULT_PAD_MULTIPLE: usize = 128;

/// Largest stream-id generation ever carried on the wire.
///
/// Generations are handed out per `(stream id, direction)` and stored as a
/// `u32`. Reaching this bound means one direction of one session recycled the
/// whole 16-bit id space 4 billion times, so the honest answer is to refuse
/// rather than wrap into a repeated nonce; the mux reports it as
/// `MuxError::NonceSpaceExhausted`, whose remedy is a rekey/reconnect.
pub const MAX_STREAM_GENERATION: u32 = u32::MAX - 1;

/// Build the 12-byte AEAD nonce for a frame under one traffic key.
///
/// ```text
///   offset size field
///   0      2    stream id  (u16 BE)
///   2      4    generation (u32 BE)
///   6      4    sequence   (u32 BE)
///   10     1    frame type
///   11     1    zero
/// ```
///
/// Uniqueness argument: the traffic key is fixed per session and direction,
/// `sequence` never repeats for a live `(id, generation)` because the sender
/// only ever increments it, and `generation` is strictly monotonic per
/// `(id, direction)` — it is bumped exactly when an id is re-registered after
/// being closed (`MuxManager::claim_generation`). Therefore no
/// `(id, generation, sequence, type)` tuple can be sealed twice, including the
/// OPEN frames that always use `sequence = 0`.
///
/// This lives in the spec crate on purpose: both sides derive the nonce here,
/// so the invariant is defined once instead of being re-implemented next to
/// each codec.
#[must_use]
pub fn build_nonce(
    id: u16,
    generation: u32,
    seq: u32,
    frame_type: FrameType,
) -> [u8; AEAD_NONCE_SIZE] {
    let mut n = [0u8; AEAD_NONCE_SIZE];
    n[0..2].copy_from_slice(&id.to_be_bytes());
    n[2..6].copy_from_slice(&generation.to_be_bytes());
    n[6..10].copy_from_slice(&seq.to_be_bytes());
    n[10] = frame_type as u8;
    n
}

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

    /// The crypto crate carries its own copy of the version (it is a
    /// dependency of this crate, so the arrow cannot point the other way).
    /// Editing one copy without the other breaks this test.
    #[test]
    fn protocol_version_matches_crypto_copy() {
        assert_eq!(
            crate::PROTOCOL_VERSION,
            aetherlink_crypto::PROTOCOL_VERSION,
            "aetherlink-protocol and aetherlink-crypto disagree on PROTOCOL_VERSION"
        );
    }
}
