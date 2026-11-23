//! Egress policy: which resolved addresses may the server dial (DEC-021).
//!
//! The client names every target (`OPEN_TCP` / `OPEN_UDP`), so without a policy
//! an authenticated peer can aim the relay at the host's own loopback, its LAN
//! or the cloud metadata endpoint (`169.254.169.254`). The check runs on
//! **resolved** addresses only: matching a name is what `blocklist` does, and a
//! name says nothing about where it points (`127.0.0.1.nip.io`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Refusal reason, kept small and `Copy` so callers can log it cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDenied {
    /// Loopback, private, link-local, CGNAT, ULA or unspecified address.
    Private,
    /// Matched an operator `deny` CIDR.
    Denied,
}

impl EgressDenied {
    /// Stable reason for logs / RST diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private or metadata address",
            Self::Denied => "denied by egress policy",
        }
    }
}

/// One CIDR entry (`10.0.0.0/8`, `2001:db8::/32`; a bare address means /32 or
/// /128).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `addr/len`. Returns `None` for garbage — the config layer turns
    /// that into a hard error, so a typo never silently widens the policy.
    #[must_use]
    pub fn parse(spec: &str) -> Option<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return None;
        }
        let (addr_part, len_part) = match spec.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (spec, None),
        };
        let base: IpAddr = addr_part.parse().ok()?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = match len_part {
            Some(l) => l.parse::<u8>().ok()?,
            None => max,
        };
        if prefix > max {
            return None;
        }
        Some(Self { base, prefix })
    }

    /// Does `ip` fall inside this range?
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                prefix_match(&base.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                prefix_match(&base.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Compare the first `prefix` bits of two equally sized address buffers.
fn prefix_match(base: &[u8], ip: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if base[..full] != ip[..full] {
        return false;
    }
    let rest = prefix % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rest);
    base[full] & mask == ip[full] & mask
}

/// Validated egress policy for one listener.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    deny_private: bool,
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
}

impl EgressPolicy {
    /// Policy that lets everything through (tests, and operators who opt out).
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            deny_private: false,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }

    /// Build from already-parsed parts; `deny_private` defaults to `true` at
    /// the config boundary, not here, so the caller states its intent.
    #[must_use]
    pub fn new(deny_private: bool, allow: Vec<Cidr>, deny: Vec<Cidr>) -> Self {
        Self {
            deny_private,
            allow,
            deny,
        }
    }

    /// Is this resolved address allowed as a relay target?
    ///
    /// Order: an explicit `allow` wins over everything (the operator asked for
    /// exactly this hole), then `deny`, then the private-range default.
    pub fn check(&self, ip: IpAddr) -> Result<(), EgressDenied> {
        // Normalise v4-mapped v6 so `::ffff:127.0.0.1` cannot slip past the
        // private check under a different family.
        let ip = normalise(ip);
        if self.allow.iter().any(|c| c.contains(ip)) {
            return Ok(());
        }
        if self.deny.iter().any(|c| c.contains(ip)) {
            return Err(EgressDenied::Denied);
        }
        if self.deny_private && is_private(ip) {
            return Err(EgressDenied::Private);
        }
        Ok(())
    }

    /// Whether the private-range default is on (for startup logging).
    #[must_use]
    pub fn denies_private(&self) -> bool {
        self.deny_private
    }
}

/// Unmap `::ffff:a.b.c.d` so both families go through one set of range checks.
fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Ranges that must never be reachable through the relay by default.
///
/// Deliberately includes the cloud metadata endpoint explicitly: it is link
/// local (`169.254.0.0/16`), but naming it documents the intent.
#[must_use]
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254.0.0/16 incl. 169.254.169.254
        || ip.is_broadcast()
        // `is_documentation` is unstable too: 192.0.2.0/24, 198.51.100.0/24,
        // 203.0.113.0/24 (RFC 5737) must not be relay targets either.
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || ip.is_unspecified()
        || o[0] == 0 // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking
        || o[0] >= 240 // 240.0.0.0/4 reserved + broadcast
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // `is_unique_local` / `is_unicast_link_local` are still unstable in std,
    // so the two ranges are matched by hand: fc00::/7 and fe80::/10.
    let unique_local = (s[0] & 0xfe00) == 0xfc00;
    let link_local = (s[0] & 0xffc0) == 0xfe80;
    ip.is_loopback()
        || ip.is_unspecified()
        || unique_local
        || link_local
        || s[0] == 0x2001 && s[1] == 0x0db8 // documentation
        || s[0] == 0x2002 // 6to4: embeds an arbitrary v4, refuses to reason
        || s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 // 100::/64 discard
        || ip.to_ipv4_mapped().is_some_and(is_private_v4)
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn cidr_parses_v4_and_v6_and_rejects_garbage() {
        assert!(Cidr::parse("10.0.0.0/8").is_some());
        assert!(Cidr::parse("10.0.0.1").is_some());
        assert!(Cidr::parse("2001:db8::/32").is_some());
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);
        assert_eq!(Cidr::parse("2001:db8::/129"), None);
        assert_eq!(Cidr::parse(""), None);
        assert_eq!(Cidr::parse("not-an-ip/8"), None);
        assert_eq!(Cidr::parse("10.0.0.0/abc"), None);
    }

    #[test]
    fn cidr_contains_respects_the_prefix() {
        let c = Cidr::parse("10.1.0.0/16").expect("cidr");
        assert!(c.contains("10.1.200.4".parse().expect("ip")));
        assert!(!c.contains("10.2.0.1".parse().expect("ip")));
        let v6 = Cidr::parse("2001:db8::/32").expect("cidr");
        assert!(v6.contains("2001:db8::1".parse().expect("ip")));
        assert!(!v6.contains("2001:db9::1".parse().expect("ip")));
    }
}
