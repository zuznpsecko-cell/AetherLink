//! Virtual DNS handling: intercept + tunnel-only policy.
//!
//! Invariant `DNS_NO_LEAK`: while the tunnel is up, every DNS query
//! (UDP/53 or TCP/53) goes through the tunnel to the virtual resolver
//! (`10.255.0.1:53`) and on to the server upstreams. System resolvers
//! must never be used.

use aetherlink_protocol::{DEFAULT_DNS_UPSTREAMS, VIRTUAL_DNS_IP, VIRTUAL_DNS_PORT};

/// Virtual resolver address.
#[must_use]
pub fn virtual_resolver() -> (&'static str, u16) {
    (VIRTUAL_DNS_IP, VIRTUAL_DNS_PORT)
}

/// True when `(addr, port)` targets the virtual resolver.
#[must_use]
pub fn is_virtual_dns(addr: &str, port: u16) -> bool {
    port == VIRTUAL_DNS_PORT && addr == VIRTUAL_DNS_IP
}

/// Canonical upstream resolver list (primary first).
#[must_use]
pub fn upstreams() -> &'static [&'static str] {
    DEFAULT_DNS_UPSTREAMS
}

/// Primary upstream (`1.1.1.1:53`).
#[must_use]
pub fn primary_upstream() -> Option<&'static str> {
    DEFAULT_DNS_UPSTREAMS.first().copied()
}

/// DNS must always go via tunnel when up (documents invariant).
#[must_use]
pub const fn dns_via_tunnel() -> bool {
    true
}

/// Re-export of the canonical default list (locks the contract).
#[must_use]
pub fn default_upstreams() -> &'static [&'static str] {
    DEFAULT_DNS_UPSTREAMS
}
