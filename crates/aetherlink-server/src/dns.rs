//! Server DNS upstream resolution.
//!
//! Canonical list lives in `aetherlink_mux::dns` (single source of truth);
//! the server resolves flows against the primary first.

use std::time::Duration;

use crate::relay;
use crate::{Result, ServerError};

/// Primary upstream (`1.1.1.1:53`).
#[must_use]
pub fn upstream() -> &'static str {
    aetherlink_mux::dns::primary_upstream().unwrap_or("1.1.1.1:53")
}

/// Full upstream list, primary first.
#[must_use]
pub fn upstreams() -> &'static [&'static str] {
    aetherlink_mux::dns::upstreams()
}

/// Resolve one DNS query through `upstream` (`"ip:port"`), relaying the
/// answer back verbatim. Bounded by `timeout`.
pub fn resolve(query: &[u8], upstream: &str, timeout: Duration) -> Result<Vec<u8>> {
    let (host, port) = upstream
        .rsplit_once(':')
        .ok_or_else(|| ServerError::DnsError(format!("bad upstream {upstream}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ServerError::DnsError(format!("bad upstream {upstream}")))?;
    relay::relay_udp(host, port, query, timeout)
        .map_err(|e| ServerError::DnsError(format!("resolve via {upstream}: {e}")))
}
