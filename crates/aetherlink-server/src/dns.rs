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

/// Resolve one DNS query through the first answering upstream.
///
/// Tries each `"ip:port"` in order with `timeout` per attempt and returns
/// the first answer. A single silent upstream (DPI blackhole, dead resolver)
/// must not kill DNS for the whole tunnel.
pub fn resolve_any(query: &[u8], upstreams: &[String], timeout: Duration) -> Result<Vec<u8>> {
    let mut last_err = ServerError::DnsError("no upstreams configured".to_string());
    for upstream in upstreams {
        match resolve(query, upstream, timeout) {
            Ok(answer) => return Ok(answer),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Minimal empty NOERROR response for a blocked QNAME: copies the txid,
/// mirrors the question section, answers nothing. The app fails fast
/// (no records) instead of waiting out an upstream timeout, and nothing
/// leaks to upstream resolvers.
pub fn empty_response(query: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    if query.len() >= 2 {
        out[0] = query[0];
        out[1] = query[1];
    }
    let flags = if query.len() >= 4 {
        u16::from_be_bytes([query[2], query[3]])
    } else {
        0
    };
    // QR=1, NOERROR, keep RD; never TC.
    out[2..4].copy_from_slice(&((flags | 0x8000) & !0x0200).to_be_bytes());
    let qdcount = if query.len() >= 6 {
        u16::from_be_bytes([query[4], query[5]])
    } else {
        0
    };
    out[4..6].copy_from_slice(&qdcount.min(1).to_be_bytes());
    // AN/NS/AR counts stay zero.
    // Echo the question section verbatim (bounded walk, like the parser).
    let mut i = 12usize;
    while i < query.len() {
        let len = query[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 != 0 || len > 63 {
            break;
        }
        i += 1;
        match i.checked_add(len) {
            Some(end) if end <= query.len() => i = end,
            _ => break,
        }
        if i > 12 + 255 + 1 {
            break;
        }
    }
    let qtype_end = i.checked_add(4).unwrap_or(query.len()).min(query.len());
    out.extend_from_slice(&query[12..qtype_end]);
    out
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
