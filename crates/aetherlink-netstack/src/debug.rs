//! Debug tracing for live bring-up (Phase W-live).
//!
//! Off by default; enabled with `AETHERLINK_DEBUG=1` (any non-empty value
//! except `0`). Traces go to stderr so thin hosts surface them without any
//! protocol change. NEVER log secrets here: PSK, nonces, keys, tokens must
//! not reach these call sites (callers pass names, codes and lengths only).

use std::sync::OnceLock;
use std::time::Instant;

static ENABLED: OnceLock<bool> = OnceLock::new();
static STARTED: OnceLock<Instant> = OnceLock::new();

/// Whether debug tracing is on (env read once per process).
#[must_use]
pub fn debug_enabled() -> bool {
    *ENABLED.get_or_init(|| match std::env::var("AETHERLINK_DEBUG") {
        Ok(v) => !(v.is_empty() || v == "0"),
        Err(_) => false,
    })
}

/// Milliseconds since first debug call (lets two hosts' logs correlate).
fn elapsed_ms() -> u128 {
    STARTED.get_or_init(Instant::now).elapsed().as_millis()
}

/// Emit one debug line (no-op unless enabled). Secrets must never be args.
pub fn debug_log(line: &str) {
    if debug_enabled() {
        eprintln!("[aetherlink-debug +{}ms] {line}", elapsed_ms());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default() {
        // Given: test env never sets the flag (parallel tests share env)
        // Then: helper is inert. (Enabled-path is live-verified, not CI.)
        assert!(!debug_enabled());
    }
}
