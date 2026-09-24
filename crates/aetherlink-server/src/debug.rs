//! Debug tracing for live runs (mirrors `aetherlink-netstack::debug`).
//!
//! Duplicated on purpose: this crate must not gain a netstack dependency
//! just for logging (thin dependency discipline, like the AcceptAll test
//! helpers). Same contract: `AETHERLINK_DEBUG=1` enables stderr traces;
//! PSK, nonces, keys and tokens must never reach these call sites — log
//! ids, types, addresses, lengths and error strings only.

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
