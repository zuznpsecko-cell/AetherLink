//! Client DNS override: tunnel-only policy (§1.3 `DNS_NO_LEAK`).
//!
//! Policy layer: while the tunnel is up, system DNS must resolve via the
//! virtual resolver (`10.255.0.1:53`). Platform application (interface DNS,
//! NRPT, resolv.conf, VpnService) lands in the platform task.

use crate::Result;

/// Active DNS mode. Only `tunnel` is allowed while up.
#[must_use]
pub fn mode() -> &'static str {
    "tunnel"
}

/// Force DNS through the tunnel (policy gate; platform override follows).
pub fn force_tunnel_dns() -> Result<()> {
    debug_assert_eq!(mode(), "tunnel");
    Ok(())
}
