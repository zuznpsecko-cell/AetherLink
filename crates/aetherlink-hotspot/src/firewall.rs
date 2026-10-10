//! Fail-closed forwarding guard (DEC-014).
//!
//! One dedicated nftables table routes hotspot client traffic only into the
//! tunnel interface and drops everything else from the AP interface — so a
//! dead tunnel blocks clients instead of silently leaking them direct. The
//! table is owned end-to-end by the hotspot (apply on up, delete on down).

use crate::{run, run_quiet, HotspotError, Result};

/// nftables table name (owned; deleted on `down`).
pub const TABLE: &str = "aetherlink_hotspot";

/// Ruleset file (re-applied verbatim; inspected for debugging).
pub const RULESET_PATH: &str = "/run/aetherlink/hotspot.nft";

/// Tunnel interface client traffic is allowed into.
pub const TUN_IFACE: &str = "aether0";

/// The tunnel interface the guard protects, resolved against what actually
/// exists: `up` requests `aether0`, but the kernel may grant a renamed
/// device on name collision — guarding a ghost would fail-closed forever.
/// When nothing exists yet (hotspot before tunnel) fall back to the
/// canonical name.
#[must_use]
pub fn resolve_tun_iface() -> String {
    if std::path::Path::new(&format!("/sys/class/net/{TUN_IFACE}")).exists() {
        return TUN_IFACE.to_string();
    }
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with("aether"))
            .collect();
        names.sort();
        if let Some(first) = names.into_iter().next() {
            return first;
        }
    }
    TUN_IFACE.to_string()
}

/// Render the guard ruleset (pure; tested without privileges).
///
/// Rule order: MSS clamp for client SYNs (TUN MTU is smaller than WiFi's),
/// then conntrack-established both ways, then new wlan→tunnel, then drop
/// the rest of wlan-originated forwarding (LAN, physical uplink, other
/// clients). Forward policy stays `accept`: traffic not involving the AP
/// interface is untouched.
#[must_use]
pub fn ruleset_text(wlan_iface: &str, tun_iface: &str) -> String {
    format!(
        "table inet {TABLE} {{\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority 0; policy accept;\n\
         \x20   iifname \"{wlan_iface}\" meta l4proto tcp tcp flags & (syn) == syn tcp option maxseg size set rt mtu\n\
         \x20   ct state established,related accept\n\
         \x20   iifname \"{wlan_iface}\" oifname \"{tun_iface}\" accept\n\
         \x20   iifname \"{wlan_iface}\" drop\n\
         \x20 }}\n\
         }}\n"
    )
}

/// Apply the guard: delete any stale table, load the fresh one (idempotent).
/// Returns the tunnel interface name the ruleset was bound to.
pub fn apply(wlan_iface: &str) -> Result<String> {
    std::fs::create_dir_all("/run/aetherlink")
        .map_err(|e| HotspotError::Tool(format!("create /run/aetherlink: {e}")))?;
    let tun_iface = resolve_tun_iface();
    let text = ruleset_text(wlan_iface, &tun_iface);
    std::fs::write(RULESET_PATH, &text)
        .map_err(|e| HotspotError::Tool(format!("write {RULESET_PATH}: {e}")))?;
    // Idempotency: a stale table (crash between apply and state save) must
    // not make the reload fail.
    run_quiet("nft", &["delete".to_string(), "table".to_string(), "inet".to_string(), TABLE.to_string()]);
    run(
        "nft",
        &["-f".to_string(), RULESET_PATH.to_string()],
    )
    .map_err(|e| {
        HotspotError::Tool(format!(
            "{e} (install `nftables`: apt install nftables)"
        ))
    })?;
    Ok(tun_iface)
}

/// Delete the guard table. Best-effort by contract (teardown path): an
/// absent table, a missing `nft` binary and foreign failures are logged,
/// never propagated.
pub fn remove() -> Result<()> {
    run_quiet(
        "nft",
        &[
            "delete".to_string(),
            "table".to_string(),
            "inet".to_string(),
            TABLE.to_string(),
        ],
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_guards_wlan_and_clamps_mss() {
        let text = ruleset_text("wlan0", "aether0");
        assert!(text.contains("table inet aetherlink_hotspot"));
        assert!(text.contains("type filter hook forward priority 0; policy accept;"));
        // Clamp before any client SYN is accepted.
        let clamp = text.find("tcp option maxseg size set rt mtu").unwrap();
        // New client traffic may only exit via the tunnel...
        assert!(text.contains("iifname \"wlan0\" oifname \"aether0\" accept"));
        // ...and everything else from the AP is dropped (fail-closed).
        let allow_tun = text.find("oifname \"aether0\" accept").unwrap();
        let drop = text.find("iifname \"wlan0\" drop").unwrap();
        assert!(clamp < allow_tun && allow_tun < drop);
    }
}
