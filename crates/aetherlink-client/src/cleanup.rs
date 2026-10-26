//! Crash cleanup / `force_cleanup` (§5).
//!
//! Idempotent by contract: safe to call twice (down path + crash recovery).
//! Replays the persisted applied-change log through a fresh platform (the
//! applying process may be gone — the file is the only truth), then consumes
//! the state file. Absent state is a no-op for routes/DNS replay, but still
//! self-heals a stale tunnel DNS left on the physical adapter; an unreadable
//! file is dropped so recovery never wedges on it.

use std::path::Path;

use aetherlink_netstack::tun::{Snapshot, UpState};

use crate::platform::{Platform, RealPlatform};
use crate::Result;

/// Which host owns the network configuration behind a tunnel.
///
/// The crash-recovery log describes desktop mutations (route/netsh/DNS). On
/// Android those mutations never happen: `VpnService.Builder` owns the
/// interface, routes and DNS, and the OS tears them down with the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    /// Windows/Linux: routes, DNS and the state file are ours.
    Desktop,
    /// Android: only our own bookkeeping file is ours.
    Android,
}

/// Restore network+DNS from the default state file. Idempotent.
pub fn force_cleanup() -> Result<()> {
    force_cleanup_for(HostKind::Desktop)
}

/// Host-aware cleanup on the default state file.
///
/// `android_connect`/`android_disconnect` never write a desktop state file,
/// so an Android cleanup only clears a leftover one and returns: replaying,
/// snapshotting or resetting DNS would fail on a phone and could rewrite its
/// network settings.
pub fn force_cleanup_for(kind: HostKind) -> Result<()> {
    force_cleanup_for_with(
        kind,
        &mut RealPlatform::new(),
        &crate::platform::default_state_path(),
    )
}

/// Clear a stale tunnel DNS that outlived its state file. Returns true on repair.
///
/// A teardown that crashed before persisting (or whose state file was already
/// consumed) leaves `10.255.0.1` on the physical adapter. Nothing can be
/// replayed, so without this every later `up` fails with "run down/cleanup
/// first" while `cleanup` is a no-op — a permanent wedge.
pub fn heal_stale_dns(platform: &mut dyn Platform) -> bool {
    let Ok(snap) = platform.snapshot() else {
        return false;
    };
    if !snapshot_has_tunnel_dns(&snap) {
        return false;
    }
    let iface = platform.captured_iface().unwrap_or_default();
    aetherlink_netstack::debug_log(&format!(
        "force_cleanup: no state file, stale tunnel DNS on {iface}: resetting to DHCP"
    ));
    match platform.reset_dns_dhcp(&iface) {
        Ok(()) => {
            aetherlink_netstack::debug_log("force_cleanup: stale tunnel DNS reset");
            true
        }
        Err(e) => {
            aetherlink_netstack::debug_log(&format!(
                "force_cleanup: stale tunnel DNS reset failed: {e}"
            ));
            false
        }
    }
}

/// True when a snapshot still carries our virtual resolver.
fn snapshot_has_tunnel_dns(snap: &Snapshot) -> bool {
    snap.dns_servers
        .iter()
        .any(|s| s == &crate::lifecycle::VIRTUAL_DNS_IP.to_string())
}

/// Restore from an explicit state file, consuming it. Idempotent.
pub fn force_cleanup_from(path: &Path) -> Result<()> {
    force_cleanup_for_with(HostKind::Desktop, &mut RealPlatform::new(), path)
}

/// Host-aware cleanup with an explicit platform and state file.
///
/// The platform is a seam: tests prove that Android cleanup makes no call at
/// all, and that the desktop path still replays the log.
pub fn force_cleanup_for_with(
    kind: HostKind,
    platform: &mut dyn Platform,
    path: &Path,
) -> Result<()> {
    if kind == HostKind::Android {
        // The VPN interface and everything attached to it is gone with the
        // service. Our state file is the only leftover that is ours to drop:
        // there is no snapshot to replay and no host DNS to heal.
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        return Ok(());
    }
    force_cleanup_with(platform, path)
}

fn force_cleanup_with(platform: &mut dyn Platform, path: &Path) -> Result<()> {
    if !path.exists() {
        // Nothing to replay, but the adapter may still point at us: repair it
        // instead of leaving the next `up` permanently refused.
        let _ = heal_stale_dns(platform);
        return Ok(());
    }
    match UpState::load(path) {
        Ok(state) => match platform.restore_applied(&state) {
            Ok(()) => aetherlink_netstack::debug_log("force_cleanup: replay ok"),
            Err(e) => {
                aetherlink_netstack::debug_log(&format!("force_cleanup: replay issues: {e}"));
            }
        },
        Err(e) => {
            aetherlink_netstack::debug_log(&format!(
                "force_cleanup: unreadable state ({e}), dropping file"
            ));
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}
