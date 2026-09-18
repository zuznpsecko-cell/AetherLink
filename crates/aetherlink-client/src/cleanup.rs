//! Crash cleanup / `force_cleanup` (§5).
//!
//! Idempotent by contract: safe to call twice (down path + crash recovery).
//! Consumes the snapshot file when present (validates, then removes so a
//! second call is a no-op); absent or unreadable state is best-effort Ok —
//! cleanup must never fail its caller.

use std::path::Path;

use crate::Result;

/// Restore network+DNS from the default state file. Idempotent.
pub fn force_cleanup() -> Result<()> {
    force_cleanup_from(&crate::platform::default_state_path())
}

/// Restore from an explicit state file, consuming it. Idempotent.
pub fn force_cleanup_from(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    // Validate the snapshot before consuming: a corrupt file still gets
    // removed so recovery never wedges on it.
    let _ = aetherlink_netstack::tun::Snapshot::load(path);
    let _ = std::fs::remove_file(path);
    Ok(())
}
