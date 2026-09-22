//! Crash cleanup / `force_cleanup` (§5).
//!
//! Idempotent by contract: safe to call twice (down path + crash recovery).
//! Replays the persisted applied-change log through a fresh platform (the
//! applying process may be gone — the file is the only truth), then consumes
//! the state file. Absent state is a no-op; an unreadable file is dropped so
//! recovery never wedges on it.

use std::path::Path;

use aetherlink_netstack::tun::UpState;

use crate::platform::{Platform, RealPlatform};
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
    match UpState::load(path) {
        Ok(state) => {
            let mut platform = RealPlatform::new();
            match platform.restore_applied(&state) {
                Ok(()) => aetherlink_netstack::debug_log("force_cleanup: replay ok"),
                Err(e) => {
                    aetherlink_netstack::debug_log(&format!("force_cleanup: replay issues: {e}"));
                }
            }
        }
        Err(e) => {
            aetherlink_netstack::debug_log(&format!(
                "force_cleanup: unreadable state ({e}), dropping file"
            ));
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}
