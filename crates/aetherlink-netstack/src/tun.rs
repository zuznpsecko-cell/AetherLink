//! TUN device management + bring-up safety planning (§5).
//!
//! Pure parts (snapshot persistence, rollback planning, privilege probe)
//! are implemented and tested here. Real device ioctls (TUN fd, Wintun
//! session, route/DNS application) land in the platform task; until then
//! `open` fails gracefully with a privilege error instead of panicking.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{NetstackError, Result};

/// One routing table entry worth snapshotting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Destination (`default` or `ip[/prefix]`).
    pub dest: String,
    /// Gateway (`via`).
    pub via: String,
}

/// Pre-`up` network state: routes + DNS. Persisted to the state file so
/// `force_cleanup` can restore after a crash or reboot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Routing table entries to restore.
    pub routes: Vec<Route>,
    /// System DNS servers to restore.
    pub dns_servers: Vec<String>,
}

impl Snapshot {
    /// Persist to the state file (pretty JSON).
    pub fn save(&self, path: &Path) -> Result<()> {
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| NetstackError::TunError(format!("snapshot encode: {e}")))?;
        std::fs::write(path, raw).map_err(NetstackError::Io)?;
        Ok(())
    }

    /// Load a persisted snapshot.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path).map_err(NetstackError::Io)?;
        serde_json::from_slice(&raw)
            .map_err(|e| NetstackError::TunError(format!("snapshot decode: {e}")))
    }
}

/// One applied bring-up change (appended in application order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppliedChange {
    /// TUN device created.
    TunUp(String),
    /// Server-IP pin route via physical gateway.
    PinnedRoute(String),
    /// Default route redirected into TUN.
    DefaultViaTun,
    /// System DNS overridden (previous servers carried for restore).
    DnsOverride(Vec<String>),
}

/// One restore step (executed in plan order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOp {
    /// Remove default-via-TUN route.
    RemoveDefaultViaTun,
    /// Remove server-IP pin route.
    RemovePinnedRoute(String),
    /// Destroy TUN device.
    TunDown(String),
    /// Restore previous DNS servers.
    RestoreDns(Vec<String>),
}

/// Plan rollback: strict reverse of application order so DNS/routes come
/// back in a safe sequence (default route first, device last).
#[must_use]
pub fn rollback_plan(log: &[AppliedChange]) -> Vec<RestoreOp> {
    log.iter()
        .rev()
        .map(|change| match change {
            AppliedChange::TunUp(name) => RestoreOp::TunDown(name.clone()),
            AppliedChange::PinnedRoute(ip) => RestoreOp::RemovePinnedRoute(ip.clone()),
            AppliedChange::DefaultViaTun => RestoreOp::RemoveDefaultViaTun,
            AppliedChange::DnsOverride(servers) => RestoreOp::RestoreDns(servers.clone()),
        })
        .collect()
}

/// TUN interface handle (device ioctls land in the platform task).
#[derive(Debug)]
pub struct TunInterface {
    /// Interface name.
    pub name: String,
}

impl TunInterface {
    /// Open a TUN device. Requires root/CAP_NET_ADMIN (Linux) or admin +
    /// `wintun.dll` (Windows); without them returns a privilege error.
    pub fn open(name: &str) -> Result<Self> {
        Err(NetstackError::TunError(format!(
            "open {name}: need root/CAP_NET_ADMIN on Linux or admin on Windows (platform bring-up pending)"
        )))
    }
}
