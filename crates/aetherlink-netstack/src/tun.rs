//! TUN device management + bring-up safety planning (§5).
//!
//! Pure parts (snapshot persistence, rollback planning, privilege probe)
//! are implemented and tested here. Real device I/O: Wintun session on
//! Windows, `/dev/net/tun` ioctls on Linux. Route/DNS application lives in
//! the client platform module. Without privileges `open` fails gracefully
//! with a named error instead of panicking.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{NetstackError, Result};

/// `TUNSETIFF` (`_IOW('T', 202, int)`), stable kernel ABI — duplicated as a
/// constant so the build does not depend on which `libc` flavor exports it.
#[cfg(target_os = "linux")]
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Kernel `struct ifreq` (16-byte name + 24-byte union): hand-rolled so the
/// ioctl layout never depends on libc's per-target type aliases.
#[cfg(target_os = "linux")]
#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    flags: libc::c_short,
    _pad: [u8; 22],
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppliedChange {
    /// TUN device created.
    TunUp(String),
    /// Server-IP pin route via physical gateway.
    PinnedRoute(String),
    /// Custom direct rule route (`ip`, `base/prefix` or `lo-hi` display).
    DirectRoute(String),
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
            AppliedChange::DirectRoute(dest) => RestoreOp::RemovePinnedRoute(dest.clone()),
            AppliedChange::DefaultViaTun => RestoreOp::RemoveDefaultViaTun,
            AppliedChange::DnsOverride(servers) => RestoreOp::RestoreDns(servers.clone()),
        })
        .collect()
}

/// Previous default gateway from a snapshot, if one was captured.
///
/// Shared by bring-up (pin/direct routes go via it) and rollback (pin and
/// direct removals need the same gateway back).
#[must_use]
pub fn previous_gateway(snap: &Snapshot) -> Option<std::net::Ipv4Addr> {
    snap.routes
        .iter()
        .find(|r| r.dest == "default")
        .and_then(|r| r.via.parse().ok())
}

/// Crash-recovery state: pre-up snapshot plus the applied-change log.
///
/// `down`/`force_cleanup` replay `rollback_plan(applied)` so recovery works
/// even when the applying process is gone (only the file survives).
/// `dns_iface` is the physical interface DNS was forced on: a fresh
/// `cleanup` cannot re-derive it (the default route may point elsewhere by
/// then, e.g. another VPN came up), so it is persisted, not re-looked-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpState {
    /// Network state before `up`.
    pub snapshot: Snapshot,
    /// Mutations applied, in order (empty prefix = nothing applied yet).
    pub applied: Vec<AppliedChange>,
    /// Physical interface whose DNS was overridden.
    pub dns_iface: String,
    /// TUN adapter Win32 ifIndex at `up` time (egress binding for deletes
    /// after a crash, when no live handle exists).
    pub tun_ifindex: Option<u32>,
}

impl UpState {
    /// Persist to the state file (pretty JSON).
    pub fn save(&self, path: &Path) -> Result<()> {
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| NetstackError::TunError(format!("state encode: {e}")))?;
        std::fs::write(path, raw).map_err(NetstackError::Io)?;
        Ok(())
    }

    /// Load persisted state.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path).map_err(NetstackError::Io)?;
        serde_json::from_slice(&raw)
            .map_err(|e| NetstackError::TunError(format!("state decode: {e}")))
    }
}

/// Packet I/O over a TUN device (W3 bridge contract).
///
/// `FakeTun` in tests implements this in memory; the real `TunInterface`
/// drives wintun on Windows (Linux ioctls land in the platform task).
/// `Send` so the handle crosses into pump threads.
pub trait TunPackets: Send {
    /// Non-blocking receive: `Ok(None)` means no packet queued.
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>>;
    /// Send one raw IP packet into the device.
    fn send_packet(&mut self, pkt: &[u8]) -> Result<()>;
}

/// TUN interface handle (owns the driver session on Windows, the
/// `/dev/net/tun` descriptor on Linux).
pub struct TunInterface {
    /// Interface name.
    pub name: String,
    /// Interface MTU.
    pub mtu: u32,
    /// Live Wintun session; `None` until the platform task wires packet I/O.
    #[cfg(windows)]
    session: Option<std::sync::Arc<wintun::Session>>,
    /// Adapter handle, retained so `delete` needs no name lookup
    /// (open-by-name is unreliable across runs; the handle is exact).
    #[cfg(windows)]
    adapter: Option<std::sync::Arc<wintun::Adapter>>,
    /// Live `/dev/net/tun` descriptor (Linux). The device is created
    /// non-persistent, so closing the last fd deletes the interface —
    /// `delete` is exactly that, and a crashed host cannot leave stale TUNs.
    #[cfg(target_os = "linux")]
    fd: Option<std::fs::File>,
}

impl std::fmt::Debug for TunInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunInterface")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

// wintun::Session must cross into the pump thread later; prove it now.
#[cfg(windows)]
fn _assert_session_send(session: wintun::Session) -> impl Send {
    session
}

/// TUN creation parameters, validated before any privilege is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Interface name (`aether0`; ≤15 bytes, Linux IFNAMSIZ).
    pub name: String,
    /// MTU, 1280..=9000.
    pub mtu: u32,
}

impl TunConfig {
    /// Validate name + MTU without touching the OS.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.len() > 15 {
            return Err(NetstackError::TunError(format!(
                "bad tun name {:?} (1..=15 bytes)",
                self.name
            )));
        }
        if !(1280..=9000).contains(&self.mtu) {
            return Err(NetstackError::TunError(format!(
                "bad mtu {} (1280..=9000)",
                self.mtu
            )));
        }
        Ok(())
    }
}

impl TunInterface {
    /// Open a TUN device. Requires root/CAP_NET_ADMIN (Linux) or admin +
    /// `wintun.dll` (Windows); without them returns a privilege error.
    ///
    /// Real ioctls (`/dev/net/tun` TUNSETIFF, Wintun adapter + session)
    /// land in the platform task, which also gets to run them; until then
    /// this validates first and fails gracefully instead of panicking.
    pub fn open(name: &str) -> Result<Self> {
        Self::open_with(&TunConfig {
            name: name.to_string(),
            mtu: crate::DEFAULT_MTU as u32,
        })
    }

    /// Open with explicit parameters (validated, then driver attempt).
    pub fn open_with(config: &TunConfig) -> Result<Self> {
        config.validate()?;
        #[cfg(windows)]
        return Self::open_windows(config);
        #[cfg(target_os = "linux")]
        return Self::open_linux(config);
        #[cfg(not(any(windows, target_os = "linux")))]
        return Err(NetstackError::TunError(
            "TUN is implemented on Windows (Wintun) and Linux (/dev/net/tun) only".to_string(),
        ));
    }

    /// Linux open: `/dev/net/tun` + `TUNSETIFF` (IFF_TUN, no packet info).
    ///
    /// Needs root/CAP_NET_ADMIN; every failure names its cause (missing
    /// device node, missing privilege) instead of panicking. The fd is held
    /// non-blocking for the whole session; the interface is born DOWN —
    /// addressing/`up` is the platform step, mirroring the Wintun path.
    #[cfg(target_os = "linux")]
    fn open_linux(config: &TunConfig) -> Result<Self> {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| {
                NetstackError::TunError(if e.kind() == std::io::ErrorKind::NotFound {
                    "/dev/net/tun missing: `sudo modprobe tun` (or TUN disabled in this container)"
                        .to_string()
                } else {
                    format!("/dev/net/tun open: {e} (need root/CAP_NET_ADMIN)")
                })
            })?;
        let fd = file.as_raw_fd();
        let mut ifr = IfReq {
            name: [0; 16],
            flags: 0,
            _pad: [0; 22],
        };
        for (slot, byte) in ifr.name.iter_mut().zip(config.name.as_bytes()) {
            *slot = *byte as libc::c_char;
        }
        // IFF_TUN = 0x0001, IFF_NO_PI = 0x1000 (raw IP packets, no header).
        ifr.flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        if unsafe { libc::ioctl(fd, TUNSETIFF, &ifr as *const IfReq) } < 0 {
            let err = std::io::Error::last_os_error();
            return Err(NetstackError::TunError(format!(
                "TUNSETIFF '{}': {err} (need root/CAP_NET_ADMIN)",
                config.name
            )));
        }
        // The kernel may rewrite the name when the request collides; trust
        // what it granted, not what we asked for.
        let mut granted = Vec::new();
        for &c in &ifr.name {
            if c == 0 {
                break;
            }
            granted.push(c as u8);
        }
        let granted = String::from_utf8_lossy(&granted).into_owned();
        file.set_nonblocking(true)
            .map_err(|e| NetstackError::TunError(format!("tun nonblock: {e}")))?;
        crate::debug_log(&format!("tun: /dev/net/tun granted '{granted}'"));
        Ok(Self {
            name: granted,
            mtu: config.mtu,
            fd: Some(file),
        })
    }

    /// Windows open: load wintun.dll (next to the exe, then CWD), open or
    /// create the adapter (needs Administrator), start a ring session.
    #[cfg(windows)]
    fn open_windows(config: &TunConfig) -> Result<Self> {
        let lib = Self::load_wintun()?;
        crate::debug_log(&format!("wintun loaded for '{}'", config.name));
        let adapter = match wintun::Adapter::open(&lib, &config.name) {
            Ok(adapter) => {
                crate::debug_log(&format!("wintun open existing '{}'", config.name));
                adapter
            }
            Err(e) => {
                crate::debug_log(&format!(
                    "wintun open '{}' missed ({e}), creating",
                    config.name
                ));
                wintun::Adapter::create(&lib, &config.name, "AetherLink", None).map_err(|e| {
                    NetstackError::TunError(format!(
                        "wintun adapter '{}' needs Administrator rights: {e}",
                        config.name
                    ))
                })?
            }
        };
        // Wintun keeps an internal name ("aether0") apart from the Friendly
        // Name `netsh` addresses ("Local Area Connection N" by default).
        // Align them so `netsh interface ip set address` finds the device;
        // the OS registers renames asynchronously, hence retries.
        let mut last_err = String::new();
        let mut named = false;
        for attempt in 0..10 {
            match adapter.get_name() {
                Ok(current) if current == config.name => {
                    crate::debug_log(&format!(
                        "wintun friendly name already '{}' (attempt {attempt})",
                        config.name
                    ));
                    named = true;
                    break;
                }
                Ok(current) => {
                    crate::debug_log(&format!(
                        "wintun friendly name is '{current}', renaming to '{}' (attempt {attempt})",
                        config.name
                    ));
                    match adapter.set_name(&config.name) {
                        Ok(()) => {
                            named = true;
                            break;
                        }
                        Err(e) => {
                            last_err = format!("rename: {e}");
                        }
                    }
                }
                Err(e) => {
                    last_err = format!("get_name: {e}");
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        if !named {
            return Err(NetstackError::TunError(format!(
                "wintun adapter '{}' friendly-name sync failed: {last_err}",
                config.name
            )));
        }
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| {
                NetstackError::TunError(format!("wintun session failed (Administrator?): {e}"))
            })?;
        Ok(Self {
            name: config.name.clone(),
            mtu: config.mtu,
            session: Some(std::sync::Arc::new(session)),
            adapter: Some(adapter),
        })
    }
}

impl TunInterface {
    /// Win32 interface index of the held adapter (for `route ... if N`
    /// egress binding: Windows otherwise pins TUN-gatewayed routes to the
    /// physical NIC and traffic bypasses the tunnel — seen live).
    pub fn adapter_index(&self) -> Result<u32> {
        #[cfg(windows)]
        {
            self.adapter
                .as_ref()
                .ok_or_else(|| NetstackError::TunError("no adapter held".to_string()))?
                .get_adapter_index()
                .map_err(|e| NetstackError::TunError(format!("adapter index: {e}")))
        }
        #[cfg(target_os = "linux")]
        {
            let name = std::ffi::CString::new(self.name.clone())
                .map_err(|e| NetstackError::TunError(format!("ifindex name: {e}")))?;
            let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if idx == 0 {
                return Err(NetstackError::TunError(format!(
                    "if_nametoindex '{}': {}",
                    self.name,
                    std::io::Error::last_os_error()
                )));
            }
            Ok(idx)
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = self;
            Err(NetstackError::TunError(
                "adapter_index unsupported on this platform".to_string(),
            ))
        }
    }

    /// End the session and delete the wintun adapter (no accumulation).
    ///
    /// Consumes the handle: session drops first (device goes dark), then the
    /// last adapter ref unwraps for deletion. A foreign adapter (none held)
    /// is left alone — crash recovery deletes nothing it didn't open.
    pub fn delete(self) -> Result<()> {
        #[cfg(windows)]
        {
            let name = self.name.clone();
            drop(self.session);
            match self.adapter {
                Some(a) => match std::sync::Arc::try_unwrap(a) {
                    Ok(adapter) => adapter.delete().map_err(|e| {
                        NetstackError::TunError(format!("wintun delete '{name}': {e}"))
                    }),
                    Err(_) => Err(NetstackError::TunError(format!(
                        "wintun delete '{name}': handle still shared"
                    ))),
                },
                None => Ok(()),
            }
        }
        #[cfg(target_os = "linux")]
        {
            // The device was created non-persistent: `self` (and thus the
            // fd) is consumed right after this, and the kernel removes the
            // interface on the last close. No ioctl needed.
            crate::debug_log(&format!(
                "tun: '{}' fd released, kernel removes the device",
                self.name
            ));
            Ok(())
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = self;
            Err(NetstackError::TunError(
                "TUN delete unsupported on this platform".to_string(),
            ))
        }
    }
}

impl TunPackets for TunInterface {
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        #[cfg(windows)]
        {
            let sess = self
                .session
                .as_ref()
                .ok_or_else(|| NetstackError::TunError("wintun session not open".to_string()))?;
            sess.try_receive()
                .map(|opt| {
                    opt.map(|p| {
                        let b = p.bytes().to_vec();
                        crate::debug_log(&format!("tun: recv {}B", b.len()));
                        b
                    })
                })
                .map_err(|e| {
                    crate::debug_log(&format!("tun: recv failed: {e}"));
                    NetstackError::TunError(format!("wintun recv: {e}"))
                })
        }
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            let fd = self
                .fd
                .as_mut()
                .ok_or_else(|| NetstackError::TunError("tun fd not open".to_string()))?;
            // Jumbo-safe upper bound; TUN delivers one packet per read.
            let mut buf = vec![0u8; 65536];
            match fd.read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    crate::debug_log(&format!("tun: recv {n}B"));
                    Ok(Some(buf))
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => {
                    crate::debug_log(&format!("tun: recv failed: {e}"));
                    Err(NetstackError::TunError(format!("tun read: {e}")))
                }
            }
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = self;
            Err(NetstackError::TunError(
                "TUN recv unsupported on this platform".to_string(),
            ))
        }
    }

    fn send_packet(&mut self, pkt: &[u8]) -> Result<()> {
        #[cfg(windows)]
        {
            let sess = self
                .session
                .as_ref()
                .ok_or_else(|| NetstackError::TunError("wintun session not open".to_string()))?;
            let len = u16::try_from(pkt.len()).map_err(|_| {
                NetstackError::InvalidPacket(format!("packet too large {}", pkt.len()))
            })?;
            let mut slot = sess.allocate_send_packet(len).map_err(|e| {
                crate::debug_log(&format!("tun: alloc send failed: {e}"));
                NetstackError::TunError(format!("wintun alloc send: {e}"))
            })?;
            slot.bytes_mut().copy_from_slice(pkt);
            sess.send_packet(slot);
            crate::debug_log(&format!("tun: sent {}B", pkt.len()));
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            let fd = self
                .fd
                .as_mut()
                .ok_or_else(|| NetstackError::TunError("tun fd not open".to_string()))?;
            // A TUN packet must land as ONE write (one skb per write); the
            // qdisc can briefly fill up (EAGAIN), so retry that for a bounded
            // time. A short write would emit a truncated packet and then a
            // corrupt second one — fail named instead.
            for _ in 0..100 {
                match fd.write(pkt) {
                    Ok(n) if n == pkt.len() => {
                        crate::debug_log(&format!("tun: sent {}B", pkt.len()));
                        return Ok(());
                    }
                    Ok(n) => {
                        return Err(NetstackError::TunError(format!(
                            "tun write short ({n} of {}B); packet would corrupt",
                            pkt.len()
                        )));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(e) => {
                        crate::debug_log(&format!("tun: send failed: {e}"));
                        return Err(NetstackError::TunError(format!("tun write: {e}")));
                    }
                }
            }
            Err(NetstackError::TunError(
                "tun write: device stayed full".to_string(),
            ))
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = pkt;
            let _ = self;
            Err(NetstackError::TunError(
                "TUN send unsupported on this platform".to_string(),
            ))
        }
    }
}

impl TunInterface {
    /// Load wintun.dll: first next to the current executable (installed
    /// layout), then by default search rules (dev CWD).
    #[cfg(windows)]
    fn load_wintun() -> Result<wintun::Wintun> {
        let mut tried = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let path = dir.join("wintun.dll");
                tried.push(path.to_string_lossy().into_owned());
                match unsafe { wintun::load_from_path(&path) } {
                    Ok(lib) => return Ok(lib),
                    Err(e) => {
                        tried.push(format!("{e}"));
                    }
                }
            }
        }
        match unsafe { wintun::load() } {
            Ok(lib) => Ok(lib),
            Err(e) => Err(NetstackError::TunError(format!(
                "wintun.dll load failed (tried {}): {e}",
                tried.join(", ")
            ))),
        }
    }
}
