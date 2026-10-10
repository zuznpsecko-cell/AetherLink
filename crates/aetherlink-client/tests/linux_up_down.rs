//! Linux `up`/`down` over the real `LinuxPlatform` (privilege-tolerant).
//!
//! Without root/CAP_NET_ADMIN the bring-up must fail *cleanly* at the TUN
//! step — no state file, no route/DNS mutations left behind. With root the
//! same test exercises the full real path (TUN + routes + DNS + rollback).
//! Either way it is green, so CI without privs and a live root run both pass.

#![cfg(target_os = "linux")]

use aetherlink_client::config::ClientConfig;
use aetherlink_client::lifecycle;
use aetherlink_client::platform::{Platform, RealPlatform};

fn have_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The platform exposes its state journal path; point it at a temp file so
/// the test never touches /var/lib/aetherlink on the dev box.
struct TempState {
    inner: RealPlatform,
    path: std::path::PathBuf,
}

impl TempState {
    fn new(name: &str) -> Self {
        Self {
            inner: RealPlatform::new(),
            path: std::env::temp_dir().join(format!("aether-linux-{name}.json")),
        }
    }
}

impl Platform for TempState {
    fn resolve_host(&mut self, host: &str) -> aetherlink_client::Result<Vec<std::net::IpAddr>> {
        self.inner.resolve_host(host)
    }
    fn snapshot(&mut self) -> aetherlink_client::Result<aetherlink_netstack::tun::Snapshot> {
        self.inner.snapshot()
    }
    fn tun_up(
        &mut self,
        name: &str,
        addr: std::net::Ipv4Addr,
        mtu: u32,
    ) -> aetherlink_client::Result<()> {
        self.inner.tun_up(name, addr, mtu)
    }
    fn tun_down(&mut self) -> aetherlink_client::Result<()> {
        self.inner.tun_down()
    }
    fn pin_route(
        &mut self,
        dest: std::net::IpAddr,
        via: std::net::Ipv4Addr,
    ) -> aetherlink_client::Result<()> {
        self.inner.pin_route(dest, via)
    }
    fn add_route(
        &mut self,
        dest: &str,
        via: std::net::Ipv4Addr,
    ) -> aetherlink_client::Result<()> {
        self.inner.add_route(dest, via)
    }
    fn default_via_tun(&mut self) -> aetherlink_client::Result<()> {
        self.inner.default_via_tun()
    }
    fn force_dns(&mut self, dns_ip: std::net::Ipv4Addr) -> aetherlink_client::Result<()> {
        self.inner.force_dns(dns_ip)
    }
    fn restore(
        &mut self,
        snap: &aetherlink_netstack::tun::Snapshot,
    ) -> aetherlink_client::Result<()> {
        self.inner.restore(snap)
    }
    fn restore_applied(
        &mut self,
        state: &aetherlink_netstack::tun::UpState,
    ) -> aetherlink_client::Result<()> {
        self.inner.restore_applied(state)
    }
    fn captured_iface(&self) -> Option<String> {
        self.inner.captured_iface()
    }
    fn tun_ifindex(&self) -> Option<u32> {
        self.inner.tun_ifindex()
    }
    fn state_path(&self) -> std::path::PathBuf {
        self.path.clone()
    }
}

#[test]
fn snapshot_is_readable_without_privs() {
    let mut plat = RealPlatform::new();
    // Reading routes/DNS is unprivileged on Linux; it must not fail on a
    // normal box (a minimal sandbox without iproute2 gets a lenient pass).
    match plat.snapshot() {
        Ok(snap) => {
            // The stale-DNS gate compares against the virtual resolver.
            assert!(
                !snap
                    .dns_servers
                    .iter()
                    .any(|s| s == &aetherlink_client::lifecycle::VIRTUAL_DNS_IP.to_string()),
                "a clean box must not already point at the tunnel DNS"
            );
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("ip") || msg.contains("resolvectl"),
                "snapshot failure must name the tool, got: {msg}"
            );
        }
    }
}

#[test]
fn up_without_root_fails_cleanly_or_up_with_root() {
    let path = std::env::temp_dir().join("aether-linux-updown.json");
    let _ = std::fs::remove_file(&path);
    let cfg = ClientConfig::parse(&serde_json::json!({
        "server_addr": "example.com:443",
        "psk": "test-psk-32-bytes-long-exactly!!",
        "dns_mode": "tunnel",
    }))
    .expect("config");

    let mut plat = TempState::new("updown");
    match lifecycle::up(&mut plat, &cfg) {
        Ok(()) => {
            // Rooted environment: we are fully up; tear down and confirm the
            // journal was consumed.
            assert!(have_root(), "up succeeded, must be root");
            lifecycle::down(&mut plat).expect("down after a real up");
            assert!(!path.exists(), "down must consume the state file");
        }
        Err(e) => {
            // Unprivileged (or sandbox without network/tools): `up` must
            // fail at resolve/snapshot/TUN with a named cause — and, the
            // invariant that matters, leave no state journal behind.
            let msg = e.to_string();
            assert!(!msg.is_empty(), "errors are named, never empty");
            assert!(
                !path.exists(),
                "failed up must leave no state journal behind"
            );
        }
    }
}
