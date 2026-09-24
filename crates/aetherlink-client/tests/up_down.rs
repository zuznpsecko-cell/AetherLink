//! TDD RED: full client `up` over a fake platform (Phase C).
//!
//! No privileges needed: the fake backend records every mutation, so tests
//! prove ordering (pin → default → DNS), rollback-on-error, idempotency and
//! crash-recovery file handling at the policy level. Real ioctls stay behind
//! the `Platform` trait for the platform task.

use std::net::IpAddr;

use aetherlink_client::cleanup;
use aetherlink_client::config::ClientConfig;
use aetherlink_client::lifecycle;
use aetherlink_client::platform::{FakePlatform, Platform, Step};

fn test_config() -> ClientConfig {
    ClientConfig::parse(&serde_json::json!({
        "server_addr": "example.com:443",
        "psk": "test-psk-32-bytes-long-exactly!!",
        "dns_mode": "tunnel",
    }))
    .expect("test config")
}

fn temp_state(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("aether-{name}-state.json"))
}

#[test]
fn up_without_privilege_fails_without_traces() {
    // Given: platform whose TUN open fails (no privileges)
    let path = temp_state("no-privs");
    let _ = std::fs::remove_file(&path);
    let mut plat = FakePlatform::no_privilege(path.clone());
    // When: bringing up
    // Then: clean Err, routing/DNS tables untouched, no state file left
    assert!(lifecycle::up(&mut plat, &test_config()).is_err());
    assert_eq!(
        plat.routes().get("default").map(String::as_str),
        Some("192.168.1.1")
    );
    assert_eq!(plat.dns(), &vec!["192.168.1.1".to_string()]);
    assert!(!path.exists(), "failed up must leave no snapshot behind");
}

#[test]
fn down_after_failed_up_is_safe() {
    // Given: failed up (no privileges)
    let mut plat = FakePlatform::no_privilege(temp_state("down-safe"));
    assert!(lifecycle::up(&mut plat, &test_config()).is_err());
    // When: tearing down → Then: safe no-op Ok.
    lifecycle::down(&mut plat).expect("down after failed up");
    assert!(!plat.tun_exists());
}

#[test]
fn repeated_up_is_noop_when_up() {
    // Given: working platform, client already up
    let _ = std::fs::remove_file(temp_state("repeat"));
    let mut plat = FakePlatform::working(temp_state("repeat"));
    let mut client = aetherlink_client::Client::new_config(test_config());
    client.up_on(&mut plat).expect("first up");
    let calls = plat.applied_count();
    // When: bringing up again → Then: Ok, no duplicate changes applied.
    client.up_on(&mut plat).expect("second up");
    assert_eq!(plat.applied_count(), calls);
    assert!(client.is_up());
}

#[test]
fn rollback_restores_on_midway_failure() {
    // Given: platform failing exactly at the default-route step
    let mut plat = FakePlatform::failing_at(Step::DefaultViaTun, temp_state("rollback"));
    // When: bringing up → Then: Err, tables back to pre-up, no state file.
    assert!(lifecycle::up(&mut plat, &test_config()).is_err());
    assert_eq!(
        plat.routes().get("default").map(String::as_str),
        Some("192.168.1.1")
    );
    assert_eq!(plat.dns(), &vec!["192.168.1.1".to_string()]);
    assert!(!plat.tun_exists());
    assert!(!temp_state("rollback").exists());
}

#[test]
fn server_ip_pinned_via_previous_gateway() {
    // Given: working platform, server name resolving to a fixed IP
    let _ = std::fs::remove_file(temp_state("pin"));
    let mut plat = FakePlatform::working(temp_state("pin"));
    // When: up succeeds
    lifecycle::up(&mut plat, &test_config()).expect("up");
    // Then: pin route for the resolved server IP via the old gateway,
    // installed BEFORE the default switch (ordering proved by the log).
    let log = plat.call_log();
    let pin = log
        .iter()
        .position(|c| c.starts_with("apply:pin_route"))
        .expect("pin logged");
    let def = log
        .iter()
        .position(|c| c == "apply:default_via_tun")
        .expect("default logged");
    assert!(pin < def, "pin must precede default switch");
    assert!(plat.has_pinned("93.184.216.34"), "server IP pinned");
}

#[test]
fn dns_forced_to_virtual_resolver_on_up() {
    // Given: working platform
    let _ = std::fs::remove_file(temp_state("dns"));
    let mut plat = FakePlatform::working(temp_state("dns"));
    // When: up succeeds → Then: system DNS is the virtual resolver only.
    lifecycle::up(&mut plat, &test_config()).expect("up");
    assert_eq!(plat.dns(), &vec!["10.255.0.1".to_string()]);
}

#[test]
fn successful_up_writes_snapshot_down_removes_it() {
    // Given: working platform
    let path = temp_state("snap");
    let _ = std::fs::remove_file(&path);
    let mut plat = FakePlatform::working(path.clone());
    // When: up → Then: state file holds pre-up snapshot + applied log.
    lifecycle::up(&mut plat, &test_config()).expect("up");
    assert!(path.exists());
    let state = aetherlink_netstack::tun::UpState::load(&path).expect("load state");
    assert_eq!(state.snapshot.dns_servers, vec!["192.168.1.1".to_string()]);
    assert!(
        !state.applied.is_empty(),
        "applied log must record mutations"
    );
    // When: down → Then: snapshot consumed, device gone.
    lifecycle::down(&mut plat).expect("down");
    assert!(!plat.tun_exists());
}

#[test]
fn cleanup_consumes_state_file_idempotently() {
    // Given: a leftover snapshot file (simulated crash mid-up)
    let path = temp_state("crash");
    let snap = aetherlink_netstack::tun::Snapshot {
        routes: vec![],
        dns_servers: vec!["192.168.1.1".to_string()],
    };
    snap.save(&path).expect("save");
    // When: force cleanup twice → Then: both Ok, file consumed.
    cleanup::force_cleanup_from(&path).expect("first cleanup");
    assert!(!path.exists());
    cleanup::force_cleanup_from(&path).expect("second cleanup");
}

#[test]
fn cleanup_replays_empty_applied_log() {
    // Given: crash state with no applied mutations (fresh RealPlatform,
    // no netsh calls possible — replay must be a silent no-op).
    let path = temp_state("crash-empty");
    let state = aetherlink_netstack::tun::UpState {
        snapshot: aetherlink_netstack::tun::Snapshot {
            routes: vec![],
            dns_servers: vec!["192.168.1.1".to_string()],
        },
        applied: vec![],
        dns_iface: String::new(),
        tun_ifindex: None,
    };
    state.save(&path).expect("save");
    // When: force cleanup → Then: Ok, file consumed.
    cleanup::force_cleanup_from(&path).expect("cleanup");
    assert!(!path.exists());
}

#[test]
fn resolve_happens_before_any_mutation() {
    // Given: platform failing DNS resolution itself
    let mut plat = FakePlatform::failing_at(Step::Resolve, temp_state("resolve"));
    // When: up → Then: Err before a single mutation was attempted.
    assert!(lifecycle::up(&mut plat, &test_config()).is_err());
    assert!(plat.call_log().iter().all(|c| !c.starts_with("apply:")));
}

#[test]
fn custom_ip_rule_installed_direct() {
    // Given: config with an ip direct-rule
    let _ = std::fs::remove_file(temp_state("rules"));
    let mut plat = FakePlatform::working(temp_state("rules"));
    let cfg = ClientConfig::parse(&serde_json::json!({
        "server_addr": "example.com:443",
        "psk": "test-psk-32-bytes-long-exactly!!",
        "dns_mode": "tunnel",
        "routing": { "rules": [
            {"name": "one", "action": "direct", "priority": 40,
             "when": {"ip": "198.51.100.10"}}
        ]},
    }))
    .expect("cfg");
    // When: up → Then: direct route via the old gateway.
    lifecycle::up(&mut plat, &cfg).expect("up");
    assert_eq!(
        plat.routes().get("198.51.100.10").map(String::as_str),
        Some("192.168.1.1")
    );
}

#[test]
fn up_refuses_when_state_file_exists() {
    // Given: leftover state file from a previous (maybe crashed) up
    let path = temp_state("double-up");
    std::fs::write(&path, "{}").expect("plant state");
    let mut plat = FakePlatform::working(path.clone());
    // When: up → Then: Err before any mutation, file left for cleanup.
    assert!(lifecycle::up(&mut plat, &test_config()).is_err());
    assert_eq!(plat.applied_count(), 0);
    assert!(path.exists(), "guard must not consume foreign state");
    std::fs::remove_file(&path).ok();
}

#[test]
fn up_refuses_stale_tunnel_dns() {
    // Given: snapshot DNS already pointing at the virtual resolver
    // (previous teardown never finished)
    let path = temp_state("stale-dns");
    let _ = std::fs::remove_file(&path);
    let mut plat = FakePlatform::working(path.clone()).with_dns(vec!["10.255.0.1".to_string()]);
    // When: up → Then: Err before any mutation.
    assert!(lifecycle::up(&mut plat, &test_config()).is_err());
    assert_eq!(plat.applied_count(), 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn client_status_reflects_lifecycle() {
    // Given: fresh client
    let mut client = aetherlink_client::Client::new_config(test_config());
    let v: serde_json::Value =
        serde_json::from_str(&client.status().expect("status")).expect("json");
    assert_eq!(v["up"], false);
    // When: up on a working platform → Then: status flips.
    let _ = std::fs::remove_file(temp_state("status"));
    let mut plat = FakePlatform::working(temp_state("status"));
    client.up_on(&mut plat).expect("up");
    let v: serde_json::Value =
        serde_json::from_str(&client.status().expect("status")).expect("json");
    assert_eq!(v["up"], true);
    assert_eq!(v["dns_mode"], "tunnel");
}
