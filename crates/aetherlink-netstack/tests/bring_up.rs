//! TDD RED: TUN bring-up safety (§5) at the pure-logic level.
//!
//! Snapshot/rollback planning and the up/down state machine need no
//! privileges and are fully tested here. Real device ioctls (TUN fd,
//! Wintun session, route/DNS application) land in the platform task;
//! until then `open`/`bring_up` fail gracefully instead of panicking.

use aetherlink_netstack::manager::NetstackManager;
use aetherlink_netstack::tun::{AppliedChange, Snapshot};

fn sample_snapshot() -> Snapshot {
    Snapshot {
        routes: vec![
            aetherlink_netstack::tun::Route {
                dest: "default".to_string(),
                via: "192.168.1.1".to_string(),
            },
            aetherlink_netstack::tun::Route {
                dest: "1.2.3.4".to_string(),
                via: "192.168.1.1".to_string(),
            },
        ],
        dns_servers: vec!["192.168.1.1".to_string()],
    }
}

#[test]
fn snapshot_roundtrip_via_state_file() {
    // Given: routes + DNS snapshot
    let snap = sample_snapshot();
    let path = std::env::temp_dir().join("aether-test-state.json");
    // When: saved and loaded back
    snap.save(&path).expect("save");
    let back = Snapshot::load(&path).expect("load");
    // Then: identical (crash recovery reads exactly this file)
    assert_eq!(back, snap);
    std::fs::remove_file(&path).ok();
}

#[test]
fn rollback_plan_reverses_lifo() {
    // Given: three applied changes in order
    let log = vec![
        AppliedChange::TunUp("aether0".to_string()),
        AppliedChange::PinnedRoute("9.9.9.9".to_string()),
        AppliedChange::DefaultViaTun,
    ];
    // When: planning rollback
    let plan = aetherlink_netstack::tun::rollback_plan(&log);
    // Then: strict reverse (DNS/routes restored in safe order)
    assert_eq!(
        plan,
        vec![
            aetherlink_netstack::tun::RestoreOp::RemoveDefaultViaTun,
            aetherlink_netstack::tun::RestoreOp::RemovePinnedRoute("9.9.9.9".to_string()),
            aetherlink_netstack::tun::RestoreOp::TunDown("aether0".to_string()),
        ]
    );
}

#[test]
fn down_without_up_is_safe() {
    // Given: never brought up
    let mut m = NetstackManager::bring_down_state();
    // When: tearing down
    // Then: no-op Ok
    m.down().expect("down without up");
    assert!(!m.is_up());
}

#[test]
fn open_needs_privilege_and_says_so() {
    // Given: unprivileged test process
    // When: opening a TUN device
    let err = aetherlink_netstack::tun::TunInterface::open("aether0").expect_err("must fail here");
    // Then: graceful privilege error, never a panic or half-created device
    let msg = err.to_string();
    assert!(
        msg.contains("privilege") || msg.contains("admin") || msg.contains("root"),
        "got: {msg}"
    );
}

#[test]
fn bring_up_without_privilege_fails_cleanly() {
    // Given: fresh manager, no privileges
    let mut m = NetstackManager::bring_down_state();
    // When: bringing up
    // Then: clean Err (platform bring-up lands later), state stays down
    assert!(m.bring_up(1400).is_err());
    assert!(!m.is_up());
}
