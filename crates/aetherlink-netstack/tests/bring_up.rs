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
        msg.contains("privilege")
            || msg.contains("admin")
            || msg.contains("root")
            || msg.contains("wintun"),
        "got: {msg}"
    );
}

#[test]
#[cfg(windows)]
fn open_attempts_real_driver_not_stub() {
    use aetherlink_netstack::tun::{TunConfig, TunInterface};
    // Given: valid config, wintun.dll beside the test binary CWD or not,
    // but no admin rights in CI/dev.
    // When: opening → Then: a REAL attempt happened — the error names the
    // driver or the missing privilege, never a "pending" stub message.
    let err = TunInterface::open_with(&TunConfig {
        name: "aether0".to_string(),
        mtu: 1400,
    })
    .expect_err("must fail unprivileged");
    let msg = err.to_string();
    assert!(
        !msg.contains("pending"),
        "no stub messages allowed, got: {msg}"
    );
    assert!(
        msg.contains("wintun")
            || msg.contains("Administrator")
            || msg.contains("admin")
            || msg.contains("privilege"),
        "got: {msg}"
    );
}

#[test]
fn open_validates_before_touching_driver() {
    use aetherlink_netstack::tun::{TunConfig, TunInterface};
    // Given: garbage config → Then: validation error, driver never touched.
    let err = TunInterface::open_with(&TunConfig {
        name: String::new(),
        mtu: 1400,
    })
    .expect_err("empty name");
    assert!(err.to_string().contains("bad tun name"), "got: {err}");
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

#[test]
fn tun_config_validation_rejects_garbage() {
    use aetherlink_netstack::tun::TunConfig;
    // Given: empty / overlong names and out-of-range MTUs
    // When: validating → Then: named errors before any privilege is touched.
    assert!(TunConfig {
        name: String::new(),
        mtu: 1400
    }
    .validate()
    .is_err());
    assert!(TunConfig {
        name: "a".repeat(16),
        mtu: 1400
    }
    .validate()
    .is_err());
    assert!(TunConfig {
        name: "aether0".to_string(),
        mtu: 0
    }
    .validate()
    .is_err());
    assert!(TunConfig {
        name: "aether0".to_string(),
        mtu: 9001
    }
    .validate()
    .is_err());
    // And: sane configs validate cleanly.
    assert!(TunConfig {
        name: "aether0".to_string(),
        mtu: 1400
    }
    .validate()
    .is_ok());
    assert!(TunConfig {
        name: "aether0".to_string(),
        mtu: 1280
    }
    .validate()
    .is_ok());
}

#[test]
fn open_with_valid_config_still_needs_privilege() {
    use aetherlink_netstack::tun::{TunConfig, TunInterface};
    // Given: valid config, unprivileged process
    // When: opening → Then: privilege error (ioctls land in platform task).
    let err = TunInterface::open_with(&TunConfig {
        name: "aether0".to_string(),
        mtu: 1400,
    })
    .expect_err("must fail here");
    let msg = err.to_string();
    assert!(
        msg.contains("privilege")
            || msg.contains("admin")
            || msg.contains("root")
            || msg.contains("wintun"),
        "got: {msg}"
    );
}
