//! P1-R8: `force_cleanup` must be host-aware.
//!
//! On desktop the applied-change log is the only truth after a crash: it is
//! replayed through a fresh platform and then consumed. On Android there is
//! nothing to replay and nothing to heal: the VPN interface, its routes and
//! DNS live inside `VpnService` and vanish with the service. Touching the
//! host (snapshot, `netsh`, DNS reset) would fail or, worse, rewrite the
//! phone's network settings. Only our own bookkeeping file is ours to drop.
//!
//! L0: fake platform, temp state files.

use std::path::{Path, PathBuf};

use aetherlink_client::cleanup::{force_cleanup_for_with, HostKind};
use aetherlink_client::lifecycle::VIRTUAL_DNS_IP;
use aetherlink_client::platform::FakePlatform;
use aetherlink_netstack::tun::{AppliedChange, Snapshot, UpState};

/// Unique per test and per run: the suite runs tests in parallel threads.
fn temp_state(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "aetherlink-cleanup-{name}-{}.json",
        std::process::id()
    ))
}

/// A state file as a crashed `up` leaves it.
fn plant_crash_state(path: &Path) {
    UpState {
        snapshot: Snapshot {
            routes: vec![],
            dns_servers: vec!["192.168.1.1".to_string()],
        },
        applied: vec![
            AppliedChange::DefaultViaTun,
            AppliedChange::DnsOverride(vec!["192.168.1.1".to_string()]),
        ],
        dns_iface: "Ethernet".to_string(),
        tun_ifindex: None,
    }
    .save(path)
    .expect("plant state");
}

/// The strongest form of "Android must not touch the platform": the fake is
/// left carrying our stale tunnel resolver, so any `snapshot`/`heal` call
/// would show up and change it.
#[test]
fn android_cleanup_never_touches_the_platform() {
    let path = temp_state("android-untouched");
    plant_crash_state(&path);
    let mut platform =
        FakePlatform::working(path.clone()).with_dns(vec![VIRTUAL_DNS_IP.to_string()]);

    force_cleanup_for_with(HostKind::Android, &mut platform, &path).expect("android cleanup");

    assert!(
        platform.call_log().is_empty(),
        "Android cleanup must not call the platform at all: {:?}",
        platform.call_log()
    );
    assert_eq!(
        platform.dns(),
        &vec![VIRTUAL_DNS_IP.to_string()],
        "the phone's DNS belongs to VpnService, not to us"
    );
}

#[test]
fn android_cleanup_consumes_its_own_state_file() {
    let path = temp_state("android-state");
    plant_crash_state(&path);

    force_cleanup_for_with(
        HostKind::Android,
        &mut FakePlatform::working(path.clone()),
        &path,
    )
    .expect("first android cleanup");
    assert!(!path.exists(), "the state file must be consumed");

    // Second call: nothing left, still a successful no-op.
    force_cleanup_for_with(
        HostKind::Android,
        &mut FakePlatform::working(path.clone()),
        &path,
    )
    .expect("second android cleanup");
    force_cleanup_for_with(
        HostKind::Android,
        &mut FakePlatform::working(path.clone()),
        &temp_state("android-absent"),
    )
    .expect("android cleanup without a state file");
}

/// Desktop keeps the exact old contract: an existing state file is replayed
/// through the platform and then consumed.
#[test]
fn desktop_cleanup_still_replays_the_applied_log() {
    let path = temp_state("desktop-replay");
    plant_crash_state(&path);
    let mut platform = FakePlatform::working(path.clone());

    force_cleanup_for_with(HostKind::Desktop, &mut platform, &path).expect("desktop cleanup");

    assert!(
        platform.call_log().iter().any(|c| c == "restore"),
        "desktop must replay the snapshot on the platform: {:?}",
        platform.call_log()
    );
    assert!(!path.exists(), "the replayed state file is consumed");
}

/// ...and without a state file it still repairs a stale tunnel resolver,
/// which is what makes the "run cleanup first" wedge recoverable.
#[test]
fn desktop_cleanup_heals_stale_dns_without_a_state_file() {
    let path = temp_state("desktop-heal");
    let _ = std::fs::remove_file(&path);
    let mut platform =
        FakePlatform::working(path.clone()).with_dns(vec![VIRTUAL_DNS_IP.to_string()]);

    force_cleanup_for_with(HostKind::Desktop, &mut platform, &path).expect("desktop cleanup");

    assert!(
        platform.call_log().iter().any(|c| c == "snapshot"),
        "desktop cleanup inspects DNS when nothing is left to replay: {:?}",
        platform.call_log()
    );
    assert_eq!(
        platform.dns(),
        &vec!["192.168.1.1".to_string()],
        "a stale tunnel resolver must go back to DHCP"
    );
}
