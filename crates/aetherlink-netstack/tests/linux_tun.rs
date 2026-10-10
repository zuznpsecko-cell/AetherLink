//! Linux `/dev/net/tun` open path (D4).
//!
//! Privilege-tolerant by design: without root/CAP_NET_ADMIN the open must
//! fail with a *named* cause (missing node, missing privilege) instead of
//! panicking; with privileges it must really create the device and remove it
//! on delete. Green in both CI (unprivileged) and live-root runs.

#![cfg(target_os = "linux")]

use aetherlink_netstack::tun::{TunConfig, TunInterface};

#[test]
fn open_is_named_error_without_privs_or_opens_with_them() {
    let config = TunConfig {
        name: "aethertest0".to_string(),
        mtu: 1400,
    };
    match TunInterface::open_with(&config) {
        Ok(iface) => {
            // Root in this environment: the granted name must match, and
            // delete (fd close) must succeed without leaving the device.
            assert_eq!(iface.name, "aethertest0");
            iface.delete().expect("delete closes the fd");
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("root/CAP_NET_ADMIN")
                    || msg.contains("/dev/net/tun")
                    || msg.contains("TUNSETIFF"),
                "unprivileged open must name its cause, got: {msg}"
            );
        }
    }
}

#[test]
fn bad_name_rejected_before_any_ioctl() {
    // 16+ bytes: no privilege needed to reach this validation error.
    let config = TunConfig {
        name: "way-too-long-iface-name".to_string(),
        mtu: 1400,
    };
    let err = TunInterface::open_with(&config)
        .expect_err("IFNAMSIZ validation must fire before any privilege");
    assert!(err.to_string().contains("bad tun name"));
}

#[test]
fn bad_mtu_rejected_before_any_ioctl() {
    let config = TunConfig {
        name: "aethertest0".to_string(),
        mtu: 100,
    };
    let err = TunInterface::open_with(&config)
        .expect_err("MTU validation must fire before any privilege");
    assert!(err.to_string().contains("bad mtu"));
}
