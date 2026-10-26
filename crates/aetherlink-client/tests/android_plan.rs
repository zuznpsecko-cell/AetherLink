//! P1-R1: the Android interface plan (`clientPlan`) is a JSON contract.
//!
//! Kotlin applies exactly this document to `VpnService.Builder`, so the test
//! pins the key set (no extra fields), the tunnel address, DNS, and the two
//! routes that must always be there: the tunnel itself and the virtual DNS.
//!
//! L0: pure logic, no device, no sockets.

use std::collections::BTreeSet;

use aetherlink_client::android_plan::{plan_json, AndroidPlan};
use aetherlink_client::config::ClientConfig;
use serde_json::{json, Value};

fn config(doc: Value) -> ClientConfig {
    ClientConfig::parse(&doc).expect("test config must parse")
}

/// `mode: all`, LAN-direct off -> routes are exactly `0.0.0.0/0` + DNS.
fn all_mode_config() -> ClientConfig {
    config(json!({
        "client": {
            "server_addr": "31.57.158.233:443",
            "psk": "test-psk",
            "full_tunnel": {
                "mtu": 1400,
                "include_private_lan_direct": false
            }
        }
    }))
}

#[test]
fn android_plan_all_mode_matches_the_json_contract() {
    let cfg = all_mode_config();

    let text = plan_json(&cfg).expect("plan must build");
    let plan: Value = serde_json::from_str(&text).expect("plan must be valid JSON");

    let object = plan.as_object().expect("plan must be a JSON object");
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "address",
            "apps",
            "block_ipv6",
            "dns",
            "mtu",
            "routes",
            "session",
        ]),
        "plan schema changed: {plan}"
    );

    assert_eq!(plan["session"], json!("AetherLink"));
    assert_eq!(plan["mtu"], json!(1400));
    assert_eq!(plan["address"], json!({ "ip": "10.255.0.2", "prefix": 30 }));
    assert_eq!(plan["dns"], json!(["10.255.0.1"]));
    assert_eq!(plan["apps"], json!({ "mode": "all", "packages": [] }));
    assert_eq!(plan["block_ipv6"], json!(true));

    let routes = plan["routes"].as_array().expect("routes must be an array");
    assert!(
        routes.contains(&json!({ "ip": "0.0.0.0", "prefix": 0 })),
        "full tunnel route missing: {routes:?}"
    );
    assert!(
        routes.contains(&json!({ "ip": "10.255.0.1", "prefix": 32 })),
        "DNS route must always be in the plan: {routes:?}"
    );
    assert!(
        routes
            .iter()
            .all(|route| route.as_object().is_some_and(|o| o.len() == 2)),
        "every route is exactly {{ip, prefix}}: {routes:?}"
    );
}

#[test]
fn typed_plan_serializes_to_the_same_document() {
    let cfg = all_mode_config();

    let from_json: Value = serde_json::from_str(&plan_json(&cfg).expect("plan must build"))
        .expect("plan must be valid JSON");
    let typed: Value =
        serde_json::to_value(AndroidPlan::from_config(&cfg)).expect("typed plan must serialize");

    assert_eq!(typed, from_json);
}
