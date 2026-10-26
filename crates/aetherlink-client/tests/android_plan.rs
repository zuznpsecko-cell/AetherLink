//! P1-R1: the Android interface plan (`clientPlan`) is a JSON contract.
//!
//! Kotlin applies exactly this document to `VpnService.Builder`, so the test
//! pins the key set (no extra fields), the tunnel address, DNS, and the two
//! routes that must always be there: the tunnel itself and the virtual DNS.
//!
//! L0: pure logic, no device, no sockets.

use std::collections::BTreeSet;

use aetherlink_client::android_plan::{
    plan_json, plan_json_for, AndroidPlan, AndroidSplit, SplitMode,
};
use aetherlink_client::config::ClientConfig;
use aetherlink_client::ClientError;
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
        serde_json::to_value(AndroidPlan::from_config(&cfg).expect("plan must build"))
            .expect("typed plan must serialize");

    assert_eq!(typed, from_json);
}

// --- P1-R2: split modes ---------------------------------------------------

fn plan_for(split: &AndroidSplit) -> Value {
    let text = plan_json_for(&all_mode_config(), split).expect("split must be valid");
    serde_json::from_str(&text).expect("plan must be valid JSON")
}

fn routes_of(plan: &Value) -> BTreeSet<(String, u8)> {
    plan["routes"]
        .as_array()
        .expect("routes must be an array")
        .iter()
        .map(|route| {
            (
                route["ip"].as_str().expect("ip").to_string(),
                u8::try_from(route["prefix"].as_u64().expect("prefix")).expect("prefix fits"),
            )
        })
        .collect()
}

#[test]
fn allow_mode_keeps_the_full_tunnel_and_sets_the_package_list() {
    let plan = plan_for(&AndroidSplit {
        mode: SplitMode::Allow,
        apps: vec![
            "com.example.app".to_string(),
            "org.mozilla.firefox".to_string(),
        ],
        subnets: vec![],
    });

    assert_eq!(
        plan["apps"],
        json!({
            "mode": "allow",
            "packages": ["com.example.app", "org.mozilla.firefox"]
        })
    );
    let routes = routes_of(&plan);
    assert!(routes.contains(&("0.0.0.0".to_string(), 0)), "{routes:?}");
    assert!(
        routes.contains(&("10.255.0.1".to_string(), 32)),
        "DNS route must survive app filtering: {routes:?}"
    );
}

#[test]
fn deny_mode_marks_the_list_as_deny() {
    let plan = plan_for(&AndroidSplit {
        mode: SplitMode::Deny,
        apps: vec!["com.example.tracker".to_string()],
        subnets: vec![],
    });

    assert_eq!(
        plan["apps"],
        json!({ "mode": "deny", "packages": ["com.example.tracker"] })
    );
}

#[test]
fn subnets_mode_routes_only_those_prefixes_plus_dns() {
    let plan = plan_for(&AndroidSplit {
        mode: SplitMode::Subnets,
        apps: vec![],
        subnets: vec!["10.0.0.0/8".to_string(), "192.168.10.0/24".to_string()],
    });

    assert_eq!(
        plan["apps"],
        json!({ "mode": "all", "packages": [] }),
        "subnet split filters by destination, not by app"
    );
    assert_eq!(
        routes_of(&plan),
        BTreeSet::from([
            ("10.0.0.0".to_string(), 8),
            ("192.168.10.0".to_string(), 24),
            ("10.255.0.1".to_string(), 32),
        ])
    );
}

#[test]
fn inconsistent_split_selections_are_rejected() {
    let cases: Vec<(AndroidSplit, &str)> = vec![
        (
            AndroidSplit {
                mode: SplitMode::Allow,
                apps: vec![],
                subnets: vec![],
            },
            "at least one package",
        ),
        (
            AndroidSplit {
                mode: SplitMode::Deny,
                apps: vec![],
                subnets: vec![],
            },
            "at least one package",
        ),
        (
            AndroidSplit {
                mode: SplitMode::All,
                apps: vec!["com.example.app".to_string()],
                subnets: vec![],
            },
            "all mode",
        ),
        (
            AndroidSplit {
                mode: SplitMode::Subnets,
                apps: vec![],
                subnets: vec![],
            },
            "at least one subnet",
        ),
        (
            AndroidSplit {
                mode: SplitMode::Subnets,
                apps: vec![],
                subnets: vec!["0.0.0.0/0".to_string()],
            },
            "0.0.0.0/0",
        ),
        (
            AndroidSplit {
                mode: SplitMode::Subnets,
                apps: vec![],
                subnets: vec!["10.0.0.0/33".to_string()],
            },
            "cidr",
        ),
        (
            AndroidSplit {
                mode: SplitMode::Subnets,
                apps: vec![],
                subnets: vec!["10.1.2.3/24".to_string()],
            },
            "host bits",
        ),
        (
            AndroidSplit {
                mode: SplitMode::Allow,
                apps: vec!["com..example".to_string()],
                subnets: vec![],
            },
            "package",
        ),
        (
            AndroidSplit {
                mode: SplitMode::Allow,
                apps: vec!["com.example app".to_string()],
                subnets: vec![],
            },
            "package",
        ),
    ];

    for (split, needle) in cases {
        let err =
            plan_json_for(&all_mode_config(), &split).expect_err("invalid split must be rejected");
        assert!(
            matches!(err, ClientError::ConfigError(_)),
            "wrong error kind for {split:?}: {err}"
        );
        let text = err.to_string().to_lowercase();
        assert!(
            text.contains(needle),
            "error for {split:?} must mention {needle:?}, got: {err}"
        );
    }
}
