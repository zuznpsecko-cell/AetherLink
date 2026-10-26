//! P1-R1: the Android interface plan (`clientPlan`) is a JSON contract.
//!
//! Kotlin applies exactly this document to `VpnService.Builder`, so the test
//! pins the key set (no extra fields), the tunnel address, DNS, and the two
//! routes that must always be there: the tunnel itself and the virtual DNS.
//!
//! L0: pure logic, no device, no sockets.

use std::collections::BTreeSet;

use aetherlink_client::android_plan::{
    plan_json, plan_json_for, subtract_prefixes, AndroidPlan, AndroidSplit, IpPrefix, SplitMode,
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

// --- P1-R3: LAN-direct subtraction ---------------------------------------

fn lan_direct_config() -> ClientConfig {
    config(json!({
        "client": {
            "server_addr": "31.57.158.233:443",
            "psk": "test-psk",
            "full_tunnel": {
                "mtu": 1400,
                "include_private_lan_direct": true
            }
        }
    }))
}

fn covers(routes: &BTreeSet<(String, u8)>, ip: &str) -> bool {
    let addr: u32 = u32::from(ip.parse::<std::net::Ipv4Addr>().expect("test ip"));
    routes.iter().any(|(net, prefix)| {
        let net: u32 = u32::from(net.parse::<std::net::Ipv4Addr>().expect("route ip"));
        let mask = if *prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(*prefix))
        };
        addr & mask == net
    })
}

#[test]
fn lan_direct_keeps_public_traffic_and_the_tunnel_routes() {
    let text = plan_json(&lan_direct_config()).expect("plan must build");
    let plan: Value = serde_json::from_str(&text).expect("valid JSON");
    let routes = routes_of(&plan);

    for public in [
        "8.8.8.8",
        "1.1.1.1",
        "203.0.113.5",
        "172.32.0.1",
        "192.169.1.1",
    ] {
        assert!(
            covers(&routes, public),
            "{public} must stay in the tunnel: {routes:?}"
        );
    }
    for lan in ["10.1.2.3", "172.16.5.4", "172.31.255.254", "192.168.1.1"] {
        assert!(
            !covers(&routes, lan),
            "{lan} must bypass the tunnel (LAN direct)"
        );
    }
    for tunnel in ["10.255.0.1", "10.255.0.2"] {
        assert!(
            covers(&routes, tunnel),
            "{tunnel} is part of the tunnel: {routes:?}"
        );
    }
    assert!(
        routes.contains(&("10.255.0.1".to_string(), 32)),
        "the DNS route is always explicit: {routes:?}"
    );
    assert!(
        routes.contains(&("10.255.0.0".to_string(), 30)),
        "the tunnel network is never subtracted: {routes:?}"
    );
}

fn prefixes(list: &[(&str, u8)]) -> Vec<IpPrefix> {
    list.iter()
        .map(|(ip, prefix)| IpPrefix::new(ip, *prefix))
        .collect()
}

fn as_set(list: &[IpPrefix]) -> BTreeSet<(String, u8)> {
    list.iter().map(|p| (p.ip.clone(), p.prefix)).collect()
}

#[test]
fn subtract_prefixes_handles_the_edge_cases() {
    // Nothing excluded -> unchanged (normalized).
    assert_eq!(
        as_set(&subtract_prefixes(&prefixes(&[("0.0.0.0", 0)]), &[])),
        as_set(&prefixes(&[("0.0.0.0", 0)]))
    );

    // Excluding the whole range leaves nothing.
    assert!(
        subtract_prefixes(&prefixes(&[("10.0.0.0", 8)]), &prefixes(&[("10.0.0.0", 8)])).is_empty()
    );
    assert!(
        subtract_prefixes(&prefixes(&[("10.0.0.0", 8)]), &prefixes(&[("0.0.0.0", 0)])).is_empty()
    );

    // Excluding the lower half leaves the upper half.
    assert_eq!(
        as_set(&subtract_prefixes(
            &prefixes(&[("10.0.0.0", 24)]),
            &prefixes(&[("10.0.0.0", 25)])
        )),
        as_set(&prefixes(&[("10.0.0.128", 25)]))
    );

    // A /32 inside an excluded block disappears.
    assert!(subtract_prefixes(
        &prefixes(&[("10.0.0.1", 32)]),
        &prefixes(&[("10.0.0.0", 24)])
    )
    .is_empty());

    // A /32 outside the excluded block survives.
    assert_eq!(
        as_set(&subtract_prefixes(
            &prefixes(&[("10.0.1.1", 32)]),
            &prefixes(&[("10.0.0.0", 24)])
        )),
        as_set(&prefixes(&[("10.0.1.1", 32)]))
    );

    // Neighbours split by an excluded block stay separate.
    assert_eq!(
        as_set(&subtract_prefixes(
            &prefixes(&[("192.168.0.0", 22)]),
            &prefixes(&[("192.168.1.0", 24)])
        )),
        as_set(&prefixes(&[("192.168.0.0", 24), ("192.168.2.0", 23)]))
    );
}

#[test]
fn subtract_prefixes_normalizes_and_merges_siblings() {
    let merged = subtract_prefixes(&prefixes(&[("10.0.0.0", 25), ("10.0.0.128", 25)]), &[]);
    assert_eq!(as_set(&merged), as_set(&prefixes(&[("10.0.0.0", 24)])));

    // Sorted by network address, and no route overlaps another.
    let list = subtract_prefixes(
        &prefixes(&[("0.0.0.0", 0)]),
        &prefixes(&[("192.168.0.0", 16)]),
    );
    let mut previous_end: Option<u32> = None;
    for entry in &list {
        let net: u32 = u32::from(entry.ip.parse::<std::net::Ipv4Addr>().expect("ip"));
        let size = 1u64 << (32 - u32::from(entry.prefix));
        assert!(
            previous_end.is_none_or(|end| u64::from(end) < u64::from(net)),
            "routes overlap or are unsorted: {list:?}"
        );
        previous_end = Some(u32::try_from(u64::from(net) + size - 1).expect("fits"));
    }
}
