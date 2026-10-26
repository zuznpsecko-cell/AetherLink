//! P1-R4: Android-only config sections (`android.split`, `android.
//! use_full_tunnel_lan_direct`, `client.tls.ca_pem`) parse and validate
//! without changing desktop behaviour.
//!
//! L0: config -> plan, no device.

use aetherlink_client::android_plan::plan_json;
use aetherlink_client::config::ClientConfig;
use aetherlink_client::ClientError;
use serde_json::{json, Value};

fn config(doc: Value) -> ClientConfig {
    ClientConfig::parse(&doc).expect("test config must parse")
}

fn base_client() -> Value {
    json!({
        "server_addr": "31.57.158.233:443",
        "psk": "test-psk",
        "full_tunnel": { "mtu": 1400, "include_private_lan_direct": true }
    })
}

fn plan_for(client: Value) -> Value {
    let cfg = config(json!({ "client": client }));
    let text = plan_json(&cfg).expect("plan must build");
    serde_json::from_str(&text).expect("plan must be valid JSON")
}

fn self_signed_pem() -> String {
    let key = rcgen::generate_simple_self_signed(vec!["aetherlink.test".to_string()])
        .expect("rcgen must issue a test certificate");
    key.cert.pem()
}

#[test]
fn android_split_allow_list_reaches_the_plan() {
    let mut client = base_client();
    client["android"] = json!({
        "split": {
            "mode": "allow",
            "apps": ["com.example.app", "org.mozilla.firefox"],
            "subnets": []
        }
    });

    let plan = plan_for(client);

    assert_eq!(
        plan["apps"],
        json!({ "mode": "allow", "packages": ["com.example.app", "org.mozilla.firefox"] })
    );
}

#[test]
fn missing_android_section_means_all_apps_and_no_regression() {
    let plan = plan_for(base_client());

    assert_eq!(plan["apps"], json!({ "mode": "all", "packages": [] }));
    assert_eq!(plan["mtu"], json!(1400));
}

#[test]
fn use_full_tunnel_lan_direct_overrides_the_desktop_flag() {
    let mut client = base_client();
    client["android"] = json!({ "use_full_tunnel_lan_direct": false });

    let plan = plan_for(client);
    let routes = plan["routes"].as_array().expect("routes");

    assert!(
        routes.contains(&json!({ "ip": "0.0.0.0", "prefix": 0 })),
        "override must disable RFC1918 subtraction: {routes:?}"
    );
    assert!(
        !routes.contains(&json!({ "ip": "10.0.0.0", "prefix": 8 })),
        "no LAN carve-out when the override is false: {routes:?}"
    );
}

#[test]
fn invalid_android_split_is_a_config_error() {
    let cases = [
        (json!({ "mode": "bogus" }), "mode"),
        (
            json!({ "mode": "allow", "apps": [] }),
            "at least one package",
        ),
        (json!({ "mode": "allow", "apps": ["bad app"] }), "package"),
        (
            json!({ "mode": "subnets", "subnets": [] }),
            "at least one subnet",
        ),
        (
            json!({ "mode": "subnets", "subnets": ["0.0.0.0/0"] }),
            "0.0.0.0/0",
        ),
        (
            json!({ "mode": "subnets", "subnets": ["10.0.0.0/33"] }),
            "prefix",
        ),
    ];

    for (split, needle) in cases {
        let mut client = base_client();
        client["android"] = json!({ "split": split });
        let err = ClientConfig::parse(&json!({ "client": client }))
            .expect_err("invalid split must be rejected");
        assert!(matches!(err, ClientError::ConfigError(_)), "{err}");
        assert!(
            err.to_string().to_lowercase().contains(needle),
            "error must mention {needle:?}, got: {err}"
        );
    }
}

#[test]
fn tls_ca_pem_is_validated_and_kept() {
    let pem = self_signed_pem();
    let mut client = base_client();
    client["tls"] = json!({ "ca_pem": pem.clone() });

    let cfg = config(json!({ "client": client }));
    let kept = cfg.tls_ca_pem.expect("ca_pem must be kept");
    assert!(kept.contains("BEGIN CERTIFICATE"), "kept cert: {kept}");
    assert_eq!(kept, pem);
}

#[test]
fn broken_tls_ca_pem_is_a_config_error() {
    let mut client = base_client();
    client["tls"] = json!({ "ca_pem": "this is not a certificate" });

    let err = ClientConfig::parse(&json!({ "client": client }))
        .expect_err("garbage PEM must be rejected");
    assert!(matches!(err, ClientError::ConfigError(_)), "{err}");
    assert!(
        err.to_string().to_lowercase().contains("ca"),
        "error must name the CA: {err}"
    );
}

#[test]
fn desktop_config_without_android_or_tls_sections_is_unchanged() {
    let cfg = config(json!({
        "client": {
            "server_addr": "server.example.com:443",
            "psk": "test-psk"
        }
    }));

    assert!(cfg.tls_ca_pem.is_none());
    assert_eq!(cfg.mtu, 1400);
    assert!(cfg.include_private_lan_direct);
    assert_eq!(
        cfg.android_split.mode,
        aetherlink_client::android_plan::SplitMode::All
    );
    assert!(cfg.android_split.apps.is_empty());
}
