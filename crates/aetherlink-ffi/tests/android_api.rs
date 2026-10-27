//! P2-R1: the Rust API behind the JNI surface (L0).
//!
//! Kotlin only forwards calls: every decision lives in `android_api`, so the
//! whole host contract is testable without a device, a JNI VM or a VpnService.
//! The rules pinned here:
//!
//! - `create` returns 0 for a bad document and leaves an error text;
//! - `plan`/`status` answer with real JSON for a live handle;
//! - `connect` without a protector is `PermissionDenied` — connecting the
//!   server socket unprotected would route it into our own tunnel;
//! - `attach` rejects a bogus fd/mtu/handle before touching it;
//! - `free` is idempotent and a freed handle is dead.

use aetherlink_ffi::android_api as api;
use aetherlink_ffi::AetherError;
use serde_json::Value;

fn config(addr: &str) -> String {
    serde_json::json!({
        "client": {
            "server_addr": addr,
            "psk": "phase-p2r1-test-psk-32-bytes-long!!!",
            "dns_mode": "tunnel",
        }
    })
    .to_string()
}

fn create_ok(addr: &str) -> usize {
    let handle = api::create(&config(addr));
    assert_ne!(handle, 0, "create failed: {:?}", api::last_error());
    handle
}

#[test]
fn create_rejects_a_bad_document_with_a_reason() {
    assert_eq!(api::create("{not json"), 0);
    let err = api::last_error().expect("a failed create must leave error text");
    assert!(
        err.to_lowercase().contains("json") || err.to_lowercase().contains("config"),
        "unhelpful error: {err}"
    );

    // A missing required field is also a create failure, not a panic.
    assert_eq!(api::create(r#"{"client":{}}"#), 0);
    assert!(api::last_error().is_some());
}

#[test]
fn plan_roundtrips_the_interface_contract() {
    let handle = create_ok("127.0.0.1:9");
    let raw = api::plan(handle).expect("plan for a live handle");
    let plan: Value = serde_json::from_str(&raw).expect("plan json");
    assert_eq!(plan["session"], "AetherLink");
    assert_eq!(plan["address"]["ip"], "10.255.0.2");
    assert_eq!(plan["address"]["prefix"], 30);
    assert_eq!(plan["dns"], serde_json::json!(["10.255.0.1"]));
    assert_eq!(
        plan["apps"],
        serde_json::json!({ "mode": "all", "packages": [] })
    );
    assert_eq!(plan["block_ipv6"], true);
    let routes = plan["routes"].as_array().expect("routes array");
    assert!(
        routes
            .iter()
            .any(|r| r["ip"] == "10.255.0.1" && r["prefix"] == 32),
        "the DNS /32 is always routed: {routes:?}"
    );

    assert_eq!(api::free(handle), AetherError::Success as i32);
}

#[test]
fn connect_without_a_protector_is_permission_denied() {
    let handle = create_ok("127.0.0.1:9");

    let code = api::connect(handle, None);

    assert_eq!(
        code,
        AetherError::PermissionDenied as i32,
        "an unprotected transport must never connect"
    );
    let err = api::last_error().expect("error text");
    assert!(
        err.to_lowercase().contains("protect"),
        "the host must learn why: {err}"
    );

    // A protector that refuses is the same answer.
    assert_eq!(
        api::connect(handle, Some(&|_fd| false)),
        AetherError::PermissionDenied as i32
    );
    assert_eq!(api::free(handle), AetherError::Success as i32);
}

#[test]
fn attach_rejects_bad_arguments_before_touching_the_fd() {
    let handle = create_ok("127.0.0.1:9");

    assert_eq!(
        api::attach(handle, -1, 1400),
        AetherError::InvalidArgument as i32
    );
    assert_eq!(
        api::attach(handle, 0, 1400),
        AetherError::InvalidArgument as i32
    );
    assert_eq!(
        api::attach(handle, 5, 0),
        AetherError::InvalidArgument as i32
    );
    assert_eq!(api::attach(0, 5, 1400), AetherError::InvalidHandle as i32);
    assert!(api::last_error().is_some());

    assert_eq!(api::free(handle), AetherError::Success as i32);
}

#[test]
fn free_is_idempotent_and_kills_the_handle() {
    let handle = create_ok("127.0.0.1:9");

    assert_eq!(api::free(handle), AetherError::Success as i32);
    assert_eq!(
        api::free(handle),
        AetherError::Success as i32,
        "a second free must not fail"
    );

    assert_eq!(api::plan(handle), Err(AetherError::InvalidHandle as i32));
    assert_eq!(api::status(handle), Err(AetherError::InvalidHandle as i32));
    assert_eq!(api::disconnect(handle), AetherError::InvalidHandle as i32);
}

#[test]
fn status_is_json_for_a_live_client() {
    let handle = create_ok("127.0.0.1:9");

    let raw = api::status(handle).expect("status for a live handle");
    let status: Value = serde_json::from_str(&raw).expect("status json");
    assert_eq!(status["up"], Value::Bool(false));

    // Disconnect before connect is safe (the host may be killed early).
    assert_eq!(api::disconnect(handle), AetherError::Success as i32);
    assert_eq!(api::free(handle), AetherError::Success as i32);
}
