//! TDD RED: FFI C ABI contract smoke tests (§3).
//!
//! Locks the stable C ABI surface .NET/Android/CLI bind against:
//! version string, server start/stop lifecycle, client create,
//! null/bad-config rejection, invalid-handle errors.
//! `force_cleanup` + rules/split surface land with the client task.

use std::ffi::{CStr, CString};

use aetherlink_ffi::{
    aether_client_create, aether_client_down, aether_client_up, aether_server_start,
    aether_server_stop, aether_version, AetherError,
};

fn c(s: &str) -> CString {
    CString::new(s).expect("cstring")
}

#[test]
fn ffi_version_banner() {
    // Given: loaded cdylib
    // When: reading the version
    let ptr = aether_version();
    assert!(!ptr.is_null());
    let v = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8");
    // Then: identifies the product line
    assert!(v.starts_with("AetherLink"), "got {v}");
}

#[test]
fn ffi_server_start_stop_lifecycle() {
    // Given: minimal valid server config
    let cfg = c(r#"{"listen":"0.0.0.0:443","psk":"x","local_static_root":"./fallback"}"#);
    // When: start then stop
    let h = unsafe { aether_server_start(cfg.as_ptr()) };
    assert_ne!(h, 0, "valid config must yield a handle");
    assert_eq!(
        unsafe { aether_server_stop(h) },
        AetherError::Success as i32
    );
    // Then: handle is gone
    assert_eq!(
        unsafe { aether_server_stop(h) },
        AetherError::InvalidHandle as i32
    );
}

#[test]
fn ffi_server_rejects_null_and_bad_config() {
    // Given: null pointer / garbage JSON
    // When: starting
    assert_eq!(unsafe { aether_server_start(std::ptr::null()) }, 0);
    // Invalid as JSON and as YAML (unclosed flow sequence).
    let bad = c("[unclosed");
    assert_eq!(unsafe { aether_server_start(bad.as_ptr()) }, 0);
}

#[test]
fn ffi_accepts_yaml_configs() {
    // Given: the shipped example configs are YAML, hosts pass file content
    let server_yaml =
        std::fs::read_to_string("../../configs/server.example.yaml").expect("example yaml");
    let client_yaml =
        std::fs::read_to_string("../../configs/client.example.yaml").expect("example yaml");
    // When: starting/creating from YAML documents
    let sh = unsafe { aether_server_start(c(&server_yaml).as_ptr()) };
    let ch = unsafe { aether_client_create(c(&client_yaml).as_ptr()) };
    // Then: both accepted (YAML falls back when JSON fails)
    assert_ne!(sh, 0, "server must accept yaml config");
    assert_ne!(ch, 0, "client must accept yaml config");
    assert_eq!(
        unsafe { aether_server_stop(sh) },
        AetherError::Success as i32
    );
}

#[test]
fn ffi_client_create_and_invalid_handle() {
    // Given: valid client config document (psk is required, never defaulted)
    let cfg = c(r#"{"server_addr":"example.com:443","psk":"x"}"#);
    // When: creating
    let h = unsafe { aether_client_create(cfg.as_ptr()) };
    assert_ne!(h, 0, "create must yield a handle");
    // Then: unknown handles are rejected, not crashed on
    assert_eq!(
        unsafe { aether_client_up(usize::MAX) },
        AetherError::InvalidHandle as i32
    );
    assert_eq!(
        unsafe { aether_client_down(usize::MAX) },
        AetherError::InvalidHandle as i32
    );
    assert_eq!(
        unsafe { aether_client_create(std::ptr::null()) },
        0,
        "null config must not yield a handle"
    );
    // A config without psk is invalid: no empty-secret default, no handle.
    let no_psk = c(r#"{"server_addr":"example.com:443"}"#);
    assert_eq!(unsafe { aether_client_create(no_psk.as_ptr()) }, 0);
    let _ = h;
}
