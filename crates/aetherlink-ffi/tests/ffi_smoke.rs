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

/// Temp TLS cert/key + static root for bindable server configs.
///
/// Paths use forward slashes: backslashes are escape characters inside
/// JSON (and double-quoted YAML) string literals.
fn temp_server_files() -> (String, String, String) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aether-ffi-{nanos}"));
    std::fs::create_dir_all(&dir).expect("static dir");
    std::fs::write(dir.join("index.html"), b"<html><body>parking</body></html>")
        .expect("static file");
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert = dir.join("cert.pem");
    let keyf = dir.join("key.pem");
    std::fs::write(&cert, key.cert.pem()).expect("cert");
    std::fs::write(&keyf, key.key_pair.serialize_pem()).expect("key");
    let slash = |p: std::path::PathBuf| p.to_str().expect("utf8").replace('\\', "/");
    (slash(cert), slash(keyf), slash(dir))
}

fn bindable_server_json() -> String {
    let (cert, key, root) = temp_server_files();
    format!(
        r#"{{"listen":"127.0.0.1:0","psk":"x","local_static_root":"{root}","tls_cert":"{cert}","tls_key":"{key}"}}"#
    )
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
    // Given: bindable server config (127.0.0.1:0 + temp cert files)
    let cfg = c(&bindable_server_json());
    // When: start then stop; start must return promptly (serving is background)
    let started = std::time::Instant::now();
    let h = unsafe { aether_server_start(cfg.as_ptr()) };
    assert_ne!(h, 0, "valid config must yield a handle");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "start must not block on serving"
    );
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
fn ffi_server_start_requires_listenable_tls() {
    // Given: config without TLS identity files
    let cfg = c(r#"{"listen":"127.0.0.1:0","psk":"x","local_static_root":"./fallback"}"#);
    // When: starting → Then: no handle (bind fails fast, nothing half-started).
    assert_eq!(unsafe { aether_server_start(cfg.as_ptr()) }, 0);
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
    // Given: the shipped client example (YAML, hosts pass file content)
    let client_yaml =
        std::fs::read_to_string("../../configs/client.example.yaml").expect("example yaml");
    // When: creating from the YAML document
    let ch = unsafe { aether_client_create(c(&client_yaml).as_ptr()) };
    // Then: accepted (YAML falls back when JSON fails)
    assert_ne!(ch, 0, "client must accept yaml config");

    // Given: a server YAML document with real temp TLS files
    let (cert, key, root) = temp_server_files();
    let server_yaml = format!(
        "listen: \"127.0.0.1:0\"\npsk: \"x\"\nlocal_static_root: \"{root}\"\ntls_cert: \"{cert}\"\ntls_key: \"{key}\"\n"
    );
    // When: starting → Then: serving handle out.
    let sh = unsafe { aether_server_start(c(&server_yaml).as_ptr()) };
    assert_ne!(sh, 0, "server must accept yaml config");
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
