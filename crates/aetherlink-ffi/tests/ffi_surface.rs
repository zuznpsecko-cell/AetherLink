//! TDD RED: remaining FFI surface — routing rules, log callback,
//! Android TUN fd + split config (Phase E, §3).
//!
//! Rules roundtrip as JSON; the log callback must carry operational lines
//! with no secrets; Android entry points validate handles and arguments
//! and stage values for the platform task.

use std::ffi::{CStr, CString};
use std::sync::Mutex;

use aetherlink_ffi::{
    aether_client_android_set_tun_fd, aether_client_create, aether_client_rules_list,
    aether_client_rules_reload, aether_client_rules_set, aether_client_set_split_config,
    aether_set_log_callback, AetherError,
};

fn c(s: &str) -> CString {
    CString::new(s).expect("cstring")
}

fn make_client() -> usize {
    let cfg = c(r#"{"server_addr":"example.com:443","psk":"x"}"#);
    let h = unsafe { aether_client_create(cfg.as_ptr()) };
    assert_ne!(h, 0, "client create");
    h
}

fn read_out(handle: usize) -> String {
    let mut buf = vec![0u8; 4096];
    let rc = unsafe {
        aether_client_rules_list(
            handle,
            buf.as_mut_ptr() as *mut std::os::raw::c_char,
            buf.len(),
        )
    };
    assert_eq!(rc, AetherError::Success as i32);
    let len = buf.iter().position(|&b| b == 0).expect("nul terminator");
    String::from_utf8(buf[..len].to_vec()).expect("utf8")
}

#[test]
fn rules_set_list_reload_roundtrip() {
    // Given: fresh client with default (LAN-only) rules
    let h = make_client();
    // When: setting two custom rules
    let docs = c(r#"{"rules":[
            {"name":"one","action":"direct","priority":40,"when":{"ip":"198.51.100.10"}},
            {"name":"site","action":"direct","priority":50,"when":{"suffix":".example.com"}}
        ]}"#);
    assert_eq!(
        unsafe { aether_client_rules_set(h, docs.as_ptr()) },
        AetherError::Success as i32
    );
    // Then: list returns both, reload revalidates cleanly.
    let listed = read_out(h);
    assert!(listed.contains("\"one\""), "got: {listed}");
    assert!(listed.contains("\"site\""), "got: {listed}");
    assert_eq!(
        unsafe { aether_client_rules_reload(h) },
        AetherError::Success as i32
    );
}

#[test]
fn rules_reject_bad_input() {
    // Given: fresh client
    let h = make_client();
    // When: garbage / unknown handle
    let bad = c("[unclosed");
    // Then: InvalidArgument / InvalidHandle, never a crash.
    assert_eq!(
        unsafe { aether_client_rules_set(h, bad.as_ptr()) },
        AetherError::InvalidArgument as i32
    );
    let docs = c(r#"{"rules":[]}"#);
    assert_eq!(
        unsafe { aether_client_rules_set(usize::MAX, docs.as_ptr()) },
        AetherError::InvalidHandle as i32
    );
    let mut buf = vec![0u8; 16];
    assert_eq!(
        unsafe {
            aether_client_rules_list(
                usize::MAX,
                buf.as_mut_ptr() as *mut std::os::raw::c_char,
                buf.len(),
            )
        },
        AetherError::InvalidHandle as i32
    );
}

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

extern "C" fn capture(level: std::os::raw::c_int, message: *const std::os::raw::c_char) {
    assert!(level >= 0);
    let text = unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned();
    LINES.lock().expect("lines").push(text);
}

#[test]
fn log_callback_receives_sanitized_line() {
    // Given: registered log callback + client with a known secret
    LINES.lock().expect("lines").clear();
    assert_eq!(
        unsafe { aether_set_log_callback(capture) },
        AetherError::Success as i32
    );
    let cfg = c(r#"{"server_addr":"example.com:443","psk":"super-secret-psk-123"}"#);
    // When: creating the client
    let h = unsafe { aether_client_create(cfg.as_ptr()) };
    assert_ne!(h, 0);
    // Then: at least one operational line arrived, carrying no secret.
    let lines = LINES.lock().expect("lines");
    assert!(!lines.is_empty(), "callback must fire");
    for line in lines.iter() {
        assert!(
            !line.contains("super-secret-psk-123"),
            "secret leak: {line}"
        );
    }
}

#[test]
fn android_tun_fd_validation() {
    // Given: live handle
    let h = make_client();
    // When: bad handle / bad fd / good triple
    assert_eq!(
        unsafe { aether_client_android_set_tun_fd(usize::MAX, 5, 1400) },
        AetherError::InvalidHandle as i32
    );
    assert_eq!(
        unsafe { aether_client_android_set_tun_fd(h, -1, 1400) },
        AetherError::InvalidArgument as i32
    );
    assert_eq!(
        unsafe { aether_client_android_set_tun_fd(h, 5, 1400) },
        AetherError::Success as i32
    );
}

#[test]
fn split_config_validation() {
    // Given: live handle
    let h = make_client();
    let good = c(r#"{"mode":"all"}"#);
    let bad = c("[unclosed");
    // When/Then: validated, staged, never crashing.
    assert_eq!(
        unsafe { aether_client_set_split_config(usize::MAX, good.as_ptr()) },
        AetherError::InvalidHandle as i32
    );
    assert_eq!(
        unsafe { aether_client_set_split_config(h, bad.as_ptr()) },
        AetherError::InvalidArgument as i32
    );
    assert_eq!(
        unsafe { aether_client_set_split_config(h, good.as_ptr()) },
        AetherError::Success as i32
    );
}
