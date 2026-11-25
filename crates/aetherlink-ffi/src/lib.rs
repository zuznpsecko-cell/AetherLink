//! AetherLink FFI C ABI exports (+ JNI for Android)
//!
//! Provides stable C ABI for .NET, Android, and CLI consumers.
//! All functions use C-compatible types and error handling.
//!
//! The `jni` module adds `Java_link_aether_client_AetherCore_*` entry points
//! so the same core `.so` serves both the C ABI and Kotlin/JNI.
//!
//! Every export runs inside [`ffi_guard`]: a Rust panic must never cross the
//! `extern "C"` boundary (since Rust 1.81 that aborts the *host* process —
//! the GUI, the Android app, the server). A contained panic becomes
//! `InternalError` plus a `last_error` text. Handle bookkeeping lives in
//! [`handles`] (DEC-019, DEC-024).

pub mod android_api;
mod handles;
pub mod jni;

use once_cell::sync::Lazy;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, PoisonError};

use aetherlink_client::{Client, ClientError};
use aetherlink_server::Server;

use crate::handles::{handles, CheckoutError, FreeOutcome, Lease, Teardown};

/// Opaque handle type for FFI
pub type AetherHandle = usize;

/// Error codes for FFI functions
#[repr(i32)]
pub enum AetherError {
    Success = 0,
    InvalidHandle = -1,
    InvalidConfig = -2,
    AlreadyRunning = -3,
    NotRunning = -4,
    NetworkError = -5,
    DnsError = -6,
    AuthError = -7,
    InternalError = -8,
    InvalidArgument = -9,
    PermissionDenied = -10,
    /// `aether_client_up` refused: a leftover state file (previous run died
    /// without teardown) blocks bring-up. Hosts auto-recover: force_cleanup
    /// + retry once.
    StaleState = -11,
    /// Another call on the same client handle is still in flight (e.g. a
    /// status poll racing `up`). The handle is valid; retry later.
    Busy = -12,
}

/// Run one FFI entry point, containing any panic.
///
/// On a panic the error slot gets `"{op}: internal error (panic: …)"` and the
/// caller receives `fallback` (0 handle / `InternalError` / null). Clients
/// checked out by the panicking call are torn down by [`handles::Lease`]'s
/// `Drop`, so the table never keeps a slot that is "busy" forever.
pub(crate) fn ffi_guard<T>(op: &str, fallback: T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            let what = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string payload".to_string());
            // Bounded: panic texts are ours (no secrets by policy), but a
            // runaway message must not balloon the error slot.
            let what: String = what.chars().take(200).collect();
            set_last_error(&format!("{op}: internal error (panic: {what})"));
            fallback
        }
    }
}

/// Map a failed checkout to an FFI code + error text (C ABI wording).
fn checkout_failed(op: &str, err: CheckoutError) -> c_int {
    match err {
        CheckoutError::Invalid => {
            set_last_error("Invalid client handle");
            AetherError::InvalidHandle as c_int
        }
        CheckoutError::Busy => {
            set_last_error(&format!(
                "{op}: client handle is busy with another call, retry"
            ));
            AetherError::Busy as c_int
        }
    }
}

/// Bare FFI code for a failed checkout (JNI paths that set no error text).
pub(crate) fn handles_code(err: CheckoutError) -> c_int {
    match err {
        CheckoutError::Invalid => AetherError::InvalidHandle as c_int,
        CheckoutError::Busy => AetherError::Busy as c_int,
    }
}

/// Drop host-side staging for a handle that is gone for good.
pub(crate) fn forget_staged(handle: usize) {
    crate::jni::unstage(handle);
}

/// Copy `json` + NUL into a caller buffer.
///
/// # Safety
///
/// `out` must be writable for `out_len` bytes.
unsafe fn write_out(json: &str, out: *mut c_char, out_len: usize) -> c_int {
    if json.len() + 1 > out_len {
        set_last_error("Output buffer too small");
        return AetherError::InvalidArgument as c_int;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), out as *mut u8, json.len());
        *out.add(json.len()) = 0; // null terminator
    }
    AetherError::Success as c_int
}

/// Read a C string argument; invalid UTF-8 is an error, not an empty string.
///
/// # Safety
///
/// `ptr` must be null or a valid NUL-terminated string.
unsafe fn c_str_arg<'a>(ptr: *const c_char, name: &str) -> std::result::Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{name} is null"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| format!("{name} is not valid UTF-8"))
}

/// Process-global last error message.
///
/// Global, not thread-local: the Kotlin host may read `lastError()` on a
/// different thread than the worker that failed (a JNI call can return on a
/// pool thread while the failure happened elsewhere). `None` means "no error
/// since the last successful call".
static LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

thread_local! {
    /// Per-thread NUL-terminated copy handed to C callers.
    ///
    /// The C ABI pointer must always be a valid C string — a Rust `String` has
    /// no NUL, so handing out `String::as_ptr()` let CStr read past the
    /// allocation into heap garbage (Utf8Error / garbage tails in every GUI
    /// error). Each call on a thread refreshes this copy; the pointer stays
    /// valid until the next call on that same thread.
    static ERROR_COPY: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn set_last_error(msg: &str) {
    let mut slot = LAST_ERROR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = Some(msg.to_string());
}

/// Clear the slot: a successful call must not leave a stale message behind.
pub(crate) fn clear_last_error() {
    let mut slot = LAST_ERROR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = None;
}

/// Current error text (no trailing NUL), if any was recorded.
pub(crate) fn last_error_text() -> Option<String> {
    LAST_ERROR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Log callback type: `level` (0 info, higher = more severe), nul-terminated message.
pub type LogCallback = extern "C" fn(level: c_int, message: *const c_char);

/// Registered log callback (none by default).
static LOG_CALLBACK: Lazy<Mutex<Option<LogCallback>>> = Lazy::new(|| Mutex::new(None));

/// Emit one operational log line. Messages are static text plus numeric
/// codes only — config content and secrets never flow through here.
fn ffi_log(level: c_int, message: &str) {
    // Copy out under the lock, call without holding it: a callback that
    // re-enters the FFI must never deadlock us.
    let callback = *LOG_CALLBACK.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(callback) = callback {
        if let Ok(line) = CString::new(message) {
            callback(level, line.as_ptr());
        }
    }
}

/// Parse a config document via the shared core boundary (JSON→YAML).
fn parse_config(config_str: &str) -> std::result::Result<serde_json::Value, String> {
    aetherlink_core::config::parse_document(config_str).map_err(|e| e.to_string())
}

#[no_mangle]
pub extern "C" fn aether_version() -> *const c_char {
    static VERSION: &str = "AetherLink 1.5.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Last error message, process-global.
///
/// Returns a pointer into a per-thread NUL-terminated **copy** of the slot:
/// valid until the next call on this thread, and owned by the core — callers
/// must copy the text, never free the pointer. Null when no error was
/// recorded. The slot itself is global, so a host may read it from a
/// different thread than the failing call.
/// (The previous `CString::into_raw` leaked on every call and, worse, let
/// .NET free Rust-allocated memory with CoTaskMemFree for `string` return
/// values — heap corruption, random GUI crashes.)
#[no_mangle]
pub extern "C" fn aether_last_error() -> *const c_char {
    // No `ffi_guard` here: on a panic it would *write* the slot this call
    // reads. Nothing below can panic short of a reentrant borrow, which the
    // C ABI cannot produce (no callbacks run inside).
    let text = last_error_text();
    ERROR_COPY.with(|copy| {
        let mut buf = copy.borrow_mut();
        buf.clear();
        let Some(text) = text else {
            return std::ptr::null();
        };
        // An interior NUL would silently truncate the C string; cut there so
        // the pointer describes exactly what a CStr reader sees.
        let bytes = text.as_bytes();
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if end == 0 {
            return std::ptr::null();
        }
        buf.extend_from_slice(&bytes[..end]);
        buf.push(0);
        buf.as_ptr() as *const c_char
    })
}

/// # Safety
///
/// `config_json` must be a valid NUL-terminated C string that stays alive
/// for the duration of the call; ownership is not taken.
#[no_mangle]
pub unsafe extern "C" fn aether_server_start(config_json: *const c_char) -> AetherHandle {
    ffi_guard("aether_server_start", 0, || {
        let config_str = match unsafe { c_str_arg(config_json, "config_json") } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&e);
                return 0;
            }
        };

        let config = match parse_config(config_str) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&e);
                return 0;
            }
        };

        let server = match Server::new(config) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("Server creation failed: {}", e));
                return 0;
            }
        };

        // Bind + serve in background: start returns promptly with a live handle.
        let bound = match server.bind() {
            Ok(bound) => bound,
            Err(e) => {
                set_last_error(&format!("Server bind failed: {}", e));
                return 0;
            }
        };
        let handle = handles().insert_server(bound.serve_background());
        ffi_log(0, "server start ok");
        handle
    })
}

#[no_mangle]
pub extern "C" fn aether_server_stop(handle: AetherHandle) -> c_int {
    ffi_guard(
        "aether_server_stop",
        AetherError::InternalError as c_int,
        || {
            // Remove under the lock, stop and join outside it: the join waits
            // for the accept loop's current sleep, and other handles must not
            // queue behind that.
            let guard = handles().remove_server(handle);
            match guard {
                Some(guard) => {
                    guard.request_stop();
                    guard.join();
                    ffi_log(0, "server stop ok");
                    AetherError::Success as c_int
                }
                None => {
                    set_last_error("Invalid server handle");
                    AetherError::InvalidHandle as c_int
                }
            }
        },
    )
}

/// Is the server's accept loop still serving?
///
/// `1` = serving, `0` = stopped by itself (the listener failed; the reason is
/// in [`aether_last_error`]), `InvalidHandle` for an unknown handle. Hosts
/// poll this and exit non-zero on `0`, so a supervisor (systemd) restarts the
/// process instead of it idling with a dead listener.
#[no_mangle]
pub extern "C" fn aether_server_is_running(handle: AetherHandle) -> c_int {
    ffi_guard(
        "aether_server_is_running",
        AetherError::InternalError as c_int,
        || {
            // Copy the answer out so the lock is released before any error
            // text is written.
            let state = handles()
                .server(handle)
                .map(|guard| (guard.is_running(), guard.failure()));
            match state {
                None => {
                    set_last_error("Invalid server handle");
                    AetherError::InvalidHandle as c_int
                }
                Some((true, _)) => 1,
                Some((false, reason)) => {
                    let reason = reason.unwrap_or_else(|| "accept loop ended".to_string());
                    set_last_error(&format!("Server stopped: {reason}"));
                    0
                }
            }
        },
    )
}

/// # Safety
///
/// `config_json` must be a valid NUL-terminated C string that stays alive
/// for the duration of the call; ownership is not taken.
#[no_mangle]
pub unsafe extern "C" fn aether_client_create(config_json: *const c_char) -> AetherHandle {
    ffi_guard("aether_client_create", 0, || {
        let config_str = match unsafe { c_str_arg(config_json, "config_json") } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&e);
                return 0;
            }
        };

        let config = match parse_config(config_str) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&e);
                return 0;
            }
        };

        let client = match Client::new(config) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(&format!("Client creation failed: {}", e));
                ffi_log(2, "client create failed");
                return 0;
            }
        };

        let handle = handles().insert_client(client);
        ffi_log(0, "client create ok");
        handle
    })
}

#[no_mangle]
pub extern "C" fn aether_client_up(handle: AetherHandle) -> c_int {
    ffi_guard(
        "aether_client_up",
        AetherError::InternalError as c_int,
        || {
            // Checked out, not locked: `up_full` runs a TLS handshake, route
            // repair and TUN bring-up (seconds). The slot stays `Busy`, so a
            // concurrent free is recorded and honoured when this call finishes.
            let mut lease = match Lease::checkout(handle, Teardown::Desktop) {
                Ok(lease) => lease,
                Err(e) => return checkout_failed("Client up", e),
            };
            let outcome = lease.client().up_full(None);
            lease.finish();
            match outcome {
                Ok(_) => AetherError::Success as c_int,
                Err(ClientError::StaleState(msg)) => {
                    // Distinct code so hosts can auto-recover (force_cleanup +
                    // retry) instead of just surfacing "run down/cleanup first".
                    set_last_error(&format!("Client up failed: {msg}"));
                    AetherError::StaleState as c_int
                }
                Err(e) => {
                    set_last_error(&format!("Client up failed: {e}"));
                    AetherError::NetworkError as c_int
                }
            }
        },
    )
}

/// Release a client handle: best-effort `down` (idempotent) + drop from the
/// handle map. Hosts call it after `aether_client_down` and after a failed
/// `aether_client_up`, so repeated connect attempts do not accumulate
/// clients (each holds a platform with its TUN session).
///
/// If another call on the handle is in flight, the free is *deferred*: the
/// handle is invalid from now on and that call tears the client down when it
/// returns. Either way the result is `Success`.
#[no_mangle]
pub extern "C" fn aether_client_free(handle: AetherHandle) -> c_int {
    ffi_guard(
        "aether_client_free",
        AetherError::InternalError as c_int,
        || {
            let outcome = handles().request_free(handle, Teardown::Desktop);
            match outcome {
                FreeOutcome::Freed(mut client) => {
                    handles::tear_down(&mut client, Teardown::Desktop);
                    forget_staged(handle);
                    ffi_log(0, "client freed");
                    AetherError::Success as c_int
                }
                FreeOutcome::Deferred => {
                    ffi_log(0, "client free deferred until the in-flight call returns");
                    AetherError::Success as c_int
                }
                FreeOutcome::Unknown => {
                    set_last_error("Invalid client handle");
                    AetherError::InvalidHandle as c_int
                }
            }
        },
    )
}

#[no_mangle]
pub extern "C" fn aether_client_down(handle: AetherHandle) -> c_int {
    ffi_guard(
        "aether_client_down",
        AetherError::InternalError as c_int,
        || {
            // Same reasoning as `aether_client_up`: teardown restores DNS/routes
            // and detaches the TUN device, so it must not run under the lock.
            let mut lease = match Lease::checkout(handle, Teardown::Desktop) {
                Ok(lease) => lease,
                Err(e) => return checkout_failed("Client down", e),
            };
            let outcome = lease.client().down();
            lease.finish();
            match outcome {
                Ok(_) => AetherError::Success as c_int,
                Err(e) => {
                    set_last_error(&format!("Client down failed: {e}"));
                    AetherError::NetworkError as c_int
                }
            }
        },
    )
}

/// # Safety
///
/// `out_json` must point to a writable buffer of at least `out_len`
/// bytes; the returned length tells the caller how much was filled.
#[no_mangle]
pub unsafe extern "C" fn aether_client_status(
    handle: AetherHandle,
    out_json: *mut c_char,
    out_len: usize,
) -> c_int {
    ffi_guard(
        "aether_client_status",
        AetherError::InternalError as c_int,
        || {
            if out_json.is_null() || out_len == 0 {
                return AetherError::InvalidArgument as c_int;
            }

            // `status()` reads the TUN/route state and can touch the
            // filesystem; it must not hold the handle lock (GUIs poll this
            // from the UI thread). While `up`/`down` runs, this reports
            // `Busy` rather than a misleading `InvalidHandle`.
            let mut lease = match Lease::checkout(handle, Teardown::Desktop) {
                Ok(lease) => lease,
                Err(e) => return checkout_failed("Status", e),
            };
            let outcome = lease.client().status();
            lease.finish();

            match outcome {
                Ok(json) => unsafe { write_out(&json, out_json, out_len) },
                Err(e) => {
                    set_last_error(&format!("Status failed: {}", e));
                    AetherError::InternalError as c_int
                }
            }
        },
    )
}

#[no_mangle]
pub extern "C" fn aether_client_force_cleanup() -> c_int {
    ffi_guard(
        "aether_client_force_cleanup",
        AetherError::InternalError as c_int,
        || {
            // Load state from persistent file and restore network
            match aetherlink_client::cleanup::force_cleanup() {
                Ok(_) => AetherError::Success as c_int,
                Err(e) => {
                    set_last_error(&format!("Force cleanup failed: {}", e));
                    AetherError::InternalError as c_int
                }
            }
        },
    )
}

/// # Safety
///
/// `out_json` must point to a writable buffer of at least `out_len`
/// bytes; the returned length tells the caller how much was filled.
#[no_mangle]
pub unsafe extern "C" fn aether_client_rules_list(
    handle: AetherHandle,
    out_json: *mut c_char,
    out_len: usize,
) -> c_int {
    ffi_guard(
        "aether_client_rules_list",
        AetherError::InternalError as c_int,
        || {
            if out_json.is_null() || out_len == 0 {
                return AetherError::InvalidArgument as c_int;
            }

            // In-memory serialisation only: cheap enough to run under the lock.
            let listed = handles().with_idle_client(handle, Client::rules_json);
            let json = match listed {
                Err(e) => return checkout_failed("Rules list", e),
                Ok(Err(e)) => {
                    set_last_error(&format!("Rules list failed: {}", e));
                    return AetherError::InternalError as c_int;
                }
                Ok(Ok(json)) => json,
            };
            unsafe { write_out(&json, out_json, out_len) }
        },
    )
}

/// # Safety
///
/// `rules_json` must be a valid NUL-terminated C string that stays alive
/// for the duration of the call; ownership is not taken.
#[no_mangle]
pub unsafe extern "C" fn aether_client_rules_set(
    handle: AetherHandle,
    rules_json: *const c_char,
) -> c_int {
    ffi_guard(
        "aether_client_rules_set",
        AetherError::InternalError as c_int,
        || {
            let raw = match unsafe { c_str_arg(rules_json, "rules_json") } {
                Ok(s) => s,
                Err(e) => {
                    set_last_error(&e);
                    return AetherError::InvalidArgument as c_int;
                }
            };
            let doc: serde_json::Value = match serde_json::from_str(raw) {
                Ok(doc) => doc,
                Err(e) => {
                    set_last_error(&format!("Invalid rules JSON: {e}"));
                    return AetherError::InvalidArgument as c_int;
                }
            };

            // `set_rules` may rebuild the split-tunnel list; keep it off the
            // lock.
            let mut lease = match Lease::checkout(handle, Teardown::Desktop) {
                Ok(lease) => lease,
                Err(e) => return checkout_failed("Rules set", e),
            };
            let outcome = lease.client().set_rules(&doc);
            lease.finish();

            match outcome {
                Ok(()) => {
                    ffi_log(0, "client rules set ok");
                    AetherError::Success as c_int
                }
                Err(e) => {
                    set_last_error(&format!("Rules set failed: {e}"));
                    AetherError::InvalidArgument as c_int
                }
            }
        },
    )
}

#[no_mangle]
pub extern "C" fn aether_client_rules_reload(handle: AetherHandle) -> c_int {
    ffi_guard(
        "aether_client_rules_reload",
        AetherError::InternalError as c_int,
        || {
            // `reload_rules` touches the filesystem (rule file re-read); keep
            // it off the handle lock like the other mutating calls.
            let mut lease = match Lease::checkout(handle, Teardown::Desktop) {
                Ok(lease) => lease,
                Err(e) => return checkout_failed("Rules reload", e),
            };
            let outcome = lease.client().reload_rules();
            lease.finish();
            match outcome {
                Ok(()) => AetherError::Success as c_int,
                Err(e) => {
                    set_last_error(&format!("Rules reload failed: {e}"));
                    AetherError::InternalError as c_int
                }
            }
        },
    )
}

#[no_mangle]
pub extern "C" fn aether_client_android_set_tun_fd(
    handle: AetherHandle,
    fd: c_int,
    mtu: c_int,
) -> c_int {
    ffi_guard(
        "aether_client_android_set_tun_fd",
        AetherError::InternalError as c_int,
        || {
            if !handles().contains_client(handle) {
                set_last_error("Invalid client handle");
                return AetherError::InvalidHandle as c_int;
            }
            if fd < 0 || mtu <= 0 {
                set_last_error("Invalid tun fd or mtu");
                return AetherError::InvalidArgument as c_int;
            }
            // Validated + staged; the platform task applies it at bring-up.
            crate::jni::stage_tun(handle, fd, mtu);
            AetherError::Success as c_int
        },
    )
}

/// # Safety
///
/// `split_json` must be a valid NUL-terminated C string that stays alive
/// for the duration of the call; ownership is not taken.
#[no_mangle]
pub unsafe extern "C" fn aether_client_set_split_config(
    handle: AetherHandle,
    config_json: *const c_char,
) -> c_int {
    ffi_guard(
        "aether_client_set_split_config",
        AetherError::InternalError as c_int,
        || {
            if !handles().contains_client(handle) {
                set_last_error("Invalid client handle");
                return AetherError::InvalidHandle as c_int;
            }
            let raw = match unsafe { c_str_arg(config_json, "config_json") } {
                Ok(s) => s,
                Err(e) => {
                    set_last_error(&e);
                    return AetherError::InvalidArgument as c_int;
                }
            };
            let doc = match serde_json::from_str::<serde_json::Value>(raw) {
                Ok(doc) if doc.is_object() => doc,
                _ => {
                    set_last_error("Invalid split config JSON");
                    return AetherError::InvalidArgument as c_int;
                }
            };
            // Validated + staged; enforced at dial time on Android only.
            crate::jni::stage_split(handle, doc.to_string());
            AetherError::Success as c_int
        },
    )
}

#[no_mangle]
pub extern "C" fn aether_set_log_callback(
    callback: extern "C" fn(level: c_int, message: *const c_char),
) -> c_int {
    ffi_guard(
        "aether_set_log_callback",
        AetherError::InternalError as c_int,
        || {
            *LOG_CALLBACK.lock().unwrap_or_else(PoisonError::into_inner) = Some(callback);
            AetherError::Success as c_int
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests here observe the process-global error slot and handle table.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn create() -> usize {
        let cfg = CString::new(r#"{"server_addr":"127.0.0.1:9","psk":"guard-test-psk"}"#)
            .expect("cstring");
        let h = unsafe { aether_client_create(cfg.as_ptr()) };
        assert_ne!(h, 0, "create: {:?}", last_error_text());
        h
    }

    #[test]
    fn a_panic_becomes_internal_error_with_text() {
        let _serial = serial();
        let code = ffi_guard("probe_op", AetherError::InternalError as c_int, || {
            panic!("boom-42")
        });
        assert_eq!(code, AetherError::InternalError as c_int);
        let text = last_error_text().expect("panic must leave error text");
        assert!(text.contains("probe_op"), "{text}");
        assert!(text.contains("boom-42"), "{text}");
    }

    #[test]
    fn a_panic_while_leasing_releases_the_handle() {
        let _serial = serial();
        let h = create();
        // When: a call panics while it holds the client
        let code = ffi_guard("probe_lease", AetherError::InternalError as c_int, || {
            let _lease = Lease::checkout(h, Teardown::Desktop).expect("checkout");
            panic!("mid-call failure");
        });
        assert_eq!(code, AetherError::InternalError as c_int);
        // Then: the slot is not stuck "busy" — the handle is gone (state
        // unknown, client torn down) and later calls get a clean answer.
        assert_eq!(aether_client_down(h), AetherError::InvalidHandle as c_int);
        assert_eq!(aether_client_free(h), AetherError::InvalidHandle as c_int);
    }

    #[test]
    fn a_poisoned_table_keeps_serving() {
        let _serial = serial();
        // Given: the handle table mutex poisoned by a panic while held
        let poisoner = std::thread::spawn(|| {
            let _map = handles();
            panic!("poison the handle table");
        });
        assert!(poisoner.join().is_err());
        // Then: FFI calls still work instead of panicking on `unwrap()`.
        let h = create();
        let mut buf = [0u8; 4096];
        let rc = unsafe { aether_client_status(h, buf.as_mut_ptr() as *mut c_char, buf.len()) };
        assert_eq!(rc, AetherError::Success as c_int);
        assert_eq!(aether_client_free(h), AetherError::Success as c_int);
    }

    #[test]
    fn status_during_an_in_flight_call_is_busy_not_invalid() {
        let _serial = serial();
        let h = create();
        let lease = Lease::checkout(h, Teardown::Desktop).expect("checkout");
        let mut buf = [0u8; 4096];
        let rc = unsafe { aether_client_status(h, buf.as_mut_ptr() as *mut c_char, buf.len()) };
        assert_eq!(rc, AetherError::Busy as c_int);
        lease.finish();
        let rc = unsafe { aether_client_status(h, buf.as_mut_ptr() as *mut c_char, buf.len()) };
        assert_eq!(rc, AetherError::Success as c_int);
        assert_eq!(aether_client_free(h), AetherError::Success as c_int);
    }

    #[test]
    fn free_during_an_in_flight_call_is_honoured_on_return() {
        let _serial = serial();
        let h = create();
        // Given: a call holding the client (stands in for a slow `up`)
        let lease = Lease::checkout(h, Teardown::Desktop).expect("checkout");
        // When: the host frees the handle meanwhile
        assert_eq!(aether_client_free(h), AetherError::Success as c_int);
        assert_eq!(
            aether_client_down(h),
            AetherError::InvalidHandle as c_int,
            "a freed handle is invalid at once"
        );
        // Then: finishing the call does not resurrect the handle.
        lease.finish();
        assert_eq!(aether_client_down(h), AetherError::InvalidHandle as c_int);
        assert_eq!(aether_client_free(h), AetherError::InvalidHandle as c_int);
    }

    #[test]
    fn invalid_utf8_config_is_reported_not_treated_as_empty() {
        let _serial = serial();
        let bad = [0xFFu8, 0xFE, 0x00];
        let h = unsafe { aether_client_create(bad.as_ptr() as *const c_char) };
        assert_eq!(h, 0);
        let text = last_error_text().expect("error text");
        assert!(text.contains("UTF-8"), "{text}");
    }
}
