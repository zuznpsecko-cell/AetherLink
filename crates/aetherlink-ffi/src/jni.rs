//! JNI entry points for `link.aether.client.AetherCore` (Kotlin `object`).
//!
//! Thin bridge: every call forwards to [`crate::android_api`], where the
//! logic lives and is tested on the host. The Android flow is
//! `clientCreate` → `clientConnect` (socket protected through
//! `AetherCore.protectFd` → `VpnService.protect`) → `clientPlan` →
//! `establish()` in Kotlin → `clientAttachTun` → `clientStatus` polling →
//! `clientDisconnect`/`clientFree`.
//!
//! The desktop entry points (`clientUp`/`clientDown`, staged `setTunFd`/
//! `setSplitConfig`) are not exported over JNI: on Android they led into the
//! Windows route/DNS path. The staging maps below remain for the C ABI
//! (`aether_client_android_set_tun_fd`, `aether_client_set_split_config`).
//!
//! Error codes mirror [`crate::AetherError`] so Kotlin sees one contract.
//! Every entry point runs inside [`crate::ffi_guard`]: a Rust panic must not
//! unwind into the JVM (that aborts the app).

// JNI entry points are `unsafe` only because the JVM owns `JNIEnv`/`JClass`;
// the JVM is the single caller and guarantees their validity. A `# Safety`
// section per function would repeat that sentence a dozen times.
#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use once_cell::sync::Lazy;

/// Staged TUN attachment: VpnService fd + MTU, awaiting platform bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunAttachment {
    /// TUN file descriptor from `VpnService.Builder.establish()`.
    pub fd: i32,
    /// MTU negotiated for the interface.
    pub mtu: i32,
}

static TUN: Lazy<Mutex<HashMap<usize, TunAttachment>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static SPLIT: Lazy<Mutex<HashMap<usize, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Lock a staging map, tolerating poison (plain data, valid after a panic).
fn lock<T>(map: &Mutex<T>) -> MutexGuard<'_, T> {
    map.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Stage a TUN attachment for `handle`. Pure logic, unit-tested.
pub fn stage_tun(handle: usize, fd: i32, mtu: i32) {
    lock(&TUN).insert(handle, TunAttachment { fd, mtu });
}

/// Read back a staged attachment, if any.
#[must_use]
pub fn staged_tun(handle: usize) -> Option<TunAttachment> {
    lock(&TUN).get(&handle).copied()
}

/// Stage a split-tunnel config document for `handle`. Pure logic, unit-tested.
pub fn stage_split(handle: usize, doc: String) {
    lock(&SPLIT).insert(handle, doc);
}

/// Read back a staged split config, if any.
#[must_use]
pub fn staged_split(handle: usize) -> Option<String> {
    lock(&SPLIT).get(&handle).cloned()
}

/// Forget everything staged for a released handle (handles are never
/// reused, so leftovers would only accumulate).
pub(crate) fn unstage(handle: usize) {
    lock(&TUN).remove(&handle);
    lock(&SPLIT).remove(&handle);
}

/// Fallback for `jint` entry points whose body panicked.
const PANIC_CODE: jint = crate::AetherError::InternalError as jint;

/// `AetherCore.clientCreate(configJson): Long` — 0 on error, like C ABI.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientCreate<'local>(
    mut env: JNIEnv<'local>,
    _cls: JClass<'local>,
    config: JString<'local>,
) -> jlong {
    crate::ffi_guard("clientCreate", 0, || {
        let json: String = match env.get_string(&config) {
            Ok(s) => s.into(),
            Err(e) => {
                crate::set_last_error(&format!("clientCreate: bad Java string: {e}"));
                return 0;
            }
        };
        crate::android_api::create(&json) as jlong
    })
}

/// Return a Java string, or null when the JVM refuses to allocate it.
fn as_jstring(env: &mut JNIEnv<'_>, text: String) -> jstring {
    match env.new_string(text) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            crate::set_last_error(&format!("JNI: could not return string: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// `AetherCore.clientPlan(handle): String` — "" on error (contract).
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientPlan<'local>(
    mut env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jstring {
    crate::ffi_guard("clientPlan", std::ptr::null_mut(), || {
        let json = crate::android_api::plan(handle as usize).unwrap_or_default();
        as_jstring(&mut env, json)
    })
}

/// `AetherCore.clientStatus(handle): String` — "" on error (contract).
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientStatus<'local>(
    mut env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jstring {
    crate::ffi_guard("clientStatus", std::ptr::null_mut(), || {
        let json = crate::android_api::status(handle as usize).unwrap_or_default();
        as_jstring(&mut env, json)
    })
}

/// `AetherCore.lastError(): String` — "" when nothing failed.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_lastError<'local>(
    mut env: JNIEnv<'local>,
    _cls: JClass<'local>,
) -> jstring {
    crate::ffi_guard("lastError", std::ptr::null_mut(), || {
        let text = crate::android_api::last_error().unwrap_or_default();
        as_jstring(&mut env, text)
    })
}

/// `AetherCore.clientConnect(handle): Int`.
///
/// Socket → `AetherCore.protectFd(fd)` (Kotlin forwards to
/// `VpnService.protect`) → TCP → TLS → AUTH. The protector runs on this very
/// thread, synchronously inside the call, so the `JNIEnv` of the call is
/// valid for it: no cached `JavaVM`, no thread attach. `AetherCore` is a
/// Kotlin `object`, so the second JNI argument is its instance and
/// `protectFd` is an instance method on it.
///
/// `protectFd` returning `false` (no running `VpnService`) or throwing makes
/// the core refuse with `PermissionDenied` before a packet is sent.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientConnect<'local>(
    env: JNIEnv<'local>,
    host: JObject<'local>,
    handle: jlong,
) -> jint {
    crate::ffi_guard("clientConnect", PANIC_CODE, move || {
        let env = RefCell::new(env);
        let protector = |fd: i32| protect_via_host(&env, &host, fd);
        crate::android_api::connect(handle as usize, Some(&protector as &dyn Fn(i32) -> bool))
            as jint
    })
}

/// Call `host.protectFd(fd): Boolean`; any JNI failure counts as "not
/// protected" (and a pending Java exception is cleared, so the JVM does not
/// rethrow it at the native-method boundary).
fn protect_via_host(env: &RefCell<JNIEnv<'_>>, host: &JObject<'_>, fd: i32) -> bool {
    let Ok(mut env) = env.try_borrow_mut() else {
        return false;
    };
    let protected = env
        .call_method(host, "protectFd", "(I)Z", &[JValue::Int(fd)])
        .and_then(|value| value.z());
    match protected {
        Ok(ok) => ok,
        Err(_) => {
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            false
        }
    }
}

/// `AetherCore.clientAttachTun(handle, fd, mtu): Int`.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientAttachTun<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
    fd: jint,
    mtu: jint,
) -> jint {
    crate::ffi_guard("clientAttachTun", PANIC_CODE, || {
        crate::android_api::attach(handle as usize, fd, mtu) as jint
    })
}

/// `AetherCore.clientDisconnect(handle): Int`.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientDisconnect<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jint {
    crate::ffi_guard("clientDisconnect", PANIC_CODE, || {
        crate::android_api::disconnect(handle as usize) as jint
    })
}

/// `AetherCore.clientFree(handle): Int` — idempotent.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientFree<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jint {
    crate::ffi_guard("clientFree", PANIC_CODE, || {
        crate::android_api::free(handle as usize) as jint
    })
}

/// `AetherCore.forceCleanup(): Int`.
///
/// Android owns the VPN interface, routes and DNS: there is no desktop
/// applied-change log to replay and no host resolver to heal. Only our own
/// state file is dropped (Phase 1, P1-G8).
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_forceCleanup<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
) -> jint {
    crate::ffi_guard("forceCleanup", PANIC_CODE, || {
        match aetherlink_client::cleanup::force_cleanup_for(
            aetherlink_client::cleanup::HostKind::Android,
        ) {
            Ok(()) => crate::AetherError::Success as jint,
            Err(e) => {
                crate::set_last_error(&format!("forceCleanup: {e}"));
                crate::AetherError::InternalError as jint
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_staging_roundtrip() {
        stage_tun(4242, 99, 1400);
        assert_eq!(staged_tun(4242), Some(TunAttachment { fd: 99, mtu: 1400 }));
        assert_eq!(staged_tun(9999), None);
    }

    #[test]
    fn tun_staging_overwrites() {
        stage_tun(4243, 10, 1400);
        stage_tun(4243, 11, 1500);
        assert_eq!(staged_tun(4243), Some(TunAttachment { fd: 11, mtu: 1500 }));
    }

    #[test]
    fn unstage_forgets_both_maps() {
        stage_tun(4245, 12, 1400);
        stage_split(4245, "{}".to_string());
        unstage(4245);
        assert_eq!(staged_tun(4245), None);
        assert_eq!(staged_split(4245), None);
    }

    #[test]
    fn split_staging_roundtrip() {
        stage_split(4244, r#"{"mode":"all"}"#.to_string());
        assert_eq!(staged_split(4244).as_deref(), Some(r#"{"mode":"all"}"#));
        assert_eq!(staged_split(9998), None);
    }
}
