//! JNI entry points for `link.aether.client.AetherCore` (Kotlin `object`).
//!
//! Thin bridge: lifecycle calls forward to `aetherlink_client`; the TUN fd
//! and split config are staged here until the platform task wires them into
//! the netstack (validated + stored now, applied later).
//!
//! Error codes mirror [`crate::AetherError`] so Kotlin sees one contract.

// JNI entry points are `unsafe` only because the JVM owns `JNIEnv`/`JClass`;
// the JVM is the single caller and guarantees their validity. A `# Safety`
// section per function would repeat that sentence a dozen times.
#![allow(clippy::missing_safety_doc)]

use std::collections::HashMap;
use std::sync::Mutex;

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use once_cell::sync::Lazy;

use crate::HANDLES;

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

/// Stage a TUN attachment for `handle`. Pure logic, unit-tested.
pub fn stage_tun(handle: usize, fd: i32, mtu: i32) {
    TUN.lock()
        .expect("tun map")
        .insert(handle, TunAttachment { fd, mtu });
}

/// Read back a staged attachment, if any.
#[must_use]
pub fn staged_tun(handle: usize) -> Option<TunAttachment> {
    TUN.lock().expect("tun map").get(&handle).copied()
}

/// Stage a split-tunnel config document for `handle`. Pure logic, unit-tested.
pub fn stage_split(handle: usize, doc: String) {
    SPLIT.lock().expect("split map").insert(handle, doc);
}

/// Read back a staged split config, if any.
#[must_use]
pub fn staged_split(handle: usize) -> Option<String> {
    SPLIT.lock().expect("split map").get(&handle).cloned()
}

fn client_exists(handle: usize) -> bool {
    HANDLES
        .lock()
        .expect("handles")
        .get_client(handle)
        .is_some()
}

/// `AetherCore.clientCreate(configJson): Long` — 0 on error, like C ABI.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientCreate<'local>(
    mut env: JNIEnv<'local>,
    _cls: JClass<'local>,
    config: JString<'local>,
) -> jlong {
    let json: String = match env.get_string(&config) {
        Ok(s) => s.into(),
        Err(e) => {
            crate::set_last_error(&format!("clientCreate: bad Java string: {e}"));
            return 0;
        }
    };
    crate::android_api::create(&json) as jlong
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
    let json = crate::android_api::plan(handle as usize).unwrap_or_default();
    as_jstring(&mut env, json)
}

/// `AetherCore.clientStatus(handle): String` — "" on error (contract).
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientStatus<'local>(
    mut env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jstring {
    let json = crate::android_api::status(handle as usize).unwrap_or_default();
    as_jstring(&mut env, json)
}

/// `AetherCore.lastError(): String` — "" when nothing failed.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_lastError<'local>(
    mut env: JNIEnv<'local>,
    _cls: JClass<'local>,
) -> jstring {
    let text = crate::android_api::last_error().unwrap_or_default();
    as_jstring(&mut env, text)
}

/// `AetherCore.clientConnect(handle): Int`.
///
/// The protector bridge into Kotlin (`VpnService.protect`) lands in P2-G3;
/// until then the call is refused with `PermissionDenied` instead of ever
/// connecting the transport unprotected.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientConnect<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jint {
    crate::android_api::connect(handle as usize, None) as jint
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
    crate::android_api::attach(handle as usize, fd, mtu) as jint
}

/// `AetherCore.clientDisconnect(handle): Int`.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientDisconnect<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jint {
    crate::android_api::disconnect(handle as usize) as jint
}

/// `AetherCore.clientFree(handle): Int` — idempotent.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientFree<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jint {
    crate::android_api::free(handle as usize) as jint
}

/// `AetherCore.clientUp(handle): Int`.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientUp<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jint {
    let mut handles = HANDLES.lock().expect("handles");
    match handles.get_client(handle as usize) {
        Some(c) => match c.up() {
            Ok(()) => crate::AetherError::Success as jint,
            Err(aetherlink_client::ClientError::StaleState(_)) => {
                crate::AetherError::StaleState as jint
            }
            Err(_) => crate::AetherError::NetworkError as jint,
        },
        None => crate::AetherError::InvalidHandle as jint,
    }
}

/// `AetherCore.clientDown(handle): Int`.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_clientDown<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
) -> jint {
    let mut handles = HANDLES.lock().expect("handles");
    match handles.get_client(handle as usize) {
        Some(c) => match c.down() {
            Ok(()) => crate::AetherError::Success as jint,
            Err(_) => crate::AetherError::NetworkError as jint,
        },
        None => crate::AetherError::InvalidHandle as jint,
    }
}

/// `AetherCore.setTunFd(handle, fd, mtu): Int` — validates + stages.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_setTunFd<'local>(
    _env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
    fd: jint,
    mtu: jint,
) -> jint {
    if !client_exists(handle as usize) {
        return crate::AetherError::InvalidHandle as jint;
    }
    if fd < 0 || mtu <= 0 {
        return crate::AetherError::InvalidArgument as jint;
    }
    stage_tun(handle as usize, fd, mtu);
    crate::AetherError::Success as jint
}

/// `AetherCore.setSplitConfig(handle, json): Int` — validates + stages.
#[no_mangle]
pub unsafe extern "C" fn Java_link_aether_client_AetherCore_setSplitConfig<'local>(
    mut env: JNIEnv<'local>,
    _cls: JClass<'local>,
    handle: jlong,
    config: JString<'local>,
) -> jint {
    if !client_exists(handle as usize) {
        return crate::AetherError::InvalidHandle as jint;
    }
    let json: String = match env.get_string(&config) {
        Ok(s) => s.into(),
        Err(_) => return crate::AetherError::InvalidArgument as jint,
    };
    if serde_json::from_str::<serde_json::Value>(&json).is_err() {
        return crate::AetherError::InvalidArgument as jint;
    }
    stage_split(handle as usize, json);
    crate::AetherError::Success as jint
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
    match aetherlink_client::cleanup::force_cleanup_for(
        aetherlink_client::cleanup::HostKind::Android,
    ) {
        Ok(()) => crate::AetherError::Success as jint,
        Err(e) => {
            crate::set_last_error(&format!("forceCleanup: {e}"));
            crate::AetherError::InternalError as jint
        }
    }
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
    fn split_staging_roundtrip() {
        stage_split(4244, r#"{"mode":"all"}"#.to_string());
        assert_eq!(staged_split(4244).as_deref(), Some(r#"{"mode":"all"}"#));
        assert_eq!(staged_split(9998), None);
    }
}
