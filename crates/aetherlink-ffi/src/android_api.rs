//! Rust API behind the Android JNI surface (`link.aether.client.AetherCore`).
//!
//! The JNI functions are deliberately trivial: parse JNI values, call one of
//! these, convert the result back. Every decision (validate the document,
//! plan the interface, protect before connecting, attach the fd, tear down)
//! lives here so it is testable on a plain host without a device, a JNI VM or
//! a `VpnService`.
//!
//! Handles live in the shared handle table ([`crate::handles`]), so the C ABI and the
//! Android host see the same clients. Error text goes to the same slot as the
//! C ABI; Kotlin reads it through `lastError()`.

use aetherlink_client::lifecycle::SocketHandle;
use aetherlink_client::{Client, ClientError};

use crate::handles::{handles, CheckoutError, FreeOutcome, Lease, Teardown};
use crate::AetherError;

/// Error code returned across the FFI boundary (`AetherError` as `i32`).
pub type Code = i32;

/// A protector callback: `VpnService.protect(fd) -> Boolean` on the host.
pub type Protector<'a> = &'a dyn Fn(i32) -> bool;

/// `clientCreate`: validate the JSON document and store a client.
///
/// Returns 0 on failure (with the reason in [`last_error`]), mirroring the
/// C ABI so the Kotlin host has one contract for both entry points.
#[must_use]
pub fn create(config_json: &str) -> usize {
    crate::clear_last_error();
    let doc: serde_json::Value = match serde_json::from_str(config_json) {
        Ok(doc) => doc,
        Err(e) => {
            crate::set_last_error(&format!("clientCreate: invalid JSON: {e}"));
            return 0;
        }
    };
    let client = match Client::new(doc) {
        Ok(client) => client,
        Err(e) => {
            crate::set_last_error(&format!("clientCreate: {e}"));
            return 0;
        }
    };
    handles().insert_client(client)
}

/// `clientPlan`: the `VpnService.Builder` document for a live handle.
pub fn plan(handle: usize) -> Result<String, Code> {
    crate::clear_last_error();
    // Out of the map for the duration of the call: the plan document reads
    // platform state, and holding the handle table lock across it would serialise every
    // other handle in the process (see DEC-019).
    let mut lease = match Lease::checkout(handle, Teardown::Android) {
        Ok(lease) => lease,
        Err(e) => return Err(checkout_failed("clientPlan", e)),
    };
    let outcome = lease.client().android_plan();
    lease.finish();
    outcome.map_err(|e| {
        crate::set_last_error(&format!("clientPlan: {e}"));
        AetherError::InternalError as Code
    })
}

/// `clientStatus`: the status document for a live handle.
pub fn status(handle: usize) -> Result<String, Code> {
    crate::clear_last_error();
    let mut lease = match Lease::checkout(handle, Teardown::Android) {
        Ok(lease) => lease,
        Err(e) => return Err(checkout_failed("clientStatus", e)),
    };
    let outcome = lease.client().android_status();
    lease.finish();
    outcome.map_err(|e| {
        crate::set_last_error(&format!("clientStatus: {e}"));
        AetherError::InternalError as Code
    })
}

/// `clientConnect`: protect the transport socket, then TCP + TLS + AUTH.
///
/// A missing protector is refused up front: connecting unprotected would
/// send the server's SYN into the tunnel we are about to create. The
/// transport stays parked until [`attach`] pairs it with the detached fd.
pub fn connect(handle: usize, protector: Option<Protector<'_>>) -> Code {
    crate::clear_last_error();
    let Some(protector) = protector else {
        crate::set_last_error(
            "clientConnect: VpnService.protect() is unavailable; refusing an unprotected transport",
        );
        return AetherError::PermissionDenied as Code;
    };
    // This runs TCP connect + TLS handshake + AUTH with the server. Holding
    // the global handle lock across it used to freeze every other handle in
    // the host process for the duration of the network round trip.
    let mut lease = match Lease::checkout(handle, Teardown::Android) {
        Ok(lease) => lease,
        Err(e) => return checkout_failed("clientConnect", e),
    };
    let outcome = lease
        .client()
        .android_connect(None, |raw| protect_with(protector, raw));
    lease.finish();
    match outcome {
        Ok(()) => AetherError::Success as Code,
        Err(e) => {
            crate::set_last_error(&format!("clientConnect: {e}"));
            code_of(&e)
        }
    }
}

/// `clientAttachTun`: take ownership of the detached `VpnService` fd.
///
/// Arguments are checked before the descriptor is touched: a bad fd here must
/// not close somebody else's descriptor. Every other refusal still owns the
/// fd (Kotlin gave it up with `detachFd()`), so it is closed: a leaked VPN fd
/// keeps the interface up with nobody reading it, and every app's traffic
/// disappears into it.
pub fn attach(handle: usize, fd: i32, mtu: i32) -> Code {
    crate::clear_last_error();
    // Validate first: these rejections must not disturb the handle map.
    if fd <= 0 {
        crate::set_last_error(&format!("clientAttachTun: invalid tun fd {fd}"));
        return AetherError::InvalidArgument as Code;
    }
    if mtu <= 0 {
        crate::set_last_error(&format!("clientAttachTun: invalid mtu {mtu}"));
        release_fd(fd);
        return AetherError::InvalidArgument as Code;
    }
    let mut lease = match Lease::checkout(handle, Teardown::Android) {
        Ok(lease) => lease,
        Err(e) => {
            release_fd(fd);
            return checkout_failed("clientAttachTun", e);
        }
    };
    let outcome = attach_tun(lease.client(), fd, mtu);
    lease.finish();
    match outcome {
        Ok(()) => AetherError::Success as Code,
        Err(msg) => {
            crate::set_last_error(&format!("clientAttachTun: {msg}"));
            AetherError::InternalError as Code
        }
    }
}

/// `clientDisconnect`: stop the pump and release the transport.
pub fn disconnect(handle: usize) -> Code {
    crate::clear_last_error();
    let mut lease = match Lease::checkout(handle, Teardown::Android) {
        Ok(lease) => lease,
        Err(e) => return checkout_failed("clientDisconnect", e),
    };
    let outcome = lease.client().android_disconnect();
    lease.finish();
    match outcome {
        Ok(()) => AetherError::Success as Code,
        Err(e) => {
            crate::set_last_error(&format!("clientDisconnect: {e}"));
            AetherError::InternalError as Code
        }
    }
}

/// `clientFree`: disconnect and drop the handle. Idempotent by contract —
/// the host may free twice after a crash/restart path.
///
/// A free that races an in-flight call (e.g. `clientConnect` still in its
/// TLS handshake) is deferred: the handle is invalid at once and the
/// in-flight call disconnects the client when it returns. It used to report
/// success here while the in-flight call put the client back afterwards — a
/// "freed" handle that kept its live transport.
pub fn free(handle: usize) -> Code {
    crate::clear_last_error();
    let outcome = handles().request_free(handle, Teardown::Android);
    if let FreeOutcome::Freed(mut client) = outcome {
        crate::handles::tear_down(&mut client, Teardown::Android);
        crate::forget_staged(handle);
    }
    // Unknown handle: still success. The end state (no client) is what the
    // host asked for; an error here would only make teardown noisier.
    AetherError::Success as Code
}

/// `lastError`: text of the most recent failure, if any.
#[must_use]
pub fn last_error() -> Option<String> {
    crate::last_error_text()
}

fn checkout_failed(operation: &str, err: CheckoutError) -> Code {
    match err {
        CheckoutError::Invalid => {
            crate::set_last_error(&format!("{operation}: invalid client handle"));
            AetherError::InvalidHandle as Code
        }
        CheckoutError::Busy => {
            crate::set_last_error(&format!(
                "{operation}: client handle is busy with another call, retry"
            ));
            AetherError::Busy as Code
        }
    }
}

fn code_of(error: &ClientError) -> Code {
    match error {
        ClientError::PermissionDenied(_) => AetherError::PermissionDenied as Code,
        ClientError::StaleState(_) => AetherError::StaleState as Code,
        ClientError::ConfigError(_) => AetherError::InvalidConfig as Code,
        _ => AetherError::NetworkError as Code,
    }
}

/// JNI hands us an `int` fd; the transport socket handle is platform-typed.
#[cfg(unix)]
fn protect_with(protector: Protector<'_>, raw: SocketHandle) -> bool {
    protector(raw)
}

#[cfg(windows)]
fn protect_with(protector: Protector<'_>, raw: SocketHandle) -> bool {
    protector(raw as i32)
}

/// Close a `VpnService` fd that `attach` refused before wrapping it.
///
/// Android only: there the number really is the detached tun fd. Host builds
/// never receive one (tests pass made-up numbers that may alias the test
/// process's own descriptors), so nothing is closed there.
#[cfg(target_os = "android")]
fn release_fd(fd: i32) {
    use std::os::fd::{FromRawFd, OwnedFd};

    // Safety: Kotlin transferred ownership with `detachFd()` and never closes
    // it again; this is the only owner left.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
}

#[cfg(not(target_os = "android"))]
fn release_fd(_fd: i32) {}

/// Bridge the parked transport to the detached fd.
///
/// Android only: on a host build there is no `AndroidTun::attach` (the module
/// exists for tests with a fake `FdOps`), so a valid-looking fd cannot be
/// attached and must fail loudly instead of pretending.
#[cfg(target_os = "android")]
fn attach_tun(client: &mut Client, fd: i32, mtu: i32) -> Result<(), String> {
    use std::sync::{Arc, Mutex};

    use aetherlink_netstack::android_tun::AndroidTun;

    // Safety: the fd came from `ParcelFileDescriptor.detachFd()`; Kotlin
    // transferred ownership and must not close it.
    let tun = unsafe { AndroidTun::attach(fd, mtu as usize) }
        .map_err(|e| format!("android tun attach: {e}"))?;
    client
        .android_attach_tun_with(Arc::new(Mutex::new(tun)))
        .map_err(|e| format!("tls pump attach: {e}"))
}

#[cfg(not(target_os = "android"))]
fn attach_tun(_client: &mut Client, fd: i32, mtu: i32) -> Result<(), String> {
    Err(format!(
        "android tun attach is only available on Android (fd {fd}, mtu {mtu})"
    ))
}
