//! Process-global handle table shared by the C ABI and the JNI bridge.
//!
//! Two rules shape this module (DEC-019, DEC-024):
//!
//! 1. **No lock across network I/O.** A call checks its client *out* of the
//!    table, works without the lock, and checks it back *in*.
//! 2. **A checked-out client still owns its handle.** The slot stays in the
//!    table as [`Slot::Busy`], so a concurrent call sees "busy" (not "invalid
//!    handle"), and a concurrent `free` is *recorded* instead of being lost.
//!    The call that holds the client performs the deferred teardown when it
//!    checks the client back in.
//!
//! The old table removed the client for the duration of a call and put it
//! back with `entry().or_insert()`. A `free` that raced an in-flight `up`
//! found nothing to free (C ABI: "invalid handle"; JNI: "success" without
//! doing anything) and the in-flight call then *re-inserted* the client:
//! a freed handle came back to life holding a live TLS session and TUN.
//!
//! [`Lease`] is the only way calls borrow a client. Its `Drop` covers the
//! panic path: if a call unwinds while holding the client, the handle is
//! discarded and the client torn down, instead of leaving a slot that stays
//! "busy" forever.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use aetherlink_client::Client;
use aetherlink_server::ServerGuard;
use once_cell::sync::Lazy;

/// How a client is torn down when its handle is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Teardown {
    /// Desktop host: `down()` restores routes and DNS.
    Desktop,
    /// Android host: `android_disconnect()`; the OS owns routes/DNS.
    Android,
}

/// One client slot.
enum Slot {
    /// Parked in the table, available to the next call. Boxed: a `Client`
    /// is large next to the `Busy` marker.
    Idle(Box<Client>),
    /// Checked out by a call. `free_requested` records a `free` that arrived
    /// meanwhile (and how the freeing host wants the client torn down).
    Busy { free_requested: Option<Teardown> },
}

/// Copy of a slot's state (no borrow of the client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Missing,
    Idle,
    Busy(Option<Teardown>),
}

/// Why a client could not be checked out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckoutError {
    /// Unknown handle, or one already freed.
    Invalid,
    /// Another call on the same handle is in flight.
    Busy,
}

/// Result of a `free` request.
pub(crate) enum FreeOutcome {
    /// The client was idle: it is out of the table, the caller tears it down.
    Freed(Box<Client>),
    /// A call holds the client: the free is recorded and that call tears it
    /// down when it finishes.
    Deferred,
    /// Unknown handle (or already freed).
    Unknown,
}

/// The table itself. Fields are private: every access goes through the
/// methods below so the slot state machine cannot be bypassed.
pub(crate) struct HandleMap {
    clients: HashMap<usize, Slot>,
    servers: HashMap<usize, ServerGuard>,
    next_id: usize,
}

impl HandleMap {
    fn new() -> Self {
        Self {
            clients: HashMap::new(),
            servers: HashMap::new(),
            next_id: 1,
        }
    }

    fn allocate_id(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub(crate) fn insert_client(&mut self, client: Client) -> usize {
        let id = self.allocate_id();
        self.clients.insert(id, Slot::Idle(Box::new(client)));
        id
    }

    pub(crate) fn insert_server(&mut self, guard: ServerGuard) -> usize {
        let id = self.allocate_id();
        self.servers.insert(id, guard);
        id
    }

    /// Copy out the slot state, so the mutations below never overlap a
    /// borrow of the slot they replace.
    fn state(&self, handle: usize) -> State {
        match self.clients.get(&handle) {
            None => State::Missing,
            Some(Slot::Idle(_)) => State::Idle,
            Some(Slot::Busy { free_requested }) => State::Busy(*free_requested),
        }
    }

    /// Does this handle name a live client (idle, or busy and not freed)?
    pub(crate) fn contains_client(&self, handle: usize) -> bool {
        matches!(self.state(handle), State::Idle | State::Busy(None))
    }

    /// Take the client for one call; the slot stays behind as `Busy`.
    pub(crate) fn checkout(&mut self, handle: usize) -> Result<Client, CheckoutError> {
        match self.state(handle) {
            State::Missing | State::Busy(Some(_)) => Err(CheckoutError::Invalid),
            State::Busy(None) => Err(CheckoutError::Busy),
            State::Idle => match self.clients.insert(
                handle,
                Slot::Busy {
                    free_requested: None,
                },
            ) {
                Some(Slot::Idle(client)) => Ok(*client),
                _ => unreachable!("slot was Idle under the same lock"),
            },
        }
    }

    /// Give a checked-out client back.
    ///
    /// Returns `Some` when the handle was freed while the call was in flight:
    /// the slot is gone and the caller must tear the client down (outside the
    /// lock) the way the freeing host asked. `fallback` is the caller's own
    /// teardown, used if the slot vanished some other way.
    pub(crate) fn checkin(
        &mut self,
        handle: usize,
        client: Client,
        fallback: Teardown,
    ) -> Option<(Client, Teardown)> {
        match self.state(handle) {
            State::Busy(None) => {
                self.clients.insert(handle, Slot::Idle(Box::new(client)));
                None
            }
            State::Busy(Some(kind)) => {
                self.clients.remove(&handle);
                Some((client, kind))
            }
            // Not checked out by us (cannot happen through `Lease`): never
            // overwrite another slot, never resurrect a vanished handle.
            State::Idle | State::Missing => Some((client, fallback)),
        }
    }

    /// Drop a `Busy` slot whose client was lost (panic in the call).
    pub(crate) fn discard(&mut self, handle: usize) {
        if matches!(self.state(handle), State::Busy(_)) {
            self.clients.remove(&handle);
        }
    }

    /// Release a client handle (see [`FreeOutcome`]).
    pub(crate) fn request_free(&mut self, handle: usize, teardown: Teardown) -> FreeOutcome {
        match self.state(handle) {
            State::Missing => FreeOutcome::Unknown,
            // Already being freed: the end state is the one asked for, and
            // the first request's teardown stands.
            State::Busy(Some(_)) => FreeOutcome::Deferred,
            State::Busy(None) => {
                self.clients.insert(
                    handle,
                    Slot::Busy {
                        free_requested: Some(teardown),
                    },
                );
                FreeOutcome::Deferred
            }
            State::Idle => match self.clients.remove(&handle) {
                Some(Slot::Idle(client)) => FreeOutcome::Freed(client),
                _ => unreachable!("slot was Idle under the same lock"),
            },
        }
    }

    /// Run `f` on an idle client without checking it out (cheap, in-memory
    /// reads only — never network or filesystem work under the lock).
    pub(crate) fn with_idle_client<R>(
        &self,
        handle: usize,
        f: impl FnOnce(&Client) -> R,
    ) -> Result<R, CheckoutError> {
        match self.clients.get(&handle) {
            Some(Slot::Idle(client)) => Ok(f(client.as_ref())),
            Some(Slot::Busy {
                free_requested: None,
            }) => Err(CheckoutError::Busy),
            Some(Slot::Busy {
                free_requested: Some(_),
            })
            | None => Err(CheckoutError::Invalid),
        }
    }

    pub(crate) fn remove_server(&mut self, handle: usize) -> Option<ServerGuard> {
        self.servers.remove(&handle)
    }

    pub(crate) fn server(&self, handle: usize) -> Option<&ServerGuard> {
        self.servers.get(&handle)
    }
}

/// Global handle storage.
static HANDLES: Lazy<Mutex<HandleMap>> = Lazy::new(|| Mutex::new(HandleMap::new()));

/// Lock the table, tolerating poison.
///
/// A panic while the lock was held (contained by `ffi_guard`) must not turn
/// every later FFI call into another panic: the table's invariants hold
/// between method calls, so the data behind a poisoned lock is still valid.
pub(crate) fn handles() -> MutexGuard<'static, HandleMap> {
    HANDLES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Tear a client down, containing any panic from the teardown itself (it may
/// run while another panic is unwinding, where a second panic would abort).
pub(crate) fn tear_down(client: &mut Client, kind: Teardown) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match kind {
        Teardown::Desktop => {
            let _ = client.down();
        }
        Teardown::Android => {
            let _ = client.android_disconnect();
        }
    }));
}

/// A client checked out for the duration of one FFI call.
///
/// Call [`Lease::finish`] to check it back in. If the lease is dropped
/// without `finish` — only possible when the call panicked — the handle is
/// discarded and the client torn down: its state is unknown, and a tunnel
/// left up without a handle could never be brought down by the host.
pub(crate) struct Lease {
    handle: usize,
    client: Option<Client>,
    teardown: Teardown,
}

impl Lease {
    /// Check `handle` out; `teardown` is how this host tears clients down.
    pub(crate) fn checkout(handle: usize, teardown: Teardown) -> Result<Self, CheckoutError> {
        let client = handles().checkout(handle)?;
        Ok(Self {
            handle,
            client: Some(client),
            teardown,
        })
    }

    /// The borrowed client.
    pub(crate) fn client(&mut self) -> &mut Client {
        self.client
            .as_mut()
            .expect("lease holds its client until finish")
    }

    /// Check the client back in; performs a `free` that arrived meanwhile.
    pub(crate) fn finish(mut self) {
        let Some(client) = self.client.take() else {
            return;
        };
        // Bind first: the lock guard must be released before the teardown,
        // which does network work.
        let deferred = handles().checkin(self.handle, client, self.teardown);
        if let Some((mut client, kind)) = deferred {
            tear_down(&mut client, kind);
            crate::forget_staged(self.handle);
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(mut client) = self.client.take() {
            handles().discard(self.handle);
            tear_down(&mut client, self.teardown);
            crate::forget_staged(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        Client::new(serde_json::json!({
            "server_addr": "127.0.0.1:9",
            "psk": "handles-unit-test-psk",
        }))
        .expect("client")
    }

    #[test]
    fn checkout_marks_the_slot_busy_instead_of_removing_it() {
        let mut map = HandleMap::new();
        let h = map.insert_client(client());

        let c = map.checkout(h).expect("idle client");
        // A second call on the same handle sees "busy", not "invalid".
        assert!(matches!(map.checkout(h), Err(CheckoutError::Busy)));
        assert!(map.contains_client(h));

        assert!(
            map.checkin(h, c, Teardown::Desktop).is_none(),
            "plain check-in parks it"
        );
        assert!(map.checkout(h).is_ok(), "idle again after check-in");
    }

    #[test]
    fn free_during_a_call_is_deferred_not_lost() {
        let mut map = HandleMap::new();
        let h = map.insert_client(client());
        let c = map.checkout(h).expect("idle client");

        // When: the host frees the handle while the call is in flight
        assert!(matches!(
            map.request_free(h, Teardown::Android),
            FreeOutcome::Deferred
        ));
        // Then: the handle is already gone for everybody else...
        assert!(!map.contains_client(h));
        assert!(matches!(map.checkout(h), Err(CheckoutError::Invalid)));
        // ...and check-in hands the client back for teardown instead of
        // resurrecting the handle (the old `or_insert` bug).
        let (_, kind) = map
            .checkin(h, c, Teardown::Desktop)
            .expect("deferred free must surface");
        assert_eq!(kind, Teardown::Android);
        assert!(!map.contains_client(h));
        assert!(matches!(
            map.request_free(h, Teardown::Desktop),
            FreeOutcome::Unknown
        ));
    }

    #[test]
    fn free_of_an_idle_client_hands_it_over() {
        let mut map = HandleMap::new();
        let h = map.insert_client(client());
        assert!(matches!(
            map.request_free(h, Teardown::Desktop),
            FreeOutcome::Freed(_)
        ));
        assert!(matches!(
            map.request_free(h, Teardown::Desktop),
            FreeOutcome::Unknown
        ));
    }

    #[test]
    fn repeated_free_while_busy_stays_deferred() {
        let mut map = HandleMap::new();
        let h = map.insert_client(client());
        let c = map.checkout(h).expect("idle client");
        assert!(matches!(
            map.request_free(h, Teardown::Desktop),
            FreeOutcome::Deferred
        ));
        assert!(matches!(
            map.request_free(h, Teardown::Android),
            FreeOutcome::Deferred
        ));
        // The first request wins: that host asked first.
        let (_, kind) = map.checkin(h, c, Teardown::Android).expect("deferred free");
        assert_eq!(kind, Teardown::Desktop);
    }

    #[test]
    fn discard_drops_only_busy_slots() {
        let mut map = HandleMap::new();
        let idle = map.insert_client(client());
        let busy = map.insert_client(client());
        let _lost = map.checkout(busy).expect("idle client");

        map.discard(idle);
        map.discard(busy);
        assert!(map.contains_client(idle), "idle client is not discarded");
        assert!(!map.contains_client(busy), "lost busy slot is gone");
    }

    #[test]
    fn idle_reads_report_busy_and_invalid() {
        let mut map = HandleMap::new();
        let h = map.insert_client(client());
        assert_eq!(map.with_idle_client(h, |_| 7), Ok(7));
        let c = map.checkout(h).expect("idle client");
        assert_eq!(map.with_idle_client(h, |_| 7), Err(CheckoutError::Busy));
        let _ = map.checkin(h, c, Teardown::Desktop);
        assert_eq!(
            map.with_idle_client(usize::MAX, |_| 7),
            Err(CheckoutError::Invalid)
        );
    }
}
