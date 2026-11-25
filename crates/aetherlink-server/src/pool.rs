//! Bounded worker pool for blocking relay I/O (std only, no runtime).
//!
//! The tunnel loop must stay responsive: one slow dial (5s timeout) must
//! not stall a fast DNS answer behind it (seen live: 11s serial backlog,
//! client gone before the reply). Slow closures run on worker threads;
//! the single caller dispatches (fail-fast at cap) and drains completions
//! in arrival order. Per-stream ordering is the caller's job.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, Receiver, Sender},
    Arc, Mutex,
};
use std::time::Duration;

type JobFn<R> = Box<dyn FnOnce() -> R + Send + 'static>;

struct Job<K, R> {
    key: K,
    work: JobFn<R>,
}

/// Refunds a reservation if `dispatch` fails before the job is queued.
struct SlotGuard<'a>(&'a AtomicUsize);

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        let _ = self
            .0
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |n| n.checked_sub(1));
    }
}

/// A completed job: caller key plus the closure's return value.
pub struct Completion<K, R> {
    pub key: K,
    pub result: R,
}

/// Fixed worker pool. `dispatch` returns `false` immediately when `cap`
/// jobs are already in flight (fail fast: the app retransmits; a busy
/// server must shed, not queue without bound).
pub struct RelayPool<K, R> {
    tx: Sender<Job<K, R>>,
    rx: Receiver<Completion<K, R>>,
    /// Release tokens: one is sent when a job finishes **without** posting a
    /// completion (a panicking job). Emptying `active` for a job that has no
    /// result must be decoupled from the result channel, because `R` has no
    /// synthesizable value.
    /// Keep-alive for the release channel: it is never read here, but dropping
    /// it would disconnect `released_rx` and make `try_recv` report
    /// `Disconnected` instead of `Empty`.
    #[allow(dead_code)]
    released_tx: Sender<()>,
    released_rx: Receiver<()>,
    cap: usize,
    active: AtomicUsize,
}

impl<K, R> RelayPool<K, R>
where
    K: Send + 'static,
    R: Send + 'static,
{
    /// Spawn `workers` threads; at most `cap` jobs in flight (running +
    /// queued). Past `cap` `dispatch` fails fast so a burst sheds instead
    /// of queueing without bound (each queued job pins its payload).
    /// Keep `cap` comfortably above the worst legit burst: shed TCP DATA
    /// is never retried past the client dedup, so shed must stay a
    /// flood-only event, not a burst event.
    #[must_use]
    pub fn new(workers: usize, cap: usize) -> Self {
        assert!(workers > 0, "pool needs at least one worker");
        assert!(cap >= workers, "cap must cover the workers");
        let (job_tx, job_rx) = mpsc::channel::<Job<K, R>>();
        let (done_tx, done_rx) = mpsc::channel::<Completion<K, R>>();
        let (released_tx, released_rx) = mpsc::channel::<()>();
        let shared = Arc::new(Mutex::new(job_rx));
        for idx in 0..workers {
            let jobs = Arc::clone(&shared);
            let done = done_tx.clone();
            let released = released_tx.clone();
            let _ = std::thread::Builder::new()
                .name(format!("relay-pool-{idx}"))
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    loop {
                        let job = match jobs.lock() {
                            Ok(guard) => guard.recv(),
                            Err(_) => break,
                        };
                        let job = match job {
                            Ok(job) => job,
                            Err(_) => break, // Pool dropped: exit.
                        };
                        let Job { key, work } = job;
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
                            Ok(result) => {
                                if done.send(Completion { key, result }).is_err() {
                                    break;
                                }
                            }
                            // A panicking job still has to give its slot back,
                            // otherwise `active` never drops and the pool wedges
                            // at "cap reached" for the rest of the session.
                            Err(_) => {
                                if released.send(()).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
        }
        Self {
            tx: job_tx,
            rx: done_rx,
            released_tx,
            released_rx,
            cap,
            active: AtomicUsize::new(0),
        }
    }

    /// Queue one job; `false` when at cap (job NOT run).
    pub fn dispatch(&self, key: K, work: impl FnOnce() -> R + Send + 'static) -> bool {
        // Reserve the slot before the job becomes visible to a worker. The
        // old order (send → fetch_add) let a fast worker post its completion
        // first, so the drain decremented an increment that had not happened
        // yet and `active` underflowed to `usize::MAX`: `dispatch` then
        // refused every job until the process restarted.
        let slot = match self
            .active
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                if n >= self.cap {
                    None
                } else {
                    Some(n + 1)
                }
            }) {
            Ok(_previous) => SlotGuard(&self.active),
            Err(_) => return false,
        };
        if self
            .tx
            .send(Job {
                key,
                work: Box::new(work),
            })
            .is_err()
        {
            // Pool dropped between the reservation and the send: this guard
            // release is the only refund needed.
            drop(slot);
            return false;
        }
        // Ownership of the reservation moves to the job: the worker (or the
        // panic path) returns it through `released`, or the reader refunds it
        // when the completion is drained.
        std::mem::forget(slot);
        true
    }

    /// One completion if already arrived, else `None`.
    pub fn try_recv(&self) -> Option<Completion<K, R>> {
        let drained = match self.rx.try_recv() {
            Ok(c) => {
                self.release_one();
                Some(c)
            }
            Err(_) => None,
        };
        // Panicked jobs report here instead: they hold no result, but they do
        // hold a reservation that must not leak.
        self.drain_released();
        drained
    }

    /// One completion within `d`, else `None`.
    pub fn recv_timeout(&self, d: Duration) -> Option<Completion<K, R>> {
        if let Ok(c) = self.rx.recv_timeout(d) {
            self.release_one();
            self.drain_released();
            return Some(c);
        }
        // Nothing finished in time; still refund any panicked jobs so the cap
        // accounting cannot drift while the caller waits.
        self.drain_released();
        None
    }

    /// Return one reservation (`active -= 1`, never wrapping).
    fn release_one(&self) {
        let _ = self
            .active
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |n| n.checked_sub(1));
    }

    /// Refund every reservation reported through the panic channel.
    fn drain_released(&self) {
        while self.released_rx.try_recv().is_ok() {
            self.release_one();
        }
    }

    /// Jobs currently in flight (dispatched, not yet drained).
    #[must_use]
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}
