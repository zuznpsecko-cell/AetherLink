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
        let shared = Arc::new(Mutex::new(job_rx));
        for _ in 0..workers {
            let jobs = Arc::clone(&shared);
            let done = done_tx.clone();
            std::thread::spawn(move || {
                loop {
                    let job = match jobs.lock() {
                        Ok(guard) => guard.recv(),
                        Err(_) => break,
                    };
                    let job = match job {
                        Ok(job) => job,
                        Err(_) => break, // Pool dropped: exit.
                    };
                    let result = (job.work)();
                    if done
                        .send(Completion {
                            key: job.key,
                            result,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        Self {
            tx: job_tx,
            rx: done_rx,
            cap,
            active: AtomicUsize::new(0),
        }
    }

    /// Queue one job; `false` when at cap (job NOT run).
    pub fn dispatch(&self, key: K, work: impl FnOnce() -> R + Send + 'static) -> bool {
        if self.active.load(Ordering::SeqCst) >= self.cap {
            return false;
        }
        if self
            .tx
            .send(Job {
                key,
                work: Box::new(work),
            })
            .is_err()
        {
            return false;
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// One completion if already arrived, else `None`.
    pub fn try_recv(&self) -> Option<Completion<K, R>> {
        match self.rx.try_recv() {
            Ok(c) => {
                self.active.fetch_sub(1, Ordering::SeqCst);
                Some(c)
            }
            Err(_) => None,
        }
    }

    /// One completion within `d`, else `None`.
    pub fn recv_timeout(&self, d: Duration) -> Option<Completion<K, R>> {
        match self.rx.recv_timeout(d) {
            Ok(c) => {
                self.active.fetch_sub(1, Ordering::SeqCst);
                Some(c)
            }
            Err(_) => None,
        }
    }

    /// Jobs currently in flight (dispatched, not yet drained).
    #[must_use]
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}
