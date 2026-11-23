//! RelayPool: bounded concurrent worker pool for blocking relay I/O.
//!
//! The serial tunnel loop must never stall behind one slow dial while a
//! fast DNS answer waits (seen live: 11s backlog, client gone by reply).
//! Slow closures run on worker threads; the caller stays responsive and
//! drains completions in arrival order.

use aetherlink_server::pool::RelayPool;
use std::time::{Duration, Instant};

#[test]
fn fast_result_first_despite_slow_job() {
    let pool: RelayPool<u16, &'static str> = RelayPool::new(2, 2);
    assert!(pool.dispatch(1, || {
        std::thread::sleep(Duration::from_millis(300));
        "slow"
    }));
    assert!(pool.dispatch(2, || "fast"));
    let first = pool
        .recv_timeout(Duration::from_secs(5))
        .expect("completion");
    assert_eq!(first.key, 2);
    assert_eq!(first.result, "fast");
}

#[test]
fn cap_fail_fast() {
    let pool: RelayPool<u16, &'static str> = RelayPool::new(1, 1);
    assert!(pool.dispatch(1, || {
        std::thread::sleep(Duration::from_millis(500));
        "blocked"
    }));
    // Give the worker a moment to pick the job up.
    std::thread::sleep(Duration::from_millis(50));
    assert!(!pool.dispatch(2, || "overflow"));
    let done = pool
        .recv_timeout(Duration::from_secs(5))
        .expect("completion");
    assert_eq!(done.key, 1);
}

#[test]
fn keys_and_results_round_trip() {
    let pool: RelayPool<u16, Result<Vec<u8>, ()>> = RelayPool::new(8, 8);
    for i in 0..8u16 {
        assert!(pool.dispatch(i, move || Ok(vec![i as u8])));
    }
    let mut seen = [false; 8];
    let deadline = Instant::now() + Duration::from_secs(5);
    for _ in 0..8 {
        let left = deadline.saturating_duration_since(Instant::now());
        let c = pool.recv_timeout(left).expect("completion");
        let payload = c.result.expect("ok");
        assert_eq!(payload, vec![c.key as u8]);
        seen[c.key as usize] = true;
    }
    assert!(seen.iter().all(|&b| b));
}

/// Regression: `dispatch` used to send the job *before* bumping `active`.
/// A fast worker could post its completion in between, the drain decremented
/// first, and `active` underflowed to `usize::MAX` — the pool then refused
/// every job for the rest of the process ("server busy" forever).
#[test]
fn fast_worker_never_underflows_the_active_counter() {
    let pool: RelayPool<u16, u16> = RelayPool::new(4, 4);
    // Hammer the exact interleaving: instant jobs, drained immediately.
    for round in 0..2_000u16 {
        assert!(
            pool.dispatch(round, move || round),
            "round {round}: pool must still accept jobs"
        );
        // No sleep: the worker may finish before the caller looks.
        let _ = pool.recv_timeout(Duration::from_secs(5));
    }
    // Then: accounting is back at zero and the pool is still usable.
    assert_eq!(pool.active(), 0, "active must not underflow or leak");
    assert!(pool.dispatch(0, || 0), "pool still accepts work");
}

/// Regression: a panicking job used to consume a pool slot forever, because
/// no completion was sent and only completions decrement `active`.
#[test]
fn panicking_job_returns_its_slot() {
    let pool: RelayPool<u16, &'static str> = RelayPool::new(1, 1);
    for round in 0..3u16 {
        assert!(
            pool.dispatch(round, || panic!("relay job blew up")),
            "round {round}: the slot from the previous panic must be free"
        );
        // The job has no result to report; wait for the slot to come back.
        let deadline = Instant::now() + Duration::from_secs(5);
        while pool.active() > 0 && Instant::now() < deadline {
            let _ = pool.try_recv();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(pool.active(), 0, "round {round}: slot not refunded");
    }
    // And: the pool still runs real work afterwards.
    assert!(pool.dispatch(99, || "ok"));
    let done = pool
        .recv_timeout(Duration::from_secs(5))
        .expect("completion after panics");
    assert_eq!(done.result, "ok");
}
