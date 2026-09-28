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
    let mut seen = vec![false; 8];
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
