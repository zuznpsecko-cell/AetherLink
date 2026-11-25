//! Accept-loop policy: which `accept()` errors are survivable, and that the
//! loop really survives them.
//!
//! Regression for the loop that ended on *any* non-`WouldBlock` error: one
//! `ECONNABORTED` (a peer resetting before we accepted it) or an `EMFILE`
//! under load silently stopped the server from accepting while the process —
//! and its systemd unit — stayed "running".

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aetherlink_server::{
    accept_backoff, classify_accept_error, run_accept_loop, AcceptErrorAction, ACCEPT_BACKOFF_MAX,
    ACCEPT_IDLE_POLL, ACCEPT_RETRY_BURST,
};

fn kind(k: io::ErrorKind) -> io::Error {
    io::Error::from(k)
}

/// Scripted `accept()`: pops one outcome per call and raises `stop` once the
/// script is exhausted, so a loop that survives everything ends with `Ok`.
fn scripted(
    stop: &AtomicBool,
    script: Vec<io::Result<u32>>,
) -> impl FnMut() -> io::Result<u32> + '_ {
    let mut script: VecDeque<_> = script.into();
    move || {
        let next = script
            .pop_front()
            .unwrap_or_else(|| Err(kind(io::ErrorKind::WouldBlock)));
        if script.is_empty() {
            stop.store(true, Ordering::Relaxed);
        }
        next
    }
}

#[test]
fn would_block_is_idle() {
    assert_eq!(
        classify_accept_error(&kind(io::ErrorKind::WouldBlock)),
        AcceptErrorAction::Idle
    );
}

#[test]
fn per_peer_errors_retry() {
    for k in [
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::Interrupted,
        io::ErrorKind::TimedOut,
    ] {
        assert_eq!(
            classify_accept_error(&kind(k)),
            AcceptErrorAction::Retry,
            "{k:?}"
        );
    }
}

#[test]
fn invalid_input_is_fatal() {
    // EINVAL / WSAEINVAL: the socket is not listening any more.
    assert_eq!(
        classify_accept_error(&kind(io::ErrorKind::InvalidInput)),
        AcceptErrorAction::Fatal
    );
}

#[test]
fn unknown_errors_back_off_instead_of_ending_the_loop() {
    assert_eq!(
        classify_accept_error(&io::Error::other("something new")),
        AcceptErrorAction::Backoff
    );
}

#[cfg(unix)]
#[test]
fn errno_classification_matches_accept_2() {
    let os = io::Error::from_raw_os_error;
    // Resource exhaustion: back off and keep serving.
    for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
        assert_eq!(
            classify_accept_error(&os(code)),
            AcceptErrorAction::Backoff,
            "errno {code}"
        );
    }
    // Errors reported on behalf of the pending peer: retry at once.
    for code in [
        libc::ECONNABORTED,
        libc::EPROTO,
        libc::ENETUNREACH,
        libc::EHOSTUNREACH,
    ] {
        assert_eq!(
            classify_accept_error(&os(code)),
            AcceptErrorAction::Retry,
            "errno {code}"
        );
    }
    // The listener descriptor itself is broken: stop.
    for code in [libc::EBADF, libc::ENOTSOCK, libc::EINVAL] {
        assert_eq!(
            classify_accept_error(&os(code)),
            AcceptErrorAction::Fatal,
            "errno {code}"
        );
    }
}

#[test]
fn backoff_doubles_from_10ms_and_is_capped() {
    assert_eq!(accept_backoff(0), Duration::from_millis(10));
    assert_eq!(accept_backoff(1), Duration::from_millis(10));
    assert_eq!(accept_backoff(2), Duration::from_millis(20));
    assert_eq!(accept_backoff(3), Duration::from_millis(40));
    assert_eq!(accept_backoff(8), ACCEPT_BACKOFF_MAX);
    assert_eq!(accept_backoff(u32::MAX), ACCEPT_BACKOFF_MAX);
}

#[test]
fn loop_survives_a_peer_abort_and_keeps_accepting() {
    let stop = AtomicBool::new(false);
    let mut accepted = Vec::new();
    let mut sleeps = Vec::new();

    let outcome = run_accept_loop(
        &stop,
        scripted(
            &stop,
            vec![
                Ok(1),
                Err(kind(io::ErrorKind::ConnectionAborted)),
                Ok(2),
                Err(kind(io::ErrorKind::WouldBlock)),
                Ok(3),
            ],
        ),
        |c| accepted.push(c),
        |d| sleeps.push(d),
    );

    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(
        accepted,
        [1, 2, 3],
        "connections after the abort are served"
    );
    assert_eq!(
        sleeps,
        [ACCEPT_IDLE_POLL],
        "a single abort retries at once; only WouldBlock idles"
    );
}

#[cfg(unix)]
#[test]
fn loop_backs_off_on_emfile_and_recovers() {
    let stop = AtomicBool::new(false);
    let mut accepted = Vec::new();
    let mut sleeps = Vec::new();
    let emfile = || Err(io::Error::from_raw_os_error(libc::EMFILE));

    let outcome = run_accept_loop(
        &stop,
        scripted(&stop, vec![emfile(), emfile(), emfile(), Ok(7)]),
        |c| accepted.push(c),
        |d| sleeps.push(d),
    );

    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(accepted, [7], "serving resumes once descriptors free up");
    assert_eq!(
        sleeps,
        [
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(40)
        ]
    );
}

#[test]
fn an_endless_abort_storm_backs_off_instead_of_spinning() {
    let stop = AtomicBool::new(false);
    let mut sleeps = Vec::new();
    let burst = ACCEPT_RETRY_BURST as usize;
    let storm: Vec<io::Result<u32>> = (0..burst + 3)
        .map(|_| Err(kind(io::ErrorKind::ConnectionAborted)))
        .collect();

    let outcome = run_accept_loop(&stop, scripted(&stop, storm), |_| {}, |d| sleeps.push(d));

    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(
        sleeps,
        [
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(40)
        ],
        "the first {burst} aborts retry at once, the rest back off"
    );
}

#[test]
fn a_success_resets_the_failure_streak() {
    let stop = AtomicBool::new(false);
    let mut sleeps = Vec::new();
    let other = || Err(io::Error::other("transient"));

    let outcome = run_accept_loop(
        &stop,
        scripted(&stop, vec![other(), other(), Ok(1), other()]),
        |_| {},
        |d| sleeps.push(d),
    );

    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(
        sleeps,
        [
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(10)
        ]
    );
}

#[test]
fn a_broken_listener_ends_the_loop_with_its_error() {
    let stop = AtomicBool::new(false);
    let mut accepted = Vec::new();

    let outcome = run_accept_loop(
        &stop,
        scripted(
            &stop,
            vec![
                Ok(1),
                Err(kind(io::ErrorKind::InvalidInput)),
                Ok(2), // never reached
            ],
        ),
        |c| accepted.push(c),
        |_| {},
    );

    let err = outcome.expect_err("a fatal listener error must surface");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(accepted, [1]);
    assert!(
        !stop.load(Ordering::Relaxed),
        "ended by the error, not the stop flag"
    );
}

#[test]
fn a_raised_stop_flag_ends_the_loop_before_accepting() {
    let stop = AtomicBool::new(true);
    let mut calls = 0;
    let outcome = run_accept_loop(
        &stop,
        || {
            calls += 1;
            Ok::<u32, io::Error>(1)
        },
        |_| {},
        |_| {},
    );
    assert!(outcome.is_ok());
    assert_eq!(calls, 0);
}
