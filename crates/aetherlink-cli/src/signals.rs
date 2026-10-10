//! Shutdown signaling: SIGINT/SIGTERM via `sigwait` (no extra deps).
//!
//! The mask is installed process-wide before any worker spawns, so the
//! dedicated waiter thread is the sole signal consumer; `up` blocks on the
//! channel instead of racing handlers.

use std::sync::mpsc;

/// Channel that fires once on SIGINT/SIGTERM. Returns the receiver to wait
/// on and a sender clone for other shutdown sources (pump watchdog).
#[cfg(unix)]
pub fn shutdown_channel() -> (mpsc::Receiver<&'static str>, mpsc::Sender<&'static str>) {
    let (tx, rx) = mpsc::channel();
    // Block INT/TERM on every thread so sigwait below owns them.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let waiter = tx.clone();
    std::thread::spawn(move || {
        let mut sig: libc::c_int = 0;
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::sigwait(&set, &mut sig);
        }
        if std::env::var_os("AETHERLINK_DEBUG").is_some() {
            eprintln!("[aetherlink-cli] signal {sig} received, shutting down");
        }
        let _ = waiter.send("signal");
    });
    (rx, tx)
}

/// Non-unix fallback (the CLI targets Linux; this keeps the build portable):
/// wait on stdin EOF (Ctrl+D / closed console).
#[cfg(not(unix))]
pub fn shutdown_channel() -> (mpsc::Receiver<&'static str>, mpsc::Sender<&'static str>) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf);
        let _ = tx.send("signal");
    });
    (rx, tx)
}
