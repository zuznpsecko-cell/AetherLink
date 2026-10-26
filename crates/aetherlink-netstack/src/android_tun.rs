//! Android TUN device over a detached `VpnService` file descriptor.
//!
//! `VpnService.Builder.establish()` hands the host a `ParcelFileDescriptor`;
//! Kotlin detaches the raw fd and passes only the integer across JNI. Rust
//! owns it from then on (including `close`), reads one IP packet per `read`,
//! and writes with a full-write loop.
//!
//! `FdOps` is the seam: the real implementation wraps `libc`, tests drive the
//! packet/no-packet/short-write/close paths with a fake and never need a
//! device or a TUN driver.
//!
//! L0: fake `FdOps`, no device.

use std::io::{self, ErrorKind};
use std::time::{Duration, Instant};

use crate::tun::TunPackets;
use crate::{NetstackError, Result};

/// Biggest IP packet the netstack can hand to a TUN.
pub const MAX_IP_PACKET: usize = 65_535;

/// Smallest MTU that can carry a minimal IPv4 datagram.
pub const MIN_MTU: usize = 68;

const IPV4_HEADER_LEN: usize = 20;

/// How long a single packet may wait for a writable descriptor.
const WRITE_BUDGET: Duration = Duration::from_secs(1);

/// Raw descriptor operations: the seam between [`AndroidTun`] and the OS.
///
/// Android supplies an fd from `ParcelFileDescriptor.detachFd()`. Tests supply
/// an in-memory fake, so packet framing, `EAGAIN` and the close-once rule are
/// checked on the host (L0).
pub trait FdOps: Send {
    /// Read at most one packet. `WouldBlock` means "nothing queued".
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write part of a packet; short writes are legal and completed by the
    /// caller.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;

    /// Wait until the descriptor is readable (`writable == false`) or
    /// writable. `Ok(false)` means the timeout elapsed.
    fn poll(&mut self, writable: bool, timeout: Duration) -> io::Result<bool>;

    /// Release the descriptor. Called exactly once by [`AndroidTun`].
    fn close(&mut self) -> io::Result<()>;
}

/// TUN device backed by a detached Android fd.
///
/// Owns the descriptor: dropping the value closes it. Reads never block the
/// caller (`O_NONBLOCK` is set by [`AndroidTun::attach`]) because the pump
/// polls the device from a thread that also serves the mux.
pub struct AndroidTun {
    ops: Box<dyn FdOps>,
    mtu: usize,
    scratch: Vec<u8>,
    closed: bool,
}

impl std::fmt::Debug for AndroidTun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidTun")
            .field("mtu", &self.mtu)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl AndroidTun {
    /// Wrap an fd source with an explicit MTU.
    ///
    /// A rejected MTU still closes the descriptor: the caller has already
    /// detached it from the `ParcelFileDescriptor` and cannot release it.
    pub fn with_ops(ops: Box<dyn FdOps>, mtu: usize) -> Result<Self> {
        let mut ops = ops;
        if !(MIN_MTU..=MAX_IP_PACKET).contains(&mtu) {
            let _ = ops.close();
            return Err(NetstackError::TunError(format!(
                "bad tun mtu {mtu} ({MIN_MTU}..={MAX_IP_PACKET})"
            )));
        }
        Ok(Self {
            ops,
            mtu,
            scratch: vec![0u8; MAX_IP_PACKET],
            closed: false,
        })
    }

    /// Take ownership of a detached `VpnService` fd and make it non-blocking.
    ///
    /// # Safety
    ///
    /// `fd` must be a live, owned descriptor (from `detachFd()`); it is closed
    /// when this value is dropped. Passing an fd someone else still uses
    /// double-closes it.
    #[cfg(unix)]
    pub unsafe fn attach(fd: std::os::fd::RawFd, mtu: usize) -> Result<Self> {
        let ops = real::RealFd::new(fd)?;
        Self::with_ops(Box::new(ops), mtu)
    }

    /// MTU this device was configured with.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// True once the descriptor has been released.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Release the descriptor now. Idempotent; `Drop` calls it too.
    ///
    /// The flag flips before the syscall, so a failing `close` is not retried
    /// by `Drop` (retrying a close whose fd may already be reused is worse
    /// than losing the error).
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.ops.close().map_err(NetstackError::Io)
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed {
            return Err(NetstackError::TunError(
                "tun descriptor is already closed".to_string(),
            ));
        }
        Ok(())
    }
}

impl TunPackets for AndroidTun {
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        self.ensure_open()?;
        let Self { ops, scratch, .. } = self;
        match ops.read(scratch) {
            Ok(0) => Err(NetstackError::TunError(
                "tun read returned 0 bytes (descriptor closed)".to_string(),
            )),
            Ok(n) => {
                // A TUN read is one whole packet, so anything smaller than an
                // IP header is framing garbage, not a packet to forward.
                if n < IPV4_HEADER_LEN {
                    return Err(NetstackError::InvalidPacket(format!(
                        "short read: {n} bytes from the tun device"
                    )));
                }
                let packet = &scratch[..n];
                // Android hands us whatever the interface received; IPv6 is
                // dropped later by the pump, not here.
                if packet[0] >> 4 == 4 {
                    let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
                    if declared > n {
                        return Err(NetstackError::InvalidPacket(format!(
                            "truncated ipv4 packet: {declared} bytes declared, {n} read"
                        )));
                    }
                }
                Ok(Some(packet.to_vec()))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                Ok(None)
            }
            Err(e) => Err(NetstackError::Io(e)),
        }
    }

    fn send_packet(&mut self, pkt: &[u8]) -> Result<()> {
        self.ensure_open()?;
        let deadline = Instant::now() + WRITE_BUDGET;
        let mut sent = 0usize;
        while sent < pkt.len() {
            match self.ops.write(&pkt[sent..]) {
                Ok(0) => {
                    return Err(NetstackError::TunError(
                        "tun write returned 0 bytes".to_string(),
                    ))
                }
                Ok(n) => sent += n,
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(NetstackError::TunError(
                            "tun write timed out: descriptor stayed unwritable".to_string(),
                        ));
                    }
                    if !self.ops.poll(true, deadline - now)? {
                        return Err(NetstackError::TunError(
                            "tun write timed out: descriptor stayed unwritable".to_string(),
                        ));
                    }
                }
                Err(e) => return Err(NetstackError::Io(e)),
            }
        }
        Ok(())
    }
}

impl Drop for AndroidTun {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(unix)]
mod real {
    use std::io;
    use std::os::fd::RawFd;
    use std::time::Duration;

    use super::FdOps;

    /// `libc`-backed descriptor used on Android (and Linux tests).
    pub struct RealFd {
        fd: RawFd,
    }

    impl RealFd {
        pub fn new(fd: RawFd) -> io::Result<Self> {
            // The pump treats the TUN as a polled source; a blocking read
            // would freeze the thread that also drains the TLS session.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd })
        }
    }

    impl FdOps for RealFd {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }

        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = unsafe { libc::write(self.fd, buf.as_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }

        fn poll(&mut self, writable: bool, timeout: Duration) -> io::Result<bool> {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: if writable {
                    libc::POLLOUT
                } else {
                    libc::POLLIN
                },
                revents: 0,
            };
            let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
            loop {
                let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                if rc < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(err);
                }
                return Ok(rc > 0);
            }
        }

        fn close(&mut self) -> io::Result<()> {
            let rc = unsafe { libc::close(self.fd) };
            if rc < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{AndroidTun, FdOps};
    use crate::tun::TunPackets;
    use crate::NetstackError;

    /// What a fake `read` does next.
    enum ReadStep {
        /// A complete packet, as the kernel would deliver it.
        Packet(Vec<u8>),
        /// No packet queued (`EAGAIN`).
        Blocked,
        /// The descriptor is gone (`read` returned 0).
        Eof,
    }

    /// Shared fake: `Arc<Mutex<_>>` keeps a handle for assertions while the
    /// `AndroidTun` owns the ops trait object.
    #[derive(Default)]
    struct FakeFd {
        reads: VecDeque<ReadStep>,
        /// Bytes accepted per `write` (partial writes when smaller).
        max_write: usize,
        /// `write` calls that return `WouldBlock` before accepting data.
        blocked_writes: usize,
        /// What `poll` reports.
        poll_ready: bool,
        written: Vec<u8>,
        writes: usize,
        polls: usize,
        closes: usize,
    }

    struct FakeHandle(Arc<Mutex<FakeFd>>);

    impl FdOps for FakeHandle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut fake = self.0.lock().expect("fake lock");
            match fake.reads.pop_front().unwrap_or(ReadStep::Blocked) {
                ReadStep::Packet(packet) => {
                    let n = packet.len().min(buf.len());
                    buf[..n].copy_from_slice(&packet[..n]);
                    Ok(n)
                }
                ReadStep::Blocked => Err(io::ErrorKind::WouldBlock.into()),
                ReadStep::Eof => Ok(0),
            }
        }

        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut fake = self.0.lock().expect("fake lock");
            fake.writes += 1;
            if fake.blocked_writes > 0 {
                fake.blocked_writes -= 1;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = if fake.max_write == 0 {
                buf.len()
            } else {
                buf.len().min(fake.max_write)
            };
            fake.written.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn poll(&mut self, _writable: bool, _timeout: Duration) -> io::Result<bool> {
            let mut fake = self.0.lock().expect("fake lock");
            fake.polls += 1;
            Ok(fake.poll_ready)
        }

        fn close(&mut self) -> io::Result<()> {
            self.0.lock().expect("fake lock").closes += 1;
            Ok(())
        }
    }

    fn fake() -> (Arc<Mutex<FakeFd>>, AndroidTun) {
        let fake = Arc::new(Mutex::new(FakeFd::default()));
        let tun = AndroidTun::with_ops(Box::new(FakeHandle(Arc::clone(&fake))), 1500)
            .expect("tun handle");
        (fake, tun)
    }

    /// A well-formed IPv4 packet: version 4, IHL 5, correct total length.
    fn ipv4_packet(payload: usize) -> Vec<u8> {
        let total = 20 + payload;
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet
    }

    fn queue_read(fake: &Arc<Mutex<FakeFd>>, step: ReadStep) {
        fake.lock().expect("fake lock").reads.push_back(step);
    }

    #[test]
    fn one_read_is_one_packet() {
        let (fake, mut tun) = fake();
        let packet = ipv4_packet(40);
        queue_read(&fake, ReadStep::Packet(packet.clone()));

        assert_eq!(tun.try_recv().expect("read"), Some(packet));

        // Nothing queued after that: an idle TUN is `None`, not an error.
        assert_eq!(tun.try_recv().expect("idle read"), None);
    }

    #[test]
    fn eagain_means_no_packet() {
        let (_fake, mut tun) = fake();

        assert_eq!(tun.try_recv().expect("eagain"), None);
    }

    #[test]
    fn a_short_read_is_an_error() {
        let (fake, mut tun) = fake();
        queue_read(&fake, ReadStep::Packet(vec![0x45, 0, 0]));

        let err = tun
            .try_recv()
            .expect_err("a 3-byte packet is not an IP frame");
        assert!(
            matches!(err, NetstackError::InvalidPacket(_)),
            "wrong error: {err}"
        );
        assert!(err.to_string().contains("short"), "unhelpful error: {err}");
    }

    #[test]
    fn a_truncated_ipv4_packet_is_an_error() {
        let (fake, mut tun) = fake();
        // Header claims 100 bytes, the device delivered 40.
        let mut packet = ipv4_packet(20);
        packet[2..4].copy_from_slice(&100u16.to_be_bytes());
        queue_read(&fake, ReadStep::Packet(packet));

        let err = tun.try_recv().expect_err("truncated IPv4 must be rejected");
        assert!(
            matches!(err, NetstackError::InvalidPacket(_)),
            "wrong error: {err}"
        );
        assert!(
            err.to_string().contains("truncated"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn a_zero_read_means_the_descriptor_is_gone() {
        let (fake, mut tun) = fake();
        queue_read(&fake, ReadStep::Eof);

        let err = tun.try_recv().expect_err("EOF is not an idle TUN");
        assert!(matches!(err, NetstackError::TunError(_)), "{err}");
    }

    #[test]
    fn send_packet_loops_until_every_byte_is_written() {
        let (fake, mut tun) = fake();
        fake.lock().expect("fake lock").max_write = 7;
        let packet = ipv4_packet(30);

        tun.send_packet(&packet).expect("send");

        let fake = fake.lock().expect("fake lock");
        assert_eq!(fake.written, packet, "partial writes must be completed");
        assert!(
            fake.writes > 1,
            "the fake caps writes at 7 bytes, so one write cannot be enough"
        );
    }

    #[test]
    fn send_packet_polls_and_retries_on_eagain() {
        let (fake, mut tun) = fake();
        {
            let mut state = fake.lock().expect("fake lock");
            state.blocked_writes = 2;
            state.poll_ready = true;
        }
        let packet = ipv4_packet(10);

        tun.send_packet(&packet).expect("send after polling");

        let state = fake.lock().expect("fake lock");
        assert_eq!(state.written, packet);
        assert_eq!(state.polls, 2, "one poll per EAGAIN");
    }

    #[test]
    fn send_packet_gives_up_when_the_descriptor_stays_unwritable() {
        let (fake, mut tun) = fake();
        {
            let mut state = fake.lock().expect("fake lock");
            state.blocked_writes = usize::MAX;
            state.poll_ready = false;
        }

        let err = tun
            .send_packet(&ipv4_packet(10))
            .expect_err("an unwritable TUN must not spin forever");
        assert!(matches!(err, NetstackError::TunError(_)), "{err}");
        assert!(
            err.to_string().contains("writable") || err.to_string().contains("timed out"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn close_runs_exactly_once_and_is_idempotent() {
        let (fake, mut tun) = fake();

        tun.close().expect("close");
        tun.close().expect("second close");

        assert_eq!(fake.lock().expect("fake lock").closes, 1);
        assert!(tun.try_recv().is_err(), "a closed TUN must not read");
        assert!(
            tun.send_packet(&ipv4_packet(0)).is_err(),
            "a closed TUN must not write"
        );
    }

    #[test]
    fn drop_closes_a_tun_that_was_not_closed_explicitly() {
        let (fake, tun) = fake();
        drop(tun);

        assert_eq!(fake.lock().expect("fake lock").closes, 1);
    }

    #[test]
    fn a_bogus_mtu_is_rejected() {
        let fake = Arc::new(Mutex::new(FakeFd::default()));
        let ops = Box::new(FakeHandle(Arc::clone(&fake)));

        assert!(AndroidTun::with_ops(ops, 0).is_err(), "mtu 0");
        assert_eq!(
            fake.lock().expect("fake lock").closes,
            1,
            "a rejected MTU must still release the fd it was given"
        );
    }
}
