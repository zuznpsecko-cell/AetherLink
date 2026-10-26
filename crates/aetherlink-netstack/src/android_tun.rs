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
