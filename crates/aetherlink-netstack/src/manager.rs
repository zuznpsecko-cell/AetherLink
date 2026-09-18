//! Netstack manager: TUN + stack lifecycle with a safe state machine.
//!
//! `down` is a no-op when already down; `bring_up` without privileges fails
//! cleanly and leaves the state down. Real device bring-up lands in the
//! platform task.

use crate::tun::TunInterface;
use crate::{NetstackError, Result};

/// Lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Tunnel down (initial + after teardown).
    Down,
    /// Tunnel up.
    Up,
}

/// Lifecycle manager.
#[derive(Debug)]
pub struct NetstackManager {
    state: State,
    /// MTU.
    pub mtu: usize,
}

impl NetstackManager {
    /// Fresh manager in the down state.
    #[must_use]
    pub fn bring_down_state() -> Self {
        Self {
            state: State::Down,
            mtu: crate::DEFAULT_MTU,
        }
    }

    /// Bring up: probe privilege first, then build the device.
    ///
    /// Device bring-up itself lands in the platform task; until then this
    /// fails cleanly (state stays down) instead of half-applying anything.
    pub fn bring_up(&mut self, mtu: usize) -> Result<()> {
        Self::probe_privilege("aether0")?;
        self.mtu = mtu;
        Err(NetstackError::InterfaceNotConfigured)
    }

    /// True while the tunnel is up.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.state == State::Up
    }

    /// Tear down; safe no-op when already down (idempotent).
    pub fn down(&mut self) -> Result<()> {
        self.state = State::Down;
        Ok(())
    }

    /// Privilege probe: can this process open a TUN device?
    fn probe_privilege(name: &str) -> Result<()> {
        match TunInterface::open(name) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
