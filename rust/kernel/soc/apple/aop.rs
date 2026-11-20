// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Common code for AOP endpoint drivers

use kernel::{prelude::*, sync::Arc, time::Delta};

/// Representation of an "EPIC" service.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EPICService {
    /// Channel id
    pub channel: u32,
    /// RTKit endpoint
    pub endpoint: u8,
}

/// Listener for the "HID" events sent by aop
pub trait FakehidListener {
    /// Process the event.
    fn process_fakehid_report(&self, data: &[u8]) -> Result<()>;
}

/// AOP communications manager.
pub trait AOP: Send + Sync {
    /// Calls a method on a specified service
    fn epic_call(&self, svc: &EPICService, subtype: u16, msg_bytes: &[u8]) -> Result<u32>;
    /// Just like epic_call, but also returns a value
    fn epic_call_ret(
        &self,
        svc: &EPICService,
        subtype: u16,
        msg_bytes: &[u8],
        ret_len: usize,
    ) -> Result<(u32, KVec<u8>)>;

    /// Adds the listener for the specified service
    fn add_fakehid_listener(
        &self,
        svc: EPICService,
        listener: Arc<dyn FakehidListener>,
    ) -> Result<()>;
    /// Remove the listener for the specified service
    fn remove_fakehid_listener(&self, svc: &EPICService) -> bool;
    /// Just like epic_call, but gives up with `ETIMEDOUT` after `timeout`: for the system sleep
    /// paths, which must not wait for ever on a co-processor that does not answer
    fn epic_call_timeout(
        &self,
        svc: &EPICService,
        subtype: u16,
        msg_bytes: &[u8],
        timeout: Delta,
    ) -> Result<u32>;
    /// Internal method to detach the device.
    fn remove(&self);
    /// Internal method: stops the endpoints' queues for a system sleep, after the services' own
    /// devices, its children, have suspended
    fn suspend(&self);
    /// Internal method: restarts the queues `suspend` stopped, before the children resume
    fn resume(&self);
}

/// Converts a text representation of a FourCC to u32
pub const fn from_fourcc(b: &[u8]) -> u32 {
    b[3] as u32 | (b[2] as u32) << 8 | (b[1] as u32) << 16 | (b[0] as u32) << 24
}
