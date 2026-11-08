// SPDX-License-Identifier: GPL-2.0-only

//! Stage 9: the Touch ID sensor (Mesa, type 3, ID 0x3352, `AppleSandDollar`) through sensor.c's shim, which
//! holds the SPI device and the power switch and refuses any frame whose type, declared length and transfer length
//! are not one of the bring-up's (work/scratch/agents/sep-step9.md, sep-step9-relay.md).
//!
//! A command frame is `80 TYPE 00 LEN_LO LEN_HI 00 00` and its payload. An encrypted one (type 0x55) carries the
//! SEP's blob at 7 and a CRC-16/ANSI (poly 0xA001 reflected, init 0) over the bytes before it. The status is one
//! 23-byte full-duplex transfer, its 16 bytes from offset 7. The sensor signals an event by its level interrupt
//! (pinctrl_ap 34); here the status is polled instead, and a status counts as an event when [11] & 0x88 is set,
//! with macOS's checks (BS272 `_handleInterrupt` 0xfffffe000920443c): [11] bit 0 an SPI error, [11] & 0x70 the
//! event code (0x10 a reset, 0x40 a watchdog reset, 0x20 and 0x30 a recovery).
//! READ(n): an event in state 7 with n bytes ready at [12..15], then the 11-byte read command and n bytes in
//! (BS272 `readSensorData` 0xfffffe0009201ac0), then the status again.

use kernel::prelude::*;
use kernel::time::delay::fsleep;
use kernel::time::Delta;

mod ffi {
    extern "C" {
        pub(super) fn apple_mesa_lab_present() -> i32;
        pub(super) fn apple_mesa_lab_power(on: i32) -> i32;
        pub(super) fn apple_mesa_lab_xfer(tx: *const u8, tx_len: usize, rx: *mut u8, len: usize) -> i32;
        pub(super) fn apple_mesa_lab_read(rx: *mut u8, len: usize) -> i32;
        pub(super) fn apple_mesa_lab_patch(buf: *const u8, len: usize) -> i32;
        pub(super) fn apple_mesa_lab_capture_arm(on: i32) -> i32;
        pub(super) fn apple_mesa_lab_read_image(rx: *mut u8, len: usize) -> i32;
    }
}

pub(crate) const SENSOR_ID: u16 = 0x3352;
pub(crate) const STATE_IDLE: u8 = 0;
pub(crate) const STATE_DATA_READY: u8 = 7;
/// status[8] after a command: done (0x29, or 0).
pub(crate) const RESULT_DONE: u8 = 0x29;
/// `_provisionStatus` = [10] | ([8] & 0x3F): provisioned.
pub(crate) const PROVISIONED: u8 = 0x20;
/// The sensor's error reply's length.
pub(crate) const ERROR_REPLY: u32 = 0x0b;

pub(crate) const T_STATUS: u8 = 0x10;
pub(crate) const T_SETUP_PATCH: u8 = 0x60;
pub(crate) const T_SERIAL: u8 = 0x70;
pub(crate) const T_SHARE: u8 = 0x72;
pub(crate) const T_SEQUENCE: u8 = 0x73;
pub(crate) const T_ENCRYPTED: u8 = 0x55;
/// Stage 11: StartCapture and Idle (BS272 `_handleCMD` cases 6 and 1), 7-byte transfers.
pub(crate) const T_START_CAPTURE: u8 = 0x40;
pub(crate) const T_IDLE: u8 = 0x30;
/// The status's state byte: armed for a capture, data ready, needs the patch (not verified here; macOS
/// sets its capture state 3 when the state reads 0x10 after StartCapture, `_handleCMD` case 6).
pub(crate) const STATE_NEEDS_PATCH: u8 = 9;
pub(crate) const STATE_FINGER_ON: u8 = 0x10;
pub(crate) const STATE_ARMED: u8 = 17;
pub(crate) const STATE_READING: u8 = 19;

/// The state byte's name, for the log.
pub(crate) fn state_name(state: u8) -> &'static str {
    match state {
        STATE_IDLE => "idle",
        STATE_DATA_READY => "data ready",
        STATE_NEEDS_PATCH => "needs the patch",
        STATE_FINGER_ON => "finger on (macOS's capture state 3)",
        STATE_ARMED => "armed",
        STATE_READING => "reading",
        _ => "?",
    }
}
/// The image (BS272 `AppleSandDollar::start` 0xfffffe000920e17c, ID 0x3352): 12 slices, 0x7200 or 0x4800 bytes;
/// `handleStateMachine` reads the larger when that much is ready, else the smaller.
pub(crate) const IMAGE_LEN: usize = 0x7200;
pub(crate) const IMAGE_LEN_SHORT: usize = 0x4800;
pub(crate) const IMAGE_SLICES: usize = 12;

/// The bring-up's frames: the serial number's reply, the key exchange's (40 at 9), the sequence counter's (64 at 9),
/// the module serial number's (0x40 or 0x44 at 9, a CRC last).
pub(crate) const SERIAL_REPLY: u32 = 0x1b;
pub(crate) const SHARE_REPLY: u32 = 0x33;
pub(crate) const SEQUENCE_REPLY: u32 = 0x4b;
/// An encrypted frame's transfer when it is not the set-parameter frame's 0x40.
pub(crate) const ENC_XFER: usize = 0x12b;

const HEADER: usize = 7;
const STATUS_XFER: usize = 23;
/// macOS's limit per sensor step (armTimerWithTimeout(…, 0x1F4)).
pub(crate) const STEP_MS: u32 = 500;

fn check(r: i32) -> Result {
    if r < 0 {
        Err(Error::from_errno(r))
    } else {
        Ok(())
    }
}

/// The 16 status bytes.
#[derive(Clone, Copy)]
pub(crate) struct Status(pub(crate) [u8; 16]);

impl Status {
    /// badSensorStatus's checks: [0] 0x80, [1] 0x20 (masked 0x3F once AppleSandDollar starts), [3] 0x10.
    pub(crate) fn sane(&self) -> bool {
        let s = &self.0;
        s[0] == 0x80 && s[1] & 0x3f == 0x20 && s[3] == 0x10
    }
    pub(crate) fn state(&self) -> u8 {
        self.0[7]
    }
    pub(crate) fn result(&self) -> u8 {
        self.0[8]
    }
    /// An interrupt pending: [11] & 0x88.
    pub(crate) fn event(&self) -> bool {
        self.0[11] & 0x88 != 0
    }
    /// [11] & 0x70: 0x10 a reset, 0x40 a watchdog reset, 0x20 and 0x30 a recovery.
    pub(crate) fn code(&self) -> u8 {
        self.0[11] & 0x70
    }
    pub(crate) fn spi_error(&self) -> bool {
        self.0[11] & 1 != 0
    }
    /// In state 0, the sensor's ID.
    pub(crate) fn id(&self) -> u16 {
        u16::from_le_bytes([self.0[12], self.0[13]])
    }
    /// In state 7, the bytes ready.
    pub(crate) fn count(&self) -> u32 {
        u32::from_le_bytes([self.0[12], self.0[13], self.0[14], self.0[15]])
    }
    /// resetSensor's `_provisionStatus`: [10] | ([8] & 0x3F).
    pub(crate) fn provision(&self) -> u8 {
        self.0[10] | (self.0[8] & 0x3f)
    }
    /// After the patch: its version, [15] | ([9] & 2) << 7.
    pub(crate) fn patch_version(&self) -> u16 {
        u16::from(self.0[15]) | (u16::from(self.0[9] & 2) << 7)
    }
}

pub(crate) fn present() -> bool {
    // SAFETY: no arguments; the shim takes its lock.
    unsafe { ffi::apple_mesa_lab_present() == 1 }
}

/// The power switch, with the shim's 7 ms (on) or 10 ms (off) after.
pub(crate) fn power(on: bool) -> Result {
    // SAFETY: an integer argument; the shim takes its lock.
    check(unsafe { ffi::apple_mesa_lab_power(on as i32) })
}

/// One full-duplex transfer: `tx`, then 0xFF to `rx.len()` bytes.
fn xfer(tx: &[u8], rx: &mut [u8]) -> Result {
    // SAFETY: `tx` is valid for `tx.len()` bytes and `rx` for `rx.len()`; the shim copies both under its lock and
    // checks the frame's shape.
    check(unsafe { ffi::apple_mesa_lab_xfer(tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len()) })
}

fn header(ty: u8, len: usize) -> [u8; HEADER] {
    [0x80, ty, 0, len as u8, (len >> 8) as u8, 0, 0]
}

pub(crate) fn status() -> Result<Status> {
    let mut rx = [0u8; STATUS_XFER];
    xfer(&header(T_STATUS, HEADER), &mut rx)?;
    let mut s = [0u8; 16];
    s.copy_from_slice(&rx[HEADER..]);
    Ok(Status(s))
}

/// A frame of `ty` and its payload, its length field its whole length, in a transfer of `xfer_len` (at least the
/// frame's); what comes back is dropped.
fn send_framed(ty: u8, payload: &[u8], xfer_len: usize) -> Result {
    let len = HEADER + payload.len();
    let mut f = KVec::with_capacity(len, GFP_KERNEL)?;
    f.extend_from_slice(&header(ty, len), GFP_KERNEL)?;
    f.extend_from_slice(payload, GFP_KERNEL)?;
    let mut rx = KVec::from_elem(0u8, xfer_len.max(len), GFP_KERNEL)?;
    xfer(&f, &mut rx)
}

/// A bare command, `80 TYPE 00 07 00 00 00`.
pub(crate) fn command(ty: u8) -> Result {
    send_framed(ty, &[], HEADER)
}

/// The key exchange's share (0x72, 0x2F bytes, no CRC) or the sequence counter's challenge (0x73, 0x47 bytes).
pub(crate) fn send_plain(ty: u8, payload: &[u8]) -> Result {
    send_framed(ty, payload, HEADER + payload.len())
}

/// CRC-16/ANSI as BS272 FillEncryptedCommandBuffer computes it: poly 0xA001 (reflected 0x8005), init 0.
pub(crate) fn crc16(d: &[u8]) -> u16 {
    let mut c = 0u16;
    for &b in d {
        c ^= u16::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xa001 } else { c >> 1 };
        }
    }
    c
}

/// An encrypted frame (0x55): `len` bytes zeroed, the header, the blob at 7, `fill` bytes stored before the blob
/// (the set-parameter frame's 0x50 at 0x27), the CRC-16 over `len - 2` bytes at `len - 2`, sent in a transfer of
/// `xfer_len`. EINVAL if the blob does not fit before the CRC.
pub(crate) fn send_encrypted(blob: &[u8], len: usize, xfer_len: usize, fill: &[(usize, u8)]) -> Result {
    if blob.len() > len - HEADER - 2 || xfer_len < len {
        return Err(EINVAL);
    }
    let mut f = KVec::from_elem(0u8, len, GFP_KERNEL)?;
    f[..HEADER].copy_from_slice(&header(T_ENCRYPTED, len));
    for &(at, v) in fill {
        f[at] = v;
    }
    f[HEADER..HEADER + blob.len()].copy_from_slice(blob);
    let c = crc16(&f[..len - 2]);
    f[len - 2..].copy_from_slice(&c.to_le_bytes());
    let mut rx = KVec::from_elem(0u8, xfer_len, GFP_KERNEL)?;
    xfer(&f, &mut rx)
}

/// How a wait for an event ended.
pub(crate) enum Event {
    /// An event, its status checked: no SPI error, and a reset only where `reset_ok`.
    Seen(Status),
    /// An event macOS treats as a fault (an SPI error, an unexpected reset, a recovery code).
    Fault(Status, &'static str),
    /// None within the step's time; the last status.
    Timeout(Status),
}

/// Polls the status every `every_ms`, after `first_ms`, until an event or `ms`; checks it as `_handleInterrupt`
/// does. `reset_ok`: the power cycle's wait, where a reset (0x10, 0x20 or 0x40) is the event wanted.
pub(crate) fn wait_event(first_ms: u32, every_ms: u32, ms: u32, reset_ok: bool) -> Result<Event> {
    if first_ms > 0 {
        fsleep(Delta::from_millis(i64::from(first_ms)));
    }
    let mut waited = first_ms;
    loop {
        let s = status()?;
        if s.event() {
            if s.spi_error() {
                return Ok(Event::Fault(s, "an SPI error ([11] bit 0)"));
            }
            return Ok(match (s.code(), reset_ok) {
                (0x10 | 0x20 | 0x40, true) => Event::Seen(s),
                (_, true) => Event::Fault(s, "the reset's event is not a reset (0x10, 0x20 or 0x40)"),
                (0x10 | 0x40, false) => Event::Fault(s, "an unexpected reset ([11] & 0x70 0x10 or 0x40)"),
                (0x20 | 0x30, false) => Event::Fault(s, "a recovery event ([11] & 0x70 0x20 or 0x30)"),
                _ => Event::Seen(s),
            });
        }
        if waited >= ms {
            return Ok(Event::Timeout(s));
        }
        fsleep(Delta::from_millis(i64::from(every_ms)));
        waited += every_ms;
    }
}

/// READ(n)'s transfer, once an event showed state 7 with `n` ready.
pub(crate) fn read(n: usize) -> Result<KVec<u8>> {
    let mut v = KVec::from_elem(0u8, n, GFP_KERNEL)?;
    // SAFETY: `v` is valid for `n` bytes; the shim checks `n` against its buffer.
    check(unsafe { ffi::apple_mesa_lab_read(v.as_mut_ptr(), n) })?;
    Ok(v)
}

/// The sensor's patch, raw, after a 0x60 frame and its event in state 0; the shim refuses it otherwise.
pub(crate) fn patch(p: &[u8]) -> Result {
    // SAFETY: `p` is valid for `p.len()` bytes; the shim copies it.
    check(unsafe { ffi::apple_mesa_lab_patch(p.as_ptr(), p.len()) })
}

/// Stage 11: the capture's frames and the image read armed (true) or disarmed in the shim.
pub(crate) fn capture_arm(on: bool) -> Result {
    // SAFETY: an integer argument; the shim takes its lock.
    check(unsafe { ffi::apple_mesa_lab_capture_arm(on as i32) })
}

/// Stage 11: the image's read, `n` 0x7200 or 0x4800, once an event showed state 7 with that much ready.
pub(crate) fn read_image(n: usize) -> Result<KVec<u8>> {
    let mut v = KVec::from_elem(0u8, n, GFP_KERNEL)?;
    // SAFETY: `v` is valid for `n` bytes; the shim checks `n` and copies under its lock.
    check(unsafe { ffi::apple_mesa_lab_read_image(v.as_mut_ptr(), n) })?;
    Ok(v)
}

/// What the image's checks found: macOS's per slice (BS272 `AppleSandDollar::_checkImageCRC` 0xfffffe000920e2b0:
/// each of the 12 slices' u32 at 3 is its length, and its last two bytes the CRC-16/ANSI of the rest) and
/// one over the whole read (its last two bytes the CRC-16 of the rest), the rule M1 and M2 sensors were seen to use.
pub(crate) struct ImageCheck {
    /// The slices whose length field is the slice's length, and of those, whose CRC holds.
    pub(crate) lengths_ok: usize,
    pub(crate) crcs_ok: usize,
    /// The first slice that failed, if any, and why.
    pub(crate) first_bad: Option<(usize, &'static str)>,
    /// One CRC over the whole read.
    pub(crate) whole_crc_ok: bool,
}

pub(crate) fn check_image(img: &[u8]) -> ImageCheck {
    let n = img.len() / IMAGE_SLICES;
    let mut c = ImageCheck { lengths_ok: 0, crcs_ok: 0, first_bad: None, whole_crc_ok: false };
    for i in 0..IMAGE_SLICES {
        let sl = &img[i * n..(i + 1) * n];
        let len = u32::from_le_bytes([sl[3], sl[4], sl[5], sl[6]]) as usize;
        if len != n {
            c.first_bad.get_or_insert((i, "its length field is not the slice's length"));
            continue;
        }
        c.lengths_ok += 1;
        if crc16(&sl[..n - 2]) == u16::from_le_bytes([sl[n - 2], sl[n - 1]]) {
            c.crcs_ok += 1;
        } else {
            c.first_bad.get_or_insert((i, "its CRC-16 fails"));
        }
    }
    let m = img.len();
    c.whole_crc_ok = m >= 2 && crc16(&img[..m - 2]) == u16::from_le_bytes([img[m - 2], img[m - 1]]);
    c
}
