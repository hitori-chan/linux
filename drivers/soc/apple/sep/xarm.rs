// SPDX-License-Identifier: GPL-2.0-only
//
// The xART service on endpoint 0x13: the SEP's requests and the host's answers, as macOS's
// AppleSEPXART::_handle_sep_driven_msg reads and answers them (rda AppleSEPManager 0xfffffe0009d203d0; 27.0.1's
// 0xfffffe0009d89c64 and 27.2's 0xfffffe0009db4b24 answer ops 0-7, 0x0e and 0x13 the same). macOS holds every request
// until gl_initialize has opened the .gl file (the handler sleeps on its ready flag at +0xC0 before it reads the
// operation); the lab holds them until its copy is open.
//
// A request's word: byte 0 the endpoint, byte 1 a tag, byte 2 the operation, bytes 3-4 the length of what the SEP put
// in xarm's in buffer, byte 5 bit 0 the SEP's records rather than the user's, bytes 6-7 a write's CRC-16. The answer
// is the same word with byte 2 the status and bytes 3-4 the length of what the host put in its out buffer; op 0x0e's
// answer also carries protected-data-access in byte 5. Op 0x1d names an app, its 4CC in bytes 3-6.

use kernel::prelude::*;
use kernel::soc::apple::mailbox::Message;

pub(crate) const OP_ROOT_READ: u8 = 0x00;
pub(crate) const OP_ROOT_WRITE: u8 = 0x01;
pub(crate) const OP_SESSION_READ: u8 = 0x05;
pub(crate) const OP_SESSION_WRITE: u8 = 0x06;
pub(crate) const OP_SESSION_DELETE: u8 = 0x07;
pub(crate) const OP_QUERY_PROTECTED: u8 = 0x0e;
pub(crate) const OP_GET_OS_UUID: u8 = 0x13;
/// 27.2's XARTDisableLog register (0x1d, a 4CC) and its two neighbours, which 27.2's service never answers; 14.8.3
/// answered 0x1d with status 0x16.
pub(crate) const OP_NAMES_APP: u8 = 0x1d;
const OP_NAMES_LAST: u8 = 0x1f;

/// The statuses the lab answers with: done, no OS UUID (op 0x13 without one), an unknown operation.
pub(crate) const STATUS_OK: u8 = 0x00;
pub(crate) const STATUS_NO_UUID: u8 = 0x02;
pub(crate) const STATUS_UNKNOWN_OP: u8 = 0x16;

/// One request, its word kept for the answer.
#[derive(Clone, Copy)]
pub(crate) struct Req {
    raw: u64,
}

impl Req {
    pub(crate) const fn of(m: &Message) -> Req {
        Req { raw: m.msg0 }
    }

    const fn byte(&self, i: u32) -> u8 {
        (self.raw >> (8 * i)) as u8
    }

    pub(crate) const fn tag(&self) -> u8 {
        self.byte(1)
    }

    pub(crate) const fn op(&self) -> u8 {
        self.byte(2)
    }

    /// The length of what the SEP wrote into xarm's in buffer.
    pub(crate) const fn len(&self) -> u16 {
        (self.raw >> 24) as u16
    }

    /// Byte 5: bit 0 picks the SEP's records (type 2 and 4) over the user's (1 and 3).
    pub(crate) const fn owner(&self) -> u8 {
        self.byte(5)
    }

    /// A write's CRC-16 of what it sends (ops 1 and 6: bytes 6-7, `in_msg_p->b`, compared with the host's
    /// little-endian CRC; a mismatch panics macOS).
    pub(crate) const fn crc16(&self) -> u16 {
        (self.raw >> 48) as u16
    }

    /// Op 0x1d's 4CC, bytes 3-6.
    pub(crate) const fn name(&self) -> u32 {
        (self.raw >> 24) as u32
    }

    /// The raw bytes 5-7, for the log.
    pub(crate) const fn tail(&self) -> [u8; 3] {
        [self.byte(5), self.byte(6), self.byte(7)]
    }

    /// The answer: the request's word, `status` in byte 2 and `len` in bytes 3-4; with `b5`, byte 5 replaced.
    pub(crate) const fn answer(&self, status: u8, len: u16, b5: Option<u8>) -> Message {
        let mut w = (self.raw & !0x0000_00ff_ffff_0000) | ((status as u64) << 16) | ((len as u64) << 24);
        if let Some(v) = b5 {
            w = (w & !0x0000_ff00_0000_0000) | ((v as u64) << 40);
        }
        Message { msg0: w, msg1: 0 }
    }
}

const fn answered(req: u64, status: u8, len: u16, b5: Option<u8>) -> u64 {
    Req { raw: req }.answer(status, len, b5).msg0
}

// macOS 14.8.3's answers, bit for bit (sep-1.log): op 0x0e (1519 -> 1803), op 0x13 (1807 -> 1813), the SEP's root
// record (1818 -> 1822, 0x11 + 0x353 bytes), an app's name (1836 -> 1892); the writes: a user locker's delete that
// found none (2081 -> 2085), the SEP's root record (4304 -> 4308, 0x353 bytes, CRC-16 0x93b4) and a SEP locker
// (4313 -> 4335, 0x10 + 0x40 bytes, CRC-16 0x2a06), each status 0, the length 0, bytes 5-7 kept.
static_assert!(answered(0x0000_0000_000e_0213, 0, 0, Some(1)) == 0x0000_0100_0000_0213);
static_assert!(answered(0x0000_0000_0013_0113, 0, 0, None) == 0x0000_0000_0000_0113);
static_assert!(answered(0x0000_0100_0000_0313, 0, 0x364, None) == 0x0000_0103_6400_0313);
static_assert!(answered(0x0073_6269_6f1d_0013, 0x16, 0, None) == 0x0073_6200_0016_0013);
static_assert!(answered(0x0000_0000_1007_0913, 0, 0, None) == 0x0000_0000_0000_0913);
static_assert!(answered(0x93b4_0103_5301_1513, 0, 0, None) == 0x93b4_0100_0000_1513);
static_assert!(answered(0x2a06_0100_5006_1613, 0, 0, None) == 0x2a06_0100_0000_1613);

/// The requests that change the store (sep.rs's xarm_reply decides by stage what becomes of them).
pub(crate) const fn is_write(op: u8) -> bool {
    matches!(op, OP_ROOT_WRITE | OP_SESSION_WRITE | OP_SESSION_DELETE)
}

/// Ops 0x1d-0x1f: the SEP naming an app; 14.8.3 answered 0x1d with 0x16, 27.2 answers none of them.
pub(crate) const fn is_naming(op: u8) -> bool {
    op >= OP_NAMES_APP && op <= OP_NAMES_LAST
}

pub(crate) fn op_name(op: u8) -> &'static str {
    match op {
        OP_ROOT_READ => "read root record",
        OP_ROOT_WRITE => "WRITE root record",
        OP_SESSION_READ => "read session record",
        OP_SESSION_WRITE => "WRITE session record",
        OP_SESSION_DELETE => "DELETE session record",
        OP_QUERY_PROTECTED => "protected-data-access query",
        OP_GET_OS_UUID => "OS UUID request",
        o if is_naming(o) => "names an app",
        _ => "unknown",
    }
}
