// SPDX-License-Identifier: GPL-2.0-only
//
// Touch ID steps 3-5: the xART store, a copy of the `.gl` file in memory. The lab copies the file from the iBoot
// System Container's xART volume with a read-only open of the partition (tools/re/apfs.py) and the firmware loader
// hands it to probe; the driver copies it into memory and writes only there: it has no disk, APFS or block-device
// code. Records are found, read, written and deleted as macOS 14.8.3's gigalocker does (rda AppleSEPManager;
// 27.0.1's is the same, work/scratch/agents/sep-step5.md):
// - gl_rec_find 0xfffffe0009d12c40: the file is 0x9000-byte slots, as many as fit; a slot's first 0x22 bytes are
//   its header, and the first slot whose bytes 1-0x11 equal the 17-byte key (a type, 1-4, then a 16-byte UUID,
//   zero for the root records) holds the record; byte 0 is not compared;
// - gl_rec_read 0xfffffe0009d12fe8: no slot is status 0 with nothing found; the data's u32 length at 0x12 (0, or
//   more than the caller's buffer, is status 0x16), its CRC-32 at 0x16 (XNU's crc32, zlib's; macOS panics on a
//   mismatch), the data at 0x22;
// - gl_rec_write 0xfffffe0009d13504: 1-0x8000 bytes, and a root key's UUID zero (else status 0x16); the key's old
//   slot (gl_rec_find) and a free one, whose byte 1 is zero (gl_rec_find_free 0xfffffe0009d12e3c): a new key
//   skips the first free slot, which a replacement takes, so one is always left for a replacement; none is
//   status 5. The new slot is written whole from 0x9000 zeroed bytes: the key at 1, the length at 0x12, the
//   CRC-32 at 0x16, the revision at 0x1a (one more than the highest so far, which gl_fixup_rev_init
//   0xfffffe0009d123ec takes from the records at open), the data at 0x22. Then the old slot is deleted;
// - gl_rec_delete 0xfffffe0009d131dc: the slot's first 0x1000 bytes zeroed (the rest stays).
// macOS writes each through the file's raw device with IO_SYNC and then flushes the disk's cache
// (_block_dev_read_write 0xfffffe0009d13b20: VNOP_WRITE, then DKIOCSYNCHRONIZE): the new slot before the old one's
// delete, which gl_fixup_rev_init resolves after a crash between them by the higher revision.

use kernel::firmware::Firmware;
use kernel::prelude::*;

pub(crate) const SLOT: usize = 0x9000;
const HDR: usize = 0x22;
const KEY: usize = 17;
const LEN: usize = 0x12;
const CRC: usize = 0x16;
const REV: usize = 0x1a;
/// gl_rec_delete zeroes this much of a slot.
const DELETE: usize = 0x1000;
/// gl_rec_write's and gl_fixup_rev_init's largest record.
pub(crate) const DATA_MAX: usize = 0x8000;

/// gl_rec_write's statuses, which _handle_sep_driven_msg puts in the reply.
pub(crate) const EIO: u8 = 5;
pub(crate) const EINVAL: u8 = 0x16;

/// The key's type byte: _handle_sep_driven_msg 0xfffffe0009d203d0 takes the SEP's when the request's byte 5 has
/// bit 0 set, the user's otherwise.
pub(crate) const TYPE_ROOT_USER: u8 = 1;
pub(crate) const TYPE_ROOT_SEP: u8 = 2;
/// A session record's (a locker's) key type, by the same bit: cases 5-7 of _handle_sep_driven_msg.
pub(crate) const TYPE_SESSION_USER: u8 = 3;
pub(crate) const TYPE_SESSION_SEP: u8 = 4;
/// The longest record a session read may return: case 5 passes gl_rec_read 0x7ff0 and puts the record at 0.
pub(crate) const SESSION_MAX: usize = 0x7ff0;

/// The longest record a root read may return: op 0 puts a 17-byte prefix before it in the 0x8000-byte buffer, so
/// its gl_rec_read is passed 0x7fef. A root write (op 1) is held to the same (macOS panics from 0x7ff0).
pub(crate) const ROOT_MAX: usize = 0x7fef;
/// The prefix: byte 0 and the zero UUID.
pub(crate) const ROOT_PREFIX: usize = 0x11;

pub(crate) type Key = [u8; KEY];

/// A session record's key: the type, then the UUID the SEP names.
pub(crate) fn session_key(ty: u8, uuid: &[u8; 16]) -> Key {
    let mut k = [0u8; KEY];
    k[0] = ty;
    k[1..].copy_from_slice(uuid);
    k
}

pub(crate) const fn root_key(ty: u8) -> Key {
    let mut k = [0u8; KEY];
    k[0] = ty;
    k
}

pub(crate) struct Record<'a> {
    pub(crate) slot: usize,
    pub(crate) data: &'a [u8],
}

pub(crate) enum Lookup<'a> {
    Found(Record<'a>),
    /// No slot holds the key: macOS answers status 0 with nothing found.
    Absent,
    /// The slot gl_rec_find picks fails gl_rec_read's checks.
    Bad { slot: usize, why: &'static str },
}

/// What gl_rec_write did.
#[allow(dead_code)] // the disk write path (Touch ID step 7b) builds its slots with Store::write
pub(crate) enum Write {
    Done {
        slot: usize,
        old: Option<usize>,
        rev: u64,
        crc32: u32,
    },
    /// gl_rec_write's refusal: the status macOS replies with, nothing changed.
    Refused { status: u8, why: &'static str },
}

pub(crate) struct Store {
    gl: VVec<u8>,
    /// The highest revision: gl_ctx +0x420.
    rev: u64,
}

fn le32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

impl Store {
    /// Copies the loader's `.gl` into memory. Every used slot must pass what gl_fixup_rev_init checks at open
    /// (a type of 1-4, 1-0x8000 bytes, its CRC-32, one slot per key; a free slot's UUID zero): it wipes or
    /// resolves the rest on the disk, which this copy cannot follow, so anything it would change refuses the copy.
    pub(crate) fn new(fw: &Firmware) -> core::result::Result<Store, &'static str> {
        let d = fw.data();
        let n = d.len();
        if n < SLOT {
            return Err("smaller than one 0x9000-byte slot");
        }
        if n % 0x1000 != 0 {
            return Err("not a multiple of 0x1000 bytes, which gl_open refuses");
        }
        let mut gl = VVec::with_capacity(n, GFP_KERNEL).map_err(|_| "too large to copy into memory")?;
        gl.extend_from_slice(d, GFP_KERNEL).map_err(|_| "too large to copy into memory")?;
        let mut s = Store { gl, rev: 0 };
        for slot in 0..s.slots() {
            let h = s.hdr(slot);
            if h[1] == 0 {
                if h[2..1 + KEY].iter().any(|&b| b != 0) {
                    return Err("a free slot with a UUID, which gl_fixup_rev_init wipes");
                }
                continue;
            }
            if h[1] > TYPE_SESSION_SEP {
                return Err("a slot of a type above 4, which gl_fixup_rev_init wipes");
            }
            let len = le32(h, LEN) as usize;
            if len == 0 || len > DATA_MAX {
                return Err("a record of 0 or more than 0x8000 bytes, which gl_fixup_rev_init wipes");
            }
            let start = slot * SLOT + HDR;
            if crc32(&s.gl[start..start + len]) != le32(h, CRC) {
                return Err("a record whose CRC-32 fails, which gl_fixup_rev_init wipes");
            }
            if (0..slot).any(|o| s.hdr(o)[1..1 + KEY] == h[1..1 + KEY]) {
                return Err("two slots with one key, which gl_fixup_rev_init resolves");
            }
            let mut r = [0u8; 8];
            r.copy_from_slice(&h[REV..REV + 8]);
            s.rev = s.rev.max(u64::from_le_bytes(r));
        }
        Ok(s)
    }

    fn hdr(&self, slot: usize) -> &[u8] {
        &self.gl[slot * SLOT..slot * SLOT + HDR]
    }

    pub(crate) fn size(&self) -> usize {
        self.gl.len()
    }

    pub(crate) fn slots(&self) -> usize {
        self.gl.len() / SLOT
    }

    pub(crate) fn rev(&self) -> u64 {
        self.rev
    }

    /// Slots whose key has a type, for the log.
    pub(crate) fn used(&self) -> usize {
        (0..self.slots()).filter(|&i| self.gl[i * SLOT + 1] != 0).count()
    }

    /// gl_rec_find: the first slot whose key is `k`, its header unchecked.
    pub(crate) fn slot_of(&self, k: &Key) -> Option<usize> {
        (0..self.slots()).find(|&slot| self.hdr(slot)[1..1 + KEY] == k[..])
    }

    /// gl_rec_find_free: the free slot after `skip` others.
    #[allow(dead_code)] // Store::write's
    fn free_slot(&self, skip: usize) -> Option<usize> {
        (0..self.slots()).filter(|&slot| self.gl[slot * SLOT + 1] == 0).nth(skip)
    }

    pub(crate) fn find(&self, k: &Key, max: usize) -> Lookup<'_> {
        let Some(slot) = self.slot_of(k) else {
            return Lookup::Absent;
        };
        let h = self.hdr(slot);
        let len = le32(h, LEN) as usize;
        if len == 0 {
            return Lookup::Bad { slot, why: "length 0" };
        }
        if len > max || HDR + len > SLOT {
            return Lookup::Bad { slot, why: "longer than the reply's buffer" };
        }
        let start = slot * SLOT + HDR;
        let data = &self.gl[start..start + len];
        if crc32(data) != le32(h, CRC) {
            return Lookup::Bad { slot, why: "CRC-32 mismatch" };
        }
        Lookup::Found(Record { slot, data })
    }

    /// gl_rec_write, into memory.
    #[allow(dead_code)] // the disk write path (Touch ID step 7b) builds its slots with it
    pub(crate) fn write(&mut self, k: &Key, data: &[u8]) -> Write {
        if data.is_empty() || data.len() > DATA_MAX {
            return Write::Refused { status: EINVAL, why: "a record of 0 or more than 0x8000 bytes" };
        }
        if k[0] != TYPE_SESSION_USER && k[0] != TYPE_SESSION_SEP && k[1..].iter().any(|&b| b != 0) {
            return Write::Refused { status: EINVAL, why: "a root record's key with a UUID" };
        }
        let old = self.slot_of(k);
        let Some(slot) = self.free_slot(usize::from(old.is_none())) else {
            return Write::Refused { status: EIO, why: "no free slot" };
        };
        self.rev += 1;
        let crc = crc32(data);
        let s = &mut self.gl[slot * SLOT..(slot + 1) * SLOT];
        s.fill(0);
        s[1..1 + KEY].copy_from_slice(k);
        s[LEN..LEN + 4].copy_from_slice(&(data.len() as u32).to_le_bytes());
        s[CRC..CRC + 4].copy_from_slice(&crc.to_le_bytes());
        s[REV..REV + 8].copy_from_slice(&self.rev.to_le_bytes());
        s[HDR..HDR + data.len()].copy_from_slice(data);
        if let Some(o) = old {
            self.delete(o);
        }
        Write::Done {
            slot,
            old,
            rev: self.rev,
            crc32: crc,
        }
    }

    /// gl_rec_delete, into memory.
    #[allow(dead_code)] // Store::write's
    pub(crate) fn delete(&mut self, slot: usize) {
        self.gl[slot * SLOT..slot * SLOT + DELETE].fill(0);
    }
}

/// zlib's CRC-32, which gl_rec_read checks (XNU's crc32(0, data, len)).
pub(crate) const fn crc32(d: &[u8]) -> u32 {
    let mut c = !0u32;
    let mut i = 0;
    while i < d.len() {
        c ^= d[i] as u32;
        let mut b = 0;
        while b < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 };
            b += 1;
        }
        i += 1;
    }
    !c
}

/// CRC-16/CCITT-FALSE, which _handle_sep_driven_msg logs for each record it serves ("Fetched %s-xART with CRC";
/// crc_table 0xfffffe000751bc70: polynomial 0x1021, 0xffff first) and checks against a write's bytes 6-7.
pub(crate) const fn crc16(d: &[u8]) -> u16 {
    crc16_from(0xffff, d)
}

/// The CRC-16 continued over `d`: macOS logs a locker's over its UUID, then its data.
pub(crate) const fn crc16_from(start: u16, d: &[u8]) -> u16 {
    let mut c = start;
    let mut i = 0;
    while i < d.len() {
        c ^= (d[i] as u16) << 8;
        let mut b = 0;
        while b < 8 {
            c = if c & 0x8000 != 0 { (c << 1) ^ 0x1021 } else { c << 1 };
            b += 1;
        }
        i += 1;
    }
    c
}

// The catalogue's check values
static_assert!(crc32(b"123456789") == 0xcbf4_3926);
static_assert!(crc16(b"123456789") == 0x29b1);
