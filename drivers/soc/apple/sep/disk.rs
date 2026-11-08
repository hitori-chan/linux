// SPDX-License-Identifier: GPL-2.0-only
//
// Stage 13 (Touch ID step 10d): the xART store's writes carried to the disk as macOS carries them (AppleSEPManager_272
// gl_rec_write 0xfffffe0009da8104 and gl_write: the new slot whole, then the old slot's first 0x1000 bytes cleared,
// each written through the `.gl` file's raw device with IO_SYNC and the disk's cache flushed after). The `.gl` is
// preallocated, so a slot's bytes are written in place in the file's extents and APFS's metadata is never touched.
// The extents come from the lab's script (a read-only APFS reader) through the firmware loader, as the `.gl` copy
// does: "XEXT", u32 the count, u32 the partition's major and minor, then per extent u64 the file offset, the length
// and the partition offset, in file order, covering the file from 0 with no gap. Each range is checked against the
// disk before it is written (the disk must hold what the SEP was served) and read back after.

use kernel::error::to_result;
use kernel::firmware::Firmware;
use kernel::prelude::*;

mod ffi {
    extern "C" {
        pub(super) fn apple_sep_disk_open(major: u32, minor: u32) -> i32;
        pub(super) fn apple_sep_disk_read(off: u64, buf: *mut u8, len: usize) -> i32;
        pub(super) fn apple_sep_disk_write(off: u64, buf: *const u8, len: usize) -> i32;
        pub(super) fn apple_sep_disk_sync() -> i32;
        pub(super) fn apple_sep_disk_close();
    }
}

const MAGIC: &[u8; 4] = b"XEXT";
const HEAD: usize = 16;
const ENTRY: usize = 24;
/// The iBoot System Container's size: no extent reaches past it.
const PART_SIZE: u64 = 524_288_000;

pub(crate) struct Extents {
    major: u32,
    minor: u32,
    /// (file offset, length, partition offset)
    runs: KVec<(u64, u64, u64)>,
}

fn le32(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}

fn le64(d: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[at..at + 8]);
    u64::from_le_bytes(b)
}

impl Extents {
    /// The loader's extents file, checked against the `.gl` copy's size: the runs in file order from 0, no gap,
    /// no overlap, each inside the partition, together exactly the file.
    pub(crate) fn new(fw: &Firmware, size: usize) -> core::result::Result<Extents, &'static str> {
        let d = fw.data();
        if d.len() < HEAD || &d[..4] != MAGIC {
            return Err("not an extents file");
        }
        let n = le32(d, 4) as usize;
        if n == 0 || d.len() != HEAD + n * ENTRY {
            return Err("the extents file's length does not match its count");
        }
        let mut runs = KVec::with_capacity(n, GFP_KERNEL).map_err(|_| "no memory")?;
        let mut next = 0u64;
        for i in 0..n {
            let e = HEAD + i * ENTRY;
            let (fo, len, po) = (le64(d, e), le64(d, e + 8), le64(d, e + 16));
            if fo != next || len == 0 || po % 0x1000 != 0 || po.checked_add(len).is_none_or(|end| end > PART_SIZE) {
                return Err("an extent out of order, empty, unaligned or past the partition");
            }
            runs.push((fo, len, po), GFP_KERNEL).map_err(|_| "no memory")?;
            next = fo + len;
        }
        if next != size as u64 {
            return Err("the extents do not cover exactly the .gl copy");
        }
        for (i, a) in runs.iter().enumerate() {
            if runs[..i].iter().any(|b| a.2 < b.2 + b.1 && b.2 < a.2 + a.1) {
                return Err("two extents overlap on the partition");
            }
        }
        Ok(Extents { major: le32(d, 8), minor: le32(d, 12), runs })
    }

    pub(crate) fn dev(&self) -> (u32, u32) {
        (self.major, self.minor)
    }

    pub(crate) fn count(&self) -> usize {
        self.runs.len()
    }

    /// The pieces of the file's range [off, off + len): (file offset, length, partition offset) each.
    fn pieces(&self, off: usize, len: usize) -> impl Iterator<Item = (usize, usize, u64)> + '_ {
        let (lo, hi) = (off as u64, (off + len) as u64);
        self.runs.iter().filter_map(move |&(fo, l, po)| {
            let (a, b) = (lo.max(fo), hi.min(fo + l));
            (a < b).then(|| (a as usize, (b - a) as usize, po + (a - fo)))
        })
    }
}

/// The partition opened read and write (disk.c checks it is the 500 MB "iBootSystemContainer").
pub(crate) fn open(e: &Extents) -> Result {
    // SAFETY: integer arguments; the helper takes its lock.
    to_result(unsafe { ffi::apple_sep_disk_open(e.major, e.minor) })
}

pub(crate) fn close() {
    // SAFETY: no arguments; the helper takes its lock.
    unsafe { ffi::apple_sep_disk_close() }
}

/// The file's bytes at `off`, into `buf`.
pub(crate) fn read(e: &Extents, off: usize, buf: &mut [u8]) -> core::result::Result<(), &'static str> {
    let mut got = 0;
    for (fo, len, po) in e.pieces(off, buf.len()) {
        let b = &mut buf[fo - off..fo - off + len];
        // SAFETY: `b` is valid for `len` bytes.
        to_result(unsafe { ffi::apple_sep_disk_read(po, b.as_mut_ptr(), len) }).map_err(|_| "a read of the partition failed")?;
        got += len;
    }
    if got != buf.len() {
        return Err("the range is not wholly in the extents");
    }
    Ok(())
}

/// Whether the disk holds `want` at the file's offset `off`.
pub(crate) fn holds(e: &Extents, off: usize, want: &[u8]) -> core::result::Result<bool, &'static str> {
    let mut buf = KVVec::from_elem(0u8, want.len(), GFP_KERNEL).map_err(|_| "no memory")?;
    read(e, off, &mut buf)?;
    Ok(buf[..] == want[..])
}

/// `data` written at the file's offset `off`, then the partition synced (its pages written, the disk's cache
/// flushed), then read back and compared.
pub(crate) fn write(e: &Extents, off: usize, data: &[u8]) -> core::result::Result<(), &'static str> {
    let mut put = 0;
    for (fo, len, po) in e.pieces(off, data.len()) {
        let b = &data[fo - off..fo - off + len];
        // SAFETY: `b` is valid for `len` bytes; the helper copies it.
        to_result(unsafe { ffi::apple_sep_disk_write(po, b.as_ptr(), len) }).map_err(|_| "a write to the partition failed")?;
        put += len;
    }
    if put != data.len() {
        return Err("the range is not wholly in the extents");
    }
    // SAFETY: no arguments; the helper takes its lock.
    to_result(unsafe { ffi::apple_sep_disk_sync() }).map_err(|_| "the partition's sync failed")?;
    if !holds(e, off, data)? {
        return Err("the partition does not read back what was written");
    }
    Ok(())
}
