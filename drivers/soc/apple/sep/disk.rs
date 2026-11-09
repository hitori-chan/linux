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
//
// Without the lab's copy, disk.c's `xart` parameter gives the extents (the file's offsets follow from their order) and
// the APFS container's UUID: the file is preallocated and written in place, so its extents hold while the container
// does, and container_is() checks the container on the disk before the file is read through them.

use kernel::error::to_result;
use kernel::firmware::Firmware;
use kernel::prelude::*;

use crate::{apfs, proto};

mod ffi {
    extern "C" {
        pub(super) fn apple_sep_disk_open(major: u32, minor: u32, write: bool) -> i32;
        pub(super) fn apple_sep_disk_read(off: u64, buf: *mut u8, len: usize) -> i32;
        pub(super) fn apple_sep_disk_write(off: u64, buf: *const u8, len: usize) -> i32;
        pub(super) fn apple_sep_disk_sync() -> i32;
        pub(super) fn apple_sep_disk_close();
        pub(super) fn apple_sep_disk_xart(major: *mut u32, minor: *mut u32, uuid: *mut u8, runs: *mut u64, max: u32) -> i32;
        pub(super) fn apple_sep_disk_find(major: *mut u32, minor: *mut u32) -> i32;
        pub(super) fn apple_sep_disk_wait(dev: *mut core::ffi::c_void) -> i32;
    }
}

const MAGIC: &[u8; 4] = b"XEXT";
const HEAD: usize = 16;
const ENTRY: usize = 24;
/// The iBoot System Container's size: no extent reaches past it.
const PART_SIZE: u64 = 524_288_000;
/// The most extents the `xart` parameter may give.
const PARAM_MAX: usize = 64;
/// The container's blocks: its superblock's nx_block_size.
const BLOCK: usize = 4096;

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
        for i in 0..n {
            let e = HEAD + i * ENTRY;
            runs.push((le64(d, e), le64(d, e + 8), le64(d, e + 16)), GFP_KERNEL).map_err(|_| "no memory")?;
        }
        Extents::checked(le32(d, 8), le32(d, 12), runs, size as u64)
    }

    /// disk.c's `xart` parameter: the extents, the file's offsets from their order, and the container's UUID; None
    /// without the parameter. The file's size is their sum.
    pub(crate) fn from_param() -> core::result::Result<Option<(Extents, [u8; 16])>, &'static str> {
        let (mut major, mut minor, mut uuid) = (0u32, 0u32, [0u8; 16]);
        let mut raw = KVec::from_elem(0u64, 2 * PARAM_MAX, GFP_KERNEL).map_err(|_| "no memory")?;
        // SAFETY: valid pointers for the call; `raw` holds PARAM_MAX pairs and `uuid` 16 bytes.
        let n = unsafe { ffi::apple_sep_disk_xart(&mut major, &mut minor, uuid.as_mut_ptr(), raw.as_mut_ptr(), PARAM_MAX as u32) };
        if n == ENOENT.to_errno() {
            return Ok(None);
        }
        if n <= 0 {
            return Err("the xart parameter does not parse, or its device node does not resolve");
        }
        let mut runs = KVec::with_capacity(n as usize, GFP_KERNEL).map_err(|_| "no memory")?;
        let mut fo = 0u64;
        for i in 0..n as usize {
            let (po, len) = (raw[2 * i], raw[2 * i + 1]);
            if len % BLOCK as u64 != 0 {
                return Err("an extent of the xart parameter is not whole blocks");
            }
            runs.push((fo, len, po), GFP_KERNEL).map_err(|_| "no memory")?;
            fo = fo.checked_add(len).ok_or("the xart parameter's extents overflow")?;
        }
        Ok(Some((Extents::checked(major, minor, runs, fo)?, uuid)))
    }

    /// The extents apfs.rs found on the partition (major, minor), checked as the others.
    fn found(major: u32, minor: u32, runs: &[(u64, u64, u64)], size: u64) -> core::result::Result<Extents, &'static str> {
        let mut v = KVec::with_capacity(runs.len(), GFP_KERNEL).map_err(|_| "no memory")?;
        v.extend_from_slice(runs, GFP_KERNEL).map_err(|_| "no memory")?;
        Extents::checked(major, minor, v, size)
    }

    /// The runs in file order from 0, no gap, no overlap, each inside the partition, together exactly `size` bytes.
    fn checked(major: u32, minor: u32, runs: KVec<(u64, u64, u64)>, size: u64) -> core::result::Result<Extents, &'static str> {
        let mut next = 0u64;
        for &(fo, len, po) in runs.iter() {
            if fo != next || len == 0 || po % 0x1000 != 0 || po.checked_add(len).is_none_or(|end| end > PART_SIZE) {
                return Err("an extent out of order, empty, unaligned or past the partition");
            }
            next = fo + len;
        }
        if runs.is_empty() || next != size {
            return Err("the extents do not cover exactly the .gl");
        }
        for (i, a) in runs.iter().enumerate() {
            if runs[..i].iter().any(|b| a.2 < b.2 + b.1 && b.2 < a.2 + a.1) {
                return Err("two extents overlap on the partition");
            }
        }
        Ok(Extents { major, minor, runs })
    }

    /// The file's size: the extents' sum.
    pub(crate) fn size(&self) -> usize {
        self.runs.last().map_or(0, |r| (r.0 + r.1) as usize)
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

/// The partition opened, read-only or read and write (disk.c checks it is the 500 MB "iBootSystemContainer").
pub(crate) fn open(e: &Extents, write: bool) -> Result {
    // SAFETY: plain arguments; the helper takes its lock.
    to_result(unsafe { ffi::apple_sep_disk_open(e.major, e.minor, write) })
}

/// The iBoot System Container on the internal NVMe disk, found by disk.c among the block devices: its device number;
/// ENOENT while no disk has it, EEXIST with more than one, EOPNOTSUPP in a modular build.
pub(crate) fn find() -> Result<(u32, u32)> {
    let (mut major, mut minor) = (0u32, 0u32);
    // SAFETY: valid pointers for the call.
    to_result(unsafe { ffi::apple_sep_disk_find(&mut major, &mut minor) })?;
    Ok((major, minor))
}

/// For the probe: EPROBE_DEFER while no disk holds the iBoot System Container, `dev` then attached again when it comes
/// (the NVMe's driver is a module, this one built in); Ok when it is found, or cannot be (the probe reports that).
pub(crate) fn wait(dev: &kernel::device::Device<kernel::device::Core<'_>>) -> Result {
    // SAFETY: the device is valid for the call; disk.c takes its own reference while it waits.
    to_result(unsafe { ffi::apple_sep_disk_wait(dev.as_raw().cast()) })
}

/// The open partition, for apfs.rs.
struct Open;

impl apfs::Disk for Open {
    fn read(&mut self, off: u64, buf: &mut [u8]) -> core::result::Result<(), &'static str> {
        if off.checked_add(buf.len() as u64).is_none_or(|end| end > PART_SIZE) {
            return Err("a read past the partition");
        }
        // SAFETY: `buf` is valid for its length.
        to_result(unsafe { ffi::apple_sep_disk_read(off, buf.as_mut_ptr(), buf.len()) }).map_err(|_| "a read of the partition failed")
    }
}

/// What the driver takes from the iBoot System Container (apfs.rs): the `.gl`'s extents and the sensor's calibration.
pub(crate) struct Found {
    pub(crate) gl: Extents,
    /// Err: why the calibration was not read (stage 12 then takes the loader's).
    pub(crate) calibration: core::result::Result<KVVec<u8>, &'static str>,
}

/// The `.gl` and the calibration found on the partition (major, minor), opened read-only for the walk and left open
/// for the caller's read of the `.gl` (close() after). Err: the partition did not open, or no `.gl` was found in it.
pub(crate) fn scan(major: u32, minor: u32) -> core::result::Result<Found, &'static str> {
    // SAFETY: plain arguments; the helper takes its lock.
    to_result(unsafe { ffi::apple_sep_disk_open(major, minor, false) }).map_err(|_| "the partition did not open")?;
    let r = (|| {
        let mut scratch = KVVec::from_elem(0u8, apfs::SCRATCH, GFP_KERNEL).map_err(|_| "no memory")?;
        let mut runs = KVVec::from_elem((0u64, 0u64, 0u64), PARAM_MAX, GFP_KERNEL).map_err(|_| "no memory")?;
        let (size, n) = apfs::find_gl(&mut Open, &mut scratch, &mut runs)?;
        let gl = Extents::found(major, minor, &runs[..n], size)?;
        let calibration = (|| {
            let mut cal = KVVec::from_elem(0u8, proto::CALIBRATION_MAX, GFP_KERNEL).map_err(|_| "no memory")?;
            let len = apfs::read_calibration(&mut Open, &mut scratch, &mut cal)?;
            cal.truncate(len);
            Ok(cal)
        })();
        Ok(Found { gl, calibration })
    })();
    if r.is_err() {
        close();
    }
    r
}

pub(crate) fn close() {
    // SAFETY: no arguments; the helper takes its lock.
    unsafe { ffi::apple_sep_disk_close() }
}

/// APFS's Fletcher-64 over a block from byte 8 (apfs.py's fletcher64).
fn fletcher64(b: &[u8]) -> u64 {
    const M: u64 = 0xffff_ffff;
    let (mut s1, mut s2) = (0u64, 0u64);
    for w in b[8..].chunks_exact(4) {
        s1 = (s1 + u64::from(le32(w, 0))) % M;
        s2 = (s2 + s1) % M;
    }
    let lo = M - (s1 + s2) % M;
    let hi = M - (s1 + lo) % M;
    hi << 32 | lo
}

/// The open partition's block 0 is an APFS container superblock (its checksum good, "NXSB", 4096-byte blocks) whose
/// nx_uuid (0x48) is `uuid`. A container made again (an erase, a restore) has another UUID and its blocks may hold
/// anything, so extents found in the old one are refused.
pub(crate) fn container_is(uuid: &[u8; 16]) -> core::result::Result<(), &'static str> {
    let mut b = KVVec::from_elem(0u8, BLOCK, GFP_KERNEL).map_err(|_| "no memory")?;
    // SAFETY: `b` is valid for BLOCK bytes.
    to_result(unsafe { ffi::apple_sep_disk_read(0, b.as_mut_ptr(), BLOCK) }).map_err(|_| "a read of the partition failed")?;
    if le64(&b, 0) != fletcher64(&b) {
        return Err("the partition's block 0 fails its checksum");
    }
    if &b[0x20..0x24] != b"NXSB" || le32(&b, 0x24) as usize != BLOCK {
        return Err("the partition's block 0 is not an APFS container superblock with 4096-byte blocks");
    }
    if b[0x48..0x58] != uuid[..] {
        return Err("the container's UUID is not the xart parameter's: the extents are from another container");
    }
    Ok(())
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
