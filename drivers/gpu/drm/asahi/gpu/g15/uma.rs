// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 UMA page pool.

use super::*;

/// G15: a UMA page pool (spec: agx-g15c/uma.md, "A pool for the fork").
/// gUPM backs a launch's dynamic on-chip storage with its pages; every job
/// registers the pool at its descriptor-table slot (the firmware keys a
/// pool by its state and slot, never by channel).
pub(crate) struct G15Uma {
    /// The descriptor-table slot (0..255); the pool ID is slot + 1.
    pub(crate) slot: u32,
    /// The pool memory: `G15_UMA_BLOCKS` blocks of 8192 pages of 4 KiB, GPU
    /// read-write.
    pub(super) _mem: KVec<fw::types::GpuArray<u8>>,
    /// The page list: a ring of `G15_UMA_CAPACITY` u64 page addresses.
    pub(super) _pages: fw::types::GpuArray<u8>,
    /// The backup range list (8 entries of 8 B per block), for a pool reset.
    pub(super) _backup: fw::types::GpuArray<u8>,
    /// The 0x70 B pool state ("UMA Page Pool State", job state +0x83E).
    pub(crate) state: fw::types::GpuArray<u8>,
    /// The u64 submit count (pool state +0x48): +1 per job before its
    /// doorbell; the firmware flushes the slot when its completion count
    /// (+0x50) catches up.
    pub(super) submits: fw::types::GpuArray<u8>,
    /// The metrics buffer: one 0x40 B slot per job (MRR 0x14070; the GPU
    /// writes the kick's peak page use at +0x00).
    pub(super) metrics: fw::types::GpuArray<u8>,
    /// The next metrics slot (byte offset, mod 0x4000).
    pub(super) metrics_next: AtomicU32,
}

/// G15: the UMA pool's blocks of 8192 pages (32 MiB), its pages and the
/// page-list capacity. Five blocks: Metal's own minimum for any compute
/// pass on this chip is 14952 pages and the kext's private pool for it 64 MiB
/// (spec: uma.md, "Sizes"); the first pool had one block, 832 pages above
/// the per-kick constant.
pub(super) const G15_UMA_BLOCKS: usize = 5;
pub(super) const G15_UMA_BLOCK_PAGES: usize = 8192;
pub(super) const G15_UMA_PAGES: usize = G15_UMA_BLOCKS * G15_UMA_BLOCK_PAGES;
pub(super) const G15_UMA_CAPACITY: usize = 0x10000;
/// G15: the GPU's view of a VA, its low 43 bits (bit 42 = the kernel half).
pub(super) const G15_GPU_VA_MASK: u64 = 0x7FF_FFFF_FFFF;

impl core::fmt::Debug for G15Uma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("G15Uma").field("slot", &self.slot).finish()
    }
}

impl G15Uma {
    pub(crate) fn new(alloc: &mut KernelAllocators, slot: u32) -> Result<G15Uma> {
        let mut mem = KVec::new();
        for _ in 0..G15_UMA_BLOCKS {
            mem.push(
                alloc
                    .gpu
                    .array_empty_tagged::<u8>(G15_UMA_BLOCK_PAGES * 0x1000, b"UMAM")?,
                GFP_KERNEL,
            )?;
        }
        let pages = alloc
            .gpu
            .array_empty_tagged::<u8>(G15_UMA_CAPACITY * 8, b"UMAL")?;
        let backup = alloc
            .gpu
            .array_empty_tagged::<u8>(G15_UMA_BLOCKS * 0x40, b"UMAB")?;
        let metrics = alloc.gpu.array_empty_tagged::<u8>(0x4000, b"UMAX")?;
        let state = alloc.shared.array_empty_tagged::<u8>(0x70, b"UMAS")?;
        let submits = alloc.stamp.array_empty_tagged::<u8>(8, b"UMAC")?;
        let pages_gva = pages.gpu_va().get() & G15_GPU_VA_MASK;
        let backup_gva = backup.gpu_va().get() & G15_GPU_VA_MASK;
        // SAFETY: in-bounds stores into the pool's own freshly allocated
        // (zeroed) buffers.
        unsafe {
            // populatePagePool: page i at entry i, the rest of the ring 0.
            let l = pages.raw_ptr().cast::<u64>();
            // The backup ranges: [47:12] the page address, [63:52] pages; a
            // block takes three and five zero entries.
            let b = backup.raw_ptr().cast::<u64>();
            for (k, blk) in mem.iter().enumerate() {
                let base = blk.gpu_va().get() & G15_GPU_VA_MASK;
                for j in 0..G15_UMA_BLOCK_PAGES {
                    l.add(k * G15_UMA_BLOCK_PAGES + j)
                        .write_volatile(base + (j as u64) * 0x1000);
                }
                b.add(k * 8).write_volatile(base | 0xFFF << 52);
                b.add(k * 8 + 1)
                    .write_volatile((base + 0xFFF000) | 0xFFF << 52);
                b.add(k * 8 + 2)
                    .write_volatile((base + 0x1FFE000) | 2 << 52);
            }
            // populateFirmwareState
            let s = state.raw_ptr();
            s.cast::<u64>().write_volatile(u64::from(slot) + 1); // +0x00 pool ID
            s.add(0x08).cast::<u32>().write_volatile(slot); // +0x08 table slot
            s.add(0x14).cast::<u64>().write_unaligned(pages_gva); // page list
            s.add(0x1C)
                .cast::<u32>()
                .write_volatile(G15_UMA_CAPACITY as u32);
            s.add(0x20).cast::<u32>().write_volatile(0); // head
            s.add(0x24)
                .cast::<u32>()
                .write_volatile((G15_UMA_PAGES % G15_UMA_CAPACITY) as u32); // tail
            s.add(0x2C)
                .cast::<u32>()
                .write_volatile(G15_UMA_PAGES as u32); // free pages
            s.add(0x34).cast::<u64>().write_unaligned(backup_gva); // backup list
            s.add(0x44)
                .cast::<u32>()
                .write_volatile(8 * G15_UMA_BLOCKS as u32); // backup entries
            s.add(0x48)
                .cast::<u64>()
                .write_volatile(submits.gpu_va().get()); // -> submit count
            s.add(0x50).cast::<u64>().write_volatile(0); // completion count
        }
        crate::mem::dc_civac(submits.raw_ptr().cast_const(), 8);
        Ok(G15Uma {
            slot,
            _mem: mem,
            _pages: pages,
            _backup: backup,
            state,
            submits,
            metrics,
            metrics_next: AtomicU32::new(0),
        })
    }

    /// The next job's metrics slot, zeroed: its GPU VA.
    pub(super) fn metrics_slot(&self) -> u64 {
        let off = self.metrics_next.fetch_add(0x40, Ordering::Relaxed) % 0x4000;
        // SAFETY: a 0x40 B in-bounds slot of the metrics buffer.
        unsafe {
            core::ptr::write_bytes(self.metrics.raw_ptr().add(off as usize), 0, 0x40);
        }
        self.metrics.gpu_va().get() + u64::from(off)
    }

    /// Logs the pool state the firmware and GPU keep (head, tail, flag,
    /// free pages, reset state, completions; the host's submit count) and
    /// its descriptor-table entry (spec: uma.md, "The descriptor table").
    pub(super) fn log(
        &self,
        dev: &kernel::device::Device,
        table: &fw::types::GpuArray<u8>,
        tag: &str,
    ) {
        let s = self.state.raw_ptr();
        let t = table.raw_ptr().wrapping_add(self.slot as usize * 0x20);
        crate::mem::dc_civac(s.cast_const(), 0x70);
        crate::mem::dc_civac(t.cast_const(), 0x20);
        crate::mem::dc_civac(self.submits.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds reads of the 0x70 B state, the 8 B submit count
        // and the slot's 0x20 B table entry.
        unsafe {
            let r32 = |off: usize| (s.add(off) as *const u32).read_volatile();
            let e = |i: usize| (t.add(i * 8) as *const u64).read_volatile();
            dev_err!(dev, "G15: UMA pool {} (slot {}) {}: head {:#x} tail {:#x} flag {:#x} free {:#x} reset {} completions {} submits {}; table {:#x} {:#x} {:#x}\n",
                     self.slot + 1, self.slot, tag, r32(0x20), r32(0x24), r32(0x28), r32(0x2C), r32(0x30),
                     (s.add(0x50) as *const u64).read_volatile(),
                     (self.submits.raw_ptr() as *const u64).read_volatile(),
                     e(0), e(1), e(2));
        }
    }

    /// One more job submitted (AGXUMAFList::updateSubmitInfo), before its
    /// doorbell.
    pub(super) fn count_submit(&self) {
        let p = self.submits.raw_ptr();
        // SAFETY: the u64 submit count, 8 B aligned; written by the host only.
        unsafe { (*(p as *const AtomicU64)).fetch_add(1, Ordering::AcqRel) };
        crate::mem::dc_civac(p.cast_const(), 8);
    }
}
