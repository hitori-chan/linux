// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 parameter buffers.

use super::*;

/// The parameter buffer's blocks: 128 KiB each, the kext's minimum count
/// (`halGetDefaultParameterBufferSizeMin` = 0x2E0000); the block ring holds
/// one more (it is full when `(head + 1) % max == start`).
pub(super) const PB_BLOCKS: usize = 23;
pub(super) const PB_MAX_BLOCKS: usize = PB_BLOCKS + 1;
pub(super) const PB_BLOCK_SIZE: usize = 0x20000;

/// The scene records (`chip+0x678` = 80) and the per-slot array's slots
/// (36, a 0x100 B stride: enough for any cluster configuration).
pub(super) const PB_SCENES: usize = 80;
pub(super) const PB_SLOTS: usize = 36;
pub(super) const PB_SLOT_STRIDE: usize = 0x100;

/// G15: one parameter buffer (spec: render-job.md, "The parameter
/// buffer"), fixed-size: the kext's minimum, never grown. The blocks are
/// in the jobs' VM, in [64 GiB, 576 GiB) (a block-list entry is the 40-bit
/// form's bits \[39:15\]); the rest (`G15PbState`) is the firmware's and the
/// GPU's (kernel VAs), one per buffer ID for the device's lifetime.
pub(crate) struct G15Pb {
    /// The hardware buffer ID (PBID), and the allocator it returns to.
    pub(crate) id: u32,
    pub(super) ids: Option<Arc<Mutex<u64>>>,
    pub(super) st: Arc<G15PbState>,
    /// The blocks, in the VM's low half.
    pub(crate) blocks: fw::types::GpuArray<u8>,
}

impl core::ops::Deref for G15Pb {
    type Target = G15PbState;
    fn deref(&self) -> &G15PbState {
        &self.st
    }
}

/// G15: the firmware's and the GPU's part of buffer ID n's parameter
/// buffer, kept for the device's lifetime and cleared when the ID is used
/// again. The firmware's PB registry keeps the info's address after the
/// last pass (BSS `0x188850`, 127 entries) and its post-recovery walk reads
/// the info and the counter of every entry (`AGFA_IRQPostRecovery`+0x3e8):
/// a freed info crashed it (a NULL +0x58).
pub(crate) struct G15PbState {
    /// The 0x80 B buffer info (TA js+0x24, 3D js+0x28).
    pub(crate) info: fw::types::GpuArray<u8>,
    /// The 0x80 B block control (+0x40: the stats).
    pub(crate) block_ctl: fw::types::GpuArray<u8>,
    /// The 4 B counter (info +0x58), the 3D jobs submitted (`count_3d`): in
    /// the firmware-uncached stamp heap, as the kext maps it (option
    /// `0x700000007`). In a cached one the firmware unregistered the buffer
    /// under a running 3D (a NULL info at `AGFA_Executor`+0x1da4, eight
    /// processes): it read an old count, inferred.
    pub(crate) counter: fw::types::GpuArray<u8>,
    /// The block list: 8 B per block.
    pub(crate) block_list: fw::types::GpuArray<u8>,
    /// The page list: 4 B per 32 KiB page, 4 pages per block.
    pub(crate) page_list: fw::types::GpuArray<u8>,
    /// The 80 scene records (0x80 B each), then one 0x40 B trailer.
    pub(crate) scenes: fw::types::GpuArray<u8>,
    /// The page-metrics words, one u32 per scene (scene +0x00/+0x08).
    pub(crate) metrics: fw::types::GpuArray<u8>,
    /// The per-slot array (scene +0x28).
    pub(crate) slots: fw::types::GpuArray<u8>,
}

impl Drop for G15Pb {
    fn drop(&mut self) {
        if let Some(ids) = self.ids.take() {
            *ids.lock() &= !(1u64 << self.id);
        }
    }
}

impl G15PbState {
    /// Zero every buffer, for a new parameter buffer with this ID.
    pub(crate) fn clear(&self) {
        for a in [
            &self.info,
            &self.block_ctl,
            &self.counter,
            &self.block_list,
            &self.page_list,
            &self.scenes,
            &self.metrics,
            &self.slots,
        ] {
            // SAFETY: the whole of a buffer this state owns.
            unsafe { core::ptr::write_bytes(a.raw_ptr(), 0, a.len()) };
        }
    }

    /// Count one 3D job submitted on the buffer, before its ring entry is
    /// published (the kext's `incrementPMSubmittedOperations`; spec:
    /// parameter-buffer.md, "The firmware's registry"). The firmware's 3D
    /// post-process unregisters the buffer when its 3D completions (info
    /// +0x00) reach the count, and its post-recovery walk sends a buffer
    /// whose counts differ into the full rebuild at its next TA.
    pub(super) fn count_3d(&self) {
        let c = self.counter.raw_ptr().cast::<u32>();
        // SAFETY: an in-bounds u32 of the buffer's own counter, written by the
        // host alone; the submit holds the queue, the counter's one writer.
        unsafe { c.write_volatile(c.read_volatile().wrapping_add(1)) };
        crate::mem::dc_civac(c as *const u8, 4);
    }
}

impl G15Pb {
    /// Scene record `i` and the trailer.
    pub(super) fn scene(&self, i: usize) -> u64 {
        va(&self.scenes) + (i % PB_SCENES * 0x80) as u64
    }
    pub(super) fn trailer(&self) -> u64 {
        va(&self.scenes) + (PB_SCENES * 0x80) as u64
    }
}

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: a parameter buffer with hardware ID `id`, its blocks from
    /// `ualloc` (the jobs' VM, in [64 GiB, 576 GiB)); `ids` takes the ID
    /// back when it goes.
    pub(super) fn g15_pb_new(
        &self,
        ualloc: &mut alloc::DefaultAllocator,
        id: u32,
        ids: Option<Arc<Mutex<u64>>>,
    ) -> Result<G15Pb> {
        let blocks = ualloc.array_empty_tagged::<u8>(PB_BLOCKS * PB_BLOCK_SIZE, b"PBBK")?;
        // GPU and firmware mapped, as the kext maps them: the GPU reads the
        // page metrics and lists (a firmware-only page metrics word was a
        // NoAccess fault in the PM, boot #151).
        let st = {
            let mut states = self.g15.pb_states.lock();
            let slot = states.get_mut(id as usize).ok_or(EINVAL)?;
            match slot {
                Some(st) => {
                    st.clear();
                    st.clone()
                }
                None => {
                    let mut guard = self.alloc.lock();
                    let a = &mut *guard;
                    let g = &mut a.gpu;
                    let st = Arc::new(
                        G15PbState {
                            info: g.array_empty_tagged::<u8>(0x80, b"PBIN")?,
                            block_ctl: g.array_empty_tagged::<u8>(0x80, b"PBBC")?,
                            counter: a.stamp.array_empty_tagged::<u8>(0x40, b"PBCN")?,
                            block_list: g.array_empty_tagged::<u8>(PB_MAX_BLOCKS * 8, b"PBBL")?,
                            page_list: g.array_empty_tagged::<u8>(PB_MAX_BLOCKS * 16, b"PBPL")?,
                            scenes: g.array_empty_tagged::<u8>(PB_SCENES * 0x80 + 0x40, b"PBSC")?,
                            metrics: g.array_empty_tagged::<u8>(PB_SCENES * 4, b"PBMT")?,
                            slots: g
                                .array_empty_tagged::<u8>(PB_SLOTS * PB_SLOT_STRIDE, b"PBSL")?,
                        },
                        GFP_KERNEL,
                    )?;
                    *slot = Some(st.clone());
                    st
                }
            }
        };
        let pb = G15Pb {
            id,
            ids,
            st,
            blocks,
        };
        let n = PB_BLOCKS as u32;
        let base = pb.blocks.gpu_va().get();
        // The pages are 32 KiB (a page-list entry is the 40-bit form >> 15:
        // the VCE wrote blocks at 0xf0_0011_0000 to kernel 0x470_0011_0000,
        // boot #162), so only user VAs in [64 GiB, 576 GiB) can hold them.
        if base & 0x7FFF != 0
            || base < 0x10_0000_0000
            || base + (PB_BLOCKS * PB_BLOCK_SIZE) as u64 > 0x90_0000_0000
        {
            dev_err!(self.dev.as_ref(), "G15: parameter buffer blocks at {base:#x}: not in [64 GiB, 576 GiB) or 32 KiB-aligned\n");
            return Err(EINVAL);
        }
        let pl = va(&pb.page_list);
        // SAFETY: every store is in bounds of the buffer it names, each
        // freshly allocated and sized above.
        unsafe {
            // The block list (8 B per block: the u32 va40(VA) >> 15) and the
            // page list (4 u32 per block: its four 32 KiB pages).
            let bl = W(pb.block_list.raw_ptr());
            let pg = W(pb.page_list.raw_ptr());
            for i in 0..PB_BLOCKS {
                let e = (va40(base + (i * PB_BLOCK_SIZE) as u64) >> 15) as u32 & 0x1FF_FFFF;
                bl.u32(i * 8, e);
                for k in 0..4 {
                    pg.u32(i * 16 + k * 4, e + k as u32);
                }
            }
            // The block control: head = published = N, start 0; the stats
            // at +0x40 zeroed.
            let bc = W(pb.block_ctl.raw_ptr());
            bc.u32(0x00, n);
            bc.u32(0x04, n);
            bc.u32(0x08, 0);
            // The buffer info (resetHWParamBufferState, buildPageList).
            let f = W(pb.info.raw_ptr());
            f.u32(0x08, id);
            f.u64(0x1C, pl);
            f.u32(0x24, (PB_MAX_BLOCKS * 16) as u32);
            f.u32(0x28, 4 * n); // page count
            f.u32(0x2C, PB_MAX_BLOCKS as u32);
            f.u32(0x30, n); // end
            f.u32(0x34, 0); // start
            f.u64(0x38, va(&pb.block_list));
            f.u64(0x40, va(&pb.block_ctl));
            f.u32(0x48, 4 * n - 1); // last page
            f.u32(0x4C, PB_BLOCK_SIZE as u32);
            f.u64(0x58, va(&pb.counter));
            f.u32(0x70, 4 * n); // max pages (= the page count: no growing)
            f.u32(0x74, 4 * n);
            // The scene records: +0x00/+0x08 the scene's page-metrics word,
            // +0x28 its per-slot array element, +0x40 the stats.
            let sc = W(pb.scenes.raw_ptr());
            for i in 0..PB_SCENES {
                let m = va(&pb.metrics) + 4 * i as u64;
                sc.u64(i * 0x80, m);
                sc.u64(i * 0x80 + 0x08, m);
                sc.u64(
                    i * 0x80 + 0x28,
                    va(&pb.slots) + ((i % PB_SLOTS) * PB_SLOT_STRIDE) as u64,
                );
                sc.u64(i * 0x80 + 0x40, va(&pb.block_ctl) + 0x40);
            }
            // The PB descriptor-table entry (halLoadPBDesc): the page list's
            // VA bits [38:7] and [42], the page count.
            let hi = ((pl.wrapping_add(if pl & 1 << 42 != 0 { 0 } else { 0x70_0000_0000 })
                & 0x70_0000_0000)
                | (pl >> 3 & 0x80_0000_0000))
                >> 36;
            let d = W(self.initdata.pb_desc_table.raw_ptr().add(16 * id as usize));
            d.u32(0, (pl >> 4) as u32 & 0xFFFF_FFF8);
            d.u32(4, (hi as u32) << 28 | ((4 * n) & 0x3F_FFFF));
            d.u32(8, 0);
            d.u32(12, 0);
        }
        Ok(pb)
    }
}
