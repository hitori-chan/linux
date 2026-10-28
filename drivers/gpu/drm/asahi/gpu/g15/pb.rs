// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 parameter buffers.
//!
//! The TA job bins a pass's geometry into a parameter buffer, which the 3D
//! job then reads. A buffer has a hardware ID (1..63) and two parts: its
//! blocks, in the jobs' VM, and the firmware's and GPU's bookkeeping
//! ([`G15PbState`]), which outlives the buffer because the firmware keeps
//! referring to it by ID.
//!
//! Spec: parameter-buffer.md.

use super::*;

/// The parameter buffer's blocks: 128 KiB each, 64 of them (8 MiB) to start
/// with, so that a first pass seldom fills the buffer and renders in parts.
/// macOS starts at a third of its maximum and never below 23 blocks
/// (`halGetDefaultParameterBufferSizeMin` = 0x2E0000). The buffer then grows
/// from the firmware's statistics (`g15_pb_grow`) and a waiting TA's
/// requests up to [`pb_cap`] blocks.
pub(super) const PB_BLOCKS: usize = 64;
pub(super) const PB_BLOCK_SIZE: usize = 0x20000;

/// The blocks a parameter buffer grows to, macOS's maximum
/// (`halGetDefaultParameterBufferSizeMax`): the larger of 192 MiB and 5 % of
/// the RAM, rounded up to 0x1020000 (129 blocks), so that a pass renders in
/// parts only where it would on macOS. Its block ring holds one more: it is
/// full when `(head + 1) % max == start`.
pub(super) fn pb_cap() -> usize {
    let mut si = kernel::bindings::sysinfo::default();
    // SAFETY: `si_meminfo` only fills the struct it is given.
    unsafe { kernel::bindings::si_meminfo(&mut si) };
    let ram = si.totalram * si.mem_unit as usize;
    ((ram / 20).div_ceil(0x102_0000) * 129).max(1536)
}

/// How often a queue's parameter buffer may grow, as the kext's
/// `checkUsage` reads the statistics at most every 4 ms.
pub(super) const PB_CHECK_MS: i64 = 4;

/// The blocks a TA out of pages gets: half the buffer, at least the 10
/// blocks the kext's `growImmediately` adds and at most 16 MiB, which the
/// poller allocates while the TA waits.
pub(super) const PB_GROW_MIN: usize = 10;
pub(super) const PB_GROW_MAX: usize = 128;

/// A parameter buffer and the allocator it grows from, by ID, while its
/// queue lives.
pub(crate) type G15PbGrow = (Arc<G15Pb>, Arc<Mutex<alloc::DefaultAllocator>>);

/// A TA's request for more pages (event 7), which the grow ack (device
/// control 7) answers with the same fields.
#[derive(Clone, Copy)]
pub(crate) struct G15GrowReq {
    pub(crate) pbid: u32,
    /// The context the firmware's append maps the lists in.
    pub(crate) ctx: u32,
    pub(crate) counter: u32,
    /// The TA's hardware slot.
    pub(crate) slot: u32,
    /// The event page's stop count at the request: the firmware drops an
    /// ack with another.
    pub(crate) stops: u64,
}

/// The scene records (80, as on macOS) and the per-slot array's slots (36,
/// with a 0x100-byte stride: enough for any cluster configuration).
pub(super) const PB_SCENES: usize = 80;
pub(super) const PB_SLOTS: usize = 36;
pub(super) const PB_SLOT_STRIDE: usize = 0x100;

/// A parameter buffer. The blocks are in the jobs' VM, in
/// [64 GiB, 576 GiB), since a block-list entry holds bits 39:15 of the
/// 40-bit form of the VA.
pub(crate) struct G15Pb {
    /// The hardware buffer ID (PBID), and the allocator it returns to.
    pub(crate) id: u32,
    pub(super) ids: Option<Arc<Mutex<u64>>>,
    pub(super) st: Arc<G15PbState>,
    /// The first [`PB_BLOCKS`] blocks, in the VM's low half.
    pub(crate) blocks: fw::types::GpuArray<u8>,
    /// The blocks the buffer grew by, kept as long as it: a buffer never
    /// shrinks on G15 (`checkForShrink` only checks for idle).
    pub(super) more: Arc<Mutex<KVec<fw::types::GpuOnlyArray<u8>>>>,
}

/// The parameter-manager record a TA job carries ahead of its job state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum G15Pm {
    None,
    /// PMRebuild (type 6): the first TA job on a buffer, and the first after
    /// a host stop.
    Rebuild,
    /// PMGrow (type 5): the first after the buffer grew.
    Grow,
}

impl core::ops::Deref for G15Pb {
    type Target = G15PbState;
    fn deref(&self) -> &G15PbState {
        &self.st
    }
}

/// The firmware's and the GPU's part of the parameter buffer with a given
/// ID, kept for the device's lifetime and cleared when the ID is used
/// again: the firmware's buffer registry keeps the info's address after the
/// last pass, and its post-recovery walk reads the info and the counter of
/// every registered buffer.
pub(crate) struct G15PbState {
    /// The 0x80-byte buffer info, which the TA and 3D job states point to.
    pub(crate) info: fw::types::GpuArray<u8>,
    /// The 0x80-byte block control, with the statistics at +0x40, mapped
    /// firmware non-cacheable as macOS maps it: the firmware's append reads
    /// the published count with no cache maintenance, so through a cached
    /// mapping it could take the count of the buffer that last had this ID
    /// and append blocks whose entries are zero.
    pub(crate) block_ctl: fw::types::GpuArray<u8>,
    /// The count of 3D jobs submitted on the buffer, in the firmware-uncached
    /// stamp heap as macOS maps it: through a cached mapping the firmware
    /// could read an old count and unregister the buffer under a running 3D
    /// job.
    pub(crate) counter: fw::types::GpuArray<u8>,
    /// The block list: 8 bytes per block.
    pub(crate) block_list: fw::types::GpuArray<u8>,
    /// The page list: 4 bytes per 32 KiB page, 4 pages per block.
    pub(crate) page_list: fw::types::GpuArray<u8>,
    /// The 80 scene records of 0x80 bytes, then a 0x40-byte trailer.
    pub(crate) scenes: fw::types::GpuArray<u8>,
    /// The page-metrics words, one u32 per scene, which the TA writes and
    /// the firmware reads and zeroes at the TA's end with no cache
    /// maintenance: mapped firmware non-cacheable, as macOS maps its
    /// `PMPageMetricsBuffer` (range 7).
    pub(crate) metrics: fw::types::GpuArray<u8>,
    /// The per-slot array the scenes point into.
    pub(crate) slots: fw::types::GpuArray<u8>,
    /// The blocks the host has published: block control `[0]` and `[1]`.
    pub(crate) published: AtomicU32,
}

impl Drop for G15Pb {
    fn drop(&mut self) {
        // A pass renders in parts when its TA runs out of pages at the cap or
        // cannot wait for more: rare, and where the fork's partial renders
        // can lose pixels, so it is logged once per buffer.
        let (asked, done) = self.st.partials();
        if asked != 0 {
            pr_info!(
                "G15: parameter buffer {} rendered in parts {asked} times ({done} done) at {} blocks\n",
                self.id,
                self.st.published.load(Ordering::Relaxed)
            );
        }
        if let Some(ids) = self.ids.take() {
            *ids.lock() &= !(1u64 << self.id);
        }
    }
}

impl G15PbState {
    /// The partial renders the firmware requested and finished on this
    /// buffer (`info+0x64`, `+0x68`).
    pub(super) fn partials(&self) -> (u32, u32) {
        crate::mem::dc_civac(self.info.raw_ptr().cast_const(), 0x80);
        // SAFETY: in-bounds u32 reads of the state's own info.
        unsafe {
            let i = self.info.raw_ptr() as *const u32;
            (
                i.add(0x64 / 4).read_volatile(),
                i.add(0x68 / 4).read_volatile(),
            )
        }
    }

    /// Zeroes every buffer, for a new parameter buffer with this ID.
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

    /// The lists' state for a recovery's log: the info's page count, start
    /// and appended head (`+0x28`, `+0x34`, `+0x30`), the published head
    /// (block control `[1]`), and the zero entries in the page list's free
    /// span and among the published block-list entries. `ring` is the
    /// descriptor's free-page ring, words 2 and 3: the GPU takes pages at
    /// `A` and gives them back at `B`, `C` (word 3 bit 31) set when it has
    /// taken them all, so the free span is `[A, B)` round the list's end and
    /// only it must hold no zero entry; the taken span keeps whatever it held
    /// (`sub_31F3C` appends at `B`, over taken entries, and leaves the list's
    /// new tail unwritten).
    pub(super) fn lists(&self, ring: [u32; 2]) -> [u32; 6] {
        crate::mem::dc_civac(self.info.raw_ptr().cast_const(), 0x80);
        crate::mem::dc_civac(self.block_ctl.raw_ptr().cast_const(), 0x10);
        // SAFETY: in-bounds u32 reads of the state's own info and block control.
        let (pages, start, head, publ) = unsafe {
            let i = self.info.raw_ptr() as *const u32;
            let c = self.block_ctl.raw_ptr() as *const u32;
            (
                i.add(10).read_volatile(),
                i.add(13).read_volatile(),
                i.add(12).read_volatile(),
                c.add(1).read_volatile(),
            )
        };
        let np = (pages as usize).min(self.page_list.len() / 4);
        let nb = (publ as usize).min(self.block_list.len() / 8);
        crate::mem::dc_civac(self.page_list.raw_ptr().cast_const(), np * 4);
        crate::mem::dc_civac(self.block_list.raw_ptr().cast_const(), nb * 8);
        // SAFETY: the reads stay within the first np u32 and nb u64 of the lists.
        let (zp, zb) = unsafe {
            let pl = self.page_list.raw_ptr() as *const u32;
            let bl = self.block_list.raw_ptr() as *const u64;
            let (a, b, c) = (ring[0] & 0x3F_FFFF, ring[1] & 0x3F_FFFF, ring[1] >> 31 != 0);
            let free = |k: usize| {
                let k = k as u32;
                !c && if a < b {
                    (a..b).contains(&k)
                } else {
                    k >= a || k < b
                }
            };
            (
                (0..np)
                    .filter(|&k| free(k) && pl.add(k).read_volatile() == 0)
                    .count() as u32,
                (0..nb).filter(|&k| bl.add(k).read_volatile() == 0).count() as u32,
            )
        };
        [pages, start, head, publ, zp, zb]
    }

    /// Counts one 3D job submitted on the buffer, before its ring entry is
    /// published (`incrementPMSubmittedOperations`). The firmware
    /// unregisters the buffer when its 3D completions reach the count, and
    /// its post-recovery walk rebuilds a buffer whose counts differ at the
    /// next TA job.
    pub(super) fn count_3d(&self) {
        let c = self.counter.raw_ptr().cast::<u32>();
        // SAFETY: the buffer's own u32 counter, which only the host writes,
        // from the submitting queue.
        unsafe { c.write_volatile(c.read_volatile().wrapping_add(1)) };
        crate::mem::dc_civac(c as *const u8, 4);
    }

    /// Starts the buffer again after a host stop, as the kext's
    /// `resetParameterState` does (`resetHWParamBufferState`, then
    /// `buildPageList`): the 3D and TA completions, the TAs in flight, the
    /// partial renders and the host's 3D count at 0; the page list written
    /// again from every published block, all its pages free, the appended
    /// head at the published count and the start at 0; the statistics
    /// zeroed with their reset pending; and the descriptor-table entry
    /// `desc` loaded from that state, its free-page ring at 0. The gate
    /// (`+0x18`) stays as the firmware left it, as the kext leaves it.
    ///
    /// # Safety
    ///
    /// `desc` must be the buffer's 16-byte entry of the descriptor table.
    pub(super) unsafe fn reset_counts(&self, desc: *mut u8) {
        let n = (self.published.load(Ordering::Relaxed) as usize)
            .min(self.block_list.len() / 8)
            .min(self.page_list.len() / 16);
        let pages = 4 * n as u32;
        // SAFETY: in-bounds stores into the buffer's own info, block control,
        // counter and lists (n bounded by both lists above), and into `desc`
        // per the caller.
        unsafe {
            let bl = self.block_list.raw_ptr() as *const u32;
            let pg = W(self.page_list.raw_ptr());
            for i in 0..n {
                let e = bl.add(2 * i).read_volatile();
                for k in 0..4 {
                    pg.u32(i * 16 + k * 4, e + k as u32);
                }
            }
            let f = W(self.info.raw_ptr());
            for off in [0x00, 0x10, 0x14, 0x34, 0x50, 0x60, 0x64, 0x68, 0x6C] {
                f.u32(off, 0);
            }
            f.u32(0x28, pages);
            f.u32(0x30, n as u32);
            f.u32(0x48, pages.wrapping_sub(1));
            let bc = W(self.block_ctl.raw_ptr());
            bc.u32(0x00, n as u32);
            bc.u32(0x04, n as u32);
            bc.u32(0x08, 0);
            core::ptr::write_bytes(self.block_ctl.raw_ptr().add(0x40), 0, 0x40);
            bc.u32(0x60, 1);
            self.counter.raw_ptr().cast::<u32>().write_volatile(0);
            let w = pb_desc_words(va(&self.page_list), pages);
            let d = W(desc);
            d.u32(0, w[0]);
            d.u32(4, w[1]);
            d.u32(8, 0);
            d.u32(12, 0);
        }
        for a in [&self.info, &self.block_ctl, &self.counter] {
            crate::mem::dc_civac(a.raw_ptr().cast_const(), a.len());
        }
        crate::mem::dc_civac(self.page_list.raw_ptr().cast_const(), n * 16);
        crate::mem::dc_civac(desc.cast_const(), 16);
    }
}

impl G15Pb {
    /// The GPU VA of scene record `i`.
    pub(super) fn scene(&self, i: usize) -> u64 {
        va(&self.scenes) + (i % PB_SCENES * 0x80) as u64
    }

    /// The GPU VA of the scene trailer.
    pub(super) fn trailer(&self) -> u64 {
        va(&self.scenes) + (PB_SCENES * 0x80) as u64
    }
}

/// Whether `n` blocks at `base` can go into a block list. The pages are
/// 32 KiB and a block-list entry is the 40-bit form of the VA >> 15, so only
/// user VAs in [64 GiB, 576 GiB) can hold them.
fn pb_blocks_fit(base: u64, n: usize) -> bool {
    base & 0x7FFF == 0
        && base >= 0x10_0000_0000
        && base + (n * PB_BLOCK_SIZE) as u64 <= 0x90_0000_0000
}

/// A descriptor-table entry's first two words (`halLoadPBDesc`): the page
/// list's VA bits 38:7 and 42, and the page count.
fn pb_desc_words(pl: u64, pages: u32) -> [u32; 2] {
    let hi = ((pl.wrapping_add(if pl & 1 << 42 != 0 { 0 } else { 0x70_0000_0000 })
        & 0x70_0000_0000)
        | (pl >> 3 & 0x80_0000_0000))
        >> 36;
    [
        (pl >> 4) as u32 & 0xFFFF_FFF8,
        (hi as u32) << 28 | (pages & 0x3F_FFFF),
    ]
}

#[versions(AGX)]
impl GpuManager::ver {
    /// The descriptor-table entry of parameter buffer `id`, for diagnostics:
    /// the page list's VA and page count, then the free-page ring's state,
    /// as the firmware last loaded it.
    pub(super) fn g15_pb_desc(&self, id: u32) -> [u32; 4] {
        let p = self
            .initdata
            .pb_desc_table
            .raw_ptr()
            .wrapping_add(16 * id as usize);
        crate::mem::dc_civac(p.cast_const(), 16);
        // SAFETY: an in-bounds entry of the 64-entry table.
        unsafe {
            let w = p as *const u32;
            [
                w.read_volatile(),
                w.add(1).read_volatile(),
                w.add(2).read_volatile(),
                w.add(3).read_volatile(),
            ]
        }
    }

    /// Creates a parameter buffer with hardware ID `id`, its blocks from
    /// `ualloc` (the jobs' VM, in [64 GiB, 576 GiB)); `ids` takes the ID back
    /// when it goes. On an error the ID stays taken. The device allocator is locked with neither `ualloc` nor
    /// the buffer states held: queue creation holds it while it locks a
    /// file's `ualloc` (`Buffer::ensure_blocks`).
    pub(super) fn g15_pb_new(
        &self,
        ualloc: &Mutex<alloc::DefaultAllocator>,
        id: u32,
        ids: Option<Arc<Mutex<u64>>>,
    ) -> Result<G15Pb> {
        let blocks = ualloc
            .lock()
            .array_empty_tagged::<u8>(PB_BLOCKS * PB_BLOCK_SIZE, b"PBBK")?;
        let more = Arc::pin_init(new_mutex!(KVec::new(), "g15_pb_more"), GFP_KERNEL)?;
        let max = self.g15.pb_cap + 1;
        let old = {
            let states = self.g15.pb_states.lock();
            let slot = states.get(id as usize).ok_or(EINVAL)?;
            if let Some(st) = slot {
                st.clear();
            }
            slot.clone()
        };
        // Mapped for the GPU and the firmware, as on macOS: the GPU reads the
        // page metrics and lists. The ID is the caller's alone, so no other
        // state for it can appear meanwhile.
        let st = match old {
            Some(st) => st,
            None => {
                let st = {
                    let mut guard = self.alloc.lock();
                    let a = &mut *guard;
                    let g = &mut a.gpu;
                    Arc::new(
                        G15PbState {
                            info: g.array_empty_tagged::<u8>(0x80, b"PBIN")?,
                            block_ctl: a.gpu_fw_nc.array_empty_tagged::<u8>(0x80, b"PBBC")?,
                            counter: a.stamp.array_empty_tagged::<u8>(0x40, b"PBCN")?,
                            // Firmware-uncached, unlike the kext's: the
                            // firmware's full rebuild (`sub_319A8`) cleans
                            // only the list's first `info+0x2C` bytes before
                            // reading it, so past 192 blocks it could read
                            // stale lines of its own cache.
                            block_list: a.gpu_fw_nc.array_empty_tagged::<u8>(max * 8, b"PBBL")?,
                            page_list: g.array_empty_tagged::<u8>(max * 16, b"PBPL")?,
                            scenes: g.array_empty_tagged::<u8>(PB_SCENES * 0x80 + 0x40, b"PBSC")?,
                            metrics: a
                                .gpu_fw_nc
                                .array_empty_tagged::<u8>(PB_SCENES * 4, b"PBMT")?,
                            slots: g
                                .array_empty_tagged::<u8>(PB_SLOTS * PB_SLOT_STRIDE, b"PBSL")?,
                            published: AtomicU32::new(0),
                        },
                        GFP_KERNEL,
                    )?
                };
                self.g15.pb_states.lock()[id as usize] = Some(st.clone());
                st
            }
        };
        let mut pb = G15Pb {
            id,
            ids,
            st,
            blocks,
            more,
        };
        let n = PB_BLOCKS as u32;
        pb.published.store(n, Ordering::Relaxed);
        let base = pb.blocks.gpu_va().get();
        if !pb_blocks_fit(base, PB_BLOCKS) {
            dev_err!(
                self.dev.as_ref(),
                "G15: parameter buffer blocks at {base:#x}: not in [64 GiB, 576 GiB) or 32 KiB-aligned\n"
            );
            pb.ids = None;
            return Err(EINVAL);
        }
        let pl = va(&pb.page_list);
        // SAFETY: every store is in bounds of the buffer it names, each
        // freshly allocated and sized above.
        unsafe {
            // The block list (8 bytes per block: the u32 va40(VA) >> 15) and
            // the page list (four u32 per block, its four 32 KiB pages).
            let bl = W(pb.block_list.raw_ptr());
            let pg = W(pb.page_list.raw_ptr());
            for i in 0..PB_BLOCKS {
                let e = (va40(base + (i * PB_BLOCK_SIZE) as u64) >> 15) as u32 & 0x1FF_FFFF;
                bl.u32(i * 8, e);
                for k in 0..4 {
                    pg.u32(i * 16 + k * 4, e + k as u32);
                }
            }
            // The block control: head = published = N, start 0, the
            // statistics at +0x40 zeroed.
            let bc = W(pb.block_ctl.raw_ptr());
            bc.u32(0x00, n);
            bc.u32(0x04, n);
            bc.u32(0x08, 0);
            // The buffer info (as resetHWParamBufferState and buildPageList).
            let f = W(pb.info.raw_ptr());
            f.u32(0x08, id);
            f.u64(0x1C, pl);
            f.u32(0x24, (max * 16) as u32);
            f.u32(0x28, 4 * n); // page count
            f.u32(0x2C, max as u32);
            f.u32(0x30, n); // end
            f.u32(0x34, 0); // start
            f.u64(0x38, va(&pb.block_list));
            f.u64(0x40, va(&pb.block_ctl));
            f.u32(0x48, 4 * n - 1); // last page
            f.u32(0x4C, PB_BLOCK_SIZE as u32);
            f.u64(0x58, va(&pb.counter));
            // The max pages, which only set the descriptor's can-grow bit
            // (`+0x28 < +0x74`): at the first page count, the bit stays
            // clear as the buffer grows. A TA asks for pages (event 7) by
            // its job's flag (`g15_ta_job_new`), not by this bit.
            f.u32(0x70, 4 * n);
            f.u32(0x74, 4 * n);
            // The scene records: +0x00 and +0x08 the scene's page-metrics
            // word, +0x28 its per-slot array element, +0x40 the statistics.
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
            // The descriptor-table entry, its free-page ring at 0.
            let w = pb_desc_words(pl, 4 * n);
            let d = W(self.initdata.pb_desc_table.raw_ptr().add(16 * id as usize));
            d.u32(0, w[0]);
            d.u32(4, w[1]);
            d.u32(8, 0);
            d.u32(12, 0);
            // The table is firmware-uncached, four entries to a line: the
            // entry goes back at once, before a neighbour's firmware write.
            crate::mem::dc_civac(d.0.cast_const(), 16);
        }
        // Cleaned as `reset_counts` cleans: the firmware's TA kick re-reads
        // the info and the GPU reads the lists.
        for a in [
            &pb.info,
            &pb.block_ctl,
            &pb.counter,
            &pb.block_list,
            &pb.page_list,
            &pb.scenes,
            &pb.metrics,
            &pb.slots,
        ] {
            crate::mem::dc_civac(a.raw_ptr().cast_const(), a.len());
        }
        Ok(pb)
    }

    /// Grows queue `q`'s parameter buffer before a pass, as the kext's
    /// `checkUsage` does: at most every [`PB_CHECK_MS`] and once the firmware
    /// has taken the last check's reset, to three times the most pages a pass
    /// used or four pages past the most in use at once, whichever is more.
    /// The new blocks' entries go into the block list and the block control's
    /// head and published count move past them; the firmware appends their
    /// pages to the page list (`sub_31F3C`) when a TA job hands it a PMGrow
    /// record, which the next pass carries (`q.grown`), or a PMRebuild one.
    pub(super) fn g15_pb_grow(&self, q: &mut G15RdQueue) -> Result {
        let Some(ualloc) = q.ualloc.as_ref() else {
            return Ok(());
        };
        if q.checked
            .is_some_and(|t| t.elapsed() < Delta::from_millis(PB_CHECK_MS))
        {
            return Ok(());
        }
        let Some(pb) = q.res.as_ref().map(|r| &r.pb) else {
            return Ok(());
        };
        // The statistics at block control +0x40, which the firmware updates
        // at each 3D job's end (`sub_247EC`): [0] the most pages a pass used,
        // all its partial renders' together, [1] the most in the buffer in
        // use at once, [8] the reset, which the next end takes by zeroing
        // them. Racing that end loses at most one pass's numbers.
        let s = pb.block_ctl.raw_ptr().wrapping_add(0x40);
        crate::mem::dc_civac(s.cast_const(), 0x40);
        // SAFETY: in-bounds u32 accesses to the buffer's own 0x80-byte block
        // control.
        let (most, in_use) = unsafe {
            let p = s.cast::<u32>();
            if p.add(8).read_volatile() == 1 {
                return Ok(());
            }
            let r = (p.read_volatile(), p.add(1).read_volatile());
            p.add(8).write_volatile(1);
            r
        };
        crate::mem::dc_civac(s.cast_const(), 0x40);
        q.checked = Some(Instant::<Monotonic>::now());
        let want = (3 * most as usize).max(in_use as usize + 4).div_ceil(4);
        if self.g15_pb_add(pb, ualloc, |_| want)? {
            q.grown = true;
        }
        Ok(())
    }

    /// Grows `pb` from `ualloc` to `want(n)` blocks (at most the cap,
    /// [`pb_cap`]), `n` being the blocks it has: writes the new
    /// blocks' block-list entries and moves the block control's head and
    /// published count past them. Returns whether it grew. The firmware
    /// appends the blocks' pages at the next TA job's PMGrow or PMRebuild
    /// record, or at a grow ack. The buffer's `more` lock orders the growers.
    fn g15_pb_add(
        &self,
        pb: &G15Pb,
        ualloc: &Mutex<alloc::DefaultAllocator>,
        want: impl FnOnce(usize) -> usize,
    ) -> Result<bool> {
        let mut more = pb.more.lock();
        let n = pb.published.load(Ordering::Relaxed) as usize;
        let want = want(n).min(self.g15.pb_cap);
        if want <= n {
            return Ok(false);
        }
        let add = want - n;
        let chunk = ualloc.lock().array_gpuonly::<u8>(add * PB_BLOCK_SIZE)?;
        let base = chunk.gpu_va().get();
        if !pb_blocks_fit(base, add) {
            return Err(EINVAL);
        }
        // Kept before the firmware can see them.
        more.push(chunk, GFP_KERNEL)?;
        // The entries reach memory before the published count: a TA out of
        // pages makes the firmware append the published blocks at any time
        // (`AGFA_IRQStageMachine`), as `growImmediately` publishes each
        // block after a barrier.
        // SAFETY: in-bounds stores into the buffer's own block list (entries
        // below `want` <= the cap, one fewer than the list holds).
        unsafe {
            let bl = W(pb.block_list.raw_ptr());
            for i in 0..add {
                let e = (va40(base + (i * PB_BLOCK_SIZE) as u64) >> 15) as u32 & 0x1FF_FFFF;
                bl.u32((n + i) * 8, e);
            }
        }
        crate::mem::dc_civac(
            pb.block_list.raw_ptr().wrapping_add(n * 8).cast_const(),
            add * 8,
        );
        // SAFETY: in-bounds stores into the buffer's own block control.
        unsafe {
            let bc = W(pb.block_ctl.raw_ptr());
            bc.u32(0x00, want as u32);
            bc.u32(0x04, want as u32);
        }
        crate::mem::dc_civac(pb.block_ctl.raw_ptr().cast_const(), 0x40);
        pb.published.store(want as u32, Ordering::Relaxed);
        mod_dev_dbg!(
            self.dev,
            "G15: parameter buffer {} grows from {n} to {want} blocks\n",
            pb.id
        );
        Ok(true)
    }

    /// Lets queue `q`'s parameter buffer grow while a TA waits for pages,
    /// from `q.ualloc`; without one, a TA out of pages renders in parts.
    pub(super) fn g15_pb_register(&self, q: &G15RdQueue) {
        let Some(r) = q.res.as_ref() else {
            return;
        };
        let new = q.ualloc.clone().map(|a| (r.pb.clone(), a));
        let old = core::mem::replace(&mut self.g15.pb_grow.lock()[r.pb.id as usize], new);
        drop(old);
    }

    /// Ends queue `q`'s growth: its buffer goes with its last pass.
    pub(super) fn g15_pb_unregister(&self, q: &G15RdQueue) {
        let Some(r) = q.res.as_ref() else {
            return;
        };
        let old = self.g15.pb_grow.lock()[r.pb.id as usize].take();
        drop(old);
    }

    /// Answers the TAs waiting for pages (event 7), as the kext's
    /// `allocateMemoryEvent` does: grows each buffer by half, within
    /// [`PB_GROW_MIN`] and [`PB_GROW_MAX`] blocks, and sends the grow ack
    /// (device control 7: `{7, result, PBID, context, counter, TA slot,
    /// stop count}`). With a result of 1 the firmware appends the published
    /// blocks and resumes the TA; with 0 the TA renders in parts. Runs in
    /// the poller.
    pub(super) fn g15_pb_grow_pending(&self) {
        let reqs = core::mem::take(&mut *self.g15.pb_grow_reqs.lock());
        for r in reqs.iter() {
            let reg = {
                let grow = self.g15.pb_grow.lock();
                grow.get(r.pbid as usize).cloned().flatten()
            };
            let grew = match reg {
                Some((pb, ualloc)) => self
                    .g15_pb_add(&pb, &ualloc, |n| {
                        n + (n / 2).clamp(PB_GROW_MIN, PB_GROW_MAX)
                    })
                    .unwrap_or_else(|e| {
                        dev_warn!(
                            self.dev.as_ref(),
                            "G15: parameter buffer {} cannot grow: {e:?}\n",
                            r.pbid
                        );
                        false
                    }),
                None => false,
            };
            let mut ack = [0u32; 14];
            ack[0] = 7;
            ack[1] = u32::from(grew);
            ack[2] = r.pbid;
            ack[3] = r.ctx;
            ack[4] = r.counter;
            ack[5] = r.slot;
            ack[6] = r.stops as u32;
            ack[7] = (r.stops >> 32) as u32;
            if let Err(e) = self.g15_ctl_send(&ack) {
                dev_err!(
                    self.dev.as_ref(),
                    "G15: parameter buffer {}: grow ack not sent ({e:?})\n",
                    r.pbid
                );
            }
        }
    }
}
