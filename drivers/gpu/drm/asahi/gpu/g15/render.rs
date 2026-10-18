// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 render passes: the TA and 3D pair, queues and submission.

use super::*;

/// G15: a render queue's TA and 3D channels.
pub(crate) type G15RdChans = (Arc<Mutex<G15ClChannel>>, Arc<Mutex<G15ClChannel>>);

/// A render target's geometry (`AGXRenderTargetMemoryG15::halComputeGeometry`,
/// Asahi's `TileInfo`; spec: render-job.md, "Per render pass"): 32x32 px
/// tiles of 32x32, 32x16 or 16x16 px utiles; a macrotile is 4x4 tiles
/// (`align(ceil(tiles / 4), 4)` per axis).
#[derive(Clone, Copy)]
pub(crate) struct G15RdGeom {
    pub(super) w: u32,
    pub(super) h: u32,
    pub(super) layers: u32,
    pub(super) tiles_x: u32,
    pub(super) tiles_y: u32,
    /// Tiles per macrotile along x and y.
    pub(super) tpm_x: u32,
    pub(super) tpm_y: u32,
    /// Utiles per macrotile along x and y, and n (their product).
    pub(super) upm_x: u32,
    pub(super) upm_y: u32,
    pub(super) n: u32,
    /// The utile config (`0x10008`/`0x10148`): utile width/16 `<< 12`,
    /// height/16 `<< 14`, log2 samples.
    pub(super) utile_config: u64,
    /// The 2 KiB tilebuffer blocks per utile (`0x10050`).
    pub(super) blocks_per_utile: u32,
}

impl G15RdGeom {
    pub(crate) fn new(
        w: u32,
        h: u32,
        layers: u32,
        samples: u32,
        utile_w: u32,
        utile_h: u32,
        sample_size: u32,
    ) -> Result<G15RdGeom> {
        if w == 0 || h == 0 || w > 16384 || h > 16384 || layers == 0 || layers > 2048 {
            return Err(EINVAL);
        }
        match (utile_w, utile_h) {
            (32, 32) | (32, 16) | (16, 16) => (),
            _ => return Err(EINVAL),
        }
        let samples_log2 = match samples {
            1 => 0,
            2 => 1,
            4 => 2,
            _ => return Err(EINVAL),
        };
        let (tiles_x, tiles_y) = (w.div_ceil(32), h.div_ceil(32));
        let tpm_x = tiles_x.div_ceil(4).next_multiple_of(4);
        let tpm_y = tiles_y.div_ceil(4).next_multiple_of(4);
        let (upm_x, upm_y) = (tpm_x * (32 / utile_w), tpm_y * (32 / utile_h));
        Ok(G15RdGeom {
            w,
            h,
            layers,
            tiles_x,
            tiles_y,
            tpm_x,
            tpm_y,
            upm_x,
            upm_y,
            n: upm_x * upm_y,
            utile_config: u64::from((utile_w / 16) << 12 | (utile_h / 16) << 14 | samples_log2),
            blocks_per_utile: (((utile_w * utile_h) << samples_log2) * sample_size).div_ceil(2048),
        })
    }

    /// The region size (`rtm+0x18`): 5 B per utile of a macrotile, in u32.
    pub(super) fn rgn_size(&self) -> u32 {
        (5 * self.n) >> 2
    }

    pub(super) fn tilemap_size(&self) -> usize {
        (0x50 * self.n * self.layers) as usize
    }

    /// TE_SCREEN: the last tile on each axis.
    pub(super) fn te_screen(&self) -> u64 {
        u64::from((self.tiles_y - 1) << 12 | (self.tiles_x - 1))
    }

    /// ISP_MTILE_SIZE: utiles per macrotile, x and y.
    pub(super) fn mtile_size(&self) -> u64 {
        u64::from((self.upm_x & 0x3FF) << 16 | self.upm_y)
    }
}

/// A depth or stencil buffer (the ISP's load/store bases and strides).
#[derive(Clone, Copy, Default)]
pub(crate) struct G15RdZls {
    pub(crate) base: u64,
    pub(crate) comp_base: u64,
    pub(crate) stride: u64,
    pub(crate) comp_stride: u64,
}

/// A render pass's inputs. VAs are the client's (user VAs of the job's
/// VM); None or 0 = none.
#[derive(Clone, Copy)]
pub(crate) struct G15RdCmd {
    pub(crate) geom: G15RdGeom,
    /// The VDM control stream (`0x1C880`), or None for a terminate-only one.
    pub(crate) vdm: Option<u64>,
    /// The background and end-of-tile words (`0x15368`/`0x15370`,
    /// `0x15378`/`0x15380`): word 0 the binding, word 1 the entry
    /// program's VA.
    pub(crate) bg: (u64, u64),
    pub(crate) eot: (u64, u64),
    /// The partial render's background (it reloads the tiles a partial
    /// render stored) and end-of-tile programs, in the same form. The
    /// firmware puts them in place of `bg`/`eot` only for partial renders
    /// (render-job.md, "Partial renders").
    pub(crate) partial_bg: (u64, u64),
    pub(crate) partial_eot: (u64, u64),
    /// Process empty tiles (tile config bit 16).
    pub(crate) process_empty: bool,
    pub(crate) multisamplectl: u64,
    pub(crate) zls_pixels: u64,
    pub(crate) zls_ctrl: u64,
    pub(crate) bgobjdepth: u32,
    pub(crate) bgobjvals: u32,
    pub(crate) depth: G15RdZls,
    pub(crate) stencil: G15RdZls,
    pub(crate) scissor: u64,
    pub(crate) dbias: u64,
    pub(crate) oclqry: u64,
    /// isp_ctl (`0x15020`): `0xC000`, `| 1 << 18` for integer depth bias.
    pub(crate) isp_ctl: u64,
    pub(crate) merge_x: u32,
    pub(crate) merge_y: u32,
}

/// G15: one job of a render pass (TA or 3D): its job state, stream, its
/// own notifier when it has no pass notifier, and the record published
/// ahead of it: the type-6 PMRebuild record of the first TA job of a
/// parameter buffer, or the 3D's type-4 stamp barrier on its TA.
pub(crate) struct G15RdJob {
    pub(crate) job_state: fw::types::GpuArray<u8>,
    pub(super) _stream: fw::types::GpuArray<u8>,
    pub(super) _notifier: Option<fw::types::GpuArray<u8>>,
    pub(crate) pre: Option<fw::types::GpuArray<u8>>,
    pub(crate) stamp: u32,
    /// The UMA pool the job registers.
    pub(super) uma: Arc<crate::gpu::G15Uma>,
}

impl G15RdJob {
    /// The record slots the job takes: its job state, and the record ahead.
    pub(super) fn records(&self) -> u32 {
        1 + u32::from(self.pre.is_some())
    }
}

/// The link of a pass's TA and 3D: the pass notifier (one, two kicks) and
/// the other job's stamp.
#[derive(Clone, Copy)]
pub(super) struct G15RdLink {
    /// The pass notifier's VA, or None: each job its own (one kick).
    pub(super) ntf: Option<u64>,
    /// TA: its 3D's {stamp index, stamp} (js+0x77C). 3D: the TA's
    /// {FW stamp word FWVA, stamp, stamp index} to wait on (a type-4
    /// barrier record), or 0 for none.
    pub(super) other_index: u32,
    pub(super) other_stamp: u32,
    pub(super) other_word: u64,
}

/// G15: a queue's render state: its TA and 3D channels and its parameter
/// buffer (in the queue's VM), and the passes run so far.
pub(crate) struct G15RdQueue {
    pub(super) ta: Arc<Mutex<G15ClChannel>>,
    pub(super) d3: Arc<Mutex<G15ClChannel>>,
    pub(super) pb: Arc<G15Pb>,
    pub(super) passes: u32,
    /// The TA-only render-target buffers of the queue's passes.
    pub(super) rt: Option<Arc<G15RtShared>>,
}

impl G15RdQueue {
    /// The 3D channel: a pass is complete when its 3D job is.
    pub(crate) fn d3(&self) -> &Arc<Mutex<G15ClChannel>> {
        &self.d3
    }

    /// The queue's TA-only render-target buffers (`GpuManager::g15_rt_new`).
    pub(crate) fn rt_cache(&mut self) -> &mut Option<Arc<G15RtShared>> {
        &mut self.rt
    }
}

/// G15: a submitted render pass's buffers, kept until its 3D retires.
pub(crate) struct G15RdPass {
    pub(super) _ta: G15RdJob,
    pub(super) _d3: G15RdJob,
    pub(super) _ntf: fw::types::GpuArray<u8>,
    pub(super) _rt: G15Rt,
    pub(super) _pb: Arc<G15Pb>,
    /// The pass's scene record index in its parameter buffer.
    pub(super) scene: usize,
}

impl G15RdPass {
    /// The pass's notifier, shared by its TA and 3D jobs.
    pub(super) fn notifier(&self) -> &fw::types::GpuArray<u8> {
        &self._ntf
    }

    /// Zero the TA's tail-pointer cache, as the kext does for an unfinished
    /// TA job at a recovery (`processFirmwareTACommandsRecovery`, spec:
    /// faults.md, "The host's side").
    pub(super) fn clear_tpc(&self) {
        let t = &self._rt.tpc;
        // SAFETY: the whole of the pass's own TPC buffer.
        unsafe { core::ptr::write_bytes(t.raw_ptr(), 0, t.len()) };
        crate::mem::dc_civac(t.raw_ptr().cast_const(), t.len());
    }

    /// Mark the pass's scene aborted (scene record `+0x38` = 1), as the
    /// firmware's post-recovery walk does for each TA left in its channel
    /// table (`AGFA_IRQPostRecovery`, `sub_D324`) but not for a TA in an
    /// active slot, which the walk marks done without running it. The 3D
    /// kick then skips the scene and its end still counts the 3D (record 7
    /// and 8, `AGFA_Executor`); a TA that kicks again clears the mark
    /// (`sub_23570`) and runs as usual (spec: faults.md, "The post-recovery
    /// walk"). Without it the 3D of a TA that never ran draws from a
    /// never-written tilemap: an `IPF` read at the 40-bit form of a small
    /// value (boot #276).
    pub(super) fn abort_scene(&self) {
        let p = self
            ._pb
            .scenes
            .raw_ptr()
            .wrapping_add(self.scene % PB_SCENES * 0x80 + 0x38);
        // SAFETY: an in-bounds u32 of the buffer's own scene record.
        unsafe { p.cast::<u32>().write_volatile(1) };
        crate::mem::dc_civac(p.cast_const(), 4);
    }

    /// The pass's parameter buffer as the firmware keeps it (spec:
    /// parameter-buffer.md, "The firmware's registry"): its ID, then info
    /// +0x00 (3D completions), +0x10 (TA completions), +0x14 (TAs in
    /// flight), +0x18 (the post-recovery gate) and the host's 3D count.
    pub(super) fn pb_counts(&self) -> (u32, [u32; 5]) {
        let pb = &self._pb;
        crate::mem::dc_civac(pb.info.raw_ptr().cast_const(), 0x20);
        crate::mem::dc_civac(pb.counter.raw_ptr().cast_const(), 4);
        // SAFETY: in-bounds u32 reads of the buffer's own info and counter.
        let c = unsafe {
            let i = pb.info.raw_ptr() as *const u32;
            [
                i.read_volatile(),
                i.add(4).read_volatile(),
                i.add(5).read_volatile(),
                i.add(6).read_volatile(),
                (pb.counter.raw_ptr() as *const u32).read_volatile(),
            ]
        };
        (pb.id, c)
    }
}

/// The rings of the queue ([`fw::g15::QUEUE`]): the TA's (class 0) and the 3D's (class 1).
pub(super) const TA_RING: usize = fw::g15::ring(0);
pub(super) const D3_RING: usize = fw::g15::ring(1);

#[versions(AGX)]
impl GpuManager::ver {
    /// The notifier of one job (as the CL one): +0x00 -> the u32 count of
    /// its kicks (at +0xC0), +0x08 the key, +0x10 the flush threshold,
    /// +0xA8 no stale cutoff.
    pub(super) fn g15_notifier_new(&self, key: u32, kicks: u32) -> Result<fw::types::GpuArray<u8>> {
        let n = self
            .alloc
            .lock()
            .fw_nc
            .array_empty_tagged::<u8>(0x100, b"NTFY")?;
        let f = W(n.raw_ptr());
        // SAFETY: in-bounds stores into the fresh 0x100 B notifier.
        unsafe {
            f.u32(0xC0, kicks);
            f.u64(0, va(&n) + 0xC0);
            f.u32(0x08, key);
            f.u32(0x0C, 0);
            f.u32(0x10, 80);
            f.u32(0x94, 0);
            f.u64(0xA8, u64::MAX);
        }
        // The firmware reads the notifier uncached.
        crate::mem::dc_civac(n.raw_ptr().cast_const(), 0x100);
        Ok(n)
    }

    /// G15: stage `job` on `ch`: its records into the channel's record slots
    /// (the PMRebuild record first) and one ring entry at the ring's cursor in
    /// `rings` (the locked `g15_rings`), whose command ID is the slot cursor
    /// after them, stored and cleaned to memory. Returns the ring's next write
    /// index; `g15_rd_publish` shows it to the firmware, under the same lock.
    /// The caller has found room for it (`g15_ring_room`): a pass checks both
    /// rings before it writes either, so it never leaves half a pass behind.
    pub(super) fn g15_rd_stage(
        &self,
        rings: &mut [u32; fw::g15::RINGS],
        ch: &mut G15ClChannel,
        job: &G15RdJob,
        ring: usize,
        class: u32,
    ) -> u32 {
        let mut slot = ch.submitted_records;
        let records = [job.pre.as_ref().map(va), Some(va(&job.job_state))];
        for r in records.iter().flatten() {
            // SAFETY: an in-bounds 8 B store into the 256 record slots.
            unsafe { W(ch.chan_cached.raw_ptr()).u64((slot % 256) as usize * 8, *r) };
            slot += 1;
        }
        ch.submitted_records = slot;
        ch.submitted += 1;
        core::sync::atomic::fence(Ordering::Release);
        job.uma.count_submit();
        let idx = rings[ring];
        rings[ring] = (idx + 1) % 256;
        let base = self.initdata.ring_area.raw_ptr();
        // SAFETY: the ring entry (slot idx % 256 of the 0x1800 storage) is in
        // bounds of the 128 KiB ring region.
        unsafe {
            let e = W(base.add(ring * fw::g15::RING_STRIDE + 8 + (idx % 256) as usize * 24));
            e.u64(0x00, 0);
            e.u64(0x08, va(&ch.state));
            e.u32(0x10, class);
            e.0.add(0x14)
                .cast::<u16>()
                .write_unaligned((slot % 256) as u16);
            e.0.add(0x16).write_volatile(ch.stamp_index as u8);
            e.0.add(0x17).write_volatile(1);
            crate::mem::dc_civac(e.0, 24);
        }
        (idx + 1) % 256
    }

    /// G15: show the staged entries to the firmware: the write indices, stored
    /// together and cleaned together. The consumer reads an entry before its
    /// fields are visible (NULL state, sub_68BC +0x45C; a skipped entry) if the
    /// index comes first, and `dmb ish` does not order the stores for its core,
    /// so the entries are cleaned first and the indices follow `G15_PUBLISH_GAP_US`
    /// later. The 3D entry of a pass goes before its TA entry and waits for the
    /// TA's stamp: a consumer pass that takes it with the TA entry still unseen
    /// stops there (boot #451: both rings unconsumed behind it for good), so the
    /// two indices change within a few tens of ns.
    pub(super) fn g15_rd_publish(&self, rings: &[(usize, u32)]) {
        kernel::time::delay::udelay(kernel::time::Delta::from_micros(super::G15_PUBLISH_GAP_US));
        let base = self.initdata.ring_area.raw_ptr();
        let mut words = [core::ptr::null::<u8>(); 2];
        for (i, (ring, next)) in rings.iter().enumerate() {
            let w = base.wrapping_add(ring * fw::g15::RING_STRIDE);
            // SAFETY: the write index word is in bounds of the 128 KiB ring region.
            unsafe { w.cast::<u32>().write_volatile(*next) };
            words[i] = w.cast_const();
        }
        crate::mem::dc_civac_each(&words[..rings.len()]);
    }

    /// G15: publish `job` on `ch` and ring: its entry (`g15_rd_stage`), the
    /// ring's write index, and with `doorbell` the doorbell message (`q << 2 | class`).
    pub(super) fn g15_rd_submit(
        &self,
        ch: &mut G15ClChannel,
        job: &G15RdJob,
        ring: usize,
        class: u32,
        doorbell: bool,
    ) -> Result {
        let mut rings = self.g15.rings.lock();
        self.g15_ring_room(ring, rings[ring], ch, ch.submitted_records, job.records())?;
        let next = self.g15_rd_stage(&mut rings, ch, job, ring, class);
        self.g15_rd_publish(&[(ring, next)]);
        drop(rings);
        if doorbell {
            self.g15_send(
                EP_DOORBELL,
                MSG_TX_DOORBELL | fw::g15::bell(u64::from(class)),
            )?;
        }
        Ok(())
    }

    /// G15: a render pass on `pb`: the 3D job's entry and the TA job's, the
    /// buffer's 3D count, then both indices together and the TA's doorbell.
    pub(super) fn g15_rd_submit_pass(
        &self,
        pb: &G15PbState,
        d3: &mut G15ClChannel,
        dj: &G15RdJob,
        ta: &mut G15ClChannel,
        tj: &G15RdJob,
    ) -> Result {
        let mut rings = self.g15.rings.lock();
        // Room for both first: a 3D entry staged without its TA would go out
        // with the next pass and wait for good.
        self.g15_ring_room(
            D3_RING,
            rings[D3_RING],
            d3,
            d3.submitted_records,
            dj.records(),
        )?;
        self.g15_ring_room(
            TA_RING,
            rings[TA_RING],
            ta,
            ta.submitted_records,
            tj.records(),
        )?;
        let n3 = self.g15_rd_stage(&mut rings, d3, dj, D3_RING, 1);
        let nt = self.g15_rd_stage(&mut rings, ta, tj, TA_RING, 0);
        pb.count_3d();
        self.g15_rd_publish(&[(D3_RING, n3), (TA_RING, nt)]);
        drop(rings);
        self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(0))
    }

    /// The stamp words of `ch`: (host, firmware).
    pub(super) fn g15_rd_words(ch: &G15ClChannel) -> (u32, u32) {
        crate::mem::dc_civac(ch.words.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds u32 reads of the channel's own stamp words.
        unsafe {
            let w = ch.words.raw_ptr() as *const u32;
            (w.read_volatile(), w.add(1).read_volatile())
        }
    }

    /// Wait for `stamp` on `ch` (either stamp word), re-ringing `class`
    /// every 500 ms. Returns the milliseconds waited, or None on a timeout.
    pub(super) fn g15_rd_wait(
        &self,
        name: &str,
        ch: &G15ClChannel,
        stamp: u32,
        class: u32,
    ) -> Option<u32> {
        const WAIT_MS: u32 = 3000;
        const RING_MS: u32 = 500;
        let dev = self.dev.as_ref();
        let reached = |ch: &G15ClChannel| {
            let (h, f) = Self::g15_rd_words(ch);
            h.wrapping_sub(stamp) as i32 >= 0 || f.wrapping_sub(stamp) as i32 >= 0
        };
        let mut waited = 0;
        while waited < WAIT_MS && !reached(ch) {
            kernel::time::delay::fsleep(Delta::from_millis(1));
            waited += 1;
            if waited % RING_MS == 0 {
                let _ = self.g15_send(
                    EP_DOORBELL,
                    MSG_TX_DOORBELL | fw::g15::bell(u64::from(class)),
                );
            }
        }
        let (h, f) = Self::g15_rd_words(ch);
        if reached(ch) {
            dev_info!(dev, "G15 render self-test: {name} COMPLETED after ~{waited} ms (stamp {stamp:#x}: host {h:#x}, fw {f:#x})\n");
            Some(waited)
        } else {
            dev_err!(dev, "G15 render self-test: {name} TIMEOUT after {waited} ms (stamp {stamp:#x}: host {h:#x}, fw {f:#x})\n");
            None
        }
    }

    /// G15: one pass submitted as the kext does (the 3D behind a type-4
    /// barrier, no doorbell; then the TA, rung), waited for.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn g15_rd_linked(
        &self,
        name: &str,
        ta: &mut G15ClChannel,
        d3: &mut G15ClChannel,
        pb: &G15Pb,
        rt: &G15Rt,
        ctx: u32,
        id: u32,
        scene: usize,
        cmd: &G15RdCmd,
        jobs: &mut KVec<G15RdJob>,
        notifiers: &mut KVec<fw::types::GpuArray<u8>>,
    ) -> Result<bool> {
        let key = 0x20 + scene as u32 + 3;
        let ntf = self.g15_notifier_new(key, 2)?;
        let (ta_stamp, d3_stamp) = ((ta.submitted + 1) << 8, (d3.submitted + 1) << 8);
        let tl = G15RdLink {
            ntf: Some(va(&ntf)),
            other_index: d3.stamp_index,
            other_stamp: d3_stamp,
            other_word: 0,
        };
        let dl = G15RdLink {
            ntf: Some(va(&ntf)),
            other_index: ta.stamp_index,
            other_stamp: ta_stamp,
            other_word: va(&ta.words) + 4,
        };
        let dj = self.g15_3d_job_new(d3, pb, rt, ctx, id, key, scene, dl, cmd)?;
        let tj = self.g15_ta_job_new(ta, pb, rt, ctx, id + 1, key, scene, tl, false, cmd)?;
        let pbt = &self.initdata.pb_table;
        pbt.with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
        let r = self.g15_rd_submit_pass(pb, d3, &dj, ta, &tj);
        if let Err(e) = r {
            dev_err!(
                self.dev.as_ref(),
                "G15 render self-test: {name} submit failed ({e:?})\n"
            );
        }
        let mut tname = KVec::new();
        let mut dname = KVec::new();
        for (v, sfx) in [(&mut tname, " TA"), (&mut dname, " 3D")] {
            v.extend_from_slice(name.as_bytes(), GFP_KERNEL)?;
            v.extend_from_slice(sfx.as_bytes(), GFP_KERNEL)?;
        }
        let ok = self
            .g15_rd_wait(
                core::str::from_utf8(&tname).unwrap_or("TA"),
                ta,
                tj.stamp,
                0,
            )
            .is_some()
            & self
                .g15_rd_wait(
                    core::str::from_utf8(&dname).unwrap_or("3D"),
                    d3,
                    dj.stamp,
                    1,
                )
                .is_some();
        pbt.with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
        g15_fwdump(6);
        jobs.push(tj, GFP_KERNEL)?;
        jobs.push(dj, GFP_KERNEL)?;
        notifiers.push(ntf, GFP_KERNEL)?;
        Ok(ok)
    }

    /// G15: a render queue's TA and 3D channels. They share one notifier
    /// list: the kext hands both the same `channel+0xA8`
    /// (`AGXCommandQueue::allocate3DWorkQueue`, `AGX3DWorkQueue::allocTAChannel`),
    /// so a pass's notifier, which the TA's kick inserts, is walked by the
    /// 3D's post-processing too. With a list each, a TA that is
    /// post-processed before its 3D leaves the notifier unflushed (the 3D
    /// walks an empty list): the firmware's stamp moves, the host's never
    /// does and no completion event comes (renders of over a thousand tiles).
    pub(super) fn g15_rd_chans_new(&self) -> Result<(G15ClChannel, G15ClChannel)> {
        let ta = self.g15_cl_channel_new()?;
        let d3 = self.g15_cl_channel_new()?;
        // SAFETY: the 3D state's +0x10 is one in-bounds u64 of its own
        // state block (the notifier-list header's GPUVA).
        unsafe {
            d3.state
                .raw_ptr()
                .add(0x10)
                .cast::<u64>()
                .write_volatile(ta.chan_list.gpu_va().get());
        }
        Ok((ta, d3))
    }

    /// G15: a queue's render state: a free TA/3D channel pair (else a new
    /// one), a parameter-buffer ID and the buffer, its blocks from
    /// `ualloc` (the queue's VM: its kernel range must reach into
    /// [64 GiB, 576 GiB)).
    pub(crate) fn g15_rd_queue_new(
        &self,
        ualloc: &Arc<Mutex<alloc::DefaultAllocator>>,
    ) -> Result<G15RdQueue> {
        let id = {
            let mut ids = self.g15.pb_ids.lock();
            let free = !*ids;
            if free == 0 {
                return Err(EBUSY);
            }
            let i = free.trailing_zeros();
            *ids |= 1u64 << i;
            i
        };
        // On an error the buffer (or the bare ID) returns the ID.
        let pb = match self.g15_pb_new(&mut ualloc.lock(), id, Some(self.g15.pb_ids.clone())) {
            Ok(pb) => pb,
            Err(e) => {
                *self.g15.pb_ids.lock() &= !(1u64 << id);
                return Err(e);
            }
        };
        let (ta, d3) = match self.g15.free_rd_chans.lock().pop() {
            Some(pair) => pair,
            None => {
                let (ta, d3) = self.g15_rd_chans_new()?;
                (
                    Arc::pin_init(new_mutex!(ta, "g15_ta_chan"), GFP_KERNEL)?,
                    Arc::pin_init(new_mutex!(d3, "g15_3d_chan"), GFP_KERNEL)?,
                )
            }
        };
        Ok(G15RdQueue {
            ta,
            d3,
            pb: Arc::new(pb, GFP_KERNEL)?,
            passes: 0,
            rt: None,
        })
    }

    /// G15: a destroyed queue's channels go back for reuse, unless a job
    /// on either never finished (as `g15_cl_channel_put`). The parameter
    /// buffer goes with its last pass.
    pub(crate) fn g15_rd_queue_put(&self, q: &G15RdQueue) {
        let idle = |c: &Arc<Mutex<G15ClChannel>>| Self::g15_chan_idle(&c.lock());
        if idle(&q.ta) && idle(&q.d3) {
            if self
                .g15
                .free_rd_chans
                .lock()
                .push((q.ta.clone(), q.d3.clone()), GFP_KERNEL)
                .is_err()
            {
                dev_err!(
                    self.dev.as_ref(),
                    "G15: cannot keep a render channel pair\n"
                );
            }
        } else {
            dev_warn!(
                self.dev.as_ref(),
                "G15: render channels with an unfinished job are retired\n"
            );
            let mut dead = self.g15.dead_chans.lock();
            if dead.push(q.ta.clone(), GFP_KERNEL).is_err()
                || dead.push(q.d3.clone(), GFP_KERNEL).is_err()
            {
                dev_err!(self.dev.as_ref(), "G15: cannot keep a render channel\n");
            }
        }
    }

    /// G15: run one render pass of queue `q` in `vm`'s context: its 3D job
    /// first, behind a type-4 barrier on the TA's stamp and without a
    /// doorbell, then its TA job, rung (as `g15_rd_linked`); `done` runs
    /// once the 3D completed. The first TA job of the queue's parameter
    /// buffer carries the PMRebuild record.
    pub(crate) fn g15_rd_pass_run(
        &self,
        q: &mut G15RdQueue,
        vm: mmu::VmBind,
        cmd: &G15RdCmd,
        rt: G15Rt,
        done: KBox<dyn FnMut(Option<Error>) + Send>,
    ) -> Result {
        let ctx = vm.slot();
        let scene = (q.passes % PB_SCENES as u32) as usize;
        let first = q.passes == 0;
        let id = self.g15.rd_ids.fetch_add(2, Ordering::Relaxed);
        let key = 0x20 + scene as u32 + 3;
        let ntf = self.g15_notifier_new(key, 2)?;
        // A pass that meets a firmware stop is built again after the resume,
        // waited for without the channel locks (`g15_wait_resume`):
        // `g15_ring_room` returns `EAGAIN` before anything is staged.
        let pending = loop {
            let mut ta = q.ta.lock();
            let mut d3 = q.d3.lock();
            let (ta_stamp, d3_stamp) = ((ta.submitted + 1) << 8, (d3.submitted + 1) << 8);
            let tl = G15RdLink {
                ntf: Some(va(&ntf)),
                other_index: d3.stamp_index,
                other_stamp: d3_stamp,
                other_word: 0,
            };
            let dl = G15RdLink {
                ntf: Some(va(&ntf)),
                other_index: ta.stamp_index,
                other_stamp: ta_stamp,
                other_word: va(&ta.words) + 4,
            };
            let dj = self.g15_3d_job_new(&d3, &q.pb, &rt, ctx, id, key, scene, dl, cmd)?;
            let tj =
                self.g15_ta_job_new(&ta, &q.pb, &rt, ctx, id + 1, key, scene, tl, first, cmd)?;
            let pbt = &self.initdata.pb_table;
            pbt.with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
            let r = self.g15_rd_submit_pass(&q.pb, &mut d3, &dj, &mut ta, &tj);
            pbt.with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
            match r {
                Err(e) if e == EAGAIN => {
                    drop((ta, d3, dj, tj));
                    self.g15_wait_resume()?;
                    continue;
                }
                r => r?,
            }
            q.passes += 1;
            mod_dev_dbg!(
                self.dev,
                "G15: render pass {} rung (ctx {ctx}, TA stamp {:#x}, 3D stamp {:#x})\n",
                q.passes,
                tj.stamp,
                dj.stamp
            );
            let ta_stamp = tj.stamp;
            break G15ClPending {
                chan: q.d3.clone(),
                stamp: dj.stamp,
                n: d3.submitted,
                ctx,
                ta: Some((q.ta.clone(), ta_stamp)),
                _work: G15Work::Rd(KBox::new(
                    G15RdPass {
                        _ta: tj,
                        _d3: dj,
                        _ntf: ntf,
                        _rt: rt,
                        _pb: q.pb.clone(),
                        scene,
                    },
                    GFP_KERNEL,
                )?),
                _vm: vm,
                done,
                signaled: false,
                error: None,
                nudge: kernel::time::Instant::<kernel::time::Monotonic>::now(),
                nudges: 0,
                fw_at: None,
            };
        };
        self.g15.pending.lock().push(pending, GFP_KERNEL)?;
        self.g15_cl_retire();
        if let Some(kick) = self.g15.kick.lock().as_ref() {
            kick();
        }
        Ok(())
    }
}
