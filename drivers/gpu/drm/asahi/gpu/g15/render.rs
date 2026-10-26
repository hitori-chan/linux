// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 render passes.
//!
//! A render pass is a TA job on its queue's TA channel and a 3D job on its
//! 3D channel. Both are staged at once: the 3D job first, behind a stamp
//! barrier on the TA job, then the TA job, whose doorbell starts the pair.
//! The two jobs share one notifier, and the pass is complete when its 3D
//! job is.
//!
//! Spec: render-firmware.md, render-job.md.

use super::*;

/// A render queue's TA and 3D channels.
pub(crate) type G15RdChans = (Arc<Mutex<G15ClChannel>>, Arc<Mutex<G15ClChannel>>);

/// A render target's geometry (`AGXRenderTargetMemoryG15::halComputeGeometry`,
/// the G13 path's `TileInfo`): 32x32 pixel tiles of 32x32, 32x16 or 16x16
/// pixel utiles. A macrotile is `align(ceil(tiles / 4), 4)` tiles per axis.
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
    /// Utiles per macrotile along x and y, and their product.
    pub(super) upm_x: u32,
    pub(super) upm_y: u32,
    pub(super) n: u32,
    /// The utile config (`0x10008`, `0x10148`): utile width / 16 in bits
    /// 12 up, height / 16 in bits 14 up, log2 of the sample count.
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

    /// The region size: 5 bytes per utile of a macrotile, in words.
    pub(super) fn rgn_size(&self) -> u32 {
        (5 * self.n) >> 2
    }

    /// In `usize`, as `tpc_size`: a large layered target overflows `u32`
    /// (10 GiB at 16384x16384 with 2048 layers), and an overflow panics.
    pub(super) fn tilemap_size(&self) -> usize {
        0x50 * self.n as usize * self.layers as usize
    }

    /// The tail-pointer cache: 128 bytes per utile of each layer and
    /// cluster, the size macOS allocates (`halComputeGeometry`).
    pub(super) fn tpc_size(&self) -> usize {
        RT_CLUSTERS as usize * self.layers as usize * self.n as usize * 128
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

/// A render pass's inputs. Addresses are user VAs of the job's VM; None or 0
/// means none.
#[derive(Clone, Copy)]
pub(crate) struct G15RdCmd {
    pub(crate) geom: G15RdGeom,
    /// The VDM control stream (`0x1C880`), or None for a terminate-only one.
    pub(crate) vdm: Option<u64>,
    /// The background and end-of-tile programs (`0x15368`, `0x15370`,
    /// `0x15378`, `0x15380`): the binding, then the entry program's VA.
    pub(crate) bg: (u64, u64),
    pub(crate) eot: (u64, u64),
    /// The partial render's background (it reloads the tiles a partial
    /// render stored) and end-of-tile programs, in the same form. The
    /// firmware puts them in place of `bg` and `eot` only for partial
    /// renders.
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
    /// The ISP control word (`0x15020`): `0xC000`, with bit 18 for integer
    /// depth bias.
    pub(crate) isp_ctl: u64,
    pub(crate) merge_x: u32,
    pub(crate) merge_y: u32,
    /// The user timestamps of the TA and 3D halves (start, end): kernel VAs
    /// of slots in the client's timestamp buffers, 0 for none.
    pub(crate) ts_ta: (u64, u64),
    pub(crate) ts_3d: (u64, u64),
}

/// One job of a render pass, TA or 3D: its job state and stream, its own
/// notifier when it has no pass notifier, and the records published ahead
/// of it: a stamp barrier (a 3D job's on its TA job, a TA job's on the
/// queue's previous 3D job), a TA job's second on the queue's last compute
/// job, then a TA job's parameter-manager record
/// (PMRebuild or PMGrow).
pub(crate) struct G15RdJob {
    pub(crate) job_state: fw::types::GpuArray<u8>,
    pub(super) _stream: fw::types::GpuArray<u8>,
    pub(super) _notifier: Option<fw::types::GpuArray<u8>>,
    pub(crate) wait: Option<fw::types::GpuArray<u8>>,
    pub(crate) after: Option<fw::types::GpuArray<u8>>,
    pub(crate) pre: Option<fw::types::GpuArray<u8>>,
    pub(crate) stamp: u32,
    /// The UMA pool the job registers.
    pub(super) uma: Arc<crate::gpu::G15Uma>,
}

impl G15RdJob {
    /// The record slots the job takes: its job state, and the records ahead.
    pub(super) fn records(&self) -> u32 {
        1 + u32::from(self.wait.is_some())
            + u32::from(self.after.is_some())
            + u32::from(self.pre.is_some())
    }
}

/// The link of a pass's TA and 3D jobs: the notifier they share, the other
/// job's stamp, and what the job's stamp barrier waits for.
#[derive(Clone, Copy)]
pub(super) struct G15RdLink {
    /// The pass notifier's VA, or None for a notifier per job.
    pub(super) ntf: Option<u64>,
    /// The other job's stamp index and stamp.
    pub(super) other_index: u32,
    pub(super) other_stamp: u32,
    /// The firmware stamp word, stamp index and stamp a stamp barrier ahead
    /// of the job waits for, or a word of 0 for no barrier: for a 3D job its
    /// TA job, for a TA job the queue's previous 3D job.
    pub(super) wait_word: u64,
    pub(super) wait_index: u32,
    pub(super) wait_stamp: u32,
}

/// What a render queue runs its passes on: a TA and 3D channel pair and a
/// parameter buffer in the queue's VM. Stamp indices and buffer IDs are few
/// (127 and 63), so an idle queue gives them up (`g15_rd_steal`) and takes a
/// set again at its next pass, as macOS moves an idle stamp index to another
/// channel and binds a buffer ID per TA job.
pub(crate) struct G15RdRes {
    pub(super) ta: Arc<Mutex<G15ClChannel>>,
    pub(super) d3: Arc<Mutex<G15ClChannel>>,
    pub(super) pb: Arc<G15Pb>,
}

/// A queue's render state: its channels and parameter buffer while it has
/// them, and the number of passes run on that buffer.
pub(crate) struct G15RdQueue {
    /// The queue's render pool, which its TA and 3D jobs register; None
    /// for the device's TA and 3D pools.
    pub(super) uma: Option<Arc<G15Uma>>,
    pub(super) res: Option<G15RdRes>,
    pub(super) passes: u32,
    /// The VM's allocator, which parameter buffers come from.
    pub(super) valloc: Arc<Mutex<alloc::DefaultAllocator>>,
    /// The allocator the parameter buffer grows from; None once growing
    /// failed.
    pub(super) ualloc: Option<Arc<Mutex<alloc::DefaultAllocator>>>,
    /// When the queue last took its resources or ran a pass: a queue used
    /// within `G15_RD_STEAL_MS` keeps them.
    pub(super) used: Instant<Monotonic>,
    /// When the buffer's statistics were last read (`g15_pb_grow`).
    pub(super) checked: Option<Instant<Monotonic>>,
    /// The buffer grew since the last TA job: the next carries PMGrow.
    pub(super) grown: bool,
    /// The TA-only render-target buffers of the queue's passes.
    pub(super) rt: Option<Arc<G15RtShared>>,
    /// The host stop the queue's parameter buffer was last started after
    /// (`G15State::reset_gen`).
    pub(super) gen: u32,
    /// The process that made the queue: its channels' owner. A queue takes
    /// them from a worker, whose pid is not the submitter's.
    owner: u32,
    /// The queue is destroyed (`g15_rd_queue_put`): a pass that runs after
    /// its teardown timed out takes no channels, which nothing would give
    /// back or steal.
    dead: bool,
}

/// How long a render queue keeps its resources after it last used them, its
/// passes done or not: no queue loses them between taking them and running
/// its next pass.
const G15_RD_STEAL_MS: i64 = 100;

impl G15RdQueue {
    /// The 3D channel, if the queue has one: a pass is complete when its 3D
    /// job is.
    pub(crate) fn d3(&self) -> Option<&Arc<Mutex<G15ClChannel>>> {
        self.res.as_ref().map(|r| &r.d3)
    }

    /// The queue's TA-only render-target buffers, for `g15_rt_new`.
    pub(crate) fn rt_cache(&mut self) -> &mut Option<Arc<G15RtShared>> {
        &mut self.rt
    }
}

/// A submitted render pass's buffers, kept until its 3D job retires.
pub(crate) struct G15RdPass {
    pub(super) _ta: G15RdJob,
    pub(super) _d3: G15RdJob,
    pub(super) _ntf: fw::types::GpuArray<u8>,
    pub(super) _rt: G15Rt,
    pub(super) _pb: Arc<G15Pb>,
    /// The pass's scene record index in its parameter buffer.
    pub(super) scene: usize,
    /// The target's geometry, for the recovery dump.
    pub(super) geom: G15RdGeom,
}

impl G15RdPass {
    /// The pass's notifier, shared by its TA and 3D jobs.
    pub(super) fn notifier(&self) -> &fw::types::GpuArray<u8> {
        &self._ntf
    }

    /// Marks the pass's scene aborted, as the firmware's post-recovery walk
    /// (`AGFA_IRQPostRecovery`) does for each TA job left in its channel
    /// table and in an active slot, which it marks done without running it;
    /// a host stop skips the walk. The 3D job then skips the scene and still
    /// counts as run; a TA job that kicks again clears the mark and runs as
    /// usual. Otherwise the 3D job of a TA job that never ran reads a
    /// tilemap nothing wrote and faults.
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

    /// The GPU VA range of the pass's parameter buffer's first blocks (the
    /// grown ones are not included: their list is behind a sleeping lock).
    pub(super) fn pb_blocks(&self) -> (u64, u64) {
        let b = self._pb.blocks.gpu_va().get();
        (b, b + self._pb.blocks.len() as u64)
    }

    /// The pass's parameter buffer's lists (`G15PbState::lists`).
    pub(super) fn pb_lists(&self, ring: [u32; 2]) -> [u32; 6] {
        self._pb.lists(ring)
    }

    /// The pass's parameter-buffer counters, for diagnostics: the buffer's
    /// ID, then the firmware's 3D completions, TA completions, TA jobs in
    /// flight and post-recovery gate, and the host's 3D count.
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

/// The command rings of render jobs: the TA's (class 0) and the 3D's (class
/// 1), on queue [`fw::g15::QUEUE`].
pub(super) const TA_RING: usize = fw::g15::ring(0);
pub(super) const D3_RING: usize = fw::g15::ring(1);

#[versions(AGX)]
impl GpuManager::ver {
    /// A type-4 stamp barrier record (`setupBarrierCommand`, 0x40 bytes) for
    /// the job with stamp `stamp` and ID `id`, met when the firmware stamp
    /// word `link.wait_word` reaches `link.wait_stamp`; the job's channel
    /// parks until then. None when the link waits for nothing.
    pub(super) fn g15_stamp_barrier(
        &self,
        link: &G15RdLink,
        stamp: u32,
        id: u32,
    ) -> Result<Option<fw::types::GpuArray<u8>>> {
        if link.wait_word == 0 {
            return Ok(None);
        }
        let a = G15After {
            word: link.wait_word,
            index: link.wait_index,
            stamp: link.wait_stamp,
        };
        self.g15_barrier_rec(a, false, stamp, id).map(Some)
    }

    /// The stamp barrier record for the job with stamp `stamp` and ID `id`
    /// on `a`, tested on its channel's host stamp word when `host`, else on
    /// its firmware stamp word. It is in `fw_nc`, so the firmware keeps no
    /// line of it: a cached line of a freed record shadowed the zeros of the
    /// next channel's stamp table at its address.
    pub(super) fn g15_barrier_rec(
        &self,
        a: G15After,
        host: bool,
        stamp: u32,
        id: u32,
    ) -> Result<fw::types::GpuArray<u8>> {
        let b = self
            .alloc
            .lock()
            .fw_nc
            .array_empty_tagged::<u8>(0x40, b"BARR")?;
        let r = W(b.raw_ptr());
        // SAFETY: in-bounds stores into the fresh 0x40-byte record.
        unsafe {
            r.u32(0x00, 4);
            // The host word is the firmware word's neighbour, 4 bytes below.
            r.u64(0x04, if host { a.word - 4 } else { a.word });
            r.u64(0x0C, a.word);
            r.u32(0x14, a.stamp);
            r.u32(0x18, a.index);
            r.u32(0x1C, stamp);
            r.u32(0x20, id & 0x7FFF_FFFF);
            r.u32(0x24, u32::from(host));
            r.u32(0x28, 0);
        }
        crate::mem::dc_civac(b.raw_ptr().cast_const(), 0x40);
        Ok(b)
    }

    /// Allocates a notifier for `kicks` kicks under `key`: a pointer to the
    /// kick count (kept at +0xC0), the key, the flush threshold and no
    /// stale cutoff.
    pub(super) fn g15_notifier_new(&self, key: u32, kicks: u32) -> Result<fw::types::GpuArray<u8>> {
        let n = self
            .alloc
            .lock()
            .fw_nc
            .array_empty_tagged::<u8>(0x100, b"NTFY")?;
        let f = W(n.raw_ptr());
        // SAFETY: in-bounds stores into the fresh 0x100-byte notifier.
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

    /// Stages `job` on `ch`: its records into the channel's record slots,
    /// the parameter-manager record first, and one entry at the ring's
    /// cursor in `rings` (the locked write indices), whose command ID is the
    /// slot cursor after them. Returns the ring's next write index, which
    /// `g15_rd_publish` shows to the firmware under the same lock.
    ///
    /// The caller has found room for the job with `g15_ring_room`. A pass
    /// checks both rings before it writes either, so that it never leaves
    /// half a pass behind.
    pub(super) fn g15_rd_stage(
        &self,
        rings: &mut [u32; fw::g15::RINGS],
        ch: &mut G15ClChannel,
        job: &G15RdJob,
        ring: usize,
        class: u32,
    ) -> u32 {
        let mut slot = ch.submitted_records;
        let records = [
            job.wait.as_ref().map(va),
            job.after.as_ref().map(va),
            job.pre.as_ref().map(va),
            Some(va(&job.job_state)),
        ];
        for r in records.iter().flatten() {
            // SAFETY: an in-bounds u64 store into the 256 record slots.
            unsafe { W(ch.chan_cached.raw_ptr()).u64((slot % 256) as usize * 8, *r) };
            slot += 1;
        }
        ch.submitted_records = slot;
        ch.submitted += 1;
        // The firmware reads the job state, stream and records uncached.
        for a in [
            Some(&job.job_state),
            Some(&job._stream),
            job.wait.as_ref(),
            job.after.as_ref(),
            job.pre.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            crate::mem::dc_civac(a.raw_ptr().cast_const(), a.len());
        }
        core::sync::atomic::fence(Ordering::Release);
        job.uma.count_submit();
        let idx = rings[ring];
        rings[ring] = (idx + 1) % 256;
        let base = self.initdata.ring_area.raw_ptr();
        // SAFETY: the ring entry (slot idx % 256 of the ring's 0x1800 bytes)
        // is in bounds of the 128 KiB ring area.
        unsafe {
            let e = W(base.add(ring * fw::g15::RING_STRIDE + 8 + (idx % 256) as usize * 24));
            e.u64(0x00, self.g15.perf.fw_now());
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

    /// Shows the staged entries to the firmware by storing the rings' write
    /// indices together and cleaning them together.
    ///
    /// The entries are cleaned first and the indices follow, as the kext
    /// stores an index after a `dmb`. A pass's 3D entry, which waits for its
    /// TA job's stamp, goes before the TA entry: a consumer that takes the
    /// 3D entry with the TA entry still unseen stops there for good, so the
    /// two indices change within a few tens of nanoseconds.
    pub(super) fn g15_rd_publish(&self, rings: &[(usize, u32)]) {
        let base = self.initdata.ring_area.raw_ptr();
        let mut words = [core::ptr::null::<u8>(); 2];
        for (i, (ring, next)) in rings.iter().enumerate() {
            let w = base.wrapping_add(ring * fw::g15::RING_STRIDE);
            // SAFETY: the write index is in bounds of the 128 KiB ring area.
            unsafe { w.cast::<u32>().write_volatile(*next) };
            words[i] = w.cast_const();
        }
        crate::mem::dc_civac_each(&words[..rings.len()]);
    }

    /// Submits a render pass on `pb`: stages the 3D job's entry and the TA
    /// job's, counts the 3D job in the buffer, publishes both indices
    /// together and rings the TA class.
    pub(super) fn g15_rd_submit_pass(
        &self,
        pb: &G15PbState,
        d3: &mut G15ClChannel,
        dj: &G15RdJob,
        ta: &mut G15ClChannel,
        tj: &G15RdJob,
    ) -> Result {
        let mut rings = self.g15.rings.lock();
        // Room for both first: a 3D entry staged without its TA entry would
        // go out with the next pass and wait for good.
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

    /// Allocates a render queue's TA and 3D channels.
    ///
    /// They share one notifier list, as on macOS
    /// (`AGXCommandQueue::allocate3DWorkQueue`), so that the 3D job's
    /// post-processing walks the pass notifier the TA job's kick inserted.
    /// With a list each, a TA job post-processed before its 3D job leaves
    /// the notifier unflushed: the firmware stamp moves, the host stamp
    /// never does and no completion event comes.
    pub(super) fn g15_rd_chans_new(&self) -> Result<(G15ClChannel, G15ClChannel)> {
        let ta = self.g15_cl_channel_new(false)?;
        let mut d3 = self.g15_cl_channel_new(false)?;
        d3.list_va = ta.chan_list.gpu_va().get();
        // SAFETY: +0x10, the notifier-list header's VA, is an in-bounds u64
        // of the 3D channel's own state block.
        unsafe {
            d3.state
                .raw_ptr()
                .add(0x10)
                .cast::<u64>()
                .write_volatile(d3.list_va);
        }
        Ok((ta, d3))
    }

    /// Sets up a queue's render state, with no channels or parameter buffer
    /// yet: its first pass takes them (`g15_rd_res_get`). `ualloc` is the
    /// queue's VM allocator (its kernel range must reach into
    /// [64 GiB, 576 GiB)), `uma` the queue's render pool if it has one.
    pub(crate) fn g15_rd_queue_new(
        &self,
        ualloc: &Arc<Mutex<alloc::DefaultAllocator>>,
        uma: Option<Arc<G15Uma>>,
    ) -> G15RdQueue {
        G15RdQueue {
            uma,
            res: None,
            passes: 0,
            valloc: ualloc.clone(),
            ualloc: Some(ualloc.clone()),
            used: Instant::<Monotonic>::now(),
            checked: None,
            grown: false,
            rt: None,
            gen: self.g15.reset_gen.load(Ordering::Relaxed),
            owner: kernel::current!().group_leader().pid() as u32,
            dead: false,
        }
    }

    /// Adds a new queue's render state to the live ones.
    pub(crate) fn g15_rd_queue_add(&self, rd: &Arc<Mutex<G15RdQueue>>) -> Result {
        self.g15.rd_live.lock().push(rd.clone(), GFP_KERNEL)?;
        Ok(())
    }

    /// Keeps an idle channel pair for reuse. A pair is never freed: the
    /// firmware's job table holds each channel's job-slot object.
    pub(super) fn g15_rd_chans_keep(&self, pair: G15RdChans) {
        let mut pool = self.g15.free_rd_chans.lock();
        if pool.reserve(1, GFP_KERNEL).is_err() {
            dev_err!(
                self.dev.as_ref(),
                "G15: cannot keep a render channel pair\n"
            );
            core::mem::forget(pair);
            return;
        }
        let _ = pool.push(pair, GFP_KERNEL);
    }

    /// Takes the channel pair of a live queue that has not used it for
    /// `G15_RD_STEAL_MS` and whose jobs have all retired and completed (as
    /// their fences saw it: the queue's next compute command after a render
    /// one waits for nothing once the pair has gone); that queue takes
    /// a set again at its next pass. Its parameter buffer goes, and the
    /// buffer's ID with the last pass that holds it. The caller's own queue,
    /// which it has locked, is passed over.
    pub(super) fn g15_rd_steal(&self) -> Option<G15RdChans> {
        let res = {
            let live = self.g15.rd_live.lock();
            let mut res = None;
            for rd in live.iter() {
                let Some(mut q) = rd.try_lock() else {
                    continue;
                };
                let Some(r) = q.res.as_ref() else {
                    continue;
                };
                if q.used.elapsed() < Delta::from_millis(G15_RD_STEAL_MS)
                    || !Self::g15_chan_idle(&r.ta.lock())
                    || !{
                        let d3 = r.d3.lock();
                        Self::g15_chan_idle(&d3) && self.g15_chan_done(&d3)
                    }
                {
                    continue;
                }
                self.g15_pb_unregister(&q);
                res = q.res.take();
                break;
            }
            res
        };
        // The buffer is dropped with no lock held.
        res.map(|r| (r.ta, r.d3))
    }

    /// A parameter buffer ID (1..63), or `EBUSY`.
    fn g15_pb_id_take(&self) -> Result<u32> {
        let mut ids = self.g15.pb_ids.lock();
        let free = !*ids;
        if free == 0 {
            return Err(EBUSY);
        }
        let i = free.trailing_zeros();
        *ids |= 1u64 << i;
        Ok(i)
    }

    /// Gives queue `q` a channel pair and a parameter buffer if it has none:
    /// a destroyed queue's pair or a new one, else an idle queue's
    /// (`g15_rd_steal`), and a buffer with a free ID, its blocks from the
    /// queue's VM. `EBUSY` while every set is in use: the pass waits for one
    /// (`G15Run::ready`). `ECANCELED` once the queue is destroyed.
    pub(crate) fn g15_rd_res_get(&self, q: &mut G15RdQueue) -> Result {
        q.used = Instant::<Monotonic>::now();
        if q.res.is_some() {
            return Ok(());
        }
        if q.dead {
            return Err(ECANCELED);
        }
        // Popped with the pool's lock dropped at once: channel creation
        // takes it when the stamp indices run out.
        let pooled = self.g15.free_rd_chans.lock().pop();
        let pair = match pooled {
            Some(p) => Some(p),
            None => match self.g15_rd_chans_new() {
                Ok((ta, d3)) => Some((
                    Arc::pin_init(new_mutex!(ta, "g15_ta_chan"), GFP_KERNEL)?,
                    Arc::pin_init(new_mutex!(d3, "g15_3d_chan"), GFP_KERNEL)?,
                )),
                Err(e) if e == EBUSY => None,
                Err(e) => return Err(e),
            },
        };
        let (ta, d3) = match pair {
            Some(p) => p,
            None => self.g15_rd_steal().ok_or_else(|| {
                self.g15_rd_busy("127 stamp indices");
                EBUSY
            })?,
        };
        // With every ID taken, an idle queue's buffer goes; its ID is free
        // once the last pass holding it has retired.
        let id = match self.g15_pb_id_take() {
            Ok(id) => Ok(id),
            Err(_) => {
                if let Some(p) = self.g15_rd_steal() {
                    self.g15_rd_chans_keep(p);
                }
                self.g15_pb_id_take()
            }
        };
        // g15_pb_new leaves the ID taken on an error.
        let pb = id.and_then(|id| {
            self.g15_pb_new(&q.valloc, id, Some(self.g15.pb_ids.clone()))
                .inspect_err(|_| *self.g15.pb_ids.lock() &= !(1u64 << id))
        });
        let pb = match pb.and_then(|pb| Ok(Arc::new(pb, GFP_KERNEL)?)) {
            Ok(pb) => pb,
            Err(e) => {
                if e == EBUSY {
                    self.g15_rd_busy("63 parameter buffer IDs");
                }
                self.g15_rd_chans_keep((ta, d3));
                return Err(e);
            }
        };
        Self::g15_chan_owner(&ta.lock(), q.owner);
        Self::g15_chan_owner(&d3.lock(), q.owner);
        q.res = Some(G15RdRes { ta, d3, pb });
        q.passes = 0;
        q.ualloc = Some(q.valloc.clone());
        q.checked = None;
        q.grown = false;
        Ok(())
    }

    /// Notes, once, that render passes wait for `what`, all in use.
    fn g15_rd_busy(&self, what: &str) {
        static WARNED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        if !WARNED.swap(true, Ordering::Relaxed) {
            dev_warn!(
                self.dev.as_ref(),
                "G15: render passes wait for one of the {what}, all in use\n"
            );
        }
    }

    /// Takes a destroyed queue's render state off the live ones and returns
    /// its channels for reuse, unless a job on either never finished, as
    /// `g15_cl_channel_put` does. The parameter buffer goes with the queue's
    /// last pass.
    pub(crate) fn g15_rd_queue_put(&self, rd: &Arc<Mutex<G15RdQueue>>) {
        {
            let mut live = self.g15.rd_live.lock();
            if let Some(i) = live.iter().position(|q| Arc::ptr_eq(q, rd)) {
                live.swap_remove(i);
            }
        }
        let mut q = rd.lock();
        q.dead = true;
        self.g15_pb_unregister(&q);
        let Some(G15RdRes { ta, d3, .. }) = q.res.take() else {
            return;
        };
        let idle = |c: &Arc<Mutex<G15ClChannel>>| Self::g15_chan_idle(&c.lock());
        if idle(&ta) && idle(&d3) {
            drop(q);
            self.g15_chans_retire(G15Dead::Rd((ta, d3)));
        } else {
            dev_warn!(
                self.dev.as_ref(),
                "G15: render channels with an unfinished job are retired\n"
            );
            self.g15_dead_keep(G15Dead::Rd((ta, d3)));
        }
    }

    /// Runs one render pass of queue `q` in `vm`'s context. `done` runs
    /// once its 3D job is complete. The first TA job on the queue's
    /// parameter buffer carries the PMRebuild record, and so does the first
    /// after a host stop; the first after the buffer grew carries PMGrow.
    ///
    /// The TA job waits for the queue's previous 3D job, as the kext's does
    /// (`AGXTACommandDescriptor::prepare`), so that a parameter buffer has
    /// one TA job in flight at most. With none, Firefox's passes put 19 to 21
    /// TA jobs in flight on one buffer, and they stopped finishing. It also
    /// waits for `after`, the queue's last compute job, on a second barrier.
    pub(crate) fn g15_rd_pass_run(
        &self,
        q: &mut G15RdQueue,
        vm: mmu::VmBind,
        cmd: &G15RdCmd,
        rt: G15Rt,
        after: Option<G15After>,
        done: KBox<dyn FnMut(Option<Error>) + Send>,
    ) -> Result {
        let ctx = vm.slot();
        self.g15_rd_res_get(q)?;
        let (tac, d3c, pb) = match q.res.as_ref() {
            Some(r) => (r.ta.clone(), r.d3.clone(), r.pb.clone()),
            None => return Err(EIO),
        };
        let id = self.g15.rd_ids.fetch_add(2, Ordering::Relaxed);
        if q.passes == 0 {
            self.g15_pb_register(q);
        }
        // Before the channels are locked: the blocks come from the VM's
        // allocator. A buffer that cannot grow keeps the blocks it has.
        if let Err(e) = self.g15_pb_grow(q) {
            dev_warn!(
                self.dev.as_ref(),
                "G15: parameter buffer {} cannot grow: {e:?}\n",
                pb.id
            );
            q.ualloc = None;
            self.g15_pb_register(q);
        }
        // A pass that meets a firmware stop is built again after the resume,
        // which is waited for without the channel locks: `g15_ring_room`
        // returns `EAGAIN` before anything is staged.
        let pending = loop {
            // The firmware's rebuild at a host stop forgot the parameter
            // buffer: it starts again from a PMRebuild record.
            let gen = self.g15.reset_gen.load(Ordering::Relaxed);
            if q.gen != gen {
                q.passes = 0;
                q.gen = gen;
            }
            // A set with no pass in flight at the last recovery, which
            // cleared the others.
            rt.clear_ta_state(self.g15.rt_gen.load(Ordering::Relaxed));
            let scene = (q.passes % PB_SCENES as u32) as usize;
            let pm = if q.passes == 0 {
                G15Pm::Rebuild
            } else if q.grown {
                G15Pm::Grow
            } else {
                G15Pm::None
            };
            let key = self.g15.ntf_keys.fetch_add(1, Ordering::Relaxed);
            let ntf = self.g15_notifier_new(key, 2)?;
            self.g15_wait_stamp_room(&[&tac, &d3c])?;
            let mut ta = tac.lock();
            let mut d3 = d3c.lock();
            self.g15_chan_fresh(&mut ta);
            self.g15_chan_fresh(&mut d3);
            let (ta_stamp, d3_stamp) = ((ta.submitted + 1) << 8, (d3.submitted + 1) << 8);
            let prev_3d = if self.g15_chan_done(&d3) {
                0
            } else {
                va(&d3.words) + 4
            };
            let tl = G15RdLink {
                ntf: Some(va(&ntf)),
                other_index: d3.stamp_index,
                other_stamp: d3_stamp,
                // The firmware word. The host word, which the firmware polls,
                // would make the TA wait for the 3D job's post-process: a
                // GPU-bound client loses 14 % (barrier-race.md).
                wait_word: prev_3d,
                wait_index: d3.stamp_index,
                wait_stamp: d3.submitted << 8,
            };
            let dl = G15RdLink {
                ntf: Some(va(&ntf)),
                other_index: ta.stamp_index,
                other_stamp: ta_stamp,
                wait_word: va(&ta.words) + 4,
                wait_index: ta.stamp_index,
                wait_stamp: ta_stamp,
            };
            let (tu, du) = match &q.uma {
                Some(u) => (u.clone(), u.clone()),
                None => (
                    self.g15_uma_get(G15UmaDm::Ta)?,
                    self.g15_uma_get(G15UmaDm::D3)?,
                ),
            };
            let dj = self.g15_3d_job_new(&d3, &pb, &rt, ctx, id, key, scene, dl, cmd, &du)?;
            let mut tj =
                self.g15_ta_job_new(&ta, &pb, &rt, ctx, id + 1, key, scene, tl, pm, cmd, &tu)?;
            tj.after = after
                .map(|a| self.g15_barrier_rec(a, true, ta_stamp, id + 1))
                .transpose()?;
            let pbt = &self.initdata.pb_table;
            pbt.with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
            let r = self.g15_rd_submit_pass(&pb, &mut d3, &dj, &mut ta, &tj);
            pbt.with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
            match r {
                Err(e) if e == EAGAIN => {
                    drop((ta, d3, dj, tj, ntf));
                    self.g15_wait_resume()?;
                    continue;
                }
                r => r?,
            }
            q.passes += 1;
            q.grown = false;
            mod_dev_dbg!(
                self.dev,
                "G15: render pass {} rung (ctx {ctx}, TA stamp {:#x}, 3D stamp {:#x})\n",
                q.passes,
                tj.stamp,
                dj.stamp
            );
            let ta_stamp = tj.stamp;
            break G15ClPending {
                chan: d3c.clone(),
                stamp: dj.stamp,
                n: d3.submitted,
                ctx,
                pid: Self::g15_chan_pid(&d3),
                ta: Some((tac.clone(), ta_stamp)),
                _work: G15Work::Rd(KBox::new(
                    G15RdPass {
                        _ta: tj,
                        _d3: dj,
                        _ntf: ntf,
                        _rt: rt,
                        _pb: pb.clone(),
                        scene,
                        geom: cmd.geom,
                    },
                    GFP_KERNEL,
                )?),
                _vm: vm,
                done,
                signaled: false,
                error: None,
                since: kernel::time::Instant::<kernel::time::Monotonic>::now(),
                fw_at: None,
                late: false,
            };
        };
        self.g15.pending.lock().push(pending, GFP_KERNEL)?;
        self.g15_cl_retire(G15Retirer::Submit);
        self.g15_kick(false);
        Ok(())
    }
}
