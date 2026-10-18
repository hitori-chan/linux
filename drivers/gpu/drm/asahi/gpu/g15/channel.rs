// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 channels: the per-queue firmware state and the command rings.

use super::*;

/// G15: one CL channel (the kext's `AGXChannel` for a CL queue; spec:
/// agx-g15c/cl-job.md, "Successive jobs on one channel"): the state
/// object and the buffers every job of the channel shares.
pub(crate) struct G15ClChannel {
    /// The 0x24C0 B state object (the kext's `_AGFIChannelState`,
    /// `AGXChannel::resetChannelState`): the ring entry's +0x08. The
    /// consumer/dispatcher/registration dereference it (cursors at
    /// +0x20/+0x28, priority stage +0x30, record slots +0x08, stamp table
    /// +0x18, job-slot object +0xA4, capacity +0x50).
    pub(crate) state: fw::types::GpuArray<u8>,
    /// The state's +0x00 target (uncached channel memory): +0x30 = the
    /// last command ID (firmware-written), +0x50 = the slot capacity.
    pub(crate) chan_uncached: fw::types::GpuArray<u8>,
    /// The state's +0x08 target: the 8 B record slots (slot\[i\] = job
    /// state GPUVA), 256 slots.
    pub(crate) chan_cached: fw::types::GpuArray<u8>,
    /// The state's +0x18 target: the 128 x 0x48 B stamp-entry table,
    /// zeroed once (registration rewrites table\[sequence\] per job).
    pub(crate) stamp_table: fw::types::GpuArray<u8>,
    /// The state's +0xA4 target: the 0x38 B job-slot object (fresh: +0x00
    /// = +0x01 = 0xFF; the firmware allocates on use).
    pub(crate) job_slot: fw::types::GpuArray<u8>,
    /// The stand-in for the channel's +0x1B0 buffer: the context record's
    /// +0x180…+0x198 group points into it, sized as `AGXCLChannel::init`
    /// does for t6034 (S = 0x3C000, T = 0x2000: A = base, B = A + S,
    /// C = A + 2S, D = C + T, `(2S + T) | 0x400` B).
    pub(crate) ctx_store: fw::types::GpuArray<u8>,
    /// The state's +0x10 target: the notifier-list header {0, P+0x10, 0,
    /// P+0x20, 0} (`sub_27D40`; every value a GPUVA, boot #62).
    pub(crate) chan_list: fw::types::GpuArray<u8>,
    /// The CDM preempt buffer (register 0x1A510), zeroed.
    pub(crate) preempt: fw::types::GpuArray<u8>,
    /// The channel's two stamp words: +0x00 the host stamp word
    /// (js+0x7E8; the notifier walk writes the stamp value there at a
    /// flush), +0x04 the firmware stamp word (js+0x7F0, the start record
    /// +0x28; the in-order retire writes it).
    pub(crate) words: fw::types::GpuArray<u8>,
    /// Jobs submitted so far: the next job submitted is number
    /// submitted + 1 (its stamp, IDs and record slot are written at submit
    /// time, so a job built but never run leaves no gap in the stamp
    /// sequence).
    pub(crate) submitted: u32,
    /// Records published so far (render channels: a job can carry a
    /// pre-record, so the record cursor runs ahead of the job count).
    pub(crate) submitted_records: u32,
    /// The channel's stamp index (the DAG slot: ring +0x16, js+0x7FC), one
    /// of 1..127 like the kext's `requestStampIndexForChannel` (0 left
    /// unused).
    pub(crate) stamp_index: u32,
    /// The allocator the index returns to when the channel goes.
    pub(super) stamp_ids: Option<Arc<Mutex<u128>>>,
}

impl Drop for G15ClChannel {
    fn drop(&mut self) {
        if let Some(ids) = self.stamp_ids.take() {
            *ids.lock() &= !(1u128 << self.stamp_index);
        }
    }
}

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: a fresh CL channel (the kext's `AGXChannel::resetChannelState`;
    /// spec: agx-g15c/submission.md, "The channel state object").
    pub(super) fn g15_cl_channel_new(&self) -> Result<G15ClChannel> {
        // A free stamp index (1..127).
        let stamp_index = {
            let mut ids = self.g15.stamp_ids.lock();
            let free = !*ids & !1u128;
            if free == 0 {
                return Err(EBUSY);
            }
            let i = free.trailing_zeros();
            *ids |= 1u128 << i;
            i
        };
        const SLOTS: u32 = 256; // the record slots' capacity
        let mut guard = self.alloc.lock();
        let preempt = guard.gpu.array_empty_tagged::<u8>(0x4000, b"PRMT")?;
        let words = guard.stamp.array_empty_tagged::<u8>(0x40, b"STWD")?;
        let chan_list = guard.fw_nc.array_empty_tagged::<u8>(0x40, b"NLST")?;
        let shared = &mut guard.shared;
        let ch = G15ClChannel {
            state: shared.array_empty_tagged::<u8>(0x24C0, b"STTE")?,
            chan_uncached: shared.array_empty_tagged::<u8>(0x100, b"UCMN")?,
            chan_cached: shared.array_empty_tagged::<u8>(SLOTS as usize * 8, b"CCMN")?,
            stamp_table: shared.array_empty_tagged::<u8>(128 * 0x48, b"STMP")?,
            job_slot: shared.array_empty_tagged::<u8>(0x40, b"JSLO")?,
            ctx_store: shared.array_empty_tagged::<u8>(0x7A400 + 0x400, b"CTXS")?,
            chan_list,
            words,
            preempt,
            submitted: 0,
            submitted_records: 0,
            stamp_index,
            stamp_ids: Some(self.g15.stamp_ids.clone()),
        };
        core::mem::drop(guard);

        let unc_va = ch.chan_uncached.gpu_va().get();
        let cached_va = ch.chan_cached.gpu_va().get();
        let stamp_va = ch.stamp_table.gpu_va().get();
        let job_slot_va = ch.job_slot.gpu_va().get();
        let chan_list_va = ch.chan_list.gpu_va().get();
        // SAFETY: each write is one in-bounds field of the channel's own
        // freshly allocated (zeroed) buffers.
        unsafe {
            let c = ch.state.raw_ptr();
            let q = |off: usize| c.add(off).cast::<u64>();
            q(0x00).write_volatile(unc_va); // -> uncached chan mem (capacity at +0x50)
            q(0x08).write_volatile(cached_va); // -> record slots
            q(0x10).write_volatile(chan_list_va); // -> notifier-list header
            q(0x18).write_volatile(stamp_va); // -> stamp table
            c.add(0x2C).cast::<u32>().write_volatile(0xFFFFFFFF); // fresh sentinel
                                                                  // The channel priority (AGXArmFirmware::setChannelPriority):
                                                                  // resetChannelState leaves +0x30 = 4, which no executor stage
                                                                  // runs. Priority 5 (and 0) is stage 0, mask 0xFFFFFFFFFFFF0000,
                                                                  // +0x40 = 1; a default foreground queue (priority 1, sub-level
                                                                  // 0) is stage 2, mask 0xFFFFFFFF00000000, +0x40 = 0. The
                                                                  // background tick preempts (a context store, trace event 0x35)
                                                                  // the slots of a queue that used more than its share, except at
                                                                  // stage 0, and the store of a TA job wrote to address 0 + 0x80 * k
                                                                  // (a `dIPP_CS` fault, boots #456-#459).
            c.add(0x30).cast::<u32>().write_volatile(0); // stage
            c.add(0x34).cast::<u32>().write_volatile(0);
            q(0x38).write_volatile(0xFFFF_FFFF_FFFF_0000); // mask (TA path only)
            c.add(0x40).cast::<u32>().write_volatile(1);
            c.add(0x44).cast::<u32>().write_volatile(0); // queue+0x838 (sub-queue)
            c.add(0x48).cast::<u32>().write_volatile(0); // pending row 0xD + this
            c.add(0x4C).cast::<u32>().write_volatile(0xFFFFFFFF);
            c.add(0x50).cast::<u32>().write_volatile(SLOTS); // slot capacity
            q(0xA4).write_volatile(job_slot_va); // -> job-slot object
            ch.chan_uncached
                .raw_ptr()
                .add(0x50)
                .cast::<u32>()
                .write_volatile(SLOTS);
            // The job-slot object: fresh (the firmware allocates on use).
            let p = ch.job_slot.raw_ptr();
            p.write_volatile(0xFF); // +0x00 no job-table slot
            p.add(1).write_volatile(0xFF); // +0x01 no job index
                                           // The notifier-list header, fresh: sub_27D40's walk reads
                                           // *(*(P[1]+8)), so P[1] = Q with *(Q+8) = R and *R = 0.
            let n = ch.chan_list.raw_ptr();
            n.cast::<u64>().write_volatile(0); // +0x00 P[0] head = fresh
            n.add(8).cast::<u64>().write_volatile(chan_list_va + 0x10); // +0x08 P[1] = Q
            n.add(16).cast::<u64>().write_volatile(0); // +0x10 unused
            n.add(24).cast::<u64>().write_volatile(chan_list_va + 0x20); // +0x18 P[3] = R
            n.add(32).cast::<u64>().write_volatile(0); // +0x20 *R = 0 (the walk stops)
        }
        // The firmware reads the header uncached.
        crate::mem::dc_civac(ch.chan_list.raw_ptr().cast_const(), 0x40);
        Ok(ch)
    }

    /// G15: a CL channel for a queue: a destroyed queue's, else a new one.
    pub(crate) fn g15_cl_channel_get(&self) -> Result<Arc<Mutex<G15ClChannel>>> {
        if let Some(ch) = self.g15.free_chans.lock().pop() {
            return Ok(ch);
        }
        let ch = self.g15_cl_channel_new()?;
        Arc::pin_init(new_mutex!(ch, "g15_chan"), GFP_KERNEL)
    }

    /// G15: whether the firmware retired every job submitted on `c`: its stamp
    /// word has reached the last job's stamp. The retire is the last thing it
    /// does for a job (after the completion event and the host stamp, which can
    /// stay behind for good, see `g15_cl_done`), and only then may the channel
    /// serve another queue or go (boot #441: `bigpp` after `pingpong`, which
    /// reused the pair at its host stamp: "Unknown SKU command type 24").
    pub(super) fn g15_chan_idle(c: &G15ClChannel) -> bool {
        crate::mem::dc_civac(c.words.raw_ptr().cast_const(), 8);
        // SAFETY: an in-bounds u32 read of the channel's own stamp words.
        let fwst = unsafe { (c.words.raw_ptr() as *const u32).add(1).read_volatile() };
        fwst.wrapping_sub(c.submitted << 8) as i32 >= 0
    }

    /// G15: free the retired channels whose last job has finished since
    /// (their stamp indices return to the pool).
    pub(super) fn g15_reclaim_dead(&self) {
        let mut freed = KVec::new();
        {
            let mut dead = self.g15.dead_chans.lock();
            let mut i = 0;
            while i < dead.len() {
                if Self::g15_chan_idle(&dead[i].lock()) {
                    if freed.push(dead.swap_remove(i), GFP_ATOMIC).is_err() {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        }
        core::mem::drop(freed);
    }

    /// G15: a destroyed queue's CL channel goes back for reuse — unless a
    /// job on it never finished (its stamp words short of the last job's):
    /// then it is set aside until it has (`g15_reclaim_dead`).
    pub(crate) fn g15_cl_channel_put(&self, ch: Arc<Mutex<G15ClChannel>>) {
        let idle = Self::g15_chan_idle(&ch.lock());
        let list = if idle {
            &self.g15.free_chans
        } else {
            &self.g15.dead_chans
        };
        if !idle {
            dev_warn!(
                self.dev.as_ref(),
                "G15: a CL channel with an unfinished job is retired\n"
            );
        }
        if list.lock().push(ch, GFP_KERNEL).is_err() {
            dev_err!(self.dev.as_ref(), "G15: cannot keep a CL channel\n");
        }
    }

    /// G15: wait until ring `k` has room for the entry at `next` (its cursor,
    /// under the `g15_rings` lock) and `ch`'s record slots, `queued` used so
    /// far, for `records` more.
    /// Every queue's jobs share a ring's 256 entries, and a channel has 256
    /// record slots. The firmware frees an entry when its consumer takes it
    /// (the read index, region 2) and a slot when its record dispatcher
    /// passes it (channel state +0x20, the slot cursor). An entry or a slot
    /// written before that is lost, or shows the dispatcher a command ID
    /// behind its cursor: it walks every slot and crashes on an empty one
    /// (`AGFA_RecordDispatch`+0x130, eight `eglpass loop` processes).
    pub(super) fn g15_ring_room(
        &self,
        k: usize,
        next: u32,
        ch: &G15ClChannel,
        queued: u32,
        records: u32,
    ) -> Result {
        let base = self.initdata.ring_area.raw_ptr();
        let rp = base
            .wrapping_add(fw::g15::RING_REGION2_OFF + 16 * k)
            .cast_const();
        let cur = ch.state.raw_ptr().wrapping_add(0x20).cast_const();
        let start = Instant::<Monotonic>::now();
        loop {
            // A stopped firmware takes nothing until its recovery resumes it,
            // and the recovery needs the channel locks this submit holds: the
            // caller drops them and waits for the resume (`g15_wait_resume`),
            // then submits again (spec: faults.md, "The fork's recovery").
            if self.crashed.load(Ordering::Relaxed) {
                return Err(ECANCELED);
            }
            if self.g15_fw_stopped() {
                return Err(EAGAIN);
            }
            crate::mem::dc_civac(rp, 4);
            crate::mem::dc_civac(cur, 4);
            // SAFETY: in-bounds u32 reads of the ring region and the channel state.
            let (read, passed) = unsafe {
                (
                    rp.cast::<u32>().read_volatile(),
                    cur.cast::<u32>().read_volatile(),
                )
            };
            let free = (read % 256 + 255 - next) % 256;
            let used = queued.wrapping_sub(passed) % 256;
            if free > 0 && used + records < 256 {
                return Ok(());
            }
            if start.elapsed() >= Delta::from_millis(G15_RING_WAIT_MS) {
                dev_err!(self.dev.as_ref(), "G15: ring {k} full (read {read:#x}, next {next:#x}) or stamp index {} slots full ({used} in use)\n", ch.stamp_index);
                // G15 lab: the firmware's last events at the first stall (the ktrace flag, `Debug4`).
                static DUMPED: core::sync::atomic::AtomicBool =
                    core::sync::atomic::AtomicBool::new(false);
                if !DUMPED.swap(true, Ordering::Relaxed) {
                    self.g15_trace_dump(160);
                    self.g15_dump_ring_stall(k);
                    Self::g15_dump_chan_state(self.dev.as_ref(), "submitting", ch);
                }
                return Err(EBUSY);
            }
            kernel::time::delay::fsleep(Delta::from_micros(50));
        }
    }

    /// G15: whether every job submitted on `ch` has completed.
    pub(crate) fn g15_chan_done(&self, ch: &G15ClChannel) -> bool {
        ch.submitted == 0 || self.g15_cl_done(ch, ch.submitted << 8)
    }

    /// G15: whether ring `k` holds entries the firmware has not consumed:
    /// its write index (the doorbell word) is not its read index
    /// (firmware-owned, region 2).
    pub(super) fn g15_ring_unconsumed(&self, k: usize) -> bool {
        let base = self.initdata.ring_area.raw_ptr();
        let wp = base.wrapping_add(k * fw::g15::RING_STRIDE);
        let rp = base.wrapping_add(fw::g15::RING_REGION2_OFF + 16 * k);
        crate::mem::dc_civac(wp.cast_const(), 4);
        crate::mem::dc_civac(rp.cast_const(), 4);
        // SAFETY: in-bounds u32 reads of the 128 KiB ring region.
        unsafe { (wp as *const u32).read_volatile() != (rp as *const u32).read_volatile() }
    }
}
