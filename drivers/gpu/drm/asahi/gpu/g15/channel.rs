// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 channels and the command rings.
//!
//! A channel is the firmware's per-queue state (macOS's `AGXChannel`): a
//! state object, the record slots that hold its jobs, the stamp table and
//! words, and the notifier list. Compute queues own one channel, render
//! queues a TA and a 3D channel. Jobs reach the firmware through entries in
//! the command rings, which all queues share.

use super::*;

/// A firmware channel: the state object and the buffers every job of the
/// channel shares.
pub(crate) struct G15ClChannel {
    /// The 0x24C0-byte state object (`_AGFIChannelState`, set up as
    /// `AGXChannel::resetChannelState` does), which a ring entry points to.
    /// The firmware keeps its cursors, the priority stage, the record
    /// slots, the stamp table and the job-slot object here.
    pub(crate) state: fw::types::GpuArray<u8>,
    /// Uncached channel memory: the last command ID (written by the
    /// firmware) and the slot capacity.
    pub(crate) chan_uncached: fw::types::GpuArray<u8>,
    /// The 256 record slots of 8 bytes, each the GPU VA of a job state.
    pub(crate) chan_cached: fw::types::GpuArray<u8>,
    /// The table of 128 stamp entries of 0x48 bytes, zeroed once; each job's
    /// registration rewrites its entry.
    pub(crate) stamp_table: fw::types::GpuArray<u8>,
    /// The 0x38-byte job-slot object, created empty (the firmware allocates
    /// a slot on use).
    pub(crate) job_slot: fw::types::GpuArray<u8>,
    /// The context store a compute job's context record points into, sized
    /// as `AGXCLChannel::init` does for t6034: S = 0x3C000, T = 0x2000,
    /// `(2S + T) | 0x400` bytes.
    pub(crate) ctx_store: fw::types::GpuArray<u8>,
    /// The notifier list's header {0, P + 0x10, 0, P + 0x20, 0}: a BSD tail
    /// queue of the channel's jobs in flight, which the firmware walks after
    /// each job.
    pub(crate) chan_list: fw::types::GpuArray<u8>,
    /// The CDM preemption buffer (register 0x1A510), zeroed.
    pub(crate) preempt: fw::types::GpuArray<u8>,
    /// The channel's two stamp words: +0x00 the host stamp word, which the
    /// notifier walk writes at the end of a job's post-processing, and
    /// +0x04 the firmware stamp word, which the firmware's in-order retire
    /// writes.
    pub(crate) words: fw::types::GpuArray<u8>,
    /// Jobs submitted so far. A job's stamp, IDs and record slot are
    /// assigned at submission, so a job built but never run leaves no gap
    /// in the stamp sequence.
    pub(crate) submitted: u32,
    /// Records published so far. A render job can carry a pre-record, so
    /// this runs ahead of the job count.
    pub(crate) submitted_records: u32,
    /// The channel's stamp index (its slot in the firmware's job graph),
    /// one of 1..127 as `requestStampIndexForChannel` assigns them.
    pub(crate) stamp_index: u32,
    /// The allocator the stamp index returns to when the channel goes.
    pub(super) stamp_ids: Option<Arc<Mutex<u128>>>,
    /// The host stop the channel was last set up after (`G15State::reset_gen`).
    pub(super) gen: u32,
}

impl Drop for G15ClChannel {
    fn drop(&mut self) {
        if let Some(ids) = self.stamp_ids.take() {
            *ids.lock() &= !(1u128 << self.stamp_index);
        }
    }
}

/// The capacity of a channel's record slots.
const G15_CHAN_SLOTS: u32 = 256;

#[versions(AGX)]
impl GpuManager::ver {
    /// Creates a channel (`AGXChannel::resetChannelState`).
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
        let mut guard = self.alloc.lock();
        let preempt = guard.gpu.array_empty_tagged::<u8>(0x4000, b"PRMT")?;
        let words = guard.stamp.array_empty_tagged::<u8>(0x40, b"STWD")?;
        let chan_list = guard.fw_nc.array_empty_tagged::<u8>(0x40, b"NLST")?;
        let shared = &mut guard.shared;
        let ch = G15ClChannel {
            state: shared.array_empty_tagged::<u8>(0x24C0, b"STTE")?,
            chan_uncached: shared.array_empty_tagged::<u8>(0x100, b"UCMN")?,
            chan_cached: shared.array_empty_tagged::<u8>(G15_CHAN_SLOTS as usize * 8, b"CCMN")?,
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
            gen: self.g15.reset_gen.load(Ordering::Relaxed),
        };
        core::mem::drop(guard);
        Self::g15_chan_init(&ch);
        Self::g15_chan_own(&ch);
        Ok(ch)
    }

    /// Fills a channel's buffers, new or zeroed by `g15_chan_reset`, as
    /// `AGXChannel::resetChannelState` does.
    fn g15_chan_init(ch: &G15ClChannel) {
        let unc_va = ch.chan_uncached.gpu_va().get();
        let cached_va = ch.chan_cached.gpu_va().get();
        let stamp_va = ch.stamp_table.gpu_va().get();
        let job_slot_va = ch.job_slot.gpu_va().get();
        let chan_list_va = ch.chan_list.gpu_va().get();
        // SAFETY: each write is one in-bounds field of the channel's own
        // zeroed buffers.
        unsafe {
            let c = ch.state.raw_ptr();
            let q = |off: usize| c.add(off).cast::<u64>();
            q(0x00).write_volatile(unc_va); // -> uncached chan mem (capacity at +0x50)
            q(0x08).write_volatile(cached_va); // -> record slots
            q(0x10).write_volatile(chan_list_va); // -> notifier-list header
            q(0x18).write_volatile(stamp_va); // -> stamp table
            c.add(0x2C).cast::<u32>().write_volatile(0xFFFFFFFF); // fresh sentinel

            // The priority stage (AGXArmFirmware::setChannelPriority).
            // resetChannelState leaves +0x30 = 4, which no executor stage
            // runs; a default foreground queue would be stage 2. The
            // firmware's background tick preempts the slots of a queue that
            // used more than its share, except at stage 0, and a TA job's
            // context store faults (it writes near address 0). So every
            // channel is stage 0: mask 0xFFFFFFFFFFFF0000, +0x40 = 1.
            c.add(0x30).cast::<u32>().write_volatile(0); // stage
            c.add(0x34).cast::<u32>().write_volatile(0);
            q(0x38).write_volatile(0xFFFF_FFFF_FFFF_0000); // mask (TA path only)
            c.add(0x40).cast::<u32>().write_volatile(1);
            c.add(0x44).cast::<u32>().write_volatile(0); // sub-queue
            c.add(0x48).cast::<u32>().write_volatile(0); // pending row 0xD + this
            c.add(0x4C).cast::<u32>().write_volatile(0xFFFFFFFF);
            q(0xA4).write_volatile(job_slot_va); // -> job-slot object
            ch.chan_uncached
                .raw_ptr()
                .add(0x50)
                .cast::<u32>()
                .write_volatile(G15_CHAN_SLOTS);

            // The job-slot object, empty: the firmware allocates on use.
            let p = ch.job_slot.raw_ptr();
            p.write_volatile(0xFF); // +0x00 no job-table slot
            p.add(1).write_volatile(0xFF); // +0x01 no job index

            // The notifier list's header, empty. The insert reads
            // *(*(P[1] + 8)), so P[1] = Q with *(Q + 8) = R and *R = 0.
            let n = ch.chan_list.raw_ptr();
            n.cast::<u64>().write_volatile(0); // +0x00 P[0] head = fresh
            n.add(8).cast::<u64>().write_volatile(chan_list_va + 0x10); // +0x08 P[1] = Q
            n.add(16).cast::<u64>().write_volatile(0); // +0x10 unused
            n.add(24).cast::<u64>().write_volatile(chan_list_va + 0x20); // +0x18 P[3] = R
            n.add(32).cast::<u64>().write_volatile(0); // +0x20 *R = 0 (the walk stops)
        }
        // The firmware reads the header uncached.
        crate::mem::dc_civac(ch.chan_list.raw_ptr().cast_const(), 0x40);
    }

    /// Sets a channel up again after a host stop, whose rebuild made the
    /// firmware forget every channel (`AGXChannel::resetChannelState`): the
    /// state object, the record slots, the stamp table, the job-slot object
    /// and the notifier list as at creation, the cursors at 0. Its jobs are
    /// complete: both stamp words go to the last job's stamp, as IOGPU's
    /// `forceCompleteAllStamps` does. The owner stays.
    pub(super) fn g15_chan_reset(&self, ch: &mut G15ClChannel) {
        let pid_at = ch.state.raw_ptr().wrapping_add(0x50).cast::<u32>();
        // SAFETY: an in-bounds u32 read of the channel's state block.
        let pid = unsafe { pid_at.read_volatile() };
        for a in [
            &ch.state,
            &ch.chan_uncached,
            &ch.chan_cached,
            &ch.stamp_table,
            &ch.job_slot,
            &ch.chan_list,
        ] {
            // SAFETY: each buffer is the channel's own, `len()` bytes long.
            unsafe { core::ptr::write_bytes(a.raw_ptr(), 0, a.len()) };
        }
        Self::g15_chan_init(ch);
        let stamp = ch.submitted << 8;
        // SAFETY: in-bounds u32 stores into the channel's state block and
        // its two stamp words.
        unsafe {
            pid_at.write_volatile(pid);
            let w = ch.words.raw_ptr().cast::<u32>();
            w.write_volatile(stamp);
            w.add(1).write_volatile(stamp);
        }
        for a in [
            &ch.state,
            &ch.chan_uncached,
            &ch.chan_cached,
            &ch.stamp_table,
            &ch.job_slot,
        ] {
            crate::mem::dc_civac(a.raw_ptr().cast_const(), a.len());
        }
        crate::mem::dc_civac(ch.words.raw_ptr().cast_const(), 8);
        ch.submitted_records = 0;
        ch.gen = self.g15.reset_gen.load(Ordering::Relaxed);
    }

    /// Sets `ch` up again if a host stop came since it last was.
    pub(super) fn g15_chan_fresh(&self, ch: &mut G15ClChannel) {
        if ch.gen != self.g15.reset_gen.load(Ordering::Relaxed) {
            self.g15_chan_reset(ch);
        }
    }

    /// A channel for a queue: a destroyed queue's, else a new one.
    pub(crate) fn g15_cl_channel_get(&self) -> Result<Arc<Mutex<G15ClChannel>>> {
        if let Some(ch) = self.g15.free_chans.lock().pop() {
            Self::g15_chan_own(&ch.lock());
            return Ok(ch);
        }
        let ch = self.g15_cl_channel_new()?;
        Arc::pin_init(new_mutex!(ch, "g15_chan"), GFP_KERNEL)
    }

    /// Makes the current process the channel's owner (state +0x50): the
    /// firmware copies the pid into its job table and reports it with a
    /// recovery's guilty job.
    pub(super) fn g15_chan_own(ch: &G15ClChannel) {
        let pid = kernel::current!().group_leader().pid();
        // SAFETY: an in-bounds u32 store into the channel's state block.
        unsafe {
            ch.state
                .raw_ptr()
                .add(0x50)
                .cast::<u32>()
                .write_volatile(pid as u32);
        }
    }

    /// Whether the firmware has retired every job submitted on `c`: its
    /// stamp word has reached the last job's stamp. The retire is the last
    /// thing the firmware does for a job, after the completion event and
    /// the host stamp, and only then may the channel serve another queue.
    pub(super) fn g15_chan_idle(c: &G15ClChannel) -> bool {
        crate::mem::dc_civac(c.words.raw_ptr().cast_const(), 8);
        // SAFETY: an in-bounds u32 read of the channel's own stamp words.
        let fwst = unsafe { (c.words.raw_ptr() as *const u32).add(1).read_volatile() };
        fwst.wrapping_sub(c.submitted << 8) as i32 >= 0
    }

    /// Frees the set-aside channels whose last job has finished since; their
    /// stamp indices return to the pool.
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

    /// Takes back a destroyed queue's channel for reuse, unless a job on it
    /// never finished: such a channel is set aside until it has.
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

    /// Waits until ring `k` has room for the entry at `next` (its cursor,
    /// under the rings lock) and `ch`'s record slots, `queued` used so far,
    /// have room for `records` more.
    ///
    /// All queues share a ring's 256 entries, and a channel has 256 record
    /// slots. The firmware frees an entry when its consumer takes it (the
    /// ring's read index) and a slot when its record dispatcher passes it
    /// (the channel's slot cursor). An entry or a slot written before that
    /// is lost, or shows the dispatcher a command ID behind its cursor, and
    /// the firmware then crashes on an empty slot.
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
            // A stopped firmware takes nothing until it is resumed, and the
            // recovery needs the channel locks this submission holds: the
            // caller drops them, waits for the resume and submits again.
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
                dev_err!(
                    self.dev.as_ref(),
                    "G15: ring {k} full (read {read:#x}, next {next:#x}) or stamp index {} slots full ({used} in use)\n",
                    ch.stamp_index
                );
                // The firmware's state at the first stall.
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

    /// Whether every job submitted on `ch` has completed.
    pub(crate) fn g15_chan_done(&self, ch: &G15ClChannel) -> bool {
        ch.submitted == 0 || self.g15_cl_done(ch, ch.submitted << 8)
    }

    /// The read index of ring `k` if it holds entries the firmware has not
    /// consumed: its write index (the doorbell word) differs from it.
    pub(super) fn g15_ring_unconsumed(&self, k: usize) -> Option<u32> {
        let base = self.initdata.ring_area.raw_ptr();
        let wp = base.wrapping_add(k * fw::g15::RING_STRIDE);
        let rp = base.wrapping_add(fw::g15::RING_REGION2_OFF + 16 * k);
        crate::mem::dc_civac(wp.cast_const(), 4);
        crate::mem::dc_civac(rp.cast_const(), 4);
        // SAFETY: in-bounds u32 reads of the 128 KiB ring region.
        let (w, r) = unsafe {
            (
                (wp as *const u32).read_volatile(),
                (rp as *const u32).read_volatile(),
            )
        };
        (w != r).then_some(r)
    }
}
