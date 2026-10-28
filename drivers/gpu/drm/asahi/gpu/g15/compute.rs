// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 compute (CL) jobs.
//!
//! Spec: cl-container.md, cl-job.md, metal-compute.md, register-lists.md,
//! stream.md.

use super::*;

/// A compute job's own buffers, a fresh set per job in flight.
#[derive(Debug)]
pub(crate) struct G15ClJob {
    /// The 0x880-byte job state (tag 3), with the register list at +0x20,
    /// and the job's GPU start and end after it.
    /// GPU-readable: the CDM fetches the register list itself.
    pub(crate) job_state: fw::types::GpuArray<u8>,
    /// The job's firmware stream: 0x2B8 bytes in a 0x2C0-byte slot,
    /// allocated as 0x400 so that every record stays in bounds.
    pub(crate) stream: fw::types::GpuArray<u8>,
    /// The notifier (macOS's command-buffer notifier): +0x00 points to the
    /// count of jobs submitted under it (1, at +0xC0), +0x08 the sort key,
    /// +0x0C the firmware's completed count, +0x10 the flush threshold,
    /// +0xA8 the stale cutoff.
    pub(crate) notifier: fw::types::GpuArray<u8>,
    /// The CDM control stream when the kernel provides one (a single Stream
    /// Terminate block, for a job without a launch). Only held: the job's
    /// register list points the CDM at it.
    pub(super) _cdm_stream: Option<fw::types::GpuArray<u8>>,
    /// The stamp barrier record published ahead of the job, on its queue's
    /// last render pass.
    pub(super) wait: Option<fw::types::GpuArray<u8>>,
    /// The job's number on its channel (from 1; 0 until submitted).
    pub(crate) n: u32,
    /// The job's stamp: n * 0x100.
    pub(crate) stamp: u32,
    /// The job's context ID.
    pub(crate) ctx: u32,
    /// The UMA pool the job registers.
    pub(crate) uma: Arc<G15Uma>,
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Builds a compute job for `ch`: its job state, stream and notifier,
    /// all but the per-job numbers that `g15_cl_submit` writes. `cdm` is the
    /// GPU VA of the CDM control stream (`None`: a kernel stream holding one
    /// terminate block), `ctx` the context ID, `extra` more register list
    /// entries and `ts` the user timestamps (start, end): kernel VAs of
    /// slots in the client's timestamp buffers, 0 for none.
    pub(crate) fn g15_cl_job_new(
        &self,
        ch: &G15ClChannel,
        cdm: Option<u64>,
        ctx: u32,
        extra: &[(u32, u64)],
        ts: (u64, u64),
    ) -> Result<G15ClJob> {
        let uma = self.g15_uma_get(G15UmaDm::Cl)?;
        // The job state and stream are firmware-uncached, as the kext maps
        // all but its eGART range 8: a line the firmware caches can serve or
        // write back stale bytes.
        let (job_state, cdm_stream, stream, notifier) = {
            let mut guard = self.alloc.lock();
            let job_state = guard
                .gpu_fw_nc
                .array_empty_tagged::<u8>(CL_TIMES + 16, b"JS01")?;
            let cdm_stream = match cdm {
                Some(_) => None,
                None => Some(guard.gpu.array_empty_tagged::<u8>(0x80, b"CDMS")?),
            };
            let stream = guard.fw_nc.array_empty_tagged::<u8>(0x400, b"STRM")?;
            let notifier = guard.fw_nc.array_empty_tagged::<u8>(0x100, b"NTFY")?;
            (job_state, cdm_stream, stream, notifier)
        };
        let cdm_gva = match (&cdm_stream, cdm) {
            (Some(c), _) => {
                // SAFETY: two in-bounds u32 stores into the job's own
                // 0x80-byte buffer: a CDM Stream Terminate block (type 2 in
                // bits 31:29).
                unsafe {
                    let p = W(c.raw_ptr());
                    p.u32(0, 0x4000_0000);
                    p.u32(4, 0);
                }
                c.gpu_va().get() & G15_GPU_VA_MASK
            }
            (None, Some(va)) => va & G15_GPU_VA_MASK,
            (None, None) => return Err(EINVAL),
        };
        if 0x20 + (22 + extra.len()) * 12 > 0x720 {
            return Err(EINVAL);
        }
        let js = job_state.gpu_va().get();
        let strm = stream.gpu_va().get();
        let notifier_va = notifier.gpu_va().get();
        let state_va = ch.state.gpu_va().get();
        let ctx_store_va = ch.ctx_store.as_ref().ok_or(EINVAL)?.gpu_va().get();
        let uma_state_va = uma.state.gpu_va().get();
        let metrics_va = uma.metrics_slot();
        let words_va = ch.words.gpu_va().get();
        let preempt_gva = ch.preempt.gpu_va().get() & G15_GPU_VA_MASK;
        let stats_va = self.initdata.buf_0x228.gpu_va().get();
        let user_ts = if ts != (0, 0) { js + 0x828 } else { 0 };

        // The register list: 22 entries of 12 bytes at +0x20, each a header
        // `(register & 0x3FFF8) | write-enable` and a u64 value. The UMA page
        // reservations are macOS's defaults: CDM minimum 0x20, reload 0x40,
        // maximum 0x60; DUPM 0x20 * 8 and 0x60 * 8.
        let entries: [(u32, u64); 22] = [
            (0x1A510, preempt_gva),
            (0x1A420, cdm_gva),
            (0x1A4D0, 0),
            (0x1A4D8, 0),
            (0x1A4E0, 0),
            (0x1A4E8, 0),
            (0x1A440, 0x154024201),
            (0x1A458, 0x10C08860),
            // Metal's 0x1C (beginComputePass).
            (0x12091, 0x1C),
            (0x101D9, 0x1C),
            (0x1A089, 0),
            (0x1A091, 0),
            (0x1A059, 0),
            (0x1A061, 0),
            (0x1A0B9, 0),
            (0x1A0C1, 0),
            (0x101D1, 0),
            (0xD479, 0),
            (0x1A0E9, 8), // Metal's 8 without SCS
            (0x107A1, 0x00FF0000),
            (0xA599, 0x0000_0060_0040_0020),
            (0xD411, ((0x60 * 8) << 32) | (0x20 * 8)),
        ];
        // SAFETY: every write is one in-bounds field of the job's own
        // freshly allocated buffers or of the channel's.
        unsafe {
            let j = W(job_state.raw_ptr());
            j.u32(0, 3); // +0x00 tag = CL
            j.u32(0x10, ctx); // +0x10 context ID
            j.u64(0x14, notifier_va); // +0x14 the notifier
            let n = j.reglist(0x20, &entries);
            let count = n + j.reglist(0x20 + n as usize * 12, extra);
            j.u64(0x720, js + 0x20); // self-address

            // The list's size in bytes << 16 | its entry count.
            j.u32(0x728, (count * 12) << 16 | count);
            j.u64(0x760, strm); // stream FWVA (slot start)
            j.u32(0x768, 0x2C0); // slot size
            j.u64(0x7C4, 0x154024201); // chip config word (qword)
            j.u64(0x7E8, words_va); // host stamp word (stamp index 0)
            j.u64(0x7F0, words_va + 4); // firmware stamp word
            j.u8(0x7FC, ch.stamp_index as u8); // stamp index
            j.u32(0x800, 0); // channel index
            j.u32(0x804, 0); // no IO fences
            j.u64(0x818, js + CL_TIMES as u64); // the GPU start
            j.u64(0x820, js + CL_TIMES as u64 + 8); // and end
            j.u64(0x828, ts.0); // the user timestamps
            j.u64(0x830, ts.1);

            // The UMA pool: its state, the clean-and-invalidate flag and the
            // job's metrics slot.
            j.u64(0x83E, uma_state_va);
            j.u8(0x846, 1);
            j.u64(0x857, metrics_va);

            // The notifier, empty: +0x00 points to its submitted-jobs count
            // (1, at +0xC0), +0x08 the sort key, +0x0C the firmware's
            // completed count, +0x10 the flush threshold (80, as macOS),
            // +0x94 not listed, +0xA8 no stale cutoff.
            let f = W(notifier.raw_ptr());
            f.u32(0xC0, 1);
            f.u64(0, notifier_va + 0xC0);
            f.u32(0xC, 0);
            f.u32(0x10, 80);
            f.u32(0x94, 0);
            f.u64(0xA8, u64::MAX);
            // The firmware reads the notifier uncached.
            crate::mem::dc_civac(f.0.cast_const(), 0x100);

            // The stream, 0x2B8 bytes: the context record (0x1BC), a
            // timestamp (0x3C), a wait for idle (4), a timestamp (0x3C), the
            // start record (0x7C) and the terminator (4).
            let s = W(stream.raw_ptr());
            // Type 0xB, the context record (payload offsets + 4).
            s.u8(0, 0x0B);
            s.u64(0x14, js + 0x20); // +0x10 the command list
            s.u64(0x1C, stats_va); // +0x18 conv(*(fw+0x268))
            s.u64(0x24, state_va); // +0x20 the state
            s.u32(0x2C, ctx); // +0x28 context ID
            s.u32(0x30, g15_soft_faults()); // +0x2C HW soft faults
            s.u32(0x38, 0); // +0x34 desc+0x48C
            s.u32(0x3C, 0); // +0x38 channel index
            s.u32(0x40, 0); // +0x3C desc+0x460 != 0
            s.u64(0x44, js + 0x76C); // +0x40 jobState+0x76C

            // +0x158 the UMA group: the pool state, no grow (+0x160,
            // +0x168), the metrics slot (never 0), +0x178 0.
            s.u64(0x15C, uma_state_va);
            s.u64(0x174, metrics_va);
            // +0x180…+0x198 the CDM context store A, B, C, D.
            let cs = (ctx_store_va + 0x3FF) & !0x3FF;
            s.u64(0x184, cs); // +0x180
            s.u64(0x18C, cs + 0x3C000); // +0x188
            s.u64(0x194, cs + 0x78000); // +0x190
            s.u64(0x19C, cs + 0x7A000); // +0x198
            s.u64(0x1A4, js + 0x878); // +0x1A0 the stale flag
            s.u64(0x1B4, notifier_va + 0xA8); // +0x1B0 the stale cutoff

            // Type 3, the first timestamp (bit 31 set), 0x3C bytes at +0x1BC.
            s.u32(0x1BC, 0x80000003);
            s.u64(0x1C0, js + 0x810);
            s.u64(0x1C8, js + 0x818);
            s.u64(0x1D0, js + 0x818);
            s.u64(0x1D8, state_va);
            s.u64(0x1E0, user_ts); // the user timestamps, if any
            s.u64(0x1E8, js + 0x868);
            // The wait for idle: the single word 1 at +0x1F8.
            s.u32(0x1F8, 1);
            // Type 3, the second timestamp, 0x3C bytes at +0x1FC.
            s.u32(0x1FC, 3);
            s.u64(0x200, js + 0x810);
            s.u64(0x208, js + 0x818);
            s.u64(0x210, js + 0x820);
            s.u64(0x218, state_va);
            s.u64(0x220, user_ts);
            s.u64(0x228, js + 0x868);
            // Type 0xC, the start record, 0x7C bytes at +0x238.
            s.u32(0x238, 0x0C);
            s.u64(0x23C, stats_va);
            s.u64(0x244, state_va);
            s.u32(0x24C, ctx); // +0x14 jobState+0x10
            s.u64(0x250, js + 0x76C);
            s.u64(0x260, words_va + 4); // +0x28 the firmware stamp word
            s.u32(0x28C, 0); // +0x54 dependency flag
            s.u64(0x290, strm + 0x15C); // +0x58 the context payload+0x158
            s.u32(0x298, 0u32.wrapping_sub(0x238)); // +0x60 the rewind to the context record
            s.u8(0x29C, 0); // +0x64 flags (no deps)
            s.u64(0x29D, js + 0x878); // +0x65
            s.u64(0x2A5, js + 0x860); // +0x6D

            // Type 2, the terminator at +0x2B4.
            s.u32(0x2B4, 0x40000002);
        }
        Ok(G15ClJob {
            job_state,
            stream,
            notifier,
            _cdm_stream: cdm_stream,
            wait: None,
            n: 0,
            stamp: 0,
            ctx,
            uma,
        })
    }

    /// Submits `job` on `ch` as its next job n: the per-job numbers (stamp
    /// n * 0x100, job ID and counters n), the device's next notifier key,
    /// the records at the channel's slot cursor (a stamp barrier on `after`
    /// first), one more submission on the UMA pool, the compute ring's entry
    /// and write index, then the doorbell.
    pub(super) fn g15_cl_submit(
        &self,
        ch: &mut G15ClChannel,
        job: &mut G15ClJob,
        after: Option<G15After>,
    ) -> Result {
        const CL_RING: usize = fw::g15::ring(2);
        self.g15_chan_fresh(ch);
        let n = ch.submitted + 1;
        let stamp = n << 8; // the previous job's value + 0x100, low byte 0
        job.wait = after
            .map(|a| self.g15_barrier_rec(a, true, stamp, n))
            .transpose()?;
        let records = 1 + u32::from(job.wait.is_some());
        let mut rings = self.g15.rings.lock();
        self.g15_ring_room(CL_RING, rings[CL_RING], ch, ch.submitted_records, records)?;
        let key = self.g15.ntf_keys.fetch_add(1, Ordering::Relaxed);
        let slot = ch.submitted_records;
        job.n = n;
        job.stamp = stamp;
        let js = job.job_state.gpu_va().get();
        // SAFETY: in-bounds fields of the job's own buffers and the
        // channel's record slots.
        unsafe {
            let j = W(job.job_state.raw_ptr());
            j.u64(4, u64::from(n)); // +0x04 the queue's job counter
            j.u32(0x7F8, stamp); // stamp value
            j.u32(0x808, n); // job ID (unique u32)
            j.u32(0x80C, n - 1); // the queue's CL counter
            W(job.notifier.raw_ptr()).u32(8, key); // the notifier key
            let s = W(job.stream.raw_ptr());
            s.u32(0x34, key); // context +0x30 the notifier key
            s.u32(0x50, n); // context +0x4C job ID
            s.u64(0x1AC, u64::from(n)); // context +0x1A8 jobState+0x04
            s.u32(0x1F0, n); // first timestamp: job ID
            s.u32(0x230, n); // second timestamp: job ID
            s.u32(0x25C, n); // start +0x24 job ID
            s.u32(0x268, stamp); // start +0x30 the stamp value
            let w = W(ch.chan_cached.raw_ptr());
            if let Some(b) = job.wait.as_ref() {
                w.u64((slot % 256) as usize * 8, va(b)); // the barrier's record slot
            }
            w.u64(((slot + records - 1) % 256) as usize * 8, js); // the job's
        }
        // The firmware reads the job state, stream, barrier and notifier
        // uncached.
        crate::mem::dc_civac(job.job_state.raw_ptr().cast_const(), job.job_state.len());
        crate::mem::dc_civac(job.notifier.raw_ptr().cast_const(), 0x40);
        crate::mem::dc_civac(job.stream.raw_ptr().cast_const(), job.stream.len());
        if let Some(b) = job.wait.as_ref() {
            crate::mem::dc_civac(b.raw_ptr().cast_const(), b.len());
        }
        core::sync::atomic::fence(Ordering::Release);
        job.uma.count_submit();
        let state_va = ch.state.gpu_va().get();
        let idx = rings[CL_RING];
        rings[CL_RING] = (idx + 1) % 256;
        let ring = self.initdata.ring_area.raw_ptr();
        // SAFETY: the ring entry (slot idx % 256 of the ring's storage) and
        // the write index are within the 128 KiB ring region.
        unsafe {
            let e = W(ring.add(CL_RING * fw::g15::RING_STRIDE + 8 + (idx % 256) as usize * 24));
            e.u64(0x00, self.g15.perf.fw_now()); // submit time
            e.u64(0x08, state_va); // state FWVA
            e.u32(0x10, 2); // class = CL
            e.u16(0x14, ((slot + records) % 256) as u16); // command ID
            e.u8(0x16, ch.stamp_index as u8); // stamp index
            e.u8(0x17, 1); // flag (processed when != 0)
            crate::mem::dc_civac(e.0, 24); // the entry first, then the index
            ring.add(CL_RING * fw::g15::RING_STRIDE)
                .cast::<u32>()
                .write_volatile((idx + 1) % 256);
            crate::mem::dc_civac(ring.add(CL_RING * fw::g15::RING_STRIDE), 4);
        }
        drop(rings);
        ch.submitted = job.n;
        ch.submitted_records = slot + records;
        self.g15_bell(2);
        Ok(())
    }

    /// Submits `job` on `chan` and tracks it: `done` runs once the job is
    /// complete. The job first waits for `after`, its queue's last render
    /// pass, on a stamp barrier.
    pub(crate) fn g15_cl_run(
        &self,
        chan: &Arc<Mutex<G15ClChannel>>,
        mut job: G15ClJob,
        vm: mmu::VmBind,
        after: Option<G15After>,
        done: KBox<dyn FnMut(Option<Error>) + Send>,
    ) -> Result {
        // A submission that meets a firmware stop waits for the resume
        // without the channel lock, then submits again (`g15_ring_room`
        // takes no ring entry and writes nothing before it returns
        // `EAGAIN`).
        let (gen, pid) = loop {
            self.g15_wait_stamp_room(&[chan])?;
            let mut ch = chan.lock();
            match self.g15_cl_submit(&mut ch, &mut job, after) {
                Err(e) if e == EAGAIN => {
                    drop(ch);
                    self.g15_wait_resume()?;
                }
                r => {
                    r?;
                    break (ch.gen, Self::g15_chan_pid(&ch));
                }
            }
        };
        mod_dev_dbg!(
            self.dev,
            "G15: CL job {} rung (ctx {}, stamp {:#x})\n",
            job.n,
            job.ctx,
            job.stamp
        );
        self.g15_track(
            G15ClPending {
                chan: chan.clone(),
                stamp: job.stamp,
                n: job.n,
                ctx: job.ctx,
                pid,
                ta: None,
                work: G15Work::Cl(job),
                _vm: vm,
                done,
                signaled: false,
                error: None,
                since: Instant::<Monotonic>::now(),
                fw_at: None,
                late: false,
            },
            gen,
        );
        Ok(())
    }
}
