// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 compute (CL) jobs.

use super::*;

/// A compute job's own buffers, a fresh set per job in flight.
#[derive(Debug)]
pub(crate) struct G15ClJob {
    /// The 0x880-byte job state (tag 3), with the register list at +0x20.
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
    /// terminate block), `ctx` the context ID and `extra` more register
    /// list entries.
    pub(crate) fn g15_cl_job_new(
        &self,
        ch: &G15ClChannel,
        cdm: Option<u64>,
        ctx: u32,
        extra: &[(u32, u64)],
    ) -> Result<G15ClJob> {
        let uma = self.g15_uma_get()?;
        let (job_state, cdm_stream, stream, notifier) = {
            let mut guard = self.alloc.lock();
            let job_state = guard.gpu.array_empty_tagged::<u8>(0x880, b"JS01")?;
            let cdm_stream = match cdm {
                Some(_) => None,
                None => Some(guard.gpu.array_empty_tagged::<u8>(0x80, b"CDMS")?),
            };
            let stream = guard.shared.array_empty_tagged::<u8>(0x400, b"STRM")?;
            let notifier = guard.fw_nc.array_empty_tagged::<u8>(0x100, b"NTFY")?;
            (job_state, cdm_stream, stream, notifier)
        };
        let cdm_gva = match (&cdm_stream, cdm) {
            (Some(c), _) => {
                // SAFETY: two in-bounds u32 stores into the job's own
                // 0x80-byte buffer: a CDM Stream Terminate block (type 2 in
                // bits 31:29).
                unsafe {
                    let p = c.raw_ptr().cast::<u32>();
                    p.write_volatile(0x4000_0000);
                    p.add(1).write_volatile(0);
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
        let ctx_store_va = ch.ctx_store.gpu_va().get();
        let uma_state_va = uma.state.gpu_va().get();
        let metrics_va = uma.metrics_slot();
        let words_va = ch.words.gpu_va().get();
        let preempt_gva = ch.preempt.gpu_va().get() & G15_GPU_VA_MASK;
        let stats_va = self.initdata.buf_0x228.gpu_va().get();

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
            let j = job_state.raw_ptr();
            let q = |off: usize| j.add(off).cast::<u64>();
            j.cast::<u32>().write_volatile(3); // +0x00 tag = CL
            j.add(0x10).cast::<u32>().write_volatile(ctx); // +0x10 context ID
            q(0x14).write_volatile(notifier_va); // +0x14 the notifier
            for (i, &(mrr, val)) in Iterator::chain(entries.iter(), extra.iter()).enumerate() {
                let e = j.add(0x20 + i * 12);
                e.cast::<u32>().write_volatile(mrr);
                e.add(4).cast::<u64>().write_volatile(val);
            }
            let count = (entries.len() + extra.len()) as u32;
            q(0x720).write_volatile(js + 0x20); // self-address

            // The list's size in bytes << 16 | its entry count.
            j.add(0x728)
                .cast::<u32>()
                .write_volatile((count * 12) << 16 | count);
            q(0x760).write_volatile(strm); // stream FWVA (slot start)
            j.add(0x768).cast::<u32>().write_volatile(0x2C0); // slot size
            q(0x7C4).write_volatile(0x154024201); // chip config word (qword)
            q(0x7E8).write_volatile(words_va); // host stamp word (stamp index 0)
            q(0x7F0).write_volatile(words_va + 4); // firmware stamp word
            j.add(0x7FC).write_volatile(ch.stamp_index as u8); // stamp index
            j.add(0x800).cast::<u32>().write_volatile(0); // channel index
            j.add(0x804).cast::<u32>().write_volatile(0); // no IO fences

            // The UMA pool: its state, the clean-and-invalidate flag and the
            // job's metrics slot.
            j.add(0x83E).cast::<u64>().write_unaligned(uma_state_va);
            j.add(0x846).write_volatile(1);
            j.add(0x857).cast::<u64>().write_unaligned(metrics_va);

            // The notifier, empty: +0x00 points to its submitted-jobs count
            // (1, at +0xC0), +0x08 the sort key, +0x0C the firmware's
            // completed count, +0x10 the flush threshold (80, as macOS),
            // +0x94 not listed, +0xA8 no stale cutoff.
            let f = notifier.raw_ptr();
            f.add(0xC0).cast::<u32>().write_volatile(1);
            f.cast::<u64>().write_volatile(notifier_va + 0xC0);
            f.add(0xC).cast::<u32>().write_volatile(0);
            f.add(0x10).cast::<u32>().write_volatile(80);
            f.add(0x94).cast::<u32>().write_volatile(0);
            f.add(0xA8).cast::<u64>().write_volatile(u64::MAX);
            // The firmware reads the notifier uncached.
            crate::mem::dc_civac(f.cast_const(), 0x100);

            // The stream, 0x2B8 bytes: the context record (0x1BC), a
            // timestamp (0x3C), a wait for idle (4), a timestamp (0x3C), the
            // start record (0x7C) and the terminator (4).
            let s = stream.raw_ptr();
            let q = |off: usize| s.add(off).cast::<u64>();
            // Type 0xB, the context record (payload offsets + 4).
            s.write_volatile(0x0B);
            q(0x14).write_volatile(js + 0x20); // +0x10 the command list
            q(0x1C).write_volatile(stats_va); // +0x18 conv(*(fw+0x268))
            q(0x24).write_volatile(state_va); // +0x20 the state
            s.add(0x2C).cast::<u32>().write_volatile(ctx); // +0x28 context ID
            s.add(0x30).cast::<u32>().write_volatile(g15_soft_faults()); // +0x2C HW soft faults
            s.add(0x38).cast::<u32>().write_volatile(0); // +0x34 desc+0x48C
            s.add(0x3C).cast::<u32>().write_volatile(0); // +0x38 channel index
            s.add(0x40).cast::<u32>().write_volatile(0); // +0x3C desc+0x460 != 0
            q(0x44).write_volatile(js + 0x76C); // +0x40 jobState+0x76C

            // +0x158 the UMA group: the pool state, no grow (+0x160,
            // +0x168), the metrics slot (never 0), +0x178 0.
            q(0x15C).write_volatile(uma_state_va);
            q(0x174).write_volatile(metrics_va);
            // +0x180…+0x198 the CDM context store A, B, C, D.
            let cs = (ctx_store_va + 0x3FF) & !0x3FF;
            q(0x184).write_volatile(cs); // +0x180
            q(0x18C).write_volatile(cs + 0x3C000); // +0x188
            q(0x194).write_volatile(cs + 0x78000); // +0x190
            q(0x19C).write_volatile(cs + 0x7A000); // +0x198
            q(0x1A4).write_volatile(js + 0x878); // +0x1A0 the stale flag
            q(0x1B4).write_volatile(notifier_va + 0xA8); // +0x1B0 the stale cutoff

            // Type 3, the first timestamp (bit 31 set), 0x3C bytes at +0x1BC.
            s.add(0x1BC).cast::<u32>().write_volatile(0x80000003);
            q(0x1C0).write_volatile(js + 0x810);
            q(0x1C8).write_volatile(js + 0x818);
            q(0x1D0).write_volatile(js + 0x818);
            q(0x1D8).write_volatile(state_va);
            q(0x1E8).write_volatile(js + 0x868);
            // The wait for idle: the single word 1 at +0x1F8.
            s.add(0x1F8).cast::<u32>().write_volatile(1);
            // Type 3, the second timestamp, 0x3C bytes at +0x1FC.
            s.add(0x1FC).cast::<u32>().write_volatile(3);
            q(0x200).write_volatile(js + 0x810);
            q(0x208).write_volatile(js + 0x818);
            q(0x210).write_volatile(js + 0x820);
            q(0x218).write_volatile(state_va);
            q(0x228).write_volatile(js + 0x868);
            // Type 0xC, the start record, 0x7C bytes at +0x238.
            s.add(0x238).cast::<u32>().write_volatile(0x0C);
            q(0x23C).write_volatile(stats_va);
            q(0x244).write_volatile(state_va);
            s.add(0x24C).cast::<u32>().write_volatile(ctx); // +0x14 jobState+0x10
            q(0x250).write_volatile(js + 0x76C);
            q(0x260).write_volatile(words_va + 4); // +0x28 the firmware stamp word
            s.add(0x28C).cast::<u32>().write_volatile(0); // +0x54 dependency flag
            q(0x290).write_volatile(strm + 0x15C); // +0x58 the context payload+0x158
            s.add(0x298)
                .cast::<u32>()
                .write_volatile(0u32.wrapping_sub(0x238)); // +0x60 the rewind to the context record
            s.add(0x29C).cast::<u8>().write_volatile(0); // +0x64 flags (no deps)
            q(0x29D).write_volatile(js + 0x878); // +0x65
            q(0x2A5).write_volatile(js + 0x860); // +0x6D

            // Type 2, the terminator at +0x2B4.
            s.add(0x2B4).cast::<u32>().write_volatile(0x40000002);
        }
        Ok(G15ClJob {
            job_state,
            stream,
            notifier,
            _cdm_stream: cdm_stream,
            n: 0,
            stamp: 0,
            ctx,
            uma,
        })
    }

    /// Submits `job` on `ch` as its next job n: the per-job numbers (stamp
    /// n * 0x100, job ID and counters n, notifier key n, record slot n - 1),
    /// one more submission on the UMA pool, the compute ring's entry and
    /// write index, then the doorbell.
    pub(super) fn g15_cl_submit(&self, ch: &mut G15ClChannel, job: &mut G15ClJob) -> Result {
        const CL_RING: usize = fw::g15::ring(2);
        let mut rings = self.g15.rings.lock();
        self.g15_ring_room(CL_RING, rings[CL_RING], ch, ch.submitted, 1)?;
        let n = ch.submitted + 1;
        let stamp = n << 8; // the previous job's value + 0x100, low byte 0
        job.n = n;
        job.stamp = stamp;
        let js = job.job_state.gpu_va().get();
        // SAFETY: in-bounds fields of the job's own buffers and the
        // channel's record slots.
        unsafe {
            let j = job.job_state.raw_ptr();
            j.add(4).cast::<u64>().write_volatile(u64::from(n)); // +0x04 the queue's job counter
            j.add(0x7F8).cast::<u32>().write_volatile(stamp); // stamp value
            j.add(0x808).cast::<u32>().write_volatile(n); // job ID (unique u32)
            j.add(0x80C).cast::<u32>().write_volatile(n - 1); // the queue's CL counter
            job.notifier
                .raw_ptr()
                .add(8)
                .cast::<u32>()
                .write_volatile(n); // the notifier key
            let s = job.stream.raw_ptr();
            s.add(0x34).cast::<u32>().write_volatile(n); // context +0x30 the notifier key
            s.add(0x50).cast::<u32>().write_volatile(n); // context +0x4C job ID
            s.add(0x1AC).cast::<u64>().write_volatile(u64::from(n)); // context +0x1A8 jobState+0x04
            s.add(0x1F0).cast::<u32>().write_volatile(n); // first timestamp: job ID
            s.add(0x230).cast::<u32>().write_volatile(n); // second timestamp: job ID
            s.add(0x25C).cast::<u32>().write_volatile(n); // start +0x24 job ID
            s.add(0x268).cast::<u32>().write_volatile(stamp); // start +0x30 the stamp value
            ch.chan_cached
                .raw_ptr()
                .add(((n - 1) % 256) as usize * 8)
                .cast::<u64>()
                .write_volatile(js); // record slot n-1
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
            let storage = ring.add(CL_RING * fw::g15::RING_STRIDE + 8 + (idx % 256) as usize * 24);
            storage.cast::<u64>().write_volatile(0); // +0x00 timestamp
            storage.add(8).cast::<u64>().write_volatile(state_va); // +0x08 state FWVA
            storage.add(0x10).cast::<u32>().write_volatile(2); // +0x10 class = CL
            storage
                .add(0x14)
                .cast::<u16>()
                .write_volatile((job.n % 256) as u16); // +0x14 command ID
            storage.add(0x16).write_volatile(ch.stamp_index as u8); // +0x16 stamp index
            storage.add(0x17).write_volatile(1); // +0x17 flag (processed when != 0)
            crate::mem::dc_civac(storage, 24); // the entry first, then the index
            kernel::time::delay::udelay(Delta::from_micros(G15_PUBLISH_GAP_US));
            ring.add(CL_RING * fw::g15::RING_STRIDE)
                .cast::<u32>()
                .write_volatile((idx + 1) % 256);
            crate::mem::dc_civac(ring.add(CL_RING * fw::g15::RING_STRIDE), 4);
        }
        drop(rings);
        ch.submitted = job.n;
        self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(2))
    }

    /// Submits `job` on `chan` and tracks it: `done` runs once the job is
    /// complete.
    pub(crate) fn g15_cl_run(
        &self,
        chan: &Arc<Mutex<G15ClChannel>>,
        mut job: G15ClJob,
        vm: mmu::VmBind,
        done: KBox<dyn FnMut(Option<Error>) + Send>,
    ) -> Result {
        // A submission that meets a firmware stop waits for the resume
        // without the channel lock, then submits again (`g15_ring_room`
        // takes no ring entry and writes nothing before it returns
        // `EAGAIN`).
        loop {
            // The guard goes at the end of this statement, before the wait.
            let r = self.g15_cl_submit(&mut chan.lock(), &mut job);
            match r {
                Err(e) if e == EAGAIN => self.g15_wait_resume()?,
                r => break r?,
            }
        }
        mod_dev_dbg!(
            self.dev,
            "G15: CL job {} rung (ctx {}, stamp {:#x})\n",
            job.n,
            job.ctx,
            job.stamp
        );
        self.g15.pending.lock().push(
            G15ClPending {
                chan: chan.clone(),
                stamp: job.stamp,
                n: job.n,
                ctx: job.ctx,
                ta: None,
                _work: G15Work::Cl(job),
                _vm: vm,
                done,
                signaled: false,
                error: None,
                nudge: Instant::<Monotonic>::now(),
                nudges: 0,
                fw_at: None,
            },
            GFP_KERNEL,
        )?;
        // The job may already be complete; otherwise the poller watches it.
        self.g15_cl_retire();
        if let Some(kick) = self.g15.kick.lock().as_ref() {
            kick();
        }
        Ok(())
    }
}
