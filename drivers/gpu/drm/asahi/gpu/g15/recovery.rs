// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 recovery: the firmware's stops and the host's resume.

use super::*;

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: the firmware stopped for a recovery (a fault or a hang; spec:
    /// faults.md, "The firmware's recovery"): log what it caught, fail the
    /// guilty job, and let the firmware resume (it re-inits the GPU and
    /// retires the caught jobs).
    pub(super) fn g15_recovery(&self, count: u64, guilty: u32) {
        let dev = self.dev.as_ref();
        // G15 lab: the firmware's last events before the stop (the ktrace flag, `Debug4`).
        self.g15_trace_dump(160);
        let e = self.initdata.event_page.raw_ptr().cast::<u8>();
        crate::mem::dc_civac(e.wrapping_add(0x40A0).cast_const(), 0x524);
        let mut caught: KVec<(u32, u32, u32)> = KVec::new();
        // SAFETY: in-bounds u32/u64 accesses of the 0xC3D0 B event page.
        unsafe {
            let r32 = |off: usize| (e.add(off) as *const u32).read_volatile();
            dev_err!(dev, "G15: GPU stopped for recovery {}: {} caught job(s), guilty stamp {:#x}, pid {}, kill {}, fault bank {:#x}, busy {:#x}, stopped {}, host-requested {}\n",
                     count, r32(0x44A4), guilty, r32(0x44AC), r32(0x44B0),
                     (e.add(0x44B4) as *const u64).read_unaligned(),
                     (e.add(0x4560) as *const u64).read_unaligned(),
                     r32(0x4590), r32(0x45B0));
            for i in 0..0x80usize {
                let w = r32(0x40A0 + i * 8);
                if w & 1 == 0 {
                    break;
                }
                let v = r32(0x40A4 + i * 8);
                dev_err!(
                    dev,
                    "G15:   caught: stamp index {}, stamp {:#x}, flags {:#x}\n",
                    (w >> 4) & 0x7F,
                    v,
                    w & 0xE
                );
                let _ = caught.push(((w >> 4) & 0x7F, v, w), GFP_ATOMIC);
            }
        }
        // The TA jobs the table lists: every registered one (flags & 9 = 9),
        // anywhere in the table (the kext's processFirmwareTACommandsRecovery
        // walks all 128 entries).
        let mut tas: KVec<(u32, u32)> = KVec::new();
        // SAFETY: in-bounds u32 reads of the event page.
        unsafe {
            for i in 0..0x80usize {
                let w = (e.add(0x40A0 + i * 8) as *const u32).read_volatile();
                if w & 9 == 9 {
                    let _ = tas.push(
                        (
                            (w >> 4) & 0x7F,
                            (e.add(0x40A4 + i * 8) as *const u32).read_volatile(),
                        ),
                        GFP_ATOMIC,
                    );
                }
            }
        }
        let mut cleared = 0;
        let mut pbs = 0u64;
        for p in self.g15_pending.lock().iter_mut() {
            // Each parameter buffer with a pass in flight, once: the
            // firmware's counts at the stop (its walk gates a buffer whose 3D
            // completions differ from the host's count).
            if let G15Work::Rd(pass) = &p._work {
                let (id, c) = pass.pb_counts();
                if id < 64 && pbs & 1 << id == 0 {
                    pbs |= 1 << id;
                    dev_info!(dev, "G15:   PB {id}: 3D done {}, TA done {}, TAs in flight {}, gate {}, 3D submitted {}\n",
                              c[0], c[1], c[2], c[3], c[4]);
                }
            }
            let idx = p.chan.lock().stamp_index;
            let ta = p.ta.as_ref().map(|(c, st)| (c.lock().stamp_index, *st));
            if let Some(&(_, _, w)) = caught
                .iter()
                .find(|c| (c.0 == idx && c.1 == p.stamp) || ta == Some((c.0, c.1)))
            {
                p.error = Some(if w & 2 != 0 { EIO } else { ECANCELED });
            }
            // An unfinished listed TA starts again from an empty tail-pointer
            // cache, and its scene is aborted: the walk marks a TA in an
            // active slot done without running it, and its 3D would draw a
            // never-written tilemap. A TA that kicks again clears the mark.
            if let (Some((tc, st)), G15Work::Rd(pass)) = (p.ta.as_ref(), &p._work) {
                let tc = tc.lock();
                if tas.iter().any(|&(i, v)| i == tc.stamp_index && v == *st)
                    && !self.g15_cl_done(&tc, *st)
                {
                    pass.clear_tpc();
                    pass.abort_scene();
                    cleared += 1;
                }
            }
        }
        if cleared != 0 {
            dev_info!(dev, "G15:   {cleared} unfinished TA job(s): tail-pointer caches cleared, scenes aborted\n");
        }
        // The MMU fault at the stop, as the kext's restartWorkQueue reads it
        // (getMMUFaultInfo): the recovery handler selected the bank of the
        // latched fault and left it in effect. None for a hang (the CL
        // progress check's stop).
        if let Some(fi) = self.get_fault_info() {
            dev_err!(dev, "G15:   fault: {fi:x?}\n");
        } else {
            dev_err!(dev, "G15:   no MMU fault latched (a hang)\n");
        }
        // The pool, as the stop left it.
        if let Some(uma) = self.g15_uma.as_ref() {
            uma.log(dev.as_ref(), &self.initdata.umap_table, "at the stop");
        }
        // The firmware posts the record before it sets the stopped flag and
        // the stop count (agx_recovery_handler: +0x4590 = 1, ++(+0x4580),
        // then its wait for +0x45A0): a resume before that leaves +0x4590
        // set for good, and every later submit fails. Wait for the count.
        let mut waited = 0;
        loop {
            crate::mem::dc_civac(e.wrapping_add(0x4580).cast_const(), 0x14);
            // SAFETY: in-bounds u64/u32 reads of the event page.
            let (n, stopped) = unsafe {
                (
                    (e.add(0x4580) as *const u64).read_volatile(),
                    (e.add(0x4590) as *const u32).read_volatile(),
                )
            };
            if n > count && stopped != 0 {
                break;
            }
            if waited >= 100_000 {
                dev_err!(dev, "G15:   the firmware did not stop (count {n:#x}, stopped {stopped}); resuming anyway\n");
                break;
            }
            kernel::time::delay::udelay(kernel::time::Delta::from_micros(10));
            waited += 10;
        }
        // Resume (resumeFirmwareAfterRecovery): clear the stopped flag, then
        // set the resume word.
        // SAFETY: in-bounds u32 stores into the event page.
        unsafe {
            e.add(0x4590).cast::<u32>().write_volatile(0);
            core::sync::atomic::fence(Ordering::SeqCst);
            crate::mem::dc_civac(e.add(0x4590).cast_const(), 4);
            e.add(0x45A0).cast::<u32>().write_volatile(1);
            crate::mem::dc_civac(e.add(0x45A0).cast_const(), 4);
        }
        // Wake the submits that met the stop (`g15_wait_resume`): after the
        // flag is clear, under the lock they check it with.
        *self.g15_resumes.lock() += 1;
        self.g15_resume_cv.notify_all();
    }

    /// G15: whether the firmware is stopped for a recovery (event page
    /// `+0x4590`, set by the firmware, cleared by the host's resume).
    pub(super) fn g15_fw_stopped(&self) -> bool {
        let stopped = self
            .initdata
            .event_page
            .raw_ptr()
            .cast::<u8>()
            .wrapping_add(0x4590)
            .cast_const();
        crate::mem::dc_civac(stopped, 4);
        // SAFETY: an in-bounds u32 read of the event page.
        unsafe { stopped.cast::<u32>().read_volatile() != 0 }
    }

    /// G15: wait, holding no channel or ring lock, for the firmware to
    /// resume from a stop. A stopped firmware takes no ring entry, and the
    /// recovery needs the channel locks a waiting submit would hold. Failing
    /// the submit instead failed innocent processes' jobs at every stop
    /// (#288: GLES CTS flakes 59 -> 181). The kext's restart runs under its
    /// command gate, which its submits presumably also take (not verified).
    /// Fails after `G15_RESUME_WAIT_MS` (a firmware that never resumes) or
    /// once the firmware has crashed.
    pub(super) fn g15_wait_resume(&self) -> Result {
        let start = Instant::<Monotonic>::now();
        let mut resumes = self.g15_resumes.lock();
        loop {
            if self.crashed.load(Ordering::Relaxed) {
                return Err(ECANCELED);
            }
            // The resume clears the flag before it takes the lock to signal,
            // so a wakeup cannot fall between this check and the wait.
            if !self.g15_fw_stopped() {
                return Ok(());
            }
            let left = G15_RESUME_WAIT_MS - start.elapsed().as_millis();
            if left <= 0 {
                dev_err!(
                    self.dev.as_ref(),
                    "G15: the firmware did not resume in {G15_RESUME_WAIT_MS} ms; failing the submit\n"
                );
                return Err(ETIMEDOUT);
            }
            // Called from the scheduler's and the poller's workers, which
            // take no signals.
            let _ = self.g15_resume_cv.wait_interruptible_timeout(
                &mut resumes,
                kernel::time::msecs_to_jiffies(left as u32),
            );
        }
    }
}
