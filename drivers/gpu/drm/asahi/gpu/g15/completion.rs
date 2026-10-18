// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 job completion.
//!
//! A job is complete when its channel's host stamp word reaches its stamp:
//! the firmware's notifier walk writes it at the end of the job's
//! post-processing. The firmware stamp word, which the firmware's in-order
//! retire writes, says when the job's buffers may go. Both are polled: the
//! interrupt that announces a completion can come before the stamps, or not
//! at all.

use super::*;

/// The buffers of submitted work, kept until it retires.
#[allow(
    clippy::large_enum_variant,
    reason = "a few in flight; boxing adds an allocation per job"
)]
pub(super) enum G15Work {
    Cl(G15ClJob),
    Rd(KBox<G15RdPass>),
}

impl G15Work {
    /// Whether the firmware still lists the work's notifier in its channel's
    /// notifier list (+0x94: the insert sets it, the walk's unlink clears
    /// it). The walk follows a listed node to the job's stamp entries, so
    /// they must stay allocated until the node is unlinked, even after the
    /// firmware stamp has passed.
    pub(super) fn notifier_listed(&self) -> bool {
        let n = match self {
            G15Work::Cl(j) => &j.notifier,
            G15Work::Rd(p) => p.notifier(),
        };
        let f = n.raw_ptr().wrapping_add(0x94);
        crate::mem::dc_civac(f.cast_const(), 4);
        // SAFETY: an in-bounds u32 read of the 0x100-byte notifier.
        unsafe { (f as *const u32).read_volatile() != 0 }
    }
}

/// Submitted work waiting for its stamp: a compute job, or a render pass on
/// its 3D job's channel and stamp. `done` runs once the job is complete;
/// the buffers go once the firmware has also retired it.
pub(crate) struct G15ClPending {
    pub(super) chan: Arc<Mutex<G15ClChannel>>,
    pub(super) stamp: u32,
    /// The job's number on its channel and its context, for diagnostics.
    pub(super) n: u32,
    pub(super) ctx: u32,
    /// For a render pass, its TA job's channel and stamp: a recovery can
    /// catch either job.
    pub(super) ta: Option<(Arc<Mutex<G15ClChannel>>, u32)>,
    pub(super) _work: G15Work,
    /// The job's VM, bound to its context slot until the job's buffers go.
    /// Otherwise a queue torn down with the job still in the firmware would
    /// free the slot, another process's VM could take it, and the job would
    /// run in that VM.
    pub(super) _vm: mmu::VmBind,
    pub(super) done: KBox<dyn FnMut(Option<Error>) + Send>,
    pub(super) signaled: bool,
    /// The job's failure, set by a recovery that caught it.
    pub(super) error: Option<Error>,
    /// When the job's doorbells were last rung: at submission, then by the
    /// poller while the job is unfinished.
    pub(super) nudge: Instant<Monotonic>,
    pub(super) nudges: u32,
    /// When the firmware stamp word was first seen at the job's stamp.
    pub(super) fw_at: Option<Instant<Monotonic>>,
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Holds back the rest of a submission: the poller calls `f`, which
    /// submits what it can, until it returns true.
    pub(crate) fn g15_defer(&self, f: KBox<dyn FnMut() -> bool + Send>) -> Result {
        self.g15.deferred.lock().push(f, GFP_KERNEL)?;
        if let Some(kick) = self.g15.kick.lock().as_ref() {
            kick();
        }
        Ok(())
    }

    /// Advances the held-back submissions, outside the list's lock: they
    /// submit, and a submission may hold back more.
    pub(super) fn g15_run_deferred(&self) {
        let mut todo = core::mem::take(&mut *self.g15.deferred.lock());
        let mut i = 0;
        while i < todo.len() {
            if (todo[i])() {
                drop(todo.swap_remove(i));
            } else {
                i += 1;
            }
        }
        let mut list = self.g15.deferred.lock();
        for f in todo.drain_all() {
            if list.push(f, GFP_ATOMIC).is_err() {
                dev_err!(self.dev.as_ref(), "G15: a held-back submission was lost\n");
            }
        }
    }

    /// Whether either stamp word has reached `stamp` (a signed comparison,
    /// as `IOGPUEventMachine::testEvent`).
    pub(super) fn g15_cl_done(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        crate::mem::dc_civac(ch.words.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds u32 reads of the channel's own stamp words.
        let (host, fwst) = unsafe {
            let w = ch.words.raw_ptr() as *const u32;
            (w.read_volatile(), w.add(1).read_volatile())
        };
        host.wrapping_sub(stamp) as i32 >= 0 || fwst.wrapping_sub(stamp) as i32 >= 0
    }

    /// Whether the host stamp word has reached `stamp`.
    pub(super) fn g15_cl_host_done(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        crate::mem::dc_civac(ch.words.raw_ptr().cast_const(), 8);
        // SAFETY: an in-bounds u32 read of the channel's own stamp words.
        let host = unsafe { (ch.words.raw_ptr() as *const u32).read_volatile() };
        host.wrapping_sub(stamp) as i32 >= 0
    }

    /// Whether the firmware has retired the job at `stamp`: only then may
    /// its buffers go. The retire can come after the completion event.
    pub(super) fn g15_cl_retired(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        // SAFETY: an in-bounds u32 read of the channel's own stamp words.
        let fwst = unsafe { (ch.words.raw_ptr() as *const u32).add(1).read_volatile() };
        fwst.wrapping_sub(stamp) as i32 >= 0
    }

    /// Releases the oldest held-back job buffers once enough newer ones
    /// wait.
    pub(super) fn g15_collect_garbage(&self) {
        let mut guard = self.alloc.lock();
        let guard = &mut *guard;
        let all = (G15_QUARANTINE_BYTES_HIGH, G15_QUARANTINE_BYTES_KEEP);
        for (a, (high, keep)) in [
            (&mut guard.shared, all),
            (&mut guard.gpu, all),
            (&mut guard.fw_nc, G15_QUARANTINE_FW_NC_BYTES),
            (&mut guard.gpu_fw_nc, G15_QUARANTINE_GPU_FW_NC_BYTES),
        ] {
            let (n, bytes) = a.garbage();
            let mut count = if n > G15_QUARANTINE_HIGH {
                n - G15_QUARANTINE_KEEP
            } else {
                0
            };
            if bytes > high {
                count = count.max(a.garbage_over(keep));
            }
            if count > 0 {
                a.collect_garbage(count);
            }
        }
    }

    /// Runs `done` for every submitted job that completed, and frees the
    /// buffers of those the firmware has retired and unlinked.
    pub(super) fn g15_cl_retire(&self) {
        let mut retired = KVec::new();
        let mut pending = self.g15.pending.lock();
        let mut i = 0;
        while i < pending.len() {
            let (host, gone) = {
                let p = &pending[i];
                let ch = p.chan.lock();
                (
                    self.g15_cl_host_done(&ch, p.stamp),
                    self.g15_cl_retired(&ch, p.stamp),
                )
            };
            let p = &mut pending[i];
            // A job completes on the host stamp word, as on macOS. The
            // firmware stamp can come first, before the job's stores have
            // all landed (a vertex stage's transform feedback writes arrived
            // up to 2 ms after it under load), so it completes a job only
            // after G15_HOST_STAMP_MS: the notifier walk can skip the last
            // jobs of a burst for good.
            if gone && p.fw_at.is_none() {
                p.fw_at = Some(Instant::<Monotonic>::now());
            }
            let late = p
                .fw_at
                .is_some_and(|t| t.elapsed() >= Delta::from_millis(G15_HOST_STAMP_MS));
            if !host && late && !p.signaled {
                self.g15.host_stamp_late.fetch_add(1, Ordering::Relaxed);
            }
            let complete = host || late;
            if complete && !p.signaled {
                mod_dev_dbg!(
                    self.dev,
                    "G15: job {} (stamp {:#x}) complete\n",
                    p.n,
                    p.stamp
                );
                p.signaled = true;
                (p.done)(p.error.take());
            }
            if p.signaled && gone && !p._work.notifier_listed() {
                if retired.push(pending.swap_remove(i), GFP_ATOMIC).is_err() {
                    break;
                }
            } else {
                i += 1;
            }
        }
        core::mem::drop(pending);
        // The retired jobs' buffers are freed here, outside the lock.
        core::mem::drop(retired);
    }

    /// One pass of the completion poller: retire what completed, advance the
    /// held-back submissions, and ring again what the firmware has not
    /// picked up. Returns whether work is still pending.
    pub(crate) fn g15_poll_work(&self) -> bool {
        if self.is_crashed() {
            // A crashed firmware runs nothing more: fail every pending job
            // once (its buffers stay, since what the GPU last read is
            // unknown), let the held-back submissions fail, and ring
            // nothing. Otherwise the fences never signal and every queue
            // teardown waits out its timeout.
            for p in self.g15.pending.lock().iter_mut() {
                if !p.signaled {
                    p.signaled = true;
                    (p.done)(Some(ENODEV));
                }
            }
            self.g15_run_deferred();
            return false;
        }
        self.g15_cl_retire();
        self.g15_run_deferred();
        self.g15_collect_garbage();
        self.g15_reclaim_dead();
        self.g15_check_restart();
        // A job still unfinished G15_NUDGE_MS after its doorbell gets its
        // classes rung again: the firmware's scheduler can skip a job whose
        // ring entry it has consumed.
        const G15_NUDGE_MS: i64 = 200;
        // A stopped firmware takes no doorbell, and a mailbox full of them
        // crashes it (`MBI queue overflow: gfx_ints`): ring nothing until the
        // resume.
        let stopped = self.g15_fw_stopped();
        let mut nudge = [false; 3];
        let mut first_nudge = false;
        for p in self.g15.pending.lock().iter_mut() {
            if !stopped && !p.signaled && p.nudge.elapsed() >= Delta::from_millis(G15_NUDGE_MS) {
                first_nudge |= p.nudges == 0;
                p.nudges += 1;
                p.nudge = Instant::<Monotonic>::now();
                if p.ta.is_some() {
                    nudge[0] = true;
                    nudge[1] = true;
                } else {
                    nudge[2] = true;
                }
            }
        }
        if first_nudge {
            // The firmware's trace up to the stall, before the nudges'
            // passes overwrite it.
            self.g15_trace_dump(64);
        }
        self.g15_check_progress();
        for (class, bell) in nudge.iter().enumerate() {
            if *bell {
                self.g15.nudges.fetch_add(1, Ordering::Relaxed);
                let _ = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(class as u64));
            }
        }
        // A ring whose entries the firmware has not consumed RING_STALL_US
        // after the doorbell gets it again: a doorbell that arrives while the
        // firmware is scanning the rings is absorbed, and an entry written
        // after the scan passed its ring waits for the next doorbell.
        const RING_STALL_US: i64 = 1000;
        let mut bells = [false; 3];
        {
            let mut stall = self.g15.ring_stall.lock();
            for (class, since) in stall.iter_mut().enumerate() {
                if stopped || !self.g15_ring_unconsumed(fw::g15::ring(class)) {
                    *since = None;
                } else if since
                    .get_or_insert_with(Instant::<Monotonic>::now)
                    .elapsed()
                    >= Delta::from_micros(RING_STALL_US)
                {
                    *since = Some(Instant::<Monotonic>::now());
                    bells[class] = true;
                }
            }
        }
        let busy = !self.g15.pending.lock().is_empty()
            || !self.g15.deferred.lock().is_empty()
            || self.g15.restarting.load(Ordering::Relaxed);
        for (class, bell) in bells.iter().enumerate() {
            if *bell {
                self.g15.rerings.fetch_add(1, Ordering::Relaxed);
                mod_dev_dbg!(
                    self.dev,
                    "G15: ring {} holds unconsumed entries: re-ringing\n",
                    fw::g15::ring(class)
                );
                let _ = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(class as u64));
            }
        }
        busy
    }

    /// The host's progress check (the kext's progress timer): a job left
    /// unfinished while the firmware's progress word (event page `+0x45C0`,
    /// `AGXArmFirmware::checkGPUProgress`) stays put for `G15_PROGRESS_MS` is
    /// a hang the firmware did not catch. The host then stops the firmware
    /// (`stopFirmwareForRecoveryInspection`: message 0x85 with the stop
    /// count), at most once per `G15_PROGRESS_MS`, and waits for the stop,
    /// which posts no record: the stop count passes the one sent and the
    /// stopped flag is set. `g15_recovery` then sets things up again before
    /// it resumes.
    fn g15_check_progress(&self) {
        let unfinished = self.g15.pending.lock().iter().any(|p| !p.signaled);
        let e = self.initdata.event_page.raw_ptr().cast::<u8>();
        crate::mem::dc_civac(e.wrapping_add(0x4580).cast_const(), 0x48);
        // SAFETY: in-bounds u64 and u32 reads of the event page.
        let (count, progress) = unsafe {
            (
                (e.add(0x4580) as *const u64).read_volatile(),
                (e.add(0x45C0) as *const u32).read_volatile(),
            )
        };
        // A stop with no record that the host did not ask for (with the
        // recovery block's host-requested word left set, every stuck-job
        // event stops the firmware so) waits for a resume no record will
        // bring: take it as a host stop.
        const G15_SILENT_STOP_MS: i64 = 500;
        if self.g15_fw_stop_flag() && !self.g15.restarting.load(Ordering::Acquire) {
            let silent = self
                .g15
                .stop_seen
                .lock()
                .get_or_insert_with(Instant::<Monotonic>::now)
                .elapsed()
                >= Delta::from_millis(G15_SILENT_STOP_MS);
            if silent {
                *self.g15.stop_seen.lock() = None;
                // As a stop the drain finds, and only if no recovery took it
                // meanwhile.
                let _guard = self.g15.drain_lock.lock();
                crate::mem::dc_civac(e.wrapping_add(0x4580).cast_const(), 0x14);
                // SAFETY: an in-bounds u64 read of the event page.
                let now = unsafe { (e.add(0x4580) as *const u64).read_volatile() };
                if now == count && self.g15_fw_stop_flag() {
                    dev_err!(
                        self.dev.as_ref(),
                        "G15: the firmware stopped with no record (stop count {count}): taken as a host stop\n"
                    );
                    self.g15_recovery(count.wrapping_sub(1), 0);
                }
            }
            return;
        }
        *self.g15.stop_seen.lock() = None;
        let stalled = {
            let mut pr = self.g15.progress.lock();
            if pr.0 != progress || !unfinished {
                *pr = (progress, Instant::<Monotonic>::now());
            }
            pr.1.elapsed() >= Delta::from_millis(G15_PROGRESS_MS)
        };
        if !stalled || self.g15_fw_stopped() {
            return;
        }
        let mut last = self.g15.host_stop.lock();
        if last.is_some_and(|t| t.elapsed() < Delta::from_millis(G15_PROGRESS_MS)) {
            return;
        }
        *last = Some(Instant::<Monotonic>::now());
        dev_err!(
            self.dev.as_ref(),
            "G15: no GPU progress for {G15_PROGRESS_MS} ms with a job unfinished: host stop (stop count {count})\n"
        );
        drop(last);
        if self
            .g15_send(EP_DOORBELL, MSG_HOST_STOP | (count & ((1 << 44) - 1)))
            .is_err()
        {
            return;
        }
        for _ in 0..1000 {
            crate::mem::dc_civac(e.wrapping_add(0x4580).cast_const(), 0x14);
            // SAFETY: in-bounds u64 and u32 reads of the event page.
            let (n, stopped) = unsafe {
                (
                    (e.add(0x4580) as *const u64).read_volatile(),
                    (e.add(0x4590) as *const u32).read_volatile(),
                )
            };
            if n > count && stopped != 0 {
                // As a stop the drain finds: one recovery at a time.
                let _guard = self.g15.drain_lock.lock();
                self.g15_recovery(count, 0);
                return;
            }
            kernel::time::delay::fsleep(Delta::from_millis(1));
        }
        dev_err!(
            self.dev.as_ref(),
            "G15: the firmware did not stop for the host\n"
        );
    }
}
