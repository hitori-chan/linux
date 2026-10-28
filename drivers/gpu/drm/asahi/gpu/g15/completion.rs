// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 job completion.
//!
//! A job is complete when its channel's host stamp word reaches its stamp:
//! the firmware's notifier walk writes it at the end of the job's
//! post-processing. The firmware stamp word, which the firmware's in-order
//! retire writes, says when the job's buffers may go. Both are polled: the
//! interrupt that announces a completion can come before the stamps, or not
//! at all.
//!
//! Spec: channel-table.md, cl-container.md, ring-races.md, submit-races.md.

use super::*;

/// How long after a pass's firmware stamp its TA's host stamp word may stay
/// behind before the pass's buffers go anyway.
const G15_TA_HOST_MS: i64 = 1000;

/// What ran a retire: the drain of a firmware event ring (the interrupt
/// thread), the poller, or a submission.
#[derive(Clone, Copy)]
pub(super) enum G15Retirer {
    Irq,
    Poll,
    Submit,
}

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

/// A channel error (event 8, faults.md): the firmware killed a job (kind 1,
/// the CL kill of a channel above stage 0), a 3D job hit a memory failure
/// (kind 0) or another error (2 to 4) stalled the channel.
pub(crate) struct G15ChanErr {
    pub(crate) kind: u32,
    /// The data master: 0 TA, 1 3D, 2 CL.
    pub(crate) dm: u32,
    /// The stamp index and value of the job.
    pub(crate) index: u32,
    pub(crate) stamp: u32,
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
    /// The process that owns the job's channel, for the per-process counters.
    pub(super) pid: u32,
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
    /// When the job was submitted.
    pub(super) since: Instant<Monotonic>,
    /// When the firmware stamp word was first seen at the job's stamp.
    pub(super) fw_at: Option<Instant<Monotonic>>,
    /// Whether the host stamp word was still behind `G15_HOST_STAMP_LATE_MS`
    /// after the firmware stamp word, and has not come yet.
    pub(super) late: bool,
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Holds back the rest of a submission: the poller calls `f`, which
    /// submits what it can, until it returns true.
    /// Starts the poller if it is idle; `soon` also brings a queued pass
    /// forward to the next jiffy, for work that should not wait for the
    /// slow tick (`asahi.g15_poll_ms`).
    /// Tracks a rung job until it completes. `gen` is the host stop its
    /// channel was set up after (`G15State::reset_gen`), read under the
    /// channel lock: a later one did not see the job, may have set the
    /// channel's stamp words past it and skipped its ring entry, so the job
    /// fails as that stop's own jobs did. With no memory for the list, the
    /// job fails and its buffers, which the firmware may already read, are
    /// leaked rather than freed under it.
    pub(super) fn g15_track(&self, mut p: G15ClPending, gen: u32) {
        let mut list = self.g15.pending.lock();
        let e = if self.g15.reset_gen.load(Ordering::Relaxed) != gen {
            ECANCELED
        } else if list.reserve(1, GFP_KERNEL).is_ok() {
            // Room reserved under the lock: the push cannot fail.
            let _ = list.push_within_capacity(p);
            drop(list);
            // The job may already be complete; otherwise the poller watches it.
            self.g15_cl_retire(G15Retirer::Submit);
            self.g15_kick(false);
            return;
        } else {
            ENOMEM
        };
        drop(list);
        dev_err!(
            self.dev.as_ref(),
            "G15: job {} (stamp index {}) not tracked: {e:?}\n",
            p.n,
            p.chan.lock().stamp_index
        );
        (p.done)(Some(e));
        if e == ENOMEM {
            core::mem::forget(p);
        }
    }

    pub(super) fn g15_kick(&self, soon: bool) {
        if let Some(kick) = self.g15.kick.lock().as_ref() {
            kick(soon);
        }
    }

    pub(crate) fn g15_defer(&self, f: KBox<dyn FnMut() -> bool + Send>) -> Result {
        self.g15.deferred.lock().push(f, GFP_KERNEL)?;
        self.g15_kick(true);
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
        // A mutex, so the push may sleep: GFP_ATOMIC failed more readily, and
        // a lost submission leaves its queue stuck.
        let mut list = self.g15.deferred.lock();
        for f in todo.drain_all() {
            if list.push(f, GFP_KERNEL).is_err() {
                dev_err!(self.dev.as_ref(), "G15: a held-back submission was lost\n");
            }
        }
    }

    /// Whether either stamp word has reached `stamp`.
    pub(super) fn g15_cl_done(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        let (host, fwst) = ch.words();
        reached(host, stamp) || reached(fwst, stamp)
    }

    /// Whether the host stamp word has reached `stamp`.
    pub(super) fn g15_cl_host_done(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        reached(ch.words().0, stamp)
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
            (&mut guard.rt, all),
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

    /// Counts how long after its firmware stamp a late host stamp word came.
    fn g15_host_after(&self, p: &mut G15ClPending) {
        if !p.late {
            return;
        }
        p.late = false;
        let us = p.fw_at.map_or(0, |t| t.elapsed().as_micros_ceil()) as u64;
        let b = [10_000, 100_000, 1_000_000]
            .iter()
            .take_while(|&&l| us >= l)
            .count();
        self.g15.host_stamp_after[b].fetch_add(1, Ordering::Relaxed);
        self.g15
            .host_stamp_after_max_us
            .fetch_max(us, Ordering::Relaxed);
    }

    /// Runs `done` for every submitted job that completed, and frees the
    /// buffers of those the firmware has retired and unlinked.
    pub(super) fn g15_cl_retire(&self, by: G15Retirer) {
        let mut retired = KVec::new();
        let mut pending = self.g15.pending.lock();
        let mut i = 0;
        while i < pending.len() {
            // `gone`: the firmware has retired the job (its stamp word), and
            // only then may its buffers go. The retire can come after the
            // completion event.
            let (host, gone) = {
                let p = &pending[i];
                let (h, f) = p.chan.lock().words();
                (reached(h, p.stamp), reached(f, p.stamp))
            };
            // The walk takes a node's entries by context slot, lowest first,
            // and reads each one just before it stores its host word. A
            // pass's TA and 3D entries are stored one after the other, so
            // the TA's host word can come after the 3D's, and the TA job's
            // state must outlive it. A walk takes microseconds: a host word
            // still missing G15_TA_HOST_MS after the firmware stamp is not
            // coming, and the pass goes.
            let ta_done = pending[i].ta.as_ref().is_none_or(|(tc, st)| {
                let tc = tc.lock();
                self.g15_cl_host_done(&tc, *st)
            });
            let ta_host = ta_done
                || pending[i]
                    .fw_at
                    .is_some_and(|t| t.elapsed() >= Delta::from_millis(G15_TA_HOST_MS));
            let p = &mut pending[i];
            // A job completes on the host stamp word, as on macOS
            // (`IOGPUEventMachine::testEvent`). The firmware stamp can come
            // first, before the job's stores have all landed (a vertex
            // stage's transform feedback writes arrived up to 2 ms after it
            // under load). The walk writes the host word in key order, so the
            // notifier keys grow (`ntf_keys`); a host word still behind
            // G15_HOST_STAMP_LATE_MS later is counted (submit-races.md).
            let fresh = gone && p.fw_at.is_none();
            if fresh {
                p.fw_at = Some(Instant::<Monotonic>::now());
            }
            if !host
                && !p.late
                && p.fw_at
                    .is_some_and(|t| t.elapsed() >= Delta::from_millis(G15_HOST_STAMP_LATE_MS))
            {
                self.g15.host_stamp_late.fetch_add(1, Ordering::Relaxed);
                p.late = true;
            }
            if host {
                self.g15_host_after(p);
            }
            if host && !p.signaled {
                mod_dev_dbg!(
                    self.dev,
                    "G15: job {} (stamp {:#x}) complete\n",
                    p.n,
                    p.stamp
                );
                p.signaled = true;
                self.g15.completed_by[by as usize].fetch_add(1, Ordering::Relaxed);
                if fresh && matches!(by, G15Retirer::Poll) {
                    self.g15.poll_first.fetch_add(1, Ordering::Relaxed);
                }
                {
                    let mut ch = p.chan.lock();
                    if p.stamp.wrapping_sub(ch.completed) as i32 > 0 {
                        ch.completed = p.stamp;
                    }
                }
                (p.done)(p.error.take());
            }
            if p.signaled && gone && ta_host && !p._work.notifier_listed() {
                if !ta_done {
                    dev_warn!(
                        self.dev.as_ref(),
                        "G15: job {} retired without its TA's host stamp\n",
                        p.n
                    );
                }
                // The walk unlinks the notifier as it writes the host word.
                self.g15_host_after(p);
                self.g15.perf.retired(&p._work, p.pid);
                // A mutex: the reserve may sleep, and the job is freed
                // outside the lock.
                if retired.reserve(1, GFP_KERNEL).is_err() {
                    break;
                }
                let _ = retired.push_within_capacity(pending.swap_remove(i));
            } else {
                i += 1;
            }
        }
        core::mem::drop(pending);
        // The retired jobs' buffers are freed here, outside the lock.
        core::mem::drop(retired);
    }

    /// Answers the channel errors (event 8) as the kext's
    /// `drainFirmwareEventRing` does: fails the job the error names and sends
    /// device control 8 (`{8, data master, the channel state's firmware VA,
    /// stamp}` at +0x00, +0x04, +0x08 and +0x10), which lowers the stall
    /// count the error raised and wakes the data master's scheduler. Runs in
    /// the poller.
    pub(super) fn g15_chan_errs_pending(&self) {
        let errs = core::mem::take(&mut *self.g15.chan_errs.lock());
        for e in errs.iter() {
            let err = match e.kind {
                0 => ENOMEM,
                1 => ETIMEDOUT,
                _ => EIO,
            };
            let mut state_va = None;
            for p in self.g15.pending.lock().iter_mut() {
                // One channel lock at a time: a submission takes the TA's
                // before the 3D's.
                let d3 = {
                    let ch = p.chan.lock();
                    (ch.stamp_index == e.index && p.stamp == e.stamp)
                        .then(|| ch.state.gpu_va().get())
                };
                let va = d3.or_else(|| {
                    p.ta.as_ref().and_then(|(tc, st)| {
                        let tc = tc.lock();
                        (tc.stamp_index == e.index && *st == e.stamp)
                            .then(|| tc.state.gpu_va().get())
                    })
                });
                if va.is_some() {
                    p.error.get_or_insert(err);
                    state_va = va;
                    break;
                }
            }
            let Some(va) = state_va else {
                dev_err!(
                    self.dev.as_ref(),
                    "G15: channel error at stamp index {} stamp {:#x}: no such job\n",
                    e.index,
                    e.stamp
                );
                continue;
            };
            let mut msg = [0u32; 14];
            msg[0] = 8;
            msg[1] = e.dm;
            msg[2] = va as u32;
            msg[3] = (va >> 32) as u32;
            msg[4] = e.stamp;
            if let Err(err) = self.g15_ctl_send(&msg) {
                dev_err!(
                    self.dev.as_ref(),
                    "G15: channel error answer not sent ({err:?})\n"
                );
            }
        }
    }

    /// One pass of the completion poller: retire what completed, advance the
    /// held-back submissions, and ring again what the firmware has not
    /// picked up. Returns the jiffies to the next pass while work is
    /// pending: one while a finished job waits for its host word or the host
    /// owes the firmware an answer, else `asahi.g15_poll_ms`.
    pub(crate) fn g15_poll_work(&self) -> Option<kernel::time::Jiffies> {
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
            return None;
        }
        self.g15_cl_retire(G15Retirer::Poll);
        // Only this check ends a host stop's restart, and a held-back
        // submission that meets a stopped firmware waits in this worker for
        // the resume: check first, and hold the submissions back while the
        // firmware is stopped.
        self.g15_check_restart();
        if !self.g15_fw_stopped() {
            // First: a held-back submission can wait for ring room behind a
            // TA that waits for pages or a stalled channel.
            self.g15_chan_errs_pending();
            self.g15_pb_grow_pending();
            self.g15_run_deferred();
        }
        self.g15_collect_garbage();
        self.g15_reclaim_dead();
        let reaping = self.g15_uma_reap();
        // Before `stopped`: the check can stop the firmware.
        self.g15_check_progress();
        // A stopped firmware takes no doorbell, and a mailbox full of them
        // crashes it (`MBI queue overflow: gfx_ints`): ring nothing until the
        // resume.
        let stopped = self.g15_fw_stopped();
        // A ring with entries whose read index has not moved for
        // RING_STALL_US is a stall, counted when it ends by how long the index
        // stood still. The firmware clears its event word before each
        // consumer pass (agx_background), so a doorbell during a pass brings
        // another: no ring needs a second doorbell (ring-races.md).
        const RING_STALL_US: i64 = 1000;
        {
            let mut stall = self.g15.ring_stall.lock();
            for (class, (since, read, stuck)) in stall.iter_mut().enumerate() {
                let r = match self.g15_ring_unconsumed(fw::g15::ring(class)) {
                    Some(r) if !stopped => Some(r),
                    Some(_) => None,
                    None => {
                        // Consumed: a stall ends.
                        if let Some(t) = stuck.take() {
                            self.g15_ring_stalled(t);
                        }
                        None
                    }
                };
                let Some(r) = r else {
                    *since = None;
                    *stuck = None;
                    continue;
                };
                if r != *read {
                    if let Some(t) = stuck.take() {
                        self.g15_ring_stalled(t);
                    }
                    *read = r;
                    *since = None;
                }
                let t = *since.get_or_insert_with(Instant::<Monotonic>::now);
                if t.elapsed() >= Delta::from_micros(RING_STALL_US) {
                    stuck.get_or_insert(t);
                }
            }
        }
        // A job the firmware has finished whose host word has not come.
        let (pending, trailing) = {
            let pending = self.g15.pending.lock();
            let trailing = pending.iter().any(|p| !p.signaled && p.fw_at.is_some());
            (!pending.is_empty(), trailing)
        };
        let urgent = trailing
            || !self.g15.deferred.lock().is_empty()
            || !self.g15.pb_grow_reqs.lock().is_empty()
            || !self.g15.chan_errs.lock().is_empty()
            || reaping
            || self.g15.restarting.load(Ordering::Relaxed);
        if urgent {
            Some(1)
        } else if pending {
            let ms = (*crate::module_parameters::g15_poll_ms.value()).max(1);
            Some(kernel::time::msecs_to_jiffies(ms))
        } else {
            None
        }
    }

    /// Counts a ring stall that ended, by how long since `t` its read index
    /// stood still.
    fn g15_ring_stalled(&self, t: Instant<Monotonic>) {
        let us = t.elapsed().as_micros_ceil() as u64;
        let b = [2_000, 10_000, 100_000]
            .iter()
            .take_while(|&&l| us >= l)
            .count();
        self.g15.ring_stalls[b].fetch_add(1, Ordering::Relaxed);
        self.g15.ring_stall_max_us.fetch_max(us, Ordering::Relaxed);
    }

    /// Asks the poller for a host stop, for a job the DRM scheduler timed
    /// out: it fails every job in flight, the hung one included.
    pub(crate) fn g15_ask_stop(&self) {
        self.g15.stop_asked.store(true, Ordering::Relaxed);
        self.g15_kick(true);
    }

    /// The host's progress check (the kext's progress timer): a job left
    /// unfinished while the firmware's progress word (event page `+0x45C0`,
    /// `AGXArmFirmware::checkGPUProgress`) stays put for `G15_PROGRESS_MS` is
    /// a hang the firmware did not catch, and so is a destroyed queue's job
    /// left unfinished for `G15_DEAD_MS` (the firmware raises the word for
    /// every CL slot whose counters move, so a shader that spins forever
    /// moves it) and a job the DRM scheduler timed out. The host then stops
    /// the firmware (`stopFirmwareForRecoveryInspection`: message 0x85 with
    /// the stop count), at most once per `G15_PROGRESS_MS`, and waits for
    /// the stop, which posts no record: the stop count passes the one sent
    /// and the stopped flag is set. `g15_recovery` then sets things up again
    /// before it resumes.
    fn g15_check_progress(&self) {
        // The oldest unfinished job's age: the GPU has had work that long.
        let oldest = self
            .g15
            .pending
            .lock()
            .iter()
            .filter(|p| !p.signaled)
            .map(|p| p.since.elapsed())
            .max();
        let unfinished = oldest.is_some();
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
        // The word stays put while the GPU is idle, and the poller, which
        // stops then, last saw it before: the stall counts from the later of
        // its last move and the oldest unfinished job's submission.
        let stalled = {
            let mut pr = self.g15.progress.lock();
            if pr.0 != progress || !unfinished {
                *pr = (progress, Instant::<Monotonic>::now());
            }
            oldest.is_some_and(|a| a.min(pr.1.elapsed()) >= Delta::from_millis(G15_PROGRESS_MS))
        };
        let dead = self
            .g15
            .dead_chans
            .lock()
            .iter()
            .any(|(_, t)| t.elapsed() >= Delta::from_millis(G15_DEAD_MS));
        // A request a recovery or another host stop overtakes is dropped:
        // either failed the job too.
        let asked = self.g15.stop_asked.swap(false, Ordering::Relaxed) && unfinished;
        if !(stalled || dead || asked) || self.g15_fw_stopped() {
            return;
        }
        let mut last = self.g15.host_stop.lock();
        if last.is_some_and(|t| t.elapsed() < Delta::from_millis(G15_PROGRESS_MS)) {
            return;
        }
        *last = Some(Instant::<Monotonic>::now());
        if stalled {
            dev_err!(
                self.dev.as_ref(),
                "G15: no GPU progress for {G15_PROGRESS_MS} ms with a job unfinished: host stop (stop count {count})\n"
            );
        } else if dead {
            dev_err!(
                self.dev.as_ref(),
                "G15: a destroyed queue's job unfinished for {G15_DEAD_MS} ms: host stop (stop count {count})\n"
            );
        } else {
            dev_err!(
                self.dev.as_ref(),
                "G15: a job timed out on the DRM scheduler: host stop (stop count {count})\n"
            );
        }
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
