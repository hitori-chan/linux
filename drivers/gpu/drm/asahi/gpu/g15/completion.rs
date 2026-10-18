// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 job completion: the stamp words, retiring jobs and the poller.

use super::*;

/// G15: the buffers of submitted work, kept until it retires.
#[allow(
    clippy::large_enum_variant,
    reason = "a few in flight; boxing adds an allocation per job"
)]
pub(super) enum G15Work {
    Cl(G15ClJob),
    Rd(KBox<G15RdPass>),
}

impl G15Work {
    /// Whether the firmware still lists the work's notifier in its
    /// channel's notifier list (`+0x94`: the insert sets 1, the walk's
    /// unlink clears it). The walk follows a listed node to the job's stamp
    /// entries, so they stay allocated until the node is unlinked, even
    /// after the firmware stamp has passed (a freed one crashed the walk,
    /// a NULL store at `sub_FFFFFC000002749C+0x624`, 2026-10-17).
    pub(super) fn notifier_listed(&self) -> bool {
        let n = match self {
            G15Work::Cl(j) => &j.notifier,
            G15Work::Rd(p) => p.notifier(),
        };
        let f = n.raw_ptr().wrapping_add(0x94);
        crate::mem::dc_civac(f.cast_const(), 4);
        // SAFETY: an in-bounds u32 read of the 0x100 B notifier.
        unsafe { (f as *const u32).read_volatile() != 0 }
    }
}

/// G15: submitted work waiting for its stamp — a CL job, or a render
/// pass (on its 3D's channel and stamp): `done` runs once the channel's
/// host stamp word reaches it; the buffers go once the firmware stamp word
/// does too (the firmware's in-order retire comes after).
pub(crate) struct G15ClPending {
    pub(super) chan: Arc<Mutex<G15ClChannel>>,
    pub(super) stamp: u32,
    /// The job's number on its channel, and its context (diagnostics).
    pub(super) n: u32,
    pub(super) ctx: u32,
    /// A render pass: its TA's channel and stamp (a recovery can catch
    /// either job).
    pub(super) ta: Option<(Arc<Mutex<G15ClChannel>>, u32)>,
    pub(super) _work: G15Work,
    /// The job's VM, bound to its context slot until the job's buffers go.
    /// A queue torn down with the job still in the firmware (its fence wait
    /// timed out) would otherwise free the slot, another process's VM could
    /// take it, and the job would run in that VM (spec: faults.md, "The
    /// fork's recovery").
    pub(super) _vm: mmu::VmBind,
    pub(super) done: KBox<dyn FnMut(Option<Error>) + Send>,
    pub(super) signaled: bool,
    /// The job's failure, set by a firmware recovery that caught it.
    pub(super) error: Option<Error>,
    /// When its class doorbells were last rung (at submit, then by the poller
    /// while the job is unfinished: `G15_NUDGE_MS`).
    pub(super) nudge: Instant<Monotonic>,
    pub(super) nudges: u32,
    /// When the firmware stamp word was first seen at the job's stamp: the
    /// job completes on the host stamp word, or `G15_HOST_STAMP_MS` after
    /// this (`g15_cl_retire`).
    pub(super) fw_at: Option<Instant<Monotonic>>,
}

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: hold back the rest of a submission: the poller calls `f` until it
    /// returns true (it submits what it can each time).
    pub(crate) fn g15_defer(&self, f: KBox<dyn FnMut() -> bool + Send>) -> Result {
        self.g15.deferred.lock().push(f, GFP_KERNEL)?;
        if let Some(kick) = self.g15.kick.lock().as_ref() {
            kick();
        }
        Ok(())
    }

    /// G15: advance the held-back submissions (outside the list's lock: they
    /// submit, and a submit may hold back more).
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

    /// G15: whether `job` completed: the host stamp word has reached its
    /// stamp value (the kext's IOGPUEventMachine::testEvent, signed). The
    /// notifier walk writes it and then posts the completion event.
    pub(super) fn g15_cl_done(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        crate::mem::dc_civac(ch.words.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds u32 reads of the channel's own stamp words.
        let (host, fwst) = unsafe {
            let w = ch.words.raw_ptr() as *const u32;
            (w.read_volatile(), w.add(1).read_volatile())
        };
        // The firmware stamp comes from its in-order retire, after the job ran.
        // The notifier walk that writes the host stamp can skip the last jobs of
        // a burst (boots #435, #436: host behind, firmware at the last stamp
        // for good), so either word completes the job.
        host.wrapping_sub(stamp) as i32 >= 0 || fwst.wrapping_sub(stamp) as i32 >= 0
    }

    /// G15: whether the host stamp word has reached `stamp`.
    pub(super) fn g15_cl_host_done(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        crate::mem::dc_civac(ch.words.raw_ptr().cast_const(), 8);
        // SAFETY: an in-bounds u32 read of the channel's own stamp words.
        let host = unsafe { (ch.words.raw_ptr() as *const u32).read_volatile() };
        host.wrapping_sub(stamp) as i32 >= 0
    }

    /// G15: whether the firmware has retired `job` (its in-order retire
    /// writes the firmware stamp word, possibly after the completion
    /// event): only then may the job's buffers go.
    pub(super) fn g15_cl_retired(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        // SAFETY: an in-bounds u32 read of the channel's own stamp words.
        let fwst = unsafe { (ch.words.raw_ptr() as *const u32).add(1).read_volatile() };
        fwst.wrapping_sub(stamp) as i32 >= 0
    }

    /// G15: release the oldest quarantined job buffers once enough newer ones wait
    /// (`G15_QUARANTINE_*`).
    pub(super) fn g15_collect_garbage(&self) {
        let mut guard = self.alloc.lock();
        let guard = &mut *guard;
        for a in [&mut guard.shared, &mut guard.gpu] {
            let (n, bytes) = a.garbage();
            let mut count = if n > G15_QUARANTINE_HIGH {
                n - G15_QUARANTINE_KEEP
            } else {
                0
            };
            if bytes > G15_QUARANTINE_BYTES_HIGH {
                count = count.max(a.garbage_over(G15_QUARANTINE_BYTES_KEEP));
            }
            if count > 0 {
                a.collect_garbage(count);
            }
        }
    }

    /// G15: run `done` for every submitted CL job that completed, and free
    /// the buffers of those the firmware has retired.
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
            // The job completes on the host stamp word, as the kext's
            // IOGPUEventMachine::testEvent: the notifier walk writes it at the
            // end of the job's post-processing, and the firmware stamp can
            // come first. A render pass whose fence signalled on the firmware
            // stamp let its vertex stage's stores land 0.2-2 ms after it (6
            // processes, transform feedback read back as zeros in about 1 of
            // 4 runs). The firmware stamp completes the job only after
            // G15_HOST_STAMP_MS: the walk can skip the last jobs of a burst
            // for good (boots #435, #436).
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

    /// The poller's pass: retire what completed, run the deferred work, ring
    /// again what the firmware has not picked up. Whether work is pending.
    pub(crate) fn g15_poll_work(&self) -> bool {
        if self.is_crashed() {
            // A crashed firmware runs nothing more: fail every pending job
            // once (its buffers stay: what the GPU last read is unknown),
            // let the held-back submissions fail, and ring nothing. Else
            // the jobs' fences never signal, every queue teardown waits
            // out its timeout, and the poller rings the dead IOP every
            // millisecond.
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
        // A job still unfinished G15_NUDGE_MS after its doorbell gets its
        // classes rung again (a job the firmware's scheduler skipped: boot #440,
        // mrt1, one in about 1900 runs, ring consumed, stamps unmoved).
        const G15_NUDGE_MS: i64 = 200;
        let mut nudge = [false; 3];
        let mut first_nudge = false;
        for p in self.g15.pending.lock().iter_mut() {
            if !p.signaled && p.nudge.elapsed() >= Delta::from_millis(G15_NUDGE_MS) {
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
            // G15 lab: the trace up to the stall, before the nudges' passes overwrite it.
            self.g15_trace_dump(64);
        }
        for (class, bell) in nudge.iter().enumerate() {
            if *bell {
                self.g15.nudges.fetch_add(1, Ordering::Relaxed);
                let _ = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(class as u64));
            }
        }
        // A ring whose entries the firmware has not consumed RING_STALL_US
        // after the doorbell gets it again: a doorbell that comes while
        // the firmware's consumer is scanning the rings is absorbed, and
        // the entry written after the scan passed its ring waits for the
        // next doorbell (boots #416-#424: the last jobs of a burst hung).
        const RING_STALL_US: i64 = 1000;
        let mut bells = [false; 3];
        {
            let mut stall = self.g15.ring_stall.lock();
            for (class, since) in stall.iter_mut().enumerate() {
                if !self.g15_ring_unconsumed(fw::g15::ring(class)) {
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
        let busy = !self.g15.pending.lock().is_empty() || !self.g15.deferred.lock().is_empty();
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
}
