// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 performance counters: where the GPU's time and the submit path's go.
//!
//! - **GPU time per job.** A job's second timestamp record has the firmware
//!   read its data master's start and end counters
//!   (`_AGFHALCommandBufferTimestampEnd`) and keep the earliest start and
//!   the latest end in the two slots whose addresses the job state holds at
//!   the record's +0x0C. macOS points them at the command buffer's GPU start
//!   and end times; the fork points them past the end of the job state and
//!   reads them when the job retires.
//! - **Performance-state residency.** At each change of the GPU's
//!   performance state (`AGFA_PerfTargetSet`, `AGFA_PowerUp`,
//!   `AGFA_PowerDown`) the firmware posts a type 0xF record to the
//!   statistics ring: +0x04 its timestamp, +0x0C the new state (HwDataA
//!   +0x38, 0 when off).
//! - **Utilization.** Every power sample period (8 ms here) it posts a type
//!   4 record (`AGFA_BackgroundTick`): +0x04 its timestamp, and at +0x0C to
//!   +0x18 the percentage of the period during which the TA, the 3D and the
//!   CL data master, and any of them, were busy. A data master counts as
//!   busy from its first job to the GPU's next idle.
//! - **Submission.** The time the kernel spends in a G15 submission.
//!
//! The data masters' counters tick at 24 MHz: the firmware turns them into
//! nanoseconds as `125 * ticks / 3`, and those agree with the CPU counter.
//! The statistics ring's timestamps count the coprocessor's generic timer at
//! the frequency the firmware reads from `CNTFRQ_EL0`, not known here, so
//! its totals stay in ticks. debugfs `asahi/perf` prints the totals since
//! probe.
//!
//! Spec: stream.md, channel-table.md, power.md.

use super::*;
use kernel::fmt;

/// Where each job's GPU start and end go: two u64 past the end of its job
/// state as macOS lays it out.
pub(super) const TA_TIMES: usize = 0x920;
pub(super) const D3_TIMES: usize = 0xC60;
pub(super) const CL_TIMES: usize = 0x880;

/// The data masters, as the counters index them.
const DM_TA: usize = 0;
const DM_3D: usize = 1;
const DM_CL: usize = 2;

/// Data master ticks (24 MHz) to nanoseconds.
fn ns(ticks: u64) -> u64 {
    ticks * 125 / 3
}

/// What the statistics ring reports, in its ticks.
#[derive(Default)]
struct G15FwStats {
    /// The performance state and the timestamp of its record.
    state: Option<(u32, u64)>,
    /// Ticks in each performance state, up to its last change.
    residency: [u64; 16],
    /// The last utilization sample's timestamp.
    sample: Option<u64>,
    /// Busy ticks of the TA, 3D and CL data masters, and of any of them.
    busy: [u64; 4],
    /// Ticks the utilization samples cover.
    sampled: u64,
    /// The latest firmware timestamp seen.
    now: u64,
}

/// The G15 performance counters, totals since probe.
#[pin_data]
pub(crate) struct G15Perf {
    /// GPU ticks of the retired jobs of each data master, and their number.
    gpu: [AtomicU64; 3],
    jobs: [AtomicU64; 3],
    /// Retired jobs with no GPU time: their timestamp record did not run.
    untimed: AtomicU64,
    /// Nanoseconds spent in G15 submissions (the ioctl, which builds the
    /// jobs), and their number.
    submit_ns: AtomicU64,
    submits: AtomicU64,
    /// Nanoseconds the scheduler spent running G15 submissions (ringing
    /// them), and their number.
    run_ns: AtomicU64,
    runs: AtomicU64,
    #[pin]
    fw: Mutex<G15FwStats>,
}

impl G15Perf {
    pub(super) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            gpu: Default::default(),
            jobs: Default::default(),
            untimed: AtomicU64::new(0),
            submit_ns: AtomicU64::new(0),
            submits: AtomicU64::new(0),
            run_ns: AtomicU64::new(0),
            runs: AtomicU64::new(0),
            fw <- new_mutex!(G15FwStats::default(), "g15_perf_fw"),
        })
    }

    /// Counts a retired job's GPU time, from the start and end slots at
    /// `off` in its job state.
    fn job_retired(&self, dm: usize, js: &fw::types::GpuArray<u8>, off: usize) {
        let p = js.raw_ptr().wrapping_add(off);
        crate::mem::dc_civac(p.cast_const(), 16);
        // SAFETY: two in-bounds u64 reads of the job's own state, which the
        // firmware no longer writes once the job has retired.
        let (start, end) = unsafe {
            let q = p.cast::<u64>();
            (q.read_volatile(), q.add(1).read_volatile())
        };
        if start != 0 && end >= start {
            self.gpu[dm].fetch_add(end - start, Ordering::Relaxed);
            self.jobs[dm].fetch_add(1, Ordering::Relaxed);
        } else {
            self.untimed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts the GPU time of retired work.
    pub(super) fn retired(&self, work: &G15Work) {
        match work {
            G15Work::Cl(j) => self.job_retired(DM_CL, &j.job_state, CL_TIMES),
            G15Work::Rd(p) => {
                self.job_retired(DM_TA, &p._ta.job_state, TA_TIMES);
                self.job_retired(DM_3D, &p._d3.job_state, D3_TIMES);
            }
        }
    }

    /// Counts the time of one G15 submission.
    pub(super) fn submitted(&self, d: Delta) {
        self.submit_ns
            .fetch_add(d.as_nanos().max(0) as u64, Ordering::Relaxed);
        self.submits.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts the time of one G15 submission's run.
    pub(super) fn ran(&self, d: Delta) {
        self.run_ns
            .fetch_add(d.as_nanos().max(0) as u64, Ordering::Relaxed);
        self.runs.fetch_add(1, Ordering::Relaxed);
    }

    /// Takes a statistics ring record's first eight words.
    pub(super) fn stats_record(&self, rec: &[u32; 8]) {
        let ts = u64::from(rec[1]) | (u64::from(rec[2]) << 32);
        let mut s = self.fw.lock();
        match rec[0] {
            4 => {
                if let Some(prev) = s.sample {
                    let w = ts.saturating_sub(prev);
                    for i in 0..4 {
                        s.busy[i] += w * u64::from(rec[3 + i].min(100)) / 100;
                    }
                    s.sampled += w;
                }
                s.sample = Some(ts);
            }
            0xF => {
                if let Some((state, since)) = s.state {
                    s.residency[(state as usize).min(15)] += ts.saturating_sub(since);
                }
                s.state = Some((rec[3], ts));
            }
            _ => return,
        }
        s.now = s.now.max(ts);
    }

    /// Prints the counters, one `name value` per line, with the residency
    /// of `states` performance states.
    pub(super) fn show(&self, f: &mut fmt::Formatter<'_>, states: usize) -> fmt::Result {
        for (i, dm) in ["ta", "3d", "cl"].iter().enumerate() {
            writeln!(f, "gpu_ns_{dm} {}", ns(self.gpu[i].load(Ordering::Relaxed)))?;
            writeln!(f, "jobs_{dm} {}", self.jobs[i].load(Ordering::Relaxed))?;
        }
        writeln!(f, "jobs_untimed {}", self.untimed.load(Ordering::Relaxed))?;
        writeln!(f, "submit_ns {}", self.submit_ns.load(Ordering::Relaxed))?;
        writeln!(f, "submits {}", self.submits.load(Ordering::Relaxed))?;
        writeln!(f, "run_ns {}", self.run_ns.load(Ordering::Relaxed))?;
        writeln!(f, "runs {}", self.runs.load(Ordering::Relaxed))?;
        let s = self.fw.lock();
        for (i, dm) in ["ta", "3d", "cl", "any"].iter().enumerate() {
            writeln!(f, "busy_ticks_{dm} {}", s.busy[i])?;
        }
        writeln!(f, "sampled_ticks {}", s.sampled)?;
        // The current state's time runs to the latest timestamp seen.
        let mut res = s.residency;
        if let Some((state, since)) = s.state {
            res[(state as usize).min(15)] += s.now.saturating_sub(since);
            writeln!(f, "pstate {state}")?;
        }
        for (i, r) in res.iter().enumerate().take(states) {
            writeln!(f, "pstate_ticks_{i} {r}")?;
        }
        Ok(())
    }
}

/// What a submission held back on the host waits for: its render queue's
/// channels and parameter buffer, or an earlier held-back submission of its
/// queue.
#[derive(Clone, Copy)]
pub(crate) enum G15Hold {
    Res,
    Behind,
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Counts one submission held back on the host.
    pub(crate) fn g15_held(&self, h: G15Hold) {
        self.g15.held[h as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one poller pass and its time.
    pub(crate) fn g15_polled(&self, d: Delta) {
        self.g15.polls.fetch_add(1, Ordering::Relaxed);
        self.g15
            .poll_ns
            .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Counts the time of one G15 submission.
    pub(crate) fn g15_submitted(&self, d: Delta) {
        self.g15.perf.submitted(d);
    }

    /// Counts the time of one G15 submission's run.
    pub(crate) fn g15_ran(&self, d: Delta) {
        self.g15.perf.ran(d);
    }

    /// Prints the G15 performance counters, then those of the submit path's
    /// workarounds: late host stamps and how late they came, which path
    /// completed the jobs, re-rings and ring stalls, the poller's passes
    /// and stamp-table waits; the pooled and released channels.
    pub(crate) fn g15_perf_show(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.g15.perf.show(f, self.dyncfg.pwr.perf_states.len())?;
        let g = &self.g15;
        writeln!(
            f,
            "host_stamps_late {}",
            g.host_stamp_late.load(Ordering::Relaxed)
        )?;
        let a = |i: usize| g.host_stamp_after[i].load(Ordering::Relaxed);
        let missing = g.pending.lock().iter().filter(|p| p.late).count();
        writeln!(
            f,
            "host_stamps_late_after <10ms {} <100ms {} <1s {} >=1s {} max_us {} missing {}",
            a(0),
            a(1),
            a(2),
            a(3),
            g.host_stamp_after_max_us.load(Ordering::Relaxed),
            missing
        )?;
        writeln!(
            f,
            "stamp_waits {} us {}",
            g.stamp_waits.load(Ordering::Relaxed),
            g.stamp_wait_us.load(Ordering::Relaxed)
        )?;
        let by = |i: usize| g.completed_by[i].load(Ordering::Relaxed);
        writeln!(
            f,
            "completed_by irq {} poll {} submit {}",
            by(0),
            by(1),
            by(2)
        )?;
        let h = |i: usize| g.held[i].load(Ordering::Relaxed);
        writeln!(f, "held res {} behind {}", h(0), h(1))?;
        writeln!(f, "rt_own {}", g.rt_own.load(Ordering::Relaxed))?;
        let s = |i: usize| g.ring_stalls[i].load(Ordering::Relaxed);
        writeln!(
            f,
            "ring_stalls <2ms {} <10ms {} <100ms {} >=100ms {} max_us {}",
            s(0),
            s(1),
            s(2),
            s(3),
            g.ring_stall_max_us.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "polls {} ns {}",
            g.polls.load(Ordering::Relaxed),
            g.poll_ns.load(Ordering::Relaxed)
        )?;
        writeln!(
            f,
            "channels pooled_cl {} pooled_rd {} releasing {} released {} freed {}",
            g.free_chans.lock().len(),
            g.free_rd_chans.lock().len(),
            g.releasing.lock().len(),
            g.chans_released.load(Ordering::Relaxed),
            g.chans_freed.load(Ordering::Relaxed)
        )
    }
}
