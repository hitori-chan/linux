// SPDX-License-Identifier: GPL-2.0-only

//! G15 probe-time checks of the firmware's command paths: a control-ring
//! command, then two compute jobs.
//!
//! Spec: channel.md, cl-container.md.

use super::*;

#[versions(AGX)]
impl GpuManager::ver {
    /// Checks the control ring, after the init message: submits one
    /// ForceConfigSnapshot command as macOS's
    /// `submitCmdFirmwareForceConfigSnapshot` does and waits for the
    /// firmware to consume it.
    ///
    /// The command only refreshes the firmware's chip-config snapshot, so it
    /// is safe to send at every probe. The firmware's consumer runs only on
    /// a doorbell, which is sent again every 500 ms while the read index
    /// stays 0. A failure is logged, not fatal.
    pub(super) fn g15_control_selftest(&self) {
        let entry = CTL::ver.entry;
        const WAIT_MS: u32 = 2000;
        const RING_MS: u32 = 500;
        let dev = self.dev.as_ref();
        let storage = self.initdata.special_ring.raw_ptr();
        let ring = self.initdata.ring_area.raw_ptr();

        // SAFETY: slot 0 is in bounds of the storage and both
        // index words are in bounds of the 128 KiB ring area. The memory is
        // shared with the firmware and no slice view of it is live, so
        // every access is a volatile one through the raw pointer.
        unsafe {
            for i in 0..entry {
                storage.add(i).write_volatile(0);
            }
            storage
                .cast::<u32>()
                .write_volatile(CTL::ver.config_snapshot);
            core::sync::atomic::fence(Ordering::Release);
            ring.add(fw::g15::RING_SPECIAL_DOORBELL_OFF)
                .cast::<u32>()
                .write_volatile(1);
        }
        // SAFETY: as above; read-only.
        let read_index = || unsafe {
            (ring.add(fw::g15::RING_REGION2_OFF + 0xC0) as *const u32).read_volatile()
        };

        let mut last = 0;
        let mut waited = 0;
        while waited < WAIT_MS {
            if waited % RING_MS == 0 {
                if let Err(e) = self.g15_send(EP_DOORBELL, CTL::ver.bell) {
                    dev_err!(dev, "G15 control self-test: doorbell refused ({:?})\n", e);
                    return;
                }
            }
            last = read_index();
            if last > 0 {
                break;
            }
            kernel::time::delay::fsleep(Delta::from_millis(1));
            waited += 1;
        }

        if last > 0 {
            dev_info!(
                dev,
                "G15 control self-test: OK (read index {:#x} after ~{} ms)\n",
                last,
                waited
            );
        } else {
            dev_err!(
                dev,
                "G15 control self-test: TIMEOUT (read index still 0 after {} ms)\n",
                WAIT_MS
            );
        }
    }

    /// Checks the compute path: two compute jobs without a launch on one
    /// channel. The first is submitted inside the GPU's idle power-down, the
    /// second right after the first completes. A failure is logged, not
    /// fatal.
    pub(super) fn g15_compute_selftest(&self) {
        const JOBS: u32 = 2;
        const WAIT_MS: u32 = 5000;
        const RING_MS: u32 = 500;
        const CL_RING: usize = fw::g15::ring(2);
        let dev = self.dev.as_ref();
        let mut ch = match self.g15_cl_channel_new(true) {
            Ok(ch) => ch,
            Err(e) => {
                dev_err!(dev, "G15 compute self-test: channel alloc {e:?}\n");
                return;
            }
        };
        let ring = self.initdata.ring_area.raw_ptr();
        // SAFETY: an in-bounds u32 read of the ring area.
        let read_index = || unsafe {
            (ring.add(fw::g15::RING_REGION2_OFF + 16 * CL_RING) as *const u32).read_volatile()
        };
        let mut jobs = KVec::new();
        for _ in 0..JOBS {
            let mut job = match self.g15_cl_job_new(&ch, None, 1, &[], (0, 0), None, None) {
                Ok(j) => j,
                Err(e) => {
                    dev_err!(dev, "G15 compute self-test: job alloc {e:?}\n");
                    break;
                }
            };
            if ch.submitted == 0 {
                // Submit 100 ms after the control-ring check, inside the
                // GPU's idle power-down, where a doorbell can be missed and
                // the job runs on the doorbell sent again.
                kernel::time::delay::fsleep(Delta::from_millis(100));
                g15_fwdump(0);
            }
            let js = job.job_state.gpu_va().get();
            // A submission in progress (`updateSubmitInProgress` on macOS):
            // the firmware holds off its idle power-down while it is set.
            self.g15_submit_in_progress(true);
            if let Err(e) = self.g15_cl_submit(&mut ch, &mut job, None, false) {
                dev_err!(
                    dev,
                    "G15 compute self-test: job {} doorbell refused ({e:?})\n",
                    job.n
                );
            }
            dev_info!(
                dev,
                "G15 compute self-test: job {} submitted (job-state {js:#x}, stamp {:#x})\n",
                job.n,
                job.stamp
            );
            let mut waited = 0;
            while waited < WAIT_MS && !self.g15_cl_done(&ch, job.stamp) {
                kernel::time::delay::fsleep(Delta::from_millis(1));
                waited += 1;
                if waited % RING_MS == 0 {
                    // Again, for a doorbell lost in the power-down.
                    if let Err(e) = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(2)) {
                        dev_err!(dev, "G15 compute self-test: doorbell refused ({e:?})\n");
                        break;
                    }
                }
                if job.n == 1 && waited == 100 {
                    g15_fwdump(2);
                }
                // [tr] 27.2: the firmware's trace 50 ms into the first job, while the kick's records are in it
                #[ver(V >= V27_2)]
                if job.n == 1 && waited == 50 {
                    self.g15_drain_fw_rings();
                    self.g15_trace_dump(160);
                }
            }
            self.g15_submit_in_progress(false);
            let (host, fwst) = ch.words();
            let events = self.g15.perf.completions.load(Ordering::Relaxed);
            let done = self.g15_cl_done(&ch, job.stamp);
            if done {
                dev_info!(
                    dev,
                    "G15 compute self-test: job {} COMPLETED after ~{waited} ms (host stamp {host:#x}, fw stamp {fwst:#x}, {events} completion event(s), ring read {:#x})\n",
                    job.n,
                    read_index()
                );
            } else {
                dev_err!(
                    dev,
                    "G15 compute self-test: job {} TIMEOUT after {waited} ms (host stamp {host:#x}, fw stamp {fwst:#x}, {events} completion event(s), ring read {:#x})\n",
                    job.n,
                    read_index()
                );
            }
            // 27.2: the first job's firmware state while it is fresh, as a
            // host stop's dump comes seconds and many doorbells later: the
            // channel state, its stamp entry (the DAG node) and the
            // firmware's last trace records (with `Debug4`).
            // [tr] 27.2: the firmware's trace after the first job also when it completes
            #[ver(V >= V27_2)]
            if done && job.n == 1 {
                self.g15_drain_fw_rings();
                self.g15_trace_dump(160);
            }
            // [tr] 27.2: the device pools' state after the first job, done or not
            #[ver(V >= V27_2)]
            if job.n == 1 {
                self.g15_uma_each(|uma| {
                    if uma.slot < G15_UMA_POOLS {
                        uma.log(dev.as_ref(), &self.initdata.umap_table, "after job 1");
                    }
                });
            }
            #[ver(V >= V27_2)]
            if !done && job.n == 1 {
                Self::g15_dump_chan_raw(dev, "CL self-test", &ch);
                Self::g15_dump_stamp_entry(dev, "CL self-test", &ch, job.stamp);
                self.g15_drain_fw_rings();
                self.g15_trace_dump(160);
                // [tr] the GPU's PMGR power states while the job waits: AFR and GFX
                // (read-only; PMGR's GPX block at 0x408e80000 is always powered).
                // SAFETY: [tr] a fresh mapping of the block, two 32-bit reads, unmapped.
                unsafe {
                    let p = kernel::bindings::ioremap(0x408e80000, 0x4000);
                    if !p.is_null() {
                        let afr = kernel::bindings::readl(p.cast::<u8>().add(0x100).cast());
                        let gfx = kernel::bindings::readl(p.cast::<u8>().add(0x110).cast());
                        dev_info!(dev, "[tr] PMGR AFR {:#x} GFX {:#x}\n", afr, gfx);
                        kernel::bindings::iounmap(p);
                    }
                }
            }
            if jobs.push(job, GFP_KERNEL).is_err() || !done {
                break;
            }
        }
        // Let late notifications land before the dump.
        kernel::time::delay::fsleep(Delta::from_millis(100));
        g15_fwdump(1);
        self.g15_drain_fw_rings();
        // Keep the channel and the jobs alive: the firmware's DAG root and
        // the notifier list reference them.
        match KBox::new(ch, GFP_KERNEL) {
            Ok(ch) => *self.g15.selftest.lock() = Some((ch, jobs)),
            Err(_) => dev_err!(dev, "G15 compute self-test: cannot keep the channel\n"),
        }
    }
}
