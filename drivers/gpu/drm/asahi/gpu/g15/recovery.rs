// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 recovery.
//!
//! On a GPU fault or a hang the firmware stops itself, posts a recovery
//! record to the event ring with the table of the jobs it caught, and waits
//! for the host. The host fails the guilty job and resumes the firmware,
//! which then power-cycles the GPU and retires the caught jobs.
//!
//! A hang the firmware does not catch stops the progress word; the host
//! then stops the firmware itself (a host stop), and before the resume sets
//! up again what the firmware's rebuild of its job state forgets: the jobs
//! in flight fail, and the channels, the parameter buffers, the UMA pools and
//! the recovery and per-slot records start over. New work waits for the
//! firmware's restart after the resume.
//!
//! Spec: faults.md, recovery.md.

use super::*;

#[versions(AGX)]
impl GpuManager::ver {
    /// Handles a recovery stop: logs what the firmware caught, marks the
    /// caught jobs failed, resets the unfinished TA jobs and resumes the
    /// firmware.
    pub(super) fn g15_recovery(&self, count: u64, guilty: u32) {
        let dev = self.dev.as_ref();
        // The firmware's last trace records before the stop.
        self.g15_trace_dump(160);
        let e = self.initdata.event_page.raw_ptr().cast::<u8>();
        crate::mem::dc_civac(e.wrapping_add(0x40A0).cast_const(), 0x524);
        let mut caught: KVec<(u32, u32, u32)> = KVec::new();
        // SAFETY: in-bounds u32 and u64 reads of the 0xC3D0-byte event page.
        unsafe {
            let r32 = |off: usize| (e.add(off) as *const u32).read_volatile();
            dev_err!(
                dev,
                "G15: GPU stopped for recovery {}: {} caught job(s), guilty stamp {:#x}, pid {}, kill {}, fault bank {:#x}, busy {:#x}, stopped {}, host-requested {}\n",
                count,
                r32(0x44A4),
                guilty,
                r32(0x44AC),
                r32(0x44B0),
                (e.add(0x44B4) as *const u64).read_unaligned(),
                (e.add(0x4560) as *const u64).read_unaligned(),
                r32(0x4590),
                r32(0x45B0)
            );
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
        // anywhere in its 128 entries, as macOS's
        // processFirmwareTACommandsRecovery walks them.
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
        // The job table's non-empty entries (flags and stamp), the first few.
        {
            let (mut n, mut first) = (0, [(0u32, 0u32, 0u32); 6]);
            // SAFETY: in-bounds u32 reads of the event page.
            unsafe {
                for i in 0..0x80usize {
                    let w = (e.add(0x40A0 + i * 8) as *const u32).read_volatile();
                    if w != 0 {
                        if n < first.len() {
                            first[n] = (
                                i as u32,
                                w,
                                (e.add(0x40A4 + i * 8) as *const u32).read_volatile(),
                            );
                        }
                        n += 1;
                    }
                }
            }
            dev_err!(
                dev,
                "G15:   job table: {n} non-empty entries, first (slot, flags, stamp) {:x?}\n",
                &first[..n.min(6)]
            );
        }
        let mut cleared = 0;
        let mut pbs = 0u64;
        // Each logged buffer's first blocks, to place an MMU fault.
        let mut spans: KVec<(u32, u64, u64)> = KVec::new();
        // Each pending pass's render-target memory: (n, name, start, size).
        let mut rts: KVec<(u32, &'static str, u64, usize)> = KVec::new();
        // The processes with jobs pending: a host stop has no guilty pid, so
        // the channels' owners (state +0x50) say whose jobs it fails.
        let mut owners: KVec<(u32, u32, u32)> = KVec::new();
        let mut shown = 0;
        // The oldest unfinished job: (n, stamp, its 3D channel, its TA channel).
        type Oldest = (
            u32,
            u32,
            Arc<Mutex<G15ClChannel>>,
            Option<Arc<Mutex<G15ClChannel>>>,
        );
        let mut head: Option<Oldest> = None;
        for p in self.g15.pending.lock().iter_mut() {
            {
                let ch = p.chan.lock();
                // SAFETY: an in-bounds u32 read of the channel's state block.
                let pid = unsafe { ch.state.raw_ptr().add(0x50).cast::<u32>().read_volatile() };
                match owners
                    .iter_mut()
                    .find(|o| o.0 == pid && o.1 == ch.stamp_index)
                {
                    Some(o) => o.2 += 1,
                    None => {
                        let _ = owners.push((pid, ch.stamp_index, 1), GFP_ATOMIC);
                    }
                }
            }
            // The firmware's counts of each parameter buffer with a pass in
            // flight, logged once: its post-recovery walk holds back a buffer
            // whose 3D completions differ from the host's count.
            if let G15Work::Rd(pass) = &p._work {
                let (id, c) = pass.pb_counts();
                if id < 64 && pbs & 1 << id == 0 {
                    pbs |= 1 << id;
                    let (b0, b1) = pass.pb_blocks();
                    let _ = spans.push((id, b0, b1), GFP_ATOMIC);
                    dev_info!(
                        dev,
                        "G15:   PB {id}: 3D done {}, TA done {}, TAs in flight {}, gate {}, 3D submitted {}, blocks {b0:#x}..{b1:#x}\n",
                        c[0],
                        c[1],
                        c[2],
                        c[3],
                        c[4]
                    );
                    let d = self.g15_pb_desc(id);
                    let l = pass.pb_lists([d[2], d[3]]);
                    dev_info!(
                        dev,
                        "G15:   PB {id} lists: pages {}, start {}, head {}, published {}, zero free page entries {}, zero block entries {}\n",
                        l[0],
                        l[1],
                        l[2],
                        l[3],
                        l[4],
                        l[5]
                    );
                }
            }
            if !p.signaled && !head.as_ref().is_some_and(|h| p.n >= h.0) {
                head = Some((
                    p.n,
                    p.stamp,
                    p.chan.clone(),
                    p.ta.as_ref().map(|(c, _)| c.clone()),
                ));
            }
            if let G15Work::Rd(pass) = &p._work {
                for (name, b, l) in pass._rt.shared_spans() {
                    if !rts.iter().any(|r| r.2 == b && r.1 == name) {
                        let _ = rts.push((p.n, name, b, l), GFP_ATOMIC);
                    }
                }
            }
            let idx = p.chan.lock().stamp_index;
            let ta = p.ta.as_ref().map(|(c, st)| (c.lock().stamp_index, *st));
            let hit = caught
                .iter()
                .find(|c| (c.0 == idx && c.1 == p.stamp) || ta == Some((c.0, c.1)))
                .map(|c| c.2);
            // The first four, and every caught one.
            if (shown < 4 || hit.is_some()) && !p.signaled {
                shown += 1;
                let words = |c: &G15ClChannel| {
                    crate::mem::dc_civac(c.words.raw_ptr().cast_const(), 8);
                    // SAFETY: in-bounds u32 reads of the channel's stamp words.
                    unsafe {
                        let w = c.words.raw_ptr() as *const u32;
                        (w.read_volatile(), w.add(1).read_volatile())
                    }
                };
                let slots = |c: &G15ClChannel| {
                    let b = c.state.raw_ptr().wrapping_add(0x20);
                    crate::mem::dc_civac(b.cast_const(), 16);
                    // SAFETY: in-bounds u32 reads of the channel's state block.
                    unsafe {
                        let w = b as *const u32;
                        (
                            w.read_volatile(),
                            w.add(1).read_volatile(),
                            w.add(2).read_volatile(),
                        )
                    }
                };
                let (h, f) = words(&p.chan.lock());
                let d3 = slots(&p.chan.lock());
                let ta = p.ta.as_ref().map(|(c, st)| {
                    let c = c.lock();
                    let (h, f) = words(&c);
                    (*st, h, f, slots(&c))
                });
                let rt = match &p._work {
                    G15Work::Rd(pass) => Some(pass._rt.span()),
                    G15Work::Cl(_) => None,
                };
                dev_err!(
                    dev,
                    "G15:   pending job {}: n {} ctx {} stamp {:#x}, words host {:#x} fw {:#x}, slots (read, seen, write) {:x?}, age {} ms, fw seen {}; TA (stamp, host, fw, slots) {:x?}; rt (va, size) {:x?}\n",
                    shown,
                    p.n,
                    p.ctx,
                    p.stamp,
                    h,
                    f,
                    d3,
                    p.since.elapsed().as_millis(),
                    p.fw_at.is_some(),
                    ta,
                    rt
                );
                if let G15Work::Rd(pass) = &p._work {
                    let g = &pass.geom;
                    dev_err!(
                        dev,
                        "G15:     {}target {}x{}x{}, utile config {:#x}, n {}; ring instance {:?}; ring {:x?}, aux_fb {:x?}\n",
                        if hit.is_some() { "caught; " } else { "" },
                        g.w,
                        g.h,
                        g.layers,
                        g.utile_config,
                        g.n,
                        pass._rt.ring_index(),
                        pass._rt.shared_spans()[0],
                        pass._rt.shared_spans()[11]
                    );
                }
            }
            if let Some(w) = hit {
                p.error = Some(if w & 2 != 0 { EIO } else { ECANCELED });
            }
            // An unfinished listed TA job's scene is aborted: the walk marks
            // a TA job in an active slot done without running it, and its 3D
            // job would draw a tilemap that was never written. A TA job that
            // kicks again clears the mark. Its tail-pointer cache is zeroed
            // with the rest of its queue's TA-only buffers before the resume.
            if let (Some((tc, st)), G15Work::Rd(pass)) = (p.ta.as_ref(), &p._work) {
                let tc = tc.lock();
                if tas.iter().any(|&(i, v)| i == tc.stamp_index && v == *st)
                    && !self.g15_cl_done(&tc, *st)
                {
                    pass.abort_scene();
                    cleared += 1;
                }
            }
        }
        if cleared != 0 {
            dev_info!(
                dev,
                "G15:   {cleared} unfinished TA job(s): scenes aborted\n"
            );
        }
        for (pid, idx, n) in owners.iter() {
            dev_err!(
                dev,
                "G15:   {n} pending job(s) of pid {pid} on stamp index {idx}\n"
            );
        }
        if let Some((n, stamp, d3, ta)) = head {
            dev_err!(
                dev,
                "G15:   the oldest unfinished job: n {n} stamp {stamp:#x}\n"
            );
            Self::g15_dump_chan_raw(dev, "3D", &d3.lock());
            Self::g15_dump_stamp_entry(dev, "3D", &d3.lock(), stamp.wrapping_sub(0x100));
            Self::g15_dump_stamp_entry(dev, "3D", &d3.lock(), stamp);
            if let Some(ta) = ta {
                Self::g15_dump_chan_raw(dev, "TA", &ta.lock());
                Self::g15_dump_stamp_entry(dev, "TA", &ta.lock(), stamp);
            }
        }
        // The MMU fault at the stop, read as macOS's restartWorkQueue does:
        // the firmware selected the bank of the latched fault and left it in
        // effect. A hang has none.
        if let Some(fi) = self.get_fault_info() {
            dev_err!(dev, "G15:   fault: {fi:x?}\n");
            // A kernel VA comes masked to 43 bits.
            let kva = if fi.address & 1 << 42 != 0 {
                fi.address | !G15_GPU_VA_MASK
            } else {
                fi.address
            };
            if let Some(a) = self.alloc.try_lock() {
                for (name, h) in [("rt", &a.rt), ("gpu", &a.gpu), ("shared", &a.shared)] {
                    match h.locate(kva) {
                        Some((b, l, None)) => dev_err!(
                            dev,
                            "G15:   the fault is in the {name} heap's block {b:#x}+{l:#x}\n"
                        ),
                        Some((b, l, Some(o))) => dev_err!(
                            dev,
                            "G15:   the fault is {o:#x} into the guard page after the {name} heap's block {b:#x}+{l:#x}\n"
                        ),
                        None => (),
                    }
                }
            }
            // A buffer that holds the fault, or ends less than 32 KiB below it.
            for &(n, name, b, l) in rts.iter() {
                if (b..b + l as u64 + 0x8000).contains(&kva) {
                    dev_err!(
                        dev,
                        "G15:   the fault is at {:#x} of job n {n}'s {name} {b:#x}+{l:#x}\n",
                        kva - b
                    );
                }
            }
            for &(id, b0, b1) in spans.iter() {
                if (b0..b1).contains(&fi.address) {
                    dev_err!(
                        dev,
                        "G15:   the fault is in PB {id}'s block {}\n",
                        (fi.address - b0) / super::pb::PB_BLOCK_SIZE as u64
                    );
                }
            }
        } else {
            dev_err!(dev, "G15:   no MMU fault latched (a hang)\n");
        }
        // The rings at the stop: each one's write, read and CFI words, the
        // entries about the TA ring's read index and the 3D ring's last
        // three. An entry the firmware never took has its read behind its
        // write; a lost kick shows read at write with jobs unretired.
        self.g15_dump_ring_stall(render::TA_RING);
        self.g15_dump_ring_entries(render::D3_RING);
        for (_, idx, _) in owners.iter() {
            self.g15_dump_ring_stamp(render::TA_RING, *idx);
            self.g15_dump_ring_stamp(render::D3_RING, *idx);
        }
        // The pools with jobs in flight (and the device's), as the stop left
        // them.
        self.g15_uma_each(|uma| {
            if uma.slot < G15_UMA_POOLS || !uma.idle() {
                uma.log(dev.as_ref(), &self.initdata.umap_table, "at the stop");
            }
        });
        // The firmware posts the record before it sets the stopped flag
        // (+0x4590) and the stop count (+0x4580) and starts waiting for the
        // resume word (+0x45A0). A resume before that would leave the
        // stopped flag set for good, and every later submission would fail,
        // so wait for the count.
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
                dev_err!(
                    dev,
                    "G15:   the firmware did not stop (count {n:#x}, stopped {stopped}); resuming anyway\n"
                );
                break;
            }
            kernel::time::delay::fsleep(kernel::time::Delta::from_micros(10));
            waited += 10;
        }
        // Every render queue's TA-only buffers start zeroed, as macOS's
        // `affectedByHardwareReset` does after any restart: now, with the
        // firmware stopped, for the sets of the passes in flight; the others
        // before their next pass is staged. The generation moves under the
        // rings lock, which a pass checks it under (`g15_rd_submit_pass`).
        let rt_gen = {
            let _rings = self.g15.rings.lock();
            self.g15
                .rt_gen
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
        };
        let mut sets = 0;
        for p in self.g15.pending.lock().iter() {
            if let G15Work::Rd(pass) = &p._work {
                sets += u32::from(pass._rt.clear_ta_state(rt_gen));
            }
        }
        dev_info!(
            dev,
            "G15:   the TA-only buffers of {sets} render queue(s) zeroed\n"
        );
        // A host stop: the re-init before the resume.
        // SAFETY: an in-bounds u32 read of the event page.
        let host = unsafe { (e.add(0x45B0) as *const u32).read_volatile() } != 0;
        let orphans = if host {
            self.g15_host_reinit()
        } else {
            KVec::new()
        };
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
        if host {
            // The submissions keep waiting, for the firmware's restart
            // (`g15_check_restart`), and the failed jobs' buffers stay until
            // the firmware runs on its rebuilt state.
            *self.g15.restart_since.lock() = Some(Instant::<Monotonic>::now());
            let _old = core::mem::replace(&mut *self.g15.orphans.lock(), orphans);
        }
        // Wake the submissions that met the stop, after the flag is clear and
        // under the lock they check it with.
        *self.g15.resumes.lock() += 1;
        self.g15.resume_cv.notify_all();
    }

    /// Sets up again, with the firmware stopped by the host, what its
    /// rebuild of the job state forgets (the kext's `restartWorkQueue`,
    /// spec: recovery.md, "The host's side", step 6). Every job in flight
    /// fails, as IOGPU's `forceCompleteAllStamps` and the error on every
    /// unretired command do, and is returned to be freed once the restart
    /// is done (`g15_check_restart`).
    /// Their channels start over now; every other channel and render queue
    /// at its next submission (`G15State::reset_gen`). Every parameter
    /// buffer's counts and the UMA pools start over, and the event page's
    /// `+0x45C4` asks the resume for the rebuild. Not done: the VM slots stay
    /// bound (the kext unbinds them), and HwDataA and the power block keep
    /// their values (the kext writes its boot values again).
    fn g15_host_reinit(&self) -> KVec<G15ClPending> {
        // Under the rings lock: a submission publishes either before the new
        // generation, which its `g15_track` then finds (unless the job is
        // already in the list taken below), or after it, where
        // `g15_ring_room` sees the restart.
        {
            let _rings = self.g15.rings.lock();
            self.g15.restarting.store(true, Ordering::Release);
            self.g15.reset_gen.fetch_add(1, Ordering::Relaxed);
        }
        let mut orphans = core::mem::take(&mut *self.g15.pending.lock());
        for p in orphans.iter_mut() {
            if !p.signaled {
                p.signaled = true;
                (p.done)(Some(ECANCELED));
            }
            self.g15_chan_fresh(&mut p.chan.lock());
            if let Some((tc, _)) = p.ta.as_ref() {
                self.g15_chan_fresh(&mut tc.lock());
            }
        }
        // The destroyed queues' channels too, which their jobs alone keep
        // from `g15_reclaim_dead`: a dead channel left behind would stop the
        // firmware again at every check.
        for (d, _) in self.g15.dead_chans.lock().iter() {
            for c in d.chans() {
                self.g15_chan_fresh(&mut c.lock());
            }
        }
        let ini = &self.initdata;
        let mut pbs = 0;
        for (id, st) in self.g15.pb_states.lock().iter().enumerate() {
            let Some(st) = st else { continue };
            let desc = ini.pb_desc_table.raw_ptr().wrapping_add(16 * id);
            // SAFETY: entry `id` of the 64-entry table, the state's own.
            unsafe { st.reset_counts(desc) };
            pbs += 1;
        }
        self.g15_uma_each(|uma| uma.reset());
        // The recovery block (channel table +0x24C) but its state word
        // (+0x00), which the restart clears when done (`g15_check_restart`):
        // the firmware never clears the host-requested word (+0x04), and with
        // it set every later stuck-job event stops the firmware again as a
        // host stop, with no record. Then the per-slot records (channel table
        // +0x234, +0x23C, +0x244) as at boot: the firmware's post-recovery
        // walk, which clears them after its own stops, skips a host stop.
        let rb = ini.buf_0x238.raw_ptr();
        // SAFETY: in-bounds stores into the four buffers, which the stopped
        // firmware does not touch, sized as `g15_channel_table` allocates.
        let state = unsafe {
            core::ptr::write_bytes(rb.add(4), 0, 0x5C);
            core::ptr::write_bytes(ini.buf_0x218.raw_ptr(), 0, 0xC10);
            let b = ini.buf_0x220.raw_ptr();
            core::ptr::write_bytes(b, 0, 0x1248 / 4);
            b.add(0xC18 / 4).write_volatile(u32::MAX);
            b.add(0xC30 / 4).write_volatile(u32::MAX);
            core::ptr::write_bytes(ini.buf_0x228.raw_ptr(), 0, 0xE10);
            rb.cast::<u32>().read_volatile()
        };
        crate::mem::dc_civac(rb.cast_const(), 0x60);
        crate::mem::dc_civac(ini.buf_0x218.raw_ptr().cast_const(), 0xC10);
        crate::mem::dc_civac(ini.buf_0x220.raw_ptr().cast::<u8>().cast_const(), 0x1248);
        crate::mem::dc_civac(ini.buf_0x228.raw_ptr().cast_const(), 0xE10);
        // The resume rebuilds the job state (+0x45C4), and the two words the
        // firmware's next configuration snapshot reads start as at boot.
        let e = ini.event_page.raw_ptr().cast::<u8>();
        // SAFETY: in-bounds u32 stores into the event page.
        unsafe {
            e.add(0x45C4).cast::<u32>().write_volatile(1);
            e.add(0x08).cast::<u32>().write_volatile(0);
            e.add(0xC3C8).cast::<u32>().write_volatile(0);
        }
        crate::mem::dc_civac(e.wrapping_add(0x45C4).cast_const(), 4);
        crate::mem::dc_civac(e.wrapping_add(0x08).cast_const(), 4);
        crate::mem::dc_civac(e.wrapping_add(0xC3C8).cast_const(), 4);
        dev_err!(
            self.dev.as_ref(),
            "G15:   host stop: {} job(s) failed; their channels, {pbs} parameter buffer(s), the UMA pools, the recovery block (state {state}) and the per-slot records set up again\n",
            orphans.len()
        );
        orphans
    }

    /// Ends the wait for the firmware's restart after a host stop's resume.
    /// The restart skips every ring entry still pending (each ring's read
    /// index set to its write index), which an entry written before it would
    /// be lost to, and then clears the recovery block's state word. Once the
    /// word is 0, or after `G15_RESTART_MS`, the held-back submissions go on
    /// and every class is rung for them: the firmware's own wake after a host
    /// stop scans only the TA rings.
    pub(super) fn g15_check_restart(&self) {
        const G15_RESTART_MS: i64 = 2000;
        if !self.g15.restarting.load(Ordering::Acquire) {
            return;
        }
        let Some(since) = *self.g15.restart_since.lock() else {
            // Not resumed yet.
            return;
        };
        let rb = self.initdata.buf_0x238.raw_ptr().cast::<u32>();
        crate::mem::dc_civac(rb.cast::<u8>().cast_const(), 4);
        // SAFETY: an in-bounds u32 read of the recovery block.
        let state = unsafe { rb.read_volatile() };
        let ms = since.elapsed().as_millis();
        if state != 0 && ms < G15_RESTART_MS {
            return;
        }
        if state == 0 {
            dev_info!(
                self.dev.as_ref(),
                "G15:   the firmware's restart done after {ms} ms\n"
            );
        } else {
            dev_err!(
                self.dev.as_ref(),
                "G15:   the firmware's restart not done after {ms} ms (state {state}); going on\n"
            );
        }
        *self.g15.restart_since.lock() = None;
        let _orphans = core::mem::take(&mut *self.g15.orphans.lock());
        self.g15.restarting.store(false, Ordering::Release);
        *self.g15.resumes.lock() += 1;
        self.g15.resume_cv.notify_all();
        for class in 0..3 {
            let _ = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(class));
        }
    }

    /// Whether the firmware is stopped for a recovery: the event page's
    /// stopped flag, set by the firmware and cleared by the host's resume,
    /// or, after a host stop, until the firmware's restart is done.
    pub(super) fn g15_fw_stopped(&self) -> bool {
        self.g15.restarting.load(Ordering::Acquire) || self.g15_fw_stop_flag()
    }

    /// The event page's stopped flag alone.
    pub(super) fn g15_fw_stop_flag(&self) -> bool {
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

    /// Waits, holding no channel or ring lock, for the firmware to resume
    /// from a stop. A stopped firmware takes no ring entry, and the recovery
    /// needs the channel locks a waiting submission would hold; failing the
    /// submission instead would fail innocent processes' jobs at every stop.
    /// Fails after `G15_RESUME_WAIT_MS` or once the firmware has crashed.
    pub(super) fn g15_wait_resume(&self) -> Result {
        let start = Instant::<Monotonic>::now();
        let mut resumes = self.g15.resumes.lock();
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
            let _ = self.g15.resume_cv.wait_interruptible_timeout(
                &mut resumes,
                kernel::time::msecs_to_jiffies(left as u32),
            );
        }
    }
}
