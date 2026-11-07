// SPDX-License-Identifier: GPL-2.0-only

//! G15 firmware-to-host rings.
//!
//! The firmware reports to the host through four rings: events (job
//! completions, recovery stops, errors), traces, statistics and its log. A
//! ring's state block holds the host-owned read index at +0x00 and the
//! firmware-owned write index at +0x20.
//!
//! Spec: channel-table.md, faults.md.

use super::*;

/// The rings `g15_drain_fw_rings` takes records from.
#[derive(Clone, Copy)]
enum FwRing {
    Event,
    Trace,
    Stats,
}

/// Empty drains within `G15_IRQ_STORM_MS` that mask a GPU interrupt line
/// (`g15_irq_drain`).
const G15_IRQ_STORM: u32 = 10000;
const G15_IRQ_STORM_MS: i64 = 1000;

/// A GPU interrupt line's drains (`g15_irq_drain`). Only the line's own
/// handler, one at a time, and the unmask, with the line masked, touch it.
pub(super) struct G15IrqLine {
    /// Empty drains since `since`, counting only those with no records
    /// taken by any drain since the line's last.
    empty: AtomicU32,
    /// When the first of them came (`ktime_get`, ns).
    since: core::sync::atomic::AtomicI64,
    /// `G15State::drained` at the line's last drain.
    seen: AtomicU64,
    /// The line's IRQ number + 1 while a storm keeps it masked, else 0.
    masked: AtomicU32,
}

impl G15IrqLine {
    pub(super) const fn new() -> Self {
        Self {
            empty: AtomicU32::new(0),
            since: core::sync::atomic::AtomicI64::new(0),
            seen: AtomicU64::new(0),
            masked: AtomicU32::new(0),
        }
    }
}

/// Stores a ring's read index, host-owned, in a line the firmware also writes
/// (its write index sits 0x20 on, and the log's sub-rings share lines), as
/// this CPU maps it write-back where the firmware does not cache it: the
/// line is fetched fresh just before the store and cleaned right after, so
/// the write-back carries the firmware's latest words, not those of the
/// drain's first read.
///
/// # Safety
///
/// `p` is a ring state's read index in the driver's firmware-shared rings.
unsafe fn store_read_index(p: *mut u32, v: u32) {
    core::sync::atomic::fence(Ordering::Release);
    crate::mem::dc_civac(p.cast::<u8>().cast_const(), 4);
    // SAFETY: the caller's.
    unsafe { p.write_volatile(v) };
    crate::mem::dc_civac(p.cast::<u8>().cast_const(), 4);
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Drains the four firmware-to-host rings and returns the number of
    /// records and log messages taken. A notification names no ring, so
    /// every one drains all four, as macOS's `drainFirmwareRings(1)` does.
    pub(crate) fn g15_drain_fw_rings(&self) -> u64 {
        // The firmware's notifications (the RTKit worker) and the GPU's
        // interrupts (their IRQ threads) both drain, one at a time.
        let _guard = self.g15.drain_lock.lock();
        let dev = self.dev.as_ref();
        let rings = &self.initdata.fw_rings;
        // (ring, name, state buffer, storage buffer, index mask, record stride):
        // events (256 records of 0x38 bytes), traces (512 of 0x38) and
        // statistics (256 of 0x40); 27.2's records are all 0x48.
        let mut total = 0u64;
        let mut completions = 0u32;
        let mut stop = None;
        // A record the poller answers: a grow request or a channel error.
        let mut answer = false;
        let fr = &FW_RINGS::ver;
        for (ring, name, state_i, store_i, mask, stride) in [
            (FwRing::Event, "event", 0usize, 1usize, 0xFFu32, fr.event),
            (FwRing::Trace, "trace", 4, 5, 0x1FF, fr.trace),
            (FwRing::Stats, "stats", 6, 7, 0xFF, fr.stats),
        ] {
            let state = rings[state_i].raw_ptr();
            let storage = rings[store_i].raw_ptr();
            // The firmware's ring writes reach memory, not this CPU's cached
            // copy: read the state and the records fresh.
            crate::mem::dc_civac(state.cast_const(), 0x40);
            // SAFETY: the state and storage buffers are the driver's own
            // firmware-shared ring buffers, and the read index is
            // host-owned. Every access is in bounds and volatile, since the
            // firmware writes concurrently.
            let n = unsafe {
                let read_p = state.cast::<u32>();
                let write_p = read_p.add(8);
                // The firmware wraps the write index at the ring size.
                let write = write_p.read_volatile() & mask;
                let mut read = read_p.read_volatile() & mask;
                if read != write {
                    let mut n = 0u32;
                    while read != write {
                        let rec = storage.add(((read & mask) as usize) * stride) as *const u32;
                        crate::mem::dc_civac(rec.cast::<u8>(), stride);
                        let ty = rec.read_volatile();
                        mod_dev_dbg!(self.dev, "G15 {name} ring: record type {:#x}\n", ty);
                        match (ring, ty) {
                            (FwRing::Event, 1) => {
                                // A job completion: +0x04 the 128-bit map of
                                // the stamp indices that moved.
                                mod_dev_dbg!(
                                    self.dev,
                                    "G15 event ring: completion (+0x04 {:#x})\n",
                                    rec.add(1).read_volatile()
                                );
                                self.g15.perf.completions.fetch_add(1, Ordering::Relaxed);
                                completions += 1;
                            }
                            (FwRing::Event, 4) => {
                                // A recovery stop: +0x04 the stop count before
                                // the increment, +0x0C the guilty stamp.
                                let count = rec.add(1).cast::<u64>().read_unaligned();
                                stop = Some((count, rec.add(3).read_volatile()));
                            }
                            (FwRing::Event, EV_CHAN_ERR::ver) => {
                                // A channel error (27.2: 7): the firmware killed a job or
                                // a 3D job hit a memory failure, and the channel
                                // stays stalled until the host answers. The
                                // poller does.
                                let e = G15ChanErr {
                                    kind: rec.add(1).read_volatile(),
                                    dm: rec.add(2).read_volatile(),
                                    index: rec.add(3).read_volatile(),
                                    stamp: rec.add(4).read_volatile(),
                                };
                                dev_err!(
                                dev,
                                "G15: channel error {}: data master {}, stamp index {}, stamp {:#x}\n",
                                e.kind,
                                e.dm,
                                e.index,
                                e.stamp
                            );
                                if self.g15.chan_errs.lock().push(e, GFP_KERNEL).is_err() {
                                    dev_err!(dev, "G15: a channel error was lost\n");
                                }
                                answer = true;
                            }
                            (FwRing::Event, EV_PB_GROW::ver) => {
                                // A TA ran out of pages and waits for the host
                                // to grow its parameter buffer (27.2: 6): +0x04 the
                                // context, +0x08 the PBID, +0x0C the request
                                // counter, +0x10 the TA slot, +0x14 the stop
                                // count. The poller answers it.
                                let r = G15GrowReq {
                                    ctx: rec.add(1).read_volatile(),
                                    pbid: rec.add(2).read_volatile(),
                                    counter: rec.add(3).read_volatile(),
                                    slot: rec.add(4).read_volatile(),
                                    stops: rec.add(5).cast::<u64>().read_unaligned(),
                                };
                                mod_dev_dbg!(
                                self.dev,
                                "G15: parameter buffer {} out of pages (TA slot {}, request {:#x})\n",
                                r.pbid,
                                r.slot,
                                r.counter
                            );
                                if self.g15.pb_grow_reqs.lock().push(r, GFP_KERNEL).is_err() {
                                    dev_err!(
                                        dev,
                                        "G15: a parameter buffer's grow request was lost\n"
                                    );
                                }
                                answer = true;
                            }
                            (FwRing::Event, EV_UMA::ver | EV_UMA_DONE::ver) => {
                                // 0xA: a UMA pool ran short (slot, page list,
                                // context); 0xE: an asynchronous grow completed,
                                // or a recovery interrupted a pool's reset
                                // (27.2: 9 and 0xD). Neither is answered.
                                dev_warn!(
                                    dev,
                                    "G15: UMA pool event {:#x}: {:#x} {:#x} {:#x} {:#x}\n",
                                    ty,
                                    rec.add(1).read_volatile(),
                                    rec.add(2).read_volatile(),
                                    rec.add(3).read_volatile(),
                                    rec.add(4).read_volatile()
                                );
                            }
                            (FwRing::Event, EV_PROC_EXIT::ver) => {
                                // A kill command done (device control 0x21,
                                // `g15_kill_jobs`; event 0xD, 27.2: 0xC):
                                // +0x04 its cookie.
                                self.g15.perf.kills_done.fetch_add(1, Ordering::Relaxed);
                            }
                            (FwRing::Event, _) => {}
                            (FwRing::Stats, _) => {
                                // A performance-state change (0xF) or a
                                // utilization sample (4); the rest is not used.
                                let mut r = [0u32; 8];
                                for (i, w) in r.iter_mut().enumerate() {
                                    *w = rec.add(i).read_volatile();
                                }
                                // 27.2 renumbered the two (0x13, 0x1C), whose
                                // fields are 14.8.3's; `stats_record` takes
                                // 14.8.3's numbers.
                                #[ver(V >= V27_2)]
                                {
                                    r[0] =
                                        STATS_272.iter().find(|t| t.0 == r[0]).map_or(0, |t| t.1);
                                }
                                self.g15.perf.stats_record(&r);
                            }
                            (FwRing::Trace, _) => {
                                let q = rec.cast::<u64>();
                                let r = [
                                    q.read_volatile(),
                                    q.add(1).read_volatile(),
                                    q.add(2).read_volatile(),
                                    q.add(3).read_volatile(),
                                    q.add(4).read_volatile(),
                                    q.add(5).read_volatile(),
                                    q.add(6).read_volatile(),
                                ];
                                let mut t = self.g15.trace.lock();
                                if t.0.len() < 256 {
                                    let _ = t.0.push(r, GFP_ATOMIC);
                                } else {
                                    let i = t.1 % 256;
                                    t.0[i] = r;
                                }
                                t.1 += 1;
                            }
                        }
                        n += 1;
                        read = (read + 1) & mask;
                    }
                    store_read_index(read_p, read);
                    n
                } else {
                    0
                }
            };
            total += u64::from(n);
        }
        // The firmware's log: six sub-rings, one per firmware thread, of 256
        // entries of 0x38 bytes, and the message text in a 0x51000-byte
        // buffer (27.2: `FW_RINGS`). An entry is {+0 2, +4 multiplier, +8 sequence}; its message
        // sits at 0xD8 * (sequence + 256 * ring) * (multiplier + 1) in the
        // text buffer: {+0 3, +4 counter, +8 timestamp, +0x10 the text, NUL
        // terminated, at most 0xC8 bytes}.
        let subs = rings[2].raw_ptr().cast::<u32>();
        let entries = rings[3].raw_ptr();
        let text = rings[8].raw_ptr();
        let mut logged = 0u32;
        // SAFETY: as above; every offset is checked against the entries'
        // and the text's buffer sizes before the access.
        unsafe {
            // The sub-rings' states, 48 B each, as the firmware wrote them.
            crate::mem::dc_civac(subs.cast::<u8>().cast_const(), fr.log_subs * 48);
            for i in 0..fr.log_subs {
                let read_p = subs.add(i * 12);
                let write = subs.add(i * 12 + 8).read_volatile() & 0xFF;
                let mut read = read_p.read_volatile() & 0xFF;
                while read != write {
                    let e = (read as usize + 256 * i) * fr.log_entry;
                    crate::mem::dc_civac(entries.add(e).cast_const(), fr.log_entry);
                    let seq = entries.add(e + 8).cast::<u32>().read_volatile() as usize;
                    let mult = entries.add(e + 4).cast::<u32>().read_volatile() as usize + 1;
                    // Raw firmware words: an entry torn or written over
                    // would overflow the product, and is skipped.
                    let m = (seq + 256 * i)
                        .checked_mul(0xD8)
                        .and_then(|m| m.checked_mul(mult))
                        .filter(|&m| m <= fr.log_text - 0xD8);
                    if let Some(m) = m {
                        crate::mem::dc_civac(text.add(m).cast_const(), 0xD8);
                        let s = text.add(m + 0x10);
                        let mut len = 0;
                        while len < 0xC8 && s.add(len).read_volatile() != 0 {
                            len += 1;
                        }
                        let msg = core::slice::from_raw_parts(s, len);
                        dev_info!(
                            dev,
                            "G15 fwlog[{i}]: {}\n",
                            kernel::str::BStr::from_bytes(msg)
                        );
                    }
                    logged += 1;
                    read = (read + 1) & 0xFF;
                }
                store_read_index(read_p, read);
            }
        }
        if total > 0 || logged > 0 {
            // Under the drain lock: a drain after this one sees it.
            self.g15.drained.fetch_add(1, Ordering::Relaxed);
            mod_dev_dbg!(
                self.dev,
                "G15: fw->host rings drained: {} record(s), {} log message(s)\n",
                total,
                logged
            );
        }
        if let Some((count, stamp)) = stop {
            self.g15_recovery(count, stamp);
        }
        if completions > 0 || stop.is_some() {
            self.g15_cl_retire(G15Retirer::Irq);
        }
        // A completion's stamps can trail its interrupt: an unfinished job
        // gets a pass at the next jiffy. With the slow tick, only a job the
        // firmware has finished, whose host word is late; any other starts
        // an idle poller, at the slow tick.
        let slow = G15_POLL_SLOW_MS.load(Ordering::Relaxed) != 0;
        let (unfinished, soon) = {
            let pending = self.g15.pending.lock();
            let unfinished = pending.iter().any(|p| !p.signaled);
            let soon =
                unfinished && (!slow || pending.iter().any(|p| !p.signaled && p.fw_at.is_some()));
            (unfinished, soon)
        };
        if answer || soon {
            self.g15_kick(true);
        } else if unfinished {
            self.g15_kick(false);
        }
        total + u64::from(logged)
    }

    /// GPU interrupt line `line`'s (index 0 or 4) threaded handler, `irq` its
    /// number: drains the rings. macOS acks nothing for either line, so the
    /// firmware pulses them; a line that stays asserted with nothing to
    /// drain is masked after `G15_IRQ_STORM` empty drains within
    /// `G15_IRQ_STORM_MS`, until the next resume (`g15_irq_unmask`).
    ///
    /// Both lines drain the same rings, and when both fire for one event the
    /// drain that comes second finds nothing: an empty drain counts only if
    /// no drain of any kind took records since the line's last. Events
    /// whose records no drain sees at all (an interrupt ahead of its record)
    /// still count on both lines, and the line that always comes second
    /// never drains records itself to start its count again: the window
    /// does. A line stuck asserted drains back to back, microseconds apart,
    /// and passes 10,000 within the second; the line that comes second
    /// would need 10,000 such events in it.
    pub(crate) fn g15_irq_drain(&self, line: usize, irq: u32) {
        let n = self.g15_drain_fw_rings();
        let Some(l) = self.g15.irq_lines.get(line) else {
            return;
        };
        let drained = self.g15.drained.load(Ordering::Relaxed);
        let seen = l.seen.swap(drained, Ordering::Relaxed);
        if n > 0 {
            l.empty.store(0, Ordering::Relaxed);
            return;
        }
        if seen != drained {
            return;
        }
        // SAFETY: `ktime_get` may be called anywhere but in NMI context.
        let now = unsafe { kernel::bindings::ktime_get() };
        let empty = l.empty.load(Ordering::Relaxed);
        if empty == 0
            || now - l.since.load(Ordering::Relaxed)
                >= Delta::from_millis(G15_IRQ_STORM_MS).as_nanos()
        {
            l.since.store(now, Ordering::Relaxed);
            l.empty.store(1, Ordering::Relaxed);
        } else if empty + 1 < G15_IRQ_STORM {
            l.empty.store(empty + 1, Ordering::Relaxed);
        } else {
            l.empty.store(0, Ordering::Relaxed);
            let index = if line == 0 { 0 } else { 4 };
            dev_err!(
                self.dev.as_ref(),
                "G15: GPU IRQ index {index} stays asserted; masking it until the next resume\n"
            );
            // SAFETY: masks the line of the handler this runs in; nosync
            // from its own thread. `g15_irq_unmask` unmasks it once.
            unsafe { kernel::bindings::disable_irq_nosync(irq) };
            // After the mask: an unmask that comes between finds none.
            l.masked.store(irq + 1, Ordering::Release);
        }
    }

    /// Unmasks the GPU interrupt lines a storm masked (`g15_irq_drain`), at
    /// each resume from a stop: the storms seen came with a firmware stuck
    /// before a stop, and a line masked for good leaves the completions to
    /// the other line and the poller until the reboot.
    pub(super) fn g15_irq_unmask(&self) {
        for (i, l) in self.g15.irq_lines.iter().enumerate() {
            let m = l.masked.swap(0, Ordering::Acquire);
            if m == 0 {
                continue;
            }
            l.empty.store(0, Ordering::Relaxed);
            let index = if i == 0 { 0 } else { 4 };
            dev_info!(self.dev.as_ref(), "G15: GPU IRQ index {index} unmasked\n");
            // SAFETY: the line `g15_irq_drain` masked, unmasked once per
            // mask (the swap above).
            unsafe { kernel::bindings::enable_irq(m - 1) };
        }
    }
}
