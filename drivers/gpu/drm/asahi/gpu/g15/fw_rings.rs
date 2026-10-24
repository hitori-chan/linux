// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 firmware-to-host rings.
//!
//! The firmware reports to the host through four rings: events (job
//! completions, recovery stops, errors), traces, statistics and its log. A
//! ring's state block holds the host-owned read index at +0x00 and the
//! firmware-owned write index at +0x20.
//!
//! Spec: channel-table.md, faults.md.

use super::*;

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
        // (name, state buffer, storage buffer, index mask, record stride):
        // events (256 records of 0x38 bytes), traces (512 of 0x38) and
        // statistics (256 of 0x40).
        let mut total = 0u64;
        let mut completions = 0u32;
        let mut stop = None;
        // A record the poller answers: a grow request or a channel error.
        let mut answer = false;
        for (name, state_i, store_i, mask, stride) in [
            ("event", 0usize, 1usize, 0xFFu32, 0x38usize),
            ("trace", 4, 5, 0x1FF, 0x38),
            ("stats", 6, 7, 0xFF, 0x40),
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
                        if name == "event" && ty == 1 {
                            // A job completion: +0x04 the 128-bit map of
                            // the stamp indices that moved.
                            mod_dev_dbg!(
                                self.dev,
                                "G15 event ring: completion (+0x04 {:#x})\n",
                                rec.add(1).read_volatile()
                            );
                            self.g15.completions.fetch_add(1, Ordering::Relaxed);
                            completions += 1;
                        } else if name == "event" && ty == 4 {
                            // A recovery stop: +0x04 the stop count before
                            // the increment, +0x0C the guilty stamp.
                            let count = rec.add(1).cast::<u64>().read_unaligned();
                            stop = Some((count, rec.add(3).read_volatile()));
                        } else if name == "event" && ty == 8 {
                            // A channel error: the firmware killed a job or
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
                        } else if name == "event" && ty == 7 {
                            // A TA ran out of pages and waits for the host
                            // to grow its parameter buffer: +0x04 the
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
                                dev_err!(dev, "G15: a parameter buffer's grow request was lost\n");
                            }
                            answer = true;
                        } else if name == "event" && (ty == 0xA || ty == 0xE) {
                            // 0xA: a UMA pool ran short (slot, page list,
                            // context); 0xE: an asynchronous grow completed,
                            // or a recovery interrupted a pool's reset.
                            // Neither is answered.
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
                        if name == "stats" {
                            // A performance-state change (0xF) or a
                            // utilization sample (4); the rest is not used.
                            let mut r = [0u32; 8];
                            for (i, w) in r.iter_mut().enumerate() {
                                *w = rec.add(i).read_volatile();
                            }
                            self.g15.perf.stats_record(&r);
                        }
                        if name == "trace" {
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
                        n += 1;
                        read = (read + 1) & mask;
                    }
                    core::sync::atomic::fence(Ordering::Release);
                    read_p.write_volatile(read);
                    crate::mem::dc_civac(state.cast_const(), 0x40);
                    n
                } else {
                    0
                }
            };
            total += u64::from(n);
        }
        // The firmware's log: six sub-rings, one per firmware thread, of 256
        // entries of 0x38 bytes, and the message text in a 0x51000-byte
        // buffer. An entry is {+0 2, +4 multiplier, +8 sequence}; its message
        // sits at 0xD8 * (sequence + 256 * ring) * (multiplier + 1) in the
        // text buffer: {+0 3, +4 counter, +8 timestamp, +0x10 the text, NUL
        // terminated, at most 0xC8 bytes}.
        let subs = rings[2].raw_ptr().cast::<u32>();
        let entries = rings[3].raw_ptr();
        let text = rings[8].raw_ptr();
        let mut logged = 0u32;
        // SAFETY: as above; every offset is checked against the 0x15000 and
        // 0x51000-byte buffer sizes before the access.
        unsafe {
            for i in 0..6usize {
                let read_p = subs.add(i * 12);
                let write = subs.add(i * 12 + 8).read_volatile() & 0xFF;
                let mut read = read_p.read_volatile() & 0xFF;
                while read != write {
                    let e = (read as usize + 256 * i) * 0x38;
                    let seq = entries.add(e + 8).cast::<u32>().read_volatile() as usize;
                    let mult = entries.add(e + 4).cast::<u32>().read_volatile() as usize + 1;
                    let m = 0xD8 * (seq + 256 * i) * mult;
                    if m + 0xD8 <= 0x51000 {
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
                core::sync::atomic::fence(Ordering::Release);
                read_p.write_volatile(read);
            }
        }
        if total > 0 || logged > 0 {
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
        if answer {
            if let Some(kick) = self.g15.kick.lock().as_ref() {
                kick();
            }
        }
        total + u64::from(logged)
    }
}
