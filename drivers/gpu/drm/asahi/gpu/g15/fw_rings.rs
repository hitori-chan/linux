// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 firmware-to-host rings: events, statistics, traces and the log.

use super::*;

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: drain the four firmware-to-host rings (spec: agx-g15c/channel.md,
    /// "Firmware-to-host rings"). The firmware posts a plain 0x42<<48 on
    /// EP 0x20 with no ring ID, so every notification drains all four, as
    /// the kext's `drainFirmwareRings(1)` does. Each ring's state block:
    /// read u32 at +0x00 (host-owned), write u32 at +0x20 (firmware-owned).
    pub(crate) fn g15_drain_fw_rings(&self) -> u64 {
        // The firmware's 0x42 messages (the RTKit worker) and the GPU's
        // interrupts (their IRQ threads) both drain; one at a time.
        let _guard = self.g15.drain_lock.lock();
        let dev = self.dev.as_ref();
        let rings = &self.initdata.fw_rings;
        // (name, state idx, storage idx, index mask, record stride):
        // pair 1 event (256 x 56 B, 8-bit index), pair 3 trace
        // (512 x 56 B, 10-bit), pair 4 stats (256 x 64 B, 8-bit).
        let mut total = 0u64;
        let mut completions = 0u32;
        let mut stop = None;
        for (name, state_i, store_i, mask, stride) in [
            ("event", 0usize, 1usize, 0xFFu32, 0x38usize),
            ("trace", 4, 5, 0x1FF, 0x38),
            ("stats", 6, 7, 0xFF, 0x40),
        ] {
            let state = rings[state_i].raw_ptr();
            let storage = rings[store_i].raw_ptr();
            // The firmware's ring writes reach memory, not this CPU's cached
            // copy (boots #105-#110: a completion record seen only at the next
            // notification): read the state and the records fresh.
            crate::mem::dc_civac(state.cast_const(), 0x40);
            // SAFETY: the state/storage buffers are the driver's own
            // firmware-shared ring buffers (fw_rings); the read index is
            // host-owned (the kext's drains do the same); every access is
            // in-bounds and volatile (the firmware writes concurrently).
            let n = unsafe {
                let read_p = state.cast::<u32>();
                let write_p = read_p.add(8);
                // The firmware wraps the write index at the ring size
                // (boot #128: an unmasked read index ran on past it).
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
                            // +0x04 the 128-bit map of the stamp indices that moved.
                            mod_dev_dbg!(
                                self.dev,
                                "G15 event ring: completion (+0x04 {:#x})\n",
                                rec.add(1).read_volatile()
                            );
                            self.g15.completions.fetch_add(1, Ordering::Relaxed);
                            completions += 1;
                        } else if name == "event" && ty == 4 {
                            // The recovery packet: +0x04 the stop count before
                            // the increment, +0x0C the guilty stamp value.
                            let count = rec.add(1).cast::<u64>().read_unaligned();
                            stop = Some((count, rec.add(3).read_volatile()));
                        } else if name == "event" && ty == 8 {
                            dev_err!(dev, "G15: channel error {}: data master {}, stamp index {}, stamp {:#x}\n",
                                     rec.add(1).read_volatile(), rec.add(2).read_volatile(),
                                     rec.add(3).read_volatile(), rec.add(4).read_volatile());
                        } else if name == "event" && ty == 7 {
                            // A parameter buffer ran out of pages (Asahi's GrowTVB:
                            // the VM slot, the buffer slot, the counter); not
                            // answered yet (spec: parameter-buffer.md, "Growing").
                            dev_warn!(dev, "G15: parameter buffer full: VM slot {}, buffer slot {}, counter {:#x}\n",
                                      rec.add(1).read_volatile(), rec.add(2).read_volatile(),
                                      rec.add(3).read_volatile());
                        } else if name == "event" && (ty == 0xA || ty == 0xE) {
                            // 0xA: a UMA pool ran short (slot, page list,
                            // context); 0xE: an async grow completed, or a
                            // recovery interrupted a pool's reset (spec:
                            // uma.md); neither is answered.
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
        // Pair 2: the firmware log — six sub-rings (one per firmware
        // thread; state 0x120, 256 x 0x38 B entries each in the 0x15000
        // storage), the text in the 0x51000 buffer (channel table +0x1f8).
        // The firmware's print (sub_FFFFFC000003C924) only writes them
        // when channel table +0x230 != 0: entry = {+0 2, +4 0, +8 seq},
        // message at 0x51000-buffer + 0xD8 * (seq + 256 * ring) * (+4 + 1)
        // = {+0 3, +4 counter, +8 timestamp, +0x10 text (NUL, <= 0xC8)}.
        let subs = rings[2].raw_ptr().cast::<u32>();
        let entries = rings[3].raw_ptr();
        let text = rings[8].raw_ptr();
        let mut logged = 0u32;
        // SAFETY: as above; every offset is bounds-checked against the
        // 0x15000 / 0x51000 buffer sizes before the access.
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
            self.g15_cl_retire();
        }
        total + u64::from(logged)
    }
}
