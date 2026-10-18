// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 diagnostics: state dumps for stalls and recoveries, and a firmware
//! dump through the m1n1 hypervisor for development.

use super::*;

/// The m1n1 hypervisor call (`brk #0x4242`, x0 = the call, x1 = a tag) that
/// dumps the firmware's data segments and the GPU's job registers on the
/// host side; read-only. The tag `G15_FWDUMP_CRASH` also saves the
/// coprocessor's crash log.
pub(super) const HVC_G15_FWDUMP: u64 = 0x1503;
/// The dump tag of a firmware crash.
pub(crate) const G15_FWDUMP_CRASH: u64 = 0xc;

/// Has the m1n1 hypervisor dump the firmware's data segments and the GPU's
/// job registers (`tag` names the dump). Only with the `G15LabHv` debug
/// flag, under the hypervisor.
pub(crate) fn g15_fwdump(tag: u64) {
    if !debug_enabled(DebugFlags::G15LabHv) {
        return;
    }
    // SAFETY: the hypervisor reads x0 and x1, writes x0 and resumes after
    // the brk; nothing else in the guest's state changes. The `dsb sy`
    // completes the guest's writes before the dump.
    unsafe {
        core::arch::asm!(
            "dsb sy",
            "brk #0x4242",
            inout("x0") HVC_G15_FWDUMP => _,
            in("x1") tag,
            options(nostack),
        );
    }
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Logs the pending jobs (stamps, contexts, channel state), the rings
    /// holding unconsumed entries and the driver's counters, for a job that
    /// a queue teardown cancels.
    pub(crate) fn g15_cl_dump_pending(&self) {
        for p in self.g15.pending.lock().iter() {
            let ch = p.chan.lock();
            // SAFETY: in-bounds u32 reads of the channel's own stamp words.
            let (host, fwst) = unsafe {
                let w = ch.words.raw_ptr() as *const u32;
                (w.read_volatile(), w.add(1).read_volatile())
            };
            dev_warn!(
                self.dev.as_ref(),
                "G15: pending CL job {} ctx {} stamp {:#x}: host {:#x} fw {:#x}, chan submitted {}\n",
                p.n,
                p.ctx,
                p.stamp,
                host,
                fwst,
                ch.submitted
            );
            Self::g15_dump_chan_state(self.dev.as_ref(), "chan", &ch);
            if let Some((ta, _)) = p.ta.as_ref() {
                Self::g15_dump_chan_state(self.dev.as_ref(), "ta chan", &ta.lock());
            }
        }
        for k in 0..fw::g15::RINGS {
            let base = self.initdata.ring_area.raw_ptr();
            let wp = base.wrapping_add(k * fw::g15::RING_STRIDE);
            let rp = base.wrapping_add(fw::g15::RING_REGION2_OFF + 16 * k);
            crate::mem::dc_civac(wp.cast_const(), 4);
            crate::mem::dc_civac(rp.cast_const(), 4);
            // SAFETY: in-bounds u32 reads of the 128 KiB ring region.
            let (w, r) = unsafe {
                (
                    (wp as *const u32).read_volatile(),
                    (rp as *const u32).read_volatile(),
                )
            };
            if w != r {
                dev_warn!(
                    self.dev.as_ref(),
                    "G15: ring {} holds unconsumed entries: write {:#x} read {:#x}\n",
                    k,
                    w,
                    r
                );
            }
        }
        for k in [fw::g15::ring(0), fw::g15::ring(1), fw::g15::ring(2)] {
            self.g15_dump_ring_entries(k);
        }
        self.g15_trace_dump(64);
        let ev = self.initdata.fw_rings[0].raw_ptr() as *const u32;
        // SAFETY: in-bounds reads of the event ring's state block.
        let (rd, wr) = unsafe { (ev.read_volatile(), ev.add(8).read_volatile()) };
        dev_warn!(
            self.dev.as_ref(),
            "G15: {} notification(s), {} GPU IRQ(s), {} completion record(s), {} re-ring(s), {} nudge(s), {} late host stamp(s); event ring read {:#x} write {:#x}\n",
            self.g15.notifies.load(Ordering::Relaxed),
            self.g15.irqs.load(Ordering::Relaxed),
            self.g15.completions.load(Ordering::Relaxed),
            self.g15.rerings.load(Ordering::Relaxed),
            self.g15.nudges.load(Ordering::Relaxed),
            self.g15.host_stamp_late.load(Ordering::Relaxed),
            rd,
            wr
        );
        g15_fwdump(3);
    }

    /// Logs the last `last` records of the firmware's trace ring.
    pub(super) fn g15_trace_dump(&self, last: usize) {
        let t = self.g15.trace.lock();
        let n = t.0.len();
        let start = if n < 256 { 0 } else { t.1 % 256 };
        let first = n.saturating_sub(last);
        for j in first..n {
            let r = &t.0[(start + j) % n.max(1)];
            dev_warn!(
                self.dev.as_ref(),
                "G15 ktrace: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}\n",
                r[0] as u32,
                (r[0] >> 32) as u32,
                r[1] as u32,
                (r[1] >> 32) as u32,
                r[2] as u32,
                (r[2] >> 32) as u32,
                r[3] as u32,
                (r[3] >> 32) as u32,
                r[4] as u32,
                (r[4] >> 32) as u32,
                r[5] as u32,
                (r[5] >> 32) as u32,
                r[6] as u32,
                (r[6] >> 32) as u32
            );
        }
    }

    /// Logs the channel state the firmware writes when it takes a ring
    /// entry (the record-slot cursor, the entry's command ID and three more
    /// words) and the host's job and record counts.
    pub(super) fn g15_dump_chan_state(
        dev: &kernel::platform::Device,
        name: &str,
        ch: &G15ClChannel,
    ) {
        let st = ch.state.raw_ptr();
        crate::mem::dc_civac(st.cast_const(), 0xC0);
        // SAFETY: in-bounds u32 reads of the 0x24C0-byte state block.
        let w = |o: usize| unsafe { (st.add(o) as *const u32).read_volatile() };
        dev_warn!(
            dev,
            "G15: {} stamp index {}: state +0x20 {:#x} +0x24 {:#x} +0x28 {:#x} +0x5c {:#x} +0x80 {:#x} +0x98 {:#x}; submitted {} records {}\n",
            name,
            ch.stamp_index,
            w(0x20),
            w(0x24),
            w(0x28),
            w(0x5C),
            w(0x80),
            w(0x98),
            ch.submitted,
            ch.submitted_records
        );
    }

    /// Logs the last three entries published to ring `k`.
    pub(super) fn g15_dump_ring_entries(&self, k: usize) {
        let base = self.initdata.ring_area.raw_ptr();
        let wp = base.wrapping_add(k * fw::g15::RING_STRIDE);
        crate::mem::dc_civac(wp.cast_const(), 4);
        // SAFETY: an in-bounds u32 read of the 128 KiB ring region.
        let w = unsafe { (wp as *const u32).read_volatile() } as usize;
        for back in 1..=3usize {
            let i = (w + 256 - back) % 256;
            let e = base.wrapping_add(k * fw::g15::RING_STRIDE + 8 + i * 24);
            crate::mem::dc_civac(e.cast_const(), 24);
            // SAFETY: in-bounds u64 reads of an entry of the ring.
            let q = unsafe {
                [
                    (e as *const u64).read_volatile(),
                    (e.add(8) as *const u64).read_volatile(),
                    (e.add(16) as *const u64).read_volatile(),
                ]
            };
            dev_warn!(
                self.dev.as_ref(),
                "G15: ring {} entry {}: {:#018x} {:#018x} {:#018x}\n",
                k,
                i,
                q[0],
                q[1],
                q[2]
            );
        }
    }

    /// Logs every ring's write, read and CFI words, and the entries of ring
    /// `k` around its read index.
    pub(super) fn g15_dump_ring_stall(&self, k: usize) {
        let base = self.initdata.ring_area.raw_ptr();
        let w32 = |off: usize| {
            let p = base.wrapping_add(off);
            crate::mem::dc_civac(p.cast_const(), 4);
            // SAFETY: an in-bounds u32 read of the 128 KiB ring region.
            unsafe { (p as *const u32).read_volatile() }
        };
        for r in 0..9 {
            let off = fw::g15::RING_REGION2_OFF + 16 * r;
            dev_warn!(
                self.dev.as_ref(),
                "G15: ring {r}: write {:#x} read {:#x} cfi {:#x}\n",
                w32(r * fw::g15::RING_STRIDE),
                w32(off),
                w32(off + 8)
            );
        }
        let read = w32(fw::g15::RING_REGION2_OFF + 16 * k) as usize;
        for d in 0..4usize {
            let i = (read + 256 - 1 + d) % 256;
            let e = base.wrapping_add(k * fw::g15::RING_STRIDE + 8 + i * 24);
            crate::mem::dc_civac(e.cast_const(), 24);
            // SAFETY: in-bounds u64 reads of an entry of the ring.
            let q = unsafe {
                [
                    (e as *const u64).read_volatile(),
                    (e.add(8) as *const u64).read_volatile(),
                    (e.add(16) as *const u64).read_volatile(),
                ]
            };
            dev_warn!(
                self.dev.as_ref(),
                "G15: ring {} entry {:#x}: {:#018x} {:#018x} {:#018x}\n",
                k,
                i,
                q[0],
                q[1],
                q[2]
            );
        }
    }
}
