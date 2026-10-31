// SPDX-License-Identifier: GPL-2.0-only

//! G15 TA (tiling) jobs: the job state, its register list and the stream
//! the firmware runs for a render pass's vertex half.
//!
//! Spec: register-lists.md, render-firmware.md, render-job.md, stream.md.

use super::*;

#[versions(AGX)]
impl GpuManager::ver {
    /// Builds a render pass's TA job on the TA channel `ch`, as the next job
    /// on it. `pm` is the parameter-manager record it carries: PMRebuild
    /// for the first TA job of a parameter buffer, PMGrow for the first after
    /// the buffer grew. `uma` is the queue's UMA pool.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn g15_ta_job_new(
        &self,
        ch: &G15ClChannel,
        pb: &G15Pb,
        rt: &G15Rt,
        ctx: u32,
        id: u32,
        key: u32,
        scene_i: usize,
        link: G15RdLink,
        pm: G15Pm,
        cmd: &G15RdCmd,
        uma: &Arc<G15Uma>,
    ) -> Result<G15RdJob> {
        let g = &cmd.geom;
        let stamp = (ch.submitted + 1) << 8;
        // Firmware-uncached, as the CL job's (`g15_cl_job_new`).
        let (job_state, stream, pre) = {
            let mut guard = self.alloc.lock();
            (
                guard
                    .gpu_fw_nc
                    .array_empty_tagged::<u8>(TA_TIMES + 16, b"JSTA")?,
                guard.fw_nc.array_empty_tagged::<u8>(0x400, b"STTA")?,
                guard.fw_nc.array_empty_tagged::<u8>(0x40, b"PMRB")?,
            )
        };
        let own = match link.ntf {
            Some(_) => None,
            None => Some(self.g15_notifier_new(key, 1)?),
        };
        let ntf = link.ntf.or(own.as_ref().map(va)).ok_or(EINVAL)?;
        let metrics_va = uma.metrics_slot();
        let uma_state = va(&uma.state);
        let js = va(&job_state);
        let strm = va(&stream);
        let state_va = va(&ch.state);
        let words_va = va(&ch.words);
        let info = va(&pb.info);
        let scene = pb.scene(scene_i);
        let b218 = self.initdata.buf_0x218.gpu_va().get();
        let user_ts = cmd.ts_ta != (0, 0);

        // The scene's page-metrics address, as register 0x1C910 takes it.
        let a = va(&pb.metrics) + 4 * (scene_i % PB_SCENES) as u64;
        let r1c910 = (va40(a) & !1) | 1;
        let slot_elem = (h(&pb.slots) + (scene_i % PB_SLOTS * PB_SLOT_STRIDE) as u64) & !0xF;
        let heapmeta = (va40(rt.heapmeta()) & !0x3F) | 1 << 63;
        let te_mtile1 = (3 * g.tpm_x) | ((2 * g.tpm_x) << 9) | g.tpm_x << 18;
        let te_mtile2 = (3 * g.tpm_y) | ((2 * g.tpm_y) << 9) | g.tpm_y << 18;
        // TA_RENDER_TARGET_MAX: (layers - 1) | 0x8000, and for two layers or
        // more also 0x4000 | 0x2000, as on G13. macOS takes 0x1000 for the
        // last when a descriptor byte is clear (not decoded).
        let rt_max = u64::from(if g.layers > 1 {
            0xE000 | (g.layers - 1)
        } else {
            0x8000
        });
        let entries: [(u32, u64); 68] = [
            (0x1748, 1), // inline, write-enable clear
            (0x10141, 0x200),
            (0x1C039, va40(rt.tilemap())),
            (0x1C9C8, va40(rt.tilemap())),
            (0x1C041, h(&rt.cl_tilemaps)),
            (0x1C9D0, h(&rt.cl_tilemaps)),
            (0x1C0A1, h(&rt.tpc)),
            (0x1C031, heapmeta),
            (0x1C9C0, heapmeta),
            (0x1C051, 0x003A_0012_006B_0003), // as Metal sets it
            (0x1C061, 1),
            (0x10149, g.utile_config),
            (0x10139, cmd.multisamplectl), // PPP_MULTISAMPLECTL
            (0x10111, h(&rt.preempt1)),
            (0x1C9B0, h(&rt.preempt1)),
            (0x10119, h(&rt.preempt2)),
            (0x1C9B8, h(&rt.preempt2)),
            (0x1C958, 1),
            (0x1C950, (h(&rt.preempt3) & !0x1F) | 1 << 50),
            (0x1C930, 0),
            (0x1C880, cmd.vdm.map_or(h(&rt.vdm), va40) & !3),
            (0x1C898, 0),
            (0x1C948, h(&rt.meta2)),
            (0x1C888, h(&rt.meta3)),
            // halSetVdmSegmentCtrlReg with 4 clusters: (0x15 - 0x10) << 8 |
            // (0x15 - 0x10) << 19 | 16 * 4.
            (0x1C890, 0x28_0540),
            (0x1C918, 4), // the chip's segment count index
            (0x1C079, va40(rt.layermeta())),
            (0x1C9D8, va40(rt.layermeta())),
            (0x1C089, h(&rt.cl_layermeta)),
            (0x1C9E0, h(&rt.cl_layermeta)),
            (0x16C41, h(&rt.meta4) & !0x7F),
            (0x1CA40, h(&rt.meta4) & !0x7F),
            (0x1C9A8, 0x1C),
            (0x1C920, h(&rt.meta1) & !0x3F),
            (0x10151, 0),
            (0x1C199, 0),
            (0x1C1A1, 0),
            (0x1C1A9, 0),
            (0x1C1B1, 0),
            (0x1C1B9, 0),
            (0x1C8F8, 0x8860),
            (0x1C0B1, u64::from(g.rgn_size())),
            (0x1C850, u64::from(g.rgn_size())),
            (0x10131, cmd.multisamplectl),
            (0x10121, 0x202), // PPP_CTRL: 2 | chip+0x650 bit 17
            (0x10129, u64::from((g.h - 1) << 16 | (g.w - 1))), // PPP_SCREEN
            (0x101B9, g.te_screen()), // TE_SCREEN
            (0x1C069, u64::from(te_mtile1)),
            (0x1C071, u64::from(te_mtile2)),
            (0x1C081, u64::from(g.tpm_x * g.tpm_y)), // TE_MTILE
            (0x1C0A9, u64::from(2 * g.n)),           // TE_TPC (tpc_stride)
            (0x10171, 0x100),
            (0x10169, rt_max), // TA_RENDER_TARGET_MAX
            (0x12099, 0x1C),
            (0x101E1, 0x1C),
            (0x1C9E8, rt_max & 0x47FF),
            (0x1A099, 0),
            (0x1A0A1, 0),
            (0x1A069, 0),
            (0x1A071, 0),
            (0x1A0C9, 0),
            (0x1A0D1, 0),
            (0x101C9, 0),
            (0xD471, 0),
            (0x1A0F1, 8),
            (0x10799, 0xFF_0000),
            (0xA5A1, 0x60_0040_0020),
            (0xD419, ((0x60 * 8) << 32) | (0x20 * 8)),
        ];
        let (entries, n_entries) = variant_list(&entries, self.cfg.gpu_variant);
        let tail: [(u32, u64); 4] = [
            (0x1C830, u64::from(pb.id)),
            (0x1CA30, slot_elem),
            (0x16C39, slot_elem), // the PM's: 40-bit
            (0x1C910, r1c910),
        ];
        // SAFETY: every store is in bounds of the job's own fresh buffers:
        // the 0x930-byte job state (its 0x700-byte list body holds the 72
        // entries' 0x360 bytes), the 0x400-byte stream (0x2D8 bytes used)
        // and the 0x40-byte record.
        unsafe {
            let j = W(job_state.raw_ptr());
            j.u32(0x00, 0); // tag = TA
            j.u64(0x04, 1); // the queue's job counter
            j.u32(0x0C, ctx);
            j.u64(0x14, ntf);
            j.u32(0x1C, pb.id);
            j.u32(0x20, 0);
            j.u64(0x24, info);
            j.u64(0x2C, scene);
            j.u64(0x34, pb.trailer());
            let n = j.reglist(0x40, &entries[..n_entries]);
            let n = n + j.reglist(0x40 + n as usize * 12, &tail);
            j.u64(0x740, js + 0x40);
            j.u32(0x748, (n * 12) << 16 | n);
            j.u64(0x760, va(&rt.tpc));
            j.u64(0x768, g.tpc_size() as u64);
            j.u64(0x770, strm);
            j.u32(0x778, 0x300);
            j.u32(0x77C, link.other_index); // the partner 3D's stamp index
            j.u32(0x780, link.other_stamp); // and stamp
            j.u64(0x7A8, h(&rt.preempt1));
            // Out of pages, the TA waits for the host to grow the buffer
            // (event 7, `g15_pb_grow_pending`) where it would otherwise
            // render in parts, as macOS's do in passes that must not
            // (`desc+0xE0C`). At the cap it renders in parts.
            if (pb.published.load(Ordering::Relaxed) as usize) < self.g15.pb_cap {
                j.u32(0x854, 1);
            }
            j.u64(0x864, words_va); // host stamp word
            j.u64(0x86C, words_va + 4); // FW stamp word
            j.u32(0x874, stamp);
            j.u32(0x878, ch.stamp_index);
            j.u32(0x87C, 0); // channel index
            j.u32(0x880, 0);
            j.u32(0x884, id);
            j.u32(0x888, 0); // the queue's TA counter
            j.u64(0x8B0, js + TA_TIMES as u64); // the GPU start
            j.u64(0x8B8, js + TA_TIMES as u64 + 8); // and end
            j.u64(0x8C0, cmd.ts_ta.0); // the user timestamps
            j.u64(0x8C8, cmd.ts_ta.1);

            // The UMA pool, which the kick registers unconditionally (a NULL
            // descriptor crashes the firmware): its state, the
            // clean+invalidate flag and the metrics slot.
            j.u64(0x8D6, uma_state);
            j.0.add(0x8DE).write_volatile(1);
            j.u64(0x8EF, metrics_va);

            let s = W(stream.raw_ptr());
            // Type 5: the TA context record, payload at +4 (0x1CC bytes).
            s.u32(0x00, 5);
            let p = |o: usize| 4 + o;
            s.u64(p(0x10), js + 0x40);
            s.u64(p(0x18), info);
            s.u64(p(0x20), scene);
            s.u64(p(0x28), b218 + 4);
            s.u64(p(0x30), state_va);
            s.u64(p(0x38), js + 0x84C);
            s.u32(p(0x40), ctx);
            s.u32(p(0x44), g15_soft_faults()); // isHWSoftFaultEnabled
            s.u32(p(0x48), key);
            s.u32(p(0x4C), pb.id);
            s.u32(p(0x50), 0);
            s.u32(p(0x54), 0);
            s.u32(p(0x58), 0);
            s.u32(p(0x5C), 0);
            s.u64(p(0x60), js + 0x784);
            s.u64(p(0x68), js + 0x890);
            s.u32(p(0x78), id);
            s.u32(p(0x180), 0); // no items
            s.u64(p(0x188), uma_state); // the command-data descriptor
            s.u64(p(0x1A0), metrics_va);
            s.u64(p(0x1B0), 1); // js+0x04
            s.u64(p(0x1B8), ntf + 0xA8);
            // Type 3: the TA timestamps, around the WFI.
            for (off, first) in [(0x1CC, true), (0x20C, false)] {
                s.u32(off, if first { 0x8000_0003 } else { 3 });
                s.u64(off + 0x04, js + 0x8A8);
                s.u64(off + 0x0C, js + 0x8B0);
                s.u64(off + 0x14, js + if first { 0x8B0 } else { 0x8B8 });
                s.u64(off + 0x1C, state_va);
                s.u64(off + 0x24, if user_ts { js + 0x8C0 } else { 0 });
                s.u64(off + 0x2C, js + 0x900);
                s.u32(off + 0x34, id);
            }
            s.u32(0x208, 1); // WFI

            // Type 6: the TA finish record (0x8C bytes).
            let f = 0x248;
            s.u32(f, 6);
            s.u64(f + 0x04, scene);
            s.u64(f + 0x0C, info);
            s.u64(f + 0x14, b218 + 4);
            s.u64(f + 0x1C, state_va);
            s.u64(f + 0x24, js + 0x84C);
            s.u32(f + 0x2C, ctx);
            s.u64(f + 0x34, js + 0x784);
            s.u32(f + 0x40, id);
            s.u64(f + 0x44, words_va + 4);
            s.u32(f + 0x4C, stamp);
            s.u64(f + 0x74, strm + 4 + 0x188);
            // A stopped job rewinds to the stream's start, its context record.
            s.u32(f + 0x7C, 0u32.wrapping_sub(f as u32));
            s.u64(f + 0x84, js + 0x8F8);
            s.u32(0x2D4, 0x4000_0002); // terminator

            let r = W(pre.raw_ptr());
            if pm == G15Pm::Grow {
                // Type 5: the PMGrow record (0x18 bytes).
                r.u32(0x00, 5);
                r.u32(0x04, ctx);
                r.u32(0x08, pb.id);
                r.u64(0x0C, info);
                r.u32(0x14, stamp);
            } else {
                // Type 6: the PMRebuild record (0x20 bytes).
                r.u32(0x00, 6);
                r.u32(0x04, ctx);
                r.u32(0x08, pb.id);
                // The PM's start and head: a head of 0 would send the
                // firmware into its full rebuild.
                r.u32(0x0C, 0);
                r.u32(0x10, pb.published.load(Ordering::Relaxed));
                r.u64(0x14, info);
                r.u32(0x1C, stamp);
            }
        }
        // The stamp barrier on the queue's previous 3D job, if unfinished.
        let wait = self.g15_stamp_barrier(&link, stamp, id)?;
        Ok(G15RdJob {
            job_state,
            _stream: stream,
            _notifier: own,
            wait,
            after: None,
            pre: if pm == G15Pm::None { None } else { Some(pre) },
            stamp,
            uma: uma.clone(),
        })
    }
}
