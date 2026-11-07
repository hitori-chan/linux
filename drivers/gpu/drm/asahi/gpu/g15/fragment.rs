// SPDX-License-Identifier: GPL-2.0-only

//! G15 3D (fragment) jobs: the job state, its register list and the stream
//! the firmware runs for a render pass's fragment half.
//!
//! Spec: depth-msaa.md, register-lists.md, render-job.md, stream.md.

use super::*;

#[versions(AGX)]
impl GpuManager::ver {
    /// Builds a render pass's 3D job on the 3D channel `ch`, as the next job
    /// on it. When `link` names a TA job, the 3D job waits for it behind a
    /// stamp barrier. `uma` is the queue's UMA pool.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn g15_3d_job_new(
        &self,
        ch: &G15ClChannel,
        pb: &G15Pb,
        rt: &G15Rt,
        ctx: u32,
        id: u32,
        key: u32,
        scene_i: usize,
        link: G15RdLink,
        cmd: &G15RdCmd,
        uma: &Arc<G15Uma>,
    ) -> Result<G15RdJob> {
        let g = &cmd.geom;
        let stamp = ch.submitted.wrapping_add(1) << 8;
        let (job_state, times, stream) = {
            let mut guard = self.alloc.lock();
            (
                guard
                    .job
                    .array_empty_tagged::<u8>(D3_JS::ver.c.size, b"JS3D")?,
                guard.fw_nc.array_empty_tagged::<u8>(TIMES_SIZE, b"TIMS")?,
                guard.job_fw.array_empty_tagged::<u8>(0x400, b"ST3D")?,
            )
        };
        let own = match link.ntf {
            Some(_) => None,
            None => Some(self.g15_notifier_new(key, 1)?),
        };
        let ntf = link
            .ntf
            .or(own.as_ref().map(|n| va(&n.node)))
            .ok_or(EINVAL)?;
        let metrics_va = uma.metrics_slot();
        let uma_state = va(&uma.state);
        let js = va(&job_state);
        let strm = va(&stream);
        let state_va = va(&ch.state);
        let words_va = va(&ch.words);
        let info = va(&pb.info);
        let scene = pb.scene(scene_i);
        let b220 = self.initdata.buf_0x220.gpu_va().get();
        let user_ts = cmd.ts_3d != (0, 0);
        let o = &D3_JS::ver;
        let c = &o.c;
        let st = &D3_STRM::ver;
        let wide = JOB_ID_U64::ver;
        let slot_elem = (h(&pb.slots) + (scene_i % PB_SLOTS * PB_SLOT_STRIDE) as u64) & !0xF;

        let utile_config = g.utile_config;
        let te_screen = g.te_screen();
        let mtile_size = g.mtile_size();
        let layered = u64::from(g.layers > 1);
        let tile_config: u64 = 0x280 | layered | if cmd.process_empty { 0x1_0000 } else { 0 };
        let frg_tilecfg = 0x36011
            | (utile_config & 0xF000) << 28
            | layered << 32
            | 0x200 << 28
            | (te_screen & 0x1FF) << 44
            | (te_screen >> 12 & 0x1FF) << 53;
        // The ISP's pointers: the client's (a user VA is valid in the GPU's
        // 43-bit view as is), otherwise the pass's zeroed arrays.
        let or = |v: u64, a: &fw::types::GpuArray<u8>| if v != 0 { v } else { gva(a) };
        let mut entries: [(u32, u64); 79] = [
            (0x1739, 1), // inline
            (0x10009, utile_config),
            (0x15379, cmd.eot.0), // EOT binding
            (0x15381, cmd.eot.1), // EOT entry program
            (0x15369, cmd.bg.0),  // background binding
            (0x15371, cmd.bg.1),  // background entry program
            (0x15131, u64::from(cmd.merge_x)),
            (0x15139, u64::from(cmd.merge_y)),
            (0x100A1, 0),
            (0x15069, 0),
            (0x15071, 0),
            (0x16058, 0),
            (0x10019, cmd.multisamplectl),
            (0x100B1, mtile_size),
            (0x16030, mtile_size),
            (0x100D9, te_screen),
            (0x10791, 0xFF_0200),
            (0x16098, rt.heapmeta() & G15_GPU_VA_MASK & !0x3F),
            (0x15109, or(cmd.scissor, &rt.scissor) & !3),
            (0x15101, or(cmd.dbias, &rt.dbias) & !3),
            (0x15021, cmd.isp_ctl),
            (0x15211, u64::from(g.h) << 32 | u64::from(g.w)),
            (0x15049, 0x10_0000),
            (0x10051, u64::from(g.blocks_per_utile)),
            (0x15321, cmd.zls_pixels),            // ISP_ZLS_PIXELS
            (0x15301, u64::from(cmd.bgobjdepth)), // ISP_BGOBJDEPTH
            (0x15309, u64::from(cmd.bgobjvals)),  // ISP_BGOBJVALS
            (0x15311, cmd.oclqry & !0xF),
            (0x15319, cmd.zls_ctrl), // ZLSCTL
            (0x15349, 0x0404_0404),
            (0x15351, 0),
            (0x15329, cmd.depth.base), // ISP_ZLOAD_BASE
            (0x15331, cmd.depth.base), // ISP_ZSTORE_BASE
            (0x15339, cmd.stencil.base),
            (0x15341, cmd.stencil.base),
            (0x15231, 0),
            (0x15221, 0),
            (0x15239, 0),
            (0x15229, 0),
            (0x15401, cmd.depth.stride), // load
            (0x15421, cmd.depth.stride), // store
            (0x15409, cmd.stencil.stride),
            (0x15429, cmd.stencil.stride),
            (0x153C1, cmd.depth.comp_base), // load
            (0x15411, cmd.depth.comp_stride),
            (0x153C9, cmd.depth.comp_base), // store
            (0x15431, cmd.depth.comp_stride),
            (0x153D1, cmd.stencil.comp_base),
            (0x15419, cmd.stencil.comp_stride),
            (0x153D9, cmd.stencil.comp_base),
            (0x15439, cmd.stencil.comp_stride),
            (0x16429, rt.tilemap() & G15_GPU_VA_MASK),
            (0x16060, rt.layermeta() & G15_GPU_VA_MASK),
            (0x16431, u64::from(g.rgn_size()) << 26),
            (0x10039, tile_config),
            (0x16020, 0),
            (0x16451, 0),
            (0x15359, 0),
            (0x100B8, 0x8860),
            (0x16461, gva(&rt.auxfb)), // aux_fb, the context store's
            (0x16090, gva(&rt.auxfb)),
            (0x120A1, 0x1C),
            (0x101E9, 0x1C),
            (0x160A8, 0),
            (0x16068, frg_tilecfg),
            (0x160B8, 0),
            (0x1A0A9, 0),
            (0x1A0B1, 0),
            (0x1A079, 0),
            (0x1A081, 0),
            (0x1A0D9, 0),
            (0x1A0E1, 0),
            (0x101C1, 0),
            (0xD469, 0),
            (0x1A0F9, 8),
            (0x1C838, u64::from(pb.id)),
            (0x1CA28, slot_elem), // the PM's: 40-bit
            (0xA5A9, 0x60_0040_0020),
            (0xD429, ((0x60 * 8) << 32) | (0x20 * 8)),
        ];
        let n_entries = variant_list(&mut entries, self.cfg.gpu_variant);
        // SAFETY: every store is in bounds of the job's own fresh buffers:
        // the 0xC80-byte job state (27.2: 0xCA0; the 79 entries take 0x3B4
        // bytes of its 0x700-byte list body) and the 0x400-byte stream (0x310
        // bytes used; 27.2: 0x338).
        unsafe {
            let j = W(job_state.raw_ptr());
            j.u32(0x00, 1); // tag = 3D normal
            j.u64(0x04, 1);
            j.u32(0x0C, ctx);
            j.u64(0x14, strm);
            j.u32(0x1C, st.slot);
            j.u64(c.ntf, ntf);
            j.u64(0x28, info);
            j.u64(0x30, scene);
            j.u64(0x38, pb.trailer());
            j.u64(0x40, rt.tilemap() & G15_GPU_VA_MASK); // as 0x16428
            j.u64(0x48, cmd.multisamplectl);
            j.u32(0x50, 1);
            j.u32(0x54, mtile_size as u32);
            j.u32(0x58, 1);
            j.u32(0x68, cmd.merge_x);
            j.u32(0x6C, cmd.merge_y);
            let n = j.reglist(0x80, &entries[..n_entries]);
            j.u64(0x780, js + 0x80);
            j.u32(0x788, (n * 12) << 16 | n);
            j.u64(0x9D8, tile_config);
            // The partial-render programs, which the firmware's executor
            // writes into the register list only when the TA ran out of
            // parameter-buffer pages. Left zero, a partial render runs its
            // background and end-of-tile programs from VA 0.
            j.u64(0x928, cmd.partial_bg.0); // -> 0x15368
            j.u64(0x930, cmd.partial_bg.1); // -> 0x15370
            j.u64(0xA14, cmd.partial_eot.0); // -> 0x15378
            j.u64(0xA1C, cmd.partial_eot.1); // -> 0x15380

            // The depth and stencil buffers, laid out as G13's fragment
            // job: ZLSCTL (the firmware adds the load and store bits),
            // then per buffer the load base (only tested: it sets the load
            // bit), the partial strides, the store base and the partial
            // base and metadata, which the partial passes store to and
            // reload from.
            j.u64(0x938, cmd.zls_ctrl);
            j.u64(0x940, 0x0404_0404); // -> 0x15348, as in the list
            j.u64(0x948, cmd.depth.base);
            j.u64(0x950, cmd.depth.stride); // -> 0x15420
            j.u64(0x958, cmd.depth.comp_stride); // -> 0x15430
            j.u64(0x960, cmd.depth.base);
            j.u64(0x968, cmd.depth.base); // -> 0x15330, 0x15328
            j.u64(0x970, cmd.depth.comp_base); // -> 0x153C8, 0x153C0
            j.u64(0x978, cmd.stencil.base);
            j.u64(0x980, cmd.stencil.stride); // -> 0x15428
            j.u64(0x988, cmd.stencil.comp_stride); // -> 0x15438
            j.u64(0x990, cmd.stencil.base);
            j.u64(0x998, cmd.stencil.base); // -> 0x15340, 0x15338
            j.u64(0x9A0, cmd.stencil.comp_base); // -> 0x153D8, 0x153D0
            j.u32(0xA28, cmd.bgobjdepth);
            j.u32(0xA2C, cmd.bgobjvals); // -> 0x15308 | 0x200

            // Process empty tiles (0x10038 bit 16) in the first store pass
            // as in the render, so that a clear reaches the tiles no draw
            // touches. A reload pass (+0xB9C) leaves them out: their stored
            // contents are already in memory, and a reload of every tile
            // loses all but the last segment's pixels.
            j.u32(o.process_empty, u32::from(cmd.process_empty));

            j.u64(c.host_word, words_va);
            j.u64(c.fw_word, words_va + 4);
            j.u32(c.stamp, stamp);
            j.u32(c.stamp_index, ch.stamp_index);
            j.u32(c.chan_index, 0);
            j.u32(c.io_fences, 0);
            j.id(c.job_id, id, wide);
            j.u32(o.zero, 0);
            j.u64(c.gpu_start, va(&times)); // the GPU start
            j.u64(c.gpu_start + 8, va(&times) + 8); // and end
            j.u64(c.user_ts, cmd.ts_3d.0); // the user timestamps
            j.u64(c.user_ts + 8, cmd.ts_3d.1);
            j.u64(c.uma, uma_state);
            j.0.add(c.uma_flag).write_volatile(1);
            j.u64(c.metrics, metrics_va);

            let s = W(stream.raw_ptr());
            // Type 7: the 3D context record, payload at +4 (0x1DC bytes;
            // 27.2: 0x1E4).
            s.u32(0x00, 7);
            let p = |o: usize| 4 + o;
            s.u64(p(0x10), js + 0x80);
            s.u64(p(0x18), scene);
            s.u64(p(0x20), b220 + 8);
            s.u64(p(0x28), js + 0xB70);
            // 27.2 points +0x30 at the scene's +0x4C instead.
            #[ver(V < V27_2)]
            s.u64(p(0x30), js + 0xB74);
            #[ver(V >= V27_2)]
            s.u64(p(0x30), scene + 0x4C);
            s.u64(p(0x38), js + o.flag4 as u64);
            if let Some(a) = o.flag5 {
                s.u64(p(0x40), js + a as u64);
            }
            s.u64(p(st.ctx_state), state_va);
            s.u64(p(st.ctx_js), js);
            s.u32(p(st.ctx_ctx), ctx);
            s.u32(p(st.ctx_soft), g15_soft_faults()); // isHWSoftFaultEnabled
            s.u32(p(st.ctx_key), key);
            s.u32(p(st.ctx_pbid), pb.id);
            s.u32(p(st.ctx_flags), 0); // partial renders allowed
            s.u32(p(st.ctx_flags + 4), 0);
            s.u32(p(st.ctx_flags + 8), 0);
            s.u32(p(st.ctx_flags + 0xC), 0);
            s.u64(p(st.ctx_a58), js + 0xA58);
            s.u64(p(st.ctx_frag_barrier), js + o.frag_barrier as u64);
            s.id(p(st.ctx_job_id), id, wide);
            for (i, r) in cmd.slc[..cmd.slc_count as usize].iter().enumerate() {
                let o = p(st.ctx_slc + 16 * i);
                s.u64(o, r.va);
                s.u32(o + 8, r.lines);
                s.u16(o + 0xC, u16::from(r.dsid));
                s.u16(o + 0xE, r.shift);
            }
            s.u32(p(st.ctx_slc_count), cmd.slc_count);
            s.u64(p(st.ctx_uma), uma_state);
            s.u64(p(st.ctx_metrics), metrics_va);
            s.u64(p(st.ctx_counter), 1);
            if let Some(a) = st.ctx_ntf_stale {
                // The stale cutoff, 14.8.3's only: the channel's kill word
                // (asahi.g15_kill), or the notifier's +0xA8, which the
                // scheduler's gate also reads.
                s.u64(
                    p(a),
                    ch.kill.as_ref().map_or(ntf + 0xA8, |k| k.gpu_va().get()),
                );
            }
            if let Some(a) = st.ctx_stamp_index {
                s.u32(p(a), ch.stamp_index);
            }
            // Type 3: the 3D timestamps, around the WFI (`TS_REC`).
            for (off, first) in [(st.ts1, true), (st.ts2, false)] {
                // The first points at the start twice, the second at the end.
                let end = if first { c.gpu_start } else { c.gpu_start + 8 };
                s.u32(off, if first { 0x8000_0003 } else { 3 });
                s.u64(off + 0x04, js + c.ts_slot as u64);
                s.u64(off + 0x0C, js + c.gpu_start as u64);
                s.u64(off + 0x14, js + end as u64);
                s.u64(off + 0x1C, state_va);
                s.u64(off + 0x24, if user_ts { js + c.user_ts as u64 } else { 0 });
                s.u64(off + 0x2C, js + c.end_slot as u64);
                if let Some(b) = TS_REC::ver.block {
                    s.u64(off + b, js + c.ts_block as u64); // the tick block
                }
                s.id(off + TS_REC::ver.job_id, id, wide);
            }
            s.u32(st.wfi, 1); // WFI

            // Type 8: the 3D finish record (0xB4 bytes).
            let f = st.fin;
            s.u32(f, 8);
            // The job ID: 27.2's u64 at +0x04 replaces 14.8.3's u32 and the
            // zero after it.
            s.id(f + 0x04, id, wide);
            s.u64(f + 0x0C, words_va + 4);
            s.u32(f + 0x14, stamp);
            s.u64(f + 0x1C, scene);
            s.u64(f + 0x24, info);
            #[ver(V < V27_2)]
            s.u64(f + 0x2C, 1);
            #[ver(V >= V27_2)]
            s.u32(f + 0x2C, 1);
            s.u64(f + st.fin_b220, b220 + 8);
            s.u64(f + st.fin_flag4, js + o.flag4 as u64);
            if let (Some(a), Some(b)) = (st.fin_flag5, o.flag5) {
                s.u64(f + a, js + b as u64);
            }
            s.u64(f + st.fin_b70, js + 0xB70);
            s.u64(f + st.fin_state, state_va);
            s.u64(f + st.fin_js, js);
            s.u32(f + st.fin_ctx, ctx);
            s.u64(f + 0x64, js + 0xA58);
            s.u64(f + st.fin_payload, strm + 4 + st.ctx_uma as u64);
            // A stopped job rewinds to the stream's start, its context record.
            s.u32(f + st.fin_rewind, 0u32.wrapping_sub(f as u32));
            s.u64(f + st.fin_word, js + o.fin_word as u64);
            if let Some(a) = st.fin_stamp_index {
                s.u32(f + a, ch.stamp_index);
            }
            s.u32(st.term, 0x4000_0002); // terminator
        }
        // The stamp barrier on the TA job: the 3D job parks until the TA
        // channel's firmware stamp word reaches the TA job's stamp.
        let wait = self.g15_stamp_barrier(&link, stamp, id)?;
        Ok(G15RdJob {
            job_state,
            times,
            _stream: stream,
            _notifier: own,
            wait,
            after: None,
            pre: None,
            stamp,
            uma: uma.clone(),
        })
    }
}
