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
        let stamp = (ch.submitted + 1) << 8;
        // Firmware-uncached, as the CL job's (`g15_cl_job_new`).
        let (job_state, stream) = {
            let mut guard = self.alloc.lock();
            (
                guard
                    .gpu_fw_nc
                    .array_empty_tagged::<u8>(D3_TIMES + 16, b"JS3D")?,
                guard.fw_nc.array_empty_tagged::<u8>(0x400, b"ST3D")?,
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
        let b220 = self.initdata.buf_0x220.gpu_va().get();
        let user_ts = cmd.ts_3d != (0, 0);
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
        // the 0xC70-byte job state (the 79 entries take 0x3B4 bytes of its
        // 0x700-byte list body) and the 0x400-byte stream (0x310 bytes
        // used).
        unsafe {
            let j = W(job_state.raw_ptr());
            j.u32(0x00, 1); // tag = 3D normal
            j.u64(0x04, 1);
            j.u32(0x0C, ctx);
            j.u64(0x14, strm);
            j.u32(0x1C, 0x340);
            j.u64(0x20, ntf);
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
            j.u32(0xB98, u32::from(cmd.process_empty));

            j.u64(0xBAC, words_va);
            j.u64(0xBB4, words_va + 4);
            j.u32(0xBBC, stamp);
            j.u32(0xBC0, ch.stamp_index);
            j.u32(0xBC4, 0);
            j.u32(0xBC8, 0);
            j.u32(0xBCC, id);
            j.u32(0xBD0, 0);
            j.u64(0xBF8, js + D3_TIMES as u64); // the GPU start
            j.u64(0xC00, js + D3_TIMES as u64 + 8); // and end
            j.u64(0xC08, cmd.ts_3d.0); // the user timestamps
            j.u64(0xC10, cmd.ts_3d.1);
            j.u64(0xC1E, uma_state);
            j.0.add(0xC26).write_volatile(1);
            j.u64(0xC37, metrics_va);

            let s = W(stream.raw_ptr());
            // Type 7: the 3D context record, payload at +4 (0x1DC bytes).
            s.u32(0x00, 7);
            let p = |o: usize| 4 + o;
            s.u64(p(0x10), js + 0x80);
            s.u64(p(0x18), scene);
            s.u64(p(0x20), b220 + 8);
            s.u64(p(0x28), js + 0xB70);
            s.u64(p(0x30), js + 0xB74);
            s.u64(p(0x38), js + 0xBA0);
            s.u64(p(0x40), state_va);
            s.u64(p(0x48), js);
            s.u32(p(0x50), ctx);
            s.u32(p(0x54), g15_soft_faults()); // isHWSoftFaultEnabled
            s.u32(p(0x58), key);
            s.u32(p(0x5C), pb.id);
            s.u32(p(0x60), 0); // partial renders allowed
            s.u32(p(0x64), 0);
            s.u32(p(0x68), 0);
            s.u32(p(0x6C), 0);
            s.u64(p(0x70), js + 0xA58);
            s.u64(p(0x78), js + 0xBD8);
            s.u32(p(0x94), id);
            s.u32(p(0x198), 0);
            s.u64(p(0x1A0), uma_state);
            s.u64(p(0x1B8), metrics_va);
            s.u64(p(0x1C8), 1);
            s.u64(p(0x1D0), ntf + 0xA8);
            // Type 3: the 3D timestamps, around the WFI.
            for (off, first) in [(0x1DC, true), (0x21C, false)] {
                s.u32(off, if first { 0x8000_0003 } else { 3 });
                s.u64(off + 0x04, js + 0xBF0);
                s.u64(off + 0x0C, js + 0xBF8);
                s.u64(off + 0x14, js + if first { 0xBF8 } else { 0xC00 });
                s.u64(off + 0x1C, state_va);
                s.u64(off + 0x24, if user_ts { js + 0xC08 } else { 0 });
                s.u64(off + 0x2C, js + 0xC48);
                s.u32(off + 0x34, id);
            }
            s.u32(0x218, 1); // WFI

            // Type 8: the 3D finish record (0xB4 bytes).
            let f = 0x258;
            s.u32(f, 8);
            s.u32(f + 0x04, id);
            s.u64(f + 0x0C, words_va + 4);
            s.u32(f + 0x14, stamp);
            s.u64(f + 0x1C, scene);
            s.u64(f + 0x24, info);
            s.u64(f + 0x2C, 1);
            s.u64(f + 0x34, b220 + 8);
            s.u64(f + 0x3C, js + 0xBA0);
            s.u64(f + 0x44, js + 0xB70);
            s.u64(f + 0x4C, state_va);
            s.u64(f + 0x54, js);
            s.u32(f + 0x5C, ctx);
            s.u64(f + 0x64, js + 0xA58);
            s.u64(f + 0x9C, strm + 4 + 0x1A0);
            // A stopped job rewinds to the stream's start, its context record.
            s.u32(f + 0xA4, 0u32.wrapping_sub(f as u32));
            s.u64(f + 0xAC, js + 0xC40);
            s.u32(0x30C, 0x4000_0002); // terminator
        }
        // The stamp barrier on the TA job: the 3D job parks until the TA
        // channel's firmware stamp word reaches the TA job's stamp.
        let wait = self.g15_stamp_barrier(&link, stamp, id)?;
        Ok(G15RdJob {
            job_state,
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
