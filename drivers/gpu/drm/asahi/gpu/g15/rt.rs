// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 render-target memory.

use super::*;

/// The GPU clusters (`chip+0x4A0`) and `halGetGtpScalingSegmentIdRangeMaxSegments`
/// (`{16, 24, 32, 48, 64, 96, 128}[chip+0x20A0 = 4]`).
pub(super) const RT_CLUSTERS: u32 = 4;
pub(super) const RT_SEGMENTS: usize = 64;

/// G15: one render pass's target memory (spec: parameter-buffer.md, "Per
/// render pass"): its own tilemap, layermeta and heapmeta (the kext's
/// resource A, one instance per pass), and its queue's TA-only buffers
/// (`G15RtShared`, through `Deref`).
pub(crate) struct G15Rt {
    pub(super) tilemap: fw::types::GpuArray<u8>,
    pub(super) layermeta: fw::types::GpuArray<u8>,
    pub(super) heapmeta: fw::types::GpuArray<u8>,
    pub(super) shared: Arc<G15RtShared>,
}

impl core::ops::Deref for G15Rt {
    type Target = G15RtShared;
    fn deref(&self) -> &G15RtShared {
        &self.shared
    }
}

/// G15: the buffers only a TA uses (the kext's resource B,
/// `AGXRenderTargetMemory::updateGtpOnlyBuffers`), shared by the passes of
/// one queue, whose TAs run one at a time on its TA channel. As the kext's,
/// they are never cleared between passes and are replaced by larger ones
/// when a pass needs more; a pass in flight keeps the set it was built
/// with. Each region is its own allocation.
pub(crate) struct G15RtShared {
    /// The per-pass tilemap size the cluster tilemaps hold.
    pub(super) tilemap_size: usize,
    pub(super) tpc: fw::types::GpuArray<u8>,
    pub(super) cl_tilemaps: fw::types::GpuArray<u8>,
    pub(super) cl_layermeta: fw::types::GpuArray<u8>,
    pub(super) meta1: fw::types::GpuArray<u8>,
    pub(super) meta2: fw::types::GpuArray<u8>,
    pub(super) meta3: fw::types::GpuArray<u8>,
    pub(super) meta4: fw::types::GpuArray<u8>,
    pub(super) preempt1: fw::types::GpuArray<u8>,
    pub(super) preempt2: fw::types::GpuArray<u8>,
    pub(super) preempt3: fw::types::GpuArray<u8>,
    /// The VDM control stream (Stream Terminate only).
    pub(super) vdm: fw::types::GpuArray<u8>,
    /// The scissor and depth-bias arrays (zeroed).
    pub(super) scissor: fw::types::GpuArray<u8>,
    pub(super) dbias: fw::types::GpuArray<u8>,
}

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: a render pass's target memory for geometry `geo`, each region
    /// its own kernel allocation. `cache` is the queue's TA-only set: used
    /// when it is large enough, else replaced by one large enough for this
    /// pass and the earlier ones.
    pub(crate) fn g15_rt_new(
        &self,
        geo: &G15RdGeom,
        cache: &mut Option<Arc<G15RtShared>>,
    ) -> Result<G15Rt> {
        let tilemap_size = geo.tilemap_size();
        // The computed TPC is C · layers · n · 128 B (8 KiB at 64x64), but
        // the MMB wrote at +0x2000 there (boot #150): 8x that, at least
        // 64 KiB, until the layout is known (an estimate).
        let tpc_size = ((RT_CLUSTERS * geo.layers * geo.n * 128 * 8) as usize).max(0x10000);
        let shared = match cache {
            Some(sh) if sh.tilemap_size >= tilemap_size && sh.tpc.len() >= tpc_size => sh.clone(),
            _ => {
                let (tm, tpc) = cache.as_ref().map_or((tilemap_size, tpc_size), |sh| {
                    (
                        sh.tilemap_size.max(tilemap_size),
                        sh.tpc.len().max(tpc_size),
                    )
                });
                let sh = Arc::new(self.g15_rt_shared_new(tm, tpc)?, GFP_KERNEL)?;
                *cache = Some(sh.clone());
                sh
            }
        };
        let mut guard = self.alloc.lock();
        let g = &mut guard.gpu;
        Ok(G15Rt {
            tilemap: g.array_empty_tagged::<u8>(tilemap_size, b"TMAP")?,
            layermeta: g.array_empty_tagged::<u8>(0x100, b"LMTA")?,
            heapmeta: g.array_empty_tagged::<u8>(0x200, b"HMTA")?,
            shared,
        })
    }

    /// G15: a queue's TA-only render-target buffers (`G15RtShared`) for
    /// per-pass tilemaps of `tilemap_size` and a TPC of `tpc_size`.
    pub(super) fn g15_rt_shared_new(
        &self,
        tilemap_size: usize,
        tpc_size: usize,
    ) -> Result<G15RtShared> {
        let mut guard = self.alloc.lock();
        let g = &mut guard.gpu;
        let sh = G15RtShared {
            tilemap_size,
            tpc: g.array_empty_tagged::<u8>(tpc_size, b"TPC ")?,
            cl_tilemaps: g.array_empty_tagged::<u8>(tilemap_size * RT_SEGMENTS, b"CTMP")?,
            cl_layermeta: g.array_empty_tagged::<u8>(0x100, b"CLMT")?,
            meta1: g.array_empty_tagged::<u8>(0x80, b"MTA1")?,
            meta2: g.array_empty_tagged::<u8>((0x2C0 * RT_CLUSTERS + 0x680) as usize, b"MTA2")?,
            meta3: g.array_empty_tagged::<u8>((0x500 * RT_CLUSTERS) as usize, b"MTA3")?,
            meta4: g.array_empty_tagged::<u8>(0x4000, b"MTA4")?,
            preempt1: g.array_empty_tagged::<u8>(0x10000, b"PRM1")?,
            preempt2: g.array_empty_tagged::<u8>(0x10000, b"PRM2")?,
            preempt3: g.array_empty_tagged::<u8>(0x10000, b"PRM3")?,
            // The VDM reads ahead of the stream (0x480 B past a terminate,
            // into the next page: boot #149), so the stream gets two pages.
            vdm: g.array_empty_tagged::<u8>(0x8000, b"VDMS")?,
            scissor: g.array_empty_tagged::<u8>(0x100, b"SCIS")?,
            dbias: g.array_empty_tagged::<u8>(0x100, b"DBIA")?,
        };
        // SAFETY: one in-bounds u32 store: VDM Stream Terminate (block type 6
        // at [31:29]).
        unsafe { W(sh.vdm.raw_ptr()).u32(0, 0xC000_0000) };
        Ok(sh)
    }
}
