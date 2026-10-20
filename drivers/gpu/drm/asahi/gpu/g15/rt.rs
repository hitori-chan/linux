// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 render-target memory: the per-pass tilemaps and metadata, and the
//! buffers only TA jobs use, which a queue's passes share.
//!
//! Spec: parameter-buffer.md.

use super::*;

/// The GPU's clusters and the tiling segments
/// (`halGetGtpScalingSegmentIdRangeMaxSegments` for this chip).
pub(super) const RT_CLUSTERS: u32 = 4;
pub(super) const RT_SEGMENTS: usize = 64;

/// The layer and heap metadata sizes. macOS sizes the layer metadata 0x100
/// with two layers or more and 0 with one (`halComputeGeometry`); the fork
/// gives it 0x100 always.
const RT_LAYERMETA: usize = 0x100;
const RT_HEAPMETA: usize = 0x200;

/// A render pass's target memory: its tilemap, layer metadata and heap
/// metadata in one block (an instance of macOS's resource A), and its
/// queue's TA-only buffers ([`G15RtShared`], through `Deref`).
pub(crate) struct G15Rt {
    /// The tilemap rounded up to 4 KiB, then the layer metadata, then the
    /// heap metadata, as `updateRenderTarget` lays out an instance in its
    /// ring, followed by an instance's size of slack, 16 KiB at least: the
    /// 3D job reads past these buffers (dIPP faults 0x1C0 and 0x1480 bytes
    /// into the guard page after one), and on macOS such a read lands in the
    /// ring.
    pub(super) a: fw::types::GpuArray<u8>,
    /// The tilemap's size rounded up to 4 KiB: the layer metadata's offset.
    pub(super) tilemap_4k: usize,
    pub(super) shared: Arc<G15RtShared>,
}

impl G15Rt {
    /// The tilemap's VA.
    pub(super) fn tilemap(&self) -> u64 {
        va(&self.a)
    }

    /// The layer metadata's VA.
    pub(super) fn layermeta(&self) -> u64 {
        va(&self.a) + self.tilemap_4k as u64
    }

    /// The heap metadata's VA.
    pub(super) fn heapmeta(&self) -> u64 {
        va(&self.a) + (self.tilemap_4k + RT_LAYERMETA) as u64
    }
}

impl core::ops::Deref for G15Rt {
    type Target = G15RtShared;
    fn deref(&self) -> &G15RtShared {
        &self.shared
    }
}

/// The buffers only TA jobs use (macOS's resource B,
/// `AGXRenderTargetMemory::updateGtpOnlyBuffers`), shared by the passes of a
/// queue, whose TA jobs run one at a time on its TA channel. As on macOS,
/// they are not cleared between passes and are replaced by larger ones when
/// a pass needs more; a pass in flight keeps the set it was built with.
pub(crate) struct G15RtShared {
    /// The per-pass tilemap size the cluster tilemaps hold.
    pub(super) tilemap_size: usize,
    pub(super) tpc: fw::types::GpuArray<u8>,
    pub(super) cl_tilemaps: fw::types::GpuArray<u8>,
    /// The cluster layer metadata: 0x100 bytes per segment, as macOS sizes
    /// it (the layer metadata times the segments). The GPU writes past a
    /// single segment's 0x100 bytes into the next allocation.
    pub(super) cl_layermeta: fw::types::GpuArray<u8>,
    pub(super) meta1: fw::types::GpuArray<u8>,
    pub(super) meta2: fw::types::GpuArray<u8>,
    pub(super) meta3: fw::types::GpuArray<u8>,
    pub(super) meta4: fw::types::GpuArray<u8>,
    pub(super) preempt1: fw::types::GpuArray<u8>,
    pub(super) preempt2: fw::types::GpuArray<u8>,
    pub(super) preempt3: fw::types::GpuArray<u8>,
    /// The 3D job's context-store area (`aux_fb`, registers 0x16460 and
    /// 0x16090), which a store of a busy 3D job at a non-zero stage writes:
    /// 0x80 bytes, then 0x280 a core (Metal's `ContextSwitcherGen3` size,
    /// `-[AGXG15XFamilyRenderContext initWith…]`). The queue's 3D jobs run
    /// one at a time on its 3D channel.
    pub(super) auxfb: fw::types::GpuArray<u8>,
    /// The VDM control stream: a Stream Terminate only.
    pub(super) vdm: fw::types::GpuArray<u8>,
    /// The scissor and depth-bias arrays (zeroed).
    pub(super) scissor: fw::types::GpuArray<u8>,
    pub(super) dbias: fw::types::GpuArray<u8>,
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Allocates a render pass's target memory for geometry `geo`. `cache`
    /// is the queue's TA-only set: used when it is large enough, otherwise
    /// replaced by one large enough for this pass and the earlier ones.
    pub(crate) fn g15_rt_new(
        &self,
        geo: &G15RdGeom,
        cache: &mut Option<Arc<G15RtShared>>,
    ) -> Result<G15Rt> {
        let tilemap_size = geo.tilemap_size();
        // macOS's size. Allocated eight times over after an overrun (#150),
        // a canary past the first eighth held over 4,096 buffers (#363).
        let tpc_size = geo.tpc_size();
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
        let tilemap_4k = tilemap_size.next_multiple_of(0x1000);
        let instance = tilemap_4k + RT_LAYERMETA + RT_HEAPMETA;
        let a = self
            .alloc
            .lock()
            .rt
            .array_empty_tagged::<u8>(instance + instance.max(0x4000), b"RTMA")?;
        Ok(G15Rt {
            a,
            tilemap_4k,
            shared,
        })
    }

    /// Allocates a queue's TA-only buffers for per-pass tilemaps of
    /// `tilemap_size` bytes and a tail-pointer cache of `tpc_size`.
    pub(super) fn g15_rt_shared_new(
        &self,
        tilemap_size: usize,
        tpc_size: usize,
    ) -> Result<G15RtShared> {
        let mut guard = self.alloc.lock();
        let g = &mut guard.rt;
        let sh = G15RtShared {
            tilemap_size,
            tpc: g.array_empty_tagged::<u8>(tpc_size, b"TPC ")?,
            cl_tilemaps: g.array_empty_tagged::<u8>(tilemap_size * RT_SEGMENTS, b"CTMP")?,
            cl_layermeta: g.array_empty_tagged::<u8>(0x100 * RT_SEGMENTS, b"CLMT")?,
            meta1: g.array_empty_tagged::<u8>(0x80, b"MTA1")?,
            meta2: g.array_empty_tagged::<u8>((0x2C0 * RT_CLUSTERS + 0x680) as usize, b"MTA2")?,
            meta3: g.array_empty_tagged::<u8>((0x500 * RT_CLUSTERS) as usize, b"MTA3")?,
            meta4: g.array_empty_tagged::<u8>(0x4000, b"MTA4")?,
            preempt1: g.array_empty_tagged::<u8>(0x10000, b"PRM1")?,
            preempt2: g.array_empty_tagged::<u8>(0x10000, b"PRM2")?,
            preempt3: g.array_empty_tagged::<u8>(0x10000, b"PRM3")?,
            auxfb: g.array_empty_tagged::<u8>(0x10000, b"AUXF")?,
            // The VDM reads ahead of the stream (0x480 bytes past a
            // terminate, into the next page), so the stream gets two pages.
            vdm: g.array_empty_tagged::<u8>(0x8000, b"VDMS")?,
            scissor: g.array_empty_tagged::<u8>(0x100, b"SCIS")?,
            dbias: g.array_empty_tagged::<u8>(0x100, b"DBIA")?,
        };
        // SAFETY: one in-bounds u32 store: a VDM Stream Terminate (block type
        // 6 in bits 31:29).
        unsafe { W(sh.vdm.raw_ptr()).u32(0, 0xC000_0000) };
        Ok(sh)
    }
}
