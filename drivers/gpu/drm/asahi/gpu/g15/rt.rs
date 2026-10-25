// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 render-target memory: the per-pass tilemaps and metadata, and the
//! buffers only TA jobs use, which a queue's passes share.
//!
//! Spec: parameter-buffer.md.

use super::*;
use core::sync::atomic::{AtomicBool, AtomicUsize};

/// The GPU's clusters and the tiling segments
/// (`halGetGtpScalingSegmentIdRangeMaxSegments` for this chip).
pub(super) const RT_CLUSTERS: u32 = 4;
pub(super) const RT_SEGMENTS: usize = 64;

/// The layer and heap metadata sizes. macOS sizes the layer metadata 0x100
/// with two layers or more and 0 with one (`halComputeGeometry`); the fork
/// gives it 0x100 always.
const RT_LAYERMETA: usize = 0x100;
const RT_HEAPMETA: usize = 0x200;

/// Instances in a queue's ring of target memory (macOS's resource A is a
/// ring of at least 16 instances, `AGXRenderTargetMemoryG15`).
const RT_RING: usize = 16;

/// A render pass's target memory: its tilemap, layer metadata and heap
/// metadata in one instance of the queue's ring (macOS's resource A), and
/// the queue's TA-only buffers ([`G15RtShared`], through `Deref`).
///
/// An instance is followed by the next one, or by an instance's size of
/// slack at the ring's end, 16 KiB at least: the 3D job reads past these
/// buffers (dIPP faults 0x1C0 and 0x1480 bytes into the guard page after
/// one), and on macOS such a read lands in the ring. The firmware or the GPU
/// writes to an instance after its pass retired, so one is reused only after
/// the ring has gone round: a heap that gave it to the next pass at once
/// corrupted that pass's tilemap (dIPP faults, hangs in the VK CTS).
pub(crate) struct G15Rt {
    mem: RtMem,
    /// The tilemap's size rounded up to 4 KiB: the layer metadata's offset.
    pub(super) tilemap_4k: usize,
    pub(super) shared: Arc<G15RtShared>,
}

enum RtMem {
    /// Instance `i` of the shared ring.
    Ring(usize),
    /// A block of its own, when the ring's next instance is still in use.
    Own(fw::types::GpuArray<u8>),
}

impl G15Rt {
    /// The instance's VA.
    pub(super) fn base(&self) -> u64 {
        match &self.mem {
            RtMem::Ring(i) => va(&self.shared.ring) + (i * self.shared.stride) as u64,
            RtMem::Own(a) => va(a),
        }
    }

    /// The instance's address and size, for the recovery dump.
    pub(super) fn span(&self) -> (u64, usize) {
        match &self.mem {
            RtMem::Ring(_) => (self.base(), self.shared.stride),
            RtMem::Own(a) => (va(a), a.len()),
        }
    }

    /// The ring instance the pass has, or None for a block of its own.
    pub(super) fn ring_index(&self) -> Option<usize> {
        match self.mem {
            RtMem::Ring(i) => Some(i),
            RtMem::Own(_) => None,
        }
    }

    /// The queue's ring and the buffers it shares, as (name, VA, size), for
    /// the recovery dump.
    pub(super) fn shared_spans(&self) -> [(&'static str, u64, usize); 16] {
        let sh = &self.shared;
        let s = |n, a: &fw::types::GpuArray<u8>| (n, va(a), a.len());
        [
            s("ring", &sh.ring),
            s("TPC", &sh.tpc),
            s("cluster tilemaps", &sh.cl_tilemaps),
            s("cluster layermeta", &sh.cl_layermeta),
            s("meta1", &sh.meta1),
            s("meta2", &sh.meta2),
            s("meta3", &sh.meta3),
            s("meta4", &sh.meta4),
            s("preempt1", &sh.preempt1),
            s("preempt2", &sh.preempt2),
            s("preempt3", &sh.preempt3),
            s("aux_fb", &sh.auxfb),
            s("VDM", &sh.vdm),
            s("scissor", &sh.scissor),
            s("depth bias", &sh.dbias),
            ("instance", self.base(), self.span().1),
        ]
    }

    /// The tilemap's VA.
    pub(super) fn tilemap(&self) -> u64 {
        self.base()
    }

    /// The layer metadata's VA.
    pub(super) fn layermeta(&self) -> u64 {
        self.base() + self.tilemap_4k as u64
    }

    /// The heap metadata's VA.
    pub(super) fn heapmeta(&self) -> u64 {
        self.base() + (self.tilemap_4k + RT_LAYERMETA) as u64
    }
}

impl Drop for G15Rt {
    fn drop(&mut self) {
        if let RtMem::Ring(i) = self.mem {
            self.shared.taken[i].store(false, Ordering::Release);
        }
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
    /// The ring of instances (tilemap, layer metadata, heap metadata), each
    /// `stride` bytes, and which are in use by a pass.
    ring: fw::types::GpuArray<u8>,
    stride: usize,
    taken: [AtomicBool; RT_RING],
    next: AtomicUsize,
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
        // The next instance of the ring, unless a pass still uses it. A ring
        // that has gone round with a pass in flight is a queue far ahead of
        // its GPU: that pass's instance is a block of its own.
        let i = shared.next.fetch_add(1, Ordering::Relaxed) % RT_RING;
        let mem = if shared.taken[i].swap(true, Ordering::Acquire) {
            self.g15.rt_own.fetch_add(1, Ordering::Relaxed);
            RtMem::Own(
                self.alloc
                    .lock()
                    .rt
                    .array_empty_tagged::<u8>(instance + instance.max(0x4000), b"RTMA")?,
            )
        } else {
            // The instance as a fresh allocation would be: zeroed.
            let p = shared.ring.raw_ptr().wrapping_add(i * shared.stride);
            // SAFETY: the instance lies inside the ring: `instance` is at
            // most the ring's `stride`, as `tilemap_size` is at most the
            // shared set's.
            unsafe { core::ptr::write_bytes(p, 0, instance) };
            crate::mem::dc_civac(p.cast_const(), instance);
            RtMem::Ring(i)
        };
        Ok(G15Rt {
            mem,
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
        let stride = (tilemap_size.next_multiple_of(0x1000) + RT_LAYERMETA + RT_HEAPMETA)
            .next_multiple_of(0x1000);
        let sh = G15RtShared {
            tilemap_size,
            ring: g.array_empty_tagged::<u8>(stride * RT_RING + stride.max(0x4000), b"RTMA")?,
            stride,
            taken: [const { AtomicBool::new(false) }; RT_RING],
            next: AtomicUsize::new(0),
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
