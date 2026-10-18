// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 render jobs: the TA and 3D containers (spec: agx-g15c/render-job.md).
//!
//! A render pass is a TA job and a 3D job built from a `G15RdCmd` (the
//! pass's inputs: its geometry, VDM stream, programs, depth/stencil and
//! ISP state), on a parameter buffer (`G15Pb`) and fresh render-target
//! memory (`G15Rt`). The uAPI's render submit builds them from Mesa's
//! command; the lab self-test from its own: a 64x64 target, one layer,
//! one sample, 32x32 tiles and utiles.

use super::*;

/// The self-test's render target: 64x64 px.
const RT_W: u32 = 64;
const RT_H: u32 = 64;
/// The GPU clusters (`chip+0x4A0`) and `halGetGtpScalingSegmentIdRangeMaxSegments`
/// (`{16, 24, 32, 48, 64, 96, 128}[chip+0x20A0 = 4]`).
const RT_CLUSTERS: u32 = 4;
const RT_SEGMENTS: usize = 64;

/// A render target's geometry (`AGXRenderTargetMemoryG15::halComputeGeometry`,
/// Asahi's `TileInfo`; spec: render-job.md, "Per render pass"): 32x32 px
/// tiles of 32x32, 32x16 or 16x16 px utiles; a macrotile is 4x4 tiles
/// (`align(ceil(tiles / 4), 4)` per axis).
#[derive(Clone, Copy)]
pub(crate) struct G15RdGeom {
    w: u32,
    h: u32,
    layers: u32,
    tiles_x: u32,
    tiles_y: u32,
    /// Tiles per macrotile along x and y.
    tpm_x: u32,
    tpm_y: u32,
    /// Utiles per macrotile along x and y, and n (their product).
    upm_x: u32,
    upm_y: u32,
    n: u32,
    /// The utile config (`0x10008`/`0x10148`): utile width/16 `<< 12`,
    /// height/16 `<< 14`, log2 samples.
    utile_config: u64,
    /// The 2 KiB tilebuffer blocks per utile (`0x10050`).
    blocks_per_utile: u32,
}

impl G15RdGeom {
    pub(crate) fn new(w: u32, h: u32, layers: u32, samples: u32, utile_w: u32, utile_h: u32, sample_size: u32) -> Result<G15RdGeom> {
        if w == 0 || h == 0 || w > 16384 || h > 16384 || layers == 0 || layers > 2048 {
            return Err(EINVAL);
        }
        match (utile_w, utile_h) {
            (32, 32) | (32, 16) | (16, 16) => (),
            _ => return Err(EINVAL),
        }
        let samples_log2 = match samples {
            1 => 0,
            2 => 1,
            4 => 2,
            _ => return Err(EINVAL),
        };
        let (tiles_x, tiles_y) = (w.div_ceil(32), h.div_ceil(32));
        let tpm_x = tiles_x.div_ceil(4).next_multiple_of(4);
        let tpm_y = tiles_y.div_ceil(4).next_multiple_of(4);
        let (upm_x, upm_y) = (tpm_x * (32 / utile_w), tpm_y * (32 / utile_h));
        Ok(G15RdGeom {
            w,
            h,
            layers,
            tiles_x,
            tiles_y,
            tpm_x,
            tpm_y,
            upm_x,
            upm_y,
            n: upm_x * upm_y,
            utile_config: u64::from((utile_w / 16) << 12 | (utile_h / 16) << 14 | samples_log2),
            blocks_per_utile: (((utile_w * utile_h) << samples_log2) * sample_size).div_ceil(2048),
        })
    }

    /// The region size (`rtm+0x18`): 5 B per utile of a macrotile, in u32.
    fn rgn_size(&self) -> u32 {
        (5 * self.n) >> 2
    }

    fn tilemap_size(&self) -> usize {
        (0x50 * self.n * self.layers) as usize
    }

    /// TE_SCREEN: the last tile on each axis.
    fn te_screen(&self) -> u64 {
        u64::from((self.tiles_y - 1) << 12 | (self.tiles_x - 1))
    }

    /// ISP_MTILE_SIZE: utiles per macrotile, x and y.
    fn mtile_size(&self) -> u64 {
        u64::from((self.upm_x & 0x3FF) << 16 | self.upm_y)
    }
}

/// A depth or stencil buffer (the ISP's load/store bases and strides).
#[derive(Clone, Copy, Default)]
pub(crate) struct G15RdZls {
    pub(crate) base: u64,
    pub(crate) comp_base: u64,
    pub(crate) stride: u64,
    pub(crate) comp_stride: u64,
}

/// A render pass's inputs. VAs are the client's (user VAs of the job's
/// VM); None or 0 = none.
#[derive(Clone, Copy)]
pub(crate) struct G15RdCmd {
    pub(crate) geom: G15RdGeom,
    /// The VDM control stream (`0x1C880`), or None for a terminate-only one.
    pub(crate) vdm: Option<u64>,
    /// The background and end-of-tile words (`0x15368`/`0x15370`,
    /// `0x15378`/`0x15380`): word 0 the binding, word 1 the entry
    /// program's VA.
    pub(crate) bg: (u64, u64),
    pub(crate) eot: (u64, u64),
    /// Process empty tiles (tile config bit 16).
    pub(crate) process_empty: bool,
    pub(crate) multisamplectl: u64,
    pub(crate) zls_pixels: u64,
    pub(crate) zls_ctrl: u64,
    pub(crate) bgobjdepth: u32,
    pub(crate) bgobjvals: u32,
    pub(crate) depth: G15RdZls,
    pub(crate) stencil: G15RdZls,
    pub(crate) scissor: u64,
    pub(crate) dbias: u64,
    pub(crate) oclqry: u64,
    /// isp_ctl (`0x15020`): `0xC000`, `| 1 << 18` for integer depth bias.
    pub(crate) isp_ctl: u64,
    pub(crate) merge_x: u32,
    pub(crate) merge_y: u32,
}

impl G15RdCmd {
    /// The self-test's pass: its 64x64 target, one sample at (8, 8)/16,
    /// depth cleared to 1.0, no depth/stencil buffers, no programs.
    fn test() -> Result<G15RdCmd> {
        #[allow(clippy::float_arithmetic, reason = "constant operands, folded at build time")]
        let merge = |d: u32| f32::to_bits(1.7321 / d as f32);
        Ok(G15RdCmd {
            geom: G15RdGeom::new(RT_W, RT_H, 1, 1, 32, 32, 4)?,
            vdm: None,
            bg: (0, 0),
            eot: (0, 0),
            process_empty: false,
            multisamplectl: 0x88,
            zls_pixels: u64::from((RT_H - 1) << 15 | (RT_W - 1)),
            zls_ctrl: 0,
            bgobjdepth: 0x3F80_0000,
            bgobjvals: 0x300,
            depth: Default::default(),
            stencil: Default::default(),
            scissor: 0,
            dbias: 0,
            oclqry: 0,
            isp_ctl: 0xC000,
            merge_x: merge(RT_W),
            merge_y: merge(RT_H),
        })
    }

    /// The self-test's pass with programs (the clear's, the quad's).
    fn with_progs(self, p: &G15RdProgs) -> G15RdCmd {
        G15RdCmd {
            vdm: p.vdm,
            bg: p.bg,
            eot: p.eot,
            process_empty: true,
            ..self
        }
    }
}

/// The parameter buffer's blocks: 128 KiB each, the kext's minimum count
/// (`halGetDefaultParameterBufferSizeMin` = 0x2E0000); the block ring holds
/// one more (it is full when `(head + 1) % max == start`).
const PB_BLOCKS: usize = 23;
const PB_MAX_BLOCKS: usize = PB_BLOCKS + 1;
const PB_BLOCK_SIZE: usize = 0x20000;
/// The self-test's hardware buffer ID (PBID); the uAPI's buffers take
/// 1..63 (`g15_pb_ids`).
const PB_ID: u32 = 0;
/// The scene records (`chip+0x678` = 80) and the per-slot array's slots
/// (36, a 0x100 B stride: enough for any cluster configuration).
const PB_SCENES: usize = 80;
const PB_SLOTS: usize = 36;
const PB_SLOT_STRIDE: usize = 0x100;
/// The blocks' range in the self-test's VM: below 2^40 (a block-list entry
/// keeps VA bits [39:15]), as Asahi's IOVA_KERN_GPU_BUFMGR_LOW.
const PB_VA: Range<u64> = 0x20_0000_0000..0x21_0000_0000;
/// The self-test VM's 1 TiB window: a PBE's buffer is VA bits [39:4]
/// from 0x100_0000_0000 (a user target at 0x20_0034_0000 was written at
/// 0x120_0034_xxxx, boot #158; demo15 keeps its target at 1 TiB too).
const HI_VA: Range<u64> = 0x100_1000_0000..0x100_2000_0000;
/// The self-test VM's whole kernel range: demo15's fixed VAs included.
const VM_KERNEL_VA: Range<u64> = 0x4000..0x100_2000_0000;

/// Little-endian stores into a freshly allocated buffer.
#[derive(Clone, Copy)]
struct W(*mut u8);

impl W {
    /// # Safety
    /// `off + 4` must be in bounds of the buffer.
    unsafe fn u32(self, off: usize, v: u32) {
        // SAFETY: in bounds per the caller.
        unsafe { self.0.add(off).cast::<u32>().write_unaligned(v) }
    }

    /// # Safety
    /// `off + 8` must be in bounds of the buffer.
    unsafe fn u64(self, off: usize, v: u64) {
        // SAFETY: in bounds per the caller.
        unsafe { self.0.add(off).cast::<u64>().write_unaligned(v) }
    }

    /// Writes a register list (12 B entries: the u32 header `(mrr &
    /// 0x3FFF8) | write-enable`, then the u64 value) at `off`; returns
    /// the entry count.
    ///
    /// # Safety
    /// `off + 12 * entries.len()` must be in bounds of the buffer.
    unsafe fn reglist(self, off: usize, entries: &[(u32, u64)]) -> u32 {
        for (i, &(h, v)) in entries.iter().enumerate() {
            // SAFETY: in bounds per the caller.
            unsafe {
                self.u32(off + i * 12, h);
                self.u64(off + i * 12 + 4, v);
            }
        }
        entries.len() as u32
    }
}

fn va(a: &fw::types::GpuArray<u8>) -> u64 {
    a.gpu_va().get()
}

/// A VA in the 40-bit form the kext writes to `0x1C910` and the PB
/// descriptor (`halLoadPBDesc`): bit 39 = the kernel half; the GPU reads a
/// user value as VA = value + 64 GiB, unwrapped (boot #148: our 43-bit
/// kernel VA `0x42C_0001_0180` fetched as user `0x3C_0001_0180`; boot
/// #160: user `0x18000` encoded `0x70_0001_8000` fetched at
/// `0x80_0001_8000`). So only user VAs in [64 GiB, 576 GiB) have one.
fn va40(a: u64) -> u64 {
    (a >> 3 & 1 << 39) | (a.wrapping_add(if a & 1 << 42 != 0 { 0 } else { 0x70_0000_0000 }) & 0x7F_FFFF_FFFF)
}

/// A buffer's VA as the TA pointer registers take it: the 40-bit form
/// (the VDM base and the TPC decoded our 43-bit kernel VAs as user VAs,
/// boots #148-#150).
fn h(a: &fw::types::GpuArray<u8>) -> u64 {
    va40(va(a))
}

/// A buffer's VA as the 3D (ISP) pointer registers take it: the GPU's
/// 43-bit view (bit 42 = the kernel half), as the CDM's; the ISP read the
/// 40-bit form of the heapmeta as a user VA (boot #153). The PM registers
/// of both lists (`0x16C38`, `0x1CA28`, `0x1CA30`) take the 40-bit form.
fn gva(a: &fw::types::GpuArray<u8>) -> u64 {
    a.gpu_va().get() & G15_GPU_VA_MASK
}

/// The self-test's VM, bound: its slot is the jobs' context ID.
pub(crate) struct G15RdVm {
    pub(crate) bind: mmu::VmBind,
    pub(crate) vm: mmu::Vm,
    /// An allocator in the VM's low half (the blocks, the self-test's
    /// programs and their data).
    pub(crate) ualloc: alloc::DefaultAllocator,
    /// An allocator in the VM's 1 TiB window (render targets).
    pub(crate) hialloc: alloc::DefaultAllocator,
}

/// G15: one parameter buffer (spec: render-job.md, "The parameter
/// buffer"), fixed-size: the kext's minimum, never grown. The blocks are
/// in the jobs' VM, in [64 GiB, 576 GiB) (a block-list entry is the 40-bit
/// form's bits [39:15]); the rest (`G15PbState`) is the firmware's and the
/// GPU's (kernel VAs), one per buffer ID for the device's lifetime.
pub(crate) struct G15Pb {
    /// The hardware buffer ID (PBID), and the allocator it returns to.
    pub(crate) id: u32,
    ids: Option<Arc<Mutex<u64>>>,
    st: Arc<G15PbState>,
    /// The blocks, in the VM's low half.
    pub(crate) blocks: fw::types::GpuArray<u8>,
}

impl core::ops::Deref for G15Pb {
    type Target = G15PbState;
    fn deref(&self) -> &G15PbState {
        &self.st
    }
}

/// G15: the firmware's and the GPU's part of buffer ID n's parameter
/// buffer, kept for the device's lifetime and cleared when the ID is used
/// again. The firmware's PB registry keeps the info's address after the
/// last pass (BSS `0x188850`, 127 entries) and its post-recovery walk reads
/// the info and the counter of every entry (`AGFA_IRQPostRecovery`+0x3e8):
/// a freed info crashed it (a NULL +0x58).
pub(crate) struct G15PbState {
    /// The 0x80 B buffer info (TA js+0x24, 3D js+0x28).
    pub(crate) info: fw::types::GpuArray<u8>,
    /// The 0x80 B block control (+0x40: the stats).
    pub(crate) block_ctl: fw::types::GpuArray<u8>,
    /// The 4 B counter (info +0x58), the 3D jobs submitted (`count_3d`): in
    /// the firmware-uncached stamp heap, as the kext maps it (option
    /// `0x700000007`). In a cached one the firmware unregistered the buffer
    /// under a running 3D (a NULL info at `AGFA_Executor`+0x1da4, eight
    /// processes): it read an old count, inferred.
    pub(crate) counter: fw::types::GpuArray<u8>,
    /// The block list: 8 B per block.
    pub(crate) block_list: fw::types::GpuArray<u8>,
    /// The page list: 4 B per 32 KiB page, 4 pages per block.
    pub(crate) page_list: fw::types::GpuArray<u8>,
    /// The 80 scene records (0x80 B each), then one 0x40 B trailer.
    pub(crate) scenes: fw::types::GpuArray<u8>,
    /// The page-metrics words, one u32 per scene (scene +0x00/+0x08).
    pub(crate) metrics: fw::types::GpuArray<u8>,
    /// The per-slot array (scene +0x28).
    pub(crate) slots: fw::types::GpuArray<u8>,
}

impl Drop for G15Pb {
    fn drop(&mut self) {
        if let Some(ids) = self.ids.take() {
            *ids.lock() &= !(1u64 << self.id);
        }
    }
}

impl G15PbState {
    /// Zero every buffer, for a new parameter buffer with this ID.
    fn clear(&self) {
        for a in [&self.info, &self.block_ctl, &self.counter, &self.block_list, &self.page_list, &self.scenes, &self.metrics, &self.slots] {
            // SAFETY: the whole of a buffer this state owns.
            unsafe { core::ptr::write_bytes(a.raw_ptr(), 0, a.len()) };
        }
    }

    /// Count one 3D job submitted on the buffer, before its ring entry is
    /// published (the kext's `incrementPMSubmittedOperations`; spec:
    /// parameter-buffer.md, "The firmware's registry"). The firmware's 3D
    /// post-process unregisters the buffer when its 3D completions (info
    /// +0x00) reach the count, and its post-recovery walk sends a buffer
    /// whose counts differ into the full rebuild at its next TA.
    fn count_3d(&self) {
        let c = self.counter.raw_ptr().cast::<u32>();
        // SAFETY: an in-bounds u32 of the buffer's own counter, written by the
        // host alone; the submit holds the queue, the counter's one writer.
        unsafe { c.write_volatile(c.read_volatile().wrapping_add(1)) };
        crate::mem::dc_civac(c as *const u8, 4);
    }
}

impl G15Pb {
    /// Scene record `i` and the trailer.
    fn scene(&self, i: usize) -> u64 {
        va(&self.scenes) + (i % PB_SCENES * 0x80) as u64
    }
    fn trailer(&self) -> u64 {
        va(&self.scenes) + (PB_SCENES * 0x80) as u64
    }
}

/// G15: one render pass's target memory (spec: render-job.md, "Per
/// render pass"), each region its own allocation.
pub(crate) struct G15Rt {
    tilemap: fw::types::GpuArray<u8>,
    layermeta: fw::types::GpuArray<u8>,
    heapmeta: fw::types::GpuArray<u8>,
    tpc: fw::types::GpuArray<u8>,
    cl_tilemaps: fw::types::GpuArray<u8>,
    cl_layermeta: fw::types::GpuArray<u8>,
    meta1: fw::types::GpuArray<u8>,
    meta2: fw::types::GpuArray<u8>,
    meta3: fw::types::GpuArray<u8>,
    meta4: fw::types::GpuArray<u8>,
    preempt1: fw::types::GpuArray<u8>,
    preempt2: fw::types::GpuArray<u8>,
    preempt3: fw::types::GpuArray<u8>,
    /// The VDM control stream (Stream Terminate only).
    vdm: fw::types::GpuArray<u8>,
    /// The scissor and depth-bias arrays (zeroed).
    scissor: fw::types::GpuArray<u8>,
    dbias: fw::types::GpuArray<u8>,
}

/// G15: one job of a render pass (TA or 3D): its job state, stream, its
/// own notifier when it has no pass notifier, and the record published
/// ahead of it: the type-6 PMRebuild record of the first TA job of a
/// parameter buffer, or the 3D's type-4 stamp barrier on its TA.
pub(crate) struct G15RdJob {
    pub(crate) job_state: fw::types::GpuArray<u8>,
    _stream: fw::types::GpuArray<u8>,
    _notifier: Option<fw::types::GpuArray<u8>>,
    pub(crate) pre: Option<fw::types::GpuArray<u8>>,
    pub(crate) stamp: u32,
    /// The UMA pool the job registers.
    uma: Arc<crate::gpu::G15Uma>,
}

impl G15RdJob {
    /// The record slots the job takes: its job state, and the record ahead.
    fn records(&self) -> u32 {
        1 + u32::from(self.pre.is_some())
    }
}

/// The 3D's programs: the background and end-of-tile words (`0x15368`/
/// `0x15370`, `0x15378`/`0x15380`: word 0 the binding, word 1 the entry
/// program's VA), with empty tiles processed; and the TA's VDM stream
/// (`0x1C880`, a user VA), or None for the empty one.
#[derive(Clone, Copy)]
struct G15RdProgs {
    bg: (u64, u64),
    eot: (u64, u64),
    vdm: Option<u64>,
}

/// The link of a pass's TA and 3D: the pass notifier (one, two kicks) and
/// the other job's stamp.
#[derive(Clone, Copy)]
struct G15RdLink {
    /// The pass notifier's VA, or None: each job its own (one kick).
    ntf: Option<u64>,
    /// TA: its 3D's {stamp index, stamp} (js+0x77C). 3D: the TA's
    /// {FW stamp word FWVA, stamp, stamp index} to wait on (a type-4
    /// barrier record), or 0 for none.
    other_index: u32,
    other_stamp: u32,
    other_word: u64,
}

/// G15: a queue's render state: its TA and 3D channels and its parameter
/// buffer (in the queue's VM), and the passes run so far.
pub(crate) struct G15RdQueue {
    ta: Arc<Mutex<G15ClChannel>>,
    d3: Arc<Mutex<G15ClChannel>>,
    pb: Arc<G15Pb>,
    passes: u32,
}

impl G15RdQueue {
    /// The 3D channel: a pass is complete when its 3D job is.
    pub(crate) fn d3(&self) -> &Arc<Mutex<G15ClChannel>> {
        &self.d3
    }
}

/// G15: a submitted render pass's buffers, kept until its 3D retires.
pub(crate) struct G15RdPass {
    _ta: G15RdJob,
    _d3: G15RdJob,
    _ntf: fw::types::GpuArray<u8>,
    _rt: G15Rt,
    _pb: Arc<G15Pb>,
    /// The pass's scene record index in its parameter buffer.
    scene: usize,
}

impl G15RdPass {
    /// The pass's notifier, shared by its TA and 3D jobs.
    pub(crate) fn notifier(&self) -> &fw::types::GpuArray<u8> {
        &self._ntf
    }

    /// Zero the TA's tail-pointer cache, as the kext does for an unfinished
    /// TA job at a recovery (`processFirmwareTACommandsRecovery`, spec:
    /// faults.md, "The host's side").
    pub(crate) fn clear_tpc(&self) {
        let t = &self._rt.tpc;
        // SAFETY: the whole of the pass's own TPC buffer.
        unsafe { core::ptr::write_bytes(t.raw_ptr(), 0, t.len()) };
        crate::mem::dc_civac(t.raw_ptr().cast_const(), t.len());
    }

    /// Mark the pass's scene aborted (scene record `+0x38` = 1), as the
    /// firmware's post-recovery walk does for each TA left in its channel
    /// table (`AGFA_IRQPostRecovery`, `sub_D324`) but not for a TA in an
    /// active slot, which the walk marks done without running it. The 3D
    /// kick then skips the scene and its end still counts the 3D (record 7
    /// and 8, `AGFA_Executor`); a TA that kicks again clears the mark
    /// (`sub_23570`) and runs as usual (spec: faults.md, "The post-recovery
    /// walk"). Without it the 3D of a TA that never ran draws from a
    /// never-written tilemap: an `IPF` read at the 40-bit form of a small
    /// value (boot #276).
    pub(crate) fn abort_scene(&self) {
        let p = self._pb.scenes.raw_ptr().wrapping_add(self.scene % PB_SCENES * 0x80 + 0x38);
        // SAFETY: an in-bounds u32 of the buffer's own scene record.
        unsafe { p.cast::<u32>().write_volatile(1) };
        crate::mem::dc_civac(p.cast_const(), 4);
    }

    /// The pass's parameter buffer as the firmware keeps it (spec:
    /// parameter-buffer.md, "The firmware's registry"): its ID, then info
    /// +0x00 (3D completions), +0x10 (TA completions), +0x14 (TAs in
    /// flight), +0x18 (the post-recovery gate) and the host's 3D count.
    pub(crate) fn pb_counts(&self) -> (u32, [u32; 5]) {
        let pb = &self._pb;
        crate::mem::dc_civac(pb.info.raw_ptr().cast_const(), 0x20);
        crate::mem::dc_civac(pb.counter.raw_ptr().cast_const(), 4);
        // SAFETY: in-bounds u32 reads of the buffer's own info and counter.
        let c = unsafe {
            let i = pb.info.raw_ptr() as *const u32;
            [i.read_volatile(), i.add(4).read_volatile(), i.add(5).read_volatile(), i.add(6).read_volatile(),
             (pb.counter.raw_ptr() as *const u32).read_volatile()]
        };
        (pb.id, c)
    }
}

/// The self-test's state, kept for the device's lifetime (the firmware
/// references the channels, the buffers and the jobs).
pub(crate) struct G15RenderTest {
    _ta: G15ClChannel,
    _d3: G15ClChannel,
    _pb: G15Pb,
    _vm: G15RdVm,
    _rt: G15Rt,
    _jobs: KVec<G15RdJob>,
    _notifiers: KVec<fw::types::GpuArray<u8>>,
    _clears: KVec<G15RdClear>,
    _tris: KVec<G15RdTri>,
}

/// A byte cursor for hand-assembled AGX3 code: the encoders of
/// noopwafel's demo15 (Mesa `hacky-tribuf-15x-demo`, `src/asahi/lib/demo.c`).
struct Asm {
    p: *mut u8,
    off: usize,
}

impl Asm {
    /// # Safety
    /// The buffer must have room for every byte written.
    unsafe fn bytes(&mut self, b: &[u8]) {
        for &x in b {
            // SAFETY: in bounds per the caller.
            unsafe { self.p.add(self.off).write_volatile(x) };
            self.off += 1;
        }
    }
    /// # Safety
    /// The buffer must have room for the 4 bytes written.
    unsafe fn u32(&mut self, v: u32) {
        // SAFETY: as `bytes`.
        unsafe { self.bytes(&v.to_le_bytes()) }
    }
    /// # Safety
    /// The buffer must have room for the 8 bytes written.
    unsafe fn u64(&mut self, v: u64) {
        // SAFETY: as `bytes`.
        unsafe { self.bytes(&v.to_le_bytes()) }
    }
    /// `mov uN, rM` (4 B).
    ///
    /// # Safety
    /// The buffer must have room for the 4 bytes written.
    unsafe fn mov_u_r(&mut self, u: u32, r: u32) {
        // SAFETY: as `bytes`.
        unsafe { self.u32(0x0409_000B | (u & 0xF) << 4 | (u >> 4) << 22 | r << 9) }
    }
    /// `wait` on scoreboard slot `id` (8 B).
    ///
    /// # Safety
    /// The buffer must have room for the 8 bytes written.
    unsafe fn wait(&mut self, id: u32) {
        // SAFETY: as `bytes`.
        unsafe { self.bytes(&[6, (4 << id) as u8, 6, 0, 6, 0, 6, 0]) }
    }
    /// `mov rN, imm32` (8 B).
    ///
    /// # Safety
    /// The buffer must have room for the 8 bytes written.
    unsafe fn imm(&mut self, v: u32, r: u64) {
        let v = u64::from(v);
        let i = (v & 0x7F) << 8 | (v >> 7 & 0xF) << 33 | (v >> 11 & 3) << 42 | (v >> 13 & 0xFFF) << 48 | (v >> 25 & 0x7F) << 25;
        // SAFETY: as `bytes`.
        unsafe { self.u64(0x2800C | i | (r & 0xF) << 4 | (r >> 4) << 22) }
    }
    /// The entry program's "load shader": jump to the program at `va`.
    ///
    /// # Safety
    /// The buffer must have room for the 8 bytes written.
    unsafe fn load_shader(&mut self, va: u64, dest: u64) {
        // SAFETY: as `bytes`.
        unsafe { self.u64(0x2A0177 | dest << 8 | (va >> 6) << 23) }
    }
    /// # Safety
    /// The buffer must have room for the 4 bytes written.
    unsafe fn stop(&mut self) {
        // SAFETY: as `bytes`.
        unsafe { self.bytes(&[0x0E, 0, 0, 0]) }
    }
}

/// The self-test's clear: the programs, their data and the target.
pub(crate) struct G15RdClear {
    progs: G15RdProgs,
    _code: fw::types::GpuArray<u8>,
    _data: fw::types::GpuArray<u8>,
    out: fw::types::GpuArray<u8>,
}

/// demo15's fixed VAs (Mesa `hacky-tribuf-15x-demo`, `demo.c`): the VDM
/// stream (+ its PPP blocks at +0x1000/+0x1100/+0x1200) at 192 GiB (the
/// TA's VDM pointer reaches only user VAs in [64 GiB, 576 GiB): demo15's
/// "low" 0x18000 was a hint the kext ignored), the rest at 1 TiB — the
/// fragment shader in the first 16 KiB there, the target, the vertices,
/// the matrix, the programs' data and the programs.
const TRI_VDM: u64 = 0x30_0000_0000;
const TRI_FS_BLOCK: u64 = 0x100_0000_0000;
const TRI_OUT: u64 = 0x100_0002_0000;
const TRI_VERTS: u64 = 0x100_0016_8000;
const TRI_MATRIX: u64 = 0x100_0019_0000;
const TRI_DATA: u64 = 0x100_0025_0000;
const TRI_CODE: u64 = 0x100_0027_0000;

/// demo15's VDM stream for the VAs above, a 64x64 target and 6 vertices:
/// (offset, bytes) runs, from Mesa's packers with noopwafel's G15
/// `cmdbuf.xml` (the vertex entry program at TRI_CODE + 0x4000, the
/// fragment entry program at TRI_CODE + 0x3000). The stream's PPP
/// pointers take the 40-bit form too (VA − 64 GiB: boot #161 fetched a
/// raw `0x30_0000_1000` at `0x40_0000_1000`).
const TRI_VDM_RUNS: &[(usize, &[u8])] = &[
    (0x0, &[
            0x2E, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x9D,
            0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x20, 0x07, 0x00, 0x00, 0x00, 0x12,
            0x00, 0x00, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x06, 0xC4, 0x61,
            0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xC0,
    ]),
    (0x1000, &[
            0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xC0, 0x9C, 0x00, 0x00,
    ]),
    (0x1100, &[
            0x00, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x42,
            0x00, 0x00, 0x00, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3F,
    ]),
    (0x1200, &[
            0xB4, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x06, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00,
    ]),
];

/// demo15's fragment shader (at TRI_FS_BLOCK + 0x4C0).
const TRI_FS: &[u8] = &[
            0x97, 0x0C, 0x54, 0x00, 0x03, 0x40, 0x80, 0x50, 0x04, 0xC8, 0x03, 0x00, 0x01, 0x01,
            0x87, 0x02, 0x54, 0x00, 0x06, 0x00, 0x87, 0x02, 0x54, 0x0C, 0x08, 0x00, 0xE7, 0x06,
            0x54, 0x00, 0x00, 0x00, 0x01, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x07, 0x02, 0x54, 0x0C,
            0x02, 0x00, 0x0E, 0x00, 0x00, 0x00,
];

/// demo15's vertex shader's transform (12 ffma).
const TRI_VS_FFMA: &[u8] = &[
            0x59, 0x09, 0x26, 0x81, 0x21, 0x20, 0x82, 0xC0, 0x39, 0x0B, 0x26, 0x81, 0x21, 0x22,
            0x82, 0x00, 0x49, 0x83, 0x26, 0x11, 0xA0, 0x0A, 0x39, 0x83, 0x26, 0x13, 0xA0, 0x06,
            0x39, 0x85, 0x26, 0x19, 0x81, 0x08, 0x42, 0x02, 0x29, 0x85, 0x26, 0x1B, 0x82, 0x06,
            0x42, 0x02, 0x00, 0x04, 0x39, 0x0D, 0x26, 0x81, 0x21, 0x24, 0x82, 0x00, 0x09, 0x0F,
            0x36, 0x01, 0x21, 0x26, 0x82, 0x00, 0x39, 0x83, 0x26, 0x15, 0xA0, 0x06, 0x09, 0x03,
            0x2E, 0x17, 0xA0, 0x00, 0x19, 0x85, 0x26, 0x1D, 0x82, 0x06, 0x42, 0x02, 0x00, 0x08,
            0x09, 0x05, 0x2E, 0x1F, 0x82, 0x00, 0x42, 0x02, 0x00, 0x0C,
];

/// demo15's vertices (x, y, z; w = 0 in memory) and its frame-0 matrix.
const TRI_VERTICES: [f32; 18] = [
    -0.5, -0.5, 0.0, -0.5, 0.5, 0.0, 0.5, -0.5, 0.0, 0.5, 0.5, 0.0, -0.5, 0.5, 0.0, 0.5, -0.5, 0.0,
];
const TRI_MATRIX_F: [f32; 16] = [1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0];

/// The self-test's triangles: demo15's quad, its buffers at fixed VAs.
pub(crate) struct G15RdTri {
    progs: G15RdProgs,
    out: (fw::types::GpuArray<u8>, alloc::DefaultAllocator),
    _bufs: KVec<(fw::types::GpuArray<u8>, alloc::DefaultAllocator)>,
}

/// The clear colour (r, g, b, a) and its RGBA8 pixel.
const CLEAR_RGBA: [f32; 4] = [1.0, 0.0, 1.0, 1.0];
const CLEAR_PIXEL: u32 = 0xFFFF_00FF;
const CLEAR_FILL: u8 = 0x11;

/// What a pass wrote to its target: the pixels equal to the clear, those
/// still at the fill, and five samples: pixels 0, 1, (40, 33), (32, 32),
/// the last.
fn g15_rd_check(out: &fw::types::GpuArray<u8>) -> (usize, usize, [u32; 5]) {
    crate::mem::dc_civac(out.raw_ptr().cast_const(), (RT_W * RT_H * 4) as usize);
    {
        let n = (RT_W * RT_H) as usize;
        let p = out.raw_ptr() as *const u32;
        let (mut hit, mut untouched) = (0, 0);
        for i in 0..n {
            // SAFETY: an in-bounds u32 read of the target.
            let v = unsafe { p.add(i).read_volatile() };
            if v == CLEAR_PIXEL {
                hit += 1;
            } else if v == u32::from_ne_bytes([CLEAR_FILL; 4]) {
                untouched += 1;
            }
        }
        // SAFETY: in-bounds u32 reads of the target.
        let first = unsafe {
            [
                p.read_volatile(),
                p.add(1).read_volatile(),
                p.add(RT_W as usize * 33 + 40).read_volatile(),
                p.add(RT_W as usize * 32 + 32).read_volatile(),
                p.add(n - 1).read_volatile(),
            ]
        };
        (hit, untouched, first)
    }
}

/// Writes demo15's clear programs and their data: the background entry
/// program (at `c` + 0x1000) loads the clear colour's base (`d` + 0x200,
/// the colour at +0x40) into u2-u5 and jumps to the background program
/// (`c` + 0x50C0: packs it to RGBA8, stores it to the tile); the
/// end-of-tile entry program (`c` + 0x2000) loads the PBE descriptor's
/// address (`d` + 0x600 -> `d` + 0x700; +0x640 = 0) into u0/u1 and jumps
/// to the end-of-tile program (`c` + 0x5200: writes the tile through the
/// PBE to `out`). The bindings are demo15's: background
/// `0xffff800000000040`, end of tile 0.
///
/// # Safety
/// `code` and `data` must be 0x8000 B buffers mapped at `c` and `d`.
unsafe fn g15_rd_write_clear(code: *mut u8, c: u64, data: *mut u8, d: u64, out: u64) -> G15RdProgs {
    let (bg_entry, eot_entry, bg_prog, eot_prog) = (c + 0x1000, c + 0x2000, c + 0x50C0, c + 0x5200);
    let clear_base = d + 0x200;
    let eot_base = d + 0x600;
    let pbe = d + 0x700;
    // SAFETY: in bounds per the caller.
    unsafe {
        let dw = W(data);
        for (i, f) in CLEAR_RGBA.iter().enumerate() {
            dw.u32(0x240 + 4 * i, f.to_bits());
        }
        dw.u64(0x600, pbe);
        dw.u64(0x640, 0);
        // The PBE descriptor: 2D, linear, R8G8B8A8 unorm, RGBA, the
        // target's size, the buffer as VA bits [39:4] (from 1 TiB),
        // level 1, the stride minus 16 (as demo15).
        let w0 = 2 | 0x28 << 6 | 1 << 18 | 2 << 20 | 3 << 22 | u64::from(RT_W - 1) << 24 | u64::from(RT_H - 1) << 38;
        let w1 = (out >> 4 & 0xF_FFFF_FFFF) | 1 << 36 | u64::from(RT_W * 4 - 0x10) << 40;
        dw.u64(0x700, w0);
        dw.u64(0x708, w1);
        dw.u64(0x710, 0);

        let mut a = Asm { p: code.add(0x1000), off: 0 };
        a.imm(clear_base as u32, 2);
        a.imm((clear_base >> 32) as u32, 3);
        a.bytes(&[0x67, 0x00, 0x54, 0x24, 0x02, 0x00, 0x00, 0x00, 0x57, 0x00, 0x08, 0x40, 0x26, 0x00]);
        a.bytes(&[0x77, 0x00, 0x2A, 0x43, 0x4B, 0x00, 0x00, 0x00]);
        a.load_shader(bg_prog, 1);
        a.bytes(&[0x04, 0x00, 0x06, 0x08, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00]);
        a.bytes(&[0x2B, 0x24, 0x09, 0x04, 0x3B, 0x26, 0x09, 0x04, 0x4B, 0x28, 0x09, 0x04, 0x5B, 0x2A, 0x09, 0x04]);
        a.stop();

        let mut a = Asm { p: code.add(0x50C0), off: 0 };
        a.bytes(&[0x97, 0x0C, 0x54, 0x00, 0x02, 0x08, 0x18, 0xD0, 0x05, 0xC8]);
        a.bytes(&[0x97, 0x04, 0x54, 0x01, 0x02, 0x10, 0x28, 0xD0, 0x05, 0xC8]);
        a.bytes(&[0xE7, 0x06, 0x54, 0, 0, 0, 0x01, 0x4E, 0, 0, 0, 0]);
        a.stop();

        let mut a = Asm { p: code.add(0x2000), off: 0 };
        a.imm(eot_base as u32, 2);
        a.imm((eot_base >> 32) as u32, 3);
        a.bytes(&[0x0C, 0x00, 0x3B, 0x00, 0x01, 0x04]);
        a.bytes(&[0x67, 0, 0x54, 0x24, 0x02, 0, 0, 0, 0x51, 0x00, 0x08, 0x40, 0x26, 0]);
        a.bytes(&[0x67, 0, 0x54, 0x20, 0x02, 0, 0, 0, 0x59, 0x00, 0x00, 0x40, 0x26, 0]);
        a.bytes(&[0x77, 0x00, 0x2A, 0x43, 0x4B, 0x00, 0x00, 0x00]);
        a.load_shader(eot_prog, 1);
        a.bytes(&[0x04, 0x00, 0xF7, 0x00, 0x2A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        a.bytes(&[0x06, 0x08, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00]);
        a.bytes(&[0x2B, 0x24, 0x09, 0x04, 0x0B, 0x20, 0x09, 0x04, 0x1B, 0x22, 0x09, 0x04]);
        a.stop();

        let mut a = Asm { p: code.add(0x5200), off: 0 };
        a.bytes(&[0x1C, 0x9C, 0x10, 0x06, 0x0C, 0x9D, 0x10, 0x26, 0x34, 0xA8, 0x10, 0x06, 0x24, 0xA9, 0x10, 0x26]);
        a.bytes(&[0x9F, 0x10, 0x54, 0x00, 0x00, 0x04, 0x18, 0x00, 0x50, 0x06, 0x0B, 0x00]);
        a.bytes(&[0x9F, 0x20, 0x54, 0x02, 0x00, 0x00, 0x10, 0x00, 0x50, 0x06, 0x0B, 0x00]);
        for r in 0..64 {
            a.imm(0, r);
        }
        a.bytes(&[0x97, 0x05, 0x54, 0x04, 0x00, 0x08, 0x00, 0x00, 0xD0, 0x40, 0x10, 0x00]);
        a.bytes(&[0x57, 0x10, 0x54, 0x00, 0x00, 0x00, 0x00, 0x80, 0xA8, 0x75, 0x00, 0x00]);
        a.stop();
    }
    G15RdProgs {
        bg: (0xFFFF_8000_0000_0040, bg_entry),
        eot: (0, eot_entry),
        vdm: None,
    }
}

/// The rings of the queue ([`fw::g15::QUEUE`]): the TA's (class 0) and the 3D's (class 1).
const TA_RING: usize = fw::g15::ring(0);
const D3_RING: usize = fw::g15::ring(1);

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: a fixed parameter buffer as the kext leaves a fresh one after
    /// its first TA `prepare` (spec: render-job.md, "The parameter
    /// buffer"): every block created and published, the page list built,
    /// the PB descriptor-table entry loaded (`halLoadPBDesc`).
    /// The self-test's VM: the blocks' range and the 1 TiB window.
    fn g15_rd_vm_new(&self) -> Result<G15RdVm> {
        let vm = self.new_vm(VM_KERNEL_VA)?;
        let bind = self.bind_vm(&vm)?;
        let ualloc = alloc::DefaultAllocator::new(
            &self.dev,
            &vm,
            PB_VA,
            PB_BLOCK_SIZE,
            mmu::PROT_GPU_SHARED_RW,
            PB_BLOCKS * PB_BLOCK_SIZE,
            true,
            fmt!("G15 render self-test PB"),
            false,
        )?;
        let hialloc = alloc::DefaultAllocator::new(
            &self.dev,
            &vm,
            HI_VA,
            0x4000,
            mmu::PROT_GPU_SHARED_RW,
            0x10_0000,
            true,
            fmt!("G15 render self-test targets"),
            false,
        )?;
        Ok(G15RdVm {
            bind,
            vm,
            ualloc,
            hialloc,
        })
    }

    /// G15: a parameter buffer with hardware ID `id`, its blocks from
    /// `ualloc` (the jobs' VM, in [64 GiB, 576 GiB)); `ids` takes the ID
    /// back when it goes.
    pub(crate) fn g15_pb_new(&self, ualloc: &mut alloc::DefaultAllocator, id: u32, ids: Option<Arc<Mutex<u64>>>) -> Result<G15Pb> {
        let blocks = ualloc.array_empty_tagged::<u8>(PB_BLOCKS * PB_BLOCK_SIZE, b"PBBK")?;
        // GPU and firmware mapped, as the kext maps them: the GPU reads the
        // page metrics and lists (a firmware-only page metrics word was a
        // NoAccess fault in the PM, boot #151).
        let st = {
            let mut states = self.g15_pb_states.lock();
            let slot = states.get_mut(id as usize).ok_or(EINVAL)?;
            match slot {
                Some(st) => {
                    st.clear();
                    st.clone()
                }
                None => {
                    let mut guard = self.alloc.lock();
                    let a = &mut *guard;
                    let g = &mut a.gpu;
                    let st = Arc::new(
                        G15PbState {
                            info: g.array_empty_tagged::<u8>(0x80, b"PBIN")?,
                            block_ctl: g.array_empty_tagged::<u8>(0x80, b"PBBC")?,
                            counter: a.stamp.array_empty_tagged::<u8>(0x40, b"PBCN")?,
                            block_list: g.array_empty_tagged::<u8>(PB_MAX_BLOCKS * 8, b"PBBL")?,
                            page_list: g.array_empty_tagged::<u8>(PB_MAX_BLOCKS * 16, b"PBPL")?,
                            scenes: g.array_empty_tagged::<u8>(PB_SCENES * 0x80 + 0x40, b"PBSC")?,
                            metrics: g.array_empty_tagged::<u8>(PB_SCENES * 4, b"PBMT")?,
                            slots: g.array_empty_tagged::<u8>(PB_SLOTS * PB_SLOT_STRIDE, b"PBSL")?,
                        },
                        GFP_KERNEL,
                    )?;
                    *slot = Some(st.clone());
                    st
                }
            }
        };
        let pb = G15Pb { id, ids, st, blocks };
        let n = PB_BLOCKS as u32;
        let base = pb.blocks.gpu_va().get();
        // The pages are 32 KiB (a page-list entry is the 40-bit form >> 15:
        // the VCE wrote blocks at 0xf0_0011_0000 to kernel 0x470_0011_0000,
        // boot #162), so only user VAs in [64 GiB, 576 GiB) can hold them.
        if base & 0x7FFF != 0 || base < 0x10_0000_0000 || base + (PB_BLOCKS * PB_BLOCK_SIZE) as u64 > 0x90_0000_0000 {
            dev_err!(self.dev.as_ref(), "G15: parameter buffer blocks at {base:#x}: not in [64 GiB, 576 GiB) or 32 KiB-aligned\n");
            return Err(EINVAL);
        }
        let pl = va(&pb.page_list);
        // SAFETY: every store is in bounds of the buffer it names, each
        // freshly allocated and sized above.
        unsafe {
            // The block list (8 B per block: the u32 va40(VA) >> 15) and the
            // page list (4 u32 per block: its four 32 KiB pages).
            let bl = W(pb.block_list.raw_ptr());
            let pg = W(pb.page_list.raw_ptr());
            for i in 0..PB_BLOCKS {
                let e = (va40(base + (i * PB_BLOCK_SIZE) as u64) >> 15) as u32 & 0x1FF_FFFF;
                bl.u32(i * 8, e);
                for k in 0..4 {
                    pg.u32(i * 16 + k * 4, e + k as u32);
                }
            }
            // The block control: head = published = N, start 0; the stats
            // at +0x40 zeroed.
            let bc = W(pb.block_ctl.raw_ptr());
            bc.u32(0x00, n);
            bc.u32(0x04, n);
            bc.u32(0x08, 0);
            // The buffer info (resetHWParamBufferState, buildPageList).
            let f = W(pb.info.raw_ptr());
            f.u32(0x08, id);
            f.u64(0x1C, pl);
            f.u32(0x24, (PB_MAX_BLOCKS * 16) as u32);
            f.u32(0x28, 4 * n); // page count
            f.u32(0x2C, PB_MAX_BLOCKS as u32);
            f.u32(0x30, n); // end
            f.u32(0x34, 0); // start
            f.u64(0x38, va(&pb.block_list));
            f.u64(0x40, va(&pb.block_ctl));
            f.u32(0x48, 4 * n - 1); // last page
            f.u32(0x4C, PB_BLOCK_SIZE as u32);
            f.u64(0x58, va(&pb.counter));
            f.u32(0x70, 4 * n); // max pages (= the page count: no growing)
            f.u32(0x74, 4 * n);
            // The scene records: +0x00/+0x08 the scene's page-metrics word,
            // +0x28 its per-slot array element, +0x40 the stats.
            let sc = W(pb.scenes.raw_ptr());
            for i in 0..PB_SCENES {
                let m = va(&pb.metrics) + 4 * i as u64;
                sc.u64(i * 0x80, m);
                sc.u64(i * 0x80 + 0x08, m);
                sc.u64(i * 0x80 + 0x28, va(&pb.slots) + ((i % PB_SLOTS) * PB_SLOT_STRIDE) as u64);
                sc.u64(i * 0x80 + 0x40, va(&pb.block_ctl) + 0x40);
            }
            // The PB descriptor-table entry (halLoadPBDesc): the page list's
            // VA bits [38:7] and [42], the page count.
            let hi = ((pl.wrapping_add(if pl & 1 << 42 != 0 { 0 } else { 0x70_0000_0000 }) & 0x70_0000_0000)
                | (pl >> 3 & 0x80_0000_0000))
                >> 36;
            let d = W(self.initdata.pb_desc_table.raw_ptr().add(16 * id as usize));
            d.u32(0, (pl >> 4) as u32 & 0xFFFF_FFF8);
            d.u32(4, (hi as u32) << 28 | ((4 * n) & 0x3F_FFFF));
            d.u32(8, 0);
            d.u32(12, 0);
        }
        Ok(pb)
    }

    /// G15: a render pass's target memory for geometry `geo`, each region
    /// its own kernel allocation.
    pub(crate) fn g15_rt_new(&self, geo: &G15RdGeom) -> Result<G15Rt> {
        let mut guard = self.alloc.lock();
        let g = &mut guard.gpu;
        let tilemap_size = geo.tilemap_size();
        // The computed TPC is C · layers · n · 128 B (8 KiB at 64x64), but
        // the MMB wrote at +0x2000 there (boot #150): 8x that, at least
        // 64 KiB, until the layout is known (an estimate).
        let tpc_size = ((RT_CLUSTERS * geo.layers * geo.n * 128 * 8) as usize).max(0x10000);
        let rt = G15Rt {
            tilemap: g.array_empty_tagged::<u8>(tilemap_size, b"TMAP")?,
            layermeta: g.array_empty_tagged::<u8>(0x100, b"LMTA")?,
            heapmeta: g.array_empty_tagged::<u8>(0x200, b"HMTA")?,
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
        unsafe { W(rt.vdm.raw_ptr()).u32(0, 0xC000_0000) };
        Ok(rt)
    }

    /// The notifier of one job (as the CL one): +0x00 -> the u32 count of
    /// its kicks (at +0xC0), +0x08 the key, +0x10 the flush threshold,
    /// +0xA8 no stale cutoff.
    fn g15_notifier_new(&self, key: u32, kicks: u32) -> Result<fw::types::GpuArray<u8>> {
        let n = self.alloc.lock().shared.array_empty_tagged::<u8>(0x100, b"NTFY")?;
        let f = W(n.raw_ptr());
        // SAFETY: in-bounds stores into the fresh 0x100 B notifier.
        unsafe {
            f.u32(0xC0, kicks);
            f.u64(0, va(&n) + 0xC0);
            f.u32(0x08, key);
            f.u32(0x0C, 0);
            f.u32(0x10, 80);
            f.u32(0x94, 0);
            f.u64(0xA8, u64::MAX);
        }
        Ok(n)
    }

    /// G15: the TA job of an empty pass (spec: render-job.md, "The TA job
    /// state", "The TA register list", "The TA stream"). `ch` is the TA
    /// channel; the job is its first (stamp 0x100); `pre` adds the type-6
    /// PMRebuild record the first TA job of a parameter buffer carries.
    #[allow(clippy::too_many_arguments)]
    fn g15_ta_job_new(
        &self,
        ch: &G15ClChannel,
        pb: &G15Pb,
        rt: &G15Rt,
        ctx: u32,
        id: u32,
        key: u32,
        scene_i: usize,
        link: G15RdLink,
        pmrebuild: bool,
        cmd: &G15RdCmd,
    ) -> Result<G15RdJob> {
        let g = &cmd.geom;
        let stamp = (ch.submitted + 1) << 8;
        let uma = self.g15_uma_get()?;
        let (job_state, stream, pre) = {
            let mut guard = self.alloc.lock();
            (
                guard.gpu.array_empty_tagged::<u8>(0x920, b"JSTA")?,
                guard.shared.array_empty_tagged::<u8>(0x400, b"STTA")?,
                guard.shared.array_empty_tagged::<u8>(0x40, b"PMRB")?,
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

        // The page-metrics address (scene +0x00) as register 0x1C910 takes it.
        let a = va(&pb.metrics) + 4 * (scene_i % PB_SCENES) as u64;
        let r1c910 = (va40(a) & !1) | 1;
        let slot_elem = (h(&pb.slots) + (scene_i % PB_SLOTS * PB_SLOT_STRIDE) as u64) & !0xF;
        let heapmeta = (h(&rt.heapmeta) & !0x3F) | 1 << 63;
        let te_mtile1 = (3 * g.tpm_x) | ((2 * g.tpm_x) << 9) | g.tpm_x << 18;
        let te_mtile2 = (3 * g.tpm_y) | ((2 * g.tpm_y) << 9) | g.tpm_y << 18;
        let entries: [(u32, u64); 68] = [
            (0x1748, 1), // inline, write-enable clear
            (0x10141, 0x200),
            (0x1C039, h(&rt.tilemap)),
            (0x1C9C8, h(&rt.tilemap)),
            (0x1C041, h(&rt.cl_tilemaps)),
            (0x1C9D0, h(&rt.cl_tilemaps)),
            (0x1C0A1, h(&rt.tpc)),
            (0x1C031, heapmeta),
            (0x1C9C0, heapmeta),
            (0x1C051, 0x003A_0012_006B_0003), // Metal's raw+0xB8
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
            (0x1C918, 4), // chip+0x20A0
            (0x1C079, h(&rt.layermeta)),
            (0x1C9D8, h(&rt.layermeta)),
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
            (0x1C0A9, u64::from(2 * g.n)), // TE_TPC (tpc_stride)
            (0x10171, 0x100),
            (0x10169, 0x8000), // one layer (not decoded for more)
            (0x12099, 0x1C),
            (0x101E1, 0x1C),
            (0x1C9E8, 0x8000 & 0x47FF),
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
        let tail: [(u32, u64); 4] = [
            (0x1C830, u64::from(pb.id)),
            (0x1CA30, slot_elem),
            (0x16C39, slot_elem), // the PM: 40-bit (boot #155)
            (0x1C910, r1c910),
        ];
        // SAFETY: every store is in bounds of the job's own fresh buffers:
        // the 0x920 B job state (a 0x700 B list body: 72 entries = 0x360 B),
        // the 0x400 B stream (0x2D8 B used) and the 0x40 B record.
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
            let n = j.reglist(0x40, &entries);
            let n = n + j.reglist(0x40 + n as usize * 12, &tail);
            j.u64(0x740, js + 0x40);
            j.u32(0x748, (n * 12) << 16 | n);
            j.u64(0x760, va(&rt.tpc));
            j.u64(0x768, rt.tpc.len() as u64);
            j.u64(0x770, strm);
            j.u32(0x778, 0x300);
            j.u32(0x77C, link.other_index); // the partner 3D's stamp index
            j.u32(0x780, link.other_stamp); // and stamp
            j.u64(0x7A8, h(&rt.preempt1));
            j.u64(0x864, words_va); // host stamp word
            j.u64(0x86C, words_va + 4); // FW stamp word
            j.u32(0x874, stamp);
            j.u32(0x878, ch.stamp_index);
            j.u32(0x87C, 0); // channel index
            j.u32(0x880, 0);
            j.u32(0x884, id);
            j.u32(0x888, 0); // the queue's TA counter
            // The UMA pool (the kick registers it unconditionally: a NULL
            // descriptor crashed the firmware, boot #147): its state, the
            // clean+invalidate flag, the metrics slot.
            j.u64(0x8D6, uma_state);
            j.0.add(0x8DE).write_volatile(1);
            j.u64(0x8EF, metrics_va);

            let s = W(stream.raw_ptr());
            // type 5 — the TA context record, payload at +4 (0x1CC B).
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
            // type 3 — the timestamps, TA column, around the WFI.
            for (off, first) in [(0x1CC, true), (0x20C, false)] {
                s.u32(off, if first { 0x8000_0003 } else { 3 });
                s.u64(off + 0x04, js + 0x8A8);
                s.u64(off + 0x0C, js + 0x8B0);
                s.u64(off + 0x14, js + if first { 0x8B0 } else { 0x8B8 });
                s.u64(off + 0x1C, state_va);
                s.u64(off + 0x2C, js + 0x900);
                s.u32(off + 0x34, id);
            }
            s.u32(0x208, 1); // WFI
            // type 6 — the TA finish record at +0x248 (0x8C B).
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
            // a stopped job rewinds to the stream's start, its context record
            s.u32(f + 0x7C, 0u32.wrapping_sub(f as u32));
            s.u64(f + 0x84, js + 0x8F8);
            s.u32(0x2D4, 0x4000_0002); // terminator

            // type 6 — PMRebuild (0x20 B): the first TA job of the buffer.
            let r = W(pre.raw_ptr());
            r.u32(0x00, 6);
            r.u32(0x04, ctx);
            r.u32(0x08, pb.id);
            // {PM+0x138, PM+0x13C} = {start 0, head N}: a head of 0 would
            // send the firmware into its full rebuild (sub_319A8).
            r.u32(0x0C, 0);
            r.u32(0x10, PB_BLOCKS as u32);
            r.u64(0x14, info);
            r.u32(0x1C, stamp);
        }
        Ok(G15RdJob {
            job_state,
            _stream: stream,
            _notifier: own,
            pre: if pmrebuild { Some(pre) } else { None },
            stamp,
            uma,
        })
    }

    /// G15: the 3D job of an empty pass (spec: render-job.md, "The 3D job
    /// state", "The 3D register list", "The 3D stream"): no background or
    /// end-of-tile program, empty tiles skipped.
    #[allow(clippy::too_many_arguments)]
    fn g15_3d_job_new(
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
    ) -> Result<G15RdJob> {
        let g = &cmd.geom;
        let stamp = (ch.submitted + 1) << 8;
        let uma = self.g15_uma_get()?;
        let (job_state, stream) = {
            let mut guard = self.alloc.lock();
            (
                guard.gpu.array_empty_tagged::<u8>(0xC60, b"JS3D")?,
                guard.shared.array_empty_tagged::<u8>(0x400, b"ST3D")?,
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
        // The ISP's pointers: the client's (43-bit view: a user VA as is),
        // else the pass's zeroed arrays.
        let or = |v: u64, a: &fw::types::GpuArray<u8>| if v != 0 { v } else { gva(a) };
        let entries: [(u32, u64); 79] = [
            (0x1739, 1), // inline
            (0x10009, utile_config),
            (0x15379, cmd.eot.0), // EOT binding
            (0x15381, cmd.eot.1), // EOT entry program
            (0x15369, cmd.bg.0), // background binding
            (0x15371, cmd.bg.1), // background entry program
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
            (0x16098, gva(&rt.heapmeta) & !0x3F),
            (0x15109, or(cmd.scissor, &rt.scissor) & !3),
            (0x15101, or(cmd.dbias, &rt.dbias) & !3),
            (0x15021, cmd.isp_ctl),
            (0x15211, u64::from(g.h) << 32 | u64::from(g.w)),
            (0x15049, 0x10_0000),
            (0x10051, u64::from(g.blocks_per_utile)),
            (0x15321, cmd.zls_pixels), // ISP_ZLS_PIXELS
            (0x15301, u64::from(cmd.bgobjdepth)), // ISP_BGOBJDEPTH
            (0x15309, u64::from(cmd.bgobjvals)), // ISP_BGOBJVALS
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
            (0x16429, gva(&rt.tilemap)),
            (0x16060, gva(&rt.layermeta)),
            (0x16431, u64::from(g.rgn_size()) << 26),
            (0x10039, tile_config),
            (0x16020, 0),
            (0x16451, 0),
            (0x15359, 0),
            (0x100B8, 0x8860),
            (0x16461, 0),
            (0x16090, 0),
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
            (0x1CA28, slot_elem), // the PM: 40-bit (boot #154)
            (0xA5A9, 0x60_0040_0020),
            (0xD429, ((0x60 * 8) << 32) | (0x20 * 8)),
        ];
        // SAFETY: every store is in bounds of the job's own fresh buffers:
        // the 0xC60 B job state (79 entries = 0x3B4 B of the 0x700 B body)
        // and the 0x400 B stream (0x310 B used).
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
            j.u64(0x40, gva(&rt.tilemap)); // as 0x16428
            j.u64(0x48, cmd.multisamplectl);
            j.u32(0x50, 1);
            j.u32(0x54, mtile_size as u32);
            j.u32(0x58, 1);
            j.u32(0x68, cmd.merge_x);
            j.u32(0x6C, cmd.merge_y);
            let n = j.reglist(0x80, &entries);
            j.u64(0x780, js + 0x80);
            j.u32(0x788, (n * 12) << 16 | n);
            j.u64(0x9D8, tile_config);
            j.u64(0xBAC, words_va);
            j.u64(0xBB4, words_va + 4);
            j.u32(0xBBC, stamp);
            j.u32(0xBC0, ch.stamp_index);
            j.u32(0xBC4, 0);
            j.u32(0xBC8, 0);
            j.u32(0xBCC, id);
            j.u32(0xBD0, 0);
            j.u64(0xC1E, uma_state);
            j.0.add(0xC26).write_volatile(1);
            j.u64(0xC37, metrics_va);

            let s = W(stream.raw_ptr());
            // type 7 — the 3D context record, payload at +4 (0x1DC B).
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
            for (off, first) in [(0x1DC, true), (0x21C, false)] {
                s.u32(off, if first { 0x8000_0003 } else { 3 });
                s.u64(off + 0x04, js + 0xBF0);
                s.u64(off + 0x0C, js + 0xBF8);
                s.u64(off + 0x14, js + if first { 0xBF8 } else { 0xC00 });
                s.u64(off + 0x1C, state_va);
                s.u64(off + 0x2C, js + 0xC48);
                s.u32(off + 0x34, id);
            }
            s.u32(0x218, 1); // WFI
            // type 8 — the 3D finish record at +0x258 (0xB4 B).
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
            // a stopped job rewinds to the stream's start, its context record
            s.u32(f + 0xA4, 0u32.wrapping_sub(f as u32));
            s.u64(f + 0xAC, js + 0xC40);
            s.u32(0x30C, 0x4000_0002); // terminator
        }
        // type 4 — the stamp barrier on the TA (setupBarrierCommand, 0x40
        // B): met when the TA's FW stamp word reaches its stamp; the 3D
        // parks until the TA's index registers (spec: render-job.md,
        // "Linking TA and 3D").
        let pre = if link.other_word != 0 {
            let b = self.alloc.lock().shared.array_empty_tagged::<u8>(0x40, b"BARR")?;
            let r = W(b.raw_ptr());
            // SAFETY: in-bounds stores into the fresh 0x40 B record.
            unsafe {
                r.u32(0x00, 4);
                r.u64(0x04, link.other_word);
                r.u64(0x0C, link.other_word);
                r.u32(0x14, link.other_stamp);
                r.u32(0x18, link.other_index);
                r.u32(0x1C, stamp);
                r.u32(0x20, id & 0x7FFF_FFFF);
                r.u32(0x24, 0); // the FW stamp word, not the host one
                r.u32(0x28, 0);
            }
            Some(b)
        } else {
            None
        };
        Ok(G15RdJob {
            job_state,
            _stream: stream,
            _notifier: own,
            pre,
            stamp,
            uma,
        })
    }

    /// G15: stage `job` on `ch`: its records into the channel's record slots
    /// (the PMRebuild record first) and one ring entry at the ring's cursor in
    /// `rings` (the locked `g15_rings`), whose command ID is the slot cursor
    /// after them, stored and cleaned to memory. Returns the ring's next write
    /// index; `g15_rd_publish` shows it to the firmware, under the same lock.
    /// The caller has found room for it (`g15_ring_room`): a pass checks both
    /// rings before it writes either, so it never leaves half a pass behind.
    fn g15_rd_stage(&self, rings: &mut [u32; fw::g15::RINGS], ch: &mut G15ClChannel, job: &G15RdJob, ring: usize, class: u32) -> u32 {
        let mut slot = ch.submitted_records;
        let records = [job.pre.as_ref().map(va), Some(va(&job.job_state))];
        for r in records.iter().flatten() {
            // SAFETY: an in-bounds 8 B store into the 256 record slots.
            unsafe { W(ch.chan_cached.raw_ptr()).u64((slot % 256) as usize * 8, *r) };
            slot += 1;
        }
        ch.submitted_records = slot;
        ch.submitted += 1;
        core::sync::atomic::fence(Ordering::Release);
        job.uma.count_submit();
        let idx = rings[ring];
        rings[ring] = (idx + 1) % 256;
        let base = self.initdata.ring_area.raw_ptr();
        // SAFETY: the ring entry (slot idx % 256 of the 0x1800 storage) is in
        // bounds of the 128 KiB ring region.
        unsafe {
            let e = W(base.add(ring * fw::g15::RING_STRIDE + 8 + (idx % 256) as usize * 24));
            e.u64(0x00, 0);
            e.u64(0x08, va(&ch.state));
            e.u32(0x10, class);
            e.0.add(0x14).cast::<u16>().write_unaligned((slot % 256) as u16);
            e.0.add(0x16).write_volatile(ch.stamp_index as u8);
            e.0.add(0x17).write_volatile(1);
            crate::mem::dc_civac(e.0, 24);
        }
        (idx + 1) % 256
    }

    /// G15: show the staged entries to the firmware: the write indices, stored
    /// together and cleaned together. The consumer reads an entry before its
    /// fields are visible (NULL state, sub_68BC +0x45C; a skipped entry) if the
    /// index comes first, and `dmb ish` does not order the stores for its core,
    /// so the entries are cleaned first and the indices follow `G15_PUBLISH_GAP_US`
    /// later. The 3D entry of a pass goes before its TA entry and waits for the
    /// TA's stamp: a consumer pass that takes it with the TA entry still unseen
    /// stops there (boot #451: both rings unconsumed behind it for good), so the
    /// two indices change within a few tens of ns.
    fn g15_rd_publish(&self, rings: &[(usize, u32)]) {
        kernel::time::delay::udelay(kernel::time::Delta::from_micros(super::G15_PUBLISH_GAP_US));
        let base = self.initdata.ring_area.raw_ptr();
        let mut words = [core::ptr::null::<u8>(); 2];
        for (i, (ring, next)) in rings.iter().enumerate() {
            let w = base.wrapping_add(ring * fw::g15::RING_STRIDE);
            // SAFETY: the write index word is in bounds of the 128 KiB ring region.
            unsafe { w.cast::<u32>().write_volatile(*next) };
            words[i] = w.cast_const();
        }
        crate::mem::dc_civac_each(&words[..rings.len()]);
    }

    /// G15: publish `job` on `ch` and ring: its entry (`g15_rd_stage`), the
    /// ring's write index, and with `doorbell` the doorbell message (`q << 2 | class`).
    fn g15_rd_submit(&self, ch: &mut G15ClChannel, job: &G15RdJob, ring: usize, class: u32, doorbell: bool) -> Result {
        let mut rings = self.g15_rings.lock();
        self.g15_ring_room(ring, rings[ring], ch, ch.submitted_records, job.records())?;
        let next = self.g15_rd_stage(&mut rings, ch, job, ring, class);
        self.g15_rd_publish(&[(ring, next)]);
        drop(rings);
        if doorbell {
            self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(u64::from(class)))?;
        }
        Ok(())
    }

    /// G15: a render pass on `pb`: the 3D job's entry and the TA job's, the
    /// buffer's 3D count, then both indices together and the TA's doorbell.
    fn g15_rd_submit_pass(&self, pb: &G15PbState, d3: &mut G15ClChannel, dj: &G15RdJob, ta: &mut G15ClChannel, tj: &G15RdJob) -> Result {
        let mut rings = self.g15_rings.lock();
        // Room for both first: a 3D entry staged without its TA would go out
        // with the next pass and wait for good.
        self.g15_ring_room(D3_RING, rings[D3_RING], d3, d3.submitted_records, dj.records())?;
        self.g15_ring_room(TA_RING, rings[TA_RING], ta, ta.submitted_records, tj.records())?;
        let n3 = self.g15_rd_stage(&mut rings, d3, dj, D3_RING, 1);
        let nt = self.g15_rd_stage(&mut rings, ta, tj, TA_RING, 0);
        pb.count_3d();
        self.g15_rd_publish(&[(D3_RING, n3), (TA_RING, nt)]);
        drop(rings);
        self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(0))
    }

    /// The stamp words of `ch`: (host, firmware).
    fn g15_rd_words(ch: &G15ClChannel) -> (u32, u32) {
        crate::mem::dc_civac(ch.words.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds u32 reads of the channel's own stamp words.
        unsafe {
            let w = ch.words.raw_ptr() as *const u32;
            (w.read_volatile(), w.add(1).read_volatile())
        }
    }

    /// Wait for `stamp` on `ch` (either stamp word), re-ringing `class`
    /// every 500 ms. Returns the milliseconds waited, or None on a timeout.
    fn g15_rd_wait(&self, name: &str, ch: &G15ClChannel, stamp: u32, class: u32) -> Option<u32> {
        const WAIT_MS: u32 = 3000;
        const RING_MS: u32 = 500;
        let dev = self.dev.as_ref();
        let reached = |ch: &G15ClChannel| {
            let (h, f) = Self::g15_rd_words(ch);
            h.wrapping_sub(stamp) as i32 >= 0 || f.wrapping_sub(stamp) as i32 >= 0
        };
        let mut waited = 0;
        while waited < WAIT_MS && !reached(ch) {
            kernel::time::delay::fsleep(Delta::from_millis(1));
            waited += 1;
            if waited % RING_MS == 0 {
                let _ = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(u64::from(class)));
            }
        }
        let (h, f) = Self::g15_rd_words(ch);
        if reached(ch) {
            dev_info!(dev, "G15 render self-test: {name} COMPLETED after ~{waited} ms (stamp {stamp:#x}: host {h:#x}, fw {f:#x})\n");
            Some(waited)
        } else {
            dev_err!(dev, "G15 render self-test: {name} TIMEOUT after {waited} ms (stamp {stamp:#x}: host {h:#x}, fw {f:#x})\n");
            None
        }
    }

    /// Ring `job` alone (its own doorbell) and wait for it.
    fn g15_rd_run(&self, name: &str, ch: &mut G15ClChannel, job: &G15RdJob, ring: usize, class: u32) -> Option<u32> {
        let pb = &self.initdata.pb_table;
        pb.with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
        if let Err(e) = self.g15_rd_submit(ch, job, ring, class, true) {
            dev_err!(self.dev.as_ref(), "G15 render self-test: {name} doorbell refused ({e:?})\n");
        }
        let r = self.g15_rd_wait(name, ch, job.stamp, class);
        pb.with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
        r
    }

    /// G15: one pass submitted as the kext does (the 3D behind a type-4
    /// barrier, no doorbell; then the TA, rung), waited for.
    #[allow(clippy::too_many_arguments)]
    fn g15_rd_linked(
        &self,
        name: &str,
        ta: &mut G15ClChannel,
        d3: &mut G15ClChannel,
        pb: &G15Pb,
        rt: &G15Rt,
        ctx: u32,
        id: u32,
        scene: usize,
        cmd: &G15RdCmd,
        jobs: &mut KVec<G15RdJob>,
        notifiers: &mut KVec<fw::types::GpuArray<u8>>,
    ) -> Result<bool> {
        let key = 0x20 + scene as u32 + 3;
        let ntf = self.g15_notifier_new(key, 2)?;
        let (ta_stamp, d3_stamp) = ((ta.submitted + 1) << 8, (d3.submitted + 1) << 8);
        let tl = G15RdLink {
            ntf: Some(va(&ntf)),
            other_index: d3.stamp_index,
            other_stamp: d3_stamp,
            other_word: 0,
        };
        let dl = G15RdLink {
            ntf: Some(va(&ntf)),
            other_index: ta.stamp_index,
            other_stamp: ta_stamp,
            other_word: va(&ta.words) + 4,
        };
        let dj = self.g15_3d_job_new(d3, pb, rt, ctx, id, key, scene, dl, cmd)?;
        let tj = self.g15_ta_job_new(ta, pb, rt, ctx, id + 1, key, scene, tl, false, cmd)?;
        let pbt = &self.initdata.pb_table;
        pbt.with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
        let r = self.g15_rd_submit_pass(pb, d3, &dj, ta, &tj);
        if let Err(e) = r {
            dev_err!(self.dev.as_ref(), "G15 render self-test: {name} submit failed ({e:?})\n");
        }
        let mut tname = KVec::new();
        let mut dname = KVec::new();
        for (v, sfx) in [(&mut tname, " TA"), (&mut dname, " 3D")] {
            v.extend_from_slice(name.as_bytes(), GFP_KERNEL)?;
            v.extend_from_slice(sfx.as_bytes(), GFP_KERNEL)?;
        }
        let ok = self.g15_rd_wait(core::str::from_utf8(&tname).unwrap_or("TA"), ta, tj.stamp, 0).is_some()
            & self.g15_rd_wait(core::str::from_utf8(&dname).unwrap_or("3D"), d3, dj.stamp, 1).is_some();
        pbt.with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
        g15_fwdump(6);
        jobs.push(tj, GFP_KERNEL)?;
        jobs.push(dj, GFP_KERNEL)?;
        notifiers.push(ntf, GFP_KERNEL)?;
        Ok(ok)
    }

    /// G15: a render queue's TA and 3D channels. They share one notifier
    /// list: the kext hands both the same `channel+0xA8`
    /// (`AGXCommandQueue::allocate3DWorkQueue`, `AGX3DWorkQueue::allocTAChannel`),
    /// so a pass's notifier, which the TA's kick inserts, is walked by the
    /// 3D's post-processing too. With a list each, a TA that is
    /// post-processed before its 3D leaves the notifier unflushed (the 3D
    /// walks an empty list): the firmware's stamp moves, the host's never
    /// does and no completion event comes (renders of over a thousand tiles).
    fn g15_rd_chans_new(&self) -> Result<(G15ClChannel, G15ClChannel)> {
        let ta = self.g15_cl_channel_new()?;
        let d3 = self.g15_cl_channel_new()?;
        // SAFETY: the 3D state's +0x10 is one in-bounds u64 of its own
        // state block (the notifier-list header's GPUVA).
        unsafe {
            d3.state.raw_ptr().add(0x10).cast::<u64>().write_volatile(ta.chan_list.gpu_va().get());
        }
        Ok((ta, d3))
    }

    /// G15: a queue's render state: a free TA/3D channel pair (else a new
    /// one), a parameter-buffer ID and the buffer, its blocks from
    /// `ualloc` (the queue's VM: its kernel range must reach into
    /// [64 GiB, 576 GiB)).
    pub(crate) fn g15_rd_queue_new(&self, ualloc: &Arc<Mutex<alloc::DefaultAllocator>>) -> Result<G15RdQueue> {
        let id = {
            let mut ids = self.g15_pb_ids.lock();
            let free = !*ids;
            if free == 0 {
                return Err(EBUSY);
            }
            let i = free.trailing_zeros();
            *ids |= 1u64 << i;
            i
        };
        // On an error the buffer (or the bare ID) returns the ID.
        let pb = match self.g15_pb_new(&mut ualloc.lock(), id, Some(self.g15_pb_ids.clone())) {
            Ok(pb) => pb,
            Err(e) => {
                *self.g15_pb_ids.lock() &= !(1u64 << id);
                return Err(e);
            }
        };
        let (ta, d3) = match self.g15_free_rd_chans.lock().pop() {
            Some(pair) => pair,
            None => {
                let (ta, d3) = self.g15_rd_chans_new()?;
                (
                    Arc::pin_init(new_mutex!(ta, "g15_ta_chan"), GFP_KERNEL)?,
                    Arc::pin_init(new_mutex!(d3, "g15_3d_chan"), GFP_KERNEL)?,
                )
            }
        };
        Ok(G15RdQueue {
            ta,
            d3,
            pb: Arc::new(pb, GFP_KERNEL)?,
            passes: 0,
        })
    }

    /// G15: a destroyed queue's channels go back for reuse, unless a job
    /// on either never finished (as `g15_cl_channel_put`). The parameter
    /// buffer goes with its last pass.
    pub(crate) fn g15_rd_queue_put(&self, q: &G15RdQueue) {
        let idle = |c: &Arc<Mutex<G15ClChannel>>| Self::g15_chan_idle(&c.lock());
        if idle(&q.ta) && idle(&q.d3) {
            if self.g15_free_rd_chans.lock().push((q.ta.clone(), q.d3.clone()), GFP_KERNEL).is_err() {
                dev_err!(self.dev.as_ref(), "G15: cannot keep a render channel pair\n");
            }
        } else {
            dev_warn!(self.dev.as_ref(), "G15: render channels with an unfinished job are retired\n");
            let mut dead = self.g15_dead_chans.lock();
            if dead.push(q.ta.clone(), GFP_KERNEL).is_err() || dead.push(q.d3.clone(), GFP_KERNEL).is_err() {
                dev_err!(self.dev.as_ref(), "G15: cannot keep a render channel\n");
            }
        }
    }

    /// G15: run one render pass of queue `q` in context `ctx`: its 3D job
    /// first, behind a type-4 barrier on the TA's stamp and without a
    /// doorbell, then its TA job, rung (as `g15_rd_linked`); `done` runs
    /// once the 3D completed. The first TA job of the queue's parameter
    /// buffer carries the PMRebuild record.
    pub(crate) fn g15_rd_pass_run(
        &self,
        q: &mut G15RdQueue,
        ctx: u32,
        cmd: &G15RdCmd,
        rt: G15Rt,
        done: KBox<dyn FnMut(Option<Error>) + Send>,
    ) -> Result {
        let scene = (q.passes % PB_SCENES as u32) as usize;
        let first = q.passes == 0;
        let id = self.g15_rd_ids.fetch_add(2, Ordering::Relaxed);
        let key = 0x20 + scene as u32 + 3;
        let ntf = self.g15_notifier_new(key, 2)?;
        let pending = {
            let mut ta = q.ta.lock();
            let mut d3 = q.d3.lock();
            let (ta_stamp, d3_stamp) = ((ta.submitted + 1) << 8, (d3.submitted + 1) << 8);
            let tl = G15RdLink {
                ntf: Some(va(&ntf)),
                other_index: d3.stamp_index,
                other_stamp: d3_stamp,
                other_word: 0,
            };
            let dl = G15RdLink {
                ntf: Some(va(&ntf)),
                other_index: ta.stamp_index,
                other_stamp: ta_stamp,
                other_word: va(&ta.words) + 4,
            };
            let dj = self.g15_3d_job_new(&d3, &q.pb, &rt, ctx, id, key, scene, dl, cmd)?;
            let tj = self.g15_ta_job_new(&ta, &q.pb, &rt, ctx, id + 1, key, scene, tl, first, cmd)?;
            let pbt = &self.initdata.pb_table;
            pbt.with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
            let r = self.g15_rd_submit_pass(&q.pb, &mut d3, &dj, &mut ta, &tj);
            pbt.with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
            r?;
            q.passes += 1;
            mod_dev_dbg!(self.dev, "G15: render pass {} rung (ctx {ctx}, TA stamp {:#x}, 3D stamp {:#x})\n", q.passes, tj.stamp, dj.stamp);
            let ta_stamp = tj.stamp;
            G15ClPending {
                chan: q.d3.clone(),
                stamp: dj.stamp,
                n: d3.submitted,
                ctx,
                ta: Some((q.ta.clone(), ta_stamp)),
                _work: G15Work::Rd(KBox::new(
                    G15RdPass {
                        _ta: tj,
                        _d3: dj,
                        _ntf: ntf,
                        _rt: rt,
                        _pb: q.pb.clone(),
                        scene,
                    },
                    GFP_KERNEL,
                )?),
                done,
                signaled: false,
                error: None,
                nudge: kernel::time::Instant::<kernel::time::Monotonic>::now(),
                nudges: 0,
            }
        };
        self.g15_pending.lock().push(pending, GFP_KERNEL)?;
        self.g15_cl_retire();
        if let Some(kick) = self.g15_kick.lock().as_ref() {
            kick();
        }
        Ok(())
    }

    /// G15: demo15's clear, in the self-test's VM (user VAs); the
    /// programs and their data as `g15_rd_write_clear`.
    fn g15_rd_clear_progs(&self, pb: &mut G15RdVm) -> Result<G15RdClear> {
        let code = pb.ualloc.array_empty_tagged::<u8>(0x8000, b"SHDR")?;
        let data = pb.ualloc.array_empty_tagged::<u8>(0x8000, b"PDAT")?;
        let out = pb.hialloc.array_empty_tagged::<u8>((RT_W * RT_H * 4) as usize, b"OUTB")?;
        let (c, d) = (va(&code), va(&data));
        // SAFETY: fresh 0x8000 B code and data buffers and the target.
        let progs = unsafe {
            core::ptr::write_bytes(out.raw_ptr(), CLEAR_FILL, (RT_W * RT_H * 4) as usize);
            g15_rd_write_clear(code.raw_ptr(), c, data.raw_ptr(), d, va(&out))
        };
        dev_info!(self.dev.as_ref(), "G15 render self-test: clear programs at {c:#x}, data {d:#x}, target {:#x}\n", va(&out));
        Ok(G15RdClear {
            progs,
            _code: code,
            _data: data,
            out,
        })
    }

    /// One buffer of the self-test's VM at a fixed VA: its own allocator
    /// over [`at`, `at` + `size` + a guard page).
    fn g15_rd_fixed(&self, vm: &mmu::Vm, at: u64, size: usize, tag: &[u8; 4]) -> Result<(fw::types::GpuArray<u8>, alloc::DefaultAllocator)> {
        let mut a = alloc::DefaultAllocator::new(
            &self.dev,
            vm,
            at..at + (size + mmu::UAT_PGSZ) as u64,
            mmu::UAT_PGSZ,
            mmu::PROT_GPU_SHARED_RW,
            size,
            true,
            fmt!("G15 render self-test {at:#x}"),
            false,
        )?;
        let b = a.array_empty_tagged::<u8>(size, tag)?;
        if va(&b) != at {
            dev_err!(self.dev.as_ref(), "G15 render self-test: {at:#x} allocated at {:#x}\n", va(&b));
            return Err(EINVAL);
        }
        Ok((b, a))
    }

    /// G15: demo15's quad (two triangles, 6 vertices at +-0.5) at its fixed
    /// VAs: the VDM stream and its PPP blocks (TRI_VDM_RUNS), the vertex
    /// entry program (loads the vertex pointer into u0/u1 and the matrix
    /// into u4-u19, then the vertex shader: fetches its vertex by r0 << 4,
    /// transforms it, st_var x, y, z, w), the fragment entry program and
    /// shader, and the clear's background and end-of-tile programs.
    fn g15_rd_tri(&self, pb: &G15RdVm) -> Result<G15RdTri> {
        let vm = &pb.vm;
        let n = (RT_W * RT_H * 4) as usize;
        let vdm = self.g15_rd_fixed(vm, TRI_VDM, 0x8000, b"TVDM")?;
        let fsb = self.g15_rd_fixed(vm, TRI_FS_BLOCK, 0x4000, b"TFSH")?;
        let out = self.g15_rd_fixed(vm, TRI_OUT, n, b"TOUT")?;
        let verts = self.g15_rd_fixed(vm, TRI_VERTS, 0x20000, b"TVTX")?;
        let mat = self.g15_rd_fixed(vm, TRI_MATRIX, 0x20000, b"TMAT")?;
        let data = self.g15_rd_fixed(vm, TRI_DATA, 0x8000, b"TDAT")?;
        let code = self.g15_rd_fixed(vm, TRI_CODE, 0x8000, b"TCOD")?;
        let vs = TRI_CODE + 0x480;
        // SAFETY: every store is in bounds of the buffer it names, each
        // freshly allocated and sized above; each program well under its
        // slot.
        let progs = unsafe {
            for (off, b) in TRI_VDM_RUNS {
                core::ptr::copy_nonoverlapping(b.as_ptr(), vdm.0.raw_ptr().add(*off), b.len());
            }
            core::ptr::copy_nonoverlapping(TRI_FS.as_ptr(), fsb.0.raw_ptr().add(0x4C0), TRI_FS.len());
            core::ptr::write_bytes(out.0.raw_ptr(), CLEAR_FILL, n);
            let vw = W(verts.0.raw_ptr());
            for (i, f) in TRI_VERTICES.iter().enumerate() {
                vw.u32(16 * (i / 3) + 4 * (i % 3), f.to_bits());
            }
            let mw = W(mat.0.raw_ptr());
            for (i, f) in TRI_MATRIX_F.iter().enumerate() {
                mw.u32(0x100 + 4 * i, f.to_bits());
            }
            W(data.0.raw_ptr()).u64(0x100, TRI_VERTS);

            let c = code.0.raw_ptr();
            let mut a = Asm { p: c.add(0x480), off: 0 };
            a.bytes(&[0x0C, 0xDD, 0x10, 0x06]); // get_sr r0
            a.wait(0);
            a.bytes(&[0x67, 0x10, 0x44, 0, 0, 0x80, 0x20, 0, 0x5D, 0x01, 0, 0x40, 0x40, 0]);
            a.wait(5);
            a.bytes(TRI_VS_FFMA);
            for i in 0..4u8 {
                a.bytes(&[0x57, 6 | 0x10 << i, 0x54, 6 - 2 * i, 0x20 * i, 0x40, 0x48 + i, 0]);
            }
            a.stop();

            let (pv, rot) = (TRI_DATA + 0x100, TRI_MATRIX + 0x100 + 0x8000);
            let mut a = Asm { p: c.add(0x4000), off: 0 };
            a.imm(pv as u32, 2);
            a.imm((pv >> 32) as u32, 3);
            a.imm(rot as u32, 18);
            a.imm((rot >> 32) as u32, 19);
            a.bytes(&[0x67, 0, 0x54, 0x20, 0x02, 0, 0, 0, 0x59, 0, 0, 0x40, 0x26, 0]);
            for (i, m) in [0x3Cu8, 0x34, 0x2C, 0x24].iter().enumerate() {
                let i = i as u8;
                a.bytes(&[0x67, 0, 0x54, *m, 0x12, 0, 0, 0, 0x57, if i == 3 { 4 } else { 0 }, 6 - 2 * i, 0x50, 0x26, 0]);
            }
            a.load_shader(vs, 1);
            a.bytes(&[0x06, 0x00, 0xF7, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            a.mov_u_r(0, 16);
            a.mov_u_r(1, 17);
            for i in 4..20 {
                a.mov_u_r(i, i + 14);
            }
            a.stop();

            let mut a = Asm { p: c.add(0x3000), off: 0 };
            a.bytes(&[0x77, 0x00, 0x2A, 0x43, 0x4B, 0x00, 0x00, 0x00]);
            a.load_shader(TRI_FS_BLOCK + 0x4C0, 1);
            a.bytes(&[0x04, 0x00]);
            a.imm(0, 1);
            a.bytes(&[0x14, 0x81, 0x11, 0x06, 0, 0, 0, 0]); // get_sr
            a.imm(0x100, 0);
            a.bytes(&[0x9F, 0x11, 0x54, 0x00, 0x02, 0x00, 0x08, 0xA8, 0x10, 0x05]); // iadd
            a.imm(0x100, 1);
            a.bytes(&[0x0F, 0x12, 0x54, 0x00, 0x4C, 0x00, 0x07, 0x02, 0x54, 0xF3, 0x02, 0x00]);
            a.stop();

            G15RdProgs {
                vdm: Some(TRI_VDM),
                ..g15_rd_write_clear(c, TRI_CODE, data.0.raw_ptr(), TRI_DATA, TRI_OUT)
            }
        };
        let mut bufs = KVec::new();
        for b in [vdm, fsb, verts, mat, data, code] {
            bufs.push(b, GFP_KERNEL)?;
        }
        dev_info!(self.dev.as_ref(), "G15 render self-test: quad: VDM {TRI_VDM:#x}, programs {TRI_CODE:#x}, target {TRI_OUT:#x}\n");
        Ok(G15RdTri {
            progs,
            out,
            _bufs: bufs,
        })
    }

    /// G15: the first render jobs. Pass 1: the TA of an empty pass, then
    /// (once it completed) its 3D, each rung on its own. Pass 2, as the
    /// kext submits a pass (AGX3DWorkQueue::submitCommand): the 3D first,
    /// behind a type-4 barrier on the TA's stamp and without a doorbell,
    /// then the TA with the doorbell; one notifier with two kicks.
    pub(super) fn g15_render_selftest(&self) {
        let dev = self.dev.as_ref();
        let run = || -> Result<G15RenderTest> {
            let (mut ta, mut d3) = self.g15_rd_chans_new()?;
            let mut rdvm = self.g15_rd_vm_new()?;
            let pb = self.g15_pb_new(&mut rdvm.ualloc, PB_ID, None)?;
            let cmd = G15RdCmd::test()?;
            let rt = self.g15_rt_new(&cmd.geom)?;
            let ctx = rdvm.bind.slot();
            dev_info!(dev, "G15 render self-test: VDM {:#x} tilemap {:#x} layermeta {:#x} heapmeta {:#x} TPC {:#x} cl-tilemaps {:#x} cl-layermeta {:#x} meta1-4 {:#x} {:#x} {:#x} {:#x}\n",
                      va(&rt.vdm), va(&rt.tilemap), va(&rt.layermeta), va(&rt.heapmeta), va(&rt.tpc), va(&rt.cl_tilemaps),
                      va(&rt.cl_layermeta), va(&rt.meta1), va(&rt.meta2), va(&rt.meta3), va(&rt.meta4));
            dev_info!(dev, "G15 render self-test: preempt {:#x} {:#x} {:#x} scissor {:#x} dbias {:#x}; PB info {:#x} ctl {:#x} counter {:#x} blocks list {:#x} pages {:#x} scenes {:#x} metrics {:#x} slots {:#x}\n",
                      va(&rt.preempt1), va(&rt.preempt2), va(&rt.preempt3), va(&rt.scissor), va(&rt.dbias), va(&pb.info),
                      va(&pb.block_ctl), va(&pb.counter), va(&pb.block_list), va(&pb.page_list), va(&pb.scenes),
                      va(&pb.metrics), va(&pb.slots));
            dev_info!(dev, "G15 render self-test: context {ctx}, PB blocks at {:#x}, TA index {}, 3D index {}\n",
                      pb.blocks.gpu_va().get(), ta.stamp_index, d3.stamp_index);
            let mut jobs = KVec::new();
            let mut notifiers = KVec::new();
            let mut clears = KVec::new();

            // Pass 1: separately.
            let solo = |other_index, other_stamp| G15RdLink {
                ntf: None,
                other_index,
                other_stamp,
                other_word: 0,
            };
            let tj = self.g15_ta_job_new(&ta, &pb, &rt, ctx, 0x1001, 0x21, 0, solo(d3.stamp_index, 0x100), true, &cmd)?;
            let dj = self.g15_3d_job_new(&d3, &pb, &rt, ctx, 0x1002, 0x22, 0, solo(0, 0), &cmd)?;
            g15_fwdump(4);
            let ok = self.g15_rd_run("pass 1 TA", &mut ta, &tj, TA_RING, 0).is_some()
                && self.g15_rd_run("pass 1 3D", &mut d3, &dj, D3_RING, 1).is_some();
            jobs.push(tj, GFP_KERNEL)?;
            jobs.push(dj, GFP_KERNEL)?;
            g15_fwdump(5);

            // Pass 2: one submission. Pass 3: a clear (background and
            // end-of-tile programs).
            let mut ok = ok;
            if ok {
                ok = self.g15_rd_linked("pass 2", &mut ta, &mut d3, &pb, &rt, ctx, 0x1003, 1, &cmd, &mut jobs, &mut notifiers)?;
            }
            if ok {
                let clear = self.g15_rd_clear_progs(&mut rdvm)?;
                ok = self.g15_rd_linked("pass 3", &mut ta, &mut d3, &pb, &rt, ctx, 0x1005, 2, &cmd.with_progs(&clear.progs), &mut jobs, &mut notifiers)?;
                let (hit, untouched, px) = g15_rd_check(&clear.out);
                dev_info!(dev, "G15 render self-test: clear: {hit}/{} pixels {CLEAR_PIXEL:#010x}, {untouched} untouched; pixels 0, 1, (40, 33), (32, 32), last: {:#010x} {:#010x} {:#010x} {:#010x} {:#010x}\n",
                          RT_W * RT_H, px[0], px[1], px[2], px[3], px[4]);
                clears.push(clear, GFP_KERNEL)?;
            }
            // Pass 4: demo15's quad.
            let mut tris = KVec::new();
            if ok {
                let tri = self.g15_rd_tri(&rdvm)?;
                self.g15_rd_linked("pass 4", &mut ta, &mut d3, &pb, &rt, ctx, 0x1007, 3, &cmd.with_progs(&tri.progs), &mut jobs, &mut notifiers)?;
                let (hit, untouched, px) = g15_rd_check(&tri.out.0);
                let n = (RT_W * RT_H) as usize;
                dev_info!(dev, "G15 render self-test: quad: {hit}/{n} pixels {CLEAR_PIXEL:#010x}, {untouched} untouched, {} other; pixels 0, 1, (40, 33), (32, 32), last: {:#010x} {:#010x} {:#010x} {:#010x} {:#010x}\n",
                          n - hit - untouched, px[0], px[1], px[2], px[3], px[4]);
                tris.push(tri, GFP_KERNEL)?;
            }
            self.g15_drain_fw_rings();
            Ok(G15RenderTest {
                _ta: ta,
                _d3: d3,
                _pb: pb,
                _vm: rdvm,
                _rt: rt,
                _jobs: jobs,
                _notifiers: notifiers,
                _clears: clears,
                _tris: tris,
            })
        };
        match run() {
            Ok(t) => match KBox::new(t, GFP_KERNEL) {
                Ok(t) => *self.g15_render_test.lock() = Some(t),
                Err(_) => dev_err!(dev, "G15 render self-test: cannot keep its state\n"),
            },
            Err(e) => dev_err!(dev, "G15 render self-test: setup failed ({e:?})\n"),
        }
    }
}
