// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 self-tests run at probe.

use super::*;

/// The self-test's render target: 64x64 px.
pub(super) const RT_W: u32 = 64;
pub(super) const RT_H: u32 = 64;

impl G15RdCmd {
    /// The self-test's pass: its 64x64 target, one sample at (8, 8)/16,
    /// depth cleared to 1.0, no depth/stencil buffers, no programs.
    pub(crate) fn test() -> Result<G15RdCmd> {
        #[allow(
            clippy::float_arithmetic,
            reason = "constant operands, folded at build time"
        )]
        let merge = |d: u32| f32::to_bits(1.7321 / d as f32);
        Ok(G15RdCmd {
            geom: G15RdGeom::new(RT_W, RT_H, 1, 1, 32, 32, 4)?,
            vdm: None,
            bg: (0, 0),
            eot: (0, 0),
            partial_bg: (0, 0),
            partial_eot: (0, 0),
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
    pub(super) fn with_progs(self, p: &G15RdProgs) -> G15RdCmd {
        G15RdCmd {
            vdm: p.vdm,
            bg: p.bg,
            eot: p.eot,
            process_empty: true,
            ..self
        }
    }
}

/// The self-test's hardware buffer ID (PBID); the uAPI's buffers take
/// 1..63 (`g15_pb_ids`).
pub(super) const PB_ID: u32 = 0;

/// The blocks' range in the self-test's VM: below 2^40 (a block-list entry
/// keeps VA bits \[39:15\]), as Asahi's IOVA_KERN_GPU_BUFMGR_LOW.
pub(super) const PB_VA: Range<u64> = 0x20_0000_0000..0x21_0000_0000;
/// The self-test VM's 1 TiB window: a PBE's buffer is VA bits \[39:4\]
/// from 0x100_0000_0000 (a user target at 0x20_0034_0000 was written at
/// 0x120_0034_xxxx, boot #158; demo15 keeps its target at 1 TiB too).
pub(super) const HI_VA: Range<u64> = 0x100_1000_0000..0x100_2000_0000;
/// The self-test VM's whole kernel range: demo15's fixed VAs included.
pub(super) const VM_KERNEL_VA: Range<u64> = 0x4000..0x100_2000_0000;

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

/// The 3D's programs: the background and end-of-tile words (`0x15368`/
/// `0x15370`, `0x15378`/`0x15380`: word 0 the binding, word 1 the entry
/// program's VA), with empty tiles processed; and the TA's VDM stream
/// (`0x1C880`, a user VA), or None for the empty one.
#[derive(Clone, Copy)]
pub(super) struct G15RdProgs {
    pub(super) bg: (u64, u64),
    pub(super) eot: (u64, u64),
    pub(super) vdm: Option<u64>,
}

/// The self-test's state, kept for the device's lifetime (the firmware
/// references the channels, the buffers and the jobs).
pub(crate) struct G15RenderTest {
    pub(super) _ta: G15ClChannel,
    pub(super) _d3: G15ClChannel,
    pub(super) _pb: G15Pb,
    pub(super) _vm: G15RdVm,
    pub(super) _rt: G15Rt,
    pub(super) _jobs: KVec<G15RdJob>,
    pub(super) _notifiers: KVec<fw::types::GpuArray<u8>>,
    pub(super) _clears: KVec<G15RdClear>,
    pub(super) _tris: KVec<G15RdTri>,
}

/// A byte cursor for hand-assembled AGX3 code: the encoders of
/// noopwafel's demo15 (Mesa `hacky-tribuf-15x-demo`, `src/asahi/lib/demo.c`).
pub(super) struct Asm {
    pub(super) p: *mut u8,
    pub(super) off: usize,
}

impl Asm {
    /// # Safety
    /// The buffer must have room for every byte written.
    pub(super) unsafe fn bytes(&mut self, b: &[u8]) {
        for &x in b {
            // SAFETY: in bounds per the caller.
            unsafe { self.p.add(self.off).write_volatile(x) };
            self.off += 1;
        }
    }
    /// # Safety
    /// The buffer must have room for the 4 bytes written.
    pub(crate) unsafe fn u32(&mut self, v: u32) {
        // SAFETY: as `bytes`.
        unsafe { self.bytes(&v.to_le_bytes()) }
    }
    /// # Safety
    /// The buffer must have room for the 8 bytes written.
    pub(crate) unsafe fn u64(&mut self, v: u64) {
        // SAFETY: as `bytes`.
        unsafe { self.bytes(&v.to_le_bytes()) }
    }
    /// `mov uN, rM` (4 B).
    ///
    /// # Safety
    /// The buffer must have room for the 4 bytes written.
    pub(super) unsafe fn mov_u_r(&mut self, u: u32, r: u32) {
        // SAFETY: as `bytes`.
        unsafe { self.u32(0x0409_000B | (u & 0xF) << 4 | (u >> 4) << 22 | r << 9) }
    }
    /// `wait` on scoreboard slot `id` (8 B).
    ///
    /// # Safety
    /// The buffer must have room for the 8 bytes written.
    pub(super) unsafe fn wait(&mut self, id: u32) {
        // SAFETY: as `bytes`.
        unsafe { self.bytes(&[6, (4 << id) as u8, 6, 0, 6, 0, 6, 0]) }
    }
    /// `mov rN, imm32` (8 B).
    ///
    /// # Safety
    /// The buffer must have room for the 8 bytes written.
    pub(super) unsafe fn imm(&mut self, v: u32, r: u64) {
        let v = u64::from(v);
        let i = (v & 0x7F) << 8
            | (v >> 7 & 0xF) << 33
            | (v >> 11 & 3) << 42
            | (v >> 13 & 0xFFF) << 48
            | (v >> 25 & 0x7F) << 25;
        // SAFETY: as `bytes`.
        unsafe { self.u64(0x2800C | i | (r & 0xF) << 4 | (r >> 4) << 22) }
    }
    /// The entry program's "load shader": jump to the program at `va`.
    ///
    /// # Safety
    /// The buffer must have room for the 8 bytes written.
    pub(super) unsafe fn load_shader(&mut self, va: u64, dest: u64) {
        // SAFETY: as `bytes`.
        unsafe { self.u64(0x2A0177 | dest << 8 | (va >> 6) << 23) }
    }
    /// # Safety
    /// The buffer must have room for the 4 bytes written.
    pub(super) unsafe fn stop(&mut self) {
        // SAFETY: as `bytes`.
        unsafe { self.bytes(&[0x0E, 0, 0, 0]) }
    }
}

/// The self-test's clear: the programs, their data and the target.
pub(crate) struct G15RdClear {
    pub(super) progs: G15RdProgs,
    pub(super) _code: fw::types::GpuArray<u8>,
    pub(super) _data: fw::types::GpuArray<u8>,
    pub(super) out: fw::types::GpuArray<u8>,
}

/// demo15's fixed VAs (Mesa `hacky-tribuf-15x-demo`, `demo.c`): the VDM
/// stream (+ its PPP blocks at +0x1000/+0x1100/+0x1200) at 192 GiB (the
/// TA's VDM pointer reaches only user VAs in [64 GiB, 576 GiB): demo15's
/// "low" 0x18000 was a hint the kext ignored), the rest at 1 TiB — the
/// fragment shader in the first 16 KiB there, the target, the vertices,
/// the matrix, the programs' data and the programs.
pub(super) const TRI_VDM: u64 = 0x30_0000_0000;
pub(super) const TRI_FS_BLOCK: u64 = 0x100_0000_0000;
pub(super) const TRI_OUT: u64 = 0x100_0002_0000;
pub(super) const TRI_VERTS: u64 = 0x100_0016_8000;
pub(super) const TRI_MATRIX: u64 = 0x100_0019_0000;
pub(super) const TRI_DATA: u64 = 0x100_0025_0000;
pub(super) const TRI_CODE: u64 = 0x100_0027_0000;

/// demo15's VDM stream for the VAs above, a 64x64 target and 6 vertices:
/// (offset, bytes) runs, from Mesa's packers with noopwafel's G15
/// `cmdbuf.xml` (the vertex entry program at TRI_CODE + 0x4000, the
/// fragment entry program at TRI_CODE + 0x3000). The stream's PPP
/// pointers take the 40-bit form too (VA − 64 GiB: boot #161 fetched a
/// raw `0x30_0000_1000` at `0x40_0000_1000`).
pub(super) const TRI_VDM_RUNS: &[(usize, &[u8])] = &[
    (
        0x0,
        &[
            0x2E, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x9D,
            0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x20, 0x07, 0x00, 0x00, 0x00, 0x12,
            0x00, 0x00, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x06, 0xC4, 0x61,
            0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xC0,
        ],
    ),
    (
        0x1000,
        &[
            0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xC0, 0x9C, 0x00, 0x00,
        ],
    ),
    (
        0x1100,
        &[
            0x00, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x42,
            0x00, 0x00, 0x00, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3F,
        ],
    ),
    (
        0x1200,
        &[
            0xB4, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x06, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00,
        ],
    ),
];

/// demo15's fragment shader (at TRI_FS_BLOCK + 0x4C0).
pub(super) const TRI_FS: &[u8] = &[
    0x97, 0x0C, 0x54, 0x00, 0x03, 0x40, 0x80, 0x50, 0x04, 0xC8, 0x03, 0x00, 0x01, 0x01, 0x87, 0x02,
    0x54, 0x00, 0x06, 0x00, 0x87, 0x02, 0x54, 0x0C, 0x08, 0x00, 0xE7, 0x06, 0x54, 0x00, 0x00, 0x00,
    0x01, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x07, 0x02, 0x54, 0x0C, 0x02, 0x00, 0x0E, 0x00, 0x00, 0x00,
];

/// demo15's vertex shader's transform (12 ffma).
pub(super) const TRI_VS_FFMA: &[u8] = &[
    0x59, 0x09, 0x26, 0x81, 0x21, 0x20, 0x82, 0xC0, 0x39, 0x0B, 0x26, 0x81, 0x21, 0x22, 0x82, 0x00,
    0x49, 0x83, 0x26, 0x11, 0xA0, 0x0A, 0x39, 0x83, 0x26, 0x13, 0xA0, 0x06, 0x39, 0x85, 0x26, 0x19,
    0x81, 0x08, 0x42, 0x02, 0x29, 0x85, 0x26, 0x1B, 0x82, 0x06, 0x42, 0x02, 0x00, 0x04, 0x39, 0x0D,
    0x26, 0x81, 0x21, 0x24, 0x82, 0x00, 0x09, 0x0F, 0x36, 0x01, 0x21, 0x26, 0x82, 0x00, 0x39, 0x83,
    0x26, 0x15, 0xA0, 0x06, 0x09, 0x03, 0x2E, 0x17, 0xA0, 0x00, 0x19, 0x85, 0x26, 0x1D, 0x82, 0x06,
    0x42, 0x02, 0x00, 0x08, 0x09, 0x05, 0x2E, 0x1F, 0x82, 0x00, 0x42, 0x02, 0x00, 0x0C,
];

/// demo15's vertices (x, y, z; w = 0 in memory) and its frame-0 matrix.
pub(super) const TRI_VERTICES: [f32; 18] = [
    -0.5, -0.5, 0.0, -0.5, 0.5, 0.0, 0.5, -0.5, 0.0, 0.5, 0.5, 0.0, -0.5, 0.5, 0.0, 0.5, -0.5, 0.0,
];
pub(super) const TRI_MATRIX_F: [f32; 16] = [
    1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
];

/// The self-test's triangles: demo15's quad, its buffers at fixed VAs.
pub(crate) struct G15RdTri {
    pub(super) progs: G15RdProgs,
    pub(super) out: (fw::types::GpuArray<u8>, alloc::DefaultAllocator),
    pub(super) _bufs: KVec<(fw::types::GpuArray<u8>, alloc::DefaultAllocator)>,
}

/// The clear colour (r, g, b, a) and its RGBA8 pixel.
pub(super) const CLEAR_RGBA: [f32; 4] = [1.0, 0.0, 1.0, 1.0];
pub(super) const CLEAR_PIXEL: u32 = 0xFFFF_00FF;
pub(super) const CLEAR_FILL: u8 = 0x11;

/// What a pass wrote to its target: the pixels equal to the clear, those
/// still at the fill, and five samples: pixels 0, 1, (40, 33), (32, 32),
/// the last.
pub(super) fn g15_rd_check(out: &fw::types::GpuArray<u8>) -> (usize, usize, [u32; 5]) {
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
pub(super) unsafe fn g15_rd_write_clear(
    code: *mut u8,
    c: u64,
    data: *mut u8,
    d: u64,
    out: u64,
) -> G15RdProgs {
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
        let w0 = 2
            | 0x28 << 6
            | 1 << 18
            | 2 << 20
            | 3 << 22
            | u64::from(RT_W - 1) << 24
            | u64::from(RT_H - 1) << 38;
        let w1 = (out >> 4 & 0xF_FFFF_FFFF) | 1 << 36 | u64::from(RT_W * 4 - 0x10) << 40;
        dw.u64(0x700, w0);
        dw.u64(0x708, w1);
        dw.u64(0x710, 0);

        let mut a = Asm {
            p: code.add(0x1000),
            off: 0,
        };
        a.imm(clear_base as u32, 2);
        a.imm((clear_base >> 32) as u32, 3);
        a.bytes(&[
            0x67, 0x00, 0x54, 0x24, 0x02, 0x00, 0x00, 0x00, 0x57, 0x00, 0x08, 0x40, 0x26, 0x00,
        ]);
        a.bytes(&[0x77, 0x00, 0x2A, 0x43, 0x4B, 0x00, 0x00, 0x00]);
        a.load_shader(bg_prog, 1);
        a.bytes(&[0x04, 0x00, 0x06, 0x08, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00]);
        a.bytes(&[
            0x2B, 0x24, 0x09, 0x04, 0x3B, 0x26, 0x09, 0x04, 0x4B, 0x28, 0x09, 0x04, 0x5B, 0x2A,
            0x09, 0x04,
        ]);
        a.stop();

        let mut a = Asm {
            p: code.add(0x50C0),
            off: 0,
        };
        a.bytes(&[0x97, 0x0C, 0x54, 0x00, 0x02, 0x08, 0x18, 0xD0, 0x05, 0xC8]);
        a.bytes(&[0x97, 0x04, 0x54, 0x01, 0x02, 0x10, 0x28, 0xD0, 0x05, 0xC8]);
        a.bytes(&[0xE7, 0x06, 0x54, 0, 0, 0, 0x01, 0x4E, 0, 0, 0, 0]);
        a.stop();

        let mut a = Asm {
            p: code.add(0x2000),
            off: 0,
        };
        a.imm(eot_base as u32, 2);
        a.imm((eot_base >> 32) as u32, 3);
        a.bytes(&[0x0C, 0x00, 0x3B, 0x00, 0x01, 0x04]);
        a.bytes(&[
            0x67, 0, 0x54, 0x24, 0x02, 0, 0, 0, 0x51, 0x00, 0x08, 0x40, 0x26, 0,
        ]);
        a.bytes(&[
            0x67, 0, 0x54, 0x20, 0x02, 0, 0, 0, 0x59, 0x00, 0x00, 0x40, 0x26, 0,
        ]);
        a.bytes(&[0x77, 0x00, 0x2A, 0x43, 0x4B, 0x00, 0x00, 0x00]);
        a.load_shader(eot_prog, 1);
        a.bytes(&[
            0x04, 0x00, 0xF7, 0x00, 0x2A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        a.bytes(&[0x06, 0x08, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00]);
        a.bytes(&[
            0x2B, 0x24, 0x09, 0x04, 0x0B, 0x20, 0x09, 0x04, 0x1B, 0x22, 0x09, 0x04,
        ]);
        a.stop();

        let mut a = Asm {
            p: code.add(0x5200),
            off: 0,
        };
        a.bytes(&[
            0x1C, 0x9C, 0x10, 0x06, 0x0C, 0x9D, 0x10, 0x26, 0x34, 0xA8, 0x10, 0x06, 0x24, 0xA9,
            0x10, 0x26,
        ]);
        a.bytes(&[
            0x9F, 0x10, 0x54, 0x00, 0x00, 0x04, 0x18, 0x00, 0x50, 0x06, 0x0B, 0x00,
        ]);
        a.bytes(&[
            0x9F, 0x20, 0x54, 0x02, 0x00, 0x00, 0x10, 0x00, 0x50, 0x06, 0x0B, 0x00,
        ]);
        for r in 0..64 {
            a.imm(0, r);
        }
        a.bytes(&[
            0x97, 0x05, 0x54, 0x04, 0x00, 0x08, 0x00, 0x00, 0xD0, 0x40, 0x10, 0x00,
        ]);
        a.bytes(&[
            0x57, 0x10, 0x54, 0x00, 0x00, 0x00, 0x00, 0x80, 0xA8, 0x75, 0x00, 0x00,
        ]);
        a.stop();
    }
    G15RdProgs {
        bg: (0xFFFF_8000_0000_0040, bg_entry),
        eot: (0, eot_entry),
        vdm: None,
    }
}

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: end-to-end self-test of the guest→firmware command path, run
    /// by `init()` after the init message. Submits one ForceConfigSnapshot
    /// record on the special control ring the way the kext's
    /// `submitCmdFirmwareForceConfigSnapshot` does (the 56 B entry
    /// `{0x13, zeros}`, flags 1 = doorbell, no completion wait): the record
    /// into slot 0, the write-index word (the kext's `setWriteIndex`), then
    /// the device-control doorbell. The firmware's consumer runs only on a
    /// doorbell event, so the doorbell is re-sent every 500 ms while the
    /// read-index word stays 0. The 0x13 handler is firmware-internal
    /// bookkeeping (it refreshes the chip-config snapshot; no GPU kick), so
    /// it is safe to send unconditionally. A failure is logged, not fatal.
    /// spec: agx-g15c/channel.md (the control-ring path).
    pub(crate) fn g15_control_selftest(&self) {
        const ENTRY: usize = 0x38;
        const WAIT_MS: u32 = 2000;
        const RING_MS: u32 = 500;
        let dev = self.dev.as_ref();
        let storage = self.initdata.special_ring.raw_ptr();
        let ring = self.initdata.ring_area.raw_ptr();

        // SAFETY: slot 0 is in bounds of the 0x3800 storage and both index
        // words are in bounds of the 128 KiB ring region. The memory is
        // firmware-shared and no slice view of it is live, so every access
        // is a volatile one through the raw pointer.
        unsafe {
            for i in 0..ENTRY {
                storage.add(i).write_volatile(0);
            }
            storage.cast::<u32>().write_volatile(0x13);
            core::sync::atomic::fence(Ordering::Release);
            ring.add(fw::g15::RING_SPECIAL_DOORBELL_OFF)
                .cast::<u32>()
                .write_volatile(1);
        }
        // SAFETY: as above; read-only.
        let read_index = || unsafe {
            (ring.add(fw::g15::RING_REGION2_OFF + 0xC0) as *const u32).read_volatile()
        };

        let mut last = 0;
        let mut waited = 0;
        while waited < WAIT_MS {
            if waited % RING_MS == 0 {
                if let Err(e) = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL) {
                    dev_err!(dev, "G15 control self-test: doorbell refused ({:?})\n", e);
                    return;
                }
            }
            last = read_index();
            if last > 0 {
                break;
            }
            kernel::time::delay::fsleep(Delta::from_millis(1));
            waited += 1;
        }

        if last > 0 {
            dev_info!(
                dev,
                "G15 control self-test: OK (read index {:#x} after ~{} ms)\n",
                last,
                waited
            );
        } else {
            dev_err!(
                dev,
                "G15 control self-test: TIMEOUT (read index still 0 after {} ms)\n",
                WAIT_MS
            );
        }
    }

    /// G15: the first GPU jobs — two no-launch compute jobs on one channel
    /// (spec: agx-g15c/cl-job.md, "The no-launch compute container" and
    /// "Successive jobs on one channel"). The first is submitted inside the
    /// GPU's idle power-down, the second right after the first completes.
    pub(crate) fn g15_compute_selftest(&self) {
        const JOBS: u32 = 2;
        const WAIT_MS: u32 = 5000;
        const RING_MS: u32 = 500;
        const CL_RING: usize = fw::g15::ring(2);
        let dev = self.dev.as_ref();
        let mut ch = match self.g15_cl_channel_new() {
            Ok(ch) => ch,
            Err(e) => {
                dev_err!(dev, "G15 compute self-test: channel alloc {e:?}\n");
                return;
            }
        };
        let ring = self.initdata.ring_area.raw_ptr();
        // SAFETY: read-only, in-bounds of the ring region.
        let read_index = || unsafe {
            (ring.add(fw::g15::RING_REGION2_OFF + 16 * CL_RING) as *const u32).read_volatile()
        };
        let words = ch.words.raw_ptr() as *const u32;
        let mut jobs = KVec::new();
        for _ in 0..JOBS {
            let mut job = match self.g15_cl_job_new(&ch, None, 1, &[]) {
                Ok(j) => j,
                Err(e) => {
                    dev_err!(dev, "G15 compute self-test: job alloc {e:?}\n");
                    break;
                }
            };
            if ch.submitted == 0 {
                // Submit 100 ms after the control self-test, inside the
                // GPU's idle power-down, where a doorbell can be missed
                // (the job then runs on the re-ring; boots #87-#89, #92).
                kernel::time::delay::fsleep(Delta::from_millis(100));
                // Lab diagnostic: the firmware's state before the jobs.
                g15_fwdump(0);
            }
            let js = job.job_state.gpu_va().get();
            // A submission in progress (the kext's updateSubmitInProgress):
            // the firmware holds off its idle power-down while it is set.
            self.initdata
                .pb_table
                .with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
            if let Err(e) = self.g15_cl_submit(&mut ch, &mut job) {
                dev_err!(
                    dev,
                    "G15 compute self-test: job {} doorbell refused ({e:?})\n",
                    job.n
                );
            }
            dev_info!(
                dev,
                "G15 compute self-test: job {} submitted (job-state {js:#x}, stamp {:#x})\n",
                job.n,
                job.stamp
            );
            let mut waited = 0;
            while waited < WAIT_MS && !self.g15_cl_done(&ch, job.stamp) {
                kernel::time::delay::fsleep(Delta::from_millis(1));
                waited += 1;
                if waited % RING_MS == 0 {
                    // The re-ring: a doorbell lost in the power-down.
                    if let Err(e) = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(2)) {
                        dev_err!(dev, "G15 compute self-test: doorbell refused ({e:?})\n");
                        break;
                    }
                }
                if job.n == 1 && waited == 100 {
                    // Lab diagnostic: after the first doorbell (fwdump-2).
                    g15_fwdump(2);
                }
            }
            self.initdata
                .pb_table
                .with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
            // SAFETY: in-bounds u32 reads of the channel's own stamp words.
            let (host, fwst) = unsafe { (words.read_volatile(), words.add(1).read_volatile()) };
            let events = self.g15_completions.load(Ordering::Relaxed);
            let done = self.g15_cl_done(&ch, job.stamp);
            if done {
                dev_info!(dev, "G15 compute self-test: job {} COMPLETED after ~{waited} ms (host stamp {host:#x}, fw stamp {fwst:#x}, {events} completion event(s), ring read {:#x})\n", job.n, read_index());
            } else {
                dev_err!(dev, "G15 compute self-test: job {} TIMEOUT after {waited} ms (host stamp {host:#x}, fw stamp {fwst:#x}, {events} completion event(s), ring read {:#x})\n", job.n, read_index());
            }
            if jobs.push(job, GFP_KERNEL).is_err() || !done {
                break;
            }
        }
        // Let late notifications land before the second dump.
        kernel::time::delay::fsleep(Delta::from_millis(100));
        // Lab diagnostic: the firmware's state after the jobs (fwdump-1).
        g15_fwdump(1);
        // The firmware log of the jobs (posted with or without a 0x42).
        self.g15_drain_fw_rings();
        // Keep the channel and the jobs alive: the firmware's DAG root and
        // the notifier list reference them.
        match KBox::new(ch, GFP_KERNEL) {
            Ok(ch) => *self.g15_selftest.lock() = Some((ch, jobs)),
            Err(_) => dev_err!(dev, "G15 compute self-test: cannot keep the channel\n"),
        }
    }

    /// G15: a fixed parameter buffer as the kext leaves a fresh one after
    /// its first TA `prepare` (spec: render-job.md, "The parameter
    /// buffer"): every block created and published, the page list built,
    /// the PB descriptor-table entry loaded (`halLoadPBDesc`).
    /// The self-test's VM: the blocks' range and the 1 TiB window.
    pub(super) fn g15_rd_vm_new(&self) -> Result<G15RdVm> {
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

    /// Ring `job` alone (its own doorbell) and wait for it.
    pub(super) fn g15_rd_run(
        &self,
        name: &str,
        ch: &mut G15ClChannel,
        job: &G15RdJob,
        ring: usize,
        class: u32,
    ) -> Option<u32> {
        let pb = &self.initdata.pb_table;
        pb.with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
        if let Err(e) = self.g15_rd_submit(ch, job, ring, class, true) {
            dev_err!(
                self.dev.as_ref(),
                "G15 render self-test: {name} doorbell refused ({e:?})\n"
            );
        }
        let r = self.g15_rd_wait(name, ch, job.stamp, class);
        pb.with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
        r
    }

    /// G15: demo15's clear, in the self-test's VM (user VAs); the
    /// programs and their data as `g15_rd_write_clear`.
    pub(super) fn g15_rd_clear_progs(&self, pb: &mut G15RdVm) -> Result<G15RdClear> {
        let code = pb.ualloc.array_empty_tagged::<u8>(0x8000, b"SHDR")?;
        let data = pb.ualloc.array_empty_tagged::<u8>(0x8000, b"PDAT")?;
        let out = pb
            .hialloc
            .array_empty_tagged::<u8>((RT_W * RT_H * 4) as usize, b"OUTB")?;
        let (c, d) = (va(&code), va(&data));
        // SAFETY: fresh 0x8000 B code and data buffers and the target.
        let progs = unsafe {
            core::ptr::write_bytes(out.raw_ptr(), CLEAR_FILL, (RT_W * RT_H * 4) as usize);
            g15_rd_write_clear(code.raw_ptr(), c, data.raw_ptr(), d, va(&out))
        };
        dev_info!(
            self.dev.as_ref(),
            "G15 render self-test: clear programs at {c:#x}, data {d:#x}, target {:#x}\n",
            va(&out)
        );
        Ok(G15RdClear {
            progs,
            _code: code,
            _data: data,
            out,
        })
    }

    /// One buffer of the self-test's VM at a fixed VA: its own allocator
    /// over [`at`, `at` + `size` + a guard page).
    pub(super) fn g15_rd_fixed(
        &self,
        vm: &mmu::Vm,
        at: u64,
        size: usize,
        tag: &[u8; 4],
    ) -> Result<(fw::types::GpuArray<u8>, alloc::DefaultAllocator)> {
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
            dev_err!(
                self.dev.as_ref(),
                "G15 render self-test: {at:#x} allocated at {:#x}\n",
                va(&b)
            );
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
    pub(super) fn g15_rd_tri(&self, pb: &G15RdVm) -> Result<G15RdTri> {
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
            core::ptr::copy_nonoverlapping(
                TRI_FS.as_ptr(),
                fsb.0.raw_ptr().add(0x4C0),
                TRI_FS.len(),
            );
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
            let mut a = Asm {
                p: c.add(0x480),
                off: 0,
            };
            a.bytes(&[0x0C, 0xDD, 0x10, 0x06]); // get_sr r0
            a.wait(0);
            a.bytes(&[
                0x67, 0x10, 0x44, 0, 0, 0x80, 0x20, 0, 0x5D, 0x01, 0, 0x40, 0x40, 0,
            ]);
            a.wait(5);
            a.bytes(TRI_VS_FFMA);
            for i in 0..4u8 {
                a.bytes(&[
                    0x57,
                    6 | 0x10 << i,
                    0x54,
                    6 - 2 * i,
                    0x20 * i,
                    0x40,
                    0x48 + i,
                    0,
                ]);
            }
            a.stop();

            let (pv, rot) = (TRI_DATA + 0x100, TRI_MATRIX + 0x100 + 0x8000);
            let mut a = Asm {
                p: c.add(0x4000),
                off: 0,
            };
            a.imm(pv as u32, 2);
            a.imm((pv >> 32) as u32, 3);
            a.imm(rot as u32, 18);
            a.imm((rot >> 32) as u32, 19);
            a.bytes(&[
                0x67, 0, 0x54, 0x20, 0x02, 0, 0, 0, 0x59, 0, 0, 0x40, 0x26, 0,
            ]);
            for (i, m) in [0x3Cu8, 0x34, 0x2C, 0x24].iter().enumerate() {
                let i = i as u8;
                a.bytes(&[
                    0x67,
                    0,
                    0x54,
                    *m,
                    0x12,
                    0,
                    0,
                    0,
                    0x57,
                    if i == 3 { 4 } else { 0 },
                    6 - 2 * i,
                    0x50,
                    0x26,
                    0,
                ]);
            }
            a.load_shader(vs, 1);
            a.bytes(&[
                0x06, 0x00, 0xF7, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ]);
            a.mov_u_r(0, 16);
            a.mov_u_r(1, 17);
            for i in 4..20 {
                a.mov_u_r(i, i + 14);
            }
            a.stop();

            let mut a = Asm {
                p: c.add(0x3000),
                off: 0,
            };
            a.bytes(&[0x77, 0x00, 0x2A, 0x43, 0x4B, 0x00, 0x00, 0x00]);
            a.load_shader(TRI_FS_BLOCK + 0x4C0, 1);
            a.bytes(&[0x04, 0x00]);
            a.imm(0, 1);
            a.bytes(&[0x14, 0x81, 0x11, 0x06, 0, 0, 0, 0]); // get_sr
            a.imm(0x100, 0);
            a.bytes(&[0x9F, 0x11, 0x54, 0x00, 0x02, 0x00, 0x08, 0xA8, 0x10, 0x05]); // iadd
            a.imm(0x100, 1);
            a.bytes(&[
                0x0F, 0x12, 0x54, 0x00, 0x4C, 0x00, 0x07, 0x02, 0x54, 0xF3, 0x02, 0x00,
            ]);
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
    pub(crate) fn g15_render_selftest(&self) {
        let dev = self.dev.as_ref();
        let run = || -> Result<G15RenderTest> {
            let (mut ta, mut d3) = self.g15_rd_chans_new()?;
            let mut rdvm = self.g15_rd_vm_new()?;
            let pb = self.g15_pb_new(&mut rdvm.ualloc, PB_ID, None)?;
            let cmd = G15RdCmd::test()?;
            let rt = self.g15_rt_new(&cmd.geom, &mut None)?;
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
            let tj = self.g15_ta_job_new(
                &ta,
                &pb,
                &rt,
                ctx,
                0x1001,
                0x21,
                0,
                solo(d3.stamp_index, 0x100),
                true,
                &cmd,
            )?;
            let dj = self.g15_3d_job_new(&d3, &pb, &rt, ctx, 0x1002, 0x22, 0, solo(0, 0), &cmd)?;
            g15_fwdump(4);
            let ok = self
                .g15_rd_run("pass 1 TA", &mut ta, &tj, TA_RING, 0)
                .is_some()
                && self
                    .g15_rd_run("pass 1 3D", &mut d3, &dj, D3_RING, 1)
                    .is_some();
            jobs.push(tj, GFP_KERNEL)?;
            jobs.push(dj, GFP_KERNEL)?;
            g15_fwdump(5);

            // Pass 2: one submission. Pass 3: a clear (background and
            // end-of-tile programs).
            let mut ok = ok;
            if ok {
                ok = self.g15_rd_linked(
                    "pass 2",
                    &mut ta,
                    &mut d3,
                    &pb,
                    &rt,
                    ctx,
                    0x1003,
                    1,
                    &cmd,
                    &mut jobs,
                    &mut notifiers,
                )?;
            }
            if ok {
                let clear = self.g15_rd_clear_progs(&mut rdvm)?;
                ok = self.g15_rd_linked(
                    "pass 3",
                    &mut ta,
                    &mut d3,
                    &pb,
                    &rt,
                    ctx,
                    0x1005,
                    2,
                    &cmd.with_progs(&clear.progs),
                    &mut jobs,
                    &mut notifiers,
                )?;
                let (hit, untouched, px) = g15_rd_check(&clear.out);
                dev_info!(dev, "G15 render self-test: clear: {hit}/{} pixels {CLEAR_PIXEL:#010x}, {untouched} untouched; pixels 0, 1, (40, 33), (32, 32), last: {:#010x} {:#010x} {:#010x} {:#010x} {:#010x}\n",
                          RT_W * RT_H, px[0], px[1], px[2], px[3], px[4]);
                clears.push(clear, GFP_KERNEL)?;
            }
            // Pass 4: demo15's quad.
            let mut tris = KVec::new();
            if ok {
                let tri = self.g15_rd_tri(&rdvm)?;
                self.g15_rd_linked(
                    "pass 4",
                    &mut ta,
                    &mut d3,
                    &pb,
                    &rt,
                    ctx,
                    0x1007,
                    3,
                    &cmd.with_progs(&tri.progs),
                    &mut jobs,
                    &mut notifiers,
                )?;
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
