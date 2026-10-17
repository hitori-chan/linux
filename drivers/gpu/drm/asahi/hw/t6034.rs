// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Hardware configuration for t6034 platforms (M3 Max 14-core, 30 GPU
//! cores, G15C; boards j514m/j516m, this Mac is j514map/Mac15,10).
//!
//! Known values come from the 14.8.3 (V14_7) AGXG15C kext analysis
//! (`spec/agx-g15c/`): the `kAGXGPUCoreName` table (G15C = core 24),
//! `configureDevice` (MMIO windows, 6 MCache windows on G15C, core ID
//! check 0x17/0x18), `initFirmwareData` (HwDataB constants) and
//! `readChipInfo` (1 die, the rest from the ID registers). The SoC is the
//! 14-core M3 Max variant (the public tree's `t6034.dtsi` includes
//! `t6031.dtsi` and disables the extra memory channels); the 40-core
//! variant is t6031 (boards j514c/j516c).
//!
use crate::f32;

use super::*;

pub(crate) const HWCONFIG: super::HwConfig = HwConfig {
    // The SoC number: the kext's G15C branch tests getChipId() == 0x6034
    // (DT `/chosen chip-id`; the static ADT has 0, so L2 confirms live).
    // Goes to the firmware in HwDataB.
    chip_id: 0x6034,
    gpu_gen: GpuGen::G15,
    gpu_variant: GpuVariant::C,
    gpu_core: GpuCore::G15C,

    // initFirmwareData (Arm): HwDataB+0xa68 = 0x5dc0 (kHz) = 24 MHz
    base_clock_hz: 24_000_000,
    // Traced 2026-10-08 in AGXSharedGartTableBackingG15::initGartInfo: 3
    // levels, 16 KiB GART pages (shift 14), index masks [41:36]/[35:25]/
    // [24:14] -> 42-bit OAS. (spec/agx-g15c/gart.md)
    uat_oas: 42,
    // readChipInfo: G15C requires num dies != 0; M3 Max = 1 die
    num_dies: 1,
    // The live ID_COUNTS_1 (0x0021040a): 4 clusters x 10 cores, 30 of
    // the 40 enabled (spec/agx-g15c/gpu-id.md)
    max_num_clusters: 4,
    max_num_cores: 10,
    // TODO(M0): frags/GPs per cluster not yet read (ID_COUNTS_2)
    max_num_frags: 8,
    max_num_gps: 4,

    // TODO: preemption buffer sizes not yet decoded for G15 (from G14X)
    preempt1_size: 0x540,
    preempt2_size: 0x280,
    preempt3_size: 0x20,
    compute_preempt1_size: 0x10000,
    clustering: None,

    render: HwRenderConfig {
        // TODO: tiling control not yet sourced for G15 (from G14X)
        tiling_control: 0xa041,
    },

    // TODO: HwDataA/B values from the 14.8.3 populator, not yet mapped
    // (placeholder from G14X)
    da: HwConfigA {
        unk_87c: 900,
        unk_8cc: 11000,
        unk_e24: 125,
    },
    db: HwConfigB {
        unk_454: 1,
        unk_4e0: 4,
        unk_534: 0,
        unk_ab8: 0x2048,
        unk_abc: 0x4000,
        unk_b30: 1,
    },
    // TODO: shared tables from the 14.8.3 init data (placeholder from G14X)
    shared1_tab: &[
        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    ],
    shared1_a4: 0,
    shared2_tab: &[-1, -1, -1, -1, -1, -1, -1, -1, 0xaa5aa, 0],
    shared2_unk_508: 0xc00000,
    shared2_curves: Some(HwConfigShared2Curves {
        t1_coef: 7200,
        t2: &[
            0xf07, 0x4c0, 0x6c0, 0x8c0, 0xac0, 0xc40, 0xdc0, 0xec0, 0xf80,
        ],
        t3_coefs: &[0, 20, 28, 36, 44, 50, 56, 60, 63],
        t3_scales: &[9, 3209, 10400],
    }),
    shared3_unk: 5,
    shared3_tab: &[
        10700, 10700, 10700, 10700, 10700, 6000, 1000, 1000, 1000, 10700, 10700, 10700, 10700,
        10700, 10700, 10700,
    ],
    idle_off_standby_timer_default: 0,
    unk_hws2_4: None,
    unk_hws2_24: 0,
    global_unk_54: 0xffff,

    // TODO: SRAM / sensor data from the 14.8.3 kext (placeholder from G14X)
    sram_k: f32!(1.02),
    unk_coef_a: &[&f32!([0.0, 0.0, 0.0, 0.0, 5.3, 0.0, 5.3, 5.3])],
    unk_coef_b: &[&f32!([0.0, 0.0, 0.0, 0.0, 5.3, 0.0, 5.3, 5.3])],
    global_tab: None,
    // readChipInfo sets cfg+0x75/0x76 for G15C: chip+0x4e5/0x4e6, the
    // CS and AFR perf-state tables (spec: chip-config.md)
    has_csafr: true,
    fast_sensor_mask: [0x6800, 0],
    fast_sensor_mask_alt: [0x6800, 0],
    fast_die0_sensor_present: 0x02,
    // G15 uses the register-window table below, not the M1 io_mappings
    // layout (the G15 HwDataB publishes the windows at 0x640/0x648+j*8;
    // spec/agx-g15c/alloc.md + hwdata-b.md).
    io_mappings: &[],
    // The 31-entry register-window table (chip+0x6d0, 0x98 stride), from
    // configureDevice (base + G15X override) for t6034/G15C
    // (spec/agx-g15c/alloc.md). The ADT's sgx regs are bus addresses (bus 0
    // -> CPU 0x2_0000_0000): main = reg[0] at CPU 0x408000000 (RGXRegs and
    // the main-relative windows at 0x408…/0x409…), Fender = reg[1] at CPU
    // 0x408d00000 (the probe's index selection for a two-entry reg). The
    // ID registers and the MRRs live in the Fender block (live with GFX on:
    // Fender+0x4000 = 0x07041100, +0x440a0 = 0x5ed7f4ff).
    g15_windows: Some(&[
        // j=0 FenderRegs: the whole Fender window (G15X size override)
        G15Window::mapped(0x408d00000, 0x144000, 1),
        // j=1 AICTimerRegs: the base code's constant 0x20e101000 masked to
        // the page (configureDevice: `-1 << page_shift & 0x20e101000`)
        G15Window::mapped(0x20e100000, 0x4000, 0),
        // j=2 AICSWIntRegs
        G15Window::mapped(0x292414000, 0x4000, 1),
        // j=3 RGXRegs: the main window's first 0x20000
        G15Window::mapped(0x408000000, 0x20000, 1),
        // j=4 UVDRegs: the kext writes a garbage base (a masked provider
        // pointer) — effectively dead; the driver uses base 0
        G15Window { flag: 1, kind: 0, base: 0, size: 0x4000, pairs: &[] },
        // j=5 unused
        G15Window::none(),
        // j=6 DisplayUnderrunWA (flag set, no window)
        G15Window { flag: 1, kind: 0, base: 0, size: 0, pairs: &[] },
        // j=7 AnalogTempSensorControllerRegs (core 0x18): size
        // (1 << s) + 0xfff & -(1 << s)
        G15Window::mapped(0x290444000, 0x4000, 0),
        // j=8 PMPDoorbell
        G15Window { flag: 1, kind: 0, base: 0, size: 0, pairs: &[] },
        // j=9 MetrologySensorRegs: main + 0xe08000
        G15Window::mapped(0x408e08000, 0x8000, 1),
        // j=10 GM GIFAF
        G15Window { flag: 1, kind: 0, base: 0, size: 0, pairs: &[] },
        // j=11 MCache registers (G15C): kind 6, the six window PAs
        // 0x220000000 + i*0x2000000 (i = 0..5) go into the PIO buffer
        G15Window {
            flag: 1,
            kind: 6,
            base: 0x220000000,
            size: 0xd8000,
            pairs: &[
                0x222000000, 0x224000000, 0x226000000, 0x228000000, 0x22a000000,
            ],
        },
        // j=12 AICBankedRegisters
        G15Window::mapped(0x29244c000, 0x4000, 0),
        // j=13 PMGRScratch
        G15Window { flag: 1, kind: 0, base: 0, size: 0, pairs: &[] },
        // j=14/15 NIA special-agent idle registers, die 0/1
        G15Window { flag: 1, kind: 0, base: 0, size: 0, pairs: &[] },
        G15Window { flag: 1, kind: 0, base: 0, size: 0, pairs: &[] },
        // j=16/17 CRE / streaming codec
        G15Window::none(),
        G15Window::none(),
        // j=18..20 PushTelemetryDashboard (…/…Read/…Config)
        // (only the Read window is read-only)
        G15Window::mapped(0x2903d0000, 0x4000, 1),
        G15Window::mapped(0x2903c0000, 0x4000, 0),
        G15Window::mapped(0x2903d8000, 0x4000, 1),
        // j=21 AFRClkGenRegs: main + 0xeb4000 (core 0x18), size
        // (1 << s) + 0x1fff & -(1 << s)
        G15Window::mapped(0x408eb4000, 0x4000, 1),
        // j=22/23 unused
        G15Window::none(),
        G15Window::none(),
        // j=24 GFXCAXI2AFRegs: main + 0x1000000 (core 0x18), size
        // (1 << s) + 0x7fff & -(1 << s)
        G15Window::mapped(0x409000000, 0x8000, 1),
        // j=25 ANE0Doorbell (core 0x18)
        G15Window::mapped(0x3c945c000, 0x4000, 1),
        // j=26 PMSMetrologySensorRegs
        G15Window::mapped(0x290400000, 0x8000, 0),
        // j=27 unused
        G15Window::none(),
        // j=28 AONPTDSpace (core 0x18)
        G15Window::mapped(0x2a4dc0000, 0x24000, 0),
        // j=29 GFXCLKGEN_MGPU: main + 0xe1c000
        G15Window::mapped(0x408e1c000, 0x4000, 0),
        // j=30 unused
        G15Window::none(),
    ]),
    // The ADT's ptd_data_table rows for the identifiers the kext looks up
    // (RT0g…RT3g, RT0r, RT0f; the table has 91 rows).
    aon_ptd: &[
        aon_ptd_row(b"RT0g", 171, 1, 20),
        aon_ptd_row(b"RT1g", 141, 1, 20),
        aon_ptd_row(b"RT2g", 139, 1, 20),
        aon_ptd_row(b"RT3g", 173, 1, 20),
        aon_ptd_row(b"RT0r", 235, 1, 20),
        aon_ptd_row(b"RT0f", 203, 1, 22),
    ],
    sram_base: None,
    sram_size: None,
};

/// An AON PTD row with version 1, no entry IRQ and no features.
const fn aon_ptd_row(id: &[u8; 4], start: u16, size: u8, irq: u8) -> [u8; 12] {
    let st = start.to_le_bytes();
    [id[0], id[1], id[2], id[3], 1, 0, st[0], st[1], size, irq, 0, 0]
}
