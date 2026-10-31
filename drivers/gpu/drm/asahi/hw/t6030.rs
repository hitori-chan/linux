// SPDX-License-Identifier: GPL-2.0-only

//! Hardware configuration for t6030 platforms (M3 Pro, 14 or 18 GPU cores,
//! G15S; boards j514s and j516s). Not run: no such Mac.
//!
//! macOS drives it with `AGXG15S`, built from G15C's sources for core 0x17
//! (14.8.3): its firmware data drops G15C's second sensor-mask words and
//! the upper halves of the 128-sensor arrays (`fw::g15::HWDATA_A_G15S`,
//! `PB_TABLE_G15S`, `FMC_MAGIC_G15S`), `readChipInfo` enables no CS or AFR
//! tables, and `configureDevice` builds the register windows from t6030's
//! addresses. The rest is t6034's.
//!
//! Spec: chip-config.md, hwdata-a.md, kext.md, mmio.md.
use super::*;

pub(crate) const HWCONFIG: super::HwConfig = HwConfig {
    chip_id: 0x6030,
    gpu_variant: GpuVariant::S,
    gpu_core: GpuCore::G15S,

    // readChipInfo: core 0x17 has 20 cores (cfg+0x40), 10 a cluster.
    max_num_clusters: 2,
    max_num_cores: 10,

    has_csafr: false,
    // MtrPolynomGFX is not known for t6030: the hotspot sensors, which an
    // MTR alarm must at least match (power.md). An estimate.
    mtr_sensor_mask: [0x402a_002b, 0],
    // getGPUHotspotSensorMask, core 0x17
    hotspot_sensor_mask: [0x402a_002b, 0],
    g15_windows: Some(&WINDOWS),
    aon_ptd: &[],
    ..super::t6034::HWCONFIG
};

/// `AGXG15S`'s `configureDevice` (the base and G15X versions, core 0x17).
/// The main window is the ADT's sgx reg[0] (bus 0x80000000, CPU
/// 0x290000000 through arm-io's first range) and the Fender block reg[1].
pub(super) const WINDOWS: [G15Window; 31] = {
    let mut w = super::t6034::WINDOWS;
    // j=0 FenderRegs
    w[0] = G15Window::mapped(0x290d00000, 0x144000, 1);
    // j=2 AICSWIntRegs
    w[2] = G15Window::mapped(0x351014000, 0x4000, 1);
    // j=3 RGXRegs
    w[3] = G15Window::mapped(0x290000000, 0x20000, 1);
    // j=7 AnalogTempSensorControllerRegs (core 0x17)
    w[7] = G15Window::mapped(0x3502bc000, 0x4000, 0);
    // j=9 MetrologySensorRegs: main + 0xe08000
    w[9] = G15Window::mapped(0x290e08000, 0x8000, 1);
    // j=11 MCache registers: two windows, size (1 << s) + 0x94fff & -(1 << s)
    w[11] = G15Window {
        flag: 1,
        kind: 2,
        base: 0x220000000,
        size: 0x98000,
        pairs: &[0x222000000],
    };
    // j=12 AICBankedRegisters
    w[12] = G15Window::mapped(0x35104c000, 0x4000, 0);
    // j=18..20 PushTelemetryDashboard (…/…Read/…Config)
    w[18] = G15Window::mapped(0x3503d0000, 0x4000, 1);
    w[19] = G15Window::mapped(0x3503c0000, 0x4000, 0);
    w[20] = G15Window::mapped(0x3503d8000, 0x4000, 1);
    // j=21 AFRClkGenRegs and j=24 GFXCAXI2AFRegs are core 0x18's
    w[21] = G15Window::none();
    w[24] = G15Window::none();
    // j=23 AFRRegs (core 0x17): main + 0x3000000, size (1 << s) + 0x3fffff
    // & -(1 << s)
    w[23] = G15Window::mapped(0x293000000, 0x400000, 1);
    // j=25 ANE0Doorbell (core 0x17)
    w[25] = G15Window::mapped(0x30945c000, 0x4000, 1);
    // j=26 PMSMetrologySensorRegs
    w[26] = G15Window::mapped(0x350280000, 0x8000, 0);
    // j=28 AONPTDSpace is core 0x18's
    w[28] = G15Window::none();
    // j=29 GFXCLKGEN_MGPU: main + 0xe5c000
    w[29] = G15Window::mapped(0x290e5c000, 0x4000, 0);
    w
};
