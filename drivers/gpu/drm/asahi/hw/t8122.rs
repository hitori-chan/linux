// SPDX-License-Identifier: GPL-2.0-only

//! Hardware configuration for t8122 platforms (M3, 8 or 10 GPU cores,
//! G15G; boards j433, j434, j504, j613, j615). Not run: no such Mac.
//!
//! macOS drives it with `AGXG15G` (14.8.3), whose chip class is
//! `AGXAcceleratorG15G`, not G15X: its HwDataA and power block are G15S's,
//! its HwDataB drops 8 bytes (`fw::g15::HWDATA_B_G15G`), its accelerator
//! rings are in RAM, its DPE configs are filled and its job lists carry no
//! multi-cluster registers. The windows are built from t8122's addresses.
//!
//! Spec: g15g.md, g15s.md, mmio.md.
use super::*;

pub(crate) const HWCONFIG: super::HwConfig = HwConfig {
    chip_id: 0x8122,
    gpu_variant: GpuVariant::G,
    gpu_core: GpuCore::G15G,

    // readChipInfo: core 0x16 has 10 cores (cfg+0x40), one cluster.
    max_num_clusters: 1,
    max_num_cores: 10,

    // MtrPolynomGFX is not known for t8122: the hotspot sensors, which an
    // MTR alarm must at least match (power.md). An estimate.
    mtr_sensor_mask: [0x4248, 0],
    // populateSoCHotConfigData, populateFastDieDeviceConfigData
    hotspot_sensor_mask: [0x4248, 0],
    // 85.0 degrees: 110.0 only with /arm-io process-node 4, which no
    // t8122 ADT here has.
    fastdie_target: 8500,
    g15_windows: Some(&WINDOWS),
    ..super::t6030::HWCONFIG
};

/// `AGXG15G`'s `configureDevice` (the base, `AGXAcceleratorG15` and
/// `AGXAcceleratorG15G` versions). t8122's arm-io maps bus 0 to CPU
/// 0x2_1000_0000, as t6030's: the main window is the ADT's sgx reg[0]
/// (0x290000000) and the Fender block reg[1] (0x290d00000).
const WINDOWS: [G15Window; 31] = {
    let mut w = super::t6030::WINDOWS;
    // j=0 FenderRegs (the G15 size)
    w[0] = G15Window::mapped(0x290d00000, 0x104000, 1);
    // j=2 AICSWIntRegs: the page of the ADT's meta-sw-interrupt
    w[2] = G15Window::mapped(0x2d1014000, 0x4000, 1);
    // j=7 TempSensorRegs and j=12 AICBankedRegisters are unused
    w[7] = G15Window::none();
    w[12] = G15Window::none();
    // j=10 GMGIFAFRegs: main + 0xd0d000
    w[10] = G15Window::mapped(0x290d0d000, 0x1000, 1);
    // j=11 MCache registers: two windows, size (1 << s) + 0x54fff & -(1 << s)
    w[11] = G15Window {
        flag: 1,
        kind: 2,
        base: 0x220000000,
        size: 0x58000,
        pairs: &[0x222000000],
    };
    // j=18/19 PushTelemetryDashboard (…/…Read); no …Config
    w[18] = G15Window::mapped(0x2d03d0000, 0x1000, 1);
    w[19] = G15Window::mapped(0x2d03c0000, 0x2000, 0);
    w[20] = G15Window::none();
    // j=23 AFRRegs is core 0x17's
    w[23] = G15Window::none();
    // j=25 ANE0Doorbell
    w[25] = G15Window::mapped(0x31145c000, 0x4000, 1);
    // j=26 PMSMetrologySensorRegs
    w[26] = G15Window::mapped(0x2d0280000, 0x8000, 0);
    // j=29 GFXCLKGEN_MGPU: GMGIFAF + 0x10f000
    w[29] = G15Window::mapped(0x290e1c000, 0x4000, 0);
    w
};
