// SPDX-License-Identifier: GPL-2.0-only

//! G15 firmware init-data structures: macOS 14.8.3's layouts that 27.2's
//! (`super::g15_272`) build on.
//!
//! The G15 firmware takes no monolithic init block as M1/M2 do: it takes a
//! set of separate buffers, whose addresses the channel table and the FMC
//! channel header publish. The layouts are those macOS 14.8.3's
//! `initFirmwareData` (base and Arm), `initPowerAndPerformanceData`,
//! `initFirmwareSharedData` and `initSoftFaultSettings` write. A field's
//! name carries its offset, and the compile-time asserts at the bottom pin
//! the sizes and offsets.
//!
//! Fields marked "chip" are properties of macOS's chip object
//! (`AGXAcceleratorG15X`; the driver's counterpart is `hw/t6034.rs`).
//! Fields whose source is not decoded are left zero.
//!
//! Spec: alloc.md, channel-table.md, hwdata-a.md, hwdata-b.md, initdata.md,
//! pb-table.md.

use super::types::{GpuStruct, Pad, U64};
use crate::default_zeroed;
use crate::float::F32;

/// The ring area's layout. macOS keeps the 13 rings' index words and
/// storages in the Fender scratch, 128 KiB of shared SRAM. The driver backs
/// the same layout with a 128 KiB firmware non-cacheable buffer and
/// publishes its addresses in the channel table:
///
/// - region 1 (first 0x14000): the doorbells and storages of all 13 rings.
///   Ring `k`'s doorbell u32 is at `k * RING_STRIDE`, its 0x1800 storage at
///   `k * RING_STRIDE + 8` (12 command rings; the 13th ring's storage is a
///   separate 0x3800 DMA buffer).
/// - region 2 (0xC000, at +0x14000): the read/CFI index words. Ring `k`'s
///   read u32 is at `16k`, its CFI u32 at `16k + 8`.
///
/// The 13th ring, the special control ring of 0x38-byte entries: read 0xC0,
/// CFI 0xC8, doorbell 12 * RING_STRIDE = 0x12060.
pub(crate) const RING_REGION_SIZE: usize = 0x20000;
pub(crate) const RING_REGION2_OFF: usize = 0x14000;
pub(crate) const RING_STRIDE: usize = 0x1808;
pub(crate) const RING_SPECIAL_DOORBELL_OFF: usize = 12 * RING_STRIDE;
/// The ring table has four rows (queues) of three rings, the TA, 3D and CL
/// rings of row `k` being rings `k`, `4 + k` and `8 + k`
/// (`AGXFirmware::initFirmwareData`). A channel's jobs go to the row of its
/// priority stage, as macOS's submit paths take the row from
/// `AGXChannel::getPriority`, the state's +0x30 (`G15Prio::row`).
/// The ring table's rows.
pub(crate) const ROWS: usize = 4;
/// The command rings: four rows of three classes.
pub(crate) const RINGS: usize = 12;
/// The ring of channel class `class` (0 TA, 1 3D, 2 CL) on row `row`.
pub(crate) const fn ring(row: usize, class: usize) -> usize {
    4 * class + row
}
/// The doorbell word of channel class `class` on row `row`: `row << 2 | class`.
pub(crate) const fn bell(row: usize, class: u64) -> u64 {
    ((row as u64) << 2) | class
}

/// One row of the channel table's ring table: the TA, 3D and CL rings of one
/// queue. Each ring takes four words: the firmware addresses of its read
/// index, its CFI index, its write index (the doorbell word) and its
/// storage.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct RingEntry {
    /// Ring `k`, the TA ring of queue `k` (`getReadIndexGPUPtr`,
    /// `getCFIIndexGPUPtr`, `getWriteIndexGPUPtr`, the 0x1800-byte
    /// storage).
    pub(crate) ta_read: U64,
    pub(crate) ta_cfi: U64,
    pub(crate) ta_write: U64,
    pub(crate) ta_storage: U64,
    /// Ring `4 + k`, the 3D ring of queue `k`.
    pub(crate) d3_read: U64,
    pub(crate) d3_cfi: U64,
    pub(crate) d3_write: U64,
    pub(crate) d3_storage: U64,
    /// Ring `8 + k`, the CL ring of queue `k`.
    pub(crate) cl_read: U64,
    pub(crate) cl_cfi: U64,
    pub(crate) cl_write: U64,
    pub(crate) cl_storage: U64,
}

/// FMC channel header, at the start of the FMC ring buffer
/// (`FMC = this+0x1600`, `buf = FMC->vtbl[0x138]()`), 0xc0 bytes.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct FmcHeader {
    /// +0x00 magic (`super::g15_272::FMC_MAGIC_V27_2`)
    pub(crate) magic: u64,
    /// +0x08 the ring2 GPU address: `AGXMemoryMap(this+0x1638)` vtbl
    /// 0x158 (identity on G15)
    pub(crate) ring2_fwva: U64,
    /// +0x10…+0x17 unwritten
    pad_0x10: Pad<8>,
    /// +0x18 `conv(channel table PA)`
    pub(crate) channel_table_fwva: U64,
    /// +0x20 `conv(PB table PA)`
    pub(crate) pb_table_fwva: U64,
    /// +0x28 constant 0x100000000
    pub(crate) const_0x28: U64,
    /// +0x30…+0x97 the GART table (`AGXSharedGartTableBackingG15::
    /// initGartInfo`): three 0x20-byte level records and a zero word, all
    /// constants for 16 KiB pages
    pub(crate) chip_a078: [U64; 13],
    /// +0x98…+0xa7 unwritten
    pad_0x98: Pad<0x10>,
    /// +0xa8 `conv(this+0x910)`
    pub(crate) buf_0x910_fwva: U64,
    /// +0xb0 `conv(this+0xa40)`: the 0xc3d0-byte firmware event page
    pub(crate) buf_0xa40_fwva: U64,
    /// +0xb8 `conv(this+0xa48)`: the 0x238-byte host/firmware power-control
    /// block, which the firmware's power task reads unchecked
    pub(crate) buf_0xa48_fwva: U64,
}

/// HwDataA, buffer `this+0x230` (VA) / `0x270` (PA), size 0x6e48.
///
/// Zeroed first, then populated by `initPowerAndPerformanceData` (base:
/// the 0…0x6c0 head; Arm: the 0xb58…0x1794 region plus the DPEPPT block at
/// 0x64c0). Only the base-pass head is field-decoded so far; the rest is
/// opaque, with the known sub-regions noted in the pads.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct HwDataA {
    /// +0x00…+0x03 unwritten
    pad_0x00: Pad<4>,
    /// +0x04 `chip->vtbl[0xe70]()` (written twice)
    pub(crate) vtbl_0xe70: u32,
    /// +0x08 `chip->vtbl[0xe70]()`
    pub(crate) vtbl_0xe70_2: u32,
    /// +0x0c…+0x13 constant (`qword_7109960` = 0x4_0000_0000, 8-byte
    /// `stur d0` at 0x8e6742c: 0 at +0x0c, 4 at +0x10)
    pub(crate) const_0x0c: [u32; 2],
    /// +0x14 1.0f (`MOV W8,#0x3F800000; STUR X8` at 0x8e67430; the high
    /// word is 0)
    pub(crate) const_0x14: f32,
    /// +0x18…+0x2b unwritten
    pad_0x18: Pad<0x14>,
    /// +0x2c…+0x33 two u32 of 1 (`MOVI V0.2S,#1` + `STUR D0` at
    /// 0x8e67438): the power code's perf-state indices (an index of
    /// 0xffffffff faults the firmware once isPIOSupported runs it)
    pub(crate) const_0x2c: [u32; 2],
    /// +0x34 zero
    pub(crate) zero_0x34: u32,
    /// +0x38…+0x3f unwritten
    pad_0x38: Pad<8>,
    /// +0x40…+0x4f the Arm override (`STP` at 0x8e872fc): 0,
    /// `chip+0x2848` = base·100, 1, `chip+0x27e0` = c34·100
    pub(crate) arm_0x40: [u32; 4],
    /// +0x50…+0x53 unwritten
    pad_0x50: Pad<4>,
    /// +0x54 100
    pub(crate) const_0x54: u32,
    /// +0x58…+0x5f unwritten
    pad_0x58: Pad<8>,
    /// +0x60…+0x1bf 0x160 bytes copied from the static config block
    /// (`this+0xa50`)
    pub(crate) static_config: [u8; 0x160],
    /// +0x1c0…+0x657 unwritten
    pad_0x1c0: Pad<0x498>,
    /// +0x658 `chip+0x27b0` = 0x271 (the Arm setupConfig)
    pub(crate) chip_0x27b0: u32,
    /// +0x65c zero
    pub(crate) zero_0x65c: u32,
    /// +0x660…+0x663 unwritten
    pad_0x660: Pad<4>,
    /// +0x664 (f−1)/f, f = float(`chip+0x27a0`)
    pub(crate) f_0x664: f32,
    /// +0x668…+0x66b unwritten
    pad_0x668: Pad<4>,
    /// +0x66c 1/f
    pub(crate) f_0x66c: f32,
    /// +0x670…+0x673 unwritten
    pad_0x670: Pad<4>,
    /// +0x674 `chip+0x27c4`
    pub(crate) chip_0x27c4: u32,
    /// +0x678…+0x67b unwritten
    pad_0x678: Pad<4>,
    /// +0x67c `float(chip+0x27c8)`, `float(chip+0x27cc)` (an 8-byte
    /// `vcvt_f32_s32` store: integral-min-clamp and the max power)
    pub(crate) chip_0x27c8: [F32; 2],
    /// +0x684 `chip+0x27d0`
    pub(crate) chip_0x27d0: u32,
    /// +0x688…+0x68b unwritten
    pad_0x688: Pad<4>,
    /// +0x68c `chip+0x27d4`
    pub(crate) chip_0x27d4: F32,
    /// +0x690 `chip+0x27d8`
    pub(crate) chip_0x27d8: u32,
    /// +0x694…+0x697 unwritten
    pad_0x694: Pad<4>,
    /// +0x698 `chip+0x27e0` (the "Power" controller parameter, also at
    /// +0x6d4)
    pub(crate) chip_0x27e0: u32,
    /// +0x69c…+0x69f unwritten
    pad_0x69c: Pad<4>,
    /// +0x6a0 zero
    pub(crate) zero_0x6a0: u32,
    /// +0x6a4 `chip+0x2798`
    pub(crate) chip_0x2798: u32,
    /// +0x6a8…+0x6cf unwritten
    pad_0x6a8: Pad<0x28>,
    /// +0x6d0 `chip+0x27f0`
    pub(crate) chip_0x27f0: u32,
    /// +0x6d4 `chip+0x27e0`
    pub(crate) chip_0x27e0_2: u32,
    /// +0x6d8 `chip+0x27f4`
    pub(crate) chip_0x27f4: u32,
    /// +0x6dc…+0x6ef unwritten (`chip+0x2800` at 0x788)
    pad_0x6dc: Pad<0x14>,
    /// +0x6f0 `chip+0x2638` = (ppm-tc-ms / sp) << 2
    pub(crate) perf_0x6f0: u32,
    /// +0x6f4 0
    pub(crate) perf_0x6f4: u32,
    /// +0x6f8…+0x6fb unwritten
    pad_0x6f8: Pad<4>,
    /// +0x6fc `chip+0x263c` = (f−1)/f (f = float(chip+0x2628))
    pub(crate) perf_0x6fc: F32,
    /// +0x700…+0x703 unwritten
    pad_0x700: Pad<4>,
    /// +0x704 `chip+0x2640` = 1/f
    pub(crate) perf_0x704: F32,
    /// +0x708…+0x70b unwritten
    pad_0x708: Pad<4>,
    /// +0x70c `chip+0x2674 ?: 0x264c` = f32(gpu-ppm-ki) × sp/1000 (0x2674
    /// never written)
    pub(crate) perf_0x70c: F32,
    /// +0x710…+0x713 unwritten
    pad_0x710: Pad<4>,
    /// +0x714 float(chip+0x2650/0x2654), an 8-byte SCVTF (0x8e86da0):
    /// gpu-pwr-integral-min-clamp (0 here) and float(0x10000)
    pub(crate) perf_0x714: [F32; 2],
    /// +0x71c `chip+0x2670 ?: 0x2658` = f32(gpu-ppm-kp) (0x2670 is 0)
    pub(crate) perf_0x71c: F32,
    /// +0x720…+0x723 unwritten
    pad_0x720: Pad<4>,
    /// +0x724 `chip+0x265c` (never written → 0)
    pub(crate) perf_0x724: u32,
    /// +0x728 `chip+0x2660/0x2664`, an 8-byte copy (0x8e86db4): c30 =
    /// u32(gpu-pwr-min-duty-cycle), c34·100
    pub(crate) perf_0x728: [u32; 2],
    /// +0x730 `chip+0x2668` (never written → 0)
    pub(crate) perf_0x730: u32,
    /// +0x734…+0x737 unwritten
    pad_0x734: Pad<4>,
    /// +0x738 0
    pub(crate) perf_0x738: u32,
    /// +0x73c `chip+0x266c ?: chip+0x2644` = P, the G15X max power
    pub(crate) perf_0x73c: u32,
    /// +0x740…+0x743 unwritten
    pad_0x740: Pad<4>,
    /// +0x744 `chip+0x262c` = u32(gpu-ppm-filter-time-constant-ms)
    pub(crate) perf_0x744: u32,
    /// +0x748…+0x74b unwritten
    pad_0x748: Pad<4>,
    /// +0x74c `chip+0x2630` (u64, 4-misaligned → [u32; 2]) = sp · (tc/sp) ·
    /// 0x5dc0
    pub(crate) perf_0x74c: [u32; 2],
    /// +0x754…+0x787 unwritten
    pad_0x754: Pad<0x34>,
    /// +0x788 `chip+0x2800` = gpu-perf-tgt-utilization (also at 0x7ec)
    pub(crate) perf_tgt_util: u32,
    /// +0x78c…+0x78f unwritten
    pad_0x78c: Pad<4>,
    /// +0x790 `chip+0x2804/0x2808` = gpu-perf-boost-min-util,
    /// gpu-perf-boost-ce-step
    pub(crate) perf_boost: [u32; 2],
    /// +0x798 `chip+0x280c` = gpu-perf-reset-iters (default 6)
    pub(crate) perf_reset_iters: u32,
    /// +0x79c…+0x79f unwritten
    pad_0x79c: Pad<4>,
    /// +0x7a0 `chip+0x2810` = 6
    pub(crate) chip_0x2810: u32,
    /// The "Performance" controller (`AGXFirmware::
    /// initPowerAndPerformanceData`, the getters reading the chip block
    /// `setupConfig` fills).
    /// +0x7a4 dual filter (`chip+0x2820` != 0)
    pub(crate) perf_dual_filter: u32,
    /// +0x7a8 `chip+0x281c` = gpu-perf-filter-drop-threshold
    pub(crate) perf_drop_threshold: u32,
    /// +0x7ac (f−1)/f and +0x7b4 1/f for the two time constants
    /// (`chip+0x2814/0x2818`)
    pub(crate) perf_tc_decay: [F32; 2],
    pub(crate) perf_tc_inv: [F32; 2],
    /// +0x7bc the integral gains (`chip+0x2824/0x2828`)
    pub(crate) perf_integral_gain: [F32; 2],
    /// +0x7c4 float(`chip+0x282c`), float(`chip+0x2830`): the integral
    /// min clamp and 95
    pub(crate) perf_clamp: [F32; 2],
    /// +0x7cc the proportional gains (`chip+0x2834/0x2838`)
    pub(crate) perf_proportional_gain: [F32; 2],
    /// +0x7d4 `chip+0x283c` = (c34 − base)·100 / `chip+0x2830`
    pub(crate) perf_0x7d4: F32,
    /// +0x7d8 `chip+0x2840/0x2844` = base·100, c34·100
    pub(crate) perf_0x7d8: [u32; 2],
    /// +0x7e0 `chip+0x2848` = base·100
    pub(crate) perf_0x7e0: u32,
    /// +0x7e4…+0x7e7 unwritten
    pad_0x7e4: Pad<4>,
    /// +0x7e8 0
    pub(crate) zero_0x7e8: u32,
    /// +0x7ec `chip+0x2800`
    pub(crate) perf_tgt_util_2: u32,
    /// +0x7f0…+0x817 unwritten
    pad_0x7f0: Pad<0x28>,
    /// +0x818 float(`chip+0x2850`) (no writer: 0)
    pub(crate) perf_0x818: F32,
    /// +0x81c `chip+0x2848` (u64)
    pub(crate) perf_0x81c: [u32; 2],
    /// +0x824…+0x837 unwritten
    pad_0x824: Pad<0xC>,
    /// +0x830 `getUMAPagePoolDescriptorTableGPUAddress` (no firmware
    /// reader found; the kext writes it)
    pub(crate) uma_desc_table: U64,
    /// +0x838…+0x85b the clock descriptor (firmware `this+0x197c…0x1994`,
    /// the Arm `setupConfig`): float(`this+0x1980`) = 65536.0,
    /// float(c30), float(c34·100), the top state's clock in MHz
    pub(crate) clock_0x838: F32,
    pub(crate) clock_0x83c: [F32; 2],
    pub(crate) clock_top_mhz: u32,
    pad_0x848: Pad<4>,
    /// +0x84c `this+0x1990 ?: this+0x197c` = 0
    pub(crate) clock_0x84c: u32,
    pad_0x850: Pad<4>,
    /// +0x854 c30 (`this+0x1984`), +0x858 `this+0x1994` = 0
    pub(crate) clock_0x854: u32,
    pub(crate) clock_0x858: u32,
    pad_0x85c: Pad<4>,
    /// +0x860 `getGPUMemoryThreshold()` = 100.0
    pub(crate) mem_threshold: F32,
    /// +0x864 c34·100
    pub(crate) perf_0x864: u32,
    /// +0x868 0
    pub(crate) zero_0x868: u32,
    /// +0x86c (f−1)/f, 1/f, f = gpu-perf-limiter-filter-time-constant
    /// (`fw+0xc88`, default 5)
    pub(crate) limiter_filter: [F32; 2],
    /// +0x874…+0x8ab unwritten (+0x8a8 = 0)
    pad_0x874: Pad<0x38>,
    /// +0x8ac…+0x943 the fast-die controller: `chip+0x21a0…0x2218` as the
    /// Arm `setupConfig` leaves them (temperatures in centi-°C). +0x8ac
    /// the MTR sensor mask (the G15X `populateFastDieDeviceConfigData`),
    /// +0x8bc the release temperature, +0x8c0 cfg+0x18·100, +0x8c4 4
    pub(crate) fastdie_sensor_mask: U64,
    pub(crate) fastdie_0x8b4: U64,
    pub(crate) fastdie_release_temp: u32,
    pub(crate) fastdie_0x8c0: u32,
    pub(crate) fastdie_0x8c4: u32,
    pad_0x8c8: Pad<8>,
    /// +0x8d0 0.0, +0x8d8 1.0 (`chip+0x21cc/0x21d0`)
    pub(crate) fastdie_0x8d0: F32,
    pad_0x8d4: Pad<4>,
    pub(crate) fastdie_0x8d8: F32,
    pad_0x8dc: Pad<4>,
    /// +0x8e0 gpu-fast-die0-integral-gain × (sample period / 1000)
    pub(crate) fastdie_integral_gain: F32,
    pad_0x8e4: Pad<4>,
    /// +0x8e8 float(`chip+0x21e0/0x21e4`) = 0.0, 65536.0
    pub(crate) fastdie_0x8e8: [F32; 2],
    /// +0x8f0 gpu-fast-die0-proportional-gain
    pub(crate) fastdie_proportional_gain: F32,
    pad_0x8f4: Pad<4>,
    pub(crate) fastdie_0x8f8: u32,
    /// +0x8fc c30, +0x900/+0x904 c34·100
    pub(crate) fastdie_0x8fc: [u32; 3],
    /// +0x908 gpu-fast-die0-prop-tgt-delta·100
    pub(crate) fastdie_prop_tgt_delta: u32,
    pad_0x90c: Pad<4>,
    /// +0x910 the target, cfg+0x10·100 (110.0 °C, the G15X value)
    pub(crate) fastdie_target: u32,
    pad_0x914: Pad<0x2c>,
    /// +0x940 c34·100
    pub(crate) fastdie_0x940: u32,
    /// +0x944…+0xde7 unwritten or 0 (the 0x95c/0xb5c copies of the
    /// fast-die cfg table are zero on G15C B1)
    pad_0x944: Pad<0x4a4>,
    /// +0xde8 c34·100
    pub(crate) perf_0xde8: u32,
    /// +0xdec…+0x1087 unwritten
    pad_0xdec: Pad<0x29c>,
    /// +0x1088 u8(chip+0x2858) = `chip+0x654` bit 0 = 1 on t6034: the
    /// block is written
    pub(crate) powerzone_count: u32,
    /// +0x108c chip+0x2864 (the zone-chain count)
    pub(crate) powerzone_0x108c: u32,
    /// +0x1090…+0x1097 {chip+0x285c, chip+0x285c} = P (the G15X
    /// `populateMaximumPerformancePower`'s `setGPUMaxPower`)
    pub(crate) powerzone_0x1090: [u32; 2],
    /// +0x1098 chip+0x285c (third copy)
    pub(crate) powerzone_0x1098: u32,
    /// +0x109c…+0x10a3 zero
    pad_0x109c: Pad<8>,
    /// +0x10a4 float(x−1)/x, x = float(chip+0x286c) = 1.0 (target-filter-tc)
    pub(crate) powerzone_0x10a4: f32,
    /// +0x10a8 float 1/x
    pub(crate) powerzone_0x10a8: f32,
    /// +0x10ac chip+0x2870 (tc<<2)
    pub(crate) powerzone_0x10ac: u32,
    /// +0x10b0 getSamplePeriod() × u32(chip+0x286c)
    pub(crate) powerzone_0x10b0: u32,
    /// +0x10b4 u32(chip+0x286c) × getSamplePeriod() × 0x5dc0
    pub(crate) powerzone_0x10b4: u32,
    /// +0x10b8…+0x1183 zero (the zone entries start at +0x10bc; 0 zones)
    pad_0x10b8: Pad<0xcc>,
    /// +0x1184…+0x1207 avg-power header (Arm pass, after a u64 memset;
    /// chip+0x28d0 = filter-tc-ms / sp = 4, ki = 12.5f · sp/1000 = 0.1f,
    /// kp = 0.3f).
    /// +0x1184 chip+0x28e0 (= chip+0x28d0 << 2)
    pub(crate) avg_0x1184: u32,
    /// +0x1188…+0x118f 0 (u64 store)
    avg_0x1188: [u32; 2],
    /// +0x1190 float(x−1)/x, x = float(chip+0x28d0)
    pub(crate) avg_0x1190: f32,
    /// +0x1194 0
    avg_0x1194: u32,
    /// +0x1198 float 1/x
    pub(crate) avg_0x1198: f32,
    /// +0x119c 0
    avg_0x119c: u32,
    /// +0x11a0 u32(chip+0x28f4) (the ki product, float bits)
    pub(crate) avg_0x11a0: u32,
    /// +0x11a4 0
    avg_0x11a4: u32,
    /// +0x11a8…+0x11af float(u64 chip+0x28f8) (0)
    pub(crate) avg_0x11a8: [u32; 2],
    /// +0x11b0 u32(chip+0x2900) (the P&P default)
    pub(crate) avg_0x11b0: u32,
    /// +0x11b4 0
    avg_0x11b4: u32,
    /// +0x11b8 u32(chip+0x2904) (the 0x11b8…0x1200 group is written
    /// unconditionally; `chip+0x654` bit 1, clear here, picks the values)
    pub(crate) avg_0x11b8: u32,
    /// +0x11bc…+0x11c3 u64(chip+0x2908) = {c30, c34·100}
    pub(crate) avg_0x11bc: [u32; 2],
    /// +0x11c4 u32(chip+0x2910) = c34·100
    pub(crate) avg_0x11c4: u32,
    /// +0x11c8 0
    avg_0x11c8: u32,
    /// +0x11cc float(u32 chip+0x28ec) (= chip+0x285c = P)
    pub(crate) avg_0x11cc: f32,
    /// +0x11d0 u32(chip+0x28ec)
    pub(crate) avg_0x11d0: u32,
    /// +0x11d4 0
    avg_0x11d4: u32,
    /// +0x11d8 u32(chip+0x28d4) = gpu-avg-power-filter-tc-ms
    pub(crate) avg_0x11d8: u32,
    /// +0x11dc 0
    avg_0x11dc: u32,
    /// +0x11e0…+0x11e7 u64(chip+0x28d8) = chip+0x28d0 × chip+0x28cc × 0x5dc0
    pub(crate) avg_0x11e0: U64,
    /// +0x11e8…+0x11fb 0
    pad_0x11e8: Pad<0x14>,
    /// +0x11fc u32(chip+0x2920) (never written)
    pub(crate) avg_0x11fc: u32,
    /// +0x1200 u32(chip+0x2910) = c34·100
    pub(crate) avg_0x1200: u32,
    /// +0x1204 u32(chip+0x2924) = chip+0x27f4 (the overrideControllerValue
    /// user knob, 0 at init)
    pub(crate) avg_0x1204: u32,
    /// +0x1208…+0x12cf unwritten
    pad_0x1208: Pad<0xc8>,
    /// +0x12d0…+0x13af perf governor (Arm pass, after the base pass — the
    /// whole region is written).
    /// sp = getSamplePeriod() = 8; tc/tc1 = gpu-se-filter-time-constant(-1)
    /// = 9/3; the kext computes in float32.
    /// +0x12d0 0
    gov_0x12d0: u32,
    /// +0x12d4 0
    gov_0x12d4: u32,
    /// +0x12d8…+0x12df 0 (u64 store)
    gov_0x12d8: [u32; 2],
    /// +0x12e0…+0x12ef unwritten
    pad_0x12e0: Pad<0x10>,
    /// +0x12f0…+0x12f7 0 (u64 store; the base pass's chip+0x26f0/0x26f4
    /// are wiped by the Arm pass)
    gov_0x12f0: [u32; 2],
    /// +0x12f8 0
    gov_0x12f8: u32,
    /// +0x12fc 0x32 (kext constant)
    pub(crate) gov_0x12fc: u32,
    /// +0x1300 u32(chip+0x26dc) = 1 (P&P default)
    pub(crate) gov_0x1300: u32,
    /// +0x1304 unwritten
    pad_0x1304: Pad<4>,
    /// +0x1308…+0x1317 the SE filter coefficients (float32), one 4-lane
    /// `fdiv` in setupConfig:
    /// {(tc−1)/tc, (tc1−1)/tc1, 1/tc, 1/tc1}
    pub(crate) gov_0x1308: F32,
    pub(crate) gov_0x130c: F32,
    pub(crate) gov_0x1310: F32,
    pub(crate) gov_0x1314: F32,
    /// +0x1318 chip+0x2700 = gpu-se-ki × sp/1000
    pub(crate) gov_0x1318: F32,
    /// +0x131c chip+0x2704 = gpu-se-ki-1 × sp/1000
    pub(crate) gov_0x131c: F32,
    /// +0x1320 float(chip+0x2708) = 0.0 (P&P default)
    pub(crate) gov_0x1320: F32,
    /// +0x1324 float(chip+0x270c) = 65536.0 (`chip+0x270c` = 0x10000)
    pub(crate) gov_0x1324: F32,
    /// +0x1328 chip+0x26f8 = gpu-se-kp
    pub(crate) gov_0x1328: F32,
    /// +0x132c chip+0x26fc = gpu-se-kp-1
    pub(crate) gov_0x132c: F32,
    /// +0x1330 unwritten
    pad_0x1330: Pad<4>,
    /// +0x1334…+0x133b u64{chip+0x2714, chip+0x2718} = {0x64, pstates×100−100}
    pub(crate) gov_0x1334: [u32; 2],
    /// +0x133c chip+0x2710 final = chip+0x2848 = base·100
    pub(crate) gov_0x133c: u32,
    /// +0x1340 chip+0x26d8 = 0 (P&P default)
    pub(crate) gov_0x1340: u32,
    /// +0x1344 float(0x1394) = float(sp × 1000)
    pub(crate) gov_0x1344: F32,
    /// +0x1348 chip+0x26d4 = gpu-se-tgt
    pub(crate) gov_0x1348: u32,
    /// +0x134c 0
    gov_0x134c: u32,
    /// +0x1350 sp × tc
    pub(crate) gov_0x1350: u32,
    /// +0x1354 sp × tc1
    pub(crate) gov_0x1354: u32,
    /// +0x1358…+0x135f tc × sp × 0x5dc0
    pub(crate) gov_0x1358: U64,
    /// +0x1360…+0x1367 tc1 × sp × 0x5dc0
    pub(crate) gov_0x1360: U64,
    /// +0x1368 unwritten
    pad_0x1368: Pad<4>,
    /// +0x136c float(chip+0x270c) (a second copy of +0x1324)
    pub(crate) gov_0x136c: F32,
    /// +0x1370 0
    gov_0x1370: u32,
    /// +0x1374…+0x1393 unwritten
    pad_0x1374: Pad<0x20>,
    /// +0x1394 sp × 1000
    pub(crate) gov_0x1394: u32,
    /// +0x1398 chip+0x2730 = (sp/2 + 0x21)/sp (integer)
    pub(crate) gov_0x1398: u32,
    /// +0x139c…+0x13a3 u64{chip+0x271c, chip+0x2720} = {gpu-se-inactive-
    /// threshold, gpu-se-engagement-criteria}
    pub(crate) gov_0x139c: [u32; 2],
    /// +0x13a4…+0x13ab u64{chip+0x2724, chip+0x2728} = {engagement-, reset-}
    /// tolerance (P&P defaults 2/4; no ADT properties here)
    pub(crate) gov_0x13a4: [u32; 2],
    /// +0x13ac chip+0x272c = gpu-se-reset-criteria
    pub(crate) gov_0x13ac: u32,
    /// +0x13b0…+0x13d7 zero (the Arm pass's stores here are 0)
    pad_0x13b0: Pad<0x28>,
    /// +0x13d8 65536.0f (the u64 `0x4780000000000000` at 0x13d4)
    pub(crate) f_0x13d8: F32,
    /// +0x13dc…+0x13e7 zero
    pad_0x13dc: Pad<0xc>,
    /// +0x13e8 `fw+0xc30` = gpu-pwr-min-duty-cycle, +0x13ec c34·100
    pub(crate) se_0x13e8: [u32; 2],
    /// +0x13f0…+0x148f zero / unwritten
    pad_0x13f0: Pad<0xa0>,
    /// +0x1490 the SoC hot config's first word (firmware `this+0x19a0`,
    /// `populateSoCHotConfigData`): the G15C path
    /// overwrites the copied chip feature mask (chip+0x1a08, 0 on G15C)
    /// with 0x802a002b802a002b (G15S: 0x402a002b)
    pub(crate) sochot_0x1490: u64,
    /// +0x1498 `this+0x19a8` — G15C: 0 (chip+0x1a10)
    pub(crate) sochot_0x1498: u64,
    /// +0x14a0 `this+0x19b0` — 125 (silicon rev != A0; rev A0 would use
    /// the ADT's gpu-sochot-temp, 111 here, with a 120 fallback)
    pub(crate) sochot_0x14a0: u32,
    /// +0x14a4 constant 1 (initPowerAndPerformanceData)
    pub(crate) sochot_0x14a4: u32,
    /// +0x14a8…+0x18a7 the two 0x200-byte blocks (firmware `this+0x19b4`
    /// and its `this+0x1bb4` copy, → HwDataA 0x16a8) — zero on G15C
    /// (populate writes nothing past buf+0x10 for this core)
    pad_0x14a8: Pad<0x1000>,
    /// +0x24a8…+0x24b7 `chip+0x1a08/0x1a10`: the MTR sensor mask, one bit
    /// per entry of PMGR's MtrPolynomGFX (power.md) — the Arm pass zeroes
    /// 0x18a8…0x64bf first
    pub(crate) chip_0x1a08: [u32; 4],
    /// +0x24b8 `chip+0x1a18` = 1
    pub(crate) chip_0x1a18: u32,
    /// +0x24bc…+0x64bb zero
    pad_0x24bc: Pad<0x4000>,
    /// +0x64bc `chip+0x2020` = 0x40a00000 (G15X)
    pub(crate) chip_0x2020: u32,
    /// +0x64c0…+0x6b9f DPEPPT block (AGFDPEPPTConfigData, 0x6e0 bytes) —
    /// zero on G15X: its `populateDPEPPTConfigData` (chip vtbl 0xce0) is
    /// the base implementation, a `bzero`; G15G's fills it. Updated at
    /// runtime by `updateDPEPPT`. Mirrored at PB table 0xd0…0x7a7.
    pub(crate) dpeppt: [u8; 0x6e0],
    /// +0x6ba0…+0x6bf0 8 qwords + 2 u32 from firmware `this+0x18e8…
    /// 0x1934`, the DPE leakage-update config (mirrored into the 0xa38
    /// buffer): zero on G15X, filled on G15G; the rest of the gap
    /// unwritten.
    pub(crate) dpe_leak: [u8; 0xb8],
    /// +0x6c58… AGFAONPTDState, as `AGXArmFirmware::
    /// initPowerAndPerformanceData` builds it: the G15X
    /// `populateAONPTDIdentifiers` (chip vtbl 0xcc0) writes the
    /// identifiers — +0x84 `"RT<n>g"` × the cluster count (chip+0x4a0 =
    /// the core config's MGPU count, copied in `getProbeScore`), +0xac
    /// `"RT<n>r"` × the die count (chip+0x4a8), +0xbc `"RT0f"` — then
    /// `getAONPTDFromOSDictionary` (types 0/1/2) looks each one up in
    /// ApplePTD's `ptd-data-table-dict` (the ADT `/arm-io/aon-ptd`
    /// `ptd_data_table`), appends the 12-byte row to the entries and
    /// sets its bit in the type's found mask. The firmware's power task
    /// counts the entries (the last nonzero of the 11).
    pub(crate) aonptd_entries: [[u8; 12]; 11],
    /// +0x6cdc the "g" identifiers (one per cluster)
    pub(crate) aonptd_ids_g: [[u8; 4]; 8],
    /// +0x6cfc the "g" found mask
    pub(crate) aonptd_found_g: U64,
    /// +0x6d04 the "r" identifiers (one per die)
    pub(crate) aonptd_ids_r: [[u8; 4]; 2],
    /// +0x6d0c the "r" found mask
    pub(crate) aonptd_found_r: U64,
    /// +0x6d14 "RT0f"
    pub(crate) aonptd_id_f: [u8; 4],
    /// +0x6d18 the "f" found mask
    pub(crate) aonptd_found_f: U64,
    /// +0x6d20…+0x6d33 unwritten
    aonptd_pad_0x6d20: Pad<0x14>,
    /// +0x6d34 the AP timebase at fill time (the kext's
    /// `mach_absolute_time()`)
    pub(crate) timestamp_0x6d34: U64,
    /// +0x6d3c…+0x6d7f unwritten
    pad_0x6d3c: Pad<0x44>,
    /// +0x6d80 feature-word bit 18, +0x6d84 bit 31 (`chip+0x650`)
    pub(crate) feat_0x6d80: [u32; 2],
    /// +0x6d88 unwritten
    pad_0x6d88: Pad<0x4>,
    /// +0x6d8c the core leakage per cluster, `populateChipLeakageData`'s
    /// (G15S: one from fuses; G15G: one and the SRAM's; G15C: none)
    pub(crate) core_leak: [u32; 8],
    /// +0x6dac not written by any of the three
    pad_0x6dac: Pad<0x20>,
    /// +0x6dcc the SRAM leakage per cluster
    pub(crate) sram_leak: [u32; 8],
    /// +0x6dec…+0x6e47 not written by any of the three
    pad_0x6dec: Pad<0x5c>,
}

/// The root of the G15 init data. The firmware never reads it: it only
/// records the addresses of the buffer set, whose objects
/// `super::initdata::InitData::ver` keeps alive, for debugging.
#[derive(Debug, Default)]
#[repr(C)]
pub(crate) struct InitData {
    pub(crate) hwdata_a: U64,
    pub(crate) hwdata_b: U64,
    pub(crate) channel_table: U64,
    pub(crate) pb_table: U64,
    pub(crate) fmc: U64,
    pub(crate) ring2: U64,
    pub(crate) buf_0x4000: U64,
    /// The MCache PIO buffer.
    pub(crate) mcache_piob: U64,
    /// The ring area.
    pub(crate) ring_area: U64,
}

impl GpuStruct for InitData {
    type Raw<'a> = InitData;
}
// SAFETY: only U64 fields, zero is a valid state.
unsafe impl ::pin_init::Zeroable for InitData {}

default_zeroed!(HwDataA);
default_zeroed!(FmcHeader);

/// Compile-time layout checks against the kext model.
///
/// A mismatch is a compile error (an empty array of the wrong length), so
/// the sizes and offsets below are enforced on every build.
const _: [(); {
    (size_of::<RingEntry>() == 0x60) as usize
        * (size_of::<FmcHeader>() == 0xc0) as usize
        * (size_of::<HwDataA>() == 0x6e48) as usize
}] = [(); 1];

const _: [(); {
    (core::mem::offset_of!(HwDataA, clock_0x838) == 0x838
        && core::mem::offset_of!(HwDataA, fastdie_sensor_mask) == 0x8ac
        && core::mem::offset_of!(HwDataA, fastdie_target) == 0x910
        && core::mem::offset_of!(HwDataA, fastdie_0x940) == 0x940
        && core::mem::offset_of!(HwDataA, timestamp_0x6d34) == 0x6d34
        && core::mem::offset_of!(HwDataA, feat_0x6d80) == 0x6d80
        && core::mem::offset_of!(HwDataA, core_leak) == 0x6d8c
        && core::mem::offset_of!(HwDataA, sram_leak) == 0x6dcc
        && core::mem::offset_of!(HwDataA, mem_threshold) == 0x860) as usize
}] = [(); 1];

const _: [(); {
    (core::mem::offset_of!(FmcHeader, channel_table_fwva) == 0x18) as usize
        * (core::mem::offset_of!(FmcHeader, pb_table_fwva) == 0x20) as usize
        * (core::mem::offset_of!(FmcHeader, chip_a078) == 0x30) as usize
        * (core::mem::offset_of!(FmcHeader, buf_0x910_fwva) == 0xa8) as usize
        * (core::mem::offset_of!(FmcHeader, buf_0xa40_fwva) == 0xb0) as usize
}] = [(); 1];

const _: [(); {
    (core::mem::offset_of!(HwDataA, vtbl_0xe70) == 0x04) as usize
        * (core::mem::offset_of!(HwDataA, static_config) == 0x60) as usize
        * (core::mem::offset_of!(HwDataA, perf_dual_filter) == 0x7a4) as usize
        * (core::mem::offset_of!(HwDataA, perf_tgt_util_2) == 0x7ec) as usize
        * (core::mem::offset_of!(HwDataA, limiter_filter) == 0x86c) as usize
        * (core::mem::offset_of!(HwDataA, perf_0xde8) == 0xde8) as usize
        * (core::mem::offset_of!(HwDataA, chip_0x27e0) == 0x698) as usize
        * (core::mem::offset_of!(HwDataA, powerzone_count) == 0x1088) as usize
        * (core::mem::offset_of!(HwDataA, powerzone_0x10b4) == 0x10b4) as usize
        * (core::mem::offset_of!(HwDataA, avg_0x1184) == 0x1184) as usize
        * (core::mem::offset_of!(HwDataA, avg_0x11e0) == 0x11e0) as usize
        * (core::mem::offset_of!(HwDataA, avg_0x1204) == 0x1204) as usize
        * (core::mem::offset_of!(HwDataA, gov_0x12fc) == 0x12fc) as usize
        * (core::mem::offset_of!(HwDataA, gov_0x139c) == 0x139c) as usize
        * (core::mem::offset_of!(HwDataA, pad_0x13b0) == 0x13b0) as usize
        * (core::mem::offset_of!(HwDataA, dpeppt) == 0x64c0) as usize
        * (core::mem::offset_of!(HwDataA, aonptd_ids_g) == 0x6cdc) as usize
        * (core::mem::offset_of!(HwDataA, aonptd_ids_r) == 0x6d04) as usize
        * (core::mem::offset_of!(HwDataA, aonptd_id_f) == 0x6d14) as usize
        * (core::mem::offset_of!(HwDataA, aonptd_found_f) == 0x6d18) as usize
        * (core::mem::size_of::<HwDataA>() == 0x6e48) as usize
}] = [(); 1];
