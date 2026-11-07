// SPDX-License-Identifier: GPL-2.0-only

//! G15 firmware init-data structures, macOS 27.2's firmware (V27_2).
//!
//! 27.2's init data is a new ABI, not 14.8.3's with fields appended: the FMC
//! header, the channel table, the PB table, HwDataB (and its window record)
//! and HwDataA change layout or size, and four buffers are new. The buffers
//! whose layout is unchanged (the control block, the 3D and CL slot records,
//! the 0x60 and 0x88 buffers, ring 2, the data-master rings) keep
//! `super::g15`'s definitions.
//!
//! A field's name carries its 27.2 offset, or the chip-object source the
//! spec gives for 27.2 (`chip_*`); a field 27.2 keeps from 14.8.3 without a
//! known 27.2 source keeps its 14.8.3 name. Each field's doc gives its
//! offset, its 14.8.3 counterpart and the spec's grade: **T** traced in the
//! 27.2 kext or firmware, **I** inferred. A value 27.2 computes from a chip
//! word the spec has no t6034 value for is 14.8.3's value or zero, marked
//! "not verified". The compile-time asserts at the bottom pin every offset
//! and size.
//!
//! Static RE only: no 27.2 layout has run on the Mac.
//!
//! Spec: fw272-init.md (the FMC header, the channel table, the PB table,
//! the sizes), fw272-hwdata.md (HwDataB, HwDataA, the power-control block,
//! the event page, the other buffers).

use super::g15::{FmcHeader, RingEntry, RING_REGION2_OFF, RING_STRIDE};
use super::types::{GpuStruct, Pad, U64};
use crate::default_zeroed;
use crate::float::F32;
use core::sync::atomic::AtomicU32;

/// The FMC channel header's magic for 27.2's G15C firmware, which the
/// firmware compares exactly at its boot (`AGFA_InitDataGrab` cmp at
/// 0xfffffc0000032cd8; kext `MOV X8` at 0xfffffe0008ba7a28, T). Its low
/// 16 bits are the channel table's size. 27.2's G15S magic is unknown.
pub(crate) const FMC_MAGIC_V27_2: u64 = 0x0c8a_836f_0496_04b8;

/// TA slot records (`buf_0x218`), 0xc10 → 0xc18, zeroed (fw272-hwdata.md
/// §1.8, T).
pub(crate) const TA_RECORDS_SIZE: usize = 0xc18;
/// The control ring's storage: 256 entries of 0x40 (was 0x38;
/// `submitDeviceControl` 0xfffffe0008b7f15c, T).
pub(crate) const CONTROL_RING_SIZE: usize = 0x4000;
/// The event page, 0xc3d0 → 0xede0 (fw272-init.md §2, T).
pub(crate) const EVENT_PAGE_SIZE: usize = 0xede0;
/// The event page's word set to 1 by the base `initFirmwareData` (`MOV
/// W9,#0x51B4` at 0xfffffe0008b81668; was +0x45c4, T).
pub(crate) const EVENT_PAGE_ONE: usize = 0x51b4;
/// The event page's memory-descriptor ring head and storage fields (was
/// +0x4568/+0x4570; `AGXArmFirmware::init`, T).
pub(crate) const EVENT_PAGE_MEMDESC_HEAD: usize = 0x5168;
pub(crate) const EVENT_PAGE_MEMDESC_RING: usize = 0x5170;
/// Where the driver places the zeroed memory-descriptor head and ring in
/// the event page, clear of the firmware's reads at +0x8 and +0xcfb8
/// (fw272-init.md §4, the spec's example; I).
pub(crate) const EVENT_PAGE_MEMDESC_AT: usize = 0xed00;
/// The power-control block, 0x238 → 0x6a0 (fw272-init.md §2, T).
pub(crate) const PWR_CTL_SIZE: usize = 0x6a0;
/// The new 0x60 block-2 buffer (`this+0x350/0x358`, FMC header +0xc0), not
/// written by the kext after allocation (T).
pub(crate) const FMC_BUF_SIZE: usize = 0x60;
/// The new 8-byte block-2 buffer (`this+0x360/0x368`, HwDataA +0x4bb0): a
/// max-temperature sequence word (`getOverallMaxTemperature`
/// 0xfffffe0008b9cf1c, T).
pub(crate) const HWDATA_A_BUF8_SIZE: usize = 8;
/// The new block-4 AON PTD entries buffer (`this+0xfe8/0xfe0`, HwDataA
/// +0x9360): 19 rows of 12 bytes (T).
pub(crate) const AONPTD_ROWS: usize = 19;
pub(crate) const AONPTD_SIZE: usize = AONPTD_ROWS * 12;
/// The GPU power-assertion counter (channel table +0x18): a u32 macOS keeps
/// in the Fender scratch (`allocGPUPowerAssertionCounters`
/// 0xfffffe0008b90340, T). The driver keeps it in the ring area, the
/// scratch's stand-in, past region 1's 13 rings (I: whether the firmware
/// accepts it outside the SRAM is not verified). The host increments it
/// per asserting device-control command (fw272-control.md §2.2).
pub(crate) const PWR_ASSERT_CTR_OFF: usize = RING_REGION2_OFF - 0x40;
const _: () = assert!(13 * RING_STRIDE <= PWR_ASSERT_CTR_OFF);

/// The firmware-to-host rings of 27.2 (fw272-hwdata.md §1.8): the four ring
/// state and storage pairs (event, log, trace, stats), then the log text.
/// The state sizes are T; the log's 9 sub-rings (was 6) are I.
pub(crate) const FW_RINGS: [(usize, &[u8; 4]); 9] = [
    (0x30, b"RS0A"),
    (0x4800, b"RB0A"),
    (0x1b0, b"RS1B"),
    (0x28800, b"RB1B"),
    (0x30, b"RS2C"),
    (0x9000, b"RB2C"),
    (0x30, b"RS3D"),
    (0x4800, b"RB3D"),
    (0x79800, b"B900"),
];

/// FMC channel header, 0xc0 → 0xc8 (fw272-init.md §1.1). The firmware's
/// grab copies 0xc8 bytes (`LDR X10,[X8,#0xC0]` at 0xfffffc0000032d28).
#[derive(Debug)]
#[repr(C)]
pub(crate) struct FmcHeaderV27_2 {
    /// +0x00…+0xbf 14.8.3's header, unchanged but for its magic
    /// (`FMC_MAGIC_V27_2`): ring 2, the channel table, the PB table, the
    /// 0x1_0000_0000 word, the GART table (`initGartInfo`
    /// 0xfffffe0008bb7d40, the same values), the control block, the event
    /// page and the power-control block (T)
    pub(crate) base: FmcHeader,
    /// +0xc0 new: `conv(this+0x358)`, the zeroed 0x60 block-2 buffer
    /// (Arm `initFirmwareData` 0xfffffe0008ba7bbc). The firmware stores it
    /// at qword_FFFFFC0000182F20 (0xfffffc0000032d74); no reader found (T;
    /// its use I)
    pub(crate) buf_0x358_fwva: U64,
}

/// Channel info table, 0x490 → 0x4b8 (fw272-init.md §1.2): everything after
/// +0x18 moves by +8 … +0x38. Writers: the base `initFirmwareData`
/// (0xfffffe0008b81008), `initFirmwareSharedData` (0xfffffe0008b970cc), the
/// Arm `initFirmwareData` and `AGXArmFirmware::init`.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct ChannelTableV27_2 {
    /// +0x00 `conv(HwDataB)` (T)
    pub(crate) hwdata_b_fwva: U64,
    /// +0x08 `conv(FWBRN table)`, size 0 (`getSizeOfFWBRNTable`
    /// 0xfffffe0008bbd1a4, T)
    pub(crate) fwbrn_fwva: U64,
    /// +0x10 `conv(this+0x288)`, the 0x88 buffer (T)
    pub(crate) buf_0x248_fwva: U64,
    /// +0x18 new: the FW VA of the GPU power-assertion counter, a u32
    /// (`this+0x330`; base `initFirmwareData` 0xfffffe0008b813c4). The
    /// firmware's control handler compares it with event page +0xedc8 (T)
    pub(crate) pwr_assert_ctr_fwva: U64,
    /// +0x20…+0x19f the ring table, the same 0x60 rows (was +0x18; base
    /// loop `i = 0x58…0x1d8`, T)
    pub(crate) ring: [RingEntry; 4],
    /// +0x1a0…+0x1bf the control ring's row: the `this+0xc00` object,
    /// storage `this+0xc20` (was +0x198, T)
    pub(crate) special: [U64; 4],
    /// +0x1c0…+0x1ff the pointer block: event, log, trace and stats, state
    /// then storage (was +0x1b8, T)
    pub(crate) ptr_block: [U64; 8],
    /// +0x200 `conv(this+0x900)`, the log text (was +0x1f8, T)
    pub(crate) buf_0x900_fwva: U64,
    /// +0x208…+0x24f unwritten by the kext (was 0x30 at +0x200, now 0x48;
    /// T by absence)
    pad_0x208: Pad<0x48>,
    /// +0x250 the firmware-log enable, 0 in the kext (was +0x230, T)
    pub(crate) log_enable: u32,
    /// +0x254 `conv` of the 0xc18 TA slot records (was +0x234; odd offset,
    /// T)
    pub(crate) buf_0x218_fwva: [u32; 2],
    /// +0x25c the 0x1248 3D slot records (was +0x23c, T)
    pub(crate) buf_0x220_fwva: [u32; 2],
    /// +0x264 the 0xe10 CL slot records (was +0x244, T)
    pub(crate) buf_0x228_fwva: [u32; 2],
    /// +0x26c the block-1 0x60 buffer (was +0x24c, T)
    pub(crate) buf_0x238_fwva: [u32; 2],
    /// +0x274…+0x2c7 unwritten (T)
    pad_0x274: Pad<0x54>,
    /// +0x2c8 `conv(chip+0x125a0)` if `chip+0x10d04`: the HWDSID table
    /// (was +0x2a8, `chip_0x30d0_fwva`, T)
    pub(crate) chip_0x125a0_fwva: U64,
    /// +0x2d0 the PB descriptor table (chip+0x11bb0): its +0x58 mapping's
    /// VA (was +0x2b0, T). The driver has one mapping (I)
    pub(crate) pb_desc_table_gpuva: U64,
    /// +0x2d8 its +0x50 mapping's VA, the one the firmware reads (was
    /// +0x2b8, T)
    pub(crate) pb_desc_table_fwva: U64,
    /// +0x2e0/+0x2e8 the UMA page-pool descriptor table (chip+0x11bb8), the
    /// same pattern; the firmware reads +0x2e8 (was +0x2c0/+0x2c8, T)
    pub(crate) umap_pool_pa: U64,
    pub(crate) umap_pool_fwva: U64,
    /// +0x2f0 new: 0 (Arm `initFirmwareData`, T)
    pub(crate) zero_0x2f0: U64,
    /// +0x2f8 `chip+0x10d5c` (was +0x2d0 `chip+0x20b8`, 4 =
    /// halGetDefaultUscMaxTgmem; T offset, value not verified)
    pub(crate) chip_0x10d5c: u32,
    /// +0x2fc `chip+0x10dcc` (was +0x2d4 `chip+0x2114`, T)
    pub(crate) chip_0x10dcc: u32,
    /// +0x300…+0x3d7 unwritten (T)
    pad_0x300: Pad<0xd8>,
    /// +0x3d8…+0x480 the tail, still 0xa9 bytes (was +0x3b0): 0xff at +0,
    /// 0x90 zero bytes, the firmware-written THM activation count at +0x91
    /// (abs +0x469, 8 bytes and 8 unwritten; `getTHMActivationCount`), and
    /// `conv(HwDataA)` at **+0xa1** (abs +0x479, was +0x91; 88 firmware
    /// reads). 14.8.3's `chip+0x2088` at +0x99 has no 27.2 writer (T)
    pub(crate) tail_0x3d8: [u8; 0xa9],
    /// +0x481…+0x4b7 unwritten; +0x495…+0x4b4 zeroed by
    /// `AGXArmFirmware::init` (T)
    pad_0x481: Pad<0x37>,
}

/// `ChannelTableV27_2::tail_0x3d8`'s HwDataA address (abs +0x479).
pub(crate) const CHANNEL_TAIL_HWDATA_A: usize = 0xa1;

/// The PB table (power block), 0x1208 → 0x1258 (fw272-init.md §1.3): it
/// shifts at about ten points (+4 … +0x34), with 17 new fields. Writers:
/// the base and Arm `initFirmwareData`, the base (0xfffffe0008b80418) and
/// Arm (0xfffffe0008ba45ac) `initPowerAndPerformanceData`, the Arm
/// `setupConfig` (0xfffffe0008ba9170), `AGXArmFirmware::init` and the
/// setters, compared function by function (T).
#[derive(Debug)]
#[repr(C)]
pub(crate) struct PBTableV27_2 {
    /// +0x00 7 if `chip+0x690` bit 30 (was `chip+0x650` bit 28), else 0;
    /// `setTimerCSwitch` (T; 0 as on 14.8.3's t6034, not verified)
    pub(crate) header: u32,
    /// +0x04 0 (T)
    pub(crate) zero_0x04: u32,
    /// +0x08 new: 0 (base, T)
    pub(crate) zero_0x08: u32,
    /// +0x0c `setDMPauseMode(0)` (vtbl 0x630; was +0x08, T)
    pub(crate) dm_pause_mode: u32,
    /// +0x10 0 (was +0x0c, T)
    pub(crate) zero_0x10: u32,
    /// +0x14 `setDMPauseTimer`, 0 (was +0x10, T)
    pub(crate) dm_pause_timer: u32,
    /// +0x18 0 (was +0x14, T)
    pub(crate) zero_0x18: u32,
    /// +0x1c `setDisableCSwitch(chip+0x1171c)` (was +0x18 = 0; T, the
    /// value I: 0, not verified)
    pub(crate) disable_cswitch: u32,
    /// +0x20 `chip+0x12038` (was +0x1c; T, 0 as the 14.8.3 driver)
    pub(crate) frg_timeout: u32,
    /// +0x24 `setRelaxedCLKillTimeout` 3000 (0xfffffe0008b9a908; was
    /// +0x20, T)
    pub(crate) relaxed_cl_kill_timeout: u32,
    /// +0x28 `setFRGTaskTimeout(chip+0x1203c)` (was +0x24; T, 0 as the
    /// 14.8.3 driver)
    pub(crate) frg_task_timeout: u32,
    /// +0x2c `chip+0x6c0` (was +0x28 `chip+0x660`, T)
    pub(crate) chip_0x6c0: u32,
    /// +0x30 `u8(chip+0x690 & 1)` (was +0x2c `chip+0x650` bit 0, T)
    pub(crate) chip_0x690_bit0: u8,
    pad_0x31: Pad<3>,
    /// +0x34 feature bit 1 (`setSmartIdleOffEnable`; was +0x30, T)
    pub(crate) feature_bit1: u32,
    /// +0x38 new: `(chip+0x699 & 4) != 0` (Arm P&P; T, the value I: 0,
    /// not verified)
    pub(crate) chip_0x699_bit2: u32,
    /// +0x3c 0 if `gpu-noise-suppression` (was +0x34, T)
    pub(crate) noise_suppression: u32,
    /// +0x40 0x78 (was +0x38, T)
    pub(crate) const_0x40: u32,
    /// +0x44 the CPMS window, +0x48 TFCA: 0 (was +0x3c/+0x40, T)
    pub(crate) zero_0x44: u32,
    pub(crate) zero_0x48: u32,
    /// +0x4c/+0x50/+0x54 0 (was +0x44/+0x48/+0x4c, T)
    pub(crate) zero_0x4c: u32,
    pub(crate) zero_0x50: u32,
    pub(crate) zero_0x54: u32,
    /// +0x58/+0x5a/+0x5c `chip+0x728/0x72a/0x72c` (was +0x50… from
    /// `chip+0x6c4…`, T)
    pub(crate) chip_0x728: u16,
    pub(crate) chip_0x72a: u16,
    pub(crate) chip_0x72c: u16,
    /// +0x5e…+0x61 0 (was +0x56, T)
    pub(crate) zero_0x5e: u16,
    pad_0x60: Pad<2>,
    /// +0x62 new, 4 bytes: `isQOSBillingEnabled()` (chip vtbl 0xee8; base
    /// 0xfffffe0008b81738; T, the value I: 0, not verified)
    pub(crate) qos_billing: [u8; 4],
    /// +0x66 `(chip+0x19920 & 3) == 0` (was +0x5a `chip+0xa218`, T)
    pub(crate) chip_0x19920_eq0: u8,
    pad_0x67: Pad<3>,
    /// +0x6a new, 4 bytes: `setPanicOnPMOOM(3)` (vtbl 0x220, T)
    pub(crate) panic_on_pm_oom: [u8; 4],
    /// +0x6e `setCSwitchTimerMultiplier(max(HwDataB+0xff0, 1))` (was
    /// +0x5e, T)
    pub(crate) power_sample_period: u8,
    /// +0x6f…+0x7b unwritten at init; +0x72 `setCDMCSModeChange` (T)
    pad_0x6f: Pad<0xd>,
    /// +0x7c `setCommandSubmissionEnabled` 1 (0xfffffe0008bab7e0; was
    /// +0x70, T)
    pub(crate) cmd_submission_enabled: u32,
    /// +0x80 submissions in progress: `updateSubmitInProgress`
    /// (0xfffffe0008ba3384) increments it and +0x84 at a submit's start
    /// and decrements only it (was +0x74, T)
    pub(crate) submit_in_progress: AtomicU32,
    /// +0x84 new: the monotonic submit counter, only incremented (T)
    pub(crate) submit_count: AtomicU32,
    /// +0x88…+0x93 `updatePowerInterfaceTarget(0/1/2)` (was +0x78, T)
    pub(crate) pwr_target: [u32; 3],
    /// +0x94 `overrideControllerValue`, 0 at init (was +0x84, T)
    pub(crate) override_controller: u32,
    /// +0x98 `chip+0x6bc` if nonzero (also copied to the transfer field
    /// +0xb0), +0x9c 100 × the perf-state cap (`updatePerfStateCap`) (was
    /// +0x88 `chip_0x65c`, T)
    pub(crate) chip_0x6bc: U64,
    /// +0xa0/+0xa4 new: 0, 0 (Arm P&P end, T)
    pub(crate) zero_0xa0: [u32; 2],
    /// +0xa8…+0xe7 the perf-controller block, 0x40 (was 0x38 at +0x90),
    /// copied from fw-object +0x21b0: the target +0xa8, the new dead zone
    /// +0xac (`gpu-perf-dz`), the transfer +0xb0, the CE step +0xb8, the
    /// reset iterations +0xbc, the time filter +0xc1, the flags +0xd9…+0xe0
    /// (T offsets; zero as on 14.8.3, the dead zone's t6034 value not
    /// verified)
    pub(crate) fw_util: [u8; 0x40],
    /// +0xe8/+0xec `updateDeadlineControllerOverride` (was +0xc8, T)
    pub(crate) deadline_override: [u32; 2],
    /// +0xf0…+0x7c7 the DPEPPT mirror of HwDataA +0x8bec… (was +0xd0, T)
    pub(crate) dpeppt: [u8; 0x6d8],
    /// +0x7c8…+0x7ef the idle-off predictor, `chip+0x10690…` (was +0x7a8,
    /// T)
    pub(crate) idleoff: [u32; 10],
    /// +0x7f0 1, +0x7f4 `enablePMUEngagement` = `chip+0x690` bit 59 (was
    /// +0x7d0 = [1, 1]; T, the bit's value I: 1 as 14.8.3's word, not
    /// verified)
    pub(crate) one_0x7f0: [u32; 2],
    /// +0x7f8/+0x7fc `chip_0x2198/0x2194` (was +0x7d8/+0x7dc, T)
    pub(crate) chip_0x2198: u32,
    pub(crate) chip_0x2194: u32,
    /// +0x800…+0x99b: 0x804…0x98b zeroed by `AGXArmFirmware::init`,
    /// `addRegisterOverride` at +0x984 (was +0x7e0, T)
    pad_0x800: Pad<0x19c>,
    /// +0x99c…+0x9b3 the progress check, 6 u32 (was 7 at +0x97c): 16 bytes
    /// from `chip+0x10e1c` = {0x28, 0xa, 0xfa, 1} (the 3D, TA and CL
    /// intervals, then the threshold at +0x9a8), then 8 bytes from
    /// `chip+0x10e2c` at +0x9ac (the new DM config,
    /// `setProgressCheckDmConfig`) and +0x9b0 (T; the 0x10e2c values I: 0,
    /// not verified)
    pub(crate) progress: [u32; 6],
    pad_0x9b4: Pad<8>,
    /// +0x9bc/+0x9c0/+0x9c4 the GPU idle-off, Fender idle-off and FW
    /// early-wake ternaries: 2, 40, 5 (was +0x9a0, T)
    pub(crate) ternary_0x9bc: u32,
    pub(crate) ternary_0x9c0: u32,
    pub(crate) ternary_0x9c4: u32,
    /// +0x9c8 the GVDM timer, 0 (was +0x9ac, T)
    pub(crate) zero_0x9c8: u32,
    /// +0x9cc `setCLContextSwitchTimeout` 40, +0x9d0 `setCLKillTimeout` 50
    /// (was +0x9b0/+0x9b4, T)
    pub(crate) cl_ctx_switch_timeout: u32,
    pub(crate) cl_kill_timeout: u32,
    /// +0x9d4 new: `setPhaseOneCDMContextSwitchTimeout(1)` (vtbl 0x578, T)
    pub(crate) phase1_cdm_ctx_switch_timeout: u32,
    /// +0x9d8 new: `setFRGContextSwitchTimeout(0)` (vtbl 0x548, T)
    pub(crate) frg_ctx_switch_timeout: u32,
    /// +0x9dc new: `setFRGKillTimeout(50)` (vtbl 0x588, T)
    pub(crate) frg_kill_timeout: u32,
    /// +0x9e0 0 (was +0x9b8, T)
    pub(crate) zero_0x9e0: u32,
    /// +0x9e4 `setCDMBackoffTimeout` 4 (was +0x9bc, T)
    pub(crate) cdm_backoff_timeout: u8,
    /// +0x9e5…+0x1210 `populateFwUtilPerfTunables` (unchanged,
    /// 0xfffffe0008bbd86c): the same 0x74 bytes of constants (was +0x9bd,
    /// T)
    pub(crate) fw_util_perf_tunables: [u8; 0x82c],
    /// +0x1211…+0x1234: +0x1215 the quick process exit
    /// (`halGetProcessExitDefaultTimeoutMS()` if `chip+0x699` bit 1, else 0;
    /// was +0x11ed, the value I: 0), the keep-alive words +0x1219…+0x1228
    /// and the UMA recall parameters +0x1229/+0x122d/+0x1231 (runtime) (T)
    tail_0x1211: [u8; 0x24],
    /// +0x1235 the soft-fault settings, `initSoftFaultSettings(true)` = 3
    /// (`updateSoftFaultSettings` 0xfffffe0008bab448; was +0x1201; odd
    /// offset, T)
    pub(crate) soft_fault: [u8; 4],
    /// +0x1239 new: 1 (base, after P&P, T)
    pub(crate) one_0x1239: [u8; 4],
    /// +0x123d new: the RIART U-levels disable mask, 0 (T)
    pub(crate) riart_ulevel_mask: [u8; 4],
    /// +0x1241 new: RIART TT disabled, 0 (T)
    pub(crate) riart_tt_disabled: [u8; 4],
    /// +0x1245 new: 0 (T)
    pub(crate) zero_0x1245: [u8; 4],
    /// +0x1249…+0x1257 unwritten
    tail_0x1249: [u8; 0xf],
}

/// One 0x28 register-window record of HwDataB (was 0x20; fw272-hwdata.md
/// §1.4). Source entry: the chip window table `chip+0x740 + 0x438·j`. The
/// Arm overlay skips windows with flag bit 0 and forces record 41's fwva
/// to 0; the firmware takes its RGX base from record 17 (was 3) (T).
#[derive(Debug)]
#[repr(C)]
pub(crate) struct WindowRecordV27_2 {
    /// +0x00 the window's physical base or first pair (T)
    pub(crate) base: U64,
    /// +0x08 the Arm pass's window address, 0 for a flag-bit-0 window (T)
    pub(crate) fwva: U64,
    /// +0x10 kind × size (T)
    pub(crate) kind_size: u32,
    /// +0x14 size (`src+0x208`, T)
    pub(crate) size: u32,
    /// +0x18 new: `u64(src+0x210)` (T; what it holds I, possibly
    /// `getPIORelativeOffsetTable`)
    pub(crate) src_0x210: U64,
    /// +0x20 `flag & 2` (was the whole flag byte at +0x18, T)
    pub(crate) flag: u32,
    pad_0x24: Pad<4>,
}

/// The register-window records: 60, was 31 (Arm loop 0x648…0xfa8, T).
pub(crate) const WINDOWS: usize = 60;

/// HwDataB, 0x1868 → 0x2790 (fw272-hwdata.md §1.4). Offsets move at about
/// ten points after 0x640; 5 fields go, about 25 are new; the volt tables
/// and the AFR table double. Writers: the base and Arm `initFirmwareData`,
/// the Arm `setupConfig`, the base and Arm P&P and `setAbsTimeOffset`
/// (0xfffffe0008b7cba4). The feature word moved from `chip+0x650` (u32) to
/// `chip+0x690` (u64) with some bits renumbered; the per-field values carry
/// over (I).
#[derive(Debug)]
#[repr(C)]
pub(crate) struct HwDataBV27_2 {
    /// +0x00…+0x27 the head constants, unchanged (T)
    pub(crate) magic1: U64,
    pub(crate) magic2: U64,
    pub(crate) const_0x10: U64,
    pub(crate) const_0x18: U64,
    pub(crate) const_0x20: U64,
    /// +0x28 the timestamp base: macOS's is `conv(0xfffffc2181400000)` (was
    /// 0xfffffc2011800000; base 0xfffffe0008b81c38, T). The firmware drops
    /// a timestamp store outside [base, base + 0x3FFFFF8]; whether it
    /// accepts the driver's base is not verified
    pub(crate) egart_fwva: U64,
    /// +0x30 unchanged (T)
    pub(crate) ts_area_base: U64,
    /// +0x38…+0x637 the 32 chip records, unchanged (T)
    pub(crate) chip_records: [U64; 96],
    pub(crate) chip_records_hi: [U64; 96],
    /// +0x638 the border-colour table address, unchanged (T)
    pub(crate) vtbl_0xdc8: U64,
    /// +0x640…+0xf9f 60 register-window records of 0x28 (was 31 × 0x20;
    /// base loop `j = 0x3c`, T)
    pub(crate) windows: [WindowRecordV27_2; WINDOWS],
    /// +0xfa0 `conv((this+0x1818)->vtbl[0x158]())` (was +0xa20, T)
    pub(crate) arm_0xfa0: U64,
    /// +0xfa8 new: the coredump copy buffer
    /// (`getCoredumpCopyBufferEDTProperty`, 0xfffffe0008b816b8; T, 0 not
    /// verified)
    pub(crate) coredump_buf: U64,
    /// +0xfb0/+0xfb8 `chip+0x20c0…0x20cf`: the chip ID, 1, 2, 0 (was
    /// +0xa28/+0xa30, +0x588; T offset, the values 14.8.3's)
    pub(crate) chip_0x20c0: U64,
    pub(crate) chip_0x20c8: U64,
    /// +0xfc0 the probe byte's bit 1 (was +0xa38). With +0x26c8 the
    /// firmware's power-up gate (`armfw_g15c_272` sub_FFFFFC00000101CC
    /// +0x760…0x93c, T)
    pub(crate) probe_da2_bit1: u32,
    /// +0xfc4 feature bit 8 (was +0xa3c, T)
    pub(crate) chip_0x650_bit8: u32,
    // +0xa40 `isPIOSupported()` is gone: +0x26c8 takes its role (T).
    /// +0xfc8 the probe byte's bit 4 (was +0xa44, +0x584, T)
    pub(crate) probe_da2_bit4: u32,
    /// +0xfcc…+0xfdb {0, 0, 0, 1}: one 16-byte store (base
    /// `initFirmwareData` 0xfffffe0008b81808, T). 14.8.3's +0xa48…+0xa57
    /// was {0 (u64), 1, 0}: the 1 sits one word later than the +0x584
    /// shift gives (I mapping)
    pub(crate) zero_0xfcc: u32,
    pub(crate) zero_0xfd0: u32,
    pub(crate) zero_0xfd4: u32,
    pub(crate) one_0xfd8: u32,
    /// +0xfdc feature bit 11 (was +0xa58, T)
    pub(crate) chip_0x650_bit11: u32,
    /// +0xfe0 feature bit 12 (was +0xa5c, T)
    pub(crate) chip_0xca_bit12: u32,
    /// +0xfe4 1 (was +0xa60; the grab reads it, T)
    pub(crate) one_0xfe4: u32,
    /// +0xfe8 0 (was +0xa64, T)
    pub(crate) zero_0xfe8: u32,
    /// +0xfec the base clock, kHz (was +0xa68, T)
    pub(crate) base_clock_khz: u32,
    /// +0xff0 200 for `model-slow`, else 1; the PB table's +0x6e reads it
    /// (was +0xa6c, T)
    pub(crate) power_sample_period: u32,
    /// +0xff4 `getSamplePeriod()` (was +0xa70, T)
    pub(crate) vtbl_0xe68: u32,
    /// +0xff8 `chip+0x664`'s field (was +0xa74, T)
    pub(crate) chip_0x664: u32,
    /// +0xffc 1 (was +0xa78, T)
    pub(crate) one_0xffc: u32,
    /// +0x1000 [1, 1] (was +0xa7c, T)
    pub(crate) const_0x1000: [u32; 2],
    pad_0x1008: Pad<4>,
    /// +0x100c `chip+0x2034`'s field (was +0xa88, T)
    pub(crate) chip_0x2034: u32,
    /// +0x1010 `getUVWarnPhysicalAddress() != 0` (was +0xa8c, T)
    pub(crate) vtbl_0xb18_flag: u32,
    /// +0x1014 14.8.3's `chip_idx_0x9e` (+0xa90): no 27.2 writer (I)
    pad_0x1014: Pad<4>,
    /// +0x1018 0 (was +0xa94, T)
    pub(crate) zero_0x1018: u32,
    /// +0x101c `pmp-sw-interrupt` present (was +0xa98, T)
    pub(crate) pmp_sw_interrupt: u32,
    /// +0x1020 0x1f (was +0xa9c, T)
    pub(crate) const_0x1020: u32,
    /// +0x1024 `chip+0x19d8`'s field (was +0xaa0, T)
    pub(crate) chip_0x19d8: u32,
    /// +0x1028 feature bit 19 (was +0xaa4, T)
    pub(crate) chip_0xca_bit19: u32,
    /// +0x102c `chip+0x6c2 != 0` (was +0xaa8, T)
    pub(crate) chip_0x6c2_flag: u32,
    /// +0x1030 0 (was +0xaac, T)
    pub(crate) zero_0x1030: u32,
    pad_0x1034: Pad<0xc>,
    /// +0x1040 `chip+0x2028`, now a u64 (was a u32 at +0xabc): the default
    /// MCache writes, 4 (T)
    pub(crate) chip_0x2028: U64,
    /// +0x1048 `chip+0x2030`'s field (was +0xac4, T)
    pub(crate) chip_0x2030: u32,
    /// +0x104c/+0x1054 the two u64 constants (was +0xac8/+0xad0, T)
    pub(crate) const_0x104c: U64,
    pub(crate) const_0x1054: U64,
    /// +0x105c 0 (was +0xad8, T)
    pub(crate) zero_0x105c: u32,
    /// +0x1060 feature bit 21, +0x1064 feature bit 26 (was +0xadc/+0xae0,
    /// T)
    pub(crate) chip_0x650_bit21: u32,
    pub(crate) chip_0x650_bit26: u32,
    /// +0x1068 `chip+0x2064` = 0x31 (was +0xae4, T)
    pub(crate) chip_0x2064: u32,
    /// +0x106c 0 (was +0xae8, T)
    pub(crate) zero_0x106c: U64,
    pad_0x1074: Pad<4>,
    /// +0x1078 0 (was +0xaf4, T)
    pub(crate) zero_0x1078: u32,
    pad_0x107c: Pad<4>,
    /// +0x1080 0 (was +0xafc, T)
    pub(crate) zero_0x1080: u32,
    /// +0x1084 `chip+0x654` bit 12 (was +0xb00, T)
    pub(crate) chip_0x654_bit12: u32,
    /// +0x1088 `u8(chip+0x40e)`'s field (was +0xb04, T)
    pub(crate) chip_0x40e: u32,
    /// +0x108c/+0x1094 `chip+0x20d0/0x20d8`'s fields (was +0xb08/+0xb10, T)
    pub(crate) chip_0x20d0: U64,
    pub(crate) chip_0x20d8: U64,
    /// +0x109c feature bit 25 (was +0xb18, T)
    pub(crate) chip_0x650_bit25: u32,
    pad_0x10a0: Pad<4>,
    /// +0x10a4 `getEnabledNumUSCs()` (was +0xb20, T)
    pub(crate) enabled_uscs: u32,
    /// +0x10a8 `chip+0x2040`, one bit per MCache window (was +0xb24, T)
    pub(crate) chip_0x2040: U64,
    /// +0x10b0 new: 0 (T)
    pub(crate) zero_0x10b0: u32,
    /// +0x10b4 new: `chip+0x11730 & 1` (T, the value I: 0, not verified)
    pub(crate) chip_0x11730_bit0: u32,
    /// +0x10b8…+0x10cb: 14.8.3's `uat_config` (+0xb40) is gone (T)
    pad_0x10b8: Pad<0x14>,
    /// +0x10cc the GPTBAT base (was +0xb44, +0x588, T)
    pub(crate) vtbl_0x1018: U64,
    /// +0x10d4 the core ID and the revision ID, +0x10dc the cores (was
    /// +0xb4c/+0xb54, T)
    pub(crate) core_id: [u32; 2],
    pub(crate) chip_0x47c: u32,
    /// +0x10e0…+0x263b the perf-state block (was +0xb58, +0x588; 0x920
    /// larger, T). +0x10e0 table A's state count − 1
    pub(crate) perf_max_pstate: u32,
    /// +0x10e4 table A's clocks, MHz (T by the next field)
    pub(crate) perf_freq_mhz: [u32; 0x10],
    /// +0x1124 table A's volts, `[[u32; 16]; 16]` (was 8 slots, T)
    pub(crate) perf_volt_mv: [[u32; 0x10]; 0x10],
    /// +0x1524 table A's SRAM volts, the same (T)
    pub(crate) perf_volt_sram_mv: [[u32; 0x10]; 0x10],
    /// +0x1924 table B's clocks; +0x1964/+0x19a4 HwDataA's SRAM power
    /// scales (14.8.3's order; T by +0x19e4)
    pub(crate) perf2_freq_mhz: [u32; 0x10],
    pub(crate) sram_scale: [u32; 0x10],
    pub(crate) sram_scale_2: [u32; 0x10],
    /// +0x19e4 each state's power, % of the top state's, now f32 (T)
    pub(crate) perf_pwr_pct: [F32; 0x10],
    /// +0x1a24 each state's clock, % of the base-to-top span, now f32:
    /// 100.0·(f − f_base)/(f_top − f_base) (T)
    pub(crate) perf_freq_pct: [F32; 0x10],
    /// +0x1a64 new, never written by the kext; the firmware reads it next
    /// to the AFR clocks (T)
    pub(crate) perf_0x1a64: [F32; 0x10],
    /// +0x1aa4 new, unused: no kext writer, and the grab reads +0x1a64…
    /// +0x1aa0, then +0x1ae4 (`armfw_g15c_272` 0xfffffc0000033240…324c);
    /// zero (T)
    pub(crate) perf_0x1aa4: [u32; 0x10],
    /// +0x1ae4 the state-map words, MAP_A then MAP_B at +0x1b24 (was
    /// +0x10dc; Arm P&P 0xfffffe0008ba55d0, T)
    pub(crate) perf_state_map: [u32; 0x20],
    /// +0x1b64…+0x1cab the CS table (was +0x115c): count − 1, the cap,
    /// clocks at +0x1b6c, volts at +0x1bac, SRAM volts at +0x1c2c (Arm
    /// P&P 0xfffffe0008ba5288; the grab copies 0x148 bytes, T)
    pub(crate) cs_max_pstate: u32,
    pub(crate) cs_cap: u32,
    pub(crate) cs_freq_mhz: [u32; 0x10],
    pub(crate) cs_volt_mv: [[u32; 2]; 0x10],
    pub(crate) cs_volt_sram_mv: [[u32; 2]; 0x10],
    /// +0x1cac the AFR table, 16 states (was 8 at +0x12a4, T)
    pub(crate) afr_max_pstate: u32,
    pub(crate) afr_cap: u32,
    pub(crate) afr_freq_mhz: [u32; 0x10],
    pub(crate) afr_volt_mv: [[u32; 2]; 0x10],
    pub(crate) afr_volt_sram_mv: [[u32; 2]; 0x10],
    /// +0x1df4 table B (bzero 0x848, T): its count − 1, clocks, volts and
    /// SRAM volts, `[[u32; 16]; 16]`
    pub(crate) perf2_max_pstate: u32,
    pub(crate) perf2_freq_mhz_2: [u32; 0x10],
    pub(crate) perf2_volt_mv: [[u32; 0x10]; 0x10],
    pub(crate) perf2_volt_sram_mv: [[u32; 0x10]; 0x10],
    /// +0x2638…+0x2643 the block's end, unwritten (T)
    pad_0x2638: Pad<0xc>,
    /// +0x2644 the fence buffer address (vtbl 0xe70, was 0xdd0 at +0x179c;
    /// +0xea8, T)
    pub(crate) fence_buf: [u32; 2],
    pad_0x264c: Pad<0x14>,
    /// +0x2660 `chip+0x688` (was +0x17b8, +0xea8, T)
    pub(crate) chip_0x688: u32,
    /// +0x2664 `((feat >> 4) & 4) | ((feat >> 6) & 2)` (was +0x17bc = 0;
    /// T formula; 6 from 14.8.3's feature bits 6 and 7, not verified)
    pub(crate) chip_0x68c: u32,
    /// +0x2668…+0x2673 the core-config masks (was +0x17c0, +0xea8, T)
    pub(crate) mask_0x2668: [u32; 2],
    pub(crate) mask_0x2670: u32,
    /// +0x2674…+0x268b the rest of the Arm tail, 0 (T)
    pad_0x2674: Pad<0x18>,
    /// +0x268c new: the enabled core count (T)
    pub(crate) enabled_cores: u32,
    pad_0x2690: Pad<4>,
    /// +0x2694 new: 1 (T)
    pub(crate) one_0x2694: u32,
    pad_0x2698: Pad<8>,
    /// +0x26a0 new: abstime − conttime (`setAbsTimeOffset`, u64; T, 0 I)
    pub(crate) abs_cont_offset: U64,
    pad_0x26a8: Pad<8>,
    /// +0x26b0 new: `chip+0x11bf0`, else `chip+0x11bd8` (u64; T, the
    /// value not given: 0)
    pub(crate) chip_0x11bf0: U64,
    pad_0x26b8: Pad<4>,
    /// +0x26bc 1: 14.8.3's +0x1800 pair as one word, the UMA page-pool
    /// gate (T value, I mapping)
    pub(crate) one_0x26bc: u32,
    /// +0x26c0 `chip+0x654` bit 5, +0x26c4 0 when it is set (I: 14.8.3's
    /// +0x1808 at its neighbours' +0xeb8)
    pub(crate) feat_0x26c0: [u32; 2],
    /// +0x26c8 0x1_0000_0001, now the power-up gate with +0xfc0 (was
    /// +0x1810; Arm `initFirmwareData`, the grab stores it at
    /// 0xfffffc0000033424, T)
    pub(crate) pwr_gate_0x26c8: [u32; 2],
    /// +0x26d0 feature bit 7, +0x26d4 0 (I: 14.8.3's +0x1818 at +0xeb8)
    pub(crate) feat_0x26d0: [u32; 2],
    /// +0x26d8…+0x2707 the FSTP masks, all ones (was +0x1820, +0xeb8, T)
    pub(crate) ones_0x26d8: [u8; 0x30],
    pad_0x2708: Pad<0x20>,
    /// +0x2728 0x1_0000_0000 (T)
    pub(crate) const_0x2728: U64,
    pad_0x2730: Pad<0x2c>,
    /// +0x275c 1 (T)
    pub(crate) one_0x275c: u32,
    pad_0x2760: Pad<0x2a>,
    /// +0x278a 1 (T; 2-aligned)
    pub(crate) one_0x278a: [u8; 4],
    pad_0x278e: Pad<2>,
}

/// HwDataA, 0x6e48 → 0x9c68 (fw272-hwdata.md §1.5; size: the base P&P bzero
/// 0xfffffe0008b80418; writer: the Arm P&P 0xfffffe0008ba45ac). Only the
/// head (0x00–0x37) keeps its offsets.
///
/// The blocks 27.2 carries over from 14.8.3 are byte regions here, filled
/// by moving a 14.8.3 HwDataA built by the V14_7 code (`HWDATA_A_MOVES`),
/// so `super::g15::HwDataA` documents their fields. A region whose block
/// the spec gives two shifts for (+a/+b) is moved at +a: where its extra 4
/// bytes go is not traced, so its fields past the first are I. The fields
/// 27.2 changes are named and written after the moves.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct HwDataAV27_2 {
    /// +0x00…+0x37 the head, unchanged (14.8.3's +0x00, T)
    pub(crate) head: [u8; 0x38],
    pad_0x38: Pad<4>,
    /// +0x3c…+0x4b the Arm override: 0, base·100, 1, c34·100 (was +0x40;
    /// Arm P&P 0xfffffe0008ba6b9c, T)
    pub(crate) arm_0x3c: [u32; 4],
    pad_0x4c: Pad<4>,
    /// +0x50 100 (was +0x54, base, T)
    pub(crate) const_0x50: u32,
    /// +0x54…+0xaf the per-domain records' rest: a second record (+0x5c,
    /// +0x64, +0x68, +0x7c…+0x90) and a new pair at +0x9c (T offsets; no
    /// values in the spec: zero, not verified)
    pub(crate) dom_0x54: [u8; 0x5c],
    /// +0xb0…+0x20f the P&E block, the static config (was +0x60, +0x50,
    /// base memcpy, T)
    pub(crate) static_config: [u8; 0x160],
    /// +0x210…+0x9c7 firmware-owned perf counters and tables (T)
    pub(crate) fw_0x210: [u8; 0x7b8],
    /// +0x9c8…+0xa4b the power config: 14.8.3's +0x658…+0x6d7 at +0x370
    /// (T start, I past it)
    pub(crate) pwr_cfg_0x9c8: [u8; 0x84],
    /// +0xa4c the power config's last word, 14.8.3's +0x6d8 `chip+0x27f4`
    /// at +0x374 (T, the block's end)
    pub(crate) pwr_cfg_0xa4c: u32,
    pad_0xa50: Pad<0x30>,
    /// +0xa80…+0xb07 the PPM governor: 14.8.3's +0x6f0…+0x777 at +0x390
    /// (T start; its end moves +0x394, so I past the start)
    pub(crate) ppm_0xa80: [u8; 0x88],
    pad_0xb08: Pad<0x30>,
    /// +0xb38…+0xb9f the perf controller's head: 14.8.3's +0x788…+0x7ef
    /// at +0x3b0 (base P&P +0xb38, +0xb54…+0xb9c; Arm P&P +0xb40…+0xb50;
    /// the firmware's controller to +0xba0, T)
    pub(crate) perf_0xb38: [u8; 0x14],
    /// +0xb4c new: `gpu-perf-dz` (`chip+0x1151c`; Arm P&P's store at
    /// 0xfffffe0008ba5748, T; t6034's value not verified: 0)
    pub(crate) perf_dz_0xb4c: u32,
    pub(crate) perf_0xb50: [u8; 0x4c],
    /// +0xb9c the target utilization − the dead zone (was +0x7ec = the
    /// target, base P&P, T)
    pub(crate) perf_tgt_util_2: u32,
    pad_0xba0: Pad<4>,
    /// +0xba4 new: `gpu-perf-dz` again (base P&P, T)
    pub(crate) perf_dz_0xba4: u32,
    /// +0xba8…+0xbcb firmware-owned (u64s at +0xbb0/+0xbb8, T): 27.2's
    /// four extra bytes enter here, in 14.8.3's +0x7f4…+0x80b, which no
    /// kext writes, so where is not located (I); zero
    pub(crate) perf_0xba8: [u8; 0x24],
    /// +0xbcc…+0xbd7 the perf controller's tail: 14.8.3's +0x818…+0x823 at
    /// +0x3b4 (base P&P +0xbcc/+0xbd0; the firmware's controller from
    /// +0xbc0, T)
    pub(crate) perf_0xbcc: [u8; 0xc],
    pad_0xbd8: Pad<0x27>,
    /// +0xbff…+0x21fe new: three 16-entry arrays (Arm P&P, after the base
    /// P&P call, 0xfffffe0008ba4640, T): 0x100 bytes zero at
    /// +0xbff + 0x100i, 0x40 bytes of u16 0x8000 at +0x1bff + 0x40i, and
    /// 0x20 bytes zero at +0x1fff + 0x20i (u8, u32, u32, u8, u32, u32, u8,
    /// u32, u32, 5 × u8)
    pub(crate) fill_0xbff: [[u8; 0x100]; 0x10],
    pub(crate) fill_0x1bff: [[u8; 0x40]; 0x10],
    pub(crate) fill_0x1fff: [[u8; 0x20]; 0x10],
    pad_0x21ff: Pad<1>,
    /// +0x2200…+0x2227 the clock descriptor (was +0x838…+0x85b),
    /// reordered: its order is not in the spec, so it is not placed (zero,
    /// not verified)
    pub(crate) clock_0x2200: [u8; 0x28],
    /// +0x2228…+0x223b the memory threshold and limiter: 14.8.3's +0x860 at
    /// +0x19c8 (T)
    pub(crate) mem_0x2228: [u8; 0x14],
    pad_0x223c: Pad<0x34>,
    /// +0x2270…+0x272f the fast-die controller, record 0 of a 0x4c0 array
    /// (was +0x8a8): its sensor mask at +0x2278, now 8-aligned (T), and
    /// 14.8.3's fields after it at the mask's +0x19cc (I)
    pub(crate) fastdie_0x2270: [u8; 8],
    pub(crate) fastdie_sensor_mask: U64,
    pub(crate) fastdie_0x2280: [u8; 0x4b0],
    /// +0x2730…+0x2bf5 new: the Turbo controller, its enable 0 (the kext's
    /// default, T)
    pub(crate) turbo_0x2730: [u8; 0x4c6],
    pad_0x2bf6: Pad<0x8a>,
    /// +0x2c80…+0x2cef the PI record: 14.8.3's +0xde0 at +0x1ea0 (T);
    /// +0x2c88 = 100·c34 (T)
    pub(crate) pi_0x2c80: [u8; 8],
    pub(crate) perf_0x2c88: u32,
    pub(crate) pi_0x2c8c: [u8; 0x64],
    /// +0x2cf0…+0x2e9f the power zones and average power, zeroed by Arm
    /// P&P: 14.8.3's +0x1088…+0x11d3 at +0x1c68 and +0x11d8…+0x1207 at
    /// +0x1c6c; +0x2e40 and +0x2e9c new zeros, and the zeroed tail 0x14
    /// longer (T)
    pub(crate) zones_0x2cf0: [u8; 0x1b0],
    pad_0x2ea0: Pad<0xb0>,
    /// +0x2f50…+0x3033 the SE perf governor: 14.8.3's +0x12d0…+0x13af at
    /// +0x1c80 (T start; its end moves +0x1c84, so I past the start)
    pub(crate) gov_0x2f50: [u8; 0xe4],
    pad_0x3034: Pad<0x2c>,
    /// +0x3060 65536.0f: 14.8.3's +0x13d8 at +0x3070's shift (I)
    pub(crate) se_0x3060: F32,
    pad_0x3064: Pad<0xc>,
    /// +0x3070 `chip+0x10ea0`: the minimum duty cycle, c34·100 (was
    /// +0x13e8, Arm P&P, T)
    pub(crate) se_0x3070: [u32; 2],
    /// +0x3078…+0x332f: the new AvgPStateLimiter controller at +0x3138 and
    /// +0x3238…+0x332b, its enable 0 (the kext's default, T)
    pub(crate) avgp_0x3078: [u8; 0x2b8],
    /// +0x3330…+0x3747 the SoC hot config: 14.8.3's +0x1490 at +0x1ea0 (T)
    pub(crate) sochot_0x3330: U64,
    pub(crate) sochot_0x3338: U64,
    pub(crate) sochot_0x3340: u32,
    pub(crate) sochot_0x3344: u32,
    pub(crate) sochot_0x3348: [u8; 0x400],
    /// +0x3748…+0x8be7 the MTR block, zeroed (was +0x18a8 + 0x4c18, now
    /// 0x54a0, T)
    pub(crate) mtr_0x3748: [u8; 0x1468],
    /// +0x4bb0 new: the FW VA of the 8-byte block-2 buffer (`this+0x368`;
    /// `AGXArmFirmware::init`, T)
    pub(crate) buf_0x368_fwva: U64,
    /// +0x4bb8 the MTR sensor mask, +0x4bc8 the count (was +0x24a8/+0x24b8,
    /// +0x2710, T)
    pub(crate) mtr_mask: [u32; 4],
    pub(crate) mtr_count: u32,
    pub(crate) mtr_0x4bcc: [u8; 0x4000],
    /// +0x8bcc `chip+0x2020`, now a u64 (was a u32 at +0x64bc; Arm P&P, T)
    pub(crate) chip_0x2020: U64,
    pad_0x8bd4: Pad<0x14>,
    /// +0x8be8…+0x92c7 the DPEPPT block, mirrored at PB +0xf0 (was +0x64c0,
    /// +0x2728, T)
    pub(crate) dpeppt: [u8; 0x6e0],
    /// +0x92c8…+0x935f the DPE leakage update (was +0x6ba0, +0x2728, T)
    pub(crate) dpe_leak: [u8; 0x98],
    /// +0x9360 the AON PTD state (was +0x6c58, restructured): +0x00 the FW
    /// VA of the 0xe4 entries buffer, which the firmware dereferences
    /// (`getAONPTDFromOSDictionary` 0xfffffe0008b51770, Arm P&P
    /// 0xfffffe0008ba6e90, T)
    pub(crate) aonptd_entries_fwva: U64,
    /// +0x9368 the "g" identifiers, 16 (I: the IDs start at state +0x08,
    /// T; 14.8.3's 8 widened to fill up to the first mask)
    pub(crate) aonptd_ids_g: [[u8; 4]; 16],
    /// +0x93a8 the "g" found mask (state +0x48, T)
    pub(crate) aonptd_found_g: U64,
    /// +0x93b0 the "r" identifiers (I: 14.8.3's spacing)
    pub(crate) aonptd_ids_r: [[u8; 4]; 2],
    /// +0x93b8 the "r" found mask (state +0x58, T)
    pub(crate) aonptd_found_r: U64,
    /// +0x93c0 "RT0f" (I: 14.8.3's spacing)
    pub(crate) aonptd_id_f: [u8; 4],
    /// +0x93c4 the "f" found mask (state +0x64, T)
    pub(crate) aonptd_found_f: U64,
    /// +0x93cc…+0x9407 the source types 3–5 (state +0x70…+0x9c; G15X
    /// `populateAONPTDIdentifiers` 0xfffffe0008bbdb98, T): their
    /// identifiers are not in the spec (zero, not verified)
    pub(crate) aonptd_0x93cc: [u8; 0x3c],
    /// +0x9408 new: `chip+0x11734` (Arm P&P, T; the value not given: 0)
    pub(crate) chip_0x11734: u32,
    pub(crate) fw_0x940c: [u8; 0x690],
    /// +0x9a9c the AP timebase at fill time (was +0x6d34, +0x2d68, T)
    pub(crate) timestamp_0x9a9c: U64,
    pad_0x9aa4: Pad<0x44>,
    /// +0x9ae8 `chip+0x690` bits 17 and 33 (was +0x6d80, bits 18/31, T)
    pub(crate) feat_0x9ae8: [u32; 2],
    pad_0x9af0: Pad<4>,
    /// +0x9af4…+0x9bd3 the leakage arrays: 3 × `[u32; 16]` (was 8) and
    /// one of 8 (T); the core's first and the SRAM's third, 14.8.3's order
    /// (I). Zero on G15C
    pub(crate) core_leak: [u32; 16],
    pub(crate) leak_0x9b34: [u32; 16],
    pub(crate) sram_leak: [u32; 16],
    pub(crate) leak_0x9bb4: [u32; 8],
    /// +0x9bd4…+0x9c67 the firmware's tail; +0x9c35 the TGraph enable
    /// (`enableTGraph`, runtime, T)
    pub(crate) fw_0x9bd4: [u8; 0x94],
}

/// The 14.8.3 HwDataA blocks 27.2 keeps: (14.8.3 start, 14.8.3 end, 27.2
/// start), fw272-hwdata.md §1.5's shifts. The fields 27.2 changes inside
/// them are written after the moves.
pub(crate) const HWDATA_A_MOVES: &[(usize, usize, usize)] = &[
    // the head, the Arm override, 100, the P&E block
    (0x00, 0x38, 0x00),
    (0x40, 0x50, 0x3c),
    (0x54, 0x58, 0x50),
    (0x60, 0x1c0, 0xb0),
    // the power config (+0x370), its last word (+0x374)
    (0x658, 0x6d8, 0x9c8),
    (0x6d8, 0x6dc, 0xa4c),
    // the PPM governor (+0x390), the perf controller (+0x3b0 to +0x7ef,
    // +0x3b4 from +0x818; the zero gap between not moved)
    (0x6f0, 0x778, 0xa80),
    (0x788, 0x7f0, 0xb38),
    (0x818, 0x824, 0xbcc),
    // the memory threshold and limiter (+0x19c8), the fast-die
    // controller from its sensor mask (+0x19cc), the PI record (+0x1ea0)
    (0x860, 0x874, 0x2228),
    (0x8ac, 0x944, 0x2278),
    (0xde0, 0xe50, 0x2c80),
    // the power zones and average power (+0x1c68 to +0x11d3, +0x1c6c from
    // +0x11d8), the SE governor (+0x1c80), its 65536.0 and the duty-cycle
    // pair (+0x1c88)
    (0x1088, 0x11d4, 0x2cf0),
    (0x11d8, 0x1208, 0x2e44),
    (0x12d0, 0x13b0, 0x2f50),
    (0x13d8, 0x13f0, 0x3060),
    // the SoC hot config (+0x1ea0), the MTR mask and count (+0x2710)
    (0x1490, 0x18a8, 0x3330),
    (0x24a8, 0x24bc, 0x4bb8),
    // the DPEPPT block and the DPE leakage update (+0x2728)
    (0x64c0, 0x6c38, 0x8be8),
    // the timestamp and the feature flags (+0x2d68)
    (0x6d34, 0x6d3c, 0x9a9c),
    (0x6d80, 0x6d88, 0x9ae8),
    // the core and SRAM leakage, 8 of 16 each
    (0x6d8c, 0x6dac, 0x9af4),
    (0x6dcc, 0x6dec, 0x9b74),
];

/// Copies `HWDATA_A_MOVES` from a 14.8.3 HwDataA's bytes to a 27.2 one's.
pub(crate) fn move_hwdata_a(dst: &mut [u8], src: &[u8]) {
    for &(start, end, at) in HWDATA_A_MOVES {
        dst[at..at + (end - start)].copy_from_slice(&src[start..end]);
    }
}

/// Where `HWDATA_A_MOVES` puts 14.8.3's byte `off`, or `usize::MAX`.
const fn moved(off: usize) -> usize {
    let mut i = 0;
    while i < HWDATA_A_MOVES.len() {
        let (s, e, d) = HWDATA_A_MOVES[i];
        if s <= off && off < e {
            return d + (off - s);
        }
        i += 1;
    }
    usize::MAX
}

/// The moves stay inside both layouts and do not overlap in 27.2's.
const fn moves_ok(moves: &[(usize, usize, usize)], src_size: usize, dst_size: usize) -> bool {
    let mut i = 0;
    while i < moves.len() {
        let (s, e, d) = moves[i];
        if s >= e || e > src_size || d + (e - s) > dst_size {
            return false;
        }
        let mut j = i + 1;
        while j < moves.len() {
            let (s2, e2, d2) = moves[j];
            if d < d2 + (e2 - s2) && d2 < d + (e - s) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const _: () = assert!(moves_ok(
    HWDATA_A_MOVES,
    size_of::<super::g15::HwDataA>(),
    size_of::<HwDataAV27_2>()
));

impl GpuStruct for HwDataBV27_2 {
    type Raw<'a> = HwDataBV27_2;
}
impl GpuStruct for HwDataAV27_2 {
    type Raw<'a> = HwDataAV27_2;
}
impl GpuStruct for ChannelTableV27_2 {
    type Raw<'a> = ChannelTableV27_2;
}
impl GpuStruct for PBTableV27_2 {
    type Raw<'a> = PBTableV27_2;
}

default_zeroed!(HwDataBV27_2);
default_zeroed!(HwDataAV27_2);
default_zeroed!(ChannelTableV27_2);
default_zeroed!(PBTableV27_2);
default_zeroed!(FmcHeaderV27_2);

// Compile-time layout checks against fw272-init.md and fw272-hwdata.md: a
// mismatch fails the build.
macro_rules! at {
    ($t:ty, $f:ident, $off:expr) => {
        const _: () = assert!(core::mem::offset_of!($t, $f) == $off);
    };
}

const _: () = assert!(size_of::<FmcHeaderV27_2>() == 0xc8);
const _: () = assert!(size_of::<ChannelTableV27_2>() == 0x4b8);
const _: () = assert!(size_of::<PBTableV27_2>() == 0x1258);
const _: () = assert!(size_of::<WindowRecordV27_2>() == 0x28);
const _: () = assert!(size_of::<HwDataBV27_2>() == 0x2790);
const _: () = assert!(size_of::<HwDataAV27_2>() == 0x9c68);
const _: () = assert!(AONPTD_SIZE == 0xe4);
// The magic's low 16 bits are the channel table's size.
const _: () = assert!(FMC_MAGIC_V27_2 & 0xffff == 0x4b8);

at!(FmcHeaderV27_2, base, 0x00);
at!(FmcHeaderV27_2, buf_0x358_fwva, 0xc0);

at!(ChannelTableV27_2, hwdata_b_fwva, 0x00);
at!(ChannelTableV27_2, fwbrn_fwva, 0x08);
at!(ChannelTableV27_2, buf_0x248_fwva, 0x10);
at!(ChannelTableV27_2, pwr_assert_ctr_fwva, 0x18);
at!(ChannelTableV27_2, ring, 0x20);
at!(ChannelTableV27_2, special, 0x1a0);
at!(ChannelTableV27_2, ptr_block, 0x1c0);
at!(ChannelTableV27_2, buf_0x900_fwva, 0x200);
at!(ChannelTableV27_2, pad_0x208, 0x208);
at!(ChannelTableV27_2, log_enable, 0x250);
at!(ChannelTableV27_2, buf_0x218_fwva, 0x254);
at!(ChannelTableV27_2, buf_0x220_fwva, 0x25c);
at!(ChannelTableV27_2, buf_0x228_fwva, 0x264);
at!(ChannelTableV27_2, buf_0x238_fwva, 0x26c);
at!(ChannelTableV27_2, chip_0x125a0_fwva, 0x2c8);
at!(ChannelTableV27_2, pb_desc_table_gpuva, 0x2d0);
at!(ChannelTableV27_2, pb_desc_table_fwva, 0x2d8);
at!(ChannelTableV27_2, umap_pool_pa, 0x2e0);
at!(ChannelTableV27_2, umap_pool_fwva, 0x2e8);
at!(ChannelTableV27_2, zero_0x2f0, 0x2f0);
at!(ChannelTableV27_2, chip_0x10d5c, 0x2f8);
at!(ChannelTableV27_2, chip_0x10dcc, 0x2fc);
at!(ChannelTableV27_2, tail_0x3d8, 0x3d8);
at!(ChannelTableV27_2, pad_0x481, 0x481);
const _: () =
    assert!(core::mem::offset_of!(ChannelTableV27_2, tail_0x3d8) + CHANNEL_TAIL_HWDATA_A == 0x479);
// HwDataA's u64 is the tail's last 8 bytes.
const _: () = assert!(
    core::mem::offset_of!(ChannelTableV27_2, tail_0x3d8) + CHANNEL_TAIL_HWDATA_A + 8
        == core::mem::offset_of!(ChannelTableV27_2, pad_0x481)
);

at!(PBTableV27_2, header, 0x00);
at!(PBTableV27_2, zero_0x04, 0x04);
at!(PBTableV27_2, zero_0x08, 0x08);
at!(PBTableV27_2, dm_pause_mode, 0x0c);
at!(PBTableV27_2, zero_0x10, 0x10);
at!(PBTableV27_2, dm_pause_timer, 0x14);
at!(PBTableV27_2, zero_0x18, 0x18);
at!(PBTableV27_2, disable_cswitch, 0x1c);
at!(PBTableV27_2, frg_timeout, 0x20);
at!(PBTableV27_2, relaxed_cl_kill_timeout, 0x24);
at!(PBTableV27_2, frg_task_timeout, 0x28);
at!(PBTableV27_2, chip_0x6c0, 0x2c);
at!(PBTableV27_2, chip_0x690_bit0, 0x30);
at!(PBTableV27_2, feature_bit1, 0x34);
at!(PBTableV27_2, chip_0x699_bit2, 0x38);
at!(PBTableV27_2, noise_suppression, 0x3c);
at!(PBTableV27_2, const_0x40, 0x40);
at!(PBTableV27_2, zero_0x44, 0x44);
at!(PBTableV27_2, zero_0x48, 0x48);
at!(PBTableV27_2, zero_0x4c, 0x4c);
at!(PBTableV27_2, zero_0x50, 0x50);
at!(PBTableV27_2, zero_0x54, 0x54);
at!(PBTableV27_2, chip_0x728, 0x58);
at!(PBTableV27_2, chip_0x72a, 0x5a);
at!(PBTableV27_2, chip_0x72c, 0x5c);
at!(PBTableV27_2, zero_0x5e, 0x5e);
at!(PBTableV27_2, qos_billing, 0x62);
at!(PBTableV27_2, chip_0x19920_eq0, 0x66);
at!(PBTableV27_2, panic_on_pm_oom, 0x6a);
at!(PBTableV27_2, power_sample_period, 0x6e);
at!(PBTableV27_2, cmd_submission_enabled, 0x7c);
at!(PBTableV27_2, submit_in_progress, 0x80);
at!(PBTableV27_2, submit_count, 0x84);
at!(PBTableV27_2, pwr_target, 0x88);
at!(PBTableV27_2, override_controller, 0x94);
at!(PBTableV27_2, chip_0x6bc, 0x98);
at!(PBTableV27_2, zero_0xa0, 0xa0);
at!(PBTableV27_2, fw_util, 0xa8);
at!(PBTableV27_2, deadline_override, 0xe8);
at!(PBTableV27_2, dpeppt, 0xf0);
at!(PBTableV27_2, idleoff, 0x7c8);
at!(PBTableV27_2, one_0x7f0, 0x7f0);
at!(PBTableV27_2, chip_0x2198, 0x7f8);
at!(PBTableV27_2, chip_0x2194, 0x7fc);
at!(PBTableV27_2, pad_0x800, 0x800);
at!(PBTableV27_2, progress, 0x99c);
at!(PBTableV27_2, ternary_0x9bc, 0x9bc);
at!(PBTableV27_2, ternary_0x9c0, 0x9c0);
at!(PBTableV27_2, ternary_0x9c4, 0x9c4);
at!(PBTableV27_2, zero_0x9c8, 0x9c8);
at!(PBTableV27_2, cl_ctx_switch_timeout, 0x9cc);
at!(PBTableV27_2, cl_kill_timeout, 0x9d0);
at!(PBTableV27_2, phase1_cdm_ctx_switch_timeout, 0x9d4);
at!(PBTableV27_2, frg_ctx_switch_timeout, 0x9d8);
at!(PBTableV27_2, frg_kill_timeout, 0x9dc);
at!(PBTableV27_2, zero_0x9e0, 0x9e0);
at!(PBTableV27_2, cdm_backoff_timeout, 0x9e4);
at!(PBTableV27_2, fw_util_perf_tunables, 0x9e5);
at!(PBTableV27_2, tail_0x1211, 0x1211);
at!(PBTableV27_2, soft_fault, 0x1235);
at!(PBTableV27_2, one_0x1239, 0x1239);
at!(PBTableV27_2, riart_ulevel_mask, 0x123d);
at!(PBTableV27_2, riart_tt_disabled, 0x1241);
at!(PBTableV27_2, zero_0x1245, 0x1245);
at!(PBTableV27_2, tail_0x1249, 0x1249);

at!(WindowRecordV27_2, base, 0x00);
at!(WindowRecordV27_2, fwva, 0x08);
at!(WindowRecordV27_2, kind_size, 0x10);
at!(WindowRecordV27_2, size, 0x14);
at!(WindowRecordV27_2, src_0x210, 0x18);
at!(WindowRecordV27_2, flag, 0x20);

at!(HwDataBV27_2, egart_fwva, 0x28);
at!(HwDataBV27_2, ts_area_base, 0x30);
at!(HwDataBV27_2, chip_records, 0x38);
at!(HwDataBV27_2, chip_records_hi, 0x338);
at!(HwDataBV27_2, vtbl_0xdc8, 0x638);
at!(HwDataBV27_2, windows, 0x640);
at!(HwDataBV27_2, arm_0xfa0, 0xfa0);
at!(HwDataBV27_2, coredump_buf, 0xfa8);
at!(HwDataBV27_2, chip_0x20c0, 0xfb0);
at!(HwDataBV27_2, chip_0x20c8, 0xfb8);
at!(HwDataBV27_2, probe_da2_bit1, 0xfc0);
at!(HwDataBV27_2, chip_0x650_bit8, 0xfc4);
at!(HwDataBV27_2, probe_da2_bit4, 0xfc8);
at!(HwDataBV27_2, zero_0xfcc, 0xfcc);
at!(HwDataBV27_2, zero_0xfd0, 0xfd0);
at!(HwDataBV27_2, zero_0xfd4, 0xfd4);
at!(HwDataBV27_2, one_0xfd8, 0xfd8);
at!(HwDataBV27_2, chip_0x650_bit11, 0xfdc);
at!(HwDataBV27_2, chip_0xca_bit12, 0xfe0);
at!(HwDataBV27_2, one_0xfe4, 0xfe4);
at!(HwDataBV27_2, zero_0xfe8, 0xfe8);
at!(HwDataBV27_2, base_clock_khz, 0xfec);
at!(HwDataBV27_2, power_sample_period, 0xff0);
at!(HwDataBV27_2, vtbl_0xe68, 0xff4);
at!(HwDataBV27_2, chip_0x664, 0xff8);
at!(HwDataBV27_2, one_0xffc, 0xffc);
at!(HwDataBV27_2, const_0x1000, 0x1000);
at!(HwDataBV27_2, chip_0x2034, 0x100c);
at!(HwDataBV27_2, vtbl_0xb18_flag, 0x1010);
at!(HwDataBV27_2, zero_0x1018, 0x1018);
at!(HwDataBV27_2, pmp_sw_interrupt, 0x101c);
at!(HwDataBV27_2, const_0x1020, 0x1020);
at!(HwDataBV27_2, chip_0x19d8, 0x1024);
at!(HwDataBV27_2, chip_0xca_bit19, 0x1028);
at!(HwDataBV27_2, chip_0x6c2_flag, 0x102c);
at!(HwDataBV27_2, zero_0x1030, 0x1030);
at!(HwDataBV27_2, chip_0x2028, 0x1040);
at!(HwDataBV27_2, chip_0x2030, 0x1048);
at!(HwDataBV27_2, const_0x104c, 0x104c);
at!(HwDataBV27_2, const_0x1054, 0x1054);
at!(HwDataBV27_2, zero_0x105c, 0x105c);
at!(HwDataBV27_2, chip_0x650_bit21, 0x1060);
at!(HwDataBV27_2, chip_0x650_bit26, 0x1064);
at!(HwDataBV27_2, chip_0x2064, 0x1068);
at!(HwDataBV27_2, zero_0x106c, 0x106c);
at!(HwDataBV27_2, zero_0x1078, 0x1078);
at!(HwDataBV27_2, zero_0x1080, 0x1080);
at!(HwDataBV27_2, chip_0x654_bit12, 0x1084);
at!(HwDataBV27_2, chip_0x40e, 0x1088);
at!(HwDataBV27_2, chip_0x20d0, 0x108c);
at!(HwDataBV27_2, chip_0x20d8, 0x1094);
at!(HwDataBV27_2, chip_0x650_bit25, 0x109c);
at!(HwDataBV27_2, enabled_uscs, 0x10a4);
at!(HwDataBV27_2, chip_0x2040, 0x10a8);
at!(HwDataBV27_2, zero_0x10b0, 0x10b0);
at!(HwDataBV27_2, chip_0x11730_bit0, 0x10b4);
at!(HwDataBV27_2, vtbl_0x1018, 0x10cc);
at!(HwDataBV27_2, core_id, 0x10d4);
at!(HwDataBV27_2, chip_0x47c, 0x10dc);
at!(HwDataBV27_2, perf_max_pstate, 0x10e0);
at!(HwDataBV27_2, perf_freq_mhz, 0x10e4);
at!(HwDataBV27_2, perf_volt_mv, 0x1124);
at!(HwDataBV27_2, perf_volt_sram_mv, 0x1524);
at!(HwDataBV27_2, perf2_freq_mhz, 0x1924);
at!(HwDataBV27_2, sram_scale, 0x1964);
at!(HwDataBV27_2, sram_scale_2, 0x19a4);
at!(HwDataBV27_2, perf_pwr_pct, 0x19e4);
at!(HwDataBV27_2, perf_freq_pct, 0x1a24);
at!(HwDataBV27_2, perf_0x1a64, 0x1a64);
at!(HwDataBV27_2, perf_0x1aa4, 0x1aa4);
at!(HwDataBV27_2, perf_state_map, 0x1ae4);
at!(HwDataBV27_2, cs_max_pstate, 0x1b64);
at!(HwDataBV27_2, cs_cap, 0x1b68);
at!(HwDataBV27_2, cs_freq_mhz, 0x1b6c);
at!(HwDataBV27_2, cs_volt_mv, 0x1bac);
at!(HwDataBV27_2, cs_volt_sram_mv, 0x1c2c);
at!(HwDataBV27_2, afr_max_pstate, 0x1cac);
at!(HwDataBV27_2, afr_cap, 0x1cb0);
at!(HwDataBV27_2, afr_freq_mhz, 0x1cb4);
at!(HwDataBV27_2, afr_volt_mv, 0x1cf4);
at!(HwDataBV27_2, afr_volt_sram_mv, 0x1d74);
at!(HwDataBV27_2, perf2_max_pstate, 0x1df4);
at!(HwDataBV27_2, perf2_freq_mhz_2, 0x1df8);
at!(HwDataBV27_2, perf2_volt_mv, 0x1e38);
at!(HwDataBV27_2, perf2_volt_sram_mv, 0x2238);
at!(HwDataBV27_2, pad_0x2638, 0x2638);
at!(HwDataBV27_2, fence_buf, 0x2644);
at!(HwDataBV27_2, chip_0x688, 0x2660);
at!(HwDataBV27_2, chip_0x68c, 0x2664);
at!(HwDataBV27_2, mask_0x2668, 0x2668);
at!(HwDataBV27_2, mask_0x2670, 0x2670);
at!(HwDataBV27_2, enabled_cores, 0x268c);
at!(HwDataBV27_2, one_0x2694, 0x2694);
at!(HwDataBV27_2, abs_cont_offset, 0x26a0);
at!(HwDataBV27_2, chip_0x11bf0, 0x26b0);
at!(HwDataBV27_2, one_0x26bc, 0x26bc);
at!(HwDataBV27_2, feat_0x26c0, 0x26c0);
at!(HwDataBV27_2, pwr_gate_0x26c8, 0x26c8);
at!(HwDataBV27_2, feat_0x26d0, 0x26d0);
at!(HwDataBV27_2, ones_0x26d8, 0x26d8);
at!(HwDataBV27_2, const_0x2728, 0x2728);
at!(HwDataBV27_2, one_0x275c, 0x275c);
at!(HwDataBV27_2, one_0x278a, 0x278a);
// Table B's bzero (0x848) ends the perf-state block at +0x263c.
const _: () = assert!(core::mem::offset_of!(HwDataBV27_2, perf2_max_pstate) + 0x848 == 0x263c);
// Record 17's fwva is the RGX base the firmware reads at +0x8f0; record
// 41's, forced to 0, is +0xcb0.
const _: () = assert!(
    core::mem::offset_of!(HwDataBV27_2, windows)
        + 17 * size_of::<WindowRecordV27_2>()
        + core::mem::offset_of!(WindowRecordV27_2, fwva)
        == 0x8f0
);
const _: () = assert!(
    core::mem::offset_of!(HwDataBV27_2, windows)
        + 41 * size_of::<WindowRecordV27_2>()
        + core::mem::offset_of!(WindowRecordV27_2, fwva)
        == 0xcb0
);

at!(HwDataAV27_2, head, 0x00);
at!(HwDataAV27_2, arm_0x3c, 0x3c);
at!(HwDataAV27_2, const_0x50, 0x50);
at!(HwDataAV27_2, dom_0x54, 0x54);
at!(HwDataAV27_2, static_config, 0xb0);
at!(HwDataAV27_2, fw_0x210, 0x210);
at!(HwDataAV27_2, pwr_cfg_0x9c8, 0x9c8);
at!(HwDataAV27_2, pwr_cfg_0xa4c, 0xa4c);
at!(HwDataAV27_2, ppm_0xa80, 0xa80);
at!(HwDataAV27_2, perf_0xb38, 0xb38);
at!(HwDataAV27_2, perf_dz_0xb4c, 0xb4c);
at!(HwDataAV27_2, perf_0xb50, 0xb50);
at!(HwDataAV27_2, perf_tgt_util_2, 0xb9c);
at!(HwDataAV27_2, perf_dz_0xba4, 0xba4);
at!(HwDataAV27_2, perf_0xba8, 0xba8);
at!(HwDataAV27_2, perf_0xbcc, 0xbcc);
at!(HwDataAV27_2, pad_0xbd8, 0xbd8);
at!(HwDataAV27_2, fill_0xbff, 0xbff);
at!(HwDataAV27_2, fill_0x1bff, 0x1bff);
at!(HwDataAV27_2, fill_0x1fff, 0x1fff);
at!(HwDataAV27_2, pad_0x21ff, 0x21ff);
at!(HwDataAV27_2, clock_0x2200, 0x2200);
at!(HwDataAV27_2, mem_0x2228, 0x2228);
at!(HwDataAV27_2, fastdie_0x2270, 0x2270);
at!(HwDataAV27_2, fastdie_sensor_mask, 0x2278);
at!(HwDataAV27_2, fastdie_0x2280, 0x2280);
at!(HwDataAV27_2, turbo_0x2730, 0x2730);
at!(HwDataAV27_2, pi_0x2c80, 0x2c80);
at!(HwDataAV27_2, perf_0x2c88, 0x2c88);
at!(HwDataAV27_2, zones_0x2cf0, 0x2cf0);
at!(HwDataAV27_2, pad_0x2ea0, 0x2ea0);
at!(HwDataAV27_2, gov_0x2f50, 0x2f50);
at!(HwDataAV27_2, se_0x3060, 0x3060);
at!(HwDataAV27_2, se_0x3070, 0x3070);
at!(HwDataAV27_2, avgp_0x3078, 0x3078);
at!(HwDataAV27_2, sochot_0x3330, 0x3330);
at!(HwDataAV27_2, sochot_0x3340, 0x3340);
at!(HwDataAV27_2, sochot_0x3344, 0x3344);
at!(HwDataAV27_2, mtr_0x3748, 0x3748);
at!(HwDataAV27_2, buf_0x368_fwva, 0x4bb0);
at!(HwDataAV27_2, mtr_mask, 0x4bb8);
at!(HwDataAV27_2, mtr_count, 0x4bc8);
at!(HwDataAV27_2, chip_0x2020, 0x8bcc);
at!(HwDataAV27_2, dpeppt, 0x8be8);
at!(HwDataAV27_2, dpe_leak, 0x92c8);
at!(HwDataAV27_2, aonptd_entries_fwva, 0x9360);
at!(HwDataAV27_2, aonptd_ids_g, 0x9368);
at!(HwDataAV27_2, aonptd_found_g, 0x9360 + 0x48);
at!(HwDataAV27_2, aonptd_ids_r, 0x93b0);
at!(HwDataAV27_2, aonptd_found_r, 0x9360 + 0x58);
at!(HwDataAV27_2, aonptd_id_f, 0x93c0);
at!(HwDataAV27_2, aonptd_found_f, 0x9360 + 0x64);
at!(HwDataAV27_2, aonptd_0x93cc, 0x9360 + 0x6c);
at!(HwDataAV27_2, chip_0x11734, 0x9408);
at!(HwDataAV27_2, timestamp_0x9a9c, 0x9a9c);
at!(HwDataAV27_2, feat_0x9ae8, 0x9ae8);
at!(HwDataAV27_2, core_leak, 0x9af4);
at!(HwDataAV27_2, leak_0x9b34, 0x9b34);
at!(HwDataAV27_2, sram_leak, 0x9b74);
at!(HwDataAV27_2, leak_0x9bb4, 0x9bb4);
at!(HwDataAV27_2, fw_0x9bd4, 0x9bd4);
// The AON PTD state ends at +0x940b.
const _: () = assert!(core::mem::offset_of!(HwDataAV27_2, fw_0x940c) == 0x940c);
// The traced 14.8.3 → 27.2 points of the two-shift blocks
// (fw272-hwdata.md §1.5): the perf controller's +0x3b0 run (base P&P
// +0xb38, +0xb54, +0xb9c; Arm P&P's +0xb40 and +0xb50) and its +0x3b4 tail
// (+0xbcc, +0xbd0); the zones' +0x1c68 run (+0x2cf0, the records at
// +0x2d24, +0x2e38) and +0x1c6c run (+0x2e44, +0x2e4c, +0x2e70).
const _: () = assert!(
    moved(0x788) == 0xb38
        && moved(0x790) == 0xb40
        && moved(0x7a0) == 0xb50
        && moved(0x7a4) == 0xb54
        && moved(0x7ec) == 0xb9c
        && moved(0x818) == 0xbcc
        && moved(0x81c) == 0xbd0
        && moved(0x1088) == 0x2cf0
        && moved(0x10bc) == 0x2d24
        && moved(0x11d0) == 0x2e38
        && moved(0x11d8) == 0x2e44
        && moved(0x11e0) == 0x2e4c
        && moved(0x1204) == 0x2e70
);
// 14.8.3's zero gaps in them are not moved.
const _: () = assert!(moved(0x7f0) == usize::MAX && moved(0x11d4) == usize::MAX);
// The MTR bzero (0x54a0 from +0x3748) ends where the DPEPPT starts.
const _: () = assert!(
    core::mem::offset_of!(HwDataAV27_2, mtr_0x3748) + 0x54a0
        == core::mem::offset_of!(HwDataAV27_2, dpeppt)
);
