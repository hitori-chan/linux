// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 (t6034, j514map) firmware init-data structures.
//!
//! The G15 firmware (V14_7, `armfw_g15c`) is not given one monolithic init
//! block like M1: it receives a set of separate DMA buffers whose firmware
//! VAs are published through the channel table and the FMC channel header.
//! The layouts below are decoded from the 14.8.3 `AGXG15C` kext (fields
//! written by `initFirmwareData` base/Arm, `initPowerAndPerformanceData`,
//! `initFirmwareSharedData` and `initSoftFaultSettings`); every named field
//! carries its spec offset in the field name, and the compile-time asserts
//! at the bottom pin the total sizes and offsets to the kext model.
//!
//! See spec/agx-g15c/{initdata,hwdata-a,hwdata-b,channel,pb-table,alloc}.md.

//! Fields marked "chip" are properties of the kext chip object
//! (`AGXAcceleratorG15X`, the driver's counterpart is `hw/t6034.rs`); fields
//! whose value is not yet resolved are zeroed here and revisited as they
//! are decoded (the firmware boots with the M1-style unknowns, and the
//! missing ones surface as faults).

use super::types::{GpuStruct, U64, Pad};
use core::sync::atomic::AtomicU32;
use crate::default_zeroed;
use crate::float::F32;

/// Ring region layout (spec: agx-g15c/channel.md, "Doorbell and live
/// command path"). The kext keeps the 13 rings' index words and storages
/// in the Fender scratch — shared SRAM at CPU PA 0x408d60000 (the sgx
/// window 0x408000000 + 0xD60000; the ADT's 0x208… is a bus address),
/// 128 KiB. (The 2026-10-10 "secure-world-only" faults were reads of the
/// bus address 0x208d60000, where nothing lives; the real window is not
/// probed yet.) The driver backs the identical layout with a 128 KiB `alloc.shared` DMA
/// buffer (RAM, already visible to the firmware through the UAT kernel VM)
/// and publishes its GPU VAs in the channel table. The layout mirrors the
/// scratch so the offsets below are the same either way:
///
/// - region 1 (first 0x14000): the doorbells and storages of all 13 rings.
///   Ring `k`'s doorbell u32 is at `k * RING_STRIDE`, its 0x1800 storage at
///   `k * RING_STRIDE + 8` (12 command rings; the 13th ring's storage is a
///   separate 0x3800 DMA buffer).
/// - region 2 (0xC000, at +0x14000): the read/CFI index words. Ring `k`'s
///   read u32 is at `16k`, its CFI u32 at `16k + 8`.
///
/// The 13th (special control, 56 B entry) ring: read 0xC0, CFI 0xC8,
/// doorbell 12 * RING_STRIDE = 0x12060.
pub(crate) const RING_REGION_SIZE: usize = 0x20000;
pub(crate) const RING_REGION2_OFF: usize = 0x14000;
pub(crate) const RING_STRIDE: usize = 0x1808;
pub(crate) const RING_SPECIAL_DOORBELL_OFF: usize = 12 * RING_STRIDE;
/// The kext's Fender scratch CPU PA (j514map): reference only — the guest
/// uses the RAM ring region instead.
pub(crate) const FENDER_SCRATCH_PA: u64 = 0x408d60000;
/// Offset of the scratch within the sgx window: reference only.
pub(crate) const FENDER_SCRATCH_SGX_OFF: usize = 0xD60000;

/// One row of the channel table ring table: three channels (TA, 3D, CL) of
/// one queue. The ring PAs are the channel objects' `+0x20` fields.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct RingEntry {
    /// Group 1 = ring `k` (TA queue k): the four words below are
    /// {`getReadIndexGPUPtr`, `getCFIIndexGPUPtr`, `getWriteIndexGPUPtr`
    /// (the doorbell word), storage GPU VA} — the ring vtable slots
    /// 0x10/0x40/0x28 and the `ring+0x20` field, each through
    /// `convertGPUVAToFWVA` (spec: channel.md#command-entries).
    /// Field names are the legacy 2026-10-05 decode ("state/ring2/ring3/
    /// ring"); rename with the M4 fill.
    /// `conv(ring_k->vtbl[0x10]())`
    pub(crate) ta_state: U64,
    /// `conv(ring_k->vtbl[0x40]())`
    pub(crate) ta_ring2: U64,
    /// `conv(ring_k->vtbl[0x28]())` — the write-index (doorbell) FWVA
    pub(crate) ta_ring3: U64,
    /// `conv(ring_k + 0x20)` — the ring storage FWVA (0x1800)
    pub(crate) ta_ring: U64,
    /// Group 2 = ring `3 + k` (3D queue k), same four words
    pub(crate) d3_state: U64,
    pub(crate) d3_ring2: U64,
    /// the 3D ring's write-index (doorbell) FWVA
    pub(crate) d3_ring3: U64,
    /// the 3D ring's storage FWVA
    pub(crate) d3_ring: U64,
    /// Group 3 = ring `6 + k` (CL queue k), same four words
    pub(crate) cl_state: U64,
    pub(crate) cl_ring2: U64,
    /// the CL ring's write-index (doorbell) FWVA
    pub(crate) cl_ring3: U64,
    /// the CL ring's storage FWVA
    pub(crate) cl_ring: U64,
}

/// Channel info table, buffer `this+0x8d8` (VA) / `0x8f8` (PA), size 0x490.
///
/// Header + four queue ring entries + the special channel (the `this+0x918`
/// object, ring at `this+0x938`, the 0x3800 buffer) + the pointer block,
/// then the Arm-populated fields. All pointer values are firmware VAs
/// (`convertGPUVAToFWVA(PA)`, identity on G15) unless noted.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct ChannelTable {
    /// `conv(HwDataB PA)`
    pub(crate) hwdata_b_fwva: U64,
    /// `conv(FWBRN table PA)` — size 0 on G15
    pub(crate) fwbrn_fwva: U64,
    /// `conv(this+0x288)` (the 0x88 buffer)
    pub(crate) buf_0x248_fwva: U64,

    /// Ring entries for k = 0…3 (channel table +0x18…+0x197): entry k
    /// covers rings {k, 3+k, 6+k} = {TA qk, 3D qk, CL qk}; entry 3's groups
    /// alias rings 3/6/9 (the kext's loop runs four times although each
    /// class has three queues — spec: channel.md)
    pub(crate) ring: [RingEntry; 4],

    /// The special channel's TA row (channel table +0x198…+0x1b7): the
    /// `this+0x918` object (`vtbl[0x10/0x40/0x28]`) and the ring PA
    /// `conv(this+0x938)`.
    pub(crate) special: [U64; 4],

    /// Pointer block (channel table +0x1b8…+0x1f8), written after the ring
    /// loop, over the tail of entry 4:
    /// `conv(0x9d0/0x9f0/0x9d8/0x9f8/0x9e0/0xa00/0x9e8/0xa08)`.
    pub(crate) ptr_block: [U64; 8],

    /// +0x1f8 `conv(this+0x900)`
    pub(crate) buf_0x900_fwva: U64,
    pad_0x200: Pad<0x30>,
    /// +0x230 the firmware-log enable (u32; 0 in the kext): non-zero makes
    /// the firmware's print write the pair-2 rings (+0x1c8/+0x1d0, text at
    /// the +0x1f8 buffer) and notify with 0x42 on EP 0x20
    pub(crate) log_enable: u32,
    /// +0x234 `conv(this+0x258)` (the 0xc10 buffer; 8 bytes at an odd
    /// offset)
    pub(crate) buf_0x218_fwva: [u32; 2],
    /// +0x23c `conv(this+0x260)` (the 0x1248 buffer; odd offset)
    pub(crate) buf_0x220_fwva: [u32; 2],
    /// +0x244 `conv(this+0x268)` (the 0xe10 buffer; odd offset)
    pub(crate) buf_0x228_fwva: [u32; 2],
    /// +0x24c `conv(this+0x278)` (the 0x60 buffer; odd offset)
    pub(crate) buf_0x238_fwva: [u32; 2],
    pad_0x254: Pad<0x54>,
    /// +0x2a8 `conv(chip+0x30d0)`, if `chip+0x204c != 0`
    pub(crate) chip_0x30d0_fwva: U64,
    /// +0x2b0 `getPBDescriptorTableGPUAddress()` = `chip+0x29E0`: the
    /// parameter-buffer descriptor table (0x1000 B, 16 B per hardware
    /// buffer ID). Not the 0x1208 B power block (FMC header +0x20).
    pub(crate) pb_desc_table_gpuva: U64,
    /// +0x2b8 `conv(+0x2b0)`: the firmware's PB rebuild/reset write here
    pub(crate) pb_desc_table_fwva: U64,
    /// +0x2c0 `getUMAPagePoolDescriptorTableGPUAddress()`: the UMA
    /// page-pool descriptor table (256 x 0x20 B pool entries); the
    /// firmware's GPU init writes it to MRR 0x14000 (spec: uma.md).
    pub(crate) umap_pool_pa: U64,
    /// +0x2c8 the same address (conv is the identity on G15): the init-data
    /// grab → `g_uma_pp_desc_table`, where `AGFA_UMAPoolRegister` writes a
    /// pool's entry at each registration.
    pub(crate) umap_pool_fwva: U64,
    /// +0x2d0 `chip+0x20b8`
    pub(crate) chip_0x20b8: u32,
    /// +0x2d4 `chip+0x2114`
    pub(crate) chip_0x2114: u32,
    /// +0x2d8…+0x3af unwritten
    pad_0x2d8: Pad<0xd8>,
    /// +0x3b0…+0x458: 0xff at +0x3b0, 18 zeroed u64s at +0x3b1…+0x439
    /// (odd offsets), then `conv(HwDataA)` at +0x441, `chip+0x2088` at
    /// +0x449 and `chip+0x2090` at +0x451 (odd offsets).
    pub(crate) tail_0x3b0: [u8; 0xa9],
    /// +0x459…+0x48f unwritten
    pad_0x459: Pad<0x37>,
}

/// PB descriptor table, buffer `this+0x2b0` (VA) / `0x2b8` (PA), size 0x1208.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct PBTable {
    /// +0x00 7 if `chip+0x650` bit 28 else 0
    pub(crate) header: u32,
    /// +0x04 zero
    pub(crate) zero_0x04: u32,
    /// +0x08 zero (Arm)
    pub(crate) zero_0x08: u32,
    /// +0x0c…+0x13 unwritten
    pad_0x0c: Pad<8>,
    /// +0x14 zero
    pub(crate) zero_0x14: u32,
    /// +0x18 zero
    pub(crate) zero_0x18: u32,
    /// +0x1c `chip+0x2e80` (the FRG task timeout base)
    pub(crate) frg_timeout: u32,
    /// +0x20 `setRelaxedCLKillTimeout` (3000) and +0x24
    /// `setFRGTaskTimeout` (`chip+0x2e84`, not decoded: 0) (spec:
    /// faults.md, "Hangs without a fault")
    pub(crate) relaxed_cl_kill_timeout: u32,
    pub(crate) frg_task_timeout: u32,
    /// +0x28 `chip+0x660`
    pub(crate) chip_0x660: u32,
    /// +0x2c `u8(chip+0x650 & 1)`
    pub(crate) chip_0x650_bit0: u8,
    /// +0x2d…+0x2f unwritten
    pad_0x2d: Pad<3>,
    /// +0x30 `(chip+0x650) >> 1 & 1` (feature bit 1)
    pub(crate) feature_bit1: u32,
    /// +0x34 zero (only when `gpu-noise-suppression` is nonzero)
    pub(crate) noise_suppression: u32,
    /// +0x38 0x78 (base `initFirmwareData`)
    pub(crate) const_0x38: u32,
    /// +0x3c zero (Arm)
    pub(crate) zero_0x3c: u32,
    /// +0x40 zero (Arm)
    pub(crate) zero_0x40: u32,
    /// +0x44 zero
    pub(crate) zero_0x44: u32,
    /// +0x48 zero (Arm)
    pub(crate) zero_0x48: u32,
    /// +0x4c zero (Arm)
    pub(crate) zero_0x4c: u32,
    /// +0x50…+0x54 `chip+0x6c4…0x6c8` (3 × u16)
    pub(crate) chip_0x6c4: u16,
    pub(crate) chip_0x6c6: u16,
    pub(crate) chip_0x6c8: u16,
    /// +0x56…+0x59 zero (Arm; 4 bytes at an odd offset)
    pub(crate) zero_0x56: u16,
    /// +0x58…+0x59 zero
    pad_0x58: Pad<2>,
    /// +0x5a `(chip+0xa218 & 3) == 0`
    pub(crate) chip_a218_eq0: u8,
    /// +0x5b unwritten
    pad_0x5b: Pad<3>,
    /// +0x5e `max(HwDataB.power_sample_period, 1)`
    pub(crate) power_sample_period: u8,
    /// +0x5f…+0x6f unwritten
    pad_0x5f: Pad<0x11>,
    /// +0x70 command submission enabled
    /// (`AGXArmFirmware::setCommandSubmissionEnabled`, 1 from
    /// `AGXAccelerator::start`)
    pub(crate) cmd_submission_enabled: u32,
    /// +0x74 submissions in progress: the kext's `updateSubmitInProgress`
    /// increments it around each submit (`OSIncrementAtomic` /
    /// `OSDecrementAtomic`). The firmware's idle loop (`sub_3DD98`) holds
    /// off the GPU's power-down while it and +0x70 are nonzero (and the
    /// GPU is above its base p-state, power-control +0x230) — M1's
    /// `pending_submissions`.
    pub(crate) submit_in_progress: AtomicU32,
    /// +0x78/+0x7c/+0x80 `updatePowerInterfaceTarget(0/1/2)` (0x8e67a50):
    /// P, c34·100, c34·100
    pub(crate) pwr_target: [u32; 3],
    /// +0x84…+0x87 unwritten
    pad_0x84: Pad<4>,
    /// +0x88 `chip+0x65c` (if nonzero), +0x8c c38·100 (0x8e87338)
    pub(crate) chip_0x65c: U64,
    /// +0x90…+0xc7 firmware `this+0x1db8…0x1de8` (7 × u64) — the
    /// performance-controller block: setupConfig zeroes 0x1db8…0x1dcf
    /// (0xfffffe0008e89994…a8) and nothing writes 0x1dd0…0x1de8 at all
    /// (the setPerformanceController* writers are runtime, after this
    /// copy) — all zero at copy time
    pub(crate) fw_util: [U64; 7],
    /// +0xc8…+0xcf unwritten
    pad_0xc8: Pad<8>,
    /// +0xd0…+0x7a7 DPEPPTConfigData mirror (HwDataA+0x64c4…0x6b93, 0x6d8)
    pub(crate) dpeppt: [u8; 0x6d8],
    /// +0x7a8…+0x7cf `chip+0x19e0…0x1a04`, the idle-off predictor: the
    /// standby timer, eight floats, the reset iterations (the last as
    /// a u32 → float → u32 round trip)
    pub(crate) idleoff: [u32; 10],
    /// +0x7d0/+0x7d4 1, 1 (0x8e8733c)
    pub(crate) one_0x7d0: [u32; 2],
    /// +0x7d8 `chip+0x2198` (Arm initFirmwareData)
    pub(crate) chip_0x2198: u32,
    /// +0x7dc `chip+0x2194` (Arm initFirmwareData)
    pub(crate) chip_0x2194: u32,
    /// +0x7e0…+0x97b unwritten
    pad_0x7e0: Pad<0x19c>,
    /// +0x97c `chip+0x2150` (Arm setupConfig)
    pub(crate) chip_0x2150: U64,
    /// +0x984 `chip+0x2158` (Arm setupConfig)
    pub(crate) chip_0x2158: U64,
    /// +0x98c `chip+0x2160` (Arm setupConfig)
    pub(crate) chip_0x2160: U64,
    /// +0x994 `chip+0x2168` (Arm setupConfig)
    pub(crate) chip_0x2168: u32,
    /// +0x998…+0x99f unwritten
    pad_0x998: Pad<8>,
    /// +0x9a0/0x9a4/0x9a8 ternaries from firmware `this+0x1e2c…0x1e48`
    pub(crate) ternary_0x9a0: u32,
    pub(crate) ternary_0x9a4: u32,
    pub(crate) ternary_0x9a8: u32,
    /// +0x9ac zero
    pub(crate) zero_0x9ac: u32,
    /// +0x9b0 `setCLContextSwitchTimeout` (40), +0x9b4 `setCLKillTimeout`
    /// (50), in the firmware's progress ticks
    pub(crate) cl_ctx_switch_timeout: u32,
    pub(crate) cl_kill_timeout: u32,
    /// +0x9b8 zero
    pub(crate) zero_0x9b8: u32,
    /// +0x9bc `setCDMBackoffTimeout` (4)
    pub(crate) cdm_backoff_timeout: u8,
    /// +0x9bd…+0x11e8 `populateFwUtilPerfTunables(AGFPowerFwUtilPerfMonitorTunables*)`
    /// (chip vtbl 0xdb8): 0x74 bytes of constants, rest zeroed. Written
    /// directly at +0x9bd (odd offset).
    pub(crate) fw_util_perf_tunables: [u8; 0x82c],
    /// +0x11e9…+0x1200 unwritten (+0x11ed zeroed by the Arm initFirmwareData)
    tail: [u8; 0x18],
    /// +0x1201 the soft-fault settings (u32 LE at an odd offset):
    /// `initSoftFaultSettings(1)` = 3 (bit 0 → `+0xD900`, bit 1 → `+0xD910`)
    pub(crate) soft_fault: [u8; 4],
    /// +0x1205…+0x1207 unwritten
    tail_0x1205: [u8; 3],
}

/// FMC channel header, at the start of the FMC ring buffer
/// (`FMC = this+0x1600`, `buf = FMC->vtbl[0x138]()`), 0xc0 bytes.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct FmcHeader {
    /// +0x00 magic 0xc08e21e84820490
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
    /// +0x28 `0x100000000` (constant DAT_fffffe0007109980)
    pub(crate) const_0x28: U64,
    /// +0x30…+0x97 `[chip+0xa078]+0x18…+0x7f` (13 × u64; chip+0xa078 is a
    /// pointer to the `AGXSharedGartTableBackingG15` GART table struct
    /// (initGartInfo 0xfffffe0008e9ba98): three 0x20-byte level records at
    /// +0x18/+0x38/+0x58 + this+0x78 = 0 — all fields are G15 constants
    /// (page size 0x4000, shift 14), spec: gart.md + channel.md)
    pub(crate) chip_a078: [U64; 13],
    /// +0x98…+0xa7 unwritten
    pad_0x98: Pad<0x10>,
    /// +0xa8 `conv(this+0x910)`
    pub(crate) buf_0x910_fwva: U64,
    /// +0xb0 `conv(this+0xa40)` — the 0xc3d0 firmware event/fence page
    /// (Arm `initFirmwareData`, `STR X0,[X20,#0xB0]` at 0xfffffe0008e881c8)
    pub(crate) buf_0xa40_fwva: U64,
    /// +0xb8 `conv(this+0xa48)` — the 0x238 B host/firmware power-control
    /// block (Arm `initFirmwareData`, `STR X0,[X21,#0xB8]` at
    /// 0xfffffe0008e88214); the firmware's power task reads +0x1e8 of it
    /// unchecked (boot #50: a NULL fault while it was unset)
    pub(crate) buf_0xa48_fwva: U64,
}

/// One 0x20 register-window record of HwDataB (base pass); the Arm pass
/// overwrites +0x08 with the GPU-converted address of the window's buffer,
/// so the fields are a mixed base/Arm result. Source entry: the chip
/// register-window table `chip+0x6d0+j*0x98` (spec: alloc.md).
#[derive(Debug)]
#[repr(C)]
pub(crate) struct WindowRecord {
    /// +0x00 `u64(src+8)`: the window's physical base (kind 1) or first pair
    pub(crate) base: U64,
    /// +0x08 base 0; Arm: `conv(buf_j fwva + u32(this+0x1798+j*4))`, 0 if the
    /// window's base or size is 0
    pub(crate) fwva: U64,
    /// +0x10 `u32(src+4) * u32(src+0x88)` (kind × size)
    pub(crate) kind_size: u32,
    /// +0x14 `u32(src+0x88)`
    pub(crate) size: u32,
    /// +0x18 `u8(src+0)`
    pub(crate) flag: u8,
    /// +0x19…+0x1f unwritten by the kext
    pad: Pad<7>,
}

/// HwDataB, buffer `this+0x210` (VA) / `0x250` (PA), size 0x1868.
///
/// Populated by `initFirmwareData` (base + Arm) and the tail of
/// `initPowerAndPerformanceData`; every field is written explicitly by the
/// kext (the buffer is not zeroed), so the unresolved fields below are the
/// ones whose chip-object source is not yet decoded.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct HwDataB {
    /// +0x00 constant 0x6f00000000
    pub(crate) magic1: U64,
    /// +0x08 constant 0xffc00000
    pub(crate) magic2: U64,
    /// +0x10 constant 0x1000000000
    pub(crate) const_0x10: U64,
    /// +0x18 constant 0x1000000000
    pub(crate) const_0x18: U64,
    /// +0x20 constant 0x2ffffff8000
    pub(crate) const_0x20: U64,
    /// +0x28 `conv(0xfffffc2011800000)` — eGartRange-11 base (identity)
    pub(crate) egart_fwva: U64,
    /// +0x30 `chip[chip+0x9a70]->vtbl[0x158]()` or 0
    pub(crate) ts_area_base: U64,

    /// +0x38…+0x337 the low band of the 32 chip records
    /// (`chip+0x9a78+i*0x18`, fields +0/+8/+0x10; the disassembly loop
    /// bound is `CMP X9, #0x300` / `ADD X9, X9, #0x18` = 32, the earlier
    /// "10" was another miscount)
    pub(crate) chip_records: [U64; 96],

    /// +0x338…+0x637 the high band of the same 32 records
    /// (source fields +0x300/+0x308/+0x310)
    pub(crate) chip_records_hi: [U64; 96],
    /// +0x638 `chip->vtbl[0xdc8]()`
    pub(crate) vtbl_0xdc8: U64,

    /// +0x640…+0xa1f 31 register-window records (base pass), overlaid at
    /// +0x648…+0x73f by the Arm pass's 31 window GPU addresses (the
    /// records end at 0xa20, where the Arm fields below begin)
    pub(crate) windows: [WindowRecord; 31],
    /// +0xa20 `conv((this+0x1818)->vtbl[0x158]())`, if present (Arm)
    pub(crate) arm_0xa20: U64,
    /// +0xa28 `chip+0x20c0` (Arm)
    pub(crate) chip_0x20c0: U64,
    /// +0xa30 `chip+0x20c8` (Arm)
    pub(crate) chip_0x20c8: U64,
    /// +0xa38 bit 1 of the probe's config byte (`byte_be96da2`): 1 unless
    /// the ADT `no-gpc` is 1
    pub(crate) probe_da2_bit1: u32,
    /// +0xa3c `(chip+0x650) >> 8 & 1`
    pub(crate) chip_0x650_bit8: u32,
    /// +0xa40 `chip->vtbl[0xae0]()` (nonzero = flag)
    pub(crate) vtbl_0xae0: u32,
    /// +0xa44 bit 4 of the probe's config byte: `model-slow` == 1
    pub(crate) probe_da2_bit4: u32,
    /// +0xa48 zero
    pub(crate) zero_0xa48: u32,
    /// +0xa4c unwritten
    pad_0xa4c: Pad<4>,
    /// +0xa50 1
    pub(crate) one_0xa50: u32,
    /// +0xa54 zero
    pub(crate) zero_0xa54: u32,
    /// +0xa58 `(chip+0x650) >> 0xb & 1` (Arm setupConfig)
    pub(crate) chip_0x650_bit11: u32,
    /// +0xa5c `(chip+0xca) >> 0xc & 1` (Arm)
    pub(crate) chip_0xca_bit12: u32,
    /// +0xa60 1
    pub(crate) one_0xa60: u32,
    /// +0xa64 zero (Arm)
    pub(crate) zero_0xa64: u32,
    /// +0xa68 base clock, kHz (24000 on this machine)
    pub(crate) base_clock_khz: u32,
    /// +0xa6c `(DA2 & 0x10) ? 200 : 1` (1 without `model-slow`)
    pub(crate) power_sample_period: u32,
    /// +0xa70 `chip->vtbl[0xe68]()` (Arm)
    pub(crate) vtbl_0xe68: u32,
    /// +0xa74 `chip+0x664` (Arm setupConfig)
    pub(crate) chip_0x664: u32,
    /// +0xa78 1 (Arm)
    pub(crate) one_0xa78: u32,
    /// +0xa7c…+0xa83 two u32 of 0xffffffff (`movi v0.2S,#0x1` + `str d0`)
    pub(crate) const_0xa7c: [u32; 2],
    /// +0xa84…+0xa87 unwritten
    pad_0xa84: Pad<4>,
    /// +0xa88 `chip+0x2034` (Arm)
    pub(crate) chip_0x2034: u32,
    /// +0xa8c `1 if chip->vtbl[0xb18]() != 0`
    pub(crate) vtbl_0xb18_flag: u32,
    /// +0xa90 `chip[0x9e*8]`, if `chip[0x8e*8] == 4` (Arm)
    pub(crate) chip_idx_0x9e: u32,
    /// +0xa94 zero (Arm)
    pub(crate) zero_0xa94: u32,
    /// +0xa98 1 if a `pmp-sw-interrupt` provider is present (Arm)
    pub(crate) pmp_sw_interrupt: u32,
    /// +0xa9c 0x1f (Arm)
    pub(crate) const_0xa9c: u32,
    /// +0xaa0 `chip+0x19d8`
    pub(crate) chip_0x19d8: u32,
    /// +0xaa4 `(chip+0xca) >> 0x13 & 1`
    pub(crate) chip_0xca_bit19: u32,
    /// +0xaa8 `chip+0x6c2 != 0` (Arm)
    pub(crate) chip_0x6c2_flag: u32,
    /// +0xaac zero (Arm)
    pub(crate) zero_0xaac: u32,
    /// +0xab0…+0xab7 unwritten
    pad_0xab0: Pad<0xc>,
    /// +0xabc `chip+0x2028` (Arm)
    pub(crate) chip_0x2028: u32,
    /// +0xac0…+0xac3 unwritten
    pad_0xac0: Pad<4>,
    /// +0xac4 `chip+0x2030` (Arm)
    pub(crate) chip_0x2030: u32,
    /// +0xac8/0xad0 two u64 constants (DAT_fffffe0007109610)
    pub(crate) const_0xac8: U64,
    pub(crate) const_0xad0: U64,
    /// +0xad8 zero (Arm)
    pub(crate) zero_0xad8: u32,
    /// +0xadc `(chip+0x650) >> 0x15 & 1` (Arm)
    pub(crate) chip_0x650_bit21: u32,
    /// +0xae0 `(chip+0x650) >> 0x1a & 1` (Arm setupConfig)
    pub(crate) chip_0x650_bit26: u32,
    /// +0xae4 `chip+0x2064` (Arm setupConfig)
    pub(crate) chip_0x2064: u32,
    /// +0xae8 zero (Arm)
    pub(crate) zero_0xae8: U64,
    /// +0xaf0…+0xaf3 unwritten
    pad_0xaf0: Pad<4>,
    /// +0xaf4 zero (Arm)
    pub(crate) zero_0xaf4: u32,
    /// +0xaf8…+0xafb unwritten
    pad_0xaf8: Pad<4>,
    /// +0xafc zero (Arm)
    pub(crate) zero_0xafc: u32,
    /// +0xb00 `chip[0x654] >> 0xc & 1` (Arm)
    pub(crate) chip_0x654_bit12: u32,
    /// +0xb04 `u8(chip+0x40e)`
    pub(crate) chip_0x40e: u32,
    /// +0xb08 `chip+0x20d0` (Arm setupConfig)
    pub(crate) chip_0x20d0: U64,
    /// +0xb10 `chip+0x20d8` (Arm setupConfig)
    pub(crate) chip_0x20d8: U64,
    /// +0xb18 `(chip+0x650) >> 0x19 & 1` (Arm)
    pub(crate) chip_0x650_bit25: u32,
    /// +0xb1c zeroed by the Arm setupConfig
    pad_0xb1c: Pad<4>,
    /// +0xb20 `getEnabledNumUSCs()` (chip vtbl 0xa70): the popcount of
    /// chip+0x4b8 if nonzero, else chip+0x47c = cores per cluster ×
    /// clusters
    pub(crate) enabled_uscs: u32,
    /// +0xb24 `chip+0x2040` = 0x3f (G15X)
    pub(crate) chip_0x2040: U64,
    /// +0xb2c…+0xb3f unwritten
    pad_0xb2c: Pad<0x14>,
    /// +0xb40 `chip+0x206c != 0`: the UAT config, 4 on G15X
    /// (`AGXAcceleratorG15X::start`; nonzero selects `AGXGartG15`)
    pub(crate) uat_config: u32,
    /// +0xb44 `chip->vtbl[0x1018]()` (Arm)
    pub(crate) vtbl_0x1018: U64,
    /// +0xb4c…+0xb53 `chip+0x470…0x477`: the core ID (0x18 on G15C) and
    /// the revision ID
    pub(crate) core_id: [u32; 2],
    /// +0xb54 `chip+0x47c` = cores per cluster × clusters
    pub(crate) chip_0x47c: u32,
    /// +0xb58 the GPU table's state count − 1 (`this+0xc34`). The GPU
    /// perf-state tables, `0xb58…0x1793` (spec: chip-config.md, the GPU
    /// perf-state tables): table A = `chip+0xa6f0`, table B =
    /// `chip+0xab38`, both built by `createMGPUPerfStateTables`.
    pub(crate) perf_max_pstate: u32,
    /// +0xb5c table A's clocks, MHz
    pub(crate) perf_freq_mhz: [u32; 0x10],
    /// +0xb9c table A's volts (mV), per state: one slot per cluster,
    /// slots 4…7 = slot 0
    pub(crate) perf_volt_mv: [[u32; 8]; 0x10],
    /// +0xd9c table A's SRAM volts, the same layout
    pub(crate) perf_volt_sram_mv: [[u32; 8]; 0x10],
    /// +0xf9c table B's clocks, MHz (the base pass)
    pub(crate) perf2_freq_mhz: [u32; 0x10],
    /// +0xfdc HwDataA 0x80… (the P&E SRAM power scale, f32 bits) and
    /// +0x101c HwDataA 0xc0…
    pub(crate) sram_scale: [u32; 0x10],
    pub(crate) sram_scale_2: [u32; 0x10],
    /// +0x105c each state's power, % of the top state's (Σ over the
    /// clusters of V²·f, `chip+0xb170`)
    pub(crate) perf_pwr_pct: [u32; 0x10],
    /// +0x109c each state's clock, % of the span from the base state to
    /// the top state (0 below the base state)
    pub(crate) perf_freq_pct: [u32; 0x10],
    /// +0x10dc the state-map nibbles (`chip+0xa228…`: 16 for table A, 16
    /// for table B)
    pub(crate) perf_state_map: [u32; 0x20],
    /// +0x115c the CS table (`chip+0xaf80`, the ADT `cs-perf-states`):
    /// the count − 1, the cap (`this+0xc3c`, count − 1 on B1), the clocks
    /// (MHz), then per state and die the volts and the SRAM volts (mV)
    pub(crate) cs_max_pstate: u32,
    pub(crate) cs_cap: u32,
    pub(crate) cs_freq_mhz: [u32; 0x10],
    pub(crate) cs_volt_mv: [[u32; 2]; 0x10],
    pub(crate) cs_volt_sram_mv: [[u32; 2]; 0x10],
    /// +0x12a4 the AFR table (`chip+0xb0c8`, `afr-perf-states`): the
    /// same, 8 states (the cap is `this+0xc40`)
    pub(crate) afr_max_pstate: u32,
    pub(crate) afr_cap: u32,
    pub(crate) afr_freq_mhz: [u32; 8],
    pub(crate) afr_volt_mv: [[u32; 2]; 8],
    pub(crate) afr_volt_sram_mv: [[u32; 2]; 8],
    /// +0x134c table B's state count − 1
    pub(crate) perf2_max_pstate: u32,
    /// +0x1350 table B's clocks, MHz
    pub(crate) perf2_freq_mhz_2: [u32; 0x10],
    /// +0x1390 table B's volts and +0x1590 SRAM volts: only the slots
    /// below the table count (one per cluster) are copied
    pub(crate) perf2_volt_mv: [[u32; 8]; 0x10],
    pub(crate) perf2_volt_sram_mv: [[u32; 8]; 0x10],
    /// +0x1790…+0x179b unwritten
    pad_0x1790: Pad<0xc>,
    /// +0x179c `chip->vtbl[0xdd0]()` (8 bytes at an odd offset)
    pub(crate) vtbl_0xdd0: [u32; 2],
    /// +0x17a4…+0x17b7 unwritten
    pad_0x17a4: Pad<0x14>,
    /// The Arm `initFirmwareData` tail (spec: hwdata-b.md). +0x17b8
    /// `chip+0x688` (5 on G15C), +0x17bc `chip+0x68c` (0)
    pub(crate) chip_0x688: u32,
    pub(crate) chip_0x68c: u32,
    /// +0x17c0 `(1 << chip+0x494) − 1`, `(1 << chip+0x498) − 1` and +0x17c8
    /// `(1 << chip+0x49c) − 1` (the core config's cfg+0x24/0x28/0x2c)
    pub(crate) mask_0x17c0: [u32; 2],
    pub(crate) mask_0x17c8: u32,
    /// +0x17cc…+0x17e7 unwritten or 0 (+0x17d4 = `chip+0x4b8`, zero on G15)
    pad_0x17cc: Pad<0x1c>,
    /// +0x17e8 1
    pub(crate) one_0x17e8: u32,
    /// +0x17ec…+0x17fb unwritten or 0
    pad_0x17ec: Pad<0x10>,
    /// +0x17fc `chip+0x654` bit 4
    pub(crate) feat_0x17fc: u32,
    /// +0x1800, +0x1804 1
    pub(crate) one_0x1800: [u32; 2],
    /// +0x1808 `chip+0x654` bit 5; +0x180c 0 when it is set
    pub(crate) feat_0x1808: [u32; 2],
    /// +0x1810 `0x100000001`
    pub(crate) const_0x1810: [u32; 2],
    /// +0x1818 `chip+0x650` bit 7; +0x181c 0
    pub(crate) feat_0x1818: [u32; 2],
    /// +0x1820…+0x184f all ones
    pub(crate) ones_0x1820: [u8; 0x30],
    /// +0x1850…+0x185f 0 / unwritten
    pad_0x1850: Pad<0x10>,
    /// +0x1860 `(DA2 & 0x10) == 0` (the probe's config byte; bit 4 =
    /// `model-slow` == 1)
    pub(crate) da2_0x1860: u32,
    /// +0x1864…+0x1867 unwritten
    pad_0x1864: Pad<4>,
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
    /// `setupConfig` fills; spec: hwdata-a.md, chip-config.md).
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
    /// block is written (spec: hwdata-a.md, chip-config.md)
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
    /// kp = 0.3f). Spec: hwdata-a.md.
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
    /// whole region is written, spec: hwdata-a.md, chip-config.md).
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
    /// `fdiv` in setupConfig (0xfffffe0008e899d4…0xfffffe0008e8afc8):
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
    /// `populateSoCHotConfigData`, resolved 2026-10-09): the G15C path
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
    /// +0x24a8…+0x24b7 `chip+0x1a08/0x1a10` (the SoC hot feature mask,
    /// 0/0 on G15C) — the Arm pass zeroes 0x18a8…0x64bf first
    pub(crate) chip_0x1a08: [u32; 4],
    /// +0x24b8 `chip+0x1a18` = 1
    pub(crate) chip_0x1a18: u32,
    /// +0x24bc…+0x64bb zero
    pad_0x24bc: Pad<0x4000>,
    /// +0x64bc `chip+0x2020` = 0x40a00000 (G15X)
    pub(crate) chip_0x2020: u32,
    /// +0x64c0…+0x6b9f DPEPPT block (AGFDPEPPTConfigData, 0x6e0 bytes) —
    /// zero on G15: `populateDPEPPTConfigData` (chip vtbl 0xce0) is the
    /// base implementation, a jump to the kernel's `___bzero` (verified
    /// 2026-10-08 in both 14.8.3 and 27.0.1). Runtime state, updated by
    /// `updateDPEPPT`, not init data. Mirrored at PB table 0xd0…0x7a7.
    pad_0x64c0: Pad<0x6e0>,
    /// +0x6ba0…+0x6bf0 8 qwords + 2 u32 from firmware `this+0x18e8…
    /// 0x1934` (the block mirrored into the 0xa38 buffer); runtime
    /// values, zero here; the rest of the gap unwritten.
    pad_0x6ba0: Pad<0xb8>,
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
    /// +0x6d88…+0x6e47 the leakage mirror and the rest (zero on G15C)
    pad_0x6d88: Pad<0xc0>,
}

/// The G15 top-level "init data" object.
///
/// Unlike M1's monolithic `raw::InitData`, the G15 firmware is not given
/// one block: it receives the separate buffers below, whose roots the
/// driver keeps alive in [`super::initdata::InitData::ver`] and whose
/// GPU addresses are published in the channel table and the FMC header
/// (spec/agx-g15c/{initdata,channel}.md). This raw type is driver-side
/// bookkeeping only — the object is empty; the host→firmware publication
/// itself is the kernel IOGPU start path (the M2 milestone).
/// Bookkeeping: the GPU addresses of the buffer set, kept in the (empty)
/// root object so the debug views and the M2 handoff can find them.
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
    /// The MCache PIO buffer (the window table's kind-6 slot): 12 u64s,
    /// the first `kind` filled with the MCache window PAs (spec: alloc.md).
    pub(crate) mcache_piob: U64,
    /// The RAM ring region (128 KiB): the 13 rings' index words and the 12
    /// command rings' storages (fw/g15.rs constants; spec: channel.md).
    pub(crate) ring_area: U64,
}

impl GpuStruct for InitData {
    type Raw<'a> = InitData;
}
// SAFETY: only U64 fields, zero is a valid state.
unsafe impl ::pin_init::Zeroable for InitData {}

/// GpuStruct plumbing for the buffer layouts above: each raw struct is its
/// own GpuStruct (no inner objects), zero-initialized on allocation.
impl GpuStruct for HwDataB {
    type Raw<'a> = HwDataB;
}
impl GpuStruct for HwDataA {
    type Raw<'a> = HwDataA;
}
impl GpuStruct for ChannelTable {
    type Raw<'a> = ChannelTable;
}
impl GpuStruct for PBTable {
    type Raw<'a> = PBTable;
}

default_zeroed!(HwDataB);
default_zeroed!(HwDataA);
default_zeroed!(ChannelTable);
default_zeroed!(PBTable);
default_zeroed!(FmcHeader);

/// Compile-time layout checks against the kext model.
///
/// A mismatch is a compile error (an empty array of the wrong length), so
/// the sizes and offsets below are enforced on every build.
const _: [(); {
    (size_of::<RingEntry>() == 0x60)
        as usize
        *
    (size_of::<ChannelTable>() == 0x490)
        as usize
        *
    (size_of::<PBTable>() == 0x1208)
        as usize
        *
    (size_of::<FmcHeader>() == 0xc0)
        as usize
        *
    (size_of::<WindowRecord>() == 0x20)
        as usize
        *
    (size_of::<HwDataB>() == 0x1868)
        as usize
        *
    (size_of::<HwDataA>() == 0x6e48)
        as usize
}] = [(); 1];

const _: [(); {
    (core::mem::offset_of!(HwDataB, ts_area_base) == 0x30)
        as usize
        *
    (core::mem::offset_of!(HwDataB, chip_records) == 0x38)
        as usize
        *
    (core::mem::offset_of!(HwDataB, vtbl_0xdc8) == 0x638)
        as usize
        *
    (core::mem::offset_of!(HwDataB, windows) == 0x640)
        as usize
        *
    (core::mem::offset_of!(HwDataB, arm_0xa20) == 0xa20)
        as usize
        *
    (core::mem::offset_of!(HwDataB, base_clock_khz) == 0xa68)
        as usize
        *
    (core::mem::offset_of!(HwDataB, core_id) == 0xb4c)
        as usize
        *
    (core::mem::offset_of!(HwDataB, vtbl_0xdd0) == 0x179c)
        as usize
}] = [(); 1];
const _: [(); {
    (core::mem::offset_of!(HwDataB, perf_state_map) == 0x10dc
        && core::mem::offset_of!(HwDataB, cs_max_pstate) == 0x115c
        && core::mem::offset_of!(HwDataB, cs_volt_sram_mv) == 0x1224
        && core::mem::offset_of!(HwDataB, afr_max_pstate) == 0x12a4
        && core::mem::offset_of!(HwDataB, afr_volt_sram_mv) == 0x130c
        && core::mem::offset_of!(HwDataB, perf2_max_pstate) == 0x134c
        && core::mem::offset_of!(HwDataB, perf2_volt_sram_mv) == 0x1590) as usize
}] = [(); 1];
const _: [(); {
    (core::mem::offset_of!(HwDataA, clock_0x838) == 0x838
        && core::mem::offset_of!(HwDataA, fastdie_sensor_mask) == 0x8ac
        && core::mem::offset_of!(HwDataA, fastdie_target) == 0x910
        && core::mem::offset_of!(HwDataA, fastdie_0x940) == 0x940
        && core::mem::offset_of!(HwDataA, timestamp_0x6d34) == 0x6d34
        && core::mem::offset_of!(HwDataA, feat_0x6d80) == 0x6d80
        && core::mem::offset_of!(HwDataA, mem_threshold) == 0x860) as usize
}] = [(); 1];

const _: [(); {
    (core::mem::offset_of!(ChannelTable, ring) == 0x18)
        as usize
        *
    (core::mem::offset_of!(ChannelTable, special) == 0x198)
        as usize
        *
    (core::mem::offset_of!(ChannelTable, ptr_block) == 0x1b8)
        as usize
        *
    (core::mem::offset_of!(ChannelTable, buf_0x900_fwva) == 0x1f8)
        as usize
        *
    (core::mem::offset_of!(ChannelTable, pb_desc_table_gpuva) == 0x2b0)
        as usize
        *
    (core::mem::offset_of!(ChannelTable, umap_pool_fwva) == 0x2c8)
        as usize
        *
    (core::mem::offset_of!(ChannelTable, buf_0x218_fwva) == 0x234)
        as usize
}] = [(); 1];

const _: [(); {
    (core::mem::offset_of!(PBTable, frg_timeout) == 0x1c)
        as usize
        *
    (core::mem::offset_of!(PBTable, chip_0x660) == 0x28)
        as usize
        *
    (core::mem::offset_of!(PBTable, power_sample_period) == 0x5e)
        as usize
        *
    (core::mem::offset_of!(PBTable, submit_in_progress) == 0x74)
        as usize
        *
    (core::mem::offset_of!(PBTable, dpeppt) == 0xd0)
        as usize
        *
    (core::mem::offset_of!(PBTable, idleoff) == 0x7a8)
        as usize
        *
    (core::mem::offset_of!(PBTable, chip_0x2198) == 0x7d8)
        as usize
        *
    (core::mem::offset_of!(PBTable, chip_0x2194) == 0x7dc)
        as usize
        *
    (core::mem::offset_of!(PBTable, fw_util_perf_tunables) == 0x9bd)
        as usize
}] = [(); 1];

const _: [(); {
    (core::mem::offset_of!(FmcHeader, channel_table_fwva) == 0x18)
        as usize
        *
    (core::mem::offset_of!(FmcHeader, pb_table_fwva) == 0x20)
        as usize
        *
    (core::mem::offset_of!(FmcHeader, chip_a078) == 0x30)
        as usize
        *
    (core::mem::offset_of!(FmcHeader, buf_0x910_fwva) == 0xa8)
        as usize
        *
    (core::mem::offset_of!(FmcHeader, buf_0xa40_fwva) == 0xb0)
        as usize
}] = [(); 1];

const _: [(); {
    (core::mem::offset_of!(HwDataA, vtbl_0xe70) == 0x04)
        as usize
        *
    (core::mem::offset_of!(HwDataA, static_config) == 0x60)
        as usize
        *
    (core::mem::offset_of!(HwDataA, perf_dual_filter) == 0x7a4)
        as usize
        *
    (core::mem::offset_of!(HwDataA, perf_tgt_util_2) == 0x7ec)
        as usize
        *
    (core::mem::offset_of!(HwDataA, limiter_filter) == 0x86c)
        as usize
        *
    (core::mem::offset_of!(HwDataA, perf_0xde8) == 0xde8)
        as usize
        *
    (core::mem::offset_of!(HwDataA, chip_0x27e0) == 0x698)
        as usize
        *
    (core::mem::offset_of!(HwDataA, powerzone_count) == 0x1088)
        as usize
        *
    (core::mem::offset_of!(HwDataA, powerzone_0x10b4) == 0x10b4)
        as usize
        *
    (core::mem::offset_of!(HwDataA, avg_0x1184) == 0x1184)
        as usize
        *
    (core::mem::offset_of!(HwDataA, avg_0x11e0) == 0x11e0)
        as usize
        *
    (core::mem::offset_of!(HwDataA, avg_0x1204) == 0x1204)
        as usize
        *
    (core::mem::offset_of!(HwDataA, gov_0x12fc) == 0x12fc)
        as usize
        *
    (core::mem::offset_of!(HwDataA, gov_0x139c) == 0x139c)
        as usize
        *
    (core::mem::offset_of!(HwDataA, pad_0x13b0) == 0x13b0)
        as usize
        *
    (core::mem::offset_of!(HwDataA, pad_0x64c0) == 0x64c0)
        as usize
        *
    (core::mem::offset_of!(HwDataA, aonptd_ids_g) == 0x6cdc)
        as usize
        *
    (core::mem::offset_of!(HwDataA, aonptd_ids_r) == 0x6d04)
        as usize
        *
    (core::mem::offset_of!(HwDataA, aonptd_id_f) == 0x6d14)
        as usize
        *
    (core::mem::offset_of!(HwDataA, aonptd_found_f) == 0x6d18)
        as usize
        *
    (core::mem::size_of::<HwDataA>() == 0x6e48)
        as usize
}] = [(); 1];
