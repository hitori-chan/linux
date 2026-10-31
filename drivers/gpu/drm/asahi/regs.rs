// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! GPU MMIO register abstraction
//!
//! Since the vast majority of the interactions with the GPU are brokered through the firmware,
//! there is very little need to interact directly with GPU MMIO register. This module abstracts
//! the few operations that require that, mainly reading the MMU fault status, reading GPU ID
//! information, and starting the GPU firmware coprocessor.

use crate::hw;
use kernel::{
    c_str,
    device::Core,
    io::{
        mem::IoMem,
        Io,
        IoBase, //
    },
    platform,
    prelude::*,
    soc::apple::rtkit::ASC_CPU_CONTROL,
    sync::{
        aref::ARef,
        Arc, //
    }, //
};

/// Size of the ASC control MMIO region.
pub(crate) const ASC_CTL_SIZE: usize = 0x4000;

/// Size of the SGX MMIO region.
pub(crate) const SGX_SIZE: usize = 0x1000000;

const FAULT_INFO: usize = 0x17030;

/// The G15 Fender block (the DT's sgx reg\[1\]) inside the "sgx" window
/// (reg\[0\]): the base of macOS's register getter, with the ID registers
/// at +0x4000 and the MMU configuration block at +0x8000 (adt.md, uat.md).
const G15_FENDER: usize = 0xd00000;
/// The G15 MMU configuration block (`AGXSecureMonitorG15::setupMMUConfig`).
const G15_MMU_CFG: usize = G15_FENDER + 0x8000;
/// The G15 TTBA cache invalidate (`AGXSecureMonitorG15::invalidateGPUTTBACache`).
const G15_TTBA_INVAL: usize = G15_MMU_CFG + 0x30;
/// The G15 ID registers `readChipInfo` reads (gpu-id.md).
const G15_ID_VERSION: usize = G15_FENDER + 0x4000;
const G15_ID_COUNTS_1: usize = G15_FENDER + 0x4010;
/// The per-core enable mask, 10 bits a cluster, two words.
const G15_CORE_MASK: usize = G15_FENDER + 0x101500;
/// The perf-state maps `parsePerfStateMapRegs` reads: eight words for table
/// A, eight for table B, two entries a word (chip-config.md).
const G15_PSTATE_MAP_A: usize = G15_FENDER + 0x101400;
const G15_PSTATE_MAP_B: usize = G15_FENDER + 0x101480;
/// Die 0's CS mask: its popcount scales the CS power (chip-config.md).
const G15_CS_MASK: usize = G15_FENDER + 0x141600;

const FAULT_INFO_G14X: usize = 0xd8c0;
const FAULT_ADDR_G14X: usize = 0xd8c8;

/// Enum representing the unit that caused an MMU fault.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum FaultUnit {
    /// Decompress / pixel fetch
    DCMP(u8),
    /// USC L1 Cache (device loads/stores)
    UL1C(u8),
    /// Compress / pixel store
    CMP(u8),
    GSL1(u8),
    IAP(u8),
    VCE(u8),
    /// Tiling Engine
    TE(u8),
    RAS(u8),
    /// Vertex Data Master
    VDM(u8),
    PPP(u8),
    /// ISP Parameter Fetch
    IPF(u8),
    IPF_CPF(u8),
    VF(u8),
    VF_CPF(u8),
    /// Depth/Stencil load/store
    ZLS(u8),

    /// Parameter Management
    dPM,
    /// Compute Data Master
    dCDM_KS(u8),
    dIPP,
    dIPP_CS,
    // Vertex Data Master
    dVDM_CSD,
    dVDM_SSD,
    dVDM_ILF,
    dVDM_ILD,
    dRDE(u8),
    FC,
    GSL2,

    /// Graphics L2 Cache Control?
    GL2CC_META(u8),
    GL2CC_MB,

    /// Parameter Management
    gPM_SP(u8),
    /// Vertex Data Master - CSD
    gVDM_CSD_SP(u8),
    gVDM_SSD_SP(u8),
    gVDM_ILF_SP(u8),
    gVDM_TFP_SP(u8),
    gVDM_MMB_SP(u8),
    /// Compute Data Master
    gCDM_CS_KS0_SP(u8),
    gCDM_CS_KS1_SP(u8),
    gCDM_CS_KS2_SP(u8),
    gCDM_KS0_SP(u8),
    gCDM_KS1_SP(u8),
    gCDM_KS2_SP(u8),
    gIPP_SP(u8),
    gIPP_CS_SP(u8),
    gRDE0_SP(u8),
    gRDE1_SP(u8),

    gCDM_CS,
    gCDM_ID,
    gCDM_CSR,
    gCDM_CSW,
    gCDM_CTXR,
    gCDM_CTXW,
    gIPP,
    gIPP_CS,
    gKSM_RCE,

    Unknown(u8),
}

/// Reason for an MMU fault.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum FaultReason {
    Unmapped,
    AfFault,
    WriteOnly,
    ReadOnly,
    NoAccess,
    Unknown(u8),
}

/// Collection of information about an MMU fault.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FaultInfo {
    pub(crate) address: u64,
    pub(crate) sideband: u8,
    pub(crate) vm_slot: u32,
    pub(crate) unit_code: u8,
    pub(crate) unit: FaultUnit,
    pub(crate) level: u8,
    pub(crate) unk_5: u8,
    pub(crate) read: bool,
    pub(crate) reason: FaultReason,
}

/// The G15 values read from the Fender block at probe.
struct G15LiveId {
    id_version: u32,
    id_counts_1: u32,
    core_mask: [u32; 2],
    /// Table A's 16 map entries, then table B's.
    pstate_map: [u32; 32],
    cs_mask: u32,
}

/// Device resources for this GPU instance.
pub(crate) struct Resources<'drm> {
    dev: ARef<platform::Device>,
    sgx: Arc<IoMem<'drm, SGX_SIZE>>,
}

impl Resources<'_> {
    /// Map the required resources given our platform device.
    pub(crate) fn new<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
    ) -> Result<Resources<'bound>> {
        let sgx_req = pdev.io_request_by_name(c"sgx").ok_or(EINVAL)?;
        let sgx_iomem = Arc::new(sgx_req.iomap_sized::<SGX_SIZE>()?, GFP_KERNEL)?;

        Ok(Resources {
            // SAFETY: This device does DMA via the UAT IOMMU.
            dev: pdev.into(),
            sgx: sgx_iomem,
        })
    }

    fn sgx_read64<const OFF: usize>(&self) -> u64 {
        // TODO: use infallible `read64()`
        self.sgx
            .as_view()
            .relaxed()
            .try_read64(OFF)
            .expect("64-bit read failed!")
    }

    /// Drops the GPU's cached TTBA pair of context `ctx` after the host
    /// changed it, as macOS's `invalidateGPUTTBACache` does after
    /// `AGXLegacyGartG15::registerContextID` takes the context ID from an
    /// address space.
    pub(crate) fn g15_ttba_inval(&self, ctx: u32) {
        self.sgx.as_view().write32(ctx << 8, G15_TTBA_INVAL);
    }

    /// Enables the G15 MMU and points its GPTBAT at the TTBAT region, as
    /// macOS's `AGXSecureMonitorG15::setupMMUConfig` does (uat.md).
    ///
    /// The GPTBAT, the array of per-context table bases the GPU's MMU reads,
    /// lives in the TTBAT region in RAM; +0x2C holds its PA >> 14. The
    /// enable word at +0x0 is the gate: the block is programmed only when
    /// it reads 0, and the word is written last. The block normally reads
    /// programmed after the GFX power-on, so this only checks it.
    ///
    /// Returns whether it programmed the block, and the enable word and
    /// GPTBAT base after the call.
    pub(crate) fn setup_g15_mmu(&self, ttbs_pa: u64) -> Option<(bool, u32, u32)> {
        let r = self.sgx.as_view().relaxed();
        let m = G15_MMU_CFG;
        let programmed = r.read32(m) == 0;
        if programmed {
            r.write32(((ttbs_pa >> 14) & 0xfff_ffff) as u32, m + 0x2C);
            r.write32(0x80d8, m + 0x14);
            r.write32(0x80d8, m + 0x18);
            r.write32(0, m + 0x0c);
            r.write32(0, m + 0x10);
            r.write32(0, m + 0x1c);
            r.write32(0, m + 0x20);
            r.write32(0, m + 0x24);
            r.write32(0, m + 0x28);
            r.write32(1, m + 0x08);
            r.write32(0x3ff, m + 0x04);
            r.write32(1, m);
            crate::mem::sync();
        }
        Some((programmed, r.read32(m), r.read32(m + 0x2C)))
    }

    /// Initialize the MMIO registers for the GPU.
    pub(crate) fn init_mmio(&self) -> Result {
        // Nothing to do for now...

        Ok(())
    }

    /// Start the ASC coprocessor CPU.
    pub(crate) fn start_cpu(pdev: &platform::Device<Core<'_>>) -> Result {
        let asc_req = pdev.io_request_by_name(c_str!("asc")).ok_or(EINVAL)?;
        let asc_mmio = asc_req.iomap_sized::<ASC_CTL_SIZE>()?;
        let asc_mmio = asc_mmio.as_view().relaxed();
        asc_mmio.update(ASC_CPU_CONTROL, |r| r.with_const_cpu_run::<1>());
        Ok(())
    }

    /// The G15 ID from the DT: `apple,id-version` and `apple,id-counts-1`
    /// hold the register values, and `apple,core-mask` the per-core enable
    /// mask (u32 cells, low word first).
    fn g15_id_from_dt(&self) -> Result<(u32, u32, KVec<u32>)> {
        let dev = self.dev.as_ref();
        let fwnode = dev.fwnode().ok_or(EINVAL)?;
        let id_version = fwnode
            .property_read::<u32>(c_str!("apple,id-version"))
            .required_by(dev)?;
        let id_counts_1 = fwnode
            .property_read::<u32>(c_str!("apple,id-counts-1"))
            .required_by(dev)?;
        let n = fwnode.property_count_elem::<u32>(c_str!("apple,core-mask"))?;
        let masks = fwnode
            .property_read_array_vec::<u32>(c_str!("apple,core-mask"), n)?
            .required_by(dev)?;
        Ok((id_version, id_counts_1, masks))
    }

    /// Reads the G15 ID, the core mask, the perf-state maps and the CS
    /// mask from the Fender block, as macOS's probe does with the GPU
    /// powered (`readChipInfo`, `parsePerfStateMapRegs`). Called after
    /// `setup_g15_mmu`, the block's first access, with the GFX domain on.
    fn g15_read_live(&self) -> Result<G15LiveId> {
        let r = self.sgx.as_view().relaxed();
        let mut pstate_map = [0u32; 32];
        for i in 0..8 {
            let a = r.try_read32(G15_PSTATE_MAP_A + 4 * i)?;
            let b = r.try_read32(G15_PSTATE_MAP_B + 4 * i)?;
            pstate_map[2 * i] = a & 0xf;
            pstate_map[2 * i + 1] = (a >> 16) & 0xf;
            pstate_map[16 + 2 * i] = b & 0xf;
            pstate_map[16 + 2 * i + 1] = (b >> 16) & 0xf;
        }
        Ok(G15LiveId {
            id_version: r.read32(G15_ID_VERSION),
            id_counts_1: r.read32(G15_ID_COUNTS_1),
            core_mask: [r.read32(G15_CORE_MASK), r.read32(G15_CORE_MASK + 4)],
            pstate_map,
            cs_mask: r.read32(G15_CS_MASK),
        })
    }

    /// Get the GPU identification info.
    ///
    /// See [`hw::GpuIdConfig`] for the result.
    ///
    /// The G15 ID comes from the GPU's registers, as on macOS; the DT's
    /// copy (`apple,id-version`, `apple,id-counts-1`, `apple,core-mask`:
    /// one chip's values) is checked against them, and used only when the
    /// registers do not read as a G15.
    pub(crate) fn get_gpu_id(&self) -> Result<hw::GpuIdConfig> {
        let live = self.g15_read_live();
        let dt = self.g15_id_from_dt();
        let (id_version, id_counts_1, mut core_mask_regs, g15_live) = match live {
            Ok(l) if l.id_version >> 24 == 7 => {
                dev_info!(
                    self.dev.as_ref(),
                    "GPU ID: version={:#x} counts1={:#x} mask={:#x?} cs={:#x}\n",
                    l.id_version,
                    l.id_counts_1,
                    l.core_mask,
                    l.cs_mask
                );
                if let Ok((v, c, m)) = &dt {
                    if *v != l.id_version || *c != l.id_counts_1 || m[..] != l.core_mask[..] {
                        dev_warn!(
                            self.dev.as_ref(),
                            "GPU ID: the DT's (version={:#x} counts1={:#x} mask={:#x?}) is not this GPU's\n",
                            v,
                            c,
                            m
                        );
                    }
                }
                let mut masks = KVec::new();
                masks.extend_from_slice(&l.core_mask, GFP_KERNEL)?;
                (l.id_version, l.id_counts_1, masks, Some(l))
            }
            l => {
                let (v, c, m) = dt?;
                dev_warn!(
                    self.dev.as_ref(),
                    "GPU ID: the registers read {:#x?}; the DT's: version={:#x} counts1={:#x} mask={:#x?}\n",
                    l.map(|l| l.id_version),
                    v,
                    c,
                    m
                );
                (v, c, m, None)
            }
        };

        // ID_COUNTS_2 is not in the DT, and G15 uses none of the fields
        // derived from it (num_frags, num_gps).
        let id_counts_2 = 0u32;

        let gpu_gen = (id_version >> 24) & 0xff;

        let num_dies = ((id_counts_1 >> 16) & 0xf) as usize;
        let num_clusters = match gpu_gen {
            // G15: clusters per die * dies
            7 => {
                if num_dies == 0 || num_dies > 4 {
                    dev_err!(self.dev.as_ref(), "Invalid G15 die count {}\n", num_dies);
                    return Err(ENODEV);
                }
                ((id_counts_1 >> 8) & 0xff) * ((id_counts_1 >> 16) & 0xf)
            }
            a => {
                dev_err!(self.dev.as_ref(), "Unknown GPU generation {}\n", a);
                return Err(ENODEV);
            }
        };

        let mut core_masks_packed = KVec::new();
        core_masks_packed.extend_from_slice(&core_mask_regs, GFP_KERNEL)?;

        dev_info!(self.dev.as_ref(), "Core masks: {:#x?}\n", core_masks_packed);

        let num_cores = id_counts_1 & 0xff;

        if num_cores > 32 {
            dev_err!(
                self.dev.as_ref(),
                "Too many cores per cluster ({} > 32)\n",
                num_cores
            );
            return Err(ENODEV);
        }

        if num_cores * num_clusters > (core_mask_regs.len() * 32) as u32 {
            dev_err!(
                self.dev.as_ref(),
                "Too many total cores ({} x {} > {})\n",
                num_clusters,
                num_cores,
                core_mask_regs.len() * 32
            );
            return Err(ENODEV);
        }

        let mut core_masks = KVec::new();
        let mut total_active_cores: u32 = 0;

        let max_core_mask = ((1u64 << num_cores) - 1) as u32;
        for _ in 0..num_clusters {
            let mask = core_mask_regs[0] & max_core_mask;
            core_masks.push(mask, GFP_KERNEL)?;
            for i in 0..core_mask_regs.len() {
                core_mask_regs[i] >>= num_cores;
                if i < (core_mask_regs.len() - 1) {
                    core_mask_regs[i] |= core_mask_regs[i + 1] << (32 - num_cores);
                }
            }
            total_active_cores += mask.count_ones();
        }

        if core_mask_regs.iter().any(|a| *a != 0) {
            dev_err!(
                self.dev.as_ref(),
                "Leftover core mask: {:#x?}\n",
                core_mask_regs
            );
            return Err(EIO);
        }

        let (gpu_rev, gpu_rev_id) = match (id_version >> 8) & 0xff {
            0x00 => (hw::GpuRevision::A0, hw::GpuRevisionID::A0),
            0x01 => (hw::GpuRevision::A1, hw::GpuRevisionID::A1),
            0x10 => (hw::GpuRevision::B0, hw::GpuRevisionID::B0),
            0x11 => (hw::GpuRevision::B1, hw::GpuRevisionID::B1),
            0x20 => (hw::GpuRevision::C0, hw::GpuRevisionID::C0),
            0x21 => (hw::GpuRevision::C1, hw::GpuRevisionID::C1),
            a => {
                dev_err!(self.dev.as_ref(), "Unknown GPU revision {}\n", a);
                return Err(ENODEV);
            }
        };

        Ok(hw::GpuIdConfig {
            gpu_gen: match (id_version >> 24) & 0xff {
                7 => hw::GpuGen::G15,
                a => {
                    dev_err!(self.dev.as_ref(), "Unknown GPU generation {}\n", a);
                    return Err(ENODEV);
                }
            },
            // The SKU variant (`readChipInfo`).
            gpu_variant: match (id_version >> 16) & 0xff {
                0 => hw::GpuVariant::P,
                2 => hw::GpuVariant::G,
                3 => hw::GpuVariant::S,
                4 => hw::GpuVariant::C,
                a => {
                    dev_err!(self.dev.as_ref(), "Unknown G15 SKU variant {}\n", a);
                    return Err(ENODEV);
                }
            },
            gpu_rev,
            gpu_rev_id,
            num_clusters,
            num_cores,
            num_frags: id_counts_2 & 0xff,
            num_gps: (id_counts_2 >> 16) & 0xff,
            total_active_cores,
            core_masks,
            core_masks_packed,
            g15_pstate_map: g15_live.as_ref().map(|l| l.pstate_map),
            g15_cs_mask: g15_live.map_or(0, |l| l.cs_mask),
        })
    }

    /// Get the fault information from the MMU status register, if one occurred.
    pub(crate) fn get_fault_info(&self, cfg: &'static hw::HwConfig) -> Option<FaultInfo> {
        let g14x = cfg.gpu_core as u32 >= hw::GpuCore::G14S as u32;

        let fault_info = if g14x {
            self.sgx_read64::<FAULT_INFO_G14X>()
        } else {
            self.sgx_read64::<FAULT_INFO>()
        };

        if fault_info & 1 == 0 {
            return None;
        }

        let fault_addr = if g14x {
            self.sgx_read64::<FAULT_ADDR_G14X>()
        } else {
            fault_info >> 30
        };

        let unit_code = ((fault_info >> 9) & 0xff) as u8;
        let unit = match unit_code {
            0x00..=0x9f => match unit_code & 0xf {
                0x0 => FaultUnit::DCMP(unit_code >> 4),
                0x1 => FaultUnit::UL1C(unit_code >> 4),
                0x2 => FaultUnit::CMP(unit_code >> 4),
                0x3 => FaultUnit::GSL1(unit_code >> 4),
                0x4 => FaultUnit::IAP(unit_code >> 4),
                0x5 => FaultUnit::VCE(unit_code >> 4),
                0x6 => FaultUnit::TE(unit_code >> 4),
                0x7 => FaultUnit::RAS(unit_code >> 4),
                0x8 => FaultUnit::VDM(unit_code >> 4),
                0x9 => FaultUnit::PPP(unit_code >> 4),
                0xa => FaultUnit::IPF(unit_code >> 4),
                0xb => FaultUnit::IPF_CPF(unit_code >> 4),
                0xc => FaultUnit::VF(unit_code >> 4),
                0xd => FaultUnit::VF_CPF(unit_code >> 4),
                0xe => FaultUnit::ZLS(unit_code >> 4),
                _ => FaultUnit::Unknown(unit_code),
            },
            0xa1 => FaultUnit::dPM,
            0xa2 => FaultUnit::dCDM_KS(0),
            0xa3 => FaultUnit::dCDM_KS(1),
            0xa4 => FaultUnit::dCDM_KS(2),
            0xa5 => FaultUnit::dIPP,
            0xa6 => FaultUnit::dIPP_CS,
            0xa7 => FaultUnit::dVDM_CSD,
            0xa8 => FaultUnit::dVDM_SSD,
            0xa9 => FaultUnit::dVDM_ILF,
            0xaa => FaultUnit::dVDM_ILD,
            0xab => FaultUnit::dRDE(0),
            0xac => FaultUnit::dRDE(1),
            0xad => FaultUnit::FC,
            0xae => FaultUnit::GSL2,
            0xb0..=0xb7 => FaultUnit::GL2CC_META(unit_code & 0xf),
            0xb8 => FaultUnit::GL2CC_MB,
            0xd0..=0xdf if g14x => match unit_code & 0xf {
                0x0 => FaultUnit::gCDM_CS,
                0x1 => FaultUnit::gCDM_ID,
                0x2 => FaultUnit::gCDM_CSR,
                0x3 => FaultUnit::gCDM_CSW,
                0x4 => FaultUnit::gCDM_CTXR,
                0x5 => FaultUnit::gCDM_CTXW,
                0x6 => FaultUnit::gIPP,
                0x7 => FaultUnit::gIPP_CS,
                0x8 => FaultUnit::gKSM_RCE,
                _ => FaultUnit::Unknown(unit_code),
            },
            0xe0..=0xff if g14x => match unit_code & 0xf {
                0x0 => FaultUnit::gPM_SP((unit_code >> 4) & 1),
                0x1 => FaultUnit::gVDM_CSD_SP((unit_code >> 4) & 1),
                0x2 => FaultUnit::gVDM_SSD_SP((unit_code >> 4) & 1),
                0x3 => FaultUnit::gVDM_ILF_SP((unit_code >> 4) & 1),
                0x4 => FaultUnit::gVDM_TFP_SP((unit_code >> 4) & 1),
                0x5 => FaultUnit::gVDM_MMB_SP((unit_code >> 4) & 1),
                0x6 => FaultUnit::gRDE0_SP((unit_code >> 4) & 1),
                _ => FaultUnit::Unknown(unit_code),
            },
            0xe0..=0xff if !g14x => match unit_code & 0xf {
                0x0 => FaultUnit::gPM_SP((unit_code >> 4) & 1),
                0x1 => FaultUnit::gVDM_CSD_SP((unit_code >> 4) & 1),
                0x2 => FaultUnit::gVDM_SSD_SP((unit_code >> 4) & 1),
                0x3 => FaultUnit::gVDM_ILF_SP((unit_code >> 4) & 1),
                0x4 => FaultUnit::gVDM_TFP_SP((unit_code >> 4) & 1),
                0x5 => FaultUnit::gVDM_MMB_SP((unit_code >> 4) & 1),
                0x6 => FaultUnit::gCDM_CS_KS0_SP((unit_code >> 4) & 1),
                0x7 => FaultUnit::gCDM_CS_KS1_SP((unit_code >> 4) & 1),
                0x8 => FaultUnit::gCDM_CS_KS2_SP((unit_code >> 4) & 1),
                0x9 => FaultUnit::gCDM_KS0_SP((unit_code >> 4) & 1),
                0xa => FaultUnit::gCDM_KS1_SP((unit_code >> 4) & 1),
                0xb => FaultUnit::gCDM_KS2_SP((unit_code >> 4) & 1),
                0xc => FaultUnit::gIPP_SP((unit_code >> 4) & 1),
                0xd => FaultUnit::gIPP_CS_SP((unit_code >> 4) & 1),
                0xe => FaultUnit::gRDE0_SP((unit_code >> 4) & 1),
                0xf => FaultUnit::gRDE1_SP((unit_code >> 4) & 1),
                _ => FaultUnit::Unknown(unit_code),
            },
            _ => FaultUnit::Unknown(unit_code),
        };

        let reason = match (fault_info >> 1) & 0x7 {
            0 => FaultReason::Unmapped,
            1 => FaultReason::AfFault,
            2 => FaultReason::WriteOnly,
            3 => FaultReason::ReadOnly,
            4 => FaultReason::NoAccess,
            a => FaultReason::Unknown(a as u8),
        };

        Some(FaultInfo {
            address: fault_addr << 6,
            sideband: ((fault_info >> 23) & 0x7f) as u8,
            vm_slot: ((fault_info >> 17) & 0x3f) as u32,
            unit_code,
            unit,
            level: ((fault_info >> 7) & 3) as u8,
            unk_5: ((fault_info >> 5) & 3) as u8,
            read: (fault_info & (1 << 4)) != 0,
            reason,
        })
    }
}
