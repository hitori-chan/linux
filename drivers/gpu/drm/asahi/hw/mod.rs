// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Per-SoC hardware configuration structures
//!
//! This module contains the definitions used to store per-GPU and per-SoC configuration data.

use crate::fw::types::*;
use kernel::c_str;
use kernel::device;
use kernel::prelude::*;

const MAX_POWERZONES: usize = 5;

mod g15_pstates;
pub(crate) mod t6030;
pub(crate) mod t6031;
pub(crate) mod t6034;
pub(crate) mod t8122;

/// GPU generation enumeration. Note: Part of the UABI.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u32)]
pub(crate) enum GpuGen {
    #[allow(dead_code)] // UABI value; this fork builds G15 only
    G13 = 13,
    #[allow(dead_code)] // UABI value; this fork builds G15 only
    G14 = 14,
    G15 = 15,
}

/// GPU variant enumeration. Note: Part of the UABI.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u32)]
pub(crate) enum GpuVariant {
    P = 'P' as u32,
    G = 'G' as u32,
    S = 'S' as u32,
    C = 'C' as u32,
    #[allow(dead_code)] // UABI value; this fork builds G15 only
    D = 'D' as u32,
}

/// GPU revision enumeration. Note: Part of the UABI.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u32)]
pub(crate) enum GpuRevision {
    A0 = 0x00,
    A1 = 0x01,
    B0 = 0x10,
    B1 = 0x11,
    C0 = 0x20,
    C1 = 0x21,
}

/// GPU core type enumeration. Note: Part of the firmware ABI.
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
#[allow(dead_code)] // the firmware's table; this fork builds G15C only
pub(crate) enum GpuCore {
    // Unknown = 0,
    // G5P = 1,
    // G5G = 2,
    // G9P = 3,
    // G9G = 4,
    // G10P = 5,
    // G11P = 6,
    // G11M = 7,
    // G11G = 8,
    // G12P = 9,
    // G13P = 10,
    G13G = 11,
    G13S = 12,
    G13C = 13,
    // G14P = 14,
    G14G = 15,
    G14S = 16,
    G14C = 17,
    G14D = 18, // Split out, unlike G13D
    // G15 (M3): macOS's kAGXGPUCoreName table
    G15M = 19,
    G15PAgx2 = 20, // macOS's G15P_AGX2
    G15P = 21,
    G15G = 22,
    G15S = 23,
    G15C = 24, // M3 Max (t6031 16-core / t6034 14-core)
}

/// GPU revision ID. Note: Part of the firmware ABI.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u32)]
pub(crate) enum GpuRevisionID {
    // Unknown = 0,
    A0 = 1,
    A1 = 2,
    B0 = 3,
    B1 = 4,
    C0 = 5,
    C1 = 6,
}

/// A single performance state of the GPU.
#[derive(Debug)]
pub(crate) struct PState {
    /// Voltage in millivolts, per GPU cluster.
    pub(crate) volt_mv: KVec<u32>,
    /// Frequency in hertz.
    pub(crate) freq_hz: u32,
    /// Maximum power consumption of the GPU at this pstate, in milliwatts.
    pub(crate) pwr_mw: u32,
}

impl PState {
    pub(crate) fn max_volt_mv(&self) -> u32 {
        *self.volt_mv.iter().max().expect("No voltages")
    }
}

/// A power zone definition (we have no idea what this is but Apple puts them in the DT).
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct PowerZone {
    pub(crate) target: u32,
    pub(crate) target_offset: u32,
    pub(crate) filter_tc: u32,
}

/// An MMIO mapping used by the firmware.
#[derive(Debug, Copy, Clone)]
pub(crate) struct IOMapping {
    /// Base physical address of the mapping.
    pub(crate) base: usize,
    /// Whether this mapping should be replicated to all dies
    pub(crate) per_die: bool,
    /// Number of mappings.
    pub(crate) count: usize,
    /// Size of one mapping.
    pub(crate) size: usize,
    /// Stride between mappings.
    pub(crate) stride: usize,
    /// Whether the mapping should be writable.
    pub(crate) writable: bool,
}

/// One entry of the G15 register-window table (macOS's chip+0x6d0 grid).
/// Kind 1 entries with a nonzero base and size
/// are register windows the driver GPU-maps; kind > 1 entries are PIO
/// buffers holding `kind` physical addresses (the pairs below).
#[derive(Debug, Clone, Copy)]
pub(crate) struct G15Window {
    /// Entry flag byte (+0x00); passed to the mapping as the RW attribute.
    pub(crate) flag: u8,
    /// Entry kind (+0x04): 0 unused, 1 mapped window, >1 PIO pairs.
    pub(crate) kind: u32,
    /// Entry base (+0x08): window physical address (kind 1) or first pair
    /// (kind > 1). 0 = the window is not present.
    pub(crate) base: u64,
    /// Entry size (+0x88).
    pub(crate) size: u32,
    /// kind > 1: the remaining pairs (after `base`); kind <= 1: empty.
    pub(crate) pairs: &'static [u64],
}

impl G15Window {
    /// Convenience constructor for a kind-1 (mapped) window.
    pub(crate) const fn mapped(base: u64, size: u32, flag: u8) -> G15Window {
        G15Window {
            flag,
            kind: 1,
            base,
            size,
            pairs: &[],
        }
    }

    /// Convenience constructor for an unused (all-zero) entry.
    pub(crate) const fn none() -> G15Window {
        G15Window {
            flag: 0,
            kind: 0,
            base: 0,
            size: 0,
            pairs: &[],
        }
    }
}

impl IOMapping {
    /// Convenience constructor for a new IOMapping.
    #[allow(dead_code)] // for M1/M2 io_mappings tables; t6034 has none
    pub(crate) const fn new(
        base: usize,
        per_die: bool,
        count: usize,
        size: usize,
        stride: usize,
        writable: bool,
    ) -> IOMapping {
        IOMapping {
            base,
            per_die,
            count,
            size,
            stride,
            writable,
        }
    }
}

/// Unknown HwConfigA fields that vary from SoC to SoC.
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct HwConfigA {
    pub(crate) unk_87c: i32,
    pub(crate) unk_8cc: u32,
    pub(crate) unk_e24: u32,
}

/// Unknown HwConfigB fields that vary from SoC to SoC.
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct HwConfigB {
    pub(crate) unk_454: u32,
    pub(crate) unk_4e0: u64,
    pub(crate) unk_534: u32,
    #[allow(dead_code)] // read for V < V13_0B4 only
    pub(crate) unk_ab8: u32,
    #[allow(dead_code)] // read for V < V13_0B4 only
    pub(crate) unk_abc: u32,
    pub(crate) unk_b30: u32,
}

/// Render command configs that vary from SoC to SoC.
#[derive(Debug, Copy, Clone)]
pub(crate) struct HwRenderConfig {
    /// Vertex/tiling-related configuration register (lsb: disable clustering)
    pub(crate) tiling_control: u32,
}

#[derive(Debug)]
pub(crate) struct HwConfigShared2Curves {
    pub(crate) t1_coef: u32,
    pub(crate) t2: &'static [i16],
    pub(crate) t3_coefs: &'static [u32],
    pub(crate) t3_scales: &'static [u32],
}

/// Static hardware clustering configuration for multi-cluster SoCs.
#[derive(Debug)]
pub(crate) struct HwClusteringConfig {
    pub(crate) meta1_blocksize: usize,
    pub(crate) meta2_size: usize,
    pub(crate) meta3_size: usize,
    pub(crate) meta4_size: usize,
    pub(crate) max_splits: usize,
}

/// Static hardware configuration for a given SoC model.
#[derive(Debug)]
pub(crate) struct HwConfig {
    /// Chip ID in hex format (e.g. 0x8103 for t8103).
    pub(crate) chip_id: u32,
    /// GPU generation.
    pub(crate) gpu_gen: GpuGen,
    /// GPU variant type.
    pub(crate) gpu_variant: GpuVariant,
    /// GPU core type ID (as known by the firmware).
    pub(crate) gpu_core: GpuCore,

    /// Base clock used used for timekeeping.
    pub(crate) base_clock_hz: u32,
    /// Output address space for the UAT on this SoC.
    pub(crate) uat_oas: u32,
    /// Number of dies on this SoC.
    pub(crate) num_dies: u32,
    /// Maximum number of clusters on this SoC.
    pub(crate) max_num_clusters: u32,
    /// Maximum number of cores per cluster for this GPU.
    pub(crate) max_num_cores: u32,
    /// Maximum number of frags per cluster for this GPU.
    pub(crate) max_num_frags: u32,
    /// Maximum number of GPs per cluster for this GPU.
    pub(crate) max_num_gps: u32,

    /// Required size of the first preemption buffer.
    pub(crate) preempt1_size: usize,
    /// Required size of the second preemption buffer.
    pub(crate) preempt2_size: usize,
    /// Required size of the third preemption buffer.
    pub(crate) preempt3_size: usize,

    /// Required size of the compute preemption buffer.
    pub(crate) compute_preempt1_size: usize,

    pub(crate) clustering: Option<HwClusteringConfig>,

    /// Rendering-relevant configuration.
    pub(crate) render: HwRenderConfig,

    /// Misc HWDataA field values.
    pub(crate) da: HwConfigA,
    /// Misc HWDataB field values.
    pub(crate) db: HwConfigB,
    /// HwDataShared1.table.
    pub(crate) shared1_tab: &'static [i32],
    /// HwDataShared1.unk_a4.
    pub(crate) shared1_a4: u32,
    /// HwDataShared2.table.
    pub(crate) shared2_tab: &'static [i32],
    /// HwDataShared2.unk_508.
    pub(crate) shared2_unk_508: u32,
    /// HwDataShared2.unk_508.
    pub(crate) shared2_curves: Option<HwConfigShared2Curves>,

    /// HwDataShared3.unk_8.
    pub(crate) shared3_unk: u32,
    /// HwDataShared3.table.
    pub(crate) shared3_tab: &'static [u32],

    /// Globals.idle_off_standby_timer.
    pub(crate) idle_off_standby_timer_default: u32,
    /// Globals.unk_hws2_4.
    pub(crate) unk_hws2_4: Option<[F32; 8]>,
    /// Globals.unk_hws2_24.
    pub(crate) unk_hws2_24: u32,
    /// Globals.unk_54
    pub(crate) global_unk_54: u16,

    /// Constant related to SRAM voltages.
    pub(crate) sram_k: F32,
    /// Unknown per-cluster coefficients 1.
    pub(crate) unk_coef_a: &'static [&'static [F32]],
    /// Unknown per-cluster coefficients 2.
    pub(crate) unk_coef_b: &'static [&'static [F32]],
    /// Unknown table in Global struct.
    pub(crate) global_tab: Option<&'static [u8]>,
    /// Whether this GPU has CS/AFR performance states
    pub(crate) has_csafr: bool,

    /// Temperature sensor list (8 bits per sensor).
    pub(crate) fast_sensor_mask: [u64; 2],
    /// Temperature sensor list (alternate).
    pub(crate) fast_sensor_mask_alt: [u64; 2],
    /// Temperature sensor present bitmask.
    #[allow(dead_code)] // read for V < V13_0B4 only
    pub(crate) fast_die0_sensor_present: u32,
    /// G15: the GPU's MTR temperature sensors, one bit per entry of PMGR's
    /// MtrPolynomGFX. The firmware fails on an MTR alarm that none of them
    /// raised (power.md). m1n1's `apple,mtr-sensor-mask` replaces it.
    pub(crate) mtr_sensor_mask: [u64; 2],
    /// G15: the hotspot sensors the SoC-hot and fast-die controllers watch
    /// (`getGPUHotspotSensorMask`; G15S keeps only the first word).
    pub(crate) hotspot_sensor_mask: [u64; 2],
    /// G15: the fast-die controller's target in centi-degrees
    /// (`populateFastDieDeviceConfigData`).
    pub(crate) fastdie_target: u32,
    /// Required MMIO mappings for this GPU/firmware (M1 layout; empty for
    /// G15, which uses `g15_windows` instead).
    pub(crate) io_mappings: &'static [Option<IOMapping>],
    /// G15: the 31 register-window table entries.
    /// None = the table is not decoded for this chip yet.
    pub(crate) g15_windows: Option<&'static [G15Window]>,
    /// G15: the AON PTD rows the firmware's AON PTD table can use — rows
    /// of the ADT `/arm-io/aon-ptd` `ptd_data_table` (12 bytes: the u32
    /// identifier, u16 version, u16 start, u8 size, u8 IRQ, u8 entry IRQ,
    /// u8 features).
    pub(crate) aon_ptd: &'static [[u8; 12]],
    /// SRAM base
    #[allow(dead_code)] // the M1/M2 sram mapping; G15 has none
    pub(crate) sram_base: Option<usize>,
    /// SRAM size
    #[allow(dead_code)] // the M1/M2 sram mapping; G15 has none
    pub(crate) sram_size: Option<usize>,
}

/// Dynamic (fetched from hardware/DT) configuration.
#[derive(Debug)]
pub(crate) struct DynConfig {
    /// Base physical address of the UAT TTB (from DT reserved memory region).
    pub(crate) uat_ttb_base: u64,
    /// GPU ID configuration read from hardware.
    pub(crate) id: GpuIdConfig,
    /// Power calibration configuration for this specific chip/device.
    pub(crate) pwr: PwrConfig,
    /// Firmware version.
    #[allow(dead_code)]
    pub(crate) firmware_version: KVec<u32>,

    pub(crate) hw_data_a: KVVec<u8>,
    pub(crate) hw_data_b: KVVec<u8>,
    pub(crate) hw_globals: KVVec<u8>,
}

/// Specific GPU ID configuration fetched from SGX MMIO registers.
#[derive(Debug)]
pub(crate) struct GpuIdConfig {
    /// GPU generation (should match static config).
    pub(crate) gpu_gen: GpuGen,
    /// GPU variant type (should match static config).
    pub(crate) gpu_variant: GpuVariant,
    /// GPU silicon revision.
    pub(crate) gpu_rev: GpuRevision,
    /// GPU silicon revision ID (firmware enum).
    pub(crate) gpu_rev_id: GpuRevisionID,
    /// Total number of GPU clusters.
    pub(crate) num_clusters: u32,
    /// Maximum number of GPU cores per cluster.
    pub(crate) num_cores: u32,
    /// Number of frags per cluster.
    pub(crate) num_frags: u32,
    /// Number of GPs per cluster.
    pub(crate) num_gps: u32,
    /// Total number of active cores for the whole GPU.
    pub(crate) total_active_cores: u32,
    /// Mask of active cores per cluster.
    pub(crate) core_masks: KVec<u32>,
    /// Packed mask of all active cores.
    pub(crate) core_masks_packed: KVec<u32>,
    /// G15: the perf-state maps read from the GPU (table A's 16 entries,
    /// then table B's), when its ID was.
    pub(crate) g15_pstate_map: Option<[u32; 32]>,
    /// G15: die 0's CS mask (MRR `0x141600`), 0 when not read.
    pub(crate) g15_cs_mask: u32,
}

/// Configurable CS/AFR GPU power settings from the device tree.
#[derive(Debug)]
pub(crate) struct CsAfrPwrConfig {
    /// GPU CS performance state list.
    pub(crate) perf_states_cs: KVec<PState>,
    /// GPU AFR performance state list.
    pub(crate) perf_states_afr: KVec<PState>,

    /// CS leakage coefficient per die.
    pub(crate) leak_coef_cs: KVec<F32>,
    /// AFR leakage coefficient per die.
    pub(crate) leak_coef_afr: KVec<F32>,

    /// Minimum voltage for the CS/AFR SRAM power domain in microvolts.
    pub(crate) min_sram_microvolt: u32,
}

/// Configurable GPU power settings from the device tree.
#[derive(Debug)]
pub(crate) struct PwrConfig {
    /// GPU performance state list.
    pub(crate) perf_states: KVec<PState>,
    /// G15: the second GPU performance state table (`apple,gpu2-opp`, the
    /// second table macOS's `createMGPUPerfStateTables` builds).
    pub(crate) perf_states_2: KVec<PState>,
    /// G15: the perf-state map nibbles macOS reads at probe (16 for
    /// the first table, then 16 for the second; `apple,perf-state-map`).
    pub(crate) perf_state_map: KVec<u32>,
    /// G15: the GPU's AON PTD rows (`HwConfig::aon_ptd`'s layout).
    pub(crate) aon_ptd: KVec<[u8; 12]>,
    /// G15: the GPU's MTR sensors (`HwConfig::mtr_sensor_mask`).
    pub(crate) mtr_sensor_mask: [u64; 2],
    /// G15: the live ADT's source perf-state rows (`apple,perf-states`),
    /// {Hz, the first table's mV}.
    pub(crate) source_states: KVec<(u32, u32)>,
    /// GPU power zone list.
    pub(crate) power_zones: KVec<PowerZone>,

    /// Core leakage coefficient per cluster.
    pub(crate) core_leak_coef: KVec<F32>,
    /// SRAM leakage coefficient per cluster.
    pub(crate) sram_leak_coef: KVec<F32>,

    pub(crate) csafr: Option<CsAfrPwrConfig>,

    /// Maximum total power of the GPU in milliwatts.
    pub(crate) max_power_mw: u32,
    /// Maximum frequency of the GPU in megahertz.
    pub(crate) max_freq_mhz: u32,

    /// Minimum performance state to start at.
    pub(crate) perf_base_pstate: u32,
    /// Maximum enabled performance state.
    pub(crate) perf_max_pstate: u32,

    /// Minimum voltage for the SRAM power domain in microvolts.
    pub(crate) min_sram_microvolt: u32,

    // Most of these fields are just named after Apple ADT property names and we don't fully
    // understand them. They configure various power-related PID loops and filters.
    /// Average power filter time constant in milliseconds.
    pub(crate) avg_power_filter_tc_ms: u32,
    /// Average power filter PID integral gain?
    pub(crate) avg_power_ki_only: F32,
    /// Average power filter PID proportional gain?
    pub(crate) avg_power_kp: F32,
    pub(crate) avg_power_min_duty_cycle: u32,
    /// Average power target filter time constant in periods.
    pub(crate) avg_power_target_filter_tc: u32,
    /// "Fast die0" (temperature?) PID integral gain.
    pub(crate) fast_die0_integral_gain: F32,
    /// "Fast die0" (temperature?) PID proportional gain.
    pub(crate) fast_die0_proportional_gain: F32,
    pub(crate) fast_die0_prop_tgt_delta: u32,
    pub(crate) fast_die0_release_temp: u32,
    /// Delay from the fender (?) becoming idle to powerdown
    pub(crate) fender_idle_off_delay_ms: u32,
    /// Timeout from firmware early wake to sleep if no work was submitted (?)
    pub(crate) fw_early_wake_timeout_ms: u32,
    /// Delay from the GPU becoming idle to powerdown
    pub(crate) idle_off_delay_ms: u32,
    /// Related to the above?
    pub(crate) idle_off_standby_timer: u32,
    /// G15's idle-off predictor's minimum confidence.
    pub(crate) idle_off_min_conf: F32,
    /// Percent?
    pub(crate) perf_boost_ce_step: u32,
    /// Minimum utilization before performance state is increased in %.
    pub(crate) perf_boost_min_util: u32,
    pub(crate) perf_filter_drop_threshold: u32,
    /// Performance PID filter time constant? (periods?)
    pub(crate) perf_filter_time_constant: u32,
    /// Performance PID filter time constant 2? (periods?)
    pub(crate) perf_filter_time_constant2: u32,
    /// Performance PID integral gain.
    pub(crate) perf_integral_gain: F32,
    /// Performance PID integral gain 2 (?).
    pub(crate) perf_integral_gain2: F32,
    pub(crate) perf_integral_min_clamp: u32,
    /// Performance PID proportional gain.
    pub(crate) perf_proportional_gain: F32,
    /// Performance PID proportional gain 2 (?).
    pub(crate) perf_proportional_gain2: F32,
    pub(crate) perf_reset_iters: u32,
    /// Target GPU utilization for the performance controller in %.
    pub(crate) perf_tgt_utilization: u32,
    /// Power sampling period in milliseconds.
    pub(crate) power_sample_period: u32,
    /// PPM (?) filter time constant in milliseconds.
    pub(crate) ppm_filter_time_constant_ms: u32,
    /// PPM (?) filter PID integral gain.
    pub(crate) ppm_ki: F32,
    /// PPM (?) filter PID proportional gain.
    pub(crate) ppm_kp: F32,
    /// Power consumption filter time constant (periods?)
    pub(crate) pwr_filter_time_constant: u32,
    /// Power consumption filter PID integral gain.
    pub(crate) pwr_integral_gain: F32,
    pub(crate) pwr_integral_min_clamp: u32,
    pub(crate) pwr_min_duty_cycle: u32,
    pub(crate) pwr_proportional_gain: F32,
    /// Power sample period in base clocks, used when not an integer number of ms
    pub(crate) pwr_sample_period_aic_clks: u32,

    pub(crate) se_engagement_criteria: i32,
    pub(crate) se_filter_time_constant: u32,
    pub(crate) se_filter_time_constant_1: u32,
    pub(crate) se_inactive_threshold: u32,
    pub(crate) se_ki: F32,
    pub(crate) se_ki_1: F32,
    pub(crate) se_kp: F32,
    pub(crate) se_kp_1: F32,
    pub(crate) se_reset_criteria: u32,
}

impl PwrConfig {
    fn load_opp(
        dev: &device::Device,
        name: &CStr,
        voltage_count: u32,
        with_power: bool,
    ) -> Result<KVec<PState>> {
        let mut perf_states = KVec::new();

        let node = dev.of_node().ok_or(EIO)?;
        let opps = node.parse_phandle(name, 0).ok_or(EIO)?;

        for opp in opps.children() {
            let freq_hz: u64 = opp.get_property(c_str!("opp-hz"))?;
            let mut volt_uv: KVec<u32> = opp.get_property(c_str!("opp-microvolt"))?;
            let pwr_uw: u32 = if with_power {
                opp.get_property(c_str!("opp-microwatt"))?
            } else {
                0
            };

            if volt_uv.len() != voltage_count as usize {
                dev_err!(
                    dev,
                    "Invalid opp-microvolt length (expected {}, got {})\n",
                    voltage_count,
                    volt_uv.len()
                );
                return Err(EINVAL);
            }

            volt_uv.iter_mut().for_each(|a| *a /= 1000);
            let volt_mv = volt_uv;

            let pwr_mw = pwr_uw / 1000;

            perf_states.push(
                PState {
                    freq_hz: freq_hz.try_into()?,
                    volt_mv,
                    pwr_mw,
                },
                GFP_KERNEL,
            )?;
        }

        if perf_states.is_empty() {
            Err(EINVAL)
        } else {
            Ok(perf_states)
        }
    }

    /// Load the GPU power configuration from the device tree, with the
    /// GPU's ID and perf-state maps.
    pub(crate) fn load(
        dev: &device::Device,
        cfg: &HwConfig,
        id: &GpuIdConfig,
    ) -> Result<PwrConfig> {
        let node = dev.of_node().ok_or(EIO)?;
        // The DT's own tables (one chip's volts), when it has them.
        let mut perf_states = if node
            .parse_phandle(c_str!("operating-points-v2"), 0)
            .is_some()
        {
            Self::load_opp(
                dev,
                c_str!("operating-points-v2"),
                cfg.max_num_clusters,
                true,
            )?
        } else {
            KVec::new()
        };
        let mut perf_states_2 = if node.parse_phandle(c_str!("apple,gpu2-opp"), 0).is_some() {
            Self::load_opp(dev, c_str!("apple,gpu2-opp"), cfg.max_num_clusters, false)?
        } else {
            KVec::new()
        };

        macro_rules! prop {
            ($prop:expr, $default:expr) => {{
                node.get_opt_property(c_str!($prop))
                    .map_err(|e| {
                        dev_err!(dev, "Error reading property {}: {:?}\n", $prop, e);
                        e
                    })?
                    .unwrap_or($default)
            }};
            ($prop:expr) => {{
                node.get_property(c_str!($prop)).map_err(|e| {
                    dev_err!(dev, "Error reading property {}: {:?}\n", $prop, e);
                    e
                })?
            }};
        }

        let pz_data = prop!("apple,power-zones", KVec::new());

        if pz_data.len() > 3 * MAX_POWERZONES || pz_data.len() % 3 != 0 {
            dev_err!(dev, "Invalid apple,power-zones value\n");
            return Err(EINVAL);
        }

        let pz_count = pz_data.len() / 3;
        let mut power_zones = KVec::new();
        for i in (0..pz_count).step_by(3) {
            power_zones.push(
                PowerZone {
                    target: pz_data[i],
                    target_offset: pz_data[i + 1],
                    filter_tc: pz_data[i + 2],
                },
                GFP_KERNEL,
            )?;
        }

        let core_leak_coef: KVec<F32> = prop!("apple,core-leak-coef");
        let sram_leak_coef: KVec<F32> = prop!("apple,sram-leak-coef");

        if core_leak_coef.len() != cfg.max_num_clusters as usize {
            dev_err!(dev, "Invalid apple,core-leak-coef\n");
            return Err(EINVAL);
        }
        if sram_leak_coef.len() != cfg.max_num_clusters as usize {
            dev_err!(dev, "Invalid apple,sram_leak_coef\n");
            return Err(EINVAL);
        }

        let csafr = if cfg.has_csafr {
            Some(CsAfrPwrConfig {
                perf_states_cs: Self::load_opp(dev, c_str!("apple,cs-opp"), cfg.num_dies, false)?,
                perf_states_afr: Self::load_opp(dev, c_str!("apple,afr-opp"), cfg.num_dies, false)?,
                leak_coef_cs: prop!("apple,cs-leak-coef"),
                leak_coef_afr: prop!("apple,afr-leak-coef"),
                min_sram_microvolt: prop!("apple,csafr-min-sram-microvolt"),
            })
        } else {
            None
        };

        let power_sample_period: u32 = prop!("apple,power-sample-period");

        let mut perf_state_map: KVec<u32> = prop!("apple,perf-state-map", KVec::new());
        if !perf_state_map.is_empty() && perf_state_map.len() != 32 {
            dev_err!(dev, "Invalid apple,perf-state-map\n");
            return Err(EINVAL);
        }
        if let Some(live) = id.g15_pstate_map {
            if perf_state_map.is_empty() {
                perf_state_map.extend_from_slice(&live, GFP_KERNEL)?;
            } else if perf_state_map[..] != live[..] {
                dev_warn!(
                    dev,
                    "GPU perf-state maps: the GPU's {:?} are not the DT's\n",
                    live
                );
            }
        }

        // G15: the live ADT's tables (`apple,perf-states`, from m1n1), built
        // with the GPU's maps. Where the DT has tables of its own, they stay
        // and are checked against these, and a bad live table is only
        // reported.
        let raw: Option<KVec<u32>> = node.get_opt_property(c_str!("apple,perf-states"))?;
        let mut source_states = KVec::new();
        if let Some(raw) = raw {
            let tables: u32 = prop!("apple,perf-state-table-count", 1);
            let map = match id.g15_pstate_map {
                Some(live) => Some(live),
                None if perf_state_map.len() == 32 => {
                    let mut map = [0u32; 32];
                    map.copy_from_slice(&perf_state_map);
                    Some(map)
                }
                None => None,
            };
            let built = map.ok_or(EINVAL).and_then(|map| {
                let (a, b) = g15_pstates::build(
                    &raw,
                    tables,
                    cfg.max_num_clusters,
                    cfg.num_dies,
                    &map,
                    id,
                    csafr.as_ref(),
                    g15_pstates::f32_q30(core_leak_coef.first().map_or(0, |c| c.to_bits())),
                )?;
                Ok((a, b, map))
            });
            match built {
                Err(e) if perf_states.is_empty() => {
                    dev_err!(dev, "Invalid apple,perf-states or no GPU perf-state maps\n");
                    return Err(e);
                }
                Err(_) => dev_warn!(
                    dev,
                    "GPU perf states: the live ADT's are invalid; the DT's stay\n"
                ),
                Ok((a, b, map)) => {
                    // build() checked the shape: tables x count rows of {Hz, mV}.
                    let count = raw.len() / (2 * tables as usize);
                    for i in 0..count {
                        source_states.push((raw[2 * i], raw[2 * i + 1]), GFP_KERNEL)?;
                    }
                    if perf_states.is_empty() {
                        perf_states = a;
                        perf_states_2 = b;
                        perf_state_map.clear();
                        perf_state_map.extend_from_slice(&map, GFP_KERNEL)?;
                    } else if g15_pstates::same(&a, &perf_states)
                        && g15_pstates::same(&b, &perf_states_2)
                    {
                        dev_info!(dev, "GPU perf states: the live ADT's are the DT's\n");
                    } else {
                        dev_warn!(
                            dev,
                            "GPU perf states: the live ADT's differ from the DT's, which stay: {:?} {:?}\n",
                            a,
                            b
                        );
                    }
                }
            }
        }
        if perf_states.is_empty() {
            dev_err!(dev, "No GPU perf states\n");
            return Err(EINVAL);
        }

        // G15: the AON PTD rows of the live ADT's `ptd_data_table`
        // (`apple,ptd-data-table`, from m1n1): {u32 id, u16 version, u16
        // start, u8 size, u8 IRQ, u8 entry IRQ, u8 features}, the GPU's ids
        // "RT..". Where the hardware config has rows, they stay and are
        // checked against these.
        let ptd: KVec<u8> = prop!("apple,ptd-data-table", KVec::new());
        let mut aon_ptd = KVec::new();
        for row in ptd.chunks_exact(12) {
            let mut r = [0u8; 12];
            r.copy_from_slice(row);
            r[..4].reverse();
            if r[..2] == *b"RT" {
                aon_ptd.push(r, GFP_KERNEL)?;
            }
        }
        if !cfg.aon_ptd.is_empty() {
            if !aon_ptd.is_empty() {
                let same = cfg
                    .aon_ptd
                    .iter()
                    .all(|row| aon_ptd.iter().any(|r| r == row));
                if same {
                    dev_info!(dev, "AON PTD: the live ADT's rows are the config's\n");
                } else {
                    dev_warn!(
                        dev,
                        "AON PTD: the live ADT's rows differ from the config's, which stay: {:x?}\n",
                        aon_ptd
                    );
                }
            }
            aon_ptd.clear();
            aon_ptd.extend_from_slice(cfg.aon_ptd, GFP_KERNEL)?;
        }

        // G15: the MTR sensors of the live ADT's PMGR
        // `mtr-polynom-fuse-agx`, which macOS's PMGR publishes as
        // MtrPolynomGFX (`apple,mtr-sensor-mask`, from m1n1: u32 cells, low
        // word first); else the hardware config's.
        let mtr: KVec<u32> = prop!("apple,mtr-sensor-mask", KVec::new());
        let mtr_sensor_mask = match mtr[..] {
            [a, b, c, d] => {
                let m = [
                    u64::from(a) | u64::from(b) << 32,
                    u64::from(c) | u64::from(d) << 32,
                ];
                if m == cfg.mtr_sensor_mask {
                    dev_info!(dev, "MTR sensors: the live ADT's are the config's\n");
                } else {
                    dev_info!(
                        dev,
                        "MTR sensors: the live ADT's {:#x?} (the config's {:#x?})\n",
                        m,
                        cfg.mtr_sensor_mask
                    );
                }
                m
            }
            _ => cfg.mtr_sensor_mask,
        };

        Ok(PwrConfig {
            core_leak_coef,
            sram_leak_coef,

            max_power_mw: perf_states.iter().map(|a| a.pwr_mw).max().unwrap(),
            max_freq_mhz: perf_states.iter().map(|a| a.freq_hz).max().unwrap() / 1_000_000,

            perf_base_pstate: prop!("apple,perf-base-pstate", 1),
            perf_max_pstate: perf_states.len() as u32 - 1,
            min_sram_microvolt: prop!("apple,min-sram-microvolt"),

            avg_power_filter_tc_ms: prop!("apple,avg-power-filter-tc-ms"),
            avg_power_ki_only: prop!("apple,avg-power-ki-only"),
            avg_power_kp: prop!("apple,avg-power-kp"),
            avg_power_min_duty_cycle: prop!("apple,avg-power-min-duty-cycle"),
            avg_power_target_filter_tc: prop!("apple,avg-power-target-filter-tc"),
            fast_die0_integral_gain: prop!("apple,fast-die0-integral-gain"),
            fast_die0_proportional_gain: prop!("apple,fast-die0-proportional-gain"),
            fast_die0_prop_tgt_delta: prop!("apple,fast-die0-prop-tgt-delta", 0),
            fast_die0_release_temp: prop!("apple,fast-die0-release-temp", 80),
            fender_idle_off_delay_ms: prop!("apple,fender-idle-off-delay-ms", 40),
            fw_early_wake_timeout_ms: prop!("apple,fw-early-wake-timeout-ms", 5),
            idle_off_delay_ms: prop!("apple,idle-off-delay-ms", 2),
            idle_off_standby_timer: prop!(
                "apple,idleoff-standby-timer",
                cfg.idle_off_standby_timer_default
            ),
            idle_off_min_conf: prop!("apple,idleoff-min-conf", f32!(0.7)),
            perf_boost_ce_step: prop!("apple,perf-boost-ce-step", 25),
            perf_boost_min_util: prop!("apple,perf-boost-min-util", 100),
            perf_filter_drop_threshold: prop!("apple,perf-filter-drop-threshold"),
            perf_filter_time_constant2: prop!("apple,perf-filter-time-constant2"),
            perf_filter_time_constant: prop!("apple,perf-filter-time-constant"),
            perf_integral_gain2: prop!("apple,perf-integral-gain2"),
            perf_integral_gain: prop!("apple,perf-integral-gain", f32!(7.8956833)),
            perf_integral_min_clamp: prop!("apple,perf-integral-min-clamp"),
            perf_proportional_gain2: prop!("apple,perf-proportional-gain2"),
            perf_proportional_gain: prop!("apple,perf-proportional-gain", f32!(14.707963)),
            perf_reset_iters: prop!("apple,perf-reset-iters", 6),
            perf_tgt_utilization: prop!("apple,perf-tgt-utilization"),
            power_sample_period,
            ppm_filter_time_constant_ms: prop!("apple,ppm-filter-time-constant-ms"),
            ppm_ki: prop!("apple,ppm-ki"),
            ppm_kp: prop!("apple,ppm-kp"),
            pwr_filter_time_constant: prop!("apple,pwr-filter-time-constant", 313),
            pwr_integral_gain: prop!("apple,pwr-integral-gain", f32!(0.0202129)),
            pwr_integral_min_clamp: prop!("apple,pwr-integral-min-clamp", 0),
            pwr_min_duty_cycle: prop!("apple,pwr-min-duty-cycle"),
            pwr_proportional_gain: prop!("apple,pwr-proportional-gain", f32!(5.2831855)),
            pwr_sample_period_aic_clks: prop!(
                "apple,pwr-sample-period-aic-clks",
                cfg.base_clock_hz / 1000 * power_sample_period
            ),
            se_engagement_criteria: prop!("apple,se-engagement-criteria", -1),
            se_filter_time_constant: prop!("apple,se-filter-time-constant", 9),
            se_filter_time_constant_1: prop!("apple,se-filter-time-constant-1", 3),
            se_inactive_threshold: prop!("apple,se-inactive-threshold", 2500),
            se_ki: prop!("apple,se-ki", f32!(-50.0)),
            se_ki_1: prop!("apple,se-ki-1", f32!(-100.0)),
            se_kp: prop!("apple,se-kp", f32!(-5.0)),
            se_kp_1: prop!("apple,se-kp-1", f32!(-10.0)),
            se_reset_criteria: prop!("apple,se-reset-criteria", 50),

            perf_states,
            perf_states_2,
            perf_state_map,
            aon_ptd,
            mtr_sensor_mask,
            source_states,
            power_zones,
            csafr,
        })
    }

    pub(crate) fn max_frequency_khz(&self) -> u32 {
        self.perf_states[self.perf_max_pstate as usize].freq_hz / 1000
    }
}
