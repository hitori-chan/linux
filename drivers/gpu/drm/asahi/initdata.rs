// SPDX-License-Identifier: GPL-2.0-only OR MIT
#![allow(clippy::unusual_byte_groupings)]

//! GPU initialization data builder.
//!
//! The root of all interaction between the GPU firmware and the host driver is a complex set of
//! nested structures that we call InitData. This includes both GPU hardware/firmware configuration
//! and the pointers to the ring buffers and global data fields that are used for communication at
//! runtime.
//!
//! Many of these structures are poorly understood, so there are lots of hardcoded unknown values
//! derived from observing the InitData structures that macOS generates.


use crate::f32;
use crate::fw::initdata::*;
use crate::fw::types::*;
use crate::module_parameters;
use crate::{
    driver::AsahiDrmDevice,
    gem,
    gpu,
    hw,
    mmu, //
};
use kernel::error::{
    Error,
    Result, //
};
use kernel::io::{
    Io, //
};
use kernel::macros::versions;
use kernel::prelude::*;
use kernel::try_init;

use ::pin_init;
use ::pin_init::Init;

/// Builder helper for the global GPU InitData.
#[versions(AGX)]
pub(crate) struct InitDataBuilder<'a> {
    dev: &'a AsahiDrmDevice,
    alloc: &'a mut gpu::KernelAllocators,
    cfg: &'static hw::HwConfig,
    dyncfg: &'a hw::DynConfig,
}

#[versions(AGX)]
impl<'a> InitDataBuilder::ver<'a> {
    /// Create a new InitData builder
    pub(crate) fn new(
        dev: &'a AsahiDrmDevice,
        alloc: &'a mut gpu::KernelAllocators,
        cfg: &'static hw::HwConfig,
        dyncfg: &'a hw::DynConfig,
    ) -> InitDataBuilder::ver<'a> {
        InitDataBuilder::ver {
            dev,
            alloc,
            cfg,
            dyncfg,
        }
    }

    /// Create the HwDataShared1 structure, which is used in two places in InitData.
    fn hw_shared1(cfg: &'static hw::HwConfig) -> impl Init<raw::HwDataShared1> {
        init!(raw::HwDataShared1 {
            unk_a4: cfg.shared1_a4,
            ..Zeroable::init_zeroed()
        })
        .chain(|ret| {
            for (i, val) in cfg.shared1_tab.iter().enumerate() {
                ret.table[i] = *val;
            }
            Ok(())
        })
    }

    fn init_curve(
        curve: &mut raw::HwDataShared2Curve,
        unk_0: u32,
        unk_4: u32,
        t1: &[u16],
        t2: &[i16],
        t3: &[KVec<i32>],
    ) {
        curve.unk_0 = unk_0;
        curve.unk_4 = unk_4;
        (*curve.t1)[..t1.len()].copy_from_slice(t1);
        (*curve.t1)[t1.len()..].fill(t1[0]);
        (*curve.t2)[..t2.len()].copy_from_slice(t2);
        (*curve.t2)[t2.len()..].fill(t2[0]);
        for (i, a) in curve.t3.iter_mut().enumerate() {
            a.fill(0x3ffffff);
            if i < t3.len() {
                let b = &t3[i];
                (**a)[..b.len()].copy_from_slice(b);
            }
        }
    }

    /// Create the HwDataShared2 structure, which is used in two places in InitData.
    fn hw_shared2(
        cfg: &'static hw::HwConfig,
        dyncfg: &'a hw::DynConfig,
    ) -> impl Init<raw::HwDataShared2, Error> + 'a {
        try_init!(raw::HwDataShared2 {
            unk_28: Array::new([0xff; 16]),
            g14: Default::default(),
            unk_508: cfg.shared2_unk_508,
            ..Zeroable::init_zeroed()
        })
        .chain(|ret| {
            for (i, val) in cfg.shared2_tab.iter().enumerate() {
                ret.table[i] = *val;
            }

            let curve_cfg = match cfg.shared2_curves.as_ref() {
                None => return Ok(()),
                Some(a) => a,
            };

            let mut t1 = KVec::new();
            let mut t3 = KVec::new();

            for _ in 0..curve_cfg.t3_scales.len() {
                t3.push(KVec::new(), GFP_KERNEL)?;
            }

            for (i, ps) in dyncfg.pwr.perf_states.iter().enumerate() {
                let t3_coef = curve_cfg.t3_coefs[i];
                if t3_coef == 0 {
                    t1.push(0xffff, GFP_KERNEL)?;
                    for j in t3.iter_mut() {
                        j.push(0x3ffffff, GFP_KERNEL)?;
                    }
                    continue;
                }

                let f_khz = (ps.freq_hz / 1000) as u64;
                let v_max = ps.max_volt_mv() as u64;

                t1.push(
                    (1000000000 * (curve_cfg.t1_coef as u64) / (f_khz * v_max))
                        .try_into()
                        .unwrap(),
                    GFP_KERNEL,
                )?;

                for (j, scale) in curve_cfg.t3_scales.iter().enumerate() {
                    t3[j].push(
                        (t3_coef as u64 * 1000000100 * *scale as u64 / (f_khz * v_max * 6))
                            .try_into()
                            .unwrap(),
                        GFP_KERNEL,
                    )?;
                }
            }

            ret.g14.unk_14 = 0x6000000;
            Self::init_curve(
                &mut ret.g14.curve1,
                0,
                0x20000000,
                &[0xffff],
                &[0x0f07],
                &[],
            );
            Self::init_curve(&mut ret.g14.curve2, 7, 0x80000000, &t1, curve_cfg.t2, &t3);

            Ok(())
        })
    }

    /// Create the HwDataShared3 structure, which is used in two places in InitData.
    fn hw_shared3(cfg: &'static hw::HwConfig) -> impl Init<raw::HwDataShared3> {
        pin_init::init_zeroed::<raw::HwDataShared3>().chain(|ret| {
            if !cfg.shared3_tab.is_empty() {
                ret.unk_0 = 1;
                ret.unk_4 = 500;
                ret.unk_8 = cfg.shared3_unk;
                ret.table.copy_from_slice(cfg.shared3_tab);
                ret.unk_4c = 1;
            }
            Ok(())
        })
    }

    /// Create an unknown T81xx-specific data structure.
    fn t81xx_data(
        cfg: &'static hw::HwConfig,
        dyncfg: &'a hw::DynConfig,
    ) -> impl Init<raw::T81xxData> {
        let _perf_max_pstate = dyncfg.pwr.perf_max_pstate;

        pin_init::init_zeroed::<raw::T81xxData>().chain(move |_ret| {
            match cfg.chip_id {
                0x8103 | 0x8112 => {
                    #[ver(V < V13_3)]
                    {
                        _ret.unk_d8c = 0x80000000;
                        _ret.unk_d90 = 4;
                        _ret.unk_d9c = f32!(0.6);
                        _ret.unk_da4 = f32!(0.4);
                        _ret.unk_dac = f32!(0.38552);
                        _ret.unk_db8 = f32!(65536.0);
                        _ret.unk_dbc = f32!(13.56);
                        _ret.max_pstate_scaled = 100 * _perf_max_pstate;
                    }
                }
                _ => (),
            }
            Ok(())
        })
    }

    /// Create the HwDataA structure. This mostly contains power-related configuration.
    fn hwdata_a(&mut self) -> Result<GpuObject<HwDataA::ver>> {
        let pwr = &self.dyncfg.pwr;
        let period_ms = pwr.power_sample_period;
        let period_s = F32::from(period_ms) / f32!(1000.0);
        let ppm_filter_tc_periods = pwr.ppm_filter_time_constant_ms / period_ms;
        #[ver(V >= V13_0B4)]
        let ppm_filter_tc_ms_rounded = ppm_filter_tc_periods * period_ms;
        let ppm_filter_a = f32!(1.0) / ppm_filter_tc_periods.into();
        let perf_filter_a = f32!(1.0) / pwr.perf_filter_time_constant.into();
        let perf_filter_a2 = f32!(1.0) / pwr.perf_filter_time_constant2.into();
        let avg_power_target_filter_a = f32!(1.0) / pwr.avg_power_target_filter_tc.into();
        let avg_power_filter_tc_periods = pwr.avg_power_filter_tc_ms / period_ms;
        #[ver(V >= V13_0B4)]
        let avg_power_filter_tc_ms_rounded = avg_power_filter_tc_periods * period_ms;
        let avg_power_filter_a = f32!(1.0) / avg_power_filter_tc_periods.into();
        let pwr_filter_a = f32!(1.0) / pwr.pwr_filter_time_constant.into();

        let base_ps = pwr.perf_base_pstate;
        let base_ps_scaled = 100 * base_ps;
        let max_ps = pwr.perf_max_pstate;
        let max_ps_scaled = 100 * max_ps;
        let boost_ps_count = max_ps - base_ps;

        #[allow(unused_variables)]
        let base_clock_khz = self.cfg.base_clock_hz / 1000;
        let v_clocks_per_period = pwr.pwr_sample_period_aic_clks;

        #[allow(unused_variables)]
        let clocks_per_period_coarse = self.cfg.base_clock_hz / 1000 * pwr.power_sample_period;

        self.alloc
            .private
            .new_init(pin_init::init_zeroed(), |_inner, _ptr| {
                let cfg = &self.cfg;
                let dyncfg = &self.dyncfg;
                try_init!(raw::HwDataA::ver {
                    clocks_per_period: v_clocks_per_period,
                    #[ver(V >= V13_0B4)]
                    clocks_per_period_2: v_clocks_per_period,
                    pwr_status: AtomicU32::new(4),
                    unk_10: f32!(1.0),
                    actual_pstate: 1,
                    tgt_pstate: 1,
                    base_pstate_scaled: base_ps_scaled,
                    unk_40: 1,
                    max_pstate_scaled: max_ps_scaled,
                    min_pstate_scaled: 100,
                    unk_64c: 625,
                    pwr_filter_a_neg: f32!(1.0) - pwr_filter_a,
                    pwr_filter_a: pwr_filter_a,
                    pwr_integral_gain: pwr.pwr_integral_gain,
                    pwr_integral_min_clamp: pwr.pwr_integral_min_clamp.into(),
                    max_power_1: pwr.max_power_mw.into(),
                    pwr_proportional_gain: pwr.pwr_proportional_gain,
                    pwr_pstate_related_k: -F32::from(max_ps_scaled) / pwr.max_power_mw.into(),
                    pwr_pstate_max_dc_offset: pwr.pwr_min_duty_cycle as i32 - max_ps_scaled as i32,
                    max_pstate_scaled_2: max_ps_scaled,
                    max_power_2: pwr.max_power_mw,
                    max_pstate_scaled_3: max_ps_scaled,
                    ppm_filter_tc_periods_x4: ppm_filter_tc_periods * 4,
                    ppm_filter_a_neg: f32!(1.0) - ppm_filter_a,
                    ppm_filter_a: ppm_filter_a,
                    ppm_ki_dt: pwr.ppm_ki * period_s,
                    unk_6fc: f32!(65536.0),
                    ppm_kp: pwr.ppm_kp,
                    pwr_min_duty_cycle: pwr.pwr_min_duty_cycle,
                    max_pstate_scaled_4: max_ps_scaled,
                    unk_71c: f32!(0.0),
                    max_power_3: pwr.max_power_mw,
                    cur_power_mw_2: 0x0,
                    ppm_filter_tc_ms: pwr.ppm_filter_time_constant_ms,
                    #[ver(V >= V13_0B4)]
                    ppm_filter_tc_clks: ppm_filter_tc_ms_rounded * base_clock_khz,
                    perf_tgt_utilization: pwr.perf_tgt_utilization,
                    perf_boost_min_util: pwr.perf_boost_min_util,
                    perf_boost_ce_step: pwr.perf_boost_ce_step,
                    perf_reset_iters: pwr.perf_reset_iters,
                    unk_774: 6,
                    unk_778: 1,
                    perf_filter_drop_threshold: pwr.perf_filter_drop_threshold,
                    perf_filter_a_neg: f32!(1.0) - perf_filter_a,
                    perf_filter_a2_neg: f32!(1.0) - perf_filter_a2,
                    perf_filter_a: perf_filter_a,
                    perf_filter_a2: perf_filter_a2,
                    perf_ki: pwr.perf_integral_gain,
                    perf_ki2: pwr.perf_integral_gain2,
                    perf_integral_min_clamp: pwr.perf_integral_min_clamp.into(),
                    unk_79c: f32!(95.0),
                    perf_kp: pwr.perf_proportional_gain,
                    perf_kp2: pwr.perf_proportional_gain2,
                    boost_state_unk_k: F32::from(boost_ps_count) / f32!(0.95),
                    base_pstate_scaled_2: base_ps_scaled,
                    max_pstate_scaled_5: max_ps_scaled,
                    base_pstate_scaled_3: base_ps_scaled,
                    perf_tgt_utilization_2: pwr.perf_tgt_utilization,
                    base_pstate_scaled_4: base_ps_scaled,
                    unk_7fc: f32!(65536.0),
                    pwr_min_duty_cycle_2: pwr.pwr_min_duty_cycle.into(),
                    max_pstate_scaled_6: max_ps_scaled.into(),
                    max_freq_mhz: pwr.max_freq_mhz,
                    pwr_min_duty_cycle_3: pwr.pwr_min_duty_cycle,
                    min_pstate_scaled_4: f32!(100.0),
                    max_pstate_scaled_7: max_ps_scaled,
                    unk_alpha_neg: f32!(0.8),
                    unk_alpha: f32!(0.2),
                    fast_die0_sensor_mask: U64(cfg.fast_sensor_mask[0]),
                    #[ver(G >= G14X)]
                    fast_die1_sensor_mask: U64(cfg.fast_sensor_mask[1]),
                    fast_die0_release_temp_cc: 100 * pwr.fast_die0_release_temp,
                    unk_87c: cfg.da.unk_87c,
                    unk_880: 0x4,
                    unk_894: f32!(1.0),

                    fast_die0_ki_dt: pwr.fast_die0_integral_gain * period_s,
                    unk_8a8: f32!(65536.0),
                    fast_die0_kp: pwr.fast_die0_proportional_gain,
                    pwr_min_duty_cycle_4: pwr.pwr_min_duty_cycle,
                    max_pstate_scaled_8: max_ps_scaled,
                    max_pstate_scaled_9: max_ps_scaled,
                    fast_die0_prop_tgt_delta: 100 * pwr.fast_die0_prop_tgt_delta,
                    unk_8cc: cfg.da.unk_8cc,
                    max_pstate_scaled_10: max_ps_scaled,
                    max_pstate_scaled_11: max_ps_scaled,
                    unk_c2c: 1,
                    power_zone_count: pwr.power_zones.len() as u32,
                    max_power_4: pwr.max_power_mw,
                    max_power_5: pwr.max_power_mw,
                    max_power_6: pwr.max_power_mw,
                    avg_power_target_filter_a_neg: f32!(1.0) - avg_power_target_filter_a,
                    avg_power_target_filter_a: avg_power_target_filter_a,
                    avg_power_target_filter_tc_x4: 4 * pwr.avg_power_target_filter_tc,
                    avg_power_target_filter_tc_xperiod: period_ms * pwr.avg_power_target_filter_tc,
                    #[ver(V >= V13_0B4)]
                    avg_power_target_filter_tc_clks: period_ms
                        * pwr.avg_power_target_filter_tc
                        * base_clock_khz,
                    avg_power_filter_tc_periods_x4: 4 * avg_power_filter_tc_periods,
                    avg_power_filter_a_neg: f32!(1.0) - avg_power_filter_a,
                    avg_power_filter_a: avg_power_filter_a,
                    avg_power_ki_dt: pwr.avg_power_ki_only * period_s,
                    unk_d20: f32!(65536.0),
                    avg_power_kp: pwr.avg_power_kp,
                    avg_power_min_duty_cycle: pwr.avg_power_min_duty_cycle,
                    max_pstate_scaled_12: max_ps_scaled,
                    max_pstate_scaled_13: max_ps_scaled,
                    max_power_7: pwr.max_power_mw.into(),
                    max_power_8: pwr.max_power_mw,
                    avg_power_filter_tc_ms: pwr.avg_power_filter_tc_ms,
                    #[ver(V >= V13_0B4)]
                    avg_power_filter_tc_clks: avg_power_filter_tc_ms_rounded * base_clock_khz,
                    max_pstate_scaled_14: max_ps_scaled,
                    t81xx_data <- Self::t81xx_data(cfg, dyncfg),
                    #[ver(V >= V13_0B4)]
                    unk_e10_0 <- {
                        let filter_a = f32!(1.0) / pwr.se_filter_time_constant.into();
                        let filter_1_a = f32!(1.0) / pwr.se_filter_time_constant_1.into();
                        try_init!(raw::HwDataA130Extra {
                            unk_38: 4,
                            unk_3c: 8000,
                            gpu_se_inactive_threshold: pwr.se_inactive_threshold,
                            gpu_se_engagement_criteria: pwr.se_engagement_criteria,
                            gpu_se_reset_criteria: pwr.se_reset_criteria,
                            unk_54: 50,
                            unk_58: 0x1,
                            gpu_se_filter_a_neg: f32!(1.0) - filter_a,
                            gpu_se_filter_1_a_neg: f32!(1.0) - filter_1_a,
                            gpu_se_filter_a: filter_a,
                            gpu_se_filter_1_a: filter_1_a,
                            gpu_se_ki_dt: pwr.se_ki * period_s,
                            gpu_se_ki_1_dt: pwr.se_ki_1 * period_s,
                            unk_7c: f32!(65536.0),
                            gpu_se_kp: pwr.se_kp,
                            gpu_se_kp_1: pwr.se_kp_1,

                            #[ver(V >= V13_3)]
                            unk_8c: 100,
                            #[ver(V < V13_3)]
                            unk_8c: 40,

                            max_pstate_scaled_1: max_ps_scaled,
                            unk_9c: f32!(8000.0),
                            unk_a0: 1400,
                            gpu_se_filter_time_constant_ms: pwr.se_filter_time_constant * period_ms,
                            gpu_se_filter_time_constant_1_ms: pwr.se_filter_time_constant_1
                                * period_ms,
                            gpu_se_filter_time_constant_clks: U64((pwr.se_filter_time_constant
                                * clocks_per_period_coarse)
                                .into()),
                            gpu_se_filter_time_constant_1_clks: U64((pwr
                                .se_filter_time_constant_1
                                * clocks_per_period_coarse)
                                .into()),
                            unk_c4: f32!(65536.0),
                            unk_114: f32!(65536.0),
                            unk_124: 40,
                            max_pstate_scaled_2: max_ps_scaled,
                            ..Zeroable::init_zeroed()
                        })
                    },
                    fast_die0_sensor_mask_2: U64(cfg.fast_sensor_mask[0]),
                    #[ver(G >= G14X)]
                    fast_die1_sensor_mask_2: U64(cfg.fast_sensor_mask[1]),
                    unk_e24: cfg.da.unk_e24,
                    unk_e28: 1,
                    fast_die0_sensor_mask_alt: U64(cfg.fast_sensor_mask_alt[0]),
                    #[ver(G >= G14X)]
                    fast_die1_sensor_mask_alt: U64(cfg.fast_sensor_mask_alt[1]),
                    #[ver(V < V13_0B4)]
                    fast_die0_sensor_present: U64(cfg.fast_die0_sensor_present as u64),
                    unk_163c: 1,
                    unk_3644: 0,
                    hws1 <- Self::hw_shared1(cfg),
                    hws2 <- Self::hw_shared2(cfg, dyncfg),
                    hws3 <- Self::hw_shared3(cfg),
                    unk_3ce8: 1,
                    ..Zeroable::init_zeroed()
                })
                .chain(|raw| {
                    for i in 0..self.dyncfg.pwr.perf_states.len() {
                        raw.sram_k[i] = self.cfg.sram_k;
                    }

                    for (i, coef) in pwr.core_leak_coef.iter().enumerate() {
                        raw.core_leak_coef[i] = *coef;
                    }

                    for (i, coef) in pwr.sram_leak_coef.iter().enumerate() {
                        raw.sram_leak_coef[i] = *coef;
                    }

                    #[ver(V >= V13_0B4)]
                    if let Some(csafr) = pwr.csafr.as_ref() {
                        for (i, coef) in csafr.leak_coef_afr.iter().enumerate() {
                            raw.aux_leak_coef.cs_1[i] = *coef;
                            raw.aux_leak_coef.cs_2[i] = *coef;
                        }

                        for (i, coef) in csafr.leak_coef_cs.iter().enumerate() {
                            raw.aux_leak_coef.afr_1[i] = *coef;
                            raw.aux_leak_coef.afr_2[i] = *coef;
                        }
                    }

                    for i in 0..self.dyncfg.id.num_clusters as usize {
                        if let Some(coef_a) = self.cfg.unk_coef_a.get(i) {
                            (*raw.unk_coef_a1[i])[..coef_a.len()].copy_from_slice(coef_a);
                            (*raw.unk_coef_a2[i])[..coef_a.len()].copy_from_slice(coef_a);
                        }
                        if let Some(coef_b) = self.cfg.unk_coef_b.get(i) {
                            (*raw.unk_coef_b1[i])[..coef_b.len()].copy_from_slice(coef_b);
                            (*raw.unk_coef_b2[i])[..coef_b.len()].copy_from_slice(coef_b);
                        }
                    }

                    for (i, pz) in pwr.power_zones.iter().enumerate() {
                        raw.power_zones[i].target = pz.target;
                        raw.power_zones[i].target_off = pz.target - pz.target_offset;
                        raw.power_zones[i].filter_tc_x4 = 4 * pz.filter_tc;
                        raw.power_zones[i].filter_tc_xperiod = period_ms * pz.filter_tc;
                        let filter_a = f32!(1.0) / pz.filter_tc.into();
                        raw.power_zones[i].filter_a = filter_a;
                        raw.power_zones[i].filter_a_neg = f32!(1.0) - filter_a;
                        #[ver(V >= V13_0B4)]
                        raw.power_zones[i].unk_10 = 1320000000;
                    }

                    #[ver(V >= V13_0B4 && G >= G14X)]
                    for (i, j) in raw.hws2.g14.curve2.t1.iter().enumerate() {
                        raw.unk_hws2[i] = if *j == 0xffff { 0 } else { j / 2 };
                    }

                    if !dyncfg.hw_data_b.is_empty() {
                        unsafe {
                            let mut matches: bool = true;
                            let sla = core::slice::from_raw_parts(
                                raw as *const raw::HwDataA::ver as *const u8,
                                core::mem::size_of::<raw::HwDataA::ver>(),
                            );
                            if sla.len() != dyncfg.hw_data_a.len() {
                                matches = false;
                                dev_err!(
                                    self.dev.as_ref(),
                                    "!!! Hwdata A size mismatch: {} {}",
                                    sla.len(),
                                    dyncfg.hw_data_a.len(),
                                );
                            }
                            for i in 0..core::cmp::min(sla.len(), dyncfg.hw_data_a.len()) {
                                if sla[i] != dyncfg.hw_data_a[i] {
                                    matches = false;
                                    dev_err!(self.dev.as_ref(), "!!! Hwdata A first mismatch: {i}");
                                    break;
                                }
                            }
                            if matches {
                                dev_info!(self.dev.as_ref(), "!!! Hwdata A match");
                            }
                        }
                    }

                    Ok(())
                })
            })
    }

    /// Create the HwDataB structure. This mostly contains GPU-related configuration.
    fn hwdata_b(&mut self) -> Result<GpuObject<HwDataB::ver>> {
        self.alloc
            .private
            .new_init(pin_init::init_zeroed(), |_inner, _ptr| {
                let cfg = &self.cfg;
                let dyncfg = &self.dyncfg;
                try_init!(raw::HwDataB::ver {
                    // Userspace VA map related
                    #[ver(V < V13_0B4)]
                    unk_0: U64(0x13_00000000),
                    unk_8: U64(0x14_00000000),
                    #[ver(V < V13_0B4)]
                    unk_10: U64(0x1_00000000),
                    unk_18: U64(0xffc00000),
                    // USC start
                    unk_20: U64(0), // U64(0x11_00000000),
                    unk_28: U64(0), // U64(0x11_00000000),
                    // Unknown page
                    //unk_30: U64(0x6f_ffff8000),
                    unk_30: U64(mmu::IOVA_UNK_PAGE),
                    timestamp_area_base: U64(gpu::IOVA_KERN_TIMESTAMP_RANGE.start),
                    // TODO: yuv matrices
                    chip_id: cfg.chip_id,
                    unk_454: cfg.db.unk_454,
                    unk_458: 0x1,
                    unk_460: 0x1,
                    unk_464: 0x1,
                    unk_468: 0x1,
                    unk_47c: 0x1,
                    unk_484: 0x1,
                    unk_48c: 0x1,
                    base_clock_khz: cfg.base_clock_hz / 1000,
                    power_sample_period: dyncfg.pwr.power_sample_period,
                    unk_49c: 0x1,
                    unk_4a0: 0x1,
                    unk_4a4: 0x1,
                    unk_4c0: 0x1f,
                    unk_4e0: U64(cfg.db.unk_4e0),
                    unk_4f0: 0x1,
                    unk_4f4: 0x1,
                    unk_504: 0x31,
                    unk_524: 0x1, // use_secure_cache_flush
                    unk_534: cfg.db.unk_534,
                    num_frags: dyncfg.id.num_frags * dyncfg.id.num_clusters,
                    unk_554: 0x1,
                    uat_ttb_base: U64(dyncfg.uat_ttb_base),
                    gpu_core_id: cfg.gpu_core as u32,
                    gpu_rev_id: dyncfg.id.gpu_rev_id as u32,
                    num_cores: dyncfg.id.num_cores * dyncfg.id.num_clusters,
                    max_pstate: dyncfg.pwr.perf_states.len() as u32 - 1,
                    #[ver(V < V13_0B4)]
                    num_pstates: dyncfg.pwr.perf_states.len() as u32,
                    #[ver(V < V13_0B4)]
                    min_sram_volt: dyncfg.pwr.min_sram_microvolt / 1000,
                    #[ver(V < V13_0B4)]
                    unk_ab8: cfg.db.unk_ab8,
                    #[ver(V < V13_0B4)]
                    unk_abc: cfg.db.unk_abc,
                    #[ver(V < V13_0B4)]
                    unk_ac0: 0x1020,

                    #[ver(V >= V13_0B4)]
                    unk_ae4: Array::new([0x0, 0x3, 0x7, 0x7]),
                    #[ver(V < V13_0B4)]
                    unk_ae4: Array::new([0x0, 0xf, 0x3f, 0x3f]),
                    unk_b10: 0x1,
                    timer_offset: U64(0),
                    unk_b24: 0x1,
                    unk_b28: 0x1,
                    unk_b2c: 0x1,
                    unk_b30: cfg.db.unk_b30,
                    #[ver(V >= V13_0B4)]
                    unk_b38_0: 1,
                    #[ver(V >= V13_0B4)]
                    unk_b38_4: 1,
                    unk_b38: Array::new([0xffffffff; 12]),
                    #[ver(V >= V13_0B4 && V < V13_3)]
                    unk_c3c: 0x19,
                    #[ver(V >= V13_3)]
                    unk_c3c: 0x1a,
                    ..Zeroable::init_zeroed()
                })
                .chain(|raw| {
                    #[ver(V >= V13_3)]
                    for i in 0..16 {
                        raw.unk_arr_0[i] = i as u32;
                    }

                    let base_ps = self.dyncfg.pwr.perf_base_pstate as usize;
                    let max_ps = self.dyncfg.pwr.perf_max_pstate as usize;
                    let base_freq = self.dyncfg.pwr.perf_states[base_ps].freq_hz;
                    let max_freq = self.dyncfg.pwr.perf_states[max_ps].freq_hz;

                    for (i, ps) in self.dyncfg.pwr.perf_states.iter().enumerate() {
                        raw.frequencies[i] = ps.freq_hz / 1000000;
                        for (j, mv) in ps.volt_mv.iter().enumerate() {
                            let sram_mv = (*mv).max(self.dyncfg.pwr.min_sram_microvolt / 1000);
                            raw.voltages[i][j] = *mv;
                            raw.voltages_sram[i][j] = sram_mv;
                        }
                        for j in ps.volt_mv.len()..raw.voltages[i].len() {
                            raw.voltages[i][j] = raw.voltages[i][0];
                            raw.voltages_sram[i][j] = raw.voltages_sram[i][0];
                        }
                        raw.sram_k[i] = self.cfg.sram_k;
                        raw.rel_max_powers[i] = ps.pwr_mw * 100 / self.dyncfg.pwr.max_power_mw;
                        raw.rel_boost_freqs[i] = if i > base_ps {
                            (ps.freq_hz - base_freq) / ((max_freq - base_freq) / 100)
                        } else {
                            0
                        };
                    }

                    #[ver(V >= V13_0B4)]
                    if let Some(csafr) = self.dyncfg.pwr.csafr.as_ref() {
                        let aux = &mut raw.aux_ps;
                        aux.cs_max_pstate = (csafr.perf_states_cs.len() - 1).try_into()?;
                        aux.afr_max_pstate = (csafr.perf_states_afr.len() - 1).try_into()?;

                        for (i, ps) in csafr.perf_states_cs.iter().enumerate() {
                            aux.cs_frequencies[i] = ps.freq_hz / 1000000;
                            for (j, mv) in ps.volt_mv.iter().enumerate() {
                                let sram_mv = (*mv).max(csafr.min_sram_microvolt / 1000);
                                aux.cs_voltages[i][j] = *mv;
                                aux.cs_voltages_sram[i][j] = sram_mv;
                            }
                        }

                        for (i, ps) in csafr.perf_states_afr.iter().enumerate() {
                            aux.afr_frequencies[i] = ps.freq_hz / 1000000;
                            for (j, mv) in ps.volt_mv.iter().enumerate() {
                                let sram_mv = (*mv).max(csafr.min_sram_microvolt / 1000);
                                aux.afr_voltages[i][j] = *mv;
                                aux.afr_voltages_sram[i][j] = sram_mv;
                            }
                        }
                    }

                    // Special case override for T602x
                    #[ver(G == G14X)]
                    if dyncfg.id.gpu_rev_id == hw::GpuRevisionID::B1 {
                        raw.gpu_rev_id = hw::GpuRevisionID::B0 as u32;
                    }

                    if !dyncfg.hw_data_b.is_empty() {
                        unsafe {
                            let mut matches: bool = true;
                            let sla = core::slice::from_raw_parts(
                                raw as *const raw::HwDataB::ver as *const u8,
                                core::mem::size_of::<raw::HwDataB::ver>(),
                            );
                            if sla.len() != dyncfg.hw_data_b.len() {
                                matches = false;
                                dev_err!(
                                    self.dev.as_ref(),
                                    "!!! Hwdata B size mismatch: {} {}",
                                    sla.len(),
                                    dyncfg.hw_data_b.len(),
                                );
                            }
                            for i in 0..core::cmp::min(sla.len(), dyncfg.hw_data_b.len()) {
                                if sla[i] != dyncfg.hw_data_b[i] {
                                    matches = false;
                                    dev_err!(self.dev.as_ref(), "!!! Hwdata B first mismatch: {i}");
                                    break;
                                }
                            }
                            if matches {
                                dev_info!(self.dev.as_ref(), "!!! Hwdata B match");
                            }
                        }
                    }

                    Ok(())
                })
            })
    }

    /// Create the Globals structure, which contains global firmware config including more power
    /// configuration data and globals used to exchange state between the firmware and driver.
    fn globals(&mut self) -> Result<GpuObject<Globals::ver>> {
        self.alloc
            .private
            .new_init(pin_init::init_zeroed(), |_inner, _ptr| {
                let cfg = &self.cfg;
                let dyncfg = &self.dyncfg;
                let pwr = &dyncfg.pwr;
                let period_ms = pwr.power_sample_period;
                let period_s = F32::from(period_ms) / f32!(1000.0);
                let avg_power_filter_tc_periods = pwr.avg_power_filter_tc_ms / period_ms;

                let max_ps = pwr.perf_max_pstate;
                let max_ps_scaled = 100 * max_ps;

                try_init!(raw::Globals::ver {
                    //ktrace_enable: 0xffffffff,
                    ktrace_enable: 0,
                    #[ver(V >= V13_2)]
                    unk_24_0: 3000,
                    unk_24: 0,
                    #[ver(V >= V13_0B4)]
                    debug: 0,
                    unk_28: 1,
                    #[ver(G >= G14X)]
                    unk_2c_0: 1,
                    #[ver(V >= V13_0B4 && G < G14X)]
                    unk_2c_0: 0,
                    unk_2c: 1,
                    unk_30: 0,
                    unk_34: 120,
                    // sub <- try_init!(raw::GlobalsSub::ver {
                        unk_54: cfg.global_unk_54,
                        unk_56: 40,
                        unk_58: 0xffff,
                        unk_5e: U32(1),
                        unk_66: U32(1),
                    //     ..Zeroable::init_zeroed()
                    // }),
                    unk_8900: 1,
                    pending_submissions: AtomicU32::new(0),
                    max_power: pwr.max_power_mw,
                    max_pstate_scaled: max_ps_scaled,
                    max_pstate_scaled_2: max_ps_scaled,
                    max_pstate_scaled_3: max_ps_scaled,
                    power_zone_count: pwr.power_zones.len() as u32,
                    avg_power_filter_tc_periods: avg_power_filter_tc_periods,
                    avg_power_ki_dt: pwr.avg_power_ki_only * period_s,
                    avg_power_kp: pwr.avg_power_kp,
                    avg_power_min_duty_cycle: pwr.avg_power_min_duty_cycle,
                    avg_power_target_filter_tc: pwr.avg_power_target_filter_tc,
                    unk_89bc: cfg.da.unk_8cc,
                    fast_die0_release_temp: 100 * pwr.fast_die0_release_temp,
                    unk_89c4: cfg.da.unk_87c,
                    fast_die0_prop_tgt_delta: 100 * pwr.fast_die0_prop_tgt_delta,
                    fast_die0_kp: pwr.fast_die0_proportional_gain,
                    fast_die0_ki_dt: pwr.fast_die0_integral_gain * period_s,
                    unk_89e0: 1,
                    max_power_2: pwr.max_power_mw,
                    ppm_kp: pwr.ppm_kp,
                    ppm_ki_dt: pwr.ppm_ki * period_s,
                    #[ver(V >= V13_0B4)]
                    unk_89f4_8: 1,
                    unk_89f4: 0,
                    hws1 <- Self::hw_shared1(cfg),
                    hws2 <- Self::hw_shared2(cfg, dyncfg),
                    hws3 <- Self::hw_shared3(cfg),
                    #[ver(V >= V13_0B4)]
                    idle_off_standby_timer: pwr.idle_off_standby_timer,
                    #[ver(V >= V13_0B4)]
                    unk_hws2_4: cfg.unk_hws2_4.map(Array::new).unwrap_or_default(),
                    #[ver(V >= V13_0B4)]
                    unk_hws2_24: cfg.unk_hws2_24,
                    unk_900c: 1,
                    #[ver(V >= V13_0B4)]
                    unk_9010_0: 1,
                    #[ver(V >= V13_0B4)]
                    unk_903c: 1,
                    #[ver(V < V13_0B4)]
                    unk_903c: 0,
                    fault_control: *module_parameters::fault_control.value(),
                    do_init: 1,
                    progress_check_interval_3d: 40,
                    progress_check_interval_ta: 10,
                    progress_check_interval_cl: 250,
                    #[ver(V >= V13_0B4)]
                    unk_1102c_0: 1,
                    #[ver(V >= V13_0B4)]
                    unk_1102c_4: 1,
                    #[ver(V >= V13_0B4)]
                    unk_1102c_8: 100,
                    #[ver(V >= V13_0B4)]
                    unk_1102c_c: 1,
                    idle_off_delay_ms: AtomicU32::new(pwr.idle_off_delay_ms),
                    fender_idle_off_delay_ms: pwr.fender_idle_off_delay_ms,
                    fw_early_wake_timeout_ms: pwr.fw_early_wake_timeout_ms,
                    cl_context_switch_timeout_ms: 40,
                    #[ver(V >= V13_0B4)]
                    cl_kill_timeout_ms: 50,
                    #[ver(V >= V13_0B4)]
                    unk_11edc: 0,
                    #[ver(V >= V13_0B4)]
                    unk_11efc: 0,
                    ..Zeroable::init_zeroed()
                })
                .chain(|raw| {
                    for (i, pz) in self.dyncfg.pwr.power_zones.iter().enumerate() {
                        raw.power_zones[i].target = pz.target;
                        raw.power_zones[i].target_off = pz.target - pz.target_offset;
                        raw.power_zones[i].filter_tc = pz.filter_tc;
                    }

                    if let Some(tab) = self.cfg.global_tab.as_ref() {
                        for (i, x) in tab.iter().enumerate() {
                            raw.unk_118ec[i] = *x;
                        }
                        raw.unk_118e8 = 1;
                    }

                    if !dyncfg.hw_globals.is_empty() {
                        unsafe {
                            let mut matches: bool = true;
                            let sla = core::slice::from_raw_parts(
                                raw as *const raw::Globals::ver as *const u8,
                                core::mem::size_of::<raw::Globals::ver>(),
                            );
                            if sla.len() != dyncfg.hw_globals.len() {
                                matches = false;
                                dev_err!(
                                    self.dev.as_ref(),
                                    "!!! Globals size mismatch: {} {}",
                                    sla.len(),
                                    dyncfg.hw_globals.len(),
                                );
                            }
                            for i in 0..core::cmp::min(sla.len(), dyncfg.hw_globals.len()) {
                                if sla[i] != dyncfg.hw_globals[i] {
                                    matches = false;
                                    dev_err!(self.dev.as_ref(), "!!! Globals first mismatch: {i}");
                                    break;
                                }
                            }
                            if matches {
                                dev_info!(self.dev.as_ref(), "!!! Globals match");
                            }
                        }
                    }

                    Ok(())
                })
            })
    }

    /// Create the RuntimePointers structure, which contains pointers to most of the other
    /// structures including the ring buffer channels, statistics structures, and HwDataA/HwDataB.
    fn runtime_pointers(&mut self) -> Result<GpuObject<RuntimePointers::ver>> {
        let hwa = self.hwdata_a()?;
        let hwb = self.hwdata_b()?;

        let mut buffer_mgr_ctl = gem::new_kernel_object(self.dev, 0x4000)?;
        // TODO: aren't new GEM shmem object zero initialized?
        let size = buffer_mgr_ctl.size();
        let vmap = buffer_mgr_ctl.vmap()?;
        for off in 0..size {
            vmap.try_write8(0x0, off)?;
        }

        GpuObject::new_init_prealloc(
            self.alloc.private.alloc_object()?,
            |_ptr| {
                let alloc = &mut *self.alloc;
                try_init!(RuntimePointers::ver {
                    stats <- {
                        let alloc = &mut *alloc;
                        try_init!(Stats::ver {
                            vtx: alloc.private.new_default::<GpuGlobalStatsVtx>()?,
                            frag: alloc.private.new_init(
                                pin_init::init_zeroed::<GpuGlobalStatsFrag::ver>(),
                                |_inner, _ptr| {
                                    try_init!(raw::GpuGlobalStatsFrag::ver {
                                        total_cmds: 0,
                                        unk_4: 0,
                                        stats: Default::default(),
                                    })
                                }
                            )?,
                            comp: alloc.private.new_default::<GpuStatsComp>()?,
                        })
                    },

                    hwdata_a: hwa,
                    unkptr_190: alloc.private.array_empty_tagged(0x80, b"I190")?,
                    unkptr_198: alloc.private.array_empty_tagged(0xc0, b"I198")?,
                    hwdata_b: hwb,

                    unkptr_1b8: alloc.private.array_empty_tagged(0x1000, b"I1B8")?,
                    unkptr_1c0: alloc.private.array_empty_tagged(0x300, b"I1C0")?,
                    unkptr_1c8: alloc.private.array_empty_tagged(0x1000, b"I1C8")?,

                    buffer_mgr_ctl,
                    buffer_mgr_ctl_low_mapping: None,
                    buffer_mgr_ctl_high_mapping: None,
                })
            },
            |inner, _ptr| {
                try_init!(raw::RuntimePointers::ver {
                    pipes: Default::default(),
                    device_control: Default::default(),
                    event: Default::default(),
                    fw_log: Default::default(),
                    ktrace: Default::default(),
                    stats: Default::default(),

                    stats_vtx: inner.stats.vtx.gpu_pointer(),
                    stats_frag: inner.stats.frag.gpu_pointer(),
                    stats_comp: inner.stats.comp.gpu_pointer(),

                    hwdata_a: inner.hwdata_a.gpu_pointer(),
                    unkptr_190: inner.unkptr_190.gpu_pointer(),
                    unkptr_198: inner.unkptr_198.gpu_pointer(),
                    hwdata_b: inner.hwdata_b.gpu_pointer(),
                    hwdata_b_2: inner.hwdata_b.gpu_pointer(),

                    fwlog_buf: None,

                    unkptr_1b8: inner.unkptr_1b8.gpu_pointer(),

                    #[ver(G < G14X)]
                    unkptr_1c0: inner.unkptr_1c0.gpu_pointer(),
                    #[ver(G < G14X)]
                    unkptr_1c8: inner.unkptr_1c8.gpu_pointer(),

                    buffer_mgr_ctl_gpu_addr: U64(gpu::IOVA_KERN_GPU_BUFMGR_LOW),
                    buffer_mgr_ctl_fw_addr: U64(gpu::IOVA_KERN_GPU_BUFMGR_HIGH),

                    __pad0: Default::default(),
                    unk_160: U64(0),
                    unk_168: U64(0),
                    unk_1d0: 0,
                    unk_1d4: 0,
                    unk_1d8: Default::default(),

                    __pad1: Default::default(),
                    gpu_scratch: raw::RuntimeScratch::ver {
                        unk_6b38: 0xff,
                        ..Default::default()
                    },
                })
            },
        )
    }

    /// Create the FwStatus structure, which is used to coordinate the firmware halt state between
    /// the firmware and the driver.
    fn fw_status(&mut self) -> Result<GpuObject<FwStatus>> {
        self.alloc
            .shared
            .new_object(Default::default(), |_inner| Default::default())
    }

    /// Create one UatLevelInfo structure, which describes one level of translation for the UAT MMU.
    fn uat_level_info(
        cfg: &'static hw::HwConfig,
        index_shift: usize,
        num_entries: usize,
    ) -> raw::UatLevelInfo {
        raw::UatLevelInfo {
            index_shift: index_shift as _,
            unk_1: 14,
            unk_2: 14,
            unk_3: 8,
            unk_4: 0x4000,
            num_entries: num_entries as _,
            unk_8: U64(1),
            unk_10: U64(((1u64 << cfg.uat_oas) - 1) & !(mmu::UAT_PGMSK as u64)),
            index_mask: U64(((num_entries - 1) << index_shift) as u64),
        }
    }

    /// Build the top-level InitData object.
    #[inline(never)]
    pub(crate) fn build(&mut self) -> Result<KBox<GpuObject<InitData::ver>>> {
        self.build_impl()
    }

    /// Build the M1/M2 monolithic init block (the `InitData` above).
    #[ver(G != G15)]
    fn build_impl(&mut self) -> Result<KBox<GpuObject<InitData::ver>>> {
        let runtime_pointers = self.runtime_pointers()?;
        let globals = self.globals()?;
        let fw_status = self.fw_status()?;
        let shared_ro = &mut self.alloc.shared_ro;

        let obj = self.alloc.private.new_init(
            try_init!(InitData::ver {
                unk_buf: shared_ro.array_empty_tagged(0x4000, b"IDTA")?,
                runtime_pointers,
                globals,
                fw_status,
            }),
            |inner, _ptr| {
                let cfg = &self.cfg;
                try_init!(raw::InitData::ver {
                    #[ver(V == V13_5 && G != G14X)]
                    ver_info: Array::new([0x6ba0, 0x1f28, 0x601, 0xb0]),
                    #[ver(V == V13_5 && G == G14X)]
                    ver_info: Array::new([0xb390, 0x70f8, 0x601, 0xb0]),
                    #[ver(G == G15 && V == V14_7)]
                    // TODO: V14_7 ver_info not yet sourced (no IDTA writer in the
                    // kext; expected from the firmware side, see M3)
                    ver_info: Array::new([0xb390, 0x70f8, 0x601, 0xb0]),
                    unk_buf: inner.unk_buf.gpu_pointer(),
                    unk_8: 0,
                    unk_c: 0,
                    runtime_pointers: inner.runtime_pointers.gpu_pointer(),
                    globals: inner.globals.gpu_pointer(),
                    fw_status: inner.fw_status.gpu_pointer(),
                    uat_page_size: 0x4000,
                    uat_page_bits: 14,
                    uat_num_levels: 3,
                    uat_level_info: Array::new([
                        Self::uat_level_info(cfg, 36, 8),
                        Self::uat_level_info(cfg, 25, 2048),
                        Self::uat_level_info(cfg, 14, 2048),
                    ]),
                    __pad0: Default::default(),
                    host_mapped_fw_allocations: 1,
                    unk_ac: 0,
                    unk_b0: 0,
                    unk_b4: 0,
                    unk_b8: 0,
                })
            },
        )?;
        Ok(KBox::new(obj, GFP_KERNEL)?)
    }

    /// Build the G15 (V14_7) buffer set.
    ///
    /// The layouts are the kext model in `fw/g15.rs`; the fill values are the
    /// spec/agx-g15c/{hwdata-a,hwdata-b,channel,pb-table,chip-config}.md maps.
    /// Every buffer is zeroed on allocation. The kext writes **every** field of
    /// HwDataA/B explicitly (it does not zero them), so a zero left below is
    /// "source not yet decoded", not a claim of value 0, except where the
    /// kext itself writes 0.
    /// G15: fill one ring group's four channel-table words for ring `r`
    /// (packed U64 fields — the pointers are into the entry's own fields):
    /// {read, CFI, doorbell, storage} = {R + 16r, R + 16r + 8, S + r*0x1808,
    /// S + r*0x1808 + 8} with S = the ring area base, R = base + 0x14000.
    #[ver(G == G15)]
    unsafe fn fill_ring_words(
        read: *mut U64,
        cfi: *mut U64,
        doorbell: *mut U64,
        storage: *mut U64,
        r: usize,
        base: u64,
    ) {
        let read_va = base + crate::fw::g15::RING_REGION2_OFF as u64 + 16 * r as u64;
        let doorbell_va = base + r as u64 * crate::fw::g15::RING_STRIDE as u64;
        unsafe {
            core::ptr::write(read, U64(read_va));
            core::ptr::write(cfi, U64(read_va + 8));
            core::ptr::write(doorbell, U64(doorbell_va));
            core::ptr::write(storage, U64(doorbell_va + 8));
        }
    }

    #[ver(G == G15)]
    fn build_impl(&mut self) -> Result<KBox<GpuObject<InitData::ver>>> {
        use crate::fw::g15;
        let cfg = self.cfg;
        let dyncfg = self.dyncfg;

        // HwDataA (0x6e48). Base pass (spec: hwdata-a.md); the Arm-pass
        // powerzone table (0x1088), avg-power header (0x1184), perf
        // governor (0x12d0), AONPTD (0x6c58), PPM perf params (0x6f0)
        // and the SoC hot config (0x14a8/0x16a8) are filled below
        // (sources resolved 2026-10-07…09). DPEPPT (0x64c0) stays zero
        // (the kext's own bzero).
        // The UMA page-pool descriptor table (createHardwareMappings:
        // 256 x 0x20 B). The GPU reads it through MRR 0x14000 and writes
        // entries back at a slot flush, so it is GPU-visible (spec:
        // uma.md, "The descriptor table").
        let umap_table = self.alloc.gpu.array_empty_tagged::<u8>(0x2000, b"UMAP")?;
        let mut hwdata_a = self.alloc.shared.new_default::<g15::HwDataA>()?;
        hwdata_a.with_mut(|raw, _| {
            raw.uma_desc_table = U64(umap_table.gpu_va().get());
            // f = float(chip+0x27a0) = 313.0 (gpu-max-power float filter tc)
            let f = 313.0f32;
            raw.vtbl_0xe70 = dyncfg.pwr.pwr_sample_period_aic_clks;
            raw.vtbl_0xe70_2 = dyncfg.pwr.pwr_sample_period_aic_clks;
            raw.const_0x0c = [0, 4];
            raw.const_0x14 = 1.0;
            // +0x40…+0x4f the Arm override: 0, base·100, 1, c34·100 (the
            // values come from the governor block below)
            raw.arm_0x40 = [0, 100 * dyncfg.pwr.perf_base_pstate, 1,
                100 * (dyncfg.pwr.perf_states.len() as u32).saturating_sub(1)];
            raw.const_0x2c = [1, 1];
            raw.const_0x54 = 100;
            // static_config (0x60..0x1bf) = the kext's P&E block (fw
            // +0xa50). On G15C only the G15X `populateSRAMPowerScaleData`
            // writes it: 1.02f (0x3f828f5c) at +0x20 + 4i for each GPU
            // perf state (chip+0xa6f0); the DPE fills are never called.
            for i in 0..dyncfg.pwr.perf_states.len().min((0x160 - 0x20) / 4) {
                let o = 0x20 + 4 * i;
                raw.static_config[o..o + 4].copy_from_slice(&0x3f82_8f5cu32.to_le_bytes());
            }
            // The PPM perf params (0x6f0…0x773) are filled below (resolved
            // 2026-10-09); AONPTD (0x6c58) is filled after the governor.
            raw.f_0x664 = (f - 1.0) / f;
            raw.f_0x66c = 1.0 / f;
            raw.chip_0x27c4 = 0x3ca59586;
            raw.chip_0x27d0 = 0x40a90fdb;
            // chip+0x2798 = P, the G15X max power: the top state's summed
            // per-cluster power (populateMaximumPerformancePower →
            // setGPUMaxPower; the DT's opp-microwatt carries the table)
            raw.chip_0x2798 = dyncfg.pwr.max_power_mw;
            // The power controller block `AGXFirmware::setupConfig`
            // derives (chip-config.md): c34 = the GPU perf-state count − 1,
            // c30 = gpu-pwr-min-duty-cycle, max = chip+0x2798.
            // chip+0x27f0 has no writer and chip+0x27f4 is the
            // overrideControllerValue knob, both 0.
            let c34x100 = 100 * (dyncfg.pwr.perf_states.len() as u32).saturating_sub(1);
            let max_power = raw.chip_0x2798;
            raw.chip_0x27c8 = [
                F32::from(dyncfg.pwr.pwr_integral_min_clamp as i32),
                F32::from(max_power as i32),
            ];
            raw.chip_0x27d4 = -F32::from(c34x100) / F32::from(max_power);
            raw.chip_0x27d8 = dyncfg.pwr.pwr_min_duty_cycle.wrapping_sub(c34x100);
            raw.chip_0x27e0 = c34x100;
            raw.chip_0x27e0_2 = c34x100;

            // The Arm pass's chip-sourced words (spec: hwdata-a.md): the
            // feature word chip+0x650 = 0xa04709c7 (chip-config.md), the
            // Arm setupConfig's 0x27b0 and the perf-boost/reset values,
            // configurePowerAndPerformanceController's 0x2810 = 6, chip
            // +0x1a18 = 1 and the G15X's chip+0x2020 = 0x40a00000.
            raw.chip_0x27b0 = 0x271;
            raw.perf_boost = [dyncfg.pwr.perf_boost_min_util, dyncfg.pwr.perf_boost_ce_step];
            raw.perf_reset_iters = dyncfg.pwr.perf_reset_iters;
            raw.chip_0x2810 = 6;
            raw.f_0x13d8 = f32!(65536.0);
            raw.se_0x13e8 = [dyncfg.pwr.pwr_min_duty_cycle, c34x100];
            raw.chip_0x1a18 = 1;
            raw.chip_0x2020 = 0x40a0_0000;
            raw.feat_0x6d80 = [1, 1];

            // The "Performance" controller block (0x788…0x873, 0xde8):
            // `configurePowerAndPerformanceController` constants (chip
            // +0x2810… = {6, 5, 50, 0}, +0x2820 = 1, +0x2830 = 95) with the
            // ADT gpu-perf-* overrides from `setupConfig`.
            let pw = &dyncfg.pwr;
            let base100 = 100 * pw.perf_base_pstate;
            let clamp_div = 95u32; // chip+0x2830
            let decay = |tc: u32| (F32::from(tc) - f32!(1.0)) / F32::from(tc);
            let inv = |tc: u32| f32!(1.0) / F32::from(tc);
            raw.perf_tgt_util = pw.perf_tgt_utilization;
            raw.perf_dual_filter = 1;
            raw.perf_drop_threshold = pw.perf_filter_drop_threshold;
            raw.perf_tc_decay = [
                decay(pw.perf_filter_time_constant),
                decay(pw.perf_filter_time_constant2),
            ];
            raw.perf_tc_inv = [
                inv(pw.perf_filter_time_constant),
                inv(pw.perf_filter_time_constant2),
            ];
            raw.perf_integral_gain = [pw.perf_integral_gain, pw.perf_integral_gain2];
            raw.perf_clamp = [
                F32::from(pw.perf_integral_min_clamp as i32),
                F32::from(clamp_div as i32),
            ];
            raw.perf_proportional_gain = [pw.perf_proportional_gain, pw.perf_proportional_gain2];
            raw.perf_0x7d4 =
                F32::from(c34x100.saturating_sub(base100)) / F32::from(clamp_div);
            raw.perf_0x7d8 = [base100, c34x100];
            raw.perf_0x7e0 = base100;
            raw.perf_tgt_util_2 = pw.perf_tgt_utilization;
            raw.perf_0x81c = [base100, 0];
            raw.mem_threshold = f32!(100.0);
            raw.perf_0x864 = c34x100;
            // gpu-perf-limiter-filter-time-constant: not in the ADT,
            // the kext's default 5
            raw.limiter_filter = [decay(5), inv(5)];
            raw.perf_0xde8 = c34x100;
            // The clock descriptor (0x838…0x85b): the Arm setupConfig's
            // this+0x197c…0x1994 — 0x1_0000_0000_0000, c30, c34·100, the
            // top state's clock (MHz), then zeros.
            let c30 = dyncfg.pwr.pwr_min_duty_cycle;
            raw.clock_0x838 = f32!(65536.0);
            raw.clock_0x83c = [F32::from(c30), F32::from(c34x100)];
            raw.clock_top_mhz =
                dyncfg.pwr.perf_states[dyncfg.pwr.perf_max_pstate as usize].freq_hz / 1_000_000;
            raw.clock_0x854 = c30;
            // The fast-die controller (0x8ac…0x943), chip+0x21a0…0x2218:
            // the G15X populateFastDieDeviceConfigData's MTR sensor mask
            // and 110.0 °C target, the ADT gains; the release temperature
            // and prop-tgt-delta are absent from the ADT (0).
            raw.fastdie_sensor_mask = U64(0x802a_002b_802a_002b);
            raw.fastdie_0x8c4 = 4;
            raw.fastdie_0x8d8 = f32!(1.0);
            raw.fastdie_integral_gain = dyncfg.pwr.fast_die0_integral_gain
                * (F32::from(dyncfg.pwr.power_sample_period) / f32!(1000.0));
            raw.fastdie_0x8e8 = [f32!(0.0), f32!(65536.0)];
            raw.fastdie_proportional_gain = dyncfg.pwr.fast_die0_proportional_gain;
            raw.fastdie_0x8fc = [c30, c34x100, c34x100];
            raw.fastdie_target = 11000;
            raw.fastdie_0x940 = c34x100;
            // +0x6d34: the kext's mach_absolute_time() at fill time
            let now: u64;
            // SAFETY: only reads the counter
            unsafe { core::arch::asm!("mrs {x}, CNTPCT_EL0", x = out(reg) now) };
            raw.timestamp_0x6d34 = U64(now);

            // Powerzone table (0x1088…): chip+0x2858 = chip+0x654 bit 0 = 1
            // on t6034, so the block is written; no `gpu-power-zone-*` in
            // the live ADT (0 zones); chip+0x285c = P. x = float(chip+0x286c)
            // = gpu-avg-power-target-filter-tc = 1; sp = getSamplePeriod() = 8.
            let pmax = dyncfg.pwr.max_power_mw;
            raw.powerzone_count = 1;
            raw.powerzone_0x108c = 0;
            raw.powerzone_0x1090 = [pmax, pmax];
            raw.powerzone_0x1098 = pmax;
            raw.powerzone_0x10a4 = 0.0; // (x-1)/x
            raw.powerzone_0x10a8 = 1.0; // 1/x
            raw.powerzone_0x10ac = 4; // chip+0x2870 = tc << 2
            raw.powerzone_0x10b0 = 8; // sp * tc
            raw.powerzone_0x10b4 = 8 * cfg.base_clock_hz / 1000; // tc · sp · 24000

            // Avg-power header (0x1184…0x1207), the Arm setupConfig's
            // chip+0x28c8… (chip-config.md): chip+0x28d0 = filter-tc-ms / sp
            // = 32/8 = 4, chip+0x28e4 = {(x−1)/x, 1/x}, chip+0x28f4 = ki-only
            // 12.5f · sp/1000 = 0.1f, chip+0x2900 = kp 0.3f, chip+0x28fc =
            // 0x10000; chip+0x654 bit 1 is clear, so 0x2904 = 0.0 and
            // 0x2908/0x2910 = {c30, c34·100}, c34·100. chip+0x28ec = P;
            // avg_0x1204 (chip+0x27f4, the overrideControllerValue knob) is 0
            // and avg_0x11fc (chip+0x2920) is never written.
            let c34x100_avg = 100 * (dyncfg.pwr.perf_states.len() as u32).saturating_sub(1);
            let x = 4.0f32;
            raw.avg_0x1184 = 4 << 2; // chip+0x28e0
            raw.avg_0x1190 = (x - 1.0) / x;
            raw.avg_0x1198 = 1.0 / x;
            raw.avg_0x11a0 = 0x3dcc_cccd; // 0.1f
            raw.avg_0x11a8 = [0, 0x4780_0000]; // float(u64 0x28f8): 0, 65536.0
            raw.avg_0x11b0 = 0x3e99_999a; // kp 0.3f
            raw.avg_0x11bc = [dyncfg.pwr.pwr_min_duty_cycle, c34x100_avg];
            raw.avg_0x11c4 = c34x100_avg;
            raw.avg_0x11cc = f32::from_bits(F32::from(pmax).to_bits());
            raw.avg_0x11d0 = pmax;
            raw.avg_0x11d8 = 32; // filter-tc-ms
            raw.avg_0x11e0 = U64(4 * 8 * u64::from(cfg.base_clock_hz / 1000)); // 768000
            raw.avg_0x1200 = c34x100_avg;

            // Perf governor (0x12d0…0x13af): all sources resolved 2026-10-08
            // (chip-config.md). sp = getSamplePeriod() = apple,power-sample-
            // period; tc/tc1 = gpu-se-filter-time-constant(-1); the kext
            // computes everything in float32 (the filter coefficients are one
            // 4-lane fdiv, the ki pair is gpu-se-ki(-1) × sp/1000).
            // All the float math goes through the driver's software F32
            // (no FPU in kernel mode; a raw f32 op would emit __divsf3).
            use crate::float::F32;
            let one = crate::f32!(1.0);
            let sp = dyncfg.pwr.power_sample_period;
            let tc = F32::from(dyncfg.pwr.se_filter_time_constant);
            let tc1 = F32::from(dyncfg.pwr.se_filter_time_constant_1);
            let sc = F32::from(sp) / F32::from(1000);
            raw.gov_0x12fc = 0x32;
            raw.gov_0x1300 = 1; // chip+0x26dc (P&P default)
            raw.gov_0x1308 = (tc - one) / tc;
            raw.gov_0x130c = (tc1 - one) / tc1;
            raw.gov_0x1310 = one / tc;
            raw.gov_0x1314 = one / tc1;
            raw.gov_0x1318 = dyncfg.pwr.se_ki * sc;
            raw.gov_0x131c = dyncfg.pwr.se_ki_1 * sc;
            raw.gov_0x1320 = F32::default(); // chip+0x2708 (P&P default)
            raw.gov_0x1324 = crate::f32!(65536.0); // float(chip+0x270c = 0x10000)
            raw.gov_0x1328 = dyncfg.pwr.se_kp;
            raw.gov_0x132c = dyncfg.pwr.se_kp_1;
            raw.gov_0x1334 = [
                0x64, // chip+0x2714 (P&P default)
                dyncfg.pwr.perf_states.len() as u32 * 100 - 100, // chip+0x2718
            ];
            raw.gov_0x133c = 100 * dyncfg.pwr.perf_base_pstate; // chip+0x2848
            raw.gov_0x1344 = F32::from(sp * 1000);
            raw.gov_0x1348 = 0x578; // gpu-se-tgt
            raw.gov_0x1350 = sp * dyncfg.pwr.se_filter_time_constant;
            raw.gov_0x1354 = sp * dyncfg.pwr.se_filter_time_constant_1;
            raw.gov_0x1358 = U64(u64::from(
                dyncfg.pwr.se_filter_time_constant * sp * 0x5dc0,
            ));
            raw.gov_0x1360 = U64(u64::from(
                dyncfg.pwr.se_filter_time_constant_1 * sp * 0x5dc0,
            ));
            raw.gov_0x136c = crate::f32!(65536.0); // float(chip+0x270c)
            raw.gov_0x1394 = sp * 1000;
            raw.gov_0x1398 = (sp / 2 + 0x21) / sp; // integer (sp/2+0x21)/sp
            raw.gov_0x139c = [
                dyncfg.pwr.se_inactive_threshold,
                u32::try_from(dyncfg.pwr.se_engagement_criteria).unwrap_or(0xffffffff),
            ];
            raw.gov_0x13a4 = [2, 4]; // engagement-/reset-tolerance defaults
            raw.gov_0x13ac = dyncfg.pwr.se_reset_criteria;

            // AONPTD (0x6c58): the identifiers (one "g" per cluster, one
            // "r" per die, "f"), each looked up in the chip's AON PTD rows;
            // a found row is appended to the entries and its bit set, and
            // the lookup stops at the first identifier with no row, as
            // `getAONPTDFromOSDictionary` does. The DPEPPT block before it
            // (0x64c0) is the vtbl-0xce0 bzero — already zero. Spec:
            // hwdata-a.md.
            const IDS_G: [[u8; 4]; 8] = [
                *b"RT0g", *b"RT1g", *b"RT2g", *b"RT3g",
                *b"RT4g", *b"RT5g", *b"RT6g", *b"RT7g",
            ];
            const IDS_R: [[u8; 4]; 2] = [*b"RT0r", *b"RT1r"];
            let n_g = (dyncfg.id.num_clusters as usize).min(IDS_G.len());
            let n_r = (cfg.num_dies as usize).min(IDS_R.len());
            raw.aonptd_ids_g[..n_g].copy_from_slice(&IDS_G[..n_g]);
            raw.aonptd_ids_r[..n_r].copy_from_slice(&IDS_R[..n_r]);
            raw.aonptd_id_f = *b"RT0f";
            let mut n = 0;
            let mut found = [0u64; 3];
            let lists: [&[[u8; 4]]; 3] = [&IDS_G[..n_g], &IDS_R[..n_r], &[*b"RT0f"]];
            'types: for (t, ids) in lists.iter().enumerate() {
                for (i, id) in ids.iter().enumerate() {
                    match cfg.aon_ptd.iter().find(|row| row[..4] == id[..]) {
                        Some(row) if n < raw.aonptd_entries.len() => {
                            raw.aonptd_entries[n] = *row;
                            n += 1;
                            found[t] |= 1 << i;
                        }
                        _ => break 'types,
                    }
                }
            }
            raw.aonptd_found_g = U64(found[0]);
            raw.aonptd_found_r = U64(found[1]);
            raw.aonptd_found_f = U64(found[2]);

            // PPM perf params (0x6f0…0x773): sources resolved 2026-10-09
            // (chip-config.md) — ADT + constants, no PMS. The kext's PPM
            // block: chip+0x262c = gpu-ppm-filter-time-constant-ms (tc),
            // chip+0x2624 = getSamplePeriod() (= sp, 8 on this machine),
            // chip+0x2628 = tc/sp (integer), chip+0x2638 = (tc/sp) << 2,
            // chip+0x2630 = sp·(tc/sp)·0x5dc0 (u64), chip+0x263c/0x2640 =
            // {0.5/f, (f−1)/f} (f = float(tc/sp)), chip+0x264c =
            // f32(gpu-ppm-ki)·sp/1000, chip+0x2658 = f32(gpu-ppm-kp),
            // chip+0x2660 = gpu-pwr-min-duty-cycle (the base setupConfig's
            // fw+0xc30), chip+0x2650 = gpu-pwr-integral-min-clamp. The
            // offsets not listed here are never written by the kext (the
            // buffer is memset first) and the 0x2620/0x265c/0x2668/0x267c
            // sources are runtime or never written → 0.
            let ptc = dyncfg.pwr.ppm_filter_time_constant_ms;
            let p28 = ptc / sp; // chip+0x2628
            let pf = F32::from(p28);
            raw.perf_0x6f0 = p28 << 2; // chip+0x2638
            raw.perf_0x6f4 = 0;
            raw.perf_0x6fc = (pf - one) / pf; // (f−1)/f
            raw.perf_0x704 = one / pf; // 1/f
            raw.perf_0x70c = dyncfg.pwr.ppm_ki * sc; // chip+0x264c
            raw.perf_0x714 = [
                F32::from(dyncfg.pwr.pwr_integral_min_clamp),
                crate::f32!(65536.0), // float(chip+0x2654 = 0x10000)
            ];
            raw.perf_0x71c = dyncfg.pwr.ppm_kp;
            raw.perf_0x724 = 0; // chip+0x265c (never written)
            raw.perf_0x728 = [
                dyncfg.pwr.pwr_min_duty_cycle, // chip+0x2660
                100 * (dyncfg.pwr.perf_states.len() as u32).saturating_sub(1), // chip+0x2664
            ];
            raw.perf_0x730 = 0; // chip+0x2668 (never written)
            raw.perf_0x738 = 0;
            raw.perf_0x73c = dyncfg.pwr.max_power_mw; // chip+0x2644 = P
            raw.perf_0x744 = ptc; // chip+0x262c
            let p30 = u64::from(sp) * u64::from(p28) * 0x5dc0; // chip+0x2630
            raw.perf_0x74c = [p30 as u32, (p30 >> 32) as u32];

            // SoC hot config (0x1490…0x14a4): `populateSoCHotConfigData`
            // (chip vtbl 0xcb0, called from setupConfig with the buffer at
            // fw+0x19a0). The G15C path overwrites the copied chip feature
            // mask (chip+0x1a08/0x1a10, 0/0 on G15C) with
            // 0x802a002b802a002b/0 and writes 125 into the temp word —
            // except at silicon revision A0, where the temp word would be
            // the ADT's gpu-sochot-temp (111 here) with a 120 fallback.
            // This machine is rev B0 (apple,id-version 0x07401000, see
            // spec/agx-g15c/gpu-id.md). initPowerAndPerformanceData adds
            // the constant 1 at 0x14a4; the two 0x200-byte blocks
            // (0x14a8/0x16a8, from fw+0x19b4/0x1bb4) stay zero (the kext
            // writes nothing there for G15C).
            raw.sochot_0x1490 = 0x802a002b802a002b;
            raw.sochot_0x1498 = 0;
            raw.sochot_0x14a0 = 125;
            raw.sochot_0x14a4 = 1;
        });

        // HwDataB (0x1868). Constants + DTS-derived values (spec: hwdata-b.md);
        // the chip-feature bits (chip+0x650/0x654) and the pstate/perf blocks
        // (0xb58..0x1794) stay zero until the feature word is decoded.
        // Block 1 of the kext's allocation (HwDataA/B, the channel table)
        // is mapped read-write for the firmware (options 7); only block 3,
        // the PB table, has no write bit.
        let mut hwdata_b = self.alloc.shared.new_default::<g15::HwDataB>()?;
        hwdata_b.with_mut(|raw, _| {
            raw.magic1 = U64(0x6f_0000_0000);
            raw.magic2 = U64(0xff_c0_0000);
            raw.const_0x10 = U64(0x10_0000_0000);
            raw.const_0x18 = U64(0x10_0000_0000);
            raw.const_0x20 = U64(0x2ffffff8000);
            raw.egart_fwva = U64(0xffff_fc20_1180_0000);
            raw.one_0xa50 = 1;
            raw.one_0xa60 = 1;
            raw.base_clock_khz = cfg.base_clock_hz / 1000;
            // (DA2 & 0x10) ? 200 : 1 — DA2 bit 4 is the ADT `model-slow`
            // == 1, absent here
            raw.power_sample_period = 1;
            raw.vtbl_0xe68 = dyncfg.pwr.power_sample_period;
            raw.one_0xa78 = 1;
            raw.const_0xa7c = [1, 1];
            raw.const_0xa9c = 0x1f;
            raw.const_0xac8 = U64(0x100000000);
            raw.const_0xad0 = U64(1);
            // chip+0x470…0x47f, the core config `getProbeScore` copies:
            // the core ID (0x18, G15C), the revision ID (kAGXGPURevName
            // order, B1 = 4) and cfg+0xc = cores per cluster × clusters
            // (40 on t6034, all cores, not the enabled ones).
            // The feature-word and probe-byte bits (chip+0x650 =
            // 0xa04709c7, +0x654 = 0x2831, +0x656 = 0x02; DA2 = the probe's
            // config byte, bit 1 set, bit 4 clear; chip-config.md).
            raw.probe_da2_bit1 = 1;
            raw.chip_0x650_bit8 = 1;
            raw.chip_0x650_bit11 = 1;
            raw.chip_0x2040 = U64(0x3f);
            // +0xa28…+0xa37 chip+0x20c0…0x20cf: the chip ID, 1, 2, 0
            raw.chip_0x20c0 = U64(0x1_0000_6034);
            raw.chip_0x20c8 = U64(2);
            // +0xa40 isPIOSupported(): 1, as the kext. The firmware copies
            // it to BSS 0x18BFAC, and with 0xa38 it gates the real power
            // path (sub_FFFFFC000001485C): with 0 the power-up only marks
            // HwDataA +0x38/+0x3c and never sets a PRC perf state, so the
            // GPU stays at state 0 (GFXCLKGEN_MGPU invalid, the UMA
            // constants read 0, a kicked list never completes; boots
            // #67-#73). The RAM rings work with 1 (#76). The power path
            // talks to the PMP: without it the firmware stalls after its
            // version banner (#75), and an unserviced PMP stalls the idle
            // power-down (#77).
            raw.vtbl_0xae0 = 1;
            raw.chip_0x2028 = 8;
            raw.chip_0x2064 = 0x31; // configureDevice+0x92c
            raw.enabled_uscs = dyncfg.id.num_cores * dyncfg.id.num_clusters;
            raw.feat_0x17fc = 1;
            raw.feat_0x1808 = [1, 0];
            raw.feat_0x1818 = [1, 0];
            raw.da2_0x1860 = 1;
            raw.core_id[0] = 0x18;
            raw.core_id[1] = dyncfg.id.gpu_rev_id as u32;
            raw.chip_0x47c = dyncfg.id.num_cores * dyncfg.id.num_clusters;
            raw.uat_config = 1;

            // The GPU perf-state tables (chip-config.md § the GPU
            // perf-state tables). The DT's two OPP tables are the kext's
            // tables A and B: the ADT `perf-states` rows the state maps
            // select. Volts: one slot per cluster, the rest = slot 0 (the
            // parse's fill); SRAM = max(volt, min-sram), as the ADT
            // `perf-states-sram` rows are.
            let pw = &dyncfg.pwr;
            let min_sram_mv = pw.min_sram_microvolt / 1000;
            let row = |ps: &crate::hw::PState, slots: usize| {
                let mut volt = [0u32; 8];
                let mut sram = [0u32; 8];
                for k in 0..slots.min(8) {
                    let mv = *ps.volt_mv.get(k).unwrap_or(&ps.volt_mv[0]);
                    volt[k] = mv;
                    sram[k] = mv.max(min_sram_mv);
                }
                (ps.freq_hz / 1_000_000, volt, sram)
            };
            let a = &pw.perf_states;
            let n = a.len().min(0x10);
            raw.perf_max_pstate = a.len() as u32 - 1;
            for (i, ps) in a.iter().take(n).enumerate() {
                let (mhz, volt, sram) = row(ps, 8);
                raw.perf_freq_mhz[i] = mhz;
                raw.perf_volt_mv[i] = volt;
                raw.perf_volt_sram_mv[i] = sram;
                // HwDataA 0x80 + 4i, populateSRAMPowerScaleData's 1.02f
                raw.sram_scale[i] = 0x3f82_8f5c;
            }
            // +0x105c: each state's max power as a share of the top
            // state's. The G15X populateMaximumPerformancePower's per-state
            // power (Σ over the clusters, chip+0xb170) needs powf(V, 1.2):
            // the DT's opp-microwatt carries it, computed offline.
            let power = |ps: &crate::hw::PState| -> u64 { ps.pwr_mw as u64 };
            let top = power(&a[n - 1]);
            for (i, ps) in a.iter().take(n).enumerate() {
                raw.perf_pwr_pct[i] = if top != 0 { (100 * power(ps) / top) as u32 } else { 0 };
            }
            // +0x109c: the clocks from the base state (HwDataA 0x7e0 / 100)
            // up, as a share of base…top, in Hz (the kext's u64 math)
            let base = pw.perf_base_pstate as usize;
            let clk = |i: usize| a[i].freq_hz as u64;
            for i in base..n - 1 {
                let span = clk(n - 1).wrapping_sub(clk(base));
                raw.perf_freq_pct[i] = if span != 0 {
                    (100u64.wrapping_mul(clk(i).wrapping_sub(clk(base))) / span) as u32
                } else {
                    0
                };
            }
            raw.perf_freq_pct[n - 1] = 100;
            for (j, m) in pw.perf_state_map.iter().take(0x20).enumerate() {
                raw.perf_state_map[j] = *m;
            }
            // The CS and AFR tables: the ADT rows, the clocks in MHz, one
            // volt per die, SRAM = max(volt, the tables' SRAM floor); the
            // caps are count − 1 (getPerfStateCap on B1).
            if let Some(csafr) = pw.csafr.as_ref() {
                let min = csafr.min_sram_microvolt / 1000;
                let cs = &csafr.perf_states_cs;
                raw.cs_max_pstate = cs.len() as u32 - 1;
                raw.cs_cap = cs.len() as u32 - 1;
                for (i, ps) in cs.iter().take(0x10).enumerate() {
                    raw.cs_freq_mhz[i] = ps.freq_hz / 1_000_000;
                    for (d, mv) in ps.volt_mv.iter().take(2).enumerate() {
                        raw.cs_volt_mv[i][d] = *mv;
                        raw.cs_volt_sram_mv[i][d] = (*mv).max(min);
                    }
                }
                let afr = &csafr.perf_states_afr;
                raw.afr_max_pstate = afr.len() as u32 - 1;
                raw.afr_cap = afr.len() as u32 - 1;
                for (i, ps) in afr.iter().take(8).enumerate() {
                    raw.afr_freq_mhz[i] = ps.freq_hz / 1_000_000;
                    for (d, mv) in ps.volt_mv.iter().take(2).enumerate() {
                        raw.afr_volt_mv[i][d] = *mv;
                        raw.afr_volt_sram_mv[i][d] = (*mv).max(min);
                    }
                }
            }
            // Table B: only the slots below the table count are copied.
            if let Some(last) = pw.perf_states_2.len().checked_sub(1) {
                raw.perf2_max_pstate = last as u32;
                for (i, ps) in pw.perf_states_2.iter().take(0x10).enumerate() {
                    let (mhz, volt, sram) = row(ps, ps.volt_mv.len());
                    raw.perf2_freq_mhz[i] = mhz;
                    raw.perf2_freq_mhz_2[i] = mhz;
                    raw.perf2_volt_mv[i] = volt;
                    raw.perf2_volt_sram_mv[i] = sram;
                }
            }

            // The Arm `initFirmwareData` tail. The masks come from the
            // core config's ID_UNK18 products (cfg+0x24/0x28/0x2c = 2, 3, 3
            // for UNK18 0x01320311 on t6034).
            let mask = |n: u32| if n > 63 { u32::MAX } else { ((1u64 << n) - 1) as u32 };
            raw.chip_0x688 = 5;
            raw.chip_0x68c = 0;
            raw.mask_0x17c0 = [mask(2), mask(3)];
            raw.mask_0x17c8 = mask(3);
            raw.one_0x17e8 = 1;
            raw.one_0x1800 = [1, 1];
            raw.const_0x1810 = [1, 1];
            raw.ones_0x1820 = [0xff; 0x30];
        });

        // PB descriptor table (0x1208). Constants from spec: pb-table.md;
        // the powerzone/perf-mirror regions stay zero (untraced).
        let mut pb_table = self.alloc.fw_nc.new_default::<g15::PBTable>()?;
        pb_table.with_mut(|raw, _| {
            raw.const_0x38 = 0x78;
            raw.cmd_submission_enabled = 1; // AGXAccelerator::start
            // The kext's hang timeouts and soft-fault settings (the end of
            // the Arm initFirmwareData; spec: faults.md).
            raw.relaxed_cl_kill_timeout = 3000;
            raw.cl_ctx_switch_timeout = 40;
            raw.cl_kill_timeout = 50;
            raw.cdm_backoff_timeout = 4;
            raw.soft_fault = 3u32.to_le_bytes();
            raw.chip_0x6c4 = 0xffff; // chip+0x6c4 = 0x28ffff
            raw.chip_0x6c6 = 0x0028;
            raw.chip_0x6c8 = 0xffff;
            raw.chip_a218_eq0 = 1; // (chip+0xa218 & 3) == 0
            let c34x100_pb = 100 * (dyncfg.pwr.perf_states.len() as u32).saturating_sub(1);
            raw.pwr_target = [dyncfg.pwr.max_power_mw, c34x100_pb, c34x100_pb];
            raw.chip_0x65c = U64((c34x100_pb as u64) << 32); // +0x8c c38·100
            raw.one_0x7d0 = [1, 1];
            raw.chip_0x2198 = 100; // keepalive thresholds (configureDevice)
            raw.chip_0x2194 = 100;
            raw.chip_0x2150 = U64(0x28 | (0xa << 32));
            raw.chip_0x2158 = U64(0xfa | (1 << 32));
            raw.chip_0x2160 = U64(1 | (0x64 << 32));
            raw.chip_0x2168 = 1;
            raw.ternary_0x9a0 = 2; // fw+0x1e2c/0x1e38/0x1e44 (ADT defaults)
            raw.ternary_0x9a4 = 40;
            raw.ternary_0x9a8 = 5;
            // +0x7a8 the idle-off predictor (chip+0x19e0…0x1a04):
            // `configurePowerAndPerformanceController`'s defaults with the
            // ADT gpu-idleoff-* overrides (standby-timer 1500; min_conf
            // 0.7, the default).
            raw.idleoff = [
                dyncfg.pwr.idle_off_standby_timer,
                0x3f80_0000, // prob-init-val 1.0
                0x3f4c_cccd, // fn-hit 0.8
                0x3e4c_cccd, // fi-hit 0.2
                0x3f66_6666, // fn-miss 0.9
                0x3dcc_cccd, // fi-miss 0.1
                0x3e80_0000, // nei-hit 0.25
                0x3f33_3333, // min_conf 0.7
                0x3f66_6666, // high-conf 0.9
                6,           // reset-iter
            ];
            // +0x2c/+0x30 feature-word bits 0 and 1 (chip+0x650 =
            // 0xa04709c7)
            raw.chip_0x650_bit0 = 1;
            raw.feature_bit1 = 1;
            // +0x5e max(HwDataB.power_sample_period, 1)
            raw.power_sample_period = hwdata_b.power_sample_period.min(255) as u8;
            // populateFwUtilPerfTunables (chip vtbl 0xdb8), +0x9bd: 0x74 bytes
            let t = &mut raw.fw_util_perf_tunables;
            t[0] = 1;
            t[0x19] = 0;
            t[0x1c] = 0;
            t[0x20] = 0;
            t[0x24] = 1;
            t[0x28] = 2;
            t[0x2c] = 1;
            t[0x30] = 1;
            for off in [0x34, 0x4c, 0x64] {
                t[off..off + 8].copy_from_slice(&[0x5a, 0x4b, 1, 1, 0, 0, 0, 0]);
            }
        });

        // The special control ring's storage (0x3800 = 256 x 56 B
        // AGFIAcceleratorDeviceControlEntry records); the kext's fw+0x938
        // DMA buffer (spec: channel.md).
        let special_ring = self.alloc.shared.array_empty_tagged(0x3800, b"AGFE")?;

        // The RAM ring region (128 KiB, zeroed): the 13 rings' index words
        // and the 12 command rings' storages, laid out like the kext's
        // Fender scratch (fw/g15.rs); the channel table carries plain
        // pointers, so the scratch itself is not needed. This buffer is
        // already visible to the firmware through the UAT kernel VM, so its
        // GPU VAs go straight into the channel table.
        let ring_area = self.alloc.shared.array_empty_tagged(g15::RING_REGION_SIZE, b"AGFR")?;
        let ring_base = ring_area.gpu_va().get();

        // Channel info table (0x490). Header + tail + the full ring table:
        // entry *k*'s groups point at rings {k, 3+k, 6+k} = {TA qk, 3D qk,
        // CL qk} (entry 3's TA group aliases ring 3, as in the kext — the
        // loop runs four times although each class has three queues), and
        // the special row's index words are the 13th ring's (spec:
        // channel.md).
        // The 0x88 timestamp/clock table (kext this+0x248): the base pass
        // zeros it whole (the u32 gate at +0x00 stays 0, so the firmware
        // builds its own default {0, time, 1.0}x4 table), but the firmware
        // dereferences the pointer unconditionally (armfw
        // sub_FFFFFC000003DAD4: LDR W9, [*(table+0x10)] before the CBZ),
        // so the buffer must exist (boot #37: FAR = 0x0).
        let buf_0x248 = self.alloc.shared.array_empty_tagged::<u8>(0x88, b"TBL8")?;
        // The HWDSID table: `chip+0x204c` = 0x80 on G15X, so the kext
        // publishes its AGXHWDSIDManager's 0x800-byte table at +0x2a8, and
        // the firmware's control-ring command 13 stores into it.
        let hwdsid_table = self.alloc.shared.array_empty_tagged::<u8>(0x800, b"DSID")?;
        // The base initFirmwareData's four buffers (channel table +0x234/
        // +0x23c/+0x244/+0x24c): zeroed, and 0xffffffff at +0xc18/+0xc30 of
        // the 0x1248 one. agx_background reads the u32 behind +0x24c
        // (boot #51: a NULL fault while it was unset).
        let buf_0x218 = self.alloc.shared.array_empty_tagged::<u8>(0xc10, b"B218")?;
        let mut buf_0x220 = self.alloc.shared.array_empty_tagged::<u32>(0x1248 / 4, b"B220")?;
        buf_0x220.as_mut_slice()[0xc18 / 4] = u32::MAX;
        buf_0x220.as_mut_slice()[0xc30 / 4] = u32::MAX;
        let buf_0x228 = self.alloc.shared.array_empty_tagged::<u8>(0xe10, b"B228")?;
        let buf_0x238 = self.alloc.shared.array_empty_tagged::<u8>(0x60, b"B238")?;
        // Read-write: agx_background zeroes the words at +0x318… (boot #52:
        // a permission fault while it was read-only).
        // The firmware-to-host rings (the pointer block +0x1b8…+0x1f0 and
        // +0x1f8): four {ring state, storage} pairs — 0x30/0x3800,
        // 0x120 (six sub-rings)/0x15000, 0x30/0x7000, 0x30/0x4000 — and the
        // 0x51000 buffer. The kext only sets each read index to its write
        // index (both 0 after the allocation's bzero). The power task posts
        // its statistics to the fourth (boot #56: a NULL fault at +0x1e8).
        let mut fw_rings = KVec::new();
        for (size, tag) in [
            (0x30usize, b"RS0A"),
            (0x3800, b"RB0A"),
            (0x120, b"RS1B"),
            (0x15000, b"RB1B"),
            (0x30, b"RS2C"),
            (0x7000, b"RB2C"),
            (0x30, b"RS3D"),
            (0x4000, b"RB3D"),
            (0x51000, b"B900"),
        ] {
            // Normal non-cacheable for the firmware, as the kext's block
            // 2 (Device-mapped, its ring writes took an alignment fault,
            // boot #111; cached, its recovery report stalled, #126).
            fw_rings.push(self.alloc.fw_nc.array_empty_tagged::<u8>(size, tag)?, GFP_KERNEL)?;
        }
        // The parameter-buffer descriptor table (createHardwareMappings:
        // 0x1000 B; halLoadPBDesc fills an entry per PBID). Zeroed. A
        // hardware mapping: the GPU's PM reads it (a firmware-only table
        // was a NoAccess fault, boot #152).
        let pb_desc_table = self.alloc.gpu.array_empty_tagged::<u8>(0x1000, b"PBDT")?;
        let mut channel_table = self.alloc.shared.new_default::<g15::ChannelTable>()?;
        channel_table.with_mut(|raw, _inner| {
            raw.hwdata_b_fwva = U64(hwdata_b.gpu_va().get());
            raw.buf_0x248_fwva = U64(buf_0x248.gpu_va().get());
            raw.chip_0x30d0_fwva = U64(hwdsid_table.gpu_va().get());
            let split = |va: u64| [va as u32, (va >> 32) as u32];
            raw.buf_0x218_fwva = split(buf_0x218.gpu_va().get());
            raw.buf_0x220_fwva = split(buf_0x220.gpu_va().get());
            raw.buf_0x228_fwva = split(buf_0x228.gpu_va().get());
            raw.buf_0x238_fwva = split(buf_0x238.gpu_va().get());
            raw.pb_desc_table_gpuva = U64(pb_desc_table.gpu_va().get());
            raw.pb_desc_table_fwva = U64(pb_desc_table.gpu_va().get());
            raw.umap_pool_pa = U64(umap_table.gpu_va().get());
            raw.umap_pool_fwva = U64(umap_table.gpu_va().get());
            raw.special[3] = U64(special_ring.gpu_va().get());
            // The firmware log: the print (sub_FFFFFC000003C924) writes the
            // pair-2 rings only when this is non-zero; the kext writes 0.
            raw.log_enable = 1;
            raw.chip_0x20b8 = 4; // halGetDefaultUscMaxTgmem
            for (k, buf) in fw_rings.iter().take(8).enumerate() {
                raw.ptr_block[k] = U64(buf.gpu_va().get());
            }
            raw.buf_0x900_fwva = U64(fw_rings[8].gpu_va().get());
            for k in 0..4 {
                let e = &mut raw.ring[k];
                // One ring group: the four words are {read, CFI, doorbell,
                // storage} = {R + 16r, R + 16r + 8, S + r*0x1808,
                // S + r*0x1808 + 8} (R = region 2 base, S = region 1 base =
                // the ring area base). Packed fields — pointer writes.
                // SAFETY: the pointers are into the entry's own fields and
                // the writes are in-bounds.
                unsafe {
                    Self::fill_ring_words(
                        core::ptr::addr_of_mut!(e.ta_state),
                        core::ptr::addr_of_mut!(e.ta_ring2),
                        core::ptr::addr_of_mut!(e.ta_ring3),
                        core::ptr::addr_of_mut!(e.ta_ring),
                        k,
                        ring_base,
                    );
                    Self::fill_ring_words(
                        core::ptr::addr_of_mut!(e.d3_state),
                        core::ptr::addr_of_mut!(e.d3_ring2),
                        core::ptr::addr_of_mut!(e.d3_ring3),
                        core::ptr::addr_of_mut!(e.d3_ring),
                        3 + k,
                        ring_base,
                    );
                    Self::fill_ring_words(
                        core::ptr::addr_of_mut!(e.cl_state),
                        core::ptr::addr_of_mut!(e.cl_ring2),
                        core::ptr::addr_of_mut!(e.cl_ring3),
                        core::ptr::addr_of_mut!(e.cl_ring),
                        6 + k,
                        ring_base,
                    );
                }
            }
            // The special control ring (13th): read/CFI in region 2 after
            // the 12 command rings, doorbell in region 1.
            let s = ring_base + g15::RING_REGION2_OFF as u64 + 0xC0;
            raw.special[0] = U64(s);
            raw.special[1] = U64(s + 8);
            raw.special[2] = U64(ring_base + g15::RING_SPECIAL_DOORBELL_OFF as u64);
            // Tail: 0xff at +0x3b0; conv(HwDataA) at +0x441 (an unaligned
            // full u64 — the firmware reads a qword from there: it uses the
            // HwDataA block as its own state, the u32 at HwDataA+0x38 as a
            // gate (0 in the kext) and writes its timer scale 0x3dd00000
            // at HwDataA+0x1080 — boot #35 crashed with a truncated u32);
            // chip +0x2088 at +0x449 and +0x2090 at +0x451 (both untraced,
            // zero).
            let p = raw.tail_0x3b0.as_mut_ptr();
            // SAFETY: tail_0x3b0 is a 0xa9-byte array covering 0x3b0..0x459;
            // all writes below are in-bounds, unaligned byte-wise stores.
            unsafe {
                p.write(0xff);
                (p.add(0x91) as *mut u64).write_unaligned(hwdata_a.gpu_va().get());
            }
        });

        // The MCache PIO buffer (window slot 11, kind 6): the kext's
        // createFWPIOMapping creates a GPU mapping of kind*0x10 bytes
        // filled with the entry's own physical addresses (spec: alloc.md).
        // The firmware reads the PAs from here and maps the MCache windows
        // itself; the buffer content is the table's pairs (base + 5).
        // 12 u64s = 0x60 bytes = kind*0x10 (kind 6). `array_empty_tagged`
        // takes an element count, not a byte size.
        let mut mcache_piob = self.alloc.shared.array_empty_tagged(12, b"MCPI")?;
        {
            let mut slots = [0u64; 12];
            if let Some(windows) = cfg.g15_windows {
                for w in windows.iter() {
                    if w.kind > 1 && w.base != 0 && w.size != 0 {
                        slots[0] = w.base;
                        for (i, p) in w.pairs.iter().enumerate() {
                            slots[i + 1] = *p;
                        }
                        break;
                    }
                }
            }
            let slice = mcache_piob.as_mut_slice();
            slice.copy_from_slice(&slots);
        }

        // The three ring buffers (spec: channel.md#fmc-ring-buffers). All are
        // zeroed; the FMC channel header (0xc0) is filled below, and the
        // AGFA terminator record the kext writes to ring2 before boot
        // (stp xzr,xzr + str wzr at +0x10) is already zero. The FMC ring is a
        // u64 array so its base pointer is 8-byte aligned (the header's u64
        // fields).
        let fmc = self.alloc.shared.array_empty_tagged(0x800, b"FRMC")?;
        let ring2 = self.alloc.shared.array_empty_tagged(0x1000, b"AGFA")?;
        let buf_0x4000 = self.alloc.shared.array_empty_tagged(0x4000, b"BUF4")?;

        // FMC channel header at the start of the FMC ring (spec: channel.md).
        let mut header = g15::FmcHeader::default();
        header.magic = 0xc08e21e84820490;
        header.ring2_fwva = U64(ring2.gpu_va().get());
        header.channel_table_fwva = U64(channel_table.gpu_va().get());
        header.pb_table_fwva = U64(pb_table.gpu_va().get());
        header.const_0x28 = U64(0x100000000);
        // The GART table struct (AGXSharedGartTableBackingG15::initGartInfo,
        // 0xfffffe0008e9ba98): three level records at +0x18/+0x38/+0x58 +
        // this+0x78 = 0. The index-mask u64 (record +0x1c) overlaps the
        // next record's +0x00…+0x03, so the words below are the raw bytes
        // of the store sequence (page size 0x4000, shift 14, 64/2048/2048
        // entries, PTE template {1, (2^28-1)<<14}).
        header.chip_a078 = [
            U64(0x240e0e08030e_4000), // +0x30 top: 0x4000, 14, 3, 0x0e08, 0x0e, 0x24
            U64(0x000000014000_0040), // +0x38 top: 64 entries, 0x4000, template lo
            U64(0xffffc0000000_0000), // +0x40 template hi
            U64(0x3ff), // +0x48 template hi upper + top mask lo 32b (0)
            U64(0x190e0e080000_03f0), // +0x50 top mask hi 32b (0x3f0) + mid: 0x0e08, 0x0e, 0x19
            U64(0x000000014000_0800), // +0x58 mid: 2048 entries, 0x4000, template lo
            U64(0xffffc0000000_0000), // +0x60 template hi
            U64(0xfe0000000000_03ff), // +0x68 template hi upper + mid mask lo 32b (0xfe000000)
            U64(0x0e0e0e080000_000f), // +0x70 mid mask hi 32b (0xf) + leaf: 0x0e08, 0x0e, 0x0e
            U64(0x000000014000_0800), // +0x78 leaf: 2048 entries, 0x4000, template lo
            U64(0xffffc0000000_0000), // +0x80 template hi
            U64(0x01ffc0000000_03ff), // +0x88 template hi upper + leaf mask lo 32b (0xffc000)
            U64(0), // +0x90 this+0x78
        ];
        // The host/firmware control block (this+0x910, 0x20 B): the kext
        // stores the ktrace flags (0) at +0x0 (initFirmwareSharedData+0x300)
        // and 1 at +0x4 (initFirmwareData+0xb8c); +0x8/+0xc stay 0.
        let mut fw_ctl = self.alloc.fw_nc.array_empty_tagged(8, b"FCTL")?;
        fw_ctl.as_mut_slice()[1] = 1;
        header.buf_0x910_fwva = U64(fw_ctl.gpu_va().get());
        // The firmware event/fence page (this+0xa30/0xa40, 0xc3d0 B; the
        // kext's AGXBlockFence and drainFirmwareEventRing use it): zeroed,
        // with the u32 at +0x45c4 = 1 (initFirmwareData+0xa6c), published
        // at FMC header +0xb0 (the firmware's config snapshot reads its
        // +0x8 and +0xc3c8).
        let mut event_page = self.alloc.fw_nc.array_empty_tagged(0xc3d0 / 4, b"FEVT")?;
        let ep = event_page.gpu_va().get();
        let s = event_page.as_mut_slice();
        s[0x45c4 / 4] = 1;
        s[0x4 / 4] = 1; // (chip+0x650 >> 2) & 1
        // The secure-cache-flush ring (base+0x4568 head structure, base
        // +0x4570 ring buffer, the AGXArmFirmware::init fill): the kext
        // publishes conv(0) for both — its this+0x1670/0x1678 fields are
        // zeroed in the constructor and never set, and convertGPUVAToFWVA is
        // identity on G15 — and its firmware never enters the flush, so the
        // zero ring is never dereferenced. Ours does (boot #49: LDR W8,[X10]
        // at sub_34F30+0x30, X10 = base+0x4568 = 0, FAR 0). Publish a valid
        // no-op ring instead: a zeroed head structure (u32 head @+0, u8 tail
        // @+0x10; head == tail == 0 → the flush sees no work and returns)
        // and a zeroed ring buffer, both carved from the event-page top
        // (already zeroed, below the +0xc3c8 config-snapshot read). The
        // driver submits no secure-cache-flush work (the secure monitor is
        // off — the kext's halNewSecureMonitor returns 0), so no-op is
        // correct, not a mask.
        let head = ep + 0xc300;
        let ring = ep + 0xc320;
        s[0x4568 / 4] = head as u32;
        s[0x456c / 4] = (head >> 32) as u32;
        s[0x4570 / 4] = ring as u32;
        s[0x4574 / 4] = (ring >> 32) as u32;
        header.buf_0xa40_fwva = U64(ep);
        // FMC header +0xb8: the 0x238 B power-control block, the kext's
        // init stores (setupConfig, initFirmwareSharedData, the Arm
        // initPowerAndPerformanceData; spec: pb-table.md). The doorbells
        // other than the PPM one (+0x8 zones, +0xa4 fast-die, +0xe8 SE,
        // +0x1d0 perf) stay 0, as does the DSID mask +0x1e8.
        let mut pwr_ctl = self.alloc.fw_nc.array_empty_tagged::<u32>(0x238 / 4, b"PCTL")?;
        {
            let pw = &self.dyncfg.pwr;
            let w = pwr_ctl.as_mut_slice();
            // +0xc…+0x20 the avg-power header: chip+0x2864 (zones, 0),
            // 0x28d0, 0x28f4, 0x2900, 0x2908, 0x286c
            w[0xc / 4] = 0;
            w[0x10 / 4] = 4;
            w[0x14 / 4] = 0x3dcc_cccd; // 0.1f
            w[0x18 / 4] = 0x3e99_999a; // 0.3f
            w[0x1c / 4] = pw.pwr_min_duty_cycle;
            w[0x20 / 4] = 1;
            // +0xa8…+0xc8 the fast-die mirror: the target (110.0 °C; the
            // firmware clamps the PTD target to it), the gains
            w[0xa8 / 4] = 11000;
            w[0xb8 / 4] = pw.fast_die0_proportional_gain.to_bits();
            w[0xbc / 4] = (pw.fast_die0_integral_gain
                * (F32::from(pw.power_sample_period) / f32!(1000.0)))
                .to_bits();
            // +0xd0 the PPM target, P (chip+0x266c ?: 0x2644), with its
            // doorbell +0xcc = 1 (setPPMControllerTarget at init, this+0xc68
            // = 1); +0xd4/+0xd8 the PPM gains (HwDataA 0x71c/0x70c)
            w[0xcc / 4] = 1;
            w[0xd0 / 4] = pw.max_power_mw;
            w[0xd4 / 4] = 0x3e99_999a; // gpu-ppm-kp 0.3f
            w[0xd8 / 4] = 0x3e1c_779b; // gpu-ppm-ki · 0.008
            // +0xec SE engagement on
            w[0xec / 4] = 1;
        }
        header.buf_0xa48_fwva = U64(pwr_ctl.gpu_va().get());
        let mut fmc = fmc;
        {
            let elems = fmc.as_mut_slice();
            // SAFETY: the u64 array base is 8-aligned like FmcHeader, and
            // 0xc0 <= 0x4000.
            unsafe { (elems.as_mut_ptr() as *mut g15::FmcHeader).write(header) };
        }

        let obj = self.alloc.private.new_init(
            try_init!(InitData::ver {
                hwdata_a,
                hwdata_b,
                channel_table,
                pb_table,
                fmc,
                ring2,
                buf_0x4000,
                mcache_piob,
                special_ring,
                fw_ctl,
                event_page,
                ring_area,
                clock_table: buf_0x248,
                hwdsid_table,
                pwr_ctl,
                buf_0x218,
                buf_0x220,
                buf_0x228,
                buf_0x238,
                fw_rings,
                umap_table,
                pb_desc_table,
            }),
            |inner, _ptr| {
                g15::InitData {
                    hwdata_a: U64(inner.hwdata_a.gpu_va().get()),
                    hwdata_b: U64(inner.hwdata_b.gpu_va().get()),
                    channel_table: U64(inner.channel_table.gpu_va().get()),
                    pb_table: U64(inner.pb_table.gpu_va().get()),
                    fmc: U64(inner.fmc.gpu_va().get()),
                    ring2: U64(inner.ring2.gpu_va().get()),
                    buf_0x4000: U64(inner.buf_0x4000.gpu_va().get()),
                    mcache_piob: U64(inner.mcache_piob.gpu_va().get()),
                    ring_area: U64(inner.ring_area.gpu_va().get()),
                }
            },
        )?;
        Ok(KBox::new(obj, GFP_KERNEL)?)
    }
}
