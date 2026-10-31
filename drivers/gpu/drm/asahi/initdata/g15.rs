// SPDX-License-Identifier: GPL-2.0-only

//! G15 initialization data.
//!
//! The G15 firmware takes a set of separate buffers in place of the M1/M2
//! InitData block. The init message points it at the FMC ring, whose
//! channel header holds the addresses of the channel table, the PB table
//! and the host/firmware control blocks. The channel table in turn holds
//! those of HwDataA and HwDataB, the command rings and the firmware-to-host
//! rings.
//!
//! The values are the ones macOS writes (`AGXFirmware::initFirmwareData` and
//! its Arm override, `initPowerAndPerformanceData`, `setupConfig` and the
//! G15X chip's `populate*` methods): constants, the chip configuration and
//! the ADT's power properties. Fields named `chip_*` carry a property of
//! macOS's chip object at that offset. A field left zero is one macOS also
//! leaves zero, or one not decoded yet.
//!
//! Spec: chip-config.md, chip-config-pnp.md, channel-table.md, hwdata-a.md,
//! hwdata-b.md, initdata.md, pb-table.md.

use super::*;
use crate::float::F32;
use crate::fw::g15;

/// The firmware addresses the channel table publishes.
struct ChannelTableVas {
    hwdata_a: u64,
    hwdata_b: u64,
    clock_table: u64,
    hwdsid_table: u64,
    buf_0x218: u64,
    buf_0x220: u64,
    buf_0x228: u64,
    buf_0x238: u64,
    pb_desc_table: u64,
    umap_table: u64,
    special_ring: u64,
    ring_area: u64,
    fw_rings: [u64; 9],
}

/// The top GPU perf state's index (chip+0xc34) times 100.
fn top_pstate_x100(pw: &hw::PwrConfig) -> u32 {
    100 * (pw.perf_states.len() as u32).saturating_sub(1)
}

/// G15G's DPE leakage-update config (`populateDPELeakageUpdateConfig`,
/// firmware `this+0x18e8`): the 16 words at +0x00…+0x3f.
const G15G_DPE_LEAK: [u32; 16] = [
    12500, 12500, 12500, 12500, 12500, 3000, 3000, 3000, 12500, 12500, 12500, 12500, 12500, 12500,
    12500, 12500,
];
/// Its +0x40, +0x44, +0x48 and +0x4c.
const G15G_DPE_LEAK_TAIL: [u32; 4] = [500, 5, 1, 1];

/// G15G's DPE/PPT config (`AGXAcceleratorG15G::populateDPEPPTConfigData`,
/// g15g.md): the static register image, then for each source perf state s
/// from 1 its reactive windows, Imax budget and trigger thresholds. With
/// k = 1e15 / (3 · Hz · mV) and the default 21.0 A limit. Computed in
/// integers, where the kext rounds each f32 step: a field may differ by
/// one count.
fn g15g_dpeppt(pw: &hw::PwrConfig) -> Result<[u8; 0x6e0]> {
    // populateDPEPPTConfigData's window-2 lengths, by state
    const W2: [u64; 14] = [0, 14, 27, 35, 37, 41, 42, 47, 46, 52, 51, 57, 53, 59];
    // The trigger thresholds' words and factors (num / den).
    const TRIG: [(usize, u128, u128); 4] = [
        (0x3cc, 45, 10000),
        (0x40c, 35045, 10000),
        (0x44c, 5, 1),
        (0x4cc, 6, 1),
    ];
    let mut b = [0u8; 0x6e0];
    let fill = |b: &mut [u8; 0x6e0], from: usize, to: usize, v: &[u8]| {
        for chunk in b[from..to].chunks_exact_mut(v.len()) {
            chunk.copy_from_slice(v);
        }
    };
    let pattern = 0x0f07_0f07_0f07_0f07u64.to_le_bytes();
    fill(&mut b, 0xcc, 0xec, &[0xff]);
    fill(&mut b, 0xec, 0xf4, &0x80000u64.to_le_bytes());
    fill(&mut b, 0xf4, 0x104, &0x003f_ffffu32.to_le_bytes());
    fill(
        &mut b,
        0x114,
        0x11c,
        &0x003f_0000_0000_0000u64.to_le_bytes(),
    );
    fill(
        &mut b,
        0x13c,
        0x144,
        &0x2000_0000_0000_0000u64.to_le_bytes(),
    );
    fill(&mut b, 0x144, 0x164, &[0xff]);
    fill(&mut b, 0x164, 0x184, &pattern);
    fill(&mut b, 0x184, 0x384, &0x03ff_ffffu32.to_le_bytes());
    fill(
        &mut b,
        0x384,
        0x38c,
        &0xa000_0000_0000_0017u64.to_le_bytes(),
    );
    fill(&mut b, 0x38c, 0x3ac, &[0xff]);
    fill(&mut b, 0x3ac, 0x3cc, &pattern);
    fill(&mut b, 0x3cc, 0x5cc, &0x03ff_ffffu32.to_le_bytes());
    fill(&mut b, 0x5d4, 0x5dc, &0xc0_0000u64.to_le_bytes());

    let set = |b: &mut [u8; 0x6e0], off: usize, shift: usize, width: u32, v: u64| {
        let mut w = u64::from_le_bytes(b[off..off + 8].try_into().unwrap_or([0; 8]));
        let mask = ((1u64 << width) - 1) << shift;
        w = (w & !mask) | ((v << shift) & mask);
        b[off..off + 8].copy_from_slice(&w.to_le_bytes());
    };
    let states = &pw.source_states;
    if states.len() > W2.len() {
        return Err(EINVAL);
    }
    for (s, &(hz, mv)) in states.iter().enumerate().skip(1) {
        let den = 3 * u128::from(hz) * u128::from(mv);
        if den == 0 {
            return Err(EINVAL);
        }
        let w2 = W2[s];
        let lane = (16 * s) & 0x30;
        // the reactive windows: 1 is 0 (3 bits), 2 is W2 (6 bits)
        set(&mut b, 0x3ac + 8 * (s >> 2), lane, 3, 0);
        set(&mut b, 0x3ac + 8 * (s >> 2), lane + 6, 6, w2);
        // the reactive budget: min(21.0 · k, 65535)
        let budget = (21 * 1_000_000_000_000_000u128 / den).min(0xffff) as u64;
        set(&mut b, 0x38c + 8 * (s >> 2), lane, 16, budget);
        for &(off, num, dnm) in TRIG.iter() {
            let t = 1_000_000_000_000_000u128 * num * u128::from(w2 + 1) / (dnm * den);
            if t >= 1 << 27 {
                return Err(EINVAL);
            }
            set(&mut b, off + 8 * (s >> 1), (32 * s) & 0x20, 27, t as u64);
        }
    }
    Ok(b)
}

#[versions(AGX)]
impl<'a> InitDataBuilder::ver<'a> {
    /// The base pass of HwDataA, the power controller (`setupConfig`) and
    /// the chip words of the Arm pass, including the SoC hot config and the
    /// MTR sensors.
    #[ver(G == G15)]
    fn g15_hwdata_a_base(raw: &mut g15::HwDataA, cfg: &hw::HwConfig, pw: &hw::PwrConfig) {
        // The gpu-max-power filter time constant (chip+0x27a0).
        let f = 313.0f32;
        raw.vtbl_0xe70 = pw.pwr_sample_period_aic_clks;
        raw.vtbl_0xe70_2 = pw.pwr_sample_period_aic_clks;
        raw.const_0x0c = [0, 4];
        raw.const_0x14 = 1.0;
        // The Arm override: 0, the base state, 1, the top state.
        raw.arm_0x40 = [0, 100 * pw.perf_base_pstate, 1, top_pstate_x100(pw)];
        raw.const_0x2c = [1, 1];
        raw.const_0x54 = 100;
        // The P&E block. On G15C only the G15X `populateSRAMPowerScaleData`
        // writes it: 1.02 for each GPU perf state.
        for i in 0..pw.perf_states.len().min((0x160 - 0x20) / 4) {
            let o = 0x20 + 4 * i;
            raw.static_config[o..o + 4].copy_from_slice(&0x3f82_8f5cu32.to_le_bytes());
        }
        #[allow(
            clippy::float_arithmetic,
            reason = "constant operands, folded at build time"
        )]
        let (f_0x664, f_0x66c) = ((f - 1.0) / f, 1.0 / f);
        raw.f_0x664 = f_0x664;
        raw.f_0x66c = f_0x66c;
        raw.chip_0x27c4 = 0x3ca59586;
        raw.chip_0x27d0 = 0x40a90fdb;
        // The G15X max power: the top state's power summed over the
        // clusters (`populateMaximumPerformancePower`), which the DT's
        // opp-microwatt carries.
        raw.chip_0x2798 = pw.max_power_mw;

        // The power controller (`AGXFirmware::setupConfig`).
        let c34x100 = top_pstate_x100(pw);
        let max_power = raw.chip_0x2798;
        raw.chip_0x27c8 = [
            F32::from(pw.pwr_integral_min_clamp as i32),
            F32::from(max_power as i32),
        ];
        raw.chip_0x27d4 = -F32::from(c34x100) / F32::from(max_power);
        raw.chip_0x27d8 = pw.pwr_min_duty_cycle.wrapping_sub(c34x100);
        raw.chip_0x27e0 = c34x100;
        raw.chip_0x27e0_2 = c34x100;

        // The chip words of the Arm pass: `setupConfig`'s, the perf boost
        // and reset values, and `configurePowerAndPerformanceController`'s.
        raw.chip_0x27b0 = 0x271;
        raw.perf_boost = [pw.perf_boost_min_util, pw.perf_boost_ce_step];
        raw.perf_reset_iters = pw.perf_reset_iters;
        raw.chip_0x2810 = 6;
        raw.f_0x13d8 = f32!(65536.0);
        raw.se_0x13e8 = [pw.pwr_min_duty_cycle, c34x100];
        // The MTR sensors, which the firmware matches each MTR alarm
        // against: with none, every alarm is fatal (power.md).
        let mtr = cfg.mtr_sensor_mask;
        raw.chip_0x1a08 = [
            mtr[0] as u32,
            (mtr[0] >> 32) as u32,
            mtr[1] as u32,
            (mtr[1] >> 32) as u32,
        ];
        raw.chip_0x1a18 = 1;
        raw.chip_0x2020 = 0x40a0_0000;
        raw.feat_0x6d80 = [1, 1];

        // The SoC hot config (`populateSoCHotConfigData`): the hotspot
        // sensors and 125 degrees (the ADT's gpu-sochot-temp is only for
        // revision A0), and `initPowerAndPerformanceData`'s 1.
        raw.sochot_0x1490 = cfg.hotspot_sensor_mask[0];
        raw.sochot_0x1498 = cfg.hotspot_sensor_mask[1];
        raw.sochot_0x14a0 = 125;
        raw.sochot_0x14a4 = 1;
    }

    /// HwDataA's performance controller, clock descriptor and fast-die
    /// controller: `configurePowerAndPerformanceController`'s constants with
    /// the ADT's gpu-perf-* overrides from `setupConfig`.
    #[ver(G == G15)]
    fn g15_hwdata_a_perf(raw: &mut g15::HwDataA, cfg: &hw::HwConfig, pw: &hw::PwrConfig) {
        let c34x100 = top_pstate_x100(pw);
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
        raw.perf_0x7d4 = F32::from(c34x100.saturating_sub(base100)) / F32::from(clamp_div);
        raw.perf_0x7d8 = [base100, c34x100];
        raw.perf_0x7e0 = base100;
        raw.perf_tgt_util_2 = pw.perf_tgt_utilization;
        raw.perf_0x81c = [base100, 0];
        raw.mem_threshold = f32!(100.0);
        raw.perf_0x864 = c34x100;
        // gpu-perf-limiter-filter-time-constant is not in the ADT: macOS's
        // default.
        raw.limiter_filter = [decay(5), inv(5)];
        raw.perf_0xde8 = c34x100;

        // The clock descriptor of the Arm `setupConfig`: 65536.0, the
        // minimum duty cycle, the top state, its clock in MHz.
        let c30 = pw.pwr_min_duty_cycle;
        raw.clock_0x838 = f32!(65536.0);
        raw.clock_0x83c = [F32::from(c30), F32::from(c34x100)];
        raw.clock_top_mhz = pw.perf_states[pw.perf_max_pstate as usize].freq_hz / 1_000_000;
        raw.clock_0x854 = c30;

        // The fast-die controller (`populateFastDieDeviceConfigData`): the
        // hotspot sensors, a 110.0 degree target and the ADT's gains. The
        // release temperature and target delta are not in the ADT.
        raw.fastdie_sensor_mask = U64(cfg.hotspot_sensor_mask[0]);
        raw.fastdie_0x8b4 = U64(cfg.hotspot_sensor_mask[1]);
        raw.fastdie_0x8c4 = 4;
        raw.fastdie_0x8d8 = f32!(1.0);
        raw.fastdie_integral_gain =
            pw.fast_die0_integral_gain * (F32::from(pw.power_sample_period) / f32!(1000.0));
        raw.fastdie_0x8e8 = [f32!(0.0), f32!(65536.0)];
        raw.fastdie_proportional_gain = pw.fast_die0_proportional_gain;
        raw.fastdie_0x8fc = [c30, c34x100, c34x100];
        raw.fastdie_target = cfg.fastdie_target;
        raw.fastdie_0x940 = c34x100;

        // The time of the fill, as macOS's mach_absolute_time().
        let now: u64;
        // SAFETY: only reads the counter.
        unsafe { core::arch::asm!("mrs {x}, CNTPCT_EL0", x = out(reg) now) };
        raw.timestamp_0x6d34 = U64(now);
    }

    /// HwDataA's power zone table and average-power controller (the Arm
    /// `setupConfig`). The ADT has no gpu-power-zone-* properties, so the
    /// table holds one zone at the max power.
    #[ver(G == G15)]
    fn g15_hwdata_a_power(raw: &mut g15::HwDataA, cfg: &hw::HwConfig, pw: &hw::PwrConfig) {
        let pmax = pw.max_power_mw;
        // The filter time constant (gpu-avg-power-target-filter-tc) is 1
        // and the sample period 8.
        raw.powerzone_count = 1;
        raw.powerzone_0x108c = 0;
        raw.powerzone_0x1090 = [pmax, pmax];
        raw.powerzone_0x1098 = pmax;
        raw.powerzone_0x10a4 = 0.0; // (tc - 1) / tc
        raw.powerzone_0x10a8 = 1.0; // 1 / tc
        raw.powerzone_0x10ac = 4; // tc << 2
        raw.powerzone_0x10b0 = 8; // period * tc
        raw.powerzone_0x10b4 = 8 * cfg.base_clock_hz / 1000;

        // The average-power controller: a 32 ms filter at the 8 ms sample
        // period (x = 4), ki 0.1 and kp 0.3.
        let c34x100 = top_pstate_x100(pw);
        let x = 4.0f32;
        raw.avg_0x1184 = 4 << 2;
        #[allow(
            clippy::float_arithmetic,
            reason = "constant operands, folded at build time"
        )]
        let (avg_0x1190, avg_0x1198) = ((x - 1.0) / x, 1.0 / x);
        raw.avg_0x1190 = avg_0x1190;
        raw.avg_0x1198 = avg_0x1198;
        raw.avg_0x11a0 = 0x3dcc_cccd; // 0.1
        raw.avg_0x11a8 = [0, 0x4780_0000]; // 0.0, 65536.0
        raw.avg_0x11b0 = 0x3e99_999a; // 0.3
        raw.avg_0x11bc = [pw.pwr_min_duty_cycle, c34x100];
        raw.avg_0x11c4 = c34x100;
        raw.avg_0x11cc = f32::from_bits(F32::from(pmax).to_bits());
        raw.avg_0x11d0 = pmax;
        raw.avg_0x11d8 = 32; // the filter time constant in ms
        raw.avg_0x11e0 = U64(4 * 8 * u64::from(cfg.base_clock_hz / 1000));
        raw.avg_0x1200 = c34x100;
    }

    /// HwDataA's performance governor, from the ADT's apple,power-sample-
    /// period and gpu-se-* properties. macOS computes it in float32; the
    /// driver uses its software `F32`, as kernel mode has no FPU.
    #[ver(G == G15)]
    fn g15_hwdata_a_governor(raw: &mut g15::HwDataA, pw: &hw::PwrConfig) {
        let one = f32!(1.0);
        let sp = pw.power_sample_period;
        let tc = F32::from(pw.se_filter_time_constant);
        let tc1 = F32::from(pw.se_filter_time_constant_1);
        let sc = F32::from(sp) / F32::from(1000);
        raw.gov_0x12fc = 0x32;
        raw.gov_0x1300 = 1;
        raw.gov_0x1308 = (tc - one) / tc;
        raw.gov_0x130c = (tc1 - one) / tc1;
        raw.gov_0x1310 = one / tc;
        raw.gov_0x1314 = one / tc1;
        raw.gov_0x1318 = pw.se_ki * sc;
        raw.gov_0x131c = pw.se_ki_1 * sc;
        raw.gov_0x1320 = F32::default();
        raw.gov_0x1324 = f32!(65536.0);
        raw.gov_0x1328 = pw.se_kp;
        raw.gov_0x132c = pw.se_kp_1;
        raw.gov_0x1334 = [0x64, pw.perf_states.len() as u32 * 100 - 100];
        raw.gov_0x133c = 100 * pw.perf_base_pstate;
        raw.gov_0x1344 = F32::from(sp * 1000);
        raw.gov_0x1348 = 0x578; // gpu-se-tgt
        raw.gov_0x1350 = sp * pw.se_filter_time_constant;
        raw.gov_0x1354 = sp * pw.se_filter_time_constant_1;
        raw.gov_0x1358 = U64(u64::from(pw.se_filter_time_constant * sp * 0x5dc0));
        raw.gov_0x1360 = U64(u64::from(pw.se_filter_time_constant_1 * sp * 0x5dc0));
        raw.gov_0x136c = f32!(65536.0);
        raw.gov_0x1394 = sp * 1000;
        raw.gov_0x1398 = (sp / 2 + 0x21) / sp;
        raw.gov_0x139c = [
            pw.se_inactive_threshold,
            u32::try_from(pw.se_engagement_criteria).unwrap_or(0xffffffff),
        ];
        raw.gov_0x13a4 = [2, 4]; // the engagement and reset tolerances
        raw.gov_0x13ac = pw.se_reset_criteria;
    }

    /// HwDataA's AON PTD table (`getAONPTDFromOSDictionary`): an
    /// identifier per cluster ("g"), per die ("r") and one "f", each looked
    /// up in the chip's AON PTD rows. A row found is appended to the entries
    /// and its bit set; the lookup stops at the first identifier without
    /// one.
    #[ver(G == G15)]
    fn g15_hwdata_a_aonptd(raw: &mut g15::HwDataA, cfg: &hw::HwConfig, dyncfg: &hw::DynConfig) {
        const IDS_G: [[u8; 4]; 8] = [
            *b"RT0g", *b"RT1g", *b"RT2g", *b"RT3g", *b"RT4g", *b"RT5g", *b"RT6g", *b"RT7g",
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
                match dyncfg.pwr.aon_ptd.iter().find(|row| row[..4] == id[..]) {
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
    }

    /// HwDataA's PPM controller parameters, from the ADT's gpu-ppm-*
    /// properties: the filter time constant in sample periods (f), its
    /// coefficients, the gains and the power target.
    #[ver(G == G15)]
    fn g15_hwdata_a_ppm(raw: &mut g15::HwDataA, pw: &hw::PwrConfig) {
        let one = f32!(1.0);
        let sp = pw.power_sample_period;
        let sc = F32::from(sp) / F32::from(1000);
        let ptc = pw.ppm_filter_time_constant_ms;
        let p28 = ptc / sp;
        let pf = F32::from(p28);
        raw.perf_0x6f0 = p28 << 2;
        raw.perf_0x6f4 = 0;
        raw.perf_0x6fc = (pf - one) / pf;
        raw.perf_0x704 = one / pf;
        raw.perf_0x70c = pw.ppm_ki * sc;
        raw.perf_0x714 = [F32::from(pw.pwr_integral_min_clamp), f32!(65536.0)];
        raw.perf_0x71c = pw.ppm_kp;
        raw.perf_0x724 = 0;
        raw.perf_0x728 = [pw.pwr_min_duty_cycle, top_pstate_x100(pw)];
        raw.perf_0x730 = 0;
        raw.perf_0x738 = 0;
        raw.perf_0x73c = pw.max_power_mw;
        raw.perf_0x744 = ptc;
        let p30 = u64::from(sp) * u64::from(p28) * 0x5dc0;
        raw.perf_0x74c = [p30 as u32, (p30 >> 32) as u32];
    }

    /// Allocates and fills HwDataA. `umap_table` is the UMA page-pool
    /// descriptor table.
    #[ver(G == G15)]
    fn g15_hwdata_a(&mut self, umap_table: &GpuArray<u8>) -> Result<GpuObject<g15::HwDataA>> {
        let cfg = self.cfg;
        let dyncfg = self.dyncfg;
        let g15g = cfg.gpu_variant == hw::GpuVariant::G;
        let dpeppt = if g15g {
            Some(g15g_dpeppt(&dyncfg.pwr)?)
        } else {
            None
        };
        let mut hwdata_a = self.alloc.shared.new_default::<g15::HwDataA>()?;
        hwdata_a.with_mut(|raw, _| {
            raw.uma_desc_table = U64(umap_table.gpu_va().get());
            Self::g15_hwdata_a_base(raw, cfg, &dyncfg.pwr);
            Self::g15_hwdata_a_perf(raw, cfg, &dyncfg.pwr);
            Self::g15_hwdata_a_power(raw, cfg, &dyncfg.pwr);
            Self::g15_hwdata_a_governor(raw, &dyncfg.pwr);
            // G15S and G15G have no AON PTD state
            // (`populateAONPTDIdentifiers` is G15C's only).
            if cfg.gpu_variant == hw::GpuVariant::C {
                Self::g15_hwdata_a_aonptd(raw, cfg, dyncfg);
            }
            Self::g15_hwdata_a_ppm(raw, &dyncfg.pwr);
            if let Some(dpe) = &dpeppt {
                raw.dpeppt = *dpe;
                // The leakage-update config's mirror: +0x4c, +0x40 (u64),
                // +0x00…+0x3f, +0x48.
                let mut put = |off: usize, v: u32| {
                    raw.dpe_leak[off..off + 4].copy_from_slice(&v.to_le_bytes())
                };
                put(0x4, G15G_DPE_LEAK_TAIL[3]);
                put(0x8, G15G_DPE_LEAK_TAIL[0]);
                put(0xc, G15G_DPE_LEAK_TAIL[1]);
                for (i, v) in G15G_DPE_LEAK.iter().enumerate() {
                    put(0x10 + 4 * i, *v);
                }
                put(0x50, G15G_DPE_LEAK_TAIL[2]);
            }
            if matches!(cfg.gpu_variant, hw::GpuVariant::S | hw::GpuVariant::G) {
                // SAFETY: HwDataA is plain repr(C) data, not yet shared with
                // the firmware, and the slice covers exactly its bytes.
                let bytes = unsafe {
                    core::slice::from_raw_parts_mut(
                        core::ptr::from_mut(raw).cast::<u8>(),
                        core::mem::size_of::<g15::HwDataA>(),
                    )
                };
                g15::compact(bytes, g15::HWDATA_A_G15S);
            }
        });
        Ok(hwdata_a)
    }

    /// HwDataB's GPU perf-state tables. The DT's two OPP tables are macOS's
    /// tables A and B. Volts: one slot per cluster, the rest copies of slot
    /// 0; SRAM volts: at least the minimum SRAM volts.
    #[ver(G == G15)]
    fn g15_hwdata_b_pstates(raw: &mut g15::HwDataB, pw: &hw::PwrConfig) {
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
            // `populateSRAMPowerScaleData`'s 1.02.
            raw.sram_scale[i] = 0x3f82_8f5c;
        }
        // Each state's max power as a share of the top state's. The DT's
        // opp-microwatt carries the per-state power macOS computes.
        let power = |ps: &crate::hw::PState| -> u64 { u64::from(ps.pwr_mw) };
        let top = power(&a[n - 1]);
        for (i, ps) in a.iter().take(n).enumerate() {
            raw.perf_pwr_pct[i] = (100 * power(ps)).checked_div(top).map_or(0, |q| q as u32);
        }
        // The clocks from the base state up, as a share of the base to top
        // span.
        let base = pw.perf_base_pstate as usize;
        let clk = |i: usize| u64::from(a[i].freq_hz);
        for i in base..n - 1 {
            let span = clk(n - 1).wrapping_sub(clk(base));
            raw.perf_freq_pct[i] = 100u64
                .wrapping_mul(clk(i).wrapping_sub(clk(base)))
                .checked_div(span)
                .map_or(0, |q| q as u32);
        }
        raw.perf_freq_pct[n - 1] = 100;
        for (j, m) in pw.perf_state_map.iter().take(0x20).enumerate() {
            raw.perf_state_map[j] = *m;
        }
        // The CS and AFR tables: one volt per die, at least the tables'
        // minimum SRAM volts; the caps are the count - 1.
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
        // Table B: only the slots below the table's count are copied.
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
    }

    /// Allocates and fills HwDataB: constants, the chip configuration and
    /// the perf-state tables.
    #[ver(G == G15)]
    fn g15_hwdata_b(&mut self) -> Result<GpuObject<g15::HwDataB>> {
        let cfg = self.cfg;
        let dyncfg = self.dyncfg;
        let mut hwdata_b = self.alloc.shared.new_default::<g15::HwDataB>()?;
        hwdata_b.with_mut(|raw, _| {
            raw.magic1 = U64(0x6f_0000_0000);
            raw.magic2 = U64(0xff_c0_0000);
            raw.const_0x10 = U64(0x10_0000_0000);
            raw.const_0x18 = U64(0x10_0000_0000);
            raw.const_0x20 = U64(0x2ffffff8000);
            raw.egart_fwva = U64(gpu::IOVA_KERN_TIMESTAMP_RANGE.start);
            raw.one_0xa50 = 1;
            raw.one_0xa60 = 1;
            raw.base_clock_khz = cfg.base_clock_hz / 1000;
            // 200 for an ADT `model-slow` device, 1 otherwise.
            raw.power_sample_period = 1;
            raw.vtbl_0xe68 = dyncfg.pwr.power_sample_period;
            raw.one_0xa78 = 1;
            raw.const_0xa7c = [1, 1];
            raw.const_0xa9c = 0x1f;
            raw.const_0xac8 = U64(0x100000000);
            raw.const_0xad0 = U64(1);
            // The feature-word and probe-byte bits.
            raw.probe_da2_bit1 = 1;
            raw.chip_0x650_bit8 = 1;
            raw.chip_0x650_bit11 = 1;
            // One bit per MCache window: 0x3f for t6034's six.
            let mcache = cfg
                .g15_windows
                .and_then(|w| w.iter().find(|w| w.kind > 1))
                .map_or(0, |w| w.pairs.len() + 1);
            raw.chip_0x2040 = U64((1u64 << mcache) - 1);
            // The chip ID, 1, 2, 0.
            raw.chip_0x20c0 = U64(0x1_0000_0000 | u64::from(cfg.chip_id));
            raw.chip_0x20c8 = U64(2);
            // isPIOSupported(): 1, as on macOS. With 0, the firmware's
            // power-up never sets a perf state and the GPU stays at state
            // 0, where no job completes.
            raw.vtbl_0xae0 = 1;
            // halGetDefaultMcacheWrites(): 4 on G15X, which configureDevice
            // ORs with 4 again. The firmware picks two GPU clients' DSIDs
            // and cache-write bits from it at every power-up
            // (AGFA_GPUHWInit, RGX +0xD950, +0xD968, +0xD978).
            raw.chip_0x2028 = 4;
            raw.chip_0x2064 = 0x31;
            raw.enabled_uscs = dyncfg.id.num_cores * dyncfg.id.num_clusters;
            raw.feat_0x17fc = 1;
            raw.feat_0x1808 = [1, 0];
            raw.feat_0x1818 = [1, 0];
            raw.da2_0x1860 = 1;
            // The core configuration `getProbeScore` copies: the core ID
            // (G15C), the revision ID and the cores of all clusters.
            raw.core_id[0] = cfg.gpu_core as u32;
            raw.core_id[1] = dyncfg.id.gpu_rev_id as u32;
            raw.chip_0x47c = dyncfg.id.num_cores * dyncfg.id.num_clusters;
            raw.uat_config = 1;

            Self::g15_hwdata_b_pstates(raw, &dyncfg.pwr);

            // The tail of the Arm `initFirmwareData`. The masks come from
            // the core configuration's ID_UNK18 products.
            let mask = |n: u32| {
                if n > 63 {
                    u32::MAX
                } else {
                    ((1u64 << n) - 1) as u32
                }
            };
            // configureDevice: 4 on G15G
            raw.chip_0x688 = if cfg.gpu_variant == hw::GpuVariant::G {
                4
            } else {
                5
            };
            raw.chip_0x68c = 0;
            raw.mask_0x17c0 = [mask(2), mask(3)];
            raw.mask_0x17c8 = mask(3);
            raw.one_0x17e8 = 1;
            raw.one_0x1800 = [1, 1];
            raw.const_0x1810 = [1, 1];
            raw.ones_0x1820 = [0xff; 0x30];
            if cfg.gpu_variant == hw::GpuVariant::G {
                // SAFETY: HwDataB is plain repr(C) data, not yet shared with
                // the firmware, and the slice covers exactly its bytes.
                let bytes = unsafe {
                    core::slice::from_raw_parts_mut(
                        core::ptr::from_mut(raw).cast::<u8>(),
                        core::mem::size_of::<g15::HwDataB>(),
                    )
                };
                g15::compact(bytes, g15::HWDATA_B_G15G);
            }
        });
        Ok(hwdata_b)
    }

    /// Allocates and fills the PB table: the firmware's timeouts, soft-fault
    /// settings, power targets and idle-off predictor.
    #[ver(G == G15)]
    fn g15_pb_table(&mut self, power_sample_period: u32) -> Result<GpuObject<g15::PBTable>> {
        let pw = &self.dyncfg.pwr;
        let g15g = self.cfg.gpu_variant == hw::GpuVariant::G;
        let s_layout = matches!(self.cfg.gpu_variant, hw::GpuVariant::S | hw::GpuVariant::G);
        let dpeppt = if g15g { Some(g15g_dpeppt(pw)?) } else { None };
        let mut pb_table = self.alloc.fw_nc.new_default::<g15::PBTable>()?;
        pb_table.with_mut(|raw, _| {
            raw.const_0x38 = 0x78;
            raw.cmd_submission_enabled = 1;
            // The hang timeouts and soft-fault settings of the Arm
            // `initFirmwareData`.
            raw.relaxed_cl_kill_timeout = 3000;
            raw.cl_ctx_switch_timeout = 40;
            raw.cl_kill_timeout = 50;
            raw.cdm_backoff_timeout = 4;
            raw.soft_fault = 3u32.to_le_bytes();
            raw.chip_0x6c4 = 0xffff;
            raw.chip_0x6c6 = 0x0028;
            raw.chip_0x6c8 = 0xffff;
            raw.chip_a218_eq0 = 1;
            let c34x100 = top_pstate_x100(pw);
            raw.pwr_target = [pw.max_power_mw, c34x100, c34x100];
            raw.chip_0x65c = U64(u64::from(c34x100) << 32);
            raw.one_0x7d0 = [1, 1];
            // The keepalive thresholds (`configureDevice`).
            raw.chip_0x2198 = 100;
            raw.chip_0x2194 = 100;
            raw.chip_0x2150 = U64(0x28 | (0xa << 32));
            raw.chip_0x2158 = U64(0xfa | (1 << 32));
            raw.chip_0x2160 = U64(1 | (0x64 << 32));
            raw.chip_0x2168 = 1;
            raw.ternary_0x9a0 = 2;
            raw.ternary_0x9a4 = 40;
            raw.ternary_0x9a8 = 5;
            // The idle-off predictor: `configurePowerAndPerformanceController`'s
            // defaults with the ADT's gpu-idleoff-* overrides.
            raw.idleoff = [
                pw.idle_off_standby_timer,
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
            // Feature-word bits 0 and 1.
            raw.chip_0x650_bit0 = 1;
            raw.feature_bit1 = 1;
            raw.power_sample_period = power_sample_period.min(255) as u8;
            // G15X's `populateFwUtilPerfTunables` bytes: the monitor on; the
            // fabric P-state vote at power-down 0 and at power-up 1; a 2 ms
            // sample; per level {up count, down count, up % at least, down %
            // under, up step, down step}. The rest stays zero: past 0x20 is
            // the sensor override mask, whose set bits replace a sensor's
            // reading with the override table's. G15G takes the base's
            // zeros: the monitor off.
            if !g15g {
                raw.fw_util_perf_tunables[..0x19].copy_from_slice(&[
                    1, 0, 0, 0, 0, 1, 2, 1, 1, 90, 75, 1, 1, 1, 2, 90, 75, 1, 1, 1, 1, 90, 75, 1, 1,
                ]);
            }
            // The DPEPPT block's mirror (HwDataA +0x64c4…).
            if let Some(dpe) = &dpeppt {
                raw.dpeppt.copy_from_slice(&dpe[4..4 + 0x6d8]);
            }
            if s_layout {
                // SAFETY: the power block is plain repr(C) data (the atomic
                // word included), not yet shared with the firmware, and the
                // slice covers exactly its bytes.
                let bytes = unsafe {
                    core::slice::from_raw_parts_mut(
                        core::ptr::from_mut(raw).cast::<u8>(),
                        core::mem::size_of::<g15::PBTable>(),
                    )
                };
                g15::compact(bytes, g15::PB_TABLE_G15S);
            }
        });
        Ok(pb_table)
    }

    /// Allocates the firmware-to-host rings: four ring state and storage
    /// pairs, then the 0x51000-byte buffer. Zeroed, every ring is empty.
    #[ver(G == G15)]
    fn g15_fw_rings(&mut self) -> Result<KVec<GpuArray<u8>>> {
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
            // Normal non-cacheable for the firmware, as on macOS: through a
            // Device mapping its ring writes fault on alignment, and through
            // a cached one its recovery report stalls.
            fw_rings.push(
                self.alloc.fw_nc.array_empty_tagged::<u8>(size, tag)?,
                GFP_KERNEL,
            )?;
        }
        Ok(fw_rings)
    }

    /// Fills one ring group's four channel-table words for ring `r`: its
    /// read and CFI index words, its doorbell word and its storage, in the
    /// ring area at `base`.
    ///
    /// # Safety
    ///
    /// Each pointer must be valid for a write of a `U64`.
    #[ver(G == G15)]
    unsafe fn g15_fill_ring_words(
        read: *mut U64,
        cfi: *mut U64,
        doorbell: *mut U64,
        storage: *mut U64,
        r: usize,
        base: u64,
    ) {
        let read_va = base + g15::RING_REGION2_OFF as u64 + 16 * r as u64;
        let doorbell_va = base + r as u64 * g15::RING_STRIDE as u64;
        // SAFETY: each pointer is valid for a `U64` write per the caller, and
        // `U64` is packed(1), so any address is aligned for it.
        unsafe {
            core::ptr::write(read, U64(read_va));
            core::ptr::write(cfi, U64(read_va + 8));
            core::ptr::write(doorbell, U64(doorbell_va));
            core::ptr::write(storage, U64(doorbell_va + 8));
        }
    }

    /// Allocates and fills the channel table: the addresses of the other
    /// buffers and the ring table, whose row `k` holds rings `k`, `4 + k`
    /// and `8 + k`, the TA, 3D and CL rings of queue `k`.
    #[ver(G == G15)]
    fn g15_channel_table(&mut self, v: &ChannelTableVas) -> Result<GpuObject<g15::ChannelTable>> {
        let mut channel_table = self.alloc.shared.new_default::<g15::ChannelTable>()?;
        channel_table.with_mut(|raw, _inner| {
            raw.hwdata_b_fwva = U64(v.hwdata_b);
            raw.buf_0x248_fwva = U64(v.clock_table);
            raw.chip_0x30d0_fwva = U64(v.hwdsid_table);
            let split = |va: u64| [va as u32, (va >> 32) as u32];
            raw.buf_0x218_fwva = split(v.buf_0x218);
            raw.buf_0x220_fwva = split(v.buf_0x220);
            raw.buf_0x228_fwva = split(v.buf_0x228);
            raw.buf_0x238_fwva = split(v.buf_0x238);
            raw.pb_desc_table_gpuva = U64(v.pb_desc_table);
            raw.pb_desc_table_fwva = U64(v.pb_desc_table);
            raw.umap_pool_pa = U64(v.umap_table);
            raw.umap_pool_fwva = U64(v.umap_table);
            raw.special[3] = U64(v.special_ring);
            // The firmware writes its log to the rings only with this set;
            // macOS leaves it 0.
            raw.log_enable = 1;
            raw.chip_0x20b8 = 4; // halGetDefaultUscMaxTgmem
            for (k, va) in v.fw_rings.iter().take(8).enumerate() {
                raw.ptr_block[k] = U64(*va);
            }
            raw.buf_0x900_fwva = U64(v.fw_rings[8]);
            for k in 0..4 {
                let e = &mut raw.ring[k];
                // SAFETY: the pointers are to the entry's own fields.
                unsafe {
                    Self::g15_fill_ring_words(
                        core::ptr::addr_of_mut!(e.ta_read),
                        core::ptr::addr_of_mut!(e.ta_cfi),
                        core::ptr::addr_of_mut!(e.ta_write),
                        core::ptr::addr_of_mut!(e.ta_storage),
                        k,
                        v.ring_area,
                    );
                    Self::g15_fill_ring_words(
                        core::ptr::addr_of_mut!(e.d3_read),
                        core::ptr::addr_of_mut!(e.d3_cfi),
                        core::ptr::addr_of_mut!(e.d3_write),
                        core::ptr::addr_of_mut!(e.d3_storage),
                        4 + k,
                        v.ring_area,
                    );
                    Self::g15_fill_ring_words(
                        core::ptr::addr_of_mut!(e.cl_read),
                        core::ptr::addr_of_mut!(e.cl_cfi),
                        core::ptr::addr_of_mut!(e.cl_write),
                        core::ptr::addr_of_mut!(e.cl_storage),
                        8 + k,
                        v.ring_area,
                    );
                }
            }
            // The special control ring, the 13th: its index words follow
            // the 12 command rings'.
            let s = v.ring_area + g15::RING_REGION2_OFF as u64 + 0xC0;
            raw.special[0] = U64(s);
            raw.special[1] = U64(s + 8);
            raw.special[2] = U64(v.ring_area + g15::RING_SPECIAL_DOORBELL_OFF as u64);
            // The tail: 0xff, then HwDataA's address as an unaligned u64.
            // The firmware reads a whole u64 there and uses HwDataA as its
            // own state.
            let p = raw.tail_0x3b0.as_mut_ptr();
            // SAFETY: tail_0x3b0 is a 0xa9-byte array covering 0x3b0..0x459;
            // both stores are in bounds and unaligned.
            unsafe {
                p.write(0xff);
                p.add(0x91).cast::<u64>().write_unaligned(v.hwdata_a);
            }
        });
        Ok(channel_table)
    }

    /// Allocates the MCache PIO buffer (`createFWPIOMapping`): the MCache
    /// window's base and register pairs, from which the firmware maps the
    /// MCache windows itself.
    #[ver(G == G15)]
    fn g15_mcache_piob(&mut self) -> Result<GpuArray<u64>> {
        let mut mcache_piob = self.alloc.shared.array_empty_tagged(12, b"MCPI")?;
        let mut slots = [0u64; 12];
        if let Some(windows) = self.cfg.g15_windows {
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
        mcache_piob.as_mut_slice().copy_from_slice(&slots);
        Ok(mcache_piob)
    }

    /// Allocates the host/firmware control block: the firmware's trace
    /// flags, then 1.
    #[ver(G == G15)]
    fn g15_fw_ctl(&mut self) -> Result<GpuArray<u32>> {
        let mut fw_ctl = self.alloc.fw_nc.array_empty_tagged(8, b"FCTL")?;
        fw_ctl.as_mut_slice()[1] = 1;
        if crate::debug::debug_enabled(crate::debug::DebugFlags::Debug4) {
            // The firmware's scheduler and barrier traces, and its
            // context-store requests, in its flight recorder.
            fw_ctl.as_mut_slice()[0] = 0x23;
        }
        Ok(fw_ctl)
    }

    /// Allocates the firmware's event page, which macOS's `AGXBlockFence`
    /// and event-ring drain use.
    #[ver(G == G15)]
    #[allow(
        clippy::eq_op,
        reason = "s[0x4 / 4]: a byte offset / 4, as its neighbours"
    )]
    fn g15_event_page(&mut self) -> Result<GpuArray<u32>> {
        let mut event_page = self.alloc.fw_nc.array_empty_tagged(0xc3d0 / 4, b"FEVT")?;
        let ep = event_page.gpu_va().get();
        let s = event_page.as_mut_slice();
        s[0x45c4 / 4] = 1;
        s[0x4 / 4] = 1; // feature-word bit 2
                        // The secure cache flush ring. macOS publishes a NULL head and ring,
                        // and its firmware never enters the flush, but this one does. A
                        // zeroed head (head == tail) and ring at the top of the page make
                        // the flush find no work, which is right: the driver submits no
                        // secure cache flushes, as there is no secure monitor.
        let head = ep + 0xc300;
        let ring = ep + 0xc320;
        s[0x4568 / 4] = head as u32;
        s[0x456c / 4] = (head >> 32) as u32;
        s[0x4570 / 4] = ring as u32;
        s[0x4574 / 4] = (ring >> 32) as u32;
        Ok(event_page)
    }

    /// Allocates the host/firmware power-control block: the host's
    /// controller parameters as `setupConfig`, `initFirmwareSharedData` and
    /// the Arm `initPowerAndPerformanceData` store them. Of the doorbells,
    /// only the PPM one is set.
    #[ver(G == G15)]
    fn g15_pwr_ctl(&mut self) -> Result<GpuArray<u32>> {
        let pw = &self.dyncfg.pwr;
        let cfg = self.cfg;
        let mut pwr_ctl = self
            .alloc
            .fw_nc
            .array_empty_tagged::<u32>(0x238 / 4, b"PCTL")?;
        let w = pwr_ctl.as_mut_slice();
        // The average-power controller: no zones, its filter, ki 0.1, kp
        // 0.3, the minimum duty cycle and the target filter.
        w[0xc / 4] = 0;
        w[0x10 / 4] = 4;
        w[0x14 / 4] = 0x3dcc_cccd;
        w[0x18 / 4] = 0x3e99_999a;
        w[0x1c / 4] = pw.pwr_min_duty_cycle;
        w[0x20 / 4] = 1;
        // The fast-die controller: the target (110.0 degrees on G15X), to
        // which the firmware clamps its PTD target, and the gains.
        w[0xa8 / 4] = cfg.fastdie_target;
        w[0xb8 / 4] = pw.fast_die0_proportional_gain.to_bits();
        w[0xbc / 4] = (pw.fast_die0_integral_gain
            * (F32::from(pw.power_sample_period) / f32!(1000.0)))
        .to_bits();
        // The PPM controller: its doorbell, the max power as its target
        // (`setPPMControllerTarget`), kp 0.3 and ki 0.008.
        w[0xcc / 4] = 1;
        w[0xd0 / 4] = pw.max_power_mw;
        w[0xd4 / 4] = 0x3e99_999a;
        w[0xd8 / 4] = 0x3e1c_779b;
        // SE engagement on.
        w[0xec / 4] = 1;
        // G15G's DPE leakage-update config: +0x4c, +0x40, +0x44, then
        // +0x00…+0x3f and +0x48 (zero on G15X).
        if cfg.gpu_variant == hw::GpuVariant::G {
            w[0x15c / 4] = G15G_DPE_LEAK_TAIL[3];
            w[0x160 / 4] = G15G_DPE_LEAK_TAIL[0];
            w[0x164 / 4] = G15G_DPE_LEAK_TAIL[1];
            w[0x168 / 4..0x1a8 / 4].copy_from_slice(&G15G_DPE_LEAK);
            w[0x1a8 / 4] = G15G_DPE_LEAK_TAIL[2];
        }
        Ok(pwr_ctl)
    }

    /// The FMC channel header, from the addresses of the buffers it
    /// publishes.
    #[ver(G == G15)]
    fn g15_fmc_header(
        magic: u64,
        ring2: u64,
        channel_table: u64,
        pb_table: u64,
        fw_ctl: u64,
        event_page: u64,
        pwr_ctl: u64,
    ) -> g15::FmcHeader {
        let mut header = g15::FmcHeader::default();
        header.magic = magic;
        header.ring2_fwva = U64(ring2);
        header.channel_table_fwva = U64(channel_table);
        header.pb_table_fwva = U64(pb_table);
        header.const_0x28 = U64(0x100000000);
        // The GART table (`AGXSharedGartTableBackingG15::initGartInfo`):
        // three level records and a zero word. A record's index mask
        // overlaps the next record, so these are the raw bytes of the
        // stores for 16 KiB pages, 64/2048/2048 entries and the PTE
        // template {1, (2^28 - 1) << 14}.
        header.chip_a078 = [
            U64(0x240e0e08030e_4000), // top: 0x4000, 14, 3, 0x0e08, 0x0e, 0x24
            U64(0x000000014000_0040), // top: 64 entries, 0x4000, template lo
            U64(0xffffc0000000_0000), // template hi
            U64(0x3ff),               // template hi upper, top mask lo (0)
            U64(0x190e0e080000_03f0), // top mask hi (0x3f0), mid: 0x0e08, 0x0e, 0x19
            U64(0x000000014000_0800), // mid: 2048 entries, 0x4000, template lo
            U64(0xffffc0000000_0000), // template hi
            U64(0xfe0000000000_03ff), // template hi upper, mid mask lo (0xfe000000)
            U64(0x0e0e0e080000_000f), // mid mask hi (0xf), leaf: 0x0e08, 0x0e, 0x0e
            U64(0x000000014000_0800), // leaf: 2048 entries, 0x4000, template lo
            U64(0xffffc0000000_0000), // template hi
            U64(0x01ffc0000000_03ff), // template hi upper, leaf mask lo (0xffc000)
            U64(0),
        ];
        header.buf_0x910_fwva = U64(fw_ctl);
        header.buf_0xa40_fwva = U64(event_page);
        header.buf_0xa48_fwva = U64(pwr_ctl);
        header
    }

    /// Builds the G15 buffer set.
    #[ver(G == G15)]
    pub(super) fn build_impl(&mut self) -> Result<KBox<GpuObject<InitData::ver>>> {
        // The UMA page-pool descriptor table (`createHardwareMappings`, 256
        // entries of 0x20 bytes). The GPU reads it and writes entries back
        // at a slot flush.
        let umap_table = self
            .alloc
            .gpu_fw_nc
            .array_empty_tagged::<u8>(0x2000, b"UMAP")?;
        let hwdata_a = self.g15_hwdata_a(&umap_table)?;
        let hwdata_b = self.g15_hwdata_b()?;
        // HwDataB's sample period, at least 1.
        let power_sample_period = hwdata_b.with(|raw, _| raw.power_sample_period).max(1);
        let pb_table = self.g15_pb_table(power_sample_period)?;

        // The special control ring's storage: 256 entries of 0x38 bytes.
        let special_ring = self.alloc.shared.array_empty_tagged(0x3800, b"AGFE")?;
        // The ring area: the 13 rings' index words and the 12 command rings'
        // storages, laid out as macOS's Fender scratch. Firmware
        // non-cacheable: the firmware reads the entries and index words
        // without cache maintenance, and through a cached mapping it reads
        // stale entries. The host cleans its stores to memory.
        let ring_area = self
            .alloc
            .fw_nc
            .array_empty_tagged(g15::RING_REGION_SIZE, b"AGFR")?;
        // The timestamp/clock table. Zeroed, its gate makes the firmware
        // build its own default table, but the firmware dereferences the
        // pointer anyway.
        let clock_table = self.alloc.shared.array_empty_tagged::<u8>(0x88, b"TBL8")?;
        // The HWDSID table (`AGXHWDSIDManager`), which the firmware's
        // control-ring command 13 stores into.
        let hwdsid_table = self.alloc.shared.array_empty_tagged::<u8>(0x800, b"DSID")?;
        // The base `initFirmwareData`'s four buffers: zeroed, but for two
        // words of the second.
        let buf_0x218 = self.alloc.shared.array_empty_tagged::<u8>(0xc10, b"B218")?;
        let mut buf_0x220 = self
            .alloc
            .shared
            .array_empty_tagged::<u32>(0x1248 / 4, b"B220")?;
        buf_0x220.as_mut_slice()[0xc18 / 4] = u32::MAX;
        buf_0x220.as_mut_slice()[0xc30 / 4] = u32::MAX;
        let buf_0x228 = self.alloc.shared.array_empty_tagged::<u8>(0xe10, b"B228")?;
        let buf_0x238 = self.alloc.shared.array_empty_tagged::<u8>(0x60, b"B238")?;
        let fw_rings = self.g15_fw_rings()?;
        // The parameter-buffer descriptor table (`createHardwareMappings`;
        // `halLoadPBDesc` fills an entry per buffer ID), which the GPU's PM
        // reads.
        let pb_desc_table = self
            .alloc
            .gpu_fw_nc
            .array_empty_tagged::<u8>(0x1000, b"PBDT")?;

        let mut ring_vas = [0u64; 9];
        for (va, buf) in ring_vas.iter_mut().zip(fw_rings.iter()) {
            *va = buf.gpu_va().get();
        }
        let channel_table = self.g15_channel_table(&ChannelTableVas {
            hwdata_a: hwdata_a.gpu_va().get(),
            hwdata_b: hwdata_b.gpu_va().get(),
            clock_table: clock_table.gpu_va().get(),
            hwdsid_table: hwdsid_table.gpu_va().get(),
            buf_0x218: buf_0x218.gpu_va().get(),
            buf_0x220: buf_0x220.gpu_va().get(),
            buf_0x228: buf_0x228.gpu_va().get(),
            buf_0x238: buf_0x238.gpu_va().get(),
            pb_desc_table: pb_desc_table.gpu_va().get(),
            umap_table: umap_table.gpu_va().get(),
            special_ring: special_ring.gpu_va().get(),
            ring_area: ring_area.gpu_va().get(),
            fw_rings: ring_vas,
        })?;
        let mcache_piob = self.g15_mcache_piob()?;

        // The three FMC ring buffers, zeroed: the FMC ring, whose start
        // holds the channel header (a u64 array, for its alignment), ring 2
        // and the third.
        let mut fmc = self.alloc.shared.array_empty_tagged(0x800, b"FRMC")?;
        let ring2 = self.alloc.shared.array_empty_tagged(0x1000, b"AGFA")?;
        let buf_0x4000 = self.alloc.shared.array_empty_tagged(0x4000, b"BUF4")?;
        let fw_ctl = self.g15_fw_ctl()?;
        let event_page = self.g15_event_page()?;
        let pwr_ctl = self.g15_pwr_ctl()?;
        let magic = if matches!(self.cfg.gpu_variant, hw::GpuVariant::S | hw::GpuVariant::G) {
            g15::FMC_MAGIC_G15S
        } else {
            g15::FMC_MAGIC
        };
        let header = Self::g15_fmc_header(
            magic,
            ring2.gpu_va().get(),
            channel_table.gpu_va().get(),
            pb_table.gpu_va().get(),
            fw_ctl.gpu_va().get(),
            event_page.gpu_va().get(),
            pwr_ctl.gpu_va().get(),
        );
        {
            let elems: &mut [u64] = fmc.as_mut_slice();
            // SAFETY: the u64 array's base is 8-byte aligned as FmcHeader
            // needs, and the 0xc0-byte header fits in its 0x4000 bytes.
            unsafe { elems.as_mut_ptr().cast::<g15::FmcHeader>().write(header) };
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
                clock_table,
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
            |inner, _ptr| g15::InitData {
                hwdata_a: U64(inner.hwdata_a.gpu_va().get()),
                hwdata_b: U64(inner.hwdata_b.gpu_va().get()),
                channel_table: U64(inner.channel_table.gpu_va().get()),
                pb_table: U64(inner.pb_table.gpu_va().get()),
                fmc: U64(inner.fmc.gpu_va().get()),
                ring2: U64(inner.ring2.gpu_va().get()),
                buf_0x4000: U64(inner.buf_0x4000.gpu_va().get()),
                mcache_piob: U64(inner.mcache_piob.gpu_va().get()),
                ring_area: U64(inner.ring_area.gpu_va().get()),
            },
        )?;
        Ok(KBox::new(obj, GFP_KERNEL)?)
    }
}
