// SPDX-License-Identifier: GPL-2.0-only

//! G15 GPU perf-state tables from the live ADT.
//!
//! iBoot bins the GPU's volts per chip into the ADT's `perf-states`: one
//! table a cluster, `count` rows of {Hz, mV} each, table-major. m1n1 copies
//! it into `apple,perf-states`, with `apple,perf-state-table-count`. As
//! macOS's `createMGPUPerfStateTables` does, the GPU's perf-state maps
//! pick the rows of tables A and B, and as G15X's
//! `populateMaximumPerformancePower` does, each state of table A gets its
//! maximum power (chip-config.md: the GPU perf-state tables, maximum
//! power; G15G's adds the chip's leakage, g15g.md). macOS computes the
//! power in float32, this in fixed point: the two can differ by 1 mW where
//! macOS's value lies within about 0.01 of an integer.

use super::{CsAfrPwrConfig, GpuIdConfig, GpuVariant, PState};
use kernel::prelude::*;

/// (mV / 1000)^1.2 in Q30.
fn pow_1_2(mv: u32) -> u64 {
    let mv = u64::from(mv.min(5000));
    let v = (mv << 30) / 1000;
    // y = (mV / 1000)^(1/5): the largest Q30 y with y^5 <= v, y < 1.5
    // (y^5 stays below 2^64 in Q30).
    let (mut lo, mut hi) = (0u64, 3u64 << 29);
    while lo + 1 < hi {
        let y = (lo + hi) / 2;
        let mut p = y;
        for _ in 0..4 {
            p = (p * y) >> 30;
        }
        if p <= v {
            lo = y;
        } else {
            hi = y;
        }
    }
    mv * lo / 1000
}

/// V · min(V^1.2 · `k10` / 10 · MHz · `n` / `d`, `clamp`) in mW, truncated.
fn max_power(mv: u32, mhz: u32, k10: u64, n: u32, d: u64, clamp: u64) -> u32 {
    let dynamic = pow_1_2(mv) * k10 * u64::from(mhz) * u64::from(n) / (10 * d);
    let p = u64::from(mv) * dynamic.min(clamp << 30) / 1000;
    (p >> 30) as u32
}

/// A positive f32 below 2^33 (its bits) in Q30, truncated; 0 otherwise.
pub(super) fn f32_q30(bits: u32) -> u64 {
    let e = ((bits >> 23) & 0xff) as i32 - 127;
    if bits >> 31 != 0 || bits >> 23 == 0 || e >= 33 {
        return 0;
    }
    let mant = u64::from((bits & 0x7f_ffff) | 0x80_0000);
    let shift = e + 30 - 23;
    if shift >= 0 {
        mant << shift
    } else {
        mant >> -shift
    }
}

/// e^(`x` / 2^48) in Q48, for `x` < 9 << 48.
fn exp_q48(x: u64) -> u64 {
    // e^0 ... e^8 in Q48
    const E: [u64; 9] = [
        0x1000000000000,
        0x2b7e151628aed,
        0x763992e35376b,
        0x1415e5bf6fb106,
        0x3699205c4e74b1,
        0x9469c4cb819c79,
        0x1936dc5690c08f3,
        0x448a216abb76a9c,
        0xba4f53ea38636f8,
    ];
    // e^f for the fraction f < 1: the Taylor series to f^20 / 20!
    let f = u128::from(x & ((1 << 48) - 1));
    let (mut sum, mut term) = (1u128 << 48, 1u128 << 48);
    for n in 1..=20u128 {
        term = term * f / (n << 48);
        sum += term;
    }
    ((u128::from(E[(x >> 48) as usize]) * sum) >> 48) as u64
}

/// G15G's `populateMaximumPerformancePower`, the bands of the chip's
/// leakage L (L / 3897.66 at 0.758, 1.071, 1.433, 1.789): the least L, then
/// a, b and c of L · a · e^(b · mV + c), the f32 constants in Q48.
const G15G_LEAK: [(u64, u64, u64, u64); 5] = [
    (0, 0x36a80f00000, 0x838f380000, 0x33fdcf8000000),
    (2954, 0x339a5c00000, 0x8bb08b0000, 0x333376c000000),
    (4175, 0x31b53000000, 0x83e8810000, 0x33dc094000000),
    (5585, 0x2f78dd40000, 0x84f3bd0000, 0x3330ce4000000),
    (6972, 0x30b94380000, 0x8d6bed0000, 0x3019c68000000),
];

/// V · min(L · a · e^(b · mV + c) + V^1.2 · 16.5 · MHz · `n` / 10, 24800)
/// in mW, truncated; `leak` is L in Q30.
fn max_power_g15g(mv: u32, mhz: u32, n: u32, leak: u64) -> u32 {
    let clamp = 24800u64 << 30;
    let (_, a, b, c) = G15G_LEAK
        .iter()
        .rev()
        .find(|r| leak >= r.0 << 30)
        .unwrap_or(&G15G_LEAK[0]);
    let x = b * u64::from(mv.min(5000)) + c;
    let leakage = if x >= 9 << 48 {
        clamp
    } else {
        let la = (u128::from(leak) * u128::from(*a)) >> 48;
        ((la * u128::from(exp_q48(x))) >> 48).min(u128::from(clamp)) as u64
    };
    let dynamic = pow_1_2(mv) * 165 * u64::from(mhz) * u64::from(n) / 100;
    let p = u64::from(mv) * (leakage + dynamic).min(clamp) / 1000;
    (p >> 30) as u32
}

/// Builds tables A and B from `raw` (`apple,perf-states`) with the maps
/// `map` (table A's 16 entries, then table B's), each state with
/// `clusters` volts; table A's states carry their maximum power. `leak` is
/// the chip's leakage in Q30 (G15G's power uses it).
#[allow(clippy::too_many_arguments)]
pub(super) fn build(
    raw: &[u32],
    tables: u32,
    clusters: u32,
    dies: u32,
    map: &[u32; 32],
    id: &GpuIdConfig,
    csafr: Option<&CsAfrPwrConfig>,
    leak: u64,
) -> Result<(KVec<PState>, KVec<PState>)> {
    let tables = tables as usize;
    if tables == 0 || tables > 8 || raw.len() % (2 * tables) != 0 {
        return Err(EINVAL);
    }
    let count = raw.len() / (2 * tables);
    if !(2..=16).contains(&count) {
        return Err(EINVAL);
    }
    // Row i of table t, {Hz, mV}; a zero volt takes table 0's.
    let volt = |i: usize, m: usize| {
        let v = if m < tables {
            raw[2 * (m * count + i) + 1]
        } else {
            0
        };
        if v != 0 {
            v
        } else {
            raw[2 * i + 1]
        }
    };

    // Both tables start with state 0; MAP_A's first entry past the
    // source ends both.
    let mut rows_a = KVec::new();
    let mut rows_b = KVec::new();
    rows_a.push(0usize, GFP_KERNEL)?;
    rows_b.push(0usize, GFP_KERNEL)?;
    for j in 1..16 {
        let (a, b) = (map[j] as usize, map[16 + j] as usize);
        if a >= count {
            break;
        }
        if a != 0 {
            rows_a.push(a, GFP_KERNEL)?;
        }
        if b != 0 && b < count {
            rows_b.push(b, GFP_KERNEL)?;
        }
    }

    // The CS states' power per die (`populateMaximumPerformancePowerCS`),
    // scaled by die 0's CS mask (G15C: 37000 mW clamp, 11.7).
    let k = (id.num_clusters / dies.max(1)).max(1);
    let cs_power = |s: usize, d: usize| -> u32 {
        let Some(cs) = csafr.map(|c| &c.perf_states_cs) else {
            return 0;
        };
        let s = s.min(cs.len().saturating_sub(1));
        if s == 0 {
            return 0;
        }
        let ps = &cs[s];
        let mv = *ps.volt_mv.get(d).unwrap_or(&ps.volt_mv[0]);
        max_power(
            mv,
            ps.freq_hz / 1_000_000,
            117,
            id.g15_cs_mask.count_ones(),
            16,
            37000,
        )
    };

    let mut a = KVec::new();
    for (s, &i) in rows_a.iter().enumerate() {
        let mut volt_mv = KVec::new();
        let mut pwr_mw = 0u32;
        let mhz = raw[2 * i] / 1_000_000;
        for m in 0..clusters as usize {
            let mv = volt(i, m);
            volt_mv.push(mv, GFP_KERNEL)?;
            if s == 0 || m >= id.num_clusters as usize {
                continue;
            }
            // The cluster's enabled cores (`getEnabledNumUSCs`), 34000 mW
            // clamp, 19.9, and its share of the CS power; G15G's one
            // cluster its own formula.
            let n = id.core_masks.get(m).map_or(0, |c| c.count_ones());
            if id.gpu_variant == GpuVariant::G {
                pwr_mw += max_power_g15g(mv, mhz, n, leak);
                continue;
            }
            pwr_mw += max_power(mv, mhz, 199, n, 10, 34000);
            pwr_mw += cs_power(s, m / k as usize) / k;
        }
        a.push(
            PState {
                volt_mv,
                freq_hz: raw[2 * i],
                pwr_mw,
            },
            GFP_KERNEL,
        )?;
    }

    let mut b = KVec::new();
    for &i in rows_b.iter() {
        let mut volt_mv = KVec::new();
        for m in 0..clusters as usize {
            volt_mv.push(volt(i, m), GFP_KERNEL)?;
        }
        b.push(
            PState {
                volt_mv,
                freq_hz: raw[2 * i],
                pwr_mw: 0,
            },
            GFP_KERNEL,
        )?;
    }

    Ok((a, b))
}

/// Whether two tables have the same clocks, volts and power.
pub(super) fn same(x: &[PState], y: &[PState]) -> bool {
    x.len() == y.len()
        && x.iter().zip(y.iter()).all(|(p, q)| {
            p.freq_hz == q.freq_hz && p.pwr_mw == q.pwr_mw && p.volt_mv[..] == q.volt_mv[..]
        })
}
