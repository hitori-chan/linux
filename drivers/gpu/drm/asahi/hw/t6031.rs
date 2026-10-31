// SPDX-License-Identifier: GPL-2.0-only

//! Hardware configuration for t6031 platforms (M3 Max, 16 CPU and 40 GPU
//! cores, G15C; boards j514c and j516c). Not run: no such Mac.
//!
//! The same kext path as t6034's: `configureDevice` tests the chip ID once,
//! and for any G15C chip but 0x6034 takes eight MCache windows (mask 0xff)
//! where t6034 has six (spec: chip-config.md, mmio.md). The rest is
//! t6034's. The AON PTD rows come from the live ADT through m1n1
//! (`apple,ptd-data-table`), and the MTR sensor mask too
//! (`apple,mtr-sensor-mask`; without it t6034's, not verified).
use super::*;

pub(crate) const HWCONFIG: super::HwConfig = HwConfig {
    chip_id: 0x6031,
    g15_windows: Some(&WINDOWS),
    aon_ptd: &[],
    ..super::t6034::HWCONFIG
};

const WINDOWS: [G15Window; 31] = {
    let mut w = super::t6034::WINDOWS;
    // j=11 MCache registers: kind 8, the eight window PAs 0x220000000 +
    // i*0x2000000 (i = 0..7)
    w[11] = G15Window {
        flag: 1,
        kind: 8,
        base: 0x220000000,
        size: 0xd8000,
        pairs: &[
            0x222000000,
            0x224000000,
            0x226000000,
            0x228000000,
            0x22a000000,
            0x22c000000,
            0x22e000000,
        ],
    };
    w
};
