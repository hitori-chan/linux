// SPDX-License-Identifier: GPL-2.0-only

//! A counter session's packing, as 27.2's kext does it (`AGXG15C_272`,
//! ported as `gen.py --fw 272`): the partition table, the checks a counter
//! list passes, the event page's counter records ([`record`]) and the RDE
//! program's words ([`read_word`]). It uses `core` only, so that the same
//! file builds on a host and its bytes can be compared with `gen.py`'s.
//!
//! A counter is `[SRC@]PART:SELECT[:FLAG][/WIDTH]`: the source whose RDE
//! reads it (a name or an index; by default the first of RDE_0, BMPR_RDE_0,
//! APS_USC and Firmware that the partition allows, as `gen.py`), the
//! partition (a name or an index), the select, the plist's flag (2 and 4
//! select a TPU or PBE pixel format) and width A (default 32).
//!
//! A partition is read only from the sources its mask allows, as 27.2's
//! kext checks (a BMPR partition read through a GPU RDE is not traced).
//! Stricter than the kext: only the four RDE sources (the Firmware source's
//! selects write registers, and APS's firmware path is not traced), and a
//! period of at least `PERIOD_MIN`.

/// A partition of 27.2's table (`sPerfCtrPartitionInfoList_G15`,
/// `AGXG15C_272` 0xfffffe000cc388e0; 14.8.3's `sAGXPerfCtr_G15_*` after
/// `AGXPerfCtrSamplerGen11::init`, which leaves every instance count 1 on
/// this GPU, but for the DCDM and DCMP banks): its name, the sources it may
/// be read from (`1 << source`), its enable and bank registers (0: not
/// banked), and its slot count. Slot `i` selects at
/// `enable + 8 + 8 * i` and counts at `enable + 0x50 + 0x10 * i` (every
/// `sAGXPerfCtrRegList_G15_*`); Software, Global, Bmpr_Global and APS_USC
/// have no slot table.
pub(crate) struct Part {
    pub(crate) name: &'static str,
    pub(crate) mask: u8,
    pub(crate) enable: u32,
    pub(crate) bank: u32,
    pub(crate) count: u16,
    pub(crate) slots: bool,
}

const fn part(
    name: &'static str,
    mask: u8,
    enable: u32,
    bank: u32,
    count: u16,
    slots: bool,
) -> Part {
    Part {
        name,
        mask,
        enable,
        bank,
        count,
        slots,
    }
}

/// The 41 partitions, by index (the plist's `Partition`).
pub(crate) const PARTS: [Part; 41] = [
    part("SOFTWARE", 0x1, 0x0, 0x0, 32, false),
    part("GLOBAL", 0x7, 0x0, 0x0, 896, false),
    part("BMPR_GLOBAL", 0x19, 0x0, 0x0, 896, false),
    part("AFR_AXL", 0x18, 0x4a00, 0x0, 8, true),
    part("AFR_AXLNI", 0x18, 0x9900, 0x0, 8, true),
    part("AFR_MGPUNI", 0x18, 0x9d10, 0x0, 8, true),
    part("BMPR_MISC", 0x18, 0x5a50, 0x0, 8, true),
    part("CMP", 0x6, 0x13e08, 0x13e00, 4, true),
    part("DCDM", 0x6, 0x1a910, 0x1a900, 8, true),
    part("DCMP", 0x6, 0x13a08, 0x13a00, 8, true),
    part("DIPP", 0x6, 0x16500, 0x164f8, 8, true),
    part("DPWR_FRG", 0x6, 0x1ba10, 0x1ba00, 4, true),
    part("DPWR_USC_RIA", 0x6, 0x6e10, 0x6e00, 4, true),
    part("FRG0", 0x6, 0x15610, 0x15608, 8, true),
    part("FRG1", 0x6, 0x15710, 0x15608, 8, true),
    part("GCDM", 0x18, 0x1a610, 0x0, 8, true),
    part("GGTP", 0x18, 0x1cc08, 0x0, 8, true),
    part("GIPP", 0x18, 0x16200, 0x0, 8, true),
    part("GM_GL2C", 0x18, 0x18988, 0x18980, 8, true),
    part("GM_GMMU_GIF", 0x18, 0x19e08, 0x19e00, 4, true),
    part("GM_GMMU_NTLB", 0x18, 0xde10, 0xde00, 4, true),
    part("GM_GMMU_TWC", 0x18, 0x1ed08, 0x1ed00, 4, true),
    part("GM_MTH", 0x18, 0x14db0, 0x14da8, 8, true),
    part("GTP_CORE", 0x6, 0x1c238, 0x1c230, 8, true),
    part("GTP_GP", 0x6, 0x14a10, 0x14a00, 8, true),
    part("KSM", 0x18, 0xc178, 0x0, 4, true),
    part("KSM_RSM", 0x18, 0xcd78, 0x0, 4, true),
    part("PBE", 0x6, 0x13408, 0x13400, 4, true),
    part("SL1", 0x6, 0x1ae08, 0x1ae00, 8, true),
    part("SL2", 0x6, 0x1b208, 0x1b200, 8, true),
    part("TC", 0x6, 0x12e08, 0x12e00, 8, true),
    part("TMB_MGPU", 0x6, 0x1750, 0x0, 4, true),
    part("TPU", 0x6, 0x12408, 0x12400, 8, true),
    part("USC_GUPM", 0x18, 0x14108, 0x0, 8, true),
    part("USC_UMA_CORE", 0x6, 0xd508, 0xd500, 8, true),
    part("WDSB_AFR", 0x18, 0x6900, 0x0, 4, true),
    part("WDSB_GC_CTRL", 0x18, 0x6100, 0x0, 4, true),
    part("WDSB_GC_WORK", 0x18, 0x6300, 0x0, 4, true),
    part("WDSB_GM", 0x18, 0x6500, 0x0, 4, true),
    part("WDSB_MGPU", 0x6, 0x6700, 0x0, 4, true),
    part("APS_USC", 0x20, 0xa020, 0xa000, 64, false),
];

/// Partitions below this are register reads (Software, Global,
/// Bmpr_Global): width B is width A (GRC's rule).
const NGLOBAL: usize = 3;
/// The Global partition, whose record is a register read.
const GLOBAL: u8 = 1;

/// The registers a Global or Bmpr_Global read may name
/// (`sAllowedRegAddrList`), inclusive.
const ALLOWED: [(u64, u64); 11] = [
    (0x1660, 0x16d0),
    (0x1128, 0x1628),
    (0x1138, 0x1138),
    (0x6a18, 0x6a18),
    (0x6a08, 0x6a08),
    (0x5868, 0x5868),
    (0x5858, 0x5858),
    (0x7238, 0x7238),
    (0x7228, 0x7228),
    (0x1038, 0x1038),
    (0x1028, 0x1028),
];

/// The AGC's banked registers (`sAGCBankRegAddrList`), inclusive.
const AGC_BANK: [(u64, u64); 10] = [
    (0x7200, 0x72f8),
    (0x1000, 0x10f8),
    (0x9c00, 0x9ff8),
    (0x18800, 0x18bf8),
    (0x19c00, 0x19ff8),
    (0xd800, 0xdff8),
    (0x1ec00, 0x1eff8),
    (0x14c00, 0x14ff8),
    (0x6200, 0x63f8),
    (0x6400, 0x65f8),
];

/// The selects that stand for the n-th TPU and PBE pixel-format counter
/// (`sTPUFormatCounterSelects_G15`, `sPBEFormatCounterSelects_G15`).
const FMT: [&[u32]; 2] = [
    &[
        0x200f0f00, 0x200ff000, 0x2010000f, 0x201000f0, 0x20100f00, 0x2010f000, 0x2011000f,
        0x201100f0,
    ],
    &[0xa0100, 0xa0200, 0xa0400, 0xa0800],
];

/// The sources (`sPerfCtrSourceConfigList_G15`, `AGXG15C_272`
/// 0xfffffe000cc38a28; the index is the state's
/// type, the source's mask `1 << index`) and their RDE prologue's length
/// (`sPerfCtrSourceRDEHeaderCmdSeq*`, without the 16 timestamp words of
/// source flag 0x80).
pub(crate) const NSRC: usize = 6;
pub(crate) const SRC_NAMES: [&str; NSRC] = [
    "Firmware",
    "RDE_0",
    "RDE_1",
    "BMPR_RDE_0",
    "BMPR_RDE_1",
    "APS_USC",
];
pub(crate) const PROLOGUE: [usize; NSRC] = [0, 12, 12, 7, 7, 0];

/// A session's limits: the event page's 0x200 records, 0xE0 counters a
/// source and 0x100 program words.
pub(crate) const MAX_CMDS: usize = 0x200;
const MAX_LIST: usize = 0xE0;
pub(crate) const PROG_MAX: usize = 0x100;

/// Command 5's source flags: 0x40 (an RDE read is width B wide), which GRC
/// always sets.
pub(crate) const SRC_FLAGS: u32 = 0x40;

/// The period's floor and default, in ticks of the clock the RDE's timer
/// counts (mode 8): on RDE_0 the GPU's clock at its performance state (338
/// MHz under a light load, 1380 MHz at state 8), on BMPR_RDE_0 a fixed 850
/// MHz. Ours: the floor keeps a ring under ~350 k records a second even at
/// 1.4 GHz.
pub(crate) const PERIOD_MIN: u32 = 0x1000;
pub(crate) const PERIOD_DEFAULT: u32 = 0x10000;

/// The counter `start` takes when given none: a TPU counter.
pub(crate) const DEFAULT_SPEC: &str = "RDE_0@TPU:0x2002ffff/32";

/// The job stages whose job state carries range words, in `Session::range`'s
/// order: TA (+0x844, +0x848), 3D (+0xB8C, +0xB90) and CL (+0x7E4, +0x7E8).
pub(crate) const STAGES: [&str; 3] = ["ta", "3d", "cl"];
pub(crate) const TA: usize = 0;
pub(crate) const D3: usize = 1;
pub(crate) const CL: usize = 2;

/// A job's range words: the first and last batch its counters count. A
/// batch is a draw's (or dispatch's) index in its encoder (Metal's
/// `filterCounterRangeWithFirstBatch:lastBatch:`). The firmware clamps each
/// word to 0x3FFF and writes `lo | hi << 16` at the job's first marker (TA:
/// 0x10278 and 0x10048; 3D: 0x10048, and 0x15078 bit 4 = lo is 0, bit 5 = hi
/// is past 0x3FFE; CL: 0x1A4F0…0x1A508). This is Metal's default, every
/// batch: its contexts' init value.
pub(crate) const RANGE_ALL: (u32, u32) = (0, u32::MAX);

/// The PPP_CTRL bit the kext sets in a TA job's register list while the
/// sampler runs and the job's range is not `RANGE_ALL`
/// (`AGXTAChannelG15::generateRegisterList`). I: Rogue's `flush_mode`, which
/// keeps the end-of-draw flushes the batch numbers need.
pub(crate) const PPP_BATCH: u64 = 0x800;

/// Command 5's modes a source with counters runs in: `MODE_TIMER` (8) on its
/// RDE's timer, one record every `period` ticks; `MODE_KICK` (2) at each TA,
/// 3D and CL kick's start and end (the firmware arms the RDE's six kick
/// triggers, `agfHALPerfCtrSourceSamplerRDESetupTrigger`
/// `0xfffffc000002f1b0`), each record holding what was counted since the
/// one before, so a kick's end record holds what the kick counted.
pub(crate) const MODE_TIMER: u32 = 8;
pub(crate) const MODE_KICK: u32 = 2;

/// The encoder IDs a job's kick IDs carry while a kick-mode session or arm
/// is in effect (`kick_id`): a pass the pick or the selector keeps, and the
/// others. Neither is 0, which an unwritten kick-ID register reads.
pub(crate) const ENC_KEPT: u32 = 0x101;
pub(crate) const ENC_OTHER: u32 = 0x100;

/// A kick ID as the kext's register lists write it while its sampler runs
/// (the barrier triple, register-lists.md entries 69–71 and 79–81): the
/// job's ID and its encoder's, `u32 js+0x884 | u32 desc+0x6C4 << 32` for a
/// TA job. An RDE's record carries the kick's (its words 4–11).
pub(crate) const fn kick_id(id: u32, enc: u32) -> u64 {
    id as u64 | (enc as u64) << 32
}

/// What a render pass's TA or 3D job carries for the counters
/// (`g15_perf_pass`): its range words, whether its PPP_CTRL gets
/// `PPP_BATCH` (TA jobs only) and the encoder ID of the kick IDs its
/// register list writes, if it writes them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct JobWords {
    pub(crate) range: (u32, u32),
    pub(crate) batch: bool,
    pub(crate) enc: Option<u32>,
}

/// A job's words with no session: Metal's default range, no `PPP_BATCH`,
/// no kick IDs.
pub(crate) const JOB_DEFAULT: JobWords = JobWords {
    range: RANGE_ALL,
    batch: false,
    enc: None,
};

/// A stage's range words as one word, `lo | hi << 32`.
pub(crate) const fn range_pack(r: (u32, u32)) -> u64 {
    r.0 as u64 | (r.1 as u64) << 32
}

pub(crate) const fn range_unpack(w: u64) -> (u32, u32) {
    (w as u32, (w >> 32) as u32)
}

/// A session's `pick=M:K` and the render pass ID it counts from, as one word:
/// M in bits 0–15 (0: no pick), K in 16–31, the ID in 32–63.
pub(crate) const fn pick_pack(pick: (u16, u16), first: u32) -> u64 {
    pick.0 as u64 | (pick.1 as u64) << 16 | (first as u64) << 32
}

/// Whether `pick` (`pick_pack`) keeps the render pass whose ID is `id` (two
/// IDs a pass, the 3D job's first): pass n from the session's first, kept
/// when n % M is K.
pub(crate) const fn picked(pick: u64, id: u32) -> bool {
    let m = (pick & 0xFFFF) as u32;
    if m == 0 {
        return false;
    }
    let k = ((pick >> 16) & 0xFFFF) as u32;
    (id.wrapping_sub((pick >> 32) as u32) / 2) % m == k
}

/// The longest fragment attachment list a render command takes
/// (`G15_SLC_RANGES`, as Metal sends at most).
pub(crate) const MAX_ATTS: u64 = 16;

/// A render pass as a pass selector sees it (`g15_perf_pass`): its fragment
/// attachment list's length (`DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS`, 0 with
/// none), its framebuffer's size and its ZLS control word.
#[derive(Clone, Copy)]
pub(crate) struct PassKey {
    pub(crate) atts: u32,
    pub(crate) w: u32,
    pub(crate) h: u32,
    pub(crate) zls: u64,
}

/// The pass selector's tests: `pickatt=N` (the attachment count),
/// `picksize=WxH` (decimal) and `pickzls=MASK:VAL` (the ZLS word's low 32
/// bits under MASK equal VAL). A pass is kept when it passes every test
/// asked.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Sel {
    pub(crate) atts: Option<u8>,
    pub(crate) size: Option<(u16, u16)>,
    /// (MASK, VAL); MASK 0: no test.
    pub(crate) zls: (u32, u32),
}

const SEL_ATTS: u64 = 1 << 62;
const SEL_SIZE: u64 = 1 << 63;

/// A selector as two words: the count in bits 0–7, W in 16–31, H in 32–47
/// and which of the two are asked (`SEL_ATTS`, `SEL_SIZE`); then MASK |
/// VAL << 32. Both 0: no selector.
pub(crate) const fn sel_pack(s: Sel) -> [u64; 2] {
    let mut w = 0;
    if let Some(n) = s.atts {
        w |= SEL_ATTS | n as u64;
    }
    if let Some((x, y)) = s.size {
        w |= SEL_SIZE | (x as u64) << 16 | (y as u64) << 32;
    }
    [w, s.zls.0 as u64 | (s.zls.1 as u64) << 32]
}

pub(crate) const fn sel_unpack(w: [u64; 2]) -> Sel {
    Sel {
        atts: if w[0] & SEL_ATTS != 0 {
            Some(w[0] as u8)
        } else {
            None
        },
        size: if w[0] & SEL_SIZE != 0 {
            Some(((w[0] >> 16) as u16, (w[0] >> 32) as u16))
        } else {
            None
        },
        zls: (w[1] as u32, (w[1] >> 32) as u32),
    }
}

/// Whether `w` (`sel_pack`) asks any test.
pub(crate) const fn sel_active(w: [u64; 2]) -> bool {
    w[0] & (SEL_ATTS | SEL_SIZE) != 0 || w[1] as u32 != 0
}

/// Whether the pass `k` passes every test `w` (`sel_pack`) asks.
pub(crate) const fn sel_match(w: [u64; 2], k: &PassKey) -> bool {
    (w[0] & SEL_ATTS == 0 || k.atts == (w[0] & 0xFF) as u32)
        && (w[0] & SEL_SIZE == 0
            || (k.w == ((w[0] >> 16) & 0xFFFF) as u32 && k.h == ((w[0] >> 32) & 0xFFFF) as u32))
        && (k.zls as u32) & (w[1] as u32) == (w[1] >> 32) as u32
}

/// Whether a session keeps the render pass `id` (`picked`'s ID), `k`: the
/// selector's tests when it has one, else `pick`'s.
pub(crate) const fn pass_kept(pick: u64, sel: [u64; 2], id: u32, k: &PassKey) -> bool {
    if sel_active(sel) {
        sel_match(sel, k)
    } else {
        picked(pick, id)
    }
}

/// A render pass's TA and 3D range words: the session's (`ta`, `d3`:
/// `range_pack`), or the kept words (`keep`, `RANGE_ALL` unless a `keep=`
/// token set others) for a pass it keeps (`pass_kept`).
pub(crate) const fn pass_range(ta: u64, d3: u64, keep: u64, kept: bool) -> [(u32, u32); 2] {
    if kept {
        [range_unpack(keep); 2]
    } else {
        [range_unpack(ta), range_unpack(d3)]
    }
}

/// A render pass's TA and 3D job words (`JobWords`): the range words
/// `pass_range` gives; on the TA job `PPP_BATCH` when its words are not
/// `RANGE_ALL`, as the kext's, or when the pass is kept and `keep_batch`
/// asks it; the kick IDs' encoder ID when `kick` (a kick-mode session or
/// arm in effect), `ENC_KEPT` on a kept pass.
pub(crate) const fn pass_words(
    ta: u64,
    d3: u64,
    keep: u64,
    kept: bool,
    keep_batch: bool,
    kick: bool,
) -> [JobWords; 2] {
    let [rt, rd] = pass_range(ta, d3, keep, kept);
    let enc = if !kick {
        None
    } else if kept {
        Some(ENC_KEPT)
    } else {
        Some(ENC_OTHER)
    };
    [
        JobWords {
            range: rt,
            batch: !is_all(rt) || (kept && keep_batch),
            enc,
        },
        JobWords {
            range: rd,
            batch: false,
            enc,
        },
    ]
}

/// Whether `r` is `RANGE_ALL`.
pub(crate) const fn is_all(r: (u32, u32)) -> bool {
    r.0 == RANGE_ALL.0 && r.1 == RANGE_ALL.1
}

/// PPP_CTRL for a TA job: `base`, with `PPP_BATCH` when `batch`
/// (`JobWords::batch`).
pub(crate) const fn ppp_ctrl(base: u64, batch: bool) -> u64 {
    if batch {
        base | PPP_BATCH
    } else {
        base
    }
}

/// `LO:HI`, two u32s.
fn range_tok(v: &str) -> Option<(u32, u32)> {
    let (lo, hi) = v.split_once(':')?;
    Some((u32::try_from(num(lo)?).ok()?, u32::try_from(num(hi)?).ok()?))
}

/// A counter of a session: the kext's list entry (`PerfCtrCommandGen11`),
/// less the plist's flag, which `Session::add` reads (2 and 4) but for its
/// bit 0x20 ([`Ctr::bank0`]).
#[derive(Clone, Copy, Default)]
pub(crate) struct Ctr {
    /// The select, after a pixel-format counter's replacement.
    pub(crate) select: u64,
    pub(crate) src: u8,
    pub(crate) part: u8,
    /// The first slot (the partition's count before it).
    pub(crate) slot: u16,
    /// Widths A and B, in bits.
    pub(crate) wa: u8,
    pub(crate) wb: u8,
    /// The index in its source's list.
    pub(crate) idx: u8,
    /// The flag's 0x20: the counter is read from bank 0, not 3
    /// ([`read_word`]).
    pub(crate) bank0: bool,
}

/// Why a counter list was refused.
pub(crate) type Refusal = &'static str;

fn num(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn in_ranges(r: &[(u64, u64)], v: u64) -> bool {
    r.iter().any(|&(lo, hi)| lo <= v && v <= hi)
}

/// A source by name or index.
pub(crate) fn source(s: &str) -> Option<usize> {
    match num(s) {
        Some(i) if (i as usize) < NSRC => Some(i as usize),
        Some(_) => None,
        None => SRC_NAMES.iter().position(|n| n.eq_ignore_ascii_case(s)),
    }
}

/// A partition by name or index (an index past the table is refused by
/// `Session::add`, as the kext refuses it).
fn part_index(s: &str) -> Option<usize> {
    if s.as_bytes().first()?.is_ascii_digit() {
        num(s).map(|i| i.min(usize::MAX as u64) as usize)
    } else {
        PARTS.iter().position(|p| p.name.eq_ignore_ascii_case(s))
    }
}

/// The first source the partition allows, in `gen.py`'s order: RDE_0,
/// BMPR_RDE_0, APS_USC, then the Firmware source.
fn default_source(part: usize) -> Result<usize, Refusal> {
    let m = PARTS.get(part).ok_or("no such partition")?.mask;
    [2u8, 8, 0x20, 1]
        .iter()
        .find(|&&want| m & want != 0)
        .map(|&want| want.trailing_zeros() as usize)
        .ok_or("the partition has no source")
}

/// Slot `i`'s select and counter registers.
fn slot_regs(p: &Part, i: u16) -> (u32, u32) {
    let i = u32::from(i);
    (p.enable + 8 + 8 * i, p.enable + 0x50 + 0x10 * i)
}

/// A session being built: the counters in the order they were added, and
/// what the kext keeps beside them.
pub(crate) struct Session<'a> {
    ctrs: &'a mut [Ctr],
    n: usize,
    /// Each partition's slots taken, by every source (the kext's
    /// `running`, session-wide).
    running: [u16; PARTS.len()],
    /// Each source's list length.
    lists: [u16; NSRC],
    /// The TPU and PBE pixel formats: how many, and the value (a select a
    /// byte) of the event page's +0x4210 and +0x4258 selects.
    fmt: [(u32, u64); 2],
    /// Command 5's period, for every source with counters.
    pub(crate) period: u32,
    /// The range words of the jobs built while the session runs, a stage
    /// (`STAGES`).
    pub(crate) range: [(u32, u32); 3],
    /// `pick=M:K` (M 0: none): one render pass in M, the K-th, carries
    /// `RANGE_ALL` on TA and 3D; every other pass the TA and 3D words.
    pub(crate) pick: (u16, u16),
    /// The pass selector (`pickatt=`, `picksize=`, `pickzls=`): the passes
    /// it keeps carry `RANGE_ALL` on TA and 3D, every other the TA and 3D
    /// words. With no range it gates nothing and only counts them.
    pub(crate) sel: Sel,
    /// The GPU RDEs' mode (`mode=kick` or `mode=timer`): `MODE_TIMER` or
    /// `MODE_KICK`. The BMPR RDEs stay on their timer: their kick records
    /// read the memory side's latched window, not the kick (gpuprof.md §2).
    pub(crate) mode: u32,
    /// The words a kept pass carries on TA and 3D (`keep=LO:HI`,
    /// `RANGE_ALL` unless given), and whether its TA job gets `PPP_BATCH`
    /// with them too (`keepbatch=1`; the kext sets it only with words other
    /// than `RANGE_ALL`).
    pub(crate) keep: (u32, u32),
    pub(crate) keep_batch: bool,
}

impl<'a> Session<'a> {
    /// An empty session over `ctrs`, which holds at most `MAX_CMDS`.
    pub(crate) fn new(ctrs: &'a mut [Ctr]) -> Self {
        Session {
            ctrs,
            n: 0,
            running: [0; PARTS.len()],
            lists: [0; NSRC],
            fmt: [(0, 0); 2],
            period: PERIOD_DEFAULT,
            range: [RANGE_ALL; 3],
            pick: (0, 0),
            sel: Sel::default(),
            mode: MODE_TIMER,
            keep: RANGE_ALL,
            keep_batch: false,
        }
    }

    /// Parses `start`'s arguments: `period=N`, `src=SRC` (the source of the
    /// counters after it that name none), the range words (`range=LO:HI` for
    /// every stage, `rangeta=`, `range3d=`, `rangecl=` for one; later tokens
    /// win), `pick=M:K`, the pass selector (`pickatt=N`, `picksize=WxH`,
    /// `pickzls=MASK:VAL`; not with `pick`), a kept pass's words (`keep=LO:HI`,
    /// `keepbatch=0|1`; with a pick or a selector), the GPU RDEs' mode
    /// (`mode=kick|timer`) and counters. With no counter, the default one
    /// (`DEFAULT_SPEC`). Fails with the token and the reason.
    pub(crate) fn parse<'l>(&mut self, args: &'l str) -> Result<(), (&'l str, Refusal)> {
        let mut dflt = None;
        let mut any = false;
        let mut pick_tok = None;
        let mut sel_tok = None;
        let mut keep_tok = None;
        for tok in args.split_ascii_whitespace() {
            let stage = match tok.split_once('=') {
                Some(("range", v)) => Some((0..STAGES.len(), v)),
                Some((k, v)) => k
                    .strip_prefix("range")
                    .and_then(|s| STAGES.iter().position(|&n| n == s))
                    .map(|i| (i..i + 1, v)),
                None => None,
            };
            if let Some((stages, v)) = stage {
                let r = range_tok(v).ok_or((tok, "a range is LO:HI, two u32s"))?;
                for i in stages {
                    self.range[i] = r;
                }
            } else if let Some(v) = tok.strip_prefix("pick=") {
                let (m, k) = range_tok(v).ok_or((tok, "pick is M:K"))?;
                if !(2..=0xFFFF).contains(&m) || k >= m {
                    return Err((tok, "pick needs 2 <= M <= 0xffff and K < M"));
                }
                self.pick = (m as u16, k as u16);
                pick_tok = Some(tok);
            } else if let Some(v) = tok.strip_prefix("pickatt=") {
                match num(v) {
                    Some(n) if n <= MAX_ATTS => self.sel.atts = Some(n as u8),
                    _ => return Err((tok, "pickatt needs N <= 16")),
                }
                sel_tok = Some(tok);
            } else if let Some(v) = tok.strip_prefix("picksize=") {
                // Decimal: a hex prefix's x would split it.
                let wh = v
                    .split_once('x')
                    .and_then(|(w, h)| Some((w.parse::<u16>().ok()?, h.parse::<u16>().ok()?)));
                match wh {
                    Some((w, h)) if w != 0 && h != 0 => self.sel.size = Some((w, h)),
                    _ => return Err((tok, "picksize is WxH in decimal, each 1..=65535")),
                }
                sel_tok = Some(tok);
            } else if let Some(v) = tok.strip_prefix("pickzls=") {
                match range_tok(v) {
                    Some((m, x)) if m != 0 && x & !m == 0 => self.sel.zls = (m, x),
                    _ => return Err((tok, "pickzls is MASK:VAL, MASK not 0, VAL within it")),
                }
                sel_tok = Some(tok);
            } else if let Some(v) = tok.strip_prefix("mode=") {
                self.mode = match v {
                    "kick" => MODE_KICK,
                    "timer" => MODE_TIMER,
                    _ => return Err((tok, "mode is kick or timer")),
                };
            } else if let Some(v) = tok.strip_prefix("keep=") {
                self.keep = range_tok(v).ok_or((tok, "keep is LO:HI, two u32s"))?;
                keep_tok = Some(tok);
            } else if let Some(v) = tok.strip_prefix("keepbatch=") {
                self.keep_batch = match v {
                    "1" => true,
                    "0" => false,
                    _ => return Err((tok, "keepbatch is 0 or 1")),
                };
                keep_tok = Some(tok);
            } else if let Some(v) = tok.strip_prefix("src=") {
                dflt = Some(source(v).ok_or((tok, "no such source"))?);
            } else if let Some(v) = tok.strip_prefix("period=") {
                let p = num(v).ok_or((tok, "the period is not a number"))?;
                if p < u64::from(PERIOD_MIN) || p > u64::from(u32::MAX) {
                    return Err((tok, "the period is out of 0x1000..=0xffffffff"));
                }
                self.period = p as u32;
            } else {
                self.spec(tok, dflt).map_err(|e| (tok, e))?;
                any = true;
            }
        }
        if !any {
            self.spec(DEFAULT_SPEC, None)
                .map_err(|e| (DEFAULT_SPEC, e))?;
        }
        if let Some(tok) = pick_tok {
            if sel_tok.is_some() {
                return Err((tok, "pick and the pass selector are exclusive"));
            }
            if self.range[TA] == RANGE_ALL && self.range[D3] == RANGE_ALL {
                return Err((tok, "pick with no TA or 3D range: every pass counts"));
            }
        }
        if let Some(tok) = keep_tok {
            if pick_tok.is_none() && sel_tok.is_none() {
                return Err((tok, "keep and keepbatch need a pick or a pass selector"));
            }
        }
        self.check().map_err(|e| ("start", e))
    }

    /// One counter, `[SRC@]PART:SELECT[:FLAG][/WIDTH]`.
    fn spec(&mut self, tok: &str, dflt: Option<usize>) -> Result<(), Refusal> {
        let (src, rest) = match tok.split_once('@') {
            Some((s, r)) => (Some(source(s).ok_or("no such source")?), r),
            None => (dflt, tok),
        };
        let (rest, wa) = match rest.rsplit_once('/') {
            Some((r, w)) => (r, num(w).ok_or("the width is not a number")?),
            None => (rest, 32),
        };
        let mut f = rest.split(':');
        let part = part_index(f.next().unwrap_or("")).ok_or("no such partition")?;
        let select = num(f.next().ok_or("no select")?).ok_or("the select is not a number")?;
        let flags = match f.next() {
            Some(x) => num(x).ok_or("the flag is not a number")?,
            None => 0,
        };
        if f.next().is_some() {
            return Err("more than PART:SELECT:FLAG");
        }
        if part >= PARTS.len() {
            return Err("no such partition");
        }
        let src = match src {
            Some(s) => s,
            None => default_source(part)?,
        };
        let flags = u32::try_from(flags).map_err(|_| "the flag is past 32 bits")?;
        // Past 0xFF it fails the width check.
        let wa = wa.min(0xFF) as u32;
        self.add(src, part, select, flags, wa)
    }

    /// A pixel-format counter (`AGXPerfCtrSamplerGen15::addSelectedCounter`,
    /// `AGXG15C_272` 0xfffffe0008bd5d0c): the select goes into the n-th byte
    /// of the format's value, and the n-th format select stands for it.
    fn pixfmt(&mut self, k: usize, select: u64) -> Result<u64, Refusal> {
        let (n, v) = self.fmt[k];
        if n as usize >= FMT[k].len() || select > 0xFF {
            return Err("a pixel-format select past the table or 0xff");
        }
        self.fmt[k] = (n + 1, v | select << ((8 * (n & 0xFF)) & 63));
        Ok(u64::from(FMT[k][n as usize]))
    }

    /// Adds a counter (`gen.py`'s `add`, `_gen15_add` and `_cmd_add`:
    /// `PerfCtrCommandGen11::addSelectedCounter`), with this file's stricter
    /// checks.
    fn add(
        &mut self,
        s: usize,
        part: usize,
        select: u64,
        flags: u32,
        wa: u32,
    ) -> Result<(), Refusal> {
        let (mut wa, mut wb) = (wa, wa);
        if part == 0 {
            (wa, wb) = (0x40, 0x40);
        } else if wa != 0x40 && part >= NGLOBAL {
            wb = wa + 16;
        }
        let mut select = select;
        if flags & 2 != 0 {
            select = self.pixfmt(0, select)?;
        }
        if flags & 4 != 0 {
            select = self.pixfmt(1, select)?;
        }
        if self.n >= MAX_CMDS.min(self.ctrs.len()) {
            return Err("0x200 counters");
        }
        if s >= NSRC {
            return Err("no such source");
        }
        if s == 0 {
            return Err("the Firmware source is not driven");
        }
        if s == NSRC - 1 {
            return Err("APS_USC is not driven: its firmware path is not traced");
        }
        let n = self.lists[s] as usize;
        if n > MAX_LIST - 1 {
            return Err("the source's list is full (0xe0)");
        }
        let p = PARTS.get(part).ok_or("no such partition")?;
        if p.mask & (1 << s) == 0 {
            return Err("the partition is not on this source");
        }
        if part != 0 {
            if part < NGLOBAL {
                let kind = select >> 60;
                // A kind-4 read's whole register field, bits 0-14, as the
                // kext checks it (`addSelectedCounter` 0xfffffe0008bd5d0c).
                let off = if kind == 4 {
                    8 * (select & 0x7FFF)
                } else {
                    select & 0xFFFFF
                };
                if !matches!(kind, 0 | 3 | 4) {
                    return Err("a register read of kind other than 0, 3 or 4");
                }
                if !in_ranges(&ALLOWED, off) {
                    return Err("a register off sAllowedRegAddrList");
                }
            }
        } else if s != 0 {
            return Err("Software counters only on the Firmware source");
        }
        for w in [wa, wb] {
            if !(1..=0x40).contains(&w) || w & 0xF != 0 {
                return Err("a width other than 16, 32, 48 or 64");
            }
        }
        let slot = self.running[part];
        let new = u32::from(slot) + (wa >> 4);
        if new > u32::from(p.count) {
            return Err("the partition's slots are taken");
        }
        self.ctrs[self.n] = Ctr {
            select,
            src: s as u8,
            part: part as u8,
            slot,
            wa: wa as u8,
            wb: wb as u8,
            idx: n as u8,
            bank0: flags & 0x20 != 0,
        };
        self.n += 1;
        self.lists[s] += 1;
        self.running[part] = new as u16;
        Ok(())
    }

    /// The commit's checks (`gen.py`'s `commit`, `_rde_program`): each
    /// program within 0x100 words. (A read kind the program refuses, and
    /// source flag 1, never get here.)
    fn check(&self) -> Result<(), Refusal> {
        for s in 0..NSRC {
            if self.lists[s] != 0 && PROLOGUE[s] + self.lists[s] as usize > PROG_MAX {
                return Err("a program past 0x100 words");
            }
        }
        Ok(())
    }

    /// The counters, in the order they were added.
    pub(crate) fn counters(&self) -> &[Ctr] {
        &self.ctrs[..self.n]
    }

    /// Source `s`'s counters.
    pub(crate) fn count(&self, s: usize) -> usize {
        self.lists[s] as usize
    }

    /// Whether source `s` reads a partition past 2 (state +0xF4).
    pub(crate) fn anypart(&self, s: usize) -> bool {
        self.counters()
            .iter()
            .any(|c| c.src as usize == s && c.part as usize >= NGLOBAL)
    }

    /// The TPU (0) or PBE (1) pixel-format value.
    pub(crate) fn fmt(&self, k: usize) -> u64 {
        self.fmt[k].1
    }

    /// The bytes of the TPU (0) or PBE (1) pixel-format value its counters
    /// set: the mask the firmware writes the value under
    /// (`AGXPerfCtrSamplerGen15::addSelectedCounter`, `AGXG15C_272`
    /// 0xfffffe0008bd5d0c: `0xFF << 8 * n` for the n-th).
    pub(crate) fn fmt_mask(&self, k: usize) -> u64 {
        match self.fmt[k].0 {
            0 => 0,
            n if n >= 8 => u64::MAX,
            n => (1u64 << (8 * n)) - 1,
        }
    }
}

/// A Global read's record: +0 1, +8 the select, +0x10 the index.
fn global_record(c: &Ctr) -> [u8; 0x20] {
    let mut r = [0u8; 0x20];
    r[0] = 1;
    r[8..0x10].copy_from_slice(&c.select.to_le_bytes());
    r[0x10] = c.idx;
    r
}

/// A counter's enable and disable words (with its slots' bits) and its
/// first slot's select and counter registers.
fn record_words(c: &Ctr) -> (u32, u32, u32, u32) {
    let p = &PARTS[c.part as usize];
    // Source flag 0x100 would set 0xFF000000 in the enable word.
    let (mut en, mut dis) = (1u32, 0xFF00_1803u32);
    if c.wa >= 0x10 {
        let mut bits = 0u32;
        for i in 0..u32::from(c.wa >> 4) {
            let b = u32::from(c.slot) + 2 + i;
            if b < 32 {
                bits |= 1 << b;
            }
        }
        en |= bits;
        dis |= bits;
    }
    let (sel, ctr) = if p.slots {
        slot_regs(p, c.slot)
    } else {
        (0, 0)
    };
    (en, dis, sel, ctr)
}

/// A counter's event-page record
/// (`PerfCtrCommandGen11::generatePerfCtrCommandList`, `AGXG15C_272`
/// 0xfffffe0008bd3004; read by `armfw_g15c_272` `sub_FFFFFC00000273F0`):
/// +0 the partition | the enable register >> 2 << 8, +4 the first slot's
/// select and +8 counter registers, +0xC the enable and +0x10 the disable
/// words, +0x14 the select, +0x18 the bank register, +0x1C the instances,
/// +0x1D the slots, +0x1E the index. A Global read's is `global_record`.
pub(crate) fn record(c: &Ctr) -> [u8; 0x20] {
    if c.part == GLOBAL {
        return global_record(c);
    }
    let mut r = [0u8; 0x20];
    let p = &PARTS[c.part as usize];
    let (en, dis, sel, ctr) = record_words(c);
    let w0 = u32::from(c.part) | (p.enable >> 2) << 8;
    r[0..4].copy_from_slice(&w0.to_le_bytes());
    r[4..8].copy_from_slice(&sel.to_le_bytes());
    r[8..0xC].copy_from_slice(&ctr.to_le_bytes());
    r[0xC..0x10].copy_from_slice(&en.to_le_bytes());
    r[0x10..0x14].copy_from_slice(&dis.to_le_bytes());
    r[0x14..0x18].copy_from_slice(&(c.select as u32).to_le_bytes());
    r[0x18..0x1C].copy_from_slice(&p.bank.to_le_bytes());
    r[0x1C] = 1;
    r[0x1D] = c.wa >> 4;
    r[0x1E] = c.idx;
    r
}

/// A counter's RDE program word (`AGXPerfCtrSamplerGen11::
/// commitSourceCounterList`'s RDE branch, `AGXG15C_272` 0xfffffe0008bd3824,
/// its LABEL_64 block for reads of kinds 0, 1 and 3 and a partition's slot,
/// packed by `AGXPerfCtrRDECommand::pack` 0xfffffe0008bc0ed8; source flag
/// 0x40): bits 0–14 the register >> 3, 16–17 width B / 16 (0 for 64 bits),
/// 18–21 the sub-index; for a banked read bit 35 and the bank at 27–34, 3,
/// or 0 with counter flag 0x20; a BMPR partition's word also bit 40 when
/// banked, the bank at 41–42 on every read, and bit 43 for an AGC bank
/// register. A Global read of kind 4 goes through `unpack`
/// (0xfffffe0008bc0e34) and `pack`: the select's fields, the width replaced.
pub(crate) fn read_word(c: &Ctr) -> u64 {
    /// `pack`'s fields: bits 15, 36-39, 44, 47 and 50-63 are dropped.
    const FIELDS: u64 = 0x0003_6F0F_FFFF_7FFF;
    let p = &PARTS[c.part as usize];
    let w = (u64::from(c.wb) >> 4) & 3;
    let sel = c.select;
    let (reg, sub, banked);
    if c.part as usize >= NGLOBAL {
        reg = if p.slots {
            u64::from(slot_regs(p, c.slot).1)
        } else {
            0
        };
        sub = 0;
        banked = p.bank != 0;
    } else {
        let kind = sel >> 60;
        if kind == 4 {
            return sel & FIELDS & !0x3_0000 | w << 16;
        }
        // Kind 0 or 3: `Session::add` refuses the others.
        reg = sel & 0xFFFFF;
        banked = kind == 1 || kind == 3;
        sub = if kind == 3 { (sel >> 44) & 0xF } else { 0 };
    }
    let bk: u64 = if c.bank0 { 0 } else { 3 };
    let mut word = (reg >> 3) & 0x7FFF | w << 16 | sub << 18;
    if banked {
        word |= bk << 27 | 1 << 35;
    }
    if p.mask & 0x18 != 0 {
        word |= u64::from(banked) << 40 | bk << 41;
        if in_ranges(&AGC_BANK, reg) {
            word |= 1 << 43;
        }
    }
    word
}
