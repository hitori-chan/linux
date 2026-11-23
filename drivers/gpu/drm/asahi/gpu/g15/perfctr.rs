// SPDX-License-Identifier: GPL-2.0-only

//! G15 hardware performance counters through the 14.8.3 and 27.2
//! firmwares, for the hardware tests (`asahi.perfctr=1`).
//!
//! The host describes a session in the event page's perf area
//! ([`fw::g15::PerfArea`] on 14.8.3; 27.2 moves its fields past the core
//! layout, [`PerfLay`]): the counter records, one source state per
//! sampling source (the Firmware source, RDE_0 and RDE_1, the two BMPR
//! RDEs, APS), one sampler state per ring and a sample cache, all
//! firmware-visible. Device control 4 starts it: the firmware programs each
//! source whose sampler states all have a ring, and sets the running word
//! (+0x4030; 27.2 +0x4040) if one did. The first type-4 stream marker with
//! bit 31 after it programs the counters and enables the RDEs, which from
//! then on write a record into their rings at each trigger; every later
//! one writes only the job's range words. Device control 5 stops it and
//! clears the running word; a GPU recovery ends it by itself, without one.
//! While that word is set the firmware rereads the area at every power-up,
//! marker and perf-thread pass, so nothing it points at is freed until it
//! reads 0.
//!
//! The session memory is allocated at probe and kept. debugfs
//! `asahi/perfctr` starts and stops one session: `start [period=N]
//! [mode=kick|timer] [src=SRC] [range=LO:HI] [rangeta=|range3d=|rangecl=LO:HI]
//! [pick=M:K] [pickatt=N] [picksize=WxH] [pickzls=MASK:VAL] [keep=LO:HI]
//! [keepbatch=0|1] COUNTER...` packs the counters as the firmware's kext
//! does ([`pack`]) and samples every source with counters on its RDE's timer
//! (mode 8, every `N` ticks of the timer's clock) or, with `mode=kick`, the
//! GPU RDEs at each kick's start and end (mode 2; the BMPR RDEs stay on
//! their timer), into its rings in a VM of the driver's own, under that
//! VM's context ID; `stop` ends it. Its reads print the session
//! as the firmware sees it and each ring's first 0x200 bytes;
//! `asahi/perfctr_rings` holds the rings whole.
//!
//! The range words: every job built while a session runs carries its
//! stage's words in its job state ([`pack::RANGE_ALL`], Metal's default,
//! unless a range token set others), and a TA job whose words are not that
//! default also PPP_CTRL's [`pack::PPP_BATCH`], as the kext's. The firmware
//! writes a job's words into the counters' batch filter at its first marker.
//! With `pick=M:K` one render pass in M carries the default and the others
//! the session's TA and 3D words, so that only that pass counts. The pass
//! selector does the same for the passes whose fragment attachment list has
//! N entries (`pickatt=N`), whose framebuffer is W×H (`picksize=WxH`) and
//! whose ZLS control word's bits under MASK are VAL (`pickzls=MASK:VAL`),
//! the tests asked; with no range it only counts them. A kept pass carries
//! `keep=`'s words in place of the default, and with `keepbatch=1` its TA
//! job gets `PPP_BATCH` too. While a `mode=kick` session or arm is in effect
//! every TA and 3D job's register list also writes its kick IDs (the job's ID
//! and an encoder ID, [`pack::ENC_KEPT`] on a kept pass), as the kext's do
//! while its sampler runs, so that a kick record names its pass. A start
//! sets the words for the jobs built after it, so the jobs it finds in
//! flight carry the default and count whole: `arm` with the same tokens
//! sets them earlier, with no session. The TA and 3D markers share
//! register 0x10048: a TA marker that lands while an earlier pass's 3D job
//! runs sets that job's filter too, which a render with the vertex overlap
//! (`DRM_ASAHI_RENDER_OVERLAP_VERTEX`) allows; the read counts those
//! passes.
//!
//! A record holds the prologue's reads, 8 bytes each (the stamp
//! 0xFEEDCBA987654321, the status, the n-clock, the timer clock and the
//! kick IDs), then the counters in the order given, each packed at its read
//! width B (width A + 16 bits: 6 bytes for a 32-bit counter), the record
//! rounded up to 16 bytes (#673, #674: the stamps' spacing). An RDE does
//! not wait for the host's read pointer: an undrained ring wraps (I: build
//! 1's write pointers). A kick record's status (word 1) names its event in
//! bits 32–37 (CL start, CL end, TA start, TA end, 3D start, 3D end) and
//! its kick slot in bits 16–21; its kick ID is the word at 4 (TA), 6 (3D) or
//! 9 (CL) plus the slot (`AGXPerfCtrRDESampleHeaderParser::parse`, 14.8.3
//! `0xfffffe0008ea3e78`).
//!
//! What 27.2 changes ([`LAY_272`]): the perf area's fields past the core
//! layout, the source state (0x938 bytes: its config 0xE0, the fields after
//! it +8, a byte at +0xF0, the program +0x18), the counter records
//! ([`pack::record_272`]), two partitions' banks ([`pack::bank`]), the TPU
//! and PBE formats (masked triples) and the CL job's range words
//! (`JobCommon::perf_range`). The markers, the sampler states, the RDE
//! program words and prologues, the registers and the kick IDs are
//! 14.8.3's.
//!
//! Spec: stream.md (the marker), perf-counters.md (the perf area).

mod pack;

use super::*;
use core::mem::ManuallyDrop;
use kernel::{fmt, fs::file::Offset, uaccess::UserSliceWriter};
use pack::{
    is_all, pass_kept, pass_words, pick_pack, range_pack, range_unpack, read_word, record,
    sel_pack, sel_unpack, PassKey, Session, CL, D3, MAX_ATTS, MAX_CMDS, MODE_KICK, MODE_TIMER,
    NSRC, PARTS, PROLOGUE, SRC_FLAGS, SRC_NAMES, STAGES, TA,
};
pub(super) use pack::{kick_id, ppp_ctrl, JobWords, JOB_DEFAULT, RANGE_ALL};

/// A pass selector (`pack::sel_pack`) as the debugfs read and the log print
/// it: `att N size WxH zls MASK:VAL`, `-` for a test not asked.
struct SelFmt([u64; 2]);

impl core::fmt::Display for SelFmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = sel_unpack(self.0);
        match s.atts {
            Some(n) => write!(f, "att {n}")?,
            None => write!(f, "att -")?,
        }
        match s.size {
            Some((w, h)) => write!(f, " size {w}x{h}")?,
            None => write!(f, " size -")?,
        }
        match s.zls {
            (0, _) => write!(f, " zls -"),
            (m, v) => write!(f, " zls {m:#x}:{v:#x}"),
        }
    }
}

// The log's macros take the kernel's trait.
impl fmt::Display for SelFmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

/// A type-4 perf marker's size: `{u32 0x4 | bit 31 for the first | class
/// << 27, u32 the encoder ID, u32 the job ID, u64 the job state}`.
pub(super) const PERF_MARKER: usize = 0x14;

/// A stream's slot size (job state `+0x768` on a CL job) with `m` bytes of
/// each perf marker: the records' slot and both markers, rounded up to 0x40
/// as `finishEncode` stores it; the firmware invalidates as many. `m` 0
/// gives `slot`.
pub(super) const fn perf_slot(slot: u32, m: usize) -> u32 {
    (slot + 2 * m as u32 + 0x3F) & !0x3F
}

/// Writes a job stream's perf-marker pair (`AGFA_Executor` case 4): the
/// first at the stream's start, before the context record, with bit 31
/// (the range words, and the counters' setup at a session's first), the
/// second at `second`, after the WFI (the Firmware source's sample). Class
/// 0 is TA, 1 3D, 2 CL. The encoder ID (Metal's `desc+0x6C4`) is 0, as the
/// job state's copy of it: the firmware reads it only into its trace and
/// the Firmware source's records.
///
/// # Safety
///
/// `s` must point at a stream buffer of at least `second + PERF_MARKER`
/// bytes.
pub(super) unsafe fn perf_markers(s: W, second: usize, class: u32, id: u32, js: u64) {
    for (off, first) in [(0, true), (second, false)] {
        // SAFETY: both markers are in bounds per the caller.
        unsafe {
            s.u32(off, u32::from(first) << 31 | class << 27 | 4);
            s.u32(off + 4, 0);
            s.u32(off + 8, id);
            s.u64(off + 0xC, js);
        }
    }
}

/// A firmware's layout of a session: the perf area's fields (event page
/// offsets), a source state's fields, its config's size, and how the
/// counters' records, banks and pixel formats are written.
struct PerfLay {
    /// 27.2's firmware: its config offsets (`cfg_off`), counter records
    /// (`pack::record_272`), banks (`pack::bank`) and pixel-format triples.
    v272: bool,
    /// The firmware, for the logs.
    name: &'static str,
    /// The perf area's end: the job table's start (`EVP::jobs`).
    end: usize,
    /// The running word (the firmware's), command 4's flags, the sample
    /// cache (u64), the size of its part device control 4 clears and the
    /// cache past it (u64), the source states (u64) and their count, the
    /// sampler states (u64) and their count, and the sampling context ID
    /// (u16, then a byte).
    running: usize,
    flags: usize,
    cache: usize,
    cache_size: usize,
    cache_end: usize,
    states: usize,
    nstates: usize,
    samplers: usize,
    nsamplers: usize,
    ctx: usize,
    /// The TPU and PBE pixel formats: 14.8.3's u64 values, which the
    /// firmware writes whole; 27.2's `{u64 value, u64 mask, u32 register}`
    /// triples (`FMT_TRIPLE` bytes), three for the TPU and one for the PBE,
    /// which it writes under their masks and clears at device control 5.
    fmt: [usize; 2],
    /// 27.2's APS select triples (`APS_TRIPLES` of them) and the APS
    /// source's index, read only on the APS source's paths.
    aps: Option<(usize, usize)>,
    /// A source state's size, its config's words (copied to its start),
    /// and its fields past the config: the active word (device control 4's),
    /// command 5's mode, flags and period, 27.2's byte that the RDE's
    /// `RDE_A68` write shifts (`1` as macOS's command 5 sets it), whether a
    /// partition past 2 is read, the RDE program and its word count, and
    /// command 3's ring fields (the area's size, VA, header VA, FW VA).
    state: usize,
    cfg_words: usize,
    st_active: usize,
    st_mode: usize,
    st_flags: usize,
    st_period: usize,
    st_on: Option<usize>,
    st_anypart: usize,
    st_prog: usize,
    st_nprog: usize,
    st_ring: usize,
    /// The sources' states' static part.
    init: &'static [StateInit; NSRC],
}

/// 14.8.3's layout (`AGXG15C_1483`'s `AGXPerfCtrSampler`,
/// `fwSourceDataAlloc`; `armfw_g15c_1483`'s `_agfHALPerfCtrSource*`).
const LAY_1483: PerfLay = {
    use core::mem::offset_of;
    use fw::g15::{PerfArea, PERF_AREA_OFF as A};
    PerfLay {
        v272: false,
        name: "14.8.3",
        end: A + size_of::<PerfArea>(),
        running: A + offset_of!(PerfArea, running),
        flags: A + offset_of!(PerfArea, flags),
        cache: A + offset_of!(PerfArea, cache),
        cache_size: A + offset_of!(PerfArea, cache_size),
        cache_end: A + offset_of!(PerfArea, cache_end),
        states: A + offset_of!(PerfArea, states),
        nstates: A + offset_of!(PerfArea, nstates),
        samplers: A + offset_of!(PerfArea, samplers),
        nsamplers: A + offset_of!(PerfArea, nsamplers),
        ctx: A + offset_of!(PerfArea, ctx_id),
        fmt: [A + offset_of!(PerfArea, tpu), A + offset_of!(PerfArea, pbe)],
        aps: None,
        state: 0x920,
        cfg_words: 0xD8 / 4,
        st_active: 0xD8,
        st_mode: 0xDC,
        st_flags: 0xE0,
        st_period: 0xE4,
        st_on: None,
        st_anypart: 0xE8,
        st_prog: 0xF8,
        st_nprog: 0x8F8,
        st_ring: 0x900,
        init: &STATE_INIT_1483,
    }
};

/// 27.2's layout. The kext (`AGXG15C_272`): `fwSourceDataAlloc`
/// (0xfffffe0008bd13bc: the cache +0x404C/+0x4054/+0x4058, the states
/// +0x4060/+0x4068, 0x938 bytes each, their config 0xE0 bytes, the samplers
/// +0x406C/+0x4074), `sourceSamplerStart` (0xfffffe0008bd1d50: the flags
/// +0x4048), Gen11's `commitSourceCounterList` (0xfffffe0008bd3824: the
/// mode +0xE4, flags +0xE8, period +0xEC, the byte +0xF0, the partition
/// test +0xF4, the program +0x110 and its count +0x910; the context ID
/// +0x4078 and its byte +0x407A), Gen15's (0xfffffe0008bd53b8: the TPU and
/// PBE triples +0x4210 and +0x4258, the APS ones from +0x4090), Gen15's
/// `init` (the APS index +0x4290) and `processSetSourceBuffer`
/// (0xfffffe0008bd0d94: the ring fields +0x918…+0x937). The firmware
/// (`armfw_g15c_272`) reads the same: device control 4
/// `sub_FFFFFC00000035BC` case 4 and its setup `sub_FFFFFC000002835C`
/// (the running word +0x4040, the active word +0xE0), the stop (case 5),
/// the counters' and RDEs' enable `sub_FFFFFC00000273F0` and the kick
/// triggers `sub_FFFFFC000002DE3C`.
const LAY_272: PerfLay = PerfLay {
    v272: true,
    name: "27.2",
    end: 0x4298,
    running: 0x4040,
    flags: 0x4048,
    cache: 0x404C,
    cache_size: 0x4054,
    cache_end: 0x4058,
    states: 0x4060,
    nstates: 0x4068,
    samplers: 0x406C,
    nsamplers: 0x4074,
    ctx: 0x4078,
    fmt: [0x4210, 0x4258],
    aps: Some((0x4090, 0x4290)),
    state: 0x938,
    cfg_words: 0xE0 / 4,
    st_active: 0xE0,
    st_mode: 0xE4,
    st_flags: 0xE8,
    st_period: 0xEC,
    st_on: Some(0xF0),
    st_anypart: 0xF4,
    st_prog: 0x110,
    st_nprog: 0x910,
    st_ring: 0x918,
    init: &STATE_INIT_272,
};

/// 27.2's pixel-format triple: `{u64 value, u64 mask, u32 register}`, its
/// size; the TPU's and PBE's registers (`sTPUPixelFormatSelectInfo_G15`,
/// `sPBEPixelFormatSelectInfo_G15`: one register each, 14.8.3's
/// `_agfHALPerfCtrSourceSetup` writes the same two), the TPU's triples, and
/// the APS triples.
const FMT_TRIPLE: usize = 0x18;
const FMT_REG: [u32; 2] = [0x124D0, 0x13490];
const TPU_TRIPLES: usize = 3;
const APS_TRIPLES: usize = 16;

/// The counter records' count, after their 0x4000 bytes at +0x18 (both
/// firmwares).
const PERF_NCMDS: usize = 0x4018;
/// The APS source's index in `SOURCES`, which 27.2's Gen15 `init` writes.
const APS_SRC: usize = 5;

// The layouts against each other and the event page: the records and the
// core layout (+0x401C…+0x4027) are the same, the fields after them in
// order, and 27.2's TPU, PBE and APS triples end where the next begins.
const _: () = {
    let (a, b) = (&LAY_1483, &LAY_272);
    assert!(a.end == 0x40A0 && b.end == 0x4298);
    assert!(a.running == 0x4030 && a.nsamplers == 0x4060 && a.ctx == 0x4064);
    assert!(a.fmt[0] == 0x4068 && a.fmt[1] == 0x4070);
    assert!(PERF_NCMDS == fw::g15::PERF_AREA_OFF + MAX_CMDS * 0x20);
    assert!(b.running > 0x4027 && b.ctx + 3 < 0x4090);
    let Some((aps, idx)) = b.aps else { panic!() };
    assert!(aps + APS_TRIPLES * FMT_TRIPLE == b.fmt[0]);
    assert!(b.fmt[0] + TPU_TRIPLES * FMT_TRIPLE == b.fmt[1]);
    assert!(b.fmt[1] + FMT_TRIPLE <= idx && idx + 4 <= b.end);
    assert!(a.state == 0x920 && b.state == 0x938);
    assert!(a.st_ring + 0x20 == a.state && b.st_ring + 0x20 == b.state);
    assert!(a.st_prog + 8 * pack::PROG_MAX == a.st_nprog);
    assert!(b.st_prog + 8 * pack::PROG_MAX == b.st_nprog);
    assert!(a.cfg_words * 4 == a.st_active && b.cfg_words * 4 == b.st_active);
    assert!(cfg_off(CFG_TIMESTAMPS, true) + 4 == b.cfg_words * 4);
    assert!(cfg_off(CFG_TIMESTAMPS, false) + 4 == a.cfg_words * 4);
    assert!(APS_SRC == NSRC - 1);
};

/// The sampler states: 0x38 bytes each, one per ring of every source.
const SAMPLER: usize = 0x38;
const NSAMPLERS: usize = 51;
/// A ring's header record, in the header page after the rings.
const HDR: usize = 0x40;
const HDR_PAGE: usize = 0x4000;
/// The part of the sample cache device control 4 clears.
const CACHE_CLEAR: u32 = 0x4000;

/// A ring: 0x40000 bytes (a sub-buffer: `gen.py`'s `samplers`, a 16 KiB
/// multiple).
const RING: usize = 0x40000;
/// Where the rings sit in their VM: 16 KiB-aligned, below 2^48 (the RDE's
/// ring registers keep 48 bits), at 512 GiB, where every G15 user VM has
/// its kernel range (Mesa's layout), whose buffers the GPU's units write.
/// The driver's own VM holds nothing else.
const RING_VA: u64 = 0x80_0000_0000;

/// Command 4's flags: GRC's 0x40, which it always sets.
const FLAGS4: u32 = 0x40;

/// An RDE program word that reads `reg`: bits 0–13 hold `reg >> 3`, bits
/// 18–23 the sub-index (`RDE_SUB`); the counters' words are
/// [`pack::read_word`]'s.
const fn rde_read(reg: u64) -> u64 {
    (reg >> 3) & 0x3FFF
}
const RDE_SUB: u32 = 18;

/// An RDE's registers, from its block's base: the program (a u64 a word),
/// the eight trigger words (+0x800…+0x838; the first kick sets bit 0 of
/// +0x830), the status (+0x840, the prologue's second read), the ring
/// select, the trigger-set-up flag (1 while the trigger runs), the pending
/// register (the stop waits for its low byte to clear), the context
/// (`sampler +6 | ctx << 8`), the addresses of the ring's header read and
/// write pointers, the ring's read pointer, base, end (`base + size -
/// 0x10`) and write pointer (+0xA58 and +0xA60 alike; the firmware reads
/// it back from +0xA60).
const RDE_PROG: u32 = 0;
const RDE_TRIGGER: u32 = 0x800;
const RDE_ENABLE: u32 = 0x830;
const RDE_STATUS: u32 = 0x840;
const RDE_SELECT: u32 = 0xA10;
const RDE_ARMED: u32 = 0xA18;
const RDE_PENDING: u32 = 0xA20;
const RDE_CONTEXT: u32 = 0xA28;
const RDE_HDR_RPTR: u32 = 0xA30;
const RDE_HDR_WPTR: u32 = 0xA38;
const RDE_RPTR: u32 = 0xA40;
const RDE_BASE: u32 = 0xA48;
const RDE_END: u32 = 0xA50;
const RDE_WPTR: u32 = 0xA58;
const RDE_WPTR2: u32 = 0xA60;
/// The firmware writes `1 << A68_BIT` to it at each ring's setup. Its
/// meaning is not traced.
const RDE_A68: u32 = 0xA68;

/// What the RDEs of one kind share (the GPU's two, and the two BMPR RDEs).
struct RdeKind {
    /// The timer unit: its trigger, period, n-clock count and cycle count
    /// registers.
    trigger: u32,
    period: u32,
    nclock: u32,
    cycles: u32,
    /// The stamp register: device control 4 writes 0xFEEDCBA987654321
    /// there, and the prologue reads it first.
    stamp: u32,
    /// The TA, 3D and CL kick-ID registers, which the jobs' register lists
    /// write; how many reads of each the prologue makes (sub-index 0, 1…),
    /// and the bits each such read carries.
    kick: [u32; 3],
    kick_reads: [u32; 3],
    kick_bits: u64,
    /// The RDE has a ring select (`RDE_SELECT`): `ring << 16`, or 0x100
    /// while its program is written and it starts or stops.
    select: bool,
    /// The prologue's extra words the kext adds with source flag 0x80 (not
    /// used here).
    timestamps: u32,
}

/// The value the 14.8.3 kext's BMPR prologue carries in its kick-ID reads
/// (a command word's bits 25–26 = 2). Its meaning is not traced.
const BMPR_KICK_BITS: u64 = 1 << 26;

/// The GPU's RDEs (RDE_0, RDE_1).
const GPU_RDE: RdeKind = RdeKind {
    trigger: 0x1170,
    period: 0x1120,
    nclock: 0x1128,
    cycles: 0x1138,
    stamp: 0x1478,
    kick: [0x14A0, 0x1498, 0x14A8],
    kick_reads: [2, 3, 3],
    kick_bits: 0,
    select: true,
    timestamps: 16,
};

/// The BMPR RDEs.
const BMPR_RDE: RdeKind = RdeKind {
    trigger: 0x5310,
    period: 0x5850,
    nclock: 0x5858,
    cycles: 0x5868,
    stamp: 0x1F7F8,
    kick: [0x1CA10, 0x160E0, 0x1A540],
    kick_reads: [1, 1, 1],
    kick_bits: BMPR_KICK_BITS,
    select: false,
    timestamps: 0,
};

/// An RDE: its register block and its kind.
struct Rde {
    block: u32,
    kind: &'static RdeKind,
}

/// A sampling source (14.8.3's `sPerfCtrConfig_G15` sources after
/// `Gen11::init`). Its index in `SOURCES` is the state's type (0 the
/// Firmware source, 1–4 an RDE, 5 APS).
struct Source {
    /// The kext's name for it ([`pack::SRC_NAMES`]). No firmware read of it
    /// was found.
    name: &'static str,
    /// Its rings, one sampler state each: a GPU RDE has one an mGPU, APS
    /// one a core slot (`Gen11::init`).
    rings: u32,
    /// The RDE that samples it: none for the Firmware and APS sources.
    rde: Option<Rde>,
}

/// `Gen11::init`'s mode 1 for every source, which device control 4 skips
/// without a ring; its flags, period and "a partition past 2" stay 0.
const UNUSED_MODE: u32 = 1;

/// The six sources. Those without counters keep mode 1 and no ring, as
/// `Gen11::init` leaves them: device control 4 programs a source only with
/// a ring in every sampler state.
const SOURCES: [Source; NSRC] = [
    Source {
        name: SRC_NAMES[0],
        rings: 1,
        rde: None,
    },
    Source {
        name: SRC_NAMES[1],
        rings: 4,
        rde: Some(Rde {
            block: 0xE000,
            kind: &GPU_RDE,
        }),
    },
    Source {
        name: SRC_NAMES[2],
        rings: 4,
        rde: Some(Rde {
            block: 0xF000,
            kind: &GPU_RDE,
        }),
    },
    Source {
        name: SRC_NAMES[3],
        rings: 1,
        rde: Some(Rde {
            block: 0x1D000,
            kind: &BMPR_RDE,
        }),
    },
    Source {
        name: SRC_NAMES[4],
        rings: 1,
        rde: Some(Rde {
            block: 0x1F000,
            kind: &BMPR_RDE,
        }),
    },
    Source {
        name: SRC_NAMES[5],
        rings: 40,
        rde: None,
    },
];

/// The mode source `s` runs in when it has counters: the session's `mode`
/// on a GPU RDE (RDE_0, RDE_1), the timer on a BMPR RDE, whose kick records
/// read the memory side's latched window rather than the kick (gpuprof.md
/// §2).
fn src_mode(s: usize, mode: u32) -> u32 {
    match &SOURCES[s].rde {
        Some(r) if core::ptr::eq(r.kind, &GPU_RDE) => mode,
        _ => MODE_TIMER,
    }
}

/// Source `s`'s first sampler state: its rings follow the ones before it
/// (`Gen11::init`).
const fn first(s: usize) -> usize {
    let (mut i, mut n) = (0, 0);
    while i < s {
        n += SOURCES[i].rings as usize;
        i += 1;
    }
    n
}

/// Source `s`'s ring area in the ring object: its rings, then their header
/// page (`gen.py`'s `samplers`). Only an RDE source has one.
const fn area_bytes(s: usize) -> usize {
    if SOURCES[s].rde.is_some() {
        SOURCES[s].rings as usize * RING + HDR_PAGE
    } else {
        0
    }
}

const fn area_off(s: usize) -> usize {
    let (mut i, mut o) = (0, 0);
    while i < s {
        o += area_bytes(i);
        i += 1;
    }
    o
}

/// The ring object: RDE_0's area at 0, RDE_1's at 0x104000, BMPR_RDE_0's
/// at 0x208000, BMPR_RDE_1's at 0x24C000; 0x290000 bytes.
const RING_BYTES: usize = area_off(NSRC);

/// The config the kext copies to a source state's start (0xD8 bytes, 27.2
/// 0xE0): what the firmware reads (14.8.3's
/// `_agfHALPerfCtrSourceSamplerSetup`, `…EnableHW`, `…Stop`, the trigger
/// setup) and the kext's own fields. Past +0x1C it is 0 for a source
/// without an RDE. The offsets below are 14.8.3's; `cfg_off` gives 27.2's.
const CFG_WORDS: usize = 0xE0 / 4;
/// The type, `1 << type`, the name (16 bytes, NUL-padded), the rings and
/// the first one's sampler state.
const CFG_TYPE: usize = 0;
const CFG_MASK: usize = 4;
const CFG_NAME: usize = 8;
const CFG_NAME_LEN: usize = 0x10;
const CFG_RINGS: usize = 0x18;
const CFG_FIRST: usize = 0x1C;
/// The timer's trigger, the stamp, the timer's cycles, n-clock and period.
const CFG_TRIGGER: usize = 0x20;
const CFG_STAMP: usize = 0x24;
const CFG_CYCLES: usize = 0x28;
const CFG_NCLOCK: usize = 0x2C;
const CFG_PERIOD: usize = 0x30;
/// The RDE's registers (0 for a ring select it lacks).
const CFG_SELECT: usize = 0x34;
const CFG_ARMED: usize = 0x38;
const CFG_PENDING: usize = 0x3C;
const CFG_PROG: usize = 0x40;
const CFG_CONTEXT: usize = 0x44;
const CFG_BASE: usize = 0x48;
const CFG_END: usize = 0x4C;
const CFG_WPTR: usize = 0x50;
const CFG_WPTR2: usize = 0x54;
const CFG_RPTR: usize = 0x58;
const CFG_HDR_WPTR: usize = 0x5C;
const CFG_HDR_RPTR: usize = 0x60;
const CFG_TRIGGER_WORDS: usize = 0x64;
const CFG_ENABLE: usize = 0x68;
/// The status: the prologue's second read, which the kext writes into the
/// prologue from here.
const CFG_STATUS: usize = 0x6C;
/// `RDE_A68` and the bit the firmware writes there.
const CFG_A68: usize = 0x70;
const CFG_A68_BIT: usize = 0x74;
/// The TA, 3D and CL kick-ID registers.
const CFG_KICK: usize = 0x78;
/// The value the 14.8.3 kext's static initialiser writes at +0x84 of every
/// RDE's config. No reader was found; its meaning is not traced.
const CFG_84: usize = 0x84;
const CFG_84_VALUE: u32 = 1;
/// u64s: the pending mask (`RDE_PENDING`), the mask of every VA the
/// firmware writes into the RDE (48 bits, 16-byte aligned), the bits ORed
/// into the header pointers' addresses, the status busy mask (the trigger
/// setup and the stop wait for `status & mask` to clear).
const CFG_PENDING_MASK: usize = 0x88;
const CFG_VA_MASK: usize = 0x90;
const CFG_HDR_BITS: usize = 0x98;
const CFG_BUSY_MASK: usize = 0xA0;
const PENDING_MASK: u64 = 0xFF;
const VA_MASK: u64 = 0xFFFF_FFFF_FFF0;
const HDR_BITS: u64 = 1 << 63;
const BUSY_MASK: u64 = 0x00FF_00FF_0FFF_0FFF;
/// The u64 the 14.8.3 kext's static initialiser writes at +0xA8 of every
/// RDE's config. No reader was found; its meaning is not traced.
const CFG_A8: usize = 0xA8;
const CFG_A8_VALUE: u64 = 0x0040_0040_0000_0000;
/// u64s: the bits the first kick ORs into `RDE_ENABLE`, the ring select's
/// value while the program is written and the RDE starts or stops; the
/// shift of a ring's number in it.
const CFG_ENABLE_BITS: usize = 0xB0;
const CFG_SELECT_ALL: usize = 0xB8;
const CFG_SELECT_SHIFT: usize = 0xC0;
const ENABLE_BITS: u64 = 1;
const SELECT_ALL: u64 = 0x100;
const SELECT_SHIFT: u32 = 16;
/// The kext's prologue (+0xC8, a pointer into the kext, left 0: the
/// firmware reads the program at `PerfLay::st_prog`), its word count and
/// its timestamp words.
const CFG_NPROLOGUE: usize = 0xD0;
const CFG_TIMESTAMPS: usize = 0xD4;
/// The bit the firmware writes to `RDE_A68`.
const A68_BIT: u32 = 60;

/// The longest prologue (a GPU RDE's).
const PROLOGUE_MAX: usize = 12;

/// Where 14.8.3's config offset `off` lies under 27.2's firmware (`v272`):
/// 27.2 puts a word after the context register (+0x48: a context register
/// that takes the sampler's byte alone, 0 on every source), and pads to
/// 8 bytes before the pending mask, so +0x48…+0x87 move by 4 and the rest
/// by 8 (`sPerfCtrSourceConfigList_G15`, `AGXG15C_272` 0xfffffe000cc38a28,
/// against `AGXG15C_1483` 0xfffffe000be953a0: every word of the six
/// sources matches so, but the prologue's kext pointer).
const fn cfg_off(off: usize, v272: bool) -> usize {
    if !v272 || off < 0x48 {
        off
    } else if off < 0x88 {
        off + 4
    } else {
        off + 8
    }
}

/// A source state's static part: the config and the RDE program's
/// prologue (`PerfLay::st_prog`, its count `PerfLay::st_nprog`), which a
/// session's counter words follow.
struct StateInit {
    cfg: [u32; CFG_WORDS],
    prog: [u64; PROLOGUE_MAX],
    nprog: usize,
}

/// A config being built for one firmware (`v272`), at 14.8.3's offsets.
struct Cfg {
    w: [u32; CFG_WORDS],
    v272: bool,
}

impl Cfg {
    const fn put32(&mut self, off: usize, v: u32) {
        self.w[cfg_off(off, self.v272) / 4] = v;
    }

    const fn put64(&mut self, off: usize, v: u64) {
        let o = cfg_off(off, self.v272) / 4;
        self.w[o] = v as u32;
        self.w[o + 1] = (v >> 32) as u32;
    }
}

/// Source `i`'s state for the firmware `v272` names, its rings' sampler
/// states from `first`.
const fn state_init(i: usize, first: u32, v272: bool) -> StateInit {
    let src = &SOURCES[i];
    let mut c = Cfg {
        w: [0u32; CFG_WORDS],
        v272,
    };
    c.put32(CFG_TYPE, i as u32);
    c.put32(CFG_MASK, 1 << i);
    let name = src.name.as_bytes();
    assert!(name.len() < CFG_NAME_LEN);
    let mut j = 0;
    while j < name.len() {
        c.w[(CFG_NAME + j) / 4] |= (name[j] as u32) << (8 * (j % 4));
        j += 1;
    }
    c.put32(CFG_RINGS, src.rings);
    c.put32(CFG_FIRST, first);
    let mut prog = [0u64; PROLOGUE_MAX];
    let mut n = 0;
    if let Some(r) = &src.rde {
        let (k, b) = (r.kind, r.block);
        c.put32(CFG_TRIGGER, k.trigger);
        c.put32(CFG_STAMP, k.stamp);
        c.put32(CFG_CYCLES, k.cycles);
        c.put32(CFG_NCLOCK, k.nclock);
        c.put32(CFG_PERIOD, k.period);
        if k.select {
            c.put32(CFG_SELECT, b + RDE_SELECT);
            c.put64(CFG_SELECT_ALL, SELECT_ALL);
            c.put32(CFG_SELECT_SHIFT, SELECT_SHIFT);
        }
        c.put32(CFG_ARMED, b + RDE_ARMED);
        c.put32(CFG_PENDING, b + RDE_PENDING);
        c.put32(CFG_PROG, b + RDE_PROG);
        c.put32(CFG_CONTEXT, b + RDE_CONTEXT);
        c.put32(CFG_BASE, b + RDE_BASE);
        c.put32(CFG_END, b + RDE_END);
        c.put32(CFG_WPTR, b + RDE_WPTR);
        c.put32(CFG_WPTR2, b + RDE_WPTR2);
        c.put32(CFG_RPTR, b + RDE_RPTR);
        c.put32(CFG_HDR_WPTR, b + RDE_HDR_WPTR);
        c.put32(CFG_HDR_RPTR, b + RDE_HDR_RPTR);
        c.put32(CFG_TRIGGER_WORDS, b + RDE_TRIGGER);
        c.put32(CFG_ENABLE, b + RDE_ENABLE);
        c.put32(CFG_STATUS, b + RDE_STATUS);
        c.put32(CFG_A68, b + RDE_A68);
        c.put32(CFG_A68_BIT, A68_BIT);
        let mut x = 0;
        while x < 3 {
            c.put32(CFG_KICK + 4 * x, k.kick[x]);
            x += 1;
        }
        c.put32(CFG_84, CFG_84_VALUE);
        c.put64(CFG_PENDING_MASK, PENDING_MASK);
        c.put64(CFG_VA_MASK, VA_MASK);
        c.put64(CFG_HDR_BITS, HDR_BITS);
        c.put64(CFG_BUSY_MASK, BUSY_MASK);
        c.put64(CFG_A8, CFG_A8_VALUE);
        c.put64(CFG_ENABLE_BITS, ENABLE_BITS);
        // The prologue: the stamp, the status, the n-clock and cycle
        // counts, then each kick-ID register's reads.
        prog[0] = rde_read(k.stamp as u64);
        prog[1] = rde_read((b + RDE_STATUS) as u64);
        prog[2] = rde_read(k.nclock as u64);
        prog[3] = rde_read(k.cycles as u64);
        n = 4;
        x = 0;
        while x < 3 {
            let mut s = 0;
            while s < k.kick_reads[x] {
                prog[n] = rde_read(k.kick[x] as u64) | (s as u64) << RDE_SUB | k.kick_bits;
                n += 1;
                s += 1;
            }
            x += 1;
        }
        c.put32(CFG_NPROLOGUE, n as u32);
        c.put32(CFG_TIMESTAMPS, k.timestamps);
    }
    // `pack` counts the same prologue.
    assert!(n == PROLOGUE[i]);
    StateInit {
        cfg: c.w,
        prog,
        nprog: n,
    }
}

/// The sources' states for the firmware `v272` names, built at compile
/// time.
const fn state_inits(v272: bool) -> [StateInit; NSRC] {
    let mut s = [const {
        StateInit {
            cfg: [0; CFG_WORDS],
            prog: [0; PROLOGUE_MAX],
            nprog: 0,
        }
    }; NSRC];
    let mut i = 0;
    while i < NSRC {
        s[i] = state_init(i, first(i) as u32, v272);
        i += 1;
    }
    // Every sampler state has its source.
    assert!(first(NSRC) == NSAMPLERS);
    s
}

const STATE_INIT_1483: [StateInit; NSRC] = state_inits(false);
const STATE_INIT_272: [StateInit; NSRC] = state_inits(true);

/// The session's states (`G15PerfCtr::state`).
const IDLE: u32 = 0;
/// A start or a stop is under way.
const BUSY: u32 = 1;
/// Device control 4 was sent, and no confirmed stop since.
const STARTED: u32 = 2;

/// How long a device control may wait for the firmware's consumer.
const PERF_DC_WAIT_MS: i64 = 100;

/// What the firmware's session points at, freed with the device only once
/// no session can run on it.
struct G15PerfMem {
    /// The sample cache, the source states and the sampler states
    /// (firmware non-cacheable).
    cache: fw::types::GpuArray<u8>,
    states: fw::types::GpuArray<u8>,
    samplers: fw::types::GpuArray<u8>,
    /// The rings and their header page, mapped at `RING_VA` in `_vm`, held
    /// bound to a UAT slot (the context ID) for the device's lifetime.
    _ring_map: mmu::KernelMapping,
    _bind: mmu::VmBind,
    _ring: gem::ObjectRef,
    _vm: mmu::Vm,
}

/// The counters' session (`asahi.perfctr`).
pub(crate) struct G15PerfCtr {
    mem: ManuallyDrop<G15PerfMem>,
    /// The firmware's layout of it.
    lay: &'static PerfLay,
    /// `IDLE`, `BUSY` or `STARTED`: a start and a stop take it from IDLE and
    /// STARTED to BUSY, so one runs at a time, with no lock.
    state: AtomicU32,
    /// A GPU recovery came while started: the firmware ends the session
    /// itself (its perf thread clears the running word).
    ended: AtomicBool,
    /// The ring VM's context ID: its UAT slot.
    ctx: u32,
    /// The rings' kernel mapping.
    ring: usize,
    /// The range words of the jobs built from now on, a stage (`STAGES`,
    /// `range_pack`): `RANGE_ALL` but from a start to its session's end.
    range: [AtomicU64; 3],
    /// The session's pick (`pick_pack`), 0 for none.
    pick: AtomicU64,
    /// The session's jobs built with words other than `RANGE_ALL`, a stage,
    /// and its picked passes.
    ranged: [AtomicU32; 3],
    picked: AtomicU32,
    /// Whether the session's first job of a stage has been logged.
    logged: [AtomicBool; 3],
    /// The session's pass selector (`pack::sel_pack`), 0s for none.
    sel: [AtomicU64; 2],
    /// The words were set by an `arm`, ahead of a start: a stop with no
    /// session takes them off.
    armed: AtomicBool,
    /// From a start or an arm to the session's end: the TA and 3D jobs
    /// write their kick IDs (`kick_id`) in kick mode (`ids`), as the kext's
    /// lists do while its sampler runs, and the render passes are counted,
    /// all of them, those with the vertex overlap
    /// (`DRM_ASAHI_RENDER_OVERLAP_VERTEX` with no store wait: their TA may
    /// run under up to three earlier passes' 3D jobs, and its marker sets
    /// 0x10048 for them), and by their attachment count (0 to `MAX_ATTS`).
    counting: AtomicBool,
    passes: AtomicU32,
    overlap: AtomicU32,
    by_atts: [AtomicU32; MAX_ATTS as usize + 1],
    /// Whether the session's first picked pass has been logged.
    logged_pick: AtomicBool,
    /// A kept pass's words (`range_pack`) and whether its TA job gets
    /// `PPP_BATCH` with them (`Session::keep`, `Session::keep_batch`).
    keep: AtomicU64,
    keep_batch: AtomicBool,
    /// The GPU RDEs' mode of the session or arm in effect (`Session::mode`),
    /// for the debugfs read and the log.
    mode: AtomicU32,
}

impl Drop for G15PerfCtr {
    fn drop(&mut self) {
        if *self.state.get_mut() == IDLE {
            // SAFETY: dropped once, here, and nothing the firmware runs
            // points at it: no device control 4 since the last confirmed
            // stop.
            unsafe { ManuallyDrop::drop(&mut self.mem) };
        } else {
            pr_warn!("asahi: G15 perfctr: a session may run: its memory is kept\n");
        }
    }
}

/// An in-bounds little-endian u32 at `off` of `p`.
///
/// # Safety
///
/// `p + off .. + 4` must be readable.
unsafe fn r32(p: *const u8, off: usize) -> u32 {
    // SAFETY: per the caller.
    unsafe { p.add(off).cast::<u32>().read_unaligned() }
}

/// An in-bounds little-endian u64 at `off` of `p`.
///
/// # Safety
///
/// `p + off .. + 8` must be readable.
unsafe fn r64(p: *const u8, off: usize) -> u64 {
    // SAFETY: per the caller.
    unsafe { p.add(off).cast::<u64>().read_unaligned() }
}

impl G15PerfCtr {
    /// Source `s`'s ring `k`: its VA (sampler state `first(s) + k`), and
    /// its header record's offset in the ring object and VA.
    fn ring_va(s: usize, k: usize) -> u64 {
        RING_VA + (area_off(s) + k * RING) as u64
    }

    fn hdr_off(s: usize, k: usize) -> usize {
        area_off(s) + SOURCES[s].rings as usize * RING + k * HDR
    }

    fn hdr_va(s: usize, k: usize) -> u64 {
        RING_VA + Self::hdr_off(s, k) as u64
    }

    fn ring_ptr(&self) -> *mut u8 {
        self.ring as *mut u8
    }

    /// Sets `ses`'s range words, pick, pass selector and kept words for the
    /// jobs built from now on, the pick counting from render pass ID
    /// `first`, and clears the session's counts. From here until the
    /// session's end the TA and 3D jobs also write their kick IDs in kick
    /// mode (`ids`). A pass built during the stores may get a mix of the old
    /// and new words.
    fn range_set(&self, ses: &Session<'_>, first: u32) {
        for i in 0..STAGES.len() {
            self.ranged[i].store(0, Ordering::Relaxed);
            self.logged[i].store(false, Ordering::Relaxed);
            self.range[i].store(range_pack(ses.range[i]), Ordering::Relaxed);
        }
        self.picked.store(0, Ordering::Relaxed);
        self.pick
            .store(pick_pack(ses.pick, first), Ordering::Relaxed);
        for (w, v) in self.sel.iter().zip(sel_pack(ses.sel)) {
            w.store(v, Ordering::Relaxed);
        }
        self.keep.store(range_pack(ses.keep), Ordering::Relaxed);
        self.keep_batch.store(ses.keep_batch, Ordering::Relaxed);
        self.mode.store(ses.mode, Ordering::Relaxed);
        self.passes.store(0, Ordering::Relaxed);
        self.overlap.store(0, Ordering::Relaxed);
        for n in &self.by_atts {
            n.store(0, Ordering::Relaxed);
        }
        self.logged_pick.store(false, Ordering::Relaxed);
        self.counting.store(true, Ordering::Relaxed);
    }

    /// Whether the jobs built now write their kick IDs: a kick-mode session
    /// or arm in effect. A timer session's jobs write none, as before
    /// build 6.
    fn ids(&self) -> bool {
        self.counting.load(Ordering::Relaxed) && self.mode.load(Ordering::Relaxed) == MODE_KICK
    }

    /// Metal's default words, no pick, no selector and no kick IDs for the
    /// jobs built from now on; the counts stay as they are.
    fn range_reset(&self) {
        for r in &self.range {
            r.store(range_pack(RANGE_ALL), Ordering::Relaxed);
        }
        self.pick.store(0, Ordering::Relaxed);
        for w in &self.sel {
            w.store(0, Ordering::Relaxed);
        }
        self.keep.store(range_pack(RANGE_ALL), Ordering::Relaxed);
        self.keep_batch.store(false, Ordering::Relaxed);
        self.counting.store(false, Ordering::Relaxed);
        self.armed.store(false, Ordering::Relaxed);
    }

    /// Fills the source states, the sampler states, the cache and the
    /// rings' header pages for `ses`, and cleans them to memory. Every
    /// source gets its config and prologue (mode 1); a source with counters
    /// its mode (`src_mode`), its counter words, and its rings.
    fn fill(&self, ses: &Session<'_>) {
        let mem = &*self.mem;
        let lay = self.lay;
        let st = mem.states.raw_ptr();
        let sm = mem.samplers.raw_ptr();
        let rp = self.ring_ptr();
        // SAFETY: every store is in bounds of the session's own buffers: the
        // 6 states of `lay.state` bytes (a program of at most
        // `pack::PROG_MAX` words ends at `lay.st_nprog`), the 51 samplers of
        // 0x38 bytes, the cache, and the ring object (`RING_BYTES`). With no
        // session running nothing else writes them.
        unsafe {
            core::ptr::write_bytes(st, 0, mem.states.len());
            core::ptr::write_bytes(sm, 0, mem.samplers.len());
            core::ptr::write_bytes(mem.cache.raw_ptr(), 0, mem.cache.len());
            core::ptr::write_bytes(rp, 0, RING_BYTES);
            for (i, init) in lay.init.iter().enumerate() {
                let s = W(st.add(lay.state * i));
                for (j, w) in init.cfg[..lay.cfg_words].iter().enumerate() {
                    s.u32(4 * j, *w);
                }
                s.u32(lay.st_mode, UNUSED_MODE);
                for (j, w) in init.prog[..init.nprog].iter().enumerate() {
                    s.u64(lay.st_prog + 8 * j, *w);
                }
                s.u32(lay.st_nprog, init.nprog as u32);
            }
            for (i, src) in SOURCES.iter().enumerate() {
                if ses.count(i) == 0 {
                    continue;
                }
                let s = W(st.add(lay.state * i));
                // Command 5: the mode, the flags, the period, 27.2's byte
                // (1, as its command 5 sets it but with flag 0x400), and
                // whether a partition past 2 is read.
                s.u32(lay.st_mode, src_mode(i, ses.mode));
                s.u32(lay.st_flags, SRC_FLAGS);
                s.u32(lay.st_period, ses.period);
                if let Some(o) = lay.st_on {
                    s.u8(o, 1);
                }
                s.u32(lay.st_anypart, u32::from(ses.anypart(i)));
                let mut n = PROLOGUE[i];
                for c in ses.counters().iter().filter(|c| c.src as usize == i) {
                    s.u64(lay.st_prog + 8 * n, read_word(c, lay.v272));
                    n += 1;
                }
                s.u32(lay.st_nprog, n as u32);
                // Command 3's ring fields: the area's size with its header
                // page, its VA, the header page's VA; its FW VA (+0x18) is
                // 0, read only on the APS source's paths.
                s.u64(lay.st_ring, area_bytes(i) as u64);
                s.u64(lay.st_ring + 8, Self::ring_va(i, 0));
                s.u64(lay.st_ring + 0x10, Self::hdr_va(i, 0));
                for k in 0..src.rings as usize {
                    let base = Self::ring_va(i, k);
                    // The sampler state: {source, context ID, 0, size, 0,
                    // base, read pointer, write pointer, the header record's
                    // read and write pointer words}.
                    let m = W(sm.add(SAMPLER * (first(i) + k)));
                    m.u32(0, i as u32);
                    m.u16(4, self.ctx as u16);
                    m.u32(8, RING as u32);
                    m.u64(0x10, base);
                    m.u64(0x18, base);
                    m.u64(0x20, base);
                    m.u64(0x28, Self::hdr_va(i, k) + 0x20);
                    m.u64(0x30, Self::hdr_va(i, k) + 0x30);
                    // The header record: {CPU VA (0), VA, offset, size, read
                    // pointer, write pointer}.
                    let h = W(rp.add(Self::hdr_off(i, k)));
                    h.u64(8, base);
                    h.u64(0x10, (RING * k) as u64);
                    h.u32(0x18, RING as u32);
                    h.u64(0x20, base);
                    h.u64(0x30, base);
                }
            }
        }
        crate::mem::dc_civac(st.cast_const(), mem.states.len());
        crate::mem::dc_civac(sm.cast_const(), mem.samplers.len());
        crate::mem::dc_civac(mem.cache.raw_ptr().cast_const(), mem.cache.len());
        crate::mem::dc_civac(rp.cast_const(), RING_BYTES);
    }

    /// Source `s`'s state, cleaned and invalidated first.
    fn state_ptr(&self, s: usize) -> *const u8 {
        let p = self
            .mem
            .states
            .raw_ptr()
            .cast_const()
            .wrapping_add(self.lay.state * s);
        crate::mem::dc_civac(p, self.lay.state);
        p
    }

    /// The sources a session runs on: mode 8 or 2 in their state (the
    /// others keep `UNUSED_MODE`).
    fn used(&self, s: usize) -> bool {
        // SAFETY: an in-bounds read of the source's state.
        let mode = unsafe { r32(self.state_ptr(s), self.lay.st_mode) };
        matches!(mode, MODE_TIMER | MODE_KICK)
    }

    /// Source `s`'s ring `k`: its header pointers (+0x20 read, +0x30
    /// write) and its sampler's (+0x18, +0x20), from memory.
    fn ring_ptrs(&self, s: usize, k: usize) -> [u64; 4] {
        let h = self
            .ring_ptr()
            .cast_const()
            .wrapping_add(Self::hdr_off(s, k));
        let m = self
            .mem
            .samplers
            .raw_ptr()
            .cast_const()
            .wrapping_add(SAMPLER * (first(s) + k));
        crate::mem::dc_civac(h, HDR);
        crate::mem::dc_civac(m, SAMPLER);
        // SAFETY: in-bounds reads of the header page and the sampler states.
        unsafe { [r64(h, 0x20), r64(h, 0x30), r64(m, 0x18), r64(m, 0x20)] }
    }
}

/// Stores `v`'s low `4 * words` bytes at `off` of `p`, a u32 at a time:
/// the perf area's u64s lie 4 bytes off their alignment on both firmwares.
///
/// # Safety
///
/// `p + off .. + 4 * words` must be writable and `p + off` 4-aligned.
unsafe fn ev_put(p: *mut u8, off: usize, v: u64, words: usize) {
    for k in 0..words {
        // SAFETY: in bounds and aligned per the caller.
        unsafe {
            p.add(off + 4 * k)
                .cast::<u32>()
                .write_volatile((v >> (32 * k)) as u32)
        };
    }
}

#[versions(AGX)]
impl GpuManager::ver {
    /// This firmware's session layout.
    #[allow(
        clippy::let_and_return,
        reason = "each version's value bound under its #[ver], one left"
    )]
    fn g15_perf_lay() -> &'static PerfLay {
        #[ver(V < V27_2)]
        let lay = &LAY_1483;
        #[ver(V >= V27_2)]
        let lay = &LAY_272;
        lay
    }

    /// The event page, whose perf area runs from `fw::g15::PERF_AREA_OFF`
    /// to the layout's `end`.
    fn g15_ev(&self) -> *mut u8 {
        self.initdata.event_page.raw_ptr().cast::<u8>()
    }

    /// The firmware's running word (+0x4030; 27.2 +0x4040), from memory.
    fn g15_perf_running(&self) -> u32 {
        let p = self
            .g15_ev()
            .wrapping_add(Self::g15_perf_lay().running)
            .cast::<u32>();
        crate::mem::dc_civac(p.cast::<u8>().cast_const(), 4);
        // SAFETY: an aligned u32 of the event page.
        unsafe { p.read_volatile() }
    }

    /// Allocates the counters' session memory at probe (`asahi.perfctr`):
    /// the sample cache, the source and sampler states, and the rings in a
    /// VM of their own bound to a UAT slot, whose index is the context ID
    /// the RDE writes them under. Kept for the device's lifetime.
    pub(crate) fn g15_perfctr_init(&self) -> Result {
        if !self.g15.perfctr {
            return Ok(());
        }
        let dev = self.dev.as_ref();
        if crate::module_parameters::robust_isolation.value() != 0 {
            // A held slot would be the only user slot.
            dev_err!(dev, "G15 perfctr: not with asahi.robust_isolation\n");
            return Err(EBUSY);
        }
        // 0x20 a core the clusters can hold, 0x720, and the 0x4000 bytes
        // device control 4 clears (`fwSourceDataAlloc`): 0x4C20 here.
        let id = &self.dyncfg.id;
        let lay = Self::g15_perf_lay();
        let cache_size = 0x20 * (id.num_clusters * id.num_cores) as usize + 0x720 + 0x4000;
        let (cache, states, samplers) = {
            let mut guard = self.alloc.lock();
            (
                guard.fw_nc.array_empty_tagged::<u8>(cache_size, b"PCCA")?,
                guard
                    .fw_nc
                    .array_empty_tagged::<u8>(lay.state * SOURCES.len(), b"PCST")?,
                guard
                    .fw_nc
                    .array_empty_tagged::<u8>(SAMPLER * NSAMPLERS, b"PCSM")?,
            )
        };
        let vm = self
            .uat
            .new_vm(self.ids.vm.next(), RING_VA..RING_VA + RING_BYTES as u64)?;
        let mut ring = gem::new_kernel_object(&self.dev, RING_BYTES)?;
        let rp = ring.vmap()?.addr as usize;
        let ring_map = ring.map_at(&vm, RING_VA, mmu::PROT_GPU_SHARED_RW, false)?;
        let bind = self.uat.bind(&vm)?;
        let ctx = bind.slot();
        let pc = KBox::new(
            G15PerfCtr {
                lay,
                mem: ManuallyDrop::new(G15PerfMem {
                    cache,
                    states,
                    samplers,
                    _ring_map: ring_map,
                    _bind: bind,
                    _ring: ring,
                    _vm: vm,
                }),
                state: AtomicU32::new(IDLE),
                ended: AtomicBool::new(false),
                ctx,
                ring: rp,
                range: [const { AtomicU64::new(range_pack(RANGE_ALL)) }; 3],
                pick: AtomicU64::new(0),
                ranged: [const { AtomicU32::new(0) }; 3],
                picked: AtomicU32::new(0),
                logged: [const { AtomicBool::new(false) }; 3],
                sel: [const { AtomicU64::new(0) }; 2],
                armed: AtomicBool::new(false),
                counting: AtomicBool::new(false),
                passes: AtomicU32::new(0),
                overlap: AtomicU32::new(0),
                by_atts: [const { AtomicU32::new(0) }; MAX_ATTS as usize + 1],
                logged_pick: AtomicBool::new(false),
                keep: AtomicU64::new(range_pack(RANGE_ALL)),
                keep_batch: AtomicBool::new(false),
                mode: AtomicU32::new(MODE_TIMER),
            },
            GFP_KERNEL,
        )?;
        let cache_va = pc.mem.cache.gpu_va().get();
        if !self.g15.perfctr_mem.populate(pc) {
            return Err(EBUSY);
        }
        dev_info!(
            dev,
            "G15 perfctr: session memory at probe ({}'s layout): cache {cache_va:#x} ({cache_size:#x}), rings {RING_VA:#x} ({RING_BYTES:#x}) in context {ctx}; {} clusters of {} cores, {} enabled, masks {:x?}\n",
            lay.name,
            id.num_clusters,
            id.num_cores,
            id.total_active_cores,
            id.core_masks
        );
        Ok(())
    }

    /// Marks a started session ended by a GPU recovery (`g15_recovery`): the
    /// firmware's perf thread stops its sources and clears the running word
    /// itself, with no device control 5. The memory stays until it reads 0.
    pub(super) fn g15_perfctr_recovery(&self) {
        let Some(pc) = self.g15.perfctr_mem.as_ref() else {
            return;
        };
        if pc.state.load(Ordering::Acquire) != IDLE {
            pc.ended.store(true, Ordering::Release);
            // The firmware skips the markers now: the jobs go back to the
            // default words and PPP_CTRL.
            pc.range_reset();
            dev_warn!(
                self.dev.as_ref(),
                "G15 perfctr: a GPU recovery ends the session (running {})\n",
                self.g15_perf_running()
            );
        }
    }

    /// Writes the perf area for `ses`, the context ID included: the
    /// counters' records, source by source, and the pixel formats (27.2: as
    /// masked triples, with its APS selects cleared and its APS index).
    fn g15_perf_area_fill(&self, pc: &G15PerfCtr, ses: &Session<'_>) {
        let lay = pc.lay;
        let ev = self.g15_ev();
        let mem = &*pc.mem;
        let cache = mem.cache.gpu_va().get();
        let area = ev.wrapping_add(fw::g15::PERF_AREA_OFF);
        let area_len = lay.end - fw::g15::PERF_AREA_OFF;
        // No stale line of the page in the CPU's cache: a store into one
        // would write its other words back over the firmware's.
        crate::mem::dc_civac(area.cast_const(), area_len);
        // SAFETY: every field lies within the perf area (`lay.end` is the
        // job table's start), 4-aligned but for the context ID's byte, and
        // at most `MAX_CMDS` (512) records go into the 0x4000 bytes at
        // +0x18. With the running word clear the firmware reads the area
        // only at device control 4, which comes after these stores reach
        // memory (`dc_civac` below, then the control ring's own cleaning
        // and barrier).
        unsafe {
            core::ptr::write_bytes(area, 0, MAX_CMDS * 0x20);
            let mut n = 0;
            for i in 0..NSRC {
                for c in ses.counters().iter().filter(|c| c.src as usize == i) {
                    let r = if lay.v272 {
                        pack::record_272(c)
                    } else {
                        record(c)
                    };
                    for (j, b) in r.iter().enumerate() {
                        area.add(0x20 * n + j).write_volatile(*b);
                    }
                    n += 1;
                }
            }
            ev_put(ev, PERF_NCMDS, n as u64, 1);
            ev_put(ev, lay.flags, FLAGS4.into(), 1);
            ev_put(ev, lay.cache, cache, 2);
            ev_put(ev, lay.cache_size, CACHE_CLEAR.into(), 1);
            ev_put(ev, lay.cache_end, cache + u64::from(CACHE_CLEAR), 2);
            ev_put(ev, lay.states, mem.states.gpu_va().get(), 2);
            ev_put(ev, lay.nstates, NSRC as u64, 1);
            ev_put(ev, lay.samplers, mem.samplers.gpu_va().get(), 2);
            ev_put(ev, lay.nsamplers, NSAMPLERS as u64, 1);
            ev.add(lay.ctx).cast::<u16>().write_volatile(pc.ctx as u16);
            ev.add(lay.ctx + 2).write_volatile(0);
            if lay.v272 {
                // The TPU's first triple and the PBE's: the value under its
                // bytes' mask and the register; the TPU's other two and the
                // APS ones stay clear (a mask of 0 ends each list: the setup
                // `sub_FFFFFC000002835C` touches no bank or register for it),
                // and so does a kind with no format counter, as the kext
                // leaves it.
                core::ptr::write_bytes(ev.add(lay.fmt[0]), 0, (TPU_TRIPLES + 1) * FMT_TRIPLE);
                for (k, &at) in lay.fmt.iter().enumerate() {
                    let m = ses.fmt_mask(k);
                    if m == 0 {
                        continue;
                    }
                    ev_put(ev, at, ses.fmt(k) & m, 2);
                    ev_put(ev, at + 8, m, 2);
                    ev_put(ev, at + 0x10, FMT_REG[k].into(), 1);
                }
            } else {
                for (k, &at) in lay.fmt.iter().enumerate() {
                    ev_put(ev, at, ses.fmt(k), 2);
                }
            }
            if let Some((sel, idx)) = lay.aps {
                core::ptr::write_bytes(ev.add(sel), 0, APS_TRIPLES * FMT_TRIPLE);
                ev_put(ev, idx, APS_SRC as u64, 1);
            }
        }
        crate::mem::dc_civac(area.cast_const(), area_len);
    }

    /// Device control 4's preconditions, read back from memory: what the
    /// firmware dereferences or checks at it. Returns the first that fails.
    fn g15_perf_check(
        &self,
        pc: &G15PerfCtr,
        ses: &Session<'_>,
    ) -> core::result::Result<(), &'static str> {
        let mem = &*pc.mem;
        let lay = pc.lay;
        let ev = self.g15_ev().cast_const();
        let e = |off: usize| ev.wrapping_add(off);
        crate::mem::dc_civac(e(fw::g15::PERF_AREA_OFF), lay.end - fw::g15::PERF_AREA_OFF);
        crate::mem::dc_civac(mem.samplers.raw_ptr().cast_const(), mem.samplers.len());
        crate::mem::dc_civac(pc.ring_ptr().cast_const(), RING_BYTES);
        let sm = mem.samplers.raw_ptr().cast_const();
        let rp = pc.ring_ptr().cast_const();
        // SAFETY: in-bounds reads of the event page and the session's own
        // buffers.
        unsafe {
            if r32(e(lay.running), 0) != 0 {
                return Err("the running word is set: a session runs");
            }
            if r32(e(PERF_NCMDS), 0) as usize != ses.counters().len() {
                return Err("+0x4018 is not the counter count");
            }
            if r32(e(lay.nstates), 0) != NSRC as u32 {
                return Err("the source state count is not 6");
            }
            if r32(e(lay.nsamplers), 0) != NSAMPLERS as u32 {
                return Err("the sampler state count is not 51");
            }
            if r64(e(lay.cache), 0) == 0
                || r64(e(lay.states), 0) == 0
                || r64(e(lay.samplers), 0) == 0
            {
                return Err("a perf-area FW VA is 0");
            }
            if lay.v272 {
                for (k, &at) in lay.fmt.iter().enumerate() {
                    if r64(e(at + 8), 0) != ses.fmt_mask(k) || r32(e(at + 0x10), 0) != FMT_REG[k] {
                        return Err("a pixel-format triple is not the session's");
                    }
                }
            }
            for (i, src) in SOURCES.iter().enumerate() {
                let st = pc.state_ptr(i);
                let used = ses.count(i) != 0;
                if used
                    && (r32(st, lay.st_mode) != src_mode(i, ses.mode)
                        || r32(st, lay.st_nprog) as usize != PROLOGUE[i] + ses.count(i)
                        || lay.st_on.is_some_and(|o| *st.add(o) != 1))
                {
                    return Err(
                        "a source with counters is not in its mode, or its program is short, or not on",
                    );
                }
                for k in 0..src.rings as usize {
                    let s = sm.add(SAMPLER * (first(i) + k));
                    if used != (r64(s, 0x10) != 0 && r32(s, 8) != 0) {
                        return Err("a sampler state's ring does not match its source's counters");
                    }
                    if used {
                        let h = rp.add(G15PerfCtr::hdr_off(i, k));
                        let base = G15PerfCtr::ring_va(i, k);
                        if r64(h, 0x20) != base || r64(h, 0x30) != base {
                            return Err("a ring header's pointers are not its base");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Sends device control `dc` (word 0 its type, the rest 0) and waits
    /// for its consumption, which follows its handler. Fails with
    /// `ETIMEDOUT` when it was not consumed in `PERF_DC_WAIT_MS`, with the
    /// send's error when it may not have been queued.
    fn g15_perf_dc(&self, dc: u32) -> Result {
        let mut w = [0u32; CTL::ver.words];
        w[0] = dc;
        let end = self.g15_ctl_send(&w).inspect_err(|e| {
            dev_err!(
                self.dev.as_ref(),
                "G15 perfctr: device control {dc} not sent ({e:?})\n"
            );
        })?;
        let start = Instant::<Monotonic>::now();
        while !self.g15_ctl_consumed(Some(end)) {
            if start.elapsed() >= Delta::from_millis(PERF_DC_WAIT_MS) {
                return Err(ETIMEDOUT);
            }
            kernel::time::delay::fsleep(Delta::from_micros(50));
        }
        Ok(())
    }

    /// Starts `ses`: fills it, checks it, sends device control 4.
    fn g15_perfctr_start(&self, pc: &G15PerfCtr, ses: &Session<'_>) -> Result {
        let dev = self.dev.as_ref();
        if pc
            .state
            .compare_exchange(IDLE, BUSY, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            dev_err!(dev, "G15 perfctr: start: a session is started or busy\n");
            return Err(EBUSY);
        }
        if self.g15_perf_running() != 0 {
            // A session runs on the memory: nothing is rewritten.
            pc.state.store(IDLE, Ordering::Release);
            dev_err!(
                dev,
                "G15 perfctr: start: the running word is set: a session runs\n"
            );
            return Err(EBUSY);
        }
        if self.is_crashed() || self.g15_fw_stopped() {
            pc.state.store(IDLE, Ordering::Release);
            dev_err!(
                dev,
                "G15 perfctr: start: the firmware is stopped or crashed\n"
            );
            return Err(EIO);
        }
        pc.ended.store(false, Ordering::Release);
        pc.fill(ses);
        self.g15_perf_area_fill(pc, ses);
        if let Err(why) = self.g15_perf_check(pc, ses) {
            pc.state.store(IDLE, Ordering::Release);
            dev_err!(dev, "G15 perfctr: start: {why}; no device control 4\n");
            return Err(EINVAL);
        }
        pc.range_set(ses, self.g15.rd_ids.load(Ordering::Relaxed));
        let r = self.g15_perf_dc(4);
        // From here the firmware may run the session: the memory stays until
        // a stop sees the running word clear.
        pc.state.store(STARTED, Ordering::Release);
        if let Err(e) = r {
            if e == ETIMEDOUT {
                dev_err!(
                    dev,
                    "G15 perfctr: device control 4 not consumed in {PERF_DC_WAIT_MS} ms\n"
                );
            }
            return Err(e);
        }
        let running = self.g15_perf_running();
        let mode = if ses.mode == MODE_KICK {
            "kick"
        } else {
            "timer"
        };
        dev_info!(
            dev,
            "G15 perfctr: device control 4 done: running {running}, context {}, period {:#x}, GPU RDEs' mode {} ({mode}), counters: {} RDE_0, {} RDE_1, {} BMPR_RDE_0, {} BMPR_RDE_1\n",
            pc.ctx,
            ses.period,
            ses.mode,
            ses.count(1),
            ses.count(2),
            ses.count(3),
            ses.count(4)
        );
        if running != 1 {
            dev_err!(
                dev,
                "G15 perfctr: no source passed device control 4's checks\n"
            );
            return Err(EIO);
        }
        Ok(())
    }

    /// Stops the session: device control 5, unless a GPU recovery has
    /// ended it and the running word reads clear; then it must read clear.
    fn g15_perfctr_stop(&self, pc: &G15PerfCtr) -> Result {
        let dev = self.dev.as_ref();
        if pc
            .state
            .compare_exchange(STARTED, BUSY, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // No session: an arm's words come off the jobs.
            if pc.armed.load(Ordering::Relaxed)
                && pc
                    .state
                    .compare_exchange(IDLE, BUSY, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                pc.range_reset();
                pc.state.store(IDLE, Ordering::Release);
                dev_info!(dev, "G15 perfctr: stop: disarmed, no session ran\n");
                return Ok(());
            }
            dev_err!(dev, "G15 perfctr: stop: no session started, or busy\n");
            return Err(EINVAL);
        }
        if pc.ended.load(Ordering::Acquire) && self.g15_perf_running() == 0 {
            pc.range_reset();
            pc.state.store(IDLE, Ordering::Release);
            self.g15_perf_log_passes(pc);
            dev_info!(
                dev,
                "G15 perfctr: the session was ended by a GPU recovery: no device control 5\n"
            );
            return Ok(());
        }
        if let Err(e) = self.g15_perf_dc(5) {
            pc.state.store(STARTED, Ordering::Release);
            if e == ETIMEDOUT {
                dev_err!(
                    dev,
                    "G15 perfctr: device control 5 not consumed in {PERF_DC_WAIT_MS} ms: the memory stays\n"
                );
            }
            return Err(e);
        }
        let running = self.g15_perf_running();
        self.g15_perf_log_rings(pc);
        if running != 0 {
            pc.state.store(STARTED, Ordering::Release);
            dev_err!(
                dev,
                "G15 perfctr: device control 5 done but running reads {running}: the memory stays\n"
            );
            return Err(EIO);
        }
        pc.range_reset();
        pc.state.store(IDLE, Ordering::Release);
        dev_info!(dev, "G15 perfctr: device control 5 done: running 0\n");
        self.g15_perf_log_passes(pc);
        Ok(())
    }

    /// The TA and 3D job words of render pass `cmd` (`g15_rd_pass_run`),
    /// `id` its ID (the 3D job's): `JOB_DEFAULT` with no session memory,
    /// else the session's range words, or the kept words for a pass its
    /// pick or selector keeps (`pack::pass_words`), and the kick IDs'
    /// encoder ID while a kick-mode session or arm is in effect. Counts and
    /// logs them for the session.
    pub(super) fn g15_perf_pass(&self, id: u32, cmd: &G15RdCmd) -> [JobWords; 2] {
        let Some(pc) = self.g15.perfctr_mem.as_ref() else {
            return [JOB_DEFAULT; 2];
        };
        let key = PassKey {
            atts: cmd.atts,
            w: cmd.geom.w,
            h: cmd.geom.h,
            zls: cmd.zls_ctrl,
        };
        let sel = [
            pc.sel[0].load(Ordering::Relaxed),
            pc.sel[1].load(Ordering::Relaxed),
        ];
        let kept = pass_kept(pc.pick.load(Ordering::Relaxed), sel, id, &key);
        let counting = pc.counting.load(Ordering::Relaxed);
        let r = pass_words(
            pc.range[TA].load(Ordering::Relaxed),
            pc.range[D3].load(Ordering::Relaxed),
            pc.keep.load(Ordering::Relaxed),
            kept,
            pc.keep_batch.load(Ordering::Relaxed),
            pc.ids(),
        );
        if counting {
            pc.passes.fetch_add(1, Ordering::Relaxed);
            if cmd.overlap_vertex && !cmd.wait_stores {
                pc.overlap.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(n) = pc.by_atts.get(cmd.atts as usize) {
                n.fetch_add(1, Ordering::Relaxed);
            }
            if kept {
                pc.picked.fetch_add(1, Ordering::Relaxed);
            }
        }
        if kept
            && pc.state.load(Ordering::Relaxed) == STARTED
            && !pc.logged_pick.swap(true, Ordering::Relaxed)
        {
            let ov = if cmd.overlap_vertex {
                ", vertex overlap"
            } else {
                ""
            };
            let ppp = if r[0].batch {
                ", PPP_CTRL |= 0x800"
            } else {
                ""
            };
            dev_info!(
                self.dev.as_ref(),
                "G15 perfctr: the session's first picked pass (ID {id:#x}): {}x{}, {} attachments, ZLS {:#x}{ov}; TA words {:#x}:{:#x}{ppp}, 3D words {:#x}:{:#x}, encoder ID {:#x}\n",
                key.w,
                key.h,
                key.atts,
                key.zls,
                r[0].range.0,
                r[0].range.1,
                r[1].range.0,
                r[1].range.1,
                r[1].enc.unwrap_or(0)
            );
        }
        self.g15_perf_note(pc, TA, &r[0], id.wrapping_add(1), kept);
        self.g15_perf_note(pc, D3, &r[1], id, kept);
        r
    }

    /// Logs a session's render pass counts at its end.
    fn g15_perf_log_passes(&self, pc: &G15PerfCtr) {
        dev_info!(
            self.dev.as_ref(),
            "G15 perfctr: the session picked {} of {} render passes ({} with the vertex overlap)\n",
            pc.picked.load(Ordering::Relaxed),
            pc.passes.load(Ordering::Relaxed),
            pc.overlap.load(Ordering::Relaxed)
        );
    }

    /// The range words of a compute job (`g15_cl_job_new`).
    pub(super) fn g15_perf_cl(&self) -> (u32, u32) {
        let Some(pc) = self.g15.perfctr_mem.as_ref() else {
            return RANGE_ALL;
        };
        let r = range_unpack(pc.range[CL].load(Ordering::Relaxed));
        let w = JobWords {
            range: r,
            ..JOB_DEFAULT
        };
        self.g15_perf_note(pc, CL, &w, 0, false);
        r
    }

    /// Counts a job of stage `s` built with words `w` and logs the
    /// session's first: the proof that a session's jobs carry its words.
    fn g15_perf_note(&self, pc: &G15PerfCtr, s: usize, w: &JobWords, id: u32, kept: bool) {
        let r = w.range;
        if !is_all(r) {
            pc.ranged[s].fetch_add(1, Ordering::Relaxed);
        }
        if pc.state.load(Ordering::Relaxed) == STARTED
            && !pc.logged[s].swap(true, Ordering::Relaxed)
        {
            let ppp = if s == TA && ppp_ctrl(0, w.batch) != 0 {
                ", PPP_CTRL |= 0x800"
            } else {
                ""
            };
            let kept = if kept { ", picked" } else { "" };
            // 0: no kick IDs on the job (a CL job, or no session).
            let kid = w.enc.map_or(0, |e| kick_id(id, e));
            dev_info!(
                self.dev.as_ref(),
                "G15 perfctr: the session's first {} job (ID {id:#x}): range words {:#x}:{:#x}{ppp}{kept}, kick ID {kid:#x}\n",
                STAGES[s],
                r.0,
                r.1
            );
        }
    }

    /// Logs the rings' header and sampler pointers of each source a
    /// session runs on.
    fn g15_perf_log_rings(&self, pc: &G15PerfCtr) {
        for (i, src) in SOURCES.iter().enumerate() {
            if !pc.used(i) {
                continue;
            }
            for k in 0..src.rings as usize {
                let [hr, hw, sr, sw] = pc.ring_ptrs(i, k);
                dev_info!(
                    self.dev.as_ref(),
                    "G15 perfctr: {} ring {k} base {:#x}: header read {hr:#x} write {hw:#x}, sampler +0x18 {sr:#x} +0x20 {sw:#x}\n",
                    src.name,
                    G15PerfCtr::ring_va(i, k)
                );
            }
        }
    }

    /// debugfs `asahi/perfctr` writes: `start [period=N] [src=SRC]
    /// [range…=LO:HI] [pick=M:K] [pickatt=N] [picksize=WxH]
    /// [pickzls=MASK:VAL] COUNTER...` (no counter: build 1's TPU counter; the
    /// tokens: `Session::parse`), `arm` with the same tokens (the range
    /// words, pick and selector put on the jobs before a start, which takes
    /// its own: so the jobs a start finds in flight carry them too) or
    /// `stop` (which also takes an arm's words off with no session).
    pub(crate) fn g15_perfctr_cmd(&self, cmd: &str) -> Result {
        let pc = self.g15.perfctr_mem.as_ref().ok_or(ENODEV)?;
        if cmd == "stop" {
            return self.g15_perfctr_stop(pc);
        }
        let verb = |v: &str| match cmd.strip_prefix(v) {
            Some(a) if a.is_empty() || a.starts_with(|c: char| c.is_ascii_whitespace()) => Some(a),
            _ => None,
        };
        let (args, arm) = match (verb("start"), verb("arm")) {
            (Some(a), _) => (a, false),
            (_, Some(a)) => (a, true),
            _ => return Err(EINVAL),
        };
        let mut buf = KVec::from_elem(pack::Ctr::default(), MAX_CMDS, GFP_KERNEL)?;
        let mut ses = Session::new(&mut buf);
        if let Err((tok, why)) = ses.parse(args) {
            let v = if arm { "arm" } else { "start" };
            dev_err!(self.dev.as_ref(), "G15 perfctr: {v}: {tok}: {why}\n");
            return Err(EINVAL);
        }
        if arm {
            self.g15_perfctr_arm(pc, &ses)
        } else {
            self.g15_perfctr_start(pc, &ses)
        }
    }

    /// Puts `ses`'s range words, pick, selector and kept words on the jobs
    /// built from now on, with their kick IDs in kick mode, with no session:
    /// those a start finds in flight then carry them, where they would carry
    /// `RANGE_ALL` and count whole, or no kick IDs. Counters are ignored;
    /// the start or a stop follows.
    fn g15_perfctr_arm(&self, pc: &G15PerfCtr, ses: &Session<'_>) -> Result {
        let dev = self.dev.as_ref();
        if ses.range.iter().all(|&r| r == RANGE_ALL) && ses.mode != MODE_KICK {
            dev_err!(
                dev,
                "G15 perfctr: arm: no range words and not mode=kick: nothing to put on the jobs\n"
            );
            return Err(EINVAL);
        }
        if pc
            .state
            .compare_exchange(IDLE, BUSY, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            dev_err!(dev, "G15 perfctr: arm: a session is started or busy\n");
            return Err(EBUSY);
        }
        pc.range_set(ses, self.g15.rd_ids.load(Ordering::Relaxed));
        pc.armed.store(true, Ordering::Relaxed);
        pc.state.store(IDLE, Ordering::Release);
        let r = |i: usize| ses.range[i];
        // dev_info!'s arguments take no `if` expression.
        let ids = if ses.mode == MODE_KICK { "on" } else { "off" };
        dev_info!(
            dev,
            "G15 perfctr: armed: range words ta {:#x}:{:#x} 3d {:#x}:{:#x} cl {:#x}:{:#x}, pick {}:{}, selector {}, keep {:#x}:{:#x} batch {}, kick IDs {}\n",
            r(TA).0,
            r(TA).1,
            r(D3).0,
            r(D3).1,
            r(CL).0,
            r(CL).1,
            ses.pick.0,
            ses.pick.1,
            SelFmt(sel_pack(ses.sel)),
            ses.keep.0,
            ses.keep.1,
            u8::from(ses.keep_batch),
            ids
        );
        Ok(())
    }

    /// debugfs `asahi/perfctr` reads: the session as the firmware sees it
    /// (the perf area, each source's state, each counter's record and read
    /// word) and the first 0x200 bytes of each ring of a source it runs on.
    pub(crate) fn g15_perfctr_show(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(pc) = self.g15.perfctr_mem.as_ref() else {
            return writeln!(f, "perfctr: no session memory");
        };
        let state = match pc.state.load(Ordering::Acquire) {
            IDLE => "idle",
            BUSY => "busy",
            _ => "started",
        };
        let lay = pc.lay;
        let ev = self.g15_ev().cast_const();
        let pa = ev.wrapping_add(fw::g15::PERF_AREA_OFF);
        crate::mem::dc_civac(pa, lay.end - fw::g15::PERF_AREA_OFF);
        // SAFETY: in-bounds reads of the event page's perf area.
        let (running, ncmds, tpu, pbe) = unsafe {
            (
                r32(ev, lay.running),
                r32(ev, PERF_NCMDS),
                r64(ev, lay.fmt[0]),
                r64(ev, lay.fmt[1]),
            )
        };
        writeln!(
            f,
            "state {state} ended_by_recovery {} ctx {} ring_va {RING_VA:#x} ring_bytes {RING_BYTES:#x} fw {}",
            pc.ended.load(Ordering::Acquire),
            pc.ctx,
            lay.name
        )?;
        // 27.2's formats are triples: the value, then its mask.
        let (tm, pm) = if lay.v272 {
            // SAFETY: in-bounds reads of the event page's perf area.
            unsafe { (r64(ev, lay.fmt[0] + 8), r64(ev, lay.fmt[1] + 8)) }
        } else {
            (u64::MAX, u64::MAX)
        };
        writeln!(
            f,
            "running(+{:#X}) {running} ncmds(+{PERF_NCMDS:#X}) {ncmds} tpu(+{:#X}) {tpu:#x}/{tm:#x} pbe(+{:#X}) {pbe:#x}/{pm:#x}",
            lay.running,
            lay.fmt[0],
            lay.fmt[1]
        )?;
        // The words the jobs built from now on carry, and the session's
        // counts of jobs that carried others.
        write!(f, "range")?;
        for (i, name) in STAGES.iter().enumerate() {
            let (lo, hi) = range_unpack(pc.range[i].load(Ordering::Relaxed));
            write!(f, " {name} {lo:#x}:{hi:#x}")?;
        }
        let pick = pc.pick.load(Ordering::Relaxed);
        write!(
            f,
            " pick {}:{} from {:#x} ranged",
            pick & 0xFFFF,
            (pick >> 16) & 0xFFFF,
            pick >> 32
        )?;
        for (i, name) in STAGES.iter().enumerate() {
            write!(f, " {name} {}", pc.ranged[i].load(Ordering::Relaxed))?;
        }
        writeln!(f, " picked {}", pc.picked.load(Ordering::Relaxed))?;
        let sel = [
            pc.sel[0].load(Ordering::Relaxed),
            pc.sel[1].load(Ordering::Relaxed),
        ];
        write!(
            f,
            "select {} armed {} passes {} overlap {} atts",
            SelFmt(sel),
            u8::from(pc.armed.load(Ordering::Relaxed)),
            pc.passes.load(Ordering::Relaxed),
            pc.overlap.load(Ordering::Relaxed)
        )?;
        for (i, n) in pc.by_atts.iter().enumerate() {
            match n.load(Ordering::Relaxed) {
                0 => {}
                n => write!(f, " {i}:{n}")?,
            }
        }
        writeln!(f)?;
        // What a kept pass carries, and whether the jobs built now write
        // their kick IDs (a kick-mode session or arm in effect).
        let (klo, khi) = range_unpack(pc.keep.load(Ordering::Relaxed));
        writeln!(
            f,
            "kick mode {} keep {klo:#x}:{khi:#x} keepbatch {} ids {} enc kept {:#x} other {:#x}",
            pc.mode.load(Ordering::Relaxed),
            u8::from(pc.keep_batch.load(Ordering::Relaxed)),
            u8::from(pc.ids()),
            pack::ENC_KEPT,
            pack::ENC_OTHER
        )?;
        for (i, src) in SOURCES.iter().enumerate() {
            let st = pc.state_ptr(i);
            // SAFETY: in-bounds reads of source i's state.
            let w = unsafe {
                [
                    r32(st, lay.st_active),
                    r32(st, lay.st_mode),
                    r32(st, lay.st_flags),
                    r32(st, lay.st_period),
                    r32(st, lay.st_anypart),
                    r32(st, lay.st_nprog),
                ]
            };
            write!(
                f,
                "source {i} {} active(+{:#X}) {} mode(+{:#X}) {} flags(+{:#X}) {:#x} period(+{:#X}) {:#x} ",
                src.name,
                lay.st_active,
                w[0],
                lay.st_mode,
                w[1],
                lay.st_flags,
                w[2],
                lay.st_period,
                w[3]
            )?;
            if let Some(o) = lay.st_on {
                // SAFETY: an in-bounds read of source i's state.
                let on = unsafe { *st.add(o) };
                write!(f, "on(+{o:#X}) {on} ")?;
            }
            writeln!(
                f,
                "anypart(+{:#X}) {} prog(+{:#X}) {} prologue {} rings {}",
                lay.st_anypart, w[4], lay.st_nprog, w[5], PROLOGUE[i], src.rings
            )?;
        }
        // The counters: the records in source order, as many for each
        // source a session runs on as its program has words past the
        // prologue.
        let mut j = 0;
        for (i, src) in SOURCES.iter().enumerate() {
            if !pc.used(i) {
                continue;
            }
            let st = pc.state_ptr(i);
            // SAFETY: an in-bounds read of source i's state.
            let nprog = (unsafe { r32(st, lay.st_nprog) } as usize).min(pack::PROG_MAX);
            for k in PROLOGUE[i]..nprog {
                if j >= (ncmds as usize).min(MAX_CMDS) {
                    break;
                }
                let r = pa.wrapping_add(0x20 * j);
                // 14.8.3's record: the partition in +0's low 6 bits, the
                // select +0x10, the slots +0x19, the index +0x1A; 27.2's
                // (`pack::record_272`): +0's byte, +0x14, +0x1D, +0x1E.
                let (at_sel, at_slots, part_mask) = if lay.v272 {
                    (0x14, 0x1D, 0xFF)
                } else {
                    (0x10, 0x19, 0x3F)
                };
                // SAFETY: in-bounds reads of record j of the perf area and
                // of program word k of source i's state.
                let (w0, sel32, sel64, slots, idx, gidx, word) = unsafe {
                    (
                        r64(r, 0),
                        r32(r, at_sel),
                        r64(r, 8),
                        *r.add(at_slots),
                        *r.add(at_slots + 1),
                        *r.add(0x10),
                        r64(st, lay.st_prog + 8 * k),
                    )
                };
                let part = (w0 & part_mask) as usize;
                let name = PARTS.get(part).map_or("?", |p| p.name);
                // A Global read's record: +8 the select, +0x10 the index.
                let (sel, idx) = if part == 1 {
                    (sel64, gidx)
                } else {
                    (u64::from(sel32), idx)
                };
                writeln!(
                    f,
                    "counter {} {} word {k} part {part} {name} select {sel:#x} slots {slots} idx {idx} read {word:#x}",
                    src.name,
                    k - PROLOGUE[i]
                )?;
                j += 1;
            }
        }
        for (i, src) in SOURCES.iter().enumerate() {
            if !pc.used(i) {
                continue;
            }
            for k in 0..src.rings as usize {
                let [hr, hw, sr, sw] = pc.ring_ptrs(i, k);
                writeln!(
                    f,
                    "ring {} {k} base {:#x} off {:#x} size {RING:#x} hdr+0x20 {hr:#x} hdr+0x30 {hw:#x} smp+0x18 {sr:#x} smp+0x20 {sw:#x}",
                    src.name,
                    G15PerfCtr::ring_va(i, k),
                    area_off(i) + k * RING
                )?;
            }
        }
        for (i, src) in SOURCES.iter().enumerate() {
            if !pc.used(i) {
                continue;
            }
            for k in 0..src.rings as usize {
                let p = pc
                    .ring_ptr()
                    .cast_const()
                    .wrapping_add(area_off(i) + k * RING);
                crate::mem::dc_civac(p, 0x200);
                for line in 0..0x200 / 0x20 {
                    // SAFETY: in-bounds reads of the ring's first 0x200
                    // bytes.
                    let w = unsafe {
                        [
                            r64(p, line * 0x20),
                            r64(p, line * 0x20 + 8),
                            r64(p, line * 0x20 + 0x10),
                            r64(p, line * 0x20 + 0x18),
                        ]
                    };
                    writeln!(
                        f,
                        "ring {} {k} +{:03x}: {:016x} {:016x} {:016x} {:016x}",
                        src.name,
                        line * 0x20,
                        w[0],
                        w[1],
                        w[2],
                        w[3]
                    )?;
                }
            }
        }
        Ok(())
    }

    /// debugfs `asahi/perfctr_rings` reads: the ring object (`RING_BYTES`,
    /// each source's area at `area_off`), raw. Read after a stop for whole
    /// records: during a session the RDEs write it as it is copied.
    pub(crate) fn g15_perfctr_rings(
        &self,
        w: &mut UserSliceWriter,
        off: &mut Offset,
    ) -> Result<usize> {
        let pc = self.g15.perfctr_mem.as_ref().ok_or(ENODEV)?;
        let start = usize::try_from(*off).map_err(|_| EINVAL)?;
        if start >= RING_BYTES {
            return Ok(0);
        }
        let n = w.len().min(RING_BYTES - start);
        let p = pc.ring_ptr().cast_const().wrapping_add(start);
        crate::mem::dc_civac(p, n);
        // SAFETY: `start + n` lies within the ring object, mapped for the
        // device's lifetime. The RDEs may write these bytes during a
        // session: a copy then holds a torn record, never anything else.
        let chunk = unsafe { core::slice::from_raw_parts(p, n) };
        w.write_slice(chunk)?;
        *off += n as Offset;
        Ok(n)
    }
}
