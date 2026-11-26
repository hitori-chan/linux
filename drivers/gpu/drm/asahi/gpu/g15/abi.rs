// SPDX-License-Identifier: GPL-2.0-only

//! The firmware's job, channel and control layouts by version: one table
//! per structure, its fields' offsets and the numbers that changed from
//! macOS 14.8.3's, the layouts the other G15 modules were written against.
//! V27_2's are macOS 27.2's. A field the 27.2 spec gives as inferred says
//! so; the rest are traced there.
//!
//! The tables name only what the driver writes or reads. Offsets are a
//! buffer's, but for the TA and 3D context records', which are their
//! payload's (the record's + 4), as the builders' `p()` takes them.
//!
//! Spec: channel.md, cl-job.md, render-job.md, stream.md, power.md (14.8.3);
//! fw272-jobs.md, fw272-control.md, fw272-hwdata.md (27.2).

#![allow(
    clippy::let_and_return,
    reason = "a table's block binds each version's value under its #[ver], one left"
)]

use super::*;

/// The channel state and the job-slot object (fw272-jobs.md §1, §2).
pub(super) struct Chan {
    /// The sub-level, the kick's pending row: 0.
    pub(super) sub_level: usize,
    /// 0xFFFFFFFF.
    pub(super) neg1: usize,
    /// The owner's pid.
    pub(super) pid: usize,
    /// The consumer's first-use flag, the word it sets to 1 and the kick
    /// count, which the dumps show.
    pub(super) first_use: usize,
    pub(super) one: usize,
    pub(super) kicks: usize,
    /// The job-slot object's FW VA.
    pub(super) job_slot: usize,
    /// The job-slot object's slot byte (the role weight), which the release
    /// names.
    pub(super) slot_byte: usize,
    /// The job-slot object's TGMEM slot (0xFF: none) and the u32 after
    /// 14.8.3's (27.2: before), 0.
    pub(super) tgmem: usize,
    pub(super) slot_zero: usize,
}

#[versions(AGX)]
pub(super) const CHAN: Chan = {
    let t = Chan {
        sub_level: 0x44,
        neg1: 0x48,
        pid: 0x4C,
        first_use: 0x50,
        one: 0x54,
        kicks: 0x6C,
        job_slot: 0x78,
        slot_byte: 0x26,
        tgmem: 0x33,
        slot_zero: 0x22,
    };
    t
};

/// Device control: the control ring's entries, the doorbell and the
/// command numbers the driver sends (fw272-control.md §2).
pub(super) struct Ctl {
    /// An entry's size, in bytes and in u32 words.
    pub(super) entry: usize,
    pub(super) words: usize,
    /// The doorbell message.
    pub(super) bell: u64,
    /// The PB-grow ack, the channel-error answer, the release (and the
    /// cache flush) and ForceConfigSnapshot.
    pub(super) pb_grow_ack: u32,
    pub(super) chan_err_answer: u32,
    pub(super) release: u32,
    pub(super) config_snapshot: u32,
}

#[versions(AGX)]
pub(super) const CTL: Ctl = {
    let t = Ctl {
        entry: 0x40,
        words: 16,
        bell: 0x84 << 48 | DOORBELL_DEVCTRL,
        pb_grow_ack: 8,
        chan_err_answer: 9,
        release: 0x13,
        config_snapshot: 0x15,
    };
    // The entries fill the storage's 256 slots (0x3800 bytes, 27.2: 0x4000).
    assert!(t.entry == 4 * t.words);
    t
};

/// Whether a 27.2 device-control command counts as a power assertion
/// (`dcrCommandToPowerAssertion` 0xfffffe0007143684, 0x44 entries; the
/// firmware's `byte_FFFFFC00000586C0`, 0x40, the same over 0..0x3F): the host
/// bumps the counter channel table +0x18 points at for each
/// (fw272-control.md §2.2). The firmware counts the ones it has consumed
/// (event page +0xEDC8) and, finding the two apart with the GPU off, powers
/// it on before it runs the ring (`sub_FFFFFC00000035BC`, `sub_3732C`).
pub(super) const fn ctl_asserts_272(cmd: u32) -> bool {
    matches!(
        cmd,
        1..=0xD | 0xF..=0x12 | 0x16..=0x19 | 0x1C..=0x21 | 0x23..=0x29 | 0x2B..=0x2D | 0x30..=0x3C
    )
}

/// The stamp barrier record, type 4 (fw272-jobs.md §4). Its job ID is a
/// u64.
pub(super) struct Barrier {
    /// The awaited stamp index, the job's own stamp, its ID, the host flag
    /// and the last word (0).
    pub(super) index: usize,
    pub(super) own_stamp: usize,
    pub(super) job_id: usize,
    pub(super) host: usize,
    pub(super) last: usize,
    /// 27.2's new word, 0.
    pub(super) zero: Option<usize>,
}

#[versions(AGX)]
pub(super) const BARRIER: Barrier = {
    let t = Barrier {
        index: 0x20,
        own_stamp: 0x24,
        job_id: 0x28,
        host: 0x30,
        last: 0x3C,
        zero: Some(0x38),
    };
    t
};

/// The notifier node (fw272-control.md §1).
pub(super) struct Ntf {
    /// The node's allocation, and how much of it the firmware copies and
    /// cleans.
    pub(super) size: usize,
    pub(super) used: usize,
}

#[versions(AGX)]
pub(super) const NTF: Ntf = {
    let t = Ntf {
        size: 0x100,
        used: 0xC8,
    };
    t
};

/// The timestamp record, type 3 (fw272-jobs.md §9.1). Its first fields
/// (+0x04 the slot, +0x0C and +0x14 the start and end pointers, +0x1C the
/// channel state, +0x24 the user pair, +0x2C the end slot) are the same in
/// both.
pub(super) struct TsRec {
    pub(super) size: usize,
    pub(super) job_id: usize,
    /// 27.2's pointer to the job state's tick block (`JobTs::block`), whose
    /// +0x10/+0x18 the firmware stores the start and end ticks at.
    pub(super) block: Option<usize>,
}

#[versions(AGX)]
pub(super) const TS_REC: TsRec = {
    // `encodeTimeStamp` 0xfffffe0008be8738: +0x2C/+0x34 one 16-byte store
    // of the job state + {end slot, block}; +0x3C the multi-timestamp list
    // only when the job state's pointer array is set (never here: left 0).
    let t = TsRec {
        size: 0x4C,
        job_id: 0x44,
        block: Some(0x34),
    };
    t
};

/// A job state's fields that every class has, by class.
pub(super) struct JobCommon {
    /// The allocation: macOS's pool element on 14.8.3, the firmware's
    /// record size on 27.2.
    pub(super) size: usize,
    /// The notifier.
    pub(super) ntf: usize,
    /// The host and firmware stamp words, the stamp, the stamp index, the
    /// channel index, the IO fences and the job ID.
    pub(super) host_word: usize,
    pub(super) fw_word: usize,
    pub(super) stamp: usize,
    pub(super) stamp_index: usize,
    pub(super) chan_index: usize,
    pub(super) io_fences: usize,
    pub(super) job_id: usize,
    /// The timestamp slot, the GPU start pointer (the end's 8 on), the user
    /// start timestamp (the end's 8 on), the end slot and 27.2's tick block
    /// (0 on 14.8.3: none).
    pub(super) ts_slot: usize,
    pub(super) gpu_start: usize,
    pub(super) user_ts: usize,
    pub(super) end_slot: usize,
    pub(super) ts_block: usize,
    /// The first and last batch the counters count (u32 each), which the
    /// executor writes into their batch filter at a perf marker
    /// (`AGFA_Executor` case 4; 27.2's `sub_FFFFFC0000018020`: TA
    /// 0xfffffc000001b3c0, 3D 0xfffffc000001a2dc, CL 0xfffffc000001b1f0):
    /// TA +0x844, 3D +0xB8C, CL +0x7E4, the tick block's +8 for every
    /// class.
    pub(super) perf_range: usize,
    /// The UMA pool's state, its clean-and-invalidate flag and the metrics
    /// slot.
    pub(super) uma: usize,
    pub(super) uma_flag: usize,
    pub(super) metrics: usize,
}

/// The CL job state (fw272-jobs.md §6.1).
pub(super) struct ClJs {
    pub(super) c: JobCommon,
    /// The context ID.
    pub(super) ctx: usize,
    /// Whether the register list's size sits next to its count, at +0x72A
    /// (27.2 writes the u16 count alone).
    pub(super) list_size: bool,
    /// The preemption save area, then the CDM stream's end.
    pub(super) preempt: usize,
    /// The chip configuration word.
    pub(super) chip_cfg: usize,
    /// The queue's CL counter.
    pub(super) counter: usize,
    /// The words the finish record's last two pointers name: the stale
    /// flag and the one after the bind generation.
    pub(super) stale: usize,
    pub(super) fin_word: usize,
}

#[versions(AGX)]
pub(super) const CL_JS: ClJs = {
    let t = ClJs {
        c: JobCommon {
            size: 0x8E0,
            ntf: 0x10,
            host_word: 0x800,
            fw_word: 0x808,
            stamp: 0x810,
            stamp_index: 0x814,
            chan_index: 0x818,
            io_fences: 0x81C,
            job_id: 0x820,
            ts_slot: 0x82C,
            gpu_start: 0x834,
            user_ts: 0x844,
            end_slot: 0x8A3,
            ts_block: 0x7DC,
            perf_range: 0x7E4,
            uma: 0x86A,
            uma_flag: 0x872,
            metrics: 0x883,
        },
        ctx: 0x0C,
        list_size: false,
        preempt: 0x798,
        chip_cfg: 0x7C8,
        counter: 0x828,
        stale: 0x8B3,
        fin_word: 0x893,
    };
    // Every field the driver writes lies inside the allocation.
    assert!(t.c.end_slot + 8 <= t.c.size && t.stale + 8 <= t.c.size);
    assert!(t.c.metrics + 8 <= t.c.size && t.counter + 4 <= t.c.size);
    assert!(t.c.perf_range == t.c.ts_block + 8);
    t
};

/// The CL stream (fw272-jobs.md §6.2): the context record's fields
/// (buffer offsets, its payload's + 4), the records' places, and the finish
/// record's fields (from its start).
pub(super) struct ClStrm {
    /// The stream's slot, its records' size rounded up to 0x40
    /// (`finishEncode`).
    pub(super) slot: u32,
    pub(super) ctx_job_id: usize,
    /// The UMA group (the pool state), the metrics slot, the four context
    /// stores, the stale pointer, the counter (job state +0x04) and the
    /// stamp index.
    pub(super) ctx_uma: usize,
    pub(super) ctx_metrics: usize,
    pub(super) ctx_store: usize,
    pub(super) ctx_stale: usize,
    pub(super) ctx_counter: usize,
    pub(super) ctx_stamp_index: Option<usize>,
    /// The two timestamps, the wait for idle between them, the finish
    /// record and the terminator.
    pub(super) ts1: usize,
    pub(super) wfi: usize,
    pub(super) ts2: usize,
    pub(super) fin: usize,
    pub(super) term: usize,
    /// The finish record's job ID, firmware stamp word, stamp, dependency
    /// flag, payload pointer (the context's UMA group), rewind, flags, and
    /// its two pointers into the job state.
    pub(super) fin_job_id: usize,
    pub(super) fin_fw_word: usize,
    pub(super) fin_stamp: usize,
    pub(super) fin_dep: usize,
    pub(super) fin_payload: usize,
    pub(super) fin_rewind: usize,
    pub(super) fin_flags: usize,
    pub(super) fin_stale: usize,
    pub(super) fin_word: usize,
}

#[versions(AGX)]
pub(super) const CL_STRM: ClStrm = {
    let t = ClStrm {
        slot: 0x300,
        ctx_job_id: 0x50,
        ctx_uma: 0x160,
        ctx_metrics: 0x178,
        ctx_store: 0x188,
        ctx_stale: 0x1A8,
        ctx_counter: 0x1B0,
        ctx_stamp_index: Some(0x1B8),
        ts1: 0x1BC,
        wfi: 0x208,
        ts2: 0x20C,
        fin: 0x258,
        term: 0x2D4,
        fin_job_id: 0x24,
        fin_fw_word: 0x2C,
        fin_stamp: 0x34,
        fin_dep: 0x58,
        fin_payload: 0x5C,
        fin_rewind: 0x64,
        fin_flags: 0x68,
        fin_stale: 0x69,
        fin_word: 0x71,
    };
    // The records follow each other: the context record (0x1BC bytes, 27.2:
    // 0x1BC), the timestamps around the wait for idle (4), the finish
    // record (0x7C, 27.2: 0x7C) and the terminator (4), in a slot of their
    // size rounded up to 0x40.
    let ts = TS_REC::ver.size;
    assert!(t.wfi == t.ts1 + ts && t.ts2 == t.wfi + 4 && t.fin == t.ts2 + ts);
    // The slot the job state carries (`perf_slot`, as `finishEncode`
    // stores it): without the perf markers, then with both, inside the
    // 0x400-byte stream buffer.
    assert!(perf_slot(t.term + 4, 0) == t.slot);
    assert!(perf_slot(t.term + 4, PERF_MARKER) <= 0x400);
    assert!(perf_slot(t.term + 4, PERF_MARKER) == 0x300);
    assert!(t.ts1 == 0x1BC && t.term == t.fin + 0x7C);
    t
};

/// The TA job state (fw272-jobs.md §7.1).
pub(super) struct TaJs {
    pub(super) c: JobCommon,
    /// The parameter buffer's ID, the word after it (0), the info, the
    /// scene and the trailer.
    pub(super) pbid: usize,
    pub(super) zero: usize,
    pub(super) info: usize,
    pub(super) scene: usize,
    pub(super) trailer: usize,
    /// The PB-grow wait.
    pub(super) grow_wait: usize,
    /// The words the context and finish records point at: the flags, the
    /// barrier state and the one after the bind generation.
    pub(super) flags: usize,
    pub(super) barrier: usize,
    pub(super) fin_word: usize,
    /// The queue's TA counter.
    pub(super) counter: usize,
}

#[versions(AGX)]
pub(super) const TA_JS: TaJs = {
    // The allocation: the firmware's TA record size, 0x940, which the last
    // field (+0x937) fills (I: macOS's pool element not read).
    let t = TaJs {
        c: JobCommon {
            size: 0x940,
            ntf: 0x10,
            host_word: 0x878,
            fw_word: 0x880,
            stamp: 0x888,
            stamp_index: 0x88C,
            chan_index: 0x890,
            io_fences: 0x894,
            job_id: 0x898,
            ts_slot: 0x8C0,
            gpu_start: 0x8C8,
            user_ts: 0x8D8,
            end_slot: 0x92F,
            ts_block: 0x83C,
            perf_range: 0x844,
            uma: 0x8FE,
            uma_flag: 0x906,
            metrics: 0x90F,
        },
        pbid: 0x18,
        zero: 0x1C,
        info: 0x20,
        scene: 0x28,
        trailer: 0x30,
        grow_wait: 0x864,
        flags: 0x85C,
        barrier: 0x8A8,
        fin_word: 0x91F,
        counter: 0x8A0,
    };
    // Every field the driver writes lies inside the allocation.
    assert!(t.c.end_slot + 8 <= t.c.size && t.fin_word + 8 <= t.c.size);
    assert!(t.c.metrics + 8 <= t.c.size && t.counter + 4 <= t.c.size);
    assert!(t.c.perf_range == t.c.ts_block + 8);
    t
};

/// The TA stream (fw272-jobs.md §7.2): the context record's fields (its
/// payload's offsets), the records' places and the finish record's fields.
pub(super) struct TaStrm {
    pub(super) slot: u32,
    /// The job ID, the item count, the command-data descriptor (the UMA
    /// pool state), the metrics slot, the counter (job state +0x04) and the
    /// stamp index.
    pub(super) ctx_job_id: usize,
    pub(super) ctx_count: usize,
    pub(super) ctx_uma: usize,
    pub(super) ctx_metrics: usize,
    pub(super) ctx_counter: usize,
    pub(super) ctx_stamp_index: Option<usize>,
    pub(super) ts1: usize,
    pub(super) wfi: usize,
    pub(super) ts2: usize,
    pub(super) fin: usize,
    pub(super) term: usize,
    /// The finish record's job ID, firmware stamp word, stamp, stream
    /// pointer (the context's UMA descriptor), rewind and last pointer.
    pub(super) fin_job_id: usize,
    pub(super) fin_fw_word: usize,
    pub(super) fin_stamp: usize,
    pub(super) fin_payload: usize,
    pub(super) fin_rewind: usize,
    pub(super) fin_word: usize,
}

#[versions(AGX)]
pub(super) const TA_STRM: TaStrm = {
    // The context record's map: `encodeTACommandSKUStream` 0xfffffe0008bb96bc
    // against 1483's 0xfffffe0008e9d3bc (the 0x1C8-byte payload built on
    // the stack and copied); +0x00…+0x74 keep their places.
    let t = TaStrm {
        slot: 0x300,
        ctx_job_id: 0x78,
        ctx_count: 0x184,
        ctx_uma: 0x18C,
        ctx_metrics: 0x1A4,
        ctx_counter: 0x1B4,
        ctx_stamp_index: Some(0x1BC),
        ts1: 0x1CC,
        wfi: 0x218,
        ts2: 0x21C,
        fin: 0x268,
        term: 0x2FC,
        fin_job_id: 0x40,
        fin_fw_word: 0x48,
        fin_stamp: 0x50,
        fin_payload: 0x78,
        fin_rewind: 0x80,
        fin_word: 0x85,
    };
    // The records follow each other: the context record (0x1CC bytes, 27.2:
    // 0x1CC), the timestamps around the wait for idle (4), the finish
    // record (0x8C, 27.2: 0x94) and the terminator (4), in a slot of their
    // size rounded up to 0x40.
    let ts = TS_REC::ver.size;
    assert!(t.wfi == t.ts1 + ts && t.ts2 == t.wfi + 4 && t.fin == t.ts2 + ts);
    // The slot the job state carries (`perf_slot`, as `finishEncode`
    // stores it): without the perf markers, then with both, inside the
    // 0x400-byte stream buffer.
    assert!(perf_slot(t.term + 4, 0) == t.slot);
    assert!(perf_slot(t.term + 4, PERF_MARKER) <= 0x400);
    assert!(perf_slot(t.term + 4, PERF_MARKER) == 0x340);
    assert!(t.ts1 == 0x1CC && t.term == t.fin + 0x94);
    t
};

/// The 3D job state (fw272-jobs.md §8.1); +0x00…+0xB93 are the same in
/// both.
pub(super) struct D3Js {
    pub(super) c: JobCommon,
    /// The first store pass's process-empty-tiles flag.
    pub(super) process_empty: usize,
    /// The words the context and finish records point at: the fourth flag,
    /// 27.2's new word after the four flags, and the fragment barrier.
    pub(super) flag4: usize,
    pub(super) flag5: Option<usize>,
    pub(super) frag_barrier: usize,
    /// The word after the job ID (0), and the one after the bind
    /// generation, which the finish record points at.
    pub(super) zero: usize,
    pub(super) fin_word: usize,
}

#[versions(AGX)]
pub(super) const D3_JS: D3Js = {
    // The allocation: the firmware's 3D record size (I: macOS's pool
    // element not read). `process_empty` is the executor's read for the
    // tile word's bit 16, +0xBAC the reload pass's (`sub_FFFFFC0000018020`
    // 0x1c794, 0x1c2b4; 14.8.3's `AGFA_Executor` 0x1d4d4 +0xB98, 0x1d018
    // +0xB9C).
    let t = D3Js {
        c: JobCommon {
            size: 0xCA0,
            ntf: 0x20,
            host_word: 0xBC0,
            fw_word: 0xBC8,
            stamp: 0xBD0,
            stamp_index: 0xBD4,
            chan_index: 0xBD8,
            io_fences: 0xBDC,
            job_id: 0xBE0,
            ts_slot: 0xC08,
            gpu_start: 0xC10,
            user_ts: 0xC20,
            end_slot: 0xC77,
            ts_block: 0xB84,
            perf_range: 0xB8C,
            uma: 0xC46,
            uma_flag: 0xC4E,
            metrics: 0xC57,
        },
        process_empty: 0xBA8,
        flag4: 0xBB0,
        flag5: Some(0xBB4),
        frag_barrier: 0xBF0,
        zero: 0xBE8,
        fin_word: 0xC67,
    };
    // Every field the driver writes lies inside the allocation.
    assert!(t.c.end_slot + 8 <= t.c.size && t.fin_word + 8 <= t.c.size);
    assert!(t.c.metrics + 8 <= t.c.size);
    assert!(t.c.perf_range == t.c.ts_block + 8);
    t
};

/// The 3D stream (fw272-jobs.md §8.2): the context record's fields (its
/// payload's offsets), the records' places and the finish record's fields.
pub(super) struct D3Strm {
    pub(super) slot: u32,
    /// The context record: the channel state, the job state, the context
    /// ID, the soft-fault word, the notifier key, the PB ID, the four
    /// words from the partial-render flag on (0), the pointers to the job
    /// state's +0xA58 and fragment barrier, the job ID, the SLC ranges and
    /// their count, the UMA pool state, the metrics slot, the counter (job
    /// state +0x04) and the stamp index.
    /// +0x10…+0x28 and the pointers to the fourth flag (+0x38) keep their
    /// places.
    pub(super) ctx_state: usize,
    pub(super) ctx_js: usize,
    pub(super) ctx_ctx: usize,
    pub(super) ctx_soft: usize,
    pub(super) ctx_key: usize,
    pub(super) ctx_pbid: usize,
    pub(super) ctx_flags: usize,
    pub(super) ctx_a58: usize,
    pub(super) ctx_frag_barrier: usize,
    pub(super) ctx_job_id: usize,
    pub(super) ctx_slc: usize,
    pub(super) ctx_slc_count: usize,
    pub(super) ctx_uma: usize,
    pub(super) ctx_metrics: usize,
    pub(super) ctx_counter: usize,
    pub(super) ctx_stamp_index: Option<usize>,
    pub(super) ts1: usize,
    pub(super) wfi: usize,
    pub(super) ts2: usize,
    pub(super) fin: usize,
    pub(super) term: usize,
    /// The finish record: +0x30's buffer, the pointers to the fourth flag,
    /// 27.2's new word and +0xB70, the channel state, the job state, the
    /// context ID, the stream pointer (the context's UMA pool state), the
    /// rewind, the last pointer and 27.2's stamp index.
    pub(super) fin_b220: usize,
    pub(super) fin_flag4: usize,
    pub(super) fin_flag5: Option<usize>,
    pub(super) fin_b70: usize,
    pub(super) fin_state: usize,
    pub(super) fin_js: usize,
    pub(super) fin_ctx: usize,
    pub(super) fin_payload: usize,
    pub(super) fin_rewind: usize,
    pub(super) fin_word: usize,
    pub(super) fin_stamp_index: Option<usize>,
}

#[versions(AGX)]
pub(super) const D3_STRM: D3Strm = {
    // The context record's map: `encode3DCommandSKUStream` 0xfffffe0008baeb2c
    // against 1483's 0xfffffe0008e92e0c (the payload built on the stack and
    // copied, 0x1E0 bytes, was 0x1D8).
    let t = D3Strm {
        slot: 0x340,
        ctx_state: 0x48,
        ctx_js: 0x50,
        ctx_ctx: 0x58,
        ctx_soft: 0x5C,
        ctx_key: 0x60,
        ctx_pbid: 0x64,
        ctx_flags: 0x68,
        ctx_a58: 0x78,
        ctx_frag_barrier: 0x80,
        ctx_job_id: 0x9C,
        ctx_slc: 0xA4,
        ctx_slc_count: 0x1A4,
        ctx_uma: 0x1AC,
        ctx_metrics: 0x1C4,
        ctx_counter: 0x1D4,
        ctx_stamp_index: Some(0x1DC),
        ts1: 0x1E4,
        wfi: 0x230,
        ts2: 0x234,
        fin: 0x280,
        term: 0x334,
        fin_b220: 0x30,
        fin_flag4: 0x38,
        fin_flag5: Some(0x40),
        fin_b70: 0x48,
        fin_state: 0x50,
        fin_js: 0x58,
        fin_ctx: 0x60,
        fin_payload: 0x98,
        fin_rewind: 0xA0,
        fin_word: 0xA5,
        fin_stamp_index: Some(0xAD),
    };
    // The records follow each other: the context record (0x1DC bytes, 27.2:
    // 0x1E4), the timestamps around the wait for idle (4), the finish
    // record (0xB4, 27.2: 0xB4) and the terminator (4), in a slot of their
    // size rounded up to 0x40.
    let ts = TS_REC::ver.size;
    assert!(t.wfi == t.ts1 + ts && t.ts2 == t.wfi + 4 && t.fin == t.ts2 + ts);
    // The slot the job state carries (`perf_slot`, as `finishEncode`
    // stores it): without the perf markers, then with both, inside the
    // 0x400-byte stream buffer.
    assert!(perf_slot(t.term + 4, 0) == t.slot);
    assert!(perf_slot(t.term + 4, PERF_MARKER) <= 0x400);
    assert!(perf_slot(t.term + 4, PERF_MARKER) == 0x380);
    assert!(t.ts1 == 0x1E4 && t.term == t.fin + 0xB4);
    t
};

/// The event page's recovery block and progress words (fw272-hwdata.md
/// §1.7).
pub(super) struct EvPage {
    /// The job table and its entries (8 bytes each).
    pub(super) jobs: usize,
    pub(super) jobs_n: usize,
    /// The GPU restart record: +0x04 the caught jobs, +0x0C the pid, +0x10
    /// the kill, +0x14 the fault bank, +0xC0 the busy mask.
    pub(super) restart: usize,
    /// The stop count (u64), the stopped flag, the host-requested word,
    /// the progress word and the word the host's re-init sets to 1.
    pub(super) stops: usize,
    pub(super) stopped: usize,
    pub(super) host_req: usize,
    pub(super) progress: usize,
    pub(super) one: usize,
    /// The word the next configuration snapshot reads, 0 at boot.
    pub(super) snap: usize,
    /// The bytes the recovery dump and the progress check clean first.
    pub(super) dump_len: usize,
    pub(super) poll_len: usize,
}

#[versions(AGX)]
pub(super) const EVP: EvPage = {
    // The job table: `restartWorkQueue` passes event page + 0x4298
    // (0xfffffe0008b41038), and `processFirmwareInitiatedRecovery` walks
    // 0x1C0 entries. The restart record's fields keep their places:
    // `drainFirmwareEventRing` reads +0x00, +0x0C…+0x20 and +0x28…+0xC0
    // from 0x509C, 1483's from 0x44A0; the firmware fills +0x04 as 14.8.3's
    // does (`sub_FFFFFC000000772C` 0x87b0, 1483's `agx_recovery_handler`
    // 0xc140). The stopped flag
    // (`isFirmwareStopped*` 0xfffffe0008b9c2b4…2f4), the host-requested
    // word (`isFirmwareStoppedForHostRecovery`) and the progress word
    // (`checkGPUProgress`) are the kext's reads; 27.2 resumes through the
    // stopped flag (`resumeFirmwarePre/PostRecovery`), with no resume word.
    let t = EvPage {
        jobs: 0x4298,
        jobs_n: 0x1C0,
        restart: 0x509C,
        stops: 0x5180,
        stopped: 0x5190,
        host_req: 0x51A0,
        progress: 0x51B0,
        one: 0x51B4,
        snap: 0xCFB8,
        dump_len: 0xF1C,
        poll_len: 0x38,
    };
    t
};

/// The host-stop message (EP 0x21), the stop count in its low 44 bits,
/// which the firmware compares with the event page's (`EVP::stops`):
/// 14.8.3's type 5, 27.2's 6 (its handler `sub_FFFFFC000003891C`; type 5
/// is now the memory-descriptor kick).
#[versions(AGX)]
pub(super) const HOST_STOP: u64 = {
    let t = 0x86 << 48;
    t
};

/// The TA slot records' size (`buf_0x218`, channel table +0x234; 27.2:
/// +0x254), which the host's re-init zeroes.
#[versions(AGX)]
pub(super) const TA_RECORDS: usize = {
    let t = fw::g15_272::TA_RECORDS_SIZE;
    t
};

/// The power-control block's words the driver uses: the PPM target, its
/// doorbell and the energy counter (fw272-hwdata.md §1.6).
pub(super) struct PwrCtl {
    pub(super) ppm_target: usize,
    pub(super) ppm_bell: usize,
    pub(super) energy: usize,
}

#[versions(AGX)]
pub(super) const PWR_CTL: PwrCtl = {
    // `setPPMControllerTarget` and `getGPUAccumulatedEnergy`
    // (0xfffffe0008ba1d3c).
    let t = PwrCtl {
        ppm_target: 0x12C,
        ppm_bell: 0x128,
        energy: 0x5D0,
    };
    t
};

/// The firmware-to-host rings' record strides and the log's layout
/// (fw272-control.md §3).
pub(super) struct FwRings {
    pub(super) event: usize,
    pub(super) trace: usize,
    pub(super) stats: usize,
    /// The log's sub-rings, their entries' stride and the text buffer.
    pub(super) log_subs: usize,
    pub(super) log_entry: usize,
    pub(super) log_text: usize,
}

#[versions(AGX)]
pub(super) const FW_RINGS: FwRings = {
    // The log: 9 sub-rings of 256 entries of 0x48 bytes and 0xD8 bytes of
    // text per entry (0x1B0, 0x28800, 0x79800); the sub-ring states, the
    // entries and the text are 14.8.3's (the writer `sub_FFFFFC00000377E8`,
    // which leaves the multiplier 0).
    let t = FwRings {
        event: 0x48,
        trace: 0x48,
        stats: 0x48,
        log_subs: 9,
        log_entry: 0x48,
        log_text: 0x79800,
    };
    t
};

/// The event types the driver handles beyond 1 (completion) and 4
/// (recovery stop), which keep their numbers (fw272-control.md §3): a PB
/// grow request, a channel error, a UMA pool short of pages and a UMA grow
/// done.
#[versions(AGX)]
pub(super) const EV_PB_GROW: u32 = {
    let t = 6;
    t
};

#[versions(AGX)]
pub(super) const EV_CHAN_ERR: u32 = {
    let t = 7;
    t
};

#[versions(AGX)]
pub(super) const EV_UMA: u32 = {
    let t = 9;
    t
};

#[versions(AGX)]
pub(super) const EV_UMA_DONE: u32 = {
    let t = 0xD;
    t
};

/// The process-exit event, which ends a kill command (device control 0x21,
/// `g15_kill_queue`): 14.8.3's 0xD, 27.2's 0xC (fw272-control.md §3).
#[versions(AGX)]
pub(super) const EV_PROC_EXIT: u32 = {
    let t = 0xC;
    t
};

/// 27.2's statistics record types for the two the counters take
/// (utilization; the performance state), and 14.8.3's numbers for them,
/// which `G15Perf::stats_record` matches: the kext's
/// `AGXStatistics::recordStatisticsEntryFromFW` (0xfffffe0008bef1c4; 1483
/// 0xfffffe0008ec95b8) takes 0x13 and 0x1C as 14.8.3's 4 and 0xF, field
/// for field.
pub(super) const STATS_272: [(u32, u32); 2] = [(0x13, 4), (0x1C, 0xF)];

impl W {
    /// Stores a job ID, a u64 in the job states, the stream records and the
    /// stamp barrier (fw272-jobs.md, summary).
    ///
    /// # Safety
    ///
    /// `off + 8` must be within the buffer.
    pub(super) unsafe fn id(self, off: usize, id: u32) {
        // SAFETY: in bounds per the caller.
        unsafe { self.u64(off, u64::from(id)) };
    }
}
