// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 (M3) job submission.
//!
//! The G15 firmware does not use the work queues of earlier generations.
//! Each queue owns firmware channels (one for compute, a TA and a 3D one for
//! rendering). A job is a set of buffers (job state, stream, notifier) that
//! the host announces through an entry in one of the shared command rings
//! and a doorbell. The firmware reports completion by writing the channel's
//! stamp words and posting records to the firmware-to-host event ring, and
//! it stops for recovery on a fault or a hang until the host resumes it.
//!
//! - [`channel`]: channels and the command rings.
//! - [`compute`]: compute (CL) jobs.
//! - [`render`]: render passes (a TA and a 3D job), queues and submission,
//!   built by [`ta`] and [`fragment`] on a parameter buffer ([`pb`]) and
//!   render-target memory ([`rt`]).
//! - [`completion`]: the stamp words, retiring jobs and the poller.
//! - [`fw_rings`] and [`recovery`]: the firmware-to-host rings, the
//!   firmware's stops and the resume.
//! - [`uma`]: the UMA page pools, one per data master.
//! - [`perf`]: the GPU time of jobs, the performance state's residency and
//!   the submit path's time.
//!
//! Each G15 module names the pages of the reverse-engineered firmware ABI
//! (`spec/agx-g15c/` in the G15 notes) that hold the evidence for its layouts
//! and constants. This one's: boot.md, channel.md, faults.md, mmio.md, uat.md,
//! uma.md.

mod channel;
mod completion;
mod compute;
mod debug;
mod fragment;
mod fw_rings;
mod pb;
mod perf;
mod recovery;
mod render;
mod rt;
mod selftest;
mod ta;
mod uma;

use completion::*;
use pb::*;
use perf::*;
use render::*;
use rt::*;
use uma::*;

pub(crate) use self::{
    channel::{G15After, G15ClChannel, G15Dead},
    compute::G15ClJob,
    debug::{g15_fwdump, G15_FWDUMP_CRASH},
    perf::G15Hold,
    render::{G15RdCmd, G15RdGeom, G15RdQueue, G15RdZls},
    rt::G15Rt,
    uma::{G15Uma, G15UmaMem, G15_UMA_DEVICE_BLOCKS, G15_UMA_POOLS},
};

use super::*;

/// A ring class's stall: since when its ring holds entries the firmware has
/// not consumed, the read index, and since when that index has stood still
/// past `RING_STALL_US`.
type RingStall = (Option<Instant<Monotonic>>, u32, Option<Instant<Monotonic>>);

/// A destroyed queue's channels with a job unfinished, and since when.
type DeadChan = (G15Dead, Instant<Monotonic>);

/// The G15 part of the GPU manager: channels, jobs in flight and the
/// poller's state.
#[pin_data]
pub(crate) struct G15State {
    /// Job completion records seen on the event ring (types 1 and 0xA).
    completions: AtomicU64,
    /// Firmware notifications received.
    pub(super) notifies: AtomicU64,
    /// Ring stalls (a read index still for `RING_STALL_US` with entries
    /// unconsumed) by how long the index stood still: under 2 ms, 10 ms,
    /// 100 ms and longer, and the longest, in microseconds.
    ring_stalls: [AtomicU64; 4],
    ring_stall_max_us: AtomicU64,
    /// Poller passes and their CPU time.
    polls: AtomicU64,
    poll_ns: AtomicU64,
    /// Dead queues whose channels were released to the firmware, and those
    /// freed once it consumed the release (`asahi.g15_chan_release=1`).
    chans_released: AtomicU64,
    chans_freed: AtomicU64,
    /// Submissions that found a stamp table at `G15_STAMP_JOBS_WAIT` and
    /// waited, and the microseconds they waited.
    stamp_waits: AtomicU64,
    stamp_wait_us: AtomicU64,
    /// Jobs whose host stamp word was still behind `G15_HOST_STAMP_LATE_MS`
    /// after the firmware stamp word.
    host_stamp_late: AtomicU64,
    /// How long after the firmware stamp word a late host stamp word came:
    /// under 10 ms, 100 ms, 1 s and later, and the longest, in microseconds.
    host_stamp_after: [AtomicU64; 4],
    host_stamp_after_max_us: AtomicU64,
    /// The jobs each `G15Retirer` completed.
    completed_by: [AtomicU64; 3],
    /// The jobs the poller completed in the pass that first saw their
    /// firmware stamp: no interrupt's retire had seen them finish.
    poll_first: AtomicU64,
    /// Submissions held back on the host, by what their first held command
    /// waits for (`G15Hold`).
    held: [AtomicU64; 2],
    /// Render passes whose target memory was a block of its own, the
    /// queue's ring having no free instance.
    rt_own: AtomicU64,
    /// The last 256 records of the firmware's trace ring and the next slot
    /// (with `DebugFlags::Debug4`).
    #[pin]
    trace: Mutex<(KVec<[u64; 7]>, usize)>,
    /// GPU interrupts taken.
    pub(super) irqs: AtomicU64,
    /// Each command ring's next entry index, held from an entry's
    /// reservation to the store of the ring's write index. All queues share
    /// the rings, and a write index published out of order would show the
    /// firmware an entry that is still being written.
    #[pin]
    rings: Mutex<[u32; fw::g15::RINGS]>,
    /// The compute self-test's channel and jobs, kept for the device's
    /// lifetime: the firmware's job graph and notifier list still
    /// reference them.
    #[pin]
    selftest: Mutex<Option<(KBox<G15ClChannel>, KVec<G15ClJob>)>>,
    /// Submitted jobs of every queue, in submission order.
    #[pin]
    pending: Mutex<KVec<G15ClPending>>,
    /// Serializes the drains of the firmware-to-host rings.
    #[pin]
    drain_lock: Mutex<()>,
    /// Resumes from a firmware stop so far; `resume_cv` is signalled at
    /// each.
    #[pin]
    resumes: Mutex<u64>,
    #[pin]
    resume_cv: CondVar,
    /// Channel stamp indices in use (bit i: index i).
    stamp_ids: Arc<Mutex<u128>>,
    /// Parameter buffer IDs in use (bit i: ID i). ID 0 is never handed out.
    pb_ids: Arc<Mutex<u64>>,
    /// Each parameter buffer ID's firmware-visible state, kept for the
    /// device's lifetime: the firmware's post-recovery walk reads it.
    #[pin]
    pb_states: Mutex<[Option<Arc<G15PbState>>; 64]>,
    /// Each parameter buffer ID's buffer and the allocator it grows from,
    /// while its queue lives: a TA out of pages names only the ID.
    #[pin]
    pb_grow: Mutex<[Option<G15PbGrow>; 64]>,
    /// The TAs' requests for pages (event 7) the poller has not answered.
    #[pin]
    pb_grow_reqs: Mutex<KVec<G15GrowReq>>,
    /// The channel errors (event 8) the poller has not answered.
    #[pin]
    chan_errs: Mutex<KVec<G15ChanErr>>,
    /// The control ring's next entry: entry 0 is the self-test's.
    #[pin]
    ctl_next: Mutex<u32>,
    /// Render job IDs, two per pass.
    rd_ids: AtomicU32,
    /// The notifiers' keys, one sequence for the device as the kext's
    /// (`nextCommandBufferState`). A notifier list is sorted by key and its
    /// walk writes each flushed job's stamp to the host word in list order,
    /// so a later job with a smaller key, flushed in the same walk, put the
    /// host word back one job (submit-races.md).
    ntf_keys: AtomicU32,
    /// TA and 3D channel pairs of destroyed queues, for reuse.
    #[pin]
    free_rd_chans: Mutex<KVec<G15RdChans>>,
    /// The live queues' render states: an idle one gives its channel pair
    /// and parameter buffer to a queue short of them (`g15_rd_steal`).
    #[pin]
    rd_live: Mutex<KVec<Arc<Mutex<G15RdQueue>>>>,
    /// Starts the driver's completion poller (set at probe), and with true
    /// brings a queued pass forward to the next jiffy (`g15_kick`). A job's
    /// stamps and event record can trail the interrupt that announces them,
    /// or come without one, so the stamps are polled while jobs are pending.
    #[pin]
    pub(super) kick: Mutex<Option<G15Kick>>,
    /// Remainders of submissions held back until another kind of job
    /// completes; each returns true once all of it is submitted. The poller
    /// advances them.
    #[pin]
    deferred: Mutex<KVec<KBox<dyn FnMut() -> bool + Send>>>,
    /// Since when each ring class (TA, 3D, CL) holds entries the firmware
    /// has not consumed, how often it was rung again since without the
    /// firmware's read index moving, and that index.
    #[pin]
    ring_stall: Mutex<[RingStall; 3]>,
    /// Compute channels of destroyed queues, for reuse: the firmware's job
    /// table keeps a channel's job-slot object, so a channel is freed only
    /// after a release (`asahi.g15_chan_release`, `g15_chans_retire`).
    #[pin]
    free_chans: Mutex<KVec<Arc<Mutex<G15ClChannel>>>>,
    /// Channels returned with a job still unfinished, and since when: not
    /// reused, since later jobs would queue behind it, until idle.
    #[pin]
    dead_chans: Mutex<KVec<DeadChan>>,
    /// Channels to release to the firmware (device control 0x11): None until
    /// their last job is post-processed, then the control ring's write index
    /// past their release (None when they needed none).
    #[pin]
    releasing: Mutex<KVec<(G15Dead, Option<Option<u32>>)>>,
    /// The device's UMA page pools, one per data master (`G15UmaDm`); a
    /// queue's TA and 3D jobs use its own render pool instead when it has
    /// one.
    uma: KVec<Arc<G15Uma>>,
    /// The queues' render pools (`asahi.g15_uma_pools`).
    #[pin]
    uma_pools: Mutex<KVec<G15UmaEntry>>,
    /// Host stops so far. A channel or a render queue set up before the
    /// last one is set up again at its next submission, as the firmware's
    /// rebuild forgot it.
    reset_gen: AtomicU32,
    /// Recoveries so far, firmware and host stops alike: a render queue's
    /// TA-only buffers start zeroed after each (`G15RtShared::clear_ta_state`).
    rt_gen: AtomicU32,
    /// Set from a host stop until the firmware's restart after the resume
    /// is done: until then it drops new ring entries, so nothing is
    /// submitted or rung.
    restarting: AtomicBool,
    /// When the resume of the last host stop was sent, while its restart is
    /// awaited.
    #[pin]
    restart_since: Mutex<Option<Instant<Monotonic>>>,
    /// Since when the firmware has been seen stopped with no recovery run
    /// for it.
    #[pin]
    stop_seen: Mutex<Option<Instant<Monotonic>>>,
    /// The event page's progress word as last seen, and since when.
    #[pin]
    progress: Mutex<(u32, Instant<Monotonic>)>,
    /// When the last host stop was asked for.
    #[pin]
    host_stop: Mutex<Option<Instant<Monotonic>>>,
    /// Set by a DRM scheduler timeout: the next progress check stops the
    /// firmware.
    stop_asked: AtomicBool,
    /// The performance counters.
    #[pin]
    perf: G15Perf,
}

impl G15State {
    pub(crate) fn new(uma: KVec<Arc<G15Uma>>) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            completions: AtomicU64::new(0),
            notifies: AtomicU64::new(0),
            ring_stalls: [const { AtomicU64::new(0) }; 4],
            ring_stall_max_us: AtomicU64::new(0),
            polls: AtomicU64::new(0),
            poll_ns: AtomicU64::new(0),
            chans_released: AtomicU64::new(0),
            chans_freed: AtomicU64::new(0),
            stamp_waits: AtomicU64::new(0),
            stamp_wait_us: AtomicU64::new(0),
            host_stamp_late: AtomicU64::new(0),
            host_stamp_after: [const { AtomicU64::new(0) }; 4],
            host_stamp_after_max_us: AtomicU64::new(0),
            completed_by: [const { AtomicU64::new(0) }; 3],
            poll_first: AtomicU64::new(0),
            held: [const { AtomicU64::new(0) }; 2],
            rt_own: AtomicU64::new(0),
            trace <- new_mutex!((KVec::<[u64; 7]>::new(), 0usize), "g15_trace"),
            irqs: AtomicU64::new(0),
            rings <- new_mutex!([0; fw::g15::RINGS], "g15_rings"),
            selftest <- new_mutex!(None, "g15_selftest"),
            pending <- new_mutex!(KVec::new(), "g15_pending"),
            drain_lock <- new_mutex!((), "g15_drain_lock"),
            resumes <- new_mutex!(0, "g15_resumes"),
            resume_cv <- kernel::new_condvar!("g15_resume_cv"),
            stamp_ids: Arc::pin_init(new_mutex!(1u128, "g15_stamp_ids"), GFP_KERNEL)?,
            pb_ids: Arc::pin_init(new_mutex!(1u64, "g15_pb_ids"), GFP_KERNEL)?,
            pb_states <- new_mutex!([const { None }; 64], "g15_pb_states"),
            pb_grow <- new_mutex!([const { None }; 64], "g15_pb_grow"),
            pb_grow_reqs <- new_mutex!(KVec::new(), "g15_pb_grow_reqs"),
            chan_errs <- new_mutex!(KVec::new(), "g15_chan_errs"),
            ctl_next <- new_mutex!(1, "g15_ctl_next"),
            rd_ids: AtomicU32::new(0x10_0000),
            ntf_keys: AtomicU32::new(0x23),
            free_rd_chans <- new_mutex!(KVec::new(), "g15_free_rd_chans"),
            rd_live <- new_mutex!(KVec::new(), "g15_rd_live"),
            kick <- new_mutex!(None, "g15_kick"),
            deferred <- new_mutex!(KVec::new(), "g15_deferred"),
            ring_stall <- new_mutex!([(None, 0, None); 3], "g15_ring_stall"),
            free_chans <- new_mutex!(KVec::new(), "g15_free_chans"),
            dead_chans <- new_mutex!(KVec::new(), "g15_dead_chans"),
            releasing <- new_mutex!(KVec::new(), "g15_releasing"),
            uma,
            uma_pools <- new_mutex!(KVec::new(), "g15_uma_pools"),
            reset_gen: AtomicU32::new(0),
            rt_gen: AtomicU32::new(0),
            restarting: AtomicBool::new(false),
            restart_since <- new_mutex!(None, "g15_restart_since"),
            stop_seen <- new_mutex!(None, "g15_stop_seen"),
            progress <- new_mutex!((0, Instant::<Monotonic>::now()), "g15_progress"),
            host_stop <- new_mutex!(None, "g15_host_stop"),
            stop_asked: AtomicBool::new(false),
            perf <- G15Perf::new(),
        }? Error)
    }
}

/// How long a submission waits for room in a ring or in a channel's record
/// slots before it fails.
const G15_RING_WAIT_MS: i64 = 2000;

/// How many jobs one stamp index may have in its stamp table (submitted and
/// not post-processed, `G15ClChannel::in_table`). The table has 128 entries,
/// and the firmware's registration resets the entry of the job 128 behind
/// without asking whether that one ran or was post-processed: a job
/// registered over a waiting one reaches the executor with a NULL stream
/// and the firmware crashes (submit-races.md, "a stamp table wrapped by
/// unretired jobs"); one registered over a retired job not yet
/// post-processed never runs (barrier-race.md). A submission that would pass
/// this fails.
const G15_STAMP_JOBS_MAX: u32 = 127;

/// How many jobs in a stamp table make a submission wait for the firmware
/// to post-process some, before it takes any lock: a stalled queue's retire
/// needs the locks a waiting submission would hold. macOS's work queue holds
/// 80 commands not complete on the host word (`IOGPUWorkQueue`'s ring,
/// sized by `AGXAcceleratorG15X::configureDevice`; submit-races.md, "a
/// stamp table wrapped by unretired jobs").
const G15_STAMP_JOBS_WAIT: u32 = 80;

/// How long a submission that meets a firmware stop waits for the resume
/// before it fails.
const G15_RESUME_WAIT_MS: i64 = 5000;

/// How long a queue's first compute submission waits for a channel when
/// every stamp index is taken and every render pair is in use: a render
/// queue gives its pair up `G15_RD_STEAL_MS` after its last pass.
const G15_CL_WAIT_MS: i64 = 1000;

/// How long after the firmware stamp word a host stamp word still behind
/// counts as late (`asahi/perf`).
const G15_HOST_STAMP_LATE_MS: i64 = 5;

/// How long a job may stay unfinished with the firmware's progress word
/// unmoved before the host stops the firmware: the kext's progress timer,
/// IOGPU's `waitForGPUTimeoutSeconds`, which `populateAccelConfig` sets to 5.
const G15_PROGRESS_MS: i64 = 5000;

/// How long a destroyed queue's job may stay unfinished before the host
/// stops the firmware. Nothing waits for the job, and the firmware kills no
/// job of a stage-0 channel, which every channel is: its CL kill scan skips
/// them. A compute job that never ends moves the progress word, so without
/// this it would run on and keep its process's memory for good.
const G15_DEAD_MS: i64 = 2000;

/// The `isHWSoftFaultEnabled` word of the job streams: 1 when userspace is
/// told that soft faults are on, so that it may load from unmapped pages on
/// purpose.
fn g15_soft_faults() -> u32 {
    u32::from(*crate::module_parameters::fault_control.value() == 0xb)
}

/// Freed `shared` and `gpu` job buffers held back from reuse. The firmware
/// keeps lines of a job's state, stream and notifier in its cache and
/// writes some of them back later, so a buffer reused at once could have
/// its new contents overwritten or read stale. No cache flush is known for
/// G15: the buffers wait until the firmware has gone through enough newer
/// memory. Past `HIGH` objects the oldest are released down to `KEEP`, and
/// past `BYTES_HIGH` bytes down to `BYTES_KEEP` (a pass's tilemap grows
/// with its target: 1.25 MiB a layer at 16384x16384).
const G15_QUARANTINE_HIGH: usize = 8192;
const G15_QUARANTINE_KEEP: usize = 4096;
const G15_QUARANTINE_BYTES_HIGH: usize = 256 << 20;
const G15_QUARANTINE_BYTES_KEEP: usize = 128 << 20;
/// The byte bounds of the firmware-uncached heaps (`fw_nc`, 128 MiB, and
/// `gpu_fw_nc`, 64 MiB), which hold the job states and streams.
const G15_QUARANTINE_FW_NC_BYTES: (usize, usize) = (32 << 20, 16 << 20);
const G15_QUARANTINE_GPU_FW_NC_BYTES: (usize, usize) = (16 << 20, 8 << 20);

/// Little-endian stores into a freshly allocated buffer.
#[derive(Clone, Copy)]
struct W(*mut u8);

impl W {
    /// # Safety
    ///
    /// `off + 4` must be within the buffer.
    unsafe fn u32(self, off: usize, v: u32) {
        // SAFETY: in bounds per the caller.
        unsafe { self.0.add(off).cast::<u32>().write_unaligned(v) }
    }

    /// # Safety
    ///
    /// `off + 8` must be within the buffer.
    unsafe fn u64(self, off: usize, v: u64) {
        // SAFETY: in bounds per the caller.
        unsafe { self.0.add(off).cast::<u64>().write_unaligned(v) }
    }

    /// Writes a register list at `off` and returns its entry count. An
    /// entry is 12 bytes: the u32 header `(register & 0x3FFF8) |
    /// write-enable`, then the u64 value.
    ///
    /// # Safety
    ///
    /// `off + 12 * entries.len()` must be within the buffer.
    unsafe fn reglist(self, off: usize, entries: &[(u32, u64)]) -> u32 {
        for (i, &(h, v)) in entries.iter().enumerate() {
            // SAFETY: in bounds per the caller.
            unsafe {
                self.u32(off + i * 12, h);
                self.u64(off + i * 12 + 4, v);
            }
        }
        entries.len() as u32
    }
}

/// A buffer's VA.
fn va(a: &fw::types::GpuArray<u8>) -> u64 {
    a.gpu_va().get()
}

/// A VA in the 40-bit form of the TA's pointer registers and the parameter
/// buffer descriptor: bit 39 selects the kernel half, and the GPU reads a
/// user value as VA = value + 64 GiB, unwrapped. Only user VAs in
/// [64 GiB, 576 GiB) have one.
fn va40(a: u64) -> u64 {
    (a >> 3 & 1 << 39)
        | (a.wrapping_add(if a & 1 << 42 != 0 { 0 } else { 0x70_0000_0000 }) & 0x7F_FFFF_FFFF)
}

/// A buffer's VA in the 40-bit form, as the TA's pointer registers take it.
fn h(a: &fw::types::GpuArray<u8>) -> u64 {
    va40(va(a))
}

/// A buffer's VA as the 3D (ISP) pointer registers take it: the GPU's
/// 43-bit view (bit 42 selects the kernel half), as the CDM's. The PM
/// registers of both jobs (`0x16C38`, `0x1CA28`, `0x1CA30`) take the 40-bit
/// form.
fn gva(a: &fw::types::GpuArray<u8>) -> u64 {
    a.gpu_va().get() & G15_GPU_VA_MASK
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Maps the register windows of the hardware configuration into the
    /// MMIO range and fills HwDataB's window records. A kind-1 window with a
    /// base and a size gets a page-aligned mapping, and its published
    /// address adds the sub-page offset; a kind-6 window publishes the
    /// MCache PIO buffer the initdata builder allocated. Empty windows
    /// publish 0, as on macOS.
    pub(crate) fn g15_map_windows(
        this: &mut Pin<UniqueArc<GpuManager::ver>>,
        cfg: &'static hw::HwConfig,
    ) -> Result {
        let windows = cfg.g15_windows.ok_or(EINVAL)?;
        let mut fwva = [0u64; 31];

        for (j, w) in windows.iter().enumerate() {
            if w.kind == 1 && w.base != 0 && w.size != 0 {
                let off = (w.base & (mmu::UAT_PGMSK as u64)) as usize;
                let base = w.base - off as u64;
                let size = ((w.size as usize + mmu::UAT_PGMSK) & !mmu::UAT_PGMSK) as u64;

                let iova = this.as_mut().alloc_mmio_iova(size as usize);
                let mapping = this.uat.kernel_vm().map_io(
                    this.dev.as_ref().as_ref(),
                    iova,
                    base as usize,
                    size as usize,
                    if w.flag != 0 {
                        mmu::PROT_FW_MMIO_RW
                    } else {
                        mmu::PROT_FW_MMIO_RO
                    },
                )?;

                this.as_mut().io_mappings_mut().push(mapping, GFP_KERNEL)?;
                fwva[j] = iova + off as u64;
            }
        }

        let mcache = this.as_mut().initdata_mut().mcache_piob.gpu_va().get();

        // The firmware builds its window array from these records
        // (AGXArmFirmware::initFirmwareData writes each window's address
        // into its record; a record whose base is 0 is skipped).
        this.as_mut().initdata_mut().hwdata_b.with_mut(|raw, _| {
            for (j, w) in windows.iter().enumerate() {
                raw.windows[j].base = U64(w.base);
                raw.windows[j].fwva = U64(if w.kind > 1 && w.base != 0 && w.size != 0 {
                    mcache
                } else {
                    fwva[j]
                });
                raw.windows[j].kind_size = w.kind * w.size;
                raw.windows[j].size = w.size;
                raw.windows[j].flag = w.flag;
            }
        });

        Ok(())
    }

    /// Points the G15 MMU configuration block at the TTBAT (macOS's
    /// `AGXSecureMonitorG15::setupMMUConfig`): programs it if its gate reads
    /// 0, else checks that it points at our TTBAT. This runs after make_uat
    /// filled the TTBAT and before any job, through `res`: the device's
    /// resources are not pinned yet.
    pub(super) fn g15_setup_mmu(dev: &AsahiDrmDevice, res: &regs::Resources<'_>, uat: &mmu::Uat) {
        let want = ((uat.ttb_base() >> 14) & 0xfff_ffff) as u32;
        match res.setup_g15_mmu(uat.ttb_base()) {
            Some((programmed, enable, base)) => {
                let msg = if programmed {
                    "programmed"
                } else {
                    "already set"
                };
                if enable == 1 && base == want {
                    dev_info!(
                        dev.as_ref(),
                        "MMU: G15 eGART {} (enable=0x{:x}, gptbat base=0x{:x})\n",
                        msg,
                        enable,
                        base
                    );
                } else {
                    dev_err!(
                        dev.as_ref(),
                        "MMU: G15 eGART {}: enable=0x{:x}, gptbat base=0x{:x} (want 0x{:x})\n",
                        msg,
                        enable,
                        base,
                        want
                    );
                }
            }
            None => dev_warn!(dev.as_ref(), "MMU: G15 eGART: window inaccessible\n"),
        }
    }

    /// Starts the firmware: boots the coprocessor, starts the endpoints and
    /// holds it awake, since otherwise it hibernates at the GPU's first idle
    /// and no doorbell wakes it. Then sends MSG_INIT with the FMC header's
    /// address, which the firmware's init waits for, rings the
    /// device-control doorbell and runs the self-tests. Notifications
    /// arrive by interrupt.
    ///
    /// A freshly started coprocessor boots by itself: the hello, the endpoint
    /// map and an IOP power-state ACK to on, which `boot()` waits for. Only
    /// one left asleep sends no ACK and needs `wake()`'s request; a booted one
    /// never acknowledges that request, so `wake()` first would time out
    /// whenever the ACK came before it.
    pub(super) fn g15_start(&self) -> Result {
        let fmc = self.initdata.fmc.gpu_va().get();
        {
            let mut guard = self.rtkit.lock();
            let mut rtk = guard.as_mut().as_pin_mut().ok_or(EIO)?;
            if rtk.as_mut().boot().is_err() {
                rtk.as_mut().wake()?;
            }
            rtk.as_mut().start_endpoint(EP_FIRMWARE)?;
            rtk.as_mut().start_endpoint(EP_DOORBELL)?;
            rtk.as_mut().hold_awake()?;
            rtk.as_mut()
                .send_message(EP_FIRMWARE, MSG_INIT | (fmc & INIT_DATA_MASK))?;
            rtk.as_mut()
                .send_message(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL)?;
        }
        dev_info!(
            self.dev.as_ref(),
            "G15: RTKit up; init message sent (FMC header {:#x})\n",
            fmc
        );
        self.g15_control_selftest();
        self.g15_compute_selftest();
        Ok(())
    }

    /// The UMA pool for a new job of data master `dm`. A pool the firmware
    /// marked for a reset at a recovery keeps the mark, as on macOS: the
    /// pool's next kick rebuilds it from its backup list.
    pub(super) fn g15_uma_get(&self, dm: G15UmaDm) -> Result<Arc<G15Uma>> {
        self.g15.uma.get(dm as usize).cloned().ok_or(EINVAL)
    }

    /// Sends a mailbox message to the firmware.
    pub(super) fn g15_send(&self, ep: u8, msg: u64) -> Result {
        if self.is_crashed() {
            return Err(ENODEV);
        }
        // Every store before the message (ring entries, job buffers) must
        // complete first: `fence(Release)` is a `dmb ish`, which does not
        // order them for the firmware's core.
        crate::mem::sync();
        let mut guard = self.rtkit.lock();
        let rtk = guard.as_mut().as_pin_mut().ok_or(EIO)?;
        rtk.send_message(ep, msg)
    }
}
