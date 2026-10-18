// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 (M3) support: the firmware's channel model of job submission.

mod channel;
mod completion;
mod compute;
mod debug;
mod fragment;
mod fw_rings;
mod pb;
mod recovery;
mod render;
mod rt;
mod selftest;
mod ta;
mod uma;

use completion::*;
use pb::*;
use render::*;
use rt::*;
use uma::*;

use selftest::G15RenderTest;

pub(crate) use self::{
    channel::G15ClChannel,
    compute::G15ClJob,
    debug::{g15_fwdump, G15_FWDUMP_CRASH},
    render::{G15RdCmd, G15RdGeom, G15RdQueue, G15RdZls},
    rt::G15Rt,
    uma::G15Uma,
};

use super::*;

/// The G15 part of the GPU manager: the channels, the jobs in flight and
/// the poller's state.
#[pin_data]
pub(crate) struct G15State {
    /// G15: job completions seen on the event ring (record type 1, the
    /// queue-bitmask completion, or 0xA, the command-buffer completion;
    /// spec: agx-g15c/channel-table.md, the event ring).
    completions: AtomicU64,
    /// G15: the firmware's 0x42 notifications received (diagnostics).
    pub(super) notifies: AtomicU64,
    /// G15: the doorbells the poller re-rang for unconsumed ring entries.
    rerings: AtomicU64,
    /// Doorbells rung for jobs unfinished after `G15_NUDGE_MS`.
    nudges: AtomicU64,
    /// Jobs completed on the firmware stamp word, their host stamp word
    /// `G15_HOST_STAMP_MS` behind.
    host_stamp_late: AtomicU64,
    /// G15 lab: the last 256 records of the firmware's trace ring (with the ktrace flags on,
    /// `DebugFlags::Debug4`), and where the next goes.
    #[pin]
    trace: Mutex<(KVec<[u64; 7]>, usize)>,
    /// G15: the GPU interrupts taken (diagnostics).
    pub(super) irqs: AtomicU64,
    /// G15: each ring's next entry index (`fw::g15::ring`; the kext's
    /// AGXAcceleratorRing cursor), held from an entry's reservation to the
    /// store of the ring's write index: every queue's jobs share the rings,
    /// and an index published out of order shows the consumer an entry
    /// still being written (a NULL record slot, `AGFA_RecordDispatch`+0x130).
    #[pin]
    rings: Mutex<[u32; fw::g15::RINGS]>,
    /// G15: the render self-test's state, kept for the device's lifetime.
    #[pin]
    render_test: Mutex<Option<KBox<G15RenderTest>>>,
    /// G15: the self-test's channel and jobs, kept for the device's
    /// lifetime (the firmware's DAG root and notifier list reference them).
    #[pin]
    selftest: Mutex<Option<(KBox<G15ClChannel>, KVec<G15ClJob>)>>,
    /// G15: the submitted CL jobs of every queue, in submit order.
    #[pin]
    pending: Mutex<KVec<G15ClPending>>,
    /// G15: serializes the firmware-to-host ring drains.
    #[pin]
    drain_lock: Mutex<()>,
    /// G15: the resumes from a firmware stop so far; `g15_resume_cv` is
    /// signalled at each (`g15_wait_resume`).
    #[pin]
    resumes: Mutex<u64>,
    #[pin]
    resume_cv: CondVar,
    /// G15: the CL channels' stamp indices in use (bit i = index i).
    stamp_ids: Arc<Mutex<u128>>,
    /// G15: the parameter buffers' hardware IDs in use (bit 0: the render
    /// self-test's).
    pb_ids: Arc<Mutex<u64>>,
    /// G15: each buffer ID's firmware-visible parameter-buffer state, kept
    /// for the device's lifetime (`G15PbState`).
    #[pin]
    pb_states: Mutex<[Option<Arc<G15PbState>>; 64]>,
    /// G15: the render jobs' IDs (js+0x884 / +0xBCC), two per pass.
    rd_ids: AtomicU32,
    /// G15: the TA and 3D channel pairs of destroyed queues, for reuse
    /// (as `g15_free_chans`).
    #[pin]
    free_rd_chans: Mutex<KVec<G15RdChans>>,
    /// G15: starts the driver's completion poller (set by the probe): a
    /// job's stamp and event record can trail the signals that come with
    /// it, or come without one (boots #105-#114), so the stamps are
    /// polled every jiffy while a CL job is pending.
    #[pin]
    pub(super) kick: Mutex<Option<KBox<dyn Fn() + Send + Sync>>>,
    /// G15: the rest of submissions held back until another kind of job
    /// completes; each returns true once it has submitted all of it. The
    /// poller advances them (queue::G15Run).
    #[pin]
    deferred: Mutex<KVec<KBox<dyn FnMut() -> bool + Send>>>,
    /// G15: since when each ring class (TA, 3D, CL) holds entries the
    /// firmware has not consumed (the poller re-rings it).
    #[pin]
    ring_stall: Mutex<[Option<Instant<Monotonic>>; 3]>,
    /// G15: the CL channels of destroyed queues, for reuse: the firmware's
    /// job table keeps a channel's job-slot object, and freeing it under the
    /// firmware crashed it (a NULL slot object in sub_3F68C, boot #115).
    #[pin]
    free_chans: Mutex<KVec<Arc<Mutex<G15ClChannel>>>>,
    /// G15: channels returned with a job still unfinished (a hung job):
    /// never reused — later jobs would queue behind it — and never freed.
    #[pin]
    dead_chans: Mutex<KVec<Arc<Mutex<G15ClChannel>>>>,
    /// G15: the UMA page pool every job uses.
    uma: Option<Arc<G15Uma>>,
}

impl G15State {
    pub(crate) fn new(uma: Option<Arc<G15Uma>>) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            completions: AtomicU64::new(0),
            notifies: AtomicU64::new(0),
            rerings: AtomicU64::new(0),
            nudges: AtomicU64::new(0),
            host_stamp_late: AtomicU64::new(0),
            trace <- new_mutex!((KVec::<[u64; 7]>::new(), 0usize), "g15_trace"),
            irqs: AtomicU64::new(0),
            rings <- new_mutex!([0; fw::g15::RINGS], "g15_rings"),
            render_test <- new_mutex!(None, "g15_render_test"),
            selftest <- new_mutex!(None, "g15_selftest"),
            pending <- new_mutex!(KVec::new(), "g15_pending"),
            drain_lock <- new_mutex!((), "g15_drain_lock"),
            resumes <- new_mutex!(0, "g15_resumes"),
            resume_cv <- kernel::new_condvar!("g15_resume_cv"),
            stamp_ids: Arc::pin_init(new_mutex!(1u128, "g15_stamp_ids"), GFP_KERNEL)?,
            pb_ids: Arc::pin_init(new_mutex!(1u64, "g15_pb_ids"), GFP_KERNEL)?,
            pb_states <- new_mutex!([const { None }; 64], "g15_pb_states"),
            rd_ids: AtomicU32::new(0x10_0000),
            free_rd_chans <- new_mutex!(KVec::new(), "g15_free_rd_chans"),
            kick <- new_mutex!(None, "g15_kick"),
            deferred <- new_mutex!(KVec::new(), "g15_deferred"),
            ring_stall <- new_mutex!([None, None, None], "g15_ring_stall"),
            free_chans <- new_mutex!(KVec::new(), "g15_free_chans"),
            dead_chans <- new_mutex!(KVec::new(), "g15_dead_chans"),
            uma,
        }? Error)
    }
}

/// G15: a freed job buffer (`shared` and `gpu` heaps) is held back until this many
/// newer ones have been freed, and then released oldest first down to `KEEP`. The
/// firmware keeps lines of a job's state, stream and notifier in its cache and
/// writes some of them back later: a buffer reused at once gets its fresh contents
/// overwritten or read stale (boots #431-#439: "Unknown SKU command type", "DAG:
/// Non Sequential Stamp Updates", a NULL state pointer, within about 80 runs of
/// eglpass). No cache flush is known for G15, so the buffers wait until the
/// firmware has cycled through enough newer memory to have evicted the lines.
/// G15: the gap between a ring entry's stores and the store of the write index that
/// publishes it. The consumer reads the index and then the entry with no barrier
/// between: a pass already running (the doorbell of the job before, a completion)
/// can have loaded the entry before the host stored it, and then sees the index.
/// A stale entry is skipped or half read (class 0, flag 0, state NULL): the read
/// index moves and the job is never registered (boot #449: a render pass whose 3D
/// channel's DAG slot never advanced; the next job aborts "Non Sequential Stamp
/// Updates"). Loads a few tens of ns apart cannot straddle a gap this long.
pub(crate) const G15_PUBLISH_GAP_US: i64 = 5;

/// G15: how long a submit waits for room in a ring or a channel's record slots
/// (`GpuManager::g15_ring_room`) before it fails.
const G15_RING_WAIT_MS: i64 = 2000;

/// G15: how long a submit that meets a firmware stop waits for the resume
/// (`GpuManager::g15_wait_resume`) before it fails.
const G15_RESUME_WAIT_MS: i64 = 5000;
/// G15: how long after the firmware stamp word a job whose host stamp word
/// stays behind completes anyway (`g15_cl_retire`).
const G15_HOST_STAMP_MS: i64 = 5;

/// G15: the stream records' `isHWSoftFaultEnabled` word (CL +0x2C, TA +0x44,
/// 3D +0x54; spec: faults.md, "Soft faults"): 1 when the driver advertises
/// soft faults to userspace, which then loads from unmapped pages on purpose.
fn g15_soft_faults() -> u32 {
    u32::from(*crate::module_parameters::fault_control.value() == 0xb)
}

/// G15: the freed `shared` and `gpu` job buffers held back from reuse (spec:
/// submit-races.md, "A freed job buffer, reused at once"): past `HIGH`
/// objects the oldest go down to `KEEP`, and past `BYTES_HIGH` bytes down to
/// `BYTES_KEEP` (a pass's tilemap grows with its target: at 16384x16384, 1.25
/// MiB a layer).
const G15_QUARANTINE_HIGH: usize = 8192;
const G15_QUARANTINE_KEEP: usize = 4096;
const G15_QUARANTINE_BYTES_HIGH: usize = 256 << 20;
const G15_QUARANTINE_BYTES_KEEP: usize = 128 << 20;

/// Little-endian stores into a freshly allocated buffer.
#[derive(Clone, Copy)]
struct W(*mut u8);

impl W {
    /// # Safety
    /// `off + 4` must be in bounds of the buffer.
    pub(crate) unsafe fn u32(self, off: usize, v: u32) {
        // SAFETY: in bounds per the caller.
        unsafe { self.0.add(off).cast::<u32>().write_unaligned(v) }
    }

    /// # Safety
    /// `off + 8` must be in bounds of the buffer.
    pub(crate) unsafe fn u64(self, off: usize, v: u64) {
        // SAFETY: in bounds per the caller.
        unsafe { self.0.add(off).cast::<u64>().write_unaligned(v) }
    }

    /// Writes a register list (12 B entries: the u32 header `(mrr &
    /// 0x3FFF8) | write-enable`, then the u64 value) at `off`; returns
    /// the entry count.
    ///
    /// # Safety
    /// `off + 12 * entries.len()` must be in bounds of the buffer.
    pub(super) unsafe fn reglist(self, off: usize, entries: &[(u32, u64)]) -> u32 {
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

fn va(a: &fw::types::GpuArray<u8>) -> u64 {
    a.gpu_va().get()
}

/// A VA in the 40-bit form the kext writes to `0x1C910` and the PB
/// descriptor (`halLoadPBDesc`): bit 39 = the kernel half; the GPU reads a
/// user value as VA = value + 64 GiB, unwrapped (boot #148: our 43-bit
/// kernel VA `0x42C_0001_0180` fetched as user `0x3C_0001_0180`; boot
/// #160: user `0x18000` encoded `0x70_0001_8000` fetched at
/// `0x80_0001_8000`). So only user VAs in [64 GiB, 576 GiB) have one.
fn va40(a: u64) -> u64 {
    (a >> 3 & 1 << 39)
        | (a.wrapping_add(if a & 1 << 42 != 0 { 0 } else { 0x70_0000_0000 }) & 0x7F_FFFF_FFFF)
}

/// A buffer's VA as the TA pointer registers take it: the 40-bit form
/// (the VDM base and the TPC decoded our 43-bit kernel VAs as user VAs,
/// boots #148-#150).
fn h(a: &fw::types::GpuArray<u8>) -> u64 {
    va40(va(a))
}

/// A buffer's VA as the 3D (ISP) pointer registers take it: the GPU's
/// 43-bit view (bit 42 = the kernel half), as the CDM's; the ISP read the
/// 40-bit form of the heapmeta as a user VA (boot #153). The PM registers
/// of both lists (`0x16C38`, `0x1CA28`, `0x1CA30`) take the 40-bit form.
fn gva(a: &fw::types::GpuArray<u8>) -> u64 {
    a.gpu_va().get() & G15_GPU_VA_MASK
}

#[versions(AGX)]
impl GpuManager::ver {
    /// G15: map the register windows (the chip+0x6d0 table; spec:
    /// alloc.md) into the MMIO sub-range and fill the HwDataB 0x640 block
    /// (the 31 window records + the 31 window GPU addresses; spec:
    /// hwdata-b.md). A kind-1 window with a nonzero base and size gets a
    /// 16 KiB-aligned GPU mapping; its published address adds the sub-page
    /// remainder. The kind-6 MCache slot is the PIO buffer the initdata
    /// builder allocated (its PAs are its content). Windows whose entry
    /// base or size is 0 publish 0, as the kext does.
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
            // The kext's Arm pass (AGXArmFirmware::initFirmwareData) writes
            // each window's address into its record's +0x08 (stride 0x20,
            // the u32 index steps by 4), and the firmware builds its window
            // array from these records (sub_FFFFFC000003A714: record j at
            // 0x640 + 0x20*j, skipped when +0x00 is 0). spec: hwdata-b.md.
        });

        Ok(())
    }

    /// G15: the UMA pool for a new job. A pool the firmware marked for a
    /// reset at a recovery (+0x30 = 1) keeps it, as with the kext: the
    /// pool's next kick rebuilds it from its backup list, and a recovery
    /// that interrupts a reset marks it again (spec: uma.md, "The reset
    /// after a recovery").
    pub(super) fn g15_uma_get(&self) -> Result<Arc<G15Uma>> {
        self.g15.uma.clone().ok_or(EINVAL)
    }

    /// G15: send a mailbox message through RTKit.
    pub(super) fn g15_send(&self, ep: u8, msg: u64) -> Result {
        if self.is_crashed() {
            return Err(ENODEV);
        }
        // Every store before the message (the ring entries, the job
        // buffers) completes first: `fence(Release)` is a `dmb ish`, which
        // does not order them for the firmware's core.
        crate::mem::sync();
        let mut guard = self.rtkit.lock();
        let rtk = guard.as_mut().as_pin_mut().ok_or(EIO)?;
        rtk.send_message(ep, msg)
    }
}
