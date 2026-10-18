// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Top-level GPU manager
//!
//! This module is the root of all GPU firmware management for a given driver instance. It is
//! responsible for initialization, owning the top-level managers (events, UAT, etc.), and
//! communicating with the raw RtKit endpoints to send and receive messages to/from the GPU
//! firmware.
//!
//! It is also the point where diverging driver firmware/GPU variants (using the versions macro)
//! are unified, so that the top level of the driver itself (in `driver`) does not have to concern
//! itself with version dependence.

use core::any::Any;
use core::ops::Range;
use core::slice;
use core::sync::atomic::{
    AtomicBool,
    AtomicU32,
    AtomicU64,
    Ordering, //
};

use kernel::{
    c_str,
    drm::gem::shmem,
    error::code::*,
    io::{
        mem::{
            Mem,
            MemFlag, //
        },
        IoBase,
        IoSysMap,
        Region, //
    },
    macros::versions,
    new_mutex,
    prelude::*,
    soc::apple::rtkit,
    sync::{
        lock::{
            mutex::MutexBackend,
            Guard, //
        },
        Arc,
        Mutex,
        UniqueArc, //
    },
    time::{
        Delta,
        Instant,
        Monotonic, //
    },
    types::{
        ForeignOwnable, //
    },
};

use crate::alloc::Allocator;
use crate::debug::*;
use crate::driver::{
    AsahiDevRef,
    AsahiDevice,
    AsahiDrmDevice,
    AsahiRegData, //
};
use crate::fw::channels::{
    ChannelErrorType,
    PipeType, //
};
use crate::fw::types::{
    U32,
    U64, //
};
use crate::{
    alloc,
    buffer,
    channel,
    event,
    fw,
    gem,
    hw,
    initdata,
    mmu,
    queue,
    regs,
    workqueue, //
};

const DEBUG_CLASS: DebugFlags = DebugFlags::Gpu;

mod g15render;
pub(crate) use g15render::{G15RdCmd, G15RdGeom, G15RdQueue, G15RdZls, G15Rt};
use g15render::{G15PbState, G15RdPass, G15RenderTest};

/// Firmware endpoint for init & incoming notifications.
const EP_FIRMWARE: u8 = 0x20;

/// Doorbell endpoint for work/message submissions.
const EP_DOORBELL: u8 = 0x21;

/// Initialize the GPU firmware.
const MSG_INIT: u64 = 0x81 << 48;
const INIT_DATA_MASK: u64 = (1 << 44) - 1;

/// TX channel doorbell.
const MSG_TX_DOORBELL: u64 = 0x83 << 48;
/// Firmware control channel doorbell.
const MSG_FWCTL: u64 = 0x84 << 48;
// /// Halt the firmware (?).
// const MSG_HALT: u64 = 0x85 << 48;

/// Receive channel doorbell notification.
const MSG_RX_DOORBELL: u64 = 0x42 << 48;

/// Doorbell number for firmware kicks/wakeups.
#[allow(dead_code)] // M1/M2 only: G15 does not kick (start_op)
const DOORBELL_KICKFW: u64 = 0x10;
/// Doorbell number for device control channel kicks.
const DOORBELL_DEVCTRL: u64 = 0x11;

/// G15 m1n1 hypervisor call (`brk #0x4242`, x0 = id), served by the lab's
/// hypervisor script (`tools/lab/g15hv.py`): dump the firmware's data segments
/// and the job chain's GPU registers into the lab's trace dir (x1 = tag;
/// read-only; tag `G15_FWDUMP_CRASH` also saves the IOP's crashlog).
const HVC_G15_FWDUMP: u64 = 0x1503;
/// G15: the fwdump tag of a firmware crash.
const G15_FWDUMP_CRASH: u64 = 0xc;

/// G15: have the lab hypervisor dump the firmware's data segments and the
/// job chain's GPU registers (`tag` names the dump file). Only with the
/// G15LabHv debug flag.
fn g15_fwdump(tag: u64) {
    if !debug_enabled(DebugFlags::G15LabHv) {
        return;
    }
    // SAFETY: the hypervisor reads x0/x1, writes x0 and resumes after the
    // brk; nothing else in the guest state changes. The `dsb sy` completes
    // the guest's writes before the dump.
    unsafe {
        core::arch::asm!(
            "dsb sy",
            "brk #0x4242",
            inout("x0") HVC_G15_FWDUMP => _,
            in("x1") tag,
            options(nostack),
        );
    }
}

// G15 kernel VA address ranges: region 1 of the GART (bit 42 set — the
// GPTBAT word 1), 128 GiB above the region base, written sign-extended.
// The firmware's kernel window is the 42-bit upper half (its own image
// sits at 0xffff_fc00_0000_0000; boot #28 crashlog), and it rebuilds the
// MSG_INIT address as 0xffff_f000_0000_0000 | VA[43:0], so the VAs it is
// given must be 0xffff_fcxx_… — the page-table walk only uses bits 41:0
// and bit 42 (the region), so the slots are the same either way.
/// Private (cached) firmware structure VA range base.
const IOVA_KERN_PRIV_RANGE: Range<u64> = 0xffff_fc20_0000_0000..0xffff_fc26_0000_0000;
/// Private (cached) GPU-RO firmware structure VA range base.
const IOVA_KERN_GPU_RO_RANGE: Range<u64> = 0xffff_fc26_0000_0000..0xffff_fc28_0000_0000;
/// Shared (uncached) firmware structure VA range base.
const IOVA_KERN_SHARED_RANGE: Range<u64> = 0xffff_fc28_0000_0000..0xffff_fc2a_0000_0000;
/// Shared (uncached) read-only firmware structure VA range base.
const IOVA_KERN_SHARED_RO_RANGE: Range<u64> = 0xffff_fc2a_0000_0000..0xffff_fc2c_0000_0000;
/// GPU/FW shared structure VA range base.
const IOVA_KERN_GPU_RANGE: Range<u64> = 0xffff_fc2c_0000_0000..0xffff_fc2e_0000_0000;
/// GPU/FW shared structure VA range base.
const IOVA_KERN_RTKIT_RANGE: Range<u64> = 0xffff_fc2e_0000_0000..0xffff_fc2e_1000_0000;
/// Shared (uncached) timestamp region.
pub(crate) const IOVA_KERN_TIMESTAMP_RANGE: Range<u64> = 0xffff_fc2e_1000_0000..0xffff_fc2e_1400_0000;
/// G15: the FW-uncached stamp words (`KernelAllocators::stamp`).
const IOVA_KERN_STAMP_RANGE: Range<u64> = 0xffff_fc2e_1400_0000..0xffff_fc2e_1800_0000;
/// G15: the firmware's non-cacheable buffers (`KernelAllocators::fw_nc`).
const IOVA_KERN_FW_NC_RANGE: Range<u64> = 0xffff_fc2e_1800_0000..0xffff_fc2e_2000_0000;
/// G15: the GPU's tables, firmware non-cacheable (`KernelAllocators::gpu_fw_nc`).
const IOVA_KERN_GPU_FW_NC_RANGE: Range<u64> = 0xffff_fc2e_2000_0000..0xffff_fc2e_2400_0000;
/// FW MMIO VA range base.
const IOVA_KERN_MMIO_RANGE: Range<u64> = 0xffff_fc2f_0000_0000..0xffff_fc30_0000_0000;

/// GPU/FW buffer manager control address (context 0 low; region 0)
pub(crate) const IOVA_KERN_GPU_BUFMGR_LOW: u64 = 0x20_0000_0000;
/// GPU/FW buffer manager control address (context 0 high)
pub(crate) const IOVA_KERN_GPU_BUFMGR_HIGH: u64 = 0xffff_fc2e_ffff_0000;

/// Timeout for entering the halt state after a fault or request.
#[allow(dead_code)] // the M1/M2 halt handshake (recover)
const HALT_ENTER_TIMEOUT: Delta = Delta::from_millis(100);

/// Maximum amount of firmware-private memory garbage allowed before collection.
/// Collection flushes the FW cache and is expensive, so this needs to be
/// reasonably high.
const MAX_FW_ALLOC_GARBAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum count of firmware-private memory garbage objects allowed before collection.
/// This works out to 16K of memory in the garbage list (8 bytes each), which keeps us
/// within the safe range for kmalloc (on 16K page systems).
const MAX_FW_ALLOC_GARBAGE_OBJECTS: usize = 2048;

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

/// G15: the stream records' `isHWSoftFaultEnabled` word (CL +0x2C, TA +0x44,
/// 3D +0x54; spec: faults.md, "Soft faults"): 1 when the driver advertises
/// soft faults to userspace, which then loads from unmapped pages on purpose.
fn g15_soft_faults() -> u32 {
    u32::from(*crate::module_parameters::fault_control.value() == 0xb)
}

const G15_QUARANTINE_HIGH: usize = 8192;
const G15_QUARANTINE_KEEP: usize = 4096;

/// Global allocators used for kernel-half structures.
pub(crate) struct KernelAllocators {
    pub(crate) private: alloc::DefaultAllocator,
    pub(crate) shared: alloc::DefaultAllocator,
    #[allow(dead_code)] // the M1/M2 init block only (build_impl)
    pub(crate) shared_ro: alloc::DefaultAllocator,
    #[allow(dead_code)]
    pub(crate) gpu: alloc::DefaultAllocator,
    pub(crate) gpu_ro: alloc::DefaultAllocator,
    /// G15: firmware-written words the host polls (the CL stamp words),
    /// mapped FW-uncached like the kext's host stamp array
    /// (`createGPUMappingInTask(…, 0x700000007)`: perm 3 + kUATMapFWUncached)
    /// — through the firmware's cached mapping its writes reached memory
    /// late, after the completion event (boots #105, #107).
    pub(crate) stamp: alloc::DefaultAllocator,
    /// G15: buffers the firmware maps Normal non-cacheable, as the kext maps
    /// its block 2 (the event page, the firmware-to-host rings, the
    /// control blocks) and the power block: the firmware's own caches
    /// don't see the host's writes (spec: faults.md, "The fork's hang").
    pub(crate) fw_nc: alloc::DefaultAllocator,
    /// G15: hardware tables the GPU reads and writes back and the firmware
    /// edits with no cache maintenance (the UMA pool and parameter-buffer
    /// descriptor tables), mapped as the kext's `createHardwareMappings`
    /// does: firmware non-cacheable (no cached bit 41). Through a cached
    /// mapping the firmware's edits stayed in its cache while the GPU
    /// worked from memory (spec: uma.md, "The reset after a recovery").
    pub(crate) gpu_fw_nc: alloc::DefaultAllocator,
}

/// Receive (GPU->driver) ring buffer channels.
#[versions(AGX)]
#[pin_data]
struct RxChannels {
    event: channel::EventChannel::ver,
    fw_log: channel::FwLogChannel,
    ktrace: channel::KTraceChannel,
    stats: channel::StatsChannel::ver,
}

/// GPU work submission pipe channels (driver->GPU).
#[versions(AGX)]
struct PipeChannels {
    pub(crate) vtx: KVec<Pin<KBox<Mutex<channel::PipeChannel::ver>>>>,
    pub(crate) frag: KVec<Pin<KBox<Mutex<channel::PipeChannel::ver>>>>,
    pub(crate) comp: KVec<Pin<KBox<Mutex<channel::PipeChannel::ver>>>>,
}

/// Misc command transmit (driver->GPU) channels.
#[versions(AGX)]
#[pin_data]
struct TxChannels {
    pub(crate) device_control: channel::DeviceControlChannel::ver,
}

/// Number of work submission pipes per type, one for each priority level.
const NUM_PIPES: usize = 4;

/// A generic monotonically incrementing ID used to uniquely identify object instances within the
/// driver.
pub(crate) struct ID(AtomicU64);

impl ID {
    /// Create a new ID counter with a given value.
    fn new(val: u64) -> ID {
        ID(AtomicU64::new(val))
    }

    /// Fetch the next unique ID.
    pub(crate) fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for ID {
    /// IDs default to starting at 2, as 0/1 are considered reserved for the system.
    fn default() -> Self {
        Self::new(2)
    }
}

/// A guard representing one active submission on the GPU. When dropped, decrements the active
/// submission count.
pub(crate) struct OpGuard(Arc<dyn GpuManagerPriv>);

impl Drop for OpGuard {
    fn drop(&mut self) {
        self.0.end_op();
    }
}

/// Set of global sequence IDs used in the driver.
#[derive(Default)]
pub(crate) struct SequenceIDs {
    /// `File` instance ID.
    pub(crate) file: ID,
    /// `Vm` instance ID.
    pub(crate) vm: ID,
    /// Submission instance ID.
    pub(crate) submission: ID,
    /// `Queue` instance ID.
    pub(crate) queue: ID,
}

/// Top-level GPU manager that owns all the global state relevant to the driver instance.
#[versions(AGX)]
#[pin_data]
pub(crate) struct GpuManager {
    dev: AsahiDevRef,
    cfg: &'static hw::HwConfig,
    dyncfg: hw::DynConfig,
    pub(crate) initdata: fw::types::GpuObject<fw::initdata::InitData::ver>,
    uat: mmu::Uat,
    crashed: AtomicBool,
    #[pin]
    alloc: Mutex<KernelAllocators>,
    io_mappings: KVec<mmu::KernelMapping>,
    next_mmio_iova: u64,
    #[pin]
    rtkit: Mutex<Option<rtkit::RtKit<GpuManager::ver>>>,
    #[pin]
    rx_channels: Mutex<RxChannels::ver>,
    #[pin]
    tx_channels: Mutex<TxChannels::ver>,
    #[pin]
    fwctl_channel: Mutex<channel::FwCtlChannel>,
    pipes: PipeChannels::ver,
    event_manager: Arc<event::EventManager>,
    buffer_mgr: buffer::BufferManager::ver,
    ids: SequenceIDs,
    #[allow(clippy::vec_box)]
    #[pin]
    garbage_contexts: Mutex<KVec<KBox<fw::types::GpuObject<fw::workqueue::GpuContextData>>>>,
    /// G15: job completions seen on the event ring (record type 1, the
    /// queue-bitmask completion, or 0xA, the command-buffer completion;
    /// spec: agx-g15c/channel-table.md, the event ring).
    g15_completions: AtomicU64,
    /// G15: the firmware's 0x42 notifications received (diagnostics).
    g15_notifies: AtomicU64,
    /// G15: the doorbells the poller re-rang for unconsumed ring entries.
    g15_rerings: AtomicU64,
    /// Doorbells rung for jobs unfinished after `G15_NUDGE_MS`.
    g15_nudges: AtomicU64,
    /// G15 lab: the last 256 records of the firmware's trace ring (with the ktrace flags on,
    /// `DebugFlags::Debug4`), and where the next goes.
    #[pin]
    g15_trace: Mutex<(KVec<[u64; 7]>, usize)>,
    /// G15: the GPU interrupts taken (diagnostics).
    g15_irqs: AtomicU64,
    /// G15: each ring's next entry index (`fw::g15::ring`; the kext's
    /// AGXAcceleratorRing cursor), held from an entry's reservation to the
    /// store of the ring's write index: every queue's jobs share the rings,
    /// and an index published out of order shows the consumer an entry
    /// still being written (a NULL record slot, `AGFA_RecordDispatch`+0x130).
    #[pin]
    g15_rings: Mutex<[u32; fw::g15::RINGS]>,
    /// G15: the render self-test's state, kept for the device's lifetime.
    #[pin]
    g15_render_test: Mutex<Option<KBox<G15RenderTest>>>,
    /// G15: the self-test's channel and jobs, kept for the device's
    /// lifetime (the firmware's DAG root and notifier list reference them).
    #[pin]
    g15_selftest: Mutex<Option<(KBox<G15ClChannel>, KVec<G15ClJob>)>>,
    /// G15: the submitted CL jobs of every queue, in submit order.
    #[pin]
    g15_pending: Mutex<KVec<G15ClPending>>,
    /// G15: serializes the firmware-to-host ring drains.
    #[pin]
    g15_drain_lock: Mutex<()>,
    /// G15: the CL channels' stamp indices in use (bit i = index i).
    g15_stamp_ids: Arc<Mutex<u128>>,
    /// G15: the parameter buffers' hardware IDs in use (bit 0: the render
    /// self-test's).
    g15_pb_ids: Arc<Mutex<u64>>,
    /// G15: each buffer ID's firmware-visible parameter-buffer state, kept
    /// for the device's lifetime (`G15PbState`).
    #[pin]
    g15_pb_states: Mutex<[Option<Arc<G15PbState>>; 64]>,
    /// G15: the render jobs' IDs (js+0x884 / +0xBCC), two per pass.
    g15_rd_ids: AtomicU32,
    /// G15: the TA and 3D channel pairs of destroyed queues, for reuse
    /// (as `g15_free_chans`).
    #[pin]
    g15_free_rd_chans: Mutex<KVec<G15RdChans>>,
    /// G15: starts the driver's completion poller (set by the probe): a
    /// job's stamp and event record can trail the signals that come with
    /// it, or come without one (boots #105-#114), so the stamps are
    /// polled every jiffy while a CL job is pending.
    #[pin]
    g15_kick: Mutex<Option<KBox<dyn Fn() + Send + Sync>>>,
    /// G15: the rest of submissions held back until another kind of job
    /// completes; each returns true once it has submitted all of it. The
    /// poller advances them (queue::G15Run).
    #[pin]
    g15_deferred: Mutex<KVec<KBox<dyn FnMut() -> bool + Send>>>,
    /// G15: since when each ring class (TA, 3D, CL) holds entries the
    /// firmware has not consumed (the poller re-rings it).
    #[pin]
    g15_ring_stall: Mutex<[Option<Instant<Monotonic>>; 3]>,
    /// G15: the CL channels of destroyed queues, for reuse: the firmware's
    /// job table keeps a channel's job-slot object, and freeing it under the
    /// firmware crashed it (a NULL slot object in sub_3F68C, boot #115).
    #[pin]
    g15_free_chans: Mutex<KVec<Arc<Mutex<G15ClChannel>>>>,
    /// G15: channels returned with a job still unfinished (a hung job):
    /// never reused — later jobs would queue behind it — and never freed.
    #[pin]
    g15_dead_chans: Mutex<KVec<Arc<Mutex<G15ClChannel>>>>,
    /// G15: the UMA page pool every job uses.
    g15_uma: Option<Arc<G15Uma>>,
}

/// G15: a UMA page pool (spec: agx-g15c/uma.md, "A pool for the fork").
/// gUPM backs a launch's dynamic on-chip storage with its pages; every job
/// registers the pool at its descriptor-table slot (the firmware keys a
/// pool by its state and slot, never by channel).
pub(crate) struct G15Uma {
    /// The descriptor-table slot (0..255); the pool ID is slot + 1.
    pub(crate) slot: u32,
    /// The pool memory: `G15_UMA_BLOCKS` blocks of 8192 pages of 4 KiB, GPU
    /// read-write.
    _mem: KVec<fw::types::GpuArray<u8>>,
    /// The page list: a ring of `G15_UMA_CAPACITY` u64 page addresses.
    _pages: fw::types::GpuArray<u8>,
    /// The backup range list (8 entries of 8 B per block), for a pool reset.
    _backup: fw::types::GpuArray<u8>,
    /// The 0x70 B pool state ("UMA Page Pool State", job state +0x83E).
    pub(crate) state: fw::types::GpuArray<u8>,
    /// The u64 submit count (pool state +0x48): +1 per job before its
    /// doorbell; the firmware flushes the slot when its completion count
    /// (+0x50) catches up.
    submits: fw::types::GpuArray<u8>,
    /// The metrics buffer: one 0x40 B slot per job (MRR 0x14070; the GPU
    /// writes the kick's peak page use at +0x00).
    metrics: fw::types::GpuArray<u8>,
    /// The next metrics slot (byte offset, mod 0x4000).
    metrics_next: AtomicU32,
}

/// G15: the UMA pool's blocks of 8192 pages (32 MiB), its pages and the
/// page-list capacity. Five blocks: Metal's own minimum for any compute
/// pass on this chip is 14952 pages and the kext's private pool for it 64 MiB
/// (spec: uma.md, "Sizes"); the first pool had one block, 832 pages above
/// the per-kick constant.
const G15_UMA_BLOCKS: usize = 5;
const G15_UMA_BLOCK_PAGES: usize = 8192;
const G15_UMA_PAGES: usize = G15_UMA_BLOCKS * G15_UMA_BLOCK_PAGES;
const G15_UMA_CAPACITY: usize = 0x10000;
/// G15: the GPU's view of a VA, its low 43 bits (bit 42 = the kernel half).
const G15_GPU_VA_MASK: u64 = 0x7FF_FFFF_FFFF;

impl core::fmt::Debug for G15Uma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("G15Uma").field("slot", &self.slot).finish()
    }
}

impl G15Uma {
    fn new(alloc: &mut KernelAllocators, slot: u32) -> Result<G15Uma> {
        let mut mem = KVec::new();
        for _ in 0..G15_UMA_BLOCKS {
            mem.push(
                alloc.gpu.array_empty_tagged::<u8>(G15_UMA_BLOCK_PAGES * 0x1000, b"UMAM")?,
                GFP_KERNEL,
            )?;
        }
        let pages = alloc.gpu.array_empty_tagged::<u8>(G15_UMA_CAPACITY * 8, b"UMAL")?;
        let backup = alloc.gpu.array_empty_tagged::<u8>(G15_UMA_BLOCKS * 0x40, b"UMAB")?;
        let metrics = alloc.gpu.array_empty_tagged::<u8>(0x4000, b"UMAX")?;
        let state = alloc.shared.array_empty_tagged::<u8>(0x70, b"UMAS")?;
        let submits = alloc.stamp.array_empty_tagged::<u8>(8, b"UMAC")?;
        let pages_gva = pages.gpu_va().get() & G15_GPU_VA_MASK;
        let backup_gva = backup.gpu_va().get() & G15_GPU_VA_MASK;
        // SAFETY: in-bounds stores into the pool's own freshly allocated
        // (zeroed) buffers.
        unsafe {
            // populatePagePool: page i at entry i, the rest of the ring 0.
            let l = pages.raw_ptr().cast::<u64>();
            // The backup ranges: [47:12] the page address, [63:52] pages; a
            // block takes three and five zero entries.
            let b = backup.raw_ptr().cast::<u64>();
            for (k, blk) in mem.iter().enumerate() {
                let base = blk.gpu_va().get() & G15_GPU_VA_MASK;
                for j in 0..G15_UMA_BLOCK_PAGES {
                    l.add(k * G15_UMA_BLOCK_PAGES + j)
                        .write_volatile(base + (j as u64) * 0x1000);
                }
                b.add(k * 8).write_volatile(base | 0xFFF << 52);
                b.add(k * 8 + 1).write_volatile((base + 0xFFF000) | 0xFFF << 52);
                b.add(k * 8 + 2).write_volatile((base + 0x1FFE000) | 2 << 52);
            }
            // populateFirmwareState
            let s = state.raw_ptr();
            s.cast::<u64>().write_volatile(u64::from(slot) + 1); // +0x00 pool ID
            s.add(0x08).cast::<u32>().write_volatile(slot); // +0x08 table slot
            s.add(0x14).cast::<u64>().write_unaligned(pages_gva); // page list
            s.add(0x1C).cast::<u32>().write_volatile(G15_UMA_CAPACITY as u32);
            s.add(0x20).cast::<u32>().write_volatile(0); // head
            s.add(0x24).cast::<u32>().write_volatile((G15_UMA_PAGES % G15_UMA_CAPACITY) as u32); // tail
            s.add(0x2C).cast::<u32>().write_volatile(G15_UMA_PAGES as u32); // free pages
            s.add(0x34).cast::<u64>().write_unaligned(backup_gva); // backup list
            s.add(0x44).cast::<u32>().write_volatile(8 * G15_UMA_BLOCKS as u32); // backup entries
            s.add(0x48).cast::<u64>().write_volatile(submits.gpu_va().get()); // -> submit count
            s.add(0x50).cast::<u64>().write_volatile(0); // completion count
        }
        crate::mem::dc_civac(submits.raw_ptr().cast_const(), 8);
        Ok(G15Uma {
            slot,
            _mem: mem,
            _pages: pages,
            _backup: backup,
            state,
            submits,
            metrics,
            metrics_next: AtomicU32::new(0),
        })
    }

    /// The next job's metrics slot, zeroed: its GPU VA.
    fn metrics_slot(&self) -> u64 {
        let off = self.metrics_next.fetch_add(0x40, Ordering::Relaxed) % 0x4000;
        // SAFETY: a 0x40 B in-bounds slot of the metrics buffer.
        unsafe {
            core::ptr::write_bytes(self.metrics.raw_ptr().add(off as usize), 0, 0x40);
        }
        self.metrics.gpu_va().get() + u64::from(off)
    }

    /// Logs the pool state the firmware and GPU keep (head, tail, flag,
    /// free pages, reset state, completions; the host's submit count) and
    /// its descriptor-table entry (spec: uma.md, "The descriptor table").
    fn log(&self, dev: &kernel::device::Device, table: &fw::types::GpuArray<u8>, tag: &str) {
        let s = self.state.raw_ptr();
        let t = table.raw_ptr().wrapping_add(self.slot as usize * 0x20);
        crate::mem::dc_civac(s.cast_const(), 0x70);
        crate::mem::dc_civac(t.cast_const(), 0x20);
        crate::mem::dc_civac(self.submits.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds reads of the 0x70 B state, the 8 B submit count
        // and the slot's 0x20 B table entry.
        unsafe {
            let r32 = |off: usize| (s.add(off) as *const u32).read_volatile();
            let e = |i: usize| (t.add(i * 8) as *const u64).read_volatile();
            dev_err!(dev, "G15: UMA pool {} (slot {}) {}: head {:#x} tail {:#x} flag {:#x} free {:#x} reset {} completions {} submits {}; table {:#x} {:#x} {:#x}\n",
                     self.slot + 1, self.slot, tag, r32(0x20), r32(0x24), r32(0x28), r32(0x2C), r32(0x30),
                     (s.add(0x50) as *const u64).read_volatile(),
                     (self.submits.raw_ptr() as *const u64).read_volatile(),
                     e(0), e(1), e(2));
        }
    }

    /// One more job submitted (AGXUMAFList::updateSubmitInfo), before its
    /// doorbell.
    pub(crate) fn count_submit(&self) {
        let p = self.submits.raw_ptr();
        // SAFETY: the u64 submit count, 8 B aligned; written by the host only.
        unsafe { (*(p as *const AtomicU64)).fetch_add(1, Ordering::AcqRel) };
        crate::mem::dc_civac(p.cast_const(), 8);
    }
}

/// G15: one CL channel (the kext's `AGXChannel` for a CL queue; spec:
/// agx-g15c/cl-job.md, "Successive jobs on one channel"): the state
/// object and the buffers every job of the channel shares.
pub(crate) struct G15ClChannel {
    /// The 0x24C0 B state object (the kext's `_AGFIChannelState`,
    /// `AGXChannel::resetChannelState`): the ring entry's +0x08. The
    /// consumer/dispatcher/registration dereference it (cursors at
    /// +0x20/+0x28, priority stage +0x30, record slots +0x08, stamp table
    /// +0x18, job-slot object +0xA4, capacity +0x50).
    pub(crate) state: fw::types::GpuArray<u8>,
    /// The state's +0x00 target (uncached channel memory): +0x30 = the
    /// last command ID (firmware-written), +0x50 = the slot capacity.
    pub(crate) chan_uncached: fw::types::GpuArray<u8>,
    /// The state's +0x08 target: the 8 B record slots (slot\[i\] = job
    /// state GPUVA), 256 slots.
    pub(crate) chan_cached: fw::types::GpuArray<u8>,
    /// The state's +0x18 target: the 128 x 0x48 B stamp-entry table,
    /// zeroed once (registration rewrites table\[sequence\] per job).
    pub(crate) stamp_table: fw::types::GpuArray<u8>,
    /// The state's +0xA4 target: the 0x38 B job-slot object (fresh: +0x00
    /// = +0x01 = 0xFF; the firmware allocates on use).
    pub(crate) job_slot: fw::types::GpuArray<u8>,
    /// The stand-in for the channel's +0x1B0 buffer: the context record's
    /// +0x180…+0x198 group points into it, sized as `AGXCLChannel::init`
    /// does for t6034 (S = 0x3C000, T = 0x2000: A = base, B = A + S,
    /// C = A + 2S, D = C + T, `(2S + T) | 0x400` B).
    pub(crate) ctx_store: fw::types::GpuArray<u8>,
    /// The state's +0x10 target: the notifier-list header {0, P+0x10, 0,
    /// P+0x20, 0} (`sub_27D40`; every value a GPUVA, boot #62).
    pub(crate) chan_list: fw::types::GpuArray<u8>,
    /// The CDM preempt buffer (register 0x1A510), zeroed.
    pub(crate) preempt: fw::types::GpuArray<u8>,
    /// The channel's two stamp words: +0x00 the host stamp word
    /// (js+0x7E8; the notifier walk writes the stamp value there at a
    /// flush), +0x04 the firmware stamp word (js+0x7F0, the start record
    /// +0x28; the in-order retire writes it).
    pub(crate) words: fw::types::GpuArray<u8>,
    /// Jobs submitted so far: the next job submitted is number
    /// submitted + 1 (its stamp, IDs and record slot are written at submit
    /// time, so a job built but never run leaves no gap in the stamp
    /// sequence).
    pub(crate) submitted: u32,
    /// Records published so far (render channels: a job can carry a
    /// pre-record, so the record cursor runs ahead of the job count).
    pub(crate) submitted_records: u32,
    /// The channel's stamp index (the DAG slot: ring +0x16, js+0x7FC), one
    /// of 1..127 like the kext's `requestStampIndexForChannel` (0 left
    /// unused).
    pub(crate) stamp_index: u32,
    /// The allocator the index returns to when the channel goes.
    stamp_ids: Option<Arc<Mutex<u128>>>,
}

impl Drop for G15ClChannel {
    fn drop(&mut self) {
        if let Some(ids) = self.stamp_ids.take() {
            *ids.lock() &= !(1u128 << self.stamp_index);
        }
    }
}

/// G15: a render queue's TA and 3D channels.
type G15RdChans = (Arc<Mutex<G15ClChannel>>, Arc<Mutex<G15ClChannel>>);

/// G15: the buffers of submitted work, kept until it retires.
#[allow(clippy::large_enum_variant, reason = "a few in flight; boxing adds an allocation per job")]
enum G15Work {
    Cl(G15ClJob),
    Rd(KBox<G15RdPass>),
}

impl G15Work {
    /// Whether the firmware still lists the work's notifier in its
    /// channel's notifier list (`+0x94`: the insert sets 1, the walk's
    /// unlink clears it). The walk follows a listed node to the job's stamp
    /// entries, so they stay allocated until the node is unlinked, even
    /// after the firmware stamp has passed (a freed one crashed the walk,
    /// a NULL store at `sub_FFFFFC000002749C+0x624`, 2026-10-17).
    fn notifier_listed(&self) -> bool {
        let n = match self {
            G15Work::Cl(j) => &j.notifier,
            G15Work::Rd(p) => p.notifier(),
        };
        let f = n.raw_ptr().wrapping_add(0x94);
        crate::mem::dc_civac(f.cast_const(), 4);
        // SAFETY: an in-bounds u32 read of the 0x100 B notifier.
        unsafe { (f as *const u32).read_volatile() != 0 }
    }
}

/// G15: submitted work waiting for its stamp — a CL job, or a render
/// pass (on its 3D's channel and stamp): `done` runs once the channel's
/// host stamp word reaches it; the buffers go once the firmware stamp word
/// does too (the firmware's in-order retire comes after).
pub(crate) struct G15ClPending {
    chan: Arc<Mutex<G15ClChannel>>,
    stamp: u32,
    /// The job's number on its channel, and its context (diagnostics).
    n: u32,
    ctx: u32,
    /// A render pass: its TA's channel and stamp (a recovery can catch
    /// either job).
    ta: Option<(Arc<Mutex<G15ClChannel>>, u32)>,
    _work: G15Work,
    done: KBox<dyn FnMut(Option<Error>) + Send>,
    signaled: bool,
    /// The job's failure, set by a firmware recovery that caught it.
    error: Option<Error>,
    /// When its class doorbells were last rung (at submit, then by the poller
    /// while the job is unfinished: `G15_NUDGE_MS`).
    nudge: Instant<Monotonic>,
    nudges: u32,
}

/// G15: one CL job's own buffers (a fresh set per job in flight).
#[derive(Debug)]
pub(crate) struct G15ClJob {
    /// The 0x880 B CL job state (tag 3; the register list at +0x20).
    /// GPU-readable: the CDM fetches the register list itself (boot #80).
    pub(crate) job_state: fw::types::GpuArray<u8>,
    /// The SKU stream (0x2B8 B in a 0x2C0 B slot; 0x400 so every record
    /// stays in-bounds).
    pub(crate) stream: fw::types::GpuArray<u8>,
    /// The notifier (js+0x14, the kext's command-buffer notifier, 0xC0
    /// B): +0x00 → a u32 count of the jobs submitted under it (here at
    /// +0xC0, = 1), +0x08 the sort key, +0x0C the firmware's completed
    /// count, +0x10 the flush threshold, +0xA8 the stale cutoff.
    pub(crate) notifier: fw::types::GpuArray<u8>,
    /// The CDM control stream when the kernel provides one (the
    /// self-test: a single CDM Stream Terminate block). Only held: the
    /// job's register list points the CDM at it (0x1A420).
    #[allow(dead_code)]
    pub(crate) cdm_stream: Option<fw::types::GpuArray<u8>>,
    /// The job's number on its channel (1-based; 0 until submitted).
    pub(crate) n: u32,
    /// The job's stamp value (js+0x7F8): n · 0x100. Done when the host
    /// stamp word reaches it (the kext's `testEvent`, signed).
    pub(crate) stamp: u32,
    /// The job's context ID (js+0x10).
    pub(crate) ctx: u32,
    /// The UMA pool the job registers.
    pub(crate) uma: Arc<G15Uma>,
}

/// Trait used to abstract the firmware/GPU-dependent variants of the GpuManager.
pub(crate) trait GpuManager: Send + Sync {
    /// Cast as an Any type.
    fn _as_any(&self) -> &dyn Any;
    /// Cast `Arc<Self>` as an Any type.
    fn arc_as_any(self: Arc<Self>) -> Arc<dyn Any + Sync + Send>;
    /// Initialize the GPU.
    fn init(&self) -> Result;
    /// Update the GPU globals from global info
    ///
    /// TODO: Unclear what can and cannot be updated like this.
    fn update_globals(&self);
    /// Get a reference to the KernelAllocators.
    fn alloc(&self) -> Guard<'_, KernelAllocators, MutexBackend>;
    /// Create a new `Vm` given a unique `File` ID.
    fn new_vm(&self, kernel_range: Range<u64>) -> Result<mmu::Vm>;
    /// Bind a `Vm` to an available slot and return the `VmBind`.
    fn bind_vm(&self, vm: &mmu::Vm) -> Result<mmu::VmBind>;
    /// Create a new user command queue.
    fn new_queue(
        &self,
        reg_data: &AsahiRegData<'_>,
        vm: mmu::Vm,
        ualloc: Arc<Mutex<alloc::DefaultAllocator>>,
        ualloc_priv: Arc<Mutex<alloc::DefaultAllocator>>,
        priority: u32,
        usc_exec_base: u64,
    ) -> Result<KBox<dyn queue::Queue>>;
    /// Return a reference to the global `SequenceIDs` instance.
    fn ids(&self) -> &SequenceIDs;
    /// Kick the firmware (wake it up if asleep).
    ///
    /// This should be useful to reduce latency on work submission, so we can ask the firmware to
    /// wake up while we do some preparatory work for the work submission.
    #[allow(dead_code)] // M1/M2 only: G15 does not kick (start_op)
    fn kick_firmware(&self) -> Result;
    /// Flush the entire firmware cache.
    ///
    /// TODO: Does this actually work?
    fn flush_fw_cache(&self) -> Result;
    /// Handle a GPU work timeout event.
    fn handle_timeout(&self, counter: u32, event_slot: i32, unk: u32);
    /// Handle a GPU fault event.
    fn handle_fault(&self);
    /// Handle a channel error event.
    fn handle_channel_error(
        &self,
        error_type: ChannelErrorType,
        pipe_type: u32,
        event_slot: u32,
        event_value: u32,
    );
    /// Acknowledge a Buffer grow op.
    fn ack_grow(&self, buffer_slot: u32, vm_slot: u32, counter: u32);
    /// Send a firmware control command (secure cache flush).
    fn fwctl(&self, msg: fw::channels::FwCtlMsg) -> Result;
    /// Get the static GPU configuration for this SoC.
    fn get_cfg(&self) -> &'static hw::HwConfig;
    /// G15: one of the GPU's own interrupts (the sgx node's, by index):
    /// drain the firmware-to-host rings, as the kext's
    /// `AGXFirmware::handleEvent` does for index 0 and 4. Returns the
    /// records and log messages drained.
    fn g15_irq(&self, index: u32) -> u64;
    /// G15: retire the CL jobs that completed; true while any is pending
    /// (the driver's poller runs while so).
    fn g15_poll(&self) -> bool;
    /// G15: the poller's kick, run at every CL submit.
    fn g15_set_kick(&self, kick: KBox<dyn Fn() + Send + Sync>);
    /// Get the dynamic GPU configuration for this SoC.
    fn get_dyncfg(&self) -> &hw::DynConfig;
    /// Register an unused context as garbage
    fn free_context(&self, data: KBox<fw::types::GpuObject<fw::workqueue::GpuContextData>>);
    /// Check whether the GPU is crashed
    fn is_crashed(&self) -> bool;
    /// Map a BO as a timestamp buffer
    fn map_timestamp_buffer(
        &self,
        bo: gem::ObjectRef,
        range: Range<usize>,
    ) -> Result<mmu::KernelMapping>;
}

/// Private generic trait for functions that don't need to escape this module.
trait GpuManagerPriv {
    /// Decrement the pending submission counter.
    fn end_op(&self);
}

pub(crate) struct RtkitObject {
    vmap: shmem::VMapOwned<gem::AsahiObject, 0>,
    mapping: mmu::KernelMapping,
}

/// G15: a buffer the IOP preallocated in its own memory (its crashlog
/// buffer, a physical address inside the firmware's `__DATA`), memremapped.
pub(crate) struct RtkitMapped {
    pa: usize,
    vaddr: *mut u8,
    size: usize,
}

impl Drop for RtkitMapped {
    fn drop(&mut self) {
        // SAFETY: `vaddr` is the memremap() result of `shmem_map`.
        unsafe { kernel::bindings::memunmap(self.vaddr.cast()) };
    }
}

/// An RTKit buffer: one the driver allocated in the firmware's VM, or one
/// the IOP preallocated.
pub(crate) enum RtkitBuffer {
    Object(RtkitObject),
    Mapped(RtkitMapped),
}

impl rtkit::Buffer for RtkitBuffer {
    fn iova(&self) -> Result<usize> {
        match self {
            Self::Object(o) => Ok(o.mapping.iova() as usize),
            Self::Mapped(m) => Ok(m.pa),
        }
    }
    fn buf(&mut self) -> Result<IoSysMap<'_, Region>> {
        match self {
            Self::Object(o) => Ok(IoSysMap::from(o.vmap.as_view())),
            // SAFETY: the memremap covers `size` bytes of memory for as long
            // as `self` lives.
            Self::Mapped(m) => Ok(IoSysMap::from(unsafe {
                kernel::io::SysMem::new(Region::ptr_from_raw_parts_mut(m.vaddr, m.size))
            })),
        }
    }
}

#[versions(AGX)]
#[vtable]
impl rtkit::Operations for GpuManager::ver {
    type Data = Arc<GpuManager::ver>;
    type Buffer = RtkitBuffer;

    fn recv_message(data: <Self::Data as ForeignOwnable>::Borrowed<'_>, ep: u8, msg: u64) {
        let dev = &data.dev;
        //dev_info!(dev.as_ref(), "RtKit message: {:#x}:{:#x}\n", ep, msg);

        if ep != EP_FIRMWARE || msg != MSG_RX_DOORBELL {
            dev_err!(dev.as_ref(), "Unknown message: {:#x}:{:#x}\n", ep, msg);
            return;
        }

        // G15: the notification carries no ring ID; drain all four
        // firmware-to-host rings (the kext's handleEvent case 4).
        data.g15_notifies.fetch_add(1, Ordering::Relaxed);
        data.g15_drain_fw_rings();

        #[ver(G != G15)]
        if true {
            let mut ch = data.rx_channels.lock();

            ch.fw_log.poll();
            ch.ktrace.poll();
            ch.stats.poll();
            ch.event.poll();
        }
    }

    fn crashed(data: <Self::Data as ForeignOwnable>::Borrowed<'_>, _crashlog: Option<&[u8]>) {
        let dev = &data.dev;

        data.crashed.store(true, Ordering::Relaxed);
        // Lab: the firmware's segments and its crashlog page (in __DATA).
        g15_fwdump(G15_FWDUMP_CRASH);

        if debug_enabled(DebugFlags::OopsOnGpuCrash) {
            panic!("GPU firmware crashed");
        } else {
            dev_err!(dev.as_ref(), "GPU firmware crashed, failing all jobs\n");
            data.event_manager.fail_all(workqueue::WorkError::NoDevice);
        }
    }

    fn shmem_alloc(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        size: usize,
    ) -> Result<Self::Buffer> {
        let dev = &data.dev;
        mod_dev_dbg!(dev, "shmem_alloc() {:#x} bytes\n", size);

        let mut obj = gem::new_kernel_object(dev, size)?;
        let vmap = obj.gem.owned_vmap::<0>()?;
        let mapping = obj.map_into_range(
            data.uat.kernel_vm(),
            IOVA_KERN_RTKIT_RANGE,
            mmu::UAT_PGSZ as u64,
            mmu::PROT_FW_SHARED_RW,
            true,
        )?;
        mod_dev_dbg!(dev, "shmem_alloc() -> VA {:#x}\n", mapping.iova());
        Ok(RtkitBuffer::Object(RtkitObject { vmap, mapping }))
    }

    fn shmem_map(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        iova: usize,
        size: usize,
    ) -> Result<Self::Buffer> {
        // G15: the IOP preallocates its crashlog buffer and names it by
        // physical address, inside the firmware's own __DATA (0x4000 B at
        // 0x10001D08000 since boot #28). Linux's RTKit decodes a crash from it.
        // SAFETY: memremap() of a range the IOP owns; write-back like the
        // IOP's own view of its data segment.
        let vaddr = unsafe {
            kernel::bindings::memremap(iova as u64, size, kernel::bindings::MEMREMAP_WB as usize)
        };
        if vaddr.is_null() {
            dev_err!(data.dev.as_ref(), "RTKit: cannot map the IOP's buffer at {:#x}\n", iova);
            return Err(ENOMEM);
        }
        dev_info!(data.dev.as_ref(), "RTKit: the IOP's {:#x}-byte buffer at {:#x} mapped\n", size, iova);
        Ok(RtkitBuffer::Mapped(RtkitMapped { pa: iova, vaddr: vaddr.cast(), size }))
    }
}

#[versions(AGX)]
impl GpuManager::ver {
    /// Create a new GpuManager of this version/GPU combination.
    #[inline(never)]
    pub(crate) fn new(
        dev: &AsahiDrmDevice,
        res: &regs::Resources<'_>,
        cfg: &'static hw::HwConfig,
    ) -> Result<Arc<GpuManager::ver>> {
        let uat = Self::make_uat(dev, cfg)?;

        // G15: the GPU's eGART — the MMU config block with the GPTBAT base
        // (the kext's AGXSecureMonitorG15::setupMMUConfig): program it if
        // the gate reads 0, else check it points at our TTBAT. After the
        // TTBAT is filled (make_uat) and before any job (spec: uat.md § the
        // G15 MMU enable). Uses `res` directly: at this point of the probe
        // the AsahiData (dev.resources) is not pinned yet (boot #62).
        #[ver(G == G15)]
        if true {
            let want = ((uat.ttb_base() >> 14) & 0xfff_ffff) as u32;
            match res.setup_g15_mmu(uat.ttb_base()) {
                Some((programmed, enable, base)) => {
                    let msg = if programmed { "programmed" } else { "already set" };
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

        let dyncfg = Self::make_dyncfg(dev, res, cfg, &uat)?;

        // G15: the job buffers (`shared`, `gpu`) are not reused at once (see `G15_QUARANTINE_*`).
        let g15_quarantine = matches!(cfg.gpu_gen, hw::GpuGen::G15);

        let private = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_PRIV_RANGE,
            0x80,
            mmu::PROT_FW_PRIV_RW,
            1024 * 1024,
            true,
            fmt!("Kernel Private"),
            true,
        )?;
        let shared = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_SHARED_RANGE,
            0x80,
            mmu::PROT_FW_SHARED_RW,
            1024 * 1024,
            true,
            fmt!("Kernel Shared"),
            g15_quarantine,
        )?;
        let shared_ro = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_SHARED_RO_RANGE,
            0x80,
            mmu::PROT_FW_SHARED_RO,
            64 * 1024,
            true,
            fmt!("Kernel RO Shared"),
            false,
        )?;
        let gpu = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_GPU_RANGE,
            0x80,
            mmu::PROT_GPU_FW_SHARED_RW,
            64 * 1024,
            true,
            fmt!("Kernel GPU Shared"),
            g15_quarantine,
        )?;
        let gpu_ro = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_GPU_RO_RANGE,
            0x80,
            mmu::PROT_GPU_RO_FW_PRIV_RW,
            1024 * 1024,
            true,
            fmt!("Kernel GPU RO Shared"),
            true,
        )?;

        let stamp = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_STAMP_RANGE,
            0x80,
            mmu::PROT_FW_MMIO_RW,
            16 * 1024,
            true,
            fmt!("Kernel Stamp"),
            false,
        )?;
        let fw_nc = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_FW_NC_RANGE,
            0x80,
            mmu::PROT_FW_NC_RW,
            1024 * 1024,
            true,
            fmt!("Kernel FW NC"),
            false,
        )?;
        let gpu_fw_nc = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_GPU_FW_NC_RANGE,
            0x80,
            mmu::PROT_GPU_FW_NC_RW,
            64 * 1024,
            true,
            fmt!("Kernel GPU FW NC"),
            false,
        )?;

        let mut alloc = KernelAllocators {
            private,
            shared,
            shared_ro,
            gpu,
            gpu_ro,
            stamp,
            fw_nc,
            gpu_fw_nc,
        };

        let event_manager = Self::make_event_manager(&mut alloc)?;
        #[allow(unused_mut)] // only the M1/M2 path maps into it
        let mut initdata = Self::make_initdata(dev, cfg, &dyncfg, &mut alloc)?;

        // G15 publishes none of the M1 runtime pointers; the G15 buffer set
        // is its own `InitData` (M3 work for the channel model).
        #[ver(G != G15)]
        if true {
            initdata.runtime_pointers.buffer_mgr_ctl_low_mapping =
                Some(initdata.runtime_pointers.buffer_mgr_ctl.map_at(
                    uat.kernel_lower_vm(),
                    IOVA_KERN_GPU_BUFMGR_LOW,
                    mmu::PROT_GPU_SHARED_RW,
                    false,
                )?);
            initdata.runtime_pointers.buffer_mgr_ctl_high_mapping =
                Some(initdata.runtime_pointers.buffer_mgr_ctl.map_at(
                    uat.kernel_vm(),
                    IOVA_KERN_GPU_BUFMGR_HIGH,
                    mmu::PROT_FW_SHARED_RW,
                    false,
                )?);
        }

        let mut mgr = Self::make_mgr(dev, cfg, dyncfg, uat, alloc, event_manager, initdata)?;

        // The M1 channel model (fwctl, the tx/rx channels, the pipes) is
        // published in the runtime pointers; the G15 channel model (12+1
        // channels into the channel info table) is M3 work.
        #[ver(G != G15)]
        if true {
            {
                let fwctl = mgr.fwctl_channel.lock();
                let p_fwctl = fwctl.to_raw();
                core::mem::drop(fwctl);

                mgr.as_mut()
                    .initdata_mut()
                    .fw_status
                    .with_mut(|raw, _inner| {
                        raw.fwctl_channel = p_fwctl;
                    });
            }

            {
                let txc = mgr.tx_channels.lock();
                let p_device_control = txc.device_control.to_raw();
                core::mem::drop(txc);

                let rxc = mgr.rx_channels.lock();
                let p_event = rxc.event.to_raw();
                let p_fw_log = rxc.fw_log.to_raw();
                let p_ktrace = rxc.ktrace.to_raw();
                let p_stats = rxc.stats.to_raw();
                let p_fwlog_buf = rxc.fw_log.get_buf();
                core::mem::drop(rxc);

                mgr.as_mut()
                    .initdata_mut()
                    .runtime_pointers
                    .with_mut(|raw, _inner| {
                        raw.device_control = p_device_control;
                        raw.event = p_event;
                        raw.fw_log = p_fw_log;
                        raw.ktrace = p_ktrace;
                        raw.stats = p_stats;
                        raw.fwlog_buf = Some(p_fwlog_buf);
                    });
            }

            let mut p_pipes: KVec<fw::initdata::raw::PipeChannels::ver> = KVec::new();

            for ((v, f), c) in mgr
                .pipes
                .vtx
                .iter()
                .zip(&mgr.pipes.frag)
                .zip(&mgr.pipes.comp)
            {
                p_pipes.push(
                    fw::initdata::raw::PipeChannels::ver {
                        vtx: v.lock().to_raw(),
                        frag: f.lock().to_raw(),
                        comp: c.lock().to_raw(),
                    },
                    GFP_KERNEL,
                )?;
            }

            mgr.as_mut()
                .initdata_mut()
                .runtime_pointers
                .with_mut(|raw, _inner| {
                    for (i, p) in p_pipes.into_iter().enumerate() {
                        raw.pipes[i].vtx = p.vtx;
                        raw.pipes[i].frag = p.frag;
                        raw.pipes[i].comp = p.comp;
                    }
                });
        }

        // (The M1 channel-model publication above is G != G15; everything
        // from here on runs on G15 too. The io_mappings loop and the sram
        // mapping used to sit inside that gated block and were silently
        // dropped by the versions macro on G15 — fixed 2026-10-09.)
        for (i, map) in cfg.io_mappings.iter().enumerate() {
            if let Some(map) = map.as_ref() {
                Self::iomap(&mut mgr, cfg, i, map)?;
            }
        }

        Self::g15_map_windows(&mut mgr, cfg)?;

        // M1 model: map the sgx sram into the kernel VM and publish it in
        // hwdata_b. G15 has no such hwdata_b field — the RAM ring region
        // replaces the role the sram mapping served (the GPU gets IOVAs).
        #[ver(G != G15)]
        if let Some(base) = cfg.sram_base {
            let size = cfg.sram_size.unwrap();
            let iova = mgr.as_mut().alloc_mmio_iova(size);

            let mapping = mgr.uat.kernel_vm().map_io(
                dev.as_ref().as_ref(),
                iova,
                base,
                size,
                mmu::PROT_FW_SHARED_RW,
            )?;

            mgr.as_mut()
                .initdata_mut()
                .runtime_pointers
                .hwdata_b
                .with_mut(|raw, _| {
                    raw.sgx_sram_ptr = U64(mapping.iova());
                });

            mgr.as_mut().io_mappings_mut().push(mapping, GFP_KERNEL)?;
        }

        let mgr = Arc::from(mgr);

        // G15: RTKit through the DT's gfx-asc mailbox (EL1 reaches the block
        // at its CPU address, boots #85/#86).
        {
            let rtkit =
                rtkit::RtKit::<GpuManager::ver>::new(dev.as_ref().as_ref(), None, 0, mgr.clone())?;
            *mgr.rtkit.lock() = Some(rtkit);
        }

        {
            let mut rxc = mgr.rx_channels.lock();
            rxc.event.set_manager(mgr.clone());
        }

        Ok(mgr)
    }

    /// Return a mutable reference to the initdata member
    fn initdata_mut(
        self: Pin<&mut Self>,
    ) -> &mut fw::types::GpuObject<fw::initdata::InitData::ver> {
        // SAFETY: initdata does not require structural pinning.
        unsafe { &mut self.get_unchecked_mut().initdata }
    }

    /// Return a mutable reference to the io_mappings member
    fn io_mappings_mut(self: Pin<&mut Self>) -> &mut KVec<mmu::KernelMapping> {
        // SAFETY: io_mappings does not require structural pinning.
        unsafe { &mut self.get_unchecked_mut().io_mappings }
    }

    /// Allocate an MMIO iova range
    fn alloc_mmio_iova(self: Pin<&mut Self>, size: usize) -> u64 {
        // SAFETY: next_mmio_iova does not require structural pinning.
        let next_ref = unsafe { &mut self.get_unchecked_mut().next_mmio_iova };

        let addr = *next_ref;
        let next = addr + (size + mmu::UAT_PGSZ) as u64;

        assert!(next <= IOVA_KERN_MMIO_RANGE.end);

        *next_ref = next;

        addr
    }

    /// Build the entire GPU InitData structure tree and return it as a boxed GpuObject.
    fn make_initdata(
        dev: &AsahiDrmDevice,
        cfg: &'static hw::HwConfig,
        dyncfg: &hw::DynConfig,
        alloc: &mut KernelAllocators,
    ) -> Result<KBox<fw::types::GpuObject<fw::initdata::InitData::ver>>> {
        let mut builder = initdata::InitDataBuilder::ver::new(dev, alloc, cfg, dyncfg);
        builder.build()
    }

    /// Create a fresh boxed Uat instance.
    ///
    /// Force disable inlining to avoid blowing up the stack.
    #[inline(never)]
    fn make_uat(dev: &AsahiDrmDevice, cfg: &'static hw::HwConfig) -> Result<KBox<mmu::Uat>> {
        // G14X has a new thing in the Scene structure that unfortunately requires
        // write access from user contexts. Hopefully it's not security-sensitive.
        #[ver(G >= G14X)]
        let map_kernel_to_user = true;
        #[ver(G < G14X)]
        let map_kernel_to_user = false;

        Ok(KBox::new(
            mmu::Uat::new(dev.into(), cfg, map_kernel_to_user)?,
            GFP_KERNEL,
        )?)
    }

    /// Actually create the final GpuManager instance, as a UniqueArc.
    ///
    /// Force disable inlining to avoid blowing up the stack.
    #[inline(never)]
    fn make_mgr(
        dev: &AsahiDrmDevice,
        cfg: &'static hw::HwConfig,
        dyncfg: KBox<hw::DynConfig>,
        uat: KBox<mmu::Uat>,
        mut alloc: KernelAllocators,
        event_manager: Arc<event::EventManager>,
        initdata: KBox<fw::types::GpuObject<fw::initdata::InitData::ver>>,
    ) -> Result<Pin<UniqueArc<GpuManager::ver>>> {
        let mut pipes = PipeChannels::ver {
            vtx: KVec::new(),
            frag: KVec::new(),
            comp: KVec::new(),
        };

        for _i in 0..=NUM_PIPES - 1 {
            pipes.vtx.push(
                KBox::pin_init(
                    new_mutex!(
                        channel::PipeChannel::ver::new(dev.into(), &mut alloc)?,
                        "pipe_vtx",
                    ),
                    GFP_KERNEL,
                )?,
                GFP_KERNEL,
            )?;
            pipes.frag.push(
                KBox::pin_init(
                    new_mutex!(
                        channel::PipeChannel::ver::new(dev.into(), &mut alloc)?,
                        "pipe_frag",
                    ),
                    GFP_KERNEL,
                )?,
                GFP_KERNEL,
            )?;
            pipes.comp.push(
                KBox::pin_init(
                    new_mutex!(
                        channel::PipeChannel::ver::new(dev.into(), &mut alloc)?,
                        "pipe_comp",
                    ),
                    GFP_KERNEL,
                )?,
                GFP_KERNEL,
            )?;
        }

        let fwctl_channel = channel::FwCtlChannel::new(dev.into(), &mut alloc)?;
        let g15_uma = match cfg.gpu_gen {
            hw::GpuGen::G15 => Some(Arc::new(G15Uma::new(&mut alloc, 0)?, GFP_KERNEL)?),
            _ => None,
        };

        let buffer_mgr = buffer::BufferManager::ver::new()?;
        let event_manager_clone = event_manager.clone();
        let buffer_mgr_clone = buffer_mgr.clone();
        let alloc_ref = &mut alloc;
        let rx_channels = KBox::init(
            try_init!(RxChannels::ver {
                event: channel::EventChannel::ver::new(
                    dev.into(),
                    alloc_ref,
                    event_manager_clone,
                    buffer_mgr_clone,
                )?,
                fw_log: channel::FwLogChannel::new(dev.into(), alloc_ref)?,
                ktrace: channel::KTraceChannel::new(dev.into(), alloc_ref)?,
                stats: channel::StatsChannel::ver::new(dev.into(), alloc_ref)?,
            }),
            GFP_KERNEL,
        )?;

        let alloc_ref = &mut alloc;
        let tx_channels = KBox::init(
            try_init!(TxChannels::ver {
                device_control: channel::DeviceControlChannel::ver::new(dev.into(), alloc_ref)?,
            }),
            GFP_KERNEL,
        )?;

        let x = UniqueArc::pin_init(
            try_pin_init!(GpuManager::ver {
                dev: dev.into(),
                cfg,
                dyncfg: KBox::<hw::DynConfig>::into_inner(dyncfg),
                initdata: KBox::<fw::types::GpuObject<fw::initdata::InitData::ver>>::into_inner(initdata),
                uat: KBox::<mmu::Uat>::into_inner(uat),
                io_mappings: KVec::new(),
                next_mmio_iova: IOVA_KERN_MMIO_RANGE.start,
                rtkit <- new_mutex!(None, "rtkit"),
                crashed: AtomicBool::new(false),
                event_manager,
                alloc <- new_mutex!(alloc, "alloc"),
                fwctl_channel <- new_mutex!(fwctl_channel, "fwctl_channel"),
                rx_channels <- new_mutex!(KBox::<RxChannels::ver>::into_inner(rx_channels), "rx_channels"),
                tx_channels <- new_mutex!(KBox::<TxChannels::ver>::into_inner(tx_channels), "tx_channels"),
                pipes,
                buffer_mgr,
                ids: Default::default(),
                garbage_contexts <- new_mutex!(KVec::new(), "garbage_contexts"),
                g15_completions: AtomicU64::new(0),
                g15_notifies: AtomicU64::new(0),
                g15_rerings: AtomicU64::new(0),
                g15_nudges: AtomicU64::new(0),
                g15_trace <- new_mutex!((KVec::<[u64; 7]>::new(), 0usize), "g15_trace"),
                g15_irqs: AtomicU64::new(0),
                g15_rings <- new_mutex!([0; fw::g15::RINGS], "g15_rings"),
                g15_render_test <- new_mutex!(None, "g15_render_test"),
                g15_selftest <- new_mutex!(None, "g15_selftest"),
                g15_pending <- new_mutex!(KVec::new(), "g15_pending"),
                g15_drain_lock <- new_mutex!((), "g15_drain_lock"),
                g15_stamp_ids: Arc::pin_init(new_mutex!(1u128, "g15_stamp_ids"), GFP_KERNEL)?,
                g15_pb_ids: Arc::pin_init(new_mutex!(1u64, "g15_pb_ids"), GFP_KERNEL)?,
                g15_pb_states <- new_mutex!([const { None }; 64], "g15_pb_states"),
                g15_rd_ids: AtomicU32::new(0x10_0000),
                g15_free_rd_chans <- new_mutex!(KVec::new(), "g15_free_rd_chans"),
                g15_kick <- new_mutex!(None, "g15_kick"),
                g15_deferred <- new_mutex!(KVec::new(), "g15_deferred"),
                g15_ring_stall <- new_mutex!([None, None, None], "g15_ring_stall"),
                g15_free_chans <- new_mutex!(KVec::new(), "g15_free_chans"),
                g15_dead_chans <- new_mutex!(KVec::new(), "g15_dead_chans"),
                g15_uma,
            }),
            GFP_KERNEL,
        )?;

        Ok(x)
    }

    fn load_hwdata_blob(dev: AsahiDevice, name: &CStr, size_name: &CStr) -> Result<KVVec<u8>> {
        let of_node = dev.as_ref().as_ref().of_node().ok_or(EINVAL)?;
        let size: usize = dev
            .as_ref()
            .as_ref()
            .fwnode()
            .ok_or(ENOENT)?
            .property_read::<u32>(size_name)
            .or(0)
            .try_into()?;
        let res = of_node.reserved_mem_region_to_resource_byname(name)?;
        // SAFETY: No dma here, just loading init data.
        let mem = unsafe { Mem::try_new(res, (MemFlag::WB).into())? };
        if size > mem.size() {
            return Err(ENOENT);
        }
        // SAFETY: trusting the bootloader to fill it out correctly
        let blob_sl = unsafe { slice::from_raw_parts(mem.ptr(), size) };
        let mut blob = KVVec::new();
        blob.extend_from_slice(blob_sl, GFP_KERNEL)?;
        Ok(blob)
    }

    /// Fetch and validate the GPU dynamic configuration from the device tree and hardware.
    ///
    /// Force disable inlining to avoid blowing up the stack.
    #[inline(never)]
    fn make_dyncfg(
        dev: &AsahiDrmDevice,
        res: &regs::Resources<'_>,
        cfg: &'static hw::HwConfig,
        uat: &mmu::Uat,
    ) -> Result<KBox<hw::DynConfig>> {
        let gpu_id = res.get_gpu_id(cfg)?;

        dev_info!(dev.as_ref(), "GPU Information:\n");
        dev_info!(
            dev.as_ref(),
            "  Type: {:?}{:?}\n",
            gpu_id.gpu_gen,
            gpu_id.gpu_variant
        );
        dev_info!(dev.as_ref(), "  Clusters: {}\n", gpu_id.num_clusters);
        dev_info!(
            dev.as_ref(),
            "  Cores: {} ({})\n",
            gpu_id.num_cores,
            gpu_id.num_cores * gpu_id.num_clusters
        );
        dev_info!(
            dev.as_ref(),
            "  Frags: {} ({})\n",
            gpu_id.num_frags,
            gpu_id.num_frags * gpu_id.num_clusters
        );
        dev_info!(
            dev.as_ref(),
            "  GPs: {} ({})\n",
            gpu_id.num_gps,
            gpu_id.num_gps * gpu_id.num_clusters
        );
        dev_info!(dev.as_ref(), "  Core masks: {:#x?}\n", gpu_id.core_masks);
        dev_info!(
            dev.as_ref(),
            "  Active cores: {}\n",
            gpu_id.total_active_cores
        );

        dev_info!(dev.as_ref(), "Getting configuration from device tree...\n");
        let pwr_cfg = hw::PwrConfig::load(dev.as_ref().as_ref(), cfg)?;
        dev_info!(dev.as_ref(), "Dynamic configuration fetched\n");

        if gpu_id.gpu_gen != cfg.gpu_gen || gpu_id.gpu_variant != cfg.gpu_variant {
            dev_err!(
                dev.as_ref(),
                "GPU type mismatch (expected {:?}{:?}, found {:?}{:?})\n",
                cfg.gpu_gen,
                cfg.gpu_variant,
                gpu_id.gpu_gen,
                gpu_id.gpu_variant
            );
            return Err(EIO);
        }
        if gpu_id.num_clusters > cfg.max_num_clusters {
            dev_err!(
                dev.as_ref(),
                "Too many clusters ({} > {})\n",
                gpu_id.num_clusters,
                cfg.max_num_clusters
            );
            return Err(EIO);
        }
        if gpu_id.num_cores > cfg.max_num_cores {
            dev_err!(
                dev.as_ref(),
                "Too many cores ({} > {})\n",
                gpu_id.num_cores,
                cfg.max_num_cores
            );
            return Err(EIO);
        }
        if gpu_id.num_frags > cfg.max_num_frags {
            dev_err!(
                dev.as_ref(),
                "Too many frags ({} > {})\n",
                gpu_id.num_frags,
                cfg.max_num_frags
            );
            return Err(EIO);
        }
        if gpu_id.num_gps > cfg.max_num_gps {
            dev_err!(
                dev.as_ref(),
                "Too many GPs ({} > {})\n",
                gpu_id.num_gps,
                cfg.max_num_gps
            );
            return Err(EIO);
        }

        let fwnode = dev.as_ref().as_ref().fwnode().ok_or(ENOENT)?;
        let fwver = fwnode
            .property_read_array_vec(c"apple,firmware-version", 3)?
            .or(kernel::kvec![0; 3]?);

        Ok(KBox::new(
            hw::DynConfig {
                pwr: pwr_cfg,
                uat_ttb_base: uat.ttb_base(),
                id: gpu_id,
                firmware_version: fwver,

                hw_data_a: Self::load_hwdata_blob(
                    dev.into(),
                    c_str!("hw-cal-a"),
                    c_str!("debug,hw-cal-a-size"),
                )
                .unwrap_or(KVVec::new()),
                hw_data_b: Self::load_hwdata_blob(
                    dev.into(),
                    c_str!("hw-cal-b"),
                    c_str!("debug,hw-cal-b-size"),
                )
                .unwrap_or(KVVec::new()),
                hw_globals: Self::load_hwdata_blob(
                    dev.into(),
                    c_str!("globals"),
                    c_str!("debug,globals-size"),
                )
                .unwrap_or(KVVec::new()),
            },
            GFP_KERNEL,
        )?)
    }

    /// Create the global GPU event manager, and return an `Arc<>` to it.
    fn make_event_manager(alloc: &mut KernelAllocators) -> Result<Arc<event::EventManager>> {
        Ok(Arc::new(event::EventManager::new(alloc)?, GFP_KERNEL)?)
    }

    /// Create a new MMIO mapping and add it to the mappings list in initdata at the specified
    /// index.
    fn iomap(
        this: &mut Pin<UniqueArc<GpuManager::ver>>,
        cfg: &'static hw::HwConfig,
        #[allow(unused_variables)] // G15 publishes no io_mappings table
        index: usize,
        map: &hw::IOMapping,
    ) -> Result {
        let dies = if map.per_die {
            cfg.num_dies as usize
        } else {
            1
        };

        let off = map.base & mmu::UAT_PGMSK;
        let base = map.base - off;
        let end = (map.base + map.size + mmu::UAT_PGMSK) & !mmu::UAT_PGMSK;
        let map_size = end - base;

        // Array mappings must be aligned
        assert!((off == 0 && map_size == map.size) || (map.count == 1 && !map.per_die));
        assert!(map.count > 0);

        let iova = this.as_mut().alloc_mmio_iova(map_size * map.count * dies);
        let mut cur_iova = iova;

        for die in 0..dies {
            for i in 0..map.count {
                let phys_off = die * 0x20_0000_0000 + i * map.stride;

                let mapping = this.uat.kernel_vm().map_io(
                    this.dev.as_ref().as_ref(),
                    cur_iova,
                    base + phys_off,
                    map_size,
                    if map.writable {
                        mmu::PROT_FW_MMIO_RW
                    } else {
                        mmu::PROT_FW_MMIO_RO
                    },
                )?;

                this.as_mut().io_mappings_mut().push(mapping, GFP_KERNEL)?;
                cur_iova += map_size as u64;
            }
        }

        #[ver(G != G15)]
        if true {
            this.as_mut()
                .initdata_mut()
                .runtime_pointers
                .hwdata_b
                .with_mut(|raw, _| {
                    raw.io_mappings[index] = fw::initdata::raw::IOMapping {
                        phys_addr: U64(map.base as u64),
                        virt_addr: U64(iova + off as u64),
                        total_size: (map.size * map.count * dies) as u32,
                        element_size: map.size as u32,
                        readwrite: U64(map.writable as u64),
                    };
                });
        }

        Ok(())
    }

    /// G15: map the register windows (the chip+0x6d0 table; spec:
    /// alloc.md) into the MMIO sub-range and fill the HwDataB 0x640 block
    /// (the 31 window records + the 31 window GPU addresses; spec:
    /// hwdata-b.md). A kind-1 window with a nonzero base and size gets a
    /// 16 KiB-aligned GPU mapping; its published address adds the sub-page
    /// remainder. The kind-6 MCache slot is the PIO buffer the initdata
    /// builder allocated (its PAs are its content). Windows whose entry
    /// base or size is 0 publish 0, as the kext does.
    fn g15_map_windows(this: &mut Pin<UniqueArc<GpuManager::ver>>, cfg: &'static hw::HwConfig) -> Result {
        let windows = cfg.g15_windows.ok_or(EINVAL)?;
        let mut fwva = [0u64; 31];

        for (j, w) in windows.iter().enumerate() {
            if w.kind == 1 && w.base != 0 && w.size != 0 {
                let off = (w.base & (mmu::UAT_PGMSK as u64)) as usize;
                let base = w.base - off as u64;
                let size = ((w.size as usize + mmu::UAT_PGMSK) & !mmu::UAT_PGMSK) as u64;

                let iova = this.as_mut().alloc_mmio_iova(size as usize);
                let mapping = this
                    .uat
                    .kernel_vm()
                    .map_io(
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

        let mcache = this
            .as_mut()
            .initdata_mut()
            .mcache_piob
            .gpu_va()
            .get();

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

    /// G15: end-to-end self-test of the guest→firmware command path, run
    /// by `init()` after the init message. Submits one ForceConfigSnapshot
    /// record on the special control ring the way the kext's
    /// `submitCmdFirmwareForceConfigSnapshot` does (the 56 B entry
    /// `{0x13, zeros}`, flags 1 = doorbell, no completion wait): the record
    /// into slot 0, the write-index word (the kext's `setWriteIndex`), then
    /// the device-control doorbell. The firmware's consumer runs only on a
    /// doorbell event, so the doorbell is re-sent every 500 ms while the
    /// read-index word stays 0. The 0x13 handler is firmware-internal
    /// bookkeeping (it refreshes the chip-config snapshot; no GPU kick), so
    /// it is safe to send unconditionally. A failure is logged, not fatal.
    /// spec: agx-g15c/channel.md (the control-ring path).
    fn g15_control_selftest(&self) {
        const ENTRY: usize = 0x38;
        const WAIT_MS: u32 = 2000;
        const RING_MS: u32 = 500;
        let dev = self.dev.as_ref();
        let storage = self.initdata.special_ring.raw_ptr();
        let ring = self.initdata.ring_area.raw_ptr();

        // SAFETY: slot 0 is in bounds of the 0x3800 storage and both index
        // words are in bounds of the 128 KiB ring region. The memory is
        // firmware-shared and no slice view of it is live, so every access
        // is a volatile one through the raw pointer.
        unsafe {
            for i in 0..ENTRY {
                storage.add(i).write_volatile(0);
            }
            storage.cast::<u32>().write_volatile(0x13);
            core::sync::atomic::fence(Ordering::Release);
            ring.add(fw::g15::RING_SPECIAL_DOORBELL_OFF).cast::<u32>().write_volatile(1);
        }
        // SAFETY: as above; read-only.
        let read_index =
            || unsafe { (ring.add(fw::g15::RING_REGION2_OFF + 0xC0) as *const u32).read_volatile() };

        let mut last = 0;
        let mut waited = 0;
        while waited < WAIT_MS {
            if waited % RING_MS == 0 {
                if let Err(e) = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL) {
                    dev_err!(dev, "G15 control self-test: doorbell refused ({:?})\n", e);
                    return;
                }
            }
            last = read_index();
            if last > 0 {
                break;
            }
            kernel::time::delay::fsleep(Delta::from_millis(1));
            waited += 1;
        }

        if last > 0 {
            dev_info!(dev, "G15 control self-test: OK (read index {:#x} after ~{} ms)\n", last, waited);
        } else {
            dev_err!(dev, "G15 control self-test: TIMEOUT (read index still 0 after {} ms)\n", WAIT_MS);
        }
    }

    /// G15: drain the four firmware-to-host rings (spec: agx-g15c/channel.md,
    /// "Firmware-to-host rings"). The firmware posts a plain 0x42<<48 on
    /// EP 0x20 with no ring ID, so every notification drains all four, as
    /// the kext's `drainFirmwareRings(1)` does. Each ring's state block:
    /// read u32 at +0x00 (host-owned), write u32 at +0x20 (firmware-owned).
    fn g15_drain_fw_rings(&self) -> u64 {
        // The firmware's 0x42 messages (the RTKit worker) and the GPU's
        // interrupts (their IRQ threads) both drain; one at a time.
        let _guard = self.g15_drain_lock.lock();
        let dev = self.dev.as_ref();
        let rings = &self.initdata.fw_rings;
        // (name, state idx, storage idx, index mask, record stride):
        // pair 1 event (256 x 56 B, 8-bit index), pair 3 trace
        // (512 x 56 B, 10-bit), pair 4 stats (256 x 64 B, 8-bit).
        let mut total = 0u64;
        let mut completions = 0u32;
        let mut stop = None;
        for (name, state_i, store_i, mask, stride) in [
            ("event", 0usize, 1usize, 0xFFu32, 0x38usize),
            ("trace", 4, 5, 0x1FF, 0x38),
            ("stats", 6, 7, 0xFF, 0x40),
        ] {
            let state = rings[state_i].raw_ptr();
            let storage = rings[store_i].raw_ptr();
            // The firmware's ring writes reach memory, not this CPU's cached
            // copy (boots #105-#110: a completion record seen only at the next
            // notification): read the state and the records fresh.
            crate::mem::dc_civac(state.cast_const(), 0x40);
            // SAFETY: the state/storage buffers are the driver's own
            // firmware-shared ring buffers (fw_rings); the read index is
            // host-owned (the kext's drains do the same); every access is
            // in-bounds and volatile (the firmware writes concurrently).
            let n = unsafe {
                let read_p = state.cast::<u32>();
                let write_p = read_p.add(8);
                // The firmware wraps the write index at the ring size
                // (boot #128: an unmasked read index ran on past it).
                let write = write_p.read_volatile() & mask;
                let mut read = read_p.read_volatile() & mask;
                if read != write {
                    let mut n = 0u32;
                    while read != write {
                        let rec = storage.add(((read & mask) as usize) * stride) as *const u32;
                        crate::mem::dc_civac(rec.cast::<u8>(), stride);
                        let ty = rec.read_volatile();
                        mod_dev_dbg!(self.dev, "G15 {name} ring: record type {:#x}\n", ty);
                        if name == "event" && ty == 1 {
                            // +0x04 the 128-bit map of the stamp indices that moved.
                            mod_dev_dbg!(self.dev, "G15 event ring: completion (+0x04 {:#x})\n",
                                         rec.add(1).read_volatile());
                            self.g15_completions.fetch_add(1, Ordering::Relaxed);
                            completions += 1;
                        } else if name == "event" && ty == 4 {
                            // The recovery packet: +0x04 the stop count before
                            // the increment, +0x0C the guilty stamp value.
                            let count = rec.add(1).cast::<u64>().read_unaligned();
                            stop = Some((count, rec.add(3).read_volatile()));
                        } else if name == "event" && ty == 8 {
                            dev_err!(dev, "G15: channel error {}: data master {}, stamp index {}, stamp {:#x}\n",
                                     rec.add(1).read_volatile(), rec.add(2).read_volatile(),
                                     rec.add(3).read_volatile(), rec.add(4).read_volatile());
                        } else if name == "event" && ty == 7 {
                            // A parameter buffer ran out of pages (Asahi's GrowTVB:
                            // the VM slot, the buffer slot, the counter); not
                            // answered yet (spec: parameter-buffer.md, "Growing").
                            dev_warn!(dev, "G15: parameter buffer full: VM slot {}, buffer slot {}, counter {:#x}\n",
                                      rec.add(1).read_volatile(), rec.add(2).read_volatile(),
                                      rec.add(3).read_volatile());
                        } else if name == "event" && (ty == 0xA || ty == 0xE) {
                            // 0xA: a UMA pool ran short (slot, page list,
                            // context); 0xE: an async grow completed, or a
                            // recovery interrupted a pool's reset (spec:
                            // uma.md); neither is answered.
                            dev_warn!(dev, "G15: UMA pool event {:#x}: {:#x} {:#x} {:#x} {:#x}\n", ty,
                                      rec.add(1).read_volatile(), rec.add(2).read_volatile(),
                                      rec.add(3).read_volatile(), rec.add(4).read_volatile());
                        }
                        if name == "trace" {
                            let q = rec.cast::<u64>();
                            let r = [
                                q.read_volatile(), q.add(1).read_volatile(), q.add(2).read_volatile(), q.add(3).read_volatile(),
                                q.add(4).read_volatile(), q.add(5).read_volatile(), q.add(6).read_volatile(),
                            ];
                            let mut t = self.g15_trace.lock();
                            if t.0.len() < 256 {
                                let _ = t.0.push(r, GFP_ATOMIC);
                            } else {
                                let i = t.1 % 256;
                                t.0[i] = r;
                            }
                            t.1 += 1;
                        }
                        n += 1;
                        read = (read + 1) & mask;
                    }
                    core::sync::atomic::fence(Ordering::Release);
                    read_p.write_volatile(read);
                    crate::mem::dc_civac(state.cast_const(), 0x40);
                    n
                } else {
                    0
                }
            };
            total += u64::from(n);
        }
        // Pair 2: the firmware log — six sub-rings (one per firmware
        // thread; state 0x120, 256 x 0x38 B entries each in the 0x15000
        // storage), the text in the 0x51000 buffer (channel table +0x1f8).
        // The firmware's print (sub_FFFFFC000003C924) only writes them
        // when channel table +0x230 != 0: entry = {+0 2, +4 0, +8 seq},
        // message at 0x51000-buffer + 0xD8 * (seq + 256 * ring) * (+4 + 1)
        // = {+0 3, +4 counter, +8 timestamp, +0x10 text (NUL, <= 0xC8)}.
        let subs = rings[2].raw_ptr().cast::<u32>();
        let entries = rings[3].raw_ptr();
        let text = rings[8].raw_ptr();
        let mut logged = 0u32;
        // SAFETY: as above; every offset is bounds-checked against the
        // 0x15000 / 0x51000 buffer sizes before the access.
        unsafe {
            for i in 0..6usize {
                let read_p = subs.add(i * 12);
                let write = subs.add(i * 12 + 8).read_volatile() & 0xFF;
                let mut read = read_p.read_volatile() & 0xFF;
                while read != write {
                    let e = (read as usize + 256 * i) * 0x38;
                    let seq = entries.add(e + 8).cast::<u32>().read_volatile() as usize;
                    let mult = entries.add(e + 4).cast::<u32>().read_volatile() as usize + 1;
                    let m = 0xD8 * (seq + 256 * i) * mult;
                    if m + 0xD8 <= 0x51000 {
                        let s = text.add(m + 0x10);
                        let mut len = 0;
                        while len < 0xC8 && s.add(len).read_volatile() != 0 {
                            len += 1;
                        }
                        let msg = core::slice::from_raw_parts(s, len);
                        dev_info!(dev, "G15 fwlog[{i}]: {}\n", kernel::str::BStr::from_bytes(msg));
                    }
                    logged += 1;
                    read = (read + 1) & 0xFF;
                }
                core::sync::atomic::fence(Ordering::Release);
                read_p.write_volatile(read);
            }
        }
        if total > 0 || logged > 0 {
            mod_dev_dbg!(self.dev, "G15: fw->host rings drained: {} record(s), {} log message(s)\n", total, logged);
        }
        if let Some((count, stamp)) = stop {
            self.g15_recovery(count, stamp);
        }
        if completions > 0 || stop.is_some() {
            self.g15_cl_retire();
        }
        total + u64::from(logged)
    }

    /// G15: the firmware stopped for a recovery (a fault or a hang; spec:
    /// faults.md, "The firmware's recovery"): log what it caught, fail the
    /// guilty job, and let the firmware resume (it re-inits the GPU and
    /// retires the caught jobs).
    fn g15_recovery(&self, count: u64, guilty: u32) {
        let dev = self.dev.as_ref();
        // G15 lab: the firmware's last events before the stop (the ktrace flag, `Debug4`).
        self.g15_trace_dump(160);
        let e = self.initdata.event_page.raw_ptr().cast::<u8>();
        crate::mem::dc_civac(e.wrapping_add(0x40A0).cast_const(), 0x524);
        let mut caught: KVec<(u32, u32, u32)> = KVec::new();
        // SAFETY: in-bounds u32/u64 accesses of the 0xC3D0 B event page.
        unsafe {
            let r32 = |off: usize| (e.add(off) as *const u32).read_volatile();
            dev_err!(dev, "G15: GPU stopped for recovery {}: {} caught job(s), guilty stamp {:#x}, pid {}, kill {}, fault bank {:#x}, busy {:#x}, stopped {}, host-requested {}\n",
                     count, r32(0x44A4), guilty, r32(0x44AC), r32(0x44B0),
                     (e.add(0x44B4) as *const u64).read_unaligned(),
                     (e.add(0x4560) as *const u64).read_unaligned(),
                     r32(0x4590), r32(0x45B0));
            for i in 0..0x80usize {
                let w = r32(0x40A0 + i * 8);
                if w & 1 == 0 {
                    break;
                }
                let v = r32(0x40A4 + i * 8);
                dev_err!(dev, "G15:   caught: stamp index {}, stamp {:#x}, flags {:#x}\n", (w >> 4) & 0x7F, v, w & 0xE);
                let _ = caught.push(((w >> 4) & 0x7F, v, w), GFP_ATOMIC);
            }
        }
        // The TA jobs the table lists: every registered one (flags & 9 = 9),
        // anywhere in the table (the kext's processFirmwareTACommandsRecovery
        // walks all 128 entries).
        let mut tas: KVec<(u32, u32)> = KVec::new();
        // SAFETY: in-bounds u32 reads of the event page.
        unsafe {
            for i in 0..0x80usize {
                let w = (e.add(0x40A0 + i * 8) as *const u32).read_volatile();
                if w & 9 == 9 {
                    let _ = tas.push(((w >> 4) & 0x7F, (e.add(0x40A4 + i * 8) as *const u32).read_volatile()), GFP_ATOMIC);
                }
            }
        }
        let mut cleared = 0;
        let mut pbs = 0u64;
        for p in self.g15_pending.lock().iter_mut() {
            // Each parameter buffer with a pass in flight, once: the
            // firmware's counts at the stop (its walk gates a buffer whose 3D
            // completions differ from the host's count).
            if let G15Work::Rd(pass) = &p._work {
                let (id, c) = pass.pb_counts();
                if id < 64 && pbs & 1 << id == 0 {
                    pbs |= 1 << id;
                    dev_info!(dev, "G15:   PB {id}: 3D done {}, TA done {}, TAs in flight {}, gate {}, 3D submitted {}\n",
                              c[0], c[1], c[2], c[3], c[4]);
                }
            }
            let idx = p.chan.lock().stamp_index;
            let ta = p.ta.as_ref().map(|(c, st)| (c.lock().stamp_index, *st));
            if let Some(&(_, _, w)) = caught
                .iter()
                .find(|c| (c.0 == idx && c.1 == p.stamp) || ta == Some((c.0, c.1)))
            {
                p.error = Some(if w & 2 != 0 { EIO } else { ECANCELED });
            }
            // An unfinished listed TA starts again from an empty tail-pointer
            // cache, and its scene is aborted: the walk marks a TA in an
            // active slot done without running it, and its 3D would draw a
            // never-written tilemap. A TA that kicks again clears the mark.
            if let (Some((tc, st)), G15Work::Rd(pass)) = (p.ta.as_ref(), &p._work) {
                let tc = tc.lock();
                if tas.iter().any(|&(i, v)| i == tc.stamp_index && v == *st) && !self.g15_cl_done(&tc, *st) {
                    pass.clear_tpc();
                    pass.abort_scene();
                    cleared += 1;
                }
            }
        }
        if cleared != 0 {
            dev_info!(dev, "G15:   {cleared} unfinished TA job(s): tail-pointer caches cleared, scenes aborted\n");
        }
        // The MMU fault at the stop, as the kext's restartWorkQueue reads it
        // (getMMUFaultInfo): the recovery handler selected the bank of the
        // latched fault and left it in effect. None for a hang (the CL
        // progress check's stop).
        if let Some(fi) = self.get_fault_info() {
            dev_err!(dev, "G15:   fault: {fi:x?}\n");
        } else {
            dev_err!(dev, "G15:   no MMU fault latched (a hang)\n");
        }
        // The pool, as the stop left it.
        if let Some(uma) = self.g15_uma.as_ref() {
            uma.log(dev.as_ref(), &self.initdata.umap_table, "at the stop");
        }
        // The firmware posts the record before it sets the stopped flag and
        // the stop count (agx_recovery_handler: +0x4590 = 1, ++(+0x4580),
        // then its wait for +0x45A0): a resume before that leaves +0x4590
        // set for good, and every later submit fails. Wait for the count.
        let mut waited = 0;
        loop {
            crate::mem::dc_civac(e.wrapping_add(0x4580).cast_const(), 0x14);
            // SAFETY: in-bounds u64/u32 reads of the event page.
            let (n, stopped) = unsafe {
                ((e.add(0x4580) as *const u64).read_volatile(), (e.add(0x4590) as *const u32).read_volatile())
            };
            if n > count && stopped != 0 {
                break;
            }
            if waited >= 100_000 {
                dev_err!(dev, "G15:   the firmware did not stop (count {n:#x}, stopped {stopped}); resuming anyway\n");
                break;
            }
            kernel::time::delay::udelay(kernel::time::Delta::from_micros(10));
            waited += 10;
        }
        // Resume (resumeFirmwareAfterRecovery): clear the stopped flag, then
        // set the resume word.
        // SAFETY: in-bounds u32 stores into the event page.
        unsafe {
            e.add(0x4590).cast::<u32>().write_volatile(0);
            core::sync::atomic::fence(Ordering::SeqCst);
            crate::mem::dc_civac(e.add(0x4590).cast_const(), 4);
            e.add(0x45A0).cast::<u32>().write_volatile(1);
            crate::mem::dc_civac(e.add(0x45A0).cast_const(), 4);
        }
    }

    /// G15: the UMA pool for a new job. A pool the firmware marked for a
    /// reset at a recovery (+0x30 = 1) keeps it, as with the kext: the
    /// pool's next kick rebuilds it from its backup list, and a recovery
    /// that interrupts a reset marks it again (spec: uma.md, "The reset
    /// after a recovery").
    pub(crate) fn g15_uma_get(&self) -> Result<Arc<G15Uma>> {
        self.g15_uma.clone().ok_or(EINVAL)
    }

    /// G15: send a mailbox message through RTKit.
    fn g15_send(&self, ep: u8, msg: u64) -> Result {
        // Every store before the message (the ring entries, the job
        // buffers) completes first: `fence(Release)` is a `dmb ish`, which
        // does not order them for the firmware's core.
        crate::mem::sync();
        let mut guard = self.rtkit.lock();
        let rtk = guard.as_mut().as_pin_mut().ok_or(EIO)?;
        rtk.send_message(ep, msg)
    }

    /// G15: a fresh CL channel (the kext's `AGXChannel::resetChannelState`;
    /// spec: agx-g15c/submission.md, "The channel state object").
    pub(crate) fn g15_cl_channel_new(&self) -> Result<G15ClChannel> {
        // A free stamp index (1..127).
        let stamp_index = {
            let mut ids = self.g15_stamp_ids.lock();
            let free = !*ids & !1u128;
            if free == 0 {
                return Err(EBUSY);
            }
            let i = free.trailing_zeros();
            *ids |= 1u128 << i;
            i
        };
        const SLOTS: u32 = 256; // the record slots' capacity
        let mut guard = self.alloc.lock();
        let preempt = guard.gpu.array_empty_tagged::<u8>(0x4000, b"PRMT")?;
        let words = guard.stamp.array_empty_tagged::<u8>(0x40, b"STWD")?;
        let shared = &mut guard.shared;
        let ch = G15ClChannel {
            state: shared.array_empty_tagged::<u8>(0x24C0, b"STTE")?,
            chan_uncached: shared.array_empty_tagged::<u8>(0x100, b"UCMN")?,
            chan_cached: shared.array_empty_tagged::<u8>(SLOTS as usize * 8, b"CCMN")?,
            stamp_table: shared.array_empty_tagged::<u8>(128 * 0x48, b"STMP")?,
            job_slot: shared.array_empty_tagged::<u8>(0x40, b"JSLO")?,
            ctx_store: shared.array_empty_tagged::<u8>(0x7A400 + 0x400, b"CTXS")?,
            chan_list: shared.array_empty_tagged::<u8>(0x40, b"NLST")?,
            words,
            preempt,
            submitted: 0,
            submitted_records: 0,
            stamp_index,
            stamp_ids: Some(self.g15_stamp_ids.clone()),
        };
        core::mem::drop(guard);

        let unc_va = ch.chan_uncached.gpu_va().get();
        let cached_va = ch.chan_cached.gpu_va().get();
        let stamp_va = ch.stamp_table.gpu_va().get();
        let job_slot_va = ch.job_slot.gpu_va().get();
        let chan_list_va = ch.chan_list.gpu_va().get();
        // SAFETY: each write is one in-bounds field of the channel's own
        // freshly allocated (zeroed) buffers.
        unsafe {
            let c = ch.state.raw_ptr();
            let q = |off: usize| c.add(off).cast::<u64>();
            q(0x00).write_volatile(unc_va); // -> uncached chan mem (capacity at +0x50)
            q(0x08).write_volatile(cached_va); // -> record slots
            q(0x10).write_volatile(chan_list_va); // -> notifier-list header
            q(0x18).write_volatile(stamp_va); // -> stamp table
            c.add(0x2C).cast::<u32>().write_volatile(0xFFFFFFFF); // fresh sentinel
            // The channel priority (AGXArmFirmware::setChannelPriority):
            // resetChannelState leaves +0x30 = 4, which no executor stage
            // runs. Priority 5 (and 0) is stage 0, mask 0xFFFFFFFFFFFF0000,
            // +0x40 = 1; a default foreground queue (priority 1, sub-level
            // 0) is stage 2, mask 0xFFFFFFFF00000000, +0x40 = 0. The
            // background tick preempts (a context store, trace event 0x35)
            // the slots of a queue that used more than its share, except at
            // stage 0, and the store of a TA job wrote to address 0 + 0x80 * k
            // (a `dIPP_CS` fault, boots #456-#459).
            c.add(0x30).cast::<u32>().write_volatile(0); // stage
            c.add(0x34).cast::<u32>().write_volatile(0);
            q(0x38).write_volatile(0xFFFF_FFFF_FFFF_0000); // mask (TA path only)
            c.add(0x40).cast::<u32>().write_volatile(1);
            c.add(0x44).cast::<u32>().write_volatile(0); // queue+0x838 (sub-queue)
            c.add(0x48).cast::<u32>().write_volatile(0); // pending row 0xD + this
            c.add(0x4C).cast::<u32>().write_volatile(0xFFFFFFFF);
            c.add(0x50).cast::<u32>().write_volatile(SLOTS); // slot capacity
            q(0xA4).write_volatile(job_slot_va); // -> job-slot object
            ch.chan_uncached.raw_ptr().add(0x50).cast::<u32>().write_volatile(SLOTS);
            // The job-slot object: fresh (the firmware allocates on use).
            let p = ch.job_slot.raw_ptr();
            p.write_volatile(0xFF); // +0x00 no job-table slot
            p.add(1).write_volatile(0xFF); // +0x01 no job index
            // The notifier-list header, fresh: sub_27D40's walk reads
            // *(*(P[1]+8)), so P[1] = Q with *(Q+8) = R and *R = 0.
            let n = ch.chan_list.raw_ptr();
            n.cast::<u64>().write_volatile(0); // +0x00 P[0] head = fresh
            n.add(8).cast::<u64>().write_volatile(chan_list_va + 0x10); // +0x08 P[1] = Q
            n.add(16).cast::<u64>().write_volatile(0); // +0x10 unused
            n.add(24).cast::<u64>().write_volatile(chan_list_va + 0x20); // +0x18 P[3] = R
            n.add(32).cast::<u64>().write_volatile(0); // +0x20 *R = 0 (the walk stops)
        }
        Ok(ch)
    }

    /// G15: a CL channel for a queue: a destroyed queue's, else a new one.
    pub(crate) fn g15_cl_channel_get(&self) -> Result<Arc<Mutex<G15ClChannel>>> {
        if let Some(ch) = self.g15_free_chans.lock().pop() {
            return Ok(ch);
        }
        let ch = self.g15_cl_channel_new()?;
        Arc::pin_init(new_mutex!(ch, "g15_chan"), GFP_KERNEL)
    }

    /// G15: whether the firmware retired every job submitted on `c`: its stamp
    /// word has reached the last job's stamp. The retire is the last thing it
    /// does for a job (after the completion event and the host stamp, which can
    /// stay behind for good, see `g15_cl_done`), and only then may the channel
    /// serve another queue or go (boot #441: `bigpp` after `pingpong`, which
    /// reused the pair at its host stamp: "Unknown SKU command type 24").
    pub(crate) fn g15_chan_idle(c: &G15ClChannel) -> bool {
        crate::mem::dc_civac(c.words.raw_ptr().cast_const(), 8);
        // SAFETY: an in-bounds u32 read of the channel's own stamp words.
        let fwst = unsafe { (c.words.raw_ptr() as *const u32).add(1).read_volatile() };
        fwst.wrapping_sub(c.submitted << 8) as i32 >= 0
    }

    /// G15: free the retired channels whose last job has finished since
    /// (their stamp indices return to the pool).
    fn g15_reclaim_dead(&self) {
        let mut freed = KVec::new();
        {
            let mut dead = self.g15_dead_chans.lock();
            let mut i = 0;
            while i < dead.len() {
                if Self::g15_chan_idle(&dead[i].lock()) {
                    if freed.push(dead.swap_remove(i), GFP_ATOMIC).is_err() {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        }
        core::mem::drop(freed);
    }

    /// G15: a destroyed queue's CL channel goes back for reuse — unless a
    /// job on it never finished (its stamp words short of the last job's):
    /// then it is set aside until it has (`g15_reclaim_dead`).
    pub(crate) fn g15_cl_channel_put(&self, ch: Arc<Mutex<G15ClChannel>>) {
        let idle = Self::g15_chan_idle(&ch.lock());
        let list = if idle { &self.g15_free_chans } else { &self.g15_dead_chans };
        if !idle {
            dev_warn!(self.dev.as_ref(), "G15: a CL channel with an unfinished job is retired\n");
        }
        if list.lock().push(ch, GFP_KERNEL).is_err() {
            dev_err!(self.dev.as_ref(), "G15: cannot keep a CL channel\n");
        }
    }

    /// G15: build a CL job for `ch` (spec: cl-job.md, "Successive jobs on
    /// one channel"): its job state, stream and notifier, all but the
    /// per-job numbers `g15_cl_submit` writes. `cdm` = the CDM control stream's GPU VA (None: a
    /// kernel stream holding one terminate block); `ctx` = the context ID.
    pub(crate) fn g15_cl_job_new(
        &self,
        ch: &G15ClChannel,
        cdm: Option<u64>,
        ctx: u32,
        extra: &[(u32, u64)],
    ) -> Result<G15ClJob> {
        // The GPU's view of a VA is its low 43 bits (bit 42 = the kernel
        // half): AGFA_KickFlush writes +0xC048 as `va & 0x7FF_FFFF_FFFF`.
        const GPU_VA_MASK: u64 = 0x7FF_FFFF_FFFF;
        let uma = self.g15_uma_get()?;
        let (job_state, cdm_stream, stream, notifier) = {
            let mut guard = self.alloc.lock();
            let job_state = guard.gpu.array_empty_tagged::<u8>(0x880, b"JS01")?;
            let cdm_stream = match cdm {
                Some(_) => None,
                None => Some(guard.gpu.array_empty_tagged::<u8>(0x80, b"CDMS")?),
            };
            let stream = guard.shared.array_empty_tagged::<u8>(0x400, b"STRM")?;
            let notifier = guard.shared.array_empty_tagged::<u8>(0x100, b"NTFY")?;
            (job_state, cdm_stream, stream, notifier)
        };
        let cdm_gva = match (&cdm_stream, cdm) {
            (Some(c), _) => {
                // SAFETY: two in-bounds u32 stores into the job's own 0x80 B
                // buffer: CDM Stream Terminate (block type 2 at [31:29]).
                unsafe {
                    let p = c.raw_ptr().cast::<u32>();
                    p.write_volatile(0x4000_0000);
                    p.add(1).write_volatile(0);
                }
                c.gpu_va().get() & GPU_VA_MASK
            }
            (None, Some(va)) => va & GPU_VA_MASK,
            (None, None) => return Err(EINVAL),
        };
        if 0x20 + (22 + extra.len()) * 12 > 0x720 {
            return Err(EINVAL);
        }
        let js = job_state.gpu_va().get();
        let strm = stream.gpu_va().get();
        let notifier_va = notifier.gpu_va().get();
        let state_va = ch.state.gpu_va().get();
        let ctx_store_va = ch.ctx_store.gpu_va().get();
        let uma_state_va = uma.state.gpu_va().get();
        let metrics_va = uma.metrics_slot();
        let words_va = ch.words.gpu_va().get();
        let preempt_gva = ch.preempt.gpu_va().get() & GPU_VA_MASK;
        let stats_va = self.initdata.buf_0x228.gpu_va().get();

        // The register list: 22 x 12 B entries at +0x20 (header =
        // (mrr & 0x3FFF8) | write-enable). The no-launch map; the UMA page
        // reservations are the kext's defaults (no UMA pool on the job):
        // CDM min 0x20 / reload 0x40 / max 0x60, DUPM 0x20·8 / 0x60·8.
        let entries: [(u32, u64); 22] = [
            (0x1A510, preempt_gva),
            (0x1A420, cdm_gva),
            (0x1A4D0, 0),
            (0x1A4D8, 0),
            (0x1A4E0, 0),
            (0x1A4E8, 0),
            (0x1A440, 0x154024201),
            (0x1A458, 0x10C08860),
            // raw+0xA4 & 0x1F: Metal's 0x1C (beginComputePass; spec:
            // metal-compute.md, the payload)
            (0x12091, 0x1C),
            (0x101D9, 0x1C),
            (0x1A089, 0),
            (0x1A091, 0),
            (0x1A059, 0),
            (0x1A061, 0),
            (0x1A0B9, 0),
            (0x1A0C1, 0),
            (0x101D1, 0),
            (0xD479, 0),
            (0x1A0E9, 8), // raw+0x234: Metal's 8 without SCS
            (0x107A1, 0x00FF0000),
            (0xA599, 0x0000_0060_0040_0020),
            (0xD411, ((0x60 * 8) << 32) | (0x20 * 8)),
        ];
        // SAFETY: every write is one in-bounds field of the job's own
        // freshly allocated buffers or of the channel's.
        unsafe {
            let j = job_state.raw_ptr();
            let q = |off: usize| j.add(off).cast::<u64>();
            j.cast::<u32>().write_volatile(3); // +0x00 tag = CL
            j.add(0x10).cast::<u32>().write_volatile(ctx); // +0x10 context ID
            q(0x14).write_volatile(notifier_va); // +0x14 the notifier
            for (i, &(mrr, val)) in Iterator::chain(entries.iter(), extra.iter()).enumerate() {
                let e = j.add(0x20 + i * 12);
                e.cast::<u32>().write_volatile(mrr);
                e.add(4).cast::<u64>().write_volatile(val);
            }
            let count = (entries.len() + extra.len()) as u32;
            q(0x720).write_volatile(js + 0x20); // self-address
            // cursor (bytes) << 16 | count: 22 entries = 0x108_0016
            j.add(0x728).cast::<u32>().write_volatile((count * 12) << 16 | count);
            q(0x760).write_volatile(strm); // stream FWVA (slot start)
            j.add(0x768).cast::<u32>().write_volatile(0x2C0); // slot size
            q(0x7C4).write_volatile(0x154024201); // chip config word (qword)
            q(0x7E8).write_volatile(words_va); // host stamp word (stamp index 0)
            q(0x7F0).write_volatile(words_va + 4); // firmware stamp word
            j.add(0x7FC).write_volatile(ch.stamp_index as u8); // stamp index
            j.add(0x800).cast::<u32>().write_volatile(0); // channel index
            j.add(0x804).cast::<u32>().write_volatile(0); // no IO fences
            // The UMA pool (spec: uma.md, "Per kick"): its state, the
            // clean+invalidate flag, the job's metrics slot.
            j.add(0x83E).cast::<u64>().write_unaligned(uma_state_va);
            j.add(0x846).write_volatile(1);
            j.add(0x857).cast::<u64>().write_unaligned(metrics_va);

            // The notifier, fresh: +0x00 -> its submitted-jobs count (1, at
            // +0xC0), +0x08 the sort key, +0x0C the firmware's completed
            // count (0), +0x10 the flush threshold (the kext's 80), +0x94
            // not linked, +0xA8 no stale cutoff.
            let f = notifier.raw_ptr();
            f.add(0xC0).cast::<u32>().write_volatile(1);
            f.cast::<u64>().write_volatile(notifier_va + 0xC0);
            f.add(0xC).cast::<u32>().write_volatile(0);
            f.add(0x10).cast::<u32>().write_volatile(80);
            f.add(0x94).cast::<u32>().write_volatile(0);
            f.add(0xA8).cast::<u64>().write_volatile(u64::MAX);

            // The stream (0x2B8 B: 0x1BC context + 0x3C timestamp + 4 WFI +
            // 0x3C timestamp + 0x7C start + 4 terminator).
            let s = stream.raw_ptr();
            let q = |off: usize| s.add(off).cast::<u64>();
            // type 0xB — the CL context record (payload offset + 4).
            s.write_volatile(0x0B);
            q(0x14).write_volatile(js + 0x20); // +0x10 the command list
            q(0x1C).write_volatile(stats_va); // +0x18 conv(*(fw+0x268))
            q(0x24).write_volatile(state_va); // +0x20 the state
            s.add(0x2C).cast::<u32>().write_volatile(ctx); // +0x28 context ID
            s.add(0x30).cast::<u32>().write_volatile(g15_soft_faults()); // +0x2C isHWSoftFaultEnabled
            s.add(0x38).cast::<u32>().write_volatile(0); // +0x34 desc+0x48C
            s.add(0x3C).cast::<u32>().write_volatile(0); // +0x38 channel index
            s.add(0x40).cast::<u32>().write_volatile(0); // +0x3C desc+0x460 != 0
            q(0x44).write_volatile(js + 0x76C); // +0x40 jobState+0x76C
            // +0x158 the UMA group: the pool state, no grow (+0x160/+0x168),
            // the metrics slot (MRR 0x14070 = slot | 1: never 0, boot #119),
            // +0x178 0.
            q(0x15C).write_volatile(uma_state_va);
            q(0x174).write_volatile(metrics_va);
            // +0x180…+0x198 the CDM context store A, B, C, D.
            let cs = (ctx_store_va + 0x3FF) & !0x3FF;
            q(0x184).write_volatile(cs); // +0x180
            q(0x18C).write_volatile(cs + 0x3C000); // +0x188
            q(0x194).write_volatile(cs + 0x78000); // +0x190
            q(0x19C).write_volatile(cs + 0x7A000); // +0x198
            q(0x1A4).write_volatile(js + 0x878); // +0x1A0 the stale flag
            q(0x1B4).write_volatile(notifier_va + 0xA8); // +0x1B0 the stale cutoff
            // type 3 — first timestamp (MSB 0x80), 0x3C B at +0x1BC.
            s.add(0x1BC).cast::<u32>().write_volatile(0x80000003);
            q(0x1C0).write_volatile(js + 0x810);
            q(0x1C8).write_volatile(js + 0x818);
            q(0x1D0).write_volatile(js + 0x818);
            q(0x1D8).write_volatile(state_va);
            q(0x1E8).write_volatile(js + 0x868);
            // WFI — the single word 1 at +0x1F8.
            s.add(0x1F8).cast::<u32>().write_volatile(1);
            // type 3 — second timestamp (MSB 0x00), 0x3C B at +0x1FC.
            s.add(0x1FC).cast::<u32>().write_volatile(3);
            q(0x200).write_volatile(js + 0x810);
            q(0x208).write_volatile(js + 0x818);
            q(0x210).write_volatile(js + 0x820);
            q(0x218).write_volatile(state_va);
            q(0x228).write_volatile(js + 0x868);
            // type 0xC — the CL start record, 0x7C B at +0x238.
            s.add(0x238).cast::<u32>().write_volatile(0x0C);
            q(0x23C).write_volatile(stats_va);
            q(0x244).write_volatile(state_va);
            s.add(0x24C).cast::<u32>().write_volatile(ctx); // +0x14 jobState+0x10
            q(0x250).write_volatile(js + 0x76C);
            q(0x260).write_volatile(words_va + 4); // +0x28 the firmware stamp word
            s.add(0x28C).cast::<u32>().write_volatile(0); // +0x54 dependency flag
            q(0x290).write_volatile(strm + 0x15C); // +0x58 the context payload+0x158
            s.add(0x298).cast::<u32>().write_volatile(0u32.wrapping_sub(0x238)); // +0x60 the rewind to the context record
            s.add(0x29C).cast::<u8>().write_volatile(0); // +0x64 flags (no deps)
            q(0x29D).write_volatile(js + 0x878); // +0x65
            q(0x2A5).write_volatile(js + 0x860); // +0x6D
            // type 2 — terminator at +0x2B4.
            s.add(0x2B4).cast::<u32>().write_volatile(0x40000002);

        }
        Ok(G15ClJob {
            job_state,
            stream,
            notifier,
            cdm_stream,
            n: 0,
            stamp: 0,
            ctx,
            uma,
        })
    }

    /// G15: submit `job` on `ch` as its next job n: the per-job numbers
    /// (stamp value n · 0x100, job ID and counters n, notifier key n,
    /// record slot n-1), the UMA pool's submit count +1 (the kext's
    /// AGXUMAFList::updateSubmitInfo), the CL ring entry (`fw::g15::ring(2)`,
    /// the entry index shared by every channel on the ring) and
    /// its doorbell word, then the doorbell message.
    fn g15_cl_submit(&self, ch: &mut G15ClChannel, job: &mut G15ClJob) -> Result {
        const CL_RING: usize = fw::g15::ring(2);
        let mut rings = self.g15_rings.lock();
        self.g15_ring_room(CL_RING, rings[CL_RING], ch, ch.submitted, 1)?;
        let n = ch.submitted + 1;
        let stamp = n << 8; // the previous job's value + 0x100, low byte 0
        job.n = n;
        job.stamp = stamp;
        let js = job.job_state.gpu_va().get();
        // SAFETY: in-bounds fields of the job's own buffers and the
        // channel's record slots.
        unsafe {
            let j = job.job_state.raw_ptr();
            j.add(4).cast::<u64>().write_volatile(u64::from(n)); // +0x04 the queue's job counter
            j.add(0x7F8).cast::<u32>().write_volatile(stamp); // stamp value
            j.add(0x808).cast::<u32>().write_volatile(n); // job ID (unique u32)
            j.add(0x80C).cast::<u32>().write_volatile(n - 1); // the queue's CL counter
            job.notifier.raw_ptr().add(8).cast::<u32>().write_volatile(n); // the notifier key
            let s = job.stream.raw_ptr();
            s.add(0x34).cast::<u32>().write_volatile(n); // context +0x30 the notifier key
            s.add(0x50).cast::<u32>().write_volatile(n); // context +0x4C job ID
            s.add(0x1AC).cast::<u64>().write_volatile(u64::from(n)); // context +0x1A8 jobState+0x04
            s.add(0x1F0).cast::<u32>().write_volatile(n); // first timestamp: job ID
            s.add(0x230).cast::<u32>().write_volatile(n); // second timestamp: job ID
            s.add(0x25C).cast::<u32>().write_volatile(n); // start +0x24 job ID
            s.add(0x268).cast::<u32>().write_volatile(stamp); // start +0x30 the stamp value
            ch.chan_cached
                .raw_ptr()
                .add(((n - 1) % 256) as usize * 8)
                .cast::<u64>()
                .write_volatile(js); // record slot n-1
        }
        core::sync::atomic::fence(Ordering::Release);
        job.uma.count_submit();
        let state_va = ch.state.gpu_va().get();
        let idx = rings[CL_RING];
        rings[CL_RING] = (idx + 1) % 256;
        let ring = self.initdata.ring_area.raw_ptr();
        // SAFETY: the ring entry (slot idx % 256 of the 0x1800 storage) and the doorbell word are
        // in-bounds of the 128 KiB ring region.
        unsafe {
            let storage = ring.add(CL_RING * fw::g15::RING_STRIDE + 8 + (idx % 256) as usize * 24);
            storage.cast::<u64>().write_volatile(0); // +0x00 timestamp
            storage.add(8).cast::<u64>().write_volatile(state_va); // +0x08 state FWVA
            storage.add(0x10).cast::<u32>().write_volatile(2); // +0x10 class = CL
            storage.add(0x14).cast::<u16>().write_volatile((job.n % 256) as u16); // +0x14 command ID
            storage.add(0x16).write_volatile(ch.stamp_index as u8); // +0x16 stamp index
            storage.add(0x17).write_volatile(1); // +0x17 flag (processed when != 0)
            crate::mem::dc_civac(storage, 24); // the entry first, then the index (as `g15_rd_submit`)
            kernel::time::delay::udelay(Delta::from_micros(G15_PUBLISH_GAP_US));
            ring.add(CL_RING * fw::g15::RING_STRIDE).cast::<u32>().write_volatile((idx + 1) % 256);
            crate::mem::dc_civac(ring.add(CL_RING * fw::g15::RING_STRIDE), 4);
        }
        drop(rings);
        ch.submitted = job.n;
        self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(2))
    }

    /// G15: wait until ring `k` has room for the entry at `next` (its cursor,
    /// under the `g15_rings` lock) and `ch`'s record slots, `queued` used so
    /// far, for `records` more.
    /// Every queue's jobs share a ring's 256 entries, and a channel has 256
    /// record slots. The firmware frees an entry when its consumer takes it
    /// (the read index, region 2) and a slot when its record dispatcher
    /// passes it (channel state +0x20, the slot cursor). An entry or a slot
    /// written before that is lost, or shows the dispatcher a command ID
    /// behind its cursor: it walks every slot and crashes on an empty one
    /// (`AGFA_RecordDispatch`+0x130, eight `eglpass loop` processes).
    pub(crate) fn g15_ring_room(&self, k: usize, next: u32, ch: &G15ClChannel, queued: u32, records: u32) -> Result {
        let base = self.initdata.ring_area.raw_ptr();
        let rp = base.wrapping_add(fw::g15::RING_REGION2_OFF + 16 * k).cast_const();
        let cur = ch.state.raw_ptr().wrapping_add(0x20).cast_const();
        let stopped = self.initdata.event_page.raw_ptr().wrapping_add(0x4590) as *const u8;
        let start = Instant::<Monotonic>::now();
        loop {
            // A stopped firmware takes nothing until its recovery resumes it,
            // and the recovery needs the channel locks this submit holds: fail
            // the job, as macOS fails the commands it has not handed over yet
            // (spec: faults.md, "The host's side").
            crate::mem::dc_civac(stopped, 4);
            // SAFETY: an in-bounds u32 read of the event page.
            if self.crashed.load(Ordering::Relaxed) || unsafe { stopped.cast::<u32>().read_volatile() } != 0 {
                return Err(ECANCELED);
            }
            crate::mem::dc_civac(rp, 4);
            crate::mem::dc_civac(cur, 4);
            // SAFETY: in-bounds u32 reads of the ring region and the channel state.
            let (read, passed) = unsafe { (rp.cast::<u32>().read_volatile(), cur.cast::<u32>().read_volatile()) };
            let free = (read % 256 + 255 - next) % 256;
            let used = queued.wrapping_sub(passed) % 256;
            if free > 0 && used + records < 256 {
                return Ok(());
            }
            if start.elapsed() >= Delta::from_millis(G15_RING_WAIT_MS) {
                dev_err!(self.dev.as_ref(), "G15: ring {k} full (read {read:#x}, next {next:#x}) or stamp index {} slots full ({used} in use)\n", ch.stamp_index);
                // G15 lab: the firmware's last events at the first stall (the ktrace flag, `Debug4`).
                static DUMPED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
                if !DUMPED.swap(true, Ordering::Relaxed) {
                    self.g15_trace_dump(160);
                    self.g15_dump_ring_stall(k);
                    Self::g15_dump_chan_state(self.dev.as_ref(), "submitting", ch);
                }
                return Err(EBUSY);
            }
            kernel::time::delay::fsleep(Delta::from_micros(50));
        }
    }

    /// G15: whether every job submitted on `ch` has completed.
    pub(crate) fn g15_chan_done(&self, ch: &G15ClChannel) -> bool {
        ch.submitted == 0 || self.g15_cl_done(ch, ch.submitted << 8)
    }

    /// G15: hold back the rest of a submission: the poller calls `f` until it
    /// returns true (it submits what it can each time).
    pub(crate) fn g15_defer(&self, f: KBox<dyn FnMut() -> bool + Send>) -> Result {
        self.g15_deferred.lock().push(f, GFP_KERNEL)?;
        if let Some(kick) = self.g15_kick.lock().as_ref() {
            kick();
        }
        Ok(())
    }

    /// G15: advance the held-back submissions (outside the list's lock: they
    /// submit, and a submit may hold back more).
    fn g15_run_deferred(&self) {
        let mut todo = core::mem::take(&mut *self.g15_deferred.lock());
        let mut i = 0;
        while i < todo.len() {
            if (todo[i])() {
                drop(todo.swap_remove(i));
            } else {
                i += 1;
            }
        }
        let mut list = self.g15_deferred.lock();
        for f in todo.drain_all() {
            if list.push(f, GFP_ATOMIC).is_err() {
                dev_err!(self.dev.as_ref(), "G15: a held-back submission was lost\n");
            }
        }
    }

    /// G15: whether `job` completed: the host stamp word has reached its
    /// stamp value (the kext's IOGPUEventMachine::testEvent, signed). The
    /// notifier walk writes it and then posts the completion event.
    fn g15_cl_done(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        crate::mem::dc_civac(ch.words.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds u32 reads of the channel's own stamp words.
        let (host, fwst) = unsafe {
            let w = ch.words.raw_ptr() as *const u32;
            (w.read_volatile(), w.add(1).read_volatile())
        };
        // The firmware stamp comes from its in-order retire, after the job ran.
        // The notifier walk that writes the host stamp can skip the last jobs of
        // a burst (boots #435, #436: host behind, firmware at the last stamp
        // for good), so either word completes the job.
        host.wrapping_sub(stamp) as i32 >= 0 || fwst.wrapping_sub(stamp) as i32 >= 0
    }

    /// G15: whether the firmware has retired `job` (its in-order retire
    /// writes the firmware stamp word, possibly after the completion
    /// event): only then may the job's buffers go.
    fn g15_cl_retired(&self, ch: &G15ClChannel, stamp: u32) -> bool {
        // SAFETY: an in-bounds u32 read of the channel's own stamp words.
        let fwst = unsafe { (ch.words.raw_ptr() as *const u32).add(1).read_volatile() };
        fwst.wrapping_sub(stamp) as i32 >= 0
    }

    /// G15: submit `job` on `chan` and track it until its stamp: `done`
    /// runs (from the firmware's completion event) once it completed.
    pub(crate) fn g15_cl_run(
        &self,
        chan: &Arc<Mutex<G15ClChannel>>,
        mut job: G15ClJob,
        done: KBox<dyn FnMut(Option<Error>) + Send>,
    ) -> Result {
        self.g15_cl_submit(&mut chan.lock(), &mut job)?;
        mod_dev_dbg!(self.dev, "G15: CL job {} rung (ctx {}, stamp {:#x})\n", job.n, job.ctx, job.stamp);
        self.g15_pending.lock().push(
            G15ClPending {
                chan: chan.clone(),
                stamp: job.stamp,
                n: job.n,
                ctx: job.ctx,
                ta: None,
                _work: G15Work::Cl(job),
                done,
                signaled: false,
                error: None,
                nudge: Instant::<Monotonic>::now(),
                nudges: 0,
            },
            GFP_KERNEL,
        )?;
        // The completion may already have come; else the poller watches.
        self.g15_cl_retire();
        if let Some(kick) = self.g15_kick.lock().as_ref() {
            kick();
        }
        Ok(())
    }

    /// G15: log the pending CL jobs (stamps, context) and take a lab dump
    /// (the GPU's fault register among the registers): a job a queue
    /// teardown cancels never completed.
    pub(crate) fn g15_cl_dump_pending(&self) {
        for p in self.g15_pending.lock().iter() {
            let ch = p.chan.lock();
            // SAFETY: in-bounds u32 reads of the channel's own stamp words.
            let (host, fwst) = unsafe {
                let w = ch.words.raw_ptr() as *const u32;
                (w.read_volatile(), w.add(1).read_volatile())
            };
            dev_warn!(self.dev.as_ref(), "G15: pending CL job {} ctx {} stamp {:#x}: host {:#x} fw {:#x}, chan submitted {}\n",
                      p.n, p.ctx, p.stamp, host, fwst, ch.submitted);
            Self::g15_dump_chan_state(self.dev.as_ref(), "chan", &ch);
            if let Some((ta, _)) = p.ta.as_ref() {
                Self::g15_dump_chan_state(self.dev.as_ref(), "ta chan", &ta.lock());
            }
        }
        for k in 0..fw::g15::RINGS {
            let base = self.initdata.ring_area.raw_ptr();
            let wp = base.wrapping_add(k * fw::g15::RING_STRIDE);
            let rp = base.wrapping_add(fw::g15::RING_REGION2_OFF + 16 * k);
            crate::mem::dc_civac(wp.cast_const(), 4);
            crate::mem::dc_civac(rp.cast_const(), 4);
            // SAFETY: in-bounds u32 reads of the 128 KiB ring region.
            let (w, r) = unsafe { ((wp as *const u32).read_volatile(), (rp as *const u32).read_volatile()) };
            if w != r {
                dev_warn!(self.dev.as_ref(), "G15: ring {} holds unconsumed entries: write {:#x} read {:#x}\n", k, w, r);
            }
        }
        for k in [fw::g15::ring(0), fw::g15::ring(1), fw::g15::ring(2)] {
            self.g15_dump_ring_entries(k);
        }
        self.g15_trace_dump(64);
        let ev = self.initdata.fw_rings[0].raw_ptr() as *const u32;
        // SAFETY: in-bounds reads of the event ring's state block.
        let (rd, wr) = unsafe { (ev.read_volatile(), ev.add(8).read_volatile()) };
        dev_warn!(self.dev.as_ref(), "G15: {} notification(s), {} GPU IRQ(s), {} completion record(s), {} re-ring(s), {} nudge(s); event ring read {:#x} write {:#x}\n",
                  self.g15_notifies.load(Ordering::Relaxed), self.g15_irqs.load(Ordering::Relaxed),
                  self.g15_completions.load(Ordering::Relaxed), self.g15_rerings.load(Ordering::Relaxed),
                  self.g15_nudges.load(Ordering::Relaxed), rd, wr);
        g15_fwdump(3);
    }

    /// G15: release the oldest quarantined job buffers once enough newer ones wait
    /// (`G15_QUARANTINE_*`).
    fn g15_collect_garbage(&self) {
        let mut guard = self.alloc.lock();
        let (n, _) = guard.shared.garbage();
        if n > G15_QUARANTINE_HIGH {
            guard.shared.collect_garbage(n - G15_QUARANTINE_KEEP);
        }
        let (n, _) = guard.gpu.garbage();
        if n > G15_QUARANTINE_HIGH {
            guard.gpu.collect_garbage(n - G15_QUARANTINE_KEEP);
        }
    }

    /// G15 lab: print the last `last` records of the firmware's trace ring.
    fn g15_trace_dump(&self, last: usize) {
        let t = self.g15_trace.lock();
        let n = t.0.len();
        let start = if n < 256 { 0 } else { t.1 % 256 };
        let first = n.saturating_sub(last);
        for j in first..n {
            let r = &t.0[(start + j) % n.max(1)];
            dev_warn!(self.dev.as_ref(), "G15 ktrace: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}\n",
                      r[0] as u32, (r[0] >> 32) as u32, r[1] as u32, (r[1] >> 32) as u32, r[2] as u32, (r[2] >> 32) as u32, r[3] as u32,
                      (r[3] >> 32) as u32, r[4] as u32, (r[4] >> 32) as u32, r[5] as u32, (r[5] >> 32) as u32, r[6] as u32, (r[6] >> 32) as u32);
        }
    }

    /// G15 lab: the firmware's per-channel words the consumer writes when it takes an
    /// entry (`state+0x24/0x28` the record-slot cursor and the entry's command ID,
    /// `+0x5C`, `+0x80`, `+0x98`) and the records the host published.
    fn g15_dump_chan_state(dev: &kernel::platform::Device, name: &str, ch: &G15ClChannel) {
        let st = ch.state.raw_ptr();
        crate::mem::dc_civac(st.cast_const(), 0xC0);
        // SAFETY: in-bounds u32 reads of the 0x24C0 state block.
        let w = |o: usize| unsafe { (st.add(o) as *const u32).read_volatile() };
        dev_warn!(dev, "G15: {} stamp index {}: state +0x20 {:#x} +0x24 {:#x} +0x28 {:#x} +0x5c {:#x} +0x80 {:#x} +0x98 {:#x}; submitted {} records {}\n",
                  name, ch.stamp_index, w(0x20), w(0x24), w(0x28), w(0x5C), w(0x80), w(0x98), ch.submitted, ch.submitted_records);
    }

    /// G15 lab: the last two entries published to ring `k`.
    fn g15_dump_ring_entries(&self, k: usize) {
        let base = self.initdata.ring_area.raw_ptr();
        let wp = base.wrapping_add(k * fw::g15::RING_STRIDE);
        crate::mem::dc_civac(wp.cast_const(), 4);
        // SAFETY: an in-bounds u32 read of the 128 KiB ring region.
        let w = unsafe { (wp as *const u32).read_volatile() } as usize;
        for back in 1..=3usize {
            let i = (w + 256 - back) % 256;
            let e = base.wrapping_add(k * fw::g15::RING_STRIDE + 8 + i * 24);
            crate::mem::dc_civac(e.cast_const(), 24);
            // SAFETY: in-bounds u64 reads of an entry of the ring.
            let q = unsafe { [(e as *const u64).read_volatile(), (e.add(8) as *const u64).read_volatile(), (e.add(16) as *const u64).read_volatile()] };
            dev_warn!(self.dev.as_ref(), "G15: ring {} entry {}: {:#018x} {:#018x} {:#018x}\n", k, i, q[0], q[1], q[2]);
        }
    }

    /// G15 lab: every ring's write, read and CFI words, and the entries of
    /// ring `k` around its read index (a stalled consumer's head).
    fn g15_dump_ring_stall(&self, k: usize) {
        let base = self.initdata.ring_area.raw_ptr();
        let w32 = |off: usize| {
            let p = base.wrapping_add(off);
            crate::mem::dc_civac(p.cast_const(), 4);
            // SAFETY: an in-bounds u32 read of the 128 KiB ring region.
            unsafe { (p as *const u32).read_volatile() }
        };
        for r in 0..9 {
            let off = fw::g15::RING_REGION2_OFF + 16 * r;
            dev_warn!(self.dev.as_ref(), "G15: ring {r}: write {:#x} read {:#x} cfi {:#x}\n",
                      w32(r * fw::g15::RING_STRIDE), w32(off), w32(off + 8));
        }
        let read = w32(fw::g15::RING_REGION2_OFF + 16 * k) as usize;
        for d in 0..4usize {
            let i = (read + 256 - 1 + d) % 256;
            let e = base.wrapping_add(k * fw::g15::RING_STRIDE + 8 + i * 24);
            crate::mem::dc_civac(e.cast_const(), 24);
            // SAFETY: in-bounds u64 reads of an entry of the ring.
            let q = unsafe { [(e as *const u64).read_volatile(), (e.add(8) as *const u64).read_volatile(), (e.add(16) as *const u64).read_volatile()] };
            dev_warn!(self.dev.as_ref(), "G15: ring {} entry {:#x}: {:#018x} {:#018x} {:#018x}\n", k, i, q[0], q[1], q[2]);
        }
    }

    /// G15: whether ring `k` holds entries the firmware has not consumed:
    /// its write index (the doorbell word) is not its read index
    /// (firmware-owned, region 2).
    fn g15_ring_unconsumed(&self, k: usize) -> bool {
        let base = self.initdata.ring_area.raw_ptr();
        let wp = base.wrapping_add(k * fw::g15::RING_STRIDE);
        let rp = base.wrapping_add(fw::g15::RING_REGION2_OFF + 16 * k);
        crate::mem::dc_civac(wp.cast_const(), 4);
        crate::mem::dc_civac(rp.cast_const(), 4);
        // SAFETY: in-bounds u32 reads of the 128 KiB ring region.
        unsafe { (wp as *const u32).read_volatile() != (rp as *const u32).read_volatile() }
    }

    /// G15: run `done` for every submitted CL job that completed, and free
    /// the buffers of those the firmware has retired.
    fn g15_cl_retire(&self) {
        let mut retired = KVec::new();
        let mut pending = self.g15_pending.lock();
        let mut i = 0;
        while i < pending.len() {
            let (complete, gone) = {
                let p = &pending[i];
                let ch = p.chan.lock();
                (self.g15_cl_done(&ch, p.stamp), self.g15_cl_retired(&ch, p.stamp))
            };
            let p = &mut pending[i];
            if complete && !p.signaled {
                mod_dev_dbg!(self.dev, "G15: job {} (stamp {:#x}) complete\n", p.n, p.stamp);
                p.signaled = true;
                (p.done)(p.error.take());
            }
            if p.signaled && gone && !p._work.notifier_listed() {
                if retired.push(pending.swap_remove(i), GFP_ATOMIC).is_err() {
                    break;
                }
            } else {
                i += 1;
            }
        }
        core::mem::drop(pending);
        // The retired jobs' buffers are freed here, outside the lock.
        core::mem::drop(retired);
    }

    /// G15: the first GPU jobs — two no-launch compute jobs on one channel
    /// (spec: agx-g15c/cl-job.md, "The no-launch compute container" and
    /// "Successive jobs on one channel"). The first is submitted inside the
    /// GPU's idle power-down, the second right after the first completes.
    fn g15_compute_selftest(&self) {
        const JOBS: u32 = 2;
        const WAIT_MS: u32 = 5000;
        const RING_MS: u32 = 500;
        const CL_RING: usize = fw::g15::ring(2);
        let dev = self.dev.as_ref();
        let mut ch = match self.g15_cl_channel_new() {
            Ok(ch) => ch,
            Err(e) => {
                dev_err!(dev, "G15 compute self-test: channel alloc {e:?}\n");
                return;
            }
        };
        let ring = self.initdata.ring_area.raw_ptr();
        // SAFETY: read-only, in-bounds of the ring region.
        let read_index = || unsafe {
            (ring.add(fw::g15::RING_REGION2_OFF + 16 * CL_RING) as *const u32).read_volatile()
        };
        let words = ch.words.raw_ptr() as *const u32;
        let mut jobs = KVec::new();
        for _ in 0..JOBS {
            let mut job = match self.g15_cl_job_new(&ch, None, 1, &[]) {
                Ok(j) => j,
                Err(e) => {
                    dev_err!(dev, "G15 compute self-test: job alloc {e:?}\n");
                    break;
                }
            };
            if ch.submitted == 0 {
                // Submit 100 ms after the control self-test, inside the
                // GPU's idle power-down, where a doorbell can be missed
                // (the job then runs on the re-ring; boots #87-#89, #92).
                kernel::time::delay::fsleep(Delta::from_millis(100));
                // Lab diagnostic: the firmware's state before the jobs.
                g15_fwdump(0);
            }
            let js = job.job_state.gpu_va().get();
            // A submission in progress (the kext's updateSubmitInProgress):
            // the firmware holds off its idle power-down while it is set.
            self.initdata
                .pb_table
                .with(|raw, _| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
            if let Err(e) = self.g15_cl_submit(&mut ch, &mut job) {
                dev_err!(dev, "G15 compute self-test: job {} doorbell refused ({e:?})\n", job.n);
            }
            dev_info!(dev, "G15 compute self-test: job {} submitted (job-state {js:#x}, stamp {:#x})\n", job.n, job.stamp);
            let mut waited = 0;
            while waited < WAIT_MS && !self.g15_cl_done(&ch, job.stamp) {
                kernel::time::delay::fsleep(Delta::from_millis(1));
                waited += 1;
                if waited % RING_MS == 0 {
                    // The re-ring: a doorbell lost in the power-down.
                    if let Err(e) = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(2)) {
                        dev_err!(dev, "G15 compute self-test: doorbell refused ({e:?})\n");
                        break;
                    }
                }
                if job.n == 1 && waited == 100 {
                    // Lab diagnostic: after the first doorbell (fwdump-2).
                    g15_fwdump(2);
                }
            }
            self.initdata
                .pb_table
                .with(|raw, _| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
            // SAFETY: in-bounds u32 reads of the channel's own stamp words.
            let (host, fwst) = unsafe { (words.read_volatile(), words.add(1).read_volatile()) };
            let events = self.g15_completions.load(Ordering::Relaxed);
            let done = self.g15_cl_done(&ch, job.stamp);
            if done {
                dev_info!(dev, "G15 compute self-test: job {} COMPLETED after ~{waited} ms (host stamp {host:#x}, fw stamp {fwst:#x}, {events} completion event(s), ring read {:#x})\n", job.n, read_index());
            } else {
                dev_err!(dev, "G15 compute self-test: job {} TIMEOUT after {waited} ms (host stamp {host:#x}, fw stamp {fwst:#x}, {events} completion event(s), ring read {:#x})\n", job.n, read_index());
            }
            if jobs.push(job, GFP_KERNEL).is_err() || !done {
                break;
            }
        }
        // Let late notifications land before the second dump.
        kernel::time::delay::fsleep(Delta::from_millis(100));
        // Lab diagnostic: the firmware's state after the jobs (fwdump-1).
        g15_fwdump(1);
        // The firmware log of the jobs (posted with or without a 0x42).
        self.g15_drain_fw_rings();
        // Keep the channel and the jobs alive: the firmware's DAG root and
        // the notifier list reference them.
        match KBox::new(ch, GFP_KERNEL) {
            Ok(ch) => *self.g15_selftest.lock() = Some((ch, jobs)),
            Err(_) => dev_err!(dev, "G15 compute self-test: cannot keep the channel\n"),
        }
    }

    /// Mark work associated with currently in-progress event slots as failed, after a fault or
    /// timeout.
    fn mark_pending_events(&self, culprit_slot: Option<u32>, error: workqueue::WorkError) {
        dev_err!(self.dev.as_ref(), "  Pending events:\n");

        #[ver(G != G15)]
        if true {
            self.initdata.globals.with(|raw, _inner| {
            for (index, i) in raw.pending_stamps.iter().enumerate() {
                let info = i.info.load(Ordering::Relaxed);
                let wait_value = i.wait_value.load(Ordering::Relaxed);

                if info & 1 != 0 {
                    #[ver(V >= V13_5)]
                    let slot = (info >> 4) & 0x7f;
                    #[ver(V < V13_5)]
                    let slot = (info >> 3) & 0x7f;
                    #[ver(V >= V13_5)]
                    let flags = info & 0xf;
                    #[ver(V < V13_5)]
                    let flags = info & 0x7;
                    dev_err!(
                        self.dev.as_ref(),
                        "    [{}:{}] flags={} value={:#x}\n",
                        index,
                        slot,
                        flags,
                        wait_value
                    );
                    let error = if culprit_slot.is_some() && culprit_slot != Some(slot) {
                        workqueue::WorkError::Killed
                    } else {
                        error
                    };
                    self.event_manager.mark_error(slot, wait_value, error);
                    i.info.store(0, Ordering::Relaxed);
                    i.wait_value.store(0, Ordering::Relaxed);
                }
            }
            });
        }

        #[ver(G == G15)]
        if true {
            // G15: no M1-style pending stamps; the G15 workqueue model is
            // M3 work.
            let _ = (culprit_slot, &error);
        }
    }

    /// Fetch the GPU MMU fault information from the hardware registers.
    fn get_fault_info(&self) -> Option<regs::FaultInfo> {
        // TODO: handle differently
        let guard = self.dev.registration_guard()?;

        guard.registration_data_with(|reg_data| {
            let res = &reg_data.resources;

            let info = res.get_fault_info(self.cfg);
            if let Some(info) = &info {
                dev_err!(self.dev.as_ref(), "  Fault info: {:#x?}\n", info);
            }
            info
        })
    }

    /// Resume the GPU firmware after it halts (due to a timeout, fault, or request).
    fn recover(&self) {
        #[ver(G != G15)]
        if true {
            self.initdata.fw_status.with(|raw, _inner| {
            let halt_count = raw.flags.halt_count.load(Ordering::Relaxed);
            let mut halted = raw.flags.halted.load(Ordering::Relaxed);
            dev_err!(self.dev.as_ref(), "  Halt count: {}\n", halt_count);
            dev_err!(self.dev.as_ref(), "  Halted: {}\n", halted);

            if halted == 0 {
                let start = Instant::<Monotonic>::now();
                while start.elapsed() < HALT_ENTER_TIMEOUT {
                    halted = raw.flags.halted.load(Ordering::Relaxed);
                    if halted != 0 {
                        break;
                    }
                    crate::mem::sync();
                }
                halted = raw.flags.halted.load(Ordering::Relaxed);
            }

            if debug_enabled(DebugFlags::NoGpuRecovery) {
                dev_crit!(
                    self.dev.as_ref(),
                    "  GPU recovery is disabled, wedging forever!\n"
                );
            } else if halted != 0 {
                dev_err!(self.dev.as_ref(), "  Attempting recovery...\n");
                raw.flags.halted.store(0, Ordering::SeqCst);
                raw.flags.resume.store(1, Ordering::SeqCst);
            } else {
                dev_err!(self.dev.as_ref(), "  Cannot recover.\n");
            }
            });
        }

        #[ver(G == G15)]
        if true {
            // G15: the halt state lives in the FMC ring, not the M1
            // fw_status block; recovery is M3 work.
            dev_err!(self.dev.as_ref(), "  G15 recovery: not yet implemented\n");
        }
    }

    /// Return the packed GPU enabled core masks.
    // Only used for some versions
    #[allow(dead_code)]
    pub(crate) fn core_masks_packed(&self) -> &[u32] {
        self.dyncfg.id.core_masks_packed.as_slice()
    }

    /// Kick a submission pipe for a submitted job to tell the firmware to start processing it.
    pub(crate) fn run_job(&self, job: workqueue::JobSubmission::ver<'_>) -> Result {
        mod_dev_dbg!(self.dev, "GPU: run_job\n");

        let pipe_type = job.pipe_type();
        mod_dev_dbg!(self.dev, "GPU: run_job: pipe_type={:?}\n", pipe_type);

        let pipes = match pipe_type {
            PipeType::Vertex => &self.pipes.vtx,
            PipeType::Fragment => &self.pipes.frag,
            PipeType::Compute => &self.pipes.comp,
        };

        let index: usize = job.priority() as usize;
        let mut pipe = pipes.get(index).ok_or(EIO)?.lock();

        mod_dev_dbg!(self.dev, "GPU: run_job: run()\n");
        job.run(&mut pipe);
        mod_dev_dbg!(self.dev, "GPU: run_job: ring doorbell\n");

        let mut guard = self.rtkit.lock();
        let Some(rtk) = guard.as_mut().as_pin_mut() else {
            return Err(EIO);
        };
        rtk.send_message(
            EP_DOORBELL,
            MSG_TX_DOORBELL | pipe_type as u64 | ((index as u64) << 2),
        )?;
        mod_dev_dbg!(self.dev, "GPU: run_job: done\n");

        Ok(())
    }

    pub(crate) fn start_op(self: &Arc<GpuManager::ver>) -> Result<OpGuard> {
        if self.is_crashed() {
            return Err(ENODEV);
        }

        #[ver(G != G15)]
        if true {
            let val = self
                .initdata
                .globals
                .with(|raw, _inner| raw.pending_submissions.fetch_add(1, Ordering::Acquire));

            mod_dev_dbg!(self.dev, "OP start (pending: {})\n", val + 1);
        }

        #[ver(G == G15)]
        if true {
            // G15: M1's pending_submissions is the PB table's
            // submit-in-progress word.
            let val = self
                .initdata
                .pb_table
                .with(|raw, _inner| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
            mod_dev_dbg!(self.dev, "OP start (pending: {})\n", val + 1);
        }
        // G15: no M1 firmware kick — its doorbell 0x10 makes the firmware
        // log "AGFHALWaitForIdle is NOT Implemented for G15" (boot #102).
        #[ver(G != G15)]
        self.kick_firmware()?;
        Ok(OpGuard(self.clone()))
    }

    fn invalidate_context(
        &self,
        context: &fw::types::GpuObject<fw::workqueue::GpuContextData>,
    ) -> Result {
        mod_dev_dbg!(
            self.dev,
            "Invalidating GPU context @ {:?}\n",
            context.weak_pointer()
        );

        if self.is_crashed() {
            return Err(ENODEV);
        }

        // G15: no M1 GPU context to destroy — G15 jobs carry their context
        // ID, and the device-control ring does not take M1's DestroyContext.
        #[ver(G == G15)]
        if true {
            return Ok(());
        }

        let mut guard = self.alloc.lock();
        let (garbage_count, _) = guard.private.garbage();
        let (garbage_count_gpuro, _) = guard.gpu_ro.garbage();

        let dc = context.with(
            |raw, _inner| fw::channels::DeviceControlMsg::ver::DestroyContext {
                unk_4: 0,
                ctx_23: raw.unk_23,
                #[ver(V < V13_3)]
                __pad0: Default::default(),
                unk_c: U32(0),
                unk_10: U32(0),
                ctx_0: raw.unk_0,
                ctx_1: raw.unk_1,
                ctx_4: raw.unk_4,
                #[ver(V < V13_3)]
                __pad1: Default::default(),
                #[ver(V < V13_3)]
                unk_18: 0,
                gpu_context: Some(context.weak_pointer()),
                __pad2: Default::default(),
            },
        );

        mod_dev_dbg!(self.dev, "Context invalidation command: {:?}\n", &dc);

        let mut txch = self.tx_channels.lock();

        let token = txch.device_control.send(&dc);

        {
            let mut guard = self.rtkit.lock();
            let Some(rtk) = guard.as_mut().as_pin_mut() else {
                return Err(EIO);
            };
            rtk.send_message(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL)?;
        }

        txch.device_control.wait_for(token)?;

        mod_dev_dbg!(
            self.dev,
            "GPU context invalidated: {:?}\n",
            context.weak_pointer()
        );

        // The invalidation does a cache flush, so it is okay to collect garbage
        guard.private.collect_garbage(garbage_count);
        guard.gpu_ro.collect_garbage(garbage_count_gpuro);

        Ok(())
    }
}

#[versions(AGX)]
impl GpuManager for GpuManager::ver {
    fn _as_any(&self) -> &dyn Any {
        self
    }

    fn arc_as_any(self: Arc<Self>) -> Arc<dyn Any + Sync + Send> {
        self as Arc<dyn Any + Sync + Send>
    }

    fn init(&self) -> Result {
        self.tx_channels.lock().device_control.send(
            &fw::channels::DeviceControlMsg::ver::Initialize(Default::default()),
        );

        // G15: the m1n1 proxy did the IOP RTKit handshake and started the
        // AGX endpoints (the guest cannot reach the mailbox), so the
        // M1 boot sequence below does not run; the G15 one follows it.
        #[ver(G != G15)]
        if true {
            let initdata = self.initdata.gpu_va().get();
            let mut guard = self.rtkit.lock();
            let mut rtk = guard.as_mut().as_pin_mut().unwrap();

            rtk.as_mut().boot()?;
            rtk.as_mut().start_endpoint(EP_FIRMWARE)?;
            rtk.as_mut().start_endpoint(EP_DOORBELL)?;
            rtk.as_mut()
                .send_message(EP_FIRMWARE, MSG_INIT | (initdata & INIT_DATA_MASK))?;
            rtk.as_mut()
                .send_message(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL)?;
            core::mem::drop(guard);

            self.kick_firmware()?;
        }

        // G15: start RTKit (SetIOPPower INIT, the handshake), the
        // AGX endpoints, one RTKit keep-awake reference (without it the
        // firmware hibernates its IOP at the GPU's first idle and the
        // doorbell never wakes it, boots #77-#79), then MSG_INIT (the FMC
        // header's GPU VA: the firmware's init-data grab blocks until it
        // arrives, armfw `sub_FFFFFC0000034880`) and the device-control
        // doorbell. Firmware notifications arrive by IRQ (recv_message
        // drains the rings).
        let fmc = self.initdata.fmc.gpu_va().get();
        {
            let mut guard = self.rtkit.lock();
            let mut rtk = guard.as_mut().as_pin_mut().ok_or(EIO)?;
            rtk.as_mut().wake()?;
            rtk.as_mut().start_endpoint(EP_FIRMWARE)?;
            rtk.as_mut().start_endpoint(EP_DOORBELL)?;
            rtk.as_mut().hold_awake()?;
            rtk.as_mut()
                .send_message(EP_FIRMWARE, MSG_INIT | (fmc & INIT_DATA_MASK))?;
            rtk.as_mut()
                .send_message(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL)?;
        }
        dev_info!(self.dev.as_ref(), "G15: RTKit up; init message sent (FMC header {:#x})\n", fmc);
        self.g15_control_selftest();
        self.g15_compute_selftest();
        if debug_enabled(DebugFlags::G15RenderTest) {
            self.g15_render_selftest();
        }
        Ok(())
    }

    fn update_globals(&self) {
        let mut timeout: u32 = 2;
        if debug_enabled(DebugFlags::WaitForPowerOff) {
            timeout = 0;
        } else if debug_enabled(DebugFlags::KeepGpuPowered) {
            timeout = 5000;
        }

        #[ver(G != G15)]
        if true {
            self.initdata.globals.with(|raw, _inner| {
                raw.idle_off_delay_ms.store(timeout, Ordering::Relaxed);
            });
        }

        #[ver(G == G15)]
        if true {
            // G15: the idle-off delay is an FMC/PB-table parameter (M3 work).
            let _ = timeout;
        }
    }

    fn alloc(&self) -> Guard<'_, KernelAllocators, MutexBackend> {
        /* Clean up idle contexts */
        let mut garbage_ctx = KVec::new();
        core::mem::swap(&mut *self.garbage_contexts.lock(), &mut garbage_ctx);

        for ctx in garbage_ctx {
            if self.invalidate_context(&ctx).is_err() {
                dev_err!(
                    self.dev.as_ref(),
                    "GpuContext: Failed to invalidate GPU context!\n"
                );
                if debug_enabled(DebugFlags::OopsOnGpuCrash) {
                    panic!("GPU firmware timed out");
                }
            }
        }

        let mut guard = self.alloc.lock();
        let (garbage_count, garbage_bytes) = guard.private.garbage();
        let (ro_garbage_count, ro_garbage_bytes) = guard.gpu_ro.garbage();

        if garbage_bytes > MAX_FW_ALLOC_GARBAGE_BYTES
            || ro_garbage_bytes > MAX_FW_ALLOC_GARBAGE_BYTES
            || garbage_count > MAX_FW_ALLOC_GARBAGE_OBJECTS
            || ro_garbage_count > MAX_FW_ALLOC_GARBAGE_OBJECTS
        {
            mod_dev_dbg!(
                self.dev,
                "Collecting kalloc garbage (private: {} objects, {} bytes, gpuro: {} objects, {} bytes)\n",
                garbage_count,
                garbage_bytes,
                ro_garbage_count,
                ro_garbage_bytes
            );
            if self.flush_fw_cache().is_err() {
                dev_err!(self.dev.as_ref(), "Failed to flush FW cache\n");
            } else {
                guard.private.collect_garbage(garbage_count);
                guard.gpu_ro.collect_garbage(ro_garbage_count);
            }
        }

        guard
    }

    fn new_vm(&self, kernel_range: Range<u64>) -> Result<mmu::Vm> {
        self.uat.new_vm(self.ids.vm.next(), kernel_range)
    }

    fn bind_vm(&self, vm: &mmu::Vm) -> Result<mmu::VmBind> {
        self.uat.bind(vm)
    }

    fn new_queue(
        &self,
        reg_data: &AsahiRegData<'_>,
        vm: mmu::Vm,
        ualloc: Arc<Mutex<alloc::DefaultAllocator>>,
        ualloc_priv: Arc<Mutex<alloc::DefaultAllocator>>,
        priority: u32,
        usc_exec_base: u64,
    ) -> Result<KBox<dyn queue::Queue>> {
        let mut kalloc = self.alloc();
        let id = self.ids.queue.next();
        Ok(KBox::new(
            queue::Queue::ver::new(
                self.dev.clone(),
                reg_data,
                vm,
                &mut kalloc,
                ualloc,
                ualloc_priv,
                self.event_manager.clone(),
                &self.buffer_mgr,
                id,
                priority,
                usc_exec_base,
            )?,
            GFP_KERNEL,
        )?)
    }

    fn kick_firmware(&self) -> Result {
        if self.is_crashed() {
            return Err(ENODEV);
        }

        let mut guard = self.rtkit.lock();
        let Some(rtk) = guard.as_mut().as_pin_mut() else {
            return Err(EIO);
        };
        rtk.send_message(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_KICKFW)?;

        Ok(())
    }

    fn flush_fw_cache(&self) -> Result {
        mod_dev_dbg!(self.dev, "Flushing coprocessor data cache\n");

        if self.is_crashed() {
            return Err(ENODEV);
        }

        // G15: the device-control ring takes 56 B entries (spec: agx-g15c/channel.md),
        // not M1's DestroyContext. That message is never consumed, so every flush
        // would leave one entry behind and the ring fills after ~254 queue creations.
        // No G15 equivalent of the M1 cache flush is known (not verified that one is
        // needed), so the garbage is collected without it.
        #[ver(G == G15)]
        if true {
            return Ok(());
        }

        // ctx_0 == 0xff or ctx_1 == 0xff cause no effect on context,
        // but this command does a full cache flush too, so abuse it
        // for that.

        let dc = fw::channels::DeviceControlMsg::ver::DestroyContext {
            unk_4: 0,

            ctx_23: 0,
            #[ver(V < V13_3)]
            __pad0: Default::default(),
            unk_c: U32(0),
            unk_10: U32(0),
            ctx_0: 0xff,
            ctx_1: 0xff,
            ctx_4: 0,
            #[ver(V < V13_3)]
            __pad1: Default::default(),
            #[ver(V < V13_3)]
            unk_18: 0,
            gpu_context: None,
            __pad2: Default::default(),
        };

        let mut txch = self.tx_channels.lock();

        let token = txch.device_control.send(&dc);
        {
            let mut guard = self.rtkit.lock();
            let Some(rtk) = guard.as_mut().as_pin_mut() else {
                return Err(EIO);
            };
            rtk.send_message(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL)?;
        }

        txch.device_control.wait_for(token)?;
        Ok(())
    }

    fn ids(&self) -> &SequenceIDs {
        &self.ids
    }

    fn handle_timeout(&self, counter: u32, event_slot: i32, unk: u32) {
        dev_err!(self.dev.as_ref(), " (\\________/) \n");
        dev_err!(self.dev.as_ref(), "  |        |  \n");
        dev_err!(self.dev.as_ref(), "'.| \\  , / |.'\n");
        dev_err!(self.dev.as_ref(), "--| / (( \\ |--\n");
        dev_err!(self.dev.as_ref(), ".'|  _-_-  |'.\n");
        dev_err!(self.dev.as_ref(), "  |________|  \n");
        dev_err!(self.dev.as_ref(), "** GPU timeout nya~!!!!! **\n");
        dev_err!(self.dev.as_ref(), "  Event slot: {}\n", event_slot);
        dev_err!(self.dev.as_ref(), "  Timeout count: {}\n", counter);
        dev_err!(self.dev.as_ref(), "  Unk: {}\n", unk);

        // If we have fault info, consider it a fault.
        let error = match self.get_fault_info() {
            Some(info) => workqueue::WorkError::Fault(info),
            None => workqueue::WorkError::Timeout,
        };
        self.mark_pending_events(event_slot.try_into().ok(), error);
        self.recover();
    }

    fn handle_fault(&self) {
        dev_err!(self.dev.as_ref(), " (\\________/) \n");
        dev_err!(self.dev.as_ref(), "  |        |  \n");
        dev_err!(self.dev.as_ref(), "'.| \\  , / |.'\n");
        dev_err!(self.dev.as_ref(), "--| / (( \\ |--\n");
        dev_err!(self.dev.as_ref(), ".'|  _-_-  |'.\n");
        dev_err!(self.dev.as_ref(), "  |________|  \n");
        dev_err!(self.dev.as_ref(), "GPU fault nya~!!!!!\n");
        let error = match self.get_fault_info() {
            Some(info) => workqueue::WorkError::Fault(info),
            None => workqueue::WorkError::Unknown,
        };
        self.mark_pending_events(None, error);
        self.recover();
    }

    fn handle_channel_error(
        &self,
        error_type: ChannelErrorType,
        pipe_type: u32,
        event_slot: u32,
        event_value: u32,
    ) {
        dev_err!(self.dev.as_ref(), " (\\________/) \n");
        dev_err!(self.dev.as_ref(), "  |        |  \n");
        dev_err!(self.dev.as_ref(), "'.| \\  , / |.'\n");
        dev_err!(self.dev.as_ref(), "--| / (( \\ |--\n");
        dev_err!(self.dev.as_ref(), ".'|  _-_-  |'.\n");
        dev_err!(self.dev.as_ref(), "  |________|  \n");
        dev_err!(self.dev.as_ref(), "GPU channel error nya~!!!!!\n");
        dev_err!(self.dev.as_ref(), "  Error type: {:?}\n", error_type);
        dev_err!(self.dev.as_ref(), "  Pipe type: {}\n", pipe_type);
        dev_err!(self.dev.as_ref(), "  Event slot: {}\n", event_slot);
        dev_err!(self.dev.as_ref(), "  Event value: {:#x?}\n", event_value);

        self.event_manager.mark_error(
            event_slot,
            event_value,
            workqueue::WorkError::ChannelError(error_type),
        );

        let wq = match self.event_manager.get_owner(event_slot) {
            Some(wq) => wq,
            None => {
                dev_err!(
                    self.dev.as_ref(),
                    "Workqueue not found for this event slot!\n"
                );
                return;
            }
        };

        let wq = match wq.as_any().downcast_ref::<workqueue::WorkQueue::ver>() {
            Some(wq) => wq,
            None => {
                dev_crit!(self.dev.as_ref(), "GpuManager mismatched with WorkQueue!\n");
                return;
            }
        };

        if debug_enabled(DebugFlags::VerboseFaults) {
            wq.dump_info();
        }

        let dc = fw::channels::DeviceControlMsg::ver::RecoverChannel {
            pipe_type,
            work_queue: wq.info_pointer(),
            event_value,
            __pad: Default::default(),
        };

        mod_dev_dbg!(self.dev, "Recover Channel command: {:?}\n", &dc);
        let mut txch = self.tx_channels.lock();

        let token = txch.device_control.send(&dc);
        {
            let mut guard = self.rtkit.lock();
            let Some(rtk) = guard.as_mut().as_pin_mut() else {
                return;
            };
            if rtk
                .send_message(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL)
                .is_err()
            {
                dev_err!(
                    self.dev.as_ref(),
                    "Failed to send Recover Channel command\n"
                );
            }
        }

        if txch.device_control.wait_for(token).is_err() {
            dev_err!(
                self.dev.as_ref(),
                "Timed out waiting for Recover Channel command\n"
            );
        }

        if debug_enabled(DebugFlags::VerboseFaults) {
            wq.dump_info();
        }
    }

    fn ack_grow(&self, buffer_slot: u32, vm_slot: u32, counter: u32) {
        #[ver(G == G15)]
        if true {
            // G15: the TVB grow protocol is M1-only for now (M3 work).
            let _ = (buffer_slot, vm_slot, counter);
            #[allow(clippy::needless_return, reason = "the #[ver(G != G15)] path follows")]
            return;
        }

        #[ver(G != G15)]
        if true {
            let halt_count = self
                .initdata
                .fw_status
                .with(|raw, _inner| raw.flags.halt_count.load(Ordering::Relaxed));

            let dc = fw::channels::DeviceControlMsg::ver::GrowTVBAck {
                unk_4: 1,
                buffer_slot,
                vm_slot,
                counter,
                subpipe: 0, // TODO
                halt_count: U64(halt_count),
                __pad: Default::default(),
            };

            mod_dev_dbg!(self.dev, "TVB Grow Ack command: {:?}\n", &dc);

            let mut txch = self.tx_channels.lock();

            txch.device_control.send(&dc);
            {
                let mut guard = self.rtkit.lock();
                let Some(rtk) = guard.as_mut().as_pin_mut() else {
                    return;
                };
                if rtk
                    .send_message(EP_DOORBELL, MSG_TX_DOORBELL | DOORBELL_DEVCTRL)
                    .is_err()
                {
                    dev_err!(self.dev.as_ref(), "Failed to send TVB Grow Ack command\n");
                }
            }
        }
    }

    fn fwctl(&self, msg: fw::channels::FwCtlMsg) -> Result {
        if self.is_crashed() {
            return Err(ENODEV);
        }

        let mut fwctl = self.fwctl_channel.lock();
        let token = fwctl.send(&msg);
        {
            let mut guard = self.rtkit.lock();
            let Some(rtk) = guard.as_mut().as_pin_mut() else {
                return Err(EIO);
            };
            rtk.send_message(EP_DOORBELL, MSG_FWCTL)?;
        }
        fwctl.wait_for(token)?;
        Ok(())
    }

    fn g15_irq(&self, _index: u32) -> u64 {
        self.g15_irqs.fetch_add(1, Ordering::Relaxed);
        self.g15_drain_fw_rings()
    }

    fn g15_poll(&self) -> bool {
        self.g15_cl_retire();
        self.g15_run_deferred();
        self.g15_collect_garbage();
        self.g15_reclaim_dead();
        // A job still unfinished G15_NUDGE_MS after its doorbell gets its
        // classes rung again (a job the firmware's scheduler skipped: boot #440,
        // mrt1, one in about 1900 runs, ring consumed, stamps unmoved).
        const G15_NUDGE_MS: i64 = 200;
        let mut nudge = [false; 3];
        let mut first_nudge = false;
        for p in self.g15_pending.lock().iter_mut() {
            if !p.signaled && p.nudge.elapsed() >= Delta::from_millis(G15_NUDGE_MS) {
                first_nudge |= p.nudges == 0;
                p.nudges += 1;
                p.nudge = Instant::<Monotonic>::now();
                if p.ta.is_some() {
                    nudge[0] = true;
                    nudge[1] = true;
                } else {
                    nudge[2] = true;
                }
            }
        }
        if first_nudge {
            // G15 lab: the trace up to the stall, before the nudges' passes overwrite it.
            self.g15_trace_dump(64);
        }
        for (class, bell) in nudge.iter().enumerate() {
            if *bell {
                self.g15_nudges.fetch_add(1, Ordering::Relaxed);
                let _ = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(class as u64));
            }
        }
        // A ring whose entries the firmware has not consumed RING_STALL_US
        // after the doorbell gets it again: a doorbell that comes while
        // the firmware's consumer is scanning the rings is absorbed, and
        // the entry written after the scan passed its ring waits for the
        // next doorbell (boots #416-#424: the last jobs of a burst hung).
        const RING_STALL_US: i64 = 1000;
        let mut bells = [false; 3];
        {
            let mut stall = self.g15_ring_stall.lock();
            for (class, since) in stall.iter_mut().enumerate() {
                if !self.g15_ring_unconsumed(fw::g15::ring(class)) {
                    *since = None;
                } else if since.get_or_insert_with(Instant::<Monotonic>::now).elapsed()
                    >= Delta::from_micros(RING_STALL_US)
                {
                    *since = Some(Instant::<Monotonic>::now());
                    bells[class] = true;
                }
            }
        }
        let busy = !self.g15_pending.lock().is_empty() || !self.g15_deferred.lock().is_empty();
        for (class, bell) in bells.iter().enumerate() {
            if *bell {
                self.g15_rerings.fetch_add(1, Ordering::Relaxed);
                mod_dev_dbg!(self.dev, "G15: ring {} holds unconsumed entries: re-ringing\n", fw::g15::ring(class));
                let _ = self.g15_send(EP_DOORBELL, MSG_TX_DOORBELL | fw::g15::bell(class as u64));
            }
        }
        busy
    }

    fn g15_set_kick(&self, kick: KBox<dyn Fn() + Send + Sync>) {
        *self.g15_kick.lock() = Some(kick);
    }

    fn get_cfg(&self) -> &'static hw::HwConfig {
        self.cfg
    }

    fn get_dyncfg(&self) -> &hw::DynConfig {
        &self.dyncfg
    }

    fn free_context(&self, ctx: KBox<fw::types::GpuObject<fw::workqueue::GpuContextData>>) {
        let mut garbage = self.garbage_contexts.lock();

        if garbage.push(ctx, GFP_KERNEL).is_err() {
            dev_err!(
                self.dev.as_ref(),
                "Failed to reserve space for freed context, deadlock possible.\n"
            );
        }
    }

    fn is_crashed(&self) -> bool {
        self.crashed.load(Ordering::Relaxed)
    }

    fn map_timestamp_buffer(
        &self,
        mut bo: gem::ObjectRef,
        range: Range<usize>,
    ) -> Result<mmu::KernelMapping> {
        bo.map_range_into_range(
            self.uat.kernel_vm(),
            range,
            IOVA_KERN_TIMESTAMP_RANGE,
            mmu::UAT_PGSZ as u64,
            mmu::PROT_FW_SHARED_RW,
            false,
        )
    }
}

#[versions(AGX)]
impl GpuManagerPriv for GpuManager::ver {
    fn end_op(&self) {
        #[ver(G != G15)]
        if true {
            let val = self
                .initdata
                .globals
                .with(|raw, _inner| raw.pending_submissions.fetch_sub(1, Ordering::Release));

            mod_dev_dbg!(self.dev, "OP end (pending: {})\n", val - 1);
        }

        #[ver(G == G15)]
        if true {
            let val = self
                .initdata
                .pb_table
                .with(|raw, _inner| raw.submit_in_progress.fetch_sub(1, Ordering::Release));
            mod_dev_dbg!(self.dev, "OP end (pending: {})\n", val - 1);
        }
    }
}
