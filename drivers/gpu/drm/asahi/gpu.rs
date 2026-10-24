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
        CondVar,
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

mod g15;
use g15::{g15_fwdump, G15UmaMem, G15_FWDUMP_CRASH, G15_UMA_DEVICE_BLOCKS};
pub(crate) use g15::{
    G15ClChannel, G15ClJob, G15Hold, G15RdCmd, G15RdGeom, G15RdQueue, G15RdZls, G15Rt, G15Uma,
    G15_UMA_POOLS,
};

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
/// G15: stop the firmware for a recovery; the low 44 bits are the stop
/// count, and a wrong count is ignored.
const MSG_HOST_STOP: u64 = 0x85 << 48;

/// Receive channel doorbell notification.
const MSG_RX_DOORBELL: u64 = 0x42 << 48;

/// Doorbell number for firmware kicks/wakeups.
#[allow(dead_code)] // M1/M2 only: G15 does not kick (start_op)
const DOORBELL_KICKFW: u64 = 0x10;
/// Doorbell number for device control channel kicks.
const DOORBELL_DEVCTRL: u64 = 0x11;

// G15 kernel VA ranges: region 1 of the GART (bit 42 set), 128 GiB above
// the region base, written sign-extended. The firmware's kernel window is
// the upper half (its own image sits at 0xffff_fc00_0000_0000), and it
// rebuilds the MSG_INIT address as 0xffff_f000_0000_0000 | VA[43:0], so the
// VAs it is given must be 0xffff_fcxx_xxxx_xxxx. The page-table walk only
// uses bits 41:0 and the region bit.
/// Private (cached) firmware structure VA range base. It ends where macOS's
/// eGART range 9 (the register windows) starts, below the timestamp range.
const IOVA_KERN_PRIV_RANGE: Range<u64> = 0xffff_fc20_0000_0000..0xffff_fc20_1000_0000;
/// Private (cached) GPU-RO firmware structure VA range base.
const IOVA_KERN_GPU_RO_RANGE: Range<u64> = 0xffff_fc26_0000_0000..0xffff_fc28_0000_0000;
/// Shared (uncached) firmware structure VA range base.
const IOVA_KERN_SHARED_RANGE: Range<u64> = 0xffff_fc28_0000_0000..0xffff_fc2a_0000_0000;
/// Shared (uncached) read-only firmware structure VA range base.
const IOVA_KERN_SHARED_RO_RANGE: Range<u64> = 0xffff_fc2a_0000_0000..0xffff_fc2c_0000_0000;
/// GPU/FW shared structure VA range base.
const IOVA_KERN_GPU_RANGE: Range<u64> = 0xffff_fc2c_0000_0000..0xffff_fc2d_0000_0000;
/// The render passes' GPU-written scratch (`KernelAllocators::rt`).
const IOVA_KERN_RT_RANGE: Range<u64> = 0xffff_fc2d_0000_0000..0xffff_fc2e_0000_0000;
/// GPU/FW shared structure VA range base.
const IOVA_KERN_RTKIT_RANGE: Range<u64> = 0xffff_fc2e_0000_0000..0xffff_fc2e_1000_0000;
/// The user timestamp buffers: macOS's eGART range 11, whose base HwDataB
/// publishes at +0x28. The firmware writes a user timestamp only to an
/// address in the 64 MiB from that base (`_AGFHALCommandBufferTimestampEnd`)
/// and drops the others.
pub(crate) const IOVA_KERN_TIMESTAMP_RANGE: Range<u64> =
    0xffff_fc20_1180_0000..0xffff_fc20_1580_0000;
/// The firmware-uncached stamp words (`KernelAllocators::stamp`).
const IOVA_KERN_STAMP_RANGE: Range<u64> = 0xffff_fc2e_1400_0000..0xffff_fc2e_1800_0000;
/// The firmware's non-cacheable buffers (`KernelAllocators::fw_nc`).
const IOVA_KERN_FW_NC_RANGE: Range<u64> = 0xffff_fc2e_1800_0000..0xffff_fc2e_2000_0000;
/// The GPU's tables, firmware non-cacheable (`KernelAllocators::gpu_fw_nc`).
const IOVA_KERN_GPU_FW_NC_RANGE: Range<u64> = 0xffff_fc2e_2000_0000..0xffff_fc2e_6000_0000;
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

/// Global allocators used for kernel-half structures.
pub(crate) struct KernelAllocators {
    pub(crate) private: alloc::DefaultAllocator,
    pub(crate) shared: alloc::DefaultAllocator,
    #[allow(dead_code)] // the M1/M2 init block only (build_impl)
    pub(crate) shared_ro: alloc::DefaultAllocator,
    #[allow(dead_code)]
    pub(crate) gpu: alloc::DefaultAllocator,
    /// The render passes' GPU-written scratch (G15: the tilemaps, the
    /// layer and heap metadata, the TPC and the cluster buffers), apart
    /// from the structures the firmware reads: the GPU writes past what it
    /// is given, and in `gpu` that zeroed parameter-buffer infos.
    pub(crate) rt: alloc::DefaultAllocator,
    pub(crate) gpu_ro: alloc::DefaultAllocator,
    /// Firmware-written words the host polls (the channels' stamp words),
    /// mapped firmware-uncached as macOS maps its host stamp array: through
    /// a cached mapping the firmware's writes reach memory late, after the
    /// completion event.
    pub(crate) stamp: alloc::DefaultAllocator,
    /// Buffers the firmware maps Normal non-cacheable, as macOS maps the
    /// event page, the firmware-to-host rings, the control blocks and the
    /// notifiers: the firmware's caches do not see the host's writes.
    pub(crate) fw_nc: alloc::DefaultAllocator,
    /// Hardware tables the GPU reads and writes back and the firmware edits
    /// without cache maintenance (the UMA pool and parameter-buffer
    /// descriptor tables), mapped firmware non-cacheable as macOS's
    /// `createHardwareMappings` does. Through a cached mapping the
    /// firmware's edits stay in its cache while the GPU works from memory.
    /// The compute channels' context stores, the parameter buffers' block
    /// controls and page metrics, and the UMA pool's metrics too.
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
    /// The G15 submission state.
    #[pin]
    g15: g15::G15State,
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
    /// Handles G15 GPU interrupt `index`: drains the firmware-to-host rings,
    /// as macOS's `AGXFirmware::handleEvent` does for indices 0 and 4.
    /// Returns the number of records and log messages drained.
    fn g15_irq(&self, index: u32) -> u64;
    /// Runs one pass of the G15 completion poller. Returns whether work is
    /// still pending, in which case the poller runs again.
    fn g15_poll(&self) -> bool;
    /// Sets the G15 completion poller's kick, which submissions run.
    fn g15_set_kick(&self, kick: KBox<dyn Fn() + Send + Sync>);
    /// Prints the performance counters (debugfs `asahi/perf`).
    fn perf_show(&self, f: &mut kernel::fmt::Formatter<'_>) -> kernel::fmt::Result;
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

/// A buffer the coprocessor preallocated in its own memory (its crash log
/// buffer, inside the firmware's data segment), memremapped.
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

        // The notification names no ring: drain all four firmware-to-host
        // rings, as macOS's handleEvent does.
        data.g15.notifies.fetch_add(1, Ordering::Relaxed);
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
        // Under the m1n1 hypervisor, dump the firmware and its crash log.
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
        // The coprocessor preallocates its crash log buffer inside its own
        // data segment and names it by physical address. RTKit decodes a
        // crash from it.
        // SAFETY: memremap() of a range the IOP owns; write-back like the
        // IOP's own view of its data segment.
        let vaddr = unsafe {
            kernel::bindings::memremap(iova as u64, size, kernel::bindings::MEMREMAP_WB as usize)
        };
        if vaddr.is_null() {
            dev_err!(
                data.dev.as_ref(),
                "RTKit: cannot map the IOP's buffer at {:#x}\n",
                iova
            );
            return Err(ENOMEM);
        }
        dev_info!(
            data.dev.as_ref(),
            "RTKit: the IOP's {:#x}-byte buffer at {:#x} mapped\n",
            size,
            iova
        );
        Ok(RtkitBuffer::Mapped(RtkitMapped {
            pa: iova,
            vaddr: vaddr.cast(),
            size,
        }))
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

        #[ver(G == G15)]
        Self::g15_setup_mmu(dev, res, &uat);

        let dyncfg = Self::make_dyncfg(dev, res, cfg, &uat)?;

        // On G15 the job buffers (`shared`, `gpu`, `rt`, and the job states
        // and streams in `fw_nc` and `gpu_fw_nc`) are not reused at once
        // (`G15_QUARANTINE_*`), each heap whose bit of `asahi.g15_quarantine`
        // is set.
        let g15 = matches!(cfg.gpu_gen, hw::GpuGen::G15);
        let quarantine =
            |bit: u32| g15 && *crate::module_parameters::g15_quarantine.value() & bit != 0;
        // With `asahi.g15_fw_nc` the firmware maps the job buffers Attr2
        // (inner non-cacheable), as macOS maps every kernel buffer outside its
        // block 1, and holds no line of them to write back late: whether
        // that is why macOS needs no quarantine is what it tests.
        let fw_nc = if g15 {
            *crate::module_parameters::g15_fw_nc.value()
        } else {
            0
        };

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
            if fw_nc >= 2 {
                mmu::PROT_FW_NC_RW
            } else {
                mmu::PROT_FW_SHARED_RW
            },
            1024 * 1024,
            true,
            fmt!("Kernel Shared"),
            quarantine(1),
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
            if fw_nc >= 1 {
                mmu::PROT_GPU_FW_NC_RW
            } else {
                mmu::PROT_GPU_FW_SHARED_RW
            },
            64 * 1024,
            true,
            fmt!("Kernel GPU Shared"),
            quarantine(2),
        )?;
        let rt = alloc::DefaultAllocator::new(
            dev,
            uat.kernel_vm(),
            IOVA_KERN_RT_RANGE,
            0x80,
            if fw_nc >= 1 {
                mmu::PROT_GPU_FW_NC_RW
            } else {
                mmu::PROT_GPU_FW_SHARED_RW
            },
            64 * 1024,
            true,
            fmt!("Kernel Render Scratch"),
            quarantine(4),
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
            quarantine(8),
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
            quarantine(16),
        )?;

        let mut alloc = KernelAllocators {
            private,
            shared,
            shared_ro,
            gpu,
            rt,
            gpu_ro,
            stamp,
            fw_nc,
            gpu_fw_nc,
        };

        let event_manager = Self::make_event_manager(&mut alloc)?;
        #[allow(unused_mut)] // only the M1/M2 path maps into it
        let mut initdata = Self::make_initdata(dev, cfg, &dyncfg, &mut alloc)?;

        // G15 has none of the M1/M2 runtime pointers: its init data is a
        // buffer set of its own.
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

        // The M1/M2 channels (fwctl, the tx/rx channels, the pipes) are
        // published in the runtime pointers. G15's rings are in its channel
        // table.
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

        for (i, map) in cfg.io_mappings.iter().enumerate() {
            if let Some(map) = map.as_ref() {
                Self::iomap(&mut mgr, cfg, i, map)?;
            }
        }

        Self::g15_map_windows(&mut mgr, cfg)?;

        // M1/M2: map the SGX SRAM into the kernel VM and publish it in
        // HwDataB. G15 has no such field: its ring area takes the role.
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

        // RTKit, through the DT's gfx-asc mailbox.
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
        let mut g15_uma = KVec::new();
        if matches!(cfg.gpu_gen, hw::GpuGen::G15) {
            for slot in 0..G15_UMA_POOLS {
                g15_uma.push(
                    {
                        let mem = G15UmaMem::new(&mut alloc.gpu, G15_UMA_DEVICE_BLOCKS)?;
                        Arc::new(G15Uma::new(&mut alloc, mem, slot)?, GFP_KERNEL)?
                    },
                    GFP_KERNEL,
                )?;
            }
        }

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
                g15 <- g15::G15State::new(g15_uma),
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
        let gpu_id = res.get_gpu_id()?;

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
            // G15 has no pending stamps here: its jobs fail through
            // `g15_recovery`.
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

        // G15 stops and resumes through its event ring (`g15_recovery`),
        // not through the M1/M2 timeout and fault paths that call this.
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
            // M1/M2's pending_submissions is the PB table's
            // submit-in-progress word.
            let val = self
                .initdata
                .pb_table
                .with(|raw, _inner| raw.submit_in_progress.fetch_add(1, Ordering::Acquire));
            mod_dev_dbg!(self.dev, "OP start (pending: {})\n", val + 1);
        }
        // No firmware kick on G15: the firmware answers its doorbell with
        // "AGFHALWaitForIdle is NOT Implemented for G15".
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

        // G15 has no GPU context object to destroy: its jobs carry their
        // context ID, and its device-control ring takes no DestroyContext.
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

        // The M1/M2 boot sequence.
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

        #[ver(G == G15)]
        self.g15_start()?;

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
            // G15 takes its idle-off settings in the PB table.
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

        // G15's device-control ring takes 0x38-byte entries, not M1/M2's
        // DestroyContext, which it never consumes: every flush would leave
        // an entry behind until the ring fills. No G15 equivalent of the
        // cache flush is known (nor verified to be needed), so the garbage
        // is collected without one.
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
            // G15 does not use the M1/M2 TVB grow messages.
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
        self.g15.irqs.fetch_add(1, Ordering::Relaxed);
        self.g15_drain_fw_rings()
    }

    fn g15_poll(&self) -> bool {
        let t = Instant::<Monotonic>::now();
        let busy = self.g15_poll_work();
        self.g15_polled(t.elapsed());
        busy
    }

    fn g15_set_kick(&self, kick: KBox<dyn Fn() + Send + Sync>) {
        *self.g15.kick.lock() = Some(kick);
    }

    fn perf_show(&self, f: &mut kernel::fmt::Formatter<'_>) -> kernel::fmt::Result {
        self.g15_perf_show(f)
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
        // G15: the firmware stores a stamp with no cache maintenance, and its
        // cached view is not coherent with the CPU's: a stamp left in its
        // cache reached the host seconds late, and an old line written back
        // could overwrite the host's reset of the query. The device type
        // (Attr2) keeps its stores out of its own cache.
        #[ver(G == G15)]
        let prot = mmu::PROT_FW_NC_RW;
        #[ver(G != G15)]
        let prot = mmu::PROT_FW_SHARED_RW;
        bo.map_range_into_range(
            self.uat.kernel_vm(),
            range,
            IOVA_KERN_TIMESTAMP_RANGE,
            mmu::UAT_PGSZ as u64,
            prot,
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
