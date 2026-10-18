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
//! - [`uma`]: the UMA page pool every job registers.

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

pub(crate) use self::{
    channel::G15ClChannel,
    completion::G15ClPending,
    compute::G15ClJob,
    debug::{g15_fwdump, G15_FWDUMP_CRASH},
    pb::G15PbState,
    render::{G15RdChans, G15RdCmd, G15RdGeom, G15RdQueue, G15RdZls},
    rt::G15Rt,
    selftest::G15RenderTest,
    uma::G15Uma,
};

use super::*;

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

/// How long a submission waits for room in a ring or in a channel's record
/// slots before it fails.
const G15_RING_WAIT_MS: i64 = 2000;

/// How long a submission that meets a firmware stop waits for the resume
/// before it fails.
const G15_RESUME_WAIT_MS: i64 = 5000;

/// How long after the firmware stamp word a job whose host stamp word stays
/// behind completes anyway.
const G15_HOST_STAMP_MS: i64 = 5;

/// The `isHWSoftFaultEnabled` word of the job streams: 1 when userspace is
/// told that soft faults are on, so that it may load from unmapped pages on
/// purpose.
fn g15_soft_faults() -> u32 {
    u32::from(crate::module_parameters::fault_control.value() == 0xb)
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

    /// G15: the UMA pool for a new job. A pool the firmware marked for a
    /// reset at a recovery (+0x30 = 1) keeps it, as with the kext: the
    /// pool's next kick rebuilds it from its backup list, and a recovery
    /// that interrupts a reset marks it again (spec: uma.md, "The reset
    /// after a recovery").
    pub(super) fn g15_uma_get(&self) -> Result<Arc<G15Uma>> {
        self.g15_uma.clone().ok_or(EINVAL)
    }

    /// G15: send a mailbox message through RTKit.
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
