// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 UMA page pools.
//!
//! Spec: uma.md.

use super::*;

/// A UMA page pool. The GPU's page manager (gUPM) backs a launch's dynamic
/// on-chip storage with its pages. Every job registers its pool at the
/// pool's descriptor-table slot: its data master's, or its queue's render
/// pool; the firmware keys a pool by its state and slot, not by channel.
pub(crate) struct G15Uma {
    /// The descriptor-table slot (0..255); the pool ID is slot + 1.
    pub(crate) slot: u32,
    /// The pool memory, page list and backup list.
    pub(super) mem: G15UmaMem,
    /// The 0x70-byte pool state ("UMA Page Pool State").
    pub(crate) state: fw::types::GpuArray<u8>,
    /// The u64 submit count: one more per job before its doorbell. The
    /// firmware flushes the slot when its completion count catches up.
    pub(super) submits: fw::types::GpuArray<u8>,
    /// The metrics buffer: one 0x40-byte slot per job, where the GPU writes
    /// the kick's peak page use (register 0x14070), mapped firmware
    /// non-cacheable as `AGXUMAHWMetrics::init` maps it.
    pub(super) metrics: fw::types::GpuArray<u8>,
    /// The next metrics slot (a byte offset, modulo 0x4000).
    pub(super) metrics_next: AtomicU32,
}

/// The data masters with a pool of their own; the index is the pool's
/// descriptor-table slot. macOS gives the TA and 3D channels pools apart
/// from the compute one. A 3D job on the pool every job shared listed pages
/// twice, which put two compute threads' stacks on one page (uma.md, pages
/// listed twice).
#[derive(Clone, Copy)]
pub(crate) enum G15UmaDm {
    /// Compute.
    Cl = 0,
    /// The TA (vertex) stage.
    Ta = 1,
    /// The 3D (fragment) stage.
    D3 = 2,
}

/// The pools: one per `G15UmaDm`.
pub(crate) const G15_UMA_POOLS: u32 = 3;

/// The GPU-read part of a pool: its blocks, the page list and the backup
/// list, in the address space of the jobs that use it (the kernel half for
/// the device's pool, the queue's VM for a queue's, as macOS maps a client's
/// pool in the client's).
pub(crate) struct G15UmaMem {
    /// The blocks of 8192 pages of 4 KiB, GPU read-write.
    blocks: KVec<fw::types::GpuArray<u8>>,
    /// The page list: a ring of `G15_UMA_CAPACITY` u64 page addresses.
    pages: fw::types::GpuArray<u8>,
    /// The backup range list (eight 8-byte entries per block), for a pool
    /// reset.
    backup: fw::types::GpuArray<u8>,
}

impl G15UmaMem {
    /// Allocates `blocks` blocks and the two lists from `a`.
    pub(crate) fn new(a: &mut alloc::DefaultAllocator, blocks: usize) -> Result<G15UmaMem> {
        let mut mem = KVec::new();
        for _ in 0..blocks {
            mem.push(
                a.array_empty_tagged::<u8>(G15_UMA_BLOCK_PAGES * 0x1000, b"UMAM")?,
                GFP_KERNEL,
            )?;
        }
        Ok(G15UmaMem {
            blocks: mem,
            pages: a.array_empty_tagged::<u8>(G15_UMA_CAPACITY * 8, b"UMAL")?,
            backup: a.array_empty_tagged::<u8>(blocks * 0x40, b"UMAB")?,
        })
    }

    /// The pool's pages.
    fn n_pages(&self) -> usize {
        self.blocks.len() * G15_UMA_BLOCK_PAGES
    }

    /// Writes page i at entry i of the page list
    /// (AGXUMAFList::populatePagePool), the rest of the ring 0, and cleans
    /// it from the CPU's cache.
    fn fill(&self) {
        let l = self.pages.raw_ptr().cast::<u64>();
        for (k, blk) in self.blocks.iter().enumerate() {
            let base = blk.gpu_va().get() & G15_GPU_VA_MASK;
            for j in 0..G15_UMA_BLOCK_PAGES {
                // SAFETY: entry k * 8192 + j < the pool's pages <=
                // G15_UMA_CAPACITY, within the page list.
                unsafe {
                    l.add(k * G15_UMA_BLOCK_PAGES + j)
                        .write_volatile(base + (j as u64) * 0x1000)
                };
            }
        }
        crate::mem::dc_civac(self.pages.raw_ptr().cast_const(), self.n_pages() * 8);
    }
}

/// A device pool's blocks of 8192 pages (32 MiB). Metal's minimum for a
/// compute pass on this chip is 14952 pages, and macOS's private pool for
/// it is 64 MiB.
pub(crate) const G15_UMA_DEVICE_BLOCKS: usize = 5;
/// A queue's render pool (`asahi.g15_uma_pools`): 128 MiB, the low end of
/// the shared pools macOS gives each client.
pub(super) const G15_UMA_QUEUE_BLOCKS: usize = 4;
pub(super) const G15_UMA_BLOCK_PAGES: usize = 8192;
/// The page list's capacity, above any pool's pages.
pub(super) const G15_UMA_CAPACITY: usize = 0x10000;
/// The GPU's view of a VA: its low 43 bits (bit 42 selects the kernel half).
pub(super) const G15_GPU_VA_MASK: u64 = 0x7FF_FFFF_FFFF;

impl core::fmt::Debug for G15Uma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("G15Uma").field("slot", &self.slot).finish()
    }
}

impl G15Uma {
    /// Sets up a pool at descriptor-table `slot` over `mem`, its state,
    /// submit count and metrics in the kernel's allocators.
    pub(crate) fn new(alloc: &mut KernelAllocators, mem: G15UmaMem, slot: u32) -> Result<G15Uma> {
        let metrics = alloc.gpu_fw_nc.array_empty_tagged::<u8>(0x4000, b"UMAX")?;
        let state = alloc.shared.array_empty_tagged::<u8>(0x70, b"UMAS")?;
        let submits = alloc.stamp.array_empty_tagged::<u8>(8, b"UMAC")?;
        let pages_gva = mem.pages.gpu_va().get() & G15_GPU_VA_MASK;
        let backup_gva = mem.backup.gpu_va().get() & G15_GPU_VA_MASK;
        let n = mem.n_pages();
        mem.fill();
        // SAFETY: in-bounds stores into the pool's own freshly allocated
        // (zeroed) buffers.
        unsafe {
            // The backup ranges: bits 47:12 the page address, 63:52 the page
            // count. A block takes three, then five zero entries.
            let b = mem.backup.raw_ptr().cast::<u64>();
            for (k, blk) in mem.blocks.iter().enumerate() {
                let base = blk.gpu_va().get() & G15_GPU_VA_MASK;
                b.add(k * 8).write_volatile(base | 0xFFF << 52);
                b.add(k * 8 + 1)
                    .write_volatile((base + 0xFFF000) | 0xFFF << 52);
                b.add(k * 8 + 2)
                    .write_volatile((base + 0x1FFE000) | 2 << 52);
            }
            // The pool state (AGXUMAFList::populateFirmwareState).
            let s = state.raw_ptr();
            s.cast::<u64>().write_volatile(u64::from(slot) + 1); // +0x00 pool ID
            s.add(0x08).cast::<u32>().write_volatile(slot); // +0x08 table slot
            s.add(0x14).cast::<u64>().write_unaligned(pages_gva); // page list
            s.add(0x1C)
                .cast::<u32>()
                .write_volatile(G15_UMA_CAPACITY as u32);
            s.add(0x20).cast::<u32>().write_volatile(0); // head
            s.add(0x24)
                .cast::<u32>()
                .write_volatile((n % G15_UMA_CAPACITY) as u32); // tail
            s.add(0x2C).cast::<u32>().write_volatile(n as u32); // free pages
            s.add(0x34).cast::<u64>().write_unaligned(backup_gva); // backup list
            s.add(0x44)
                .cast::<u32>()
                .write_volatile(8 * mem.blocks.len() as u32); // backup entries
            s.add(0x48)
                .cast::<u64>()
                .write_volatile(submits.gpu_va().get()); // -> submit count
            s.add(0x50).cast::<u64>().write_volatile(0); // completion count
        }
        crate::mem::dc_civac(mem.backup.raw_ptr().cast_const(), mem.blocks.len() * 0x40);
        crate::mem::dc_civac(state.raw_ptr().cast_const(), 0x70);
        crate::mem::dc_civac(submits.raw_ptr().cast_const(), 8);
        Ok(G15Uma {
            slot,
            mem,
            state,
            submits,
            metrics,
            metrics_next: AtomicU32::new(0),
        })
    }

    /// Fills the pool again after a host stop, as the kext's
    /// `AGXUMAFList::resetPagePoolState` and the next `populatePagePool` and
    /// `populateFirmwareState` do: every page back in the list, the head,
    /// tail and free count as at creation, no reset pending, and the submit
    /// and completion counts at 0. The firmware's restart forgets every
    /// pool's slot registration, so the next kick on the pool loads its
    /// table entry from this state.
    pub(super) fn reset(&self) {
        let n = self.mem.n_pages();
        self.mem.fill();
        // SAFETY: in-bounds stores into the pool's own state and submit
        // count, with the firmware stopped.
        unsafe {
            let s = self.state.raw_ptr();
            s.add(0x20).cast::<u32>().write_volatile(0); // head
            s.add(0x24)
                .cast::<u32>()
                .write_volatile((n % G15_UMA_CAPACITY) as u32); // tail
            s.add(0x28).cast::<u32>().write_volatile(0); // flag
            s.add(0x2C).cast::<u32>().write_volatile(n as u32); // free pages
            s.add(0x30).cast::<u32>().write_volatile(0); // no reset pending
            s.add(0x50).cast::<u64>().write_volatile(0); // completion count
            self.submits.raw_ptr().cast::<u64>().write_volatile(0);
        }
        crate::mem::dc_civac(self.state.raw_ptr().cast_const(), 0x70);
        crate::mem::dc_civac(self.submits.raw_ptr().cast_const(), 8);
    }

    /// Whether the firmware has completed every job submitted on the pool:
    /// its completion count (state +0x50) has reached the submit count.
    pub(super) fn idle(&self) -> bool {
        let s = self.state.raw_ptr();
        crate::mem::dc_civac(s.cast_const(), 0x70);
        crate::mem::dc_civac(self.submits.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds u64 reads of the state and the submit count.
        unsafe {
            (s.add(0x50) as *const u64).read_volatile()
                == (self.submits.raw_ptr() as *const u64).read_volatile()
        }
    }

    /// Zeroes the next job's metrics slot and returns its GPU VA.
    pub(super) fn metrics_slot(&self) -> u64 {
        let off = self.metrics_next.fetch_add(0x40, Ordering::Relaxed) % 0x4000;
        // SAFETY: a 0x40-byte slot within the metrics buffer.
        unsafe {
            core::ptr::write_bytes(self.metrics.raw_ptr().add(off as usize), 0, 0x40);
        }
        self.metrics.gpu_va().get() + u64::from(off)
    }

    /// Logs the pool state the firmware and the GPU keep (head, tail, flag,
    /// free pages, reset state, completions), the host's submit count and
    /// the pool's descriptor-table entry.
    pub(super) fn log(
        &self,
        dev: &kernel::device::Device,
        table: &fw::types::GpuArray<u8>,
        tag: &str,
    ) {
        let s = self.state.raw_ptr();
        let t = table.raw_ptr().wrapping_add(self.slot as usize * 0x20);
        crate::mem::dc_civac(s.cast_const(), 0x70);
        crate::mem::dc_civac(t.cast_const(), 0x20);
        crate::mem::dc_civac(self.submits.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds reads of the 0x70-byte state, the 8-byte submit
        // count and the slot's 0x20-byte table entry.
        unsafe {
            let r32 = |off: usize| (s.add(off) as *const u32).read_volatile();
            let e = |i: usize| (t.add(i * 8) as *const u64).read_volatile();
            dev_err!(
                dev,
                "G15: UMA pool {} (slot {}) {}: head {:#x} tail {:#x} flag {:#x} free {:#x} reset {} completions {} submits {}; table {:#x} {:#x} {:#x}\n",
                self.slot + 1,
                self.slot,
                tag,
                r32(0x20),
                r32(0x24),
                r32(0x28),
                r32(0x2C),
                r32(0x30),
                (s.add(0x50) as *const u64).read_volatile(),
                (self.submits.raw_ptr() as *const u64).read_volatile(),
                e(0),
                e(1),
                e(2)
            );
        }
    }

    /// Counts one more job, before its doorbell
    /// (AGXUMAFList::updateSubmitInfo).
    pub(super) fn count_submit(&self) {
        let p = self.submits.raw_ptr();
        // SAFETY: the 8-byte aligned u64 submit count, which only the host
        // writes.
        unsafe { (*(p as *const AtomicU64)).fetch_add(1, Ordering::AcqRel) };
        crate::mem::dc_civac(p.cast_const(), 8);
    }
}

/// A queue's pool and since when its queue is gone.
pub(super) type G15UmaEntry = (Arc<G15Uma>, Option<Instant<Monotonic>>);

#[versions(AGX)]
impl GpuManager::ver {
    /// A queue's render pool, which its TA and 3D jobs share. With
    /// `asahi.g15_uma_pools=1` the queue gets its own, in its VM (`vm`, the
    /// VM's allocator), as macOS gives each client a render pool apart from
    /// its compute one; else, or with no table slot or memory left, None:
    /// its jobs take the device's TA and 3D pools.
    pub(crate) fn g15_uma_queue(
        &self,
        vm: &Arc<Mutex<alloc::DefaultAllocator>>,
    ) -> Option<Arc<G15Uma>> {
        if *crate::module_parameters::g15_uma_pools.value() == 0 {
            return None;
        }
        let mut pools = self.g15.uma_pools.lock();
        Self::g15_uma_sweep(&mut pools);
        let slot =
            (G15_UMA_POOLS..256u32).find(|s| !pools.iter().any(|(p, _)| p.slot == *s))?;
        pools.reserve(1, GFP_KERNEL).ok()?;
        // One allocator lock at a time.
        let mem = G15UmaMem::new(&mut vm.lock(), G15_UMA_QUEUE_BLOCKS);
        let made = mem
            .and_then(|mem| G15Uma::new(&mut self.alloc.lock(), mem, slot))
            .and_then(|u| Ok(Arc::new(u, GFP_KERNEL)?));
        match made {
            Ok(u) => {
                pools.push((u.clone(), None), GFP_KERNEL).ok()?;
                Some(u)
            }
            Err(e) => {
                dev_warn!(
                    self.dev.as_ref(),
                    "G15: no UMA pool for a queue ({e:?}): it uses the device's\n"
                );
                None
            }
        }
    }

    /// Lets a queue's pool go with its queue. It is freed once the firmware
    /// has completed its every job and `G15_DEAD_MS` more have passed: the
    /// pool's retire (`AGFA_UMAPoolRetire`, which flushes its slot and
    /// writes the state) runs in the post-processing after the completion.
    /// The device's pool stays.
    pub(crate) fn g15_uma_put(&self, uma: &Arc<G15Uma>) {
        let mut pools = self.g15.uma_pools.lock();
        if let Some(e) = pools.iter_mut().find(|(p, _)| Arc::ptr_eq(p, uma)) {
            e.1 = Some(Instant::<Monotonic>::now());
        }
        Self::g15_uma_sweep(&mut pools);
    }

    fn g15_uma_sweep(pools: &mut KVec<G15UmaEntry>) {
        pools.retain(|(p, gone)| {
            !gone.is_some_and(|t| t.elapsed() >= Delta::from_millis(G15_DEAD_MS) && p.idle())
        });
    }

    /// Runs `f` on the device's pools and every queue's.
    pub(super) fn g15_uma_each(&self, mut f: impl FnMut(&G15Uma)) {
        for uma in self.g15.uma.iter() {
            f(uma);
        }
        for (p, _) in self.g15.uma_pools.lock().iter() {
            f(p);
        }
    }
}
