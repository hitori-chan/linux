// SPDX-License-Identifier: GPL-2.0-only

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
    /// The pool state ("UMA Page Pool State"), in `lay`'s layout.
    pub(crate) state: fw::types::GpuArray<u8>,
    /// The state's layout, the firmware version's.
    lay: &'static G15UmaLayout,
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
/// A queue's render pool (`asahi.g15_uma_pools`) and a VM's compute pool:
/// 128 MiB, the low end of the shared pools macOS gives each client (its
/// compute pool for a stack-free kernel 128 to 160 MiB, uma-sizes.md).
pub(super) const G15_UMA_QUEUE_BLOCKS: usize = 4;
/// The render and compute pools held at once, those of gone queues included (4 GiB),
/// before a new VM waits for a gone queue's pool to go: a pool per queue
/// under dEQP-EGL at 8 jobs pinned 35 GB and ran the Mac out of memory
/// (r146).
pub(super) const G15_UMA_MAX_POOLS: usize = 32;
pub(super) const G15_UMA_BLOCK_PAGES: usize = 8192;
/// The page list's capacity, above any pool's pages.
pub(super) const G15_UMA_CAPACITY: usize = 0x10000;
/// The GPU's view of a VA: its low 43 bits (bit 42 selects the kernel half).
pub(super) const G15_GPU_VA_MASK: u64 = 0x7FF_FFFF_FFFF;

/// Where the pool state keeps the fields the driver writes past +0x2F (the
/// ID, slot, page list, capacity, head, tail, flag and free pages before it
/// keep their places).
///
/// 27.2 (`AGXUSCPrivMemFList::populateInitialFirmwareState` 0xfffffe0008bf97c4;
/// the firmware's kick gate `sub_FFFFFC000002BBF0`, register
/// `sub_FFFFFC000002B8B0` and retire `sub_FFFFFC000002BE84` against 14.8.3's
/// `AGFA_UMAPoolCanKick`, `AGFA_UMAPoolRegister` and `AGFA_UMAPoolRetire`;
/// the store counts in `sub_FFFFFC0000016B30` and `sub_FFFFFC0000016E58`, T)
/// puts the backup list at +0x30 and the reset state at +0x44, and the backup
/// entries, the submit count's address, the completion count, the shared flag
/// and the four store and stored-kick bytes four bytes on. The state grows to
/// 0x98 (the register's clean), with the new +0x40 (`chip+0x69c`, no firmware
/// reader found: 0, not verified) and the kick limit at +0x94.
pub(crate) struct G15UmaLayout {
    /// The state's size, which the firmware cleans and invalidates.
    size: usize,
    /// The backup list (u64), the reset state (0: none), the backup entries,
    /// the submit count's address (u64) and the completion count (u64).
    backup: usize,
    reset: usize,
    backup_n: usize,
    submits: usize,
    completions: usize,
    /// The shared flag, then the stores in flight and the stored kicks, four
    /// bytes.
    shared: usize,
    stores: usize,
    /// The kick limit (0: no such field).
    kicks: usize,
}

/// 14.8.3's pool state (`AGXUMAFList::populateFirmwareState`).
pub(crate) const G15_UMA_V14_7: G15UmaLayout = G15UmaLayout {
    size: 0x70,
    backup: 0x34,
    reset: 0x30,
    backup_n: 0x44,
    submits: 0x48,
    completions: 0x50,
    shared: 0x58,
    stores: 0x5C,
    kicks: 0,
};

/// 27.2's pool state.
pub(crate) const G15_UMA_V27_2: G15UmaLayout = G15UmaLayout {
    size: 0x98,
    backup: 0x30,
    reset: 0x44,
    backup_n: 0x48,
    submits: 0x4C,
    completions: 0x54,
    shared: 0x5C,
    stores: 0x60,
    kicks: 0x94,
};

impl core::fmt::Debug for G15Uma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("G15Uma").field("slot", &self.slot).finish()
    }
}

/// Writes the u64 at `p` the firmware reads: one access where it is 8-byte
/// aligned (14.8.3's offsets), else its halves, low first (27.2's +0x4C and
/// +0x54). The kernel's Rust target is strict-align, so an unaligned u64
/// access becomes byte accesses, and an unaligned volatile one is undefined.
///
/// # Safety
///
/// `p` is 4-byte aligned and valid for an 8-byte write.
unsafe fn w64(p: *mut u8, v: u64) {
    if (p as usize) % 8 == 0 {
        // SAFETY: an aligned u64, valid per the caller.
        unsafe { p.cast::<u64>().write_volatile(v) };
    } else {
        // SAFETY: two aligned u32s, valid per the caller.
        unsafe {
            p.cast::<u32>().write_volatile(v as u32);
            p.add(4).cast::<u32>().write_volatile((v >> 32) as u32);
        }
    }
}

/// Reads the u64 at `p` the firmware writes, as `w64` splits it: an unaligned
/// one by halves, the high half again until it agrees, which a count that
/// only grows cannot fool.
///
/// # Safety
///
/// `p` is 4-byte aligned and valid for an 8-byte read.
unsafe fn r64(p: *const u8) -> u64 {
    if (p as usize) % 8 == 0 {
        // SAFETY: an aligned u64, valid per the caller.
        return unsafe { p.cast::<u64>().read_volatile() };
    }
    loop {
        // SAFETY: two aligned u32s, valid per the caller.
        let (hi, lo, again) = unsafe {
            (
                p.add(4).cast::<u32>().read_volatile(),
                p.cast::<u32>().read_volatile(),
                p.add(4).cast::<u32>().read_volatile(),
            )
        };
        if hi == again {
            return (u64::from(hi) << 32) | u64::from(lo);
        }
    }
}

impl G15Uma {
    /// Sets up a pool at descriptor-table `slot` over `mem`, its state,
    /// submit count and metrics in the kernel's allocators. `shared`: a
    /// client's compute pool, which its compute channels share.
    pub(crate) fn new(
        alloc: &mut KernelAllocators,
        mem: G15UmaMem,
        slot: u32,
        shared: bool,
        lay: &'static G15UmaLayout,
    ) -> Result<G15Uma> {
        let metrics = alloc.gpu_fw_nc.array_empty_tagged::<u8>(0x4000, b"UMAX")?;
        let state = alloc.shared.array_empty_tagged::<u8>(lay.size, b"UMAS")?;
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
            s.add(lay.backup).cast::<u64>().write_unaligned(backup_gva); // backup list
            s.add(lay.backup_n)
                .cast::<u32>()
                .write_volatile(8 * mem.blocks.len() as u32); // backup entries
            w64(s.add(lay.submits), submits.gpu_va().get()); // -> submit count
            w64(s.add(lay.completions), 0); // completion count

            // +0x58 (27.2 +0x5C) "shared and compute", as macOS marks each
            // client's compute pool (AGXUMAFList::populateFirmwareState).
            // The firmware then counts the pool's context stores in flight
            // (+0x5C, 27.2 +0x60, AGFA_CtxStoreRequest), the stored kicks
            // that hold pages (the next three bytes, AGFA_UMAPoolKickStats),
            // and holds a fresh kick on the pool until those are picked again
            // (AGFA_UMAPoolCanKick). On an unmarked pool a stage-2 store
            // stopped the GPU within 2 s of a second client's work.
            s.add(lay.shared)
                .cast::<u32>()
                .write_volatile(u32::from(shared));
            // 27.2's kick limit: 1, the kext's value for an unshared pool. A
            // shared one's is `getUMAMaxActiveCDMKicksPerMGPU`'s (1 to 3, by
            // a field not decoded); no firmware reader was found, so 1 (not
            // verified).
            if lay.kicks != 0 {
                s.add(lay.kicks).cast::<u32>().write_volatile(1);
            }
        }
        crate::mem::dc_civac(mem.backup.raw_ptr().cast_const(), mem.blocks.len() * 0x40);
        crate::mem::dc_civac(state.raw_ptr().cast_const(), lay.size);
        crate::mem::dc_civac(submits.raw_ptr().cast_const(), 8);
        Ok(G15Uma {
            slot,
            mem,
            state,
            lay,
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
            let lay = self.lay;
            s.add(0x20).cast::<u32>().write_volatile(0); // head
            s.add(0x24)
                .cast::<u32>()
                .write_volatile((n % G15_UMA_CAPACITY) as u32); // tail
            s.add(0x28).cast::<u32>().write_volatile(0); // flag
            s.add(0x2C).cast::<u32>().write_volatile(n as u32); // free pages
            s.add(lay.reset).cast::<u32>().write_volatile(0); // no reset pending
            w64(s.add(lay.completions), 0); // completion count

            // A shared pool's store and stored-kick counts: the restart
            // forgot those kicks.
            s.add(lay.stores).cast::<u32>().write_volatile(0);
            self.submits.raw_ptr().cast::<u64>().write_volatile(0);
        }
        crate::mem::dc_civac(self.state.raw_ptr().cast_const(), self.lay.size);
        crate::mem::dc_civac(self.submits.raw_ptr().cast_const(), 8);
    }

    /// Whether the firmware has completed every job submitted on the pool:
    /// its completion count (state +0x50, 27.2 +0x54) has reached the submit
    /// count.
    pub(super) fn idle(&self) -> bool {
        let s = self.state.raw_ptr();
        crate::mem::dc_civac(s.cast_const(), self.lay.size);
        crate::mem::dc_civac(self.submits.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds u64 reads of the state and the submit count.
        unsafe {
            r64(s.add(self.lay.completions))
                == (self.submits.raw_ptr() as *const u64).read_volatile()
        }
    }

    /// Zeroes the next job's metrics slot and returns its GPU VA.
    pub(super) fn metrics_slot(&self) -> u64 {
        let off = self.metrics_next.fetch_add(0x40, Ordering::Relaxed) % 0x4000;
        let slot = self.metrics.raw_ptr().wrapping_add(off as usize);
        // SAFETY: a 0x40-byte slot within the metrics buffer.
        unsafe { core::ptr::write_bytes(slot, 0, 0x40) };
        // `gpu_fw_nc`: the firmware and the GPU read memory, not this CPU's
        // cache (`AGFA_UMAPoolKickStats` reads +0x08).
        crate::mem::dc_civac(slot.cast_const(), 0x40);
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
        crate::mem::dc_civac(s.cast_const(), self.lay.size);
        crate::mem::dc_civac(t.cast_const(), 0x20);
        crate::mem::dc_civac(self.submits.raw_ptr().cast_const(), 8);
        // SAFETY: in-bounds reads of the `lay.size`-byte state, the 8-byte
        // submit count and the slot's 0x20-byte table entry.
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
                r32(self.lay.reset),
                r64(s.add(self.lay.completions)),
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

/// A render pool, the VM it is in, its queues, and since when it has had
/// none.
pub(super) struct G15UmaEntry {
    uma: Arc<G15Uma>,
    vm: Arc<Mutex<alloc::DefaultAllocator>>,
    users: u32,
    gone: Option<Instant<Monotonic>>,
    /// The VM's compute pool, apart from its render pool.
    cl: bool,
}

#[versions(AGX)]
impl GpuManager::ver {
    /// A queue's render pool, which its TA and 3D jobs share, in its VM
    /// (`vm`, the VM's allocator), or with `cl` its compute pool. With
    /// `asahi.g15_uma_pools=1` the queue gets its own render pool; with 2
    /// the queues of a VM share one, as macOS gives each client a render
    /// pool apart from its compute one. A VM's compute queues share its
    /// compute pool, marked shared (`G15Uma::new`), as macOS's
    /// (`AGXUMASharedPoolContainer`). With 0, or no memory or slot left,
    /// None: its jobs take the device's pools.
    ///
    /// No other client's jobs may share the pool: the device's 3D pool lists
    /// pages twice under load, and two jobs handed one page share their
    /// imageblock and stack storage, so one process's tile words and stack
    /// land in another's (uma.md). With `G15_UMA_MAX_POOLS` held, the queue
    /// waits for a gone queue's pool to be freed, and goes past the bound
    /// when no queue has gone or the wait outlasts the pools' hold.
    pub(crate) fn g15_uma_queue(
        &self,
        vm: &Arc<Mutex<alloc::DefaultAllocator>>,
        cl: bool,
    ) -> Option<Arc<G15Uma>> {
        let mode = match crate::module_parameters::g15_uma_pools.value() {
            m if cl && m != 0 => 2,
            m => m,
        };
        if mode == 0 {
            return None;
        }
        let mut pools = self.g15.uma_pools.lock();
        Self::g15_uma_sweep(&mut pools);
        if mode == 2 {
            if let Some(e) = pools
                .iter_mut()
                .find(|e| Arc::ptr_eq(&e.vm, vm) && e.cl == cl)
            {
                e.users += 1;
                e.gone = None;
                return Some(e.uma.clone());
            }
        }
        let mut waited = 0;
        while pools.len() >= G15_UMA_MAX_POOLS
            && pools.iter().any(|e| e.gone.is_some())
            && waited < 2 * G15_DEAD_MS
        {
            drop(pools);
            kernel::time::delay::fsleep(Delta::from_millis(10));
            waited += 10;
            pools = self.g15.uma_pools.lock();
            Self::g15_uma_sweep(&mut pools);
        }
        let slot = (G15_UMA_POOLS..256u32).find(|s| !pools.iter().any(|e| e.uma.slot == *s))?;
        pools.reserve(1, GFP_KERNEL).ok()?;
        // One allocator lock at a time.
        let mem = G15UmaMem::new(&mut vm.lock(), G15_UMA_QUEUE_BLOCKS);
        #[ver(V < V27_2)]
        let uma_lay = &G15_UMA_V14_7;
        #[ver(V >= V27_2)]
        let uma_lay = &G15_UMA_V27_2;
        let made = mem
            .and_then(|mem| G15Uma::new(&mut self.alloc.lock(), mem, slot, cl, uma_lay))
            .and_then(|u| Ok(Arc::new(u, GFP_KERNEL)?));
        match made {
            Ok(u) => {
                let e = G15UmaEntry {
                    uma: u.clone(),
                    vm: vm.clone(),
                    users: 1,
                    gone: None,
                    cl,
                };
                pools.push(e, GFP_KERNEL).ok()?;
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

    /// Lets a queue's pool go with its queue. A pool with no queue left is
    /// freed, by the next queue's setup or the poller, once the firmware has
    /// completed its every job and `G15_DEAD_MS` more have passed: the pool's retire
    /// (`AGFA_UMAPoolRetire`, which flushes its slot and writes the state)
    /// runs in the post-processing after the completion.
    /// The device's pool stays.
    pub(crate) fn g15_uma_put(&self, uma: &Arc<G15Uma>) {
        let mut pools = self.g15.uma_pools.lock();
        if let Some(e) = pools.iter_mut().find(|e| Arc::ptr_eq(&e.uma, uma)) {
            e.users -= 1;
            if e.users == 0 {
                e.gone = Some(Instant::<Monotonic>::now());
            }
        }
        Self::g15_uma_sweep(&mut pools);
        drop(pools);
        // The poller frees the pool once it may go (`g15_uma_reap`).
        self.g15_kick(false);
    }

    /// Frees the pools whose queues have gone (`g15_uma_put`), from the
    /// poller, as a gone queue may be the last; returns whether any still
    /// waits, which keeps the poller running.
    pub(super) fn g15_uma_reap(&self) -> bool {
        let mut pools = self.g15.uma_pools.lock();
        Self::g15_uma_sweep(&mut pools);
        pools.iter().any(|e| e.gone.is_some())
    }

    fn g15_uma_sweep(pools: &mut KVec<G15UmaEntry>) {
        pools.retain(|e| {
            !e.gone
                .is_some_and(|t| t.elapsed() >= Delta::from_millis(G15_DEAD_MS) && e.uma.idle())
        });
    }

    /// The queues' pools held: render, compute, those of gone queues among
    /// them, and their pages of 4 KiB.
    pub(super) fn g15_uma_held(&self) -> (usize, usize, usize, usize) {
        let pools = self.g15.uma_pools.lock();
        let cl = pools.iter().filter(|e| e.cl).count();
        let gone = pools.iter().filter(|e| e.gone.is_some()).count();
        let pages = pools.iter().map(|e| e.uma.mem.n_pages()).sum();
        (pools.len() - cl, cl, gone, pages)
    }

    /// Runs `f` on the device's pools and every queue's.
    pub(super) fn g15_uma_each(&self, mut f: impl FnMut(&G15Uma)) {
        for uma in self.g15.uma.iter() {
            f(uma);
        }
        for e in self.g15.uma_pools.lock().iter() {
            f(&e.uma);
        }
    }
}
