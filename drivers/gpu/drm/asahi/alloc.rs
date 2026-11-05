// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! GPU kernel object allocator.
//!
//! This kernel driver needs to manage a large number of GPU objects, in both firmware/kernel
//! address space and user address space. This module implements a simple grow-only heap allocator
//! based on the DRM MM range allocator, and a debug allocator that allocates each object as a
//! separate GEM object.
//!
//! Allocations may optionally have debugging enabled, which adds preambles that store metadata
//! about the allocation. This is useful for live debugging using the hypervisor or postmortem
//! debugging with a GPU memory snapshot, since it makes it easier to identify use-after-free and
//! caching issues.

use kernel::{
    drm::mm,
    error::Result,
    io::Io,
    prelude::*,
    str::CString, //
};

use crate::debug::*;
use crate::driver::{
    AsahiDevRef,
    AsahiDevice,
    AsahiDrmDevice, //
};
use crate::fw::types::Zeroable;
use crate::mmu;
use crate::object::{
    GpuArray,
    GpuObject,
    GpuOnlyArray,
    GpuStruct,
    GpuWeakPointer, //
};
use crate::util::RangeExt;

use core::cmp::Ordering;
use core::fmt;
use core::fmt::{
    Debug,
    Formatter, //
};
use core::marker::PhantomData;
use core::mem;
use core::ops::Range;
use core::ptr::NonNull;

const DEBUG_CLASS: DebugFlags = DebugFlags::Alloc;

#[cfg(not(CONFIG_DRM_ASAHI_DEBUG_ALLOCATOR))]
/// The driver-global allocator type
pub(crate) type DefaultAllocator = HeapAllocator;

#[cfg(not(CONFIG_DRM_ASAHI_DEBUG_ALLOCATOR))]
/// The driver-global allocation type
pub(crate) type DefaultAllocation = HeapAllocation;

#[cfg(CONFIG_DRM_ASAHI_DEBUG_ALLOCATOR)]
/// The driver-global allocator type
pub(crate) type DefaultAllocator = SimpleAllocator;

#[cfg(CONFIG_DRM_ASAHI_DEBUG_ALLOCATOR)]
/// The driver-global allocation type
pub(crate) type DefaultAllocation = SimpleAllocation;

/// Represents a raw allocation (without any type information).
pub(crate) trait RawAllocation {
    /// Returns the CPU-side pointer (if CPU mapping is enabled) as a byte non-null pointer.
    fn ptr(&self) -> Option<NonNull<u8>>;
    /// Returns the GPU VA pointer as a u64.
    fn gpu_ptr(&self) -> u64;
    /// Returns the AsahiDevice that owns this allocation.
    fn device(&self) -> &AsahiDevice;
}

/// Represents a typed allocation.
pub(crate) trait Allocation<T>: Debug {
    /// Returns the typed CPU-side pointer (if CPU mapping is enabled).
    fn ptr(&self) -> Option<NonNull<T>>;
    /// Returns the GPU VA pointer as a u64.
    fn gpu_ptr(&self) -> u64;
    /// Returns the size of the allocation in bytes.
    fn size(&self) -> usize;
    /// Returns the AsahiDevice that owns this allocation.
    fn device(&self) -> &AsahiDevice;
}

/// A generic typed allocation wrapping a RawAllocation.
///
/// This is currently the only Allocation implementation, since it is shared by all allocators.
///
/// # Invariants
/// The alloaction at `alloc` must have a size equal or greater than `alloc_size` plus `debug_offset` plus `padding`.
pub(crate) struct GenericAlloc<T, U: RawAllocation> {
    alloc: U,
    alloc_size: usize,
    debug_offset: usize,
    padding: usize,
    tag: u32,
    pad_word: u32,
    _p: PhantomData<T>,
}

impl<T, U: RawAllocation> Allocation<T> for GenericAlloc<T, U> {
    /// Returns a pointer to the inner (usable) part of the allocation.
    fn ptr(&self) -> Option<NonNull<T>> {
        // SAFETY: self.debug_offset is always within the allocation per the invariant, so is safe to add
        // to the base pointer.
        unsafe { self.alloc.ptr().map(|p| p.add(self.debug_offset).cast()) }
    }
    /// Returns the GPU pointer to the inner (usable) part of the allocation.
    fn gpu_ptr(&self) -> u64 {
        self.alloc.gpu_ptr() + self.debug_offset as u64
    }
    /// Returns the size of the inner (usable) part of the allocation.
    fn size(&self) -> usize {
        self.alloc_size
    }
    fn device(&self) -> &AsahiDevice {
        self.alloc.device()
    }
}

impl<T, U: RawAllocation> Debug for GenericAlloc<T, U> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct(core::any::type_name::<GenericAlloc<T, U>>())
            .field("ptr", &format_args!("{:?}", self.ptr()))
            .field("gpu_ptr", &format_args!("{:#X?}", self.gpu_ptr()))
            .field("size", &format_args!("{:#X?}", self.size()))
            .finish()
    }
}

/// Debugging data associated with an allocation, when debugging is enabled.
#[repr(C)]
struct AllocDebugData {
    state: u32,
    tag: u32,
    size: u64,
    base_gpuva: u64,
    obj_gpuva: u64,
    name: [u8; 0x20],
}

/// Magic flag indicating a live allocation.
const STATE_LIVE: u32 = u32::from_le_bytes(*b"LIVE");
/// Magic flag indicating a freed allocation.
const STATE_DEAD: u32 = u32::from_le_bytes(*b"DEAD");

/// Marker byte to identify when firmware/GPU write beyond the end of an allocation.
const GUARD_MARKER: u32 = 0x93939393;

impl<T, U: RawAllocation> Drop for GenericAlloc<T, U> {
    fn drop(&mut self) {
        let debug_len = mem::size_of::<AllocDebugData>();
        if self.debug_offset >= debug_len {
            if let Some(p) = self.alloc.ptr() {
                // SAFETY: self.debug_offset is always greater than the alloc size per
                // the invariant, and greater than debug_len as checked above.
                unsafe {
                    let p = p.as_ptr().add(self.debug_offset - debug_len);
                    p.cast::<u32>().write(STATE_DEAD);
                }
            }
        }
        if debug_enabled(DebugFlags::FillAllocations) {
            if let Some(p) = self.ptr() {
                // SAFETY: Writing to our inner base pointer with our known inner size is safe.
                unsafe { p.as_ptr().cast::<u8>().write_bytes(0xde, self.size()) };
            }
        }
        if self.padding != 0 {
            if let Some(p) = self.ptr() {
                // SAFETY: Per the invariant, we have at least `self.padding` bytes trailing
                // the inner base pointer, after `size()` bytes.
                let guard = unsafe {
                    core::slice::from_raw_parts(
                        p.as_ptr().cast::<u8>().cast_const().add(self.size()),
                        self.padding,
                    )
                };
                let mut first_err = None;
                let mut last_err = 0;
                for (i, p) in guard.iter().enumerate() {
                    if *p != (self.pad_word >> (8 * (i & 3))) as u8 {
                        if first_err.is_none() {
                            first_err = Some(i);
                        }
                        last_err = i;
                    }
                }
                if let Some(start) = first_err {
                    dev_warn!(
                        self.device().as_ref(),
                        "Allocator: Corruption after object of type {}/{:#x} at {:#x}:{:#x} + {:#x}..={:#x}\n",
                        core::any::type_name::<T>(),
                        self.tag,
                        self.gpu_ptr(),
                        self.size(),
                        start,
                        last_err,
                    );
                }
            }
        }
    }
}

static_assert!(mem::size_of::<AllocDebugData>() == 0x40);

/// A trait representing an allocator.
pub(crate) trait Allocator {
    /// The raw allocation type used by this allocator.
    type Raw: RawAllocation;
    // TODO: Needs associated_type_defaults
    // type Allocation<T> = GenericAlloc<T, Self::Raw>;

    /// Returns whether CPU-side mapping is enabled.
    fn cpu_maps(&self) -> bool;
    /// Returns the minimum alignment for allocations.
    fn min_align(&self) -> usize;
    /// Allocate an object of the given size in bytes with the given alignment.
    fn alloc(&mut self, size: usize, align: usize) -> Result<Self::Raw>;

    /// Returns a tuple of (count, size) of how much garbage (freed but not yet reusable objects)
    /// exists in this allocator. Optional.
    fn garbage(&self) -> (usize, usize) {
        (0, 0)
    }
    /// Returns the bytes backing this allocator and the bytes its objects take, garbage
    /// included. Optional.
    fn usage(&self) -> (usize, usize) {
        (0, 0)
    }
    /// Returns the address range in use (up to the top) and its dormant bytes, given back and
    /// not backed. Optional.
    fn va(&self) -> (usize, usize) {
        (0, 0)
    }
    /// Collect garbage for this allocator, up to the given object count. Optional.
    fn collect_garbage(&mut self, _count: usize) {}
    /// Bounds the garbage by count at each allocation: past `high` objects the oldest are
    /// collected down to `keep`. Optional.
    fn hold_garbage(&mut self, _high: usize, _keep: usize) {}
    /// Reuses freed objects of a size in the order they were freed, each once `keep` newer ones
    /// of its size have been freed, holding at most `cap` a size. Optional.
    fn recycle(&mut self, _keep: usize, _cap: usize) {}
    /// Returns how many of the oldest garbage objects must be collected to leave at most `bytes`
    /// of garbage. Optional.
    fn garbage_over(&self, _bytes: usize) -> usize {
        0
    }
    /// Starts a firmware cache flush's epoch: blocks emptied before the returned value may be
    /// given back once the flush is done. Optional.
    fn mark_flush(&mut self) -> u64 {
        0
    }
    /// Gives back the blocks emptied before epoch `flushed`, once they total `min` bytes.
    /// Optional.
    fn shrink(&mut self, _flushed: u64, _min: usize) {}

    /// Allocate a new GpuStruct object. See [`GpuObject::new`].
    #[inline(never)]
    fn new_object<T: GpuStruct>(
        &mut self,
        inner: T,
        callback: impl for<'a> FnOnce(&'a T) -> T::Raw<'a>,
    ) -> Result<GpuObject<T, GenericAlloc<T, Self::Raw>>> {
        GpuObject::<T, GenericAlloc<T, Self::Raw>>::new(self.alloc_object()?, inner, callback)
    }

    /// Allocate a new GpuStruct object. See [`GpuObject::new_default`].
    #[inline(never)]
    fn new_default<T: GpuStruct + Default>(
        &mut self,
    ) -> Result<GpuObject<T, GenericAlloc<T, Self::Raw>>>
    where
        for<'a> <T as GpuStruct>::Raw<'a>: Default + Zeroable,
    {
        GpuObject::<T, GenericAlloc<T, Self::Raw>>::new_default(self.alloc_object()?)
    }

    /// Allocate a new GpuStruct object. See [`GpuObject::new_init_prealloc`].
    #[inline(never)]
    fn new_init<'a, T: GpuStruct, R: PinInit<T::Raw<'a>, F>, E, F>(
        &mut self,
        inner_init: impl Init<T, E>,
        raw_init: impl FnOnce(&'a T, GpuWeakPointer<T>) -> R,
    ) -> Result<GpuObject<T, GenericAlloc<T, Self::Raw>>>
    where
        kernel::error::Error: core::convert::From<E>,
        kernel::error::Error: core::convert::From<F>,
    {
        GpuObject::<T, GenericAlloc<T, Self::Raw>>::new_init_prealloc(
            self.alloc_object()?,
            |_p| inner_init,
            raw_init,
        )
    }

    /// Allocate a generic buffer of the given size and alignment, applying the debug features if
    /// enabled to tag it and detect overflows.
    fn alloc_generic<T>(
        &mut self,
        size: usize,
        align: usize,
        tag: Option<u32>,
    ) -> Result<GenericAlloc<T, Self::Raw>> {
        let padding = if debug_enabled(DebugFlags::DetectOverflows) {
            size
        } else {
            0
        };

        let ret: GenericAlloc<T, Self::Raw> =
            if self.cpu_maps() && debug_enabled(debug::DebugFlags::DebugAllocations) {
                let debug_align = self.min_align().max(align);
                let debug_len = mem::size_of::<AllocDebugData>();
                let debug_offset = (debug_len * 2 + debug_align - 1) & !(debug_align - 1);

                let alloc = self.alloc(size + debug_offset + padding, align)?;

                let mut debug = AllocDebugData {
                    state: STATE_LIVE,
                    tag: tag.unwrap_or(0),
                    size: size as u64,
                    base_gpuva: alloc.gpu_ptr(),
                    obj_gpuva: alloc.gpu_ptr() + debug_offset as u64,
                    name: [0; 0x20],
                };

                let name = core::any::type_name::<T>().as_bytes();
                let len = name.len().min(debug.name.len() - 1);
                debug.name[..len].copy_from_slice(&name[..len]);

                if let Some(p) = alloc.ptr() {
                    // SAFETY: Per the size calculations above, this pointer math and the
                    // writes never exceed the allocation size.
                    unsafe {
                        let p = p.as_ptr();
                        p.write_bytes(0x42, debug_offset - 2 * debug_len);
                        let cur = p.add(debug_offset - debug_len).cast::<AllocDebugData>();
                        let prev = p.add(debug_offset - 2 * debug_len).cast::<AllocDebugData>();
                        prev.copy_from(cur, 1);
                        cur.copy_from(&debug, 1);
                    };
                }

                GenericAlloc {
                    alloc,
                    alloc_size: size,
                    debug_offset,
                    tag: tag.unwrap_or(0),
                    pad_word: tag.unwrap_or(GUARD_MARKER) | 0x81818181,
                    padding,
                    _p: PhantomData,
                }
            } else {
                GenericAlloc {
                    alloc: self.alloc(size + padding, align)?,
                    alloc_size: size,
                    debug_offset: 0,
                    tag: tag.unwrap_or(0),
                    pad_word: tag.unwrap_or(GUARD_MARKER) | 0x81818181,
                    padding,
                    _p: PhantomData,
                }
            };

        if debug_enabled(DebugFlags::FillAllocations) {
            if let Some(p) = ret.ptr() {
                // SAFETY: Writing to our inner base pointer with our known inner size is safe.
                unsafe { p.as_ptr().cast::<u8>().write_bytes(0xaa, ret.size()) };
            }
        }

        if padding != 0 {
            if let Some(p) = ret.ptr() {
                // SAFETY: Per the invariant, we have at least `self.padding` bytes trailing
                // the inner base pointer, after `size()` bytes.
                let guard = unsafe {
                    core::slice::from_raw_parts_mut(
                        p.as_ptr().cast::<u8>().add(ret.size()),
                        padding,
                    )
                };
                for (i, p) in guard.iter_mut().enumerate() {
                    *p = (ret.pad_word >> (8 * (i & 3))) as u8;
                }
            }
        }

        Ok(ret)
    }

    /// Allocate an object of a given type, without actually initializing the allocation.
    ///
    /// This is useful to directly call `GpuObject::new_*`, without borrowing a reference to the
    /// allocator for the entire duration (e.g. if further allocations need to happen inside the
    /// callbacks).
    fn alloc_object<T: GpuStruct>(&mut self) -> Result<GenericAlloc<T, Self::Raw>> {
        let size = mem::size_of::<T::Raw<'static>>();
        let align = mem::align_of::<T::Raw<'static>>();

        self.alloc_generic(size, align, None)
    }

    /// Allocate an empty `GpuArray` of a given type and length.
    fn array_empty<T: Sized + Default>(
        &mut self,
        count: usize,
    ) -> Result<GpuArray<T, GenericAlloc<T, Self::Raw>>> {
        let size = mem::size_of::<T>() * count;
        let align = mem::align_of::<T>();

        let alloc = self.alloc_generic(size, align, None)?;
        GpuArray::<T, GenericAlloc<T, Self::Raw>>::empty(alloc, count)
    }

    /// Allocate an empty `GpuArray` of a given type and length.
    fn array_empty_tagged<T: Sized + Default>(
        &mut self,
        count: usize,
        tag: &[u8; 4],
    ) -> Result<GpuArray<T, GenericAlloc<T, Self::Raw>>> {
        let size = mem::size_of::<T>() * count;
        let align = mem::align_of::<T>();

        let alloc = self.alloc_generic(size, align, Some(u32::from_le_bytes(*tag)))?;
        GpuArray::<T, GenericAlloc<T, Self::Raw>>::empty(alloc, count)
    }

    /// Allocate an empty `GpuOnlyArray` of a given type and length.
    fn array_gpuonly<T: Sized + Default>(
        &mut self,
        count: usize,
    ) -> Result<GpuOnlyArray<T, GenericAlloc<T, Self::Raw>>> {
        let size = mem::size_of::<T>() * count;
        let align = mem::align_of::<T>();

        let alloc = self.alloc_generic(size, align, None)?;
        GpuOnlyArray::<T, GenericAlloc<T, Self::Raw>>::new(alloc, count)
    }
}

/// A simple allocation backed by a separate GEM object.
///
/// # Invariants
/// `ptr` is either None or a valid, non-null pointer to the CPU view of the object.
/// `gpu_ptr` is the GPU-side VA of the object.
pub(crate) struct SimpleAllocation {
    dev: AsahiDevRef,
    ptr: Option<NonNull<u8>>,
    gpu_ptr: u64,
    _mapping: mmu::KernelMapping,
    obj: crate::gem::ObjectRef,
}

/// SAFETY: `SimpleAllocation` just points to raw memory and should be safe to send across threads.
unsafe impl Send for SimpleAllocation {}
/// SAFETY: `SimpleAllocation` just points to raw memory and should be safe to share across threads.
unsafe impl Sync for SimpleAllocation {}

impl Drop for SimpleAllocation {
    fn drop(&mut self) {
        mod_dev_dbg!(
            self.dev,
            "SimpleAllocator: drop object @ {:#x}\n",
            self.gpu_ptr()
        );
        if debug_enabled(DebugFlags::FillAllocations) {
            let obj_size = self.obj.size();
            if let Ok(vmap) = self.obj.vmap() {
                for off in 0..obj_size {
                    vmap.try_write8(0x42, off).unwrap();
                }
            }
        }
    }
}

impl RawAllocation for SimpleAllocation {
    fn ptr(&self) -> Option<NonNull<u8>> {
        self.ptr
    }
    fn gpu_ptr(&self) -> u64 {
        self.gpu_ptr
    }
    fn device(&self) -> &AsahiDevice {
        &self.dev
    }
}

/// A simple allocator that allocates each object as its own GEM object, aligned to the end of a
/// page.
///
/// This is very slow, but it has the advantage that over-reads by the firmware or GPU will fault on
/// the guard page after the allocation, which can be useful to validate that the firmware's or
/// GPU's idea of object size what we expect.
pub(crate) struct SimpleAllocator {
    dev: AsahiDevRef,
    range: Range<u64>,
    prot: mmu::Prot,
    vm: mmu::Vm,
    min_align: usize,
    cpu_maps: bool,
}

impl SimpleAllocator {
    /// Create a new `SimpleAllocator` for a given address range and `Vm`.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        dev: &AsahiDrmDevice,
        vm: &mmu::Vm,
        range: Range<u64>,
        min_align: usize,
        prot: mmu::Prot,
        _block_size: usize,
        mut cpu_maps: bool,
        _name: fmt::Arguments<'_>,
        _keep_garbage: bool,
    ) -> Result<SimpleAllocator> {
        if debug_enabled(DebugFlags::ForceCPUMaps) {
            cpu_maps = true;
        }
        Ok(SimpleAllocator {
            dev: dev.into(),
            vm: vm.clone(),
            range,
            prot,
            min_align,
            cpu_maps,
        })
    }
}

impl Allocator for SimpleAllocator {
    type Raw = SimpleAllocation;

    fn cpu_maps(&self) -> bool {
        self.cpu_maps
    }

    fn min_align(&self) -> usize {
        self.min_align
    }

    #[inline(never)]
    fn alloc(&mut self, size: usize, align: usize) -> Result<SimpleAllocation> {
        let size_aligned = (size + mmu::UAT_PGSZ - 1) & !mmu::UAT_PGMSK;
        let align = self.min_align.max(align);
        let offset = (size_aligned - size) & !(align - 1);

        mod_dev_dbg!(
            &self.dev,
            "SimpleAllocator::new: size={:#x} size_al={:#x} al={:#x} off={:#x}\n",
            size,
            size_aligned,
            align,
            offset
        );

        let mut obj = crate::gem::new_kernel_object_in(&self.dev, size_aligned, &self.vm)?;
        let p = obj.vmap()?.addr.cast::<u8>();
        if debug_enabled(DebugFlags::FillAllocations) {
            let obj_size = obj.size();
            if let Ok(vmap) = obj.vmap() {
                for off in 0..obj_size {
                    vmap.try_write8(0xde, off)?;
                }
            }
        }
        let mapping = obj.map_into_range(
            &self.vm,
            self.range.clone(),
            self.min_align.max(mmu::UAT_PGSZ) as u64,
            self.prot,
            true,
        )?;

        let iova = mapping.iova();

        // SAFETY: Per the math above to calculate `size_aligned`, this can never overflow.
        let ptr = unsafe { p.add(offset) };
        let gpu_ptr = iova + offset as u64;

        mod_dev_dbg!(
            &self.dev,
            "SimpleAllocator::new -> {:#?} / {:#?} | {:#x} / {:#x}\n",
            p,
            ptr,
            iova,
            gpu_ptr
        );

        Ok(SimpleAllocation {
            dev: self.dev.clone(),
            ptr: NonNull::new(ptr),
            gpu_ptr,
            _mapping: mapping,
            obj,
        })
    }
}

/// Inner data for an allocation from the heap allocator.
///
/// This is wrapped in an `mm::Node`.
pub(crate) struct HeapAllocationInner {
    dev: AsahiDevRef,
    ptr: Option<NonNull<u8>>,
    real_size: usize,
    /// Counted into its block's live count.
    counted: bool,
}

/// SAFETY: `HeapAllocationInner` just points to raw memory and should be safe to send across threads.
unsafe impl Send for HeapAllocationInner {}
/// SAFETY: `HeapAllocationInner` just points to raw memory and should be safe to share between threads.
unsafe impl Sync for HeapAllocationInner {}

/// Outer view of a heap allocation.
///
/// This uses an Option<> so we can move the internal `Node` into the garbage pool when it gets
/// dropped.
///
/// # Invariants
/// The `Option` must always be `Some(...)` while this object is alive.
pub(crate) struct HeapAllocation(Option<mm::Node<HeapAllocatorInner, HeapAllocationInner>>);

impl Drop for HeapAllocation {
    fn drop(&mut self) {
        let node = self.0.take().unwrap();
        let size = node.size();
        let alloc = node.alloc_ref();

        alloc.with(|a| {
            let node = match a.recycle_push(node) {
                Ok(()) => return None,
                Err(node) => node,
            };
            if let Some(garbage) = a.garbage.as_mut() {
                if garbage.push(node, GFP_KERNEL).is_err() {
                    dev_err!(
                        &a.dev.as_ref(),
                        "HeapAllocation[{}]::drop: Failed to keep garbage\n",
                        &*a.name,
                    );
                }
                a.total_garbage += size as usize;
                None
            } else {
                // We need to ensure node survives this scope, since dropping it
                // will try to take the mm lock and deadlock us
                Some(node)
            }
        });
    }
}

impl mm::AllocInner<HeapAllocationInner> for HeapAllocatorInner {
    fn drop_object(
        &mut self,
        start: u64,
        _size: u64,
        _color: usize,
        obj: &mut HeapAllocationInner,
    ) {
        /* real_size == 0 means it's a guard node */
        if obj.real_size > 0 {
            mod_dev_dbg!(
                obj.dev,
                "HeapAllocator[{}]: drop object @ {:#x} ({} bytes)\n",
                &*self.name,
                start,
                obj.real_size,
            );
            self.allocated -= obj.real_size;
        }
        if obj.counted {
            let i = self.backing_objects.partition_point(|b| b.start <= start);
            if let Some(block) = i.checked_sub(1).map(|i| &mut self.backing_objects[i]) {
                block.live -= 1;
                if block.live == 0 {
                    block.empty_at = self.epoch;
                }
            }
        }
    }
}

impl RawAllocation for HeapAllocation {
    // SAFETY: This function must always return a valid pointer.
    // Since the HeapAllocation contains a reference to the
    // backing_objects array that contains the object backing this pointer,
    // and a block leaves it only with no live allocation in it, this pointer
    // is guaranteed to remain valid for the lifetime of the HeapAllocation.
    fn ptr(&self) -> Option<NonNull<u8>> {
        self.0.as_ref().unwrap().ptr
    }
    // SAFETY: This function must always return a valid GPU pointer.
    // See the explanation in ptr().
    fn gpu_ptr(&self) -> u64 {
        self.0.as_ref().unwrap().start()
    }
    fn device(&self) -> &AsahiDevice {
        &self.0.as_ref().unwrap().dev
    }
}

/// Inner data for a heap allocator which uses the DRM MM range allocator to manage the heap.
///
/// This is wrapped by an `mm::Allocator`.
struct HeapAllocatorInner {
    dev: AsahiDevRef,
    allocated: usize,
    backing_objects: KVec<HeapBlock>,
    garbage: Option<KVec<mm::Node<HeapAllocatorInner, HeapAllocationInner>>>,
    total_garbage: usize,
    name: CString,
    /// The firmware cache flushes begun (`mark_flush`).
    epoch: u64,
    /// Freed objects held for reuse, a ring for each size (`HeapAllocator::recycle`).
    recycle: KVec<Recycle>,
    /// How many newer objects of its size must be freed before one is reused, and how many a
    /// size holds at most; 0 (the default) recycles nothing.
    recycle_keep: usize,
    recycle_cap: usize,
}

/// The sizes a heap recycles at most, and the largest it recycles.
const RECYCLE_SIZES: usize = 8;
const RECYCLE_MAX_SIZE: u64 = 0x4000;

/// Freed objects of one size held for reuse, oldest first: a ring of `cap` slots.
struct Recycle {
    size: u64,
    slots: KVec<Option<mm::Node<HeapAllocatorInner, HeapAllocationInner>>>,
    head: usize,
    len: usize,
}

impl HeapAllocatorInner {
    /// Holds a freed node for reuse, or gives it back if its size is not recycled or its ring
    /// is full.
    fn recycle_push(
        &mut self,
        node: mm::Node<HeapAllocatorInner, HeapAllocationInner>,
    ) -> core::result::Result<(), mm::Node<HeapAllocatorInner, HeapAllocationInner>> {
        let cap = self.recycle_cap;
        let size = node.size();
        if cap == 0 || size > RECYCLE_MAX_SIZE {
            return Err(node);
        }
        let i = match self.recycle.iter().position(|r| r.size == size) {
            Some(i) => i,
            None => {
                if self.recycle.len() >= RECYCLE_SIZES {
                    return Err(node);
                }
                let mut slots = KVec::new();
                if slots.reserve(cap, GFP_KERNEL).is_err()
                    || self.recycle.reserve(1, GFP_KERNEL).is_err()
                {
                    return Err(node);
                }
                for _ in 0..cap {
                    // Within the capacity just reserved.
                    let _ = slots.push(None, GFP_KERNEL);
                }
                let _ = self.recycle.push(
                    Recycle {
                        size,
                        slots,
                        head: 0,
                        len: 0,
                    },
                    GFP_KERNEL,
                );
                self.recycle.len() - 1
            }
        };
        let r = &mut self.recycle[i];
        if r.len == cap {
            return Err(node);
        }
        r.slots[(r.head + r.len) % cap] = Some(node);
        r.len += 1;
        Ok(())
    }

    /// Takes the oldest freed node of `size` bytes at `align` once `recycle_keep` newer ones
    /// wait behind it, as an allocation of `real_size` bytes.
    fn recycle_pop(
        &mut self,
        size: u64,
        align: u64,
        real_size: usize,
    ) -> Option<mm::Node<HeapAllocatorInner, HeapAllocationInner>> {
        let (keep, cap) = (self.recycle_keep, self.recycle_cap);
        let r = self.recycle.iter_mut().find(|r| r.size == size)?;
        if r.len <= keep {
            return None;
        }
        // A node placed at a smaller alignment stays for an allocation that fits it.
        if align > 1 && r.slots[r.head].as_ref()?.start() % align != 0 {
            return None;
        }
        let mut node = r.slots[r.head].take()?;
        r.head = (r.head + 1) % cap;
        r.len -= 1;
        let old = core::mem::replace(&mut node.as_mut().inner_mut().real_size, real_size);
        self.allocated = self.allocated - old + real_size;
        Some(node)
    }
}

/// A backing block of a heap, sorted by `start` in `backing_objects`.
struct HeapBlock {
    obj: crate::gem::ObjectRef,
    /// Held for its drop, the unmap.
    _mapping: mmu::KernelMapping,
    start: u64,
    /// The allocations in it, garbage included.
    live: usize,
    /// The epoch in which `live` last fell to 0.
    empty_at: u64,
}

/// A heap allocator which uses the DRM MM range allocator to manage its objects.
///
/// The heap is composed of a series of GEM objects. It grows by a block at its top; with CPU
/// mappings, `shrink` gives empty blocks back: their address ranges merge with their dormant
/// neighbours and with the top, and an allocation placed in a dormant range backs a block's worth
/// of it again.
pub(crate) struct HeapAllocator {
    dev: AsahiDevRef,
    range: Range<u64>,
    top: u64,
    prot: mmu::Prot,
    vm: mmu::Vm,
    min_align: usize,
    block_size: usize,
    cpu_maps: bool,
    guard_nodes: KVec<mm::Node<HeapAllocatorInner, HeapAllocationInner>>,
    mm: mm::Allocator<HeapAllocatorInner, HeapAllocationInner>,
    name: CString,
    garbage: Option<KVec<mm::Node<HeapAllocatorInner, HeapAllocationInner>>>,
    /// The ranges of the blocks given back, sorted by start, each followed by a guard node.
    dormant: KVec<(u64, usize)>,
    /// The bytes of the blocks in `backing_objects`.
    backed: usize,
    /// `hold_garbage`'s bounds, (high, keep) objects.
    hold: Option<(usize, usize)>,
}

impl HeapAllocator {
    /// Create a new HeapAllocator for a given `Vm` and address range.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        dev: &AsahiDrmDevice,
        vm: &mmu::Vm,
        range: Range<u64>,
        min_align: usize,
        prot: mmu::Prot,
        block_size: usize,
        mut cpu_maps: bool,
        name: fmt::Arguments<'_>,
        keep_garbage: bool,
    ) -> Result<HeapAllocator> {
        if !min_align.is_power_of_two() {
            return Err(EINVAL);
        }
        if debug_enabled(DebugFlags::ForceCPUMaps) {
            cpu_maps = true;
        }

        let name = CString::try_from_fmt(name)?;

        let inner = HeapAllocatorInner {
            dev: dev.into(),
            allocated: 0,
            backing_objects: KVec::new(),
            // TODO: This clearly needs a try_clone() or similar
            name: CString::try_from_fmt(fmt!("{}", &*name))?,
            garbage: if keep_garbage {
                Some(KVec::new())
            } else {
                None
            },
            total_garbage: 0,
            epoch: 0,
            recycle: KVec::new(),
            recycle_keep: 0,
            recycle_cap: 0,
        };

        let mm = mm::Allocator::new(range.start, range.range(), inner)?;

        Ok(HeapAllocator {
            dev: dev.into(),
            vm: vm.clone(),
            top: range.start,
            range,
            prot,
            min_align,
            block_size: block_size.max(min_align),
            cpu_maps,
            guard_nodes: KVec::new(),
            mm,
            name,
            garbage: if keep_garbage {
                Some({
                    let mut v = KVec::new();
                    v.reserve(128, GFP_KERNEL)?;
                    v
                })
            } else {
                None
            },
            dormant: KVec::new(),
            backed: 0,
            hold: None,
        })
    }

    /// The unmapped range after each block with CPU mappings: no allocation straddles two
    /// blocks, as their CPU mappings are not contiguous. Without CPU mappings the GPU view of the
    /// heap is contiguous, and blocks need none.
    fn guard(&self) -> usize {
        if self.cpu_maps {
            self.min_align.max(mmu::UAT_PGSZ)
        } else {
            0
        }
    }

    /// Reserves the guard range at `start`.
    fn reserve_guard(
        &mut self,
        start: u64,
    ) -> Result<mm::Node<HeapAllocatorInner, HeapAllocationInner>> {
        let guard = self.guard() as u64;
        mod_dev_dbg!(
            self.dev,
            "HeapAllocator[{}]: guard node {:#x}:{:#x}\n",
            &*self.name,
            start,
            guard
        );
        let inner = HeapAllocationInner {
            dev: self.dev.clone(),
            ptr: None,
            real_size: 0,
            counted: false,
        };
        self.mm
            .reserve_node(inner, start, guard, 0)
            .inspect_err(|e| {
                dev_err!(
                    self.dev.as_ref(),
                    "HeapAllocator[{}]: Failed to reserve guard node {:#x}:{:#x}: {:?}\n",
                    &*self.name,
                    start,
                    guard,
                    e
                );
            })
    }

    /// Adds a backing block of `size` bytes at the top of the heap, and its guard.
    #[inline(never)]
    fn add_block(&mut self, size: usize) -> Result {
        let size_aligned = size.next_multiple_of(mmu::UAT_PGSZ);
        let guard = self.guard() as u64;
        let new_top = self.top + size_aligned as u64;

        mod_dev_dbg!(
            &self.dev,
            "HeapAllocator[{}]::add_block: size={:#x} size_al={:#x}\n",
            &*self.name,
            size,
            size_aligned,
        );

        if new_top + guard > self.range.end {
            dev_err!(
                self.dev.as_ref(),
                "HeapAllocator[{}]::add_block: Exhausted VA space\n",
                &*self.name,
            );
            return Err(ENOSPC);
        }

        self.guard_nodes.reserve(1, GFP_KERNEL)?;
        let guard_node = if guard > 0 {
            Some(self.reserve_guard(new_top)?)
        } else {
            None
        };
        self.back(self.top, size_aligned)?;
        if let Some(n) = guard_node {
            let _ = self.guard_nodes.push_within_capacity(n);
        }
        self.top = new_top + guard;

        cls_dev_dbg!(
            MemStats,
            &self.dev,
            "{} Heap: grow to {} bytes\n",
            &*self.name,
            self.top - self.range.start
        );

        Ok(())
    }

    /// Backs `size` bytes at `start` with a new block.
    fn back(&mut self, start: u64, size: usize) -> Result {
        let mut obj = crate::gem::new_kernel_object_in(&self.dev, size, &self.vm)?;
        if self.cpu_maps && debug_enabled(DebugFlags::FillAllocations) {
            let obj_size = obj.size();
            if let Ok(vmap) = obj.vmap() {
                for off in 0..obj_size {
                    vmap.try_write8(0xde, off)?;
                }
            }
        }

        let mapping = obj
            .map_at(&self.vm, start, self.prot, self.cpu_maps)
            .inspect_err(|err| {
                dev_err!(
                    self.dev.as_ref(),
                    "HeapAllocator[{}]: Failed to map a block at {:#x} ({:?})\n",
                    &*self.name,
                    start,
                    err
                );
            })?;

        if self.cpu_maps {
            // Create virtual mapping here ahead of time so that the vmap() in
            // alloc_inner() does not take the the object's dma_resv lock while
            // the mm lock is locked. mmu::Vm requires the opposite lock order.
            obj.vmap()?;
        }

        let block = HeapBlock {
            obj,
            _mapping: mapping,
            start,
            live: 0,
            empty_at: 0,
        };
        self.mm.with_inner(|inner| -> Result {
            let objs = &mut inner.backing_objects;
            objs.reserve(1, GFP_KERNEL)?;
            let i = objs.partition_point(|b| b.start < start);
            objs.insert_within_capacity(i, block).map_err(|_| ENOMEM)
        })?;
        self.backed += size;
        Ok(())
    }

    /// The dormant range `addr` lies in.
    fn dormant_at(&self, addr: u64) -> Option<usize> {
        let i = self
            .dormant
            .partition_point(|&(s, _)| s <= addr)
            .checked_sub(1)?;
        let (s, size) = self.dormant[i];
        (addr < s + size as u64).then_some(i)
    }

    /// Backs the start of dormant range `i` for an allocation placed in it that ends at `end`: a
    /// block of `block_size`, or up to `end`. The rest stays dormant past a new guard, unless it
    /// is too small to hold a page.
    fn carve(&mut self, i: usize, end: u64) -> Result {
        let (start, size) = self.dormant[i];
        let dend = start + size as u64;
        let guard = self.guard() as u64;
        let pg = mmu::UAT_PGSZ as u64;
        let mut bend = (start + self.block_size as u64).max(end.next_multiple_of(pg));
        if bend + guard + pg > dend {
            bend = dend;
        }
        self.guard_nodes.reserve(1, GFP_KERNEL)?;
        let sep = if bend < dend {
            Some(self.reserve_guard(bend)?)
        } else {
            None
        };
        self.back(start, (bend - start) as usize)?;
        match sep {
            Some(n) => {
                let _ = self.guard_nodes.push_within_capacity(n);
                self.dormant[i] = (bend + guard, (dend - bend - guard) as usize);
            }
            None => {
                let _ = self.dormant.remove(i);
            }
        }
        Ok(())
    }

    /// Merges the dormant ranges next to each other (the guard between two goes) and gives the
    /// highest back to the top when it ends there.
    fn coalesce(&mut self) {
        let guard = self.guard() as u64;
        let guard_at = |g: &mut KVec<mm::Node<HeapAllocatorInner, HeapAllocationInner>>,
                        at: u64| {
            g.iter()
                .position(|n| n.start() == at)
                .map(|j| drop(g.swap_remove(j)))
                .is_some()
        };
        let mut i = 0;
        while i + 1 < self.dormant.len() {
            let (s, size) = self.dormant[i];
            let (s2, size2) = self.dormant[i + 1];
            let end = s + size as u64;
            if end + guard == s2 && guard_at(&mut self.guard_nodes, end) {
                self.dormant[i] = (s, size + guard as usize + size2);
                let _ = self.dormant.remove(i + 1);
            } else {
                i += 1;
            }
        }
        if let Some(&(s, size)) = self.dormant.last() {
            let end = s + size as u64;
            if end + guard == self.top && guard_at(&mut self.guard_nodes, end) {
                let _ = self.dormant.pop();
                self.top = s;
                cls_dev_dbg!(
                    MemStats,
                    &self.dev,
                    "{} Heap: top down to {} bytes\n",
                    &*self.name,
                    self.top - self.range.start
                );
            }
        }
    }

    /// Where `addr` lies in the heap: the backing block that holds it, or
    /// the one whose guard page does, with the offset past that block's end.
    pub(crate) fn locate(&self, addr: u64) -> Option<(u64, usize, Option<u64>)> {
        let guard = if self.cpu_maps {
            self.min_align.max(mmu::UAT_PGSZ) as u64
        } else {
            0
        };
        self.mm.with_inner(|inner| {
            let objs = &inner.backing_objects;
            let i = objs.partition_point(|b| b.start <= addr).checked_sub(1)?;
            let (start, size) = (objs[i].start, objs[i].obj.size());
            let end = start + size as u64;
            if addr < end {
                Some((start, size, None))
            } else if addr < end + guard {
                Some((start, size, Some(addr - end)))
            } else {
                None
            }
        })
    }

    /// Find the backing object index that backs a given GPU address.
    fn find_obj(&mut self, addr: u64) -> Result<usize> {
        self.mm.with_inner(|inner| {
            inner
                .backing_objects
                .binary_search_by(|b| {
                    let start = b.start;
                    let end = b.start + b.obj.size() as u64;
                    if start > addr {
                        Ordering::Greater
                    } else if end <= addr {
                        Ordering::Less
                    } else {
                        Ordering::Equal
                    }
                })
                .or(Err(ENOENT))
        })
    }

    /// Places an allocation of `size` bytes in a hole between `lo` and `hi`.
    fn insert(
        &mut self,
        size: usize,
        size_aligned: usize,
        align: usize,
        lo: u64,
        hi: u64,
    ) -> Result<mm::Node<HeapAllocatorInner, HeapAllocationInner>> {
        let inner = HeapAllocationInner {
            dev: self.dev.clone(),
            ptr: None,
            real_size: size,
            counted: false,
        };
        self.mm.insert_node_in_range(
            inner,
            size_aligned as u64,
            align as u64,
            0,
            lo,
            hi,
            mm::InsertMode::Best,
        )
    }

    fn alloc_inner(&mut self, size: usize, align: usize) -> Result<HeapAllocation> {
        if align != 0 && !align.is_power_of_two() {
            return Err(EINVAL);
        }
        let align = self.min_align.max(align);
        let size_aligned = (size + align - 1) & !(align - 1);

        // A recycled node of the size first, under the lock that also counts the garbage.
        let (recycled, n) = self.mm.with_inner(|inner| {
            (
                inner.recycle_pop(size_aligned as u64, align as u64, size),
                inner.garbage.as_ref().map_or(0, |g| g.len()),
            )
        });

        // Here rather than in a periodic pass, so the bound holds at any rate of frees, recycled
        // allocations included.
        if let Some((high, keep)) = self.hold {
            if n > high {
                self.collect_garbage(n - keep);
            }
        }

        if let Some(node) = recycled {
            return Ok(HeapAllocation(Some(node)));
        }

        mod_dev_dbg!(
            self.dev.as_ref(),
            "HeapAllocator[{}]::new: size={:#x} size_al={:#x}\n",
            &*self.name,
            size,
            size_aligned,
        );

        // A hole below the top first: in a block, or in a dormant range, which a block then backs
        // again. Only then the top, short of the range's end by the guard the block there needs.
        let guard = self.guard() as u64;
        let (top, limit) = (self.top, self.range.end - guard);
        let mut node = match self.insert(size, size_aligned, align, self.range.start, top) {
            Err(ENOSPC) if top < limit => self.insert(size, size_aligned, align, top, limit),
            r => r,
        }
        .inspect_err(|a| {
            dev_err!(
                self.dev.as_ref(),
                "HeapAllocator[{}]::new: Failed to insert node of size {:#x} / align {:#x}: {:?}\n",
                &*self.name,
                size_aligned,
                align,
                a
            );
        })?;

        self.mm.with_inner(|inner| inner.allocated += size);

        let start = node.start();
        let end = start + node.size();
        if end > self.top {
            let block_size = self
                .block_size
                .max((end - self.top) as usize)
                .min((limit - self.top) as usize);
            self.add_block(block_size)?;
        } else if let Some(i) = self.dormant_at(start) {
            self.carve(i, end)?;
        }
        assert!(end <= self.top);

        if self.cpu_maps {
            mod_dev_dbg!(
                self.dev,
                "HeapAllocator[{}]::alloc: mapping to CPU\n",
                &*self.name
            );

            let idx = match self.find_obj(start) {
                Ok(a) => a,
                Err(_) => {
                    dev_warn!(
                        self.dev.as_ref(),
                        "HeapAllocator[{}]::alloc: Failed to find object at {:#x}\n",
                        &*self.name,
                        start
                    );
                    return Err(EIO);
                }
            };
            let (obj_start, obj_size, p) = self.mm.with_inner(|inner| -> Result<_> {
                let block = &mut inner.backing_objects[idx];
                let p = block.obj.vmap()?.addr.cast::<u8>();
                block.live += 1;
                Ok((block.start, block.obj.size(), p))
            })?;
            node.as_mut().inner_mut().counted = true;
            assert!(obj_start <= start);
            assert!(obj_start + obj_size as u64 >= end);
            node.as_mut().inner_mut().ptr =
                // SAFETY: Per the asserts above, this offset is always within the allocation.
                NonNull::new(unsafe { p.add((start - obj_start) as usize) });
            mod_dev_dbg!(
                self.dev,
                "HeapAllocator[{}]::alloc: CPU pointer = {:?}\n",
                &*self.name,
                node.ptr
            );
        }

        mod_dev_dbg!(
            self.dev,
            "HeapAllocator[{}]::alloc: Allocated {:#x} bytes @ {:#x}\n",
            &*self.name,
            end - start,
            start
        );

        Ok(HeapAllocation(Some(node)))
    }
}

impl Allocator for HeapAllocator {
    type Raw = HeapAllocation;

    fn cpu_maps(&self) -> bool {
        self.cpu_maps
    }

    fn min_align(&self) -> usize {
        self.min_align
    }

    fn alloc(&mut self, size: usize, align: usize) -> Result<HeapAllocation> {
        let ret = self.alloc_inner(size, align);

        if ret.is_err() {
            dev_warn!(
                self.dev.as_ref(),
                "HeapAllocator[{}]::alloc: Allocation of {:#x}({:#x}) size object failed\n",
                &*self.name,
                size,
                align
            );
        }
        ret
    }

    fn garbage(&self) -> (usize, usize) {
        self.mm.with_inner(|inner| {
            if let Some(g) = inner.garbage.as_ref() {
                (g.len(), inner.total_garbage)
            } else {
                (0, 0)
            }
        })
    }

    fn usage(&self) -> (usize, usize) {
        (self.backed, self.mm.with_inner(|inner| inner.allocated))
    }

    fn va(&self) -> (usize, usize) {
        (
            (self.top - self.range.start) as usize,
            self.dormant.iter().map(|&(_, size)| size).sum(),
        )
    }

    fn hold_garbage(&mut self, high: usize, keep: usize) {
        self.hold = Some((high, keep.min(high)));
    }

    fn recycle(&mut self, keep: usize, cap: usize) {
        self.mm.with_inner(|inner| {
            inner.recycle_keep = keep;
            inner.recycle_cap = if cap > keep { cap } else { 0 };
        });
    }

    fn garbage_over(&self, bytes: usize) -> usize {
        self.mm.with_inner(|inner| {
            let Some(g) = inner.garbage.as_ref() else {
                return 0;
            };
            let mut left = inner.total_garbage;
            let mut count = 0;
            for node in g.iter() {
                if left <= bytes {
                    break;
                }
                left -= node.size() as usize;
                count += 1;
            }
            count
        })
    }

    fn collect_garbage(&mut self, mut count: usize) {
        if let Some(garbage) = self.garbage.as_mut() {
            garbage.clear();

            while count > 0 {
                let block = count.min(garbage.capacity());
                assert!(block > 0);

                // Take the garbage out of the inner block, so we can safely drop it without deadlocking
                self.mm.with_inner(|inner| {
                    if let Some(g) = inner.garbage.as_mut() {
                        for node in g.drain(0..block) {
                            inner.total_garbage -= node.size() as usize;
                            garbage
                                .push(node, GFP_KERNEL)
                                .expect("push() failed after reserve()");
                        }
                    }
                });

                count -= block;
                // Now drop it
                garbage.clear();
            }
        }
    }

    fn mark_flush(&mut self) -> u64 {
        self.mm.with_inner(|inner| {
            inner.epoch += 1;
            inner.epoch
        })
    }

    fn shrink(&mut self, flushed: u64, min: usize) {
        // Without CPU mappings no guard node bounds a block, so an allocation could straddle a
        // dormant range and a live block.
        if !self.cpu_maps {
            return;
        }
        let gone = |b: &HeapBlock| b.live == 0 && b.empty_at < flushed;
        let bytes: usize = self.mm.with_inner(|inner| {
            inner
                .backing_objects
                .iter()
                .filter(|b| gone(b))
                .map(|b| b.obj.size())
                .sum()
        });
        if bytes == 0 || bytes < min {
            return;
        }
        // Take the blocks out under the mm lock, then unmap and free them outside it (the lock
        // order of add_block's vmap).
        let mut freed = KVec::new();
        let taken = self.mm.with_inner(|inner| -> Result {
            let objs = &mut inner.backing_objects;
            let n = objs.iter().filter(|b| gone(b)).count();
            let mut kept = KVec::with_capacity(objs.len() - n, GFP_KERNEL)?;
            freed.reserve(n, GFP_KERNEL)?;
            self.dormant.reserve(n, GFP_KERNEL)?;
            for b in objs.drain_all() {
                let _ = if gone(&b) {
                    freed.push_within_capacity(b)
                } else {
                    kept.push_within_capacity(b)
                };
            }
            *objs = kept;
            Ok(())
        });
        if taken.is_err() {
            return;
        }
        let n = freed.len();
        for b in freed.drain_all() {
            let (start, size) = (b.start, b.obj.size());
            // Unmapped before its range can be backed again.
            drop(b);
            let i = self.dormant.partition_point(|&(s, _)| s < start);
            let _ = self.dormant.insert_within_capacity(i, (start, size));
            self.backed -= size;
        }
        self.coalesce();
        cls_dev_dbg!(
            MemStats,
            &self.dev,
            "{} Heap: gave back {} blocks, {} bytes\n",
            &*self.name,
            n,
            bytes
        );
    }
}

impl Drop for HeapAllocatorInner {
    fn drop(&mut self) {
        mod_dev_dbg!(
            self.dev,
            "HeapAllocator[{}]: dropping allocator\n",
            &*self.name
        );
        if self.allocated > 0 {
            // This should never happen
            dev_crit!(
                self.dev.as_ref().as_ref(),
                "HeapAllocator[{}]: dropping with {} bytes allocated\n",
                &*self.name,
                self.allocated
            );
        }
    }
}
