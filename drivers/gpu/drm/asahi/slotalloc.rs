// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Generic slot allocator
//!
//! This is a simple allocator to manage fixed-size pools of GPU resources that are transiently
//! required during command execution. Each item resides in a "slot" at a given index. Users borrow
//! and return free items from the available pool.
//!
//! Allocations are "sticky", and return a token that callers can use to request the same slot
//! again later. This allows slots to be lazily invalidated, so that multiple uses by the same user
//! avoid any actual cleanup work.
//!
//! The allocation policy is LRU: a fresh allocation takes the slot freed longest ago, so that a
//! token's slot is reused by others as late as possible. The free slots are kept in an intrusive
//! list in the order they were freed, so both a fresh allocation and a token's reuse are O(1)
//! (a slot limit makes the former skip the slots above it).

use core::num::NonZeroUsize;
use core::ops::{
    Deref,
    DerefMut, //
};
use kernel::{
    error::{
        code::*,
        Result, //
    },
    prelude::*,
    str::CStr,
    sync::{
        Arc,
        CondVar,
        LockClassKey,
        Mutex, //
    },
};

/// Trait representing a single item within a slot.
pub(crate) trait SlotItem {
    /// Arbitrary user data associated with the SlotAllocator.
    type Data;

    /// Called eagerly when this item is released back into the available pool.
    fn release(&mut self, _data: &mut Self::Data, _slot: u32) {}
}

/// Trivial implementation for users which do not require any slot data nor any allocator data.
impl SlotItem for () {
    type Data = ();
}

/// Represents a current or previous allocation of an item from a slot. Users keep `SlotToken`s
/// around across allocations to request that, if possible, the same slot be reused.
#[derive(Copy, Clone, Debug)]
pub(crate) struct SlotToken {
    time: u64,
    slot: u32,
}

impl SlotToken {
    /// Returns the slot index that this token represents a past assignment to.
    pub(crate) fn last_slot(&self) -> u32 {
        self.slot
    }
}

/// A guard representing active ownership of a slot.
pub(crate) struct Guard<T: SlotItem> {
    item: Option<T>,
    changed: bool,
    token: SlotToken,
    alloc: Arc<SlotAllocatorOuter<T>>,
}

impl<T: SlotItem> Guard<T> {
    /// Returns the active slot owned by this `Guard`.
    pub(crate) fn slot(&self) -> u32 {
        self.token.slot
    }

    /// Returns `true` if the slot changed since the last allocation (or no `SlotToken` was
    /// provided), or `false` if the previously allocated slot was successfully re-acquired with
    /// no other users in the interim.
    pub(crate) fn changed(&self) -> bool {
        self.changed
    }

    /// Returns a `SlotToken` that can be used to re-request the same slot at a later time, after
    /// this `Guard` is dropped.
    pub(crate) fn token(&self) -> SlotToken {
        self.token
    }
}

impl<T: SlotItem> Deref for Guard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.item.as_ref().expect("SlotItem Guard lost our item!")
    }
}

impl<T: SlotItem> DerefMut for Guard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.item.as_mut().expect("SlotItem Guard lost our item!")
    }
}

/// A slot item that is currently free.
struct Entry<T: SlotItem> {
    item: T,
    get_time: u64,
}

/// No slot: either end of the free list.
const NIL: u32 = u32::MAX;

/// The free slots, least recently freed first: a doubly-linked list threaded through the slot
/// indices, so that a slot is appended, unlinked or taken from the front in O(1).
struct FreeList {
    /// `[prev, next]` of each slot, meaningful while the slot is free.
    links: KVec<[u32; 2]>,
    head: u32,
    tail: u32,
}

impl FreeList {
    fn new(num_slots: u32) -> Result<FreeList> {
        Ok(FreeList {
            links: KVec::from_elem([NIL; 2], num_slots as usize, GFP_KERNEL)?,
            head: NIL,
            tail: NIL,
        })
    }

    /// Appends a slot just freed.
    fn push_back(&mut self, slot: u32) {
        self.links[slot as usize] = [self.tail, NIL];
        match self.tail {
            NIL => self.head = slot,
            tail => self.links[tail as usize][1] = slot,
        }
        self.tail = slot;
    }

    /// Takes a free slot out of the list.
    fn unlink(&mut self, slot: u32) {
        let [prev, next] = self.links[slot as usize];
        match prev {
            NIL => self.head = next,
            prev => self.links[prev as usize][1] = next,
        }
        match next {
            NIL => self.tail = prev,
            next => self.links[next as usize][0] = prev,
        }
    }

    /// The least recently freed slot below `limit`.
    fn first_below(&self, limit: usize) -> Option<u32> {
        let mut slot = self.head;
        while slot != NIL && slot as usize >= limit {
            slot = self.links[slot as usize][1];
        }
        (slot != NIL).then_some(slot)
    }
}

/// Inner data for the `SlotAllocator`, protected by a `Mutex`.
struct SlotAllocatorInner<T: SlotItem> {
    data: T::Data,
    slots: KVec<Option<Entry<T>>>,
    free: FreeList,
    get_count: u64,
    slot_limit: usize,
}

impl<T: SlotItem> SlotAllocatorInner<T> {
    /// Takes the item out of a free slot.
    fn take_free(&mut self, slot: u32) -> Option<T> {
        let entry = self.slots[slot as usize].take()?;
        self.free.unlink(slot);
        Some(entry.item)
    }

    /// Returns an item to its slot as the most recently freed one, or gives it back if the slot
    /// is somehow occupied.
    fn put(&mut self, token: SlotToken, mut item: T) -> core::result::Result<(), T> {
        if self.slots[token.slot as usize].is_some() {
            return Err(item);
        }
        item.release(&mut self.data, token.slot);
        self.slots[token.slot as usize] = Some(Entry {
            item,
            get_time: token.time,
        });
        self.free.push_back(token.slot);
        Ok(())
    }
}

/// A single slot allocator instance.
#[pin_data]
struct SlotAllocatorOuter<T: SlotItem> {
    #[pin]
    inner: Mutex<SlotAllocatorInner<T>>,
    #[pin]
    cond: CondVar,
}

/// A shared reference to a slot allocator instance.
pub(crate) struct SlotAllocator<T: SlotItem>(Arc<SlotAllocatorOuter<T>>);

impl<T: SlotItem> SlotAllocator<T> {
    /// Creates a new `SlotAllocator`, with a fixed number of slots and arbitrary associated data.
    ///
    /// The caller provides a constructor callback which takes a reference to the `T::Data` and
    /// creates a single slot. This is called during construction to create all the initial
    /// items, which then live the lifetime of the `SlotAllocator`.
    pub(crate) fn new(
        num_slots: u32,
        mut data: T::Data,
        mut constructor: impl FnMut(&mut T::Data, u32) -> Option<T>,
        name: &'static CStr,
        lock_key1: Pin<&'static LockClassKey>,
        lock_key2: Pin<&'static LockClassKey>,
    ) -> Result<SlotAllocator<T>> {
        let mut slots = KVec::with_capacity(num_slots as usize, GFP_KERNEL)?;
        let mut free = FreeList::new(num_slots)?;

        // In index order: before any slot is freed, the lowest free index goes first.
        for i in 0..num_slots {
            let entry = constructor(&mut data, i).map(|item| Entry { item, get_time: 0 });
            if entry.is_some() {
                free.push_back(i);
            }
            // Within the reserved capacity: never allocates.
            slots.push(entry, GFP_KERNEL)?;
        }

        let inner = SlotAllocatorInner {
            data,
            slots,
            free,
            get_count: 0,
            slot_limit: usize::MAX,
        };

        let alloc = Arc::pin_init(
            pin_init!(SlotAllocatorOuter {
                // SAFETY: `mutex_init!` is called below.
                inner <- Mutex::new(inner, name, lock_key1),
                // SAFETY: `condvar_init!` is called below.
                cond <- CondVar::new(name, lock_key2),
            }),
            GFP_KERNEL,
        )?;

        Ok(SlotAllocator(alloc))
    }

    /// Calls a callback on the inner data associated with this allocator, taking the lock.
    pub(crate) fn with_inner<RetVal>(&self, cb: impl FnOnce(&mut T::Data) -> RetVal) -> RetVal {
        let mut inner = self.0.inner.lock();
        cb(&mut inner.data)
    }

    /// Set the slot limit for this allocator. New bindings will not use slots above
    /// this threshold.
    pub(crate) fn set_limit(&self, limit: Option<NonZeroUsize>) {
        let mut inner = self.0.inner.lock();
        inner.slot_limit = limit.unwrap_or(NonZeroUsize::MAX).get();
    }

    /// Gets a fresh slot, optionally reusing a previous allocation if a `SlotToken` is provided.
    ///
    /// Blocks if no slots are free.
    pub(crate) fn get(&self, token: Option<SlotToken>) -> Result<Guard<T>> {
        self.get_inner(token, |_a, _b| Ok(()))
    }

    /// Gets a fresh slot, optionally reusing a previous allocation if a `SlotToken` is provided.
    ///
    /// Blocks if no slots are free.
    ///
    /// This version allows the caller to pass in a callback that gets a mutable reference to the
    /// user data for the allocator and the freshly acquired slot, which is called before the
    /// allocator lock is released. This can be used to perform bookkeeping associated with
    /// specific slots (such as tracking their current owner).
    pub(crate) fn get_inner(
        &self,
        token: Option<SlotToken>,
        cb: impl FnOnce(&mut T::Data, &mut Guard<T>) -> Result<()>,
    ) -> Result<Guard<T>> {
        let mut inner = self.0.inner.lock();

        // The token's slot, if nobody had it since
        if let Some(token) = token {
            let i = token.slot as usize;
            if i < inner.slot_limit
                && inner.slots[i]
                    .as_ref()
                    .is_some_and(|e| e.get_time == token.time)
            {
                let guard = Guard {
                    item: inner.take_free(token.slot),
                    changed: false,
                    token,
                    alloc: self.0.clone(),
                };
                return self.bind(&mut inner, guard, cb);
            }
        }

        // Else the slot freed longest ago, waiting for one if none is free
        let mut first = true;
        let slot = loop {
            if let Some(slot) = inner.free.first_below(inner.slot_limit) {
                break slot;
            }
            if first && inner.slot_limit == usize::MAX {
                pr_warn!(
                    "{}: out of slots, blocking\n",
                    core::any::type_name::<Self>()
                );
            }
            first = false;
            if self.0.cond.wait_interruptible(&mut inner) {
                return Err(ERESTARTSYS);
            }
        };

        inner.get_count += 1;
        let guard = Guard {
            item: inner.take_free(slot),
            changed: true,
            token: SlotToken {
                time: inner.get_count,
                slot,
            },
            alloc: self.0.clone(),
        };
        self.bind(&mut inner, guard, cb)
    }

    /// Runs the caller's bookkeeping on a slot just taken, under the allocator's lock. If it
    /// fails, the item goes back to its slot here: the `Guard` then drops without taking the lock
    /// again, which it holds.
    fn bind(
        &self,
        inner: &mut SlotAllocatorInner<T>,
        mut guard: Guard<T>,
        cb: impl FnOnce(&mut T::Data, &mut Guard<T>) -> Result<()>,
    ) -> Result<Guard<T>> {
        let ret = cb(&mut inner.data, &mut guard);
        if ret.is_err() {
            if let Some(item) = guard.item.take() {
                // The slot was taken under this lock: it is free to return to.
                let _ = inner.put(guard.token, item);
                self.0.cond.notify_one();
            }
        }
        ret.map(|()| guard)
    }
}

impl<T: SlotItem> Clone for SlotAllocator<T> {
    fn clone(&self) -> Self {
        SlotAllocator(self.0.clone())
    }
}

impl<T: SlotItem> Drop for Guard<T> {
    fn drop(&mut self) {
        // `bind` already returned the item of a guard whose bookkeeping failed
        let Some(item) = self.item.take() else {
            return;
        };
        let mut inner = self.alloc.inner.lock();
        match inner.put(self.token, item) {
            Ok(()) => self.alloc.cond.notify_one(),
            Err(_item) => pr_crit!(
                "{}: tried to return an item into a full slot ({})\n",
                core::any::type_name::<Self>(),
                self.token.slot
            ),
        }
    }
}
