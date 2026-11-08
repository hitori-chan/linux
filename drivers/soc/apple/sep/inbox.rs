// SPDX-License-Identifier: GPL-2.0-only
//
// The mailbox's messages on their way to the driver's work. The mailbox calls the driver from its hard interrupt,
// where nothing may sleep or take the driver's mutexes, so each message is stored here and the receive work reads
// them in their order. One writer (the interrupt, one line) and one reader (the work, which the workqueue never runs
// twice at once). Each slot is two atomics (the u64 word and the u32 msg1), so no slot is ever shared unsafely: the writer stores them and then
// publishes its count with release; the reader takes the count with acquire, loads the slot, and gives it back by
// publishing its own count with release. A full inbox drops the newest message and counts it.

use kernel::soc::apple::mailbox::Message;
use kernel::sync::atomic::{Acquire, Atomic, Relaxed, Release};

/// Room for a burst of the SEP's own messages (its logger) between two runs of the work.
const SLOTS: usize = 256;

pub(crate) struct Inbox {
    slots: [(Atomic<u64>, Atomic<u32>); SLOTS],
    /// Messages stored, and messages taken, since the start (each wraps; their difference is the fill).
    stored: Atomic<u32>,
    taken: Atomic<u32>,
    lost: Atomic<u32>,
}

impl Inbox {
    pub(crate) fn new() -> Inbox {
        Inbox {
            slots: core::array::from_fn(|_| (Atomic::new(0), Atomic::new(0))),
            stored: Atomic::new(0),
            taken: Atomic::new(0),
            lost: Atomic::new(0),
        }
    }

    /// The interrupt's side: false, and counted, when the inbox is full.
    pub(crate) fn put(&self, m: Message) -> bool {
        let n = self.stored.load(Relaxed);
        if n.wrapping_sub(self.taken.load(Acquire)) as usize >= SLOTS {
            self.lost.store(self.lost.load(Relaxed).wrapping_add(1), Relaxed);
            return false;
        }
        let s = &self.slots[n as usize % SLOTS];
        s.0.store(m.msg0, Relaxed);
        s.1.store(m.msg1, Relaxed);
        self.stored.store(n.wrapping_add(1), Release);
        true
    }

    /// The work's side: the oldest message not taken yet.
    pub(crate) fn get(&self) -> Option<Message> {
        let n = self.taken.load(Relaxed);
        if self.stored.load(Acquire) == n {
            return None;
        }
        let s = &self.slots[n as usize % SLOTS];
        let m = Message { msg0: s.0.load(Relaxed), msg1: s.1.load(Relaxed) };
        self.taken.store(n.wrapping_add(1), Release);
        Some(m)
    }

    /// Messages dropped on a full inbox since the start.
    pub(crate) fn lost(&self) -> u32 {
        self.lost.load(Relaxed)
    }
}
