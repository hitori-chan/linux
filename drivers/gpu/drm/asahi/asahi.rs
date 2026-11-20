// SPDX-License-Identifier: GPL-2.0-only OR MIT
#![recursion_limit = "2048"]

//! Driver for the Apple AGX GPUs found in Apple Silicon SoCs.

mod alloc;
mod buffer;
mod channel;
mod cooling;
mod debug;
mod driver;
mod event;
mod file;
mod float;
mod fw;
mod gem;
mod gpu;
mod hw;
mod initdata;
mod mem;
mod microseq;
mod mmu;
mod object;
mod pgtable;
mod queue;
mod regs;
mod slotalloc;
mod util;
#[cfg(CONFIG_DRM_ASAHI_MAPLE_TREE)]
mod vm;
mod workqueue;

kernel::module_platform_driver! {
    type: driver::AsahiPlatformDriver,
    name: "asahi",
    description: "AGX GPU driver for Apple silicon SoCs",
    license: "GPL",
    params: {
        debug_flags: u64 {
            default: 0,
            // permissions: 0o644,
            description: "Debug flags",
        },
        fault_control: u32 {
            default: 0xb,
            // permissions: 0,
            description: "Fault control (0x0: hard faults, 0xb: macOS default)",
        },
        initial_tvb_size: usize {
            default: 0x8,
            // permissions: 0o644,
            description: "Initial TVB size in blocks",
        },
        robust_isolation: u32 {
            default: 0,
            // permissions: 0o644,
            description: "Fully isolate GPU contexts (limits performance)",
        },
        g15_uma_pools: u32 {
            default: 2,
            // permissions: 0,
            description: "G15: a render UMA pool per queue (1) or per VM (2), with a compute pool per VM, or the device's pools (0)",
        },
        g15_fw_nc: u32 {
            default: 0,
            // permissions: 0,
            description: "G15: the firmware maps the gpu and rt heaps write-back (0), Attr2 as macOS does (1), and the shared heap too (2)",
        },
        g15_quarantine: u32 {
            default: 7,
            // permissions: 0,
            description: "G15: hold the freed buffers of the shared (1), gpu (2), rt (4), fw_nc (8) and gpu_fw_nc (16) heaps back from reuse, or reuse them at once as macOS does",
        },
        g15_fw_flush: u32 {
            default: 8,
            // permissions: 0,
            description: "G15: release the shared, gpu and rt heaps' held-back buffers after a firmware cache flush, all but the newest this many (0: after enough newer memory; default 8)",
        },
        g15_heap_shrink: u32 {
            default: 16,
            // permissions: 0,
            description: "G15: with g15_fw_flush, give back the shared, gpu and rt heaps' blocks emptied before a flush once they total this many MiB (0: never; default 16)",
        },
        g15_chan_release: u32 {
            default: 0,
            // permissions: 0,
            description: "G15: release a destroyed queue's channels to the firmware and free them (1), or keep them for reuse (0)",
        },
        g15_kill: u32 {
            default: 1,
            // permissions: 0,
            description: "G15: end a destroyed queue's jobs still running after 250 ms, as macOS 27.2 ends a dead process's, with device control 0x21 on each channel's own kill word (non-zero, the default), or wait for them (0)",
        },
        g15_poll_ms: u32 {
            default: 1,
            // permissions: 0,
            description: "G15: the completion poller's tick in ms while every pending job still runs on the GPU (a finished job's host word is polled every jiffy)",
        },
        g15_poll_slow_ms: u32 {
            default: 0,
            // permissions: 0,
            description: "G15: with a value, the completion poller ticks this many ms, in place of g15_poll_ms, while no finished job waits for its host word, and a completion interrupt brings its pass forward only for such a job (0: off; debugfs asahi/g15_poll_slow_ms sets it at runtime)",
        },
    },
}
