// SPDX-License-Identifier: GPL-2.0-only OR MIT
#![recursion_limit = "2048"]

//! Driver for the Apple AGX GPUs found in Apple Silicon SoCs.

mod alloc;
mod buffer;
mod channel;
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
            description: "G15: a render UMA pool per queue (1), per VM (2), or the device's TA and 3D pools (0)",
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
        g15_chan_release: u32 {
            default: 0,
            // permissions: 0,
            description: "G15: release a destroyed queue's channels to the firmware and free them (1), or keep them for reuse (0)",
        },
        g15_poll_ms: u32 {
            default: 1,
            // permissions: 0,
            description: "G15: the completion poller's tick in ms while every pending job still runs on the GPU (a finished job's host word is polled every jiffy)",
        },
    },
}
