// SPDX-License-Identifier: GPL-2.0-only

//! The GPU as a thermal cooling device.
//!
//! The firmware runs its own closed loop on the GPU's power (the PPM governor, the one macOS's
//! `setPPMControllerTarget` drives), holding its measure within 1 % of a target. A cooling state
//! is such a target, and the power allocator reads the GPU's power from the firmware's energy
//! counter, so a thermal zone shares a budget between the CPU and the GPU.
//!
//! The firmware's measure covers only part of what the GPU costs: the memory path, the fabric and
//! the regulators are outside it. The governor weighs the GPU against the CPU, so it gets the
//! cost: the system's power per watt of the firmware's measure across a target sweep.

use crate::gpu;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel::{
    bindings,
    error::from_err_ptr,
    ffi::{c_int, c_ulong},
    prelude::*,
    sync::Arc,
};

/// State 1's target, in mW: what the GPU's own measure reads at its top state under a game.
const TOP_MW: u32 = 30_000;
/// The step between states' targets, in mW.
const STEP_MW: u32 = 1_000;
/// The last state, 8 W, about the GPU's state 3 under a full-screen fill.
const MAX_STATE: usize = 23;
/// The system's power per 10 W of the firmware's measure: 2.42 under a full-screen fill from 7 to
/// 20 W, 2.33 under a game at 18 W, on the MacBook Pro 14" M3 Max.
const COST_PER_10: u32 = 24;

struct Inner {
    gpu: Arc<dyn gpu::GpuManager>,
    /// State 0's power: no limit, the firmware's default target.
    max_mw: u32,
    state: AtomicUsize,
    energy_nj: AtomicU64,
    at_ns: AtomicU64,
}

impl Inner {
    fn state_mw(&self, state: usize) -> u32 {
        match state {
            0 => self.max_mw,
            s => TOP_MW - (s.min(MAX_STATE) as u32 - 1) * STEP_MW,
        }
    }

    /// The smallest state whose target fits `mw`.
    fn mw_state(&self, mw: u32) -> usize {
        if mw >= self.max_mw || mw > TOP_MW {
            return 0;
        }
        (((TOP_MW - mw).div_ceil(STEP_MW)) as usize + 1).min(MAX_STATE)
    }

    /// A state's cost in the governor's terms. State 0 has no limit, one step above state 1.
    fn state_cost(&self, state: usize) -> u32 {
        let mw = match state {
            0 => TOP_MW + STEP_MW,
            s => self.state_mw(s),
        };
        mw * COST_PER_10 / 10
    }
}

/// # Safety
///
/// `cdev` is a device registered by [`Cooling::new`].
unsafe fn inner<'a>(cdev: *mut bindings::thermal_cooling_device) -> &'a Inner {
    // SAFETY: `devdata` is the `Inner` that outlives the registration.
    unsafe { &*((*cdev).devdata as *const Inner) }
}

/// # Safety
///
/// Called by the thermal core with the cooling device [`Cooling::new`] registered
/// and valid pointers.
unsafe extern "C" fn get_max_state(
    _cdev: *mut bindings::thermal_cooling_device,
    state: *mut c_ulong,
) -> c_int {
    // SAFETY: The thermal core passes a valid pointer.
    unsafe { *state = MAX_STATE as c_ulong };
    0
}

/// # Safety
///
/// Called by the thermal core with the cooling device [`Cooling::new`] registered
/// and valid pointers.
unsafe extern "C" fn get_cur_state(
    cdev: *mut bindings::thermal_cooling_device,
    state: *mut c_ulong,
) -> c_int {
    // SAFETY: The thermal core passes its device and a valid pointer.
    unsafe { *state = inner(cdev).state.load(Ordering::Relaxed) as c_ulong };
    0
}

/// # Safety
///
/// Called by the thermal core with the cooling device [`Cooling::new`] registered
/// and valid pointers.
unsafe extern "C" fn set_cur_state(
    cdev: *mut bindings::thermal_cooling_device,
    state: c_ulong,
) -> c_int {
    if state > MAX_STATE {
        return EINVAL.to_errno();
    }
    // SAFETY: The thermal core passes its device.
    let i = unsafe { inner(cdev) };
    if i.state.swap(state, Ordering::Relaxed) != state {
        i.gpu.ppm_target(i.state_mw(state));
    }
    0
}

/// # Safety
///
/// Called by the thermal core with the cooling device [`Cooling::new`] registered
/// and valid pointers.
unsafe extern "C" fn get_requested_power(
    cdev: *mut bindings::thermal_cooling_device,
    power: *mut u32,
) -> c_int {
    // SAFETY: The thermal core passes its device.
    let i = unsafe { inner(cdev) };
    let energy = i.gpu.energy_nj();
    // SAFETY: No preconditions.
    let now = unsafe { bindings::ktime_get() } as u64;
    let last_energy = i.energy_nj.swap(energy, Ordering::Relaxed);
    let last_now = i.at_ns.swap(now, Ordering::Relaxed);
    let mw = energy.saturating_sub(last_energy) * 1000 / now.saturating_sub(last_now).max(1);
    // SAFETY: The thermal core passes a valid pointer.
    unsafe { *power = (mw.min(u64::from(TOP_MW + STEP_MW)) as u32) * COST_PER_10 / 10 };
    0
}

/// # Safety
///
/// Called by the thermal core with the cooling device [`Cooling::new`] registered
/// and valid pointers.
unsafe extern "C" fn state2power(
    cdev: *mut bindings::thermal_cooling_device,
    state: c_ulong,
    power: *mut u32,
) -> c_int {
    // SAFETY: The thermal core passes its device and a valid pointer.
    unsafe { *power = inner(cdev).state_cost(state) };
    0
}

/// # Safety
///
/// Called by the thermal core with the cooling device [`Cooling::new`] registered
/// and valid pointers.
unsafe extern "C" fn power2state(
    cdev: *mut bindings::thermal_cooling_device,
    power: u32,
    state: *mut c_ulong,
) -> c_int {
    // SAFETY: The thermal core passes its device and a valid pointer.
    unsafe { *state = inner(cdev).mw_state(power * 10 / COST_PER_10) as c_ulong };
    0
}

static OPS: bindings::thermal_cooling_device_ops = bindings::thermal_cooling_device_ops {
    get_max_state: Some(get_max_state),
    get_cur_state: Some(get_cur_state),
    set_cur_state: Some(set_cur_state),
    get_requested_power: Some(get_requested_power),
    state2power: Some(state2power),
    power2state: Some(power2state),
};

/// The registered cooling device, for the driver's life.
pub(crate) struct Cooling {
    cdev: *mut bindings::thermal_cooling_device,
    _inner: KBox<Inner>,
}

// SAFETY: The thermal core's handle may be unregistered from any thread.
unsafe impl Send for Cooling {}
// SAFETY: `Cooling` exposes nothing but its drop.
unsafe impl Sync for Cooling {}

impl Cooling {
    /// Registers the GPU of `dev` as a cooling device, for the zones of its device tree node.
    pub(crate) fn new(dev: *mut bindings::device, gpu: Arc<dyn gpu::GpuManager>) -> Result<Self> {
        let max_mw = gpu.get_dyncfg().pwr.max_power_mw;
        let inner = KBox::new(
            Inner {
                energy_nj: AtomicU64::new(gpu.energy_nj()),
                // SAFETY: No preconditions.
                at_ns: AtomicU64::new(unsafe { bindings::ktime_get() } as u64),
                gpu,
                max_mw,
                state: AtomicUsize::new(0),
            },
            GFP_KERNEL,
        )?;
        // SAFETY: `dev` is the bound device, `OPS` is static, and `inner` outlives the
        // registration: `Cooling::drop` unregisters before it is freed.
        let cdev = from_err_ptr(unsafe {
            bindings::thermal_of_cooling_device_register(
                (*dev).of_node,
                0,
                c"asahi-gpu".as_char_ptr(),
                core::ptr::from_ref::<Inner>(&inner).cast_mut().cast(),
                &OPS,
            )
        })?;
        Ok(Self {
            cdev,
            _inner: inner,
        })
    }
}

impl Drop for Cooling {
    fn drop(&mut self) {
        // SAFETY: `cdev` was registered in `new` and is unregistered once.
        unsafe { bindings::thermal_cooling_device_unregister(self.cdev) };
    }
}
