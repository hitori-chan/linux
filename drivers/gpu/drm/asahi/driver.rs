// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Top-level GPU driver implementation.

use kernel::{
    debugfs,
    device::{
        Core,
        DeviceContext, //
    },
    dma::{
        Device,
        DmaMask, //
    },
    drm,
    drm::ioctl,
    of,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    }, //
};

use crate::{
    debug,
    file,
    gem::AsahiObject,
    gpu,
    hw,
    regs, //
};

use kernel::macros::vtable;

pub(crate) struct AsahiDrmDriver;

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type AsahiDrmDevice<Ctx = drm::Normal> = drm::Device<AsahiDrmDriver, Ctx>;

pub(crate) struct AsahiPlatformDriver;

// #[pin_data(PinnedDrop)]
pub(crate) struct AsahiPlatformDriverData<'bound> {
    /// debugfs `asahi/perf`: the performance counters.
    _perf: Pin<KBox<debugfs::File<Arc<dyn gpu::GpuManager>>>>,
    _debugfs: debugfs::Dir,
    _device: ARef<AsahiDrmDevice>,
    _reg: drm::Registration<'bound, AsahiDrmDriver>,
}

/// Holds a reference to the top-level `GpuManager` object.
#[pin_data]
pub(crate) struct AsahiDrmRegistrationData<'drm> {
    #[pin]
    pub(crate) gpu: Arc<dyn gpu::GpuManager>,
    pub(crate) resources: regs::Resources<'drm>,
}

/// Convenience type alias for the DRM device type for this driver.
pub(crate) type AsahiDevice = ARef<AsahiDrmDevice>;
pub(crate) type AsahiDevRef = ARef<AsahiDrmDevice>;
pub(crate) type AsahiRegData<'drm> = AsahiDrmRegistrationData<'drm>;

/// DRM Driver metadata
const INFO: drm::driver::DriverInfo = drm::driver::DriverInfo {
    major: 0,
    minor: 0,
    patchlevel: 0,
    name: c"asahi",
    desc: c"Apple AGX Graphics",
};

/// A G15 GPU interrupt, by index, whose thread drains the firmware rings.
/// macOS acks nothing for indices 0 and 4, so the firmware pulses them; a
/// line that stays asserted with nothing to drain is masked after `STORM`
/// empty drains in a row.
struct G15Irq {
    gpu: Arc<dyn gpu::GpuManager>,
    index: u32,
    irq: u32,
    empty: core::sync::atomic::AtomicU32,
}

impl G15Irq {
    const STORM: u32 = 10000;
}

/// The registrations of G15 interrupts 0 and 4, in one allocation.
#[pin_data]
struct G15Irqs {
    #[pin]
    irq0: kernel::irq::ThreadedRegistration<G15Irq>,
    #[pin]
    irq4: kernel::irq::ThreadedRegistration<G15Irq>,
}

impl kernel::irq::ThreadedHandler for G15Irq {
    fn handle_threaded(
        &self,
        dev: &kernel::device::Device<kernel::device::Bound>,
    ) -> kernel::irq::IrqReturn {
        use core::sync::atomic::Ordering;
        if self.gpu.g15_irq(self.index) > 0 {
            self.empty.store(0, Ordering::Relaxed);
        } else if self.empty.fetch_add(1, Ordering::Relaxed) + 1 == Self::STORM {
            dev_err!(
                dev,
                "G15: GPU IRQ index {} stays asserted; masking it\n",
                self.index
            );
            // SAFETY: masks this handler's own line; nosync from its thread.
            unsafe { kernel::bindings::disable_irq_nosync(self.irq) };
        }
        kernel::irq::IrqReturn::Handled
    }
}

/// The G15 completion poller: while work is pending, it retires the
/// completed jobs every jiffy, as the firmware's completion events can come
/// before the stamps or not at all.
#[pin_data]
struct G15Poller {
    gpu: Arc<dyn gpu::GpuManager>,
    #[pin]
    work: kernel::workqueue::DelayedWork<G15Poller>,
}

kernel::impl_has_delayed_work! {
    impl HasDelayedWork<Self> for G15Poller { self.work }
}

impl kernel::workqueue::WorkItem for G15Poller {
    type Pointer = Arc<G15Poller>;

    fn run(this: Arc<G15Poller>) {
        if this.gpu.g15_poll() {
            let _ = kernel::workqueue::system_dfl().enqueue_delayed(this, 1);
        }
    }
}

/// DRM Driver implementation for `AsahiDriver`.
#[vtable]
impl drm::driver::Driver for AsahiDrmDriver {
    type Data = ();
    type RegistrationData<'drm> = AsahiDrmRegistrationData<'drm>;
    /// Our `File` type.
    type File = file::File;
    /// Our `Object` type.
    type Object = drm::gem::shmem::Object<AsahiObject>;
    type ParentDevice<Ctx: DeviceContext> = platform::Device<Ctx>;

    const INFO: drm::driver::DriverInfo = INFO;
    const FEAT_RENDER: bool = true;
    const FEAT_SYNCOBJ: bool = true;
    const FEAT_SYNCOBJ_TIMELINE: bool = true;

    kernel::declare_drm_ioctls! {
        (ASAHI_GET_PARAMS,      drm_asahi_get_params,
                          ioctl::RENDER_ALLOW, crate::file::File::get_params),
        (ASAHI_GET_TIME,        drm_asahi_get_time,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::get_time),
        (ASAHI_VM_CREATE,       drm_asahi_vm_create,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::vm_create),
        (ASAHI_VM_DESTROY,      drm_asahi_vm_destroy,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::vm_destroy),
        (ASAHI_VM_BIND,         drm_asahi_vm_bind,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::vm_bind),
        (ASAHI_GEM_CREATE,      drm_asahi_gem_create,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::gem_create),
        (ASAHI_GEM_MMAP_OFFSET, drm_asahi_gem_mmap_offset,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::gem_mmap_offset),
        (ASAHI_GEM_BIND_OBJECT, drm_asahi_gem_bind_object,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::gem_bind_object),
        (ASAHI_QUEUE_CREATE,    drm_asahi_queue_create,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::queue_create),
        (ASAHI_QUEUE_DESTROY,   drm_asahi_queue_destroy,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::queue_destroy),
        (ASAHI_SUBMIT,          drm_asahi_submit,
            ioctl::AUTH | ioctl::RENDER_ALLOW, crate::file::File::submit),
    }
}

// OF Device ID table.s
kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    <AsahiPlatformDriver as platform::Driver>::IdInfo,
    [
        // Apple's static ADT names the node compatible "gpu,t6034"
        // (j514map, the 14-core M3 Max); "apple,agx-t6034" is the dts
        // convention for nodes we write ourselves.
        (of::DeviceId::new(c"gpu,t6034"), &hw::t6034::HWCONFIG),
        (of::DeviceId::new(c"apple,agx-t6034"), &hw::t6034::HWCONFIG),
    ]
);

/// Platform Driver implementation for `AsahiDriver`.
impl platform::Driver for AsahiPlatformDriver {
    type IdInfo = &'static hw::HwConfig;
    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);
    type Data<'bound> = AsahiPlatformDriverData<'bound>;

    /// Device probe function.
    fn probe<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
        debug::update_debug_flags();

        dev_info!(pdev.as_ref(), "Probing...\n");

        let cfg = info.ok_or(ENODEV)?;

        // SAFETY: the probe has not allocated or mapped any DMA memory yet,
        // so nothing runs concurrently with the mask update.
        unsafe { pdev.dma_set_mask_and_coherent(DmaMask::try_new(cfg.uat_oas)?)? };

        let resources = regs::Resources::new(pdev)?;

        // Initialize misc MMIO
        resources.init_mmio()?;

        // The UAT regions get a clean slate before the firmware builds its boot
        // tables in them.
        crate::mmu::Uat::prepare_regions(pdev.as_ref())?;

        // Start the coprocessor CPU, so UAT can initialize the handoff
        regs::Resources::start_cpu(pdev)?;

        let fwnode = pdev.as_ref().fwnode().ok_or(EIO)?;
        let compat: KVec<u32> = fwnode
            .property_read_array_vec(c"apple,firmware-compat", 3)?
            .required_by(pdev.as_ref())?;

        // genpd powers off the domains of every device left suspended at system
        // sleep, but those on the wakeup path; the firmware runs on through it
        // and does not survive losing power (an abort at PC 0). It idles the
        // GPU's power itself.
        // SAFETY: `pdev` is a valid, bound device for the whole call.
        unsafe {
            kernel::bindings::device_set_wakeup_capable(pdev.as_ref().as_raw(), true);
            kernel::error::to_result(kernel::bindings::device_wakeup_enable(
                pdev.as_ref().as_raw(),
            ))?;
        }

        let drm = drm::UnregisteredDevice::<AsahiDrmDriver>::new(pdev, Ok(()))?;

        let gpu = match (cfg.gpu_gen, cfg.gpu_variant, compat.as_slice()) {
            (hw::GpuGen::G15, hw::GpuVariant::C, &[14, 7, 0]) => {
                gpu::GpuManagerG15V14_7::new(&drm, &resources, cfg)? as Arc<dyn gpu::GpuManager>
            }
            _ => {
                dev_info!(
                    pdev.as_ref(),
                    "Unsupported GPU/firmware combination ({:?}, {:?}, {:?})\n",
                    cfg.gpu_gen,
                    cfg.gpu_variant,
                    compat
                );
                return Err(ENODEV);
            }
        };

        // G15: the completion poller, which submissions kick.
        let pg = gpu.clone();
        let poller = Arc::pin_init(
            pin_init!(G15Poller {
                gpu: pg,
                work <- kernel::new_delayed_work!("G15Poller::work"),
            }),
            GFP_KERNEL,
        )?;
        gpu.g15_set_kick(KBox::new(
            move || {
                let _ = kernel::workqueue::system_dfl().enqueue_delayed(poller.clone(), 1);
            },
            GFP_KERNEL,
        )?);

        // G15: the GPU's interrupts 0 and 4 drain the firmware rings: the
        // firmware does not send a mailbox message for every event. Each
        // handler is a plain value and both registrations share one box:
        // boxing a registration whose handler has its own initializer gave a
        // symbol too long for kallsyms.
        let irq = |index: u32| -> Result<_> {
            let handler = G15Irq {
                gpu: gpu.clone(),
                index,
                irq: pdev.irq_by_index(index)?.irq(),
                empty: core::sync::atomic::AtomicU32::new(0),
            };
            Ok(pdev.request_threaded_irq_by_index(
                kernel::irq::Flags::ONESHOT,
                index,
                c"asahi-g15",
                Ok::<_, Error>(handler),
            ))
        };
        let irqs = try_pin_init!(G15Irqs {
            irq0 <- irq(0)?,
            irq4 <- irq(4)?,
        });
        // The registrations live as long as the device (devres).
        core::mem::forget(KBox::pin_init(irqs, GFP_KERNEL)?);

        gpu.init()?;

        let debugfs = debugfs::Dir::new(c"asahi");
        let perf = KBox::pin_init(
            debugfs.read_callback_file(
                c"perf",
                Ok::<_, Error>(gpu.clone()),
                &|gpu: &Arc<dyn gpu::GpuManager>, f| gpu.perf_show(f),
            ),
            GFP_KERNEL,
        )?;

        let data = try_pin_init!(AsahiDrmRegistrationData { gpu, resources });

        // SAFETY: `reg` is stored in `AsahiPlatformDriverData` and dropped when the driver is
        // unbound; it is never forgotten.
        let reg = unsafe { drm::Registration::new(pdev.as_ref(), drm, data, 0)? };

        let driver = AsahiPlatformDriverData {
            _perf: perf,
            _debugfs: debugfs,
            _device: reg.device().into(),
            _reg: reg,
        };

        Ok(driver)
    }
}
