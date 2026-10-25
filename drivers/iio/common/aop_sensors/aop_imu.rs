// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Apple AOP accelerometer and gyroscope driver
//!
//! The AOP streams a sensor's reports only while its report interval is
//! non-zero. A read starts the stream and the stream stops once nothing
//! has read the sensor for `IDLE_TIMEOUT`, so an unused sensor costs no
//! wakeups.
//!
//! Copyright (C) The Asahi Linux Contributors

use core::marker::PhantomPinned;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use kernel::{
    bindings, c_str,
    device::{self, Core},
    impl_has_delayed_work, module_platform_driver, new_delayed_work, new_mutex, of, platform,
    prelude::*,
    soc::apple::aop::{EPICService, FakehidListener, AOP},
    sync::{aref::ARef, Arc, Mutex},
    time::{delay::fsleep, msecs_to_jiffies, Delta, Instant, Monotonic},
    types::ForeignOwnable,
    workqueue::{self, DelayedWork, WorkItem},
    ThisModule,
};

const EPIC_SUBTYPE_SET_PROPERTY: u16 = 0x4;
// AppleSPUHIDDriver::setPropertiesGated: ReportInterval, BatchInterval and
// RawInterval, each a u32 in microseconds
const PROP_REPORT_INTERVAL: u32 = 0x0;
const PROP_BATCH_INTERVAL: u32 = 0x16;
const PROP_RAW_INTERVAL: u32 = 0x5c;
// 1: no factory calibration loaded, 2: one is (loadCalibrationData sends it last)
const PROP_CALIBRATION_STATE: u32 = 0x3d;
const BATCH_INTERVAL_US: u32 = 10000;

// A report holds X, Y and Z as s32, in 1/65536 g or 1/65536 degree/s
const AXIS_OFFSET: [usize; 3] = [6, 10, 14];
const REPORT_MIN_LEN: usize = 18;

const DEFAULT_FREQ_HZ: i32 = 100;
const MAX_FREQ_HZ: i32 = 800;
const FIRST_REPORT_TIMEOUT_MS: u32 = 500;
const IDLE_TIMEOUT: Delta = Delta::from_secs(5);

struct Kind {
    ty: u32,
    name: &'static CStr,
    // the scale to SI units as val / 2^val2
    scale: (i32, i32),
}

// 9.80665 m/s^2 / 65536
static ACCEL: Kind = Kind {
    ty: bindings::iio_chan_type_IIO_ACCEL,
    name: c_str!("aop-sensors-accel"),
    scale: (41132071, 38),
};

// pi / 180 rad/s / 65536
static GYRO: Kind = Kind {
    ty: bindings::iio_chan_type_IIO_ANGL_VEL,
    name: c_str!("aop-sensors-gyro"),
    scale: (1171271, 42),
};

struct State {
    streaming: bool,
    removed: bool,
    freq_hz: i32,
    last_read: Instant<Monotonic>,
}

#[pin_data]
struct ImuData {
    dev: ARef<device::Device>,
    aop: Arc<dyn AOP>,
    svc: EPICService,
    kind: &'static Kind,
    axes: [AtomicI32; 3],
    reports: AtomicU32,
    #[pin]
    state: Mutex<State>,
    #[pin]
    stop_work: DelayedWork<ImuData>,
}

impl_has_delayed_work! {
    impl HasDelayedWork<Self> for ImuData { self.stop_work }
}

impl ImuData {
    fn new(
        dev: ARef<device::Device>,
        aop: Arc<dyn AOP>,
        svc: EPICService,
        kind: &'static Kind,
    ) -> Result<Arc<ImuData>> {
        Arc::pin_init(
            pin_init!(ImuData {
                dev,
                aop,
                svc,
                kind,
                axes: [AtomicI32::new(0), AtomicI32::new(0), AtomicI32::new(0)],
                reports: AtomicU32::new(0),
                state <- new_mutex!(State {
                    streaming: false,
                    removed: false,
                    freq_hz: DEFAULT_FREQ_HZ,
                    last_read: Instant::now(),
                }),
                stop_work <- new_delayed_work!("ImuData::stop_work"),
            }),
            GFP_KERNEL,
        )
    }

    fn set_property(&self, tag: u32, value: u32) -> Result {
        let mut msg = [0u8; 12];
        msg[4..8].copy_from_slice(&tag.to_le_bytes());
        msg[8..12].copy_from_slice(&value.to_le_bytes());
        self.aop
            .epic_call(&self.svc, EPIC_SUBTYPE_SET_PROPERTY, &msg)
            .map(|_| ())
    }

    // macOS sets the batch and raw intervals before the report interval
    fn set_interval(&self, report_us: u32) -> Result {
        let batch_us = if report_us != 0 { BATCH_INTERVAL_US } else { 0 };
        self.set_property(PROP_BATCH_INTERVAL, batch_us)?;
        self.set_property(PROP_RAW_INTERVAL, 0)?;
        self.set_property(PROP_REPORT_INTERVAL, report_us)
    }

    // The ADT's three calibration packets (j514m, macOS 27.0.1), as loadCalibrationData sends
    // them: the range and intrinsics, the nominal and the range extrinsics
    fn calibrate(&self) -> Result {
        const I: [u32; 10] = [1, 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x10000];
        const NEG_I: [u32; 10] = [1, 0xffff0000, 0, 0, 0, 0xffff0000, 0, 0, 0, 0xffff0000];
        const ACCEL_RANGE: [u32; 11] = [1, 0x10, 0x7d00, 0, 0, 0, 0x7d00, 0, 0, 0, 0x7d00];
        const GYRO_RANGE: [u32; 11] = [1, 0x7d0, 0xfa0, 0, 0, 0, 0xfa0, 0, 0, 0, 0xfa0];
        let accel = core::ptr::eq(self.kind, &ACCEL);
        let packets: [(u32, &[u32]); 3] = if accel {
            [(0x4b, &ACCEL_RANGE), (0x4c, &NEG_I), (0x4d, &I)]
        } else {
            [(0x4b, &GYRO_RANGE), (0x4c, &I), (0x4d, &I)]
        };
        for (tag, words) in packets {
            let mut msg = KVec::new();
            msg.resize(8 + 4 * words.len(), 0u8, GFP_KERNEL)?;
            msg[4..8].copy_from_slice(&tag.to_le_bytes());
            for (i, w) in words.iter().enumerate() {
                msg[8 + 4 * i..12 + 4 * i].copy_from_slice(&w.to_le_bytes());
            }
            self.aop
                .epic_call(&self.svc, EPIC_SUBTYPE_SET_PROPERTY, &msg)?;
        }
        self.set_property(PROP_CALIBRATION_STATE, 2)
    }

    fn start(self: &Arc<Self>, state: &mut State) -> Result {
        self.calibrate()?;
        self.set_interval(1_000_000 / state.freq_hz as u32)?;
        state.streaming = true;
        let _ = workqueue::system_dfl().enqueue_delayed(
            self.clone(),
            msecs_to_jiffies(IDLE_TIMEOUT.as_millis() as u32),
        );
        Ok(())
    }

    fn read_axis(self: &Arc<Self>, axis: usize) -> Result<i32> {
        let mut state = self.state.lock();
        if state.removed {
            return Err(ENODEV);
        }
        state.last_read = Instant::now();
        if !state.streaming {
            let seen = self.reports.load(Ordering::Acquire);
            self.start(&mut state)?;
            let mut waited = 0;
            while self.reports.load(Ordering::Acquire) == seen {
                if waited >= FIRST_REPORT_TIMEOUT_MS {
                    return Err(ETIMEDOUT);
                }
                fsleep(Delta::from_millis(10));
                waited += 10;
            }
        }
        Ok(self.axes[axis].load(Ordering::Relaxed))
    }

    fn set_freq(&self, freq_hz: i32) -> Result {
        if !(1..=MAX_FREQ_HZ).contains(&freq_hz) {
            return Err(EINVAL);
        }
        let mut state = self.state.lock();
        state.freq_hz = freq_hz;
        if state.streaming {
            self.set_interval(1_000_000 / freq_hz as u32)?;
        }
        Ok(())
    }

    fn stop(&self) {
        let mut state = self.state.lock();
        state.removed = true;
        if state.streaming {
            state.streaming = false;
            let _ = self.set_interval(0);
        }
    }
}

impl WorkItem for ImuData {
    type Pointer = Arc<ImuData>;

    fn run(this: Arc<ImuData>) {
        let mut state = this.state.lock();
        if !state.streaming {
            return;
        }
        let idle = state.last_read.elapsed();
        if idle >= IDLE_TIMEOUT {
            state.streaming = false;
            if let Err(e) = this.set_interval(0) {
                dev_warn!(this.dev, "Failed to stop the reports: {:?}\n", e);
            }
            return;
        }
        let left = (IDLE_TIMEOUT - idle).as_millis() as u32;
        drop(state);
        let _ = workqueue::system_dfl().enqueue_delayed(this, msecs_to_jiffies(left));
    }
}

impl FakehidListener for ImuData {
    fn process_fakehid_report(&self, data: &[u8]) -> Result<()> {
        if data.len() < REPORT_MIN_LEN {
            return Ok(());
        }
        for (axis, off) in AXIS_OFFSET.iter().enumerate() {
            let raw = i32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
            self.axes[axis].store(raw, Ordering::Relaxed);
        }
        self.reports.fetch_add(1, Ordering::Release);
        Ok(())
    }
}

/// # Safety
///
/// The IIO core calls it with our device and one of its channels.
unsafe extern "C" fn imu_read_raw(
    dev: *mut bindings::iio_dev,
    chan: *const bindings::iio_chan_spec,
    val: *mut i32,
    val2: *mut i32,
    mask: isize,
) -> i32 {
    // SAFETY: priv_ holds the Arc<ImuData> set up by IIOAopImuDriver::new
    let data: Arc<ImuData> = unsafe { Arc::<ImuData>::borrow((*dev).priv_.cast()) }.into();
    // SAFETY: the IIO core passes one of our channels
    let axis = unsafe { (*chan).address };
    let ret = match mask as u32 {
        bindings::BINDINGS_IIO_CHAN_INFO_RAW => data.read_axis(axis).map(|v| {
            // SAFETY: the IIO core passes valid pointers
            unsafe { *val = v };
            bindings::IIO_VAL_INT
        }),
        bindings::iio_chan_info_enum_IIO_CHAN_INFO_SCALE => {
            // SAFETY: the IIO core passes valid pointers
            unsafe {
                *val = data.kind.scale.0;
                *val2 = data.kind.scale.1;
            }
            Ok(bindings::IIO_VAL_FRACTIONAL_LOG2)
        }
        bindings::iio_chan_info_enum_IIO_CHAN_INFO_SAMP_FREQ => {
            // SAFETY: the IIO core passes valid pointers
            unsafe { *val = data.state.lock().freq_hz };
            Ok(bindings::IIO_VAL_INT)
        }
        _ => Err(EINVAL),
    };
    match ret {
        Ok(v) => v as i32,
        Err(e) => e.to_errno(),
    }
}

/// # Safety
///
/// The IIO core calls it with our device and one of its channels.
unsafe extern "C" fn imu_write_raw(
    dev: *mut bindings::iio_dev,
    _chan: *const bindings::iio_chan_spec,
    val: i32,
    _val2: i32,
    mask: isize,
) -> i32 {
    // SAFETY: priv_ holds the Arc<ImuData> set up by IIOAopImuDriver::new
    let data = unsafe { Arc::<ImuData>::borrow((*dev).priv_.cast()) };
    if mask as u32 != bindings::iio_chan_info_enum_IIO_CHAN_INFO_SAMP_FREQ {
        return EINVAL.to_errno();
    }
    match data.set_freq(val) {
        Ok(()) => 0,
        Err(e) => e.to_errno(),
    }
}

struct IIOSpec {
    spec: [bindings::iio_chan_spec; 3],
    vtable: bindings::iio_info,
    _p: PhantomPinned,
}

fn channel(ty: u32, axis: usize) -> bindings::iio_chan_spec {
    let mut spec = bindings::iio_chan_spec {
        type_: ty,
        channel2: (bindings::iio_modifier_IIO_MOD_X + axis as u32) as i32,
        address: axis,
        scan_index: axis as i32,
        __bindgen_anon_1: bindings::iio_chan_spec__bindgen_ty_1 {
            scan_type: bindings::iio_scan_type {
                __bindgen_anon_1: bindings::iio_scan_type__bindgen_ty_1 {
                    format: b's' as kernel::ffi::c_char,
                },
                realbits: 32,
                storagebits: 32,
                ..Default::default()
            },
        },
        info_mask_separate: 1 << bindings::BINDINGS_IIO_CHAN_INFO_RAW,
        info_mask_shared_by_type: (1 << bindings::iio_chan_info_enum_IIO_CHAN_INFO_SCALE)
            | (1 << bindings::iio_chan_info_enum_IIO_CHAN_INFO_SAMP_FREQ),
        ..Default::default()
    };
    spec.set_modified(1);
    spec
}

struct IIOAopImuDriver {
    dev: *mut bindings::iio_dev,
    _spec: Pin<KBox<IIOSpec>>,
    data: Arc<ImuData>,
}

impl IIOAopImuDriver {
    fn new(data: Arc<ImuData>, module: &ThisModule) -> Result<Self> {
        let ty = data.kind.ty;
        let spec = KBox::pin(
            IIOSpec {
                spec: [channel(ty, 0), channel(ty, 1), channel(ty, 2)],
                vtable: bindings::iio_info {
                    read_raw: Some(imu_read_raw),
                    write_raw: Some(imu_write_raw),
                    ..Default::default()
                },
                _p: PhantomPinned,
            },
            GFP_KERNEL,
        )?;
        // SAFETY: the parent device outlives the IIO device
        let dev = unsafe { bindings::iio_device_alloc(data.dev.as_raw(), 0) };
        if dev.is_null() {
            return Err(ENOMEM);
        }
        // SAFETY: dev is a fresh IIO device; spec is pinned and lives as long as it
        unsafe {
            (*dev).priv_ = data.clone().into_foreign().cast();
            (*dev).name = data.kind.name.as_char_ptr();
            (*dev).channels = spec.spec.as_ptr();
            (*dev).num_channels = spec.spec.len() as i32;
            (*dev).info = &spec.vtable;
        }
        // SAFETY: dev is set up above
        let ret = unsafe { bindings::__iio_device_register(dev, module.as_ptr()) };
        if ret < 0 {
            dev_err!(data.dev, "Unable to register iio sensor\n");
            // SAFETY: dev was never registered; priv_ holds the reference leaked above
            unsafe {
                Arc::<ImuData>::from_foreign((*dev).priv_.cast());
                bindings::iio_device_free(dev);
            }
            return Err(Error::from_errno(ret));
        }
        Ok(IIOAopImuDriver {
            dev,
            _spec: spec,
            data,
        })
    }
}

impl Drop for IIOAopImuDriver {
    fn drop(&mut self) {
        // SAFETY: dev was registered by new
        unsafe { bindings::iio_device_unregister(self.dev) };
        self.data.aop.remove_fakehid_listener(&self.data.svc);
        self.data.stop();
        // SAFETY: DelayedWork is a transparent wrapper of struct delayed_work
        let pending = unsafe {
            bindings::cancel_delayed_work_sync(
                core::ptr::from_ref(&self.data.stop_work)
                    .cast_mut()
                    .cast::<bindings::delayed_work>(),
            )
        };
        if pending {
            // SAFETY: a queued work owns the reference enqueue_delayed leaked
            drop(unsafe { Arc::from_raw(Arc::as_ptr(&self.data)) });
        }
        // SAFETY: priv_ holds the reference new leaked; the device is unregistered
        unsafe {
            Arc::<ImuData>::from_foreign((*self.dev).priv_.cast());
            bindings::iio_device_free(self.dev);
        }
    }
}

// SAFETY: the raw IIO device is only touched at probe and remove
unsafe impl Send for IIOAopImuDriver {}
// SAFETY: as above
unsafe impl Sync for IIOAopImuDriver {}

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    <IIOAopImuDriver as platform::Driver>::IdInfo,
    [
        (of::DeviceId::new(c_str!("apple,aop-accel")), &ACCEL),
        (of::DeviceId::new(c_str!("apple,aop-gyro")), &GYRO),
    ]
);

impl platform::Driver for IIOAopImuDriver {
    type IdInfo = &'static Kind;
    type Data<'bound> = IIOAopImuDriver;

    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

    fn probe<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        info: Option<&'bound Self::IdInfo>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
        let kind = *info.ok_or(ENODEV)?;
        let dev = pdev.as_ref();
        let parent = dev.parent().unwrap();
        // SAFETY: our parent is AOP, and AopDriver is repr(transparent) for Arc<dyn Aop>
        let adata_ptr = unsafe { Pin::<KBox<Arc<dyn AOP>>>::borrow(parent.get_drvdata()) };
        let adata = (*adata_ptr).clone();
        // SAFETY: AOP sets the platform data correctly
        let service = unsafe { *((*dev.as_raw()).platform_data as *const EPICService) };
        let data = ImuData::new(dev.into(), adata.clone(), service, kind)?;
        adata.add_fakehid_listener(service, data.clone())?;
        IIOAopImuDriver::new(data, &THIS_MODULE)
    }
}

module_platform_driver! {
    type: IIOAopImuDriver,
    name: "iio_aop_imu",
    description: "AOP accelerometer and gyroscope driver",
    license: "Dual MIT/GPL",
    alias: ["platform:iio_aop_imu"],
}
