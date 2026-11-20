// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Apple AOP ambient light sensor driver
//!
//! Copyright (C) The Asahi Linux Contributors

use kernel::{
    bindings, c_str,
    device::Core,
    firmware::Firmware,
    iio::common::aop_sensors::{AopSensorData, IIORegistration, MessageProcessor},
    module, module_platform_driver, of, platform,
    prelude::*,
    soc::apple::aop::{EPICService, AOP},
    sync::Arc,
    time::Delta,
    types::ForeignOwnable,
};

const EPIC_SUBTYPE_GET_AOP_PROPERTY: u16 = 0xa;
const EPIC_SUBTYPE_SET_ALS_PROPERTY: u16 = 0x4;
// AppleSPUHIDDriver::setPropertiesGated: ReportInterval, BatchInterval and RawInterval, each a u32
// in microseconds
const PROP_REPORT_INTERVAL: u32 = 0x0;
const PROP_BATCH_INTERVAL: u32 = 0x16;
const PROP_RAW_INTERVAL: u32 = 0x5c;
// CoreBrightness's report interval with the display on, and the kext's batch interval for a
// non-zero one
const REPORT_INTERVAL_US: u32 = 200000;
const BATCH_INTERVAL_US: u32 = 10000;
// How long a property's set at a system sleep waits for the AOP
const SLEEP_CALL_TIMEOUT: Delta = Delta::from_secs(1);
const LUX_OFFSET_CT720: usize = 0x1d;
const LUX_OFFSET_VD6286: usize = 0x28;

fn get_lux_offset(aop: &dyn AOP, dev: &platform::Device, svc: &EPICService) -> Result<usize> {
    let name = get_aop_property(aop, svc, 0xf, 16)?.1;
    match name.as_slice() {
        b"Redbird\0" => Ok(LUX_OFFSET_VD6286),
        b"FireFish2\0" => Ok(LUX_OFFSET_CT720),
        _ => {
            dev_warn!(
                dev.as_ref(),
                "Unknown sensor type {:?}",
                core::str::from_utf8(&name)
            );
            Err(EIO)
        }
    }
}

fn enable_als(aop: &dyn AOP, dev: &platform::Device, svc: &EPICService) -> Result<()> {
    let fw = Firmware::request(c_str!("apple/aop-als-cal.bin"), dev.as_ref())?;
    set_als_property(aop, svc, 0xb, fw.data())?;
    set_als_property(
        aop,
        svc,
        PROP_REPORT_INTERVAL,
        &REPORT_INTERVAL_US.to_le_bytes(),
    )?;

    Ok(())
}

fn get_aop_property(
    aop: &dyn AOP,
    svc: &EPICService,
    tag: u32,
    data_len: usize,
) -> Result<(u32, KVec<u8>)> {
    let mut buf = KVec::new();
    buf.resize(8, 0, GFP_KERNEL)?;
    buf[4..8].copy_from_slice(&tag.to_le_bytes());
    aop.epic_call_ret(svc, EPIC_SUBTYPE_GET_AOP_PROPERTY, &buf, data_len)
}

fn als_property_msg(tag: u32, data: &[u8]) -> Result<KVec<u8>> {
    let mut buf = KVec::new();
    buf.resize(data.len() + 8, 0, GFP_KERNEL)?;
    buf[8..].copy_from_slice(data);
    buf[4..8].copy_from_slice(&tag.to_le_bytes());
    Ok(buf)
}

fn set_als_property(aop: &dyn AOP, svc: &EPICService, tag: u32, data: &[u8]) -> Result<u32> {
    aop.epic_call(
        svc,
        EPIC_SUBTYPE_SET_ALS_PROPERTY,
        &als_property_msg(tag, data)?,
    )
}

/// A non-negative `f32`'s bits as thousandths, rounded down: 0 for a negative value or a NaN, saturated above.
fn f32_to_milli(f: u32) -> u32 {
    if f & 0x80000000 != 0 {
        return 0;
    }
    let exp = ((f & 0x7f800000) >> 23) as i32 - 127;
    if exp == 128 {
        return if f & 0x7fffff != 0 { 0 } else { u32::MAX };
    }
    // under 2^-10 a value is less than a thousandth; a denormal is far under it
    if exp < -10 {
        return 0;
    }
    // 24 bits by 1000: 34 bits
    let mant = u64::from(f & 0x7fffff | 0x800000) * 1000;
    let milli = if exp <= 23 {
        mant >> (23 - exp)
    } else if exp - 23 < 30 {
        mant << (exp - 23)
    } else {
        u64::MAX
    };
    milli.min(u64::from(u32::MAX)) as u32
}

struct MsgProc(usize);

impl MessageProcessor for MsgProc {
    /// The report's lux is an `f32`: whole lux lose the dim room, where a step of the screen's brightness is
    /// worth less than one.
    const DIVISOR: u32 = 1000;

    fn process(&self, message: &[u8]) -> Option<u32> {
        let &raw = message.get(self.0..)?.first_chunk()?;
        Some(f32_to_milli(u32::from_le_bytes(raw)))
    }
}

struct IIOAopAlsDriver {
    _reg: IIORegistration<MsgProc>,
    aop: Arc<dyn AOP>,
    svc: EPICService,
}

impl IIOAopAlsDriver {
    // As AppleSPUHIDDriver::setPropertiesGated sets a ReportInterval: the batch and raw intervals
    // first, the batch one 0 for a report interval of 0. Each call bounded, as a system sleep's.
    fn set_interval(&self, report_us: u32) -> Result {
        let batch_us = if report_us != 0 { BATCH_INTERVAL_US } else { 0 };
        for (tag, value) in [
            (PROP_BATCH_INTERVAL, batch_us),
            (PROP_RAW_INTERVAL, 0),
            (PROP_REPORT_INTERVAL, report_us),
        ] {
            let msg = als_property_msg(tag, &value.to_le_bytes())?;
            self.aop.epic_call_timeout(
                &self.svc,
                EPIC_SUBTYPE_SET_ALS_PROPERTY,
                &msg,
                SLEEP_CALL_TIMEOUT,
            )?;
        }
        Ok(())
    }
}

kernel::of_device_table!(
    OF_TABLE,
    (),
    [(of::DeviceId::new(c_str!("apple,aop-als")), ())]
);

impl platform::Driver for IIOAopAlsDriver {
    type IdInfo = ();
    type Data<'bound> = IIOAopAlsDriver;

    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);
    const HAS_SUSPEND: bool = true;
    const HAS_RESUME: bool = true;

    fn probe<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        _info: Option<&'bound ()>,
    ) -> impl PinInit<Self::Data<'bound>, Error> + 'bound {
        let dev = pdev.as_ref();
        let parent = dev.parent().unwrap();
        // SAFETY: our parent is AOP, and AopDriver is repr(transparent) for Arc<dyn Aop>
        let adata_ptr = unsafe { Pin::<KBox<Arc<dyn AOP>>>::borrow(parent.get_drvdata()) };
        let adata = (&*adata_ptr).clone();
        // SAFETY: AOP sets the platform data correctly
        let service = unsafe { *((*dev.as_raw()).platform_data as *const EPICService) };
        let ty = bindings::BINDINGS_IIO_LIGHT;
        let offset = get_lux_offset(adata.as_ref(), pdev, &service)?;
        let data = AopSensorData::new(dev.into(), ty, MsgProc(offset))?;
        adata.add_fakehid_listener(service, data.clone())?;
        enable_als(adata.as_ref(), pdev, &service)?;
        let info_mask = 1 << bindings::BINDINGS_IIO_CHAN_INFO_PROCESSED;
        Ok(IIOAopAlsDriver {
            _reg: IIORegistration::<MsgProc>::new(
                data,
                c"aop-sensors-als",
                ty,
                info_mask,
                module::this_module::<crate::LocalModule>(),
            )?,
            aop: adata,
            svc: service,
        })
    }

    // The ALS reports from probe on. At a system sleep they stop, as when macOS's CoreBrightness
    // sets a ReportInterval of 0 with the display off, before the AOP stops its queues; at resume
    // they come back at CoreBrightness's display-on interval. Errors are logged, not returned: the
    // sleep goes on, and the AOP's stopped queue holds the reports anyway.
    fn suspend<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        this: Pin<&Self::Data<'bound>>,
    ) -> Result {
        if let Err(e) = this.set_interval(0) {
            dev_err!(pdev.as_ref(), "Failed to stop the reports: {:?}\n", e);
        }
        Ok(())
    }

    fn resume<'bound>(
        pdev: &'bound platform::Device<Core<'_>>,
        this: Pin<&Self::Data<'bound>>,
    ) -> Result {
        if let Err(e) = this.set_interval(REPORT_INTERVAL_US) {
            dev_err!(pdev.as_ref(), "Failed to restart the reports: {:?}\n", e);
        }
        Ok(())
    }
}

module_platform_driver! {
    type: IIOAopAlsDriver,
    name: "iio_aop_als",
    description: "AOP ambient light sensor driver",
    license: "Dual MIT/GPL",
    alias: ["platform:iio_aop_als"],
    firmware: ["apple/aop-als-cal.bin"],
}
