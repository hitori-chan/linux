// SPDX-License-Identifier: GPL-2.0
/*
 * Apple Silicon DWC3 Glue driver
 * Copyright (C) The Asahi Linux Contributors
 *
 * Based on:
 *  - dwc3-qcom.c Copyright (c) 2018, The Linux Foundation. All rights reserved.
 *  - dwc3-of-simple.c Copyright (c) 2015 Texas Instruments Incorporated - https://www.ti.com
 */

#include <linux/iommu.h>
#include <linux/of.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>
#include <linux/workqueue.h>

#include "glue.h"

/*
 * This platform requires a very specific sequence of operations to bring up dwc3 and its USB3 PHY:
 *
 * 1) The PHY itself has to be brought up; for this we need to know the mode (USB3,
 *    USB3+DisplayPort, USB4, etc) and the lane orientation. This happens through typec_mux_set.
 * 2) DWC3 has to be brought up but we must not touch the gadget area or start xhci yet.
 * 3) The PHY bring-up has to be finalized and dwc3's PIPE interface has to be switched to the
 *    USB3 PHY, this is done inside phy_set_mode.
 * 4) We can now initialize xhci or gadget mode.
 *
 * We can switch 1 and 2 but 3 has to happen after (1 and 2) and 4 has to happen after 3.
 *
 * And then to bring this all down again:
 *
 * 1) DWC3 has to exit host or gadget mode and must no longer touch those registers
 * 2) The PHY has to switch dwc3's PIPE interface back to the dummy backend
 * 3) The PHY itself can be shut down, this happens from typec_mux_set
 *
 * We also can't transition the PHY from one mode to another while dwc3 is up and running (this is
 * slightly wrong, some transitions are possible, others aren't but because we have no documentation
 * for this I'd rather play it safe).
 *
 * After both the PHY and dwc3 are initialized we will only ever see a single "new device connected"
 * event. If we just keep them running only the first device plugged in will ever work. XHCI's port
 * status register actually does show the correct state but no interrupt ever comes in. In gadget
 * mode we don't even get a USBDisconnected event and everything looks like there's still something
 * connected on the other end.
 * This can be partially explained because the USB2 D+/D- lines are connected through a stateful
 * eUSB2 repeater which in turn is controlled by a variant of the TI TPS6598x USB PD chip which
 * resets the repeater out-of-band everytime the CC lines are (dis)connected. This then requires a
 * PHY reset to make sure the PHY and the eUSB2 repeater state are synchronized again.
 *
 * And to make this all extra fun: If we get the order of some of this wrong either the port is just
 * broken until a phy+dwc3 reset, or it's broken until a full SoC reset (likely because we can't
 * reset some parts of the PHY), or some watchdog kicks in after a few seconds and forces a full SoC
 * reset (mostly seen this with USB4/Thunderbolt but there's clearly some watchdog that hates
 * invalid states).
 *
 * Hence there's really no good way to keep dwc3 fully up and running after we disconnect a cable
 * because then we can't shut down the PHY anymore. And if we kept the PHY running in whatever mode
 * it was until the next cable is connected we'd need to tear it all down and bring it back up again
 * anyway to detect and use the next device.
 *
 * Instead, we just shut down everything when a cable is disconnected and transition to
 * DWC3_APPLE_NO_CABLE.
 * During initial probe we don't have any information about the connected cable and can't bring up
 * the PHY properly and thus also can't fully bring up dwc3. Instead, we just keep everything off
 * and defer the first dwc3 probe until we get the first cable connected event. Until then we stay
 * in DWC3_APPLE_PROBE_PENDING.
 * Once a cable is connected we then keep track of the controller mode here by transitioning to
 * DWC3_APPLE_HOST or DWC3_APPLE_DEVICE.
 *
 * The controller shares its power domain (ATCn_USB) with the PHY and the two DARTs. It holds a
 * runtime PM reference only in DWC3_APPLE_HOST and DWC3_APPLE_DEVICE, so with no cable genpd can
 * power the port down, as macOS takes an empty port's controller to power state 0
 * (AppleT8122USBXHCI::setPowerStateGated, then the usb-drd's gate off). dwc3 is torn down and
 * re-initialized for every cable anyway, so nothing has to be saved. Allowed by default on t6031
 * and t6034, where it has run; elsewhere probe forbids runtime PM, and "auto" in the device's
 * power/control allows it. The domain goes off only when the PHY, which shares it, allows it too.
 */
enum dwc3_apple_state {
	DWC3_APPLE_PROBE_PENDING, /* Before first cable connection, dwc3_core_probe not called */
	DWC3_APPLE_NO_CABLE, /* No cable connected, dwc3 suspended after dwc3_core_exit */
	DWC3_APPLE_HOST, /* Cable connected, dwc3 in host mode */
	DWC3_APPLE_DEVICE, /* Cable connected, dwc3 in device mode */
};

/**
 * struct dwc3_apple - Apple-specific DWC3 USB controller
 * @dwc: Core DWC3 structure
 * @dev: Pointer to the device structure
 * @mmio_resource: Resource to be passed to dwc3_core_probe
 * @apple_regs: Apple-specific DWC3 registers
 * @reset: Reset control
 * @role_sw: USB role switch
 * @lock: Mutex for synchronizing access
 * @state: Current state of the controller, see documentation for the enum for details
 */
struct dwc3_apple {
	struct dwc3 dwc;

	struct device *dev;
	struct resource *mmio_resource;
	void __iomem *apple_regs;

	struct reset_control *reset;
	struct usb_role_switch *role_sw;

	struct mutex lock;

	enum dwc3_apple_state state;

	/* the page under IOVA 0 and its check: dwc3_apple_sink_map() */
	void *sink;
	struct delayed_work sink_work;
};

#define to_dwc3_apple(d) container_of((d), struct dwc3_apple, dwc)

/*
 * Apple Silicon dwc3 vendor-specific registers
 *
 * These registers were identified by tracing XNU's memory access patterns and correlating them with
 * debug output over serial to determine their names. We don't exactly know what these do but
 * without these USB3 devices sometimes don't work.
 */
#define APPLE_DWC3_REGS_START 0xcd00
#define APPLE_DWC3_REGS_END 0xcdff

#define APPLE_DWC3_CIO_LFPS_OFFSET 0xcd38
#define APPLE_DWC3_CIO_LFPS_OFFSET_VALUE 0xf800f80

#define APPLE_DWC3_CIO_BW_NGT_OFFSET 0xcd3c
#define APPLE_DWC3_CIO_BW_NGT_OFFSET_VALUE 0xfc00fc0

#define APPLE_DWC3_CIO_LINK_TIMER 0xcd40
#define APPLE_DWC3_CIO_PENDING_HP_TIMER GENMASK(23, 16)
#define APPLE_DWC3_CIO_PENDING_HP_TIMER_VALUE 0x14
#define APPLE_DWC3_CIO_PM_LC_TIMER GENMASK(15, 8)
#define APPLE_DWC3_CIO_PM_LC_TIMER_VALUE 0xa
#define APPLE_DWC3_CIO_PM_ENTRY_TIMER GENMASK(7, 0)
#define APPLE_DWC3_CIO_PM_ENTRY_TIMER_VALUE 0x10

/* GCTL.PWRDNSCALE as macOS sets it at each reset (AppleT8122USBXHCI::reset); reset value 0x618 */
#define APPLE_DWC3_PWRDNSCALE 0xd

static inline void dwc3_apple_writel(struct dwc3_apple *appledwc, u32 offset, u32 value)
{
	writel(value, appledwc->apple_regs + offset - APPLE_DWC3_REGS_START);
}

static inline u32 dwc3_apple_readl(struct dwc3_apple *appledwc, u32 offset)
{
	return readl(appledwc->apple_regs + offset - APPLE_DWC3_REGS_START);
}

static inline void dwc3_apple_mask(struct dwc3_apple *appledwc, u32 offset, u32 mask, u32 value)
{
	u32 reg;

	reg = dwc3_apple_readl(appledwc, offset);
	reg &= ~mask;
	reg |= value;
	dwc3_apple_writel(appledwc, offset, reg);
}

static void dwc3_apple_setup_cio(struct dwc3_apple *appledwc)
{
	dwc3_apple_writel(appledwc, APPLE_DWC3_CIO_LFPS_OFFSET, APPLE_DWC3_CIO_LFPS_OFFSET_VALUE);
	dwc3_apple_writel(appledwc, APPLE_DWC3_CIO_BW_NGT_OFFSET,
			  APPLE_DWC3_CIO_BW_NGT_OFFSET_VALUE);
	dwc3_apple_mask(appledwc, APPLE_DWC3_CIO_LINK_TIMER, APPLE_DWC3_CIO_PENDING_HP_TIMER,
			FIELD_PREP(APPLE_DWC3_CIO_PENDING_HP_TIMER,
				   APPLE_DWC3_CIO_PENDING_HP_TIMER_VALUE));
	dwc3_apple_mask(appledwc, APPLE_DWC3_CIO_LINK_TIMER, APPLE_DWC3_CIO_PM_LC_TIMER,
			FIELD_PREP(APPLE_DWC3_CIO_PM_LC_TIMER, APPLE_DWC3_CIO_PM_LC_TIMER_VALUE));
	dwc3_apple_mask(appledwc, APPLE_DWC3_CIO_LINK_TIMER, APPLE_DWC3_CIO_PM_ENTRY_TIMER,
			FIELD_PREP(APPLE_DWC3_CIO_PM_ENTRY_TIMER,
				   APPLE_DWC3_CIO_PM_ENTRY_TIMER_VALUE));
}

/*
 * The power-down scale paces the link's timers while the PHY is in P3. The core sets it only from
 * a suspend clock, which this platform does not describe, so it is set here. Raw MMIO: dwc3_readl()
 * traces through the core module's tracepoints.
 */
static void dwc3_apple_setup_pwrdnscale(struct dwc3_apple *appledwc)
{
	void __iomem *gctl = appledwc->dwc.regs + DWC3_GCTL - DWC3_GLOBALS_REGS_START;
	u32 reg;

	reg = readl(gctl);
	reg &= ~DWC3_GCTL_PWRDNSCALE_MASK;
	reg |= DWC3_GCTL_PWRDNSCALE(APPLE_DWC3_PWRDNSCALE);
	writel(reg, gctl);
}

/*
 * The xHC makes one stray DMA write, three bytes (00 00 01) at IOVA 0x15c, when a device that an earlier host
 * enumerated at high speed (U-Boot's, at boot) moves to SuperSpeed during this host's first USB 2 reset of it: within
 * milliseconds of the SuperSpeed link reaching U0, by any path, the USB 2 port's reset still running or just over. No
 * address the driver hands the controller is its base (the DCBAA and every entry of it, the scratchpad array and
 * buffers, the event rings of all four interrupters, the device event buffer, each given a poisoned target of its
 * own): the base is the controller's, zero, and the controller reads nothing there first. With IOVA 0 unmapped the
 * DART faults, the xHC stops with a Host System Error, the device falls back to high speed and every suspend fails
 * on the dead controller. macOS's window does not hold IOVA 0 either, but its boot never enumerates the device first.
 *
 * So the first page of the controller's IOVA space, which the DMA API never hands out, is mapped write-only onto a
 * page of ours. The write lands there, the device comes up at SuperSpeed, and the check below says when it happened.
 */
static void dwc3_apple_sink_check(struct dwc3_apple *appledwc)
{
	u8 *sink = appledwc->sink, *p;
	unsigned long off;

	if (!sink)
		return;
	p = memchr_inv(sink, 0, PAGE_SIZE);
	if (!p)
		return;
	off = (p - sink) & ~3UL;
	dev_info(appledwc->dev, "the xHC's stray write landed in IOVA 0's page: +%#lx: %4ph\n", off, sink + off);
	memset(sink, 0, PAGE_SIZE);
}

static void dwc3_apple_sink_work(struct work_struct *work)
{
	struct dwc3_apple *appledwc = container_of(to_delayed_work(work), struct dwc3_apple, sink_work);

	dwc3_apple_sink_check(appledwc);
}

static void dwc3_apple_sink_unmap(void *data)
{
	struct dwc3_apple *appledwc = data;

	cancel_delayed_work_sync(&appledwc->sink_work);
	dwc3_apple_sink_check(appledwc);
	iommu_unmap(iommu_get_domain_for_dev(appledwc->dev), 0, PAGE_SIZE);
	free_page((unsigned long)appledwc->sink);
	appledwc->sink = NULL;
}

static int dwc3_apple_sink_map(struct dwc3_apple *appledwc)
{
	struct iommu_domain *dom = iommu_get_domain_for_dev(appledwc->dev);
	int ret;

	INIT_DELAYED_WORK(&appledwc->sink_work, dwc3_apple_sink_work);
	if (!dom)
		return 0;
	appledwc->sink = (void *)get_zeroed_page(GFP_KERNEL);
	if (!appledwc->sink)
		return -ENOMEM;
	ret = iommu_map(dom, 0, virt_to_phys(appledwc->sink), PAGE_SIZE, IOMMU_WRITE, GFP_KERNEL);
	if (ret) {
		free_page((unsigned long)appledwc->sink);
		appledwc->sink = NULL;
		return ret;
	}
	return devm_add_action_or_reset(appledwc->dev, dwc3_apple_sink_unmap, appledwc);
}

static void dwc3_apple_set_ptrcap(struct dwc3_apple *appledwc, u32 mode)
{
	guard(spinlock_irqsave)(&appledwc->dwc.lock);
	dwc3_set_prtcap(&appledwc->dwc, mode, false);
}

/* dwc3_core_probe() sets the same delay */
#define DWC3_APPLE_AUTOSUSPEND_MS 5000

static void dwc3_apple_pm_put(struct device *dev)
{
	pm_runtime_mark_last_busy(dev);
	pm_runtime_put_autosuspend(dev);
}

/* What user space chose in power/control: "auto" (true) or "on" */
static bool dwc3_apple_pm_allowed(struct device *dev)
{
#ifdef CONFIG_PM
	return dev->power.runtime_auto;
#else
	return false;
#endif
}

static int dwc3_apple_core_probe(struct dwc3_apple *appledwc)
{
	struct dwc3_probe_data probe_data = {};
	struct device *dev = appledwc->dev;
	bool allowed = dwc3_apple_pm_allowed(dev);
	int ret;

	lockdep_assert_held(&appledwc->lock);
	WARN_ON_ONCE(appledwc->state != DWC3_APPLE_PROBE_PENDING);

	appledwc->dwc.dev = appledwc->dev;
	probe_data.dwc = &appledwc->dwc;
	probe_data.res = appledwc->mmio_resource;
	probe_data.ignore_clocks_and_resets = true;
	probe_data.skip_core_init_mode = true;
	probe_data.properties = DWC3_DEFAULT_PROPERTIES;

	/*
	 * dwc3_core_probe() sets this device's runtime PM up itself (set_active, enable, forbid):
	 * hand it over disabled, then restore what user space chose. The reference taken for this
	 * cable stays counted.
	 */
	pm_runtime_disable(dev);
	ret = dwc3_core_probe(&probe_data);
	if (ret) {
		/* Its error path allowed, disabled and suspended the device */
		pm_runtime_set_active(dev);
		pm_runtime_enable(dev);
		if (!allowed)
			pm_runtime_forbid(dev);
		return ret;
	}
	if (allowed)
		pm_runtime_allow(dev);

	/*
	 * USB 2 hardware LPM: a high-speed device with BESL support on a root
	 * port stops answering (every transfer -EPROTO) once it idles into L1.
	 * The xHC is given the property at each host start.
	 */
	appledwc->dwc.usb2_lpm_disable = true;

	appledwc->state = DWC3_APPLE_NO_CABLE;
	return 0;
}

static int dwc3_apple_core_init(struct dwc3_apple *appledwc)
{
	int ret;

	lockdep_assert_held(&appledwc->lock);

	switch (appledwc->state) {
	case DWC3_APPLE_PROBE_PENDING:
		ret = dwc3_apple_core_probe(appledwc);
		if (ret)
			dev_err(appledwc->dev, "Failed to probe DWC3 Core, err=%d\n", ret);
		break;
	case DWC3_APPLE_NO_CABLE:
		ret = dwc3_core_init(&appledwc->dwc);
		if (ret)
			dev_err(appledwc->dev, "Failed to initialize DWC3 Core, err=%d\n", ret);
		break;
	default:
		/* Unreachable unless there's a bug in this driver */
		WARN_ON_ONCE(1);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int dwc3_apple_init(struct dwc3_apple *appledwc, enum dwc3_apple_state state)
{
	int ret, ret_reset;

	lockdep_assert_held(&appledwc->lock);

	/*
	 * The USB2 PHY on this platform must be configured for host or device mode while it is
	 * still powered off and before dwc3 tries to access it. Otherwise, the new configuration
	 * will sometimes only take affect after the *next* time dwc3 is brought up which causes
	 * the connected device to just not work.
	 * The USB3 PHY must be configured later after dwc3 has already been initialized.
	 */
	switch (state) {
	case DWC3_APPLE_HOST:
		phy_set_mode(appledwc->dwc.usb2_generic_phy[0], PHY_MODE_USB_HOST);
		break;
	case DWC3_APPLE_DEVICE:
		phy_set_mode(appledwc->dwc.usb2_generic_phy[0], PHY_MODE_USB_DEVICE);
		break;
	default:
		/* Unreachable unless there's a bug in this driver */
		return -EINVAL;
	}

	ret = reset_control_deassert(appledwc->reset);
	if (ret) {
		dev_err(appledwc->dev, "Failed to deassert reset, err=%d\n", ret);
		return ret;
	}

	ret = dwc3_apple_core_init(appledwc);
	if (ret)
		goto reset_assert;

	/*
	 * Now that the core is initialized and already went through dwc3_core_soft_reset we can
	 * configure some unknown Apple-specific settings and then bring up xhci or gadget mode.
	 */
	dwc3_apple_setup_cio(appledwc);
	dwc3_apple_setup_pwrdnscale(appledwc);

	switch (state) {
	case DWC3_APPLE_HOST:
		appledwc->dwc.dr_mode = USB_DR_MODE_HOST;
		dwc3_apple_set_ptrcap(appledwc, DWC3_GCTL_PRTCAP_HOST);
		/*
		 * This platform requires SUSPHY to be enabled here already in order to properly
		 * configure the PHY and switch dwc3's PIPE interface to USB3 PHY. The USB2 PHY
		 * has already been configured to the correct mode earlier.
		 */
		dwc3_enable_susphy(&appledwc->dwc, true);
		phy_set_mode(appledwc->dwc.usb3_generic_phy[0], PHY_MODE_USB_HOST);
		ret = dwc3_host_init(&appledwc->dwc);
		if (ret) {
			dev_err(appledwc->dev, "Failed to initialize host, ret=%d\n", ret);
			goto core_exit;
		}
		/* a boot's stray write comes within half a second of the host's start */
		schedule_delayed_work(&appledwc->sink_work, 2 * HZ);

		break;
	case DWC3_APPLE_DEVICE:
		appledwc->dwc.dr_mode = USB_DR_MODE_PERIPHERAL;
		dwc3_apple_set_ptrcap(appledwc, DWC3_GCTL_PRTCAP_DEVICE);
		/*
		 * This platform requires SUSPHY to be enabled here already in order to properly
		 * configure the PHY and switch dwc3's PIPE interface to USB3 PHY. The USB2 PHY
		 * has already been configured to the correct mode earlier.
		 */
		dwc3_enable_susphy(&appledwc->dwc, true);
		phy_set_mode(appledwc->dwc.usb3_generic_phy[0], PHY_MODE_USB_DEVICE);
		ret = dwc3_gadget_init(&appledwc->dwc);
		if (ret) {
			dev_err(appledwc->dev, "Failed to initialize gadget, ret=%d\n", ret);
			goto core_exit;
		}
		break;
	default:
		/* Unreachable unless there's a bug in this driver */
		WARN_ON_ONCE(1);
		ret = -EINVAL;
		goto core_exit;
	}

	appledwc->state = state;
	return 0;

core_exit:
	dwc3_core_exit(&appledwc->dwc);
reset_assert:
	ret_reset = reset_control_assert(appledwc->reset);
	if (ret_reset)
		dev_warn(appledwc->dev, "Failed to assert reset, err=%d\n", ret_reset);

	return ret;
}

static int dwc3_apple_exit(struct dwc3_apple *appledwc)
{
	int ret = 0;

	lockdep_assert_held(&appledwc->lock);

	switch (appledwc->state) {
	case DWC3_APPLE_PROBE_PENDING:
	case DWC3_APPLE_NO_CABLE:
		/* Nothing to do if we're already off */
		return 0;
	case DWC3_APPLE_DEVICE:
		dwc3_gadget_exit(&appledwc->dwc);
		break;
	case DWC3_APPLE_HOST:
		dwc3_host_exit(&appledwc->dwc);
		cancel_delayed_work_sync(&appledwc->sink_work);
		dwc3_apple_sink_check(appledwc);
		break;
	}

	/*
	 * This platform requires SUSPHY to be enabled in order to properly power down the PHY
	 * and switch dwc3's PIPE interface back to a dummy PHY (i.e. no USB3 support and USB2 via
	 * a different PHY connected through ULPI).
	 */
	dwc3_enable_susphy(&appledwc->dwc, true);
	dwc3_core_exit(&appledwc->dwc);
	appledwc->state = DWC3_APPLE_NO_CABLE;

	ret = reset_control_assert(appledwc->reset);

	/* Drop the cable's reference taken in dwc3_apple_power_init() */
	dwc3_apple_pm_put(appledwc->dev);

	if (ret) {
		dev_err(appledwc->dev, "Failed to assert reset, err=%d\n", ret);
		return ret;
	}

	return 0;
}

/* Power the port up for a cable; dwc3_apple_exit() drops the reference */
static int dwc3_apple_power_init(struct dwc3_apple *appledwc, enum dwc3_apple_state state)
{
	int ret;

	lockdep_assert_held(&appledwc->lock);

	ret = pm_runtime_resume_and_get(appledwc->dev);
	if (ret) {
		dev_err(appledwc->dev, "Failed to resume, err=%d\n", ret);
		return ret;
	}

	ret = dwc3_apple_init(appledwc, state);
	if (ret)
		dwc3_apple_pm_put(appledwc->dev);

	return ret;
}

static int dwc3_usb_role_switch_set(struct usb_role_switch *sw, enum usb_role role)
{
	struct dwc3_apple *appledwc = usb_role_switch_get_drvdata(sw);
	int ret;

	guard(mutex)(&appledwc->lock);

	/*
	 * Skip role switches if appledwc is already in the desired state. The
	 * USB-C port controller on M2 and M1/M2 Pro/Max/Ultra devices issues
	 * additional interrupts which results in usb_role_switch_set_role()
	 * calls with the current role.
	 * Ignore those calls here to ensure the USB-C port controller and
	 * appledwc are in a consistent state.
	 * This matches the behaviour in __dwc3_set_mode().
	 * Do no handle USB_ROLE_NONE for DWC3_APPLE_NO_CABLE and
	 * DWC3_APPLE_PROBE_PENDING since that is no-op anyway.
	 */
	if (appledwc->state == DWC3_APPLE_HOST && role == USB_ROLE_HOST)
		return 0;
	if (appledwc->state == DWC3_APPLE_DEVICE && role == USB_ROLE_DEVICE)
		return 0;

	/*
	 * We need to tear all of dwc3 down and re-initialize it every time a cable is
	 * connected or disconnected or when the mode changes. See the documentation for enum
	 * dwc3_apple_state for details.
	 */
	ret = dwc3_apple_exit(appledwc);
	if (ret)
		return ret;

	switch (role) {
	case USB_ROLE_NONE:
		/* Nothing to do if no cable is connected */
		return 0;
	case USB_ROLE_HOST:
		return dwc3_apple_power_init(appledwc, DWC3_APPLE_HOST);
	case USB_ROLE_DEVICE:
		return dwc3_apple_power_init(appledwc, DWC3_APPLE_DEVICE);
	default:
		dev_err(appledwc->dev, "Invalid target role: %d\n", role);
		return -EINVAL;
	}
}

static enum usb_role dwc3_usb_role_switch_get(struct usb_role_switch *sw)
{
	struct dwc3_apple *appledwc = usb_role_switch_get_drvdata(sw);

	guard(mutex)(&appledwc->lock);

	switch (appledwc->state) {
	case DWC3_APPLE_HOST:
		return USB_ROLE_HOST;
	case DWC3_APPLE_DEVICE:
		return USB_ROLE_DEVICE;
	case DWC3_APPLE_NO_CABLE:
	case DWC3_APPLE_PROBE_PENDING:
		return USB_ROLE_NONE;
	default:
		/* Unreachable unless there's a bug in this driver */
		dev_err(appledwc->dev, "Invalid internal state: %d\n", appledwc->state);
		return USB_ROLE_NONE;
	}
}

static int dwc3_apple_setup_role_switch(struct dwc3_apple *appledwc)
{
	struct usb_role_switch_desc dwc3_role_switch = { NULL };

	dwc3_role_switch.fwnode = dev_fwnode(appledwc->dev);
	dwc3_role_switch.set = dwc3_usb_role_switch_set;
	dwc3_role_switch.get = dwc3_usb_role_switch_get;
	dwc3_role_switch.driver_data = appledwc;
	appledwc->role_sw = usb_role_switch_register(appledwc->dev, &dwc3_role_switch);
	if (IS_ERR(appledwc->role_sw))
		return PTR_ERR(appledwc->role_sw);

	return 0;
}

static int dwc3_apple_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct dwc3_apple *appledwc;
	int ret;

	appledwc = devm_kzalloc(&pdev->dev, sizeof(*appledwc), GFP_KERNEL);
	if (!appledwc)
		return -ENOMEM;

	appledwc->dev = &pdev->dev;
	mutex_init(&appledwc->lock);

	appledwc->reset = devm_reset_control_get_exclusive(dev, NULL);
	if (IS_ERR(appledwc->reset))
		return dev_err_probe(&pdev->dev, PTR_ERR(appledwc->reset),
				     "Failed to get reset control\n");

	ret = reset_control_assert(appledwc->reset);
	if (ret) {
		dev_err(&pdev->dev, "Failed to assert reset, err=%d\n", ret);
		return ret;
	}

	appledwc->mmio_resource = platform_get_resource_byname(pdev, IORESOURCE_MEM, "dwc3-core");
	if (!appledwc->mmio_resource) {
		dev_err(dev, "Failed to get DWC3 MMIO\n");
		return -EINVAL;
	}

	appledwc->apple_regs = devm_platform_ioremap_resource_byname(pdev, "dwc3-apple");
	if (IS_ERR(appledwc->apple_regs))
		return dev_err_probe(dev, PTR_ERR(appledwc->apple_regs),
				     "Failed to map Apple-specific MMIO\n");

	ret = dwc3_apple_sink_map(appledwc);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to map IOVA 0's page\n");

	/*
	 * On this platform, DWC3 can only be brought up after parts of the PHY have been
	 * initialized with knowledge of the target mode and cable orientation from typec_set_mux.
	 * Since this has not happened here we cannot setup DWC3 yet and instead defer this until
	 * the first cable is connected. See the documentation for enum dwc3_apple_state for
	 * details.
	 */
	appledwc->state = DWC3_APPLE_PROBE_PENDING;
	/*
	 * dwc3_core_probe sets the driver data only at the first connection, and remove and suspend
	 * need it before that: a controller that never saw a cable crashed when unbound.
	 */
	platform_set_drvdata(pdev, &appledwc->dwc);

	/*
	 * Active. Where runtime PM is allowed, the driver core's idle check after probe suspends a
	 * controller with no cable and drops the DARTs' link references, so genpd may power the
	 * port down; forbidden, the domain stays on.
	 */
	pm_runtime_set_active(dev);
	pm_runtime_set_autosuspend_delay(dev, DWC3_APPLE_AUTOSUSPEND_MS);
	pm_runtime_use_autosuspend(dev);
	pm_runtime_enable(dev);
	if (!of_device_is_compatible(dev->of_node, "apple,t6031-dwc3"))
		pm_runtime_forbid(dev);

	ret = dwc3_apple_setup_role_switch(appledwc);
	if (ret) {
		pm_runtime_allow(dev);
		pm_runtime_disable(dev);
		pm_runtime_dont_use_autosuspend(dev);
		pm_runtime_set_suspended(dev);
		return dev_err_probe(&pdev->dev, ret, "Failed to setup role switch\n");
	}

	return 0;
}

static void dwc3_apple_remove(struct platform_device *pdev)
{
	struct dwc3 *dwc = platform_get_drvdata(pdev);
	struct dwc3_apple *appledwc = to_dwc3_apple(dwc);

	guard(mutex)(&appledwc->lock);

	usb_role_switch_unregister(appledwc->role_sw);

	/*
	 * If we're still in DWC3_APPLE_PROBE_PENDING we never got any cable connected event and
	 * dwc3_core_probe was never called and there's hence no need to call dwc3_core_remove.
	 * dwc3_apple_exit can be called unconditionally because it checks the state itself.
	 * dwc3_core_remove() undoes runtime PM; before the first cable, the glue does.
	 */
	dwc3_apple_exit(appledwc);
	if (appledwc->state != DWC3_APPLE_PROBE_PENDING) {
		dwc3_core_remove(&appledwc->dwc);
	} else {
		pm_runtime_allow(&pdev->dev);
		pm_runtime_disable(&pdev->dev);
		pm_runtime_dont_use_autosuspend(&pdev->dev);
		pm_runtime_set_suspended(&pdev->dev);
	}
}

/*
 * With no cable, dwc3 is held in reset and holds no state worth saving: genpd may cut the power.
 * Never with a cable (the reference taken in dwc3_apple_power_init() prevents that).
 * No lock: the role switch holds appledwc->lock across synchronous runtime PM calls.
 */
static int dwc3_apple_runtime_suspend(struct device *dev)
{
	struct dwc3 *dwc = dev_get_drvdata(dev);
	enum dwc3_apple_state state;

	if (!dwc)
		return 0;

	state = READ_ONCE(to_dwc3_apple(dwc)->state);
	if (state == DWC3_APPLE_HOST || state == DWC3_APPLE_DEVICE)
		return -EBUSY;

	return 0;
}

/*
 * Nothing here saves or restores the controller across system sleep, and
 * xhci-plat's resume restarts the host controller inside a dwc3 core it expects
 * configured. While a cable is connected, keep the power domain the core shares
 * with its PHY and DARTs on: without this, genpd powered it off and the xHCI
 * completed no command after resume, hanging the hub's workers.
 */
static int dwc3_apple_suspend(struct device *dev)
{
	struct dwc3 *dwc = dev_get_drvdata(dev);
	struct dwc3_apple *appledwc;

	if (!dwc)
		return 0;

	appledwc = to_dwc3_apple(dwc);
	guard(mutex)(&appledwc->lock);
	if (appledwc->state == DWC3_APPLE_HOST || appledwc->state == DWC3_APPLE_DEVICE)
		device_set_wakeup_path(dev);

	return 0;
}

static const struct dev_pm_ops dwc3_apple_pm_ops = {
	SYSTEM_SLEEP_PM_OPS(dwc3_apple_suspend, NULL)
	RUNTIME_PM_OPS(dwc3_apple_runtime_suspend, NULL, NULL)
};

static const struct of_device_id dwc3_apple_of_match[] = {
	{ .compatible = "apple,t8103-dwc3" },
	{}
};
MODULE_DEVICE_TABLE(of, dwc3_apple_of_match);

static struct platform_driver dwc3_apple_driver = {
	.probe		= dwc3_apple_probe,
	.remove		= dwc3_apple_remove,
	.driver		= {
		.name	= "dwc3-apple",
		.of_match_table	= dwc3_apple_of_match,
		.pm	= pm_ptr(&dwc3_apple_pm_ops),
	},
};

module_platform_driver(dwc3_apple_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sven Peter <sven@kernel.org>");
MODULE_DESCRIPTION("DesignWare DWC3 Apple Silicon Glue Driver");
