// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple SoC memory cache controller: the DRAM channel controllers' dynamic
 * power gating
 *
 * Each AMCC has four channel controllers (DCS). iBoot leaves their dynamic
 * power gating off; macOS's SoC tuner turns it on at boot and again after
 * every wake, and drops it only while a driver holds a bus-stall limit
 * under the gate's 45 us exit latency (SD and USB storage I/O).
 *
 * Copyright The Asahi Linux Contributors
 */

#include <linux/bits.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/suspend.h>

#define DCS_OFFSET		0x200000
#define DCS_STRIDE		0x200000
#define DCS_PER_AMCC		4

#define DCS_CTRL		0x20
#define DCS_CTRL_CLK_GATE	BIT(8)
#define DCS_CTRL_PWR_GATE	BIT(12)

struct apple_mcc {
	struct device *dev;
	void __iomem **dcs;
	unsigned int ndcs;
};

static bool power_gating = true;
module_param(power_gating, bool, 0444);
MODULE_PARM_DESC(power_gating, "Gate the DRAM channel controllers when idle (default on)");

static void apple_mcc_apply(struct apple_mcc *mcc)
{
	unsigned int i;

	if (!power_gating)
		return;

	for (i = 0; i < mcc->ndcs; i++) {
		void __iomem *reg = mcc->dcs[i] + DCS_CTRL;

		writel(readl(reg) | DCS_CTRL_PWR_GATE | DCS_CTRL_CLK_GATE, reg);
	}
}

static int apple_mcc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct apple_mcc *mcc;
	unsigned int namcc, n, d;

	namcc = pdev->num_resources;
	if (!namcc)
		return -EINVAL;

	mcc = devm_kzalloc(dev, sizeof(*mcc), GFP_KERNEL);
	if (!mcc)
		return -ENOMEM;

	mcc->dev = dev;
	mcc->ndcs = namcc * DCS_PER_AMCC;
	mcc->dcs = devm_kcalloc(dev, mcc->ndcs, sizeof(*mcc->dcs), GFP_KERNEL);
	if (!mcc->dcs)
		return -ENOMEM;

	for (n = 0; n < namcc; n++) {
		struct resource *res;
		void __iomem *amcc;

		/*
		 * Mapped from the resource, so that the bus's nonposted-mmio
		 * holds: posted writes to the AMCCs hung the boot.
		 */
		amcc = devm_platform_get_and_ioremap_resource(pdev, n, &res);
		if (IS_ERR(amcc))
			return PTR_ERR(amcc);
		if (resource_size(res) < DCS_OFFSET + DCS_PER_AMCC * DCS_STRIDE)
			return dev_err_probe(dev, -EINVAL, "AMCC %u: bad register range\n", n);

		for (d = 0; d < DCS_PER_AMCC; d++)
			mcc->dcs[n * DCS_PER_AMCC + d] = amcc + DCS_OFFSET + d * DCS_STRIDE;
	}

	platform_set_drvdata(pdev, mcc);
	apple_mcc_apply(mcc);
	dev_info(dev, "%u AMCCs, %u channel controllers, dynamic power gating %s\n", namcc,
		 mcc->ndcs, power_gating ? "on" : "left to the bootloader");

	return 0;
}

static int apple_mcc_resume(struct device *dev)
{
	/*
	 * Only after a sleep that reset the controllers: macOS writes the gate
	 * on a state change only, and s2idle keeps the register.
	 */
	if (pm_suspend_via_firmware())
		apple_mcc_apply(dev_get_drvdata(dev));
	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(apple_mcc_pm_ops, NULL, apple_mcc_resume);

static const struct of_device_id apple_mcc_of_match[] = {
	{ .compatible = "apple,t6031-mcc" },
	{}
};
MODULE_DEVICE_TABLE(of, apple_mcc_of_match);

static struct platform_driver apple_mcc_driver = {
	.driver = {
		.name = "apple-mcc",
		.of_match_table = apple_mcc_of_match,
		.pm = pm_sleep_ptr(&apple_mcc_pm_ops),
	},
	.probe = apple_mcc_probe,
};
module_platform_driver(apple_mcc_driver);

MODULE_DESCRIPTION("Apple SoC memory cache controller power gating");
MODULE_LICENSE("GPL");
