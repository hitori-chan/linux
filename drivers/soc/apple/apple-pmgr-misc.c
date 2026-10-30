// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple SoC PMGR device power state driver
 *
 * Copyright The Asahi Linux Contributors
 */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#define APPLE_CLKGEN_PSTATE 0
#define APPLE_CLKGEN_PSTATE_DESIRED GENMASK(3, 0)

#define DCS_DEV_PSTATE_MIN_T600X 7
#define SYS_DEV_PSTATE_SUSPEND 1

#define KEEPALIVE_MAX 2
#define KEEPALIVE_STRIDE 0x44

#define TVM_MAX 5
#define TVM_CTL_ENABLE BIT(0)
#define TVM_STATUS 0x250
#define TVM_STATUS_BUSY BIT(1)
#define TVM_TIMEOUT_US 1000

enum sys_device {
	DEV_FABRIC,
	DEV_DCS,
	DEV_MAX,
};

struct apple_pmgr_sys_device {
	void __iomem *base;
	u32 active_state;
	u32 suspend_state;
};

struct apple_pmgr_misc_hw {
	bool has_sys_devices;
	u32 dev_min_ps[DEV_MAX];
};

struct apple_pmgr_keepalive {
	void __iomem *base;
	unsigned int count;
};

struct apple_pmgr_misc {
	struct device *dev;
	struct apple_pmgr_sys_device devices[DEV_MAX];
	struct apple_pmgr_keepalive keepalive[KEEPALIVE_MAX];
	void __iomem *tvm[TVM_MAX];
	unsigned int tvm_count;
};

static void apple_pmgr_sys_dev_set_pstate(struct apple_pmgr_misc *misc,
					  enum sys_device dev, bool active)
{
	u32 pstate;
	u32 val;

	if (!misc->devices[dev].base)
		return;

	if (active)
		pstate = misc->devices[dev].active_state;
	else
		pstate = misc->devices[dev].suspend_state;

	dev_dbg(misc->dev, "set %d ps to pstate %d\n", dev, pstate);

	val = readl_relaxed(misc->devices[dev].base + APPLE_CLKGEN_PSTATE);
	FIELD_MODIFY(APPLE_CLKGEN_PSTATE_DESIRED, &val, pstate);
	writel_relaxed(val, misc->devices[dev].base + APPLE_CLKGEN_PSTATE);
}

/*
 * Word 0 of each keepalive entry: macOS sets it at boot and wake and clears
 * it before sleep (t6031). Without it the memory path sleeps between a CPU's
 * lone DRAM misses.
 */
static void apple_pmgr_misc_set_keepalive(struct apple_pmgr_misc *misc, bool on)
{
	unsigned int i, j;

	for (i = 0; i < KEEPALIVE_MAX; i++)
		for (j = 0; j < misc->keepalive[i].count; j++)
			writel_relaxed(on, misc->keepalive[i].base + j * KEEPALIVE_STRIDE);
}

/*
 * The PMGR's temperature voltage management (TVM) of a rail: SOC, DCS, FAB
 * and DISP on t6031 (DISP2's goes with the external displays' power cluster,
 * pmgr-pwrstate). iBoot leaves it off, which holds each rail's
 * voltage whatever the die's temperature; macOS turns it on at boot and wake
 * and off before sleep, waiting for the status's busy bit to clear.
 */
static void apple_pmgr_misc_set_tvm(struct apple_pmgr_misc *misc, bool on)
{
	unsigned int i;
	u32 val;

	for (i = 0; i < misc->tvm_count; i++) {
		val = readl_relaxed(misc->tvm[i]);
		if (on) {
			writel_relaxed(val | TVM_CTL_ENABLE, misc->tvm[i]);
			continue;
		}
		writel_relaxed(val & ~TVM_CTL_ENABLE, misc->tvm[i]);
		if (readl_poll_timeout_atomic(misc->tvm[i] + TVM_STATUS, val,
					      !(val & TVM_STATUS_BUSY), 1,
					      TVM_TIMEOUT_US))
			dev_warn(misc->dev, "tvm%u stays busy\n", i);
	}
}

static int __maybe_unused apple_pmgr_misc_suspend_noirq(struct device *dev)
{
	struct apple_pmgr_misc *misc = dev_get_drvdata(dev);
	int i;

	apple_pmgr_misc_set_keepalive(misc, false);
	apple_pmgr_misc_set_tvm(misc, false);

	for (i = 0; i < DEV_MAX; i++)
		apple_pmgr_sys_dev_set_pstate(misc, i, false);

	return 0;
}

static int __maybe_unused apple_pmgr_misc_resume_noirq(struct device *dev)
{
	struct apple_pmgr_misc *misc = dev_get_drvdata(dev);
	int i;

	for (i = 0; i < DEV_MAX; i++)
		apple_pmgr_sys_dev_set_pstate(misc, i, true);

	apple_pmgr_misc_set_tvm(misc, true);
	apple_pmgr_misc_set_keepalive(misc, true);

	return 0;
}

static int apple_pmgr_init_device(struct apple_pmgr_misc *misc,
				  const struct apple_pmgr_misc_hw *hw,
				  enum sys_device dev,
				  const char *device_name)
{
	void __iomem *base;
	char name[32];
	u32 val;

	snprintf(name, sizeof(name), "%s-ps", device_name);

	base = devm_platform_ioremap_resource_byname(
		to_platform_device(misc->dev), name);
	if (IS_ERR(base))
		return PTR_ERR(base);

	val = readl_relaxed(base + APPLE_CLKGEN_PSTATE);

	misc->devices[dev].base = base;
	misc->devices[dev].active_state =
		FIELD_GET(APPLE_CLKGEN_PSTATE_DESIRED, val);
	misc->devices[dev].suspend_state = hw->dev_min_ps[dev];

	return 0;
}

static int apple_pmgr_misc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct apple_pmgr_misc_hw *hw;
	struct apple_pmgr_misc *misc;
	int i, ret;

	misc = devm_kzalloc(dev, sizeof(*misc), GFP_KERNEL);
	if (!misc)
		return -ENOMEM;

	misc->dev = dev;
	hw = of_device_get_match_data(dev);
	if (!hw)
		return -EINVAL;

	if (hw->has_sys_devices) {
		ret = apple_pmgr_init_device(misc, hw, DEV_FABRIC, "fabric");
		if (ret)
			return ret;

		ret = apple_pmgr_init_device(misc, hw, DEV_DCS, "dcs");
		if (ret)
			return ret;
	}

	for (i = 0; i < KEEPALIVE_MAX; i++) {
		struct resource *res;
		char name[16];

		snprintf(name, sizeof(name), "keepalive%d", i);
		res = platform_get_resource_byname(pdev, IORESOURCE_MEM, name);
		if (!res)
			break;

		misc->keepalive[i].base = devm_ioremap_resource(dev, res);
		if (IS_ERR(misc->keepalive[i].base))
			return PTR_ERR(misc->keepalive[i].base);
		misc->keepalive[i].count = DIV_ROUND_UP(resource_size(res), KEEPALIVE_STRIDE);
	}

	for (i = 0; i < TVM_MAX; i++) {
		char name[8];

		snprintf(name, sizeof(name), "tvm%d", i);
		if (!platform_get_resource_byname(pdev, IORESOURCE_MEM, name))
			break;

		misc->tvm[i] = devm_platform_ioremap_resource_byname(pdev, name);
		if (IS_ERR(misc->tvm[i]))
			return PTR_ERR(misc->tvm[i]);
		misc->tvm_count++;
	}

	apple_pmgr_misc_set_tvm(misc, true);
	apple_pmgr_misc_set_keepalive(misc, true);

	platform_set_drvdata(pdev, misc);

	return 0;
}

static const struct apple_pmgr_misc_hw apple_pmgr_misc_hw_t600x = {
	.has_sys_devices = true,
	.dev_min_ps = {
		[DEV_FABRIC] = SYS_DEV_PSTATE_SUSPEND,
		[DEV_DCS] = DCS_DEV_PSTATE_MIN_T600X,
	},
};

static const struct apple_pmgr_misc_hw apple_pmgr_misc_hw_t602x = {
	.has_sys_devices = true,
	.dev_min_ps = {
		[DEV_FABRIC] = SYS_DEV_PSTATE_SUSPEND,
		[DEV_DCS] = SYS_DEV_PSTATE_SUSPEND,
	},
};

/* t6031: no fabric or DCS p-state in this block, the keepalive words only */
static const struct apple_pmgr_misc_hw apple_pmgr_misc_hw_t6031 = {
	.has_sys_devices = false,
};

static const struct of_device_id apple_pmgr_misc_of_match[] = {
	{ .compatible = "apple,t6000-pmgr-misc", .data = &apple_pmgr_misc_hw_t600x },
	{ .compatible = "apple,t6020-pmgr-misc", .data = &apple_pmgr_misc_hw_t602x },
	{ .compatible = "apple,t6031-pmgr-misc", .data = &apple_pmgr_misc_hw_t6031 },
	{}
};

MODULE_DEVICE_TABLE(of, apple_pmgr_misc_of_match);

static const struct dev_pm_ops apple_pmgr_misc_pm_ops = {
	SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(apple_pmgr_misc_suspend_noirq,
				      apple_pmgr_misc_resume_noirq)
};

static struct platform_driver apple_pmgr_misc_driver = {
	.probe = apple_pmgr_misc_probe,
	.driver = {
		.name = "apple-pmgr-misc",
		.of_match_table = apple_pmgr_misc_of_match,
		.pm = pm_ptr(&apple_pmgr_misc_pm_ops),
	},
};

MODULE_AUTHOR("Hector Martin <marcan@marcan.st>");
MODULE_DESCRIPTION("PMGR misc driver for Apple SoCs");
MODULE_LICENSE("GPL");

module_platform_driver(apple_pmgr_misc_driver);
