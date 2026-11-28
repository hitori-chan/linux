// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple SoC memory cache controller: the DRAM channel controllers' dynamic
 * power gating, and the traffic counters the PMP reads
 *
 * Each AMCC has four channel controllers (DCS). iBoot leaves their dynamic
 * power gating off; macOS's SoC tuner turns it on at boot and again after
 * every wake, and drops it only while a driver holds a bus-stall limit
 * under the gate's 45 us exit latency (SD and USB storage I/O).
 *
 * The PMP's bandwidth monitors (DCS-BW, AFR-BW, the GPU's AGX-*-BW) read
 * each AMCC's second counter bank, which the AMCCs' push engines copy into
 * the PMP's dashboard: the bank's four counters, each one AMCX port's reads
 * or writes in a requester range, and one counter per plane. macOS's
 * memory-cache driver programs the bank at start and after every wake, and
 * stops it before sleep; it never reads it. iBoot leaves it off, and then
 * the PMP sees no traffic and holds DRAM, the fabric and the GPU's fabric
 * clock at their floors.
 *
 * Copyright The Asahi Linux Contributors
 */

#include <linux/bitfield.h>
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

/* The second counter bank: its four counters and each plane's one */
#define PMP_BANK_EN		0x158800
#define PMP_BANK_CFG		0x158818
#define PMP_BANK_CTL(i)		(0x158858 + 0x10 * (i))
#define PMP_PLANE(p)		(0x1c000 + 0x40000 * (p))
#define PMP_PLANE_EN(p)		(PMP_PLANE(p) + 0x8800)
#define PMP_PLANE_CFG(p)	(PMP_PLANE(p) + 0x8810)
#define PMP_PLANE_CTL(p)	(PMP_PLANE(p) + 0x8858)

/* macOS's constants, not decoded: a bank's or plane's configuration, ctl1's 43:36 */
#define PMP_CFG			0x103fff00000000ULL
#define PMP_CTL1_ANY		GENMASK_ULL(43, 36)
#define PMP_CTL0_LO		GENMASK_ULL(19, 0)
#define PMP_CTL0_HI		GENMASK_ULL(39, 20)
#define PMP_CTL0_PLANE_DIR	GENMASK_ULL(57, 56)
#define PMP_CTL1_DIR		GENMASK_ULL(49, 48)
#define PMP_CTL1_PORT		GENMASK_ULL(53, 52)

/* dir: 0 reads, 1 writes, 2 both; a plane row has plane >= 0 and idx 0 */
struct apple_mcc_pmp_row {
	u8 amcc;
	s8 plane;
	u8 idx;
	u8 port;
	u8 dir;
	u32 lo, hi;
};

#define PMP_BANK_ROW(a, i, p, d, l, h) \
	{ .amcc = a, .plane = -1, .idx = i, .port = p, .dir = d, .lo = l, .hi = h }
#define PMP_PLANE_ROW(a, pl, d, l, h) \
	{ .amcc = a, .plane = pl, .idx = 0, .dir = d, .lo = l, .hi = h }

/*
 * macOS's rows for the PMP, in its order (AppleH15MCD's _kCounterTypes[1],
 * die 0), used up to the first one whose AMCC is absent: rows 0-41 on t6034.
 */
static const struct apple_mcc_pmp_row apple_mcc_pmp_rows[] = {
	PMP_BANK_ROW(0, 0, 0, 0, 0x01000, 0x01005),
	PMP_PLANE_ROW(0, 0, 0, 0x01000, 0x01005),
	PMP_BANK_ROW(0, 1, 0, 1, 0x01000, 0x01005),
	PMP_PLANE_ROW(0, 1, 1, 0x01000, 0x01005),
	PMP_BANK_ROW(0, 2, 0, 0, 0x02000, 0x02005),
	PMP_PLANE_ROW(0, 2, 0, 0x02000, 0x02005),
	PMP_BANK_ROW(0, 3, 0, 1, 0x02000, 0x02005),
	PMP_PLANE_ROW(0, 3, 1, 0x02000, 0x02005),
	PMP_BANK_ROW(1, 0, 0, 0, 0x00000, 0x00005),
	PMP_PLANE_ROW(1, 0, 0, 0x00000, 0x00005),
	PMP_BANK_ROW(1, 1, 0, 1, 0x00000, 0x00005),
	PMP_PLANE_ROW(1, 1, 1, 0x00000, 0x00005),
	PMP_BANK_ROW(1, 2, 2, 0, 0x2a100, 0x31149),
	PMP_BANK_ROW(1, 3, 2, 1, 0x2a100, 0x31149),
	PMP_PLANE_ROW(1, 2, 0, 0x2a100, 0x31149),
	PMP_PLANE_ROW(1, 3, 1, 0x2a100, 0x31149),
	PMP_BANK_ROW(2, 0, 0, 0, 0x00000, 0x3ffff),
	PMP_BANK_ROW(2, 1, 0, 1, 0x00000, 0x3ffff),
	PMP_BANK_ROW(2, 2, 1, 0, 0x00000, 0x3ffff),
	PMP_BANK_ROW(2, 3, 1, 1, 0x00000, 0x3ffff),
	PMP_BANK_ROW(3, 0, 2, 0, 0x00000, 0x3ffff),
	PMP_BANK_ROW(3, 1, 2, 1, 0x00000, 0x3ffff),
	PMP_BANK_ROW(3, 2, 3, 0, 0x00000, 0x3ffff),
	PMP_BANK_ROW(3, 3, 3, 1, 0x00000, 0x3ffff),
	PMP_PLANE_ROW(2, 0, 0, 0x00000, 0x3ffff),
	PMP_PLANE_ROW(2, 1, 1, 0x00000, 0x3ffff),
	PMP_PLANE_ROW(2, 2, 0, 0x111c0, 0x111c4),
	PMP_PLANE_ROW(2, 3, 1, 0x111c0, 0x111c4),
	PMP_BANK_ROW(4, 0, 1, 0, 0x14280, 0x1429b),
	PMP_PLANE_ROW(3, 0, 0, 0x14280, 0x1429b),
	PMP_BANK_ROW(4, 1, 1, 1, 0x14280, 0x1429b),
	PMP_PLANE_ROW(3, 1, 1, 0x14280, 0x1429b),
	PMP_BANK_ROW(4, 2, 1, 0, 0x142c0, 0x142e9),
	PMP_PLANE_ROW(3, 2, 0, 0x142c0, 0x142e9),
	PMP_BANK_ROW(4, 3, 1, 1, 0x142c0, 0x142e9),
	PMP_PLANE_ROW(3, 3, 1, 0x142c0, 0x142e9),
	PMP_BANK_ROW(5, 0, 1, 0, 0x15500, 0x15510),
	PMP_BANK_ROW(5, 1, 1, 1, 0x15500, 0x15510),
	PMP_BANK_ROW(5, 2, 2, 0, 0x15500, 0x15510),
	PMP_PLANE_ROW(4, 0, 0, 0x15500, 0x15510),
	PMP_BANK_ROW(5, 3, 2, 1, 0x15500, 0x15510),
	PMP_PLANE_ROW(4, 1, 1, 0x15500, 0x15510),
	PMP_BANK_ROW(6, 0, 1, 0, 0x10200, 0x10208),
	PMP_PLANE_ROW(4, 2, 0, 0x10200, 0x10208),
	PMP_BANK_ROW(6, 1, 1, 1, 0x10200, 0x10208),
	PMP_PLANE_ROW(4, 3, 1, 0x10200, 0x10208),
	PMP_PLANE_ROW(5, 0, 0, 0x15240, 0x15248),
	PMP_PLANE_ROW(5, 1, 1, 0x15240, 0x15248),
	PMP_BANK_ROW(6, 2, 1, 0, 0x11680, 0x116bf),
	PMP_PLANE_ROW(5, 2, 0, 0x11680, 0x116bf),
	PMP_BANK_ROW(6, 3, 1, 1, 0x11680, 0x116bf),
	PMP_PLANE_ROW(5, 3, 1, 0x11680, 0x116bf),
	PMP_BANK_ROW(7, 0, 1, 2, 0x12700, 0x12732),
	PMP_BANK_ROW(7, 1, 1, 2, 0x12740, 0x12772),
	PMP_BANK_ROW(7, 2, 1, 2, 0x12780, 0x127b2),
	PMP_BANK_ROW(7, 3, 1, 2, 0x127c0, 0x127f2),
};

struct apple_mcc {
	struct device *dev;
	void __iomem **amcc;
	unsigned int namcc;
	void __iomem **dcs;
	unsigned int ndcs;
};

static bool power_gating = true;
module_param(power_gating, bool, 0444);
MODULE_PARM_DESC(power_gating, "Gate the DRAM channel controllers when idle (default on)");

static bool pmp_counters = true;
module_param(pmp_counters, bool, 0444);
MODULE_PARM_DESC(pmp_counters, "Count the memory traffic for the PMP's DVFS (default on)");

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

/*
 * As macOS: on, each row's two control words (after the first, an index-0
 * row's bank or plane configuration), then its enable bit; off, the enable
 * bits alone, the words kept.
 */
static void apple_mcc_pmp_set(struct apple_mcc *mcc, bool on)
{
	unsigned int k;

	if (!pmp_counters)
		return;

	for (k = 0; k < ARRAY_SIZE(apple_mcc_pmp_rows); k++) {
		const struct apple_mcc_pmp_row *r = &apple_mcc_pmp_rows[k];
		void __iomem *base;
		u64 ctl0, ctl1, en;
		u32 ctl, cfg, enr;

		if (r->amcc >= mcc->namcc)
			break;
		base = mcc->amcc[r->amcc];

		ctl0 = FIELD_PREP(PMP_CTL0_LO, r->lo) | FIELD_PREP(PMP_CTL0_HI, r->hi);
		if (r->plane >= 0) {
			ctl0 |= FIELD_PREP(PMP_CTL0_PLANE_DIR, r->dir + 1);
			ctl1 = PMP_CTL1_ANY;
			ctl = PMP_PLANE_CTL(r->plane);
			cfg = PMP_PLANE_CFG(r->plane);
			enr = PMP_PLANE_EN(r->plane);
		} else {
			ctl1 = PMP_CTL1_ANY | FIELD_PREP(PMP_CTL1_DIR, r->dir + 1) |
			       FIELD_PREP(PMP_CTL1_PORT, r->port);
			ctl = PMP_BANK_CTL(r->idx);
			cfg = PMP_BANK_CFG;
			enr = PMP_BANK_EN;
		}

		if (on) {
			writeq(ctl0, base + ctl);
			if (r->idx == 0)
				writeq(PMP_CFG, base + cfg);
			writeq(ctl1, base + ctl + 8);
		}

		en = readq(base + enr);
		if (on)
			en |= BIT_ULL(r->idx);
		else
			en &= ~BIT_ULL(r->idx);
		writeq(en, base + enr);
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
	mcc->namcc = namcc;
	mcc->amcc = devm_kcalloc(dev, namcc, sizeof(*mcc->amcc), GFP_KERNEL);
	mcc->ndcs = namcc * DCS_PER_AMCC;
	mcc->dcs = devm_kcalloc(dev, mcc->ndcs, sizeof(*mcc->dcs), GFP_KERNEL);
	if (!mcc->amcc || !mcc->dcs)
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

		mcc->amcc[n] = amcc;
		for (d = 0; d < DCS_PER_AMCC; d++)
			mcc->dcs[n * DCS_PER_AMCC + d] = amcc + DCS_OFFSET + d * DCS_STRIDE;
	}

	platform_set_drvdata(pdev, mcc);
	apple_mcc_apply(mcc);
	apple_mcc_pmp_set(mcc, true);
	dev_info(dev, "%u AMCCs, %u channel controllers, dynamic power gating %s, PMP counters %s\n",
		 namcc, mcc->ndcs, power_gating ? "on" : "left to the bootloader",
		 pmp_counters ? "on" : "off");

	return 0;
}

static int apple_mcc_suspend(struct device *dev)
{
	/* macOS stops the counters before its sleep; s2idle keeps them */
	if (pm_suspend_via_firmware())
		apple_mcc_pmp_set(dev_get_drvdata(dev), false);
	return 0;
}

static int apple_mcc_resume(struct device *dev)
{
	struct apple_mcc *mcc = dev_get_drvdata(dev);

	/*
	 * Only after a sleep that reset the controllers: macOS writes the gate
	 * on a state change only, and s2idle keeps the register.
	 */
	if (pm_suspend_via_firmware()) {
		apple_mcc_apply(mcc);
		apple_mcc_pmp_set(mcc, true);
	}
	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(apple_mcc_pm_ops, apple_mcc_suspend, apple_mcc_resume);

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

MODULE_DESCRIPTION("Apple SoC memory cache controller power gating and PMP counters");
MODULE_LICENSE("GPL");
