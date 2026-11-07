// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple Generic RTKit helper coprocessor
 * Copyright The Asahi Linux Contributors
 */

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ioport.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/soc/apple/rtkit.h>

#define APPLE_ASC_CPU_CONTROL		0x44
#define APPLE_ASC_CPU_CONTROL_RUN	BIT(4)

/*
 * How long a sleep or a wake waits for the co-processor's echo of the AP's
 * state, and how often it looks. macOS's RTBuddy waits its "timeout", 20 s
 * when the nub sets none, as the MTP's does not, then NMIs the co-processor;
 * here a missing echo changes nothing (helper->ap_asleep is what was sent),
 * so the wait stays apple_rtkit_set_ap_asleep()'s 1 s.
 */
#define APPLE_RTKIT_HELPER_AP_TIMEOUT_US	(1 * USEC_PER_SEC)
#define APPLE_RTKIT_HELPER_AP_POLL_US		(10 * USEC_PER_MSEC)

struct apple_rtkit_helper {
	struct device *dev;
	struct apple_rtkit *rtk;

	void __iomem *asc_base;

	struct resource *sram;
	void __iomem *sram_base;

	bool ap_asleep;
};

static int apple_rtkit_helper_shmem_setup(void *cookie, struct apple_rtkit_shmem *bfr)
{
	struct apple_rtkit_helper *helper = cookie;
	struct resource res = {
		.start = bfr->iova,
		.end = bfr->iova + bfr->size - 1,
		.name = "rtkit_map",
	};

	if (!bfr->iova) {
		bfr->buffer = dma_alloc_coherent(helper->dev, bfr->size,
						    &bfr->iova, GFP_KERNEL);
		if (!bfr->buffer)
			return -ENOMEM;
		return 0;
	}

	if (!helper->sram) {
		dev_err(helper->dev,
			"RTKit buffer request with no SRAM region: %pR", &res);
		return -EFAULT;
	}

	res.flags = helper->sram->flags;

	if (res.end < res.start || !resource_contains(helper->sram, &res)) {
		dev_err(helper->dev,
			"RTKit buffer request outside SRAM region: %pR", &res);
		return -EFAULT;
	}

	bfr->iomem = helper->sram_base + (res.start - helper->sram->start);
	bfr->is_mapped = true;

	return 0;
}

static void apple_rtkit_helper_shmem_destroy(void *cookie, struct apple_rtkit_shmem *bfr)
{
	// no-op
}

static const struct apple_rtkit_ops apple_rtkit_helper_ops = {
	.shmem_setup = apple_rtkit_helper_shmem_setup,
	.shmem_destroy = apple_rtkit_helper_shmem_destroy,
};

static int apple_rtkit_helper_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct apple_rtkit_helper *helper;
	int ret;

	/* 44 bits for addresses in standard RTKit requests */
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(44));
	if (ret)
		return ret;

	helper = devm_kzalloc(dev, sizeof(*helper), GFP_KERNEL);
	if (!helper)
		return -ENOMEM;

	helper->dev = dev;
	platform_set_drvdata(pdev, helper);

	helper->asc_base = devm_platform_ioremap_resource_byname(pdev, "asc");
	if (IS_ERR(helper->asc_base))
		return PTR_ERR(helper->asc_base);

	helper->sram = platform_get_resource_byname(pdev, IORESOURCE_MEM, "sram");
	if (helper->sram) {
		helper->sram_base = devm_ioremap_resource(dev, helper->sram);
		if (IS_ERR(helper->sram_base))
			return dev_err_probe(dev, PTR_ERR(helper->sram_base),
					"Failed to map SRAM region");
	}

	helper->rtk =
		devm_apple_rtkit_init(dev, helper, NULL, 0, &apple_rtkit_helper_ops);
	if (IS_ERR(helper->rtk))
		return dev_err_probe(dev, PTR_ERR(helper->rtk),
				     "Failed to intialize RTKit");

	writel_relaxed(APPLE_ASC_CPU_CONTROL_RUN,
		       helper->asc_base + APPLE_ASC_CPU_CONTROL);

	/* Works for both wake and boot */
	ret = apple_rtkit_wake(helper->rtk);
	if (ret != 0)
		return dev_err_probe(dev, ret, "Failed to wake up coprocessor");

	return 0;
}

/*
 * As macOS for the MTP (an IOP RTBuddy does not power-manage: the ADT's
 * iop-mtp-nub has sleep-on-hibernate only): the co-processor stays up
 * through a sleep and is told the AP sleeps. The MTP's firmware publishes
 * a wake (comm event 0xF2) for an input report only while the AP sleeps.
 *
 * The MTP records the AP's state as its message arrives, echoes it only
 * once its clients have run, and panics on the same state twice in a row
 * ("Invalid AP power"). So helper->ap_asleep is what was sent, not what was
 * echoed: a wake follows every sleep that went out, its echo or not, and
 * neither is sent twice.
 */
static int apple_rtkit_helper_wait_ap(struct apple_rtkit_helper *helper, bool asleep)
{
	int acked, ret;

	ret = read_poll_timeout(apple_rtkit_ap_asleep_acked, acked, acked,
				APPLE_RTKIT_HELPER_AP_POLL_US,
				APPLE_RTKIT_HELPER_AP_TIMEOUT_US, false,
				helper->rtk, asleep);
	if (ret)
		return ret;
	return acked < 0 ? acked : 0;
}

static int apple_rtkit_helper_suspend(struct device *dev)
{
	struct apple_rtkit_helper *helper = dev_get_drvdata(dev);
	int ret;

	if (helper->ap_asleep || apple_rtkit_is_crashed(helper->rtk))
		return 0;

	ret = apple_rtkit_send_ap_asleep(helper->rtk, true);
	if (ret) {
		dev_warn(dev, "Failed to report the AP's sleep: %d\n", ret);
		return 0;
	}
	helper->ap_asleep = true;

	ret = apple_rtkit_helper_wait_ap(helper, true);
	if (ret)
		dev_warn(dev, "No echo of the AP's sleep: %d\n", ret);

	return 0;
}

static int apple_rtkit_helper_resume(struct device *dev)
{
	struct apple_rtkit_helper *helper = dev_get_drvdata(dev);
	int ret;

	if (!helper->ap_asleep || apple_rtkit_is_crashed(helper->rtk))
		return 0;

	ret = apple_rtkit_send_ap_asleep(helper->rtk, false);
	if (ret) {
		dev_warn(dev, "Failed to report the AP awake: %d\n", ret);
		return 0;
	}
	helper->ap_asleep = false;

	ret = apple_rtkit_helper_wait_ap(helper, false);
	if (ret)
		dev_warn(dev, "No echo of the AP awake: %d\n", ret);

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(apple_rtkit_helper_pm_ops, apple_rtkit_helper_suspend,
				apple_rtkit_helper_resume);

static void apple_rtkit_helper_remove(struct platform_device *pdev)
{
	struct apple_rtkit_helper *helper = platform_get_drvdata(pdev);

	if (apple_rtkit_is_running(helper->rtk))
		apple_rtkit_quiesce(helper->rtk);

	writel_relaxed(0, helper->asc_base + APPLE_ASC_CPU_CONTROL);
}

static const struct of_device_id apple_rtkit_helper_of_match[] = {
	{ .compatible = "apple,rtk-helper-asc4" },
	{},
};
MODULE_DEVICE_TABLE(of, apple_rtkit_helper_of_match);

static struct platform_driver apple_rtkit_helper_driver = {
	.driver = {
		.name = "rtkit-helper",
		.of_match_table = apple_rtkit_helper_of_match,
		.pm = pm_sleep_ptr(&apple_rtkit_helper_pm_ops),
	},
	.probe = apple_rtkit_helper_probe,
	.remove = apple_rtkit_helper_remove,
};
module_platform_driver(apple_rtkit_helper_driver);

MODULE_AUTHOR("Hector Martin <marcan@marcan.st>");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Apple RTKit helper driver");
