// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE) driver
 *
 * Copyright The Asahi Linux Contributors
 */

#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>

#include "ave.h"

static int apple_ave_probe(struct platform_device *pdev)
{
	static const char * const pd_names[] = { "sys", "dma", "pipe4", "pipe5", "me0", "me1" };
	const struct dev_pm_domain_attach_data pd_data = {
		.pd_names = pd_names,
		.num_pd_names = ARRAY_SIZE(pd_names),
	};
	struct device *dev = &pdev->dev;
	struct apple_ave *ave;
	int ret;

	ave = devm_kzalloc(dev, sizeof(*ave), GFP_KERNEL);
	if (!ave)
		return -ENOMEM;
	ave->dev = dev;
	ret = devm_mutex_init(dev, &ave->lock);
	if (ret)
		return ret;
	spin_lock_init(&ave->hw_lock);
	platform_set_drvdata(pdev, ave);

	ret = of_alias_get_id(dev->of_node, "ave");
	if (ret < 0)
		return dev_err_probe(dev, ret, "no ave alias\n");
	ave->instance = ret;

	ave->iop = devm_platform_ioremap_resource_byname(pdev, "iop");
	if (IS_ERR(ave->iop))
		return PTR_ERR(ave->iop);
	ave->mbox = devm_platform_ioremap_resource_byname(pdev, "mbox");
	if (IS_ERR(ave->mbox))
		return PTR_ERR(ave->mbox);
	ave->axi2af = devm_platform_ioremap_resource_byname(pdev, "axi2af");
	if (IS_ERR(ave->axi2af))
		return PTR_ERR(ave->axi2af);

	if (!device_iommu_mapped(dev))
		return dev_err_probe(dev, -ENODEV, "no DART\n");

	ret = ave_fw_parse(ave);
	if (ret)
		return ret;

	init_completion(&ave->event);
	/* the first line is the mailbox's; the firmware's other lines are not needed here */
	ave->irq = platform_get_irq(pdev, 0);
	if (ave->irq < 0)
		return ave->irq;
	ret = devm_request_irq(dev, ave->irq, ave_fw_irq, IRQF_NO_AUTOEN, dev_name(dev), ave);
	if (ret)
		return ret;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret)
		return ret;

	ret = devm_pm_domain_attach_list(dev, &pd_data, &ave->pd_list);
	if (ret < 0)
		return dev_err_probe(dev, ret, "cannot attach the power domains\n");

	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return ret;

	/* once through, so that its DARTs and their domain go off until the first frame */
	ret = pm_runtime_resume_and_get(dev);
	if (ret)
		return ret;
	pm_runtime_put(dev);

	ave->wq = alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, dev_name(dev));
	if (!ave->wq)
		return -ENOMEM;

	ret = ave_v4l2_register(ave);
	if (ret)
		destroy_workqueue(ave->wq);
	return ret;
}

static void apple_ave_remove(struct platform_device *pdev)
{
	struct apple_ave *ave = platform_get_drvdata(pdev);

	ave_v4l2_unregister(ave);
	destroy_workqueue(ave->wq);
}

/* A session does not survive the power domains: the next frame starts one, with an IDR */
static int apple_ave_suspend(struct device *dev)
{
	struct apple_ave *ave = dev_get_drvdata(dev);

	v4l2_m2m_suspend(ave->m2m_dev);
	flush_workqueue(ave->wq);
	mutex_lock(&ave->lock);
	if (ave->owner && ave->owner->running)
		ave_session_stop(ave->owner);
	mutex_unlock(&ave->lock);
	return 0;
}

static int apple_ave_resume(struct device *dev)
{
	v4l2_m2m_resume(((struct apple_ave *)dev_get_drvdata(dev))->m2m_dev);
	return 0;
}

static const struct dev_pm_ops apple_ave_pm_ops = {
	SYSTEM_SLEEP_PM_OPS(apple_ave_suspend, apple_ave_resume)
};

static const struct of_device_id apple_ave_of_match[] = {
	{ .compatible = "apple,t6031-ave" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, apple_ave_of_match);

static struct platform_driver apple_ave_driver = {
	.probe = apple_ave_probe,
	.remove = apple_ave_remove,
	.driver = {
		.name = APPLE_AVE_NAME,
		.of_match_table = apple_ave_of_match,
		.pm = pm_ptr(&apple_ave_pm_ops),
	},
};
module_platform_driver(apple_ave_driver);

MODULE_DESCRIPTION("Apple video encoder driver");
MODULE_LICENSE("GPL");
