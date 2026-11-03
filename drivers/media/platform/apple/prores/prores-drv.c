// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple ProRes codec driver
 *
 * Copyright The Asahi Linux Contributors
 */

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>

#include "prores.h"
#include "prores-regs.h"

/* APR_FindDevRev and SetDevFeatureList's major 3: v0 descriptors */
#define APR_VERSION_T6031	0x30014

static int apple_prores_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct apple_prores_dev *apr;
	struct resource *res;
	int irq, ret;

	apr = devm_kzalloc(dev, sizeof(*apr), GFP_KERNEL);
	if (!apr)
		return -ENOMEM;
	apr->dev = dev;
	ret = devm_mutex_init(dev, &apr->lock);
	if (ret)
		return ret;
	spin_lock_init(&apr->hw_lock);
	INIT_DELAYED_WORK(&apr->timeout_work, apple_prores_timeout_work);
	platform_set_drvdata(pdev, apr);

	apr->regs = devm_platform_get_and_ioremap_resource(pdev, 0, &res);
	if (IS_ERR(apr->regs))
		return PTR_ERR(apr->regs);
	apr->axi2af = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(apr->axi2af))
		return PTR_ERR(apr->axi2af);

	apr->core = apple_prores_hw_find_core(res->start);
	if (!apr->core)
		return dev_err_probe(dev, -ENODEV, "no tunables for the core at %pa\n",
				     &res->start);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	/* the ring's high word holds 10 bits */
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(42));
	if (ret)
		return dev_err_probe(dev, ret, "failed to set the DMA mask\n");

	apr->ring = dmam_alloc_coherent(dev, APR_RING_SIZE, &apr->ring_dma,
					GFP_KERNEL);
	if (!apr->ring)
		return -ENOMEM;
	apr->stats = dmam_alloc_coherent(dev, APR_STATS_SIZE, &apr->stats_dma,
					 GFP_KERNEL);
	if (!apr->stats)
		return -ENOMEM;

	pm_runtime_set_autosuspend_delay(dev, 100);
	pm_runtime_use_autosuspend(dev);
	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return ret;

	ret = pm_runtime_resume_and_get(dev);
	if (ret)
		return dev_err_probe(dev, ret, "failed to power up\n");
	apr->version = apr_read(apr, APR_VERSION);
	pm_runtime_put_autosuspend(dev);

	if (apr->version != APR_VERSION_T6031)
		return dev_err_probe(dev, -ENODEV, "hardware version %#x, expected %#x\n",
				     apr->version, APR_VERSION_T6031);
	dev_info(dev, "hardware version %#x\n", apr->version);

	ret = devm_request_threaded_irq(dev, irq, NULL, apple_prores_irq_thread,
					IRQF_ONESHOT, dev_name(dev), apr);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request the IRQ\n");

	return apple_prores_v4l2_register(apr);
}

static void apple_prores_remove(struct platform_device *pdev)
{
	apple_prores_v4l2_unregister(platform_get_drvdata(pdev));
}

static int apple_prores_runtime_resume(struct device *dev)
{
	apple_prores_hw_activate(dev_get_drvdata(dev));
	return 0;
}

static int apple_prores_runtime_suspend(struct device *dev)
{
	apple_prores_hw_deactivate(dev_get_drvdata(dev));
	return 0;
}

static int apple_prores_suspend(struct device *dev)
{
	struct apple_prores_dev *apr = dev_get_drvdata(dev);

	v4l2_m2m_suspend(apr->m2m_dev);
	cancel_delayed_work_sync(&apr->timeout_work);
	return pm_runtime_force_suspend(dev);
}

static int apple_prores_resume(struct device *dev)
{
	struct apple_prores_dev *apr = dev_get_drvdata(dev);
	int ret;

	ret = pm_runtime_force_resume(dev);
	if (ret)
		return ret;
	v4l2_m2m_resume(apr->m2m_dev);
	return 0;
}

static const struct dev_pm_ops apple_prores_pm_ops = {
	SYSTEM_SLEEP_PM_OPS(apple_prores_suspend, apple_prores_resume)
	RUNTIME_PM_OPS(apple_prores_runtime_suspend, apple_prores_runtime_resume,
		       NULL)
};

static const struct of_device_id apple_prores_of_match[] = {
	{ .compatible = "apple,t6031-prores" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, apple_prores_of_match);

static struct platform_driver apple_prores_driver = {
	.probe = apple_prores_probe,
	.remove = apple_prores_remove,
	.driver = {
		.name = APPLE_PRORES_NAME,
		.of_match_table = apple_prores_of_match,
		.pm = pm_ptr(&apple_prores_pm_ops),
	},
};
module_platform_driver(apple_prores_driver);

MODULE_DESCRIPTION("Apple ProRes codec driver");
MODULE_LICENSE("GPL");
