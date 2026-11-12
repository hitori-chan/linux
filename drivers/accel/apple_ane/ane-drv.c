// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple Neural Engine driver
 *
 * Copyright The Asahi Linux Contributors
 */

#include <drm/drm_drv.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>

#include "ane.h"

static int ane_debugfs_boot_set(void *data, u64 val)
{
	struct apple_ane *ane = data;
	int ret = 0;

	mutex_lock(&ane->lock);
	if (val && !ane->running)
		ret = ane_fw_boot(ane);
	else if (!val && ane->running) {
		ane_job_stop(ane);
		ane_fw_shutdown(ane);
	}
	mutex_unlock(&ane->lock);
	return ret;
}

static int ane_debugfs_boot_get(void *data, u64 *val)
{
	struct apple_ane *ane = data;

	*val = ane->running;
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(ane_debugfs_boot, ane_debugfs_boot_get, ane_debugfs_boot_set, "%llu\n");

static int apple_ane_probe(struct platform_device *pdev)
{
	static const char * const pd_names[] = { "sys", "cpu", "td", "base" };
	const struct dev_pm_domain_attach_data pd_data = {
		.pd_names = pd_names,
		.num_pd_names = ARRAY_SIZE(pd_names),
	};
	struct device *dev = &pdev->dev;
	struct apple_ane *ane;
	struct resource *res;
	int ret;

	ane = devm_drm_dev_alloc(dev, &ane_drm_driver, struct apple_ane, drm);
	if (IS_ERR(ane))
		return PTR_ERR(ane);
	ane->dev = dev;
	ret = devm_mutex_init(dev, &ane->lock);
	if (ret)
		return ret;
	ret = devm_mutex_init(dev, &ane->ring_lock);
	if (ret)
		return ret;
	init_completion(&ane->cmd_done);
	INIT_LIST_HEAD(&ane->surfaces);
	INIT_LIST_HEAD(&ane->progs);
	platform_set_drvdata(pdev, ane);

	ane->regs = devm_platform_get_and_ioremap_resource(pdev, 0, &res);
	if (IS_ERR(ane->regs))
		return PTR_ERR(ane->regs);
	ane->regs_phys = res->start;
	ane->regs_ctl = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(ane->regs_ctl))
		return PTR_ERR(ane->regs_ctl);

	if (!device_iommu_mapped(dev))
		return dev_err_probe(dev, -ENODEV, "no DART\n");
	ane->domain = iommu_get_domain_for_dev(dev);

	ane->irq = platform_get_irq(pdev, 0);
	if (ane->irq < 0)
		return ane->irq;
	ret = devm_request_threaded_irq(dev, ane->irq, ane_fw_irq, ane_fw_irq_thread,
					IRQF_NO_AUTOEN | IRQF_ONESHOT, dev_name(dev), ane);
	if (ret)
		return ret;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret)
		return ret;

	ret = devm_pm_domain_attach_list(dev, &pd_data, &ane->pd_list);
	if (ret < 0)
		return dev_err_probe(dev, ret, "cannot attach the power domains\n");

	/*
	 * Nothing resumes the device before its first model, so say that it is suspended: the
	 * DARTs' links hold them active from the IOMMU's probe until the consumer's first
	 * suspend, and with them ANE_SYS, its power cluster and the fabric node behind it.
	 */
	pm_runtime_set_suspended(dev);
	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return ret;

	ane->debugfs = debugfs_create_dir(dev_name(dev), NULL);
	debugfs_create_file_unsafe("boot", 0600, ane->debugfs, ane, &ane_debugfs_boot);
	ane_job_init(ane);

	ret = ane_accel_init(ane);
	if (ret) {
		debugfs_remove_recursive(ane->debugfs);
		return dev_err_probe(dev, ret, "cannot register the accel device\n");
	}
	return 0;
}

static void apple_ane_remove(struct platform_device *pdev)
{
	struct apple_ane *ane = platform_get_drvdata(pdev);

	ane_accel_fini(ane);
	debugfs_remove_recursive(ane->debugfs);
	mutex_lock(&ane->lock);
	ane_job_fini(ane);
	if (ane->running)
		ane_fw_shutdown(ane);
	ane_fw_unload(ane);
	mutex_unlock(&ane->lock);
}

static int apple_ane_suspend(struct device *dev)
{
	struct apple_ane *ane = dev_get_drvdata(dev);

	ane_accel_suspend(ane);
	return pm_runtime_force_suspend(dev);
}

static int apple_ane_resume(struct device *dev)
{
	struct apple_ane *ane = dev_get_drvdata(dev);
	int ret;

	ret = pm_runtime_force_resume(dev);
	if (ret)
		return ret;
	ane_accel_resume(ane);
	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(apple_ane_pm, apple_ane_suspend, apple_ane_resume);

static const struct of_device_id apple_ane_of_match[] = {
	{ .compatible = "apple,t6031-ane" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, apple_ane_of_match);

static struct platform_driver apple_ane_driver = {
	.probe = apple_ane_probe,
	.remove = apple_ane_remove,
	.driver = {
		.name = APPLE_ANE_NAME,
		.of_match_table = apple_ane_of_match,
		.pm = pm_sleep_ptr(&apple_ane_pm),
		.suppress_bind_attrs = true,
	},
};
module_platform_driver(apple_ane_driver);

MODULE_DESCRIPTION("Apple Neural Engine driver");
MODULE_LICENSE("GPL");
