// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple JPEG codec driver
 *
 * Copyright The Asahi Linux Contributors
 *
 * The codec runs no firmware: the host programs one job at a time through
 * its registers. The sequences follow macOS's AppleJPEGDriver (jpeg-hw.c);
 * the V4L2 side is a stateful mem2mem decoder (jpeg-v4l2.c).
 */

#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>

#include "jpeg.h"

static bool enable;
module_param(enable, bool, 0444);
MODULE_PARM_DESC(enable, "Bind the codec (default: off, the driver is not verified on hardware)");

struct apple_jpeg_variant {
	u32 hw_version;
};

static int apple_jpeg_probe(struct platform_device *pdev)
{
	const struct apple_jpeg_variant *variant;
	struct device *dev = &pdev->dev;
	struct apple_jpeg_dev *jpeg;
	struct resource *res;
	int irq, ret;

	if (!enable) {
		dev_info(dev, "disabled, load with enable=1 to bind\n");
		return -ENODEV;
	}

	variant = of_device_get_match_data(dev);

	jpeg = devm_kzalloc(dev, sizeof(*jpeg), GFP_KERNEL);
	if (!jpeg)
		return -ENOMEM;
	jpeg->dev = dev;
	ret = devm_mutex_init(dev, &jpeg->lock);
	if (ret)
		return ret;
	spin_lock_init(&jpeg->hw_lock);
	INIT_DELAYED_WORK(&jpeg->timeout_work, apple_jpeg_timeout_work);
	platform_set_drvdata(pdev, jpeg);

	jpeg->regs = devm_platform_get_and_ioremap_resource(pdev, 0, &res);
	if (IS_ERR(jpeg->regs))
		return PTR_ERR(jpeg->regs);

	jpeg->core = apple_jpeg_hw_find_core(res->start);
	if (!jpeg->core)
		dev_warn(dev, "no tunables for the core at %pa\n", &res->start);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	/* the DMA end addresses reset to 0xf_ffffffff (inferred) */
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(36));
	if (ret)
		return dev_err_probe(dev, ret, "failed to set the DMA mask\n");

	pm_runtime_set_autosuspend_delay(dev, 100);
	pm_runtime_use_autosuspend(dev);
	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return ret;

	/* AppleJPEGHalV8::checkHardwareVersion */
	ret = pm_runtime_resume_and_get(dev);
	if (ret)
		return dev_err_probe(dev, ret, "failed to power up\n");
	jpeg->hw_version = apple_jpeg_hw_version(jpeg);
	pm_runtime_put_autosuspend(dev);

	if (jpeg->hw_version != variant->hw_version)
		return dev_err_probe(dev, -ENODEV,
				     "hardware version %#x, expected %#x\n",
				     jpeg->hw_version, variant->hw_version);
	dev_info(dev, "hardware version %#x\n", jpeg->hw_version);

	ret = devm_request_threaded_irq(dev, irq, NULL, apple_jpeg_irq_thread,
					IRQF_ONESHOT, dev_name(dev), jpeg);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request the IRQ\n");

	return apple_jpeg_v4l2_register(jpeg);
}

static void apple_jpeg_remove(struct platform_device *pdev)
{
	struct apple_jpeg_dev *jpeg = platform_get_drvdata(pdev);

	apple_jpeg_v4l2_unregister(jpeg);
}

/* AppleJPEGHalV8::setActive_gated: the codec is reset on every power-up */
static int apple_jpeg_runtime_resume(struct device *dev)
{
	struct apple_jpeg_dev *jpeg = dev_get_drvdata(dev);

	return apple_jpeg_hw_reset(jpeg);
}

static int apple_jpeg_runtime_suspend(struct device *dev)
{
	struct apple_jpeg_dev *jpeg = dev_get_drvdata(dev);

	apple_jpeg_hw_idle(jpeg);
	return 0;
}

/*
 * The running job finishes, or times out, before the power goes: force
 * suspend alone would cut it mid-DMA and leave the timeout armed.
 */
static int apple_jpeg_suspend(struct device *dev)
{
	struct apple_jpeg_dev *jpeg = dev_get_drvdata(dev);

	v4l2_m2m_suspend(jpeg->m2m_dev);
	cancel_delayed_work_sync(&jpeg->timeout_work);
	return pm_runtime_force_suspend(dev);
}

static int apple_jpeg_resume(struct device *dev)
{
	struct apple_jpeg_dev *jpeg = dev_get_drvdata(dev);
	int ret;

	ret = pm_runtime_force_resume(dev);
	if (ret)
		return ret;
	v4l2_m2m_resume(jpeg->m2m_dev);
	return 0;
}

static const struct dev_pm_ops apple_jpeg_pm_ops = {
	SYSTEM_SLEEP_PM_OPS(apple_jpeg_suspend, apple_jpeg_resume)
	RUNTIME_PM_OPS(apple_jpeg_runtime_suspend, apple_jpeg_runtime_resume,
		       NULL)
};

/*
 * AppleJPEGDriver::start: the ADT's hw-type 0xf1008 & 0xffff0fff; t6030's
 * and t8122's hw-type 0xf0008 takes the same V8 HAL
 */
static const struct apple_jpeg_variant apple_jpeg_t6031 = {
	.hw_version = JPEG_HW_VERSION_T6031,
};

static const struct of_device_id apple_jpeg_of_match[] = {
	{ .compatible = "apple,t6030-jpeg", .data = &apple_jpeg_t6031 },
	{ .compatible = "apple,t6031-jpeg", .data = &apple_jpeg_t6031 },
	{ .compatible = "apple,t8122-jpeg", .data = &apple_jpeg_t6031 },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, apple_jpeg_of_match);

static struct platform_driver apple_jpeg_driver = {
	.probe = apple_jpeg_probe,
	.remove = apple_jpeg_remove,
	.driver = {
		.name = "apple-jpeg",
		.of_match_table = apple_jpeg_of_match,
		.pm = pm_ptr(&apple_jpeg_pm_ops),
	},
};
module_platform_driver(apple_jpeg_driver);

MODULE_DESCRIPTION("Apple JPEG codec driver");
MODULE_LICENSE("GPL");
