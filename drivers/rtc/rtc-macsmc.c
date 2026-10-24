// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple SMC RTC driver
 * Copyright The Asahi Linux Contributors
 */

#include <linux/bitops.h>
#include <linux/mfd/macsmc.h>
#include <linux/module.h>
#include <linux/nvmem-consumer.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/rtc.h>
#include <linux/slab.h>

/* 48-bit RTC */
#define RTC_BYTES 6
#define RTC_BITS (8 * RTC_BYTES)

/* 32768 Hz clock */
#define RTC_SEC_SHIFT 15

/*
 * The PMU's alarm, as macOS's AppleDialogSPMIPMURTC::programRTCAlarm drives
 * it, with the ADT's masks: the control register holds the alarm's event
 * (info-rtc_alarm_event_mask, write 1 to clear), the monitor bit
 * (info-rtc_alarm_monitor_mask) and the enable (info-rtc_alarm_ctrl_en_mask);
 * the alarm register is the seconds count (the counter's ticks >> 15) to
 * match; the interrupt mask's info-rtc_alarm_mask bit masks it.
 */
#define RTC_ALARM_EVENT		BIT(1)
#define RTC_ALARM_MONITOR	BIT(0)
#define RTC_ALARM_ENABLE	BIT(6)
#define RTC_ALARM_IRQ_MASK	BIT(0)

struct macsmc_rtc {
	struct device *dev;
	struct apple_smc *smc;
	struct rtc_device *rtc_dev;
	struct nvmem_cell *rtc_offset;
	struct nvmem_cell *alarm_ctrl;
	struct nvmem_cell *alarm;
	struct nvmem_cell *irq_mask;
	struct notifier_block nb;
	/* The armed alarm in counter seconds, 0 for none */
	u32 alarm_secs;
};

static int macsmc_rtc_read_offset(struct macsmc_rtc *rtc, s64 *off)
{
	void *p_off;
	size_t len;
	u64 v = 0;

	p_off = nvmem_cell_read(rtc->rtc_offset, &len);
	if (IS_ERR(p_off))
		return PTR_ERR(p_off);
	if (len < RTC_BYTES) {
		kfree(p_off);
		return -EIO;
	}

	memcpy(&v, p_off, RTC_BYTES);
	kfree(p_off);
	*off = sign_extend64(v, RTC_BITS - 1);
	return 0;
}

static int macsmc_rtc_read_u8(struct nvmem_cell *cell, u8 *val)
{
	void *p;
	size_t len;

	p = nvmem_cell_read(cell, &len);
	if (IS_ERR(p))
		return PTR_ERR(p);
	*val = len ? *(u8 *)p : 0;
	kfree(p);
	return len ? 0 : -EIO;
}

/* Arms the alarm at counter second @secs, or disarms it for 0 */
static int macsmc_rtc_program_alarm(struct macsmc_rtc *rtc, u32 secs)
{
	u8 ctrl, mask = secs ? 0 : RTC_ALARM_IRQ_MASK;
	__le32 val = cpu_to_le32(secs);
	int ret;

	ret = macsmc_rtc_read_u8(rtc->alarm_ctrl, &ctrl);
	if (ret)
		return ret;
	if (ctrl & RTC_ALARM_EVENT) {
		ctrl = RTC_ALARM_EVENT;
		ret = nvmem_cell_write(rtc->alarm_ctrl, &ctrl, 1);
		if (ret < 0)
			return ret;
	}
	if (secs) {
		ret = nvmem_cell_write(rtc->alarm, &val, sizeof(val));
		if (ret < 0)
			return ret;
	}
	ret = nvmem_cell_write(rtc->irq_mask, &mask, 1);
	if (ret < 0)
		return ret;
	ctrl = RTC_ALARM_MONITOR | (secs ? RTC_ALARM_ENABLE : 0);
	ret = nvmem_cell_write(rtc->alarm_ctrl, &ctrl, 1);
	if (ret < 0)
		return ret;
	rtc->alarm_secs = secs;
	return 0;
}

static int macsmc_rtc_get_time(struct device *dev, struct rtc_time *tm)
{
	struct macsmc_rtc *rtc = dev_get_drvdata(dev);
	u64 ctr = 0, off = 0;
	time64_t now;
	void *p_off;
	size_t len;
	int ret;

	ret = apple_smc_read(rtc->smc, SMC_KEY(CLKM), &ctr, RTC_BYTES);
	if (ret < 0)
		return ret;
	if (ret != RTC_BYTES)
		return -EIO;

	p_off = nvmem_cell_read(rtc->rtc_offset, &len);
	if (IS_ERR(p_off))
		return PTR_ERR(p_off);
	if (len < RTC_BYTES) {
		kfree(p_off);
		return -EIO;
	}

	memcpy(&off, p_off, RTC_BYTES);
	kfree(p_off);

	/* Sign extend from 48 to 64 bits, then arithmetic shift right 15 bits to get seconds */
	now = sign_extend64(ctr + off, RTC_BITS - 1) >> RTC_SEC_SHIFT;
	rtc_time64_to_tm(now, tm);

	return ret;
}

static int macsmc_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct macsmc_rtc *rtc = dev_get_drvdata(dev);
	u64 ctr = 0, off = 0;
	int ret;

	ret = apple_smc_read(rtc->smc, SMC_KEY(CLKM), &ctr, RTC_BYTES);
	if (ret < 0)
		return ret;
	if (ret != RTC_BYTES)
		return -EIO;

	/* This sets the offset such that the set second begins now */
	off = (rtc_tm_to_time64(tm) << RTC_SEC_SHIFT) - ctr;
	return nvmem_cell_write(rtc->rtc_offset, &off, RTC_BYTES);
}

static int macsmc_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *wkalrm)
{
	struct macsmc_rtc *rtc = dev_get_drvdata(dev);
	__le32 *p;
	size_t len;
	s64 off;
	u32 secs;
	u8 ctrl;
	int ret;

	ret = macsmc_rtc_read_offset(rtc, &off);
	if (ret)
		return ret;
	ret = macsmc_rtc_read_u8(rtc->alarm_ctrl, &ctrl);
	if (ret)
		return ret;
	p = nvmem_cell_read(rtc->alarm, &len);
	if (IS_ERR(p))
		return PTR_ERR(p);
	secs = len >= sizeof(*p) ? le32_to_cpu(*p) : 0;
	kfree(p);

	wkalrm->enabled = !!(ctrl & RTC_ALARM_ENABLE);
	wkalrm->pending = !!(ctrl & RTC_ALARM_EVENT);
	rtc_time64_to_tm((((s64)secs << RTC_SEC_SHIFT) + off) >> RTC_SEC_SHIFT, &wkalrm->time);
	return 0;
}

static int macsmc_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *wkalrm)
{
	struct macsmc_rtc *rtc = dev_get_drvdata(dev);
	s64 off;
	u32 secs;
	int ret;

	ret = macsmc_rtc_read_offset(rtc, &off);
	if (ret)
		return ret;

	/* The counter second at which the RTC reads the alarm's time */
	secs = ((rtc_tm_to_time64(&wkalrm->time) << RTC_SEC_SHIFT) - off) >> RTC_SEC_SHIFT;
	if (!secs)
		return -ERANGE;
	return macsmc_rtc_program_alarm(rtc, wkalrm->enabled ? secs : 0);
}

static int macsmc_rtc_alarm_irq_enable(struct device *dev, unsigned int enabled)
{
	struct macsmc_rtc *rtc = dev_get_drvdata(dev);
	struct rtc_wkalrm wkalrm;
	int ret;

	if (!enabled)
		return macsmc_rtc_program_alarm(rtc, 0);
	ret = macsmc_rtc_read_alarm(dev, &wkalrm);
	if (ret)
		return ret;
	wkalrm.enabled = 1;
	return macsmc_rtc_set_alarm(dev, &wkalrm);
}

/*
 * The PMU's alarm wakes the SMC, which wakes the system; which notification
 * it sends is not known, so every one checks the alarm's event while it is
 * armed.
 */
static int macsmc_rtc_event(struct notifier_block *nb, unsigned long event, void *data)
{
	struct macsmc_rtc *rtc = container_of(nb, struct macsmc_rtc, nb);
	u8 ctrl;

	bool fired;

	rtc_lock(rtc->rtc_dev);
	fired = rtc->alarm_secs && !macsmc_rtc_read_u8(rtc->alarm_ctrl, &ctrl) &&
		(ctrl & RTC_ALARM_EVENT);
	if (fired)
		macsmc_rtc_program_alarm(rtc, 0);
	rtc_unlock(rtc->rtc_dev);
	if (!fired)
		return NOTIFY_DONE;

	dev_dbg(rtc->dev, "alarm on SMC event %08lx\n", event);
	pm_wakeup_dev_event(rtc->dev, 0, true);
	rtc_update_irq(rtc->rtc_dev, 1, RTC_AF | RTC_IRQF);
	return NOTIFY_DONE;
}

static const struct rtc_class_ops macsmc_rtc_ops = {
	.read_time = macsmc_rtc_get_time,
	.set_time = macsmc_rtc_set_time,
};

static const struct rtc_class_ops macsmc_rtc_alarm_ops = {
	.read_time = macsmc_rtc_get_time,
	.set_time = macsmc_rtc_set_time,
	.read_alarm = macsmc_rtc_read_alarm,
	.set_alarm = macsmc_rtc_set_alarm,
	.alarm_irq_enable = macsmc_rtc_alarm_irq_enable,
};

static void macsmc_rtc_unregister(void *data)
{
	struct macsmc_rtc *rtc = data;

	blocking_notifier_chain_unregister(&rtc->smc->event_handlers, &rtc->nb);
}

static struct nvmem_cell *macsmc_rtc_alarm_cell(struct device *dev, const char *name)
{
	struct nvmem_cell *cell = devm_nvmem_cell_get(dev, name);

	return IS_ERR(cell) ? NULL : cell;
}

static int macsmc_rtc_probe(struct platform_device *pdev)
{
	struct apple_smc *smc = dev_get_drvdata(pdev->dev.parent);
	struct macsmc_rtc *rtc;
	int ret;

	/*
	 * MFD will probe this device even without a node in the device tree,
	 * thus bail out early if the SMC on the current machines does not
	 * support RTC and has no node in the device tree.
	 */
	if (!pdev->dev.of_node)
		return -ENODEV;

	rtc = devm_kzalloc(&pdev->dev, sizeof(*rtc), GFP_KERNEL);
	if (!rtc)
		return -ENOMEM;

	rtc->dev = &pdev->dev;
	rtc->smc = smc;

	rtc->rtc_offset = devm_nvmem_cell_get(&pdev->dev, "rtc_offset");
	if (IS_ERR(rtc->rtc_offset))
		return dev_err_probe(&pdev->dev, PTR_ERR(rtc->rtc_offset),
				     "Failed to get rtc_offset NVMEM cell\n");

	rtc->rtc_dev = devm_rtc_allocate_device(&pdev->dev);
	if (IS_ERR(rtc->rtc_dev))
		return PTR_ERR(rtc->rtc_dev);

	rtc->rtc_dev->ops = &macsmc_rtc_ops;
	rtc->rtc_dev->range_min = S64_MIN >> (RTC_SEC_SHIFT + (64 - RTC_BITS));
	rtc->rtc_dev->range_max = S64_MAX >> (RTC_SEC_SHIFT + (64 - RTC_BITS));

	platform_set_drvdata(pdev, rtc);

	/* The PMU's alarm, where the device tree names its registers */
	rtc->alarm_ctrl = macsmc_rtc_alarm_cell(&pdev->dev, "rtc_alarm_ctrl");
	rtc->alarm = macsmc_rtc_alarm_cell(&pdev->dev, "rtc_alarm");
	rtc->irq_mask = macsmc_rtc_alarm_cell(&pdev->dev, "rtc_irq_mask");
	if (rtc->alarm_ctrl && rtc->alarm && rtc->irq_mask) {
		rtc->rtc_dev->ops = &macsmc_rtc_alarm_ops;
		rtc->nb.notifier_call = macsmc_rtc_event;
		blocking_notifier_chain_register(&smc->event_handlers, &rtc->nb);
		ret = devm_add_action_or_reset(&pdev->dev, macsmc_rtc_unregister, rtc);
		if (ret)
			return ret;
		device_init_wakeup(&pdev->dev, true);
	} else {
		clear_bit(RTC_FEATURE_ALARM, rtc->rtc_dev->features);
	}

	return devm_rtc_register_device(rtc->rtc_dev);
}

static const struct of_device_id macsmc_rtc_of_table[] = {
	{ .compatible = "apple,smc-rtc", },
	{}
};
MODULE_DEVICE_TABLE(of, macsmc_rtc_of_table);

static struct platform_driver macsmc_rtc_driver = {
	.driver = {
		.name = "macsmc-rtc",
		.of_match_table = macsmc_rtc_of_table,
	},
	.probe = macsmc_rtc_probe,
};
module_platform_driver(macsmc_rtc_driver);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Apple SMC RTC driver");
MODULE_AUTHOR("Hector Martin <marcan@marcan.st>");
