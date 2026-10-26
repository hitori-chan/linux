/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Apple JPEG codec driver
 *
 * Copyright The Asahi Linux Contributors
 */

#ifndef APPLE_JPEG_H
#define APPLE_JPEG_H

#include <linux/device.h>
#include <linux/io.h>
#include <linux/types.h>

struct apple_jpeg_tunable {
	u32 reg;
	u32 mask;
	u32 val;
};

struct apple_jpeg_core {
	phys_addr_t base;
	const struct apple_jpeg_tunable *tunables;
	unsigned int num_tunables;
};

struct apple_jpeg_dev {
	struct device *dev;
	void __iomem *regs;
	const struct apple_jpeg_core *core;
	u32 hw_version;
};

static inline u32 jpeg_read(struct apple_jpeg_dev *jpeg, u32 reg)
{
	return readl(jpeg->regs + reg);
}

static inline void jpeg_write(struct apple_jpeg_dev *jpeg, u32 reg, u32 val)
{
	writel(val, jpeg->regs + reg);
}

const struct apple_jpeg_core *apple_jpeg_hw_find_core(phys_addr_t base);
int apple_jpeg_hw_reset(struct apple_jpeg_dev *jpeg);
u32 apple_jpeg_hw_version(struct apple_jpeg_dev *jpeg);
void apple_jpeg_hw_idle(struct apple_jpeg_dev *jpeg);

#endif /* APPLE_JPEG_H */
