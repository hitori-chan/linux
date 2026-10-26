// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple JPEG codec: register sequences
 *
 * Copyright The Asahi Linux Contributors
 *
 * Ported from macOS's AppleJPEGDriver 6.6.2 (AppleJPEGHalV8 with the
 * PhloxFunctions platform class). The AXI wrapper the macOS driver also
 * tunes is left alone: its power domain is not known.
 */

#include <linux/array_size.h>
#include <linux/kernel.h>

#include "jpeg.h"
#include "jpeg-regs.h"

#define JPEG_POLL_TRIES		10001

/*
 * Per-core tunables (jpeg0_tunable, jpeg1_tunable), applied on every reset.
 * PhloxFunctions::_setupTunables picks the table by the core's base address.
 */
static const struct apple_jpeg_tunable jpeg0_tunables[] = {
	{ 0x098, 0xff, 0x01 }, { 0x0a8, 0xff, 0x02 }, { 0x0c8, 0xff, 0x03 },
	{ 0x0d8, 0xff, 0x04 }, { 0x298, 0xff, 0x05 }, { 0x29c, 0xff, 0x06 },
	{ 0x2b4, 0xff, 0x07 }, { 0x2b8, 0xff, 0x08 }, { 0x294, 0xff, 0x07 },
	{ 0x2b0, 0xff, 0x07 }, { 0x0b8, 0xff, 0x7f }, { 0x0bc, 0xff, 0x7f },
};

static const struct apple_jpeg_tunable jpeg1_tunables[] = {
	{ 0x098, 0xff, 0x09 }, { 0x0a8, 0xff, 0x0a }, { 0x0c8, 0xff, 0x0b },
	{ 0x0d8, 0xff, 0x0c }, { 0x298, 0xff, 0x0d }, { 0x29c, 0xff, 0x0e },
	{ 0x2b4, 0xff, 0x0f }, { 0x2b8, 0xff, 0x10 }, { 0x294, 0xff, 0x07 },
	{ 0x2b0, 0xff, 0x07 }, { 0x0b8, 0xff, 0x7f }, { 0x0bc, 0xff, 0x7f },
};

static const struct apple_jpeg_core apple_jpeg_cores[] = {
	{ 0x2cf000000, jpeg0_tunables, ARRAY_SIZE(jpeg0_tunables) },
	{ 0x2cf008000, jpeg1_tunables, ARRAY_SIZE(jpeg1_tunables) },
};

struct apple_jpeg_reg_val {
	u16 reg;
	u32 val;
};

/*
 * ajpeg_driver_set_default_regs, in its order. JPEG_DEBUG (0x19c) takes the
 * macOS driver's "jpeg-log" debug flag, 0 here.
 */
static const struct apple_jpeg_reg_val apple_jpeg_defaults[] = {
	{ 0x000, 0 }, { 0x004, 0 }, { 0x028, 0 }, { 0x02c, 0 },
	{ 0x030, 0 }, { 0x034, 1 }, { 0x038, 1 }, { 0x03c, 0 },
	{ 0x040, 0 }, { 0x044, 0 }, { 0x048, 0 }, { 0x04c, 0 },
	{ 0x050, 0 }, { 0x054, 0 }, { 0x198, 0 }, { 0x058, 0 },
	{ 0x05c, 1 }, { 0x060, 1 }, { 0x064, 1 }, { 0x068, 1 },
	{ 0x06c, 1 }, { 0x070, 1 }, { 0x074, 1 }, { 0x078, 1 },
	{ 0x07c, 1 }, { 0x080, 1 }, { 0x084, 1 }, { 0x088, 1 },
	{ 0x090, 0 }, { 0x0a0, 0 }, { 0x0b8, 1 }, { 0x0bc, 1 },
	{ 0x0b0, 0xffffffff }, { 0x0c0, 0 }, { 0x0d0, 0 },
	{ 0x0e0, 0xffffffff }, { 0x094, 0 }, { 0x0a4, 0 },
	{ 0x0b4, 0xf }, { 0x0c4, 0 }, { 0x0d4, 0 }, { 0x0e4, 0xf },
	{ 0x0e8, 0 }, { 0x0ec, 0 }, { 0x0f0, 0 }, { 0x0f4, 0 },
	{ 0x0f8, 0 }, { 0x0fc, 0 }, { 0x100, 0 }, { 0x104, 0 },
	{ 0x108, 0 }, { 0x10c, 0 }, { 0x110, 0 },
	{ 0x13c, 0 }, { 0x140, 0 }, { 0x144, 0 }, { 0x148, 0 },
	{ 0x14c, 0 }, { 0x150, 0 }, { 0x154, 0 }, { 0x158, 0 },
	{ 0x16c, 0 }, { 0x170, 0 }, { 0x184, 0 }, { 0x188, 0 },
	{ 0x18c, 0 }, { 0x190, 0 }, { 0x194, 0 }, { 0x174, 0 },
	{ 0x178, 0 }, { 0x17c, 0 }, { 0x180, 0 },
	{ 0x238, 0 }, { 0x240, 0 }, { 0x248, 0 }, { 0x250, 0 },
	{ 0x24c, 0 }, { 0x254, 0 }, { 0x23c, 0 }, { 0x244, 0 },
	{ 0x260, 0 }, { 0x264, 0 }, { 0x268, 0 }, { 0x26c, 0 },
	{ 0x270, 0 }, { 0x274, 0 }, { 0x278, 0 }, { 0x27c, 0 },
	{ 0x280, 0x1f40 }, { 0x290, 0 }, { 0x294, 7 }, { 0x2ac, 0 },
	{ 0x2b0, 7 }, { 0x288, 0 }, { 0x28c, 0 }, { 0x2a4, 0 },
	{ 0x2a8, 0 }, { 0x218, 0 }, { 0x220, 0 }, { 0x224, 0 },
	{ 0x21c, 0 }, { 0x228, 0 }, { 0x230, 0 }, { 0x234, 0 },
	{ 0x22c, 0 }, { 0x19c, 0 }, { 0x1c0, 0 }, { 0x020, 0xff },
};

/* reset_jpeg_block clears these once the soft reset is done */
static const u16 apple_jpeg_reset_clear[] = {
	JPEG_1DC, JPEG_1E4, JPEG_SLICE_INDEX, JPEG_SLICE_MORE,
	JPEG_SLICE_BYTES, JPEG_HDR_BYTES, JPEG_MCU_IMG_W, JPEG_MCU_IMG_H,
	JPEG_CROP_EN, JPEG_CROP_X, JPEG_CROP_Y, JPEG_CROP_W,
};

const struct apple_jpeg_core *apple_jpeg_hw_find_core(phys_addr_t base)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(apple_jpeg_cores); i++)
		if (apple_jpeg_cores[i].base == base)
			return &apple_jpeg_cores[i];

	return NULL;
}

static void apple_jpeg_hw_set_defaults(struct apple_jpeg_dev *jpeg)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(apple_jpeg_defaults); i++)
		jpeg_write(jpeg, apple_jpeg_defaults[i].reg,
			   apple_jpeg_defaults[i].val);
}

static void apple_jpeg_hw_set_tunables(struct apple_jpeg_dev *jpeg)
{
	const struct apple_jpeg_core *core = jpeg->core;
	unsigned int i;
	u32 val;

	if (!core)
		return;

	for (i = 0; i < core->num_tunables; i++) {
		const struct apple_jpeg_tunable *t = &core->tunables[i];

		val = jpeg_read(jpeg, t->reg);
		val = (val & ~t->mask) | (t->val & t->mask);
		jpeg_write(jpeg, t->reg, val);
	}
}

/* AppleJPEGHalV8::reset_jpeg_block */
int apple_jpeg_hw_reset(struct apple_jpeg_dev *jpeg)
{
	unsigned int i;
	u32 val;

	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_RESET);
	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_SETUP);
	jpeg_write(jpeg, JPEG_START, 0);
	apple_jpeg_hw_set_defaults(jpeg);
	apple_jpeg_hw_set_tunables(jpeg);
	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_PROGRAM);

	for (i = 0; i < JPEG_POLL_TRIES; i++) {
		val = jpeg_read(jpeg, JPEG_GO);
		if (!val)
			break;
	}
	if (val) {
		dev_err(jpeg->dev, "soft reset failed (1): %#x\n", val);
		return -ETIMEDOUT;
	}

	for (i = 0; i < JPEG_POLL_TRIES; i++) {
		jpeg_write(jpeg, JPEG_RESET_ACK, 1);
		val = jpeg_read(jpeg, JPEG_RESET_ACK);
		if (val == 1)
			break;
	}
	if (val != 1) {
		dev_err(jpeg->dev, "soft reset failed (2): %#x\n", val);
		return -ETIMEDOUT;
	}
	jpeg_write(jpeg, JPEG_RESET_ACK, 0);

	for (i = 0; i < ARRAY_SIZE(apple_jpeg_reset_clear); i++)
		jpeg_write(jpeg, apple_jpeg_reset_clear[i], 0);

	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_IDLE);

	return 0;
}

/* AppleJPEGHalV8::checkHardwareVersion, with the core powered and reset */
u32 apple_jpeg_hw_version(struct apple_jpeg_dev *jpeg)
{
	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_VERSION);
	return jpeg_read(jpeg, JPEG_HW_VERSION);
}

/* the last register write of AppleJPEGHalV8::setActive_gated(false) */
void apple_jpeg_hw_idle(struct apple_jpeg_dev *jpeg)
{
	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_IDLE);
}
