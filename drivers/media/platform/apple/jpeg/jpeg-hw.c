// SPDX-License-Identifier: GPL-2.0-only
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
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/unaligned.h>

#include <media/v4l2-jpeg.h>

#include "jpeg.h"

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

const struct apple_jpeg_core *apple_jpeg_hw_find_core(u64 base)
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

/*
 * dcd_cmp_yuv_444/422/411/420/400: per output mode, a width divisor and the
 * four counts of set_decode_mbcounts. The macOS driver uses one table for
 * 4:4:4 and 4:0:0 sources.
 */
static const u32 apple_jpeg_dcd[5][8][5] = {
	[APPLE_JPEG_SS_444] = {
		{ 0x08, 0x01, 0x08, 0x02, 0x08 }, { 0x10, 0x02, 0x08, 0x02, 0x08 },
		{ 0x10, 0x02, 0x08, 0x02, 0x04 }, { 0x10, 0x04, 0x08, 0x01, 0x01 },
		{ 0 }, { 0x08, 0x04, 0x08, 0x01, 0x01 },
		{ 0x08, 0x02, 0x08, 0x01, 0x01 }, { 0 },
	},
	[APPLE_JPEG_SS_422] = {
		{ 0 }, { 0x10, 0x02, 0x08, 0x02, 0x08 },
		{ 0x10, 0x02, 0x08, 0x02, 0x04 }, { 0x10, 0x04, 0x08, 0x01, 0x01 },
		{ 0 }, { 0x10, 0x08, 0x08, 0x01, 0x01 },
		{ 0x10, 0x04, 0x08, 0x01, 0x01 }, { 0 },
	},
	[APPLE_JPEG_SS_411] = {
		{ 0 }, { 0x20, 0x04, 0x08, 0x04, 0x08 },
		{ 0x20, 0x04, 0x08, 0x04, 0x04 }, { 0x20, 0x08, 0x08, 0x00, 0x00 },
		{ 0 }, { 0x20, 0x10, 0x08, 0x00, 0x00 },
		{ 0x20, 0x08, 0x08, 0x00, 0x00 }, { 0 },
	},
	[APPLE_JPEG_SS_420] = {
		{ 0 }, { 0x10, 0x02, 0x10, 0x02, 0x10 },
		{ 0x10, 0x02, 0x10, 0x02, 0x08 }, { 0x10, 0x04, 0x10, 0x00, 0x00 },
		{ 0 }, { 0x10, 0x08, 0x10, 0x00, 0x00 },
		{ 0x10, 0x04, 0x10, 0x00, 0x00 }, { 0 },
	},
	[APPLE_JPEG_SS_400] = {
		{ 0x08, 0x01, 0x08, 0x02, 0x08 }, { 0x10, 0x02, 0x08, 0x02, 0x08 },
		{ 0x10, 0x02, 0x08, 0x02, 0x04 }, { 0x10, 0x04, 0x08, 0x01, 0x01 },
		{ 0 }, { 0x08, 0x04, 0x08, 0x01, 0x01 },
		{ 0x08, 0x02, 0x08, 0x01, 0x01 }, { 0 },
	},
};

/* the MCU and the arguments of ajpeg_drv_wrcnvset_w_h, per subsampling */
static const struct {
	u8 w, h, vhalf, hdiv;
} apple_jpeg_mcus[] = {
	[APPLE_JPEG_SS_444] = { 8, 8, 0, 0 },
	[APPLE_JPEG_SS_422] = { 16, 8, 0, 1 },
	[APPLE_JPEG_SS_411] = { 32, 8, 0, 2 },
	[APPLE_JPEG_SS_420] = { 16, 16, 1, 1 },
	[APPLE_JPEG_SS_400] = { 8, 8, 0, 0 },
};

/*
 * decoder_req2setup: the JFIF YCbCr to RGB matrix (BT.601, full range),
 * x256 in two's complement (0xffffffa8 = -0x58), then the offsets.
 */
static const u32 apple_jpeg_csc[JPEG_CSC_WORDS] = {
	0x100, 0, 0x167, 0x100, 0xffffffa8, 0xffffff49, 0x100, 0x1c6,
	0, 0, 0xffffff80,
};

struct apple_jpeg_boundary {
	u32 two_planes;
	u32 p0_width;
	u32 height;
	u32 p1_width;
	u32 p1_height;
	u32 timeout;
};

/* ajpeg_driver_check_setup_decode */
static int apple_jpeg_check_setup(const struct apple_jpeg_job *job)
{
	u32 mode = job->fmt->mode, submode = job->fmt->submode;

	if (job->subsampling > APPLE_JPEG_SS_400 || mode > 7)
		return -EINVAL;
	if ((BIT(mode) & (BIT(0) | BIT(1) | BIT(2))) && submode)
		return -EINVAL;
	if ((BIT(mode) & (BIT(4) | BIT(6) | BIT(7))) && submode)
		return -EINVAL;
	if (submode > 1 || mode == 4 || mode == 7)
		return -EINVAL;
	if (mode == APPLE_JPEG_MODE_YUV444_2P &&
	    job->subsampling != APPLE_JPEG_SS_444 &&
	    job->subsampling != APPLE_JPEG_SS_400)
		return -EINVAL;
	if (job->scale != 1 && job->scale != 2 && job->scale != 4 &&
	    job->scale != 8)
		return -EINVAL;
	if (!apple_jpeg_dcd[job->subsampling][mode][0])
		return -EINVAL;

	return 0;
}

/* ajpeg_drv_set_image_boundary, without the register writes */
static int apple_jpeg_boundary(const struct apple_jpeg_job *job,
			       struct apple_jpeg_boundary *b)
{
	u32 s = job->scale, w, h;
	bool packed = false;
	u64 timeout;

	w = DIV_ROUND_UP(job->width, s);
	h = DIV_ROUND_UP(job->height, s);
	b->p0_width = w;
	b->height = h;
	b->two_planes = 1;
	b->p1_height = h;

	switch (job->fmt->mode) {
	case APPLE_JPEG_MODE_YUV444_2P:
		b->p1_width = 2 * w;
		break;
	case APPLE_JPEG_MODE_YUV422_2P:
		b->p1_width = ALIGN(w, 2);
		break;
	case APPLE_JPEG_MODE_YUV420_2P:
		b->p1_width = ALIGN(w, 2);
		b->p1_height = (h + 1) / 2;
		break;
	case APPLE_JPEG_MODE_YUV422_1P:
		b->p0_width = (2 * w + 2) & ~3;
		packed = true;
		break;
	case APPLE_JPEG_MODE_RGB565:
		b->p0_width = 2 * w;
		packed = true;
		break;
	default:
		b->p0_width = 4 * w;
		packed = true;
		break;
	}

	if (packed) {
		b->two_planes = 0;
		b->p1_width = 0;
		b->p1_height = 0;
	}

	/*
	 * The macOS driver computes this in 32 bits, which wraps for the
	 * largest RGB outputs: saturate instead.
	 */
	timeout = 6ULL * s * s *
		  ((u64)b->p1_width * b->p1_height + (u64)b->p0_width * h) +
		  0x3f6b5a0;
	b->timeout = clamp_t(u64, timeout, 0xfdad680, U32_MAX);

	if (b->p0_width > job->stride)
		return -EINVAL;
	if (!packed && b->p1_width > job->stride)
		return -EINVAL;

	return 0;
}

static void apple_jpeg_set_boundary(struct apple_jpeg_dev *jpeg,
				    const struct apple_jpeg_boundary *b)
{
	jpeg_write(jpeg, JPEG_TWO_PLANES, b->two_planes);
	jpeg_write(jpeg, JPEG_P0_WIDTH, b->p0_width - 1);
	jpeg_write(jpeg, JPEG_P0_HEIGHT, b->height - 1);
	jpeg_write(jpeg, JPEG_P1_WIDTH, b->p1_width - 1);
	jpeg_write(jpeg, JPEG_P1_HEIGHT, b->p1_height - 1);
	jpeg_write(jpeg, JPEG_HW_TIMEOUT, b->timeout);
}

/* ajpeg_drv_wrcnvset_w_h */
static void apple_jpeg_set_last_mcu(struct apple_jpeg_dev *jpeg,
				    const struct apple_jpeg_job *job)
{
	u32 mw = apple_jpeg_mcus[job->subsampling].w;
	u32 mh = apple_jpeg_mcus[job->subsampling].h;
	u32 cols = DIV_ROUND_UP(job->width, mw);
	u32 rows = DIV_ROUND_UP(job->height, mh);
	u32 lw = job->width - cols * mw + mw;
	u32 lh = job->height - rows * mh + mh;
	u32 lcw = lw, lch = lh;

	jpeg_write(jpeg, JPEG_MCU_COLS, cols);
	jpeg_write(jpeg, JPEG_MCU_ROWS2, rows);
	jpeg_write(jpeg, JPEG_MCU_ROWS, rows);
	jpeg_write(jpeg, JPEG_LAST_W, lw);
	jpeg_write(jpeg, JPEG_LAST_H, lh);

	if (apple_jpeg_mcus[job->subsampling].vhalf)
		lch = (lh + 1) / 2;
	if (apple_jpeg_mcus[job->subsampling].hdiv == 1)
		lcw = (lw + 1) / 2;
	else if (apple_jpeg_mcus[job->subsampling].hdiv == 2)
		lcw = (lw + 3) / 4;

	jpeg_write(jpeg, JPEG_LAST_CW, lcw);
	jpeg_write(jpeg, JPEG_LAST_CH, lch);
}

/* the resampling enables of ajpeg_drv_setx_decode_CMP_YUV_* */
static void apple_jpeg_set_resample(struct apple_jpeg_dev *jpeg,
				    const struct apple_jpeg_job *job)
{
	u32 mode = job->fmt->mode;
	u32 r044 = job->scale == 8 ? JPEG_RESAMPLE_198 : JPEG_RESAMPLE_044;
	bool rgb = mode == APPLE_JPEG_MODE_ARGB || mode == APPLE_JPEG_MODE_RGB565;

	switch (job->subsampling) {
	case APPLE_JPEG_SS_444:
		if (mode == APPLE_JPEG_MODE_YUV420_2P) {
			jpeg_write(jpeg, JPEG_RESAMPLE_03C, 1);
			jpeg_write(jpeg, r044, 1);
		} else if (mode == APPLE_JPEG_MODE_YUV422_2P ||
			   mode == APPLE_JPEG_MODE_YUV422_1P) {
			jpeg_write(jpeg, JPEG_RESAMPLE_03C, 1);
		}
		break;
	case APPLE_JPEG_SS_422:
		if (rgb)
			jpeg_write(jpeg, JPEG_RESAMPLE_04C, 1);
		else if (mode == APPLE_JPEG_MODE_YUV420_2P)
			jpeg_write(jpeg, r044, 1);
		break;
	case APPLE_JPEG_SS_411:
		if (mode == APPLE_JPEG_MODE_YUV422_2P ||
		    mode == APPLE_JPEG_MODE_YUV422_1P) {
			jpeg_write(jpeg, JPEG_RESAMPLE_04C, 1);
		} else if (mode == APPLE_JPEG_MODE_YUV420_2P) {
			jpeg_write(jpeg, JPEG_RESAMPLE_04C, 1);
			jpeg_write(jpeg, r044, 1);
		} else if (rgb) {
			jpeg_write(jpeg, JPEG_RESAMPLE_050, 1);
		}
		break;
	case APPLE_JPEG_SS_420:
		if (rgb) {
			jpeg_write(jpeg, JPEG_RESAMPLE_04C, 1);
			jpeg_write(jpeg, JPEG_RESAMPLE_054, 1);
		} else if (mode == APPLE_JPEG_MODE_YUV422_2P ||
			   mode == APPLE_JPEG_MODE_YUV422_1P) {
			jpeg_write(jpeg, JPEG_RESAMPLE_054, 1);
		}
		break;
	case APPLE_JPEG_SS_400:
		if (mode == APPLE_JPEG_MODE_YUV422_2P)
			jpeg_write(jpeg, JPEG_RESAMPLE_03C, 1);
		break;
	}
}

/* ajpeg_drv_set_decode_mbcounts */
static void apple_jpeg_set_mbcounts(struct apple_jpeg_dev *jpeg,
				    const struct apple_jpeg_job *job)
{
	const u32 *dcd = apple_jpeg_dcd[job->subsampling][job->fmt->mode];
	u32 s = job->scale;

	apple_jpeg_set_last_mcu(jpeg, job);
	apple_jpeg_set_resample(jpeg, job);

	jpeg_write(jpeg, JPEG_DCD_CNT4,
		   DIV_ROUND_UP(DIV_ROUND_UP(job->width, dcd[0]), s));
	jpeg_write(jpeg, JPEG_DCD_CNT0, dcd[1]);
	jpeg_write(jpeg, JPEG_DCD_CNT1, DIV_ROUND_UP(dcd[2], s));
	jpeg_write(jpeg, JPEG_DCD_CNT2, dcd[3]);
	jpeg_write(jpeg, JPEG_DCD_CNT3, DIV_ROUND_UP(dcd[4], s));
}

/* ajpeg_drv_set_decode_submode */
static void apple_jpeg_set_submode(struct apple_jpeg_dev *jpeg,
				   const struct apple_jpeg_job *job)
{
	u32 mode = job->fmt->mode, submode = job->fmt->submode;
	unsigned int i;

	if (mode == APPLE_JPEG_MODE_ARGB || mode == APPLE_JPEG_MODE_RGB565)
		for (i = 0; i < JPEG_CSC_WORDS; i++)
			jpeg_write(jpeg, JPEG_CSC(i), apple_jpeg_csc[i]);

	if (mode == APPLE_JPEG_MODE_ARGB) {
		jpeg_write(jpeg, JPEG_ALPHA, 0xff);
		jpeg_write(jpeg, JPEG_SUBMODE_RGB, !!submode);
	} else if (mode == APPLE_JPEG_MODE_YUV422_1P) {
		jpeg_write(jpeg, JPEG_SUBMODE_YUV, !!submode);
	}
}

/* ajpeg_set_dcd_scaling */
static u32 apple_jpeg_scale_code(u32 scale)
{
	static const u32 codes[] = { 0, 1, 3, 2 };

	return scale - 1 < ARRAY_SIZE(codes) ? codes[scale - 1] : 3;
}

/* ajpeg_drv_set_pointers */
static void apple_jpeg_set_pointers(struct apple_jpeg_dev *jpeg,
				    const struct apple_jpeg_job *job)
{
	bool two_planes = job->fmt->vsub;
	dma_addr_t rd = job->src + job->data_offset;
	dma_addr_t rd_end = job->src + job->src_size - 1;
	dma_addr_t wr0 = job->dst;
	dma_addr_t wr1 = two_planes ? job->dst + job->plane1_offset : job->dst;
	dma_addr_t wr_end = job->dst + job->dst_size - 1;

	jpeg_write(jpeg, JPEG_RD0_LO, lower_32_bits(rd));
	jpeg_write(jpeg, JPEG_RD1_LO, lower_32_bits(rd));
	jpeg_write(jpeg, JPEG_RD_END_LO, lower_32_bits(rd_end));
	jpeg_write(jpeg, JPEG_WR0_LO, lower_32_bits(wr0));
	jpeg_write(jpeg, JPEG_WR1_LO, lower_32_bits(wr1));
	jpeg_write(jpeg, JPEG_WR_END_LO, lower_32_bits(wr_end));
	jpeg_write(jpeg, JPEG_RD0_HI, upper_32_bits(rd));
	jpeg_write(jpeg, JPEG_RD1_HI, upper_32_bits(rd));
	jpeg_write(jpeg, JPEG_RD_END_HI, upper_32_bits(rd_end));
	jpeg_write(jpeg, JPEG_WR0_HI, upper_32_bits(wr0));
	jpeg_write(jpeg, JPEG_WR1_HI, upper_32_bits(wr1));
	jpeg_write(jpeg, JPEG_WR_END_HI, upper_32_bits(wr_end));
	jpeg_write(jpeg, JPEG_P0_STRIDE, job->stride);
	jpeg_write(jpeg, JPEG_P1_STRIDE, two_planes ? job->stride : 0);
}

/*
 * AppleJPEGHalV8::startDecoderGated with ajpeg_drv_set_decode: program one
 * decode and start it.
 */
int apple_jpeg_hw_decode(struct apple_jpeg_dev *jpeg,
			 const struct apple_jpeg_job *job)
{
	u32 mode = job->fmt->mode, run, i;
	struct apple_jpeg_boundary b;
	int ret;

	ret = apple_jpeg_check_setup(job);
	if (ret)
		return ret;
	ret = apple_jpeg_boundary(job, &b);
	if (ret)
		return ret;
	if (job->hdr_len > JPEG_HDR_WINDOW_SIZE || job->hdr_len % 4)
		return -EINVAL;

	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_SETUP);
	jpeg_write(jpeg, JPEG_START, 0);
	apple_jpeg_hw_set_defaults(jpeg);
	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_PROGRAM);

	jpeg_write(jpeg, JPEG_034, 1);
	jpeg_write(jpeg, JPEG_ENCODE, 0);
	jpeg_write(jpeg, JPEG_038, 0);
	jpeg_write(jpeg, JPEG_SUBSAMPLING, job->subsampling);
	jpeg_write(jpeg, JPEG_OUT_MODE, mode);
	apple_jpeg_set_boundary(jpeg, &b);
	jpeg_write(jpeg, JPEG_0B8, 0x1f);
	jpeg_write(jpeg, JPEG_0BC, 1);
	apple_jpeg_set_mbcounts(jpeg, job);
	apple_jpeg_set_submode(jpeg, job);
	jpeg_write(jpeg, JPEG_SCALE, apple_jpeg_scale_code(job->scale));
	apple_jpeg_set_pointers(jpeg, job);

	for (i = 0; i < job->hdr_len; i += 4)
		jpeg_write(jpeg, JPEG_HDR_WINDOW + i,
			   get_unaligned_le32(job->hdr + i));

	/* a single slice; no crop (the reset cleared JPEG_CROP_*) */
	jpeg_write(jpeg, JPEG_SLICE_INDEX, 0);
	jpeg_write(jpeg, JPEG_SLICE_MORE, 0);
	jpeg_write(jpeg, JPEG_SLICE_BYTES, job->slice_bytes);
	jpeg_write(jpeg, JPEG_HDR_BYTES, job->hdr_len);
	jpeg_write(jpeg, JPEG_MCU_IMG_W, 0);
	jpeg_write(jpeg, JPEG_MCU_IMG_H, 0);

	if (mode == APPLE_JPEG_MODE_ARGB || mode == APPLE_JPEG_MODE_RGB565)
		run = JPEG_RUN_RGB;
	else
		run = JPEG_RUN_YUV;

	jpeg_write(jpeg, JPEG_154, 0);
	jpeg_write(jpeg, JPEG_158, 1);
	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_RUN(run));
	jpeg_write(jpeg, JPEG_1D8, 1);
	jpeg_write(jpeg, JPEG_1028, 0);
	jpeg_write(jpeg, JPEG_1000, 0x3f);
	jpeg_write(jpeg, JPEG_START, 1);
	jpeg_write(jpeg, JPEG_GO, 1);

	return 0;
}

/*
 * encoder_req2setup: the JFIF RGB to YCbCr matrix (BT.601, full range), x256 in
 * two's complement, then the offsets.
 */
static const u32 apple_jpeg_enc_csc[JPEG_CSC_WORDS] = {
	0x4d, 0x96, 0x1d, 0xffffffd5, 0xffffffab, 0x80, 0x80, 0xffffff95,
	0xffffffeb, 0, 0x80,
};

/* std_luminance_quant_tbl and std_chrominance_quant_tbl: tables 2 and 3 */
static const u8 apple_jpeg_std_qtbl[2][V4L2_JPEG_PIXELS_IN_BLOCK] = {
	{
		0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x02, 0x02,
		0x02, 0x03, 0x02, 0x02, 0x03, 0x03, 0x06, 0x04,
		0x03, 0x03, 0x03, 0x03, 0x07, 0x05, 0x08, 0x04,
		0x06, 0x08, 0x08, 0x0a, 0x09, 0x08, 0x07, 0x0b,
		0x08, 0x0a, 0x0e, 0x0d, 0x0b, 0x0a, 0x0a, 0x0c,
		0x0a, 0x08, 0x08, 0x0b, 0x10, 0x0c, 0x0c, 0x0d,
		0x0f, 0x0f, 0x0f, 0x0f, 0x09, 0x0b, 0x10, 0x11,
		0x0f, 0x0e, 0x11, 0x0d, 0x0e, 0x0e, 0x0e, 0x01,
	}, {
		0x04, 0x04, 0x04, 0x05, 0x04, 0x05, 0x09, 0x05,
		0x05, 0x09, 0x0f, 0x0a, 0x08, 0x0a, 0x0f, 0x1a,
		0x13, 0x09, 0x09, 0x13, 0x1a, 0x1a, 0x1a, 0x1a,
		0x0d, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a,
		0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a,
		0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a,
		0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a,
		0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a,
	},
};

/* ajpeg_driver_check_setup_encode, for the modes the driver offers */
static int apple_jpeg_check_setup_encode(const struct apple_jpeg_job *job)
{
	u32 mode = job->fmt->mode;

	switch (job->subsampling) {
	case APPLE_JPEG_SS_444:
		if (mode == APPLE_JPEG_MODE_YUV422_2P ||
		    mode == APPLE_JPEG_MODE_YUV420_2P ||
		    mode == APPLE_JPEG_MODE_YUV422_1P)
			return -EINVAL;
		break;
	case APPLE_JPEG_SS_422:
		if (mode == APPLE_JPEG_MODE_YUV420_2P)
			return -EINVAL;
		break;
	case APPLE_JPEG_SS_420:
	case APPLE_JPEG_SS_400:
		break;
	default:
		/* "Encode cannot handle any CMP_YUV_411" */
		return -EINVAL;
	}

	return 0;
}

/* ajpeg_drv_setx_encode_CMP_YUV_*: the two reads per MCU of each source plane */
static void apple_jpeg_enc_set_counts(struct apple_jpeg_dev *jpeg,
				      const struct apple_jpeg_job *job)
{
	u32 mode = job->fmt->mode;
	bool packed = mode == APPLE_JPEG_MODE_YUV422_1P ||
		      mode == APPLE_JPEG_MODE_ARGB;
	u32 p0_bytes = mode == APPLE_JPEG_MODE_ARGB ? 4 : 2;
	u32 p1_bytes = 2, rows = 8, p1_rows = 8, b8, bc;

	switch (job->subsampling) {
	case APPLE_JPEG_SS_444:
		b8 = 0xc;
		bc = 2;
		break;
	case APPLE_JPEG_SS_422:
		if (mode == APPLE_JPEG_MODE_ARGB)
			p0_bytes = 8;
		else if (mode == APPLE_JPEG_MODE_YUV422_1P)
			p0_bytes = 4;
		b8 = 8;
		bc = 2;
		break;
	case APPLE_JPEG_SS_420:
		if (mode == APPLE_JPEG_MODE_ARGB)
			p0_bytes = 8;
		else if (mode == APPLE_JPEG_MODE_YUV422_1P)
			p0_bytes = 4;
		rows = 0x10;
		p1_rows = mode == APPLE_JPEG_MODE_YUV420_2P ? 8 : 0x10;
		b8 = 3;
		bc = 1;
		break;
	default:
		/* the kext's table by source mode: 1, 1, 1, 2, 4, 4, 2, 4 */
		p0_bytes = mode == APPLE_JPEG_MODE_ARGB ? 4 :
			   mode == APPLE_JPEG_MODE_YUV422_1P ? 2 : 1;
		packed = true;
		b8 = 0xb;
		bc = 2;
		break;
	}

	jpeg_write(jpeg, JPEG_DCD_CNT0, p0_bytes);
	jpeg_write(jpeg, JPEG_DCD_CNT1, rows);
	if (!packed) {
		jpeg_write(jpeg, JPEG_DCD_CNT2, p1_bytes);
		jpeg_write(jpeg, JPEG_DCD_CNT3, p1_rows);
	}
	jpeg_write(jpeg, JPEG_0B8, b8);
	jpeg_write(jpeg, JPEG_0BC, bc);
}

/* ajpeg_drv_set_encode_submode */
static void apple_jpeg_enc_set_source(struct apple_jpeg_dev *jpeg,
				      const struct apple_jpeg_job *job)
{
	u32 submode = job->fmt->submode;
	unsigned int i;

	switch (job->fmt->mode) {
	case APPLE_JPEG_MODE_YUV422_1P:
		jpeg_write(jpeg, JPEG_ENC_SRC_LAYOUT, 5);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(0), submode ? 0 : 1);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(1), submode ? 1 : 0);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(2), submode ? 3 : 2);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(3), submode ? 2 : 3);
		break;
	case APPLE_JPEG_MODE_ARGB:
		jpeg_write(jpeg, JPEG_ENC_CSC_ENABLE, 1);
		for (i = 0; i < JPEG_CSC_WORDS; i++)
			jpeg_write(jpeg, JPEG_CSC(i), apple_jpeg_enc_csc[i]);
		jpeg_write(jpeg, JPEG_ENC_SRC_LAYOUT, 2);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(0), submode ? 0 : 2);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(1), 1);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(2), submode ? 2 : 0);
		break;
	default:
		jpeg_write(jpeg, JPEG_ENC_SRC_LAYOUT, 4);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(0), 0);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(1), 0);
		jpeg_write(jpeg, JPEG_ENC_SRC_ORDER(2), 1);
		break;
	}
}

/* ajpeg_drv_set_encode_uv_subsample */
static void apple_jpeg_enc_set_resample(struct apple_jpeg_dev *jpeg,
					const struct apple_jpeg_job *job)
{
	bool wide = job->fmt->mode == APPLE_JPEG_MODE_ARGB;
	u32 mode = job->fmt->mode;

	if (job->subsampling == APPLE_JPEG_SS_420) {
		if (wide)
			jpeg_write(jpeg, JPEG_RESAMPLE_03C, 1);
		if (wide || mode == APPLE_JPEG_MODE_YUV422_2P ||
		    mode == APPLE_JPEG_MODE_YUV422_1P)
			jpeg_write(jpeg, JPEG_RESAMPLE_044, 1);
	} else if (job->subsampling == APPLE_JPEG_SS_422 && wide) {
		jpeg_write(jpeg, JPEG_RESAMPLE_03C, 1);
	}
}

/* ajpeg_drv_set_pointers, the raw image read and the stream written */
static void apple_jpeg_enc_set_pointers(struct apple_jpeg_dev *jpeg,
					const struct apple_jpeg_job *job)
{
	bool two_planes = job->fmt->vsub;
	dma_addr_t rd0 = job->src;
	dma_addr_t rd1 = two_planes ? job->src + job->plane1_offset : job->src;
	/* encoder_req2setup asks for 8-byte reads: the end is rounded up */
	dma_addr_t rd_end = (job->src + job->src_size - 1) | 7;
	dma_addr_t wr_end = job->dst + job->dst_size - 1;

	jpeg_write(jpeg, JPEG_RD0_LO, lower_32_bits(rd0));
	jpeg_write(jpeg, JPEG_RD1_LO, lower_32_bits(rd1));
	jpeg_write(jpeg, JPEG_RD_END_LO, lower_32_bits(rd_end));
	jpeg_write(jpeg, JPEG_WR0_LO, lower_32_bits(job->dst));
	jpeg_write(jpeg, JPEG_WR1_LO, lower_32_bits(job->dst));
	jpeg_write(jpeg, JPEG_WR_END_LO, lower_32_bits(wr_end));
	jpeg_write(jpeg, JPEG_RD0_HI, upper_32_bits(rd0));
	jpeg_write(jpeg, JPEG_RD1_HI, upper_32_bits(rd1));
	jpeg_write(jpeg, JPEG_RD_END_HI, upper_32_bits(rd_end));
	jpeg_write(jpeg, JPEG_WR0_HI, upper_32_bits(job->dst));
	jpeg_write(jpeg, JPEG_WR1_HI, upper_32_bits(job->dst));
	jpeg_write(jpeg, JPEG_WR_END_HI, upper_32_bits(wr_end));
	jpeg_write(jpeg, JPEG_P0_STRIDE, job->stride);
	jpeg_write(jpeg, JPEG_P1_STRIDE, two_planes ? job->stride : 0);
}

/* jpeg_qtbl_set: only the low byte of each entry, four to a big-endian word */
static void apple_jpeg_enc_write_qtbl(struct apple_jpeg_dev *jpeg, u32 n,
				      const u8 *tbl)
{
	unsigned int i;

	for (i = 0; i < JPEG_QTBL_WORDS; i++)
		jpeg_write(jpeg, JPEG_QTBL(n) + 4 * i,
			   get_unaligned_be32(tbl + 4 * i));
}

/* the IJG scale of the tables of Annex K, as cjpeg's -quality */
static void apple_jpeg_enc_scale_qtbl(u8 *out, const u8 *ref, u32 quality)
{
	u32 scale = quality < 50 ? 5000 / quality : 200 - 2 * quality;
	unsigned int i;

	for (i = 0; i < V4L2_JPEG_PIXELS_IN_BLOCK; i++)
		out[i] = clamp((ref[i] * scale + 50) / 100, 1U, 255U);
}

/* jpeg_write_tables: chroma on the second pair of tables */
static void apple_jpeg_enc_set_tables(struct apple_jpeg_dev *jpeg,
				      const struct apple_jpeg_job *job)
{
	u8 tbl[V4L2_JPEG_PIXELS_IN_BLOCK];

	apple_jpeg_enc_scale_qtbl(tbl, v4l2_jpeg_ref_table_luma_qt, job->quality);
	apple_jpeg_enc_write_qtbl(jpeg, 0, tbl);
	apple_jpeg_enc_scale_qtbl(tbl, v4l2_jpeg_ref_table_chroma_qt, job->quality);
	apple_jpeg_enc_write_qtbl(jpeg, 1, tbl);
	apple_jpeg_enc_write_qtbl(jpeg, 2, apple_jpeg_std_qtbl[0]);
	apple_jpeg_enc_write_qtbl(jpeg, 3, apple_jpeg_std_qtbl[1]);
	jpeg_write(jpeg, JPEG_ENC_HTBL_SELECT, 0x3c);
	jpeg_write(jpeg, JPEG_ENC_QTBL_SELECT, 0x14);
}

/*
 * AppleJPEGHalV8::startEncoderGated with ajpeg_drv_set_encode: program one
 * encode and start it. The codec writes the whole stream, SOI to EOI, with its
 * own Huffman tables: CMPhoto writes no header, and the kext's
 * jpeg_huffman_set has no callers.
 */
int apple_jpeg_hw_encode(struct apple_jpeg_dev *jpeg,
			 const struct apple_jpeg_job *job)
{
	static const struct apple_jpeg_mcu_size {
		u8 w, h, frame;
	} mcus[] = {
		[APPLE_JPEG_SS_444] = { 8, 8, JPEG_1000_ENC_444 },
		[APPLE_JPEG_SS_422] = { 16, 8, JPEG_1000_ENC_422 },
		[APPLE_JPEG_SS_420] = { 16, 16, JPEG_1000_ENC_420 },
		[APPLE_JPEG_SS_400] = { 8, 8, JPEG_1000_ENC_400 },
	};
	const struct apple_jpeg_mcu_size *mcu = &mcus[job->subsampling];
	struct apple_jpeg_boundary b;
	u32 run;
	int ret;

	ret = apple_jpeg_check_setup_encode(job);
	if (ret)
		return ret;
	ret = apple_jpeg_boundary(job, &b);
	if (ret)
		return ret;

	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_SETUP);
	jpeg_write(jpeg, JPEG_START, 0);
	apple_jpeg_hw_set_defaults(jpeg);
	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_PROGRAM);

	jpeg_write(jpeg, JPEG_038, 1);
	jpeg_write(jpeg, JPEG_ENCODE, 1);
	jpeg_write(jpeg, JPEG_034, 0);
	jpeg_write(jpeg, JPEG_SUBSAMPLING, job->subsampling);
	apple_jpeg_set_boundary(jpeg, &b);

	if (job->limited_range) {
		jpeg_write(jpeg, JPEG_ENC_Y_EXPAND, 1);
		jpeg_write(jpeg, JPEG_ENC_Y_OFFSET0, 0x1ff0);
		jpeg_write(jpeg, JPEG_ENC_Y_OFFSET1, 0);
		jpeg_write(jpeg, JPEG_ENC_Y_GAIN, 0x2543);
		jpeg_write(jpeg, JPEG_ENC_C_EXPAND, 1);
		jpeg_write(jpeg, JPEG_ENC_C_OFFSET0, 0x1f80);
		jpeg_write(jpeg, JPEG_ENC_C_OFFSET1, 0x80);
		jpeg_write(jpeg, JPEG_ENC_C_GAIN, 0x2449);
	}

	jpeg_write(jpeg, JPEG_DCD_CNT4, DIV_ROUND_UP(job->width, mcu->w));
	jpeg_write(jpeg, JPEG_MCU_ROWS, DIV_ROUND_UP(job->height, mcu->h));
	apple_jpeg_enc_set_counts(jpeg, job);
	jpeg_write(jpeg, JPEG_ENC_WIDTH, job->width);
	jpeg_write(jpeg, JPEG_ENC_HEIGHT, job->height);

	apple_jpeg_enc_set_source(jpeg, job);
	apple_jpeg_enc_set_resample(jpeg, job);
	apple_jpeg_enc_set_pointers(jpeg, job);

	jpeg_write(jpeg, JPEG_154, 1);
	jpeg_write(jpeg, JPEG_158, 0);

	run = job->fmt->mode == APPLE_JPEG_MODE_ARGB ? JPEG_RUN_ENC_RGB :
						       JPEG_RUN_ENC_YUV;
	jpeg_write(jpeg, JPEG_CTRL, JPEG_CTRL_RUN(run));
	jpeg_write(jpeg, JPEG_1000, JPEG_1000_ENC(mcu->frame));
	jpeg_write(jpeg, JPEG_ENC_FRAME_WIDTH, job->width);
	jpeg_write(jpeg, JPEG_ENC_FRAME_HEIGHT, job->height);
	jpeg_write(jpeg, JPEG_ENC_RESTART, job->restart_interval);
	jpeg_write(jpeg, JPEG_1024, 0);
	apple_jpeg_enc_set_tables(jpeg, job);

	jpeg_write(jpeg, JPEG_START, 1);
	jpeg_write(jpeg, JPEG_GO, 1);

	return 0;
}

/* AppleJPEGHalV8::checkForInterrupt: read the status and acknowledge */
void apple_jpeg_hw_irq(struct apple_jpeg_dev *jpeg,
		       struct apple_jpeg_status *st)
{
	st->status = jpeg_read(jpeg, JPEG_IRQ_STATUS);
	st->axi = jpeg_read(jpeg, JPEG_AXI_STATUS);
	st->aux = jpeg_read(jpeg, JPEG_STATUS_AUX);
	jpeg_write(jpeg, JPEG_AXI_STATUS, 0);
	jpeg_write(jpeg, JPEG_START, 0);
	jpeg_write(jpeg, JPEG_154, 0);
	jpeg_write(jpeg, JPEG_158, 0);
	jpeg_write(jpeg, JPEG_IRQ_ENABLE, 0);
	st->bitstream = jpeg_read(jpeg, JPEG_BITSTREAM_ERROR);
	st->cycles = jpeg_read(jpeg, JPEG_CYCLES);
	st->bytes = jpeg_read(jpeg, JPEG_ENC_BYTES);
}

/* the checks of checkForInterrupt and AppleJPEGHalV8::finishDecode_gated */
bool apple_jpeg_hw_failed(struct apple_jpeg_dev *jpeg,
			  const struct apple_jpeg_status *st)
{
	u32 s = st->status;
	bool axi_bad = st->axi != JPEG_AXI_STATUS_OK0 &&
		       st->axi != JPEG_AXI_STATUS_OK1;
	bool failed = false;

	if (s & JPEG_IRQ_TIMEOUT) {
		dev_err_ratelimited(jpeg->dev, "hardware timeout\n");
		failed = true;
	}
	if (s & JPEG_IRQ_RDMA_OVERFLOW) {
		dev_err_ratelimited(jpeg->dev, "read DMA overflow\n");
		failed = true;
	}
	if (s & JPEG_IRQ_WDMA_OVERFLOW) {
		dev_err_ratelimited(jpeg->dev, "write DMA overflow\n");
		failed = true;
	}
	if (s & JPEG_IRQ_CODEC_OVERFLOW) {
		dev_err_ratelimited(jpeg->dev, "codec overflow\n");
		failed = true;
	}
	/* a lone bit 5 is no error when JPEG_STATUS_AUX bit 2 is set */
	if ((s & JPEG_IRQ_ERROR5) &&
	    ((s & JPEG_IRQ_ERRORS & ~JPEG_IRQ_ERROR5) || axi_bad ||
	     st->bitstream || !(st->aux & JPEG_STATUS_AUX_OK5)))
		failed = true;
	if (s & JPEG_IRQ_AXI_ERROR) {
		dev_err_ratelimited(jpeg->dev, "AXI bus error\n");
		failed = true;
	}
	if (axi_bad || (s & JPEG_IRQ_ERROR7))
		failed = true;
	if (st->bitstream) {
		dev_err_ratelimited(jpeg->dev, "bitstream corruption type %u\n",
				    st->bitstream);
		failed = true;
	}
	if (failed)
		dev_err_ratelimited(jpeg->dev,
				    "job failed: status %#x, AXI %#x, aux %#x\n",
				    s, st->axi, st->aux);

	return failed;
}

/* the registers that tell a hung or failed job apart, for the log */
void apple_jpeg_hw_dump(struct apple_jpeg_dev *jpeg)
{
	dev_err(jpeg->dev,
		"start %#x ctrl %#x aux %#x irq %#x/%#x go %#x axi %#x bitstream %#x cycles %u result %#x %#x\n",
		jpeg_read(jpeg, JPEG_START), jpeg_read(jpeg, JPEG_CTRL),
		jpeg_read(jpeg, JPEG_STATUS_AUX),
		jpeg_read(jpeg, JPEG_IRQ_ENABLE),
		jpeg_read(jpeg, JPEG_IRQ_STATUS), jpeg_read(jpeg, JPEG_GO),
		jpeg_read(jpeg, JPEG_AXI_STATUS),
		jpeg_read(jpeg, JPEG_BITSTREAM_ERROR),
		jpeg_read(jpeg, JPEG_CYCLES), jpeg_read(jpeg, JPEG_RESULT0),
		jpeg_read(jpeg, JPEG_RESULT1));
}
