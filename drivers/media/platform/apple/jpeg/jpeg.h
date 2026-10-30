/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Apple JPEG codec driver
 *
 * Copyright The Asahi Linux Contributors
 */

#ifndef APPLE_JPEG_H
#define APPLE_JPEG_H

#include <linux/device.h>
#include <linux/io.h>
#include <linux/irqreturn.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <media/v4l2-device.h>
#include <media/v4l2-fh.h>
#include <media/v4l2-mem2mem.h>

#include "jpeg-regs.h"

#define APPLE_JPEG_NAME		"apple-jpeg"
/* CMPhotoJPEGGetMaximumHardwareOutputDimensions */
#define APPLE_JPEG_MAX_DIM	16384
#define APPLE_JPEG_MIN_DIM	8

/* JPEG_SUBSAMPLING */
enum apple_jpeg_subsampling {
	APPLE_JPEG_SS_444 = 0,
	APPLE_JPEG_SS_422 = 1,
	APPLE_JPEG_SS_411 = 2,
	APPLE_JPEG_SS_420 = 3,
	APPLE_JPEG_SS_400 = 4,
};

/* JPEG_OUT_MODE, the IMG_* formats of the macOS driver */
enum apple_jpeg_mode {
	APPLE_JPEG_MODE_YUV444_2P = 0,
	APPLE_JPEG_MODE_YUV422_2P = 1,
	APPLE_JPEG_MODE_YUV420_2P = 2,
	APPLE_JPEG_MODE_YUV422_1P = 3,
	APPLE_JPEG_MODE_ARGB = 5,
	APPLE_JPEG_MODE_RGB565 = 6,
};

struct apple_jpeg_fmt {
	u32 fourcc;
	u8 mode;
	u8 submode;
	/* bytes per pixel of the first plane */
	u8 cpp;
	/* vertical subsampling of the CbCr plane, 0 without one */
	u8 vsub;
};

/* one decode, in the terms of the macOS driver's ajpeg_setup_t */
struct apple_jpeg_job {
	enum apple_jpeg_subsampling subsampling;
	u32 width;
	u32 height;
	const struct apple_jpeg_fmt *fmt;

	dma_addr_t src;
	size_t src_size;
	u32 data_offset;
	const u8 *hdr;
	u32 hdr_len;
	u32 slice_bytes;
	/* DCT downscale: 1, 2, 4 or 8 */
	u32 scale;

	dma_addr_t dst;
	size_t dst_size;
	u32 stride;
	u32 plane1_offset;
};

struct apple_jpeg_status {
	u32 status;
	u32 axi;
	u32 aux;
	u32 bitstream;
	u32 cycles;
};

struct apple_jpeg_tunable {
	u32 reg;
	u32 mask;
	u32 val;
};

struct apple_jpeg_core {
	u64 base;
	const struct apple_jpeg_tunable *tunables;
	unsigned int num_tunables;
};

struct apple_jpeg_src_buf {
	struct v4l2_m2m_buffer m2m;
	bool error;
	enum apple_jpeg_subsampling subsampling;
	u32 width;
	u32 height;
	u32 data_offset;
	u32 hdr_len;
	u8 hdr[JPEG_HDR_WINDOW_SIZE];
};

struct apple_jpeg_ctx {
	struct v4l2_fh fh;
	struct apple_jpeg_dev *jpeg;
	struct v4l2_pix_format_mplane out_fmt;
	struct v4l2_pix_format_mplane cap_fmt;
	const struct apple_jpeg_fmt *cap_jfmt;
	u32 out_seq;
	u32 cap_seq;
	bool source_change;
	bool need_initial_source_change;
};

struct apple_jpeg_dev {
	struct device *dev;
	void __iomem *regs;
	const struct apple_jpeg_core *core;
	u32 hw_version;

	struct v4l2_device v4l2_dev;
	struct video_device vdev;
	struct v4l2_m2m_dev *m2m_dev;
	/* serializes the ioctls and the queues */
	struct mutex lock;

	/* protects curr between device_run, the interrupt and the timeout */
	spinlock_t hw_lock;
	struct apple_jpeg_ctx *curr;
	struct delayed_work timeout_work;
};

static inline u32 jpeg_read(struct apple_jpeg_dev *jpeg, u32 reg)
{
	return readl(jpeg->regs + reg);
}

static inline void jpeg_write(struct apple_jpeg_dev *jpeg, u32 reg, u32 val)
{
	writel(val, jpeg->regs + reg);
}

const struct apple_jpeg_core *apple_jpeg_hw_find_core(u64 base);
int apple_jpeg_hw_reset(struct apple_jpeg_dev *jpeg);
u32 apple_jpeg_hw_version(struct apple_jpeg_dev *jpeg);
void apple_jpeg_hw_idle(struct apple_jpeg_dev *jpeg);
int apple_jpeg_hw_decode(struct apple_jpeg_dev *jpeg,
			 const struct apple_jpeg_job *job);
void apple_jpeg_hw_irq(struct apple_jpeg_dev *jpeg,
		       struct apple_jpeg_status *st);
bool apple_jpeg_hw_failed(struct apple_jpeg_dev *jpeg,
			  const struct apple_jpeg_status *st);
void apple_jpeg_hw_dump(struct apple_jpeg_dev *jpeg);

int apple_jpeg_v4l2_register(struct apple_jpeg_dev *jpeg);
void apple_jpeg_v4l2_unregister(struct apple_jpeg_dev *jpeg);
irqreturn_t apple_jpeg_irq_thread(int irq, void *data);
void apple_jpeg_timeout_work(struct work_struct *work);

#endif /* APPLE_JPEG_H */
