/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Apple ProRes codec driver
 */

#ifndef APPLE_PRORES_H
#define APPLE_PRORES_H

#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <media/v4l2-device.h>
#include <media/v4l2-fh.h>
#include <media/v4l2-mem2mem.h>

#define APPLE_PRORES_NAME	"apple-prores"

struct apple_prores_tunable {
	u32 offset, mask, value;
};

struct apple_prores_core {
	u64 base;
	const struct apple_prores_tunable *axi2af;
	unsigned int num_axi2af;
};

/* a raw format: 8-bit 2-plane YCbCr, its chroma's width against the luma's */
struct apple_prores_raw {
	u32 fourcc;
	u8 chroma;	/* the descriptor's chroma format: 2 4:2:2, 3 4:4:4 */
	u8 cpp1;	/* bytes a luma pixel in the chroma plane */
};

struct apple_prores_profile {
	u32 fourcc;
	const char *name;
	bool chroma444;
	u8 quant_sel;
	u8 qindex;
	u16 rc_min, rc_max;	/* a slice's bytes, at 8 macroblocks a slice */
};

struct apple_prores_job {
	const struct apple_prores_raw *raw;
	const struct apple_prores_profile *profile;
	u32 width, height, stride0, stride1;
	dma_addr_t src0, src1, dst;
	u32 dst_size;
	u32 frame;
	u8 rate_code, primaries, transfer, matrix;
};

struct apple_prores_status {
	u32 irq, st0, st1, st2;
};

struct apple_prores_ctx {
	struct v4l2_fh fh;
	struct apple_prores_dev *apr;
	struct v4l2_pix_format_mplane out_fmt, cap_fmt;
	const struct apple_prores_raw *raw;
	const struct apple_prores_profile *profile;
	u8 rate_code;
	struct v4l2_fract tpf;
	u32 out_seq, cap_seq;
	u32 bytes;
};

struct apple_prores_dev {
	struct device *dev;
	void __iomem *regs;
	void __iomem *axi2af;
	const struct apple_prores_core *core;
	u32 version;

	void *ring;
	dma_addr_t ring_dma;
	u32 head;
	void *stats;
	dma_addr_t stats_dma;

	struct v4l2_device v4l2_dev;
	struct video_device vdev_enc;
	struct v4l2_m2m_dev *m2m_dev;
	/* serializes the ioctls and the queues */
	struct mutex lock;

	/* protects curr between device_run, the interrupt and the timeout */
	spinlock_t hw_lock;
	struct apple_prores_ctx *curr;
	struct delayed_work timeout_work;
};

static inline u32 apr_read(struct apple_prores_dev *apr, u32 reg)
{
	return readl(apr->regs + reg);
}

static inline void apr_write(struct apple_prores_dev *apr, u32 reg, u32 val)
{
	writel(val, apr->regs + reg);
}

const struct apple_prores_core *apple_prores_hw_find_core(u64 base);
void apple_prores_hw_activate(struct apple_prores_dev *apr);
void apple_prores_hw_deactivate(struct apple_prores_dev *apr);
void apple_prores_hw_encode(struct apple_prores_dev *apr,
			    const struct apple_prores_job *job);
bool apple_prores_hw_irq(struct apple_prores_dev *apr,
			 struct apple_prores_status *st);
bool apple_prores_hw_failed(struct apple_prores_dev *apr,
			    const struct apple_prores_status *st);
void apple_prores_hw_dump(struct apple_prores_dev *apr);

int apple_prores_v4l2_register(struct apple_prores_dev *apr);
void apple_prores_v4l2_unregister(struct apple_prores_dev *apr);
irqreturn_t apple_prores_irq_thread(int irq, void *data);
void apple_prores_timeout_work(struct work_struct *work);

#endif /* APPLE_PRORES_H */
