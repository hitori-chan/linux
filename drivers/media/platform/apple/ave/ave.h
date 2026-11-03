/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Apple video encoder (AVE) driver
 */

#ifndef APPLE_AVE_H
#define APPLE_AVE_H

#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/pm_domain.h>
#include <linux/spinlock.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-fh.h>
#include <media/v4l2-mem2mem.h>

#define APPLE_AVE_NAME		"apple-ave"

/*
 * macOS's session: twelve of each per-frame buffer, ten for the frames others
 * refer to and the last for those none does. One frame is in flight, so the
 * coded data always goes to the first.
 */
#define AVE_NUM_SLOTS		12
#define AVE_USED_SLOTS		2
#define AVE_NUM_PIPES		4

/* HEVC's slice headers, one a slice, which the firmware writes */
#define AVE_SLICE_HDR_STRIDE	0x400
#define AVE_SLICE_HDR_NUM	256

/* The commands' ids, CFlowControllerBase::CmdProcessor */
#define AVE_CMD_CONFIG		1
#define AVE_CMD_HALT		2
#define AVE_CMD_OPEN		3
#define AVE_CMD_CLOSE		4
#define AVE_CMD_START		6
#define AVE_CMD_STOP		7
#define AVE_CMD_PROCESS		8
#define AVE_CMD_COMPLETE	9
#define AVE_CMD_MAX		15

#define AVE_CMD_SMALL_SIZE	0x48

struct ave_segment {
	phys_addr_t phys;
	size_t size;
	dma_addr_t iova;
};

struct ave_buf {
	void *cpu;
	dma_addr_t iova;
	size_t size;
};

struct ave_recon {
	dma_addr_t y, c, a, b;
};

struct apple_ave_ctx;

struct ave_bits {
	u8 *b;
	u32 n;
};

struct ave_sizes {
	u32 lowres_ref, colocated, info, pixel, data, fw, entropy;
	u32 transcoded;		/* H.264's, sized from the coded data's */
	u32 extra;		/* HEVC's two */
};

/* What a session's commands and buffers take from its codec */
struct ave_codec {
	u32 id;			/* each command's +0x18 */
	u32 start_size, process_size;
	u32 x28_session, x28_frame;
	u32 pipes;
	u32 slice_hdr_size;
	/* the level, the references and the parameter sets */
	void (*layout)(struct apple_ave_ctx *ctx);
	void (*sizes)(struct apple_ave_ctx *ctx, struct ave_sizes *s);
	void (*fill_start)(struct apple_ave_ctx *ctx, u8 *b);
	void (*fill_process)(struct apple_ave_ctx *ctx, u8 *b, dma_addr_t src);
};

struct apple_ave {
	struct device *dev;
	void __iomem *iop;
	void __iomem *mbox;
	void __iomem *axi2af;
	struct dev_pm_domain_list *pd_list;
	u32 instance;
	int irq;
	bool irq_on;
	struct completion event;

	struct ave_segment text, data;
	phys_addr_t data_copy;

	struct ave_buf ipc, heap, iopipc;
	size_t ipc_used;
	u64 fw_ipc_base;

	u32 num_channels, channel_size, heap_size, client_size;
	void *ch_mem;
	/* the next slot of IO the host sends in, of IO_T2H and SHAREDMALLOC it reads */
	u32 io_next, t2h_next, sm_next, term_next;
	u32 t2h_seen[AVE_CMD_MAX + 1];
	u64 seq;

	struct v4l2_device v4l2_dev;
	struct video_device vdev;
	struct v4l2_m2m_dev *m2m_dev;
	/* the V4L2 ioctls and the firmware's owner */
	struct mutex lock;
	spinlock_t hw_lock;
	struct workqueue_struct *wq;
	struct apple_ave_ctx *owner;
};

struct apple_ave_ctx {
	struct v4l2_fh fh;
	struct apple_ave *ave;
	struct v4l2_pix_format_mplane out_fmt, cap_fmt;
	struct v4l2_ctrl_handler ctrls;
	struct v4l2_fract tpf;
	struct work_struct work;
	u32 out_seq, cap_seq;
	u32 bitrate;

	/* the encoding session, from the first frame to the stream's end */
	const struct ave_codec *codec;
	bool running;
	u32 frame;		/* frames since the IDR */
	u32 total;		/* frames since the session's start */
	u32 idr_id;
	u32 gop_size;		/* frames an IDR; 0 only the first */
	bool force_idr;

	u32 mbw, mbh, height16, level, refs;
	u8 headers[128];
	u32 headers_len, sps_len;
	u8 *process;
	size_t process_off;

	struct ave_buf mem;		/* all but the first coded buffer and its header */
	struct ave_buf coded0, coded_hdr0, slice_hdr;
	u32 coded_size, lowres_result_size, transcoded_size, entropy_size;
	struct ave_recon recon[AVE_NUM_SLOTS];
	dma_addr_t coded[AVE_NUM_SLOTS], coded_hdr[AVE_NUM_SLOTS];
	dma_addr_t lowres_ref[AVE_NUM_SLOTS], lowres_result[AVE_NUM_SLOTS];
	dma_addr_t colocated[AVE_NUM_SLOTS];
	dma_addr_t lowres_result_a, lowres_result_b, transcoded[2], extra[2];
	dma_addr_t neighbor_info, neighbor_pixel, neighbor_data, neighbor_fw;
	dma_addr_t entropy[2][AVE_NUM_PIPES];
	dma_addr_t client, misc, params;
};

/* ave-fw.c */
int ave_fw_parse(struct apple_ave *ave);
irqreturn_t ave_fw_irq(int irq, void *data);
int ave_fw_boot(struct apple_ave *ave);
void ave_fw_shutdown(struct apple_ave *ave, bool halt);
void *ave_ipc_alloc(struct apple_ave *ave, size_t size, size_t *offset);
u64 ave_fw_time_ms(struct apple_ave *ave);
int ave_fw_send(struct apple_ave *ave, size_t off, u32 size);
int ave_fw_wait(struct apple_ave *ave, unsigned int cmd, u32 seen, unsigned int timeout_us);
int ave_fw_command(struct apple_ave *ave, size_t off, u32 size, unsigned int cmd);

/* ave-session.c */
void ave_put_bits(struct ave_bits *w, u32 v, u32 n);
void ave_put_ue(struct ave_bits *w, u32 v);
void ave_put_se(struct ave_bits *w, int v);
u8 *ave_put_nal(u8 *o, struct ave_bits *w);
u32 ave_fps(const struct apple_ave_ctx *ctx);
void ave_put_words(u8 *b, const u32 *t, size_t n);
void ave_cmd_header(struct apple_ave_ctx *ctx, u8 *b, u16 id, u32 slot, u32 x20, u32 x28, u32 x30);
void ave_fill_start_buffers(struct apple_ave_ctx *ctx, u8 *b);
void ave_session_free(struct apple_ave_ctx *ctx);
int ave_session_start(struct apple_ave_ctx *ctx);
void ave_session_stop(struct apple_ave_ctx *ctx);
int ave_session_encode(struct apple_ave_ctx *ctx, dma_addr_t src, u8 *dst, size_t dst_size,
		       size_t *bytes, bool *keyframe);

static inline void ave_put_dva(u8 *b, u32 off, dma_addr_t dva)
{
	put_unaligned_le64(dva, b + off);
}

/* ave-h264.c, ave-hevc.c */
extern const struct ave_codec ave_codec_h264, ave_codec_hevc;

/* ave-v4l2.c */
int ave_v4l2_register(struct apple_ave *ave);
void ave_v4l2_unregister(struct apple_ave *ave);

#endif
