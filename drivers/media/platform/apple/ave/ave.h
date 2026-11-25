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
 * refer to and the last for those none does. One frame is in flight on 7060
 * and on two cores, so their coded data always goes to the first.
 */
#define AVE_NUM_SLOTS		12
#define AVE_TWO_RINGS		5
#define AVE_USED_SLOTS		2
/* AVE_Drv::IO_init: surface config 0x16, "IOPIPC", 16 KiB a device, two devices */
#define AVE_IOPIPC_SIZE		(2 * SZ_16K)
/*
 * The two-core mode's session memory, from the DMA API in pieces this size
 * and mapped as one block at the shared address: no allocation needs a
 * slot aligned to the block's size (ave-session.c's AVE_TWO_SIZE covers them)
 */
#define AVE_MEM_PART		SZ_32M
#define AVE_MEM_PARTS		56
#define AVE_NUM_PIPES		8

/*
 * 9013 on one core: the Process commands a session keeps at the firmware.
 * FW27 queues them: CFlowControllerBase::ProcessCmd_Process_AVC (0xb87f4) and
 * _HEVC copy each into one of the client's 17 command buffers
 * (aquireEncCmdBufFromPool 0xb3440, CAVEClient::CAVEClient 0xd3f10) and
 * SendCommandToQueue (0xc1a8c) queues it; ProcessQueue (0xbb65c) runs each
 * stage on the next frame as the stage frees, the next frame's LRME beside
 * this one's pipe (AcquireAndTriggerLRMEFSForEnc 0xc31f8: once the LRME's
 * starts equal the pipe's, with settings+0x3f8 bit 4) and this one's
 * transcode beside the next one's pipe (isOverlapPipeXcode). 27.2's kext
 * keeps that many at once when settings+0x0 bit 12 is set, VideoToolbox's
 * 0x1000: the CHM's limit at +0xe8, which AVE_HwC::ProcessIntr_Cmd
 * (0xfffffe0008e652d8) sets at Start's reply from
 * AVE_MD_SVE::GetOutputBufNum (0xfffffe0008ee8b1c), against the Process
 * commands sent and not answered (AVE_HwC::ProcessInputCmd_Process
 * 0xfffffe0008e59cb4).
 */
#define AVE9_INFLIGHT		2
#define AVE_INFLIGHT_MAX	4
/* each frame its own output: those in flight and the one the host reads */
#define AVE_OUT_SETS		(AVE_INFLIGHT_MAX + 1)
/* the Process replies' slots and status kept, by reply (ave_serve_t2h) */
#define AVE_REPLY_RING		8

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

/* the session's fixed buffers (were ave-session.c's) */
#define AVE_CODED_HDR_SIZE	0x30000
#define AVE_MISC_SIZE		0x20000
#define AVE_PARAMS_SIZE		0x4000
#define AVE_DEFAULT_CLIENT_SIZE	0x108000

/*
 * The preloaded firmware, known by its __TEXT's size (m1n1's logs: 0x104000
 * under 14.8.3's stub, 0x154000 under 27.2's).
 */
#define AVE_FW_7060_TEXT	0x104000
#define AVE_FW_9013_TEXT	0x154000

enum ave_fw_gen {
	AVE_FW_UNKNOWN,	/* left to the probe's gate (ave272.md): bound, no node */
	AVE_FW_7060,	/* AppleAVE2FW 7060.21.0, macOS 14.8.3 */
	AVE_FW_9013,	/* AppleAVE2FW 9013.55.1, macOS 27.2 */
};

struct ave_segment {
	phys_addr_t phys;
	size_t size;
	dma_addr_t iova;
};

struct ave_buf {
	void *cpu;
	dma_addr_t iova;
	dma_addr_t dva;		/* where the firmware sees it: iova, or on both cores' DARTs */
	size_t size;
};

struct ave_recon {
	dma_addr_t y, c, a, b;
};

struct apple_ave;
struct apple_ave_ctx;

struct ave_bits {
	u8 *b;
	u32 n;
};

/* 9013: a frame's slices, as the coded header lists them */
#define AVE9_SLICES_MAX		32

struct ave9_slice {
	u32 off, size;		/* the data, in the coded data */
	u32 hdr_off, hdr_size;	/* HEVC: the slice header, in the slice header buffer */
};

struct ave_sizes {
	u32 lowres_ref, colocated, info, pixel, data, fw, entropy;
	u32 transcoded;		/* H.264's, sized from the coded data's */
	u32 extra;		/* HEVC's two */
	u32 rec_y, rec_c, rec_a, rec_b;	/* a reconstructed frame's planes */
};

/* What a session's commands and buffers take from its codec */
struct ave_codec {
	u32 id;			/* each command's codec word: 7060 +0x18 (0, 1), 9013 +0x1c (1, 2) */
	u32 start_size, process_size;
	u32 x28_session, x28_frame;
	u32 session_flags;	/* 9013: settings+0x2c, each command's +0x28 */
	u32 pipes;		/* a core's; twice that in the two-core mode */
	u32 slice_hdr_size;
	u32 slice_bits_size;	/* 9013 H.264: the host's slice header bits go in a buffer */
	/* the level, the references and the parameter sets */
	void (*layout)(struct apple_ave_ctx *ctx);
	void (*sizes)(struct apple_ave_ctx *ctx, struct ave_sizes *s);
	void (*fill_start)(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b);
	void (*fill_process)(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b,
			     dma_addr_t src);
};

struct apple_ave {
	struct device *dev;
	void __iomem *iop;
	void __iomem *mbox;
	void __iomem *axi2af;
	void __iomem *dapf;
	phys_addr_t iop_phys;
	struct dev_pm_domain_list *pd_list;
	unsigned int pstate;	/* the vote of its sys domain (ave_session_vote) */
	u32 instance;
	int irq;
	bool irq_on;
	struct completion event;

	struct ave_segment text, data;
	phys_addr_t data_copy;
	enum ave_fw_gen fw;

	struct ave_buf ipc, heap, iopipc;
	struct ave_buf fwlog;	/* 9013: the firmware's log surface (MakeFwCfg +0x20) */
	u32 fwlog_pos;		/* 9013: the log ring's bytes printed */
	size_t ipc_used;
	u64 fw_ipc_base;

	u32 num_channels, channel_size, heap_size, client_size;
	void *ch_mem;
	/* the next slot of IO the host sends in, of IO_T2H and SHAREDMALLOC it reads */
	u32 io_next, t2h_next, sm_next, term_next;
	u32 t2h_seen[AVE_CMD_MAX + 1];
	u32 t2h_status[AVE_CMD_MAX + 1];	/* each reply's +0x40 (FW27 NotificationToHost 0xc00b0) */
	/* each Process reply's slot (+0x20) and status, by t2h_seen[AVE_CMD_PROCESS] */
	u32 p_slot[AVE_REPLY_RING], p_status[AVE_REPLY_RING];
	u64 seq;

	struct v4l2_device v4l2_dev;
	struct video_device vdev;
	struct v4l2_m2m_dev *m2m_dev;
	/* the V4L2 ioctls and the firmware's owner */
	struct mutex lock;
	spinlock_t hw_lock;
	struct workqueue_struct *wq;
	struct apple_ave_ctx *owner;	/* cmpxchg: the other core's two-core session claims this */
	bool pausing;		/* system sleep: a job sends no more frames (ave_work) */
};

/* A frame's own buffers, which the firmware writes or reads after its Process is sent */
struct ave_out {
	struct ave_buf coded, hdr, slice_hdr, slice_bits;
	u8 *process;		/* one core: the frame's Process command */
	size_t process_off;
};

/* A frame sent to the firmware, until the host has read it */
struct ave_flight {
	struct ave_out *out;
	u32 set;		/* out's index: the Process slot's */
	u32 total, frame;	/* ctx->total and ctx->frame at its send */
	u32 seen[2];		/* each core's Process replies before its own */
	bool keyframe;
	ktime_t sent;
};

struct apple_ave_ctx {
	struct v4l2_fh fh;
	struct apple_ave *ave;
	struct v4l2_pix_format_mplane out_fmt, cap_fmt;
	struct v4l2_ctrl_handler ctrls;
	struct v4l2_ctrl *hevc_profile;
	struct v4l2_fract tpf;
	struct work_struct work;
	u32 out_seq, cap_seq;
	u32 bitrate;

	/* the encoding session, from the first frame to the stream's end */
	const struct ave_codec *codec;
	struct apple_ave *peer;	/* the second core, in the two-core mode */
	dma_addr_t dva_next;
	struct ave_buf iopipc;
	struct ave_buf mem_part[AVE_MEM_PARTS];	/* two cores: the pieces of mem */
	u32 mem_parts;
	dma_addr_t src_dva[VIDEO_MAX_FRAME];
	size_t src_size[VIDEO_MAX_FRAME];
	bool running;
	bool stop_feed;		/* the job aborted: it sends no more frames (ave_work) */
	ktime_t done_at;	/* the last frame's end, and its encode's time (ave_work) */
	s64 enc_ns;
	u32 frame;		/* frames since the IDR */
	u32 total;		/* frames since the session's start */
	u32 idr_id;
	u32 gop_size;		/* frames an IDR; 0 only the first */
	bool force_idr;

	u32 mbw, mbh, height16, level, refs, bit_depth;
	u8 headers[128];
	u32 headers_len, sps_len;
	u8 *process[2];		/* two cores: by core */
	size_t process_off[2];

	/*
	 * The frames in flight, oldest first, and the one being sent or read;
	 * each set's buffers its frames', set k the frames whose total is k
	 * modulo out_sets
	 */
	u32 inflight, out_sets;
	struct ave_flight flight[AVE_INFLIGHT_MAX];
	u32 fl_first, fl_n;
	struct ave_flight *cur;
	u32 p_next[2];		/* by core: the Process replies before the next frame's */
	bool entropy_sets;	/* the kext's entropy layout: two sets in turn (ave-9013.c) */

	struct ave_buf mem;		/* all but the output sets */
	struct ave_out out[AVE_OUT_SETS];
	struct ave_sizes sizes;
	u32 coded_size, lowres_result_size, transcoded_size, entropy_size;
	struct ave9_slice slices[AVE9_SLICES_MAX];
	u32 nslices;
	struct ave_recon recon[AVE_NUM_SLOTS];
	dma_addr_t coded[AVE_NUM_SLOTS], coded_hdr[AVE_NUM_SLOTS];
	dma_addr_t lowres_ref[AVE_NUM_SLOTS], lowres_result[AVE_NUM_SLOTS];
	dma_addr_t colocated[AVE_NUM_SLOTS];
	dma_addr_t colocated_peer[2];
	dma_addr_t lowres_result_ab[3], transcoded[2], extra[2];
	dma_addr_t neighbor_info[2], neighbor_pixel[2], neighbor_data[2], neighbor_fw[2];
	dma_addr_t entropy[2][AVE_NUM_PIPES];
	dma_addr_t client, client_peer, misc, params;
};

/* ave-fw.c */
int ave_fw_parse(struct apple_ave *ave);
bool ave_fw_supported(struct apple_ave *ave);
irqreturn_t ave_fw_irq(int irq, void *data);
int ave_fw_boot(struct apple_ave *ave, struct apple_ave *peer, dma_addr_t iopipc);
void ave_fw_shutdown(struct apple_ave *ave, bool halt);
void *ave_ipc_alloc(struct apple_ave *ave, size_t size, size_t *offset);
u64 ave_fw_time_ms(struct apple_ave *ave);
u64 ave_fw_time_us(struct apple_ave *ave);
int ave_fw_send(struct apple_ave *ave, size_t off, u32 size);
int ave_fw_wait(struct apple_ave *ave, unsigned int cmd, u32 seen, unsigned int timeout_us);
int ave_fw_command(struct apple_ave *ave, size_t off, u32 size, unsigned int cmd);

/* ave-session.c */
void ave_put_bits(struct ave_bits *w, u32 v, u32 n);
void ave_put_ue(struct ave_bits *w, u32 v);
void ave_put_se(struct ave_bits *w, int v);
u8 *ave_put_nal(u8 *o, struct ave_bits *w);
u32 ave_fps(const struct apple_ave_ctx *ctx);
u32 ave_fps_double(const struct apple_ave_ctx *ctx);
void ave_put_words(u8 *b, const u32 *t, size_t n);
void ave_cmd_header(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b, u16 id, u32 slot,
		    u32 x20, u32 x28, u32 x30);
void ave_fill_start_buffers(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b);
void ave_session_free(struct apple_ave_ctx *ctx);
int ave_session_start(struct apple_ave_ctx *ctx);
void ave_session_stop(struct apple_ave_ctx *ctx);
void ave_session_abort(struct apple_ave_ctx *ctx);
void ave_session_vote(struct apple_ave_ctx *ctx, bool waiting);
int ave_session_send(struct apple_ave_ctx *ctx, struct vb2_buffer *src);
int ave_session_finish(struct apple_ave_ctx *ctx, u8 *dst, size_t dst_size, size_t *bytes,
		       bool *keyframe);
void ave_session_unmap_src(struct apple_ave_ctx *ctx, unsigned int index);
struct apple_ave *ave_core(u32 instance);

/* 9013: AVE_CalcBufSizeOfEntropyCodingHeader, (height + 0x7f) & ~0x7f bytes after the data */
static inline u32 ave9_entropy_hdr_size(const struct apple_ave_ctx *ctx)
{
	return ALIGN(ctx->height16, 0x80);
}

static inline void ave_put_dva(u8 *b, u32 off, dma_addr_t dva)
{
	put_unaligned_le64(dva, b + off);
}

/* ave-h264.c, ave-hevc.c */
extern const struct ave_codec ave_codec_h264, ave_codec_hevc;
void ave_h264_layout(struct apple_ave_ctx *ctx);
void ave_h264_sizes(struct apple_ave_ctx *ctx, struct ave_sizes *s);
void ave_h264_slice_bits(struct apple_ave_ctx *ctx, u8 *bytes, u32 *nbits, bool idr);
void ave_hevc_layout(struct apple_ave_ctx *ctx);
void ave_hevc_sizes(struct apple_ave_ctx *ctx, struct ave_sizes *s);

/* ave-9013.c */
extern const struct ave_codec ave_codec_h264_9013, ave_codec_hevc_9013;

static inline bool ave_is_9013(const struct apple_ave *ave)
{
	return IS_ENABLED(CONFIG_VIDEO_APPLE_AVE_9013) && ave->fw == AVE_FW_9013;
}

u32 ave9_fwlog_level(void);
int ave9_frame_done(struct apple_ave_ctx *ctx, u32 *start, u32 *bytes);
int ave9_reply_check(struct apple_ave_ctx *ctx, struct apple_ave *ave, u32 seen);
u32 ave9_slices_size(const struct apple_ave_ctx *ctx);
void ave9_slices_copy(struct apple_ave_ctx *ctx, u8 *dst);
void ave9_fwlog_print(struct apple_ave *ave);
u64 ave9_cmd_time(struct apple_ave *ave);

/* ave-v4l2.c */
int ave_v4l2_register(struct apple_ave *ave);
void ave_v4l2_unregister(struct apple_ave *ave);

#endif
