// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple ProRes codec: the V4L2 stateful encoder and decoder
 *
 * Copyright The Asahi Linux Contributors
 *
 * Raw frames on OUTPUT, one ProRes frame on each CAPTURE buffer, starting at its
 * frame size and 'icpf'. The CAPTURE format names the profile, as a container's
 * sample description does. The decoder takes one such frame on each OUTPUT
 * buffer, whatever follows it there, and the frame's header sets the CAPTURE
 * format.
 */

#include <linux/delay.h>
#include <linux/pm_runtime.h>
#include <linux/unaligned.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-dma-contig.h>

#include "prores.h"
#include "prores-regs.h"

#define APPLE_PRORES_TIMEOUT_MS	1500	/* the kext's job watchdog */
#define APPLE_PRORES_MIN_DIM	32
#define APPLE_PRORES_MAX_DIM	16384
#define APPLE_PRORES_DEF_WIDTH	1920
#define APPLE_PRORES_DEF_HEIGHT	1080

static const struct apple_prores_raw apple_prores_raws[] = {
	{ V4L2_PIX_FMT_NV16, 2, 1 },
	{ V4L2_PIX_FMT_NV24, 3, 2 },
};

static const struct apple_prores_profile apple_prores_profiles[] = {
	{ V4L2_PIX_FMT_APCN, "422", false, 0x23, 2, 0x248, 0x298 },
	{ V4L2_PIX_FMT_APCH, "422 HQ", false, 0x13, 1, 0x378, 0x3e8 },
	{ V4L2_PIX_FMT_APCS, "422 LT", false, 0x33, 3, 0x198, 0x1c8 },
	{ V4L2_PIX_FMT_APCO, "422 Proxy", false, 0x43, 8, 0xb0, 0xc8 },
	{ V4L2_PIX_FMT_AP4H, "4444", true, 0x13, 1, 0x538, 0x5e0 },
	{ V4L2_PIX_FMT_AP4X, "4444 XQ", true, 0x03, 1, 0x7e8, 0x8e0 },
};

#define APPLE_PRORES_DEFAULT_TPF ((struct v4l2_fract){ 1, 30 })

/* getFrameRate's table, RDD 36's codes */
static const struct {
	u32 num, den;
	u8 code;
} apple_prores_rates[] = {
	{ 24000, 1001, 1 }, { 24, 1, 2 }, { 25, 1, 3 }, { 30000, 1001, 4 },
	{ 30, 1, 5 }, { 50, 1, 6 }, { 60000, 1001, 7 }, { 60, 1, 8 },
	{ 100, 1, 9 }, { 120000, 1001, 10 }, { 120, 1, 11 },
};

static struct apple_prores_ctx *file_to_ctx(struct file *file)
{
	return container_of(file_to_v4l2_fh(file), struct apple_prores_ctx, fh);
}

static const struct apple_prores_raw *apple_prores_find_raw(u32 fourcc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(apple_prores_raws); i++)
		if (apple_prores_raws[i].fourcc == fourcc)
			return &apple_prores_raws[i];
	return &apple_prores_raws[0];
}

static const struct apple_prores_profile *apple_prores_find_profile(u32 fourcc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(apple_prores_profiles); i++)
		if (apple_prores_profiles[i].fourcc == fourcc)
			return &apple_prores_profiles[i];
	return &apple_prores_profiles[0];
}

static void apple_prores_fill_out(struct v4l2_pix_format_mplane *pix,
				  const struct apple_prores_raw *raw)
{
	u32 bpl;

	pix->width = ALIGN(clamp_t(u32, pix->width, APPLE_PRORES_MIN_DIM,
				   APPLE_PRORES_MAX_DIM), 2);
	pix->height = clamp_t(u32, pix->height, APPLE_PRORES_MIN_DIM,
			      APPLE_PRORES_MAX_DIM);
	bpl = ALIGN(pix->width, 64);
	pix->pixelformat = raw->fourcc;
	pix->field = V4L2_FIELD_NONE;
	pix->num_planes = 1;
	pix->flags = 0;
	pix->plane_fmt[0].bytesperline = bpl;
	pix->plane_fmt[0].sizeimage = bpl * pix->height +
				      ALIGN(pix->width * raw->cpp1, 64) * pix->height;
	memset(pix->plane_fmt[0].reserved, 0, sizeof(pix->plane_fmt[0].reserved));
	if (pix->colorspace == V4L2_COLORSPACE_DEFAULT)
		pix->colorspace = V4L2_COLORSPACE_REC709;
}

/* the largest frame of any profile stays under 4 bytes a pixel (estimate) */
static void apple_prores_fill_cap(struct v4l2_pix_format_mplane *pix,
				  const struct apple_prores_profile *profile,
				  const struct v4l2_pix_format_mplane *out)
{
	u64 size = (u64)out->width * out->height * 4 + SZ_64K;

	size = max_t(u64, size, pix->plane_fmt[0].sizeimage);
	pix->width = out->width;
	pix->height = out->height;
	pix->pixelformat = profile->fourcc;
	pix->field = V4L2_FIELD_NONE;
	pix->num_planes = 1;
	pix->flags = 0;
	pix->colorspace = out->colorspace;
	pix->xfer_func = out->xfer_func;
	pix->ycbcr_enc = out->ycbcr_enc;
	pix->quantization = out->quantization;
	pix->plane_fmt[0].bytesperline = 0;
	pix->plane_fmt[0].sizeimage = min_t(u64, size, SZ_256M);
	memset(pix->plane_fmt[0].reserved, 0, sizeof(pix->plane_fmt[0].reserved));
}

/* the frame header's colour codes, 2 unspecified */
static void apple_prores_colour(const struct v4l2_pix_format_mplane *pix,
				struct apple_prores_job *job)
{
	job->primaries = 2;
	job->transfer = 2;
	job->matrix = 2;

	switch (pix->colorspace) {
	case V4L2_COLORSPACE_REC709:
		job->primaries = 1;
		job->transfer = 1;
		job->matrix = 1;
		break;
	case V4L2_COLORSPACE_SMPTE170M:
		job->primaries = 6;
		job->transfer = 6;
		job->matrix = 6;
		break;
	case V4L2_COLORSPACE_BT2020:
		job->primaries = 9;
		job->transfer = 9;
		job->matrix = 9;
		break;
	default:
		break;
	}

	if (pix->xfer_func == V4L2_XFER_FUNC_SMPTE2084)
		job->transfer = 16;
}

static void apple_prores_job_done(struct apple_prores_ctx *ctx,
				  enum vb2_buffer_state state)
{
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	struct apple_prores_dev *apr = ctx->apr;
	struct vb2_v4l2_buffer *src, *dst;
	unsigned long flags;

	spin_lock_irqsave(&apr->hw_lock, flags);
	src = v4l2_m2m_src_buf_remove(m2m_ctx);
	dst = v4l2_m2m_dst_buf_remove(m2m_ctx);
	if (dst) {
		vb2_set_plane_payload(&dst->vb2_buf, 0,
				      state == VB2_BUF_STATE_DONE ? ctx->bytes : 0);
		if (src && v4l2_m2m_is_last_draining_src_buf(m2m_ctx, src)) {
			static const struct v4l2_event ev = {
				.type = V4L2_EVENT_EOS,
			};

			dst->flags |= V4L2_BUF_FLAG_LAST;
			v4l2_m2m_mark_stopped(m2m_ctx);
			v4l2_event_queue_fh(&ctx->fh, &ev);
		}
		v4l2_m2m_buf_done(dst, state);
	}
	if (src)
		v4l2_m2m_buf_done(src, state);
	spin_unlock_irqrestore(&apr->hw_lock, flags);

	v4l2_m2m_job_finish(apr->m2m_dev, m2m_ctx);
}

/* RDD 36's frame header, as the codec writes it */
struct apple_prores_hdr {
	u32 width, height;
	const struct apple_prores_raw *raw;
};

static int apple_prores_parse(struct apple_prores_ctx *ctx, struct vb2_buffer *vb,
			      struct apple_prores_hdr *hdr)
{
	const u8 *d = vb2_plane_vaddr(vb, 0);
	u32 len = vb2_get_plane_payload(vb, 0);

	if (!d || len < 24 || memcmp(d + 4, "icpf", 4) ||
	    get_unaligned_be32(d) > len)
		return -EINVAL;

	hdr->width = get_unaligned_be16(d + 16);
	hdr->height = get_unaligned_be16(d + 18);
	/* interlaced frames: not traced */
	if (d[20] & 0x0c || hdr->width < APPLE_PRORES_MIN_DIM ||
	    hdr->height < APPLE_PRORES_MIN_DIM ||
	    hdr->width > APPLE_PRORES_MAX_DIM || hdr->height > APPLE_PRORES_MAX_DIM ||
	    hdr->width & 1)
		return -EINVAL;

	switch (d[20] >> 6) {
	case 2:
		hdr->raw = &apple_prores_raws[0];
		return 0;
	case 3:
		hdr->raw = &apple_prores_raws[1];
		return 0;
	}
	return -EINVAL;
}

static void apple_prores_set_last_buffer(struct apple_prores_ctx *ctx)
{
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	struct vb2_v4l2_buffer *dst;
	unsigned long flags;

	spin_lock_irqsave(&ctx->apr->hw_lock, flags);
	dst = v4l2_m2m_dst_buf_remove(m2m_ctx);
	if (dst) {
		v4l2_m2m_last_buffer_done(m2m_ctx, dst);
	} else {
		m2m_ctx->is_draining = true;
		m2m_ctx->next_buf_last = true;
	}
	spin_unlock_irqrestore(&ctx->apr->hw_lock, flags);
}

/* a frame of another size or chroma: the client sets the capture queue up again */
static bool apple_prores_source_change(struct apple_prores_ctx *ctx,
				       const struct apple_prores_hdr *hdr)
{
	static const struct v4l2_event ev = {
		.type = V4L2_EVENT_SOURCE_CHANGE,
		.u.src_change.changes = V4L2_EVENT_SRC_CH_RESOLUTION,
	};
	struct v4l2_pix_format_mplane *cap = &ctx->cap_fmt;

	if (ctx->source_change)
		return true;
	if (!ctx->need_initial_source_change && cap->width == hdr->width &&
	    cap->height == hdr->height && ctx->raw == hdr->raw)
		return false;

	cap->width = hdr->width;
	cap->height = hdr->height;
	ctx->raw = hdr->raw;
	apple_prores_fill_out(cap, ctx->raw);
	ctx->need_initial_source_change = false;
	ctx->source_change = true;
	v4l2_event_queue_fh(&ctx->fh, &ev);

	if (vb2_is_streaming(v4l2_m2m_get_dst_vq(ctx->fh.m2m_ctx)))
		apple_prores_set_last_buffer(ctx);
	return true;
}

static int apple_prores_job_ready(void *priv)
{
	return !((struct apple_prores_ctx *)priv)->source_change;
}

static void apple_prores_device_run(void *priv)
{
	struct apple_prores_ctx *ctx = priv;
	struct apple_prores_dev *apr = ctx->apr;
	const struct v4l2_pix_format_mplane *out = &ctx->out_fmt;
	const struct v4l2_pix_format_mplane *cap = &ctx->cap_fmt;
	struct vb2_v4l2_buffer *src, *dst;
	struct apple_prores_job job = {};
	struct apple_prores_hdr hdr;
	unsigned long flags;
	int ret;

	src = v4l2_m2m_next_src_buf(ctx->fh.m2m_ctx);
	dst = v4l2_m2m_next_dst_buf(ctx->fh.m2m_ctx);
	if (!src || !dst) {
		v4l2_m2m_job_finish(apr->m2m_dev, ctx->fh.m2m_ctx);
		return;
	}

	if (ctx->decoder) {
		if (apple_prores_parse(ctx, &src->vb2_buf, &hdr)) {
			dev_dbg(apr->dev, "no frame in an OUTPUT buffer\n");
			src->sequence = ctx->out_seq++;
			dst->sequence = ctx->cap_seq++;
			v4l2_m2m_buf_copy_metadata(src, dst);
			apple_prores_job_done(ctx, VB2_BUF_STATE_ERROR);
			return;
		}
		if (apple_prores_source_change(ctx, &hdr)) {
			v4l2_m2m_job_finish(apr->m2m_dev, ctx->fh.m2m_ctx);
			return;
		}
	}

	src->sequence = ctx->out_seq++;
	dst->sequence = ctx->cap_seq++;
	v4l2_m2m_buf_copy_metadata(src, dst);

	job.raw = ctx->raw;
	job.profile = ctx->profile;
	job.frame = src->sequence;
	job.src0 = vb2_dma_contig_plane_dma_addr(&src->vb2_buf, 0);
	job.dst = vb2_dma_contig_plane_dma_addr(&dst->vb2_buf, 0);
	if (ctx->decoder) {
		job.width = cap->width;
		job.height = cap->height;
		job.stride0 = cap->plane_fmt[0].bytesperline;
		job.stride1 = ALIGN(cap->width * ctx->raw->cpp1, 64);
		job.dst1 = job.dst + job.stride0 * cap->height;
	} else {
		job.width = out->width;
		job.height = out->height;
		job.stride0 = out->plane_fmt[0].bytesperline;
		job.stride1 = ALIGN(out->width * ctx->raw->cpp1, 64);
		job.src1 = job.src0 + job.stride0 * out->height;
		job.dst_size = vb2_plane_size(&dst->vb2_buf, 0);
		job.rate_code = ctx->rate_code;
		apple_prores_colour(out, &job);
	}

	ret = pm_runtime_resume_and_get(apr->dev);
	if (ret) {
		dev_err(apr->dev, "failed to power up: %d\n", ret);
		apple_prores_job_done(ctx, VB2_BUF_STATE_ERROR);
		return;
	}

	spin_lock_irqsave(&apr->hw_lock, flags);
	apr->curr = ctx;
	spin_unlock_irqrestore(&apr->hw_lock, flags);

	/* before the head moves: a fast interrupt must not leave this to the next job */
	mod_delayed_work(system_wq, &apr->timeout_work,
			 msecs_to_jiffies(APPLE_PRORES_TIMEOUT_MS));
	if (ctx->decoder)
		apple_prores_hw_decode(apr, &job);
	else
		apple_prores_hw_encode(apr, &job);
}

/* the frame's own size word (RDD 36): no register holds it */
static u32 apple_prores_frame_size(struct apple_prores_ctx *ctx)
{
	struct vb2_v4l2_buffer *dst = v4l2_m2m_next_dst_buf(ctx->fh.m2m_ctx);
	const u8 *hdr = dst ? vb2_plane_vaddr(&dst->vb2_buf, 0) : NULL;
	u32 size;

	if (!hdr)
		return 0;
	size = get_unaligned_be32(hdr);
	if (size < 8 || size > vb2_plane_size(&dst->vb2_buf, 0) ||
	    memcmp(hdr + 4, "icpf", 4)) {
		dev_err(ctx->apr->dev, "no frame in the output: %*ph\n", 8, hdr);
		return 0;
	}
	return size;
}

irqreturn_t apple_prores_irq_thread(int irq, void *data)
{
	struct apple_prores_dev *apr = data;
	struct apple_prores_ctx *ctx;
	struct apple_prores_status st;
	unsigned long flags;

	if (pm_runtime_get_if_active(apr->dev) <= 0)
		return IRQ_NONE;
	if (!apple_prores_hw_irq(apr, &st)) {
		pm_runtime_put_autosuspend(apr->dev);
		return IRQ_NONE;
	}

	spin_lock_irqsave(&apr->hw_lock, flags);
	ctx = apr->curr;
	apr->curr = NULL;
	spin_unlock_irqrestore(&apr->hw_lock, flags);

	if (ctx) {
		bool failed = apple_prores_hw_failed(apr, &st);

		cancel_delayed_work(&apr->timeout_work);
		if (ctx->decoder)
			ctx->bytes = ctx->cap_fmt.plane_fmt[0].sizeimage;
		else
			ctx->bytes = failed ? 0 : apple_prores_frame_size(ctx);
		failed |= !ctx->bytes;
		dev_dbg(apr->dev, "done: irq %#x st %#x %#x %#x, %u bytes\n", st.irq,
			st.st0, st.st1, st.st2, ctx->bytes);
		pm_runtime_put_autosuspend(apr->dev);
		apple_prores_job_done(ctx, failed ? VB2_BUF_STATE_ERROR :
					    VB2_BUF_STATE_DONE);
	}
	pm_runtime_put_autosuspend(apr->dev);

	return IRQ_HANDLED;
}

/* timerHandler's reset, without its traffic's quiesce */
void apple_prores_timeout_work(struct work_struct *work)
{
	struct apple_prores_dev *apr =
		container_of(to_delayed_work(work), struct apple_prores_dev,
			     timeout_work);
	struct apple_prores_ctx *ctx;
	unsigned long flags;

	spin_lock_irqsave(&apr->hw_lock, flags);
	ctx = apr->curr;
	apr->curr = NULL;
	spin_unlock_irqrestore(&apr->hw_lock, flags);

	if (!ctx)
		return;

	dev_err(apr->dev, "job timed out\n");
	if (pm_runtime_get_if_active(apr->dev) > 0) {
		apple_prores_hw_dump(apr);
		apple_prores_hw_deactivate(apr);
		apple_prores_hw_activate(apr);
		pm_runtime_put_autosuspend(apr->dev);
	}
	pm_runtime_put_autosuspend(apr->dev);
	apple_prores_job_done(ctx, VB2_BUF_STATE_ERROR);
}

static int apple_prores_queue_setup(struct vb2_queue *q, unsigned int *nbuffers,
				    unsigned int *nplanes, unsigned int sizes[],
				    struct device *alloc_devs[])
{
	struct apple_prores_ctx *ctx = vb2_get_drv_priv(q);
	const struct v4l2_pix_format_mplane *pix;
	u32 size;

	pix = V4L2_TYPE_IS_OUTPUT(q->type) ? &ctx->out_fmt : &ctx->cap_fmt;
	size = pix->plane_fmt[0].sizeimage;

	/* the first frame's header sets the capture format */
	if (ctx->decoder && V4L2_TYPE_IS_OUTPUT(q->type) &&
	    !vb2_is_streaming(v4l2_m2m_get_dst_vq(ctx->fh.m2m_ctx)))
		ctx->need_initial_source_change = true;

	if (*nplanes)
		return *nplanes != 1 || sizes[0] < size ? -EINVAL : 0;

	*nplanes = 1;
	sizes[0] = size;

	return 0;
}

static int apple_prores_buf_out_validate(struct vb2_buffer *vb)
{
	to_vb2_v4l2_buffer(vb)->field = V4L2_FIELD_NONE;
	return 0;
}

static int apple_prores_buf_prepare(struct vb2_buffer *vb)
{
	struct apple_prores_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);

	to_vb2_v4l2_buffer(vb)->field = V4L2_FIELD_NONE;

	if (V4L2_TYPE_IS_OUTPUT(vb->vb2_queue->type) && ctx->decoder)
		return vb2_get_plane_payload(vb, 0) ? 0 : -EINVAL;

	if (V4L2_TYPE_IS_OUTPUT(vb->vb2_queue->type))
		return vb2_get_plane_payload(vb, 0) <
		       ctx->out_fmt.plane_fmt[0].sizeimage ? -EINVAL : 0;

	if (vb2_plane_size(vb, 0) < ctx->cap_fmt.plane_fmt[0].sizeimage)
		return -EINVAL;
	vb2_set_plane_payload(vb, 0, 0);

	return 0;
}

static void apple_prores_buf_queue(struct vb2_buffer *vb)
{
	struct apple_prores_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;

	if (V4L2_TYPE_IS_CAPTURE(vb->vb2_queue->type) &&
	    vb2_is_streaming(vb->vb2_queue) &&
	    v4l2_m2m_dst_buf_is_last(m2m_ctx)) {
		static const struct v4l2_event ev = {
			.type = V4L2_EVENT_EOS,
		};

		vbuf->field = V4L2_FIELD_NONE;
		vbuf->sequence = ctx->cap_seq++;
		v4l2_m2m_last_buffer_done(m2m_ctx, vbuf);
		v4l2_event_queue_fh(&ctx->fh, &ev);
		return;
	}

	if (V4L2_TYPE_IS_OUTPUT(vb->vb2_queue->type) && ctx->decoder) {
		struct apple_prores_hdr hdr;

		if (apple_prores_parse(ctx, vb, &hdr)) {
			/* without a capture queue no job would ever return it */
			if (!vb2_is_streaming(v4l2_m2m_get_dst_vq(m2m_ctx))) {
				vbuf->sequence = ctx->out_seq++;
				v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_ERROR);
				return;
			}
		} else if (!v4l2_m2m_num_src_bufs_ready(m2m_ctx)) {
			apple_prores_source_change(ctx, &hdr);
		}
	}

	v4l2_m2m_buf_queue(m2m_ctx, vbuf);
}

static int apple_prores_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct apple_prores_ctx *ctx = vb2_get_drv_priv(q);

	v4l2_m2m_update_start_streaming_state(ctx->fh.m2m_ctx, q);

	if (V4L2_TYPE_IS_CAPTURE(q->type)) {
		ctx->cap_seq = 0;
		ctx->source_change = false;
		ctx->need_initial_source_change = false;
	}

	return 0;
}

static void apple_prores_stop_streaming(struct vb2_queue *q)
{
	struct apple_prores_ctx *ctx = vb2_get_drv_priv(q);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	struct vb2_v4l2_buffer *vbuf;

	for (;;) {
		if (V4L2_TYPE_IS_OUTPUT(q->type))
			vbuf = v4l2_m2m_src_buf_remove(m2m_ctx);
		else
			vbuf = v4l2_m2m_dst_buf_remove(m2m_ctx);
		if (!vbuf)
			break;
		v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_ERROR);
	}

	v4l2_m2m_update_stop_streaming_state(m2m_ctx, q);

	/* here, not at the start: the decoder returns a bad buffer as it is queued */
	if (V4L2_TYPE_IS_OUTPUT(q->type))
		ctx->out_seq = 0;

	/* a STOP sent before the source change still drains */
	if (V4L2_TYPE_IS_CAPTURE(q->type) && ctx->source_change &&
	    m2m_ctx->last_src_buf)
		m2m_ctx->is_draining = true;

	if (V4L2_TYPE_IS_OUTPUT(q->type) && v4l2_m2m_has_stopped(m2m_ctx)) {
		static const struct v4l2_event ev = {
			.type = V4L2_EVENT_EOS,
		};

		v4l2_event_queue_fh(&ctx->fh, &ev);
	}
}

static const struct vb2_ops apple_prores_qops = {
	.queue_setup = apple_prores_queue_setup,
	.buf_out_validate = apple_prores_buf_out_validate,
	.buf_prepare = apple_prores_buf_prepare,
	.buf_queue = apple_prores_buf_queue,
	.start_streaming = apple_prores_start_streaming,
	.stop_streaming = apple_prores_stop_streaming,
};

static int apple_prores_queue_init(void *priv, struct vb2_queue *src_vq,
				   struct vb2_queue *dst_vq)
{
	struct apple_prores_ctx *ctx = priv;
	int ret;

	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	src_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	src_vq->drv_priv = ctx;
	src_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	src_vq->ops = &apple_prores_qops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	src_vq->lock = &ctx->apr->lock;
	src_vq->dev = ctx->apr->dev;

	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	dst_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	dst_vq->drv_priv = ctx;
	dst_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	dst_vq->ops = &apple_prores_qops;
	dst_vq->mem_ops = &vb2_dma_contig_memops;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	dst_vq->lock = &ctx->apr->lock;
	dst_vq->dev = ctx->apr->dev;

	return vb2_queue_init(dst_vq);
}

static int apple_prores_querycap(struct file *file, void *priv,
				 struct v4l2_capability *cap)
{
	strscpy(cap->driver, APPLE_PRORES_NAME, sizeof(cap->driver));
	strscpy(cap->card, "Apple ProRes codec", sizeof(cap->card));
	return 0;
}

static int apple_prores_enum_fmt_vid_cap(struct file *file, void *priv,
					 struct v4l2_fmtdesc *f)
{
	if (f->index >= ARRAY_SIZE(apple_prores_profiles))
		return -EINVAL;
	f->pixelformat = apple_prores_profiles[f->index].fourcc;
	return 0;
}

static int apple_prores_enum_fmt_vid_out(struct file *file, void *priv,
					 struct v4l2_fmtdesc *f)
{
	if (f->index >= ARRAY_SIZE(apple_prores_raws))
		return -EINVAL;
	f->pixelformat = apple_prores_raws[f->index].fourcc;
	return 0;
}

static int apple_prores_dec_enum_fmt_vid_cap(struct file *file, void *priv,
					     struct v4l2_fmtdesc *f)
{
	return apple_prores_enum_fmt_vid_out(file, priv, f);
}

static int apple_prores_dec_enum_fmt_vid_out(struct file *file, void *priv,
					     struct v4l2_fmtdesc *f)
{
	f->flags |= V4L2_FMT_FLAG_DYN_RESOLUTION;
	return apple_prores_enum_fmt_vid_cap(file, priv, f);
}

static int apple_prores_enum_framesizes(struct file *file, void *priv,
					struct v4l2_frmsizeenum *fsize)
{
	unsigned int i;
	bool known = false;

	for (i = 0; i < ARRAY_SIZE(apple_prores_raws); i++)
		known |= apple_prores_raws[i].fourcc == fsize->pixel_format;
	for (i = 0; i < ARRAY_SIZE(apple_prores_profiles); i++)
		known |= apple_prores_profiles[i].fourcc == fsize->pixel_format;
	if (fsize->index || !known)
		return -EINVAL;
	fsize->type = V4L2_FRMSIZE_TYPE_CONTINUOUS;
	fsize->stepwise.min_width = APPLE_PRORES_MIN_DIM;
	fsize->stepwise.max_width = APPLE_PRORES_MAX_DIM;
	fsize->stepwise.step_width = 1;
	fsize->stepwise.min_height = APPLE_PRORES_MIN_DIM;
	fsize->stepwise.max_height = APPLE_PRORES_MAX_DIM;
	fsize->stepwise.step_height = 1;
	return 0;
}

static int apple_prores_g_fmt_vid_cap(struct file *file, void *priv,
				      struct v4l2_format *f)
{
	f->fmt.pix_mp = file_to_ctx(file)->cap_fmt;
	return 0;
}

static int apple_prores_g_fmt_vid_out(struct file *file, void *priv,
				      struct v4l2_format *f)
{
	f->fmt.pix_mp = file_to_ctx(file)->out_fmt;
	return 0;
}

static int apple_prores_try_fmt_vid_out(struct file *file, void *priv,
					struct v4l2_format *f)
{
	apple_prores_fill_out(&f->fmt.pix_mp,
			      apple_prores_find_raw(f->fmt.pix_mp.pixelformat));
	return 0;
}

static int apple_prores_try_fmt_vid_cap(struct file *file, void *priv,
					struct v4l2_format *f)
{
	apple_prores_fill_cap(&f->fmt.pix_mp,
			      apple_prores_find_profile(f->fmt.pix_mp.pixelformat),
			      &file_to_ctx(file)->out_fmt);
	return 0;
}

static int apple_prores_s_fmt_vid_out(struct file *file, void *priv,
				      struct v4l2_format *f)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);

	if (vb2_is_busy(v4l2_m2m_get_src_vq(ctx->fh.m2m_ctx)))
		return -EBUSY;

	apple_prores_try_fmt_vid_out(file, priv, f);
	ctx->out_fmt = f->fmt.pix_mp;
	ctx->raw = apple_prores_find_raw(f->fmt.pix_mp.pixelformat);

	ctx->cap_fmt.plane_fmt[0].sizeimage = 0;
	apple_prores_fill_cap(&ctx->cap_fmt, ctx->profile, &ctx->out_fmt);
	return 0;
}

static int apple_prores_s_fmt_vid_cap(struct file *file, void *priv,
				      struct v4l2_format *f)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);

	if (vb2_is_busy(v4l2_m2m_get_dst_vq(ctx->fh.m2m_ctx)))
		return -EBUSY;

	apple_prores_try_fmt_vid_cap(file, priv, f);
	ctx->cap_fmt = f->fmt.pix_mp;
	ctx->profile = apple_prores_find_profile(f->fmt.pix_mp.pixelformat);
	return 0;
}

static int apple_prores_dec_try_fmt_vid_out(struct file *file, void *priv,
					    struct v4l2_format *f)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);
	struct v4l2_pix_format_mplane raw = f->fmt.pix_mp;

	apple_prores_fill_out(&raw, ctx->raw);
	apple_prores_fill_cap(&f->fmt.pix_mp,
			      apple_prores_find_profile(f->fmt.pix_mp.pixelformat),
			      &raw);
	return 0;
}

/* the frame's header sets the size */
static int apple_prores_dec_try_fmt_vid_cap(struct file *file, void *priv,
					    struct v4l2_format *f)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);

	f->fmt.pix_mp.width = ctx->cap_fmt.width;
	f->fmt.pix_mp.height = ctx->cap_fmt.height;
	f->fmt.pix_mp.colorspace = ctx->out_fmt.colorspace;
	f->fmt.pix_mp.xfer_func = ctx->out_fmt.xfer_func;
	f->fmt.pix_mp.ycbcr_enc = ctx->out_fmt.ycbcr_enc;
	f->fmt.pix_mp.quantization = ctx->out_fmt.quantization;
	apple_prores_fill_out(&f->fmt.pix_mp,
			      apple_prores_find_raw(f->fmt.pix_mp.pixelformat));
	return 0;
}

static int apple_prores_dec_s_fmt_vid_out(struct file *file, void *priv,
					  struct v4l2_format *f)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);

	if (vb2_is_busy(v4l2_m2m_get_src_vq(ctx->fh.m2m_ctx)))
		return -EBUSY;

	apple_prores_dec_try_fmt_vid_out(file, priv, f);
	ctx->out_fmt = f->fmt.pix_mp;
	ctx->profile = apple_prores_find_profile(f->fmt.pix_mp.pixelformat);
	if (!vb2_is_busy(v4l2_m2m_get_dst_vq(ctx->fh.m2m_ctx))) {
		ctx->cap_fmt.width = ctx->out_fmt.width;
		ctx->cap_fmt.height = ctx->out_fmt.height;
		ctx->cap_fmt.colorspace = ctx->out_fmt.colorspace;
		ctx->cap_fmt.xfer_func = ctx->out_fmt.xfer_func;
		ctx->cap_fmt.ycbcr_enc = ctx->out_fmt.ycbcr_enc;
		ctx->cap_fmt.quantization = ctx->out_fmt.quantization;
		apple_prores_fill_out(&ctx->cap_fmt, ctx->raw);
	}
	return 0;
}

static int apple_prores_dec_s_fmt_vid_cap(struct file *file, void *priv,
					  struct v4l2_format *f)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);

	if (vb2_is_busy(v4l2_m2m_get_dst_vq(ctx->fh.m2m_ctx)))
		return -EBUSY;

	apple_prores_dec_try_fmt_vid_cap(file, priv, f);
	ctx->cap_fmt = f->fmt.pix_mp;
	ctx->raw = apple_prores_find_raw(f->fmt.pix_mp.pixelformat);
	return 0;
}

static int apple_prores_s_parm(struct file *file, void *priv,
			       struct v4l2_streamparm *a)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);
	struct v4l2_fract *tpf;
	unsigned int i;

	if (!V4L2_TYPE_IS_OUTPUT(a->type))
		return -EINVAL;
	tpf = &a->parm.output.timeperframe;
	a->parm.output.capability = V4L2_CAP_TIMEPERFRAME;
	ctx->rate_code = 0;
	if (!tpf->numerator || !tpf->denominator)
		*tpf = APPLE_PRORES_DEFAULT_TPF;
	ctx->tpf = *tpf;
	for (i = 0; i < ARRAY_SIZE(apple_prores_rates); i++)
		if ((u64)apple_prores_rates[i].num * tpf->numerator ==
		    (u64)apple_prores_rates[i].den * tpf->denominator)
			ctx->rate_code = apple_prores_rates[i].code;
	return 0;
}

static int apple_prores_g_parm(struct file *file, void *priv,
			       struct v4l2_streamparm *a)
{
	if (!V4L2_TYPE_IS_OUTPUT(a->type))
		return -EINVAL;
	a->parm.output.capability = V4L2_CAP_TIMEPERFRAME;
	a->parm.output.timeperframe = file_to_ctx(file)->tpf;
	return 0;
}

static int apple_prores_subscribe_event(struct v4l2_fh *fh,
					const struct v4l2_event_subscription *sub)
{
	if (sub->type == V4L2_EVENT_EOS)
		return v4l2_event_subscribe(fh, sub, 2, NULL);
	if (sub->type == V4L2_EVENT_SOURCE_CHANGE)
		return v4l2_src_change_event_subscribe(fh, sub);
	return v4l2_ctrl_subscribe_event(fh, sub);
}

static int apple_prores_encoder_cmd(struct file *file, void *priv,
				    struct v4l2_encoder_cmd *cmd)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	unsigned long flags;
	bool stopped;
	int ret;

	ret = v4l2_m2m_ioctl_try_encoder_cmd(file, priv, cmd);
	if (ret < 0)
		return ret;

	if (!vb2_is_streaming(v4l2_m2m_get_src_vq(m2m_ctx)))
		return 0;

	spin_lock_irqsave(&ctx->apr->hw_lock, flags);
	stopped = v4l2_m2m_has_stopped(m2m_ctx);
	ret = v4l2_m2m_ioctl_encoder_cmd(file, priv, cmd);
	spin_unlock_irqrestore(&ctx->apr->hw_lock, flags);
	if (ret < 0)
		return ret;

	if (cmd->cmd == V4L2_ENC_CMD_STOP && v4l2_m2m_has_stopped(m2m_ctx)) {
		static const struct v4l2_event ev = {
			.type = V4L2_EVENT_EOS,
		};

		v4l2_event_queue_fh(&ctx->fh, &ev);
	}
	if (cmd->cmd == V4L2_ENC_CMD_START && stopped) {
		vb2_clear_last_buffer_dequeued(&m2m_ctx->cap_q_ctx.q);
		v4l2_m2m_try_schedule(m2m_ctx);
	}

	return 0;
}

static int apple_prores_decoder_cmd(struct file *file, void *priv,
				    struct v4l2_decoder_cmd *cmd)
{
	struct apple_prores_ctx *ctx = file_to_ctx(file);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	unsigned long flags;
	bool stopped;
	int ret;

	ret = v4l2_m2m_ioctl_try_decoder_cmd(file, priv, cmd);
	if (ret < 0)
		return ret;

	if (!vb2_is_streaming(v4l2_m2m_get_src_vq(m2m_ctx)))
		return 0;

	spin_lock_irqsave(&ctx->apr->hw_lock, flags);
	stopped = v4l2_m2m_has_stopped(m2m_ctx);
	ret = v4l2_m2m_ioctl_decoder_cmd(file, priv, cmd);
	/* with no capture queue and nothing queued the drain is over at once */
	if (!ret && cmd->cmd == V4L2_DEC_CMD_STOP &&
	    !vb2_is_streaming(v4l2_m2m_get_dst_vq(m2m_ctx)) &&
	    !v4l2_m2m_num_src_bufs_ready(m2m_ctx))
		v4l2_m2m_mark_stopped(m2m_ctx);
	spin_unlock_irqrestore(&ctx->apr->hw_lock, flags);
	if (ret < 0)
		return ret;

	if (cmd->cmd == V4L2_DEC_CMD_STOP && v4l2_m2m_has_stopped(m2m_ctx)) {
		static const struct v4l2_event ev = {
			.type = V4L2_EVENT_EOS,
		};

		v4l2_event_queue_fh(&ctx->fh, &ev);
	}
	if (cmd->cmd == V4L2_DEC_CMD_START && stopped) {
		vb2_clear_last_buffer_dequeued(&m2m_ctx->cap_q_ctx.q);
		v4l2_m2m_try_schedule(m2m_ctx);
	}
	return 0;
}

static const struct v4l2_ioctl_ops apple_prores_dec_ioctl_ops = {
	.vidioc_querycap = apple_prores_querycap,

	.vidioc_enum_fmt_vid_cap = apple_prores_dec_enum_fmt_vid_cap,
	.vidioc_enum_fmt_vid_out = apple_prores_dec_enum_fmt_vid_out,
	.vidioc_enum_framesizes = apple_prores_enum_framesizes,
	.vidioc_g_fmt_vid_cap_mplane = apple_prores_g_fmt_vid_cap,
	.vidioc_g_fmt_vid_out_mplane = apple_prores_g_fmt_vid_out,
	.vidioc_try_fmt_vid_cap_mplane = apple_prores_dec_try_fmt_vid_cap,
	.vidioc_try_fmt_vid_out_mplane = apple_prores_dec_try_fmt_vid_out,
	.vidioc_s_fmt_vid_cap_mplane = apple_prores_dec_s_fmt_vid_cap,
	.vidioc_s_fmt_vid_out_mplane = apple_prores_dec_s_fmt_vid_out,

	.vidioc_subscribe_event = apple_prores_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,

	.vidioc_try_decoder_cmd = v4l2_m2m_ioctl_try_decoder_cmd,
	.vidioc_decoder_cmd = apple_prores_decoder_cmd,

	.vidioc_reqbufs = v4l2_m2m_ioctl_reqbufs,
	.vidioc_querybuf = v4l2_m2m_ioctl_querybuf,
	.vidioc_qbuf = v4l2_m2m_ioctl_qbuf,
	.vidioc_dqbuf = v4l2_m2m_ioctl_dqbuf,
	.vidioc_prepare_buf = v4l2_m2m_ioctl_prepare_buf,
	.vidioc_create_bufs = v4l2_m2m_ioctl_create_bufs,
	.vidioc_expbuf = v4l2_m2m_ioctl_expbuf,
	.vidioc_streamon = v4l2_m2m_ioctl_streamon,
	.vidioc_streamoff = v4l2_m2m_ioctl_streamoff,
};

static const struct v4l2_ioctl_ops apple_prores_enc_ioctl_ops = {
	.vidioc_querycap = apple_prores_querycap,

	.vidioc_enum_fmt_vid_cap = apple_prores_enum_fmt_vid_cap,
	.vidioc_enum_fmt_vid_out = apple_prores_enum_fmt_vid_out,
	.vidioc_enum_framesizes = apple_prores_enum_framesizes,
	.vidioc_g_fmt_vid_cap_mplane = apple_prores_g_fmt_vid_cap,
	.vidioc_g_fmt_vid_out_mplane = apple_prores_g_fmt_vid_out,
	.vidioc_try_fmt_vid_cap_mplane = apple_prores_try_fmt_vid_cap,
	.vidioc_try_fmt_vid_out_mplane = apple_prores_try_fmt_vid_out,
	.vidioc_s_fmt_vid_cap_mplane = apple_prores_s_fmt_vid_cap,
	.vidioc_s_fmt_vid_out_mplane = apple_prores_s_fmt_vid_out,
	.vidioc_g_parm = apple_prores_g_parm,
	.vidioc_s_parm = apple_prores_s_parm,

	.vidioc_subscribe_event = apple_prores_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,

	.vidioc_try_encoder_cmd = v4l2_m2m_ioctl_try_encoder_cmd,
	.vidioc_encoder_cmd = apple_prores_encoder_cmd,

	.vidioc_reqbufs = v4l2_m2m_ioctl_reqbufs,
	.vidioc_querybuf = v4l2_m2m_ioctl_querybuf,
	.vidioc_qbuf = v4l2_m2m_ioctl_qbuf,
	.vidioc_dqbuf = v4l2_m2m_ioctl_dqbuf,
	.vidioc_prepare_buf = v4l2_m2m_ioctl_prepare_buf,
	.vidioc_create_bufs = v4l2_m2m_ioctl_create_bufs,
	.vidioc_expbuf = v4l2_m2m_ioctl_expbuf,
	.vidioc_streamon = v4l2_m2m_ioctl_streamon,
	.vidioc_streamoff = v4l2_m2m_ioctl_streamoff,
};

static int apple_prores_open(struct file *file)
{
	struct apple_prores_dev *apr = video_drvdata(file);
	struct apple_prores_ctx *ctx;
	int ret;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	ctx->apr = apr;
	ctx->decoder = video_devdata(file) == &apr->vdev_dec;
	ctx->raw = &apple_prores_raws[0];
	ctx->profile = &apple_prores_profiles[0];
	ctx->tpf = APPLE_PRORES_DEFAULT_TPF;
	if (ctx->decoder) {
		ctx->cap_fmt.width = APPLE_PRORES_DEF_WIDTH;
		ctx->cap_fmt.height = APPLE_PRORES_DEF_HEIGHT;
		apple_prores_fill_out(&ctx->cap_fmt, ctx->raw);
		apple_prores_fill_cap(&ctx->out_fmt, ctx->profile, &ctx->cap_fmt);
	} else {
		ctx->out_fmt.width = APPLE_PRORES_DEF_WIDTH;
		ctx->out_fmt.height = APPLE_PRORES_DEF_HEIGHT;
		apple_prores_fill_out(&ctx->out_fmt, ctx->raw);
		apple_prores_fill_cap(&ctx->cap_fmt, ctx->profile, &ctx->out_fmt);
	}

	if (mutex_lock_interruptible(&apr->lock)) {
		kfree(ctx);
		return -ERESTARTSYS;
	}

	v4l2_fh_init(&ctx->fh, video_devdata(file));
	ctx->fh.m2m_ctx = v4l2_m2m_ctx_init(apr->m2m_dev, ctx,
					    apple_prores_queue_init);
	if (IS_ERR(ctx->fh.m2m_ctx)) {
		ret = PTR_ERR(ctx->fh.m2m_ctx);
		v4l2_fh_exit(&ctx->fh);
		mutex_unlock(&apr->lock);
		kfree(ctx);
		return ret;
	}
	v4l2_fh_add(&ctx->fh, file);
	mutex_unlock(&apr->lock);

	return 0;
}

static int apple_prores_release(struct file *file)
{
	struct apple_prores_dev *apr = video_drvdata(file);
	struct apple_prores_ctx *ctx = file_to_ctx(file);

	mutex_lock(&apr->lock);
	v4l2_m2m_ctx_release(ctx->fh.m2m_ctx);
	v4l2_fh_del(&ctx->fh, file);
	v4l2_fh_exit(&ctx->fh);
	mutex_unlock(&apr->lock);
	kfree(ctx);

	return 0;
}

static const struct v4l2_file_operations apple_prores_fops = {
	.owner = THIS_MODULE,
	.open = apple_prores_open,
	.release = apple_prores_release,
	.poll = v4l2_m2m_fop_poll,
	.unlocked_ioctl = video_ioctl2,
	.mmap = v4l2_m2m_fop_mmap,
};

static const struct v4l2_m2m_ops apple_prores_m2m_ops = {
	.device_run = apple_prores_device_run,
	.job_ready = apple_prores_job_ready,
};

static int apple_prores_register_node(struct apple_prores_dev *apr,
				      struct video_device *vdev, const char *name,
				      const struct v4l2_ioctl_ops *ops)
{
	int ret;

	strscpy(vdev->name, name, sizeof(vdev->name));
	vdev->fops = &apple_prores_fops;
	vdev->ioctl_ops = ops;
	vdev->minor = -1;
	vdev->release = video_device_release_empty;
	vdev->lock = &apr->lock;
	vdev->v4l2_dev = &apr->v4l2_dev;
	vdev->vfl_dir = VFL_DIR_M2M;
	vdev->device_caps = V4L2_CAP_STREAMING | V4L2_CAP_VIDEO_M2M_MPLANE;
	video_set_drvdata(vdev, apr);

	ret = video_register_device(vdev, VFL_TYPE_VIDEO, -1);
	if (!ret)
		dev_info(apr->dev, "%s registered as %s\n", name,
			 video_device_node_name(vdev));
	return ret;
}

int apple_prores_v4l2_register(struct apple_prores_dev *apr)
{
	int ret;

	ret = v4l2_device_register(apr->dev, &apr->v4l2_dev);
	if (ret)
		return ret;

	apr->m2m_dev = v4l2_m2m_init(&apple_prores_m2m_ops);
	if (IS_ERR(apr->m2m_dev)) {
		ret = PTR_ERR(apr->m2m_dev);
		goto err_v4l2;
	}

	ret = apple_prores_register_node(apr, &apr->vdev_enc, APPLE_PRORES_NAME "-enc",
					 &apple_prores_enc_ioctl_ops);
	if (ret)
		goto err_m2m;

	ret = apple_prores_register_node(apr, &apr->vdev_dec, APPLE_PRORES_NAME "-dec",
					 &apple_prores_dec_ioctl_ops);
	if (ret)
		goto err_enc;

	return 0;

err_enc:
	video_unregister_device(&apr->vdev_enc);
err_m2m:
	v4l2_m2m_release(apr->m2m_dev);
err_v4l2:
	v4l2_device_unregister(&apr->v4l2_dev);
	return ret;
}

void apple_prores_v4l2_unregister(struct apple_prores_dev *apr)
{
	video_unregister_device(&apr->vdev_dec);
	video_unregister_device(&apr->vdev_enc);
	v4l2_m2m_suspend(apr->m2m_dev);
	cancel_delayed_work_sync(&apr->timeout_work);
	v4l2_m2m_release(apr->m2m_dev);
	v4l2_device_unregister(&apr->v4l2_dev);
}
