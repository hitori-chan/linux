// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple JPEG codec: V4L2 memory-to-memory decoder
 *
 * Copyright The Asahi Linux Contributors
 *
 * The job flow follows the i.MX8 JPEG driver (mxc-jpeg): the header is
 * parsed when a JPEG buffer is queued, and a new size raises a source
 * change on the capture queue.
 */

#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-jpeg.h>
#include <media/v4l2-mem2mem.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-v4l2.h>

#include "jpeg.h"

#define APPLE_JPEG_TIMEOUT_MS	2000
#define APPLE_JPEG_DEF_WIDTH	640
#define APPLE_JPEG_DEF_HEIGHT	480

static bool header_window;
module_param(header_window, bool, 0644);
MODULE_PARM_DESC(header_window,
		 "Pass the JPEG markers through the header window (default: only for a stream without DHT)");

/*
 * decoder_req2setup maps the IOSurface FourCCs to these output modes. The
 * byte order of IMG_ARGB is inferred from the CoreVideo names: BGRA is B,
 * G, R, A in memory, RGBA (submode 1) R, G, B, A.
 */
static const struct apple_jpeg_fmt apple_jpeg_formats[] = {
	/* 420v */
	{ V4L2_PIX_FMT_NV12, APPLE_JPEG_MODE_YUV420_2P, 0, 1, 2 },
	/* 422v */
	{ V4L2_PIX_FMT_NV16, APPLE_JPEG_MODE_YUV422_2P, 0, 1, 1 },
	/* 2vuy */
	{ V4L2_PIX_FMT_UYVY, APPLE_JPEG_MODE_YUV422_1P, 0, 2, 0 },
	/* yuvs */
	{ V4L2_PIX_FMT_YUYV, APPLE_JPEG_MODE_YUV422_1P, 1, 2, 0 },
	/* BGRA, alpha 0xff */
	{ V4L2_PIX_FMT_XBGR32, APPLE_JPEG_MODE_ARGB, 0, 4, 0 },
	{ V4L2_PIX_FMT_ABGR32, APPLE_JPEG_MODE_ARGB, 0, 4, 0 },
	/* RGBA */
	{ V4L2_PIX_FMT_RGBX32, APPLE_JPEG_MODE_ARGB, 1, 4, 0 },
	{ V4L2_PIX_FMT_RGBA32, APPLE_JPEG_MODE_ARGB, 1, 4, 0 },
};

/* startDecoderGated fails an image narrower and lower than these */
static const struct {
	u16 w, h;
} apple_jpeg_min_size[] = {
	[APPLE_JPEG_SS_444] = { 8, 8 },
	[APPLE_JPEG_SS_422] = { 16, 8 },
	[APPLE_JPEG_SS_411] = { 32, 8 },
	[APPLE_JPEG_SS_420] = { 16, 16 },
	[APPLE_JPEG_SS_400] = { 8, 8 },
};

static struct apple_jpeg_ctx *file_to_ctx(struct file *file)
{
	return container_of(file_to_v4l2_fh(file), struct apple_jpeg_ctx, fh);
}

static struct apple_jpeg_src_buf *to_src_buf(struct vb2_v4l2_buffer *vbuf)
{
	return container_of(vbuf, struct apple_jpeg_src_buf, m2m.vb);
}

static const struct apple_jpeg_fmt *apple_jpeg_find_fmt(u32 fourcc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(apple_jpeg_formats); i++)
		if (apple_jpeg_formats[i].fourcc == fourcc)
			return &apple_jpeg_formats[i];

	return NULL;
}

static void apple_jpeg_colorimetry(struct v4l2_pix_format_mplane *pix)
{
	pix->field = V4L2_FIELD_NONE;
	/* V4L2_COLORSPACE_JPEG spelled out, as the raw side must say sRGB */
	pix->colorspace = V4L2_COLORSPACE_SRGB;
	pix->ycbcr_enc = V4L2_YCBCR_ENC_601;
	pix->quantization = V4L2_QUANTIZATION_FULL_RANGE;
	pix->xfer_func = V4L2_XFER_FUNC_SRGB;
}

static void apple_jpeg_fill_cap(struct v4l2_pix_format_mplane *pix,
				const struct apple_jpeg_fmt *fmt)
{
	u32 bpl = ALIGN(pix->width * fmt->cpp, 64);
	u32 size = bpl * pix->height;

	if (fmt->vsub)
		size += bpl * DIV_ROUND_UP(pix->height, fmt->vsub);

	pix->pixelformat = fmt->fourcc;
	pix->num_planes = 1;
	pix->plane_fmt[0].bytesperline = bpl;
	pix->plane_fmt[0].sizeimage = size;
	memset(pix->plane_fmt[0].reserved, 0,
	       sizeof(pix->plane_fmt[0].reserved));
	apple_jpeg_colorimetry(pix);
}

/* a larger buffer than the default for the size, if asked for, is kept */
static void apple_jpeg_fill_out(struct v4l2_pix_format_mplane *pix)
{
	u32 size = clamp_t(u32, pix->width * pix->height * 3 / 2 + SZ_64K,
			   SZ_256K, SZ_64M);

	size = max(size, pix->plane_fmt[0].sizeimage);
	pix->pixelformat = V4L2_PIX_FMT_JPEG;
	pix->num_planes = 1;
	pix->plane_fmt[0].bytesperline = 0;
	pix->plane_fmt[0].sizeimage = min_t(u32, size, SZ_256M);
	memset(pix->plane_fmt[0].reserved, 0,
	       sizeof(pix->plane_fmt[0].reserved));
	apple_jpeg_colorimetry(pix);
}

static void apple_jpeg_clamp_size(struct v4l2_pix_format_mplane *pix)
{
	pix->width = clamp_t(u32, pix->width, APPLE_JPEG_MIN_DIM,
			     APPLE_JPEG_MAX_DIM);
	pix->height = clamp_t(u32, pix->height, APPLE_JPEG_MIN_DIM,
			      APPLE_JPEG_MAX_DIM);
}

static void apple_jpeg_notify_eos(struct apple_jpeg_ctx *ctx)
{
	static const struct v4l2_event ev = {
		.type = V4L2_EVENT_EOS,
	};

	v4l2_event_queue_fh(&ctx->fh, &ev);
}

static void apple_jpeg_notify_src_change(struct apple_jpeg_ctx *ctx)
{
	static const struct v4l2_event ev = {
		.type = V4L2_EVENT_SOURCE_CHANGE,
		.u.src_change.changes = V4L2_EVENT_SRC_CH_RESOLUTION,
	};

	v4l2_event_queue_fh(&ctx->fh, &ev);
}

/* with jpeg->hw_lock held */
static void apple_jpeg_set_last_buffer(struct apple_jpeg_ctx *ctx)
{
	struct vb2_v4l2_buffer *dst;

	dst = v4l2_m2m_dst_buf_remove(ctx->fh.m2m_ctx);
	if (!dst) {
		ctx->fh.m2m_ctx->is_draining = true;
		ctx->fh.m2m_ctx->next_buf_last = true;
		return;
	}

	v4l2_m2m_last_buffer_done(ctx->fh.m2m_ctx, dst);
}

/*
 * A JPEG of another size: set the capture format to it, keeping the pixel
 * format, and wait for the client to set the capture queue up again.
 */
static bool apple_jpeg_source_change(struct apple_jpeg_ctx *ctx,
				     struct apple_jpeg_src_buf *jbuf)
{
	struct v4l2_pix_format_mplane *cap = &ctx->cap_fmt;
	unsigned long flags;

	if (ctx->source_change)
		return true;
	if (!ctx->need_initial_source_change && cap->width == jbuf->width &&
	    cap->height == jbuf->height)
		return false;

	dev_dbg(ctx->jpeg->dev, "source change: %ux%u to %ux%u\n",
		cap->width, cap->height, jbuf->width, jbuf->height);

	cap->width = jbuf->width;
	cap->height = jbuf->height;
	apple_jpeg_fill_cap(cap, ctx->cap_jfmt);
	ctx->need_initial_source_change = false;
	ctx->source_change = true;
	apple_jpeg_notify_src_change(ctx);

	if (vb2_is_streaming(v4l2_m2m_get_dst_vq(ctx->fh.m2m_ctx))) {
		spin_lock_irqsave(&ctx->jpeg->hw_lock, flags);
		apple_jpeg_set_last_buffer(ctx);
		spin_unlock_irqrestore(&ctx->jpeg->hw_lock, flags);
	}

	return true;
}

static int apple_jpeg_window_add(struct apple_jpeg_src_buf *jbuf, u32 *len,
				 u8 marker, const u8 *seg, u32 seg_len)
{
	/* room for up to 7 bytes of front padding */
	if (*len + 2 + seg_len > JPEG_HDR_WINDOW_SIZE - 8)
		return -E2BIG;

	jbuf->hdr[8 + *len] = 0xff;
	jbuf->hdr[8 + *len + 1] = marker;
	memcpy(&jbuf->hdr[8 + *len + 2], seg, seg_len);
	*len += 2 + seg_len;

	return 0;
}

/* a DHT segment with the four tables of ITU-T T.81 Annex K.3 */
static int apple_jpeg_window_add_dht(struct apple_jpeg_src_buf *jbuf, u32 *len)
{
	static const struct {
		u8 tc_th;
		const u8 *table;
		u32 size;
	} tables[] = {
		{ 0x00, v4l2_jpeg_ref_table_luma_dc_ht, V4L2_JPEG_REF_HT_DC_LEN },
		{ 0x10, v4l2_jpeg_ref_table_luma_ac_ht, V4L2_JPEG_REF_HT_AC_LEN },
		{ 0x01, v4l2_jpeg_ref_table_chroma_dc_ht, V4L2_JPEG_REF_HT_DC_LEN },
		{ 0x11, v4l2_jpeg_ref_table_chroma_ac_ht, V4L2_JPEG_REF_HT_AC_LEN },
	};
	u8 seg[2 + 4 + 2 * V4L2_JPEG_REF_HT_DC_LEN + 2 * V4L2_JPEG_REF_HT_AC_LEN];
	unsigned int i;
	u32 n = 2;

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		seg[n++] = tables[i].tc_th;
		memcpy(&seg[n], tables[i].table, tables[i].size);
		n += tables[i].size;
	}
	put_unaligned_be16(n, seg);

	return apple_jpeg_window_add(jbuf, len, 0xc4, seg, n);
}

/*
 * The header window as macOS's CMPhoto fills it for a slice of a split
 * decode: SOI, then only the stream's DQT, SOF0, DHT, DRI and SOS segments,
 * front-padded with 0xff fill bytes to a multiple of 8 bytes; the codec then
 * reads the entropy-coded data from the end of SOS. Using it for a whole
 * image, and the inserted Annex K tables, are inferred: not verified.
 */
static int apple_jpeg_build_window(struct apple_jpeg_src_buf *jbuf,
				   const u8 *va, size_t ecs, bool need_dht)
{
	u32 pos = 2, len = 2, pad;
	int ret;

	/* SOI */
	jbuf->hdr[8] = 0xff;
	jbuf->hdr[9] = 0xd8;

	while (pos < ecs) {
		u8 marker;
		u32 seg_len;

		if (va[pos] != 0xff) {
			pos++;
			continue;
		}
		while (pos < ecs && va[pos] == 0xff)
			pos++;
		if (pos >= ecs)
			break;
		marker = va[pos++];
		/* markers without a segment */
		if (marker == 0x01 || (marker >= 0xd0 && marker <= 0xd9))
			continue;
		if (pos + 2 > ecs)
			return -EINVAL;
		seg_len = get_unaligned_be16(&va[pos]);
		if (seg_len < 2 || pos + seg_len > ecs)
			return -EINVAL;

		switch (marker) {
		case 0xda:
			if (need_dht) {
				ret = apple_jpeg_window_add_dht(jbuf, &len);
				if (ret)
					return ret;
			}
			fallthrough;
		case 0xc0:
		case 0xc4:
		case 0xdb:
		case 0xdd:
			ret = apple_jpeg_window_add(jbuf, &len, marker, &va[pos],
						    seg_len);
			if (ret)
				return ret;
			break;
		}
		pos += seg_len;
	}

	pad = -len & 7;
	memmove(&jbuf->hdr[pad], &jbuf->hdr[8], len);
	memset(jbuf->hdr, 0xff, pad);
	jbuf->hdr_len = pad + len;
	jbuf->data_offset = ecs;

	return 0;
}

static int apple_jpeg_parse(struct apple_jpeg_ctx *ctx, struct vb2_buffer *vb)
{
	struct apple_jpeg_src_buf *jbuf = to_src_buf(to_vb2_v4l2_buffer(vb));
	size_t size = vb2_get_plane_payload(vb, 0);
	struct device *dev = ctx->jpeg->dev;
	struct v4l2_jpeg_header hdr = {};
	enum apple_jpeg_subsampling ss;
	u8 *va = vb2_plane_vaddr(vb, 0);
	int ret;

	if (!va)
		return -EINVAL;

	ret = v4l2_jpeg_parse_header(va, size, &hdr);
	if (ret < 0) {
		dev_dbg(dev, "cannot parse the JPEG header: %d\n", ret);
		return ret;
	}

	/* the codec is a baseline decoder */
	if (!hdr.sof.start || hdr.sof.start < va + 2 ||
	    hdr.sof.start[-1] != 0xc0 || hdr.frame.precision != 8) {
		dev_dbg(dev, "not a baseline JPEG\n");
		return -EINVAL;
	}
	if (hdr.frame.num_components == 3 &&
	    hdr.app14_tf == V4L2_JPEG_APP14_TF_CMYK_RGB) {
		dev_dbg(dev, "RGB JPEG not supported\n");
		return -EINVAL;
	}

	switch (hdr.frame.subsampling) {
	case V4L2_JPEG_CHROMA_SUBSAMPLING_444:
		ss = APPLE_JPEG_SS_444;
		break;
	case V4L2_JPEG_CHROMA_SUBSAMPLING_422:
		ss = APPLE_JPEG_SS_422;
		break;
	case V4L2_JPEG_CHROMA_SUBSAMPLING_420:
		ss = APPLE_JPEG_SS_420;
		break;
	case V4L2_JPEG_CHROMA_SUBSAMPLING_411:
		ss = APPLE_JPEG_SS_411;
		break;
	case V4L2_JPEG_CHROMA_SUBSAMPLING_GRAY:
		ss = APPLE_JPEG_SS_400;
		break;
	default:
		dev_dbg(dev, "subsampling %d not supported\n",
			hdr.frame.subsampling);
		return -EINVAL;
	}
	if ((hdr.frame.num_components != 3 && ss != APPLE_JPEG_SS_400) ||
	    (hdr.frame.num_components != 1 && ss == APPLE_JPEG_SS_400))
		return -EINVAL;

	if (hdr.frame.width > APPLE_JPEG_MAX_DIM ||
	    hdr.frame.height > APPLE_JPEG_MAX_DIM ||
	    (hdr.frame.width < apple_jpeg_min_size[ss].w &&
	     hdr.frame.height < apple_jpeg_min_size[ss].h)) {
		dev_dbg(dev, "size %ux%u not supported\n", hdr.frame.width,
			hdr.frame.height);
		return -EINVAL;
	}

	jbuf->subsampling = ss;
	jbuf->width = hdr.frame.width;
	jbuf->height = hdr.frame.height;
	jbuf->data_offset = 0;
	jbuf->hdr_len = 0;

	/*
	 * CMPhoto's plain decode leaves the window empty, which has the codec
	 * parse the markers from the stream.
	 */
	if (header_window || !hdr.num_dht) {
		ret = apple_jpeg_build_window(jbuf, va, hdr.ecs_offset,
					      !hdr.num_dht);
		if (ret) {
			dev_dbg(dev, "cannot build the header window: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static int apple_jpeg_job_ready(void *priv)
{
	struct apple_jpeg_ctx *ctx = priv;

	return !ctx->source_change;
}

/* return the job's buffers and finish it */
static void apple_jpeg_job_done(struct apple_jpeg_ctx *ctx,
				enum vb2_buffer_state state)
{
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	struct apple_jpeg_dev *jpeg = ctx->jpeg;
	struct vb2_v4l2_buffer *src, *dst;
	unsigned long flags;

	spin_lock_irqsave(&jpeg->hw_lock, flags);
	src = v4l2_m2m_src_buf_remove(m2m_ctx);
	dst = v4l2_m2m_dst_buf_remove(m2m_ctx);
	if (dst) {
		vb2_set_plane_payload(&dst->vb2_buf, 0,
				      state == VB2_BUF_STATE_DONE ?
				      ctx->cap_fmt.plane_fmt[0].sizeimage : 0);
		if (src && v4l2_m2m_is_last_draining_src_buf(m2m_ctx, src)) {
			dst->flags |= V4L2_BUF_FLAG_LAST;
			v4l2_m2m_mark_stopped(m2m_ctx);
			apple_jpeg_notify_eos(ctx);
		}
		v4l2_m2m_buf_done(dst, state);
	}
	if (src)
		v4l2_m2m_buf_done(src, state);
	spin_unlock_irqrestore(&jpeg->hw_lock, flags);

	v4l2_m2m_job_finish(jpeg->m2m_dev, m2m_ctx);
}

static void apple_jpeg_device_run(void *priv)
{
	struct apple_jpeg_ctx *ctx = priv;
	struct apple_jpeg_dev *jpeg = ctx->jpeg;
	const struct v4l2_pix_format_mplane *cap = &ctx->cap_fmt;
	struct vb2_v4l2_buffer *src, *dst;
	struct apple_jpeg_src_buf *jbuf;
	struct apple_jpeg_job job = {};
	unsigned long flags;
	int ret;

	src = v4l2_m2m_next_src_buf(ctx->fh.m2m_ctx);
	dst = v4l2_m2m_next_dst_buf(ctx->fh.m2m_ctx);
	if (!src || !dst) {
		v4l2_m2m_job_finish(jpeg->m2m_dev, ctx->fh.m2m_ctx);
		return;
	}
	jbuf = to_src_buf(src);

	if (!jbuf->error && apple_jpeg_source_change(ctx, jbuf)) {
		v4l2_m2m_job_finish(jpeg->m2m_dev, ctx->fh.m2m_ctx);
		return;
	}

	src->sequence = ctx->out_seq++;
	dst->sequence = ctx->cap_seq++;
	v4l2_m2m_buf_copy_metadata(src, dst);

	if (jbuf->error)
		goto err;

	if (vb2_plane_size(&dst->vb2_buf, 0) < cap->plane_fmt[0].sizeimage) {
		dev_dbg(jpeg->dev, "capture buffer too small\n");
		goto err;
	}

	job.subsampling = jbuf->subsampling;
	job.width = jbuf->width;
	job.height = jbuf->height;
	job.fmt = ctx->cap_jfmt;
	job.scale = 1;
	job.src = vb2_dma_contig_plane_dma_addr(&src->vb2_buf, 0);
	job.src_size = vb2_plane_size(&src->vb2_buf, 0);
	job.data_offset = jbuf->data_offset;
	job.hdr = jbuf->hdr;
	job.hdr_len = jbuf->hdr_len;
	/* CMPhoto: the entropy-coded bytes to the end of the buffer */
	if (jbuf->hdr_len)
		job.slice_bytes = job.src_size - jbuf->data_offset;
	job.dst = vb2_dma_contig_plane_dma_addr(&dst->vb2_buf, 0);
	job.dst_size = vb2_plane_size(&dst->vb2_buf, 0);
	job.stride = cap->plane_fmt[0].bytesperline;
	job.plane1_offset = job.stride * cap->height;

	ret = pm_runtime_resume_and_get(jpeg->dev);
	if (ret) {
		dev_err(jpeg->dev, "failed to power up: %d\n", ret);
		goto err;
	}

	spin_lock_irqsave(&jpeg->hw_lock, flags);
	jpeg->curr = ctx;
	spin_unlock_irqrestore(&jpeg->hw_lock, flags);

	/* before GO: a fast interrupt must not leave this deadline to the next job */
	mod_delayed_work(system_wq, &jpeg->timeout_work,
			 msecs_to_jiffies(APPLE_JPEG_TIMEOUT_MS));

	ret = apple_jpeg_hw_decode(jpeg, &job);
	if (ret) {
		spin_lock_irqsave(&jpeg->hw_lock, flags);
		ctx = jpeg->curr;
		jpeg->curr = NULL;
		spin_unlock_irqrestore(&jpeg->hw_lock, flags);
		/* the timeout took the job */
		if (!ctx)
			return;
		cancel_delayed_work(&jpeg->timeout_work);
		dev_dbg(jpeg->dev, "cannot set the decode up: %d\n", ret);
		apple_jpeg_hw_reset(jpeg);
		pm_runtime_put_autosuspend(jpeg->dev);
		goto err;
	}
	return;

err:
	apple_jpeg_job_done(ctx, VB2_BUF_STATE_ERROR);
}

irqreturn_t apple_jpeg_irq_thread(int irq, void *data)
{
	struct apple_jpeg_dev *jpeg = data;
	struct apple_jpeg_status st;
	struct apple_jpeg_ctx *ctx;
	unsigned long flags;
	bool failed;

	/* never touch the codec powered down */
	if (pm_runtime_get_if_active(jpeg->dev) <= 0)
		return IRQ_NONE;

	apple_jpeg_hw_irq(jpeg, &st);

	spin_lock_irqsave(&jpeg->hw_lock, flags);
	ctx = jpeg->curr;
	jpeg->curr = NULL;
	spin_unlock_irqrestore(&jpeg->hw_lock, flags);

	if (!ctx) {
		dev_warn_ratelimited(jpeg->dev,
				     "unexpected interrupt: status %#x\n",
				     st.status);
		pm_runtime_put_autosuspend(jpeg->dev);
		return IRQ_HANDLED;
	}
	cancel_delayed_work(&jpeg->timeout_work);

	failed = apple_jpeg_hw_failed(jpeg, &st);
	if (!failed && !(st.status & JPEG_IRQ_DONE))
		dev_warn_ratelimited(jpeg->dev,
				     "interrupt without the done bit: status %#x\n",
				     st.status);
	dev_dbg(jpeg->dev, "status %#x, %u cycles\n", st.status, st.cycles);

	/* finishDecode_gated resets the codec after every job */
	apple_jpeg_hw_reset(jpeg);
	pm_runtime_put_autosuspend(jpeg->dev);
	pm_runtime_put_autosuspend(jpeg->dev);

	apple_jpeg_job_done(ctx, failed ? VB2_BUF_STATE_ERROR :
				     VB2_BUF_STATE_DONE);

	return IRQ_HANDLED;
}

void apple_jpeg_timeout_work(struct work_struct *work)
{
	struct apple_jpeg_dev *jpeg =
		container_of(to_delayed_work(work), struct apple_jpeg_dev,
			     timeout_work);
	struct apple_jpeg_ctx *ctx;
	unsigned long flags;

	spin_lock_irqsave(&jpeg->hw_lock, flags);
	ctx = jpeg->curr;
	jpeg->curr = NULL;
	spin_unlock_irqrestore(&jpeg->hw_lock, flags);

	if (!ctx)
		return;

	dev_err(jpeg->dev, "decode timed out\n");
	/* never touch the codec powered down */
	if (pm_runtime_get_if_active(jpeg->dev) > 0) {
		apple_jpeg_hw_dump(jpeg);
		apple_jpeg_hw_reset(jpeg);
		pm_runtime_put_autosuspend(jpeg->dev);
	}
	pm_runtime_put_autosuspend(jpeg->dev);
	apple_jpeg_job_done(ctx, VB2_BUF_STATE_ERROR);
}

static int apple_jpeg_queue_setup(struct vb2_queue *q, unsigned int *nbuffers,
				  unsigned int *nplanes, unsigned int sizes[],
				  struct device *alloc_devs[])
{
	struct apple_jpeg_ctx *ctx = vb2_get_drv_priv(q);
	const struct v4l2_pix_format_mplane *pix;
	u32 size;

	pix = V4L2_TYPE_IS_OUTPUT(q->type) ? &ctx->out_fmt : &ctx->cap_fmt;
	size = pix->plane_fmt[0].sizeimage;

	if (*nplanes)
		return *nplanes != 1 || sizes[0] < size ? -EINVAL : 0;

	*nplanes = 1;
	sizes[0] = size;

	if (V4L2_TYPE_IS_OUTPUT(q->type))
		ctx->need_initial_source_change = true;

	return 0;
}

static int apple_jpeg_buf_out_validate(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);

	vbuf->field = V4L2_FIELD_NONE;
	return 0;
}

static int apple_jpeg_buf_prepare(struct vb2_buffer *vb)
{
	struct apple_jpeg_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);

	vbuf->field = V4L2_FIELD_NONE;

	if (V4L2_TYPE_IS_OUTPUT(vb->vb2_queue->type))
		return vb2_get_plane_payload(vb, 0) ? 0 : -EINVAL;

	if (!ctx->source_change &&
	    vb2_plane_size(vb, 0) < ctx->cap_fmt.plane_fmt[0].sizeimage)
		return -EINVAL;
	vb2_set_plane_payload(vb, 0, 0);

	return 0;
}

static void apple_jpeg_buf_queue(struct vb2_buffer *vb)
{
	struct apple_jpeg_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	struct apple_jpeg_src_buf *jbuf;

	if (V4L2_TYPE_IS_CAPTURE(vb->vb2_queue->type)) {
		if (vb2_is_streaming(vb->vb2_queue) &&
		    v4l2_m2m_dst_buf_is_last(m2m_ctx)) {
			vbuf->field = V4L2_FIELD_NONE;
			vbuf->sequence = ctx->cap_seq++;
			v4l2_m2m_last_buffer_done(m2m_ctx, vbuf);
			apple_jpeg_notify_eos(ctx);
			return;
		}
		v4l2_m2m_buf_queue(m2m_ctx, vbuf);
		return;
	}

	jbuf = to_src_buf(vbuf);
	jbuf->error = apple_jpeg_parse(ctx, vb) < 0;
	if (jbuf->error) {
		/* without a capture queue no job would ever return it */
		if (!vb2_is_streaming(v4l2_m2m_get_dst_vq(m2m_ctx))) {
			v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_ERROR);
			return;
		}
	} else if (!v4l2_m2m_num_src_bufs_ready(m2m_ctx)) {
		apple_jpeg_source_change(ctx, jbuf);
	}

	v4l2_m2m_buf_queue(m2m_ctx, vbuf);
}

static int apple_jpeg_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct apple_jpeg_ctx *ctx = vb2_get_drv_priv(q);

	v4l2_m2m_update_start_streaming_state(ctx->fh.m2m_ctx, q);

	if (V4L2_TYPE_IS_CAPTURE(q->type)) {
		ctx->source_change = false;
		ctx->need_initial_source_change = false;
		ctx->cap_seq = 0;
	} else {
		ctx->out_seq = 0;
	}

	return 0;
}

static void apple_jpeg_stop_streaming(struct vb2_queue *q)
{
	struct apple_jpeg_ctx *ctx = vb2_get_drv_priv(q);
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

	/* a STOP sent before the source change still drains */
	if (V4L2_TYPE_IS_CAPTURE(q->type) && ctx->source_change &&
	    m2m_ctx->last_src_buf)
		m2m_ctx->is_draining = true;

	if (V4L2_TYPE_IS_OUTPUT(q->type) && v4l2_m2m_has_stopped(m2m_ctx))
		apple_jpeg_notify_eos(ctx);
}

static const struct vb2_ops apple_jpeg_qops = {
	.queue_setup = apple_jpeg_queue_setup,
	.buf_out_validate = apple_jpeg_buf_out_validate,
	.buf_prepare = apple_jpeg_buf_prepare,
	.buf_queue = apple_jpeg_buf_queue,
	.start_streaming = apple_jpeg_start_streaming,
	.stop_streaming = apple_jpeg_stop_streaming,
};

static int apple_jpeg_queue_init(void *priv, struct vb2_queue *src_vq,
				 struct vb2_queue *dst_vq)
{
	struct apple_jpeg_ctx *ctx = priv;
	int ret;

	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	src_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	src_vq->drv_priv = ctx;
	src_vq->buf_struct_size = sizeof(struct apple_jpeg_src_buf);
	src_vq->ops = &apple_jpeg_qops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	src_vq->lock = &ctx->jpeg->lock;
	src_vq->dev = ctx->jpeg->dev;

	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	dst_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	dst_vq->drv_priv = ctx;
	dst_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	dst_vq->ops = &apple_jpeg_qops;
	dst_vq->mem_ops = &vb2_dma_contig_memops;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	dst_vq->lock = &ctx->jpeg->lock;
	dst_vq->dev = ctx->jpeg->dev;

	return vb2_queue_init(dst_vq);
}

static int apple_jpeg_querycap(struct file *file, void *priv,
			       struct v4l2_capability *cap)
{
	strscpy(cap->driver, APPLE_JPEG_NAME, sizeof(cap->driver));
	strscpy(cap->card, "Apple JPEG decoder", sizeof(cap->card));
	return 0;
}

static int apple_jpeg_enum_fmt_vid_cap(struct file *file, void *priv,
				       struct v4l2_fmtdesc *f)
{
	if (f->index >= ARRAY_SIZE(apple_jpeg_formats))
		return -EINVAL;

	f->pixelformat = apple_jpeg_formats[f->index].fourcc;
	return 0;
}

static int apple_jpeg_enum_fmt_vid_out(struct file *file, void *priv,
				       struct v4l2_fmtdesc *f)
{
	if (f->index)
		return -EINVAL;

	f->pixelformat = V4L2_PIX_FMT_JPEG;
	f->flags = V4L2_FMT_FLAG_DYN_RESOLUTION;
	return 0;
}

static int apple_jpeg_enum_framesizes(struct file *file, void *priv,
				      struct v4l2_frmsizeenum *fsize)
{
	if (fsize->index)
		return -EINVAL;
	if (fsize->pixel_format != V4L2_PIX_FMT_JPEG &&
	    !apple_jpeg_find_fmt(fsize->pixel_format))
		return -EINVAL;

	fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	fsize->stepwise.min_width = APPLE_JPEG_MIN_DIM;
	fsize->stepwise.max_width = APPLE_JPEG_MAX_DIM;
	fsize->stepwise.step_width = 1;
	fsize->stepwise.min_height = APPLE_JPEG_MIN_DIM;
	fsize->stepwise.max_height = APPLE_JPEG_MAX_DIM;
	fsize->stepwise.step_height = 1;

	return 0;
}

static int apple_jpeg_g_fmt_vid_cap(struct file *file, void *priv,
				    struct v4l2_format *f)
{
	f->fmt.pix_mp = file_to_ctx(file)->cap_fmt;
	return 0;
}

static int apple_jpeg_g_fmt_vid_out(struct file *file, void *priv,
				    struct v4l2_format *f)
{
	f->fmt.pix_mp = file_to_ctx(file)->out_fmt;
	return 0;
}

static const struct apple_jpeg_fmt *
apple_jpeg_try_cap(struct v4l2_pix_format_mplane *pix)
{
	const struct apple_jpeg_fmt *fmt = apple_jpeg_find_fmt(pix->pixelformat);

	if (!fmt)
		fmt = &apple_jpeg_formats[0];
	apple_jpeg_clamp_size(pix);
	apple_jpeg_fill_cap(pix, fmt);

	return fmt;
}

static int apple_jpeg_try_fmt_vid_cap(struct file *file, void *priv,
				      struct v4l2_format *f)
{
	apple_jpeg_try_cap(&f->fmt.pix_mp);
	return 0;
}

static int apple_jpeg_try_fmt_vid_out(struct file *file, void *priv,
				      struct v4l2_format *f)
{
	apple_jpeg_clamp_size(&f->fmt.pix_mp);
	apple_jpeg_fill_out(&f->fmt.pix_mp);
	return 0;
}

static int apple_jpeg_s_fmt_vid_cap(struct file *file, void *priv,
				    struct v4l2_format *f)
{
	struct apple_jpeg_ctx *ctx = file_to_ctx(file);
	struct vb2_queue *vq = v4l2_m2m_get_vq(ctx->fh.m2m_ctx, f->type);

	if (vb2_is_busy(vq))
		return -EBUSY;

	ctx->cap_jfmt = apple_jpeg_try_cap(&f->fmt.pix_mp);
	ctx->cap_fmt = f->fmt.pix_mp;

	return 0;
}

static int apple_jpeg_s_fmt_vid_out(struct file *file, void *priv,
				    struct v4l2_format *f)
{
	struct apple_jpeg_ctx *ctx = file_to_ctx(file);
	struct vb2_queue *vq = v4l2_m2m_get_vq(ctx->fh.m2m_ctx, f->type);

	if (vb2_is_busy(vq))
		return -EBUSY;

	apple_jpeg_try_fmt_vid_out(file, priv, f);
	ctx->out_fmt = f->fmt.pix_mp;

	/* the capture queue follows, as for any stateful decoder */
	vq = v4l2_m2m_get_dst_vq(ctx->fh.m2m_ctx);
	if (!vb2_is_busy(vq)) {
		ctx->cap_fmt.width = ctx->out_fmt.width;
		ctx->cap_fmt.height = ctx->out_fmt.height;
		apple_jpeg_fill_cap(&ctx->cap_fmt, ctx->cap_jfmt);
	}

	return 0;
}

static int apple_jpeg_g_selection(struct file *file, void *priv,
				  struct v4l2_selection *s)
{
	struct apple_jpeg_ctx *ctx = file_to_ctx(file);

	if (s->type != V4L2_BUF_TYPE_VIDEO_CAPTURE &&
	    s->type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)
		return -EINVAL;

	switch (s->target) {
	case V4L2_SEL_TGT_COMPOSE:
	case V4L2_SEL_TGT_COMPOSE_DEFAULT:
	case V4L2_SEL_TGT_COMPOSE_BOUNDS:
	case V4L2_SEL_TGT_COMPOSE_PADDED:
		s->r.left = 0;
		s->r.top = 0;
		s->r.width = ctx->cap_fmt.width;
		s->r.height = ctx->cap_fmt.height;
		return 0;
	default:
		return -EINVAL;
	}
}

static int apple_jpeg_subscribe_event(struct v4l2_fh *fh,
				      const struct v4l2_event_subscription *sub)
{
	switch (sub->type) {
	case V4L2_EVENT_EOS:
		return v4l2_event_subscribe(fh, sub, 0, NULL);
	case V4L2_EVENT_SOURCE_CHANGE:
		return v4l2_src_change_event_subscribe(fh, sub);
	default:
		return -EINVAL;
	}
}

static int apple_jpeg_decoder_cmd(struct file *file, void *priv,
				  struct v4l2_decoder_cmd *cmd)
{
	struct apple_jpeg_ctx *ctx = file_to_ctx(file);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	unsigned long flags;
	int ret;

	ret = v4l2_m2m_ioctl_try_decoder_cmd(file, priv, cmd);
	if (ret < 0)
		return ret;

	if (!vb2_is_streaming(v4l2_m2m_get_src_vq(m2m_ctx)))
		return 0;

	spin_lock_irqsave(&ctx->jpeg->hw_lock, flags);
	ret = v4l2_m2m_ioctl_decoder_cmd(file, priv, cmd);
	spin_unlock_irqrestore(&ctx->jpeg->hw_lock, flags);
	if (ret < 0)
		return ret;

	if (cmd->cmd == V4L2_DEC_CMD_STOP && v4l2_m2m_has_stopped(m2m_ctx))
		apple_jpeg_notify_eos(ctx);
	if (cmd->cmd == V4L2_DEC_CMD_START && v4l2_m2m_has_stopped(m2m_ctx))
		vb2_clear_last_buffer_dequeued(&m2m_ctx->cap_q_ctx.q);

	return 0;
}

static const struct v4l2_ioctl_ops apple_jpeg_ioctl_ops = {
	.vidioc_querycap = apple_jpeg_querycap,

	.vidioc_enum_fmt_vid_cap = apple_jpeg_enum_fmt_vid_cap,
	.vidioc_enum_fmt_vid_out = apple_jpeg_enum_fmt_vid_out,
	.vidioc_enum_framesizes = apple_jpeg_enum_framesizes,
	.vidioc_g_fmt_vid_cap_mplane = apple_jpeg_g_fmt_vid_cap,
	.vidioc_g_fmt_vid_out_mplane = apple_jpeg_g_fmt_vid_out,
	.vidioc_try_fmt_vid_cap_mplane = apple_jpeg_try_fmt_vid_cap,
	.vidioc_try_fmt_vid_out_mplane = apple_jpeg_try_fmt_vid_out,
	.vidioc_s_fmt_vid_cap_mplane = apple_jpeg_s_fmt_vid_cap,
	.vidioc_s_fmt_vid_out_mplane = apple_jpeg_s_fmt_vid_out,
	.vidioc_g_selection = apple_jpeg_g_selection,

	.vidioc_subscribe_event = apple_jpeg_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,

	.vidioc_try_decoder_cmd = v4l2_m2m_ioctl_try_decoder_cmd,
	.vidioc_decoder_cmd = apple_jpeg_decoder_cmd,

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

static int apple_jpeg_open(struct file *file)
{
	struct apple_jpeg_dev *jpeg = video_drvdata(file);
	struct apple_jpeg_ctx *ctx;
	int ret;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	ctx->jpeg = jpeg;
	ctx->out_fmt.width = APPLE_JPEG_DEF_WIDTH;
	ctx->out_fmt.height = APPLE_JPEG_DEF_HEIGHT;
	apple_jpeg_fill_out(&ctx->out_fmt);
	ctx->cap_fmt.width = APPLE_JPEG_DEF_WIDTH;
	ctx->cap_fmt.height = APPLE_JPEG_DEF_HEIGHT;
	ctx->cap_jfmt = &apple_jpeg_formats[0];
	apple_jpeg_fill_cap(&ctx->cap_fmt, ctx->cap_jfmt);

	if (mutex_lock_interruptible(&jpeg->lock)) {
		kfree(ctx);
		return -ERESTARTSYS;
	}

	v4l2_fh_init(&ctx->fh, video_devdata(file));
	ctx->fh.m2m_ctx = v4l2_m2m_ctx_init(jpeg->m2m_dev, ctx,
					    apple_jpeg_queue_init);
	if (IS_ERR(ctx->fh.m2m_ctx)) {
		ret = PTR_ERR(ctx->fh.m2m_ctx);
		v4l2_fh_exit(&ctx->fh);
		mutex_unlock(&jpeg->lock);
		kfree(ctx);
		return ret;
	}
	v4l2_fh_add(&ctx->fh, file);
	mutex_unlock(&jpeg->lock);

	return 0;
}

static int apple_jpeg_release(struct file *file)
{
	struct apple_jpeg_dev *jpeg = video_drvdata(file);
	struct apple_jpeg_ctx *ctx = file_to_ctx(file);

	mutex_lock(&jpeg->lock);
	v4l2_m2m_ctx_release(ctx->fh.m2m_ctx);
	v4l2_fh_del(&ctx->fh, file);
	v4l2_fh_exit(&ctx->fh);
	mutex_unlock(&jpeg->lock);
	kfree(ctx);

	return 0;
}

static const struct v4l2_file_operations apple_jpeg_fops = {
	.owner = THIS_MODULE,
	.open = apple_jpeg_open,
	.release = apple_jpeg_release,
	.poll = v4l2_m2m_fop_poll,
	.unlocked_ioctl = video_ioctl2,
	.mmap = v4l2_m2m_fop_mmap,
};

static const struct v4l2_m2m_ops apple_jpeg_m2m_ops = {
	.device_run = apple_jpeg_device_run,
	.job_ready = apple_jpeg_job_ready,
};

int apple_jpeg_v4l2_register(struct apple_jpeg_dev *jpeg)
{
	struct video_device *vdev = &jpeg->vdev;
	int ret;

	ret = v4l2_device_register(jpeg->dev, &jpeg->v4l2_dev);
	if (ret)
		return ret;

	jpeg->m2m_dev = v4l2_m2m_init(&apple_jpeg_m2m_ops);
	if (IS_ERR(jpeg->m2m_dev)) {
		ret = PTR_ERR(jpeg->m2m_dev);
		goto err_v4l2;
	}

	strscpy(vdev->name, APPLE_JPEG_NAME "-dec", sizeof(vdev->name));
	vdev->fops = &apple_jpeg_fops;
	vdev->ioctl_ops = &apple_jpeg_ioctl_ops;
	vdev->minor = -1;
	vdev->release = video_device_release_empty;
	vdev->lock = &jpeg->lock;
	vdev->v4l2_dev = &jpeg->v4l2_dev;
	vdev->vfl_dir = VFL_DIR_M2M;
	vdev->device_caps = V4L2_CAP_STREAMING | V4L2_CAP_VIDEO_M2M_MPLANE;
	video_set_drvdata(vdev, jpeg);

	ret = video_register_device(vdev, VFL_TYPE_VIDEO, -1);
	if (ret)
		goto err_m2m;

	dev_info(jpeg->dev, "decoder registered as %s\n",
		 video_device_node_name(vdev));

	return 0;

err_m2m:
	v4l2_m2m_release(jpeg->m2m_dev);
err_v4l2:
	v4l2_device_unregister(&jpeg->v4l2_dev);
	return ret;
}

void apple_jpeg_v4l2_unregister(struct apple_jpeg_dev *jpeg)
{
	video_unregister_device(&jpeg->vdev);
	v4l2_m2m_suspend(jpeg->m2m_dev);
	cancel_delayed_work_sync(&jpeg->timeout_work);
	v4l2_m2m_release(jpeg->m2m_dev);
	v4l2_device_unregister(&jpeg->v4l2_dev);
}
