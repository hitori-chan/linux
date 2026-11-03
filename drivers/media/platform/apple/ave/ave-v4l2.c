// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): the V4L2 memory-to-memory encoder
 *
 * Copyright The Asahi Linux Contributors
 *
 * The firmware runs one session here: one client of a core encodes at a time
 * and each core has its node. The firmware takes the raw frame directly but
 * writes the coded data only to the buffers its Start command listed, so each
 * frame is copied from there to the capture buffer.
 */

#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-vmalloc.h>

#include "ave.h"

#define AVE_MIN_WIDTH		64
#define AVE_MIN_HEIGHT		64
#define AVE_MAX_WIDTH		4096
#define AVE_MAX_HEIGHT		2304
#define AVE_DEF_WIDTH		1280
#define AVE_DEF_HEIGHT		720
#define AVE_DEF_BITRATE		4000000
#define AVE_MAX_BITRATE		240000000
#define AVE_DEF_TPF		((struct v4l2_fract){ 1, 30 })

static inline struct apple_ave_ctx *file_to_ctx(struct file *file)
{
	return container_of(file_to_v4l2_fh(file), struct apple_ave_ctx, fh);
}

static void ave_fill_out(struct v4l2_pix_format_mplane *pix)
{
	u32 min_bpl;

	/* whole macroblocks are coded, the rest cropped by the SPS */
	pix->width = ALIGN(clamp_t(u32, pix->width, AVE_MIN_WIDTH, AVE_MAX_WIDTH), 2);
	pix->height = ALIGN(clamp_t(u32, pix->height, AVE_MIN_HEIGHT, AVE_MAX_HEIGHT), 2);
	pix->pixelformat = V4L2_PIX_FMT_NV12;
	pix->field = V4L2_FIELD_NONE;
	pix->num_planes = 1;
	pix->flags = 0;
	/* AVE_CHM_SetDataInfo_FwBuf asserts a stride of a multiple of 64 */
	min_bpl = ALIGN(pix->width, 64);
	pix->plane_fmt[0].bytesperline = max_t(u32, min_bpl,
					       ALIGN(min_t(u32, pix->plane_fmt[0].bytesperline, SZ_64K),
						     64));
	pix->plane_fmt[0].sizeimage = pix->plane_fmt[0].bytesperline * pix->height * 3 / 2;
	memset(pix->plane_fmt[0].reserved, 0, sizeof(pix->plane_fmt[0].reserved));
	if (pix->colorspace == V4L2_COLORSPACE_DEFAULT)
		pix->colorspace = V4L2_COLORSPACE_REC709;
}

static void ave_fill_cap(struct v4l2_pix_format_mplane *pix,
			 const struct v4l2_pix_format_mplane *out)
{
	u32 size = pix->plane_fmt[0].sizeimage;

	pix->width = out->width;
	pix->height = out->height;
	pix->pixelformat = V4L2_PIX_FMT_H264;
	pix->field = V4L2_FIELD_NONE;
	pix->num_planes = 1;
	pix->flags = 0;
	pix->colorspace = out->colorspace;
	pix->xfer_func = out->xfer_func;
	pix->ycbcr_enc = out->ycbcr_enc;
	pix->quantization = out->quantization;
	pix->plane_fmt[0].bytesperline = 0;
	/* the coded data's buffer, as the firmware's, and the parameter sets */
	pix->plane_fmt[0].sizeimage = max_t(u32, size, ALIGN(max_t(u32, pix->width * pix->height * 2,
								   SZ_1M), SZ_16K));
	memset(pix->plane_fmt[0].reserved, 0, sizeof(pix->plane_fmt[0].reserved));
}

static void ave_job_done(struct apple_ave_ctx *ctx, enum vb2_buffer_state state, size_t bytes,
			 bool keyframe)
{
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	struct apple_ave *ave = ctx->ave;
	struct vb2_v4l2_buffer *src, *dst;
	unsigned long flags;

	spin_lock_irqsave(&ave->hw_lock, flags);
	src = v4l2_m2m_src_buf_remove(m2m_ctx);
	dst = v4l2_m2m_dst_buf_remove(m2m_ctx);
	if (src && dst) {
		dst->vb2_buf.timestamp = src->vb2_buf.timestamp;
		dst->timecode = src->timecode;
		dst->flags &= ~V4L2_BUF_FLAG_TSTAMP_SRC_MASK;
		dst->flags |= src->flags & V4L2_BUF_FLAG_TSTAMP_SRC_MASK;
		src->sequence = ctx->out_seq++;
	}
	if (dst) {
		dst->field = V4L2_FIELD_NONE;
		dst->sequence = ctx->cap_seq++;
		dst->flags &= ~(V4L2_BUF_FLAG_KEYFRAME | V4L2_BUF_FLAG_PFRAME);
		if (state == VB2_BUF_STATE_DONE)
			dst->flags |= keyframe ? V4L2_BUF_FLAG_KEYFRAME : V4L2_BUF_FLAG_PFRAME;
		vb2_set_plane_payload(&dst->vb2_buf, 0, state == VB2_BUF_STATE_DONE ? bytes : 0);
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
	spin_unlock_irqrestore(&ave->hw_lock, flags);

	v4l2_m2m_job_finish(ave->m2m_dev, m2m_ctx);
}

/* A firmware that did not answer is powered off running: the next frame boots it again */
static void ave_work(struct work_struct *work)
{
	struct apple_ave_ctx *ctx = container_of(work, struct apple_ave_ctx, work);
	struct vb2_v4l2_buffer *src, *dst;
	enum vb2_buffer_state state = VB2_BUF_STATE_ERROR;
	size_t bytes = 0;
	bool keyframe = false;
	int ret = 0;

	src = v4l2_m2m_next_src_buf(ctx->fh.m2m_ctx);
	dst = v4l2_m2m_next_dst_buf(ctx->fh.m2m_ctx);

	if (src && dst && !ctx->running)
		ret = ave_h264_start(ctx);
	if (src && dst && !ret) {
		ret = ave_h264_encode(ctx, vb2_dma_contig_plane_dma_addr(&src->vb2_buf, 0),
				      vb2_plane_vaddr(&dst->vb2_buf, 0),
				      vb2_plane_size(&dst->vb2_buf, 0), &bytes, &keyframe);
		if (!ret) {
			state = VB2_BUF_STATE_DONE;
		} else if (ret != -ENOSPC) {
			ave_fw_shutdown(ctx->ave, false);
			ave_h264_free(ctx);
			ctx->running = false;
		}
	}
	ave_job_done(ctx, state, bytes, keyframe);
}

static void ave_device_run(void *priv)
{
	struct apple_ave_ctx *ctx = priv;

	queue_work(ctx->ave->wq, &ctx->work);
}

static int ave_queue_setup(struct vb2_queue *q, unsigned int *nbuffers, unsigned int *nplanes,
			   unsigned int sizes[], struct device *alloc_devs[])
{
	struct apple_ave_ctx *ctx = vb2_get_drv_priv(q);
	const struct v4l2_pix_format_mplane *pix;
	u32 size;

	pix = V4L2_TYPE_IS_OUTPUT(q->type) ? &ctx->out_fmt : &ctx->cap_fmt;
	size = pix->plane_fmt[0].sizeimage;

	if (*nplanes)
		return *nplanes != 1 || sizes[0] < size ? -EINVAL : 0;

	*nplanes = 1;
	sizes[0] = size;
	return 0;
}

static int ave_buf_out_validate(struct vb2_buffer *vb)
{
	to_vb2_v4l2_buffer(vb)->field = V4L2_FIELD_NONE;
	return 0;
}

static int ave_buf_prepare(struct vb2_buffer *vb)
{
	struct apple_ave_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);

	to_vb2_v4l2_buffer(vb)->field = V4L2_FIELD_NONE;

	if (V4L2_TYPE_IS_OUTPUT(vb->vb2_queue->type))
		return vb2_get_plane_payload(vb, 0) <
		       ctx->out_fmt.plane_fmt[0].sizeimage ? -EINVAL : 0;

	if (vb2_plane_size(vb, 0) < ctx->cap_fmt.plane_fmt[0].sizeimage)
		return -EINVAL;
	vb2_set_plane_payload(vb, 0, 0);
	return 0;
}

static void ave_buf_queue(struct vb2_buffer *vb)
{
	struct apple_ave_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
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

	v4l2_m2m_buf_queue(m2m_ctx, vbuf);
}

static void ave_return_bufs(struct vb2_queue *q, enum vb2_buffer_state state)
{
	struct apple_ave_ctx *ctx = vb2_get_drv_priv(q);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	struct vb2_v4l2_buffer *vbuf;

	for (;;) {
		if (V4L2_TYPE_IS_OUTPUT(q->type))
			vbuf = v4l2_m2m_src_buf_remove(m2m_ctx);
		else
			vbuf = v4l2_m2m_dst_buf_remove(m2m_ctx);
		if (!vbuf)
			break;
		v4l2_m2m_buf_done(vbuf, state);
	}
}

static int ave_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct apple_ave_ctx *ctx = vb2_get_drv_priv(q);
	struct apple_ave *ave = ctx->ave;

	if (ave->owner && ave->owner != ctx) {
		ave_return_bufs(q, VB2_BUF_STATE_QUEUED);
		return -EBUSY;
	}
	ave->owner = ctx;

	v4l2_m2m_update_start_streaming_state(ctx->fh.m2m_ctx, q);
	if (V4L2_TYPE_IS_OUTPUT(q->type))
		ctx->out_seq = 0;
	else
		ctx->cap_seq = 0;
	return 0;
}

static void ave_stop_streaming(struct vb2_queue *q)
{
	struct apple_ave_ctx *ctx = vb2_get_drv_priv(q);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	struct apple_ave *ave = ctx->ave;

	ave_return_bufs(q, VB2_BUF_STATE_ERROR);
	v4l2_m2m_update_stop_streaming_state(m2m_ctx, q);

	if (V4L2_TYPE_IS_OUTPUT(q->type) && v4l2_m2m_has_stopped(m2m_ctx)) {
		static const struct v4l2_event ev = {
			.type = V4L2_EVENT_EOS,
		};

		v4l2_event_queue_fh(&ctx->fh, &ev);
	}

	if (ctx->running)
		ave_h264_stop(ctx);
	/* vb2 clears this queue's streaming flag after this returns */
	if (ave->owner == ctx &&
	    !vb2_is_streaming(V4L2_TYPE_IS_OUTPUT(q->type) ? v4l2_m2m_get_dst_vq(m2m_ctx) :
			      v4l2_m2m_get_src_vq(m2m_ctx)))
		ave->owner = NULL;
}

static const struct vb2_ops ave_qops = {
	.queue_setup = ave_queue_setup,
	.buf_out_validate = ave_buf_out_validate,
	.buf_prepare = ave_buf_prepare,
	.buf_queue = ave_buf_queue,
	.start_streaming = ave_start_streaming,
	.stop_streaming = ave_stop_streaming,
};

static int ave_queue_init(void *priv, struct vb2_queue *src_vq, struct vb2_queue *dst_vq)
{
	struct apple_ave_ctx *ctx = priv;
	int ret;

	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	src_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	src_vq->drv_priv = ctx;
	src_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	src_vq->ops = &ave_qops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	src_vq->lock = &ctx->ave->lock;
	src_vq->dev = ctx->ave->dev;

	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	/* only the CPU touches a capture buffer */
	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	dst_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	dst_vq->drv_priv = ctx;
	dst_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	dst_vq->ops = &ave_qops;
	dst_vq->mem_ops = &vb2_vmalloc_memops;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	dst_vq->lock = &ctx->ave->lock;
	dst_vq->dev = ctx->ave->dev;

	return vb2_queue_init(dst_vq);
}

static int ave_querycap(struct file *file, void *priv, struct v4l2_capability *cap)
{
	strscpy(cap->driver, APPLE_AVE_NAME, sizeof(cap->driver));
	strscpy(cap->card, "Apple video encoder", sizeof(cap->card));
	return 0;
}

static int ave_enum_fmt_vid_cap(struct file *file, void *priv, struct v4l2_fmtdesc *f)
{
	if (f->index)
		return -EINVAL;
	f->pixelformat = V4L2_PIX_FMT_H264;
	return 0;
}

static int ave_enum_fmt_vid_out(struct file *file, void *priv, struct v4l2_fmtdesc *f)
{
	if (f->index)
		return -EINVAL;
	f->pixelformat = V4L2_PIX_FMT_NV12;
	return 0;
}

static int ave_enum_framesizes(struct file *file, void *priv, struct v4l2_frmsizeenum *fsize)
{
	if (fsize->index || (fsize->pixel_format != V4L2_PIX_FMT_NV12 &&
			     fsize->pixel_format != V4L2_PIX_FMT_H264))
		return -EINVAL;
	fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	fsize->stepwise.min_width = AVE_MIN_WIDTH;
	fsize->stepwise.max_width = AVE_MAX_WIDTH;
	fsize->stepwise.step_width = 2;
	fsize->stepwise.min_height = AVE_MIN_HEIGHT;
	fsize->stepwise.max_height = AVE_MAX_HEIGHT;
	fsize->stepwise.step_height = 2;
	return 0;
}

static int ave_g_fmt_vid_cap(struct file *file, void *priv, struct v4l2_format *f)
{
	f->fmt.pix_mp = file_to_ctx(file)->cap_fmt;
	return 0;
}

static int ave_g_fmt_vid_out(struct file *file, void *priv, struct v4l2_format *f)
{
	f->fmt.pix_mp = file_to_ctx(file)->out_fmt;
	return 0;
}

static int ave_try_fmt_vid_out(struct file *file, void *priv, struct v4l2_format *f)
{
	ave_fill_out(&f->fmt.pix_mp);
	return 0;
}

static int ave_try_fmt_vid_cap(struct file *file, void *priv, struct v4l2_format *f)
{
	ave_fill_cap(&f->fmt.pix_mp, &file_to_ctx(file)->out_fmt);
	return 0;
}

static int ave_s_fmt_vid_out(struct file *file, void *priv, struct v4l2_format *f)
{
	struct apple_ave_ctx *ctx = file_to_ctx(file);

	if (vb2_is_busy(v4l2_m2m_get_src_vq(ctx->fh.m2m_ctx)))
		return -EBUSY;

	ave_fill_out(&f->fmt.pix_mp);
	ctx->out_fmt = f->fmt.pix_mp;
	ctx->cap_fmt.plane_fmt[0].sizeimage = 0;
	ave_fill_cap(&ctx->cap_fmt, &ctx->out_fmt);
	return 0;
}

static int ave_s_fmt_vid_cap(struct file *file, void *priv, struct v4l2_format *f)
{
	struct apple_ave_ctx *ctx = file_to_ctx(file);

	if (vb2_is_busy(v4l2_m2m_get_dst_vq(ctx->fh.m2m_ctx)))
		return -EBUSY;

	ave_fill_cap(&f->fmt.pix_mp, &ctx->out_fmt);
	ctx->cap_fmt = f->fmt.pix_mp;
	return 0;
}

static int ave_g_parm(struct file *file, void *priv, struct v4l2_streamparm *a)
{
	if (!V4L2_TYPE_IS_OUTPUT(a->type))
		return -EINVAL;
	a->parm.output.capability = V4L2_CAP_TIMEPERFRAME;
	a->parm.output.timeperframe = file_to_ctx(file)->tpf;
	return 0;
}

static int ave_s_parm(struct file *file, void *priv, struct v4l2_streamparm *a)
{
	struct apple_ave_ctx *ctx = file_to_ctx(file);
	struct v4l2_fract *tpf;

	if (!V4L2_TYPE_IS_OUTPUT(a->type))
		return -EINVAL;
	tpf = &a->parm.output.timeperframe;
	a->parm.output.capability = V4L2_CAP_TIMEPERFRAME;
	if (!tpf->numerator || !tpf->denominator)
		*tpf = AVE_DEF_TPF;
	ctx->tpf = *tpf;
	return 0;
}

static int ave_subscribe_event(struct v4l2_fh *fh, const struct v4l2_event_subscription *sub)
{
	if (sub->type == V4L2_EVENT_EOS)
		return v4l2_event_subscribe(fh, sub, 2, NULL);
	return v4l2_ctrl_subscribe_event(fh, sub);
}

static int ave_encoder_cmd(struct file *file, void *priv, struct v4l2_encoder_cmd *cmd)
{
	struct apple_ave_ctx *ctx = file_to_ctx(file);
	struct v4l2_m2m_ctx *m2m_ctx = ctx->fh.m2m_ctx;
	unsigned long flags;
	bool stopped;
	int ret;

	ret = v4l2_m2m_ioctl_try_encoder_cmd(file, priv, cmd);
	if (ret < 0)
		return ret;

	if (!vb2_is_streaming(v4l2_m2m_get_src_vq(m2m_ctx)))
		return 0;

	spin_lock_irqsave(&ctx->ave->hw_lock, flags);
	stopped = v4l2_m2m_has_stopped(m2m_ctx);
	ret = v4l2_m2m_ioctl_encoder_cmd(file, priv, cmd);
	spin_unlock_irqrestore(&ctx->ave->hw_lock, flags);
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

static const struct v4l2_ioctl_ops ave_ioctl_ops = {
	.vidioc_querycap = ave_querycap,

	.vidioc_enum_fmt_vid_cap = ave_enum_fmt_vid_cap,
	.vidioc_enum_fmt_vid_out = ave_enum_fmt_vid_out,
	.vidioc_enum_framesizes = ave_enum_framesizes,
	.vidioc_g_fmt_vid_cap_mplane = ave_g_fmt_vid_cap,
	.vidioc_g_fmt_vid_out_mplane = ave_g_fmt_vid_out,
	.vidioc_try_fmt_vid_cap_mplane = ave_try_fmt_vid_cap,
	.vidioc_try_fmt_vid_out_mplane = ave_try_fmt_vid_out,
	.vidioc_s_fmt_vid_cap_mplane = ave_s_fmt_vid_cap,
	.vidioc_s_fmt_vid_out_mplane = ave_s_fmt_vid_out,
	.vidioc_g_parm = ave_g_parm,
	.vidioc_s_parm = ave_s_parm,

	.vidioc_subscribe_event = ave_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,

	.vidioc_try_encoder_cmd = v4l2_m2m_ioctl_try_encoder_cmd,
	.vidioc_encoder_cmd = ave_encoder_cmd,

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

static int ave_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct apple_ave_ctx *ctx = container_of(ctrl->handler, struct apple_ave_ctx, ctrls);

	switch (ctrl->id) {
	case V4L2_CID_MPEG_VIDEO_BITRATE:
		ctx->bitrate = ctrl->val;
		break;
	case V4L2_CID_MPEG_VIDEO_GOP_SIZE:
		ctx->gop_size = ctrl->val;
		break;
	case V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME:
		WRITE_ONCE(ctx->force_idr, true);
		break;
	}
	return 0;
}

static const struct v4l2_ctrl_ops ave_ctrl_ops = {
	.s_ctrl = ave_s_ctrl,
};

static int ave_init_ctrls(struct apple_ave_ctx *ctx)
{
	struct v4l2_ctrl_handler *h = &ctx->ctrls;
	struct v4l2_ctrl *c;

	v4l2_ctrl_handler_init(h, 6);
	v4l2_ctrl_new_std(h, &ave_ctrl_ops, V4L2_CID_MPEG_VIDEO_BITRATE, 100000, AVE_MAX_BITRATE, 1,
			  AVE_DEF_BITRATE);
	c = v4l2_ctrl_new_std_menu(h, &ave_ctrl_ops, V4L2_CID_MPEG_VIDEO_H264_PROFILE,
				   V4L2_MPEG_VIDEO_H264_PROFILE_HIGH,
				   ~BIT(V4L2_MPEG_VIDEO_H264_PROFILE_HIGH),
				   V4L2_MPEG_VIDEO_H264_PROFILE_HIGH);
	if (c)
		c->flags |= V4L2_CTRL_FLAG_READ_ONLY;
	c = v4l2_ctrl_new_std_menu(h, &ave_ctrl_ops, V4L2_CID_MPEG_VIDEO_HEADER_MODE,
				   V4L2_MPEG_VIDEO_HEADER_MODE_JOINED_WITH_1ST_FRAME, 0,
				   V4L2_MPEG_VIDEO_HEADER_MODE_JOINED_WITH_1ST_FRAME);
	if (c)
		c->flags |= V4L2_CTRL_FLAG_READ_ONLY;
	v4l2_ctrl_new_std(h, &ave_ctrl_ops, V4L2_CID_MPEG_VIDEO_GOP_SIZE, 0, 65535, 1, 0);
	v4l2_ctrl_new_std(h, &ave_ctrl_ops, V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME, 0, 0, 0, 0);
	v4l2_ctrl_new_std(h, &ave_ctrl_ops, V4L2_CID_MIN_BUFFERS_FOR_OUTPUT, 1, 1, 1, 1);
	if (h->error) {
		int ret = h->error;

		v4l2_ctrl_handler_free(h);
		return ret;
	}
	ctx->fh.ctrl_handler = h;
	ctx->bitrate = AVE_DEF_BITRATE;
	return 0;
}

static int ave_open(struct file *file)
{
	struct apple_ave *ave = video_drvdata(file);
	struct apple_ave_ctx *ctx;
	int ret;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	ctx->ave = ave;
	ctx->tpf = AVE_DEF_TPF;
	INIT_WORK(&ctx->work, ave_work);
	ctx->out_fmt.width = AVE_DEF_WIDTH;
	ctx->out_fmt.height = AVE_DEF_HEIGHT;
	ave_fill_out(&ctx->out_fmt);
	ave_fill_cap(&ctx->cap_fmt, &ctx->out_fmt);

	if (mutex_lock_interruptible(&ave->lock)) {
		kfree(ctx);
		return -ERESTARTSYS;
	}

	v4l2_fh_init(&ctx->fh, video_devdata(file));
	ret = ave_init_ctrls(ctx);
	if (ret)
		goto err_fh;
	ctx->fh.m2m_ctx = v4l2_m2m_ctx_init(ave->m2m_dev, ctx, ave_queue_init);
	if (IS_ERR(ctx->fh.m2m_ctx)) {
		ret = PTR_ERR(ctx->fh.m2m_ctx);
		v4l2_ctrl_handler_free(&ctx->ctrls);
		goto err_fh;
	}
	v4l2_fh_add(&ctx->fh, file);
	mutex_unlock(&ave->lock);
	return 0;

err_fh:
	v4l2_fh_exit(&ctx->fh);
	mutex_unlock(&ave->lock);
	kfree(ctx);
	return ret;
}

static int ave_release(struct file *file)
{
	struct apple_ave *ave = video_drvdata(file);
	struct apple_ave_ctx *ctx = file_to_ctx(file);

	mutex_lock(&ave->lock);
	v4l2_m2m_ctx_release(ctx->fh.m2m_ctx);
	v4l2_fh_del(&ctx->fh, file);
	v4l2_fh_exit(&ctx->fh);
	v4l2_ctrl_handler_free(&ctx->ctrls);
	mutex_unlock(&ave->lock);
	kfree(ctx);
	return 0;
}

static const struct v4l2_file_operations ave_fops = {
	.owner = THIS_MODULE,
	.open = ave_open,
	.release = ave_release,
	.poll = v4l2_m2m_fop_poll,
	.unlocked_ioctl = video_ioctl2,
	.mmap = v4l2_m2m_fop_mmap,
};

static const struct v4l2_m2m_ops ave_m2m_ops = {
	.device_run = ave_device_run,
};

int ave_v4l2_register(struct apple_ave *ave)
{
	struct video_device *vdev = &ave->vdev;
	int ret;

	ret = v4l2_device_register(ave->dev, &ave->v4l2_dev);
	if (ret)
		return ret;

	ave->m2m_dev = v4l2_m2m_init(&ave_m2m_ops);
	if (IS_ERR(ave->m2m_dev)) {
		ret = PTR_ERR(ave->m2m_dev);
		goto err_v4l2;
	}

	strscpy(vdev->name, APPLE_AVE_NAME "-enc", sizeof(vdev->name));
	vdev->fops = &ave_fops;
	vdev->ioctl_ops = &ave_ioctl_ops;
	vdev->minor = -1;
	vdev->release = video_device_release_empty;
	vdev->lock = &ave->lock;
	vdev->v4l2_dev = &ave->v4l2_dev;
	vdev->vfl_dir = VFL_DIR_M2M;
	vdev->device_caps = V4L2_CAP_STREAMING | V4L2_CAP_VIDEO_M2M_MPLANE;
	video_set_drvdata(vdev, ave);

	ret = video_register_device(vdev, VFL_TYPE_VIDEO, -1);
	if (ret)
		goto err_m2m;
	dev_info(ave->dev, "%s registered as %s\n", vdev->name, video_device_node_name(vdev));
	return 0;

err_m2m:
	v4l2_m2m_release(ave->m2m_dev);
err_v4l2:
	v4l2_device_unregister(&ave->v4l2_dev);
	return ret;
}

void ave_v4l2_unregister(struct apple_ave *ave)
{
	video_unregister_device(&ave->vdev);
	v4l2_m2m_suspend(ave->m2m_dev);
	flush_workqueue(ave->wq);
	v4l2_m2m_release(ave->m2m_dev);
	v4l2_device_unregister(&ave->v4l2_dev);
}

MODULE_IMPORT_NS("DMA_BUF");
