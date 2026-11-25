// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): H.264 sessions
 *
 * The level, the parameter sets until the firmware's replace them, the
 * buffers' sizes and each frame's slice header from slice_type on, which
 * the firmware completes; Start and Process are in ave-9013.c.
 *
 * macOS's stream alternates frames others refer to, on one core, with frames none
 * does, on the other. Here every frame is a reference, referring to the one
 * before it.
 */

#include <linux/sizes.h>

#include "ave.h"

/* log2_max_frame_num and log2_max_pic_order_cnt_lsb in macOS's parameter sets */
#define AVE_H264_FRAME_NUM_BITS	5
#define AVE_H264_POC_BITS	6

/* the QP the host writes into a slice header; the firmware replaces it */
#define AVE_H264_SLICE_QP	75

static const u8 ave_h264_pps[] = { 0x28, 0xee, 0x3c, 0xb0 };

/* H.264's table A-1, the High profile's rates */
static const struct ave_h264_level {
	u8 idc;
	u32 max_fs, max_mbps, max_dpb_mbs, max_kbps;
} ave_h264_levels[] = {
	{ 30, 1620, 40500, 8100, 12500 },
	{ 31, 3600, 108000, 18000, 17500 },
	{ 32, 5120, 216000, 20480, 25000 },
	{ 40, 8192, 245760, 32768, 25000 },
	{ 41, 8192, 245760, 32768, 62500 },
	{ 42, 8704, 522240, 34816, 62500 },
	{ 50, 22080, 589824, 110400, 168750 },
	{ 51, 36864, 983040, 184320, 300000 },
	{ 52, 36864, 2073600, 184320, 300000 },
};

/* The sequence parameter set macOS writes */
static u8 *ave_h264_sps(struct apple_ave_ctx *ctx, u8 *o)
{
	u8 rbsp[32];
	struct ave_bits w = { rbsp, 0 };
	u32 crop = ctx->height16 - ctx->out_fmt.height;
	u32 crop_r = ctx->mbw * 16 - ctx->out_fmt.width;

	ave_put_bits(&w, 0x27, 8);
	ave_put_bits(&w, 100, 8);	/* High */
	ave_put_bits(&w, 0, 8);
	ave_put_bits(&w, ctx->level, 8);
	ave_put_ue(&w, 0);		/* seq_parameter_set_id */
	ave_put_ue(&w, 1);		/* chroma_format_idc */
	ave_put_ue(&w, 0);		/* bit_depth_luma_minus8 */
	ave_put_ue(&w, 0);		/* bit_depth_chroma_minus8 */
	ave_put_bits(&w, 0, 2);		/* no bypass, no scaling matrix */
	ave_put_ue(&w, AVE_H264_FRAME_NUM_BITS - 4);
	ave_put_ue(&w, 0);		/* pic_order_cnt_type */
	ave_put_ue(&w, AVE_H264_POC_BITS - 4);
	ave_put_ue(&w, ctx->refs);
	ave_put_bits(&w, 0, 1);		/* gaps_in_frame_num_value_allowed_flag */
	ave_put_ue(&w, ctx->mbw - 1);
	ave_put_ue(&w, ctx->mbh - 1);
	ave_put_bits(&w, 3, 2);		/* frame_mbs_only_flag, direct_8x8_inference_flag */
	ave_put_bits(&w, crop || crop_r, 1);
	if (crop || crop_r) {
		ave_put_ue(&w, 0);
		ave_put_ue(&w, crop_r / 2);
		ave_put_ue(&w, 0);
		ave_put_ue(&w, crop / 2);
	}
	ave_put_bits(&w, 0, 1);		/* vui_parameters_present_flag */
	return ave_put_nal(o, &w);
}

/* The level macOS picks: the first that holds the size, the rate and the bitrate */
void ave_h264_layout(struct apple_ave_ctx *ctx)
{
	const struct ave_h264_level *l = NULL;
	static const u8 start[] = { 0, 0, 0, 1 };
	u32 mbs, mbps, i;
	u8 *o = ctx->headers;

	mbs = ctx->mbw * ctx->mbh;
	mbps = mbs * ave_fps(ctx);

	for (i = 0; i < ARRAY_SIZE(ave_h264_levels); i++) {
		l = &ave_h264_levels[i];
		if (mbs <= l->max_fs && mbps <= l->max_mbps &&
		    ctx->bitrate / 1000 <= l->max_kbps)
			break;
	}
	ctx->level = l->idc;
	/* the two-core mode's firmware keeps one */
	ctx->refs = ctx->peer ? 1 : min_t(u32, 10, l->max_dpb_mbs / mbs);

	o = ave_h264_sps(ctx, o);
	memcpy(o, start, sizeof(start));
	o += sizeof(start);
	memcpy(o, ave_h264_pps, sizeof(ave_h264_pps));
	o += sizeof(ave_h264_pps);
	ctx->headers_len = o - ctx->headers;
}

void ave_h264_sizes(struct apple_ave_ctx *ctx, struct ave_sizes *s)
{
	u32 w = ctx->mbw * 16, h = ctx->height16, mbw = ctx->mbw, mbh = ctx->mbh;

	s->lowres_ref = 2 * ((((((mbw + 3) >> 2) * (((h + 0x3f) & ~0xfu) >> 4)) << 8) + 0x1ff) & ~0x1ffu);
	s->colocated = ((8 * w + 0x78) & ~0x7fu) * mbh;
	s->info = max_t(u32, (16 * w + 0xf0) & ~0xffu, SZ_16K);
	s->pixel = max_t(u32, ((w << 6) + 0x3c0) & ~0x3ffu, SZ_16K);
	s->data = max_t(u32, 0x38 * mbw, SZ_16K);
	s->fw = max_t(u32, (((4 * w + 0x3c) & ~0x3fu) + 0x7f) & ~0x7fu, SZ_16K);
	s->entropy = s->pixel * ((mbh + 3) >> 2);
	s->transcoded = 1;
}

/* The slice header from slice_type to the deblocking, without first_mb_in_slice's bit */
void ave_h264_slice_bits(struct apple_ave_ctx *ctx, u8 *bytes, u32 *nbits, bool idr)
{
	struct ave_bits w = { bytes, 0 };
	u32 frame_num = ctx->frame & (BIT(AVE_H264_FRAME_NUM_BITS) - 1);

	ave_put_ue(&w, idr ? 2 : 0);	/* slice_type: I or P */
	ave_put_ue(&w, 0);		/* pic_parameter_set_id */
	ave_put_bits(&w, frame_num, AVE_H264_FRAME_NUM_BITS);
	if (idr)
		ave_put_ue(&w, ctx->idr_id);
	ave_put_bits(&w, ctx->frame & (BIT(AVE_H264_POC_BITS) - 1), AVE_H264_POC_BITS);
	if (idr) {
		ave_put_bits(&w, 0, 2);	/* no_output_of_prior_pics_flag, long_term_reference_flag */
	} else {
		ave_put_bits(&w, 0, 2);	/* num_ref_idx_active_override_flag, no list modification */
		ave_put_bits(&w, 0, 1);	/* adaptive_ref_pic_marking_mode_flag */
		ave_put_ue(&w, 0);	/* cabac_init_idc */
	}
	ave_put_se(&w, AVE_H264_SLICE_QP);
	ave_put_ue(&w, 0);		/* disable_deblocking_filter_idc */
	ave_put_se(&w, 0);
	ave_put_se(&w, 0);
	*nbits = w.n;
}
