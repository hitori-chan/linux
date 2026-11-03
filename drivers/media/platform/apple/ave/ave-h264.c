// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): H.264 sessions
 *
 * The commands are macOS 14.8.3's as sent at 640x360, 1280x720 and 1920x1080:
 * their constant words are in ave-h264-tables.h and only the words that differ
 * between those sessions or from frame to frame are written here. The firmware
 * does the rate control and the entropy coding; the host gives it the parameter
 * sets, each frame's slice header up to the QP, which it replaces, and the
 * buffers.
 *
 * macOS's stream alternates frames others refer to, on one core, with frames none
 * does, on the other. Here one core encodes every frame and each is a reference,
 * referring to the one before it.
 */

#include <linux/math64.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>

#include "ave.h"
#include "ave-h264-tables.h"

/* log2_max_frame_num and log2_max_pic_order_cnt_lsb in macOS's parameter sets */
#define AVE_H264_FRAME_NUM_BITS	5
#define AVE_H264_POC_BITS	6

/* the QP the host writes into a slice header; the firmware replaces it */
#define AVE_H264_SLICE_QP	75

#define AVE_H264_TIMESCALE	14400000
#define AVE_H264_PIPES		4

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
static void ave_h264_layout(struct apple_ave_ctx *ctx)
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
	ctx->sps_len = o - ctx->headers;
	memcpy(o, start, sizeof(start));
	o += sizeof(start);
	memcpy(o, ave_h264_pps, sizeof(ave_h264_pps));
	o += sizeof(ave_h264_pps);
	ctx->headers_len = o - ctx->headers;
}

static void ave_h264_sizes(struct apple_ave_ctx *ctx, struct ave_sizes *s)
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

/* AVE_CHM_MakeFwCmd_Start_AVC (0xfffffe00090d6a88) */
static void ave_h264_fill_start(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b)
{
	u32 crop = ctx->height16 - ctx->out_fmt.height;
	u32 crop_r = ctx->mbw * 16 - ctx->out_fmt.width;

	if (ctx->peer)
		ave_put_words(b, ave_h264_two_start_words, ARRAY_SIZE(ave_h264_two_start_words));
	else
		ave_put_words(b, ave_h264_start_words, ARRAY_SIZE(ave_h264_start_words));
	ave_fill_start_buffers(ctx, ave, b);

	/* 0x20 traced at 640x368, 0x10 from 864x480 up */
	put_unaligned_le32(ctx->mbw * ctx->mbh <= 1200 ? 0x20 : 0x10, b + 0x84);
	ave_put_dva(b, 0x5e0, ctx->transcoded[0]);
	ave_put_dva(b, 0x5e8, ctx->transcoded[1]);
	put_unaligned_le32(ctx->transcoded_size, b + 0x5f0);
	/* set from 2560x1440 up, not at 1080p: level 5 or above */
	put_unaligned_le32(ctx->level >= 50 ? 0x10000 : 0, b + 0x17bb0);

	/* the sequence parameter set, as fields and as its NAL unit with its start code */
	put_unaligned_le32(ctx->level, b + 0x18218);
	put_unaligned_le32(ctx->refs, b + 0x18624);
	put_unaligned_le32(ctx->mbw - 1, b + 0x1862c);
	put_unaligned_le32(ctx->mbh - 1, b + 0x18630);
	put_unaligned_le32(crop || crop_r, b + 0x18688);
	put_unaligned_le32(crop_r / 2, b + 0x18690);
	put_unaligned_le32(crop / 2, b + 0x18698);
	if (ctx->peer) {
		/* the second core's mark; the parameter sets are the host's alone */
		put_unaligned_le32(ave->instance, b + 0x18a58);
		return;
	}
	put_unaligned_le32(8 * ctx->sps_len, b + 0x186a0);
	memcpy(b + 0x186a4, ctx->headers, ctx->sps_len);
}

/* The slice header from slice_type to the deblocking, without first_mb_in_slice's bit */
static void ave_h264_slice_bits(struct apple_ave_ctx *ctx, u8 *bytes, u32 *nbits, bool idr)
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

/* AVE_CHM_MakeFwCmd_Process_AVC (0xfffffe00090d9dbc) with AVE_CHM_SetDataInfo_*'s */
static void ave_h264_fill_process_two(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b,
				      dma_addr_t src)
{
	const struct v4l2_pix_format_mplane *out = &ctx->out_fmt;
	u32 stride = out->plane_fmt[0].bytesperline;

	memset(b, 0, ctx->codec->process_size);
	ave_put_words(b, ave_h264_two_process_words, ARRAY_SIZE(ave_h264_two_process_words));
	ave_cmd_header(ctx, ave, b, AVE_CMD_PROCESS, 0x15, 0, ctx->codec->x28_frame, 0xb540);

	put_unaligned_le32(ctx->bitrate, b + 0xa80);
	put_unaligned_le32(ave_fps(ctx), b + 0xa84);
	put_unaligned_le32(!ctx->total, b + 0x1150);
	ave_put_dva(b, 0x3740, src);
	put_unaligned_le32(stride, b + 0x3748);
	ave_put_dva(b, 0x3750, src + stride * out->height);
	put_unaligned_le32(stride, b + 0x3758);
	put_unaligned_le32(out->width, b + 0x37dc);
	put_unaligned_le32(out->height, b + 0x37e0);
	ave_put_dva(b, 0x3a80, ctx->coded[0]);
	ave_put_dva(b, 0x3a88, ctx->coded_hdr[0]);
	put_unaligned_le32(ctx->coded_size, b + 0x3a90);
	put_unaligned_le32(ctx->total, b + 0x3ac0);
	put_unaligned_le32(mul_u64_u32_div((u64)ctx->total * ctx->tpf.numerator, AVE_H264_TIMESCALE,
					   ctx->tpf.denominator), b + 0x3ad8);
	put_unaligned_le32(ave_fps_double(ctx), b + 0x3ad4);
	put_unaligned_le32(AVE_H264_TIMESCALE, b + 0x3ae0);
}

static void ave_h264_fill_process(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b,
				  dma_addr_t src)
{
	const struct v4l2_pix_format_mplane *out = &ctx->out_fmt;
	u32 stride = out->plane_fmt[0].bytesperline, n = ctx->frame, nbits, i;
	bool idr = !n;
	u32 slot = n % AVE_USED_SLOTS;
	const struct ave_recon *rec = &ctx->recon[slot];
	u8 bits[16];

	if (ctx->peer) {
		ave_h264_fill_process_two(ctx, ave, b, src);
		return;
	}

	memset(b, 0, ctx->codec->process_size);
	ave_put_words(b, ave_h264_process_words, ARRAY_SIZE(ave_h264_process_words));
	ave_cmd_header(ctx, ave, b, AVE_CMD_PROCESS, 0x15, 0, ctx->codec->x28_frame, 0xb540);

	/* the frame's kind: nal_unit_type; nal_ref_idc stays the table's 1 */
	put_unaligned_le32(idr ? 5 : 1, b + 0x50);
	put_unaligned_le32(idr ? 2 : 0, b + 0x58);
	put_unaligned_le32(n & (BIT(AVE_H264_FRAME_NUM_BITS) - 1), b + 0x64);
	put_unaligned_le32(idr ? 0x10000 : 0, b + 0x68);
	put_unaligned_le32(ctx->idr_id, b + 0x6c);
	put_unaligned_le32(n, b + 0x70);
	put_unaligned_le32(idr, b + 0x88);
	put_unaligned_le32(idr ? 0xffffffff : 0, b + 0x8c);
	put_unaligned_le32(!ctx->total, b + 0x1150);

	/* the slice header */
	memset(bits, 0, sizeof(bits));
	ave_h264_slice_bits(ctx, bits, &nbits, idr);
	put_unaligned_le32(nbits, b + 0x66c);
	for (i = 0; i * 8 < nbits; i += 4)
		memcpy(b + 0x670 + i, bits + i, 4);

	/*
	 * The rate. macOS splits it over two cores, reference frames on the
	 * first and non-reference ones on the second; a core given both kinds
	 * never moves its QP from the first frame's, so every frame here is a
	 * reference, each referring to the one before.
	 */
	put_unaligned_le32(ctx->bitrate, b + 0xa80);
	put_unaligned_le32(ave_fps(ctx), b + 0xa84);

	/* the frame it refers to */
	if (!idr) {
		u32 ref_slot = (n - 1) % AVE_USED_SLOTS;
		const struct ave_recon *ref = &ctx->recon[ref_slot];

		ave_put_dva(b, 0x3578, ref->y);
		ave_put_dva(b, 0x3598, ref->a);
		ave_put_dva(b, 0x35b8, ref->c);
		ave_put_dva(b, 0x35d8, ref->b);
		ave_put_dva(b, 0x35f8, ctx->lowres_ref[ref_slot]);
		put_unaligned_le32(n - 1, b + 0x36d8);
	}

	/* the reconstructed frame and the source */
	ave_put_dva(b, 0x3718, rec->y);
	ave_put_dva(b, 0x3720, rec->a);
	ave_put_dva(b, 0x3728, rec->c);
	ave_put_dva(b, 0x3730, rec->b);
	ave_put_dva(b, 0x3738, ctx->colocated[slot]);
	ave_put_dva(b, 0x3740, src);
	put_unaligned_le32(stride, b + 0x3748);
	ave_put_dva(b, 0x3750, src + stride * out->height);
	put_unaligned_le32(stride, b + 0x3758);
	put_unaligned_le32(out->width, b + 0x37dc);
	put_unaligned_le32(out->height, b + 0x37e0);

	ave_put_dva(b, 0x37f8, ctx->neighbor_info[0]);
	ave_put_dva(b, 0x3818, ctx->neighbor_pixel[0]);
	ave_put_dva(b, 0x3838, ctx->neighbor_data[0]);
	ave_put_dva(b, 0x3858, ctx->neighbor_fw[0]);
	for (i = 0; i < AVE_H264_PIPES; i++) {
		ave_put_dva(b, 0x3878 + 0x20 * i, ctx->entropy[0][i]);
		ave_put_dva(b, 0x3880 + 0x20 * i, ctx->entropy[1][i]);
	}

	/* the outputs */
	put_unaligned_le32(0, b + 0x3a7c);
	ave_put_dva(b, 0x3a80, ctx->coded[0]);
	ave_put_dva(b, 0x3a88, ctx->coded_hdr[0]);
	put_unaligned_le32(ctx->coded_size, b + 0x3a90);
	ave_put_dva(b, 0x3a98, ctx->lowres_ref[slot]);
	ave_put_dva(b, 0x3aa0, ctx->lowres_result[slot]);
	put_unaligned_le32(ctx->lowres_result_size, b + 0x3aa8);

	/* the frame's number and time */
	put_unaligned_le32(ctx->total, b + 0x3ac0);
	put_unaligned_le32(idr ? 3 : 1, b + 0x3ac4);
	put_unaligned_le32(mul_u64_u32_div((u64)ctx->total * ctx->tpf.numerator, AVE_H264_TIMESCALE,
					   ctx->tpf.denominator), b + 0x3ad8);
	put_unaligned_le32(ave_fps_double(ctx), b + 0x3ad4);
	put_unaligned_le32(AVE_H264_TIMESCALE, b + 0x3ae0);
	put_unaligned_le32(n, b + 0x3ae8);
}

const struct ave_codec ave_codec_h264 = {
	.id = 0,
	.start_size = 0x18a60,
	.process_size = 0x3e30,
	.x28_session = 0x50,
	.x28_frame = 0x70,
	.pipes = AVE_H264_PIPES,
	.layout = ave_h264_layout,
	.sizes = ave_h264_sizes,
	.fill_start = ave_h264_fill_start,
	.fill_process = ave_h264_fill_process,
};
