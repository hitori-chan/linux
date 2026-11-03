// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): HEVC sessions
 *
 * The commands are macOS 14.8.3's as sent at 640x360, 1280x720 and 1920x1080:
 * their constant words are in ave-hevc-tables.h and only the words that differ
 * between those sessions or from frame to frame are written here. The firmware
 * does the rate control and the entropy coding and writes each frame's slice
 * header itself, to buffers of its own; the host gives it the parameter sets, the
 * frame's reference picture set (the kext's HEVC_RPS, copied to +0x88f4) and the
 * buffers.
 *
 * One core encodes every frame, each referring to the one before it.
 */

#include <linux/math64.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>

#include "ave.h"
#include "ave-hevc-tables.h"

#define AVE_HEVC_TIMESCALE	14400000
#define AVE_HEVC_PIPES		2
#define AVE_HEVC_NAL_IDR_N_LP	20
#define AVE_HEVC_NAL_TRAIL_R	1

/* start code, NAL */
#define AVE_HEVC_VPS_LEN	28
#define AVE_HEVC_VPS_PROFILE	10
#define AVE_HEVC_VPS_COMPAT	11
#define AVE_HEVC_VPS_LEVEL	24
#define AVE_HEVC_VPS_DPB	25

static const u8 ave_hevc_vps[AVE_HEVC_VPS_LEN] = {
	0, 0, 0, 1,
	0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00,
	0xb0, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x1b, 0x02, 0x40,
};

static const u8 ave_hevc_pps[] = { 0, 0, 0, 1, 0x44, 0x01, 0xc0, 0x72, 0xf0, 0x53, 0x24 };

/* HEVC's table A.8, the Main tier's rates; general_level_idc is 30 times the level */
static const struct ave_hevc_level {
	u8 idc;
	u32 max_luma_ps;
	u64 max_luma_sr;
	u32 max_kbps;
} ave_hevc_levels[] = {
	{ 63, 245760, 7372800, 3000 },
	{ 90, 552960, 16588800, 6000 },
	{ 93, 983040, 33177600, 10000 },
	{ 120, 2228224, 66846720, 12000 },
	{ 123, 2228224, 133693440, 20000 },
	{ 150, 8912896, 267386880, 25000 },
	{ 153, 8912896, 534773760, 40000 },
	{ 156, 8912896, 1069547520, 60000 },
	{ 180, 35651584, 1069547520, 60000 },
	{ 183, 35651584, 2139095040, 120000 },
	{ 186, 35651584, 4278190080ULL, 240000 },
};

/* The sequence parameter set macOS writes */
static u8 *ave_hevc_sps(struct apple_ave_ctx *ctx, u8 *o)
{
	u8 rbsp[64];
	struct ave_bits w = { rbsp, 0 };
	u32 w16 = ctx->mbw * 16;
	u32 crop_r = w16 - ctx->out_fmt.width, crop_b = ctx->height16 - ctx->out_fmt.height;
	static const u8 sets[] = { 4, 1, 2, 3 };
	bool main10 = ctx->bit_depth > 8;
	u32 i, k;

	ave_put_bits(&w, 0x4201, 16);
	ave_put_bits(&w, 0, 4);		/* sps_video_parameter_set_id */
	ave_put_bits(&w, 0, 3);		/* sps_max_sub_layers_minus1 */
	ave_put_bits(&w, 1, 1);		/* sps_temporal_id_nesting_flag */
	ave_put_bits(&w, main10 ? 2 : 1, 8);	/* Main 10, Main */
	ave_put_bits(&w, main10 ? 0x20000000 : 0x60000000, 32);
	ave_put_bits(&w, 0xb, 4);	/* progressive, frame only */
	ave_put_bits(&w, 0, 32);
	ave_put_bits(&w, 0, 12);
	ave_put_bits(&w, ctx->level, 8);
	ave_put_ue(&w, 0);		/* sps_seq_parameter_set_id */
	ave_put_ue(&w, 1);		/* chroma_format_idc */
	ave_put_ue(&w, w16);
	ave_put_ue(&w, ctx->height16);
	ave_put_bits(&w, crop_r || crop_b, 1);
	if (crop_r || crop_b) {
		ave_put_ue(&w, 0);
		ave_put_ue(&w, crop_r / 2);
		ave_put_ue(&w, 0);
		ave_put_ue(&w, crop_b / 2);
	}
	ave_put_ue(&w, ctx->bit_depth - 8);	/* bit_depth_luma_minus8 */
	ave_put_ue(&w, ctx->bit_depth - 8);	/* bit_depth_chroma_minus8 */
	ave_put_ue(&w, 7);		/* log2_max_pic_order_cnt_lsb_minus4 */
	ave_put_bits(&w, 0, 1);		/* sps_sub_layer_ordering_info_present_flag */
	ave_put_ue(&w, ctx->refs - 1);
	ave_put_ue(&w, 0);
	ave_put_ue(&w, 0);
	ave_put_ue(&w, 0);		/* log2_min_luma_coding_block_size_minus3 */
	ave_put_ue(&w, 2);		/* log2_diff_max_min_luma_coding_block_size */
	ave_put_ue(&w, 0);		/* log2_min_luma_transform_block_size_minus2 */
	ave_put_ue(&w, 3);		/* log2_diff_max_min_luma_transform_block_size */
	ave_put_ue(&w, 1);		/* max_transform_hierarchy_depth_inter */
	ave_put_ue(&w, 0);		/* max_transform_hierarchy_depth_intra */
	ave_put_bits(&w, 1, 1);		/* scaling_list_enabled_flag */
	ave_put_bits(&w, 0, 1);		/* sps_scaling_list_data_present_flag */
	ave_put_bits(&w, 0, 1);		/* amp_enabled_flag */
	ave_put_bits(&w, 1, 1);		/* sample_adaptive_offset_enabled_flag */
	ave_put_bits(&w, 0, 1);		/* pcm_enabled_flag */
	ave_put_ue(&w, ARRAY_SIZE(sets));
	for (i = 0; i < ARRAY_SIZE(sets); i++) {
		if (i)
			ave_put_bits(&w, 0, 1);	/* inter_ref_pic_set_prediction_flag */
		ave_put_ue(&w, sets[i]);
		ave_put_ue(&w, 0);
		for (k = 0; k < sets[i]; k++) {
			ave_put_ue(&w, 0);
			ave_put_bits(&w, 1, 1);
		}
	}
	ave_put_bits(&w, 0, 1);		/* long_term_ref_pics_present_flag */
	ave_put_bits(&w, 1, 1);		/* sps_temporal_mvp_enabled_flag */
	ave_put_bits(&w, 0, 1);		/* strong_intra_smoothing_enabled_flag */
	ave_put_bits(&w, 0, 1);		/* vui_parameters_present_flag */
	ave_put_bits(&w, 0, 1);		/* sps_extension_present_flag */
	return ave_put_nal(o, &w);
}

/* The level macOS picks: the first that holds the size, the rate and the bitrate */
static void ave_hevc_layout(struct apple_ave_ctx *ctx)
{
	const struct ave_hevc_level *l = NULL;
	u32 luma = ctx->mbw * 16 * ctx->height16, i;
	u64 rate = (u64)luma * ave_fps(ctx);
	u8 *o = ctx->headers;

	for (i = 0; i < ARRAY_SIZE(ave_hevc_levels); i++) {
		l = &ave_hevc_levels[i];
		if (luma <= l->max_luma_ps && rate <= l->max_luma_sr &&
		    ctx->bitrate / 1000 <= l->max_kbps)
			break;
	}
	ctx->level = l->idc;
	/* macOS: 6 up to 1080p, 5 at 4K and 8K */
	ctx->refs = luma > 1920 * 1088 ? 5 : 6;

	memcpy(o, ave_hevc_vps, AVE_HEVC_VPS_LEN);
	if (ctx->bit_depth > 8) {
		o[AVE_HEVC_VPS_PROFILE] = 2;
		o[AVE_HEVC_VPS_COMPAT] = 0x20;
	}
	o[AVE_HEVC_VPS_LEVEL] = ctx->level;
	o[AVE_HEVC_VPS_DPB] = ctx->refs == 5 ? 0x17 : 0x1b;
	o += AVE_HEVC_VPS_LEN;
	o = ave_hevc_sps(ctx, o);
	ctx->sps_len = o - ctx->headers - AVE_HEVC_VPS_LEN;
	memcpy(o, ave_hevc_pps, sizeof(ave_hevc_pps));
	o += sizeof(ave_hevc_pps);
	ctx->headers_len = o - ctx->headers;
}

static void ave_hevc_sizes(struct apple_ave_ctx *ctx, struct ave_sizes *s)
{
	u32 w = ctx->mbw * 16, h = ctx->height16;
	u32 ctbw = (w + 31) >> 5, ctbh = (h + 31) >> 5;

	s->lowres_ref = 2 * (((((((((w + 31) & ~31u) >> 4) + 3) >> 2) *
			       (((h + 63) & ~63u) >> 6)) << 8) + 0x1ff) & ~0x1ffu);
	s->colocated = ((2 * w + 0x3e) & ~0x3fu) * ((ctbh + 1) & ~1u);
	s->info = max_t(u32, 0xc0 * ctbw, SZ_16K);
	s->pixel = max_t(u32, 0x300 * ctbw, SZ_16K);
	s->data = max_t(u32, ((w + 31) >> 3) & ~3u, SZ_16K);
	s->fw = max_t(u32, (((2 * w + 0x3e) & ~0x3fu) + 0x7f) & ~0x7fu, SZ_16K);
	s->entropy = ctbw * ((ctbh + 1) >> 1) * 0x900 * (ctx->bit_depth > 8 ? 2 : 1);
	s->extra = ALIGN(w * h / 32, SZ_16K);
}

/* AVE_CHM_MakeFwCmd_Start_HEVC (0xfffffe00090d7144) */
static void ave_hevc_fill_start(struct apple_ave_ctx *ctx, u8 *b)
{
	u32 w16 = ctx->mbw * 16;
	u32 crop_r = w16 - ctx->out_fmt.width, crop_b = ctx->height16 - ctx->out_fmt.height;

	ave_put_words(b, ave_hevc_start_words, ARRAY_SIZE(ave_hevc_start_words));
	ave_fill_start_buffers(ctx, b);

	ave_put_dva(b, 0x17548, ctx->extra[0]);
	ave_put_dva(b, 0x17550, ctx->extra[1]);
	put_unaligned_le32(crop_b ? 10 : 0, b + 0x17a30);
	put_unaligned_le32(ctx->level, b + 0x1824c);

	/* the parameter sets, as fields and as NAL units with their start codes */
	memcpy(b + 0x2c1d0, ctx->headers, AVE_HEVC_VPS_LEN);
	put_unaligned_le32(ctx->level, b + 0x2c328);
	put_unaligned_le32(w16, b + 0x2c518);
	put_unaligned_le32(ctx->height16, b + 0x2c51c);
	put_unaligned_le32((w16 + 31) >> 5, b + 0x2c520);
	put_unaligned_le32((ctx->height16 + 31) >> 5, b + 0x2c524);
	put_unaligned_le32(crop_r || crop_b, b + 0x2c528);
	put_unaligned_le32(crop_r / 2, b + 0x2c530);
	put_unaligned_le32(crop_b / 2, b + 0x2c538);
	put_unaligned_le32(8 * ctx->sps_len, b + 0x2dfc0);
	memcpy(b + 0x2dfc4, ctx->headers + AVE_HEVC_VPS_LEN, ctx->sps_len);

	/* the table's are Main's; these are Main 10's, the only session traced at 720p */
	if (ctx->bit_depth > 8) {
		u32 depth = ctx->bit_depth, mid = BIT(depth - 1);
		int qp = -6 * (int)(depth - 8);

		put_unaligned_le32(depth, b + 0x17890);
		put_unaligned_le32(mid, b + 0x17a34);
		put_unaligned_le32(mid << 16 | mid, b + 0x17a38);
		put_unaligned_le32(0, b + 0x17a8c);
		put_unaligned_le32(qp, b + 0x181d8);
		put_unaligned_le32(qp, b + 0x181e0);
		put_unaligned_le32(2, b + 0x18218);
		put_unaligned_le32(0x10000, b + 0x1821c);
		put_unaligned_le32(0x1000101, b + 0x18240);
		put_unaligned_le32(2, b + 0x2c2f4);
		put_unaligned_le32(0x10000, b + 0x2c2f8);
		put_unaligned_le32(0x1000000, b + 0x2c31c);
		put_unaligned_le32(depth - 8, b + 0x2c53c);
		put_unaligned_le32(depth - 8, b + 0x2c540);
	}
}

/* AVE_CHM_MakeFwCmd_Process_HEVC (0xfffffe00090da224) */
static void ave_hevc_fill_process(struct apple_ave_ctx *ctx, u8 *b, dma_addr_t src)
{
	const struct v4l2_pix_format_mplane *out = &ctx->out_fmt;
	u32 stride = out->plane_fmt[0].bytesperline, n = ctx->frame, i;
	bool idr = !n, first = !ctx->total;
	u32 slot = n % AVE_USED_SLOTS;
	const struct ave_recon *rec = &ctx->recon[slot];

	memset(b, 0, ctx->codec->process_size);
	ave_put_words(b, ave_hevc_process_words, ARRAY_SIZE(ave_hevc_process_words));
	ave_cmd_header(ctx, b, AVE_CMD_PROCESS, 0x15, 0, ctx->codec->x28_frame, 0xb540);

	put_unaligned_le32(idr ? AVE_HEVC_NAL_IDR_N_LP : AVE_HEVC_NAL_TRAIL_R, b + 0x50);
	put_unaligned_le32(idr ? 2 : 0, b + 0x64);
	put_unaligned_le32(n, b + 0x70);
	put_unaligned_le32(idr ? 0x1010100 : 0x10100, b + 0x164);
	put_unaligned_le32(idr ? 0xffffffff : 0, b + 0x168);
	put_unaligned_le32(0xffffffff, b + 0x16c);
	put_unaligned_le32(first ? 0 : 0x100, b + 0x3b0);
	if (ctx->bit_depth > 8)
		put_unaligned_le32(0x3f, b + 0x3f4);
	for (i = 0; i < AVE_SLICE_HDR_NUM; i++)
		ave_put_dva(b, 0x538 + 8 * i, ctx->slice_hdr.iova + AVE_SLICE_HDR_STRIDE * i);

	put_unaligned_le32(ctx->bitrate, b + 0x5548);
	put_unaligned_le32(ave_fps(ctx), b + 0x554c);
	put_unaligned_le32(first, b + 0x5c18);
	put_unaligned_le32(ctx->level >= 120, b + 0x5c1c);
	put_unaligned_le32(ctx->height16 != out->height, b + 0x5c30);

	/* the frame it refers to */
	if (!idr) {
		u32 ref_slot = (n - 1) % AVE_USED_SLOTS;
		const struct ave_recon *ref = &ctx->recon[ref_slot];

		ave_put_dva(b, 0x8040, ref->y);
		ave_put_dva(b, 0x8060, ref->a);
		ave_put_dva(b, 0x8080, ref->c);
		ave_put_dva(b, 0x80a0, ref->b);
		ave_put_dva(b, 0x80c0, ctx->lowres_ref[ref_slot]);
		put_unaligned_le32(n - 1, b + 0x81a0);
	}

	/* the reconstructed frame and the source */
	ave_put_dva(b, 0x81e0, rec->y);
	ave_put_dva(b, 0x81e8, rec->a);
	ave_put_dva(b, 0x81f0, rec->c);
	ave_put_dva(b, 0x81f8, rec->b);
	ave_put_dva(b, 0x8200, ctx->colocated[slot]);
	ave_put_dva(b, 0x8208, src);
	put_unaligned_le32(stride, b + 0x8210);
	ave_put_dva(b, 0x8218, src + stride * out->height);
	put_unaligned_le32(stride, b + 0x8220);
	put_unaligned_le32(out->width, b + 0x82a4);
	put_unaligned_le32(out->height, b + 0x82a8);

	ave_put_dva(b, 0x82c0, ctx->neighbor_info);
	ave_put_dva(b, 0x82e0, ctx->neighbor_pixel);
	ave_put_dva(b, 0x8300, ctx->neighbor_data);
	ave_put_dva(b, 0x8320, ctx->neighbor_fw);
	for (i = 0; i < AVE_HEVC_PIPES; i++) {
		ave_put_dva(b, 0x8340 + 0x20 * i, ctx->entropy[0][i]);
		ave_put_dva(b, 0x8348 + 0x20 * i, ctx->entropy[1][i]);
	}

	/* the outputs */
	ave_put_dva(b, 0x8548, ctx->coded[0]);
	ave_put_dva(b, 0x8550, ctx->coded_hdr[0]);
	put_unaligned_le32(ctx->coded_size, b + 0x8558);
	ave_put_dva(b, 0x8560, ctx->lowres_ref[slot]);
	ave_put_dva(b, 0x8568, ctx->lowres_result[slot]);
	put_unaligned_le32(ctx->lowres_result_size, b + 0x8570);

	/* the frame's number and time */
	put_unaligned_le32(ctx->total, b + 0x8588);
	put_unaligned_le32(idr ? 3 : 1, b + 0x858c);
	put_unaligned_le32(mul_u64_u32_div((u64)ctx->total * ctx->tpf.numerator, AVE_HEVC_TIMESCALE,
					   ctx->tpf.denominator), b + 0x85a0);
	put_unaligned_le32(AVE_HEVC_TIMESCALE, b + 0x85a8);
	put_unaligned_le32(n, b + 0x85b0);

	/* HEVC_RPS: num_negative_pics; delta_poc_s0_minus1 stays 0: the frame before */
	put_unaligned_le32(!idr, b + 0x892c);
	put_unaligned_le32(!first, b + 0x8954);
}

const struct ave_codec ave_codec_hevc = {
	.id = 1,
	.start_size = 0x3aa10,
	.process_size = 0x8c08,
	.x28_session = 0x8,
	.x28_frame = 0x68,
	.pipes = AVE_HEVC_PIPES,
	.slice_hdr_size = AVE_SLICE_HDR_STRIDE * AVE_SLICE_HDR_NUM,
	.layout = ave_hevc_layout,
	.sizes = ave_hevc_sizes,
	.fill_start = ave_hevc_fill_start,
	.fill_process = ave_hevc_fill_process,
};
