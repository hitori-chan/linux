// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): HEVC sessions
 *
 * The level, the parameter sets until the firmware's replace them and the
 * buffers' sizes; Start and Process are in ave-9013.c. The firmware writes
 * each frame's slice header itself.
 *
 * Each frame refers to the one before it.
 */

#include <linux/sizes.h>

#include "ave.h"

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
void ave_hevc_layout(struct apple_ave_ctx *ctx)
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
	/* macOS: 6 up to 1080p, 5 at 4K and 8K, its two-core mode */
	ctx->refs = ctx->peer ? 5 : 6;

	memcpy(o, ave_hevc_vps, AVE_HEVC_VPS_LEN);
	if (ctx->bit_depth > 8) {
		o[AVE_HEVC_VPS_PROFILE] = 2;
		o[AVE_HEVC_VPS_COMPAT] = 0x20;
	}
	o[AVE_HEVC_VPS_LEVEL] = ctx->level;
	o[AVE_HEVC_VPS_DPB] = ctx->refs == 5 ? 0x17 : 0x1b;
	o += AVE_HEVC_VPS_LEN;
	o = ave_hevc_sps(ctx, o);
	memcpy(o, ave_hevc_pps, sizeof(ave_hevc_pps));
	o += sizeof(ave_hevc_pps);
	ctx->headers_len = o - ctx->headers;
}

void ave_hevc_sizes(struct apple_ave_ctx *ctx, struct ave_sizes *s)
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
}
