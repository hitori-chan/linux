// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): H.264 sessions
 *
 * The commands are macOS 14.8.3's as sent at 640x360, 1280x720 and 1920x1080:
 * their constant words are in ave-h264-tables.h and only the words that differ
 * between those sessions or from frame to frame are written here. The firmware
 * does the rate control and the entropy coding; the host gives it the parameter
 * sets, each frame's slice header up to the QP, which it replaces, and the
 * buffers, sized as the kext does (AVE_CalcBufSizeOf*, rda AppleAVE2
 * 0xfffffe00090d1cc0 on).
 *
 * macOS's stream alternates frames others refer to, on one core, with frames none
 * does, on the other. Here one core encodes every frame and each is a reference,
 * referring to the one before it.
 */

#include <linux/dma-mapping.h>
#include <linux/log2.h>
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

#define AVE_CODED_HDR_SIZE	0x30000
#define AVE_CODED_HDR_STRIDE	0x220
#define AVE_CODED_HDR_BYTES	0x180
#define AVE_CODED_HDR_REMOVE	0x38c
#define AVE_CODED_HDR_MAX	0x100
#define AVE_MISC_SIZE		0x20000
#define AVE_PARAMS_SIZE		0x4000
#define AVE_DEFAULT_CLIENT_SIZE	0x108000

#define AVE_FRAME_TIMEOUT_US	2000000

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

struct ave_bits {
	u8 *b;
	u32 n;
};

static void ave_put_bits(struct ave_bits *w, u32 v, u32 n)
{
	while (n--) {
		if (!(w->n & 7))
			w->b[w->n >> 3] = 0;
		w->b[w->n >> 3] |= ((v >> n) & 1) << (7 - (w->n & 7));
		w->n++;
	}
}

static void ave_put_ue(struct ave_bits *w, u32 v)
{
	u32 len = fls(v + 1);

	ave_put_bits(w, 0, len - 1);
	ave_put_bits(w, v + 1, len);
}

static void ave_put_se(struct ave_bits *w, int v)
{
	ave_put_ue(w, v > 0 ? 2 * v - 1 : -2 * v);
}

static u32 ave_fps(const struct apple_ave_ctx *ctx)
{
	return max_t(u32, 1, DIV_ROUND_CLOSEST(ctx->tpf.denominator, ctx->tpf.numerator));
}

/* The level macOS picks: the first that holds the size, the rate and the bitrate */
void ave_h264_layout(struct apple_ave_ctx *ctx)
{
	const struct ave_h264_level *l = NULL;
	u32 mbs, mbps, i;

	ctx->mbw = DIV_ROUND_UP(ctx->out_fmt.width, 16);
	ctx->mbh = DIV_ROUND_UP(ctx->out_fmt.height, 16);
	ctx->height16 = ctx->mbh * 16;
	mbs = ctx->mbw * ctx->mbh;
	mbps = mbs * ave_fps(ctx);

	for (i = 0; i < ARRAY_SIZE(ave_h264_levels); i++) {
		l = &ave_h264_levels[i];
		if (mbs <= l->max_fs && mbps <= l->max_mbps &&
		    ctx->bitrate / 1000 <= l->max_kbps)
			break;
	}
	ctx->level = l->idc;
	ctx->refs = min_t(u32, 10, l->max_dpb_mbs / mbs);
}

/* The sequence parameter set macOS writes, then its picture parameter set */
static void ave_h264_headers(struct apple_ave_ctx *ctx)
{
	static const u8 start[] = { 0, 0, 0, 1 };
	u8 rbsp[32], *o = ctx->headers;
	struct ave_bits w = { rbsp, 0 };
	u32 crop = ctx->height16 - ctx->out_fmt.height, i, zeros = 0;
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
	ave_put_bits(&w, 1, 1);		/* the stop bit */
	while (w.n & 7)
		ave_put_bits(&w, 0, 1);

	memcpy(o, start, sizeof(start));
	o += sizeof(start);
	for (i = 0; i < w.n / 8; i++) {
		if (zeros >= 2 && rbsp[i] <= 3) {
			*o++ = 3;
			zeros = 0;
		}
		zeros = rbsp[i] ? 0 : zeros + 1;
		*o++ = rbsp[i];
	}
	memcpy(o, start, sizeof(start));
	o += sizeof(start);
	memcpy(o, ave_h264_pps, sizeof(ave_h264_pps));
	o += sizeof(ave_h264_pps);
	ctx->headers_len = o - ctx->headers;
}

int ave_h264_alloc(struct apple_ave_ctx *ctx)
{
	struct device *dev = ctx->ave->dev;
	u32 w = ctx->mbw * 16, h = ctx->height16, mbw = ctx->mbw, mbh = ctx->mbh;
	u32 rec_y = ALIGN(w, 32) * ALIGN(h + 16, 32), rec_c = rec_y / 2 + SZ_16K;
	u32 rec_a = ALIGN(w * h / 16, SZ_16K), rec_b = ALIGN(w * h / 64, SZ_16K);
	u32 lowres_ref, colocated, info, pixel, data, fw, client;
	size_t off = 0;
	int i, p;

#define AVE_ALLOC(size) ({ size_t _o = off; off += ALIGN(size, SZ_16K) + SZ_16K; _o; })

	lowres_ref = 2 * ((((((mbw + 3) >> 2) * (((h + 0x3f) & ~0xfu) >> 4)) << 8) + 0x1ff) & ~0x1ffu);
	colocated = ((8 * w + 0x78) & ~0x7fu) * mbh;
	info = max_t(u32, (16 * w + 0xf0) & ~0xffu, SZ_16K);
	pixel = max_t(u32, ((w << 6) + 0x3c0) & ~0x3ffu, SZ_16K);
	data = max_t(u32, 0x38 * mbw, SZ_16K);
	fw = max_t(u32, (((4 * w + 0x3c) & ~0x3fu) + 0x7f) & ~0x7fu, SZ_16K);
	client = ctx->ave->client_size ?: AVE_DEFAULT_CLIENT_SIZE;

	/* AVE_CalcBufSizeOfCodedData: never less than a 640x480 frame's */
	ctx->coded_size = ALIGN(max_t(u32, w * h * 3 / 2, 640 * 480 * 3 / 2), SZ_16K);
	ctx->coded_size = max_t(u32, ctx->coded_size,
				ALIGN(ctx->bitrate / ave_fps(ctx) / 4, SZ_16K));
	ctx->lowres_result_size = ALIGN(4 * ((((((w + 31) >> 5) * ((h + 63) >> 6))) << 7) + 0x400),
					SZ_16K);
	ctx->transcoded_size = ALIGN(ctx->coded_size / 2, SZ_16K);
	ctx->entropy_size = ALIGN(pixel * ((mbh + 3) >> 2), SZ_16K);

	/* a frame refers only to the one before it, so Start's rings hold two sets each */
	for (i = 0; i < AVE_USED_SLOTS; i++) {
		size_t base = AVE_ALLOC(rec_a + rec_b + rec_y + rec_c);

		ctx->recon[i].a = base;
		ctx->recon[i].b = base + rec_a;
		ctx->recon[i].y = base + rec_a + rec_b;
		ctx->recon[i].c = ctx->recon[i].y + rec_y;
		ctx->lowres_ref[i] = AVE_ALLOC(lowres_ref);
		ctx->lowres_result[i] = AVE_ALLOC(ctx->lowres_result_size);
		ctx->colocated[i] = AVE_ALLOC(colocated);
	}
	ctx->lowres_result_a = AVE_ALLOC(ctx->lowres_result_size);
	ctx->lowres_result_b = AVE_ALLOC(ctx->lowres_result_size);
	ctx->transcoded[0] = AVE_ALLOC(ctx->transcoded_size);
	ctx->transcoded[1] = AVE_ALLOC(ctx->transcoded_size);
	ctx->neighbor_info = AVE_ALLOC(info);
	ctx->neighbor_pixel = AVE_ALLOC(pixel);
	ctx->neighbor_data = AVE_ALLOC(data);
	ctx->neighbor_fw = AVE_ALLOC(fw);
	for (i = 0; i < 2; i++)
		for (p = 0; p < AVE_NUM_PIPES; p++)
			ctx->entropy[i][p] = AVE_ALLOC(ctx->entropy_size);
	ctx->client = AVE_ALLOC(client);
	ctx->misc = AVE_ALLOC(AVE_MISC_SIZE);
	ctx->params = AVE_ALLOC(AVE_PARAMS_SIZE);
#undef AVE_ALLOC

	ctx->mem.size = off;
	ctx->mem.cpu = dma_alloc_attrs(dev, off, &ctx->mem.iova, GFP_KERNEL,
				       DMA_ATTR_NO_KERNEL_MAPPING);
	if (!ctx->mem.cpu)
		return -ENOMEM;
	ctx->coded0.size = ctx->coded_size;
	ctx->coded0.cpu = dma_alloc_coherent(dev, ctx->coded0.size, &ctx->coded0.iova, GFP_KERNEL);
	ctx->coded_hdr0.size = AVE_CODED_HDR_SIZE;
	ctx->coded_hdr0.cpu = dma_alloc_coherent(dev, ctx->coded_hdr0.size, &ctx->coded_hdr0.iova,
						 GFP_KERNEL);
	if (!ctx->coded0.cpu || !ctx->coded_hdr0.cpu) {
		ave_h264_free(ctx);
		return -ENOMEM;
	}

	for (i = 0; i < AVE_NUM_SLOTS; i++) {
		if (i < AVE_USED_SLOTS) {
			ctx->recon[i].a += ctx->mem.iova;
			ctx->recon[i].b += ctx->mem.iova;
			ctx->recon[i].y += ctx->mem.iova;
			ctx->recon[i].c += ctx->mem.iova;
			ctx->lowres_ref[i] += ctx->mem.iova;
			ctx->lowres_result[i] += ctx->mem.iova;
			ctx->colocated[i] += ctx->mem.iova;
		} else {
			ctx->recon[i] = ctx->recon[i % AVE_USED_SLOTS];
			ctx->lowres_ref[i] = ctx->lowres_ref[i % AVE_USED_SLOTS];
			ctx->lowres_result[i] = ctx->lowres_result[i % AVE_USED_SLOTS];
			ctx->colocated[i] = ctx->colocated[i % AVE_USED_SLOTS];
		}
		ctx->coded[i] = ctx->coded0.iova;
		ctx->coded_hdr[i] = ctx->coded_hdr0.iova;
	}
	ctx->lowres_result_a += ctx->mem.iova;
	ctx->lowres_result_b += ctx->mem.iova;
	ctx->transcoded[0] += ctx->mem.iova;
	ctx->transcoded[1] += ctx->mem.iova;
	ctx->neighbor_info += ctx->mem.iova;
	ctx->neighbor_pixel += ctx->mem.iova;
	ctx->neighbor_data += ctx->mem.iova;
	ctx->neighbor_fw += ctx->mem.iova;
	for (i = 0; i < 2; i++)
		for (p = 0; p < AVE_NUM_PIPES; p++)
			ctx->entropy[i][p] += ctx->mem.iova;
	ctx->client += ctx->mem.iova;
	ctx->misc += ctx->mem.iova;
	ctx->params += ctx->mem.iova;

	return 0;
}

void ave_h264_free(struct apple_ave_ctx *ctx)
{
	struct device *dev = ctx->ave->dev;

	if (ctx->mem.cpu)
		dma_free_attrs(dev, ctx->mem.size, ctx->mem.cpu, ctx->mem.iova,
			       DMA_ATTR_NO_KERNEL_MAPPING);
	if (ctx->coded0.cpu)
		dma_free_coherent(dev, ctx->coded0.size, ctx->coded0.cpu, ctx->coded0.iova);
	if (ctx->coded_hdr0.cpu)
		dma_free_coherent(dev, ctx->coded_hdr0.size, ctx->coded_hdr0.cpu,
				  ctx->coded_hdr0.iova);
	ctx->mem.cpu = NULL;
	ctx->coded0.cpu = NULL;
	ctx->coded_hdr0.cpu = NULL;
}

static void ave_put_words(u8 *b, const u32 *t, size_t n)
{
	size_t i = 0;

	while (i < n) {
		u32 off = t[i], count = t[i + 1];

		memcpy(b + off, &t[i + 2], count * sizeof(u32));
		i += 2 + count;
	}
}

/* AVE_CHM_MakeFwCmd_*: the header each command starts with */
static void ave_cmd_header(struct apple_ave *ave, u8 *b, u16 id, u32 slot, u32 x20, u32 x28, u32 x30)
{
	ave->seq += 100;
	put_unaligned_le16(id, b);
	put_unaligned_le64(ave->seq, b + 0x08);
	put_unaligned_le32(1, b + 0x10);	/* the client */
	put_unaligned_le32(1, b + 0x14);	/* the encoder engine */
	put_unaligned_le32(0, b + 0x18);	/* AVC */
	put_unaligned_le32(slot, b + 0x1c);
	put_unaligned_le32(x20, b + 0x20);
	put_unaligned_le32(0x16, b + 0x24);
	put_unaligned_le32(x28, b + 0x28);
	put_unaligned_le32(x30, b + 0x30);
	put_unaligned_le64(ave_fw_time_ms(ave), b + 0x38);
}

static int ave_small_command(struct apple_ave *ave, u16 id, u32 x20, u32 x28)
{
	size_t off;
	u8 *b = ave_ipc_alloc(ave, 0xf0, &off);

	if (!b)
		return -ENOMEM;
	ave_cmd_header(ave, b, id, id, x20, x28, 0x170c0);
	return ave_fw_command(ave, off, AVE_CMD_SMALL_SIZE, id);
}

static void ave_put_dva(u8 *b, u32 off, dma_addr_t dva)
{
	put_unaligned_le64(dva, b + off);
}

/* AVE_CHM_MakeFwCmd_Start_AVC (0xfffffe00090d6a88) with AVE_CHM_SetFwBuf */
static void ave_h264_fill_start(struct apple_ave_ctx *ctx, u8 *b)
{
	struct apple_ave *ave = ctx->ave;
	u32 crop = ctx->height16 - ctx->out_fmt.height, spslen, i, p;
	u32 crop_r = ctx->mbw * 16 - ctx->out_fmt.width;
	static const u8 start[] = { 0, 0, 0, 1 };

	ave_put_words(b, ave_h264_start_words, ARRAY_SIZE(ave_h264_start_words));
	ave_cmd_header(ave, b, AVE_CMD_START, AVE_CMD_START, 0xc8, 0x50, 0x170c0);

	ave_put_dva(b, 0x48, ctx->client);
	put_unaligned_le32(ave->client_size ?: AVE_DEFAULT_CLIENT_SIZE, b + 0x50);
	ave_put_dva(b, 0x58, ctx->misc);
	put_unaligned_le32(AVE_MISC_SIZE, b + 0x60);
	put_unaligned_le32(ctx->mbw * 16, b + 0x68);
	put_unaligned_le32(ctx->height16, b + 0x6c);
	/* 0x20 traced at 640x368, 0x10 from 864x480 up */
	put_unaligned_le32(ctx->mbw * ctx->mbh <= 1200 ? 0x20 : 0x10, b + 0x84);

	for (i = 0; i < AVE_NUM_SLOTS; i++) {
		ave_put_dva(b, 0x98 + 0x10 * i, ctx->recon[i].y);
		ave_put_dva(b, 0xa0 + 0x10 * i, ctx->recon[i].a);
		ave_put_dva(b, 0x2b8 + 8 * i, ctx->lowres_ref[i]);
		ave_put_dva(b, 0x478 + 8 * i, ctx->coded[i]);
		put_unaligned_le32(ctx->coded_size, b + 0x568 + 4 * i);
		ave_put_dva(b, 0x5f8 + 8 * i, ctx->coded_hdr[i]);
		put_unaligned_le32(AVE_CODED_HDR_SIZE, b + 0x6e8 + 4 * i);
		ave_put_dva(b, 0x16f60 + 8 * i, ctx->colocated[i]);
	}
	ave_put_dva(b, 0x3c8, ctx->lowres_result_a);
	put_unaligned_le32(ctx->lowres_result_size, b + 0x418);
	ave_put_dva(b, 0x420, ctx->lowres_result_b);
	put_unaligned_le32(ctx->lowres_result_size, b + 0x470);
	ave_put_dva(b, 0x5e0, ctx->transcoded[0]);
	ave_put_dva(b, 0x5e8, ctx->transcoded[1]);
	put_unaligned_le32(ctx->transcoded_size, b + 0x5f0);

	ave_put_dva(b, 0x17080, ctx->neighbor_info);
	ave_put_dva(b, 0x170a0, ctx->neighbor_pixel);
	ave_put_dva(b, 0x170c0, ctx->neighbor_data);
	ave_put_dva(b, 0x17a40, ctx->neighbor_fw);
	for (p = 0; p < AVE_NUM_PIPES; p++) {
		ave_put_dva(b, 0x170e0 + 0x20 * p, ctx->entropy[0][p]);
		ave_put_dva(b, 0x170e8 + 0x20 * p, ctx->entropy[1][p]);
		put_unaligned_le32(ctx->entropy_size, b + 0x172e0 + 0x10 * p);
		put_unaligned_le32(ctx->entropy_size, b + 0x172e4 + 0x10 * p);
	}
	ave_put_dva(b, 0x173e0, ctx->params);
	put_unaligned_le32(AVE_PARAMS_SIZE, b + 0x173e8);

	put_unaligned_le32(ctx->height16, b + 0x17924);
	put_unaligned_le32(ctx->bitrate, b + 0x17b70);
	/* set from 2560x1440 up, not at 1080p: level 5 or above */
	put_unaligned_le32(ctx->level >= 50 ? 0x10000 : 0, b + 0x17bb0);
	put_unaligned_le32(ave_fps(ctx), b + 0x17b84);
	put_unaligned_le32(ave_fps(ctx), b + 0x17b9c);

	/* the sequence parameter set, as fields and as its NAL unit with its start code */
	put_unaligned_le32(ctx->level, b + 0x18218);
	put_unaligned_le32(ctx->refs, b + 0x18624);
	put_unaligned_le32(ctx->mbw - 1, b + 0x1862c);
	put_unaligned_le32(ctx->mbh - 1, b + 0x18630);
	put_unaligned_le32(crop || crop_r, b + 0x18688);
	put_unaligned_le32(crop_r / 2, b + 0x18690);
	put_unaligned_le32(crop / 2, b + 0x18698);
	spslen = ctx->headers_len - sizeof(ave_h264_pps) - sizeof(start);
	put_unaligned_le32(8 * spslen, b + 0x186a0);
	memcpy(b + 0x186a4, ctx->headers, spslen);
}

/* The session up to its first frame: AVE_HwC's Open and Start, each answered on IO_T2H */
int ave_h264_start(struct apple_ave_ctx *ctx)
{
	struct apple_ave *ave = ctx->ave;
	size_t start_off;
	u8 *start;
	int ret;

	ave_h264_layout(ctx);
	ave_h264_headers(ctx);

	ret = ave_fw_boot(ave);
	if (ret)
		return ret;

	ret = ave_h264_alloc(ctx);
	if (ret)
		goto err;

	ret = ave_small_command(ave, AVE_CMD_OPEN, 0xc8, 0x78);
	if (ret)
		goto err_free;

	start = ave_ipc_alloc(ave, AVE_START_H264_SIZE, &start_off);
	ctx->process = ave_ipc_alloc(ave, AVE_PROCESS_H264_SIZE, &ctx->process_off);
	if (!start || !ctx->process) {
		ret = -ENOMEM;
		goto err_free;
	}
	ave_h264_fill_start(ctx, start);
	ret = ave_fw_command(ave, start_off, AVE_START_H264_SIZE, AVE_CMD_START);
	if (ret)
		goto err_free;

	ctx->frame = 0;
	ctx->total = 0;
	ctx->idr_id = 0;
	ctx->running = true;
	return 0;

err_free:
	ave_h264_free(ctx);
err:
	ave_fw_shutdown(ave, false);
	return ret;
}

/* The stream's end: Complete, Stop and Close, each answered, then the firmware's halt */
void ave_h264_stop(struct apple_ave_ctx *ctx)
{
	struct apple_ave *ave = ctx->ave;
	int ret;

	ret = ave_small_command(ave, AVE_CMD_COMPLETE, 0, 0x70);
	if (!ret)
		ret = ave_small_command(ave, AVE_CMD_STOP, 0xc8, 0x70);
	if (!ret)
		ret = ave_small_command(ave, AVE_CMD_CLOSE, 0xc8, 0x50);
	ave_fw_shutdown(ave, !ret);
	ave_h264_free(ctx);
	ctx->running = false;
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
static void ave_h264_fill_process(struct apple_ave_ctx *ctx, u8 *b, dma_addr_t src)
{
	struct apple_ave *ave = ctx->ave;
	const struct v4l2_pix_format_mplane *out = &ctx->out_fmt;
	u32 stride = out->plane_fmt[0].bytesperline, n = ctx->frame, nbits, i;
	bool idr = !n;
	u32 slot = n % AVE_USED_SLOTS;
	const struct ave_recon *rec = &ctx->recon[slot];
	u8 bits[16];

	memset(b, 0, AVE_PROCESS_H264_SIZE);
	ave_put_words(b, ave_h264_process_words, ARRAY_SIZE(ave_h264_process_words));
	ave_cmd_header(ave, b, AVE_CMD_PROCESS, 0x15, 0, 0x70, 0xb540);

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

	ave_put_dva(b, 0x37f8, ctx->neighbor_info);
	ave_put_dva(b, 0x3818, ctx->neighbor_pixel);
	ave_put_dva(b, 0x3838, ctx->neighbor_data);
	ave_put_dva(b, 0x3858, ctx->neighbor_fw);
	for (i = 0; i < AVE_NUM_PIPES; i++) {
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
	put_unaligned_le32(AVE_H264_TIMESCALE, b + 0x3ae0);
	put_unaligned_le32(n, b + 0x3ae8);
}

/* AVE_RetrieveRCFrameStats (0xfffffe00090f6930): the frame's bytes from its header */
static int ave_h264_coded_bytes(struct apple_ave_ctx *ctx, u32 *bytes)
{
	u8 *hdr = ctx->coded_hdr0.cpu;
	u32 total = 0, remove = 0, i;

	for (i = 0; i < AVE_CODED_HDR_MAX; i++) {
		const u8 *e = hdr + i * AVE_CODED_HDR_STRIDE;
		u32 size = get_unaligned_le32(e + AVE_CODED_HDR_BYTES);
		s8 rm = e[AVE_CODED_HDR_REMOVE];

		if (!size)
			break;
		if (rm < 0) {
			dev_err(ctx->ave->dev, "slice %u: %d bytes to remove\n", i, rm);
			return -EPROTO;
		}
		total += size;
		remove += rm;
	}
	memset(hdr, 0, min_t(size_t, (i + 1) * AVE_CODED_HDR_STRIDE, AVE_CODED_HDR_SIZE));

	if (!total || total - remove > ctx->coded_size) {
		dev_err(ctx->ave->dev, "frame %u: %u bytes, %u to remove, of %u\n", ctx->frame,
			total, remove, ctx->coded_size);
		return -EPROTO;
	}
	*bytes = total - remove;
	return 0;
}

int ave_h264_encode(struct apple_ave_ctx *ctx, dma_addr_t src, u8 *dst, size_t dst_size,
		    size_t *bytes, bool *keyframe)
{
	struct apple_ave *ave = ctx->ave;
	u32 seen = ave->t2h_seen[AVE_CMD_PROCESS], coded, head = 0;
	int ret;

	/* an IDR restarts the numbering; consecutive IDRs' idr_pic_id must differ */
	if (ctx->frame && (xchg(&ctx->force_idr, false) ||
			   (ctx->gop_size && ctx->frame >= ctx->gop_size))) {
		ctx->frame = 0;
		ctx->idr_id ^= 1;
	}
	*keyframe = !ctx->frame;
	ave_h264_fill_process(ctx, ctx->process, src);
	ret = ave_fw_send(ave, ctx->process_off, AVE_PROCESS_H264_SIZE);
	if (ret)
		return ret;
	ret = ave_fw_wait(ave, AVE_CMD_PROCESS, seen, AVE_FRAME_TIMEOUT_US);
	if (ret)
		return ret;

	ret = ave_h264_coded_bytes(ctx, &coded);
	if (ret)
		return ret;
	ctx->frame++;
	ctx->total++;

	if (*keyframe)
		head = ctx->headers_len;
	if (head + coded > dst_size) {
		dev_err(ave->dev, "frame %u: %u bytes, the buffer holds %zu\n", ctx->frame - 1,
			head + coded, dst_size);
		return -ENOSPC;
	}
	if (head)
		memcpy(dst, ctx->headers, head);
	memcpy(dst + head, ctx->coded0.cpu, coded);
	*bytes = head + coded;
	return 0;
}
