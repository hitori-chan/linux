// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): what H.264 and HEVC sessions share
 *
 * The session's commands, its buffers, sized as the kext does
 * (AVE_CalcBufSizeOf*, rda AppleAVE2 0xfffffe00090d1cc0 on), and the frame's way
 * to the capture buffer.
 */

#include <linux/dma-mapping.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>

#include "ave.h"

#define AVE_CODED_HDR_SIZE	0x30000
#define AVE_CODED_HDR_STRIDE	0x220
#define AVE_CODED_HDR_BYTES	0x180
#define AVE_CODED_HDR_REMOVE	0x38c
#define AVE_CODED_HDR_MAX	0x100
#define AVE_MISC_SIZE		0x20000
#define AVE_PARAMS_SIZE		0x4000
#define AVE_DEFAULT_CLIENT_SIZE	0x108000

#define AVE_FRAME_TIMEOUT_US	2000000

void ave_put_bits(struct ave_bits *w, u32 v, u32 n)
{
	while (n--) {
		if (!(w->n & 7))
			w->b[w->n >> 3] = 0;
		w->b[w->n >> 3] |= ((v >> n) & 1) << (7 - (w->n & 7));
		w->n++;
	}
}

void ave_put_ue(struct ave_bits *w, u32 v)
{
	u32 len = fls(v + 1);

	ave_put_bits(w, 0, len - 1);
	ave_put_bits(w, v + 1, len);
}

void ave_put_se(struct ave_bits *w, int v)
{
	ave_put_ue(w, v > 0 ? 2 * v - 1 : -2 * v);
}

/* The stop bit and the alignment, then the NAL unit with its start code and escapes */
u8 *ave_put_nal(u8 *o, struct ave_bits *w)
{
	static const u8 start[] = { 0, 0, 0, 1 };
	u32 i, zeros = 0;

	ave_put_bits(w, 1, 1);
	while (w->n & 7)
		ave_put_bits(w, 0, 1);

	memcpy(o, start, sizeof(start));
	o += sizeof(start);
	for (i = 0; i < w->n / 8; i++) {
		if (zeros >= 2 && w->b[i] <= 3) {
			*o++ = 3;
			zeros = 0;
		}
		zeros = w->b[i] ? 0 : zeros + 1;
		*o++ = w->b[i];
	}
	return o;
}

u32 ave_fps(const struct apple_ave_ctx *ctx)
{
	return max_t(u32, 1, DIV_ROUND_CLOSEST(ctx->tpf.denominator, ctx->tpf.numerator));
}

static int ave_alloc(struct apple_ave_ctx *ctx)
{
	struct device *dev = ctx->ave->dev;
	u32 w = ctx->mbw * 16, h = ctx->height16;
	u32 rec_y = ALIGN(w, 32) * ALIGN(h + 16, 32), rec_c = rec_y / 2 + SZ_16K;
	u32 rec_a = ALIGN(w * h / 16, SZ_16K), rec_b = ALIGN(w * h / 64, SZ_16K);
	struct ave_sizes s = {};
	size_t off = 0;
	int i, p;

#define AVE_ALLOC(size) ({ size_t _o = off; off += ALIGN(size, SZ_16K) + SZ_16K; _o; })

	ctx->codec->sizes(ctx, &s);

	/* AVE_CalcBufSizeOfCodedData: never less than a 640x480 frame's */
	ctx->coded_size = ALIGN(max_t(u32, w * h * 3 / 2, 640 * 480 * 3 / 2), SZ_16K);
	ctx->coded_size = max_t(u32, ctx->coded_size,
				ALIGN(ctx->bitrate / ave_fps(ctx) / 4, SZ_16K));
	ctx->lowres_result_size = ALIGN(4 * ((((((w + 31) >> 5) * ((h + 63) >> 6))) << 7) + 0x400),
					SZ_16K);
	ctx->transcoded_size = s.transcoded ? ALIGN(ctx->coded_size / 2, SZ_16K) : 0;
	ctx->entropy_size = ALIGN(s.entropy, SZ_16K);

	/* a frame refers only to the one before it, so Start's rings hold two sets each */
	for (i = 0; i < AVE_USED_SLOTS; i++) {
		size_t base = AVE_ALLOC(rec_a + rec_b + rec_y + rec_c);

		ctx->recon[i].a = base;
		ctx->recon[i].b = base + rec_a;
		ctx->recon[i].y = base + rec_a + rec_b;
		ctx->recon[i].c = ctx->recon[i].y + rec_y;
		ctx->lowres_ref[i] = AVE_ALLOC(s.lowres_ref);
		ctx->lowres_result[i] = AVE_ALLOC(ctx->lowres_result_size);
		ctx->colocated[i] = AVE_ALLOC(s.colocated);
	}
	ctx->lowres_result_a = AVE_ALLOC(ctx->lowres_result_size);
	ctx->lowres_result_b = AVE_ALLOC(ctx->lowres_result_size);
	ctx->transcoded[0] = AVE_ALLOC(ctx->transcoded_size);
	ctx->transcoded[1] = AVE_ALLOC(ctx->transcoded_size);
	ctx->extra[0] = AVE_ALLOC(s.extra);
	ctx->extra[1] = AVE_ALLOC(s.extra);
	ctx->neighbor_info = AVE_ALLOC(s.info);
	ctx->neighbor_pixel = AVE_ALLOC(s.pixel);
	ctx->neighbor_data = AVE_ALLOC(s.data);
	ctx->neighbor_fw = AVE_ALLOC(s.fw);
	for (i = 0; i < 2; i++)
		for (p = 0; p < ctx->codec->pipes; p++)
			ctx->entropy[i][p] = AVE_ALLOC(ctx->entropy_size);
	ctx->client = AVE_ALLOC(ctx->ave->client_size ?: AVE_DEFAULT_CLIENT_SIZE);
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
	if (!ctx->coded0.cpu || !ctx->coded_hdr0.cpu)
		goto err;
	if (ctx->codec->slice_hdr_size) {
		ctx->slice_hdr.size = ctx->codec->slice_hdr_size;
		ctx->slice_hdr.cpu = dma_alloc_coherent(dev, ctx->slice_hdr.size,
							&ctx->slice_hdr.iova, GFP_KERNEL);
		if (!ctx->slice_hdr.cpu)
			goto err;
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
	ctx->extra[0] += ctx->mem.iova;
	ctx->extra[1] += ctx->mem.iova;
	ctx->neighbor_info += ctx->mem.iova;
	ctx->neighbor_pixel += ctx->mem.iova;
	ctx->neighbor_data += ctx->mem.iova;
	ctx->neighbor_fw += ctx->mem.iova;
	for (i = 0; i < 2; i++)
		for (p = 0; p < ctx->codec->pipes; p++)
			ctx->entropy[i][p] += ctx->mem.iova;
	ctx->client += ctx->mem.iova;
	ctx->misc += ctx->mem.iova;
	ctx->params += ctx->mem.iova;

	return 0;

err:
	ave_session_free(ctx);
	return -ENOMEM;
}

void ave_session_free(struct apple_ave_ctx *ctx)
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
	if (ctx->slice_hdr.cpu)
		dma_free_coherent(dev, ctx->slice_hdr.size, ctx->slice_hdr.cpu,
				  ctx->slice_hdr.iova);
	ctx->mem.cpu = NULL;
	ctx->coded0.cpu = NULL;
	ctx->coded_hdr0.cpu = NULL;
	ctx->slice_hdr.cpu = NULL;
}

void ave_put_words(u8 *b, const u32 *t, size_t n)
{
	size_t i = 0;

	while (i < n) {
		u32 off = t[i], count = t[i + 1];

		memcpy(b + off, &t[i + 2], count * sizeof(u32));
		i += 2 + count;
	}
}

/* AVE_CHM_MakeFwCmd_*: the header each command starts with */
void ave_cmd_header(struct apple_ave_ctx *ctx, u8 *b, u16 id, u32 slot, u32 x20, u32 x28, u32 x30)
{
	struct apple_ave *ave = ctx->ave;

	ave->seq += 100;
	put_unaligned_le16(id, b);
	put_unaligned_le64(ave->seq, b + 0x08);
	put_unaligned_le32(1, b + 0x10);	/* the client */
	put_unaligned_le32(1, b + 0x14);	/* the encoder engine */
	put_unaligned_le32(ctx->codec->id, b + 0x18);
	put_unaligned_le32(slot, b + 0x1c);
	put_unaligned_le32(x20, b + 0x20);
	put_unaligned_le32(0x16, b + 0x24);
	put_unaligned_le32(x28, b + 0x28);
	put_unaligned_le32(x30, b + 0x30);
	put_unaligned_le64(ave_fw_time_ms(ave), b + 0x38);
}

static int ave_small_command(struct apple_ave_ctx *ctx, u16 id, u32 x20, u32 x28)
{
	struct apple_ave *ave = ctx->ave;
	size_t off;
	u8 *b = ave_ipc_alloc(ave, 0xf0, &off);

	if (!b)
		return -ENOMEM;
	ave_cmd_header(ctx, b, id, id, x20, x28, 0x170c0);
	return ave_fw_command(ave, off, AVE_CMD_SMALL_SIZE, id);
}

/* AVE_CHM_SetFwBuf: the buffers in Start, at the same place for both codecs */
void ave_fill_start_buffers(struct apple_ave_ctx *ctx, u8 *b)
{
	struct apple_ave *ave = ctx->ave;
	u32 i, p;

	ave_cmd_header(ctx, b, AVE_CMD_START, AVE_CMD_START, 0xc8, ctx->codec->x28_session, 0x170c0);

	ave_put_dva(b, 0x48, ctx->client);
	put_unaligned_le32(ave->client_size ?: AVE_DEFAULT_CLIENT_SIZE, b + 0x50);
	ave_put_dva(b, 0x58, ctx->misc);
	put_unaligned_le32(AVE_MISC_SIZE, b + 0x60);
	put_unaligned_le32(ctx->mbw * 16, b + 0x68);
	put_unaligned_le32(ctx->height16, b + 0x6c);

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

	ave_put_dva(b, 0x17080, ctx->neighbor_info);
	ave_put_dva(b, 0x170a0, ctx->neighbor_pixel);
	ave_put_dva(b, 0x170c0, ctx->neighbor_data);
	ave_put_dva(b, 0x17a40, ctx->neighbor_fw);
	for (p = 0; p < ctx->codec->pipes; p++) {
		ave_put_dva(b, 0x170e0 + 0x20 * p, ctx->entropy[0][p]);
		ave_put_dva(b, 0x170e8 + 0x20 * p, ctx->entropy[1][p]);
		put_unaligned_le32(ctx->entropy_size, b + 0x172e0 + 0x10 * p);
		put_unaligned_le32(ctx->entropy_size, b + 0x172e4 + 0x10 * p);
	}
	ave_put_dva(b, 0x173e0, ctx->params);
	put_unaligned_le32(AVE_PARAMS_SIZE, b + 0x173e8);

	put_unaligned_le32(ctx->height16, b + 0x17924);
	put_unaligned_le32(ctx->bitrate, b + 0x17b70);
	put_unaligned_le32(ave_fps(ctx), b + 0x17b84);
	put_unaligned_le32(ave_fps(ctx), b + 0x17b9c);
}

/* The session up to its first frame: AVE_HwC's Open and Start, each answered on IO_T2H */
int ave_session_start(struct apple_ave_ctx *ctx)
{
	struct apple_ave *ave = ctx->ave;
	size_t start_off;
	u8 *start;
	int ret;

	ctx->codec = ctx->cap_fmt.pixelformat == V4L2_PIX_FMT_HEVC ? &ave_codec_hevc :
								     &ave_codec_h264;
	ctx->mbw = DIV_ROUND_UP(ctx->out_fmt.width, 16);
	ctx->mbh = DIV_ROUND_UP(ctx->out_fmt.height, 16);
	ctx->height16 = ctx->mbh * 16;
	ctx->codec->layout(ctx);

	ret = ave_fw_boot(ave);
	if (ret)
		return ret;

	ret = ave_alloc(ctx);
	if (ret)
		goto err;

	ret = ave_small_command(ctx, AVE_CMD_OPEN, 0xc8, 0x78);
	if (ret)
		goto err_free;

	start = ave_ipc_alloc(ave, ctx->codec->start_size, &start_off);
	ctx->process = ave_ipc_alloc(ave, ctx->codec->process_size, &ctx->process_off);
	if (!start || !ctx->process) {
		ret = -ENOMEM;
		goto err_free;
	}
	ctx->codec->fill_start(ctx, start);
	ret = ave_fw_command(ave, start_off, ctx->codec->start_size, AVE_CMD_START);
	if (ret)
		goto err_free;

	ctx->frame = 0;
	ctx->total = 0;
	ctx->idr_id = 0;
	ctx->running = true;
	return 0;

err_free:
	ave_session_free(ctx);
err:
	ave_fw_shutdown(ave, false);
	return ret;
}

/* The stream's end: Complete, Stop and Close, each answered, then the firmware's halt */
void ave_session_stop(struct apple_ave_ctx *ctx)
{
	struct apple_ave *ave = ctx->ave;
	int ret;

	ret = ave_small_command(ctx, AVE_CMD_COMPLETE, 0, ctx->codec->x28_frame);
	if (!ret)
		ret = ave_small_command(ctx, AVE_CMD_STOP, 0xc8, ctx->codec->x28_frame);
	if (!ret)
		ret = ave_small_command(ctx, AVE_CMD_CLOSE, 0xc8, ctx->codec->x28_session);
	ave_fw_shutdown(ave, !ret);
	ave_session_free(ctx);
	ctx->running = false;
}

/* AVE_RetrieveRCFrameStats (0xfffffe00090f6930): the frame's bytes from its header */
static int ave_coded_bytes(struct apple_ave_ctx *ctx, u32 *bytes)
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

/*
 * HEVC's slice header, which the firmware wrote apart from the coded data: its
 * start code and NAL header to the entry points' last byte, which is not zero.
 */
static u32 ave_slice_hdr_bytes(struct apple_ave_ctx *ctx)
{
	const u8 *h = ctx->slice_hdr.cpu;
	u32 n = AVE_SLICE_HDR_STRIDE;

	if (!h)
		return 0;
	while (n && !h[n - 1])
		n--;
	return n;
}

int ave_session_encode(struct apple_ave_ctx *ctx, dma_addr_t src, u8 *dst, size_t dst_size,
		       size_t *bytes, bool *keyframe)
{
	struct apple_ave *ave = ctx->ave;
	u32 seen = ave->t2h_seen[AVE_CMD_PROCESS], coded, head = 0, slice;
	int ret;

	/* an IDR restarts the numbering; consecutive IDRs' idr_pic_id must differ */
	if (ctx->frame && (xchg(&ctx->force_idr, false) ||
			   (ctx->gop_size && ctx->frame >= ctx->gop_size))) {
		ctx->frame = 0;
		ctx->idr_id ^= 1;
	}
	*keyframe = !ctx->frame;
	ctx->codec->fill_process(ctx, ctx->process, src);
	ret = ave_fw_send(ave, ctx->process_off, ctx->codec->process_size);
	if (ret)
		return ret;
	ret = ave_fw_wait(ave, AVE_CMD_PROCESS, seen, AVE_FRAME_TIMEOUT_US);
	if (ret)
		return ret;

	ret = ave_coded_bytes(ctx, &coded);
	if (ret)
		return ret;
	slice = ave_slice_hdr_bytes(ctx);
	ctx->frame++;
	ctx->total++;

	if (*keyframe)
		head = ctx->headers_len;
	if (head + slice + coded > dst_size) {
		dev_err(ave->dev, "frame %u: %u bytes, the buffer holds %zu\n", ctx->frame - 1,
			head + slice + coded, dst_size);
		return -ENOSPC;
	}
	if (head)
		memcpy(dst, ctx->headers, head);
	if (slice) {
		memcpy(dst + head, ctx->slice_hdr.cpu, slice);
		memset(ctx->slice_hdr.cpu, 0, AVE_SLICE_HDR_STRIDE);
	}
	memcpy(dst + head + slice, ctx->coded0.cpu, coded);
	*bytes = head + slice + coded;
	return 0;
}
