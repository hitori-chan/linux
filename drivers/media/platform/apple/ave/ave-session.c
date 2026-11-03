// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): what H.264 and HEVC sessions share
 *
 * The session's commands, its buffers, sized as the kext does
 * (AVE_CalcBufSizeOf*, rda AppleAVE2 0xfffffe00090d1cc0 on), and the frame's way
 * to the capture buffer.
 */

#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>

#include <media/videobuf2-dma-contig.h>

#include "ave.h"

/*
 * The two-core mode's buffers are at the same address on both cores, as macOS's
 * are, mapped by hand in this part of the DARTs' 4 GiB. The DMA API allocates
 * from the top of it.
 */
#define AVE_TWO_DVA		0x10010000000ULL
#define AVE_TWO_PROT		(IOMMU_READ | IOMMU_WRITE)
/* macOS's mode from here up; the firmware takes no more on one core */
#define AVE_TWO_MIN_MBS		(240 * 135)
#define AVE_ONE_MAX_MBS		(256 * 144)

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

static struct iommu_domain *ave_domain(struct apple_ave *ave)
{
	return iommu_get_domain_for_dev(ave->dev);
}

/* A buffer on both cores' DARTs at one address, or as the DMA API mapped it */
static int ave_share(struct apple_ave_ctx *ctx, struct ave_buf *buf, unsigned long attrs)
{
	struct device *dev = ctx->ave->dev;
	struct sg_table sgt;
	ssize_t mapped;
	int ret;

	buf->dva = buf->iova;
	if (!ctx->peer)
		return 0;

	ret = dma_get_sgtable_attrs(dev, &sgt, buf->cpu, buf->iova, buf->size, attrs);
	if (ret)
		return ret;
	buf->dva = ctx->dva_next;
	mapped = iommu_map_sgtable(ave_domain(ctx->ave), buf->dva, &sgt, AVE_TWO_PROT);
	if (mapped == buf->size) {
		mapped = iommu_map_sgtable(ave_domain(ctx->peer), buf->dva, &sgt, AVE_TWO_PROT);
		if (mapped != buf->size) {
			if (mapped > 0)
				iommu_unmap(ave_domain(ctx->peer), buf->dva, mapped);
			iommu_unmap(ave_domain(ctx->ave), buf->dva, buf->size);
			mapped = -ENOMEM;
		}
	} else if (mapped > 0) {
		iommu_unmap(ave_domain(ctx->ave), buf->dva, mapped);
		mapped = -ENOMEM;
	}
	sg_free_table(&sgt);
	if (mapped < 0) {
		buf->dva = 0;
		return mapped;
	}
	ctx->dva_next += ALIGN(buf->size, SZ_16K) + SZ_16K;
	return 0;
}

static void ave_unshare(struct apple_ave_ctx *ctx, struct ave_buf *buf)
{
	if (ctx->peer && buf->dva) {
		iommu_unmap(ave_domain(ctx->ave), buf->dva, buf->size);
		iommu_unmap(ave_domain(ctx->peer), buf->dva, buf->size);
	}
	buf->dva = 0;
}

static int ave_alloc_cpu(struct apple_ave_ctx *ctx, struct ave_buf *buf, size_t size)
{
	struct device *dev = ctx->ave->dev;
	int ret;

	buf->size = size;
	buf->cpu = dma_alloc_coherent(dev, size, &buf->iova, GFP_KERNEL);
	if (!buf->cpu)
		return -ENOMEM;
	ret = ave_share(ctx, buf, 0);
	if (ret) {
		dma_free_coherent(dev, size, buf->cpu, buf->iova);
		buf->cpu = NULL;
	}
	return ret;
}

static void ave_free_cpu(struct apple_ave_ctx *ctx, struct ave_buf *buf)
{
	if (!buf->cpu)
		return;
	ave_unshare(ctx, buf);
	dma_free_coherent(ctx->ave->dev, buf->size, buf->cpu, buf->iova);
	buf->cpu = NULL;
}

static int ave_alloc(struct apple_ave_ctx *ctx)
{
	struct device *dev = ctx->ave->dev;
	u32 w = ctx->mbw * 16, h = ctx->height16;
	u32 rec_y = ALIGN(w, 32) * ALIGN(h + 16, 32) * ctx->bit_depth / 8;
	u32 rec_c = rec_y / 2 + SZ_16K;
	u32 rec_a = ALIGN(w * h / 16, SZ_16K), rec_b = ALIGN(w * h / 64, SZ_16K);
	u32 pipes = ctx->codec->pipes * (ctx->peer ? 2 : 1);
	u32 client = ctx->ave->client_size ?: AVE_DEFAULT_CLIENT_SIZE;
	struct ave_sizes s = {};
	dma_addr_t base;
	size_t off = 0;
	int i, p, ret;

#define AVE_ALLOC(size) ({ size_t _o = off; off += ALIGN(size, SZ_16K) + SZ_16K; _o; })

	ctx->codec->sizes(ctx, &s);

	/* AVE_CalcBufSizeOfCodedData: never less than a 640x480 frame's */
	ctx->coded_size = ALIGN(max_t(u32, w * h * 3 / 2 * ctx->bit_depth / 8, 640 * 480 * 3 / 2),
				SZ_16K);
	ctx->coded_size = max_t(u32, ctx->coded_size,
				ALIGN(ctx->bitrate / ave_fps(ctx) / 4, SZ_16K));
	ctx->lowres_result_size = ALIGN(4 * ((((((w + 31) >> 5) * ((h + 63) >> 6))) << 7) + 0x400),
					SZ_16K);
	ctx->transcoded_size = s.transcoded ? ALIGN(ctx->coded_size / 2, SZ_16K) : 0;
	ctx->entropy_size = ALIGN(s.entropy, SZ_16K);

	/* a frame refers only to the one before it, so Start's rings hold two sets each */
	for (i = 0; i < AVE_USED_SLOTS; i++) {
		size_t set = AVE_ALLOC(rec_a + rec_b + rec_y + rec_c);

		ctx->recon[i].a = set;
		ctx->recon[i].b = set + rec_a;
		ctx->recon[i].y = set + rec_a + rec_b;
		ctx->recon[i].c = ctx->recon[i].y + rec_y;
		ctx->lowres_ref[i] = AVE_ALLOC(s.lowres_ref);
		ctx->lowres_result[i] = AVE_ALLOC(ctx->lowres_result_size);
		ctx->colocated[i] = AVE_ALLOC(s.colocated);
		ctx->colocated_peer[i] = AVE_ALLOC(ctx->peer ? s.colocated : 0);
		ctx->neighbor_info[i] = AVE_ALLOC(s.info);
		ctx->neighbor_pixel[i] = AVE_ALLOC(s.pixel);
		ctx->neighbor_data[i] = AVE_ALLOC(s.data);
		ctx->neighbor_fw[i] = AVE_ALLOC(s.fw);
	}
	for (i = 0; i < ARRAY_SIZE(ctx->lowres_result_ab); i++)
		ctx->lowres_result_ab[i] = AVE_ALLOC(ctx->lowres_result_size);
	ctx->transcoded[0] = AVE_ALLOC(ctx->transcoded_size);
	ctx->transcoded[1] = AVE_ALLOC(ctx->transcoded_size);
	ctx->extra[0] = AVE_ALLOC(s.extra);
	ctx->extra[1] = AVE_ALLOC(s.extra);
	for (i = 0; i < 2; i++)
		for (p = 0; p < pipes; p++)
			ctx->entropy[i][p] = AVE_ALLOC(ctx->entropy_size);
	ctx->client = AVE_ALLOC(client);
	ctx->client_peer = AVE_ALLOC(ctx->peer ? client : 0);
	ctx->misc = AVE_ALLOC(AVE_MISC_SIZE);
	ctx->params = AVE_ALLOC(AVE_PARAMS_SIZE);
#undef AVE_ALLOC

	ctx->mem.size = off;
	ctx->mem.cpu = dma_alloc_attrs(dev, off, &ctx->mem.iova, GFP_KERNEL,
				       DMA_ATTR_NO_KERNEL_MAPPING);
	if (!ctx->mem.cpu)
		return -ENOMEM;
	ret = ave_share(ctx, &ctx->mem, DMA_ATTR_NO_KERNEL_MAPPING);
	if (ret) {
		dma_free_attrs(dev, off, ctx->mem.cpu, ctx->mem.iova, DMA_ATTR_NO_KERNEL_MAPPING);
		ctx->mem.cpu = NULL;
		return ret;
	}
	ret = ave_alloc_cpu(ctx, &ctx->coded0, ctx->coded_size);
	if (!ret)
		ret = ave_alloc_cpu(ctx, &ctx->coded_hdr0, AVE_CODED_HDR_SIZE);
	if (!ret && ctx->codec->slice_hdr_size)
		ret = ave_alloc_cpu(ctx, &ctx->slice_hdr, ctx->codec->slice_hdr_size);
	if (ret) {
		ave_session_free(ctx);
		return ret;
	}

	base = ctx->mem.dva;
	for (i = 0; i < AVE_NUM_SLOTS; i++) {
		if (i < AVE_USED_SLOTS) {
			ctx->recon[i].a += base;
			ctx->recon[i].b += base;
			ctx->recon[i].y += base;
			ctx->recon[i].c += base;
			ctx->lowres_ref[i] += base;
			ctx->lowres_result[i] += base;
			ctx->colocated[i] += base;
			ctx->colocated_peer[i] += base;
			ctx->neighbor_info[i] += base;
			ctx->neighbor_pixel[i] += base;
			ctx->neighbor_data[i] += base;
			ctx->neighbor_fw[i] += base;
		} else {
			ctx->recon[i] = ctx->recon[i % AVE_USED_SLOTS];
			ctx->lowres_ref[i] = ctx->lowres_ref[i % AVE_USED_SLOTS];
			ctx->lowres_result[i] = ctx->lowres_result[i % AVE_USED_SLOTS];
			ctx->colocated[i] = ctx->colocated[i % AVE_USED_SLOTS];
		}
		ctx->coded[i] = ctx->coded0.dva;
		ctx->coded_hdr[i] = ctx->coded_hdr0.dva;
	}
	for (i = 0; i < ARRAY_SIZE(ctx->lowres_result_ab); i++)
		ctx->lowres_result_ab[i] += base;
	ctx->transcoded[0] += base;
	ctx->transcoded[1] += base;
	ctx->extra[0] += base;
	ctx->extra[1] += base;
	for (i = 0; i < 2; i++)
		for (p = 0; p < pipes; p++)
			ctx->entropy[i][p] += base;
	ctx->client += base;
	ctx->client_peer += base;
	ctx->misc += base;
	ctx->params += base;

	return 0;
}

void ave_session_free(struct apple_ave_ctx *ctx)
{
	struct device *dev = ctx->ave->dev;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ctx->src_dva); i++)
		ave_session_unmap_src(ctx, i);
	if (ctx->mem.cpu) {
		ave_unshare(ctx, &ctx->mem);
		dma_free_attrs(dev, ctx->mem.size, ctx->mem.cpu, ctx->mem.iova,
			       DMA_ATTR_NO_KERNEL_MAPPING);
		ctx->mem.cpu = NULL;
	}
	ave_free_cpu(ctx, &ctx->coded0);
	ave_free_cpu(ctx, &ctx->coded_hdr0);
	ave_free_cpu(ctx, &ctx->slice_hdr);
	ave_free_cpu(ctx, &ctx->iopipc);
	if (ctx->peer) {
		WRITE_ONCE(ctx->peer->owner, NULL);
		ctx->peer = NULL;
	}
}

/* The source on both cores' DARTs for the session, through its pages */
static int ave_map_src(struct apple_ave_ctx *ctx, struct vb2_buffer *vb, dma_addr_t *dva)
{
	unsigned int i = vb->index;
	size_t size = PAGE_ALIGN(vb2_plane_size(vb, 0));
	struct device *dev = ctx->ave->dev;
	dma_addr_t iova = vb2_dma_contig_plane_dma_addr(vb, 0);
	struct dma_buf_attachment *att = NULL;
	struct sg_table own, *sgt = &own;
	ssize_t mapped;
	int ret;

	if (ctx->src_dva[i]) {
		*dva = ctx->src_dva[i];
		return 0;
	}

	if (vb->memory == VB2_MEMORY_DMABUF) {
		att = dma_buf_attach(vb->planes[0].dbuf, dev);
		if (IS_ERR(att))
			return PTR_ERR(att);
		sgt = dma_buf_map_attachment_unlocked(att, DMA_TO_DEVICE);
		if (IS_ERR(sgt)) {
			dma_buf_detach(vb->planes[0].dbuf, att);
			return PTR_ERR(sgt);
		}
	} else {
		ret = dma_get_sgtable(dev, sgt, vb2_plane_vaddr(vb, 0), iova, size);
		if (ret)
			return ret;
	}

	mapped = iommu_map_sgtable(ave_domain(ctx->ave), ctx->dva_next, sgt, AVE_TWO_PROT);
	if (mapped == size) {
		mapped = iommu_map_sgtable(ave_domain(ctx->peer), ctx->dva_next, sgt, AVE_TWO_PROT);
		if (mapped != size) {
			if (mapped > 0)
				iommu_unmap(ave_domain(ctx->peer), ctx->dva_next, mapped);
			iommu_unmap(ave_domain(ctx->ave), ctx->dva_next, size);
			mapped = -ENOMEM;
		}
	} else if (mapped > 0) {
		iommu_unmap(ave_domain(ctx->ave), ctx->dva_next, mapped);
		mapped = -ENOMEM;
	}

	if (att) {
		dma_buf_unmap_attachment_unlocked(att, sgt, DMA_TO_DEVICE);
		dma_buf_detach(vb->planes[0].dbuf, att);
	} else {
		sg_free_table(sgt);
	}
	if (mapped < 0)
		return mapped;

	ctx->src_dva[i] = ctx->dva_next;
	ctx->src_size[i] = size;
	ctx->dva_next += ALIGN(size, SZ_16K) + SZ_16K;
	*dva = ctx->src_dva[i];
	return 0;
}

void ave_session_unmap_src(struct apple_ave_ctx *ctx, unsigned int index)
{
	if (!ctx->src_dva[index] || !ctx->peer)
		return;
	iommu_unmap(ave_domain(ctx->ave), ctx->src_dva[index], ctx->src_size[index]);
	iommu_unmap(ave_domain(ctx->peer), ctx->src_dva[index], ctx->src_size[index]);
	ctx->src_dva[index] = 0;
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
void ave_cmd_header(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b, u16 id, u32 slot,
		    u32 x20, u32 x28, u32 x30)
{
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

static int ave_small_command(struct apple_ave_ctx *ctx, struct apple_ave *ave, u16 id, u32 x20,
			     u32 x28)
{
	size_t off;
	u8 *b = ave_ipc_alloc(ave, 0xf0, &off);

	if (!b)
		return -ENOMEM;
	ave_cmd_header(ctx, ave, b, id, id, x20, x28, 0x170c0);
	return ave_fw_command(ave, off, AVE_CMD_SMALL_SIZE, id);
}

/*
 * The cores by their firmware's role, whichever node the stream came through:
 * the first core's commands go first, the second's Start before it, and a
 * firmware's +0x18a58 or +0x3aa0c says which it is.
 */
static void ave_cores(struct apple_ave_ctx *ctx, struct apple_ave *cores[2])
{
	bool swap = ctx->peer && ctx->ave->instance;

	cores[0] = swap ? ctx->peer : ctx->ave;
	cores[1] = swap ? ctx->ave : ctx->peer;
}

/*
 * The two-core mode's first frame: macOS's Complete follows at once on each core,
 * and the second core's reply to the frame waits for it.
 */
static int ave_two_flush(struct apple_ave_ctx *ctx)
{
	struct apple_ave *cores[2];
	u32 seen[2];
	int i, ret;

	ave_cores(ctx, cores);
	for (i = 0; i < 2; i++) {
		size_t off;
		u8 *b = ave_ipc_alloc(cores[i], 0xf0, &off);

		if (!b)
			return -ENOMEM;
		seen[i] = cores[i]->t2h_seen[AVE_CMD_COMPLETE];
		ave_cmd_header(ctx, cores[i], b, AVE_CMD_COMPLETE, AVE_CMD_COMPLETE, 0,
			       ctx->codec->x28_session, 0x170c0);
		ret = ave_fw_send(cores[i], off, AVE_CMD_SMALL_SIZE);
		if (ret)
			return ret;
	}
	for (i = 0; i < 2; i++) {
		ret = ave_fw_wait(cores[i], AVE_CMD_COMPLETE, seen[i], AVE_FRAME_TIMEOUT_US);
		if (ret)
			return ret;
	}
	return 0;
}

/* AVE_CHM_SetFwBuf: the buffers in Start, at the same place for both codecs */
void ave_fill_start_buffers(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b)
{
	bool second = ctx->peer && ave->instance;
	u32 rings = ctx->peer ? AVE_TWO_RINGS : AVE_NUM_SLOTS;
	u32 pipes = ctx->codec->pipes * (ctx->peer ? 2 : 1);
	u32 i, p;

	/* the session's own command words on the two-core mode's first core */
	ave_cmd_header(ctx, ave, b, AVE_CMD_START, AVE_CMD_START, 0xc8,
		       ctx->peer && !second ? ctx->codec->x28_frame : ctx->codec->x28_session,
		       0x170c0);

	ave_put_dva(b, 0x48, second ? ctx->client_peer : ctx->client);
	put_unaligned_le32(ave->client_size ?: AVE_DEFAULT_CLIENT_SIZE, b + 0x50);
	ave_put_dva(b, 0x58, ctx->misc);
	put_unaligned_le32(AVE_MISC_SIZE, b + 0x60);
	put_unaligned_le32(ctx->mbw * 16, b + 0x68);
	put_unaligned_le32(ctx->height16, b + 0x6c);

	if (ctx->peer) {
		for (i = 0; i < AVE_USED_SLOTS; i++) {
			ave_put_dva(b, 0x98 + 0x10 * i, ctx->recon[i].y);
			ave_put_dva(b, 0xa0 + 0x10 * i, ctx->recon[i].a);
			ave_put_dva(b, 0x2b8 + 8 * i, ctx->lowres_ref[i]);
			ave_put_dva(b, 0x16f60 + 8 * i,
				    second ? ctx->colocated_peer[i] : ctx->colocated[i]);
		}
		for (i = 0; i < ARRAY_SIZE(ctx->lowres_result_ab); i++)
			ave_put_dva(b, 0x3c8 + 8 * i, ctx->lowres_result_ab[i]);
	} else {
		for (i = 0; i < AVE_NUM_SLOTS; i++) {
			ave_put_dva(b, 0x98 + 0x10 * i, ctx->recon[i].y);
			ave_put_dva(b, 0xa0 + 0x10 * i, ctx->recon[i].a);
			ave_put_dva(b, 0x2b8 + 8 * i, ctx->lowres_ref[i]);
			ave_put_dva(b, 0x16f60 + 8 * i, ctx->colocated[i]);
		}
		ave_put_dva(b, 0x3c8, ctx->lowres_result_ab[0]);
		ave_put_dva(b, 0x420, ctx->lowres_result_ab[1]);
		put_unaligned_le32(ctx->lowres_result_size, b + 0x470);
	}
	put_unaligned_le32(ctx->lowres_result_size, b + 0x418);

	for (i = 0; i < rings; i++) {
		ave_put_dva(b, 0x478 + 8 * i, ctx->coded[i]);
		put_unaligned_le32(ctx->coded_size, b + 0x568 + 4 * i);
		ave_put_dva(b, 0x5f8 + 8 * i, ctx->coded_hdr[i]);
		put_unaligned_le32(AVE_CODED_HDR_SIZE, b + 0x6e8 + 4 * i);
	}

	for (i = 0; i < (ctx->peer ? 2 : 1); i++) {
		ave_put_dva(b, 0x17080 + 8 * i, ctx->neighbor_info[i]);
		ave_put_dva(b, 0x170a0 + 8 * i, ctx->neighbor_pixel[i]);
		ave_put_dva(b, 0x170c0 + 8 * i, ctx->neighbor_data[i]);
		ave_put_dva(b, 0x17a40 + 8 * i, ctx->neighbor_fw[i]);
	}
	for (p = 0; p < pipes; p++) {
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

/* Open and Start on a core, each answered on IO_T2H */
static int ave_core_start(struct apple_ave_ctx *ctx, struct apple_ave *ave)
{
	u32 i = ave->instance;
	size_t start_off;
	u8 *start;
	int ret;

	ret = ave_small_command(ctx, ave, AVE_CMD_OPEN, 0xc8, 0x78);
	if (ret)
		return ret;

	start = ave_ipc_alloc(ave, ctx->codec->start_size, &start_off);
	ctx->process[i] = ave_ipc_alloc(ave, ctx->codec->process_size, &ctx->process_off[i]);
	if (!start || !ctx->process[i])
		return -ENOMEM;
	ctx->codec->fill_start(ctx, ave, start);
	return ave_fw_command(ave, start_off, ctx->codec->start_size, AVE_CMD_START);
}

/* The other core, for a frame too large for one or as macOS would ask for it */
static int ave_claim_peer(struct apple_ave_ctx *ctx)
{
	struct apple_ave *peer = ave_core(!ctx->ave->instance);
	u32 mbs = ctx->mbw * ctx->mbh;

	ctx->peer = NULL;
	if (mbs < AVE_TWO_MIN_MBS)
		return 0;
	if (peer && !cmpxchg(&peer->owner, NULL, ctx)) {
		ctx->peer = peer;
		return 0;
	}
	return mbs > AVE_ONE_MAX_MBS ? -EBUSY : 0;
}

/* The session up to its first frame: on the second core first, as macOS */
int ave_session_start(struct apple_ave_ctx *ctx)
{
	struct apple_ave *cores[2];
	int ret;

	ctx->codec = ctx->cap_fmt.pixelformat == V4L2_PIX_FMT_HEVC ? &ave_codec_hevc :
								     &ave_codec_h264;
	ctx->mbw = DIV_ROUND_UP(ctx->out_fmt.width, 16);
	ctx->mbh = DIV_ROUND_UP(ctx->out_fmt.height, 16);
	ctx->height16 = ctx->mbh * 16;
	ctx->bit_depth = ctx->out_fmt.pixelformat == V4L2_PIX_FMT_P010 ? 10 : 8;

	ret = ave_claim_peer(ctx);
	if (ret)
		return ret;
	ctx->codec->layout(ctx);
	ave_cores(ctx, cores);

	if (ctx->peer) {
		/* One IOPIPC surface for both firmwares, at one address, as macOS */
		ctx->dva_next = AVE_TWO_DVA;
		ret = ave_alloc_cpu(ctx, &ctx->iopipc, AVE_IOPIPC_SIZE);
		if (ret)
			goto err_peer;
		ret = ave_fw_boot(cores[1], cores[0], ctx->iopipc.dva);
		if (ret)
			goto err_peer;
	}
	ret = ave_fw_boot(cores[0], cores[1], ctx->iopipc.dva);
	if (ret)
		goto err_peer_off;

	ret = ave_alloc(ctx);
	if (ret)
		goto err_off;

	if (ctx->peer) {
		ret = ave_core_start(ctx, cores[1]);
		if (ret)
			goto err_free;
	}
	ret = ave_core_start(ctx, cores[0]);
	if (ret)
		goto err_free;

	ctx->frame = 0;
	ctx->total = 0;
	ctx->idr_id = 0;
	ctx->running = true;
	return 0;

err_free:
	ave_fw_shutdown(cores[0], false);
	if (cores[1])
		ave_fw_shutdown(cores[1], false);
	ave_session_free(ctx);
	return ret;
err_off:
	ave_fw_shutdown(cores[0], false);
err_peer_off:
	if (cores[1])
		ave_fw_shutdown(cores[1], false);
err_peer:
	ave_free_cpu(ctx, &ctx->iopipc);
	if (ctx->peer) {
		WRITE_ONCE(ctx->peer->owner, NULL);
		ctx->peer = NULL;
	}
	return ret;
}

static void ave_core_stop(struct apple_ave_ctx *ctx, struct apple_ave *ave)
{
	int ret;

	ret = ave_small_command(ctx, ave, AVE_CMD_COMPLETE, 0, ctx->codec->x28_frame);
	if (!ret)
		ret = ave_small_command(ctx, ave, AVE_CMD_STOP, 0xc8, ctx->codec->x28_frame);
	if (!ret)
		ret = ave_small_command(ctx, ave, AVE_CMD_CLOSE, 0xc8, ctx->codec->x28_session);
	ave_fw_shutdown(ave, !ret);
}

/* The stream's end: Complete, Stop and Close, each answered, then the firmware's halt */
void ave_session_stop(struct apple_ave_ctx *ctx)
{
	struct apple_ave *cores[2];

	ave_cores(ctx, cores);
	ave_core_stop(ctx, cores[0]);
	if (cores[1])
		ave_core_stop(ctx, cores[1]);
	ave_session_free(ctx);
	ctx->running = false;
}

/* A firmware that did not answer is powered off running: the next frame boots it again */
void ave_session_abort(struct apple_ave_ctx *ctx)
{
	ave_fw_shutdown(ctx->ave, false);
	if (ctx->peer)
		ave_fw_shutdown(ctx->peer, false);
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

int ave_session_encode(struct apple_ave_ctx *ctx, struct vb2_buffer *src, u8 *dst, size_t dst_size,
		       size_t *bytes, bool *keyframe)
{
	struct apple_ave *cores[2];
	u32 seen[2] = {}, coded, head = 0, slice;
	int i, n = ctx->peer ? 2 : 1, ret;
	dma_addr_t src_dva;

	ave_cores(ctx, cores);

	/* an IDR restarts the numbering; consecutive IDRs' idr_pic_id must differ */
	if (ctx->frame && (xchg(&ctx->force_idr, false) ||
			   (ctx->gop_size && ctx->frame >= ctx->gop_size))) {
		ctx->frame = 0;
		ctx->idr_id ^= 1;
	}
	*keyframe = !ctx->frame;

	if (ctx->peer) {
		ret = ave_map_src(ctx, src, &src_dva);
		if (ret)
			return ret;
	} else {
		src_dva = vb2_dma_contig_plane_dma_addr(src, 0);
	}

	for (i = 0; i < n; i++) {
		u32 c = cores[i]->instance;

		seen[i] = cores[i]->t2h_seen[AVE_CMD_PROCESS];
		ctx->codec->fill_process(ctx, cores[i], ctx->process[c], src_dva);
		ret = ave_fw_send(cores[i], ctx->process_off[c], ctx->codec->process_size);
		if (ret)
			return ret;
	}
	if (ctx->peer && !ctx->total) {
		ret = ave_two_flush(ctx);
		if (ret)
			return ret;
	}
	for (i = 0; i < n; i++) {
		ret = ave_fw_wait(cores[i], AVE_CMD_PROCESS, seen[i], AVE_FRAME_TIMEOUT_US);
		if (ret)
			return ret;
	}

	ret = ave_coded_bytes(ctx, &coded);
	if (ret)
		return ret;
	slice = ave_slice_hdr_bytes(ctx);
	ctx->frame++;
	ctx->total++;

	if (*keyframe)
		head = ctx->headers_len;
	if (head + slice + coded > dst_size) {
		dev_err(ctx->ave->dev, "frame %u: %u bytes, the buffer holds %zu\n", ctx->frame - 1,
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
