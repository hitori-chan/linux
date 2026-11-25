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
#include <linux/pm_domain.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>

#include <media/videobuf2-dma-contig.h>

#include "ave.h"

/*
 * The two-core mode's buffers are at the same address on both cores, as macOS's
 * are, mapped by hand in this window of the DARTs' 4 GiB. The DMA API maps the
 * same buffers, top down and each aligned to its size's power of two, and
 * nothing kept it out of the window: at 8K Main 10 it gave a session's coded
 * buffer an address the session's block had taken (dart_init_pte's -EEXIST).
 * Both cores' DT nodes reserve the window (t6031-base.dtsi, the
 * iommu-addresses of ave0-two-window and ave1-two-window); without the
 * reservation the driver keeps to one core.
 */
#define AVE_TWO_DVA		0x10010000000ULL
#define AVE_TWO_SIZE		0x70000000ULL
#define AVE_TWO_PROT		(IOMMU_READ | IOMMU_WRITE)
/*
 * macOS's mode from here up; the firmware takes no more on one core. 27.2's
 * kext the same: AVE_Work_Enc_CalcEUNumInParallel (0xfffffe0008f08f68) gives
 * one core from 0x7e90 macroblocks, and AVE_Work_Enc_DecideSchedMode
 * (0xfffffe0008f094a0) then both on each frame (CalcEUNumInSequential,
 * AVE_Enc_CalcSVEMax's 2 from 352x208).
 */
#define AVE_TWO_MIN_MBS		(240 * 135)
#define AVE_ONE_MAX_MBS		(256 * 144)

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

/* Both cores' DT nodes reserve the window from the DMA API (iommu-addresses) */
static bool ave_two_window_reserved(struct device *dev)
{
	struct iommu_resv_region *r;
	LIST_HEAD(regions);
	bool ok = false;

	iommu_get_resv_regions(dev, &regions);
	list_for_each_entry(r, &regions, list)
		ok |= r->type == IOMMU_RESV_RESERVED && r->start <= AVE_TWO_DVA &&
		      r->start + r->length >= AVE_TWO_DVA + AVE_TWO_SIZE;
	iommu_put_resv_regions(dev, &regions);
	return ok;
}

/* Room in the window for size bytes at dva */
static bool ave_two_fits(struct apple_ave_ctx *ctx, dma_addr_t dva, size_t size)
{
	if (dva >= AVE_TWO_DVA && ALIGN(size, SZ_16K) <= AVE_TWO_DVA + AVE_TWO_SIZE - dva)
		return true;
	dev_err_ratelimited(ctx->ave->dev, "two cores: %zu bytes at %pad, past the window\n",
			    size, &dva);
	return false;
}

/* A buffer's pages on both cores' DARTs at dva */
static int ave_share_at(struct apple_ave_ctx *ctx, struct ave_buf *buf, dma_addr_t dva,
			unsigned long attrs)
{
	struct device *dev = ctx->ave->dev;
	struct sg_table sgt;
	ssize_t mapped;
	int ret;

	buf->dva = 0;
	if (!ave_two_fits(ctx, dva, buf->size))
		return -ENOSPC;
	ret = dma_get_sgtable_attrs(dev, &sgt, buf->cpu, buf->iova, buf->size, attrs);
	if (ret)
		return ret;
	buf->dva = dva;
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
	return 0;
}

/* A buffer on both cores' DARTs at one address, or as the DMA API mapped it */
static int ave_share(struct apple_ave_ctx *ctx, struct ave_buf *buf, unsigned long attrs)
{
	int ret;

	buf->dva = buf->iova;
	if (!ctx->peer)
		return 0;
	ret = ave_share_at(ctx, buf, ctx->dva_next, attrs);
	if (!ret)
		ctx->dva_next += ALIGN(buf->size, SZ_16K) + SZ_16K;
	return ret;
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

/*
 * The session's block, which the CPU never touches: one DMA API buffer on one
 * core; on two, pieces of it mapped one after another at the shared address,
 * so that the DMA API, which aligns each allocation to its size's power of
 * two, needs no free slot the whole block's size (752 MiB at 8K Main 10)
 */
static int ave_alloc_mem(struct apple_ave_ctx *ctx, size_t size)
{
	struct device *dev = ctx->ave->dev;
	dma_addr_t dva = ctx->dva_next;
	size_t off;
	int ret;

	ctx->mem.size = size;
	if (!ctx->peer) {
		ctx->mem.cpu = dma_alloc_attrs(dev, size, &ctx->mem.iova, GFP_KERNEL,
					       DMA_ATTR_NO_KERNEL_MAPPING);
		if (!ctx->mem.cpu)
			return -ENOMEM;
		ctx->mem.dva = ctx->mem.iova;
		return 0;
	}

	if (size > (size_t)AVE_MEM_PARTS * AVE_MEM_PART || !ave_two_fits(ctx, dva, size))
		return -ENOSPC;
	for (off = 0; off < size; off += AVE_MEM_PART) {
		struct ave_buf *part = &ctx->mem_part[ctx->mem_parts];

		part->size = min_t(size_t, size - off, AVE_MEM_PART);
		part->cpu = dma_alloc_attrs(dev, part->size, &part->iova, GFP_KERNEL,
					    DMA_ATTR_NO_KERNEL_MAPPING);
		if (!part->cpu)
			return -ENOMEM;
		ctx->mem_parts++;
		ret = ave_share_at(ctx, part, dva + off, DMA_ATTR_NO_KERNEL_MAPPING);
		if (ret)
			return ret;
	}
	ctx->mem.dva = dva;
	ctx->dva_next += ALIGN(size, SZ_16K) + SZ_16K;
	return 0;
}

static void ave_free_mem(struct apple_ave_ctx *ctx)
{
	struct device *dev = ctx->ave->dev;

	while (ctx->mem_parts) {
		struct ave_buf *part = &ctx->mem_part[--ctx->mem_parts];

		ave_unshare(ctx, part);
		dma_free_attrs(dev, part->size, part->cpu, part->iova, DMA_ATTR_NO_KERNEL_MAPPING);
		part->cpu = NULL;
	}
	if (ctx->mem.cpu)
		dma_free_attrs(dev, ctx->mem.size, ctx->mem.cpu, ctx->mem.iova,
			       DMA_ATTR_NO_KERNEL_MAPPING);
	ctx->mem.cpu = NULL;
	ctx->mem.dva = 0;
}

static int ave_alloc(struct apple_ave_ctx *ctx)
{
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
	s.rec_y = rec_y;
	s.rec_c = rec_c;
	s.rec_a = rec_a;
	s.rec_b = rec_b;
	ctx->sizes = s;

	/* AVE_CalcBufSizeOfCodedData: never less than a 640x480 frame's */
	ctx->coded_size = ALIGN(max_t(u32, w * h * 3 / 2 * ctx->bit_depth / 8, 640 * 480 * 3 / 2),
				SZ_16K);
	ctx->coded_size = max_t(u32, ctx->coded_size,
				ALIGN(ctx->bitrate / ave_fps(ctx) / 4, SZ_16K));
	ctx->lowres_result_size = ALIGN(4 * ((((((w + 31) >> 5) * ((h + 63) >> 6))) << 7) + 0x400),
					SZ_16K);
	ctx->transcoded_size = s.transcoded ? ALIGN(ctx->coded_size / 2, SZ_16K) : 0;
	/* the kext's entropy layout: each pipe's data, then its header (ave-9013.c) */
	ctx->entropy_size = ALIGN(s.entropy + (ctx->entropy_sets ? ave9_entropy_hdr_size(ctx) : 0),
				  SZ_16K);

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

	ret = ave_alloc_mem(ctx, off);
	if (ret) {
		ave_free_mem(ctx);
		return ret;
	}
	for (i = 0, ret = 0; i < ctx->out_sets && !ret; i++) {
		struct ave_out *o = &ctx->out[i];

		ret = ave_alloc_cpu(ctx, &o->coded, ctx->coded_size);
		if (!ret)
			ret = ave_alloc_cpu(ctx, &o->hdr, AVE_CODED_HDR_SIZE);
		if (!ret && ctx->codec->slice_hdr_size)
			ret = ave_alloc_cpu(ctx, &o->slice_hdr, ctx->codec->slice_hdr_size);
		if (!ret && ctx->codec->slice_bits_size)
			ret = ave_alloc_cpu(ctx, &o->slice_bits, ctx->codec->slice_bits_size);
	}
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
		/*
		 * Start's rings list every output set, as the kext's list its
		 * coded buffers; each Process names its own (P+0x4ae0, +0x4af0)
		 * and its slot is 0x13 + the entry, set s entry 2 + s
		 */
		ctx->coded[i] = ctx->out[(i + 2 * ctx->out_sets - 2) % ctx->out_sets].coded.dva;
		ctx->coded_hdr[i] = ctx->out[(i + 2 * ctx->out_sets - 2) % ctx->out_sets].hdr.dva;
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
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ctx->src_dva); i++)
		ave_session_unmap_src(ctx, i);
	ave_free_mem(ctx);
	for (i = 0; i < ARRAY_SIZE(ctx->out); i++) {
		ave_free_cpu(ctx, &ctx->out[i].coded);
		ave_free_cpu(ctx, &ctx->out[i].hdr);
		ave_free_cpu(ctx, &ctx->out[i].slice_hdr);
		ave_free_cpu(ctx, &ctx->out[i].slice_bits);
		ctx->out[i].process = NULL;
	}
	ctx->fl_n = 0;
	ctx->cur = NULL;
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
	if (!ave_two_fits(ctx, ctx->dva_next, size))
		return -ENOSPC;

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
		    u32 x20, u32 x30)
{
	ave->seq += 100;
	/*
	 * AppleAVE2 27.2 MakeFwCmd_* (Start_AVC 0xfffffe0008dab0b4) and
	 * SendFwCmd (0xfffffe0008e51ca8): the client id is 64-bit. FW27's
	 * CmdProcessor (0xb5ab0) asserts the codec 1 or 2 and the engine 1,
	 * 2, 3, 4 or 6.
	 */
	put_unaligned_le16(id, b);
	put_unaligned_le64(ave->seq, b + 0x08);
	put_unaligned_le64(1, b + 0x10);		/* the client */
	put_unaligned_le32(1, b + 0x18);		/* the encoder engine */
	put_unaligned_le32(ctx->codec->id, b + 0x1c);	/* 1 H.264, 2 HEVC */
	put_unaligned_le32(slot, b + 0x20);
	put_unaligned_le32(x20, b + 0x24);		/* the priority (FW27 SetClientPriority) */
	put_unaligned_le32(ctx->codec->session_flags, b + 0x28);	/* settings+0x2c */
	/*
	 * The power domains that were off since the last command, which
	 * the firmware restores: SendFwCmd writes AVE_DPM::RetrieveHw's
	 * (0xfffffe0008ecca30) here, the session's power-down set (the
	 * DPM map of gsc_sAVE_DevCap_SEntry_{AVC,HEVC}_6034: 0xb0, and
	 * HEVC's 0x1d0 at its search range; bits as
	 * gsc_piaAVE_PMGR_PDName, 4 DMA/FE, 5 Pipe4/HME, 6 Pipe5/MDINTRA,
	 * 7 ME0, 8 ME1) less the domains still on, then TuneUpHw powers
	 * them up for the command. The six venc domains stay on through
	 * a session here: none.
	 */
	put_unaligned_le32(0, b + 0x2c);
	/* VideoToolbox's 16 bytes: the timeout, scaled by 8/10, and the time */
	put_unaligned_le64(x30, b + 0x30);
	put_unaligned_le64(ave9_cmd_time(ave), b + 0x38);
}

static int ave_small_command(struct apple_ave_ctx *ctx, struct apple_ave *ave, u16 id, u32 x20)
{
	size_t off;
	u8 *b = ave_ipc_alloc(ave, 0xf0, &off);

	if (!b)
		return -ENOMEM;
	ave_cmd_header(ctx, ave, b, id, id, x20, AVE9_START_TIMEOUT);
	return ave_fw_command(ave, off, AVE_CMD_SMALL_SIZE, id);
}

/*
 * The cores by their firmware's role, whichever node the stream came through:
 * the first core's commands go first, the second's Start before it, and
 * Start's core map says which it is (ave9_put_eu).
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
			       AVE9_START_TIMEOUT);
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

/* Open and Start on a core, each answered on IO_T2H */
static int ave_core_start(struct apple_ave_ctx *ctx, struct apple_ave *ave)
{
	u32 i = ave->instance, k;
	size_t start_off;
	u8 *start;
	int ret;

	ret = ave_small_command(ctx, ave, AVE_CMD_OPEN, 0xc8);
	if (ret)
		return ret;

	start = ave_ipc_alloc(ave, ctx->codec->start_size, &start_off);
	if (!start)
		return -ENOMEM;
	if (ctx->peer) {
		ctx->process[i] = ave_ipc_alloc(ave, ctx->codec->process_size,
						&ctx->process_off[i]);
		if (!ctx->process[i])
			return -ENOMEM;
	}
	/* one core: a Process command a set, each frame in flight its own */
	for (k = 0; !ctx->peer && k < ctx->out_sets; k++) {
		struct ave_out *o = &ctx->out[k];

		o->process = ave_ipc_alloc(ave, ctx->codec->process_size, &o->process_off);
		if (!o->process)
			return -ENOMEM;
	}
	ctx->codec->fill_start(ctx, ave, start);
	return ave_fw_command(ave, start_off, ctx->codec->start_size, AVE_CMD_START);
}

/*
 * The other core, for a frame too large for one or as macOS would ask for it;
 * both run the firmware iBoot preloaded, so the same one
 */
static int ave_claim_peer(struct apple_ave_ctx *ctx)
{
	struct apple_ave *peer = ave_core(!ctx->ave->instance);
	u32 mbs = ctx->mbw * ctx->mbh;

	ctx->peer = NULL;
	if (mbs < AVE_TWO_MIN_MBS)
		return 0;
	if (peer && peer->fw == ctx->ave->fw &&
	    !(ave_two_window_reserved(ctx->ave->dev) && ave_two_window_reserved(peer->dev))) {
		dev_warn_once(ctx->ave->dev,
			      "two cores: the DT reserves no window at %#llx (ave0-two-window): one core\n",
			      AVE_TWO_DVA);
		return mbs > AVE_ONE_MAX_MBS ? -EOPNOTSUPP : 0;
	}
	if (peer && peer->fw == ctx->ave->fw && !cmpxchg(&peer->owner, NULL, ctx)) {
		ctx->peer = peer;
		return 0;
	}
	return mbs > AVE_ONE_MAX_MBS ? -EBUSY : 0;
}

/* The session up to its first frame: on the second core first, as macOS */
int ave_session_start(struct apple_ave_ctx *ctx)
{
	struct apple_ave *cores[2];
	bool hevc = ctx->cap_fmt.pixelformat == V4L2_PIX_FMT_HEVC;
	int ret;

	ctx->codec = hevc ? &ave_codec_hevc_9013 : &ave_codec_h264_9013;
	ctx->mbw = DIV_ROUND_UP(ctx->out_fmt.width, 16);
	ctx->mbh = DIV_ROUND_UP(ctx->out_fmt.height, 16);
	ctx->height16 = ctx->mbh * 16;
	ctx->bit_depth = ctx->out_fmt.pixelformat == V4L2_PIX_FMT_P010 ? 10 : 8;

	ret = ave_claim_peer(ctx);
	if (ret)
		return ret;
	ctx->codec->layout(ctx);
	ave_cores(ctx, cores);

	/*
	 * One core keeps frames in flight (AVE9_INFLIGHT), each with its own
	 * output and, as the kext lays them out, the entropy buffers of two
	 * sets in turn: one frame's transcode reads its set while the next
	 * frame's pipe writes the other. Two cores, one.
	 */
	ctx->inflight = ctx->peer ? 1 : AVE9_INFLIGHT;
	ctx->entropy_sets = !ctx->peer;
	ctx->out_sets = ctx->inflight > 1 ? ctx->inflight + 1 : 1;
	ctx->fl_first = 0;
	ctx->fl_n = 0;

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

	ctx->p_next[cores[0]->instance] = cores[0]->t2h_seen[AVE_CMD_PROCESS];
	if (cores[1])
		ctx->p_next[cores[1]->instance] = cores[1]->t2h_seen[AVE_CMD_PROCESS];
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

	ret = ave_small_command(ctx, ave, AVE_CMD_COMPLETE, 0);
	if (!ret)
		ret = ave_small_command(ctx, ave, AVE_CMD_STOP, 0xc8);
	if (!ret)
		ret = ave_small_command(ctx, ave, AVE_CMD_CLOSE, 0xc8);
	ave_fw_shutdown(ave, !ret);
}

/*
 * The cores' votes for the SoC's levels, through their sys domain's
 * performance state (the PMP report entry's: 1 SOC 1, 2 SOC 2, 3 SOC 2 and
 * the fabric's 2), as AVE_DPM_DecideIOPPower and DecideFABPower (AppleAVE2)
 * choose them a frame: with frames waiting, the top, as macOS runs a session
 * with work pending (4K at 62 frames/s against 32.7 with none); else one
 * state down a frame, to SOC 1 above 1,795,200 macroblocks a second a core
 * (AVE_DPM's floor for a realtime session, about 4K55), or none. macOS takes
 * the rate from the frames' arrivals, this from S_PARM's.
 */
#define AVE_PSTATE_TOP		3
#define AVE_PSTATE_FAST_MBS	1795200

static void ave_core_vote(struct apple_ave *ave, unsigned int state)
{
	if (!ave->pd_list || ave->pstate == state)
		return;
	if (!dev_pm_genpd_set_performance_state(ave->pd_list->pd_devs[0], state))
		ave->pstate = state;
}

void ave_session_vote(struct apple_ave_ctx *ctx, bool waiting)
{
	struct apple_ave *cores[2];
	u64 rate = (u64)ctx->mbw * ctx->mbh * ave_fps(ctx);
	unsigned int state, floor;

	ave_cores(ctx, cores);
	/* AVE_Client_CalcMBNumOfCHM: 1.1 / n of it a core */
	if (cores[1])
		rate = rate * 11 / 20;
	floor = rate > AVE_PSTATE_FAST_MBS ? 1 : 0;
	state = waiting ? AVE_PSTATE_TOP : max(floor, cores[0]->pstate ? cores[0]->pstate - 1 : 0);
	ave_core_vote(cores[0], state);
	if (cores[1])
		ave_core_vote(cores[1], state);
}

/* No vote kept past the session: genpd would restore it at the next one's resume */
static void ave_session_unvote(struct apple_ave_ctx *ctx)
{
	ctx->enc_ns = 0;
	ave_core_vote(ctx->ave, 0);
	if (ctx->peer)
		ave_core_vote(ctx->peer, 0);
}

/* The stream's end: Complete, Stop and Close, each answered, then the firmware's halt */
void ave_session_stop(struct apple_ave_ctx *ctx)
{
	struct apple_ave *cores[2];

	ave_session_unvote(ctx);
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
	ave_session_unvote(ctx);
	ave_fw_shutdown(ctx->ave, false);
	if (ctx->peer)
		ave_fw_shutdown(ctx->peer, false);
	ave_session_free(ctx);
	ctx->running = false;
}

/*
 * HEVC's slice header, which the firmware wrote apart from the coded data: its
 * start code and NAL header to the entry points' last byte, which is not zero.
 */
static u32 ave_slice_hdr_bytes(struct apple_ave_ctx *ctx)
{
	const u8 *h = ctx->cur->out->slice_hdr.cpu;
	u32 n = AVE_SLICE_HDR_STRIDE;

	if (!h)
		return 0;
	while (n && !h[n - 1])
		n--;
	return n;
}

/* Both firmwares' logs when a two-core frame fails, the one that did not stop it too */
static int ave_two_failed(struct apple_ave_ctx *ctx, int ret)
{
	if (ret && ctx->peer) {
		ave9_fwlog_print(ctx->ave);
		ave9_fwlog_print(ctx->peer);
	}
	return ret;
}

/*
 * A frame to the firmware, its Process command on each core: the session's
 * inflight at once (ave_session_finish takes the oldest back). The frame's
 * numbers move on here, its Process is filled in order.
 */
int ave_session_send(struct apple_ave_ctx *ctx, struct vb2_buffer *src)
{
	struct apple_ave *cores[2];
	struct ave_flight *f;
	int i, n = ctx->peer ? 2 : 1, ret;
	dma_addr_t src_dva;

	if (ctx->fl_n >= ctx->inflight)
		return -EBUSY;
	ave_cores(ctx, cores);

	/* an IDR restarts the numbering; consecutive IDRs' idr_pic_id must differ */
	if (ctx->frame && (xchg(&ctx->force_idr, false) ||
			   (ctx->gop_size && ctx->frame >= ctx->gop_size))) {
		ctx->frame = 0;
		ctx->idr_id ^= 1;
	}

	if (ctx->peer) {
		ret = ave_map_src(ctx, src, &src_dva);
		if (ret)
			return ret;
	} else {
		src_dva = vb2_dma_contig_plane_dma_addr(src, 0);
	}

	f = &ctx->flight[(ctx->fl_first + ctx->fl_n) % AVE_INFLIGHT_MAX];
	f->set = ctx->total % ctx->out_sets;
	f->out = &ctx->out[f->set];
	f->total = ctx->total;
	f->frame = ctx->frame;
	f->keyframe = !ctx->frame;
	f->sent = ktime_get();
	ctx->cur = f;
	for (i = 0; i < n; i++) {
		u32 c = cores[i]->instance;
		u8 *b = ctx->peer ? ctx->process[c] : f->out->process;
		size_t off = ctx->peer ? ctx->process_off[c] : f->out->process_off;

		ctx->codec->fill_process(ctx, cores[i], b, src_dva);
		ret = ave_fw_send(cores[i], off, ctx->codec->process_size);
		if (ret)
			return ret;
		f->seen[i] = ctx->p_next[c]++;
	}
	ctx->fl_n++;
	ctx->frame++;
	ctx->total++;
	if (ctx->peer && !f->total) {
		ret = ave_two_flush(ctx);
		if (ret)
			return ave_two_failed(ctx, ret);
	}
	return 0;
}

/* The oldest frame in flight: its reply on each core, then its bytes to dst */
int ave_session_finish(struct apple_ave_ctx *ctx, u8 *dst, size_t dst_size, size_t *bytes,
		       bool *keyframe)
{
	struct apple_ave *cores[2];
	struct ave_flight *f;
	u32 coded, head = 0, slice, start = 0;
	int i, n = ctx->peer ? 2 : 1, ret;
	bool slices;

	if (!ctx->fl_n)
		return -EPROTO;
	ave_cores(ctx, cores);
	f = &ctx->flight[ctx->fl_first];
	ctx->fl_first = (ctx->fl_first + 1) % AVE_INFLIGHT_MAX;
	ctx->fl_n--;
	ctx->cur = f;
	*keyframe = f->keyframe;

	for (i = 0; i < n; i++) {
		ret = ave_fw_wait(cores[i], AVE_CMD_PROCESS, f->seen[i], AVE_FRAME_TIMEOUT_US);
		if (!ret)
			ret = ave9_reply_check(ctx, cores[i], f->seen[i]);
		if (ret)
			return ave_two_failed(ctx, ret);
	}

	ret = ave9_frame_done(ctx, &start, &coded);
	if (ret)
		return ave_two_failed(ctx, ret);
	/* the slices past the first (two cores' bands), each with its HEVC header */
	slices = ctx->nslices > 1;
	if (slices) {
		coded = ave9_slices_size(ctx);
		slice = 0;
	} else {
		slice = ave_slice_hdr_bytes(ctx);
		if (slice && ctx->slices[0].hdr_size != slice)
			dev_dbg(ctx->ave->dev, "frame %u: the slice header's record %u bytes, %u found\n",
				f->total, ctx->slices[0].hdr_size, slice);
	}

	if (f->keyframe)
		head = ctx->headers_len;
	if (head + slice + coded > dst_size) {
		dev_err(ctx->ave->dev, "frame %u: %u bytes, the buffer holds %zu\n", f->frame,
			head + slice + coded, dst_size);
		return -ENOSPC;
	}
	if (head)
		memcpy(dst, ctx->headers, head);
	if (slice) {
		memcpy(dst + head, f->out->slice_hdr.cpu, slice);
		memset(f->out->slice_hdr.cpu, 0, AVE_SLICE_HDR_STRIDE);
	}
	if (slices)
		ave9_slices_copy(ctx, dst + head);
	else
		memcpy(dst + head + slice, f->out->coded.cpu + start, coded);
	*bytes = head + slice + coded;
	return 0;
}
