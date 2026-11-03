// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple ProRes codec: the hardware
 *
 * Copyright The Asahi Linux Contributors
 *
 * No firmware: a descriptor ring in DART memory, one interrupt a job. The
 * bring-up and the ring are macOS's AppleProResHW (rda
 * com_apple_driver_AppleProResHW): activateDevice 0xfffffe0009c66c00,
 * UpdateDRHead 0xfffffe0009c69eb4, interruptHandler 0xfffffe0009c687e8. Its
 * plugins fill the descriptors' fields, in macOS's trace of them.
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/unaligned.h>

#include "prores.h"
#include "prores-regs.h"
#include "prores-tables.h"

static const struct apple_prores_core apple_prores_cores[] = {
	{ 0x2c5000000, apr_axi2af_scodec, ARRAY_SIZE(apr_axi2af_scodec) },
	{ 0x287000000, apr_axi2af_prores, ARRAY_SIZE(apr_axi2af_prores) },
};

const struct apple_prores_core *apple_prores_hw_find_core(u64 base)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(apple_prores_cores); i++)
		if (apple_prores_cores[i].base == base)
			return &apple_prores_cores[i];
	return NULL;
}

static void apr_apply(void __iomem *base,
		      const struct apple_prores_tunable *t, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		u32 v = readl(base + t[i].offset);

		writel((v & ~t[i].mask) | t[i].value, base + t[i].offset);
	}
}

/* ProgramCustomQuantizationAndRoundingMatrices: 2 entries of 6 + 6 bits a word */
static void apr_write_bank(struct apple_prores_dev *apr, u32 reg, const u8 *q,
			   const u8 *r)
{
	unsigned int i;

	for (i = 0; i < APR_QUANT_WORDS; i++) {
		u32 v = (q[2 * i] & 0x3f) | (r[2 * i] & 0x3f) << 6 |
			(q[2 * i + 1] & 0x3f) << 12 |
			(r[2 * i + 1] & 0x3f) << 18;

		apr_write(apr, reg + 4 * i, v);
	}
}

static void apr_write_matrices(struct apple_prores_dev *apr)
{
	apr_write_bank(apr, APR_QUANT_LUMA(0), apr_luma_xq, apr_round_lt);
	apr_write_bank(apr, APR_QUANT_CHROMA(0), apr_chroma_hq, apr_round_lt);
	apr_write_bank(apr, APR_QUANT_LUMA(1), apr_chroma_hq, apr_round_lt);
	apr_write_bank(apr, APR_QUANT_CHROMA(1), apr_chroma_hq, apr_round_lt);
	apr_write_bank(apr, APR_QUANT_LUMA(2), apr_chroma_std, apr_round_lt);
	apr_write_bank(apr, APR_QUANT_CHROMA(2), apr_chroma_std, apr_round_lt);
	apr_write_bank(apr, APR_QUANT_LUMA(3), apr_chroma_lt, apr_round_lt);
	apr_write_bank(apr, APR_QUANT_CHROMA(3), apr_chroma_lt, apr_round_lt);
	apr_write_bank(apr, APR_QUANT_LUMA(4), apr_chroma_proxy, apr_round_proxy);
	apr_write_bank(apr, APR_QUANT_CHROMA(4), apr_chroma_proxy, apr_round_proxy);
}

/* ProgramDCQuantizationScale: q(i) = i to 128, then 4 i - 384, two a word */
static void apr_write_dc_scale(struct apple_prores_dev *apr)
{
	unsigned int i, n = 0;

	for (i = 1; i < 0xe0; i += 2, n++) {
		u32 a = i <= 128 ? i : 4 * i - 384;
		u32 b = i + 1 <= 128 ? i + 1 : 4 * (i + 1) - 384;

		apr_write(apr, APR_DC_SCALE + 4 * n, (a & 0x1ff) | (b & 0x1ff) << 9);
	}
}

/* activateDevice, on every power-up */
void apple_prores_hw_activate(struct apple_prores_dev *apr)
{
	u32 stats;

	apr_write(apr, APR_CTRL, 0);
	apr_apply(apr->regs, apr_tunables_h1, ARRAY_SIZE(apr_tunables_h1));
	if (apr->core)
		apr_apply(apr->axi2af, apr->core->axi2af, apr->core->num_axi2af);

	apr->head = 0;
	apr_write(apr, APR_DR_SIZE, APR_RING_SIZE);
	apr_write(apr, APR_DR_ADDR_LO, lower_32_bits(apr->ring_dma) & ~0x7f);
	apr_write(apr, APR_DR_ADDR_HI, upper_32_bits(apr->ring_dma) & 0x3ff);
	apr_write(apr, APR_DR_TAIL, 0);

	/* the tunables set the sizes: macOS allocates 1.5 MiB and reads them back */
	stats = max(apr_read(apr, APR_STATS0_SIZE), apr_read(apr, APR_STATS1_SIZE));
	if (stats > APR_STATS_SIZE)
		dev_warn(apr->dev, "statistics size %#x over the buffer's\n", stats);
	apr_write(apr, APR_STATS0_LO, lower_32_bits(apr->stats_dma) & ~0x3f);
	apr_write(apr, APR_STATS0_HI, upper_32_bits(apr->stats_dma) & 0x3ff);
	apr_write(apr, APR_STATS1_LO, lower_32_bits(apr->stats_dma) & ~0x3f);
	apr_write(apr, APR_STATS1_HI, upper_32_bits(apr->stats_dma) & 0x3ff);

	apr_write(apr, APR_CTRL, APR_CTRL_RUN);
	apr_write(apr, APR_IRQ_ENABLE, 3);
	apr_write_matrices(apr);
	apr_write_dc_scale(apr);
}

/* deactivateDevice */
void apple_prores_hw_deactivate(struct apple_prores_dev *apr)
{
	apr_write(apr, APR_IRQ_ENABLE, 0);
	apr_write(apr, APR_CTRL, 0);
}

/* calculateNumSlicesPerRow: log2's slices and a power of two's for the rest */
static u32 apr_slices_per_row(u32 mb_width, unsigned int log2)
{
	return (mb_width >> log2) + hweight32(mb_width & (BIT(log2) - 1));
}

static void apr_fill_encode(const struct apple_prores_job *job, u8 *d)
{
	u32 mb_w = DIV_ROUND_UP(job->width, 16);
	u32 mb_h = DIV_ROUND_UP(job->height, 16);
	unsigned int log2 = 3, i;
	bool c444 = job->raw->chroma == 3;
	static const u32 rc4[] = { 0x880080, 0x4e00c5, 0x9000d0, 0x200122 };

	memset(d, 0, APR_ENC_DESC_SIZE);

	put_unaligned_le32(FIELD_PREP(APR_D_CTL_FRAME, job->frame & 0xffff) |
			   0x3600 | 0x30 |
			   FIELD_PREP(APR_D_CTL_CHROMA, job->raw->chroma),
			   d + APR_D_CTL);
	put_unaligned_le64(job->dst, d + APR_D_OUT);
	put_unaligned_le32(job->dst_size, d + APR_D_OUT_SIZE);
	put_unaligned_le16(job->width, d + APR_D_WIDTH);
	put_unaligned_le16(job->height, d + APR_D_HEIGHT);
	put_unaligned_le16(job->width, d + APR_D_SURF_WIDTH);
	put_unaligned_le16(job->height, d + APR_D_SURF_HEIGHT);
	put_unaligned_le16(job->stride0 >> 6, d + APR_D_STRIDE(0));
	put_unaligned_le16(job->stride1 >> 6, d + APR_D_STRIDE(1));
	put_unaligned_le64(job->src0, d + APR_D_PLANE(0));
	put_unaligned_le64(job->src1, d + APR_D_PLANE(1));
	put_unaligned_le64(job->src0, d + APR_D_PLANE(2));

	/* the frame header the codec writes (RDD 36), as the kext's template */
	put_unaligned_be16(148, d + APR_D_HDR_SIZE);
	d[APR_D_HDR_VERSION] = c444 ? 1 : 0;
	memcpy(d + APR_D_HDR_ENCODER, "apl0", 4);
	put_unaligned_be16(job->width, d + APR_D_HDR_WIDTH);
	put_unaligned_be16(job->height, d + APR_D_HDR_HEIGHT);
	d[APR_D_HDR_FORMAT] = job->raw->chroma << 6;
	d[APR_D_HDR_RATE] = job->rate_code;
	d[APR_D_HDR_PRIMARIES] = job->primaries;
	d[APR_D_HDR_TRANSFER] = job->transfer;
	d[APR_D_HDR_MATRIX] = job->matrix;
	d[APR_D_HDR_SRC] = c444 ? 0xd0 : 0x10;
	d[APR_D_HDR_FLAGS] = 3;

	put_unaligned_be16(apr_slices_per_row(mb_w, log2) * mb_h, d + APR_D_SLICES);
	d[APR_D_SLICE_LOG2] = log2 << 4;
	d[APR_D_QINDEX] = job->profile->qindex;

	put_unaligned_le16(job->profile->rc_min, d + APR_D_RC0);
	put_unaligned_le16(job->profile->rc_max, d + APR_D_RC1);
	put_unaligned_le64(0x8000402015100c0cULL, d + APR_D_RC2);
	put_unaligned_le32(0x2c8080, d + APR_D_RC3);
	for (i = 0; i < ARRAY_SIZE(rc4); i++)
		put_unaligned_le32(rc4[i], d + APR_D_RC4 + 4 * i);
	for (i = 0; i < 16; i++)
		put_unaligned_le32(0x400200, d + APR_D_RC5 + 4 * i);
	d[APR_D_QUANT_SEL] = job->profile->quant_sel;
}

/* EncodeFrameGated: a descriptor at the head, then the head moved */
void apple_prores_hw_encode(struct apple_prores_dev *apr,
			    const struct apple_prores_job *job)
{
	u32 off = FIELD_GET(APR_DR_OFFSET, apr->head) << 7;
	u32 wrap = apr->head & APR_DR_WRAP;
	u8 desc[APR_ENC_DESC_SIZE];
	u32 first = min_t(u32, sizeof(desc), APR_RING_SIZE - off);

	apr_fill_encode(job, desc);
	memcpy(apr->ring + off, desc, first);
	memcpy(apr->ring, desc + first, sizeof(desc) - first);
	/* the descriptor reaches memory before the head moves */
	dma_wmb();

	off += sizeof(desc);
	if (off >= APR_RING_SIZE) {
		off -= APR_RING_SIZE;
		wrap ^= APR_DR_WRAP;
	}
	apr->head = (off & APR_DR_OFFSET) | wrap;
	apr_write(apr, APR_DR_HEAD, apr->head);
}

bool apple_prores_hw_irq(struct apple_prores_dev *apr,
			 struct apple_prores_status *st)
{
	st->irq = apr_read(apr, APR_IRQ_STATUS);
	st->st0 = apr_read(apr, APR_ST0);
	st->st1 = apr_read(apr, APR_ST1);
	st->st2 = apr_read(apr, APR_ST2);
	if (!(st->irq & (APR_IRQ_DONE | APR_IRQ_ERROR)))
		return false;
	apr_write(apr, APR_IRQ_STATUS, st->irq);
	return true;
}

/* processEncodeFrameDone */
bool apple_prores_hw_failed(struct apple_prores_dev *apr,
			    const struct apple_prores_status *st)
{
	if (!(st->irq & APR_IRQ_ERROR))
		return false;
	dev_err(apr->dev, "job failed: status %#x, code %lu, st1 %#x, st2 %#x\n",
		st->st0, FIELD_GET(APR_ST0_CODE, st->st0), st->st1, st->st2);
	return true;
}

void apple_prores_hw_dump(struct apple_prores_dev *apr)
{
	dev_err(apr->dev, "irq %#x enable %#x st %#x %#x %#x head %#x tail %#x\n",
		apr_read(apr, APR_IRQ_STATUS), apr_read(apr, APR_IRQ_ENABLE),
		apr_read(apr, APR_ST0), apr_read(apr, APR_ST1),
		apr_read(apr, APR_ST2), apr_read(apr, APR_DR_HEAD),
		apr_read(apr, APR_DR_TAIL));
}
