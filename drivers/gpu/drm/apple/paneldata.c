// SPDX-License-Identifier: GPL-2.0-only
/*
 * The panel model's display data on 27.2's firmware: the LCDA containers
 * macOS keeps as /System/Library/Display/<model>/<index>-{lcdca,dbm,od}.bin,
 * parsed into the DCP's blocks as IOMobileFramebuffer.framework's
 * DisplayDataBlockParser does for IOMFB_FDR_Loader (rda
 * IOMobileFramebuffer_272): a CA record per "  CA" block (process_ca
 * 0x1B5A7E0FC), the DBMA header with its map out of band (process_dbma
 * 0x1B5A7F598), and the overdrive's PDC table config and LUT sets from the
 * PDCc and PDCp blocks (process_pdc_cal_v5 0x1B5A85AA8, process_pdc_param_v5
 * 0x1B5AB26D0, validate_pdc 0x1B5A92E10, set_pdc_luts 0x1B5A91634).
 *
 * 27.2's DCP runs the same parser on DCPExpert's display-data-adcl, but runs
 * CA, DBMA and PDC there only with ADCLLoadAll set, which its pipe's start
 * clears (rda t603xdcp_272 0x2BED3C): those three are the AP's to parse.
 * The block setters take them whatever ADCLLoadAll is (CA 0x18B948, DBMA
 * 0x1EED24, PDC config 0x29A8E8, PDC LUT 0x29B364).
 *
 * Only what this panel's files hold is parsed: PDC version 5 without bin
 * interpolation or the refresh-rate ("rr") tables. A container with more is
 * refused, block by block as macOS's parser does, and its PDC as a whole.
 */

#include <linux/bits.h>
#include <linux/math64.h>
#include <linux/minmax.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "paneldata.h"

#define LCDA_MAGIC	0x4144434c	/* "ADCL" */
#define LCDA_V5		0x50000		/* a 9-word header; any other has 3 */

#define TAG_CA		0x20204341	/* "  CA" */
#define TAG_DBMA	0x44424d41
#define TAG_PDCC	0x50444363
#define TAG_PDCP	0x50444370

/* a record's fields: a sub-block each, copied as words */
#define CA_VERSION	0x000
#define CA_RLUT_WORDS	0x040
#define CA_RLUT		0x044
#define CA_RLUT_LEN	600
#define CA_PRCW		0xae0
#define CA_MSFD		0xb60
#define CA_PRCW3_A	0xb64
#define CA_PRCW3_B	0xbc4

#define TAG_PRCW	0x50524357
#define TAG_RLUT	0x524c5554

struct ca_field {
	u32 tag;
	u16 off;
	u16 words;
	bool exact;
};

static const struct ca_field ca_fields[] = {
	{ 0x49524558, 0x004, 3, true },		/* IREX */
	{ 0x53494558, 0x010, 3, true },		/* SIEX */
	{ 0x53314558, 0x01c, 3, true },		/* S1EX */
	{ 0x53324558, 0x028, 3, true },		/* S2EX */
	{ 0x53334558, 0x034, 3, true },		/* S3EX */
	{ TAG_RLUT, CA_RLUT, CA_RLUT_LEN, false },
	{ 0x43525850, 0x9a4, 1, true },		/* CRXP */
	{ 0x4352564c, 0x9a8, 1, true },		/* CRVL */
	{ 0x43545850, 0x9ac, 1, true },		/* CTXP */
	{ 0x4354564c, 0x9b0, 4, true },		/* CTVL */
	{ 0x564c4558, 0x9c0, 1, true },		/* VLEX */
	{ 0x564c564c, 0x9c4, 65, true },	/* VLVL */
	{ 0x56494558, 0xac8, 1, true },		/* VIEX */
	{ 0x56314558, 0xacc, 1, true },		/* V1EX */
	{ 0x56324558, 0xad0, 1, true },		/* V2EX */
	{ 0x56334558, 0xad4, 1, true },		/* V3EX */
	{ 0x52464558, 0xad8, 1, true },		/* RFEX */
	{ 0x52445346, 0xadc, 1, true },		/* RDSF */
	{ 0x50524344, 0xb20, 16, false },	/* PRCD */
	{ 0x4d534644, CA_MSFD, 1, true },	/* MSFD: version 2 */
};

/* the PDC table config (block 0x1c), the fields at their offsets in it */
#define PDC_VERSION		0x000
#define PDC_TEMPS		0x00c	/* s32[20], Q16 degrees */
#define PDC_BRIGHTS		0x05c	/* s32[20], Q16 */
#define PDC_SFS			0x0ac	/* u16[20] */
#define PDC_FRAME_REPEAT	0x0d4	/* u16[20], from PDCp */
#define PDC_PARAMS		0x0fc	/* u16[20] */
#define PDC_DC_IDX		0x124	/* u16[24] */
#define PDC_PM_IDX		0x154	/* u16[24] */
#define PDC_DATA_VERSION	0x184
#define PDC_N_TEMPS		0x186
#define PDC_N_BRIGHTS		0x188
#define PDC_DC_SIZE		0x18a
#define PDC_PM_SIZE		0x18c
#define PDC_N_SFS		0x18e
#define PDC_N_DURATIONS		0x190	/* from PDCp, as below */
#define PDC_N_PARAMS		0x192
#define PDC_SETTLE		0x194
#define PDC_196			0x196
#define PDC_SAVE_UNSTABLE	0x198
#define PDC_SAVE_LONG		0x19a
#define PDC_DURATIONS		0x19c	/* u32[20] */
#define PDC_DURATION_TABLE	0x1ec	/* u32[n * n] */
#define PDC_82C			0x82c
#define PDC_82E			0x82e
#define PDC_CUTOFF		0x830	/* Q16 */
#define PDC_HYSTERESIS		0x834	/* Q16 */

#define PDC_V5		5
#define PDC_KEYS	20
#define PDC_IDX_MAX	24
#define PDC_BINS_MAX	20
#define PDC_CHANS	7

/* a PDC LUT set's in-band part: its buffer's size and address */
#define PDC_LUT_VERSION	0x00
#define PDC_LUT_SIZE	0x10
#define PDC_LUT_ADDR	0x18

/* DBMA's in-band part: its map's address and size */
#define DBMA_HEADER	0x3c
#define DBMA_MAP_ADDR	0x50
#define DBMA_MAP_SIZE	0x58
#define DBMA_MAP_MAX	0x8000

/* the FFR index macOS's parser takes when the panel's is not found */
#define PDC_FFR_DEFAULT	0x8000	/* 0.5, Q16 */

struct pdc_table {
	struct pdc_table *next;
	/* the keys, then their indices in the config's tables */
	u32 temp, sf, bright, param;
	u32 chans;
	u16 *lut;
	u32 lut_len;
};

struct pdc_state {
	u8 cfg[PANEL_PDC_CONFIG_LEN];
	/* the counts each PDCc header gives, checked against the keys */
	u16 hdr_temps, hdr_sfs, hdr_brights, hdr_params;
	bool bin_known, refused;
	u32 bin;
	struct pdc_table *tables;
};

struct pd_buf {
	const u8 *p;
	size_t left;
};

static bool rd16(struct pd_buf *b, u16 *v)
{
	if (b->left < 2)
		return false;
	*v = get_unaligned_le16(b->p);
	b->p += 2;
	b->left -= 2;
	return true;
}

static bool rd32(struct pd_buf *b, u32 *v)
{
	if (b->left < 4)
		return false;
	*v = get_unaligned_le32(b->p);
	b->p += 4;
	b->left -= 4;
	return true;
}

static u16 cfg16(struct pdc_state *s, u32 off)
{
	return get_unaligned_le16(s->cfg + off);
}

static void set16(struct pdc_state *s, u32 off, u16 v)
{
	put_unaligned_le16(v, s->cfg + off);
}

static void set32(struct pdc_state *s, u32 off, u32 v)
{
	put_unaligned_le32(v, s->cfg + off);
}

static void tag_name(u32 tag, char name[5])
{
	name[0] = tag >> 24;
	name[1] = tag >> 16;
	name[2] = tag >> 8;
	name[3] = tag;
	name[4] = 0;
}

static struct panel_block *pb_add(struct panel_blocks *pb, u32 type, u32 len)
{
	struct panel_block *b;

	if (pb->n == pb->alloc) {
		u32 alloc = pb->alloc ? pb->alloc * 2 : 32;
		struct panel_block *nb;

		nb = krealloc_array(pb->b, alloc, sizeof(*nb), GFP_KERNEL);
		if (!nb)
			return NULL;
		pb->b = nb;
		pb->alloc = alloc;
	}
	b = &pb->b[pb->n];
	memset(b, 0, sizeof(*b));
	b->data = kvzalloc(len, GFP_KERNEL);
	if (!b->data)
		return NULL;
	b->type = type;
	b->len = len;
	pb->n++;
	return b;
}

void panel_blocks_free(struct panel_blocks *pb)
{
	u32 i;

	for (i = 0; i < pb->n; i++) {
		kvfree(pb->b[i].data);
		kvfree(pb->b[i].oob);
	}
	kfree(pb->b);
	memset(pb, 0, sizeof(*pb));
}

/* A CA sub-block's words into the record (ca_subblock 0x1B5AB0A7C) */
static int ca_words(u8 *rec, struct pd_buf *b, u32 words, u32 off,
		    u32 count, bool exact)
{
	if (words > count || (exact && words < count) ||
	    b->left < (size_t)words * 4)
		return -EINVAL;
	memcpy(rec + off, b->p, words * 4);
	memset(rec + off + words * 4, 0, (count - words) * 4);
	b->p += words * 4;
	b->left -= words * 4;
	return 0;
}

/* PRCW: version 3 holds two 24-word tables, any older 16 words (0x1B5AB3240) */
static int ca_prcw(u8 *rec, struct pd_buf *b, u32 version, u32 words)
{
	u32 flag;

	if (version >= 4)
		return -EINVAL;
	if (version != 3)
		return ca_words(rec, b, words, CA_PRCW, 16, false);
	if (words != 0x34 - 3 || !rd32(b, &flag))
		return -EINVAL;
	if (!flag)
		return 0;
	if (b->left < 2 * 24 * 4)
		return -EINVAL;
	memcpy(rec + CA_PRCW3_A, b->p, 24 * 4);
	memcpy(rec + CA_PRCW3_B, b->p + 24 * 4, 24 * 4);
	b->p += 2 * 24 * 4;
	b->left -= 2 * 24 * 4;
	return 0;
}

static int pd_ca(struct device *dev, struct panel_blocks *pb, const u8 *body,
		 size_t len)
{
	struct pd_buf b = { body, len };
	struct panel_block *blk;
	u8 *rec;
	int ret = 0;

	blk = pb_add(pb, PANEL_BLOCK_CA, PANEL_CA_LEN);
	if (!blk)
		return -ENOMEM;
	rec = blk->data;
	/* macOS's template: zeros, then 0xaa from MSFD on (0x1B5AB5220) */
	memset(rec + CA_MSFD, 0xaa, PANEL_CA_LEN - CA_MSFD);
	put_unaligned_le32(1, rec + CA_VERSION);

	while (b.left >= 12 && !ret) {
		u32 tag = get_unaligned_le32(b.p);
		u32 version = get_unaligned_le32(b.p + 4) >> 16;
		u32 size = get_unaligned_le32(b.p + 8);
		u32 words, i;

		if (size < 3 || (size_t)size * 4 - 12 > b.left - 12) {
			ret = -EINVAL;
			break;
		}
		b.p += 12;
		b.left -= 12;
		words = size - 3;

		if (tag == TAG_PRCW) {
			ret = ca_prcw(rec, &b, version, words);
			continue;
		}
		for (i = 0; i < ARRAY_SIZE(ca_fields); i++)
			if (ca_fields[i].tag == tag)
				break;
		if (i == ARRAY_SIZE(ca_fields)) {
			char name[5];

			tag_name(tag, name);
			dev_warn(dev, "panel data: CA: unknown block %s\n", name);
			ret = -EINVAL;
			break;
		}
		ret = ca_words(rec, &b, words, ca_fields[i].off,
			       ca_fields[i].words, ca_fields[i].exact);
		if (tag == TAG_RLUT)
			put_unaligned_le32(words, rec + CA_RLUT_WORDS);
		if (ca_fields[i].off == CA_MSFD)
			put_unaligned_le32(2, rec + CA_VERSION);
	}
	if (ret) {
		/* nothing sent for it, as macOS's parser */
		kvfree(blk->data);
		pb->n--;
		return ret;
	}
	pb->n_ca++;
	return 0;
}

/* DBMA's header fields, from the block to the in-band part */
static const struct {
	u8 src, dst, len;
} dbma_fields[] = {
	{ 0x00, 0x10, 1 }, { 0x01, 0x11, 1 }, { 0x02, 0x12, 2 },
	{ 0x04, 0x14, 2 }, { 0x06, 0x16, 2 }, { 0x08, 0x18, 2 },
	{ 0x0a, 0x1a, 2 }, { 0x0c, 0x1c, 2 }, { 0x0e, 0x1e, 1 },
	{ 0x0f, 0x20, 2 }, { 0x11, 0x22, 2 }, { 0x13, 0x24, 1 },
};

static int pd_dbma(struct panel_blocks *pb, u32 version, const u8 *body,
		   size_t len)
{
	struct panel_block *blk;
	size_t map, i;

	if ((version >> 16) > 2 || len <= DBMA_HEADER)
		return -EINVAL;
	map = len - DBMA_HEADER;
	if (round_up(map, PANEL_OOB_ALIGN) > DBMA_MAP_MAX)
		return -EINVAL;

	blk = pb_add(pb, PANEL_BLOCK_DBMA, PANEL_DBMA_LEN);
	if (!blk)
		return -ENOMEM;
	blk->oob_len = round_up(map, PANEL_OOB_ALIGN);
	blk->oob = kvzalloc(blk->oob_len, GFP_KERNEL);
	if (!blk->oob)
		return -ENOMEM;
	memcpy(blk->oob, body + DBMA_HEADER, map);

	put_unaligned_le32(1, blk->data);
	for (i = 0; i < ARRAY_SIZE(dbma_fields); i++)
		memcpy(blk->data + dbma_fields[i].dst, body + dbma_fields[i].src,
		       dbma_fields[i].len);
	/* then twenty u16 from 0x14 to 0x3a, to 0x26 to 0x4c */
	for (i = 0; i < 20; i++)
		memcpy(blk->data + 0x26 + 2 * i, body + 0x14 + 2 * i, 2);
	blk->ptr_off = DBMA_MAP_ADDR;
	put_unaligned_le32(blk->oob_len, blk->data + DBMA_MAP_SIZE);
	pb->n_dbma++;
	return 0;
}

/* Inserts v into a sorted table of at most PDC_KEYS (table_insert 0x1B5A865F4) */
static bool pdc_insert_s32(struct pdc_state *s, u32 off, u32 n_off, s32 v)
{
	u16 n = cfg16(s, n_off);
	u32 i;

	for (i = 0; i < n; i++) {
		s32 t = get_unaligned_le32(s->cfg + off + 4 * i);

		if (t == v)
			return true;
		if (t > v)
			break;
	}
	if (n == PDC_KEYS)
		return false;
	memmove(s->cfg + off + 4 * (i + 1), s->cfg + off + 4 * i, 4 * (n - i));
	set32(s, off + 4 * i, v);
	set16(s, n_off, n + 1);
	return true;
}

static bool pdc_insert_u16(struct pdc_state *s, u32 off, u32 n_off, u16 v)
{
	u16 n = cfg16(s, n_off);
	u32 i;

	for (i = 0; i < n; i++) {
		u16 t = cfg16(s, off + 2 * i);

		if (t == v)
			return true;
		if (t > v)
			break;
	}
	if (n == PDC_KEYS)
		return false;
	memmove(s->cfg + off + 2 * (i + 1), s->cfg + off + 2 * i, 2 * (n - i));
	set16(s, off + 2 * i, v);
	set16(s, n_off, n + 1);
	return true;
}

/* An IEEE 754 single as Q16, rounded down, without the FPU; -1 if negative */
static s64 f32_q16(u32 f)
{
	int exp = (f >> 23) & 0xff;
	u64 man = (f & 0x7fffff) | 0x800000;
	int sh;

	if (f & BIT(31))
		return (f & ~BIT(31)) ? -1 : 0;
	if (!exp)
		return 0;
	sh = exp - 134;
	if (sh >= 0)
		return sh > 32 ? S64_MAX : (s64)(man << sh);
	return sh < -63 ? 0 : (s64)(man >> -sh);
}

/* The bin v falls in, at least 1, and how far into it (find_pdc_ffr_bin) */
static u32 pdc_bin_of(const s64 *thr, u32 n, s64 v, s64 *frac)
{
	u32 i;

	for (i = 0; i < n && v > thr[i]; i++)
		;
	*frac = 0;
	if (i >= 1 && i < n && i - 1 < n - 2 && thr[i] > thr[i - 1])
		*frac = div64_s64((v - thr[i - 1]) << 16, thr[i] - thr[i - 1]);
	return max(i, 1U);
}

/*
 * The bin the PDC tables are taken from (figure_pdc_ffr_index 0x1B5A79F70):
 * the panel's FFR indices, low and high, placed in the two threshold lists
 * and mixed. macOS reads them from AppleCLCD2's FFR_raw_index and
 * FFR_raw_high_index and takes 0.5 when they are missing; Linux has neither,
 * so 0.5 (not verified against the property on this panel).
 */
static int pdc_figure_bin(struct device *dev, struct pdc_state *s,
			  const s64 *lo, const s64 *hi, u32 n, s64 mix)
{
	s64 flo, fhi, a, c, pos, frac;
	u32 blo, bhi;

	blo = pdc_bin_of(lo, n, PDC_FFR_DEFAULT, &flo);
	bhi = pdc_bin_of(hi, n, PDC_FFR_DEFAULT, &fhi);
	a = ((s64)blo << 16) + flo;
	c = ((s64)bhi << 16) + fhi;
	pos = ((65536 - mix) * c + mix * a) >> 16;
	s->bin = pos >> 16;
	frac = pos & 0xffff;
	if (s->bin > n - 2)
		frac = 0;
	s->bin_known = true;
	if (frac) {
		dev_warn(dev, "panel data: PDC wants bins %u and %u mixed: not supported\n",
			 s->bin, s->bin + 1);
		s->refused = true;
		return -EOPNOTSUPP;
	}
	return 0;
}

/* The table with these keys, a new one if none (find_pdc_table 0x1B5A7A278) */
static struct pdc_table *pdc_table_get(struct pdc_state *s, u32 temp, u32 sf,
				       u32 bright, u32 param, u32 chans)
{
	struct pdc_table *t;

	for (t = s->tables; t; t = t->next)
		if (t->temp == temp && t->bright == bright &&
		    t->param == param && t->sf == sf)
			break;
	if (t)
		return (t->chans & chans) ? ERR_PTR(-EEXIST) : t;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return ERR_PTR(-ENOMEM);
	t->temp = temp;
	t->sf = sf;
	t->bright = bright;
	t->param = param;
	/* at the head, as macOS's list: the last file's key goes first */
	t->next = s->tables;
	s->tables = t;
	return t;
}

/* An index table's values, the same in every PDCc (PDC_DC_IDX, PDC_PM_IDX) */
static bool pdc_index(struct pdc_state *s, struct pd_buf *b, u32 off, u16 n)
{
	u32 i;

	for (i = 0; i < n; i++) {
		u16 v, old = cfg16(s, off + 2 * i);

		if (!rd16(b, &v) || (old && old != v))
			return false;
		set16(s, off + 2 * i, v);
	}
	return true;
}

/* A LUT, n * n u16 per channel, into each channel the block names */
static bool pdc_lut(struct pd_buf *b, u16 *lut, u32 sq, u32 chans)
{
	bool zero = true;
	u32 i;

	if (b->left < 2 * (size_t)sq)
		return false;
	for (i = 0; i < sq; i++) {
		u16 v = get_unaligned_le16(b->p + 2 * i);

		if (chans & 1)
			lut[i] = v;
		if (chans & 2)
			lut[sq + i] = v;
		if (chans & 4)
			lut[2 * sq + i] = v;
		zero &= !v;
	}
	b->p += 2 * sq;
	b->left -= 2 * sq;
	return !zero;
}

/* "R", "G", "B" and spaces, a byte each (channel_mask 0x1B5A7A1CC) */
static u32 pdc_chans(u32 code)
{
	u32 m = 0;

	for (; code; code >>= 8) {
		switch (code & 0xff) {
		case 'R':
			m |= 1;
			break;
		case 'G':
			m |= 2;
			break;
		case 'B':
			m |= 4;
			break;
		case ' ':
			break;
		default:
			return 0;
		}
	}
	return m;
}

static int pd_pdcc(struct device *dev, struct pdc_state *s, const u8 *body,
		   size_t len)
{
	struct pd_buf b = { body, len };
	s64 lo[PDC_BINS_MAX], hi[PDC_BINS_MAX], mix;
	u16 h[7], dc, pm, bin, temp, sf, bright;
	u32 skip, code, onoff, f, i, n, chans, dc_sq, pm_sq;
	struct pdc_table *t, *scratch = NULL;
	int ret = -EINVAL;

	set32(s, PDC_VERSION, PDC_V5);
	if (!rd32(&b, &skip))
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(h); i++)
		if (!rd16(&b, &h[i]))
			return -EINVAL;
	set16(s, PDC_DATA_VERSION, h[0]);
	s->hdr_temps = h[1];
	s->hdr_sfs = h[2];
	s->hdr_brights = h[4];
	s->hdr_params = h[6];
	n = h[5] + 1;
	if (h[3] != 3 || n > PDC_BINS_MAX)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		if (!rd32(&b, &f))
			return -EINVAL;
		lo[i] = f32_q16(f);
	}
	for (i = 0; i < n; i++) {
		if (!rd32(&b, &f))
			return -EINVAL;
		hi[i] = f32_q16(f);
	}
	if (!rd32(&b, &f))
		return -EINVAL;
	mix = f32_q16(f);
	if (mix < 0 || mix > 65536)
		return -EINVAL;
	if (!s->bin_known) {
		ret = pdc_figure_bin(dev, s, lo, hi, n, mix);
		if (ret)
			return ret;
		ret = -EINVAL;
	}

	/* one size for every table: the config holds it once */
	if (!rd16(&b, &dc) || !rd16(&b, &pm) || dc > PDC_IDX_MAX ||
	    pm > PDC_IDX_MAX ||
	    (cfg16(s, PDC_DC_SIZE) && cfg16(s, PDC_DC_SIZE) != dc) ||
	    (cfg16(s, PDC_PM_SIZE) && cfg16(s, PDC_PM_SIZE) != pm))
		return -EINVAL;
	set16(s, PDC_DC_SIZE, dc);
	set16(s, PDC_PM_SIZE, pm);
	if (!rd16(&b, &bin) || !rd16(&b, &temp) || !rd16(&b, &sf) ||
	    !rd16(&b, &bright) || !rd32(&b, &code) || !rd32(&b, &onoff))
		return -EINVAL;
	chans = pdc_chans(code);
	if (!chans)
		return -EINVAL;

	/* another bin's tables are parsed, and their keys kept, then dropped */
	if (bin == s->bin) {
		t = pdc_table_get(s, ((u32)temp << 16) / 10, sf, (u32)bright << 16,
				  onoff == 0x20204f4e, chans);
		if (IS_ERR(t))
			return PTR_ERR(t);
	} else {
		t = scratch = kzalloc(sizeof(*t), GFP_KERNEL);
		if (!t)
			return -ENOMEM;
		t->temp = ((u32)temp << 16) / 10;
		t->sf = sf;
		t->bright = (u32)bright << 16;
		t->param = onoff == 0x20204f4e;
	}
	t->chans |= chans;

	dc_sq = dc * dc;
	pm_sq = pm * pm;
	if (!t->lut) {
		t->lut_len = round_up(6 * (dc_sq + pm_sq), PANEL_OOB_ALIGN);
		t->lut = kvzalloc(t->lut_len, GFP_KERNEL);
		if (!t->lut) {
			ret = -ENOMEM;
			goto out;
		}
	}
	if (!pdc_index(s, &b, PDC_DC_IDX, dc) ||
	    !pdc_lut(&b, t->lut, dc_sq, chans) ||
	    !pdc_index(s, &b, PDC_PM_IDX, pm) ||
	    !pdc_lut(&b, t->lut + 3 * dc_sq, pm_sq, chans))
		goto out;

	if (pdc_insert_s32(s, PDC_TEMPS, PDC_N_TEMPS, t->temp) &&
	    pdc_insert_s32(s, PDC_BRIGHTS, PDC_N_BRIGHTS, t->bright) &&
	    pdc_insert_u16(s, PDC_SFS, PDC_N_SFS, t->sf) &&
	    pdc_insert_u16(s, PDC_PARAMS, PDC_N_PARAMS, t->param))
		ret = 0;
out:
	if (scratch) {
		kvfree(scratch->lut);
		kfree(scratch);
	}
	return ret;
}

/* PDCp v5: the durations and their table, the frame repeat LUT, the cutoff */
static int pd_pdcp(struct pdc_state *s, const u8 *body, size_t len)
{
	struct pd_buf b = { body, len };
	u16 version, min, max, n, v, count;
	u32 d, i;
	static const u32 words[] = {
		PDC_SETTLE, PDC_196, PDC_82C, PDC_SAVE_UNSTABLE, PDC_SAVE_LONG,
	};

	set32(s, PDC_VERSION, PDC_V5);
	if (!rd16(&b, &version) || !rd16(&b, &min) || !rd16(&b, &max) ||
	    !rd16(&b, &n) || !n || n > PDC_KEYS)
		return -EINVAL;
	set16(s, PDC_N_DURATIONS, n);
	for (i = 0; i < n; i++) {
		if (!rd32(&b, &d))
			return -EINVAL;
		set32(s, PDC_DURATIONS + 4 * i, d);
	}
	if (get_unaligned_le32(s->cfg + PDC_DURATIONS) != min ||
	    get_unaligned_le32(s->cfg + PDC_DURATIONS + 4 * (n - 1)) != max)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(words); i++) {
		if (!rd16(&b, &v))
			return -EINVAL;
		set16(s, words[i], v);
	}
	for (i = 0; i < (u32)n * n; i++) {
		if (!rd32(&b, &d))
			return -EINVAL;
		set32(s, PDC_DURATION_TABLE + 4 * i, d);
	}
	if (!rd16(&b, &v) || !rd16(&b, &count) || count < n || count > PDC_KEYS)
		return -EINVAL;
	set16(s, PDC_82E, v);
	/* two lists of count: the first is skipped, as macOS's parser does */
	if (b.left < 4 * (size_t)count)
		return -EINVAL;
	b.p += 2 * count;
	b.left -= 2 * count;
	for (i = 0; i < count; i++) {
		rd16(&b, &v);
		set16(s, PDC_FRAME_REPEAT + 2 * i, v);
	}
	if (!rd16(&b, &v))
		return -EINVAL;
	set32(s, PDC_CUTOFF, (u32)v << 16);
	if (!rd16(&b, &v))
		return -EINVAL;
	set32(s, PDC_HYSTERESIS, (u32)v << 16);
	return 0;
}

static u32 pdc_find_s32(struct pdc_state *s, u32 off, u32 n_off, u32 v)
{
	u32 n = cfg16(s, n_off), i;

	for (i = 0; i < n && get_unaligned_le32(s->cfg + off + 4 * i) != v; i++)
		;
	return i;
}

static u32 pdc_find_u16(struct pdc_state *s, u32 off, u32 n_off, u32 v)
{
	u32 n = cfg16(s, n_off), i;

	for (i = 0; i < n && cfg16(s, off + 2 * i) != v; i++)
		;
	return i;
}

/*
 * Checks the tables against the counts and sends the config, then a LUT set
 * per table, indexed {temperature, brightness, duration, parameter}
 * (validate_pdc, set_pdc_tab_config 0x1B5A91588, set_pdc_luts)
 */
static int pdc_finish(struct device *dev, const char *name,
		      struct pdc_state *s, struct panel_blocks *pb)
{
	struct pdc_table *t;
	struct panel_block *blk;
	u32 count = 0;

	if (!s->tables || s->refused)
		return 0;
	if (cfg16(s, PDC_N_TEMPS) != s->hdr_temps ||
	    cfg16(s, PDC_N_SFS) != s->hdr_sfs ||
	    cfg16(s, PDC_N_BRIGHTS) != s->hdr_brights ||
	    cfg16(s, PDC_N_PARAMS) != s->hdr_params) {
		dev_warn(dev, "panel data: %s: PDC's tables do not match its counts\n",
			 name);
		return 0;
	}
	for (t = s->tables; t; t = t->next) {
		t->temp = pdc_find_s32(s, PDC_TEMPS, PDC_N_TEMPS, t->temp);
		t->bright = pdc_find_s32(s, PDC_BRIGHTS, PDC_N_BRIGHTS, t->bright);
		t->sf = pdc_find_s32(s, PDC_DURATIONS, PDC_N_DURATIONS, t->sf);
		t->param = pdc_find_u16(s, PDC_PARAMS, PDC_N_PARAMS, t->param);
		if (t->chans != PDC_CHANS) {
			dev_warn(dev, "panel data: %s: a PDC table lacks a channel\n",
				 name);
			return 0;
		}
		count++;
	}
	if (count != s->hdr_temps * s->hdr_sfs * s->hdr_brights * s->hdr_params) {
		dev_warn(dev, "panel data: %s: %u PDC LUT sets, not %u\n", name,
			 count, s->hdr_temps * s->hdr_sfs * s->hdr_brights *
			 s->hdr_params);
		return 0;
	}

	blk = pb_add(pb, PANEL_BLOCK_PDC_CONFIG, PANEL_PDC_CONFIG_LEN);
	if (!blk)
		return -ENOMEM;
	memcpy(blk->data, s->cfg, PANEL_PDC_CONFIG_LEN);
	pb->pdc_config = true;

	for (t = s->tables; t; t = t->next) {
		blk = pb_add(pb, PANEL_BLOCK_PDC_LUT, PANEL_PDC_LUT_LEN);
		if (!blk)
			return -ENOMEM;
		put_unaligned_le32(PDC_V5, blk->data + PDC_LUT_VERSION);
		put_unaligned_le32(t->lut_len, blk->data + PDC_LUT_SIZE);
		blk->ptr_off = PDC_LUT_ADDR;
		blk->idx[0] = t->temp;
		blk->idx[1] = t->bright;
		blk->idx[2] = t->sf;
		blk->idx[3] = t->param;
		blk->nidx = 4;
		blk->oob = t->lut;
		blk->oob_len = t->lut_len;
		t->lut = NULL;
		pb->n_pdc_luts++;
	}
	return 0;
}

static void pdc_free(struct pdc_state *s)
{
	struct pdc_table *t, *next;

	for (t = s->tables; t; t = next) {
		next = t->next;
		kvfree(t->lut);
		kfree(t);
	}
	kfree(s);
}

/*
 * Appends the blocks of one container to pb, in macOS's order: each CA record
 * and DBMA as found, then the PDC config and its LUT sets at the end
 * (process_adcl_data 0x1B5A7BD90). A block that does not parse is skipped.
 */
int panel_data_parse(struct device *dev, const char *name, const u8 *data,
		     size_t size, struct panel_blocks *pb)
{
	struct pdc_state *s;
	size_t end, pos;
	int ret = 0;

	if (size < 12 || get_unaligned_le32(data) != LCDA_MAGIC)
		return -EINVAL;
	end = (size_t)get_unaligned_le32(data + 8) * 4;
	pos = get_unaligned_le32(data + 4) == LCDA_V5 ? 36 : 12;
	if (end > size || end < pos)
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	while (end - pos > 12) {
		const u8 *h = data + pos;
		u32 tag = get_unaligned_le32(h);
		u32 version = get_unaligned_le32(h + 4);
		u32 words = get_unaligned_le32(h + 8);
		size_t len = (size_t)words * 4 - 12;
		char tname[5];

		tag_name(tag, tname);
		if (!tag || words < 3 || (size_t)words * 4 > end - pos) {
			dev_warn(dev, "panel data: %s: block %s not well formed\n",
				 name, tname);
			break;
		}

		switch (tag) {
		case TAG_CA:
			ret = pd_ca(dev, pb, h + 12, len);
			break;
		case TAG_DBMA:
			ret = pd_dbma(pb, version, h + 12, len);
			break;
		case TAG_PDCC:
			if (s->refused)
				break;
			ret = (version >> 16) == PDC_V5 ?
				pd_pdcc(dev, s, h + 12, len) : -EOPNOTSUPP;
			break;
		case TAG_PDCP:
			if (s->refused)
				break;
			ret = (version >> 16) == PDC_V5 ?
				pd_pdcp(s, h + 12, len) : -EOPNOTSUPP;
			break;
		default:
			ret = -EOPNOTSUPP;
			break;
		}
		if (ret == -ENOMEM)
			goto out;
		if (ret) {
			dev_warn(dev, "panel data: %s: block %s v%#x skipped: %d\n",
				 name, tname, version, ret);
			/* the PDC as a whole goes only if each of its blocks parsed */
			if (tag == TAG_PDCC || tag == TAG_PDCP)
				s->refused = true;
			ret = 0;
		}
		pos += (size_t)words * 4;
	}
	ret = pdc_finish(dev, name, s, pb);
out:
	pdc_free(s);
	return ret;
}
