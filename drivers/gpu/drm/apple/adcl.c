// SPDX-License-Identifier: GPL-2.0-only
/*
 * The internal panel's PRC (polarity compensation) calibration.
 *
 * The display's M3 replays a static frame (idle caching) only once a frame's
 * hold reaches the last entry of the PRC durations table, and the DCP's
 * default table ends at 30 subframes, past the 10 a 120 Hz frame is held. The
 * panel's factory calibration (ADCL, an "LCDA" blob) carries the table the
 * panel was measured with. On macOS IOMFB_FDR_Loader parses it in user space
 * and sends what it finds as blocks: block 5 the table, then block 3 once per
 * LUT. The blob is per panel, so Linux takes a copy from the firmware
 * directory and sends the same blocks before the display powers on: the M3
 * reads the table at its power-up. The display first powers on from the
 * initramfs, so the blob is declared: mkinitcpio and dracut copy it there.
 *
 * macOS also sends the panel model's display data, the same LCDA container
 * kept per model in /System/Library/Display/<model>/<index>-*.bin: the charge
 * accumulation (CA) records, the DBM map and the overdrive (PDC) tables, which
 * its loader parses into blocks 8, 0x45, 0x1c and 0x1b. PDC is on in the
 * firmware but runs only once its tables arrive. 27.2's firmware takes no
 * whole container: its block 0x61 is a 4-byte get-only one and the
 * container's moved to 0x62, whose setter only logs "Set User Cal Data is not
 * longer available" (rda t603xdcp_272 0x2A632C).
 * Its parser still runs on DCPExpert's property "display-data-adcl", but
 * parses CA, DBMA and PDC only with ADCLLoadAll set, which its pipe's start
 * clears (0x2BED3C): macOS parses those three in IOMobileFramebuffer.framework
 * and sends their blocks. Linux parses them the same way (paneldata.c) and
 * sends the blocks after the PRC blocks, their tables out of band.
 */

#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/unaligned.h>

#include "dcp.h"
#include "dcp-internal.h"
#include "iomfb.h"
#include "paneldata.h"

#define ADCL_FIRMWARE	"apple/dcp-adcl.bin"
MODULE_FIRMWARE(ADCL_FIRMWARE);

#define ADCL_MAGIC	0x4144434c	/* "LCDA" */
/* the container version whose header is 9 words; any other has 3 */
#define ADCL_V5		0x50000
#define ADCL_TAG_PRC	0x20505243	/* " PRC" */
#define ADCL_PRC_V2	0x20000

/* a v2 PRC block: 3 header words, 6 u16 keys, three 257-entry LUTs */
#define ADCL_PRC_WORDS	393
#define ADCL_PRC_LUTS	3
#define ADCL_PRC_LUT_STRIDE	0x204
#define ADCL_PRC_LUT_SIZE	0x202

#define PRC_LUT_VERSION	2

/*
 * The set_block types sent here, by firmware (the descriptors registered
 * through rda t603xdcp_272 sub_1B9A7C): the PRC table (0x134 bytes) and a PRC
 * LUT set (0x60c, 5 indices). The panel data's are CA 8 (0xc24), DBMA 0x45
 * (0x60), PDC config 0x1c (0xa14) and PDC LUTs 0x1b (0xda0). The ICC blocks'
 * types are iomfb_template.c's, built per firmware. An older firmware gets
 * none of them.
 */
struct dcp_block_ids {
	u32 prc_table;
	u32 prc_lut;
};

static const struct dcp_block_ids dcp_blocks_27_2 = {
	.prc_table = 5,
	.prc_lut = 3,
};

static const struct dcp_block_ids *dcp_blocks(struct apple_dcp *dcp)
{
	if (dcp->fw_compat >= DCP_FIRMWARE_V_27_2)
		return &dcp_blocks_27_2;
	return NULL;
}

/* the files, in the order sent; each a copy of macOS's for this panel */
static const char *const panel_data_fw[] = {
	"apple/dcp-lcdca.bin",
	"apple/dcp-dbm.bin",
	"apple/dcp-od.bin",
};
MODULE_FIRMWARE("apple/dcp-lcdca.bin");
MODULE_FIRMWARE("apple/dcp-dbm.bin");
MODULE_FIRMWARE("apple/dcp-od.bin");

/*
 * Which files go, a bit each in panel_data_fw's order; all by default, as
 * macOS sends them. A file that is not installed is skipped.
 */
static unsigned int panel_data = 7;
module_param(panel_data, uint, 0444);
MODULE_PARM_DESC(panel_data, "The panel model's display data sent to the DCP, a bit each: 1 apple/dcp-lcdca.bin (CA), 2 apple/dcp-dbm.bin (DBM), 4 apple/dcp-od.bin (overdrive); default 7, all");

#define PANEL_DATA_MAX	0x80000

struct panel_data_buf {
	void *buf;
	dma_addr_t dva;
	size_t len;
};

#define PRC_MAX_TEMPS	8
#define PRC_MAX_LEVELS	16
#define PRC_MAX_DURATIONS	16

/* block 5, UPPipeDCP_H13P::prc_set_tab_config's argument */
struct prc_table {
	__le32 version;
	__le32 temps[24];
	__le32 n_temps;
	__le32 levels[24];
	__le32 n_levels;
	__le32 durations[24];
	__le32 n_durations;
	__le32 n_polarities;
} __packed;

static_assert(sizeof(struct prc_table) == 0x134);

/* block 3: one LUT set, indexed {0, temperature, duration, level, polarity} */
struct prc_lut {
	__le32 version;
	u8 luts[ADCL_PRC_LUTS][ADCL_PRC_LUT_SIZE];
	u8 padding[2];
} __packed;

static_assert(sizeof(struct prc_lut) == 0x60c);

struct dcp_prc_entry {
	u16 temp, duration, level, polarity;
	const u8 *luts;
};

struct dcp_prc {
	const struct firmware *fw;
	struct prc_table table;
	u32 temps[PRC_MAX_TEMPS], levels[PRC_MAX_LEVELS];
	u32 durations[PRC_MAX_DURATIONS];
	u32 n_temps, n_levels, n_durations, n_polarities;
	/* the next block to send: 0 the table, then entry - 1 */
	u32 next, n_entries;
	/* sent, or refused: nothing more to send this boot */
	bool done;
	/* the panel data files parsed, loaded at the power-on */
	u32 n_data;
	/* the files' blocks, their tables in one buffer the DCP reads */
	struct panel_blocks blocks;
	struct panel_data_buf oob;
	u32 next_block, failed_blocks;
	struct dcp_set_block_dcp_req req;
	struct dcp_prc_entry entries[];
};

/* Adds v to the sorted set of n values; false if it holds max already */
static bool prc_set_add(u32 *set, u32 *n, u32 max, u32 v)
{
	u32 i;

	for (i = 0; i < *n && set[i] < v; i++)
		;
	if (i < *n && set[i] == v)
		return true;
	if (*n == max)
		return false;
	memmove(&set[i + 1], &set[i], (*n - i) * sizeof(*set));
	set[i] = v;
	(*n)++;
	return true;
}

static u32 prc_index(const u32 *set, u32 n, u32 v)
{
	u32 i;

	for (i = 0; i < n && set[i] != v; i++)
		;
	return i;
}

/*
 * Walks the blob's top-level blocks as the DCP's DisplayDataBlockParser does
 * and keeps the v2 PRC blocks whose sixth key is 0, as it does. A blob whose
 * durations skip a value needs LUTs interpolated between them, which the
 * DCP's parser does and this one does not: it is refused.
 */
static struct dcp_prc *prc_parse(struct apple_dcp *dcp, const struct firmware *fw)
{
	const u8 *d = fw->data;
	size_t words = fw->size / 4, pos, n = 0;
	struct dcp_prc *prc;
	u32 i;

	if (words < 3 || get_unaligned_le32(d) != ADCL_MAGIC ||
	    get_unaligned_le32(d + 8) > words) {
		dev_warn(dcp->dev, "PRC: %s is not an ADCL blob\n", ADCL_FIRMWARE);
		return NULL;
	}
	words = get_unaligned_le32(d + 8);
	pos = get_unaligned_le32(d + 4) == 0x50000 ? 9 : 3;

	prc = kzalloc(struct_size(prc, entries, words / ADCL_PRC_WORDS),
		      GFP_KERNEL);
	if (!prc)
		return NULL;

	while (pos + 3 <= words) {
		const u8 *b = d + pos * 4;
		u32 tag = get_unaligned_le32(b);
		u32 size = get_unaligned_le32(b + 8);
		struct dcp_prc_entry *e = &prc->entries[n];
		const u8 *k = b + 12;

		if (!tag || !size || size > words - pos)
			break;
		pos += size;
		if (tag != ADCL_TAG_PRC || get_unaligned_le32(b + 4) != ADCL_PRC_V2 ||
		    size != ADCL_PRC_WORDS || get_unaligned_le16(k + 10))
			continue;

		e->temp = get_unaligned_le16(k + 2);
		e->duration = get_unaligned_le16(k + 4);
		e->level = get_unaligned_le16(k + 6);
		e->polarity = get_unaligned_le16(k + 8);
		e->luts = k + 12;
		if (e->polarity > 1 ||
		    !prc_set_add(prc->temps, &prc->n_temps, PRC_MAX_TEMPS, e->temp) ||
		    !prc_set_add(prc->levels, &prc->n_levels, PRC_MAX_LEVELS, e->level) ||
		    !prc_set_add(prc->durations, &prc->n_durations,
				 PRC_MAX_DURATIONS, e->duration))
			goto bad;
		prc->n_polarities |= BIT(e->polarity);
		n++;
	}

	prc->n_polarities = hweight32(prc->n_polarities);
	if (!n || n != prc->n_temps * prc->n_levels * prc->n_durations *
			      prc->n_polarities)
		goto bad;
	for (i = 1; i < prc->n_durations; i++)
		if (prc->durations[i] != prc->durations[i - 1] + 1)
			goto bad;

	prc->table.version = cpu_to_le32(1);
	for (i = 0; i < prc->n_temps; i++)
		prc->table.temps[i] = cpu_to_le32(prc->temps[i]);
	for (i = 0; i < prc->n_levels; i++)
		prc->table.levels[i] = cpu_to_le32(prc->levels[i]);
	for (i = 0; i < prc->n_durations; i++)
		prc->table.durations[i] = cpu_to_le32(prc->durations[i]);
	prc->table.n_temps = cpu_to_le32(prc->n_temps);
	prc->table.n_levels = cpu_to_le32(prc->n_levels);
	prc->table.n_durations = cpu_to_le32(prc->n_durations);
	prc->table.n_polarities = cpu_to_le32(prc->n_polarities);
	prc->n_entries = n;
	prc->fw = fw;

	dev_info(dcp->dev, "PRC: %u temperatures, %u levels, durations %u-%u, %zu LUT sets\n",
		 prc->n_temps, prc->n_levels, prc->durations[0],
		 prc->durations[prc->n_durations - 1], n);
	return prc;

bad:
	dev_warn(dcp->dev, "PRC: %s: unsupported PRC tables (%zu kept)\n",
		 ADCL_FIRMWARE, n);
	kfree(prc);
	return NULL;
}

/*
 * Parses each panel data file present and chosen into its blocks, and copies
 * their out-of-band tables into one buffer the DCP can read
 */
static void panel_data_parse_all(struct apple_dcp *dcp, struct dcp_prc *prc)
{
	struct panel_blocks *pb = &prc->blocks;
	const struct firmware *fw;
	size_t len = 0;
	u32 i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(panel_data_fw); i++) {
		if (!(panel_data & BIT(i)) ||
		    firmware_request_nowarn(&fw, panel_data_fw[i], dcp->dev))
			continue;
		ret = fw->size > PANEL_DATA_MAX ? -EINVAL :
			panel_data_parse(dcp->dev, panel_data_fw[i], fw->data,
					 fw->size, pb);
		release_firmware(fw);
		if (ret == -EINVAL) {
			dev_warn(dcp->dev, "panel data: %s is not an LCDA container\n",
				 panel_data_fw[i]);
			continue;
		}
		if (ret)
			goto bad;
		prc->n_data++;
	}

	for (i = 0; i < pb->n; i++) {
		pb->b[i].oob_off = len;
		len += pb->b[i].oob_len;
	}
	if (len) {
		prc->oob.buf = dma_alloc_coherent(dcp->dev, len, &prc->oob.dva,
						  GFP_KERNEL);
		if (!prc->oob.buf)
			goto bad;
		prc->oob.len = len;
		for (i = 0; i < pb->n; i++) {
			struct panel_block *b = &pb->b[i];

			if (!b->oob_len)
				continue;
			memcpy(prc->oob.buf + b->oob_off, b->oob, b->oob_len);
			kvfree(b->oob);
			b->oob = NULL;
		}
	}
	if (pb->n)
		dev_info(dcp->dev, "panel data: %u blocks: %u CA, %u DBMA, %d PDC config, %u PDC LUT sets; %zu bytes out of band\n",
			 pb->n, pb->n_ca, pb->n_dbma, pb->pdc_config,
			 pb->n_pdc_luts, len);
	return;

bad:
	dev_warn(dcp->dev, "panel data: out of memory, none sent\n");
	panel_blocks_free(pb);
}

static void panel_data_release(struct apple_dcp *dcp, struct dcp_prc *prc)
{
	if (prc->oob.buf)
		dma_free_coherent(dcp->dev, prc->oob.len, prc->oob.buf,
				  prc->oob.dva);
	prc->oob.buf = NULL;
	panel_blocks_free(&prc->blocks);
}

/*
 * True if the PRC blocks are still to be sent: loads the blob at the first
 * power-on that finds it, as the root file system may come up after the DCP.
 */
bool dcp_prc_pending(struct apple_dcp *dcp)
{
	const struct firmware *fw;

	if (dcp->connector_type != DRM_MODE_CONNECTOR_eDP || !dcp_blocks(dcp))
		return false;
	if (dcp->prc) {
		/* the replies came in the last power-on: the buffers can go */
		if (dcp->prc->done)
			panel_data_release(dcp, dcp->prc);
		return !dcp->prc->done;
	}

	if (firmware_request_nowarn(&fw, ADCL_FIRMWARE, dcp->dev))
		return false;
	dcp->prc = prc_parse(dcp, fw);
	if (!dcp->prc) {
		release_firmware(fw);
		/* a stub, so the blob is not parsed again: no PRC blocks */
		dcp->prc = kzalloc(sizeof(*dcp->prc), GFP_KERNEL);
		if (!dcp->prc)
			return false;
		dcp->prc->next = 1;
	}
	panel_data_parse_all(dcp, dcp->prc);
	dcp->prc->done = dcp->prc->next > dcp->prc->n_entries &&
			 !dcp->prc->n_data && !dcp->prc->blocks.n;
	return !dcp->prc->done;
}

/*
 * The next panel data block, its table's address in the request and at its
 * place in the block, as macOS's IOMobileFramebufferAP::set_block
 * maps it (map_block_buf, rda IOMFB-DCP_272 0xfffffe000ae53260)
 */
static struct dcp_set_block_dcp_req *panel_block_next(struct apple_dcp *dcp,
						      struct dcp_prc *prc)
{
	struct dcp_set_block_dcp_req *req = &prc->req;
	const struct panel_block *b;
	u32 i;

	if (prc->next_block == prc->blocks.n) {
		if (prc->blocks.n)
			dev_info(dcp->dev, "panel data: %u of %u blocks set\n",
				 prc->blocks.n - prc->failed_blocks,
				 prc->blocks.n);
		prc->done = true;
		return NULL;
	}

	b = &prc->blocks.b[prc->next_block++];
	memset(req, 0, sizeof(*req));
	req->type = b->type;
	memcpy(req->data, b->data, b->len);
	req->len = b->len;
	for (i = 0; i < b->nidx; i++)
		req->idx[i] = b->idx[i];
	req->nidx = b->nidx;
	if (b->oob_len) {
		req->dva = prc->oob.dva + b->oob_off;
		req->dva_len = b->oob_len;
		req->dva_flag = 1;
		put_unaligned_le64(req->dva, req->data + b->ptr_off);
	}
	return req;
}

/*
 * The next block to send: the PRC table and its LUT sets, then the panel
 * data; NULL once all are sent
 */
struct dcp_set_block_dcp_req *dcp_prc_next(struct apple_dcp *dcp)
{
	struct dcp_prc *prc = dcp->prc;
	struct dcp_set_block_dcp_req *req = &prc->req;

	if (prc->done)
		return NULL;
	if (prc->next > prc->n_entries) {
		if (prc->n_entries && prc->next == prc->n_entries + 1)
			dev_info(dcp->dev, "PRC: the table and %u LUT sets sent\n",
				 prc->n_entries);
		prc->next = prc->n_entries + 2;
		return panel_block_next(dcp, prc);
	}

	memset(req, 0, sizeof(*req));
	if (prc->next == 0) {
		req->type = dcp_blocks(dcp)->prc_table;
		memcpy(req->data, &prc->table, sizeof(prc->table));
		req->len = sizeof(prc->table);
	} else {
		const struct dcp_prc_entry *e = &prc->entries[prc->next - 1];
		struct prc_lut *lut = (struct prc_lut *)req->data;
		int k;

		req->type = dcp_blocks(dcp)->prc_lut;
		req->idx[1] = prc_index(prc->temps, prc->n_temps, e->temp);
		req->idx[2] = prc_index(prc->durations, prc->n_durations, e->duration);
		req->idx[3] = prc_index(prc->levels, prc->n_levels, e->level);
		req->idx[4] = e->polarity;
		req->nidx = 5;
		lut->version = cpu_to_le32(PRC_LUT_VERSION);
		for (k = 0; k < ADCL_PRC_LUTS; k++)
			memcpy(lut->luts[k], e->luts + k * ADCL_PRC_LUT_STRIDE,
			       ADCL_PRC_LUT_SIZE);
		req->len = sizeof(*lut);
	}
	prc->next++;
	return req;
}

/*
 * The DCP refused a block. A PRC block stops the sends for this boot; the
 * panel data goes on with the next block, as macOS's parser does, but for a
 * refused PDC config's LUT sets (set_data).
 */
void dcp_prc_abort(struct apple_dcp *dcp, u32 status)
{
	struct dcp_prc *prc = dcp->prc;

	if (prc->next <= prc->n_entries + 1) {
		dev_warn(dcp->dev, "PRC: block %u (%u of %u) failed: %#x\n",
			 prc->req.type, prc->next, prc->n_entries + 1, status);
	} else {
		dev_warn(dcp->dev, "panel data: block %#x (%u of %u) failed: %#x\n",
			 prc->req.type, prc->next_block, prc->blocks.n, status);
		prc->failed_blocks++;
		if (prc->req.type == PANEL_BLOCK_PDC_CONFIG) {
			while (prc->next_block < prc->blocks.n &&
			       prc->blocks.b[prc->next_block].type ==
				       PANEL_BLOCK_PDC_LUT) {
				prc->next_block++;
				prc->failed_blocks++;
			}
		}
		return;
	}
	prc->done = true;
}

void dcp_prc_free(struct apple_dcp *dcp)
{
	if (!dcp->prc)
		return;
	panel_data_release(dcp, dcp->prc);
	release_firmware(dcp->prc->fw);
	kfree(dcp->prc);
	dcp->prc = NULL;
}
