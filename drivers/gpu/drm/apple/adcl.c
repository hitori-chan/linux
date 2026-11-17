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
 * its loader parses into blocks 8, 67, 27 and 26. PDC is on in the firmware
 * but runs only once its tables arrive. 14.8.3's firmware also takes a whole
 * container in block 0x61 (set_user_cal_data, rda t603xdcp_1483 0x1E82E4) and
 * runs its own parser on it (0x125874), which sets the same blocks. Linux
 * sends each file present and chosen (panel_data) that way, after the PRC
 * blocks.
 */

#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/unaligned.h>

#include "dcp-internal.h"
#include "iomfb.h"

#define ADCL_FIRMWARE	"apple/dcp-adcl.bin"
MODULE_FIRMWARE(ADCL_FIRMWARE);

#define ADCL_MAGIC	0x4144434c	/* "LCDA" */
#define ADCL_TAG_PRC	0x20505243	/* " PRC" */
#define ADCL_PRC_V2	0x20000

/* a v2 PRC block: 3 header words, 6 u16 keys, three 257-entry LUTs */
#define ADCL_PRC_WORDS	393
#define ADCL_PRC_LUTS	3
#define ADCL_PRC_LUT_STRIDE	0x204
#define ADCL_PRC_LUT_SIZE	0x202

#define PRC_BLOCK_TABLE	5
#define PRC_BLOCK_LUT	3
#define PRC_LUT_VERSION	2

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

#define PANEL_DATA_BLOCK	0x61
#define PANEL_DATA_MAX	0x80000

/* block 0x61's in-band part: a v1 descriptor of the buffer at dva */
struct panel_data_desc {
	__le32 version;
	__le32 pad0;
	__le32 len;
	__le32 pad1;
	__le64 addr;
	__le32 size;
	__le32 pad2;
} __packed;

static_assert(sizeof(struct panel_data_desc) == 0x20);

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
	/* the panel data, loaded at the power-on; the next one to send */
	struct panel_data_buf data[ARRAY_SIZE(panel_data_fw)];
	u32 next_data, n_data;
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
 * True if the PRC blocks are still to be sent: loads the blob at the first
 * power-on that finds it, as the root file system may come up after the DCP.
 */
/* Copies each panel data file present into a buffer the DCP can read */
static void panel_data_load(struct apple_dcp *dcp, struct dcp_prc *prc)
{
	const struct firmware *fw;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(panel_data_fw); i++) {
		struct panel_data_buf *b = &prc->data[i];

		if (!(panel_data & BIT(i)) ||
		    firmware_request_nowarn(&fw, panel_data_fw[i], dcp->dev))
			continue;
		if (fw->size < 12 || fw->size > PANEL_DATA_MAX ||
		    get_unaligned_le32(fw->data) != ADCL_MAGIC) {
			dev_warn(dcp->dev, "panel data: %s is not an LCDA container\n",
				 panel_data_fw[i]);
		} else {
			b->buf = dma_alloc_coherent(dcp->dev, fw->size, &b->dva,
						    GFP_KERNEL);
			if (b->buf) {
				memcpy(b->buf, fw->data, fw->size);
				b->len = fw->size;
				prc->n_data++;
			}
		}
		release_firmware(fw);
	}
}

static void panel_data_release(struct apple_dcp *dcp, struct dcp_prc *prc)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(panel_data_fw); i++) {
		struct panel_data_buf *b = &prc->data[i];

		if (b->buf)
			dma_free_coherent(dcp->dev, b->len, b->buf, b->dva);
		b->buf = NULL;
	}
}

bool dcp_prc_pending(struct apple_dcp *dcp)
{
	const struct firmware *fw;

	if (dcp->connector_type != DRM_MODE_CONNECTOR_eDP)
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
	panel_data_load(dcp, dcp->prc);
	dcp->prc->done = dcp->prc->next > dcp->prc->n_entries && !dcp->prc->n_data;
	return !dcp->prc->done;
}

/* The next panel data file's block 0x61, or NULL once each is sent */
static struct dcp_set_block_dcp_req *panel_data_next(struct apple_dcp *dcp,
						     struct dcp_prc *prc)
{
	struct dcp_set_block_dcp_req *req = &prc->req;
	struct panel_data_desc *desc = (struct panel_data_desc *)req->data;

	while (prc->next_data < ARRAY_SIZE(panel_data_fw) &&
	       !prc->data[prc->next_data].buf)
		prc->next_data++;
	if (prc->next_data == ARRAY_SIZE(panel_data_fw)) {
		if (prc->n_data)
			dev_info(dcp->dev, "panel data: %u files sent\n", prc->n_data);
		prc->done = true;
		return NULL;
	}

	memset(req, 0, sizeof(*req));
	req->type = PANEL_DATA_BLOCK;
	desc->version = cpu_to_le32(1);
	desc->len = cpu_to_le32(prc->data[prc->next_data].len);
	desc->size = cpu_to_le32(prc->data[prc->next_data].len);
	req->len = sizeof(*desc);
	req->dva = prc->data[prc->next_data].dva;
	req->dva_len = prc->data[prc->next_data].len;
	req->dva_flag = 1;
	prc->next_data++;
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

	if (prc->next > prc->n_entries) {
		if (prc->n_entries && prc->next == prc->n_entries + 1)
			dev_info(dcp->dev, "PRC: the table and %u LUT sets sent\n",
				 prc->n_entries);
		prc->next = prc->n_entries + 2;
		return panel_data_next(dcp, prc);
	}

	memset(req, 0, sizeof(*req));
	if (prc->next == 0) {
		req->type = PRC_BLOCK_TABLE;
		memcpy(req->data, &prc->table, sizeof(prc->table));
		req->len = sizeof(prc->table);
	} else {
		const struct dcp_prc_entry *e = &prc->entries[prc->next - 1];
		struct prc_lut *lut = (struct prc_lut *)req->data;
		int k;

		req->type = PRC_BLOCK_LUT;
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

/* The DCP refused a block: send none again this boot */
void dcp_prc_abort(struct apple_dcp *dcp, u32 status)
{
	struct dcp_prc *prc = dcp->prc;

	if (prc->req.type == PANEL_DATA_BLOCK)
		dev_warn(dcp->dev, "panel data: %s failed: %#x\n",
			 panel_data_fw[prc->next_data - 1], status);
	else
		dev_warn(dcp->dev, "PRC: block %u (%u of %u) failed: %#x\n",
			 prc->req.type, prc->next, prc->n_entries + 1, status);
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
