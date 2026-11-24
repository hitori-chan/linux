/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __APPLE_PANELDATA_H__
#define __APPLE_PANELDATA_H__

#include <linux/device.h>
#include <linux/types.h>

/* 27.2's set_block types for the panel data, and their in-band sizes */
#define PANEL_BLOCK_CA		0x08
#define PANEL_BLOCK_DBMA	0x45
#define PANEL_BLOCK_PDC_CONFIG	0x1c
#define PANEL_BLOCK_PDC_LUT	0x1b

#define PANEL_CA_LEN		0xc24
#define PANEL_DBMA_LEN		0x60
#define PANEL_PDC_CONFIG_LEN	0xa14
#define PANEL_PDC_LUT_LEN	0xda0

/* an out-of-band buffer's size unit, as macOS's parser allocates them */
#define PANEL_OOB_ALIGN		0x4000

/*
 * One block to send: its in-band bytes and, for DBMA and the PDC LUTs, a
 * buffer the DCP copies from, whose address the in-band bytes also hold at
 * ptr_off.
 */
struct panel_block {
	u32 type;
	u32 len;
	u32 nidx;
	u32 idx[4];
	u32 ptr_off;
	u32 oob_len;
	/* where the sender put the buffer, from the start of its own */
	u32 oob_off;
	u8 *data;
	void *oob;
};

struct panel_blocks {
	struct panel_block *b;
	u32 n, alloc;
	u32 n_ca, n_dbma, n_pdc_luts;
	bool pdc_config;
};

int panel_data_parse(struct device *dev, const char *name, const u8 *data,
		     size_t size, struct panel_blocks *pb);
void panel_blocks_free(struct panel_blocks *pb);

#endif
