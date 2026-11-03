/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Apple ProRes codec registers, as macOS's AppleProResHW uses them (rda
 * com_apple_driver_AppleProResHW).
 */

#ifndef APPLE_PRORES_REGS_H
#define APPLE_PRORES_REGS_H

#define APR_VERSION		0x000
#define APR_CTRL		0x008
#define APR_CTRL_RUN		0xd
#define APR_IRQ_ENABLE		0x00c
#define APR_IRQ_STATUS		0x010
#define APR_IRQ_DONE		BIT(0)
#define APR_IRQ_ERROR		BIT(1)
#define APR_ST0			0x014
#define APR_ST0_CODE		GENMASK(29, 24)
#define APR_ST1			0x018
#define APR_ST2			0x01c
#define APR_RESULT_3C		0x03c

/* the descriptor ring: a head the host writes, a tail the hardware advances */
#define APR_DR_SIZE		0x100
#define APR_DR_ADDR_LO		0x104
#define APR_DR_ADDR_HI		0x108
#define APR_DR_HEAD		0x10c
#define APR_DR_OFFSET		GENMASK(23, 7)
#define APR_DR_WRAP		BIT(24)
#define APR_DR_TAIL		0x110

/* the statistics buffer, read by both DMA blocks */
#define APR_STATS0_LO		0x38c
#define APR_STATS0_HI		0x390
#define APR_STATS0_SIZE		0x394
#define APR_STATS1_LO		0x70c
#define APR_STATS1_HI		0x710
#define APR_STATS1_SIZE		0x714

/* each 32 words: two 64-entry matrices' entries with their dead-zone rounding */
#define APR_QUANT_LUMA(k)	(0x800 + 0x80 * (k))
#define APR_QUANT_CHROMA(k)	(0x1000 + 0x80 * (k))
#define APR_QUANT_BANKS		5
#define APR_QUANT_WORDS		32
#define APR_DC_SCALE		0x1800

#define APR_RING_SIZE		0x20000
#define APR_STATS_SIZE		0x180000

/* the decode descriptor as macOS 14.8.3 fills it */
#define APR_DEC_DESC_SIZE	0x100
#define APR_DD_CTL		0x00
#define APR_DD_IN		0x08
#define APR_DD_WIDTH		0x14
#define APR_DD_HEIGHT		0x16
#define APR_DD_SURF_WIDTH	0x1c
#define APR_DD_SURF_HEIGHT	0x1e
#define APR_DD_STRIDE(p)	(0x20 + 2 * (p))
#define APR_DD_PLANE(p)		(0x28 + 0x10 * (p))
#define APR_DD_90		0x90

/* the YCbCr encode descriptor, v0 (ProgramEncodeYCbCrDescriptor<v0>) */
#define APR_ENC_DESC_SIZE	0x180
#define APR_D_CTL		0x00
#define APR_D_CTL_FRAME		GENMASK(31, 16)
#define APR_D_CTL_CHROMA	GENMASK(3, 2)
#define APR_D_CTL_16BIT		GENMASK(1, 0)
#define APR_D_CTL_ALPHA16	0x180
#define APR_D_OUT		0x08
#define APR_D_OUT_SIZE		0x10
#define APR_D_WIDTH		0x18
#define APR_D_HEIGHT		0x1a
#define APR_D_SURF_WIDTH	0x1c
#define APR_D_SURF_HEIGHT	0x1e
#define APR_D_STRIDE(p)		(0x20 + 2 * (p))
#define APR_D_PLANE(p)		(0x28 + 0x10 * (p))
#define APR_D_HDR_SIZE		0x58
#define APR_D_HDR_VERSION	0x5b
#define APR_D_HDR_ENCODER	0x5c
#define APR_D_HDR_WIDTH		0x60
#define APR_D_HDR_HEIGHT	0x62
#define APR_D_HDR_FORMAT	0x64
#define APR_D_HDR_RATE		0x65
#define APR_D_HDR_PRIMARIES	0x66
#define APR_D_HDR_TRANSFER	0x67
#define APR_D_HDR_MATRIX	0x68
#define APR_D_HDR_SRC		0x69
#define APR_D_HDR_FLAGS		0x6b
#define APR_D_SLICES		0xec
#define APR_D_SLICE_LOG2	0xee
#define APR_D_QINDEX		0xef
#define APR_D_RC0		0xf0
#define APR_D_RC1		0xf2
#define APR_D_RC2		0xf4
#define APR_D_RC3		0xfc
#define APR_D_RC4		0x100
#define APR_D_RC5		0x110
#define APR_D_QUANT_SEL		0x150

#endif /* APPLE_PRORES_REGS_H */
