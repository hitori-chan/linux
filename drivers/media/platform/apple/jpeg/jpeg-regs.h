/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Apple JPEG codec registers
 *
 * Copyright The Asahi Linux Contributors
 *
 * Offsets and values are taken from macOS's AppleJPEGDriver (AppleJPEGHalV8,
 * the HAL of hardware version 0xf1008). Most names describe how that driver
 * uses a register; the hardware meaning behind them is inferred.
 */

#ifndef APPLE_JPEG_REGS_H
#define APPLE_JPEG_REGS_H

#include <linux/bits.h>

/* 1 starts a job, 0 stops it (reset, interrupt ack) */
#define JPEG_START			0x0000
#define JPEG_004			0x0004

/* clock and sub-block control (inferred) */
#define JPEG_CTRL			0x0008
#define JPEG_CTRL_RESET			0x100
#define JPEG_CTRL_SETUP			0x13e
#define JPEG_CTRL_PROGRAM		0x17f
#define JPEG_CTRL_IDLE			0x143
#define JPEG_CTRL_VERSION		0x147
#define JPEG_CTRL_RUN(f)		(((f) << 1) | 0x141)
#define JPEG_RUN_YUV			0x0b
#define JPEG_RUN_RGB			0x1b

/* bit 2 clears a lone status bit 5 */
#define JPEG_STATUS_AUX			0x000c
#define JPEG_STATUS_AUX_OK5		BIT(2)

#define JPEG_IRQ_ENABLE			0x0020
#define JPEG_IRQ_STATUS			0x0024
#define JPEG_IRQ_DONE			BIT(0)
#define JPEG_IRQ_TIMEOUT		BIT(1)
#define JPEG_IRQ_RDMA_OVERFLOW		BIT(2)
#define JPEG_IRQ_WDMA_OVERFLOW		BIT(3)
#define JPEG_IRQ_CODEC_OVERFLOW		BIT(4)
#define JPEG_IRQ_ERROR5			BIT(5)
#define JPEG_IRQ_AXI_ERROR		BIT(6)
#define JPEG_IRQ_ERROR7			BIT(7)
#define JPEG_IRQ_ERRORS			GENMASK(7, 1)

/* source subsampling: enum apple_jpeg_subsampling */
#define JPEG_SUBSAMPLING		0x0028
/* 0 decode, 1 encode */
#define JPEG_ENCODE			0x002c
#define JPEG_034			0x0034
#define JPEG_038			0x0038

/* chroma resampling enables (inferred) */
#define JPEG_RESAMPLE_03C		0x003c
#define JPEG_RESAMPLE_044		0x0044
#define JPEG_RESAMPLE_04C		0x004c
#define JPEG_RESAMPLE_050		0x0050
#define JPEG_RESAMPLE_054		0x0054

/* image boundary and MCU counts (set_image_boundary, set_decode_mbcounts) */
#define JPEG_TWO_PLANES			0x0058
#define JPEG_DCD_CNT4			0x005c
#define JPEG_MCU_ROWS			0x0060
#define JPEG_P0_WIDTH			0x0064
#define JPEG_P0_HEIGHT			0x0068
#define JPEG_DCD_CNT0			0x006c
#define JPEG_DCD_CNT1			0x0070
#define JPEG_P0_STRIDE			0x0074
#define JPEG_P1_WIDTH			0x0078
#define JPEG_P1_HEIGHT			0x007c
#define JPEG_DCD_CNT2			0x0080
#define JPEG_DCD_CNT3			0x0084
#define JPEG_P1_STRIDE			0x0088

/* DMA: the source (read) and destination (write) DVAs, low and high words */
#define JPEG_RD0_LO			0x0090
#define JPEG_RD0_HI			0x0094
#define JPEG_RD1_LO			0x00a0
#define JPEG_RD1_HI			0x00a4
#define JPEG_RD_END_LO			0x00b0
#define JPEG_RD_END_HI			0x00b4
#define JPEG_0B8			0x00b8
#define JPEG_0BC			0x00bc
#define JPEG_WR0_LO			0x00c0
#define JPEG_WR0_HI			0x00c4
#define JPEG_WR1_LO			0x00d0
#define JPEG_WR1_HI			0x00d4
#define JPEG_WR_END_LO			0x00e0
#define JPEG_WR_END_HI			0x00e4

/* YCbCr to RGB matrix and offsets, 11 words */
#define JPEG_CSC(n)			(0x00e8 + 4 * (n))
#define JPEG_CSC_WORDS			11

#define JPEG_154			0x0154
#define JPEG_158			0x0158

/* the last MCU column and row (wrcnvset_w_h) */
#define JPEG_MCU_COLS			0x016c
#define JPEG_MCU_ROWS2			0x0170
#define JPEG_LAST_W			0x0174
#define JPEG_LAST_H			0x0178
#define JPEG_LAST_CW			0x017c
#define JPEG_LAST_CH			0x0180

/* DCT downscale: 0 = 1/1, 1 = 1/2, 2 = 1/4, 3 = 1/8 */
#define JPEG_SCALE			0x0184
#define JPEG_OUT_MODE			0x0188
#define JPEG_SUBMODE_YUV		0x018c
#define JPEG_SUBMODE_RGB		0x0190
#define JPEG_ALPHA			0x0194
#define JPEG_RESAMPLE_198		0x0198
#define JPEG_DEBUG			0x019c

#define JPEG_RESULT0			0x01a8
#define JPEG_RESULT1			0x01ac
#define JPEG_CYCLES			0x01b4
/* hardware timeout, in cycles (inferred) */
#define JPEG_HW_TIMEOUT			0x01c0
/* reads the hardware version after JPEG_CTRL = JPEG_CTRL_VERSION */
#define JPEG_HW_VERSION			0x01c4
#define JPEG_HW_VERSION_T6031		0x000f0008

#define JPEG_1D8			0x01d8
#define JPEG_1DC			0x01dc
#define JPEG_1E4			0x01e4

/*
 * Slice and header-window parameters. How the codec uses them is inferred
 * from how macOS's CMPhoto fills them: 0 for a plain decode, which has the
 * codec parse the markers from the stream itself.
 */
#define JPEG_SLICE_INDEX		0x01e8
#define JPEG_SLICE_MORE			0x01ec
#define JPEG_SLICE_BYTES		0x01f0
#define JPEG_HDR_BYTES			0x01f8
#define JPEG_MCU_IMG_W			0x01fc
#define JPEG_MCU_IMG_H			0x0200
#define JPEG_CROP_EN			0x0204
#define JPEG_CROP_X			0x0208
#define JPEG_CROP_Y			0x020c
#define JPEG_CROP_W			0x0210
#define JPEG_CROP_H			0x0214

#define JPEG_1000			0x1000
/* 1 starts a job; reads 0 once a soft reset has finished */
#define JPEG_GO				0x1004
/* soft reset handshake: write 1 until it reads back 1, then 0 */
#define JPEG_RESET_ACK			0x1014
#define JPEG_1028			0x1028
#define JPEG_AXI_STATUS			0x102c
#define JPEG_AXI_STATUS_OK0		0x80000000
#define JPEG_AXI_STATUS_OK1		0x40000000
#define JPEG_BITSTREAM_ERROR		0x1030

/* the JPEG header window: up to 4 KiB of marker segments */
#define JPEG_HDR_WINDOW			0x2000
#define JPEG_HDR_WINDOW_SIZE		0x1000

#endif /* APPLE_JPEG_REGS_H */
