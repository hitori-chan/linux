// SPDX-License-Identifier: GPL-2.0-only OR MIT
/* Copyright 2021 Alyssa Rosenzweig */

/*
 * This file is intended to be included multiple times with IOMFB_VER
 * defined to declare DCP firmware version dependent structs.
 */

#ifdef DCP_FW_VER

#include <drm/drm_crtc.h>

#include <linux/types.h>

#include "iomfb.h"
#include "iomfb_plane.h"
#include "plane.h"
#include "version_utils.h"

struct DCP_FW_NAME(dcp_swap) {
	u64 unk_pres_ts1;
	u64 unk_pres_ts2;

	u64 unk_10;
	u64 unk_18;
	u64 ts64_unk;
	u64 unk_28;
	u64 unk_pres_ts3;
	u64 unk_38;

	u64 flags1;
	u64 flags2;
#if DCP_FW_VER >= DCP_FW_VERSION(14, 7, 0)
	u8 unk_v14_7[0x48];
#endif
	u32 swap_id;

	u32 surf_ids[SWAP_SURFACES];
	struct dcp_rect src_rect[SWAP_SURFACES];
	u32 surf_flags[SWAP_SURFACES];
	u32 surf_unk[SWAP_SURFACES];
	struct dcp_rect dst_rect[SWAP_SURFACES];
	u32 swap_enabled;
	u32 swap_completed;

	u32 bg_color;
	u8 unk_110[0x24];
	/* 14.7: A407 +0x17c, the DCP's swap +0x32c: 0 normal, 8 idle-cache buffer */
	u32 swap_type;
	u8 unk_138[0x8];
	u32 active_region_en[SWAP_SURFACES];
	struct dcp_rect active_regions[SWAP_SURFACES];
	u8 unk_190[0x138];
	u32 unk_2c8;
#if DCP_FW_VER < DCP_FW_VERSION(14, 7, 0)
	u8 unk_2cc[0x14];
#else
	u8 unk_2cc[0x24];
	/*
	 * A407 +0x338: unk_pres_ts1 is a delay, which DCP adds to its own clock
	 * (rda t603xdcp_1483 IOMobileFramebuffer__swap_submit_dcp 0x1346A4)
	 */
	u8 pres_relative;
	u8 unk_339[0x1b];
#endif
#if DCP_FW_VER < DCP_FW_VERSION(14, 7, 0)
	u32 unk_2e0;
#else
	u32 bl_update;
#endif
#if DCP_FW_VER < DCP_FW_VERSION(13, 2, 0)
	u16 unk_2e2;
#elif DCP_FW_VER < DCP_FW_VERSION(14, 7, 0)
	u8 unk_2e2[3];
#elif DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	/* A407 +0x358: BLNitsCap is valid (its double at +0x36C) */
	u8 unk_2e2;
	/* A407 +0x359: edr_factor is valid */
	u8 edr_update;
	u8 unk_2e4;
#else
	/*
	 * 27.2 inserts the indicator's nits cap's flag here, so every flag
	 * after A457 +0x357 moves by one: +0x359 is now BLNitsCap's, the EDR
	 * factor's +0x35A (rda t603xdcp_272 sub_1C7670 0x1C7BA4: the TBL
	 * copies A457 +0x354..+0x35B to the swap's +0x849..+0x850, then
	 * sub_225884: +0x84E sets runtime property 0x75 BLNitsCap from
	 * +0x870, +0x84F the EDR factor from +0x878; IOMobileFramebuffer
	 * 27.2's kern_SwapSetBrightnessLimit and kern_SwapSetDisplayEdr write
	 * these same bytes). 14.x's offsets put F into BLNitsCap: a nits cap
	 * of 1, held until the DCP restarts.
	 */
	u8 unk_358;		/* the indicator's nits cap is valid */
	u8 bl_limit_update;	/* A457 +0x359: bl_limit is valid */
	u8 edr_update;		/* A457 +0x35A: edr_factor is valid */
	u8 unk_35b;
	u8 edr_headroom_update;	/* A457 +0x35C: edr_headroom is valid */
	u8 unk_35d;
#endif
#if DCP_FW_VER < DCP_FW_VERSION(14, 7 ,0)
	u64 bl_unk;
	u32 bl_value; // min value is 0x10000000
	u8  bl_power; // constant 0x40 for on
#else
#if DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u8 unk_2e5;
#endif
	/*
	 * A407 +0x35C (27.2's A457 +0x35E), a double: the brightness in nits,
	 * with an EDR factor the peak (the backlight table's entries are its
	 * bits 24-55, 0x40 above).
	 */
	u64 brightness;
#endif
#if DCP_FW_VER < DCP_FW_VERSION(14, 7, 0)
	u8 unk_2f3[0x2d];
#elif DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u8 unk_2f3[0x10];
	/*
	 * A407 +0x374 (27.2: +0x37E), a double: the EDR factor F = 1 / H for a headroom H over
	 * the SDR level, which DCP puts at the brightness times F; it scales
	 * each layer by F / (unk_num / unk_denom), 0 / 0 as 1 (rda t603xdcp_1483
	 * 0x18A2D4). 0 gives no light.
	 */
	u64 edr_factor;
	u8 unk_2fb[0x15];
#else
	/* A457 +0x366: the indicator's nits, +0x36E its cap (new in 27.2) */
	u8 unk_366[0x10];
	/*
	 * A457 +0x376, a double: BLNitsCap, the backlight's cap in nits,
	 * which the DCP keeps until another one comes (rda t603xdcp_272
	 * sub_2C9710, sub_22182C, the cap at the controller's +0x28, read by
	 * sub_18A918). The driver sends none: it starts at the panel's
	 * maximum (0x2BDA48).
	 */
	u64 bl_limit;
	/* A457 +0x37E, a double: the EDR factor F, as 14.x's +0x374 */
	u64 edr_factor;
	u8 unk_386[0x60];
	/*
	 * A457 +0x3E6, a double: the headroom in use, H with EDR content
	 * and 1.0 without (QuartzCore's swap_display_headroom_used); the
	 * DCP turns the PCC2D's 0x14C008 on when it is not 1.0 (sub_2985F0).
	 * Not sent, as on 14.x.
	 */
	u64 edr_headroom;
	/* 0x533 on is new; all zero, as the driver sets none of them */
	u8 unk_3ee[0x2f2];
#endif
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0) && DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u8 unk_320[0x13f];
#if DCP_FW_VER >= DCP_FW_VERSION(14, 7, 0)
	u8 unk_14_7_2[0x30];
#endif
	u32 unk_flags;
	u32 unk_flags2;
#endif
} __packed;

/* Information describing a surface */
struct DCP_FW_NAME(dcp_surface) {
	struct dcp_surface base;
#if DCP_FW_VER < DCP_FW_VERSION(13, 2, 0)
	u8 padding[7];
#else
	u8 padding[47];
#endif
} __packed;

/* Prototypes */

/*
 * 14.7 has a sixth secondary surface: macOS 14.8.3's
 * IOMobileFramebufferAP::swap_submit_dcp builds the 0x1b58-byte A407 request
 * with six surfaces at 0xdf8, six addresses at 0x1b00 and six null flags
 * after the four primary ones.
 */
#if DCP_FW_VER >= DCP_FW_VERSION(14, 7, 0)
#define DCP_SWAP_SURFACES2 6
#else
#define DCP_SWAP_SURFACES2 5
#endif

struct DCP_FW_NAME(dcp_swap_start_req) {
	u32 swap_id;
#if DCP_FW_VER < DCP_FW_VERSION(14, 0, 0)
	struct dcp_iouserclient client;
	u8 swap_id_null;
	u8 client_null;
	u8 padding[2];
#else
	u64 unkAddr;
	u8 swap_id_null;
	u8 padding[3];
#endif
} __packed;

struct DCP_FW_NAME(dcp_swap_start_resp) {
	u32 swap_id;
#if DCP_FW_VER < DCP_FW_VERSION(14, 0, 0)
	struct dcp_iouserclient client;
#endif
	u32 ret;
} __packed;

struct DCP_FW_NAME(dcp_swap_submit_req) {
	struct DCP_FW_NAME(dcp_swap) swap;
	struct DCP_FW_NAME(dcp_surface) surf[SWAP_SURFACES];
	u64 surf_iova[SWAP_SURFACES];
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u64 unk_u64_a[SWAP_SURFACES];
	struct DCP_FW_NAME(dcp_surface) surf2[DCP_SWAP_SURFACES2];
	u64 surf2_iova[DCP_SWAP_SURFACES2];
#endif
	u8 unkbool;
	u64 unkdouble;
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u64 unkU64;
	u8 unkbool2;
#endif
	u32 clear; // or maybe switch to default fb?
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u32 unkU32Ptr;
#endif
	u8 swap_null;
	u8 surf_null[SWAP_SURFACES];
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u8 surf2_null[DCP_SWAP_SURFACES2];
#endif
	u8 unkoutbool_null;
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u8 unkU32Ptr_null;
	u8 unkU32out_null;
#endif
#if DCP_FW_VER < DCP_FW_VERSION(14, 0, 0)
	u8 padding[1];
#endif
} __packed;

#undef DCP_SWAP_SURFACES2

struct DCP_FW_NAME(dcp_swap_submit_resp) {
	u8 unkoutbool;
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u32 unkU32out;
#endif
	u32 ret;
	u8 padding[3];
} __packed;

struct DCP_FW_NAME(dc_swap_complete_resp) {
	u32 swap_id;
	u8 unkbool;
	u64 swap_data;
#if DCP_FW_VER < DCP_FW_VERSION(13, 2, 0)
	u8 swap_info[0x6c4];
#elif DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u8 swap_info[0x6c5];
#else
	/*
	 * 27.2's D594: SwapCompleteData's rest, then 8 records of 0xe0 bytes,
	 * their count, a flag and the null flag (rda t603xdcp_272 sub_1CE154)
	 */
	u8 swap_info[0x71a];
#endif
	u32 unkint;
#if DCP_FW_VER >= DCP_FW_VERSION(27, 2, 0)
	u8 unkbool2;
#endif
	u8 swap_info_null;
#if DCP_FW_VER >= DCP_FW_VERSION(27, 2, 0)
	u8 padding[3];
#endif
} __packed;

#if DCP_FW_VER >= DCP_FW_VERSION(27, 2, 0)
/*
 * 27.2's D589 swap_info_notify: a swap's record, which the DCP takes back
 * from the reply (rda t603xdcp_272 sub_1CE054)
 */
struct DCP_FW_NAME(dcp_swap_info) {
	u8 data[0xe0];
} __packed;

struct DCP_FW_NAME(dcp_swap_info_req) {
	struct DCP_FW_NAME(dcp_swap_info) info;
	u8 info_null;
	u8 padding[3];
} __packed;
#endif

struct DCP_FW_NAME(dcp_map_reg_req) {
	char obj[4];
	u32 index;
	u32 flags;
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u8 unk_u64_null;
#endif
	u8 addr_null;
	u8 length_null;
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u8 padding[1];
#else
	u8 padding[2];
#endif
} __packed;

struct DCP_FW_NAME(dcp_map_reg_resp) {
#if DCP_FW_VER >= DCP_FW_VERSION(13, 2, 0)
	u64 dva;
#endif
	u64 addr;
	u64 length;
	u32 ret;
} __packed;

struct DCP_FW_NAME(dcp_rt_bandwidth) {
#if DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u64 unk1;
	u64 reg_scratch;
	u64 reg_doorbell;
	u32 unk2;
	u32 doorbell_bit;
	u32 padding[7];
#else
	/*
	 * 27.2's D003 (rda t603xdcp_272 sub_2A9240, K27
	 * UPPipeAP_H13P::rt_bandwidth_setup_ap)
	 */
	u64 reg_scratch;
	u64 reg_doorbell;
	u32 doorbell_bit;
	/* the scratch's and the doorbell's offsets in their register mappings */
	u32 scratch_offset;
	u32 doorbell_offset;
	/* the mailbox's length in bytes: 4 the legacy one, with a doorbell */
	u32 mbox_len;
	u32 padding[2];
	u32 ret;
#endif
} __packed;

struct DCP_FW_NAME(dcp_map_buf_resp) {
#if DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u64 vaddr;
#else
	/* 27.2: rda t603xdcp_272 sub_2379B0 */
	u32 vaddr;
#endif
	u64 dva;
	u32 ret;
} __packed;

struct DCP_FW_NAME(dcp_unmap_buf_resp) {
	u64 buffer;
#if DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u64 vaddr;
#else
	/* 27.2: rda t603xdcp_272 sub_237AB0 */
	u32 vaddr;
#endif
	u64 dva;
	u8 unk;
#if DCP_FW_VER >= DCP_FW_VERSION(27, 2, 0)
	u8 unk2;
#endif
	u8 buf_null;
#if DCP_FW_VER >= DCP_FW_VERSION(27, 2, 0)
	u8 padding;
#endif
} __packed;

struct DCP_FW_NAME(dcp_allocate_buffer_resp) {
	/* 27.2 has no physical address (rda t603xdcp_272 sub_21A098) */
#if DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u64 paddr;
#endif
	u64 dva;
	u64 dva_size;
	u32 mem_desc_id;
} __packed;

struct DCP_FW_NAME(dcp_set_power_state_req) {
	u64 unklong;
	u8 unkbool;
#if DCP_FW_VER < DCP_FW_VERSION(27, 2, 0)
	u8 unkint_null;
	u8 padding[2];
#else
	/*
	 * 27.2's A534: three flags, the last new, then the output's null flag
	 * (rda t603xdcp_272 sub_1CF264). macOS's power management sets the
	 * new one, its API and shutdown paths clear it (K27
	 * IOMobileFramebufferAP::setPowerState's callers); 14.8.3's request
	 * holds it as 0 (t603xdcp_1483 sub_13BF34), as does the driver.
	 */
	u8 unk_9;
	u8 unk_a;
	u8 unk_b;
	u8 unkint_null;
	u8 padding[3];
#endif
} __packed;


struct apple_dcp;

int DCP_FW_NAME(iomfb_modeset)(struct apple_dcp *dcp,
			       struct drm_crtc_state *crtc_state);
void DCP_FW_NAME(iomfb_flush)(struct apple_dcp *dcp, struct drm_crtc *crtc, struct drm_atomic_commit *commit);
void DCP_FW_NAME(iomfb_poweron)(struct apple_dcp *dcp);
void DCP_FW_NAME(iomfb_poweroff)(struct apple_dcp *dcp);
void DCP_FW_NAME(iomfb_sleep)(struct apple_dcp *dcp);
void DCP_FW_NAME(iomfb_start)(struct apple_dcp *dcp);
void DCP_FW_NAME(iomfb_shutdown)(struct apple_dcp *dcp);

#endif
