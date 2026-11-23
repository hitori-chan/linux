// SPDX-License-Identifier: GPL-2.0-only
/* Copyright The Asahi Linux Contributors */

/*
 * The DCP's interface on macOS 27.2's firmware. Its methods are renumbered,
 * as macOS 27.2's kexts send them (IOMobileFramebufferAP::*_0); the swap
 * record, the swap submit and completion, the RT bandwidth reply, the
 * buffer callbacks and setPowerState change their layout (iomfb_template.h).
 */

/* Include all per-version headers before defining DCP_FW ourself. */
#include "iomfb_v12_3.h"
#include "iomfb_v13_3.h"
#include "iomfb_v14_7.h"
#include "iomfb_v27_2.h"
#include "version_utils.h"

static const struct dcp_method_entry dcp_methods[dcpep_num_methods] = {
	IOMFB_METHOD("A000", dcpep_late_init_signal),
	IOMFB_METHOD("A027", dcpep_setup_video_limits),
	IOMFB_METHOD("A135", dcpep_init_ca_pmu),
	IOMFB_METHOD("A136", iomfbep_a131_pmu_service_matched),
	IOMFB_METHOD("A137", iomfbep_a132_backlight_service_matched),
	IOMFB_METHOD("A390", dcpep_set_create_dfb),
	IOMFB_METHOD("A391", iomfbep_a358_vi_set_temperature_hint),
	IOMFB_METHOD("A451", dcpep_start_signal),
	IOMFB_METHOD("A456", dcpep_swap_start),
	IOMFB_METHOD("A457", dcpep_swap_submit),
	IOMFB_METHOD("A461", dcpep_set_display_device),
	IOMFB_METHOD("A462", dcpep_is_main_display),
	IOMFB_METHOD("A463", dcpep_set_digital_out_mode),
	IOMFB_METHOD("A473", iomfbep_set_matrix),
	IOMFB_METHOD("A477", iomfbep_get_color_remap_mode),
	IOMFB_METHOD("A491", dcpep_set_block_dcp),
	IOMFB_METHOD("A500", dcpep_set_parameter_dcp),
	IOMFB_METHOD("A504", dcpep_create_default_fb),
	IOMFB_METHOD("A508", dcpep_enable_disable_video_power_savings),
	IOMFB_METHOD("A516", dcpep_first_client_open),
	IOMFB_METHOD("A517", iomfbep_last_client_close),
	IOMFB_METHOD("A525", dcpep_set_display_refresh_properties),
	IOMFB_METHOD("A528", dcpep_flush_supports_power),
	IOMFB_METHOD("A529", iomfbep_abort_swaps_dcp),
	IOMFB_METHOD("A534", dcpep_set_power_state),
};

#define DCP_FW v27_2_0
#define DCP_FW_VER DCP_FW_VERSION(27, 2, 0)

#include "iomfb_template.c"

/* The firmware's A457 and A534 handlers check these (rda t603xdcp_272 sub_1D4FC8, sub_1CF264) */
static_assert(sizeof(struct dcp_swap_v27_2_0) == 0x6e0);
static_assert(sizeof(struct dcp_swap_submit_req_v27_2_0) == 0x1d30);
static_assert(sizeof(struct dcp_swap_submit_resp_v27_2_0) == 0xc);
static_assert(sizeof(struct dcp_swap_start_req_v27_2_0) == 0x10);
static_assert(sizeof(struct dcp_swap_start_resp_v27_2_0) == 0x8);
static_assert(sizeof(struct dcp_set_power_state_req_v27_2_0) == 0x10);
static_assert(offsetof(struct dcp_set_power_state_req_v27_2_0, unkint_null) == 0xc);
static_assert(sizeof(struct dcp_set_power_state_resp) == 0x8);
static_assert(sizeof(struct dcp_surface_v27_2_0) == 0x22c);

/* The swap record's fields the driver sets (rda t603xdcp_272 sub_1C7670, sub_225884) */
static_assert(offsetof(struct dcp_swap_v27_2_0, swap_type) == 0x17c);
static_assert(offsetof(struct dcp_swap_v27_2_0, pres_relative) == 0x338);
static_assert(offsetof(struct dcp_swap_v27_2_0, bl_update) == 0x354);
static_assert(offsetof(struct dcp_swap_v27_2_0, edr_update) == 0x359);
static_assert(offsetof(struct dcp_swap_v27_2_0, brightness) == 0x35e);
static_assert(offsetof(struct dcp_swap_v27_2_0, edr_factor) == 0x376);

/* A457 after the record moves by 0x1d8 (rda t603xdcp_272 sub_1D4FC8) */
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, surf) == 0x6e0);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, surf_iova) == 0xf90);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, surf2) == 0xfd0);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, surf2_iova) == 0x1cd8);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, unkbool) == 0x1d08);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, clear) == 0x1d1a);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, swap_null) == 0x1d22);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, surf_null) == 0x1d23);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, surf2_null) == 0x1d27);
static_assert(offsetof(struct dcp_swap_submit_req_v27_2_0, unkoutbool_null) == 0x1d2d);

/* The callbacks' sizes, as the firmware sends them (rda t603xdcp_272 sub_189398's callers) */
static_assert(sizeof(struct dc_swap_complete_resp_v27_2_0) == 0x730);
/* SwapCompleteData +0x21, the idle cache's flag */
static_assert(offsetof(struct dc_swap_complete_resp_v27_2_0, swap_info) + 0x19 == 0x26);
static_assert(sizeof(struct dcp_swap_info_req_v27_2_0) == 0xe4);
static_assert(sizeof(struct dcp_swap_info_v27_2_0) == 0xe0);
static_assert(sizeof(struct dcp_rt_bandwidth_v27_2_0) == 0x2c);
static_assert(offsetof(struct dcp_rt_bandwidth_v27_2_0, scratch_offset) == 0x14);
static_assert(offsetof(struct dcp_rt_bandwidth_v27_2_0, mbox_len) == 0x1c);
static_assert(offsetof(struct dcp_rt_bandwidth_v27_2_0, ret) == 0x28);
static_assert(sizeof(struct dcp_map_buf_req) == 0xc);
static_assert(sizeof(struct dcp_map_buf_resp_v27_2_0) == 0x10);
static_assert(offsetof(struct dcp_map_buf_resp_v27_2_0, dva) == 0x4);
static_assert(sizeof(struct dcp_unmap_buf_resp_v27_2_0) == 0x18);
static_assert(offsetof(struct dcp_unmap_buf_resp_v27_2_0, dva) == 0xc);
static_assert(sizeof(struct dcp_allocate_buffer_req) == 0x14);
static_assert(sizeof(struct dcp_allocate_buffer_resp_v27_2_0) == 0x14);
static_assert(sizeof(struct dcp_map_reg_req_v27_2_0) == 0x10);
static_assert(sizeof(struct dcp_map_reg_resp_v27_2_0) == 0x1c);

/*
 * The callbacks by 27.2's tags: 14.7's 107-129 are one less, 574-577 one or
 * two less, 578-581 one more and 582-598 four or five more. D589 is new,
 * swap_complete is D594. An unknown one is acked zeroed (dcpep_handle_cb).
 */
static const iomfb_cb_handler cb_handlers[IOMFB_MAX_CB] = {
	[0] = trampoline_true, /* did_boot_signal */
	[1] = trampoline_true, /* did_power_on_signal */
	[2] = trampoline_nop, /* will_power_off_signal */
	[3] = trampoline_rt_bandwidth,
	[4] = trampoline_nop, /* UPPipeAP_H13P::mcc_report_replay(bool, u32) */
	[6] = trampoline_nop, /* set_frame_sync_props */
	[100] = iomfbep_cb_match_pmu_service,
	[101] = trampoline_zero, /* get_display_default_stride */
	[102] = trampoline_nop, /* set_number_property */
	[103] = trampoline_nop, /* trigger_user_cal_loader */
	[104] = trampoline_nop, /* set_boolean_property */
	[106] = trampoline_nop, /* remove_property */
	[107] = trampoline_true, /* create_provider_service */
	[108] = trampoline_true, /* create_product_service */
	[109] = trampoline_true, /* create_pmu_service */
	[110] = trampoline_true, /* create_iomfb_service */
	[111] = trampoline_create_backlight_service,
	[112] = trampoline_true, /* create_nvram_service */
	[114] = trampoline_get_tiling_state,
	[115] = trampoline_false, /* set_tiling_state */
	[116] = trampoline_set_idle_caching_state,
	[120] = dcpep_cb_boot_1, /* start_hardware_boot */
	[121] = trampoline_false, /* is_dark_boot */
	[122] = trampoline_false, /* is_waking_from_hibernate */
	[124] = trampoline_read_edt_data,
	[126] = trampoline_prop_start,
	[127] = trampoline_prop_chunk,
	[128] = trampoline_prop_end,
	[130] = trampoline_nop, /* update_ext_pipe_count */
	/* the mode export's platform limits, a counter in macOS */
	[132] = trampoline_nop, /* apply_suppress */
	/* an Apple display's vendor and product: never the panel */
	[133] = trampoline_zero, /* vi_is_displayX1 */
	[201] = trampoline_map_piodma,
	[202] = trampoline_unmap_piodma,
	[204] = trampoline_get_ideal_screen_space,
	[206] = iomfbep_cb_match_pmu_service_2,
	[207] = iomfbep_cb_match_backlight_service,
	[208] = trampoline_nop, /* update_backlight_factor_prop */
	[209] = trampoline_get_time,
	[300] = trampoline_pr_publish,
	[401] = trampoline_get_uint_prop,
	[404] = trampoline_nop, /* sr_set_uint_prop */
	[406] = trampoline_set_fx_prop,
	[408] = trampoline_get_frequency,
	[411] = trampoline_map_reg,
	[413] = trampoline_true, /* sr_set_property_dict */
	[414] = trampoline_sr_set_property_int,
	[415] = trampoline_true, /* sr_set_property_bool */
	[451] = trampoline_allocate_buffer,
	/* MemDescRelay::prepare and complete: the buffers are coherent */
	[452] = trampoline_zero,
	[453] = trampoline_zero,
	[454] = trampoline_release_mem_desc,
	[552] = trampoline_true, /* set_property_dict_0 */
	[561] = trampoline_true, /* set_property_dict */
	[563] = trampoline_true, /* set_property_int */
	[565] = trampoline_true, /* set_property_bool */
	[567] = trampoline_true, /* set_property_str */
	[572] = trampoline_zero, /* power_up_dart */
	[575] = trampoline_hotplug,
	[576] = trampoline_nop, /* powerstate_notify */
	[579] = trampoline_true, /* idle_fence_create(IdleCachingState): must be true */
	[580] = trampoline_nop, /* idle_fence_complete */
	[581] = trampoline_idle_surface_release,
	[582] = trampoline_nop, /* swap_complete_head_of_line */
	[586] = trampoline_true, /* create_default_fb_surface */
	[588] = trampoline_nop, /* swap_notify_gated */
	[589] = trampoline_swap_info_notify,
	[593] = trampoline_nop, /* update_ap_hdcp_encryption_status */
	[594] = trampoline_swap_complete,
	[596] = trampoline_swap_complete_intent_gated,
	[597] = trampoline_abort_swap_ap_gated,
	[598] = trampoline_enable_backlight_message_ap_gated,
	[599] = trampoline_nop, /* IOMobileFramebufferAP::setSystemConsoleMode */
	[601] = trampoline_false, /* IOMobileFramebufferAP::isDFBAllocated */
	[602] = trampoline_false, /* IOMobileFramebufferAP::preserveContents */
	[603] = trampoline_nop, /* find_swap_function_gated */
};

void DCP_FW_NAME(iomfb_start)(struct apple_dcp *dcp)
{
	dcp->cb_handlers = cb_handlers;

	dcp_start_signal(dcp, false, dcp_started, NULL);
}

#undef DCP_FW_VER
#undef DCP_FW
