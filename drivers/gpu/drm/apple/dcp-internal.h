// SPDX-License-Identifier: GPL-2.0-only OR MIT
/* Copyright 2021 Alyssa Rosenzweig */

#ifndef __APPLE_DCP_INTERNAL_H__
#define __APPLE_DCP_INTERNAL_H__

#include <linux/backlight.h>
#include <linux/device.h>
#include <linux/ioport.h>
#include <linux/mutex.h>
#include <linux/mux/consumer.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/usb/typec_mux.h>

#include "dptxep.h"
#include "iomfb.h"
#include "iomfb_v12_3.h"
#include "iomfb_v13_3.h"
#include "iomfb_v14_7.h"
#include "epic/dpavservep.h"
#include "version_utils.h"

#define DCP_MAX_PLANES 4

struct apple_dcp;
struct apple_dcp_afkep;

struct dcpav_service_epic;

enum {
	SYSTEM_ENDPOINT = 0x20,
	TEST_ENDPOINT = 0x21,
	DCP_EXPERT_ENDPOINT = 0x22,
	DISP0_ENDPOINT = 0x23,
	DPAVSERV_ENDPOINT = 0x28,
	AV_ENDPOINT = 0x29,
	DPTX_ENDPOINT = 0x2a,
	HDCP_ENDPOINT = 0x2b,
	REMOTE_ALLOC_ENDPOINT = 0x2d,
	IOMFB_ENDPOINT = 0x37,
};

/* Temporary backing for a chunked transfer via setDCPAVPropStart/Chunk/End */
struct dcp_chunks {
	size_t length;
	void *data;
};

#define DCP_MAX_MAPPINGS (128) /* should be enough */
#define MAX_DISP_REGISTERS (7)

struct dcp_mem_descriptor {
	size_t size;
	void *buf;
	dma_addr_t dva;
	struct sg_table map;
	u64 reg;
};

/* Limit on call stack depth (arbitrary). Some nesting is required */
#define DCP_MAX_CALL_DEPTH 8

typedef void (*dcp_callback_t)(struct apple_dcp *, void *, void *);

struct dcp_channel {
	dcp_callback_t callbacks[DCP_MAX_CALL_DEPTH];
	void *cookies[DCP_MAX_CALL_DEPTH];
	void *output[DCP_MAX_CALL_DEPTH];
	u16 end[DCP_MAX_CALL_DEPTH];

	/* Current depth of the call stack. Less than DCP_MAX_CALL_DEPTH */
	u8 depth;
	/* Already warned about busy channel */
	bool warned_busy;
};

struct dcp_fb_reference {
	struct list_head head;
	struct drm_framebuffer *fb;
	u32 swap_id;
};

#define MAX_NOTCH_HEIGHT 160

struct dcp_brightness {
	struct backlight_device *bl_dev;
	u32 maximum;
	u32 dac;
	int nits;
	int scale;
	bool update;
	/* the EDR factor last sent, 16.16; 0: none */
	u32 edr;
};

struct audiosrv_data;

/** laptop/AiO integrated panel parameters from DT */
struct dcp_panel {
	/// panel width in millimeter
	int width_mm;
	/// panel height in millimeter
	int height_mm;
	/// panel has a mini-LED backlight
	bool has_mini_led;
};

struct apple_dcp_hw_data {
	u32 num_dptx_ports;
};

/* TODO: move IOMFB members to its own struct */
struct drm_gem_dma_object;
struct dcp_prc;

struct apple_dcp {
	struct device *dev;
	struct platform_device *piodma;
	struct iommu_domain *iommu_dom;
	struct apple_rtkit *rtk;
	struct apple_crtc *crtc;
	struct apple_connector *connector;

	struct apple_dcp_hw_data hw;

	/* firmware version and compatible firmware version */
	enum dcp_firmware_version fw_compat;

	/* Coprocessor control register */
	void __iomem *coproc_reg;

	/* DCP has crashed */
	bool crashed;

	DECLARE_BITMAP(iomfb_surfaces, DCP_MAX_PLANES);

	/************* IOMFB **************************************************
	 * everything below is mostly used inside IOMFB but it could make     *
	 * sense to keep some of the members in apple_dcp.                    *
	 **********************************************************************/

	/* clock rate request by dcp in */
	struct clk *clk;

	/* DCP shared memory */
	void *shmem;

	/* Display registers mappable to the DCP */
	struct resource *disp_registers[MAX_DISP_REGISTERS];
	unsigned int nr_disp_registers;

	struct resource disp_bw_scratch_res;
	struct resource disp_bw_doorbell_res;
	u32 disp_bw_scratch_index;
	u32 disp_bw_scratch_offset;
	u32 disp_bw_doorbell_index;
	u32 disp_bw_doorbell_offset;

	u32 index;

	/* Bitmap of memory descriptors used for mappings made by the DCP */
	DECLARE_BITMAP(memdesc_map, DCP_MAX_MAPPINGS);

	/* Indexed table of memory descriptors */
	struct dcp_mem_descriptor memdesc[DCP_MAX_MAPPINGS];

	struct dcp_channel ch_cmd, ch_oobcmd;
	struct dcp_channel ch_cb, ch_oobcb, ch_async, ch_oobasync;

	/* iomfb EP callback handlers */
	const iomfb_cb_handler *cb_handlers;

	/* Active chunked transfer. There can only be one at a time. */
	struct dcp_chunks chunks;

	/* Queued swap. Owned by the DCP to avoid per-swap memory allocation */
	union {
		struct dcp_swap_submit_req_v12_3 v12_3;
		struct dcp_swap_submit_req_v13_3 v13_3;
		struct dcp_swap_submit_req_v14_7_0 v14_7_0;
	} swap;

	/* swap id of the last completed swap */
	u32 last_swap_id;
	ktime_t swap_start;

	/* Current display mode */
	bool during_modeset;
	bool valid_mode;
	bool use_timestamps;
	struct dcp_set_digital_out_mode_req mode;

	/* completion for active turning true */
	struct completion start_done;

	/* Is the DCP booted? */
	bool active;

	/* eDP display without DP-HDMI conversion */
	bool main_display;

	/* clear all surfaces on init */
	bool surfaces_cleared;

	/* enable CRC calculation */
	bool crc_enabled;

	/* Modes valid for the connected display */
	struct dcp_display_mode *modes;
	unsigned int nr_modes;

	/* Attributes of the connector */
	int connector_type;

	/* Attributes of the connected display */
	int width_mm, height_mm;

	unsigned notch_height;

	/* Workqueue for sending vblank events when a dcp swap is not possible */
	struct work_struct vblank_wq;

	/* List of referenced drm_framebuffers which can be unreferenced
	 * on the next successfully completed swap.
	 */
	struct list_head swapped_out_fbs;

	struct dcp_brightness brightness;

	/* the internal panel's PRC calibration, sent at power-on (adcl.c) */
	struct dcp_prc *prc;

	/* DCP idle caching (replay) of the internal panel */
	struct {
		struct drm_gem_dma_object *bo;
		struct delayed_work work;
		/* the last D117 state; 0: no cache buffer */
		u32 fw_state;
		/* the swap ID of the last type-8 swap */
		u32 swap_id;
		/* the DCP may write bo: do not hand it again */
		bool held;
		/* the next empty flush sends the type-8 swap */
		bool request;
	} idle_cache;
	/* Workqueue for updating the initial brightness */
	struct work_struct bl_register_wq;
	struct mutex bl_register_mutex;
	/* Workqueue for updating the brightness */
	struct work_struct bl_update_wq;

	/* integrated panel if present */
	struct dcp_panel panel;

	struct apple_dcp_afkep *systemep;
	struct completion systemep_done;

	struct apple_dcp_afkep *ibootep;
	struct apple_dcp_afkep *dcpavservep;
	struct dcpavserv dcpavserv;

	struct apple_dcp_afkep *avep;
	struct audiosrv_data *audiosrv;

	struct apple_dcp_afkep *dptxep;

	struct dptx_port dptxport[2];

	/* debugfs entries */
	struct dentry *ep_debugfs[0x20];

	/* these fields are output port specific */
	struct phy *phy;
	struct mux_control *xbar;
	struct typec_mux *typec_mux;

	struct gpio_desc *hdmi_hpd;
	struct gpio_desc *hdmi_pwren;
	struct gpio_desc *dp2hdmi_pwren;

	struct mutex hpd_mutex;

	u32 dptx_phy;
	u32 dptx_die;
	int hdmi_hpd_irq;
};

void dcp_drm_crtc_page_flip(struct apple_dcp *dcp, ktime_t now);

int dcp_backlight_register(struct apple_dcp *dcp);
int dcp_backlight_update(struct apple_dcp *dcp);
bool dcp_has_panel(struct apple_dcp *dcp);

extern bool panel_srgb;
extern unsigned int idle_cache_ms;
extern unsigned int hdr_sdr_white;
void dcp_idle_cache_arm(struct apple_dcp *dcp);

struct dcp_set_block_dcp_req;
bool dcp_prc_pending(struct apple_dcp *dcp);
struct dcp_set_block_dcp_req *dcp_prc_next(struct apple_dcp *dcp);
void dcp_prc_abort(struct apple_dcp *dcp, u32 status);
void dcp_prc_free(struct apple_dcp *dcp);

#define DCP_AUDIO_MAX_CHANS 15

#endif /* __APPLE_DCP_INTERNAL_H__ */
