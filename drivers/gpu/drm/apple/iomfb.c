// SPDX-License-Identifier: GPL-2.0-only OR MIT
/* Copyright 2021 Alyssa Rosenzweig */

#include <linux/align.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/soc/apple/rtkit.h>

#include <drm/drm_edid.h>
#include <drm/drm_fb_dma_helper.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_gem_dma_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_vblank.h>

#include "dcp.h"
#include "dcp-internal.h"
#include "iomfb.h"
#include "iomfb_internal.h"
#include "parser.h"
#include "trace.h"

static int dcp_tx_offset(enum dcp_context_id id)
{
	switch (id) {
	case DCP_CONTEXT_CB:
	case DCP_CONTEXT_CMD:
		return 0x00000;
	case DCP_CONTEXT_OOBCB:
	case DCP_CONTEXT_OOBCMD:
		return 0x08000;
	default:
		return -EINVAL;
	}
}

static int dcp_channel_offset(enum dcp_context_id id)
{
	switch (id) {
	case DCP_CONTEXT_ASYNC:
		return 0x40000;
	case DCP_CONTEXT_OOBASYNC:
		return 0x48000;
	case DCP_CONTEXT_CB:
		return 0x60000;
	case DCP_CONTEXT_OOBCB:
		return 0x68000;
	default:
		return dcp_tx_offset(id);
	}
}

static inline u64 dcpep_set_shmem(u64 dart_va)
{
	return FIELD_PREP(IOMFB_MESSAGE_TYPE, IOMFB_MESSAGE_TYPE_SET_SHMEM) |
	       FIELD_PREP(IOMFB_SHMEM_FLAG, IOMFB_SHMEM_FLAG_VALUE) |
	       FIELD_PREP(IOMFB_SHMEM_DVA, dart_va);
}

static inline u64 dcpep_msg(enum dcp_context_id id, u32 length, u16 offset)
{
	return FIELD_PREP(IOMFB_MESSAGE_TYPE, IOMFB_MESSAGE_TYPE_MSG) |
		FIELD_PREP(IOMFB_MSG_CONTEXT, id) |
		FIELD_PREP(IOMFB_MSG_OFFSET, offset) |
		FIELD_PREP(IOMFB_MSG_LENGTH, length);
}

static inline u64 dcpep_ack(enum dcp_context_id id)
{
	return dcpep_msg(id, 0, 0) | IOMFB_MSG_ACK;
}

/*
 * A channel is busy if we have sent a message that has yet to be
 * acked. The driver must not sent a message to a busy channel.
 */
static bool dcp_channel_busy(struct dcp_channel *ch)
{
	return (ch->depth != 0);
}

/*
 * Get the context ID passed to the DCP for a command we push. The rule is
 * simple: callback contexts are used when replying to the DCP, command
 * contexts are used otherwise. That corresponds to a non/zero call stack
 * depth. This rule frees the caller from tracking the call context manually.
 */
static enum dcp_context_id dcp_call_context(struct apple_dcp *dcp, bool oob)
{
	u8 depth = oob ? dcp->ch_oobcmd.depth : dcp->ch_cmd.depth;

	if (depth)
		return oob ? DCP_CONTEXT_OOBCB : DCP_CONTEXT_CB;
	else
		return oob ? DCP_CONTEXT_OOBCMD : DCP_CONTEXT_CMD;
}

/* Get a channel for a context */
static struct dcp_channel *dcp_get_channel(struct apple_dcp *dcp,
					   enum dcp_context_id context)
{
	switch (context) {
	case DCP_CONTEXT_CB:
		return &dcp->ch_cb;
	case DCP_CONTEXT_CMD:
		return &dcp->ch_cmd;
	case DCP_CONTEXT_OOBCB:
		return &dcp->ch_oobcb;
	case DCP_CONTEXT_OOBCMD:
		return &dcp->ch_oobcmd;
	case DCP_CONTEXT_ASYNC:
		return &dcp->ch_async;
	case DCP_CONTEXT_OOBASYNC:
		return &dcp->ch_oobasync;
	default:
		return NULL;
	}
}

/* Get the start of a packet: after the end of the previous packet */
static u16 dcp_packet_start(struct dcp_channel *ch, u8 depth)
{
	if (depth > 0)
		return ch->end[depth - 1];
	else
		return 0;
}

/* Pushes and pops the depth of the call stack with safety checks */
static u8 dcp_push_depth(u8 *depth)
{
	u8 ret = (*depth)++;

	WARN_ON(ret >= DCP_MAX_CALL_DEPTH);
	return ret;
}

static u8 dcp_pop_depth(u8 *depth)
{
	WARN_ON((*depth) == 0);

	return --(*depth);
}

/* Call a DCP function given by a tag */
void dcp_push(struct apple_dcp *dcp, bool oob, const struct dcp_method_entry *call,
		     u32 in_len, u32 out_len, void *data, dcp_callback_t cb,
		     void *cookie)
{
	enum dcp_context_id context = dcp_call_context(dcp, oob);
	struct dcp_channel *ch = dcp_get_channel(dcp, context);

	struct dcp_packet_header header = {
		.in_len = in_len,
		.out_len = out_len,

		/* Tag is reversed due to endianness of the fourcc */
		.tag[0] = call->tag[3],
		.tag[1] = call->tag[2],
		.tag[2] = call->tag[1],
		.tag[3] = call->tag[0],
	};

	u8 depth = dcp_push_depth(&ch->depth);
	u16 offset = dcp_packet_start(ch, depth);

	void *out = dcp->shmem + dcp_tx_offset(context) + offset;
	void *out_data = out + sizeof(header);
	size_t data_len = sizeof(header) + in_len + out_len;

	memcpy(out, &header, sizeof(header));

	if (in_len > 0)
		memcpy(out_data, data, in_len);

	trace_iomfb_push(dcp, call, context, offset, depth);

	ch->callbacks[depth] = cb;
	ch->cookies[depth] = cookie;
	ch->output[depth] = out + sizeof(header) + in_len;
	ch->end[depth] = offset + ALIGN(data_len, DCP_PACKET_ALIGNMENT);

	dcp_send_message(dcp, IOMFB_ENDPOINT,
			 dcpep_msg(context, data_len, offset));
}

/* Parse a callback tag "D123" into the ID 123. Returns -EINVAL on failure. */
int dcp_parse_tag(char tag[4])
{
	u32 d[3];
	int i;

	if (tag[3] != 'D')
		return -EINVAL;

	for (i = 0; i < 3; ++i) {
		d[i] = (u32)(tag[i] - '0');

		if (d[i] > 9)
			return -EINVAL;
	}

	return d[0] + (d[1] * 10) + (d[2] * 100);
}

/* Ack a callback from the DCP */
void dcp_ack(struct apple_dcp *dcp, enum dcp_context_id context)
{
	struct dcp_channel *ch = dcp_get_channel(dcp, context);

	dcp_pop_depth(&ch->depth);
	dcp_send_message(dcp, IOMFB_ENDPOINT,
			 dcpep_ack(context));
}

/*
 * Helper to send a DRM hotplug event. The DCP is accessed from a single
 * (RTKit) thread. To handle hotplug callbacks, we need to call
 * drm_kms_helper_hotplug_event, which does an atomic commit (via DCP) and
 * waits for vblank (a DCP callback). That means we deadlock if we call from
 * the RTKit thread! Instead, move the call to another thread via a workqueue.
 */
void dcp_hotplug(struct work_struct *work)
{
	struct apple_connector *connector;
	struct apple_dcp *dcp;

	connector = container_of(work, struct apple_connector, hotplug_wq);

	dcp = platform_get_drvdata(connector->dcp);
	dev_info(dcp->dev, "%s() connected:%d valid_mode:%d nr_modes:%u\n", __func__,
		 connector->connected, dcp->valid_mode, dcp->nr_modes);

	if (!connector->connected) {
		drm_edid_free(connector->drm_edid);
		drm_connector_set_vrr_capable_property(&connector->base, false);
		connector->drm_edid = NULL;
	}

	/*
	 * DCP defers link training until we set a display mode. But we set
	 * display modes from atomic_flush, so userspace needs to trigger a
	 * flush, or the CRTC gets no signal.
	 */
	if (connector->base.state && !dcp->valid_mode && connector->connected)
		drm_connector_set_link_status_property(&connector->base,
						       DRM_MODE_LINK_STATUS_BAD);

	drm_kms_helper_connector_hotplug_event(&connector->base);
}

static void dcpep_handle_cb(struct apple_dcp *dcp, enum dcp_context_id context,
			    void *data, u32 length, u16 offset)
{
	struct device *dev = dcp->dev;
	struct dcp_packet_header *hdr = data;
	void *in, *out;
	int tag = dcp_parse_tag(hdr->tag);
	struct dcp_channel *ch = dcp_get_channel(dcp, context);
	u8 depth;

	if (tag < 0 || tag >= IOMFB_MAX_CB || !dcp->cb_handlers || !dcp->cb_handlers[tag]) {
		dev_warn(dev, "received unknown callback %c%c%c%c\n",
			 hdr->tag[3], hdr->tag[2], hdr->tag[1], hdr->tag[0]);
		return;
	}

	in = data + sizeof(*hdr);
	out = in + hdr->in_len;

	// TODO: verify that in_len and out_len match our prototypes
	// for now just clear the out data to have at least consistent results
	if (hdr->out_len)
		memset(out, 0, hdr->out_len);

	depth = dcp_push_depth(&ch->depth);
	ch->output[depth] = out;
	ch->end[depth] = offset + ALIGN(length, DCP_PACKET_ALIGNMENT);

	if (dcp->cb_handlers[tag](dcp, tag, out, in))
		dcp_ack(dcp, context);
}

static void dcpep_handle_ack(struct apple_dcp *dcp, enum dcp_context_id context,
			     void *data, u32 length)
{
	struct dcp_packet_header *header = data;
	struct dcp_channel *ch = dcp_get_channel(dcp, context);
	void *cookie;
	dcp_callback_t cb;

	if (!ch) {
		dev_warn(dcp->dev, "ignoring ack on context %X\n", context);
		return;
	}

	dcp_pop_depth(&ch->depth);

	cb = ch->callbacks[ch->depth];
	cookie = ch->cookies[ch->depth];

	ch->callbacks[ch->depth] = NULL;
	ch->cookies[ch->depth] = NULL;

	if (cb)
		cb(dcp, data + sizeof(*header) + header->in_len, cookie);
}

static void dcpep_got_msg(struct apple_dcp *dcp, u64 message)
{
	enum dcp_context_id ctx_id;
	u16 offset;
	u32 length;
	int channel_offset;
	void *data;

	ctx_id = FIELD_GET(IOMFB_MSG_CONTEXT, message);
	offset = FIELD_GET(IOMFB_MSG_OFFSET, message);
	length = FIELD_GET(IOMFB_MSG_LENGTH, message);

	channel_offset = dcp_channel_offset(ctx_id);

	if (channel_offset < 0) {
		dev_warn(dcp->dev, "invalid context received %u\n", ctx_id);
		return;
	}

	data = dcp->shmem + channel_offset + offset;

	if (FIELD_GET(IOMFB_MSG_ACK, message))
		dcpep_handle_ack(dcp, ctx_id, data, length);
	else
		dcpep_handle_cb(dcp, ctx_id, data, length, offset);
}

/* An EDID chromaticity: CIE x or y in 1/10000, rounded to ten bits */
#define EDID_CIE(v) (((v) * 1024 + 5000) / 10000)
/* A fixed product code, J514's: no DCP call reports the panel's own */
#define DCP_PANEL_PRODUCT 0x0514
/* EDID's year with week 0xff is the model year: the M3 MacBook Pros are 2023's */
#define DCP_PANEL_MODEL_YEAR 2023

/*
 * The internal panel has no EDID, so userspace found neither its gamut nor
 * its HDR. Build one: a base block with one of the DCP's modes, the panel's
 * size and primaries, and a CTA-861 block with the BT.2020 RGB and PQ that
 * the connector's Colorspace and HDR_OUTPUT_METADATA take (apple_drv.c) and
 * the panel's peak. No serial number: it is the unit's. DRM keeps offering
 * the DCP's modes, never the EDID's.
 */
static const struct drm_edid *dcp_panel_edid(struct apple_dcp *dcp)
{
	/* SMPTE EG 432-1: red, green, blue, D65 white */
	static const u16 p3[8] = {
		EDID_CIE(6800), EDID_CIE(3200), EDID_CIE(2650), EDID_CIE(6900),
		EDID_CIE(1500), EDID_CIE(600), EDID_CIE(3127), EDID_CIE(3290),
	};
	struct {
		struct edid base;
		u8 cta[EDID_LENGTH];
	} __packed e = {};
	struct edid *b = &e.base;
	struct detailed_pixel_timing *dtd = &b->detailed_timings[0].data.pixel_data;
	const struct drm_display_mode *m = NULL;
	u32 w = dcp->panel.width_mm, h = dcp->panel.height_mm;
	u32 hbl, hfp, hsw, vbl, vfp, vsw;
	u8 *raw = (u8 *)&e, *c = raw + offsetof(struct edid, red_green_lo);
	u8 *db = e.cta + 4, sum;
	bool peak = dcp->fw_compat == DCP_FIRMWARE_V_14_7 && hdr_sdr_white;
	unsigned int i, j;

	/* A DTD holds 655.35 MHz: the preferred mode if it fits, else the fastest */
	for (i = 0; i < dcp->nr_modes; i++) {
		const struct drm_display_mode *mode = &dcp->modes[i].mode;

		if (mode->clock > 655350 || (m && (m->type & DRM_MODE_TYPE_PREFERRED)))
			continue;
		if (!m || (mode->type & DRM_MODE_TYPE_PREFERRED) || mode->clock > m->clock)
			m = mode;
	}
	if (!m)
		return ERR_PTR(-ERANGE);
	hbl = m->htotal - m->hdisplay;
	hfp = m->hsync_start - m->hdisplay;
	hsw = m->hsync_end - m->hsync_start;
	vbl = m->vtotal - m->vdisplay;
	/* The panel's 102-line front porch passes six bits: the blanking is kept */
	vfp = min(m->vsync_start - m->vdisplay, 63);
	vsw = min(m->vsync_end - m->vsync_start, 63);
	if (m->hdisplay > 4095 || m->vdisplay > 4095 || hbl > 4095 || vbl > 4095 ||
	    hfp > 1023 || hsw > 1023 || !w || w > 4095 || !h || h > 4095)
		return ERR_PTR(-ERANGE);

	memcpy(b->header, "\x00\xff\xff\xff\xff\xff\xff\x00", 8);
	b->product_id.manufacturer_name = cpu_to_be16(('A' - '@') << 10 |
						      ('P' - '@') << 5 | ('P' - '@'));
	b->product_id.product_code = cpu_to_le16(DCP_PANEL_PRODUCT);
	b->product_id.week_of_manufacture = 0xff;
	b->product_id.year_of_manufacture = DCP_PANEL_MODEL_YEAR - 1990;
	b->version = 1;
	b->revision = 4;
	b->input = DRM_EDID_INPUT_DIGITAL;
	b->width_cm = DIV_ROUND_CLOSEST(w, 10);
	b->height_cm = DIV_ROUND_CLOSEST(h, 10);
	b->gamma = 0xff;
	if (dcp->panel.display_p3) {
		/* Display P3's transfer, sRGB's, as gamma 2.2 */
		b->gamma = 120;
		/* bytes 25-26 the low two bits, 27-34 the high eight */
		for (i = 0; i < 8; i++) {
			c[i / 4] |= (p3[i] & 3) << (6 - 2 * (i % 4));
			c[2 + i] = p3[i] >> 2;
		}
	}
	if (m->type & DRM_MODE_TYPE_PREFERRED)
		b->features = DRM_EDID_FEATURE_PREFERRED_TIMING;
	memset(b->standard_timings, 1, sizeof(b->standard_timings));
	b->extensions = 1;

	b->detailed_timings[0].pixel_clock = cpu_to_le16(DIV_ROUND_CLOSEST(m->clock, 10));
	dtd->hactive_lo = m->hdisplay;
	dtd->hblank_lo = hbl;
	dtd->hactive_hblank_hi = (m->hdisplay >> 8) << 4 | hbl >> 8;
	dtd->vactive_lo = m->vdisplay;
	dtd->vblank_lo = vbl;
	dtd->vactive_vblank_hi = (m->vdisplay >> 8) << 4 | vbl >> 8;
	dtd->hsync_offset_lo = hfp;
	dtd->hsync_pulse_width_lo = hsw;
	dtd->vsync_offset_pulse_width_lo = (vfp & 15) << 4 | (vsw & 15);
	dtd->hsync_vsync_offset_pulse_width_hi = (hfp >> 8) << 6 | (hsw >> 8) << 4 |
						 (vfp >> 4) << 2 | vsw >> 4;
	dtd->width_mm_lo = w;
	dtd->height_mm_lo = h;
	dtd->width_height_mm_hi = (w >> 8) << 4 | h >> 8;
	dtd->misc = DRM_EDID_PT_SEPARATE_SYNC;
	if (m->flags & DRM_MODE_FLAG_PHSYNC)
		dtd->misc |= DRM_EDID_PT_HSYNC_POSITIVE;
	if (m->flags & DRM_MODE_FLAG_PVSYNC)
		dtd->misc |= DRM_EDID_PT_VSYNC_POSITIVE;
	for (i = 1; i < 4; i++)
		b->detailed_timings[i].data.other_data.type = 0x10; /* dummy */

	e.cta[0] = 0x02; /* CTA-861 */
	e.cta[1] = 3;
	e.cta[3] = BIT(7); /* a panel: no overscan */
	*db++ = 7 << 5 | 3; /* extended tag, three bytes */
	*db++ = 0x05; /* colorimetry */
	*db++ = BIT(7); /* BT2020_RGB */
	*db++ = 0;
	*db++ = 7 << 5 | (peak ? 4 : 3);
	*db++ = 0x06; /* HDR static metadata */
	*db++ = BIT(0) | BIT(2); /* traditional SDR, SMPTE ST 2084 */
	*db++ = BIT(0); /* static metadata type 1 */
	/* the EDR peak (iomfb_template.c), as 50 * 2^(cv / 32) nits */
	BUILD_BUG_ON_NOT_POWER_OF_2(DCP_EDR_PEAK / 50);
	if (peak)
		*db++ = 32 * ilog2(DCP_EDR_PEAK / 50);
	e.cta[2] = db - e.cta; /* no DTDs */

	for (j = 0; j < sizeof(e); j += EDID_LENGTH) {
		for (sum = 0, i = 0; i < EDID_LENGTH - 1; i++)
			sum += raw[j + i];
		raw[j + EDID_LENGTH - 1] = -sum;
	}
	return drm_edid_alloc(&e, sizeof(e)) ?: ERR_PTR(-ENOMEM);
}

int dcp_get_modes(struct drm_connector *connector)
{
	struct apple_connector *apple_connector = to_apple_connector(connector);
	struct platform_device *pdev = apple_connector->dcp;
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	struct drm_device *dev = connector->dev;
	struct drm_display_mode *mode;
	int i;

	for (i = 0; i < dcp->nr_modes; ++i) {
		mode = drm_mode_duplicate(dev, &dcp->modes[i].mode);

		if (!mode) {
			dev_err(dev->dev, "Failed to duplicate display mode\n");
			return 0;
		}

		drm_mode_probed_add(connector, mode);
	}

	if (dcp->nr_modes && dcp->dcpavserv.enabled &&
	    !apple_connector->drm_edid) {
		const struct drm_edid *edid;
		edid = dcpavserv_copy_edid(dcp->dcpavserv.service);
		if (IS_ERR_OR_NULL(edid)) {
			dev_info(dcp->dev, "copy_edid failed: %pe\n", edid);
		} else {
			drm_edid_free(apple_connector->drm_edid);
			apple_connector->drm_edid = edid;
		}
	}
	if (dcp->nr_modes && apple_connector->drm_edid) {
		drm_edid_connector_update(connector, apple_connector->drm_edid);
	} else if (dcp->nr_modes && dcp_has_panel(dcp)) {
		const struct drm_edid *edid = dcp_panel_edid(dcp);
		bool fw = dcp->width_mm && dcp->height_mm;

		if (IS_ERR(edid)) {
			dev_warn_once(dcp->dev, "no panel EDID: %pe\n", edid);
		} else {
			drm_edid_connector_update(connector, edid);
			drm_edid_free(edid);
			/* It set the EDID's centimetres: the size dcp_set_dimensions() set */
			connector->display_info.width_mm = fw ? dcp->width_mm : dcp->panel.width_mm;
			connector->display_info.height_mm = fw ? dcp->height_mm : dcp->panel.height_mm;
		}
	}

	return dcp->nr_modes;
}

/* The user may own drm_display_mode, so we need to search for our copy */
struct dcp_display_mode *lookup_mode(struct apple_dcp *dcp,
					    const struct drm_display_mode *mode)
{
	int i;

	for (i = 0; i < dcp->nr_modes; ++i) {
		if (drm_mode_match(mode, &dcp->modes[i].mode,
				   DRM_MODE_MATCH_TIMINGS |
					   DRM_MODE_MATCH_CLOCK))
			return &dcp->modes[i];
	}

	return NULL;
}

enum drm_mode_status dcp_mode_valid(struct drm_connector *connector,
				    const struct drm_display_mode *mode)
{
	struct apple_connector *apple_connector = to_apple_connector(connector);
	struct platform_device *pdev = apple_connector->dcp;
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	return lookup_mode(dcp, mode) ? MODE_OK : MODE_BAD;
}

int dcp_crtc_atomic_modeset(struct drm_crtc *crtc,
			    struct drm_atomic_commit *commit)
{
	struct apple_crtc *apple_crtc = to_apple_crtc(crtc);
	struct apple_dcp *dcp = platform_get_drvdata(apple_crtc->dcp);
	struct drm_crtc_state *crtc_state;
	int ret = -EIO;
	bool modeset;

	crtc_state = drm_atomic_get_new_crtc_state(commit, crtc);
	if (!crtc_state)
		return 0;

	modeset = drm_atomic_crtc_needs_modeset(crtc_state) || !dcp->valid_mode;

	if (!modeset)
		return 0;

	/* ignore no mode, poweroff is handled elsewhere */
	if (crtc_state->mode.hdisplay == 0 && crtc_state->mode.vdisplay == 0)
		return 0;

	switch (dcp->fw_compat) {
	case DCP_FIRMWARE_V_12_3:
		ret = iomfb_modeset_v12_3(dcp, crtc_state);
		break;
	case DCP_FIRMWARE_V_13_5:
		ret = iomfb_modeset_v13_3(dcp, crtc_state);
		break;
	case DCP_FIRMWARE_V_14_7:
		ret = iomfb_modeset_v14_7_0(dcp, crtc_state);
		break;
	default:
		WARN_ONCE(true, "Unexpected firmware version: %u\n",
			  dcp->fw_compat);
		break;
	}

	return ret;
}

bool dcp_crtc_mode_fixup(struct drm_crtc *crtc,
			 const struct drm_display_mode *mode,
			 struct drm_display_mode *adjusted_mode)
{
	struct apple_crtc *apple_crtc = to_apple_crtc(crtc);
	struct platform_device *pdev = apple_crtc->dcp;
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	/* TODO: support synthesized modes through scaling */
	return lookup_mode(dcp, mode) != NULL;
}


void dcp_flush(struct drm_crtc *crtc, struct drm_atomic_commit *commit)
{
	struct platform_device *pdev = to_apple_crtc(crtc)->dcp;
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	if (dcp_channel_busy(&dcp->ch_cmd))
	{
		if (!dcp->ch_cmd.warned_busy) {
			dev_err(dcp->dev, "unexpected busy command channel\n");
			dcp->ch_cmd.warned_busy = true;
		}
		/* HACK: issue a delayed vblank event to avoid timeouts in
		 * drm_atomic_helper_wait_for_vblanks().
		 */
		schedule_work(&dcp->vblank_wq);
		return;
	} else if (dcp->ch_cmd.warned_busy) {
		dcp->ch_cmd.warned_busy = false;
	}

	switch (dcp->fw_compat) {
	case DCP_FIRMWARE_V_12_3:
		iomfb_flush_v12_3(dcp, crtc, commit);
		break;
	case DCP_FIRMWARE_V_13_5:
		iomfb_flush_v13_3(dcp, crtc, commit);
		break;
	case DCP_FIRMWARE_V_14_7:
		iomfb_flush_v14_7_0(dcp, crtc, commit);
		break;
	default:
		WARN_ONCE(true, "Unexpected firmware version: %u\n", dcp->fw_compat);
		break;
	}
}

static void iomfb_start(struct apple_dcp *dcp)
{
	switch (dcp->fw_compat) {
	case DCP_FIRMWARE_V_12_3:
		iomfb_start_v12_3(dcp);
		break;
	case DCP_FIRMWARE_V_13_5:
		iomfb_start_v13_3(dcp);
		break;
	case DCP_FIRMWARE_V_14_7:
		iomfb_start_v14_7_0(dcp);
		break;
	default:
		WARN_ONCE(true, "Unexpected firmware version: %u\n", dcp->fw_compat);
		break;
	}
}

bool dcp_is_initialized(struct platform_device *pdev)
{
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	return dcp->active;
}

void iomfb_recv_msg(struct apple_dcp *dcp, u64 message)
{
	enum dcpep_type type = FIELD_GET(IOMFB_MESSAGE_TYPE, message);

	if (type == IOMFB_MESSAGE_TYPE_INITIALIZED)
		iomfb_start(dcp);
	else if (type == IOMFB_MESSAGE_TYPE_MSG)
		dcpep_got_msg(dcp, message);
	else
		dev_warn(dcp->dev, "Ignoring unknown message %llx\n", message);
}

int iomfb_start_rtkit(struct apple_dcp *dcp)
{
	dma_addr_t shmem_iova;
	apple_rtkit_start_ep(dcp->rtk, IOMFB_ENDPOINT);

	dcp->shmem = dma_alloc_coherent(dcp->dev, DCP_SHMEM_SIZE, &shmem_iova,
					GFP_KERNEL);

	dcp_send_message(dcp, IOMFB_ENDPOINT, dcpep_set_shmem(shmem_iova));

	return 0;
}

void iomfb_shutdown(struct apple_dcp *dcp)
{
	/* We're going down */
	dcp->active = false;
	dcp->valid_mode = false;

	switch (dcp->fw_compat) {
	case DCP_FIRMWARE_V_12_3:
		iomfb_shutdown_v12_3(dcp);
		break;
	case DCP_FIRMWARE_V_13_5:
		iomfb_shutdown_v13_3(dcp);
		break;
	case DCP_FIRMWARE_V_14_7:
		iomfb_shutdown_v14_7_0(dcp);
		break;
	default:
		WARN_ONCE(true, "Unexpected firmware version: %u\n", dcp->fw_compat);
		break;
	}
}
