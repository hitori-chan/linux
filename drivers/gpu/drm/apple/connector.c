// SPDX-License-Identifier: GPL-2.0+ OR MIT
/*
 * Copyright (C) The Asahi Linux Contributors
 */

#include "connector.h"

#include "linux/err.h"
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/seq_file.h>
#include <linux/string_helpers.h>
#include <linux/uaccess.h>

#include <drm/drm_managed.h>

#include "dcp-internal.h"

#include <linux/soc/apple/rtkit.h>

enum dcp_chunk_type {
	DCP_CHUNK_COLOR_ELEMENTS,
	DCP_CHUNK_TIMING_ELELMENTS,
	DCP_CHUNK_DISPLAY_ATTRIBUTES,
	DCP_CHUNK_TRANSPORT,
	DCP_CHUNK_NUM_TYPES,
};

static int chunk_show(struct seq_file *m,
		      enum dcp_chunk_type chunk_type)
{
	struct apple_connector *apple_con = m->private;
	struct dcp_chunks *chunk = NULL;

	mutex_lock(&apple_con->chunk_lock);

	switch (chunk_type) {
	case DCP_CHUNK_COLOR_ELEMENTS:
		chunk = &apple_con->color_elements;
		break;
	case DCP_CHUNK_TIMING_ELELMENTS:
		chunk = &apple_con->timing_elements;
		break;
	case DCP_CHUNK_DISPLAY_ATTRIBUTES:
		chunk = &apple_con->display_attributes;
		break;
	case DCP_CHUNK_TRANSPORT:
		chunk = &apple_con->transport;
		break;
	default:
		break;
	}

	if (chunk)
                seq_write(m, chunk->data, chunk->length);

	mutex_unlock(&apple_con->chunk_lock);

	return 0;
}

#define CONNECTOR_DEBUGFS_ENTRY(name, type) \
static int chunk_ ## name ## _show(struct seq_file *m, void *data) \
{ \
        return chunk_show(m, type); \
} \
static int chunk_ ## name ## _open(struct inode *inode, struct file *file) \
{ \
        return single_open(file,  chunk_ ## name ## _show, inode->i_private); \
} \
static const struct file_operations chunk_ ## name ## _fops = { \
        .owner = THIS_MODULE, \
        .open = chunk_ ## name ## _open, \
        .read = seq_read, \
        .llseek = seq_lseek, \
        .release = single_release, \
}

CONNECTOR_DEBUGFS_ENTRY(color, DCP_CHUNK_COLOR_ELEMENTS);
CONNECTOR_DEBUGFS_ENTRY(timing, DCP_CHUNK_TIMING_ELELMENTS);
CONNECTOR_DEBUGFS_ENTRY(display_attribs, DCP_CHUNK_DISPLAY_ATTRIBUTES);
CONNECTOR_DEBUGFS_ENTRY(transport, DCP_CHUNK_TRANSPORT);

static void dcp_afk_debugfs_root(struct platform_device *pdev, int ep, struct dentry *root)
{
#if IS_ENABLED(CONFIG_DRM_APPLE_DEBUG)
	struct dentry *entry = NULL;
	struct apple_dcp *dcp = platform_get_drvdata(pdev);

	switch (ep) {
	case AV_ENDPOINT:
		entry = debugfs_create_dir("avep", root);
		break;
	default:
		break;
	}

	if (!IS_ERR_OR_NULL(entry))
		dcp->ep_debugfs[ep - 0x20] = entry;
#endif
}

/*
 * keep_awake: 1 while Linux holds the DCP's RTKit keep-awake reference
 * (apple,rtkit-keep-awake). Writing 0 drops it, so the firmware naps at idle
 * as it does without one, and 1 takes it again: the nap test of the idle
 * SoC's DISP_CPU. A napping DCP that misses its doorbells needs a reboot.
 */
static DEFINE_MUTEX(dcp_keep_awake_lock);

static int dcp_keep_awake_get(void *data, u64 *val)
{
	struct apple_dcp *dcp = data;

	*val = !READ_ONCE(dcp->awake_released);
	return 0;
}

static int dcp_keep_awake_set(void *data, u64 val)
{
	struct apple_dcp *dcp = data;
	bool release = !val;
	int ret = 0;

	mutex_lock(&dcp_keep_awake_lock);
	if (dcp->awake_released != release) {
		ret = release ? apple_rtkit_release_awake(dcp->rtk) :
				apple_rtkit_hold_awake(dcp->rtk);
		if (!ret)
			WRITE_ONCE(dcp->awake_released, release);
	}
	mutex_unlock(&dcp_keep_awake_lock);
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(dcp_keep_awake_fops, dcp_keep_awake_get,
			 dcp_keep_awake_set, "%llu\n");

void apple_connector_debugfs_init(struct drm_connector *connector, struct dentry *root)
{
	struct apple_connector *apple_con = to_apple_connector(connector);
	struct apple_dcp *dcp = platform_get_drvdata(apple_con->dcp);

	if (of_property_read_bool(dcp->dev->of_node, "apple,rtkit-keep-awake"))
		debugfs_create_file_unsafe("keep_awake", 0600, root, dcp,
					   &dcp_keep_awake_fops);

        debugfs_create_file("ColorElements", 0444, root, apple_con,
                            &chunk_color_fops);
        debugfs_create_file("TimingElements", 0444, root, apple_con,
                            &chunk_timing_fops);
        debugfs_create_file("DisplayAttributes", 0444, root, apple_con,
                            &chunk_display_attribs_fops);
        debugfs_create_file("Transport", 0444, root, apple_con,
                            &chunk_transport_fops);

	switch (connector->connector_type) {
	case DRM_MODE_CONNECTOR_DisplayPort:
	case DRM_MODE_CONNECTOR_HDMIA:
		dcp_afk_debugfs_root(apple_con->dcp, AV_ENDPOINT, root);
		break;
	default:
		break;
	}
}

static void dcp_connector_set_dict(struct apple_connector *connector,
				   struct dcp_chunks *dict,
				   struct dcp_chunks *chunks)
{
	if (dict->data)
		devm_kfree(&connector->dcp->dev, dict->data);

	*dict = *chunks;
}

void dcp_connector_update_dict(struct apple_connector *connector, const char *key,
			       struct dcp_chunks *chunks)
{
	mutex_lock(&connector->chunk_lock);
	if (!strcmp(key, "ColorElements"))
		dcp_connector_set_dict(connector, &connector->color_elements, chunks);
	else if (!strcmp(key, "TimingElements"))
		dcp_connector_set_dict(connector, &connector->timing_elements, chunks);
	else if (!strcmp(key, "DisplayAttributes"))
		dcp_connector_set_dict(connector, &connector->display_attributes, chunks);
	else if (!strcmp(key, "Transport"))
		dcp_connector_set_dict(connector, &connector->transport, chunks);

	chunks->data = NULL;
	chunks->length = 0;

	mutex_unlock(&connector->chunk_lock);
}
