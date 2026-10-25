// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) The Asahi Linux Contributors
 */

#ifndef __APPLE_PLANE_H__
#define __APPLE_PLANE_H__

#include <drm/drm_plane.h>

#include <linux/iosys-map.h>
#include <linux/types.h>

#include "iomfb_plane.h"

struct drm_gem_dma_object;

/*
 * A cursor image is at most APPLE_CURSOR_SIZE square. DCP scans it out of a
 * driver-owned copy with APPLE_CURSOR_PAD transparent pixels on each side,
 * so that the surface on screen can always be 32x32 or larger.
 */
#define APPLE_CURSOR_SIZE	64
#define APPLE_CURSOR_PAD	32
#define APPLE_CURSOR_DIM	(APPLE_CURSOR_SIZE + 2 * APPLE_CURSOR_PAD)
#define APPLE_CURSOR_BUFS	3

struct apple_plane {
	struct drm_plane base;
	u32 iomfb_surf;
	struct drm_gem_dma_object *cursor_bo[APPLE_CURSOR_BUFS];
	unsigned int cursor_next;
};

#define to_apple_plane(x) container_of(x, struct apple_plane, base)

struct apple_plane_state {
	struct drm_plane_state base;
	struct dcp_surface surf;
	struct dcp_rect src_rect;
	struct dcp_rect dst_rect;
	u64 iova;
	struct iosys_map cursor_map;
};

#define to_apple_plane_state(x) container_of(x, struct apple_plane_state, base)

struct drm_plane *apple_plane_init(struct drm_device *dev,
				   unsigned long possible_crtcs,
				   u32 iomfb_surf,
				   bool supports_l10r,
				   enum drm_plane_type type,
				   bool interchange);

#endif /* __APPLE_PLANE_H__ */
