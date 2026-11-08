/* SPDX-License-Identifier: GPL-2.0-only */
/* The xART store's disk side for sep.rs's stage 13 (disk.c); sep/xart.rs declares the same. */
#ifndef _APPLE_SEP_DISK_H
#define _APPLE_SEP_DISK_H

#include <linux/types.h>

int apple_sep_disk_open(u32 major, u32 minor);
int apple_sep_disk_read(u64 off, u8 *buf, size_t len);
int apple_sep_disk_write(u64 off, const u8 *buf, size_t len);
int apple_sep_disk_sync(void);
void apple_sep_disk_close(void);

#endif
