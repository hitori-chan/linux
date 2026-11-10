/* SPDX-License-Identifier: GPL-2.0-only */
/* The FIDO2 authenticator's resident credentials on the disk (store.c); sep.rs declares the same. */
#ifndef _APPLE_SEP_STORE_H
#define _APPLE_SEP_STORE_H

#include <linux/types.h>

/* 0 when `dir` is a directory, else a negative errno */
int apple_sep_store_dir(const char *dir);
/* the file's size (a regular file's, no link followed), -ENOENT with no such file, or another negative errno */
loff_t apple_sep_store_size(const char *path);
/* the whole file into buf: its length, -ENOENT with no such file, -EFBIG past max, or another negative errno */
ssize_t apple_sep_store_read(const char *path, u8 *buf, size_t max);
/* the file made or cut to len bytes of buf (mode 0600) and synced, then `dir`, its directory, synced */
int apple_sep_store_write(const char *dir, const char *path, const u8 *buf, size_t len);

#endif
