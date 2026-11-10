/* SPDX-License-Identifier: GPL-2.0-only */
/* The SEP's random numbers as a hwrng (rng.c); sep.rs declares the same. */
#ifndef _APPLE_SEP_RNG_H
#define _APPLE_SEP_RNG_H

#include <linux/device.h>
#include <linux/types.h>

struct apple_sep_rng;

/* up to max bytes into buf (a multiple of 4 at most): the count, 0 for none now, or a negative errno */
typedef int (*apple_sep_rng_read_t)(void *ctx, u8 *buf, size_t max);

struct apple_sep_rng *apple_sep_rng_create(struct device *parent, void *ctx, apple_sep_rng_read_t read);
void apple_sep_rng_destroy(struct apple_sep_rng *r);

#endif
