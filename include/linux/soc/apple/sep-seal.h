/* SPDX-License-Identifier: GPL-2.0-only */
/* Sealing to this Mac's Secure Enclave: 32-byte keys wrapped by the SEP's key store (drivers/soc/apple/sep/seal.c). */
#ifndef _LINUX_SOC_APPLE_SEP_SEAL_H
#define _LINUX_SOC_APPLE_SEP_SEAL_H

#include <linux/types.h>

#define APPLE_SEP_SEAL_KEY_LEN 32
/* the longest wrapped key taken */
#define APPLE_SEP_SEAL_BLOB_MAX 128

/* whether this machine has a SEP the driver serves (its device tree node is enabled) */
bool apple_sep_seal_present(void);
/*
 * A 32-byte key wrapped (the wrapped length, at most APPLE_SEP_SEAL_BLOB_MAX, into out) or unwrapped (0); a negative
 * errno otherwise: -ENODEV when the SEP's key store did not come up within the wait or holds no key bag.
 */
int apple_sep_seal_wrap(const u8 *key, u8 *out);
int apple_sep_seal_unwrap(const u8 *blob, size_t len, u8 *key);

/* the driver's side: `fn` wraps (len 32) or unwraps into out (room bytes), the length or a negative errno */
typedef int (*apple_sep_seal_fn_t)(void *ctx, bool wrap, const u8 *in, size_t len, u8 *out, size_t room);
void apple_sep_seal_register(void *ctx, apple_sep_seal_fn_t fn);
/* the driver went, or its bring-up stopped: callers no longer wait */
void apple_sep_seal_unregister(void);

#endif
