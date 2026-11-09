/* SPDX-License-Identifier: GPL-2.0-only */
/* The SEP's FIDO2 authenticator's HID device and ciphers (fido.c); sep/fido.rs declares the same. */
#ifndef _APPLE_SEP_FIDO_H
#define _APPLE_SEP_FIDO_H

#include <linux/device.h>
#include <linux/types.h>

struct apple_sep_fido;

/* one 64-byte CTAPHID packet from the host */
typedef void (*apple_sep_fido_rx_t)(void *ctx, const u8 *pkt);

struct apple_sep_fido *apple_sep_fido_create(struct device *parent, void *ctx, apple_sep_fido_rx_t rx);
void apple_sep_fido_destroy(struct apple_sep_fido *f);
int apple_sep_fido_send(struct apple_sep_fido *f, const u8 *pkt);
int apple_sep_fido_aes256_cbc(const u8 *key, int encrypt, u8 *buf, size_t len);
void apple_sep_fido_hmac_sha256(const u8 *key, size_t key_len, const u8 *data, size_t len, u8 *out);

#endif
