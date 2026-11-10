// SPDX-License-Identifier: GPL-2.0-only
/*
 * Trusted keys sealed to an Apple Secure Enclave. The SEP's key store wraps 32 bytes at a time, so a key's payload
 * is encrypted by AES-256-GCM under a random key, and that key is wrapped by the SEP: only this Mac's SEP, with the
 * key bag the driver holds, unwraps it. The blob: u8 the version, u8 the wrapped key's length, the wrapped key, the
 * 12-byte nonce, the payload's ciphertext, the 16-byte tag. The version and the wrapped key are the tag's
 * associated data.
 */
#include <crypto/aes-gcm.h>
#include <keys/trusted-type.h>
#include <keys/trusted_apple_sep.h>
#include <linux/key-type.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/soc/apple/sep-seal.h>

#define SEP_BLOB_VERSION 1
#define SEP_NONCE_LEN 12
#define SEP_TAG_LEN 16

static int trusted_apple_sep_seal(struct trusted_key_payload *p, char *datablob)
{
	u8 key[APPLE_SEP_SEAL_KEY_LEN], *b = p->blob, *nonce;
	struct aes_gcm_key *ctx;
	int wrapped, ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	get_random_bytes(key, sizeof(key));
	wrapped = apple_sep_seal_wrap(key, b + 2);
	if (wrapped <= 0 || wrapped > 255) {
		ret = wrapped < 0 ? wrapped : -EIO;
		goto out;
	}
	if (2 + wrapped + SEP_NONCE_LEN + p->key_len + SEP_TAG_LEN > MAX_BLOB_SIZE) {
		ret = -E2BIG;
		goto out;
	}
	b[0] = SEP_BLOB_VERSION;
	b[1] = wrapped;
	nonce = b + 2 + wrapped;
	get_random_bytes(nonce, SEP_NONCE_LEN);
	ret = aes_gcm_preparekey(ctx, key, sizeof(key), SEP_TAG_LEN);
	if (ret)
		goto out;
	aes_gcm_encrypt(nonce + SEP_NONCE_LEN, p->key, p->key_len, nonce + SEP_NONCE_LEN + p->key_len, b, 2 + wrapped,
			nonce, ctx);
	p->blob_len = 2 + wrapped + SEP_NONCE_LEN + p->key_len + SEP_TAG_LEN;
out:
	memzero_explicit(key, sizeof(key));
	kfree_sensitive(ctx);
	return ret;
}

static int trusted_apple_sep_unseal(struct trusted_key_payload *p, char *datablob)
{
	u8 key[APPLE_SEP_SEAL_KEY_LEN], *b = p->blob, *nonce;
	struct aes_gcm_key *ctx;
	size_t wrapped, len;
	int ret;

	if (p->blob_len < 2 || b[0] != SEP_BLOB_VERSION)
		return -EINVAL;
	wrapped = b[1];
	if (!wrapped || p->blob_len < 2 + wrapped + SEP_NONCE_LEN + SEP_TAG_LEN)
		return -EINVAL;
	len = p->blob_len - (2 + wrapped + SEP_NONCE_LEN + SEP_TAG_LEN);
	if (len < MIN_KEY_SIZE || len > MAX_KEY_SIZE)
		return -EINVAL;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ret = apple_sep_seal_unwrap(b + 2, wrapped, key);
	if (ret)
		goto out;
	nonce = b + 2 + wrapped;
	ret = aes_gcm_preparekey(ctx, key, sizeof(key), SEP_TAG_LEN);
	if (ret)
		goto out;
	ret = aes_gcm_decrypt(p->key, nonce + SEP_NONCE_LEN, len, nonce + SEP_NONCE_LEN + len, b, 2 + wrapped, nonce,
			      ctx);
	if (ret) {
		memzero_explicit(p->key, len);
		goto out;
	}
	p->key_len = len;
out:
	memzero_explicit(key, sizeof(key));
	kfree_sensitive(ctx);
	return ret;
}

static int trusted_apple_sep_init(void)
{
	if (!apple_sep_seal_present())
		return -ENODEV;
	return register_key_type(&key_type_trusted);
}

static void trusted_apple_sep_exit(void)
{
	unregister_key_type(&key_type_trusted);
}

struct trusted_key_ops apple_sep_trusted_key_ops = {
	.migratable = 0,
	.init = trusted_apple_sep_init,
	.seal = trusted_apple_sep_seal,
	.unseal = trusted_apple_sep_unseal,
	.exit = trusted_apple_sep_exit,
};
