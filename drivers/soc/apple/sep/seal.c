// SPDX-License-Identifier: GPL-2.0-only
/*
 * Sealing to the SEP for other kernel code (trusted keys): the driver registers its wrap and unwrap once its key
 * store is up, and a caller that comes earlier waits for it.
 */
#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/wait.h>
#include <linux/soc/apple/sep-seal.h>

/* the key store comes up with the driver's bring-up, which waits for the disk */
#define SEAL_WAIT_MS 30000

static DEFINE_MUTEX(seal_lock);
static DECLARE_WAIT_QUEUE_HEAD(seal_wq);
static void *seal_ctx;
static apple_sep_seal_fn_t seal_fn;
/* the driver's bring-up stopped, or the driver went: no wait */
static bool seal_gone;

/* the driver's match table (sep.rs, OF_TABLE) */
static const struct of_device_id seal_of_match[] = {
	{ .compatible = "apple,t6031-sep" },
	{}
};

bool apple_sep_seal_present(void)
{
	struct device_node *np = of_find_matching_node(NULL, seal_of_match);
	bool ok = np && of_device_is_available(np);

	of_node_put(np);
	return ok;
}
EXPORT_SYMBOL_GPL(apple_sep_seal_present);

static int seal_call(bool wrap, const u8 *in, size_t len, u8 *out, size_t room)
{
	int ret;

	if (!wait_event_timeout(seal_wq, READ_ONCE(seal_fn) || READ_ONCE(seal_gone), msecs_to_jiffies(SEAL_WAIT_MS)))
		return -ENODEV;
	mutex_lock(&seal_lock);
	ret = seal_fn ? seal_fn(seal_ctx, wrap, in, len, out, room) : -ENODEV;
	mutex_unlock(&seal_lock);
	return ret;
}

int apple_sep_seal_wrap(const u8 *key, u8 *out)
{
	return seal_call(true, key, APPLE_SEP_SEAL_KEY_LEN, out, APPLE_SEP_SEAL_BLOB_MAX);
}
EXPORT_SYMBOL_GPL(apple_sep_seal_wrap);

int apple_sep_seal_unwrap(const u8 *blob, size_t len, u8 *key)
{
	int ret = seal_call(false, blob, len, key, APPLE_SEP_SEAL_KEY_LEN);

	if (ret < 0)
		return ret;
	return ret == APPLE_SEP_SEAL_KEY_LEN ? 0 : -EBADMSG;
}
EXPORT_SYMBOL_GPL(apple_sep_seal_unwrap);

void apple_sep_seal_register(void *ctx, apple_sep_seal_fn_t fn)
{
	mutex_lock(&seal_lock);
	seal_ctx = ctx;
	WRITE_ONCE(seal_fn, fn);
	WRITE_ONCE(seal_gone, false);
	mutex_unlock(&seal_lock);
	wake_up_all(&seal_wq);
}
EXPORT_SYMBOL_GPL(apple_sep_seal_register);

void apple_sep_seal_unregister(void)
{
	mutex_lock(&seal_lock);
	WRITE_ONCE(seal_fn, NULL);
	seal_ctx = NULL;
	WRITE_ONCE(seal_gone, true);
	mutex_unlock(&seal_lock);
	wake_up_all(&seal_wq);
}
EXPORT_SYMBOL_GPL(apple_sep_seal_unregister);

MODULE_DESCRIPTION("Apple SEP sealing for kernel users");
MODULE_LICENSE("GPL");
