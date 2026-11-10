// SPDX-License-Identifier: GPL-2.0-only
/*
 * The SEP's random numbers as a hwrng: sep.rs asks the SEP's control endpoint for entropy (macOS's
 * AppleSEPControl::cmsgGET_ENTROPY_FOR_XNU_PRNG, which reseeds XNU's generator from it), 32 bits a request. A read
 * sleeps for the SEP's answers, so one that may not wait gets nothing.
 */
#include <linux/err.h>
#include <linux/hw_random.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "rng.h"

struct apple_sep_rng {
	struct hwrng rng;
	void *ctx;
	apple_sep_rng_read_t read;
};

static int apple_sep_rng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	struct apple_sep_rng *r = container_of(rng, struct apple_sep_rng, rng);

	if (!wait)
		return 0;
	return r->read(r->ctx, buf, max);
}

struct apple_sep_rng *apple_sep_rng_create(struct device *parent, void *ctx, apple_sep_rng_read_t read)
{
	struct apple_sep_rng *r = kzalloc(sizeof(*r), GFP_KERNEL);
	int ret;

	if (!r)
		return ERR_PTR(-ENOMEM);
	r->ctx = ctx;
	r->read = read;
	r->rng.name = "apple-sep";
	r->rng.read = apple_sep_rng_read;
	ret = hwrng_register(&r->rng);
	if (ret) {
		kfree(r);
		return ERR_PTR(ret);
	}
	return r;
}
EXPORT_SYMBOL_GPL(apple_sep_rng_create);

void apple_sep_rng_destroy(struct apple_sep_rng *r)
{
	hwrng_unregister(&r->rng);
	kfree(r);
}
EXPORT_SYMBOL_GPL(apple_sep_rng_destroy);

MODULE_DESCRIPTION("Apple SEP random number generator");
MODULE_LICENSE("GPL");
