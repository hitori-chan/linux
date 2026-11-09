// SPDX-License-Identifier: GPL-2.0-only
/*
 * The SEP's FIDO2 authenticator, its HID side and its ciphers, for sep.rs (fido.rs): a virtual HID device with the
 * FIDO Alliance's CTAPHID report descriptor (64-byte reports each way), which hidraw gives to libfido2. Each output
 * report goes to the driver's callback; the driver's packets come back as input reports. The ciphers are the
 * PIN/UV protocol 1's: AES-256-CBC with a zero IV and HMAC-SHA-256.
 */

#include <crypto/aes-cbc.h>
#include <crypto/aes.h>
#include <crypto/sha2.h>
#include <linux/hid.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "fido.h"

#define FIDO_REPORT 64

static const u8 fido_rdesc[] = {
	0x06, 0xd0, 0xf1,	/* Usage Page (FIDO Alliance) */
	0x09, 0x01,		/* Usage (CTAPHID) */
	0xa1, 0x01,		/* Collection (Application) */
	0x09, 0x20,		/*   Usage (Data In) */
	0x15, 0x00,		/*   Logical Minimum (0) */
	0x26, 0xff, 0x00,	/*   Logical Maximum (255) */
	0x75, 0x08,		/*   Report Size (8) */
	0x95, 0x40,		/*   Report Count (64) */
	0x81, 0x02,		/*   Input (Data, Var, Abs) */
	0x09, 0x21,		/*   Usage (Data Out) */
	0x15, 0x00,		/*   Logical Minimum (0) */
	0x26, 0xff, 0x00,	/*   Logical Maximum (255) */
	0x75, 0x08,		/*   Report Size (8) */
	0x95, 0x40,		/*   Report Count (64) */
	0x91, 0x02,		/*   Output (Data, Var, Abs) */
	0xc0,			/* End Collection */
};

struct apple_sep_fido {
	struct hid_device *hid;
	void *ctx;
	apple_sep_fido_rx_t rx;
};

static int fido_parse(struct hid_device *hid)
{
	return hid_parse_report(hid, (u8 *)fido_rdesc, sizeof(fido_rdesc));
}

static int fido_start(struct hid_device *hid)
{
	return 0;
}

static void fido_stop(struct hid_device *hid)
{
}

static int fido_open(struct hid_device *hid)
{
	return 0;
}

static void fido_close(struct hid_device *hid)
{
}

/* hidraw passes the report number first: 0, as the descriptor numbers no report */
static int fido_output_report(struct hid_device *hid, u8 *buf, size_t len)
{
	struct apple_sep_fido *f = hid->driver_data;

	if (len == FIDO_REPORT + 1 && buf[0] == 0) {
		buf++;
		len--;
	}
	if (len != FIDO_REPORT)
		return -EINVAL;
	f->rx(f->ctx, buf);
	return FIDO_REPORT + 1;
}

static int fido_raw_request(struct hid_device *hid, unsigned char reportnum, u8 *buf, size_t len,
			    unsigned char rtype, int reqtype)
{
	if (rtype == HID_OUTPUT_REPORT && reqtype == HID_REQ_SET_REPORT)
		return fido_output_report(hid, buf, len);
	return -EIO;
}

static const struct hid_ll_driver fido_ll = {
	.parse = fido_parse,
	.start = fido_start,
	.stop = fido_stop,
	.open = fido_open,
	.close = fido_close,
	.raw_request = fido_raw_request,
	.output_report = fido_output_report,
};

struct apple_sep_fido *apple_sep_fido_create(struct device *parent, void *ctx, apple_sep_fido_rx_t rx)
{
	struct apple_sep_fido *f;
	struct hid_device *hid;
	int ret;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return ERR_PTR(-ENOMEM);
	hid = hid_allocate_device();
	if (IS_ERR(hid)) {
		kfree(f);
		return ERR_CAST(hid);
	}
	f->hid = hid;
	f->ctx = ctx;
	f->rx = rx;
	hid->ll_driver = &fido_ll;
	/*
	 * libfido2's Linux enumeration takes USB HID devices only (hid_linux.c copy_info: "bus", build 64 with
	 * BUS_VIRTUAL), and systemd-cryptsetup's token finds its device by that enumeration; uhid's virtual
	 * authenticators say USB for the same reason.
	 */
	hid->bus = BUS_USB;
	hid->dev.parent = parent;
	hid->driver_data = f;
	strscpy(hid->name, "SEP FIDO2 authenticator", sizeof(hid->name));
	strscpy(hid->phys, dev_name(parent), sizeof(hid->phys));
	ret = hid_add_device(hid);
	if (ret) {
		hid_destroy_device(hid);
		kfree(f);
		return ERR_PTR(ret);
	}
	return f;
}
EXPORT_SYMBOL_GPL(apple_sep_fido_create);

void apple_sep_fido_destroy(struct apple_sep_fido *f)
{
	hid_destroy_device(f->hid);
	kfree(f);
}
EXPORT_SYMBOL_GPL(apple_sep_fido_destroy);

int apple_sep_fido_send(struct apple_sep_fido *f, const u8 *pkt)
{
	u8 buf[FIDO_REPORT];

	memcpy(buf, pkt, FIDO_REPORT);
	return hid_input_report(f->hid, HID_INPUT_REPORT, buf, FIDO_REPORT, 0);
}
EXPORT_SYMBOL_GPL(apple_sep_fido_send);

int apple_sep_fido_aes256_cbc(const u8 *key, int encrypt, u8 *buf, size_t len)
{
	struct aes_key k;
	u8 iv[AES_BLOCK_SIZE] = {};
	int ret;

	if (len % AES_BLOCK_SIZE)
		return -EINVAL;
	ret = aes_preparekey(&k, key, AES_KEYSIZE_256);
	if (ret)
		return ret;
	if (encrypt)
		aes_cbc_encrypt(buf, buf, len, iv, &k);
	else
		aes_cbc_decrypt(buf, buf, len, iv, &k);
	memzero_explicit(&k, sizeof(k));
	return 0;
}
EXPORT_SYMBOL_GPL(apple_sep_fido_aes256_cbc);

void apple_sep_fido_hmac_sha256(const u8 *key, size_t key_len, const u8 *data, size_t len, u8 *out)
{
	hmac_sha256_usingrawkey(key, key_len, data, len, out);
}
EXPORT_SYMBOL_GPL(apple_sep_fido_hmac_sha256);

MODULE_DESCRIPTION("Apple SEP: the FIDO2 authenticator's HID device and ciphers");
MODULE_LICENSE("GPL");
