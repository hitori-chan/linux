// SPDX-License-Identifier: GPL-2.0-only
/*
 * The FIDO2 authenticator's resident credentials on the disk (sep/rk.rs): two small sealed files the driver reads and
 * writes whole, from its own work item, as the target core keeps its ALUA metadata in files under /var/target. An
 * authenticator has to keep them itself: CTAP2 gives the host no part in it, and a credential must be on the disk
 * before MakeCredential answers. A kernel thread's own root is empty: the paths are resolved as init's
 * (scoped_with_init_fs, as the firmware loader's are), so the files are the root filesystem's once it is there.
 */
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/module.h>
#include <linux/namei.h>

#include "store.h"

int apple_sep_store_dir(const char *dir)
{
	struct path p;
	int ret;

	scoped_with_init_fs()
		ret = kern_path(dir, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &p);
	if (ret)
		return ret;
	path_put(&p);
	return 0;
}
EXPORT_SYMBOL_GPL(apple_sep_store_dir);

loff_t apple_sep_store_size(const char *path)
{
	struct path p;
	loff_t size;
	int ret;

	scoped_with_init_fs()
		ret = kern_path(path, 0, &p);
	if (ret)
		return ret;
	size = d_is_reg(p.dentry) ? i_size_read(d_inode(p.dentry)) : -EINVAL;
	path_put(&p);
	return size;
}
EXPORT_SYMBOL_GPL(apple_sep_store_size);

ssize_t apple_sep_store_read(const char *path, u8 *buf, size_t max)
{
	ssize_t n, got = 0;
	struct file *f;
	loff_t pos = 0;
	u8 more;

	scoped_with_init_fs()
		f = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);
	if (!S_ISREG(file_inode(f)->i_mode)) {
		filp_close(f, NULL);
		return -EINVAL;
	}
	while (got < max) {
		n = kernel_read(f, buf + got, max - got, &pos);
		if (n < 0) {
			got = n;
			break;
		}
		if (!n)
			break;
		got += n;
	}
	if (got == max && kernel_read(f, &more, 1, &pos) == 1)
		got = -EFBIG;
	filp_close(f, NULL);
	return got;
}
EXPORT_SYMBOL_GPL(apple_sep_store_read);

static int store_sync_dir(const char *dir)
{
	struct file *d;
	int ret;

	scoped_with_init_fs()
		d = filp_open(dir, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(d))
		return PTR_ERR(d);
	ret = vfs_fsync(d, 0);
	filp_close(d, NULL);
	return ret;
}

int apple_sep_store_write(const char *dir, const char *path, const u8 *buf, size_t len)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t n;
	int ret;

	scoped_with_init_fs()
		f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
	if (IS_ERR(f))
		return PTR_ERR(f);
	if (!S_ISREG(file_inode(f)->i_mode)) {
		filp_close(f, NULL);
		return -EINVAL;
	}
	n = kernel_write(f, buf, len, &pos);
	ret = n == len ? vfs_fsync(f, 0) : n < 0 ? n : -EIO;
	filp_close(f, NULL);
	return ret ? ret : store_sync_dir(dir);
}
EXPORT_SYMBOL_GPL(apple_sep_store_write);

MODULE_DESCRIPTION("Apple SEP: the FIDO2 authenticator's resident credentials on the disk");
MODULE_LICENSE("GPL");
