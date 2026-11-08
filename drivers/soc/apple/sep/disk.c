// SPDX-License-Identifier: GPL-2.0-only
/*
 * The xART store's disk side for sep.rs's stage 13 (Touch ID step 10d, the first planned xART write).
 *
 * macOS writes the gigalocker's slots through the `.gl` file's raw device with IO_SYNC, then flushes the disk's cache
 * (AppleSEPManager_272 gl_write, _block_dev_read_write: VNOP_WRITE, then DKIOCSYNCHRONIZE). The file is preallocated
 * and its size never changes, so its data blocks are written in place and APFS's metadata is never touched. Here the
 * lab's script finds the file's extents with a read-only APFS reader and hands them to sep.rs, which maps a byte
 * range of the file to the partition and calls these:
 * - apple_sep_disk_open(): the iBoot System Container's partition by its device number, read and write, checked to be
 *   a 500 MB GPT partition named "iBootSystemContainer" (the script's checks again);
 * - apple_sep_disk_read() and apple_sep_disk_write(): a byte range of the partition, through its page cache;
 * - apple_sep_disk_sync(): the partition's dirty pages written and the disk's cache flushed (blkdev_fsync), then
 *   its clean pages dropped, so a read-back comes from the disk;
 * - apple_sep_disk_close().
 * One partition at a time, under a mutex. Nothing else is read or written: sep.rs checks each range against the
 * extents and the disk's bytes against its copy before it writes.
 */

#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>

#include "disk.h"

#define ISC_SIZE 524288000ULL
#define ISC_NAME "iBootSystemContainer"

static DEFINE_MUTEX(disk_lock);
static struct file *disk_file;

int apple_sep_disk_open(u32 major, u32 minor)
{
	struct block_device *bdev;
	struct file *f;
	int ret = 0;

	mutex_lock(&disk_lock);
	if (disk_file) {
		ret = -EBUSY;
		goto out;
	}
	f = bdev_file_open_by_dev(MKDEV(major, minor), BLK_OPEN_READ | BLK_OPEN_WRITE, &disk_file, NULL);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		goto out;
	}
	bdev = file_bdev(f);
	if (!bdev_is_partition(bdev) || bdev_nr_bytes(bdev) != ISC_SIZE || !bdev->bd_meta_info ||
	    strcmp((const char *)bdev->bd_meta_info->volname, ISC_NAME)) {
		pr_err("[sep2] xART disk: %u:%u is not the 500 MB partition %s: not opened\n", major, minor, ISC_NAME);
		fput(f);
		ret = -ENODEV;
		goto out;
	}
	disk_file = f;
	pr_info("[sep2] xART disk: %u:%u, %s, opened read and write\n", major, minor, ISC_NAME);
out:
	mutex_unlock(&disk_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_sep_disk_open);

static int disk_rw(u64 off, u8 *buf, size_t len, bool write)
{
	loff_t pos = off;
	ssize_t n;
	int ret = 0;

	if (!len || off + len < off || off + len > ISC_SIZE)
		return -EINVAL;
	mutex_lock(&disk_lock);
	if (!disk_file) {
		ret = -ENODEV;
		goto out;
	}
	n = write ? kernel_write(disk_file, buf, len, &pos) : kernel_read(disk_file, buf, len, &pos);
	if (n != len)
		ret = n < 0 ? n : -EIO;
out:
	mutex_unlock(&disk_lock);
	return ret;
}

int apple_sep_disk_read(u64 off, u8 *buf, size_t len)
{
	return disk_rw(off, buf, len, false);
}
EXPORT_SYMBOL_GPL(apple_sep_disk_read);

int apple_sep_disk_write(u64 off, const u8 *buf, size_t len)
{
	return disk_rw(off, (u8 *)buf, len, true);
}
EXPORT_SYMBOL_GPL(apple_sep_disk_write);

int apple_sep_disk_sync(void)
{
	int ret;

	mutex_lock(&disk_lock);
	ret = disk_file ? vfs_fsync(disk_file, 0) : -ENODEV;
	/* clean now: dropped, so the read-back that follows comes from the disk, not the page cache */
	if (!ret)
		invalidate_mapping_pages(disk_file->f_mapping, 0, -1);
	mutex_unlock(&disk_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_sep_disk_sync);

void apple_sep_disk_close(void)
{
	mutex_lock(&disk_lock);
	if (disk_file) {
		vfs_fsync(disk_file, 0);
		fput(disk_file);
		disk_file = NULL;
	}
	mutex_unlock(&disk_lock);
}
EXPORT_SYMBOL_GPL(apple_sep_disk_close);

static void __exit apple_sep_disk_exit(void)
{
	apple_sep_disk_close();
}
module_exit(apple_sep_disk_exit);

MODULE_DESCRIPTION("The SEP lab driver's xART disk writes (Touch ID step 10d)");
MODULE_LICENSE("GPL");
