// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple Neural Engine driver: the firmware's image from the disk
 *
 * Copyright The Asahi Linux Contributors
 *
 * The firmware is an RTKit Mach-O: __TEXT at vm 0 and __DATA after it, at the
 * DART window's base plus their vm addresses (the ADT's segment-ranges remap,
 * 0x100_0000_0000 + vm), where iBoot set and locked the CPU's reset vector
 * at __TEXT's start. For macOS
 * iBoot loads it and fills in two of __DATA's sections; the driver does the
 * same from the image on the disk:
 * - _rtk_patchbay, packed records {u32 tag, u32 size, the value}: the stack
 *   guard, the SoC, its revision and the ASC's CPU and wrapper addresses;
 * - _rtk_tunables, blocks of {u8 type, u8 3, u8 capacity, u8 count, u32 word}
 *   and capacity entries {u32 offset, u64 mask, u64 value}: the entries from
 *   ane0's "apple,tunables", the count, and the word iBoot writes, 0x10.
 * Anything else in the image iBoot leaves as it is (rda ane_fw_t603x_1483,
 * against a preload read back over m1n1's proxy).
 */

#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/iommu.h>
#include <linux/of.h>
#include <linux/random.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/vmalloc.h>

#include <asm/cputype.h>

#include "ane.h"

#define ANE_FW_NAME		"apple/ane-t603x.macho"

#define MH_MAGIC_64		0xfeedfacf
#define CPU_TYPE_ARM64		0x0100000c
#define LC_SEGMENT_64		0x19

/* The ASC's CPU and wrapper, from ane0's first register range */
#define ANE_ASC_CPU		0x1000000
#define ANE_ASC_WRAP		0x1400000

#define ANE_TUN_HEADER		8
#define ANE_TUN_ENTRY		20
#define ANE_TUN_WORD		0x10
#define ANE_TUN_CELLS		6

#define RTK_TAG(a, b, c, d)	((a) << 24 | (b) << 16 | (c) << 8 | (d))

struct macho_header {
	__le32 magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved;
};

struct macho_segment {
	__le32 cmd, cmdsize;
	char segname[16];
	__le64 vmaddr, vmsize, fileoff, filesize;
	__le32 maxprot, initprot, nsects, flags;
};

struct macho_section {
	char sectname[16], segname[16];
	__le64 addr, size;
	__le32 offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3;
};

static int ane_macho_segment(struct apple_ane *ane, const struct firmware *fw, const char *name,
			     struct macho_segment *seg, size_t *cmd)
{
	struct macho_header h;
	size_t off = sizeof(h), end;
	u32 i;

	if (fw->size < sizeof(h))
		return -EINVAL;
	memcpy(&h, fw->data, sizeof(h));
	if (le32_to_cpu(h.magic) != MH_MAGIC_64 || le32_to_cpu(h.cputype) != CPU_TYPE_ARM64)
		return -EINVAL;
	end = sizeof(h) + (size_t)le32_to_cpu(h.sizeofcmds);
	if (end > fw->size)
		return -EINVAL;

	for (i = 0; i < le32_to_cpu(h.ncmds); i++) {
		u32 type, size;
		u64 fo, fs;

		if (off + 8 > end)
			return -EINVAL;
		type = get_unaligned_le32(fw->data + off);
		size = get_unaligned_le32(fw->data + off + 4);
		if (size < 8 || size > end - off)
			return -EINVAL;
		if (type != LC_SEGMENT_64 || size < sizeof(*seg)) {
			off += size;
			continue;
		}
		memcpy(seg, fw->data + off, sizeof(*seg));
		if (strncmp(seg->segname, name, sizeof(seg->segname))) {
			off += size;
			continue;
		}
		fo = le64_to_cpu(seg->fileoff);
		fs = le64_to_cpu(seg->filesize);
		if (sizeof(*seg) + (u64)le32_to_cpu(seg->nsects) * sizeof(struct macho_section) > size ||
		    fo > fw->size || fs > fw->size - fo || fs > le64_to_cpu(seg->vmsize)) {
			dev_err(ane->dev, "%s: segment %s out of the file\n", ANE_FW_NAME, name);
			return -EINVAL;
		}
		*cmd = off;
		return 0;
	}
	dev_err(ane->dev, "%s: no segment %s\n", ANE_FW_NAME, name);
	return -ENOENT;
}

/* A section of the segment at cmd, as an offset into the segment's vm range */
static int ane_macho_section(struct apple_ane *ane, const struct firmware *fw, size_t cmd,
			     const struct macho_segment *seg, const char *name, size_t *off, size_t *size)
{
	u64 base = le64_to_cpu(seg->vmaddr), vmsize = le64_to_cpu(seg->vmsize);
	u32 i;

	for (i = 0; i < le32_to_cpu(seg->nsects); i++) {
		struct macho_section s;
		u64 addr, len;

		memcpy(&s, fw->data + cmd + sizeof(*seg) + i * sizeof(s), sizeof(s));
		if (strncmp(s.sectname, name, sizeof(s.sectname)))
			continue;
		addr = le64_to_cpu(s.addr);
		len = le64_to_cpu(s.size);
		if (addr < base || len > vmsize || addr - base > vmsize - len) {
			dev_err(ane->dev, "%s: section %s out of its segment\n", ANE_FW_NAME, name);
			return -EINVAL;
		}
		*off = addr - base;
		*size = len;
		return 0;
	}
	dev_err(ane->dev, "%s: no section %s\n", ANE_FW_NAME, name);
	return -ENOENT;
}

/* The SoC as iBoot writes it: 0x6034 for "apple,t6034" */
static int ane_soc_id(u32 *id)
{
	const char *s;
	struct property *prop;

	of_property_for_each_string(of_root, "compatible", prop, s) {
		unsigned int v;
		int n = 0;

		if (sscanf(s, "apple,t%x%n", &v, &n) == 1 && n == strlen(s) && n == 11) {
			*id = v;
			return 0;
		}
	}
	return -ENODEV;
}

static int ane_patchbay(struct apple_ane *ane, u8 *bay, size_t size)
{
	u64 midr = read_cpuid_id();
	struct {
		u32 tag, len;
		u64 val;
		bool done;
	} p[] = {
		{ RTK_TAG('S', 'T', 'K', 'G'), 8, get_random_u64() },
		{ RTK_TAG('S', 'O', 'C', '_'), 4, 0 },
		/* 0x12 here, the CPUs' MIDR variant and revision (inferred) */
		{ RTK_TAG('S', 'O', 'C', 'R'), 4, MIDR_VARIANT(midr) << 4 | MIDR_REVISION(midr) },
		{ RTK_TAG('C', 'p', 'A', 'd'), 8, ane->regs_phys + ANE_ASC_CPU },
		{ RTK_TAG('W', 'r', 'A', 'd'), 8, ane->regs_phys + ANE_ASC_WRAP },
	};
	size_t off = 0;
	u32 soc;
	int i, ret;

	ret = ane_soc_id(&soc);
	if (ret) {
		dev_err(ane->dev, "no apple,tNNNN in the root's compatible\n");
		return ret;
	}
	p[1].val = soc;

	while (off + 8 <= size) {
		u32 tag = get_unaligned_le32(bay + off);
		u32 len = get_unaligned_le32(bay + off + 4);

		if (len > size - off - 8)
			return -EINVAL;
		for (i = 0; i < ARRAY_SIZE(p); i++) {
			if (p[i].tag != tag)
				continue;
			if (len != p[i].len)
				return -EINVAL;
			if (len == 4)
				put_unaligned_le32(p[i].val, bay + off + 8);
			else
				put_unaligned_le64(p[i].val, bay + off + 8);
			p[i].done = true;
		}
		off += 8 + len;
	}
	for (i = 0; i < ARRAY_SIZE(p); i++) {
		if (!p[i].done) {
			dev_err(ane->dev, "%s: no patch record %.4s\n", ANE_FW_NAME,
				(char *)&(__be32){ cpu_to_be32(p[i].tag) });
			return -ENOENT;
		}
	}
	return 0;
}

static int ane_tunables(struct apple_ane *ane, u8 *sec, size_t size)
{
	struct device_node *np = ane->dev->of_node;
	int n = of_property_count_u32_elems(np, "apple,tunables");
	size_t off = 0;
	int i, placed = 0, ret = 0;
	u32 *t;

	if (n <= 0 || n % ANE_TUN_CELLS) {
		dev_err(ane->dev, "apple,tunables: %d cells, not entries of %d\n", n, ANE_TUN_CELLS);
		return -EINVAL;
	}
	t = kmalloc_array(n, sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;
	ret = of_property_read_u32_array(np, "apple,tunables", t, n);
	if (ret)
		goto out;

	while (off + ANE_TUN_HEADER <= size) {
		u8 type = sec[off], cap = sec[off + 2], count = 0;
		size_t len = ANE_TUN_HEADER + cap * ANE_TUN_ENTRY;

		if (len > size - off) {
			ret = -EINVAL;
			goto out;
		}
		for (i = 0; i < n; i += ANE_TUN_CELLS) {
			u8 *e;

			if (t[i] != type)
				continue;
			if (count == cap) {
				dev_err(ane->dev, "apple,tunables: over block %u's %u entries\n", type, cap);
				ret = -ENOSPC;
				goto out;
			}
			e = sec + off + ANE_TUN_HEADER + count * ANE_TUN_ENTRY;
			put_unaligned_le32(t[i + 1], e);
			put_unaligned_le64((u64)t[i + 2] << 32 | t[i + 3], e + 4);
			put_unaligned_le64((u64)t[i + 4] << 32 | t[i + 5], e + 12);
			count++;
		}
		sec[off + 3] = count;
		put_unaligned_le32(ANE_TUN_WORD, sec + off + 4);
		placed += count;
		off += len;
	}
	if (placed != n / ANE_TUN_CELLS) {
		dev_err(ane->dev, "apple,tunables: %d entries of a type the image has no block for\n",
			n / ANE_TUN_CELLS - placed);
		ret = -ENOENT;
	}
out:
	kfree(t);
	return ret;
}

static int ane_seg_alloc(struct apple_ane *ane, struct ane_seg *s, const struct macho_segment *seg)
{
	s->iova = ane->domain->geometry.aperture_start + le64_to_cpu(seg->vmaddr);
	s->size = le64_to_cpu(seg->vmsize);
	if (!IS_ALIGNED(s->iova, SZ_16K) || !s->size)
		return -EINVAL;
	s->buf.size = round_up(s->size, SZ_16K);
	s->buf.cpu = dma_alloc_coherent(ane->dev, s->buf.size, &s->buf.iova, GFP_KERNEL);
	return s->buf.cpu ? 0 : -ENOMEM;
}

static void ane_seg_free(struct apple_ane *ane, struct ane_seg *s)
{
	if (s->buf.cpu)
		dma_free_coherent(ane->dev, s->buf.size, s->buf.cpu, s->buf.iova);
	s->buf.cpu = NULL;
}

int ane_fw_load(struct apple_ane *ane)
{
	struct macho_segment text, data;
	const struct firmware *fw;
	size_t tcmd, dcmd, off, size;
	int ret;

	if (ane->data_image)
		return 0;

	ret = request_firmware(&fw, ANE_FW_NAME, ane->dev);
	if (ret)
		return ret;

	ret = ane_macho_segment(ane, fw, "__TEXT", &text, &tcmd) ?:
	      ane_macho_segment(ane, fw, "__DATA", &data, &dcmd);
	if (ret)
		goto out;

	ret = -EINVAL;
	if (le64_to_cpu(text.vmaddr)) {
		dev_err(ane->dev, "%s: __TEXT at %#llx, not at the reset vector's 0\n", ANE_FW_NAME,
			le64_to_cpu(text.vmaddr));
		goto out;
	}
	if (le64_to_cpu(data.vmaddr) < le64_to_cpu(text.vmsize) ||
	    le64_to_cpu(data.vmsize) > ANE_FW_WINDOW ||
	    le64_to_cpu(data.vmaddr) > ANE_FW_WINDOW - le64_to_cpu(data.vmsize)) {
		dev_err(ane->dev, "%s: __DATA at %#llx, %#llx bytes, past the firmware's window\n",
			ANE_FW_NAME, le64_to_cpu(data.vmaddr), le64_to_cpu(data.vmsize));
		goto out;
	}

	ane->data_image = vzalloc(le64_to_cpu(data.vmsize));
	if (!ane->data_image) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(ane->data_image, fw->data + le64_to_cpu(data.fileoff), le64_to_cpu(data.filesize));

	ret = ane_macho_section(ane, fw, dcmd, &data, "_rtk_patchbay", &off, &size);
	if (ret)
		goto err;
	ret = ane_patchbay(ane, ane->data_image + off, size);
	if (ret)
		goto err;
	ret = ane_macho_section(ane, fw, dcmd, &data, "_rtk_tunables", &off, &size);
	if (ret)
		goto err;
	ret = ane_tunables(ane, ane->data_image + off, size);
	if (ret)
		goto err;

	ret = ane_seg_alloc(ane, &ane->text, &text) ?:
	      ane_seg_alloc(ane, &ane->data, &data);
	if (ret)
		goto err;
	/* __TEXT once; __DATA again at each boot, from data_image */
	memset(ane->text.buf.cpu, 0, ane->text.buf.size);
	memcpy(ane->text.buf.cpu, fw->data + le64_to_cpu(text.fileoff), le64_to_cpu(text.filesize));

	dev_info(ane->dev, "%s: __TEXT %#zx bytes at %#llx, __DATA %#zx at %#llx\n",
		 ANE_FW_NAME, ane->text.size, ane->text.iova, ane->data.size, ane->data.iova);
	goto out;

err:
	ane_fw_unload(ane);
out:
	release_firmware(fw);
	return ret;
}

void ane_fw_unload(struct apple_ane *ane)
{
	ane_seg_free(ane, &ane->data);
	ane_seg_free(ane, &ane->text);
	vfree(ane->data_image);
	ane->data_image = NULL;
}

MODULE_FIRMWARE(ANE_FW_NAME);
