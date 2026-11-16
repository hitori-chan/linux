// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple Neural Engine: an .hwx read as macOS's loader reads it, and the four sections LOAD_PROGRAM names built
 * from it: the generic (the program's buffers), the operations, the procedures and the segment properties.
 * Segment threads (flavor 4, H15's) only.
 *
 * rda AppleH11ANEInterface 14.8.3: ZinComputeProgramMake 0xfffffe00097d1fa8, ZinComputeProgramMakeOperations
 * 0xfffffe00097d372c, ZinComputeProgramMakeProcedures 0xfffffe00097d3f3c, ZinComputeInitGenericSection
 * 0xfffffe00097cf7e0, ZinComputeInitOperationSection 0xfffffe00097cff80, ZinComputeInitProcedureSection
 * 0xfffffe00097d0530, ZinComputeInitTextPropertySection 0xfffffe00097d0c90, ZinComputeInitSneProgram
 * 0xfffffe00097cf104.
 *
 * The firmware checks at LOAD_PROGRAM that each buffer an operation binds is named once: by the text record,
 * the kernel record or a generic record (rda ane_fw_t603x_1483 sub_50024 0x50024; it asserts at
 * CAneProgramManager.cpp:475 otherwise). A procedure call's buffers are checked against the generic records
 * (sub_50758 0x50758) and give the operation's base addresses (sub_48580 0x48580).
 */

#include "ane-hwx.h"

#define MH_MAGIC_ANE		0xbeefface
#define MH_MAGIC_64		0xfeedfacf
#define CPU_TYPE_ANE		0x80

#define LC_SEGMENT_64		0x19
#define LC_THREAD		0x04

/* segment_command_64 */
#define SEG_NAME		0x08
#define SEG_VMADDR		0x18
#define SEG_FILEOFF		0x28
#define SEG_FILESIZE		0x30
#define SEG_INITPROT		0x3c
#define SEG_NSECTS		0x40
#define SEG_FLAGS		0x44
#define SEG_SECTS		0x48
#define SEG_FVMLIB		BIT(1)	/* one buffer for the whole segment */

/* section_64 */
#define SECT_SIZE		0x50
#define SECT_SEGNAME		0x10
#define SECT_ADDR		0x20
#define SECT_LEN		0x28
#define SECT_FLAGS		0x40

/* the thread state of an operation */
#define ST_FIRST		0x800	/* the first segment's address */
#define ST_WORDS		0x814	/* its length in words */
#define ST_SEGID		0x818
#define ST_81C			0x81c
#define ST_820			0x820
#define ST_KIND			0x824	/* 0 the last, 1 a jump, 2 a branch */
#define ST_TARGET0		0x828
#define ST_TARGET1		0x82c
#define ST_MASK			0x834	/* the engines, flavor 4 */
#define ST_MIN			0x838

#define FLAVOR_TD		1
#define FLAVOR_SEGMENT		4

/* The firmware's buffer types, from a section's type (its flags' low byte) */
#define BT_TEXT			0x3e8
#define BT_KERNEL		0x3e9
#define BT_GENERIC		0x3ea
#define BT_OPERATION		0x3eb
#define BT_PROCEDURE		0x3ec
#define BT_SEGPROP		0x3ed

static const u16 hwx_buf_type[12] = {
	0x3ee, 0x3ee, 0x3ef, 0x3ef, 0x3f0, 0x3f0, BT_KERNEL, BT_KERNEL, BT_TEXT, 0, 0x3f1, 0x3f1,
};

/* the kind the firmware gets for buffer types 0x3ee-0x3f1 */
static const u8 hwx_kind[4] = { 0, 1, 2, 5 };

static inline u16 rd16(const u8 *p) { return get_unaligned_le16(p); }
static inline u32 rd32(const u8 *p) { return get_unaligned_le32(p); }
static inline u64 rd64(const u8 *p) { return get_unaligned_le64(p); }

static size_t align8(size_t n)
{
	return (n + 7) & ~(size_t)7;
}

static u32 sect_buf_type(const u8 *sect)
{
	u32 t = rd32(sect + SECT_FLAGS) & 0xff;

	return t >= 0x20 && t < 0x2c ? hwx_buf_type[t - 0x20] : 0;
}

/*
 * A split kernel section: the compiler's --split-kernel-section puts the kernels in __KERN_n,__kern_n and leaves
 * __TEXT,__const for LOAD_PROGRAM's kernel record. macOS 27.2 tells it so (its AppleH11ANEInterface,
 * ZinComputeProgramIsKernelSection 0xfffffe0009678f34) and gives its address with each call as a custom base
 * address of type 3. The 14.8.3 firmware has no such type (sub_481CC 0x481cc asserts on it) and 14.8.3's kext no
 * such section: here it gets a generic record, and each call names it as it names the buffers.
 */
static bool sect_ksplit(const u8 *sect)
{
	return (rd32(sect + SECT_FLAGS) & 0xff) == 0x26 && !memcmp(sect + SECT_SEGNAME, "__KERN", 6) &&
	       !memcmp(sect, "__kern", 6);
}

/* The kind of a section's generic record, or -1 for a section without one */
static int sect_generic_kind(const u8 *sect)
{
	u32 bt = sect_buf_type(sect);

	if (bt >= 0x3ee && bt <= 0x3f1)
		return hwx_kind[bt - 0x3ee];
	return sect_ksplit(sect) ? HWX_KIND_KERNEL : -1;
}

static const u8 *seg_sect(const struct hwx *h, u32 s, u32 j)
{
	return h->seg[s].cmd + SEG_SECTS + j * SECT_SIZE;
}

static u32 seg_nsects(const struct hwx *h, u32 s)
{
	return rd32(h->seg[s].cmd + SEG_NSECTS);
}

static bool seg_fvmlib(const struct hwx *h, u32 s)
{
	return rd32(h->seg[s].cmd + SEG_FLAGS) & SEG_FVMLIB;
}

/* A section's buffer index: the segment's first for an FVMLIB segment (ZinComputeLookupBufferBySection) */
static u32 sect_index(const struct hwx *h, u32 s, u32 j)
{
	return h->seg[s].first + (seg_fvmlib(h, s) ? 0 : j);
}

static int sect_at(const struct hwx *h, u64 addr, u32 *s_out, u32 *j_out)
{
	u32 s, j;

	for (s = 0; s < h->nsegs; s++)
		for (j = 0; j < seg_nsects(h, s); j++) {
			const u8 *sect = seg_sect(h, s, j);
			u64 a = rd64(sect + SECT_ADDR), n = rd64(sect + SECT_LEN);

			if (addr >= a && addr - a < n) {
				*s_out = s;
				*j_out = j;
				return 0;
			}
		}
	return -ENOENT;
}

static u32 nbr_of_ne(const struct hwx *h)
{
	u32 mask = rd32(h->op[0].state + ST_MASK);

	return mask ? 32 - __builtin_clz(mask) : 0;
}

int hwx_parse(struct hwx *h, const void *data, size_t len)
{
	const u8 *b = data;
	u32 ncmds, i, nsect = 0, flavor = 0;
	size_t o = 0x20;

	memset(h, 0, sizeof(*h));
	h->b = b;
	h->len = len;
	if (len < 0x20 || ((uintptr_t)b & 7))
		return -EINVAL;
	if ((rd32(b) != MH_MAGIC_ANE && rd32(b) != MH_MAGIC_64) || rd32(b + 4) != CPU_TYPE_ANE)
		return -EINVAL;
	h->cpusubtype = rd32(b + 8);
	h->filetype = rd32(b + 0xc);
	ncmds = rd32(b + 0x10);

	for (i = 0; i < ncmds; i++) {
		u32 cmd, size;

		if (o + 8 > len)
			return -EINVAL;
		cmd = rd32(b + o);
		size = rd32(b + o + 4);
		if (size < 8 || (size & 7) || size > len - o)
			return -EINVAL;

		if (cmd == LC_SEGMENT_64) {
			u32 n;

			if (size < SEG_SECTS || h->nsegs == HWX_MAX_SEGS)
				return -EINVAL;
			n = rd32(b + o + SEG_NSECTS);
			if (n > 0x100 || SEG_SECTS + (size_t)n * SECT_SIZE > size)
				return -EINVAL;
			h->seg[h->nsegs].cmd = b + o;
			h->seg[h->nsegs].first = nsect;
			h->nsegs++;
			nsect += n;
		} else if (cmd == LC_THREAD) {
			u32 fl, count;
			const u8 *tail, *end;

			if (size < 0x10)
				return -EINVAL;
			fl = rd32(b + o + 8);
			count = rd32(b + o + 0xc);
			if (0x10 + (size_t)count * 4 > size)
				return -EINVAL;
			if (fl != FLAVOR_TD && fl != FLAVOR_SEGMENT)
				goto next;
			if (flavor && fl != flavor)
				return -EINVAL;		/* the kext wants one flavor */
			flavor = fl;
			if ((size_t)count * 4 < ST_MIN || h->nops == HWX_MAX_OPS)
				return -EINVAL;
			h->op[h->nops].state = b + o + 0x10;
			tail = b + o + 0x10 + count * 4;
			end = b + o + size;
			while (tail < end && !*tail)
				tail++;
			h->op[h->nops].name = tail;
			while (tail < end && *tail)
				tail++;
			h->op[h->nops].name_len = tail - h->op[h->nops].name;
			h->nops++;
		}
next:
		o += size;
	}
	if (flavor != FLAVOR_SEGMENT || !h->nops)
		return -EOPNOTSUPP;

	/* the sections' addresses lie in the file where they have data */
	for (i = 0; i < h->nsegs; i++) {
		const u8 *seg = h->seg[i].cmd;
		u64 fo = rd64(seg + SEG_FILEOFF), fs = rd64(seg + SEG_FILESIZE);

		if (fo > len || fs > len - fo)
			return -EINVAL;
	}

	/*
	 * The kernel and the text the firmware reads from the mapped .hwx (hwx_message, hwx_call_kernels): inside
	 * their segment's data. A split kernel section has no address anywhere else.
	 */
	for (i = 0; i < h->nsegs; i++) {
		const u8 *seg = h->seg[i].cmd;
		u64 va = rd64(seg + SEG_VMADDR), fs = rd64(seg + SEG_FILESIZE);
		bool mapped = !(rd32(seg + SEG_INITPROT) & 2) && fs;
		u32 j;

		for (j = 0; j < seg_nsects(h, i); j++) {
			const u8 *sect = seg_sect(h, i, j);
			u32 bt = sect_buf_type(sect);
			u64 a = rd64(sect + SECT_ADDR), n = rd64(sect + SECT_LEN);

			if (bt != BT_KERNEL && bt != BT_TEXT)
				continue;
			if (sect_ksplit(sect) && (!mapped || seg_fvmlib(h, i)))
				return -EINVAL;
			if (!mapped)
				continue;
			if (a < va || a - va > fs || n > fs - (a - va))
				return -EINVAL;
		}
	}

	/* the procedures: runs of operations with one name */
	for (i = 0; i < h->nops; i++) {
		const struct hwx_op *op = &h->op[i], *prev = i ? &h->op[i - 1] : NULL;

		if (prev && prev->name_len == op->name_len && !memcmp(prev->name, op->name, op->name_len)) {
			h->proc_count[h->nprocs - 1]++;
			continue;
		}
		if (h->nprocs == HWX_MAX_PROCS)
			return -EINVAL;
		h->proc_first[h->nprocs] = i;
		h->proc_count[h->nprocs] = 1;
		h->nprocs++;
	}

	/* the sizes, as the kext checks them */
	for (i = 0; i < h->nsegs; i++) {
		u32 j;

		for (j = 0; j < seg_nsects(h, i); j++) {
			if (sect_generic_kind(seg_sect(h, i, j)) < 0)
				continue;
			h->ngeneric++;
			if (seg_fvmlib(h, i))
				break;
		}
	}
	h->size[HWX_GENERIC] = align8(0x208 + 0x30 * h->ngeneric);
	h->size[HWX_OPERATION] = align8(0x40c * h->nops + 4);
	h->size[HWX_PROCEDURE] = align8(8 + 0x24 * h->nprocs + 0xc * h->nops);
	h->size[HWX_SEGPROP] = align8(8 + 0x20 * h->nops);
	return 0;
}

static int build_generic(const struct hwx *h, u8 *out)
{
	u32 s, j, n = 0;

	put_unaligned_le32(1, out);
	put_unaligned_le32(nbr_of_ne(h), out + 4);
	for (s = 0; s < h->nsegs; s++) {
		const u8 *seg = h->seg[s].cmd;
		u32 prot = rd32(seg + SEG_INITPROT) & 3;

		for (j = 0; j < seg_nsects(h, s); j++) {
			const u8 *sect = seg_sect(h, s, j);
			int kind = sect_generic_kind(sect);
			u8 *r = out + 0x208 + 0x30 * n;
			u64 size = rd32(sect + SECT_LEN);

			if (kind < 0)
				continue;
			if (seg_fvmlib(h, s)) {
				u64 base = rd64(seg + SEG_VMADDR), top = base;
				u32 k;

				for (k = 0; k < seg_nsects(h, s); k++) {
					const u8 *x = seg_sect(h, s, k);
					u64 a = rd64(x + SECT_ADDR), e = a + rd64(x + SECT_LEN);

					if (a < base)
						return -EINVAL;
					if (e > top)
						top = e;
				}
				size = top - base;
			}
			put_unaligned_le32(1, r);
			put_unaligned_le32(sect_index(h, s, j), r + 4);
			put_unaligned_le32(kind, r + 8);
			put_unaligned_le32(!memcmp(seg + SEG_NAME, "__L3", 5), r + 0xc);
			put_unaligned_le32(prot, r + 0x10);
			put_unaligned_le64(size, r + 0x20);
			put_unaligned_le64(0xffff, r + 0x28);
			n++;
			if (seg_fvmlib(h, s))
				break;
		}
	}
	put_unaligned_le32(n, out + 0x204);
	return 0;
}

/* Flavor 4: the bound slots in pairs (ZinComputeSetSegmentOperationProperty 0xfffffe00097cfc50) */
static int build_operation(const struct hwx *h, u8 *out)
{
	u32 i, slot;

	put_unaligned_le32(h->nops, out);
	for (i = 0; i < h->nops; i++) {
		u8 *r = out + 4 + 0x40c * i;
		u32 m = 0;

		put_unaligned_le16(nbr_of_ne(h), r + 4);
		for (slot = 0; slot < 0x100; slot++) {
			u64 a = rd64(h->op[i].state + 8 * slot);
			u32 s, j;

			if (!a)
				continue;
			if (sect_at(h, a, &s, &j))
				return -EINVAL;
			if (m == (0x40c - 0xc) / 8)
				return -E2BIG;
			put_unaligned_le32(slot >> 1, r + 0xc + 8 * m);
			put_unaligned_le32(sect_index(h, s, j), r + 0x10 + 8 * m);
			m++;
		}
		put_unaligned_le32(m, r + 8);
	}
	return 0;
}

/* Flavor 4: each procedure's segments and their order (ZinComputeInitSneSetProcedureSegmentProperty) */
static int build_procedure(const struct hwx *h, u8 *out)
{
	size_t body = 8 + 0x10 * h->nprocs;
	u32 p, first = 0;

	put_unaligned_le32(h->nprocs, out);
	for (p = 0; p < h->nprocs; p++) {
		u32 k = h->proc_count[p], j, cond = 0;
		u8 *r = out + body;

		for (j = 0; j < k; j++) {
			const u8 *st = h->op[h->proc_first[p] + j].state;
			u8 *e = r + 0x14 + 0xc * j;
			u32 id = rd32(st + ST_SEGID), kind = rd32(st + ST_KIND);

			if (id >= k || id + first >= h->nops)
				return -EINVAL;
			put_unaligned_le32(id + first, e);
			put_unaligned_le32(0xffffffff, e + 4);
			put_unaligned_le32((kind == 0 ? 4 : 0) | (kind == 2 ? 1 : 0), e + 8);
		}
		for (j = 0; j < k; j++) {
			const u8 *st = h->op[h->proc_first[p] + j].state;
			u32 kind = rd32(st + ST_KIND), t, n, x;

			if (kind != 1 && kind != 2)
				continue;
			for (t = 0; t < kind; t++) {
				u32 tgt = rd32(st + (t ? ST_TARGET1 : ST_TARGET0));

				if (tgt >= k)
					return -EINVAL;
				for (n = 0; n < k; n++)
					if (rd32(r + 0x14 + 0xc * n) == tgt + first)
						break;
				if (n == k)
					return -EINVAL;
				if (kind == 1) {
					put_unaligned_le32(n, r + 0x14 + 0xc * j + 4);
				} else {
					x = rd32(r + 0x14 + 0xc * n + 8);
					put_unaligned_le32(x | 2, r + 0x14 + 0xc * n + 8);
					cond = 1;
				}
			}
		}
		put_unaligned_le32(1, r);
		put_unaligned_le32(3, r + 4);
		put_unaligned_le32(cond, r + 8);
		put_unaligned_le32(first, r + 0xc);
		put_unaligned_le32(k, r + 0x10);
		put_unaligned_le64(body, out + 8 + 0x10 * p);
		put_unaligned_le64(0x14 + 0xc * k, out + 0x10 + 0x10 * p);
		body += 0x14 + 0xc * k;
		first += k;
	}
	return 0;
}

static int text_sect(const struct hwx *h, u32 *s_out, u32 *j_out)
{
	u32 s, j;

	for (s = 0; s < h->nsegs; s++)
		for (j = 0; j < seg_nsects(h, s); j++)
			if (sect_buf_type(seg_sect(h, s, j)) == BT_TEXT) {
				*s_out = s;
				*j_out = j;
				return 0;
			}
	return -ENOENT;
}

/*
 * Operation i's segment: its offset in the text section (at text) and its bytes, as the segment properties give
 * them to the firmware. The procedures are runs of operations, so a property's index is its operation's.
 */
static int op_segment(const struct hwx *h, u32 i, u64 text, u64 *off, u64 *len)
{
	const u8 *st = h->op[i].state;
	u64 at = rd64(st + ST_FIRST);

	if (at < text)
		return -EINVAL;
	*off = (u32)(at - text);
	*len = (u64)4 * rd32(st + ST_WORDS);
	return 0;
}

static int build_segprop(const struct hwx *h, u8 *out)
{
	u32 p, j, s, t, first = 0, n = 0;
	u64 text, off, len;

	if (text_sect(h, &s, &t))
		return -EINVAL;
	text = rd64(seg_sect(h, s, t) + SECT_ADDR);
	put_unaligned_le32(h->nops, out);
	for (p = 0; p < h->nprocs; p++) {
		for (j = 0; j < h->proc_count[p]; j++, n++) {
			const u8 *st = h->op[h->proc_first[p] + j].state;
			u8 *r = out + 8 + 0x20 * n;

			if (op_segment(h, h->proc_first[p] + j, text, &off, &len))
				return -EINVAL;
			put_unaligned_le32(rd32(st + ST_SEGID) + first, r);
			put_unaligned_le32(rd32(st + ST_820), r + 4);
			put_unaligned_le32(rd32(st + ST_81C), r + 8);
			put_unaligned_le64(off, r + 0x10);
			put_unaligned_le64(len, r + 0x18);
		}
		first += h->proc_count[p];
	}
	return 0;
}

/* The sections into zeroed buffers of h->size[] bytes */
int hwx_build(const struct hwx *h, void *const out[HWX_NSECT])
{
	return build_generic(h, out[HWX_GENERIC]) ?: build_operation(h, out[HWX_OPERATION]) ?:
	       build_procedure(h, out[HWX_PROCEDURE]) ?: build_segprop(h, out[HWX_SEGPROP]);
}

static void msg_record(u8 *r, u32 index, u32 kind, u32 l3, u64 dva, u64 size)
{
	put_unaligned_le32(1, r);
	put_unaligned_le32(index, r + 4);
	put_unaligned_le32(kind, r + 8);
	put_unaligned_le32(l3, r + 0xc);
	put_unaligned_le32(1, r + 0x10);
	put_unaligned_le64(dva, r + 0x18);
	put_unaligned_le64(size, r + 0x20);
}

/*
 * The type of the LOAD_PROGRAM record a section gets, BT_KERNEL or BT_TEXT, or 0: a kernel (not a split one) or
 * a text section in a read-only segment with data, where the firmware reads it in the mapped .hwx.
 */
static u32 msg_sect_type(const struct hwx *h, u32 s, u32 j)
{
	const u8 *seg = h->seg[s].cmd, *sect = seg_sect(h, s, j);
	u32 bt = sect_buf_type(sect);

	if ((rd32(seg + SEG_INITPROT) & 2) || !rd64(seg + SEG_FILESIZE))
		return 0;
	if ((bt != BT_KERNEL && bt != BT_TEXT) || sect_ksplit(sect))
		return 0;
	return bt;
}

/*
 * LOAD_PROGRAM's records: the kernel and the text sections where the .hwx is mapped (a segment's DVA is the
 * mapping's plus its file offset, ZinAneLoadProgramSegment 0xfffffe000979e3f0), then the four sections.
 */
void hwx_message(const struct hwx *h, u8 *msg, u64 hwx_dva, const u64 dva[HWX_NSECT])
{
	static const u16 at[HWX_NSECT] = { 0x08, 0x98, 0xc8, 0x128 };
	u32 s, j, i;

	memset(msg, 0, HWX_MSG_SIZE);
	put_unaligned_le16(0x200, msg + 4);
	for (s = 0; s < h->nsegs; s++) {
		const u8 *seg = h->seg[s].cmd;
		u64 base = hwx_dva + rd64(seg + SEG_FILEOFF);

		for (j = 0; j < seg_nsects(h, s); j++) {
			const u8 *sect = seg_sect(h, s, j);
			u32 bt = msg_sect_type(h, s, j);

			if (!bt)
				continue;
			msg_record(msg + (bt == BT_KERNEL ? 0x38 : 0x68), sect_index(h, s, j),
				   bt == BT_KERNEL ? HWX_KIND_KERNEL : HWX_KIND_PROGRAM,
				   !memcmp(seg + SEG_NAME, "__L3", 5),
				   base + rd64(sect + SECT_ADDR) - rd64(seg + SEG_VMADDR), rd64(sect + SECT_LEN));
		}
	}
	for (i = 0; i < HWX_NSECT; i++)
		msg_record(msg + at[i], BT_GENERIC + i, HWX_KIND_PROGRAM, 0, dva[i], h->size[i]);
}

/* The bytes of the buffer a call brings for a section: its FVMLIB segment's extent, else the section's */
static u64 sect_buf_size(const struct hwx *h, u32 s, u32 j)
{
	u64 base, top;
	u32 x;

	if (!seg_fvmlib(h, s))
		return rd64(seg_sect(h, s, j) + SECT_LEN);
	base = rd64(h->seg[s].cmd + SEG_VMADDR);
	top = base;
	for (x = 0; x < seg_nsects(h, s); x++) {
		const u8 *sx = seg_sect(h, s, x);

		if (rd64(sx + SECT_ADDR) + rd64(sx + SECT_LEN) > top)
			top = rd64(sx + SECT_ADDR) + rd64(sx + SECT_LEN);
	}
	return top - base;
}

/*
 * The sections a procedure's operations bind that have a generic record, each once: the buffers a call brings
 * and the split kernel sections, HWX_MAX_BUFS at most, a call's records. The kernel and the text LOAD_PROGRAM
 * names are the program's.
 */
static int proc_sects(const struct hwx *h, u32 proc, struct hwx_buf *all)
{
	int n = 0, i;
	u32 o, slot;

	if (proc >= h->nprocs)
		return -EINVAL;
	for (o = h->proc_first[proc]; o < h->proc_first[proc] + h->proc_count[proc]; o++) {
		for (slot = 0; slot < 0x100; slot++) {
			u64 a = rd64(h->op[o].state + 8 * slot);
			u32 s, j, idx;
			int kind;

			if (!a || sect_at(h, a, &s, &j))
				continue;
			kind = sect_generic_kind(seg_sect(h, s, j));
			if (kind < 0)
				continue;
			idx = sect_index(h, s, j);
			for (i = 0; i < n; i++)
				if (all[i].index == idx)
					break;
			if (i < n)
				continue;
			if (n == HWX_MAX_BUFS)
				return -E2BIG;
			all[n].index = idx;
			all[n].kind = kind;
			all[n].prot = rd32(h->seg[s].cmd + SEG_INITPROT) & 3;
			all[n].size = sect_buf_size(h, s, j);
			n++;
		}
	}
	return n;
}

/*
 * The buffers a procedure's call brings, in a procedure call's order: inputs, outputs, intermediates, then
 * kind 5 (ANE_ProgramSendUnCachedRequest_gated 0xfffffe00097b3c14).
 */
int hwx_proc_bufs(const struct hwx *h, u32 proc, struct hwx_buf *bufs, int max)
{
	static const u8 order[4] = { HWX_KIND_INPUT, HWX_KIND_OUTPUT, HWX_KIND_INTERMEDIATE, HWX_KIND_5 };
	struct hwx_buf all[HWX_MAX_BUFS];
	int n, out = 0, k, i;

	n = proc_sects(h, proc, all);
	if (n < 0)
		return n;
	for (k = 0; k < 4; k++)
		for (i = 0; i < n; i++)
			if (all[i].kind == order[k]) {
				if (out == max)
					return -E2BIG;
				bufs[out++] = all[i];
			}
	return out;
}

/*
 * A procedure call's records for the split kernel sections its operations bind, after the buffers', max at
 * most: where the .hwx is mapped, as LOAD_PROGRAM's kernel. Returns their count.
 */
int hwx_call_kernels(const struct hwx *h, u32 proc, u8 *d, int max, u64 hwx_dva)
{
	struct hwx_buf all[HWX_MAX_BUFS];
	int n, out = 0, i;
	u32 s;

	n = proc_sects(h, proc, all);
	if (n < 0)
		return n;
	for (i = 0; i < n; i++) {
		const u8 *seg, *sect;

		if (all[i].kind != HWX_KIND_KERNEL)
			continue;
		if (out == max)
			return -E2BIG;
		/* its segment is no FVMLIB one (hwx_parse): the index is the section's own */
		for (s = 0; s < h->nsegs; s++)
			if (all[i].index - h->seg[s].first < seg_nsects(h, s))
				break;
		if (s == h->nsegs)
			return -EINVAL;
		seg = h->seg[s].cmd;
		sect = seg_sect(h, s, all[i].index - h->seg[s].first);
		msg_record(d + 0x30 * out++, all[i].index, HWX_KIND_KERNEL, !memcmp(seg + SEG_NAME, "__L3", 5),
			   hwx_dva + rd64(seg + SEG_FILEOFF) + rd64(sect + SECT_ADDR) - rd64(seg + SEG_VMADDR),
			   all[i].size);
	}
	return out;
}

/* A refusal: why, for the log */
static int hwx_refuse(const char **why, const char *w)
{
	*why = w;
	return -EINVAL;
}

/* The text section LOAD_PROGRAM names: the program's only one */
static int hwx_text(const struct hwx *h, const u8 **text, u64 *addr, u64 *len, u32 *index)
{
	const u8 *seg, *sect;
	u32 s, j, s0 = 0, j0 = 0, n = 0;

	for (s = 0; s < h->nsegs; s++)
		for (j = 0; j < seg_nsects(h, s); j++)
			if (sect_buf_type(seg_sect(h, s, j)) == BT_TEXT) {
				s0 = s;
				j0 = j;
				n++;
			}
	if (n != 1 || msg_sect_type(h, s0, j0) != BT_TEXT)
		return -EINVAL;
	seg = h->seg[s0].cmd;
	sect = seg_sect(h, s0, j0);
	*addr = rd64(sect + SECT_ADDR);
	*len = rd64(sect + SECT_LEN);
	/* inside its segment's data (hwx_parse) */
	*text = h->b + rd64(seg + SEG_FILEOFF) + *addr - rd64(seg + SEG_VMADDR);
	*index = sect_index(h, s0, j0);
	return 0;
}

/*
 * The firmware's load checker, CAneProgramCheckerH15 (rda ane_fw_t603x_1483: sub_5064C 0x5064c and its callees
 * sub_4F938 the generic section, sub_4FAFC the operations, sub_4FC30 the procedures, sub_4FD24 the segment
 * properties, sub_4FE58 the TD counts, sub_502B4 and sub_50024 the buffers an operation binds), on the sections
 * hwx_build made and the text LOAD_PROGRAM names. A section it refuses asserts the firmware
 * (CAneProgramManager.cpp:475), which then hangs for every client until a restart. Stricter where the firmware
 * reads what it did not bound: one text section, every segment's TD headers inside it.
 */
int hwx_check(const struct hwx *h, void *const out[HWX_NSECT], const char **why)
{
	const u8 *g = out[HWX_GENERIC], *op = out[HWX_OPERATION], *pr = out[HWX_PROCEDURE], *sp = out[HWX_SEGPROP];
	const u8 *text;
	s64 kern_index = -1;
	u64 taddr, tlen, end;
	u32 text_index, n, ng, i, k, s, j;

	if (hwx_text(h, &text, &taddr, &tlen, &text_index))
		return hwx_refuse(why, "not one text section, in a read-only segment");
	for (s = 0; s < h->nsegs; s++)
		for (j = 0; j < seg_nsects(h, s); j++)
			if (msg_sect_type(h, s, j) == BT_KERNEL)
				kern_index = sect_index(h, s, j);	/* the last, as hwx_message */

	/* sub_4F938 */
	if (rd32(g) != 1 || rd32(g + 4) > 0x10)
		return hwx_refuse(why, "generic: its version or more than 16 engines");
	ng = rd32(g + 0x204);
	if (!ng || ng > 0x200 || 0x208 + 0x30 * (size_t)ng > h->size[HWX_GENERIC])
		return hwx_refuse(why, "generic: no buffer or more than 0x200");
	for (k = 0; k < ng; k++)
		if (!(rd32(g + 0x208 + 0x30 * k) & 1) || rd32(g + 0x208 + 0x30 * k + 8) >= 8)
			return hwx_refuse(why, "generic: a record invalid or of kind 8 or more");

	/* sub_4FAFC, sub_502B4, sub_50024 */
	n = rd32(op);
	if (n > 0x80 || 4 + 0x40c * (size_t)n > h->size[HWX_OPERATION])
		return hwx_refuse(why, "more than 0x80 operations");
	for (i = 0; i < n; i++) {
		const u8 *r = op + 4 + 0x40c * i;
		u32 m;

		if (rd32(r) > 3)
			return hwx_refuse(why, "an operation's type");
		if (rd32(r))
			continue;
		m = rd32(r + 8);
		if (rd16(r + 4) > 0x10 || m > 0x3d)
			return hwx_refuse(why, "an operation with more than 16 engines or 0x3d buffers");
		for (k = 0; k < m; k++) {
			u32 bar = rd32(r + 0xc + 8 * k), idx = rd32(r + 0x10 + 8 * k), hits, x;

			if (bar > 0x3c)
				return hwx_refuse(why, "an operation binds a logical BAR past 0x3c");
			hits = (idx == text_index) + (kern_index >= 0 && idx == kern_index);
			for (x = 0; x < ng; x++)
				hits += rd32(g + 0x208 + 0x30 * x + 4) == idx;
			if (hits != 1)
				return hwx_refuse(why, "an operation binds a buffer its records do not name once");
		}
	}

	/* sub_4FC30 */
	n = rd32(pr);
	if (8 + 0x10 * (size_t)n > h->size[HWX_PROCEDURE])
		return hwx_refuse(why, "procedures: count");
	for (i = 0, end = 0; i < n; i++) {
		u64 off = rd64(pr + 8 + 0x10 * i), len = rd64(pr + 0x10 + 0x10 * i);

		if (off < end || len > h->size[HWX_PROCEDURE] || off > h->size[HWX_PROCEDURE] - len)
			return hwx_refuse(why, "procedures: a body past the section or before the last");
		end = off + len;
	}

	/* sub_4FD24, sub_4FE58 */
	n = rd32(sp);
	if (8 + 0x20 * (size_t)n > h->size[HWX_SEGPROP])
		return hwx_refuse(why, "segment properties: count");
	for (i = 0, end = 0; i < n; i++) {
		const u8 *r = sp + 8 + 0x20 * i;
		u64 off = rd64(r + 0x10), len = rd64(r + 0x18), at, last = 0;
		u32 hdr, count = 0;

		if (off < end || len > tlen || off > tlen - len)
			return hwx_refuse(why, "a segment past the text or before the last");
		end = off + len;
		if (len < 4)
			return hwx_refuse(why, "an empty segment");
		hdr = rd32(text + off);
		for (at = hdr & 4 ? 0x30 : 0x10; at < len; count++) {
			u32 words = rd16(text + off + at + 2) & 0x7ff;

			if (!words)
				return hwx_refuse(why, "a TD of no words");
			last = at;
			at += (4 * words + 0xf) & 0x3ff0;
		}
		if (!count || count != rd32(r + 4))
			return hwx_refuse(why, "a segment's TDs other than its count");
		if ((hdr & 1) && (last + 0x1c > len || rd32(text + off + last + 0x18)))
			return hwx_refuse(why, "a segment's last TD's word 6");
	}
	return 0;
}

/*
 * The task descriptors' check (defence in depth: the DART is the bound). A TD is a register-write program for
 * the engine (rda ane_fw_t603x_1483 sub_367EC 0x367ec, CSneTMDrvH15.cpp): a header of 8 words, then commands,
 * one header word each, bits 31-29: 000 writes registers r to r + n (r bits 0-14, n bits 15-20), 1xx writes r
 * and r + 1 + i for each set bit i of bits 15-30, 001 relocates register r (64-bit when bit 15) to hardware
 * BAR bits 22-28 plus the value that follows, 010 and 011 assert the firmware. The firmware writes no TD; the
 * task manager applies the relocations from the BARs the firmware fills per call (sub_48580 0x48580).
 */

/* The address registers only a relocation may fill: input, second source, output, kernels */
static bool td_addr_reg(u32 r)
{
	switch (r) {
	case 0x1344: case 0x1345:
	case 0x134a: case 0x134b:
	case 0x1442: case 0x1443:
	case 0x1544: case 0x1545:
	case 0x1586: case 0x1587:
		return true;
	}
	return false;
}

static const char td_bad_write[] = "a TD writes an address register or one outside the compiler's blocks";

/* The register blocks the compiler writes, its address registers left out */
static bool td_write_ok(u32 r)
{
	return (r < 0xc00 || (r >= 0x1000 && r < 0x1700)) && !td_addr_reg(r);
}

/*
 * The buffer an operation (its thread state st) binds at logical BAR l: thread slots 2l and 2l + 1
 * (ZinComputeSetSegmentOperationProperty, build_operation), one buffer if both are set.
 */
static int td_bound(const struct hwx *h, const u8 *st, u32 l, u32 *s, u32 *j)
{
	u64 a0 = rd64(st + 16 * l), a1 = rd64(st + 16 * l + 8);
	u32 s1, j1;

	if (!a0 && !a1)
		return -ENOENT;
	if (sect_at(h, a0 ?: a1, s, j))
		return -ENOENT;
	if (a0 && a1 && (sect_at(h, a1, &s1, &j1) || sect_index(h, s1, j1) != sect_index(h, *s, *j)))
		return -EINVAL;
	return 0;
}

static int td_reloc(const struct hwx *h, const u8 *st, u32 w, const u8 *val, const char **why)
{
	u32 reg = w & 0x7fff, bar = (w >> 22) & 0x7f, s, j;
	const u8 *sect;
	bool ok;
	int kind;

	if (w & 0x3f0000)
		return hwx_refuse(why, "a relocation's bits 16-21");
	if (!(w & BIT(15))) {
		/* DMA configuration words against BAR 8, logical 4, which no call binds in the corpus */
		if ((reg == 0x1340 || reg == 0x1341 || reg == 0x1440) && bar == 8)
			return 0;
		return hwx_refuse(why, "a 32-bit relocation other than BAR 8's of 0x1340, 0x1341, 0x1440");
	}
	if ((bar & 1) || bar >> 1 > 0x3c)
		return hwx_refuse(why, "a 64-bit relocation's BAR odd or past 0x79");
	if (td_bound(h, st, bar >> 1, &s, &j))
		return hwx_refuse(why, "a relocation against a BAR its operation does not bind");
	sect = seg_sect(h, s, j);
	kind = sect_generic_kind(sect);
	switch (reg) {
	case 0x1344:
	case 0x134a:
		ok = kind == HWX_KIND_INPUT || kind == HWX_KIND_INTERMEDIATE;
		break;
	case 0x1442:
		ok = (rd32(h->seg[s].cmd + SEG_INITPROT) & 2) && kind >= 0 && kind != HWX_KIND_KERNEL;
		break;
	case 0x1544:
	case 0x1586:
		ok = sect_buf_type(sect) == BT_KERNEL;
		break;
	default:
		ok = false;
	}
	if (!ok)
		return hwx_refuse(why, "a 64-bit relocation of a register against a buffer it does not take");
	/* the BAR holds the buffer's start: a kernel section's, a call buffer's (its FVMLIB segment's) */
	if (rd64(val) >= sect_buf_size(h, s, j))
		return hwx_refuse(why, "a relocation's offset past its buffer");
	return 0;
}

static int td_cmds(const struct hwx *h, const u8 *st, const u8 *td, u32 tdlen, const char **why)
{
	u32 o, w, reg, n, len, k;
	int ret;

	for (o = 0x20; o < tdlen; o += len) {
		if (tdlen - o < 4)
			return hwx_refuse(why, "a TD command past its TD");
		w = rd32(td + o);
		reg = w & 0x7fff;
		if (w >> 29 == 2 || w >> 29 == 3)
			return hwx_refuse(why, "a TD's assert command");
		switch (w >> 29) {
		case 0:
			n = (w >> 15) & 0x3f;
			len = 8 + 4 * n;
			break;
		case 1:
			n = 0;
			len = w & BIT(15) ? 12 : 8;
			break;
		default:
			n = (w >> 15) & 0xffff;
			len = 8 + 4 * hweight32(n);
			break;
		}
		if (len > tdlen - o)
			return hwx_refuse(why, "a TD command past its TD");
		switch (w >> 29) {
		case 0:
			for (k = 0; k <= n; k++)
				if (!td_write_ok(reg + k))
					return hwx_refuse(why, td_bad_write);
			break;
		case 1:
			ret = td_reloc(h, st, w, td + o + 4, why);
			if (ret)
				return ret;
			break;
		default:
			if (!td_write_ok(reg))
				return hwx_refuse(why, td_bad_write);
			for (k = 0; k < 16; k++)
				if ((n & BIT(k)) && !td_write_ok(reg + 1 + k))
					return hwx_refuse(why, td_bad_write);
			break;
		}
	}
	return 0;
}

/*
 * Each operation's segment walked TD by TD: headers inside the segment with words 3 and 5 (gen 0-3's next TD)
 * zero and no word 7 bit 1 (a 0x24-byte header), every command inside its TD; plain writes only in the blocks
 * the compiler writes and to no address register; a 64-bit relocation only of an address register, against a
 * BAR its operation binds to a buffer of the register's kind (reads an input or intermediate, writes a buffer
 * of a writable segment, weights a kernel section), its offset inside that buffer; a 32-bit one only of the
 * DMA words against BAR 8. Extents (strides and sizes) are not bounded: the DART is.
 */
int hwx_check_tds(const struct hwx *h, const char **why)
{
	const u8 *text;
	u64 taddr, tlen;
	u32 i, tindex;
	int ret;

	if (hwx_text(h, &text, &taddr, &tlen, &tindex))
		return hwx_refuse(why, "not one text section, in a read-only segment");
	for (i = 0; i < h->nops; i++) {
		const u8 *st = h->op[i].state;
		u64 off, len, at;
		u32 count = 0;

		if (op_segment(h, i, taddr, &off, &len) || len < 4 || len > tlen || off > tlen - len)
			return hwx_refuse(why, "a segment outside the text");
		for (at = rd32(text + off) & 4 ? 0x30 : 0x10; at < len; count++) {
			const u8 *td = text + off + at;
			u32 tdlen;

			if (len - at < 0x20)
				return hwx_refuse(why, "a TD's header past its segment");
			tdlen = 4 * ((rd32(td) >> 16) & 0x7ff);
			if (tdlen < 0x20 || tdlen > len - at)
				return hwx_refuse(why, "a TD's size");
			if (rd32(td + 0xc) || rd32(td + 0x14) || (rd32(td + 0x1c) & 2))
				return hwx_refuse(why, "a TD header's word 3 or 5 set, or word 7 bit 1");
			ret = td_cmds(h, st, td, tdlen, why);
			if (ret)
				return ret;
			at += (tdlen + 0xf) & 0x3ff0;
		}
		if (count != rd32(st + ST_820))
			return hwx_refuse(why, "a segment's TDs other than its count");
	}
	return 0;
}
