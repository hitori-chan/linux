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

static int build_segprop(const struct hwx *h, u8 *out)
{
	u32 p, j, s, t, first = 0, n = 0;
	u64 text;

	if (text_sect(h, &s, &t))
		return -EINVAL;
	text = rd64(seg_sect(h, s, t) + SECT_ADDR);
	put_unaligned_le32(h->nops, out);
	for (p = 0; p < h->nprocs; p++) {
		for (j = 0; j < h->proc_count[p]; j++, n++) {
			const u8 *st = h->op[h->proc_first[p] + j].state;
			u8 *r = out + 8 + 0x20 * n;
			u64 at = rd64(st + ST_FIRST);

			if (at < text)
				return -EINVAL;
			put_unaligned_le32(rd32(st + ST_SEGID) + first, r);
			put_unaligned_le32(rd32(st + ST_820), r + 4);
			put_unaligned_le32(rd32(st + ST_81C), r + 8);
			put_unaligned_le64((u32)(at - text), r + 0x10);
			put_unaligned_le64((u64)4 * rd32(st + ST_WORDS), r + 0x18);
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

		if ((rd32(seg + SEG_INITPROT) & 2) || !rd64(seg + SEG_FILESIZE))
			continue;
		for (j = 0; j < seg_nsects(h, s); j++) {
			const u8 *sect = seg_sect(h, s, j);
			u32 bt = sect_buf_type(sect);

			if ((bt != BT_KERNEL && bt != BT_TEXT) || sect_ksplit(sect))
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
			if (seg_fvmlib(h, s)) {
				u32 x;
				u64 base = rd64(h->seg[s].cmd + SEG_VMADDR), top = base;

				for (x = 0; x < seg_nsects(h, s); x++) {
					const u8 *sx = seg_sect(h, s, x);

					if (rd64(sx + SECT_ADDR) + rd64(sx + SECT_LEN) > top)
						top = rd64(sx + SECT_ADDR) + rd64(sx + SECT_LEN);
				}
				all[n].size = top - base;
			} else {
				all[n].size = rd64(seg_sect(h, s, j) + SECT_LEN);
			}
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
