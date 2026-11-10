/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Apple Neural Engine: a program from the compiler's Mach-O (.hwx)
 */

#ifndef _APPLE_ANE_HWX_H
#define _APPLE_ANE_HWX_H

#ifdef __KERNEL__
#include <linux/bits.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unaligned.h>
#endif

#define HWX_MAX_SEGS	64
#define HWX_MAX_OPS	128
#define HWX_MAX_PROCS	0x80
#define HWX_MAX_BUFS	64

/* LOAD_PROGRAM (command 0x200) */
#define HWX_MSG_SIZE	0x1c0
#define HWX_MSG_PROGRAM	0x1b8	/* the program ID, in the answer */

/* The four sections LOAD_PROGRAM names */
enum { HWX_GENERIC, HWX_OPERATION, HWX_PROCEDURE, HWX_SEGPROP, HWX_NSECT };

/* A buffer's kind in the generic section and in a procedure call */
enum { HWX_KIND_INPUT = 0, HWX_KIND_OUTPUT = 1, HWX_KIND_INTERMEDIATE = 2, HWX_KIND_KERNEL = 3,
       HWX_KIND_PROGRAM = 4, HWX_KIND_5 = 5 };

struct hwx_seg {
	const u8 *cmd;		/* its segment_command_64 */
	u32 first;		/* the global index of its first section */
};

struct hwx_op {
	const u8 *state;	/* the thread state, at least 0x838 bytes */
	const u8 *name;		/* the procedure's name, after the state */
	size_t name_len;
};

struct hwx {
	const u8 *b;
	size_t len;
	u32 cpusubtype, filetype;
	u32 nsegs, nops, nprocs;
	struct hwx_seg seg[HWX_MAX_SEGS];
	struct hwx_op op[HWX_MAX_OPS];
	u32 proc_first[HWX_MAX_PROCS], proc_count[HWX_MAX_PROCS];
	u32 ngeneric;			/* the generic section's records */
	size_t size[HWX_NSECT];		/* each section's bytes */
};

/* A buffer one procedure binds: its generic record */
struct hwx_buf {
	u32 index, kind, prot;
	u64 size;
};

int hwx_parse(struct hwx *h, const void *b, size_t len);
int hwx_build(const struct hwx *h, void *const out[HWX_NSECT]);
void hwx_message(const struct hwx *h, u8 *msg, u64 hwx_dva, const u64 dva[HWX_NSECT]);
int hwx_proc_bufs(const struct hwx *h, u32 proc, struct hwx_buf *bufs, int max);
int hwx_call_kernels(const struct hwx *h, u32 proc, u8 *d, int max, u64 hwx_dva);

#endif
