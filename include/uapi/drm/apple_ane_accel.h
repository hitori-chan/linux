/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Apple Neural Engine (M3): the DRM accel interface.
 *
 * A program is the compiler's output, an H15 Mach-O (.hwx, segment threads), handed over in a buffer
 * object: the kernel parses it, builds the firmware's sections and loads it. A submission calls one
 * of its procedures with a buffer object for each buffer the procedure binds; PROGRAM_INFO lists
 * them. A submission waits for the implicit fences of its buffers and the syncobjs it names, and its
 * fence goes on its buffers and on its out-syncobj.
 */

#ifndef _UAPI_APPLE_ANE_ACCEL_H_
#define _UAPI_APPLE_ANE_ACCEL_H_

#include "drm.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define DRM_APPLE_ANE_BO_CREATE		0x00
#define DRM_APPLE_ANE_BO_WAIT		0x01
#define DRM_APPLE_ANE_PROGRAM_CREATE	0x02
#define DRM_APPLE_ANE_PROGRAM_DESTROY	0x03
#define DRM_APPLE_ANE_PROGRAM_INFO	0x04
#define DRM_APPLE_ANE_SUBMIT		0x05

#define DRM_IOCTL_APPLE_ANE_BO_CREATE \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_APPLE_ANE_BO_CREATE, struct drm_apple_ane_bo_create)
#define DRM_IOCTL_APPLE_ANE_BO_WAIT \
	DRM_IOW(DRM_COMMAND_BASE + DRM_APPLE_ANE_BO_WAIT, struct drm_apple_ane_bo_wait)
#define DRM_IOCTL_APPLE_ANE_PROGRAM_CREATE \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_APPLE_ANE_PROGRAM_CREATE, struct drm_apple_ane_program_create)
#define DRM_IOCTL_APPLE_ANE_PROGRAM_DESTROY \
	DRM_IOW(DRM_COMMAND_BASE + DRM_APPLE_ANE_PROGRAM_DESTROY, struct drm_apple_ane_program_destroy)
#define DRM_IOCTL_APPLE_ANE_PROGRAM_INFO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_APPLE_ANE_PROGRAM_INFO, struct drm_apple_ane_program_info)
#define DRM_IOCTL_APPLE_ANE_SUBMIT \
	DRM_IOW(DRM_COMMAND_BASE + DRM_APPLE_ANE_SUBMIT, struct drm_apple_ane_submit)

/**
 * struct drm_apple_ane_bo_create - a buffer object the engine can read and write
 * @size: in, its bytes (rounded up to the page)
 * @flags: in, 0
 * @handle: out, its GEM handle
 * @offset: out, its offset for mmap() on the device
 */
struct drm_apple_ane_bo_create {
	__u64 size;
	__u32 flags;
	__u32 handle;
	__u64 offset;
};

/**
 * struct drm_apple_ane_bo_wait - wait for the submissions that write a buffer object
 * @handle: the buffer object
 * @pad: 0
 * @timeout_ns: an absolute CLOCK_MONOTONIC time; 0 polls
 */
struct drm_apple_ane_bo_wait {
	__u32 handle;
	__u32 pad;
	__s64 timeout_ns;
};

/**
 * struct drm_apple_ane_program_create - load a program; needs CAP_SYS_ADMIN, since a program's task
 * descriptors drive the engine's DMA in the one address space all clients share
 * @handle: in, the buffer object holding the .hwx
 * @size: in, the .hwx's bytes from the object's start
 * @program: out, the program's ID in this file
 * @procedures: out, its procedure count
 */
struct drm_apple_ane_program_create {
	__u32 handle;
	__u32 size;
	__u32 program;
	__u32 procedures;
};

/**
 * struct drm_apple_ane_program_destroy - unload a program once its submissions are done
 * @program: its ID
 * @pad: 0
 */
struct drm_apple_ane_program_destroy {
	__u32 program;
	__u32 pad;
};

#define DRM_APPLE_ANE_BUF_INPUT		0
#define DRM_APPLE_ANE_BUF_OUTPUT	1
#define DRM_APPLE_ANE_BUF_INTERMEDIATE	2
#define DRM_APPLE_ANE_BUF_KIND_5	5

/**
 * struct drm_apple_ane_buf_info - a buffer a procedure binds
 * @index: the program's buffer index, which a submission names
 * @kind: DRM_APPLE_ANE_BUF_*
 * @size: the bytes the buffer object needs at least
 */
struct drm_apple_ane_buf_info {
	__u32 index;
	__u32 kind;
	__u64 size;
};

/**
 * struct drm_apple_ane_program_info - the buffers one procedure binds
 * @program: in
 * @procedure: in
 * @count: in, the entries @bufs holds; out, the buffers the procedure binds
 * @pad: 0
 * @bufs: in, a user pointer to @count struct drm_apple_ane_buf_info, or 0
 */
struct drm_apple_ane_program_info {
	__u32 program;
	__u32 procedure;
	__u32 count;
	__u32 pad;
	__u64 bufs;
};

/**
 * struct drm_apple_ane_submit_buf - one bound buffer
 * @index: the program's buffer index (struct drm_apple_ane_buf_info)
 * @handle: the buffer object
 * @offset: the buffer's start in the object, page-aligned
 */
struct drm_apple_ane_submit_buf {
	__u32 index;
	__u32 handle;
	__u64 offset;
};

/**
 * struct drm_apple_ane_submit - call one procedure
 * @program: the program's ID
 * @procedure: the procedure's index
 * @buf_count: the entries in @bufs: every buffer the procedure binds, each once
 * @in_sync_count: the entries in @in_syncs
 * @bufs: a user pointer to struct drm_apple_ane_submit_buf
 * @in_syncs: a user pointer to __u32 syncobj handles the call waits for
 * @out_sync: a syncobj handle that takes the call's fence, or 0
 * @priority: 0
 */
struct drm_apple_ane_submit {
	__u32 program;
	__u32 procedure;
	__u32 buf_count;
	__u32 in_sync_count;
	__u64 bufs;
	__u64 in_syncs;
	__u32 out_sync;
	__u32 priority;
};

#if defined(__cplusplus)
}
#endif

#endif
