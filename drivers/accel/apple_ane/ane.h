/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Apple Neural Engine driver
 *
 * Copyright The Asahi Linux Contributors
 */

#ifndef _APPLE_ANE_H
#define _APPLE_ANE_H

#include <drm/drm_device.h>
#include <drm/gpu_scheduler.h>
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/irqreturn.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pm_domain.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#define APPLE_ANE_NAME "apple-ane"

#define ANE_MAX_CHANNELS 0x20

/* The firmware's window, from the DART's base: __TEXT, __DATA and "PHNI" */
#define ANE_FW_WINDOW 0x700000

/* The engine window's second range: the DART parameters, SCRATCH, the doorbell and the IRQs */
#define ANE_CTL_BASE 0x1830000

/* IO_T2H's CSNE_CMD_PROGRAM_EVENT, a procedure call's end */
#define ANE_T2H_PROGRAM_EVENT	0x300
#define ANE_T2H_EVENT_SIZE	0x38

#define ANE_HWX_MAX		(32 << 20)
#define ANE_COOKIE_MASK		0xffffffff00000000ull
/*
 * The calls the firmware holds at once: CREATE_PROCESS gives each process a pool of 32 call slots,
 * a PROCEDURE_CALL takes one before its 0x300 and a call with none left asserts the firmware
 * ("No resource for new Procedure call", CAneProgramManagerH15.cpp:368; rda ane_fw_t603x_1483
 * sub_47484 0x476e4, sub_48580 0x489d8); it acks the message first, so it never refuses one. The
 * kext counts against RESOURCE_INFO_GET's +0x10 (calls a process) and +0x14 (requests a priority),
 * 32 each, under its 64 overall (firmwareResourceIsAvailable, rda AppleH11ANEInterface
 * 0xfffffe0009791830). Every call here goes at one priority, so 32 bounds both.
 */
#define ANE_CALLS_IN_FLIGHT	32

/* IO_T2H 0x300 events that end a procedure call */
#define ANE_EVENT_DONE		1
#define ANE_EVENT_FAILED	2

struct ane_buf {
	void *cpu;
	dma_addr_t iova;
	size_t size;
};

/* A firmware segment: the driver's pages, mapped again at the firmware's address */
struct ane_seg {
	struct ane_buf buf;
	u64 iova;
	size_t size;
};

/* A surface the firmware asked for on SHAREDMALLOC */
struct ane_surface {
	struct list_head node;
	struct ane_buf buf;
	u32 tag;
};

/* IOProcessorChannel (rda AppleH11ANEInterface 0xfffffe000975ba90): a ring of 64-byte slots */
struct ane_channel {
	char name[0x21];
	u8 *ring;
	u32 slots;
	u32 bell;
	u32 kind;		/* the record's +0x40: 0 the host produces, 2 unidirectional */
	u32 type;		/* the slot's bit 0 that means the host holds it */
	s32 rd, wr;		/* -1: nothing to read, no slot to write */
};

struct apple_ane {
	struct drm_device drm;	/* the accel device (ane-accel.c) */
	struct device *dev;
	/*
	 * The engine's window in two: below its DARTs (0x1800000-0x1824000, held by
	 * apple-dart) and above them, from ANE_CTL_BASE. Offsets stay the engine's.
	 */
	void __iomem *regs;
	void __iomem *regs_ctl;
	int irq;
	struct dev_pm_domain_list *pd_list;
	struct iommu_domain *domain;

	phys_addr_t regs_phys;

	/* From the disk at the first boot (ane-load.c) */
	struct ane_seg text, data;
	void *data_image;	/* __DATA as each boot starts it: the image's, patched */

	/* Everything below is valid while the firmware runs */
	struct mutex lock;
	bool running;
	u32 fw_gen;		/* counts the firmware's boots: a program is of one */
	struct mutex ring_lock;
	struct ane_buf ipc, heap, dmm;	/* "IPC ", "HEAP", the commands' "DMM" */
	struct ane_buf fwheap;		/* "PHNI": the rest of the firmware's window */
	u64 fwheap_iova;
	u32 num_channels;
	struct ane_channel ch[ANE_MAX_CHANNELS];
	int ch_malloc, ch_terminal, ch_io, ch_io_t2h;
	struct list_head surfaces;

	/* one command at a time, under lock */
	struct completion cmd_done;
	u64 cmd_iova;

	/* the lab's program and its procedure calls (ane-job.c), under lock */
	struct ane_prog *prog;
	void *hwx_stage;
	size_t hwx_len;
	struct completion job_done;
	u8 job_event[ANE_T2H_EVENT_SIZE];
	u64 job_cookie;
	u32 job_seq, job_status;

	struct dentry *debugfs;

	/* The accel device's submissions (ane-accel.c) */
	struct drm_gpu_scheduler sched;
	struct mutex sched_lock;
	spinlock_t fence_lock, job_lock;
	struct list_head inflight;	/* the calls the firmware holds, under job_lock */
	u64 fence_ctx, fence_seq;
	u32 call_seq;
	u32 fw_users;			/* its programs, under lock */
	bool accel_booted;		/* the firmware started for them */
	struct delayed_work idle_work;
	struct list_head progs;		/* every program loaded, under lock: loaded again after a sleep */
	bool sleep_boot;		/* the firmware ran for programs when the system slept */
};

int ane_alloc(struct apple_ane *ane, struct ane_buf *buf, size_t size);
void ane_free(struct apple_ane *ane, struct ane_buf *buf);
int ane_command(struct apple_ane *ane, u16 id, void *buf, size_t size, size_t reply);

void ane_job_init(struct apple_ane *ane);
void ane_job_stop(struct apple_ane *ane);
void ane_job_fini(struct apple_ane *ane);
void ane_job_event(struct apple_ane *ane, const u8 *m);

/* The accel device (ane-accel.c) */
extern const struct drm_driver ane_drm_driver;
int ane_accel_init(struct apple_ane *ane);
void ane_accel_fini(struct apple_ane *ane);
void ane_accel_suspend(struct apple_ane *ane);
void ane_accel_resume(struct apple_ane *ane);
void ane_accel_event(struct apple_ane *ane, u64 cookie, u32 event);

/* Programs (ane-job.c), under ane->lock */
struct hwx_buf;
struct ane_prog *ane_prog_create(struct apple_ane *ane, const void *hwx, size_t len);
void ane_prog_destroy(struct apple_ane *ane, struct ane_prog *p);
void ane_progs_reload(struct apple_ane *ane);
bool ane_prog_live(struct apple_ane *ane, const struct ane_prog *p);
u32 ane_prog_procs(const struct ane_prog *p);
u32 ane_prog_id(const struct ane_prog *p);
int ane_prog_bufs(const struct ane_prog *p, u32 proc, struct hwx_buf *bufs, int max);
int ane_prog_call(struct apple_ane *ane, struct ane_prog *p, u32 proc, u64 cookie, const struct hwx_buf *bufs,
		  const dma_addr_t *dva, int n);

int ane_fw_load(struct apple_ane *ane);
void ane_fw_unload(struct apple_ane *ane);
int ane_fw_boot(struct apple_ane *ane);
void ane_fw_shutdown(struct apple_ane *ane);
void ane_fw_kill(struct apple_ane *ane);
irqreturn_t ane_fw_irq(int irq, void *data);
irqreturn_t ane_fw_irq_thread(int irq, void *data);

static inline void __iomem *ane_reg(struct apple_ane *ane, u32 off)
{
	return off >= ANE_CTL_BASE ? ane->regs_ctl + (off - ANE_CTL_BASE) : ane->regs + off;
}

#endif
