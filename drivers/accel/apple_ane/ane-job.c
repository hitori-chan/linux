// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple Neural Engine: programs and their procedure calls. The accel device (ane-accel.c) and the
 * lab's debugfs files below use them:
 *
 *   # cat model.H15.espresso.hwx > /sys/kernel/debug/<ane>/hwx
 *   # echo 1 > /sys/kernel/debug/<ane>/load     (LOAD_PROGRAM, then a process on it)
 *   # echo 0 > /sys/kernel/debug/<ane>/run      (procedure 0, inputs filled with fp16 0.5)
 *   # echo 0 > /sys/kernel/debug/<ane>/load
 *
 * The commands, rda AppleH11ANEInterface 14.8.3: 0x200 load (ANE_ProgramCreate_gated 0xfffffe00097a04e4), 0x202
 * create process (ANE_ProcessCreate_gated), 0x20c procedure call (ANE_ProgramSendUnCachedRequest_gated
 * 0xfffffe00097b3c14), its completion 0x300 on IO_T2H (processTargetToHostIOCommand 0xfffffe000977e898), 0x203 and
 * 0x201 to undo. A command's ack is its u16 at +6.
 */

#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "ane.h"
#include "ane-hwx.h"

#define ANE_CMD_LOAD_PROGRAM		0x200
#define ANE_CMD_UNLOAD_PROGRAM		0x201
#define ANE_CMD_CREATE_PROCESS		0x202
#define ANE_CMD_DESTROY_PROCESS		0x203
#define ANE_CMD_PROCEDURE_CALL		0x20c

#define ANE_CREATE_SIZE			0x214
#define ANE_CALL_SIZE			0xca8
#define ANE_CALL_BUFS			0x60	/* 0x30-byte descriptors, 64 at most */
#define ANE_CALL_TIMEOUT		(2 * HZ)

#define ANE_LAB_COOKIE			0xa4e0000000000000ull

/*
 * The firmware asserts 2 <= priority <= 7 for 0x20c (CANEController.cpp:1825); the kext passes the client's value
 * and lowers a realtime client's by one, to 2 at least (ANE_ProgramSendRequestInitialChecksAndLookups_gated
 * 0xfffffe00097af460). 4, the middle: macOS's default is not verified.
 */
#define ANE_CALL_PRIORITY		4

struct ane_prog {
	struct hwx h;
	struct ane_buf hwx, sect[HWX_NSECT];
	u32 program, process;
	u32 gen;		/* the firmware's boot it was loaded in */
	bool loaded, created;
	struct list_head node;	/* on ane->progs */
};

static u16 ane_ack(const u8 *msg)
{
	return get_unaligned_le16(msg + 6);
}

u32 ane_prog_procs(const struct ane_prog *p)
{
	return p->h.nprocs;
}

u32 ane_prog_id(const struct ane_prog *p)
{
	return p->program;
}

bool ane_prog_live(struct apple_ane *ane, const struct ane_prog *p)
{
	return ane->running && p->gen == ane->fw_gen;
}

int ane_prog_bufs(const struct ane_prog *p, u32 proc, struct hwx_buf *bufs, int max)
{
	return hwx_proc_bufs(&p->h, proc, bufs, max);
}

/* Under ane->lock. A program of an earlier boot went with that firmware: only its memory is left. */
void ane_prog_destroy(struct apple_ane *ane, struct ane_prog *p)
{
	u8 msg[0x10] = {};
	int i;

	if (!p)
		return;
	list_del(&p->node);
	if (p->created && ane_prog_live(ane, p)) {
		/* as ANE_ProcessDestroy_gated (0xfffffe0009764fdc) sends it */
		put_unaligned_le32(p->program, msg + 8);
		put_unaligned_le32(p->process, msg + 0xc);
		if (ane_command(ane, ANE_CMD_DESTROY_PROCESS, msg, 0x10, 0x10) || ane_ack(msg))
			dev_err(ane->dev, "destroying process %u: ack %#x\n", p->process, ane_ack(msg));
	}
	if (p->loaded && ane_prog_live(ane, p)) {
		memset(msg, 0, sizeof(msg));
		put_unaligned_le32(p->program, msg + 8);
		if (ane_command(ane, ANE_CMD_UNLOAD_PROGRAM, msg, 0xc, 0xc) || ane_ack(msg))
			dev_err(ane->dev, "unloading program %u: ack %#x\n", p->program, ane_ack(msg));
	}
	for (i = 0; i < HWX_NSECT; i++)
		ane_free(ane, &p->sect[i]);
	ane_free(ane, &p->hwx);
	kfree(p);
}

/*
 * Under ane->lock, the firmware running: LOAD_PROGRAM and CREATE_PROCESS for a program whose .hwx and
 * sections are in place, in this boot of the firmware.
 */
static int ane_prog_load(struct apple_ane *ane, struct ane_prog *p)
{
	u64 dva[HWX_NSECT];
	u8 *msg;
	int i, ret;

	p->loaded = false;
	p->created = false;
	p->gen = ane->fw_gen;
	msg = kzalloc(ANE_CREATE_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	for (i = 0; i < HWX_NSECT; i++)
		dva[i] = p->sect[i].iova;

	hwx_message(&p->h, msg, p->hwx.iova, dva);
	ret = ane_command(ane, ANE_CMD_LOAD_PROGRAM, msg, HWX_MSG_SIZE, HWX_MSG_SIZE);
	if (ret || ane_ack(msg)) {
		dev_err(ane->dev, "LOAD_PROGRAM: %d, ack %#x\n", ret, ane_ack(msg));
		ret = ret ?: -EIO;
		goto out;
	}
	p->program = get_unaligned_le32(msg + HWX_MSG_PROGRAM);
	p->loaded = true;

	memset(msg, 0, ANE_CREATE_SIZE);
	put_unaligned_le32(p->program, msg + 8);
	ret = ane_command(ane, ANE_CMD_CREATE_PROCESS, msg, ANE_CREATE_SIZE, ANE_CREATE_SIZE);
	if (ret || ane_ack(msg)) {
		dev_err(ane->dev, "CREATE_PROCESS for program %u: %d, ack %#x\n", p->program, ret, ane_ack(msg));
		ret = ret ?: -EIO;
		goto out;
	}
	p->process = get_unaligned_le32(msg + 0xc);
	p->created = true;
	dev_dbg(ane->dev, "program %u, process %u\n", p->program, p->process);
out:
	kfree(msg);
	return ret;
}

/*
 * Under ane->lock, the firmware booted again (a system sleep stopped it): every program loaded in this boot.
 * One that fails keeps the earlier boot or its program without a process, and its calls fail with -ENODEV.
 */
void ane_progs_reload(struct apple_ane *ane)
{
	struct ane_prog *p;
	u32 gen;
	int ret;

	list_for_each_entry(p, &ane->progs, node) {
		gen = p->gen;
		ret = ane_prog_load(ane, p);
		if (ret && !p->loaded)
			p->gen = gen;
		if (ret)
			dev_err(ane->dev, "a program after the sleep: %d\n", ret);
	}
}

/*
 * Under ane->lock, the firmware running: the .hwx copied (the firmware reads its text there for the
 * program's life), parsed, its sections built, then LOAD_PROGRAM and CREATE_PROCESS.
 */
struct ane_prog *ane_prog_create(struct apple_ane *ane, const void *hwx, size_t len)
{
	struct ane_prog *p;
	void *out[HWX_NSECT];
	int i, ret;

	if (!ane->running)
		return ERR_PTR(-ENODEV);
	if (len > ANE_HWX_MAX)
		return ERR_PTR(-E2BIG);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&p->node);
	p->gen = ane->fw_gen;
	ret = ane_alloc(ane, &p->hwx, len);
	if (ret)
		goto fail;
	memcpy(p->hwx.cpu, hwx, len);
	ret = hwx_parse(&p->h, p->hwx.cpu, len);
	if (ret) {
		dev_dbg(ane->dev, "the .hwx does not parse: %d\n", ret);
		goto fail;
	}
	for (i = 0; i < HWX_NSECT; i++) {
		ret = ane_alloc(ane, &p->sect[i], p->h.size[i]);
		if (ret)
			goto fail;
		memset(p->sect[i].cpu, 0, p->sect[i].size);
		out[i] = p->sect[i].cpu;
	}
	ret = hwx_build(&p->h, out);
	if (ret) {
		dev_dbg(ane->dev, "the sections do not build: %d\n", ret);
		goto fail;
	}
	dev_dbg(ane->dev, ".hwx %zu bytes, cpusubtype %u, %u operations in %u procedures, %u buffers; sections %#zx %#zx %#zx %#zx\n",
		len, p->h.cpusubtype, p->h.nops, p->h.nprocs, p->h.ngeneric, p->h.size[0], p->h.size[1],
		p->h.size[2], p->h.size[3]);

	ret = ane_prog_load(ane, p);
	if (ret)
		goto fail;
	list_add_tail(&p->node, &ane->progs);
	return p;

fail:
	ane_prog_destroy(ane, p);
	return ERR_PTR(ret);
}

/*
 * Under ane->lock: PROCEDURE_CALL for procedure proc with bufs[i] at dva[i], then the program's split kernel
 * sections the procedure binds, its completion the 0x300 that carries the cookie.
 */
int ane_prog_call(struct apple_ane *ane, struct ane_prog *p, u32 proc, u64 cookie, const struct hwx_buf *bufs,
		  const dma_addr_t *dva, int n)
{
	u8 *msg;
	int i, k, ret;

	if (!ane_prog_live(ane, p) || !p->created)
		return -ENODEV;
	if (n < 0 || n > HWX_MAX_BUFS)
		return -EINVAL;
	msg = kzalloc(ANE_CALL_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	put_unaligned_le32(p->program, msg + 8);
	put_unaligned_le32(p->process, msg + 0xc);
	put_unaligned_le32(proc, msg + 0x10);
	put_unaligned_le32(ANE_CALL_PRIORITY, msg + 0x18);
	put_unaligned_le64(cookie, msg + 0x20);
	for (i = 0; i < n; i++) {
		u8 *d = msg + ANE_CALL_BUFS + 0x30 * i;

		put_unaligned_le32(1, d);
		put_unaligned_le32(bufs[i].index, d + 4);
		put_unaligned_le32(bufs[i].kind, d + 8);
		put_unaligned_le32(3, d + 0x10);
		put_unaligned_le64(dva[i], d + 0x18);
		put_unaligned_le64(bufs[i].size, d + 0x20);
	}
	k = hwx_call_kernels(&p->h, proc, msg + ANE_CALL_BUFS + 0x30 * n, HWX_MAX_BUFS - n, p->hwx.iova);
	if (k < 0) {
		ret = k;
		goto out;
	}
	put_unaligned_le32(n + k, msg + 0x28);
	ret = ane_command(ane, ANE_CMD_PROCEDURE_CALL, msg, ANE_CALL_SIZE, ANE_CALL_SIZE);
	if (!ret && ane_ack(msg)) {
		dev_err(ane->dev, "PROCEDURE_CALL %u of program %u: ack %#x\n", proc, p->program, ane_ack(msg));
		ret = -EIO;
	}
out:
	kfree(msg);
	return ret;
}

/*
 * IO_T2H's 0x300: the procedure call's cookie at +8, the event at +0x1c. A call has several: 0 when it
 * starts, 1 when it is done, 2 when it failed, and others the kext only hands to its performance
 * controller (3 here, between 0 and 1); only 1 and 2 end it (`processTargetToHostIOCommand`).
 */
void ane_job_event(struct apple_ane *ane, const u8 *m)
{
	u64 cookie = get_unaligned_le64(m + 8);
	u32 event = get_unaligned_le32(m + 0x1c);

	if (event != ANE_EVENT_DONE && event != ANE_EVENT_FAILED)
		return;
	if ((cookie & ANE_COOKIE_MASK) == ANE_LAB_COOKIE) {
		memcpy(ane->job_event, m, sizeof(ane->job_event));
		if (cookie == ane->job_cookie)
			complete(&ane->job_done);
		return;
	}
	ane_accel_event(ane, cookie, event);
}

/* The lab's one program */

static int ane_lab_unload(struct apple_ane *ane)
{
	ane_prog_destroy(ane, ane->prog);
	ane->prog = NULL;
	return 0;
}

static int ane_lab_load(struct apple_ane *ane)
{
	struct ane_prog *p;

	if (!ane->running || !ane->hwx_len)
		return -EINVAL;
	ane_lab_unload(ane);
	p = ane_prog_create(ane, ane->hwx_stage, ane->hwx_len);
	if (IS_ERR(p))
		return PTR_ERR(p);
	dev_info(ane->dev, "job: .hwx %zu bytes, %u operations in %u procedures, %u buffers: program %u, process %u\n",
		 ane->hwx_len, p->h.nops, p->h.nprocs, p->h.ngeneric, p->program, p->process);
	ane->prog = p;
	return 0;
}

static void ane_out_summary(struct apple_ane *ane, const struct hwx_buf *b, const struct ane_buf *buf)
{
	const u16 *v = buf->cpu;
	size_t n = b->size / 2, i, nz = 0;

	for (i = 0; i < n; i++)
		nz += v[i] != 0;
	dev_info(ane->dev, "job: output %u: %zu of %zu halves nonzero; %04x %04x %04x %04x %04x %04x %04x %04x\n",
		 b->index, nz, n, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
}

static int ane_lab_run(struct apple_ane *ane, u32 proc)
{
	struct ane_prog *p = ane->prog;
	struct hwx_buf *bufs;
	dma_addr_t *dva;
	struct ane_buf *mem;
	int n = 0, i, ret;
	size_t k;

	if (!p || !ane->running)
		return -EINVAL;
	bufs = kcalloc(HWX_MAX_BUFS, sizeof(*bufs), GFP_KERNEL);
	dva = kcalloc(HWX_MAX_BUFS, sizeof(*dva), GFP_KERNEL);
	mem = kcalloc(HWX_MAX_BUFS, sizeof(*mem), GFP_KERNEL);
	if (!bufs || !dva || !mem) {
		ret = -ENOMEM;
		goto out;
	}
	n = ane_prog_bufs(p, proc, bufs, HWX_MAX_BUFS);
	if (n < 0) {
		ret = n;
		n = 0;
		goto out;
	}
	for (i = 0; i < n; i++) {
		ret = ane_alloc(ane, &mem[i], bufs[i].size);
		if (ret)
			goto out;
		dva[i] = mem[i].iova;
		if (bufs[i].kind == HWX_KIND_INPUT) {
			u16 *v = mem[i].cpu;

			for (k = 0; k < bufs[i].size / 2; k++)
				v[k] = 0x3800;	/* fp16 0.5 */
		} else {
			memset(mem[i].cpu, 0, mem[i].size);
		}
	}

	reinit_completion(&ane->job_done);
	ane->job_cookie = ANE_LAB_COOKIE | (++ane->job_seq & 0xffffffff);
	memset(ane->job_event, 0, sizeof(ane->job_event));
	ret = ane_prog_call(ane, p, proc, ane->job_cookie, bufs, dva, n);
	if (ret) {
		dev_err(ane->dev, "job: PROCEDURE_CALL %u: %d\n", proc, ret);
		goto out;
	}
	if (!wait_for_completion_timeout(&ane->job_done, ANE_CALL_TIMEOUT)) {
		dev_err(ane->dev, "job: procedure %u: no completion in 2 s\n", proc);
		ret = -ETIMEDOUT;
		goto out;
	}
	ane->job_status = get_unaligned_le32(ane->job_event + 0x1c);
	dev_info(ane->dev, "job: procedure %u: event %u (program %u, process %u, procedure %u)\n", proc,
		 ane->job_status, get_unaligned_le32(ane->job_event + 0x10),
		 get_unaligned_le32(ane->job_event + 0x14), get_unaligned_le32(ane->job_event + 0x18));
	for (i = 0; i < n; i++)
		if (bufs[i].kind == HWX_KIND_OUTPUT)
			ane_out_summary(ane, &bufs[i], &mem[i]);
	ret = ane->job_status == ANE_EVENT_DONE ? 0 : -EIO;
out:
	for (i = 0; mem && i < n; i++)
		ane_free(ane, &mem[i]);
	kfree(mem);
	kfree(dva);
	kfree(bufs);
	return ret;
}

static ssize_t ane_hwx_write(struct file *f, const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct apple_ane *ane = f->private_data;
	ssize_t ret;

	mutex_lock(&ane->lock);
	if (!ane->hwx_stage) {
		ane->hwx_stage = vzalloc(ANE_HWX_MAX);
		if (!ane->hwx_stage) {
			mutex_unlock(&ane->lock);
			return -ENOMEM;
		}
	}
	if (*ppos == 0)
		ane->hwx_len = 0;
	ret = simple_write_to_buffer(ane->hwx_stage, ANE_HWX_MAX, ppos, ubuf, count);
	if (ret > 0)
		ane->hwx_len = max_t(size_t, ane->hwx_len, *ppos);
	mutex_unlock(&ane->lock);
	return ret;
}

static const struct file_operations ane_hwx_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = ane_hwx_write,
	.llseek = default_llseek,
};

static int ane_load_set(void *data, u64 val)
{
	struct apple_ane *ane = data;
	int ret;

	mutex_lock(&ane->lock);
	ret = val ? ane_lab_load(ane) : ane_lab_unload(ane);
	mutex_unlock(&ane->lock);
	return ret;
}

static int ane_load_get(void *data, u64 *val)
{
	struct apple_ane *ane = data;

	*val = ane->prog ? ane->prog->program : 0;
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(ane_load_fops, ane_load_get, ane_load_set, "%llu\n");

static int ane_run_set(void *data, u64 val)
{
	struct apple_ane *ane = data;
	bool busy;
	int ret;

	/* the lab's call goes past the scheduler: with the accel device's calls it could take a 33rd slot */
	spin_lock(&ane->job_lock);
	busy = !list_empty(&ane->inflight);
	spin_unlock(&ane->job_lock);
	if (busy)
		return -EBUSY;
	mutex_lock(&ane->lock);
	ret = ane_lab_run(ane, val);
	mutex_unlock(&ane->lock);
	return ret;
}

static int ane_run_get(void *data, u64 *val)
{
	struct apple_ane *ane = data;

	*val = ane->job_status;
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(ane_run_fops, ane_run_get, ane_run_set, "%llu\n");

void ane_job_init(struct apple_ane *ane)
{
	init_completion(&ane->job_done);
	debugfs_create_file("hwx", 0200, ane->debugfs, ane, &ane_hwx_fops);
	debugfs_create_file_unsafe("load", 0600, ane->debugfs, ane, &ane_load_fops);
	debugfs_create_file_unsafe("run", 0600, ane->debugfs, ane, &ane_run_fops);
}

/* Under ane->lock, before the firmware stops: the lab's program goes with it */
void ane_job_stop(struct apple_ane *ane)
{
	ane_lab_unload(ane);
}

void ane_job_fini(struct apple_ane *ane)
{
	ane_lab_unload(ane);
	vfree(ane->hwx_stage);
	ane->hwx_stage = NULL;
	ane->hwx_len = 0;
}
