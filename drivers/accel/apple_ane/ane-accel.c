// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple Neural Engine: the DRM accel device (include/uapi/drm/apple_ane_accel.h).
 *
 * Buffer objects are DMA-API allocations in the engine's one DART domain. A program is a .hwx
 * copied out of a buffer object, loaded with LOAD_PROGRAM and CREATE_PROCESS (ane-job.c); it
 * keeps the firmware running, which stops a second after the last program goes. A submission
 * is one PROCEDURE_CALL through a DRM scheduler, its fence signalled by the IO_T2H 0x300 that
 * carries its cookie. Up to ANE_CALLS_IN_FLIGHT calls sit with the firmware at once (ane.h), so
 * the next is built while the engine runs.
 *
 * The engine reaches the whole domain and the firmware's confinement of a program to the
 * buffers it is given is not known, so loading a program takes CAP_SYS_ADMIN.
 */

#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_dma_helper.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_syncobj.h>
#include <drm/drm_utils.h>
#include <drm/gpu_scheduler.h>
#include <drm/apple_ane_accel.h>
#include <linux/capability.h>
#include <linux/delay.h>
#include <linux/dma-fence.h>
#include <linux/dma-resv.h>
#include <linux/slab.h>
#include <linux/xarray.h>

#include "ane.h"
#include "ane-hwx.h"

#define ANE_JOB_TIMEOUT_MS	2000
#define ANE_IDLE_DELAY		HZ
#define ANE_ACCEL_COOKIE	0xa4e1000000000000ull
#define ANE_BO_MAX		(1ull << 32)
#define ANE_IN_SYNCS_MAX	64

struct ane_file {
	struct apple_ane *ane;
	struct xarray progs;
	struct drm_sched_entity entity;
};

struct ane_uprog {
	struct kref ref;
	struct apple_ane *ane;
	struct ane_prog *p;
};

struct ane_job {
	struct drm_sched_job base;
	struct apple_ane *ane;
	struct ane_uprog *prog;
	u32 proc;
	u64 cookie;
	int n;
	struct hwx_buf *info;
	struct drm_gem_object **bo;
	dma_addr_t *dva;
	int nobj;			/* the distinct objects among bo[], first in objs[] */
	struct drm_gem_object **objs;
	bool *obj_write;
	struct dma_fence *done;		/* the 0x300 */
	struct list_head node;		/* in ane->inflight while the firmware has it */
};

static struct apple_ane *to_ane(struct drm_device *drm)
{
	return container_of(drm, struct apple_ane, drm);
}

static struct ane_job *to_ane_job(struct drm_sched_job *j)
{
	return container_of(j, struct ane_job, base);
}

static const char *ane_fence_driver(struct dma_fence *f)
{
	return APPLE_ANE_NAME;
}

static const char *ane_fence_timeline(struct dma_fence *f)
{
	return "ane";
}

static const struct dma_fence_ops ane_fence_ops = {
	.get_driver_name = ane_fence_driver,
	.get_timeline_name = ane_fence_timeline,
};

/* Programs */

static void ane_uprog_release(struct kref *ref)
{
	struct ane_uprog *up = container_of(ref, struct ane_uprog, ref);
	struct apple_ane *ane = up->ane;

	mutex_lock(&ane->lock);
	ane_prog_destroy(ane, up->p);
	if (!--ane->fw_users)
		schedule_delayed_work(&ane->idle_work, ANE_IDLE_DELAY);
	mutex_unlock(&ane->lock);
	kfree(up);
}

static void ane_uprog_put(struct ane_uprog *up)
{
	kref_put(&up->ref, ane_uprog_release);
}

static struct ane_uprog *ane_uprog_get(struct ane_file *af, u32 id)
{
	struct ane_uprog *up;

	xa_lock(&af->progs);
	up = xa_load(&af->progs, id);
	if (up && !kref_get_unless_zero(&up->ref))
		up = NULL;
	xa_unlock(&af->progs);
	return up;
}

/* The firmware with no program for ANE_IDLE_DELAY: stopped, unless the lab's debugfs started it */
static void ane_idle(struct work_struct *w)
{
	struct apple_ane *ane = container_of(to_delayed_work(w), struct apple_ane, idle_work);

	mutex_lock(&ane->lock);
	if (ane->running && ane->accel_booted && !ane->fw_users && !ane->prog) {
		ane_fw_shutdown(ane);
		ane->accel_booted = false;
	}
	mutex_unlock(&ane->lock);
}

static int ane_ioctl_program_create(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct apple_ane *ane = to_ane(drm);
	struct ane_file *af = file->driver_priv;
	struct drm_apple_ane_program_create *a = data;
	struct drm_gem_object *obj;
	struct ane_uprog *up;
	struct ane_prog *p;
	u32 id;
	int ret;

	/*
	 * A program's task descriptors drive the engine's DMA, and the kernel cannot check them: they run in the
	 * one DART space that every client's buffers and the firmware itself share. So programs are root's;
	 * macOS's kext, likewise, wants an entitlement of its clients (com.apple.ane.iokit-user-access).
	 */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (a->size < 32 || a->size > ANE_HWX_MAX)
		return -EINVAL;
	obj = drm_gem_object_lookup(file, a->handle);
	if (!obj)
		return -ENOENT;
	if (a->size > obj->size) {
		ret = -EINVAL;
		goto out;
	}
	up = kzalloc(sizeof(*up), GFP_KERNEL);
	if (!up) {
		ret = -ENOMEM;
		goto out;
	}
	kref_init(&up->ref);
	up->ane = ane;

	cancel_delayed_work_sync(&ane->idle_work);
	mutex_lock(&ane->lock);
	ane->fw_users++;
	ret = 0;
	if (!ane->running) {
		ret = ane_fw_boot(ane);
		if (!ret)
			ane->accel_booted = true;
	}
	p = ret ? ERR_PTR(ret) : ane_prog_create(ane, to_drm_gem_dma_obj(obj)->vaddr, a->size);
	if (IS_ERR(p)) {
		if (!--ane->fw_users)
			schedule_delayed_work(&ane->idle_work, ANE_IDLE_DELAY);
		mutex_unlock(&ane->lock);
		kfree(up);
		ret = PTR_ERR(p);
		goto out;
	}
	up->p = p;
	mutex_unlock(&ane->lock);

	ret = xa_alloc(&af->progs, &id, up, xa_limit_32b, GFP_KERNEL);
	if (ret) {
		ane_uprog_put(up);
		goto out;
	}
	a->program = id;
	a->procedures = ane_prog_procs(p);
out:
	drm_gem_object_put(obj);
	return ret;
}

static int ane_ioctl_program_destroy(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct ane_file *af = file->driver_priv;
	struct drm_apple_ane_program_destroy *a = data;
	struct ane_uprog *up;

	if (a->pad)
		return -EINVAL;
	up = xa_erase(&af->progs, a->program);
	if (!up)
		return -ENOENT;
	/* its submissions hold their own references */
	ane_uprog_put(up);
	return 0;
}

static int ane_ioctl_program_info(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct ane_file *af = file->driver_priv;
	struct drm_apple_ane_program_info *a = data;
	struct drm_apple_ane_buf_info __user *ubufs = u64_to_user_ptr(a->bufs);
	struct hwx_buf *bufs;
	struct ane_uprog *up;
	int n, i, ret = 0;

	if (a->pad)
		return -EINVAL;
	up = ane_uprog_get(af, a->program);
	if (!up)
		return -ENOENT;
	bufs = kcalloc(HWX_MAX_BUFS, sizeof(*bufs), GFP_KERNEL);
	if (!bufs) {
		ret = -ENOMEM;
		goto out;
	}
	n = a->procedure < ane_prog_procs(up->p) ? ane_prog_bufs(up->p, a->procedure, bufs, HWX_MAX_BUFS) : -EINVAL;
	if (n < 0) {
		ret = n;
		goto out;
	}
	for (i = 0; ubufs && i < n && i < a->count; i++) {
		struct drm_apple_ane_buf_info b = {
			.index = bufs[i].index,
			.kind = bufs[i].kind,
			.size = bufs[i].size,
		};

		if (copy_to_user(&ubufs[i], &b, sizeof(b))) {
			ret = -EFAULT;
			goto out;
		}
	}
	a->count = n;
out:
	kfree(bufs);
	ane_uprog_put(up);
	return ret;
}

/* Buffer objects */

static int ane_ioctl_bo_create(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct drm_apple_ane_bo_create *a = data;
	struct drm_gem_dma_object *dma;
	int ret;

	if (a->flags || !a->size || a->size > ANE_BO_MAX)
		return -EINVAL;
	dma = drm_gem_dma_create(drm, PAGE_ALIGN(a->size));
	if (IS_ERR(dma))
		return PTR_ERR(dma);
	ret = drm_gem_handle_create(file, &dma->base, &a->handle);
	if (!ret)
		a->offset = drm_vma_node_offset_addr(&dma->base.vma_node);
	drm_gem_object_put(&dma->base);
	return ret;
}

static int ane_ioctl_bo_wait(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct drm_apple_ane_bo_wait *a = data;
	struct drm_gem_object *obj;
	long ret;

	if (a->pad)
		return -EINVAL;
	obj = drm_gem_object_lookup(file, a->handle);
	if (!obj)
		return -ENOENT;
	ret = dma_resv_wait_timeout(obj->resv, DMA_RESV_USAGE_WRITE, true,
				    drm_timeout_abs_to_jiffies(a->timeout_ns));
	drm_gem_object_put(obj);
	if (!ret)
		return a->timeout_ns ? -ETIMEDOUT : -EBUSY;
	return ret < 0 ? ret : 0;
}

/* Submissions */

static void ane_job_release(struct ane_job *job)
{
	int i;

	for (i = 0; job->bo && i < job->n; i++)
		if (job->bo[i])
			drm_gem_object_put(job->bo[i]);
	dma_fence_put(job->done);
	if (job->prog)
		ane_uprog_put(job->prog);
	kfree(job->obj_write);
	kfree(job->objs);
	kfree(job->dva);
	kfree(job->bo);
	kfree(job->info);
	kfree(job);
}

static struct dma_fence *ane_run_job(struct drm_sched_job *sj)
{
	struct ane_job *job = to_ane_job(sj);
	struct apple_ane *ane = job->ane;
	struct dma_fence *f;
	int ret;

	if (unlikely(sj->s_fence->finished.error))
		return NULL;
	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return ERR_PTR(-ENOMEM);
	dma_fence_init(f, &ane_fence_ops, &ane->fence_lock, ane->fence_ctx, ++ane->fence_seq);
	job->done = dma_fence_get(f);
	job->cookie = ANE_ACCEL_COOKIE | (++ane->call_seq & 0xffffffff);

	/* on the list before the firmware can answer */
	spin_lock(&ane->job_lock);
	list_add_tail(&job->node, &ane->inflight);
	spin_unlock(&ane->job_lock);

	mutex_lock(&ane->lock);
	ret = ane_prog_call(ane, job->prog->p, job->proc, job->cookie, job->info, job->dva, job->n);
	mutex_unlock(&ane->lock);
	if (ret) {
		spin_lock(&ane->job_lock);
		list_del_init(&job->node);
		spin_unlock(&ane->job_lock);
		dma_fence_set_error(f, ret);
		dma_fence_signal(f);
	}
	return f;
}

/* IO_T2H's 0x300 that ends a submission (1 done, 2 failed: ane_job_event), from the IRQ thread */
void ane_accel_event(struct apple_ane *ane, u64 cookie, u32 event)
{
	struct ane_job *job, *found = NULL;

	spin_lock(&ane->job_lock);
	list_for_each_entry(job, &ane->inflight, node) {
		if (job->cookie == cookie) {
			list_del_init(&job->node);
			found = job;
			break;
		}
	}
	spin_unlock(&ane->job_lock);
	if (!found) {
		dev_warn(ane->dev, "a completion for no submission: cookie %#llx, event %u\n", cookie, event);
		return;
	}
	if (event != ANE_EVENT_DONE) {
		dev_err(ane->dev, "procedure %u: failed (event %u)\n", found->proc, event);
		dma_fence_set_error(found->done, -EIO);
	}
	dma_fence_signal(found->done);
}

/*
 * A call the firmware did not answer: every call it holds fails and the firmware restarts, which
 * loses its programs (a submission on one then fails with -ENODEV). In the kext's order: the
 * engine powered off before the calls' fences signal (their buffers may then go), then a boot,
 * and after a boot with no handshake one more power cycle and boot.
 */
static enum drm_gpu_sched_stat ane_timedout_job(struct drm_sched_job *sj)
{
	struct ane_job *job = to_ane_job(sj), *j, *t;
	struct apple_ane *ane = job->ane;
	LIST_HEAD(lost);
	int ret = 0, i;

	drm_sched_stop(&ane->sched, sj);
	dev_err(ane->dev, "procedure %u: no completion in %u ms, the firmware restarts\n", job->proc,
		ANE_JOB_TIMEOUT_MS);
	spin_lock(&ane->job_lock);
	list_splice_init(&ane->inflight, &lost);
	spin_unlock(&ane->job_lock);
	mutex_lock(&ane->lock);
	if (ane->running) {
		ane_job_stop(ane);
		ane_fw_kill(ane);
	}
	list_for_each_entry_safe(j, t, &lost, node) {
		list_del_init(&j->node);
		dma_fence_set_error(j->done, -ETIMEDOUT);
		dma_fence_signal(j->done);
	}
	for (i = 0; ane->fw_users && i < 2; i++) {
		ret = ane_fw_boot(ane);
		if (!ret)
			break;
		dev_err(ane->dev, "the firmware's restart %d: %d\n", i + 1, ret);
	}
	mutex_unlock(&ane->lock);
	drm_sched_start(&ane->sched, 0);
	return DRM_GPU_SCHED_STAT_RESET;
}

static void ane_free_job(struct drm_sched_job *sj)
{
	struct ane_job *job = to_ane_job(sj);

	drm_sched_job_cleanup(sj);
	ane_job_release(job);
}

static const struct drm_sched_backend_ops ane_sched_ops = {
	.run_job = ane_run_job,
	.timedout_job = ane_timedout_job,
	.free_job = ane_free_job,
};

/* Each of the procedure's buffers named once, inside its object, page-aligned */
static int ane_job_bufs(struct drm_file *file, struct ane_job *job, const struct drm_apple_ane_submit_buf *ub)
{
	DECLARE_BITMAP(used, HWX_MAX_BUFS) = {};
	int i, k, o;

	for (i = 0; i < job->n; i++) {
		struct drm_gem_object *obj;

		for (k = 0; k < job->n && ub[k].index != job->info[i].index; k++)
			;
		if (k == job->n || test_and_set_bit(k, used))
			return -EINVAL;
		if (!PAGE_ALIGNED(ub[k].offset))
			return -EINVAL;
		obj = drm_gem_object_lookup(file, ub[k].handle);
		if (!obj)
			return -ENOENT;
		job->bo[i] = obj;
		if (ub[k].offset > obj->size || job->info[i].size > obj->size - ub[k].offset)
			return -EINVAL;
		job->dva[i] = to_drm_gem_dma_obj(obj)->dma_addr + ub[k].offset;

		for (o = 0; o < job->nobj && job->objs[o] != obj; o++)
			;
		if (o == job->nobj)
			job->objs[job->nobj++] = obj;
		job->obj_write[o] |= job->info[i].kind != HWX_KIND_INPUT;
	}
	return 0;
}

static int ane_ioctl_submit(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct apple_ane *ane = to_ane(drm);
	struct ane_file *af = file->driver_priv;
	struct drm_apple_ane_submit *a = data;
	u32 __user *in_syncs = u64_to_user_ptr(a->in_syncs);
	struct drm_apple_ane_submit_buf *ub = NULL;
	struct drm_syncobj *out_sync = NULL;
	struct ww_acquire_ctx ctx;
	struct dma_fence *fence;
	struct ane_job *job;
	int i, ret;

	if (a->priority || a->buf_count > HWX_MAX_BUFS || a->in_sync_count > ANE_IN_SYNCS_MAX)
		return -EINVAL;
	job = kzalloc(sizeof(*job), GFP_KERNEL);
	if (!job)
		return -ENOMEM;
	INIT_LIST_HEAD(&job->node);
	job->ane = ane;
	job->proc = a->procedure;
	job->prog = ane_uprog_get(af, a->program);
	if (!job->prog) {
		ret = -ENOENT;
		goto fail;
	}
	if (a->procedure >= ane_prog_procs(job->prog->p)) {
		ret = -EINVAL;
		goto fail;
	}
	job->info = kcalloc(HWX_MAX_BUFS, sizeof(*job->info), GFP_KERNEL);
	if (!job->info) {
		ret = -ENOMEM;
		goto fail;
	}
	job->n = ane_prog_bufs(job->prog->p, a->procedure, job->info, HWX_MAX_BUFS);
	if (job->n < 0 || job->n != a->buf_count) {
		ret = job->n < 0 ? job->n : -EINVAL;
		job->n = 0;
		goto fail;
	}
	job->bo = kcalloc(job->n, sizeof(*job->bo), GFP_KERNEL);
	job->dva = kcalloc(job->n, sizeof(*job->dva), GFP_KERNEL);
	job->objs = kcalloc(job->n, sizeof(*job->objs), GFP_KERNEL);
	job->obj_write = kcalloc(job->n, sizeof(*job->obj_write), GFP_KERNEL);
	ub = kvmalloc_array(job->n, sizeof(*ub), GFP_KERNEL);
	if ((job->n && (!job->bo || !job->dva || !job->objs || !job->obj_write || !ub))) {
		ret = -ENOMEM;
		goto fail;
	}
	if (copy_from_user(ub, u64_to_user_ptr(a->bufs), job->n * sizeof(*ub))) {
		ret = -EFAULT;
		goto fail;
	}
	ret = ane_job_bufs(file, job, ub);
	if (ret)
		goto fail;
	if (a->out_sync) {
		out_sync = drm_syncobj_find(file, a->out_sync);
		if (!out_sync) {
			ret = -ENOENT;
			goto fail;
		}
	}

	ret = drm_sched_job_init(&job->base, &af->entity, 1, af, file->client_id);
	if (ret)
		goto fail;
	for (i = 0; i < a->in_sync_count; i++) {
		u32 h;

		if (get_user(h, &in_syncs[i])) {
			ret = -EFAULT;
			goto fail_job;
		}
		ret = drm_sched_job_add_syncobj_dependency(&job->base, file, h, 0);
		if (ret)
			goto fail_job;
	}

	ret = drm_gem_lock_reservations(job->objs, job->nobj, &ctx);
	if (ret)
		goto fail_job;
	for (i = 0; i < job->nobj; i++) {
		ret = dma_resv_reserve_fences(job->objs[i]->resv, 1);
		if (!ret)
			ret = drm_sched_job_add_implicit_dependencies(&job->base, job->objs[i], job->obj_write[i]);
		if (ret) {
			drm_gem_unlock_reservations(job->objs, job->nobj, &ctx);
			goto fail_job;
		}
	}
	mutex_lock(&ane->sched_lock);
	drm_sched_job_arm(&job->base);
	fence = dma_fence_get(&job->base.s_fence->finished);
	drm_sched_entity_push_job(&job->base);
	mutex_unlock(&ane->sched_lock);
	for (i = 0; i < job->nobj; i++)
		dma_resv_add_fence(job->objs[i]->resv, fence,
				   job->obj_write[i] ? DMA_RESV_USAGE_WRITE : DMA_RESV_USAGE_READ);
	drm_gem_unlock_reservations(job->objs, job->nobj, &ctx);
	if (out_sync) {
		drm_syncobj_replace_fence(out_sync, fence);
		drm_syncobj_put(out_sync);
	}
	dma_fence_put(fence);
	kvfree(ub);
	return 0;

fail_job:
	drm_sched_job_cleanup(&job->base);
fail:
	if (out_sync)
		drm_syncobj_put(out_sync);
	kvfree(ub);
	ane_job_release(job);
	return ret;
}

/* The device */

static int ane_open(struct drm_device *drm, struct drm_file *file)
{
	struct apple_ane *ane = to_ane(drm);
	struct drm_gpu_scheduler *sched = &ane->sched;
	struct ane_file *af;
	int ret;

	af = kzalloc(sizeof(*af), GFP_KERNEL);
	if (!af)
		return -ENOMEM;
	af->ane = ane;
	xa_init_flags(&af->progs, XA_FLAGS_ALLOC1);
	ret = drm_sched_entity_init(&af->entity, DRM_SCHED_PRIORITY_NORMAL, &sched, 1, NULL);
	if (ret) {
		kfree(af);
		return ret;
	}
	file->driver_priv = af;
	return 0;
}

static void ane_postclose(struct drm_device *drm, struct drm_file *file)
{
	struct ane_file *af = file->driver_priv;
	struct ane_uprog *up;
	unsigned long id;

	drm_sched_entity_destroy(&af->entity);
	xa_for_each(&af->progs, id, up)
		ane_uprog_put(up);
	xa_destroy(&af->progs);
	kfree(af);
}

static const struct drm_ioctl_desc ane_ioctls[] = {
	DRM_IOCTL_DEF_DRV(APPLE_ANE_BO_CREATE, ane_ioctl_bo_create, 0),
	DRM_IOCTL_DEF_DRV(APPLE_ANE_BO_WAIT, ane_ioctl_bo_wait, 0),
	DRM_IOCTL_DEF_DRV(APPLE_ANE_PROGRAM_CREATE, ane_ioctl_program_create, 0),
	DRM_IOCTL_DEF_DRV(APPLE_ANE_PROGRAM_DESTROY, ane_ioctl_program_destroy, 0),
	DRM_IOCTL_DEF_DRV(APPLE_ANE_PROGRAM_INFO, ane_ioctl_program_info, 0),
	DRM_IOCTL_DEF_DRV(APPLE_ANE_SUBMIT, ane_ioctl_submit, 0),
};

DEFINE_DRM_ACCEL_FOPS(ane_fops);

const struct drm_driver ane_drm_driver = {
	.driver_features = DRIVER_COMPUTE_ACCEL | DRIVER_GEM | DRIVER_SYNCOBJ,
	.open = ane_open,
	.postclose = ane_postclose,
	.ioctls = ane_ioctls,
	.num_ioctls = ARRAY_SIZE(ane_ioctls),
	.fops = &ane_fops,
	.name = APPLE_ANE_NAME,
	.desc = "Apple Neural Engine",
	.major = 0,
	.minor = 1,
	DRM_GEM_DMA_DRIVER_OPS,
};

int ane_accel_init(struct apple_ane *ane)
{
	const struct drm_sched_init_args args = {
		.ops = &ane_sched_ops,
		.num_rqs = DRM_SCHED_PRIORITY_COUNT,
		.credit_limit = ANE_CALLS_IN_FLIGHT,
		.timeout = msecs_to_jiffies(ANE_JOB_TIMEOUT_MS),
		.name = dev_name(ane->dev),
		.dev = ane->dev,
	};
	int ret;

	spin_lock_init(&ane->fence_lock);
	spin_lock_init(&ane->job_lock);
	INIT_LIST_HEAD(&ane->inflight);
	INIT_DELAYED_WORK(&ane->idle_work, ane_idle);
	ret = devm_mutex_init(ane->dev, &ane->sched_lock);
	if (ret)
		return ret;
	ane->fence_ctx = dma_fence_context_alloc(1);
	ret = drm_sched_init(&ane->sched, &args);
	if (ret)
		return ret;
	ret = drm_dev_register(&ane->drm, 0);
	if (ret)
		drm_sched_fini(&ane->sched);
	return ret;
}

/* Before the firmware's last stop: no file can reach the device, its jobs are done */
void ane_accel_fini(struct apple_ane *ane)
{
	drm_dev_unregister(&ane->drm);
	drm_sched_fini(&ane->sched);
	cancel_delayed_work_sync(&ane->idle_work);
}

/*
 * A system sleep powers the engine's domains off under its firmware. So the calls drain (the one the
 * firmware holds ends within its timeout; a call it never answers fails), the firmware stops, and at the
 * resume it boots again with every program loaded again: a client sees a pause. The lab's debugfs boot,
 * with no program of a client, is not booted again.
 */
void ane_accel_suspend(struct apple_ane *ane)
{
	struct ane_job *j, *t;
	LIST_HEAD(lost);
	int i;

	cancel_delayed_work_sync(&ane->idle_work);
	drm_sched_wqueue_stop(&ane->sched);
	for (i = 0; i < ANE_JOB_TIMEOUT_MS / 10; i++) {
		bool idle;

		spin_lock(&ane->job_lock);
		idle = list_empty(&ane->inflight);
		spin_unlock(&ane->job_lock);
		if (idle)
			break;
		usleep_range(10000, 11000);
	}

	mutex_lock(&ane->lock);
	ane->sleep_boot = ane->running && ane->fw_users;
	if (ane->running) {
		ane_job_stop(ane);
		ane_fw_shutdown(ane);
	}
	if (!ane->sleep_boot)
		ane->accel_booted = false;
	mutex_unlock(&ane->lock);

	spin_lock(&ane->job_lock);
	list_splice_init(&ane->inflight, &lost);
	spin_unlock(&ane->job_lock);
	list_for_each_entry_safe(j, t, &lost, node) {
		list_del_init(&j->node);
		dma_fence_set_error(j->done, -ETIMEDOUT);
		dma_fence_signal(j->done);
	}
}

void ane_accel_resume(struct apple_ane *ane)
{
	int ret;

	mutex_lock(&ane->lock);
	if (ane->sleep_boot) {
		ane->sleep_boot = false;
		ret = ane_fw_boot(ane);
		if (ret) {
			dev_err(ane->dev, "the firmware's boot after the sleep: %d; its programs are lost\n", ret);
		} else {
			ane->accel_booted = true;
			ane_progs_reload(ane);
		}
	}
	mutex_unlock(&ane->lock);
	drm_sched_wqueue_start(&ane->sched);
}
