// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Submission queue management
//!
//! This module implements the userspace view of submission queues and the logic to map userspace
//! submissions to firmware queues.

use kernel::dma_fence::*;
use kernel::prelude::*;
use kernel::{
    c_str,
    dma_fence,
    drm::sched,
    macros::versions,
    new_mutex,
    sync::{
        Arc,
        LockClassKey,
        Mutex, //
    },
    uapi,
    xarray, //
};

use crate::alloc::Allocator;
use crate::debug::*;
use crate::driver::{AsahiDevRef, AsahiDevice};

/// G15: the device's GPU manager, while the DRM device is registered.
fn reg_gpu(dev: &AsahiDevRef) -> Option<Arc<dyn gpu::GpuManager>> {
    let guard = dev.registration_guard()?;
    Some(guard.registration_data_with(|d| d.gpu.clone()))
}
use crate::file::MAX_COMMANDS_PER_SUBMISSION;
use crate::fw::types::*;
use crate::gpu::GpuManager;
use crate::inner_weak_ptr;
use crate::microseq;
use crate::module_parameters;
use crate::util::{
    AnyBitPattern,
    Reader, //
};
use crate::{
    alloc,
    buffer,
    channel,
    driver::AsahiRegData,
    event,
    file,
    fw,
    gpu,
    mmu,
    workqueue, //
};

use core::sync::atomic::{
    AtomicU64,
    Ordering, //
};

const DEBUG_CLASS: DebugFlags = DebugFlags::Queue;

const WQ_SIZE: u32 = 0x500;

mod common;
mod compute;
mod render;

/// Trait implemented by all versioned queues.
pub(crate) trait Queue: Send + Sync {
    fn submit(
        &mut self,
        reg_data: &AsahiRegData<'_>,
        id: u64,
        syncs: KVec<file::SyncItem>,
        in_sync_count: usize,
        cmdbuf_raw: &[u8],
        objects: Pin<&xarray::XArray<KBox<file::Object>>>,
    ) -> Result;
}

#[versions(AGX)]
struct SubQueue {
    wq: Arc<workqueue::WorkQueue::ver>,
}

#[versions(AGX)]
impl SubQueue::ver {
    fn new_job(&mut self, fence: dma_fence::Fence) -> SubQueueJob::ver {
        SubQueueJob::ver {
            wq: self.wq.clone(),
            fence: Some(fence),
            job: None,
        }
    }
}

#[versions(AGX)]
struct SubQueueJob {
    wq: Arc<workqueue::WorkQueue::ver>,
    job: Option<workqueue::Job::ver>,
    fence: Option<dma_fence::Fence>,
}

#[versions(AGX)]
impl SubQueueJob::ver {
    fn get(&mut self) -> Result<&mut workqueue::Job::ver> {
        if self.job.is_none() {
            mod_pr_debug!("SubQueueJob: Creating {:?} job\n", self.wq.pipe_type());
            self.job
                .replace(self.wq.new_job(self.fence.take().unwrap())?);
        }
        Ok(self.job.as_mut().expect("expected a Job"))
    }

    fn commit(&mut self) -> Result {
        match self.job.as_mut() {
            Some(job) => job.commit(),
            None => Ok(()),
        }
    }

    fn can_submit(&self) -> Option<Fence> {
        self.job.as_ref().and_then(|job| job.can_submit())
    }
}

#[versions(AGX)]
pub(crate) struct Queue {
    dev: AsahiDevRef,
    _sched: sched::Scheduler<QueueJob::ver>,
    entity: sched::Entity<QueueJob::ver>,
    vm: mmu::Vm,
    q_vtx: Option<SubQueue::ver>,
    q_frag: Option<SubQueue::ver>,
    q_comp: Option<SubQueue::ver>,
    fence_ctx: FenceContexts,
    inner: QueueInner::ver,
    /// G15: the queue's CL channel (created at its first compute submit).
    g15_chan: Option<Arc<Mutex<gpu::G15ClChannel>>>,
    /// G15: the queue's render state (created at its first render submit).
    g15_rd: Option<Arc<Mutex<gpu::G15RdQueue>>>,
}

#[versions(AGX)]
pub(crate) struct QueueInner {
    dev: AsahiDevRef,
    ualloc: Arc<Mutex<alloc::DefaultAllocator>>,
    buffer: buffer::Buffer::ver,
    gpu_context: Arc<workqueue::GpuContext>,
    notifier_list: Arc<GpuObject<fw::event::NotifierList>>,
    notifier: Arc<GpuObject<fw::event::Notifier::ver>>,
    usc_exec_base: u64,
    id: u64,
    #[ver(V >= V13_0B4)]
    counter: AtomicU64,
}

#[versions(AGX)]
#[derive(Default)]
pub(crate) struct JobFence {
    id: u64,
    pending: AtomicU64,
}

#[versions(AGX)]
impl JobFence::ver {
    fn add_command(self: &FenceObject<Self>) {
        self.pending.fetch_add(1, Ordering::Relaxed);
    }

    fn command_complete(self: &FenceObject<Self>) {
        let remain = self.pending.fetch_sub(1, Ordering::Relaxed) - 1;
        mod_pr_debug!(
            "JobFence[{}]: Command complete (remain: {})\n",
            self.id,
            remain
        );
        if remain == 0 {
            mod_pr_debug!("JobFence[{}]: Signaling\n", self.id);
            self.signal();
        }
    }
}

#[versions(AGX)]
#[vtable]
impl dma_fence::FenceOps for JobFence::ver {
    fn get_driver_name<'a>(self: &'a FenceObject<Self>) -> &'a CStr {
        c_str!("asahi")
    }
    fn get_timeline_name<'a>(self: &'a FenceObject<Self>) -> &'a CStr {
        c_str!("queue")
    }
}

#[versions(AGX)]
pub(crate) struct QueueJob {
    dev: AsahiDevRef,
    vm_bind: mmu::VmBind,
    op_guard: Option<gpu::OpGuard>,
    sj_vtx: Option<SubQueueJob::ver>,
    sj_frag: Option<SubQueueJob::ver>,
    sj_comp: Option<SubQueueJob::ver>,
    fence: UserFence<JobFence::ver>,
    notifier: Arc<GpuObject<fw::event::Notifier::ver>>,
    notification_count: u32,
    did_run: bool,
    id: u64,
    /// G15: the queue's CL channel and this submission's CL jobs (built at
    /// the ioctl, numbered and rung at run time).
    g15_chan: Option<Arc<Mutex<gpu::G15ClChannel>>>,
    g15_jobs: KVec<gpu::G15ClJob>,
    /// G15: the queue's render state and this submission's render passes
    /// (their inputs and target memory; built and rung at run time).
    g15_rd: Option<Arc<Mutex<gpu::G15RdQueue>>>,
    g15_passes: KVec<(gpu::G15RdCmd, gpu::G15Rt)>,
}

#[versions(AGX)]
impl QueueJob::ver {
    fn get_vtx(&mut self) -> Result<&mut workqueue::Job::ver> {
        self.sj_vtx
            .as_mut()
            .ok_or_else(|| {
                cls_pr_debug!(Errors, "No vertex queue\n");
                EINVAL
            })?
            .get()
    }
    fn get_frag(&mut self) -> Result<&mut workqueue::Job::ver> {
        self.sj_frag
            .as_mut()
            .ok_or_else(|| {
                cls_pr_debug!(Errors, "No fragment queue\n");
                EINVAL
            })?
            .get()
    }
    fn get_comp(&mut self) -> Result<&mut workqueue::Job::ver> {
        self.sj_comp
            .as_mut()
            .ok_or_else(|| {
                cls_pr_debug!(Errors, "No compute queue\n");
                EINVAL
            })?
            .get()
    }

    fn commit(&mut self) -> Result {
        mod_dev_dbg!(self.dev, "QueueJob {}: Committing\n", self.id);

        self.sj_vtx.as_mut().map(|a| a.commit()).unwrap_or(Ok(()))?;
        self.sj_frag
            .as_mut()
            .map(|a| a.commit())
            .unwrap_or(Ok(()))?;
        self.sj_comp.as_mut().map(|a| a.commit()).unwrap_or(Ok(()))
    }
}

#[versions(AGX)]
impl sched::JobImpl for QueueJob::ver {
    fn prepare(job: &mut sched::Job<Self>) -> Option<Fence> {
        mod_dev_dbg!(job.dev, "QueueJob {}: Checking runnability\n", job.id);

        if let Some(sj) = job.sj_vtx.as_ref() {
            if let Some(fence) = sj.can_submit() {
                mod_dev_dbg!(
                    job.dev,
                    "QueueJob {}: Blocking due to vertex queue full\n",
                    job.id
                );
                return Some(fence);
            }
        }
        if let Some(sj) = job.sj_frag.as_ref() {
            if let Some(fence) = sj.can_submit() {
                mod_dev_dbg!(
                    job.dev,
                    "QueueJob {}: Blocking due to fragment queue full\n",
                    job.id
                );
                return Some(fence);
            }
        }
        if let Some(sj) = job.sj_comp.as_ref() {
            if let Some(fence) = sj.can_submit() {
                mod_dev_dbg!(
                    job.dev,
                    "QueueJob {}: Blocking due to compute queue full\n",
                    job.id
                );
                return Some(fence);
            }
        }
        None
    }

    #[allow(unused_assignments)]
    fn run(job: &mut sched::Job<Self>) -> Result<Option<dma_fence::Fence>> {
        mod_dev_dbg!(job.dev, "QueueJob {}: Running Job\n", job.id);

        if job.g15_chan.is_some() || job.g15_rd.is_some() {
            // G15: ring the CL jobs or the render passes; each signals its
            // fence command at its stamp (GpuManager::g15_cl_run,
            // g15_rd_pass_run).
            let gpu = match reg_gpu(&job.dev).map(|g| g.arc_as_any().downcast::<gpu::GpuManager::ver>()) {
                Some(Ok(gpu)) => gpu,
                _ => return Err(EIO),
            };
            if job.op_guard.is_none() {
                job.op_guard = Some(gpu.start_op()?);
            }
            let fence_done = |fence: UserFence<JobFence::ver>| {
                KBox::new(
                    move |err: Option<Error>| {
                        if let Some(err) = err {
                            fence.set_error(err);
                        }
                        fence.command_complete()
                    },
                    GFP_KERNEL,
                )
            };
            if let Some(rd) = job.g15_rd.clone() {
                let ctx = job.vm_bind.slot();
                let mut passes = KVec::new();
                core::mem::swap(&mut passes, &mut job.g15_passes);
                for (cmd, rt) in passes {
                    gpu.g15_rd_pass_run(&mut rd.lock(), ctx, &cmd, rt, fence_done(job.fence.clone())?)?;
                }
            }
            let mut jobs = KVec::new();
            core::mem::swap(&mut jobs, &mut job.g15_jobs);
            let chan = job.g15_chan.clone();
            for cl in jobs {
                let chan = chan.as_ref().ok_or(EIO)?;
                let fence = job.fence.clone();
                gpu.g15_cl_run(chan, cl, fence_done(fence)?)?;
            }
            job.did_run = true;
            return Ok(Some(Fence::from_fence(&job.fence)));
        }

        // We can only increase the notifier threshold here, now that we are
        // actually running the job. We cannot increase it while queueing the
        // job without introducing subtle race conditions. Suppose we did, as
        // early versions of drm/asahi did:
        //
        // 1. When processing the ioctl submit, a job is queued to drm_sched.
        //    Incorrectly, the notifier threshold is increased, gating firmware
        //    events.
        // 2. When DRM schedules an event, the hardware is kicked.
        // 3. When the number of processed jobs equals the threshold, the
        //    firmware signals the complete event to the kernel
        // 4. When the kernel gets a complete event, we signal the out-syncs.
        //
        // Does that work? There are a few scenarios.
        //
        // 1. There is nothing else ioctl submitted before the job completes.
        //    The job is scheduled, completes, and signals immediately.
        //    Everything works.
        // 2. There is nontrivial sync across different queues. Since each queue
        //    has a separate own notifier threshold, submitting one does not
        //    block scheduling of the other. Everything works the way you'd
        //    expect. drm/sched handles the wait/signal ordering.
        // 3. Two ioctls are submitted back-to-back. The first signals a fence
        //    that the second waits on. Due to the notifier threshold increment,
        //    the first job's completion event is deferred. But in good
        //    conditions, drm/sched will schedule the second submit anyway
        //    because it kills the pointless intra-queue sync. Then both
        //    commands execute and are signalled together.
        // 4. Two ioctls are submitted back-to-back as above, but conditions are
        //    bad. Reporting completion of the first job is still masked by the
        //    notifier threshold, but the intra-queue fences are not optimized
        //    out in drm/sched... drm/sched doesn't schedule the second job
        //    until the first is signalled, but the first isn't signalled until
        //    the second is completed, but the second can't complete until it's
        //    scheduled. We hang!
        //
        // In good conditions, everything works properly and/or we win the race
        // to mask the issue. So the issue here is challenging to hit.
        // Nevertheless, we do need to get it right.
        //
        // The intention with drm/sched is that jobs that are not yet scheduled
        // are "invisible" to the firmware. Incrementing the notifier threshold
        // earlier than this violates that which leads to circles like the
        // above. Deferring the increment to submit solves the race.
        job.notifier.threshold.with(|raw, _inner| {
            raw.increase(job.notification_count);
        });

        let dev = job.dev.clone();
        let Some(guard) = dev.registration_guard() else {
            return Err(ENODEV);
        };

        return guard.registration_data_with(|reg_data| {
            let gpu = match reg_data
                .gpu
                .clone()
                .arc_as_any()
                .downcast::<gpu::GpuManager::ver>()
            {
                Ok(gpu) => gpu,
                Err(_) => {
                    dev_crit!(job.dev.as_ref(), "GpuManager mismatched with QueueJob!\n");
                    return Err(EIO);
                }
            };

            if job.op_guard.is_none() {
                job.op_guard = Some(gpu.start_op()?);
            }

            // First submit all the commands for each queue. This can fail.

            let mut frag_job = None;
            let mut frag_sub = None;
            if let Some(sj) = job.sj_frag.as_mut() {
                frag_job = sj.job.take();
                if let Some(wqjob) = frag_job.as_mut() {
                    mod_dev_dbg!(job.dev, "QueueJob {}: Submit fragment\n", job.id);
                    frag_sub = Some(wqjob.submit()?);
                }
            }

            let mut vtx_job = None;
            let mut vtx_sub = None;
            if let Some(sj) = job.sj_vtx.as_mut() {
                vtx_job = sj.job.take();
                if let Some(wqjob) = vtx_job.as_mut() {
                    mod_dev_dbg!(job.dev, "QueueJob {}: Submit vertex\n", job.id);
                    vtx_sub = Some(wqjob.submit()?);
                }
            }

            let mut comp_job = None;
            let mut comp_sub = None;
            if let Some(sj) = job.sj_comp.as_mut() {
                comp_job = sj.job.take();
                if let Some(wqjob) = comp_job.as_mut() {
                    mod_dev_dbg!(job.dev, "QueueJob {}: Submit compute\n", job.id);
                    comp_sub = Some(wqjob.submit()?);
                }
            }

            // Now we fully commit to running the job
            mod_dev_dbg!(job.dev, "QueueJob {}: Run fragment\n", job.id);
            frag_sub.map(|a| gpu.run_job(a)).transpose()?;

            mod_dev_dbg!(job.dev, "QueueJob {}: Run vertex\n", job.id);
            vtx_sub.map(|a| gpu.run_job(a)).transpose()?;

            mod_dev_dbg!(job.dev, "QueueJob {}: Run compute\n", job.id);
            comp_sub.map(|a| gpu.run_job(a)).transpose()?;

            mod_dev_dbg!(job.dev, "QueueJob {}: Drop compute job\n", job.id);
            core::mem::drop(comp_job);
            mod_dev_dbg!(job.dev, "QueueJob {}: Drop vertex job\n", job.id);
            core::mem::drop(vtx_job);
            mod_dev_dbg!(job.dev, "QueueJob {}: Drop fragment job\n", job.id);
            core::mem::drop(frag_job);

            job.did_run = true;

            Ok(Some(Fence::from_fence(&job.fence)))
        });
    }

    fn timed_out(job: &mut sched::Job<Self>) -> sched::Status {
        // FIXME: Handle timeouts properly
        dev_err!(
            job.dev.as_ref(),
            "QueueJob {}: Job timed out on the DRM scheduler, things will probably break (ran: {})\n",
            job.id, job.did_run
        );
        sched::Status::NoDevice
    }

    fn cancel(job: &mut sched::Job<Self>) {
        dev_info!(
            job.dev.as_ref(),
            "QueueJob {}: Job canceled on DRM scheduler teardown\n",
            job.id
        );
        if job.g15_chan.is_some() || job.g15_rd.is_some() {
            if let Some(Ok(gpu)) = reg_gpu(&job.dev).map(|g| g.arc_as_any().downcast::<gpu::GpuManager::ver>()) {
                gpu.g15_cl_dump_pending();
            }
        }
    }
}

#[versions(AGX)]
impl Drop for QueueJob::ver {
    fn drop(&mut self) {
        mod_dev_dbg!(self.dev, "QueueJob {}: Dropping\n", self.id);
    }
}

static QUEUE_NAME: &CStr = c_str!("asahi_fence");
static QUEUE_CLASS_KEY: Pin<&LockClassKey> = kernel::static_lock_class!();

#[versions(AGX)]
impl Queue::ver {
    /// Create a new user queue.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new<'drm>(
        dev: AsahiDevice,
        reg_data: &AsahiRegData<'drm>,
        vm: mmu::Vm,
        alloc: &mut gpu::KernelAllocators,
        ualloc: Arc<Mutex<alloc::DefaultAllocator>>,
        ualloc_priv: Arc<Mutex<alloc::DefaultAllocator>>,
        event_manager: Arc<event::EventManager>,
        mgr: &buffer::BufferManager::ver,
        id: u64,
        priority: u32,
        usc_exec_base: u64,
    ) -> Result<Queue::ver> {
        mod_dev_dbg!(dev, "[Queue {}] Creating queue\n", id);

        // Must be shared, no cache management on this one!
        let mut notifier_list = alloc.shared.new_default::<fw::event::NotifierList>()?;

        let self_ptr = notifier_list.weak_pointer();
        notifier_list.with_mut(|raw, _inner| {
            raw.list_head.next = Some(inner_weak_ptr!(self_ptr, list_head));
        });

        let threshold = alloc.shared.new_default::<fw::event::Threshold>()?;

        let notifier: Arc<GpuObject<fw::event::Notifier::ver>> = Arc::new(
            alloc.private.new_init(
                /*try_*/ init!(fw::event::Notifier::ver { threshold }),
                |inner, _p| {
                    try_init!(fw::event::raw::Notifier::ver {
                        threshold: inner.threshold.gpu_pointer(),
                        generation: AtomicU32::new(id as u32),
                        cur_count: AtomicU32::new(0),
                        unk_10: AtomicU32::new(0x50),
                        state: Default::default()
                    })
                },
            )?,
            GFP_KERNEL,
        )?;

        // Priorities are handled by the AGX scheduler, there is no meaning within a
        // per-queue scheduler. Use a single run queue wth Kernel priority.
        let sched = sched::Scheduler::new(
            dev.as_ref().as_ref(),
            1,
            WQ_SIZE,
            0,
            100000,
            c_str!("asahi_sched"),
        )?;
        let entity = sched::Entity::new(&sched, sched::Priority::Kernel)?;

        let buffer =
            buffer::Buffer::ver::new(&*reg_data.gpu, alloc, ualloc.clone(), ualloc_priv, mgr)?;

        let mut ret = Queue::ver {
            dev: dev.clone(),
            _sched: sched,
            entity,
            vm,
            q_vtx: None,
            q_frag: None,
            q_comp: None,
            fence_ctx: FenceContexts::new(1, QUEUE_NAME, QUEUE_CLASS_KEY)?,
            g15_chan: None,
            g15_rd: None,
            inner: QueueInner::ver {
                dev: dev.clone(),
                ualloc,
                gpu_context: Arc::new(
                    workqueue::GpuContext::new(dev.clone(), alloc, buffer.any_ref())?,
                    GFP_KERNEL,
                )?,

                buffer,
                notifier_list: Arc::new(notifier_list, GFP_KERNEL)?,
                notifier,
                usc_exec_base,
                id,
                #[ver(V >= V13_0B4)]
                counter: AtomicU64::new(0),
            },
        };

        // Rendering structures
        let tvb_blocks = *module_parameters::initial_tvb_size.value();

        ret.inner.buffer.ensure_blocks(tvb_blocks)?;

        ret.q_vtx = Some(SubQueue::ver {
            wq: workqueue::WorkQueue::ver::new(
                dev.clone(),
                alloc,
                event_manager.clone(),
                ret.inner.gpu_context.clone(),
                ret.inner.notifier_list.clone(),
                channel::PipeType::Vertex,
                id,
                priority,
                WQ_SIZE,
            )?,
        });

        ret.q_frag = Some(SubQueue::ver {
            wq: workqueue::WorkQueue::ver::new(
                dev.clone(),
                alloc,
                event_manager.clone(),
                ret.inner.gpu_context.clone(),
                ret.inner.notifier_list.clone(),
                channel::PipeType::Fragment,
                id,
                priority,
                WQ_SIZE,
            )?,
        });

        // Compute structures
        ret.q_comp = Some(SubQueue::ver {
            wq: workqueue::WorkQueue::ver::new(
                dev.clone(),
                alloc,
                event_manager,
                ret.inner.gpu_context.clone(),
                ret.inner.notifier_list.clone(),
                channel::PipeType::Compute,
                id,
                priority,
                WQ_SIZE,
            )?,
        });

        mod_dev_dbg!(dev, "[Queue {}] Queue created\n", id);
        Ok(ret)
    }

    /// G15: a render command's pass inputs (spec: agx-g15c/render-job.md,
    /// "The 3D register list"). The VDM stream must be in [64 GiB, 576 GiB)
    /// (the TA's 40-bit form).
    fn g15_render_cmd(
        r: &uapi::drm_asahi_cmd_render,
        g: &uapi::drm_asahi_cmd_render_g15,
    ) -> Result<gpu::G15RdCmd> {
        let geom = gpu::G15RdGeom::new(
            r.width_px as u32,
            r.height_px as u32,
            r.layers as u32,
            r.samples as u32,
            r.utile_width_px as u32,
            r.utile_height_px as u32,
            r.sample_size_B as u32,
        )
        .inspect_err(|_| {
            cls_pr_debug!(Errors, "G15 render: invalid geometry {}x{}x{}, {} samples, utile {}x{}\n",
                          r.width_px, r.height_px, r.layers, r.samples, r.utile_width_px, r.utile_height_px);
        })?;
        if !(0x10_0000_0000..0x90_0000_0000).contains(&r.vdm_ctrl_stream_base) {
            cls_pr_debug!(Errors, "G15 render: VDM stream at {:#x}\n", r.vdm_ctrl_stream_base);
            return Err(EINVAL);
        }
        let zls = |b: &uapi::drm_asahi_zls_buffer| gpu::G15RdZls {
            base: b.base,
            comp_base: b.comp_base,
            stride: b.stride as u64,
            comp_stride: b.comp_stride as u64,
        };
        let flags = r.flags as u32;
        Ok(gpu::G15RdCmd {
            geom,
            vdm: Some(r.vdm_ctrl_stream_base),
            bg: (g.bg[0], g.bg[1]),
            eot: (g.eot[0], g.eot[1]),
            process_empty: flags & uapi::drm_asahi_render_flags_DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES as u32 != 0,
            multisamplectl: r.ppp_multisamplectl,
            zls_pixels: r.isp_zls_pixels as u64,
            zls_ctrl: r.zls_ctrl,
            bgobjdepth: r.isp_bgobjdepth,
            bgobjvals: r.isp_bgobjvals,
            depth: zls(&r.depth),
            stencil: zls(&r.stencil),
            scissor: r.isp_scissor_base,
            dbias: r.isp_dbias_base,
            oclqry: r.isp_oclqry_base,
            // The flag is the hardware bit (as on G13).
            isp_ctl: 0xC000 | (flags & uapi::drm_asahi_render_flags_DRM_ASAHI_RENDER_DBIAS_IS_INT as u32) as u64,
            merge_x: r.isp_merge_upper_x,
            merge_y: r.isp_merge_upper_y,
        })
    }

    /// G15: a submission of compute commands (spec: agx-g15c/cl-job.md) or
    /// of render commands (agx-g15c/render-job.md): each compute command
    /// becomes a CL job on the queue's channel, each render command a TA
    /// and a 3D job on the queue's render channels, in the VM's context;
    /// the job's fence signals once every command's stamp is reached.
    /// Barriers are implicit (one channel runs its jobs in order); a
    /// submission mixing compute and render is not supported yet (the
    /// order between the CL and render channels needs barrier records).
    fn submit_g15(
        &mut self,
        gpu: &Arc<gpu::GpuManager::ver>,
        id: u64,
        mut syncs: KVec<file::SyncItem>,
        in_sync_count: usize,
        cmdbuf_raw: &[u8],
    ) -> Result {
        if gpu.is_crashed() {
            return Err(ENODEV);
        }
        // Parse and validate everything first.
        let mut cmds: KVec<uapi::drm_asahi_cmd_compute> = KVec::new();
        let mut renders: KVec<gpu::G15RdCmd> = KVec::new();
        let mut cmdbuf = Reader::new(cmdbuf_raw);
        while !cmdbuf.is_empty() {
            let header: uapi::drm_asahi_cmd_header = cmdbuf.read()?;
            let size = header.size as usize;
            match header.cmd_type as u32 {
                uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_COMPUTE => {
                    cmds.push(cmdbuf.read_up_to(size)?, GFP_KERNEL)?;
                }
                uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_RENDER => {
                    let rsize = core::mem::size_of::<uapi::drm_asahi_cmd_render>();
                    let gsize = core::mem::size_of::<uapi::drm_asahi_cmd_render_g15>();
                    if size < rsize + gsize {
                        cls_pr_debug!(Errors, "G15 submit: a render command without its G15 part ({} B)\n", size);
                        return Err(EINVAL);
                    }
                    let r: uapi::drm_asahi_cmd_render = cmdbuf.read()?;
                    let g: uapi::drm_asahi_cmd_render_g15 = cmdbuf.read()?;
                    cmdbuf.skip(size - rsize - gsize);
                    renders.push(Self::g15_render_cmd(&r, &g)?, GFP_KERNEL)?;
                }
                uapi::drm_asahi_cmd_type_DRM_ASAHI_SET_COMPUTE_ATTACHMENTS
                | uapi::drm_asahi_cmd_type_DRM_ASAHI_SET_VERTEX_ATTACHMENTS
                | uapi::drm_asahi_cmd_type_DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS => cmdbuf.skip(size),
                t => {
                    cls_pr_debug!(Errors, "G15 submit: command type {} not supported\n", t);
                    return Err(EINVAL);
                }
            }
        }
        let n = cmds.len() + renders.len();
        if n == 0 || n > MAX_COMMANDS_PER_SUBMISSION as usize || (!cmds.is_empty() && !renders.is_empty()) {
            cls_pr_debug!(Errors, "G15 submit: {} compute and {} render commands\n", cmds.len(), renders.len());
            return Err(EINVAL);
        }

        let op_guard = if in_sync_count > 0 {
            Some(gpu.start_op()?)
        } else {
            None
        };
        let vm_bind = gpu.bind_vm(&self.vm)?;
        let ctx = vm_bind.slot();
        let chan = if cmds.is_empty() {
            None
        } else {
            if self.g15_chan.is_none() {
                self.g15_chan = Some(gpu.g15_cl_channel_get()?);
            }
            Some(self.g15_chan.clone().ok_or(EIO)?)
        };
        let rd = if renders.is_empty() {
            None
        } else {
            if self.g15_rd.is_none() {
                let q = gpu.g15_rd_queue_new(&self.inner.ualloc)?;
                self.g15_rd = Some(Arc::pin_init(new_mutex!(q, "g15_rd_queue"), GFP_KERNEL)?);
            }
            self.g15_rd.clone()
        };

        let fence: UserFence<JobFence::ver> = self
            .fence_ctx
            .new_fence::<JobFence::ver>(
                0,
                JobFence::ver {
                    id,
                    pending: Default::default(),
                },
            )?
            .into();
        let mut jobs = KVec::new();
        if let Some(chan) = chan.as_ref() {
            for c in cmds.iter() {
                let cl = gpu.g15_cl_job_new(&chan.lock(), Some(c.cdm_ctrl_stream_base), ctx, &[])?;
                jobs.push(cl, GFP_KERNEL)?;
                fence.add_command();
            }
        }
        let mut passes = KVec::new();
        for r in renders.iter() {
            passes.push((*r, gpu.g15_rt_new(&r.geom)?), GFP_KERNEL)?;
            fence.add_command();
        }

        let mut job = self.entity.new_job(
            1,
            QueueJob::ver {
                dev: self.dev.clone(),
                vm_bind,
                op_guard,
                sj_vtx: None,
                sj_frag: None,
                sj_comp: None,
                fence,
                notifier: self.inner.notifier.clone(),
                notification_count: 0,
                did_run: false,
                id,
                g15_chan: chan,
                g15_jobs: jobs,
                g15_rd: rd,
                g15_passes: passes,
            },
        )?;
        for sync in syncs.drain(0..in_sync_count) {
            if let Some(fence) = sync.fence {
                job.add_dependency(fence)?;
            }
        }
        let mut job = job.arm();
        let out_fence = job.fences().finished();
        job.push();
        for mut sync in syncs {
            if let Some(chain) = sync.chain_fence.take() {
                sync.syncobj
                    .add_point(chain, &out_fence, sync.timeline_value);
            } else {
                sync.syncobj.replace_fence(Some(&out_fence));
            }
        }
        Ok(())
    }
}

const SQ_RENDER: usize = 0;
const SQ_COMPUTE: usize = 1;
const SQ_COUNT: usize = 2;

// SAFETY: All bit patterns are valid by construction.
unsafe impl AnyBitPattern for uapi::drm_asahi_cmd_header {}
unsafe impl AnyBitPattern for uapi::drm_asahi_cmd_render {}
unsafe impl AnyBitPattern for uapi::drm_asahi_cmd_render_g15 {}
unsafe impl AnyBitPattern for uapi::drm_asahi_cmd_compute {}
unsafe impl AnyBitPattern for uapi::drm_asahi_attachment {}

fn build_attachments(reader: &mut Reader<'_>, size: usize) -> Result<microseq::Attachments> {
    const STRIDE: usize = core::mem::size_of::<uapi::drm_asahi_attachment>();
    let count = size / STRIDE;

    if count > microseq::MAX_ATTACHMENTS {
        return Err(EINVAL);
    }

    let mut attachments: microseq::Attachments = Default::default();
    attachments.count = count as u32;

    for i in 0..count {
        let att: uapi::drm_asahi_attachment = reader.read()?;

        if att.flags != 0 || att.pad != 0 {
            return Err(EINVAL);
        }

        // Some kind of power-of-2 exponent related to attachment size, in
        // bounds [1, 6]? We don't know what this is exactly yet.
        let unk_e = 1;

        let cache_lines = (att.size + 127) >> 7;
        attachments.list[i as usize] = microseq::Attachment {
            address: U64(att.pointer),
            size: cache_lines.try_into()?,
            unk_c: 0x17,
            unk_e: unk_e as u16,
        };
    }

    Ok(attachments)
}

#[versions(AGX)]
impl Queue for Queue::ver {
    fn submit<'drm>(
        &mut self,
        reg_data: &AsahiRegData<'drm>,
        id: u64,
        mut syncs: KVec<file::SyncItem>,
        in_sync_count: usize,
        cmdbuf_raw: &[u8],
        objects: Pin<&xarray::XArray<KBox<file::Object>>>,
    ) -> Result {
        let gpu = match reg_data
            .gpu
            .clone()
            .arc_as_any()
            .downcast::<gpu::GpuManager::ver>()
        {
            Ok(gpu) => gpu,
            Err(_) => {
                dev_crit!(self.dev.as_ref(), "GpuManager mismatched with JobImpl!\n");
                return Err(EIO);
            }
        };

        mod_dev_dbg!(self.dev, "[Submission {}] Submit job\n", id);

        #[ver(G == G15)]
        if true {
            return self.submit_g15(&gpu, id, syncs, in_sync_count, cmdbuf_raw);
        }

        if gpu.is_crashed() {
            dev_err!(
                self.dev.as_ref(),
                "[Submission {}] GPU is crashed, cannot submit\n",
                id
            );
            return Err(ENODEV);
        }

        let op_guard = if in_sync_count > 0 {
            Some(gpu.start_op()?)
        } else {
            None
        };

        let mut events: [KVec<Option<workqueue::QueueEventInfo::ver>>; SQ_COUNT] =
            Default::default();

        events[SQ_RENDER].push(
            self.q_frag.as_ref().and_then(|a| a.wq.event_info()),
            GFP_KERNEL,
        )?;
        events[SQ_COMPUTE].push(
            self.q_comp.as_ref().and_then(|a| a.wq.event_info()),
            GFP_KERNEL,
        )?;

        let vm_bind = gpu.bind_vm(&self.vm)?;
        let vm_slot = vm_bind.slot();

        mod_dev_dbg!(self.dev, "[Submission {}] Creating job\n", id);

        // FIXME: I think this can violate the fence seqno ordering contract.
        // If we have e.g. a render submission with no barriers and then a compute submission
        // with no barriers, it's possible for the compute submission to complete first, and
        // therefore its fence. Maybe we should have separate fence contexts for render
        // and compute, and then do a ? (Vert+frag should be fine since there is no vert
        // without frag, and frag always serializes.)
        let fence: UserFence<JobFence::ver> = self
            .fence_ctx
            .new_fence::<JobFence::ver>(
                0,
                JobFence::ver {
                    id,
                    pending: Default::default(),
                },
            )?
            .into();

        let mut cmdbuf = Reader::new(cmdbuf_raw);

        // First, parse the headers to determine the number of compute/render
        // commands. This will be used to determine when to flush stamps.
        //
        // We also use it to determine how many notifications the job will
        // generate. We could calculate that in the second pass since we don't
        // need until much later, but it's convenient to gather everything at
        // the same time.
        let mut nr_commands = 0;
        let mut last_compute = 0;
        let mut last_render = 0;
        let mut nr_render = 0;
        let mut nr_compute = 0;

        while !cmdbuf.is_empty() {
            let header: uapi::drm_asahi_cmd_header = cmdbuf.read()?;
            cmdbuf.skip(header.size as usize);
            nr_commands += 1;

            match header.cmd_type as u32 {
                uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_RENDER => {
                    last_compute = nr_commands;
                    nr_render += 1;
                }
                uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_COMPUTE => {
                    last_render = nr_commands;
                    nr_compute += 1;
                }
                _ => {}
            }
        }

        let mut job = self.entity.new_job(
            1,
            QueueJob::ver {
                dev: self.dev.clone(),
                vm_bind,
                op_guard,
                sj_vtx: self
                    .q_vtx
                    .as_mut()
                    .map(|a| a.new_job(Fence::from_fence(&fence))),
                sj_frag: self
                    .q_frag
                    .as_mut()
                    .map(|a| a.new_job(Fence::from_fence(&fence))),
                sj_comp: self
                    .q_comp
                    .as_mut()
                    .map(|a| a.new_job(Fence::from_fence(&fence))),
                fence,
                notifier: self.inner.notifier.clone(),

                // Each render command generates 2 notifications: 1 for the
                // vertex part, 1 for the fragment part. Each compute command
                // generates 1 notification. Sum up to calculate the total
                // notification count for the job.
                notification_count: (2 * nr_render) + nr_compute,

                did_run: false,
                id,
                g15_chan: None,
                g15_jobs: KVec::new(),
                g15_rd: None,
                g15_passes: KVec::new(),
            },
        )?;

        mod_dev_dbg!(
            self.dev,
            "[Submission {}] Adding {} in_syncs\n",
            id,
            in_sync_count
        );
        for sync in syncs.drain(0..in_sync_count) {
            if let Some(fence) = sync.fence {
                job.add_dependency(fence)?;
            }
        }

        // Validate the number of hardware commands, ignoring software commands
        let nr_hw_commands = nr_render + nr_compute;
        if nr_hw_commands == 0 || nr_hw_commands > MAX_COMMANDS_PER_SUBMISSION {
            cls_pr_debug!(
                Errors,
                "submit: Command count {} out of valid range [1, {}]\n",
                nr_hw_commands,
                MAX_COMMANDS_PER_SUBMISSION - 1
            );
            return Err(EINVAL);
        }

        cmdbuf.rewind();

        let mut command_index = 0;
        let mut vertex_attachments: microseq::Attachments = Default::default();
        let mut fragment_attachments: microseq::Attachments = Default::default();
        let mut compute_attachments: microseq::Attachments = Default::default();

        // Parse the full command buffer submitting as we go
        while !cmdbuf.is_empty() {
            let header: uapi::drm_asahi_cmd_header = cmdbuf.read()?;
            let header_size = header.size as usize;

            // Pre-increment command index to match last_compute/last_render
            command_index += 1;

            for (queue_idx, index) in [header.vdm_barrier, header.cdm_barrier].iter().enumerate() {
                if *index == uapi::DRM_ASAHI_BARRIER_NONE as u16 {
                    continue;
                }
                if let Some(event) = events[queue_idx].get(*index as usize).ok_or_else(|| {
                    cls_pr_debug!(Errors, "Invalid barrier #{}: {}\n", queue_idx, index);
                    EINVAL
                })? {
                    let mut alloc = gpu.alloc();
                    let queue_job = match header.cmd_type as u32 {
                        uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_RENDER => job.get_vtx()?,
                        uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_COMPUTE => job.get_comp()?,
                        _ => return Err(EINVAL),
                    };
                    mod_dev_dbg!(self.dev, "[Submission {}] Create Explicit Barrier\n", id);
                    let barrier = alloc.private.new_init(
                        pin_init::zeroed::<fw::workqueue::Barrier>(),
                        |_inner, _p| {
                            let queue_job = &queue_job;
                            try_init!(fw::workqueue::raw::Barrier {
                                tag: fw::workqueue::CommandType::Barrier,
                                wait_stamp: event.fw_stamp_pointer,
                                wait_value: event.value,
                                wait_slot: event.slot,
                                stamp_self: queue_job.event_info().value.next(),
                                uuid: 0xffffbbbb,
                                external_barrier: 0,
                                internal_barrier_type: 1,
                                padding: Default::default(),
                            })
                        },
                    )?;
                    mod_dev_dbg!(self.dev, "[Submission {}] Add Explicit Barrier\n", id);
                    queue_job.add(barrier, vm_slot)?;
                } else {
                    assert!(*index == 0);
                }
            }

            match header.cmd_type as u32 {
                uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_RENDER => {
                    let render: uapi::drm_asahi_cmd_render = cmdbuf.read_up_to(header_size)?;

                    self.inner.submit_render(
                        &gpu,
                        &mut job,
                        &render,
                        &vertex_attachments,
                        &fragment_attachments,
                        objects,
                        id,
                        command_index == last_render,
                    )?;
                    events[SQ_RENDER].push(
                        Some(
                            job.sj_frag
                                .as_ref()
                                .expect("No frag queue?")
                                .job
                                .as_ref()
                                .expect("No frag job?")
                                .event_info(),
                        ),
                        GFP_KERNEL,
                    )?;
                }
                uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_COMPUTE => {
                    let compute: uapi::drm_asahi_cmd_compute = cmdbuf.read_up_to(header_size)?;

                    self.inner.submit_compute(
                        &gpu,
                        &mut job,
                        &compute,
                        &compute_attachments,
                        objects,
                        id,
                        command_index == last_compute,
                    )?;
                    events[SQ_COMPUTE].push(
                        Some(
                            job.sj_comp
                                .as_ref()
                                .expect("No comp queue?")
                                .job
                                .as_ref()
                                .expect("No comp job?")
                                .event_info(),
                        ),
                        GFP_KERNEL,
                    )?;
                }
                uapi::drm_asahi_cmd_type_DRM_ASAHI_SET_VERTEX_ATTACHMENTS => {
                    vertex_attachments = build_attachments(&mut cmdbuf, header_size)?;
                }
                uapi::drm_asahi_cmd_type_DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS => {
                    fragment_attachments = build_attachments(&mut cmdbuf, header_size)?;
                }
                uapi::drm_asahi_cmd_type_DRM_ASAHI_SET_COMPUTE_ATTACHMENTS => {
                    compute_attachments = build_attachments(&mut cmdbuf, header_size)?;
                }
                _ => {
                    cls_pr_debug!(Errors, "Unknown command type {}\n", header.cmd_type);
                    return Err(EINVAL);
                }
            }
        }

        mod_dev_dbg!(
            self.dev,
            "Queue {}: Committing job {}\n",
            self.inner.id,
            job.id
        );
        job.commit()?;

        mod_dev_dbg!(self.dev, "Queue {}: Arming job {}\n", self.inner.id, job.id);
        let mut job = job.arm();
        let out_fence = job.fences().finished();
        mod_dev_dbg!(
            self.dev,
            "Queue {}: Pushing job {}\n",
            self.inner.id,
            job.id
        );
        job.push();

        mod_dev_dbg!(
            self.dev,
            "Queue {}: Adding {} out_syncs\n",
            self.inner.id,
            syncs.len()
        );
        for mut sync in syncs {
            if let Some(chain) = sync.chain_fence.take() {
                sync.syncobj
                    .add_point(chain, &out_fence, sync.timeline_value);
            } else {
                sync.syncobj.replace_fence(Some(&out_fence));
            }
        }

        Ok(())
    }
}

#[versions(AGX)]
impl Drop for Queue::ver {
    fn drop(&mut self) {
        mod_dev_dbg!(self.dev, "[Queue {}] Dropping queue\n", self.inner.id);
        if let Some(Ok(gpu)) = reg_gpu(&self.dev).map(|g| g.arc_as_any().downcast::<gpu::GpuManager::ver>()) {
            if let Some(ch) = self.g15_chan.take() {
                gpu.g15_cl_channel_put(ch);
            }
            if let Some(rd) = self.g15_rd.take() {
                gpu.g15_rd_queue_put(&rd.lock());
            }
        }
    }
}
