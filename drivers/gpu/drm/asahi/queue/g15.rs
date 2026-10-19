// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! G15 submission.
//!
//! A G15 submission does not go through the firmware's work queues: its
//! compute commands become CL jobs on the queue's compute channel and its
//! render commands render passes on the queue's TA and 3D channels (see
//! `gpu::g15`). The commands are rung when the scheduler runs the job, in
//! order, and the job's fence signals once all of them are complete.

use super::*;

/// One command of a submission. `after` makes it wait for the queue's work
/// of the other kind before it: its header's `cdm_barrier` (for a render
/// command) or `vdm_barrier` (for a compute command) is set. Commands of one
/// kind run in order on their channel. `ts` holds the timestamp buffers the
/// command's jobs write to until it is complete.
#[allow(
    clippy::large_enum_variant,
    reason = "a few per submission; boxing adds an allocation each"
)]
pub(super) enum G15Step {
    Cl {
        job: gpu::G15ClJob,
        after: bool,
        ts: KVec<fw::job::UserTimestamp>,
    },
    Rd {
        cmd: gpu::G15RdCmd,
        rt: gpu::G15Rt,
        after: bool,
        ts: KVec<fw::job::UserTimestamp>,
    },
}

/// A submission's commands not submitted yet.
///
/// A command that waits for the other kind's work goes once that kind's
/// last job has completed: the host orders the two kinds, as stamp barriers
/// between the compute and render channels crash the firmware. A held-back
/// submission holds back the queue's later ones, since a channel runs its
/// jobs in the order they are rung. The completion poller resumes them
/// (`GpuManager::g15_defer`).
#[versions(AGX)]
pub(super) struct G15Run {
    gpu: Arc<gpu::GpuManager::ver>,
    chan: Option<Arc<Mutex<gpu::G15ClChannel>>>,
    rd: Option<Arc<Mutex<gpu::G15RdQueue>>>,
    vm: mmu::VmBind,
    fence: UserFence<JobFence::ver>,
    steps: KVec<Option<G15Step>>,
    next: usize,
}

#[versions(AGX)]
impl G15Run::ver {
    /// Whether the other kind's last job before `step` has completed.
    fn ready(&self, step: &G15Step) -> bool {
        match step {
            G15Step::Cl { after: true, .. } => self
                .rd
                .as_ref()
                .is_none_or(|rd| self.gpu.g15_chan_done(&rd.lock().d3().lock())),
            G15Step::Rd { after: true, .. } => self
                .chan
                .as_ref()
                .is_none_or(|ch| self.gpu.g15_chan_done(&ch.lock())),
            _ => true,
        }
    }

    /// The completion of one command: its share of the job's fence. It
    /// holds the command's timestamp buffers.
    fn done(
        &self,
        ts: KVec<fw::job::UserTimestamp>,
    ) -> Result<KBox<dyn FnMut(Option<Error>) + Send>> {
        let fence = self.fence.clone();
        Ok(KBox::new(
            move |err: Option<Error>| {
                let _ts = &ts;
                if let Some(err) = err {
                    fence.set_error(err);
                }
                fence.command_complete()
            },
            GFP_KERNEL,
        )?)
    }

    fn submit(&self, step: G15Step) -> Result {
        match step {
            G15Step::Cl { job, ts, .. } => self.gpu.g15_cl_run(
                self.chan.as_ref().ok_or(EIO)?,
                job,
                self.vm.clone(),
                self.done(ts)?,
            ),
            G15Step::Rd { cmd, rt, ts, .. } => {
                let rd = self.rd.as_ref().ok_or(EIO)?;
                self.gpu
                    .g15_rd_pass_run(&mut rd.lock(), self.vm.clone(), &cmd, rt, self.done(ts)?)
            }
        }
    }

    /// Fails the commands not submitted yet.
    pub(super) fn cancel(&mut self, err: Error) {
        for _ in self.next..self.steps.len() {
            self.fence.set_error(err);
            self.fence.command_complete();
        }
        self.next = self.steps.len();
    }

    /// Submits the commands whose wait is met, in order. Returns true once
    /// all are submitted. A command that fails to submit fails itself and
    /// every one after it.
    fn advance(&mut self) -> bool {
        // A crashed firmware completes nothing: a wait would never be met.
        if self.gpu.is_crashed() {
            self.cancel(ENODEV);
            return true;
        }
        while self.next < self.steps.len() {
            if self.steps[self.next]
                .as_ref()
                .is_some_and(|s| !self.ready(s))
            {
                return false;
            }
            if let Some(step) = self.steps[self.next].take() {
                if let Err(e) = self.submit(step) {
                    self.cancel(e);
                    break;
                }
            }
            self.next += 1;
        }
        true
    }

    /// Advances a queue's held-back submissions in order. Returns true once
    /// none is left.
    fn advance_all(held: &mut KVec<Self>) -> bool {
        while let Some(run) = held.first_mut() {
            if !run.advance() {
                return false;
            }
            let _ = held.remove(0);
        }
        true
    }
}

#[versions(AGX)]
impl QueueJob::ver {
    /// Runs a G15 job: rings its commands in order, holding back from the
    /// first that waits for the other kind's work. Each command signals its
    /// share of the job's fence once complete.
    pub(super) fn run_g15(job: &mut sched::Job<Self>) -> Result<Option<dma_fence::Fence>> {
        let gpu = match reg_gpu(&job.dev).map(|g| g.arc_as_any().downcast::<gpu::GpuManager::ver>())
        {
            Some(Ok(gpu)) => gpu,
            _ => return Err(EIO),
        };
        if job.op_guard.is_none() {
            job.op_guard = Some(gpu.start_op()?);
        }
        let mut run = G15Run::ver {
            gpu: gpu.clone(),
            chan: job.g15_chan.clone(),
            rd: job.g15_rd.clone(),
            vm: job.vm_bind.clone(),
            fence: job.fence.clone(),
            steps: core::mem::take(&mut job.g15_steps),
            next: 0,
        };
        let held = job.g15_held.clone().ok_or(EIO)?;
        let mut list = held.lock();
        if !list.is_empty() || !run.advance() {
            list.push(run, GFP_KERNEL)?;
            if list.len() == 1 {
                let held = held.clone();
                gpu.g15_defer(KBox::new(
                    move || G15Run::ver::advance_all(&mut held.lock()),
                    GFP_KERNEL,
                )?)?;
            }
        }
        job.did_run = true;
        Ok(Some(Fence::from_fence(&job.fence)))
    }
}

#[versions(AGX)]
impl Queue::ver {
    /// Converts a render command into a pass's inputs. The VDM stream must
    /// be in [64 GiB, 576 GiB), which the TA job takes in a 40-bit form.
    fn g15_render_cmd(
        r: &uapi::drm_asahi_cmd_render,
        g: &uapi::drm_asahi_cmd_render_g15,
    ) -> Result<gpu::G15RdCmd> {
        let geom = gpu::G15RdGeom::new(
            u32::from(r.width_px),
            u32::from(r.height_px),
            u32::from(r.layers),
            u32::from(r.samples),
            u32::from(r.utile_width_px),
            u32::from(r.utile_height_px),
            u32::from(r.sample_size_B),
        )
        .inspect_err(|_| {
            cls_pr_debug!(
                Errors,
                "G15 render: invalid geometry {}x{}x{}, {} samples, utile {}x{}\n",
                r.width_px,
                r.height_px,
                r.layers,
                r.samples,
                r.utile_width_px,
                r.utile_height_px
            );
        })?;
        if !(0x10_0000_0000..0x90_0000_0000).contains(&r.vdm_ctrl_stream_base) {
            cls_pr_debug!(
                Errors,
                "G15 render: VDM stream at {:#x}\n",
                r.vdm_ctrl_stream_base
            );
            return Err(EINVAL);
        }
        let zls = |b: &uapi::drm_asahi_zls_buffer| gpu::G15RdZls {
            base: b.base,
            comp_base: b.comp_base,
            stride: u64::from(b.stride),
            comp_stride: u64::from(b.comp_stride),
        };
        let flags = r.flags;
        Ok(gpu::G15RdCmd {
            geom,
            vdm: Some(r.vdm_ctrl_stream_base),
            bg: (g.bg[0], g.bg[1]),
            eot: (g.eot[0], g.eot[1]),
            partial_bg: (g.partial_bg[0], g.partial_bg[1]),
            partial_eot: (g.partial_eot[0], g.partial_eot[1]),
            process_empty: flags
                & uapi::drm_asahi_render_flags_DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES
                != 0,
            multisamplectl: r.ppp_multisamplectl,
            zls_pixels: u64::from(r.isp_zls_pixels),
            zls_ctrl: r.zls_ctrl,
            bgobjdepth: r.isp_bgobjdepth,
            bgobjvals: r.isp_bgobjvals,
            depth: zls(&r.depth),
            stencil: zls(&r.stencil),
            scissor: r.isp_scissor_base,
            dbias: r.isp_dbias_base,
            oclqry: r.isp_oclqry_base,
            // The flag is the hardware bit (as on G13).
            isp_ctl: 0xC000
                | u64::from(flags & uapi::drm_asahi_render_flags_DRM_ASAHI_RENDER_DBIAS_IS_INT),
            merge_x: r.isp_merge_upper_x,
            merge_y: r.isp_merge_upper_y,
            ts_ta: (0, 0),
            ts_3d: (0, 0),
        })
    }

    /// Resolves a command's user timestamps (start, end) to the kernel VAs
    /// its jobs write them to, keeping their buffers in `keep`.
    fn g15_timestamps(
        objects: Pin<&xarray::XArray<KBox<file::Object>>>,
        ts: &uapi::drm_asahi_timestamps,
        keep: &mut KVec<fw::job::UserTimestamp>,
    ) -> Result<(u64, u64)> {
        let mut va = [0u64; 2];
        for (va, t) in va.iter_mut().zip([ts.start, ts.end]) {
            if let Some(t) = common::get_timestamp_object(objects, t)? {
                *va = t.mapping.iova() + t.offset as u64;
                keep.push(t, GFP_KERNEL)?;
            }
        }
        Ok((va[0], va[1]))
    }

    /// Submits compute and render commands, in their order. A compute
    /// command becomes a CL job on the queue's compute channel and a render
    /// command a TA and a 3D job on its render channels, in the VM's
    /// context. The job's fence signals once every command is complete.
    pub(super) fn submit_g15(
        &mut self,
        gpu: &Arc<gpu::GpuManager::ver>,
        id: u64,
        mut syncs: KVec<file::SyncItem>,
        in_sync_count: usize,
        cmdbuf_raw: &[u8],
        objects: Pin<&xarray::XArray<KBox<file::Object>>>,
    ) -> Result {
        if gpu.is_crashed() {
            return Err(ENODEV);
        }
        // Parse and validate everything first.
        enum Cmd {
            Cl(uapi::drm_asahi_cmd_compute, (u64, u64), bool),
            Rd(KBox<gpu::G15RdCmd>, bool),
        }
        let mut ts: KVec<KVec<fw::job::UserTimestamp>> = KVec::new();
        let mut cmds: KVec<Cmd> = KVec::new();
        let (mut n_cl, mut n_rd) = (0usize, 0usize);
        let mut cmdbuf = Reader::new(cmdbuf_raw);
        while !cmdbuf.is_empty() {
            let header: uapi::drm_asahi_cmd_header = cmdbuf.read()?;
            let size = header.size as usize;
            // A barrier waits on the previous submissions (0) or on one of
            // this submission's earlier commands of its kind (1..=N).
            let none = uapi::DRM_ASAHI_BARRIER_NONE as u16;
            let (on_rd, on_cl) = (header.vdm_barrier != none, header.cdm_barrier != none);
            if (on_rd && header.vdm_barrier as usize > n_rd)
                || (on_cl && header.cdm_barrier as usize > n_cl)
            {
                cls_pr_debug!(
                    Errors,
                    "G15 submit: invalid barriers {} {}\n",
                    header.vdm_barrier,
                    header.cdm_barrier
                );
                return Err(EINVAL);
            }
            match u32::from(header.cmd_type) {
                uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_COMPUTE => {
                    let c: uapi::drm_asahi_cmd_compute = cmdbuf.read_up_to(size)?;
                    let mut keep = KVec::new();
                    let t = Self::g15_timestamps(objects, &c.ts, &mut keep)?;
                    cmds.push(Cmd::Cl(c, t, on_rd), GFP_KERNEL)?;
                    ts.push(keep, GFP_KERNEL)?;
                    n_cl += 1;
                }
                uapi::drm_asahi_cmd_type_DRM_ASAHI_CMD_RENDER => {
                    let rsize = core::mem::size_of::<uapi::drm_asahi_cmd_render>();
                    let gsize = core::mem::size_of::<uapi::drm_asahi_cmd_render_g15>();
                    if size < rsize + gsize {
                        cls_pr_debug!(
                            Errors,
                            "G15 submit: a render command without its G15 part ({} B)\n",
                            size
                        );
                        return Err(EINVAL);
                    }
                    let r: uapi::drm_asahi_cmd_render = cmdbuf.read()?;
                    let g: uapi::drm_asahi_cmd_render_g15 = cmdbuf.read()?;
                    cmdbuf.skip(size - rsize - gsize);
                    let mut cmd = Self::g15_render_cmd(&r, &g)?;
                    let mut keep = KVec::new();
                    cmd.ts_ta = Self::g15_timestamps(objects, &r.ts_vtx, &mut keep)?;
                    cmd.ts_3d = Self::g15_timestamps(objects, &r.ts_frag, &mut keep)?;
                    cmds.push(Cmd::Rd(KBox::new(cmd, GFP_KERNEL)?, on_cl), GFP_KERNEL)?;
                    ts.push(keep, GFP_KERNEL)?;
                    n_rd += 1;
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
        if cmds.is_empty() || cmds.len() > MAX_COMMANDS_PER_SUBMISSION as usize {
            cls_pr_debug!(
                Errors,
                "G15 submit: {} compute and {} render commands\n",
                n_cl,
                n_rd
            );
            return Err(EINVAL);
        }

        let op_guard = if in_sync_count > 0 {
            Some(gpu.start_op()?)
        } else {
            None
        };
        let vm_bind = gpu.bind_vm(&self.vm)?;
        let ctx = vm_bind.slot();
        if n_cl > 0 && self.g15_chan.is_none() {
            self.g15_chan = Some(gpu.g15_cl_channel_get()?);
        }
        if n_rd > 0 && self.g15_rd.is_none() {
            let q = gpu.g15_rd_queue_new(&self.inner.ualloc)?;
            self.g15_rd = Some(Arc::pin_init(new_mutex!(q, "g15_rd_queue"), GFP_KERNEL)?);
        }

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
        let mut steps = KVec::new();
        for (c, ts) in cmds.iter().zip(ts) {
            let step = match c {
                Cmd::Cl(c, t, after) => {
                    let chan = self.g15_chan.as_ref().ok_or(EIO)?;
                    let cdm = Some(c.cdm_ctrl_stream_base);
                    let job = gpu.g15_cl_job_new(&chan.lock(), cdm, ctx, &[], *t)?;
                    G15Step::Cl {
                        job,
                        after: *after,
                        ts,
                    }
                }
                Cmd::Rd(cmd, after) => G15Step::Rd {
                    cmd: **cmd,
                    rt: gpu.g15_rt_new(
                        &cmd.geom,
                        self.g15_rd.as_ref().ok_or(EIO)?.lock().rt_cache(),
                    )?,
                    after: *after,
                    ts,
                },
            };
            steps.push(Some(step), GFP_KERNEL)?;
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
                g15_chan: self.g15_chan.clone(),
                g15_rd: self.g15_rd.clone(),
                g15_held: Some(self.g15_held.clone()),
                g15_steps: steps,
            },
        )?;
        for sync in syncs.drain(0..in_sync_count) {
            if let Some(fence) = sync.fence {
                job.add_dependency(fence)?;
            }
        }
        let mut job = job.arm();
        let out_fence = job.fences().finished();
        self.inflight
            .retain(|f| !matches!(f.wait_timeout(false, 0), Ok(1..)));
        self.inflight.push(out_fence.clone(), GFP_KERNEL)?;
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
