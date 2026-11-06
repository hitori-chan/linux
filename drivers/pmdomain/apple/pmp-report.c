// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple SoC PMP power state reporting driver
 *
 * Copyright The Asahi Linux Contributors
 */

#include <linux/bitfield.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/sched/topology.h>
#include <linux/slab.h>
#include <asm/sysreg.h>

#define PMP_REPORT_READY 0x1
#define PMP_REPORT_ONLINE_TIMEOUT_US (60 * USEC_PER_SEC)

#define PMP_DVFS_VALID BIT_ULL(61)
#define PMP_DVFS_DCS GENMASK_ULL(51, 48)
#define PMP_DVFS_FAB GENMASK_ULL(35, 32)
#define PMP_DVFS_OWN GENMASK_ULL(4, 0)

struct apple_pmp_report_offsets {
	u32 tgt_read;
	u32 tgt_write;
	u32 actual;
	u32 status;
	/*
	 * The kernel boots the PMP itself (t6034): a request made before it
	 * is online waits for it, except the always-on ones, which must be
	 * in place before it starts.
	 */
	bool wait_online;
	/* SOC-DEV-DVFS's write map: a device's DCS and fabric level floor */
	u32 dvfs_write;
};

struct apple_pmp_report {
	struct device *dev;
	const struct apple_pmp_report_offsets *offsets;
	void __iomem *base;
	spinlock_t lock;
	struct apple_pmp_floor *floor;
};

/*
 * The CPU's DRAM and fabric floor (SOC-DEV-DVFS PACC0 and PACC1): macOS's
 * CLPC raises the P clusters' DCS and fabric floors for their work, and the
 * PMP applies a cluster's floor only while the cluster is up, so a floor
 * left up costs little at idle. The PMP takes the P clusters' floors only
 * with their power requests (macOS's restoreACC), which their always-on
 * report entries give. With the PMGR's keepalive a P core's lone DRAM miss
 * takes 105 ns at the top levels against 290. Under a load the top levels
 * cost about 1.5 W, and DCS 3 with FAB 1 about 0.5 W for 95 % of the top's
 * bandwidth and xz faster for less energy than no floor, so the floor
 * climbs a ladder. The stall policy
 * reads, on each P core busy for PMP_FLOOR_BUSY_PCT of a period, the
 * memory-stall counters CLPC reads (the first three of the always-on six,
 * configured as CLPC's configure<0u>(true) does): the first level when the
 * three stalled for PMP_FLOOR_STALL_PCT of its cycles, the top one when the
 * third did for PMP_FLOOR_DRAM_PCT, DRAM's latency (a pointer chase counts
 * 94 % of its cycles in the third, a dict walk 41 %, a stream 15 %; xz 6 % in
 * the third and 18 % in all three; a spin none), or the first for
 * PMP_FLOOR_QUEUE_PCT, the bandwidth (ten readers 55-62 % at every level, one
 * reader 1-5 %, xz -T8 4-5 %). The load policy takes the top level for
 * any busy P core. A level comes down after PMP_FLOOR_HOLD periods that ask
 * for less. The E cores move the E cluster's floor (EACC0) the same way,
 * from their own counters, when the DT names it, up to floor_e's level: with
 * the keepalive an E core's lone DRAM miss takes 363 ns without a floor
 * (macOS 392), 152 at the first level and 116 at the top, and xz on an E core
 * runs 15 % faster for the same energy at the first, 20 % faster for 25 % more
 * energy at the top. An E core counts only when busy for PMP_FLOOR_E_BUSY_PCT of
 * a period (floor_e_busy): a real-time video decode, in bursts on the E cores,
 * held the floor up 70 % of the time at 50 % for no speed, and 1 % at 90 %,
 * where xz and a reader keep it all their run.
 *
 * The clpc policy is CLPC's own (NormalThreadGroup::runController and
 * updateStallControllers): for each side, a PI controller on the first and
 * third counters' share of the cycles picks the DCS level, one on the first
 * and second's the fabric's, with CLPC's defaults, which this Mac's ADT
 * leaves. The error is the largest of the cores' shares less the target,
 * and the integral moves by the error times a gain for each 10 ms, its
 * up-gain or its down-gain by the error's sign, between 0 and 1. A level is
 * the highest whose threshold the integral reaches, the thresholds being
 * the midpoints between the domain's rates. CLPC weights a thread group's
 * share by its energy per instruction, which Linux does not know; here a
 * core's is weighted by its busy share of the period, from the cores busy
 * for PMP_FLOOR_CLPC_BUSY_PCT of it.
 */
#define PMP_FLOOR_PERIOD_MS 20
#define PMP_FLOOR_HOLD 5
#define PMP_FLOOR_BUSY_PCT 50
#define PMP_FLOOR_E_BUSY_PCT 90
#define PMP_FLOOR_STALL_PCT 10
#define PMP_FLOOR_DRAM_PCT 25
#define PMP_FLOOR_QUEUE_PCT 40
#define PMP_FLOOR_CLPC_BUSY_PCT 10
#define PMP_FLOOR_MAX_DEVS 3
#define PMP_FLOOR_MAX_LEVELS 2

#define AON_CPU_MSTALL_CTL0 sys_reg(3, 1, 15, 0, 3)
#define AON_CPU_MSTALL_CTL1 sys_reg(3, 1, 15, 1, 3)
#define AON_CPU_MSTALL_CTL2 sys_reg(3, 1, 15, 2, 3)
#define AON_CPU_MSTALL_CTR(n) sys_reg(3, 1, 15, 8 + (n), 3)

enum { FLOOR_OFF, FLOOR_LOAD, FLOOR_STALL, FLOOR_ALWAYS, FLOOR_CLPC };
static const char *const apple_pmp_floor_names[] = { "off", "load", "stall", "always", "clpc" };
static int floor_policy = FLOOR_STALL;
static unsigned int floor_e = 1;
static unsigned int floor_e_busy = PMP_FLOOR_E_BUSY_PCT;
static unsigned int floor_stall = PMP_FLOOR_STALL_PCT;
static unsigned int floor_dram = PMP_FLOOR_DRAM_PCT;
static unsigned int floor_queue = PMP_FLOOR_QUEUE_PCT;

struct apple_pmp_mstall {
	u64 all;	/* counters 0-2 */
	u64 queue;	/* counter 0 */
	u64 dram;	/* counter 2 */
};

/* the P clusters' floors, moved by the P cores, and the E cluster's, by the E cores */
enum { FLOOR_P, FLOOR_E, FLOOR_SIDES };

/* the clpc policy's controllers: DCS from counters 0 and 2, the fabric from 0 and 1 */
enum { CLPC_DCS, CLPC_FAB, CLPC_NCTL };

/*
 * CLPC's defaults, in 16.16 as its tunables are: {mem,soc}-cpu-stall-ratio-
 * {target,ki-up,ki-down}-{p,e} (kp none)
 */
static const struct {
	u32 target, ki_up, ki_down;
} apple_pmp_clpc_pi[FLOOR_SIDES][CLPC_NCTL] = {
	[FLOOR_P] = { { 0x148, 0x320000, 0xa0000 }, { 0x148, 0x320000, 0xa0000 } },
	[FLOOR_E] = { { 0x4ccd, 0x8000, 0xa0000 }, { 0x4ccd, 0xa0000, 0x320000 } },
};

/* the domains' rates, as CLPC::init sets them */
static const u16 apple_pmp_clpc_dcs_rate[] = { 767, 1533, 2133, 2733, 3200 };
static const u16 apple_pmp_clpc_fab_rate[] = { 534, 800, 1068 };

struct apple_pmp_floor_side {
	u32 dev[PMP_FLOOR_MAX_DEVS];
	unsigned int ndev, level, quiet;
	u64 cur;		/* the value written */
	u64 m[CLPC_NCTL];	/* the period's largest weighted share, 2^-24 */
	s64 x[CLPC_NCTL];	/* the integral, 0 to 2^24 */
};

struct apple_pmp_floor {
	struct apple_pmp_report *rep;
	struct delayed_work poll;	/* deferrable: no wakeups while the floor is down */
	struct delayed_work drop;	/* not deferrable: the floor comes down in an idle system */
	struct mutex lock;
	u64 val[PMP_FLOOR_MAX_LEVELS + 1];	/* [0]: no floor */
	u8 dcs[PMP_FLOOR_MAX_LEVELS + 1], fab[PMP_FLOOR_MAX_LEVELS + 1];
	u64 last_ns;
	struct apple_pmp_floor_side side[FLOOR_SIDES];
	unsigned int nlevel;
	bool online;
	bool suspended;
	u64 *idle, *wall;
	struct apple_pmp_mstall *stall;
	int cpuhp;
};

static struct apple_pmp_floor *apple_pmp_floor;

static void apple_pmp_floor_write(struct apple_pmp_floor *fl, int s, u64 val)
{
	struct apple_pmp_floor_side *sd = &fl->side[s];
	unsigned int i;

	if (sd->cur == val)
		return;
	sd->cur = val;
	for (i = 0; i < sd->ndev; i++)
		writeq(val, fl->rep->base + fl->rep->offsets->dvfs_write + 8 * sd->dev[i]);
}

static void apple_pmp_floor_set(struct apple_pmp_floor *fl, int s, unsigned int level)
{
	if (s == FLOOR_E)
		level = min(level, floor_e);
	fl->side[s].level = level;
	apple_pmp_floor_write(fl, s, fl->val[level]);
}

static void apple_pmp_floor_set_all(struct apple_pmp_floor *fl, unsigned int level)
{
	int s;

	for (s = 0; s < FLOOR_SIDES; s++) {
		memset(fl->side[s].x, 0, sizeof(fl->side[s].x));
		apple_pmp_floor_set(fl, s, level);
	}
}

/* the highest level whose threshold V (2^-24) reaches: the midpoints between the N rates R */
static unsigned int apple_pmp_clpc_level(const u16 *r, unsigned int n, s64 v)
{
	/* twice the scale's ends: half a step below the first rate, above the last */
	s64 lo = max(2 * r[0] - (r[1] - r[0]), 0), span = 2 * r[n - 1] + (r[n - 1] - r[n - 2]) - lo;
	unsigned int i;

	for (i = 1; i < n; i++)
		if (v * span < ((s64)r[i - 1] + r[i] - lo) << 24)
			break;
	return i - 1;
}

/* one side's controllers over DT_US of elapsed time, and the floor they ask for */
static void apple_pmp_clpc_step(struct apple_pmp_floor *fl, int s, u64 dt_us)
{
	struct apple_pmp_floor_side *sd = &fl->side[s];
	unsigned int top = s == FLOOR_E ? min(floor_e, fl->nlevel) : fl->nlevel, dcs, fab;
	int c;

	for (c = 0; c < CLPC_NCTL; c++) {
		s64 err = (s64)sd->m[c] - ((s64)apple_pmp_clpc_pi[s][c].target << 8);
		u32 ki = err > 0 ? apple_pmp_clpc_pi[s][c].ki_up : apple_pmp_clpc_pi[s][c].ki_down;

		/* a gain is per 10 ms, as CLPC's setGainProperty makes it */
		sd->x[c] = clamp(sd->x[c] + div_s64((err * ki >> 16) * (s64)dt_us, 10 * USEC_PER_MSEC),
				 0LL, 1LL << 24);
	}
	dcs = min_t(unsigned int, fl->dcs[top],
		    apple_pmp_clpc_level(apple_pmp_clpc_dcs_rate, ARRAY_SIZE(apple_pmp_clpc_dcs_rate),
					 sd->x[CLPC_DCS]));
	fab = min_t(unsigned int, fl->fab[top],
		    apple_pmp_clpc_level(apple_pmp_clpc_fab_rate, ARRAY_SIZE(apple_pmp_clpc_fab_rate),
					 sd->x[CLPC_FAB]));
	apple_pmp_floor_write(fl, s, dcs || fab ? PMP_DVFS_VALID | FIELD_PREP(PMP_DVFS_DCS, dcs) |
					      FIELD_PREP(PMP_DVFS_FAB, fab) : 0);
}

/* configure<0u>(true), in its order: the enables, then each selector's half */
static int apple_pmp_mstall_on(unsigned int cpu)
{
	sysreg_clear_set_s(AON_CPU_MSTALL_CTL0, GENMASK_ULL(31, 0), 3);
	sysreg_clear_set_s(AON_CPU_MSTALL_CTL0, GENMASK_ULL(63, 32), 0xC7847ULL << 32);
	sysreg_clear_set_s(AON_CPU_MSTALL_CTL1, GENMASK_ULL(31, 0), 0xC7841);
	sysreg_clear_set_s(AON_CPU_MSTALL_CTL1, GENMASK_ULL(63, 32), 0x805ULL << 32);
	sysreg_clear_set_s(AON_CPU_MSTALL_CTL2, GENMASK_ULL(31, 0), 0x80D);
	sysreg_clear_set_s(AON_CPU_MSTALL_CTL2, GENMASK_ULL(63, 32), 0x815ULL << 32);
	isb();
	return 0;
}

static void apple_pmp_mstall_read(void *info)
{
	struct apple_pmp_mstall *st = info;

	st->queue = read_sysreg_s(AON_CPU_MSTALL_CTR(0)) & GENMASK_ULL(47, 0);
	st->dram = read_sysreg_s(AON_CPU_MSTALL_CTR(2)) & GENMASK_ULL(47, 0);
	st->all = st->queue + (read_sysreg_s(AON_CPU_MSTALL_CTR(1)) & GENMASK_ULL(47, 0)) +
		  st->dram;
}

/* the level each side's cores ask for: 0 none, 1 to fl->nlevel */
static void apple_pmp_floor_want(struct apple_pmp_floor *fl, unsigned int *want)
{
	unsigned int busy;
	int cpu, s;

	for (s = 0; s < FLOOR_SIDES; s++) {
		want[s] = 0;
		memset(fl->side[s].m, 0, sizeof(fl->side[s].m));
	}
	for_each_possible_cpu(cpu) {
		u64 wall, idle = get_cpu_idle_time(cpu, &wall, 0);
		u64 dw = wall - fl->wall[cpu], di = idle - fl->idle[cpu], cycles, da, dq, dd;
		struct apple_pmp_mstall st, *prev = &fl->stall[cpu];

		s = arch_scale_cpu_capacity(cpu) == SCHED_CAPACITY_SCALE ? FLOOR_P : FLOOR_E;
		if (floor_policy == FLOOR_CLPC)
			busy = PMP_FLOOR_CLPC_BUSY_PCT;
		else
			busy = s == FLOOR_E ? floor_e_busy : PMP_FLOOR_BUSY_PCT;
		fl->idle[cpu] = idle;
		fl->wall[cpu] = wall;
		if (!cpu_online(cpu) || !fl->side[s].ndev ||
		    !dw || dw <= di || (dw - di) * 100 < dw * busy) {
			/* the next busy period's count starts over */
			prev->all = U64_MAX;
			continue;
		}
		if (floor_policy != FLOOR_STALL && floor_policy != FLOOR_CLPC) {
			want[s] = fl->nlevel;
			continue;
		}
		/* the core is busy, so awake: its own counters, read on it */
		if (smp_call_function_single(cpu, apple_pmp_mstall_read, &st, 1))
			continue;
		cycles = (dw - di) * cpufreq_quick_get(cpu) / USEC_PER_MSEC;
		da = st.all - prev->all;
		dq = st.queue - prev->queue;
		dd = st.dram - prev->dram;
		/* sums of 48-bit counters: a wrap reads as a negative count */
		if (floor_policy == FLOOR_CLPC) {
			if (prev->all != U64_MAX && (s64)da > 0 && (s64)dq >= 0 && (s64)dd >= 0 &&
			    da >= dd && cycles) {
				struct apple_pmp_floor_side *sd = &fl->side[s];
				u64 n[CLPC_NCTL] = { [CLPC_DCS] = dq + dd, [CLPC_FAB] = da - dd };
				int c;

				for (c = 0; c < CLPC_NCTL; c++)
					sd->m[c] = max(sd->m[c], mul_u64_u64_div_u64(
						mul_u64_u64_div_u64(n[c], 1ULL << 24, cycles), dw - di, dw));
			}
		} else if (prev->all != U64_MAX && (s64)da > 0 && (s64)dq >= 0 && (s64)dd >= 0) {
			if (dd * 100 >= cycles * READ_ONCE(floor_dram) ||
			    dq * 100 >= cycles * READ_ONCE(floor_queue))
				want[s] = fl->nlevel;
			else if (da * 100 >= cycles * READ_ONCE(floor_stall))
				want[s] = max(want[s], 1U);
		}
		*prev = st;
	}
}

static void apple_pmp_floor_run(struct apple_pmp_floor *fl)
{
	struct apple_pmp_report *rep = fl->rep;
	unsigned long period = msecs_to_jiffies(PMP_FLOOR_PERIOD_MS);
	unsigned int want[FLOOR_SIDES];
	bool up = false;
	u64 now, dt;
	int s;

	mutex_lock(&fl->lock);
	if (fl->suspended)
		goto out;
	if (!fl->online) {
		if (!(readq(rep->base + rep->offsets->status) & PMP_REPORT_READY)) {
			schedule_delayed_work(&fl->poll, msecs_to_jiffies(100));
			goto out;
		}
		fl->online = true;
	}

	apple_pmp_floor_want(fl, want);
	now = ktime_get_ns();
	dt = min(now - fl->last_ns, (u64)NSEC_PER_SEC);
	fl->last_ns = now;
	if (floor_policy == FLOOR_OFF || floor_policy == FLOOR_ALWAYS) {
		apple_pmp_floor_set_all(fl, floor_policy == FLOOR_ALWAYS ? fl->nlevel : 0);
		goto out;	/* polled again only when the policy changes */
	}
	if (floor_policy == FLOOR_CLPC) {
		for (s = 0; s < FLOOR_SIDES; s++) {
			apple_pmp_clpc_step(fl, s, div_u64(dt, NSEC_PER_USEC));
			fl->side[s].level = 0;
			fl->side[s].quiet = 0;
			up |= fl->side[s].cur != 0;
		}
		schedule_delayed_work(up ? &fl->drop : &fl->poll, period);
		goto out;
	}
	for (s = 0; s < FLOOR_SIDES; s++) {
		struct apple_pmp_floor_side *sd = &fl->side[s];

		if (want[s] >= sd->level || ++sd->quiet >= PMP_FLOOR_HOLD) {
			sd->quiet = 0;
			apple_pmp_floor_set(fl, s, want[s]);
		}
		up |= sd->level;
	}
	schedule_delayed_work(up ? &fl->drop : &fl->poll, period);
out:
	mutex_unlock(&fl->lock);
}

static void apple_pmp_floor_poll(struct work_struct *work)
{
	apple_pmp_floor_run(container_of(to_delayed_work(work), struct apple_pmp_floor, poll));
}

static void apple_pmp_floor_drop(struct work_struct *work)
{
	apple_pmp_floor_run(container_of(to_delayed_work(work), struct apple_pmp_floor, drop));
}

static void apple_pmp_floor_kick(struct apple_pmp_floor *fl)
{
	cancel_delayed_work_sync(&fl->poll);
	cancel_delayed_work_sync(&fl->drop);
	schedule_delayed_work(&fl->poll, 0);
}

static int apple_pmp_floor_param_set(const char *val, const struct kernel_param *kp)
{
	int i = sysfs_match_string(apple_pmp_floor_names, val);

	if (i < 0)
		return i;
	floor_policy = i;
	if (apple_pmp_floor)
		apple_pmp_floor_kick(apple_pmp_floor);
	return 0;
}

static int apple_pmp_floor_param_get(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%s\n", apple_pmp_floor_names[floor_policy]);
}

static const struct kernel_param_ops apple_pmp_floor_param_ops = {
	.set = apple_pmp_floor_param_set,
	.get = apple_pmp_floor_param_get,
};
module_param_cb(floor, &apple_pmp_floor_param_ops, NULL, 0644);
MODULE_PARM_DESC(floor, "the CPU's DRAM and fabric floor: off, load (the top level for the P cores' busy time), stall (a level by their memory stalls), always (the top), clpc (macOS's controllers on the stalls)");

static int apple_pmp_floor_e_set(const char *val, const struct kernel_param *kp)
{
	unsigned int n;
	int ret = kstrtouint(val, 0, &n);

	if (ret)
		return ret;
	if (n > PMP_FLOOR_MAX_LEVELS)
		return -EINVAL;
	floor_e = n;
	if (apple_pmp_floor)
		apple_pmp_floor_kick(apple_pmp_floor);
	return 0;
}

static const struct kernel_param_ops apple_pmp_floor_e_ops = {
	.set = apple_pmp_floor_e_set,
	.get = param_get_uint,
};
module_param_cb(floor_e, &apple_pmp_floor_e_ops, &floor_e, 0644);
MODULE_PARM_DESC(floor_e, "the E cluster's highest floor level, 0 for none");
module_param(floor_e_busy, uint, 0644);
MODULE_PARM_DESC(floor_e_busy, "the share of a period, in percent, an E core is busy before its stalls count");
module_param(floor_stall, uint, 0644);
MODULE_PARM_DESC(floor_stall, "the stall policy's first level: the share of a busy core's cycles, in percent, its first three stall counters reach");
module_param(floor_dram, uint, 0644);
MODULE_PARM_DESC(floor_dram, "the stall policy's top level: the share, in percent, its third counter (DRAM's latency) reaches");
module_param(floor_queue, uint, 0644);
MODULE_PARM_DESC(floor_queue, "the stall policy's top level: the share, in percent, its first counter (the bandwidth) reaches");

static void apple_pmp_floor_remove(void *data)
{
	struct apple_pmp_floor *fl = data;

	apple_pmp_floor = NULL;
	cancel_delayed_work_sync(&fl->poll);
	cancel_delayed_work_sync(&fl->drop);
	apple_pmp_floor_set_all(fl, 0);
	if (fl->cpuhp > 0)
		cpuhp_remove_state(fl->cpuhp);
}

static int apple_pmp_floor_init(struct apple_pmp_report *rep)
{
	struct device *dev = rep->dev;
	static const char *const prop[FLOOR_SIDES] = {
		"apple,dvfs-floor-devices", "apple,dvfs-floor-e-devices",
	};
	struct apple_pmp_floor *fl;
	u32 lv[2 * PMP_FLOOR_MAX_LEVELS];
	int ret, n, i, s;

	if (!of_property_present(dev->of_node, prop[FLOOR_P]))
		return 0;
	if (!rep->offsets->dvfs_write)
		return -EINVAL;
	fl = devm_kzalloc(dev, sizeof(*fl), GFP_KERNEL);
	if (!fl)
		return -ENOMEM;
	for (s = 0; s < FLOOR_SIDES; s++) {
		struct apple_pmp_floor_side *sd = &fl->side[s];

		n = of_property_count_u32_elems(dev->of_node, prop[s]);
		if (n == -EINVAL)
			continue;
		if (n < 1 || n > PMP_FLOOR_MAX_DEVS)
			return -EINVAL;
		sd->ndev = n;
		ret = of_property_read_u32_array(dev->of_node, prop[s], sd->dev, n);
		if (ret)
			return ret;
		for (i = 0; i < n; i++)
			if (sd->dev[i] > 2)
				return -EINVAL;
	}

	/* (DCS, FAB) pairs, the lowest first */
	n = of_property_count_u32_elems(dev->of_node, "apple,dvfs-floor-levels");
	if (n < 2 || n > ARRAY_SIZE(lv) || n % 2)
		return -EINVAL;
	ret = of_property_read_u32_array(dev->of_node, "apple,dvfs-floor-levels", lv, n);
	if (ret)
		return ret;
	fl->nlevel = n / 2;
	for (i = 0; i < fl->nlevel; i++) {
		if (lv[2 * i] > 4 || lv[2 * i + 1] > 2)
			return -EINVAL;
		fl->val[i + 1] = PMP_DVFS_VALID | FIELD_PREP(PMP_DVFS_DCS, lv[2 * i]) |
				 FIELD_PREP(PMP_DVFS_FAB, lv[2 * i + 1]);
		fl->dcs[i + 1] = lv[2 * i];
		fl->fab[i + 1] = lv[2 * i + 1];
	}

	fl->idle = devm_kcalloc(dev, nr_cpu_ids, sizeof(*fl->idle), GFP_KERNEL);
	fl->wall = devm_kcalloc(dev, nr_cpu_ids, sizeof(*fl->wall), GFP_KERNEL);
	fl->stall = devm_kcalloc(dev, nr_cpu_ids, sizeof(*fl->stall), GFP_KERNEL);
	if (!fl->idle || !fl->wall || !fl->stall)
		return -ENOMEM;
	fl->rep = rep;
	mutex_init(&fl->lock);
	INIT_DEFERRABLE_WORK(&fl->poll, apple_pmp_floor_poll);
	INIT_DELAYED_WORK(&fl->drop, apple_pmp_floor_drop);

	/* each CPU's stall counters, as each comes online */
	fl->cpuhp = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "pmp_report:mstall",
				      apple_pmp_mstall_on, NULL);

	rep->floor = fl;
	ret = devm_add_action_or_reset(dev, apple_pmp_floor_remove, fl);
	if (ret)
		return ret;
	apple_pmp_floor = fl;
	schedule_delayed_work(&fl->poll, 0);
	return 0;
}

static int apple_pmp_report_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct apple_pmp_report *rep;
	int ret;

	rep = devm_kzalloc(dev, sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	spin_lock_init(&rep->lock);
	rep->dev = dev;
	rep->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(rep->base))
		return PTR_ERR(rep->base);
	rep->offsets = of_device_get_match_data(dev);
	dev_set_drvdata(dev, rep);
	/* The floor is a performance setting: without it the domains still work. */
	ret = apple_pmp_floor_init(rep);
	if (ret)
		dev_warn(dev, "no DVFS floor: %d\n", ret);
	ret = of_platform_populate(np, NULL, NULL, dev);
	if (ret)
		return dev_err_probe(dev, ret, "failed to create child devices\n");

	return 0;
}

static const struct apple_pmp_report_offsets apple_pmp_offsets_t600x = {
	.tgt_read = 0xf80,
	.tgt_write = 0x107c0,
	.actual = 0x1000,
	.status = 0x10,
};

static const struct apple_pmp_report_offsets apple_pmp_offsets_t602x = {
	.tgt_read = 0x2000,
	.tgt_write = 0x11000,
	.actual = 0x2080,
	.status = 0x10,
};

static const struct apple_pmp_report_offsets apple_pmp_offsets_t6030 = {
	.tgt_read = 0x1180,
	.tgt_write = 0x108c0,
	.actual = 0x11c0,
	.status = 0x10,
};

/* t6031/t6034 keep the t602x offsets; the kernel boots their PMP itself. */
static const struct apple_pmp_report_offsets apple_pmp_offsets_t6031 = {
	.tgt_read = 0x2000,
	.tgt_write = 0x11000,
	.actual = 0x2080,
	.status = 0x10,
	.wait_online = true,
	.dvfs_write = 0x11080,
};

static const struct apple_pmp_report_offsets apple_pmp_offsets_t8112 = {
	.tgt_read = 0xa00,
	.tgt_write = 0x10500,
	.actual = 0xa40,
	.status = 0x10,
};

static const struct apple_pmp_report_offsets apple_pmp_offsets_t8122 = {
	.tgt_read = 0x1000,
	.tgt_write = 0x10800,
	.actual = 0x1080,
	.status = 0x10,
};

static const struct of_device_id apple_pmp_report_of_match[] = {
	{ .compatible = "apple,t6000-pmp-v2-report", .data = &apple_pmp_offsets_t600x },
	{ .compatible = "apple,t6020-pmp-v2-report", .data = &apple_pmp_offsets_t602x },
	{ .compatible = "apple,t6030-pmp-v2-report", .data = &apple_pmp_offsets_t6030 },
	{ .compatible = "apple,t6031-pmp-v2-report", .data = &apple_pmp_offsets_t6031 },
	{ .compatible = "apple,t8112-pmp-v2-report", .data = &apple_pmp_offsets_t8112 },
	{ .compatible = "apple,t8122-pmp-v2-report", .data = &apple_pmp_offsets_t8122 },
	{}
};

/* Through system sleep the floor is down, as CLPC's is. */
static int apple_pmp_report_suspend(struct device *dev)
{
	struct apple_pmp_floor *fl = ((struct apple_pmp_report *)dev_get_drvdata(dev))->floor;

	if (fl) {
		mutex_lock(&fl->lock);
		fl->suspended = true;
		apple_pmp_floor_set_all(fl, 0);
		mutex_unlock(&fl->lock);
		cancel_delayed_work_sync(&fl->poll);
		cancel_delayed_work_sync(&fl->drop);
	}
	return 0;
}

static int apple_pmp_report_resume(struct device *dev)
{
	struct apple_pmp_floor *fl = ((struct apple_pmp_report *)dev_get_drvdata(dev))->floor;

	if (fl) {
		mutex_lock(&fl->lock);
		fl->suspended = false;
		mutex_unlock(&fl->lock);
		schedule_delayed_work(&fl->poll, 0);
	}
	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(apple_pmp_report_pm_ops, apple_pmp_report_suspend,
				apple_pmp_report_resume);

static struct platform_driver apple_pmp_report_driver = {
	.probe = apple_pmp_report_probe,
	.driver = {
		.name = "apple-pmp-report",
		.of_match_table = apple_pmp_report_of_match,
		.pm = pm_sleep_ptr(&apple_pmp_report_pm_ops),
	},
};

#define PMP_ENTRY_MAX_STATES 4

/*
 * A media block's entry may vote for its domains' levels, as macOS's virtual
 * power gates (VENC0-FAST, -SOC-VMAX, -FAB-VMAX...) do: its SOC-DEV-DVFS slot
 * takes the word of the block's performance state, the block's own domain in
 * bits 4:0 and its first other (the fabric) in bits 35:32, while the PS-REQ
 * bit is set. The PMP takes the vote only with the request.
 */
struct apple_pmp_report_entry {
	struct device *dev;
	struct generic_pm_domain genpd;
	u32 id;
	bool always_on;
	bool on;
	u32 dvfs_idx;
	unsigned int nstate;
	unsigned int pstate;
	u64 dvfs_word[PMP_ENTRY_MAX_STATES + 1];	/* [0]: no vote */
};

#define genpd_to_apple_pmp_report_entry(_genpd) \
	container_of(_genpd, struct apple_pmp_report_entry, genpd)

static int apple_pmp_report_set_state(struct generic_pm_domain *genpd, bool enable)
{
	struct apple_pmp_report_entry *ent = genpd_to_apple_pmp_report_entry(genpd);
	struct apple_pmp_report *rep = dev_get_drvdata(ent->dev->parent);
	u64 bit_val = BIT_ULL(ent->id);
	u64 val;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&rep->lock, flags);
	val = readq(rep->base + rep->offsets->tgt_read);
	val &= ~bit_val;
	if (enable)
		val |= bit_val;
	writeq(val, rep->base + rep->offsets->tgt_write);
	spin_unlock_irqrestore(&rep->lock, flags);
	val = readq(rep->base + rep->offsets->status);
	if ((val & PMP_REPORT_READY) == 0) {
		if (!rep->offsets->wait_online || !enable || ent->always_on)
			return 0;
		dev_info(ent->dev, "waiting for the PMP to come online\n");
		ret = readq_poll_timeout(rep->base + rep->offsets->status, val,
					 val & PMP_REPORT_READY, 10000,
					 PMP_REPORT_ONLINE_TIMEOUT_US);
		if (ret) {
			dev_err(ent->dev, "the PMP did not come online\n");
			return ret;
		}
	}
	return readq_poll_timeout_atomic(
		rep->base + rep->offsets->actual,
		val,
		!!(val & bit_val) == !!enable,
		100,
		50000);
}

static void apple_pmp_report_entry_vote(struct apple_pmp_report_entry *ent, u64 word)
{
	struct apple_pmp_report *rep = dev_get_drvdata(ent->dev->parent);

	writeq(word, rep->base + rep->offsets->dvfs_write + 8 * ent->dvfs_idx);
}

/*
 * genpd sets a device's state before the domain's power-on and drops it after
 * the power-off; the vote waits for the request and goes before it, as macOS
 * orders them (AVE_DPM_PowerOn, AVE_DPM_PowerOff).
 */
static int apple_pmp_report_entry_set_performance_state(struct generic_pm_domain *genpd,
							 unsigned int state)
{
	struct apple_pmp_report_entry *ent = genpd_to_apple_pmp_report_entry(genpd);

	if (state > ent->nstate)
		return -EINVAL;
	if (ent->on && state != ent->pstate)
		apple_pmp_report_entry_vote(ent, ent->dvfs_word[state]);
	ent->pstate = state;
	return 0;
}

static int apple_pmp_report_entry_power_on(struct generic_pm_domain *genpd)
{
	struct apple_pmp_report_entry *ent = genpd_to_apple_pmp_report_entry(genpd);
	int ret;

	ret = apple_pmp_report_set_state(genpd, true);
	if (ret)
		return ret;
	ent->on = true;
	if (ent->pstate)
		apple_pmp_report_entry_vote(ent, ent->dvfs_word[ent->pstate]);
	return 0;
}

static int apple_pmp_report_entry_power_off(struct generic_pm_domain *genpd)
{
	struct apple_pmp_report_entry *ent = genpd_to_apple_pmp_report_entry(genpd);

	if (ent->on && ent->pstate)
		apple_pmp_report_entry_vote(ent, 0);
	ent->on = false;
	return apple_pmp_report_set_state(genpd, false);
}

/* apple,dvfs-index: the SOC-DEV-DVFS slot less 0x210; apple,dvfs-levels: (own, other) pairs for states 1 and up */
static int apple_pmp_report_entry_dvfs(struct apple_pmp_report_entry *ent)
{
	struct device_node *node = ent->dev->of_node;
	struct apple_pmp_report *rep = dev_get_drvdata(ent->dev->parent);
	u32 lv[2 * PMP_ENTRY_MAX_STATES];
	unsigned int i;
	int n, ret;

	if (!of_property_present(node, "apple,dvfs-index"))
		return 0;
	if (!rep->offsets->dvfs_write)
		return -EINVAL;
	ret = of_property_read_u32(node, "apple,dvfs-index", &ent->dvfs_idx);
	if (ret)
		return ret;
	if (ent->dvfs_idx < 3 || ent->dvfs_idx >= 0x30)
		return -EINVAL;
	n = of_property_count_u32_elems(node, "apple,dvfs-levels");
	if (n < 2 || n > ARRAY_SIZE(lv) || n % 2)
		return -EINVAL;
	ret = of_property_read_u32_array(node, "apple,dvfs-levels", lv, n);
	if (ret)
		return ret;
	ent->nstate = n / 2;
	for (i = 0; i < ent->nstate; i++) {
		/* the dvfs-domain table's three levels each */
		if (lv[2 * i] > 2 || lv[2 * i + 1] > 2)
			return -EINVAL;
		ent->dvfs_word[i + 1] = PMP_DVFS_VALID | FIELD_PREP(PMP_DVFS_FAB, lv[2 * i + 1]) |
					FIELD_PREP(PMP_DVFS_OWN, lv[2 * i]);
	}
	ent->genpd.set_performance_state = apple_pmp_report_entry_set_performance_state;
	ent->genpd.flags |= GENPD_FLAG_OPP_TABLE_FW;
	return 0;
}

static int apple_pmp_report_entry_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = dev->of_node;
	struct apple_pmp_report_entry *ent;
	int ret;
	const char *name;
	struct of_phandle_iterator it;

	ent = devm_kzalloc(dev, sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return -ENOMEM;

	ent->dev = dev;

	ret = of_property_read_u32(node, "reg", &ent->id);
	if (ret)
		return dev_err_probe(dev, ret, "missing reg property\n");

	ret = of_property_read_string(node, "label", &name);
	if (ret < 0)
		return dev_err_probe(dev, ret, "missing label property\n");

	/* A device on the wakeup path keeps its domain on through system sleep. */
	ent->genpd.flags |= GENPD_FLAG_ACTIVE_WAKEUP;
	if (of_property_read_bool(node, "apple,always-on")) {
		ent->always_on = true;
		apple_pmp_report_set_state(&ent->genpd, true);
	}

	ent->genpd.name = name;
	ent->genpd.power_on = apple_pmp_report_entry_power_on;
	ent->genpd.power_off = apple_pmp_report_entry_power_off;
	ret = apple_pmp_report_entry_dvfs(ent);
	if (ret)
		return dev_err_probe(dev, ret, "bad apple,dvfs-index or apple,dvfs-levels\n");

	ret = pm_genpd_init(&ent->genpd, NULL, true);
	if (ret)
		return dev_err_probe(dev, ret, "pm_genpd_init failed\n");

	ret = of_genpd_add_provider_simple(node, &ent->genpd);
	if (ret)
		return dev_err_probe(dev, ret, "of_genpd_add_provider_simple failed\n");

	of_for_each_phandle(&it, ret, node, "power-domains", "#power-domain-cells", -1) {
		struct of_phandle_args parent, child;

		parent.np = it.node;
		parent.args_count = of_phandle_iterator_args(&it, parent.args, MAX_PHANDLE_ARGS);
		child.np = node;
		child.args_count = 0;
		ret = of_genpd_add_subdomain(&parent, &child);

		if (ret == -EPROBE_DEFER) {
			of_node_put(parent.np);
			goto err_remove;
		} else if (ret < 0) {
			dev_err(dev, "failed to add to parent domain: %d (%s -> %s)\n",
				ret, it.node->name, node->name);
			of_node_put(parent.np);
			goto err_remove;
		}
	}

	pm_genpd_remove_device(dev);

	return 0;
err_remove:
	of_genpd_del_provider(node);
	pm_genpd_remove(&ent->genpd);
	return ret;
}

static const struct of_device_id apple_pmp_report_entry_of_match[] = {
	{ .compatible = "apple,t6000-pmp-v2-report-entry" },
	{}
};

static struct platform_driver apple_pmp_report_entry_driver = {
	.probe = apple_pmp_report_entry_probe,
	.driver = {
		.name = "apple-pmp-report-entry",
		.of_match_table = apple_pmp_report_entry_of_match,
	},
};

MODULE_DEVICE_TABLE(of, apple_pmp_report_of_match);
MODULE_DEVICE_TABLE(of, apple_pmp_report_entry_of_match);

static int __init apple_pmp_report_init(void)
{
	platform_driver_register(&apple_pmp_report_entry_driver);
	platform_driver_register(&apple_pmp_report_driver);
	return 0;
}

static void __exit apple_pmp_report_exit(void)
{
	platform_driver_unregister(&apple_pmp_report_entry_driver);
	platform_driver_unregister(&apple_pmp_report_driver);
}

module_init(apple_pmp_report_init);
module_exit(apple_pmp_report_exit);

MODULE_DESCRIPTION("PMP power state reporting driver for Apple SoCs");
MODULE_LICENSE("Dual MIT/GPL");
