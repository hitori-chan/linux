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
#include <linux/pm_qos.h>
#include <linux/sched/topology.h>
#include <linux/slab.h>
#include <asm/sysreg.h>

#define PMP_REPORT_READY 0x1
#define PMP_REPORT_ONLINE_TIMEOUT_US (60 * USEC_PER_SEC)

#define PMP_DVFS_VALID BIT_ULL(61)
#define PMP_DVFS_DCS GENMASK_ULL(51, 48)
#define PMP_DVFS_FAB GENMASK_ULL(35, 32)

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
 * The E cluster's DVFS floor (SOC-DEV-DVFS EACC0): macOS's CLPC raises it
 * for the P cores' work and holds the E cluster powered, and the PMP takes
 * the DRAM controllers and the fabric to their top states. With the PMGR's
 * keepalive a CPU's lone DRAM miss then takes about 105 ns against 290. The
 * floor reaches the P clusters only while the E cluster is up, and costs
 * about 1.9 W while it holds. Here it follows the P cores' busy time: it goes
 * up when a P core was busy for half of a period, and down after
 * PMP_FLOOR_HOLD periods without one. The stall policy also wants the busy
 * core stalled on memory for PMP_FLOOR_STALL_PCT of its cycles, by the
 * memory-stall counters CLPC reads (the first three of the always-on six,
 * configured as CLPC's configure<0u>(true) does; a pointer chase counts in
 * the third, a stream and xz in all three, a spin in none), so that work that
 * does not wait on DRAM leaves the floor down: it holds the load policy's
 * gains, and eight spinning P cores draw 3 W less. The default.
 */
#define PMP_FLOOR_PERIOD_MS 20
#define PMP_FLOOR_HOLD 5
#define PMP_FLOOR_BUSY_PCT 50
#define PMP_FLOOR_STALL_PCT 10

#define AON_CPU_MSTALL_CTL0 sys_reg(3, 1, 15, 0, 3)
#define AON_CPU_MSTALL_CTL1 sys_reg(3, 1, 15, 1, 3)
#define AON_CPU_MSTALL_CTL2 sys_reg(3, 1, 15, 2, 3)
#define AON_CPU_MSTALL_CTR(n) sys_reg(3, 1, 15, 8 + (n), 3)
/* Under the deep idle state's 10 us exit latency: the CPU idles in WFI, its cluster up. */
#define PMP_FLOOR_CPU_LATENCY_US 5

enum { FLOOR_OFF, FLOOR_LOAD, FLOOR_STALL, FLOOR_ALWAYS };
static int floor_policy = FLOOR_STALL;

struct apple_pmp_floor {
	struct apple_pmp_report *rep;
	struct delayed_work poll;	/* deferrable: no wakeups while the floor is down */
	struct delayed_work drop;	/* not deferrable: the floor comes down in an idle system */
	struct mutex lock;
	u64 val;
	u32 dev;
	bool online;
	bool on;
	bool suspended;
	unsigned int quiet;
	struct device *cpu_dev;
	struct dev_pm_qos_request cpu_qos;
	u64 *idle, *wall, *stall;
	int cpuhp;
};

static struct apple_pmp_floor *apple_pmp_floor;

static void apple_pmp_floor_set(struct apple_pmp_floor *fl, bool on)
{
	if (fl->on == on)
		return;
	fl->on = on;
	writeq(on ? fl->val : 0, fl->rep->base + fl->rep->offsets->dvfs_write + 8 * fl->dev);
	if (fl->cpu_dev)
		dev_pm_qos_update_request(&fl->cpu_qos, on ? PMP_FLOOR_CPU_LATENCY_US :
					  PM_QOS_RESUME_LATENCY_NO_CONSTRAINT);
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
	*(u64 *)info = (read_sysreg_s(AON_CPU_MSTALL_CTR(0)) & GENMASK_ULL(47, 0)) +
		       (read_sysreg_s(AON_CPU_MSTALL_CTR(1)) & GENMASK_ULL(47, 0)) +
		       (read_sysreg_s(AON_CPU_MSTALL_CTR(2)) & GENMASK_ULL(47, 0));
}

static bool apple_pmp_floor_busy(struct apple_pmp_floor *fl)
{
	bool busy = false;
	int cpu;

	for_each_possible_cpu(cpu) {
		u64 wall, idle = get_cpu_idle_time(cpu, &wall, 0);
		u64 dw = wall - fl->wall[cpu], di = idle - fl->idle[cpu], st, cycles;

		fl->idle[cpu] = idle;
		fl->wall[cpu] = wall;
		if (!cpu_online(cpu) || arch_scale_cpu_capacity(cpu) != SCHED_CAPACITY_SCALE ||
		    !dw || dw <= di || (dw - di) * 100 < dw * PMP_FLOOR_BUSY_PCT) {
			/* the next busy period's count starts over */
			fl->stall[cpu] = U64_MAX;
			continue;
		}
		if (floor_policy != FLOOR_STALL) {
			busy = true;
			continue;
		}
		/* the core is busy, so awake: its own counter, read on it */
		if (smp_call_function_single(cpu, apple_pmp_mstall_read, &st, 1))
			continue;
		cycles = (dw - di) * cpufreq_quick_get(cpu) / USEC_PER_MSEC;
		/* a sum of 48-bit counters: one's wrap reads as a negative count */
		if (fl->stall[cpu] != U64_MAX && (s64)(st - fl->stall[cpu]) > 0 &&
		    (st - fl->stall[cpu]) * 100 >= cycles * PMP_FLOOR_STALL_PCT)
			busy = true;
		fl->stall[cpu] = st;
	}
	return busy;
}

static void apple_pmp_floor_run(struct apple_pmp_floor *fl)
{
	struct apple_pmp_report *rep = fl->rep;
	unsigned long period = msecs_to_jiffies(PMP_FLOOR_PERIOD_MS);
	bool busy;

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

	busy = apple_pmp_floor_busy(fl);
	if (floor_policy == FLOOR_OFF || floor_policy == FLOOR_ALWAYS) {
		apple_pmp_floor_set(fl, floor_policy == FLOOR_ALWAYS);
		goto out;	/* polled again only when the policy changes */
	}
	if (busy) {
		fl->quiet = 0;
		apple_pmp_floor_set(fl, true);
	} else if (fl->on && ++fl->quiet >= PMP_FLOOR_HOLD) {
		apple_pmp_floor_set(fl, false);
	}
	schedule_delayed_work(fl->on ? &fl->drop : &fl->poll, period);
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
	static const char *const names[] = { "off", "load", "stall", "always" };
	int i = sysfs_match_string(names, val);

	if (i < 0)
		return i;
	floor_policy = i;
	if (apple_pmp_floor)
		apple_pmp_floor_kick(apple_pmp_floor);
	return 0;
}

static int apple_pmp_floor_param_get(char *buf, const struct kernel_param *kp)
{
	static const char *const names[] = { "off", "load", "stall", "always" };

	return sysfs_emit(buf, "%s\n", names[floor_policy]);
}

static const struct kernel_param_ops apple_pmp_floor_param_ops = {
	.set = apple_pmp_floor_param_set,
	.get = apple_pmp_floor_param_get,
};
module_param_cb(floor, &apple_pmp_floor_param_ops, NULL, 0644);
MODULE_PARM_DESC(floor, "the E cluster's DVFS floor: off, load (with the P cores' busy time), stall (and their memory stalls), always");

static void apple_pmp_floor_remove(void *data)
{
	struct apple_pmp_floor *fl = data;

	apple_pmp_floor = NULL;
	cancel_delayed_work_sync(&fl->poll);
	cancel_delayed_work_sync(&fl->drop);
	apple_pmp_floor_set(fl, false);
	if (fl->cpu_dev)
		dev_pm_qos_remove_request(&fl->cpu_qos);
	if (fl->cpuhp > 0)
		cpuhp_remove_state(fl->cpuhp);
}

static int apple_pmp_floor_init(struct apple_pmp_report *rep)
{
	struct device *dev = rep->dev;
	struct apple_pmp_floor *fl;
	struct device_node *cpu_np;
	u32 cells[3];
	int ret, cpu;

	ret = of_property_read_u32_array(dev->of_node, "apple,dvfs-floor", cells, ARRAY_SIZE(cells));
	if (ret == -EINVAL)
		return 0;
	if (ret || !rep->offsets->dvfs_write || cells[0] > 2 || cells[1] > 4 || cells[2] > 2)
		return -EINVAL;

	fl = devm_kzalloc(dev, sizeof(*fl), GFP_KERNEL);
	if (!fl)
		return -ENOMEM;
	fl->idle = devm_kcalloc(dev, nr_cpu_ids, sizeof(*fl->idle), GFP_KERNEL);
	fl->wall = devm_kcalloc(dev, nr_cpu_ids, sizeof(*fl->wall), GFP_KERNEL);
	fl->stall = devm_kcalloc(dev, nr_cpu_ids, sizeof(*fl->stall), GFP_KERNEL);
	if (!fl->idle || !fl->wall || !fl->stall)
		return -ENOMEM;
	fl->rep = rep;
	fl->dev = cells[0];
	fl->val = PMP_DVFS_VALID | FIELD_PREP(PMP_DVFS_DCS, cells[1]) |
		  FIELD_PREP(PMP_DVFS_FAB, cells[2]);
	mutex_init(&fl->lock);
	INIT_DEFERRABLE_WORK(&fl->poll, apple_pmp_floor_poll);
	INIT_DELAYED_WORK(&fl->drop, apple_pmp_floor_drop);

	cpu_np = of_parse_phandle(dev->of_node, "apple,dvfs-floor-cpu", 0);
	if (cpu_np) {
		cpu = of_cpu_node_to_id(cpu_np);
		of_node_put(cpu_np);
		fl->cpu_dev = cpu >= 0 ? get_cpu_device(cpu) : NULL;
		if (!fl->cpu_dev)
			return -ENODEV;
		ret = dev_pm_qos_add_request(fl->cpu_dev, &fl->cpu_qos, DEV_PM_QOS_RESUME_LATENCY,
					     PM_QOS_RESUME_LATENCY_NO_CONSTRAINT);
		if (ret < 0)
			return ret;
	}

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
		apple_pmp_floor_set(fl, false);
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

struct apple_pmp_report_entry {
	struct device *dev;
	struct generic_pm_domain genpd;
	u32 id;
	bool always_on;
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

static int apple_pmp_report_entry_power_on(struct generic_pm_domain *genpd)
{
	return apple_pmp_report_set_state(genpd, true);
}

static int apple_pmp_report_entry_power_off(struct generic_pm_domain *genpd)
{
	return apple_pmp_report_set_state(genpd, false);
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
