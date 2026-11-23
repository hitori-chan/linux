// SPDX-License-Identifier: GPL-2.0-only
/*
 * The energy a CPU cluster of Apple's M3 (t6031, t6034) has drawn, as hwmon energy inputs: each core's and its
 * SRAM's accumulator and the cluster's CPM and CPM SRAM ones, 25 pJ a count, which macOS's PMGR reads for its
 * energy model (AppleT6031PMGR::getCPUCoreEnergyAccumulator, the CPM and SRAM siblings, and
 * energyAccumulatorToNanojoules; enableCPUEnergyAccumulators sets bits 63, 61 and 59 of the CPM's word at +0x80).
 *
 * One device a cluster: reg 0 the CPM's accumulators (+0, +8) and their enable (+0x80), reg 1 + N core N's (MPIDR
 * Aff0) accumulators (+0 the core, +8 its SRAM); apple,cpufreq the cluster's cpufreq node, whose CPUs it counts.
 * The words are read on one of the cluster's CPUs, so the cluster is powered while they are.
 */

#include <linux/bits.h>
#include <linux/cpumask.h>
#include <linux/hwmon.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/smp.h>

#define CPM_CORE	0x0
#define CPM_SRAM	0x8
#define CPM_ENABLE	0x80
#define CPM_ENABLE_BITS	(BIT_ULL(63) | BIT_ULL(61) | BIT_ULL(59))
#define MAX_CORES	8
#define PJ_PER_COUNT	25

struct ace {
	void __iomem *cpm;
	void __iomem *core[MAX_CORES];
	cpumask_t cpus;
	const char *label;
};

struct ace_read {
	struct ace *a;
	u64 sum;
};

static void ace_read_on_cluster(void *arg)
{
	struct ace_read *r = arg;
	struct ace *a = r->a;
	int i;

	r->sum = readq_relaxed(a->cpm + CPM_CORE) + readq_relaxed(a->cpm + CPM_SRAM);
	for (i = 0; i < MAX_CORES; i++)
		if (a->core[i])
			r->sum += readq_relaxed(a->core[i]) + readq_relaxed(a->core[i] + 8);
}

static void ace_enable_on_cluster(void *arg)
{
	struct ace *a = arg;
	u64 w = readq_relaxed(a->cpm + CPM_ENABLE);

	if ((w & CPM_ENABLE_BITS) != CPM_ENABLE_BITS)
		writeq_relaxed(w | CPM_ENABLE_BITS, a->cpm + CPM_ENABLE);
}

static umode_t ace_is_visible(const void *data, enum hwmon_sensor_types type, u32 attr, int channel)
{
	return 0444;
}

static int ace_read(struct device *dev, enum hwmon_sensor_types type, u32 attr, int channel, long *val)
{
	struct ace_read r = { .a = dev_get_drvdata(dev) };
	int ret;

	if (type != hwmon_energy || attr != hwmon_energy_input)
		return -EOPNOTSUPP;
	ret = smp_call_function_any(&r.a->cpus, ace_read_on_cluster, &r, 1);
	if (ret)
		return ret;
	/* µJ; a long holds 2^63 µJ */
	*val = div_u64(r.sum, 1000000 / PJ_PER_COUNT);
	return 0;
}

static int ace_read_string(struct device *dev, enum hwmon_sensor_types type, u32 attr, int channel,
			   const char **str)
{
	struct ace *a = dev_get_drvdata(dev);

	*str = a->label;
	return 0;
}

static const struct hwmon_ops ace_ops = {
	.is_visible = ace_is_visible,
	.read = ace_read,
	.read_string = ace_read_string,
};

static const struct hwmon_channel_info *const ace_info[] = {
	HWMON_CHANNEL_INFO(energy, HWMON_E_INPUT | HWMON_E_LABEL),
	NULL
};

static const struct hwmon_chip_info ace_chip = {
	.ops = &ace_ops,
	.info = ace_info,
};

static int ace_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *freq;
	struct ace *a;
	int cpu, ncores = 0;

	a = devm_kzalloc(dev, sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;
	a->cpm = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(a->cpm))
		return PTR_ERR(a->cpm);

	freq = of_parse_phandle(dev->of_node, "apple,cpufreq", 0);
	if (!freq)
		return dev_err_probe(dev, -EINVAL, "no apple,cpufreq\n");
	for_each_possible_cpu(cpu) {
		struct device_node *cn = of_get_cpu_node(cpu, NULL);
		struct device_node *pd = cn ? of_parse_phandle(cn, "performance-domains", 0) : NULL;
		u64 hwid;
		/* MPIDR's Aff0: the CPU node's reg, which of_get_cpu_hwid() reads but does not export */
		unsigned int k = cn && !of_property_read_reg(cn, 0, &hwid, NULL) ? hwid & 0xff : MAX_CORES;

		if (pd == freq && k < MAX_CORES && !a->core[k]) {
			a->core[k] = devm_platform_ioremap_resource(pdev, 1 + k);
			if (IS_ERR(a->core[k])) {
				of_node_put(pd);
				of_node_put(cn);
				of_node_put(freq);
				return dev_err_probe(dev, PTR_ERR(a->core[k]), "core %u's accumulators\n", k);
			}
			cpumask_set_cpu(cpu, &a->cpus);
			ncores++;
		}
		of_node_put(pd);
		of_node_put(cn);
	}
	of_node_put(freq);
	if (!ncores)
		return dev_err_probe(dev, -ENODEV, "no CPU in the cluster\n");

	if (of_property_read_string(dev->of_node, "label", &a->label))
		a->label = dev_name(dev);
	platform_set_drvdata(pdev, a);

	/* as macOS does at boot: the accumulators count once their three bits are set */
	if (smp_call_function_any(&a->cpus, ace_enable_on_cluster, a, 1))
		return dev_err_probe(dev, -ENODEV, "no online CPU in the cluster\n");

	return PTR_ERR_OR_ZERO(devm_hwmon_device_register_with_info(dev, "apple_cpu_energy", a, &ace_chip, NULL));
}

/* the enable may not survive the cluster's power-down in a sleep (not traced): set it again */
static int ace_resume(struct device *dev)
{
	struct ace *a = dev_get_drvdata(dev);

	smp_call_function_any(&a->cpus, ace_enable_on_cluster, a, 1);
	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(ace_pm, NULL, ace_resume);

static const struct of_device_id ace_of_match[] = {
	{ .compatible = "apple,t6031-cluster-energy" },
	{}
};
MODULE_DEVICE_TABLE(of, ace_of_match);

static struct platform_driver ace_driver = {
	.driver = {
		.name = "apple-cpu-energy",
		.of_match_table = ace_of_match,
		.pm = pm_sleep_ptr(&ace_pm),
	},
	.probe = ace_probe,
};
module_platform_driver(ace_driver);

MODULE_DESCRIPTION("Apple M3 CPU cluster energy accumulators");
MODULE_LICENSE("GPL");
