// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple SMC power mode: macOS's Low Power, Automatic and High Power as
 * platform_profile's low-power, balanced and performance.
 *
 * macOS's thermalmonitord tells the SMC the mode in zETM, its sensor exchange
 * record: a header of the sensor count (29), a version (1) and a sequence
 * bumped at each write, then 29 IEEE floats. Slot 0x12 is Low Power Mode and
 * slot 0x1b High Power, 1.0 or 0.0; the three other slots it registers have
 * no writer and stay 0. At a change it resends the record it last sent, then
 * sends the new one. The SMC answers with its High Power policy: mmMD reads 1,
 * and the fans run faster for a cooler case. Low Power sets the SMC's package
 * budget (xLPM, 23 W on the M3 Max) but holds nothing by itself: on macOS CLPC
 * enforces it, capping each CPU cluster at the ADT's
 * cpu-low-power-frequency-max. Here that cap is a cpufreq maximum on every
 * policy, from the SMC node's apple,low-power-cpu-frequency-max.
 */

#include <linux/bits.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/mfd/macsmc.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/platform_profile.h>
#include <linux/pm_qos.h>
#include <linux/slab.h>

#define ZETM_SENSORS	29
#define ZETM_LOW_POWER	0x12
#define ZETM_HIGH_POWER	0x1b
#define F32_ONE		0x3f800000

struct macsmc_zetm {
	u8 count;
	u8 version;
	u8 sequence;
	u8 zero;
	__le32 slot[ZETM_SENSORS];
} __packed;
static_assert(sizeof(struct macsmc_zetm) == 120);

struct macsmc_profile {
	struct apple_smc *smc;
	struct mutex lock;
	enum platform_profile_option profile;
	u8 sequence;
	/* Low Power's CPU ceiling (kHz; 0: none), and its request per policy */
	u32 lpm_khz;
	struct freq_qos_request *qos;
};

/* Macs on which macOS offers High Power */
static const char *const macsmc_profile_machines[] = {
	"apple,j514c", "apple,j514m", "apple,j516c", "apple,j516m",
	NULL
};

static int macsmc_profile_send(struct macsmc_profile *mp,
			       enum platform_profile_option profile)
{
	struct macsmc_zetm z = {
		.count = ZETM_SENSORS,
		.version = 1,
		.sequence = mp->sequence++,
	};

	if (profile == PLATFORM_PROFILE_LOW_POWER)
		z.slot[ZETM_LOW_POWER] = cpu_to_le32(F32_ONE);
	if (profile == PLATFORM_PROFILE_PERFORMANCE)
		z.slot[ZETM_HIGH_POWER] = cpu_to_le32(F32_ONE);

	return apple_smc_write(mp->smc, SMC_KEY(zETM), &z, sizeof(z));
}

/* Low Power's CPU ceiling on every cpufreq policy, or off */
static void macsmc_profile_cap(struct macsmc_profile *mp, bool on)
{
	struct cpufreq_policy *policy;
	unsigned int cpu;

	if (!mp->lpm_khz)
		return;

	for_each_possible_cpu(cpu) {
		struct freq_qos_request *req = &mp->qos[cpu];

		if (!on) {
			if (freq_qos_request_active(req))
				freq_qos_remove_request(req);
			continue;
		}
		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;
		if (policy->cpu == cpu && !freq_qos_request_active(req) &&
		    freq_qos_add_request(&policy->constraints, req, FREQ_QOS_MAX,
					 mp->lpm_khz) < 0)
			memset(req, 0, sizeof(*req));
		cpufreq_cpu_put(policy);
	}
}

static int macsmc_profile_choices(void *drvdata, unsigned long *choices)
{
	set_bit(PLATFORM_PROFILE_LOW_POWER, choices);
	set_bit(PLATFORM_PROFILE_BALANCED, choices);
	set_bit(PLATFORM_PROFILE_PERFORMANCE, choices);
	return 0;
}

static int macsmc_profile_get(struct device *dev,
			      enum platform_profile_option *profile)
{
	struct macsmc_profile *mp = dev_get_drvdata(dev);

	guard(mutex)(&mp->lock);
	*profile = mp->profile;
	return 0;
}

static int macsmc_profile_set(struct device *dev,
			      enum platform_profile_option profile)
{
	struct macsmc_profile *mp = dev_get_drvdata(dev);
	int ret;

	guard(mutex)(&mp->lock);
	if (profile == mp->profile)
		return 0;

	ret = macsmc_profile_send(mp, mp->profile);
	if (!ret)
		ret = macsmc_profile_send(mp, profile);
	if (ret)
		return ret;

	macsmc_profile_cap(mp, profile == PLATFORM_PROFILE_LOW_POWER);
	mp->profile = profile;
	return 0;
}

static const struct platform_profile_ops macsmc_profile_ops = {
	.probe = macsmc_profile_choices,
	.profile_get = macsmc_profile_get,
	.profile_set = macsmc_profile_set,
};

static int macsmc_profile_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct apple_smc_key_info info;
	struct macsmc_profile *mp;
	struct device *ppdev;
	int ret;

	if (!of_machine_compatible_match(macsmc_profile_machines))
		return -ENODEV;

	mp = devm_kzalloc(dev, sizeof(*mp), GFP_KERNEL);
	if (!mp)
		return -ENOMEM;
	mp->smc = dev_get_drvdata(dev->parent);
	platform_set_drvdata(pdev, mp);

	ret = apple_smc_get_key_info(mp->smc, SMC_KEY(zETM), &info);
	if (ret || info.size != sizeof(struct macsmc_zetm) ||
	    !(info.flags & APPLE_SMC_WRITABLE))
		return -ENODEV;

	ret = devm_mutex_init(dev, &mp->lock);
	if (ret)
		return ret;

	if (dev->parent->of_node &&
	    !of_property_read_u32(dev->parent->of_node,
				  "apple,low-power-cpu-frequency-max",
				  &mp->lpm_khz) && mp->lpm_khz) {
		mp->qos = devm_kcalloc(dev, nr_cpu_ids, sizeof(*mp->qos),
				       GFP_KERNEL);
		if (!mp->qos)
			return -ENOMEM;
	}

	/* A known start: Automatic, whatever the last system left */
	mp->profile = PLATFORM_PROFILE_BALANCED;
	ret = macsmc_profile_send(mp, mp->profile);
	if (ret)
		return dev_err_probe(dev, ret, "zETM write failed\n");

	ppdev = devm_platform_profile_register(dev, "macsmc", mp,
					       &macsmc_profile_ops);
	return PTR_ERR_OR_ZERO(ppdev);
}

/* The next system, macOS or this one, starts from Automatic too */
static void macsmc_profile_shutdown(struct platform_device *pdev)
{
	struct macsmc_profile *mp = platform_get_drvdata(pdev);

	guard(mutex)(&mp->lock);
	if (mp->profile != PLATFORM_PROFILE_BALANCED &&
	    !macsmc_profile_send(mp, PLATFORM_PROFILE_BALANCED)) {
		macsmc_profile_cap(mp, false);
		mp->profile = PLATFORM_PROFILE_BALANCED;
	}
}

static void macsmc_profile_remove(struct platform_device *pdev)
{
	struct macsmc_profile *mp = platform_get_drvdata(pdev);

	guard(mutex)(&mp->lock);
	macsmc_profile_cap(mp, false);
	/* platform_profile (devm) outlives remove: a later set caps nothing */
	mp->lpm_khz = 0;
}

static struct platform_driver macsmc_profile_driver = {
	.driver = {
		.name = "macsmc-profile",
	},
	.probe = macsmc_profile_probe,
	.remove = macsmc_profile_remove,
	.shutdown = macsmc_profile_shutdown,
};
module_platform_driver(macsmc_profile_driver);

MODULE_DESCRIPTION("Apple SMC power mode (Low Power, Automatic, High Power) as a platform profile");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:macsmc-profile");
