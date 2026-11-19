// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright The Asahi Linux Contributors
 *
 * CPU idle support for Apple SoCs
 */

#include <linux/init.h>
#include <linux/cpuidle.h>
#include <linux/cpu_pm.h>
#include <linux/instrumentation.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <asm/cpuidle.h>
#include <asm/fpsimd.h>

enum idle_state {
	STATE_WFI,
	STATE_RET,
	STATE_PWRDOWN,
	STATE_COUNT
};

/*
 * The retention state: the core powers down in its WFI and keeps its system
 * registers, SP and PC; it loses x0-x30 and the FP/SIMD registers. macOS
 * idles every core in it whenever its next timer is 50 us or more away.
 * The WFI runs with CYC_OVRD's WFI mode (bits 25:24) at 3, which forces the
 * retention; every other WFI in the kernel keeps m1n1's 2 (clock-gated).
 *
 * It wakes about 12 us later than a plain WFI, and the 500 us residency
 * saves as much as anything shorter does.
 */
#define RET_LATENCY_US		12
#define RET_RESIDENCY_US	500

asm(
	".pushsection .cpuidle.text, \"ax\"\n"
	".type apple_cpu_deep_wfi, @function\n"
	"apple_cpu_deep_wfi:\n"
		"str x30, [sp, #-16]!\n"
		"stp x28, x29, [sp, #-16]!\n"
		"stp x26, x27, [sp, #-16]!\n"
		"stp x24, x25, [sp, #-16]!\n"
		"stp x22, x23, [sp, #-16]!\n"
		"stp x20, x21, [sp, #-16]!\n"
		"stp x18, x19, [sp, #-16]!\n"

		"mrs x0, s3_5_c15_c5_0\n"
		"orr x0, x0, #(3L << 24)\n"
		"msr s3_5_c15_c5_0, x0\n"

	"1:\n"
		"dsb sy\n"
		"wfi\n"

		"mrs x0, ISR_EL1\n"
		"cbz x0, 1b\n"

		"mrs x0, s3_5_c15_c5_0\n"
		"bic x0, x0, #(1L << 24)\n"
		"msr s3_5_c15_c5_0, x0\n"

		"ldp x18, x19, [sp], #16\n"
		"ldp x20, x21, [sp], #16\n"
		"ldp x22, x23, [sp], #16\n"
		"ldp x24, x25, [sp], #16\n"
		"ldp x26, x27, [sp], #16\n"
		"ldp x28, x29, [sp], #16\n"
		"ldr x30, [sp], #16\n"

		"ret\n"
	".popsection\n"
);

void apple_cpu_deep_wfi(void);

/*
 * x0: the WFI mode. Returns nonzero if the core retained, i.e. lost its
 * general registers: x19 holds 1 across the WFI and a retention zeroes it
 * (XNU tests LR the same way).
 */
asm(
	".pushsection .cpuidle.text, \"ax\"\n"
	".type apple_cpu_ret_wfi, @function\n"
	"apple_cpu_ret_wfi:\n"
		"stp x29, x30, [sp, #-112]!\n"
		"mov x29, sp\n"
		"stp x18, x19, [sp, #16]\n"
		"stp x20, x21, [sp, #32]\n"
		"stp x22, x23, [sp, #48]\n"
		"stp x24, x25, [sp, #64]\n"
		"stp x26, x27, [sp, #80]\n"
		"str x28, [sp, #96]\n"

		"mrs x1, s3_5_c15_c5_0\n"
		"bic x1, x1, #(3 << 24)\n"
		"orr x1, x1, x0, lsl #24\n"
		"msr s3_5_c15_c5_0, x1\n"
		"isb\n"
		"mov x19, #1\n"

	"1:\n"
		"dsb sy\n"
		"wfi\n"

		"mrs x0, ISR_EL1\n"
		"cbz x0, 1b\n"

		"mrs x1, s3_5_c15_c5_0\n"
		"bic x1, x1, #(3 << 24)\n"
		"orr x1, x1, #(2 << 24)\n"
		"msr s3_5_c15_c5_0, x1\n"
		"isb\n"

		"eor x0, x19, #1\n"

		"ldr x28, [sp, #96]\n"
		"ldp x26, x27, [sp, #80]\n"
		"ldp x24, x25, [sp, #64]\n"
		"ldp x22, x23, [sp, #48]\n"
		"ldp x20, x21, [sp, #32]\n"
		"ldp x18, x19, [sp, #16]\n"
		"ldp x29, x30, [sp], #112\n"
		"ret\n"
	".size apple_cpu_ret_wfi, . - apple_cpu_ret_wfi\n"
	".popsection\n"
);

unsigned long apple_cpu_ret_wfi(unsigned long mode);

static __cpuidle int apple_enter_wfi(struct cpuidle_device *dev, struct cpuidle_driver *drv, int index)
{
	cpu_do_idle();
	return index;
}

static __cpuidle int apple_enter_ret(struct cpuidle_device *dev, struct cpuidle_driver *drv, int index)
{
	/*
	 * Only the FP/SIMD registers need care: the CPU's FP owner is
	 * dropped so that the next task reloads its state. The system
	 * registers survive, so no other CPU PM notifier runs.
	 */
	instrumentation_begin();
	fpsimd_save_and_flush_cpu_state();
	instrumentation_end();

	ct_cpuidle_enter();
	apple_cpu_ret_wfi(3);
	ct_cpuidle_exit();

	return index;
}

static __cpuidle int apple_enter_idle(struct cpuidle_device *dev, struct cpuidle_driver *drv, int index)
{
	/*
	 * Deep WFI will clobber FP state, among other things.
	 * The CPU PM notifier will take care of saving that and anything else
	 * that needs to be notified of the CPU powering down.
	 */
	if (cpu_pm_enter())
		return -1;

	ct_cpuidle_enter();

	switch(index) {
	case STATE_PWRDOWN:
		apple_cpu_deep_wfi();
		break;
	default:
		WARN_ON(1);
		break;
	}

	ct_cpuidle_exit();

	cpu_pm_exit();

	return index;
}

static struct cpuidle_driver apple_idle_driver = {
	.name = "apple_idle",
	.owner = THIS_MODULE,
	.states = {
		[STATE_WFI] = {
			.enter			= apple_enter_wfi,
			.enter_s2idle		= apple_enter_wfi,
			.exit_latency		= 1,
			.target_residency	= 1,
			.power_usage            = UINT_MAX,
			.name			= "WFI",
			.desc			= "CPU clock-gated",
			.flags			= 0,
		},
		[STATE_RET] = {
			.enter			= apple_enter_ret,
			.exit_latency		= RET_LATENCY_US,
			.target_residency	= RET_RESIDENCY_US,
			.power_usage		= 1,
			.name			= "RET",
			.desc			= "CPU retention",
			.flags			= CPUIDLE_FLAG_RCU_IDLE,
		},
		[STATE_PWRDOWN] = {
			.enter			= apple_enter_idle,
			.enter_s2idle		= apple_enter_idle,
			.exit_latency		= 10,
			.target_residency	= 10000,
			.power_usage            = 0,
			.name			= "CPU PD",
			.desc			= "CPU/cluster powered down",
			.flags			= CPUIDLE_FLAG_RCU_IDLE,
		},
	},
	.safe_state_index = STATE_WFI,
	.state_count = STATE_COUNT,
};

static int apple_cpuidle_probe(struct platform_device *pdev)
{
	return cpuidle_register(&apple_idle_driver, NULL);
}

static struct platform_driver apple_cpuidle_driver = {
	.driver = {
		.name = "cpuidle-apple",
	},
	.probe = apple_cpuidle_probe,
};

static int __init apple_cpuidle_init(void)
{
	struct platform_device *pdev;
	int ret;

	ret = platform_driver_register(&apple_cpuidle_driver);
	if (ret)
		return ret;

	if (!of_machine_is_compatible("apple,arm-platform"))
		return 0;

	if (!(of_machine_is_compatible("apple,t8103") ||
	      of_machine_is_compatible("apple,t8112") ||
	      of_machine_is_compatible("apple,t8122") ||
	      of_machine_is_compatible("apple,t6000") ||
	      of_machine_is_compatible("apple,t6001") ||
	      of_machine_is_compatible("apple,t6002") ||
	      of_machine_is_compatible("apple,t6020") ||
	      of_machine_is_compatible("apple,t6021") ||
	      of_machine_is_compatible("apple,t6022") ||
	      of_machine_is_compatible("apple,t6030") ||
	      of_machine_is_compatible("apple,t6031") ||
	      of_machine_is_compatible("apple,t6032") ||
	      of_machine_is_compatible("apple,t6034")))
		return 0;

	pdev = platform_device_register_simple("cpuidle-apple", -1, NULL, 0);
	if (IS_ERR(pdev)) {
		platform_driver_unregister(&apple_cpuidle_driver);
		return PTR_ERR(pdev);
	}

	return 0;
}
device_initcall(apple_cpuidle_init);
