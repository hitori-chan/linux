// SPDX-License-Identifier: GPL-2.0-only
/*
 * Spin Table SMP initialisation
 *
 * Copyright (C) 2013 ARM Ltd.
 */

#include <linux/bitfield.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/mm.h>

#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/cputype.h>
#include <asm/io.h>
#include <asm/kexec.h>
#include <asm/mmu_context.h>
#include <asm/smp_plat.h>
#include <asm/sysreg.h>

extern void secondary_holding_pen(void);
volatile unsigned long __section(".mmuoff.data.read")
secondary_holding_pen_release = INVALID_HWID;

static phys_addr_t cpu_release_addr[NR_CPUS];

/*
 * Write secondary_holding_pen_release in a way that is guaranteed to be
 * visible to all observers, irrespective of whether they're taking part
 * in coherency or not.  This is necessary for the hotplug code to work
 * reliably.
 */
static void write_pen_release(u64 val)
{
	void *start = (void *)&secondary_holding_pen_release;
	unsigned long size = sizeof(secondary_holding_pen_release);

	secondary_holding_pen_release = val;
	dcache_clean_inval_poc((unsigned long)start, (unsigned long)start + size);
}


#if defined(CONFIG_HOTPLUG_CPU) && defined(CONFIG_KEXEC_CORE)
/*
 * CPU hotplug on Apple Silicon, where the spin table cannot take a core down and nothing restarts
 * one: the PMGR's start pulse only releases a core from its first reset, and does nothing to one
 * that has run (t6034, m1n1's proxy, 2026-11-12). So an offline core is parked here: it sleeps in
 * a power-down WFI no IRQ ends, as XNU's arm64_prepare_for_sleep() leaves a core it takes offline,
 * but with FIQ left to wake it. A fast IPI ends the WFI and the core goes on after it with its
 * general registers lost and its system registers kept (measured), so what m1n1 set up at boot
 * holds. Brought back, it restarts the kernel's secondary entry from the holding pen with the MMU
 * off, as a core m1n1 releases.
 *
 * The core's bit in the PMGR's stopped-cores mask, which macOS sets for a core it takes offline
 * (ApplePMGR::configMiscCores()), stays clear: with it set and SIQ_CFG off, the first IPI to a
 * parked core reset the machine.
 */

#define SYS_IMP_APL_SIQ_CFG_EL1		sys_reg(3, 4, 15, 10, 4)
#define SIQ_CFG_OFF			3	/* no IRQ is routed to the core */
#define SYS_IMP_APL_CYC_OVRD		sys_reg(3, 5, 15, 5, 0)
#define CYC_OVRD_WFI_MODE		GENMASK_ULL(25, 24)
#define CYC_OVRD_WFI_MODE_DOWN		3
#define CYC_OVRD_IRQ_MODE		GENMASK_ULL(23, 22)
#define CYC_OVRD_IRQ_MODE_OFF		2
#define SYS_IMP_APL_IPI_RR_GLOBAL_EL1	sys_reg(3, 5, 15, 0, 1)
#define IPI_RR_CPU			GENMASK(7, 0)
#define IPI_RR_CLUSTER			GENMASK(23, 16)
#define SYS_IMP_APL_IPI_SR_EL1		sys_reg(3, 5, 15, 1, 1)
#define IPI_SR_PENDING			BIT(0)

static bool apple_parks;
static cpumask_t apple_cpus_parked, apple_cpus_revive;

/* The WFI ends with x0 to x30 lost; the stack pointer is kept */
asm(
	".pushsection .text, \"ax\"\n"
	".type apple_cpu_park_wfi, @function\n"
	"apple_cpu_park_wfi:\n"
		"stp x29, x30, [sp, #-112]!\n"
		"stp x19, x20, [sp, #16]\n"
		"stp x21, x22, [sp, #32]\n"
		"stp x23, x24, [sp, #48]\n"
		"stp x25, x26, [sp, #64]\n"
		"stp x27, x28, [sp, #80]\n"
		"str x18, [sp, #96]\n"
		"dsb sy\n"
		"wfi\n"
		"ldr x18, [sp, #96]\n"
		"ldp x27, x28, [sp, #80]\n"
		"ldp x25, x26, [sp, #64]\n"
		"ldp x23, x24, [sp, #48]\n"
		"ldp x21, x22, [sp, #32]\n"
		"ldp x19, x20, [sp, #16]\n"
		"ldp x29, x30, [sp], #112\n"
		"ret\n"
	".size apple_cpu_park_wfi, . - apple_cpu_park_wfi\n"
	".popsection\n"
);
void apple_cpu_park_wfi(void);

static void apple_cpu_init(void)
{
	/* Only where it has run */
	apple_parks = of_machine_is_compatible("apple,t6034") ||
		      of_machine_is_compatible("apple,t6031");
}

/* The boot CPU has no release address and stays */
static bool smp_spin_table_cpu_can_disable(unsigned int cpu)
{
	return apple_parks && cpu_release_addr[cpu];
}

static int smp_spin_table_cpu_disable(unsigned int cpu)
{
	return smp_spin_table_cpu_can_disable(cpu) ? 0 : -EOPNOTSUPP;
}

static void __noreturn smp_spin_table_cpu_die(unsigned int cpu)
{
	typeof(cpu_soft_restart) *restart;
	u64 siq = read_sysreg_s(SYS_IMP_APL_SIQ_CFG_EL1);
	u64 cyc = read_sysreg_s(SYS_IMP_APL_CYC_OVRD);

	write_sysreg_s(siq | SIQ_CFG_OFF, SYS_IMP_APL_SIQ_CFG_EL1);
	write_sysreg_s((cyc & ~(CYC_OVRD_IRQ_MODE | CYC_OVRD_WFI_MODE)) |
		       FIELD_PREP(CYC_OVRD_IRQ_MODE, CYC_OVRD_IRQ_MODE_OFF) |
		       FIELD_PREP(CYC_OVRD_WFI_MODE, CYC_OVRD_WFI_MODE_DOWN),
		       SYS_IMP_APL_CYC_OVRD);
	isb();

	do {
		cpumask_set_cpu(cpu, &apple_cpus_parked);
		apple_cpu_park_wfi();
		/* Interrupts are masked: nothing else takes the IPI that ended the WFI */
		write_sysreg_s(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);
		isb();
	} while (!cpumask_test_cpu(cpu, &apple_cpus_revive));

	write_sysreg_s(cyc, SYS_IMP_APL_CYC_OVRD);
	write_sysreg_s(siq, SYS_IMP_APL_SIQ_CFG_EL1);
	isb();
	cpumask_clear_cpu(cpu, &apple_cpus_revive);
	cpumask_clear_cpu(cpu, &apple_cpus_parked);

	cpu_install_idmap();
	restart = (void *)__pa_symbol(cpu_soft_restart);
	restart(0, __pa_symbol(secondary_holding_pen), 0, 0, 0);
	BUG();
}

static int smp_spin_table_cpu_kill(unsigned int cpu)
{
	int i;

	for (i = 0; i < 100; i++) {
		if (cpumask_test_cpu(cpu, &apple_cpus_parked))
			return 0;
		usleep_range(1000, 2000);
	}

	pr_err("CPU %d did not park\n", cpu);

	return -ETIMEDOUT;
}

/* Wake a parked core; the pen's release follows as at boot */
static void apple_cpu_revive(unsigned int cpu)
{
	u64 mpidr = cpu_logical_map(cpu);

	if (!cpumask_test_cpu(cpu, &apple_cpus_parked))
		return;

	cpumask_set_cpu(cpu, &apple_cpus_revive);
	write_sysreg_s(FIELD_PREP(IPI_RR_CPU, MPIDR_AFFINITY_LEVEL(mpidr, 0)) |
		       FIELD_PREP(IPI_RR_CLUSTER, MPIDR_AFFINITY_LEVEL(mpidr, 1)),
		       SYS_IMP_APL_IPI_RR_GLOBAL_EL1);
	isb();
}

/* A parked core stays in this kernel's text: no kexec leaves it behind */
bool smp_spin_table_parks_cpus(void)
{
	return apple_parks;
}

#else
static void apple_cpu_init(void) { }
static void apple_cpu_revive(unsigned int cpu) { }
bool smp_spin_table_parks_cpus(void) { return false; }
#endif

static int smp_spin_table_cpu_init(unsigned int cpu)
{
	struct device_node *dn;
	int ret;

	dn = of_get_cpu_node(cpu, NULL);
	if (!dn)
		return -ENODEV;

	apple_cpu_init();

	/*
	 * Determine the address from which the CPU is polling.
	 */
	ret = of_property_read_u64(dn, "cpu-release-addr",
				   &cpu_release_addr[cpu]);
	if (ret)
		pr_err("CPU %d: missing or invalid cpu-release-addr property\n",
		       cpu);

	of_node_put(dn);

	return ret;
}

static int smp_spin_table_cpu_prepare(unsigned int cpu)
{
	__le64 __iomem *release_addr;
	phys_addr_t pa_holding_pen = __pa_symbol(secondary_holding_pen);

	if (!cpu_release_addr[cpu])
		return -ENODEV;

	/*
	 * The cpu-release-addr may or may not be inside the linear mapping.
	 * As ioremap_cache will either give us a new mapping or reuse the
	 * existing linear mapping, we can use it to cover both cases. In
	 * either case the memory will be MT_NORMAL.
	 */
	release_addr = ioremap_cache(cpu_release_addr[cpu],
				     sizeof(*release_addr));
	if (!release_addr)
		return -ENOMEM;

	/*
	 * We write the release address as LE regardless of the native
	 * endianness of the kernel. Therefore, any boot-loaders that
	 * read this address need to convert this address to the
	 * boot-loader's endianness before jumping. This is mandated by
	 * the boot protocol.
	 */
	writeq_relaxed(pa_holding_pen, release_addr);
	dcache_clean_inval_poc((__force unsigned long)release_addr,
			    (__force unsigned long)release_addr +
				    sizeof(*release_addr));

	/*
	 * Send an event to wake up the secondary CPU.
	 */
	sev();

	iounmap(release_addr);

	return 0;
}

static int smp_spin_table_cpu_boot(unsigned int cpu)
{
	apple_cpu_revive(cpu);

	/*
	 * Update the pen release flag.
	 */
	write_pen_release(cpu_logical_map(cpu));

	/*
	 * Send an event, causing the secondaries to read pen_release.
	 */
	sev();

	return 0;
}

const struct cpu_operations smp_spin_table_ops = {
	.name		= "spin-table",
	.cpu_init	= smp_spin_table_cpu_init,
	.cpu_prepare	= smp_spin_table_cpu_prepare,
	.cpu_boot	= smp_spin_table_cpu_boot,
#if defined(CONFIG_HOTPLUG_CPU) && defined(CONFIG_KEXEC_CORE)
	.cpu_can_disable = smp_spin_table_cpu_can_disable,
	.cpu_disable	= smp_spin_table_cpu_disable,
	.cpu_die	= smp_spin_table_cpu_die,
	.cpu_kill	= smp_spin_table_cpu_kill,
#endif
};
