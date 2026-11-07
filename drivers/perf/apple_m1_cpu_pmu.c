// SPDX-License-Identifier: GPL-2.0
/*
 * CPU PMU driver for the Apple M1 and derivatives
 *
 * Copyright (C) 2021 Google LLC
 *
 * Author: Marc Zyngier <maz@kernel.org>
 *
 * Most of the information used in this driver was provided by the
 * Asahi Linux project. The rest was experimentally discovered.
 */

#include <linux/of.h>
#include <linux/perf/arm_pmu.h>
#include <linux/perf/arm_pmuv3.h>
#include <linux/platform_device.h>

#include <asm/apple_m1_pmu.h>
#include <asm/irq_regs.h>
#include <asm/perf_event.h>

#define M1_PMU_NR_COUNTERS		10

#define M1_PMU_CFG_EVENT		GENMASK(7, 0)
#define M3_PMU_CFG_EVENT		GENMASK(15, 0)

#define ANY_BUT_0_1			GENMASK(9, 2)
#define ONLY_2_TO_7			GENMASK(7, 2)
#define ONLY_2_4_6			(BIT(2) | BIT(4) | BIT(6))
#define ONLY_5_6_7			(BIT(5) | BIT(6) | BIT(7))

/*
 * Description of the events we actually know about, as well as those with
 * a specific counter affinity. Yes, this is a grand total of two known
 * counters, and the rest is anybody's guess.
 *
 * Not all counters can count all events. Counters #0 and #1 are wired to
 * count cycles and instructions respectively, and some events have
 * bizarre mappings (every other counter, or even *one* counter). These
 * restrictions equally apply to both P and E cores.
 *
 * It is worth noting that the PMUs attached to P and E cores are likely
 * to be different because the underlying uarches are different. At the
 * moment, we don't really need to distinguish between the two because we
 * know next to nothing about the events themselves, and we already have
 * per cpu-type PMU abstractions.
 */
enum m1_pmu_events {
	M1_PMU_PERFCTR_RETIRE_UOP				= 0x1,
	M1_PMU_PERFCTR_CORE_ACTIVE_CYCLE			= 0x2,
	M1_PMU_PERFCTR_L1I_TLB_FILL				= 0x4,
	M1_PMU_PERFCTR_L1D_TLB_FILL				= 0x5,
	M1_PMU_PERFCTR_MMU_TABLE_WALK_INSTRUCTION		= 0x7,
	M1_PMU_PERFCTR_MMU_TABLE_WALK_DATA			= 0x8,
	M1_PMU_PERFCTR_L2_TLB_MISS_INSTRUCTION			= 0xa,
	M1_PMU_PERFCTR_L2_TLB_MISS_DATA				= 0xb,
	M1_PMU_PERFCTR_MMU_VIRTUAL_MEMORY_FAULT_NONSPEC		= 0xd,
	M1_PMU_PERFCTR_SCHEDULE_UOP				= 0x52,
	M1_PMU_PERFCTR_INTERRUPT_PENDING			= 0x6c,
	M1_PMU_PERFCTR_MAP_STALL_DISPATCH			= 0x70,
	M1_PMU_PERFCTR_MAP_REWIND				= 0x75,
	M1_PMU_PERFCTR_MAP_STALL				= 0x76,
	M1_PMU_PERFCTR_MAP_INT_UOP				= 0x7c,
	M1_PMU_PERFCTR_MAP_LDST_UOP				= 0x7d,
	M1_PMU_PERFCTR_MAP_SIMD_UOP				= 0x7e,
	M1_PMU_PERFCTR_FLUSH_RESTART_OTHER_NONSPEC		= 0x84,
	M1_PMU_PERFCTR_INST_ALL					= 0x8c,
	M1_PMU_PERFCTR_INST_BRANCH				= 0x8d,
	M1_PMU_PERFCTR_INST_BRANCH_CALL				= 0x8e,
	M1_PMU_PERFCTR_INST_BRANCH_RET				= 0x8f,
	M1_PMU_PERFCTR_INST_BRANCH_TAKEN			= 0x90,
	M1_PMU_PERFCTR_INST_BRANCH_INDIR			= 0x93,
	M1_PMU_PERFCTR_INST_BRANCH_COND				= 0x94,
	M1_PMU_PERFCTR_INST_INT_LD				= 0x95,
	M1_PMU_PERFCTR_INST_INT_ST				= 0x96,
	M1_PMU_PERFCTR_INST_INT_ALU				= 0x97,
	M1_PMU_PERFCTR_INST_SIMD_LD				= 0x98,
	M1_PMU_PERFCTR_INST_SIMD_ST				= 0x99,
	M1_PMU_PERFCTR_INST_SIMD_ALU				= 0x9a,
	M1_PMU_PERFCTR_INST_LDST				= 0x9b,
	M1_PMU_PERFCTR_INST_BARRIER				= 0x9c,
	M1_PMU_PERFCTR_UNKNOWN_9f				= 0x9f,
	M1_PMU_PERFCTR_L1D_TLB_ACCESS				= 0xa0,
	M1_PMU_PERFCTR_L1D_TLB_MISS				= 0xa1,
	M1_PMU_PERFCTR_L1D_CACHE_MISS_ST			= 0xa2,
	M1_PMU_PERFCTR_L1D_CACHE_MISS_LD			= 0xa3,
	M1_PMU_PERFCTR_LD_UNIT_UOP				= 0xa6,
	M1_PMU_PERFCTR_ST_UNIT_UOP				= 0xa7,
	M1_PMU_PERFCTR_L1D_CACHE_WRITEBACK			= 0xa8,
	M1_PMU_PERFCTR_LDST_X64_UOP				= 0xb1,
	M1_PMU_PERFCTR_LDST_XPG_UOP				= 0xb2,
	M1_PMU_PERFCTR_ATOMIC_OR_EXCLUSIVE_SUCC			= 0xb3,
	M1_PMU_PERFCTR_ATOMIC_OR_EXCLUSIVE_FAIL			= 0xb4,
	M1_PMU_PERFCTR_L1D_CACHE_MISS_LD_NONSPEC		= 0xbf,
	M1_PMU_PERFCTR_L1D_CACHE_MISS_ST_NONSPEC		= 0xc0,
	M1_PMU_PERFCTR_L1D_TLB_MISS_NONSPEC			= 0xc1,
	M1_PMU_PERFCTR_ST_MEMORY_ORDER_VIOLATION_NONSPEC	= 0xc4,
	M1_PMU_PERFCTR_BRANCH_COND_MISPRED_NONSPEC		= 0xc5,
	M1_PMU_PERFCTR_BRANCH_INDIR_MISPRED_NONSPEC		= 0xc6,
	M1_PMU_PERFCTR_BRANCH_RET_INDIR_MISPRED_NONSPEC		= 0xc8,
	M1_PMU_PERFCTR_BRANCH_CALL_INDIR_MISPRED_NONSPEC	= 0xca,
	M1_PMU_PERFCTR_BRANCH_MISPRED_NONSPEC			= 0xcb,
	M1_PMU_PERFCTR_L1I_TLB_MISS_DEMAND			= 0xd4,
	M1_PMU_PERFCTR_MAP_DISPATCH_BUBBLE			= 0xd6,
	M1_PMU_PERFCTR_L1I_CACHE_MISS_DEMAND			= 0xdb,
	M1_PMU_PERFCTR_FETCH_RESTART				= 0xde,
	M1_PMU_PERFCTR_ST_NT_UOP				= 0xe5,
	M1_PMU_PERFCTR_LD_NT_UOP				= 0xe6,
	M1_PMU_PERFCTR_UNKNOWN_f5				= 0xf5,
	M1_PMU_PERFCTR_UNKNOWN_f6				= 0xf6,
	M1_PMU_PERFCTR_UNKNOWN_f7				= 0xf7,
	M1_PMU_PERFCTR_UNKNOWN_f8				= 0xf8,
	M1_PMU_PERFCTR_UNKNOWN_fd				= 0xfd,
	M1_PMU_PERFCTR_LAST					= M1_PMU_CFG_EVENT,

	/*
	 * From this point onwards, these are not actual HW events,
	 * but attributes that get stored in hw->config_base.
	 */
	M1_PMU_CFG_COUNT_USER					= BIT(8),
	M1_PMU_CFG_COUNT_KERNEL					= BIT(9),
	M1_PMU_CFG_COUNT_HOST					= BIT(10),
	M1_PMU_CFG_COUNT_GUEST					= BIT(11),
};

enum m3_pmu_events {
	M3_PMU_PERFCTR_RETIRE_UOP				= 0x1,
	M3_PMU_PERFCTR_CORE_ACTIVE_CYCLE			= 0x2,
	M3_PMU_PERFCTR_FLUSH_RESTART_OTHER_NONSPEC		= 0x84,
	M3_PMU_PERFCTR_INST_ALL					= 0x8c,
	M3_PMU_PERFCTR_INST_BRANCH				= 0x8d,
	M3_PMU_PERFCTR_INST_BRANCH_CALL				= 0x8e,
	M3_PMU_PERFCTR_INST_BRANCH_RET				= 0x8f,
	M3_PMU_PERFCTR_INST_BRANCH_TAKEN			= 0x90,
	M3_PMU_PERFCTR_INST_BRANCH_INDIR			= 0x93,
	M3_PMU_PERFCTR_INST_INT_LD				= 0x95,
	M3_PMU_PERFCTR_INST_INT_ST				= 0x96,
	M3_PMU_PERFCTR_INST_INT_ALU				= 0x97,
	M3_PMU_PERFCTR_INST_SIMD_LD				= 0x98,
	M3_PMU_PERFCTR_INST_SIMD_ST				= 0x99,
	M3_PMU_PERFCTR_INST_SIMD_ALU				= 0x9a,
	M3_PMU_PERFCTR_INST_LDST				= 0x9b,
	M3_PMU_PERFCTR_INST_BARRIER				= 0x9c,
	M3_PMU_PERFCTR_INST_SIMD_ALU_VEC			= 0x9f,
	M3_PMU_PERFCTR_L1D_CACHE_MISS_LD_NONSPEC		= 0xbf,
	M3_PMU_PERFCTR_L1D_CACHE_MISS_ST_NONSPEC		= 0xc0,
	M3_PMU_PERFCTR_L1D_TLB_MISS_NONSPEC			= 0xc1,
	M3_PMU_PERFCTR_ST_MEM_ORDER_VIOL_LD_NONSPEC		= 0xc4,
	M3_PMU_PERFCTR_BRANCH_COND_MISPRED_NONSPEC		= 0xc5,
	M3_PMU_PERFCTR_BRANCH_INDIR_MISPRED_NONSPEC		= 0xc6,
	M3_PMU_PERFCTR_BRANCH_RET_INDIR_MISPRED_NONSPEC		= 0xc8,
	M3_PMU_PERFCTR_BRANCH_CALL_INDIR_MISPRED_NONSPEC	= 0xca,
	M3_PMU_PERFCTR_BRANCH_MISPRED_NONSPEC			= 0xcb,
	M3_PMU_PERFCTR_MAP_DISPATCH_BUBBLE_IC			= 0x182,
	M3_PMU_PERFCTR_MAP_DISPATCH_BUBBLE_ITLB			= 0x183,
	M3_PMU_PERFCTR_DECODE_UOP				= 0x186,
	M3_PMU_PERFCTR_L1I_TLB_MISS_DEMAND			= 0x1d4,
	M3_PMU_PERFCTR_MAP_DISPATCH_BUBBLE			= 0x1d6,
	M3_PMU_PERFCTR_L1I_CACHE_MISS_DEMAND			= 0x1db,
	M3_PMU_PERFCTR_FETCH_RESTART				= 0x1de,
	M3_PMU_PERFCTR_MAP_UOP					= 0x269,
	M3_PMU_PERFCTR_INTERRUPT_PENDING			= 0x26c,
	M3_PMU_PERFCTR_MAP_STALL_DISPATCH			= 0x270,
	M3_PMU_PERFCTR_MAP_REWIND				= 0x275,
	M3_PMU_PERFCTR_MAP_STALL				= 0x276,
	M3_PMU_PERFCTR_MAP_INT_UOP				= 0x27c,
	M3_PMU_PERFCTR_MAP_LDST_UOP				= 0x27d,
	M3_PMU_PERFCTR_MAP_SIMD_UOP				= 0x27e,
	M3_PMU_PERFCTR_SCHEDULE_UOP_ANY				= 0x283,
	M3_PMU_PERFCTR_LDST_UNIT_OLD_L1D_CACHE_MISS		= 0x290,
	M3_PMU_PERFCTR_LDST_UNIT_WAITING_OLD_L1D_CACHE_MISS	= 0x291,
	M3_PMU_PERFCTR_SCHEDULE_EMPTY				= 0x351,
	M3_PMU_PERFCTR_L1I_TLB_FILL				= 0x404,
	M3_PMU_PERFCTR_L1D_TLB_FILL				= 0x405,
	M3_PMU_PERFCTR_MMU_TABLE_WALK_INSTRUCTION		= 0x407,
	M3_PMU_PERFCTR_MMU_TABLE_WALK_DATA			= 0x408,
	M3_PMU_PERFCTR_L2_TLB_MISS_INSTRUCTION			= 0x40a,
	M3_PMU_PERFCTR_L2_TLB_MISS_DATA				= 0x40b,
	M3_PMU_PERFCTR_L1D_TLB_ACCESS				= 0x5a0,
	M3_PMU_PERFCTR_L1D_TLB_MISS				= 0x5a1,
	M3_PMU_PERFCTR_L1D_CACHE_MISS_ST			= 0x5a2,
	M3_PMU_PERFCTR_L1D_CACHE_MISS_LD			= 0x5a3,
	M3_PMU_PERFCTR_LD_UNIT_UOP				= 0x5a6,
	M3_PMU_PERFCTR_ST_UNIT_UOP				= 0x5a7,
	M3_PMU_PERFCTR_L1D_CACHE_WRITEBACK			= 0x5a8,
	M3_PMU_PERFCTR_LDST_X64_UOP				= 0x5b1,
	M3_PMU_PERFCTR_LDST_XPG_UOP				= 0x5b2,
	M3_PMU_PERFCTR_ATOMIC_OR_EXCLUSIVE_SUCC			= 0x5b3,
	M3_PMU_PERFCTR_ATOMIC_OR_EXCLUSIVE_FAIL			= 0x5b4,
	M3_PMU_PERFCTR_ST_NT_UOP				= 0x5e5,
	M3_PMU_PERFCTR_LD_NT_UOP				= 0x5e6,
	M3_PMU_PERFCTR_LAST					= M3_PMU_CFG_EVENT,

	/*
	 * From this point onwards, these are not actual HW events,
	 * but attributes that get stored in hw->config_base.
	 */
	M3_PMU_CFG_COUNT_USER					= BIT(16),
	M3_PMU_CFG_COUNT_KERNEL					= BIT(17),
	M3_PMU_CFG_COUNT_HOST					= BIT(18),
	M3_PMU_CFG_COUNT_GUEST					= BIT(19),
};

enum m4_pmu_events {
	M4_PMU_PERFCTR_ARM_L1D_CACHE_REFILL				= 0x03,
	M4_PMU_PERFCTR_ARM_L1D_CACHE					= 0x04,
	M4_PMU_PERFCTR_INST_ALL						= 0x08,
	M4_PMU_PERFCTR_ARM_BR_MIS_PRED					= 0x10,
	M4_PMU_PERFCTR_CORE_ACTIVE_CYCLE				= 0x11,
	M4_PMU_PERFCTR_ARM_BR_PRED					= 0x12,
	M4_PMU_PERFCTR_INST_BRANCH					= 0x21,
	M4_PMU_PERFCTR_BRANCH_MISPRED_NONSPEC				= 0x22,
	M4_PMU_PERFCTR_ARM_STALL_FRONTEND				= 0x23,
	M4_PMU_PERFCTR_ARM_STALL_BACKEND				= 0x24,
	M4_PMU_PERFCTR_ARM_L1D_CACHE_LMISS_RD				= 0x39,
	M4_PMU_PERFCTR_RETIRE_UOP					= 0x3a,
	M4_PMU_PERFCTR_MAP_UOP						= 0x3b,
	M4_PMU_PERFCTR_ARM_STALL					= 0x3c,
	M4_PMU_PERFCTR_ARM_STALL_SLOT_BACKEND				= 0x3d,
	M4_PMU_PERFCTR_ARM_STALL_SLOT_FRONTEND				= 0x3e,
	M4_PMU_PERFCTR_ARM_STALL_SLOT					= 0x3f,
	M4_PMU_PERFCTR_ARM_L1D_CACHE_RD					= 0x40,
	M4_PMU_PERFCTR_MAP_DISPATCH_BUBBLE_IC				= 0x182,
	M4_PMU_PERFCTR_MAP_DISPATCH_BUBBLE_ITLB				= 0x183,
	M4_PMU_PERFCTR_DECODE_UOP					= 0x186,
	M4_PMU_PERFCTR_L1I_TLB_MISS_DEMAND				= 0x1d4,
	M4_PMU_PERFCTR_MAP_DISPATCH_BUBBLE				= 0x1d6,
	M4_PMU_PERFCTR_FETCH_RESTART					= 0x1de,
	M4_PMU_PERFCTR_MAP_DISPATCH_BUBBLE_SLOT				= 0x1e1,
	M4_PMU_PERFCTR_INTERRUPT_PENDING				= 0x26c,
	M4_PMU_PERFCTR_MAP_STALL_DISPATCH				= 0x270,
	M4_PMU_PERFCTR_MAP_REWIND					= 0x275,
	M4_PMU_PERFCTR_MAP_STALL					= 0x276,
	M4_PMU_PERFCTR_MAP_INT_UOP					= 0x27c,
	M4_PMU_PERFCTR_MAP_LDST_UOP					= 0x27d,
	M4_PMU_PERFCTR_MAP_SIMD_UOP					= 0x27e,
	M4_PMU_PERFCTR_SCHEDULE_UOP_ANY					= 0x283,
	M4_PMU_PERFCTR_MAP_INT_SME_UOP					= 0x285,
	M4_PMU_PERFCTR_SME_ENGINE_SM_ENABLE				= 0x286,
	M4_PMU_PERFCTR_SME_ENGINE_SM_ZA_ENABLE				= 0x287,
	M4_PMU_PERFCTR_SME_ENGINE_ZA_ENABLED_SM_DISABLED		= 0x288,
	M4_PMU_PERFCTR_LDST_UNIT_WAITING_SME_ENGINE_INST_QUEUE_FULL	= 0x28c,
	M4_PMU_PERFCTR_SCHEDULE_WAITING_SME_ENGINE_REG_DATA		= 0x28e,
	M4_PMU_PERFCTR_LDST_UNIT_WAITING_SME_ENGINE_MEM_DATA		= 0x28f,
	M4_PMU_PERFCTR_LDST_UNIT_OLD_L1D_CACHE_MISS			= 0x290,
	M4_PMU_PERFCTR_LDST_UNIT_WAITING_OLD_L1D_CACHE_MISS		= 0x291,
	M4_PMU_PERFCTR_LD_UNIT_WAITING_YOUNG_L1D_CACHE_MISS		= 0x294,
	M4_PMU_PERFCTR_MAP_RECOVERY					= 0x2ad,
	M4_PMU_PERFCTR_MAP_STALL_NONRECOVERY				= 0x2ae,
	M4_PMU_PERFCTR_SCHEDULE_EMPTY					= 0x351,
	M4_PMU_PERFCTR_L1I_TLB_FILL					= 0x404,
	M4_PMU_PERFCTR_L1D_TLB_FILL					= 0x405,
	M4_PMU_PERFCTR_MMU_TABLE_WALK_INSTRUCTION			= 0x407,
	M4_PMU_PERFCTR_MMU_TABLE_WALK_DATA				= 0x408,
	M4_PMU_PERFCTR_L2_TLB_MISS_INSTRUCTION				= 0x40a,
	M4_PMU_PERFCTR_L2_TLB_MISS_DATA					= 0x40b,
	M4_PMU_PERFCTR_LDST_SME_XPG_UOP					= 0x508,
	M4_PMU_PERFCTR_INST_SME_ENGINE_PACKING_FUSED			= 0x529,
	M4_PMU_PERFCTR_LD_BLOCKED_BY_SME_LDST				= 0x52c,
	M4_PMU_PERFCTR_ST_BARRIER_BLOCKED_BY_SME_LDST			= 0x52e,
	M4_PMU_PERFCTR_LD_SME_NT_UOP					= 0x573,
	M4_PMU_PERFCTR_ST_SME_NT_UOP					= 0x574,
	M4_PMU_PERFCTR_LD_SME_NORMAL_UOP				= 0x575,
	M4_PMU_PERFCTR_ST_SME_NORMAL_UOP				= 0x576,
	M4_PMU_PERFCTR_LDST_SME_PRED_INACTIVE				= 0x577,
	M4_PMU_PERFCTR_L1D_TLB_ACCESS					= 0x5a0,
	M4_PMU_PERFCTR_L1D_TLB_MISS					= 0x5a1,
	M4_PMU_PERFCTR_L1D_CACHE_MISS_ST				= 0x5a2,
	M4_PMU_PERFCTR_L1D_CACHE_MISS_LD				= 0x5a3,
	M4_PMU_PERFCTR_LD_UNIT_UOP					= 0x5a6,
	M4_PMU_PERFCTR_ST_UNIT_UOP					= 0x5a7,
	M4_PMU_PERFCTR_L1D_CACHE_WRITEBACK				= 0x5a8,
	M4_PMU_PERFCTR_LDST_X64_UOP					= 0x5b1,
	M4_PMU_PERFCTR_LDST_XPG_UOP					= 0x5b2,
	M4_PMU_PERFCTR_ATOMIC_OR_EXCLUSIVE_SUCC				= 0x5b3,
	M4_PMU_PERFCTR_ATOMIC_OR_EXCLUSIVE_FAIL				= 0x5b4,
	M4_PMU_PERFCTR_ST_NT_UOP					= 0x5e5,
	M4_PMU_PERFCTR_LD_NT_UOP					= 0x5e6,
	M4_PMU_PERFCTR_FLUSH_RESTART_OTHER_NONSPEC			= 0x884,
	M4_PMU_PERFCTR_INST_BRANCH_CALL					= 0x88e,
	M4_PMU_PERFCTR_INST_BRANCH_RET					= 0x88f,
	M4_PMU_PERFCTR_INST_BRANCH_TAKEN				= 0x890,
	M4_PMU_PERFCTR_INST_BRANCH_INDIR				= 0x893,
	M4_PMU_PERFCTR_INST_BRANCH_COND					= 0x894,
	M4_PMU_PERFCTR_INST_INT_LD					= 0x895,
	M4_PMU_PERFCTR_INST_INT_ST					= 0x896,
	M4_PMU_PERFCTR_INST_INT_ALU					= 0x897,
	M4_PMU_PERFCTR_INST_SIMD_LD					= 0x898,
	M4_PMU_PERFCTR_INST_SIMD_ST					= 0x899,
	M4_PMU_PERFCTR_INST_SIMD_ALU					= 0x89a,
	M4_PMU_PERFCTR_INST_LDST					= 0x89b,
	M4_PMU_PERFCTR_INST_BARRIER					= 0x89c,
	M4_PMU_PERFCTR_INST_SIMD_ALU_VEC				= 0x89f,
	M4_PMU_PERFCTR_INST_SME_ENGINE_SCALARFP				= 0x8a0,
	M4_PMU_PERFCTR_INST_SME_ENGINE_LD				= 0x8a1,
	M4_PMU_PERFCTR_INST_SME_ENGINE_ST				= 0x8a2,
	M4_PMU_PERFCTR_INST_SME_ENGINE_ALU				= 0x8a3,
	M4_PMU_PERFCTR_L1D_CACHE_MISS_LD_NONSPEC			= 0x8bf,
	M4_PMU_PERFCTR_L1D_CACHE_MISS_ST_NONSPEC			= 0x8c0,
	M4_PMU_PERFCTR_L1D_TLB_MISS_NONSPEC				= 0x8c1,
	M4_PMU_PERFCTR_ST_MEM_ORDER_VIOL_LD_NONSPEC			= 0x8c4,
	M4_PMU_PERFCTR_BRANCH_COND_MISPRED_NONSPEC			= 0x8c5,
	M4_PMU_PERFCTR_BRANCH_INDIR_MISPRED_NONSPEC			= 0x8c6,
	M4_PMU_PERFCTR_BRANCH_RET_INDIR_MISPRED_NONSPEC			= 0x8c8,
	M4_PMU_PERFCTR_BRANCH_CALL_INDIR_MISPRED_NONSPEC		= 0x8ca,
	M4_PMU_PERFCTR_L1I_CACHE_MISS_DEMAND				= 0x4006,
	M4_PMU_PERFCTR_LAST						= M3_PMU_CFG_EVENT,

	/*
	 * From this point onwards, these are not actual HW events,
	 * but attributes that get stored in hw->config_base.
	 */
	M4_PMU_CFG_COUNT_USER						= BIT(16),
	M4_PMU_CFG_COUNT_KERNEL						= BIT(17),
	M4_PMU_CFG_COUNT_HOST						= BIT(18),
	M4_PMU_CFG_COUNT_GUEST						= BIT(19),
};

/*
 * Per-event affinity table. Most events can be installed on counter
 * 2-9, but there are a number of exceptions. Note that this table
 * has been created experimentally, and I wouldn't be surprised if more
 * counters had strange affinities.
 */
static const u16 m1_pmu_event_affinity[M1_PMU_PERFCTR_LAST + 1] = {
	[0 ... M1_PMU_PERFCTR_LAST]				= ANY_BUT_0_1,
	[M1_PMU_PERFCTR_RETIRE_UOP]				= BIT(7),
	[M1_PMU_PERFCTR_CORE_ACTIVE_CYCLE]			= ANY_BUT_0_1 | BIT(0),
	[M1_PMU_PERFCTR_INST_ALL]				= BIT(7) | BIT(1),
	[M1_PMU_PERFCTR_INST_BRANCH]				= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_BRANCH_CALL]			= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_BRANCH_RET]			= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_BRANCH_TAKEN]			= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_BRANCH_INDIR]			= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_BRANCH_COND]			= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_INT_LD]				= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_INT_ST]				= BIT(7),
	[M1_PMU_PERFCTR_INST_INT_ALU]				= BIT(7),
	[M1_PMU_PERFCTR_INST_SIMD_LD]				= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_SIMD_ST]				= ONLY_5_6_7,
	[M1_PMU_PERFCTR_INST_SIMD_ALU]				= BIT(7),
	[M1_PMU_PERFCTR_INST_LDST]				= BIT(7),
	[M1_PMU_PERFCTR_INST_BARRIER]				= ONLY_5_6_7,
	[M1_PMU_PERFCTR_UNKNOWN_9f]				= BIT(7),
	[M1_PMU_PERFCTR_L1D_CACHE_MISS_LD_NONSPEC]		= ONLY_5_6_7,
	[M1_PMU_PERFCTR_L1D_CACHE_MISS_ST_NONSPEC]		= ONLY_5_6_7,
	[M1_PMU_PERFCTR_L1D_TLB_MISS_NONSPEC]			= ONLY_5_6_7,
	[M1_PMU_PERFCTR_ST_MEMORY_ORDER_VIOLATION_NONSPEC]	= ONLY_5_6_7,
	[M1_PMU_PERFCTR_BRANCH_COND_MISPRED_NONSPEC]		= ONLY_5_6_7,
	[M1_PMU_PERFCTR_BRANCH_INDIR_MISPRED_NONSPEC]		= ONLY_5_6_7,
	[M1_PMU_PERFCTR_BRANCH_RET_INDIR_MISPRED_NONSPEC]	= ONLY_5_6_7,
	[M1_PMU_PERFCTR_BRANCH_CALL_INDIR_MISPRED_NONSPEC]	= ONLY_5_6_7,
	[M1_PMU_PERFCTR_BRANCH_MISPRED_NONSPEC]			= ONLY_5_6_7,
	[M1_PMU_PERFCTR_UNKNOWN_f5]				= ONLY_2_4_6,
	[M1_PMU_PERFCTR_UNKNOWN_f6]				= ONLY_2_4_6,
	[M1_PMU_PERFCTR_UNKNOWN_f7]				= ONLY_2_4_6,
	[M1_PMU_PERFCTR_UNKNOWN_f8]				= ONLY_2_TO_7,
	[M1_PMU_PERFCTR_UNKNOWN_fd]				= ONLY_2_4_6,
};

struct event_affinity_16 {
	u16 event_code;
	u16 affinity;
};

static const struct event_affinity_16 m3_pmu_event_affinity[] = {
	{ M3_PMU_PERFCTR_RETIRE_UOP,				BIT(7)			},
	{ M3_PMU_PERFCTR_CORE_ACTIVE_CYCLE,			ANY_BUT_0_1 | BIT(0)	},
	{ M3_PMU_PERFCTR_INST_ALL,				BIT(7) | BIT(1)		},
	{ M3_PMU_PERFCTR_INST_BRANCH,				ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_BRANCH_CALL,			ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_BRANCH_RET,			ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_BRANCH_TAKEN,			ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_BRANCH_INDIR,			ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_INT_LD,				ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_INT_ST,				ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_INT_ALU,				BIT(7)			},
	{ M3_PMU_PERFCTR_INST_SIMD_LD,				ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_SIMD_ST,				ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_SIMD_ALU,				BIT(7)			},
	{ M3_PMU_PERFCTR_INST_LDST,				BIT(7)			},
	{ M3_PMU_PERFCTR_INST_BARRIER,				ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_INST_SIMD_ALU_VEC,			BIT(7)			},
	{ M3_PMU_PERFCTR_L1D_CACHE_MISS_LD_NONSPEC,		ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_L1D_CACHE_MISS_ST_NONSPEC,		ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_L1D_TLB_MISS_NONSPEC,			ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_ST_MEM_ORDER_VIOL_LD_NONSPEC,		ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_BRANCH_COND_MISPRED_NONSPEC,		ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_BRANCH_INDIR_MISPRED_NONSPEC,		ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_BRANCH_RET_INDIR_MISPRED_NONSPEC,	ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_BRANCH_CALL_INDIR_MISPRED_NONSPEC,	ONLY_5_6_7		},
	{ M3_PMU_PERFCTR_BRANCH_MISPRED_NONSPEC,		ONLY_5_6_7		},
};

static const struct event_affinity_16 m4_pmu_event_affinity[] = {
	{ M4_PMU_PERFCTR_INST_ALL,				ONLY_2_TO_7 | BIT(1)	},
	{ M4_PMU_PERFCTR_CORE_ACTIVE_CYCLE,			ANY_BUT_0_1 | BIT(0)	},
	{ M4_PMU_PERFCTR_INST_BRANCH,				ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_BRANCH_MISPRED_NONSPEC,		ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_RETIRE_UOP,				ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_BRANCH_CALL,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_BRANCH_RET,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_BRANCH_TAKEN,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_BRANCH_INDIR,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_BRANCH_COND,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_INT_LD,				ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_INT_ST,				ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_INT_ALU,				BIT(7)			},
	{ M4_PMU_PERFCTR_INST_SIMD_LD,				ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_SIMD_ST,				ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_SIMD_ALU,				BIT(7)			},
	{ M4_PMU_PERFCTR_INST_LDST,				BIT(7)			},
	{ M4_PMU_PERFCTR_INST_BARRIER,				ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_SIMD_ALU_VEC,			BIT(7)			},
	{ M4_PMU_PERFCTR_INST_SME_ENGINE_SCALARFP,		ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_SME_ENGINE_LD,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_SME_ENGINE_ST,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_INST_SME_ENGINE_ALU,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_L1D_CACHE_MISS_LD_NONSPEC,		ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_L1D_CACHE_MISS_ST_NONSPEC,		ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_L1D_TLB_MISS_NONSPEC,			ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_ST_MEM_ORDER_VIOL_LD_NONSPEC,		ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_BRANCH_COND_MISPRED_NONSPEC,		ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_BRANCH_INDIR_MISPRED_NONSPEC,		ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_BRANCH_RET_INDIR_MISPRED_NONSPEC,	ONLY_2_TO_7		},
	{ M4_PMU_PERFCTR_BRANCH_CALL_INDIR_MISPRED_NONSPEC,	ONLY_2_TO_7		},
};

static const unsigned int m1_pmu_perf_map[PERF_COUNT_HW_MAX] = {
	PERF_MAP_ALL_UNSUPPORTED,
	[PERF_COUNT_HW_CPU_CYCLES]		= M1_PMU_PERFCTR_CORE_ACTIVE_CYCLE,
	[PERF_COUNT_HW_INSTRUCTIONS]		= M1_PMU_PERFCTR_INST_ALL,
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= M1_PMU_PERFCTR_INST_BRANCH,
	[PERF_COUNT_HW_BRANCH_MISSES]		= M1_PMU_PERFCTR_BRANCH_MISPRED_NONSPEC,
};

static const unsigned int m3_pmu_perf_map[PERF_COUNT_HW_MAX] = {
	PERF_MAP_ALL_UNSUPPORTED,
	[PERF_COUNT_HW_CPU_CYCLES]		= M3_PMU_PERFCTR_CORE_ACTIVE_CYCLE,
	[PERF_COUNT_HW_INSTRUCTIONS]		= M3_PMU_PERFCTR_INST_ALL,
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= M3_PMU_PERFCTR_INST_BRANCH,
	[PERF_COUNT_HW_BRANCH_MISSES]		= M3_PMU_PERFCTR_BRANCH_MISPRED_NONSPEC,
};

static const unsigned int m4_pmu_perf_map[PERF_COUNT_HW_MAX] = {
	PERF_MAP_ALL_UNSUPPORTED,
	[PERF_COUNT_HW_CPU_CYCLES]		= M4_PMU_PERFCTR_CORE_ACTIVE_CYCLE,
	[PERF_COUNT_HW_INSTRUCTIONS]		= M4_PMU_PERFCTR_INST_ALL,
	[PERF_COUNT_HW_CACHE_REFERENCES]	= M4_PMU_PERFCTR_ARM_L1D_CACHE,
	[PERF_COUNT_HW_CACHE_MISSES]		= M4_PMU_PERFCTR_ARM_L1D_CACHE_REFILL,
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= M4_PMU_PERFCTR_INST_BRANCH,
	[PERF_COUNT_HW_BRANCH_MISSES]		= M4_PMU_PERFCTR_ARM_BR_MIS_PRED,
	[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND]	= M4_PMU_PERFCTR_ARM_STALL_FRONTEND,
	[PERF_COUNT_HW_STALLED_CYCLES_BACKEND]	= M4_PMU_PERFCTR_ARM_STALL_BACKEND,
};

#define M1_PMUV3_EVENT_MAP(pmuv3_event, m1_event)				\
	[ARMV8_PMUV3_PERFCTR_##pmuv3_event]	= M1_PMU_PERFCTR_##m1_event

#define M3_PMUV3_EVENT_MAP(pmuv3_event, m3_event)				\
	[ARMV8_PMUV3_PERFCTR_##pmuv3_event]	= M3_PMU_PERFCTR_##m3_event

#define M4_PMUV3_EVENT_MAP(pmuv3_event, m4_event)				\
	[ARMV8_PMUV3_PERFCTR_##pmuv3_event]	= M4_PMU_PERFCTR_##m4_event

static const u16 m1_pmu_pmceid_map[ARMV8_PMUV3_MAX_COMMON_EVENTS] = {
	[0 ... ARMV8_PMUV3_MAX_COMMON_EVENTS - 1]	= HW_OP_UNSUPPORTED,
	M1_PMUV3_EVENT_MAP(INST_RETIRED,	INST_ALL),
	M1_PMUV3_EVENT_MAP(CPU_CYCLES,		CORE_ACTIVE_CYCLE),
	M1_PMUV3_EVENT_MAP(BR_RETIRED,		INST_BRANCH),
	M1_PMUV3_EVENT_MAP(BR_MIS_PRED_RETIRED,	BRANCH_MISPRED_NONSPEC),
};

static const u16 m3_pmu_pmceid_map[ARMV8_PMUV3_MAX_COMMON_EVENTS] = {
	[0 ... ARMV8_PMUV3_MAX_COMMON_EVENTS - 1]	= HW_OP_UNSUPPORTED,
	M3_PMUV3_EVENT_MAP(INST_RETIRED,	INST_ALL),
	M3_PMUV3_EVENT_MAP(CPU_CYCLES,		CORE_ACTIVE_CYCLE),
	M3_PMUV3_EVENT_MAP(BR_RETIRED,		INST_BRANCH),
	M3_PMUV3_EVENT_MAP(BR_MIS_PRED_RETIRED,	BRANCH_MISPRED_NONSPEC),
};

static const u16 m4_pmu_pmceid_map[ARMV8_PMUV3_MAX_COMMON_EVENTS] = {
	[0 ... ARMV8_PMUV3_MAX_COMMON_EVENTS - 1]	= HW_OP_UNSUPPORTED,
	M4_PMUV3_EVENT_MAP(L1D_CACHE_REFILL,	ARM_L1D_CACHE_REFILL),
	M4_PMUV3_EVENT_MAP(L1D_CACHE,		ARM_L1D_CACHE),
	M4_PMUV3_EVENT_MAP(INST_RETIRED,	INST_ALL),
	M4_PMUV3_EVENT_MAP(BR_MIS_PRED,		ARM_BR_MIS_PRED),
	M4_PMUV3_EVENT_MAP(CPU_CYCLES,		CORE_ACTIVE_CYCLE),
	M4_PMUV3_EVENT_MAP(BR_PRED,		ARM_BR_PRED),
	M4_PMUV3_EVENT_MAP(BR_RETIRED,		INST_BRANCH),
	M4_PMUV3_EVENT_MAP(STALL_FRONTEND,	ARM_STALL_FRONTEND),
	M4_PMUV3_EVENT_MAP(STALL_BACKEND,	ARM_STALL_BACKEND),
	M4_PMUV3_EVENT_MAP(L1D_CACHE_LMISS_RD,	ARM_L1D_CACHE_LMISS_RD),
	M4_PMUV3_EVENT_MAP(STALL,		ARM_STALL),
	M4_PMUV3_EVENT_MAP(STALL_SLOT_BACKEND,	ARM_STALL_SLOT_BACKEND),
	M4_PMUV3_EVENT_MAP(STALL_SLOT_FRONTEND,	ARM_STALL_SLOT_FRONTEND),
	M4_PMUV3_EVENT_MAP(STALL_SLOT,		ARM_STALL_SLOT),
	M4_PMUV3_EVENT_MAP(BR_MIS_PRED_RETIRED,	BRANCH_MISPRED_NONSPEC),
};

/* sysfs definitions */
static ssize_t m1_pmu_events_sysfs_show(struct device *dev,
					struct device_attribute *attr,
					char *page)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);

	return sprintf(page, "event=0x%02llx\n", pmu_attr->id);
}

static ssize_t m3_pmu_events_sysfs_show(struct device *dev,
					struct device_attribute *attr,
					char *page)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);

	return sprintf(page, "event=0x%04llx\n", pmu_attr->id);
}

#define M1_PMU_EVENT_ATTR(name, config)					\
	PMU_EVENT_ATTR_ID(name, m1_pmu_events_sysfs_show, config)

#define M3_PMU_EVENT_ATTR(name, config)					\
	PMU_EVENT_ATTR_ID(name, m3_pmu_events_sysfs_show, config)

static struct attribute *m1_pmu_event_attrs[] = {
	M1_PMU_EVENT_ATTR(cycles, M1_PMU_PERFCTR_CORE_ACTIVE_CYCLE),
	M1_PMU_EVENT_ATTR(instructions, M1_PMU_PERFCTR_INST_ALL),
	NULL,
};

static struct attribute *m3_pmu_event_attrs[] = {
	M3_PMU_EVENT_ATTR(cycles, M3_PMU_PERFCTR_CORE_ACTIVE_CYCLE),
	M3_PMU_EVENT_ATTR(instructions, M3_PMU_PERFCTR_INST_ALL),
	NULL,
};

static struct attribute *m4_pmu_event_attrs[] = {
	M3_PMU_EVENT_ATTR(cycles, M4_PMU_PERFCTR_CORE_ACTIVE_CYCLE),
	M3_PMU_EVENT_ATTR(instructions, M4_PMU_PERFCTR_INST_ALL),
	NULL,
};

static const struct attribute_group m1_pmu_events_attr_group = {
	.name = "events",
	.attrs = m1_pmu_event_attrs,
};

static const struct attribute_group m3_pmu_events_attr_group = {
	.name = "events",
	.attrs = m3_pmu_event_attrs,
};

static const struct attribute_group m4_pmu_events_attr_group = {
	.name = "events",
	.attrs = m4_pmu_event_attrs,
};

PMU_FORMAT_ATTR_SHOW(event_8b, "config:0-7");
PMU_FORMAT_ATTR_SHOW(event_16b, "config:0-15");

static struct device_attribute format_attr_event_8b =
	__ATTR(event, 0444, event_8b_show, NULL);
static struct device_attribute format_attr_event_16b =
	__ATTR(event, 0444, event_16b_show, NULL);

static struct attribute *m1_pmu_format_attrs[] = {
	&format_attr_event_8b.attr,
	NULL,
};

static struct attribute *m3_pmu_format_attrs[] = {
	&format_attr_event_16b.attr,
	NULL,
};

static const struct attribute_group m1_pmu_format_attr_group = {
	.name = "format",
	.attrs = m1_pmu_format_attrs,
};

static const struct attribute_group m3_pmu_format_attr_group = {
	.name = "format",
	.attrs = m3_pmu_format_attrs,
};

/* Low level accessors. No synchronisation. */
#define PMU_READ_COUNTER(_idx)						\
	case _idx:	return read_sysreg_s(SYS_IMP_APL_PMC## _idx ##_EL1)

#define PMU_WRITE_COUNTER(_val, _idx)					\
	case _idx:							\
		write_sysreg_s(_val, SYS_IMP_APL_PMC## _idx ##_EL1);	\
		return

static u64 m1_pmu_read_hw_counter(unsigned int index)
{
	switch (index) {
		PMU_READ_COUNTER(0);
		PMU_READ_COUNTER(1);
		PMU_READ_COUNTER(2);
		PMU_READ_COUNTER(3);
		PMU_READ_COUNTER(4);
		PMU_READ_COUNTER(5);
		PMU_READ_COUNTER(6);
		PMU_READ_COUNTER(7);
		PMU_READ_COUNTER(8);
		PMU_READ_COUNTER(9);
	}

	BUG();
}

static void m1_pmu_write_hw_counter(u64 val, unsigned int index)
{
	switch (index) {
		PMU_WRITE_COUNTER(val, 0);
		PMU_WRITE_COUNTER(val, 1);
		PMU_WRITE_COUNTER(val, 2);
		PMU_WRITE_COUNTER(val, 3);
		PMU_WRITE_COUNTER(val, 4);
		PMU_WRITE_COUNTER(val, 5);
		PMU_WRITE_COUNTER(val, 6);
		PMU_WRITE_COUNTER(val, 7);
		PMU_WRITE_COUNTER(val, 8);
		PMU_WRITE_COUNTER(val, 9);
	}

	BUG();
}

#define get_bit_offset(index, mask)	(__ffs(mask) + (index))

static void __m1_pmu_enable_counter(unsigned int index, bool en)
{
	u64 val, bit;

	switch (index) {
	case 0 ... 7:
		bit = BIT(get_bit_offset(index, PMCR0_CNT_ENABLE_0_7));
		break;
	case 8 ... 9:
		bit = BIT(get_bit_offset(index - 8, PMCR0_CNT_ENABLE_8_9));
		break;
	default:
		BUG();
	}

	val = read_sysreg_s(SYS_IMP_APL_PMCR0_EL1);

	if (en)
		val |= bit;
	else
		val &= ~bit;

	write_sysreg_s(val, SYS_IMP_APL_PMCR0_EL1);
}

static void m1_pmu_enable_counter(unsigned int index)
{
	__m1_pmu_enable_counter(index, true);
}

static void m1_pmu_disable_counter(unsigned int index)
{
	__m1_pmu_enable_counter(index, false);
}

static void __m1_pmu_enable_counter_interrupt(unsigned int index, bool en)
{
	u64 val, bit;

	switch (index) {
	case 0 ... 7:
		bit = BIT(get_bit_offset(index, PMCR0_PMI_ENABLE_0_7));
		break;
	case 8 ... 9:
		bit = BIT(get_bit_offset(index - 8, PMCR0_PMI_ENABLE_8_9));
		break;
	default:
		BUG();
	}

	val = read_sysreg_s(SYS_IMP_APL_PMCR0_EL1);

	if (en)
		val |= bit;
	else
		val &= ~bit;

	write_sysreg_s(val, SYS_IMP_APL_PMCR0_EL1);
}

static void m1_pmu_enable_counter_interrupt(unsigned int index)
{
	__m1_pmu_enable_counter_interrupt(index, true);
}

static void m1_pmu_disable_counter_interrupt(unsigned int index)
{
	__m1_pmu_enable_counter_interrupt(index, false);
}

static void __m1_pmu_configure_event_filter(unsigned int index, bool user,
					    bool kernel, bool host)
{
	u64 clear, set, user_bit, kernel_bit;

	switch (index) {
	case 0 ... 7:
		user_bit = BIT(get_bit_offset(index, PMCR1_COUNT_A64_EL0_0_7));
		kernel_bit = BIT(get_bit_offset(index, PMCR1_COUNT_A64_EL1_0_7));
		break;
	case 8 ... 9:
		user_bit = BIT(get_bit_offset(index - 8, PMCR1_COUNT_A64_EL0_8_9));
		kernel_bit = BIT(get_bit_offset(index - 8, PMCR1_COUNT_A64_EL1_8_9));
		break;
	default:
		BUG();
	}

	clear = set = 0;
	if (user)
		set |= user_bit;
	else
		clear |= user_bit;

	if (kernel)
		set |= kernel_bit;
	else
		clear |= kernel_bit;

	if (host)
		sysreg_clear_set_s(SYS_IMP_APL_PMCR1_EL1, clear, set);
	else if (is_kernel_in_hyp_mode())
		sysreg_clear_set_s(SYS_IMP_APL_PMCR1_EL12, clear, set);
}

static void __apple_pmu_configure_eventsel(unsigned int index, u16 event,
					   unsigned int size, u64 mask)
{
	u64 clear = 0, set = 0;
	int shift;

	/*
	 * Counters 0 and 1 have fixed events. For anything else,
	 * place the event at the expected location in the relevant
	 * register (PMESR0 holds the event configuration for counters
	 * 2-5, resp. PMESR1 for counters 6-9).
	 */
	switch (index) {
	case 0 ... 1:
		break;
	case 2 ... 5:
		shift = (index - 2) * size;
		clear |= mask << shift;
		set |= (u64)event << shift;
		sysreg_clear_set_s(SYS_IMP_APL_PMESR0_EL1, clear, set);
		break;
	case 6 ... 9:
		shift = (index - 6) * size;
		clear |= mask << shift;
		set |= (u64)event << shift;
		sysreg_clear_set_s(SYS_IMP_APL_PMESR1_EL1, clear, set);
		break;
	}
}

static void m1_pmu_configure_counter(unsigned int index, unsigned long config_base)
{
	bool kernel = config_base & M1_PMU_CFG_COUNT_KERNEL;
	bool guest = config_base & M1_PMU_CFG_COUNT_GUEST;
	bool host = config_base & M1_PMU_CFG_COUNT_HOST;
	bool user = config_base & M1_PMU_CFG_COUNT_USER;
	u8 evt = config_base & M1_PMU_CFG_EVENT;

	__m1_pmu_configure_event_filter(index, user && host, kernel && host, true);
	__m1_pmu_configure_event_filter(index, user && guest, kernel && guest, false);
	__apple_pmu_configure_eventsel(index, evt, 8, M1_PMU_CFG_EVENT);
}

static void m3_pmu_configure_counter(unsigned int index, unsigned long config_base)
{
	bool kernel = config_base & M3_PMU_CFG_COUNT_KERNEL;
	bool guest = config_base & M3_PMU_CFG_COUNT_GUEST;
	bool host = config_base & M3_PMU_CFG_COUNT_HOST;
	bool user = config_base & M3_PMU_CFG_COUNT_USER;
	u16 evt = config_base & M3_PMU_CFG_EVENT;

	__m1_pmu_configure_event_filter(index, user && host, kernel && host, true);
	__m1_pmu_configure_event_filter(index, user && guest, kernel && guest, false);
	__apple_pmu_configure_eventsel(index, evt, 16, M3_PMU_CFG_EVENT);
}

/* arm_pmu backend */
static void m1_pmu_enable_event(struct perf_event *event)
{
	m1_pmu_configure_counter(event->hw.idx, event->hw.config_base);
	m1_pmu_enable_counter(event->hw.idx);
	m1_pmu_enable_counter_interrupt(event->hw.idx);
	isb();
}

static void m3_pmu_enable_event(struct perf_event *event)
{
	m3_pmu_configure_counter(event->hw.idx, event->hw.config_base);
	m1_pmu_enable_counter(event->hw.idx);
	m1_pmu_enable_counter_interrupt(event->hw.idx);
	isb();
}

static void m1_pmu_disable_event(struct perf_event *event)
{
	m1_pmu_disable_counter_interrupt(event->hw.idx);
	m1_pmu_disable_counter(event->hw.idx);
	isb();
}

static irqreturn_t m1_pmu_handle_irq(struct arm_pmu *cpu_pmu)
{
	struct pmu_hw_events *cpuc = this_cpu_ptr(cpu_pmu->hw_events);
	struct pt_regs *regs;
	u64 overflow, state;
	int idx;

	overflow = read_sysreg_s(SYS_IMP_APL_PMSR_EL1);
	if (!overflow) {
		/* Spurious interrupt? */
		state = read_sysreg_s(SYS_IMP_APL_PMCR0_EL1);
		state &= ~PMCR0_IACT;
		write_sysreg_s(state, SYS_IMP_APL_PMCR0_EL1);
		isb();
		return IRQ_NONE;
	}

	cpu_pmu->stop(cpu_pmu);

	regs = get_irq_regs();

	for_each_set_bit(idx, cpu_pmu->cntr_mask, M1_PMU_NR_COUNTERS) {
		struct perf_event *event = cpuc->events[idx];
		struct perf_sample_data data;

		if (!event)
			continue;

		armpmu_event_update(event);
		perf_sample_data_init(&data, 0, event->hw.last_period);
		if (!armpmu_event_set_period(event))
			continue;

		perf_event_overflow(event, &data, regs);
	}

	cpu_pmu->start(cpu_pmu);

	return IRQ_HANDLED;
}

static u64 m1_pmu_read_counter(struct perf_event *event)
{
	return m1_pmu_read_hw_counter(event->hw.idx);
}

static void m1_pmu_write_counter(struct perf_event *event, u64 value)
{
	m1_pmu_write_hw_counter(value, event->hw.idx);
	isb();
}

static int apple_pmu_get_event_idx(struct pmu_hw_events *cpuc,
				   struct perf_event *event,
				   unsigned long affinity)
{
	int idx;

	/*
	 * Place the event on the first free counter that can count
	 * this event.
	 *
	 * We could do a better job if we had a view of all the events
	 * counting on the PMU at any given time, and by placing the
	 * most constraining events first.
	 */
	for_each_set_bit(idx, &affinity, M1_PMU_NR_COUNTERS) {
		if (!test_and_set_bit(idx, cpuc->used_mask))
			return idx;
	}

	return -EAGAIN;
}

static int apple_pmu_get_event_idx_8(struct pmu_hw_events *cpuc,
				     struct perf_event *event,
				     const u16 event_affinities[M1_PMU_CFG_EVENT + 1])
{
	unsigned long evtype = event->hw.config_base & M1_PMU_CFG_EVENT;
	unsigned long affinity = event_affinities[evtype];

	return apple_pmu_get_event_idx(cpuc, event, affinity);
}

static int apple_pmu_get_event_idx_16(struct pmu_hw_events *cpuc,
				      struct perf_event *event,
				      unsigned long event_affinities_size,
				      const struct event_affinity_16 event_affinities[])
{
	unsigned long evtype = event->hw.config_base & M3_PMU_CFG_EVENT;
	unsigned long affinity = ANY_BUT_0_1;

	for (int idx = 0; idx < event_affinities_size; idx++) {
		if (event_affinities[idx].event_code == evtype) {
			affinity = event_affinities[idx].affinity;
			break;
		}
	}
	return apple_pmu_get_event_idx(cpuc, event, affinity);
}

static int m1_pmu_get_event_idx(struct pmu_hw_events *cpuc,
				struct perf_event *event)
{
	return apple_pmu_get_event_idx_8(cpuc, event, m1_pmu_event_affinity);
}

static int m3_pmu_get_event_idx(struct pmu_hw_events *cpuc,
				struct perf_event *event)
{
	return apple_pmu_get_event_idx_16(cpuc, event, ARRAY_SIZE(m3_pmu_event_affinity),
					  m3_pmu_event_affinity);
}

static int m4_pmu_get_event_idx(struct pmu_hw_events *cpuc,
				struct perf_event *event)
{
	return apple_pmu_get_event_idx_16(cpuc, event, ARRAY_SIZE(m4_pmu_event_affinity),
					  m4_pmu_event_affinity);
}

static void m1_pmu_clear_event_idx(struct pmu_hw_events *cpuc,
				   struct perf_event *event)
{
	clear_bit(event->hw.idx, cpuc->used_mask);
}

static void __m1_pmu_set_mode(u8 mode)
{
	u64 val;

	val = read_sysreg_s(SYS_IMP_APL_PMCR0_EL1);
	val &= ~(PMCR0_IMODE | PMCR0_IACT);
	val |= FIELD_PREP(PMCR0_IMODE, mode);
	write_sysreg_s(val, SYS_IMP_APL_PMCR0_EL1);
	isb();
}

static void m1_pmu_start(struct arm_pmu *cpu_pmu)
{
	__m1_pmu_set_mode(PMCR0_IMODE_FIQ);
}

static void m1_pmu_stop(struct arm_pmu *cpu_pmu)
{
	__m1_pmu_set_mode(PMCR0_IMODE_OFF);
}

static int apple_pmu_map_event(struct perf_event *event,
			       const unsigned int (*perf_map)[],
			       unsigned int flags, u32 mask)
{
	event->hw.flags |= flags;
	return armpmu_map_event(event, perf_map, NULL, mask);
}

/*
 * Apple PMU counters have been observed to be either 48 or
 * 64 bits wide, depending on the SoC. However, the MSB is
 * what triggers an overflow interrupt, so we advertise the
 * counters as being 1-bit smaller than hardware so as to
 * mimick ARM PMU behaviour
 */
static int m1_pmu_map_event(struct perf_event *event)
{
	return apple_pmu_map_event(event, &m1_pmu_perf_map, ARMPMU_EVT_47BIT,
				   M1_PMU_CFG_EVENT);
}

static int m2_pmu_map_event(struct perf_event *event)
{
	return apple_pmu_map_event(event, &m1_pmu_perf_map, ARMPMU_EVT_63BIT,
				   M1_PMU_CFG_EVENT);
}

static int m3_pmu_map_event(struct perf_event *event)
{
	return apple_pmu_map_event(event, &m3_pmu_perf_map, ARMPMU_EVT_63BIT,
				   M3_PMU_CFG_EVENT);
}

static int m4_pmu_map_event(struct perf_event *event)
{
	return apple_pmu_map_event(event, &m4_pmu_perf_map, ARMPMU_EVT_63BIT,
				   M3_PMU_CFG_EVENT);
}

static int apple_pmu_map_pmuv3_event(unsigned int eventsel, const u16 pmceid_map[])
{
	u16 apple_event = HW_OP_UNSUPPORTED;

	if (eventsel < ARMV8_PMUV3_MAX_COMMON_EVENTS)
		apple_event = pmceid_map[eventsel];

	return apple_event == HW_OP_UNSUPPORTED ? -EOPNOTSUPP : apple_event;
}

static int m1_pmu_map_pmuv3_event(unsigned int eventsel)
{
	return apple_pmu_map_pmuv3_event(eventsel, m1_pmu_pmceid_map);
}

static int m3_pmu_map_pmuv3_event(unsigned int eventsel)
{
	return apple_pmu_map_pmuv3_event(eventsel, m3_pmu_pmceid_map);
}

static int m4_pmu_map_pmuv3_event(unsigned int eventsel)
{
	return apple_pmu_map_pmuv3_event(eventsel, m4_pmu_pmceid_map);
}

static void apple_pmu_init_pmceid(struct arm_pmu *pmu)
{
	unsigned int event;

	for (event = 0; event < ARMV8_PMUV3_MAX_COMMON_EVENTS; event++) {
		if (pmu->map_pmuv3_event(event) >= 0)
			set_bit(event, pmu->pmceid_bitmap);
	}
}

static void m1_pmu_reset(void *info)
{
	int i;

	__m1_pmu_set_mode(PMCR0_IMODE_OFF);

	for (i = 0; i < M1_PMU_NR_COUNTERS; i++) {
		m1_pmu_disable_counter(i);
		m1_pmu_disable_counter_interrupt(i);
		m1_pmu_write_hw_counter(0, i);
	}

	isb();
}

static int m1_pmu_set_event_filter(struct hw_perf_event *event,
				   struct perf_event_attr *attr)
{
	unsigned long config_base = 0;

	if (!attr->exclude_guest && !is_kernel_in_hyp_mode()) {
		pr_debug("ARM performance counters do not support mode exclusion\n");
		return -EOPNOTSUPP;
	}
	if (!attr->exclude_kernel)
		config_base |= M1_PMU_CFG_COUNT_KERNEL;
	if (!attr->exclude_user)
		config_base |= M1_PMU_CFG_COUNT_USER;
	if (!attr->exclude_host)
		config_base |= M1_PMU_CFG_COUNT_HOST;
	if (!attr->exclude_guest)
		config_base |= M1_PMU_CFG_COUNT_GUEST;

	event->config_base = config_base;

	return 0;
}

static int m3_pmu_set_event_filter(struct hw_perf_event *event,
				   struct perf_event_attr *attr)
{
	unsigned long config_base = 0;

	if (!attr->exclude_guest && !is_kernel_in_hyp_mode()) {
		pr_debug("ARM performance counters do not support mode exclusion\n");
		return -EOPNOTSUPP;
	}
	if (!attr->exclude_kernel)
		config_base |= M3_PMU_CFG_COUNT_KERNEL;
	if (!attr->exclude_user)
		config_base |= M3_PMU_CFG_COUNT_USER;
	if (!attr->exclude_host)
		config_base |= M3_PMU_CFG_COUNT_HOST;
	if (!attr->exclude_guest)
		config_base |= M3_PMU_CFG_COUNT_GUEST;

	event->config_base = config_base;

	return 0;
}

static int apple_pmu_init(struct arm_pmu *cpu_pmu)
{
	cpu_pmu->handle_irq	  = m1_pmu_handle_irq;
	cpu_pmu->disable	  = m1_pmu_disable_event;
	cpu_pmu->read_counter	  = m1_pmu_read_counter;
	cpu_pmu->write_counter	  = m1_pmu_write_counter;
	cpu_pmu->clear_event_idx  = m1_pmu_clear_event_idx;
	cpu_pmu->start		  = m1_pmu_start;
	cpu_pmu->stop		  = m1_pmu_stop;
	cpu_pmu->reset		  = m1_pmu_reset;

	apple_pmu_init_pmceid(cpu_pmu);

	bitmap_set(cpu_pmu->cntr_mask, 0, M1_PMU_NR_COUNTERS);
	return 0;
}

/* Device driver gunk */
#define APPLE_PMU_INIT(gen, family)								\
static int gen ## _pmu_ ## family ## _init(struct arm_pmu *cpu_pmu)				\
{												\
	cpu_pmu->name			= "apple_" #family "_pmu";				\
	cpu_pmu->enable			= gen ## _pmu_enable_event;				\
	cpu_pmu->get_event_idx		= gen ## _pmu_get_event_idx;				\
	cpu_pmu->map_event		= gen ## _pmu_map_event;				\
	cpu_pmu->set_event_filter	= gen ## _pmu_set_event_filter;				\
												\
	cpu_pmu->map_pmuv3_event	= gen ## _pmu_map_pmuv3_event;				\
												\
	cpu_pmu->attr_groups[ARMPMU_ATTR_GROUP_EVENTS] = &gen ## _pmu_events_attr_group;	\
	cpu_pmu->attr_groups[ARMPMU_ATTR_GROUP_FORMATS] = &gen ## _pmu_format_attr_group;	\
	return apple_pmu_init(cpu_pmu);								\
}

#define m2_pmu_enable_event		m1_pmu_enable_event
#define m2_pmu_get_event_idx		m1_pmu_get_event_idx
#define m2_pmu_set_event_filter		m1_pmu_set_event_filter
#define m2_pmu_map_pmuv3_event		m1_pmu_map_pmuv3_event
#define m2_pmu_events_attr_group	m1_pmu_events_attr_group
#define m2_pmu_format_attr_group	m1_pmu_format_attr_group

#define m4_pmu_enable_event		m3_pmu_enable_event
#define m4_pmu_set_event_filter		m3_pmu_set_event_filter
#define m4_pmu_format_attr_group	m3_pmu_format_attr_group

APPLE_PMU_INIT(m1, icestorm)
APPLE_PMU_INIT(m1, firestorm)
APPLE_PMU_INIT(m2, avalanche)
APPLE_PMU_INIT(m2, blizzard)
APPLE_PMU_INIT(m3, sawtooth)
APPLE_PMU_INIT(m3, everest)
APPLE_PMU_INIT(m4, donan_e)
APPLE_PMU_INIT(m4, donan_p)
APPLE_PMU_INIT(m4, brava_e)
APPLE_PMU_INIT(m4, brava_p)

static const struct of_device_id m1_pmu_of_device_ids[] = {
	{ .compatible = "apple,brava-e-pmu",	.data = m4_pmu_brava_e_init, },
	{ .compatible = "apple,brava-p-pmu",	.data = m4_pmu_brava_p_init, },
	{ .compatible = "apple,donan-e-pmu",	.data = m4_pmu_donan_e_init, },
	{ .compatible = "apple,donan-p-pmu",	.data = m4_pmu_donan_p_init, },
	{ .compatible = "apple,sawtooth-pmu",	.data = m3_pmu_sawtooth_init, },
	{ .compatible = "apple,everest-pmu",	.data = m3_pmu_everest_init, },
	{ .compatible = "apple,avalanche-pmu",	.data = m2_pmu_avalanche_init, },
	{ .compatible = "apple,blizzard-pmu",	.data = m2_pmu_blizzard_init, },
	{ .compatible = "apple,icestorm-pmu",	.data = m1_pmu_icestorm_init, },
	{ .compatible = "apple,firestorm-pmu",	.data = m1_pmu_firestorm_init, },
	{ },
};
MODULE_DEVICE_TABLE(of, m1_pmu_of_device_ids);

static int m1_pmu_device_probe(struct platform_device *pdev)
{
	return arm_pmu_device_probe(pdev, m1_pmu_of_device_ids, NULL);
}

static struct platform_driver m1_pmu_driver = {
	.driver		= {
		.name			= "apple-m1-cpu-pmu",
		.of_match_table		= m1_pmu_of_device_ids,
		.suppress_bind_attrs	= true,
	},
	.probe		= m1_pmu_device_probe,
};

module_platform_driver(m1_pmu_driver);
