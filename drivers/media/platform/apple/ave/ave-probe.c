// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE) firmware handshake probe
 *
 * Copyright The Asahi Linux Contributors
 *
 * The encoder's coprocessor (the IOP) runs a firmware iBoot preloads; m1n1
 * reserves its __TEXT and __DATA at their DART addresses and keeps a copy
 * of __DATA. This driver powers the first encoder, restores __DATA and runs
 * the boot handshake of macOS's AppleAVE2 (AVE_HwC::StartUpIOP, 14.8.3),
 * logging every word the firmware sends back. It encodes nothing.
 *
 * The handshake goes through a mailbox block (AVE_SVECtrl): eight scratch
 * words, a doorbell to the IOP and a pending bit from it. Every register
 * write and its value is the kext's; the addresses in the comments are
 * kernelcache addresses in its rda database (AppleAVE2). The firmware's side
 * of it (CPlatformEnvironment, RealChannelCreateTarget) is the same.
 *
 * Nothing here has run on hardware: the stop_after parameter runs the
 * steps one at a time, and 0 (the default) binds nothing.
 */

#include <linux/bits.h>
#include <linux/crc32.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/unaligned.h>

enum ave_step {
	AVE_STEP_NONE,		/* touch nothing */
	AVE_STEP_POWER,		/* VENC0_SYS and VENC0_DMA on, nothing read */
	AVE_STEP_FABRIC,	/* the AXI2AF bridge's tunables, then the mailbox and IOP read */
	AVE_STEP_FIRMWARE,	/* __DATA restored, the IPC area allocated */
	AVE_STEP_FLAGS,		/* IOP flag 0, instance and device id in scratch 0-2 */
	AVE_STEP_START,		/* the IOP started, its first reply */
	AVE_STEP_IPC,		/* the IPC area sent, the firmware's address for it back */
	AVE_STEP_BOOT,		/* heap, channel memory and the boot block sent, the reply */
	AVE_STEP_RUN,		/* IOP flag 3 set, cleared by the firmware */
	AVE_STEP_CONFIG,	/* the first command, Config, through IO; the reply on IO_T2H */
	AVE_STEP_LAST = AVE_STEP_CONFIG,
};

static const char * const ave_step_names[] = {
	"none", "power", "fabric", "firmware", "flags", "start", "ipc", "boot", "run", "config",
};

static unsigned int stop_after;
module_param(stop_after, uint, 0444);
MODULE_PARM_DESC(stop_after,
		 "Run the handshake up to this step and stay bound: 0 binds nothing (default), 1 power, 2 fabric, 3 firmware, 4 flags, 5 start, 6 ipc, 7 boot, 8 run, 9 config");

static bool force_config;
module_param(force_config, bool, 0444);
MODULE_PARM_DESC(force_config,
		 "Write the IOP's firmware base (AVE_IOP_Config_Janus) although the firmware is pre-loaded");

/*
 * The mailbox (reg "mbox"), Janus's AVE_SVECtrl table (0xfffffe0007214f84):
 * the doorbell to the IOP, the pending bit from it, eight scratch words.
 */
#define AVE_MBOX_DOORBELL	0x0c
#define AVE_MBOX_PENDING	0x10
#define AVE_MBOX_PENDING_MSG	BIT(0)
#define AVE_MBOX_SCRATCH(n)	(0x18 + 4 * (n))
#define AVE_MBOX_NUM_SCRATCH	8
#define AVE_MBOX_MSG_WORDS	4

/* AVE_SVECtrl::SetIOPFlag (0xfffffe0009183130) and CheckIOPFlag */
#define AVE_IOP_FLAG		0x8042006

/* The IOP (reg "iop"), AVE_IOP_{Config,Start,CheckIdle}_Janus */
#define AVE_IOP_FW_BASE		0x50000
#define AVE_IOP_FW_BASE_MASK	GENMASK_ULL(41, 11)
#define AVE_IOP_FW_BASE_FLAGS	0x0102000000000000ULL
#define AVE_IOP_START_808	0x400808
#define AVE_IOP_CPU_CTRL	0x400044
#define AVE_IOP_CPU_CTRL_RUN	0x10
#define AVE_IOP_START_400	0x400400
#define AVE_IOP_CPU_STATUS	0x400048
/* AVE_IOP_GetCurrTime_Janus: the firmware's clock and its rate (0: 24 MHz) */
#define AVE_IOP_TIMER		0x178000
#define AVE_IOP_TIMER_HZ	0x160020

/* t6031's AVE_DevCap entry (gsc_saAVE_DevCap + 0x15 * 0x50): soc-id "t6031" */
#define AVE_DEV_ID		0x15
#define AVE_DEV_TYPE		0x13

/* AVE_IPC::Init: the shared area; AVE_ChkPool::Alloc: its granule */
#define AVE_IPC_SIZE		0xa00000
#define AVE_IPC_ALIGN		0x40

/* AVE_HwC::StartUpIOP's checks and the boot block (device arch 0x40) */
#define AVE_MAX_CHANNELS	8
#define AVE_CH_DESC_SIZE	0x100
#define AVE_CH_DIR		0x40
#define AVE_CH_SLOTS		0x48
#define AVE_CH_RING		0x4c
#define AVE_CH_SLOT_SIZE	0x40
#define AVE_CH_TYPE_HOST	1
#define AVE_MAX_CLIENT_SIZE	0x108000
#define AVE_BOOT_BLOCK_SIZE	0x50
#define AVE_BOOT_CH_MEM		0x08
#define AVE_BOOT_HEAP_ADDR	0x1c
#define AVE_BOOT_HEAP_SIZE	0x24
#define AVE_BOOT_DEV_TYPE	0x28

/*
 * AVE_HwC::MakeFwCmd_Config (0xfffffe0009135cf8) with AVE_Cfg_Default's
 * values: a command in a 0xf0-byte IPC block, 0x78 bytes of it sent.
 */
#define AVE_CMD_BLOCK_SIZE	0xf0
#define AVE_CMD_CONFIG		1
#define AVE_CMD_CONFIG_SIZE	0x78
#define AVE_CFG_TIMEOUT		0x30	/* ms (3000 x cfg +0x14), the firmware's now in ms at +0x38 */
#define AVE_CFG_TIMEOUT_MS	3000
#define AVE_CFG_TYPE3		0x48	/* cfg +0 == 3 (0 by default) */
#define AVE_CFG_ONE		0x49
#define AVE_CFG_FLAG17		0x4a	/* cfg +0x20 bit 17 (set by default) */
#define AVE_CFG_DSID		0x60	/* the memory cache's data stream: none under Linux */
#define AVE_CFG_IOPIPC		0x68	/* the IOPIPC surface's DART address, its size at +0x70 */
#define AVE_CFG_IOPIPC_SIZE	0x70
/* AVE_Drv::IO_init: surface config 0x16, "IOPIPC", 16 KiB a device, two devices */
#define AVE_IOPIPC_SIZE		(2 * SZ_16K)
#define AVE_CONFIG_TIMEOUT_US	5000000

/*
 * Timeouts, with the cfg's scale (+0x18, AVE_Cfg_Default) at 1:
 * RecvIOPMsg polls 2000 x 1 ms, the flag-3 wait 20000 x 100 us.
 */
#define AVE_RECV_POLL_US	1000
#define AVE_RECV_TIMEOUT_US	2000000
#define AVE_FLAG_POLL_US	100
#define AVE_FLAG_TIMEOUT_US	10000000

/*
 * After the power-up, AVE_HwC::PowerOn (0xfffffe000915082c) resets the power
 * estimator (AVE_DPE, skipped here) and applies the AXI2AF bridge's tunables,
 * for t6031 gsc_saAVE_AXI2AF_RegCfg_Default_Janus_6031 (0xfffffe00071f71b8):
 * each a read-modify-write, AVE_AXI2AF::ApplyTunables (0xfffffe00090d04ec).
 */
struct ave_tunable {
	u32 offset;
	u32 mask;
	u32 value;
};

static const struct ave_tunable ave_axi2af_tunables_t6031[] = {
	{ 0x000, 0x00000203, 0x00000201 },
	{ 0x00c, 0x000fffff, 0x00001681 },
	{ 0x010, 0x000fffff, 0x00001680 },
	{ 0x014, 0x00000fff, 0x000001e0 },
	{ 0x018, 0x00000fff, 0x000001e0 },
	{ 0x01c, 0x00000fff, 0x000005a0 },
	{ 0x020, 0x00000fff, 0x000005a0 },
	{ 0x024, 0x00000fff, 0x000005a0 },
	{ 0x028, 0x00000fff, 0x000005a0 },
	{ 0x02c, 0x00000fff, 0x000005a0 },
	{ 0x030, 0x00000fff, 0x000005a0 },
	{ 0x034, 0x00000fff, 0x000005a0 },
	{ 0x03c, 0xffffffff, 0x00050020 },
	{ 0x040, 0xffffffff, 0x000a0038 },
	{ 0x108, 0xffff0033, 0x00180031 },
	{ 0x10c, 0x000fffff, 0x00001681 },
	{ 0x110, 0x000fffff, 0x00001680 },
	{ 0x114, 0x00000fff, 0x000001e0 },
	{ 0x118, 0x00000fff, 0x000001e0 },
	{ 0x11c, 0x00000fff, 0x000005a0 },
	{ 0x120, 0x00000fff, 0x000005a0 },
	{ 0x124, 0x00000fff, 0x000005a0 },
	{ 0x128, 0x00000fff, 0x000005a0 },
	{ 0x12c, 0x00000fff, 0x000005a0 },
	{ 0x130, 0x00000fff, 0x000005a0 },
	{ 0x134, 0x00000fff, 0x000005a0 },
	{ 0x200, 0x800000ff, 0x8000003c },
	{ 0x204, 0x80ff00ff, 0x801a000b },
	{ 0x208, 0x80ff00ff, 0x801a000b },
	{ 0x20c, 0x80ff00ff, 0x801a000b },
	{ 0x240, 0x8000007f, 0x80000028 },
	{ 0x244, 0x807f007f, 0x80200004 },
	{ 0x248, 0x807f007f, 0x80200004 },
	{ 0x24c, 0x807f007f, 0x80200004 },
	{ 0x250, 0x8000007f, 0x80000034 },
	{ 0x600, 0xc3f103ff, 0xc0410010 },
	{ 0xc00, 0x01ffffff, 0x01ffffff },
	{ 0xd48, 0x07ff07ff, 0x00200000 },
	{ 0xe58, 0x07ff07ff, 0x00200038 },
	{ 0xf68, 0x07ff07ff, 0x01000018 },
};

struct ave_segment {
	phys_addr_t phys;
	size_t size;
	dma_addr_t iova;
};

struct ave_buf {
	void *cpu;
	dma_addr_t iova;
	size_t size;
};

struct apple_ave {
	struct device *dev;
	void __iomem *iop;
	void __iomem *mbox;
	void __iomem *axi2af;
	struct dev_pm_domain_list *pd_list;

	struct ave_segment text, data;
	phys_addr_t data_copy;

	struct ave_buf ipc, heap, iopipc;
	size_t ipc_used;
	u64 fw_ipc_base;

	u32 num_channels, channel_size, heap_size, client_size;
	void *ch_mem;
	void *boot_block;

	bool powered;
	enum ave_step done;
};

static u32 ave_mbox_read(struct apple_ave *ave, u32 off)
{
	return readl_relaxed(ave->mbox + off);
}

static void ave_mbox_write(struct apple_ave *ave, u32 off, u32 val)
{
	writel_relaxed(val, ave->mbox + off);
}

static void ave_dump_state(struct apple_ave *ave, const char *when)
{
	u32 s[AVE_MBOX_NUM_SCRATCH];
	int i;

	for (i = 0; i < AVE_MBOX_NUM_SCRATCH; i++)
		s[i] = ave_mbox_read(ave, AVE_MBOX_SCRATCH(i));

	dev_info(ave->dev,
		 "%s: pending %#x scratch %08x %08x %08x %08x %08x %08x %08x %08x iop status %#x fw base %#llx\n",
		 when, ave_mbox_read(ave, AVE_MBOX_PENDING),
		 s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
		 readl_relaxed(ave->iop + AVE_IOP_CPU_STATUS),
		 readq_relaxed(ave->iop + AVE_IOP_FW_BASE));
}

/* AVE_SVECtrl::SendIOPMsg (0xfffffe00091832bc): scratch 0-3, then SetIntr(1) */
static void ave_send(struct apple_ave *ave, const u32 *msg)
{
	int i;

	for (i = 0; i < AVE_MBOX_MSG_WORDS; i++)
		ave_mbox_write(ave, AVE_MBOX_SCRATCH(i), msg[i]);

	/* AVE_SVECtrl::SetIntr: a DSB, then the doorbell */
	mb();
	ave_mbox_write(ave, AVE_MBOX_DOORBELL, 1);

	dev_info(ave->dev, "sent %08x %08x %08x %08x\n", msg[0], msg[1], msg[2], msg[3]);
}

/*
 * AVE_SVECtrl::RecvIOPMsg (0xfffffe00091834b0): wait for the pending bit,
 * clear it (ClearIntr(1)), then read scratch 0-3.
 */
static int ave_recv(struct apple_ave *ave, u32 *msg, const char *what)
{
	ktime_t start = ktime_get();
	u32 val;
	int i, ret;

	ret = readl_relaxed_poll_timeout(ave->mbox + AVE_MBOX_PENDING, val,
					 val & AVE_MBOX_PENDING_MSG,
					 AVE_RECV_POLL_US, AVE_RECV_TIMEOUT_US);
	if (ret) {
		dev_err(ave->dev, "%s: no reply from the IOP in %d ms\n", what,
			AVE_RECV_TIMEOUT_US / 1000);
		ave_dump_state(ave, what);
		return ret;
	}

	ave_mbox_write(ave, AVE_MBOX_PENDING, AVE_MBOX_PENDING_MSG);

	for (i = 0; i < AVE_MBOX_MSG_WORDS; i++)
		msg[i] = ave_mbox_read(ave, AVE_MBOX_SCRATCH(i));

	dev_info(ave->dev, "%s: reply after %lld us (pending %#x): %08x %08x %08x %08x\n",
		 what, ktime_us_delta(ktime_get(), start), val,
		 msg[0], msg[1], msg[2], msg[3]);
	return 0;
}

/* AVE_IPC::Alloc: a 0x40-aligned piece of the IPC area */
static void *ave_ipc_alloc(struct apple_ave *ave, size_t size, size_t *offset)
{
	size_t off = ALIGN(ave->ipc_used, AVE_IPC_ALIGN);

	if (off + size > ave->ipc.size)
		return NULL;

	ave->ipc_used = off + size;
	*offset = off;
	memset(ave->ipc.cpu + off, 0, size);
	return ave->ipc.cpu + off;
}

/*
 * The firmware asserts that the IPC area and the heap are 16 KiB aligned
 * and sized (RealChannelCreateTarget, rda AppleAVE2FW_H15M_1483 0xbecac).
 */
static int ave_alloc_buf(struct apple_ave *ave, struct ave_buf *buf, size_t size,
			 const char *what)
{
	buf->cpu = dmam_alloc_coherent(ave->dev, size, &buf->iova, GFP_KERNEL);
	if (!buf->cpu)
		return -ENOMEM;

	buf->size = size;
	dev_info(ave->dev, "%s: %#zx bytes at DART %pad\n", what, size, &buf->iova);

	if (!IS_ALIGNED(buf->iova, SZ_16K) || !IS_ALIGNED(size, SZ_16K)) {
		dev_err(ave->dev, "%s is not 16 KiB aligned\n", what);
		return -EINVAL;
	}
	return 0;
}

/*
 * m1n1 appends three memory regions: __TEXT and __DATA with their DART
 * addresses ("iommu-addresses") and the copy of __DATA, which has none.
 */
static int ave_parse_firmware(struct apple_ave *ave)
{
	struct device_node *np = ave->dev->of_node;
	struct ave_segment segs[2];
	int nsegs = 0, ncopies = 0;
	struct resource copy = {};
	int i;

	for (i = 0; ; i++) {
		struct device_node *rn = of_parse_phandle(np, "memory-region", i);
		const __be32 *ia;
		struct resource res;
		int len, ret;

		if (!rn)
			break;

		ret = of_address_to_resource(rn, 0, &res);
		if (ret) {
			of_node_put(rn);
			continue;
		}

		ia = of_get_property(rn, "iommu-addresses", &len);

		if (!ia) {
			copy = res;
			ncopies++;
		} else if (len >= 5 * sizeof(*ia) && nsegs < ARRAY_SIZE(segs) &&
			   be32_to_cpup(ia) == np->phandle) {
			segs[nsegs].phys = res.start;
			segs[nsegs].size = resource_size(&res);
			segs[nsegs].iova = of_read_number(ia + 1, 2);
			if (of_read_number(ia + 3, 2) != segs[nsegs].size)
				dev_warn(ave->dev, "region %pOF: DART size %#llx, reg size %#zx\n",
					 rn, of_read_number(ia + 3, 2), segs[nsegs].size);
			nsegs++;
		}
		of_node_put(rn);
	}

	if (nsegs != 2 || ncopies != 1) {
		dev_err(ave->dev,
			"no preloaded firmware: %d segments and %d copies of __DATA in memory-region (m1n1 without AVE support?)\n",
			nsegs, ncopies);
		return -ENODEV;
	}

	if (segs[0].iova > segs[1].iova)
		swap(segs[0], segs[1]);
	ave->text = segs[0];
	ave->data = segs[1];
	ave->data_copy = copy.start;

	if (resource_size(&copy) < ave->data.size) {
		dev_err(ave->dev, "the __DATA copy is %#llx bytes, __DATA %#zx\n",
			(u64)resource_size(&copy), ave->data.size);
		return -EINVAL;
	}

	dev_info(ave->dev, "__TEXT %pa+%#zx at DART %pad, __DATA %pa+%#zx at DART %pad, copy %pa\n",
		 &ave->text.phys, ave->text.size, &ave->text.iova,
		 &ave->data.phys, ave->data.size, &ave->data.iova, &ave->data_copy);
	return 0;
}

static int ave_step_power(struct apple_ave *ave)
{
	int ret;

	ret = pm_runtime_resume_and_get(ave->dev);
	if (ret) {
		dev_err(ave->dev, "power on failed: %d\n", ret);
		return ret;
	}
	ave->powered = true;

	dev_info(ave->dev, "powered on\n");
	return 0;
}

static int ave_step_fabric(struct apple_ave *ave)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ave_axi2af_tunables_t6031); i++) {
		const struct ave_tunable *t = &ave_axi2af_tunables_t6031[i];
		u32 old = readl_relaxed(ave->axi2af + t->offset);

		writel_relaxed((old & ~t->mask) | t->value, ave->axi2af + t->offset);
		dev_dbg(ave->dev, "axi2af %#05x: %#010x -> %#010x\n", t->offset, old,
			(old & ~t->mask) | t->value);
	}

	dev_info(ave->dev, "applied %zu AXI2AF tunables\n",
		 ARRAY_SIZE(ave_axi2af_tunables_t6031));
	ave_dump_state(ave, "fabric");
	return 0;
}

/*
 * AVE_Firmware::UpdateImage (0xfffffe0009132030) for a pre-loaded image:
 * RestoreCTRRData, __DATA from the copy. The IPC area: AVE_IPC::Init.
 */
static int ave_step_firmware(struct apple_ave *ave)
{
	void *data, *copy;
	u32 crc_data, crc_copy;
	int ret;

	copy = memremap(ave->data_copy, ave->data.size, MEMREMAP_WB);
	data = memremap(ave->data.phys, ave->data.size, MEMREMAP_WC);
	if (!copy || !data) {
		dev_err(ave->dev, "cannot map __DATA or its copy\n");
		ret = -ENOMEM;
		goto out;
	}

	crc_data = crc32_le(~0, data, ave->data.size);
	crc_copy = crc32_le(~0, copy, ave->data.size);
	memcpy(data, copy, ave->data.size);
	/* __DATA reaches memory before the IOP starts */
	wmb();

	dev_info(ave->dev, "__DATA crc32 %08x, copy %08x: %s\n", crc_data, crc_copy,
		 crc_data == crc_copy ? "pristine" : "restored");

	ret = ave_alloc_buf(ave, &ave->ipc, AVE_IPC_SIZE, "IPC area");
out:
	if (data)
		memunmap(data);
	if (copy)
		memunmap(copy);
	return ret;
}

/*
 * StartUpIOP (0xfffffe000914d460): SetIOPFlag(0), scratch 1 the instance,
 * scratch 2 the device id, then AVE_IOP::Config (0xfffffe000915fa9c), which
 * writes the firmware base only for an image that is not pre-loaded.
 */
static int ave_step_flags(struct apple_ave *ave)
{
	ave_mbox_write(ave, AVE_MBOX_SCRATCH(0), AVE_IOP_FLAG);
	ave_mbox_write(ave, AVE_MBOX_SCRATCH(1), 0);
	ave_mbox_write(ave, AVE_MBOX_SCRATCH(2), AVE_DEV_ID);

	if (force_config) {
		/* AVE_IOP_Config_Janus (0xfffffe000915adbc) */
		u64 val = (ave->text.iova & AVE_IOP_FW_BASE_MASK) | AVE_IOP_FW_BASE_FLAGS;

		writeq_relaxed(val, ave->iop + AVE_IOP_FW_BASE);
		dev_info(ave->dev, "fw base %#llx written\n", val);
	}

	ave_dump_state(ave, "flags set");
	return 0;
}

/*
 * AVE_IOP_Start_Janus (0xfffffe000915b038), then the first reply: the
 * number of IPC channels (1-8), the channel memory's size, the channel
 * descriptor's size (0x100) and the firmware heap's size.
 */
static int ave_step_start(struct apple_ave *ave)
{
	u32 msg[AVE_MBOX_MSG_WORDS];
	int ret;

	writel_relaxed(1, ave->iop + AVE_IOP_START_808);
	writel_relaxed(0, ave->iop + AVE_IOP_CPU_CTRL);
	writel_relaxed(0x10000, ave->iop + AVE_IOP_START_400);
	writel(AVE_IOP_CPU_CTRL_RUN, ave->iop + AVE_IOP_CPU_CTRL);
	dev_info(ave->dev, "IOP started\n");

	ret = ave_recv(ave, msg, "start");
	if (ret)
		return ret;

	ave->num_channels = msg[0];
	ave->channel_size = msg[1];
	ave->heap_size = msg[3];
	dev_info(ave->dev, "%u channels, %#x bytes of channel memory, descriptor %#x, heap %#x\n",
		 msg[0], msg[1], msg[2], msg[3]);

	if (msg[0] < 1 || msg[0] > AVE_MAX_CHANNELS || (int)msg[1] <= 0 ||
	    msg[2] != AVE_CH_DESC_SIZE) {
		dev_err(ave->dev, "unexpected first reply\n");
		return -EPROTO;
	}

	return 0;
}

/* StartUpIOP, device arch 0x40: AVE_IPC::GetInfo sent, the firmware's base back */
static int ave_step_ipc(struct apple_ave *ave)
{
	u32 msg[AVE_MBOX_MSG_WORDS] = {
		lower_32_bits(ave->ipc.iova), upper_32_bits(ave->ipc.iova),
		ave->ipc.size, 0,
	};
	int ret;

	ave_send(ave, msg);
	ret = ave_recv(ave, msg, "ipc");
	if (ret)
		return ret;

	ave->fw_ipc_base = ((u64)msg[1] << 32) | msg[0];
	dev_info(ave->dev, "the firmware sees the IPC area at %#llx\n", ave->fw_ipc_base);
	return 0;
}

/*
 * StartUpIOP: CreateFwHeap, AllocChannelMem (zeroed), the 0x50-byte boot
 * block {+0x08 channel memory, +0x1c heap DART address, +0x24 heap size,
 * +0x28 device type} sent by its firmware address. The reply echoes the
 * channel memory's address and gives the client size (at most 0x108000);
 * the firmware has then filled the channel descriptors (AVE_IPC::CreateChannel).
 */
static int ave_step_boot(struct apple_ave *ave)
{
	u32 msg[AVE_MBOX_MSG_WORDS];
	size_t ch_off, bb_off;
	u64 echo;
	int ret, i;

	if (ave->heap_size) {
		size_t size = ALIGN(ALIGN(ave->heap_size, PAGE_SIZE), SZ_16K);

		ret = ave_alloc_buf(ave, &ave->heap, size, "firmware heap");
		if (ret)
			return ret;
	}

	ave->ch_mem = ave_ipc_alloc(ave, ave->channel_size, &ch_off);
	ave->boot_block = ave_ipc_alloc(ave, AVE_BOOT_BLOCK_SIZE, &bb_off);
	if (!ave->ch_mem || !ave->boot_block) {
		dev_err(ave->dev, "channel memory %#x does not fit the IPC area\n",
			ave->channel_size);
		return -ENOMEM;
	}

	put_unaligned_le64(ave->fw_ipc_base + ch_off, ave->boot_block + AVE_BOOT_CH_MEM);
	if (ave->heap.cpu) {
		put_unaligned_le64(ave->heap.iova, ave->boot_block + AVE_BOOT_HEAP_ADDR);
		put_unaligned_le32(ave->heap.size, ave->boot_block + AVE_BOOT_HEAP_SIZE);
	}
	put_unaligned_le32(AVE_DEV_TYPE, ave->boot_block + AVE_BOOT_DEV_TYPE);
	/* the boot block reaches memory before its address is sent */
	wmb();

	dev_info(ave->dev, "channel memory at IPC +%#zx, boot block at IPC +%#zx\n",
		 ch_off, bb_off);

	msg[0] = lower_32_bits(ave->fw_ipc_base + bb_off);
	msg[1] = upper_32_bits(ave->fw_ipc_base + bb_off);
	msg[2] = 0;
	msg[3] = 0;
	ave_send(ave, msg);

	ret = ave_recv(ave, msg, "boot");
	if (ret)
		return ret;

	echo = ((u64)msg[1] << 32) | msg[0];
	ave->client_size = msg[2];
	dev_info(ave->dev, "channel memory echoed at %#llx (expected %#llx), client size %#x\n",
		 echo, ave->fw_ipc_base + ch_off, msg[2]);

	for (i = 0; i < ave->num_channels; i++) {
		const u8 *d = ave->ch_mem + i * AVE_CH_DESC_SIZE;

		if ((i + 1) * AVE_CH_DESC_SIZE > ave->channel_size)
			break;
		dev_info(ave->dev, "channel %d: '%*pE' +0x40 %#x +0x44 %#x +0x48 %#x +0x4c %#llx\n",
			 i, (int)strnlen(d, 0x40), d,
			 get_unaligned_le32(d + 0x40), get_unaligned_le32(d + 0x44),
			 get_unaligned_le32(d + 0x48), get_unaligned_le64(d + 0x4c));
	}

	if (echo != ave->fw_ipc_base + ch_off || (int)msg[2] > AVE_MAX_CLIENT_SIZE) {
		dev_err(ave->dev, "unexpected boot reply\n");
		return -EPROTO;
	}

	return 0;
}

/* A channel's descriptor by name, as CreateChannel matches them */
static const u8 *ave_channel(struct apple_ave *ave, const char *name)
{
	int i;

	for (i = 0; i < ave->num_channels; i++) {
		const u8 *d = ave->ch_mem + i * AVE_CH_DESC_SIZE;

		if ((i + 1) * AVE_CH_DESC_SIZE > ave->channel_size)
			break;
		if (!strncmp(d, name, AVE_CH_DIR))
			return d;
	}
	return NULL;
}

/* A channel's ring, if it lies in the IPC area */
static u8 *ave_ring(struct apple_ave *ave, const u8 *d)
{
	u32 slots = get_unaligned_le32(d + AVE_CH_SLOTS);
	u64 off = get_unaligned_le64(d + AVE_CH_RING) - ave->fw_ipc_base;

	if (off >= ave->ipc_used || slots > (ave->ipc_used - off) / AVE_CH_SLOT_SIZE)
		return NULL;
	return ave->ipc.cpu + off;
}

/*
 * CreateChannel (rda AppleAVE2 0xfffffe0009162d2c), before SetIOPFlag(3):
 * the rings the host produces into (descriptor +0x40 0: IO, DEBUG, BUF_H2T)
 * get each slot's first word set to the channel's type, 1, and the next two
 * cleared (IOProcessorChannelCreate64 0xfffffe000919ecd8); a send flips the
 * type bit to hand a slot over. The firmware fills the other rings.
 */
static int ave_init_rings(struct apple_ave *ave)
{
	int i, j;

	for (i = 0; i < ave->num_channels; i++) {
		const u8 *d = ave->ch_mem + i * AVE_CH_DESC_SIZE;
		u32 slots = get_unaligned_le32(d + AVE_CH_SLOTS);
		u8 *ring;

		if (get_unaligned_le32(d + AVE_CH_DIR) != 0)
			continue;
		ring = ave_ring(ave, d);
		if (!ring) {
			dev_err(ave->dev, "channel %d: ring %#llx of %u slots outside the IPC area\n",
				i, get_unaligned_le64(d + AVE_CH_RING), slots);
			return -EPROTO;
		}

		for (j = 0; j < slots; j++) {
			put_unaligned_le64(AVE_CH_TYPE_HOST, ring + j * AVE_CH_SLOT_SIZE);
			put_unaligned_le64(0, ring + j * AVE_CH_SLOT_SIZE + 8);
			put_unaligned_le64(0, ring + j * AVE_CH_SLOT_SIZE + 16);
		}
		dev_info(ave->dev, "channel %d: %u slots set to the host\n", i, slots);
	}
	/* the slots reach memory before the flag */
	wmb();

	return 0;
}

/* The first slots of each ring the firmware wrote into, for a stuck start */
static void ave_dump_rings(struct apple_ave *ave)
{
	int i, j, n;

	for (i = 0; i < ave->num_channels; i++) {
		const u8 *d = ave->ch_mem + i * AVE_CH_DESC_SIZE;
		u32 slots = get_unaligned_le32(d + AVE_CH_SLOTS);
		const u8 *ring = ave_ring(ave, d);

		if (!ring)
			continue;
		for (j = 0, n = 0; j < slots && n < 4; j++) {
			const u8 *e = ring + j * AVE_CH_SLOT_SIZE;

			if (!get_unaligned_le64(e) && !get_unaligned_le64(e + 8))
				continue;
			dev_info(ave->dev, "channel %d slot %d: %016llx %016llx %016llx\n", i, j,
				 get_unaligned_le64(e), get_unaligned_le64(e + 8),
				 get_unaligned_le64(e + 16));
			n++;
		}
	}
}

/* StartUpIOP: SetIOPFlag(3), then CheckIOPFlag(3) until the firmware clears it */
static int ave_step_run(struct apple_ave *ave)
{
	ktime_t start = ktime_get();
	u32 val;
	int ret;

	ret = ave_init_rings(ave);
	if (ret)
		return ret;

	ave_mbox_write(ave, AVE_MBOX_SCRATCH(3), AVE_IOP_FLAG);

	ret = readl_relaxed_poll_timeout(ave->mbox + AVE_MBOX_SCRATCH(3), val, val == 0,
					 AVE_FLAG_POLL_US, AVE_FLAG_TIMEOUT_US);
	if (ret) {
		dev_err(ave->dev, "IOP flag 3 not cleared in %d ms (%#x)\n",
			AVE_FLAG_TIMEOUT_US / 1000, val);
		ave_dump_state(ave, "run");
		ave_dump_rings(ave);
		return ret;
	}

	dev_info(ave->dev, "firmware up: flag 3 cleared after %lld us\n",
		 ktime_us_delta(ktime_get(), start));
	ave_dump_state(ave, "up");
	return 0;
}

/* AVE_IOP_GetCurrTime64 (0xfffffe000915f3d4) in ms */
static u64 ave_fw_time_ms(struct apple_ave *ave)
{
	u64 ticks = readq_relaxed(ave->iop + AVE_IOP_TIMER);
	u32 hz = readl_relaxed(ave->iop + AVE_IOP_TIMER_HZ);

	return div64_u64(ticks, hz >= 1000 ? hz / 1000 : 24000);
}

/*
 * SendFwCmd_Config (0xfffffe000913701c), StartUp's first command: the
 * block's firmware address in an IO slot with the host's type bit flipped,
 * its size beside it (IOProcessorChannelSend64 0xfffffe000919ef44), then the
 * channel's doorbell bit, descriptor +0x44 (AVE_IPC::SetChIntr). The reply
 * is awaited on IO_T2H, whose slots are the host's once their low bit is 0
 * (IOProcessorChannelReceive64 0xfffffe000919f070).
 */
static int ave_step_config(struct apple_ave *ave)
{
	const u8 *io = ave_channel(ave, "IO"), *t2h = ave_channel(ave, "IO_T2H");
	u8 *io_ring = io ? ave_ring(ave, io) : NULL, *t2h_ring = t2h ? ave_ring(ave, t2h) : NULL;
	ktime_t start;
	size_t off;
	u64 fw_ms, q0;
	u8 *cmd;
	int ret;

	if (!io_ring || !t2h_ring) {
		dev_err(ave->dev, "no IO or IO_T2H ring\n");
		return -EPROTO;
	}

	ret = ave_alloc_buf(ave, &ave->iopipc, AVE_IOPIPC_SIZE, "IOPIPC surface");
	if (ret)
		return ret;
	cmd = ave_ipc_alloc(ave, AVE_CMD_BLOCK_SIZE, &off);
	if (!cmd)
		return -ENOMEM;

	fw_ms = ave_fw_time_ms(ave);
	put_unaligned_le32(AVE_CMD_CONFIG, cmd);
	put_unaligned_le64(0xffffffff, cmd + 0x1c);
	put_unaligned_le32(AVE_CFG_TIMEOUT_MS, cmd + AVE_CFG_TIMEOUT);
	put_unaligned_le64(fw_ms, cmd + AVE_CFG_TIMEOUT + 8);
	cmd[AVE_CFG_TYPE3] = 0;
	cmd[AVE_CFG_ONE] = 1;
	cmd[AVE_CFG_FLAG17] = 1;
	put_unaligned_le32(0, cmd + AVE_CFG_DSID);
	put_unaligned_le64(ave->iopipc.iova, cmd + AVE_CFG_IOPIPC);
	put_unaligned_le32(ave->iopipc.size, cmd + AVE_CFG_IOPIPC_SIZE);

	dev_info(ave->dev, "IO_T2H slot 0 before: %016llx %016llx %016llx\n",
		 get_unaligned_le64(t2h_ring), get_unaligned_le64(t2h_ring + 8),
		 get_unaligned_le64(t2h_ring + 16));

	put_unaligned_le64(AVE_CMD_CONFIG_SIZE, io_ring + 8);
	put_unaligned_le64(0, io_ring + 16);
	/* the block and the size reach memory before the slot changes hands */
	wmb();
	put_unaligned_le64((AVE_CH_TYPE_HOST ^ 1) | (ave->fw_ipc_base + off), io_ring);
	/* the slot reaches memory before the doorbell */
	wmb();
	start = ktime_get();
	ave_mbox_write(ave, AVE_MBOX_DOORBELL, BIT(get_unaligned_le32(io + 0x44)));
	dev_info(ave->dev, "config sent: block IPC +%#zx, firmware time %llu ms, IOPIPC %pad\n",
		 off, fw_ms, &ave->iopipc.iova);

	ret = read_poll_timeout(get_unaligned_le64, q0, !(q0 & 1) && (q0 & ~3ULL),
				AVE_RECV_POLL_US, AVE_CONFIG_TIMEOUT_US, false, t2h_ring);
	dev_info(ave->dev, "IO slot 0 after: %016llx %016llx\n", get_unaligned_le64(io_ring),
		 get_unaligned_le64(io_ring + 8));
	ave_dump_state(ave, "config");
	if (ret) {
		dev_err(ave->dev, "no reply on IO_T2H in %d ms\n", AVE_CONFIG_TIMEOUT_US / 1000);
		ave_dump_rings(ave);
		return ret;
	}

	dev_info(ave->dev, "reply after %lld us: %016llx %016llx %016llx\n",
		 ktime_us_delta(ktime_get(), start), q0, get_unaligned_le64(t2h_ring + 8),
		 get_unaligned_le64(t2h_ring + 16));
	off = (q0 & ~3ULL) - ave->fw_ipc_base;
	if (off < ave->ipc.size && ave->ipc.size - off >= 0x40)
		print_hex_dump(KERN_INFO, "ave reply: ", DUMP_PREFIX_OFFSET, 16, 4,
			       ave->ipc.cpu + off, 0x40, false);
	return 0;
}

static int (* const ave_steps[])(struct apple_ave *ave) = {
	[AVE_STEP_POWER] = ave_step_power,
	[AVE_STEP_FABRIC] = ave_step_fabric,
	[AVE_STEP_FIRMWARE] = ave_step_firmware,
	[AVE_STEP_FLAGS] = ave_step_flags,
	[AVE_STEP_START] = ave_step_start,
	[AVE_STEP_IPC] = ave_step_ipc,
	[AVE_STEP_BOOT] = ave_step_boot,
	[AVE_STEP_RUN] = ave_step_run,
	[AVE_STEP_CONFIG] = ave_step_config,
};

/*
 * AVE_HwC::PowerOff (0xfffffe0009150fcc): GetIntr and ClearIntr, then the
 * domains off. The IOP gets no halt command first (macOS's ShutDownIOP sends
 * one over an IPC channel): powering its domain off stops it.
 */
static void ave_power_off(struct apple_ave *ave)
{
	u32 pending, status;

	if (!ave->powered)
		return;

	/* AVE_IOP_CheckIdle_Janus: bits 1:0 set once the IOP is idle */
	status = readl_relaxed(ave->iop + AVE_IOP_CPU_STATUS);
	pending = ave_mbox_read(ave, AVE_MBOX_PENDING);
	ave_mbox_write(ave, AVE_MBOX_PENDING, pending);
	ave->powered = false;
	pm_runtime_put_sync(ave->dev);
	dev_info(ave->dev, "powered off (pending was %#x, iop status %#x: %s)\n", pending,
		 status, status & 3 ? "idle" : "running");
}

static ssize_t state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct apple_ave *ave = dev_get_drvdata(dev);
	int len, i;

	len = sysfs_emit(buf, "step %s\n", ave_step_names[ave->done]);
	if (!ave->powered)
		return len;

	len += sysfs_emit_at(buf, len, "pending %#x\n", ave_mbox_read(ave, AVE_MBOX_PENDING));
	for (i = 0; i < AVE_MBOX_NUM_SCRATCH; i++)
		len += sysfs_emit_at(buf, len, "scratch%d %#010x\n", i,
				     ave_mbox_read(ave, AVE_MBOX_SCRATCH(i)));
	len += sysfs_emit_at(buf, len, "iop status %#x\n",
			     readl_relaxed(ave->iop + AVE_IOP_CPU_STATUS));
	len += sysfs_emit_at(buf, len, "fw base %#llx\n",
			     readq_relaxed(ave->iop + AVE_IOP_FW_BASE));
	return len;
}
static DEVICE_ATTR_RO(state);

static struct attribute *ave_attrs[] = {
	&dev_attr_state.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ave);

static int apple_ave_probe(struct platform_device *pdev)
{
	static const char * const pd_names[] = { "sys", "dma" };
	const struct dev_pm_domain_attach_data pd_data = {
		.pd_names = pd_names,
		.num_pd_names = ARRAY_SIZE(pd_names),
	};
	struct device *dev = &pdev->dev;
	struct apple_ave *ave;
	unsigned int step, last;
	int ret;

	if (!stop_after) {
		dev_info(dev, "not started: load with stop_after=1..%d\n", AVE_STEP_LAST);
		return -ENODEV;
	}

	ave = devm_kzalloc(dev, sizeof(*ave), GFP_KERNEL);
	if (!ave)
		return -ENOMEM;
	ave->dev = dev;
	platform_set_drvdata(pdev, ave);

	ave->iop = devm_platform_ioremap_resource_byname(pdev, "iop");
	if (IS_ERR(ave->iop))
		return PTR_ERR(ave->iop);
	ave->mbox = devm_platform_ioremap_resource_byname(pdev, "mbox");
	if (IS_ERR(ave->mbox))
		return PTR_ERR(ave->mbox);
	ave->axi2af = devm_platform_ioremap_resource_byname(pdev, "axi2af");
	if (IS_ERR(ave->axi2af))
		return PTR_ERR(ave->axi2af);

	if (!device_iommu_mapped(dev))
		return dev_err_probe(dev, -ENODEV, "no DART\n");

	ret = ave_parse_firmware(ave);
	if (ret)
		return ret;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret)
		return ret;

	ret = devm_pm_domain_attach_list(dev, &pd_data, &ave->pd_list);
	if (ret < 0)
		return dev_err_probe(dev, ret, "cannot attach the power domains\n");

	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return ret;

	last = min_t(unsigned int, stop_after, AVE_STEP_LAST);
	for (step = AVE_STEP_POWER; step <= last; step++) {
		dev_info(dev, "step %d: %s\n", step, ave_step_names[step]);
		ret = ave_steps[step](ave);
		if (ret) {
			dev_err(dev, "step %d (%s) failed: %d\n", step, ave_step_names[step], ret);
			ave_power_off(ave);
			return ret;
		}
		ave->done = step;
	}

	dev_info(dev, "stopped after step %d (%s), bound until unloaded\n", ave->done,
		 ave_step_names[ave->done]);
	return 0;
}

static void apple_ave_remove(struct platform_device *pdev)
{
	ave_power_off(platform_get_drvdata(pdev));
}

static const struct of_device_id apple_ave_of_match[] = {
	{ .compatible = "apple,t6031-ave" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, apple_ave_of_match);

static struct platform_driver apple_ave_driver = {
	.driver = {
		.name = "apple-ave-probe",
		.of_match_table = apple_ave_of_match,
		.dev_groups = ave_groups,
	},
	.probe = apple_ave_probe,
	.remove = apple_ave_remove,
};
module_platform_driver(apple_ave_driver);

MODULE_DESCRIPTION("Apple video encoder firmware handshake probe");
MODULE_LICENSE("GPL");
