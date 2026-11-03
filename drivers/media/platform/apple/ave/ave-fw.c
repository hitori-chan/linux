// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): the firmware's boot and channels
 *
 * Copyright The Asahi Linux Contributors
 *
 * The encoder's coprocessor (the IOP) runs a firmware iBoot preloads; m1n1
 * reserves its __TEXT and __DATA at their DART addresses and keeps a copy of
 * __DATA. Each session boots it again, as macOS's AppleAVE2 does
 * (AVE_HwC::StartUpIOP, 14.8.3), through a mailbox block (AVE_SVECtrl): eight
 * scratch words, a doorbell to the IOP and pending bits from it. Every register
 * write and its value is the kext's; the addresses in the comments are
 * kernelcache addresses in its rda database (AppleAVE2). The firmware's side of
 * it (CPlatformEnvironment, RealChannelCreateTarget) is the same.
 */

#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "ave.h"

/*
 * The mailbox (reg "mbox"), Janus's AVE_SVECtrl table (0xfffffe0007214f84):
 * the doorbell to the IOP, the pending bit from it, eight scratch words.
 */
#define AVE_MBOX_DOORBELL	0x0c
#define AVE_MBOX_PENDING	0x10
#define AVE_MBOX_PENDING_MSG	BIT(0)
#define AVE_MBOX_SCRATCH(n)	(0x18 + 4 * (n))
#define AVE_MBOX_NUM_SCRATCH	8
/* AVE_SVECtrl::SetIdle: the block's clock gating */
#define AVE_MBOX_IDLE		0x38
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
#define AVE_IOP_CPU_IDLE	GENMASK(1, 0)
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
#define AVE_CMD_TIMEOUT_US	5000000

/*
 * Timeouts, with the cfg's scale (+0x18, AVE_Cfg_Default) at 1:
 * RecvIOPMsg polls 2000 x 1 ms, the flag-3 wait 20000 x 100 us.
 */
#define AVE_RECV_POLL_US	1000
#define AVE_WAIT_POLL_US	100
#define AVE_RECV_TIMEOUT_US	2000000
#define AVE_FLAG_POLL_US	100
#define AVE_FLAG_TIMEOUT_US	10000000
/* ShutDownIOP: AVE_IOP::Stop's idle polls (10000 x 50 us), then scratch 0's (10000 x 100 us) */
#define AVE_IDLE_POLL_US	50
#define AVE_IDLE_READS		3
#define AVE_HALT_TIMEOUT_US	1000000

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

	dev_err(ave->dev,
		"%s: pending %#x scratch %08x %08x %08x %08x %08x %08x %08x %08x iop status %#x\n",
		when, ave_mbox_read(ave, AVE_MBOX_PENDING),
		s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
		readl_relaxed(ave->iop + AVE_IOP_CPU_STATUS));
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
}

/*
 * AVE_SVECtrl::RecvIOPMsg (0xfffffe00091834b0): wait for the pending bit,
 * clear it (ClearIntr(1)), then read scratch 0-3.
 */
static int ave_recv(struct apple_ave *ave, u32 *msg, const char *what)
{
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

	return 0;
}

/* AVE_IPC::Alloc: a 0x40-aligned piece of the IPC area */
void *ave_ipc_alloc(struct apple_ave *ave, size_t size, size_t *offset)
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
	if (buf->cpu) {
		memset(buf->cpu, 0, buf->size);
		return 0;
	}

	buf->cpu = dmam_alloc_coherent(ave->dev, size, &buf->iova, GFP_KERNEL);
	if (!buf->cpu)
		return -ENOMEM;

	buf->size = size;
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
int ave_fw_parse(struct apple_ave *ave)
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

	return 0;
}

static void ave_fabric(struct apple_ave *ave)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ave_axi2af_tunables_t6031); i++) {
		const struct ave_tunable *t = &ave_axi2af_tunables_t6031[i];
		u32 old = readl_relaxed(ave->axi2af + t->offset);

		writel_relaxed((old & ~t->mask) | t->value, ave->axi2af + t->offset);
	}
}

/*
 * AVE_Firmware::UpdateImage (0xfffffe0009132030) for a pre-loaded image:
 * RestoreCTRRData, __DATA from the copy. The IPC area: AVE_IPC::Init.
 */
static int ave_restore_data(struct apple_ave *ave)
{
	void *data, *copy;
	int ret = -ENOMEM;

	copy = memremap(ave->data_copy, ave->data.size, MEMREMAP_WB);
	data = memremap(ave->data.phys, ave->data.size, MEMREMAP_WC);
	if (!copy || !data) {
		dev_err(ave->dev, "cannot map __DATA or its copy\n");
		goto out;
	}

	memcpy(data, copy, ave->data.size);
	/* __DATA reaches memory before the IOP starts */
	wmb();

	ave->ipc_used = 0;
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
 * scratch 2 the device id; AVE_IOP::Config writes the firmware base only for
 * an image that is not pre-loaded. Then AVE_IOP_Start_Janus (0xfffffe000915b038)
 * and the first reply: the number of IPC channels (1-8), the channel memory's
 * size, the channel descriptor's size (0x100) and the firmware heap's size.
 */
static int ave_start_iop(struct apple_ave *ave)
{
	u32 msg[AVE_MBOX_MSG_WORDS];
	int ret;

	ave_mbox_write(ave, AVE_MBOX_SCRATCH(0), AVE_IOP_FLAG);
	ave_mbox_write(ave, AVE_MBOX_SCRATCH(1), ave->instance);
	ave_mbox_write(ave, AVE_MBOX_SCRATCH(2), AVE_DEV_ID);

	writel_relaxed(1, ave->iop + AVE_IOP_START_808);
	writel_relaxed(0, ave->iop + AVE_IOP_CPU_CTRL);
	writel_relaxed(0x10000, ave->iop + AVE_IOP_START_400);
	writel(AVE_IOP_CPU_CTRL_RUN, ave->iop + AVE_IOP_CPU_CTRL);

	ret = ave_recv(ave, msg, "start");
	if (ret)
		return ret;

	ave->num_channels = msg[0];
	ave->channel_size = msg[1];
	ave->heap_size = msg[3];
	if (msg[0] < 1 || msg[0] > AVE_MAX_CHANNELS || (int)msg[1] <= 0 ||
	    msg[2] != AVE_CH_DESC_SIZE) {
		dev_err(ave->dev, "unexpected first reply %08x %08x %08x %08x\n",
			msg[0], msg[1], msg[2], msg[3]);
		return -EPROTO;
	}

	return 0;
}

/* StartUpIOP, device arch 0x40: AVE_IPC::GetInfo sent, the firmware's base back */
static int ave_send_ipc(struct apple_ave *ave)
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
	return 0;
}

/*
 * StartUpIOP: CreateFwHeap, AllocChannelMem (zeroed), the 0x50-byte boot
 * block {+0x08 channel memory, +0x1c heap DART address, +0x24 heap size,
 * +0x28 device type} sent by its firmware address. The reply echoes the
 * channel memory's address and gives the client size (at most 0x108000);
 * the firmware has then filled the channel descriptors (AVE_IPC::CreateChannel).
 */
static int ave_send_boot(struct apple_ave *ave)
{
	u32 msg[AVE_MBOX_MSG_WORDS];
	size_t ch_off, bb_off;
	void *boot_block;
	u64 echo;
	int ret;

	if (ave->heap_size) {
		size_t size = ALIGN(ALIGN(ave->heap_size, PAGE_SIZE), SZ_16K);

		ret = ave_alloc_buf(ave, &ave->heap, size, "firmware heap");
		if (ret)
			return ret;
	}

	ave->ch_mem = ave_ipc_alloc(ave, ave->channel_size, &ch_off);
	boot_block = ave_ipc_alloc(ave, AVE_BOOT_BLOCK_SIZE, &bb_off);
	if (!ave->ch_mem || !boot_block) {
		dev_err(ave->dev, "channel memory %#x does not fit the IPC area\n",
			ave->channel_size);
		return -ENOMEM;
	}

	put_unaligned_le64(ave->fw_ipc_base + ch_off, boot_block + AVE_BOOT_CH_MEM);
	if (ave->heap.cpu) {
		put_unaligned_le64(ave->heap.iova, boot_block + AVE_BOOT_HEAP_ADDR);
		put_unaligned_le32(ave->heap.size, boot_block + AVE_BOOT_HEAP_SIZE);
	}
	put_unaligned_le32(AVE_DEV_TYPE, boot_block + AVE_BOOT_DEV_TYPE);
	/* the boot block reaches memory before its address is sent */
	wmb();

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
	if (echo != ave->fw_ipc_base + ch_off || (int)msg[2] > AVE_MAX_CLIENT_SIZE) {
		dev_err(ave->dev, "unexpected boot reply %#llx, client size %#x\n", echo, msg[2]);
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
	}
	/* the slots reach memory before the flag */
	wmb();

	return 0;
}

/* StartUpIOP: SetIOPFlag(3), then CheckIOPFlag(3) until the firmware clears it */
static int ave_run(struct apple_ave *ave)
{
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
	}
	return ret;
}

/*
 * AVE_HwC::ProcessIntr_IPCMem (0xfffffe0009149318): the firmware asks the host
 * for memory on SHAREDMALLOC, a slot of (address, size, tag) with the
 * host's type bit, 0. Address 0 asks for size bytes (AVE_IPC::Alloc, from
 * the pool over the whole IPC area), any other frees that block; either way
 * the host answers in the same slot, the block's address and size (0 for a
 * free) with the bit flipped back, then rings the channel's doorbell
 * (IOProcessorChannelSend64 0xfffffe000919ef44 and its callback). The free
 * is acknowledged only: a session's IPC area is reused only at the next boot.
 */
static void ave_serve_malloc(struct apple_ave *ave, const u8 *d, u8 *ring)
{
	u32 *next = &ave->sm_next;
	u32 slots = get_unaligned_le32(d + AVE_CH_SLOTS);

	while (slots) {
		u8 *e = ring + *next * AVE_CH_SLOT_SIZE;
		u64 q0 = get_unaligned_le64(e), size = get_unaligned_le64(e + 8);
		u64 tag = get_unaligned_le64(e + 16), addr = q0 & ~3ULL;
		size_t off = 0;

		if (q0 & 1)
			return;
		if (!addr) {
			if (!ave_ipc_alloc(ave, size, &off)) {
				dev_err_ratelimited(ave->dev,
						    "shared malloc: no room for %#llx bytes (tag %#llx)\n",
						    size, tag);
				return;
			}
			addr = ave->fw_ipc_base + off;
		} else {
			size = 0;
		}
		put_unaligned_le64(size, e + 8);
		put_unaligned_le64(0, e + 16);
		/* the size reaches memory before the slot changes hands */
		wmb();
		put_unaligned_le64(1 | addr, e);
		/* the slot reaches memory before the doorbell */
		wmb();
		ave_mbox_write(ave, AVE_MBOX_DOORBELL, BIT(get_unaligned_le32(d + 0x44)));
		*next = (*next + 1) % slots;
	}
}

/*
 * The firmware's own commands on IO_T2H: ProcessIntr_IPCCh sends each one
 * straight back in its slot (AVE_IPC::Send on channel 2), which hands the
 * slot over, then handles it (ProcessIntr_Cmd): the replies to the host's
 * commands, each with the command's id.
 */
static void ave_serve_t2h(struct apple_ave *ave, const u8 *d, u8 *ring)
{
	u32 slots = get_unaligned_le32(d + AVE_CH_SLOTS);

	while (slots) {
		u8 *e = ring + ave->t2h_next * AVE_CH_SLOT_SIZE;
		u64 q0 = get_unaligned_le64(e);
		size_t off = (q0 & ~3ULL) - ave->fw_ipc_base;

		if (q0 & 1)
			return;
		if (off < ave->ipc.size - 2) {
			u16 id = get_unaligned_le16(ave->ipc.cpu + off);

			dev_dbg(ave->dev, "IO_T2H slot %u: id %u, status %#x\n", ave->t2h_next, id,
				get_unaligned_le32(ave->ipc.cpu + off + 0x40));
			if (id <= AVE_CMD_MAX)
				ave->t2h_seen[id]++;
		}
		put_unaligned_le64(0, e + 16);
		/* the cleared word reaches memory before the slot changes hands */
		wmb();
		put_unaligned_le64(q0 | 1, e);
		/* the slot reaches memory before the doorbell */
		wmb();
		ave_mbox_write(ave, AVE_MBOX_DOORBELL, BIT(get_unaligned_le32(d + 0x44)));
		ave->t2h_next = (ave->t2h_next + 1) % slots;
	}
}

/* AVE_IOP_GetCurrTime64 (0xfffffe000915f3d4) in ms */
u64 ave_fw_time_ms(struct apple_ave *ave)
{
	u64 ticks = readq_relaxed(ave->iop + AVE_IOP_TIMER);
	u32 hz = readl_relaxed(ave->iop + AVE_IOP_TIMER_HZ);

	return div64_u64(ticks, hz >= 1000 ? hz / 1000 : 24000);
}

/*
 * The firmware's log on TERMINAL: each slot a line's address in its LOG block
 * (the first shared malloc) and its length. macOS logs them (ProcessIntr_IPCCh's
 * default case); each is printed once and the slots left as they are.
 */
static void ave_print_terminal(struct apple_ave *ave)
{
	const u8 *d = ave_channel(ave, "TERMINAL");
	u8 *ring = d ? ave_ring(ave, d) : NULL;
	u32 slots = d ? get_unaligned_le32(d + AVE_CH_SLOTS) : 0;

	while (ring && ave->term_next < slots) {
		const u8 *e = ring + ave->term_next * AVE_CH_SLOT_SIZE;
		u64 size = get_unaligned_le64(e + 8);
		size_t off = (get_unaligned_le64(e) & ~3ULL) - ave->fw_ipc_base;

		if (!size)
			return;
		if (off < ave->ipc.size && size <= ave->ipc.size - off)
			dev_dbg(ave->dev, "fw: %*pE\n", (int)min_t(u64, size, 256),
				ave->ipc.cpu + off);
		ave->term_next++;
	}
}

/* The firmware's traffic: its memory requests, its commands, its log; the pending bits cleared */
static void ave_serve(struct apple_ave *ave)
{
	const u8 *sm = ave_channel(ave, "SHAREDMALLOC"), *t2h = ave_channel(ave, "IO_T2H");
	u32 pending = ave_mbox_read(ave, AVE_MBOX_PENDING);
	u8 *ring;

	if (pending)
		ave_mbox_write(ave, AVE_MBOX_PENDING, pending);
	ring = sm ? ave_ring(ave, sm) : NULL;
	if (ring)
		ave_serve_malloc(ave, sm, ring);
	ring = t2h ? ave_ring(ave, t2h) : NULL;
	if (ring)
		ave_serve_t2h(ave, t2h, ring);
	ave_print_terminal(ave);
}

/*
 * AVE_IPC::Send on channel 1, IO (IOProcessorChannelSend64
 * 0xfffffe000919ef44): a command block's firmware address in the next IO slot
 * with the host's type bit flipped, its size beside it, then the channel's
 * doorbell bit, descriptor +0x44 (AVE_IPC::SetChIntr). The firmware hands the
 * slot back when it has taken the block (ProcessIntr_CmdAck).
 */
int ave_fw_send(struct apple_ave *ave, size_t off, u32 size)
{
	const u8 *io = ave_channel(ave, "IO");
	u8 *ring = io ? ave_ring(ave, io) : NULL, *e;
	u32 slot = ave->io_next, val;
	u64 q;
	int ret;

	if (!ring) {
		dev_err(ave->dev, "no IO ring\n");
		return -EPROTO;
	}

	e = ring + slot * AVE_CH_SLOT_SIZE;
	ret = read_poll_timeout(get_unaligned_le64, q, (q & 1) == AVE_CH_TYPE_HOST,
				AVE_RECV_POLL_US, AVE_RECV_TIMEOUT_US, false, e);
	if (ret) {
		dev_err(ave->dev, "IO slot %u still with the firmware: %#llx\n", slot, q);
		return ret;
	}

	put_unaligned_le64(size, e + 8);
	put_unaligned_le64(0, e + 16);
	/* the block and the size reach memory before the slot changes hands */
	wmb();
	put_unaligned_le64((AVE_CH_TYPE_HOST ^ 1) | (ave->fw_ipc_base + off), e);
	/* the slot reaches memory before the doorbell */
	wmb();
	val = BIT(get_unaligned_le32(io + 0x44));
	ave_mbox_write(ave, AVE_MBOX_DOORBELL, val);
	ave->io_next = (slot + 1) % get_unaligned_le32(io + AVE_CH_SLOTS);
	return 0;
}

/* Until the firmware has replied past seen times to a command, serving it meanwhile */
int ave_fw_wait(struct apple_ave *ave, unsigned int cmd, u32 seen, unsigned int timeout_us)
{
	ktime_t start = ktime_get();

	for (;;) {
		ave_serve(ave);
		if (ave->t2h_seen[cmd] != seen)
			return 0;
		if (ktime_us_delta(ktime_get(), start) > timeout_us)
			break;
		usleep_range(AVE_WAIT_POLL_US, 2 * AVE_WAIT_POLL_US);
	}

	dev_err(ave->dev, "no reply to command %u in %u ms\n", cmd, timeout_us / 1000);
	ave_dump_state(ave, "wait");
	return -ETIMEDOUT;
}

int ave_fw_command(struct apple_ave *ave, size_t off, u32 size, unsigned int cmd)
{
	u32 seen = ave->t2h_seen[cmd];
	int ret;

	ret = ave_fw_send(ave, off, size);
	if (ret)
		return ret;
	return ave_fw_wait(ave, cmd, seen, AVE_CMD_TIMEOUT_US);
}

/* A command block's header (AVE_HwC::MakeFwCmd_*): the command, then the timeout at +0x30 */
static u8 *ave_cmd_block(struct apple_ave *ave, u32 cmd, size_t *off)
{
	u8 *b = ave_ipc_alloc(ave, AVE_CMD_BLOCK_SIZE, off);

	if (!b)
		return NULL;
	put_unaligned_le32(cmd, b);
	put_unaligned_le64(0xffffffff, b + 0x1c);
	put_unaligned_le32(AVE_CFG_TIMEOUT_MS, b + AVE_CFG_TIMEOUT);
	put_unaligned_le64(ave_fw_time_ms(ave), b + AVE_CFG_TIMEOUT + 8);
	return b;
}

/*
 * SendFwCmd_Config (0xfffffe000913701c), StartUp's first command
 * (MakeFwCmd_Config 0xfffffe0009135cf8)
 */
static int ave_send_config(struct apple_ave *ave)
{
	size_t off;
	u8 *cmd;
	int ret;

	ret = ave_alloc_buf(ave, &ave->iopipc, AVE_IOPIPC_SIZE, "IOPIPC surface");
	if (ret)
		return ret;
	cmd = ave_cmd_block(ave, AVE_CMD_CONFIG, &off);
	if (!cmd)
		return -ENOMEM;
	cmd[AVE_CFG_TYPE3] = 0;
	cmd[AVE_CFG_ONE] = 1;
	cmd[AVE_CFG_FLAG17] = 1;
	put_unaligned_le32(0, cmd + AVE_CFG_DSID);
	put_unaligned_le64(ave->iopipc.iova, cmd + AVE_CFG_IOPIPC);
	put_unaligned_le32(ave->iopipc.size, cmd + AVE_CFG_IOPIPC_SIZE);

	/* AVE_PMGR::SetClockGating(0): AVE_SVECtrl::SetIdle, before the first doorbell */
	ave_mbox_write(ave, AVE_MBOX_IDLE, 0);

	return ave_fw_command(ave, off, AVE_CMD_CONFIG_SIZE, AVE_CMD_CONFIG);
}

/*
 * The power domains on and the firmware up, to its Config: AVE_HwC::PowerOn
 * (0xfffffe000915082c), which also resets the power estimator (AVE_DPE, not
 * done here), then StartUpIOP.
 */
int ave_fw_boot(struct apple_ave *ave)
{
	int ret;

	ret = pm_runtime_resume_and_get(ave->dev);
	if (ret) {
		dev_err(ave->dev, "power on failed: %d\n", ret);
		return ret;
	}

	ave->io_next = 0;
	ave->t2h_next = 0;
	ave->sm_next = 0;
	ave->term_next = 0;
	ave->seq = 0;
	memset(ave->t2h_seen, 0, sizeof(ave->t2h_seen));

	ave_fabric(ave);
	ret = ave_restore_data(ave);
	if (!ret)
		ret = ave_start_iop(ave);
	if (!ret)
		ret = ave_send_ipc(ave);
	if (!ret)
		ret = ave_send_boot(ave);
	if (!ret)
		ret = ave_run(ave);
	if (!ret)
		ret = ave_send_config(ave);
	if (ret)
		ave_fw_shutdown(ave, false);
	return ret;
}

/*
 * ShutDownIOP (0xfffffe000914fd08): SendFwCmd_Halt (0xfffffe0009137678)
 * clears scratch 0 and sends the header alone (MakeFwCmd_Halt
 * 0xfffffe00091360fc, 0x48 bytes) with no ack awaited; AVE_IOP::Stop
 * (0xfffffe0009160178) polls CheckIdle until it reads idle three times
 * running, then ShutDownIOP polls scratch 0 until the firmware has put the
 * IOP flag back.
 */
static int ave_halt(struct apple_ave *ave)
{
	ktime_t start;
	int idle = 0, ret;
	size_t off;
	u32 val;

	if (!ave_cmd_block(ave, AVE_CMD_HALT, &off))
		return -ENOMEM;
	ave_mbox_write(ave, AVE_MBOX_SCRATCH(0), 0);
	start = ktime_get();
	ret = ave_fw_send(ave, off, AVE_CMD_SMALL_SIZE);
	if (ret)
		return ret;

	while (idle < AVE_IDLE_READS) {
		ave_serve(ave);
		if (readl_relaxed(ave->iop + AVE_IOP_CPU_STATUS) & AVE_IOP_CPU_IDLE)
			idle++;
		else
			idle = 0;
		if (ktime_us_delta(ktime_get(), start) > AVE_HALT_TIMEOUT_US) {
			dev_err(ave->dev, "halt: IOP not idle in %d ms\n",
				AVE_HALT_TIMEOUT_US / 1000);
			ave_dump_state(ave, "halt");
			return -ETIMEDOUT;
		}
		usleep_range(AVE_IDLE_POLL_US, 2 * AVE_IDLE_POLL_US);
	}

	ret = readl_relaxed_poll_timeout(ave->mbox + AVE_MBOX_SCRATCH(0), val, val == AVE_IOP_FLAG,
					 AVE_FLAG_POLL_US, AVE_HALT_TIMEOUT_US);
	ave_print_terminal(ave);
	if (ret)
		dev_err(ave->dev, "halt: scratch 0 %#x, not the IOP flag, in %d ms\n", val,
			AVE_HALT_TIMEOUT_US / 1000);
	return ret;
}

/*
 * The firmware halted if it can be, SetClockGating(1), then AVE_HwC::PowerOff
 * (0xfffffe0009150fcc): GetIntr and ClearIntr, the domains off.
 */
void ave_fw_shutdown(struct apple_ave *ave, bool halt)
{
	u32 pending;

	if (halt)
		ave_halt(ave);
	pending = ave_mbox_read(ave, AVE_MBOX_PENDING);
	ave_mbox_write(ave, AVE_MBOX_PENDING, pending);
	ave_mbox_write(ave, AVE_MBOX_IDLE, 1);
	pm_runtime_put_sync(ave->dev);
}
