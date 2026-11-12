// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple Neural Engine driver: the firmware's boot and its channels
 *
 * Copyright The Asahi Linux Contributors
 *
 * rda AppleH11ANEInterface (the 14.8.3 kext): ANE_Init 0xfffffe0009788b24,
 * power_on_hardware 0xfffffe00097883c0, mapFwCTRRRegion 0xfffffe0009772840,
 * aneInterruptHandlerPriv 0xfffffe0009779230. The firmware: rda
 * ane_fw_t603x_1483, RealChannelTableTarget_hostHandshake 0x62d4.
 */

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "ane.h"

#define ANE_CPU_CONTROL		0x1400044
#define ANE_CPU_CONTROL_RUN	0x10
#define ANE_CPU_STATUS		0x1400048
#define ANE_CPU_STATUS_HALTED	0x3
#define ANE_LLT_DART_PARAMS	0x1830080
#define ANE_SCRATCH(n)		(0x1840050 + 4 * (n))
#define ANE_DOORBELL		0x1844000
#define ANE_IRQ_PENDING		0x184c000
#define ANE_IRQ_ACK		0x1850000

#define ANE_HS_FW		0x08042006
#define ANE_HS_HOST		0xf7fbdff9
#define ANE_HS_POLL_US		1000
#define ANE_HS_TIMEOUT_US	(1000 * ANE_HS_POLL_US)

#define ANE_DMM_SIZE		0x40000
#define ANE_BOOT_BLOCK_SIZE	0x174
#define ANE_BOOT_ARGS_COUNT	0x40
#define ANE_CMD_OFF		0x1000
#define ANE_CMD_MAX		0x1000
#define ANE_CMD_TIMEOUT		(2 * HZ)

#define ANE_CH_RECORD		0x100
#define ANE_CH_KIND		0x40
#define ANE_CH_BELL		0x44
#define ANE_CH_SLOTS		0x48
#define ANE_CH_RING		0x50
#define ANE_CH_SLOT		0x40

#define ANE_CMD_START			0x00
#define ANE_CMD_STOP			0x01
#define ANE_CMD_CONFIG_GET		0x03
#define ANE_CMD_PRINT_ENABLE		0x04
#define ANE_CMD_BUILDINFO		0x06
#define ANE_CMD_POWER_DOWN		0x0b
#define ANE_CMD_RESOURCE_INFO_GET	0x22

static u32 ane_read(struct apple_ane *ane, u32 off)
{
	return readl_relaxed(ane_reg(ane, off));
}

static void ane_write(struct apple_ane *ane, u32 off, u32 val)
{
	writel_relaxed(val, ane_reg(ane, off));
}

int ane_alloc(struct apple_ane *ane, struct ane_buf *buf, size_t size)
{
	buf->size = round_up(size, SZ_16K);
	buf->cpu = dma_alloc_coherent(ane->dev, buf->size, &buf->iova, GFP_KERNEL);
	return buf->cpu ? 0 : -ENOMEM;
}

void ane_free(struct apple_ane *ane, struct ane_buf *buf)
{
	if (buf->cpu)
		dma_free_coherent(ane->dev, buf->size, buf->cpu, buf->iova);
	buf->cpu = NULL;
}

/* The CPU's view of a firmware address, in what the host allocated */
static void *ane_host_addr(struct apple_ane *ane, u64 iova, size_t size)
{
	struct ane_buf *bufs[] = { &ane->ipc, &ane->heap, &ane->dmm };
	struct ane_surface *s;
	int i;

	for (i = 0; i < ARRAY_SIZE(bufs); i++)
		if (bufs[i]->cpu && iova >= bufs[i]->iova &&
		    iova - bufs[i]->iova + size <= bufs[i]->size)
			return bufs[i]->cpu + (iova - bufs[i]->iova);
	list_for_each_entry(s, &ane->surfaces, node)
		if (iova >= s->buf.iova && iova - s->buf.iova + size <= s->buf.size)
			return s->buf.cpu + (iova - s->buf.iova);
	if (ane->fwheap.cpu && iova >= ane->fwheap_iova &&
	    iova - ane->fwheap_iova + size <= ane->fwheap.size)
		return ane->fwheap.cpu + (iova - ane->fwheap_iova);
	return NULL;
}

/* IOProcessorChannelCreate 0xfffffe000975ba90 */
static void ane_channel_init(struct ane_channel *c, const u8 *rec, u8 *ring)
{
	int i;

	memcpy(c->name, rec, 0x20);
	c->name[0x20] = 0;
	c->kind = get_unaligned_le32(rec + ANE_CH_KIND);
	c->bell = get_unaligned_le32(rec + ANE_CH_BELL);
	c->slots = get_unaligned_le32(rec + ANE_CH_SLOTS);
	c->ring = ring;
	c->type = c->kind == 0;
	c->rd = c->type ? -1 : 0;
	c->wr = c->type ? 0 : -1;
	if (c->type)
		for (i = 0; i < c->slots; i++) {
			u8 *e = ring + i * ANE_CH_SLOT;

			put_unaligned_le64(c->type, e);
			put_unaligned_le64(0, e + 8);
			put_unaligned_le64(0, e + 16);
		}
}

/* IOProcessorChannelSend 0xfffffe000975bd10 */
static int ane_channel_send(struct apple_ane *ane, struct ane_channel *c, u64 addr, u64 w1, u64 w2)
{
	u8 *e;
	s32 next, first;

	if (c->wr < 0)
		return -EBUSY;
	e = c->ring + c->wr * ANE_CH_SLOT;
	put_unaligned_le64(w1, e + 8);
	put_unaligned_le64(w2, e + 16);
	/* the slot's words reach memory before it changes hands */
	dma_wmb();
	put_unaligned_le64((c->type ^ 1) | addr, e);
	/* the slot reaches memory before the doorbell */
	wmb();

	first = c->rd < 0 ? c->wr : c->rd;
	c->rd = first;
	next = c->wr == c->slots - 1 ? 0 : c->wr + 1;
	c->wr = next == first ? -1 : next;

	ane_write(ane, ANE_DOORBELL, BIT(c->bell));
	return 0;
}

/* IOProcessorChannelReceive 0xfffffe000975be30, ...UnidirectionalReceive 0xfffffe000975c098 */
static bool ane_channel_recv(struct ane_channel *c, u64 *addr, u64 *w1, u64 *w2)
{
	u8 *e;
	u64 q;
	s32 next, first;

	if (c->rd < 0)
		return false;
	e = c->ring + c->rd * ANE_CH_SLOT;
	dma_rmb();
	q = get_unaligned_le64(e);
	if ((q & 1) != (c->type & 1))
		return false;
	*addr = q & ~3ULL;
	*w1 = get_unaligned_le64(e + 8);
	*w2 = get_unaligned_le64(e + 16);

	next = c->rd == c->slots - 1 ? 0 : c->rd + 1;
	if (c->kind == 2) {
		put_unaligned_le64(c->type ^ 1, e);
		c->rd = next;
		return true;
	}
	first = c->wr < 0 ? c->rd : c->wr;
	c->wr = first;
	c->rd = next == first ? -1 : next;
	return true;
}

/* processSharedMallocRequest 0xfffffe000977d5a0 */
static void ane_serve_malloc(struct apple_ane *ane, struct ane_channel *c, u64 addr, u64 size, u64 tag)
{
	struct ane_surface *s;
	u64 iova = 0, len = 0;

	if (!addr && !size)
		return;	/* an ISP surface's mapping: no reply */

	if (addr) {
		list_for_each_entry(s, &ane->surfaces, node) {
			if (s->buf.iova == addr) {
				list_del(&s->node);
				ane_free(ane, &s->buf);
				kfree(s);
				break;
			}
		}
	} else {
		s = kzalloc(sizeof(*s), GFP_KERNEL);
		if (s && ane_alloc(ane, &s->buf, size)) {
			kfree(s);
			s = NULL;
		}
		if (s) {
			s->tag = tag;
			list_add(&s->node, &ane->surfaces);
			iova = s->buf.iova;
			len = s->buf.size;
		} else {
			dev_err_ratelimited(ane->dev, "shared malloc: no %#llx bytes for %#llx\n",
					    size, tag);
		}
		dev_dbg(ane->dev, "shared malloc %#llx bytes for %#llx: %#llx\n", size, tag, iova);
	}
	ane_channel_send(ane, c, iova, 0, len);
}

irqreturn_t ane_fw_irq(int irq, void *data)
{
	struct apple_ane *ane = data;
	u32 pending = ane_read(ane, ANE_IRQ_PENDING);

	if (!pending)
		return IRQ_NONE;
	ane_write(ane, ANE_IRQ_ACK, pending);
	/* the ack reaches the block before the rings are read */
	wmb();
	return IRQ_WAKE_THREAD;
}

irqreturn_t ane_fw_irq_thread(int irq, void *data)
{
	struct apple_ane *ane = data;
	int i;

	mutex_lock(&ane->ring_lock);
	for (i = 0; i < ane->num_channels; i++) {
		struct ane_channel *c = &ane->ch[i];
		u64 addr, w1, w2;

		while (ane_channel_recv(c, &addr, &w1, &w2)) {
			if (i == ane->ch_malloc) {
				ane_serve_malloc(ane, c, addr, w1, w2);
			} else if (i == ane->ch_terminal) {
				char *text = addr ? ane_host_addr(ane, addr, w1) : NULL;

				if (text)
					dev_info(ane->dev, "fw: %.*s\n", (int)min_t(u64, w1, 127), text);
			} else if (i == ane->ch_io) {
				if (addr == ane->cmd_iova)
					complete(&ane->cmd_done);
			} else if (i == ane->ch_io_t2h) {
				/* the firmware's messages, their command at +4 */
				u8 *m = addr ? ane_host_addr(ane, addr, ANE_T2H_EVENT_SIZE) : NULL;
				u16 cmd = m ? get_unaligned_le16(m + 4) : 0;

				if (cmd == ANE_T2H_PROGRAM_EVENT)
					ane_job_event(ane, m);
				dev_dbg(ane->dev, "%s: %#llx %#llx %#llx: command %#x\n", c->name, addr, w1, w2, cmd);
				/*
				 * The message goes back on its channel, which hands its buffer to the firmware
				 * again: it has 15, and stops when they are out (the kext's
				 * processTargetToHostIOCommand ends with IOProcessorChannelSend of the three words)
				 */
				ane_channel_send(ane, c, addr, w1, w2);
			} else {
				dev_info(ane->dev, "%s: %#llx %#llx %#llx\n", c->name, addr, w1, w2);
			}
		}
	}
	mutex_unlock(&ane->ring_lock);
	return IRQ_HANDLED;
}

/* A command in the DMM area: u32 0, u16 id at +4, the reply over it (aneCmdSendPrivate 0xfffffe00097c00f0) */
static int ane_command_send(struct apple_ane *ane, u16 id, void *buf, size_t size, size_t reply)
{
	u8 *cmd = ane->dmm.cpu + ANE_CMD_OFF;
	int ret;

	if (WARN_ON(size > ANE_CMD_MAX || reply > ANE_CMD_MAX || size < 8))
		return -EINVAL;

	memset(cmd, 0, max(size, reply));
	if (buf)
		memcpy(cmd, buf, size);
	put_unaligned_le16(id, cmd + 4);
	put_unaligned_le16(0, cmd + 6);

	reinit_completion(&ane->cmd_done);
	ane->cmd_iova = ane->dmm.iova + ANE_CMD_OFF;
	mutex_lock(&ane->ring_lock);
	ret = ane_channel_send(ane, &ane->ch[ane->ch_io], ane->cmd_iova, size, reply);
	mutex_unlock(&ane->ring_lock);
	return ret;
}

int ane_command(struct apple_ane *ane, u16 id, void *buf, size_t size, size_t reply)
{
	int ret = ane_command_send(ane, id, buf, size, reply);

	if (ret)
		return ret;
	if (!wait_for_completion_timeout(&ane->cmd_done, ANE_CMD_TIMEOUT)) {
		dev_err(ane->dev, "command %#x: no reply\n", id);
		return -ETIMEDOUT;
	}
	if (buf)
		memcpy(buf, ane->dmm.cpu + ANE_CMD_OFF, reply);
	return 0;
}

static int ane_find_channel(struct apple_ane *ane, const char *name)
{
	int i;

	for (i = 0; i < ane->num_channels; i++)
		if (!strcmp(ane->ch[i].name, name))
			return i;
	dev_err(ane->dev, "no channel %s\n", name);
	return -ENOENT;
}

static void ane_dump(struct apple_ane *ane, const char *when)
{
	dev_err(ane->dev, "%s: scratch %08x %08x %08x %08x %08x %08x %08x %08x\n", when,
		ane_read(ane, ANE_SCRATCH(0)), ane_read(ane, ANE_SCRATCH(1)),
		ane_read(ane, ANE_SCRATCH(2)), ane_read(ane, ANE_SCRATCH(3)),
		ane_read(ane, ANE_SCRATCH(4)), ane_read(ane, ANE_SCRATCH(5)),
		ane_read(ane, ANE_SCRATCH(6)), ane_read(ane, ANE_SCRATCH(7)));
}

/*
 * An allocation's pages again at the address the firmware expects. ane0's reserved-memory
 * node keeps the firmware's window from the DMA allocator.
 */
static int ane_map_at(struct apple_ane *ane, struct ane_buf *buf, u64 iova)
{
	size_t off;
	int ret;

	for (off = 0; off < buf->size; off += SZ_16K) {
		phys_addr_t phys = iommu_iova_to_phys(ane->domain, buf->iova + off);

		ret = phys ? iommu_map(ane->domain, iova + off, phys, SZ_16K,
				       IOMMU_READ | IOMMU_WRITE, GFP_KERNEL) : -EFAULT;
		if (ret) {
			if (off)
				iommu_unmap(ane->domain, iova, off);
			return ret;
		}
	}
	return 0;
}

/*
 * __TEXT and __DATA at their addresses, __DATA as the image has it: the firmware writes
 * it while it runs.
 */
static int ane_map_segments(struct apple_ane *ane)
{
	int ret;

	memcpy(ane->data.buf.cpu, ane->data_image, ane->data.size);
	/* __DATA reaches memory before the CPU starts */
	wmb();
	ret = ane_map_at(ane, &ane->text.buf, ane->text.iova);
	if (ret)
		return ret;
	ret = ane_map_at(ane, &ane->data.buf, ane->data.iova);
	if (ret)
		iommu_unmap(ane->domain, ane->text.iova, ane->text.buf.size);
	return ret;
}

static void ane_unmap_segments(struct apple_ane *ane)
{
	iommu_unmap(ane->domain, ane->data.iova, ane->data.buf.size);
	iommu_unmap(ane->domain, ane->text.iova, ane->text.buf.size);
}

/* The window's rest after __DATA ("PHNI", AllocateFwHeapMemorySurface 0xfffffe000979e528) */
static int ane_map_fwheap(struct apple_ane *ane)
{
	u64 iova = round_up(ane->data.iova + ane->data.size, SZ_16K);
	int ret;

	ret = ane_alloc(ane, &ane->fwheap, ane->text.iova + ANE_FW_WINDOW - iova);
	if (ret)
		return ret;
	ret = ane_map_at(ane, &ane->fwheap, iova);
	if (ret) {
		ane_free(ane, &ane->fwheap);
		return ret;
	}
	ane->fwheap_iova = iova;
	return 0;
}

static void ane_unmap_fwheap(struct apple_ane *ane)
{
	if (!ane->fwheap.cpu)
		return;
	iommu_unmap(ane->domain, ane->fwheap_iova, ane->fwheap.size);
	ane_free(ane, &ane->fwheap);
}

static void ane_free_all(struct apple_ane *ane)
{
	struct ane_surface *s, *t;

	list_for_each_entry_safe(s, t, &ane->surfaces, node) {
		list_del(&s->node);
		ane_free(ane, &s->buf);
		kfree(s);
	}
	ane_unmap_fwheap(ane);
	ane_unmap_segments(ane);
	ane_free(ane, &ane->heap);
	ane_free(ane, &ane->ipc);
	ane_free(ane, &ane->dmm);
	ane->num_channels = 0;
}

/* ANE_Init 0xfffffe0009788b24 */
static int ane_handshake(struct apple_ane *ane)
{
	u32 n, queue, heap, val;
	u8 *block, *table;
	u64 addr;
	int i, ret;

	/* power_on_hardware: "LLT DART build params" +0x80 */
	ane_write(ane, ANE_LLT_DART_PARAMS, 1);

	for (i = 0; i < 8; i++)
		ane_write(ane, ANE_SCRATCH(i), 0);

	/* iBoot has set and locked RVBAR. Both writes as the kext does them; never read */
	writel(0, ane_reg(ane, ANE_CPU_CONTROL));
	writel(ANE_CPU_CONTROL_RUN, ane_reg(ane, ANE_CPU_CONTROL));

	ret = read_poll_timeout(ane_read, val, val == ANE_HS_FW, ANE_HS_POLL_US,
				ANE_HS_TIMEOUT_US, false, ane, ANE_SCRATCH(7));
	if (ret) {
		ane_dump(ane, "no first handshake");
		return ret;
	}

	n = ane_read(ane, ANE_SCRATCH(0));
	queue = ane_read(ane, ANE_SCRATCH(1)) + 1;
	heap = ane_read(ane, ANE_SCRATCH(3));
	dev_info(ane->dev, "firmware up: %u channels, IPC %#x, record %#x, heap %#x, scratch4 %#x\n",
		 n, queue, ane_read(ane, ANE_SCRATCH(2)), heap, ane_read(ane, ANE_SCRATCH(4)));
	if (!n || n > ANE_MAX_CHANNELS || queue > SZ_64M || heap > SZ_256M)
		return -EPROTO;

	ret = ane_alloc(ane, &ane->dmm, ANE_DMM_SIZE) ?:
	      ane_alloc(ane, &ane->ipc, queue);
	if (ret)
		return ret;
	if (heap) {
		ret = ane_alloc(ane, &ane->heap, heap);
		if (ret)
			return ret;
	}

	block = ane->dmm.cpu;
	put_unaligned_le64(ane->text.iova, block + 0x00);
	put_unaligned_le64(ane->ipc.iova, block + 0x08);
	put_unaligned_le64(ANE_FW_WINDOW, block + 0x10);
	put_unaligned_le64(0x10000000 - ANE_FW_WINDOW, block + 0x18);
	put_unaligned_le64(heap ? ane->heap.iova : 0, block + 0x20);
	put_unaligned_le64(ane->heap.size, block + 0x28);
	put_unaligned_le64(queue, block + 0x50);
	put_unaligned_le64(ane->dmm.iova, block + 0x58);
	put_unaligned_le64(ANE_DMM_SIZE, block + 0x60);
	put_unaligned_le32(ANE_BOOT_ARGS_COUNT, block + 0x68);
	/* the boot block reaches memory before the handshake */
	wmb();

	addr = ane->dmm.iova;
	ane_write(ane, ANE_SCRATCH(0), lower_32_bits(addr));
	ane_write(ane, ANE_SCRATCH(1), upper_32_bits(addr));
	writel(ANE_HS_HOST, ane_reg(ane, ANE_SCRATCH(7)));

	ret = read_poll_timeout(ane_read, val, val == ANE_HS_FW, ANE_HS_POLL_US,
				ANE_HS_TIMEOUT_US, false, ane, ANE_SCRATCH(7));
	if (ret) {
		ane_dump(ane, "no channel table");
		return ret;
	}

	addr = ane_read(ane, ANE_SCRATCH(0)) |
	       (u64)ane_read(ane, ANE_SCRATCH(1)) << 32;
	table = ane_host_addr(ane, addr, n * ANE_CH_RECORD);
	if (!table) {
		dev_err(ane->dev, "channel table at %#llx, outside the host's memory\n", addr);
		return -EPROTO;
	}

	for (i = 0; i < n; i++) {
		const u8 *rec = table + i * ANE_CH_RECORD;
		u32 slots = get_unaligned_le32(rec + ANE_CH_SLOTS);
		u8 *ring = ane_host_addr(ane, get_unaligned_le64(rec + ANE_CH_RING),
					 slots * ANE_CH_SLOT);

		if (!ring || get_unaligned_le32(rec + ANE_CH_BELL) >= 32) {
			dev_err(ane->dev, "channel %d: ring %#llx of %u slots, bell %u\n", i,
				get_unaligned_le64(rec + ANE_CH_RING), slots,
				get_unaligned_le32(rec + ANE_CH_BELL));
			return -EPROTO;
		}
		ane_channel_init(&ane->ch[i], rec, ring);
		dev_info(ane->dev, "channel %d %s: kind %u bell %u, %u slots\n", i,
			 ane->ch[i].name, ane->ch[i].kind, ane->ch[i].bell, slots);
	}
	/* the slots reach memory before the flag */
	wmb();
	ane->num_channels = n;

	writel(ANE_HS_FW, ane_reg(ane, ANE_SCRATCH(3)));
	ret = read_poll_timeout(ane_read, val, val == 0, ANE_HS_POLL_US,
				ANE_HS_TIMEOUT_US, false, ane, ANE_SCRATCH(3));
	if (ret) {
		ane_dump(ane, "the channel table's acknowledgement");
		return ret;
	}

	ane->ch_malloc = ane_find_channel(ane, "SHAREDMALLOC");
	ane->ch_terminal = ane_find_channel(ane, "TERMINAL");
	ane->ch_io = ane_find_channel(ane, "IO");
	ane->ch_io_t2h = ane_find_channel(ane, "IO_T2H");
	if (ane->ch_malloc < 0 || ane->ch_terminal < 0 || ane->ch_io < 0 || ane->ch_io_t2h < 0)
		return -EPROTO;
	return 0;
}

/*
 * The engine's domains off before the next boot. A put only queues its suppliers' idle
 * (rpm_suspend_suppliers), so a resume right after one can find ANE_CPU still powered, its
 * firmware still in an assert's loop: RUN does not restart it and the handshake reads SCRATCH 0.
 * Each domain's device is idled here and must read suspended; the kext likewise power-cycles the
 * engine before each ANE_Init (DisableANEClocksAndPower, rda AppleH11ANEInterface
 * 0xfffffe00097867a0). ANE_SYS stays up while its DARTs are active.
 */
static void ane_power_off(struct apple_ane *ane)
{
	unsigned int i;

	pm_runtime_put_sync(ane->dev);
	for (i = 0; ane->pd_list && i < ane->pd_list->num_pds; i++) {
		struct device *pd = ane->pd_list->pd_devs[i];
		int ret = 0;

		/* the put queued each domain's idle: wait for one in flight, run a cancelled one here */
		pm_runtime_barrier(pd);
		if (!pm_runtime_status_suspended(pd))
			ret = pm_runtime_idle(pd);
		if (!pm_runtime_status_suspended(pd))
			dev_warn(ane->dev, "power domain %u still on: %d\n", i, ret);
	}
}

int ane_fw_boot(struct apple_ane *ane)
{
	u8 buf[0x68];
	int ret;

	ret = ane_fw_load(ane);
	if (ret)
		return ret;

	ret = pm_runtime_resume_and_get(ane->dev);
	if (ret)
		return ret;

	ret = ane_map_segments(ane);
	if (ret)
		goto err_rpm;
	ret = ane_map_fwheap(ane);
	if (ret) {
		ane_unmap_segments(ane);
		goto err_rpm;
	}

	ret = ane_handshake(ane);
	if (ret)
		goto err_free;

	enable_irq(ane->irq);

	memset(buf, 0, sizeof(buf));
	ret = ane_command(ane, ANE_CMD_PRINT_ENABLE, buf, 0xc, 0xc);
	if (ret)
		goto err_irq;
	ret = ane_command(ane, ANE_CMD_START, buf, 0xc, 0xc);
	if (ret)
		goto err_irq;
	ret = ane_command(ane, ANE_CMD_CONFIG_GET, buf, 0x10, 0x10);
	if (ret)
		goto err_irq;
	dev_info(ane->dev, "started: config %*ph\n", 0x10, buf);
	memset(buf, 0, sizeof(buf));
	ret = ane_command(ane, ANE_CMD_RESOURCE_INFO_GET, buf, 0x68, 0x68);
	if (ret)
		goto err_irq;
	dev_info(ane->dev, "resources: %*ph\n", 0x68, buf);
	if (get_unaligned_le32(buf + 0x10) < ANE_CALLS_IN_FLIGHT ||
	    get_unaligned_le32(buf + 0x14) < ANE_CALLS_IN_FLIGHT)
		dev_warn(ane->dev, "the firmware takes %u calls a process and %u a priority, under the driver's %u\n",
			 get_unaligned_le32(buf + 0x10), get_unaligned_le32(buf + 0x14), ANE_CALLS_IN_FLIGHT);

	ane->running = true;
	ane->fw_gen++;
	return 0;

err_irq:
	disable_irq(ane->irq);
err_free:
	ane_free_all(ane);
err_rpm:
	ane_power_off(ane);
	return ret;
}

/* ANE_deInit 0xfffffe000978daec */
static void ane_fw_stop(struct apple_ane *ane)
{
	u8 buf[0xc] = {};
	u32 val;
	int ret;

	ret = ane_command(ane, ANE_CMD_STOP, buf, 0xc, 0xc);
	if (ret)
		return;

	/* no reply to this one: the firmware answers in the scratch register */
	writel(ANE_HS_HOST, ane_reg(ane, ANE_SCRATCH(0)));
	ret = ane_command_send(ane, ANE_CMD_POWER_DOWN, buf, 8, 8);
	if (ret)
		return;
	ret = read_poll_timeout(ane_read, val, val == ANE_HS_FW, ANE_HS_POLL_US,
				ANE_HS_TIMEOUT_US, false, ane, ANE_SCRATCH(0));
	if (ret) {
		ane_dump(ane, "no answer to the power-down");
		return;
	}

	/* the kext goes on either way */
	ret = read_poll_timeout(ane_read, val, val & ANE_CPU_STATUS_HALTED, 10000, 200000, false,
				ane, ANE_CPU_STATUS);
	if (ret)
		dev_warn(ane->dev, "the CPU has not halted: %#x\n", val);
}

static void ane_fw_down(struct apple_ane *ane, bool answers)
{
	if (answers)
		ane_fw_stop(ane);
	disable_irq(ane->irq);
	ane->running = false;
	ane_free_all(ane);
	ane_power_off(ane);
}

void ane_fw_shutdown(struct apple_ane *ane)
{
	ane_fw_down(ane, true);
}

/*
 * A firmware that stopped answering: no STOP or POWER_DOWN, which would only wait out their
 * timeouts, as the kext skips them after a timeout; the power-off restarts its CPU.
 */
void ane_fw_kill(struct apple_ane *ane)
{
	ane_fw_down(ane, false);
}
