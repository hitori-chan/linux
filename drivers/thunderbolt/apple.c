// SPDX-License-Identifier: GPL-2.0
/*
 * Apple Silicon USB4 and Thunderbolt driver
 * Copyright (c) Sven Peter <sven@kernel.org>
 *
 * This driver implements the Host Router / ACIO coprocessor as well as the
 * Native Host Interface (NHI) as shown in the diagram below.
 * The ACIO is a Cortex-M3 coprocessor which handles the Thunderbolt
 * protocol and exposes its own hardware blocks like the USB4 Native Host
 * Interface (NHI) and its IOMMU to the main SoC bus. The entire block
 * can only be brought up after the unified Type-C PHY has been initialized
 * to Thunderbolt or USB4 mode and needs an out-of-band notification from
 * the Type-C PD driver.
 *
 * +--------------------+
 * |                    |  +--------------------------------------------+
 * | Display Controller |  | Host Router / ACIO                         |
 * |       dcpext0      |  |             +----------------+             |
 * |                    |  |             |     Native     |             |
 * +--------+-----------+  |             |      Host      |             |
 *          |              |             |    Interface   |             |
 *          |              +---------+   +----------------+   +---------+     +--------+
 *          |   +--------->| DP IN   |                        | PCIE DN |<--->| APCIEC |
 *          v   |          | Adapter |   +----------------+   | Adapter |     +--------+
 *    +---------+-+        +---------+   |                |   +---------+
 *    | Display   |        |             |  IOMMU / DART  |             |
 *    | Crossbar  |        |             |                |   +---------+     +------+
 *    +---------+-+        +---------+   +----------------+   | USB3    |<--->| DWC3 |
 *          ^   |          | DP IN   |                        | Adapter |     +------+
 *          |   +--------->| Adapter |                        +---------+
 *          |              +---------+                                  |
 *          |              |                                            |
 *          |              |                 +----------+               |
 * +--------+-----------+  |                 | Type C   |               |
 * |                    |  |                 | Adapter  |               |
 * | Display Controller |  +-----------------+----------+---------------+
 * |       dcpext1      |                     ^       ^
 * |                    |                     |       |
 * +--------------------+                     |       |
 *                                            v       |
 *                                 +--------------+   | SBRX/TX
 *                                 | Apple Type-C |   |
 *                                 |    PHY       |   |
 *                                 +--------------+   |
 *                                       ^            |
 *                                       |            v
 *                                       |     +---------+
 *                                       +---->| Type C  |
 *                                     SSRX/TX | Port    |
 *                                             +---------+
 *
 * ACIO and ATCPHY have strict ordering requirements. When a USB4/Thunderbolt
 * connection is requested after a device has been connected the Type-C PD
 * driver performs the following sequence:
 *
 * 1) Configure the PHY for the negotiated mode and orientation through
 *    typec_mux_set()
 * 2) Mark the negotiated Type-C alternate mode active
 * 3) Power up ACIO, boot its RTKit co-processor and apply the tunables
 * 4) Probe the DART and NHI children now that their MMIO is accessible from
 *    the main SoC bus
 * 5) Register the USB4 domain and write the cable details to the host router
 *    which brings up the link and starts discovery
 *
 * ACIO must not be started before the PHY is configured. The child devices
 * cannot remain populated while ACIO is powered off because they are part
 * of the ACIO block and only exposed to the main SoC bus and will SError
 * once ACIO is off. Violating this ordering can panic the kernel with an
 * async SError at best and trigger some internal watchdog that will reset
 * the entire SoC at worst.
 *
 * When the cable is disconnected ACIO shutdown and PHY shutdown can happen in
 * either order as long as both have been shutdown before the next connection
 * is established.
 */

#include <linux/bitfield.h>
#include <linux/completion.h>
#include <linux/device/bus.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/reset.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/soc/apple/tunable.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/usb/pd.h>
#include <linux/usb/typec.h>
#include <linux/usb/typec_altmode.h>
#include <linux/usb/typec_tbt.h>

#include "nhi.h"
#include "tb.h"

#define APPLE_CIO_M3_CTRL				0x0c
#define APPLE_CIO_M3_CTRL_START				BIT(1)
#define APPLE_CIO_M3_STAT				0xa8
#define APPLE_CIO_M3_STAT_STATE				GENMASK(30, 24)

#define APPLE_CIO_NHI_HOP_COUNT				0x0
#define APPLE_CIO_NHI_HOP_COUNT_MASK			GENMASK(9, 0)

#define APPLE_CIO_NHI_TXRING_DESC_BASE			0x10000
#define APPLE_CIO_NHI_RXRING_DESC_BASE			0x80000
#define APPLE_CIO_NHI_RING_STRIDE			0x4000

#define APPLE_CIO_NHI_PDF_STRIDE			0x4000

#define APPLE_CIO_USB3_ADAPTER				4

#define APPLE_CIO_NHI_IRQ_STATUS			0xd0000
#define APPLE_CIO_NHI_IRQ_ENABLE			0xd0010
#define APPLE_CIO_NHI_IRQ_THROTTLE			0xd004c
#define APPLE_CIO_NHI_IRQ_THROTTLE_INTERVAL_MASK	GENMASK(15, 0)
#define APPLE_CIO_NHI_IRQ_THROTTLE_GRANULARITY_NSEC	256

#define APPLE_CIO_SRAM_IOVA_BASE			0x10000000

#define APPLE_CIO_NHI_BOOT_TIMEOUT			10000 /* ms */

/*
 * The Apple vendor-specific extended capability contains a cable-information
 * word which has to be programmed from the USB4/Thunderbolt details reported
 * out-of-band by the Type-C PD controller. It must be programmed into the
 * host router before link discovery starts.
 */
#define TB_VSE_CAP_APPLE_CABLE_INFO			0x01
#define TB_VSE_CAP_APPLE_CABLE_INFO_PRESENT		BIT(0)
#define TB_VSE_CAP_APPLE_CABLE_INFO_ORIENTATION_REVERSE	BIT(1)
#define TB_VSE_CAP_APPLE_CABLE_INFO_ACTIVE_CABLE	BIT(2)
#define TB_VSE_CAP_APPLE_CABLE_INFO_BIDIR_LSRX		BIT(3)
#define TB_VSE_CAP_APPLE_CABLE_INFO_20_GBPS		BIT(4)
#define TB_VSE_CAP_APPLE_CABLE_INFO_LEGACY_ADAPTER	BIT(9)
#define TB_VSE_CAP_APPLE_CABLE_INFO_TBT2_3		BIT(10)

struct apple_cio;

struct apple_cio_altmode {
	struct apple_cio *acio;
	struct typec_altmode *altmode;
	struct notifier_block notifier;
};

/**
 * struct apple_cio - Apple Converged I/O block
 * @dev: ACIO device
 * @np: ACIO device tree node
 * @rtk: RTKit instance for the ACIO co-processor
 * @rc_base: ACIO root controller registers
 * @rc_res: ACIO root controller MMIO resource
 * @rc_tunable: Tunable sequence for the ACIO root controller
 * @sram_res: ACIO co-processor SRAM resource
 * @sram_base: ACIO co-processor SRAM
 * @reset: ACIO reset controller
 * @pd_list: Power domains used by the ACIO block
 * @lock: Serializes cable transitions and ACIO power changes
 * @current_cable_info: Cable information currently programmed into ACIO
 * @target_cable_info: Cable information requested by the Type-C PD driver
 * @nhi_boot_completion: Signals completion of the NHI bringup
 * @nhi_boot_status: Status returned by the NHI bringup
 * @connector: Type-C connector firmware node linked to this ACIO
 * @typec_lock: Serializes Type-C alternate mode attachment and removal
 * @typec_notifier: Type-C bus notifier used to discover partner alternate modes
 * @tbt_altmode: Thunderbolt partner alternate mode subscription
 * @usb4_altmode: USB4 partner alternate mode subscription
 */
struct apple_cio {
	struct device *dev;
	struct device_node *np;
	struct apple_rtkit *rtk;
	void __iomem *rc_base;
	struct resource *rc_res;
	struct apple_tunable *rc_tunable;
	struct resource *sram_res;
	void __iomem *sram_base;
	struct reset_control *reset;
	struct dev_pm_domain_list *pd_list;
	struct mutex lock;
	u32 current_cable_info;
	u32 target_cable_info;
	struct completion nhi_boot_completion;
	int nhi_boot_status;
	struct fwnode_handle *connector;
	struct mutex typec_lock;
	struct notifier_block typec_notifier;
	struct apple_cio_altmode tbt_altmode;
	struct apple_cio_altmode usb4_altmode;
};

/**
 * struct apple_nhi - Apple Native Host Interface
 * @dev: NHI device
 * @pdev: NHI platform device
 * @np: NHI device tree node
 * @acio: Parent ACIO block
 * @tb: USB4 domain and software connection manager
 * @nhi: NHI struct
 * @nhi_base: NHI registers
 * @pdf_base: PDF (Protocol Defined Field) configuration registers
 * @tx_irqs: Transmit ring interrupts indexed by HopID
 * @rx_irqs: Receive ring interrupts indexed by HopID
 * @tx_irq_names: Names of the transmit ring interrupts
 * @rx_irq_names: Names of the receive ring interrupts
 * @nrings: Number of rings in each direction
 */
struct apple_nhi {
	struct device *dev;
	struct platform_device *pdev;
	struct device_node *np;
	struct apple_cio *acio;
	struct tb *tb;
	struct tb_nhi nhi;
	void __iomem *nhi_base;
	void __iomem *pdf_base;
	int *tx_irqs;
	int *rx_irqs;
	const char **tx_irq_names;
	const char **rx_irq_names;
	size_t nrings;
};

#define nhi_to_anhi(nhi_) container_of((nhi_), struct apple_nhi, nhi)

/**
 * apple_cio_rtkit_shmem_setup() - Map an RTKit shared memory buffer
 * @cookie: ACIO instance passed to RTKit
 * @bfr: RTKit shared memory buffer descriptor
 *
 * Translate the firmware-provided IOVA into the ACIO SRAM mapping and reject
 * buffers that fall outside the reserved SRAM resource.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int apple_cio_rtkit_shmem_setup(void *cookie, struct apple_rtkit_shmem *bfr)
{
	struct apple_cio *acio = cookie;
	struct resource res = {
		.name = "acio_rtkit_buffer",
		.flags = acio->sram_res->flags,
	};

	if (!bfr->iova)
		return -EIO;

	if (bfr->iova < APPLE_CIO_SRAM_IOVA_BASE) {
		dev_err(acio->dev, "firmware requested invalid buffer before SRAM IOVA base 0x%llx\n",
			bfr->iova);
		return -EFAULT;
	}

	res.start = bfr->iova - APPLE_CIO_SRAM_IOVA_BASE + acio->sram_res->start;
	res.end = res.start + bfr->size - 1;

	if (res.end < res.start) {
		dev_err(acio->dev, "firmware requested invalid buffer %pR\n", &res);
		return -EFAULT;
	}

	if (!resource_contains(acio->sram_res, &res)) {
		dev_err(acio->dev, "firmware requested buffer %pR outside SRAM %pR\n", &res,
			acio->sram_res);
		return -EFAULT;
	}

	bfr->iomem = acio->sram_base + (res.start - acio->sram_res->start);
	bfr->is_mapped = true;
	return 0;
}

static const struct apple_rtkit_ops apple_cio_rtkit_ops = {
	.shmem_setup = apple_cio_rtkit_shmem_setup,
};

static int apple_nhi_probe_irqs(struct apple_nhi *anhi)
{
	char name[64];
	int nirqs;

	nirqs = platform_irq_count(anhi->pdev);
	if (nirqs < 0)
		return dev_err_probe(anhi->dev, nirqs, "platform_irq_count failed\n");
	if (!nirqs)
		return dev_err_probe(anhi->dev, -EINVAL, "no interrupts found\n");
	if (nirqs % 2)
		return dev_err_probe(anhi->dev, -EINVAL,
				     "invalid number of interrupts: %d must be even\n",
				     nirqs);
	anhi->nrings = nirqs / 2;

	anhi->rx_irqs = devm_kcalloc(anhi->dev, anhi->nrings,
				     sizeof(*anhi->rx_irqs), GFP_KERNEL);
	if (!anhi->rx_irqs)
		return -ENOMEM;
	anhi->tx_irqs = devm_kcalloc(anhi->dev, anhi->nrings,
				     sizeof(*anhi->tx_irqs), GFP_KERNEL);
	if (!anhi->tx_irqs)
		return -ENOMEM;
	anhi->rx_irq_names = devm_kcalloc(anhi->dev, anhi->nrings,
					  sizeof(*anhi->rx_irq_names), GFP_KERNEL);
	if (!anhi->rx_irq_names)
		return -ENOMEM;
	anhi->tx_irq_names = devm_kcalloc(anhi->dev, anhi->nrings,
					  sizeof(*anhi->tx_irq_names), GFP_KERNEL);
	if (!anhi->tx_irq_names)
		return -ENOMEM;

	for (int i = 0; i < anhi->nrings; ++i) {
		snprintf(name, sizeof(name), "rxring%d", i);
		anhi->rx_irqs[i] = platform_get_irq_byname(anhi->pdev, name);
		if (anhi->rx_irqs[i] < 0)
			return anhi->rx_irqs[i];
		anhi->rx_irq_names[i] = devm_kasprintf(anhi->dev, GFP_KERNEL, "%s-%s",
						       dev_name(anhi->dev), name);
		if (!anhi->rx_irq_names[i])
			return -ENOMEM;

		snprintf(name, sizeof(name), "txring%d", i);
		anhi->tx_irqs[i] = platform_get_irq_byname(anhi->pdev, name);
		if (anhi->tx_irqs[i] < 0)
			return anhi->tx_irqs[i];
		anhi->tx_irq_names[i] = devm_kasprintf(anhi->dev, GFP_KERNEL, "%s-%s",
						       dev_name(anhi->dev), name);
		if (!anhi->tx_irq_names[i])
			return -ENOMEM;
	}

	return 0;
}

static unsigned int apple_cio_ring_index(struct tb_ring *ring)
{
	struct apple_nhi *anhi = nhi_to_anhi(ring->nhi);

	if (ring->is_tx)
		return ring->hop;
	else
		return ring->hop + anhi->nrings;
}

static void apple_nhi_ring_interrupt_active(struct tb_ring *ring, bool active)
{
	struct apple_nhi *anhi = nhi_to_anhi(ring->nhi);
	unsigned int idx = apple_cio_ring_index(ring);
	u32 reg, interval;

	lockdep_assert_held(&ring->nhi->lock);

	if (active && ring->interval_nsec) {
		interval = min_t(u32, ring->interval_nsec,
				 FIELD_MAX(APPLE_CIO_NHI_IRQ_THROTTLE_INTERVAL_MASK) *
				 APPLE_CIO_NHI_IRQ_THROTTLE_GRANULARITY_NSEC);
		interval = DIV_ROUND_UP(interval,
					APPLE_CIO_NHI_IRQ_THROTTLE_GRANULARITY_NSEC);
		writel(interval, anhi->nhi_base + APPLE_CIO_NHI_IRQ_THROTTLE +
				 4 * idx);
	}

	reg = readl(anhi->nhi_base + APPLE_CIO_NHI_IRQ_ENABLE);

	if (active)
		reg |= BIT(idx);
	else
		reg &= ~BIT(idx);

	writel(reg, anhi->nhi_base + APPLE_CIO_NHI_IRQ_ENABLE);
}

static void apple_nhi_ring_interrupt_mask(struct tb_ring *ring, bool mask)
{
	apple_nhi_ring_interrupt_active(ring, !mask);
}

static irqreturn_t apple_cio_ring_irq(int irq, void *data)
{
	struct tb_ring *ring = data;
	struct apple_nhi *anhi;
	unsigned int idx;

	anhi = nhi_to_anhi(ring->nhi);
	idx = apple_cio_ring_index(ring);

	guard(spinlock)(&ring->nhi->lock);
	guard(spinlock)(&ring->lock);

	writel(BIT(idx), anhi->nhi_base + APPLE_CIO_NHI_IRQ_STATUS);
	if (!ring->running)
		return IRQ_HANDLED;

	if (ring->start_poll) {
		apple_nhi_ring_interrupt_mask(ring, true);
		ring->start_poll(ring->poll_data);
	} else {
		schedule_work(&ring->work);
	}

	return IRQ_HANDLED;
}

static int apple_nhi_request_irq(struct tb_ring *ring, bool no_suspend)
{
	struct apple_nhi *anhi = nhi_to_anhi(ring->nhi);
	const char *name;

	if (ring->is_tx) {
		ring->irq = anhi->tx_irqs[ring->hop];
		name = anhi->tx_irq_names[ring->hop];
	} else {
		ring->irq = anhi->rx_irqs[ring->hop];
		name = anhi->rx_irq_names[ring->hop];
	}

	return devm_request_irq(anhi->dev, ring->irq, apple_cio_ring_irq,
				no_suspend ? IRQF_NO_SUSPEND : 0, name, ring);
}

static void apple_nhi_release_irq(struct tb_ring *ring)
{
	if (ring->irq <= 0)
		return;

	devm_free_irq(ring->nhi->dev, ring->irq, ring);
	ring->irq = 0;
}

static void __iomem *apple_nhi_ring_desc_base(struct tb_ring *ring)
{
	struct apple_nhi *anhi = nhi_to_anhi(ring->nhi);
	void __iomem *io = anhi->nhi_base;

	io += ring->hop * APPLE_CIO_NHI_RING_STRIDE;
	io += ring->is_tx ? APPLE_CIO_NHI_TXRING_DESC_BASE :
			    APPLE_CIO_NHI_RXRING_DESC_BASE;
	return io;
}

static void __iomem *apple_nhi_ring_options_base(struct tb_ring *ring)
{
	return apple_nhi_ring_desc_base(ring) + 0x10;
}

static void apple_nhi_ring_configure(struct tb_ring *ring, u32 flags, u32 e2e_flags)
{
	void __iomem *options = apple_nhi_ring_options_base(ring);
	struct apple_nhi *anhi = nhi_to_anhi(ring->nhi);
	u32 sof_eof_mask;

	lockdep_assert_held(&ring->lock);

	if (ring->is_tx) {
		/*
		 * All TX rings share what macOS calls a shared buffer with 232 entries. This is how
		 * macOS splits it up, ring 0 only carries control packets and gets the minimum.
		 */
		if (ring->hop == 0)
			writel(2, options + 4);
		else if (ring->hop <= 5)
			writel(40, options + 4);
		else
			writel(5, options + 4);
	} else {
		sof_eof_mask = ring->sof_mask << 16 | ring->eof_mask;
		writel(sof_eof_mask, options + 4);
		writel(sof_eof_mask, anhi->pdf_base + ring->hop * APPLE_CIO_NHI_PDF_STRIDE);
	}

	/*
	 * The firmware samples the ring configuration when the valid bit is set and E2E flow
	 * control never engages when configured afterwards. Write everything at once like macOS.
	 */
	writel(flags | e2e_flags, options);
}

static bool apple_nhi_add_links(struct tb_nhi *nhi)
{
	struct apple_nhi *anhi = nhi_to_anhi(nhi);
	struct fwnode_handle *endpoint, *remote;
	struct device_link *link;
	struct device *consumer;

	endpoint = fwnode_graph_get_endpoint_by_id(dev_fwnode(anhi->acio->dev),
						   APPLE_CIO_USB3_ADAPTER, 0, 0);
	if (!endpoint)
		return false;

	remote = fwnode_graph_get_remote_port_parent(endpoint);
	fwnode_handle_put(endpoint);
	if (!remote)
		return false;

	consumer = bus_find_device_by_fwnode(&platform_bus_type, remote);
	fwnode_handle_put(remote);
	if (!consumer)
		return false;

	link = device_link_add(consumer, nhi->dev,
			       DL_FLAG_AUTOREMOVE_SUPPLIER |
			       DL_FLAG_PM_RUNTIME);
	if (link)
		dev_dbg(nhi->dev, "created link from %s\n", dev_name(consumer));
	else
		dev_warn(nhi->dev, "device link creation from %s failed\n",
			 dev_name(consumer));

	put_device(consumer);

	return !!link;
}

static const struct tb_nhi_ops apple_nhi_ops = {
	.request_ring_irq = apple_nhi_request_irq,
	.release_ring_irq = apple_nhi_release_irq,
	.ring_desc_base = apple_nhi_ring_desc_base,
	.ring_options_base = apple_nhi_ring_options_base,
	.ring_interrupt_active = apple_nhi_ring_interrupt_active,
	.ring_interrupt_mask = apple_nhi_ring_interrupt_mask,
	.ring_configure = apple_nhi_ring_configure,
	.add_links = apple_nhi_add_links,
};

static int apple_nhi_probe(struct platform_device *pdev)
{
	struct apple_cio *acio = dev_get_drvdata(pdev->dev.parent);
	struct apple_tunable *tunable;
	struct apple_nhi *anhi;
	struct resource *res;
	int ret = 0;

	anhi = devm_kzalloc(&pdev->dev, sizeof(*anhi), GFP_KERNEL);
	if (!anhi) {
		ret = -ENOMEM;
		goto err;
	}

	anhi->pdev = pdev;
	anhi->dev = &pdev->dev;
	anhi->np = pdev->dev.of_node;
	anhi->acio = acio;
	platform_set_drvdata(pdev, anhi);

	/*
	 * Only 42 bits seem to be wired up for the IOVA space but this may be further
	 * limited by the IOMMU's capabilities.
	 */
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(42));
	if (ret)
		goto err;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "nhi");
	anhi->nhi_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(anhi->nhi_base)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(anhi->nhi_base),
				    "unable to map NHI regs\n");
		goto err;
	}
	tunable = devm_apple_tunable_parse(&pdev->dev, anhi->np, "apple,tunable-nhi", res);
	if (IS_ERR(tunable)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(tunable),
				    "unable to load NHI tunable\n");
		goto err;
	}
	apple_tunable_apply(anhi->nhi_base, tunable);

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "pdf");
	anhi->pdf_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(anhi->pdf_base)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(anhi->pdf_base),
				    "unable to map PDF regs\n");
		goto err;
	}

	ret = apple_nhi_probe_irqs(anhi);
	if (ret)
		goto err;

	spin_lock_init(&anhi->nhi.lock);
	/* DMA transactions on this platform always go through a DART IOMMU. */
	anhi->nhi.iommu_dma_protection = true;
	anhi->nhi.ops = &apple_nhi_ops;
	anhi->nhi.iobase = anhi->nhi_base;
	anhi->nhi.hop_count = readl(anhi->nhi_base + APPLE_CIO_NHI_HOP_COUNT) &
			      APPLE_CIO_NHI_HOP_COUNT_MASK;
	if (anhi->nhi.hop_count != anhi->nrings) {
		ret = dev_err_probe(anhi->dev, -EINVAL,
				    "ring IRQs (%zd) != HOP_COUNT (%d)\n",
				    anhi->nrings, anhi->nhi.hop_count);
		goto err;
	}

	anhi->nhi.tx_rings = devm_kcalloc(&pdev->dev, anhi->nhi.hop_count,
					  sizeof(*anhi->nhi.tx_rings), GFP_KERNEL);
	anhi->nhi.rx_rings = devm_kcalloc(&pdev->dev, anhi->nhi.hop_count,
					  sizeof(*anhi->nhi.rx_rings), GFP_KERNEL);
	if (!anhi->nhi.tx_rings || !anhi->nhi.rx_rings) {
		ret = -ENOMEM;
		goto err;
	}

	anhi->nhi.dev = &pdev->dev;
	init_completion(&anhi->nhi.domain_released);
	anhi->tb = tb_probe(&anhi->nhi);
	if (!anhi->tb) {
		ret = dev_err_probe(anhi->dev, -ENODEV,
				    "failed to init software connection manager\n");
		goto err;
	}

	ret = tb_domain_add(anhi->tb, false);
	if (ret) {
		dev_err_probe(anhi->dev, ret, "failed to add domain\n");
		tb_domain_put(anhi->tb);
		wait_for_completion(&anhi->nhi.domain_released);
		goto err;
	}

	mutex_lock(&anhi->tb->lock);

	if (!anhi->tb->root_switch->drom) {
		dev_err(anhi->dev, "no valid host DROM in the device tree\n");
		ret = -EINVAL;
		goto err_unlock_tb_domain;
	}

	if (!anhi->tb->root_switch->cap_vsec_apple) {
		dev_err(anhi->dev, "unable to find VSE Apple capability\n");
		ret = -ENODEV;
		goto err_unlock_tb_domain;
	}

	ret = tb_sw_write(anhi->tb->root_switch, &acio->target_cable_info, TB_CFG_SWITCH,
			  anhi->tb->root_switch->cap_vsec_apple +
			  TB_VSE_CAP_APPLE_CABLE_INFO, 1);
	if (ret) {
		dev_warn(anhi->dev, "setting VSE Apple cable info failed: %d\n", ret);
		goto err_unlock_tb_domain;
	}

	mutex_unlock(&anhi->tb->lock);

	acio->nhi_boot_status = 0;
	complete(&acio->nhi_boot_completion);
	return 0;

err_unlock_tb_domain:
	mutex_unlock(&anhi->tb->lock);
	tb_domain_remove(anhi->tb);
	wait_for_completion(&anhi->nhi.domain_released);
err:
	acio->nhi_boot_status = ret;
	complete(&acio->nhi_boot_completion);

	return ret;
}

static void apple_nhi_remove(struct platform_device *pdev)
{
	struct apple_nhi *anhi = platform_get_drvdata(pdev);

	tb_domain_remove(anhi->tb);
	wait_for_completion(&anhi->nhi.domain_released);
}

static const struct of_device_id apple_nhi_match[] = {
	{
		.compatible = "apple,t8103-usb4-nhi",
	},
	{},
};
MODULE_DEVICE_TABLE(of, apple_nhi_match);

static struct platform_driver apple_nhi_driver = {
	.driver = {
		.name = "thunderbolt-apple-nhi",
		.of_match_table = apple_nhi_match,
	},
	.probe = apple_nhi_probe,
	.remove = apple_nhi_remove,
};

/**
 * apple_cio_stop() - Stop and power down the ACIO block
 * @acio: ACIO block to stop
 *
 * Remove the NHI and DART children before shutting down the co-processor and
 * dropping the power-domain links. The caller must hold @acio->lock.
 */
static void apple_cio_stop(struct apple_cio *acio)
{
	int ret, i;

	lockdep_assert_held(&acio->lock);

	/*
	 * First, shutdown the blocks inside the ACIO block, like the NHI and the IOMMU.
	 * After we shut down the ACIO co-processor we will no longer be able to access
	 * the MMIO space of these so make sure nothing tries to do just that.
	 */
	of_platform_depopulate(acio->dev);

	/* Try to shut down and power off the co-processor gracefully */
	ret = apple_rtkit_poweroff(acio->rtk);
	if (ret)
		dev_warn(acio->dev,
			 "failed to shutdown M3 RTKit, continuing ACIO shutdown anyway\n");
	apple_rtkit_free(acio->rtk);

	/* Finally, remove the links to the PD domains to power everything off */
	for (i = 0; i < acio->pd_list->num_pds; i++) {
		if (acio->pd_list->pd_links[i])
			device_link_del(acio->pd_list->pd_links[i]);
		acio->pd_list->pd_links[i] = NULL;
	}

	acio->current_cable_info = 0;
}

/**
 * apple_cio_start() - Power up and start the ACIO block
 * @acio: ACIO block to start
 *
 * The Type-C PHY must already be configured for USB4 or Thunderbolt. Power up
 * ACIO, boot its RTKit co-processor, populate its child devices and wait for
 * the NHI to register the USB4 domain. The caller must hold @acio->lock.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int apple_cio_start(struct apple_cio *acio)
{
	int i, ret;
	u32 state;

	lockdep_assert_held(&acio->lock);

	/* Create device links to the power domains in order to power them on */
	for (i = 0; i < acio->pd_list->num_pds; i++) {
		struct device_link *link;

		link = device_link_add(acio->dev, acio->pd_list->pd_devs[i],
				       DL_FLAG_STATELESS | DL_FLAG_PM_RUNTIME | DL_FLAG_RPM_ACTIVE);
		if (!link) {
			ret = -ENODEV;
			goto remove_links;
		}
		acio->pd_list->pd_links[i] = link;
	}

	/*
	 * After the power domains are on we need to signal and wait for the ACIO block
	 * to actually start before we can bring up the co-processor.
	 */
	ret = reset_control_deassert(acio->reset);
	if (ret) {
		dev_err(acio->dev, "ACIO block failed to start: %d\n", ret);
		goto remove_links;
	}

	/* Start and wait for the co-processor to boot */
	writel(APPLE_CIO_M3_CTRL_START, acio->rc_base + APPLE_CIO_M3_CTRL);
	acio->rtk = apple_rtkit_init(acio->dev, acio, NULL, 0, &apple_cio_rtkit_ops);
	if (IS_ERR(acio->rtk)) {
		ret = PTR_ERR(acio->rtk);
		dev_err(acio->dev, "failed to initialize RTKit: %d\n", ret);
		goto remove_links;
	}

	ret = apple_rtkit_boot(acio->rtk);
	if (ret) {
		dev_err(acio->dev, "M3 RTKit failed to boot: %d\n", ret);
		goto err_free_rtkit;
	}

	ret = readl_poll_timeout(acio->rc_base + APPLE_CIO_M3_STAT, state,
				 state & APPLE_CIO_M3_STAT_STATE, 100, 500000);
	if (ret < 0) {
		dev_err(acio->dev, "M3 firmware failed to get ready: %d\n", ret);
		goto err_shutdown_rtkit;
	}

	apple_tunable_apply(acio->rc_base, acio->rc_tunable);

	/*
	 * Bring up devices which are part of ACIO and are now accessible by the main SoC
	 * and specifically wait for the NHI to be up to prevent concurrent shutdowns.
	 */
	reinit_completion(&acio->nhi_boot_completion);
	ret = of_platform_populate(acio->np, NULL, NULL, acio->dev);
	if (ret) {
		dev_err(acio->dev, "failed to populate children: %d\n", ret);
		goto err_depopulate;
	}

	if (!wait_for_completion_timeout(&acio->nhi_boot_completion,
					 msecs_to_jiffies(APPLE_CIO_NHI_BOOT_TIMEOUT))) {
		dev_err(acio->dev, "timed out waiting for the NHI to come up\n");
		ret = -ETIMEDOUT;
		goto err_depopulate;
	}
	if (acio->nhi_boot_status) {
		ret = acio->nhi_boot_status;
		goto err_depopulate;
	}

	acio->current_cable_info = acio->target_cable_info;
	return 0;

err_depopulate:
	of_platform_depopulate(acio->dev);
err_shutdown_rtkit:
	/* Ignore errors here since we're about to cut power to the entire block anyway */
	apple_rtkit_poweroff(acio->rtk);
err_free_rtkit:
	apple_rtkit_free(acio->rtk);
remove_links:
	/* Cut power to reset the entire block  */
	for (i = 0; i < acio->pd_list->num_pds; i++) {
		if (acio->pd_list->pd_links[i])
			device_link_del(acio->pd_list->pd_links[i]);
		acio->pd_list->pd_links[i] = NULL;
	}

	return ret;
}

static int apple_cio_set_cable_info(struct apple_cio *acio, u32 cable_info)
{
	guard(mutex)(&acio->lock);

	acio->target_cable_info = cable_info;
	if (acio->target_cable_info == acio->current_cable_info)
		return 0;

	/*
	 * Transitions between different cables without a shutdown inbetween are invalid and can
	 * only happen when there's a bug inside the Type-C PD driver. If we tried such a
	 * transition, ACIO would crash and then trigger some watchdog that would reset the entire
	 * SoC a few seconds later. Shutting down instead only makes the connected device not work
	 * but we should be able to recover once the next cable is plugged in.
	 */
	if (acio->current_cable_info && acio->target_cable_info) {
		dev_err(acio->dev,
			"invalid cable transition from 0x%x to 0x%x, shutting down instead\n",
			acio->current_cable_info, acio->target_cable_info);
		acio->target_cable_info = 0;
	}

	/*
	 * Bring up or power down the ACIO block
	 * current_cable_info will be updated in the start/stop functions
	 */
	if (acio->target_cable_info)
		return apple_cio_start(acio);

	apple_cio_stop(acio);
	return 0;
}

static int apple_cio_tbt_cable_info(struct apple_cio *acio,
				    struct typec_altmode *altmode, u32 *cable_info)
{
	u32 info = TB_VSE_CAP_APPLE_CABLE_INFO_PRESENT |
		   TB_VSE_CAP_APPLE_CABLE_INFO_TBT2_3;
	enum typec_orientation orientation;
	struct typec_altmode *plug;
	u32 cable_mode;

	plug = typec_altmode_get_plug(altmode, TYPEC_PLUG_SOP_P);
	if (!plug)
		return -ENODEV;

	cable_mode = plug->vdo;
	typec_altmode_put_plug(plug);
	orientation = typec_altmode_get_orientation(altmode);

	if (cable_mode & TBT_CABLE_ACTIVE_PASSIVE) {
		info |= TB_VSE_CAP_APPLE_CABLE_INFO_ACTIVE_CABLE;
		if (!(cable_mode & TBT_CABLE_LINK_TRAINING))
			info |= TB_VSE_CAP_APPLE_CABLE_INFO_BIDIR_LSRX;
	}
	if (TBT_ADAPTER(altmode->vdo))
		info |= TB_VSE_CAP_APPLE_CABLE_INFO_LEGACY_ADAPTER;
	if (TBT_CABLE_SPEED(cable_mode) == TBT_CABLE_10_AND_20GBPS)
		info |= TB_VSE_CAP_APPLE_CABLE_INFO_20_GBPS;
	if (orientation == TYPEC_ORIENTATION_REVERSE)
		info |= TB_VSE_CAP_APPLE_CABLE_INFO_ORIENTATION_REVERSE;

	dev_dbg(acio->dev,
		"TBT cable: cable mode %#x, device mode %#x, orientation %d -> cable info %#x\n",
		cable_mode, altmode->vdo, orientation, info);
	*cable_info = info;
	return 0;
}

static int apple_cio_usb4_cable_info(struct apple_cio *acio,
				     struct typec_altmode *altmode, u32 *cable_info)
{
	u32 info = TB_VSE_CAP_APPLE_CABLE_INFO_PRESENT;
	enum typec_orientation orientation;
	u32 eudo = altmode->eudo;

	if (FIELD_GET(EUDO_USB_MODE_MASK, eudo) != EUDO_USB_MODE_USB4)
		return -EINVAL;

	orientation = typec_altmode_get_orientation(altmode);
	if (FIELD_GET(EUDO_CABLE_TYPE_MASK, eudo) != EUDO_CABLE_TYPE_PASSIVE)
		info |= TB_VSE_CAP_APPLE_CABLE_INFO_ACTIVE_CABLE;
	if (FIELD_GET(EUDO_CABLE_SPEED_MASK, eudo) == EUDO_CABLE_SPEED_USB4_GEN3)
		info |= TB_VSE_CAP_APPLE_CABLE_INFO_20_GBPS;
	if (orientation == TYPEC_ORIENTATION_REVERSE)
		info |= TB_VSE_CAP_APPLE_CABLE_INFO_ORIENTATION_REVERSE;

	dev_dbg(acio->dev, "USB4 cable: EUDO %#x, orientation %d -> cable info %#x\n",
		eudo, orientation, info);
	*cable_info = info;
	return 0;
}

static int apple_cio_altmode_notify(struct notifier_block *nb,
				    unsigned long action, void *data)
{
	struct apple_cio_altmode *subscription;
	struct typec_altmode *altmode = data;
	struct apple_cio *acio;
	u32 cable_info;
	int ret;

	subscription = container_of(nb, struct apple_cio_altmode, notifier);
	acio = subscription->acio;

	if (altmode != subscription->altmode)
		return NOTIFY_DONE;

	switch (action) {
	case TYPEC_ALTMODE_ENTERED:
		if (altmode->mode_kind == TYPEC_MODE_KIND_ALTMODE &&
		    altmode->svid == USB_TYPEC_TBT_SID)
			ret = apple_cio_tbt_cable_info(acio, altmode, &cable_info);
		else if (altmode->mode_kind == TYPEC_MODE_KIND_USB4)
			ret = apple_cio_usb4_cable_info(acio, altmode, &cable_info);
		else
			ret = -EINVAL;
		if (ret) {
			dev_err(acio->dev, "failed to read Type-C cable information: %d\n", ret);
			return NOTIFY_OK;
		}
		break;
	case TYPEC_ALTMODE_EXITED:
		cable_info = 0;
		break;
	default:
		return NOTIFY_DONE;
	}

	/*
	 * The altmode has already been negotiated and we can't exit it anyway
	 * on Apple Silicon so just warn the we couldn't start but still return
	 * success.
	 */
	ret = apple_cio_set_cable_info(acio, cable_info);
	if (ret)
		dev_warn(acio->dev, "failed to start ACIO: %d\n", ret);

	return NOTIFY_OK;
}

static struct apple_cio_altmode *
apple_cio_altmode_subscription(struct apple_cio *acio, struct typec_altmode *altmode)
{
	if (altmode->mode_kind == TYPEC_MODE_KIND_ALTMODE &&
	    altmode->svid == USB_TYPEC_TBT_SID)
		return &acio->tbt_altmode;
	if (altmode->mode_kind == TYPEC_MODE_KIND_USB4)
		return &acio->usb4_altmode;
	return NULL;
}

static bool apple_cio_altmode_matches(struct apple_cio *acio,
				      struct typec_altmode *altmode)
{
	if (!apple_cio_altmode_subscription(acio, altmode))
		return false;

	return dev_fwnode(altmode->dev.parent->parent) == acio->connector;
}

static int apple_cio_altmode_attach_locked(struct apple_cio *acio,
					   struct typec_altmode *altmode)
{
	struct apple_cio_altmode *subscription;
	int ret;

	lockdep_assert_held(&acio->typec_lock);

	if (!apple_cio_altmode_matches(acio, altmode))
		return 0;

	subscription = apple_cio_altmode_subscription(acio, altmode);

	if (subscription->altmode == altmode)
		return 0;
	if (subscription->altmode)
		return -EBUSY;

	get_device(&altmode->dev);
	subscription->altmode = altmode;
	ret = typec_altmode_register_notifier(altmode, &subscription->notifier);
	if (ret) {
		subscription->altmode = NULL;
		put_device(&altmode->dev);
	}

	return ret;
}

static int apple_cio_altmode_attach(struct apple_cio *acio,
				    struct typec_altmode *altmode)
{
	guard(mutex)(&acio->typec_lock);

	return apple_cio_altmode_attach_locked(acio, altmode);
}

static void apple_cio_altmode_detach(struct apple_cio *acio,
				     struct typec_altmode *altmode)
{
	struct apple_cio_altmode *subscription;
	bool active;

	subscription = apple_cio_altmode_subscription(acio, altmode);
	if (!subscription)
		return;

	guard(mutex)(&acio->typec_lock);
	if (subscription->altmode != altmode)
		return;

	active = altmode->active;
	typec_altmode_unregister_notifier(altmode, &subscription->notifier);
	subscription->altmode = NULL;
	if (active)
		apple_cio_set_cable_info(acio, 0);
	put_device(&altmode->dev);
}

static int apple_cio_typec_notify(struct notifier_block *nb,
				  unsigned long action, void *data)
{
	struct apple_cio *acio = container_of(nb, struct apple_cio, typec_notifier);
	struct typec_altmode *altmode;
	struct device *dev = data;
	int ret;

	if (!is_typec_partner_altmode(dev))
		return NOTIFY_DONE;

	altmode = to_typec_altmode(dev);
	switch (action) {
	case BUS_NOTIFY_ADD_DEVICE:
		ret = apple_cio_altmode_attach(acio, altmode);
		if (ret)
			dev_err(acio->dev,
				"failed to register for alternate mode notifications: %d\n", ret);
		break;
	case BUS_NOTIFY_DEL_DEVICE:
	case BUS_NOTIFY_REMOVED_DEVICE:
		apple_cio_altmode_detach(acio, altmode);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static int apple_cio_scan_altmode(struct device *dev, void *data)
{
	if (!is_typec_partner_altmode(dev))
		return 0;

	return apple_cio_altmode_attach_locked(data, to_typec_altmode(dev));
}

static void apple_cio_unregister_typec(struct apple_cio *acio)
{
	bus_unregister_notifier(&typec_bus, &acio->typec_notifier);
	if (acio->tbt_altmode.altmode)
		apple_cio_altmode_detach(acio, acio->tbt_altmode.altmode);
	if (acio->usb4_altmode.altmode)
		apple_cio_altmode_detach(acio, acio->usb4_altmode.altmode);
}

static void apple_cio_put_connector(void *data)
{
	struct apple_cio *acio = data;

	fwnode_handle_put(acio->connector);
}

static int apple_cio_probe(struct platform_device *pdev)
{
	struct dev_pm_domain_attach_data pd_data = {
		.pd_flags = PD_FLAG_NO_DEV_LINK,
	};
	struct device *dev = &pdev->dev;
	struct fwnode_handle *endpoint;
	struct apple_cio *acio;
	int ret;

	acio = devm_kzalloc(dev, sizeof(*acio), GFP_KERNEL);
	if (!acio)
		return -ENOMEM;
	platform_set_drvdata(pdev, acio);

	ret = devm_mutex_init(dev, &acio->lock);
	if (ret)
		return ret;

	ret = devm_mutex_init(dev, &acio->typec_lock);
	if (ret)
		return ret;

	init_completion(&acio->nhi_boot_completion);
	acio->dev = &pdev->dev;
	acio->np = dev->of_node;
	acio->typec_notifier.notifier_call = apple_cio_typec_notify;
	acio->tbt_altmode.acio = acio;
	acio->tbt_altmode.notifier.notifier_call = apple_cio_altmode_notify;
	acio->usb4_altmode.acio = acio;
	acio->usb4_altmode.notifier.notifier_call = apple_cio_altmode_notify;

	endpoint = fwnode_graph_get_endpoint_by_id(dev_fwnode(dev), 1, 0, 0);
	if (!endpoint)
		return dev_err_probe(dev, -ENODEV, "unable to find Type-C graph endpoint\n");
	acio->connector = fwnode_graph_get_remote_port_parent(endpoint);
	fwnode_handle_put(endpoint);
	if (!acio->connector)
		return dev_err_probe(dev, -ENODEV, "unable to find Type-C connector\n");
	ret = devm_add_action_or_reset(dev, apple_cio_put_connector, acio);
	if (ret)
		return ret;

	acio->sram_res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "sram");
	if (!acio->sram_res)
		return dev_err_probe(dev, -EIO, "failed to get SRAM resource\n");
	acio->sram_base = devm_ioremap_resource(dev, acio->sram_res);
	if (IS_ERR(acio->sram_base))
		return dev_err_probe(dev, PTR_ERR(acio->sram_base), "failed to map SRAM\n");

	acio->rc_res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "rc");
	acio->rc_base = devm_ioremap_resource(&pdev->dev, acio->rc_res);
	if (IS_ERR(acio->rc_base))
		return dev_err_probe(dev, PTR_ERR(acio->rc_base), "unable to map rc regs\n");
	acio->rc_tunable =
		devm_apple_tunable_parse(dev, acio->np, "apple,tunable-rc", acio->rc_res);
	if (IS_ERR(acio->rc_tunable))
		return dev_err_probe(dev, PTR_ERR(acio->rc_tunable),
				     "unable to load rc tunable\n");

	acio->reset = devm_reset_control_get_exclusive(dev, NULL);
	if (IS_ERR(acio->reset))
		return dev_err_probe(dev, PTR_ERR(acio->reset), "unable to get CIO reset\n");

	/*
	 * If there is only a single PM domain listed in the device tree the
	 * platform driver framework will already attach it. Thus, if we find an
	 * already attached PM domain here something's wrong in the device tree
	 * because we expect at least three separate domains that we have to
	 * control manually.
	 */
	if (dev->pm_domain) {
		dev_err(dev, "PM domain already attached, check if the DT lists three domains\n");
		return -EINVAL;
	}

	/*
	 * Find and attach the PM domains but don't power them on yet since we must only
	 * do that after the PHY has already been configured into USB4/Thunderbolt mode.
	 */
	ret = devm_pm_domain_attach_list(dev, &pd_data, &acio->pd_list);
	if (ret < 0)
		return dev_err_probe(dev, ret, "unable to attach PM domains\n");
	else if (ret < 3)
		return dev_err_probe(dev, -EINVAL, "not enough PM domains\n");

	ret = bus_register_notifier(&typec_bus, &acio->typec_notifier);
	if (ret)
		return dev_err_probe(dev, ret, "unable to register Type-C notifier\n");

	scoped_guard(mutex, &acio->typec_lock) {
		ret = bus_for_each_dev(&typec_bus, NULL, acio, apple_cio_scan_altmode);
	}
	if (ret) {
		apple_cio_unregister_typec(acio);
		return dev_err_probe(dev, ret,
				     "unable to register for alternate modes notifications\n");
	}

	return 0;
}

static void apple_cio_remove(struct platform_device *pdev)
{
	struct apple_cio *acio = platform_get_drvdata(pdev);

	apple_cio_unregister_typec(acio);

	guard(mutex)(&acio->lock);
	if (acio->current_cable_info)
		apple_cio_stop(acio);
}

static int apple_cio_prepare(struct device *dev)
{
	struct apple_cio *acio = dev_get_drvdata(dev);

	guard(mutex)(&acio->lock);

	if (acio->current_cable_info) {
		dev_err(dev, "unable to suspend while a USB4/Thunderbolt connection is active\n");
		return -EBUSY;
	}

	return 0;
}

static const struct dev_pm_ops apple_cio_pm_ops = {
	.prepare = apple_cio_prepare,
};

static const struct of_device_id apple_acio_match[] = {
	{
		.compatible = "apple,t8103-usb4-acio",
	},
	{},
};
MODULE_DEVICE_TABLE(of, apple_acio_match);

static struct platform_driver apple_cio_driver = {
	.driver = {
		.name = "thunderbolt-apple-acio",
		.of_match_table = apple_acio_match,
		.pm = pm_sleep_ptr(&apple_cio_pm_ops),
	},
	.probe = apple_cio_probe,
	.remove = apple_cio_remove,
};

static struct platform_driver * const apple_cio_drivers[] = {
	&apple_nhi_driver,
	&apple_cio_driver,
};

static int __init apple_cio_init(void)
{
	return platform_register_drivers(apple_cio_drivers,
					 ARRAY_SIZE(apple_cio_drivers));
}
module_init(apple_cio_init);

static void __exit apple_cio_exit(void)
{
	platform_unregister_drivers(apple_cio_drivers,
				    ARRAY_SIZE(apple_cio_drivers));
}
module_exit(apple_cio_exit);

MODULE_AUTHOR("Sven Peter <sven@kernel.org>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Apple Silicon USB4/Thunderbolt driver");
