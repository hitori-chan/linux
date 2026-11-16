// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple Neural Engine: the engine's DMA confined to the client whose call runs.
 *
 * The firmware's CPU and its task manager go through ane_dart0 (LLT), the engine's reads and writes through
 * ane_dart1 (BRD) and ane_dart2 (BWR): on t6034 a call with BRD's and BWR's stream 0 off times out with the
 * firmware still up, and with LLT's off the firmware never answers its handshake. A program's task descriptors
 * give the engine its addresses as offsets from the buffers a call binds, but neither the firmware nor
 * macOS's kext bounds them (rda ane_fw_t603x_1483 sub_48580 0x48580, sub_36E18 0x36e18), nor the extents the
 * strides and sizes give; so the bound is the DART.
 *
 * ane0 keeps LLT and the DMA API's domain, where the firmware, its heap, the sections and every buffer get
 * their addresses. The DT's "engine" child of ane0 holds BRD and BWR: a device of its own here, whose DMA the
 * driver owns. Its DARTs point at one ane_vm at a time, a paging domain per file holding that file's buffer
 * objects and the .hwx of its programs (read-only) at the addresses LLT gives them. The firmware's memory and
 * the other files' buffers are on no table of the engine's. One file's calls are on the engine at a time
 * (ane-accel.c, ane_prepare_job).
 */

#include <linux/cleanup.h>
#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include "ane.h"

/* LLT's domain maps in the DART's 16K pages (ane_map_at) */
#define ANE_VM_PAGE	SZ_16K

/*
 * A test's fallback, not a confinement: should the task manager fetch its BAR block or TDs through BRD, the
 * firmware's window (__TEXT, __DATA, its heap) read-only in every address space too.
 */
static bool engine_fw_window;
module_param(engine_fw_window, bool, 0600);
MODULE_PARM_DESC(engine_fw_window, "Mirror the firmware's window read-only to the engine (a test; default: no)");

static void ane_vm_release(struct kref *ref)
{
	struct ane_vm *vm = container_of(ref, struct ane_vm, ref);
	struct apple_ane *ane = vm->ane;

	if (vm->domain) {
		/* no call of its own is on the engine: its jobs, programs and buffers held it */
		mutex_lock(&ane->vm_lock);
		if (ane->engine_vm == vm) {
			iommu_detach_group(vm->domain, ane->engine_group);
			spin_lock(&ane->job_lock);
			ane->engine_vm = NULL;
			spin_unlock(&ane->job_lock);
		}
		mutex_unlock(&ane->vm_lock);
		iommu_domain_free(vm->domain);
	}
	kfree(vm);
}

/* An empty address space; without the engine's device, one with no domain, where every step is a no-op */
struct ane_vm *ane_vm_create(struct apple_ane *ane)
{
	struct ane_vm *vm;
	int ret;

	vm = kzalloc(sizeof(*vm), GFP_KERNEL);
	if (!vm)
		return ERR_PTR(-ENOMEM);
	kref_init(&vm->ref);
	vm->ane = ane;
	if (ane->engine) {
		vm->domain = iommu_paging_domain_alloc(ane->engine);
		if (IS_ERR(vm->domain)) {
			ret = PTR_ERR(vm->domain);
			kfree(vm);
			return ERR_PTR(ret);
		}
	}
	return vm;
}

struct ane_vm *ane_vm_get(struct ane_vm *vm)
{
	kref_get(&vm->ref);
	return vm;
}

void ane_vm_put(struct ane_vm *vm)
{
	if (vm)
		kref_put(&vm->ref, ane_vm_release);
}

/*
 * The pages LLT's domain maps at [iova, iova + size) mapped again at the same addresses in vm's, physically
 * contiguous runs at once: a buffer has one address for the firmware and the engine. ane0 is not
 * dma-coherent, so the DMA API's own entries carry no IOMMU_CACHE either.
 */
int ane_vm_map(struct ane_vm *vm, dma_addr_t iova, size_t size, int prot)
{
	struct apple_ane *ane = vm->ane;
	size_t off = 0, run;
	phys_addr_t phys;
	int ret;

	if (!vm->domain)
		return 0;
	if (!IS_ALIGNED(iova | size, ANE_VM_PAGE))
		return -EINVAL;
	while (off < size) {
		phys = iommu_iova_to_phys(ane->domain, iova + off);
		if (!phys) {
			ret = -EFAULT;
			goto fail;
		}
		for (run = ANE_VM_PAGE; off + run < size; run += ANE_VM_PAGE)
			if (iommu_iova_to_phys(ane->domain, iova + off + run) != phys + run)
				break;
		ret = iommu_map(vm->domain, iova + off, phys, run, prot, GFP_KERNEL);
		if (ret)
			goto fail;
		off += run;
	}
	return 0;

fail:
	if (off)
		iommu_unmap(vm->domain, iova, off);
	return ret;
}

/* Before the pages go back to LLT's allocator */
void ane_vm_unmap(struct ane_vm *vm, dma_addr_t iova, size_t size)
{
	size_t done;

	if (!vm->domain)
		return;
	done = iommu_unmap(vm->domain, iova, size);
	if (done != size)
		dev_warn(vm->ane->dev, "engine unmap at %pad: %#zx of %#zx bytes\n", &iova, done, size);
}

/*
 * Under ane->lock, no call of another address space on the engine: vm on the engine's DARTs. The switch
 * passes the blocking domain (their streams off) and flushes both DARTs' TLBs.
 */
int ane_vm_attach(struct ane_vm *vm)
{
	struct apple_ane *ane = vm->ane;
	int ret = 0;

	if (!vm->domain)
		return 0;
	/* the window as this boot of the firmware maps it in LLT's domain: contiguous, ane_fw_boot */
	if (engine_fw_window && ane->running && vm->fw_gen != ane->fw_gen) {
		if (vm->fw_gen)
			ane_vm_unmap(vm, ane->text.iova, ANE_FW_WINDOW);
		vm->fw_gen = ane_vm_map(vm, ane->text.iova, ANE_FW_WINDOW, IOMMU_READ) ? 0 : ane->fw_gen;
	}
	/*
	 * The firmware's heap, read-only: the task manager fetches a call's blocks from it through BRD (T1, int
	 * #617: a fault at heap + 0xd53e40 on conv16's every call). A boot of the firmware allocates it anew, and
	 * the engine runs nothing before the next attach, so the mirror follows the boot here.
	 */
	if (ane->running && ane->heap.cpu && vm->heap_gen != ane->fw_gen) {
		if (vm->heap_gen)
			ane_vm_unmap(vm, vm->heap_iova, vm->heap_size);
		vm->heap_gen = 0;
		ret = ane_vm_map(vm, ane->heap.iova, ane->heap.size, IOMMU_READ);
		if (ret) {
			dev_err(ane->dev, "the firmware's heap in a file's tables: %d\n", ret);
			return ret;
		}
		vm->heap_gen = ane->fw_gen;
		vm->heap_iova = ane->heap.iova;
		vm->heap_size = ane->heap.size;
	}
	mutex_lock(&ane->vm_lock);
	if (ane->engine_vm != vm) {
		if (ane->engine_vm)
			iommu_detach_group(ane->engine_vm->domain, ane->engine_group);
		ret = iommu_attach_group(vm->domain, ane->engine_group);
		if (ret)
			dev_err(ane->dev, "the engine's DARTs on a file's tables: %d\n", ret);
		spin_lock(&ane->job_lock);
		ane->engine_vm = ret ? NULL : vm;
		spin_unlock(&ane->job_lock);
	}
	mutex_unlock(&ane->vm_lock);
	return ret;
}

static void ane_engine_destroy(void *data)
{
	struct apple_ane *ane = data;

	mutex_lock(&ane->vm_lock);
	if (ane->engine_vm) {
		iommu_detach_group(ane->engine_vm->domain, ane->engine_group);
		spin_lock(&ane->job_lock);
		ane->engine_vm = NULL;
		spin_unlock(&ane->job_lock);
	}
	mutex_unlock(&ane->vm_lock);
	pm_runtime_disable(ane->engine);
	iommu_device_release_dma_owner(ane->engine);
	iommu_group_put(ane->engine_group);
	of_platform_device_destroy(ane->engine, NULL);
	ane->engine = NULL;
}

/*
 * At the probe: the engine's device from ane0's "engine" node, its DMA owned by the driver (the blocking
 * domain until a file's is attached), suspended until the firmware runs (ane_fw_boot). Without the node
 * (an older DT, all three DARTs on ane0) the driver runs as before, unconfined.
 */
int ane_engine_init(struct apple_ane *ane)
{
	struct device_node *np __free(device_node) = of_get_child_by_name(ane->dev->of_node, "engine");
	struct platform_device *pdev;
	int ret;

	ret = devm_mutex_init(ane->dev, &ane->vm_lock);
	if (ret)
		return ret;
	if (!np) {
		dev_warn(ane->dev, "no engine node: a program reaches every client's buffers and takes CAP_SYS_ADMIN\n");
		return 0;
	}
	pdev = of_platform_device_create(np, NULL, ane->dev);
	if (!pdev)
		return dev_err_probe(ane->dev, -ENODEV, "cannot create the engine's device\n");
	ane->engine = &pdev->dev;

	/* the IOMMU core took it at its creation if its DARTs had probed; else this defers */
	if (!device_iommu_mapped(ane->engine)) {
		ret = of_dma_configure(ane->engine, np, true);
		if (!ret && !device_iommu_mapped(ane->engine))
			ret = -EPROBE_DEFER;
		if (ret)
			goto fail_destroy;
	}
	ane->engine_group = iommu_group_get(ane->engine);
	if (!ane->engine_group) {
		ret = -ENODEV;
		goto fail_destroy;
	}
	ret = iommu_device_claim_dma_owner(ane->engine, ane);
	if (ret)
		goto fail_group;

	/*
	 * As ane0 at its probe: suspended, which drops the references the DART links took at the IOMMU's
	 * probe, so BRD and BWR suspend until the firmware's boot resumes the engine.
	 */
	pm_runtime_set_suspended(ane->engine);
	pm_runtime_enable(ane->engine);
	return devm_add_action_or_reset(ane->dev, ane_engine_destroy, ane);

fail_group:
	iommu_group_put(ane->engine_group);
	ane->engine_group = NULL;
fail_destroy:
	of_platform_device_destroy(ane->engine, NULL);
	ane->engine = NULL;
	return dev_err_probe(ane->dev, ret, "the engine's DARTs\n");
}
