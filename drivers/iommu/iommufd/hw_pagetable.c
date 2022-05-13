// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/circ_buf.h>

#include "iommufd_private.h"

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable_user *uhwpt);

void iommufd_hw_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);

	WARN_ON(!list_empty(&hwpt->devices));
	if (hwpt->type == IOMMUFD_HWPT_KERNEL) {
		struct iommufd_ioas *ioas = hwpt->kernel.ioas;

		mutex_lock(&ioas->mutex);
		list_del(&hwpt->kernel.auto_domains_item);
		mutex_unlock(&ioas->mutex);
		WARN_ON(!list_empty(&hwpt->kernel.stage1_domains));
		mutex_destroy(&hwpt->kernel.mutex);
		refcount_dec(&ioas->obj.users);
	} else {
		struct iommufd_hw_pagetable *parent = hwpt->user.parent;

		mutex_lock(&parent->kernel.mutex);
		list_del(&hwpt->user.stage1_domains_item);
		mutex_unlock(&parent->kernel.mutex);
		refcount_dec(&parent->obj.users);
		iommufd_hw_pagetable_dma_fault_destroy(&hwpt->user);
	}

	iommu_domain_free(hwpt->domain);
	mutex_destroy(&hwpt->devices_lock);
}

/*
 * When automatically managing the domains we search for a compatible domain in
 * the iopt and if one is found use it, otherwise create a new domain.
 * Automatic domain selection will never pick a manually created domain.
 */
static struct iommufd_hw_pagetable *
iommufd_hw_pagetable_auto_get(struct iommufd_ctx *ictx,
			      struct iommufd_ioas *ioas, struct device *dev)
{
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_hw_pagetable_kernel *kernel;
	int rc;

	/*
	 * There is no differentiation when domains are allocated, so any domain
	 * from the right ops is interchangeable with any other.
	 */
	mutex_lock(&ioas->mutex);
	list_for_each_entry (kernel, &ioas->auto_domains, auto_domains_item) {
		hwpt = container_of(kernel, struct iommufd_hw_pagetable, kernel);
		/*
		 * FIXME: We really need an op from the driver to test if a
		 * device is compatible with a domain. This thing from VFIO
		 * works sometimes.
		 */
		if (hwpt->domain->ops == dev_iommu_ops(dev)->default_domain_ops) {
			if (refcount_inc_not_zero(&hwpt->obj.users)) {
				mutex_unlock(&ioas->mutex);
				return hwpt;
			}
		}
	}

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_unlock;
	}

	hwpt->domain = iommu_domain_alloc(dev->bus);
	if (!hwpt->domain) {
		rc = -ENOMEM;
		goto out_abort;
	}

	INIT_LIST_HEAD(&hwpt->devices);
	mutex_init(&hwpt->devices_lock);
	hwpt->type = IOMMUFD_HWPT_KERNEL;
	kernel = &hwpt->kernel;
	kernel->ioas = ioas;
	INIT_LIST_HEAD(&kernel->stage1_domains);
	mutex_init(&kernel->mutex);

	/* The calling driver is a user until iommufd_hw_pagetable_put() */
	refcount_inc(&ioas->obj.users);

	list_add_tail(&kernel->auto_domains_item, &ioas->auto_domains);
	/*
	 * iommufd_object_finalize() consumes the refcount, get one for the
	 * caller. This pairs with the first put in
	 * iommufd_object_destroy_user()
	 */
	refcount_inc(&hwpt->obj.users);
	iommufd_object_finalize(ictx, &hwpt->obj);

	mutex_unlock(&ioas->mutex);
	return hwpt;

out_abort:
	iommufd_object_abort(ictx, &hwpt->obj);
out_unlock:
	mutex_unlock(&ioas->mutex);
	return ERR_PTR(rc);
}

static enum iommu_page_response_code
iommufd_hw_pagetable_iopf_handler(struct iommu_fault *fault, void *data)
{
	struct iommufd_hw_pagetable_user *uhwpt =
				(struct iommufd_hw_pagetable_user *)data;
	struct iommufd_hw_pagetable *hwpt =
		container_of(uhwpt, struct iommufd_hw_pagetable, user);
	struct iommufd_hwpt_dma_fault *header =
		(struct iommufd_hwpt_dma_fault *)uhwpt->fault_pages;
	int head, tail, size;
	struct iommu_fault *new;
	u32 dev_id;
	int ret = 0;

	if (WARN_ON(!header))
		return -ENOENT;

	dev_id = iommufd_hw_pagetable_get_dev_id(hwpt, NULL); // wait for iommu core pass in dev
	if (dev_id == IOMMUFD_INVALID_ID)
		return -EINVAL;

	new = (struct iommu_fault *)(uhwpt->fault_pages + header->offset +
				     header->head * header->entry_size);

	mutex_lock(&uhwpt->fault_queue_lock);

	pr_debug("%s, enque fault event\n", __func__);
	head = header->head;
	tail = header->tail;
	size = header->nb_entries;

	if (CIRC_SPACE(head, tail, size) < 1) {
		ret = -ENOSPC;
		goto unlock;
	}

	*new = *fault;
	header->head = (head + 1) % size;
unlock:
	mutex_unlock(&uhwpt->fault_queue_lock);
	if (ret)
		return ret;

	mutex_lock(&uhwpt->notify_gate);
	pr_debug("%s, signal userspace!\n", __func__);
	if (uhwpt->trigger)
		eventfd_signal(uhwpt->trigger, 1);
	mutex_unlock(&uhwpt->notify_gate);

	return 0;
}

/**
 * iommufd_hw_pagetable_from_id() - Get an iommu_domain for a device
 * @ictx: iommufd context
 * @pt_id: ID of the IOAS or hw_pagetable object
 * @dev: Device to get an iommu_domain for
 *
 * Turn a general page table ID into an iommu_domain contained in a
 * iommufd_hw_pagetable object. If a hw_pagetable ID is specified then that
 * iommu_domain is used, otherwise a suitable iommu_domain in the IOAS is found
 * for the device, creating one automatically if necessary.
 */
struct iommufd_hw_pagetable *
iommufd_hw_pagetable_from_id(struct iommufd_ctx *ictx, u32 pt_id,
			     struct device *dev)
{
	struct iommufd_object *obj;

	obj = iommufd_get_object(ictx, pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(obj))
		return ERR_CAST(obj);

	switch (obj->type) {
	case IOMMUFD_OBJ_HW_PAGETABLE: {
		struct iommufd_hw_pagetable * hwpt;

		hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);
		if (!hwpt->domain) {
			hwpt->domain = iommu_domain_alloc(dev->bus);
			if (!hwpt->domain) {
				iommufd_put_object(obj);
				return ERR_PTR(-ENOMEM);
			}
			if (hwpt->type == IOMMUFD_HWPT_USER_S1) {
				/* TODO: Needs to pass the page table ptr, pgtbl config
				 * and parent domain to iommu layer, iommu layer should
				 * store the info and use the info to setup pasid entry
				 * or pasid table in the CD table and enable nested translation
				 * when calling with iommu_attach_device_pasid()
				 * Wait for iommu API ready */
				hwpt->domain->iopf_handler = iommufd_hw_pagetable_iopf_handler;
				hwpt->domain->fault_data = hwpt;
			}
		}
		iommufd_put_object_keep_user(obj);
		return hwpt;
	}
	case IOMMUFD_OBJ_IOAS: {
		struct iommufd_ioas *ioas =
			container_of(obj, struct iommufd_ioas, obj);
		struct iommufd_hw_pagetable *hwpt;

		hwpt = iommufd_hw_pagetable_auto_get(ictx, ioas, dev);
		iommufd_put_object(obj);
		return hwpt;
	}
	default:
		iommufd_put_object(obj);
		return ERR_PTR(-EINVAL);
	}
}

void iommufd_hw_pagetable_put(struct iommufd_ctx *ictx,
			      struct iommufd_hw_pagetable *hwpt)
{
	if (list_empty(&hwpt->kernel.auto_domains_item)) {
		/* Manually created hw_pagetables just keep going */
		refcount_dec(&hwpt->obj.users);
		return;
	}
	iommufd_object_destroy_user(ictx, &hwpt->obj);
}

static int iommufd_hw_pagetable_eventfd_setup(struct eventfd_ctx **ctx, int fd)
{
	struct eventfd_ctx *efdctx;

	efdctx = eventfd_ctx_fdget(fd);
	if (IS_ERR(efdctx))
		return PTR_ERR(efdctx);
	if (*ctx)
		eventfd_ctx_put(*ctx);
	*ctx = efdctx;
	return 0;
}

static void iommufd_hw_pagetable_eventfd_destroy(struct eventfd_ctx **ctx)
{
	eventfd_ctx_put(*ctx);
	*ctx = NULL;
}

static size_t hwpt_dma_fault_rw(struct iommufd_hw_pagetable_user *uhwpt,
				char __user *buf, size_t count,
				loff_t *ppos, bool iswrite)
{
	loff_t pos = *ppos;
	void *base = uhwpt->fault_pages;
	size_t size = uhwpt->fault_region_size;
	int ret = -EFAULT;

	if (pos >= size)
		return -EINVAL;

	count = min(count, (size_t)(size - pos));

	mutex_lock(&uhwpt->fault_queue_lock);

	if (iswrite) {
		struct iommufd_hwpt_dma_fault *header =
			(struct iommufd_hwpt_dma_fault *)base;
		u32 new_tail;

		/* Only allows write to the tail which is placed at offset 0 */
		if (pos != 0 || count != 4) {
			ret = -EINVAL;
			goto unlock;
		}

		if (copy_from_user((void *)&new_tail, buf, count))
			goto unlock;

		if (new_tail > header->nb_entries) {
			ret = -EINVAL;
			goto unlock;
		}
		header->tail = new_tail;
	} else {
		if (copy_to_user(buf, base + pos, count))
			goto unlock;
	}
	*ppos += count;
	ret = count;
unlock:
	mutex_unlock(&uhwpt->fault_queue_lock);
	return ret;
}

static ssize_t hwpt_fault_fops_read(struct file *filep, char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable_user *uhwpt = filep->private_data;

	return hwpt_dma_fault_rw(uhwpt, buf, count, ppos, false);
}

static ssize_t hwpt_fault_fops_write(struct file *filep,
				     const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct iommufd_hw_pagetable_user *uhwpt = filep->private_data;

	return hwpt_dma_fault_rw(uhwpt, buf, count, ppos, true);
}

static const struct file_operations hwpt_fault_fops = {
	.owner		= THIS_MODULE,
	.read		= hwpt_fault_fops_read,
	.write		= hwpt_fault_fops_write,
};

static int iommufd_hw_pagetable_get_fault_fd(struct iommufd_hw_pagetable_user *uhwpt)
{
	struct file *filep;
	int fdno, ret;

	fdno = ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		return ret;

	filep = anon_inode_getfile("[hwpt-fault]", &hwpt_fault_fops,
				   uhwpt, O_RDWR);
	if (IS_ERR(filep)) {
		put_unused_fd(fdno);
		return PTR_ERR(filep);
	}

	filep->f_mode |= (FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	fd_install(fdno, filep);

	return ret;
}

#define DMA_FAULT_RING_LENGTH 512

static int
iommufd_hw_pagetable_dma_fault_init(struct iommufd_hw_pagetable_user *uhwpt,
				    int eventfd)
{
	struct iommufd_hwpt_dma_fault *header;
	size_t size;
	int rc, fd;

	mutex_init(&uhwpt->fault_queue_lock);
	mutex_init(&uhwpt->notify_gate);

	/*
	 * We provision 1 page for the header and space for
	 * DMA_FAULT_RING_LENGTH fault records in the ring buffer.
	 */
	size = ALIGN(sizeof(struct iommu_fault) *
		     DMA_FAULT_RING_LENGTH, PAGE_SIZE) + PAGE_SIZE;

	uhwpt->fault_pages = kzalloc(size, GFP_KERNEL);
	if (!uhwpt->fault_pages)
		return -ENOMEM;

	header = (struct iommufd_hwpt_dma_fault *)uhwpt->fault_pages;
	header->entry_size = sizeof(struct iommu_fault);
	header->nb_entries = DMA_FAULT_RING_LENGTH;
	header->offset = PAGE_SIZE;
	uhwpt->fault_region_size = size;

	rc = iommufd_hw_pagetable_eventfd_setup(&uhwpt->trigger, eventfd);
	if (rc)
		goto out_free;

	fd = rc = iommufd_hw_pagetable_get_fault_fd(uhwpt);
	if (rc < 0)
		goto out_destroy_eventfd;

	return fd;

out_destroy_eventfd:
	iommufd_hw_pagetable_eventfd_destroy(&uhwpt->trigger);
out_free:
	kfree(uhwpt->fault_pages);
	return rc;
}

static void
iommufd_hw_pagetable_dma_fault_destroy(struct iommufd_hw_pagetable_user *uhwpt)
{
	struct iommufd_hwpt_dma_fault *header =
		(struct iommufd_hwpt_dma_fault *)uhwpt->fault_pages;

	WARN_ON(header->tail != header->head);
	iommufd_hw_pagetable_eventfd_destroy(&uhwpt->trigger);
	kfree(uhwpt->fault_pages);
	mutex_destroy(&uhwpt->fault_queue_lock);
	mutex_destroy(&uhwpt->notify_gate);
}

int iommufd_hwpt_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_alloc *cmd = ucmd->cmd;
	struct iommufd_object *parent_obj;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_hw_pagetable *parent;
	struct iommufd_hw_pagetable_user *user;
	int rc, fd;

	if (cmd->flags)
		return -EOPNOTSUPP;

	if (cmd->eventfd < 0)
		return -EINVAL;

	parent_obj = iommufd_get_object(ucmd->ictx, cmd->parent_hwpt_id,
					IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(parent_obj))
		return PTR_ERR(parent_obj);

	parent = container_of(parent_obj, struct iommufd_hw_pagetable, obj);
	if (parent->type != IOMMUFD_HWPT_KERNEL) {
		rc = -EINVAL;
		goto out_put;
	}

	hwpt = iommufd_object_alloc(ucmd->ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_put;
	}

	INIT_LIST_HEAD(&hwpt->devices);
	mutex_init(&hwpt->devices_lock);
	hwpt->type = IOMMUFD_HWPT_USER_S1;
	user = &hwpt->user;
	user->parent = parent;
	user->stage1_ptr = cmd->stage1_ptr;
	user->config = cmd->config;

	/*
	 * iommufd_object_finalize() consumes the refcount, get one for the
	 * caller. This pairs with the first put in
	 * iommufd_object_destroy_user()
	 */
	refcount_inc(&hwpt->obj.users);

	fd = rc = iommufd_hw_pagetable_dma_fault_init(&hwpt->user, cmd->eventfd);
	if (rc < 0)
		goto out_abort;

	cmd->out_hwpt_id = hwpt->obj.id;
	cmd->out_fault_fd = fd;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_destroy_dma;

	mutex_lock(&parent->kernel.mutex);
	list_add_tail(&user->stage1_domains_item, &parent->kernel.stage1_domains);
	mutex_unlock(&parent->kernel.mutex);
	iommufd_object_finalize(ucmd->ictx, &hwpt->obj);

	return 0;
out_destroy_dma:
	iommufd_hw_pagetable_dma_fault_destroy(&hwpt->user);
out_abort:
	iommufd_object_abort(ucmd->ictx, &hwpt->obj);
out_put:
	iommufd_put_object(parent_obj);
	return rc;
}

int iommufd_hwpt_invalidate_cache(struct iommufd_ucmd *ucmd)
{
	struct iommu_cache_invalidate_info *cmd = ucmd->cmd;
	struct iommufd_object *obj;
	struct iommufd_hw_pagetable *hwpt;
	int rc = 0;

	if (cmd->flags)
		return -EOPNOTSUPP;

	/* TODO: more sanity check when the struct is finalized */
	obj = iommufd_get_object(ucmd->ictx, cmd->hwpt_id,
				 IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	hwpt = container_of(obj, struct iommufd_hw_pagetable, obj);
	if (hwpt->type != IOMMUFD_HWPT_USER_S1) {
		rc = -EINVAL;
		goto out_put;
	}

	/* wait for iommu API
	iommu_invalidate_cache(hwpt->domain, cache_info);
	*/

out_put:
	iommufd_put_object(obj);
	return rc;
}
