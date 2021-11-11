// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2021 Intel Corporation
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommufd.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/file.h>
#include <linux/pci.h>

#include "iommufd_private.h"

/*
 * A iommufd_device object represents the binding relationship between a
 * consuming driver and the iommufd. These objects are created/destroyed by
 * external drivers, not by userspace.
 */
struct iommufd_device {
	struct iommufd_object obj;
	struct iommufd_ctx *ictx;
	struct iommufd_hw_pagetable *hwpt;
	/* Heat at iommufd_hw_pagetable::devices */
	struct list_head devices_item;
	/* always the physical device */
	struct device *dev;
	struct iommu_group *group;
	u64 dev_cookie;
};

void iommufd_device_destroy(struct iommufd_object *obj)
{
	struct iommufd_device *idev =
		container_of(obj, struct iommufd_device, obj);

	iommu_device_release_dma_owner(idev->dev,
				       DMA_OWNER_PRIVATE_DOMAIN_USER);
	fput(idev->ictx->filp);
}

/**
 * iommufd_bind_pci_device - Bind a physical device marked by a device cookie to
 *                           an iommu fd.
 * @fd: iommufd file descriptor.
 * @pdev: Pointer to a physical device struct.
 * @id: ID number to return to userspace for this device
 * @dev_cookie: A cookie that is returned to userspace in events
 *
 * A successful bind establishes a security context for the device and returns
 * struct iommufd_device pointer. Otherwise returns error pointer. An external
 * driver must call this function before touching the pci_dev in any way. Until
 * it returns the pci_dev could be subject to external manipulation via PCI P2P.
 *
 * Binding a PCI device places the entire base RID under iommufd control.
 *
 * The caller must undo this with iommufd_unbind_device()
 */
struct iommufd_device *iommufd_bind_pci_device(int fd, struct pci_dev *pdev,
					       u32 *id, u64 dev_cookie)
{
	struct iommufd_device *idev;
	struct iommufd_ctx *ictx;
	int rc;

	ictx = iommufd_fget(fd);
	if (!ictx)
		return ERR_PTR(-EINVAL);

	rc = iommu_device_set_dma_owner(
		&pdev->dev, DMA_OWNER_PRIVATE_DOMAIN_USER, ictx->filp);
	if (rc)
		goto out_file_put;

	idev = iommufd_object_alloc(ictx, idev, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		goto out_release_owner;
	}
	idev->ictx = ictx;
	idev->dev = &pdev->dev;
	idev->dev_cookie = dev_cookie;
	/* The calling driver is a user until iommufd_unbind_device() */
	refcount_inc(&idev->obj.users);

	/*
	 * If the caller fails after this success it must call
	 * iommufd_unbind_device() which is safe since we hold this refcount.
	 * This also means the device is a leaf in the graph and no other object
	 * can take a reference on it.
	 */
	iommufd_object_finalize(ictx, &idev->obj);
	*id = idev->obj.id;
	return idev;

out_release_owner:
	iommu_device_release_dma_owner(&pdev->dev,
				       DMA_OWNER_PRIVATE_DOMAIN_USER);
out_file_put:
	fput(ictx->filp);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL_GPL(iommufd_bind_pci_device);

void iommufd_unbind_device(struct iommufd_device *idev)
{
	bool was_destroyed;

	was_destroyed = iommufd_object_destroy_user(idev->ictx, &idev->obj);
	WARN_ON(!was_destroyed);
}
EXPORT_SYMBOL_GPL(iommufd_unbind_device);

static bool iommufd_hw_pagetable_has_group(struct iommufd_hw_pagetable *hwpt,
					   struct iommu_group *group)
{
	struct iommufd_device *cur_dev;

	list_for_each_entry (cur_dev, &hwpt->devices, devices_item)
		if (cur_dev->group == group)
			return true;
	return false;
}

/**
 * iommufd_device_attach - Connect a device to a page table
 * @idev: device to attach
 * @pt_id: Input a IOMMUFD_OBJ_IOAS_PAGETABLE, or IOMMUFD_OBJ_HW_PAGETABLE
 *         Output the IOMMUFD_OBJ_HW_PAGETABLE if an IOAS was specified.
 *
 * This connects the device to an page table, either automatically or manually
 * selected. Once this completes the device could do DMA.
 *
 * The caller should return the resulting pt_id back to userspace.
 * This function is undone by calling iommufd_device_detach().
 */
int iommufd_device_attach(struct iommufd_device *idev, u32 *pt_id)
{
	struct iommufd_hw_pagetable *hwpt;
	struct iommu_group *group;
	int rc;

	refcount_inc(&idev->obj.users);

	hwpt = iommufd_hw_pagetable_from_id(idev->ictx, *pt_id, idev->dev);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_users;
	}

	group = iommu_group_get(idev->dev);
	if (!group) {
		rc = -ENODEV;
		goto out_put;
	}

	mutex_lock(&hwpt->devices_lock);
	if (!iommufd_hw_pagetable_has_group(hwpt, group)) {
		rc = iommu_attach_group(hwpt->domain, group);
		if (rc)
			goto out_unlock;

		/*
		 * hwpt is now the exclusive owner of the group, thus there now
		 * is no other reserved entries using group in the iopt
		 */
		rc = iopt_table_enforce_group_iova(&hwpt->ioaspt->iopt, group);
		if (rc)
			goto out_detach;
	}

	idev->hwpt = hwpt;
	idev->group = group;
	list_add(&idev->devices_item, &hwpt->devices);
	mutex_unlock(&hwpt->devices_lock);

	/* FIXME: For PCI devices need to check the MSI like VFIO does */

	*pt_id = idev->hwpt->obj.id;
	return 0;

out_detach:
	iommu_detach_group(hwpt->domain, group);
out_unlock:
	mutex_unlock(&hwpt->devices_lock);
	iommu_group_put(group);
out_put:
	iommufd_hw_pagetable_put(idev->ictx, hwpt);
out_users:
	refcount_dec(&idev->obj.users);
	return rc;
}
EXPORT_SYMBOL_GPL(iommufd_device_attach);

void iommufd_device_detach(struct iommufd_device *idev)
{
	mutex_lock(&idev->hwpt->devices_lock);
	list_del(&idev->devices_item);
	if (!iommufd_hw_pagetable_has_group(idev->hwpt, idev->group)) {
		iopt_remove_reserved_iova(&idev->hwpt->ioaspt->iopt,
					  idev->group);
		iommu_detach_group(idev->hwpt->domain, idev->group);
	}
	mutex_unlock(&idev->hwpt->devices_lock);

	iommu_group_put(idev->group);
	idev->group = NULL;

	iommufd_hw_pagetable_put(idev->ictx, idev->hwpt);
	idev->hwpt = NULL;

	refcount_dec(&idev->obj.users);
}
EXPORT_SYMBOL_GPL(iommufd_device_detach);
