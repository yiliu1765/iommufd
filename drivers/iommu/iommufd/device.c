// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommufd.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/file.h>
#include <linux/pci.h>
#include <linux/irqdomain.h>
#include <linux/dma-iommu.h>
#include <linux/dma-map-ops.h>

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
	/* Head at iommufd_hw_pagetable::devices */
	struct list_head devices_item;
	/* always the physical device */
	struct device *dev;
	struct iommu_group *group;
};

void iommufd_device_destroy(struct iommufd_object *obj)
{
	struct iommufd_device *idev =
		container_of(obj, struct iommufd_device, obj);

	iommu_group_release_dma_owner(idev->group);
	iommu_group_put(idev->group);
	iommufd_ctx_put(idev->ictx);
}

/**
 * iommufd_device_bind - Bind a physical device to an iommu fd
 * @ictx: iommufd file descriptor
 * @dev: Pointer to a physical PCI device struct
 * @id: Output ID number to return to userspace for this device
 *
 * A successful bind establishes an ownership over the device and returns
 * struct iommufd_device pointer, otherwise returns error pointer.
 *
 * A driver using this API must set driver_managed_dma and must not touch
 * the device until this routine succeeds and establishes ownership.
 *
 * Binding a PCI device places the entire RID under iommufd control.
 *
 * The caller must undo this with iommufd_unbind_device()
 */
struct iommufd_device *iommufd_device_bind(struct iommufd_ctx *ictx,
					   struct device *dev, u32 *id)
{
	struct iommufd_device *idev;
	struct iommu_group *group;
	int rc;

       /*
        * iommufd always sets IOMMU_CACHE because we offer no way for userspace
        * to restore cache coherency.
        */
	if (!iommu_capable(dev->bus, IOMMU_CAP_CACHE_COHERENCY))
		return ERR_PTR(-EINVAL);

	group = iommu_group_get(dev);
	if (!group)
		return ERR_PTR(-ENODEV);

	/*
	 * FIXME: Use a device-centric iommu api, this won't work with
	 * multi-device groups
	 */
	rc = iommu_group_claim_dma_owner(group, ictx);
	if (rc)
		goto out_group_put;

	idev = iommufd_object_alloc(ictx, idev, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		goto out_release_owner;
	}
	idev->ictx = ictx;
	iommufd_ctx_get(ictx);
	idev->dev = dev;
	/* The calling driver is a user until iommufd_device_unbind() */
	refcount_inc(&idev->obj.users);
	/* group refcount moves into iommufd_device */
	idev->group = group;

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
	iommu_group_release_dma_owner(group);
out_group_put:
	iommu_group_put(group);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL_GPL(iommufd_device_bind);

void iommufd_device_unbind(struct iommufd_device *idev)
{
	bool was_destroyed;

	was_destroyed = iommufd_object_destroy_user(idev->ictx, &idev->obj);
	WARN_ON(!was_destroyed);
}
EXPORT_SYMBOL_GPL(iommufd_device_unbind);

/**
 * iommufd_device_enforced_coherent - True if no-snoop TLPs are blocked
 * @idev: device to query
 *
 * This can only be called if the device is attached, and the caller must ensure
 * that the this is not raced with iommufd_device_attach() /
 * iommufd_device_detach().
 */
bool iommufd_device_enforced_coherent(struct iommufd_device *idev)
{
	return iommufd_ioas_enforced_coherent(idev->hwpt->ioas);
}
EXPORT_SYMBOL_GPL(iommufd_device_enforced_coherent);

static int iommufd_device_setup_msi(struct iommufd_device *idev,
				    struct iommufd_hw_pagetable *hwpt,
				    phys_addr_t sw_msi_start,
				    unsigned int flags)
{
	int rc;

	/*
	 * IOMMU_CAP_INTR_REMAP means that the platform is isolating MSI,
	 * nothing further to do.
	 */
	if (iommu_capable(idev->dev->bus, IOMMU_CAP_INTR_REMAP))
		return 0;

	/*
	 * On ARM systems that set the global IRQ_DOMAIN_FLAG_MSI_REMAP every
	 * allocated iommu_domain will block interrupts by default and this
	 * special flow is needed to turn them back on.
	 */
	if (irq_domain_check_msi_remap()) {
		if (WARN_ON(!sw_msi_start))
			return -EPERM;
		/*
		 * iommu_get_msi_cookie() can only be called once per domain,
		 * it returns -EBUSY on later calls.
		 */
		if (hwpt->msi_cookie)
			return 0;
		rc = iommu_get_msi_cookie(hwpt->domain, sw_msi_start);
		if (rc && rc != -ENODEV)
			return rc;
		hwpt->msi_cookie = true;
		return 0;
	}

	/*
	 * Otherwise the platform has a MSI window that is not isolated. For
	 * historical compat with VFIO allow a module parameter to ignore the
	 * insecurity.
	 */
	if (!(flags & IOMMUFD_ATTACH_FLAGS_ALLOW_UNSAFE_INTERRUPT))
		return -EPERM;
	return 0;
}

static bool iommufd_hw_pagetable_has_group(struct iommufd_hw_pagetable *hwpt,
					   struct iommu_group *group)
{
	struct iommufd_device *cur_dev;

	list_for_each_entry (cur_dev, &hwpt->devices, devices_item)
		if (cur_dev->group == group)
			return true;
	return false;
}

static int iommufd_device_do_attach(struct iommufd_device *idev,
				    struct iommufd_hw_pagetable *hwpt,
				    unsigned int flags)
{
	int rc;

	mutex_lock(&hwpt->devices_lock);
	/*
	 * FIXME: Use a device-centric iommu api. For now check if the
	 * hw_pagetable already has a device of the same group joined to tell if
	 * we are the first and need to attach the group.
	 */
	if (!iommufd_hw_pagetable_has_group(hwpt, idev->group)) {
		phys_addr_t sw_msi_start = 0;

		rc = iommu_attach_group(hwpt->domain, idev->group);
		if (rc)
			goto out_unlock;

		/*
		 * hwpt is now the exclusive owner of the group so this is the
		 * first time enforce is called for this group.
		 */
		rc = iopt_table_enforce_group_resv_regions(
			&hwpt->ioas->iopt, idev->group, &sw_msi_start);
		if (rc)
			goto out_detach;
		rc = iommufd_device_setup_msi(idev, hwpt, sw_msi_start, flags);
		if (rc)
			goto out_iova;

		if (list_empty(&hwpt->devices)) {
			rc = iopt_table_add_domain(&hwpt->ioas->iopt,
						   hwpt->domain);
			if (rc)
				goto out_iova;
		}
	}

	idev->hwpt = hwpt;
	refcount_inc(&hwpt->obj.users);
	list_add(&idev->devices_item, &hwpt->devices);
	mutex_unlock(&hwpt->devices_lock);
	return 0;

out_iova:
	iopt_remove_reserved_iova(&hwpt->ioas->iopt, idev->group);
out_detach:
	iommu_detach_group(hwpt->domain, idev->group);
out_unlock:
	mutex_unlock(&hwpt->devices_lock);
	return rc;
}

/*
 * When automatically managing the domains we search for a compatible domain in
 * the iopt and if one is found use it, otherwise create a new domain.
 * Automatic domain selection will never pick a manually created domain.
 */
static int iommufd_device_auto_get_domain(struct iommufd_device *idev,
					  struct iommufd_ioas *ioas,
					  unsigned int flags)
{
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	/*
	 * There is no differentiation when domains are allocated, so any domain
	 * that is willing to attach to the device is interchangeable with any
	 * other.
	 */
	mutex_lock(&ioas->mutex);
	list_for_each_entry (hwpt, &ioas->hwpt_list, hwpt_item) {
		if (!hwpt->auto_domain ||
		    !refcount_inc_not_zero(&hwpt->obj.users))
			continue;

		/*
		 * FIXME: if the group is already attached to a domain make sure
		 * this returns EMEDIUMTYPE
		 */
		rc = iommufd_device_do_attach(idev, hwpt, flags);
		refcount_dec(&hwpt->obj.users);
		if (rc) {
			if (rc == -EMEDIUMTYPE)
				continue;
			goto out_unlock;
		}
		goto out_unlock;
	}

	hwpt = iommufd_hw_pagetable_alloc(idev->ictx, ioas, idev->dev);
	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_unlock;
	}
	hwpt->auto_domain = true;

	rc = iommufd_device_do_attach(idev, hwpt, flags);
	if (rc)
		goto out_abort;
	list_add_tail(&hwpt->hwpt_item, &ioas->hwpt_list);

	mutex_unlock(&ioas->mutex);
	iommufd_object_finalize(idev->ictx, &hwpt->obj);
	return 0;

out_abort:
	iommufd_object_abort_and_destroy(idev->ictx, &hwpt->obj);
out_unlock:
	mutex_unlock(&ioas->mutex);
	return rc;
}

/**
 * iommufd_device_attach - Connect a device to an iommu_domain
 * @idev: device to attach
 * @pt_id: Input a IOMMUFD_OBJ_IOAS, or IOMMUFD_OBJ_HW_PAGETABLE
 *         Output the IOMMUFD_OBJ_HW_PAGETABLE ID
 * @flags: Optional flags
 *
 * This connects the device to an iommu_domain, either automatically or manually
 * selected. Once this completes the device could do DMA.
 *
 * The caller should return the resulting pt_id back to userspace.
 * This function is undone by calling iommufd_device_detach().
 */
int iommufd_device_attach(struct iommufd_device *idev, u32 *pt_id,
			  unsigned int flags)
{
	struct iommufd_object *pt_obj;
	int rc;

	pt_obj = iommufd_get_object(idev->ictx, *pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(pt_obj))
		return PTR_ERR(pt_obj);

	switch (pt_obj->type) {
	case IOMMUFD_OBJ_HW_PAGETABLE: {
		struct iommufd_hw_pagetable *hwpt =
			container_of(pt_obj, struct iommufd_hw_pagetable, obj);

		rc = iommufd_device_do_attach(idev, hwpt, flags);
		if (rc)
			goto out_put_pt_obj;

		mutex_lock(&hwpt->ioas->mutex);
		list_add_tail(&hwpt->hwpt_item, &hwpt->ioas->hwpt_list);
		mutex_unlock(&hwpt->ioas->mutex);
		break;
	}
	case IOMMUFD_OBJ_IOAS: {
		struct iommufd_ioas *ioas =
			container_of(pt_obj, struct iommufd_ioas, obj);

		rc = iommufd_device_auto_get_domain(idev, ioas, flags);
		if (rc)
			goto out_put_pt_obj;
		break;
	}
	default:
		rc = -EINVAL;
		goto out_put_pt_obj;
	}

	refcount_inc(&idev->obj.users);
	*pt_id = idev->hwpt->obj.id;
	rc = 0;

out_put_pt_obj:
	iommufd_put_object(pt_obj);
	return rc;
}
EXPORT_SYMBOL_GPL(iommufd_device_attach);

void iommufd_device_detach(struct iommufd_device *idev)
{
	struct iommufd_hw_pagetable *hwpt = idev->hwpt;

	mutex_lock(&hwpt->ioas->mutex);
	mutex_lock(&hwpt->devices_lock);
	list_del(&idev->devices_item);
	if (!iommufd_hw_pagetable_has_group(hwpt, idev->group)) {
		if (list_empty(&hwpt->devices)) {
			iopt_table_remove_domain(&hwpt->ioas->iopt,
						 hwpt->domain);
			list_del(&hwpt->hwpt_item);
		}
		iopt_remove_reserved_iova(&hwpt->ioas->iopt, idev->group);
		iommu_detach_group(hwpt->domain, idev->group);
	}
	mutex_unlock(&hwpt->devices_lock);
	mutex_unlock(&hwpt->ioas->mutex);

	if (hwpt->auto_domain)
		iommufd_object_destroy_user(idev->ictx, &hwpt->obj);
	else
		refcount_dec(&hwpt->obj.users);

	idev->hwpt = NULL;

	refcount_dec(&idev->obj.users);
}
EXPORT_SYMBOL_GPL(iommufd_device_detach);
