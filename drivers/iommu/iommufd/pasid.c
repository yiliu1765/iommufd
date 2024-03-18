// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, Intel Corporation
 */
#include <linux/iommufd.h>
#include <linux/iommu.h>
#include "../iommu-priv.h"

#include "iommufd_private.h"

struct iommufd_hw_pagetable *
iommufd_device_pasid_do_attach(struct iommufd_device *idev, ioasid_t pasid,
			       struct iommufd_hw_pagetable *hwpt)
{
	void *curr;
	int rc;

	mutex_lock(&idev->igroup->lock);
	curr = xa_cmpxchg(&idev->pasid_hwpts, pasid, NULL, hwpt, GFP_KERNEL);
	if (curr) {
		if (curr == hwpt)
			rc = 0;
		else
			rc = xa_err(curr) ? : -EINVAL;
		goto out_unlock;
	}

	rc = iommufd_hwpt_attach_device(hwpt, idev, pasid);
	if (rc)
		goto out_erase;

	mutex_unlock(&idev->igroup->lock);
	refcount_inc(&hwpt->obj.users);
	return NULL;

out_erase:
	xa_erase(&idev->pasid_hwpts, pasid);
out_unlock:
	mutex_unlock(&idev->igroup->lock);
	return rc ? ERR_PTR(rc) : NULL;
}

struct iommufd_hw_pagetable *
iommufd_device_pasid_do_replace(struct iommufd_device *idev, ioasid_t pasid,
				struct iommufd_hw_pagetable *hwpt)
{
	void *curr;
	int rc;

	mutex_lock(&idev->igroup->lock);
	curr = xa_store(&idev->pasid_hwpts, pasid, hwpt, GFP_KERNEL);
	rc = xa_err(curr);
	if (rc)
		goto out_unlock;

	if (curr == hwpt)
		goto out_unlock;

	/* Not replace case */
	if (!curr) {
		xa_erase(&idev->pasid_hwpts, pasid);
		rc = -EINVAL;
		goto out_unlock;
	}

	/*
	 * After replacement, the reference on the old hwpt is retained
	 * in this thread as caller would free it.
	 */
	rc = iommufd_hwpt_replace_device(idev, pasid, hwpt, curr);
	if (rc) {
		WARN_ON(xa_err(xa_store(&idev->pasid_hwpts, pasid,
					curr, GFP_KERNEL)));
		goto out_unlock;
	}

	mutex_unlock(&idev->igroup->lock);
	refcount_inc(&hwpt->obj.users);
	/* Caller must destroy old_hwpt */
	return curr;

out_unlock:
	mutex_unlock(&idev->igroup->lock);
	return rc ? ERR_PTR(rc) : NULL;
}

/**
 * iommufd_device_pasid_attach - Connect a {device, pasid} to an iommu_domain
 * @idev: device to attach
 * @pasid: pasid to attach
 * @pt_id: Input a IOMMUFD_OBJ_IOAS, or IOMMUFD_OBJ_HW_PAGETABLE
 *         Output the IOMMUFD_OBJ_HW_PAGETABLE ID
 *
 * This connects a pasid of the device to an iommu_domain. Once this
 * completes the device could do DMA with the pasid.
 *
 * This function is undone by calling iommufd_device_detach_pasid().
 *
 * Return 0 for success, otherwise errno.
 */
int iommufd_device_pasid_attach(struct iommufd_device *idev,
				ioasid_t pasid, u32 *pt_id)
{
	return iommufd_device_change_pt(idev, pasid, pt_id,
					&iommufd_device_pasid_do_attach);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_attach, "IOMMUFD");

/**
 * iommufd_device_pasid_replace - Change the {device, pasid}'s iommu_domain
 * @idev: device to change
 * @pasid: pasid to change
 * @pt_id: Input a IOMMUFD_OBJ_IOAS, or IOMMUFD_OBJ_HW_PAGETABLE
 *         Output the IOMMUFD_OBJ_HW_PAGETABLE ID
 *
 * This is the same as
 *   iommufd_device_pasid_detach();
 *   iommufd_device_pasid_attach();
 *
 * If it fails then no change is made to the attachment. The iommu driver may
 * implement this so there is no disruption in translation. This can only be
 * called if iommufd_device_pasid_attach() has already succeeded.
 *
 * Return 0 for success, otherwise errno.
 */
int iommufd_device_pasid_replace(struct iommufd_device *idev,
				 ioasid_t pasid, u32 *pt_id)
{
	return iommufd_device_change_pt(idev, pasid, pt_id,
					&iommufd_device_pasid_do_replace);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_replace, "IOMMUFD");

/**
 * iommufd_device_pasid_detach - Disconnect a {device, pasid} to an iommu_domain
 * @idev: device to detach
 * @pasid: pasid to detach
 *
 * Undo iommufd_device_pasid_attach(). This disconnects the idev/pasid from
 * the previously attached pt_id.
 */
void iommufd_device_pasid_detach(struct iommufd_device *idev, ioasid_t pasid)
{
	struct iommufd_hw_pagetable *hwpt;

	mutex_lock(&idev->igroup->lock);
	hwpt = xa_erase(&idev->pasid_hwpts, pasid);
	if (WARN_ON(!hwpt)) {
		mutex_unlock(&idev->igroup->lock);
		return;
	}
	iommufd_hwpt_detach_device(hwpt, idev, pasid);
	mutex_unlock(&idev->igroup->lock);
	iommufd_hw_pagetable_put(idev->ictx, hwpt);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_detach, "IOMMUFD");
