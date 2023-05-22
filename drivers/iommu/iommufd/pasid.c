// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, Intel Corporation
 */
#include <linux/iommufd.h>
#include <linux/iommu.h>
#include "../iommu-priv.h"

#include "iommufd_private.h"

static int __iommufd_device_pasid_do_attach(struct iommufd_device *idev,
					    u32 pasid,
					    struct iommufd_hw_pagetable *hwpt,
					    bool replace)
{
	void *curr;
	int rc;

	refcount_inc(&hwpt->obj.users);
	curr = xa_cmpxchg(&idev->pasid_hwpts, pasid, NULL, hwpt, GFP_KERNEL);
	if (curr && xa_err(curr)) {
		rc = -EBUSY;
		goto err_put_hwpt;
	}

	if (!replace)
		rc = iommu_attach_device_pasid(hwpt->domain, idev->dev, pasid);
	else
		rc = iommu_replace_device_pasid(hwpt->domain, idev->dev, pasid);
	if (rc) {
		xa_erase(&idev->pasid_hwpts, pasid);
		goto err_put_hwpt;
	}

	return 0;

err_put_hwpt:
	refcount_dec(&hwpt->obj.users);
	return rc;
}

struct iommufd_hw_pagetable *
iommufd_device_pasid_do_attach(struct iommufd_device *idev, u32 pasid,
			       struct iommufd_hw_pagetable *hwpt)
{
	int rc;

	rc = __iommufd_device_pasid_do_attach(idev, pasid, hwpt, false);
	return rc ? ERR_PTR(rc) : NULL;
}

struct iommufd_hw_pagetable *
iommufd_device_pasid_do_replace(struct iommufd_device *idev, u32 pasid,
				struct iommufd_hw_pagetable *hwpt)
{
	struct iommufd_hw_pagetable *old_hwpt;
	int rc;

	old_hwpt = xa_erase(&idev->pasid_hwpts, pasid);
	if (!old_hwpt)
		return ERR_PTR(-EINVAL);

	if (hwpt == old_hwpt)
		return NULL;

	rc = __iommufd_device_pasid_do_attach(idev, pasid, hwpt, true);
	if (rc)
		xa_store(&idev->pasid_hwpts, pasid, old_hwpt, GFP_KERNEL);

	/* Caller must destroy old_hwpt */
	return rc ? ERR_PTR(rc) : old_hwpt;
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
 * iommufd does not handle race between iommufd_device_pasid_attach(),
 * iommufd_device_pasid_replace() and iommufd_device_pasid_detach().
 * So caller of them should guarantee no concurrent call on the same
 * device and pasid.
 */
int iommufd_device_pasid_attach(struct iommufd_device *idev,
				u32 pasid, u32 *pt_id)
{
	struct attach_data data = {
		.pasid_attach_fn = &iommufd_device_pasid_do_attach,
		.pasid = pasid,
	};

	return iommufd_device_change_pt(idev, pt_id, &data);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_attach, IOMMUFD);

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
 * iommufd does not handle race between iommufd_device_pasid_replace(),
 * iommufd_device_pasid_attach() and iommufd_device_pasid_detach().
 * So caller of them should guarantee no concurrent call on the same
 * device and pasid.
 */
int iommufd_device_pasid_replace(struct iommufd_device *idev,
				 u32 pasid, u32 *pt_id)
{
	struct attach_data data = {
		.pasid_attach_fn = &iommufd_device_pasid_do_replace,
		.pasid = pasid,
	};

	return iommufd_device_change_pt(idev, pt_id, &data);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_replace, IOMMUFD);

/**
 * iommufd_device_pasid_detach - Disconnect a {device, pasid} to an iommu_domain
 * @idev: device to detach
 * @pasid: pasid to detach
 *
 * Undo iommufd_device_pasid_attach(). This disconnects the idev/pasid from
 * the previously attached pt_id.
 *
 * iommufd does not handle race between iommufd_device_pasid_detach(),
 * iommufd_device_pasid_attach() and iommufd_device_pasid_replace().
 * So caller of them should guarantee no concurrent call on the same
 * device and pasid.
 */
void iommufd_device_pasid_detach(struct iommufd_device *idev, u32 pasid)
{
	struct iommufd_hw_pagetable *hwpt;

	hwpt = xa_erase(&idev->pasid_hwpts, pasid);
	if (WARN_ON(!hwpt))
		return;
	iommu_detach_device_pasid(hwpt->domain, idev->dev, pasid);
	iommufd_hw_pagetable_put(idev->ictx, hwpt);
}
EXPORT_SYMBOL_NS_GPL(iommufd_device_pasid_detach, IOMMUFD);
