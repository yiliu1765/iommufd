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

struct iommufd_device_attach_data {
	unsigned int flags;
	ioasid_t pasid;
};

void iommufd_device_destroy(struct iommufd_object *obj)
{
	struct iommufd_device *idev =
		container_of(obj, struct iommufd_device, obj);

	if (idev->dma_owner_claimed)
		iommu_group_release_dma_owner(idev->group);
	iommu_group_put(idev->group);
	fput(idev->ictx->filp);
}

/**
 * iommufd_bind_device - Bind a physical device to an iommu fd
 * @fd: iommufd file descriptor.
 * @pdev: Pointer to a physical PCI device struct
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
struct iommufd_device *iommufd_bind_device(int fd, struct device *dev,
					   unsigned int flags, u32 *id)
{
	struct iommufd_device *idev;
	struct iommufd_ctx *ictx;
	struct iommu_group *group;
	int rc;

       /*
        * iommufd always sets IOMMU_CACHE because we offer no way for userspace
        * to restore cache coherency.
        */
       if (!iommu_capable(dev->bus, IOMMU_CAP_CACHE_COHERENCY))
		return ERR_PTR(-EINVAL);

	ictx = iommufd_fget(fd);
	if (!ictx)
		return ERR_PTR(-EINVAL);

	group = iommu_group_get(dev);
	if (!group) {
		rc = -ENODEV;
		goto out_file_put;
	}

	/*
	 * FIXME: Use a device-centric iommu api and this won't work with
	 * multi-device groups
	 */
	if (!(flags & IOMMUFD_BIND_FLAGS_BYPASS_DMA_OWNERSHIP)) {
		rc = iommu_group_claim_dma_owner(group, ictx->filp);
		if (rc)
			goto out_group_put;
	}

	idev = iommufd_object_alloc(ictx, idev, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		goto out_release_owner;
	}
	idev->ictx = ictx;
	idev->dev = dev;
	idev->dma_owner_claimed =
		!(flags & IOMMUFD_BIND_FLAGS_BYPASS_DMA_OWNERSHIP);
	xa_init_flags(&idev->pasid_xa, XA_FLAGS_ALLOC | XA_FLAGS_ACCOUNT);
	mutex_init(&idev->pasid_lock);
	/* The calling driver is a user until iommufd_unbind_device() */
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
	if ((!flags & IOMMUFD_BIND_FLAGS_BYPASS_DMA_OWNERSHIP))
		iommu_group_release_dma_owner(group);
out_group_put:
	iommu_group_put(group);
out_file_put:
	fput(ictx->filp);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL_GPL(iommufd_bind_device);

void iommufd_unbind_device(struct iommufd_device *idev)
{
	bool was_destroyed;

	was_destroyed = iommufd_object_destroy_user(idev->ictx, &idev->obj);
	WARN_ON(!was_destroyed);
}
EXPORT_SYMBOL_GPL(iommufd_unbind_device);

int iommufd_device_get_info(struct iommufd_ucmd *ucmd)
{
	struct iommu_device_info *cmd = ucmd->cmd;
	struct iommufd_object *obj;
	struct iommufd_device *idev;
	struct iommu_hw_info hw_info;
	u32 user_length;
	int rc;

	if (cmd->flags || cmd->reserved || cmd->dev_id == IOMMUFD_INVALID_ID)
		return -EOPNOTSUPP;

	obj = iommufd_get_object(ucmd->ictx, cmd->dev_id, IOMMUFD_OBJ_DEVICE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	idev = container_of(obj, struct iommufd_device, obj);

	rc = iommu_get_hw_info(idev->dev, &hw_info);
	if (rc < 0)
		goto out_put;

	cmd->iommu_hw_type = hw_info.type;

	if (hw_info.data_length <= cmd->hw_data_len &&
	    copy_to_user((void __user *)cmd->hw_data_ptr,
			 &hw_info.data, hw_info.data_length)) {
		rc = -EFAULT;
		goto out_put;
	}

	user_length = cmd->hw_data_len;
	cmd->hw_data_len = hw_info.data_length;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_put;

	if (hw_info.data_length > user_length) {
		rc = -EMSGSIZE;
	}

out_put:
	iommufd_put_object(obj);
	return rc;
}

static int iommufd_device_setup_msi(struct iommufd_device *idev,
				    struct iommufd_hw_pagetable *hwpt,
				    phys_addr_t sw_msi_start,
				    unsigned int flags)
{
	struct iommufd_hw_pagetable_ioas *ioas_hwpt = &hwpt->ioas_hwpt;
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
		if (ioas_hwpt->msi_cookie)
			return 0;
		rc = iommu_get_msi_cookie(hwpt->domain, sw_msi_start);
		if (rc && rc != -ENODEV)
			return rc;
		ioas_hwpt->msi_cookie = true;
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

unsigned int
iommufd_hw_pagetable_get_dev_id(struct iommufd_hw_pagetable *hwpt,
				struct device *dev, ioasid_t pasid)
{
	struct iommufd_hwpt_device *hdev = NULL;
	unsigned long index;

	mutex_lock(&hwpt->devices_lock);
	xa_for_each (&hwpt->devices, index, hdev)
		if (hdev->idev->dev == dev && hdev->pasid == pasid) {
			mutex_unlock(&hwpt->devices_lock);
			return hdev->idev->obj.id;
		}
	mutex_unlock(&hwpt->devices_lock);

	return IOMMUFD_INVALID_ID;
}

static bool iommufd_hw_pagetable_has_group(struct iommufd_hw_pagetable *hwpt,
					   struct iommu_group *group)
{
	struct iommufd_hwpt_device *hdev = NULL;
	unsigned long index;

	xa_for_each (&hwpt->devices, index, hdev)
		if (hdev->idev->group == group)
			return true;
	return false;
}

static int device_attach_ioas_hwpt(struct iommufd_device *idev,
				   struct iommufd_hw_pagetable *hwpt,
				   unsigned int flags)
{
	phys_addr_t sw_msi_start = 0;
	int rc;

	/*
	 * hwpt is now the exclusive owner of the group so this is the
	 * first time enforce is called for this group.
	 */
	rc = iopt_table_enforce_group_resv_regions(
		&hwpt->ioas_hwpt.ioas->iopt, idev->group, &sw_msi_start);
	if (rc)
		return rc;
	rc = iommufd_device_setup_msi(idev, hwpt, sw_msi_start, flags);
	if (rc)
		goto out_iova;
	if ((hwpt->type == IOMMUFD_HWPT_IOAS_AUTO) && xa_empty(&hwpt->devices)) {
		rc = iopt_table_add_domain(&hwpt->ioas_hwpt.ioas->iopt, hwpt->domain);
		if (rc)
		goto out_iova;
	}
	return 0;
out_iova:
	iopt_remove_reserved_iova(&hwpt->ioas_hwpt.ioas->iopt, idev->group);
	return rc;
}

static void device_detach_ioas_hwpt(struct iommufd_device *idev,
				    struct iommufd_hw_pagetable *hwpt,
				    bool *destroy_auto_domain)
{
	struct iommufd_hw_pagetable_ioas *ioas_hwpt = &hwpt->ioas_hwpt;

	if ((hwpt->type == IOMMUFD_HWPT_IOAS_AUTO) && xa_empty(&hwpt->devices)) {
		iopt_table_remove_domain(&ioas_hwpt->ioas->iopt,
					 hwpt->domain);
		if (!list_empty(&ioas_hwpt->auto_domains_item)) {
			list_del_init(&ioas_hwpt->auto_domains_item);
			if (destroy_auto_domain)
				*destroy_auto_domain = true;
		}
	}
	iopt_remove_reserved_iova(&ioas_hwpt->ioas->iopt, idev->group);
}

static int iommufd_device_attach_domain(struct iommufd_device *idev,
					struct iommu_domain *domain,
				        ioasid_t pasid)
{
	int rc;

	if (pasid == INVALID_IOASID)
		rc = iommu_attach_group(domain, idev->group);
	else
		rc = iommu_attach_device_pasid(domain, idev->dev, pasid);
	return rc;
}

static void iommufd_device_detach_domain(struct iommufd_device *idev,
					 struct iommu_domain *domain,
					 ioasid_t pasid)
{
	if (pasid == INVALID_IOASID)
		iommu_detach_group(domain, idev->group);
	else
		iommu_detach_device_pasid(domain, idev->dev, pasid);

}

static int iommufd_device_attach_hwpt(struct iommufd_device *idev,
				      struct iommufd_hw_pagetable *hwpt,
				      struct iommufd_device_attach_data *attach)
{
	unsigned int flags = attach->flags;
	int rc;

	/*
	 * FIXME: Use a device-centric iommu api. For now check if the
	 * hw_pagetable already has a device of the same group joined to tell if
	 * we are the first and need to attach the group.
	 */
	if (iommufd_hw_pagetable_has_group(hwpt, idev->group))
		return 0;

	rc = iommufd_device_attach_domain(idev, hwpt->domain, attach->pasid);
	if (rc)
		return rc;

	if (hwpt->type == IOMMUFD_HWPT_IOAS_AUTO ||
	    hwpt->type == IOMMUFD_HWPT_IOAS_USER) {
		rc = device_attach_ioas_hwpt(idev, hwpt, flags);
		if (rc)
			iommufd_device_detach_domain(idev, hwpt->domain,
						     attach->pasid);
	}

	return rc;
}

static void iommufd_device_detach_hwpt(struct iommufd_hwpt_device *hdev,
				       ioasid_t pasid,
				       bool *destroy_auto_domain)
{
	struct iommufd_device *idev = hdev->idev;
	struct iommufd_hw_pagetable *hwpt = hdev->hwpt;

	if (iommufd_hw_pagetable_has_group(hdev->hwpt, idev->group))
		return;

	if (hwpt->type == IOMMUFD_HWPT_IOAS_AUTO ||
	    hwpt->type == IOMMUFD_HWPT_IOAS_USER)
		device_detach_ioas_hwpt(idev, hwpt, destroy_auto_domain);

	iommufd_device_detach_domain(idev, hwpt->domain, pasid);
}

static struct iommufd_hwpt_device *
iommufd_alloc_hwpt_device(struct iommufd_hw_pagetable *hwpt,
			  struct iommufd_device *idev, ioasid_t pasid)
{
	struct iommufd_hwpt_device *hdev;

	hdev = kzalloc(sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return NULL;

	hdev->hwpt = hwpt;
	hdev->idev = idev;
	hdev->pasid = pasid;

	return hdev;
}

static int iommufd_device_do_attach(struct iommufd_device *idev,
				    struct iommufd_hw_pagetable *hwpt,
				    struct iommufd_device_attach_data *attach,
				    struct iommufd_hwpt_device **out_hdev)
{
	struct iommufd_hwpt_device *hdev, *tmp;
	int rc;

	mutex_lock(&hwpt->devices_lock);
	hdev = iommufd_alloc_hwpt_device(hwpt, idev, attach->pasid);
	if (!hdev) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	rc = iommufd_device_attach_hwpt(idev, hwpt, attach);
	if (rc)
		goto out_free;

	rc = xa_alloc(&hwpt->devices, &hdev->hwpt_xa_id, hdev,
		      xa_limit_32b, GFP_KERNEL_ACCOUNT);
	if (rc)
		goto out_detach;
	tmp = xa_store(&idev->pasid_xa, attach->pasid, hdev, GFP_KERNEL_ACCOUNT);
	if (IS_ERR(tmp)) {
		rc = PTR_ERR(tmp);
		goto out_release_hwpt_xa_id;
	}
	refcount_inc(&hwpt->obj.users);
	mutex_unlock(&hwpt->devices_lock);
	if (out_hdev)
		*out_hdev = hdev;
	return 0;
out_release_hwpt_xa_id:
	xa_erase(&idev->pasid_xa, attach->pasid);
out_detach:
	iommufd_device_detach_hwpt(hdev, attach->pasid, NULL);
out_free:
	kfree(hdev);
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
					  struct iommufd_device_attach_data *attach,
					  struct iommufd_hwpt_device **out_hdev)
{
	struct iommufd_hw_pagetable_ioas *ioas_hwpt;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	/*
	 * There is no differentiation when domains are allocated, so any domain
	 * that is willing to attach to the device is interchangeable with any
	 * other.
	 */
	mutex_lock(&ioas->mutex);
	list_for_each_entry (ioas_hwpt, &ioas->auto_domains, auto_domains_item) {
		hwpt = container_of(ioas_hwpt, struct iommufd_hw_pagetable, ioas_hwpt);
		if (!refcount_inc_not_zero(&hwpt->obj.users))
			continue;

		/* FIXME: if the group is already attached to a domain make sure
		this returns EMEDIUMTYPE */
		rc = iommufd_device_do_attach(idev, hwpt, attach, out_hdev);
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

	rc = iommufd_device_do_attach(idev, hwpt, attach, out_hdev);
	if (rc)
		goto out_abort;

	list_add_tail(&hwpt->ioas_hwpt.auto_domains_item, &ioas->auto_domains);

	mutex_unlock(&ioas->mutex);
	iommufd_object_finalize(idev->ictx, &hwpt->obj);
	return 0;

out_abort:
	iommufd_object_abort_and_destroy(idev->ictx, &hwpt->obj);
out_unlock:
	mutex_unlock(&ioas->mutex);
	return rc;
}

static int iommufd_device_hw_pagetable_attach(struct iommufd_device *idev,
					      struct iommufd_hw_pagetable *hwpt,
					      struct iommufd_device_attach_data *attach)
{
	int rc;

	switch (hwpt->type) {
	case IOMMUFD_HWPT_IOAS_AUTO:
	case IOMMUFD_HWPT_IOAS_USER:
		rc = iommufd_device_do_attach(idev, hwpt, attach, NULL);
		break;
	case IOMMUFD_HWPT_USER_S1:
		rc = device_attach_ioas_hwpt(idev, hwpt->s1_hwpt.stage2, attach->flags);
		if (rc)
			break;
		rc = iommufd_device_do_attach(idev, hwpt, attach, NULL);
		if (rc)
			device_detach_ioas_hwpt(idev, hwpt->s1_hwpt.stage2, NULL);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

static int __iommufd_device_attach(struct iommufd_device *idev, u32 *pt_id,
				   struct iommufd_device_attach_data *attach)
{
	struct iommufd_object *pt_obj;
	struct iommufd_hwpt_device *hdev;
	int rc;

	pt_obj = iommufd_get_object(idev->ictx, *pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(pt_obj))
		return PTR_ERR(pt_obj);

	mutex_lock(&idev->pasid_lock);
	switch (pt_obj->type) {
	case IOMMUFD_OBJ_HW_PAGETABLE: {
		struct iommufd_hw_pagetable *hwpt =
			container_of(pt_obj, struct iommufd_hw_pagetable, obj);

		rc = iommufd_device_hw_pagetable_attach(idev, hwpt, attach);
		if (rc)
			goto out_unlock;
		break;
	}
	case IOMMUFD_OBJ_IOAS: {
		struct iommufd_ioas *ioas =
			container_of(pt_obj, struct iommufd_ioas, obj);

		rc = iommufd_device_auto_get_domain(idev, ioas, attach, &hdev);
		if (rc)
			goto out_unlock;
		*pt_id = hdev->hwpt->obj.id;
		break;
	}
	default:
		rc = -EINVAL;
		goto out_unlock;
	}

	refcount_inc(&idev->obj.users);
	rc = 0;

out_unlock:
	mutex_unlock(&idev->pasid_lock);
	iommufd_put_object(pt_obj);
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
	struct iommufd_device_attach_data attach = { .flags = flags,
						     .pasid = INVALID_IOASID };

	/*
	 * For the iommufd_device which hasn't claimed ownership, cannot
	 * goto do attachment. Should use the iommufd_device_pasid_attach().
	 */
	if (!idev->dma_owner_claimed)
		return -EPERM;

	return __iommufd_device_attach(idev, pt_id, &attach);
}
EXPORT_SYMBOL_GPL(iommufd_device_attach);

static void iommufd_ioas_hwpt_detach(struct iommufd_hwpt_device *hdev)
{
	struct iommufd_hw_pagetable *hwpt = hdev->hwpt;
	struct iommufd_device *idev = hdev->idev;
	bool destroy_auto_domain = false;

	mutex_lock(&hwpt->ioas_hwpt.ioas->mutex);
	mutex_lock(&hwpt->devices_lock);
	xa_erase(&idev->pasid_xa, hdev->pasid);
	xa_erase(&hdev->hwpt->devices, hdev->hwpt_xa_id);
	iommufd_device_detach_hwpt(hdev, hdev->pasid, &destroy_auto_domain);
	kfree(hdev);
	mutex_unlock(&hwpt->devices_lock);
	mutex_unlock(&hwpt->ioas_hwpt.ioas->mutex);

	if (destroy_auto_domain)
		iommufd_object_destroy_user(idev->ictx, &hwpt->obj);
	else
		refcount_dec(&hwpt->obj.users);

	refcount_dec(&idev->obj.users);
}

static void iommufd_s1_hwpt_detach(struct iommufd_hwpt_device *hdev)
{
	struct iommufd_hw_pagetable *hwpt = hdev->hwpt;
	struct iommufd_device *idev = hdev->idev;

	mutex_lock(&hwpt->devices_lock);
	xa_erase(&idev->pasid_xa, hdev->pasid);
	xa_erase(&hdev->hwpt->devices, hdev->hwpt_xa_id);
	iommufd_device_detach_hwpt(hdev, hdev->pasid, NULL);
	kfree(hdev);
	mutex_unlock(&hwpt->devices_lock);

	device_detach_ioas_hwpt(idev, hwpt->s1_hwpt.stage2, NULL);

	refcount_dec(&hwpt->obj.users);

	refcount_dec(&idev->obj.users);
}

static void
__iommufd_device_pasid_detach(struct iommufd_device *idev, ioasid_t pasid)
{
	struct iommufd_hwpt_device *hdev;
	struct iommufd_hw_pagetable *hwpt;

	mutex_lock(&idev->pasid_lock);
	hdev = xa_load(&idev->pasid_xa, pasid);
	if (IS_ERR(hdev)) {
		mutex_unlock(&idev->pasid_lock);
		return;
	}
	hwpt = hdev->hwpt;
	switch (hwpt->type) {
	case IOMMUFD_HWPT_IOAS_AUTO:
	case IOMMUFD_HWPT_IOAS_USER:
		iommufd_ioas_hwpt_detach(hdev);
		break;
	case IOMMUFD_HWPT_USER_S1:
		iommufd_s1_hwpt_detach(hdev);
		break;
	default:
		break;
	}
	mutex_unlock(&idev->pasid_lock);
}

void iommufd_device_detach(struct iommufd_device *idev)
{
	if (!idev->dma_owner_claimed)
		return;

	__iommufd_device_pasid_detach(idev, INVALID_IOASID);
}
EXPORT_SYMBOL_GPL(iommufd_device_detach);

/**
 * iommufd_device_pasid_attach - Connect a device+pasid to an iommu_domain
 * @idev: device to attach
 * @pasid: pasid to attach
 * @pt_id: Input a IOMMUFD_OBJ_IOAS, or IOMMUFD_OBJ_HW_PAGETABLE
 *         Output the IOMMUFD_OBJ_HW_PAGETABLE ID
 * @flags: Optional flags
 *
 * This connects the device to an iommu_domain, either automatically or manually
 * selected. Once this completes the device could do DMA.
 *
 * The caller should return the resulting pt_id back to userspace.
 * This function is undone by calling iommufd_device_pasid_detach().
 */
int iommufd_device_pasid_attach(struct iommufd_device *idev, u32 *pt_id,
				ioasid_t pasid, unsigned int flags)
{
	struct iommufd_device_attach_data attach = { .flags = flags,
						     .pasid = pasid };

	return __iommufd_device_attach(idev, pt_id, &attach);
}
EXPORT_SYMBOL_GPL(iommufd_device_pasid_attach);

void iommufd_device_pasid_detach(struct iommufd_device *idev, ioasid_t pasid)
{
	__iommufd_device_pasid_detach(idev, pasid);
}
EXPORT_SYMBOL_GPL(iommufd_device_pasid_detach);

#ifdef CONFIG_IOMMUFD_TEST
/*
 * Creating a real iommufd_device is too hard, bypass creating a iommufd_device
 * and go directly to attaching a domain.
 */
struct iommufd_hw_pagetable *
iommufd_device_selftest_attach(struct iommufd_ctx *ictx,
			       struct iommufd_ioas *ioas,
			       struct device *mock_dev)
{
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	hwpt = iommufd_hw_pagetable_alloc(ictx, ioas, mock_dev);
	if (IS_ERR(hwpt))
		return hwpt;

	rc = iopt_table_add_domain(&hwpt->ioas_hwpt.ioas->iopt, hwpt->domain);
	if (rc)
		goto out_hwpt;

	refcount_inc(&hwpt->obj.users);
	iommufd_object_finalize(ictx, &hwpt->obj);
	return hwpt;

out_hwpt:
	iommufd_object_abort_and_destroy(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}

void iommufd_device_selftest_detach(struct iommufd_ctx *ictx,
				    struct iommufd_hw_pagetable *hwpt)
{
	iopt_table_remove_domain(&hwpt->ioas_hwpt.ioas->iopt, hwpt->domain);
	refcount_dec(&hwpt->obj.users);
}
#endif
