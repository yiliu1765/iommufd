// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommu.h>

#include "iommufd_private.h"

void iommufd_hw_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);
	struct iommufd_ioas_pagetable *ioaspt = hwpt->ioaspt;

	down_write(&ioaspt->iopt.rwsem);
	list_del(&hwpt->auto_domains_item);
	iopt_table_remove_domain(&hwpt->ioaspt->iopt, hwpt->domain);
	up_write(&ioaspt->iopt.rwsem);

	iommu_domain_free(hwpt->domain);
	refcount_dec(&hwpt->ioaspt->obj.users);
	mutex_destroy(&hwpt->devices_lock);
}

/*
 * When automatically managing the domains we search for a compatible domain in
 * the iopt and if one is found use it, otherwise create a new domain.
 * Automatic domain selection will never pick a manually created domain.
 */
static struct iommufd_hw_pagetable *
iommufd_hw_pagetable_auto_get(struct iommufd_ctx *ictx,
			      struct iommufd_ioas_pagetable *ioaspt,
			      struct device *dev)
{
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	/*
	 * There is no differentiation when domains are allocated, so any domain
	 * from the right ops is interchangable with any other.
	 */
	down_write(&ioaspt->iopt.rwsem);
	list_for_each_entry (hwpt, &ioaspt->auto_domains, auto_domains_item) {
		if (hwpt->domain->ops == dev->bus->iommu_ops) {
			if (refcount_inc_not_zero(&hwpt->obj.users))
				goto out_unlock;
		}
	}

	hwpt = iommufd_object_alloc(ictx, hwpt, IOMMUFD_OBJ_HW_PAGETABLE);
	if (IS_ERR(hwpt))
		goto out_unlock;

	hwpt->domain = iommu_domain_alloc(dev->bus);
	if (!hwpt->domain) {
		hwpt = ERR_PTR(-ENOMEM);
		goto out_unlock;
	}
	rc = iopt_table_add_domain(&ioaspt->iopt, hwpt->domain);
	if (rc) {
		hwpt = ERR_PTR(rc);
		goto out_domain;
	}

	INIT_LIST_HEAD(&hwpt->devices);
	mutex_init(&hwpt->devices_lock);
	hwpt->ioaspt = ioaspt;
	/* The calling driver is a user until iommufd_hw_pagetable_put() */
	refcount_inc(&ioaspt->obj.users);

	list_add_tail(&hwpt->auto_domains_item, &ioaspt->auto_domains);
	iommufd_object_finalize(ictx, &hwpt->obj);
	goto out_unlock;

out_domain:
	iommu_domain_free(hwpt->domain);
out_unlock:
	up_write(&ioaspt->iopt.rwsem);
	return hwpt;
}

/*
 * Turn a general page table ID into a iommufd_hw_pagetable. This autocreates
 * and manages domains if a IOAS is specified, otherwise it uses exactly the
 * hw_pagetable userspace choose.
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
	case IOMMUFD_OBJ_HW_PAGETABLE:
		iommufd_put_object_keep_user(obj);
		return container_of(obj, struct iommufd_hw_pagetable, obj);
	case IOMMUFD_OBJ_IOAS_PAGETABLE: {
		struct iommufd_ioas_pagetable *ioaspt =
			container_of(obj, struct iommufd_ioas_pagetable, obj);
		struct iommufd_hw_pagetable *hwpt;

		hwpt = iommufd_hw_pagetable_auto_get(ictx, ioaspt, dev);
		iommufd_put_object_keep_user(obj);
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
	if (list_empty(&hwpt->auto_domains_item)) {
		/* Manually created hw_pagetables just keep going */
		refcount_dec(&hwpt->obj.users);
		return;
	}
	iommufd_object_destroy_user(ictx, &hwpt->obj);
}
