// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>

#include "../iommu-priv.h"
#include "iommufd_private.h"

void iommufd_hwpt_paging_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);
	struct iommufd_hwpt_paging *hwpt_paging = to_hwpt_paging(hwpt);

	if (!list_empty(&hwpt_paging->hwpt_item)) {
		mutex_lock(&hwpt_paging->ioas->mutex);
		list_del(&hwpt_paging->hwpt_item);
		mutex_unlock(&hwpt_paging->ioas->mutex);

		iopt_table_remove_domain(&hwpt_paging->ioas->iopt, hwpt->domain);
	}

	if (hwpt->domain)
		iommu_domain_free(hwpt->domain);

	refcount_dec(&hwpt_paging->ioas->obj.users);
}

void iommufd_hwpt_paging_abort(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);
	struct iommufd_hwpt_paging *hwpt_paging = to_hwpt_paging(hwpt);

	/* The ioas->mutex must be held until finalize is called. */
	lockdep_assert_held(&hwpt_paging->ioas->mutex);

	if (!list_empty(&hwpt_paging->hwpt_item)) {
		list_del_init(&hwpt_paging->hwpt_item);
		iopt_table_remove_domain(&hwpt_paging->ioas->iopt, hwpt->domain);
	}
	iommufd_hwpt_paging_destroy(obj);
}

void iommufd_hwpt_nested_destroy(struct iommufd_object *obj)
{
	struct iommufd_hw_pagetable *hwpt =
		container_of(obj, struct iommufd_hw_pagetable, obj);
	struct iommufd_hwpt_nested *hwpt_nested = to_hwpt_nested(hwpt);

	if (hwpt->domain)
		iommu_domain_free(hwpt->domain);

	refcount_dec(&hwpt_nested->parent->common.obj.users);
}

void iommufd_hwpt_nested_abort(struct iommufd_object *obj)
{
	iommufd_hwpt_nested_destroy(obj);
}

static int
iommufd_hw_pagetable_enforce_cc(struct iommufd_hwpt_paging *hwpt_paging)
{
	struct iommu_domain *paging_domain = hwpt_paging->common.domain;

	if (hwpt_paging->enforce_cache_coherency)
		return 0;

	if (paging_domain->ops->enforce_cache_coherency)
		hwpt_paging->enforce_cache_coherency =
			paging_domain->ops->enforce_cache_coherency(
				paging_domain);
	if (!hwpt_paging->enforce_cache_coherency)
		return -EINVAL;
	return 0;
}

/**
 * iommufd_hw_pagetable_alloc_paging() - Get a PAGING iommu_domain for a device
 * @ictx: iommufd context
 * @ioas: IOAS to associate the domain with
 * @idev: Device to get an iommu_domain for
 * @flags: Flags from userspace
 * @immediate_attach: True if idev should be attached to the hwpt
 *
 * Allocate a new iommu_domain and return it as a hw_pagetable. The HWPT
 * will be linked to the given ioas and upon return the underlying iommu_domain
 * is fully popoulated.
 *
 * The caller must hold the ioas->mutex until after
 * iommufd_object_abort_and_destroy() or iommufd_object_finalize() is called on
 * the returned hwpt.
 */
struct iommufd_hw_pagetable *
iommufd_hw_pagetable_alloc_paging(struct iommufd_ctx *ictx,
				  struct iommufd_ioas *ioas,
				  struct iommufd_device *idev,
				  u32 flags, bool immediate_attach)
{
	const struct iommu_ops *ops = dev_iommu_ops(idev->dev);
	struct iommufd_hwpt_paging *hwpt_paging;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	lockdep_assert_held(&ioas->mutex);

	if (flags && !ops->domain_alloc_user)
		return ERR_PTR(-EOPNOTSUPP);

	hwpt = container_of(_iommufd_object_alloc(ictx, sizeof(*hwpt_paging),
						  IOMMUFD_OBJ_HWPT_PAGING),
			    typeof(*hwpt), obj);
	if (IS_ERR(hwpt))
		return hwpt;
	hwpt_paging = to_hwpt_paging(hwpt);

	INIT_LIST_HEAD(&hwpt_paging->hwpt_item);
	/* Pairs with iommufd_hw_pagetable_destroy() */
	refcount_inc(&ioas->obj.users);
	hwpt_paging->ioas = ioas;
	hwpt_paging->nest_parent = flags & IOMMU_HWPT_ALLOC_NEST_PARENT;

	if (ops->domain_alloc_user) {
		hwpt->domain = ops->domain_alloc_user(idev->dev, flags,
						      NULL, NULL);
		if (IS_ERR(hwpt->domain)) {
			rc = PTR_ERR(hwpt->domain);
			hwpt->domain = NULL;
			goto out_abort;
		}
	} else {
		hwpt->domain = iommu_domain_alloc(idev->dev->bus);
		if (!hwpt->domain) {
			rc = -ENOMEM;
			goto out_abort;
		}
	}

	/*
	 * Set the coherency mode before we do iopt_table_add_domain() as some
	 * iommus have a per-PTE bit that controls it and need to decide before
	 * doing any maps. It is an iommu driver bug to report
	 * IOMMU_CAP_ENFORCE_CACHE_COHERENCY but fail enforce_cache_coherency on
	 * a new domain.
	 */
	if (idev->enforce_cache_coherency) {
		rc = iommufd_hw_pagetable_enforce_cc(hwpt_paging);
		if (WARN_ON(rc))
			goto out_abort;
	}

	/*
	 * immediate_attach exists only to accommodate iommu drivers that cannot
	 * directly allocate a domain. These drivers do not finish creating the
	 * domain until attach is completed. Thus we must have this call
	 * sequence. Once those drivers are fixed this should be removed.
	 */
	if (immediate_attach) {
		rc = iommufd_hw_pagetable_attach(hwpt, idev);
		if (rc)
			goto out_abort;
	}

	rc = iopt_table_add_domain(&ioas->iopt, hwpt->domain);
	if (rc)
		goto out_detach;
	list_add_tail(&hwpt_paging->hwpt_item, &ioas->hwpt_list);
	return hwpt;

out_detach:
	if (immediate_attach)
		iommufd_hw_pagetable_detach(idev);
out_abort:
	iommufd_object_abort_and_destroy(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}

/**
 * iommufd_hw_pagetable_alloc_nested() - Get a NESTED iommu_domain for a device
 * @ictx: iommufd context
 * @parent: Parent PAGING-type hwpt to associate the domain with
 * @idev: Device to get an iommu_domain for
 * @user_data: user_data pointer. Must be valid
 *
 * Allocate a new iommu_domain (must be IOMMU_DOMAIN_NESTED) and return it as
 * a NESTED hw_pagetable. The given parent PAGING-type hwpt must be capable of
 * being a parent.
 */
static struct iommufd_hw_pagetable *
iommufd_hw_pagetable_alloc_nested(struct iommufd_ctx *ictx,
				  struct iommufd_hwpt_paging *parent,
				  struct iommufd_device *idev,
				  const struct iommu_user_data *user_data)
{
	const struct iommu_ops *ops = dev_iommu_ops(idev->dev);
	struct iommufd_hwpt_nested *hwpt_nested;
	struct iommufd_hw_pagetable *hwpt;
	int rc;

	if (!user_data)
		return ERR_PTR(-EINVAL);
	if (user_data->type == IOMMU_HWPT_DATA_NONE)
		return ERR_PTR(-EINVAL);
	if (parent->auto_domain)
		return ERR_PTR(-EINVAL);
	if (!parent->nest_parent)
		return ERR_PTR(-EINVAL);

	if (!ops->domain_alloc_user)
		return ERR_PTR(-EOPNOTSUPP);

	hwpt = container_of(_iommufd_object_alloc(ictx, sizeof(*hwpt_nested),
						  IOMMUFD_OBJ_HWPT_NESTED),
			    typeof(*hwpt), obj);
	if (IS_ERR(hwpt))
		return hwpt;

	refcount_inc(&parent->common.obj.users);
	hwpt_nested = to_hwpt_nested(hwpt);
	hwpt_nested->parent = parent;

	hwpt->domain = ops->domain_alloc_user(idev->dev, 0,
					      parent->common.domain,
					      user_data);
	if (IS_ERR(hwpt->domain)) {
		rc = PTR_ERR(hwpt->domain);
		hwpt->domain = NULL;
		goto out_abort;
	}

	if (WARN_ON_ONCE(hwpt->domain->type != IOMMU_DOMAIN_NESTED)) {
		rc = -EINVAL;
		goto out_abort;
	}
	return hwpt;

out_abort:
	iommufd_object_abort_and_destroy(ictx, &hwpt->obj);
	return ERR_PTR(rc);
}


int iommufd_hwpt_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_alloc *cmd = ucmd->cmd;
	const struct iommu_user_data user_data = {
		.type = cmd->data_type,
		.uptr = u64_to_user_ptr(cmd->data_uptr),
		.len = cmd->data_len,
	};
	struct iommufd_hwpt_paging *parent;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_ioas *ioas = NULL;
	struct iommufd_object *pt_obj;
	struct iommufd_device *idev;
	int rc;

	if ((cmd->flags & (~IOMMU_HWPT_ALLOC_NEST_PARENT)) || cmd->__reserved)
		return -EOPNOTSUPP;
	if (!cmd->data_len && cmd->data_type != IOMMU_HWPT_DATA_NONE)
		return -EINVAL;
	if (cmd->flags & IOMMU_HWPT_ALLOC_NEST_PARENT &&
	    cmd->data_type != IOMMU_HWPT_DATA_NONE)
		return -EINVAL;

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);

	pt_obj = iommufd_get_object(ucmd->ictx, cmd->pt_id, IOMMUFD_OBJ_ANY);
	if (IS_ERR(pt_obj)) {
		rc = -EINVAL;
		goto out_put_idev;
	}

	switch (pt_obj->type) {
	case IOMMUFD_OBJ_IOAS:
		ioas = container_of(pt_obj, struct iommufd_ioas, obj);
		mutex_lock(&ioas->mutex);
		hwpt = iommufd_hw_pagetable_alloc_paging(ucmd->ictx, ioas, idev,
							 cmd->flags, false);
		break;
	case IOMMUFD_OBJ_HWPT_PAGING:
		parent = to_hwpt_paging(
				container_of(pt_obj, typeof(*hwpt), obj));
		hwpt = iommufd_hw_pagetable_alloc_nested(ucmd->ictx, parent,
							 idev, user_data.len ?
							 &user_data : NULL);
		break;
	default:
		rc = -EINVAL;
		goto out_put_pt;
	}

	if (IS_ERR(hwpt)) {
		rc = PTR_ERR(hwpt);
		goto out_unlock;
	}

	cmd->out_hwpt_id = hwpt->obj.id;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_hwpt;
	iommufd_object_finalize(ucmd->ictx, &hwpt->obj);
	goto out_unlock;

out_hwpt:
	iommufd_object_abort_and_destroy(ucmd->ictx, &hwpt->obj);
out_unlock:
	if (ioas)
		mutex_unlock(&ioas->mutex);
out_put_pt:
	iommufd_put_object(pt_obj);
out_put_idev:
	iommufd_put_object(&idev->obj);
	return rc;
}
