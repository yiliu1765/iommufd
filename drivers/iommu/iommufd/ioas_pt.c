// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/interval_tree.h>
#include <linux/iommufd.h>
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>

#include "iommufd_private.h"

void iommufd_ioas_pagetable_destroy(struct iommufd_object *obj)
{
	struct iommufd_ioas_pagetable *ioaspt =
		container_of(obj, struct iommufd_ioas_pagetable, obj);
	int rc;

	rc = iopt_unmap_all(&ioaspt->iopt);
	WARN_ON(rc);
	iopt_destroy_table(&ioaspt->iopt);
}

struct iommufd_ioas_pagetable *
iommufd_ioas_pagetable_alloc(struct iommufd_ctx *ictx)
{
	struct iommufd_ioas_pagetable *ioaspt;
	int rc;

	ioaspt = iommufd_object_alloc(ictx, ioaspt,
					   IOMMUFD_OBJ_IOAS_PAGETABLE);
	if (IS_ERR(ioaspt))
		return ioaspt;

	rc = iopt_init_table(&ioaspt->iopt);
	if (rc)
		goto out_abort;

	INIT_LIST_HEAD(&ioaspt->auto_domains);
	return ioaspt;

out_abort:
	iommufd_object_abort(ictx, &ioaspt->obj);
	return ERR_PTR(rc);
}

int iommufd_ioas_pagetable_alloc_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_pagetable_alloc *cmd = ucmd->cmd;
	struct iommufd_ioas_pagetable *ioaspt;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	ioaspt = iommufd_ioas_pagetable_alloc(ucmd->ictx);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	cmd->out_ioas_id = ioaspt->obj.id;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_table;
	iommufd_object_finalize(ucmd->ictx, &ioaspt->obj);
	return 0;

out_table:
	iommufd_ioas_pagetable_destroy(&ioaspt->obj);
	return rc;
}

int iommufd_ioas_pagetable_iova_ranges(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_pagetable_iova_ranges __user *uptr = ucmd->ubuffer;
	struct iommu_ioas_pagetable_iova_ranges *cmd = ucmd->cmd;
	struct iommufd_ioas_pagetable *ioaspt;
	struct interval_tree_span_iter span;
	u32 max_iovas;
	int rc;

	if (cmd->__reserved)
		return -EOPNOTSUPP;

	max_iovas = cmd->size - sizeof(*cmd);
	if (max_iovas % sizeof(cmd->out_valid_iovas[0]))
		return -EINVAL;
	max_iovas /= sizeof(cmd->out_valid_iovas[0]);

	ioaspt = get_ioas_pagetable(ucmd, cmd->ioas_id);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	down_read(&ioaspt->iopt.rwsem);
	cmd->out_num_iovas = 0;
	for (interval_tree_span_iter_first(
		     &span, &ioaspt->iopt.reserved_iova_itree, 0, ULONG_MAX);
	     !interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		if (!span.is_hole)
			continue;
		if (cmd->out_num_iovas < max_iovas) {
			rc = put_user((u64)span.start_hole,
				      &uptr->out_valid_iovas[cmd->out_num_iovas]
					       .start);
			if (rc)
				goto out_put;
			rc = put_user(
				(u64)span.last_hole,
				&uptr->out_valid_iovas[cmd->out_num_iovas].last);
			if (rc)
				goto out_put;
		}
		cmd->out_num_iovas++;
	}

	if (cmd->out_num_iovas > max_iovas) {
		cmd->size = sizeof(*cmd) + cmd->out_num_iovas * sizeof(cmd->out_valid_iovas[0]);
	}

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_put;
	if (cmd->out_num_iovas > max_iovas)
		rc = -EMSGSIZE;
out_put:
	up_read(&ioaspt->iopt.rwsem);
	iommufd_put_object(&ioaspt->obj);
	return rc;
}

static int conv_iommu_prot(u32 map_flags)
{
	int iommu_prot;

	/*
	 * We provide no manual cache coherencey ioctls to userspace and most
	 * architectures make the CPU ops for cache flushing privileged.
	 * Therefore we require the underlying IOMMU to support CPU coherent
	 * operation.
	 */
	iommu_prot = IOMMU_CACHE;
	if (map_flags & IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE)
		iommu_prot |= IOMMU_WRITE;
	if (map_flags & IOMMU_IOAS_PAGETABLE_MAP_READABLE)
		iommu_prot |= IOMMU_READ;
	return iommu_prot;
}

int iommufd_ioas_pagetable_map(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_pagetable_map *cmd = ucmd->cmd;
	struct iommufd_ioas_pagetable *ioaspt;
	int rc;

	if ((cmd->flags & ~(IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA |
			    IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE |
			    IOMMU_IOAS_PAGETABLE_MAP_READABLE)) ||
	    cmd->__reserved)
		return -EOPNOTSUPP;
	if (cmd->iova >= ULONG_MAX || cmd->length >= ULONG_MAX)
		return -EOVERFLOW;

	ioaspt = get_ioas_pagetable(ucmd, cmd->ioas_id);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	down_write(&ioaspt->iopt.rwsem);
	if (!(cmd->flags & IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA)) {
		unsigned long iova;

		rc = iopt_alloc_iova(&ioaspt->iopt, &iova, cmd->user_va,
				     cmd->length);
		if (rc)
			goto out_unlock;
		cmd->iova = iova;
	}

	rc = iopt_map_user_pages(&ioaspt->iopt, cmd->iova,
				 u64_to_user_ptr(cmd->user_va), cmd->length,
				 conv_iommu_prot(cmd->flags));
	if (rc)
		goto out_unlock;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
out_unlock:
	up_write(&ioaspt->iopt.rwsem);
	iommufd_put_object(&ioaspt->obj);
	return rc;
}

int iommufd_ioas_pagetable_copy(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_pagetable_copy *cmd = ucmd->cmd;
	struct iommufd_ioas_pagetable *src_ioaspt;
	struct iommufd_ioas_pagetable *dst_ioaspt;
	struct iopt_pages *pages;
	int rc;

	if ((cmd->flags & ~(IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA |
			    IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE |
			    IOMMU_IOAS_PAGETABLE_MAP_READABLE)))
		return -EOPNOTSUPP;
	if (cmd->length >= ULONG_MAX)
		return -EOVERFLOW;

	src_ioaspt = get_ioas_pagetable(ucmd, cmd->src_ioas_id);
	if (IS_ERR(src_ioaspt))
		return PTR_ERR(src_ioaspt);
	/* FIXME: copy is not limited to an exact match anymore */
	pages = iopt_get_pages(&src_ioaspt->iopt, cmd->src_iova, cmd->length);
	iommufd_put_object(&src_ioaspt->obj);
	if (IS_ERR(pages))
		return PTR_ERR(pages);

	dst_ioaspt = get_ioas_pagetable(ucmd, cmd->dst_ioas_id);
	if (IS_ERR(dst_ioaspt))
		return PTR_ERR(dst_ioaspt);

	down_write(&dst_ioaspt->iopt.rwsem);
	if (!(cmd->flags & IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA)) {
		unsigned long iova;

		rc = iopt_alloc_iova(&dst_ioaspt->iopt, &iova, cmd->src_iova,
				     cmd->length);
		if (rc)
			goto out_unlock;
		cmd->dst_iova = iova;
	}

	rc = iopt_copy_iova(&dst_ioaspt->iopt, pages, cmd->dst_iova,
			    cmd->length, conv_iommu_prot(cmd->flags));
	if (rc)
		goto out_unlock;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
out_unlock:
	up_write(&dst_ioaspt->iopt.rwsem);
	iommufd_put_object(&dst_ioaspt->obj);
	return rc;
}

int iommufd_ioas_pagetable_unmap(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_pagetable_unmap *cmd = ucmd->cmd;
	struct iommufd_ioas_pagetable *ioaspt;
	int rc;

	ioaspt = get_ioas_pagetable(ucmd, cmd->ioas_id);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	if (cmd->iova == 0 && cmd->length == U64_MAX) {
		rc = iopt_unmap_all(&ioaspt->iopt);
	} else {
		if (cmd->iova >= ULONG_MAX || cmd->length >= ULONG_MAX) {
			rc = -EOVERFLOW;
			goto out_put;
		}
		rc = iopt_unmap_iova(&ioaspt->iopt, cmd->iova, cmd->length);
	}

out_put:
	iommufd_put_object(&ioaspt->obj);
	return rc;
}
