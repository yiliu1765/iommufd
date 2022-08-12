// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/interval_tree.h>
#include <linux/iommufd.h>
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>

#include "io_pagetable.h"

void iommufd_ioas_destroy(struct iommufd_object *obj)
{
	struct iommufd_ioas *ioas = container_of(obj, struct iommufd_ioas, obj);
	int rc;

	rc = iopt_unmap_all(&ioas->iopt, NULL);
	WARN_ON(rc && rc != -ENOENT);
	iopt_destroy_table(&ioas->iopt);
	WARN_ON(!xa_empty(&ioas->access_list));
	mutex_destroy(&ioas->mutex);
}

struct iommufd_ioas *iommufd_ioas_alloc(struct iommufd_ctx *ictx)
{
	struct iommufd_ioas *ioas;
	int rc;

	ioas = iommufd_object_alloc(ictx, ioas, IOMMUFD_OBJ_IOAS);
	if (IS_ERR(ioas))
		return ioas;

	rc = iopt_init_table(&ioas->iopt);
	if (rc)
		goto out_abort;

	INIT_LIST_HEAD(&ioas->hwpt_list);
	mutex_init(&ioas->mutex);
	xa_init_flags(&ioas->access_list, XA_FLAGS_ALLOC);
	return ioas;

out_abort:
	iommufd_object_abort(ictx, &ioas->obj);
	return ERR_PTR(rc);
}

int iommufd_ioas_alloc_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_alloc *cmd = ucmd->cmd;
	struct iommufd_ioas *ioas;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	ioas = iommufd_ioas_alloc(ucmd->ictx);
	if (IS_ERR(ioas))
		return PTR_ERR(ioas);

	cmd->out_ioas_id = ioas->obj.id;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_table;
	iommufd_object_finalize(ucmd->ictx, &ioas->obj);
	return 0;

out_table:
	iommufd_ioas_destroy(&ioas->obj);
	return rc;
}

int iommufd_ioas_iova_ranges(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_iova_ranges __user *uptr = ucmd->ubuffer;
	struct iommu_ioas_iova_ranges *cmd = ucmd->cmd;
	struct iommufd_ioas *ioas;
	struct interval_tree_span_iter span;
	u32 max_iovas;
	int rc;

	if (cmd->__reserved)
		return -EOPNOTSUPP;

	max_iovas = cmd->size - sizeof(*cmd);
	if (max_iovas % sizeof(cmd->out_valid_iovas[0]))
		return -EINVAL;
	max_iovas /= sizeof(cmd->out_valid_iovas[0]);

	ioas = iommufd_get_ioas(ucmd, cmd->ioas_id);
	if (IS_ERR(ioas))
		return PTR_ERR(ioas);

	down_read(&ioas->iopt.iova_rwsem);
	cmd->out_num_iovas = 0;
	interval_tree_for_each_span (&span, &ioas->iopt.reserved_itree,
				     0, ULONG_MAX) {
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
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_put;
	if (cmd->out_num_iovas > max_iovas)
		rc = -EMSGSIZE;
out_put:
	up_read(&ioas->iopt.iova_rwsem);
	iommufd_put_object(&ioas->obj);
	return rc;
}

static int iommufd_ioas_load_iovas(struct rb_root_cached *itree,
				   struct iommu_iova_range __user *ranges,
				   u32 num)
{
	u32 i;

	for (i = 0; i != num; i++) {
		struct iommu_iova_range range;
		struct iopt_allowed *allowed;

		if (copy_from_user(&range, ranges + i, sizeof(range)))
			return -EFAULT;

		if (range.start >= range.last)
			return -EINVAL;

		if (interval_tree_iter_first(itree, range.start, range.last))
			return -EINVAL;

		allowed = kzalloc(sizeof(*allowed), GFP_KERNEL_ACCOUNT);
		if (!allowed)
			return -ENOMEM;
		allowed->node.start = range.start;
		allowed->node.last = range.last;

		interval_tree_insert(&allowed->node, itree);
	}
	return 0;
}

int iommufd_ioas_allow_iovas(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_allow_iovas *cmd = ucmd->cmd;
	struct rb_root_cached allowed_iova = RB_ROOT_CACHED;
	struct interval_tree_node *node;
	struct iommufd_ioas *ioas;
	struct io_pagetable *iopt;
	int rc = 0;

	ioas = iommufd_get_ioas(ucmd, cmd->ioas_id);
	if (IS_ERR(ioas))
		return PTR_ERR(ioas);
	iopt = &ioas->iopt;

	rc = iommufd_ioas_load_iovas(&allowed_iova,
				      u64_to_user_ptr(cmd->allowed_iovas),
				      cmd->num_iovas);
	if (rc)
		goto out_free;

	rc = iopt_set_allow_iova(iopt, &allowed_iova);
out_free:
	while ((node = interval_tree_iter_first(&allowed_iova, 0, ULONG_MAX))) {
		interval_tree_remove(node, &allowed_iova);
		kfree(container_of(node, struct iopt_allowed, node));
	}
	iommufd_put_object(&ioas->obj);
	return rc;
}

static int conv_iommu_prot(u32 map_flags)
{
	int iommu_prot;

	/*
	 * We provide no manual cache coherency ioctls to userspace and most
	 * architectures make the CPU ops for cache flushing privileged.
	 * Therefore we require the underlying IOMMU to support CPU coherent
	 * operation. Support for IOMMU_CACHE is enforced by the
	 * dev_is_dma_coherent() test during bind.
	 */
	iommu_prot = IOMMU_CACHE;
	if (map_flags & IOMMU_IOAS_MAP_WRITEABLE)
		iommu_prot |= IOMMU_WRITE;
	if (map_flags & IOMMU_IOAS_MAP_READABLE)
		iommu_prot |= IOMMU_READ;
	return iommu_prot;
}

int iommufd_ioas_map(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_map *cmd = ucmd->cmd;
	struct iommufd_ioas *ioas;
	unsigned int flags = 0;
	unsigned long iova;
	int rc;

	if ((cmd->flags &
	     ~(IOMMU_IOAS_MAP_FIXED_IOVA | IOMMU_IOAS_MAP_WRITEABLE |
	       IOMMU_IOAS_MAP_READABLE)) ||
	    cmd->__reserved)
		return -EOPNOTSUPP;
	if (cmd->iova >= ULONG_MAX || cmd->length >= ULONG_MAX)
		return -EOVERFLOW;

	ioas = iommufd_get_ioas(ucmd, cmd->ioas_id);
	if (IS_ERR(ioas))
		return PTR_ERR(ioas);

	if (!(cmd->flags & IOMMU_IOAS_MAP_FIXED_IOVA))
		flags = IOPT_ALLOC_IOVA;
	iova = cmd->iova;
	rc = iopt_map_user_pages(&ioas->iopt, &iova,
				 u64_to_user_ptr(cmd->user_va), cmd->length,
				 conv_iommu_prot(cmd->flags), flags);
	if (rc)
		goto out_put;

	cmd->iova = iova;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
out_put:
	iommufd_put_object(&ioas->obj);
	return rc;
}

int iommufd_ioas_copy(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_copy *cmd = ucmd->cmd;
	struct iommufd_ioas *src_ioas;
	struct iommufd_ioas *dst_ioas;
	struct iopt_pages *pages;
	unsigned int flags = 0;
	unsigned long iova;
	unsigned long start_byte;
	int rc;

	if ((cmd->flags &
	     ~(IOMMU_IOAS_MAP_FIXED_IOVA | IOMMU_IOAS_MAP_WRITEABLE |
	       IOMMU_IOAS_MAP_READABLE)))
		return -EOPNOTSUPP;
	if (cmd->length >= ULONG_MAX)
		return -EOVERFLOW;

	src_ioas = iommufd_get_ioas(ucmd, cmd->src_ioas_id);
	if (IS_ERR(src_ioas))
		return PTR_ERR(src_ioas);
	/* FIXME: copy is not limited to an exact match anymore */
	pages = iopt_get_pages(&src_ioas->iopt, cmd->src_iova, &start_byte,
			       cmd->length);
	iommufd_put_object(&src_ioas->obj);
	if (IS_ERR(pages))
		return PTR_ERR(pages);

	dst_ioas = iommufd_get_ioas(ucmd, cmd->dst_ioas_id);
	if (IS_ERR(dst_ioas)) {
		iopt_put_pages(pages);
		return PTR_ERR(dst_ioas);
	}

	if (!(cmd->flags & IOMMU_IOAS_MAP_FIXED_IOVA))
		flags = IOPT_ALLOC_IOVA;
	iova = cmd->dst_iova;
	rc = iopt_map_pages(&dst_ioas->iopt, pages, &iova, start_byte,
			    cmd->length, conv_iommu_prot(cmd->flags), flags);
	if (rc) {
		iopt_put_pages(pages);
		goto out_put_dst;
	}

	cmd->dst_iova = iova;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
out_put_dst:
	iommufd_put_object(&dst_ioas->obj);
	return rc;
}

int iommufd_ioas_unmap(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_unmap *cmd = ucmd->cmd;
	struct iommufd_ioas *ioas;
	unsigned long unmapped = 0;
	int rc;

	ioas = iommufd_get_ioas(ucmd, cmd->ioas_id);
	if (IS_ERR(ioas))
		return PTR_ERR(ioas);

	if (cmd->iova == 0 && cmd->length == U64_MAX) {
		rc = iopt_unmap_all(&ioas->iopt, &unmapped);
		if (rc)
			goto out_put;
	} else {
		if (cmd->iova >= ULONG_MAX || cmd->length >= ULONG_MAX) {
			rc = -EOVERFLOW;
			goto out_put;
		}
		rc = iopt_unmap_iova(&ioas->iopt, cmd->iova, cmd->length,
				     &unmapped);
		if (rc)
			goto out_put;
	}

	cmd->length = unmapped;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));

out_put:
	iommufd_put_object(&ioas->obj);
	return rc;
}

bool iommufd_ioas_enforced_coherent(struct iommufd_ioas *ioas)
{
	struct iommufd_hw_pagetable *hwpt;
	bool ret = true;

	mutex_lock(&ioas->mutex);
	list_for_each_entry(hwpt, &ioas->hwpt_list, hwpt_item) {
		if (!hwpt->enforce_cache_coherency) {
			ret = false;
			break;
		}
	}
	mutex_unlock(&ioas->mutex);
	return ret;
}
