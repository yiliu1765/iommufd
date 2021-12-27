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

int iommufd_ioas_pagetable_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommu_ioas_pagetable_alloc *cmd = ucmd->cmd;
	struct iommufd_ioas_pagetable *ioaspt;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	ioaspt = iommufd_object_alloc_ucmd(ucmd, ioaspt,
					   IOMMUFD_OBJ_IOAS_PAGETABLE);
	if (IS_ERR(ioaspt))
		return PTR_ERR(ioaspt);

	rc = iopt_init_table(&ioaspt->iopt);
	if (rc)
		return rc;

	INIT_LIST_HEAD(&ioaspt->auto_domains);
	cmd->out_ioas_id = ioaspt->obj.id;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_table;
	return 0;

out_table:
	iopt_destroy_table(&ioaspt->iopt);
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
	 * architectures make the CPU ops for cache flushign privileged.
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

/* FIXME: VFIO_DMA_MAP_FLAG_VADDR
 * https://lore.kernel.org/kvm/1611939252-7240-1-git-send-email-steven.sistare@oracle.com/
 * Wow, what a wild feature. This should be implemetned by allowing a iopt_pages
 * to be associated with a memfd. It can then source mapping requests directly
 * from a memfd without going through a mm_struct and thus doesn't care that the
 * original qemu exec'd itself. The idea that userspace can flip a flag and
 * cause kernerl users to block indefinately is unacceptable.
 *
 * For VFIO compat we implement this in a slightly different way, creating a
 * access_user that spans the whole area will immediately stop  new faults as
 * they will be handled from the xarray. We can then reparent the iopt_pages to
 * the new mm_struct and undo the access_user. No blockage of kernel users
 * required, does require filling the xarray with pages though.
 */

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

/* FIXME: VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP I think everything with dirty
  * tracking should be in its own ioctl, not muddled in unmap. If we want to
  * atomically unmap and get the dirty bitmap it should be a flag in the dirty
  * tracking ioctl, not here in unmap. Overall dirty tracking needs a careful
  * review along side HW drivers implementing it.
  */
