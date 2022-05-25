// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) Intel Corporation.
 */
#include <linux/iommufd.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/file.h>
#include <linux/pci.h>
#include <linux/irqdomain.h>
#include <linux/dma-iommu.h>

#include "iommufd_private.h"

#define IOASID_BITS 20

int iommufd_alloc_pasid(struct iommufd_ucmd *ucmd)
{
	struct iommu_alloc_pasid *cmd = ucmd->cmd;
	ioasid_t pasid;
	int rc;

	if (cmd->flags & ~IOMMU_ALLOC_PASID_IDENTICAL)
		return -EOPNOTSUPP;

	if (cmd->range.min > cmd->range.max ||
	    cmd->range.min >= (1 << IOASID_BITS) ||
	    cmd->range.max >= (1 << IOASID_BITS))
		return -EINVAL;

	pasid = ioasid_alloc(ucmd->ictx->pasid_set,
			     cmd->range.min, cmd->range.max,
			     NULL, cmd->pasid);

	if (!pasid_valid(pasid))
		return -ENODEV;

	if (cmd->flags & IOMMU_ALLOC_PASID_IDENTICAL)
		ioasid_attach_spid(pasid, pasid);

	cmd->pasid = pasid;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_free_pasid;

	return 0;
out_free_pasid:
	ioasid_put(ucmd->ictx->pasid_set, pasid);
	return rc;
}

int iommufd_free_pasid(struct iommufd_ucmd *ucmd)
{
	struct iommu_free_pasid *cmd = ucmd->cmd;

	if (cmd->flags)
		return -EOPNOTSUPP;

	if (!pasid_valid(cmd->pasid))
		return -EINVAL;

	ioasid_put(ucmd->ictx->pasid_set, cmd->pasid);

	return 0;
}
