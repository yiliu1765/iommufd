/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_IOMMU_PRIV_H
#define __LINUX_IOMMU_PRIV_H

#include <linux/iommu.h>

static inline const struct iommu_ops *dev_iommu_ops(struct device *dev)
{
	/*
	 * Assume that valid ops must be installed if iommu_probe_device()
	 * has succeeded. The device ops are essentially for internal use
	 * within the IOMMU subsystem itself, so we should be able to trust
	 * ourselves not to misuse the helper.
	 */
	return dev->iommu->iommu_dev->ops;
}

static inline struct iommu_domain *iommu_get_unmanaged_domain(struct device *dev)
{
	const struct iommu_ops *ops;

	if (!dev->iommu || !dev->iommu->iommu_dev)
		goto attached_domain;

	ops = dev_iommu_ops(dev);
	if (ops->get_unmanaged_domain)
		return ops->get_unmanaged_domain(dev);

attached_domain:
	return iommu_get_domain_for_dev(dev);
}

int iommu_group_replace_domain(struct iommu_group *group,
			       struct iommu_domain *new_domain);

#endif /* __LINUX_IOMMU_PRIV_H */
