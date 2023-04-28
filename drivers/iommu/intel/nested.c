// SPDX-License-Identifier: GPL-2.0
/*
 * nested.c - nested mode translation support
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Author: Lu Baolu <baolu.lu@linux.intel.com>
 *         Jacob Pan <jacob.jun.pan@linux.intel.com>
 */

#define pr_fmt(fmt)	"DMAR: " fmt

#include <linux/iommu.h>

#include "iommu.h"

static void intel_nested_domain_free(struct iommu_domain *domain)
{
	kfree(to_dmar_domain(domain));
}

static void intel_nested_invalidate(struct device *dev,
				    struct dmar_domain *domain,
				    void *user_data)
{
	struct iommu_hwpt_invalidate_intel_vtd *inv_info = user_data;
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	struct intel_iommu *iommu = info->iommu;

	if (WARN_ON(!user_data))
		return;

	switch (inv_info->granularity) {
	case IOMMU_VTD_QI_GRAN_ADDR:
		if (inv_info->granule_size != VTD_PAGE_SIZE ||
		    !IS_ALIGNED(inv_info->addr, VTD_PAGE_SIZE)) {
			dev_err_ratelimited(dev, "Invalid invalidation address 0x%llx\n",
					    inv_info->addr);
			return;
		}

		iommu_flush_iotlb_psi(iommu, domain,
				      inv_info->addr >> VTD_PAGE_SHIFT,
				      inv_info->nb_granules, 1, 0);
		break;
	case IOMMU_VTD_QI_GRAN_DOMAIN:
		intel_flush_iotlb_all(&domain->domain);
		break;
	default:
		dev_err_ratelimited(dev, "Unsupported IOMMU invalidation type %d\n",
				    inv_info->granularity);
		break;
	}
}

static int intel_nested_cache_invalidate_user(struct iommu_domain *domain,
					      void *user_data)
{
	struct dmar_domain *dmar_domain = to_dmar_domain(domain);
	struct device_domain_info *info;
	unsigned long flags;

	spin_lock_irqsave(&dmar_domain->lock, flags);
	list_for_each_entry(info, &dmar_domain->devices, link)
		intel_nested_invalidate(info->dev, dmar_domain,
					user_data);
	spin_unlock_irqrestore(&dmar_domain->lock, flags);
	return 0;
}

static const struct iommu_domain_ops intel_nested_domain_ops = {
	.cache_invalidate_user	= intel_nested_cache_invalidate_user,
	.cache_invalidate_user_data_len =
		sizeof(struct iommu_hwpt_invalidate_intel_vtd),
	.free			= intel_nested_domain_free,
};

struct iommu_domain *intel_nested_domain_alloc(struct iommu_domain *s2_domain,
					       const void *user_data)
{
	const struct iommu_hwpt_intel_vtd *vtd = user_data;
	struct dmar_domain *domain;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL_ACCOUNT);
	if (!domain)
		return NULL;

	domain->use_first_level = true;
	domain->s2_domain = to_dmar_domain(s2_domain);
	domain->s1_pgtbl = vtd->pgtbl_addr;
	domain->s1_cfg = *vtd;
	domain->domain.ops = &intel_nested_domain_ops;
	domain->domain.type = IOMMU_DOMAIN_NESTED;
	INIT_LIST_HEAD(&domain->devices);
	spin_lock_init(&domain->lock);
	xa_init(&domain->iommu_array);

	return &domain->domain;
}
