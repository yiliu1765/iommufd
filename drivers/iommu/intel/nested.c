// SPDX-License-Identifier: GPL-2.0
/*
 * nested.c - nested mode translation support
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Author: Lu Baolu <baolu.lu@linux.intel.com>
 *         Jacob Pan <jacob.jun.pan@linux.intel.com>
 *         Yi Liu <yi.l.liu@intel.com>
 */

#define pr_fmt(fmt)	"DMAR: " fmt

#include <linux/iommu.h>
#include <linux/pci.h>
#include <linux/pci-ats.h>

#include "iommu.h"
#include "pasid.h"

static int intel_nested_attach_dev(struct iommu_domain *domain,
				   struct device *dev)
{
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	struct dmar_domain *dmar_domain = to_dmar_domain(domain);
	struct intel_iommu *iommu = info->iommu;
	unsigned long flags;
	int ret = 0;

	if (info->domain)
		device_block_translation(dev);

	if (iommu->agaw < dmar_domain->s2_domain->agaw) {
		dev_err_ratelimited(dev, "Adjusted guest address width not compatible\n");
		return -ENODEV;
	}

	/*
	 * Stage-1 domain cannot work alone, it is nested on a s2_domain.
	 * The s2_domain will be used in nested translation, hence needs
	 * to ensure the s2_domain is compatible with this IOMMU.
	 */
	ret = prepare_domain_attach_device(&dmar_domain->s2_domain->domain, dev);
	if (ret) {
		dev_err_ratelimited(dev, "s2 domain is not compatible\n");
		return ret;
	}

	ret = domain_attach_iommu(dmar_domain, iommu);
	if (ret) {
		dev_err_ratelimited(dev, "Failed to attach domain to iommu\n");
		return ret;
	}

	ret = intel_pasid_setup_nested(iommu, dev,
				       IOMMU_NO_PASID, dmar_domain);
	if (ret) {
		domain_detach_iommu(dmar_domain, iommu);
		dev_err_ratelimited(dev, "Failed to setup pasid entry\n");
		return ret;
	}

	info->domain = dmar_domain;
	spin_lock_irqsave(&dmar_domain->lock, flags);
	list_add(&info->link, &dmar_domain->devices);
	spin_unlock_irqrestore(&dmar_domain->lock, flags);

	return 0;
}

static void intel_nested_domain_free(struct iommu_domain *domain)
{
	kfree(to_dmar_domain(domain));
}

static void nested_flush_pasid_iotlb(struct intel_iommu *iommu,
				     struct dmar_domain *domain, u64 addr,
				     unsigned long npages, bool ih,
				     u32 *error_code)
{
	u16 did = domain_id_iommu(domain, iommu);
	unsigned long flags;

	spin_lock_irqsave(&domain->lock, flags);
	if (!list_empty(&domain->devices))
		qi_flush_piotlb(iommu, did, IOMMU_NO_PASID, addr,
				npages, ih, error_code);
	spin_unlock_irqrestore(&domain->lock, flags);
}

static void nested_flush_dev_iotlb(struct dmar_domain *domain, u64 addr,
				  unsigned mask, u32 *error_code)
{
	struct device_domain_info *info;
	unsigned long flags;
	u16 sid, qdep;

	spin_lock_irqsave(&domain->lock, flags);
	list_for_each_entry(info, &domain->devices, link) {
		if (!info->ats_enabled)
			continue;
		sid = info->bus << 8 | info->devfn;
		qdep = info->ats_qdep;
		qi_flush_dev_iotlb(info->iommu, sid, info->pfsid,
				   qdep, addr, mask, error_code);
		quirk_extra_dev_tlb_flush(info, addr, mask, IOMMU_NO_PASID, qdep);
	}
	spin_unlock_irqrestore(&domain->lock, flags);
}

static void intel_nested_flush_iotlb_all(struct iommu_domain *domain,
					 u32 *error_code)
{
	struct dmar_domain *dmar_domain = to_dmar_domain(domain);
	struct iommu_domain_info *info;
	unsigned long idx;

	xa_for_each(&dmar_domain->iommu_array, idx, info) {
		nested_flush_pasid_iotlb(info->iommu, dmar_domain, 0, -1, 0, error_code);

		if (!dmar_domain->has_iotlb_device)
			continue;

		nested_flush_dev_iotlb(dmar_domain, 0, 64 - VTD_PAGE_SHIFT, error_code);
	}
}

static void domain_flush_iotlb_psi(struct dmar_domain *domain, u64 addr,
				   unsigned long npages, u32 *error_code)
{
	struct iommu_domain_info *info;
	unsigned long i;

	xa_for_each(&domain->iommu_array, i, info) {
		nested_flush_pasid_iotlb(info->iommu, domain,
					 addr >> VTD_PAGE_SHIFT, npages,
					 0, error_code);

		if (domain->has_iotlb_device)
			continue;

		nested_flush_dev_iotlb(domain, addr,
				       ilog2(__roundup_pow_of_two(npages)),
				       error_code);
	}
}

static int intel_nested_cache_invalidate_user(struct iommu_domain *domain,
					      struct iommu_user_data_array *array)
{
	struct dmar_domain *dmar_domain = to_dmar_domain(domain);
	union iommu_hwpt_vtd_s1_invalidate_error_data err_data = {};
	struct iommu_hwpt_vtd_s1_invalidate inv_info;
	void __user *entry_uptr, *err_uptr;
	u32 error_code = 0, handled = 0;
	unsigned long klen = 0;
	u32 index;
	int ret;

	for (index = 0; index < array->entry_num; index++) {
		ret = iommu_copy_struct_from_user_array(&inv_info, array,
							IOMMU_HWPT_DATA_VTD_S1,
							index, err_data_uptr,
							&entry_uptr);
		if (ret)
			break;

		if (inv_info.__reserved || (inv_info.flags & ~IOMMU_VTD_INV_FLAGS_LEAF)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (!IS_ALIGNED(inv_info.addr, VTD_PAGE_SIZE)) {
			ret = -EINVAL;
			break;
		}

		if (inv_info.addr == 0 && inv_info.npages == U64_MAX)
			intel_nested_flush_iotlb_all(domain, &error_code);
		else
			domain_flush_iotlb_psi(dmar_domain, inv_info.addr,
					       inv_info.npages, &error_code);
	}

	array->entry_num = index;

	return ret;
}

static const struct iommu_domain_ops intel_nested_domain_ops = {
	.attach_dev		= intel_nested_attach_dev,
	.free			= intel_nested_domain_free,
	.cache_invalidate_user	= intel_nested_cache_invalidate_user,
};

struct iommu_domain *intel_nested_domain_alloc(struct iommu_domain *parent,
					       const struct iommu_user_data *user_data)
{
	struct dmar_domain *s2_domain = to_dmar_domain(parent);
	struct iommu_hwpt_vtd_s1 vtd;
	struct dmar_domain *domain;
	int ret;

	/* Must be nested domain */
	if (user_data->type != IOMMU_HWPT_DATA_VTD_S1)
		return ERR_PTR(-EOPNOTSUPP);
	if (parent->ops != intel_iommu_ops.default_domain_ops ||
	    !s2_domain->nested_parent)
		return ERR_PTR(-EINVAL);

	ret = iommu_copy_struct_from_user(&vtd, user_data,
					  IOMMU_HWPT_DATA_VTD_S1, __reserved);
	if (ret)
		return ERR_PTR(ret);

	domain = kzalloc(sizeof(*domain), GFP_KERNEL_ACCOUNT);
	if (!domain)
		return ERR_PTR(-ENOMEM);

	domain->use_first_level = true;
	domain->s2_domain = s2_domain;
	domain->s1_pgtbl = vtd.pgtbl_addr;
	domain->s1_cfg = vtd;
	domain->domain.ops = &intel_nested_domain_ops;
	domain->domain.type = IOMMU_DOMAIN_NESTED;
	INIT_LIST_HEAD(&domain->devices);
	INIT_LIST_HEAD(&domain->dev_pasids);
	spin_lock_init(&domain->lock);
	xa_init(&domain->iommu_array);

	return &domain->domain;
}
