/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Intel Corporation
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __LINUX_IOMMUFD_H
#define __LINUX_IOMMUFD_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/device.h>

struct page;
struct iommufd_device;
struct iommufd_ctx;
struct io_pagetable;
struct file;

struct iommufd_device *iommufd_device_bind(struct iommufd_ctx *ictx,
					   struct device *dev, u32 *id);
void iommufd_device_unbind(struct iommufd_device *idev);
bool iommufd_device_enforced_coherent(struct iommufd_device *idev);

enum {
	IOMMUFD_ATTACH_FLAGS_ALLOW_UNSAFE_INTERRUPT = 1 << 0,
};
int iommufd_device_attach(struct iommufd_device *idev, u32 *pt_id,
			  unsigned int flags);
void iommufd_device_detach(struct iommufd_device *idev);

int iopt_access_pages(struct io_pagetable *iopt, unsigned long iova,
		      unsigned long length, struct page **out_pages,
		      bool write);
void iopt_unaccess_pages(struct io_pagetable *iopt, unsigned long iova,
			 unsigned long length);

void iommufd_ctx_get(struct iommufd_ctx *ictx);

#if IS_ENABLED(CONFIG_IOMMUFD)
struct iommufd_ctx *iommufd_ctx_from_file(struct file *file);
void iommufd_ctx_put(struct iommufd_ctx *ictx);
#else /* !CONFIG_IOMMUFD */
static inline struct iommufd_ctx *iommufd_ctx_from_file(struct file *file)
{
       return ERR_PTR(-EOPNOTSUPP);
}

static inline void iommufd_ctx_put(struct iommufd_ctx *ictx)
{
}
#endif /* CONFIG_IOMMUFD */
#endif
