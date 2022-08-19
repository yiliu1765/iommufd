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
struct iommufd_access;
struct iommufd_ctx;
struct io_pagetable;
struct file;

struct iommufd_access {
	struct io_pagetable *iopt;
};

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

struct iommufd_access_ops {
	void (*unmap)(void *data, unsigned long iova, unsigned long length);
};

struct iommufd_access *
iommufd_access_create(struct iommufd_ctx *ictx, u32 ioas_id,
		      const struct iommufd_access_ops *ops, void *data);
void iommufd_access_destroy(struct iommufd_access *access);
int iopt_access_pages(struct io_pagetable *iopt, unsigned long iova,
		      unsigned long length, struct page **out_pages,
		      bool write);
void iopt_unaccess_pages(struct io_pagetable *iopt, unsigned long iova,
			 unsigned long length);

static inline int iommufd_access_pin_pages(struct iommufd_access *access,
					   unsigned long iova,
					   unsigned long length,
					   struct page **out_pages, bool write)
{
	if (!IS_ENABLED(CONFIG_IOMMUFD))
		return -EOPNOTSUPP;
	return iopt_access_pages(access->iopt, iova, length, out_pages, write);
}

static inline void iommufd_access_unpin_pages(struct iommufd_access *access,
					      unsigned long iova,
					      unsigned long length)
{
	if (IS_ENABLED(CONFIG_IOMMUFD))
		iopt_unaccess_pages(access->iopt, iova, length);
}

void iommufd_ctx_get(struct iommufd_ctx *ictx);

#if IS_ENABLED(CONFIG_IOMMUFD)
struct iommufd_ctx *iommufd_ctx_from_file(struct file *file);
void iommufd_ctx_put(struct iommufd_ctx *ictx);

int iommufd_vfio_compat_ioas_id(struct iommufd_ctx *ictx, u32 *out_ioas_id);

int iommufd_access_rw(struct iommufd_access *access, unsigned long iova,
		      void *data, size_t len, bool write);
#else /* !CONFIG_IOMMUFD */
static inline struct iommufd_ctx *iommufd_ctx_from_file(struct file *file)
{
       return ERR_PTR(-EOPNOTSUPP);
}

static inline void iommufd_ctx_put(struct iommufd_ctx *ictx)
{
}

static inline int iommufd_vfio_compat_ioas_id(struct iommufd_ctx *ictx,
					      u32 *out_ioas_id)
{
	return -EOPNOTSUPP;
}

static inline int iommufd_access_rw(struct iommufd_access *access, unsigned long iova,
		      void *data, size_t len, bool write)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_IOMMUFD */
#endif
