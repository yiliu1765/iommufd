/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES.
 *
 */
#ifndef __IO_PAGETABLE_H
#define __IO_PAGETABLE_H

#include <linux/interval_tree.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/xarray.h>

#include "iommufd_private.h"

struct iommu_domain;

/*
 * Each io_pagetable is composed of intervals of areas which cover regions of
 * the iova that are backed by something. iova not covered by areas is not
 * populated in the page table. Each area is fully populated with pages.
 *
 * iovas are in byte units, but must be iopt->iova_alignment aligned.
 *
 * pages can be NULL, this means some other thread is still working on setting
 * up or tearing down the area. When observed under the write side of the
 * domain_rwsem a NULL pages must mean the area is still being setup and no
 * domains are filled.
 *
 * storage_domain points at an arbitrary iommu_domain that is holding the PFNs
 * for this area. It is locked by the pages->mutex. This simplifies the locking
 * as the pages code can rely on the storage_domain without having to get the
 * iopt->domains_rwsem.
 *
 * The io_pagetable::iova_rwsem protects node
 * The iopt_pages::mutex protects pages_node
 * iopt and immu_prot are immutable
 * The pages::mutex protects num_users
 */
struct iopt_area {
	struct interval_tree_node node;
	struct interval_tree_node pages_node;
	struct io_pagetable *iopt;
	struct iopt_pages *pages;
	struct iommu_domain *storage_domain;
	/* How many bytes into the first page the area starts */
	unsigned int page_offset;
	/* IOMMU_READ, IOMMU_WRITE, etc */
	int iommu_prot;
	bool prevent_users : 1;
	unsigned int num_users;
};

struct iopt_allowed {
	struct interval_tree_node node;
};

struct iopt_reserved {
	struct interval_tree_node node;
	void *owner;
};

int iopt_area_fill_domains(struct iopt_area *area, struct iopt_pages *pages);
void iopt_area_unfill_domains(struct iopt_area *area, struct iopt_pages *pages);

int iopt_area_fill_domain(struct iopt_area *area, struct iommu_domain *domain);
void iopt_area_unfill_domain(struct iopt_area *area, struct iopt_pages *pages,
			     struct iommu_domain *domain);
void iopt_unmap_domain(struct io_pagetable *iopt, struct iommu_domain *domain);

static inline unsigned long iopt_area_index(struct iopt_area *area)
{
	return area->pages_node.start;
}

static inline unsigned long iopt_area_last_index(struct iopt_area *area)
{
	return area->pages_node.last;
}

static inline unsigned long iopt_area_iova(struct iopt_area *area)
{
	return area->node.start;
}

static inline unsigned long iopt_area_last_iova(struct iopt_area *area)
{
	return area->node.last;
}

static inline size_t iopt_area_length(struct iopt_area *area)
{
	return (area->node.last - area->node.start) + 1;
}

#define __make_iopt_iter(name)                                                 \
	static inline struct iopt_##name *iopt_##name##_iter_first(            \
		struct io_pagetable *iopt, unsigned long start,                \
		unsigned long last)                                            \
	{                                                                      \
		struct interval_tree_node *node;                               \
                                                                               \
		lockdep_assert_held(&iopt->iova_rwsem);                        \
		node = interval_tree_iter_first(&iopt->name##_itree, start,    \
						last);                         \
		if (!node)                                                     \
			return NULL;                                           \
		return container_of(node, struct iopt_##name, node);           \
	}                                                                      \
	static inline struct iopt_##name *iopt_##name##_iter_next(             \
		struct iopt_##name *last_node, unsigned long start,            \
		unsigned long last)                                            \
	{                                                                      \
		struct interval_tree_node *node;                               \
                                                                               \
		node = interval_tree_iter_next(&last_node->node, start, last); \
		if (!node)                                                     \
			return NULL;                                           \
		return container_of(node, struct iopt_##name, node);           \
	}

__make_iopt_iter(area)
__make_iopt_iter(allowed)
__make_iopt_iter(reserved)

/*
 * This holds a pinned page list for multiple areas of IO address space. The
 * pages always originate from a linear chunk of userspace VA. Multiple
 * io_pagetable's, through their iopt_area's, can share a single iopt_pages
 * which avoids multi-pinning and double accounting of page consumption.
 *
 * indexes in this structure are measured in PAGE_SIZE units, are 0 based from
 * the start of the uptr and extend to npages. pages are pinned dynamically
 * according to the intervals in the users_itree and domains_itree, npinned
 * records the current number of pages pinned.
 */
struct iopt_pages {
	struct kref kref;
	struct mutex mutex;
	size_t npages;
	size_t npinned;
	size_t last_npinned;
	struct task_struct *source_task;
	struct mm_struct *source_mm;
	struct user_struct *source_user;
	void __user *uptr;
	bool writable:1;
	bool has_cap_ipc_lock:1;

	struct xarray pinned_pfns;
	/* Of iopt_pages_user::node */
	struct rb_root_cached users_itree;
	/* Of iopt_area::pages_node */
	struct rb_root_cached domains_itree;
};

struct iopt_pages *iopt_alloc_pages(void __user *uptr, unsigned long length,
				    bool writable);
void iopt_release_pages(struct kref *kref);
static inline void iopt_put_pages(struct iopt_pages *pages)
{
	kref_put(&pages->kref, iopt_release_pages);
}

void iopt_pages_fill_from_xarray(struct iopt_pages *pages, unsigned long start,
				 unsigned long last, struct page **out_pages);
int iopt_pages_fill_xarray(struct iopt_pages *pages, unsigned long start,
			   unsigned long last, struct page **out_pages);
void iopt_pages_unfill_xarray(struct iopt_pages *pages, unsigned long start,
			      unsigned long last);

int iopt_pages_add_user(struct iopt_pages *pages, unsigned long start,
			unsigned long last, struct page **out_pages,
			bool write);
void iopt_pages_remove_user(struct iopt_area *area, unsigned long start,
			    unsigned long last);

/*
 * Each interval represents an active iopt_access_pages(), it acts as an
 * interval lock that keeps the PFNs pinned and stored in the xarray.
 */
struct iopt_pages_user {
	struct interval_tree_node node;
	refcount_t refcount;
};

#endif
