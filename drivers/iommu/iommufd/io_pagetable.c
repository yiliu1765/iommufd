// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES.
 *
 * This is a datastructure intended to map IOVA's to PFNs. The PFNs can be
 * placed into an iommu_domain, or returned to the caller as a page list, for
 * emulated SW access.
 *
 * The datastructre is designed to be able to share chunks of PFNs between
 * different maps (to minimize the number of page pins required) and to be able
 * to store the pfns themselves inside the page table within an struct
 * iommu_domain. (avoid duplicate storage)
 *
 * It is a straightforward scheme, except for the transition from having an
 * iommu_domain hold the pfns to having the emulated domain hold the pfns. On
 * this edge the PFNs have to be moved between the iommu_domain and a xarray
 * that holds the PFNs.
 *
 * This is further complicated because the iommu_domain requires pinning ever
 * PFN, but the SW domain does not. So there are algorithms to selectively pin
 * based on emulated usages, again optimized to single pin.
 *
 * The design does not support splitting or hole punching in the allocations.
 * Each mapped in IOVA range is an object and must be manipulated as-is. This
 * matches the current VFIO semantic and significantly simplifies the design.
 */
#include <linux/rwsem.h>
#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/sched/mm.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/kref.h>
#include <linux/overflow.h>
#include <linux/interval_tree.h>
#include <linux/rwsem.h>
#include <linux/xarray.h>
#include <linux/sched.h>

#include "iommufd_private.h"

#define TEMP_MEMORY_LIMIT 65536
#define BATCH_BACKUP_SIZE 32

/*
 * Each io_pagetable is composed of intervals of areas which cover regions of
 * the iova that are backed by something. iova not covered by areas is not
 * populated in the page table. Each area is fully populated with pages.
 *
 * iovas are in byte units, but must be iopt->iova_alignemnt aligned.
 */
struct iopt_area {
	struct interval_tree_node node;
	struct interval_tree_node pages_node;
	struct io_pagetable *iopt;
	struct iopt_pages *pages;
	atomic_t num_users;
	/* IOMMU_READ, IOMMU_WRITE, etc */
	int iommu_prot;
};

/*
 * This holds a pinned page list for an area of IO address space. The pages
 * always originate from a linear chunk of userspace VA. Multiple io_pagetable's
 * through their iopt_area's can share a single iopt_pages which avoids
 * multi-pinning and double accounting of page consumption.
 *
 * If any io_pagetable has a domain then the domain must have a fully populated
 * list of PFNs in this pages. In this case the domain becomes the backing store
 * for the pfn list.
 *
 * For non-domain io_pagetables the list of pages is stored in the pinned_pfns
 * xarray and a record of users is kept in the users_itree. The union of all
 * intervals in the users_itree represents the populated PFNs, while the holes
 * in users_itree that are not covered by any interverals represents user va
 * that is not currently pinned.
 *
 * As io_pagetables can be attached/removed at any time the iopt_pages can shift
 * between domain backed and pinned_pfns back during its lifecycle.
 *
 * indexes in this structure are measured in PAGE_SIZE units, are 0 based from
 * the start of the uptr and extend to npages.
 */
struct iopt_pages {
	struct kref kref;
	struct mutex mutex;
	size_t npages;
	size_t npinned;
	struct mm_struct *source_mm;
	void __user *uptr;
	bool writable;

	struct xarray pinned_pfns;
	struct rb_root_cached users_itree;
	struct rb_root_cached domains_itree;
};

static void iopt_add_npinned(struct iopt_pages *pages, size_t npages)
{
	int rc;

	rc = check_add_overflow(pages->npinned, npages, &pages->npinned);
	if (IS_ENABLED(CONFIG_IOMMUFD_TEST))
		WARN_ON(rc || pages->npinned > pages->npages);
}

static void iopt_sub_npinned(struct iopt_pages *pages, size_t npages)
{
	int rc;

	rc = check_sub_overflow(pages->npinned, npages, &pages->npinned);
	if (IS_ENABLED(CONFIG_IOMMUFD_TEST))
		WARN_ON(rc || pages->npinned > pages->npages);
}

/*
 * More memory makes the algorithms more efficient, but as this is only a
 * performance optimization don't try too hard to get it. A 64k allocation can
 * hold about 26M of 4k pages and 13G of 2M pages in an iopt_batch. Various
 * destroy paths cannot fail and provide a small amount of stack memory as a
 * backup contingency. If backup_len is given this cannot fail.
 */
static void *temp_kmalloc(size_t *size, void *backup, size_t backup_len)
{
	void *res;

	if (*size < backup_len)
		return backup;
	*size = min_t(size_t, *size, TEMP_MEMORY_LIMIT);
	res = kmalloc(*size, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
	if (res)
		return res;
	*size = PAGE_SIZE;
	if (backup_len) {
		res = kmalloc(*size, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
		if (res)
			return res;
		*size = backup_len;
		return backup;
	}
	return kmalloc(*size, GFP_KERNEL);
}

static void iommu_unmap_nofail(struct iommu_domain *domain, unsigned long iova,
			       size_t size)
{
	size_t ret;

	ret = iommu_unmap(domain, iova, size);
	/*
	 * It is a logic error in this code or a driver bug if the IOMMU unmaps
	 * something other than exactly as requested.
	 */
	WARN_ON(ret != size);
}

/*
 * A simple datastructure to hold a vector of PFNs, optimizing for contiguous
 * pfns. This is used as a temporary holding memory for shuttling pfns from one
 * place to another. Generally everything is made more efficient if operations
 * work on the largest possible grouping of pfns. eg fewer lock/unlock cycles,
 * better cache locality, etc
 */
struct iopt_pfn_batch {
	unsigned long *pfns;
	u16 *npfns;
	unsigned int array_size;
	unsigned int end;
	unsigned int total_pfns;
};

static void iopt_batch_clear(struct iopt_pfn_batch *batch)
{
	batch->total_pfns = 0;
	batch->end = 0;
	batch->pfns[0] = 0;
	batch->npfns[0] = 0;
}

static int __iopt_batch_init(struct iopt_pfn_batch *batch, size_t max_pages,
			     void *backup, size_t backup_len)
{
	const size_t elmsz = sizeof(*batch->pfns) + sizeof(batch->npfns);
	size_t size = max_pages * elmsz;

	batch->pfns = temp_kmalloc(&size, backup, backup_len);
	if (!batch->pfns)
		return -ENOMEM;
	batch->array_size = size / elmsz;
	batch->npfns = (u16 *)(batch->pfns + batch->array_size);
	iopt_batch_clear(batch);
	return 0;
}

static int iopt_batch_init(struct iopt_pfn_batch *batch, size_t max_pages)
{
	return __iopt_batch_init(batch, max_pages, NULL, 0);
}

static void iopt_batch_init_backup(struct iopt_pfn_batch *batch,
				   size_t max_pages, void *backup,
				   size_t backup_len)
{
	__iopt_batch_init(batch, max_pages, backup, backup_len);
}

static void iopt_batch_destroy(struct iopt_pfn_batch *batch, void *backup)
{
	if (batch->pfns != backup)
		kfree(batch->pfns);
}

/* true if the pfn could be added, false otherwise */
static bool iopt_batch_add_pfn(struct iopt_pfn_batch *batch, unsigned long pfn)
{
	if (batch->end &&
	    pfn == batch->pfns[batch->end - 1] + batch->npfns[batch->end - 1]) {
		batch->total_pfns++;
		if (batch->npfns[batch->end - 1]++ == U16_MAX) {
			if (batch->end == batch->array_size)
				return false;
			batch->pfns[batch->end] = pfn;
			batch->npfns[batch->end] = 0;
			batch->end++;
		}
	} else {
		if (batch->end == batch->array_size)
			return false;
		batch->total_pfns++;
		batch->pfns[batch->end] = pfn;
		batch->npfns[batch->end] = 1;
		batch->end++;
	}
	return true;
}

static void iopt_batch_from_domain(struct iopt_pfn_batch *batch,
				   struct iommu_domain *domain,
				   unsigned long iova, size_t npages)
{
	unsigned long next_iova = (iova & PAGE_MASK) + PAGE_SIZE;
	phys_addr_t phys;

	iopt_batch_clear(batch);
	while (npages) {
		/*
		 * This is pretty slow, it would be nice to get the page size
		 * back from the driver, or have the driver directly fill the
		 * batch.
		 */
		phys = iommu_iova_to_phys(domain, iova);
		if (!iopt_batch_add_pfn(batch, PHYS_PFN(phys)))
			return;
		iova = next_iova;
		next_iova += PAGE_SIZE;
		npages--;
	}
}

static int iopt_batch_to_domain(struct iopt_pfn_batch *batch,
				struct iommu_domain *domain, unsigned long iova,
				unsigned long last_iova, int iommu_prot)
{
	unsigned long next_iova = (iova & PAGE_MASK);
	unsigned long start_iova = iova;
	unsigned int cur = 0;
	int rc;

	while (cur < batch->end) {
		next_iova = min(last_iova + 1,
				next_iova + batch->npfns[cur] * PAGE_SIZE);
		rc = iommu_map(domain, iova,
			       PFN_PHYS(batch->pfns[cur]) + (iova % PAGE_SIZE),
			       next_iova - iova, iommu_prot);
		if (rc) {
			if (start_iova != iova)
				iommu_unmap_nofail(domain, start_iova,
						   iova - start_iova);
			return rc;
		}
		iova = next_iova;
		cur++;
	}
	return 0;
}

static void iopt_batch_from_xarray(struct iopt_pfn_batch *batch,
				   struct xarray *xa, unsigned long start_index,
				   unsigned long last_index)
{
	XA_STATE(xas, xa, start_index);
	void *entry;

	rcu_read_lock();
	while (true) {
		entry = xas_next(&xas);
		if (xas_retry(&xas, entry))
			continue;
		WARN_ON(!xa_is_value(entry));
		if (!iopt_batch_add_pfn(batch, xa_to_value(entry)) ||
		    start_index == last_index)
			break;
		start_index++;
	}
	rcu_read_unlock();
}

static void iopt_clear_xarray(struct xarray *xa, unsigned long index,
			      unsigned long last)
{
	XA_STATE(xas, xa, index);
	void *entry;

	xas_lock(&xas);
	xas_for_each (&xas, entry, last)
		xas_store(&xas, NULL);
	xas_unlock(&xas);
}

static int iopt_batch_to_xarray(struct iopt_pfn_batch *batch, struct xarray *xa,
				unsigned long start_index)
{
	XA_STATE(xas, xa, start_index);
	unsigned int npage = 0;
	unsigned int cur = 0;

	do {
		xas_lock(&xas);
		while (cur < batch->end) {
			void *old;

			old = xas_store(&xas,
					xa_mk_value(batch->pfns[cur] + npage));
			if (xas_error(&xas))
				break;
			WARN_ON(old);
			npage++;
			if (npage == batch->npfns[cur]) {
				npage = 0;
				cur++;
			}
			xas_next(&xas);
		}
		xas_unlock(&xas);
	} while (xas_nomem(&xas, GFP_KERNEL));

	if (xas_error(&xas)) {
		if (xas.xa_index != start_index)
			iopt_clear_xarray(xa, start_index, xas.xa_index - 1);
		return xas_error(&xas);
	}
	return 0;
}

static void iopt_batch_to_pages(struct iopt_pfn_batch *batch,
				struct page **pages)
{
	unsigned int npage = 0;
	unsigned int cur = 0;

	while (cur < batch->end) {
		*pages++ = pfn_to_page(batch->pfns[cur] + npage);
		npage++;
		if (npage == batch->npfns[cur]) {
			npage = 0;
			cur++;
		}
	}
}

static void iopt_batch_from_pages(struct iopt_pfn_batch *batch,
				  struct page **pages, size_t npages)
{
	struct page **end = pages + npages;

	for (; pages != end; pages++)
		if (!iopt_batch_add_pfn(batch, page_to_pfn(*pages)))
			break;
}

static void iopt_batch_unpin(struct iopt_pfn_batch *batch,
			     struct iopt_pages *pages, unsigned int offset,
			     size_t npages)
{
	unsigned int cur = 0;

	while (offset) {
		if (batch->npfns[cur] < offset)
			break;
		offset -= batch->npfns[cur];
		cur++;
	}

	while (npages) {
		size_t to_unpin =
			min_t(size_t, npages, batch->npfns[cur] - offset);

		unpin_user_page_range_dirty_lock(
			pfn_to_page(batch->pfns[cur] + offset), to_unpin,
			pages->writable);
		iopt_sub_npinned(pages, to_unpin);
		cur++;
		offset = 0;
		npages -= to_unpin;
	}
}

/*
 * Each interval represents an active iopt_access_pages(), it acts as an
 * interval lock that keeps the pfns pined and in the xarray.
 */
struct iopt_pages_user {
	struct interval_tree_node node;
	refcount_t refcount;
};

static struct iopt_area *iopt_area_iter_first(struct io_pagetable *iopt,
					      unsigned long start,
					      unsigned long last)
{
	struct interval_tree_node *node;

	node = interval_tree_iter_first(&iopt->area_itree, start, last);
	if (!node)
		return NULL;
	return container_of(node, struct iopt_area, node);
}

static struct iopt_area *iopt_area_iter_next(struct iopt_area *area,
					     unsigned long start,
					     unsigned long last)
{
	struct interval_tree_node *node;

	node = interval_tree_iter_next(&area->node, start, last);
	if (!node)
		return NULL;
	return container_of(node, struct iopt_area, node);
}

static unsigned long iopt_area_iova(struct iopt_area *area)
{
	return area->node.start;
}

static unsigned long iopt_area_last_iova(struct iopt_area *area)
{
	return area->node.last;
}

static size_t iopt_area_length(struct iopt_area *area)
{
	return (area->node.last - area->node.start) + 1;
}

static struct iopt_area *iopt_area_find_exact(struct io_pagetable *iopt,
					      unsigned long iova,
					      unsigned long last_iova)
{
	struct iopt_area *area;

	area = iopt_area_iter_first(iopt, iova, last_iova);
	if (!area || area->node.start != iova || area->node.last != last_iova)
		return NULL;
	return area;
}

static unsigned long iopt_area_index(struct iopt_area *area)
{
	return area->pages_node.start;
}

static unsigned long iopt_area_last_index(struct iopt_area *area)
{
	return area->pages_node.last;
}

/*
 * index is the number of PAGE_SIZE units from the start of the area's
 * iopt_pages. If the iova is sub page-size then the area has an iova that
 * covers a portion of the first and last pages in the range.
 */
static unsigned long iopt_index_to_iova(struct iopt_area *area,
					unsigned long index)
{
	if (IS_ENABLED(CONFIG_IOMMUFD_TEST))
		WARN_ON(index < iopt_area_index(area) ||
			index > iopt_area_last_index(area));
	index -= iopt_area_index(area);
	if (index == 0)
		return iopt_area_iova(area);
	return (iopt_area_iova(area) & PAGE_MASK) + index * PAGE_SIZE;
}

static struct iopt_area *iopt_find_domain_area(struct iopt_pages *pages,
					       unsigned long index)
{
	struct interval_tree_node *node;

	node = interval_tree_iter_first(&pages->domains_itree, index, index);
	if (!node)
		return NULL;
	return container_of(node, struct iopt_area, pages_node);
}

static unsigned long iopt_iova_to_index(struct iopt_area *area,
					unsigned long iova)
{
	if (IS_ENABLED(CONFIG_IOMMUFD_TEST))
		WARN_ON(iova < iopt_area_iova(area) ||
			iova > iopt_area_last_iova(area));
	return (iova - (iopt_area_iova(area) & PAGE_MASK)) / PAGE_SIZE;
}

static struct iopt_pages *iopt_alloc_pages(void __user *uptr,
					   unsigned long iova,
					   unsigned long length, bool writable)
{
	struct iopt_pages *pages;

	/*
	 * The iommu API uses size_t as the length, and protect the DIV_ROUND_UP
	 * below from overflow
	 */
	if (length > SIZE_MAX - PAGE_SIZE)
		return ERR_PTR(-EINVAL);
	if ((iova % PAGE_SIZE) != (((uintptr_t)uptr) % PAGE_SIZE))
		return ERR_PTR(-EINVAL);

	pages = kzalloc(sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	kref_init(&pages->kref);
	xa_init(&pages->pinned_pfns);
	mutex_init(&pages->mutex);
	pages->source_mm = current->mm;
	mmgrab(pages->source_mm);
	pages->uptr = (void __user *)ALIGN_DOWN((uintptr_t)uptr, PAGE_SIZE);
	pages->npages = DIV_ROUND_UP(length + (uptr - pages->uptr), PAGE_SIZE);
	pages->users_itree = RB_ROOT_CACHED;
	pages->domains_itree = RB_ROOT_CACHED;
	pages->writable = writable;

	return pages;
}

static void iopt_release_pages(struct kref *kref)
{
	struct iopt_pages *pages = container_of(kref, struct iopt_pages, kref);

	WARN_ON(!RB_EMPTY_ROOT(&pages->users_itree.rb_root));
	WARN_ON(!RB_EMPTY_ROOT(&pages->domains_itree.rb_root));
	WARN_ON(pages->npinned);
	mmdrop(pages->source_mm);
	mutex_destroy(&pages->mutex);
	kfree(pages);
}

static void iopt_put_pages(struct iopt_pages *pages)
{
	kref_put(&pages->kref, iopt_release_pages);
}

static struct iommu_domain *iopt_get_any_domain(struct io_pagetable *iopt)
{
	struct iommu_domain *domain = xa_load(&iopt->domains, 0);

	lockdep_assert_held(&iopt->rwsem);
	WARN_ON(!domain);
	return domain;
}


static void iopt_area_unmap_domain(struct iopt_area *area,
				   struct iommu_domain *domain,
				   unsigned long start_index,
				   unsigned long last_index)
{
	unsigned long start_iova = iopt_index_to_iova(area, start_index);
	unsigned long last_iova;

	if (last_index == iopt_area_last_index(area))
		last_iova = iopt_area_last_iova(area);
	else
		last_iova = iopt_index_to_iova(area, last_index + 1) - 1;
	iommu_unmap_nofail(domain, start_iova, last_iova - start_iova + 1);
}

/*
 * PFNs are stored in three places, in order of preference:
 * - The iopt_pages xarray. This is only populated if there is a
 *   iopt_pages_user
 * - The iommu_domain under an area
 * - The original PFN source, ie pages->source_mm
 *
 * This iterator reads the pfns optimizing to load according to the
 * above order.
 */
struct iopt_pfn_reader {
	struct iopt_pages *pages;
	struct interval_tree_span_iter span;
	struct iopt_pfn_batch batch;
	unsigned long cur_index;
	unsigned long fill_index;
	unsigned long last_index;

	struct page **upages;
	size_t upages_len;
	unsigned long upages_start;
	unsigned long upages_end;
};

static int iopt_pfn_reader_pin_pages(struct iopt_pfn_reader *pfns)
{
	struct iopt_pages *pages = pfns->pages;
	unsigned int gup_flags;
	unsigned long npages;
	long rc;

	if (pfns->pages->writable) {
		gup_flags = FOLL_LONGTERM | FOLL_WRITE;
	} else {
		/* Still need to break COWs on read */
		gup_flags = FOLL_LONGTERM | FOLL_FORCE | FOLL_WRITE;
	}

	if (!pfns->upages) {
		/* All undone in iopt_pfn_reader_destroy */
		pfns->upages_len = (pfns->last_index - pfns->fill_index + 1) *
				   sizeof(*pfns->upages);
		pfns->upages = temp_kmalloc(&pfns->upages_len, NULL, 0);
		if (!pfns->upages) {
			return -ENOMEM;
		}

		if (!mmget_not_zero(pages->source_mm)) {
			kfree(pfns->upages);
			return -EINVAL;
		}
		mmap_read_lock(pages->source_mm);
	}

	npages = min_t(unsigned long,
		       pfns->span.last_hole - pfns->fill_index + 1,
		       pfns->upages_len / sizeof(*pfns->upages));

	/* FIXME memlock */
	rc = pin_user_pages_remote(
		pages->source_mm,
		(uintptr_t)(pages->uptr + pfns->fill_index * PAGE_SIZE), npages,
		gup_flags, pfns->upages, NULL, NULL);
	if (rc < 0)
		return rc;
	if (WARN_ON(!rc))
		return -EFAULT;
	iopt_add_npinned(pages, rc);
	pfns->upages_start = pfns->fill_index;
	pfns->upages_end = pfns->fill_index + rc;
	return 0;
}

/*
 * The batch can contain a mixture of pages that are still in use and pages that
 * need to be unpinned. Unpin only pages that are not held anywhere else.
 */
static void iopt_pages_unpin(struct iopt_pages *pages,
			     struct iopt_pfn_batch *batch, unsigned long index,
			     unsigned long last)
{
	struct interval_tree_span_iter user_span;
	struct interval_tree_span_iter area_span;

	lockdep_assert_held(&pages->mutex);

	for (interval_tree_span_iter_first(&user_span, &pages->users_itree, 0,
					   last);
	     !interval_tree_span_iter_done(&user_span);
	     interval_tree_span_iter_next(&user_span)) {
		if (!user_span.is_hole)
			continue;

		for (interval_tree_span_iter_first(
			     &area_span, &pages->domains_itree,
			     user_span.start_hole, user_span.last_hole);
		     !interval_tree_span_iter_done(&area_span);
		     interval_tree_span_iter_next(&area_span)) {
			if (!area_span.is_hole)
				continue;

			iopt_batch_unpin(
				batch, pages, area_span.start_hole - index,
				area_span.last_hole - area_span.start_hole + 1);
		}
	}
}

static int iopt_pfn_reader_fill_span(struct iopt_pfn_reader *pfns)
{
	struct interval_tree_span_iter *span = &pfns->span;
	struct iopt_area *area;
	int rc;

	if (!span->is_hole) {
		iopt_batch_from_xarray(&pfns->batch, &pfns->pages->pinned_pfns,
				       pfns->fill_index, span->last_used);
		return 0;
	}

	area = iopt_find_domain_area(pfns->pages, pfns->fill_index);
	if (area) {
		unsigned int last_index;

		last_index = min(iopt_area_last_index(area), span->last_hole);
		iopt_batch_from_domain(
			&pfns->batch, iopt_get_any_domain(area->iopt),
			iopt_index_to_iova(area, pfns->fill_index),
			last_index - pfns->fill_index + 1);
		return 0;
	}

	if (pfns->fill_index >= pfns->upages_end) {
		rc = iopt_pfn_reader_pin_pages(pfns);
		if (rc)
			return rc;
	}

	iopt_batch_from_pages(&pfns->batch,
			      pfns->upages +
				      (pfns->fill_index - pfns->upages_start),
			      pfns->upages_end - pfns->upages_start);
	return 0;
}

static bool iopt_pfn_reader_done(struct iopt_pfn_reader *pfns)
{
	return pfns->cur_index == pfns->last_index + 1;
}

static int iopt_pfn_reader_next(struct iopt_pfn_reader *pfns)
{
	int rc;

	iopt_batch_clear(&pfns->batch);
	pfns->cur_index = pfns->fill_index;
	while (pfns->fill_index != pfns->last_index + 1) {
		rc = iopt_pfn_reader_fill_span(pfns);
		if (rc)
			return rc;
		pfns->fill_index = pfns->cur_index + pfns->batch.total_pfns;
		if (pfns->fill_index != pfns->span.last_used + 1)
			return 0;
		interval_tree_span_iter_next(&pfns->span);
	}
	return 0;
}

static int iopt_pfn_reader_seek_hole(struct iopt_pfn_reader *pfns,
				struct interval_tree_span_iter *span)
{
	pfns->cur_index = span->start_hole;
	pfns->fill_index = span->start_hole;
	pfns->last_index = span->last_hole;
	pfns->span = *span;
	return iopt_pfn_reader_next(pfns);
}

static int iopt_pfn_reader_init(struct iopt_pfn_reader *pfns,
				struct iopt_pages *pages, unsigned long index,
				unsigned long last)
{
	int rc;

	lockdep_assert_held(&pages->mutex);

	rc = iopt_batch_init(&pfns->batch, last - index + 1);
	if (rc)
		return rc;
	pfns->pages = pages;
	pfns->cur_index = index;
	pfns->fill_index = index;
	pfns->last_index = last;
	pfns->upages = NULL;
	pfns->upages_start = 0;
	pfns->upages_end = 0;
	interval_tree_span_iter_first(&pfns->span, &pages->users_itree,
				      index, last);
	return 0;
}

static void iopt_pfn_reader_destroy(struct iopt_pfn_reader *pfns)
{
	if (pfns->upages) {
		mmap_read_unlock(pfns->pages->source_mm);
		mmput(pfns->pages->source_mm);

		/* Any pages not transfered to the batch are just unpinned */
		unpin_user_pages(
			pfns->upages + (pfns->fill_index - pfns->upages_start),
			pfns->upages_end - pfns->fill_index);
		kfree(pfns->upages);
		pfns->upages = NULL;
	}

	if (pfns->cur_index != pfns->fill_index)
		iopt_pages_unpin(pfns->pages, &pfns->batch, pfns->cur_index,
				 pfns->fill_index - 1);
	iopt_batch_destroy(&pfns->batch, NULL);
}

static int iopt_pfn_reader_first(struct iopt_pfn_reader *pfns,
				 struct iopt_pages *pages, unsigned long index,
				 unsigned long last)
{
	int rc;

	rc = iopt_pfn_reader_init(pfns, pages, index, last);
	if (rc)
		return rc;
	rc = iopt_pfn_reader_next(pfns);
	if (rc) {
		iopt_pfn_reader_destroy(pfns);
		return rc;
	}
	return 0;
}

static bool iopt_fully_covers(struct rb_root_cached *root, unsigned long index,
			      unsigned long last)
{
	struct interval_tree_node *node;

	node = interval_tree_iter_first(root, index, last);
	if (!node)
		return false;
	return node->start <= index && node->last >= last;
}

static bool iopt_fully_covers_area(struct rb_root_cached *root,
				   struct iopt_area *area)
{
	return iopt_fully_covers(root, iopt_area_index(area),
				 iopt_area_last_index(area));
}

static void __iopt_area_unfill_domain(struct iopt_area *area,
				      struct iommu_domain *domain,
				      unsigned long last_index, bool force_fast)
{
	unsigned long unmapped_index = iopt_area_index(area);
	unsigned long cur_index = unmapped_index;
	u64 backup[BATCH_BACKUP_SIZE];
	struct iopt_pfn_batch batch;

	lockdep_assert_held(&area->pages->mutex);

	/* Fast path if there is obviously something else using every pfn */
	if (force_fast ||
	    iopt_fully_covers_area(&area->pages->domains_itree, area) ||
	    iopt_fully_covers_area(&area->pages->users_itree, area)) {
		iopt_area_unmap_domain(area, domain, iopt_area_index(area),
				       last_index);
		return;
	}

	/*
	 * unmaps must always 'cut' at a place where the pfns are not contiguous
	 * to pair with the maps that always install contiguous pages. This
	 * algorithm is efficient in the expected case of few pinners.
	 */
	iopt_batch_init_backup(&batch, last_index + 1, backup, sizeof(backup));
	while (cur_index != last_index + 1) {
		unsigned long batch_index = cur_index;

		iopt_batch_from_domain(&batch, domain,
				       iopt_index_to_iova(area, cur_index),
				       last_index - cur_index + 1);
		cur_index += batch.total_pfns;
		iopt_area_unmap_domain(area, domain, unmapped_index,
				       cur_index - 1);
		unmapped_index = cur_index;
		iopt_pages_unpin(area->pages, &batch, batch_index,
				 cur_index - 1);
		iopt_batch_clear(&batch);
	}
	iopt_batch_destroy(&batch, backup);
}

static void iopt_area_unfill_domain(struct iopt_area *area,
				    struct iommu_domain *domain,
				    unsigned long end_index, bool force_fast)
{
	if (end_index != iopt_area_index(area))
		__iopt_area_unfill_domain(area, domain, end_index - 1,
					  force_fast);
}

static void iopt_area_unfill_whole_domain(struct iopt_area *area,
					  struct iommu_domain *domain)
{
	__iopt_area_unfill_domain(area, domain, iopt_area_last_index(area),
				  false);
}

static int iopt_area_fill_domain(struct iopt_area *area,
				 struct iommu_domain *domain)
{
	struct iopt_pfn_reader pfns;
	int rc;

	lockdep_assert_held(&area->pages->mutex);

	rc = iopt_pfn_reader_first(&pfns, area->pages, iopt_area_index(area),
				   iopt_area_last_index(area));
	if (rc)
		return rc;

	while (!iopt_pfn_reader_done(&pfns)) {
		rc = iopt_batch_to_domain(
			&pfns.batch, domain,
			iopt_index_to_iova(area, pfns.cur_index),
			iopt_area_last_iova(area), area->iommu_prot);
		if (rc)
			goto out_unmap;

		rc = iopt_pfn_reader_next(&pfns);
		if (rc)
			goto out_unmap;
	}
	rc = 0;
	goto out_destroy;

out_unmap:
	iopt_area_unfill_domain(area, domain, pfns.cur_index, false);
out_destroy:
	iopt_pfn_reader_destroy(&pfns);
	return rc;
}

static int iopt_area_fill_domains(struct iopt_area *area)
{
	struct iopt_pfn_reader pfns;
	struct iommu_domain *domain;
	unsigned long unmap_index;
	unsigned long index;
	int rc;

	lockdep_assert_held_write(&area->iopt->rwsem);

	if (xa_empty(&area->iopt->domains))
		return 0;

	mutex_lock(&area->pages->mutex);
	rc = iopt_pfn_reader_first(&pfns, area->pages, iopt_area_index(area),
				   iopt_area_last_index(area));
	if (rc)
		goto out_unlock;

	while (!iopt_pfn_reader_done(&pfns)) {
		xa_for_each (&area->iopt->domains, index, domain) {
			rc = iopt_batch_to_domain(
				&pfns.batch, domain,
				iopt_index_to_iova(area, pfns.cur_index),
				iopt_area_last_iova(area), area->iommu_prot);
			if (rc)
				goto out_unmap;
		}

		rc = iopt_pfn_reader_next(&pfns);
		if (rc)
			goto out_unmap;
	}
	interval_tree_insert(&area->pages_node, &area->pages->domains_itree);
	rc = 0;
	goto out_destroy;

out_unmap:
	/*
	 * The area is not yet part of the domains_itree so only the last
	 * domain is unpinned, the others are fast unmapped.
	 */
	xa_for_each (&area->iopt->domains, unmap_index, domain) {
		unsigned long end_index = pfns.cur_index;

		if (unmap_index <= index)
			end_index = pfns.fill_index;
		iopt_area_unfill_domain(area, domain, end_index,
					unmap_index !=
						area->iopt->next_domain_id - 1);
	}
out_destroy:
	iopt_pfn_reader_destroy(&pfns);
out_unlock:
	mutex_unlock(&area->pages->mutex);
	return rc;
}

static void iopt_area_unfill_domains(struct iopt_area *area)
{
	struct io_pagetable *iopt = area->iopt;
	struct iommu_domain *domain;
	unsigned long index;

	lockdep_assert_held_write(&iopt->rwsem);

	if (xa_empty(&area->iopt->domains))
		return;

	/* Fast unmap every domain that is not iopt_get_any_domain() */
	if (iopt->next_domain_id > 1) {
		xa_for_each_range (&iopt->domains, index, domain, 1,
				   iopt->next_domain_id - 1)
			iopt_area_unmap_domain(area, domain,
					       iopt_area_index(area),
					       iopt_area_last_index(area));
	}

	mutex_lock(&area->pages->mutex);
	interval_tree_remove(&area->pages_node,&area->pages->domains_itree);
	iopt_area_unfill_whole_domain(area, iopt_get_any_domain(iopt));
	mutex_unlock(&area->pages->mutex);
}

/*
 * Erase entries in the pinned_pfns xarray that are not covered by any users.
 * This does not unpin the pages, the caller is responsible to deal with the pin
 * reference. The main purpose of this action is to save memory in the xarray.
 */
static void iopt_pages_clean_xarray(struct iopt_pages *pages,
				    unsigned long index, unsigned long last)
{
	struct interval_tree_span_iter span;

	lockdep_assert_held(&pages->mutex);

	for (interval_tree_span_iter_first(&span, &pages->users_itree, index,
					   last);
	     !interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span))
		if (span.is_hole)
			iopt_clear_xarray(&pages->pinned_pfns, span.start_hole,
					  span.last_hole);
}


static void iopt_pages_unfill_xarray(struct iopt_pages *pages,
				     unsigned long index, unsigned long last)
{
	struct interval_tree_span_iter span;
	struct iopt_pfn_batch batch;
	u64 backup[BATCH_BACKUP_SIZE];

	if (iopt_fully_covers(&pages->domains_itree, index, last))
		return iopt_pages_clean_xarray(pages, index, last);

	iopt_batch_init_backup(&batch, last + 1, backup, sizeof(backup));
	for (interval_tree_span_iter_first(&span, &pages->users_itree, index,
					   last);
	     !interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		unsigned long cur_index;

		if (span.is_hole)
			continue;
		cur_index = span.start_hole;
		while (cur_index != span.last_hole + 1) {
			iopt_batch_from_xarray(&batch, &pages->pinned_pfns,
					       cur_index, span.last_hole);
			iopt_pages_unpin(pages, &batch, cur_index,
					 cur_index + batch.total_pfns - 1);
			cur_index += batch.total_pfns;
			iopt_batch_clear(&batch);
		}
	}
	iopt_batch_destroy(&batch, backup);
}

static void iopt_pages_fill_from_xarray(struct iopt_pages *pages,
					unsigned long start_index,
					unsigned long last_index,
					struct page **out_pages)
{
	XA_STATE(xas, &pages->pinned_pfns, start_index);
	void *entry;

	rcu_read_lock();
	while (true) {
		entry = xas_next(&xas);
		if (xas_retry(&xas, entry))
			continue;
		WARN_ON(!xa_is_value(entry));
		*(out_pages++) = pfn_to_page(xa_to_value(entry));
		if (start_index == last_index)
			break;
		start_index++;
	}
	rcu_read_unlock();
}

static int iopt_pages_fill_xarray(struct iopt_pages *pages, unsigned long index,
				  unsigned long last, struct page **out_pages)
{
	struct interval_tree_span_iter span;
	unsigned long xa_end = index;
	struct iopt_pfn_reader pfns;
	int rc;

	mutex_lock(&pages->mutex);

	rc = iopt_pfn_reader_init(&pfns, pages, index, last);
	if (rc)
		goto out_unlock;

	for (interval_tree_span_iter_first(&span, &pages->users_itree, index,
					   last);
	     !interval_tree_span_iter_done(&span);
	     interval_tree_span_iter_next(&span)) {
		if (!span.is_hole) {
			if (out_pages)
				iopt_pages_fill_from_xarray(
					pages + (span.start_used - index),
					span.start_used, span.last_used,
					out_pages);
			continue;
		}

		rc = iopt_pfn_reader_seek_hole(&pfns, &span);
		if (rc)
			goto out_clean_xa;

		while (!iopt_pfn_reader_done(&pfns)) {
			rc = iopt_batch_to_xarray(&pfns.batch,
						  &pages->pinned_pfns,
						  pfns.cur_index);
			if (rc)
				goto out_clean_xa;
			iopt_batch_to_pages(&pfns.batch, out_pages);
			xa_end += pfns.batch.total_pfns;
			out_pages += pfns.batch.total_pfns;
			rc = iopt_pfn_reader_next(&pfns);
			if (rc)
				goto out_clean_xa;
		}
	}

out_clean_xa:
	if (index != xa_end)
		iopt_pages_unfill_xarray(pages, index, xa_end);
	iopt_pfn_reader_destroy(&pfns);
out_unlock:
	mutex_unlock(&pages->mutex);
	return rc;
}

static struct iopt_area *iopt_alloc_area(struct io_pagetable *iopt,
					 unsigned long iova,
					 unsigned long length,
					 struct iopt_pages *pages,
					 int iommu_prot)
{
	struct iopt_area *area;
	unsigned long iova_end;

	if ((iova & (iopt->iova_alignment - 1)) ||
	    (length & (iopt->iova_alignment - 1)) || !length)
		return ERR_PTR(-EINVAL);

	if (check_add_overflow(iova, length - 1, &iova_end))
		return ERR_PTR(-EOVERFLOW);

	/* Check that there is not already a mapping in the range */
	if (iopt_area_iter_first(iopt, iova, iova_end))
		return ERR_PTR(-EADDRINUSE);

	/* No reserved IOVA intersects the range */
	if (interval_tree_iter_first(&iopt->reserved_iova_itree, iova,
				     iova_end))
		return ERR_PTR(-ENOENT);

	if ((iommu_prot & IOMMU_WRITE) && !pages->writable)
		return ERR_PTR(-EPERM);

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (!area)
		return ERR_PTR(-ENOMEM);
	area->node.start = iova;
	area->node.last = iova_end;
	area->pages_node.start = 0;
	area->pages_node.last = pages->npages - 1;
	area->iopt = iopt;
	area->iommu_prot = iommu_prot;
	/* Move the reference in from the caller */
	area->pages = pages;
	return area;
}

static void iopt_free_area(struct iopt_area *area)
{
	iopt_put_pages(area->pages);
	kfree(area);
}

static bool __alloc_iova_check_hole(struct interval_tree_span_iter *span,
				    unsigned long length,
				    unsigned long iova_alignment,
				    unsigned long iova_bits)
{
	if (!span->is_hole || span->last_hole - span->start_hole < length - 1)
		return false;

	span->start_hole = ALIGN(span->start_hole, iova_alignment) | iova_bits;
	if (span->start_hole > span->last_hole ||
	    span->last_hole - span->start_hole < length - 1)
		return false;
	return true;
}

/**
 * iopt_alloc_iova - Find an available range of iova
 *
 * Automatically find a block of IOVA that is not being used and not reserved.
 * Does not return a 0 IOVA even if it is valid.
 */
int iopt_alloc_iova(struct io_pagetable *iopt, unsigned long *iova,
		    unsigned long uptr, unsigned long length)
{
	struct interval_tree_span_iter reserved_span;
	unsigned long iova_bits = uptr % PAGE_SIZE;
	struct interval_tree_span_iter area_span;
	unsigned long iova_alignment;

	lockdep_assert_held(&iopt->rwsem);

	if (length == 0 || length >= ULONG_MAX / 2)
		return -EINVAL;

	/*
	 * Keep alignment present in the uptr when building the IOVA, this
	 * increases the chance we can map a THP.
	 */
	if (!uptr)
		iova_alignment = roundup_pow_of_two(length);
	else
		iova_alignment =
			min_t(unsigned long, roundup_pow_of_two(length),
			      1UL << __ffs64(uptr));

	if (iova_alignment < iopt->iova_alignment)
		return -EINVAL;
	for (interval_tree_span_iter_first(&area_span, &iopt->area_itree,
					   PAGE_SIZE, ULONG_MAX - PAGE_SIZE);
	     !interval_tree_span_iter_done(&area_span);
	     interval_tree_span_iter_next(&area_span)) {
		if (!__alloc_iova_check_hole(&area_span, length, iova_alignment,
					     iova_bits))
			continue;

		for (interval_tree_span_iter_first(
			     &reserved_span, &iopt->reserved_iova_itree,
			     area_span.start_hole, area_span.last_hole);
		     !interval_tree_span_iter_done(&reserved_span);
		     interval_tree_span_iter_next(&reserved_span)) {
			if (!__alloc_iova_check_hole(&reserved_span, length,
						     iova_alignment, iova_bits))
				continue;

			*iova = reserved_span.start_hole;
			return 0;
		}
	}
	return -ENOSPC;
}

/**
 * iopt_map_user_pages - Assign a user va to an iova in the io page table
 *
 * iova, uptr, and length must have a PAGE_SIZE alignment. For domain backed
 * page tables this will pin the pages and load them into the domain at iova.
 * For non-domain page tables this will only setup a lazy reference and the
 * caller must use iopt_access_pages() to touch them.
 *
 * iopt_unmap_iova() must be called to undo this before the io_pagetable can be
 * destroyed.
 */
int iopt_map_user_pages(struct io_pagetable *iopt, unsigned long iova,
			void __user *uptr, unsigned long length, int iommu_prot)
{
	struct iopt_pages *pages;
	struct iopt_area *area;
	int rc;

	lockdep_assert_held_write(&iopt->rwsem);

	pages = iopt_alloc_pages(uptr, iova, length, iommu_prot & IOMMU_WRITE);
	if (IS_ERR(pages)) {
		return PTR_ERR(pages);
	}

	area = iopt_alloc_area(iopt, iova, length, pages, iommu_prot);
	if (IS_ERR(area)) {
		iopt_put_pages(pages);
		return PTR_ERR(area);
	}

	rc = iopt_area_fill_domains(area);
	if (rc)
		goto out_free_area;
	interval_tree_insert(&area->node, &area->iopt->area_itree);
	return 0;

out_free_area:
	iopt_free_area(area);
	return rc;
}

struct iopt_pages *iopt_get_pages(struct io_pagetable *iopt, unsigned long iova,
				  unsigned long length)
{
	unsigned long iova_end;
	struct iopt_pages *pages;
	struct iopt_area *area;

	if (check_add_overflow(iova, length - 1, &iova_end))
		return ERR_PTR(-EOVERFLOW);

	down_read(&iopt->rwsem);
	area = iopt_area_find_exact(iopt, iova, iova_end);
	if (!area) {
		up_read(&iopt->rwsem);
		return ERR_PTR(-ENOENT);
	}
	pages = area->pages;
	kref_get(&pages->kref);
	up_read(&iopt->rwsem);

	return pages;
}

int iopt_copy_iova(struct io_pagetable *dst, struct iopt_pages *pages,
		   unsigned long dst_iova, unsigned long length, int iommu_prot)
{
	struct iopt_area *area;
	int rc;

	lockdep_assert_held(&dst->rwsem);

	if ((iommu_prot & IOMMU_WRITE) && !pages->writable) {
		iopt_put_pages(pages);
		return -EPERM;
	}

	area = iopt_alloc_area(dst, dst_iova, length, pages, iommu_prot);
	if (IS_ERR(area)) {
		iopt_put_pages(pages);
		return PTR_ERR(area);
	}

	rc = iopt_area_fill_domains(area);
	if (rc)
		goto out_free_area;
	interval_tree_insert(&area->node, &area->iopt->area_itree);
	return 0;

out_free_area:
	iopt_free_area(area);
	return rc;
}

static int __iopt_unmap_iova(struct io_pagetable *iopt, struct iopt_area *area)
{
	/* Drivers have to unpin on notification. */
	if (WARN_ON(atomic_read(&area->num_users)))
		return -EBUSY;

	interval_tree_remove(&area->node, &iopt->area_itree);
	iopt_area_unfill_domains(area);
	WARN_ON(atomic_read(&area->num_users));
	iopt_free_area(area);
	return 0;
}

/**
 * iopt_unmap_iova - Remove a range of iova
 *
 * The requested range must exactly match an existing range.
 * Splitting/truncating IOVA mappings is not allowed.
 */
int iopt_unmap_iova(struct io_pagetable *iopt, unsigned long iova,
		    unsigned long length)
{
	struct iopt_area *area;
	unsigned long iova_end;
	int rc;

	if (!length)
		return -EINVAL;

	if (check_add_overflow(iova, length - 1, &iova_end))
		return -EOVERFLOW;

	down_write(&iopt->rwsem);
	area = iopt_area_find_exact(iopt, iova, iova_end);
	if (!area) {
		rc = -ENOENT;
		goto out_unlock;
	}

	rc = __iopt_unmap_iova(iopt, area);
out_unlock:
	up_write(&iopt->rwsem);
	return rc;
}

int iopt_unmap_all(struct io_pagetable *iopt)
{
	struct iopt_area *area;
	int rc;

	down_write(&iopt->rwsem);
	while ((area = iopt_area_iter_first(iopt, 0, ULONG_MAX))) {
		rc = __iopt_unmap_iova(iopt, area);
		if (rc)
			goto out_unlock;
	}
	rc = 0;

out_unlock:
	up_write(&iopt->rwsem);
	return rc;
}

static struct iopt_pages_user *
iopt_pages_get_exact_user(struct iopt_pages *pages, unsigned long index,
			  unsigned long last)
{
	struct interval_tree_node *node;

	lockdep_assert_held(&pages->mutex);

	/* There can be overlapping ranges in this interval tree */
	for (node = interval_tree_iter_first(&pages->users_itree, index, last);
	     node; node = interval_tree_iter_next(node, index, last))
		if (node->start == index && node->last == last)
			return container_of(node, struct iopt_pages_user, node);
	return NULL;
}

static int iopt_pages_add_user(struct iopt_pages *pages, unsigned long index,
			       unsigned long last, struct page **out_pages,
			       bool write)
{
	struct iopt_pages_user *user;
	int rc;

	if (pages->writable != write)
		return -EPERM;

	mutex_lock(&pages->mutex);
	user = iopt_pages_get_exact_user(pages, index, last);
	if (user) {
		iopt_pages_fill_from_xarray(pages, index, last, out_pages);
		refcount_inc(&user->refcount);
		rc = 0;
		goto out_unlock;
	}

	user = kzalloc(sizeof(*user), GFP_KERNEL);
	if (!user) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	rc = iopt_pages_fill_xarray(pages, index, last, out_pages);
	if (rc)
		goto out_free;

	user->node.start = index;
	user->node.last = last;
	refcount_set(&user->refcount, 1);
	interval_tree_insert(&user->node, &pages->users_itree);
	rc = 0;

out_free:
	kfree(user);
out_unlock:
	mutex_unlock(&pages->mutex);
	return rc;
}

static void iopt_pages_remove_user(struct iopt_pages *pages,
				   unsigned long index, unsigned long last)
{
	struct iopt_pages_user *user;

	mutex_lock(&pages->mutex);
	user = iopt_pages_get_exact_user(pages, index, last);
	if (WARN_ON(!user))
		goto out_unlock;

	if (!refcount_dec_and_test(&user->refcount))
		goto out_unlock;

	iopt_pages_unfill_xarray(pages, index, last);
out_unlock:
	mutex_unlock(&pages->mutex);
}

/**
* iopt_access_pages - Return a list of pages under the iova
*
* Reads @npages starting at iova and returns the struct page * pointers. These
* can be kmap'd by the caller for CPU access.
*
* The caller must perform iopt_unaccess_pages() when done to balance this.
*
* iova can be unaligned from PAGE_SIZE. The first returned byte starts at
* page_to_phys(out_pages[0]) + (iova % PAGE_SIZE). The caller promises not
* to touch memory outside the requested iova subslice.
*
* FIXME: callers that need a DMA mapping via a sgl should create another
* interface to build the SGL efficiently
*/
int iopt_access_pages(struct io_pagetable *iopt, unsigned long iova,
		      size_t length, struct page **out_pages, bool write)
{
	unsigned long cur_iova = iova;
	unsigned long last_iova;
	struct iopt_area *area;
	int rc;

	if (!length)
		return -EINVAL;
	if (check_add_overflow(iova, length - 1, &last_iova))
		return -EOVERFLOW;

	down_read(&iopt->rwsem);
	for (area = iopt_area_iter_first(iopt, iova, last_iova); area;
	     area = iopt_area_iter_next(area, iova, last_iova)) {
		unsigned long last = min(last_iova, iopt_area_last_iova(area));
		unsigned long last_index;
		unsigned long index;

		/* Need contiguous areas in the access */
		if (iopt_area_iova(area) < cur_iova) {
			rc = -EINVAL;
			goto out_remove;
		}

		index = iopt_iova_to_index(area, cur_iova);
		last_index = iopt_iova_to_index(area, last);
		rc = iopt_pages_add_user(area->pages, index, last_index,
					 out_pages, write);
		if (rc)
			goto out_remove;
		if (last == last_iova)
			break;
		/*
		 * Can't cross areas that are not aligned to the system page
		 * size with this API.
		 */
		if (cur_iova % PAGE_SIZE) {
			rc = -EINVAL;
			goto out_remove;
		}
		cur_iova = last + 1;
		out_pages += last_index - index;
		atomic_inc(&area->num_users);
	}

	up_read(&iopt->rwsem);
	return 0;

out_remove:
	if (cur_iova != iova)
		iopt_unaccess_pages(iopt, iova, cur_iova - iova);
	return rc;
}

/**
 * iopt_unaccess_pages - Undo iopt_access_pages
 *
 * Return the struct page's. The caller must stop accessing them before calling
 * this.
 */
void iopt_unaccess_pages(struct io_pagetable *iopt, unsigned long iova,
			 size_t length)
{
	unsigned long cur_iova = iova;
	unsigned long last_iova;
	struct iopt_area *area;

	if (WARN_ON(!length) ||
	    WARN_ON(check_add_overflow(iova, length - 1, &last_iova)))
		return;

	down_read(&iopt->rwsem);
	for (area = iopt_area_iter_first(iopt, iova, last_iova); area;
	     area = iopt_area_iter_next(area, iova, last_iova)) {
		unsigned long last = min(last_iova, iopt_area_last_iova(area));
		int num_users;

		iopt_pages_remove_user(area->pages,
				       iopt_iova_to_index(area, cur_iova),
				       iopt_iova_to_index(area, last));
		if (last == last_iova)
			break;
		cur_iova = last + 1;
		num_users = atomic_dec_return(&area->num_users);
		WARN_ON(num_users < 0);
	}
	up_read(&iopt->rwsem);
}

struct iopt_reserved_iova {
	struct interval_tree_node node;
	void *owner;
};

int iopt_reserve_iova(struct io_pagetable *iopt, unsigned long start,
		      unsigned long last, void *owner)
{
	struct iopt_reserved_iova *reserved;

	reserved = kzalloc(sizeof(*reserved), GFP_KERNEL);
	if (!reserved)
		return -ENOMEM;
	reserved->node.start = start;
	reserved->node.last = last;
	reserved->owner = owner;
	interval_tree_insert(&reserved->node, &iopt->reserved_iova_itree);
	return 0;
}

void iopt_remove_reserved_iova(struct io_pagetable *iopt, void *owner)
{

	struct interval_tree_node *node;

	for (node = interval_tree_iter_first(&iopt->reserved_iova_itree, 0,
					     ULONG_MAX);
	     node;) {
		struct iopt_reserved_iova *reserved =
			container_of(node, struct iopt_reserved_iova, node);

		node = interval_tree_iter_next(node, 0, ULONG_MAX);

		if (reserved->owner == owner) {
			interval_tree_remove(&reserved->node,
					     &iopt->reserved_iova_itree);
			kfree(reserved);
		}
	}
}

int iopt_init_table(struct io_pagetable *iopt)
{
	init_rwsem(&iopt->rwsem);
	iopt->area_itree = RB_ROOT_CACHED;
	iopt->reserved_iova_itree = RB_ROOT_CACHED;
	xa_init(&iopt->domains);

	/*
	 * iopt's start as SW tables that can use the entire size_t IOVA space
	 * due to the use of size_t in the APIs. They have no alignment
	 * restriction.
	 */
	iopt->iova_alignment = 1;

	return 0;
}

void iopt_destroy_table(struct io_pagetable *iopt)
{
	iopt_remove_reserved_iova(iopt, NULL);
	WARN_ON(!RB_EMPTY_ROOT(&iopt->reserved_iova_itree.rb_root));
	WARN_ON(!xa_empty(&iopt->domains));
	WARN_ON(!RB_EMPTY_ROOT(&iopt->area_itree.rb_root));
}

/* All existing area's conform to an increased page size */
static int iopt_check_iova_alignment(struct io_pagetable *iopt,
				     unsigned long new_iova_alignment)
{
	struct iopt_area *area;

	lockdep_assert_held(&iopt->rwsem);

	for (area = iopt_area_iter_first(iopt, 0, ULONG_MAX); area;
	     area = iopt_area_iter_next(area, 0, ULONG_MAX))
		if ((iopt_area_iova(area) % new_iova_alignment) ||
		    (iopt_area_length(area) % new_iova_alignment))
			return -EADDRINUSE;
	return 0;
}

static void iopt_unpopulate_domain(struct io_pagetable *iopt,
				   struct iommu_domain *domain)
{
	struct iopt_area *area;

	/*
	 * Some other domain is holding all the pfns still, rapidly unmap this
	 * domain.
	 */
	if (iopt->next_domain_id != 0) {
		struct interval_tree_span_iter span;

		for (interval_tree_span_iter_first(&span, &iopt->area_itree, 0,
						   ULONG_MAX);
		     !interval_tree_span_iter_done(&span);
		     interval_tree_span_iter_next(&span))
			if (!span.is_hole)
				iommu_unmap_nofail(domain, span.start_used,
						   span.last_used -
							   span.start_used + 1);
		return;
	}

	for (area = iopt_area_iter_first(iopt, 0, ULONG_MAX); area;
	     area = iopt_area_iter_next(area, 0, ULONG_MAX)) {
		struct iopt_pages *pages = area->pages;

		mutex_lock(&pages->mutex);
		interval_tree_remove(&area->pages_node,
				     &area->pages->domains_itree);
		iopt_area_unfill_whole_domain(area, domain);
		mutex_unlock(&pages->mutex);
	}
}

static int iopt_populate_new_domain(struct io_pagetable *iopt,
				    struct iommu_domain *domain)
{
	struct iopt_area *end_area;
	struct iopt_area *area;
	int rc;

	for (area = iopt_area_iter_first(iopt, 0, ULONG_MAX); area;
	     area = iopt_area_iter_next(area, 0, ULONG_MAX)) {
		mutex_lock(&area->pages->mutex);
		rc = iopt_area_fill_domain(area, domain);
		if (rc) {
			mutex_unlock(&area->pages->mutex);
			goto out_unfill;
		}
		if (iopt->next_domain_id == 0)
			interval_tree_insert(&area->pages_node,
					     &area->pages->domains_itree);
		mutex_unlock(&area->pages->mutex);
	}
	return 0;

out_unfill:
	end_area = area;
	for (area = iopt_area_iter_first(iopt, 0, ULONG_MAX); area;
	     area = iopt_area_iter_next(area, 0, ULONG_MAX)) {
		if (area == end_area)
			break;
		mutex_lock(&area->pages->mutex);
		if (iopt->next_domain_id == 0)
			interval_tree_remove(&area->pages_node,
					     &area->pages->domains_itree);
		iopt_area_unfill_whole_domain(area, domain);
		mutex_unlock(&area->pages->mutex);
	}
	return rc;
}

int iopt_table_add_domain(struct io_pagetable *iopt,
			  struct iommu_domain *domain)
{
	const struct iommu_domain_geometry *geometry = &domain->geometry;
	struct iommu_domain *iter_domain;
	unsigned int new_iova_alignment;
	unsigned long index;
	int rc;

	lockdep_assert_held_write(&iopt->rwsem);

	xa_for_each (&iopt->domains, index, iter_domain)
		if (WARN_ON(iter_domain == domain))
			return -EEXIST;

	/*
	 * The io page size drives the iova_alignment. Internally the iopt_pages
	 * works in PAGE_SIZE units and we adjust when mapping sub-PAGE_SIZE
	 * objects into the iommu_domina.
	 *
	 * A iommu_domain must always be able to accept PAGE_SIZE to be
	 * compatible as we can't guarentee higher contiguity.
	 */
	new_iova_alignment =
		max_t(unsigned long, 1UL << __ffs(domain->pgsize_bitmap),
		      iopt->iova_alignment);
	if (new_iova_alignment > PAGE_SIZE)
		return -EINVAL;
	if (new_iova_alignment != iopt->iova_alignment) {
		rc = iopt_check_iova_alignment(iopt, new_iova_alignment);
		if (rc)
			return rc;
	}

	/* No area exists that is outside the allowed domain aperture */
	if (geometry->aperture_start != 0) {
		if (iopt_area_iter_first(iopt, 0, geometry->aperture_start - 1))
			return -EADDRINUSE;
		rc = iopt_reserve_iova(iopt, 0, geometry->aperture_start - 1,
				       domain);
		if (rc)
			goto out_reserved;
	}
	if (geometry->aperture_end != ULONG_MAX) {
		if (iopt_area_iter_first(iopt, geometry->aperture_end + 1,
					 ULONG_MAX))
			return -EADDRINUSE;
		rc = iopt_reserve_iova(iopt, geometry->aperture_end + 1,
				       ULONG_MAX, domain);
		if (rc)
			goto out_reserved;
	}

	rc = xa_reserve(&iopt->domains, iopt->next_domain_id, GFP_KERNEL);
	if (rc)
		goto out_reserved;

	rc = iopt_populate_new_domain(iopt, domain);
	if (rc)
		goto out_release;

	iopt->iova_alignment = new_iova_alignment;
	xa_store(&iopt->domains, iopt->next_domain_id, domain,
			     GFP_KERNEL);
	iopt->next_domain_id++;
	return 0;
out_release:
	xa_release(&iopt->domains, iopt->next_domain_id);
out_reserved:
	iopt_remove_reserved_iova(iopt, domain);
	return rc;
}

void iopt_table_remove_domain(struct io_pagetable *iopt,
			      struct iommu_domain *domain)
{
	struct iommu_domain *iter_domain = NULL;
	unsigned long new_iova_alignment;
	unsigned long index;

	lockdep_assert_held_write(&iopt->rwsem);

	xa_for_each(&iopt->domains, index, iter_domain)
		if (iter_domain == domain)
			break;
	if (WARN_ON(iter_domain != domain) || index >= iopt->next_domain_id)
		return;

	/*
	 * Compress the xarray to keep it linear by swapping the entry to erase
	 * with the tail entry and shrinking the tail.
	 */
	iopt->next_domain_id--;
	iter_domain = xa_erase(&iopt->domains, iopt->next_domain_id);
	if (index != iopt->next_domain_id)
		xa_store(&iopt->domains, index, iter_domain, GFP_KERNEL);

	iopt_unpopulate_domain(iopt, domain);
	iopt_remove_reserved_iova(iopt, domain);

	/* Recalculate the iova alingment without the domain */
	new_iova_alignment = 1;
	xa_for_each (&iopt->domains, index, iter_domain)
		new_iova_alignment = max_t(unsigned long,
					   1UL << __ffs(domain->pgsize_bitmap),
					   new_iova_alignment);
	if (!WARN_ON(new_iova_alignment > iopt->iova_alignment))
		iopt->iova_alignment = new_iova_alignment;
}

/* Narrow the valid_iova_itree to include reserved ranges from a group. */
int iopt_table_enforce_group_iova(struct io_pagetable *iopt,
				  struct iommu_group *group)
{
	struct iommu_resv_region *resv;
	LIST_HEAD(group_resv_regions);
	int rc;

	down_write(&iopt->rwsem);
	rc = iommu_get_group_resv_regions(group, &group_resv_regions);
	if (rc)
		goto out_unlock;

	list_for_each_entry (resv, &group_resv_regions, list) {
		if (resv->type == IOMMU_RESV_DIRECT_RELAXABLE)
			continue;
		if (iopt_area_iter_first(iopt, resv->start,
					 resv->length - 1 + resv->start)) {
			rc = -EADDRINUSE;
			goto out_reserved;
		}
		rc = iopt_reserve_iova(iopt, resv->start,
				       resv->length - 1 + resv->start, group);
		if (rc)
			goto out_reserved;
	}
	rc = 0;
	goto out_free_resv;

out_reserved:
	iopt_remove_reserved_iova(iopt, group);
out_free_resv:
	while ((resv = list_first_entry_or_null(
			&group_resv_regions, struct iommu_resv_region, list))) {
		list_del(&resv->list);
		kfree(resv);
	}
out_unlock:
	up_write(&iopt->rwsem);
	return rc;
}
