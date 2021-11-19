// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES.
 */
#ifndef _UAPI_IOMMUFD_TEST_H
#define _UAPI_IOMMUFD_TEST_H

#include <linux/types.h>
#include <linux/iommufd.h>

enum {
	IOMMU_TEST_OP_ADD_RESERVED,
	IOMMU_TEST_OP_MOCK_DOMAIN,
	IOMMU_TEST_OP_MD_CHECK_MAP,
	IOMMU_TEST_OP_MD_CHECK_REFS,
};

enum {
	MOCK_APERTURE_START = 1UL << 24,
	MOCK_APERTURE_LAST = (1UL << 31) - 1,
};

struct iommu_test_cmd {
	__u32 size;
	__u32 op;
	__u32 id;
	union {
		struct {
			__aligned_u64 start;
			__aligned_u64 length;
		} add_reserved;
		struct {
			__aligned_u64 iova;
			__aligned_u64 length;
			__aligned_u64 uptr;
		} check_map;
		struct {
			__aligned_u64 length;
			__aligned_u64 uptr;
			__u32 refs;
		} check_refs;
	};
	__u32 last;
};
#define IOMMU_TEST_CMD _IO(IOMMUFD_TYPE, IOMMUFD_CMD_BASE + 32)

#endif
