/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES.
 */
#ifndef _UAPI_IOMMUFD_H
#define _UAPI_IOMMUFD_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define IOMMUFD_TYPE (';')

/**
 * DOC: General ioctl format
 *
 * The ioctl mechanims follows a general format to allow for extensibility. Each
 * ioctl is passed in a structure pointer as the argument providing the size of
 * the structure in the first u32. The kernel checks that any structure space
 * beyond what it understands is 0. This allows userspace to use the backward
 * compatible portion while consistently using the newer, larger, structures.
 *
 * ioctls use a standard meaning for common errnos:
 *
 *  - ENOTTY: The IOCTL number itself is not supported at all
 *  - E2BIG: The IOCTL number is supported, but the provided structure has
 *    non-zero in a part the kernel does not understand.
 *  - EOPNOTSUPP: The IOCTL number is supported, and the structure is
 *    understood, however a known field has a value the kernel does not
 *    understand or support.
 *  - EINVAL: Everything about the IOCTL was understood, but a field is not
 *    correct.
 *  - ENOENT: An ID or IOVA provided does not exist.
 *  - ENOMEM: Out of memory.
 *  - EOVERFLOW: Mathematics oveflowed.
 *
 * As well as additional errnos. within specific ioctls.
 */
enum {
	IOMMUFD_CMD_BASE = 0x80,
	IOMMUFD_CMD_DESTROY = IOMMUFD_CMD_BASE,
	IOMMUFD_CMD_IOAS_ALLOC,
	IOMMUFD_CMD_IOAS_IOVA_RANGES,
	IOMMUFD_CMD_IOAS_MAP,
	IOMMUFD_CMD_IOAS_COPY,
	IOMMUFD_CMD_IOAS_UNMAP,
	IOMMUFD_CMD_VFIO_IOAS,
	IOMMUFD_CMD_DEVICE_GET_INFO,
	IOMMUFD_CMD_HWPT_ALLOC,
};

/**
 * struct iommu_destroy - ioctl(IOMMU_DESTROY)
 * @size: sizeof(struct iommu_destroy)
 * @id: iommufd object ID to destroy. Can by any destroyable object type.
 *
 * Destroy any object held within iommufd.
 */
struct iommu_destroy {
	__u32 size;
	__u32 id;
};
#define IOMMU_DESTROY _IO(IOMMUFD_TYPE, IOMMUFD_CMD_DESTROY)

/**
 * struct iommu_ioas_alloc - ioctl(IOMMU_IOAS_ALLOC)
 * @size: sizeof(struct iommu_ioas_alloc)
 * @flags: Must be 0
 * @out_ioas_id: Output IOAS ID for the allocated object
 *
 * Allocate an IO Address Space (IOAS) which holds an IO Virtual Address (IOVA)
 * to memory mapping.
 */
struct iommu_ioas_alloc {
	__u32 size;
	__u32 flags;
	__u32 out_ioas_id;
};
#define IOMMU_IOAS_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_ALLOC)

/**
 * struct iommu_ioas_iova_ranges - ioctl(IOMMU_IOAS_IOVA_RANGES)
 * @size: sizeof(struct iommu_ioas_iova_ranges)
 * @ioas_id: IOAS ID to read ranges from
 * @out_num_iovas: Output total number of ranges in the IOAS
 * @__reserved: Must be 0
 * @out_valid_iovas: Array of valid IOVA ranges. The array length is the smaller
 *                   of out_num_iovas or the length implied by size.
 * @out_valid_iovas.start: First IOVA in the allowed range
 * @out_valid_iovas.last: Inclusive last IOVA in the allowed range
 *
 * Query an IOAS for ranges of allowed IOVAs. Operation outside these ranges is
 * not allowed. out_num_iovas will be set to the total number of iovas
 * and the out_valid_iovas[] will be filled in as space permits.
 * size should include the allocated flex array.
 */
struct iommu_ioas_iova_ranges {
	__u32 size;
	__u32 ioas_id;
	__u32 out_num_iovas;
	__u32 __reserved;
	struct iommu_valid_iovas {
		__aligned_u64 start;
		__aligned_u64 last;
	} out_valid_iovas[];
};
#define IOMMU_IOAS_IOVA_RANGES _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_IOVA_RANGES)

/**
 * enum iommufd_ioas_map_flags - Flags for map and copy
 * @IOMMU_IOAS_MAP_FIXED_IOVA: If clear the kernel will compute an appropriate
 *                             IOVA to place the mapping at
 * @IOMMU_IOAS_MAP_WRITEABLE: DMA is allowed to write to this mapping
 * @IOMMU_IOAS_MAP_READABLE: DMA is allowed to read from this mapping
 */
enum iommufd_ioas_map_flags {
	IOMMU_IOAS_MAP_FIXED_IOVA = 1 << 0,
	IOMMU_IOAS_MAP_WRITEABLE = 1 << 1,
	IOMMU_IOAS_MAP_READABLE = 1 << 2,
};

/**
 * struct iommu_ioas_map - ioctl(IOMMU_IOAS_MAP)
 * @size: sizeof(struct iommu_ioas_map)
 * @flags: Combination of enum iommufd_ioas_map_flags
 * @ioas_id: IOAS ID to change the mapping of
 * @__reserved: Must be 0
 * @user_va: Userspace pointer to start mapping from
 * @length: Number of bytes to map
 * @iova: IOVA the mapping was placed at. If IOMMU_IOAS_MAP_FIXED_IOVA is set
 *        then this must be provided as input.
 *
 * Set an IOVA mapping from a user pointer. If FIXED_IOVA is specified then the
 * mapping will be established at iova, otherwise a suitable location will be
 * automatically selected and returned in iova.
 */
struct iommu_ioas_map {
	__u32 size;
	__u32 flags;
	__u32 ioas_id;
	__u32 __reserved;
	__aligned_u64 user_va;
	__aligned_u64 length;
	__aligned_u64 iova;
};
#define IOMMU_IOAS_MAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_MAP)

/**
 * struct iommu_ioas_copy - ioctl(IOMMU_IOAS_COPY)
 * @size: sizeof(struct iommu_ioas_copy)
 * @flags: Combination of enum iommufd_ioas_map_flags
 * @dst_ioas_id: IOAS ID to change the mapping of
 * @src_ioas_id: IOAS ID to copy from
 * @length: Number of bytes to copy and map
 * @dst_iova: IOVA the mapping was placed at. If IOMMU_IOAS_MAP_FIXED_IOVA is
 *            set then this must be provided as input.
 * @src_iova: IOVA to start the copy
 *
 * Copy an already existing mapping from src_ioas_id and establish it in
 * dst_ioas_id. The src iova/length must exactly match a range used with
 * IOMMU_IOAS_MAP.
 */
struct iommu_ioas_copy {
	__u32 size;
	__u32 flags;
	__u32 dst_ioas_id;
	__u32 src_ioas_id;
	__aligned_u64 length;
	__aligned_u64 dst_iova;
	__aligned_u64 src_iova;
};
#define IOMMU_IOAS_COPY _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_COPY)

/**
 * struct iommu_ioas_unmap - ioctl(IOMMU_IOAS_UNMAP)
 * @size: sizeof(struct iommu_ioas_copy)
 * @ioas_id: IOAS ID to change the mapping of
 * @iova: IOVA to start the unmapping at
 * @length: Number of bytes to unmap, and return back the bytes unmapped
 *
 * Unmap an IOVA range. The iova/length must exactly match a range
 * used with IOMMU_IOAS_PAGETABLE_MAP, or be the values 0 & U64_MAX.
 * In the latter case all IOVAs will be unmaped.
 */
struct iommu_ioas_unmap {
	__u32 size;
	__u32 ioas_id;
	__aligned_u64 iova;
	__aligned_u64 length;
};
#define IOMMU_IOAS_UNMAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_UNMAP)

/**
 * enum iommufd_vfio_ioas_op
 * @IOMMU_VFIO_IOAS_GET: Get the current compatibility IOAS
 * @IOMMU_VFIO_IOAS_SET: Change the current compatibility IOAS
 * @IOMMU_VFIO_IOAS_CLEAR: Disable VFIO compatibility
 */
enum iommufd_vfio_ioas_op {
	IOMMU_VFIO_IOAS_GET = 0,
	IOMMU_VFIO_IOAS_SET = 1,
	IOMMU_VFIO_IOAS_CLEAR = 2,
};

/**
 * struct iommu_vfio_ioas - ioctl(IOMMU_VFIO_IOAS)
 * @size: sizeof(struct iommu_ioas_copy)
 * @ioas_id: For IOMMU_VFIO_IOAS_SET the input IOAS ID to set
 *           For IOMMU_VFIO_IOAS_GET will output the IOAS ID
 * @op: One of enum iommufd_vfio_ioas_op
 * @__reserved: Must be 0
 *
 * The VFIO compatibility support uses a single ioas because VFIO APIs do not
 * support the ID field. Set or Get the IOAS that VFIO compatibility will use.
 * When VFIO_GROUP_SET_CONTAINER is used on an iommufd it will get the
 * compatibility ioas, either by taking what is already set, or auto creating
 * one. From then on VFIO will continue to use that ioas and is not effected by
 * this ioctl. SET or CLEAR does not destroy any auto-created IOAS.
 */
struct iommu_vfio_ioas {
	__u32 size;
	__u32 ioas_id;
	__u16 op;
	__u16 __reserved;
};
#define IOMMU_VFIO_IOAS _IO(IOMMUFD_TYPE, IOMMUFD_CMD_VFIO_IOAS)

/*
 * struct iommu_vtd_data - Intel VT-d hardware data
 *
 * @flags: VT-d specific flags. Currently reserved for future
 *	   extension. must be set to 0.
 * @cap_reg: Describe basic capabilities as defined in VT-d capability
 *	     register.
 * @ecap_reg: Describe the extended capabilities as defined in VT-d
 *	      extended capability register.
 */
struct iommu_vtd_data {
	__u32 flags;
	__u8 padding[32];
	__aligned_u64 cap_reg;
	__aligned_u64 ecap_reg;
};

/*
 * struct iommu_device_info - ioctl(IOMMU_DEVICE_GET_INFO)
 * @size: sizeof the whole info
 * @flags: must be 0
 * @dev_id: the device to query
 * @iommu_hw_type: physical iommu type
 * @reserved: must be 0
 * @hw_data_ptr_len: length of hw data
 * @hw_data_ptr: pointer to hw data area
 */
enum iommu_hw_type {
	IOMMU_DRIVER_INTEL_V1,
	IOMMU_DRIVER_ARM_V1,
};

struct iommu_device_info {
	__u32 size;
	__u32 flags;
	__u32 dev_id;
	__u32 iommu_hw_type;
	__u32 reserved;
	__u32 hw_data_ptr_len;
	__aligned_u64 hw_data_ptr;
};
#define IOMMU_DEVICE_GET_INFO _IO(IOMMUFD_TYPE, IOMMUFD_CMD_DEVICE_GET_INFO)

/**
 * struct iommu_stage1_config_vtd - Intel VT-d specific data on user managed pgtbl
 *
 * @flags:	VT-d PASID table entry attributes
 * @pat:	Page attribute table data to compute effective memory type
 * @emt:	Extended memory type
 * @addr_width: the user managed page table input address width
 *
 * Only guest vIOMMU selectable and effective options are passed down to
 * the host IOMMU.
 */
struct iommu_stage1_config_vtd {
#define IOMMU_VTD_PGTBL_SRE	(1 << 0) /* supervisor request */
#define IOMMU_VTD_PGTBL_EAFE	(1 << 1) /* extended access enable */
#define IOMMU_VTD_PGTBL_PCD	(1 << 2) /* page-level cache disable */
#define IOMMU_VTD_PGTBL_PWT	(1 << 3) /* page-level write through */
#define IOMMU_VTD_PGTBL_EMTE	(1 << 4) /* extended mem type enable */
#define IOMMU_VTD_PGTBL_CD	(1 << 5) /* PASID-level cache disable */
#define IOMMU_VTD_PGTBL_WPE	(1 << 6) /* Write protect enable */
#define IOMMU_VTD_PGTBL_LAST	(1 << 7)
	__u64 flags;
	__u32 pat;
	__u32 emt;
	__u32 addr_width;
	__u32 __reserved;
};

#define IOMMU_VTD_PGTBL_MTS_MASK	(IOMMU_VTD_PGTBL_CD | \
					 IOMMU_VTD_PGTBL_EMTE | \
					 IOMMU_VTD_PGTBL_PCD |  \
					 IOMMU_VTD_PGTBL_PWT)

union iommu_stage1_config {
	struct iommu_stage1_config_vtd vtd;
};

/**
 * struct iommu_hwpt_alloc - ioctl(IOMMU_HWPT_ALLOC)
 * @size: sizeof(struct iommu_hwpt_alloc)
 * @flags: Must be 0
 * @parent_hwpt_id: hwpt ID for the parent object
 * @out_hwpt_id: Output hwpt ID for the allocated object
 * @stage1_ptr: the stage1 (a.k.a user managed page table) pointer.
		       This pointer should be subjected to stage2 translation.
 * @config: vendor specific stage1 configurations
 *
 * Allocate a hardware page table which holds an I/O page table
 */
struct iommu_hwpt_alloc {
	__u32 size;
	__u32 flags;
	__u32 parent_hwpt_id;
	__u32 out_hwpt_id;
	__aligned_u64 stage1_ptr;
	/* Vendor specific data */
	union iommu_stage1_config config;
};
#define IOMMU_HWPT_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_ALLOC)

#endif
