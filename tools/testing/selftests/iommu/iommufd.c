// SPDX-License-Identifier: GPL-2.0-only
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <assert.h>

#include "../kselftest_harness.h"

#define __EXPORTED_HEADERS__
#include <linux/iommufd.h>
#include "../../../../drivers/iommu/iommufd/iommufd_test.h"

enum { BUFFER_SIZE = 64 * 1024 };
static void *buffer;

static unsigned long PAGE_SIZE;
static __attribute__((constructor)) void setup_page_size(void)
{
	int rc;

	PAGE_SIZE = sysconf(_SC_PAGE_SIZE);
	rc = posix_memalign(&buffer, BUFFER_SIZE, BUFFER_SIZE);
	assert(rc || (uintptr_t)buffer % PAGE_SIZE == 0);
}

#define MOCK_PAGE_SIZE (PAGE_SIZE / 2)

/*
 * Have the kernel check the refcount on pages. I don't know why a freshly
 * mmap'd anon non-compound page starts out with a ref of 3
 */
#define check_refs(_ptr, _length, _refs)                                       \
	({                                                                     \
		struct iommu_test_cmd test_cmd = {                             \
			.size = sizeof(test_cmd),                              \
			.op = IOMMU_TEST_OP_MD_CHECK_REFS,                     \
			.check_refs = { .length = _length,                     \
					.uptr = (uintptr_t)(_ptr),             \
					.refs = _refs },                       \
		};                                                             \
		ASSERT_EQ(0,                                                   \
			  ioctl(self->fd,                                      \
				_IOMMU_TEST_CMD(IOMMU_TEST_OP_MD_CHECK_REFS),  \
				&test_cmd));                                   \
	})

/* Hack to make assertions more readable */
#define _IOMMU_TEST_CMD(x) IOMMU_TEST_CMD

#define EXPECT_ERRNO(expected_errno, cmd)                                      \
	({                                                                     \
		ASSERT_EQ(-1, cmd);                                            \
		EXPECT_EQ(expected_errno, errno);                              \
	})

FIXTURE(iommufd) {
	int fd;
};

FIXTURE_SETUP(iommufd) {
	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
}

FIXTURE_TEARDOWN(iommufd) {
	ASSERT_EQ(0, close(self->fd));
}

TEST_F(iommufd, simple_close)
{
}

TEST_F(iommufd, cmd_fail)
{
	struct iommu_destroy cmd = { .size = sizeof(cmd), .id = 0 };

	/* object id is invalid */
	EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_DESTROY, &cmd));
	/* Bad pointer */
	EXPECT_ERRNO(EFAULT, ioctl(self->fd, IOMMU_DESTROY, NULL));
	/* Unknown ioctl */
	EXPECT_ERRNO(ENOTTY,
		     ioctl(self->fd, _IO(IOMMUFD_TYPE, IOMMUFD_CMD_BASE - 1),
			   &cmd));
}

TEST_F(iommufd, cmd_ex_fail)
{
	struct {
		struct iommu_destroy cmd;
		__u64 future;
	} cmd = { .cmd = { .size = sizeof(cmd), .id = 0 } };

	/* object id is invalid and command is longer */
	EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_DESTROY, &cmd));
	/* future area is non-zero */
	cmd.future = 1;
	EXPECT_ERRNO(E2BIG, ioctl(self->fd, IOMMU_DESTROY, &cmd));
	/* Original command "works" */
	cmd.cmd.size = sizeof(cmd.cmd);
	EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_DESTROY, &cmd));
	/* Short command fails */
	cmd.cmd.size = sizeof(cmd.cmd) - 1;
	EXPECT_ERRNO(EOPNOTSUPP, ioctl(self->fd, IOMMU_DESTROY, &cmd));
}

FIXTURE(iommufd_ioas) {
	int fd;
	uint32_t ioas_id;
	uint32_t domain_id;
	uint64_t base_iova;
};

FIXTURE_VARIANT(iommufd_ioas) {
	unsigned int mock_domains;
};

FIXTURE_SETUP(iommufd_ioas) {
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};
	unsigned int i;

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	self->ioas_id = alloc_cmd.out_ioas_id;

	for (i = 0; i != variant->mock_domains; i++) {
		struct iommu_test_cmd test_cmd = {
			.size = sizeof(test_cmd),
			.op = IOMMU_TEST_OP_MOCK_DOMAIN,
			.id = self->ioas_id,
		};

		ASSERT_EQ(0, ioctl(self->fd,
				   _IOMMU_TEST_CMD(IOMMU_TEST_OP_MOCK_DOMAIN),
				   &test_cmd));
		EXPECT_NE(0, test_cmd.id);
		self->domain_id = test_cmd.id;
		self->base_iova = MOCK_APERTURE_START;
	}
}

FIXTURE_TEARDOWN(iommufd_ioas) {
	ASSERT_EQ(0, close(self->fd));

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	check_refs(buffer, BUFFER_SIZE, 0);
	ASSERT_EQ(0, close(self->fd));
}

FIXTURE_VARIANT_ADD(iommufd_ioas, no_domain) {
};

FIXTURE_VARIANT_ADD(iommufd_ioas, mock_domain) {
	.mock_domains = 1
};

FIXTURE_VARIANT_ADD(iommufd_ioas, two_mock_domain) {
	.mock_domains = 2
};

TEST_F(iommufd_ioas, ioas_auto_destroy)
{
}

TEST_F(iommufd_ioas, ioas_destroy)
{
	struct iommu_destroy destroy_cmd = {
		.size = sizeof(destroy_cmd),
		.id = self->ioas_id,
	};

	if (self->domain_id) {
		/* IOAS cannot be freed while a domain is on it */
		EXPECT_ERRNO(EBUSY,
			     ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	} else {
		/* Can allocate and manually free an IOAS table */
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	}
}

TEST_F(iommufd_ioas, ioas_area_destroy)
{
	struct iommu_destroy destroy_cmd = {
		.size = sizeof(destroy_cmd),
		.id = self->ioas_id,
	};
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.ioas_id = self->ioas_id,
		.user_va = (uintptr_t)buffer,
		.length = PAGE_SIZE,
		.iova = self->base_iova,
	};

	/* Adding an area does not change ability to destroy */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	if (self->domain_id)
		EXPECT_ERRNO(EBUSY,
			     ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
	else
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
}

TEST_F(iommufd_ioas, ioas_area_auto_destroy)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.ioas_id = self->ioas_id,
		.user_va = (uintptr_t)buffer,
		.length = PAGE_SIZE,
	};
	int i;

	/* Can allocate and automatically free an IOAS table with many areas */
	for (i = 0; i != 10; i++) {
		map_cmd.iova = self->base_iova + i * PAGE_SIZE;
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	}
}

TEST_F(iommufd_ioas, area)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.length = PAGE_SIZE,
		.user_va = (uintptr_t)buffer,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
	};
	int i;

	/* Unmap fails if nothing is mapped */
	for (i = 0; i != 10; i++) {
		unmap_cmd.iova = i * PAGE_SIZE;
		EXPECT_ERRNO(ENOENT, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
					   &unmap_cmd));
	}

	/* Unmap works */
	for (i = 0; i != 10; i++) {
		map_cmd.iova = self->base_iova + i * PAGE_SIZE;
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.iova = self->base_iova + i * PAGE_SIZE;
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}

	/* Split fails */
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = self->base_iova + 16 * PAGE_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	unmap_cmd.iova = self->base_iova + 16 * PAGE_SIZE;
	EXPECT_ERRNO(ENOENT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));
	unmap_cmd.iova = self->base_iova + 17 * PAGE_SIZE;
	EXPECT_ERRNO(ENOENT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));

	/* Over map fails */
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = self->base_iova + 16 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE;
	map_cmd.iova = self->base_iova + 16 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE;
	map_cmd.iova = self->base_iova + 17 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE * 2;
	map_cmd.iova = self->base_iova + 15 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	map_cmd.length = PAGE_SIZE * 3;
	map_cmd.iova = self->base_iova + 15 * PAGE_SIZE;
	EXPECT_ERRNO(EADDRINUSE,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));

	/* unmap all works */
	unmap_cmd.iova = 0;
	unmap_cmd.length = UINT64_MAX;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap_cmd));
}

TEST_F(iommufd_ioas, area_auto_iova)
{
	struct iommu_test_cmd test_cmd = {
		.size = sizeof(test_cmd),
		.op = IOMMU_TEST_OP_ADD_RESERVED,
		.id = self->ioas_id,
		.add_reserved = { .start = PAGE_SIZE * 4,
				  .length = PAGE_SIZE * 100 },
	};
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
		.user_va = (uintptr_t)buffer,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
	};
	uint64_t iovas[10];
	int i;

	/* Simple 4k pages */
	for (i = 0; i != 10; i++) {
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
		iovas[i] = map_cmd.iova;
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.iova = iovas[i];
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}

	/* Kernel automatically aligns IOVAs properly */
	if (self->domain_id)
		map_cmd.user_va = (uintptr_t)buffer;
	else
		map_cmd.user_va = 1UL << 31;
	for (i = 0; i != 10; i++) {
		map_cmd.length = PAGE_SIZE * (i + 1);
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
		iovas[i] = map_cmd.iova;
		EXPECT_EQ(0, map_cmd.iova % (1UL << (ffs(map_cmd.length)-1)));
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.length = PAGE_SIZE * (i + 1);
		unmap_cmd.iova = iovas[i];
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}

	/* Avoids a reserved region */
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ADD_RESERVED),
			&test_cmd));
	for (i = 0; i != 10; i++) {
		map_cmd.length = PAGE_SIZE * (i + 1);
		ASSERT_EQ(0,
			  ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
		iovas[i] = map_cmd.iova;
		EXPECT_EQ(0, map_cmd.iova % (1UL << (ffs(map_cmd.length)-1)));
		EXPECT_EQ(false,
			  map_cmd.iova > test_cmd.add_reserved.start &&
				  map_cmd.iova <
					  test_cmd.add_reserved.start +
						  test_cmd.add_reserved.length);
	}
	for (i = 0; i != 10; i++) {
		unmap_cmd.length = PAGE_SIZE * (i + 1);
		unmap_cmd.iova = iovas[i];
		ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
				   &unmap_cmd));
	}
}

TEST_F(iommufd_ioas, copy_area)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.length = PAGE_SIZE,
		.user_va = (uintptr_t)buffer,
	};
	struct iommu_ioas_pagetable_copy copy_cmd = {
		.size = sizeof(copy_cmd),
		.flags = IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA,
		.dst_ioas_id = self->ioas_id,
		.src_ioas_id = self->ioas_id,
		.length = PAGE_SIZE,
	};
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};

	map_cmd.iova = self->base_iova;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));

	/* Copy inside a single IOAS */
	copy_cmd.src_iova = self->base_iova;
	copy_cmd.dst_iova = self->base_iova + PAGE_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_COPY, &copy_cmd));

	/* Copy between IOAS's */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	copy_cmd.src_iova = self->base_iova;
	copy_cmd.dst_iova = 0;
	copy_cmd.dst_ioas_id = alloc_cmd.out_ioas_id;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_COPY, &copy_cmd));
}

TEST_F(iommufd_ioas, iova_ranges)
{
	struct iommu_test_cmd test_cmd = {
		.size = sizeof(test_cmd),
		.op = IOMMU_TEST_OP_ADD_RESERVED,
		.id = self->ioas_id,
		.add_reserved = { .start = PAGE_SIZE, .length = PAGE_SIZE },
	};
	struct iommu_ioas_pagetable_iova_ranges *cmd = (void *)buffer;

	*cmd = (struct iommu_ioas_pagetable_iova_ranges){
		.size = BUFFER_SIZE,
		.ioas_id = self->ioas_id,
	};

	/* Range can be read */
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	EXPECT_EQ(1, cmd->out_num_iovas);
	if (!self->domain_id) {
		EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(SIZE_MAX, cmd->out_valid_iovas[0].last);
	} else {
		EXPECT_EQ(MOCK_APERTURE_START, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(MOCK_APERTURE_LAST, cmd->out_valid_iovas[0].last);
	}
	memset(cmd->out_valid_iovas, 0,
	       sizeof(cmd->out_valid_iovas[0]) * cmd->out_num_iovas);

	/* Buffer too small */
	cmd->size = sizeof(*cmd);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	EXPECT_EQ(1, cmd->out_num_iovas);
	EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
	EXPECT_EQ(0, cmd->out_valid_iovas[0].last);

	/* 2 ranges */
	ASSERT_EQ(0,
		  ioctl(self->fd, _IOMMU_TEST_CMD(IOMMU_TEST_OP_ADD_RESERVED),
			&test_cmd));
	cmd->size = BUFFER_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	if (!self->domain_id) {
		EXPECT_EQ(2, cmd->out_num_iovas);
		EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(PAGE_SIZE - 1, cmd->out_valid_iovas[0].last);
		EXPECT_EQ(PAGE_SIZE * 2, cmd->out_valid_iovas[1].start);
		EXPECT_EQ(SIZE_MAX, cmd->out_valid_iovas[1].last);
	} else {
		EXPECT_EQ(1, cmd->out_num_iovas);
		EXPECT_EQ(MOCK_APERTURE_START, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(MOCK_APERTURE_LAST, cmd->out_valid_iovas[0].last);
	}
	memset(cmd->out_valid_iovas, 0,
	       sizeof(cmd->out_valid_iovas[0]) * cmd->out_num_iovas);

	/* Buffer too small */
	cmd->size = sizeof(*cmd) + sizeof(cmd->out_valid_iovas[0]);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, cmd));
	if (!self->domain_id) {
		EXPECT_EQ(2, cmd->out_num_iovas);
		EXPECT_EQ(0, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(PAGE_SIZE - 1, cmd->out_valid_iovas[0].last);
	} else {
		EXPECT_EQ(1, cmd->out_num_iovas);
		EXPECT_EQ(MOCK_APERTURE_START, cmd->out_valid_iovas[0].start);
		EXPECT_EQ(MOCK_APERTURE_LAST, cmd->out_valid_iovas[0].last);
	}
	EXPECT_EQ(0, cmd->out_valid_iovas[1].start);
	EXPECT_EQ(0, cmd->out_valid_iovas[1].last);
}

FIXTURE(iommufd_mock_domain) {
	int fd;
	uint32_t ioas_id;
	uint32_t domain_id;
	uint32_t domain_ids[2];
};

FIXTURE_VARIANT(iommufd_mock_domain) {
	unsigned int mock_domains;
};

FIXTURE_SETUP(iommufd_mock_domain)
{
	struct iommu_ioas_pagetable_alloc alloc_cmd = {
		.size = sizeof(alloc_cmd),
	};
	struct iommu_test_cmd test_cmd = {
		.size = sizeof(test_cmd),
		.op = IOMMU_TEST_OP_MOCK_DOMAIN,
	};
	unsigned int i;

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_cmd));
	ASSERT_NE(0, alloc_cmd.out_ioas_id);
	self->ioas_id = alloc_cmd.out_ioas_id;

	ASSERT_GE(ARRAY_SIZE(self->domain_ids), variant->mock_domains);

	for (i = 0; i != variant->mock_domains; i++) {
		test_cmd.id = self->ioas_id;
		ASSERT_EQ(0, ioctl(self->fd,
				   _IOMMU_TEST_CMD(IOMMU_TEST_OP_MOCK_DOMAIN),
				   &test_cmd));
		EXPECT_NE(0, test_cmd.id);
		self->domain_ids[i] = test_cmd.id;
	}
	self->domain_id = self->domain_ids[0];
}

FIXTURE_TEARDOWN(iommufd_mock_domain) {
	ASSERT_EQ(0, close(self->fd));

	self->fd = open("/dev/iommu", O_RDWR);
	ASSERT_NE(-1, self->fd);
	check_refs(buffer, BUFFER_SIZE, 0);
	ASSERT_EQ(0, close(self->fd));
}

FIXTURE_VARIANT_ADD(iommufd_mock_domain, one_domain){
	.mock_domains = 1,
};

FIXTURE_VARIANT_ADD(iommufd_mock_domain, two_domains){
	.mock_domains = 2,
};

/* Have the kernel check that the user pages made it to the iommu_domain */
#define check_mock_iova(_ptr, _iova, _length)                                  \
	({                                                                     \
		struct iommu_test_cmd test_cmd = {                             \
			.size = sizeof(test_cmd),                              \
			.op = IOMMU_TEST_OP_MD_CHECK_MAP,                      \
			.id = self->domain_id,                                 \
			.check_map = { .iova = _iova,                          \
				       .length = _length,                      \
				       .uptr = (uintptr_t)(_ptr) },            \
		};                                                             \
		ASSERT_EQ(0,                                                   \
			  ioctl(self->fd,                                      \
				_IOMMU_TEST_CMD(IOMMU_TEST_OP_MD_CHECK_MAP),   \
				&test_cmd));                                   \
		if (self->domain_ids[1]) {                                     \
			test_cmd.id = self->domain_ids[1];                     \
			ASSERT_EQ(0,                                           \
				  ioctl(self->fd,                              \
					_IOMMU_TEST_CMD(                       \
						IOMMU_TEST_OP_MD_CHECK_MAP),   \
					&test_cmd));                           \
		}                                                              \
	})

TEST_F(iommufd_mock_domain, basic)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
	};
	uint8_t *buf;

	/* Simple one page map */
	map_cmd.user_va = (uintptr_t)buffer;
	map_cmd.length = PAGE_SIZE;
	ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
	check_mock_iova(buffer, map_cmd.iova, PAGE_SIZE);

	/* EFAULT half way through mapping */
	buf = mmap(0, PAGE_SIZE * 8, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(MAP_FAILED, buf);
	ASSERT_EQ(0, munmap(buf + PAGE_SIZE * 4, PAGE_SIZE * 4));
	map_cmd.user_va = (uintptr_t)buf;
	map_cmd.length = PAGE_SIZE * 8;
	EXPECT_ERRNO(EFAULT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));

	/* EFAULT on first page */
	ASSERT_EQ(0, munmap(buf, PAGE_SIZE * 4));
	EXPECT_ERRNO(EFAULT,
		     ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP, &map_cmd));
}

TEST_F(iommufd_mock_domain, all_aligns)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
	};
	size_t buf_size = PAGE_SIZE * 8;
	unsigned int start;
	unsigned int end;
	uint8_t *buf;

	buf = mmap(0, buf_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	ASSERT_NE(MAP_FAILED, buf);
	check_refs(buf, buf_size, 0);

	/*
	 * Map every combination of page size and alignment within a big region
	 */
	for (start = 0; start != buf_size - MOCK_PAGE_SIZE;
	     start += MOCK_PAGE_SIZE) {
		map_cmd.user_va = (uintptr_t)buf + start;
		for (end = start + MOCK_PAGE_SIZE; end <= buf_size;
		     end += MOCK_PAGE_SIZE) {
			map_cmd.length = end - start;
			ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP,
					   &map_cmd));
			check_mock_iova(buf + start, map_cmd.iova,
					map_cmd.length);
			check_refs(buf + start / PAGE_SIZE * PAGE_SIZE,
				   end / PAGE_SIZE * PAGE_SIZE -
					   start / PAGE_SIZE * PAGE_SIZE,
				   1);

			unmap_cmd.iova = map_cmd.iova;
			unmap_cmd.length = end - start;
			ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
					   &unmap_cmd));
		}
	}
	check_refs(buf, buf_size, 0);
	ASSERT_EQ(0, munmap(buf, buf_size));
}

TEST_F(iommufd_mock_domain, all_aligns_copy)
{
	struct iommu_ioas_pagetable_map map_cmd = {
		.size = sizeof(map_cmd),
		.ioas_id = self->ioas_id,
	};
	struct iommu_ioas_pagetable_unmap unmap_cmd = {
		.size = sizeof(unmap_cmd),
		.ioas_id = self->ioas_id,
	};
	struct iommu_test_cmd add_mock_pt = {
		.size = sizeof(add_mock_pt),
		.op = IOMMU_TEST_OP_MOCK_DOMAIN,
	};
	struct iommu_destroy destroy_cmd = {
		.size = sizeof(destroy_cmd),
	};
	size_t buf_size = PAGE_SIZE * 8;
	unsigned int start;
	unsigned int end;
	uint8_t *buf;

	buf = mmap(0, buf_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	ASSERT_NE(MAP_FAILED, buf);
	check_refs(buf, buf_size, 0);

	/* Map every combination and copy into a newly added domain */
	for (start = 0; start != buf_size - MOCK_PAGE_SIZE;
	     start += MOCK_PAGE_SIZE) {
		map_cmd.user_va = (uintptr_t)buf + start;
		for (end = start + MOCK_PAGE_SIZE; end <= buf_size;
		     end += MOCK_PAGE_SIZE) {
			unsigned int old_id;

			map_cmd.length = end - start;
			ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_MAP,
					   &map_cmd));

			/* Add and destroy a domain while the area exists */
			add_mock_pt.id = self->ioas_id;
			ASSERT_EQ(0, ioctl(self->fd,
					   _IOMMU_TEST_CMD(
						   IOMMU_TEST_OP_MOCK_DOMAIN),
					   &add_mock_pt));
			old_id = self->domain_ids[1];
			self->domain_ids[1] = add_mock_pt.id;

			check_mock_iova(buf + start, map_cmd.iova,
					map_cmd.length);
			check_refs(buf + start / PAGE_SIZE * PAGE_SIZE,
				   end / PAGE_SIZE * PAGE_SIZE -
					   start / PAGE_SIZE * PAGE_SIZE,
				   1);

			destroy_cmd.id = add_mock_pt.id;
			ASSERT_EQ(0,
				  ioctl(self->fd, IOMMU_DESTROY, &destroy_cmd));
			self->domain_ids[1] = old_id;

			unmap_cmd.iova = map_cmd.iova;
			unmap_cmd.length = end - start;
			ASSERT_EQ(0, ioctl(self->fd, IOMMU_IOAS_PAGETABLE_UNMAP,
					   &unmap_cmd));
		}
	}
	check_refs(buf, buf_size, 0);
	ASSERT_EQ(0, munmap(buf, buf_size));
}

/* FIXME check copy'd iopt_pages scenarios around iopt_populate_new_domain() */
/* FIXME manipulate TEMP_MEMORY_LIMIT to test edge cases */
/* FIXME check huge pages */
/* FIXME check user mappings for mdev */

TEST_HARNESS_MAIN
