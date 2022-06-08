/* Intel IOMMU test driver Based on pci-stub
 */
#define DEBUG
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/intel-iommu.h>
#include <linux/intel-svm.h>
#include <linux/ioasid.h>

static char ids[1024] __initdata;
struct page_req_dsc {
	u64 srr:1;
	u64 bof:1;
	u64 pasid_present:1;
	u64 lpig:1;
	u64 pasid:20;
	u64 bus:8;
	u64 private:23;
	u64 prg_index:9;
	u64 rd_req:1;
	u64 wr_req:1;
	u64 exe_req:1;
	u64 priv_req:1;
	u64 devfn:8;
	u64 addr:52;
};

module_param_string(ids, ids, sizeof(ids), 0);
MODULE_PARM_DESC(ids, "Initial PCI IDs to add to the vtd_test driver, format is "
		 "\"vendor:device[:subvendor[:subdevice[:class[:class_mask]]]]\""
		 " and multiple comma separated entries can be specified");

#define PASIDPTR_MASK 0xFFFFFFFFFFFFFULL
enum {
	TEST_IOASID_SET_ALLOC = 1,
	TEST_IOASID_SET_DESTROY,
	TEST_IOASID_ALLOC_WITH_SET,
	TEST_IOASID_PUT_WITH_SET,
	TEST_IOASID_ALLOC_WITHOUT_SET,
	TEST_IOASID_PUT_WITHOUT_SET,
	TEST_IOASID_ALLOC_WITH_SPID,
	TEST_IOASID_PUT_WITH_SPID,
	TEST_IOASID_SPID_LOOKUP,
	TEST_IOASID_ALLOCATOR_REG,
	TEST_IOASID_ALLOCATOR_UNREG,
	NR_VTD_TESTS,
};

static u32 ioasid1 = 1001;
static u32 ioasid2 = 2001;

static ioasid_t intel_ioasid_alloc1(ioasid_t min, ioasid_t max, void *data)
{
	return ioasid1++;
}

static ioasid_t intel_ioasid_alloc2(ioasid_t min, ioasid_t max, void *data)
{
	return ioasid2++;
}

static void intel_ioasid_free(ioasid_t ioasid, void *data)
{
	pr_debug("%s: %u\n", __func__, ioasid);
}

static struct ioasid_allocator_ops intel_iommu_ioasid_allocator1 = {
	.alloc = intel_ioasid_alloc1,
	.free = intel_ioasid_free,
};
static struct ioasid_allocator_ops intel_iommu_ioasid_allocator2 = {
	.alloc = intel_ioasid_alloc2,
	.free = intel_ioasid_free,
};
static struct ioasid_allocator_ops intel_iommu_ioasid_allocator22 = {
	.alloc = intel_ioasid_alloc2,
	.free = intel_ioasid_free,
};


static ioasid_t gpasid_test[2] = {1001, 1002};
static ioasid_t hpasid_test[2];
struct ioasid_set *iset1, *iset2;

static ssize_t test_vtd_run_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct mm_struct *mm;
	unsigned long num;
	int ret;

	ret = kstrtoul(buf, 0, &num);
	if (ret)
		return ret;

	switch (num) {
	case  TEST_IOASID_SET_ALLOC:
		pr_info("test IOASID set alloc %d\n", gpasid_test[1]);
		mm = get_task_mm(current);
		iset1 = ioasid_set_alloc_with_mm(mm, 1000);
		if (IS_ERR(iset1))
			pr_info("Failed to allocate ioasid set 1");
		pr_info("Allocated ioasid_set #%d\n", iset1->id);
		iset2 = ioasid_set_alloc_with_mm(mm, 1000);
		if (IS_ERR(iset2))
			pr_info("Failed to allocate ioasid set 2");
		else
			pr_info("Allocated ioasid_set #%d\n", iset2->id);
		mmput(mm);
		break;
	case  TEST_IOASID_SET_DESTROY:
		pr_debug("test IOASID set destroy %d\n", iset1->id);
		ioasid_set_destroy(iset1);
		break;
	case TEST_IOASID_ALLOC_WITH_SET:
		hpasid_test[0] = ioasid_alloc(iset1, 200, 1000, NULL, gpasid_test[0]);
		hpasid_test[1] = ioasid_alloc(iset1, 200, 1000, NULL, gpasid_test[1]);
		pr_debug("Allocated PASID %d from set %d\n", hpasid_test[0], iset1->id);
		pr_debug("Allocated PASID %d from set %d\n", hpasid_test[1], iset1->id);
		break;
	case TEST_IOASID_PUT_WITH_SET:
		ioasid_put(iset1, hpasid_test[0]);
		ioasid_put(iset1, hpasid_test[1]);
		pr_debug("Put PASID %d from set %d\n", hpasid_test[0], iset1->id);
		pr_debug("Put PASID %d from set %d\n", hpasid_test[1], iset1->id);
		pr_debug("Put all pasids in set %d\n", iset1->id);
		ioasid_put_all_in_set(iset1);
		break;
	case TEST_IOASID_SPID_LOOKUP:
		pr_info("HPASID %d from lookup SPID %d",
			ioasid_find_by_spid(iset1, gpasid_test[0], false), gpasid_test[0]);
		pr_info("HPASID %d from lookup SPID %d",
			ioasid_find_by_spid(iset1, gpasid_test[1], false), gpasid_test[1]);
		break;
	case TEST_IOASID_ALLOC_WITHOUT_SET:
		hpasid_test[0] = ioasid_alloc(NULL, 200, 1000, NULL, 0);
		pr_debug("Allocated PASID %d from NULL set\n", hpasid_test[0]);
		break;
	case TEST_IOASID_PUT_WITHOUT_SET:
		ioasid_put(NULL, hpasid_test[0]);
		pr_debug("Put PASID %d from NULL set\n", hpasid_test[0]);
		break;
	case  TEST_IOASID_ALLOCATOR_REG:
		ret = ioasid_register_allocator(&intel_iommu_ioasid_allocator1);
		pr_debug("Done register allocator1 %d\n", ret);
		ret = ioasid_register_allocator(&intel_iommu_ioasid_allocator2);
		pr_debug("Done register allocator2 %d\n", ret);
		ret = ioasid_register_allocator(&intel_iommu_ioasid_allocator22);
		pr_debug("Done register allocator22 %d\n", ret);
		break;
	case  TEST_IOASID_ALLOCATOR_UNREG:
		ioasid_unregister_allocator(&intel_iommu_ioasid_allocator1);
		pr_debug("Done unregister allocator1 \n");
		ioasid_unregister_allocator(&intel_iommu_ioasid_allocator2);
		pr_debug("Done unregister allocator2 \n");
		ioasid_unregister_allocator(&intel_iommu_ioasid_allocator22);
		pr_debug("Done unregister allocator22 \n");
		break;

	default:
		pr_debug("Unknown cmd %lu Choose TEST_PASIDPTR_UNBIND 1\n TEST_INVALIDATE_ALL 2 \n TEST_PASID_BIND_MM 3\n TEST_GPASID_BIND 4 \n TEST_GPASID_UNBIND 5\n TEST_IOASID_REG\n TEST_IOASID_UNREG\n TEST_UAPI_SIZE\n", num);

	}

	return count;
}

static ssize_t test_vtd_run_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return 0;
}

static DEVICE_ATTR(vtd_test_run, S_IRUGO|S_IWUSR,
	test_vtd_run_show,
	test_vtd_run_store);

static int pci_vtd_test_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int ret;

	dev_info(&dev->dev, "claimed by vtd_test\n");

	ret = device_create_file(&dev->dev, &dev_attr_vtd_test_run);

	return ret;
}

static void pci_vtd_test_remove(struct pci_dev *pdev)
{
	device_remove_file(&pdev->dev, &dev_attr_vtd_test_run);
}

static struct pci_driver vtd_test_driver = {
	.name		= "pci_vtd_test",
	.id_table	= NULL,	/* only dynamic id's */
	.probe		= pci_vtd_test_probe,
	.remove 	= pci_vtd_test_remove,
};

static int __init pci_vtd_test_init(void)
{
	char *p, *id;
	int rc;

	rc = pci_register_driver(&vtd_test_driver);
	if (rc)
		return rc;

	/* no ids passed actually */
	if (ids[0] == '\0')
		return 0;

	/* add ids specified in the module parameter */
	p = ids;
	while ((id = strsep(&p, ","))) {
		unsigned int vendor, device, subvendor = PCI_ANY_ID,
			subdevice = PCI_ANY_ID, class = 0, class_mask = 0;
		int fields;

		if (!strlen(id))
			continue;

		fields = sscanf(id, "%x:%x:%x:%x:%x:%x",
				&vendor, &device, &subvendor, &subdevice,
				&class, &class_mask);

		if (fields < 2) {
			pr_warn("pci_vtd_test: invalid id string \"%s\"\n", id);
			continue;
		}

		pr_info("pci_vtd_test: add %04X:%04X sub=%04X:%04X cls=%08X/%08X\n",
			vendor, device, subvendor, subdevice, class, class_mask);

		rc = pci_add_dynid(&vtd_test_driver, vendor, device,
				subvendor, subdevice, class, class_mask, 0);
		if (rc)
			pr_warn("pci_vtd_test: failed to add dynamic id (%d)\n", rc);
	}

	return 0;
}

static void __exit pci_vtd_test_exit(void)
{
	pci_unregister_driver(&vtd_test_driver);
}

module_init(pci_vtd_test_init);
module_exit(pci_vtd_test_exit);

MODULE_LICENSE("GPL");
