// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Intel Corporation.
 */
#include <linux/vfio.h>
#include <linux/iommufd.h>

#include "vfio.h"

static dev_t device_devt;

void vfio_init_device_cdev(struct vfio_device *device)
{
	device->device.devt = MKDEV(MAJOR(device_devt), device->index);
	cdev_init(&device->cdev, &vfio_device_fops);
	device->cdev.owner = THIS_MODULE;
}

/*
 * device access via the fd opened by this function is blocked until
 * .open_device() is called successfully during BIND_IOMMUFD.
 */
int vfio_device_fops_cdev_open(struct inode *inode, struct file *filep)
{
	struct vfio_device *device = container_of(inode->i_cdev,
						  struct vfio_device, cdev);
	struct vfio_device_file *df;
	int ret;

	if (!vfio_device_try_get_registration(device))
		return -ENODEV;

	df = vfio_allocate_device_file(device);
	if (IS_ERR(df)) {
		ret = PTR_ERR(df);
		goto err_put_registration;
	}

	df->is_cdev_device = true;
	filep->private_data = df;

	return 0;

err_put_registration:
	vfio_device_put_registration(device);
	return ret;
}

static void vfio_device_get_kvm_safe(struct vfio_device_file *df)
{
	spin_lock(&df->kvm_ref_lock);
	if (!df->kvm)
		goto unlock;

	_vfio_device_get_kvm_safe(df->device, df->kvm);

unlock:
	spin_unlock(&df->kvm_ref_lock);
}

void vfio_device_cdev_close(struct vfio_device_file *df)
{
	struct vfio_device *device = df->device;

	mutex_lock(&device->dev_set->lock);
	if (!smp_load_acquire(&df->access_granted)) {
		mutex_unlock(&device->dev_set->lock);
		return;
	}
	vfio_device_close(df);
	vfio_device_put_kvm(device);
	if (df->iommufd)
		iommufd_ctx_put(df->iommufd);
	mutex_unlock(&device->dev_set->lock);
	vfio_device_unblock_group(device);
}

long vfio_device_ioctl_bind_iommufd(struct vfio_device_file *df,
				    unsigned long arg)
{
	struct vfio_device *device = df->device;
	struct vfio_device_bind_iommufd bind;
	struct iommufd_ctx *iommufd = NULL;
	struct fd f;
	unsigned long minsz;
	int ret;

	minsz = offsetofend(struct vfio_device_bind_iommufd, out_devid);

	if (copy_from_user(&bind, (void __user *)arg, minsz))
		return -EFAULT;

	if (bind.argsz < minsz || bind.flags)
		return -EINVAL;

	if (!device->ops->bind_iommufd)
		return -ENODEV;

	ret = vfio_device_block_group(device);
	if (ret)
		return ret;

	mutex_lock(&device->dev_set->lock);
	/*
	 * If already been bound to an iommufd, or already set noiommu
	 * then fail it.
	 */
	if (df->iommufd || df->noiommu) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* iommufd < 0 means noiommu mode */
	if (bind.iommufd < 0) {
		if (!capable(CAP_SYS_RAWIO)) {
			ret = -EPERM;
			goto out_unlock;
		}
		df->noiommu = true;
	} else {
		f = fdget(bind.iommufd);
		if (!f.file) {
			ret = -EBADF;
			goto out_unlock;
		}
		iommufd = iommufd_ctx_from_file(f.file);
		if (IS_ERR(iommufd)) {
			ret = PTR_ERR(iommufd);
			goto out_put_file;
		}
	}

	/*
	 * Before the device open, get the KVM pointer currently
	 * associated with the device file (if there is) and obtain a
	 * reference. This reference is held until device closed. Save
	 * the pointer in the device for use by drivers.
	 */
	vfio_device_get_kvm_safe(df);

	df->iommufd = iommufd;
	ret = vfio_device_open(df, &bind.out_devid, NULL);
	if (ret)
		goto out_put_kvm;

	ret = copy_to_user((void __user *)arg +
			   offsetofend(struct vfio_device_bind_iommufd, iommufd),
			   &bind.out_devid,
			   sizeof(bind.out_devid)) ? -EFAULT : 0;
	if (ret)
		goto out_close_device;

	if (iommufd)
		fdput(f);
	else if (df->noiommu)
		dev_warn(device->dev, "vfio-noiommu device used by user "
			 "(%s:%d)\n", current->comm, task_pid_nr(current));

	/*
	 * Paired with smp_load_acquire() in vfio_device_fops::ioctl/
	 * read/write/mmap
	 */
	smp_store_release(&df->access_granted, true);
	mutex_unlock(&device->dev_set->lock);

	return 0;

out_close_device:
	vfio_device_close(df);
out_put_kvm:
	df->iommufd = NULL;
	df->noiommu = false;
	vfio_device_put_kvm(device);
out_put_file:
	if (iommufd) {
		iommufd_ctx_put(iommufd);
		fdput(f);
	}
out_unlock:
	mutex_unlock(&device->dev_set->lock);
	vfio_device_unblock_group(device);
	return ret;
}

static char *vfio_device_devnode(const struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "vfio/devices/%s", dev_name(dev));
}

int vfio_cdev_init(struct class *device_class)
{
	device_class->devnode = vfio_device_devnode;
	return alloc_chrdev_region(&device_devt, 0,
				   MINORMASK + 1, "vfio-dev");
}

void vfio_cdev_cleanup(void)
{
	unregister_chrdev_region(device_devt, MINORMASK + 1);
}
