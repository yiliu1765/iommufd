// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO core
 *
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 */

#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/vfio.h>
#include <linux/iommufd.h>
#include "vfio.h"

static struct vfio {
	struct class			*class;
	struct list_head		group_list;
	struct mutex			group_lock; /* locks group_list */
	struct ida			group_ida;
	dev_t				group_devt;
} vfio;

static const struct file_operations vfio_group_fops;
/*
 * Group objects - create, release, get, put, search
 */
static void vfio_group_get(struct vfio_group *group);

/*
 * Group objects - create, release, get, put, search
 */
static struct vfio_group *
__vfio_group_get_from_iommu(struct iommu_group *iommu_group)
{
	struct vfio_group *group;

	list_for_each_entry(group, &vfio.group_list, vfio_next) {
		if (group->iommu_group == iommu_group) {
			vfio_group_get(group);
			return group;
		}
	}
	return NULL;
}

static struct vfio_group *
vfio_group_get_from_iommu(struct iommu_group *iommu_group)
{
	struct vfio_group *group;

	mutex_lock(&vfio.group_lock);
	group = __vfio_group_get_from_iommu(iommu_group);
	mutex_unlock(&vfio.group_lock);
	return group;
}

static void vfio_group_release(struct device *dev)
{
	struct vfio_group *group = container_of(dev, struct vfio_group, dev);

	mutex_destroy(&group->device_lock);
	iommu_group_put(group->iommu_group);
	ida_free(&vfio.group_ida, MINOR(group->dev.devt));
	kfree(group);
}

static struct vfio_group *vfio_group_alloc(struct iommu_group *iommu_group,
					   enum vfio_group_type type)
{
	struct vfio_group *group;
	int minor;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return ERR_PTR(-ENOMEM);

	minor = ida_alloc_max(&vfio.group_ida, MINORMASK, GFP_KERNEL);
	if (minor < 0) {
		kfree(group);
		return ERR_PTR(minor);
	}

	device_initialize(&group->dev);
	group->dev.devt = MKDEV(MAJOR(vfio.group_devt), minor);
	group->dev.class = vfio.class;
	group->dev.release = vfio_group_release;
	cdev_init(&group->cdev, &vfio_group_fops);
	group->cdev.owner = THIS_MODULE;

	refcount_set(&group->users, 1);
	init_rwsem(&group->group_rwsem);
	INIT_LIST_HEAD(&group->device_list);
	mutex_init(&group->device_lock);
	group->iommu_group = iommu_group;
	/* put in vfio_group_release() */
	iommu_group_ref_get(iommu_group);
	group->type = type;
	BLOCKING_INIT_NOTIFIER_HEAD(&group->notifier);

	return group;
}

static struct vfio_group *vfio_create_group(struct iommu_group *iommu_group,
		enum vfio_group_type type)
{
	struct vfio_group *group;
	struct vfio_group *ret;
	int err;

	group = vfio_group_alloc(iommu_group, type);
	if (IS_ERR(group))
		return group;

	err = dev_set_name(&group->dev, "%s%d",
			   group->type == VFIO_NO_IOMMU ? "noiommu-" : "",
			   iommu_group_id(iommu_group));
	if (err) {
		ret = ERR_PTR(err);
		goto err_put;
	}

	mutex_lock(&vfio.group_lock);

	/* Did we race creating this group? */
	ret = __vfio_group_get_from_iommu(iommu_group);
	if (ret)
		goto err_unlock;

	err = cdev_device_add(&group->cdev, &group->dev);
	if (err) {
		ret = ERR_PTR(err);
		goto err_unlock;
	}

	list_add(&group->vfio_next, &vfio.group_list);

	mutex_unlock(&vfio.group_lock);
	return group;

err_unlock:
	mutex_unlock(&vfio.group_lock);
err_put:
	put_device(&group->dev);
	return ret;
}

static void vfio_group_put(struct vfio_group *group)
{
	if (!refcount_dec_and_mutex_lock(&group->users, &vfio.group_lock))
		return;

	/*
	 * These data structures all have paired operations that can only be
	 * undone when the caller holds a live reference on the group. Since all
	 * pairs must be undone these WARN_ON's indicate some caller did not
	 * properly hold the group reference.
	 */
	WARN_ON(!list_empty(&group->device_list));
	WARN_ON(group->container || group->container_users);
	WARN_ON(group->notifier.head);

	list_del(&group->vfio_next);
	cdev_device_del(&group->cdev, &group->dev);
	mutex_unlock(&vfio.group_lock);

	put_device(&group->dev);
}

static void vfio_group_get(struct vfio_group *group)
{
	refcount_inc(&group->users);
}

static struct vfio_device *vfio_group_get_device(struct vfio_group *group,
						 struct device *dev)
{
	struct vfio_device *device;

	mutex_lock(&group->device_lock);
	list_for_each_entry(device, &group->device_list, group_next) {
		if (device->dev == dev &&
		    vfio_device_try_get_registration(device)) {
			mutex_unlock(&group->device_lock);
			return device;
		}
	}
	mutex_unlock(&group->device_lock);
	return NULL;
}

struct vfio_group *vfio_noiommu_group_alloc(struct device *dev,
		enum vfio_group_type type)
{
	struct iommu_group *iommu_group;
	struct vfio_group *group;
	int ret;

	iommu_group = iommu_group_alloc();
	if (IS_ERR(iommu_group))
		return ERR_CAST(iommu_group);

	ret = iommu_group_set_name(iommu_group, "vfio-noiommu");
	if (ret)
		goto out_put_group;
	ret = iommu_group_add_device(iommu_group, dev);
	if (ret)
		goto out_put_group;

	group = vfio_create_group(iommu_group, type);
	if (IS_ERR(group)) {
		ret = PTR_ERR(group);
		goto out_remove_device;
	}
	iommu_group_put(iommu_group);
	return group;

out_remove_device:
	iommu_group_remove_device(dev);
out_put_group:
	iommu_group_put(iommu_group);
	return ERR_PTR(ret);
}

struct vfio_group *vfio_group_find_or_alloc(struct device *dev)
{
	struct iommu_group *iommu_group;
	struct vfio_group *group;

	iommu_group = iommu_group_get(dev);
	if (!iommu_group && vfio_noiommu) {
		/*
		 * With noiommu enabled, create an IOMMU group for devices that
		 * don't already have one, implying no IOMMU hardware/driver
		 * exists.  Taint the kernel because we're about to give a DMA
		 * capable device to a user without IOMMU protection.
		 */
		group = vfio_noiommu_group_alloc(dev, VFIO_NO_IOMMU);
		if (!IS_ERR(group)) {
			add_taint(TAINT_USER, LOCKDEP_STILL_OK);
			dev_warn(dev, "Adding kernel taint for vfio-noiommu group on device\n");
		}
		return group;
	}

	if (!iommu_group)
		return ERR_PTR(-EINVAL);

	/*
	 * VFIO always sets IOMMU_CACHE because we offer no way for userspace to
	 * restore cache coherency. It has to be checked here because it is only
	 * valid for cases where we are using iommu groups.
	 */
	if (!device_iommu_capable(dev, IOMMU_CAP_CACHE_COHERENCY)) {
		iommu_group_put(iommu_group);
		return ERR_PTR(-EINVAL);
	}

	group = vfio_group_get_from_iommu(iommu_group);
	if (!group)
		group = vfio_create_group(iommu_group, VFIO_IOMMU);

	/* The vfio_group holds a reference to the iommu_group */
	iommu_group_put(iommu_group);
	return group;
}

void vfio_device_put_group(struct vfio_device *device)
{
	struct vfio_group *group = device->group;

	if (group->type == VFIO_NO_IOMMU ||
	    group->type == VFIO_EMULATED_IOMMU)
		iommu_group_remove_device(device->dev);
	vfio_group_put(group);
}

void vfio_group_register_device(struct vfio_device *device)
{
	mutex_lock(&device->group->device_lock);
	list_add(&device->group_next, &device->group->device_list);
	mutex_unlock(&device->group->device_lock);
}

void vfio_group_unregister_device(struct vfio_device *device)
{
	mutex_lock(&device->group->device_lock);
	list_del(&device->group_next);
	mutex_unlock(&device->group->device_lock);
}

bool vfio_group_find_device(struct vfio_group *group,
			    struct vfio_device *device)
{
	struct vfio_device *existing_device;

	existing_device = vfio_group_get_device(group, device->dev);
	if (existing_device) {
		dev_WARN(device->dev, "Device already exists on group %d\n",
			 iommu_group_id(group->iommu_group));
		vfio_device_put_registration(existing_device);
		return true;
	}
	return false;
}

static struct vfio_device *vfio_device_get_from_name(struct vfio_group *group,
						     char *buf)
{
	struct vfio_device *it, *device = ERR_PTR(-ENODEV);

	mutex_lock(&group->device_lock);
	list_for_each_entry(it, &group->device_list, group_next) {
		int ret;

		if (it->ops->match) {
			ret = it->ops->match(it, buf);
			if (ret < 0) {
				device = ERR_PTR(ret);
				break;
			}
		} else {
			ret = !strcmp(dev_name(it->dev), buf);
		}

		if (ret && vfio_device_try_get_registration(it)) {
			device = it;
			break;
		}
	}
	mutex_unlock(&group->device_lock);

	return device;
}

/*
 * VFIO Group fd, /dev/vfio/$GROUP
 */

bool vfio_group_opened(struct vfio_group *group)
{
	return group->opened_file;
}

void vfio_group_down_write(struct vfio_group *group)
{
	down_write(&group->group_rwsem);
}

void vfio_group_up_write(struct vfio_group *group)
{
	lockdep_assert_held_write(&group->group_rwsem);
	up_write(&group->group_rwsem);
}

static bool vfio_group_has_iommu(struct vfio_group *group)
{
	lockdep_assert_held(&group->group_rwsem);
	if (!group->container)
		WARN_ON(group->container_users);
	else
		WARN_ON(!group->container_users);
	return group->container || group->iommufd;
}

bool vfio_group_device_cdev_opened(struct vfio_group *group)
{
	lockdep_assert_held_write(&group->group_rwsem);
	return group->device_cdev_open_cnt;
}

void vfio_group_inc_device_cdev_cnt(struct vfio_group *group)
{
	lockdep_assert_held_write(&group->group_rwsem);
	group->device_cdev_open_cnt++;
}

void vfio_group_dec_device_cdev_cnt(struct vfio_group *group)
{
	lockdep_assert_held_write(&group->group_rwsem);
	if (!group->device_cdev_open_cnt) {
		WARN_ON(1);
		return;
	}
	group->device_cdev_open_cnt--;
}

/*
 * VFIO_GROUP_UNSET_CONTAINER should fail if there are other users or
 * if there was no container to unset.  Since the ioctl is called on
 * the group, we know that still exists, therefore the only valid
 * transition here is 1->0.
 */
static int vfio_group_ioctl_unset_container(struct vfio_group *group)
{
	int ret = 0;

	down_write(&group->group_rwsem);
	if (!vfio_group_has_iommu(group)) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (group->container) {
		if (group->container_users != 1) {
			ret = -EBUSY;
			goto out_unlock;
		}
		vfio_container_detach_group(group);
	}
	if (group->iommufd) {
		iommufd_ctx_put(group->iommufd);
		group->iommufd = NULL;
	}

out_unlock:
	up_write(&group->group_rwsem);
	return ret;
}

static int vfio_group_ioctl_set_container(struct vfio_group *group,
					  int __user *arg)
{
	struct vfio_container *container;
	struct iommufd_ctx *iommufd;
	struct fd f;
	int ret;
	int fd;

	if (get_user(fd, arg))
		return -EFAULT;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	down_write(&group->group_rwsem);
	if (vfio_group_has_iommu(group)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	container = vfio_container_from_file(f.file);
	if (container) {
		ret = vfio_container_attach_group(container, group);
		goto out_unlock;
	}

	iommufd = iommufd_ctx_from_file(f.file);
	if (!IS_ERR(iommufd)) {
		u32 ioas_id;

		group->iommufd = iommufd;
		ret = iommufd_vfio_compat_ioas_id(iommufd, &ioas_id);
		goto out_unlock;
	}

	/* The FD passed is not recognized. */
	ret = -EBADF;

out_unlock:
	up_write(&group->group_rwsem);
	fdput(f);
	return ret;
}

int vfio_group_open_device(struct vfio_device *device)
{
	int ret;

	lockdep_assert_held(&device->dev_set->lock);

	/*
	 * Here we pass the KVM pointer with the group under the read lock.  If
	 * the device driver will use it, it must obtain a reference and release
	 * it during close_device.
	 */
	down_write(&device->group->group_rwsem);
	if (!vfio_group_has_iommu(device->group)) {
		ret = -EINVAL;
		goto err_unlock;
	}

	if (device->group->container) {
		ret = vfio_container_use(device->group);
		if (ret)
			goto err_unlock;
	} else if (device->group->iommufd) {
		ret = vfio_iommufd_bind(device, device->group->iommufd);
		if (ret)
			goto err_unlock;
	}

	device->kvm = device->group->kvm;
	if (device->ops->open_device) {
		ret = device->ops->open_device(device);
		if (ret)
			goto err_container;
	}
	if (device->group->container)
		vfio_container_register_device(device);
	up_write(&device->group->group_rwsem);
	return 0;

err_container:
	if (device->group->container)
		vfio_container_unuse(device->group);
	vfio_iommufd_unbind(device);
	device->kvm = NULL;
err_unlock:
	up_write(&device->group->group_rwsem);
	return ret;
}

void vfio_group_close_device(struct vfio_device *device)
{
	lockdep_assert_held(&device->dev_set->lock);

	down_write(&device->group->group_rwsem);
	if (device->group->container)
		vfio_container_unregister_device(device);
	if (device->ops->close_device)
		device->ops->close_device(device);
	if (device->group->container)
		vfio_container_unuse(device->group);
	up_write(&device->group->group_rwsem);
}

static struct file *vfio_group_get_device_file(struct vfio_device *device)
{
	struct file *filep;

	/*
	 * We can't use anon_inode_getfd() because we need to modify
	 * the f_mode flags directly to allow more than just ioctls
	 */
	filep = anon_inode_getfile("[vfio-device]", &vfio_device_fops,
				   device, O_RDWR);
	if (IS_ERR(filep))
		goto out;

	/*
	 * TODO: add an anon_inode interface to do this.
	 * Appears to be missing by lack of need rather than
	 * explicitly prevented.  Now there's need.
	 */
	filep->f_mode |= (FMODE_PREAD | FMODE_PWRITE);

	if (device->group->type == VFIO_NO_IOMMU)
		dev_warn(device->dev, "vfio-noiommu device opened by user "
			 "(%s:%d)\n", current->comm, task_pid_nr(current));
	/*
	 * On success the ref of device is moved to the file and
	 * put in vfio_device_fops_release()
	 */
out:
	return filep;
}

static int vfio_group_ioctl_get_device_fd(struct vfio_group *group,
					  char __user *arg)
{
	struct vfio_device *device;
	struct file *filep;
	char *buf;
	int fdno;
	int ret;

	buf = strndup_user(arg, PAGE_SIZE);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	device = vfio_device_get_from_name(group, buf);
	kfree(buf);
	if (IS_ERR(device))
		return PTR_ERR(device);

	fdno = get_unused_fd_flags(O_CLOEXEC);
	if (fdno < 0) {
		ret = fdno;
		goto err_put_device;
	}

	mutex_lock(&device->dev_set->lock);
	ret = vfio_device_open(device);
	mutex_unlock(&device->dev_set->lock);
	if (ret)
		goto err_put_fdno;

	filep = vfio_group_get_device_file(device);
	if (IS_ERR(filep)) {
		ret = PTR_ERR(filep);
		goto err_close_device;
	}

	fd_install(fdno, filep);
	return fdno;

err_close_device:
	mutex_lock(&device->dev_set->lock);
	if (device->open_count == 1)
		vfio_device_last_close(device);
	device->open_count--;
	mutex_unlock(&device->dev_set->lock);
err_put_fdno:
	put_unused_fd(fdno);
err_put_device:
	vfio_device_put_registration(device);
	return ret;
}

static int vfio_group_ioctl_get_status(struct vfio_group *group,
				       struct vfio_group_status __user *arg)
{
	unsigned long minsz = offsetofend(struct vfio_group_status, flags);
	struct vfio_group_status status;

	if (copy_from_user(&status, arg, minsz))
		return -EFAULT;

	if (status.argsz < minsz)
		return -EINVAL;

	status.flags = 0;

	down_read(&group->group_rwsem);
	if (group->container || group->iommufd)
		status.flags |= VFIO_GROUP_FLAGS_CONTAINER_SET |
				VFIO_GROUP_FLAGS_VIABLE;
	else if (!iommu_group_dma_owner_claimed(group->iommu_group))
		status.flags |= VFIO_GROUP_FLAGS_VIABLE;
	up_read(&group->group_rwsem);

	if (copy_to_user(arg, &status, minsz))
		return -EFAULT;
	return 0;
}

static long vfio_group_fops_unl_ioctl(struct file *filep,
				      unsigned int cmd, unsigned long arg)
{
	struct vfio_group *group = filep->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case VFIO_GROUP_GET_DEVICE_FD:
		return vfio_group_ioctl_get_device_fd(group, uarg);
	case VFIO_GROUP_GET_STATUS:
		return vfio_group_ioctl_get_status(group, uarg);
	case VFIO_GROUP_SET_CONTAINER:
		return vfio_group_ioctl_set_container(group, uarg);
	case VFIO_GROUP_UNSET_CONTAINER:
		return vfio_group_ioctl_unset_container(group);
	default:
		return -ENOTTY;
	}
}

static int vfio_group_fops_open(struct inode *inode, struct file *filep)
{
	struct vfio_group *group =
		container_of(inode->i_cdev, struct vfio_group, cdev);
	int ret;

	down_write(&group->group_rwsem);

	/* users can be zero if this races with vfio_group_put() */
	if (!refcount_inc_not_zero(&group->users)) {
		ret = -ENODEV;
		goto err_unlock;
	}

	if (group->type == VFIO_NO_IOMMU && !capable(CAP_SYS_RAWIO)) {
		ret = -EPERM;
		goto err_put;
	}

	/*
	 * Do we need multiple instances of the group open?  Seems not.
	 */
	if (vfio_group_opened(group) || group->device_cdev_open_cnt) {
		ret = -EBUSY;
		goto err_put;
	}
	group->opened_file = filep;
	filep->private_data = group;

	up_write(&group->group_rwsem);
	return 0;
err_put:
	vfio_group_put(group);
err_unlock:
	up_write(&group->group_rwsem);
	return ret;
}

static int vfio_group_fops_release(struct inode *inode, struct file *filep)
{
	struct vfio_group *group = filep->private_data;

	filep->private_data = NULL;

	down_write(&group->group_rwsem);
	/*
	 * Device FDs hold a group file reference, therefore the group release
	 * is only called when there are no open devices.
	 */
	WARN_ON(group->notifier.head);
	if (group->container)
		vfio_container_detach_group(group);
	if (group->iommufd) {
		iommufd_ctx_put(group->iommufd);
		group->iommufd = NULL;
	}
	group->opened_file = NULL;
	up_write(&group->group_rwsem);

	vfio_group_put(group);

	return 0;
}

static const struct file_operations vfio_group_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= vfio_group_fops_unl_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.open		= vfio_group_fops_open,
	.release	= vfio_group_fops_release,
};

/**
 * vfio_file_iommu_group - Return the struct iommu_group for the vfio group file
 * @file: VFIO group file
 *
 * The returned iommu_group is valid as long as a ref is held on the file.
 */
struct iommu_group *vfio_file_iommu_group(struct file *file)
{
	struct vfio_group *group = file->private_data;

	if (file->f_op != &vfio_group_fops)
		return NULL;
	return group->iommu_group;
}
EXPORT_SYMBOL_GPL(vfio_file_iommu_group);

bool vfio_is_group_file(struct file *file)
{
	return file->f_op == &vfio_group_fops;
}

bool vfio_group_enforced_coherent(struct vfio_group *group)
{
	bool ret;

	down_read(&group->group_rwsem);
	if (group->container) {
		ret = vfio_container_ioctl_check_extension(group->container,
							   VFIO_DMA_CC_IOMMU);
	} else if (group->iommufd) {
		struct vfio_device *device;

		mutex_lock(&group->device_lock);
		ret = true;
		list_for_each_entry(device, &group->device_list, group_next) {
			if (!vfio_device_try_get_registration(device))
				continue;
			ret &= vfio_iommufd_enforced_coherent(device);
			vfio_device_put_registration(device);
		}
		mutex_unlock(&group->device_lock);
	} else {
		/*
		 * Since the coherency state is determined only once a container
		 * is attached the user must do so before they can prove they
		 * have permission.
		 */
		ret = true;
	}
	up_read(&group->group_rwsem);
	return ret;
}

void vfio_group_set_kvm(struct vfio_group *group, struct kvm *kvm)
{

	down_write(&group->group_rwsem);
	group->kvm = kvm;
	up_write(&group->group_rwsem);
}

bool vfio_group_has_dev(struct vfio_group *group,
			struct vfio_device *device)
{
	return group == device->group;
}

bool vfio_group_has_container(struct vfio_group *group)
{
	return group->container;
}

static char *vfio_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "vfio/%s", dev_name(dev));
}

int __init vfio_group_init(void)
{
	int ret;

	ida_init(&vfio.group_ida);
	mutex_init(&vfio.group_lock);
	INIT_LIST_HEAD(&vfio.group_list);

	/* /dev/vfio/$GROUP */
	vfio.class = class_create(THIS_MODULE, "vfio");
	if (IS_ERR(vfio.class)) {
		ret = PTR_ERR(vfio.class);
		goto err_group_class;
	}

	vfio.class->devnode = vfio_devnode;

	ret = alloc_chrdev_region(&vfio.group_devt, 0, MINORMASK + 1,
				  "vfio-group");
	if (ret)
		goto err_alloc_chrdev;
	return 0;

err_alloc_chrdev:
	class_destroy(vfio.class);
	vfio.class = NULL;
err_group_class:
	return ret;
}

void vfio_group_cleanup(void)
{
	WARN_ON(!list_empty(&vfio.group_list));
	ida_destroy(&vfio.group_ida);
	unregister_chrdev_region(vfio.group_devt, MINORMASK + 1);
	class_destroy(vfio.class);
	vfio.class = NULL;
}
