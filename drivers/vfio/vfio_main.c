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

#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/wait.h>
#include <linux/sched/signal.h>
#include <linux/pm_runtime.h>
#include <linux/iommufd.h>
#include "vfio.h"

#define DRIVER_VERSION	"0.3"
#define DRIVER_AUTHOR	"Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC	"VFIO - User Level meta-driver"

static struct vfio {
	struct class			*device_class;
	struct list_head		device_list;
	struct mutex			device_lock; /* locks device_list */
	struct ida			device_ida;
	dev_t                           device_devt;
} vfio;

bool vfio_allow_unsafe_interrupts;
EXPORT_SYMBOL_GPL(vfio_allow_unsafe_interrupts);

static DEFINE_XARRAY(vfio_device_set_xa);

int vfio_assign_device_set(struct vfio_device *device, void *set_id)
{
	unsigned long idx = (unsigned long)set_id;
	struct vfio_device_set *new_dev_set;
	struct vfio_device_set *dev_set;

	if (WARN_ON(!set_id))
		return -EINVAL;

	/*
	 * Atomically acquire a singleton object in the xarray for this set_id
	 */
	xa_lock(&vfio_device_set_xa);
	dev_set = xa_load(&vfio_device_set_xa, idx);
	if (dev_set)
		goto found_get_ref;
	xa_unlock(&vfio_device_set_xa);

	new_dev_set = kzalloc(sizeof(*new_dev_set), GFP_KERNEL);
	if (!new_dev_set)
		return -ENOMEM;
	mutex_init(&new_dev_set->lock);
	INIT_LIST_HEAD(&new_dev_set->device_list);
	new_dev_set->set_id = set_id;

	xa_lock(&vfio_device_set_xa);
	dev_set = __xa_cmpxchg(&vfio_device_set_xa, idx, NULL, new_dev_set,
			       GFP_KERNEL);
	if (!dev_set) {
		dev_set = new_dev_set;
		goto found_get_ref;
	}

	kfree(new_dev_set);
	if (xa_is_err(dev_set)) {
		xa_unlock(&vfio_device_set_xa);
		return xa_err(dev_set);
	}

found_get_ref:
	dev_set->device_count++;
	xa_unlock(&vfio_device_set_xa);
	mutex_lock(&dev_set->lock);
	device->dev_set = dev_set;
	list_add_tail(&device->dev_set_list, &dev_set->device_list);
	mutex_unlock(&dev_set->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(vfio_assign_device_set);

static void vfio_release_device_set(struct vfio_device *device)
{
	struct vfio_device_set *dev_set = device->dev_set;

	if (!dev_set)
		return;

	mutex_lock(&dev_set->lock);
	list_del(&device->dev_set_list);
	mutex_unlock(&dev_set->lock);

	xa_lock(&vfio_device_set_xa);
	if (!--dev_set->device_count) {
		__xa_erase(&vfio_device_set_xa,
			   (unsigned long)dev_set->set_id);
		mutex_destroy(&dev_set->lock);
		kfree(dev_set);
	}
	xa_unlock(&vfio_device_set_xa);
}

/*
 * Device objects - create, release, get, put, search
 */
/* Device reference always implies a group reference */
void vfio_device_put_registration(struct vfio_device *device)
{
	if (refcount_dec_and_test(&device->refcount))
		complete(&device->comp);
}

bool vfio_device_try_get_registration(struct vfio_device *device)
{
	return refcount_inc_not_zero(&device->refcount);
}

/*
 * VFIO driver API
 */
/* Release helper called by vfio_put_device() */
static void vfio_device_release(struct device *dev)
{
	struct vfio_device *device =
			container_of(dev, struct vfio_device, device);

	vfio_release_device_set(device);
	ida_free(&vfio.device_ida, MINOR(device->device.devt));

	/*
	 * kvfree() cannot be done here due to a life cycle mess in
	 * vfio-ccw. Before the ccw part is fixed all drivers are
	 * required to support @release and call vfio_free_device()
	 * from there.
	 */
	device->ops->release(device);
}

/*
 * Alloc and initialize vfio_device so it can be registered to vfio
 * core.
 *
 * Drivers should use the wrapper vfio_alloc_device() for allocation.
 * @size is the size of the structure to be allocated, including any
 * private data used by the driver.
 *
 * Driver may provide an @init callback to cover device private data.
 *
 * Use vfio_put_device() to release the structure after success return.
 */
struct vfio_device *_vfio_alloc_device(size_t size, struct device *dev,
				       const struct vfio_device_ops *ops)
{
	struct vfio_device *device;
	int ret;

	if (WARN_ON(size < sizeof(struct vfio_device)))
		return ERR_PTR(-EINVAL);

	device = kvzalloc(size, GFP_KERNEL);
	if (!device)
		return ERR_PTR(-ENOMEM);

	ret = vfio_init_device(device, dev, ops);
	if (ret)
		goto out_free;
	return device;

out_free:
	kvfree(device);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(_vfio_alloc_device);

/*
 * Initialize a vfio_device so it can be registered to vfio core.
 *
 * Only vfio-ccw driver should call this interface.
 */
int vfio_init_device(struct vfio_device *device, struct device *dev,
		     const struct vfio_device_ops *ops)
{
	unsigned int minor;
	int ret;

	ret = ida_alloc_max(&vfio.device_ida, MINORMASK, GFP_KERNEL);
	if (ret < 0) {
		dev_dbg(dev, "Error to alloc minor\n");
		return ret;
	}

	minor = ret;
	init_completion(&device->comp);
	device->dev = dev;
	device->ops = ops;

	if (ops->init) {
		ret = ops->init(device);
		if (ret)
			goto out_uninit;
	}

	device_initialize(&device->device);
	device->device.devt = MKDEV(MAJOR(vfio.device_devt), minor);
	device->device.release = vfio_device_release;
	device->device.class = vfio.device_class;
	device->device.parent = device->dev;
	cdev_init(&device->cdev, &vfio_device_fops);
	device->cdev.owner = THIS_MODULE;
	return 0;

out_uninit:
	vfio_release_device_set(device);
	ida_free(&vfio.device_ida, minor);
	return ret;
}
EXPORT_SYMBOL_GPL(vfio_init_device);

/*
 * The helper called by driver @release callback to free the device
 * structure. Drivers which don't have private data to clean can
 * simply use this helper as its @release.
 */
void vfio_free_device(struct vfio_device *device)
{
	kvfree(device);
}
EXPORT_SYMBOL_GPL(vfio_free_device);

static bool vfio_find_device_for_dev(struct device *dev)
{
	struct vfio_device *device;

	mutex_lock(&vfio.device_lock);
	list_for_each_entry(device, &vfio.device_list, vfio_next) {
		if (device->dev == dev &&
		    vfio_device_try_get_registration(device)) {
			vfio_device_put_registration(device);
			mutex_unlock(&vfio.device_lock);
			dev_WARN(device->dev, "Device already exists\n");
			return true;
		}
	}
	mutex_unlock(&vfio.device_lock);
	return false;
}

static int __vfio_register_dev(struct vfio_device *device,
		struct vfio_group *group)
{
	int ret;

	if (IS_ERR(group))
		return PTR_ERR(group);

	if (WARN_ON(device->ops->bind_iommufd &&
		    (!device->ops->unbind_iommufd ||
		     !device->ops->attach_ioas)))
		return -EINVAL;

	/*
	 * If the driver doesn't specify a set then the device is added to a
	 * singleton set just for itself.
	 */
	if (!device->dev_set)
		vfio_assign_device_set(device, device);

	if (vfio_group_find_device(group, device) ||
	    vfio_find_device_for_dev(device->dev)) {
		ret = -EBUSY;
		goto err_out;
	}

	/* Our reference on group is moved to the device */
	device->group = group;

	ret = dev_set_name(&device->device, "vfio%d", MINOR(device->device.devt));
	if (ret)
		goto err_out;

	ret = cdev_device_add(&device->cdev, &device->device);
	if (ret)
		return ret;

	dev_dbg(device->dev, "Creates Device interface successfully!\n");

	/* Refcounting can't start until the driver calls register */
	refcount_set(&device->refcount, 1);

	mutex_lock(&vfio.device_lock);
	list_add(&device->vfio_next, &vfio.device_list);
	mutex_unlock(&vfio.device_lock);

	vfio_group_register_device(device);

	return 0;
err_out:
	vfio_device_put_group(device);
	return ret;
}

int vfio_register_group_dev(struct vfio_device *device)
{
	return __vfio_register_dev(device,
		vfio_group_find_or_alloc(device->dev));
}
EXPORT_SYMBOL_GPL(vfio_register_group_dev);

/*
 * Register a virtual device without IOMMU backing.  The user of this
 * device must not be able to directly trigger unmediated DMA.
 */
int vfio_register_emulated_iommu_dev(struct vfio_device *device)
{
	return __vfio_register_dev(device,
		vfio_noiommu_group_alloc(device->dev, VFIO_EMULATED_IOMMU));
}
EXPORT_SYMBOL_GPL(vfio_register_emulated_iommu_dev);

/*
 * Decrement the device reference count and wait for the device to be
 * removed.  Open file descriptors for the device... */
void vfio_unregister_group_dev(struct vfio_device *device)
{
	unsigned int i = 0;
	bool interrupted = false;
	long rc;

	vfio_device_put_registration(device);
	rc = try_wait_for_completion(&device->comp);
	while (rc <= 0) {
		if (device->ops->request)
			device->ops->request(device, i++);

		if (interrupted) {
			rc = wait_for_completion_timeout(&device->comp,
							 HZ * 10);
		} else {
			rc = wait_for_completion_interruptible_timeout(
				&device->comp, HZ * 10);
			if (rc < 0) {
				interrupted = true;
				dev_warn(device->dev,
					 "Device is currently in use, task"
					 " \"%s\" (%d) "
					 "blocked until device is released",
					 current->comm, task_pid_nr(current));
			}
		}
	}

	vfio_group_unregister_device(device);

	mutex_lock(&vfio.device_lock);
	list_del(&device->vfio_next);
	mutex_unlock(&vfio.device_lock);

	/* Balances device_add in register path */
	cdev_device_del(&device->cdev, &device->device);

	vfio_device_put_group(device);
}
EXPORT_SYMBOL_GPL(vfio_unregister_group_dev);

/* true if the vfio_device has open_device() called but not close_device() */
static bool vfio_assert_device_open(struct vfio_device *device)
{
	return !WARN_ON_ONCE(!READ_ONCE(device->open_count));
}

static int vfio_device_first_open(struct vfio_device *device)
{
	int ret;

	lockdep_assert_held(&device->dev_set->lock);

	if (!try_module_get(device->dev->driver->owner))
		return -ENODEV;

	if (vfio_group_opened(device->group)) {
		ret = vfio_group_open_device(device);
		if (ret)
			goto err_module_put;
	} else if (device->ops->open_device) {
		ret = device->ops->open_device(device);
		if (ret)
			goto err_module_put;
	}
	return 0;

err_module_put:
	module_put(device->dev->driver->owner);
	return ret;
}

void vfio_device_last_close(struct vfio_device *device)
{
	lockdep_assert_held(&device->dev_set->lock);

	if (vfio_group_opened(device->group))
		vfio_group_close_device(device);
	else if (device->ops->close_device)
		device->ops->close_device(device);
	device->kvm = NULL;
	vfio_iommufd_unbind(device);
	module_put(device->dev->driver->owner);
}

int vfio_device_open(struct vfio_device *device)
{
	int ret = 0;

	lockdep_assert_held(&device->dev_set->lock);

	device->open_count++;
	if (device->open_count == 1) {
		ret = vfio_device_first_open(device);
		if (ret)
			device->open_count--;
	}
	return ret;
}

/*
 * Wrapper around pm_runtime_resume_and_get().
 * Return error code on failure or 0 on success.
 */
static inline int vfio_device_pm_runtime_get(struct vfio_device *device)
{
	struct device *dev = device->dev;

	if (dev->driver && dev->driver->pm) {
		int ret;

		ret = pm_runtime_resume_and_get(dev);
		if (ret) {
			dev_info_ratelimited(dev,
				"vfio: runtime resume failed %d\n", ret);
			return -EIO;
		}
	}

	return 0;
}

/*
 * Wrapper around pm_runtime_put().
 */
static inline void vfio_device_pm_runtime_put(struct vfio_device *device)
{
	struct device *dev = device->dev;

	if (dev->driver && dev->driver->pm)
		pm_runtime_put(dev);
}

/*
 * VFIO Device fd
 */
static int vfio_device_fops_open(struct inode *inode, struct file *filep)
{
	struct vfio_device *device = container_of(inode->i_cdev,
						  struct vfio_device, cdev);
	int ret = 0;

	if (!vfio_device_try_get_registration(device))
		return -ENODEV;

	mutex_lock(&device->dev_set->lock);

	vfio_group_down_write(device->group);
	if (vfio_group_opened(device->group)) {
		ret = -EBUSY;
		goto out_put_unlock;
	} else {
		vfio_group_inc_device_cdev_cnt(device->group);
	}
	vfio_group_up_write(device->group);

	ret = vfio_device_open(device);
	if (ret) {
		vfio_group_down_write(device->group);
		goto out_put_unlock;
	}

	mutex_unlock(&device->dev_set->lock);

	return 0;
out_put_unlock:
	vfio_group_up_write(device->group);
	mutex_unlock(&device->dev_set->lock);
	vfio_device_put_registration(device);
	return ret;
}

static int vfio_device_fops_release(struct inode *inode, struct file *filep)
{
	struct vfio_device *device;

	if (filep->private_data)
		device = filep->private_data;
	else
		device = container_of(inode->i_cdev, struct vfio_device, cdev);

	mutex_lock(&device->dev_set->lock);
	vfio_assert_device_open(device);
	if (device->open_count == 1)
		vfio_device_last_close(device);
	device->open_count--;
	vfio_group_down_write(device->group);
	if (vfio_group_device_cdev_opened(device->group))
		vfio_group_dec_device_cdev_cnt(device->group);
	vfio_group_up_write(device->group);
	mutex_unlock(&device->dev_set->lock);

	vfio_device_put_registration(device);

	return 0;
}

/*
 * vfio_mig_get_next_state - Compute the next step in the FSM
 * @cur_fsm - The current state the device is in
 * @new_fsm - The target state to reach
 * @next_fsm - Pointer to the next step to get to new_fsm
 *
 * Return 0 upon success, otherwise -errno
 * Upon success the next step in the state progression between cur_fsm and
 * new_fsm will be set in next_fsm.
 *
 * This breaks down requests for combination transitions into smaller steps and
 * returns the next step to get to new_fsm. The function may need to be called
 * multiple times before reaching new_fsm.
 *
 */
int vfio_mig_get_next_state(struct vfio_device *device,
			    enum vfio_device_mig_state cur_fsm,
			    enum vfio_device_mig_state new_fsm,
			    enum vfio_device_mig_state *next_fsm)
{
	enum { VFIO_DEVICE_NUM_STATES = VFIO_DEVICE_STATE_RUNNING_P2P + 1 };
	/*
	 * The coding in this table requires the driver to implement the
	 * following FSM arcs:
	 *         RESUMING -> STOP
	 *         STOP -> RESUMING
	 *         STOP -> STOP_COPY
	 *         STOP_COPY -> STOP
	 *
	 * If P2P is supported then the driver must also implement these FSM
	 * arcs:
	 *         RUNNING -> RUNNING_P2P
	 *         RUNNING_P2P -> RUNNING
	 *         RUNNING_P2P -> STOP
	 *         STOP -> RUNNING_P2P
	 * Without P2P the driver must implement:
	 *         RUNNING -> STOP
	 *         STOP -> RUNNING
	 *
	 * The coding will step through multiple states for some combination
	 * transitions; if all optional features are supported, this means the
	 * following ones:
	 *         RESUMING -> STOP -> RUNNING_P2P
	 *         RESUMING -> STOP -> RUNNING_P2P -> RUNNING
	 *         RESUMING -> STOP -> STOP_COPY
	 *         RUNNING -> RUNNING_P2P -> STOP
	 *         RUNNING -> RUNNING_P2P -> STOP -> RESUMING
	 *         RUNNING -> RUNNING_P2P -> STOP -> STOP_COPY
	 *         RUNNING_P2P -> STOP -> RESUMING
	 *         RUNNING_P2P -> STOP -> STOP_COPY
	 *         STOP -> RUNNING_P2P -> RUNNING
	 *         STOP_COPY -> STOP -> RESUMING
	 *         STOP_COPY -> STOP -> RUNNING_P2P
	 *         STOP_COPY -> STOP -> RUNNING_P2P -> RUNNING
	 */
	static const u8 vfio_from_fsm_table[VFIO_DEVICE_NUM_STATES][VFIO_DEVICE_NUM_STATES] = {
		[VFIO_DEVICE_STATE_STOP] = {
			[VFIO_DEVICE_STATE_STOP] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_RUNNING] = VFIO_DEVICE_STATE_RUNNING_P2P,
			[VFIO_DEVICE_STATE_STOP_COPY] = VFIO_DEVICE_STATE_STOP_COPY,
			[VFIO_DEVICE_STATE_RESUMING] = VFIO_DEVICE_STATE_RESUMING,
			[VFIO_DEVICE_STATE_RUNNING_P2P] = VFIO_DEVICE_STATE_RUNNING_P2P,
			[VFIO_DEVICE_STATE_ERROR] = VFIO_DEVICE_STATE_ERROR,
		},
		[VFIO_DEVICE_STATE_RUNNING] = {
			[VFIO_DEVICE_STATE_STOP] = VFIO_DEVICE_STATE_RUNNING_P2P,
			[VFIO_DEVICE_STATE_RUNNING] = VFIO_DEVICE_STATE_RUNNING,
			[VFIO_DEVICE_STATE_STOP_COPY] = VFIO_DEVICE_STATE_RUNNING_P2P,
			[VFIO_DEVICE_STATE_RESUMING] = VFIO_DEVICE_STATE_RUNNING_P2P,
			[VFIO_DEVICE_STATE_RUNNING_P2P] = VFIO_DEVICE_STATE_RUNNING_P2P,
			[VFIO_DEVICE_STATE_ERROR] = VFIO_DEVICE_STATE_ERROR,
		},
		[VFIO_DEVICE_STATE_STOP_COPY] = {
			[VFIO_DEVICE_STATE_STOP] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_RUNNING] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_STOP_COPY] = VFIO_DEVICE_STATE_STOP_COPY,
			[VFIO_DEVICE_STATE_RESUMING] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_RUNNING_P2P] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_ERROR] = VFIO_DEVICE_STATE_ERROR,
		},
		[VFIO_DEVICE_STATE_RESUMING] = {
			[VFIO_DEVICE_STATE_STOP] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_RUNNING] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_STOP_COPY] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_RESUMING] = VFIO_DEVICE_STATE_RESUMING,
			[VFIO_DEVICE_STATE_RUNNING_P2P] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_ERROR] = VFIO_DEVICE_STATE_ERROR,
		},
		[VFIO_DEVICE_STATE_RUNNING_P2P] = {
			[VFIO_DEVICE_STATE_STOP] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_RUNNING] = VFIO_DEVICE_STATE_RUNNING,
			[VFIO_DEVICE_STATE_STOP_COPY] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_RESUMING] = VFIO_DEVICE_STATE_STOP,
			[VFIO_DEVICE_STATE_RUNNING_P2P] = VFIO_DEVICE_STATE_RUNNING_P2P,
			[VFIO_DEVICE_STATE_ERROR] = VFIO_DEVICE_STATE_ERROR,
		},
		[VFIO_DEVICE_STATE_ERROR] = {
			[VFIO_DEVICE_STATE_STOP] = VFIO_DEVICE_STATE_ERROR,
			[VFIO_DEVICE_STATE_RUNNING] = VFIO_DEVICE_STATE_ERROR,
			[VFIO_DEVICE_STATE_STOP_COPY] = VFIO_DEVICE_STATE_ERROR,
			[VFIO_DEVICE_STATE_RESUMING] = VFIO_DEVICE_STATE_ERROR,
			[VFIO_DEVICE_STATE_RUNNING_P2P] = VFIO_DEVICE_STATE_ERROR,
			[VFIO_DEVICE_STATE_ERROR] = VFIO_DEVICE_STATE_ERROR,
		},
	};

	static const unsigned int state_flags_table[VFIO_DEVICE_NUM_STATES] = {
		[VFIO_DEVICE_STATE_STOP] = VFIO_MIGRATION_STOP_COPY,
		[VFIO_DEVICE_STATE_RUNNING] = VFIO_MIGRATION_STOP_COPY,
		[VFIO_DEVICE_STATE_STOP_COPY] = VFIO_MIGRATION_STOP_COPY,
		[VFIO_DEVICE_STATE_RESUMING] = VFIO_MIGRATION_STOP_COPY,
		[VFIO_DEVICE_STATE_RUNNING_P2P] =
			VFIO_MIGRATION_STOP_COPY | VFIO_MIGRATION_P2P,
		[VFIO_DEVICE_STATE_ERROR] = ~0U,
	};

	if (WARN_ON(cur_fsm >= ARRAY_SIZE(vfio_from_fsm_table) ||
		    (state_flags_table[cur_fsm] & device->migration_flags) !=
			state_flags_table[cur_fsm]))
		return -EINVAL;

	if (new_fsm >= ARRAY_SIZE(vfio_from_fsm_table) ||
	   (state_flags_table[new_fsm] & device->migration_flags) !=
			state_flags_table[new_fsm])
		return -EINVAL;

	/*
	 * Arcs touching optional and unsupported states are skipped over. The
	 * driver will instead see an arc from the original state to the next
	 * logical state, as per the above comment.
	 */
	*next_fsm = vfio_from_fsm_table[cur_fsm][new_fsm];
	while ((state_flags_table[*next_fsm] & device->migration_flags) !=
			state_flags_table[*next_fsm])
		*next_fsm = vfio_from_fsm_table[*next_fsm][new_fsm];

	return (*next_fsm != VFIO_DEVICE_STATE_ERROR) ? 0 : -EINVAL;
}
EXPORT_SYMBOL_GPL(vfio_mig_get_next_state);

/*
 * Convert the drivers's struct file into a FD number and return it to userspace
 */
static int vfio_ioct_mig_return_fd(struct file *filp, void __user *arg,
				   struct vfio_device_feature_mig_state *mig)
{
	int ret;
	int fd;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto out_fput;
	}

	mig->data_fd = fd;
	if (copy_to_user(arg, mig, sizeof(*mig))) {
		ret = -EFAULT;
		goto out_put_unused;
	}
	fd_install(fd, filp);
	return 0;

out_put_unused:
	put_unused_fd(fd);
out_fput:
	fput(filp);
	return ret;
}

static int
vfio_ioctl_device_feature_mig_device_state(struct vfio_device *device,
					   u32 flags, void __user *arg,
					   size_t argsz)
{
	size_t minsz =
		offsetofend(struct vfio_device_feature_mig_state, data_fd);
	struct vfio_device_feature_mig_state mig;
	struct file *filp = NULL;
	int ret;

	if (!device->mig_ops)
		return -ENOTTY;

	ret = vfio_check_feature(flags, argsz,
				 VFIO_DEVICE_FEATURE_SET |
				 VFIO_DEVICE_FEATURE_GET,
				 sizeof(mig));
	if (ret != 1)
		return ret;

	if (copy_from_user(&mig, arg, minsz))
		return -EFAULT;

	if (flags & VFIO_DEVICE_FEATURE_GET) {
		enum vfio_device_mig_state curr_state;

		ret = device->mig_ops->migration_get_state(device,
							   &curr_state);
		if (ret)
			return ret;
		mig.device_state = curr_state;
		goto out_copy;
	}

	/* Handle the VFIO_DEVICE_FEATURE_SET */
	filp = device->mig_ops->migration_set_state(device, mig.device_state);
	if (IS_ERR(filp) || !filp)
		goto out_copy;

	return vfio_ioct_mig_return_fd(filp, arg, &mig);
out_copy:
	mig.data_fd = -1;
	if (copy_to_user(arg, &mig, sizeof(mig)))
		return -EFAULT;
	if (IS_ERR(filp))
		return PTR_ERR(filp);
	return 0;
}

static int vfio_ioctl_device_feature_migration(struct vfio_device *device,
					       u32 flags, void __user *arg,
					       size_t argsz)
{
	struct vfio_device_feature_migration mig = {
		.flags = device->migration_flags,
	};
	int ret;

	if (!device->mig_ops)
		return -ENOTTY;

	ret = vfio_check_feature(flags, argsz, VFIO_DEVICE_FEATURE_GET,
				 sizeof(mig));
	if (ret != 1)
		return ret;
	if (copy_to_user(arg, &mig, sizeof(mig)))
		return -EFAULT;
	return 0;
}

static int vfio_ioctl_device_feature(struct vfio_device *device,
				     struct vfio_device_feature __user *arg)
{
	size_t minsz = offsetofend(struct vfio_device_feature, flags);
	struct vfio_device_feature feature;

	if (copy_from_user(&feature, arg, minsz))
		return -EFAULT;

	if (feature.argsz < minsz)
		return -EINVAL;

	/* Check unknown flags */
	if (feature.flags &
	    ~(VFIO_DEVICE_FEATURE_MASK | VFIO_DEVICE_FEATURE_SET |
	      VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_PROBE))
		return -EINVAL;

	/* GET & SET are mutually exclusive except with PROBE */
	if (!(feature.flags & VFIO_DEVICE_FEATURE_PROBE) &&
	    (feature.flags & VFIO_DEVICE_FEATURE_SET) &&
	    (feature.flags & VFIO_DEVICE_FEATURE_GET))
		return -EINVAL;

	switch (feature.flags & VFIO_DEVICE_FEATURE_MASK) {
	case VFIO_DEVICE_FEATURE_MIGRATION:
		return vfio_ioctl_device_feature_migration(
			device, feature.flags, arg->data,
			feature.argsz - minsz);
	case VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE:
		return vfio_ioctl_device_feature_mig_device_state(
			device, feature.flags, arg->data,
			feature.argsz - minsz);
	default:
		if (unlikely(!device->ops->device_feature))
			return -EINVAL;
		return device->ops->device_feature(device, feature.flags,
						   arg->data,
						   feature.argsz - minsz);
	}
}

static long vfio_device_fops_unl_ioctl(struct file *filep,
				       unsigned int cmd, unsigned long arg)
{
	struct vfio_device *device = filep->private_data;
	int ret;

	if (!device)
		return -EINVAL;

	ret = vfio_device_pm_runtime_get(device);
	if (ret)
		return ret;

	switch (cmd) {
	case VFIO_DEVICE_FEATURE:
		ret = vfio_ioctl_device_feature(device, (void __user *)arg);
		break;

	default:
		if (unlikely(!device->ops->ioctl))
			ret = -EINVAL;
		else
			ret = device->ops->ioctl(device, cmd, arg);
		break;
	}

	vfio_device_pm_runtime_put(device);
	return ret;
}

static ssize_t vfio_device_fops_read(struct file *filep, char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct vfio_device *device = filep->private_data;

	if (!device || unlikely(!device->ops->read))
		return -EINVAL;

	return device->ops->read(device, buf, count, ppos);
}

static ssize_t vfio_device_fops_write(struct file *filep,
				      const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct vfio_device *device = filep->private_data;

	if (!device || unlikely(!device->ops->write))
		return -EINVAL;

	return device->ops->write(device, buf, count, ppos);
}

static int vfio_device_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct vfio_device *device = filep->private_data;

	if (!device || unlikely(!device->ops->mmap))
		return -EINVAL;

	return device->ops->mmap(device, vma);
}

const struct file_operations vfio_device_fops = {
	.owner		= THIS_MODULE,
	.open		= vfio_device_fops_open,
	.release	= vfio_device_fops_release,
	.read		= vfio_device_fops_read,
	.write		= vfio_device_fops_write,
	.unlocked_ioctl	= vfio_device_fops_unl_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.mmap		= vfio_device_fops_mmap,
};

/**
 * vfio_file_enforced_coherent - True if the DMA associated with the VFIO file
 *        is always CPU cache coherent
 * @file: VFIO group file
 *
 * Enforced coherency means that the IOMMU ignores things like the PCIe no-snoop
 * bit in DMA transactions. A return of false indicates that the user has
 * rights to access additional instructions such as wbinvd on x86.
 */
bool vfio_file_enforced_coherent(struct file *file)
{
	struct vfio_group *group = file->private_data;

	if (!vfio_is_group_file(file))
		return true;

	return vfio_group_enforced_coherent(group);
}
EXPORT_SYMBOL_GPL(vfio_file_enforced_coherent);

/**
 * vfio_file_set_kvm - Link a kvm with VFIO drivers
 * @file: VFIO group file
 * @kvm: KVM to link
 *
 * When a VFIO device is first opened the KVM will be available in
 * device->kvm if one was associated with the group.
 */
void vfio_file_set_kvm(struct file *file, struct kvm *kvm)
{
	struct vfio_group *group = file->private_data;

	if (!vfio_is_group_file(file))
		return;

	vfio_group_set_kvm(group, kvm);
}
EXPORT_SYMBOL_GPL(vfio_file_set_kvm);

/**
 * vfio_file_has_dev - True if the VFIO file is a handle for device
 * @file: VFIO file to check
 * @device: Device that must be part of the file
 *
 * Returns true if given file has permission to manipulate the given device.
 */
bool vfio_file_has_dev(struct file *file, struct vfio_device *device)
{
	struct vfio_group *group = file->private_data;

	if (!vfio_is_group_file(file))
		return false;

	return vfio_group_has_dev(group, device);
}
EXPORT_SYMBOL_GPL(vfio_file_has_dev);

/*
 * Sub-module support
 */
/*
 * Helper for managing a buffer of info chain capabilities, allocate or
 * reallocate a buffer with additional @size, filling in @id and @version
 * of the capability.  A pointer to the new capability is returned.
 *
 * NB. The chain is based at the head of the buffer, so new entries are
 * added to the tail, vfio_info_cap_shift() should be called to fixup the
 * next offsets prior to copying to the user buffer.
 */
struct vfio_info_cap_header *vfio_info_cap_add(struct vfio_info_cap *caps,
					       size_t size, u16 id, u16 version)
{
	void *buf;
	struct vfio_info_cap_header *header, *tmp;

	buf = krealloc(caps->buf, caps->size + size, GFP_KERNEL);
	if (!buf) {
		kfree(caps->buf);
		caps->buf = NULL;
		caps->size = 0;
		return ERR_PTR(-ENOMEM);
	}

	caps->buf = buf;
	header = buf + caps->size;

	/* Eventually copied to user buffer, zero */
	memset(header, 0, size);

	header->id = id;
	header->version = version;

	/* Add to the end of the capability chain */
	for (tmp = buf; tmp->next; tmp = buf + tmp->next)
		; /* nothing */

	tmp->next = caps->size;
	caps->size += size;

	return header;
}
EXPORT_SYMBOL_GPL(vfio_info_cap_add);

void vfio_info_cap_shift(struct vfio_info_cap *caps, size_t offset)
{
	struct vfio_info_cap_header *tmp;
	void *buf = (void *)caps->buf;

	for (tmp = buf; tmp->next; tmp = buf + tmp->next - offset)
		tmp->next += offset;
}
EXPORT_SYMBOL(vfio_info_cap_shift);

int vfio_info_add_capability(struct vfio_info_cap *caps,
			     struct vfio_info_cap_header *cap, size_t size)
{
	struct vfio_info_cap_header *header;

	header = vfio_info_cap_add(caps, size, cap->id, cap->version);
	if (IS_ERR(header))
		return PTR_ERR(header);

	memcpy(header + 1, cap + 1, size - sizeof(*header));

	return 0;
}
EXPORT_SYMBOL(vfio_info_add_capability);

int vfio_set_irqs_validate_and_prepare(struct vfio_irq_set *hdr, int num_irqs,
				       int max_irq_type, size_t *data_size)
{
	unsigned long minsz;
	size_t size;

	minsz = offsetofend(struct vfio_irq_set, count);

	if ((hdr->argsz < minsz) || (hdr->index >= max_irq_type) ||
	    (hdr->count >= (U32_MAX - hdr->start)) ||
	    (hdr->flags & ~(VFIO_IRQ_SET_DATA_TYPE_MASK |
				VFIO_IRQ_SET_ACTION_TYPE_MASK)))
		return -EINVAL;

	if (data_size)
		*data_size = 0;

	if (hdr->start >= num_irqs || hdr->start + hdr->count > num_irqs)
		return -EINVAL;

	switch (hdr->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
	case VFIO_IRQ_SET_DATA_NONE:
		size = 0;
		break;
	case VFIO_IRQ_SET_DATA_BOOL:
		size = sizeof(uint8_t);
		break;
	case VFIO_IRQ_SET_DATA_EVENTFD:
		size = sizeof(int32_t);
		break;
	default:
		return -EINVAL;
	}

	if (size) {
		if (hdr->argsz - minsz < hdr->count * size)
			return -EINVAL;

		if (!data_size)
			return -EINVAL;

		*data_size = hdr->count * size;
	}

	return 0;
}
EXPORT_SYMBOL(vfio_set_irqs_validate_and_prepare);

/*
 * Pin contiguous user pages and return their associated host pages for local
 * domain only.
 * @device [in]  : device
 * @iova [in]    : starting IOVA of user pages to be pinned.
 * @npage [in]   : count of pages to be pinned.  This count should not
 *		   be greater than VFIO_PIN_PAGES_MAX_ENTRIES.
 * @prot [in]    : protection flags
 * @pages[out]   : array of host pages
 * Return error or number of pages pinned.
 *
 * A driver may only call this function if the vfio_device was created
 * by vfio_register_emulated_iommu_dev() due to vfio_container_pin_pages().
 */
int vfio_pin_pages(struct vfio_device *device, dma_addr_t iova,
		   int npage, int prot, struct page **pages)
{
	if (!pages || !npage || !vfio_assert_device_open(device))
		return -EINVAL;
	if (vfio_group_has_container(device->group))
		return vfio_container_pin_pages(device, iova, npage, prot, pages);
	if (device->iommufd_access) {
		if (iova > ULONG_MAX)
			return -EINVAL;
		return iommufd_access_pin_pages(device->iommufd_access, iova,
						npage * PAGE_SIZE, pages,
						prot & IOMMU_WRITE);
	}
	return -EINVAL;
}
EXPORT_SYMBOL(vfio_pin_pages);

/*
 * Unpin contiguous host pages for local domain only.
 * @device [in]  : device
 * @iova [in]    : starting address of user pages to be unpinned.
 * @npage [in]   : count of pages to be unpinned.  This count should not
 *                 be greater than VFIO_PIN_PAGES_MAX_ENTRIES.
 */
void vfio_unpin_pages(struct vfio_device *device, dma_addr_t iova, int npage)
{
	if (WARN_ON(!vfio_assert_device_open(device)))
		return;

	if (vfio_group_has_container(device->group)) {
		vfio_container_unpin_pages(device, iova, npage);
	} else if (device->iommufd_access) {
		if (WARN_ON(iova > ULONG_MAX))
			return;
		iommufd_access_unpin_pages(device->iommufd_access, iova,
					   npage * PAGE_SIZE);
	}
}
EXPORT_SYMBOL(vfio_unpin_pages);

/*
 * This interface allows the CPUs to perform some sort of virtual DMA on
 * behalf of the device.
 *
 * CPUs read/write from/into a range of IOVAs pointing to user space memory
 * into/from a kernel buffer.
 *
 * As the read/write of user space memory is conducted via the CPUs and is
 * not a real device DMA, it is not necessary to pin the user space memory.
 *
 * @device [in]		: VFIO device
 * @iova [in]		: base IOVA of a user space buffer
 * @data [in]		: pointer to kernel buffer
 * @len [in]		: kernel buffer length
 * @write		: indicate read or write
 * Return error code on failure or 0 on success.
 */
int vfio_dma_rw(struct vfio_device *device, dma_addr_t iova, void *data,
		size_t len, bool write)
{
	if (!data || len <= 0 || !vfio_assert_device_open(device))
		return -EINVAL;

	if (vfio_group_has_container(device->group))
		return vfio_container_dma_rw(device, iova, data, len, write);

	if (device->iommufd_access) {
		if (iova > ULONG_MAX)
			return -EINVAL;
		return iommufd_access_rw(device->iommufd_access, iova, data,
					 len, write);
	}
	return -EINVAL;
}
EXPORT_SYMBOL(vfio_dma_rw);

/*
 * Module/class support
 */
static char *vfio_device_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "vfio/devices/%s", dev_name(dev));
}

static int __init vfio_init(void)
{
	int ret;

	ida_init(&vfio.device_ida);
	mutex_init(&vfio.device_lock);
	INIT_LIST_HEAD(&vfio.device_list);

	ret = vfio_container_init();
	if (ret)
		return ret;

	ret = vfio_group_init();
	if (ret)
		goto err_group_init;

	/* /sys/class/vfio-dev/vfioX */
	vfio.device_class = class_create(THIS_MODULE, "vfio-dev");
	if (IS_ERR(vfio.device_class)) {
		ret = PTR_ERR(vfio.device_class);
		goto err_dev_class;
	}

	vfio.device_class->devnode = vfio_device_devnode;
	ret = alloc_chrdev_region(&vfio.device_devt, 0,
				  MINORMASK + 1, "vfio-dev");
	if (ret)
		goto err_alloc_dev_chrdev;

	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");
	return 0;

err_alloc_dev_chrdev:
	class_destroy(vfio.device_class);
	vfio.device_class = NULL;
err_dev_class:
	vfio_group_cleanup();
err_group_init:
	vfio_container_cleanup();
	return ret;
}

static void __exit vfio_cleanup(void)
{
	WARN_ON(!list_empty(&vfio.device_list));
	ida_destroy(&vfio.device_ida);
	unregister_chrdev_region(vfio.device_devt, MINORMASK + 1);
	class_destroy(vfio.device_class);
	vfio.device_class = NULL;
	vfio_group_cleanup();
	vfio_container_cleanup();
	xa_destroy(&vfio_device_set_xa);
}

module_init(vfio_init);
module_exit(vfio_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_ALIAS_MISCDEV(VFIO_MINOR);
MODULE_ALIAS("devname:vfio/vfio");
MODULE_SOFTDEP("post: vfio_iommu_type1 vfio_iommu_spapr_tce");
