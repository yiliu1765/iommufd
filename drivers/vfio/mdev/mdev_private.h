/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Mediated device internal definitions
 *
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved.
 *     Author: Neo Jia <cjia@nvidia.com>
 *             Kirti Wankhede <kwankhede@nvidia.com>
 */

#ifndef MDEV_PRIVATE_H
#define MDEV_PRIVATE_H

int  mdev_bus_register(void);
void mdev_bus_unregister(void);

extern const struct attribute_group *mdev_device_groups[];

#define to_mdev_type_attr(_attr)	\
	container_of(_attr, struct mdev_type_attribute, attr)
#define to_mdev_type(_kobj)		\
	container_of(_kobj, struct mdev_type, kobj)

int mdev_type_add(struct mdev_parent *parent, struct mdev_type *type);
void mdev_type_remove(struct mdev_type *type);

int mdev_device_create(struct mdev_type *kobj, const guid_t *uuid);
int  mdev_device_remove(struct mdev_device *dev);

#endif /* MDEV_PRIVATE_H */
