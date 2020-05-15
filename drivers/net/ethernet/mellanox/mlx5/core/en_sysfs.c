/*
 * Copyright (c) 2014, Mellanox Technologies inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/etherdevice.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>
#include "mlx5_core.h"
#include "en_tc.h"
#include "en_sysfs.h"
#include "en/fs.h"

struct prio_hp_attributes {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_prio_hp *, struct prio_hp_attributes *,
			char *buf);
	ssize_t (*store)(struct mlx5_prio_hp *, struct prio_hp_attributes *,
			 const char *buf, size_t count);
};

static ssize_t prio_hp_attr_show(struct kobject *kobj,
				 struct attribute *attr, char *buf)
{
	struct prio_hp_attributes *ga =
		container_of(attr, struct prio_hp_attributes, attr);
	struct mlx5_prio_hp *g = container_of(kobj, struct mlx5_prio_hp, kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t prio_hp_attr_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buf, size_t size)
{
	struct prio_hp_attributes *ga =
		container_of(attr, struct prio_hp_attributes, attr);
	struct mlx5_prio_hp *g = container_of(kobj, struct mlx5_prio_hp, kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

static const struct sysfs_ops prio_hp_ops = {
	.show = prio_hp_attr_show,
	.store = prio_hp_attr_store,
};

static ssize_t rate_store(struct mlx5_prio_hp *g,
			   struct prio_hp_attributes *oa,
			   const char *buf,
			   size_t count)
{
	struct mlx5e_priv *priv = g->priv;
	int rate;

	if (sscanf(buf, "%d", &rate) != 1)
		return -EINVAL;

	if (g->rate == rate)
		return count;

	g->rate = rate;

	/* Update rate limit of hp prio g->prio */
	return count;
}

static ssize_t rate_show(struct mlx5_prio_hp *g, struct prio_hp_attributes *oa,
			   char *buf)
{
	return sprintf(buf, "%d\n", g->rate);
}

#define PRIO_HP_ATTR(_name) struct prio_hp_attributes prio_hp_attr_##_name = \
	__ATTR(_name, 0644, _name##_show, _name##_store)
PRIO_HP_ATTR(rate);

static struct attribute *prio_hp_attrs[] = {
	&prio_hp_attr_rate.attr,
	NULL
};

static struct kobj_type prio_hp_sysfs = {
	.sysfs_ops     = &prio_hp_ops,
	.default_attrs = prio_hp_attrs
};

int create_prio_hp_sysfs(struct mlx5e_priv *priv, int prio)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_prio_hp *prio_hp = tc->prio_hp;
	int err;

	err = kobject_init_and_add(&prio_hp[prio].kobj, &prio_hp_sysfs, tc->hp_config,
				   "%d", prio);
	if (err) {
		netdev_err(priv->netdev, "can't create hp queues per q sysfs %d, err %d\n", prio, err);
		return err;
	}

	kobject_uevent(&prio_hp[prio].kobj, KOBJ_ADD);

	return 0;
}

static ssize_t prio_hp_num_store(struct device *device, struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	int num_hp;
	int err;

	err = sscanf(buf, "%d", &num_hp);
	if (err != 1)
		return -EINVAL;

	if (num_hp < 0 || num_hp > MLX5E_MAX_HP_PRIO)
		return -EINVAL;

	rtnl_lock();
	mutex_lock(&priv->state_lock);

	if (num_hp && !tc->num_prio_hp) {
		err = mlx5e_prio_hairpin_mode_enable(priv, num_hp);
		if (err)
			goto err_config;
	} else if (!num_hp && tc->num_prio_hp) {
		err = mlx5e_prio_hairpin_mode_disable(priv);
		if (err)
			goto err_config;
	} else {
		err = -EINVAL;
		goto err_config;
	}

	mutex_unlock(&priv->state_lock);
	rtnl_unlock();

	return count;

err_config:
	mutex_unlock(&priv->state_lock);
	rtnl_unlock();
	return err;
}

static ssize_t prio_hp_num_show(struct device *device, struct device_attribute *attr,
				char *buf)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	ssize_t result;


	mutex_lock(&priv->state_lock);
	result = sprintf(buf, "%d\n", tc->num_prio_hp);
	mutex_unlock(&priv->state_lock);

	return result;
}

static DEVICE_ATTR(num_prio_hp, S_IRUGO | S_IWUSR,
		   prio_hp_num_show, prio_hp_num_store);

static struct device_attribute *mlx5_class_attributes[] = {
	&dev_attr_num_prio_hp,
};

int mlx5e_tc_sysfs_init(struct mlx5e_priv *priv)
{
	struct device *device = &priv->netdev->dev;
	int err;

	err = device_create_file(device, mlx5_class_attributes[0]);
	if (err)
		return err;

	return 0;
}

void mlx5e_tc_sysfs_cleanup(struct mlx5e_priv *priv)
{
	struct device *device = &priv->netdev->dev;

	device_remove_file(device, mlx5_class_attributes[0]);
}
