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
	struct mlx5_core_dev *mdev = priv->mdev;
	int user_rate, rate;
	int err;

	if (sscanf(buf, "%d", &user_rate) != 1)
		return -EINVAL;

	if (user_rate == g->rate)
		/* nothing to do */
		return count;

	if (!mlx5_rl_is_supported(mdev)) {
		netdev_err(priv->netdev, "Rate limiting is not supported on this device\n");
		return -EINVAL;
	}

	/* rate is given in Mb/sec, HW config is in Kb/sec */
	rate = user_rate << 10;

	/* Check whether rate in valid range, 0 is always valid */
	if (rate && !mlx5_rl_is_in_range(mdev, rate)) {
		netdev_err(priv->netdev, "TX rate %u, is not in range\n", rate);
		return -ERANGE;
	}

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		err = mlx5e_set_prio_hairpin_rate(priv, g->prio, rate);
	if (err) {
		mutex_unlock(&priv->state_lock);

		return err;
	}

	g->rate = user_rate;
	mutex_unlock(&priv->state_lock);

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

#define MLX5E_MAX_HP_PP_BURST_SIZE (30 * 1514)
static ssize_t pp_burst_size_store(struct device *device, struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	int burst_size;
	int err;

	err = sscanf(buf, "%d", &burst_size);
	if (err != 1)
		return -EINVAL;

	if (burst_size < 0 || burst_size > MLX5E_MAX_HP_PP_BURST_SIZE)
		return -EINVAL;

	rtnl_lock();
	mutex_lock(&priv->state_lock);

	tc->max_pp_burst_size = burst_size;

	mutex_unlock(&priv->state_lock);
	rtnl_unlock();

	return count;
}

static ssize_t pp_burst_size_show(struct device *device, struct device_attribute *attr,
				  char *buf)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	ssize_t result;


	mutex_lock(&priv->state_lock);
	result = sprintf(buf, "%d\n", tc->max_pp_burst_size);
	mutex_unlock(&priv->state_lock);

	return result;
}

static DEVICE_ATTR(num_prio_hp, S_IRUGO | S_IWUSR,
		   prio_hp_num_show, prio_hp_num_store);
static DEVICE_ATTR(hp_pp_burst_size, S_IRUGO | S_IWUSR,
		   pp_burst_size_show, pp_burst_size_store);

static struct device_attribute *mlx5_class_attributes[] = {
	&dev_attr_num_prio_hp,
	&dev_attr_hp_pp_burst_size,
};

int mlx5e_tc_sysfs_init(struct mlx5e_priv *priv)
{
	struct device *device = &priv->netdev->dev;
	int i, err;

	for (i = 0; i < ARRAY_SIZE(mlx5_class_attributes); i++) {
		err = device_create_file(device, mlx5_class_attributes[i]);
		if (err)
			return err;
	}

	return 0;
}

void mlx5e_tc_sysfs_cleanup(struct mlx5e_priv *priv)
{
	struct device *device = &priv->netdev->dev;
	int i;

	for (i = 0; i < ARRAY_SIZE(mlx5_class_attributes); i++)
		device_remove_file(device, mlx5_class_attributes[i]);
}
