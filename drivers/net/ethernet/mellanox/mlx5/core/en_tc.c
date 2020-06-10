/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
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

#include <net/flow_dissector.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_skbedit.h>
#include <linux/mlx5/fs.h>
#include <linux/mlx5/device.h>
#include <linux/rhashtable.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <net/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_csum.h>
#include <net/arp.h>
#include <net/ipv6_stubs.h>
#include "en.h"
#include "en_rep.h"
#include "en_tc.h"
#include "en_sysfs.h"
#include "eswitch.h"
#include "fs_core.h"
#include "en/port.h"
#include "en/tc_tun.h"
#include "en/tc_ct.h"
#include "lib/devcom.h"
#include "lib/geneve.h"

#define MLX5_MH_ACT_SZ MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto)

static inline u32 hash_mod_hdr_info(struct mod_hdr_key *key)
{
	return jhash(key->actions,
		     key->num_actions * MLX5_MH_ACT_SZ, 0);
}

static inline int cmp_mod_hdr_info(struct mod_hdr_key *a,
				   struct mod_hdr_key *b)
{
	if (a->num_actions != b->num_actions)
		return 1;

	return memcmp(a->actions, b->actions, a->num_actions * MLX5_MH_ACT_SZ);
}

static int mlx5e_attach_mod_hdr(struct mlx5e_priv *priv,
				struct mlx5e_tc_flow *flow,
				struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int num_actions, actions_size, namespace, err;
	struct mlx5e_mod_hdr_entry *mh;
	struct mod_hdr_key key;
	bool found = false;
	u32 hash_key;

	num_actions  = parse_attr->num_mod_hdr_actions;
	actions_size = MLX5_MH_ACT_SZ * num_actions;

	key.actions = parse_attr->mod_hdr_actions;
	key.num_actions = num_actions;

	hash_key = hash_mod_hdr_info(&key);

	if (mlx5e_is_eswitch_flow(flow)) {
		namespace = MLX5_FLOW_NAMESPACE_FDB;
		hash_for_each_possible(esw->offloads.mod_hdr_tbl, mh,
				       mod_hdr_hlist, hash_key) {
			if (!cmp_mod_hdr_info(&mh->key, &key)) {
				found = true;
				break;
			}
		}
	} else {
		namespace = MLX5_FLOW_NAMESPACE_KERNEL;
		hash_for_each_possible(priv->fs.tc.mod_hdr_tbl, mh,
				       mod_hdr_hlist, hash_key) {
			if (!cmp_mod_hdr_info(&mh->key, &key)) {
				found = true;
				break;
			}
		}
	}

	if (found)
		goto attach_flow;

	mh = kzalloc(sizeof(*mh) + actions_size, GFP_KERNEL);
	if (!mh)
		return -ENOMEM;

	mh->key.actions = (void *)mh + sizeof(*mh);
	memcpy(mh->key.actions, key.actions, actions_size);
	mh->key.num_actions = num_actions;
	INIT_LIST_HEAD(&mh->flows);

	err = mlx5_modify_header_alloc(priv->mdev, namespace,
				       mh->key.num_actions,
				       mh->key.actions,
				       &mh->mod_hdr_id);
	if (err)
		goto out_err;

	if (mlx5e_is_eswitch_flow(flow))
		hash_add(esw->offloads.mod_hdr_tbl, &mh->mod_hdr_hlist, hash_key);
	else
		hash_add(priv->fs.tc.mod_hdr_tbl, &mh->mod_hdr_hlist, hash_key);

attach_flow:
	list_add(&flow->mod_hdr, &mh->flows);
	flow->attr.mod_hdr_id = mh->mod_hdr_id;

	return 0;

out_err:
	kfree(mh);
	return err;
}

static void mlx5e_detach_mod_hdr(struct mlx5e_priv *priv,
				 struct mlx5e_tc_flow *flow)
{
	struct list_head *next = flow->mod_hdr.next;

	list_del(&flow->mod_hdr);

	if (list_empty(next)) {
		struct mlx5e_mod_hdr_entry *mh;

		mh = list_entry(next, struct mlx5e_mod_hdr_entry, flows);

		mlx5_modify_header_dealloc(priv->mdev, mh->mod_hdr_id);
		hash_del(&mh->mod_hdr_hlist);
		kfree(mh);
	}
}

static
struct mlx5_core_dev *mlx5e_hairpin_get_mdev(struct net *net, int ifindex)
{
	struct net_device *netdev;
	struct mlx5e_priv *priv;

	netdev = __dev_get_by_index(net, ifindex);
	priv = netdev_priv(netdev);
	return priv->mdev;
}

static int mlx5e_hairpin_create_transport(struct mlx5e_hairpin *hp)
{
	u32 in[MLX5_ST_SZ_DW(create_tir_in)] = {0};
	void *tirc;
	int err;

	err = mlx5_core_alloc_transport_domain(hp->func_mdev, &hp->tdn);
	if (err)
		goto alloc_tdn_err;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
	MLX5_SET(tirc, tirc, inline_rqn, hp->pair->rqn[0]);
	MLX5_SET(tirc, tirc, transport_domain, hp->tdn);

	err = mlx5_core_create_tir(hp->func_mdev, in, MLX5_ST_SZ_BYTES(create_tir_in), &hp->tirn);
	if (err)
		goto create_tir_err;

	return 0;

create_tir_err:
	mlx5_core_dealloc_transport_domain(hp->func_mdev, hp->tdn);
alloc_tdn_err:
	return err;
}

static void mlx5e_hairpin_destroy_transport(struct mlx5e_hairpin *hp)
{
	mlx5_core_destroy_tir(hp->func_mdev, hp->tirn);
	mlx5_core_dealloc_transport_domain(hp->func_mdev, hp->tdn);
}

static void mlx5e_hairpin_fill_rqt_rqns(struct mlx5e_hairpin *hp, void *rqtc)
{
	u32 indirection_rqt[MLX5E_INDIR_RQT_SIZE], rqn;
	struct mlx5e_priv *priv = hp->func_priv;
	int i, ix, sz = MLX5E_INDIR_RQT_SIZE;

	mlx5e_build_default_indir_rqt(indirection_rqt, sz,
				      hp->num_channels);

	for (i = 0; i < sz; i++) {
		ix = i;
		if (priv->rss_params.hfunc == ETH_RSS_HASH_XOR)
			ix = mlx5e_bits_invert(i, ilog2(sz));
		ix = indirection_rqt[ix];
		rqn = hp->pair->rqn[ix];
		MLX5_SET(rqtc, rqtc, rq_num[i], rqn);
	}
}

static int mlx5e_hairpin_create_indirect_rqt(struct mlx5e_hairpin *hp)
{
	int inlen, err, sz = MLX5E_INDIR_RQT_SIZE;
	struct mlx5e_priv *priv = hp->func_priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	void *rqtc;
	u32 *in;

	inlen = MLX5_ST_SZ_BYTES(create_rqt_in) + sizeof(u32) * sz;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	rqtc = MLX5_ADDR_OF(create_rqt_in, in, rqt_context);

	MLX5_SET(rqtc, rqtc, rqt_actual_size, sz);
	MLX5_SET(rqtc, rqtc, rqt_max_size, sz);

	mlx5e_hairpin_fill_rqt_rqns(hp, rqtc);

	err = mlx5_core_create_rqt(mdev, in, inlen, &hp->indir_rqt.rqtn);
	if (!err)
		hp->indir_rqt.enabled = true;

	kvfree(in);
	return err;
}

static int mlx5e_hairpin_create_indirect_tirs(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;
	u32 in[MLX5_ST_SZ_DW(create_tir_in)];
	int tt, i, err;
	void *tirc;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++) {
		struct mlx5e_tirc_config ttconfig = mlx5e_tirc_get_default_config(tt);

		memset(in, 0, MLX5_ST_SZ_BYTES(create_tir_in));
		tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

		MLX5_SET(tirc, tirc, transport_domain, hp->tdn);
		MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_INDIRECT);
		MLX5_SET(tirc, tirc, indirect_table, hp->indir_rqt.rqtn);
		mlx5e_build_indir_tir_ctx_hash(&priv->rss_params, &ttconfig, tirc, false);

		err = mlx5_core_create_tir(hp->func_mdev, in,
					   MLX5_ST_SZ_BYTES(create_tir_in), &hp->indir_tirn[tt]);
		if (err) {
			mlx5_core_warn(hp->func_mdev, "create indirect tirs failed, %d\n", err);
			goto err_destroy_tirs;
		}
	}
	return 0;

err_destroy_tirs:
	for (i = 0; i < tt; i++)
		mlx5_core_destroy_tir(hp->func_mdev, hp->indir_tirn[i]);
	return err;
}

static void mlx5e_hairpin_destroy_indirect_tirs(struct mlx5e_hairpin *hp)
{
	int tt;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++)
		mlx5_core_destroy_tir(hp->func_mdev, hp->indir_tirn[tt]);
}

static void mlx5e_hairpin_set_ttc_params(struct mlx5e_hairpin *hp,
					 struct ttc_params *ttc_params)
{
	struct mlx5_flow_table_attr *ft_attr = &ttc_params->ft_attr;
	int tt;

	memset(ttc_params, 0, sizeof(*ttc_params));

	ttc_params->any_tt_tirn = hp->tirn;

	for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++)
		ttc_params->indir_tirn[tt] = hp->indir_tirn[tt];

	ft_attr->max_fte = MLX5E_TTC_TABLE_SIZE;
	ft_attr->level = MLX5E_TC_TTC_FT_LEVEL;
	ft_attr->prio = MLX5E_TC_PRIO;
}

static int mlx5e_hairpin_rss_init(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;
	struct ttc_params ttc_params;
	int err;

	err = mlx5e_hairpin_create_indirect_rqt(hp);
	if (err)
		return err;

	err = mlx5e_hairpin_create_indirect_tirs(hp);
	if (err)
		goto err_create_indirect_tirs;

	mlx5e_hairpin_set_ttc_params(hp, &ttc_params);
	err = mlx5e_create_ttc_table(priv, &ttc_params, &hp->ttc);
	if (err)
		goto err_create_ttc_table;

	netdev_dbg(priv->netdev, "add hairpin: using %d channels rss ttc table id %x\n",
		   hp->num_channels, hp->ttc.ft.t->id);

	return 0;

err_create_ttc_table:
	mlx5e_hairpin_destroy_indirect_tirs(hp);
err_create_indirect_tirs:
	mlx5e_destroy_rqt(priv, &hp->indir_rqt);

	return err;
}

static void mlx5e_hairpin_rss_cleanup(struct mlx5e_hairpin *hp)
{
	struct mlx5e_priv *priv = hp->func_priv;

	mlx5e_destroy_ttc_table(priv, &hp->ttc);
	mlx5e_hairpin_destroy_indirect_tirs(hp);
	mlx5e_destroy_rqt(priv, &hp->indir_rqt);
}

static struct mlx5e_hairpin *
mlx5e_hairpin_create(struct mlx5e_priv *priv, struct mlx5_hairpin_params *params,
		     struct mlx5_core_dev *peer_mdev)
{
	struct mlx5_core_dev *func_mdev;
	struct mlx5e_hairpin *hp;
	struct mlx5_hairpin *pair;
	int err;

	hp = kzalloc(sizeof(*hp), GFP_KERNEL);
	if (!hp)
		return ERR_PTR(-ENOMEM);

	func_mdev = priv->mdev;

	pair = mlx5_core_hairpin_create(func_mdev, peer_mdev, params);
	if (IS_ERR(pair)) {
		err = PTR_ERR(pair);
		goto create_pair_err;
	}
	hp->pair = pair;
	hp->func_mdev = func_mdev;
	hp->func_priv = priv;
	hp->num_channels = params->num_channels;

	err = mlx5e_hairpin_create_transport(hp);
	if (err)
		goto create_transport_err;

	if (hp->num_channels > 1) {
		err = mlx5e_hairpin_rss_init(hp);
		if (err)
			goto rss_init_err;
	}

	return hp;

rss_init_err:
	mlx5e_hairpin_destroy_transport(hp);
create_transport_err:
	mlx5_core_hairpin_destroy(hp->pair);
create_pair_err:
	kfree(hp);
	return ERR_PTR(err);
}

static void mlx5e_hairpin_destroy(struct mlx5e_hairpin *hp)
{
	if (hp->num_channels > 1)
		mlx5e_hairpin_rss_cleanup(hp);
	mlx5e_hairpin_destroy_transport(hp);
	mlx5_core_hairpin_destroy(hp->pair);
	kvfree(hp);
}

static inline u32 hash_hairpin_info(u16 peer_vhca_id, u16 prio)
{
	return (peer_vhca_id << 16 | prio);
}

static struct mlx5e_hairpin_entry *mlx5e_hairpin_get(struct mlx5e_priv *priv,
						     u16 peer_vhca_id, u16 prio)
{
	struct mlx5e_hairpin_entry *hpe;
	u32 hash_key = hash_hairpin_info(peer_vhca_id, prio);

	hash_for_each_possible(priv->fs.tc.hairpin_tbl, hpe,
			       hairpin_hlist, hash_key) {
		if (hpe->peer_vhca_id == peer_vhca_id && hpe->prio == prio)
			return hpe;
	}

	return NULL;
}

#define UNKNOWN_MATCH_PRIO 8

static int mlx5e_hairpin_get_prio(struct mlx5e_priv *priv,
				  struct mlx5_flow_spec *spec,
				  u16 user_prio, u16 *match_prio,
				  struct netlink_ext_ack *extack)
{
	void *headers_c, *headers_v;
	u8 prio_val, prio_mask = 0;
	bool vlan_present;

	if (priv->fs.tc.num_prio_hp) {
		*match_prio = user_prio + UNKNOWN_MATCH_PRIO;

		return 0;
	}

#ifdef CONFIG_MLX5_CORE_EN_DCB
	if (priv->dcbx_dp.trust_state != MLX5_QPTS_TRUST_PCP) {
		NL_SET_ERR_MSG_MOD(extack,
				   "only PCP trust state supported for hairpin");
		return -EOPNOTSUPP;
	}
#endif
	headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, outer_headers);
	headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value, outer_headers);

	vlan_present = MLX5_GET(fte_match_set_lyr_2_4, headers_v, cvlan_tag);
	if (vlan_present) {
		prio_mask = MLX5_GET(fte_match_set_lyr_2_4, headers_c, first_prio);
		prio_val = MLX5_GET(fte_match_set_lyr_2_4, headers_v, first_prio);
	}

	if (!vlan_present || !prio_mask) {
		prio_val = 0;
	} else if (prio_mask != 0x7) {
		NL_SET_ERR_MSG_MOD(extack,
				   "masked priority match not supported for hairpin");
		return -EOPNOTSUPP;
	}

	*match_prio = prio_val;
	return 0;
}

struct mlx5e_hairpin_entry *mlx5e_get_hairpin_entry(struct mlx5e_priv *priv,
						    struct mlx5_core_dev *peer_dev,
						    u16 match_prio)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_hairpin_params params;
	struct mlx5e_hairpin_entry *hpe;
	struct mlx5e_hairpin *hp;
	u64 link_speed64;
	u32 link_speed;
	u16 peer_id;

	peer_id = MLX5_CAP_GEN(peer_dev, vhca_id);
	hpe = mlx5e_hairpin_get(priv, peer_id, match_prio);
	if (hpe)
		return hpe;

	hpe = kzalloc(sizeof(*hpe), GFP_KERNEL);
	if (!hpe)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&hpe->flows);
	hpe->peer_vhca_id = peer_id;
	hpe->prio = match_prio;

/*	params.log_data_size = 15;
	params.log_data_size = min_t(u8, params.log_data_size,
				     MLX5_CAP_GEN(priv->mdev, log_max_hairpin_wq_data_sz));
	params.log_data_size = max_t(u8, params.log_data_size,
				     MLX5_CAP_GEN(priv->mdev, log_min_hairpin_wq_data_sz));*/
	params.log_data_size = MLX5_CAP_GEN(priv->mdev, log_max_hairpin_wq_data_sz);

	//params.log_num_packets = params.log_data_size - 10;
	params.log_num_packets = params.log_data_size -
				 MLX5_MPWRQ_MIN_LOG_STRIDE_SZ(priv->mdev);
	params.log_num_packets = min_t(u8, params.log_num_packets,
				       MLX5_CAP_GEN(priv->mdev, log_max_hairpin_num_packets));

	params.q_counter = priv->q_counter;
	/* set hairpin pair per each 50Gbs share of the link
	 * unless we are in priority hairpin mode.
	 */
	params.num_channels = 1;
	if (!tc->num_prio_hp) {
		mlx5e_port_max_linkspeed(priv->mdev, &link_speed);
		link_speed = max_t(u32, link_speed, 50000);
		link_speed64 = link_speed;
		do_div(link_speed64, 50000);
		params.num_channels = link_speed64;
	}

	hp = mlx5e_hairpin_create(priv, &params, peer_dev);
	if (IS_ERR(hp)) {
		kfree(hpe);
		return ERR_CAST(hp);
	}

	netdev_warn(priv->netdev, "add hairpin: tirn %x rqn %x peer %s sqn %x prio %d (log) data %d packets %d\n",
		   hp->tirn, hp->pair->rqn[0],
		   dev_name(hp->pair->peer_mdev->device),
		   hp->pair->sqn[0], match_prio, params.log_data_size, params.log_num_packets);

	hpe->hp = hp;
	hash_add(priv->fs.tc.hairpin_tbl, &hpe->hairpin_hlist,
		 hash_hairpin_info(peer_id, match_prio));

	return hpe;
}

static struct mlx5_flow_handle  *
mlx5e_add_prio_hp_flow(struct mlx5e_priv *priv,
		       struct mlx5e_hairpin_entry *hpe,
		       int prio)
{
	struct mlx5_flow_act flow_act = { .flags = FLOW_ACT_NO_APPEND, };
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_flow_spec s, *spec = &s;
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_flow_destination dest;
	struct mlx5_flow_table *ft;
	void *misc;

	ft = tc->hp_fwd;

	memset(spec, 0, sizeof(*spec));
	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc, metadata_reg_c_5, 0xFFFFFFFF);
	misc = MLX5_ADDR_OF(fte_match_param, spec->match_value, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc, metadata_reg_c_5, prio);
	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS_2;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	dest.tir_num = hpe->hp->tirn;
//	printk(KERN_ERR "%s %d %s @@ adding restore rule, tag: %d, copy_hdr_id: %d\n", __FILE__, __LINE__, __func__, tag, offload->restore_copy_hdr_id);
	flow_rule = mlx5_add_flow_rules(ft, spec, &flow_act, &dest, 1);

	if (IS_ERR(flow_rule))
		mlx5_core_warn(priv->mdev, "Failed to create hp fwd rule for prio: %d, err(%d)\n", prio, (int) PTR_ERR(flow_rule));

	//pr_err("created rule to fwd reg_c5=%d to tirn=%d\n", prio, dest.tir_num);
	return flow_rule;
}

static int mlx5e_prio_hairpin_init_queues(struct mlx5e_priv *priv)
{
	int num_queues = priv->fs.tc.num_prio_hp;
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5e_hairpin_entry *hpe;
	struct mlx5_core_dev *peer_mdev;
	struct hlist_node *tmp;
	u16 match_prio;
	int i, err;

	if (!num_queues)
		return 0;

	peer_mdev = mlx5_get_next_phys_dev(dev);
	if (!peer_mdev) {
		netdev_warn(priv->netdev, "Couldn't find peer dev to create prio hairpin queues\n");
		return -EINVAL;
	}

	if (!MLX5_CAP_GEN(priv->mdev, hairpin) || !MLX5_CAP_GEN(peer_mdev, hairpin)) {
		netdev_warn(priv->netdev, "hairpin is not supported");
		return -EOPNOTSUPP;
	}

	for (i = 0; i < num_queues; i++) {
		err = mlx5e_hairpin_get_prio(priv, NULL, i, &match_prio,
					     NULL);
		if (err)
			goto err_queues;

		hpe = mlx5e_get_hairpin_entry(priv, peer_mdev, match_prio);
		if (IS_ERR(hpe)) {
			err = PTR_ERR(hpe);
			goto err_queues;
		}

		hpe->fwd_rule = mlx5e_add_prio_hp_flow(priv, hpe, i);
		if (IS_ERR(hpe->fwd_rule)) {
			err = PTR_ERR(hpe->fwd_rule);
			goto err_queues;
		}
	}

	return 0;

err_queues:
	hash_for_each_safe(priv->fs.tc.hairpin_tbl, i, tmp,
			  hpe, hairpin_hlist) {
		if (hpe->fwd_rule)
			mlx5_del_flow_rules(hpe->fwd_rule);
		mlx5e_hairpin_destroy(hpe->hp);
		hash_del(&hpe->hairpin_hlist);
		kfree(hpe);
	}

	return err;
}

static void mlx5e_prio_hairpin_destroy_queues(struct mlx5e_priv *priv)
{
	struct mlx5e_hairpin_entry *hpe;
	struct mlx5_rate_limit rl = {0};
	struct mlx5_core_dev *peer_dev;
	struct hlist_node *tmp;
	int i;

	hash_for_each_safe(priv->fs.tc.hairpin_tbl, i, tmp,
			  hpe, hairpin_hlist) {
		if (hpe->fwd_rule)
			mlx5_del_flow_rules(hpe->fwd_rule);
		rl.rate = hpe->hp->rate_limit;
		peer_dev = hpe->hp->pair->peer_mdev;
		mlx5e_hairpin_destroy(hpe->hp);

		if (rl.rate)
			mlx5_rl_remove_rate(peer_dev, &rl);

		hash_del(&hpe->hairpin_hlist);
		kfree(hpe);
	}
}

int mlx5e_prio_hairpin_fwd_tbl_create(struct mlx5e_priv *priv, int num_hp)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_flow_namespace *ns;
	void *match_criteria, *misc;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *g;
	int err = 0;
	u32 *flow_group_in;

	ns = mlx5_get_flow_namespace(dev, MLX5_FLOW_NAMESPACE_KERNEL);
	if (!ns) {
		mlx5_core_warn(dev, "Failed to get restore ft namespace type:%d\n", MLX5_FLOW_NAMESPACE_KERNEL);
		return -EOPNOTSUPP;
	}

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in) {
		err = -ENOMEM;
		goto out_free;
	}

	ft_attr.unmanaged = true;
	ft_attr.max_fte = num_hp;
	ft_attr.level = MLX5E_TC_TTC_FT_LEVEL;
	ft_attr.prio = MLX5E_TC_PRIO;

	ft = mlx5_create_flow_table(ns, &ft_attr);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		mlx5_core_warn(dev, "Failed to create restore table, err %d\n", err);
		goto out_free;
	}

	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_MISC_PARAMETERS_2);

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);
	misc = MLX5_ADDR_OF(fte_match_param, match_criteria, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc, metadata_reg_c_5, 0xFFFFFFFF);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, ft_attr.max_fte - 1);
	g = mlx5_create_flow_group(ft, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		mlx5_core_warn(dev, "Failed to create restore flow group err(%d)\n", err);
		goto err_group;
	}

	//pr_err("created prio_hp forward2tir table size %d\n", ft_attr.max_fte);
	tc->hp_fwd = ft;
	tc->hp_fwd_g = g;
	atomic_set(&tc->hp_fwd_ref_cnt, 0);

	kvfree(flow_group_in);

	return 0;

err_group:
	mlx5_destroy_flow_table(ft);
out_free:
	kvfree(flow_group_in);

	return err;
}

void mlx5e_prio_hairpin_fwd_tbl_destroy(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;

	mlx5_destroy_flow_group(tc->hp_fwd_g);
	mlx5_destroy_flow_table(tc->hp_fwd);
	tc->hp_fwd = NULL;
}

int mlx5e_set_prio_hairpin_rate(struct mlx5e_priv *priv,
				u16 prio, int rate)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_modify_sq_param msp = {0};
	struct mlx5e_hairpin_entry *hpe;
	struct mlx5_rate_limit rl = {0};
	struct mlx5_core_dev *peer_mdev;
	struct mlx5e_hairpin *hp;
	u16 rl_index = 0;
	u16 match_prio;
	int err;

	peer_mdev = mlx5_get_next_phys_dev(mdev);
	if (!peer_mdev) {
		netdev_warn(priv->netdev, "Couldn't find peer dev to get hairpin queue entry\n");
		return -EINVAL;
	}

	err = mlx5e_hairpin_get_prio(priv, NULL, prio, &match_prio,
				     NULL);
	if (err) {
		netdev_warn(priv->netdev, "Set prio hairpin rate: Invalid hairpin priority %d\n",
			    prio);
		return -EINVAL;
	}

	hpe = mlx5e_get_hairpin_entry(priv, peer_mdev, match_prio);
	if (IS_ERR(hpe)) {
		err = PTR_ERR(hpe);
		netdev_warn(priv->netdev, "Set prio hairpin rate: Can't find hairpin entry, err %d\n",
			    err);
		return err;
	}

	hp = hpe->hp;
	if (hp->rate_limit) {
		//pr_err("releasing current prio %d rl %d\n", prio, hp->rate_limit);
		rl.rate = hp->rate_limit;
		rl.max_burst_sz = hp->max_pp_burst_size;
		/* remove current rl index to free space to next ones */
		mlx5_rl_remove_rate(peer_mdev, &rl);
	}

	hp->rate_limit = 0;

	if (rate) {
		//pr_err("trying to set rate %d to hp prio %d, sqn 0x%.8x\n", rate, prio, hp->pair->sqn[0]);
		rl.rate = rate;
		rl.max_burst_sz = tc->max_pp_burst_size;
		err = mlx5_rl_add_rate(peer_mdev, &rl_index, &rl);
		if (err) {
			netdev_err(priv->netdev, "Failed configuring rate %u: %d\n",
				   rate, err);
			return err;
		}
	}

	msp.curr_state = MLX5_SQC_STATE_RDY;
	msp.next_state = MLX5_SQC_STATE_RDY;
	msp.rl_index   = rl_index;
	msp.rl_update  = true;
	err = mlx5e_modify_sq(peer_mdev, hp->pair->sqn[0], &msp);
	if (err) {
		netdev_err(priv->netdev, "Failed configuring rate %u: %d\n",
			   rate, err);
		/* remove the rate from the table */
		if (rate)
			mlx5_rl_remove_rate(peer_mdev, &rl);
		return err;
	}

	hp->rate_limit = rate;
	hp->max_pp_burst_size = rate ? tc->max_pp_burst_size : 0;
	return 0;
}


int mlx5e_prio_hairpin_mode_enable(struct mlx5e_priv *priv, int num_hp)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_prio_hp *prio_hp;
	int err, i;

	tc->hp_config = kobject_create_and_add("hp_queues", &priv->netdev->dev.kobj);
	if (!tc->hp_config) {
		netdev_err(priv->netdev, "can't alloc hp_queues group\n");
		return -ENOMEM;
	}

	prio_hp = kcalloc(num_hp, sizeof(*prio_hp), GFP_KERNEL);
	if (!prio_hp) {
		netdev_err(priv->netdev, "can't alloc prio_hp queue of size %d\n", num_hp);
		err = -ENOMEM;
		goto err_array;
	}

	tc->prio_hp = prio_hp;
	/* Create sysfs entry per queue */
	for (i = 0; i < num_hp; i++) {
		err = create_prio_hp_sysfs(priv, i);
		if (err)
			goto err_sysfs;

		prio_hp[i].prio = i;
		prio_hp[i].priv = priv;
	}

	tc->num_prio_hp = num_hp;

	/* Creating prio2hp forwarding table */
	mlx5e_prio_hairpin_fwd_tbl_create(priv, num_hp);

	/* Create the prio hp queues */
	err = mlx5e_prio_hairpin_init_queues(priv);
	if (err) {
		netdev_err(priv->netdev, "Can't create %d prio hairpin queues, err %d\n", num_hp, err);
		goto err_queues;
	}

	return 0;

err_queues:
	mlx5e_prio_hairpin_fwd_tbl_destroy(priv);
err_sysfs:
	for (i--; i >= 0; i--)
		kobject_put(&tc->prio_hp[i].kobj);
	kfree(tc->prio_hp);
err_array:
	kobject_put(tc->hp_config);

	return err;
}

int mlx5e_prio_hairpin_mode_disable(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	int i = tc->num_prio_hp - 1;

	if (!tc->num_prio_hp)
		return 0;

	if (atomic_read(&tc->hp_fwd_ref_cnt)) {
		netdev_warn(priv->netdev, "Can't destroy hairpin fwd table, still have flows attached\n");
		return -EBUSY;
	}

	mlx5e_prio_hairpin_destroy_queues(priv);
	for (; i >= 0; i--) {
		kobject_put(&tc->prio_hp[i].kobj);
	}

	mlx5e_prio_hairpin_fwd_tbl_destroy(priv);
	kfree(tc->prio_hp);
	kobject_put(tc->hp_config);

	tc->num_prio_hp = 0;

	return 0;
}

static int mlx5e_hairpin_flow_add(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow,
				  struct mlx5e_tc_flow_parse_attr *parse_attr,
				  struct netlink_ext_ack *extack)
{
	int peer_ifindex = parse_attr->mirred_ifindex[0];
	struct mlx5_core_dev *peer_mdev;
	struct mlx5e_hairpin_entry *hpe;
	u16 match_prio;
	int err;

	if (priv->fs.tc.num_prio_hp)
		return 0;

	peer_mdev = mlx5e_hairpin_get_mdev(dev_net(priv->netdev), peer_ifindex);
	if (!MLX5_CAP_GEN(priv->mdev, hairpin) || !MLX5_CAP_GEN(peer_mdev, hairpin)) {
		NL_SET_ERR_MSG_MOD(extack, "hairpin is not supported");
		return -EOPNOTSUPP;
	}

	err = mlx5e_hairpin_get_prio(priv, &parse_attr->spec, 0, &match_prio,
				     extack);
	if (err)
		return err;

	hpe = mlx5e_get_hairpin_entry(priv, peer_mdev, match_prio);
	if (IS_ERR(hpe))
		return PTR_ERR(hpe);

	if (hpe->hp->num_channels > 1) {
		flow_flag_set(flow, HAIRPIN_RSS);
		flow->attr.hairpin_ft = hpe->hp->ttc.ft.t;
	} else {
		flow->attr.hairpin_tirn = hpe->hp->tirn;
	}
	list_add(&flow->hairpin, &hpe->flows);

	return 0;
}

static void mlx5e_hairpin_flow_del(struct mlx5e_priv *priv,
				   struct mlx5e_tc_flow *flow)
{
	struct list_head *next = flow->hairpin.next;

	if (priv->fs.tc.num_prio_hp)
		return;

	list_del(&flow->hairpin);

	/* no more hairpin flows for us, release the hairpin pair */
	if (list_empty(next)) {
		struct mlx5e_hairpin_entry *hpe;

		hpe = list_entry(next, struct mlx5e_hairpin_entry, flows);

		netdev_dbg(priv->netdev, "del hairpin: peer %s\n",
			   dev_name(hpe->hp->pair->peer_mdev->device));

		mlx5e_hairpin_destroy(hpe->hp);
		hash_del(&hpe->hairpin_hlist);
		kfree(hpe);
	}
}

struct mlx5_flow_handle *
mlx5e_add_offloaded_nic_rule(struct mlx5e_priv *priv,
			     struct mlx5_flow_spec *spec,
			     struct mlx5_flow_attr *attr,
			     struct mlx5e_tc_flow *flow)
{
	struct mlx5_flow_context *flow_context = &spec->flow_context;
	struct mlx5_tc_chains_offload *nic_chains =
					&priv->fs.tc.nic_chains;
	struct mlx5_flow_destination dest[2] = {};
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_flow_act flow_act = {
		.action = attr->action,
		.reformat_id = 0,
		.flags    = FLOW_ACT_NO_APPEND,
	};
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_table *ft;
	bool table_created = false;
	int dest_ix = 0;

	flow_context->flags |= FLOW_CONTEXT_HAS_TAG;
	flow_context->flow_tag = attr->flow_tag;

	if (flow_flag_test(flow, HAIRPIN)) {
		flow_act.ignore_level = true;
		if (tc->num_prio_hp) {
			dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
			dest[dest_ix].ft = tc->hp_fwd;
		} else if (flow_flag_test(flow, HAIRPIN_RSS)) {
			dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
			dest[dest_ix].ft = attr->hairpin_ft;
		} else {
			dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_TIR;
			dest[dest_ix].tir_num = attr->hairpin_tirn;
		}
		dest_ix++;
	} else if (attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
		flow_act.ignore_level = true;
		dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		if (attr->dest_chain) {
			dest[dest_ix].ft = mlx5_tc_chain_get_prio_table(nic_chains,
									attr->dest_chain, 1,
									MLX5E_TC_FT_LEVEL,
									MLX5_FLOW_NAMESPACE_KERNEL);
			if (IS_ERR(dest[dest_ix].ft))
				return ERR_CAST(dest[dest_ix].ft);
		} else {
			dest[dest_ix].ft = priv->fs.vlan.ft.t;
		}
		dest_ix++;
	}

	if (flow_act.action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		dest[dest_ix].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
		dest[dest_ix].counter_id = mlx5_fc_id(attr->counter);
		dest_ix++;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		flow_act.modify_id = attr->mod_hdr_id;

	if (IS_ERR_OR_NULL(priv->fs.tc.t)) {
		/* Create root table once - chain 0/prio 1
		 * Ariel: Consider creating it in the init stage
		 */
		priv->fs.tc.t =
			mlx5_tc_chain_get_prio_table(nic_chains,
						     0, 1,
						     MLX5E_TC_FT_LEVEL,
						     MLX5_FLOW_NAMESPACE_KERNEL);
		if (IS_ERR(priv->fs.tc.t)) {
			netdev_err(priv->netdev,
				   "Failed to create tc base offload table\n");
			rule = ERR_CAST(priv->fs.tc.t);
			goto err_base_tbl;
		}

		table_created = true;
	}

	ft = mlx5_tc_chain_get_prio_table(nic_chains,
					  attr->chain, attr->prio,
					  MLX5E_TC_FT_LEVEL,
					  MLX5_FLOW_NAMESPACE_KERNEL);
	if (IS_ERR(ft)) {
		rule = ERR_CAST(ft);
		goto err_ft_get;
	}

	rule = mlx5_add_flow_rules(ft, spec,
				   &flow_act, dest, dest_ix);
	if (IS_ERR(rule)) {
		rule = ERR_CAST(rule);
		goto err_rule;
	}

	if (dest[0].ft == tc->hp_fwd)
		atomic_inc(&tc->hp_fwd_ref_cnt);

	return rule;

err_rule:
	mlx5_tc_chain_put_prio_table(nic_chains,
				     attr->chain, attr->prio, 0);
err_ft_get:
	if (table_created) {
		mlx5_tc_chain_put_prio_table(nic_chains,
					     attr->dest_chain, 1, 0);
		priv->fs.tc.t = NULL;
	}
err_base_tbl:
	if (attr->dest_chain)
		mlx5_tc_chain_put_prio_table(nic_chains,
					     attr->dest_chain, 1, 0);

	return rule;
}

static int
mlx5e_tc_add_nic_flow(struct mlx5e_priv *priv,
		      struct mlx5e_tc_flow_parse_attr *parse_attr,
		      struct mlx5e_tc_flow *flow,
		      struct netlink_ext_ack *extack)
{
	struct mlx5_flow_attr *attr = &flow->attr;
	struct mlx5_core_dev *dev = priv->mdev;
	bool ct_flow = flow_flag_test(flow, CT);
	struct mlx5_fc *counter = NULL;
	int err;

	if (flow_flag_test(flow, HAIRPIN)) {
		err = mlx5e_hairpin_flow_add(priv, flow, parse_attr, extack);
		if (err)
			return err;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		if (ct_flow)
			counter = mlx5_fc_create_virtual(dev,
							 true);
		else
			counter = mlx5_fc_create(dev, true);
		if (IS_ERR(counter))
			return PTR_ERR(counter);

		attr->counter = counter;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR && !ct_flow) {
		err = mlx5e_attach_mod_hdr(priv, flow, parse_attr);
		kfree(parse_attr->mod_hdr_actions);
		parse_attr->mod_hdr_actions = NULL;
		if (err)
			return err;
	}

	if (attr->inner_match_level != MLX5_MATCH_NONE)
		parse_attr->spec.match_criteria_enable |= MLX5_MATCH_OUTER_HEADERS;

	if (ct_flow) {
		err = mlx5e_ct_flow_offload(flow);
		if (err)
			return err;

		flow->rule[0] = NULL;
		return 0;
	}

	flow->rule[0] = mlx5e_add_offloaded_nic_rule(priv, &parse_attr->spec,
						     attr, flow);

	if (IS_ERR(flow->rule[0]))
 		return PTR_ERR(flow->rule[0]);

	return 0;
}

void mlx5e_del_offloaded_nic_rule(struct mlx5e_priv *priv,
				  struct mlx5_flow_handle *rule,
				  struct mlx5_flow_attr *attr)
{
	struct mlx5_tc_chains_offload *nic_chains =
					&priv->fs.tc.nic_chains;

	mlx5_del_flow_rules(rule);

	mlx5_tc_chain_put_prio_table(nic_chains,
				     attr->chain, attr->prio, 0);

	if (attr->dest_chain)
		mlx5_tc_chain_put_prio_table(nic_chains,
					     attr->dest_chain, 1, 0);

	if (!mlx5e_tc_num_filters(priv, MLX5_TC_FLAG(NIC)) && priv->fs.tc.t) {
		mlx5_tc_chain_put_prio_table(nic_chains, 0, 1, 0);
		priv->fs.tc.t = NULL;
	}
}

static void mlx5e_tc_del_nic_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow)
{
	bool ct_flow = flow_flag_test(flow, CT);
	struct mlx5_flow_attr *attr = &flow->attr;
	struct mlx5e_tc_table *tc = &priv->fs.tc;

	if (ct_flow)
		mlx5e_ct_delete_flow(flow);
	else if (!IS_ERR_OR_NULL(flow->rule[0]))
		mlx5e_del_offloaded_nic_rule(priv, flow->rule[0], &flow->attr);

	flow_flag_clear(flow, OFFLOADED);


	if ((attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR) && !ct_flow)
		mlx5e_detach_mod_hdr(priv, flow);
	else if (ct_flow)
		kfree(attr->parse_attr->mod_hdr_actions);

	if (flow_flag_test(flow, HAIRPIN)) {
		if (tc->num_prio_hp)
			atomic_dec(&tc->hp_fwd_ref_cnt);
		mlx5e_hairpin_flow_del(priv, flow);
	}

	mlx5_fc_destroy(priv->mdev, attr->counter);

	kvfree(attr->parse_attr);
}

static void mlx5e_detach_encap(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *flow, int out_index);

static int mlx5e_attach_encap(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow,
			      struct net_device *mirred_dev,
			      int out_index,
			      struct netlink_ext_ack *extack,
			      struct net_device **encap_dev,
			      bool *encap_valid);

static struct mlx5_flow_handle *
mlx5e_tc_offload_fdb_rules(struct mlx5_eswitch *esw,
			   struct mlx5e_tc_flow *flow,
			   struct mlx5_flow_spec *spec,
			   struct mlx5_flow_attr *attr)
{
	bool ct_flow = flow_flag_test(flow, CT);
	struct mlx5_flow_handle *rule;
	int err;

	if (ct_flow) {
		err = mlx5e_ct_flow_offload(flow);
		if (err)
			return ERR_PTR(err);

		return NULL;
	}

	rule = mlx5_eswitch_add_offloaded_rule(esw, spec, attr);
	if (IS_ERR(rule))
		return rule;

	if (attr->split_count) {
		flow->rule[1] = mlx5_eswitch_add_fwd_rule(esw, spec, attr);
		if (IS_ERR(flow->rule[1])) {
			mlx5_eswitch_del_offloaded_rule(esw, rule, attr);
			return flow->rule[1];
		}
	}

	flow_flag_set(flow, OFFLOADED);
	return rule;
}

static void
mlx5e_tc_unoffload_fdb_rules(struct mlx5_eswitch *esw,
			     struct mlx5e_tc_flow *flow,
			     struct mlx5_flow_attr *attr)
{
	bool ct_flow = flow_flag_test(flow, CT);

	if (ct_flow) {
		mlx5e_ct_delete_flow(flow);
		return;
	}

	flow_flag_clear(flow, OFFLOADED);

	if (attr->split_count)
		mlx5_eswitch_del_fwd_rule(esw, flow->rule[1], attr);

	mlx5_eswitch_del_offloaded_rule(esw, flow->rule[0], attr);
}

static struct mlx5_flow_handle *
mlx5e_tc_offload_to_slow_path(struct mlx5_eswitch *esw,
			      struct mlx5e_tc_flow *flow,
			      struct mlx5_flow_spec *spec,
			      struct mlx5_flow_attr *slow_attr)
{
	struct mlx5_flow_handle *rule;

	memcpy(slow_attr, &flow->attr, sizeof(*slow_attr));
	slow_attr->action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	slow_attr->split_count = 0;
	slow_attr->dest_chain = 0;
	slow_attr->slow_path = true;

	rule = mlx5e_tc_offload_fdb_rules(esw, flow, spec, slow_attr);
	if (!IS_ERR(rule))
		flow_flag_set(flow, SLOW);

	return rule;
}

static void
mlx5e_tc_unoffload_from_slow_path(struct mlx5_eswitch *esw,
				  struct mlx5e_tc_flow *flow,
				  struct mlx5_flow_attr *slow_attr)
{
	memcpy(slow_attr, &flow->attr, sizeof(*slow_attr));
	slow_attr->action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	slow_attr->split_count = 0;
	slow_attr->dest_chain = 0;
	slow_attr->slow_path = true;

	mlx5e_tc_unoffload_fdb_rules(esw, flow, slow_attr);
	flow_flag_clear(flow, SLOW);
}

static void add_unready_flow(struct mlx5e_tc_flow *flow)
{
	struct mlx5_rep_uplink_priv *uplink_priv;
	struct mlx5e_rep_priv *rpriv;
	struct mlx5_eswitch *esw;

	esw = flow->priv->mdev->priv.eswitch;
	rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &rpriv->uplink_priv;

	flow_flag_set(flow, NOT_READY);
	list_add_tail(&flow->unready, &uplink_priv->unready_flows);
}

static void remove_unready_flow(struct mlx5e_tc_flow *flow)
{
	list_del(&flow->unready);
	flow_flag_clear(flow, NOT_READY);
}

static int
mlx5e_tc_add_fdb_flow(struct mlx5e_priv *priv,
		      struct mlx5e_tc_flow *flow,
		      struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_tc_chains_offload *fdb_chains =
			&esw->fdb_table.offloads.fdb_chains;
	u32 max_chain = mlx5_tc_get_chain_range(fdb_chains);
	struct mlx5_flow_attr *attr = &flow->attr;
	struct mlx5e_tc_flow_parse_attr *parse_attr = attr->parse_attr;
	u16 max_prio = mlx5_tc_get_prio_range(fdb_chains);
	struct net_device *out_dev, *encap_dev = NULL;
	bool ct_flow = flow_flag_test(flow, CT);
	struct mlx5_fc *counter = NULL;
	struct mlx5e_rep_priv *rpriv;
	struct mlx5e_priv *out_priv;
	bool encap_valid = true;
	int err = 0;
	int out_index;

	if (!TC_CHAIN_OFFLOAD_CHAINS_PRIOS_SUPPORT(fdb_chains) && attr->prio != 1) {
		NL_SET_ERR_MSG(extack, "E-switch priorities unsupported, upgrade FW");
		return -EOPNOTSUPP;
	}

	if (attr->chain > max_chain) {
		NL_SET_ERR_MSG(extack, "Requested chain is out of supported range");
		err = -EOPNOTSUPP;
		goto err_max_prio_chain;
	}

	if (attr->prio > max_prio) {
		NL_SET_ERR_MSG(extack, "Requested priority is out of supported range");
		err = -EOPNOTSUPP;
		goto err_max_prio_chain;
	}

	for (out_index = 0; out_index < MLX5_MAX_FLOW_FWD_VPORTS; out_index++) {
		int mirred_ifindex;

		if (!(attr->dests[out_index].flags & MLX5_ESW_DEST_ENCAP))
			continue;

		mirred_ifindex = parse_attr->mirred_ifindex[out_index];
		out_dev = __dev_get_by_index(dev_net(priv->netdev),
					     mirred_ifindex);
		err = mlx5e_attach_encap(priv, flow, out_dev, out_index,
					 extack, &encap_dev, &encap_valid);
		if (err)
			goto err_attach_encap;

		out_priv = netdev_priv(encap_dev);
		rpriv = out_priv->ppriv;
		attr->dests[out_index].rep = rpriv->rep;
		attr->dests[out_index].mdev = out_priv->mdev;
	}

	err = mlx5_eswitch_add_vlan_action(esw, attr);
	if (err)
		goto err_add_vlan;

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR && !ct_flow) {
		err = mlx5e_attach_mod_hdr(priv, flow, parse_attr);
		kfree(parse_attr->mod_hdr_actions);
		parse_attr->mod_hdr_actions = NULL;
		if (err)
			goto err_mod_hdr;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		if (ct_flow)
			counter = mlx5_fc_create_virtual(attr->counter_dev,
							 true);
		else
			counter = mlx5_fc_create(attr->counter_dev, true);
		if (IS_ERR(counter)) {
			err = PTR_ERR(counter);
			goto err_create_counter;
		}

		attr->counter = counter;
	}

	/* we get here if one of the following takes place:
	 * (1) there's no error
	 * (2) there's an encap action and we don't have valid neigh
	 */
	if (!encap_valid) {
		/* continue with goto slow path rule instead */
		struct mlx5_flow_attr slow_attr;

		flow->rule[0] = mlx5e_tc_offload_to_slow_path(esw, flow, &parse_attr->spec, &slow_attr);
	} else {
		flow->rule[0] = mlx5e_tc_offload_fdb_rules(esw, flow, &parse_attr->spec, attr);
	}

	if (IS_ERR(flow->rule[0])) {
		err = PTR_ERR(flow->rule[0]);
		goto err_add_rule;
	}

	return 0;

err_add_rule:
	mlx5_fc_destroy(attr->counter_dev, counter);
err_create_counter:
	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		mlx5e_detach_mod_hdr(priv, flow);
err_mod_hdr:
	mlx5_eswitch_del_vlan_action(esw, attr);
err_add_vlan:
	for (out_index = 0; out_index < MLX5_MAX_FLOW_FWD_VPORTS; out_index++)
		if (attr->dests[out_index].flags & MLX5_ESW_DEST_ENCAP)
			mlx5e_detach_encap(priv, flow, out_index);
err_attach_encap:
err_max_prio_chain:
	return err;
}

static bool mlx5_flow_has_geneve_opt(struct mlx5e_tc_flow *flow)
{
	struct mlx5_flow_spec *spec = &flow->attr.parse_attr->spec;
	void *headers_v = MLX5_ADDR_OF(fte_match_param,
				       spec->match_value,
				       misc_parameters_3);
	u32 geneve_tlv_opt_0_data = MLX5_GET(fte_match_set_misc3,
					     headers_v,
					     geneve_tlv_option_0_data);

	return !!geneve_tlv_opt_0_data;
}

static void put_tunnel_mapping(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *flow);
static void mlx5e_tc_del_fdb_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_flow_attr *attr = &flow->attr;
	bool ct_flow = flow_flag_test(flow, CT);
	struct mlx5_flow_attr slow_attr;
	int out_index;

	put_tunnel_mapping(priv, flow);

	if (flow_flag_test(flow, NOT_READY)) {
		remove_unready_flow(flow);
		kvfree(attr->parse_attr);
		return;
	}

	if (mlx5e_is_offloaded_flow(flow) || ct_flow) {
		if (flow_flag_test(flow, SLOW))
			mlx5e_tc_unoffload_from_slow_path(esw, flow, &slow_attr);
		else
			mlx5e_tc_unoffload_fdb_rules(esw, flow, attr);
	}

	if (mlx5_flow_has_geneve_opt(flow))
		mlx5_geneve_tlv_option_del(priv->mdev->geneve);

	mlx5_eswitch_del_vlan_action(esw, attr);

	for (out_index = 0; out_index < MLX5_MAX_FLOW_FWD_VPORTS; out_index++)
		if (attr->dests[out_index].flags & MLX5_ESW_DEST_ENCAP)
			mlx5e_detach_encap(priv, flow, out_index);

	if ((attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR) && !ct_flow)
		mlx5e_detach_mod_hdr(priv, flow);
	else if (ct_flow)
		kfree(attr->parse_attr->mod_hdr_actions);

	kvfree(attr->parse_attr);

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_COUNT)
		mlx5_fc_destroy(attr->counter_dev, attr->counter);
}

void mlx5e_tc_encap_flows_add(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_flow_attr slow_attr, *esw_attr;
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_spec *spec;
	struct encap_flow_item *efi;
	struct mlx5e_tc_flow *flow;
	int err;

	err = mlx5_packet_reformat_alloc(priv->mdev,
					 e->reformat_type,
					 e->encap_size, e->encap_header,
					 MLX5_FLOW_NAMESPACE_FDB,
					 &e->encap_id);
	if (err) {
		mlx5_core_warn(priv->mdev, "Failed to offload cached encapsulation header, %d\n",
			       err);
		return;
	}
	e->flags |= MLX5_ENCAP_ENTRY_VALID;
	mlx5e_rep_queue_neigh_stats_work(priv);

	list_for_each_entry(efi, &e->flows, list) {
		bool all_flow_encaps_valid = true;
		int i;

		flow = container_of(efi, struct mlx5e_tc_flow, encaps[efi->index]);
		esw_attr = &flow->attr;
		spec = &esw_attr->parse_attr->spec;

		esw_attr->dests[efi->index].encap_id = e->encap_id;
		esw_attr->dests[efi->index].flags |= MLX5_ESW_DEST_ENCAP_VALID;
		/* Flow can be associated with multiple encap entries.
		 * Before offloading the flow verify that all of them have
		 * a valid neighbour.
		 */
		for (i = 0; i < MLX5_MAX_FLOW_FWD_VPORTS; i++) {
			if (!(esw_attr->dests[i].flags & MLX5_ESW_DEST_ENCAP))
				continue;
			if (!(esw_attr->dests[i].flags & MLX5_ESW_DEST_ENCAP_VALID)) {
				all_flow_encaps_valid = false;
				break;
			}
		}
		/* Do not offload flows with unresolved neighbors */
		if (!all_flow_encaps_valid)
			continue;
		/* update from slow path rule to encap rule */
		rule = mlx5e_tc_offload_fdb_rules(esw, flow, spec, esw_attr);
		if (IS_ERR(rule)) {
			err = PTR_ERR(rule);
			mlx5_core_warn(priv->mdev, "Failed to update cached encapsulation flow, %d\n",
				       err);
			continue;
		}

		mlx5e_tc_unoffload_from_slow_path(esw, flow, &slow_attr);
		flow_flag_set(flow, OFFLOADED); /* was unset when slow path rule removed */
		flow->rule[0] = rule;
	}
}

void mlx5e_tc_encap_flows_del(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_flow_attr slow_attr;
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_spec *spec;
	struct encap_flow_item *efi;
	struct mlx5e_tc_flow *flow;
	int err;

	list_for_each_entry(efi, &e->flows, list) {
		flow = container_of(efi, struct mlx5e_tc_flow, encaps[efi->index]);
		spec = &flow->attr.parse_attr->spec;

		/* update from encap rule to slow path rule */
		rule = mlx5e_tc_offload_to_slow_path(esw, flow, spec, &slow_attr);
		/* mark the flow's encap dest as non-valid */
		flow->attr.dests[efi->index].flags &= ~MLX5_ESW_DEST_ENCAP_VALID;

		if (IS_ERR(rule)) {
			err = PTR_ERR(rule);
			mlx5_core_warn(priv->mdev, "Failed to update slow path (encap) flow, %d\n",
				       err);
			continue;
		}

		mlx5e_tc_unoffload_fdb_rules(esw, flow, &flow->attr);
		flow_flag_set(flow, OFFLOADED); /* was unset when fast path rule removed */
		flow->rule[0] = rule;
	}

	/* we know that the encap is valid */
	e->flags &= ~MLX5_ENCAP_ENTRY_VALID;
	mlx5_packet_reformat_dealloc(priv->mdev, e->encap_id);
}

static struct mlx5_fc *mlx5e_tc_get_counter(struct mlx5e_tc_flow *flow)
{
	return flow->attr.counter;
}

void mlx5e_tc_update_neigh_used_value(struct mlx5e_neigh_hash_entry *nhe)
{
	struct mlx5e_neigh *m_neigh = &nhe->m_neigh;
	struct mlx5e_tc_flow *flow;
	struct mlx5e_encap_entry *e;
	struct mlx5_fc *counter;
	struct neigh_table *tbl;
	bool neigh_used = false;
	struct neighbour *n;
	u64 lastuse;

	if (m_neigh->family == AF_INET)
		tbl = &arp_tbl;
#if IS_ENABLED(CONFIG_IPV6)
	else if (m_neigh->family == AF_INET6)
		tbl = &nd_tbl;
#endif
	else
		return;

	list_for_each_entry(e, &nhe->encap_list, encap_list) {
		struct encap_flow_item *efi;
		if (!(e->flags & MLX5_ENCAP_ENTRY_VALID))
			continue;
		list_for_each_entry(efi, &e->flows, list) {
			flow = container_of(efi, struct mlx5e_tc_flow,
					    encaps[efi->index]);
			if (flow_flag_test(flow, OFFLOADED)) {
				counter = mlx5e_tc_get_counter(flow);
				lastuse = mlx5_fc_query_cached_lastuse(counter);
				if (time_after((unsigned long)lastuse, nhe->reported_lastuse)) {
					neigh_used = true;
					break;
				}
			}
		}
		if (neigh_used)
			break;
	}

	if (neigh_used) {
		nhe->reported_lastuse = jiffies;

		/* find the relevant neigh according to the cached device and
		 * dst ip pair
		 */
		n = neigh_lookup(tbl, &m_neigh->dst_ip, m_neigh->dev);
		if (!n)
			return;

		neigh_event_send(n, NULL);
		neigh_release(n);
	}
}

static void mlx5e_detach_encap(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *flow, int out_index)
{
	struct list_head *next = flow->encaps[out_index].list.next;

	list_del(&flow->encaps[out_index].list);
	if (list_empty(next)) {
		struct mlx5e_encap_entry *e;

		e = list_entry(next, struct mlx5e_encap_entry, flows);
		mlx5e_rep_encap_entry_detach(netdev_priv(e->out_dev), e);

		if (e->flags & MLX5_ENCAP_ENTRY_VALID)
			mlx5_packet_reformat_dealloc(priv->mdev, e->encap_id);

		hash_del_rcu(&e->encap_hlist);
		kfree(e->encap_header);
		kfree(e);
	}
}

static void __mlx5e_tc_del_fdb_peer_flow(struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = flow->priv->mdev->priv.eswitch;

	if (!(mlx5e_is_eswitch_flow(flow)) ||
	    !(flow_flag_test(flow, DUP)))
		return;

	mutex_lock(&esw->offloads.peer_mutex);
	list_del(&flow->peer);
	mutex_unlock(&esw->offloads.peer_mutex);

	flow_flag_clear(flow, DUP);

	mlx5e_tc_del_fdb_flow(flow->peer_flow->priv, flow->peer_flow);
	kvfree(flow->peer_flow);
	flow->peer_flow = NULL;
}

static void mlx5e_tc_del_fdb_peer_flow(struct mlx5e_tc_flow *flow)
{
	struct mlx5_core_dev *dev = flow->priv->mdev;
	struct mlx5_devcom *devcom = dev->priv.devcom;
	struct mlx5_eswitch *peer_esw;

	peer_esw = mlx5_devcom_get_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
	if (!peer_esw)
		return;

	__mlx5e_tc_del_fdb_peer_flow(flow);
	mlx5_devcom_release_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
}

int __rcu (*tc_skb_update_hook)(struct sk_buff *skb, u32 reg_c0, u32 reg_c1);
int mlx5e_nic_update_skb(struct sk_buff *skb, u32 reg_c0, u32 reg_c1);
int mlx5e_esw_update_skb(struct sk_buff *skb, u32 reg_c0, u32 reg_c1);

static void mlx5e_tc_del_flow(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow)
{
	if (mlx5e_is_eswitch_flow(flow)) {
		mlx5e_tc_del_fdb_peer_flow(flow);
		mlx5e_tc_del_fdb_flow(priv, flow);
	} else {
		mlx5e_tc_del_nic_flow(priv, flow);
	}
}

static int is_simple_flow(struct mlx5e_tc_flow *flow, struct flow_rule *rule,
			  bool *decap)
{
	struct mlx5_eswitch *esw = flow->priv->mdev->priv.eswitch;
	struct flow_action *flow_action = &rule->action;
	const struct flow_action_entry *act;
	bool simple = true;
	int i;

	*decap = false;

	flow_action_for_each(i, act, flow_action) {
		switch (act->id) {
			case FLOW_ACTION_GOTO:
				simple = false;
			break;
			case FLOW_ACTION_TUNNEL_DECAP:
				*decap = true;
			break;
			default:
			break;
		}
	}

	if (!mlx5e_is_eswitch_flow(flow))
		return true;

	/* If metadata isn't supported, we still wan't to support full
	 * matching with chain to not cause a regression, count it as
	 * simple rules
	 */
	if (!mlx5_eswitch_vport_match_metadata_enabled(esw))
		return true;

	if (flow->attr.chain)
		return false;

	return simple;
}

static int get_tunnel_mapping(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow,
			      struct tunnel_match_key *key,
			      struct netlink_ext_ack *extack);
static int parse_tunnel_attr(struct mlx5e_priv *priv,
			     struct mlx5e_tc_flow *flow,
			     struct mlx5_flow_spec *spec,
			     struct flow_cls_offload *f,
			     struct net_device *filter_dev, u8 *match_level)
{
	struct netlink_ext_ack *extack = f->common.extack;
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct tunnel_match_key tunnel_key;
	bool simple_flow, decap;
	int err;

	simple_flow = is_simple_flow(flow, rule, &decap);
	/* we don't fill spec for eswitch later rules or simple flows */
	if (simple_flow || !flow->attr.chain) {
		err = mlx5e_tc_tun_parse(filter_dev, priv, spec, f,
					 headers_c, headers_v, match_level);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack,
					   "failed to parse tunnel attributes");
			return err;
		}


		/* Enforce DMAC when offloading incoming tunneled flows.
		 * Flow counters require a match on the DMAC.
		 */
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, dmac_47_16);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, dmac_15_0);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     dmac_47_16), priv->netdev->dev_addr);

		/* let software handle IP fragments */
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag, 0);

		/* Simple rule, done here */
		if (simple_flow)
			return 0;
	}

	/* if we decap, we don't rewrite the tunnel metadata register
	 * via get_tunnel_mapping()
	 * */
	if (decap)
		return 0;

	memset(&tunnel_key, 0, sizeof(tunnel_key));

#define COPY_DISSECTOR_KEY(rule, diss_key, field)\
	memcpy(&tunnel_key.field,\
	       skb_flow_dissector_target(rule->match.dissector,\
					 diss_key,\
					 rule->match.key),\
	       sizeof(tunnel_key.field))

	// need to check ? if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP)) {
	COPY_DISSECTOR_KEY(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL, enc_control);
	if (tunnel_key.enc_control.addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS)
		COPY_DISSECTOR_KEY(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS, enc_ipv4);
	else
		COPY_DISSECTOR_KEY(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS, enc_ipv6);
	COPY_DISSECTOR_KEY(rule, FLOW_DISSECTOR_KEY_ENC_IP, enc_ip);
	COPY_DISSECTOR_KEY(rule, FLOW_DISSECTOR_KEY_ENC_PORTS, enc_tp);
	COPY_DISSECTOR_KEY(rule, FLOW_DISSECTOR_KEY_ENC_OPTS, enc_opts);
	COPY_DISSECTOR_KEY(rule, FLOW_DISSECTOR_KEY_ENC_KEYID, enc_key_id);

	err = get_tunnel_mapping(priv, flow, &tunnel_key, extack);
	if (err)
		return err;

	return 0;
}

static void *get_match_headers_criteria(u32 flags,
					struct mlx5_flow_spec *spec)
{
	return (flags & MLX5_FLOW_CONTEXT_ACTION_DECAP) ?
		MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			     inner_headers) :
		MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			     outer_headers);
}

static void *get_match_headers_value(u32 flags,
				     struct mlx5_flow_spec *spec)
{
	return (flags & MLX5_FLOW_CONTEXT_ACTION_DECAP) ?
		MLX5_ADDR_OF(fte_match_param, spec->match_value,
			     inner_headers) :
		MLX5_ADDR_OF(fte_match_param, spec->match_value,
			     outer_headers);
}

static int __parse_cls_flower(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow,
			      struct mlx5_flow_spec *spec,
			      struct flow_cls_offload *f,
			      struct net_device *filter_dev,
			      u8 *inner_match_level, u8 *outer_match_level)
{
	struct netlink_ext_ack *extack = f->common.extack;
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);
	void *misc_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    misc_parameters);
	void *misc_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    misc_parameters);
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_dissector *dissector = rule->match.dissector;
	u16 addr_type = 0;
	u8 ip_proto = 0;
	u8 *match_level;

	match_level = outer_match_level;

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_META) |
	      BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_CVLAN) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_PORTS)	|
	      BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_TCP) |
	      BIT(FLOW_DISSECTOR_KEY_IP)  |
	      BIT(FLOW_DISSECTOR_KEY_CT) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IP) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_OPTS))) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported key");
		netdev_warn(priv->netdev, "Unsupported key used: 0x%x\n",
			    dissector->used_keys);
		return -EOPNOTSUPP;
	}

	if (mlx5e_get_tc_tun(filter_dev)) {
		bool write = f->common.chain_index ? false : true;

		if (parse_tunnel_attr(priv, flow, spec, f, filter_dev, outer_match_level))
			return -EOPNOTSUPP;

		/* At this point, header pointers should point to the inner
		 * headers, outer header were already set by parse_tunnel_attr
		 */
		match_level = inner_match_level;
		if (write) {
			headers_c = get_match_headers_criteria(MLX5_FLOW_CONTEXT_ACTION_DECAP,
							       spec);
			headers_v = get_match_headers_value(MLX5_FLOW_CONTEXT_ACTION_DECAP,
							    spec);
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ethertype,
			 ntohs(match.mask->n_proto));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype,
			 ntohs(match.key->n_proto));

		if (match.mask->n_proto)
			*match_level = MLX5_MATCH_L2;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN) ||
	    is_vlan_dev(filter_dev)) {
		struct flow_dissector_key_vlan filter_dev_mask;
		struct flow_dissector_key_vlan filter_dev_key;
		struct flow_match_vlan match;

		if (is_vlan_dev(filter_dev)) {
			match.key = &filter_dev_key;
			match.key->vlan_id = vlan_dev_vlan_id(filter_dev);
			match.key->vlan_tpid = vlan_dev_vlan_proto(filter_dev);
			match.key->vlan_priority = 0;
			match.mask = &filter_dev_mask;
			memset(match.mask, 0xff, sizeof(*match.mask));
			match.mask->vlan_priority = 0;
		} else {
			flow_rule_match_vlan(rule, &match);
		}
		if (match.mask->vlan_id ||
		    match.mask->vlan_priority ||
		    match.mask->vlan_tpid) {
			if (match.key->vlan_tpid == htons(ETH_P_8021AD)) {
				MLX5_SET(fte_match_set_lyr_2_4, headers_c,
					 svlan_tag, 1);
				MLX5_SET(fte_match_set_lyr_2_4, headers_v,
					 svlan_tag, 1);
			} else {
				MLX5_SET(fte_match_set_lyr_2_4, headers_c,
					 cvlan_tag, 1);
				MLX5_SET(fte_match_set_lyr_2_4, headers_v,
					 cvlan_tag, 1);
			}

			MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_vid,
				 match.mask->vlan_id);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_vid,
				 match.key->vlan_id);

			MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_prio,
				 match.mask->vlan_priority);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_prio,
				 match.key->vlan_priority);

			*match_level = MLX5_MATCH_L2;
		}
	} else if (*match_level != MLX5_MATCH_NONE) {
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, svlan_tag, 1);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, cvlan_tag, 1);
		*match_level = MLX5_MATCH_L2;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_cvlan(rule, &match);
		if (match.mask->vlan_id ||
		    match.mask->vlan_priority ||
		    match.mask->vlan_tpid) {
			if (match.key->vlan_tpid == htons(ETH_P_8021AD)) {
				MLX5_SET(fte_match_set_misc, misc_c,
					 outer_second_svlan_tag, 1);
				MLX5_SET(fte_match_set_misc, misc_v,
					 outer_second_svlan_tag, 1);
			} else {
				MLX5_SET(fte_match_set_misc, misc_c,
					 outer_second_cvlan_tag, 1);
				MLX5_SET(fte_match_set_misc, misc_v,
					 outer_second_cvlan_tag, 1);
			}

			MLX5_SET(fte_match_set_misc, misc_c, outer_second_vid,
				 match.mask->vlan_id);
			MLX5_SET(fte_match_set_misc, misc_v, outer_second_vid,
				 match.key->vlan_id);
			MLX5_SET(fte_match_set_misc, misc_c, outer_second_prio,
				 match.mask->vlan_priority);
			MLX5_SET(fte_match_set_misc, misc_v, outer_second_prio,
				 match.key->vlan_priority);

			*match_level = MLX5_MATCH_L2;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
					     dmac_47_16),
				match.mask->dst);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     dmac_47_16),
				match.key->dst);

		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
					     smac_47_16),
				match.mask->src);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     smac_47_16),
				match.key->src);

		if (!is_zero_ether_addr(match.mask->src) ||
		    !is_zero_ether_addr(match.mask->dst))
			*match_level = MLX5_MATCH_L2;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
		addr_type = match.key->addr_type;

		/* the HW doesn't support frag first/later */
		if (match.mask->flags & FLOW_DIS_FIRST_FRAG)
			return -EOPNOTSUPP;

		if (match.mask->flags & FLOW_DIS_IS_FRAGMENT) {
			MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag,
				 match.key->flags & FLOW_DIS_IS_FRAGMENT);

			/* the HW doesn't need L3 inline to match on frag=no */
			if (!(match.key->flags & FLOW_DIS_IS_FRAGMENT))
				*match_level = MLX5_MATCH_L2;
	/* ***  L2 attributes parsing up to here *** */
			else
				*match_level = MLX5_MATCH_L3;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		ip_proto = match.key->ip_proto;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_protocol,
			 match.mask->ip_proto);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
			 match.key->ip_proto);

		if (match.mask->ip_proto)
			*match_level = MLX5_MATCH_L3;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &match.mask->src, sizeof(match.mask->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &match.key->src, sizeof(match.key->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &match.mask->dst, sizeof(match.mask->dst));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &match.key->dst, sizeof(match.key->dst));

		if (match.mask->src || match.mask->dst)
			*match_level = MLX5_MATCH_L3;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &match.mask->src, sizeof(match.mask->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &match.key->src, sizeof(match.key->src));

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &match.mask->dst, sizeof(match.mask->dst));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &match.key->dst, sizeof(match.key->dst));

		if (ipv6_addr_type(&match.mask->src) != IPV6_ADDR_ANY ||
		    ipv6_addr_type(&match.mask->dst) != IPV6_ADDR_ANY)
			*match_level = MLX5_MATCH_L3;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_ecn,
			 match.mask->tos & 0x3);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_ecn,
			 match.key->tos & 0x3);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_dscp,
			 match.mask->tos >> 2);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_dscp,
			 match.key->tos  >> 2);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ttl_hoplimit,
			 match.mask->ttl);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ttl_hoplimit,
			 match.key->ttl);

		if (match.mask->ttl &&
		    !MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev,
						ft_field_support.outer_ipv4_ttl)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Matching on TTL is not supported");
			return -EOPNOTSUPP;
		}

		if (match.mask->tos || match.mask->ttl)
			*match_level = MLX5_MATCH_L3;
	}

	/* ***  L3 attributes parsing up to here *** */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		switch (ip_proto) {
		case IPPROTO_TCP:
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 tcp_sport, ntohs(match.mask->src));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 tcp_sport, ntohs(match.key->src));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 tcp_dport, ntohs(match.mask->dst));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 tcp_dport, ntohs(match.key->dst));
			break;

		case IPPROTO_UDP:
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 udp_sport, ntohs(match.mask->src));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 udp_sport, ntohs(match.key->src));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 udp_dport, ntohs(match.mask->dst));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 udp_dport, ntohs(match.key->dst));
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack,
					   "Only UDP and TCP transports are supported for L4 matching");
			netdev_err(priv->netdev,
				   "Only UDP and TCP transport are supported\n");
			return -EINVAL;
		}

		if (match.mask->src || match.mask->dst)
			*match_level = MLX5_MATCH_L4;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TCP)) {
		struct flow_match_tcp match;

		flow_rule_match_tcp(rule, &match);
		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_flags,
			 ntohs(match.mask->flags));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_flags,
			 ntohs(match.key->flags));

		if (match.mask->flags)
			*match_level = MLX5_MATCH_L4;
	}

	return 0;
}

static int parse_cls_flower(struct mlx5e_priv *priv,
			    struct mlx5e_tc_flow *flow,
			    struct mlx5_flow_spec *spec,
			    struct flow_cls_offload *f,
			    struct net_device *filter_dev)
{
	u8 inner_match_level, outer_match_level, non_tunnel_match_level;
	struct netlink_ext_ack *extack = f->common.extack;
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep;
	int err;

	inner_match_level = MLX5_MATCH_NONE;
	outer_match_level = MLX5_MATCH_NONE;

	err = __parse_cls_flower(priv, flow, spec, f, filter_dev, &inner_match_level,
				 &outer_match_level);
	non_tunnel_match_level = (inner_match_level == MLX5_MATCH_NONE) ?
				 outer_match_level : inner_match_level;

	if (!err && mlx5e_is_eswitch_flow(flow)) {
		rep = rpriv->rep;
		if (rep->vport != MLX5_VPORT_UPLINK &&
		    (esw->offloads.inline_mode != MLX5_INLINE_MODE_NONE &&
		    esw->offloads.inline_mode < non_tunnel_match_level)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Flow is not offloaded due to min inline setting");
			netdev_warn(priv->netdev,
				    "Flow is not offloaded due to min inline setting, required %d actual %d\n",
				    non_tunnel_match_level, esw->offloads.inline_mode);
			return -EOPNOTSUPP;
		}
	}

	if (mlx5e_is_eswitch_flow(flow)) {
		flow->attr.inner_match_level = inner_match_level;
		flow->attr.outer_match_level = outer_match_level;
	} else {
		flow->attr.inner_match_level = non_tunnel_match_level;
	}

	return err;
}

struct pedit_headers {
	struct ethhdr  eth;
	struct vlan_hdr vlan;
	struct iphdr   ip4;
	struct ipv6hdr ip6;
	struct tcphdr  tcp;
	struct udphdr  udp;
};

struct pedit_headers_action {
	struct pedit_headers	vals;
	struct pedit_headers	masks;
	u32			pedits;
};

static int pedit_header_offsets[] = {
	[FLOW_ACT_MANGLE_HDR_TYPE_ETH] = offsetof(struct pedit_headers, eth),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP4] = offsetof(struct pedit_headers, ip4),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP6] = offsetof(struct pedit_headers, ip6),
	[FLOW_ACT_MANGLE_HDR_TYPE_TCP] = offsetof(struct pedit_headers, tcp),
	[FLOW_ACT_MANGLE_HDR_TYPE_UDP] = offsetof(struct pedit_headers, udp),
};

#define pedit_header(_ph, _htype) ((void *)(_ph) + pedit_header_offsets[_htype])

static int set_pedit_val(u8 hdr_type, u32 mask, u32 val, u32 offset,
			 struct pedit_headers_action *hdrs)
{
	u32 *curr_pmask, *curr_pval;

	curr_pmask = (u32 *)(pedit_header(&hdrs->masks, hdr_type) + offset);
	curr_pval  = (u32 *)(pedit_header(&hdrs->vals, hdr_type) + offset);

	if (*curr_pmask & mask)  /* disallow acting twice on the same location */
		goto out_err;

	*curr_pmask |= mask;
	*curr_pval  |= (val & mask);

	return 0;

out_err:
	return -EOPNOTSUPP;
}

struct mlx5_fields {
	u8  field;
	u8  field_bsize;
	u32 field_mask;
	u32 offset;
	u32 match_offset;
};

#define OFFLOAD(fw_field, field_bsize, field_mask, field, off, match_field) \
		{MLX5_ACTION_IN_FIELD_OUT_ ## fw_field, field_bsize, field_mask, \
		 offsetof(struct pedit_headers, field) + (off), \
		 MLX5_BYTE_OFF(fte_match_set_lyr_2_4, match_field)}

/* masked values are the same and there are no rewrites that do not have a
 * match.
 */
#define SAME_VAL_MASK(type, valp, maskp, matchvalp, matchmaskp) ({ \
	type matchmaskx = *(type *)(matchmaskp); \
	type matchvalx = *(type *)(matchvalp); \
	type maskx = *(type *)(maskp); \
	type valx = *(type *)(valp); \
	\
	(valx & maskx) == (matchvalx & matchmaskx) && !(maskx & (maskx ^ \
								 matchmaskx)); \
})

static bool cmp_val_mask(void *valp, void *maskp, void *matchvalp,
			 void *matchmaskp, u8 bsize)
{
	bool same = false;

	switch (bsize) {
	case 8:
		same = SAME_VAL_MASK(u8, valp, maskp, matchvalp, matchmaskp);
		break;
	case 16:
		same = SAME_VAL_MASK(u16, valp, maskp, matchvalp, matchmaskp);
		break;
	case 32:
		same = SAME_VAL_MASK(u32, valp, maskp, matchvalp, matchmaskp);
		break;
	}

	return same;
}

static struct mlx5_fields fields[] = {
	OFFLOAD(DMAC_47_16, 32, U32_MAX, eth.h_dest[0], 0, dmac_47_16),
	OFFLOAD(DMAC_15_0,  16, U16_MAX, eth.h_dest[4], 0, dmac_15_0),
	OFFLOAD(SMAC_47_16, 32, U32_MAX, eth.h_source[0], 0, smac_47_16),
	OFFLOAD(SMAC_15_0,  16, U16_MAX, eth.h_source[4], 0, smac_15_0),
	OFFLOAD(ETHERTYPE,  16, U16_MAX, eth.h_proto, 0, ethertype),
	OFFLOAD(FIRST_VID,  16, U16_MAX, vlan.h_vlan_TCI, 0, first_vid),

	OFFLOAD(IP_DSCP, 8,    0xfc, ip4.tos,   0, ip_dscp),
	OFFLOAD(IP_TTL,  8,  U8_MAX, ip4.ttl,   0, ttl_hoplimit),
	OFFLOAD(SIPV4,  32, U32_MAX, ip4.saddr, 0, src_ipv4_src_ipv6.ipv4_layout.ipv4),
	OFFLOAD(DIPV4,  32, U32_MAX, ip4.daddr, 0, dst_ipv4_dst_ipv6.ipv4_layout.ipv4),

	OFFLOAD(SIPV6_127_96, 32, U32_MAX, ip6.saddr.s6_addr32[0], 0,
		src_ipv4_src_ipv6.ipv6_layout.ipv6[0]),
	OFFLOAD(SIPV6_95_64,  32, U32_MAX, ip6.saddr.s6_addr32[1], 0,
		src_ipv4_src_ipv6.ipv6_layout.ipv6[4]),
	OFFLOAD(SIPV6_63_32,  32, U32_MAX, ip6.saddr.s6_addr32[2], 0,
		src_ipv4_src_ipv6.ipv6_layout.ipv6[8]),
	OFFLOAD(SIPV6_31_0,   32, U32_MAX, ip6.saddr.s6_addr32[3], 0,
		src_ipv4_src_ipv6.ipv6_layout.ipv6[12]),
	OFFLOAD(DIPV6_127_96, 32, U32_MAX, ip6.daddr.s6_addr32[0], 0,
		dst_ipv4_dst_ipv6.ipv6_layout.ipv6[0]),
	OFFLOAD(DIPV6_95_64,  32, U32_MAX, ip6.daddr.s6_addr32[1], 0,
		dst_ipv4_dst_ipv6.ipv6_layout.ipv6[4]),
	OFFLOAD(DIPV6_63_32,  32, U32_MAX, ip6.daddr.s6_addr32[2], 0,
		dst_ipv4_dst_ipv6.ipv6_layout.ipv6[8]),
	OFFLOAD(DIPV6_31_0,   32, U32_MAX, ip6.daddr.s6_addr32[3], 0,
		dst_ipv4_dst_ipv6.ipv6_layout.ipv6[12]),
	OFFLOAD(IPV6_HOPLIMIT, 8,  U8_MAX, ip6.hop_limit, 0, ttl_hoplimit),

	OFFLOAD(TCP_SPORT, 16, U16_MAX, tcp.source,  0, tcp_sport),
	OFFLOAD(TCP_DPORT, 16, U16_MAX, tcp.dest,    0, tcp_dport),
	/* in linux iphdr tcp_flags is 8 bits long */
	OFFLOAD(TCP_FLAGS,  8,  U8_MAX, tcp.ack_seq, 5, tcp_flags),

	OFFLOAD(UDP_SPORT, 16, U16_MAX, udp.source, 0, udp_sport),
	OFFLOAD(UDP_DPORT, 16, U16_MAX, udp.dest,   0, udp_dport),
};

/* On input attr->max_mod_hdr_actions tells how many HW actions can be parsed at
 * max from the SW pedit action. On success, attr->num_mod_hdr_actions
 * says how many HW actions were actually parsed.
 */
static int offload_pedit_fields(struct pedit_headers_action *hdrs,
				struct mlx5e_tc_flow_parse_attr *parse_attr,
				u32 *action_flags,
				struct netlink_ext_ack *extack)
{
	struct pedit_headers *set_masks, *add_masks, *set_vals, *add_vals;
	int i, action_size, nactions, max_actions, first, last, next_z;
	void *headers_c, *headers_v, *action, *vals_p;
	u32 *s_masks_p, *a_masks_p, s_mask, a_mask;
	struct mlx5_fields *f;
	unsigned long mask;
	__be32 mask_be32;
	__be16 mask_be16;
	u8 cmd;

	headers_c = get_match_headers_criteria(*action_flags, &parse_attr->spec);
	headers_v = get_match_headers_value(*action_flags, &parse_attr->spec);

	set_masks = &hdrs[0].masks;
	add_masks = &hdrs[1].masks;
	set_vals = &hdrs[0].vals;
	add_vals = &hdrs[1].vals;

	action_size = MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto);
	action = parse_attr->mod_hdr_actions +
		 parse_attr->num_mod_hdr_actions * action_size;

	max_actions = parse_attr->max_mod_hdr_actions;
	nactions = parse_attr->num_mod_hdr_actions;

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		bool skip;

		f = &fields[i];
		/* avoid seeing bits set from previous iterations */
		s_mask = 0;
		a_mask = 0;

		s_masks_p = (void *)set_masks + f->offset;
		a_masks_p = (void *)add_masks + f->offset;

		s_mask = *s_masks_p & f->field_mask;
		a_mask = *a_masks_p & f->field_mask;

		if (!s_mask && !a_mask) /* nothing to offload here */
			continue;

		if (s_mask && a_mask) {
			NL_SET_ERR_MSG_MOD(extack,
					   "can't set and add to the same HW field");
			printk(KERN_WARNING "mlx5: can't set and add to the same HW field (%x)\n", f->field);
			return -EOPNOTSUPP;
		}

		if (nactions == max_actions) {
			NL_SET_ERR_MSG_MOD(extack,
					   "too many pedit actions, can't offload");
			printk(KERN_WARNING "mlx5: parsed %d pedit actions, can't do more\n", nactions);
			return -EOPNOTSUPP;
		}

		skip = false;
		if (s_mask) {
			void *match_mask = headers_c + f->match_offset;
			void *match_val = headers_v + f->match_offset;

			cmd  = MLX5_ACTION_TYPE_SET;
			mask = s_mask;
			vals_p = (void *)set_vals + f->offset;
			/* don't rewrite if we have a match on the same value */
			if (cmp_val_mask(vals_p, s_masks_p, match_val,
					 match_mask, f->field_bsize))
				skip = true;
			/* clear to denote we consumed this field */
			*s_masks_p &= ~f->field_mask;
		} else {
			cmd  = MLX5_ACTION_TYPE_ADD;
			mask = a_mask;
			vals_p = (void *)add_vals + f->offset;
			/* add 0 is no change */
			if ((*(u32 *)vals_p & f->field_mask) == 0)
				skip = true;
			/* clear to denote we consumed this field */
			*a_masks_p &= ~f->field_mask;
		}
		if (skip)
			continue;

		if (f->field_bsize == 32) {
			mask_be32 = *(__be32 *)&mask;
			mask = (__force unsigned long)cpu_to_le32(be32_to_cpu(mask_be32));
		} else if (f->field_bsize == 16) {
			mask_be16 = *(__be16 *)&mask;
			mask = (__force unsigned long)cpu_to_le16(be16_to_cpu(mask_be16));
		}

		first = find_first_bit(&mask, f->field_bsize);
		next_z = find_next_zero_bit(&mask, f->field_bsize, first);
		last  = find_last_bit(&mask, f->field_bsize);
		if (first < next_z && next_z < last) {
			NL_SET_ERR_MSG_MOD(extack,
					   "rewrite of few sub-fields isn't supported");
			printk(KERN_WARNING "mlx5: rewrite of few sub-fields (mask %lx) isn't offloaded\n",
			       mask);
			return -EOPNOTSUPP;
		}

		MLX5_SET(set_action_in, action, action_type, cmd);
		MLX5_SET(set_action_in, action, field, f->field);

		if (cmd == MLX5_ACTION_TYPE_SET) {
			int start;

			/* if field is bit sized it can start not from first bit */
			start = find_first_bit((unsigned long *)&f->field_mask,
					       f->field_bsize);

			MLX5_SET(set_action_in, action, offset, first - start);
			/* length is num of bits to be written, zero means length of 32 */
			MLX5_SET(set_action_in, action, length, (last - first + 1));
		}

		if (f->field_bsize == 32)
			MLX5_SET(set_action_in, action, data, ntohl(*(__be32 *)vals_p) >> first);
		else if (f->field_bsize == 16)
			MLX5_SET(set_action_in, action, data, ntohs(*(__be16 *)vals_p) >> first);
		else if (f->field_bsize == 8)
			MLX5_SET(set_action_in, action, data, *(u8 *)vals_p >> first);

		action += action_size;
		nactions++;
	}

	parse_attr->num_mod_hdr_actions = nactions;
	return 0;
}

static int mlx5e_flow_namespace_max_modify_action(struct mlx5_core_dev *mdev,
						  int namespace)
{
	if (namespace == MLX5_FLOW_NAMESPACE_FDB) /* FDB offloading */
		return MLX5_CAP_ESW_FLOWTABLE_FDB(mdev, max_modify_header_actions);
	else /* namespace is MLX5_FLOW_NAMESPACE_KERNEL - NIC offloading */
		return MLX5_CAP_FLOWTABLE_NIC_RX(mdev, max_modify_header_actions);
}

static int alloc_mod_hdr_actions(struct mlx5e_priv *priv,
				 struct pedit_headers_action *hdrs,
				 int namespace,
				 struct mlx5e_tc_flow_parse_attr *parse_attr)
{
	int nkeys = 0, action_size, max_actions;

	if (hdrs) {
		nkeys = hdrs[TCA_PEDIT_KEY_EX_CMD_SET].pedits +
			hdrs[TCA_PEDIT_KEY_EX_CMD_ADD].pedits;
	}
	action_size = MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto);

	max_actions = mlx5e_flow_namespace_max_modify_action(priv->mdev, namespace);
	/* can get up to crazingly 16 HW actions in 32 bits pedit SW key */
	if (nkeys)
		max_actions = min(max_actions, nkeys * 16);
	else
		max_actions = min(max_actions, CT_REWRITE_ACTIONS);

	parse_attr->mod_hdr_actions = kcalloc(max_actions, action_size, GFP_KERNEL);
	if (!parse_attr->mod_hdr_actions)
		return -ENOMEM;

	parse_attr->max_mod_hdr_actions = max_actions;
	return 0;
}

static const struct pedit_headers zero_masks = {};

static int parse_tc_pedit_action(struct mlx5e_priv *priv,
				 const struct flow_action_entry *act, int namespace,
				 struct mlx5e_tc_flow_parse_attr *parse_attr,
				 struct pedit_headers_action *hdrs,
				 struct netlink_ext_ack *extack)
{
	u8 cmd = (act->id == FLOW_ACTION_MANGLE) ? 0 : 1;
	int err = -EOPNOTSUPP;
	u32 mask, val, offset;
	u8 htype;

	htype = act->mangle.htype;
	err = -EOPNOTSUPP; /* can't be all optimistic */

	if (htype == FLOW_ACT_MANGLE_UNSPEC) {
		NL_SET_ERR_MSG_MOD(extack, "legacy pedit isn't offloaded");
		goto out_err;
	}

	if (!mlx5e_flow_namespace_max_modify_action(priv->mdev, namespace)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "The pedit offload action is not supported");
		goto out_err;
	}

	mask = act->mangle.mask;
	val = act->mangle.val;
	offset = act->mangle.offset;

	err = set_pedit_val(htype, ~mask, val, offset, &hdrs[cmd]);
	if (err)
		goto out_err;

	hdrs[cmd].pedits++;

	return 0;
out_err:
	return err;
}

static int alloc_tc_pedit_action(struct mlx5e_priv *priv, int namespace,
				 struct mlx5e_tc_flow_parse_attr *parse_attr,
				 struct pedit_headers_action *hdrs,
				 u32 *action_flags,
				 struct netlink_ext_ack *extack)
{
	struct pedit_headers *cmd_masks;
	int err;
	u8 cmd;

	if (!parse_attr->mod_hdr_actions) {
		err = alloc_mod_hdr_actions(priv,
					    hdrs, namespace, parse_attr);
		if (err)
			goto out_err;
	}

	err = offload_pedit_fields(hdrs, parse_attr, action_flags, extack);
	if (err < 0)
		goto out_dealloc_parsed_actions;

	for (cmd = 0; cmd < __PEDIT_CMD_MAX; cmd++) {
		cmd_masks = &hdrs[cmd].masks;
		if (memcmp(cmd_masks, &zero_masks, sizeof(zero_masks))) {
			NL_SET_ERR_MSG_MOD(extack,
					   "attempt to offload an unsupported field");
			netdev_warn(priv->netdev, "attempt to offload an unsupported field (cmd %d)\n", cmd);
			print_hex_dump(KERN_WARNING, "mask: ", DUMP_PREFIX_ADDRESS,
				       16, 1, cmd_masks, sizeof(zero_masks), true);
			err = -EOPNOTSUPP;
			goto out_dealloc_parsed_actions;
		}
	}

	return 0;

out_dealloc_parsed_actions:
	kfree(parse_attr->mod_hdr_actions);
out_err:
	return err;
}

static bool csum_offload_supported(struct mlx5e_priv *priv,
				   u32 action,
				   u32 update_flags,
				   struct netlink_ext_ack *extack)
{
	u32 prot_flags = TCA_CSUM_UPDATE_FLAG_IPV4HDR | TCA_CSUM_UPDATE_FLAG_TCP |
			 TCA_CSUM_UPDATE_FLAG_UDP;

	/*  The HW recalcs checksums only if re-writing headers */
	if (!(action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "TC csum action is only offloaded with pedit");
		netdev_warn(priv->netdev,
			    "TC csum action is only offloaded with pedit\n");
		return false;
	}

	if (update_flags & ~prot_flags) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't offload TC csum action for some header/s");
		netdev_warn(priv->netdev,
			    "can't offload TC csum action for some header/s - flags %#x\n",
			    update_flags);
		return false;
	}

	return true;
}

struct ip_ttl_word {
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
};

struct ipv6_hoplimit_word {
	__be16	payload_len;
	__u8	nexthdr;
	__u8	hop_limit;
};

static int is_action_keys_supported(const struct flow_action_entry *act,
				    bool ct_flow, bool *modify_ip_header,
				    struct netlink_ext_ack *extack)
{
	u32 mask, offset;
	u8 htype;

	htype = act->mangle.htype;
	offset = act->mangle.offset;
	mask = ~act->mangle.mask;
	/* For IPv4 & IPv6 header check 4 byte word,
	 * to determine that modified fields
	 * are NOT ttl & hop_limit only.
	 */
	if (htype == FLOW_ACT_MANGLE_HDR_TYPE_IP4) {
		struct ip_ttl_word *ttl_word =
			(struct ip_ttl_word *)&mask;

		if (offset != offsetof(struct iphdr, ttl) ||
		    ttl_word->protocol ||
		    ttl_word->check) {
			*modify_ip_header = true;
		}

		if (ct_flow && offset >= offsetof(struct iphdr, saddr)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "can't offload re-write of ipv4 address with action ct");
			return -EOPNOTSUPP;
		}
	} else if (htype == FLOW_ACT_MANGLE_HDR_TYPE_IP6) {
		struct ipv6_hoplimit_word *hoplimit_word =
			(struct ipv6_hoplimit_word *)&mask;

		if (offset != offsetof(struct ipv6hdr, payload_len) ||
		    hoplimit_word->payload_len ||
		    hoplimit_word->nexthdr) {
			*modify_ip_header = true;
		}

		if (ct_flow && offset >= offsetof(struct ipv6hdr, saddr)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "can't offload re-write of ipv6 address with action ct");
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static bool modify_header_match_supported(struct mlx5_flow_spec *spec,
					  struct flow_action *flow_action,
					  u32 actions, bool ct_flow,
					  struct netlink_ext_ack *extack)
{
	const struct flow_action_entry *act;
	bool modify_ip_header;
	void *headers_v;
	u16 ethertype;
	u8 ip_proto;
	int i, err;

	headers_v = get_match_headers_value(actions, spec);
	ethertype = MLX5_GET(fte_match_set_lyr_2_4, headers_v, ethertype);

	/* for non-IP we only re-write MACs, so we're okay */
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		goto out_ok;

	modify_ip_header = false;
	flow_action_for_each(i, act, flow_action) {
		if (act->id != FLOW_ACTION_MANGLE &&
		    act->id != FLOW_ACTION_ADD)
			continue;

		err = is_action_keys_supported(act, ct_flow,
					       &modify_ip_header, extack);
		if (err)
			return err;
	}

	ip_proto = MLX5_GET(fte_match_set_lyr_2_4, headers_v, ip_protocol);
	if (modify_ip_header && ip_proto != IPPROTO_TCP &&
	    ip_proto != IPPROTO_UDP && ip_proto != IPPROTO_ICMP) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't offload re-write of non TCP/UDP");
		pr_info("can't offload re-write of ip proto %d\n", ip_proto);
		return false;
	}

out_ok:
	return true;
}

static struct match_mapping_params match_mappings_arr[] = {
	[mp_chain] = {
		.mfield = MLX5_ACTION_IN_FIELD_METADATA_REG_C_0,
		.moffset = 0,
		.mlen = 2,
		.soffset = MLX5_BYTE_OFF(fte_match_param,
					 misc_parameters_2.metadata_reg_c_0),
	},
	[mp_tunnel_miss] = { /* and mp_tupleid */
		.mfield = MLX5_ACTION_IN_FIELD_METADATA_REG_C_1,
		.moffset = 0,
		.mlen = 4,
		.soffset = MLX5_BYTE_OFF(fte_match_param,
					 misc_parameters_2.metadata_reg_c_1),
	},
	[mp_tunnel_match] = {
		.mfield = MLX5_ACTION_IN_FIELD_METADATA_REG_C_5,
		.moffset = 0,
		.mlen = 4,
		.soffset = MLX5_BYTE_OFF(fte_match_param,
					 misc_parameters_2.metadata_reg_c_5),
	},
	[mp_statezone] = mp_statezone_mapping,
	[mp_mark] = mp_mark_mapping,
	[mp_labels] = mp_labels_mapping,
	[mp_user_prio] = {
		.mfield = MLX5_ACTION_IN_FIELD_METADATA_REG_C_5,
		.moffset = 0,
		.mlen = 4,
		.soffset = MLX5_BYTE_OFF(fte_match_param,
					 misc_parameters_2.metadata_reg_c_5),
	},
};

struct match_mapping_params *match_mappings = match_mappings_arr;

int
get_direct_match_mapping(struct mlx5e_priv *priv,
			 struct mlx5_flow_attr *attr,
			 enum match_mapping_type type,
			 u32 data,
			 u32 mask,
			 bool rewrite)
{
	struct mlx5_flow_spec *spec = &attr->parse_attr->spec;
	int moffset = match_mappings[type].moffset;
	int soffset = match_mappings[type].soffset;
	int mfield = match_mappings[type].mfield;
	void *headers_c = spec->match_criteria;
	void *headers_v = spec->match_value;
	int mlen = match_mappings[type].mlen;
	enum mlx5_flow_namespace_type ns;
	struct mlx5_eswitch *esw;


	esw = priv->mdev->priv.eswitch;
	ns = (mlx5_eswitch_mode(esw) == MLX5_ESWITCH_OFFLOADS) ? MLX5_FLOW_NAMESPACE_FDB:
								 MLX5_FLOW_NAMESPACE_KERNEL;
	if (rewrite) {
		size_t action_size = MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto);
		struct mlx5e_tc_flow_parse_attr *parse_attr = attr->parse_attr;
		char *modact;
		int err;

		if (!parse_attr->mod_hdr_actions) {
			err = alloc_mod_hdr_actions(priv, NULL,
						    ns,
						    parse_attr);
			if (err)
				return err;
		} else if (parse_attr->num_mod_hdr_actions == parse_attr->max_mod_hdr_actions) {
			return -ENOSPC;
		}

		modact = parse_attr->mod_hdr_actions +
			 parse_attr->num_mod_hdr_actions * action_size;

		if (mlen == 4)
			mlen = 0;

		MLX5_SET(set_action_in, modact, action_type, MLX5_ACTION_TYPE_SET);
		MLX5_SET(set_action_in, modact, field, mfield);
		MLX5_SET(set_action_in, modact, offset, moffset*8);
		MLX5_SET(set_action_in, modact, length, mlen*8);
		MLX5_SET(set_action_in, modact, data, data);
		parse_attr->num_mod_hdr_actions++;
	} else {
		char *fmask = headers_c + soffset;
		char *fval = headers_v + soffset;

		mask = cpu_to_be32(mask);
		data = cpu_to_be32(data);
		memcpy(fmask, &mask, mlen);
		memcpy(fval, &data, mlen);

		spec->match_criteria_enable |= MLX5_MATCH_MISC_PARAMETERS_2;
	}

	return 0;
}

struct tunnel_mapping {
	struct tunnel_match_key key;
	struct hlist_node tunnel_hlist;

	struct list_head flows; /* struct mlx5e_tc_flow *flow */
	int encap_id;
	int mod_hdr_id;
	u32 match_id;
	struct flow_dissector_key_enc_opts enc_opts;

	struct net_device *dev;
};

static int get_tunnel_mapping(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow,
			      struct tunnel_match_key *key,
			      struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_rep_uplink_priv *uplink_priv;
	struct mlx5e_rep_priv *uplink_rpriv;
	struct tunnel_mapping *mp;
	bool found = false;
	int index = 0, err;
	size_t action_size;
	u32 hash_key;

	action_size = MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto);
	/*
	print_hex_dump(KERN_ERR, "key: ", DUMP_PREFIX_ADDRESS,
			16, 1, key, sizeof(*key), true);
	*/
	hash_key = jhash(key, sizeof(*key), 0);
	if (flow->attr.chain) {
		if (key->enc_opts.len) {
			NL_SET_ERR_MSG_MOD(extack,
					   "later chains with enc_opts matching isn't supported");
			return -EOPNOTSUPP;
		}
		memset(&key->enc_opts, 0, sizeof(key->enc_opts));
		hash_key = jhash(key, sizeof(*key), 0);
		printk(KERN_ERR "%s %d %s @@ searcing...., opts_len: %d, hash: %d\n", __FILE__, __LINE__, __func__, key->enc_opts.len, hash_key);

		/* actually we check that both key and mask are the same. */
		hash_for_each_possible(esw->offloads.tunnel_tbl, mp,
				       tunnel_hlist, hash_key) {
			if (!memcmp(&mp->key, key, sizeof(*key))) {
				found = true;
				break;
			}
		}

		/* later flows must find */
		if (!found) {
			NL_SET_ERR_MSG_MOD(extack,
					   "later chains with different outer match isn't supported");
			return -EOPNOTSUPP;
		}
		printk(KERN_ERR "%s %d %s @@ found match id: %d, attaching.\n", __FILE__, __LINE__, __func__, mp->match_id);
		goto attach_flow;
	}

	printk(KERN_ERR "%s %d %s @@ creating tunnel maping...\n", __FILE__, __LINE__, __func__);

	mp = kzalloc(sizeof(*mp), GFP_KERNEL);
	if (!mp)
		return -ENOMEM;

	INIT_LIST_HEAD(&mp->flows);
	mp->dev = flow->attr.parse_attr->filter_dev;

	/* We don't support enc_opts on later keys, so we copy it to a different
	 * member, and we hash without it */
	memcpy(&mp->key, key, sizeof(*key));
	memcpy(&mp->enc_opts, &key->enc_opts, sizeof(key->enc_opts));
	memset(&mp->key.enc_opts, 0, sizeof(key->enc_opts));
	hash_key = jhash(&mp->key, sizeof(mp->key), 0);

	index = MAX_TUPLE_ID + 1;
	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &uplink_rpriv->uplink_priv;
	err = idr_alloc_u32(&uplink_priv->tunnel_ids, mp, &index, 0xFFFF,
			    GFP_KERNEL);
	if (err)
		goto out_err_idr;
	mp->match_id = index;

	hash_add(esw->offloads.tunnel_tbl, &mp->tunnel_hlist, hash_key);

	printk(KERN_ERR "%s %d %s @@ created: %d (on tunnel_ids: %px), hash: %d, opts_len: %d\n", __FILE__, __LINE__, __func__, mp->match_id, &uplink_priv->tunnel_ids, hash_key, key->enc_opts.len);

attach_flow:
	printk(KERN_ERR "%s %d %s @@ mp: %px attached flow: %px, using match id: %d\n", __FILE__, __LINE__, __func__, mp, flow, mp->match_id);
	list_add(&flow->tunnel, &mp->flows);

	if (!found)
		get_direct_match_mapping(priv, &flow->attr, mp_tunnel_miss,
					 mp->match_id, 0xFFFFFFFF, true);
	get_direct_match_mapping(priv, &flow->attr, mp_tunnel_match,
			mp->match_id, 0xFFFFFFFF, !found);
	flow->attr.tunnel_id = mp->match_id;

	return err;

out_err_idr:
	kfree(mp);
	return err;
}

static void put_tunnel_mapping(struct mlx5e_priv *priv,
			       struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct list_head *next = flow->tunnel.next;
	struct mlx5_rep_uplink_priv *uplink_priv;
	struct mlx5e_rep_priv *uplink_rpriv;
	struct tunnel_mapping *mp;

	if (!flow || list_empty(&flow->tunnel))
		return;

	flow->attr.tunnel_id = 0;
	list_del(&flow->tunnel);

	if (!list_empty(next))
		return;

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &uplink_rpriv->uplink_priv;
	mp = list_entry(next, struct tunnel_mapping, flows);

	printk(KERN_ERR "%s %d %s @@ mp: %px, flow: %px, put tunnel mapping id %d, cleanup (tunnel_ids: %px)\n", __FILE__, __LINE__, __func__, mp, flow, mp->match_id, &uplink_priv->tunnel_ids);

	idr_remove(&uplink_priv->tunnel_ids, mp->match_id);
	kfree(mp);
}

static bool actions_match_supported(struct mlx5e_priv *priv,
				    struct flow_action *flow_action,
				    struct mlx5e_tc_flow_parse_attr *parse_attr,
				    struct mlx5e_tc_flow *flow,
				    struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	bool ct_flow = flow_flag_test(flow, CT);
	bool vlan_emulation;
	u32 actions;

	if (mlx5e_is_eswitch_flow(flow)) {
		actions = flow->attr.action;
		/* TODO: need to check all calls to get_match_headers_criteria and see if they
		 * make sense with chains and not actually decap */
		if (actions & MLX5_FLOW_CONTEXT_ACTION_DECAP &&
		    flow->attr.dest_chain &&
		    !mlx5_eswitch_vport_match_metadata_enabled(esw)) {
			NL_SET_ERR_MSG(extack, "Decap and goto isn't supported without register metadata support");
			return -EOPNOTSUPP;
		}

		/* vlan emulation is handled in mlx5_eswitch_add_vlan_action */
		vlan_emulation = (actions & (MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH |
					     MLX5_FLOW_CONTEXT_ACTION_VLAN_POP)) &&
				 !mlx5_eswitch_vlan_actions_supported(esw->dev, 1);

		if (vlan_emulation) {
			if (ct_flow) {
				NL_SET_ERR_MSG_MOD(extack, "can't offload vlan emulation with action ct");
				return -EOPNOTSUPP;
			}
			if (flow->attr.chain || flow->attr.dest_chain) {
				NL_SET_ERR_MSG_MOD(extack, "can't offload vlan emulation with chains");
				return -EOPNOTSUPP;
			}
		}

		if (flow->attr.split_count && ct_flow) {
			NL_SET_ERR_MSG_MOD(extack, "can't offload mirroring with action ct");
			return -EOPNOTSUPP;
		}
	} else {
		actions = flow->attr.action;
	}

	if (actions & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		return modify_header_match_supported(&parse_attr->spec,
						     flow_action, actions,
						     ct_flow, extack);

	return true;
}

static bool same_hw_devs(struct mlx5e_priv *priv, struct mlx5e_priv *peer_priv)
{
	struct mlx5_core_dev *fmdev, *pmdev;
	u64 fsystem_guid, psystem_guid;

	fmdev = priv->mdev;
	pmdev = peer_priv->mdev;

	fsystem_guid = mlx5_query_nic_system_image_guid(fmdev);
	psystem_guid = mlx5_query_nic_system_image_guid(pmdev);

	return (fsystem_guid == psystem_guid);
}

static int add_vlan_rewrite_action(struct mlx5e_priv *priv, int namespace,
				   const struct flow_action_entry *act,
				   struct mlx5e_tc_flow_parse_attr *parse_attr,
				   struct pedit_headers_action *hdrs,
				   u32 *action, struct netlink_ext_ack *extack)
{
	u16 mask16 = VLAN_VID_MASK;
	u16 val16 = act->vlan.vid & VLAN_VID_MASK;
	const struct flow_action_entry pedit_act = {
		.id = FLOW_ACTION_MANGLE,
		.mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_ETH,
		.mangle.offset = offsetof(struct vlan_ethhdr, h_vlan_TCI),
		.mangle.mask = ~(u32)be16_to_cpu(*(__be16 *)&mask16),
		.mangle.val = (u32)be16_to_cpu(*(__be16 *)&val16),
	};
	u8 match_prio_mask, match_prio_val;
	void *headers_c, *headers_v;
	int err;

	headers_c = get_match_headers_criteria(*action, &parse_attr->spec);
	headers_v = get_match_headers_value(*action, &parse_attr->spec);

	if (!(MLX5_GET(fte_match_set_lyr_2_4, headers_c, cvlan_tag) &&
	      MLX5_GET(fte_match_set_lyr_2_4, headers_v, cvlan_tag))) {
		NL_SET_ERR_MSG_MOD(extack,
				   "VLAN rewrite action must have VLAN protocol match");
		return -EOPNOTSUPP;
	}

	match_prio_mask = MLX5_GET(fte_match_set_lyr_2_4, headers_c, first_prio);
	match_prio_val = MLX5_GET(fte_match_set_lyr_2_4, headers_v, first_prio);
	if (act->vlan.prio != (match_prio_val & match_prio_mask)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Changing VLAN prio is not supported");
		return -EOPNOTSUPP;
	}

	err = parse_tc_pedit_action(priv, &pedit_act, namespace, parse_attr,
				    hdrs, NULL);
	*action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;

	return err;
}

static int
add_vlan_prio_tag_rewrite_action(struct mlx5e_priv *priv,
				 struct mlx5e_tc_flow_parse_attr *parse_attr,
				 struct pedit_headers_action *hdrs,
				 u32 *action, struct netlink_ext_ack *extack)
{
	const struct flow_action_entry prio_tag_act = {
		.vlan.vid = 0,
		.vlan.prio =
			MLX5_GET(fte_match_set_lyr_2_4,
				 get_match_headers_value(*action,
							 &parse_attr->spec),
				 first_prio) &
			MLX5_GET(fte_match_set_lyr_2_4,
				 get_match_headers_criteria(*action,
							    &parse_attr->spec),
				 first_prio),
	};

	return add_vlan_rewrite_action(priv, MLX5_FLOW_NAMESPACE_FDB,
				       &prio_tag_act, parse_attr, hdrs, action,
				       extack);
}

static int parse_tc_nic_actions(struct mlx5e_priv *priv,
				struct flow_action *flow_action,
				struct mlx5e_tc_flow_parse_attr *parse_attr,
				struct mlx5e_tc_flow *flow,
				struct netlink_ext_ack *extack)
{
	struct mlx5_flow_attr *attr = &flow->attr;
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_tc_chains_offload *nic_chains =
				&tc->nic_chains;
	struct pedit_headers_action hdrs[2] = {};
	const struct flow_action_entry *act;
	bool prio_set = false;
	u32 action = 0;
	int err, i;

	if (!flow_action_has_entries(flow_action))
		return -EINVAL;

	attr->flow_tag = MLX5_FS_DEFAULT_FLOW_TAG;

	flow_action_for_each(i, act, flow_action) {
		switch (act->id) {
		case FLOW_ACTION_DROP:
			action |= MLX5_FLOW_CONTEXT_ACTION_DROP;
			if (MLX5_CAP_FLOWTABLE(priv->mdev,
					       flow_table_properties_nic_receive.flow_counter))
				action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
			break;
		case FLOW_ACTION_MANGLE:
		case FLOW_ACTION_ADD:
			err = parse_tc_pedit_action(priv, act, MLX5_FLOW_NAMESPACE_KERNEL,
						    parse_attr, hdrs, extack);
			if (err)
				return err;
			action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
			break;
		case FLOW_ACTION_VLAN_MANGLE:
			err = add_vlan_rewrite_action(priv,
						      MLX5_FLOW_NAMESPACE_KERNEL,
						      act, parse_attr, hdrs,
						      &action, extack);
			if (err)
				return err;

			break;
		case FLOW_ACTION_CSUM:
			if (csum_offload_supported(priv, action,
						   act->csum_flags,
						   extack))
				break;

			return -EOPNOTSUPP;
		case FLOW_ACTION_REDIRECT: {
			struct net_device *peer_dev = act->dev;

			if (priv->netdev->netdev_ops == peer_dev->netdev_ops &&
			    same_hw_devs(priv, netdev_priv(peer_dev))) {
				parse_attr->mirred_ifindex[0] = peer_dev->ifindex;
				flow_flag_set(flow, HAIRPIN);
				action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
					  MLX5_FLOW_CONTEXT_ACTION_COUNT;
			} else {
				NL_SET_ERR_MSG_MOD(extack,
						   "device is not on same HW, can't offload");
				netdev_warn(priv->netdev, "device %s not on same HW, can't offload\n",
					    peer_dev->name);
				return -EINVAL;
			}
			}
			break;
		case FLOW_ACTION_MARK: {
			u32 mark = act->mark;

			if (mark & ~MLX5E_TC_FLOW_ID_MASK) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Bad flow mark - only 16 bit is supported");
				return -EINVAL;
			}

			attr->flow_tag = mark;
			action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
			}
			break;
		case FLOW_ACTION_GOTO: {
			u32 dest_chain = act->chain_index;
			u32 max_chain = mlx5_tc_get_chain_range(nic_chains);

			if (dest_chain <= attr->chain) {
				NL_SET_ERR_MSG(extack, "Goto earlier chain isn't supported");
				return -EOPNOTSUPP;
			}
			if (dest_chain > max_chain) {
				NL_SET_ERR_MSG(extack, "Requested destination chain is out of supported range");
				return -EOPNOTSUPP;
			}
			action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
			attr->dest_chain = dest_chain;
			}
			break;
		case FLOW_ACTION_CT: {
			err = mlx5e_ct_parse_action(flow, act, extack);
			if (err)
				return err;

			flow_flag_set(flow, CT);
			}
			break;
		case FLOW_ACTION_PRIORITY:
			if (act->prio > tc->num_prio_hp) {
				NL_SET_ERR_MSG_MOD(extack, "Skb priority value is out of range");
				return -EINVAL;
			}

			attr->user_prio = act->prio;
			prio_set = true;
			action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack, "The offload action is not supported");
			return -EOPNOTSUPP;
		}
	}

	if (hdrs[TCA_PEDIT_KEY_EX_CMD_SET].pedits ||
	    hdrs[TCA_PEDIT_KEY_EX_CMD_ADD].pedits) {
		err = alloc_tc_pedit_action(priv, MLX5_FLOW_NAMESPACE_KERNEL,
					    parse_attr, hdrs, &action, extack);
		if (err)
			return err;
		/* in case all pedit actions are skipped, remove the MOD_HDR
		 * flag.
		 */
		if (parse_attr->num_mod_hdr_actions == 0) {
			action &= ~MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
			kfree(parse_attr->mod_hdr_actions);
		}
	}

	if (prio_set) {
		err = get_direct_match_mapping(priv, attr, mp_user_prio,
					       attr->user_prio, 0xFFFFFFFF, true);
		if (err) {
			netdev_warn(priv->netdev, "Failed to user prio in modify_hdr, err %d\n", err);
			return err;
		}
	}

	attr->action = action;

	if (attr->dest_chain) {
		if (attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
			NL_SET_ERR_MSG(extack, "Mirroring goto chain rules isn't supported");
			return -EOPNOTSUPP;
		}
		attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	}

	if (attr->action & MLX5_FLOW_CONTEXT_ACTION_MOD_HDR)
		attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;

	if (!actions_match_supported(priv, flow_action, parse_attr, flow, extack))
		return -EOPNOTSUPP;

	return 0;
}

struct encap_key {
	const struct ip_tunnel_key *ip_tun_key;
	struct mlx5e_tc_tunnel *tc_tunnel;
};

static inline int cmp_encap_info(struct encap_key *a,
				 struct encap_key *b)
{
	return memcmp(a->ip_tun_key, b->ip_tun_key, sizeof(*a->ip_tun_key)) ||
	       a->tc_tunnel->tunnel_type != b->tc_tunnel->tunnel_type;
}

static inline int hash_encap_info(struct encap_key *key)
{
	return jhash(key->ip_tun_key, sizeof(*key->ip_tun_key),
		     key->tc_tunnel->tunnel_type);
}


static bool is_merged_eswitch_dev(struct mlx5e_priv *priv,
				  struct net_device *peer_netdev)
{
	struct mlx5e_priv *peer_priv;

	peer_priv = netdev_priv(peer_netdev);

	return (MLX5_CAP_ESW(priv->mdev, merged_eswitch) &&
		mlx5e_eswitch_rep(priv->netdev) &&
		mlx5e_eswitch_rep(peer_netdev) &&
		same_hw_devs(priv, peer_priv));
}



static int mlx5e_attach_encap(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow,
			      struct net_device *mirred_dev,
			      int out_index,
			      struct netlink_ext_ack *extack,
			      struct net_device **encap_dev,
			      bool *encap_valid)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5_flow_attr *attr = &flow->attr;
	const struct ip_tunnel_info *tun_info;
	struct encap_key key, e_key;
	struct mlx5e_encap_entry *e;
	unsigned short family;
	uintptr_t hash_key;
	bool found = false;
	int err = 0;

	parse_attr = attr->parse_attr;
	tun_info = parse_attr->tun_info[out_index];
	family = ip_tunnel_info_af(tun_info);
	key.ip_tun_key = &tun_info->key;
	key.tc_tunnel = mlx5e_get_tc_tun(mirred_dev);
	if (!key.tc_tunnel) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported tunnel");
		return -EOPNOTSUPP;
	}

	hash_key = hash_encap_info(&key);

	hash_for_each_possible_rcu(esw->offloads.encap_tbl, e,
				   encap_hlist, hash_key) {
		e_key.ip_tun_key = &e->tun_info->key;
		e_key.tc_tunnel = e->tunnel;
		if (!cmp_encap_info(&e_key, &key)) {
			found = true;
			break;
		}
	}

	/* must verify if encap is valid or not */
	if (found)
		goto attach_flow;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->tun_info = tun_info;
	err = mlx5e_tc_tun_init_encap_attr(mirred_dev, priv, e, extack);
	if (err)
		goto out_err;

	INIT_LIST_HEAD(&e->flows);

	if (family == AF_INET)
		err = mlx5e_tc_tun_create_header_ipv4(priv, mirred_dev, e);
	else if (family == AF_INET6)
		err = mlx5e_tc_tun_create_header_ipv6(priv, mirred_dev, e);

	if (err)
		goto out_err;

	hash_add_rcu(esw->offloads.encap_tbl, &e->encap_hlist, hash_key);

attach_flow:
	list_add(&flow->encaps[out_index].list, &e->flows);
	flow->encaps[out_index].index = out_index;
	*encap_dev = e->out_dev;
	if (e->flags & MLX5_ENCAP_ENTRY_VALID) {
		attr->dests[out_index].encap_id = e->encap_id;
		attr->dests[out_index].flags |= MLX5_ESW_DEST_ENCAP_VALID;
		*encap_valid = true;
	} else {
		*encap_valid = false;
	}

	return err;

out_err:
	kfree(e);
	return err;
}

static int parse_tc_vlan_action(struct mlx5e_priv *priv,
				const struct flow_action_entry *act,
				struct mlx5_flow_attr *attr,
				u32 *action)
{
	u8 vlan_idx = attr->total_vlan;

	if (vlan_idx >= MLX5_FS_VLAN_DEPTH)
		return -EOPNOTSUPP;

	switch (act->id) {
	case FLOW_ACTION_VLAN_POP:
		if (vlan_idx) {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev,
								 MLX5_FS_VLAN_DEPTH))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP_2;
		} else {
			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
		}
		break;
	case FLOW_ACTION_VLAN_PUSH:
		attr->vlan_vid[vlan_idx] = act->vlan.vid;
		attr->vlan_prio[vlan_idx] = act->vlan.prio;
		attr->vlan_proto[vlan_idx] = act->vlan.proto;
		if (!attr->vlan_proto[vlan_idx])
			attr->vlan_proto[vlan_idx] = htons(ETH_P_8021Q);

		if (vlan_idx) {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev,
								 MLX5_FS_VLAN_DEPTH))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH_2;
		} else {
			if (!mlx5_eswitch_vlan_actions_supported(priv->mdev, 1) &&
			    (act->vlan.proto != htons(ETH_P_8021Q) ||
			     act->vlan.prio))
				return -EOPNOTSUPP;

			*action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH;
		}
		break;
	default:
		return -EINVAL;
	}

	attr->total_vlan = vlan_idx + 1;

	return 0;
}

static int add_vlan_push_action(struct mlx5e_priv *priv,
				struct mlx5_flow_attr *attr,
				struct net_device **out_dev,
				u32 *action)
{
	struct net_device *vlan_dev = *out_dev;
	struct flow_action_entry vlan_act = {
		.id = FLOW_ACTION_VLAN_PUSH,
		.vlan.vid = vlan_dev_vlan_id(vlan_dev),
		.vlan.proto = vlan_dev_vlan_proto(vlan_dev),
		.vlan.prio = 0,
	};
	int err;

	err = parse_tc_vlan_action(priv, &vlan_act, attr, action);
	if (err)
		return err;

	*out_dev = dev_get_by_index_rcu(dev_net(vlan_dev),
					dev_get_iflink(vlan_dev));
	if (is_vlan_dev(*out_dev))
		err = add_vlan_push_action(priv, attr, out_dev, action);

	return err;
}

static int add_vlan_pop_action(struct mlx5e_priv *priv,
			       struct mlx5_flow_attr *attr,
			       u32 *action)
{
	int nest_level = vlan_get_encap_level(attr->parse_attr->filter_dev);
	struct flow_action_entry vlan_act = {
		.id = FLOW_ACTION_VLAN_POP,
	};
	int err = 0;

	while (nest_level--) {
		err = parse_tc_vlan_action(priv, &vlan_act, attr, action);
		if (err)
			return err;
	}

	return err;
}

bool mlx5e_is_valid_eswitch_fwd_dev(struct mlx5e_priv *priv,
				    struct net_device *out_dev)
{
	if (is_merged_eswitch_dev(priv, out_dev))
		return true;

	return mlx5e_eswitch_rep(out_dev) &&
	       same_hw_devs(priv, netdev_priv(out_dev));
}

static int parse_tc_fdb_actions(struct mlx5e_priv *priv,
				struct flow_action *flow_action,
				struct mlx5e_tc_flow *flow,
				struct netlink_ext_ack *extack)
{
	struct pedit_headers_action hdrs[2] = {};
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_tc_chains_offload *fdb_chains =
			&esw->fdb_table.offloads.fdb_chains;
	struct mlx5_flow_attr *attr = &flow->attr;
	struct mlx5e_tc_flow_parse_attr *parse_attr = attr->parse_attr;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	const struct ip_tunnel_info *info = NULL;
	const struct flow_action_entry *act;
	bool encap = false;
	u32 action = 0;
	int err, i;

	if (!flow_action_has_entries(flow_action))
		return -EINVAL;

	flow_action_for_each(i, act, flow_action) {
		switch (act->id) {
		case FLOW_ACTION_DROP:
			action |= MLX5_FLOW_CONTEXT_ACTION_DROP |
				  MLX5_FLOW_CONTEXT_ACTION_COUNT;
			break;
		case FLOW_ACTION_MANGLE:
		case FLOW_ACTION_ADD:
			err = parse_tc_pedit_action(priv, act, MLX5_FLOW_NAMESPACE_FDB,
						    parse_attr, hdrs, extack);
			if (err)
				return err;

			action |= MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
			attr->split_count = attr->out_count;
			break;
		case FLOW_ACTION_CSUM:
			if (csum_offload_supported(priv, action,
						   act->csum_flags, extack))
				break;

			return -EOPNOTSUPP;
		case FLOW_ACTION_REDIRECT:
		case FLOW_ACTION_MIRRED: {
			struct mlx5e_priv *out_priv;
			struct net_device *out_dev;

			out_dev = act->dev;
			if (!out_dev) {
				/* out_dev is NULL when filters with
				 * non-existing mirred device are replayed to
				 * the driver.
				 */
				return -EINVAL;
			}

			if (attr->out_count >= MLX5_MAX_FLOW_FWD_VPORTS) {
				NL_SET_ERR_MSG_MOD(extack,
						   "can't support more output ports, can't offload forwarding");
				return -EOPNOTSUPP;
			}

			action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
				  MLX5_FLOW_CONTEXT_ACTION_COUNT;
			if (netdev_port_same_parent_id(priv->netdev, out_dev)) {
				struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
				struct net_device *uplink_dev = mlx5_eswitch_uplink_get_proto_dev(esw, REP_ETH);
				struct net_device *uplink_upper = netdev_master_upper_dev_get(uplink_dev);

				if (uplink_upper &&
				    netif_is_lag_master(uplink_upper) &&
				    uplink_upper == out_dev)
					out_dev = uplink_dev;

				if (is_vlan_dev(out_dev)) {
					err = add_vlan_push_action(priv, attr,
								   &out_dev,
								   &action);
					if (err)
						return err;
				}

				if (is_vlan_dev(parse_attr->filter_dev)) {
					err = add_vlan_pop_action(priv, attr,
								  &action);
					if (err)
						return err;
				}

				if (!mlx5e_is_valid_eswitch_fwd_dev(priv, out_dev)) {
					NL_SET_ERR_MSG_MOD(extack,
							   "devices are not on same switch HW, can't offload forwarding");
					pr_err("devices %s %s not on same switch HW, can't offload forwarding\n",
					       priv->netdev->name, out_dev->name);
					return -EOPNOTSUPP;
				}

				out_priv = netdev_priv(out_dev);
				rpriv = out_priv->ppriv;
				attr->dests[attr->out_count].rep = rpriv->rep;
				attr->dests[attr->out_count].mdev = out_priv->mdev;
				attr->out_count++;
			} else if (encap) {
				parse_attr->mirred_ifindex[attr->out_count] =
					out_dev->ifindex;
				parse_attr->tun_info[attr->out_count] = info;
				encap = false;
				attr->dests[attr->out_count].flags |=
					MLX5_ESW_DEST_ENCAP;
				attr->out_count++;
				/* attr->dests[].rep is resolved when we
				 * handle encap
				 */
			} else if (parse_attr->filter_dev != priv->netdev) {
				/* All mlx5 devices are called to configure
				 * high level device filters. Therefore, the
				 * *attempt* to  install a filter on invalid
				 * eswitch should not trigger an explicit error
				 */
				return -EINVAL;
			} else {
				NL_SET_ERR_MSG_MOD(extack,
						   "devices are not on same switch HW, can't offload forwarding");
				pr_err("devices %s %s not on same switch HW, can't offload forwarding\n",
				       priv->netdev->name, out_dev->name);
				return -EINVAL;
			}
			}
			break;
		case FLOW_ACTION_TUNNEL_ENCAP:
			info = act->tunnel;
			if (info)
				encap = true;
			else
				return -EOPNOTSUPP;

			break;
		case FLOW_ACTION_VLAN_PUSH:
		case FLOW_ACTION_VLAN_POP:
			if (act->id == FLOW_ACTION_VLAN_PUSH &&
			    (action & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP)) {
				/* Replace vlan pop+push with vlan modify */
				action &= ~MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
				err = add_vlan_rewrite_action(priv,
							      MLX5_FLOW_NAMESPACE_FDB,
							      act, parse_attr, hdrs,
							      &action, extack);
			} else {
				err = parse_tc_vlan_action(priv, act, attr, &action);
			}
			if (err)
				return err;

			attr->split_count = attr->out_count;
			break;
		case FLOW_ACTION_VLAN_MANGLE:
			err = add_vlan_rewrite_action(priv,
						      MLX5_FLOW_NAMESPACE_FDB,
						      act, parse_attr, hdrs,
						      &action, extack);
			if (err)
				return err;

			attr->split_count = attr->out_count;
			break;
		case FLOW_ACTION_TUNNEL_DECAP:
			action |= MLX5_FLOW_CONTEXT_ACTION_DECAP;
			break;
		case FLOW_ACTION_GOTO: {
			u32 dest_chain = act->chain_index;
			u32 max_chain = mlx5_tc_get_chain_range(fdb_chains);

			if (dest_chain <= attr->chain) {
				NL_SET_ERR_MSG(extack, "Goto earlier chain isn't supported");
				return -EOPNOTSUPP;
			}
			if (dest_chain > max_chain) {
				NL_SET_ERR_MSG(extack, "Requested destination chain is out of supported range");
				return -EOPNOTSUPP;
			}
			action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
			attr->dest_chain = dest_chain;
			break;
			}
		case FLOW_ACTION_CT: {
			err = mlx5e_ct_parse_action(flow, act, extack);
			if (err)
				return err;

			flow_flag_set(flow, CT);
			break;
			}
		default:
			NL_SET_ERR_MSG_MOD(extack, "The offload action is not supported");
			return -EOPNOTSUPP;
		}
	}

	if (MLX5_CAP_GEN(esw->dev, prio_tag_required) &&
	    action & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP) {
		/* For prio tag mode, replace vlan pop with rewrite vlan prio
		 * tag rewrite.
		 */
		action &= ~MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
		err = add_vlan_prio_tag_rewrite_action(priv, parse_attr, hdrs,
						       &action, extack);
		if (err)
			return err;
	}

	if (hdrs[TCA_PEDIT_KEY_EX_CMD_SET].pedits ||
	    hdrs[TCA_PEDIT_KEY_EX_CMD_ADD].pedits) {
		err = alloc_tc_pedit_action(priv, MLX5_FLOW_NAMESPACE_FDB,
					    parse_attr, hdrs, &action, extack);
		if (err)
			return err;
		/* in case all pedit actions are skipped, remove the MOD_HDR
		 * flag. we might have set split_count either by pedit or
		 * pop/push. if there is no pop/push either, reset it too.
		 */
		if (parse_attr->num_mod_hdr_actions == 0) {
			action &= ~MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
			kfree(parse_attr->mod_hdr_actions);
			if (!((action & MLX5_FLOW_CONTEXT_ACTION_VLAN_POP) ||
			      (action & MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH)))
				attr->split_count = 0;
		}
	}

	attr->action = action;
	if (!actions_match_supported(priv, flow_action, parse_attr, flow, extack))
		return -EOPNOTSUPP;

	if (encap && flow_flag_test(flow, CT)) {
		/* TODO: Handle neigh update so we can allow this */
		NL_SET_ERR_MSG(extack, "Encap and ct rules aren't supported");
		return -EOPNOTSUPP;
	}

	if (attr->dest_chain) {
		if (attr->action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
			NL_SET_ERR_MSG(extack, "Mirroring goto chain rules isn't supported");
			return -EOPNOTSUPP;
		}
		attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	}

	if (attr->split_count > 0 && !mlx5_esw_has_fwd_fdb(priv->mdev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "current firmware doesn't support split rule for port mirroring");
		netdev_warn_once(priv->netdev, "current firmware doesn't support split rule for port mirroring\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static const struct rhashtable_params tc_ht_params = {
	.head_offset = offsetof(struct mlx5e_tc_flow, node),
	.key_offset = offsetof(struct mlx5e_tc_flow, cookie),
	.key_len = sizeof(((struct mlx5e_tc_flow *)0)->cookie),
	.automatic_shrinking = true,
};

static struct rhashtable *get_tc_ht(struct mlx5e_priv *priv, int flags)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;

	if (flags & MLX5_TC_FLAG(ESWITCH)) {
		uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
		return &uplink_rpriv->uplink_priv.tc_ht;
	} else /* NIC offload */
		return &priv->fs.tc.ht;
}

struct mlx5e_tc_flow *mlx5e_tc_get_flow(struct mlx5e_priv *priv,
					int flags,
					unsigned long cookie)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);

	return rhashtable_lookup_fast(tc_ht, &cookie, tc_ht_params);
}

static bool is_peer_flow_needed(struct mlx5e_tc_flow *flow)
{
	struct mlx5_flow_attr *attr = &flow->attr;
	bool is_rep_ingress = attr->in_rep->vport != MLX5_VPORT_UPLINK &&
			      flow_flag_test(flow, INGRESS);
	bool act_is_encap = !!(attr->action &
			       MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT);
	bool esw_paired = mlx5_devcom_is_paired(attr->in_mdev->priv.devcom,
						MLX5_DEVCOM_ESW_OFFLOADS);

	if (!esw_paired)
		return false;

	if ((mlx5_lag_is_sriov(attr->in_mdev) ||
	     mlx5_lag_is_multipath(attr->in_mdev)) &&
	    (is_rep_ingress || act_is_encap))
		return true;

	return false;
}

static int
mlx5e_alloc_flow(struct mlx5e_priv *priv,
		 struct flow_cls_offload *f, u16 flow_flags,
		 struct mlx5e_tc_flow_parse_attr **__parse_attr,
		 struct mlx5e_tc_flow **__flow)
{
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int err;

	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	parse_attr = kvzalloc(sizeof(*parse_attr), GFP_KERNEL);
	if (!parse_attr || !flow) {
		err = -ENOMEM;
		goto err_free;
	}

	flow->cookie = f->cookie;
	flow->flags = flow_flags;
	flow->priv = priv;

	*__flow = flow;
	*__parse_attr = parse_attr;

	return 0;

err_free:
	kfree(flow);
	kvfree(parse_attr);
	return err;
}

static void
mlx5e_flow_attr_init(struct mlx5_flow_attr *attr,
		     struct mlx5e_priv *priv,
		     struct mlx5e_tc_flow_parse_attr *parse_attr,
		     struct flow_cls_offload *f,
		     bool is_eswitch_flow,
		     struct mlx5_eswitch_rep *in_rep,
		     struct mlx5_core_dev *in_mdev)
{
	attr->parse_attr = parse_attr;
	attr->chain = f->common.chain_index;
	attr->prio = f->common.prio;
	attr->counter_dev = priv->mdev;

	if (is_eswitch_flow) {
		struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;

		attr->in_rep = in_rep;
		attr->in_mdev = in_mdev;

		if (MLX5_CAP_ESW(esw->dev, counter_eswitch_affinity) ==
		    MLX5_COUNTER_SOURCE_ESWITCH)
			attr->counter_dev = in_mdev;
	}
}

static struct mlx5e_tc_flow *
__mlx5e_add_fdb_flow(struct mlx5e_priv *priv,
		     struct flow_cls_offload *f,
		     u16 flow_flags,
		     struct net_device *filter_dev,
		     struct mlx5_eswitch_rep *in_rep,
		     struct mlx5_core_dev *in_mdev)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct netlink_ext_ack *extack = f->common.extack;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int err;

	flow_flags |= MLX5_TC_FLAG(ESWITCH);
	err = mlx5e_alloc_flow(priv, f, flow_flags,
			       &parse_attr, &flow);
	if (err)
		goto out;

	parse_attr->filter_dev = filter_dev;
	mlx5e_flow_attr_init(&flow->attr,
			     priv, parse_attr,
			     f, true, in_rep, in_mdev);

	err = parse_cls_flower(flow->priv, flow, &parse_attr->spec,
			       f, filter_dev);
	if (err)
		goto err_free;

	err = parse_tc_fdb_actions(priv, &rule->action, flow, extack);
	if (err)
		goto err_free;

	if (flow_flag_test(flow, EGRESS) && !flow->attr.chain &&
	    mlx5_eswitch_vport_match_metadata_enabled(esw)) {
		flow->attr.action |= MLX5_FLOW_CONTEXT_ACTION_DECAP;
		printk(KERN_ERR "%s %d %s @@ egress flow: %px, implicit decap, actions: %d\n", __FILE__, __LINE__, __func__, flow, flow->attr.action);
	}

	err = mlx5e_ct_parse_match(flow, f, extack);
	if (err)
		goto err_free;

	err = mlx5e_tc_add_fdb_flow(priv, flow, extack);
	if (err) {
		if (!(err == -ENETUNREACH && mlx5_lag_is_multipath(in_mdev)))
			goto err_free;

		add_unready_flow(flow);
	}

	return flow;

err_free:
	kfree(flow);
	kvfree(parse_attr);
out:
	return ERR_PTR(err);
}

static int mlx5e_tc_add_fdb_peer_flow(struct flow_cls_offload *f,
				      struct mlx5e_tc_flow *flow,
				      u16 flow_flags)
{
	struct mlx5e_priv *priv = flow->priv, *peer_priv;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch, *peer_esw;
	struct mlx5_devcom *devcom = priv->mdev->priv.devcom;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_rep_priv *peer_urpriv;
	struct mlx5e_tc_flow *peer_flow;
	struct mlx5_core_dev *in_mdev;
	int err = 0;

	peer_esw = mlx5_devcom_get_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
	if (!peer_esw)
		return -ENODEV;

	peer_urpriv = mlx5_eswitch_get_uplink_priv(peer_esw, REP_ETH);
	peer_priv = netdev_priv(peer_urpriv->netdev);

	/* in_mdev is assigned of which the packet originated from.
	 * So packets redirected to uplink use the same mdev of the
	 * original flow and packets redirected from uplink use the
	 * peer mdev.
	 */
	if (flow->attr.in_rep->vport == MLX5_VPORT_UPLINK)
		in_mdev = peer_priv->mdev;
	else
		in_mdev = priv->mdev;

	parse_attr = flow->attr.parse_attr;
	peer_flow = __mlx5e_add_fdb_flow(peer_priv, f, flow_flags,
					 parse_attr->filter_dev,
					 flow->attr.in_rep, in_mdev);
	if (IS_ERR(peer_flow)) {
		err = PTR_ERR(peer_flow);
		goto out;
	}

	flow->peer_flow = peer_flow;
	flow_flag_set(flow, DUP);
	mutex_lock(&esw->offloads.peer_mutex);
	list_add_tail(&flow->peer, &esw->offloads.peer_flows);
	mutex_unlock(&esw->offloads.peer_mutex);

out:
	mlx5_devcom_release_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
	return err;
}

static int
mlx5e_add_fdb_flow(struct mlx5e_priv *priv,
		   struct flow_cls_offload *f,
		   u16 flow_flags,
		   struct net_device *filter_dev,
		   struct mlx5e_tc_flow **__flow)
{
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *in_rep = rpriv->rep;
	struct mlx5_core_dev *in_mdev = priv->mdev;
	struct mlx5e_tc_flow *flow;
	int err;

	flow = __mlx5e_add_fdb_flow(priv, f, flow_flags, filter_dev, in_rep,
				    in_mdev);
	if (IS_ERR(flow))
		return PTR_ERR(flow);

	if (is_peer_flow_needed(flow)) {
		err = mlx5e_tc_add_fdb_peer_flow(f, flow, flow_flags);
		if (err) {
			mlx5e_tc_del_fdb_flow(priv, flow);
			goto out;
		}
	}

	*__flow = flow;

	return 0;

out:
	return err;
}

static int
mlx5e_add_nic_flow(struct mlx5e_priv *priv,
		   struct flow_cls_offload *f,
		   u16 flow_flags,
		   struct net_device *filter_dev,
		   struct mlx5e_tc_flow **__flow)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct netlink_ext_ack *extack = f->common.extack;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	struct mlx5e_tc_flow *flow;
	int err;

	/* multi-chain not supported for NIC rules */
	//if (!tc_cls_can_offload_and_chain0(priv->netdev, &f->common))
	//	return -EOPNOTSUPP;

	flow_flags |= MLX5_TC_FLAG(NIC);
	err = mlx5e_alloc_flow(priv, f, flow_flags,
			       &parse_attr, &flow);
	if (err)
		goto out;

	parse_attr->filter_dev = filter_dev;
	mlx5e_flow_attr_init(&flow->attr,
			     priv, parse_attr,
			     f, false, NULL, NULL);

	//ARIEL TODO: check if we support metadata reg_c0

	err = parse_cls_flower(flow->priv, flow, &parse_attr->spec,
			       f, filter_dev);
	if (err)
		goto err_free;

	err = parse_tc_nic_actions(priv, &rule->action, parse_attr, flow, extack);
	if (err)
		goto err_free;

	err = mlx5e_ct_parse_match(flow, f, extack);
	if (err)
		goto err_free;

	err = mlx5e_tc_add_nic_flow(priv, parse_attr, flow, extack);
	if (err)
		goto err_free;

	flow_flag_set(flow, OFFLOADED);
	*__flow = flow;

	return 0;

err_free:
	kfree(flow);
	kvfree(parse_attr);
out:
	return err;
}

static int
mlx5e_tc_add_flow(struct mlx5e_priv *priv,
		  struct flow_cls_offload *f,
		  int flags,
		  struct net_device *filter_dev,
		  struct mlx5e_tc_flow **flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int err;

	if (!tc_can_offload_extack(priv->netdev, f->common.extack))
		return -EOPNOTSUPP;

	if (esw && esw->mode == MLX5_ESWITCH_OFFLOADS)
		err = mlx5e_add_fdb_flow(priv, f, flags,
					 filter_dev, flow);
	else
		err = mlx5e_add_nic_flow(priv, f, flags,
					 filter_dev, flow);

	return err;
}

int mlx5e_configure_flower(struct net_device *dev, struct mlx5e_priv *priv,
			   struct flow_cls_offload *f, int flags)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct mlx5e_tc_flow *flow;
	int err = 0;

	flow = rhashtable_lookup_fast(tc_ht, &f->cookie, tc_ht_params);
	if (flow) {
		NL_SET_ERR_MSG_MOD(extack,
				   "flow cookie already exists, ignoring");
		netdev_warn_once(priv->netdev,
				 "flow cookie %lx already exists, ignoring\n",
				 f->cookie);
		err = -EEXIST;
		goto out;
	}

	err = mlx5e_tc_add_flow(priv, f, flags, dev, &flow);
	if (err)
		goto out;

	err = rhashtable_insert_fast(tc_ht, &flow->node, tc_ht_params);
	if (err)
		goto err_free;

	return 0;

err_free:
	mlx5e_tc_del_flow(priv, flow);
	kfree(flow);
out:
	return err;
}

#define FLOW_DIRECTION_MASK (MLX5_TC_FLAG(INGRESS) | MLX5_TC_FLAG(EGRESS))

static bool same_flow_direction(struct mlx5e_tc_flow *flow, int flags)
{
	if ((flow->flags & FLOW_DIRECTION_MASK) == (flags & FLOW_DIRECTION_MASK))
		return true;

	return false;
}

int mlx5e_delete_flower(struct net_device *dev, struct mlx5e_priv *priv,
			struct flow_cls_offload *f, int flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct mlx5e_tc_flow *flow;

	flow = rhashtable_lookup_fast(tc_ht, &f->cookie, tc_ht_params);
	if (!flow || !same_flow_direction(flow, flags))
		return -EINVAL;

	rhashtable_remove_fast(tc_ht, &flow->node, tc_ht_params);

	mlx5e_tc_del_flow(priv, flow);

	kfree(flow);

	return 0;
}

int mlx5e_stats_flower(struct net_device *dev, struct mlx5e_priv *priv,
		       struct flow_cls_offload *f, int flags)
{
	struct mlx5_devcom *devcom = priv->mdev->priv.devcom;
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct mlx5_eswitch *peer_esw;
	struct mlx5e_tc_flow *flow;
	struct mlx5_fc *counter;
	u64 lastuse = 0;
	u64 packets = 0;
	u64 bytes = 0;

	flow = rhashtable_lookup_fast(tc_ht, &f->cookie, tc_ht_params);
	if (!flow || !same_flow_direction(flow, flags))
		return -EINVAL;

	if (mlx5e_is_offloaded_flow(flow) || flow_flag_test(flow, CT)) {
		counter = mlx5e_tc_get_counter(flow);
		if (!counter)
			return 0;

		mlx5_fc_query_cached(counter, &bytes, &packets, &lastuse);
	}

	/* Under multipath it's possible for one rule to be currently
	 * un-offloaded while the other rule is offloaded.
	 */
	peer_esw = mlx5_devcom_get_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
	if (!peer_esw)
		goto out;

	if (flow_flag_test(flow, DUP) &&
	    mlx5e_is_offloaded_flow(flow->peer_flow)) {
		u64 bytes2;
		u64 packets2;
		u64 lastuse2;

		counter = mlx5e_tc_get_counter(flow->peer_flow);
		if (!counter)
			goto no_peer_counter;
		mlx5_fc_query_cached(counter, &bytes2, &packets2, &lastuse2);

		bytes += bytes2;
		packets += packets2;
		lastuse = max_t(u64, lastuse, lastuse2);
	}

no_peer_counter:
	mlx5_devcom_release_peer_data(devcom, MLX5_DEVCOM_ESW_OFFLOADS);
out:
	flow_stats_update(&f->stats, bytes, packets, lastuse);

	return 0;
}

static void mlx5e_tc_hairpin_update_dead_peer(struct mlx5e_priv *priv,
					      struct mlx5e_priv *peer_priv)
{
	struct mlx5_core_dev *peer_mdev = peer_priv->mdev;
	struct mlx5e_hairpin_entry *hpe;
	u16 peer_vhca_id;
	int bkt;

	if (!same_hw_devs(priv, peer_priv))
		return;

	peer_vhca_id = MLX5_CAP_GEN(peer_mdev, vhca_id);

	hash_for_each(priv->fs.tc.hairpin_tbl, bkt, hpe, hairpin_hlist) {
		if (hpe->peer_vhca_id == peer_vhca_id)
			hpe->hp->pair->peer_gone = true;
	}
}

static int mlx5e_tc_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct mlx5e_flow_steering *fs;
	struct mlx5e_priv *peer_priv;
	struct mlx5e_tc_table *tc;
	struct mlx5e_priv *priv;

	if (ndev->netdev_ops != &mlx5e_netdev_ops ||
	    event != NETDEV_UNREGISTER ||
	    ndev->reg_state == NETREG_REGISTERED)
		return NOTIFY_DONE;

	tc = container_of(this, struct mlx5e_tc_table, netdevice_nb);
	fs = container_of(tc, struct mlx5e_flow_steering, tc);
	priv = container_of(fs, struct mlx5e_priv, fs);
	peer_priv = netdev_priv(ndev);
	if (priv == peer_priv ||
	    !(priv->netdev->features & NETIF_F_HW_TC))
		return NOTIFY_DONE;

	mlx5e_tc_hairpin_update_dead_peer(priv, peer_priv);

	return NOTIFY_DONE;
}

struct mlx5_flow_table *
nic_rx_create_next_ft(struct mlx5_tc_chains_offload *nic_chains,
		      u32 chain, u32 prio, u32 level,
		      struct mlx5_flow_table *next_ft)
{
	struct mlx5_core_dev *dev = nic_chains->dev;
	struct mlx5_flow_namespace *ns = mlx5_get_flow_namespace(dev,
						MLX5_FLOW_NAMESPACE_KERNEL);
	struct mlx5_flow_table_attr ft_attr = {};
	int grp_sz, sz;
	struct mlx5_flow_table *ft;
	u32 max_flow_counter;

	max_flow_counter = (MLX5_CAP_GEN(dev, max_flow_counter_31_16) << 16) |
		MLX5_CAP_GEN(dev, max_flow_counter_15_0);

	grp_sz = min_t(int, max_flow_counter, MLX5E_TC_TABLE_MAX_GROUP_SIZE);

	sz = min_t(int, grp_sz * MLX5E_TC_TABLE_NUM_GROUPS + 1,
		   BIT(MLX5_CAP_FLOWTABLE_NIC_RX(dev, log_max_ft_size)));

	ft_attr.max_fte = (level == MLX5E_TC_TTC_FT_LEVEL) ? MLX5E_NUM_TT : sz;
	ft_attr.next_ft = next_ft;

	if (!TC_CHAIN_OFFLOAD_IGNORE_FLOW_LEVEL(nic_chains) ||
	    (chain == 0 && prio == 1 && level == 0)) {
		/* First table to be managed by fs_core */
		ft_attr.unmanaged = false;
		ft_attr.level = level;
		ft_attr.prio = (chain * TC_MAX_PRIO) + prio - 1;
	} else {
		ft_attr.unmanaged = true;
		ft_attr.prio = MLX5E_TC_PRIO;
		ft_attr.level = 1;
	}

	//printk(KERN_ERR "%s %d %s @@ creating ft, chain: %d, prio: %d, level: %d, sz: %d, managed: %d, next_ft: %px\n", __FILE__, __LINE__, __func__, chain, prio, level, ft_attr.max_fte, !ft_attr.unmanaged, next_ft);
	ft = mlx5_create_flow_table(ns, &ft_attr);
	if (IS_ERR(ft))
		esw_warn(dev, "Failed to create NIC RX Table err %d (chain %d, prio: %d, level: %d, actual level: %d, size: %d)\n",
			 (int)PTR_ERR(ft), chain, prio, level, ft->level, sz);

	ft->autogroup.active = true;
	ft->autogroup.required_groups = 5;

//	printk(KERN_ERR "%s %d %s @@ created ft: %px, chain: %d, prio: %d, level: %d, actual level: %d, sz: %d\n", __FILE__, __LINE__, __func__, ft, chain, prio, level, ft->level, sz);

	return ft;
}

int mlx5e_tc_nic_init(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_tc_chains_offload *nic_chains =
			&tc->nic_chains;
	int err;

	hash_init(tc->mod_hdr_tbl);
	hash_init(tc->hairpin_tbl);
	err = init_tc_chains_offload(priv->mdev, nic_chains,
				     nic_rx_create_next_ft);
	if (err)
		return err;

	err = mlx5e_ct_init(priv, &tc->ct_control);
	if (err)
		goto ct_init_err;

	err = rhashtable_init(&tc->ht, &tc_ht_params);
	if (err)
		goto ht_init_err;

	/* ariel todo: check dev caps - supporting metadata */
	err = mlx5_create_restore_table(nic_chains,
					MLX5_FLOW_NAMESPACE_KERNEL,
					MLX5E_TC_RESTORE_PRIO);
	if (err)
		goto restore_err;

	nic_chains->flags |= MLX5_TC_CHAINS_AND_PRIOS_SUPPORTED;
	nic_chains->restore_dest_ft = priv->fs.vlan.ft.t;
	nic_chains->miss_ft = nic_chains->ft_offloads_restore;

	tc->netdevice_nb.notifier_call = mlx5e_tc_netdev_event;
	if (register_netdevice_notifier(&tc->netdevice_nb)) {
		tc->netdevice_nb.notifier_call = NULL;
		mlx5_core_warn(priv->mdev, "Failed to register netdev notifier\n");
	}

	rcu_assign_pointer(tc_skb_update_hook, mlx5e_nic_update_skb);

	return 0;

restore_err:
	rhashtable_destroy(&tc->ht);
ht_init_err:
	mlx5e_ct_clean(&tc->ct_control);
ct_init_err:
	destroy_tc_chains_offload(&priv->fs.tc.nic_chains);
	return err;
}

static void _mlx5e_tc_del_flow(void *ptr, void *arg)
{
	struct mlx5e_tc_flow *flow = ptr;
	struct mlx5e_priv *priv = flow->priv;

	mlx5e_tc_del_flow(priv, flow);
	kfree(flow);
}

void mlx5e_tc_nic_cleanup(struct mlx5e_priv *priv)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, MLX5_TC_FLAG(NIC));
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5_tc_chains_offload *nic_chains =
			&tc->nic_chains;

	RCU_INIT_POINTER(tc_skb_update_hook, NULL);
	synchronize_rcu();

	if (tc->netdevice_nb.notifier_call)
		unregister_netdevice_notifier(&tc->netdevice_nb);

	mlx5e_ct_clean(&tc->ct_control);
	rhashtable_free_and_destroy(tc_ht, _mlx5e_tc_del_flow, NULL);
	if (!IS_ERR_OR_NULL(tc->t)) {
		mlx5_tc_chain_put_prio_table(nic_chains, 0, 1, 0);
		tc->t = NULL;
	}

	mlx5e_prio_hairpin_mode_disable(priv);

	mlx5_destroy_restore_table(nic_chains);
	destroy_tc_chains_offload(nic_chains);
}

int mlx5e_tc_esw_init(struct rhashtable *tc_ht)
{
	struct mlx5_rep_uplink_priv *uplink_priv;
	struct mlx5e_rep_priv *priv;
	struct mlx5e_priv *npriv;
	int err;

	uplink_priv = container_of(tc_ht, struct mlx5_rep_uplink_priv, tc_ht);
	idr_init(&uplink_priv->tunnel_ids);
	priv = container_of(uplink_priv, struct mlx5e_rep_priv, uplink_priv);
	npriv = netdev_priv(priv->netdev); 
	err = mlx5e_ct_init(npriv, (struct mlx5e_ct_control **)&uplink_priv->ct_control);
	if (err)
		return err;

	err = rhashtable_init(tc_ht, &tc_ht_params);
	if (err)
		goto ht_init_err;

	rcu_assign_pointer(tc_skb_update_hook, mlx5e_esw_update_skb);

	return 0;

ht_init_err:
	mlx5e_ct_clean((struct mlx5e_ct_control **)&uplink_priv->ct_control);

	return err;
}

void mlx5e_tc_esw_cleanup(struct rhashtable *tc_ht)
{
	struct mlx5_rep_uplink_priv *uplink_priv;

	RCU_INIT_POINTER(tc_skb_update_hook, NULL);
	synchronize_rcu();

	uplink_priv = container_of(tc_ht, struct mlx5_rep_uplink_priv, tc_ht);
	idr_destroy(&uplink_priv->tunnel_ids);
	mlx5e_ct_clean((struct mlx5e_ct_control **)&uplink_priv->ct_control);

	rhashtable_free_and_destroy(tc_ht, _mlx5e_tc_del_flow, NULL);
}

int mlx5e_tc_num_filters(struct mlx5e_priv *priv, int flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);

	return atomic_read(&tc_ht->nelems);
}

void mlx5e_tc_clean_fdb_peer_flows(struct mlx5_eswitch *esw)
{
	struct mlx5e_tc_flow *flow, *tmp;

	list_for_each_entry_safe(flow, tmp, &esw->offloads.peer_flows, peer)
		__mlx5e_tc_del_fdb_peer_flow(flow);
}

void mlx5e_tc_reoffload_flows_work(struct work_struct *work)
{
	struct mlx5_rep_uplink_priv *rpriv =
		container_of(work, struct mlx5_rep_uplink_priv,
			     reoffload_flows_work);
	struct mlx5e_tc_flow *flow, *tmp;

	rtnl_lock();
	list_for_each_entry_safe(flow, tmp, &rpriv->unready_flows, unready) {
		if (!mlx5e_tc_add_fdb_flow(flow->priv, flow, NULL))
			remove_unready_flow(flow);
	}
	rtnl_unlock();
}

static int mlx5e_restore_tunnel(struct mlx5_rep_uplink_priv *uplink_priv,
				struct sk_buff *skb, u32 tunnel_id)
{
	struct tunnel_match_key *key;
	struct metadata_dst *tun_dst;
	struct tunnel_mapping *mp;

	mp = idr_find(&uplink_priv->tunnel_ids, tunnel_id);
	if (!mp) {
		printk(KERN_ERR "%s %d %s @@ skb: %pxb, tunnel: %d failed\n", __FILE__, __LINE__, __func__, skb, tunnel_id);
		return 0;
	}
	key = &mp->key;

	tun_dst = tun_rx_dst(mp->enc_opts.len);
	if (!tun_dst) {
		WARN_ON(1);
		return -ENOMEM;
	}

	ip_tunnel_key_init(&tun_dst->u.tun_info.key,
			   key->enc_ipv4.src, key->enc_ipv4.dst, /* ip */
			   0, 64, /* tos, ttl */
			   0, /* label */
			   key->enc_tp.src, key->enc_tp.dst, /* ports */
			   key32_to_tunnel_id(key->enc_key_id.keyid),//ntohl(key->enc_key_id.keyid)),
			   TUNNEL_KEY);

	if (mp->enc_opts.len) {
		ip_tunnel_info_opts_set(&tun_dst->u.tun_info,
					mp->enc_opts.data,
					mp->enc_opts.len,
					mp->enc_opts.dst_opt_type);
	}

	skb_dst_set(skb, (struct dst_entry *)tun_dst);
	skb->dev = mp->dev;

	return 0;
}

u32 mlx5e_get_chain_for_tag(struct mlx5_tc_chains_offload *offload, u32 tag)
{
	struct tc_chain *tc_chain;

	tc_chain = idr_find(&offload->chain_ids, tag & MAX_CHAIN_TAG);
	if (!tc_chain) {
		printk(KERN_ERR "%s %d %s @@ can't find tag: %d\n", __FILE__, __LINE__, __func__, tag & MAX_CHAIN_TAG);
		return 0;
	}

	return tc_chain->chain;
}

int mlx5e_nic_update_skb(struct sk_buff *skb, u32 reg_c0, u32 reg_c1)
{
	struct mlx5e_priv *priv = netdev_priv(skb->dev);
	struct tc_skb_ext *chainp;
	u32 chain = 0, tunnel_tuple_id = 0;

	if (!reg_c0) {
		if (WARN_ON_ONCE(reg_c1))
			printk(KERN_ERR "%s %d %s @@ reg_c1 should be zero, but it's %d\n", __FILE__, __LINE__, __func__, reg_c1);
		return 0;
	}

	chain = mlx5e_get_chain_for_tag(&priv->fs.tc.nic_chains, reg_c0);
	if (WARN_ON_ONCE(chain == 0))
		return 0;
	chainp = skb_ext_add(skb, TC_SKB_EXT);
	if (!chainp) {
		WARN_ON(1);
		return 0;
	}

	chainp->chain = chain;

	tunnel_tuple_id = reg_c1;
	if (tunnel_tuple_id <= MAX_TUPLE_ID) {
		u32 tunnel_id = 0;

		mlx5e_ct_restore_flow(priv->fs.tc.ct_control, skb, tunnel_tuple_id, &tunnel_id);
	}

	return 0;
}

int mlx5e_esw_update_skb(struct sk_buff *skb, u32 reg_c0, u32 reg_c1)
{
	struct mlx5_rep_uplink_priv *uplink_priv;
	struct mlx5e_rep_priv *uplink_rpriv;
	u32 chain = 0, tunnel_tuple_id = 0;
	struct tc_skb_ext *chainp;
	struct mlx5_eswitch *esw;
	struct mlx5e_priv *priv;

	if (!mlx5e_eswitch_rep(skb->dev))
		return 0;

	priv = netdev_priv(skb->dev);
	esw = priv->mdev->priv.eswitch;
	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &uplink_rpriv->uplink_priv;

	if (!reg_c0) {
		if (WARN_ON_ONCE(reg_c1))
			printk(KERN_ERR "%s %d %s @@ reg_c1 should be zero, but it's %d\n", __FILE__, __LINE__, __func__, reg_c1);
		return 0;
	}

	chain = mlx5e_get_chain_for_tag(&esw->fdb_table.offloads.fdb_chains,
				       reg_c0);
	if (WARN_ON_ONCE(chain == 0))
		return 0;

	chainp = skb_ext_add(skb, TC_SKB_EXT);
	if (!chainp) {
		WARN_ON(1);
		return 0;
	}

	chainp->chain = chain;

	tunnel_tuple_id = reg_c1;
	if (tunnel_tuple_id <= MAX_TUPLE_ID) {
		u32 tunnel_id = 0;

		mlx5e_ct_restore_flow(uplink_priv->ct_control, skb, tunnel_tuple_id, &tunnel_id);
		if (tunnel_id)
			mlx5e_restore_tunnel(uplink_priv, skb, tunnel_id);
	} else {
		mlx5e_restore_tunnel(uplink_priv, skb, tunnel_tuple_id);
	}

	return 0;
}

/* Flow Steering support for TC chains */
static const struct rhashtable_params chain_params = {
	.head_offset = offsetof(struct tc_chain, node),
	.key_offset = offsetof(struct tc_chain, chain),
	.key_len = sizeof(int),
	.automatic_shrinking = true,
};

static const struct rhashtable_params prio_params = {
	.head_offset = offsetof(struct tc_prio, node),
	.key_offset = offsetof(struct tc_prio, chain),
	.key_len = sizeof(u32) * 3,
	.automatic_shrinking = true,
};

unsigned int mlx5_tc_get_chain_range(struct mlx5_tc_chains_offload *offload)
{
	if (!TC_CHAIN_OFFLOAD_CHAINS_PRIOS_SUPPORT(offload))
		return 1;

	if (TC_CHAIN_OFFLOAD_IGNORE_FLOW_LEVEL(offload))
		return UINT_MAX;

	return TC_MAX_CHAIN;
}

unsigned int mlx5_tc_get_prio_range(struct mlx5_tc_chains_offload *offload)
{
	if (!TC_CHAIN_OFFLOAD_CHAINS_PRIOS_SUPPORT(offload))
		return 1;

	if (TC_CHAIN_OFFLOAD_IGNORE_FLOW_LEVEL(offload))
		return UINT_MAX;

	return TC_MAX_PRIO;
}

unsigned int mlx5_tc_get_level_range(struct mlx5_tc_chains_offload *offload)
{
	if (!TC_CHAIN_OFFLOAD_CHAINS_PRIOS_SUPPORT(offload))
		return 1;

	if (TC_CHAIN_OFFLOAD_IGNORE_FLOW_LEVEL(offload))
		return UINT_MAX;

	return TC_MAX_LEVEL;
}

int init_tc_chains_offload(struct mlx5_core_dev *dev,
			   struct mlx5_tc_chains_offload *offload,
			   create_ft_cb ft_cb)
{
	int err;

	mutex_init(&offload->chains_lock);
	idr_init(&offload->chain_ids);

	err = rhashtable_init(&offload->chains_ht, &chain_params);
	if (err)
		return err;

	err = rhashtable_init(&offload->prios_ht, &prio_params);
	if (err) {
		rhashtable_destroy(&offload->chains_ht);
		idr_destroy(&offload->chain_ids);
		mutex_destroy(&offload->chains_lock);
		return err;
	}

	/* Fill with based on FW cap per table type */
	offload->flags |= MLX5_TC_IGNORE_FT_LEVEL;

	offload->dev = dev;
	offload->create_next_ft = ft_cb;

	return 0;
}

void destroy_tc_chains_offload(struct mlx5_tc_chains_offload *offload)
{
	rhashtable_destroy(&offload->prios_ht);
	rhashtable_destroy(&offload->chains_ht);
	idr_destroy(&offload->chain_ids);
	mutex_destroy(&offload->chains_lock);
}

static struct mlx5_flow_handle
*add_hdr_restore_rule(struct mlx5_tc_chains_offload *offload, int tag)
{
	struct mlx5_flow_act flow_act = { .flags = FLOW_ACT_NO_APPEND, };
	struct mlx5_flow_table *ft = offload->ft_offloads_restore;
	struct mlx5_flow_context *flow_context;
	struct mlx5_flow_spec s, *spec = &s;
	struct mlx5_flow_handle *flow_rule;
	struct mlx5_flow_destination dest;
	void *misc;

	memset(spec, 0, sizeof(*spec));
	misc = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc, metadata_reg_c_0, MAX_CHAIN_TAG);
	misc = MLX5_ADDR_OF(fte_match_param, spec->match_value, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc, metadata_reg_c_0, tag);
	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS_2;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
		MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
	flow_act.modify_id = offload->restore_copy_hdr_id;

	flow_context = &spec->flow_context;
	flow_context->flags |= FLOW_CONTEXT_HAS_TAG;
	flow_context->flow_tag = tag;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = offload->restore_dest_ft;
//	printk(KERN_ERR "%s %d %s @@ adding restore rule, tag: %d, copy_hdr_id: %d\n", __FILE__, __LINE__, __func__, tag, offload->restore_copy_hdr_id);
	flow_rule = mlx5_add_flow_rules(ft, spec, &flow_act, &dest, 1);

	if (IS_ERR(flow_rule))
		mlx5_core_warn(offload->dev, "Failed to create restore rule for tag: %d, err(%d)\n", tag, (int) PTR_ERR(flow_rule));

	return flow_rule;
}

static struct tc_chain *create_tc_chain(struct mlx5_tc_chains_offload *offload, u32 chain,
					enum mlx5_flow_namespace_type ns_type)
{
	char modact[MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto)];
	struct tc_chain *tc_chain = NULL;
	int err;

	tc_chain = kvzalloc(sizeof(*tc_chain), GFP_KERNEL);
	if (!tc_chain) {
		printk(KERN_ERR "%s %d %s @@ err: %d\n", __FILE__, __LINE__, __func__, -ENOMEM);
		return ERR_PTR(-ENOMEM);
	}

	tc_chain->chain = chain;
	INIT_LIST_HEAD(&tc_chain->prios_list);

	if (chain) {
		u32 index = 1;

		err = idr_alloc_u32(&offload->chain_ids, tc_chain, &index,
				    MAX_CHAIN_TAG, GFP_KERNEL);
		if (err) {
			printk(KERN_ERR "%s %d %s @@ err: %d\n", __FILE__, __LINE__, __func__, err);
			goto err_idr;
		}
		tc_chain->id = index;
	}

	MLX5_SET(set_action_in, modact, action_type, MLX5_ACTION_TYPE_SET);
	MLX5_SET(set_action_in, modact, field, match_mappings[mp_chain].mfield);
	MLX5_SET(set_action_in, modact, offset, match_mappings[mp_chain].moffset*8);
	MLX5_SET(set_action_in, modact, length, match_mappings[mp_chain].mlen*8);
	MLX5_SET(set_action_in, modact, data, tc_chain->id);

	err = mlx5_modify_header_alloc(offload->dev, ns_type,
				       1, modact, &tc_chain->miss_hdr_id);
	//printk(KERN_ERR "%s %d %s @@ chain: %d, created miss header: %d (tag: %d), err: %d\n", __FILE__, __LINE__, __func__, chain, tc_chain->miss_hdr_id, tc_chain->id, err);
	if (err) {
		printk(KERN_ERR "%s %d %s @@ err: %d\n", __FILE__, __LINE__, __func__, err);
		goto err_mod_hdr;
	}

	tc_chain->restore_rule = add_hdr_restore_rule(offload, tc_chain->id);
	if (IS_ERR(tc_chain->restore_rule)) {
		err = PTR_ERR(tc_chain->restore_rule);
		printk(KERN_ERR "%s %d %s @@ err: %d\n", __FILE__, __LINE__, __func__, err);
		goto err_restore;
	}

	err = rhashtable_insert_fast(&offload->chains_ht, &tc_chain->node,
				     chain_params);
	if (err) {
		printk(KERN_ERR "%s %d %s @@ err: %d\n", __FILE__, __LINE__, __func__, err);
		goto err_insert;
	}

	//printk(KERN_ERR "%s %d %s @@ created new chain: %d\n", __FILE__, __LINE__, __func__, chain);
	return tc_chain;

err_insert:
	mlx5_del_flow_rules(tc_chain->restore_rule);
err_restore:
	mlx5_modify_header_dealloc(offload->dev, tc_chain->miss_hdr_id);
err_mod_hdr:
	if (tc_chain->id)
		idr_remove(&offload->chain_ids, tc_chain->id); /* need to fix race with datapath here */
err_idr:
	kvfree(tc_chain);
	return ERR_PTR(err);
}

static void destroy_tc_chain(struct mlx5_tc_chains_offload *offload, struct tc_chain *tc_chain)
{
	//printk(KERN_ERR "%s %d %s @@ destroy chain: %d\n", __FILE__, __LINE__, __func__, tc_chain->chain);
	rhashtable_remove_fast(&offload->chains_ht, &tc_chain->node,
			       chain_params);
	mlx5_del_flow_rules(tc_chain->restore_rule);
	mlx5_modify_header_dealloc(offload->dev, tc_chain->miss_hdr_id);
	if (tc_chain->id)
		idr_remove(&offload->chain_ids, tc_chain->id);
	kvfree(tc_chain);
}

static struct tc_chain *get_tc_chain(struct mlx5_tc_chains_offload *offload, u32 chain,
				     enum mlx5_flow_namespace_type type)
{
	struct tc_chain *tc_chain;

	tc_chain = rhashtable_lookup_fast(&offload->chains_ht, &chain,
					   chain_params);
	if (!tc_chain) {
		//printk(KERN_ERR "%s %d %s @@ chain: %d, creating...\n", __FILE__, __LINE__, __func__, chain);
		tc_chain = create_tc_chain(offload, chain, type);
		if (IS_ERR(tc_chain))
			return tc_chain;
	}

	tc_chain->ref++;
	//printk(KERN_ERR "%s %d %s @@ chain: %d, after ref: %d\n", __FILE__, __LINE__, __func__, chain, tc_chain->ref);

	return tc_chain;
}

static void put_tc_chain(struct mlx5_tc_chains_offload *offload,
			 struct tc_chain *tc_chain)
{
	//printk(KERN_ERR "%s %d %s @@ chain: %d, ref before dec: %d\n", __FILE__, __LINE__, __func__, tc_chain->chain, tc_chain->ref);
	if (--tc_chain->ref == 0) {
		//printk(KERN_ERR "%s %d %s @@ chain: %d, destroy\n", __FILE__, __LINE__, __func__, tc_chain->chain);
		destroy_tc_chain(offload, tc_chain);
	}
}


#define prio_fmt "%px (chain: %d, prio: %d, level: %d)"
#define prio_fmt_s "(%d, %d, %d)"
#define prio_print(tc_prio) (tc_prio), (tc_prio)->chain, (tc_prio)->prio, (tc_prio)->level
#define prio_print_s(tc_prio) (tc_prio)->chain, (tc_prio)->prio, (tc_prio)->level
#define prio_from_list(l) list_entry(l, struct tc_prio, list)
#define prio_list_params(l) (prio_from_list(l)), (prio_from_list(l))->chain, (prio_from_list(l))->prio, (prio_from_list(l))->level
static struct tc_prio *create_tc_prio(struct mlx5_tc_chains_offload *offload,
					u32 chain, u32 prio, u32 level,
					enum mlx5_flow_namespace_type type)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_handle *miss_rule = NULL;
	struct tc_prio *tc_prio = NULL;
	struct mlx5_flow_spec spec = {};
	struct mlx5_flow_table *next_ft;
	struct mlx5_flow_act act = {0};
	struct tc_chain *tc_chain;
	struct list_head *pos;
	u32 *flow_group_in;
	int err;

	tc_chain = get_tc_chain(offload, chain, type);
	if (IS_ERR(tc_chain))
		return ERR_CAST(tc_chain);

	tc_prio = kvzalloc(sizeof(*tc_prio), GFP_KERNEL);
	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!tc_prio || !flow_group_in) {
		err = -ENOMEM;
		printk(KERN_ERR "%s %d %s @@ err: %d\n", __FILE__, __LINE__, __func__, err);
		goto err_alloc;
	}

	tc_prio->chain = chain;
	tc_prio->prio = prio;
	tc_prio->level = level;
	tc_prio->tc_chain = tc_chain;

	/* prio list is sorted by prio and level, and for each
	 * prio we expect to have level 0 (expected to be handled by user of
	 * this API), example list: (3,0)->(3,2)->(5,0)->(5,3)->(7,0)
	 * All levels point to next prio level 0.
	 * In hardware, we will we have the following pointers:
	 * (3,0) -> (5,0) -> (7,0)
	 * (3,2) -> (5,0)
	 * (5,3) -> (7,0)
	 * */
	next_ft = offload->miss_ft;
	list_for_each(pos, &tc_chain->prios_list) {
		struct tc_prio *p = list_entry(pos, struct tc_prio, list);

		//printk(KERN_ERR "%s %d %s @@ "prio_fmt_s" < "prio_fmt_s"?\n", __FILE__, __LINE__, __func__, prio_print_s(tc_prio), prio_print_s(p));
		if (prio < p->prio || (prio == p->prio && level < p->level)) /* exit on first that is largest */
		{
			next_ft = (p->level == 0) ? p->ft : p->next_ft;
			//printk(KERN_ERR "%s %d %s @@ "prio_fmt" break\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));
			break;
		}
	}
	tc_prio->next_ft = next_ft;


	tc_prio->ft = offload->create_next_ft(offload, tc_chain->chain,
					      prio, level, offload->miss_ft);
	if (IS_ERR(tc_prio->ft)) {
		err = PTR_ERR(tc_prio->ft);
		printk(KERN_ERR "%s %d %s @@ "prio_fmt" err: %d\n",  __FILE__, __LINE__, __func__, prio_print(tc_prio), err);
		goto err_create;
	}

	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" ft: %px, tc_prio->ft autogroups: %d, creating group\n", __FILE__, __LINE__, __func__,
	//			     prio_print(tc_prio), tc_prio->ft, tc_prio->ft->autogroup.active);
	if (!level) {
		MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, tc_prio->ft->max_fte-3);
		MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, tc_prio->ft->max_fte-1);
		tc_prio->miss_group = mlx5_create_flow_group(tc_prio->ft,
							     flow_group_in);
		tc_prio->ft->autogroup.num_groups++;
		if (IS_ERR(tc_prio->miss_group)) {
			err = PTR_ERR(tc_prio->miss_group);
			printk(KERN_ERR "%s %d %s @@ "prio_fmt" err: %d\n",  __FILE__, __LINE__, __func__, prio_print(tc_prio), err);
			goto err_group;
		}
	}
	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" fg: %px (id: %d)\n", __FILE__, __LINE__, __func__, prio_print(tc_prio),  tc_prio->miss_group, tc_prio->miss_group->id);

	/* We handle miss rules just for level 0 tables and we expect
	 * level 0 to be added first for each prio, other levels are
	 * ignored. */
	if (!level && (next_ft == offload->miss_ft)) { /* if next is miss table */
		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" creating miss rule to offload->miss_ft at %px, using miss hdr: %d\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), offload->miss_ft, tc_chain->miss_hdr_id);
		memset(&act, 0, sizeof(act));
		act.action = MLX5_FLOW_CONTEXT_ACTION_MOD_HDR |
			     MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
		act.modify_id = tc_chain->miss_hdr_id;
		act.ignore_level = true;
		act.flags = FLOW_ACT_NO_APPEND;
		dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		dest.ft = offload->miss_ft;
		miss_rule = mlx5_add_flow_rules(tc_prio->ft, &spec, &act,
						&dest, 1);
		if (IS_ERR(miss_rule)) {
			err = PTR_ERR(miss_rule);
			//printk(KERN_ERR "%s %d %s @@ "prio_fmt" err: %d\n",  __FILE__, __LINE__, __func__, prio_print(tc_prio), err);
			goto err_miss_rule;
		}

		tc_prio->miss_rule = miss_rule;
	} else if (!level) {
		memset(&act, 0, sizeof(act));
		act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
		act.ignore_level = true;
		act.flags = FLOW_ACT_NO_APPEND;
		dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		dest.ft = next_ft;
		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" creating miss rule to next ft %px\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), next_ft);
		miss_rule = mlx5_add_flow_rules(tc_prio->ft, &spec, &act,
						&dest, 1);
		if (IS_ERR(miss_rule)) {
			err = PTR_ERR(miss_rule);
			//printk(KERN_ERR "%s %d %s @@ "prio_fmt" err: %d\n",  __FILE__, __LINE__, __func__, prio_print(tc_prio), err);
			goto err_miss_rule;
		}

		tc_prio->miss_rule = miss_rule;
		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" setting miss_rule: %px\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), tc_prio->miss_rule);
	}

	if (!level && pos->prev != &tc_chain->prios_list) {
		/* update prev */
		struct tc_prio *pos_prio = list_entry(pos,
						       struct tc_prio,
						       list);

		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" update prevs\n",  __FILE__, __LINE__, __func__, prio_print(tc_prio));
		list_for_each_entry_continue_reverse(pos_prio,
						     &tc_chain->prios_list,
						     list) {
			if (pos_prio->level)
				continue;

			//printk(KERN_ERR "%s %d %s @@ updating "prio_fmt" to point to "prio_fmt"\n", __FILE__, __LINE__, __func__, prio_print(pos_prio), prio_print(tc_prio));

			memset(&act, 0, sizeof(act));
			act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
			act.ignore_level = true;
			act.flags = FLOW_ACT_NO_APPEND;
			dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
			dest.ft = tc_prio->ft;
			miss_rule = mlx5_add_flow_rules(pos_prio->ft, &spec, &act,
							&dest, 1);
			if (IS_ERR(miss_rule)) {
				err = PTR_ERR(miss_rule);
				//printk(KERN_ERR "%s %d %s @@ "prio_fmt" error adding miss rule: %d\n", __FILE__, __LINE__, __func__, prio_print(pos_prio), err);
				miss_rule = NULL;
				goto err_prev_rule;
			}

			if (pos_prio->miss_rule) {
				//printk(KERN_ERR "%s %d %s @@ "prio_fmt" deleting miss rule %px\n", __FILE__, __LINE__, __func__, prio_print(pos_prio), pos_prio->miss_rule);
				mlx5_del_flow_rules(pos_prio->miss_rule);
			} else {
				//printk(KERN_ERR "%s %d %s @@ "prio_fmt" no miss rulle?\n", __FILE__, __LINE__, __func__, prio_print(pos_prio));
			}

			pos_prio->miss_rule = miss_rule;
			//printk(KERN_ERR "%s %d %s @@ "prio_fmt" setting miss_rule: %px\n", __FILE__, __LINE__, __func__, prio_print(pos_prio), pos_prio->miss_rule);
			break;

			/*
			WARN_ON(mlx5_set_flow_table_next(pos_prio->fdb,
							 tc_prio->fdb));
			*/
		}
	}

	list_add(&tc_prio->list, pos->prev);

	{
		char list[256] = "";
		struct tc_prio *t;

		list_for_each_entry(t, &tc_chain->prios_list, list) {
			sprintf(list, "%s "prio_fmt_s"", list, prio_print_s(t));
		}
		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" list: %s\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), list);
	}

	err = rhashtable_insert_fast(&offload->prios_ht, &tc_prio->node,
				     prio_params);
	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" add to prios_ht: %d\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), err);

	kvfree(flow_group_in);
	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" created\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));
	return tc_prio;

err_prev_rule:
	if (miss_rule)
		mlx5_del_flow_rules(miss_rule);
err_miss_rule:
	if (tc_prio->miss_group)
		mlx5_destroy_flow_group(tc_prio->miss_group);
err_group:
	mlx5_destroy_flow_table(tc_prio->ft);
err_create:
err_alloc:
	//printk(KERN_ERR "%s %d %s @@ %d\n", __FILE__, __LINE__, __func__, err);
	kvfree(tc_prio);
	kvfree(flow_group_in);
	put_tc_chain(offload, tc_chain);
	return ERR_PTR(err);
}

struct mlx5_flow_table *
mlx5_tc_chain_get_prio_table(struct mlx5_tc_chains_offload *offload,
			     u32 chain, u32 prio, u32 level,
			     enum mlx5_flow_namespace_type type)
{
	struct tc_prio *tc_prio;
	struct {
		u32 chain;
		u32 prio;
		u32 level;
	} key = { chain, prio, level };

	if (chain > mlx5_tc_get_chain_range(offload) ||
	    prio > mlx5_tc_get_prio_range(offload) ||
	    level > mlx5_tc_get_level_range(offload))
		return ERR_PTR(-EOPNOTSUPP);

	//printk(KERN_ERR "%s %d %s @@ chain: %d, prio: %d: level: %d\n", __FILE__, __LINE__, __func__, chain, prio, level);

	mutex_lock(&offload->chains_lock);
	tc_prio = rhashtable_lookup_fast(&offload->prios_ht, &key,
					 prio_params);
	if (!tc_prio) {
		//printk(KERN_ERR "%s %d %s @@ chain: %d, prio: %d: level: %d, creating...\n", __FILE__, __LINE__, __func__, chain, prio, level);
		tc_prio = create_tc_prio(offload, chain, prio, level, type);
		if (IS_ERR(tc_prio))
			goto err_create_prio;
	}

	++tc_prio->ref;
	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" before inc %d, fdb: %px\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), tc_prio->ref, tc_prio->ft);
	mutex_unlock(&offload->chains_lock);

	return tc_prio->ft;

err_create_prio:
	mutex_unlock(&offload->chains_lock);
	return ERR_CAST(tc_prio);
}

static void destroy_tc_prio(struct mlx5_tc_chains_offload *offload, struct tc_prio *tc_prio)
{
	struct tc_chain *tc_chain = tc_prio->tc_chain;
	struct list_head *next = tc_prio->list.next;
	//printk(KERN_ERR "%s %d %s @@ "prio_fmt"\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));

	if (!tc_prio->level) {
		struct mlx5_flow_destination dest = {};
		struct mlx5_flow_handle *miss_rule;
		struct mlx5_flow_spec spec = {};
		struct mlx5_flow_act act = {0};
		struct tc_prio *pos = tc_prio;

		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" - update prevs\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));
		if (next == &tc_chain->prios_list) {
			//printk(KERN_ERR "%s %d %s @@ "prio_fmt" was max updating chain miss rule\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));
			list_for_each_entry_continue_reverse(pos,
							     &tc_chain->prios_list,
							     list) {
				if (pos->level)
					continue;

				//printk(KERN_ERR "%s %d %s @@ "prio_fmt" moving it to point to slow path, using mod hdr: %d\n", __FILE__, __LINE__, __func__, prio_print(pos), tc_chain->miss_hdr_id);
				memset(&act, 0, sizeof(act));
				act.action = MLX5_FLOW_CONTEXT_ACTION_MOD_HDR |
					     MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
				act.modify_id = tc_chain->miss_hdr_id;
				act.ignore_level = true;
				act.flags = FLOW_ACT_NO_APPEND;
				dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
				dest.ft = offload->miss_ft;
				miss_rule = mlx5_add_flow_rules(pos->ft, &spec, &act,
								&dest, 1);
				if (WARN_ON(IS_ERR(miss_rule))) {
					printk(KERN_ERR "%s %d %s @@ "prio_fmt" out of sync: %d\n", __FILE__, __LINE__, __func__, prio_print(pos), (int) PTR_ERR(miss_rule));
					break;
				}

				if (pos->miss_rule) {
					//printk(KERN_ERR "%s %d %s @@ "prio_fmt" deleting miss rule: %px\n", __FILE__, __LINE__, __func__, prio_print(pos), pos->miss_rule);
					mlx5_del_flow_rules(pos->miss_rule);
				} else {
					//printk(KERN_ERR "%s %d %s @@ "prio_fmt" no miss rule!\n", __FILE__, __LINE__, __func__, prio_print(pos));
				}
				pos->miss_rule = miss_rule;
				//printk(KERN_ERR "%s %d %s @@ "prio_fmt" setting miss rule: %px\n", __FILE__, __LINE__, __func__, prio_print(pos), pos->miss_rule);
				break;
			}
		} else {
			list_for_each_entry_continue_reverse(pos,
						             &tc_chain->prios_list,
							     list) {
				//struct tc_prio *n = list_entry(tc_prio->list.next, struct tc_prio, list);

				if (pos->level)
					continue;

				//printk(KERN_ERR "%s %d %s @@ "prio_fmt" updating miss to -> "prio_fmt")\n", __FILE__, __LINE__, __func__, prio_print(pos), prio_print(n));

				memset(&act, 0, sizeof(act));
				act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
				act.ignore_level = true;
				act.flags = FLOW_ACT_NO_APPEND;
				dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
				dest.ft = tc_prio->next_ft;
				miss_rule = mlx5_add_flow_rules(pos->ft, &spec, &act,
								&dest, 1);
				if (IS_ERR(miss_rule)) {
					int err = PTR_ERR(miss_rule);
					printk(KERN_ERR "%s %d %s @@ "prio_fmt" error adding miss rule %d ft %px to next_ft %px\n",
					       __FILE__, __LINE__, __func__, prio_print(pos), err, pos->ft, dest.ft);
					break;
				}

				if (pos->miss_rule) {
					//printk(KERN_ERR "%s %d %s @@ "prio_fmt" deleting miss rule: %px\n", __FILE__, __LINE__, __func__, prio_print(pos), pos->miss_rule);
					mlx5_del_flow_rules(pos->miss_rule);
				} else {
					//printk(KERN_ERR "%s %d %s @@ "prio_fmt" no miss rule!\n", __FILE__, __LINE__, __func__, prio_print(pos));
				}
				pos->miss_rule = miss_rule;
				//printk(KERN_ERR "%s %d %s @@ "prio_fmt" setting miss rule: %px\n", __FILE__, __LINE__, __func__, prio_print(pos), pos->miss_rule);
				break;
			}
		}
	}

	rhashtable_remove_fast(&offload->prios_ht, &tc_prio->node,
			       prio_params);
	list_del(&tc_prio->list);

	if (!tc_prio->level) {
		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" deleting miss rule: %px\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), tc_prio->miss_rule);
		mlx5_del_flow_rules(tc_prio->miss_rule);
	}
	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" deleting miss group: %px\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), tc_prio->miss_group);
	if (tc_prio->miss_group) {
		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" deleting miss group ft %px\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), tc_prio->ft);
		mlx5_destroy_flow_group(tc_prio->miss_group);
	}
	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" deleting ft: %px, is_empty? %d\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), tc_prio->ft, list_empty(&tc_prio->ft->fwd_rules));
	mlx5_destroy_flow_table(tc_prio->ft);

	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" put chain\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));
	put_tc_chain(offload, tc_chain);
	//printk(KERN_ERR "%s %d %s @@ "prio_fmt" free\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));
	kvfree(tc_prio);
}

void
mlx5_tc_chain_put_prio_table(struct mlx5_tc_chains_offload *offload,
			     u32 chain, u32 prio, u32 level)
{
	struct tc_prio *tc_prio;
	struct {
		u32 chain;
		u32 prio;
		u32 level;
	} key = { chain, prio, level };

	//printk(KERN_ERR "%s %d %s @@ chain: %d, prio: %d: level: %d, destroy...\n", __FILE__, __LINE__, __func__, chain, prio, level);

	mutex_lock(&offload->chains_lock);
	tc_prio = rhashtable_lookup_fast(&offload->prios_ht, &key,
					  prio_params);
	if (!tc_prio)
		goto err_get_prio;

	//printk(KERN_ERR "%s %d %s @ "prio_fmt" ref before dec: %d\n", __FILE__, __LINE__, __func__, prio_print(tc_prio), tc_prio->ref);
	if (--tc_prio->ref == 0) {
		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" destroy...\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));
		destroy_tc_prio(offload, tc_prio);
		//printk(KERN_ERR "%s %d %s @@ "prio_fmt" destroy... done\n", __FILE__, __LINE__, __func__, prio_print(tc_prio));
	}
	mutex_unlock(&offload->chains_lock);
	return;

err_get_prio:
	mutex_unlock(&offload->chains_lock);
	WARN_ON(1);
}

void mlx5_destroy_restore_table(struct mlx5_tc_chains_offload *offload)
{
	mlx5_modify_header_dealloc(offload->dev, offload->restore_copy_hdr_id);
	mlx5_destroy_flow_group(offload->restore_group);
	mlx5_destroy_flow_table(offload->ft_offloads_restore);
}

int mlx5_create_restore_table(struct mlx5_tc_chains_offload *offload,
			      enum mlx5_flow_namespace_type ns_type,
			      u16 ft_prio)
{
	//struct mlx5_flow_act flow_act = { .flags = FLOW_ACT_NO_APPEND, };
	char modact[MLX5_UN_SZ_BYTES(set_action_in_add_action_in_auto)];
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_core_dev *dev = offload->dev;
	struct mlx5_flow_namespace *ns;
	void *match_criteria, *misc;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *g;
	int mod_hdr_id, err = 0;
	u32 *flow_group_in;

	ns = mlx5_get_flow_namespace(dev, ns_type);
	if (!ns) {
		mlx5_core_warn(dev, "Failed to get restore ft namespace type:%d\n", ns_type);
		return -EOPNOTSUPP;
	}

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in) {
		err = -ENOMEM;
		goto out_free;
	}

	ft_attr.max_fte = MAX_CHAIN_TAG;
	ft_attr.prio = ft_prio;
	ft = mlx5_create_flow_table(ns, &ft_attr);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		mlx5_core_warn(dev, "Failed to create restore table, err %d\n", err);
		goto out_free;
	}

	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_MISC_PARAMETERS_2);

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);
	misc = MLX5_ADDR_OF(fte_match_param, match_criteria, misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc, metadata_reg_c_0, MAX_CHAIN_TAG);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, ft_attr.max_fte - 1);
	g = mlx5_create_flow_group(ft, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "Failed to create restore flow group err(%d)\n", err);
		goto err_group;
	}

	MLX5_SET(copy_action_in, modact, action_type, MLX5_ACTION_TYPE_COPY);
	MLX5_SET(copy_action_in, modact, src_field, MLX5_ACTION_IN_FIELD_METADATA_REG_C_1);
	MLX5_SET(copy_action_in, modact, src_offset, 0);
	MLX5_SET(copy_action_in, modact, dst_field, MLX5_ACTION_IN_FIELD_METADATA_REG_B);
	MLX5_SET(copy_action_in, modact, dst_offset, 0);
	MLX5_SET(copy_action_in, modact, length, 0);
	err = mlx5_modify_header_alloc(dev, MLX5_FLOW_NAMESPACE_KERNEL, 1, modact, &mod_hdr_id);
	if (err) {
		mlx5_core_warn(dev, "Failed to create restore mod header err(%d)\n", err);
		goto err_mod_hdr;
	}

	offload->ft_offloads_restore = ft;
	offload->restore_group = g;
	offload->restore_copy_hdr_id = mod_hdr_id;

	kvfree(flow_group_in);

	return 0;

	//mlx5_modify_header_dealloc(esw->dev, mod_hdr_id);
err_mod_hdr:
	mlx5_destroy_flow_group(g);
err_group:
	mlx5_destroy_flow_table(ft);
out_free:
	kvfree(flow_group_in);

	return err;
}
