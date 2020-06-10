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

#ifndef __MLX5_EN_TC_H__
#define __MLX5_EN_TC_H__

#include <net/pkt_cls.h>

#define MLX5E_TC_FLOW_ID_MASK 0x0000ffff

#ifdef CONFIG_MLX5_ESWITCH
#include <net/ip_tunnels.h>
#include "eswitch.h"
#include "en.h"
#include "en/fs.h"

/*struct mlx5_nic_flow_attr {
	u32 action;
	u32 flow_tag;
	u32 mod_hdr_id;
	u32 hairpin_tirn;
	u8 match_level;
	struct mlx5_flow_table	*hairpin_ft;
	struct mlx5_fc		*counter;
	u32 chain;
	u16 prio;
	u32 dest_chain;
};*/

enum {
	MLX5E_TC_FLOW_FLAG_INGRESS,
	MLX5E_TC_FLOW_FLAG_EGRESS,
	MLX5E_TC_FLOW_FLAG_ESWITCH,
	MLX5E_TC_FLOW_FLAG_NIC,
	MLX5E_TC_FLOW_FLAG_OFFLOADED,
	MLX5E_TC_FLOW_FLAG_HAIRPIN,
	MLX5E_TC_FLOW_FLAG_HAIRPIN_RSS,
	MLX5E_TC_FLOW_FLAG_SLOW,
	MLX5E_TC_FLOW_FLAG_DUP,
	MLX5E_TC_FLOW_FLAG_NOT_READY,
	MLX5E_TC_FLOW_FLAG_DELETED,
	MLX5E_TC_FLOW_FLAG_CT,
};

#define MLX5_TC_FLAG(flag) BIT(MLX5E_TC_FLOW_FLAG_##flag)

#define MLX5E_TC_MAX_SPLITS 1

/* Helper struct for accessing a struct containing list_head array.
 * Containing struct
 *   |- Helper array
 *      [0] Helper item 0
 *          |- list_head item 0
 *          |- index (0)
 *      [1] Helper item 1
 *          |- list_head item 1
 *          |- index (1)
 * To access the containing struct from one of the list_head items:
 * 1. Get the helper item from the list_head item using
 *    helper item =
 *        container_of(list_head item, helper struct type, list_head field)
 * 2. Get the contining struct from the helper item and its index in the array:
 *    containing struct =
 *        container_of(helper item, containing struct type, helper field[index])
 */
struct encap_flow_item {
	struct list_head list;
	int index;
};

struct mlx5e_tc_flow {
	struct rhash_head	node;
	struct mlx5e_priv	*priv;
	u64			cookie;
	unsigned long		flags;
	struct mlx5_flow_handle *rule[MLX5E_TC_MAX_SPLITS + 1];
	/* Flow can be associated with multiple encap IDs.
	 * The number of encaps is bounded by the number of supported
	 * destinations.
	 */
	struct hlist_node ct_node;       /* Entry in hash of ct_flows */
	struct encap_flow_item encaps[MLX5_MAX_FLOW_FWD_VPORTS];
	struct mlx5e_tc_flow    *peer_flow;
	struct list_head	mod_hdr; /* flows sharing the same mod hdr ID */
	struct list_head	hairpin; /* flows sharing the same hairpin */
	struct list_head	peer;    /* flows with peer flow */
	struct list_head	unready; /* flows not ready to be offloaded (e.g due to missing route) */
	refcount_t		refcnt;
	struct rcu_head		rcu_head;
	struct list_head        tunnel;  /* flows sharing the same tunnel match */
	struct mlx5_flow_attr	attr;
};

struct mlx5e_tc_flow_parse_attr {
	const struct ip_tunnel_info *tun_info[MLX5_MAX_FLOW_FWD_VPORTS];
	struct net_device *filter_dev;
	struct mlx5_flow_spec spec;
	int num_mod_hdr_actions;
	int max_mod_hdr_actions;
	void *mod_hdr_actions;
	int mirred_ifindex[MLX5_MAX_FLOW_FWD_VPORTS];
};

#define MLX5E_TC_TABLE_NUM_GROUPS 4
#define MLX5E_TC_TABLE_MAX_GROUP_SIZE BIT(16)

static inline void __flow_flag_set(struct mlx5e_tc_flow *flow, unsigned long flag)
{
	/* Complete all memory stores before setting bit. */
	smp_mb__before_atomic();
	set_bit(flag, &flow->flags);
}

#define flow_flag_set(flow, flag) __flow_flag_set(flow, MLX5E_TC_FLOW_FLAG_##flag)

static inline bool __flow_flag_test_and_set(struct mlx5e_tc_flow *flow,
				     unsigned long flag)
{
	/* test_and_set_bit() provides all necessary barriers */
	return test_and_set_bit(flag, &flow->flags);
}

#define flow_flag_test_and_set(flow, flag)			\
	__flow_flag_test_and_set(flow, MLX5E_TC_FLOW_FLAG_##flag)

static inline void __flow_flag_clear(struct mlx5e_tc_flow *flow, unsigned long flag)
{
	/* Complete all memory stores before clearing bit. */
	smp_mb__before_atomic();
	clear_bit(flag, &flow->flags);
}

#define flow_flag_clear(flow, flag) __flow_flag_clear(flow, MLX5E_TC_FLOW_FLAG_##flag)

static inline bool __flow_flag_test(struct mlx5e_tc_flow *flow, unsigned long flag)
{
	bool ret = test_bit(flag, &flow->flags);

	/* Read fields of flow structure only after checking flags. */
	smp_mb__after_atomic();
	return ret;
}

#define flow_flag_test(flow, flag) __flow_flag_test(flow, \
						    MLX5E_TC_FLOW_FLAG_##flag)

static inline bool mlx5e_is_eswitch_flow(struct mlx5e_tc_flow *flow)
{
	return flow_flag_test(flow, ESWITCH);
}

static inline bool mlx5e_is_offloaded_flow(struct mlx5e_tc_flow *flow)
{
	return flow_flag_test(flow, OFFLOADED);
}

struct mlx5e_hairpin {
	struct mlx5_hairpin *pair;

	struct mlx5_core_dev *func_mdev;
	struct mlx5e_priv *func_priv;
	u32 tdn;
	u32 tirn;

	int num_channels;
	struct mlx5e_rqt indir_rqt;
	u32 indir_tirn[MLX5E_NUM_INDIR_TIRS];
	struct mlx5e_ttc_table ttc;
	u32 rate_limit;
	u32 max_pp_burst_size;
	u32 chain;
	u16 prio;
};

struct mlx5e_hairpin_entry {
	/* a node of a hash table which keeps all the  hairpin entries */
	struct hlist_node hairpin_hlist;

	/* flows sharing the same hairpin */
	struct list_head flows;

	u16 peer_vhca_id;
	u16 prio;
	struct mlx5e_hairpin *hp;
	struct mlx5_flow_handle *fwd_rule;
};

struct mod_hdr_key {
	int num_actions;
	void *actions;
};

struct mlx5e_mod_hdr_entry {
	/* a node of a hash table which keeps all the mod_hdr entries */
	struct hlist_node mod_hdr_hlist;

	/* flows sharing the same mod_hdr entry */
	struct list_head flows;

	struct mod_hdr_key key;

	u32 mod_hdr_id;
};

int mlx5e_tc_nic_init(struct mlx5e_priv *priv);
void mlx5e_tc_nic_cleanup(struct mlx5e_priv *priv);

int mlx5e_tc_esw_init(struct rhashtable *tc_ht);
void mlx5e_tc_esw_cleanup(struct rhashtable *tc_ht);

int mlx5e_configure_flower(struct net_device *dev, struct mlx5e_priv *priv,
			   struct flow_cls_offload *f, int flags);
int mlx5e_delete_flower(struct net_device *dev, struct mlx5e_priv *priv,
			struct flow_cls_offload *f, int flags);

int mlx5e_stats_flower(struct net_device *dev, struct mlx5e_priv *priv,
		       struct flow_cls_offload *f, int flags);

struct mlx5e_encap_entry;
void mlx5e_tc_encap_flows_add(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e);
void mlx5e_tc_encap_flows_del(struct mlx5e_priv *priv,
			      struct mlx5e_encap_entry *e);

struct mlx5e_neigh_hash_entry;
void mlx5e_tc_update_neigh_used_value(struct mlx5e_neigh_hash_entry *nhe);

int mlx5e_tc_num_filters(struct mlx5e_priv *priv, int flags);

void mlx5e_tc_reoffload_flows_work(struct work_struct *work);
struct mlx5e_tc_flow *mlx5e_tc_get_flow(struct mlx5e_priv *priv,
					int flags,
					unsigned long cookie);
extern int __rcu (*tc_skb_update_hook)(struct sk_buff *skb, u32 reg_c0,
				       u32 reg_c1);

enum match_mapping_type {
	mp_chain,
	mp_tunnel_match,
	mp_tunnel_miss,
	mp_tupleid = mp_tunnel_miss,
	mp_statezone,
	mp_mark,
	mp_labels,
	mp_user_prio,
};

struct match_mapping_params {
	/* rewrite field */
	int mfield;
	int moffset; /*offset of mfield, and soffset */
	int mlen; /* bytes to rewrite/match */

	/* spec to write, size of mlen above */
	int soffset;
};

extern struct match_mapping_params *match_mappings;

bool mlx5e_is_valid_eswitch_fwd_dev(struct mlx5e_priv *priv,
				    struct net_device *out_dev);
int get_direct_match_mapping(struct mlx5e_priv *priv,
			     struct mlx5_flow_attr *esw_attr,
			     enum match_mapping_type type,
			     u32 data,
			     u32 mask,
			     bool rewrite);

struct mlx5_flow_handle *
mlx5e_add_offloaded_nic_rule(struct mlx5e_priv *priv,
			     struct mlx5_flow_spec *spec,
			     struct mlx5_flow_attr *attr,
			     struct mlx5e_tc_flow *flow);
void mlx5e_del_offloaded_nic_rule(struct mlx5e_priv *priv,
				  struct mlx5_flow_handle *rule,
				  struct mlx5_flow_attr *attr);
int mlx5e_prio_hairpin_mode_enable(struct mlx5e_priv *priv, int num_hp);
int mlx5e_prio_hairpin_mode_disable(struct mlx5e_priv *priv);
int mlx5e_set_prio_hairpin_rate(struct mlx5e_priv *priv,
				u16 prio, int rate);

#else /* CONFIG_MLX5_ESWITCH */
static inline int  mlx5e_tc_nic_init(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_tc_nic_cleanup(struct mlx5e_priv *priv) {}
static inline int  mlx5e_tc_num_filters(struct mlx5e_priv *priv, int flags) { return 0; }
static int __rcu (*tc_skb_update_hook)(struct sk_buff *skb, u32 reg_c0,
#endif

#endif /* __MLX5_EN_TC_H__ */
