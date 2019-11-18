/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2018 Mellanox Technologies. */

#include <net/pkt_cls.h>
#include <net/tc_act/tc_ct.h>

#include "eswitch.h"
#include "en_tc.h"
#include "en.h"
#include "en_rep.h"

int mlx5e_ct_init(struct mlx5e_priv *priv, struct mlx5e_ct_control **ct_control);
void mlx5e_ct_clean(struct mlx5e_ct_control **ct_control);

int mlx5e_ct_flow_offload(struct mlx5e_tc_flow *flow);
void mlx5e_ct_delete_flow(struct mlx5e_tc_flow *flow);
int mlx5e_ct_parse_match(struct mlx5e_tc_flow *flow,
			 struct flow_cls_offload *f,
			 struct netlink_ext_ack *extack);
int mlx5e_ct_parse_action(struct mlx5e_tc_flow *flow,
			  const struct flow_action_entry *act,
			  struct netlink_ext_ack *extack);

int mlx5e_configure_ct(struct net_device *dev, struct mlx5e_priv *priv,
		       struct flow_cls_offload *f, int flags);

int mlx5e_ct_restore_flow(struct mlx5e_ct_control *control,
			  struct sk_buff *skb, u32 tupleid, int *tunnel_id);

#define mp_statezone_mapping {\
	.mfield = MLX5_ACTION_IN_FIELD_METADATA_REG_C_2,\
	.moffset = 0,\
	.mlen = 4,\
	.soffset = MLX5_BYTE_OFF(fte_match_param,\
				 misc_parameters_2.metadata_reg_c_2),\
}

#define mp_mark_mapping {\
	.mfield = MLX5_ACTION_IN_FIELD_METADATA_REG_C_3,\
	.moffset = 0,\
	.mlen = 4,\
	.soffset = MLX5_BYTE_OFF(fte_match_param,\
				 misc_parameters_2.metadata_reg_c_3),\
}

#define mp_labels_mapping {\
	.mfield = MLX5_ACTION_IN_FIELD_METADATA_REG_C_4,\
	.moffset = 0,\
	.mlen = 4,\
	.soffset = MLX5_BYTE_OFF(fte_match_param,\
				 misc_parameters_2.metadata_reg_c_4),\
}

#define CT_REWRITE_ACTIONS 8
#define MAX_TUPLE_ID 0x7FFF
