#ifndef _MLX5_EN_TC_CHAINS_
#define _MLX5_EN_TC_CHAINS_

#include <linux/mlx5/device.h>
#include <linux/mlx5/fs.h>
#include "fs_core.h"

/* TC chains support in FS */

#define MAX_CHAIN_TAG 0xFFFF

#define TC_MAX_CHAIN 3
#define TC_MAX_PRIO 16
#define TC_MAX_LEVEL 2

struct mlx5_tc_chains_offload;

struct tc_chain {
	struct rhash_head node;

	u32 chain;

	int ref;

	u32 id;
	int miss_hdr_id;
	struct list_head prios_list;
	struct mlx5_flow_handle *restore_rule;
};

struct tc_prio {
	struct rhash_head node;
	struct list_head list;

	/* key in tc_prios_ht, See prio_params below. */
	u32 chain;
	u32 prio;
	u32 level;

	int ref;

	struct tc_chain *tc_chain;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_table *next_ft;
	struct mlx5_flow_group *miss_group;
	struct mlx5_flow_handle *miss_rule;
};

enum mlx5_tc_chain_offloads_flags {
	MLX5_TC_CHAINS_AND_PRIOS_SUPPORTED = BIT(0),
	MLX5_TC_IGNORE_FT_LEVEL = BIT(1),
};

typedef struct mlx5_flow_table *(*create_ft_cb)(struct mlx5_tc_chains_offload *offload,
						u32 chain, u32 prio, u32 level,
						struct mlx5_flow_table *miss_ft);
/* Database to manage TC chained tables */
struct mlx5_tc_chains_offload {
	struct mlx5_core_dev *dev;
	u32 flags;

	struct idr chain_ids;
	struct rhashtable chains_ht;
	struct rhashtable prios_ht;
	/* Protects chains */
	struct mutex chains_lock;
	struct mlx5_flow_table *miss_ft;

	/* hdr restore */
	struct mlx5_flow_table *ft_offloads_restore;
	struct mlx5_flow_group *restore_group;
	struct mlx5_flow_handle **restore_rules;
	int restore_copy_hdr_id;
	struct mlx5_flow_table *restore_dest_ft;

	/* ft creation cb */
	create_ft_cb create_next_ft;

};

#define TC_CHAIN_OFFLOAD_CHAINS_PRIOS_SUPPORT(offload) \
	(!!(offload->flags & MLX5_TC_CHAINS_AND_PRIOS_SUPPORTED))
#define TC_CHAIN_OFFLOAD_IGNORE_FLOW_LEVEL(offload) \
	(!!(offload->flags & MLX5_TC_IGNORE_FT_LEVEL))

unsigned int mlx5_tc_get_chain_range(struct mlx5_tc_chains_offload *offload);
unsigned int mlx5_tc_get_prio_range(struct mlx5_tc_chains_offload *offload);
unsigned int mlx5_tc_get_level_range(struct mlx5_tc_chains_offload *offload);

int init_tc_chains_offload(struct mlx5_core_dev *dev,
			   struct mlx5_tc_chains_offload *offload,
			   create_ft_cb ft_cb);
void destroy_tc_chains_offload(struct mlx5_tc_chains_offload *offload);

struct mlx5_flow_table *
mlx5_tc_chain_get_prio_table(struct mlx5_tc_chains_offload *offload,
			     u32 chain, u32 prio, u32 level,
			     enum mlx5_flow_namespace_type type);
void
mlx5_tc_chain_put_prio_table(struct mlx5_tc_chains_offload *offload,
			     u32 chain, u32 prio, u32 level);
void mlx5_destroy_restore_table(struct mlx5_tc_chains_offload *offload);
int mlx5_create_restore_table(struct mlx5_tc_chains_offload *offload,
			      enum mlx5_flow_namespace_type ns_type,
			      u16 ft_prio);
#endif
