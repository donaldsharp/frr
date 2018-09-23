/* BGP routing table
 * Copyright (C) 1998, 2001 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_TABLE_H
#define _QUAGGA_BGP_TABLE_H

#include "mpls.h"
#include "table.h"
#include "queue.h"
#include "linklist.h"

struct bgp_table {
	/* table belongs to this instance */
	struct bgp *bgp;

	/* afi/safi of this table */
	afi_t afi;
	safi_t safi;

	int lock;

	struct route_table *route_table;
	uint64_t version;
};

struct bgp_dest {
	struct route_node *bn;
	struct bgp_adj_out *adj_out;

	struct bgp_adj_in *adj_in;

	struct route_node *prn;

	STAILQ_ENTRY(bgp_dest) pq;

	mpls_label_t local_label;

	uint64_t version;
	uint8_t flags;
#define BGP_NODE_PROCESS_SCHEDULED	(1 << 0)
#define BGP_NODE_USER_CLEAR             (1 << 1)
#define BGP_NODE_LABEL_CHANGED          (1 << 2)
#define BGP_NODE_REGISTERED_FOR_LABEL   (1 << 3)

	void *info;
};

/*
 * bgp_table_iter_t
 *
 * Structure that holds state for iterating over a bgp table.
 */
typedef struct bgp_table_iter_t_ {
	struct bgp_table *table;
	route_table_iter_t rt_iter;
} bgp_table_iter_t;

extern struct bgp_table *bgp_table_init(struct bgp *bgp, afi_t, safi_t);
extern void bgp_table_lock(struct bgp_table *);
extern void bgp_table_unlock(struct bgp_table *);
extern void bgp_table_finish(struct bgp_table **);

/*
 * bgp_node_table
 *
 * Returns the bgp_table that the given node is in.
 */
static inline struct bgp_table *bgp_node_table(struct route_node *node)
{
	return node->table->info;
}

/*
 * bgp_node_parent_nolock
 *
 * Gets the parent node of the given node without locking it.
 */
static inline struct route_node *bgp_node_parent_nolock(struct route_node *node)
{
	return node->parent;
}

/*
 * bgp_table_top_nolock
 *
 * Gets the top node in the table without locking it.
 *
 * @see bgp_table_top
 */
static inline struct route_node *
bgp_table_top_nolock(const struct bgp_table *const table)
{
	return table->route_table->top;
}

/*
 * bgp_table_top
 */
static inline struct route_node *
bgp_table_top(const struct bgp_table *const table)
{
	return route_top(table->route_table);
}

/*
 * bgp_node_get
 */
static inline struct route_node *bgp_node_get(struct bgp_table *const table,
					    struct prefix *p)
{
	struct route_node *rn = route_node_get(table->route_table, p);

	if (!rn->info) {
		struct bgp_dest *dest;
		dest = XCALLOC(MTYPE_TMP, sizeof(struct bgp_dest));
		dest->bn = rn;

		rn->info = dest;
	}
	return rn;
}

/*
 * bgp_node_lookup
 */
static inline struct route_node *
bgp_node_lookup(const struct bgp_table *const table, struct prefix *p)
{
	return route_node_lookup(table->route_table, p);
}

/*
 * bgp_node_match
 */
static inline struct route_node *bgp_node_match(const struct bgp_table *table,
					      struct prefix *p)
{
	return route_node_match(table->route_table, p);
}

/*
 * bgp_node_match_ipv4
 */
static inline struct route_node *
bgp_node_match_ipv4(const struct bgp_table *table, struct in_addr *addr)
{
	return route_node_match_ipv4(table->route_table, addr);
}

/*
 * bgp_node_match_ipv6
 */
static inline struct route_node *
bgp_node_match_ipv6(const struct bgp_table *table, struct in6_addr *addr)
{
	return route_node_match_ipv6(table->route_table, addr);
}

static inline unsigned long bgp_table_count(const struct bgp_table *const table)
{
	return route_table_count(table->route_table);
}

/*
 * bgp_table_get_next
 */
static inline struct route_node *bgp_table_get_next(const struct bgp_table *table,
						  struct prefix *p)
{
	return route_table_get_next(table->route_table, p);
}

/*
 * bgp_table_iter_init
 */
static inline void bgp_table_iter_init(bgp_table_iter_t *iter,
				       struct bgp_table *table)
{
	bgp_table_lock(table);
	iter->table = table;
	route_table_iter_init(&iter->rt_iter, table->route_table);
}

/*
 * bgp_table_iter_next
 */
static inline struct route_node *bgp_table_iter_next(bgp_table_iter_t *iter)
{
	return route_table_iter_next(&iter->rt_iter);
}

/*
 * bgp_table_iter_cleanup
 */
static inline void bgp_table_iter_cleanup(bgp_table_iter_t *iter)
{
	route_table_iter_cleanup(&iter->rt_iter);
	bgp_table_unlock(iter->table);
	iter->table = NULL;
}

/*
 * bgp_table_iter_pause
 */
static inline void bgp_table_iter_pause(bgp_table_iter_t *iter)
{
	route_table_iter_pause(&iter->rt_iter);
}

/*
 * bgp_table_iter_is_done
 */
static inline int bgp_table_iter_is_done(bgp_table_iter_t *iter)
{
	return route_table_iter_is_done(&iter->rt_iter);
}

/*
 * bgp_table_iter_started
 */
static inline int bgp_table_iter_started(bgp_table_iter_t *iter)
{
	return route_table_iter_started(&iter->rt_iter);
}

/* This would benefit from a real atomic operation...
 * until then. */
static inline uint64_t bgp_table_next_version(struct bgp_table *table)
{
	return ++table->version;
}

static inline uint64_t bgp_table_version(struct bgp_table *table)
{
	return table->version;
}

void bgp_table_range_lookup(const struct bgp_table *table, struct prefix *p,
			    uint8_t maxlen, struct list *matches);


static inline struct bgp_aggregate *
bgp_aggregate_get_node_info(struct route_node *node)
{
	struct bgp_dest *dest = node->info;

	return dest->info;
}

static inline void bgp_aggregate_set_node_info(struct route_node *node,
					       struct bgp_aggregate *aggregate)
{
	struct bgp_dest *dest = node->info;

	dest->info = aggregate;
}

static inline struct bgp_distance *bgp_distance_get_node(struct route_node *node)
{
	struct bgp_dest *dest = node->info;

	return dest->info;
}

static inline void bgp_distance_set_node_info(struct route_node *node,
					      struct bgp_distance *distance)
{
	struct bgp_dest *dest = node->info;

	dest->info = distance;
}

static inline struct bgp_static *bgp_static_get_node_info(struct route_node *node)
{
	struct bgp_dest *dest = node->info;

	return dest->info;
}

static inline void bgp_static_set_node_info(struct route_node *node,
					    struct bgp_static *bgp_static)
{
	struct bgp_dest *dest = node->info;

	dest->info = bgp_static;
}

static inline struct bgp_connected_ref *
bgp_connected_get_node_info(struct route_node *node)
{
	struct bgp_dest *dest = node->info;

	return dest->info;
}

static inline void bgp_connected_set_node_info(struct route_node *node,
					       struct bgp_connected_ref *bc)
{
	struct bgp_dest *dest = node->info;

	dest->info = bc;
}

static inline struct bgp_nexthop_cache *
bgp_nexthop_get_node_info(struct route_node *node)
{
	struct bgp_dest *dest = node->info;

	return dest->info;
}

static inline void bgp_nexthop_set_node_info(struct route_node *node,
					     struct bgp_nexthop_cache *bnc)
{
	struct bgp_dest *dest = node->info;

	dest->info = bnc;
}

static inline struct bgp_info *bgp_info_from_node(struct route_node *node)
{
	struct bgp_dest *dest = node->info;

	if (!dest)
		return NULL;

	return dest->info;
}

static inline void bgp_info_set_node_info(struct route_node *node,
					  struct bgp_info *bi)
{
	struct bgp_dest *dest = node->info;

	dest->info = bi;
}

static inline struct bgp_table *bgp_table_from_node(struct route_node *node)
{
	struct bgp_dest *dest = node->info;

	return dest->info;
}

static inline void bgp_table_set_node_info(struct route_node *node,
					   struct bgp_table *table)
{
	struct bgp_dest *dest = node->info;

	dest->info = table;
}

static inline struct bgp_dest *bgp_dest_from_node(struct route_node *node)
{
	return node->info;
}

static inline bool bgp_has_info_data(struct route_node *node)
{
	struct bgp_dest *dest = bgp_dest_from_node(node);

	return dest && !!dest->info;
}

static inline void **bgp_get_info_pptr(struct route_node *node)
{
	return &node->info;
}

#endif /* _QUAGGA_BGP_TABLE_H */
