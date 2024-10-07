/* BGP Per Source Nexthop Group
 * Copyright (C) 2013 Cumulus Networks, Inc.
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

#include "typesafe.h"

#ifndef _BGP_PER_SRC_NHG_H
#define _BGP_PER_SRC_NHG_H

PREDECL_RBTREE_UNIQ(bgp_nhg_nexthop_cache);

struct bgp_nhg_nexthop_cache {
	// afi_t afi;
	ifindex_t ifindex;
	struct prefix prefix;
	struct nexthop nh;
	int refcnt;
	/* RB-tree entry. */
	struct bgp_nhg_nexthop_cache_item entry;
	struct bgp_nhg_nexthop_cache_head *tree;
};


extern int bgp_nhg_nexthop_cache_compare(const struct bgp_nhg_nexthop_cache *a,
					 const struct bgp_nhg_nexthop_cache *b);

DECLARE_RBTREE_UNIQ(bgp_nhg_nexthop_cache, struct bgp_nhg_nexthop_cache, entry,
		    bgp_nhg_nexthop_cache_compare);


PREDECL_DLIST(bgp_dest_soo_qlist);

PREDECL_DLIST(bgp_dest_soo_use_soo_nhgid_qlist);
/*
 * Hashtables containing nhg entries is in `bgp_vrf`.
 */
struct bgp_dest_soo_hash_entry {
	struct bgp_dest_soo_qlist_item item;
	struct bgp_dest_soo_use_soo_nhgid_qlist_item item1;
	struct bgp *bgp;
	struct bgp_per_src_nhg_hash_entry *nhe;

	struct prefix p;

	/* Time since last update */
	uint64_t uptime;

	// we need to back pointer for dest
	struct bgp_dest *dest;

	//TODO, need to store the bitmaps of NH for soo
	bitfield_t bgp_pi_bitmap;
	uint32_t refcnt;

	uint32_t flags;
#define DEST_PRESENT_IN_NHGID_USE_LIST (1 << 0)
#define DEST_SOO_DEL_PENDING (1 << 1)
};

DECLARE_DLIST(bgp_dest_soo_qlist, struct bgp_dest_soo_hash_entry, item);

DECLARE_DLIST(bgp_dest_soo_use_soo_nhgid_qlist, struct bgp_dest_soo_hash_entry,
	      item1);

/*
 * Hashtables containing nhg entries is in `bgp_vrf`.
 */
struct bgp_per_src_nhg_hash_entry {
	uint32_t nhg_id;
	struct bgp *bgp;

	/* SOO Attr */
	struct ipaddr ip;

	// we need to back pointer for dest
	struct bgp_dest *dest;

	/* Time since last update */
	uint64_t uptime;

	struct bgp_nhg_nexthop_cache_head nhg_nexthop_cache_table;

	/* hash table of dest with soo attribute */
	struct hash *dest_with_soo;

	/*linked list of dest_soo for easier walkthrough*/
	struct bgp_dest_soo_qlist_head dest_soo_list;

	struct bgp_dest_soo_use_soo_nhgid_qlist_head dest_soo_use_nhid_list;

	bitfield_t bgp_soo_route_pi_bitmap;
	bitfield_t bgp_selected_soo_route_pi_bitmap;

	uint32_t refcnt;

	bool soo_timer_running;

	uint32_t flags;

/*
 * Is this nexthop group valid, ie all nexthops are fully resolved.
 * What is fully resolved?  It's a nexthop that is either self contained
 * and correct( ie no recursive pointer ) or a nexthop that is recursively
 * resolved and correct.
 */
#define PER_SRC_NEXTHOP_GROUP_VALID (1 << 0)
/*
 * Has this nexthop group been installed?  At this point in time, this
 * means that the data-plane has been told about this nexthop group
 * and it's possible usage by a route entry.
 */
#define PER_SRC_NEXTHOP_GROUP_INSTALLED (1 << 1)
/*
 * Has the nexthop group been queued to be send to the ZEBRA?
 * The NEXTHOP_GROUP_VALID flag should also be set by this point.
 */
#define PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING (1 << 2)
/*
 * Is this a nexthop group timer on?
 */
#define PER_SRC_NEXTHOP_GROUP_TIMER_ON (1 << 3)
#define PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL (1 << 4)
#define PER_SRC_NEXTHOP_GROUP_DEL_PENDING (1 << 5)
#define PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED (1 << 6)
#define PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_DO_WECMP (1 << 7)
};

#define BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS 10
#define BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_PERIOD                                 \
	50 // in milli seconds, total timer wheel period

void bgp_dest_soo_init(struct bgp_per_src_nhg_hash_entry *nhe);
void bgp_dest_soo_finish(struct bgp_per_src_nhg_hash_entry *nhe);
void bgp_per_src_nhg_init(struct bgp *bgp);
void bgp_per_src_nhg_finish(struct bgp *bgp);
void bgp_process_route_soo_attr(struct bgp *bgp, afi_t afi,
				struct bgp_dest *dest, struct bgp_path_info *pi,
				bool is_add);
bool bgp_per_src_nhg_use_nhgid(struct bgp *bgp, struct bgp_dest *dest,
			       struct bgp_path_info *pi, uint32_t *nhg_id);
extern void bgp_per_src_nhg_soo_timer_wheel_delete(struct bgp *bgp);
extern void bgp_per_src_nhg_soo_timer_wheel_init(struct bgp *bgp);
struct bgp_per_src_nhg_hash_entry *bgp_per_src_nhg_find(struct bgp *bgp,
							struct ipaddr *ip);
void bgp_process_route_soo_attr_change(struct bgp *bgp, afi_t afi,
				struct bgp_dest *dest, struct bgp_path_info *pi,
				struct attr *new_attr);
bool bgp_check_is_soo_route(struct bgp *bgp, afi_t afi,
                                struct bgp_dest *dest, struct bgp_path_info *pi);
void bgp_process_route_transition_between_nhid(struct bgp *bgp, struct bgp_dest *dest,
                               struct bgp_path_info *pi);
void bgp_process_mpath_route_soo_attr(struct bgp *bgp, afi_t afi,
				struct bgp_dest *dest, struct bgp_path_info *new_best,
				bool is_add);
bool is_path_using_soo_nhg(const struct prefix *p, struct bgp_path_info *path,
			   uint32_t *soo_nhg, struct in_addr *soo);
#endif /* _BGP_PER_SRC_NHG_H */
