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


PREDECL_DLIST(bgp_dest_soo_qlist);

/*
 * Hashtables containing nhg entries is in `bgp_vrf`.
 */
struct bgp_dest_soo_hash_entry {
	struct bgp_dest_soo_qlist_item item;
	struct bgp *bgp;
	struct bgp_per_src_nhg_hash_entry *nhe;

	struct prefix p;

	/* Time since last update */
	uint64_t uptime;

	//TODO, do we need to back pointer for bgp path info

	//TODO, need to store the bitmaps of NH for soo
	bitfield_t bgp_pi_bitmap;
};

DECLARE_DLIST(bgp_dest_soo_qlist, struct bgp_dest_soo_hash_entry, item);

/*
 * Hashtables containing nhg entries is in `bgp_vrf`.
 */
struct bgp_per_src_nhg_hash_entry {
	uint32_t nhg_id;
	struct bgp *bgp;

	/* SOO Attr */
	struct ipaddr ip;

	/* Time since last update */
	uint64_t uptime;

	struct nexthop_group nhg;

	/* hash table of dest with soo attribute */
	struct hash *dest_with_soo;

	/*linked list of dest_soo for easier walkthrough*/
	struct bgp_dest_soo_qlist_head dest_soo_list;

	//TODO, need to store the bitmaps of NH for soo
	bitfield_t bgp_soo_route_pi_bitmap;

	uint32_t refcnt;

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
#define PER_SRC_NEXTHOP_GROUP_QUEUED (1 << 2)
/*
 * Is this a nexthop group timer on?
 */
#define PER_SRC_NEXTHOP_GROUP_TIMER_ON (1 << 3)

	struct thread *t_select_nh_eval;
#define PER_SRC_NHG_UPDATE_TIMER 200
};


void bgp_dest_soo_init(struct bgp_per_src_nhg_hash_entry *nhe);
void bgp_dest_soo_finish(struct bgp_per_src_nhg_hash_entry *nhe);
void bgp_per_src_nhg_init(struct bgp *bgp);
void bgp_per_src_nhg_finish(struct bgp *bgp);
#endif /* _BGP_PER_SRC_NHG_H */
