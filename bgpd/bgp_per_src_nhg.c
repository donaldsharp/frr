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

#include <zebra.h>

#include "command.h"
#include "frrevent.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "nexthop.h"
#include "vrf.h"
#include "filter.h"
#include "nexthop_group.h"
#include "lib/jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_per_src_nhg.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_PER_SRC_NHG, "BGP Per Source NHG Information");
DEFINE_MTYPE_STATIC(BGPD, BGP_DEST_SOO_HE, "BGP Dest SOO hash entry Information");

/*dest soo hash table per per source NHG*/
static void *bgp_dest_soo_alloc(void *p)
{
	struct bgp_dest_soo_hash_entry *tmp_dest_he = p;
	struct bgp_dest_soo_hash_entry *dest_he;

	dest_he = XCALLOC(MTYPE_BGP_DEST_SOO_HE,
			  sizeof(struct bgp_dest_soo_hash_entry));
	*dest_he = *tmp_dest_he;

	return ((void *)dest_he);
}

static struct bgp_dest_soo_hash_entry *
bgp_dest_soo_find(struct bgp_per_src_nhg_hash_entry *nhe, struct ipaddr *ip)
{
	struct bgp_dest_soo_hash_entry tmp;
	struct bgp_dest_soo_hash_entry *dest_he;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	dest_he = hash_lookup(nhe->dest_with_soo, &tmp);

	return dest_he;
}

static struct bgp_dest_soo_hash_entry *
bgp_dest_soo_add(struct bgp_per_src_nhg_hash_entry *nhe, struct ipaddr *ip)
{
	struct bgp_dest_soo_hash_entry tmp_he;
	struct bgp_dest_soo_hash_entry *dest_he = NULL;
	char buf[INET6_ADDRSTRLEN];

	memset(&tmp_he, 0, sizeof(tmp_he));
	memcpy(&tmp_he.ip, ip, sizeof(struct ipaddr));
	dest_he = hash_get(nhe->dest_with_soo, &tmp_he, bgp_dest_soo_alloc);
	dest_he->nhe = nhe;

	bgp_dest_soo_qlist_add_tail(&nhe->dest_soo_list, dest_he);
	bf_init(dest_he->bgp_pi_bitmap, BGP_PEER_INIT_BITMAP_SIZE);
	bf_assign_zero_index(dest_he->bgp_pi_bitmap);

	//TODO Add Processing pending

	//if (BGP_DEBUG())
	zlog_debug("bgp vrf %s per src nhg %s dest soo %s add",
		   nhe->bgp->name_pretty,
		   ipaddr2str(&nhe->ip, buf, sizeof(buf)),
		   ipaddr2str(&dest_he->ip, buf, sizeof(buf)));

	return dest_he;
}

/* Delete nexthop entry if there are no paths referencing it */
static void bgp_dest_soo_del(struct bgp_dest_soo_hash_entry *dest_he)
{
	struct bgp_per_src_nhg_hash_entry *nhe = dest_he->nhe;
	struct bgp_dest_soo_hash_entry *tmp_he;
	char buf[INET6_ADDRSTRLEN];


	//TODO Del Processing pending

	//if (BGP_DEBUG())
	zlog_debug("bgp vrf %s per src nhg %s dest soo %s del",
		   nhe->bgp->name_pretty,
		   ipaddr2str(&nhe->ip, buf, sizeof(buf)),
		   ipaddr2str(&dest_he->ip, buf, sizeof(buf)));

	bgp_dest_soo_qlist_del(&nhe->dest_soo_list, dest_he);
	tmp_he = hash_release(nhe->dest_with_soo, dest_he);
	XFREE(MTYPE_BGP_DEST_SOO_HE, tmp_he);
}

static unsigned int bgp_dest_soo_hash_keymake(const void *p)
{
	const struct bgp_dest_soo_hash_entry *dest_he = p;
	const struct ipaddr *ip = &dest_he->ip;

	if (IS_IPADDR_V4(ip))
		return jhash_1word(ip->ipaddr_v4.s_addr, 0);

	return jhash2(ip->ipaddr_v6.s6_addr32,
		      array_size(ip->ipaddr_v6.s6_addr32), 0);
}

static bool bgp_dest_soo_cmp(const void *p1, const void *p2)
{
	const struct bgp_dest_soo_hash_entry *dest_he1 = p1;
	const struct bgp_dest_soo_hash_entry *dest_he2 = p2;

	if (dest_he1 == NULL && dest_he2 == NULL)
		return true;

	if (dest_he1 == NULL || dest_he2 == NULL)
		return false;

	return (ipaddr_cmp(&dest_he1->ip, &dest_he2->ip) == 0);
}

void bgp_dest_soo_init(struct bgp_per_src_nhg_hash_entry *nhe)
{
	char buf[INET6_ADDRSTRLEN];

	//TODO, enable per src NHG debug
	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per source nhg %s dest soo hash init",
		   nhe->bgp->name_pretty,
		   ipaddr2str(&nhe->ip, buf, sizeof(buf)));
	nhe->dest_with_soo =
		hash_create(bgp_dest_soo_hash_keymake, bgp_dest_soo_cmp,
			    "BGP Dest SOO hash table");
}


static void bgp_dest_soo_free(struct bgp_dest_soo_hash_entry *dest_he)
{
	XFREE(MTYPE_BGP_DEST_SOO_HE, dest_he);
}

static void bgp_dest_soo_flush_entry(struct bgp_dest_soo_hash_entry *dest_he)
{
	struct bgp_per_src_nhg_hash_entry *nhe = dest_he->nhe;
	char buf[INET6_ADDRSTRLEN];

	bgp_dest_soo_qlist_del(&nhe->dest_soo_list, dest_he);
	//TODO, flush processing pending

	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per src nhg %s dest soo %s flush",
		   nhe->bgp->name_pretty,
		   ipaddr2str(&nhe->ip, buf, sizeof(buf)),
		   ipaddr2str(&dest_he->ip, buf, sizeof(buf)));
}

static void bgp_dest_soo_flush_cb(struct hash_bucket *bucket, void *ctxt)
{
	struct bgp_dest_soo_hash_entry *dest_he =
		(struct bgp_dest_soo_hash_entry *)bucket->data;

	bgp_dest_soo_flush_entry(dest_he);
}

void bgp_dest_soo_finish(struct bgp_per_src_nhg_hash_entry *nhe)
{
	char buf[INET6_ADDRSTRLEN];

	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per source nhg %s dest soo hash finish",
		   nhe->bgp->name_pretty,
		   ipaddr2str(&nhe->ip, buf, sizeof(buf)));
	hash_iterate(
		nhe->dest_with_soo,
		(void (*)(struct hash_bucket *, void *))bgp_dest_soo_flush_cb,
		NULL);
	hash_clean(nhe->dest_with_soo, (void (*)(void *))bgp_dest_soo_free);
}

static void *bgp_per_src_nhg_alloc(void *p)
{
	struct bgp_per_src_nhg_hash_entry *tmp_nhe = p;
	struct bgp_per_src_nhg_hash_entry *nhe;

	nhe = XCALLOC(MTYPE_BGP_PER_SRC_NHG,
		      sizeof(struct bgp_per_src_nhg_hash_entry));
	*nhe = *tmp_nhe;

	return ((void *)nhe);
}

static struct bgp_per_src_nhg_hash_entry *
bgp_per_src_nhg_find(struct bgp *bgp, struct ipaddr *ip)
{
	struct bgp_per_src_nhg_hash_entry tmp;
	struct bgp_per_src_nhg_hash_entry *nhe;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	nhe = hash_lookup(bgp->per_src_nhg_table, &tmp);

	return nhe;
}

static struct bgp_per_src_nhg_hash_entry *bgp_per_src_nhg_add(struct bgp *bgp,
							      struct ipaddr *ip)
{
	struct bgp_per_src_nhg_hash_entry tmp_nhe;
	struct bgp_per_src_nhg_hash_entry *nhe = NULL;
	char buf[INET6_ADDRSTRLEN];

	memset(&tmp_nhe, 0, sizeof(tmp_nhe));
	memcpy(&tmp_nhe.ip, ip, sizeof(struct ipaddr));
	nhe = hash_get(bgp->per_src_nhg_table, &tmp_nhe, bgp_per_src_nhg_alloc);
	nhe->bgp = bgp;

	bgp_dest_soo_init(nhe);
	bgp_dest_soo_qlist_init(&nhe->dest_soo_list);
	bf_init(nhe->bgp_soo_route_pi_bitmap, BGP_PEER_INIT_BITMAP_SIZE);
	bf_assign_zero_index(nhe->bgp_soo_route_pi_bitmap);

	//TODO Add Processing pending

	//if (BGP_DEBUG())
	zlog_debug("bgp vrf %s per src nhg %s add", bgp->name_pretty,
		   ipaddr2str(ip, buf, sizeof(buf)));

	return nhe;
}

/* Delete nexthop entry if there are no paths referencing it */
static void bgp_per_src_nhg_del(struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_per_src_nhg_hash_entry *tmp_nhe;
	char buf[INET6_ADDRSTRLEN];

	//TODO Del Processing pending

	//if (BGP_DEBUG())
	zlog_debug("bgp vrf %s per src nhg %s del", nhe->bgp->name_pretty,
		   ipaddr2str(&nhe->ip, buf, sizeof(buf)));

	bgp_dest_soo_qlist_fini(&nhe->dest_soo_list);
	bgp_dest_soo_finish(nhe);
	tmp_nhe = hash_release(nhe->bgp->per_src_nhg_table, nhe);
	XFREE(MTYPE_BGP_PER_SRC_NHG, tmp_nhe);
}

static unsigned int bgp_per_src_nhg_hash_keymake(const void *p)
{
	const struct bgp_per_src_nhg_hash_entry *nhe = p;
	const struct ipaddr *ip = &nhe->ip;

	if (IS_IPADDR_V4(ip))
		return jhash_1word(ip->ipaddr_v4.s_addr, 0);

	return jhash2(ip->ipaddr_v6.s6_addr32,
		      array_size(ip->ipaddr_v6.s6_addr32), 0);
}

static bool bgp_per_src_nhg_cmp(const void *p1, const void *p2)
{
	const struct bgp_per_src_nhg_hash_entry *nhe1 = p1;
	const struct bgp_per_src_nhg_hash_entry *nhe2 = p2;

	if (nhe1 == NULL && nhe2 == NULL)
		return true;

	if (nhe1 == NULL || nhe2 == NULL)
		return false;

	return (ipaddr_cmp(&nhe1->ip, &nhe2->ip) == 0);
}

void bgp_per_src_nhg_init(struct bgp *bgp)
{
	//TODO, enable per src NHG debug
	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per source nhg hash init", bgp->name_pretty);
	bgp->per_src_nhg_table =
		hash_create(bgp_per_src_nhg_hash_keymake, bgp_per_src_nhg_cmp,
			    "BGP Per Source NHG hash table");
}


static void bgp_per_src_nhe_free(struct bgp_per_src_nhg_hash_entry *nhe)
{
	XFREE(MTYPE_BGP_PER_SRC_NHG, nhe);
}

static void bgp_per_src_nhg_flush_entry(struct bgp_per_src_nhg_hash_entry *nhe)
{
	char buf[INET6_ADDRSTRLEN];

	bgp_dest_soo_qlist_fini(&nhe->dest_soo_list);
	bgp_dest_soo_finish(nhe);
	//TODO, flush processing pending

	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per src nhg %s flush", nhe->bgp->name_pretty,
		   ipaddr2str(&nhe->ip, buf, sizeof(buf)));
}

static void bgp_per_src_nhg_flush_cb(struct hash_bucket *bucket, void *ctxt)
{
	struct bgp_per_src_nhg_hash_entry *nhe =
		(struct bgp_per_src_nhg_hash_entry *)bucket->data;

	bgp_per_src_nhg_flush_entry(nhe);
}

void bgp_per_src_nhg_finish(struct bgp *bgp)
{
	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per src nhg finish", bgp->name_pretty);
	hash_iterate(bgp->per_src_nhg_table,
		     (void (*)(struct hash_bucket *,
			       void *))bgp_per_src_nhg_flush_cb,
		     NULL);
	hash_clean(bgp->per_src_nhg_table,
		   (void (*)(void *))bgp_per_src_nhe_free);
}

// Check if 'SoO route' pi(path info) bitmap is a subset of 'route with SoO'
static bool is_soo_rt_pi_subset_of_rt_with_soo_pi(
	struct bgp_dest_soo_hash_entry *bgp_dest_with_soo_entry)
{
	if (!bgp_dest_with_soo_entry) {
		return false;
	}

	bitfield_t rt_with_soo_pi_bitmap =
		bgp_dest_with_soo_entry->bgp_pi_bitmap;
	bitfield_t soo_rt_pi_bitmap =
		bgp_dest_with_soo_entry->nhe->bgp_soo_route_pi_bitmap;

	return bf_is_subset(&soo_rt_pi_bitmap, &rt_with_soo_pi_bitmap);
}

/* Check if SOO route path info bitmap is subset of path info bitmap of "all"
 * the routes with SOO. This function walks all the "route with SOO" and checks
 * if "SOO route" path info bitmap is a subset of each one of them
 *
 * TODO: Implement a more efficient way using 'count' array which checks if 'SoO
 * route' pi bitmap is subset of ALL 'route with SoO'
 */
static bool is_soo_rt_pi_subset_of_all_rts_with_soo_pi(
	struct bgp_per_src_nhg_hash_entry *bgp_per_src_nhg_entry)
{
	struct bgp_dest_soo_hash_entry *bgp_dest_soo_entry = NULL;
	bool is_subset_of_all_routes = true;

	// Walk all the 'routes with SoO'
	frr_each (bgp_dest_soo_qlist, &bgp_per_src_nhg_entry->dest_soo_list,
		  bgp_dest_soo_entry) {
		// Check if 'SoO route' pi bitmap a subset of 'route with SoO'
		if (!is_soo_rt_pi_subset_of_rt_with_soo_pi(
			    bgp_dest_soo_entry)) {
			is_subset_of_all_routes = false;
		}
	}

	// 'SoO route' pi bitmap is subset of ALL 'route with SoO'
	return is_subset_of_all_routes;
}
