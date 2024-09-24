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
#include "thread.h"
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
#include "wheel.h"
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
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_mpath.h"

extern struct zclient *zclient;

DEFINE_MTYPE_STATIC(BGPD, BGP_PER_SRC_NHG, "BGP Per Source NHG Information");
DEFINE_MTYPE_STATIC(BGPD, BGP_DEST_SOO_HE, "BGP Dest SOO hash entry Information");
DEFINE_MTYPE_STATIC(BGPD, BGP_SOO_NHG_NEXTHOP_CACHE,
		    "BGP SOO NHG nexthop cache Information");

extern int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p);
extern struct in6_addr *
bgp_path_info_to_ipv6_nexthop(struct bgp_path_info *path, ifindex_t *ifindex);
static struct bgp_per_src_nhg_hash_entry *
bgp_per_src_nhg_find(struct bgp *bgp, struct ipaddr *ip);

static unsigned int bgp_per_src_nhg_hash_keymake(const void *p);
static bool bgp_per_src_nhg_cmp(const void *p1, const void *p2);

static bool is_soo_rt_pi_subset_of_rt_with_soo_pi(
	struct bgp_dest_soo_hash_entry *bgp_dest_with_soo_entry);

static bool is_soo_rt_pi_subset_of_all_rts_with_soo_pi(
	struct bgp_per_src_nhg_hash_entry *bgp_per_src_nhg_entry);


bool bgp_is_soo_route(struct bgp_dest *dest, struct bgp_path_info *pi,
		      struct in_addr *ip);

struct bgp_nhg_nexthop_cache *
bnc_nhg_new(struct bgp_nhg_nexthop_cache_head *tree, struct prefix *prefix,
	    ifindex_t ifindex);

void bnc_nhg_nexthop_free(struct bgp_nhg_nexthop_cache *bnc);
void bnc_nhg_free(struct bgp_nhg_nexthop_cache *bnc);


struct bgp_nhg_nexthop_cache *
bnc_nhg_find(struct bgp_nhg_nexthop_cache_head *tree, struct prefix *prefix,
	     ifindex_t ifindex);

void bgp_process_route_with_soo_attr(struct bgp *bgp, struct bgp_dest *dest,
				     struct bgp_path_info *pi,
				     struct in_addr *ipaddr, bool is_add);

static struct bgp_dest_soo_hash_entry *
bgp_dest_soo_find(struct bgp_per_src_nhg_hash_entry *nhe, struct prefix *p);

/*temp code, will be deleted after timer wheel test*/
void bgp_soo_route_select_nh_eval(struct thread *thread);

void bgp_process_soo_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
			   struct bgp_path_info *pi, struct in_addr *ipaddr,
			   bool is_add);

void bgp_per_src_nhg_nc_del(afi_t afi, struct bgp_per_src_nhg_hash_entry *nhe,
			    struct bgp_path_info *pi);

static unsigned int bgp_per_src_nhg_slot_key(const void *item)
{
	const struct bgp_per_src_nhg_hash_entry *nhe = item;
	const struct ipaddr *ip = &nhe->ip;

	if (IS_IPADDR_V4(ip))
		return jhash_1word(ip->ipaddr_v4.s_addr, 0) %
				BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS;

	return jhash2(ip->ipaddr_v6.s6_addr32,
		array_size(ip->ipaddr_v6.s6_addr32), 0) %
		BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS;
}

static void bgp_start_soo_timer(struct bgp *bgp,
                         struct bgp_per_src_nhg_hash_entry *soo_entry)
{
	if (!bgp->per_src_nhg_soo_timer_wheel) {
		return;
	}

	if (!soo_entry->soo_timer_running) {
		// if soo timer is not already running, insert it in to the
		// timer wheel
		wheel_add_item(bgp->per_src_nhg_soo_timer_wheel, soo_entry);
		soo_entry->soo_timer_running = true;
	}
}

static void bgp_stop_soo_timer(struct bgp *bgp,
                        struct bgp_per_src_nhg_hash_entry *soo_entry)
{
	// if soo timer is not already running, insert it in the timer wheel
	if (!bgp->per_src_nhg_soo_timer_wheel) {
		return;
	}

	if (soo_entry->soo_timer_running) {
		wheel_remove_item(bgp->per_src_nhg_soo_timer_wheel, soo_entry);
		soo_entry->soo_timer_running = false;
	}
}

// SOO timer expiry
static void bgp_per_src_nhg_timer_slot_run(void *item)
{
	struct bgp_per_src_nhg_hash_entry *soo_entry = item;
	/* TODO
	if SOO selected NHs match installed SOO NHG AND all routes w/ SOO point
	to SOO NHG done

	# Case for moving routes from zebra NHG to SOO NHG
	if SOO selected NHs match installed SOO NHG
	-- Evaluate all routes w/ SOO and update those were the SOO NHG's NHs
	are a strict subset of route's selected NHs to SOO NHG; other routes
	remain on zebra NHG
	-- done

	# Case for expanding the SOO NHG
	If the SOO's new selected NHs are still a strict subset of all the
	routes that already point to SOO_NHG expand the SOO_NHG done
	*/

	// remove the timer from the timer wheel since processing is done
	bgp_stop_soo_timer(soo_entry->bgp, soo_entry);
}

static void bgp_per_src_nhg_soo_timer_wheel_init(struct bgp *bgp)
{
	if (!bgp->per_src_nhg_soo_timer_wheel_created) {
		bgp->per_src_nhg_soo_timer_wheel = wheel_init(
				bm->master, BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_PERIOD,
				BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS,
				bgp_per_src_nhg_slot_key,
				bgp_per_src_nhg_timer_slot_run,
				"BGP per src NHG SoO Timer Wheel");
		bgp->per_src_nhg_soo_timer_wheel_created = true;
	}
}

static void bgp_per_src_nhg_soo_timer_wheel_delete(struct bgp *bgp)
{
	if (bgp->per_src_nhg_soo_timer_wheel_created) {
		wheel_delete(bgp->per_src_nhg_soo_timer_wheel);
		bgp->per_src_nhg_soo_timer_wheel_created = false;
	}
}


int bgp_nhg_nexthop_cache_compare(const struct bgp_nhg_nexthop_cache *a,
				  const struct bgp_nhg_nexthop_cache *b)
{
	if (a->ifindex < b->ifindex)
		return -1;
	if (a->ifindex > b->ifindex)
		return 1;

	return prefix_cmp(&a->prefix, &b->prefix);
}

void bnc_nhg_nexthop_free(struct bgp_nhg_nexthop_cache *bnc)
{
	// TODO processing
	// nexthops_free(bnc->nexthop);
}

struct bgp_nhg_nexthop_cache *
bnc_nhg_new(struct bgp_nhg_nexthop_cache_head *tree, struct prefix *prefix,
	    ifindex_t ifindex)
{
	struct bgp_nhg_nexthop_cache *bnc;

	bnc = XCALLOC(MTYPE_BGP_SOO_NHG_NEXTHOP_CACHE,
		      sizeof(struct bgp_nhg_nexthop_cache));
	bnc->prefix = *prefix;
	bnc->ifindex = ifindex;
	bnc->tree = tree;
	bgp_nhg_nexthop_cache_add(tree, bnc);

	return bnc;
}

void bnc_nhg_free(struct bgp_nhg_nexthop_cache *bnc)
{
	bnc_nhg_nexthop_free(bnc);
	bgp_nhg_nexthop_cache_del(bnc->tree, bnc);
	XFREE(MTYPE_BGP_SOO_NHG_NEXTHOP_CACHE, bnc);
}

/* Reset and free BGP nhg nexthop cache. */
static void bgp_nhg_nexthop_cache_reset(struct bgp_nhg_nexthop_cache_head *tree)
{
	struct bgp_nhg_nexthop_cache *bnc;

	while (bgp_nhg_nexthop_cache_count(tree) > 0) {
		bnc = bgp_nhg_nexthop_cache_first(tree);

		bnc_nhg_free(bnc);
	}
}

struct bgp_nhg_nexthop_cache *
bnc_nhg_find(struct bgp_nhg_nexthop_cache_head *tree, struct prefix *prefix,
	     ifindex_t ifindex)
{
	struct bgp_nhg_nexthop_cache bnc = {};

	if (!tree)
		return NULL;

	bnc.prefix = *prefix;
	bnc.ifindex = ifindex;
	return bgp_nhg_nexthop_cache_find(tree, &bnc);
}


bool bgp_per_src_nhg_use_nhgid(struct bgp *bgp, struct bgp_dest *dest,
			       struct bgp_path_info *pi, uint32_t *nhg_id)
{
	struct in_addr in;
	struct bgp_dest_soo_hash_entry *dest_he;
	struct bgp_per_src_nhg_hash_entry *nhe;
	bool is_evpn = false;
	struct bgp_table *table = NULL;

	table = bgp_dest_table(dest);
	if (table && table->afi == AFI_L2VPN && table->safi == SAFI_EVPN)
		is_evpn = true;


	if (!CHECK_FLAG(bgp->per_src_nhg_flags[table->afi][table->safi],
			BGP_FLAG_NHG_PER_ORIGIN) ||
	    is_evpn) {
		return false;
	}

	if (route_has_soo_attr(pi)) {
		if (bgp_is_soo_route(dest, pi, &in)) {
			struct ipaddr ip;

			memset(&ip, 0, sizeof(ip));
			SET_IPADDR_V4(&ip);
			memcpy(&ip.ipaddr_v4, &in, sizeof(ip.ipaddr_v4));


			nhe = bgp_per_src_nhg_find(bgp, &ip);
			if ((!nhe) ||
			    (!CHECK_FLAG(nhe->flags,
					 PER_SRC_NEXTHOP_GROUP_VALID)))
				return false;

			dest_he = bgp_dest_soo_find(nhe, &dest->p);
			if (!dest_he)
				return false;

			if (!is_soo_rt_pi_subset_of_rt_with_soo_pi(dest_he))
				return false;

			*nhg_id = nhe->nhg_id;
			return true;
		}
	}

	return false;
}

static void bgp_per_src_nhg_add_send(struct bgp_per_src_nhg_hash_entry *nhe)
{
	uint32_t nhg_id = nhe->nhg_id;
	struct zapi_nexthop *api_nh;
	struct zapi_nhg api_nhg = {};
	struct bgp_nhg_nexthop_cache_head *tree;
	struct bgp_nhg_nexthop_cache *bnc_iter;
	char buf[INET6_ADDRSTRLEN];

	/* Skip installation of L3-NHG if host routes used */
	if (!nhg_id)
		return;

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	// if(debug)
	zlog_debug("bgp vrf %s per src nhg %s id %d add to zebra",
		   nhe->bgp->name_pretty, buf, nhe->nhg_id);

	/* only the gateway ip changes for each NH. rest of the params
	 * are constant
	 */

	api_nhg.id = nhg_id;
	tree = &nhe->nhg_nexthop_cache_table;

	frr_each (bgp_nhg_nexthop_cache, tree, bnc_iter) {
		if (!CHECK_FLAG(bnc_iter->nh.flags, BGP_NEXTHOP_VALID))
			continue;

		/* Don't overrun the zapi buffer. */
		if (api_nhg.nexthop_num == MULTIPATH_NUM)
			break;

		/* convert to zapi format */
		api_nh = &api_nhg.nexthops[api_nhg.nexthop_num];
		zapi_nexthop_from_nexthop(api_nh, &bnc_iter->nh);

		++api_nhg.nexthop_num;
	}

	if (!api_nhg.nexthop_num)
		return;

	zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
	SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
}

static void bgp_per_src_nhg_del_send(struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct zapi_nhg api_nhg = {};

	api_nhg.id = nhe->nhg_id;
	char buf[INET6_ADDRSTRLEN];

	/* Skip installation of L3-NHG if host routes used */
	if (!api_nhg.id)
		return;

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	// if ()
	zlog_debug("bgp vrf %s per src nhg %s id %d del to zebra",
		   nhe->bgp->name_pretty, buf, nhe->nhg_id);

	zclient_nhg_send(zclient, ZEBRA_NHG_DEL, &api_nhg);
	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
}

static struct bgp_nhg_nexthop_cache *
bgp_per_src_nhg_nc_add(afi_t afi, struct bgp_per_src_nhg_hash_entry *nhe,
		       struct bgp_path_info *pi)
{
	ifindex_t ifindex = 0; // for ipv6 need to be taken from peer, refer nht
	struct prefix p;
	struct bgp_nhg_nexthop_cache *bnc;
	uint32_t nh_weight;
	bool do_wt_ecmp;

	if (make_prefix(afi, pi, &p) < 0)
		return NULL;

	nh_weight = 0;
	/* Determine if we're doing weighted ECMP or not */
	do_wt_ecmp = bgp_path_info_mpath_chkwtd(nhe->bgp, pi);
	if (do_wt_ecmp) {
		/*bgp_zebra_use_nhop_weighted(
			    bgp, mpinfo->attr->link_bw, &nh_weight);*/
		nh_weight = pi->attr->link_bw;
	}

	bnc = bnc_nhg_find(&nhe->nhg_nexthop_cache_table, &p, ifindex);
	if (!bnc) {
		// TODO, check with Donald, the number of nexthop per pi peer
		bnc = bnc_nhg_new(&nhe->nhg_nexthop_cache_table, &p, ifindex);
		if (pi->attr) {
			if (afi == AF_INET) {
				bnc->nh.gate.ipv4 = pi->attr->nexthop;
				bnc->nh.ifindex = pi->attr->nh_ifindex;
				bnc->nh.type = NEXTHOP_TYPE_IPV4_IFINDEX;
			} else if (afi == AF_INET6) {
				ifindex_t ifindex = IFINDEX_INTERNAL;
				struct in6_addr *nexthop;
				nexthop = bgp_path_info_to_ipv6_nexthop(
					pi, &ifindex);
				bnc->nh.ifindex = ifindex;
				bnc->nh.gate.ipv6 = *nexthop;
				bnc->nh.type = NEXTHOP_TYPE_IPV6_IFINDEX;
			}
		}

		bnc->nh.vrf_id = nhe->bgp->vrf_id;
		bnc->nh.flags = NEXTHOP_FLAG_ONLINK;
		bnc->nh.weight = nh_weight;
		SET_FLAG(bnc->nh.flags, BGP_NEXTHOP_VALID);
	}

	bnc->refcnt++;
	return bnc;
}

void bgp_per_src_nhg_nc_del(afi_t afi, struct bgp_per_src_nhg_hash_entry *nhe,
			    struct bgp_path_info *pi)
{
	ifindex_t ifindex = 0; // for ipv6 need to be taken from peer, refer nht
	struct prefix p;
	struct bgp_nhg_nexthop_cache *bnc;

	if (make_prefix(afi, pi, &p) < 0)
		return;


	bnc = bnc_nhg_find(&nhe->nhg_nexthop_cache_table, &p, ifindex);
	if (!bnc)
		return;

	bnc->refcnt--;
	if (!bnc->refcnt)
		bnc_nhg_free(bnc);
}


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
bgp_dest_soo_find(struct bgp_per_src_nhg_hash_entry *nhe, struct prefix *p)
{
	struct bgp_dest_soo_hash_entry tmp;
	struct bgp_dest_soo_hash_entry *dest_he;

	memset(&tmp, 0, sizeof(tmp));
	prefix_copy(&tmp.p, p);
	dest_he = hash_lookup(nhe->dest_with_soo, &tmp);

	return dest_he;
}

static struct bgp_dest_soo_hash_entry *
bgp_dest_soo_add(struct bgp_per_src_nhg_hash_entry *nhe, struct bgp_dest *dest)
{
	struct bgp_dest_soo_hash_entry tmp_he;
	struct bgp_dest_soo_hash_entry *dest_he = NULL;
	char buf[INET6_ADDRSTRLEN];
	char pfxprint[PREFIX2STR_BUFFER];
	struct prefix *p = &dest->p;

	prefix2str(p, pfxprint, sizeof(pfxprint));

	memset(&tmp_he, 0, sizeof(tmp_he));
	prefix_copy(&tmp_he.p, p);
	dest_he = hash_get(nhe->dest_with_soo, &tmp_he, bgp_dest_soo_alloc);
	dest_he->nhe = nhe;
	dest_he->dest = dest;

	bgp_dest_soo_qlist_add_tail(&nhe->dest_soo_list, dest_he);
	bf_init(dest_he->bgp_pi_bitmap, BGP_PEER_INIT_BITMAP_SIZE);
	bf_assign_zero_index(dest_he->bgp_pi_bitmap);

	// TODO Add Processing pending

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	//if (BGP_DEBUG())
	zlog_debug("bgp vrf %s per src nhg %s dest soo %s add",
		   nhe->bgp->name_pretty, buf, pfxprint);

	return dest_he;
}

/* Delete nexthop entry if there are no paths referencing it */
static void bgp_dest_soo_del(struct bgp_dest_soo_hash_entry *dest_he)
{
	struct bgp_per_src_nhg_hash_entry *nhe = dest_he->nhe;
	struct bgp_dest_soo_hash_entry *tmp_he;
	char buf[INET6_ADDRSTRLEN];
	char pfxprint[PREFIX2STR_BUFFER];

	prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));


	// TODO: Del Processing pending

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	//if (BGP_DEBUG())
	zlog_debug("bgp vrf %s per src nhg %s dest soo %s del",
		   nhe->bgp->name_pretty, buf, pfxprint);

	bgp_dest_soo_qlist_del(&nhe->dest_soo_list, dest_he);
	tmp_he = hash_release(nhe->dest_with_soo, dest_he);
	XFREE(MTYPE_BGP_DEST_SOO_HE, tmp_he);
}

static uint32_t bgp_dest_soo_hash_keymake(const void *p)
{
	const struct bgp_dest_soo_hash_entry *dest_he = p;
	return prefix_hash_key((void *)&dest_he->p);
}

static bool bgp_dest_soo_cmp(const void *p1, const void *p2)
{
	const struct bgp_dest_soo_hash_entry *dest_he1 = p1;
	const struct bgp_dest_soo_hash_entry *dest_he2 = p2;

	if (dest_he1 == NULL && dest_he2 == NULL)
		return true;

	if (dest_he1 == NULL || dest_he2 == NULL)
		return false;

	// TODO: check with Donald, host part ignored
	return (prefix_cmp(&dest_he1->p, &dest_he2->p) == 0);
}

void bgp_dest_soo_init(struct bgp_per_src_nhg_hash_entry *nhe)
{
	char buf[INET6_ADDRSTRLEN];

	// TODO: enable per src NHG debug
	// if (BGP_DEBUG(,))
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
	char pfxprint[PREFIX2STR_BUFFER];

	prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));

	bgp_dest_soo_qlist_del(&nhe->dest_soo_list, dest_he);
	// TODO: flush processing pending

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per src nhg %s dest soo %s flush",
		   nhe->bgp->name_pretty, buf, pfxprint);
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

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per source nhg %s dest soo hash finish",
		   nhe->bgp->name_pretty, buf);
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
	nhe->nhg_id = bgp_l3nhg_id_alloc(PER_SRC_NHG);
	bgp_start_soo_timer(bgp, nhe);

	// TODO, check with Donald if table needs to be per afi
	bgp_nhg_nexthop_cache_init(&nhe->nhg_nexthop_cache_table);

	ipaddr2str(ip, buf, sizeof(buf));
	//if (BGP_DEBUG())
	zlog_debug("bgp vrf %s per src nhg %s add", bgp->name_pretty, buf);

	return nhe;
}

static void bgp_per_src_nhg_update(struct bgp_per_src_nhg_hash_entry *nhe)
{
	bgp_start_soo_timer(nhe->bgp, nhe);
}

/* Delete nexthop entry if there are no paths referencing it */
static void bgp_per_src_nhg_del(struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_per_src_nhg_hash_entry *tmp_nhe;
	char buf[INET6_ADDRSTRLEN];

	// TODO Del Processing pending, also make sure to do NHG replace or
	// install blackhole route
	bgp_l3nhg_id_free(PER_SRC_NHG, nhe->nhg_id);
	bgp_stop_soo_timer(nhe->bgp, nhe);

	bgp_nhg_nexthop_cache_reset(&nhe->nhg_nexthop_cache_table);

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	//if (BGP_DEBUG())
	zlog_debug("bgp vrf %s per src nhg %s del", nhe->bgp->name_pretty, buf);

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
	// TODO, enable per src NHG debug
	// if (BGP_DEBUG(,))
	// zlog_debug("bgp vrf %s per source nhg hash init", bgp->name_pretty);
	bgp->per_src_nhg_table =
		hash_create(bgp_per_src_nhg_hash_keymake, bgp_per_src_nhg_cmp,
			    "BGP Per Source NHG hash table");
	bgp_per_src_nhg_soo_timer_wheel_init(bgp);
}


static void bgp_per_src_nhe_free(struct bgp_per_src_nhg_hash_entry *nhe)
{
	XFREE(MTYPE_BGP_PER_SRC_NHG, nhe);
}

static void bgp_per_src_nhg_flush_entry(struct bgp_per_src_nhg_hash_entry *nhe)
{
	char buf[INET6_ADDRSTRLEN];

	bgp_nhg_nexthop_cache_reset(&nhe->nhg_nexthop_cache_table);
	bgp_dest_soo_qlist_fini(&nhe->dest_soo_list);
	bgp_dest_soo_finish(nhe);
	//TODO, flush processing pending
	bgp_l3nhg_id_free(PER_SRC_NHG, nhe->nhg_id);
	bgp_stop_soo_timer(nhe->bgp, nhe);

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	//if (BGP_DEBUG(,))
	zlog_debug("bgp vrf %s per src nhg %s flush", nhe->bgp->name_pretty,
		   buf);
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
	/*zlog_debug("bgp vrf %s per src nhg finish", bgp->name_pretty);
	hash_iterate(bgp->per_src_nhg_table,
		     (void (*)(struct hash_bucket *,
			       void *))bgp_per_src_nhg_flush_cb,
		     NULL);
	hash_clean(bgp->per_src_nhg_table,
		   (void (*)(void *))bgp_per_src_nhe_free);*/
	bgp_per_src_nhg_soo_timer_wheel_delete(bgp);
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

/*temp code, will be deleted after timer wheel test*/
void bgp_soo_route_select_nh_eval(struct thread *thread)
{
	struct bgp_per_src_nhg_hash_entry *nhe;

	nhe = THREAD_ARG(thread);

	THREAD_OFF(nhe->t_select_nh_eval);
	if (nhe->refcnt) {
		bgp_per_src_nhg_add_send(nhe);
	}
	// TODO: Re-enable this again
	/*else {
		bgp_per_src_nhg_del_send(nhe);
		bgp_per_src_nhg_del(nhe);
	}*/
}


void bgp_process_route_with_soo_attr(struct bgp *bgp, struct bgp_dest *dest,
				     struct bgp_path_info *pi,
				     struct in_addr *ipaddr, bool is_add)
{
	struct bgp_dest_soo_hash_entry *dest_he;
	struct bgp_per_src_nhg_hash_entry *nhe;
	struct ipaddr ip;

	memset(&ip, 0, sizeof(ip));
	SET_IPADDR_V4(&ip);
	memcpy(&ip.ipaddr_v4, ipaddr, sizeof(ip.ipaddr_v4));


	nhe = bgp_per_src_nhg_find(bgp, &ip);
	if (!nhe) {
		// TODO, check with Donald, handling in absence of nhe
		return;
	}

	dest_he = bgp_dest_soo_find(nhe, &dest->p);
	if (!dest_he) {
		if (is_add)
			dest_he = bgp_dest_soo_add(nhe, dest);
		else
			return;
	}

	if (is_add) {
		if (!bf_test_index(dest_he->bgp_pi_bitmap,
				   pi->peer->bit_index)) {
			bf_set_bit(dest_he->bgp_pi_bitmap, pi->peer->bit_index);
		}
	} else {
		if (bf_test_index(dest_he->bgp_pi_bitmap,
				  pi->peer->bit_index)) {
			bf_release_index(dest_he->bgp_pi_bitmap,
					 pi->peer->bit_index);
		}
		bgp_dest_soo_del(dest_he);
	}
}

void bgp_process_soo_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
			   struct bgp_path_info *pi, struct in_addr *ipaddr,
			   bool is_add)
{
	struct ipaddr ip;
	struct bgp_per_src_nhg_hash_entry *nhe;

	/* find-create nh */
	memset(&ip, 0, sizeof(ip));
	SET_IPADDR_V4(&ip);
	memcpy(&ip.ipaddr_v4, ipaddr, sizeof(ip.ipaddr_v4));

	nhe = bgp_per_src_nhg_find(bgp, &ip);
	if (!nhe) {
		if (is_add)
			nhe = bgp_per_src_nhg_add(bgp, &ip);
		else
			return;
	} else {
		bgp_per_src_nhg_update(nhe);
	}

	if (is_add) {
		if (!bf_test_index(nhe->bgp_soo_route_pi_bitmap,
				   pi->peer->bit_index)) {
			bf_set_bit(nhe->bgp_soo_route_pi_bitmap,
				   pi->peer->bit_index);
			nhe->refcnt++;
		}
		bgp_per_src_nhg_nc_add(afi, nhe, pi);
	} else {
		if (bf_test_index(nhe->bgp_soo_route_pi_bitmap,
				  pi->peer->bit_index)) {
			bf_release_index(nhe->bgp_soo_route_pi_bitmap,
					 pi->peer->bit_index);
			nhe->refcnt--;
		}
		bgp_per_src_nhg_nc_del(afi, nhe, pi);
	}

	/*temp code, will be deleted after timer wheel test*/
	if (!nhe->t_select_nh_eval) {
		thread_add_timer_msec(bm->master, bgp_soo_route_select_nh_eval,
				      nhe, PER_SRC_NHG_UPDATE_TIMER,
				      &nhe->t_select_nh_eval);
	}
}


bool bgp_is_soo_route(struct bgp_dest *dest, struct bgp_path_info *pi,
		      struct in_addr *ip)
{
	struct prefix to;

	memset(ip, 0, sizeof(*ip));
	if (!route_get_ip_from_soo_attr(pi, ip))
		return false;

	inaddrv42prefix(ip, 32, &to);

	if (prefix_same(&to, &dest->p))
		return true;

	return false;
}

void bgp_process_route_soo_attr(struct bgp *bgp, afi_t afi,
				struct bgp_dest *dest, struct bgp_path_info *pi,
				bool is_add)
{
	struct in_addr ip;

	if (route_has_soo_attr(pi)) {
		if (bgp_is_soo_route(dest, pi, &ip)) {
			/*processing of soo route*/
			bgp_process_soo_route(bgp, afi, dest, pi, &ip, is_add);

		} else {
			/*processing of route with soo attr*/
			bgp_process_route_with_soo_attr(bgp, dest, pi, &ip,
							is_add);
		}
	}
}
