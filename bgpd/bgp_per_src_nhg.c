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
#include "wheel.h"
#include "lib/jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nhg.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_per_src_nhg.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_vty.h"
#include <config.h>

extern struct zclient *zclient;

DEFINE_MTYPE_STATIC(BGPD, BGP_PER_SRC_NHG, "BGP Per Source NHG Information");
DEFINE_MTYPE_STATIC(BGPD, BGP_DEST_SOO_HE, "BGP Dest SOO hash entry Information");
DEFINE_MTYPE_STATIC(BGPD, BGP_SOO_NHG_NEXTHOP_CACHE,
		    "BGP SOO NHG nexthop cache Information");

extern int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p);
extern struct in6_addr *
bgp_path_info_to_ipv6_nexthop(struct bgp_path_info *path, ifindex_t *ifindex);

static unsigned int bgp_per_src_nhg_hash_keymake(const void *p);
static bool bgp_per_src_nhg_cmp(const void *p1, const void *p2);

static bool is_soo_rt_selected_pi_subset_of_rt_with_soo_pi(
	struct bgp_dest_soo_hash_entry *bgp_dest_with_soo_entry);

static bool is_soo_rt_selected_pi_subset_of_all_rts_with_soo_using_soo_nhg_pi(
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

void bgp_process_route_with_soo_attr(struct bgp *bgp, afi_t, safi_t safi,
				     struct bgp_dest *dest,
				     struct bgp_path_info *pi,
				     struct in_addr *ipaddr, bool is_add,
				     bool soo_attr_del);
static struct bgp_dest_soo_hash_entry *
bgp_dest_soo_find(struct bgp_per_src_nhg_hash_entry *nhe,
		  const struct prefix *p);

void bgp_process_soo_route(struct bgp *bgp, afi_t afi, safi_t safi,
			   struct bgp_dest *dest, struct bgp_path_info *pi,
			   struct in_addr *ipaddr, bool is_add,
			   bool soo_attr_del);
void bgp_per_src_nhg_nc_del(afi_t afi, struct bgp_per_src_nhg_hash_entry *nhe,
			    struct bgp_path_info *pi);

static bool is_soo_rt_installed_pi_subset_of_rt_with_soo_pi(
	struct bgp_dest_soo_hash_entry *bgp_dest_with_soo_entry);

static void bgp_per_src_nhg_add_send(struct bgp_per_src_nhg_hash_entry *nhe);
static void bgp_per_src_nhg_del_send(struct bgp_per_src_nhg_hash_entry *nhe);
static void bgp_soo_zebra_route_install(struct bgp_per_src_nhg_hash_entry *nhe,
					struct bgp_dest *dest);
static void bgp_per_src_nhg_del(struct bgp_per_src_nhg_hash_entry *nhe);
static void bgp_dest_soo_del(struct bgp_dest_soo_hash_entry *dest_he,
		struct bgp_per_src_nhg_hash_entry *nhe);

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
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"bgp vrf %s per src nhg soo %pIA %s add to timer wheel",
				bgp->name_pretty, &soo_entry->ip,
				get_afi_safi_str(soo_entry->afi,
						 soo_entry->safi, false));

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
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"bgp vrf %s per src nhg soo %pIA %s remove from timer wheel",
				bgp->name_pretty, &soo_entry->ip,
				get_afi_safi_str(soo_entry->afi,
						 soo_entry->safi, false));
		wheel_remove_item(bgp->per_src_nhg_soo_timer_wheel, soo_entry);
		soo_entry->soo_timer_running = false;
	}
}

static void
bgp_per_src_nhg_zebra_route_install(struct bgp_dest_soo_hash_entry *bgp_dest_soo_entry,
				    struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_path_info *pi;
	struct bgp_dest *dest = bgp_dest_soo_entry->dest;
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&
		    (pi->type == ZEBRA_ROUTE_BGP &&
		     pi->sub_type == BGP_ROUTE_NORMAL) &&
		    !BGP_PATH_HOLDDOWN(pi)) {
			// call the below install  code if decide to
			// change nh-id of dest
			if (is_soo_rt_installed_pi_subset_of_rt_with_soo_pi(
				    bgp_dest_soo_entry)) {
				if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
					zlog_debug(
						"bgp vrf %s per src nhg soo route %pIA %s pi is "
						"subset of route with soo %s "
						"(program it in zebra to use soo nhg %u)",
						nhe->bgp->name_pretty, &nhe->ip,
						get_afi_safi_str(nhe->afi,
								 nhe->safi,
								 false),
						bgp_dest_get_prefix_str(dest),
						nhe->nhg_id);

				bgp_zebra_route_install(dest, pi, nhe->bgp,
							true, NULL, false);
			}
		}
	}
}

// SOO timer expiry
static void bgp_per_src_nhg_timer_slot_run(void *item)
{
	struct bgp_per_src_nhg_hash_entry *nhe = item;
	struct bgp_dest_soo_hash_entry *bgp_dest_soo_entry = NULL;
	struct bgp_dest *dest;
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

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg soo %pIA %s timer slot run",
			   nhe->bgp->name_pretty, &nhe->ip,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));

	// remove the timer from the timer wheel since processing is done
	bgp_stop_soo_timer(nhe->bgp, nhe);

	if (is_soo_rt_selected_pi_subset_of_all_rts_with_soo_using_soo_nhg_pi(
		    nhe)) {
		// program the running ecmp and do NHG replace
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"bgp vrf %s per src nhg soo route %pIA %s pi is subset of all route with soo using soo nhg",
				nhe->bgp->name_pretty, &nhe->ip,
				get_afi_safi_str(nhe->afi, nhe->safi, false));
		if (nhe->refcnt) {
			if (CHECK_FLAG(nhe->flags,
				       PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING))
				bgp_per_src_nhg_add_send(nhe);
		}
	}

	dest = nhe->dest;
	// 'SOO route' dest
	if (!CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL)) {
		bgp_soo_zebra_route_install(nhe, dest);
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL);
	}

	// check for expansion case and then install the soo route with soo
	// NHGID if it satisfies

	// Walk all the 'routes with SoO' and move from zebra nhid to soo nhid
	frr_each (bgp_dest_soo_qlist, &nhe->dest_soo_list, bgp_dest_soo_entry) {
		bgp_per_src_nhg_zebra_route_install(bgp_dest_soo_entry, nhe);
	}
}

void bgp_per_src_nhg_soo_timer_wheel_init(struct bgp *bgp)
{
	if (!bgp->per_src_nhg_soo_timer_wheel_created) {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"bgp vrf %s per src nhg soo timer wheel init total "
				"period %u ms slots %u",
				bgp->name_pretty,
				bgp->per_src_nhg_convergence_timer,
				BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS);

		bgp->per_src_nhg_soo_timer_wheel = wheel_init(
			bm->master, bgp->per_src_nhg_convergence_timer,
			BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS,
			bgp_per_src_nhg_slot_key,
			bgp_per_src_nhg_timer_slot_run,
			"BGP per src NHG SoO Timer Wheel");
		bgp->per_src_nhg_soo_timer_wheel_created = true;
	}
}

void bgp_per_src_nhg_soo_timer_wheel_delete(struct bgp *bgp)
{
	if (bgp->per_src_nhg_soo_timer_wheel_created) {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"bgp vrf %s per src nhg soo timer wheel delete",
				bgp->name_pretty);

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

void bgp_process_route_transition_between_nhid(struct bgp *bgp, struct bgp_dest *dest,
                               struct bgp_path_info *pi, bool withdraw)
{
	struct in_addr in;
	struct bgp_dest_soo_hash_entry *dest_he;
	struct bgp_per_src_nhg_hash_entry *nhe;
	bool is_evpn = false;
	struct bgp_table *table = NULL;
	struct ipaddr ip;
	bool is_soo_route = false;

	memset(&ip, 0, sizeof(ip));

	table = bgp_dest_table(dest);
	if (!table)
		return;

	if (table->afi == AFI_L2VPN && table->safi == SAFI_EVPN)
		is_evpn = true;

	if (!CHECK_FLAG(bgp->per_src_nhg_flags[table->afi][table->safi],
			BGP_FLAG_NHG_PER_ORIGIN) ||
	    is_evpn) {
		return;
	}

	if (route_has_soo_attr(pi)) {
		is_soo_route = bgp_is_soo_route(dest, pi, &in);
		SET_IPADDR_V4(&ip);
		memcpy(&ip.ipaddr_v4, &in, sizeof(ip.ipaddr_v4));

		nhe = bgp_per_src_nhg_find(bgp, &ip, table->afi, table->safi);
		if (!nhe)
			return;

		if (is_soo_route) {
			if (withdraw)
				UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED);
			if (CHECK_FLAG(nhe->flags,
				 PER_SRC_NEXTHOP_GROUP_DEL_PENDING) &&
					!CHECK_FLAG(nhe->flags,
                                 PER_SRC_NEXTHOP_GROUP_VALID) &&
					!CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED) &&
				!bgp_dest_soo_use_soo_nhgid_qlist_count(&nhe->dest_soo_use_nhid_list)) {
				bgp_per_src_nhg_del_send(nhe);
				bgp_per_src_nhg_del(nhe);
			}

		} else {
			dest_he = bgp_dest_soo_find(nhe, &dest->rn->p);
			if (!dest_he) {
				if (CHECK_FLAG(
					    nhe->flags,
					    PER_SRC_NEXTHOP_GROUP_DEL_PENDING) &&
				    !CHECK_FLAG(nhe->flags,
						PER_SRC_NEXTHOP_GROUP_VALID) &&
				    !CHECK_FLAG(
					    nhe->flags,
					    PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED) &&
				    !bgp_dest_soo_use_soo_nhgid_qlist_count(
					    &nhe->dest_soo_use_nhid_list)) {
					bgp_per_src_nhg_del_send(nhe);
					bgp_per_src_nhg_del(nhe);
				}
				return;
			}

			if (CHECK_FLAG(dest_he->flags,
				DEST_SOO_DEL_PENDING)) {
				bgp_dest_soo_del(dest_he, nhe);
			}
		}
	}
}

bool bgp_per_src_nhg_use_nhgid(struct bgp *bgp, struct bgp_dest *dest,
			       struct bgp_path_info *pi, uint32_t *nhg_id)
{
	struct in_addr in;
	struct bgp_dest_soo_hash_entry *dest_he;
	struct bgp_per_src_nhg_hash_entry *nhe;
	bool is_evpn = false;
	struct bgp_table *table = NULL;
	struct ipaddr ip;
	bool is_soo_route = false;
	char buf[INET6_ADDRSTRLEN];

	memset(&ip, 0, sizeof(ip));

	table = bgp_dest_table(dest);
	if (!table)
		return false;
	if (table->afi == AFI_L2VPN && table->safi == SAFI_EVPN)
		is_evpn = true;

	if (!CHECK_FLAG(bgp->per_src_nhg_flags[table->afi][table->safi],
			BGP_FLAG_NHG_PER_ORIGIN) ||
	    is_evpn) {
		return false;
	}

	if (route_has_soo_attr(pi)) {
		is_soo_route = bgp_is_soo_route(dest, pi, &in);
		SET_IPADDR_V4(&ip);
		memcpy(&ip.ipaddr_v4, &in, sizeof(ip.ipaddr_v4));

		nhe = bgp_per_src_nhg_find(bgp, &ip, table->afi, table->safi);
		if (!nhe)
			return false;

		ipaddr2str(&nhe->ip, buf, sizeof(buf));
		if (is_soo_route) {
			if (CHECK_FLAG(nhe->flags,
                                 PER_SRC_NEXTHOP_GROUP_VALID)) {
				SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED);
				*nhg_id = nhe->nhg_id;
				if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
					zlog_debug(
						"bgp vrf %s per src nhg %s %s "
						"add to soo nhid",
						nhe->bgp->name_pretty, buf,
						get_afi_safi_str(nhe->afi,
								 nhe->safi,
								 false));
				return true;
			} else {
				UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED);
				if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
					zlog_debug(
						"bgp vrf %s per src nhg %s %s "
						"del from soo nhid",
						nhe->bgp->name_pretty, buf,
						get_afi_safi_str(nhe->afi,
								 nhe->safi,
								 false));
				return false;
			}
		} else {
			dest_he = bgp_dest_soo_find(nhe, &dest->rn->p);
			char buf[INET6_ADDRSTRLEN];
			char pfxprint[PREFIX2STR_BUFFER];
			if (!dest_he)
				return false;

			prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));
			if (!is_soo_rt_installed_pi_subset_of_rt_with_soo_pi(
				    dest_he) ||
			    (!CHECK_FLAG(nhe->flags,
					 PER_SRC_NEXTHOP_GROUP_VALID))) {
				if (CHECK_FLAG(dest_he->flags,
					 DEST_PRESENT_IN_NHGID_USE_LIST)) {
					bgp_dest_soo_use_soo_nhgid_qlist_del(&nhe->dest_soo_use_nhid_list,
								     dest_he);
					UNSET_FLAG(dest_he->flags, DEST_PRESENT_IN_NHGID_USE_LIST);
					if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
						zlog_debug(
							"bgp vrf %s per src nhg %s %s dest soo %s "
							"del from soo nhid use list",
							nhe->bgp->name_pretty,
							buf,
							get_afi_safi_str(
								nhe->afi,
								nhe->safi,
								false),
							pfxprint);
				}
				return false;
			}

			if (!CHECK_FLAG(dest_he->flags,
				DEST_PRESENT_IN_NHGID_USE_LIST)) {
				bgp_dest_soo_use_soo_nhgid_qlist_add_tail(
						&nhe->dest_soo_use_nhid_list, dest_he);
				SET_FLAG(dest_he->flags,
				DEST_PRESENT_IN_NHGID_USE_LIST);
				if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
					zlog_debug(
						"bgp vrf %s per src nhg %s dest soo %s %s"
						"add to soo nhid use list",
						nhe->bgp->name_pretty, buf,
						get_afi_safi_str(nhe->afi,
								 nhe->safi,
								 false),
						pfxprint);
				}
			}
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

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s id %d add to zebra",
			   nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false),
			   nhe->nhg_id);

	/* only the gateway ip changes for each NH. rest of the params
	 * are constant
	 */

	api_nhg.id = nhg_id;
	SET_FLAG(api_nhg.flags, ZEBRA_FLAG_ALLOW_RECURSION);
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
		api_nh->weight = bnc_iter->nh_weight;
		++api_nhg.nexthop_num;
	}

	if (!api_nhg.nexthop_num)
		return;

	zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
	SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
	assert(bf_is_inited(nhe->bgp_soo_route_selected_pi_bitmap));
	if (bf_is_inited(nhe->bgp_soo_route_installed_pi_bitmap))
		bf_free(nhe->bgp_soo_route_installed_pi_bitmap);
	nhe->bgp_soo_route_installed_pi_bitmap = bf_copy(nhe->bgp_soo_route_selected_pi_bitmap);
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
	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s id %d del to zebra",
			   nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false),
			   nhe->nhg_id);

	zclient_nhg_send(zclient, ZEBRA_NHG_DEL, &api_nhg);
	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
        assert(bf_is_inited(nhe->bgp_soo_route_selected_pi_bitmap));
        if (bf_is_inited(nhe->bgp_soo_route_installed_pi_bitmap))
                bf_free(nhe->bgp_soo_route_installed_pi_bitmap);
        nhe->bgp_soo_route_installed_pi_bitmap = bf_copy(nhe->bgp_soo_route_selected_pi_bitmap);
}

static struct bgp_nhg_nexthop_cache *
bgp_per_src_nhg_nc_add(afi_t afi, struct bgp_per_src_nhg_hash_entry *nhe,
		       struct bgp_path_info *pi)
{
	ifindex_t ifindex = 0; // for ipv6 need to be taken from peer, refer nht
	struct prefix p;
	struct bgp_nhg_nexthop_cache *bnc;
	uint32_t nh_weight;
	bool do_wt_ecmp = false;

	if (make_prefix(afi, pi, &p) < 0)
		return NULL;

	nh_weight = 0;
	/* Determine if we're doing weighted ECMP or not */
	do_wt_ecmp = bgp_path_info_mpath_chkwtd(nhe->bgp, pi);
	if (do_wt_ecmp) {
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_DO_WECMP);
	} else if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_DO_WECMP)) {
		do_wt_ecmp = true;
	}

	bnc = bnc_nhg_find(&nhe->nhg_nexthop_cache_table, &p, ifindex);
	if (!bnc) {
		// TODO, check with Donald, the number of nexthop per pi peer
		bnc = bnc_nhg_new(&nhe->nhg_nexthop_cache_table, &p, ifindex);
		if (pi->attr) {
			if (afi == AFI_IP) {
				bnc->nh.gate.ipv4 = pi->attr->nexthop;
				bnc->nh.ifindex = 0;
				bnc->nh.type = NEXTHOP_TYPE_IPV4;
			} else if (afi == AFI_IP6) {
				ifindex_t ifindex = IFINDEX_INTERNAL;
				struct in6_addr *nexthop;
				nexthop = bgp_path_info_to_ipv6_nexthop(
					pi, &ifindex);
				bnc->nh.ifindex = ifindex;
				bnc->nh.gate.ipv6 = *nexthop;
				bnc->nh.type = NEXTHOP_TYPE_IPV6;
			}
		}

		bnc->nh.vrf_id = nhe->bgp->vrf_id;
		bnc->nh.flags = NEXTHOP_FLAG_RECURSIVE;
		bnc->refcnt++;
		if (do_wt_ecmp && pi->attr) {
			bgp_zebra_use_nhop_weighted(
				    nhe->bgp, pi->attr, &nh_weight);
		}
		bnc->nh_weight = nh_weight;
		SET_FLAG(bnc->nh.flags, BGP_NEXTHOP_VALID);
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"Allocated bnc nhg %pFX(%d)(%s) peer %p refcnt:%d wei::%d attr wei:%d afi:%d ecmp:%d",
				&bnc->prefix, bnc->ifindex,
				nhe->bgp->name_pretty, pi->peer, nhe->refcnt,
				bnc->nh_weight, pi->attr->link_bw, afi, do_wt_ecmp);
	} else {
		if (do_wt_ecmp) {
			bgp_zebra_use_nhop_weighted(
				    nhe->bgp, pi->attr, &nh_weight);
			if (bnc->nh_weight != nh_weight) {
				bnc->nh_weight = nh_weight;
				SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);

			}
		}
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"Found existing bnc nhg %pFX(%d)(%s) peer %p refcnt:%d wei:%d attr wei:%d ecmp:%d",
				&bnc->prefix, bnc->ifindex,
				nhe->bgp->name_pretty, pi->peer, nhe->refcnt,bnc->nh_weight, pi->attr->link_bw, do_wt_ecmp);
	}

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug(
			"Link pi to  bnc nhg %pFX(%d)(%s) peer %p refcnt(%d)",
			&bnc->prefix, bnc->ifindex, nhe->bgp->name_pretty,
			pi->peer, bnc->refcnt);
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
	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("Unlink pi bnc nhg %pFX(%d)(%s) peer %p refcnt(%d)",
			   &bnc->prefix, bnc->ifindex, nhe->bgp->name_pretty,
			   pi->peer, bnc->refcnt);
	bnc->refcnt--;
	if (!bnc->refcnt) {
		UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_DO_WECMP);
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("Free bnc nhg %pFX(%d)(%s) peer %p",
				   &bnc->prefix, bnc->ifindex,
				   nhe->bgp->name_pretty, pi->peer);
		bnc_nhg_free(bnc);
	}
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
bgp_dest_soo_find(struct bgp_per_src_nhg_hash_entry *nhe,
		  const struct prefix *p)
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
	struct prefix *p = &dest->rn->p;

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

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s add",
			   nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false),
			   pfxprint);

	return dest_he;
}

/* Delete nexthop entry if there are no paths referencing it */
static void bgp_dest_soo_del(struct bgp_dest_soo_hash_entry *dest_he,
		struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_dest_soo_hash_entry *tmp_he;

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
		char buf[INET6_ADDRSTRLEN];
		char pfxprint[PREFIX2STR_BUFFER];
		ipaddr2str(&nhe->ip, buf, sizeof(buf));
		prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));
		zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s del",
			   nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false),
			   pfxprint);
	}
	bgp_dest_soo_qlist_del(&nhe->dest_soo_list, dest_he);

	if (CHECK_FLAG(dest_he->flags,
		 DEST_PRESENT_IN_NHGID_USE_LIST)) {
		bgp_dest_soo_use_soo_nhgid_qlist_del(&nhe->dest_soo_use_nhid_list,
					     dest_he);
		UNSET_FLAG(dest_he->flags, DEST_PRESENT_IN_NHGID_USE_LIST);
	}

	tmp_he = hash_release(nhe->dest_with_soo, dest_he);
	XFREE(MTYPE_BGP_DEST_SOO_HE, tmp_he);

	//check if nhe del pending and process
	if (CHECK_FLAG(nhe->flags,
		 PER_SRC_NEXTHOP_GROUP_DEL_PENDING) &&
			!CHECK_FLAG(nhe->flags,
		 PER_SRC_NEXTHOP_GROUP_VALID) &&
			!CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED) &&
		!bgp_dest_soo_use_soo_nhgid_qlist_count(&nhe->dest_soo_use_nhid_list)) {
		bgp_per_src_nhg_del_send(nhe);
		bgp_per_src_nhg_del(nhe);
	}

}
static void bgp_process_dest_soo_del(struct bgp_dest_soo_hash_entry *dest_he)
{
	struct bgp_per_src_nhg_hash_entry *nhe = dest_he->nhe;

	if (CHECK_FLAG(dest_he->flags,
		 DEST_PRESENT_IN_NHGID_USE_LIST)) {
		//wait for route with soo to move to zebra nhid
		SET_FLAG(dest_he->flags, DEST_SOO_DEL_PENDING);
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
			char buf[INET6_ADDRSTRLEN];
			char pfxprint[PREFIX2STR_BUFFER];
			ipaddr2str(&nhe->ip, buf, sizeof(buf));
			prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));
			zlog_debug(
				"bgp vrf %s per src nhg %s %s dest soo %s del pending",
				nhe->bgp->name_pretty, buf,
				get_afi_safi_str(nhe->afi, nhe->safi, false),
				pfxprint);
		}
	} else {
		bgp_dest_soo_del(dest_he, nhe);
	}
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

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per source nhg %s %s dest soo hash init",
			   nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));
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
	if (CHECK_FLAG(dest_he->flags,
		 DEST_PRESENT_IN_NHGID_USE_LIST)) {
		bgp_dest_soo_use_soo_nhgid_qlist_del(&nhe->dest_soo_use_nhid_list,
					     dest_he);
		UNSET_FLAG(dest_he->flags, DEST_PRESENT_IN_NHGID_USE_LIST);
	}
	// TODO: flush processing pending

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s flush",
			   nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false),
			   pfxprint);
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

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug(
			"bgp vrf %s per source nhg %s %s dest soo hash finish",
			nhe->bgp->name_pretty, buf,
			get_afi_safi_str(nhe->afi, nhe->safi, false));
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

struct bgp_per_src_nhg_hash_entry *
bgp_per_src_nhg_find(struct bgp *bgp, struct ipaddr *ip, afi_t afi, safi_t safi)
{
	struct bgp_per_src_nhg_hash_entry tmp;
	struct bgp_per_src_nhg_hash_entry *nhe;

	if (!bgp->per_src_nhg_table[afi][safi]) {
		return NULL;
	}

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	nhe = hash_lookup(bgp->per_src_nhg_table[afi][safi], &tmp);

	return nhe;
}

static struct bgp_per_src_nhg_hash_entry *
bgp_per_src_nhg_add(struct bgp *bgp, struct ipaddr *ip, afi_t afi, safi_t safi)
{
	struct bgp_per_src_nhg_hash_entry tmp_nhe;
	struct bgp_per_src_nhg_hash_entry *nhe = NULL;

	memset(&tmp_nhe, 0, sizeof(tmp_nhe));
	memcpy(&tmp_nhe.ip, ip, sizeof(struct ipaddr));

	nhe = hash_get(bgp->per_src_nhg_table[afi][safi], &tmp_nhe,
		       bgp_per_src_nhg_alloc);

	nhe->bgp = bgp;
	nhe->afi = afi;
	nhe->safi = safi;

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg soo entry create: %pIA %s",
			   bgp->name_pretty, &nhe->ip,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));

	bgp_dest_soo_init(nhe);
	bgp_dest_soo_qlist_init(&nhe->dest_soo_list);
	bgp_dest_soo_use_soo_nhgid_qlist_init(&nhe->dest_soo_use_nhid_list);

	bf_init(nhe->bgp_soo_route_selected_pi_bitmap,
		BGP_PEER_INIT_BITMAP_SIZE);
	bf_assign_zero_index(nhe->bgp_soo_route_selected_pi_bitmap);
	bf_init(nhe->bgp_soo_route_installed_pi_bitmap,
		BGP_PEER_INIT_BITMAP_SIZE);
	bf_assign_zero_index(nhe->bgp_soo_route_installed_pi_bitmap);

	// TODO, check with Donald if table needs to be per afi
	bgp_nhg_nexthop_cache_init(&nhe->nhg_nexthop_cache_table);

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
		char buf[INET6_ADDRSTRLEN];
		ipaddr2str(ip, buf, sizeof(buf));
		zlog_debug("bgp vrf %s per src nhg %s %s add", bgp->name_pretty,
			   buf, get_afi_safi_str(nhe->afi, nhe->safi, false));
	}

	return nhe;
}

static void bgp_per_src_nhg_delete(struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_dest_soo_hash_entry *bgp_dest_soo_entry = NULL;
	struct bgp_dest *dest;

	zlog_debug(
		"bgp vrf %s per src nhg soo %pIA %s timer slot run delete cnt:%ld and flags %d",
		nhe->bgp->name_pretty, &nhe->ip,
		get_afi_safi_str(nhe->afi, nhe->safi, false),
		bgp_dest_soo_use_soo_nhgid_qlist_count(
			&nhe->dest_soo_use_nhid_list),
		nhe->flags);
	// cant delete soo NHID till all routes with soo and soo route is  moved
	// to zebra nhid
	if (!bgp_dest_soo_use_soo_nhgid_qlist_count(
		    &nhe->dest_soo_use_nhid_list) &&
	    !CHECK_FLAG(nhe->flags,
			PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED)) {
		if (CHECK_FLAG(nhe->flags,
			       PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING))
			bgp_per_src_nhg_del_send(nhe);
		bgp_per_src_nhg_del(nhe);
	} else {
		UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING);
		frr_each (bgp_dest_soo_use_soo_nhgid_qlist,
			  &nhe->dest_soo_use_nhid_list, bgp_dest_soo_entry) {
			bgp_per_src_nhg_zebra_route_install(bgp_dest_soo_entry,
							    nhe);
		}
		// 'SOO route' dest
		dest = nhe->dest;
		if (dest &&
		    CHECK_FLAG(nhe->flags,
			       PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL)) {
			bgp_soo_zebra_route_install(nhe, dest);
			UNSET_FLAG(nhe->flags,
				   PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL);
		}
	}
	return;
}

static void bgp_per_src_nhg_update(struct bgp_per_src_nhg_hash_entry *nhe)
{
	/*
	bgp_soo_route_installed_pi_bitmap -> what is installed in the kernel
	(old/existing)
	bgp_soo_route_selected_pi_bitmap 		 -> what is received
	from BGP update (new)

	We can have 4 cases between bgp_soo_route_selected_pi_bitmap and
	bgp_soo_route_installed_pi_bitmap
	Case 1: bgp_soo_route_selected_pi_bitmap and
	bgp_soo_route_installed_pi_bitmap are 'DISJOINT'
	TODO: What to do?

	Case 2: bgp_soo_route_selected_pi_bitmap and
	bgp_soo_route_installed_pi_bitmap are 'OVERLAPPING'
	TODO: What to do?

	Case 3: bgp_soo_route_selected_pi_bitmap is 'SUBSET' of
	bgp_soo_route_installed_pi_bitmap
		Case a:
			ECMP Case (3).(a).(i): ECMP Shrink
				Example 1: old = NH1 NH2 NH3
							new = NH1 NH3
		Case b: W-ECMP Case
			(3).(b).(i): Same ECMP but weights increase or decrease
				Example 1: old = NH1,255/NH2,85/NH3,127
						   new = NH1,255/NH2,255/NH3,255
				Example 2: old = NH1,255/NH2,255/NH3,255
						   new = NH1,255/NH2,85/NH3,127
			case (3).(b).(ii):ECMP Shrink with weights increase or
	decrease Example 1: old = NH1,255/NH2,255/NH3,166 new = NH1,255/NH3,85
				Example 2: old = NH1,255/NH2,255/NH3,166
						new = NH1,255/NH3,255

	Case 4: bgp_soo_route_selected_pi_bitmap is 'SUPERSET' of
	bgp_soo_route_installed_pi_bitmap
	*/

	// running is subset of installed - shrink case - immediate nhg replace
	if (bf_is_subset(&nhe->bgp_soo_route_selected_pi_bitmap,
			 &nhe->bgp_soo_route_installed_pi_bitmap)) {
		// Case 3: NHG replace can be done immediately without waiting
		// for any timer
		// TODO: Call code to do NHG replace
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"bgp vrf %s per src nhg soo route upd: %pIA %s NHG replace",
				nhe->bgp->name_pretty, &nhe->ip,
				get_afi_safi_str(nhe->afi, nhe->safi, false));

		if (nhe->refcnt) {
			if (CHECK_FLAG(nhe->flags,
				       PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING))
				bgp_per_src_nhg_add_send(nhe);
		}
	}

	// installed is subset of running - expansion case - start timer
	if (bf_is_subset(&nhe->bgp_soo_route_installed_pi_bitmap,
			 &nhe->bgp_soo_route_selected_pi_bitmap)) {
		// Case 4: This is ECMP expansion case, this can be done after
		// the soo timer expiry
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug(
				"bgp vrf %s per src nhg soo route upd: %pIA %s NHG expansion "
				"(add to timer wheel if not done yet)",
				nhe->bgp->name_pretty, &nhe->ip,
				get_afi_safi_str(nhe->afi, nhe->safi, false));
		bgp_start_soo_timer(nhe->bgp, nhe);
	}
}

/* Delete nexthop entry if there are no paths referencing it */
static void bgp_per_src_nhg_del(struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_per_src_nhg_hash_entry *tmp_nhe;
	char buf[INET6_ADDRSTRLEN];
	struct bgp *bgp = nhe->bgp;
	afi_t afi = nhe->afi;
	safi_t safi = nhe->safi;

	// TODO Del Processing pending, also make sure to do NHG replace or
	// install blackhole route
	bgp_nhg_id_free(PER_SRC_NHG, nhe->nhg_id);
	bgp_stop_soo_timer(nhe->bgp, nhe);

	bgp_nhg_nexthop_cache_reset(&nhe->nhg_nexthop_cache_table);

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s del",
			   nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));

	bgp_dest_soo_qlist_fini(&nhe->dest_soo_list);
	bgp_dest_soo_use_soo_nhgid_qlist_fini(&nhe->dest_soo_use_nhid_list);
	bgp_dest_soo_finish(nhe);
	tmp_nhe = hash_release(nhe->bgp->per_src_nhg_table[afi][safi], nhe);
	XFREE(MTYPE_BGP_PER_SRC_NHG, tmp_nhe);
	if (!bgp->per_src_nhg_table[afi][safi]->count &&
	    CHECK_FLAG(bgp->per_src_nhg_flags[afi][safi],
		       BGP_FLAG_CONFIG_DEL_PENDING)) {
		UNSET_FLAG(bgp->per_src_nhg_flags[afi][safi],
			   BGP_FLAG_CONFIG_DEL_PENDING);
		UNSET_FLAG(bgp->per_src_nhg_flags[afi][safi],
			   BGP_FLAG_NHG_PER_ORIGIN);
		bgp_clear(NULL, bgp, afi, safi, clear_all, BGP_CLEAR_SOFT_IN,
			  NULL);
	}
}

static unsigned int bgp_per_src_nhg_hash_keymake(const void *p)
{
	const struct bgp_per_src_nhg_hash_entry *nhe = p;
	const struct ipaddr *ip = &nhe->ip;

	return jhash_1word(ip->ipaddr_v4.s_addr, 0);
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

void bgp_per_src_nhg_init(struct bgp *bgp, afi_t afi, safi_t safi)
{
	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per source nhg hash init",
			   bgp->name_pretty);
	bgp->per_src_nhg_table[afi][safi] =
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

	bgp_nhg_nexthop_cache_reset(&nhe->nhg_nexthop_cache_table);
	bgp_dest_soo_finish(nhe);
	bgp_dest_soo_qlist_fini(&nhe->dest_soo_list);
	bgp_dest_soo_use_soo_nhgid_qlist_fini(&nhe->dest_soo_use_nhid_list);
	//TODO, flush processing pending
	bgp_nhg_id_free(PER_SRC_NHG, nhe->nhg_id);
	bgp_stop_soo_timer(nhe->bgp, nhe);
	if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID))
		bgp_per_src_nhg_del_send(nhe);

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s flush",
			   nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));
}

static void bgp_per_src_nhg_flush_cb(struct hash_bucket *bucket, void *arg)
{
	struct bgp_dest *dest;
	struct bgp_dest_soo_hash_entry *bgp_dest_soo_entry = NULL;
	struct bgp_per_src_nhg_hash_entry *nhe =
		(struct bgp_per_src_nhg_hash_entry *)bucket->data;

	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
	SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING);
	frr_each (bgp_dest_soo_use_soo_nhgid_qlist,
		  &nhe->dest_soo_use_nhid_list, bgp_dest_soo_entry) {
		bgp_per_src_nhg_zebra_route_install(bgp_dest_soo_entry, nhe);
	}

	// 'SOO route' dest
	dest = nhe->dest;
	if (dest &&
	    CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL)) {
		bgp_soo_zebra_route_install(nhe, dest);
		UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL);
	}

	/*bgp_nhg_nexthop_cache_reset(&nhe->nhg_nexthop_cache_table);
	bgp_dest_soo_finish(nhe);
	bgp_dest_soo_qlist_fini(&nhe->dest_soo_list);
	bgp_dest_soo_use_soo_nhgid_qlist_fini(&nhe->dest_soo_use_nhid_list);
	//TODO, flush processing pending
	bgp_nhg_id_free(PER_SRC_NHG, nhe->nhg_id);
	bgp_stop_soo_timer(nhe->bgp, nhe);

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s flush",
			   nhe->bgp->name_pretty, buf);
	tmp_nhe = hash_release(nhe->bgp->per_src_nhg_table[nhe->afi][nhe->safi],
	nhe); XFREE(MTYPE_BGP_PER_SRC_NHG, tmp_nhe);*/
}

void bgp_per_src_nhg_finish(struct bgp *bgp, afi_t afi, safi_t safi)
{
	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg finish", bgp->name_pretty);
	hash_iterate(bgp->per_src_nhg_table[afi][safi],
		     (void (*)(struct hash_bucket *,
			       void *))bgp_per_src_nhg_flush_cb,
		     NULL);
}

static void bgp_per_src_nhg_stop_cb(struct hash_bucket *bucket, void *ctxt)
{
	struct bgp_per_src_nhg_hash_entry *nhe =
		(struct bgp_per_src_nhg_hash_entry *)bucket->data;

	if (nhe)
		bgp_per_src_nhg_flush_entry(nhe);
}

void bgp_per_src_nhg_stop(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg stop", bgp->name_pretty);

	FOREACH_AFI_SAFI (afi, safi) {
		if (bgp->per_src_nhg_table[afi][safi]) {
			hash_iterate(bgp->per_src_nhg_table[afi][safi],
				     (void (*)(struct hash_bucket *,
					       void *))bgp_per_src_nhg_stop_cb,
				     NULL);
			hash_clean(bgp->per_src_nhg_table[afi][safi],
				   (void (*)(void *))bgp_per_src_nhe_free);
		}
	}
}

static bool is_soo_rt_installed_pi_subset_of_rt_with_soo_pi(
	struct bgp_dest_soo_hash_entry *bgp_dest_with_soo_entry)
{
	if (!bgp_dest_with_soo_entry) {
		return false;
	}

	bitfield_t rt_with_soo_pi_bitmap =
		bgp_dest_with_soo_entry->bgp_pi_bitmap;
	bitfield_t soo_rt_installed_pi_bitmap =
		bgp_dest_with_soo_entry->nhe->bgp_soo_route_installed_pi_bitmap;

	return bf_is_subset(&soo_rt_installed_pi_bitmap,
			    &rt_with_soo_pi_bitmap);
}

// Check if 'SoO route' selected pi bitmap is a subset of 'route with SoO' pi
// bitmap
static bool is_soo_rt_selected_pi_subset_of_rt_with_soo_pi(
	struct bgp_dest_soo_hash_entry *bgp_dest_with_soo_entry)
{
	if (!bgp_dest_with_soo_entry) {
		return false;
	}

	bitfield_t rt_with_soo_pi_bitmap =
		bgp_dest_with_soo_entry->bgp_pi_bitmap;
	bitfield_t soo_rt_selected_pi_bitmap =
		bgp_dest_with_soo_entry->nhe->bgp_soo_route_selected_pi_bitmap;

	return bf_is_subset(&soo_rt_selected_pi_bitmap, &rt_with_soo_pi_bitmap);
}

/* Check if SOO route path info bitmap is subset of path info bitmap of "all"
 * the routes with SOO. This function walks all the "route with SOO" and checks
 * if "SOO route" path info bitmap is a subset of each one of them
 *
 * TODO: Implement a more efficient way using 'count' array which checks if 'SoO
 * route' pi bitmap is subset of ALL 'route with SoO'
 */
static bool is_soo_rt_selected_pi_subset_of_all_rts_with_soo_using_soo_nhg_pi(
	struct bgp_per_src_nhg_hash_entry *bgp_per_src_nhg_entry)
{
	struct bgp_dest_soo_hash_entry *bgp_dest_soo_entry = NULL;
	bool is_subset_of_all_routes = true;

	// Walk only the 'routes with SoO' that use SoO NHG, not ALL 'route with
	// SoO'
	frr_each (bgp_dest_soo_use_soo_nhgid_qlist,
		  &bgp_per_src_nhg_entry->dest_soo_use_nhid_list,
		  bgp_dest_soo_entry) {
		// Check if 'SoO route' pi bitmap a subset of 'route with SoO'
		if (!is_soo_rt_selected_pi_subset_of_rt_with_soo_pi(
			    bgp_dest_soo_entry)) {
			is_subset_of_all_routes = false;
		}
	}

	// 'SoO route' pi bitmap is subset of ALL 'route with SoO'
	return is_subset_of_all_routes;
}

static void bgp_soo_zebra_route_install(struct bgp_per_src_nhg_hash_entry *nhe,
					struct bgp_dest *dest)
{
	struct bgp_path_info *pi;
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&
		    (pi->type == ZEBRA_ROUTE_BGP &&
		     pi->sub_type == BGP_ROUTE_NORMAL)) {
			/*if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
				zlog_debug(
					"bgp vrf %s per src nhg soo route zebra
			install soo %pIA %s " "nhg %d dest %s peer %pSU idx %d",
					nhe->bgp->name_pretty, &nhe->ip,
			get_afi_safi_str(nhe->afi, nhe->safi, false),
					nhe->nhg_id,
					bgp_dest_get_prefix_str(dest),
					&pi->peer->connection->su, pi->peer->bit_index);
			}*/
			bgp_zebra_route_install(dest, pi, nhe->bgp, true, NULL,
						false);
		}
	}

	return;
}

void bgp_process_route_with_soo_attr(struct bgp *bgp, afi_t afi, safi_t safi,
				     struct bgp_dest *dest,
				     struct bgp_path_info *pi,
				     struct in_addr *ipaddr, bool is_add,
				     bool soo_attr_del)
{
	struct bgp_dest_soo_hash_entry *dest_he;
	struct bgp_per_src_nhg_hash_entry *nhe;
	struct ipaddr ip;
	char buf[INET6_ADDRSTRLEN];
	char pfxprint[PREFIX2STR_BUFFER];

	prefix2str(&dest->rn->p, pfxprint, sizeof(pfxprint));

	memset(&ip, 0, sizeof(ip));
	SET_IPADDR_V4(&ip);
	memcpy(&ip.ipaddr_v4, ipaddr, sizeof(ip.ipaddr_v4));
	ipaddr2str(&ip, buf, sizeof(buf));

	nhe = bgp_per_src_nhg_find(bgp, &ip, afi, safi);
	if (!nhe) {
		if (is_add)
			nhe = bgp_per_src_nhg_add(bgp, &ip, afi, safi);
		else {
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
				zlog_debug(
					"bgp vrf %s per src nhg not found %s %s dest soo %s del",
					bgp->name_pretty, buf,
					get_afi_safi_str(afi, safi, false),
					pfxprint);
			return;
		}
	}

	dest_he = bgp_dest_soo_find(nhe, &dest->rn->p);
	if (!dest_he) {
		if (is_add) {
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
				zlog_debug(
					"bgp vrf %s per src nhg route with soo %s %s dest %s "
					"peer %pSU idx %d add",
					bgp->name_pretty, buf,
					get_afi_safi_str(afi, safi, false),
					bgp_dest_get_prefix_str(dest),
					&pi->peer->connection->su, pi->peer->bit_index);
			}
			dest_he = bgp_dest_soo_add(nhe, dest);
		} else {
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
				zlog_debug(
					"bgp vrf %s per src nhg %s %s dest soo %s not found for del oper",
					bgp->name_pretty, buf,
					get_afi_safi_str(afi, safi, false),
					pfxprint);
			return;
		}
	} else {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
			zlog_debug(
				"bgp vrf %s per src nhg route with soo %s %s dest %s "
				"peer %pSU idx %d %s",
				bgp->name_pretty, buf,
				get_afi_safi_str(afi, safi, false),
				bgp_dest_get_prefix_str(dest), &pi->peer->connection->su,
				pi->peer->bit_index, is_add ? "upd" : "del");
		}
	}

	if (is_add) {
		if (!bf_test_index(dest_he->bgp_pi_bitmap,
				   pi->peer->bit_index)) {
			bf_set_bit(dest_he->bgp_pi_bitmap, pi->peer->bit_index);
			dest_he->refcnt++;
		}
	} else {
		if (bf_test_index(dest_he->bgp_pi_bitmap,
				  pi->peer->bit_index)) {
			bf_release_index(dest_he->bgp_pi_bitmap,
					 pi->peer->bit_index);
			dest_he->refcnt--;
			zlog_debug(
				"bgp vrf %s per src nhg route with soo %s %s dest %s "
				"peer %pSU idx %d %s refcnt:%d",
				bgp->name_pretty, buf,
				get_afi_safi_str(afi, safi, false),
				bgp_dest_get_prefix_str(dest), &pi->peer->connection->su,
				pi->peer->bit_index, is_add ? "upd" : "del",
				dest_he->refcnt);
		}

		if(soo_attr_del) {
			if (CHECK_FLAG(dest_he->flags,
				 DEST_PRESENT_IN_NHGID_USE_LIST)) {
				char buf[INET6_ADDRSTRLEN];
				char pfxprint[PREFIX2STR_BUFFER];
				ipaddr2str(&nhe->ip, buf, sizeof(buf));
				prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));
				bgp_dest_soo_use_soo_nhgid_qlist_del(&nhe->dest_soo_use_nhid_list,
							     dest_he);
				UNSET_FLAG(dest_he->flags, DEST_PRESENT_IN_NHGID_USE_LIST);
				zlog_debug(
					"bgp vrf %s per src nhg %s %s dest soo %s "
					"del from soo nhid use list",
					nhe->bgp->name_pretty, buf,
					get_afi_safi_str(afi, safi, false),
					pfxprint);
			}
		}

		if (!dest_he->refcnt)
			bgp_process_dest_soo_del(dest_he);
	}
}

void bgp_process_soo_route(struct bgp *bgp, afi_t afi, safi_t safi,
			   struct bgp_dest *dest, struct bgp_path_info *pi,
			   struct in_addr *ipaddr, bool is_add,
			   bool soo_attr_del)
{
	struct ipaddr ip;
	struct bgp_per_src_nhg_hash_entry *nhe;

	/* find-create nh */
	memset(&ip, 0, sizeof(ip));
	SET_IPADDR_V4(&ip);
	memcpy(&ip.ipaddr_v4, ipaddr, sizeof(ip.ipaddr_v4));

	nhe = bgp_per_src_nhg_find(bgp, &ip, afi, safi);
	if (!nhe) {
		if (is_add) {
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
				char buf[INET6_ADDRSTRLEN];
				ipaddr2str(&ip, buf, sizeof(buf));
				zlog_debug(
					"bgp vrf %s per src nhg soo route soo %s %s dest %s "
					"peer %pSU idx %d add",
					bgp->name_pretty, buf,
					get_afi_safi_str(afi, safi, false),
					bgp_dest_get_prefix_str(dest),
					&pi->peer->connection->su, pi->peer->bit_index);
			}
			nhe = bgp_per_src_nhg_add(bgp, &ip, afi, safi);
			nhe->dest = dest;
			// Even though NHG is allocated here, it is programed
			// in to zebra after soo timer expiry
			nhe->nhg_id = bgp_nhg_id_alloc(PER_SRC_NHG);
			bgp_start_soo_timer(bgp, nhe);
		} else
			return;
	} else {
		if (is_add) {
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
				char buf[INET6_ADDRSTRLEN];
				ipaddr2str(&ip, buf, sizeof(buf));
				zlog_debug(
					"bgp vrf %s per src nhg soo route soo %s %s dest %s "
					"peer %pSU idx %d %s",
					bgp->name_pretty, buf,
					get_afi_safi_str(afi, safi, false),
					bgp_dest_get_prefix_str(dest),
					&pi->peer->connection->su, pi->peer->bit_index,
					is_add ? "upd" : "del");
				// Even though NHG is allocated here, it is
				// programed in to zebra after soo timer expiry
				if (!nhe->nhg_id) {
					nhe->nhg_id =
						bgp_nhg_id_alloc(PER_SRC_NHG);
					bgp_start_soo_timer(bgp, nhe);
				}
			}
		}
	}

	if (is_add) {
		if (!bf_test_index(nhe->bgp_soo_route_selected_pi_bitmap,
				   pi->peer->bit_index)) {
			bf_set_bit(nhe->bgp_soo_route_selected_pi_bitmap,
				   pi->peer->bit_index);
			nhe->refcnt++;
		}
		bgp_per_src_nhg_nc_add(afi, nhe, pi);
	} else {
		if (bf_test_index(nhe->bgp_soo_route_selected_pi_bitmap,
				  pi->peer->bit_index)) {
			bf_release_index(nhe->bgp_soo_route_selected_pi_bitmap,
					 pi->peer->bit_index);
			nhe->refcnt--;
		}

		if (soo_attr_del)
			UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED);
		bgp_per_src_nhg_nc_del(afi, nhe, pi);
	}

	if (!nhe->refcnt) {
		bgp_per_src_nhg_delete(nhe);
	} else {
		bgp_per_src_nhg_update(nhe);
	}
}


bool bgp_is_soo_route(struct bgp_dest *dest, struct bgp_path_info *pi,
		      struct in_addr *ip)
{
	struct prefix to;
	struct prefix *p = &dest->rn->p;

	memset(ip, 0, sizeof(*ip));
	if (!route_get_ip_from_soo_attr(pi, ip))
		return false;

	if (p) {
		if (p->family == AF_INET) {
			inaddrv42prefix(ip, 32, &to);
			if (prefix_same(&to, p))
				return true;
		} else if (p->family == AF_INET6) {
			struct in_addr ipv4;
			if (IS_MAPPED_IPV6(&p->u.prefix6)) {
				ipv4_mapped_ipv6_to_ipv4(&p->u.prefix6, &ipv4);
				if (IPV4_ADDR_SAME(&ipv4, ip))
					return true;
			}
		}
	}

	return false;
}

void bgp_process_route_soo_attr(struct bgp *bgp, afi_t afi, safi_t safi,
				struct bgp_dest *dest, struct bgp_path_info *pi,
				bool is_add)
{
	struct in_addr ip;

	/* 	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
			zlog_debug(
				"bgp vrf %s per src nhg check if dest: %s has
	   soo attr peer:%pSU", bgp->name_pretty, bgp_dest_get_prefix_str(dest),
	   &pi->peer->su);
		} */

	if (route_has_soo_attr(pi)) {
		if (bgp_is_soo_route(dest, pi, &ip)) {
			/*processing of soo route*/
			bgp_process_soo_route(bgp, afi, safi, dest, pi, &ip,
					      is_add, false);

		} else {
			/*processing of route with soo attr*/
			bgp_process_route_with_soo_attr(bgp, afi, safi, dest,
							pi, &ip, is_add, false);
		}
	} else {
		/* 		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
					zlog_debug(
						"bgp vrf %s per src nhg dest: %s
		   does not have soo attr", bgp->name_pretty,
		   bgp_dest_get_prefix_str(dest));
				} */
	}
}

void bgp_process_route_soo_attr_change(struct bgp *bgp, afi_t afi, safi_t safi,
				       struct bgp_dest *dest,
				       struct bgp_path_info *pi,
				       struct attr *new_attr)
{
	struct in_addr ip;

	/*old select has the soo attr attached but new one doesn't*/
	if (is_soo_attr(pi->attr) && !is_soo_attr(new_attr)) {
		if (bgp_is_soo_route(dest, pi, &ip)) {
			/*processing of soo route*/
			bgp_process_soo_route(bgp, afi, safi, dest, pi, &ip,
					      false, true);

		} else {
			/*processing of route with soo attr*/
			bgp_process_route_with_soo_attr(bgp, afi, safi, dest,
							pi, &ip, false, true);
		}
	}
}

bool bgp_check_is_soo_route(struct bgp *bgp, struct bgp_dest *dest,
			    struct bgp_path_info *pi)
{
	struct in_addr ip;

	if(route_has_soo_attr(pi) && bgp_is_soo_route(dest, pi, &ip))
		return true;
	else
		return false;
}

void bgp_process_mpath_route_soo_attr(struct bgp *bgp, afi_t afi, safi_t safi,
				      struct bgp_dest *dest,
				      struct bgp_path_info *mpinfo, bool is_add)
{
	for (; mpinfo;
	     mpinfo = bgp_path_info_mpath_next(mpinfo)) {
		bgp_process_route_soo_attr(bgp, afi, safi, dest, mpinfo,
					   is_add);
	}
}

bool is_nhg_per_origin_configured(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	bool nhg_per_origin = false;
	FOREACH_AFI_SAFI (afi, safi) {
		if (CHECK_FLAG(bgp->per_src_nhg_flags[afi][safi],
			       BGP_FLAG_NHG_PER_ORIGIN)) {
			nhg_per_origin = true;
			break;
		}
	}

	return nhg_per_origin;
}

bool is_path_using_soo_nhg(const struct prefix *p, struct bgp_path_info *path,
			   uint32_t *soo_nhg, struct in_addr *soo)
{
	bool using_soo_nhg = false;
	struct bgp_dest *dest = path->net;
	struct bgp_table *table = NULL;
	afi_t afi;
	safi_t safi;

	if (!dest)
		return false;

	table = bgp_dest_table(dest);
	if (!table)
		return false;

	if (table->afi == AFI_L2VPN && table->safi == SAFI_EVPN)
		return false;

	afi = table->afi;
	safi = table->safi;

	if (is_nhg_per_origin_configured(path->peer->bgp) &&
	    route_has_soo_attr(path)) {
		struct in_addr in;
		bool is_soo_route = bgp_is_soo_route(path->net, path, &in);
		struct bgp_per_src_nhg_hash_entry *nhe = NULL;
		struct ipaddr ip;

		memset(&ip, 0, sizeof(struct ipaddr));
		SET_IPADDR_V4(&ip);
		memcpy(&ip.ipaddr_v4, &in, sizeof(ip.ipaddr_v4));
		nhe = bgp_per_src_nhg_find(path->peer->bgp, &ip, afi, safi);

		if (nhe) {
			if (is_soo_route) {
				if (bf_test_index(
					    nhe->bgp_soo_route_installed_pi_bitmap,
					    path->peer->bit_index)) {
					using_soo_nhg = true;
					*soo_nhg = nhe->nhg_id;
					memcpy(soo, &in,
					       sizeof(struct in_addr));
				}
			} else {
				struct bgp_dest_soo_hash_entry *dest_he;
				dest_he = bgp_dest_soo_find(nhe, p);
				if (dest_he && CHECK_FLAG(
					    dest_he->flags,
					    DEST_PRESENT_IN_NHGID_USE_LIST)) {
					using_soo_nhg = true;
					*soo_nhg = nhe->nhg_id;
					memcpy(soo, &in,
					       sizeof(struct in_addr));
				}
			}
		}
	}

	return using_soo_nhg;
}
