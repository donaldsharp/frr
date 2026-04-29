// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound Helper Functions
 * Copyright (C) 2024 FRRouting
 *
 * Helper functions to reduce code duplication in bgp_nb_config.c
 */

#include <zebra.h>

#include "northbound.h"
#include "log.h"
#include "filter.h"
#include "routemap.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_nb_helpers.h"

/*
 * Route-map helpers
 */
int bgp_nb_peer_rmap_modify(struct nb_cb_modify_args *args,
			    const char *peer_xpath, afi_t afi, safi_t safi,
			    int direct)
{
	struct peer *peer;
	const char *rmap_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		rmap_name = yang_dnode_get_string(args->dnode, NULL);
		peer_route_map_set(peer, afi, safi, direct, rmap_name,
				   route_map_lookup_by_name(rmap_name));
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_rmap_destroy(struct nb_cb_destroy_args *args,
			     const char *peer_xpath, afi_t afi, safi_t safi,
			     int direct)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_route_map_unset(peer, afi, safi, direct);
		break;
	}

	return NB_OK;
}

/*
 * Prefix-list helpers
 */
int bgp_nb_peer_plist_modify(struct nb_cb_modify_args *args,
			     const char *peer_xpath, afi_t afi, safi_t safi,
			     int direct)
{
	struct peer *peer;
	const char *plist_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		plist_name = yang_dnode_get_string(args->dnode, NULL);
		peer_prefix_list_set(peer, afi, safi, direct, plist_name);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_plist_destroy(struct nb_cb_destroy_args *args,
			      const char *peer_xpath, afi_t afi, safi_t safi,
			      int direct)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_prefix_list_unset(peer, afi, safi, direct);
		break;
	}

	return NB_OK;
}

/*
 * Access-list (distribute-list) helpers
 */
int bgp_nb_peer_distribute_modify(struct nb_cb_modify_args *args,
				  const char *peer_xpath, afi_t afi,
				  safi_t safi, int direct)
{
	struct peer *peer;
	const char *acl_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		acl_name = yang_dnode_get_string(args->dnode, NULL);
		peer_distribute_set(peer, afi, safi, direct, acl_name);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_distribute_destroy(struct nb_cb_destroy_args *args,
				   const char *peer_xpath, afi_t afi,
				   safi_t safi, int direct)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_distribute_unset(peer, afi, safi, direct);
		break;
	}

	return NB_OK;
}

/*
 * AS-path filter list helpers
 */
int bgp_nb_peer_aslist_modify(struct nb_cb_modify_args *args,
			      const char *peer_xpath, afi_t afi, safi_t safi,
			      int direct)
{
	struct peer *peer;
	const char *aslist_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		aslist_name = yang_dnode_get_string(args->dnode, NULL);
		peer_aslist_set(peer, afi, safi, direct, aslist_name);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_aslist_destroy(struct nb_cb_destroy_args *args,
			       const char *peer_xpath, afi_t afi, safi_t safi,
			       int direct)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_aslist_unset(peer, afi, safi, direct);
		break;
	}

	return NB_OK;
}

/*
 * Unsuppress-map helpers
 */
int bgp_nb_peer_unsuppress_map_modify(struct nb_cb_modify_args *args,
				      const char *peer_xpath, afi_t afi,
				      safi_t safi)
{
	struct peer *peer;
	const char *map_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		map_name = yang_dnode_get_string(args->dnode, NULL);
		peer_unsuppress_map_set(peer, afi, safi, map_name,
					route_map_lookup_by_name(map_name));
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_unsuppress_map_destroy(struct nb_cb_destroy_args *args,
				       const char *peer_xpath, afi_t afi,
				       safi_t safi)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_unsuppress_map_unset(peer, afi, safi);
		break;
	}

	return NB_OK;
}

/*
 * Address-family flag helper
 */
/*
 * Apply a peer AF flag (set or unset) one bit at a time.
 *
 * peer_af_flag_modify() compares `flag` against a single PEER_FLAG_* constant
 * to decide whether a dynamic-capability ORF change can avoid a session
 * reset (see the `flag == PEER_FLAG_ORF_PREFIX_SM` / `PEER_FLAG_ORF_PREFIX_RM`
 * checks in bgpd.c). Passing the OR of both bits at once defeats that check
 * and forces an unnecessary reset. Split the call so each bit is handled
 * independently, matching the baseline DEFUN for `capability orf ... both`.
 */
static void bgp_nb_peer_af_flag_apply(struct peer *peer, afi_t afi, safi_t safi,
				      uint64_t flag, bool set)
{
	uint64_t bit;

	while (flag) {
		bit = flag & -flag;
		if (set)
			peer_af_flag_set(peer, afi, safi, bit);
		else
			peer_af_flag_unset(peer, afi, safi, bit);
		flag &= ~bit;
	}
}

int bgp_nb_peer_af_flag_modify(struct nb_cb_modify_args *args,
			       const char *peer_xpath, afi_t afi, safi_t safi,
			       uint64_t flag)
{
	struct peer *peer;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		enable = yang_dnode_get_bool(args->dnode, NULL);
		bgp_nb_peer_af_flag_apply(peer, afi, safi, flag, enable);

		/* Send dynamic capability for ORF changes */
		if (flag & (PEER_FLAG_ORF_PREFIX_SM | PEER_FLAG_ORF_PREFIX_RM))
			bgp_capability_send(peer, afi, safi,
					    CAPABILITY_CODE_ORF,
					    enable ? CAPABILITY_ACTION_SET
						   : CAPABILITY_ACTION_UNSET);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_af_flag_destroy(struct nb_cb_destroy_args *args,
				const char *peer_xpath, afi_t afi, safi_t safi,
				uint64_t flag)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		bgp_nb_peer_af_flag_apply(peer, afi, safi, flag, false);

		/* Send dynamic capability for ORF changes */
		if (flag & (PEER_FLAG_ORF_PREFIX_SM | PEER_FLAG_ORF_PREFIX_RM))
			bgp_capability_send(peer, afi, safi,
					    CAPABILITY_CODE_ORF,
					    CAPABILITY_ACTION_UNSET);
		break;
	}

	return NB_OK;
}

/*
 * Weight helpers
 */
int bgp_nb_peer_weight_modify(struct nb_cb_modify_args *args,
			      const char *peer_xpath, afi_t afi, safi_t safi)
{
	struct peer *peer;
	uint16_t weight;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		weight = yang_dnode_get_uint16(args->dnode, NULL);
		peer_weight_set(peer, afi, safi, weight);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_weight_destroy(struct nb_cb_destroy_args *args,
			       const char *peer_xpath, afi_t afi, safi_t safi)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_weight_unset(peer, afi, safi);
		break;
	}

	return NB_OK;
}

/*
 * Peer-group AF flag helper
 * Gets peer_group from running store and uses group->conf for peer operations
 */
int bgp_nb_peer_group_af_flag_modify(struct nb_cb_modify_args *args,
				     const char *group_xpath, afi_t afi,
				     safi_t safi, uint64_t flag)
{
	struct peer_group *group;
	struct peer *peer;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable)
			peer_af_flag_set(peer, afi, safi, flag);
		else
			peer_af_flag_unset(peer, afi, safi, flag);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_flag_destroy(struct nb_cb_destroy_args *args,
				      const char *group_xpath, afi_t afi,
				      safi_t safi, uint64_t flag)
{
	struct peer_group *group;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_af_flag_unset(peer, afi, safi, flag);
		break;
	}

	return NB_OK;
}

/*
 * Peer-group weight helpers
 * Gets peer_group from running store and uses group->conf for peer operations
 */
int bgp_nb_peer_group_weight_modify(struct nb_cb_modify_args *args,
				    const char *group_xpath, afi_t afi,
				    safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;
	uint16_t weight;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		weight = yang_dnode_get_uint16(args->dnode, NULL);
		peer_weight_set(peer, afi, safi, weight);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_group_weight_destroy(struct nb_cb_destroy_args *args,
				     const char *group_xpath, afi_t afi,
				     safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_weight_unset(peer, afi, safi);
		break;
	}

	return NB_OK;
}

/*
 * Peer-group allowas_in helpers
 * For allow-own-as and allow-own-origin-as configuration
 */
int bgp_nb_peer_group_allowas_in_modify(struct nb_cb_modify_args *args,
					const char *group_xpath, afi_t afi,
					safi_t safi, int origin)
{
	struct peer_group *group;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		if (origin) {
			/*
			 * allow-own-origin-as is a boolean leaf.
			 * When true, enable allowas-in with origin mode.
			 * When false, disable allowas-in.
			 */
			bool enabled = yang_dnode_get_bool(args->dnode, NULL);
			if (enabled)
				peer_allowas_in_set(peer, afi, safi, 0, origin);
			else
				peer_allowas_in_unset(peer, afi, safi);
		} else {
			/* allow-own-as is a uint8 leaf */
			uint8_t allow_num = yang_dnode_get_uint8(args->dnode, NULL);
			peer_allowas_in_set(peer, afi, safi, allow_num, origin);
		}
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_group_allowas_in_destroy(struct nb_cb_destroy_args *args,
					 const char *group_xpath, afi_t afi,
					 safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_allowas_in_unset(peer, afi, safi);
		break;
	}

	return NB_OK;
}

/*
 * Neighbor allowas_in helpers
 */
int bgp_nb_peer_allowas_in_modify(struct nb_cb_modify_args *args,
				  const char *peer_xpath, afi_t afi,
				  safi_t safi, int origin)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		if (origin) {
			/*
			 * allow-own-origin-as is a boolean leaf.
			 * When true, enable allowas-in with origin mode.
			 * When false, disable allowas-in.
			 */
			bool enabled = yang_dnode_get_bool(args->dnode, NULL);
			if (enabled)
				peer_allowas_in_set(peer, afi, safi, 0, origin);
			else
				peer_allowas_in_unset(peer, afi, safi);
		} else {
			/* allow-own-as is a uint8 leaf */
			uint8_t allow_num = yang_dnode_get_uint8(args->dnode, NULL);
			peer_allowas_in_set(peer, afi, safi, allow_num, origin);
		}
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_allowas_in_destroy(struct nb_cb_destroy_args *args,
				   const char *peer_xpath, afi_t afi,
				   safi_t safi)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		peer_allowas_in_unset(peer, afi, safi);
		break;
	}

	return NB_OK;
}

/*
 * Helper to convert YANG add-path-type string to BGP addpath strategy enum
 */
static enum bgp_addpath_strat yang_to_addpath_strat(const char *path_type)
{
	if (strmatch(path_type, "all"))
		return BGP_ADDPATH_ALL;
	else if (strmatch(path_type, "per-as"))
		return BGP_ADDPATH_BEST_PER_AS;
	else
		return BGP_ADDPATH_NONE;
}

/*
 * Neighbor add-paths helpers
 */
int bgp_nb_peer_addpath_modify(struct nb_cb_modify_args *args,
			       const char *peer_xpath, afi_t afi, safi_t safi)
{
	struct peer *peer;
	const char *path_type_str;
	enum bgp_addpath_strat addpath_type;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		path_type_str = yang_dnode_get_string(args->dnode, NULL);
		addpath_type = yang_to_addpath_strat(path_type_str);
		bgp_addpath_set_peer_type(peer, afi, safi, addpath_type, 0);
		break;
	}

	return NB_OK;
}

/*
 * Peer-group add-paths helpers
 */
int bgp_nb_peer_group_addpath_modify(struct nb_cb_modify_args *args,
				     const char *group_xpath, afi_t afi,
				     safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;
	const char *path_type_str;
	enum bgp_addpath_strat addpath_type;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		path_type_str = yang_dnode_get_string(args->dnode, NULL);
		addpath_type = yang_to_addpath_strat(path_type_str);
		bgp_addpath_set_peer_type(peer, afi, safi, addpath_type, 0);
		break;
	}

	return NB_OK;
}

/*
 * Default-originate helper functions
 */
int bgp_nb_peer_default_originate_modify(struct nb_cb_modify_args *args,
					 const char *peer_xpath, afi_t afi,
					 safi_t safi)
{
	struct peer *peer;
	bool enable;
	const char *rmap_name = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable) {
			/*
			 * Get the route-map name from YANG dnode sibling or
			 * peer struct. Pass NULL for route_map pointer - it
			 * will be resolved by the route-map callback when
			 * the route-map is created/modified.
			 */
			if (yang_dnode_exists(args->dnode, "../route-map"))
				rmap_name = yang_dnode_get_string(args->dnode,
								  "../route-map");
			else if (peer->default_rmap[afi][safi].name)
				rmap_name = peer->default_rmap[afi][safi].name;

			/*
			 * Read the default-originate timer from YANG before
			 * calling peer_default_originate_set(). This ensures
			 * the timer is set correctly regardless of northbound
			 * callback execution order. The timer xpath is relative
			 * to the BGP instance node.
			 */
			if (rmap_name && !peer->bgp->rmap_def_originate_eval_timer) {
				const struct lyd_node *bgp_dnode;
				const char *timer_xpath =
					"./global/global-neighbor-config/default-originate-timer";

				bgp_dnode = yang_dnode_get_parent(args->dnode,
								  "bgp");
				if (bgp_dnode &&
				    yang_dnode_exists(bgp_dnode, timer_xpath)) {
					peer->bgp->rmap_def_originate_eval_timer =
						yang_dnode_get_uint32(bgp_dnode,
								      "%s", timer_xpath);
				}
			}

			peer_default_originate_set(peer, afi, safi, rmap_name,
						  rmap_name ? route_map_lookup_by_name(rmap_name) : NULL);
		} else {
			peer_default_originate_unset(peer, afi, safi);
		}
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_default_originate_rmap_modify(struct nb_cb_modify_args *args,
					      const char *peer_xpath, afi_t afi,
					      safi_t safi)
{
	struct peer *peer;
	const char *rmap_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		rmap_name = yang_dnode_get_string(args->dnode, NULL);

		peer_default_originate_set(peer, afi, safi, rmap_name,
					   route_map_lookup_by_name(rmap_name));
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_default_originate_rmap_destroy(struct nb_cb_destroy_args *args,
					       const char *peer_xpath, afi_t afi,
					       safi_t safi)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		/* If default-originate is still enabled, keep it without route-map */
		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE))
			peer_default_originate_set(peer, afi, safi, NULL, NULL);
		break;
	}

	return NB_OK;
}

/*
 * Peer-group default-originate helper functions
 */
int bgp_nb_peer_group_default_originate_modify(struct nb_cb_modify_args *args,
					       const char *group_xpath, afi_t afi,
					       safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;
	bool enable;
	const char *rmap_name = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable) {
			/*
			 * Get the route-map name from YANG dnode sibling or
			 * peer struct. Pass NULL for the route-map pointer.
			 * The route-map hook mechanism and timer will update
			 * it when the route-map is ready.
			 */
			if (yang_dnode_exists(args->dnode, "../route-map"))
				rmap_name = yang_dnode_get_string(args->dnode,
								  "../route-map");
			else if (peer->default_rmap[afi][safi].name)
				rmap_name = peer->default_rmap[afi][safi].name;

			peer_default_originate_set(peer, afi, safi, rmap_name, NULL);
		} else {
			peer_default_originate_unset(peer, afi, safi);
		}
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_group_default_originate_rmap_modify(struct nb_cb_modify_args *args,
						    const char *group_xpath, afi_t afi,
						    safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;
	const char *rmap_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		rmap_name = yang_dnode_get_string(args->dnode, NULL);

		/*
		 * Pass NULL for the route-map pointer. The route-map hook
		 * mechanism and timer will update it when the route-map
		 * is ready. This matches baseline behavior.
		 */
		peer_default_originate_set(peer, afi, safi, rmap_name, NULL);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_group_default_originate_rmap_destroy(struct nb_cb_destroy_args *args,
						     const char *group_xpath, afi_t afi,
						     safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		/* If default-originate is still enabled, keep it without route-map */
		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE))
			peer_default_originate_set(peer, afi, safi, NULL, NULL);
		break;
	}

	return NB_OK;
}

/*
 * Prefix-limit helpers
 *
 * Prefix-limit configuration has a complex structure:
 * - direction-list (keyed by direction: in/out)
 *   - max-prefixes (mandatory)
 *   - force-check (optional, default false)
 *   - options container (only for direction=in)
 *     - choice: warning-only, restart-timer, shutdown-threshold-pct,
 *       or threshold-restart (tr-*), or threshold-warning (tw-*)
 *
 * APIs:
 * - Inbound: peer_maximum_prefix_set(peer, afi, safi, max, threshold,
 *                                    warning_only, restart, force)
 * - Outbound: peer_maximum_prefix_out_set(peer, afi, safi, max)
 */

/* Default threshold percentage if not specified */
#define MAXIMUM_PREFIX_THRESHOLD_DEFAULT 75

/*
 * Internal helper to read prefix-limit config from direction-list dnode
 * and apply it to a peer
 */
static int prefix_limit_apply_from_dnode(struct peer *peer, afi_t afi,
					 safi_t safi,
					 const struct lyd_node *dir_dnode)
{
	int direction;
	uint32_t max;
	bool force = false;
	uint8_t threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
	bool warning = false;
	uint16_t restart = 0;
	int ret;

	/* Get direction (1=in, 2=out) */
	direction = yang_dnode_get_enum(dir_dnode, "direction");

	/* Get max-prefixes (mandatory) */
	max = yang_dnode_get_uint32(dir_dnode, "max-prefixes");

	/* Get force-check if it exists */
	if (yang_dnode_exists(dir_dnode, "force-check"))
		force = yang_dnode_get_bool(dir_dnode, "force-check");

	if (direction == 2) {
		/* Outbound prefix limit - only uses max-prefixes */
		ret = peer_maximum_prefix_out_set(peer, afi, safi, max);
		return (ret == 0) ? NB_OK : NB_ERR_INCONSISTENCY;
	}

	/* Inbound prefix limit - check options container */
	if (yang_dnode_exists(dir_dnode, "options/warning-only")) {
		warning = yang_dnode_get_bool(dir_dnode, "options/warning-only");
	} else if (yang_dnode_exists(dir_dnode, "options/restart-timer")) {
		restart = yang_dnode_get_uint16(dir_dnode,
						"options/restart-timer");
	} else if (yang_dnode_exists(dir_dnode,
				     "options/shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir_dnode,
						 "options/shutdown-threshold-pct");
	} else if (yang_dnode_exists(dir_dnode,
				     "options/tr-shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir_dnode,
						 "options/tr-shutdown-threshold-pct");
		if (yang_dnode_exists(dir_dnode, "options/tr-restart-timer"))
			restart = yang_dnode_get_uint16(dir_dnode,
							"options/tr-restart-timer");
	} else if (yang_dnode_exists(dir_dnode,
				     "options/tw-shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir_dnode,
						 "options/tw-shutdown-threshold-pct");
		if (yang_dnode_exists(dir_dnode, "options/tw-warning-only"))
			warning = yang_dnode_get_bool(dir_dnode,
						      "options/tw-warning-only");
	}

	ret = peer_maximum_prefix_set(peer, afi, safi, max, threshold, warning,
				      restart, force);
	return (ret == 0) ? NB_OK : NB_ERR_INCONSISTENCY;
}

/*
 * Apply prefix-limit configuration for a neighbor/unnumbered-neighbor
 * Called from leaf modify callbacks under direction-list
 */
int bgp_nb_peer_prefix_limit_apply(struct nb_cb_modify_args *args,
				   const char *peer_xpath,
				   const char *dir_xpath, afi_t afi,
				   safi_t safi)
{
	struct peer *peer;
	const struct lyd_node *dir_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		/* Navigate to direction-list node */
		dir_dnode = yang_dnode_get(args->dnode, dir_xpath);
		if (!dir_dnode)
			return NB_ERR_NOT_FOUND;

		return prefix_limit_apply_from_dnode(peer, afi, safi, dir_dnode);
	}

	return NB_OK;
}

/*
 * Destroy prefix-limit configuration for a neighbor/unnumbered-neighbor
 * Called from direction-list destroy callback
 */
int bgp_nb_peer_prefix_limit_destroy(struct nb_cb_destroy_args *args,
				     const char *peer_xpath, afi_t afi,
				     safi_t safi)
{
	struct peer *peer;
	int direction;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		/* Get direction from current node (direction-list) */
		direction = yang_dnode_get_enum(args->dnode, "direction");

		if (direction == 2) {
			/* Outbound */
			ret = peer_maximum_prefix_out_unset(peer, afi, safi);
		} else {
			/* Inbound */
			ret = peer_maximum_prefix_unset(peer, afi, safi);
		}
		return (ret == 0) ? NB_OK : NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

/*
 * Apply prefix-limit configuration for a peer-group
 */
int bgp_nb_peer_group_prefix_limit_apply(struct nb_cb_modify_args *args,
					 const char *group_xpath,
					 const char *dir_xpath, afi_t afi,
					 safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;
	const struct lyd_node *dir_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		/* Navigate to direction-list node */
		dir_dnode = yang_dnode_get(args->dnode, dir_xpath);
		if (!dir_dnode)
			return NB_ERR_NOT_FOUND;

		return prefix_limit_apply_from_dnode(peer, afi, safi, dir_dnode);
	}

	return NB_OK;
}

/*
 * Destroy prefix-limit configuration for a peer-group
 */
int bgp_nb_peer_group_prefix_limit_destroy(struct nb_cb_destroy_args *args,
					   const char *group_xpath, afi_t afi,
					   safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;
	int direction;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		/* Get direction from current node (direction-list) */
		direction = yang_dnode_get_enum(args->dnode, "direction");

		if (direction == 2) {
			/* Outbound */
			ret = peer_maximum_prefix_out_unset(peer, afi, safi);
		} else {
			/* Inbound */
			ret = peer_maximum_prefix_unset(peer, afi, safi);
		}
		return (ret == 0) ? NB_OK : NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

/*
 * Site-of-Origin (SOO) helpers
 */
int bgp_nb_peer_soo_modify(struct nb_cb_modify_args *args,
			   const char *peer_xpath, afi_t afi, safi_t safi)
{
	struct peer *peer;
	const char *soo_str;
	struct ecommunity *ecomm_soo;

	switch (args->event) {
	case NB_EV_VALIDATE:
		soo_str = yang_dnode_get_string(args->dnode, NULL);
		ecomm_soo = ecommunity_str2com(soo_str, ECOMMUNITY_SITE_ORIGIN, 0);
		if (!ecomm_soo) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Malformed SoO extended community: %s", soo_str);
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&ecomm_soo);
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		soo_str = yang_dnode_get_string(args->dnode, NULL);
		ecomm_soo = ecommunity_str2com(soo_str, ECOMMUNITY_SITE_ORIGIN, 0);
		if (!ecomm_soo)
			return NB_ERR_RESOURCE;

		ecommunity_str(ecomm_soo);

		if (!ecommunity_match(peer->soo[afi][safi], ecomm_soo)) {
			ecommunity_free(&peer->soo[afi][safi]);
			peer->soo[afi][safi] = ecomm_soo;
		} else {
			ecommunity_free(&ecomm_soo);
		}

		peer_af_flag_set(peer, afi, safi, PEER_FLAG_SOO);
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_soo_destroy(struct nb_cb_destroy_args *args,
			    const char *peer_xpath, afi_t afi, safi_t safi)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		ecommunity_free(&peer->soo[afi][safi]);
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_SOO);
		break;
	}

	return NB_OK;
}

/*
 * Neighbor dampening helpers
 */
int bgp_nb_peer_dampening_enable_modify(struct nb_cb_modify_args *args,
					const char *peer_xpath, afi_t afi,
					safi_t safi)
{
	struct peer *peer;
	bool enable;
	time_t half, max;
	unsigned int reuse, suppress;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, peer_xpath, true);
		if (!peer)
			return NB_ERR_NOT_FOUND;

		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable) {
			/* Read optional parameters or use defaults */
			if (yang_dnode_exists(args->dnode, "../half-life"))
				half = yang_dnode_get_uint8(args->dnode, "../half-life") * 60;
			else
				half = DEFAULT_HALF_LIFE * 60;

			if (yang_dnode_exists(args->dnode, "../reuse-threshold"))
				reuse = yang_dnode_get_uint16(args->dnode, "../reuse-threshold");
			else
				reuse = DEFAULT_REUSE;

			if (yang_dnode_exists(args->dnode, "../suppress-threshold"))
				suppress = yang_dnode_get_uint16(args->dnode, "../suppress-threshold");
			else
				suppress = DEFAULT_SUPPRESS;

			if (yang_dnode_exists(args->dnode, "../max-suppress-time"))
				max = yang_dnode_get_uint8(args->dnode, "../max-suppress-time") * 60;
			else
				max = half * 4;

			bgp_peer_damp_enable(peer, afi, safi, half, reuse, suppress, max);
		} else {
			bgp_peer_damp_disable(peer, afi, safi);
		}
		break;
	}

	return NB_OK;
}

int bgp_nb_peer_group_dampening_enable_modify(struct nb_cb_modify_args *args,
					      const char *group_xpath, afi_t afi,
					      safi_t safi)
{
	struct peer_group *group;
	struct peer *peer;
	bool enable;
	time_t half, max;
	unsigned int reuse, suppress;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(args->dnode, group_xpath, true);
		if (!group)
			return NB_ERR_NOT_FOUND;

		peer = group->conf;
		if (!peer)
			return NB_ERR_NOT_FOUND;

		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable) {
			/* Read optional parameters or use defaults */
			if (yang_dnode_exists(args->dnode, "../half-life"))
				half = yang_dnode_get_uint8(args->dnode, "../half-life") * 60;
			else
				half = DEFAULT_HALF_LIFE * 60;

			if (yang_dnode_exists(args->dnode, "../reuse-threshold"))
				reuse = yang_dnode_get_uint16(args->dnode, "../reuse-threshold");
			else
				reuse = DEFAULT_REUSE;

			if (yang_dnode_exists(args->dnode, "../suppress-threshold"))
				suppress = yang_dnode_get_uint16(args->dnode, "../suppress-threshold");
			else
				suppress = DEFAULT_SUPPRESS;

			if (yang_dnode_exists(args->dnode, "../max-suppress-time"))
				max = yang_dnode_get_uint8(args->dnode, "../max-suppress-time") * 60;
			else
				max = half * 4;

			bgp_peer_damp_enable(peer, afi, safi, half, reuse, suppress, max);
		} else {
			bgp_peer_damp_disable(peer, afi, safi);
		}
		break;
	}

	return NB_OK;
}

/*
 * Maximum-prefix cli_write helper
 * Called from all 24 max_prefixes_cli_write variations
 * dnode points to max-prefixes leaf
 * addr_xpath is relative path to remote-address/interface/peer-group-name
 */
void bgp_nb_peer_max_prefix_cli_write(struct vty *vty,
				      const struct lyd_node *dnode,
				      const char *addr_xpath,
				      bool show_defaults)
{
	uint32_t max_prefixes;
	const char *addr;

	max_prefixes = yang_dnode_get_uint32(dnode, NULL);
	if (max_prefixes == 0 && !show_defaults)
		return;

	addr = yang_dnode_get_string(dnode, "%s", addr_xpath);

	/*
	 * Check for options - they are siblings under direction-list
	 * YANG structure: direction-list/options/...
	 * From max-prefixes, options is at ../options
	 *
	 * Cases:
	 * 1. warning-only only
	 * 2. restart-timer only
	 * 3. shutdown-threshold-pct only (just threshold)
	 * 4. tr-shutdown-threshold-pct + tr-restart-timer (threshold + restart)
	 * 5. tw-shutdown-threshold-pct + tw-warning-only (threshold + warning)
	 */

	/* Check threshold-restart case */
	if (yang_dnode_exists(dnode, "../options/tr-shutdown-threshold-pct")) {
		uint8_t threshold = yang_dnode_get_uint8(dnode, "../options/tr-shutdown-threshold-pct");
		uint16_t restart = yang_dnode_get_uint16(dnode, "../options/tr-restart-timer");
		vty_out(vty, "  neighbor %s maximum-prefix %u %u restart %u\n",
			addr, max_prefixes, threshold, restart);
		return;
	}

	/* Check threshold-warning case */
	if (yang_dnode_exists(dnode, "../options/tw-shutdown-threshold-pct")) {
		uint8_t threshold = yang_dnode_get_uint8(dnode, "../options/tw-shutdown-threshold-pct");
		vty_out(vty, "  neighbor %s maximum-prefix %u %u warning-only\n",
			addr, max_prefixes, threshold);
		return;
	}

	/* Check restart-timer only case */
	if (yang_dnode_exists(dnode, "../options/restart-timer")) {
		uint16_t restart = yang_dnode_get_uint16(dnode, "../options/restart-timer");
		vty_out(vty, "  neighbor %s maximum-prefix %u restart %u\n",
			addr, max_prefixes, restart);
		return;
	}

	/* Check warning-only only case */
	if (yang_dnode_exists(dnode, "../options/warning-only")) {
		bool warning = yang_dnode_get_bool(dnode, "../options/warning-only");
		if (warning) {
			vty_out(vty, "  neighbor %s maximum-prefix %u warning-only\n",
				addr, max_prefixes);
			return;
		}
	}

	/* Check shutdown-threshold-pct only case (just threshold) */
	if (yang_dnode_exists(dnode, "../options/shutdown-threshold-pct")) {
		uint8_t threshold = yang_dnode_get_uint8(dnode, "../options/shutdown-threshold-pct");
		vty_out(vty, "  neighbor %s maximum-prefix %u %u\n",
			addr, max_prefixes, threshold);
		return;
	}

	/* Basic case - just max-prefixes */
	vty_out(vty, "  neighbor %s maximum-prefix %u\n", addr, max_prefixes);
}

/*
 * Create a BGP instance with default flags applied.
 * This is the preferred function for creating BGP instances from
 * any code path (northbound, VTY, etc.) as it ensures defaults
 * like import-check are applied consistently.
 */
int bgp_instance_create(struct bgp **bgp, as_t *as, const char *name,
			enum bgp_instance_type inst_type, const char *as_pretty,
			enum asnotation_mode asnotation)
{
	int ret = bgp_get(bgp, as, name, inst_type, as_pretty, asnotation);

	if (ret == BGP_CREATED) {
		bgp_timers_set(NULL, *bgp, DFLT_BGP_KEEPALIVE, DFLT_BGP_HOLDTIME,
			       DFLT_BGP_CONNECT_RETRY, BGP_DEFAULT_DELAYOPEN);

		if (DFLT_BGP_IMPORT_CHECK)
			SET_FLAG((*bgp)->flags, BGP_FLAG_IMPORT_CHECK);
		if (DFLT_BGP_SHOW_HOSTNAME)
			SET_FLAG((*bgp)->flags, BGP_FLAG_SHOW_HOSTNAME);
		if (DFLT_BGP_SHOW_NEXTHOP_HOSTNAME)
			SET_FLAG((*bgp)->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
		if (DFLT_BGP_LOG_NEIGHBOR_CHANGES)
			SET_FLAG((*bgp)->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
		if (DFLT_BGP_DETERMINISTIC_MED)
			SET_FLAG((*bgp)->flags, BGP_FLAG_DETERMINISTIC_MED);
		if (DFLT_BGP_EBGP_REQUIRES_POLICY)
			SET_FLAG((*bgp)->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
		if (DFLT_BGP_SUPPRESS_DUPLICATES)
			SET_FLAG((*bgp)->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
		if (DFLT_BGP_GRACEFUL_NOTIFICATION)
			SET_FLAG((*bgp)->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		if (DFLT_BGP_HARD_ADMIN_RESET)
			SET_FLAG((*bgp)->flags, BGP_FLAG_HARD_ADMIN_RESET);
		if (DFLT_BGP_SOFT_VERSION_CAPABILITY)
			SET_FLAG((*bgp)->flags,
				 BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
		if (DFLT_BGP_LINK_LOCAL_CAPABILITY)
			SET_FLAG((*bgp)->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
		if (DFLT_BGP_DYNAMIC_CAPABILITY)
			SET_FLAG((*bgp)->flags,
				 BGP_FLAG_DYNAMIC_CAPABILITY);
		if (DFLT_BGP_ENFORCE_FIRST_AS)
			SET_FLAG((*bgp)->flags, BGP_FLAG_ENFORCE_FIRST_AS);
		if (DFLT_BGP_RR_ALLOW_OUTBOUND_POLICY)
			SET_FLAG((*bgp)->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		if (DFLT_BGP_COMPARE_AIGP)
			SET_FLAG((*bgp)->flags, BGP_FLAG_COMPARE_AIGP);

		ret = BGP_SUCCESS;
	}
	return ret;
}

/*
 * Wrapper for bgp_static_set() that takes struct bgp * instead of vty.
 * Used by NB callbacks which don't have a vty context.
 */
int bgp_static_set_nb(struct bgp *bgp, bool negate, const char *ip_str,
		       const char *rd_str, const char *label_str,
		       afi_t afi, safi_t safi, const char *rmap)
{
	struct vty vty_dummy = {};
	int ret;

	/* bgp_static_set uses VTY_DECLVAR_CONTEXT which reads
	 * vty->qobj_index. Set up a minimal vty with bgp's QOBJ.
	 */
	vty_dummy.node = BGP_VPNV4_NODE;
	vty_dummy.qobj_index = bgp->qobj_node.nid;

	ret = bgp_static_set(&vty_dummy, negate, ip_str, rd_str, label_str,
			     afi, safi, rmap, 0, 0, 0, NULL, NULL, NULL, NULL);

	return ret;
}
