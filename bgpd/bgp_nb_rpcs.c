// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound RPC Implementations
 * Copyright (C) 2024 FRRouting
 *
 * This file implements YANG RPC handlers for BGP operations,
 * providing RESTCONF-accessible equivalents to VTY commands.
 */

#include <zebra.h>

#include "northbound.h"
#include "linklist.h"
#include "prefix.h"
#include "yang_wrappers.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mplsvpn.h"
#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_private.h"
#endif
#endif

/* Forward declarations */
static bool safi_is_two_level(safi_t safi);

/*
 * Helper function to convert YANG afi string to afi_t
 */
static afi_t yang_afi_to_afi(const char *afi_str)
{
	if (!afi_str)
		return AFI_UNSPEC;
	if (strcmp(afi_str, "ipv4") == 0)
		return AFI_IP;
	if (strcmp(afi_str, "ipv6") == 0)
		return AFI_IP6;
	if (strcmp(afi_str, "l2vpn") == 0)
		return AFI_L2VPN;
	return AFI_UNSPEC;
}

/*
 * Helper function to convert YANG safi string to safi_t
 */
static safi_t yang_safi_to_safi(const char *safi_str)
{
	if (!safi_str)
		return SAFI_UNSPEC;
	if (strcmp(safi_str, "unicast") == 0)
		return SAFI_UNICAST;
	if (strcmp(safi_str, "multicast") == 0)
		return SAFI_MULTICAST;
	if (strcmp(safi_str, "labeled-unicast") == 0)
		return SAFI_LABELED_UNICAST;
	if (strcmp(safi_str, "vpn") == 0)
		return SAFI_MPLS_VPN;
	if (strcmp(safi_str, "evpn") == 0)
		return SAFI_EVPN;
	if (strcmp(safi_str, "flowspec") == 0)
		return SAFI_FLOWSPEC;
	return SAFI_UNSPEC;
}

/*
 * Helper function to convert YANG clear-type string to bgp_clear_type
 */
static enum bgp_clear_type yang_clear_type_to_bgp(const char *type_str)
{
	if (!type_str || strcmp(type_str, "hard") == 0)
		return BGP_CLEAR_SOFT_NONE;
	if (strcmp(type_str, "soft-in") == 0)
		return BGP_CLEAR_SOFT_IN;
	if (strcmp(type_str, "soft-out") == 0)
		return BGP_CLEAR_SOFT_OUT;
	if (strcmp(type_str, "soft-both") == 0)
		return BGP_CLEAR_SOFT_BOTH;
	if (strcmp(type_str, "message-stats") == 0)
		return BGP_CLEAR_MESSAGE_STATS;
	return BGP_CLEAR_SOFT_NONE;
}

/*
 * Clear a single peer
 */
static int bgp_nb_clear_peer(struct bgp *bgp, struct peer *peer,
			     afi_t afi, safi_t safi,
			     enum bgp_clear_type stype)
{
	if (stype == BGP_CLEAR_SOFT_NONE) {
		/* Hard reset */
		return peer_clear(peer, NULL);
	} else {
		/* Soft reset */
		return peer_clear_soft(peer, afi, safi, stype);
	}
}

/*
 * RPC: /frr-bgp:clear-bgp-peer
 * Clear BGP peer sessions
 */
int clear_bgp_peer_rpc(struct nb_cb_rpc_args *args)
{
	const char *vrf_name;
	const char *afi_str;
	const char *safi_str;
	const char *clear_type_str;
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;
	afi_t afi;
	safi_t safi;
	enum bgp_clear_type stype;
	int cleared = 0;

	/* Get input parameters - vrf is optional, check existence first */
	if (yang_dnode_exists(args->input, "vrf")) {
		vrf_name = yang_dnode_get_string(args->input, "vrf");
		if (strcmp(vrf_name, "default") == 0)
			vrf_name = NULL;
	} else {
		vrf_name = NULL;
	}

	/* Look up BGP instance */
	if (vrf_name) {
		bgp = bgp_lookup_by_name(vrf_name);
	} else {
		bgp = bgp_get_default();
	}

	if (!bgp) {
		snprintf(args->errmsg, args->errmsg_len,
			 "BGP instance not found for VRF %s",
			 vrf_name ? vrf_name : "default");
		return NB_ERR;
	}

	/* Parse AFI/SAFI */
	if (yang_dnode_exists(args->input, "afi"))
		afi_str = yang_dnode_get_string(args->input, "afi");
	else
		afi_str = NULL;
	afi = yang_afi_to_afi(afi_str);

	if (yang_dnode_exists(args->input, "safi"))
		safi_str = yang_dnode_get_string(args->input, "safi");
	else
		safi_str = NULL;
	safi = yang_safi_to_safi(safi_str);

	/* Parse clear type */
	if (yang_dnode_exists(args->input, "clear-type"))
		clear_type_str = yang_dnode_get_string(args->input, "clear-type");
	else
		clear_type_str = "hard";
	stype = yang_clear_type_to_bgp(clear_type_str);

	/* Determine target and clear */
	if (yang_dnode_exists(args->input, "all")) {
		/* Clear all peers */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			bgp_nb_clear_peer(bgp, peer, afi, safi, stype);
			cleared++;
		}
	} else if (yang_dnode_exists(args->input, "peer-address")) {
		/* Clear specific peer */
		const char *peer_str = yang_dnode_get_string(args->input, "peer-address");
		union sockunion su;

		if (str2sockunion(peer_str, &su) < 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid peer address: %s", peer_str);
			return NB_ERR;
		}

		peer = peer_lookup(bgp, &su);
		if (!peer) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Peer not found: %s", peer_str);
			return NB_ERR;
		}

		bgp_nb_clear_peer(bgp, peer, afi, safi, stype);
		cleared = 1;
	} else if (yang_dnode_exists(args->input, "peer-group-name")) {
		/* Clear peer group */
		const char *group_name = yang_dnode_get_string(args->input, "peer-group-name");
		struct peer_group *group;

		group = peer_group_lookup(bgp, group_name);
		if (!group) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Peer group not found: %s", group_name);
			return NB_ERR;
		}

		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			bgp_nb_clear_peer(bgp, peer, afi, safi, stype);
			cleared++;
		}
	} else if (yang_dnode_exists(args->input, "as-number")) {
		/* Clear by AS number */
		as_t as = yang_dnode_get_uint32(args->input, "as-number");

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->as == as) {
				bgp_nb_clear_peer(bgp, peer, afi, safi, stype);
				cleared++;
			}
		}
	} else if (yang_dnode_exists(args->input, "external")) {
		/* Clear external peers */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->sort == BGP_PEER_EBGP) {
				bgp_nb_clear_peer(bgp, peer, afi, safi, stype);
				cleared++;
			}
		}
	} else {
		/* No target specified - clear all */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			bgp_nb_clear_peer(bgp, peer, afi, safi, stype);
			cleared++;
		}
	}

	/* Set output */
	if (yang_dnode_exists(args->output, "result")) {
		char result[128];
		snprintf(result, sizeof(result), "Cleared %d peer(s)", cleared);
		yang_dnode_change_leaf(args->output, result);
	}

	return NB_OK;
}

/*
 * RPC: /frr-bgp:clear-bgp-prefix
 * Clear BGP bestpath for a specific prefix
 */
int clear_bgp_prefix_rpc(struct nb_cb_rpc_args *args)
{
	const char *vrf_name;
	const char *prefix_str;
	const char *afi_str;
	const char *safi_str;
	struct bgp *bgp;
	struct prefix match;
	struct bgp_dest *dest;
	struct bgp_table *rib;
	afi_t afi;
	safi_t safi;
	int ret;

	/* Get input parameters - vrf is optional, check existence first */
	if (yang_dnode_exists(args->input, "vrf")) {
		vrf_name = yang_dnode_get_string(args->input, "vrf");
		if (strcmp(vrf_name, "default") == 0)
			vrf_name = NULL;
	} else {
		vrf_name = NULL;
	}

	/* prefix is mandatory - check existence first */
	if (!yang_dnode_exists(args->input, "prefix")) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Missing mandatory parameter: prefix");
		return NB_ERR;
	}
	prefix_str = yang_dnode_get_string(args->input, "prefix");

	/* Look up BGP instance */
	if (vrf_name) {
		bgp = bgp_lookup_by_name(vrf_name);
	} else {
		bgp = bgp_get_default();
	}

	if (!bgp) {
		snprintf(args->errmsg, args->errmsg_len,
			 "BGP instance not found for VRF %s",
			 vrf_name ? vrf_name : "default");
		return NB_ERR;
	}

	/* Parse prefix */
	ret = str2prefix(prefix_str, &match);
	if (!ret) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Invalid prefix: %s", prefix_str);
		return NB_ERR;
	}

	/* Parse AFI - derive from prefix if not specified */
	if (yang_dnode_exists(args->input, "afi"))
		afi_str = yang_dnode_get_string(args->input, "afi");
	else
		afi_str = NULL;

	if (afi_str) {
		afi = yang_afi_to_afi(afi_str);
	} else {
		/* Derive AFI from prefix */
		if (match.family == AF_INET)
			afi = AFI_IP;
		else if (match.family == AF_INET6)
			afi = AFI_IP6;
		else {
			snprintf(args->errmsg, args->errmsg_len,
				 "Cannot determine AFI from prefix: %s", prefix_str);
			return NB_ERR;
		}
	}

	/* Parse SAFI */
	if (yang_dnode_exists(args->input, "safi"))
		safi_str = yang_dnode_get_string(args->input, "safi");
	else
		safi_str = "unicast";
	safi = yang_safi_to_safi(safi_str);

	/* Get RIB and find prefix */
	rib = bgp->rib[afi][safi];
	if (!rib) {
		snprintf(args->errmsg, args->errmsg_len,
			 "No RIB for %s/%s",
			 afi == AFI_IP ? "ipv4" : "ipv6",
			 safi == SAFI_UNICAST ? "unicast" : "multicast");
		return NB_ERR;
	}

	dest = bgp_node_match(rib, &match);
	if (dest) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		if (dest_p->prefixlen == match.prefixlen) {
			SET_FLAG(dest->flags, BGP_NODE_USER_CLEAR);
			bgp_process(bgp, dest, NULL, afi, safi);
		}
		bgp_dest_unlock_node(dest);
	}

	/* Set output */
	if (yang_dnode_exists(args->output, "result")) {
		char result[128];
		snprintf(result, sizeof(result), "Cleared prefix %s", prefix_str);
		yang_dnode_change_leaf(args->output, result);
	}

	return NB_OK;
}

/*
 * Input parameters for get-routes RPC
 */
struct get_routes_input {
	const char *vrf;
	afi_t afi;
	safi_t safi;
	uint32_t limit;
	const char *prefix_filter;
	uint8_t prefix_len_min;
	uint8_t prefix_len_max;
	union sockunion nexthop;
	bool nexthop_set;
	const char *community_filter;
	int8_t origin_filter; /* -1=any, 0=igp, 1=egp, 2=incomplete */
	bool best_only;
};

/*
 * Check if prefix matches a pattern (supports wildcards)
 * Pattern formats:
 *   "10.0.0.0/24" - exact match
 *   "10.0.*" - wildcard match (all prefixes starting with 10.0.)
 *   "10.0.0.0" - match any prefix for this network (any length)
 */
static bool prefix_matches_pattern(const struct prefix *p,
				   const char *pattern)
{
	char prefix_str[PREFIX_STRLEN];
	const char *wildcard;

	prefix2str(p, prefix_str, sizeof(prefix_str));

	/* Check for wildcard */
	wildcard = strchr(pattern, '*');
	if (wildcard) {
		/* Match up to the wildcard */
		size_t match_len = wildcard - pattern;
		return strncmp(prefix_str, pattern, match_len) == 0;
	}

	/* Check if pattern has /len */
	if (strchr(pattern, '/')) {
		/* Exact match including length */
		return strcmp(prefix_str, pattern) == 0;
	}

	/* Pattern is just network address - match prefix of any length */
	size_t pattern_len = strlen(pattern);
	return strncmp(prefix_str, pattern, pattern_len) == 0 &&
	       (prefix_str[pattern_len] == '/' || prefix_str[pattern_len] == '\0');
}

/*
 * Check if route has matching community
 * Uses community_match which checks if com2's values are all in com1
 */
static bool community_matches(struct attr *attr, const char *community_str)
{
	struct community *route_comm;
	struct community *filter_comm;
	bool match = false;

	if (!attr || !community_str)
		return false;

	route_comm = bgp_attr_get_community(attr);
	if (!route_comm)
		return false;

	/* Parse the filter community string */
	filter_comm = community_str2com(community_str);
	if (!filter_comm)
		return false;

	/* Check if filter community is contained in route community */
	match = community_match(route_comm, filter_comm);

	community_free(&filter_comm);
	return match;
}

/*
 * Check if nexthop matches filter
 */
static bool nexthop_matches(struct attr *attr, union sockunion *filter)
{
	if (!attr || !filter)
		return false;

	/* IPv4 nexthop */
	if (filter->sa.sa_family == AF_INET) {
		if (attr->nexthop.s_addr == filter->sin.sin_addr.s_addr)
			return true;
		/* Also check mp_nexthop for IPv4 */
		if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4 &&
		    attr->mp_nexthop_global_in.s_addr == filter->sin.sin_addr.s_addr)
			return true;
	}

	/* IPv6 nexthop */
	if (filter->sa.sa_family == AF_INET6) {
		if (attr->mp_nexthop_len >= BGP_ATTR_NHLEN_IPV6_GLOBAL &&
		    memcmp(&attr->mp_nexthop_global, &filter->sin6.sin6_addr,
			   sizeof(struct in6_addr)) == 0)
			return true;
	}

	return false;
}

/*
 * Check if a path matches all filter criteria
 */
static bool path_matches_criteria(struct bgp_dest *dest,
				  struct bgp_path_info *pi,
				  struct get_routes_input *input)
{
	const struct prefix *p = bgp_dest_get_prefix(dest);

	/* Prefix length filter */
	if (input->prefix_len_min > 0 && p->prefixlen < input->prefix_len_min)
		return false;
	if (input->prefix_len_max > 0 && p->prefixlen > input->prefix_len_max)
		return false;

	/* Prefix pattern filter */
	if (input->prefix_filter) {
		if (!prefix_matches_pattern(p, input->prefix_filter))
			return false;
	}

	/* Origin filter */
	if (input->origin_filter >= 0) {
		if (pi->attr->origin != (uint8_t)input->origin_filter)
			return false;
	}

	/* Best only filter */
	if (input->best_only) {
		if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
			return false;
	}

	/* Nexthop filter */
	if (input->nexthop_set) {
		if (!nexthop_matches(pi->attr, &input->nexthop))
			return false;
	}

	/* Community filter */
	if (input->community_filter) {
		if (!community_matches(pi->attr, input->community_filter))
			return false;
	}

	return true;
}

/*
 * Get origin string from attribute
 */
static const char *origin_to_string(uint8_t origin)
{
	switch (origin) {
	case BGP_ORIGIN_IGP:
		return "igp";
	case BGP_ORIGIN_EGP:
		return "egp";
	case BGP_ORIGIN_INCOMPLETE:
		return "incomplete";
	default:
		return "unknown";
	}
}

/*
 * Get route-type string from path info type
 */
static const char *route_type_to_string(uint8_t type)
{
	switch (type) {
	case ZEBRA_ROUTE_STATIC:
		return "static";
	case ZEBRA_ROUTE_CONNECT:
		return "connected";
	case ZEBRA_ROUTE_BGP:
		return "bgp";
	default:
		return "bgp";
	}
}

/*
 * Get route-subtype string from path info sub_type
 */
static const char *route_subtype_to_string(uint8_t sub_type)
{
	switch (sub_type) {
	case BGP_ROUTE_NORMAL:
		return "normal";
	case BGP_ROUTE_STATIC:
		return "static";
	case BGP_ROUTE_AGGREGATE:
		return "aggregate";
	case BGP_ROUTE_REDISTRIBUTE:
		return "redistribute";
	case BGP_ROUTE_IMPORTED:
		return "imported";
	default:
		return "normal";
	}
}

/*
 * Format uptime string from timestamp
 */
static void format_uptime(time_t uptime, char *buf, size_t len)
{
	time_t now = monotime(NULL);
	time_t diff = now - uptime;
	int days, hours, mins, secs;

	days = diff / 86400;
	diff %= 86400;
	hours = diff / 3600;
	diff %= 3600;
	mins = diff / 60;
	secs = diff % 60;

	if (days > 0)
		snprintf(buf, len, "%dd%02dh%02dm", days, hours, mins);
	else if (hours > 0)
		snprintf(buf, len, "%02d:%02d:%02d", hours, mins, secs);
	else
		snprintf(buf, len, "00:%02d:%02d", mins, secs);
}

/*
 * Helper function to add a single route to RPC output
 * Returns true if route was added (for counting), false otherwise
 * rd_dest: for VPN SAFIs, the parent RD dest node (NULL for other SAFIs)
 */
static bool add_route_to_output(struct lyd_node *output,
				struct bgp_dest *dest,
				struct bgp_dest *rd_dest,
				struct get_routes_input *input,
				const struct prefix *actual_prefix)
{
	struct bgp_path_info *pi;
	struct lyd_node *route_node = NULL;
	struct lyd_node *paths_node = NULL;
	char prefix_str[PREFIX_STRLEN];
	char nexthop_str[INET6_ADDRSTRLEN];
	char uptime_str[32];
	char rd_str[RD_ADDRSTRLEN];
	const struct prefix_rd *prd = NULL;
	bool dest_added = false;
	int ret;

	/* Get RD for VPN SAFIs */
	if (rd_dest && safi_is_two_level(input->safi)) {
		prd = bgp_rd_from_dest(rd_dest, input->safi);
	}

	pi = bgp_dest_get_bgp_path_info(dest);
	if (!pi)
		return false;

	/* Check each path */
	for (; pi; pi = pi->next) {
		if (!path_matches_criteria(dest, pi, input))
			continue;

		/* Add route node if this is first matching path */
		if (!dest_added) {
			prefix2str(actual_prefix, prefix_str, sizeof(prefix_str));

			/*
			 * Use output=1 since routes is in RPC output schema.
			 * Note: routes list has no keys in schema, so no key args.
			 */
			ret = lyd_new_list(output, NULL, "routes",
					   1, &route_node);
			if (ret != LY_SUCCESS)
				return false;

			ret = lyd_new_term(route_node, NULL, "prefix",
					   prefix_str, 1, NULL);
			if (ret != LY_SUCCESS)
				return false;

			dest_added = true;
		}

		/* Add path node - paths is a keyless list, no keys passed */
		ret = lyd_new_list(route_node, NULL, "paths",
				   1, &paths_node);
		if (ret != LY_SUCCESS)
			continue;

		/* path-id */
		char path_id_str[16];
		snprintf(path_id_str, sizeof(path_id_str), "%u",
			 pi->addpath_rx_id);
		lyd_new_term(paths_node, NULL, "path-id", path_id_str, 1, NULL);

		/* nexthop */
		if (pi->attr) {
			if (actual_prefix->family == AF_INET6 &&
			    pi->attr->mp_nexthop_len >= BGP_ATTR_NHLEN_IPV6_GLOBAL) {
				inet_ntop(AF_INET6, &pi->attr->mp_nexthop_global,
					  nexthop_str, sizeof(nexthop_str));
			} else if (pi->attr->nexthop.s_addr != INADDR_ANY) {
				inet_ntop(AF_INET, &pi->attr->nexthop,
					  nexthop_str, sizeof(nexthop_str));
			} else if (pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4) {
				inet_ntop(AF_INET, &pi->attr->mp_nexthop_global_in,
					  nexthop_str, sizeof(nexthop_str));
			} else {
				snprintf(nexthop_str, sizeof(nexthop_str), "0.0.0.0");
			}
			lyd_new_term(paths_node, NULL, "nexthop", nexthop_str, 1, NULL);

			/* metric (MED) */
			char metric_str[16];
			snprintf(metric_str, sizeof(metric_str), "%u", pi->attr->med);
			lyd_new_term(paths_node, NULL, "metric", metric_str, 1, NULL);

			/* local-preference */
			char locpref_str[16];
			snprintf(locpref_str, sizeof(locpref_str), "%u",
				 pi->attr->local_pref);
			lyd_new_term(paths_node, NULL, "local-preference",
				     locpref_str, 1, NULL);

			/* weight */
			char weight_str[16];
			snprintf(weight_str, sizeof(weight_str), "%u", pi->attr->weight);
			lyd_new_term(paths_node, NULL, "weight", weight_str, 1, NULL);

			/* origin */
			lyd_new_term(paths_node, NULL, "origin",
				     origin_to_string(pi->attr->origin), 1, NULL);

			/* as-path */
			if (pi->attr->aspath) {
				const char *aspath_str = aspath_print(pi->attr->aspath);
				if (aspath_str)
					lyd_new_term(paths_node, NULL, "as-path",
						     aspath_str, 1, NULL);
			}

			/* communities */
			struct community *comm = bgp_attr_get_community(pi->attr);
			if (comm) {
				char *comm_str = community_str(comm, false, false);
				if (comm_str)
					lyd_new_term(paths_node, NULL, "communities",
						     comm_str, 1, NULL);
			}

			/* extended-communities */
			struct ecommunity *ecomm = bgp_attr_get_ecommunity(pi->attr);
			if (ecomm) {
				char *ecomm_str = ecommunity_ecom2str(ecomm,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				if (ecomm_str) {
					lyd_new_term(paths_node, NULL,
						     "extended-communities",
						     ecomm_str, 1, NULL);
					XFREE(MTYPE_ECOMMUNITY_STR, ecomm_str);
				}
			}

			/* large-communities */
			struct lcommunity *lcomm = bgp_attr_get_lcommunity(pi->attr);
			if (lcomm) {
				char *lcomm_str = lcommunity_str(lcomm, false, false);
				if (lcomm_str)
					lyd_new_term(paths_node, NULL,
						     "large-communities",
						     lcomm_str, 1, NULL);
			}
		}

		/* valid */
		lyd_new_term(paths_node, NULL, "valid",
			     CHECK_FLAG(pi->flags, BGP_PATH_VALID) ? "true" : "false",
			     1, NULL);

		/* best */
		lyd_new_term(paths_node, NULL, "best",
			     CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) ? "true" : "false",
			     1, NULL);

		/* stale */
		lyd_new_term(paths_node, NULL, "stale",
			     CHECK_FLAG(pi->flags, BGP_PATH_STALE) ? "true" : "false",
			     1, NULL);

		/* multipath */
		lyd_new_term(paths_node, NULL, "multipath",
			     CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH) ? "true" : "false",
			     1, NULL);

		/* route-type */
		lyd_new_term(paths_node, NULL, "route-type",
			     route_type_to_string(pi->type), 1, NULL);

		/* route-subtype */
		lyd_new_term(paths_node, NULL, "route-subtype",
			     route_subtype_to_string(pi->sub_type), 1, NULL);

		/* source-peer (peer IP address) */
		if (pi->peer && pi->peer->host) {
			lyd_new_term(paths_node, NULL, "source-peer",
				     pi->peer->host, 1, NULL);
		}

		/* peer-id (router ID of the peer) */
		if (pi->peer) {
			char peer_id_str[INET_ADDRSTRLEN];
			if (pi->peer->remote_id.s_addr != INADDR_ANY) {
				inet_ntop(AF_INET, &pi->peer->remote_id,
					  peer_id_str, sizeof(peer_id_str));
				lyd_new_term(paths_node, NULL, "peer-id",
					     peer_id_str, 1, NULL);
			}
		}

		/* VPN-specific fields */
		/* route-distinguisher */
		if (prd) {
			prefix_rd2str(prd, rd_str, sizeof(rd_str), ASNOTATION_PLAIN);
			lyd_new_term(paths_node, NULL, "route-distinguisher",
				     rd_str, 1, NULL);
		}

		/* mpls-labels */
		if (pi->extra && pi->extra->labels &&
		    pi->extra->labels->num_labels > 0) {
			char labels_str[256] = "";
			size_t offset = 0;
			for (uint8_t i = 0; i < pi->extra->labels->num_labels &&
					   i < BGP_MAX_LABELS; i++) {
				uint32_t label_val = decode_label(
					&pi->extra->labels->label[i]);
				if (i > 0)
					offset += snprintf(labels_str + offset,
							   sizeof(labels_str) - offset, ",");
				offset += snprintf(labels_str + offset,
						   sizeof(labels_str) - offset, "%u",
						   label_val);
			}
			lyd_new_term(paths_node, NULL, "mpls-labels",
				     labels_str, 1, NULL);
		}

		/* underlay-nexthop (for VPN routes with VNC) */
#if ENABLE_BGP_VNC
		if (input->safi == SAFI_MPLS_VPN && pi->attr) {
			struct prefix pfx_un;
			if (rfapiGetVncTunnelUnAddr(pi->attr, &pfx_un) == 0) {
				char un_str[INET6_ADDRSTRLEN];
				inet_ntop(pfx_un.family, pfx_un.u.val, un_str,
					  sizeof(un_str));
				lyd_new_term(paths_node, NULL, "underlay-nexthop",
					     un_str, 1, NULL);
			}
		}
#endif

		/* uptime */
		format_uptime(pi->uptime, uptime_str, sizeof(uptime_str));
		lyd_new_term(paths_node, NULL, "uptime", uptime_str, 1, NULL);
	}

	return dest_added;
}

/*
 * Check if SAFI uses two-level table structure (RD -> prefixes)
 */
static bool safi_is_two_level(safi_t safi)
{
	return (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN);
}

/*
 * RPC: /frr-bgp:get-routes
 * Query BGP routes with filtering options
 */
int get_routes_rpc(struct nb_cb_rpc_args *args)
{
	struct get_routes_input input = {0};
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_dest *dest;
	uint32_t route_count = 0;
	const char *afi_safi_str;

	zlog_info("get_routes_rpc: ENTERED");

	if (!args || !args->input) {
		zlog_err("get_routes_rpc: args or args->input is NULL!");
		return NB_ERR;
	}

	zlog_info("get_routes_rpc: args->input is valid");

	/* Parse VRF - check existence first since it has a default */
	if (yang_dnode_exists(args->input, "vrf")) {
		input.vrf = yang_dnode_get_string(args->input, "vrf");
		if (strcmp(input.vrf, "default") == 0)
			input.vrf = NULL;
	} else {
		input.vrf = NULL;
	}

	/* Find BGP instance */
	if (input.vrf)
		bgp = bgp_lookup_by_name(input.vrf);
	else
		bgp = bgp_get_default();

	if (!bgp) {
		snprintf(args->errmsg, args->errmsg_len,
			 "BGP instance not found for VRF %s",
			 input.vrf ? input.vrf : "default");
		return NB_ERR;
	}

	/* Parse AFI/SAFI (mandatory) */
	if (!yang_dnode_exists(args->input, "afi-safi")) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Missing mandatory parameter: afi-safi");
		return NB_ERR;
	}
	afi_safi_str = yang_dnode_get_string(args->input, "afi-safi");
	yang_afi_safi_identity2value(afi_safi_str, &input.afi, &input.safi);

	if (input.afi == AFI_UNSPEC || input.safi == SAFI_UNSPEC) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Invalid AFI/SAFI: %s", afi_safi_str);
		return NB_ERR;
	}

	/* Get routing table */
	table = bgp->rib[input.afi][input.safi];
	if (!table) {
		snprintf(args->errmsg, args->errmsg_len,
			 "No RIB for AFI/SAFI %s", afi_safi_str);
		return NB_ERR;
	}

	/* Parse optional filter parameters */
	if (yang_dnode_exists(args->input, "limit"))
		input.limit = yang_dnode_get_uint32(args->input, "limit");
	else
		input.limit = 0;

	if (yang_dnode_exists(args->input, "prefix"))
		input.prefix_filter = yang_dnode_get_string(args->input, "prefix");
	else
		input.prefix_filter = NULL;

	if (yang_dnode_exists(args->input, "prefix-len-min"))
		input.prefix_len_min = yang_dnode_get_uint8(args->input, "prefix-len-min");
	else
		input.prefix_len_min = 0;

	if (yang_dnode_exists(args->input, "prefix-len-max"))
		input.prefix_len_max = yang_dnode_get_uint8(args->input, "prefix-len-max");
	else
		input.prefix_len_max = 0;

	if (yang_dnode_exists(args->input, "nexthop")) {
		const char *nh_str = yang_dnode_get_string(args->input, "nexthop");
		if (str2sockunion(nh_str, &input.nexthop) == 0)
			input.nexthop_set = true;
	}

	if (yang_dnode_exists(args->input, "community"))
		input.community_filter = yang_dnode_get_string(args->input, "community");
	else
		input.community_filter = NULL;

	if (yang_dnode_exists(args->input, "origin")) {
		const char *origin_str = yang_dnode_get_string(args->input, "origin");
		if (strcmp(origin_str, "igp") == 0)
			input.origin_filter = BGP_ORIGIN_IGP;
		else if (strcmp(origin_str, "egp") == 0)
			input.origin_filter = BGP_ORIGIN_EGP;
		else if (strcmp(origin_str, "incomplete") == 0)
			input.origin_filter = BGP_ORIGIN_INCOMPLETE;
		else
			input.origin_filter = -1;
	} else {
		input.origin_filter = -1;
	}

	if (yang_dnode_exists(args->input, "best-only"))
		input.best_only = yang_dnode_get_bool(args->input, "best-only");
	else
		input.best_only = false;

	/*
	 * Iterate through routes.
	 * VPN/ENCAP/EVPN use two-level tables: RD -> sub-table -> prefixes
	 * Other SAFIs use single-level tables: directly prefixes
	 */
	if (safi_is_two_level(input.safi)) {
		/* Two-level table: iterate RD entries, then sub-tables */
		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			struct bgp_table *sub_table;
			struct bgp_dest *rm;

			/* Get the per-RD sub-table */
			sub_table = bgp_dest_get_bgp_table_info(dest);
			if (!sub_table)
				continue;

			/* Iterate prefixes in the sub-table */
			for (rm = bgp_table_top(sub_table); rm;
			     rm = bgp_route_next(rm)) {
				const struct prefix *p = bgp_dest_get_prefix(rm);

				/* Check limit */
				if (input.limit > 0 && route_count >= input.limit) {
					bgp_dest_unlock_node(rm);
					bgp_dest_unlock_node(dest);
					goto done;
				}

				if (add_route_to_output(args->output, rm, dest, &input, p))
					route_count++;
			}
		}
	} else {
		/* Single-level table: directly iterate prefixes */
		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *p = bgp_dest_get_prefix(dest);

			/* Check limit */
			if (input.limit > 0 && route_count >= input.limit) {
				bgp_dest_unlock_node(dest);
				break;
			}

			if (add_route_to_output(args->output, dest, NULL, &input, p))
				route_count++;
		}
	}

done:
	/* Set route-count - use output=1 for RPC output schema */
	char count_str[16];
	snprintf(count_str, sizeof(count_str), "%u", route_count);

	LY_ERR lerr = lyd_new_term(args->output, NULL, "route-count",
				   count_str, 1, NULL);
	if (lerr != LY_SUCCESS) {
		zlog_err("get_routes_rpc: lyd_new_term(route-count) failed: %d", lerr);
	}

	zlog_info("get_routes_rpc: returning NB_OK with %u routes", route_count);
	return NB_OK;
}
