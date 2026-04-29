// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP VTY interface.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 */

#include <zebra.h>

#ifdef GNU_LINUX
#include <linux/rtnetlink.h> //RT_TABLE_XXX
#endif

#include "command.h"
#include "lib/json.h"
#include "lib/sockopt.h"
#include "lib_errors.h"
#include "lib/zclient.h"
#include "lib/printfrr.h"
#include "prefix.h"
#include "plist.h"
#include "buffer.h"
#include "linklist.h"
#include "stream.h"
#include "frrevent.h"
#include "log.h"
#include "memory.h"
#include "lib_vty.h"
#include "hash.h"
#include "queue.h"
#include "filter.h"
#include "frrstr.h"
#include "asn.h"
#include "frregex_real.h"
#include "lib/northbound.h"
#include "lib/northbound_cli.h"
#include "lib/yang.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_filter_cli.h"
#include "bgpd/bgp_nb_helpers.h"
#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#endif

DEFINE_HOOK(bgp_inst_config_write,
		(struct bgp *bgp, struct vty *vty),
		(bgp, vty));
DEFINE_HOOK(bgp_snmp_update_last_changed, (struct bgp *bgp), (bgp));
DEFINE_HOOK(bgp_snmp_init_stats, (struct bgp *bgp), (bgp));
DEFINE_HOOK(bgp_snmp_traps_config_write, (struct vty * vty), (vty));
DEFINE_HOOK(bgp_route_distinguisher_update, (struct bgp *bgp, afi_t afi, bool preconfig),
	    (bgp, afi, preconfig));

/*
 * hook_call expands to a static helper in the TU that owns DEFINE_HOOK, so
 * other .c files (e.g. bgp_nb_config.c) can't invoke it directly. Export a
 * thin wrapper so NB callbacks can notify listeners (BMP) when an RD
 * changes.
 */
void bgp_route_distinguisher_update_notify(struct bgp *bgp, afi_t afi,
					   bool preconfig)
{
	hook_call(bgp_route_distinguisher_update, bgp, afi, preconfig);
}

/* Show BGP peer's information. */
enum show_type {
	show_all,
	show_peer,
	show_ipv4_all,
	show_ipv6_all,
	show_ipv4_peer,
	show_ipv6_peer
};

static void bgp_show_global_graceful_restart_mode_vty(struct vty *vty,
						      struct bgp *bgp);

static int bgp_show_neighbor_graceful_restart_afi_all(struct vty *vty, struct bgp *bgp,
						      enum show_type type, const char *ip_str,
						      afi_t afi, bool use_json);

static const char *get_afi_safi_vty_str(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP) {
		if (safi == SAFI_UNICAST)
			return "IPv4 Unicast";
		if (safi == SAFI_MULTICAST)
			return "IPv4 Multicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "IPv4 Labeled Unicast";
		if (safi == SAFI_MPLS_VPN)
			return "IPv4 VPN";
		if (safi == SAFI_ENCAP)
			return "IPv4 Encap";
		if (safi == SAFI_FLOWSPEC)
			return "IPv4 Flowspec";
	} else if (afi == AFI_IP6) {
		if (safi == SAFI_UNICAST)
			return "IPv6 Unicast";
		if (safi == SAFI_MULTICAST)
			return "IPv6 Multicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "IPv6 Labeled Unicast";
		if (safi == SAFI_MPLS_VPN)
			return "IPv6 VPN";
		if (safi == SAFI_ENCAP)
			return "IPv6 Encap";
		if (safi == SAFI_FLOWSPEC)
			return "IPv6 Flowspec";
	} else if (afi == AFI_L2VPN) {
		if (safi == SAFI_EVPN)
			return "L2VPN EVPN";
	} else if (afi == AFI_BGP_LS) {
		if (safi == SAFI_BGP_LS)
			return "Link-State";
	}

	return "Unknown";
}

/*
 * Please note that we have intentionally camelCased
 * the return strings here.  So if you want
 * to use this function, please ensure you
 * are doing this within json output
 */
static const char *get_afi_safi_json_str(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP) {
		if (safi == SAFI_UNICAST)
			return "ipv4Unicast";
		if (safi == SAFI_MULTICAST)
			return "ipv4Multicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "ipv4LabeledUnicast";
		if (safi == SAFI_MPLS_VPN)
			return "ipv4Vpn";
		if (safi == SAFI_ENCAP)
			return "ipv4Encap";
		if (safi == SAFI_FLOWSPEC)
			return "ipv4Flowspec";
	} else if (afi == AFI_IP6) {
		if (safi == SAFI_UNICAST)
			return "ipv6Unicast";
		if (safi == SAFI_MULTICAST)
			return "ipv6Multicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "ipv6LabeledUnicast";
		if (safi == SAFI_MPLS_VPN)
			return "ipv6Vpn";
		if (safi == SAFI_ENCAP)
			return "ipv6Encap";
		if (safi == SAFI_FLOWSPEC)
			return "ipv6Flowspec";
	} else if (afi == AFI_L2VPN) {
		if (safi == SAFI_EVPN)
			return "l2VpnEvpn";
	} else if (afi == AFI_BGP_LS) {
		if (safi == SAFI_BGP_LS)
			return "linkState";
	}

	return "Unknown";
}

/* unset srv6 locator */

/* Utility function to get address family from current node.  */
afi_t bgp_node_afi(struct vty *vty)
{
	afi_t afi;
	switch (vty->node) {
	case BGP_IPV6_NODE:
	case BGP_IPV6M_NODE:
	case BGP_IPV6L_NODE:
	case BGP_VPNV6_NODE:
	case BGP_FLOWSPECV6_NODE:
		afi = AFI_IP6;
		break;
	case BGP_EVPN_NODE:
		afi = AFI_L2VPN;
		break;
	default:
		afi = AFI_IP;
		break;
	}
	return afi;
}

/* Utility function to get subsequent address family from current
   node.  */
safi_t bgp_node_safi(struct vty *vty)
{
	safi_t safi;
	switch (vty->node) {
	case BGP_VPNV4_NODE:
	case BGP_VPNV6_NODE:
		safi = SAFI_MPLS_VPN;
		break;
	case BGP_IPV4M_NODE:
	case BGP_IPV6M_NODE:
		safi = SAFI_MULTICAST;
		break;
	case BGP_EVPN_NODE:
		safi = SAFI_EVPN;
		break;
	case BGP_IPV4L_NODE:
	case BGP_IPV6L_NODE:
		safi = SAFI_LABELED_UNICAST;
		break;
	case BGP_FLOWSPECV4_NODE:
	case BGP_FLOWSPECV6_NODE:
		safi = SAFI_FLOWSPEC;
		break;
	default:
		safi = SAFI_UNICAST;
		break;
	}
	return safi;
}

/**
 * Converts an AFI in string form to afi_t
 *
 * @param afi string, one of
 *  - "ipv4"
 *  - "ipv6"
 *  - "l2vpn"
 * @return the corresponding afi_t
 */
afi_t bgp_vty_afi_from_str(const char *afi_str)
{
	afi_t afi = AFI_MAX; /* unknown */
	if (strmatch(afi_str, "ipv4"))
		afi = AFI_IP;
	else if (strmatch(afi_str, "ipv6"))
		afi = AFI_IP6;
	else if (strmatch(afi_str, "l2vpn"))
		afi = AFI_L2VPN;
	return afi;
}

int argv_find_and_parse_afi(struct cmd_token **argv, int argc, int *index,
			    afi_t *afi)
{
	int ret = 0;
	if (argv_find(argv, argc, "ipv4", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP;
	} else if (argv_find(argv, argc, "ipv6", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP6;
	} else if (argv_find(argv, argc, "l2vpn", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_L2VPN;
	}
	return ret;
}

/* supports <unicast|multicast|vpn|labeled-unicast> */
safi_t bgp_vty_safi_from_str(const char *safi_str)
{
	safi_t safi = SAFI_MAX; /* unknown */
	if (strmatch(safi_str, "multicast"))
		safi = SAFI_MULTICAST;
	else if (strmatch(safi_str, "unicast"))
		safi = SAFI_UNICAST;
	else if (strmatch(safi_str, "vpn"))
		safi = SAFI_MPLS_VPN;
	else if (strmatch(safi_str, "evpn"))
		safi = SAFI_EVPN;
	else if (strmatch(safi_str, "labeled-unicast"))
		safi = SAFI_LABELED_UNICAST;
	else if (strmatch(safi_str, "flowspec"))
		safi = SAFI_FLOWSPEC;
	return safi;
}

int argv_find_and_parse_safi(struct cmd_token **argv, int argc, int *index,
			     safi_t *safi)
{
	int ret = 0;
	if (argv_find(argv, argc, "unicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_UNICAST;
	} else if (argv_find(argv, argc, "multicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_MULTICAST;
	} else if (argv_find(argv, argc, "labeled-unicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_LABELED_UNICAST;
	} else if (argv_find(argv, argc, "vpn", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_MPLS_VPN;
	} else if (argv_find(argv, argc, "evpn", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_EVPN;
	} else if (argv_find(argv, argc, "flowspec", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_FLOWSPEC;
	}
	return ret;
}

int bgp_get_vty(struct bgp **bgp, as_t *as, const char *name,
		enum bgp_instance_type inst_type, const char *as_pretty,
		enum asnotation_mode asnotation)
{
	return bgp_instance_create(bgp, as, name, inst_type, as_pretty,
				   asnotation);
}

/*
 * bgp_vty_find_and_parse_afi_safi_bgp
 *
 * For a given 'show ...' command, correctly parse the afi/safi/bgp out from it
 * This function *assumes* that the calling function pre-sets the afi/safi/bgp
 * to appropriate values for the calling function.  This is to allow the
 * calling function to make decisions appropriate for the show command
 * that is being parsed.
 *
 * The show commands are generally of the form:
 * "show [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6>
 * [<unicast|multicast|vpn|labeled-unicast>]] ..."
 *
 * Since we use argv_find if the show command in particular doesn't have:
 * [ip]
 * [<view|vrf> VIEWVRFNAME]
 * [<ipv4|ipv6> [<unicast|multicast|vpn|labeled-unicast>]]
 * The command parsing should still be ok.
 *
 * vty  -> The vty for the command so we can output some useful data in
 *         the event of a parse error in the vrf.
 * argv -> The command tokens
 * argc -> How many command tokens we have
 * idx  -> The current place in the command, generally should be 0 for this
 * function
 * afi  -> The parsed afi if it was included in the show command, returned here
 * safi -> The parsed safi if it was included in the show command, returned here
 * bgp  -> Pointer to the bgp data structure we need to fill in.
 * use_json -> json is configured or not
 *
 * The function returns the correct location in the parse tree for the
 * last token found.
 *
 * Returns 0 for failure to parse correctly, else the idx position of where
 * it found the last token.
 */
int bgp_vty_find_and_parse_afi_safi_bgp(struct vty *vty,
					struct cmd_token **argv, int argc,
					int *idx, afi_t *afi, safi_t *safi,
					struct bgp **bgp, bool use_json)
{
	char *vrf_name = NULL;

	assert(afi);
	assert(safi);
	assert(bgp);

	if (argv_find(argv, argc, "ip", idx))
		*afi = AFI_IP;

	if (argv_find(argv, argc, "view", idx))
		vrf_name = argv[*idx + 1]->arg;
	else if (argv_find(argv, argc, "vrf", idx)) {
		vrf_name = argv[*idx + 1]->arg;
		if (strmatch(vrf_name, VRF_DEFAULT_NAME))
			vrf_name = NULL;
	}
	if (vrf_name) {
		if (strmatch(vrf_name, "all"))
			*bgp = NULL;
		else {
			/*
			 * Explicit "show ... vrf NAME" must resolve the
			 * implied/auto-created VRF instances that EVPN creates
			 * via bgp_evpn_local_l3vni_add (e.g. bgp_evpn_rt5_implied
			 * test).  Prior refactor replaced the
			 * bgp_lookup_by_name_filter(..., false) call with the
			 * filter_auto=true wrapper, making explicit-name lookups
			 * return NULL for BGP_VRF_AUTO instances.  Mirror the
			 * baseline behavior: do not filter auto for an
			 * explicit-name show.
			 */
			*bgp = bgp_lookup_by_name_filter(vrf_name, false);
			if (!*bgp) {
				if (use_json) {
					json_object *json = NULL;
					json = json_object_new_object();
					json_object_string_add(
					  json, "warning",
					  "View/Vrf is unknown");
					vty_json(vty, json);
				}
				else
					vty_out(vty, "View/Vrf %s is unknown\n",
						vrf_name);
				*idx = 0;
				return 0;
			}
		}
	} else {
		*bgp = bgp_get_default();
		if (!*bgp) {
			if (use_json) {
				json_object *json = NULL;
				json = json_object_new_object();
				json_object_string_add(
					json, "warning",
					"Default BGP instance not found");
				vty_json(vty, json);
			}
			else
				vty_out(vty,
					"Default BGP instance not found\n");
			*idx = 0;
			return 0;
		}
	}

	if (argv_find_and_parse_afi(argv, argc, idx, afi))
		argv_find_and_parse_safi(argv, argc, idx, safi);

	*idx += 1;
	return *idx;
}

/* Utility function for looking up peer from VTY.  */

/* Utility function for looking up peer or peer group.  */
/* This is used only for configuration, so disallow if attempted on
 * a dynamic neighbor.
 */
struct peer *peer_and_group_lookup_vty(struct vty *vty, const char *peer_str)
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int ret;
	union sockunion su;
	struct peer *peer = NULL;
	struct peer_group *group = NULL;

	if (!bgp) {
		return NULL;
	}

	ret = str2sockunion(peer_str, &su);
	if (ret == 0) {
		/* IP address, locate peer. */
		peer = peer_lookup(bgp, &su);
	} else {
		/* Not IP, could match either peer configured on interface or a
		 * group. */
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (!peer)
			group = peer_group_lookup(bgp, peer_str);
	}

	if (peer) {
		if (peer_dynamic_neighbor(peer)) {
			zlog_warn(
				"%pBP: Operation not allowed on a dynamic neighbor",
				peer);
			vty_out(vty,
				"%% Operation not allowed on a dynamic neighbor\n");
			return NULL;
		}

		return peer;
	}

	if (group)
		return group->conf;

	zlog_warn("Specify remote-as or peer-group commands first before: %s",
		  vty->buf);
	vty_out(vty, "%% Specify remote-as or peer-group commands first\n");

	return NULL;
}

int bgp_vty_return(struct vty *vty, enum bgp_create_error_code ret)
{
	const char *str = NULL;

	switch (ret) {
	case BGP_SUCCESS:
	case BGP_CREATED:
	case BGP_INSTANCE_EXISTS:
	case BGP_GR_NO_OPERATION:
		break;
	case BGP_ERR_INVALID_VALUE:
		str = "Invalid value";
		break;
	case BGP_ERR_INVALID_FLAG:
		str = "Invalid flag";
		break;
	case BGP_ERR_PEER_GROUP_SHUTDOWN:
		str = "Peer-group has been shutdown. Activate the peer-group first";
		break;
	case BGP_ERR_PEER_FLAG_CONFLICT:
		str = "Can't set override-capability and strict-capability-match at the same time";
		break;
	case BGP_ERR_PEER_GROUP_NO_REMOTE_AS:
		str = "Specify remote-as or peer-group remote AS first";
		break;
	case BGP_ERR_PEER_GROUP_CANT_CHANGE:
		str = "Cannot change the peer-group. Deconfigure first";
		break;
	case BGP_ERR_PEER_GROUP_MISMATCH:
		str = "Peer is not a member of this peer-group";
		break;
	case BGP_ERR_PEER_FILTER_CONFLICT:
		str = "Prefix/distribute list can not co-exist";
		break;
	case BGP_ERR_NOT_INTERNAL_PEER:
		str = "Invalid command. Not an internal neighbor";
		break;
	case BGP_ERR_REMOVE_PRIVATE_AS:
		str = "remove-private-AS cannot be configured for IBGP peers";
		break;
	case BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS:
		str = "Cannot have local-as same as BGP AS number";
		break;
	case BGP_ERR_TCPSIG_FAILED:
		str = "Error while applying TCP-Sig to session(s)";
		break;
	case BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK:
		str = "ebgp-multihop and ttl-security cannot be configured together";
		break;
	case BGP_ERR_NO_IBGP_WITH_TTLHACK:
		str = "ttl-security only allowed for EBGP peers";
		break;
	case BGP_ERR_AS_OVERRIDE:
		str = "as-override cannot be configured for IBGP peers";
		break;
	case BGP_ERR_INVALID_DYNAMIC_NEIGHBORS_LIMIT:
		str = "Invalid limit for number of dynamic neighbors";
		break;
	case BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_EXISTS:
		str = "Dynamic neighbor listen range already exists";
		break;
	case BGP_ERR_INVALID_FOR_DYNAMIC_PEER:
		str = "Operation not allowed on a dynamic neighbor";
		break;
	case BGP_ERR_INVALID_FOR_DIRECT_PEER:
		str = "Operation not allowed on a directly connected neighbor";
		break;
	case BGP_ERR_PEER_SAFI_CONFLICT:
		str = "Cannot activate peer for both 'ipv4 unicast' and 'ipv4 labeled-unicast'";
		break;
	case BGP_ERR_GR_INVALID_CMD:
		str = "The Graceful Restart command used is not valid at this moment.";
		break;
	case BGP_ERR_GR_OPERATION_FAILED:
		str = "The Graceful Restart Operation failed due to an err.";
		break;
	case BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_NOT_FOUND:
		str = "Range specified cannot be deleted because it is not part of current config.";
		break;
	case BGP_ERR_INSTANCE_MISMATCH:
		str = "Instance specified does not match the current instance.";
		break;
	case BGP_ERR_NO_INTERFACE_CONFIG:
		str = "Interface specified is not being used for interface based peer.";
		break;
	case BGP_ERR_SOFT_RECONFIG_UNCONFIGURED:
		str = "No configuration already specified for soft reconfiguration.";
		break;
	case BGP_ERR_AS_MISMATCH:
		str = "BGP is already running.";
		break;
	case BGP_ERR_AF_UNCONFIGURED:
		str = "AFI/SAFI specified is not currently configured.";
		break;
	case BGP_ERR_INVALID_AS:
		str = "Confederation AS specified is the same AS as our AS.";
		break;
	case BGP_ERR_INVALID_ROLE_NAME:
		str = "Invalid role name";
		break;
	case BGP_ERR_INVALID_INTERNAL_ROLE:
		str = "External roles can be set only on eBGP session";
		break;
	}
	if (str) {
		vty_out(vty, "%% %s\n", str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

/* BGP clear sort. */
enum clear_sort {
	clear_all,
	clear_peer,
	clear_group,
	clear_external,
	clear_as
};

static void bgp_clear_vty_error(struct vty *vty, struct peer *peer, afi_t afi,
				safi_t safi, int error)
{
	switch (error) {
	case BGP_ERR_AF_UNCONFIGURED:
		if (vty)
			vty_out(vty,
				"%% BGP: Enable %s address family for the neighbor %s\n",
				get_afi_safi_str(afi, safi, false), peer->host);
		else
			zlog_warn(
				"%% BGP: Enable %s address family for the neighbor %s",
				get_afi_safi_str(afi, safi, false), peer->host);
		break;
	case BGP_ERR_SOFT_RECONFIG_UNCONFIGURED:
		if (vty)
			vty_out(vty,
				"%% BGP: Inbound soft reconfig for %s not possible as it\n      has neither refresh capability, nor inbound soft reconfig\n",
				peer->host);
		else
			zlog_warn(
				"%% BGP: Inbound soft reconfig for %s not possible as it has neither refresh capability, nor inbound soft reconfig",
				peer->host);
		break;
	default:
		break;
	}
}

static int bgp_peer_clear(struct peer *peer, afi_t afi, safi_t safi,
			  struct listnode **nnode, enum bgp_clear_type stype)
{
	int ret = 0;
	struct peer_af *paf;

	/* if afi/.safi not specified, spin thru all of them */
	if ((afi == AFI_UNSPEC) && (safi == SAFI_UNSPEC)) {
		afi_t tmp_afi;
		safi_t tmp_safi;
		enum bgp_af_index index;

		for (index = BGP_AF_START; index < BGP_AF_MAX; index++) {
			paf = peer->peer_af_array[index];
			if (!paf)
				continue;

			if (paf && paf->subgroup)
				SET_FLAG(paf->subgroup->sflags,
					 SUBGRP_STATUS_FORCE_UPDATES);

			tmp_afi = paf->afi;
			tmp_safi = paf->safi;
			if (!peer->afc[tmp_afi][tmp_safi])
				continue;

			if (stype == BGP_CLEAR_SOFT_NONE)
				ret = peer_clear(peer, nnode);
			else
				ret = peer_clear_soft(peer, tmp_afi, tmp_safi,
						      stype);
		}
	/* if afi specified and safi not, spin thru safis on this afi */
	} else if (safi == SAFI_UNSPEC) {
		safi_t tmp_safi;

		for (tmp_safi = SAFI_UNICAST;
		     tmp_safi < SAFI_MAX; tmp_safi++) {
			if (!peer->afc[afi][tmp_safi])
				continue;

			paf = peer_af_find(peer, afi, tmp_safi);
			if (paf && paf->subgroup)
				SET_FLAG(paf->subgroup->sflags,
					 SUBGRP_STATUS_FORCE_UPDATES);

			if (stype == BGP_CLEAR_SOFT_NONE)
				ret = peer_clear(peer, nnode);
			else
				ret = peer_clear_soft(peer, afi,
						      tmp_safi, stype);
		}
	/* both afi/safi specified, let the caller know if not defined */
	} else {
		if (!peer->afc[afi][safi])
			return 1;

		paf = peer_af_find(peer, afi, safi);
		if (paf && paf->subgroup)
			SET_FLAG(paf->subgroup->sflags,
				 SUBGRP_STATUS_FORCE_UPDATES);

		if (stype == BGP_CLEAR_SOFT_NONE)
			ret = peer_clear(peer, nnode);
		else
			ret = peer_clear_soft(peer, afi, safi, stype);
	}

	return ret;
}

/* `clear ip bgp' functions. */
static int bgp_clear(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
		     enum clear_sort sort, enum bgp_clear_type stype,
		     const char *arg)
{
	int ret = 0;
	bool found = false;
	struct peer *peer;
	bool afi_safi_unspec = false;

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	afi_safi_unspec = ((afi == AFI_UNSPEC) && (safi == SAFI_UNSPEC));

	/* Clear all neighbors. */
	/*
	 * Pass along pointer to next node to peer_clear() when walking all
	 * nodes on the BGP instance as that may get freed if it is a
	 * doppelganger
	 */
	if (sort == clear_all) {
		if (afi_safi_unspec)
			bgp_clearing_batch_begin(bgp);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {

			bgp_peer_gr_flags_update(peer);

			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				gr_router_detected = true;

			ret = bgp_peer_clear(peer, afi, safi, &nnode,
							  stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
		}

		if (gr_router_detected
		    && bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {
			bgp_zebra_send_capabilities(bgp, false);
		} else if (!gr_router_detected
			   && bgp->present_zebra_gr_state == ZEBRA_GR_ENABLE) {
			bgp_zebra_send_capabilities(bgp, true);
		}

		/* This is to apply read-only mode on this clear. */
		if (stype == BGP_CLEAR_SOFT_NONE) {
			bgp->update_delay_over = 0;
			event_cancel(&bgp->t_advertisement_delay);
			bgp->advertisement_delay_started = 0;
			bgp->advertisement_delay_over = 0;
		}

		if (afi_safi_unspec)
			bgp_clearing_batch_end_event_start(bgp);
		return CMD_SUCCESS;
	}

	/* Clear specified neighbor. */
	if (sort == clear_peer) {
		union sockunion su;

		/* Make sockunion for lookup. */
		ret = str2sockunion(arg, &su);
		if (ret < 0) {
			peer = peer_lookup_by_conf_if(bgp, arg);
			if (!peer) {
				peer = peer_lookup_by_hostname(bgp, arg);
				if (!peer) {
					vty_out(vty,
						"Malformed address or name: %s\n",
						arg);
					return CMD_WARNING;
				}
			}
		} else {
			peer = peer_lookup(bgp, &su);
			if (!peer) {
				vty_out(vty,
					"%% BGP: Unknown neighbor - \"%s\"\n",
					arg);
				return CMD_WARNING;
			}
		}

		VTY_BGP_GR_ROUTER_DETECT(bgp, peer, peer->bgp->peer);
		VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(peer->bgp, ret);

		ret = bgp_peer_clear(peer, afi, safi, NULL, stype);

		/* if afi/safi not defined for this peer, let caller know */
		if (ret == 1)
			ret = BGP_ERR_AF_UNCONFIGURED;

		if (ret < 0)
			bgp_clear_vty_error(vty, peer, afi, safi, ret);

		return CMD_SUCCESS;
	}

	/* Clear all neighbors belonging to a specific peer-group. */
	if (sort == clear_group) {
		struct peer_group *group;

		group = peer_group_lookup(bgp, arg);
		if (!group) {
			vty_out(vty, "%% BGP: No such peer-group %s\n", arg);
			return CMD_WARNING;
		}

		if (afi_safi_unspec)
			bgp_clearing_batch_begin(bgp);
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			ret = bgp_peer_clear(peer, afi, safi, &nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}
		if (afi_safi_unspec)
			bgp_clearing_batch_end_event_start(bgp);

		if (!found)
			vty_out(vty,
				"%% BGP: No %s peer belonging to peer-group %s is configured\n",
				get_afi_safi_str(afi, safi, false), arg);

		return CMD_SUCCESS;
	}

	/* Clear all external (eBGP) neighbors. */
	if (sort == clear_external) {
		if (afi_safi_unspec)
			bgp_clearing_batch_begin(bgp);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->sort == BGP_PEER_IBGP)
				continue;

			bgp_peer_gr_flags_update(peer);

			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				gr_router_detected = true;

			ret = bgp_peer_clear(peer, afi, safi, &nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}

		if (gr_router_detected
		    && bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {
			bgp_zebra_send_capabilities(bgp, false);
		} else if (!gr_router_detected
			   && bgp->present_zebra_gr_state == ZEBRA_GR_ENABLE) {
			bgp_zebra_send_capabilities(bgp, true);
		}
		if (afi_safi_unspec)
			bgp_clearing_batch_end_event_start(bgp);
		if (!found)
			vty_out(vty,
				"%% BGP: No external %s peer is configured\n",
				get_afi_safi_str(afi, safi, false));

		return CMD_SUCCESS;
	}

	/* Clear all neighbors belonging to a specific AS. */
	if (sort == clear_as) {
		as_t as;

		if (!asn_str2asn(arg, &as)) {
			vty_out(vty, "%% BGP: No such AS %s\n", arg);
			return CMD_WARNING;
		}

		if (afi_safi_unspec)
			bgp_clearing_batch_begin(bgp);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->as != as)
				continue;

			bgp_peer_gr_flags_update(peer);

			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				gr_router_detected = true;

			ret = bgp_peer_clear(peer, afi, safi, &nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}

		if (gr_router_detected
		    && bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {
			bgp_zebra_send_capabilities(bgp, false);
		} else if (!gr_router_detected
			   && bgp->present_zebra_gr_state == ZEBRA_GR_ENABLE) {
			bgp_zebra_send_capabilities(bgp, true);
		}

		if (afi_safi_unspec)
			bgp_clearing_batch_end_event_start(bgp);
		if (!found)
			vty_out(vty,
				"%% BGP: No %s peer is configured with AS %s\n",
				get_afi_safi_str(afi, safi, false), arg);

		return CMD_SUCCESS;
	}

	return CMD_SUCCESS;
}

static int bgp_clear_vty(struct vty *vty, const char *name, afi_t afi,
			 safi_t safi, enum clear_sort sort,
			 enum bgp_clear_type stype, const char *arg)
{
	struct bgp *bgp;

	/* BGP structure lookup. */
	if (name) {
		bgp = bgp_lookup_by_name(name);
		if (bgp == NULL) {
			vty_out(vty, "Can't find BGP instance %s\n", name);
			return CMD_WARNING;
		}
	} else {
		bgp = bgp_get_default();
		if (bgp == NULL) {
			vty_out(vty, "No BGP process is configured\n");
			return CMD_WARNING;
		}
	}

	return bgp_clear(vty, bgp, afi, safi, sort, stype, arg);
}

/* clear soft inbound */
void bgp_clear_star_soft_in(struct vty *vty, const char *name)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_vty(vty, name, afi, safi, clear_all,
			      BGP_CLEAR_SOFT_IN, NULL);
}

/* clear soft outbound */
void bgp_clear_star_soft_out(struct vty *vty, const char *name)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_vty(vty, name, afi, safi, clear_all,
			      BGP_CLEAR_SOFT_OUT, NULL);
}

void bgp_clear_soft_in(struct bgp *bgp, afi_t afi, safi_t safi)
{
	bgp_clear(NULL, bgp, afi, safi, clear_all, BGP_CLEAR_SOFT_IN, NULL);
}

static int peer_flag_modify_vty(struct vty *vty, const char *ip_str,
				uint64_t flag, int set)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * If 'neighbor <interface>', then this is for directly connected peers,
	 * we should not accept disable-connected-check.
	 */
	if (peer->conf_if && (flag == PEER_FLAG_DISABLE_CONNECTED_CHECK)) {
		vty_out(vty,
			"%s is directly connected peer, cannot accept disable-connected-check\n",
			ip_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!set && flag == PEER_FLAG_SHUTDOWN)
		peer_tx_shutdown_message_unset(peer);

	if (set)
		ret = peer_flag_set(peer, flag);
	else
		ret = peer_flag_unset(peer, flag);

	return bgp_vty_return(vty, ret);
}

static int peer_flag_set_vty(struct vty *vty, const char *ip_str, uint64_t flag)
{
	return peer_flag_modify_vty(vty, ip_str, flag, 1);
}

static int peer_flag_unset_vty(struct vty *vty, const char *ip_str,
			       uint64_t flag)
{
	return peer_flag_modify_vty(vty, ip_str, flag, 0);
}

#include "bgpd/bgp_vty_clippy.c"

DEFUN_HIDDEN (bgp_local_mac,
              bgp_local_mac_cmd,
              "bgp local-mac vni " CMD_VNI_RANGE " mac WORD seq (0-4294967295)",
              BGP_STR
              "Local MAC config\n"
              "VxLAN Network Identifier\n"
              "VNI number\n"
              "local mac\n"
              "mac address\n"
              "mac-mobility sequence\n"
              "seq number\n")
{
	int rv;
	vni_t vni;
	struct ethaddr mac;
	struct ipaddr ip;
	uint32_t seq;
	struct bgp *bgp;

	vni = strtoul(argv[3]->arg, NULL, 10);
	if (!prefix_str2mac(argv[5]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address\n");
		return CMD_WARNING;
	}
	memset(&ip, 0, sizeof(ip));
	seq = strtoul(argv[7]->arg, NULL, 10);

	bgp = bgp_get_default();
	if (!bgp || IS_BGP_INSTANCE_HIDDEN(bgp)) {
		vty_out(vty, "Default BGP instance is not there\n");
		return CMD_WARNING;
	}

	rv = bgp_evpn_local_macip_add(bgp, vni, &mac, &ip, 0 /* flags */, seq,
			zero_esi);
	if (rv < 0) {
		vty_out(vty, "Internal error\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_bgp_local_mac,
              no_bgp_local_mac_cmd,
              "no bgp local-mac vni " CMD_VNI_RANGE " mac WORD",
              NO_STR
              BGP_STR
              "Local MAC config\n"
              "VxLAN Network Identifier\n"
              "VNI number\n"
              "local mac\n"
              "mac address\n")
{
	int rv;
	vni_t vni;
	struct ethaddr mac;
	struct ipaddr ip;
	struct bgp *bgp;

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!prefix_str2mac(argv[6]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address\n");
		return CMD_WARNING;
	}
	memset(&ip, 0, sizeof(ip));

	bgp = bgp_get_default();
	if (!bgp || IS_BGP_INSTANCE_HIDDEN(bgp)) {
		vty_out(vty, "Default BGP instance is not there\n");
		return CMD_WARNING;
	}

	rv = bgp_evpn_local_macip_del(bgp, vni, &mac, &ip, ZEBRA_NEIGH_ACTIVE);
	if (rv < 0) {
		vty_out(vty, "Internal error\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* "router bgp" commands. */

/* "no router bgp" commands. */

/* bgp session-dscp */

/* BGP router-id.  */

/* bgp_community_alias_cmd removed - using bgp_community_alias_cli_cmd from bgp_cli.c */

/* BGP Cluster ID.  */

DEFPY (bgp_norib,
       bgp_norib_cmd,
       "bgp no-rib",
       BGP_STR
       "Disable BGP route installation to RIB (Zebra)\n")
{
	if (bgp_option_check(BGP_OPT_NO_FIB)) {
		vty_out(vty,
			"%% No-RIB option is already set, nothing to do here.\n");
		return CMD_SUCCESS;
	}

	bgp_option_norib_set_runtime();

	return CMD_SUCCESS;
}

DEFPY (no_bgp_norib,
       no_bgp_norib_cmd,
       "no bgp no-rib",
       NO_STR
       BGP_STR
       "Disable BGP route installation to RIB (Zebra)\n")
{
	if (!bgp_option_check(BGP_OPT_NO_FIB)) {
		vty_out(vty,
			"%% No-RIB option is not set, nothing to do here.\n");
		return CMD_SUCCESS;
	}

	bgp_option_norib_unset_runtime();

	return CMD_SUCCESS;
}

/**
 * Central routine for maximum-paths configuration.
 * @peer_type: BGP_PEER_EBGP or BGP_PEER_IBGP
 * @set: 1 for setting values, 0 for removing the max-paths config.
 */

void bgp_config_write_update_delay(struct vty *vty, struct bgp *bgp)
{
	/* If configured globally, no need to display per-instance value */
	if (bgp->v_update_delay != bm->v_update_delay) {
		vty_out(vty, " update-delay %d", bgp->v_update_delay);
		if (bgp->v_update_delay != bgp->v_establish_wait)
			vty_out(vty, " %d", bgp->v_establish_wait);
		vty_out(vty, "\n");
	}
}

/* Global update-delay configuration */

/* Global update-delay deconfiguration */

/* Update-delay configuration */

/* Update-delay deconfiguration */

void bgp_config_write_wpkt_quanta(struct vty *vty, struct bgp *bgp)
{
	uint32_t quanta =
		atomic_load_explicit(&bgp->wpkt_quanta, memory_order_relaxed);
	if (quanta != BGP_WRITE_PACKET_MAX)
		vty_out(vty, " write-quanta %d\n", quanta);
}

void bgp_config_write_rpkt_quanta(struct vty *vty, struct bgp *bgp)
{
	uint32_t quanta =
		atomic_load_explicit(&bgp->rpkt_quanta, memory_order_relaxed);
	if (quanta != BGP_READ_PACKET_MAX)
		vty_out(vty, " read-quanta %d\n", quanta);
}

/* Packet quanta configuration
 *
 * XXX: The value set here controls the size of a stack buffer in the IO
 * thread. When changing these limits be careful to prevent stack overflow.
 *
 * Furthermore, the maximums used here should correspond to
 * BGP_WRITE_PACKET_MAX and BGP_READ_PACKET_MAX.
 */

void bgp_config_write_coalesce_time(struct vty *vty, struct bgp *bgp)
{
	if (!bgp->heuristic_coalesce)
		vty_out(vty, " coalesce-time %u\n", bgp->coalesce_time);
}


/* Maximum-paths configuration */

/* BGP timers.  */

/* BGP minimum holdtime.  */

/* "bgp always-compare-med" configuration. */

DEFPY(bgp_lu_uses_explicit_null, bgp_lu_uses_explicit_null_cmd,
      "[no] bgp labeled-unicast <explicit-null|ipv4-explicit-null|ipv6-explicit-null>$value",
      NO_STR BGP_STR
      "BGP Labeled-unicast options\n"
      "Use explicit-null label values for all local prefixes\n"
      "Use the IPv4 explicit-null label value for IPv4 local prefixes\n"
      "Use the IPv6 explicit-null label value for IPv6 local prefixes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint64_t label_mode;

	if (strmatch(value, "ipv4-explicit-null"))
		label_mode = BGP_FLAG_LU_IPV4_EXPLICIT_NULL;
	else if (strmatch(value, "ipv6-explicit-null"))
		label_mode = BGP_FLAG_LU_IPV6_EXPLICIT_NULL;
	else
		label_mode = BGP_FLAG_LU_IPV4_EXPLICIT_NULL |
			     BGP_FLAG_LU_IPV6_EXPLICIT_NULL;
	if (no)
		UNSET_FLAG(bgp->flags, label_mode);
	else
		SET_FLAG(bgp->flags, label_mode);
	return CMD_SUCCESS;
}


/* "bgp graceful-restart mode" configuration. */

DEFPY (bgp_administrative_reset,
	bgp_administrative_reset_cmd,
	"[no$no] bgp hard-administrative-reset",
	NO_STR
	BGP_STR
	"Send Hard Reset CEASE Notification for 'Administrative Reset'\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (no)
		UNSET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);

	return CMD_SUCCESS;
}

/*
 * Function to announce route to peer
 */

/*
 * Function to perform a soft reset of BGP neighborship on a peer or peer group
 */

static inline void bgp_initiate_graceful_shut_unshut(struct vty *vty,
						     struct bgp *bgp)
{
	bgp_static_redo_import_check(bgp);
	bgp_redistribute_redo(bgp);
	bgp_clear_star_soft_out(vty, bgp->name);
	bgp_clear_star_soft_in(vty, bgp->name);
}



/* "bgp graceful-shutdown" configuration */

/* "bgp fast-external-failover" configuration. */

/* "bgp bestpath compare-routerid" configuration.  */

/* "bgp bestpath as-path ignore" configuration.  */

/* "bgp bestpath as-path confed" configuration.  */

/* "bgp bestpath as-path multipath-relax" configuration.  */

/* "bgp bestpath peer-type multipath-relax" configuration. */

/* "bgp log-neighbor-changes" configuration.  */

/* "bgp bestpath med" configuration. */

/* "bgp bestpath bandwidth" configuration. */

/* Display hostname in certain command outputs */

/* Display hostname in certain command outputs */

/* "bgp network import-check" configuration.  */

void bgp_config_write_listen(struct vty *vty, struct bgp *bgp)
{
	struct peer_group *group;
	struct listnode *node, *nnode, *rnode, *nrnode;
	struct prefix *range;
	afi_t afi;

	if (bgp->dynamic_neighbors_limit != BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT)
		vty_out(vty, " bgp listen limit %d\n",
			bgp->dynamic_neighbors_limit);

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			for (ALL_LIST_ELEMENTS(group->listen_range[afi], rnode,
					       nrnode, range)) {
				vty_out(vty,
					" bgp listen range %pFX peer-group %s\n",
					range, group->name);
			}
		}
	}
}

/* Enable fast convergence of bgp sessions. If this is enabled, bgp
 * sessions do not wait for hold timer expiry to bring down the sessions
 * when nexthop becomes unreachable
 */

/* neighbor passive. */

/* neighbor shutdown. */

/* neighbor capability dynamic. */

/* neighbor dont-capability-negotiate */

/* neighbor capability fqdn */

/* neighbor capability extended next hop encoding */

/* neighbor capability software-version */

/* neighbor capability link-local */

static int peer_af_flag_modify_vty(struct vty *vty, const char *peer_str,
				   afi_t afi, safi_t safi, uint64_t flag,
				   int set)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (set)
		ret = peer_af_flag_set(peer, afi, safi, flag);
	else
		ret = peer_af_flag_unset(peer, afi, safi, flag);

	return bgp_vty_return(vty, ret);
}

static int peer_af_flag_set_vty(struct vty *vty, const char *peer_str,
				afi_t afi, safi_t safi, uint64_t flag)
{
	return peer_af_flag_modify_vty(vty, peer_str, afi, safi, flag, 1);
}

static int peer_af_flag_unset_vty(struct vty *vty, const char *peer_str,
				  afi_t afi, safi_t safi, uint64_t flag)
{
	return peer_af_flag_modify_vty(vty, peer_str, afi, safi, flag, 0);
}

/* neighbor capability orf prefix-list. */

/* neighbor next-hop-self. */

/* neighbor next-hop-self. */

/* neighbor as-override */

/* neighbor remove-private-AS. */

/* neighbor send-community. */

/* neighbor send-community extended. */

DEFPY (neighbor_ecommunity_rpki,
       neighbor_ecommunity_rpki_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor send-community extended rpki",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Extended Community attributes\n"
       "Send RPKI Extended Community attributes\n")
{
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		return peer_af_flag_unset_vty(vty, neighbor, afi, safi,
					      PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
	else
		return peer_af_flag_set_vty(vty, neighbor, afi, safi,
					    PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
}

/* neighbor soft-reconfig. */

/* neighbor route-server-client. */

/* EBGP multihop configuration. */

/* neighbor ebgp-multihop. */

/* disable-connected-check */

DEFPY(neighbor_nhc_attribute,
      neighbor_nhc_attribute_cmd,
      "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor send-nexthop-characteristics",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Send BGP Next Hop Dependent Characteristics Attribute\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		return peer_flag_unset_vty(vty, neighbor, PEER_FLAG_SEND_NHC_ATTRIBUTE);

	return peer_flag_set_vty(vty, neighbor, PEER_FLAG_SEND_NHC_ATTRIBUTE);
}

/* disable-link-bw-encoding-ieee */

/* extended-optional-parameters */

/* enforce-first-as */

#define BGP_UPDATE_SOURCE_HELP_STR                                             \
	"IPv4 address\n"                                                       \
	"IPv6 address\n"                                                       \
	"Interface name (requires zebra to be running)\n"

/* neighbor default-originate. */

/* Set specified peer's BGP port.  */

/* Time to wait before processing route-map updates */
DEFUN (bgp_set_route_map_delay_timer,
       bgp_set_route_map_delay_timer_cmd,
       "bgp route-map delay-timer (0-600)",
       SET_STR
       "BGP route-map delay timer\n"
       "Time in secs to wait before processing route-map changes\n"
       "0 disables the timer, no route updates happen when route-maps change\n")
{
	int idx_number = 3;
	uint32_t rmap_delay_timer;

	if (argv[idx_number]->arg) {
		rmap_delay_timer = strtoul(argv[idx_number]->arg, NULL, 10);
		bm->rmap_update_timer = rmap_delay_timer;

		/* if the dynamic update handling is being disabled, and a timer
		 * is
		 * running, stop the timer and act as if the timer has already
		 * fired.
		 */
		if (!rmap_delay_timer && bm->t_rmap_update) {
			event_cancel(&bm->t_rmap_update);
			event_execute(bm->master, bgp_route_map_update_timer,
				      NULL, 0, NULL);
		}
		return CMD_SUCCESS;
	} else {
		vty_out(vty, "%% BGP invalid route-map delay-timer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
}

DEFUN (no_bgp_set_route_map_delay_timer,
       no_bgp_set_route_map_delay_timer_cmd,
       "no bgp route-map delay-timer [(0-600)]",
       NO_STR
       BGP_STR
       "Default BGP route-map delay timer\n"
       "Reset to default time to wait for processing route-map changes\n"
       "0 disables the timer, no route updates happen when route-maps change\n")
{

	bm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;

	return CMD_SUCCESS;
}

/* Set advertise-map to the peer. */

/* Maximum number of prefix to be sent to the neighbor. */

/* Maximum number of prefix configuration. Prefix count is different
   for each peer configuration. So this configuration can be set for
   each peer configuration. */

/* "neighbor accept-own" */

/* "neighbor soo" */

/* "neighbor allowas-in" */

/* disable-addpath-rx */

DEFPY(
	neighbor_aspath_loop_detection, neighbor_aspath_loop_detection_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor sender-as-path-loop-detection",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Detect AS loops before sending to neighbor\n")
{
	return peer_flag_set_vty(vty, neighbor, PEER_FLAG_AS_LOOP_DETECTION);
}

DEFPY(
	no_neighbor_aspath_loop_detection,
	no_neighbor_aspath_loop_detection_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor sender-as-path-loop-detection",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Detect AS loops before sending to neighbor\n")
{
	return peer_flag_unset_vty(vty, neighbor, PEER_FLAG_AS_LOOP_DETECTION);
}

DEFPY (show_ip_bgp_neighbor_damp_param,
       show_ip_bgp_neighbor_damp_param_cmd,
       "show [ip] bgp [<ipv4|ipv6> [unicast]] neighbors <A.B.C.D|X:X::X:X|WORD>$neighbor dampening parameters [json]$json",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_AFI_HELP_STR
       "Address Family modifier\n"
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor route-flap dampening information\n"
       "Display detail of configured dampening parameters\n"
       JSON_STR)
{
	bool use_json = false;
	int idx = 0;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;
	struct peer *peer;

	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	if (argv_find(argv, argc, "ipv4", &idx))
		afi = AFI_IP;
	if (argv_find(argv, argc, "ipv6", &idx))
		afi = AFI_IP6;
	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING;
	if (json)
		use_json = true;
	bgp_show_peer_dampening_parameters(vty, peer, afi, safi, use_json);
	return CMD_SUCCESS;
}

/*
 * v2vimport is true if we are handling a `import vrf ...` command
 */
static __attribute__((unused)) afi_t vpn_policy_getafi(struct vty *vty, struct bgp *bgp, bool v2vimport)
{
	afi_t afi;

	switch (vty->node) {
	case BGP_IPV4_NODE:
		afi = AFI_IP;
		break;
	case BGP_IPV6_NODE:
		afi = AFI_IP6;
		break;
	default:
		vty_out(vty,
			"%% context error: valid only in address-family <ipv4|ipv6> unicast block\n");
		return AFI_MAX;
	}

	if (!v2vimport) {
		if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT)
		    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
				  BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			vty_out(vty,
				"%% error: Please unconfigure import vrf commands before using vpn commands\n");
			return AFI_MAX;
		}
	} else {
		if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT)
		    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
				  BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT)) {
			vty_out(vty,
				"%% error: Please unconfigure vpn to vrf commands before using import vrf commands\n");
			return AFI_MAX;
		}
	}
	return afi;
}

/* af_no_import_vrf_route_map_cmd removed - using af_import_vrf_route_map_cli_cmd from bgp_cli.c */
/* bgp_imexport_vpn_cmd removed - using af_import_export_vpn_cli_cmd from bgp_cli.c */

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN_NOSH (address_family_vpnv4,
       address_family_vpnv4_cmd,
       "address-family vpnv4 [unicast]",
       "Enter Address Family command mode\n"
       BGP_AF_STR
       BGP_AF_MODIFIER_STR)
{
	vty->node = BGP_VPNV4_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (address_family_vpnv6,
       address_family_vpnv6_cmd,
       "address-family vpnv6 [unicast]",
       "Enter Address Family command mode\n"
       BGP_AF_STR
       BGP_AF_MODIFIER_STR)
{
	vty->node = BGP_VPNV6_NODE;
	return CMD_SUCCESS;
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFPY (show_bgp_srv6,
       show_bgp_srv6_cmd,
       "show bgp segment-routing srv6",
       SHOW_STR
       BGP_STR
       "BGP Segment Routing\n"
       "BGP Segment Routing SRv6\n")
{
	struct bgp *bgp;
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	struct bgp_srv6_function *func;

	bgp = bgp_get_default();
	if (!bgp)
		return CMD_SUCCESS;

	vty_out(vty, "locator_name: %s\n", bgp->srv6_locator_name);
	if (bgp->srv6_locator) {
		vty_out(vty, "  prefix: %pFX\n", &bgp->srv6_locator->prefix);
		vty_out(vty, "  block-length: %d\n",
			bgp->srv6_locator->block_bits_length);
		vty_out(vty, "  node-length: %d\n",
			bgp->srv6_locator->node_bits_length);
		vty_out(vty, "  func-length: %d\n",
			bgp->srv6_locator->function_bits_length);
		vty_out(vty, "  arg-length: %d\n",
			bgp->srv6_locator->argument_bits_length);
	}
	vty_out(vty, "locator_chunks:\n");
	for (ALL_LIST_ELEMENTS_RO(bgp->srv6_locator_chunks, node, chunk)) {
		vty_out(vty, "- %pFX\n", &chunk->prefix);
		vty_out(vty, "  block-length: %d\n", chunk->block_bits_length);
		vty_out(vty, "  node-length: %d\n", chunk->node_bits_length);
		vty_out(vty, "  func-length: %d\n",
			chunk->function_bits_length);
		vty_out(vty, "  arg-length: %d\n", chunk->argument_bits_length);
	}

	vty_out(vty, "functions:\n");
	for (ALL_LIST_ELEMENTS_RO(bgp->srv6_functions, node, func)) {
		vty_out(vty, "- sid: %pI6\n", &func->sid);
		vty_out(vty, "  locator: %s\n", func->locator_name);
	}

	vty_out(vty, "bgps:\n");
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		vty_out(vty, "- name: %s\n",
			bgp->name ? bgp->name : "default");

		vty_out(vty, "  vpn_policy[AFI_IP].tovpn_sid: %pI6\n",
			bgp->vpn_policy[AFI_IP].tovpn_sid);
		vty_out(vty, "  vpn_policy[AFI_IP6].tovpn_sid: %pI6\n",
			bgp->vpn_policy[AFI_IP6].tovpn_sid);
		vty_out(vty, "  per-vrf tovpn_sid: %pI6\n", bgp->tovpn_sid);
		vty_out(vty, "  srv6_unicast[AFI_IP].sid: %pI6\n",
			bgp->srv6_unicast[AFI_IP].sid);
		vty_out(vty, "  srv6_unicast[AFI_IP6].sid: %pI6\n",
			bgp->srv6_unicast[AFI_IP6].sid);
	}

	return CMD_SUCCESS;
}

/* Recalculate bestpath and re-advertise a prefix */
static int bgp_clear_prefix(struct vty *vty, const char *view_name,
			    const char *ip_str, afi_t afi, safi_t safi,
			    struct prefix_rd *prd)
{
	int ret;
	struct prefix match;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_table *rib;

	/* BGP structure lookup. */
	if (view_name) {
		bgp = bgp_lookup_by_name(view_name);
		if (bgp == NULL) {
			vty_out(vty, "%% Can't find BGP instance %s\n",
				view_name);
			return CMD_WARNING;
		}
	} else {
		bgp = bgp_get_default();
		if (bgp == NULL) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING;
		}
	}

	/* Check IP address argument. */
	ret = str2prefix(ip_str, &match);
	if (!ret) {
		vty_out(vty, "%% address is malformed\n");
		return CMD_WARNING;
	}

	rib = bgp->rib[afi][safi];

	if (safi == SAFI_MPLS_VPN) {
		for (dest = bgp_table_top(rib); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (prd && memcmp(dest_p->u.val, prd->val, 8) != 0)
				continue;

			table = bgp_dest_get_bgp_table_info(dest);
			if (table == NULL)
				continue;

			rm = bgp_node_match(table, &match);
			if (rm != NULL) {
				const struct prefix *rm_p =
					bgp_dest_get_prefix(rm);

				if (rm_p->prefixlen == match.prefixlen) {
					SET_FLAG(rm->flags,
						 BGP_NODE_USER_CLEAR);
					bgp_process(bgp, rm,
						    bgp_dest_get_bgp_path_info(
							    rm),
						    afi, safi);
				}
				bgp_dest_unlock_node(rm);
			}
		}
	} else {
		dest = bgp_node_match(rib, &match);
		if (dest != NULL) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (dest_p->prefixlen == match.prefixlen) {
				SET_FLAG(dest->flags, BGP_NODE_USER_CLEAR);
				bgp_process(bgp, dest,
					    bgp_dest_get_bgp_path_info(dest),
					    afi, safi);
			}
			bgp_dest_unlock_node(dest);
		}
	}

	return CMD_SUCCESS;
}

/* one clear bgp command to rule them all */
DEFUN (clear_ip_bgp_all,
       clear_ip_bgp_all_cmd,
       "clear [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6|l2vpn> [<unicast|multicast|vpn|labeled-unicast|flowspec|evpn>]] <*|A.B.C.D$neighbor|X:X::X:X$neighbor|WORD$neighbor|ASNUM|external|peer-group PGNAME> [<soft [<in|out>]|in [prefix-filter]|out|message-stats|capabilities>]",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_AF_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       BGP_AF_MODIFIER_STR
       "Clear all peers\n"
       "BGP IPv4 neighbor to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       "Clear peers with the AS number in plain or dotted format\n"
       "Clear all external peers\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR
       BGP_SOFT_OUT_STR
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n"
       BGP_SOFT_OUT_STR
       "Reset message statistics\n"
       "Resend capabilities\n")
{
	char *vrf = NULL;

	afi_t afi = AFI_UNSPEC;
	safi_t safi = SAFI_UNSPEC;
	enum clear_sort clr_sort = clear_peer;
	enum bgp_clear_type clr_type;
	char *clr_arg = NULL;

	int idx = 0;

	/* clear [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		idx += 2;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx)) {
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
		idx += 2;
	}
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi))
		argv_find_and_parse_safi(argv, argc, &idx, &safi);

	/* <*|A.B.C.D|X:X::X:X|WORD|ASNUM|external|peer-group PGNAME> */
	if (argv_find(argv, argc, "*", &idx)) {
		clr_sort = clear_all;
	} else if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "X:X::X:X", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "peer-group", &idx)) {
		clr_sort = clear_group;
		idx++;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "PGNAME", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "WORD", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "ASNUM", &idx)) {
		clr_sort = clear_as;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "external", &idx)) {
		clr_sort = clear_external;
	}

	/* [<soft [<in|out>]|in [prefix-filter]|out|message-stats|capabilities>] */
	if (argv_find(argv, argc, "soft", &idx)) {
		if (argv_find(argv, argc, "in", &idx)
		    || argv_find(argv, argc, "out", &idx))
			clr_type = strmatch(argv[idx]->text, "in")
					   ? BGP_CLEAR_SOFT_IN
					   : BGP_CLEAR_SOFT_OUT;
		else
			clr_type = BGP_CLEAR_SOFT_BOTH;
	} else if (argv_find(argv, argc, "in", &idx)) {
		clr_type = argv_find(argv, argc, "prefix-filter", &idx)
				   ? BGP_CLEAR_SOFT_IN_ORF_PREFIX
				   : BGP_CLEAR_SOFT_IN;
	} else if (argv_find(argv, argc, "out", &idx)) {
		clr_type = BGP_CLEAR_SOFT_OUT;
	} else if (argv_find(argv, argc, "message-stats", &idx)) {
		clr_type = BGP_CLEAR_MESSAGE_STATS;
	} else if (argv_find(argv, argc, "capabilities", &idx)) {
		clr_type = BGP_CLEAR_CAPABILITIES;
	} else
		clr_type = BGP_CLEAR_SOFT_NONE;

	return bgp_clear_vty(vty, vrf, afi, safi, clr_sort, clr_type, clr_arg);
}

DEFUN (clear_ip_bgp_prefix,
       clear_ip_bgp_prefix_cmd,
       "clear [ip] bgp [<view|vrf> VIEWVRFNAME] prefix A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv4 prefix\n")
{
	char *vrf = NULL;
	char *prefix = NULL;

	int idx = 0;

	/* [<view|vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		idx += 2;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx)) {
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
		idx += 2;
	}

	prefix = argv[argc - 1]->arg;

	return bgp_clear_prefix(vty, vrf, prefix, AFI_IP, SAFI_UNICAST, NULL);
}

DEFUN (clear_bgp_ipv6_safi_prefix,
       clear_bgp_ipv6_safi_prefix_cmd,
       "clear [ip] bgp ipv6 "BGP_SAFI_CMD_STR" prefix X:X::X:X/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_AF_STR
       BGP_SAFI_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv6 prefix\n")
{
	int idx_safi = 0;
	int idx_ipv6_prefix = 0;
	safi_t safi = SAFI_UNICAST;
	char *prefix = argv_find(argv, argc, "X:X::X:X/M", &idx_ipv6_prefix) ?
		argv[idx_ipv6_prefix]->arg : NULL;

	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);
	return bgp_clear_prefix(
		vty, NULL, prefix, AFI_IP6,
		safi, NULL);
}

DEFUN (clear_bgp_instance_ipv6_safi_prefix,
       clear_bgp_instance_ipv6_safi_prefix_cmd,
       "clear [ip] bgp <view|vrf> VIEWVRFNAME ipv6 "BGP_SAFI_CMD_STR" prefix X:X::X:X/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AF_STR
       BGP_SAFI_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv6 prefix\n")
{
	int idx_safi = 0;
	int idx_vrfview = 0;
	int idx_ipv6_prefix = 0;
	safi_t safi = SAFI_UNICAST;
	char *prefix = argv_find(argv, argc, "X:X::X:X/M", &idx_ipv6_prefix) ?
		argv[idx_ipv6_prefix]->arg : NULL;
	char *vrfview = NULL;

	/* [<view|vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx_vrfview)) {
		vrfview = argv[idx_vrfview + 1]->arg;
		if (vrfview && strmatch(vrfview, VRF_DEFAULT_NAME))
			vrfview = NULL;
	} else if (argv_find(argv, argc, "view", &idx_vrfview)) {
		/* [<view> VIEWVRFNAME] */
		vrfview = argv[idx_vrfview + 1]->arg;
	}
	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);

	return bgp_clear_prefix(
		vty, vrfview, prefix,
		AFI_IP6, safi, NULL);
}

DEFUN (show_bgp_views,
       show_bgp_views_cmd,
       "show [ip] bgp views",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show the defined BGP views\n")
{
	struct list *inst = bm->bgp;
	struct listnode *node;
	struct bgp *bgp;

	vty_out(vty, "Defined BGP views:\n");
	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp)) {
		/* Skip VRFs. */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
			continue;
		vty_out(vty, "\t%s (AS%s)\n", bgp->name ? bgp->name : "(null)",
			bgp->as_pretty);
	}

	return CMD_SUCCESS;
}

static inline void calc_peers_cfgd_estbd(struct bgp *bgp, int *peers_cfgd,
					 int *peers_estbd)
{
	struct peer *peer;
	struct listnode *node;

	*peers_cfgd = *peers_estbd = 0;
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;
		(*peers_cfgd)++;
		if (peer_established(peer->connection))
			(*peers_estbd)++;
	}
}

static void print_bgp_vrfs(struct bgp *bgp, struct vty *vty, json_object *json,
			   const char *type)
{
	int peers_cfg, peers_estb;

	calc_peers_cfgd_estbd(bgp, &peers_cfg, &peers_estb);
	enum global_mode gr_mode = bgp_global_gr_mode_get(bgp);

	if (json) {
		int64_t vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN)
					    ? -1
					    : (int64_t)bgp->vrf_id;
		json_object_string_add(json, "type", type);
		json_object_int_add(json, "vrfId", vrf_id_ui);
		json_object_string_addf(json, "routerId", "%pI4",
					&bgp->router_id);
		json_object_int_add(json, "as", bgp->as);
		json_object_int_add(json, "numConfiguredPeers", peers_cfg);
		json_object_int_add(json, "numEstablishedPeers", peers_estb);
		json_object_int_add(json, "l3vni", bgp->l3vni);
		json_object_string_addf(json, "rmac", "%pEA", &bgp->rmac);
		json_object_string_add(
			json, "interface",
			ifindex2ifname(bgp->l3vni_svi_ifindex, bgp->vrf_id));

		if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART)) {
			afi_t afi;
			safi_t safi = SAFI_UNICAST;
			struct graceful_restart_info *gr_info;
			json_object *json_gr = NULL;
			json_object *json_grs = NULL;

			json_grs = json_object_new_array();

			for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
				json_gr = json_object_new_object();
				json_object_string_add(json_gr, "addressFamily",
						       get_afi_safi_str(afi, safi, false));
				gr_info = &(bgp->gr_info[afi][safi]);
				json_object_boolean_add(json_gr, "grEnabled",
							gr_info->af_enabled);
				json_object_boolean_add(json_gr,
							"grPathSelectionDeferral",
							event_is_scheduled(
								gr_info->t_select_deferral));
				if (gr_info->t_select_deferral)
					json_object_int_add(json_gr,
							    "grDeferralRemainingTimeSec",
							    event_timer_remain_second(
								    gr_info->t_select_deferral));
				json_object_array_add(json_grs, json_gr);
			}
			json_object_boolean_add(json, "grRouteSyncPending",
						bgp->gr_route_sync_pending);
			json_object_object_add(json, "grs", json_grs);
		}
		json_object_int_add(json, "grRestartTime", bgp->restart_time);
		json_object_int_add(json, "grStalePathTime", bgp->stalepath_time);
		json_object_int_add(json, "grSelectDeferTime", bgp->select_defer_time);
		json_object_string_add(json, "grMode",
				       bgp_global_gr_mode_str[gr_mode]);
		json_object_boolean_add(json, "waitForFibSet",
					CHECK_FLAG(bgp->flags,
						   BGP_FLAG_SUPPRESS_FIB_PENDING));
		json_object_boolean_add(json, "gShutEnabled",
					CHECK_FLAG(bgp->flags,
						   BGP_FLAG_GRACEFUL_SHUTDOWN));
	}
}

static int show_bgp_vrfs_detail_common(struct vty *vty, struct bgp *bgp,
				       json_object *json, const char *name,
				       const char *type, bool use_vrf)
{
	int peers_cfg, peers_estb;

	calc_peers_cfgd_estbd(bgp, &peers_cfg, &peers_estb);

	if (use_vrf) {
		if (json) {
			print_bgp_vrfs(bgp, vty, json, type);
		} else {
			vty_out(vty, "BGP instance %s VRF id %d\n",
				bgp->name_pretty,
				bgp->vrf_id == VRF_UNKNOWN ? -1
							   : (int)bgp->vrf_id);
			vty_out(vty, "Router Id %pI4\n", &bgp->router_id);
			vty_out(vty,
				"Num Configured Peers %d, Established %d\n",
				peers_cfg, peers_estb);
			if (bgp->l3vni) {
				vty_out(vty,
					"L3VNI %u, L3VNI-SVI %s, Router MAC %pEA\n",
					bgp->l3vni,
					ifindex2ifname(bgp->l3vni_svi_ifindex,
						       bgp->vrf_id),
					&bgp->rmac);
			}
		}
	} else {
		if (json) {
			print_bgp_vrfs(bgp, vty, json, type);
		} else {
			vty_out(vty, "%4s  %-5d  %-16pI4  %-9u  %-10u  %-37s\n",
				type,
				bgp->vrf_id == VRF_UNKNOWN ? -1
							   : (int)bgp->vrf_id,
				&bgp->router_id, peers_cfg, peers_estb, name);
			vty_out(vty, "%11s  %-16u  %-21pEA  %-20s\n", " ",
				bgp->l3vni, &bgp->rmac,
				ifindex2ifname(bgp->l3vni_svi_ifindex,
					       bgp->vrf_id));
		}
	}

	return CMD_SUCCESS;
}

DEFPY (show_bgp_vrfs,
       show_bgp_vrfs_cmd,
       "show [ip] bgp vrfs [<VRFNAME$vrf_name>] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show BGP VRFs\n"
       "Specific VRF name\n"
       JSON_STR)
{
	struct list *inst = bm->bgp;
	struct listnode *node;
	struct bgp *bgp;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	json_object *json_vrfs = NULL;
	json_object *json_vrf = NULL;
	int count = 0;
	const char *name = vrf_name;
	const char *type;

	if (uj)
		json = json_object_new_object();

	if (name) {
		if (strmatch(name, VRF_DEFAULT_NAME)) {
			bgp = bgp_get_default();
			type = "DFLT";
		} else {
			bgp = bgp_lookup_by_name(name);
			type = "VRF";
		}
		if (!bgp) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% Specified BGP instance not found\n");

			return CMD_WARNING;
		}
	}

	if (vrf_name) {
		if (uj)
			json_vrf = json_object_new_object();

		show_bgp_vrfs_detail_common(vty, bgp, json_vrf, name, type,
					    true);

		if (uj) {
			json_object_object_add(json, name, json_vrf);
			vty_json(vty, json);
		}

		return CMD_SUCCESS;
	}

	if (uj)
		json_vrfs = json_object_new_object();

	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp)) {
		const char *bname;

		/* Skip Views. */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
			continue;

		count++;
		if (!uj && count == 1) {
			vty_out(vty,
				"%4s  %-5s  %-16s  %9s  %10s  %-37s\n",
				"Type", "Id", "routerId", "#PeersCfg",
				"#PeersEstb", "Name");
			vty_out(vty, "%11s  %-16s  %-21s  %-6s\n", " ",
				"L3-VNI", "RouterMAC", "Interface");
		}
		if (uj)
			json_vrf = json_object_new_object();

		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			bname = VRF_DEFAULT_NAME;
			type = "DFLT";
		} else {
			bname = bgp->name;
			type = "VRF";
		}

		show_bgp_vrfs_detail_common(vty, bgp, json_vrf, bname, type,
					    false);

		if (uj)
			json_object_object_add(json_vrfs, bname, json_vrf);
	}

	if (uj) {
		json_object_object_add(json, "vrfs", json_vrfs);
		json_object_int_add(json, "totalVrfs", count);
		vty_json(vty, json);
	} else {
		if (count)
			vty_out(vty,
				"\nTotal number of VRFs (including default): %d\n",
				count);
	}

	return CMD_SUCCESS;
}

DEFPY(show_bgp_router,
      show_bgp_router_cmd,
      "show bgp router [json]",
      SHOW_STR
      BGP_STR
      "Overall BGP information\n"
      JSON_STR)
{
	char timebuf[MONOTIME_STRLEN];
	time_t unix_timestamp;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	time_to_string(bm->start_time, timebuf);

	if (uj) {
		unix_timestamp = time(NULL) - (monotime(NULL) - bm->start_time);
		json_object_int_add(json, "bgpStartedAt", unix_timestamp);
		json_object_boolean_add(json, "bgpStartedGracefully",
					CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART));
	}

	if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART)) {
		if (!uj)
			vty_out(vty, "BGP started gracefully at %s", timebuf);
		else
			json_object_boolean_add(json, "grComplete",
						CHECK_FLAG(bm->flags, BM_FLAG_GR_COMPLETE));

		if (CHECK_FLAG(bm->flags, BM_FLAG_GR_COMPLETE)) {
			time_to_string(bm->gr_completion_time, timebuf);
			if (uj) {
				unix_timestamp = time(NULL) -
						 (monotime(NULL) - bm->gr_completion_time);
				json_object_int_add(json, "grCompletedAt", unix_timestamp);
			} else
				vty_out(vty, "Graceful restart completed at %s", timebuf);
		} else {
			if (!uj)
				vty_out(vty, "Graceful restart is in progress\n");
		}
	} else {
		if (!uj)
			vty_out(vty, "BGP started at %s", timebuf);
	}

	if (uj) {
		json_object_boolean_add(json, "bgpGshutEnabled",
					CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN));
	} else {
		vty_out(vty, "BGP Graceful Shutdown is %s\n",
			CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN) ? "enabled" : "disabled");
	}

	if (uj) {
		json_object_boolean_add(json, "bgpInMaintenanceMode",
					(CHECK_FLAG(bm->flags, BM_FLAG_MAINTENANCE_MODE)));
		json_object_int_add(json, "bgpInstanceCount", listcount(bm->bgp));

	} else {
		if (CHECK_FLAG(bm->flags, BM_FLAG_MAINTENANCE_MODE))
			vty_out(vty, "BGP is in Maintenance mode (BGP GSHUT is in effect)\n");

		vty_out(vty, "Number of BGP instances (including default): %d\n",
			listcount(bm->bgp));
	}

	if (uj) {
		json_object_boolean_add(json, "bgpWaitForFibSet", bm->wait_for_fib);
	} else {
		vty_out(vty, "BGP suppress FIB pending is %s\n",
			bm->wait_for_fib ? "enabled" : "disabled");
	}

	if (uj) {
		json_object_int_add(json, "bgpInputQueueLimit", bm->inq_limit);
		json_object_int_add(json, "bgpOutputQueueLimit", bm->outq_limit);
		json_object_int_add(json, "zebraAnnounceCount",
				    zebra_announce_count(&bm->zebra_announce_head));
		json_object_int_add(json, "zebraAnnounceEarlyCount",
				    zebra_announce_count(&bm->zebra_announce_early_head));
		json_object_int_add(json, "bgpUpdateDelayTime", bm->v_update_delay);
		json_object_int_add(json, "bgpEstablishWaitTime", bm->v_establish_wait);
		if (bm->v_advertisement_delay != BGP_ADVERTISEMENT_DELAY_DEFAULT)
			json_object_int_add(json, "bgpAdvertisementDelayTime",
					    bm->v_advertisement_delay);
		json_object_int_add(json, "bgpRmapDelayTimer", bm->rmap_update_timer);
		json_object_int_add(json, "bgpRmapDelayTimerRemaining",
				    event_timer_remain_second(bm->t_rmap_update));
		vty_json(vty, json);
	} else {
		vty_out(vty, "BGP Input Queue Limit: %d\n", bm->inq_limit);
		vty_out(vty, "BGP Output Queue Limit: %d\n", bm->outq_limit);
		vty_out(vty, "Zebra announce queue (priority): %zu\n",
			zebra_announce_count(&bm->zebra_announce_early_head));
		vty_out(vty, "Zebra announce queue (normal): %zu\n",
			zebra_announce_count(&bm->zebra_announce_head));

		vty_out(vty, "BGP Global Update Delay Timers:\n");
		vty_out(vty, "  Update Delay Time: %ds\n", bm->v_update_delay);
		vty_out(vty, "  Establish Wait Time: %ds\n", bm->v_establish_wait);
		if (bm->v_advertisement_delay != BGP_ADVERTISEMENT_DELAY_DEFAULT)
			vty_out(vty, "  Advertisement Delay Time: %ds\n",
				bm->v_advertisement_delay);

		vty_out(vty, "BGP route-map Delay Timer: %ds (remaining: %lds)\n",
			bm->rmap_update_timer, event_timer_remain_second(bm->t_rmap_update));
	}
	return CMD_SUCCESS;
}

static void bgp_show_bestpath(struct vty *vty, struct bgp *bgp, json_object *json)
{
	bool use_json = json != NULL;
	const char *link_bw_handling_str;

	switch (bgp->lb_handling) {
	case BGP_LINK_BW_ECMP:
		link_bw_handling_str = "ecmp";
		break;
	case BGP_LINK_BW_IGNORE_BW:
		link_bw_handling_str = "ignore";
		break;
	case BGP_LINK_BW_SKIP_MISSING:
		link_bw_handling_str = "skip-missing";
		break;
	case BGP_LINK_BW_DEFWT_4_MISSING:
		link_bw_handling_str = "default-weight-for-missing";
		break;
	default:
		link_bw_handling_str = "ecmp";
		break;
	}

	if (use_json) {
		json_object *bestpath = json_object_new_object();

		json_object_boolean_add(bestpath, "asPathIgnore",
					CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE));

		json_object_boolean_add(bestpath, "asPathConfed",
					CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED));

		json_object_boolean_add(bestpath, "asPathMultiPathRelax",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX));

		json_object_boolean_add(bestpath, "asPathMultiPathRelaxAsSet",
			CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET));

		json_object_boolean_add(bestpath, "peerTypeRelax",
					CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX));

		json_object_boolean_add(bestpath, "compareRouterId",
					CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID));

		json_object_boolean_add(bestpath, "medConfed",
					CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED));

		json_object_boolean_add(bestpath, "medMissingAsWorst",
					CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST));

		json_object_string_add(bestpath, "linkBwHandling", link_bw_handling_str);

		json_object_boolean_add(bestpath, "alwaysCompareMed",
					CHECK_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED));

		json_object_boolean_add(bestpath, "deterministicMed",
					CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED));

		json_object_object_add(json, "bestPath", bestpath);
	} else {
		vty_out(vty, "Best Path Selection Criteria:\n");
		vty_out(vty, "  Ignore AS path is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE) ? "Enabled" : "Disabled");
		vty_out(vty, "  Include confederation ASNs in AS path is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED) ? "Enabled" : "Disabled");

		vty_out(vty, "  AS path multi-path-relax is %s",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX) ? "Enabled"
										: "Disabled");
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET))
				vty_out(vty, " (aggregate ASes as AS-SET)");
		}
		vty_out(vty, "\n");

		vty_out(vty, "  Peer type relax is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX) ? "Enabled"
										  : "Disabled");

		vty_out(vty, "  Compare router ID is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID) ? "Enabled"
									   : "Disabled");

		vty_out(vty, "  BGP bestpath MED confed is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED) ? "Enabled" : "Disabled");

		vty_out(vty, "  BGP bestpath MED missing-as-worst is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST) ? "Enabled"
									      : "Disabled");

		vty_out(vty, "  Link Bandwidth handling set to: %s\n", link_bw_handling_str);

		vty_out(vty, "  Always compare MED is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED) ? "Enabled"
									    : "Disabled");
		vty_out(vty, "  Deterministic MED is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED) ? "Enabled"
									   : "Disabled");
	}
}

DEFPY(show_bgp_vrf_bestpath, show_bgp_vrf_bestpath_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME$vrf_name] bestpath [json]",
      SHOW_STR
      BGP_STR
      BGP_INSTANCE_HELP_STR
      "Display the best path selection criteria\n"
      JSON_STR)
{
	struct bgp *bgp = NULL;
	struct listnode *node = NULL;
	struct list *inst = bm->bgp;
	json_object *json = NULL;
	json_object *json_instance = NULL;
	bool uj = use_json(argc, argv);
	const char *name = vrf_name;
	bool show_all_vrfs = false;
	bool show_all_views = false;
	int idx_vrf_view = 0;
	const char *inst_name;
	const char *type_str;

	if (uj)
		json = json_object_new_object();

	/* Determine if 'vrf all' or 'view all' was specified */
	if (name && strmatch(name, "all")) {
		if (argv_find(argv, argc, "vrf", &idx_vrf_view))
			show_all_vrfs = true;
		else if (argv_find(argv, argc, "view", &idx_vrf_view))
			show_all_views = true;
	}

	/* Handle specific VRF/VIEW case */
	if (name && !show_all_vrfs && !show_all_views) {
		bgp = strmatch(name, VRF_DEFAULT_NAME)
			      ? bgp_get_default()
			      : bgp_lookup_by_name(name);

		if (!bgp) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty, "%% Specified BGP instance not found\n");
			return CMD_WARNING;
		}

		/* Output single VRF/VIEW info */
		if (uj) {
			json_instance = json_object_new_object();
			bgp_show_bestpath(vty, bgp, json_instance);
			json_object_object_add(json, name, json_instance);
			vty_json(vty, json);
		} else {
			type_str = (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW) ? "View" : "VRF";
			vty_out(vty, "%s %s\n", type_str, name);
			bgp_show_bestpath(vty, bgp, NULL);
		}
		return CMD_SUCCESS;
	}

	/* Handle all VRFs and/or VIEWs case */
	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp)) {

		switch (bgp->inst_type) {
		case BGP_INSTANCE_TYPE_DEFAULT:
			inst_name = VRF_DEFAULT_NAME;
			type_str = "VRF";
			/* Skip if showing views only */
			if (show_all_views)
				continue;
			break;
		case BGP_INSTANCE_TYPE_VRF:
			inst_name = bgp->name;
			type_str = "VRF";
			/* Skip if showing views only */
			if (show_all_views)
				continue;
			break;
		case BGP_INSTANCE_TYPE_VIEW:
			inst_name = bgp->name;
			type_str = "View";
			/* Skip if showing vrfs only */
			if (show_all_vrfs)
				continue;
			break;
		default:
			continue;
		}

		if (uj) {
			json_instance = json_object_new_object();
			bgp_show_bestpath(vty, bgp, json_instance);
			json_object_object_add(json, inst_name, json_instance);
		} else {
			vty_out(vty, "%s %s\n", type_str, inst_name);
			bgp_show_bestpath(vty, bgp, NULL);
		}
	}

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFUN (show_bgp_mac_hash,
       show_bgp_mac_hash_cmd,
       "show bgp mac hash",
       SHOW_STR
       BGP_STR
       "Mac Address\n"
       "Mac Address database\n")
{
	bgp_mac_dump_table(vty);

	return CMD_SUCCESS;
}

static void show_tip_entry(struct hash_bucket *bucket, void *args)
{
	struct vty *vty = (struct vty *)args;
	struct tip_addr *tip = (struct tip_addr *)bucket->data;

	vty_out(vty, "addr: %pI4, count: %d\n", &tip->addr, tip->refcnt);
}

static void bgp_show_martian_nexthops(struct vty *vty, struct bgp *bgp)
{
	vty_out(vty, "self nexthop database:\n");
	bgp_nexthop_show_address_hash(vty, bgp);

	vty_out(vty, "Tunnel-ip database:\n");
	hash_iterate(bgp->tip_hash,
		     (void (*)(struct hash_bucket *, void *))show_tip_entry,
		     vty);
}

DEFUN(show_bgp_martian_nexthop_db, show_bgp_martian_nexthop_db_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME] martian next-hop",
      SHOW_STR BGP_STR BGP_INSTANCE_HELP_STR
      "martian next-hops\n"
      "martian next-hop database\n")
{
	struct bgp *bgp = NULL;
	int idx = 0;
	char *name = NULL;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		name = argv[idx + 1]->arg;
		if (name && strmatch(name, VRF_DEFAULT_NAME))
			name = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		name = argv[idx + 1]->arg;
	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();

	if (!bgp || IS_BGP_INSTANCE_HIDDEN(bgp)) {
		vty_out(vty, "%% No BGP process is configured\n");
		return CMD_WARNING;
	}
	bgp_show_martian_nexthops(vty, bgp);

	return CMD_SUCCESS;
}

DEFUN (show_bgp_memory,
       show_bgp_memory_cmd,
       "show [ip] bgp memory",
       SHOW_STR
       IP_STR
       BGP_STR
       "Global BGP memory statistics\n")
{
	char memstrbuf[MTYPE_MEMSTR_LEN];
	unsigned long count;

	/* RIB related usage stats */
	count = mtype_stats_alloc(MTYPE_BGP_NODE);
	vty_out(vty, "%ld RIB nodes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct bgp_dest)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE);
	vty_out(vty, "%ld BGP routes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct bgp_path_info)));
	if ((count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA)))
		vty_out(vty, "%ld BGP route ancillaries, using %s of memory\n",
			count,
			mtype_memstr(
				memstrbuf, sizeof(memstrbuf),
				count * sizeof(struct bgp_path_info_extra)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA_EVPN);
	if (count)
		vty_out(vty, "%ld BGP extra info for EVPN, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_path_info_extra_evpn)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA_FS);
	if (count)
		vty_out(vty,
			"%ld BGP extra info for flowspec, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_path_info_extra_fs)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK);
	if (count)
		vty_out(vty,
			"%ld BGP extra info for vrf leaking, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_path_info_extra_vrfleak)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_STATIC)))
		vty_out(vty, "%ld Static routes, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_static)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_PACKET)))
		vty_out(vty, "%ld Packets, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bpacket)));

	/* Adj-In/Out */
	if ((count = mtype_stats_alloc(MTYPE_BGP_ADJ_IN)))
		vty_out(vty, "%ld Adj-In entries, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_adj_in)));
	if ((count = mtype_stats_alloc(MTYPE_BGP_ADJ_OUT)))
		vty_out(vty, "%ld Adj-Out entries, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_adj_out)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_NEXTHOP_CACHE)))
		vty_out(vty, "%ld Nexthop cache entries, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_nexthop_cache)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_DAMP_INFO)))
		vty_out(vty, "%ld Dampening entries, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_damp_info)));

	/* Attributes */
	count = attr_count();
	vty_out(vty, "%ld BGP attributes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct attr)));

	if ((count = attr_unknown_count()))
		vty_out(vty, "%ld unknown attributes\n", count);

	/* AS_PATH attributes */
	count = aspath_count();
	vty_out(vty, "%ld BGP AS-PATH entries, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct aspath)));

	count = mtype_stats_alloc(MTYPE_AS_SEG);
	vty_out(vty, "%ld BGP AS-PATH segments, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct assegment)));

	/* Other attributes */
	if ((count = community_count()))
		vty_out(vty, "%ld BGP community entries, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(struct community)));
	if ((count = mtype_stats_alloc(MTYPE_ECOMMUNITY)))
		vty_out(vty,
			"%ld BGP ext-community entries, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct ecommunity)));
	if ((count = mtype_stats_alloc(MTYPE_LCOMMUNITY)))
		vty_out(vty,
			"%ld BGP large-community entries, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(struct lcommunity)));

	if ((count = mtype_stats_alloc(MTYPE_CLUSTER)))
		vty_out(vty, "%ld Cluster lists, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct cluster_list)));

	/* Peer related usage */
	count = mtype_stats_alloc(MTYPE_BGP_PEER);
	vty_out(vty, "%ld peers, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct peer)));

	if ((count = mtype_stats_alloc(MTYPE_PEER_GROUP)))
		vty_out(vty, "%ld peer groups, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct peer_group)));

	/* Other */
	if ((count = mtype_stats_alloc(MTYPE_BGP_REGEXP)))
		vty_out(vty, "%ld compiled regexes, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf), count * sizeof(struct frregex)));
	return CMD_SUCCESS;
}

static void bgp_show_bestpath_json(struct bgp *bgp, json_object *json)
{
	json_object *bestpath = json_object_new_object();

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE))
		json_object_string_add(bestpath, "asPath", "ignore");

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED))
		json_object_string_add(bestpath, "asPath", "confed");

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET))
			json_object_string_add(bestpath, "multiPathRelax",
					       "as-set");
		else
			json_object_string_add(bestpath, "multiPathRelax",
					       "true");
	} else
		json_object_string_add(bestpath, "multiPathRelax", "false");

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX))
		json_object_boolean_true_add(bestpath, "peerTypeRelax");

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID))
		json_object_string_add(bestpath, "compareRouterId", "true");
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED)
	    || CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST)) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED))
			json_object_string_add(bestpath, "med", "confed");
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST))
			json_object_string_add(bestpath, "med",
					       "missing-as-worst");
		else
			json_object_string_add(bestpath, "med", "true");
	}

	json_object_object_add(json, "bestPath", bestpath);
}

/* Print the error code/subcode for why the peer is down */
static void bgp_show_peer_reset(struct vty * vty, struct peer *peer,
				json_object *json_peer, bool use_json)
{
	const char *code_str;
	const char *subcode_str;

	if (use_json) {
		if (peer->last_reset == PEER_DOWN_NOTIFY_SEND
		    || peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			char errorcodesubcode_hexstr[5];
			char errorcodesubcode_str[256];

			code_str = bgp_notify_code_str(peer->notify.code);
			subcode_str = bgp_notify_subcode_str(
					 peer->notify.code,
					 peer->notify.subcode);

			snprintf(errorcodesubcode_hexstr,
				 sizeof(errorcodesubcode_hexstr), "%02X%02X",
				 peer->notify.code, peer->notify.subcode);
			json_object_string_add(json_peer,
					       "lastErrorCodeSubcode",
					       errorcodesubcode_hexstr);
			snprintf(errorcodesubcode_str, 255, "%s%s",
				 code_str, subcode_str);
			json_object_string_add(json_peer,
					       "lastNotificationReason",
					       errorcodesubcode_str);
			json_object_boolean_add(json_peer,
						"lastNotificationHardReset",
						peer->notify.hard_reset);
			if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED
			    && peer->notify.code == BGP_NOTIFY_CEASE
			    && (peer->notify.subcode
				== BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN
				|| peer->notify.subcode
				== BGP_NOTIFY_CEASE_ADMIN_RESET)
			    && peer->notify.length) {
				char msgbuf[1024];
				const char *msg_str;

				msg_str = bgp_notify_admin_message(
					     msgbuf, sizeof(msgbuf),
					     (uint8_t *)peer->notify.data,
					     peer->notify.length);
				json_object_string_add(json_peer,
				   "lastShutdownDescription",
				   msg_str);
			}

		}
		json_object_string_add(json_peer, "lastResetDueTo",
				       peer_down_str[(int)peer->last_reset]);
		json_object_int_add(json_peer, "lastResetCode",
				    peer->last_reset);
		/*
		 * A reset that occurs *while the peer is already down* is
		 * recorded in down_last_reset (see peer_set_last_reset in
		 * bgpd.h). Emit it separately so callers can distinguish the
		 * cause that brought the peer down from follow-on resets
		 * (e.g., config changes made while the peer is shut down).
		 */
		if (peer->down_last_reset != PEER_DOWN_NONE) {
			json_object_string_add(
				json_peer, "downLastResetDueTo",
				peer_down_str[peer->down_last_reset]);
			json_object_int_add(json_peer, "downLastResetCode",
					    peer->down_last_reset);
			json_object_int_add(
				json_peer, "downLastResetTimeSecs",
				monotime(NULL) - peer->down_resettime);
		}
		json_object_string_add(json_peer, "softwareVersion",
				       peer->soft_version ? peer->soft_version
							  : "n/a");
	} else {
		if (peer->last_reset == PEER_DOWN_NOTIFY_SEND
		    || peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			code_str = bgp_notify_code_str(peer->notify.code);
			subcode_str =
				bgp_notify_subcode_str(peer->notify.code,
						       peer->notify.subcode);
			vty_out(vty, " Notification %s (%s%s%s)\n",
				peer->last_reset == PEER_DOWN_NOTIFY_SEND
					? "sent"
					: "received",
				code_str, subcode_str,
				peer->notify.hard_reset
					? bgp_notify_subcode_str(
						  BGP_NOTIFY_CEASE,
						  BGP_NOTIFY_CEASE_HARD_RESET)
					: "");
		} else {
			vty_out(vty, " %s (%s)\n",
				peer_down_str[(int)peer->last_reset],
				peer->soft_version ? peer->soft_version : "n/a");
		}
	}
}

static inline bool bgp_has_peer_failed(struct peer *peer, afi_t afi,
				       safi_t safi)
{
	return ((!peer_established(peer->connection)) ||
		!peer->afc_recv[afi][safi]);
}

static void bgp_show_failed_summary(struct vty *vty, struct bgp *bgp,
				    struct peer *peer, json_object *json_peer,
				    int max_neighbor_width, bool use_json)
{
	char timebuf[BGP_UPTIME_LEN], dn_flag[2];
	int len;

	if (use_json) {
		if (peer_dynamic_neighbor(peer))
			json_object_boolean_true_add(json_peer,
						     "dynamicPeer");
		if (peer->hostname)
			json_object_string_add(json_peer, "hostname",
					       peer->hostname);

		if (peer->domainname)
			json_object_string_add(json_peer, "domainname",
					       peer->domainname);
		json_object_int_add(json_peer, "connectionsEstablished",
				    peer->established);
		json_object_int_add(json_peer, "connectionsDropped",
				    peer->dropped);
		peer_uptime(peer->uptime, timebuf, BGP_UPTIME_LEN,
			    use_json, json_peer);
		if (peer_established(peer->connection))
			json_object_string_add(json_peer, "lastResetDueTo",
					       "AFI/SAFI Not Negotiated");
		else
			bgp_show_peer_reset(NULL, peer, json_peer, true);
	} else {
		dn_flag[1] = '\0';
		dn_flag[0] = peer_dynamic_neighbor(peer) ? '*' : '\0';
		if (peer->hostname
		    && CHECK_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME))
			len = vty_out(vty, "%s%s(%s)", dn_flag,
				      peer->hostname, peer->host);
		else
			len = vty_out(vty, "%s%s", dn_flag, peer->host);

		/* pad the neighbor column with spaces */
		if (len < max_neighbor_width)
			vty_out(vty, "%*s", max_neighbor_width - len,
				" ");
		vty_out(vty, "%7d %7d %9s", peer->established,
			peer->dropped,
			peer_uptime(peer->uptime, timebuf,
				    BGP_UPTIME_LEN, 0, NULL));
		if (peer_established(peer->connection))
			vty_out(vty, "  AFI/SAFI Not Negotiated\n");
		else
			bgp_show_peer_reset(vty, peer, NULL,
					    false);
	}
}

/* Strip peer's description to the given size. */
static char *bgp_peer_description_stripped(char *desc, uint32_t size)
{
	static char stripped[BUFSIZ];
	uint32_t i = 0;
	uint32_t last_space = size;

	while (i < size) {
		if (*(desc + i) == '\0') {
			stripped[i] = '\0';
			return stripped;
		}
		if (i != 0 && *(desc + i) == ' ' && last_space != i - 1)
			last_space = i;
		stripped[i] = *(desc + i);
		i++;
	}

	stripped[last_space] = '\0';

	return stripped;
}

/* Determine whether var peer should be filtered out of the summary. */
static bool bgp_show_summary_is_peer_filtered(struct peer *peer,
					      struct peer *fpeer,
					      enum peer_asn_type as_type,
					      as_t as)
{
	/*
	 * Hide peers flagged PEER_STATUS_NB_PENDING_CONFIG: their remote-as
	 * YANG leaf was destroyed but the peer struct is kept alive to dodge
	 * the libyang delta-reconfig collapse trap.  From the user's view
	 * such peers are deconfigured and must not appear in show output.
	 */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_NB_PENDING_CONFIG))
		return true;

	/* filter neighbor XXXX */
	if (fpeer && fpeer != peer)
		return true;

	/* filter remote-as (internal|external) */
	if (as_type != AS_UNSPECIFIED) {
		if (peer->as_type == AS_SPECIFIED) {
			if (CHECK_FLAG(as_type, AS_INTERNAL)) {
				if (peer->as != peer->local_as)
					return true;
			} else if (peer->as == peer->local_as)
				return true;
		} else if (as_type != peer->as_type)
			return true;
	} else if (as && as != peer->as) /* filter remote-as XXX */
		return true;

	return false;
}

/* Show BGP peer's summary information.
 *
 * Peer's description is stripped according to if `wide` option is given
 * or not.
 *
 * When adding new columns to `show bgp summary` output, please make
 * sure `Desc` is the lastest column to show because it can contain
 * whitespaces and the whole output will be tricky.
 */
static int bgp_show_summary(struct vty *vty, struct bgp *bgp, int afi, int safi,
			    struct peer *fpeer, enum peer_asn_type as_type,
			    as_t as, uint16_t show_flags)
{
	struct peer *peer;
	struct listnode *node, *nnode;
	unsigned int count = 0, dn_count = 0;
	char timebuf[BGP_UPTIME_LEN], dn_flag[2];
	char neighbor_buf[VTY_BUFSIZ];
	int neighbor_col_default_width = 16;
	int len, failed_count = 0;
	unsigned int filtered_count = 0;
	int max_neighbor_width = 0;
	int pfx_rcd_safi;
	json_object *json = NULL;
	json_object *json_peer = NULL;
	json_object *json_peers = NULL;
	struct peer_af *paf;
	struct bgp_filter *filter;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	bool show_failed = CHECK_FLAG(show_flags, BGP_SHOW_OPT_FAILED);
	bool show_established =
		CHECK_FLAG(show_flags, BGP_SHOW_OPT_ESTABLISHED);
	bool show_wide = CHECK_FLAG(show_flags, BGP_SHOW_OPT_WIDE);
	bool show_terse = CHECK_FLAG(show_flags, BGP_SHOW_OPT_TERSE);

	/* labeled-unicast routes are installed in the unicast table so in order
	 * to
	 * display the correct PfxRcd value we must look at SAFI_UNICAST
	 */

	if (safi == SAFI_LABELED_UNICAST)
		pfx_rcd_safi = SAFI_UNICAST;
	else
		pfx_rcd_safi = safi;

	if (use_json) {
		json = json_object_new_object();
		json_peers = json_object_new_object();
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (bgp_show_summary_is_peer_filtered(peer, fpeer,
							      as_type, as)) {
				filtered_count++;
				count++;
				continue;
			}

			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
				continue;

			if (peer->afc[afi][safi]) {
				/* See if we have at least a single failed peer */
				if (bgp_has_peer_failed(peer, afi, safi))
					failed_count++;
				count++;
			}
			if (peer_dynamic_neighbor(peer))
				dn_count++;
		}

	} else {
		/* Loop over all neighbors that will be displayed to determine
		 * how many
		 * characters are needed for the Neighbor column
		 */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (bgp_show_summary_is_peer_filtered(peer, fpeer,
							      as_type, as)) {
				filtered_count++;
				count++;
				continue;
			}

			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
				continue;

			if (peer->afc[afi][safi]) {
				memset(dn_flag, '\0', sizeof(dn_flag));
				if (peer_dynamic_neighbor(peer))
					dn_flag[0] = '*';

				if (peer->hostname
				    && CHECK_FLAG(bgp->flags,
						  BGP_FLAG_SHOW_HOSTNAME))
					snprintf(neighbor_buf,
						 sizeof(neighbor_buf),
						 "%s%s(%s) ", dn_flag,
						 peer->hostname, peer->host);
				else
					snprintf(neighbor_buf,
						 sizeof(neighbor_buf), "%s%s ",
						 dn_flag, peer->host);

				len = strlen(neighbor_buf);

				if (len > max_neighbor_width)
					max_neighbor_width = len;

				/* See if we have at least a single failed peer */
				if (bgp_has_peer_failed(peer, afi, safi))
					failed_count++;
				count++;
			}
		}

		/* Originally we displayed the Neighbor column as 16
		 * characters wide so make that the default
		 */
		if (max_neighbor_width < neighbor_col_default_width)
			max_neighbor_width = neighbor_col_default_width;
	}

	if (show_failed && !failed_count) {
		if (use_json) {
			json_object_free(json_peers);

			json_object_int_add(json, "failedPeersCount", 0);
			json_object_int_add(json, "dynamicPeers", dn_count);
			json_object_int_add(json, "totalPeers", count);

			vty_json(vty, json);
		} else {
			vty_out(vty, "%% No failed BGP neighbors found\n");
		}
		return CMD_SUCCESS;
	}

	count = 0;		/* Reset the value as its used again */
	filtered_count = 0;
	dn_count = 0;
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		if (!peer->afc[afi][safi])
			continue;

		if (!count) {
			unsigned long ents;
			char memstrbuf[MTYPE_MEMSTR_LEN];
			int64_t vrf_id_ui;

			vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN)
					    ? -1
					    : (int64_t)bgp->vrf_id;

			/* Usage summary and header */
			if (use_json) {
				json_object_string_addf(json, "routerId",
							"%pI4",
							&bgp->router_id);
				asn_asn2json(json, "as", bgp->as,
					     bgp->asnotation);
				json_object_int_add(json, "vrfId", vrf_id_ui);
				json_object_string_add(
					json, "vrfName",
					(bgp->inst_type
					 == BGP_INSTANCE_TYPE_DEFAULT)
						? VRF_DEFAULT_NAME
						: bgp->name);
			} else {
				vty_out(vty,
					"BGP router identifier %pI4, local AS number %s %s vrf-id %d",
					&bgp->router_id, bgp->as_pretty,
					bgp->name_pretty,
					bgp->vrf_id == VRF_UNKNOWN
						? -1
						: (int)bgp->vrf_id);
				vty_out(vty, "\n");
			}

			if (bgp_update_delay_configured(bgp)) {
				if (use_json) {
					json_object_int_add(
						json, "updateDelayLimit",
						bgp->v_update_delay);

					if (bgp->v_update_delay
					    != bgp->v_establish_wait)
						json_object_int_add(
							json,
							"updateDelayEstablishWait",
							bgp->v_establish_wait);

					if (bgp_update_delay_active(bgp)) {
						json_object_string_add(
							json,
							"updateDelayFirstNeighbor",
							bgp->update_delay_begin_time);
						json_object_boolean_true_add(
							json,
							"updateDelayInProgress");
					} else {
						if (bgp->update_delay_over) {
							json_object_string_add(
								json,
								"updateDelayFirstNeighbor",
								bgp->update_delay_begin_time);
							json_object_string_add(
								json,
								"updateDelayBestpathResumed",
								bgp->update_delay_end_time);
							json_object_string_add(
								json,
								"updateDelayZebraUpdateResume",
								bgp->update_delay_zebra_resume_time);
							json_object_string_add(
								json,
								"updateDelayPeerUpdateResume",
								bgp->update_delay_peers_resume_time);
						}
					}
				} else {
					vty_out(vty,
						"Read-only mode update-delay limit: %d seconds\n",
						bgp->v_update_delay);
					if (bgp->v_update_delay
					    != bgp->v_establish_wait)
						vty_out(vty,
							"                   Establish wait: %d seconds\n",
							bgp->v_establish_wait);

					if (bgp_update_delay_active(bgp)) {
						vty_out(vty,
							"  First neighbor established: %s\n",
							bgp->update_delay_begin_time);
						vty_out(vty,
							"  Delay in progress\n");
					} else {
						if (bgp->update_delay_over) {
							vty_out(vty,
								"  First neighbor established: %s\n",
								bgp->update_delay_begin_time);
							vty_out(vty,
								"          Best-paths resumed: %s\n",
								bgp->update_delay_end_time);
							vty_out(vty,
								"        zebra update resumed: %s\n",
								bgp->update_delay_zebra_resume_time);
							vty_out(vty,
								"        peers update resumed: %s\n",
								bgp->update_delay_peers_resume_time);
						}
					}
				}
			}

			if (bgp_advertisement_delay_configured(bgp)) {
				if (use_json) {
					json_object_int_add(json,
							    "advertisementDelay",
							    bgp->v_advertisement_delay);
					if (bgp_advertisement_delay_active(bgp)) {
						json_object_boolean_true_add(
							json,
							"advertisementDelayInProgress");
						json_object_int_add(
							json,
							"advertisementDelayRemainingSeconds",
							event_timer_remain_second(
								bgp->t_advertisement_delay));
					} else if (bgp->advertisement_delay_resume_time[0] != '\0')
						json_object_string_add(
							json,
							"advertisementDelayResumeTime",
							bgp->advertisement_delay_resume_time);
				} else {
					vty_out(vty,
						"Advertisement delay: %d seconds\n",
						bgp->v_advertisement_delay);
					if (bgp_advertisement_delay_active(bgp))
						vty_out(vty,
							"  %lu seconds remaining\n",
							event_timer_remain_second(
								bgp->t_advertisement_delay));
					else if (bgp->advertisement_delay_resume_time[0] != '\0')
						vty_out(vty,
							"  advertisements resumed: %s\n",
							bgp->advertisement_delay_resume_time);
				}
			}

			if (use_json) {
				if (bgp_maxmed_onstartup_configured(bgp)
				    && bgp->maxmed_active)
					json_object_boolean_true_add(
						json, "maxMedOnStartup");
				if (bgp->v_maxmed_admin)
					json_object_boolean_true_add(
						json, "maxMedAdministrative");

				json_object_int_add(
					json, "tableVersion",
					bgp_table_version(bgp->rib[afi][safi]));

				ents = bgp_table_count(bgp->rib[afi][safi]);
				json_object_int_add(json, "ribCount", ents);
				json_object_int_add(
					json, "ribMemory",
					ents * sizeof(struct bgp_dest));

				ents = bgp->af_peer_count[afi][safi];
				json_object_int_add(json, "peerCount", ents);
				json_object_int_add(json, "peerMemory",
						    ents * sizeof(struct peer));

				if ((ents = listcount(bgp->group))) {
					json_object_int_add(
						json, "peerGroupCount", ents);
					json_object_int_add(
						json, "peerGroupMemory",
						ents * sizeof(struct
							      peer_group));
				}

				if (CHECK_FLAG(bgp->af_flags[afi][safi],
					       BGP_CONFIG_DAMPENING))
					json_object_boolean_true_add(
						json, "dampeningEnabled");
			} else {
				if (!show_terse) {
					if (bgp_maxmed_onstartup_configured(bgp)
					    && bgp->maxmed_active)
						vty_out(vty,
							"Max-med on-startup active\n");
					if (bgp->v_maxmed_admin)
						vty_out(vty,
							"Max-med administrative active\n");

					vty_out(vty,
						"BGP table version %" PRIu64
						"\n",
						bgp_table_version(
							bgp->rib[afi][safi]));

					ents = bgp_table_count(
						bgp->rib[afi][safi]);
					vty_out(vty,
						"RIB entries %ld, using %s of memory\n",
						ents,
						mtype_memstr(
							memstrbuf,
							sizeof(memstrbuf),
							ents
								* sizeof(
									struct
									bgp_dest)));

					/* Peer related usage */
					ents = bgp->af_peer_count[afi][safi];
					vty_out(vty,
						"Peers %ld, using %s of memory\n",
						ents,
						mtype_memstr(
							memstrbuf,
							sizeof(memstrbuf),
							ents
								* sizeof(
									struct
									peer)));

					if ((ents = listcount(bgp->group)))
						vty_out(vty,
							"Peer groups %ld, using %s of memory\n",
							ents,
							mtype_memstr(
								memstrbuf,
								sizeof(memstrbuf),
								ents
									* sizeof(
										struct
										peer_group)));

					if (CHECK_FLAG(bgp->af_flags[afi][safi],
						       BGP_CONFIG_DAMPENING))
						vty_out(vty,
							"Dampening enabled.\n");
				}
				if (show_failed) {
					vty_out(vty, "\n");

					/* Subtract 8 here because 'Neighbor' is
					 * 8 characters */
					vty_out(vty, "Neighbor");
					vty_out(vty, "%*s",
						max_neighbor_width - 8, " ");
					vty_out(vty,
						BGP_SHOW_SUMMARY_HEADER_FAILED);
				}
			}
		}

		paf = peer_af_find(peer, afi, safi);
		filter = &peer->filter[afi][safi];

		count++;
		/* Works for both failed & successful cases */
		if (peer_dynamic_neighbor(peer))
			dn_count++;

		if (use_json) {
			json_peer = NULL;
			if (bgp_show_summary_is_peer_filtered(peer, fpeer,
							      as_type, as)) {
				filtered_count++;
				continue;
			}
			if (show_failed &&
			    bgp_has_peer_failed(peer, afi, safi)) {
				json_peer = json_object_new_object();
				bgp_show_failed_summary(vty, bgp, peer,
							json_peer, 0, use_json);
			} else if (!show_failed) {
				if (show_established
				    && bgp_has_peer_failed(peer, afi, safi)) {
					filtered_count++;
					continue;
				}

				json_peer = json_object_new_object();
				if (peer_dynamic_neighbor(peer)) {
					json_object_boolean_true_add(json_peer,
								     "dynamicPeer");
				}

				if (peer->hostname)
					json_object_string_add(json_peer, "hostname",
							       peer->hostname);

				if (peer->domainname)
					json_object_string_add(json_peer, "domainname",
							       peer->domainname);

				json_object_string_add(json_peer,
						       "softwareVersion",
						       peer->soft_version
							       ? peer->soft_version
							       : "n/a");

				asn_asn2json(json_peer, "remoteAs", peer->as,
					     bgp->asnotation);
				asn_asn2json(json_peer, "localAs",
					     peer->change_local_as
						     ? peer->change_local_as
						     : peer->local_as,
					     bgp->asnotation);
				json_object_int_add(json_peer, "version", 4);
				json_object_int_add(json_peer, "msgRcvd",
						    PEER_TOTAL_RX(peer));
				json_object_int_add(json_peer, "msgSent",
						    PEER_TOTAL_TX(peer));

				atomic_size_t outq_count, inq_count;
				outq_count =
					atomic_load_explicit(&peer->connection
								      ->obuf
								      ->count,
							     memory_order_relaxed);
				inq_count =
					atomic_load_explicit(&peer->connection
								      ->ibuf
								      ->count,
							     memory_order_relaxed);

				json_object_int_add(
					json_peer, "tableVersion",
					(paf && PAF_SUBGRP(paf))
						? paf->subgroup->version
						: 0);
				json_object_int_add(json_peer, "outq",
						    outq_count);
				json_object_int_add(json_peer, "inq",
						    inq_count);
				peer_uptime(peer->uptime, timebuf, BGP_UPTIME_LEN,
					    use_json, json_peer);

				json_object_int_add(json_peer, "pfxRcd",
						    peer->pcount[afi][pfx_rcd_safi]);

				if (paf && PAF_SUBGRP(paf))
					json_object_int_add(
						json_peer, "pfxSnt",
						(PAF_SUBGRP(paf))->scount);
				else
					json_object_int_add(json_peer, "pfxSnt",
							    0);

				/* BGP FSM state */
				if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN)
				    || CHECK_FLAG(peer->bgp->flags,
						  BGP_FLAG_SHUTDOWN))
					json_object_string_add(json_peer,
							       "state",
							       "Idle (Admin)");
				else if (peer->afc_recv[afi][safi])
					json_object_string_add(
						json_peer, "state",
						lookup_msg(bgp_status_msg,
							   peer->connection->status,
							   NULL));
				else if (CHECK_FLAG(
						 peer->sflags,
						 PEER_STATUS_PREFIX_OVERFLOW))
					json_object_string_add(json_peer,
							       "state",
							       "Idle (PfxCt)");
				else
					json_object_string_add(
						json_peer, "state",
						lookup_msg(bgp_status_msg,
							   peer->connection->status,
							   NULL));

				/* BGP peer state */
				if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN)
				    || CHECK_FLAG(peer->bgp->flags,
						  BGP_FLAG_SHUTDOWN))
					json_object_string_add(json_peer,
							       "peerState",
							       "Admin");
				else if (CHECK_FLAG(
						 peer->sflags,
						 PEER_STATUS_PREFIX_OVERFLOW))
					json_object_string_add(json_peer,
							       "peerState",
							       "PfxCt");
				else if (CHECK_FLAG(peer->flags,
						    PEER_FLAG_PASSIVE))
					json_object_string_add(json_peer,
							       "peerState",
							       "Passive");
				else if (CHECK_FLAG(peer->sflags,
						    PEER_STATUS_NSF_WAIT))
					json_object_string_add(json_peer,
							       "peerState",
							       "NSF passive");
				else if (CHECK_FLAG(
						 peer->bgp->flags,
						 BGP_FLAG_EBGP_REQUIRES_POLICY)
					 && (!bgp_inbound_policy_exists(peer,
									filter)
					     || !bgp_outbound_policy_exists(
						     peer, filter)))
					json_object_string_add(json_peer,
							       "peerState",
							       "Policy");
				else
					json_object_string_add(
						json_peer, "peerState", "OK");

				json_object_int_add(json_peer, "connectionsEstablished",
						    peer->established);
				json_object_int_add(json_peer, "connectionsDropped",
						    peer->dropped);
				if (peer->desc)
					json_object_string_add(
						json_peer, "desc", peer->desc);
			}
			/* Avoid creating empty peer dicts in JSON */
			if (json_peer == NULL)
				continue;

			if (peer->conf_if)
				json_object_string_add(json_peer, "idType",
						       "interface");
			else if (peer->connection->su.sa.sa_family == AF_INET)
				json_object_string_add(json_peer, "idType",
						       "ipv4");
			else if (peer->connection->su.sa.sa_family == AF_INET6)
				json_object_string_add(json_peer, "idType",
						       "ipv6");
			json_object_object_add(json_peers, peer->host,
					       json_peer);
		} else {
			if (bgp_show_summary_is_peer_filtered(peer, fpeer,
							      as_type, as)) {
				filtered_count++;
				continue;
			}
			if (show_failed &&
			    bgp_has_peer_failed(peer, afi, safi)) {
				bgp_show_failed_summary(vty, bgp, peer, NULL,
							max_neighbor_width,
							use_json);
			} else if (!show_failed) {
				if (show_established
				    && bgp_has_peer_failed(peer, afi, safi)) {
					filtered_count++;
					continue;
				}

				if ((count - filtered_count) == 1) {
					/* display headline before the first
					 * neighbor line */
					vty_out(vty, "\n");

					/* Subtract 8 here because 'Neighbor' is
					 * 8 characters */
					vty_out(vty, "Neighbor");
					vty_out(vty, "%*s",
						max_neighbor_width - 8, " ");
					vty_out(vty,
						show_wide
							? BGP_SHOW_SUMMARY_HEADER_ALL_WIDE
							: BGP_SHOW_SUMMARY_HEADER_ALL);
				}

				memset(dn_flag, '\0', sizeof(dn_flag));
				if (peer_dynamic_neighbor(peer)) {
					dn_flag[0] = '*';
				}

				if (peer->hostname
				    && CHECK_FLAG(bgp->flags,
						  BGP_FLAG_SHOW_HOSTNAME))
					len = vty_out(vty, "%s%s(%s)", dn_flag,
						      peer->hostname,
						      peer->host);
				else
					len = vty_out(vty, "%s%s", dn_flag, peer->host);

				/* pad the neighbor column with spaces */
				if (len < max_neighbor_width)
					vty_out(vty, "%*s", max_neighbor_width - len,
						" ");

				atomic_size_t outq_count, inq_count;
				outq_count =
					atomic_load_explicit(&peer->connection
								      ->obuf
								      ->count,
							     memory_order_relaxed);
				inq_count =
					atomic_load_explicit(&peer->connection
								      ->ibuf
								      ->count,
							     memory_order_relaxed);

				vty_out(vty, "4");
				vty_out(vty, ASN_FORMAT_SPACE(bgp->asnotation),
					&peer->as);
				if (show_wide)
					vty_out(vty,
						ASN_FORMAT_SPACE(
							bgp->asnotation),
						peer->change_local_as
							? &peer->change_local_as
							: &peer->local_as);
				vty_out(vty,
					" %9u %9u %8" PRIu64 " %4zu %4zu %8s",
					PEER_TOTAL_RX(peer),
					PEER_TOTAL_TX(peer),
					(paf && PAF_SUBGRP(paf))
						? paf->subgroup->version
						: 0,
					inq_count, outq_count,
					peer_uptime(peer->uptime, timebuf,
						    BGP_UPTIME_LEN, 0, NULL));

				if (peer_established(peer->connection)) {
					if (peer->afc_recv[afi][safi]) {
						if (CHECK_FLAG(
							    bgp->flags,
							    BGP_FLAG_EBGP_REQUIRES_POLICY)
						    && !bgp_inbound_policy_exists(
							    peer, filter))
							vty_out(vty, " %12s",
								"(Policy)");
						else
							vty_out(vty,
								" %12u",
								peer->pcount
									[afi]
									[pfx_rcd_safi]);
					} else {
						vty_out(vty, "        NoNeg");
					}

					if (paf && PAF_SUBGRP(paf)) {
						if (CHECK_FLAG(
							    bgp->flags,
							    BGP_FLAG_EBGP_REQUIRES_POLICY)
						    && !bgp_outbound_policy_exists(
							    peer, filter))
							vty_out(vty, " %8s",
								"(Policy)");
						else
							vty_out(vty,
								" %8u",
								(PAF_SUBGRP(
									 paf))
									->scount);
					} else {
						vty_out(vty, "    NoNeg");
					}
				} else {
					if (CHECK_FLAG(peer->flags,
						       PEER_FLAG_SHUTDOWN)
					    || CHECK_FLAG(peer->bgp->flags,
							  BGP_FLAG_SHUTDOWN))
						vty_out(vty, " Idle (Admin)");
					else if (CHECK_FLAG(
							    peer->sflags,
							    PEER_STATUS_PREFIX_OVERFLOW))
						vty_out(vty, " Idle (PfxCt)");
					else
						vty_out(vty, " %12s",
							lookup_msg(bgp_status_msg,
								   peer->connection
									   ->status,
								   NULL));

					vty_out(vty, " %8u", 0);
				}
				/* Make sure `Desc` column is the latest in
				 * the output.
				 * If the description is not set, try
				 * to print the software version if the
				 * capability is enabled and received.
				 */
				if (peer->desc)
					vty_out(vty, " %s",
						bgp_peer_description_stripped(
							peer->desc,
							show_wide ? 64 : 20));
				else if (peer->soft_version) {
					vty_out(vty, " %s",
						bgp_peer_description_stripped(
							peer->soft_version,
							show_wide ? 64 : 20));
				} else {
					vty_out(vty, " N/A");
				}
				vty_out(vty, "\n");
			}

		}
	}

	if (use_json) {
		json_object_object_add(json, "peers", json_peers);
		json_object_int_add(json, "failedPeers", failed_count);
		json_object_int_add(json, "displayedPeers",
				    count - filtered_count);
		json_object_int_add(json, "totalPeers", count);
		json_object_int_add(json, "dynamicPeers", dn_count);

		if (!show_failed)
			bgp_show_bestpath_json(bgp, json);

		vty_json(vty, json);
	} else {
		if (count) {
			if (filtered_count == count)
				vty_out(vty, "\n%% No matching neighbor\n");
			else {
				if (show_failed)
					vty_out(vty, "\nDisplayed neighbors %d",
						failed_count);
				else if (as_type != AS_UNSPECIFIED || as
					 || fpeer || show_established)
					vty_out(vty, "\nDisplayed neighbors %d",
						count - filtered_count);

				vty_out(vty, "\nTotal number of neighbors %d\n",
					count);
			}
		} else {
			vty_out(vty, "No %s neighbor is configured\n",
				get_afi_safi_str(afi, safi, false));
		}

		if (dn_count) {
			vty_out(vty, "* - dynamic neighbor\n");
			vty_out(vty, "%d dynamic neighbor(s), limit %d\n",
				dn_count, bgp->dynamic_neighbors_limit);
		}
	}

	return CMD_SUCCESS;
}

static void bgp_show_summary_afi_safi(struct vty *vty, struct bgp *bgp, int afi,
				      int safi, struct peer *fpeer, int as_type,
				      as_t as, uint16_t show_flags)
{
	int is_first = 1;
	int afi_wildcard = (afi == AFI_MAX);
	int safi_wildcard = (safi == SAFI_MAX);
	int is_wildcard = (afi_wildcard || safi_wildcard);
	bool nbr_output = false;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (use_json && is_wildcard)
		vty_out(vty, "{\n");
	if (afi_wildcard)
		afi = 1; /* AFI_IP */
	while (afi < AFI_MAX) {
		if (safi_wildcard)
			safi = 1; /* SAFI_UNICAST */
		while (safi < SAFI_MAX) {
			if (bgp_afi_safi_peer_exists(bgp, afi, safi)) {
				nbr_output = true;

				if (is_wildcard) {
					/*
					 * So limit output to those afi/safi
					 * pairs that
					 * actualy have something interesting in
					 * them
					 */
					if (use_json) {
						if (!is_first)
							vty_out(vty, ",\n");
						else
							is_first = 0;

						vty_out(vty, "\"%s\":",
							get_afi_safi_str(afi,
									 safi,
									 true));
					} else {
						vty_out(vty, "\n%s Summary:\n",
							get_afi_safi_str(afi,
									 safi,
									 false));
					}
				}
				bgp_show_summary(vty, bgp, afi, safi, fpeer,
						 as_type, as, show_flags);
			}
			safi++;
			if (!safi_wildcard)
				safi = SAFI_MAX;
		}
		afi++;
		if (!afi_wildcard)
			afi = AFI_MAX;
	}

	if (use_json && is_wildcard)
		vty_out(vty, "}\n");
	else if (!nbr_output) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% No BGP neighbors found in %s\n",
				bgp->name_pretty);
	}
}

static void bgp_show_all_instances_summary_vty(struct vty *vty, afi_t afi,
					       safi_t safi, const char *neighbor,
					       enum peer_asn_type as_type,
					       as_t as, uint16_t show_flags)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	struct peer *fpeer = NULL;
	int is_first = 1;
	bool nbr_output = false;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (use_json)
		vty_out(vty, "{\n");

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;

		nbr_output = true;
		if (use_json) {
			if (!is_first)
				vty_out(vty, ",\n");
			else
				is_first = 0;

			vty_out(vty, "\"%s\":",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		}
		if (neighbor) {
			fpeer = peer_lookup_in_view(vty, bgp, neighbor,
						    use_json);
			if (!fpeer)
				continue;
		}
		bgp_show_summary_afi_safi(vty, bgp, afi, safi, fpeer, as_type,
					  as, show_flags);
	}

	if (use_json)
		vty_out(vty, "}\n");
	else if (!nbr_output)
		vty_out(vty, "%% BGP instance not found\n");
}

int bgp_show_summary_vty(struct vty *vty, const char *name, afi_t afi,
			 safi_t safi, const char *neighbor,
			 enum peer_asn_type as_type, as_t as,
			 uint16_t show_flags)
{
	struct bgp *bgp;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	struct peer *fpeer = NULL;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_summary_vty(vty, afi, safi,
							   neighbor, as_type,
							   as, show_flags);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);

			if (!bgp) {
				if (use_json)
					vty_out(vty, "{}\n");
				else
					vty_out(vty,
						"%% BGP instance not found\n");
				return CMD_WARNING;
			}

			if (neighbor) {
				fpeer = peer_lookup_in_view(vty, bgp, neighbor,
							    use_json);
				if (!fpeer)
					return CMD_WARNING;
			}
			bgp_show_summary_afi_safi(vty, bgp, afi, safi, fpeer,
						  as_type, as, show_flags);
			return CMD_SUCCESS;
		}
	}

	bgp = bgp_get_default();

	if (bgp) {
		if (neighbor) {
			fpeer = peer_lookup_in_view(vty, bgp, neighbor,
						    use_json);
			if (!fpeer)
				return CMD_WARNING;
		}
		bgp_show_summary_afi_safi(vty, bgp, afi, safi, fpeer, as_type,
					  as, show_flags);
	} else {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% BGP instance not found\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* `show [ip] bgp summary' commands. */
DEFPY(show_ip_bgp_summary, show_ip_bgp_summary_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [" BGP_AFI_CMD_STR
      " [" BGP_SAFI_WITH_LABEL_CMD_STR
      "]] [all$all] summary [established|failed] [<neighbor <A.B.C.D|X:X::X:X|WORD>|remote-as <ASNUM|internal|external>>] [terse] [wide] [json$uj]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_WITH_LABEL_HELP_STR
      "Display the entries for all address families\n"
      "Summary of BGP neighbor status\n"
      "Show only sessions in Established state\n"
      "Show only sessions not in Established state\n"
      "Show only the specified neighbor session\n"
      "Neighbor to display information about\n"
      "Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "Show only the specified remote AS sessions\n" AS_STR
      "Internal (iBGP) AS sessions\n"
      "External (eBGP) AS sessions\n"
      "Shorten the information on BGP instances\n"
      "Increase table width for longer output\n" JSON_STR)
{
	char *vrf = NULL;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;
	as_t as = 0; /* 0 means AS filter not set */
	int as_type = AS_UNSPECIFIED;
	uint16_t show_flags = 0;

	int idx = 0;

	/* show [ip] bgp */
	if (!all && argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		argv_find_and_parse_safi(argv, argc, &idx, &safi);
	}

	if (argv_find(argv, argc, "failed", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_FAILED);

	if (argv_find(argv, argc, "established", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_ESTABLISHED);

	if (argv_find(argv, argc, "remote-as", &idx)) {
		if (argv[idx + 1]->arg[0] == 'i')
			as_type = AS_INTERNAL;
		else if (argv[idx + 1]->arg[0] == 'e')
			as_type = AS_EXTERNAL;
		else if (argv[idx + 1]->arg[0] == 'a')
			as_type = AS_AUTO;
		else if (!asn_str2asn(argv[idx + 1]->arg, &as)) {
			vty_out(vty,
				"%% Invalid neighbor remote-as value: %s\n",
				argv[idx + 1]->arg);
			return CMD_SUCCESS;
		}
	}

	if (argv_find(argv, argc, "terse", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_TERSE);

	if (argv_find(argv, argc, "wide", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_WIDE);

	if (argv_find(argv, argc, "json", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	return bgp_show_summary_vty(vty, vrf, afi, safi, neighbor, as_type, as,
				    show_flags);
}

const char *get_afi_safi_str(afi_t afi, safi_t safi, bool for_json)
{
	if (for_json)
		return get_afi_safi_json_str(afi, safi);
	else
		return get_afi_safi_vty_str(afi, safi);
}

static void bgp_show_peer_afi_orf_cap(struct vty *vty, struct peer *p,
				      afi_t afi, safi_t safi,
				      uint16_t adv_smcap, uint16_t adv_rmcap,
				      uint16_t rcv_smcap, uint16_t rcv_rmcap,
				      bool use_json, json_object *json_pref)
{
	/* Send-Mode */
	if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap)
	    || CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap)) {
		if (use_json) {
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap)
			    && CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "advertisedAndReceived");
			else if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "advertised");
			else if (CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "received");
		} else {
			vty_out(vty, "      Send-mode: ");
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap))
				vty_out(vty, "advertised");
			if (CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				vty_out(vty, "%sreceived",
					CHECK_FLAG(p->af_cap[afi][safi],
						   adv_smcap)
						? ", "
						: "");
			vty_out(vty, "\n");
		}
	}

	/* Receive-Mode */
	if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap)
	    || CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap)) {
		if (use_json) {
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap)
			    && CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "advertisedAndReceived");
			else if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "advertised");
			else if (CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "received");
		} else {
			vty_out(vty, "      Receive-mode: ");
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap))
				vty_out(vty, "advertised");
			if (CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				vty_out(vty, "%sreceived",
					CHECK_FLAG(p->af_cap[afi][safi],
						   adv_rmcap)
						? ", "
						: "");
			vty_out(vty, "\n");
		}
	}
}

static void bgp_show_neighnor_graceful_restart_flags(struct vty *vty,
						     struct peer *p,
						     json_object *json)
{
	bool rbit = false;
	bool nbit = false;

	if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV) &&
	    (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) &&
	    (peer_established(p->connection))) {
		rbit = CHECK_FLAG(p->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV);
		nbit = CHECK_FLAG(p->cap, PEER_CAP_GRACEFUL_RESTART_N_BIT_RCV);
	}

	if (json) {
		json_object_boolean_add(json, "rBit", rbit);
		json_object_boolean_add(json, "nBit", nbit);
	} else {
		vty_out(vty, "\n    R bit: %s", rbit ? "True" : "False");
		vty_out(vty, "\n    N bit: %s\n", nbit ? "True" : "False");
	}
}

static void bgp_show_neighbor_graceful_restart_remote_mode(struct vty *vty,
							   struct peer *peer,
							   json_object *json)
{
	const char *mode = "NotApplicable";

	if (!json)
		vty_out(vty, "\n    Remote GR Mode: ");

	if (CHECK_FLAG(peer->cap, PEER_CAP_RESTART_ADV) &&
	    (peer_established(peer->connection))) {
		if ((peer->nsf_af_count == 0)
		    && !CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV)) {

			mode = "Disable";

		} else if (peer->nsf_af_count == 0
			   && CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV)) {

			mode = "Helper";

		} else if (peer->nsf_af_count != 0
			   && CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV)) {

			mode = "Restart";
		}
	}

	if (json)
		json_object_string_add(json, "remoteGrMode", mode);
	else
		vty_out(vty, "%s", mode);
}

static void bgp_show_neighbor_graceful_restart_local_mode(struct vty *vty,
							  struct peer *p,
							  json_object *json)
{
	const char *mode = "Invalid";

	if (!json)
		vty_out(vty, "    Local GR Mode: ");

	if (bgp_peer_gr_mode_get(p) == PEER_HELPER)
		mode = "Helper";
	else if (bgp_peer_gr_mode_get(p) == PEER_GR)
		mode = "Restart";
	else if (bgp_peer_gr_mode_get(p) == PEER_DISABLE)
		mode = "Disable";
	else if (bgp_peer_gr_mode_get(p) == PEER_GLOBAL_INHERIT) {
		if (bgp_global_gr_mode_get(p->bgp) == GLOBAL_HELPER)
			mode = "Helper*";
		else if (bgp_global_gr_mode_get(p->bgp) == GLOBAL_GR)
			mode = "Restart*";
		else if (bgp_global_gr_mode_get(p->bgp) == GLOBAL_DISABLE)
			mode = "Disable*";
		else
			mode = "Invalid*";
	}

	if (json)
		json_object_string_add(json, "localGrMode", mode);
	else
		vty_out(vty, "%s", mode);
}

static __attribute__((unused)) void bgp_show_neighbor_graceful_restart_capability_per_afi_safi(
	struct vty *vty, struct peer *peer, json_object *json)
{
	afi_t afi;
	safi_t safi;
	json_object *json_afi_safi = NULL;
	json_object *json_timer = NULL;
	json_object *json_endofrib_status = NULL;
	bool eor_flag = false;

	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (!peer->afc[afi][safi])
			continue;

		if (!CHECK_FLAG(peer->cap, PEER_CAP_RESTART_ADV) ||
		    !CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV))
			continue;

		if (json) {
			json_afi_safi = json_object_new_object();
			json_endofrib_status = json_object_new_object();
			json_timer = json_object_new_object();
		}

		if (peer->eor_stime[afi][safi] >= peer->pkt_stime[afi][safi])
			eor_flag = true;
		else
			eor_flag = false;

		if (!json) {
			vty_out(vty, "    %s:\n",
				get_afi_safi_str(afi, safi, false));

			vty_out(vty, "      F bit: ");
		}

		if (peer->nsf[afi][safi] &&
		    CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_RESTART_AF_PRESERVE_RCV)) {

			if (json) {
				json_object_boolean_true_add(json_afi_safi,
							     "fBit");
			} else
				vty_out(vty, "True\n");
		} else {
			if (json)
				json_object_boolean_false_add(json_afi_safi,
							      "fBit");
			else
				vty_out(vty, "False\n");
		}

		if (!json)
			vty_out(vty, "      End-of-RIB sent: ");

		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_EOR_SEND)) {
			if (json) {
				json_object_boolean_true_add(
					json_endofrib_status, "endOfRibSend");

				PRINT_EOR_JSON(eor_flag);
			} else {
				vty_out(vty, "Yes\n");
				vty_out(vty,
					"      End-of-RIB sent after update: ");

				PRINT_EOR(eor_flag);
			}
		} else {
			if (json) {
				json_object_boolean_false_add(
					json_endofrib_status, "endOfRibSend");
				json_object_boolean_false_add(
					json_endofrib_status,
					"endOfRibSentAfterUpdate");
			} else {
				vty_out(vty, "No\n");
				vty_out(vty,
					"      End-of-RIB sent after update: ");
				vty_out(vty, "No\n");
			}
		}

		if (!json)
			vty_out(vty, "      End-of-RIB received: ");

		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_EOR_RECEIVED)) {
			if (json)
				json_object_boolean_true_add(
					json_endofrib_status, "endOfRibRecv");
			else
				vty_out(vty, "Yes\n");
		} else {
			if (json)
				json_object_boolean_false_add(
					json_endofrib_status, "endOfRibRecv");
			else
				vty_out(vty, "No\n");
		}

		if (json) {
			json_object_int_add(json_timer, "stalePathTimer",
					    peer->bgp->stalepath_time);
			json_object_int_add(json_timer, "llgrStaleTime",
					    peer->llgr[afi][safi].stale_time);

			if (peer->connection->t_gr_stale != NULL) {
				json_object_int_add(json_timer,
						    "stalePathTimerRemaining",
						    event_timer_remain_second(
							    peer->connection
								    ->t_gr_stale));
			}

			/* Display Configured Selection
			 * Deferral only when when
			 * Gr mode is enabled.
			 */
			if (CHECK_FLAG(peer->flags,
				       PEER_FLAG_GRACEFUL_RESTART)) {
				json_object_int_add(json_timer, "selectionDeferralTimer",
						    peer->bgp->select_defer_time);
			}

			if (peer->bgp->gr_info[afi][safi].t_select_deferral !=
			    NULL) {

				json_object_int_add(
					json_timer,
					"selectionDeferralTimerRemaining",
					event_timer_remain_second(
						peer->bgp->gr_info[afi][safi]
							.t_select_deferral));
			}

			if (peer->bgp->gr_multihop_peer_exists) {
				if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
					json_object_int_add(json_timer,
							    "selectionDeferralTier2Timer",
							    peer->bgp->select_defer_time);

				if (peer->bgp->gr_info[afi][safi].t_select_deferral_tier2 != NULL)
					json_object_int_add(json_timer,
							    "selectionDeferralTier2TimerRemaining",
							    event_timer_remain_second(
								    peer->bgp->gr_info[afi][safi]
									    .t_select_deferral_tier2));
			}
		} else {
			vty_out(vty, "      Timers:\n");
			vty_out(vty,
				"        Configured Stale Path Time(sec): %u\n",
				peer->bgp->stalepath_time);

			if (peer->connection->t_gr_stale != NULL)
				vty_out(vty,
					"      Stale Path Remaining(sec): %ld\n",
					event_timer_remain_second(
						peer->connection->t_gr_stale));
			/* Display Configured Selection
			 * Deferral only when when
			 * Gr mode is enabled.
			 */
			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				vty_out(vty,
					"        Configured Selection Deferral Time(sec): %u\n",
					peer->bgp->select_defer_time);

			vty_out(vty, "        LLGR Stale Path Time(sec): %u\n",
				peer->llgr[afi][safi].stale_time);

			if (peer->bgp->gr_info[afi][safi].t_select_deferral !=
			    NULL)
				vty_out(vty,
					"        Selection Deferral Time Remaining(sec): %ld\n",
					event_timer_remain_second(
						peer->bgp->gr_info[afi][safi]
							.t_select_deferral));
			if (peer->bgp->gr_multihop_peer_exists) {
				vty_out(vty, "        Multihop GR peer exists\n");
				if (peer->bgp->gr_info[afi][safi].t_select_deferral_tier2 != NULL)
					vty_out(vty,
						"        Selection Deferral Tier2 Time Remaining(sec): %ld\n",
						event_timer_remain_second(
							peer->bgp->gr_info[afi][safi]
								.t_select_deferral_tier2));
			}
		}
		if (json) {
			json_object_object_add(json_afi_safi, "endOfRibStatus",
					       json_endofrib_status);
			json_object_object_add(json_afi_safi, "timers",
					       json_timer);
			json_object_object_add(
				json, get_afi_safi_str(afi, safi, true),
				json_afi_safi);
		}
	}
}

static void bgp_show_neighbor_graceful_restart_time(struct vty *vty,
						    struct peer *p,
						    json_object *json)
{
	if (json) {
		json_object *json_timer = NULL;

		json_timer = json_object_new_object();

		json_object_int_add(json_timer, "configuredRestartTimer",
				    p->bgp->restart_time);
		json_object_int_add(json_timer, "configuredLlgrStaleTime",
				    p->bgp->llgr_stale_time);

		json_object_int_add(json_timer, "receivedRestartTimer",
				    p->v_gr_restart);

		if (p->connection->t_gr_restart != NULL)
			json_object_int_add(json_timer, "restartTimerRemaining",
					    event_timer_remain_second(
						    p->connection->t_gr_restart));

		json_object_object_add(json, "timers", json_timer);
	} else {

		vty_out(vty, "    Timers:\n");
		vty_out(vty, "      Configured Restart Time(sec): %u\n",
			p->bgp->restart_time);

		vty_out(vty, "      Received Restart Time(sec): %u\n",
			p->v_gr_restart);
		vty_out(vty, "      Configured LLGR Stale Path Time(sec): %u\n",
			p->bgp->llgr_stale_time);
		if (p->connection->t_gr_restart != NULL)
			vty_out(vty, "      Restart Time Remaining(sec): %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_restart));
		if (p->connection->t_gr_restart != NULL) {
			vty_out(vty, "      Restart Time Remaining(sec): %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_restart));
		}
	}
}

static void bgp_show_peer_gr_status(struct vty *vty, struct peer *p,
				    json_object *json)
{
	char dn_flag[2] = {0};
	/* '*' + v6 address of neighbor */
	char neighborAddr[INET6_ADDRSTRLEN + 1] = {0};

	if (!p->conf_if && peer_dynamic_neighbor(p))
		dn_flag[0] = '*';

	if (p->conf_if) {
		if (json)
			json_object_string_addf(json, "neighborAddr", "%pSU",
						&p->connection->su);
		else
			vty_out(vty, "BGP neighbor on %s: %pSU\n", p->conf_if,
				&p->connection->su);
	} else {
		snprintf(neighborAddr, sizeof(neighborAddr), "%s%s", dn_flag,
			 p->host);

		if (json)
			json_object_string_add(json, "neighborAddr",
					       neighborAddr);
		else
			vty_out(vty, "BGP neighbor is %s\n", neighborAddr);
	}

	/* more gr info in new format */
	if (json) {
		json_object *json_grace = json_object_new_object();
		BGP_SHOW_PEER_GR_CAPABILITY(vty, p, json_grace);
		json_object_object_add(json, "gracefulRestartInfo", json_grace);
	} else {
		BGP_SHOW_PEER_GR_CAPABILITY(vty, p, NULL);
	}
}

void bgp_show_peer_gr_info_afi_safi(struct vty *vty, struct peer *peer, bool use_json,
					   json_object *json)
{
	afi_t afi;
	safi_t safi;
	json_object *json_afi_safi = NULL;
	json_object *json_timer = NULL;
	json_object *json_endofrib_status = NULL;
	bool eor_flag = false;

	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (!peer->afc[afi][safi])
			continue;

		if (!CHECK_FLAG(peer->cap, PEER_CAP_RESTART_ADV) ||
		    !CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV))
			continue;

		if (json) {
			json_afi_safi = json_object_new_object();
			json_endofrib_status = json_object_new_object();
			json_timer = json_object_new_object();
		}

		if (peer->eor_stime[afi][safi] >= peer->pkt_stime[afi][safi])
			eor_flag = true;
		else
			eor_flag = false;

		if (!json) {
			vty_out(vty, "    %s:\n",
				get_afi_safi_str(afi, safi, false));

			vty_out(vty, "      F bit: ");
		}

		if (peer->nsf[afi][safi] &&
		    CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_RESTART_AF_PRESERVE_RCV)) {

			if (json) {
				json_object_boolean_true_add(json_afi_safi,
							     "fBit");
			} else
				vty_out(vty, "True\n");
		} else {
			if (json)
				json_object_boolean_false_add(json_afi_safi,
							      "fBit");
			else
				vty_out(vty, "False\n");
		}

		if (!json)
			vty_out(vty, "      End-of-RIB sent: ");

		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_EOR_SEND)) {
			if (json) {
				json_object_boolean_true_add(
					json_endofrib_status, "endOfRibSend");

				PRINT_EOR_JSON(eor_flag);
			} else {
				vty_out(vty, "Yes\n");
				vty_out(vty,
					"      End-of-RIB sent after update: ");

				PRINT_EOR(eor_flag);
			}
		} else {
			if (json) {
				json_object_boolean_false_add(
					json_endofrib_status, "endOfRibSend");
				json_object_boolean_false_add(
					json_endofrib_status,
					"endOfRibSentAfterUpdate");
			} else {
				vty_out(vty, "No\n");
				vty_out(vty,
					"      End-of-RIB sent after update: ");
				vty_out(vty, "No\n");
			}
		}

		if (!json)
			vty_out(vty, "      End-of-RIB received: ");

		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_EOR_RECEIVED)) {
			if (json)
				json_object_boolean_true_add(
					json_endofrib_status, "endOfRibRecv");
			else
				vty_out(vty, "Yes\n");
		} else {
			if (json)
				json_object_boolean_false_add(
					json_endofrib_status, "endOfRibRecv");
			else
				vty_out(vty, "No\n");
		}

		if (json) {
			json_object_int_add(json_timer, "stalePathTimer",
					    peer->bgp->stalepath_time);
			json_object_int_add(json_timer, "llgrStaleTime",
					    peer->llgr[afi][safi].stale_time);

			if (peer->connection->t_gr_stale != NULL) {
				json_object_int_add(json_timer,
						    "stalePathTimerRemaining",
						    event_timer_remain_second(
							    peer->connection
								    ->t_gr_stale));
			}

			/* Display Configured Selection
			 * Deferral only when when
			 * Gr mode is enabled.
			 */
			if (CHECK_FLAG(peer->flags,
				       PEER_FLAG_GRACEFUL_RESTART)) {
				json_object_int_add(json_timer, "selectionDeferralTimer",
						    peer->bgp->select_defer_time);
			}

			if (peer->bgp->gr_info[afi][safi].t_select_deferral !=
			    NULL) {

				json_object_int_add(
					json_timer,
					"selectionDeferralTimerRemaining",
					event_timer_remain_second(
						peer->bgp->gr_info[afi][safi]
							.t_select_deferral));
			}
		} else {
			vty_out(vty, "      Timers:\n");
			vty_out(vty,
				"        Configured Stale Path Time(sec): %u\n",
				peer->bgp->stalepath_time);

			if (peer->connection->t_gr_stale != NULL)
				vty_out(vty,
					"      Stale Path Remaining(sec): %ld\n",
					event_timer_remain_second(
						peer->connection->t_gr_stale));
			/* Display Configured Selection
			 * Deferral only when when
			 * Gr mode is enabled.
			 */
			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				vty_out(vty,
					"        Configured Selection Deferral Time(sec): %u\n",
					peer->bgp->select_defer_time);

			vty_out(vty, "        LLGR Stale Path Time(sec): %u\n",
				peer->llgr[afi][safi].stale_time);

			if (peer->bgp->gr_info[afi][safi].t_select_deferral !=
			    NULL)
				vty_out(vty,
					"        Selection Deferral Time Remaining(sec): %ld\n",
					event_timer_remain_second(
						peer->bgp->gr_info[afi][safi]
							.t_select_deferral));
		}
		if (json) {
			json_object_object_add(json_afi_safi, "endOfRibStatus",
					       json_endofrib_status);
			json_object_object_add(json_afi_safi, "timers",
					       json_timer);
			json_object_object_add(
				json, get_afi_safi_str(afi, safi, true),
				json_afi_safi);
		}
	}
}

static void bgp_show_peer_afi(struct vty *vty, struct peer *p, afi_t afi,
			      safi_t safi, bool use_json,
			      json_object *json_neigh)
{
	struct bgp_filter *filter;
	struct peer_af *paf;
	char orf_pfx_name[BUFSIZ];
	int orf_pfx_count;
	json_object *json_af = NULL;
	json_object *json_prefA = NULL;
	json_object *json_addr = NULL;
	json_object *json_advmap = NULL;

	if (use_json) {
		json_addr = json_object_new_object();
		json_af = json_object_new_object();
		filter = &p->filter[afi][safi];

		if (peer_group_active(p))
			json_object_string_add(json_addr, "peerGroupMember",
					       p->group->name);

		paf = peer_af_find(p, afi, safi);
		if (paf && PAF_SUBGRP(paf)) {
			json_object_int_add(json_addr, "updateGroupId",
					    PAF_UPDGRP(paf)->id);
			json_object_int_add(json_addr, "subGroupId",
					    PAF_SUBGRP(paf)->id);
			json_object_int_add(json_addr, "packetQueueLength",
					    bpacket_queue_virtual_length(paf));
		}

		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_RCV)) {
			json_object_int_add(json_af, "orfType",
					    ORF_TYPE_PREFIX);
			json_prefA = json_object_new_object();
			bgp_show_peer_afi_orf_cap(vty, p, afi, safi,
						  PEER_CAP_ORF_PREFIX_SM_ADV,
						  PEER_CAP_ORF_PREFIX_RM_ADV,
						  PEER_CAP_ORF_PREFIX_SM_RCV,
						  PEER_CAP_ORF_PREFIX_RM_RCV,
						  use_json, json_prefA);
			json_object_object_add(json_af, "orfPrefixList",
					       json_prefA);
		}

		if (CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_ADV) ||
		    CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_RCV) ||
		    CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_RM_ADV) ||
		    CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV))
			json_object_object_add(json_addr, "afDependentCap",
					       json_af);
		else
			json_object_free(json_af);

		snprintf(orf_pfx_name, sizeof(orf_pfx_name), "%s.%d.%d",
			 p->host, afi, safi);
		orf_pfx_count = prefix_bgp_show_prefix_list(
			NULL, afi, orf_pfx_name, use_json);

		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_PREFIX_SEND)
		    || orf_pfx_count) {
			if (CHECK_FLAG(p->af_sflags[afi][safi],
				       PEER_STATUS_ORF_PREFIX_SEND))
				json_object_boolean_true_add(json_neigh,
							     "orfSent");
			if (orf_pfx_count)
				json_object_int_add(json_addr, "orfRecvCounter",
						    orf_pfx_count);
		}
		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_WAIT_REFRESH))
			json_object_string_add(
				json_addr, "orfFirstUpdate",
				"deferredUntilORFOrRouteRefreshRecvd");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REFLECTOR_CLIENT))
			json_object_boolean_true_add(json_addr,
						     "routeReflectorClient");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_RSERVER_CLIENT))
			json_object_boolean_true_add(json_addr,
						     "routeServerClient");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
			json_object_boolean_true_add(json_addr,
						     "inboundSoftConfigPermit");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsAllReplacedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsReplacedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsAllRemovedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsRemovedInUpdatesToNbr");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN)) {
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_ALLOWAS_IN_ORIGIN))
				json_object_boolean_true_add(json_addr,
							     "allowAsInOrigin");
			else
				json_object_int_add(json_addr, "allowAsInCount",
						    p->allowas_in[afi][safi]);
		}

		if (p->addpath_type[afi][safi] != BGP_ADDPATH_NONE)
			json_object_boolean_true_add(
				json_addr,
				bgp_addpath_names(p->addpath_type[afi][safi])
					->type_json_name);

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_AS_OVERRIDE))
			json_object_string_add(json_addr,
					       "overrideASNsInOutboundUpdates",
					       "ifAspathEqualRemoteAs");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_FORCE_NEXTHOP_SELF))
			json_object_boolean_true_add(json_addr,
						     "routerAlwaysNextHop");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_AS_PATH_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedAsPathPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_NEXTHOP_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedNextHopPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedMedPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY) ||
		    CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_LARGE_COMMUNITY) ||
		    CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY)) {
			char comm_attri_sent_to_nbr[BGP_SEND_COMMUNITY_STR_SIZE] = { 0 };

			if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)) {
				strncat(comm_attri_sent_to_nbr, "standard",
					sizeof(comm_attri_sent_to_nbr) -
						strlen(comm_attri_sent_to_nbr) - 1);
			}

			if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY)) {
				if (strlen(comm_attri_sent_to_nbr) > 0) {
					strncat(comm_attri_sent_to_nbr, "And",
						sizeof(comm_attri_sent_to_nbr) -
							strlen(comm_attri_sent_to_nbr) - 1);
				}
				strncat(comm_attri_sent_to_nbr, "extended",
					sizeof(comm_attri_sent_to_nbr) -
						strlen(comm_attri_sent_to_nbr) - 1);
			}

			if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_LARGE_COMMUNITY)) {
				if (strlen(comm_attri_sent_to_nbr) > 0) {
					strncat(comm_attri_sent_to_nbr, "And",
						sizeof(comm_attri_sent_to_nbr) -
							strlen(comm_attri_sent_to_nbr) - 1);
				}
				strncat(comm_attri_sent_to_nbr, "large",
					sizeof(comm_attri_sent_to_nbr) -
						strlen(comm_attri_sent_to_nbr) - 1);
			}

			json_object_string_add(json_addr, "commAttriSentToNbr",
					       comm_attri_sent_to_nbr);
		}
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE)) {
			if (p->default_rmap[afi][safi].name)
				json_object_string_add(
					json_addr, "defaultRouteMap",
					p->default_rmap[afi][safi].name);

			if (paf && PAF_SUBGRP(paf)
			    && CHECK_FLAG(PAF_SUBGRP(paf)->sflags,
					  SUBGRP_STATUS_DEFAULT_ORIGINATE))
				json_object_boolean_true_add(json_addr,
							     "defaultSent");
			else
				json_object_boolean_true_add(json_addr,
							     "defaultNotSent");
		}

		if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
			if (is_evpn_enabled())
				json_object_boolean_true_add(
					json_addr, "advertiseAllVnis");
		}

		if (filter->plist[FILTER_IN].name
		    || filter->dlist[FILTER_IN].name
		    || filter->aslist[FILTER_IN].name
		    || filter->map[RMAP_IN].name)
			json_object_boolean_true_add(json_addr,
						     "inboundPathPolicyConfig");
		if (filter->plist[FILTER_OUT].name
		    || filter->dlist[FILTER_OUT].name
		    || filter->aslist[FILTER_OUT].name
		    || filter->map[RMAP_OUT].name || filter->usmap.name)
			json_object_boolean_true_add(
				json_addr, "outboundPathPolicyConfig");

		/* prefix-list */
		if (filter->plist[FILTER_IN].name)
			json_object_string_add(json_addr,
					       "incomingUpdatePrefixFilterList",
					       filter->plist[FILTER_IN].name);
		if (filter->plist[FILTER_OUT].name)
			json_object_string_add(json_addr,
					       "outgoingUpdatePrefixFilterList",
					       filter->plist[FILTER_OUT].name);

		/* distribute-list */
		if (filter->dlist[FILTER_IN].name)
			json_object_string_add(
				json_addr, "incomingUpdateNetworkFilterList",
				filter->dlist[FILTER_IN].name);
		if (filter->dlist[FILTER_OUT].name)
			json_object_string_add(
				json_addr, "outgoingUpdateNetworkFilterList",
				filter->dlist[FILTER_OUT].name);

		/* filter-list. */
		if (filter->aslist[FILTER_IN].name)
			json_object_string_add(json_addr,
					       "incomingUpdateAsPathFilterList",
					       filter->aslist[FILTER_IN].name);
		if (filter->aslist[FILTER_OUT].name)
			json_object_string_add(json_addr,
					       "outgoingUpdateAsPathFilterList",
					       filter->aslist[FILTER_OUT].name);

		/* route-map. */
		if (filter->map[RMAP_IN].name)
			json_object_string_add(
				json_addr, "routeMapForIncomingAdvertisements",
				filter->map[RMAP_IN].name);
		if (filter->map[RMAP_OUT].name)
			json_object_string_add(
				json_addr, "routeMapForOutgoingAdvertisements",
				filter->map[RMAP_OUT].name);

		/* ebgp-requires-policy (inbound) */
		if (CHECK_FLAG(p->bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    && !bgp_inbound_policy_exists(p, filter))
			json_object_string_add(
				json_addr, "inboundEbgpRequiresPolicy",
				"Inbound updates discarded due to missing policy");

		/* ebgp-requires-policy (outbound) */
		if (CHECK_FLAG(p->bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    && (!bgp_outbound_policy_exists(p, filter)))
			json_object_string_add(
				json_addr, "outboundEbgpRequiresPolicy",
				"Outbound updates discarded due to missing policy");

		/* unsuppress-map */
		if (filter->usmap.name)
			json_object_string_add(json_addr,
					       "selectiveUnsuppressRouteMap",
					       filter->usmap.name);

		/* advertise-map */
		if (filter->advmap.aname) {
			json_advmap = json_object_new_object();
			json_object_string_add(json_advmap, "condition",
					       filter->advmap.condition
						       ? "EXIST"
						       : "NON_EXIST");
			json_object_string_add(json_advmap, "conditionMap",
					       filter->advmap.cname);
			json_object_string_add(json_advmap, "advertiseMap",
					       filter->advmap.aname);
			json_object_string_add(
				json_advmap, "advertiseStatus",
				filter->advmap.update_type ==
						UPDATE_TYPE_ADVERTISE
					? "Advertise"
					: "Withdraw");
			json_object_object_add(json_addr, "advertiseMap",
					       json_advmap);
		}

		/* Receive prefix count */
		json_object_int_add(json_addr, "acceptedPrefixCounter",
				    p->pcount[afi][safi]);
		if (paf && PAF_SUBGRP(paf))
			json_object_int_add(json_addr, "sentPrefixCounter",
						(PAF_SUBGRP(paf))->scount);

		json_object_int_add(json_addr, "receivedPrefixDup",
				    p->pcount_dup[afi][safi]);

		/* Maximum prefix */
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_OUT))
			json_object_int_add(json_addr, "prefixOutAllowedMax",
					    p->pmax_out[afi][safi]);

		/* Maximum prefix */
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX)) {
			json_object_int_add(json_addr, "prefixAllowedMax",
					    p->pmax[afi][safi]);
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_MAX_PREFIX_WARNING))
				json_object_boolean_true_add(
					json_addr, "prefixAllowedMaxWarning");
			json_object_int_add(json_addr,
					    "prefixAllowedWarningThresh",
					    p->pmax_threshold[afi][safi]);
			if (p->pmax_restart[afi][safi])
				json_object_int_add(
					json_addr,
					"prefixAllowedRestartIntervalMsecs",
					p->pmax_restart[afi][safi] * 60000);
		}
		json_object_object_add(json_neigh,
				       get_afi_safi_str(afi, safi, true),
				       json_addr);

	} else {
		filter = &p->filter[afi][safi];

		vty_out(vty, " For address family: %s\n",
			get_afi_safi_str(afi, safi, false));

		if (peer_group_active(p))
			vty_out(vty, "  %s peer-group member\n",
				p->group->name);

		paf = peer_af_find(p, afi, safi);
		if (paf && PAF_SUBGRP(paf)) {
			vty_out(vty, "  Update group %" PRIu64", subgroup %" PRIu64 "\n",
				PAF_UPDGRP(paf)->id, PAF_SUBGRP(paf)->id);
			vty_out(vty, "  Packet Queue length %d\n",
				bpacket_queue_virtual_length(paf));
		} else {
			vty_out(vty, "  Not part of any update group\n");
		}
		if (CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_ADV) ||
		    CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_RCV) ||
		    CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_RM_ADV) ||
		    CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV))
			vty_out(vty, "  AF-dependant capabilities:\n");

		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_RCV)) {
			vty_out(vty,
				"    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
				ORF_TYPE_PREFIX);
			bgp_show_peer_afi_orf_cap(
				vty, p, afi, safi, PEER_CAP_ORF_PREFIX_SM_ADV,
				PEER_CAP_ORF_PREFIX_RM_ADV,
				PEER_CAP_ORF_PREFIX_SM_RCV,
				PEER_CAP_ORF_PREFIX_RM_RCV, use_json, NULL);
		}

		snprintf(orf_pfx_name, sizeof(orf_pfx_name), "%s.%d.%d",
			 p->host, afi, safi);
		orf_pfx_count = prefix_bgp_show_prefix_list(
			NULL, afi, orf_pfx_name, use_json);

		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_PREFIX_SEND)
		    || orf_pfx_count) {
			vty_out(vty, "  Outbound Route Filter (ORF):");
			if (CHECK_FLAG(p->af_sflags[afi][safi],
				       PEER_STATUS_ORF_PREFIX_SEND))
				vty_out(vty, " sent;");
			if (orf_pfx_count)
				vty_out(vty, " received (%d entries)",
					orf_pfx_count);
			vty_out(vty, "\n");
		}
		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_WAIT_REFRESH))
			vty_out(vty,
				"  First update is deferred until ORF or ROUTE-REFRESH is received\n");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REFLECTOR_CLIENT))
			vty_out(vty, "  Route-Reflector Client\n");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_RSERVER_CLIENT))
			vty_out(vty, "  Route-Server Client\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
			vty_out(vty,
				"  Inbound soft reconfiguration allowed\n");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
			vty_out(vty,
				"  Private AS numbers (all) replaced in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
			vty_out(vty,
				"  Private AS numbers replaced in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
			vty_out(vty,
				"  Private AS numbers (all) removed in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS))
			vty_out(vty,
				"  Private AS numbers removed in updates to this neighbor\n");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN)) {
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_ALLOWAS_IN_ORIGIN))
				vty_out(vty,
					"  Local AS allowed as path origin\n");
			else
				vty_out(vty,
					"  Local AS allowed in path, %d occurrences\n",
					p->allowas_in[afi][safi]);
		}

		if (p->addpath_type[afi][safi] != BGP_ADDPATH_NONE)
			vty_out(vty, "  %s\n",
				bgp_addpath_names(p->addpath_type[afi][safi])
					->human_description);

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_AS_OVERRIDE))
			vty_out(vty,
				"  Override ASNs in outbound updates if aspath equals remote-as\n");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_FORCE_NEXTHOP_SELF))
			vty_out(vty, "  NEXT_HOP is always this router\n");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_AS_PATH_UNCHANGED))
			vty_out(vty,
				"  AS_PATH is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_NEXTHOP_UNCHANGED))
			vty_out(vty,
				"  NEXT_HOP is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
			vty_out(vty,
				"  MED is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_SEND_EXT_COMMUNITY)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_SEND_LARGE_COMMUNITY)) {
			vty_out(vty,
				"  Community attribute sent to this neighbor");
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_SEND_COMMUNITY)
			    && CHECK_FLAG(p->af_flags[afi][safi],
					  PEER_FLAG_SEND_EXT_COMMUNITY)
			    && CHECK_FLAG(p->af_flags[afi][safi],
					  PEER_FLAG_SEND_LARGE_COMMUNITY))
				vty_out(vty, "(all)\n");
			else if (CHECK_FLAG(p->af_flags[afi][safi],
					    PEER_FLAG_SEND_LARGE_COMMUNITY))
				vty_out(vty, "(large)\n");
			else if (CHECK_FLAG(p->af_flags[afi][safi],
					    PEER_FLAG_SEND_EXT_COMMUNITY))
				vty_out(vty, "(extended)\n");
			else
				vty_out(vty, "(standard)\n");
		}
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE)) {
			vty_out(vty, "  Default information originate,");

			if (p->default_rmap[afi][safi].name)
				vty_out(vty, " default route-map %s%s,",
					p->default_rmap[afi][safi].map ? "*"
								       : "",
					p->default_rmap[afi][safi].name);
			if (paf && PAF_SUBGRP(paf)
			    && CHECK_FLAG(PAF_SUBGRP(paf)->sflags,
					  SUBGRP_STATUS_DEFAULT_ORIGINATE))
				vty_out(vty, " default sent\n");
			else
				vty_out(vty, " default not sent\n");
		}

		/* advertise-vni-all */
		if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
			if (is_evpn_enabled())
				vty_out(vty, "  advertise-all-vni\n");
		}

		if (filter->plist[FILTER_IN].name
		    || filter->dlist[FILTER_IN].name
		    || filter->aslist[FILTER_IN].name
		    || filter->map[RMAP_IN].name)
			vty_out(vty, "  Inbound path policy configured\n");
		if (filter->plist[FILTER_OUT].name
		    || filter->dlist[FILTER_OUT].name
		    || filter->aslist[FILTER_OUT].name
		    || filter->map[RMAP_OUT].name || filter->usmap.name)
			vty_out(vty, "  Outbound path policy configured\n");

		/* prefix-list */
		if (filter->plist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update prefix filter list is %s%s\n",
				filter->plist[FILTER_IN].plist ? "*" : "",
				filter->plist[FILTER_IN].name);
		if (filter->plist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update prefix filter list is %s%s\n",
				filter->plist[FILTER_OUT].plist ? "*" : "",
				filter->plist[FILTER_OUT].name);

		/* distribute-list */
		if (filter->dlist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update network filter list is %s%s\n",
				filter->dlist[FILTER_IN].alist ? "*" : "",
				filter->dlist[FILTER_IN].name);
		if (filter->dlist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update network filter list is %s%s\n",
				filter->dlist[FILTER_OUT].alist ? "*" : "",
				filter->dlist[FILTER_OUT].name);

		/* filter-list. */
		if (filter->aslist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update AS path filter list is %s%s\n",
				filter->aslist[FILTER_IN].aslist ? "*" : "",
				filter->aslist[FILTER_IN].name);
		if (filter->aslist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update AS path filter list is %s%s\n",
				filter->aslist[FILTER_OUT].aslist ? "*" : "",
				filter->aslist[FILTER_OUT].name);

		/* route-map. */
		if (filter->map[RMAP_IN].name)
			vty_out(vty,
				"  Route map for incoming advertisements is %s%s\n",
				filter->map[RMAP_IN].map ? "*" : "",
				filter->map[RMAP_IN].name);
		if (filter->map[RMAP_OUT].name)
			vty_out(vty,
				"  Route map for outgoing advertisements is %s%s\n",
				filter->map[RMAP_OUT].map ? "*" : "",
				filter->map[RMAP_OUT].name);

		/* ebgp-requires-policy (inbound) */
		if (CHECK_FLAG(p->bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    && !bgp_inbound_policy_exists(p, filter))
			vty_out(vty,
				"  Inbound updates discarded due to missing policy\n");

		/* ebgp-requires-policy (outbound) */
		if (CHECK_FLAG(p->bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    && !bgp_outbound_policy_exists(p, filter))
			vty_out(vty,
				"  Outbound updates discarded due to missing policy\n");

		/* unsuppress-map */
		if (filter->usmap.name)
			vty_out(vty,
				"  Route map for selective unsuppress is %s%s\n",
				filter->usmap.map ? "*" : "",
				filter->usmap.name);

		/* advertise-map */
		if (filter->advmap.aname && filter->advmap.cname)
			vty_out(vty,
				"  Condition %s, Condition-map %s%s, Advertise-map %s%s, status: %s\n",
				filter->advmap.condition ? "EXIST"
							 : "NON_EXIST",
				filter->advmap.cmap ? "*" : "",
				filter->advmap.cname,
				filter->advmap.amap ? "*" : "",
				filter->advmap.aname,
				filter->advmap.update_type ==
						UPDATE_TYPE_ADVERTISE
					? "Advertise"
					: "Withdraw");

		/* Receive and sent prefix count, if available */
		paf = peer_af_find(p, afi, safi);
		if (paf && PAF_SUBGRP(paf))
			vty_out(vty, "  %u accepted, %u sent prefixes\n",
				p->pcount[afi][safi], PAF_SUBGRP(paf)->scount);
		else
			vty_out(vty, "  %u accepted prefixes\n",
				p->pcount[afi][safi]);

		/* maximum-prefix-out */
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_MAX_PREFIX_OUT))
			vty_out(vty,
				"  Maximum allowed prefixes sent %u\n",
				p->pmax_out[afi][safi]);

		/* Maximum prefix */
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX)) {
			vty_out(vty,
				"  Maximum prefixes allowed %u%s\n",
				p->pmax[afi][safi],
				CHECK_FLAG(p->af_flags[afi][safi],
					   PEER_FLAG_MAX_PREFIX_WARNING)
					? " (warning-only)"
					: "");
			vty_out(vty, "  Threshold for warning message %d%%",
				p->pmax_threshold[afi][safi]);
			if (p->pmax_restart[afi][safi])
				vty_out(vty, ", restart interval %d min",
					p->pmax_restart[afi][safi]);
			vty_out(vty, "\n");
		}

		vty_out(vty, "\n");
	}
}

static void bgp_show_peer_status(struct vty *vty, struct peer *p, bool use_json,
				 json_object *json_neigh)
{
	char timebuf[BGP_UPTIME_LEN];

	if (use_json)
		json_object_string_add(json_neigh, "bgpState",
				       lookup_msg(bgp_status_msg,
						  p->connection->status, NULL));
	else
		vty_out(vty, "  BGP state = %s",
			lookup_msg(bgp_status_msg, p->connection->status, NULL));

	if (peer_established(p->connection)) {
		if (use_json) {
			time_t uptime;
			time_t epoch_tbuf;

			uptime = monotime(NULL);
			uptime -= p->uptime;
			epoch_tbuf = time(NULL) - uptime;

			json_object_int_add(json_neigh, "bgpTimerUpMsec",
					    uptime * 1000);
			json_object_string_add(json_neigh, "bgpTimerUpString",
					       peer_uptime(p->uptime, timebuf,
							   BGP_UPTIME_LEN, 0,
							   NULL));
			json_object_int_add(json_neigh,
					    "bgpTimerUpEstablishedEpoch",
					    epoch_tbuf);
		} else
			vty_out(vty, ", up for %8s",
				peer_uptime(p->uptime, timebuf, BGP_UPTIME_LEN,
					    0, NULL));
	} else if (p->connection->status == Active) {
		if (use_json) {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				json_object_string_add(json_neigh, "bgpStateIs",
						       "passive");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				json_object_string_add(json_neigh, "bgpStateIs",
						       "passiveNSF");
		} else {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				vty_out(vty, " (passive)");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				vty_out(vty, " (NSF passive)");
		}
	}
	if (!use_json)
		vty_out(vty, "\n");
}

static void bgp_show_peer(struct vty *vty, struct peer *p, uint16_t sh_flags,
			  bool use_json, json_object *json)
{
	struct bgp *bgp;
	char timebuf[BGP_UPTIME_LEN];
	char dn_flag[2];
	afi_t afi;
	safi_t safi;
	uint16_t i;
	uint8_t *msg;
	json_object *json_neigh = NULL, *json_stat = NULL,
		    *json_addr_family_info = NULL;
	time_t epoch_tbuf;
	uint32_t sync_tcp_mss;
	int len = 0;
	int neighbor_col_default_width = 16;
	struct peer_af *paf;
	const char *afi_safi = NULL;
	uint32_t peer_pcount = 0, peer_scount = 0;
	bool is_first_afi_safi = true;
	bool show_brief = ((CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_ESTABLISHED_INFO) ||
			    CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_FAILED_INFO) ||
			    CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_BRIEF_INFO)));

	bgp = p->bgp;

	if (use_json)
		json_neigh = json_object_new_object();

	memset(dn_flag, '\0', sizeof(dn_flag));
	if (!p->conf_if && peer_dynamic_neighbor(p))
		dn_flag[0] = '*';

	if (show_brief) {
		if (use_json) {
			time_t uptime;

			if (p->hostname)
				json_object_string_add(json_neigh, "hostname",
						       p->hostname);
			else
				json_object_string_add(json_neigh, "hostname",
						       "Unknown");
			asn_asn2json(json_neigh, "remoteAs", p->as,
				     bgp->asnotation);
			if (p->change_local_as)
				asn_asn2json(json_neigh, "localAs",
					     p->change_local_as,
					     bgp->asnotation);
			else
				asn_asn2json(json_neigh, "localAs", p->local_as,
					     bgp->asnotation);
			json_object_string_add(json_neigh, "lastResetDueTo",
					       peer_down_str[(int)p->last_reset]);
			bgp_show_peer_status(vty, p, use_json, json_neigh);

			uptime = monotime(NULL);
			uptime -= p->resettime;

			json_object_int_add(json_neigh, "lastResetTimerMsecs",
					    (int64_t)uptime * 1000);
			json_stat = json_object_new_object();
			json_object_int_add(json_stat, "totalSent",
					    PEER_TOTAL_TX(p));
			json_object_int_add(json_stat, "totalRecv",
					    PEER_TOTAL_RX(p));
			json_object_object_add(json_neigh, "messageStats",
					       json_stat);
			json_addr_family_info = json_object_new_object();
			json_object_object_add(json_neigh, "addressFamilyInfo",
					       json_addr_family_info);
			if (p->conf_if)
				json_object_object_add(json, p->conf_if,
						       json_neigh);
			else
				json_object_object_add(json, p->host, json_neigh);
		} else {
			if (p->hostname &&
			    CHECK_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME))
				len = vty_out(vty, "%s%s(%s)", dn_flag,
					      p->hostname, p->host);
			else
				len = vty_out(vty, "%s%s", dn_flag, p->host);
			if (len < neighbor_col_default_width)
				vty_out(vty, "%*s",
					neighbor_col_default_width - len, " ");
			vty_out(vty, "%10u %9u %9u %10s %12s ", p->as,
				PEER_TOTAL_RX(p), PEER_TOTAL_TX(p),
				peer_uptime(p->resettime, timebuf,
					    BGP_UPTIME_LEN, 0, NULL),
				lookup_msg(bgp_status_msg, p->connection->status,
					   NULL));
		}
		FOREACH_AFI_SAFI (afi, safi) {
			if (p->afc[afi][safi]) {
				paf = peer_af_find(p, afi, safi);
				peer_pcount = p->pcount[afi][safi];
				peer_scount = ((paf && PAF_SUBGRP(paf))
						       ? PAF_SUBGRP(paf)->scount
						       : 0);
				if (!use_json) {
					afi_safi = get_afi_safi_str(afi, safi,
								    false);
					if (is_first_afi_safi) {
						vty_out(vty,
							"%16s %9u %9u\n",
							afi_safi, peer_pcount,
							peer_scount);
						is_first_afi_safi = false;
					} else
						vty_out(vty,
							"%70s %16s %9u %9u\n",
							" ", afi_safi,
							peer_pcount, peer_scount);
				} else {
					afi_safi = get_afi_safi_str(afi, safi,
								    true);
					json_object *json_addr =
						json_object_new_object();
					json_object_int_add(json_addr,
							    "acceptedPrefixCounter",
							    peer_pcount);
					json_object_int_add(json_addr,
							    "sentPrefixCounter",
							    peer_scount);
					json_object_object_add(
						json_addr_family_info, afi_safi,
						json_addr);
				}
			}
		}
		return;
	}

	if (!use_json) {
		if (p->conf_if) /* Configured interface name. */
			vty_out(vty, "BGP neighbor on %s: %pSU, ", p->conf_if,
				&p->connection->su);
		else /* Configured IP address. */
			vty_out(vty, "BGP neighbor is %s%s, ", dn_flag,
				p->host);
	}

	if (use_json) {
		if (p->conf_if && BGP_CONNECTION_SU_UNSPEC(p->connection))
			json_object_string_add(json_neigh, "bgpNeighborAddr",
					       "none");
		else if (p->conf_if && !BGP_CONNECTION_SU_UNSPEC(p->connection))
			json_object_string_addf(json_neigh, "bgpNeighborAddr",
						"%pSU", &p->connection->su);

		asn_asn2json(json_neigh, "remoteAs", p->as, bgp->asnotation);

		if (p->change_local_as)
			asn_asn2json(json_neigh, "localAs", p->change_local_as,
				     bgp->asnotation);
		else
			asn_asn2json(json_neigh, "localAs", p->local_as,
				     bgp->asnotation);

		if (CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND))
			json_object_boolean_true_add(json_neigh,
						     "localAsNoPrepend");

		if (CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS))
			json_object_boolean_true_add(json_neigh,
						     "localAsReplaceAs");

		json_object_boolean_add(json_neigh, "localAsReplaceAsDualAs",
					!!CHECK_FLAG(p->flags,
						     PEER_FLAG_DUAL_AS));
	} else {
		if (p->as_type == AS_SPECIFIED ||
		    CHECK_FLAG(p->as_type, AS_AUTO) ||
		    CHECK_FLAG(p->as_type, AS_EXTERNAL) ||
		    CHECK_FLAG(p->as_type, AS_INTERNAL)) {
			vty_out(vty, "remote AS ");
			vty_out(vty, ASN_FORMAT(bgp->asnotation), &p->as);
			vty_out(vty, ", ");
		} else
			vty_out(vty, "remote AS Unspecified, ");
		vty_out(vty, "local AS ");
		vty_out(vty, ASN_FORMAT(bgp->asnotation),
			p->change_local_as ? &p->change_local_as
					   : &p->local_as);
		vty_out(vty, "%s%s%s, ",
			CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND)
				? " no-prepend"
				: "",
			CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS)
				? " replace-as"
				: "",
			CHECK_FLAG(p->flags, PEER_FLAG_DUAL_AS) ? " dual-as"
								: "");
	}
	/* peer type internal or confed-internal */
	if (p->as == p->local_as || (p->change_local_as && p->as == p->change_local_as) ||
	    CHECK_FLAG(p->as_type, AS_INTERNAL)) {
		if (use_json) {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				json_object_boolean_true_add(
					json_neigh, "nbrConfedInternalLink");
			else
				json_object_boolean_true_add(json_neigh,
							     "nbrInternalLink");
		} else {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				vty_out(vty, "confed-internal link\n");
			else
				vty_out(vty, "internal link\n");
		}
	/* peer type external or confed-external */
	} else if (p->as || CHECK_FLAG(p->as_type, AS_EXTERNAL)) {
		if (use_json) {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				json_object_boolean_true_add(
					json_neigh, "nbrConfedExternalLink");
			else
				json_object_boolean_true_add(json_neigh,
							     "nbrExternalLink");
		} else {
			if (bgp_confederation_peers_check(bgp, p->as))
				vty_out(vty, "confed-external link\n");
			else
				vty_out(vty, "external link\n");
		}
	} else {
		if (use_json)
			json_object_boolean_true_add(json_neigh,
						     "nbrUnspecifiedLink");
		else
			vty_out(vty, "unspecified link\n");
	}

	/* Roles */
	if (use_json) {
		json_object_string_add(json_neigh, "localRole",
				       bgp_get_name_by_role(p->local_role));
		json_object_string_add(json_neigh, "remoteRole",
				       bgp_get_name_by_role(p->remote_role));
	} else {
		vty_out(vty, "  Local Role: %s\n",
			bgp_get_name_by_role(p->local_role));
		vty_out(vty, "  Remote Role: %s\n",
			bgp_get_name_by_role(p->remote_role));
	}

	/* Description. */
	if (p->desc) {
		if (use_json)
			json_object_string_add(json_neigh, "nbrDesc", p->desc);
		else
			vty_out(vty, " Description: %s\n", p->desc);
	}

	if (p->hostname) {
		if (use_json) {
			json_object_string_add(json_neigh, "hostname",
					       p->hostname);

			if (p->domainname)
				json_object_string_add(json_neigh, "domainname",
						       p->domainname);
		} else {
			if (p->domainname && (p->domainname[0] != '\0'))
				vty_out(vty, "Hostname: %s.%s\n", p->hostname,
					p->domainname);
			else
				vty_out(vty, "Hostname: %s\n", p->hostname);
		}
	} else {
		if (use_json)
			json_object_string_add(json_neigh, "hostname",
					       "Unknown");
	}

	/* Peer-group */
	if (p->group) {
		if (use_json) {
			json_object_string_add(json_neigh, "peerGroup",
					       p->group->name);

			if (dn_flag[0]) {
				struct prefix prefix, *range = NULL;

				if (sockunion2hostprefix(&p->connection->su,
							 &prefix))
					range = peer_group_lookup_dynamic_neighbor_range(
						p->group, &prefix);

				if (range) {
					json_object_string_addf(
						json_neigh,
						"peerSubnetRangeGroup", "%pFX",
						range);
				}
			}
		} else {
			vty_out(vty,
				" Member of peer-group %s for session parameters\n",
				p->group->name);

			if (dn_flag[0]) {
				struct prefix prefix, *range = NULL;

				if (sockunion2hostprefix(&p->connection->su,
							 &prefix))
					range = peer_group_lookup_dynamic_neighbor_range(
						p->group, &prefix);

				if (range) {
					vty_out(vty,
						" Belongs to the subnet range group: %pFX\n",
						range);
				}
			}
		}
	}

	if (use_json) {
		/* Administrative shutdown. */
		if (CHECK_FLAG(p->flags, PEER_FLAG_SHUTDOWN)
		    || CHECK_FLAG(p->bgp->flags, BGP_FLAG_SHUTDOWN))
			json_object_boolean_true_add(json_neigh,
						     "adminShutDown");

		/* BGP Version. */
		json_object_int_add(json_neigh, "bgpVersion", 4);
		json_object_string_addf(json_neigh, "remoteRouterId", "%pI4",
					&p->remote_id);
		json_object_string_addf(json_neigh, "localRouterId", "%pI4",
					&bgp->router_id);

		/* Confederation */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
		    && bgp_confederation_peers_check(bgp, p->as))
			json_object_boolean_true_add(json_neigh,
						     "nbrCommonAdmin");

		/* Status. */
		json_object_string_add(json_neigh, "bgpState",
				       lookup_msg(bgp_status_msg,
						  p->connection->status, NULL));

		if (peer_established(p->connection)) {
			time_t uptime;

			uptime = monotime(NULL);
			uptime -= p->uptime;
			epoch_tbuf = time(NULL) - uptime;

			json_object_int_add(json_neigh, "bgpTimerUpMsec",
					    uptime * 1000);
			json_object_string_add(json_neigh, "bgpTimerUpString",
					       peer_uptime(p->uptime, timebuf,
							   BGP_UPTIME_LEN, 0,
							   NULL));
			json_object_int_add(json_neigh,
					    "bgpTimerUpEstablishedEpoch",
					    epoch_tbuf);
		} else if (p->connection->status == Active) {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				json_object_string_add(json_neigh, "bgpStateIs",
						       "passive");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				json_object_string_add(json_neigh, "bgpStateIs",
						       "passiveNSF");
		}

		/* read timer */
		time_t uptime;
		struct tm tm;

		uptime = monotime(NULL);
		uptime -= p->readtime;
		gmtime_r(&uptime, &tm);

		json_object_int_add(json_neigh, "bgpTimerLastRead",
				    (tm.tm_sec * 1000) + (tm.tm_min * 60000)
					    + (tm.tm_hour * 3600000));

		uptime = monotime(NULL);
		uptime -= p->last_write;
		gmtime_r(&uptime, &tm);

		json_object_int_add(json_neigh, "bgpTimerLastWrite",
				    (tm.tm_sec * 1000) + (tm.tm_min * 60000)
					    + (tm.tm_hour * 3600000));

		uptime = monotime(NULL);
		uptime -= p->update_time;
		gmtime_r(&uptime, &tm);

		json_object_int_add(json_neigh, "bgpInUpdateElapsedTimeMsecs",
				    (tm.tm_sec * 1000) + (tm.tm_min * 60000)
					    + (tm.tm_hour * 3600000));

		/* Configured timer values. */
		json_object_int_add(json_neigh,
				    "bgpTimerConfiguredHoldTimeMsecs",
				    CHECK_FLAG(p->flags, PEER_FLAG_TIMER)
					    ? p->holdtime * 1000
					    : bgp->default_holdtime * 1000);
		json_object_int_add(json_neigh,
				    "bgpTimerConfiguredKeepAliveIntervalMsecs",
				    CHECK_FLAG(p->flags, PEER_FLAG_TIMER)
					    ? p->keepalive * 1000
					    : bgp->default_keepalive * 1000);
		json_object_int_add(json_neigh, "bgpTimerHoldTimeMsecs",
				    p->v_holdtime * 1000);
		json_object_int_add(json_neigh,
				    "bgpTimerKeepAliveIntervalMsecs",
				    p->v_keepalive * 1000);
		if (CHECK_FLAG(p->flags, PEER_FLAG_TIMER_DELAYOPEN)) {
			json_object_int_add(json_neigh,
					    "bgpTimerDelayOpenTimeMsecs",
					    p->v_delayopen * 1000);
		}

		/* Configured and Synced tcp-mss value for peer */
		sync_tcp_mss = sockopt_tcp_mss_get(p->connection->fd);
		json_object_int_add(json_neigh, "bgpTcpMssConfigured",
				    p->tcp_mss);
		json_object_int_add(json_neigh, "bgpTcpMssSynced", sync_tcp_mss);

		/* Extended Optional Parameters Length for BGP OPEN Message */
		if (BGP_OPEN_EXT_OPT_PARAMS_CAPABLE(p))
			json_object_boolean_true_add(
				json_neigh, "extendedOptionalParametersLength");
		else
			json_object_boolean_false_add(
				json_neigh, "extendedOptionalParametersLength");

		/* Conditional advertisements */
		json_object_int_add(
			json_neigh,
			"bgpTimerConfiguredConditionalAdvertisementsSec",
			bgp->condition_check_period);
		if (event_is_scheduled(bgp->t_condition_check))
			json_object_int_add(
				json_neigh,
				"bgpTimerUntilConditionalAdvertisementsSec",
				event_timer_remain_second(
					bgp->t_condition_check));
	} else {
		/* Administrative shutdown. */
		if (CHECK_FLAG(p->flags, PEER_FLAG_SHUTDOWN)
		    || CHECK_FLAG(p->bgp->flags, BGP_FLAG_SHUTDOWN))
			vty_out(vty, " Administratively shut down\n");

		/* BGP Version. */
		vty_out(vty, "  BGP version 4");
		vty_out(vty, ", remote router ID %pI4", &p->remote_id);
		vty_out(vty, ", local router ID %pI4\n", &bgp->router_id);

		/* Confederation */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
		    && bgp_confederation_peers_check(bgp, p->as))
			vty_out(vty,
				"  Neighbor under common administration\n");

		/* Status. */
		vty_out(vty, "  BGP state = %s",
			lookup_msg(bgp_status_msg, p->connection->status, NULL));

		if (peer_established(p->connection))
			vty_out(vty, ", up for %8s",
				peer_uptime(p->uptime, timebuf, BGP_UPTIME_LEN,
					    0, NULL));
		else if (p->connection->status == Active) {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				vty_out(vty, " (passive)");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				vty_out(vty, " (NSF passive)");
		}
		vty_out(vty, "\n");

		/* read timer */
		vty_out(vty, "  Last read %s",
			peer_uptime(p->readtime, timebuf, BGP_UPTIME_LEN, 0,
				    NULL));
		vty_out(vty, ", Last write %s\n",
			peer_uptime(p->last_write, timebuf, BGP_UPTIME_LEN, 0,
				    NULL));

		/* Configured timer values. */
		vty_out(vty,
			"  Hold time is %d seconds, keepalive interval is %d seconds\n",
			p->v_holdtime, p->v_keepalive);
		vty_out(vty, "  Configured hold time is %d seconds",
			CHECK_FLAG(p->flags, PEER_FLAG_TIMER)
				? p->holdtime
				: bgp->default_holdtime);
		vty_out(vty, ", keepalive interval is %d seconds\n",
			CHECK_FLAG(p->flags, PEER_FLAG_TIMER)
				? p->keepalive
				: bgp->default_keepalive);
		if (CHECK_FLAG(p->flags, PEER_FLAG_TIMER_DELAYOPEN))
			vty_out(vty,
				"  Configured DelayOpenTime is %d seconds\n",
				p->delayopen);

		/* Configured and synced tcp-mss value for peer */
		sync_tcp_mss = sockopt_tcp_mss_get(p->connection->fd);
		vty_out(vty, "  Configured tcp-mss is %d", p->tcp_mss);
		vty_out(vty, ", synced tcp-mss is %d\n", sync_tcp_mss);

		/* Extended Optional Parameters Length for BGP OPEN Message */
		if (BGP_OPEN_EXT_OPT_PARAMS_CAPABLE(p))
			vty_out(vty,
				"  Extended Optional Parameters Length is enabled\n");

		/* Conditional advertisements */
		vty_out(vty,
			"  Configured conditional advertisements interval is %d seconds\n",
			bgp->condition_check_period);
		if (event_is_scheduled(bgp->t_condition_check))
			vty_out(vty,
				"  Time until conditional advertisements begin is %lu seconds\n",
				event_timer_remain_second(
					bgp->t_condition_check));
	}
	/* Capability. */
	if (peer_established(p->connection) &&
	    (p->cap || peer_afc_advertised(p) || peer_afc_received(p))) {
		if (use_json) {
			json_object *json_cap = NULL;

			json_cap = json_object_new_object();

			/* AS4 */
			if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV))
					json_object_string_add(
						json_cap, "4byteAs",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV))
					json_object_string_add(json_cap,
							       "4byteAs",
							       "advertised");
				else if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV))
					json_object_string_add(json_cap,
							       "4byteAs",
							       "received");
			}

			/* Extended Message Support */
			if (CHECK_FLAG(p->cap, PEER_CAP_EXTENDED_MESSAGE_ADV) &&
			    CHECK_FLAG(p->cap, PEER_CAP_EXTENDED_MESSAGE_RCV))
				json_object_string_add(json_cap,
						       "extendedMessage",
						       "advertisedAndReceived");
			else if (CHECK_FLAG(p->cap,
					    PEER_CAP_EXTENDED_MESSAGE_ADV))
				json_object_string_add(json_cap,
						       "extendedMessage",
						       "advertised");
			else if (CHECK_FLAG(p->cap,
					    PEER_CAP_EXTENDED_MESSAGE_RCV))
				json_object_string_add(json_cap,
						       "extendedMessage",
						       "received");

			/* AddPath */
			if (CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_ADV)) {
				json_object *json_add = NULL;
				const char *print_store;

				json_add = json_object_new_object();

				FOREACH_AFI_SAFI (afi, safi) {
					json_object *json_sub = NULL;
					json_sub = json_object_new_object();
					print_store = get_afi_safi_str(
						afi, safi, true);

					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_RCV)) {
						json_object_boolean_add(
							json_sub,
							"txAdvertisedAndReceived",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_TX_ADV) &&
								CHECK_FLAG(
									p->af_cap[afi]
										 [safi],
									PEER_CAP_ADDPATH_AF_TX_RCV));

						json_object_boolean_add(
							json_sub, "txAdvertised",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_TX_ADV));

						json_object_boolean_add(
							json_sub, "txReceived",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_TX_RCV));
					}

					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_RCV)) {
						json_object_boolean_add(
							json_sub,
							"rxAdvertisedAndReceived",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_RX_ADV) &&
								CHECK_FLAG(
									p->af_cap[afi]
										 [safi],
									PEER_CAP_ADDPATH_AF_RX_RCV));

						json_object_boolean_add(
							json_sub, "rxAdvertised",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_RX_ADV));

						json_object_boolean_add(
							json_sub, "rxReceived",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_RX_RCV));
					}

					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_RCV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_RCV))
						json_object_object_add(
							json_add, print_store,
							json_sub);
					else
						json_object_free(json_sub);
				}

				json_object_object_add(json_cap, "addPath",
						       json_add);
			}

			/* Paths-Limit */
			if (CHECK_FLAG(p->cap, PEER_CAP_PATHS_LIMIT_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_PATHS_LIMIT_ADV)) {
				json_object *json_add = NULL;
				const char *print_store;

				json_add = json_object_new_object();

				FOREACH_AFI_SAFI (afi, safi) {
					json_object *json_sub = NULL;

					json_sub = json_object_new_object();
					print_store = get_afi_safi_str(afi, safi,
								       true);

					if (CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_ADV) ||
					    CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_RCV)) {
						if (CHECK_FLAG(p->af_cap[afi][safi],
							       PEER_CAP_PATHS_LIMIT_AF_ADV) &&
						    CHECK_FLAG(p->af_cap[afi][safi],
							       PEER_CAP_PATHS_LIMIT_AF_RCV)) {
							json_object_boolean_true_add(
								json_sub,
								"advertisedAndReceived");
							json_object_int_add(
								json_sub,
								"advertisedPathsLimit",
								p->addpath_paths_limit
									[afi][safi]
										.send);
							json_object_int_add(
								json_sub,
								"receivedPathsLimit",
								p->addpath_paths_limit
									[afi][safi]
										.receive);
						} else if (CHECK_FLAG(p->af_cap[afi]
									       [safi],
								      PEER_CAP_PATHS_LIMIT_AF_ADV)) {
							json_object_boolean_true_add(
								json_sub,
								"advertised");
							json_object_int_add(
								json_sub,
								"advertisedPathsLimit",
								p->addpath_paths_limit
									[afi][safi]
										.send);
						} else if (CHECK_FLAG(p->af_cap[afi]
									       [safi],
								      PEER_CAP_PATHS_LIMIT_AF_RCV)) {
							json_object_boolean_true_add(
								json_sub,
								"received");
							json_object_int_add(
								json_sub,
								"receivedPathsLimit",
								p->addpath_paths_limit
									[afi][safi]
										.receive);
						}
					}

					if (CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_ADV) ||
					    CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_RCV))
						json_object_object_add(json_add,
								       print_store,
								       json_sub);
					else
						json_object_free(json_sub);
				}

				json_object_object_add(json_cap, "pathsLimit",
						       json_add);
			}

			/* Dynamic */
			if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_ADV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV))
					json_object_string_add(
						json_cap, "dynamic",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_DYNAMIC_ADV))
					json_object_string_add(json_cap,
							       "dynamic",
							       "advertised");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_DYNAMIC_RCV))
					json_object_string_add(json_cap,
							       "dynamic",
							       "received");
			}

			/* Role */
			if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV))
					json_object_string_add(
						json_cap, "role",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV))
					json_object_string_add(json_cap, "role",
							       "advertised");
				else if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV))
					json_object_string_add(json_cap, "role",
							       "received");
			}

			/* Extended nexthop */
			if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV)) {
				json_object *json_nxt = NULL;
				const char *print_store;

				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV))
					json_object_string_add(
						json_cap, "extendedNexthop",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV))
					json_object_string_add(
						json_cap, "extendedNexthop",
						"advertised");
				else if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV))
					json_object_string_add(
						json_cap, "extendedNexthop",
						"received");

				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV)) {
					json_nxt = json_object_new_object();

					for (safi = SAFI_UNICAST;
					     safi < SAFI_MAX; safi++) {
						if (CHECK_FLAG(
							    p->af_cap[AFI_IP]
								     [safi],
							    PEER_CAP_ENHE_AF_RCV)) {
							print_store =
								get_afi_safi_str(
									AFI_IP,
									safi,
									true);
							json_object_string_add(
								json_nxt,
								print_store,
								"recieved"); /* misspelled for compatibility */
						}
					}
					json_object_object_add(
						json_cap,
						"extendedNexthopFamililesByPeer",
						json_nxt);
				}
			}

			/* Long-lived Graceful Restart */
			if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV)) {
				json_object *json_llgr = NULL;
				const char *afi_safi_str;

				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV))
					json_object_string_add(
						json_cap,
						"longLivedGracefulRestart",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV))
					json_object_string_add(
						json_cap,
						"longLivedGracefulRestart",
						"advertised");
				else if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV))
					json_object_string_add(
						json_cap,
						"longLivedGracefulRestart",
						"received");

				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV)) {
					json_llgr = json_object_new_object();

					FOREACH_AFI_SAFI (afi, safi) {
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ENHE_AF_RCV)) {
							afi_safi_str =
								get_afi_safi_str(
									afi,
									safi,
									true);
							json_object_string_add(
								json_llgr,
								afi_safi_str,
								"received");
						}
					}
					json_object_object_add(
						json_cap,
						"longLivedGracefulRestartByPeer",
						json_llgr);
				}
			}

			/* Route Refresh */
			if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_REFRESH_RCV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_REFRESH_RCV))
					json_object_string_add(json_cap,
							       "routeRefresh",
							       "advertisedAndReceived");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_REFRESH_ADV))
					json_object_string_add(json_cap,
							       "routeRefresh",
							       "advertised");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_REFRESH_RCV))
					json_object_string_add(json_cap,
							       "routeRefresh",
							       "received");
			}

			/* Enhanced Route Refresh */
			if (CHECK_FLAG(p->cap, PEER_CAP_ENHANCED_RR_ADV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ENHANCED_RR_RCV)) {
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_ENHANCED_RR_ADV) &&
				    CHECK_FLAG(p->cap,
					       PEER_CAP_ENHANCED_RR_RCV))
					json_object_string_add(
						json_cap,
						"enhancedRouteRefresh",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_ENHANCED_RR_ADV))
					json_object_string_add(
						json_cap,
						"enhancedRouteRefresh",
						"advertised");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_ENHANCED_RR_RCV))
					json_object_string_add(
						json_cap,
						"enhancedRouteRefresh",
						"received");
			}

			/* Multiprotocol Extensions */
			json_object *json_multi = NULL;

			json_multi = json_object_new_object();

			FOREACH_AFI_SAFI (afi, safi) {
				if (p->afc_adv[afi][safi] ||
				    p->afc_recv[afi][safi]) {
					json_object *json_exten = NULL;
					json_exten = json_object_new_object();

					if (p->afc_adv[afi][safi] &&
					    p->afc_recv[afi][safi])
						json_object_boolean_true_add(
							json_exten,
							"advertisedAndReceived");
					else if (p->afc_adv[afi][safi])
						json_object_boolean_true_add(
							json_exten,
							"advertised");
					else if (p->afc_recv[afi][safi])
						json_object_boolean_true_add(
							json_exten, "received");

					json_object_object_add(
						json_multi,
						get_afi_safi_str(afi, safi,
								 true),
						json_exten);
				}
			}
			json_object_object_add(json_cap,
					       "multiprotocolExtensions",
					       json_multi);

			/* Hostname capabilities */
			json_object *json_hname = NULL;

			json_hname = json_object_new_object();

			if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_ADV)) {
				json_object_string_add(
					json_hname, "advHostName",
					bgp->peer_self->hostname
						? bgp->peer_self->hostname
						: "n/a");
				json_object_string_add(
					json_hname, "advDomainName",
					bgp->peer_self->domainname
						? bgp->peer_self->domainname
						: "n/a");
			}

			if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_RCV)) {
				json_object_string_add(
					json_hname, "rcvHostName",
					p->hostname ? p->hostname : "n/a");
				json_object_string_add(
					json_hname, "rcvDomainName",
					p->domainname ? p->domainname : "n/a");
			}

			json_object_object_add(json_cap, "hostName",
					       json_hname);

			/* Software Version capability */
			json_object *json_soft_version = NULL;

			json_soft_version = json_object_new_object();

			if (CHECK_FLAG(p->cap, PEER_CAP_SOFT_VERSION_ADV))
				json_object_string_add(
					json_soft_version,
					"advertisedSoftwareVersion",
					cmd_software_version_get());

			if (CHECK_FLAG(p->cap, PEER_CAP_SOFT_VERSION_RCV))
				json_object_string_add(
					json_soft_version,
					"receivedSoftwareVersion",
					p->soft_version ? p->soft_version
							: "n/a");

			json_object_object_add(json_cap, "softwareVersion",
					       json_soft_version);

			/* Link-Local Next Hop capability */
			json_object *json_link_local = NULL;

			json_link_local = json_object_new_object();
			json_object_boolean_add(json_link_local, "advertised",
						!!CHECK_FLAG(p->cap, PEER_CAP_LINK_LOCAL_ADV));
			json_object_boolean_add(json_link_local, "received",
						!!CHECK_FLAG(p->cap, PEER_CAP_LINK_LOCAL_RCV));
			json_object_object_add(json_cap, "linkLocalNextHop", json_link_local);

			/* Graceful Restart */
			if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
					json_object_string_add(
						json_cap, "gracefulRestart",
						"advertisedAndReceived");
				} else if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV)) {
					json_object_string_add(json_cap, "gracefulRestart",
							       "advertised");
				} else if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
					json_object_string_add(json_cap, "gracefulRestart",
							       "received");
				}

				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
					int restart_af_count = 0;
					json_object *json_restart = NULL;
					json_restart = json_object_new_object();

					json_object_int_add(
						json_cap,
						"gracefulRestartRemoteTimerMsecs",
						p->v_gr_restart * 1000);

					FOREACH_AFI_SAFI (afi, safi) {
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_RESTART_AF_RCV)) {
							json_object *json_sub =
								NULL;
							json_sub =
								json_object_new_object();

							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_RESTART_AF_PRESERVE_RCV))
								json_object_boolean_true_add(
									json_sub,
									"preserved");
							restart_af_count++;
							json_object_object_add(
								json_restart,
								get_afi_safi_str(
									afi,
									safi,
									true),
								json_sub);
						}
					}
					if (!restart_af_count) {
						json_object_string_add(
							json_cap,
							"addressFamiliesByPeer",
							"none");
						json_object_free(json_restart);
					} else
						json_object_object_add(
							json_cap,
							"addressFamiliesByPeer",
							json_restart);
				}
			}
			json_object_object_add(
				json_neigh, "neighborCapabilities", json_cap);
		} else {
			vty_out(vty, "  Neighbor capabilities:\n");

			/* AS4 */
			if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV)) {
				vty_out(vty, "    4 Byte AS:");
				if (CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_AS4_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Extended Message Support */
			if (CHECK_FLAG(p->cap, PEER_CAP_EXTENDED_MESSAGE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_EXTENDED_MESSAGE_ADV)) {
				vty_out(vty, "    Extended Message:");
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_EXTENDED_MESSAGE_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_EXTENDED_MESSAGE_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(
							p->cap,
							PEER_CAP_EXTENDED_MESSAGE_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* AddPath */
			if (CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_ADV)) {
				vty_out(vty, "    AddPath:\n");

				FOREACH_AFI_SAFI (afi, safi) {
					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_RCV)) {
						vty_out(vty, "      %s: TX ",
							get_afi_safi_str(
								afi, safi,
								false));

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_TX_ADV))
							vty_out(vty,
								"advertised");

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_TX_RCV))
							vty_out(vty,
								"%sreceived",
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_ADDPATH_AF_TX_ADV)
									? " and "
									: "");

						vty_out(vty, "\n");
					}

					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_RCV)) {
						vty_out(vty, "      %s: RX ",
							get_afi_safi_str(
								afi, safi,
								false));

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_RX_ADV))
							vty_out(vty,
								"advertised");

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_RX_RCV))
							vty_out(vty,
								"%sreceived",
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_ADDPATH_AF_RX_ADV)
									? " and "
									: "");

						vty_out(vty, "\n");
					}
				}
			}

			/* Paths-Limit */
			if (CHECK_FLAG(p->cap, PEER_CAP_PATHS_LIMIT_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_PATHS_LIMIT_ADV)) {
				vty_out(vty, "    Paths-Limit:\n");

				FOREACH_AFI_SAFI (afi, safi) {
					if (CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_ADV) ||
					    CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_RCV)) {
						vty_out(vty, "      %s: ",
							get_afi_safi_str(afi,
									 safi,
									 false));

						if (CHECK_FLAG(p->af_cap[afi][safi],
							       PEER_CAP_PATHS_LIMIT_AF_ADV))
							vty_out(vty,
								"advertised (%u)",
								p->addpath_paths_limit
									[afi][safi]
										.send);

						if (CHECK_FLAG(p->af_cap[afi][safi],
							       PEER_CAP_PATHS_LIMIT_AF_RCV))
							vty_out(vty,
								"%sreceived (%u)",
								CHECK_FLAG(p->af_cap[afi]
										    [safi],
									   PEER_CAP_PATHS_LIMIT_AF_ADV)
									? " and "
									: "",
								p->addpath_paths_limit
									[afi][safi]
										.receive);

						vty_out(vty, "\n");
					}
				}
			}

			/* Dynamic */
			if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_ADV)) {
				vty_out(vty, "    Dynamic:");
				if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_DYNAMIC_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Role */
			if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV)) {
				vty_out(vty, "    Role:");
				if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_ROLE_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Extended nexthop */
			if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV)) {
				vty_out(vty, "    Extended nexthop:");
				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_ENHE_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");

				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV)) {
					vty_out(vty,
						"      Address families by peer:\n        ");
					for (safi = SAFI_UNICAST;
					     safi < SAFI_MAX; safi++)
						if (CHECK_FLAG(
							    p->af_cap[AFI_IP]
								     [safi],
							    PEER_CAP_ENHE_AF_RCV))
							vty_out(vty,
								"           %s\n",
								get_afi_safi_str(
									AFI_IP,
									safi,
									false));
				}
			}

			/* Long-lived Graceful Restart */
			if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV)) {
				vty_out(vty,
					"    Long-lived Graceful Restart:");
				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_LLGR_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");

				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV)) {
					vty_out(vty,
						"      Address families by peer:\n");
					FOREACH_AFI_SAFI (afi, safi)
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_LLGR_AF_RCV))
							vty_out(vty,
								"           %s\n",
								get_afi_safi_str(
									afi,
									safi,
									false));
				}
			}

			/* Route Refresh */
			if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_REFRESH_RCV)) {
				vty_out(vty, "    Route refresh:");
				if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_REFRESH_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Enhanced Route Refresh */
			if (CHECK_FLAG(p->cap, PEER_CAP_ENHANCED_RR_ADV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ENHANCED_RR_RCV)) {
				vty_out(vty, "    Enhanced Route Refresh:");
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_ENHANCED_RR_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_ENHANCED_RR_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_REFRESH_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Multiprotocol Extensions */
			FOREACH_AFI_SAFI (afi, safi)
				if (p->afc_adv[afi][safi] ||
				    p->afc_recv[afi][safi]) {
					vty_out(vty, "    Address Family %s:",
						get_afi_safi_str(afi, safi,
								 false));
					if (p->afc_adv[afi][safi])
						vty_out(vty, " advertised");
					if (p->afc_recv[afi][safi])
						vty_out(vty, " %sreceived",
							p->afc_adv[afi][safi]
								? "and "
								: "");
					vty_out(vty, "\n");
				}

			/* Hostname capability */
			vty_out(vty, "    Hostname Capability:");

			if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_ADV)) {
				vty_out(vty,
					" advertised (name: %s,domain name: %s)",
					bgp->peer_self->hostname
						? bgp->peer_self->hostname
						: "n/a",
					bgp->peer_self->domainname
						? bgp->peer_self->domainname
						: "n/a");
			} else {
				vty_out(vty, " not advertised");
			}

			if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_RCV)) {
				vty_out(vty,
					" received (name: %s,domain name: %s)",
					p->hostname ? p->hostname : "n/a",
					p->domainname ? p->domainname : "n/a");
			} else {
				vty_out(vty, " not received");
			}

			vty_out(vty, "\n");

			/* Software Version capability */
			vty_out(vty, "    Version Capability:");

			if (CHECK_FLAG(p->cap, PEER_CAP_SOFT_VERSION_ADV)) {
				vty_out(vty,
					" advertised software version (%s)",
					cmd_software_version_get());
			} else
				vty_out(vty, " not advertised");

			if (CHECK_FLAG(p->cap, PEER_CAP_SOFT_VERSION_RCV)) {
				vty_out(vty, " received software version (%s)",
					p->soft_version ? p->soft_version
							: "n/a");
			} else
				vty_out(vty, " not received");

			vty_out(vty, "\n");

			/* Link-Local Next Hop capability */
			vty_out(vty, "    Link-Local Next Hop Capability:");

			if (CHECK_FLAG(p->cap, PEER_CAP_LINK_LOCAL_ADV))
				vty_out(vty, " advertised link-local");
			else
				vty_out(vty, " not advertised");

			if (CHECK_FLAG(p->cap, PEER_CAP_LINK_LOCAL_RCV))
				vty_out(vty, " received link-local");
			else
				vty_out(vty, " not received");

			vty_out(vty, "\n");

			/* Graceful Restart */
			if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV)) {
				vty_out(vty,
					"    Graceful Restart Capability:");
				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_RESTART_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");

				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
					int restart_af_count = 0;

					vty_out(vty,
						"      Remote Restart timer is %d seconds\n",
						p->v_gr_restart);
					vty_out(vty,
						"      Address families by peer:\n        ");

					FOREACH_AFI_SAFI (afi, safi)
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_RESTART_AF_RCV)) {
							vty_out(vty, "%s%s(%s)",
								restart_af_count
									? ", "
									: "",
								get_afi_safi_str(
									afi,
									safi,
									false),
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_RESTART_AF_PRESERVE_RCV)
									? "preserved"
									: "not preserved");
							restart_af_count++;
						}
					if (!restart_af_count)
						vty_out(vty, "none");
					vty_out(vty, "\n");
				}
			} /* Graceful Restart */
		}
	}

	/* graceful restart information */
	json_object *json_grace = NULL;
	json_object *json_grace_send = NULL;
	json_object *json_grace_recv = NULL;
	int eor_send_af_count = 0;
	int eor_receive_af_count = 0;

	if (use_json) {
		json_grace = json_object_new_object();
		json_grace_send = json_object_new_object();
		json_grace_recv = json_object_new_object();

		if ((peer_established(p->connection)) &&
		    CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi],
					       PEER_STATUS_EOR_SEND)) {
					json_object_boolean_true_add(
						json_grace_send,
						get_afi_safi_str(afi, safi,
								 true));
					eor_send_af_count++;
				}
			}
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi],
					       PEER_STATUS_EOR_RECEIVED)) {
					json_object_boolean_true_add(
						json_grace_recv,
						get_afi_safi_str(afi, safi,
								 true));
					eor_receive_af_count++;
				}
			}
		}
		json_object_object_add(json_grace, "endOfRibSend",
				       json_grace_send);
		json_object_object_add(json_grace, "endOfRibRecv",
				       json_grace_recv);

		if (p->connection->t_gr_restart)
			json_object_int_add(json_grace,
					    "gracefulRestartTimerMsecs",
					    event_timer_remain_second(
						    p->connection->t_gr_restart) *
						    1000);

		if (p->connection->t_gr_stale)
			json_object_int_add(json_grace,
					    "gracefulStalepathTimerMsecs",
					    event_timer_remain_second(
						    p->connection->t_gr_stale) *
						    1000);
		/* more gr info in new format */
		BGP_SHOW_PEER_GR_CAPABILITY(vty, p, json_grace);
		json_object_object_add(json_neigh, "gracefulRestartInfo",
				       json_grace);
	} else {
		vty_out(vty, "  Graceful restart information:\n");
		if ((peer_established(p->connection)) &&
		    CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
			vty_out(vty, "    End-of-RIB send: ");
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi],
					       PEER_STATUS_EOR_SEND)) {
					vty_out(vty, "%s%s",
						eor_send_af_count ? ", " : "",
						get_afi_safi_str(afi, safi,
								 false));
					eor_send_af_count++;
				}
			}
			vty_out(vty, "\n");
			vty_out(vty, "    End-of-RIB received: ");
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi],
					       PEER_STATUS_EOR_RECEIVED)) {
					vty_out(vty, "%s%s",
						eor_receive_af_count ? ", "
								     : "",
						get_afi_safi_str(afi, safi,
								 false));
					eor_receive_af_count++;
				}
			}
			vty_out(vty, "\n");
		}

		if (p->connection->t_gr_restart)
			vty_out(vty,
				"    The remaining time of restart timer is %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_restart));

		if (p->connection->t_gr_stale)
			vty_out(vty,
				"    The remaining time of stalepath timer is %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_stale));

		/* more gr info in new format */
		BGP_SHOW_PEER_GR_CAPABILITY(vty, p, NULL);
	}

	if (use_json) {
		json_object *json_stat = NULL;
		json_object *json_pfx_stat = NULL;

		json_stat = json_object_new_object();
		json_pfx_stat = json_object_new_object();

		/* Packet counts. */
		atomic_size_t outq_count, inq_count;
		outq_count = atomic_load_explicit(&p->connection->obuf->count,
						  memory_order_relaxed);
		inq_count = atomic_load_explicit(&p->connection->ibuf->count,
						 memory_order_relaxed);

		json_object_int_add(json_stat, "depthInq",
				    (unsigned long)inq_count);
		json_object_int_add(json_stat, "depthOutq",
				    (unsigned long)outq_count);
		json_object_int_add(json_stat, "opensSent",
				    atomic_load_explicit(&p->open_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "opensRecv",
				    atomic_load_explicit(&p->open_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "notificationsSent",
				    atomic_load_explicit(&p->notify_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "notificationsRecv",
				    atomic_load_explicit(&p->notify_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "updatesSent",
				    atomic_load_explicit(&p->update_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "updatesRecv",
				    atomic_load_explicit(&p->update_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "keepalivesSent",
				    atomic_load_explicit(&p->keepalive_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "keepalivesRecv",
				    atomic_load_explicit(&p->keepalive_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "routeRefreshSent",
				    atomic_load_explicit(&p->refresh_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "routeRefreshRecv",
				    atomic_load_explicit(&p->refresh_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "capabilitySent",
				    atomic_load_explicit(&p->dynamic_cap_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "capabilityRecv",
				    atomic_load_explicit(&p->dynamic_cap_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "totalSent", PEER_TOTAL_TX(p));
		json_object_int_add(json_stat, "totalRecv", PEER_TOTAL_RX(p));
		json_object_object_add(json_neigh, "messageStats", json_stat);

		/* Prefix statistics */
		json_object_int_add(json_pfx_stat, "inboundFiltered", p->stat_pfx_filter);
		json_object_int_add(json_pfx_stat, "aspathLoop", p->stat_pfx_aspath_loop);
		json_object_int_add(json_pfx_stat, "originatorLoop", p->stat_pfx_originator_loop);
		json_object_int_add(json_pfx_stat, "clusterLoop", p->stat_pfx_cluster_loop);
		json_object_int_add(json_pfx_stat, "invalidNextHop", p->stat_pfx_nh_invalid);
		json_object_int_add(json_pfx_stat, "withdrawn", p->stat_pfx_withdraw);
		json_object_int_add(json_pfx_stat, "attributesDiscarded", p->stat_pfx_discard);
		json_object_object_add(json_neigh, "prefixStats", json_pfx_stat);
	} else {
		atomic_size_t outq_count, inq_count, open_out, open_in,
			notify_out, notify_in, update_out, update_in,
			keepalive_out, keepalive_in, refresh_out, refresh_in,
			dynamic_cap_out, dynamic_cap_in;
		outq_count = atomic_load_explicit(&p->connection->obuf->count,
						  memory_order_relaxed);
		inq_count = atomic_load_explicit(&p->connection->ibuf->count,
						 memory_order_relaxed);
		open_out = atomic_load_explicit(&p->open_out,
						memory_order_relaxed);
		open_in =
			atomic_load_explicit(&p->open_in, memory_order_relaxed);
		notify_out = atomic_load_explicit(&p->notify_out,
						  memory_order_relaxed);
		notify_in = atomic_load_explicit(&p->notify_in,
						 memory_order_relaxed);
		update_out = atomic_load_explicit(&p->update_out,
						  memory_order_relaxed);
		update_in = atomic_load_explicit(&p->update_in,
						 memory_order_relaxed);
		keepalive_out = atomic_load_explicit(&p->keepalive_out,
						     memory_order_relaxed);
		keepalive_in = atomic_load_explicit(&p->keepalive_in,
						    memory_order_relaxed);
		refresh_out = atomic_load_explicit(&p->refresh_out,
						   memory_order_relaxed);
		refresh_in = atomic_load_explicit(&p->refresh_in,
						  memory_order_relaxed);
		dynamic_cap_out = atomic_load_explicit(&p->dynamic_cap_out,
						       memory_order_relaxed);
		dynamic_cap_in = atomic_load_explicit(&p->dynamic_cap_in,
						      memory_order_relaxed);

		/* Packet counts. */
		vty_out(vty, "  Message statistics:\n");
		vty_out(vty, "    Inq depth is %zu\n", inq_count);
		vty_out(vty, "    Outq depth is %zu\n", outq_count);
		vty_out(vty, "                         Sent       Rcvd\n");
		vty_out(vty, "    Opens:         %10zu %10zu\n", open_out,
			open_in);
		vty_out(vty, "    Notifications: %10zu %10zu\n", notify_out,
			notify_in);
		vty_out(vty, "    Updates:       %10zu %10zu\n", update_out,
			update_in);
		vty_out(vty, "    Keepalives:    %10zu %10zu\n", keepalive_out,
			keepalive_in);
		vty_out(vty, "    Route Refresh: %10zu %10zu\n", refresh_out,
			refresh_in);
		vty_out(vty, "    Capability:    %10zu %10zu\n",
			dynamic_cap_out, dynamic_cap_in);
		vty_out(vty, "    Total:         %10u %10u\n\n", (uint32_t)PEER_TOTAL_TX(p),
			(uint32_t)PEER_TOTAL_RX(p));

		/* Prefix statistics */
		vty_out(vty, "  Prefix statistics:\n");
		vty_out(vty, "    Inbound filtered: %u\n", p->stat_pfx_filter);
		vty_out(vty, "    AS-PATH loop: %u\n", p->stat_pfx_aspath_loop);
		vty_out(vty, "    Originator loop: %u\n", p->stat_pfx_originator_loop);
		vty_out(vty, "    Cluster loop: %u\n", p->stat_pfx_cluster_loop);
		vty_out(vty, "    Invalid next-hop: %u\n", p->stat_pfx_nh_invalid);
		vty_out(vty, "    Withdrawn: %u\n", p->stat_pfx_withdraw);
		vty_out(vty, "    Attributes discarded: %u\n\n", p->stat_pfx_discard);
	}

	if (use_json) {
		/* advertisement-interval */
		json_object_int_add(json_neigh,
				    "minBtwnAdvertisementRunsTimerMsecs",
				    p->v_routeadv * 1000);

		/* Update-source. */
		if (p->update_if || p->update_source) {
			if (p->update_if)
				json_object_string_add(json_neigh,
						       "updateSource",
						       p->update_if);
			else if (p->update_source)
				json_object_string_addf(json_neigh,
							"updateSource", "%pSU",
							p->update_source);
		}
	} else {
		/* advertisement-interval */
		vty_out(vty,
			"  Minimum time between advertisement runs is %d seconds\n",
			p->v_routeadv);

		/* Update-source. */
		if (p->update_if || p->update_source) {
			vty_out(vty, "  Update source is ");
			if (p->update_if)
				vty_out(vty, "%s", p->update_if);
			else if (p->update_source)
				vty_out(vty, "%pSU", p->update_source);
			vty_out(vty, "\n");
		}

		vty_out(vty, "\n");
	}

	/* Address Family Information */
	json_object *json_hold = NULL;

	if (use_json)
		json_hold = json_object_new_object();

	FOREACH_AFI_SAFI (afi, safi)
		if (p->afc[afi][safi])
			bgp_show_peer_afi(vty, p, afi, safi, use_json,
					  json_hold);

	if (use_json) {
		json_object_object_add(json_neigh, "addressFamilyInfo",
				       json_hold);
		json_object_int_add(json_neigh, "connectionsEstablished",
				    p->established);
		json_object_int_add(json_neigh, "connectionsDropped",
				    p->dropped);
	} else
		vty_out(vty, "  Connections established %d; dropped %d\n",
			p->established, p->dropped);

	if (!p->last_reset) {
		if (use_json)
			json_object_string_add(json_neigh, "lastReset",
					       "never");
		else
			vty_out(vty, "  Last reset never\n");
	} else {
		if (use_json) {
			time_t uptime;
			struct tm tm;

			uptime = monotime(NULL);
			uptime -= p->resettime;
			gmtime_r(&uptime, &tm);

			json_object_int_add(json_neigh, "lastResetTimerMsecs",
					    (tm.tm_sec * 1000)
						    + (tm.tm_min * 60000)
						    + (tm.tm_hour * 3600000));
			bgp_show_peer_reset(NULL, p, json_neigh, true);
		} else {
			vty_out(vty, "  Last reset %s, ",
				peer_uptime(p->resettime, timebuf,
					    BGP_UPTIME_LEN, 0, NULL));

			bgp_show_peer_reset(vty, p, NULL, false);
			if (p->last_reset_cause) {
				msg = p->last_reset_cause->data;
				vty_out(vty,
					"  Message received that caused BGP to send a NOTIFICATION:\n    ");
				for (i = 1; i <= p->last_reset_cause->size;
				     i++) {
					vty_out(vty, "%02X", *msg++);

					if (i != p->last_reset_cause->size) {
						if (i % 16 == 0) {
							vty_out(vty, "\n    ");
						} else if (i % 4 == 0) {
							vty_out(vty, " ");
						}
					}
				}
				vty_out(vty, "\n");
			}
		}
	}

	if (CHECK_FLAG(p->sflags, PEER_STATUS_PREFIX_OVERFLOW)) {
		if (use_json)
			json_object_boolean_true_add(json_neigh,
						     "prefixesConfigExceedMax");
		else
			vty_out(vty,
				"  Peer had exceeded the max. no. of prefixes configured.\n");

		if (p->connection->t_pmax_restart) {
			if (use_json) {
				json_object_boolean_true_add(
					json_neigh, "reducePrefixNumFrom");
				json_object_int_add(json_neigh,
						    "restartInTimerMsec",
						    event_timer_remain_second(
							    p->connection
								    ->t_pmax_restart) *
							    1000);
			} else
				vty_out(vty,
					"  Reduce the no. of prefix from %s, will restart in %ld seconds\n",
					p->host,
					event_timer_remain_second(
						p->connection->t_pmax_restart));
		} else {
			if (use_json)
				json_object_boolean_true_add(
					json_neigh,
					"reducePrefixNumAndClearIpBgp");
			else
				vty_out(vty,
					"  Reduce the no. of prefix and clear ip bgp %s to restore peering\n",
					p->host);
		}
	}

	/* EBGP Multihop and GTSM */
	if (p->sort != BGP_PEER_IBGP) {
		if (use_json) {
			if (p->gtsm_hops > BGP_GTSM_HOPS_DISABLED)
				json_object_int_add(json_neigh,
						    "externalBgpNbrMaxHopsAway",
						    p->gtsm_hops);
			else
				json_object_int_add(json_neigh,
						    "externalBgpNbrMaxHopsAway",
						    p->ttl);
		} else {
			if (p->gtsm_hops > BGP_GTSM_HOPS_DISABLED)
				vty_out(vty,
					"  External BGP neighbor may be up to %d hops away.\n",
					p->gtsm_hops);
			else
				vty_out(vty,
					"  External BGP neighbor may be up to %d hops away.\n",
					p->ttl);
		}
	} else {
		if (use_json) {
			if (p->gtsm_hops > BGP_GTSM_HOPS_DISABLED)
				json_object_int_add(json_neigh,
						    "internalBgpNbrMaxHopsAway",
						    p->gtsm_hops);
			else
				json_object_int_add(json_neigh,
						    "internalBgpNbrMaxHopsAway",
						    p->ttl);
		} else {
			if (p->gtsm_hops > BGP_GTSM_HOPS_DISABLED)
				vty_out(vty,
					"  Internal BGP neighbor may be up to %d hops away.\n",
					p->gtsm_hops);
			else
				vty_out(vty,
					"  Internal BGP neighbor may be up to %d hops away.\n",
					p->ttl);
		}
	}

	/* Local address. */
	if (p->connection->su_local) {
		if (use_json) {
			json_object_string_addf(json_neigh, "hostLocal", "%pSU",
						p->connection->su_local);
			json_object_int_add(json_neigh, "portLocal",
					    ntohs(p->connection->su_local->sin.sin_port));
		} else
			vty_out(vty, "Local host: %pSU, Local port: %d\n", p->connection->su_local,
				ntohs(p->connection->su_local->sin.sin_port));
	} else {
		if (use_json) {
			json_object_string_add(json_neigh, "hostLocal",
					       "Unknown");
			json_object_int_add(json_neigh, "portLocal", -1);
		}
	}

	/* Remote address. */
	if (p->connection->su_remote) {
		if (use_json) {
			json_object_string_addf(json_neigh, "hostForeign", "%pSU",
						p->connection->su_remote);
			json_object_int_add(json_neigh, "portForeign",
					    ntohs(p->connection->su_remote->sin.sin_port));
		} else
			vty_out(vty, "Foreign host: %pSU, Foreign port: %d\n",
				p->connection->su_remote,
				ntohs(p->connection->su_remote->sin.sin_port));
	} else {
		if (use_json) {
			json_object_string_add(json_neigh, "hostForeign",
					       "Unknown");
			json_object_int_add(json_neigh, "portForeign", -1);
		}
	}

	/* Nexthop display. */
	if (p->connection->su_local) {
		if (use_json) {
			json_object_string_addf(json_neigh, "nexthop", "%pI4",
						&p->nexthop.v4);
			json_object_string_addf(json_neigh, "nexthopGlobal",
						"%pI6", &p->nexthop.v6_global);
			json_object_string_addf(json_neigh, "nexthopLocal",
						"%pI6", &p->nexthop.v6_local);
			if (p->shared_network)
				json_object_string_add(json_neigh,
						       "bgpConnection",
						       "sharedNetwork");
			else
				json_object_string_add(json_neigh,
						       "bgpConnection",
						       "nonSharedNetwork");
		} else {
			vty_out(vty, "Nexthop: %pI4\n", &p->nexthop.v4);
			vty_out(vty, "Nexthop global: %pI6\n",
				&p->nexthop.v6_global);
			vty_out(vty, "Nexthop local: %pI6\n",
				&p->nexthop.v6_local);
			vty_out(vty, "BGP connection: %s\n",
				p->shared_network ? "shared network"
						  : "non shared network");
		}
	} else {
		if (use_json) {
			json_object_string_add(json_neigh, "nexthop",
					       "Unknown");
			json_object_string_add(json_neigh, "nexthopGlobal",
					       "Unknown");
			json_object_string_add(json_neigh, "nexthopLocal",
					       "Unknown");
			json_object_string_add(json_neigh, "bgpConnection",
					       "Unknown");
		}
	}

	/* Timer information. */
	if (use_json) {
		json_object_int_add(json_neigh, "connectRetryTimer",
				    p->v_connect);
		if (peer_established(p->connection)) {
			json_object_int_add(json_neigh, "estimatedRttInMsecs",
					    p->rtt);
			if (CHECK_FLAG(p->flags, PEER_FLAG_RTT_SHUTDOWN)) {
				json_object_int_add(json_neigh,
						    "shutdownRttInMsecs",
						    p->rtt_expected);
				json_object_int_add(json_neigh,
						    "shutdownRttAfterCount",
						    p->rtt_keepalive_rcv);
			}
		}
		if (p->bfd_config) {
			json_object_int_add(json_neigh, "bfdHoldTimerExpireInMsecs",
					    event_timer_remain_second(p->bfd_config->t_hold_timer) *
						    1000);
			json_object_boolean_add(json_neigh, "bfdHoldTimerExpired",
						!!CHECK_FLAG(p->sflags,
							     PEER_STATUS_BFD_STRICT_HOLD_TIME_EXPIRED));
		}
		if (p->connection->t_start)
			json_object_int_add(json_neigh,
					    "nextStartTimerDueInMsecs",
					    event_timer_remain_second(
						    p->connection->t_start) *
						    1000);
		if (p->connection->t_connect)
			json_object_int_add(json_neigh,
					    "nextConnectTimerDueInMsecs",
					    event_timer_remain_second(
						    p->connection->t_connect) *
						    1000);
		if (p->connection->t_routeadv) {
			json_object_int_add(json_neigh, "mraiInterval",
					    p->v_routeadv);
			json_object_int_add(json_neigh, "mraiTimerExpireInMsecs",
					    event_timer_remain_second(
						    p->connection->t_routeadv) *
						    1000);
		}
		if (p->password)
			json_object_int_add(json_neigh, "authenticationEnabled",
					    1);

		if (p->connection->t_read)
			json_object_string_add(json_neigh, "readThread", "on");
		else
			json_object_string_add(json_neigh, "readThread", "off");

		if (CHECK_FLAG(p->connection->thread_flags,
			       PEER_THREAD_WRITES_ON))
			json_object_string_add(json_neigh, "writeThread", "on");
		else
			json_object_string_add(json_neigh, "writeThread",
					       "off");
	} else {
		vty_out(vty, "BGP Connect Retry Timer in Seconds: %d\n",
			p->v_connect);
		if (peer_established(p->connection)) {
			vty_out(vty, "Estimated round trip time: %d ms\n",
				p->rtt);
			if (CHECK_FLAG(p->flags, PEER_FLAG_RTT_SHUTDOWN))
				vty_out(vty,
					"Shutdown when RTT > %dms, count > %u\n",
					p->rtt_expected, p->rtt_keepalive_rcv);
		}
		if (p->connection->t_start)
			vty_out(vty, "Next start timer due in %ld seconds\n",
				event_timer_remain_second(
					p->connection->t_start));
		if (p->connection->t_connect)
			vty_out(vty, "Next connect timer due in %ld seconds\n",
				event_timer_remain_second(
					p->connection->t_connect));
		if (p->connection->t_routeadv)
			vty_out(vty,
				"MRAI (interval %u) timer expires in %ld seconds\n",
				p->v_routeadv,
				event_timer_remain_second(
					p->connection->t_routeadv));

		if (p->bfd_config)
			vty_out(vty, "BFD Hold Time (interval %u) timer expires in %ld seconds\n",
				p->bfd_config->hold_time,
				event_timer_remain_second(p->bfd_config->t_hold_timer));

		if (p->password)
			vty_out(vty, "Peer Authentication Enabled\n");

		vty_out(vty, "Read thread: %s  Write thread: %s  FD used: %d\n",
			p->connection->t_read ? "on" : "off",
			CHECK_FLAG(p->connection->thread_flags,
				   PEER_THREAD_WRITES_ON)
				? "on"
				: "off",
			p->connection->fd);
	}

	if (p->notify.code == BGP_NOTIFY_OPEN_ERR
	    && p->notify.subcode == BGP_NOTIFY_OPEN_UNSUP_CAPBL)
		bgp_capability_vty_out(vty, p, use_json, json_neigh);

	if (!use_json)
		vty_out(vty, "\n");

	/* BFD information. */
	if (p->bfd_config)
		bgp_bfd_show_info(vty, p, json_neigh);

	if (use_json) {
		if (p->conf_if) /* Configured interface name. */
			json_object_object_add(json, p->conf_if, json_neigh);
		else /* Configured IP address. */
			json_object_object_add(json, p->host, json_neigh);
	}
}

static int bgp_show_neighbor_graceful_restart(struct vty *vty, struct bgp *bgp,
					      enum show_type type,
					      union sockunion *su,
					      const char *conf_if, afi_t afi,
					      json_object *json)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	bool found = false;
	safi_t safi = SAFI_UNICAST;
	json_object *json_neighbor = NULL;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {

		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		if ((peer->afc[afi][safi]) == 0)
			continue;

		if (json)
			json_neighbor = json_object_new_object();

		if (type == show_all) {
			bgp_show_peer_gr_status(vty, peer, json_neighbor);

			if (json)
				json_object_object_add(json, peer->host,
						       json_neighbor);

		} else if (type == show_peer) {
			if (conf_if) {
				if ((peer->conf_if
				     && !strcmp(peer->conf_if, conf_if))
				    || (peer->hostname
					&& !strcmp(peer->hostname, conf_if))) {
					found = true;
					bgp_show_peer_gr_status(vty, peer,
								json_neighbor);
				}
			} else {
				if (sockunion_same(&peer->connection->su, su)) {
					found = true;
					bgp_show_peer_gr_status(vty, peer,
								json_neighbor);
				}
			}
			if (json) {
				if (found)
					json_object_object_add(json, peer->host,
							       json_neighbor);
				else
					json_object_free(json_neighbor);
			}
		}

		if (found)
			break;
	}

	if (type == show_peer && !found) {
		if (json)
			json_object_boolean_true_add(json, "bgpNoSuchNeighbor");
		else
			vty_out(vty, "%% No such neighbor\n");
	}

	if (!json)
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

static bool match_peer_state(struct peer *bpeer, uint32_t sh_flags)
{
	bool show_estab = CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_ESTABLISHED_INFO);
	bool show_not_estab = CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_FAILED_INFO);

	/* show flags for bgp state is not enabled */
	if (!(show_estab || show_not_estab))
		return true;
	/* show flag for bgp state established is enabled and
	 * bgp state is established
	 */
	else if (show_estab && bpeer->connection &&
		 peer_established(bpeer->connection))
		return true;
	/* show flag for bgp state failed (not-established)
	 * is enabled and bgp state is not established
	 */
	else if (show_not_estab && bpeer->connection &&
		 !peer_established(bpeer->connection))
		return true;

	/* peer state does not match with show flag */
	return false;
}

static int bgp_show_neighbor(struct vty *vty, struct bgp *bgp,
			     enum show_type type, union sockunion *su,
			     const char *conf_if, uint16_t sh_flags,
			     bool use_json, json_object *json)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	int find = 0;
	bool nbr_output = false;
	bool is_first = true;
	bool show_brief = ((CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_ESTABLISHED_INFO) ||
			    CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_FAILED_INFO) ||
			    CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_BRIEF_INFO)));
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;

	if (type == show_ipv4_peer || type == show_ipv4_all) {
		afi = AFI_IP;
	} else if (type == show_ipv6_peer || type == show_ipv6_all) {
		afi = AFI_IP6;
	}

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		switch (type) {
		case show_all:
			if (!match_peer_state(peer, sh_flags))
				continue;
			if (show_brief && is_first && !use_json) {
				vty_out(vty, BGP_SHOW_NEIGHBORS_BRIEF_HEADER);
				is_first = false;
			}
			bgp_show_peer(vty, peer, sh_flags, use_json, json);
			nbr_output = true;
			break;
		case show_peer:
			if (conf_if) {
				if ((peer->conf_if
				     && !strcmp(peer->conf_if, conf_if))
				    || (peer->hostname
					&& !strcmp(peer->hostname, conf_if))) {
					find = 1;
					bgp_show_peer(vty, peer, sh_flags,
						      use_json, json);
				}
			} else {
				if (sockunion_same(&peer->connection->su, su)) {
					find = 1;
					bgp_show_peer(vty, peer, sh_flags,
						      use_json, json);
				}
			}
			break;
		case show_ipv4_peer:
		case show_ipv6_peer:
			FOREACH_SAFI (safi) {
				if (peer->afc[afi][safi]) {
					if (conf_if) {
						if ((peer->conf_if
						     && !strcmp(peer->conf_if, conf_if))
						    || (peer->hostname
							&& !strcmp(peer->hostname, conf_if))) {
							find = 1;
							bgp_show_peer(vty, peer, sh_flags,
								      use_json, json);
							break;
						}
					} else {
						if (sockunion_same(&peer->connection
									    ->su,
								   su)) {
							find = 1;
							bgp_show_peer(vty, peer, sh_flags,
								      use_json, json);
							break;
						}
					}
				}
			}
			break;
		case show_ipv4_all:
		case show_ipv6_all:
			FOREACH_SAFI (safi) {
				if (peer->afc[afi][safi]) {
					if (!match_peer_state(peer, sh_flags))
						break;
					if (show_brief && is_first && !use_json) {
						vty_out(vty,
							BGP_SHOW_NEIGHBORS_BRIEF_HEADER);
						is_first = false;
					}
					bgp_show_peer(vty, peer, sh_flags,
						      use_json, json);
					nbr_output = true;
					break;
				}
			}
			break;
		}
	}

	if ((type == show_peer || type == show_ipv4_peer ||
	     type == show_ipv6_peer) && !find) {
		if (use_json)
			json_object_boolean_true_add(json, "bgpNoSuchNeighbor");
		else
			vty_out(vty, "%% No such neighbor in this view/vrf\n");
	}

	if (type != show_peer && type != show_ipv4_peer &&
	    type != show_ipv6_peer && !nbr_output && !use_json)
		vty_out(vty, "%% No BGP neighbors found\n");

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
	} else {
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

static void bgp_show_neighbor_graceful_restart_vty(struct vty *vty, struct bgp *bgp,
						   enum show_type type, const char *ip_str,
						   afi_t afi, json_object *json)
{
	int ret;
	union sockunion su;

	if (!json)
		bgp_show_global_graceful_restart_mode_vty(vty, bgp);

	if (ip_str) {
		ret = str2sockunion(ip_str, &su);
		if (ret < 0)
			bgp_show_neighbor_graceful_restart(vty, bgp, type, NULL,
							   ip_str, afi, json);
		else
			bgp_show_neighbor_graceful_restart(vty, bgp, type, &su,
							   NULL, afi, json);
	} else
		bgp_show_neighbor_graceful_restart(vty, bgp, type, NULL, NULL,
						   afi, json);
}

static void bgp_show_all_instances_neighbors_vty(struct vty *vty,
						 enum show_type type,
						 const char *ip_str,
						 uint16_t sh_flags,
						 bool use_json)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	union sockunion su;
	json_object *json = NULL;
	int ret, is_first = 1;
	bool nbr_output = false;

	if (use_json)
		vty_out(vty, "{\n");

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;

		nbr_output = true;
		if (use_json) {
			if (!(json = json_object_new_object())) {
				flog_err(
					EC_BGP_JSON_MEM_ERROR,
					"Unable to allocate memory for JSON object");
				vty_out(vty,
					"{\"error\": {\"message:\": \"Unable to allocate memory for JSON object\"}}}\n");
				return;
			}

			json_object_int_add(json, "vrfId",
					    (bgp->vrf_id == VRF_UNKNOWN)
						    ? -1
						    : (int64_t)bgp->vrf_id);
			json_object_string_add(
				json, "vrfName",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);

			if (!is_first)
				vty_out(vty, ",\n");
			else
				is_first = 0;

			vty_out(vty, "\"%s\":",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		} else {
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		}

		if (type == show_peer || type == show_ipv4_peer ||
		    type == show_ipv6_peer) {
			ret = str2sockunion(ip_str, &su);
			if (ret < 0)
				bgp_show_neighbor(vty, bgp, type, NULL, ip_str,
						  sh_flags, use_json, json);
			else
				bgp_show_neighbor(vty, bgp, type, &su, NULL,
						  sh_flags, use_json, json);
		} else {
			bgp_show_neighbor(vty, bgp, type, NULL, NULL,
					  sh_flags, use_json, json);
		}
		json_object_free(json);
		json = NULL;
	}

	if (use_json)
		vty_out(vty, "}\n");
	else if (!nbr_output)
		vty_out(vty, "%% BGP instance not found\n");
}

static int bgp_show_neighbor_vty(struct vty *vty, const char *name,
				 enum show_type type, const char *ip_str,
				 uint16_t sh_flags, bool use_json)
{
	int ret;
	struct bgp *bgp;
	union sockunion su;
	json_object *json = NULL;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_neighbors_vty(vty, type, ip_str,
							     sh_flags,
							     use_json);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);
			if (!bgp) {
				if (use_json) {
					json = json_object_new_object();
					vty_json(vty, json);
				} else
					vty_out(vty,
						"%% BGP instance not found\n");

				return CMD_WARNING;
			}
		}
	} else {
		bgp = bgp_get_default();
	}

	if (bgp) {
		json = json_object_new_object();
		if (ip_str) {
			ret = str2sockunion(ip_str, &su);
			if (ret < 0)
				bgp_show_neighbor(vty, bgp, type, NULL, ip_str,
						  sh_flags, use_json, json);
			else
				bgp_show_neighbor(vty, bgp, type, &su, NULL,
						  sh_flags, use_json, json);
		} else {
			bgp_show_neighbor(vty, bgp, type, NULL, NULL, sh_flags,
					  use_json, json);
		}
		json_object_free(json);
	} else {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% BGP instance not found\n");
	}

	return CMD_SUCCESS;
}

/* "show [ip] bgp neighbors graceful-restart" commands.  */
DEFPY (show_ip_bgp_neighbors_graceful_restart,
       show_ip_bgp_neighbors_graceful_restart_cmd,
       "show bgp [<ipv4|ipv6>]$afi [<view|vrf> VIEWVRFNAME$vrf] neighbors [<A.B.C.D|X:X::X:X|WORD>$neigh] graceful-restart [json]$json",
       SHOW_STR
       BGP_STR
       IP_STR
       IPV6_STR
       BGP_INSTANCE_HELP_STR
       NEIGHBOR_STR
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       GR_SHOW
       JSON_STR)
{
	enum show_type sh_type = show_all;
	afi_t afiz = AFI_IP;
	bool uj = !!json;
	struct bgp *bgp;

	if (afi)
		afiz = bgp_vty_afi_from_str(afi);

	if (neigh)
		sh_type = show_peer;

	bgp = vrf ? bgp_lookup_by_name(vrf) : bgp_get_default();

	if (!bgp) {
		vty_out(vty, "No such bgp instance %s", vrf ? vrf : "");
		return CMD_WARNING;
	}

	return bgp_show_neighbor_graceful_restart_afi_all(vty, bgp, sh_type, neigh, afiz, uj);
}

/* "show [ip] bgp neighbors" commands.  */
DEFPY(show_ip_bgp_neighbors, show_ip_bgp_neighbors_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6>] neighbors [<A.B.C.D|X:X::X:X|WORD>] [json$uj [brief$brief [established|failed]]]",
      SHOW_STR
      IP_STR
      BGP_STR
      BGP_INSTANCE_HELP_STR
      BGP_AF_STR
      BGP_AF_STR
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      JSON_STR
      "Brief information on BGP neighbors (JSON output)\n"
      "Display only neighbors in Established state\n"
      "Display only neighbors not in Established state\n")
{
	char *vrf = NULL;
	char *sh_arg = NULL;
	enum show_type sh_type;
	afi_t afi = AFI_MAX;
	bool use_json = !!uj;
	uint16_t peer_show_flags = 0;
	int idx = 0;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;

	idx++;

	if (argv_find(argv, argc, "ipv4", &idx)) {
		sh_type = show_ipv4_all;
		afi = AFI_IP;
	} else if (argv_find(argv, argc, "ipv6", &idx)) {
		sh_type = show_ipv6_all;
		afi = AFI_IP6;
	} else {
		sh_type = show_all;
	}

	if (argv_find(argv, argc, "A.B.C.D", &idx)
	    || argv_find(argv, argc, "X:X::X:X", &idx)
	    || argv_find(argv, argc, "WORD", &idx)) {
		sh_type = show_peer;
		sh_arg = argv[idx]->arg;
	}

	if (sh_type == show_peer && afi == AFI_IP) {
		sh_type = show_ipv4_peer;
	} else if (sh_type == show_peer && afi == AFI_IP6) {
		sh_type = show_ipv6_peer;
	}

	if (use_json && brief) {
		SET_FLAG(peer_show_flags, VTY_BGP_PEER_SHOW_BRIEF_INFO);
		idx = 0;
		if (argv_find(argv, argc, "established", &idx))
			SET_FLAG(peer_show_flags,
				 VTY_BGP_PEER_SHOW_STATE_ESTABLISHED_INFO);
		else if (argv_find(argv, argc, "failed", &idx))
			SET_FLAG(peer_show_flags,
				 VTY_BGP_PEER_SHOW_STATE_FAILED_INFO);
	}

	return bgp_show_neighbor_vty(vty, vrf, sh_type, sh_arg, peer_show_flags,
				     use_json);
}

/* Show BGP's AS paths internal data.  There are both `show [ip] bgp
   paths' and `show ip mbgp paths'.  Those functions results are the
   same.*/
DEFUN (show_ip_bgp_paths,
       show_ip_bgp_paths_cmd,
       "show [ip] bgp ["BGP_SAFI_CMD_STR"] paths",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_SAFI_HELP_STR
       "Path information\n")
{
	vty_out(vty, "Address Refcnt Path\n");
	aspath_print_all_vty(vty);
	return CMD_SUCCESS;
}

#include "hash.h"

static void community_show_all_iterator(struct hash_bucket *bucket,
					struct vty *vty)
{
	struct community *com;

	com = (struct community *)bucket->data;
	vty_out(vty, "[%p] (%ld) %s\n", (void *)com, com->refcnt,
		community_str(com, false, false));
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_community_info,
       show_ip_bgp_community_info_cmd,
       "show [ip] bgp community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")
{
	vty_out(vty, "Address Refcnt Community\n");

	hash_iterate(community_hash(),
		     (void (*)(struct hash_bucket *,
			       void *))community_show_all_iterator,
		     vty);

	return CMD_SUCCESS;
}

static void lcommunity_show_all_iterator(struct hash_bucket *bucket,
					 struct vty *vty)
{
	struct lcommunity *lcom;

	lcom = (struct lcommunity *)bucket->data;
	vty_out(vty, "[%p] (%ld) %s\n", (void *)lcom, lcom->refcnt,
		lcommunity_str(lcom, false, false));
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_lcommunity_info,
       show_ip_bgp_lcommunity_info_cmd,
       "show ip bgp large-community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp large-community information\n")
{
	vty_out(vty, "Address Refcnt Large-community\n");

	hash_iterate(lcommunity_hash(),
		     (void (*)(struct hash_bucket *,
			       void *))lcommunity_show_all_iterator,
		     vty);

	return CMD_SUCCESS;
}
/* Graceful Restart */

static void bgp_show_global_graceful_restart_mode_vty(struct vty *vty,
						      struct bgp *bgp)
{

	vty_out(vty, "\n%s", SHOW_GR_HEADER);

	enum global_mode bgp_global_gr_mode = bgp_global_gr_mode_get(bgp);

	switch (bgp_global_gr_mode) {

	case GLOBAL_HELPER:
		vty_out(vty, "Global BGP GR Mode :  Helper\n");
		break;

	case GLOBAL_GR:
		vty_out(vty, "Global BGP GR Mode :  Restart\n");
		break;

	case GLOBAL_DISABLE:
		vty_out(vty, "Global BGP GR Mode :  Disable\n");
		break;

	case GLOBAL_INVALID:
		vty_out(vty,
			"Global BGP GR Mode  Invalid\n");
		break;
	}
	vty_out(vty, "\n");
}

static int bgp_show_neighbor_graceful_restart_afi_all(struct vty *vty, struct bgp *bgp,
						      enum show_type type, const char *ip_str,
						      afi_t afi, bool use_json)
{
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if ((afi == AFI_MAX) && (ip_str == NULL)) {
		afi = AFI_IP;

		while ((afi != AFI_L2VPN) && (afi < AFI_MAX)) {
			bgp_show_neighbor_graceful_restart_vty(vty, bgp, type, ip_str, afi, json);
			afi++;
		}
	} else if (afi != AFI_MAX) {
		bgp_show_neighbor_graceful_restart_vty(vty, bgp, type, ip_str, afi, json);
	} else {
		if (json)
			json_object_free(json);
		return CMD_ERR_INCOMPLETE;
	}

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}
/* Graceful Restart */

DEFPY (show_ip_bgp_attr_info,
       show_ip_bgp_attr_info_cmd,
       "show [ip] bgp attribute-info [summary$summary]",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp attribute information\n"
       "Display summary of BGP attributes\n")
{
	attr_show_all(vty, summary);
	return CMD_SUCCESS;
}

static int bgp_show_route_leak_vty(struct vty *vty, const char *name,
				   afi_t afi, safi_t safi,
				   bool use_json, json_object *json)
{
	struct bgp *bgp;
	struct listnode *node;
	char *vname;
	char *ecom_str;
	enum vpn_policy_direction dir;

	if (json) {
		json_object *json_import_vrfs = NULL;
		json_object *json_export_vrfs = NULL;

		bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

		if (!bgp) {
			vty_json(vty, json);

			return CMD_WARNING;
		}

		/* Provide context for the block */
		json_object_string_add(json, "vrf", name ? name : "default");
		json_object_string_add(json, "afiSafi",
				       get_afi_safi_str(afi, safi, true));

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			json_object_string_add(json, "importFromVrfs", "none");
			json_object_string_add(json, "importRts", "none");
		} else {
			json_import_vrfs = json_object_new_array();

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].import_vrf,
						node, vname))
				json_object_array_add(json_import_vrfs,
						json_object_new_string(vname));

			json_object_object_add(json, "importFromVrfs",
						       json_import_vrfs);
			dir = BGP_VPN_POLICY_DIR_FROMVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					bgp->vpn_policy[afi].rtlist[dir],
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				json_object_string_add(json, "importRts",
						       ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				json_object_string_add(json, "importRts",
						       "none");
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			json_object_string_add(json, "exportToVrfs", "none");
			json_object_string_add(json, "routeDistinguisher",
					       "none");
			json_object_string_add(json, "exportRts", "none");
		} else {
			json_export_vrfs = json_object_new_array();

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].export_vrf,
						node, vname))
				json_object_array_add(json_export_vrfs,
						json_object_new_string(vname));
			json_object_object_add(json, "exportToVrfs",
					       json_export_vrfs);
			json_object_string_addf(json, "routeDistinguisher",
						BGP_RD_AS_FORMAT(bgp->asnotation),
						&bgp->vpn_policy[afi].tovpn_rd);
			dir = BGP_VPN_POLICY_DIR_TOVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					       bgp->vpn_policy[afi].rtlist[dir],
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				json_object_string_add(json, "exportRts",
						       ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				json_object_string_add(json, "exportRts",
						       "none");
		}

		if (use_json) {
			vty_json(vty, json);
		}
	} else {
		bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

		if (!bgp) {
			vty_out(vty, "%% No such BGP instance exist\n");
			return CMD_WARNING;
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_IMPORT))
			vty_out(vty,
		     "This VRF is not importing %s routes from any other VRF\n",
		      get_afi_safi_str(afi, safi, false));
		else {
			vty_out(vty,
		   "This VRF is importing %s routes from the following VRFs:\n",
		    get_afi_safi_str(afi, safi, false));

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].import_vrf,
						node, vname))
				vty_out(vty, "  %s\n", vname);

			dir = BGP_VPN_POLICY_DIR_FROMVPN;
			ecom_str = NULL;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					       bgp->vpn_policy[afi].rtlist[dir],
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, "Import RT(s): %s\n", ecom_str);

				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				vty_out(vty, "Import RT(s):\n");
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_EXPORT))
			vty_out(vty,
		       "This VRF is not exporting %s routes to any other VRF\n",
			get_afi_safi_str(afi, safi, false));
		else {
			vty_out(vty,
		       "This VRF is exporting %s routes to the following VRFs:\n",
			get_afi_safi_str(afi, safi, false));

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].export_vrf,
						node, vname))
				vty_out(vty, "  %s\n", vname);

			vty_out(vty, "RD: ");
			vty_out(vty, BGP_RD_AS_FORMAT(bgp->asnotation),
				&bgp->vpn_policy[afi].tovpn_rd);
			vty_out(vty, "\n");

			dir = BGP_VPN_POLICY_DIR_TOVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					bgp->vpn_policy[afi].rtlist[dir],
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, "Export RT: %s\n", ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				vty_out(vty, "Import RT(s):\n");
		}
	}

	return CMD_SUCCESS;
}

static int bgp_show_all_instance_route_leak_vty(struct vty *vty, afi_t afi,
						safi_t safi, bool use_json)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	char *vrf_name = NULL;
	json_object *json = NULL;
	json_object *json_vrf = NULL;
	json_object *json_vrfs = NULL;

	if (use_json) {
		json = json_object_new_object();
		json_vrfs = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {

		if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
			vrf_name = bgp->name;

		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		if (use_json) {
			json_vrf = json_object_new_object();
		} else {
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				? VRF_DEFAULT_NAME : bgp->name);
		}
		bgp_show_route_leak_vty(vty, vrf_name, afi, safi, 0, json_vrf);
		if (use_json) {
			if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				json_object_object_add(json_vrfs,
						VRF_DEFAULT_NAME, json_vrf);
			else
				json_object_object_add(json_vrfs, vrf_name,
						       json_vrf);
		}
	}

	if (use_json) {
		json_object_object_add(json, "vrfs", json_vrfs);
		vty_json(vty, json);
	}

	return CMD_SUCCESS;
}

/* "show [ip] bgp route-leak" command.  */
DEFUN (show_ip_bgp_route_leak,
	show_ip_bgp_route_leak_cmd,
	"show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] route-leak  [json]",
	SHOW_STR
	IP_STR
	BGP_STR
	BGP_INSTANCE_HELP_STR
	BGP_AFI_HELP_STR
	BGP_SAFI_HELP_STR
	"Route leaking information\n"
	JSON_STR)
{
	char *vrf = NULL;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;

	bool uj = use_json(argc, argv);
	int idx = 0;
	json_object *json = NULL;

	/* show [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
	}
	/* [vrf VIEWVRFNAME] */
	if (argv_find(argv, argc, "view", &idx)) {
		vty_out(vty,
			"%% This command is not applicable to BGP views\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	}
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi))
		argv_find_and_parse_safi(argv, argc, &idx, &safi);

	if (!((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST)) {
		vty_out(vty,
			"%% This command is applicable only for unicast ipv4|ipv6\n");
		return CMD_WARNING;
	}

	if (vrf && strmatch(vrf, "all"))
		return bgp_show_all_instance_route_leak_vty(vty, afi, safi, uj);

	if (uj)
		json = json_object_new_object();

	return bgp_show_route_leak_vty(vty, vrf, afi, safi, uj, json);
}

static void bgp_show_all_instances_updgrps_vty(struct vty *vty, afi_t afi,
					       safi_t safi, bool uj)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;

		if (!uj)
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);

		update_group_show(bgp, afi, safi, vty, 0, uj);
	}
}

static int bgp_show_update_groups(struct vty *vty, const char *name, int afi,
				  int safi, uint64_t subgrp_id, bool uj)
{
	struct bgp *bgp;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_updgrps_vty(vty, afi, safi, uj);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);
		}
	} else {
		bgp = bgp_get_default();
	}

	if (bgp)
		update_group_show(bgp, afi, safi, vty, subgrp_id, uj);
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_updgrps,
       show_ip_bgp_updgrps_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] update-groups [SUBGROUP-ID] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Detailed info about dynamic update groups\n"
       "Specific subgroup to display detailed info for\n"
       JSON_STR)
{
	char *vrf = NULL;
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	uint64_t subgrp_id = 0;

	int idx = 0;

	bool uj = use_json(argc, argv);

	/* show [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		argv_find_and_parse_safi(argv, argc, &idx, &safi);
	}

	/* get subgroup id, if provided */
	idx = argc - 1;
	if (argv[idx]->type == VARIABLE_TKN)
		subgrp_id = strtoull(argv[idx]->arg, NULL, 10);

	return (bgp_show_update_groups(vty, vrf, afi, safi, subgrp_id, uj));
}

DEFUN (show_bgp_instance_all_ipv6_updgrps,
       show_bgp_instance_all_ipv6_updgrps_cmd,
       "show [ip] bgp <view|vrf> all update-groups [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Detailed info about dynamic update groups\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);

	bgp_show_all_instances_updgrps_vty(vty, AFI_IP6, SAFI_UNICAST, uj);
	return CMD_SUCCESS;
}

DEFUN (show_bgp_l2vpn_evpn_updgrps,
	show_bgp_l2vpn_evpn_updgrps_cmd,
	"show [ip] bgp l2vpn evpn update-groups",
	SHOW_STR
	IP_STR
	BGP_STR
	"l2vpn address family\n"
	"evpn sub-address family\n"
	"Detailed info about dynamic update groups\n")
{
	char *vrf = NULL;
	uint64_t subgrp_id = 0;

	bgp_show_update_groups(vty, vrf, AFI_L2VPN, SAFI_EVPN, subgrp_id, 0);
	return CMD_SUCCESS;
}

DEFUN (show_bgp_updgrps_stats,
       show_bgp_updgrps_stats_cmd,
       "show [ip] bgp update-groups statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed info about dynamic update groups\n"
       "Statistics\n")
{
	struct bgp *bgp;

	bgp = bgp_get_default();
	if (bgp && !IS_BGP_INSTANCE_HIDDEN(bgp))
		update_group_show_stats(bgp, vty);

	return CMD_SUCCESS;
}

DEFUN (show_bgp_instance_updgrps_stats,
       show_bgp_instance_updgrps_stats_cmd,
       "show [ip] bgp <view|vrf> VIEWVRFNAME update-groups statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed info about dynamic update groups\n"
       "Statistics\n")
{
	int idx_word = 3;
	struct bgp *bgp;

	bgp = bgp_lookup_by_name(argv[idx_word]->arg);
	if (bgp)
		update_group_show_stats(bgp, vty);

	return CMD_SUCCESS;
}

static void show_bgp_updgrps_adj_info_aux(struct vty *vty, const char *name,
					  afi_t afi, safi_t safi,
					  const char *what, uint64_t subgrp_id)
{
	struct bgp *bgp;

	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();

	if (bgp) {
		if (!strcmp(what, "advertise-queue"))
			update_group_show_adj_queue(bgp, afi, safi, vty,
						    subgrp_id);
		else if (!strcmp(what, "advertised-routes"))
			update_group_show_advertised(bgp, afi, safi, vty,
						     subgrp_id);
		else if (!strcmp(what, "packet-queue"))
			update_group_show_packet_queue(bgp, afi, safi, vty,
						       subgrp_id);
	}
}

DEFPY(show_ip_bgp_instance_updgrps_adj_s,
      show_ip_bgp_instance_updgrps_adj_s_cmd,
      "show [ip]$ip bgp [<view|vrf> VIEWVRFNAME$vrf] [<ipv4|ipv6>$afi <unicast|multicast|vpn>$safi] update-groups [SUBGROUP-ID]$sgid <advertise-queue|advertised-routes|packet-queue>$rtq",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_HELP_STR
      "Detailed info about dynamic update groups\n"
      "Specific subgroup to display info for\n"
      "Advertisement queue\n"
      "Announced routes\n"
      "Packet queue\n")
{
	uint64_t subgrp_id = 0;
	afi_t afiz;
	safi_t safiz;
	if (sgid)
		subgrp_id = strtoull(sgid, NULL, 10);

	if (!ip && !afi)
		afiz = AFI_IP6;
	if (!ip && afi)
		afiz = bgp_vty_afi_from_str(afi);
	if (ip && !afi)
		afiz = AFI_IP;
	if (ip && afi) {
		afiz = bgp_vty_afi_from_str(afi);
		if (afiz != AFI_IP)
			vty_out(vty,
				"%% Cannot specify both 'ip' and 'ipv6'\n");
		return CMD_WARNING;
	}

	safiz = safi ? bgp_vty_safi_from_str(safi) : SAFI_UNICAST;

	show_bgp_updgrps_adj_info_aux(vty, vrf, afiz, safiz, rtq, subgrp_id);
	return CMD_SUCCESS;
}

static int bgp_show_one_peer_group(struct vty *vty, struct peer_group *group,
				   json_object *json)
{
	struct listnode *node, *nnode;
	struct prefix *range;
	struct peer *conf;
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *peer_status;
	int lr_count;
	int dynamic;
	bool af_cfgd = false;
	json_object *json_peer_group = NULL;
	json_object *json_peer_group_afc = NULL;
	json_object *json_peer_group_members = NULL;
	json_object *json_peer_group_dynamic = NULL;
	json_object *json_peer_group_dynamic_af = NULL;
	json_object *json_peer_group_ranges = NULL;
	uint16_t member_count = 0;

	conf = group->conf;

	if (json) {
		json_peer_group = json_object_new_object();
		json_peer_group_afc = json_object_new_array();
	}

	if (conf->as_type == AS_SPECIFIED || conf->as_type == AS_EXTERNAL) {
		if (json)
			asn_asn2json(json_peer_group, "remoteAs", conf->as,
				     bgp_get_asnotation(conf->bgp));
		else {
			vty_out(vty, "\nBGP peer-group %s, remote AS ",
				group->name);
			vty_out(vty, ASN_FORMAT(bgp_get_asnotation(conf->bgp)),
				&conf->as);
			vty_out(vty, "\n");
		}
	} else if (CHECK_FLAG(conf->as_type, AS_INTERNAL)) {
		if (json)
			asn_asn2json(json, "remoteAs", group->bgp->as,
				     group->bgp->asnotation);
		else
			vty_out(vty, "\nBGP peer-group %s, remote AS %s\n",
				group->name, group->bgp->as_pretty);
	} else {
		if (!json)
			vty_out(vty, "\nBGP peer-group %s\n", group->name);
	}

	if (CHECK_FLAG(conf->as_type, AS_AUTO)) {
		if (json)
			json_object_string_add(json_peer_group, "type", "auto");
		else
			vty_out(vty, "  Peer-group type is auto\n");
	} else if ((group->bgp->as == conf->as) ||
		   CHECK_FLAG(conf->as_type, AS_INTERNAL)) {
		if (json)
			json_object_string_add(json_peer_group, "type",
					       "internal");
		else
			vty_out(vty, "  Peer-group type is internal\n");
	} else {
		if (json)
			json_object_string_add(json_peer_group, "type",
					       "external");
		else
			vty_out(vty, "  Peer-group type is external\n");
	}

	/* Display AFs configured. */
	if (!json)
		vty_out(vty, "  Configured address-families:");

	FOREACH_AFI_SAFI (afi, safi) {
		if (conf->afc[afi][safi]) {
			af_cfgd = true;
			if (json)
				json_object_array_add(
					json_peer_group_afc,
					json_object_new_string(get_afi_safi_str(
						afi, safi, false)));
			else
				vty_out(vty, " %s;",
					get_afi_safi_str(afi, safi, false));
		}
	}

	if (json) {
		json_object_object_add(json_peer_group,
				       "addressFamiliesConfigured",
				       json_peer_group_afc);
	} else {
		if (!af_cfgd)
			vty_out(vty, " none\n");
		else
			vty_out(vty, "\n");
	}

	/* Display listen ranges (for dynamic neighbors), if any */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		lr_count = listcount(group->listen_range[afi]);
		if (lr_count) {
			if (json) {
				if (!json_peer_group_dynamic)
					json_peer_group_dynamic =
						json_object_new_object();

				json_peer_group_dynamic_af =
					json_object_new_object();
				json_peer_group_ranges =
					json_object_new_array();
				json_object_int_add(json_peer_group_dynamic_af,
						    "count", lr_count);
			} else {
				vty_out(vty, "  %d %s listen range(s)\n",
					lr_count, afi2str(afi));
			}

			for (ALL_LIST_ELEMENTS(group->listen_range[afi], node,
					       nnode, range)) {
				if (json) {
					char buf[BUFSIZ];

					snprintfrr(buf, sizeof(buf), "%pFX",
						   range);

					json_object_array_add(
						json_peer_group_ranges,
						json_object_new_string(buf));
				} else {
					vty_out(vty, "    %pFX\n", range);
				}
			}

			if (json) {
				json_object_object_add(
					json_peer_group_dynamic_af, "ranges",
					json_peer_group_ranges);

				json_object_object_add(
					json_peer_group_dynamic, afi2str(afi),
					json_peer_group_dynamic_af);
			}
		}
	}

	if (json_peer_group_dynamic)
		json_object_object_add(json_peer_group, "dynamicRanges",
				       json_peer_group_dynamic);

	/* Display group members and their status */
	if (listcount(group->peer)) {
		if (json)
			json_peer_group_members = json_object_new_object();
		else
			vty_out(vty, "  Peer-group members:\n");
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN)
			    || CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SHUTDOWN))
				peer_status = "Idle (Admin)";
			else if (CHECK_FLAG(peer->sflags,
					    PEER_STATUS_PREFIX_OVERFLOW))
				peer_status = "Idle (PfxCt)";
			else
				peer_status =
					lookup_msg(bgp_status_msg,
						   peer->connection->status,
						   NULL);

			dynamic = peer_dynamic_neighbor(peer);

			if (json) {
				json_object *json_peer_group_member =
					json_object_new_object();

				json_object_string_add(json_peer_group_member,
						       "status", peer_status);

				if (dynamic)
					json_object_boolean_true_add(
						json_peer_group_member,
						"dynamic");

				json_object_object_add(json_peer_group_members,
						       peer->host,
						       json_peer_group_member);
			} else {
				vty_out(vty, "    %s %s %s \n", peer->host,
					dynamic ? "(dynamic)" : "",
					peer_status);
			}
			member_count++;
		}
	}

	if (json) {
		json_object_int_add(json_peer_group, "memberCount", member_count);
		if (member_count)
			json_object_object_add(json_peer_group, "members", json_peer_group_members);
	}

	if (json)
		json_object_object_add(json, group->name, json_peer_group);

	return CMD_SUCCESS;
}

static int bgp_show_peer_group_vty(struct vty *vty, const char *name,
				   const char *group_name, bool uj)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer_group *group;
	bool found = false;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

	if (!bgp) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty, "%% BGP instance not found\n");

		return CMD_WARNING;
	}

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		if (group_name) {
			if (strmatch(group->name, group_name)) {
				bgp_show_one_peer_group(vty, group, json);
				found = true;
				break;
			}
		} else {
			bgp_show_one_peer_group(vty, group, json);
		}
	}

	if (group_name && !found && !uj)
		vty_out(vty, "%% No such peer-group\n");

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFUN(show_ip_bgp_peer_groups, show_ip_bgp_peer_groups_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] peer-group [PGNAME] [json]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR
      "Detailed information on BGP peer groups\n"
      "Peer group name\n" JSON_STR)
{
	char *vrf, *pg;
	int idx = 0;
	bool uj = use_json(argc, argv);

	vrf = argv_find(argv, argc, "VIEWVRFNAME", &idx) ? argv[idx]->arg
							 : NULL;
	pg = argv_find(argv, argc, "PGNAME", &idx) ? argv[idx]->arg : NULL;

	return bgp_show_peer_group_vty(vty, vrf, pg, uj);
}

/* Redistribute VTY commands.  */

DEFPY(bgp_redistribute_ipv6_table, bgp_redistribute_ipv6_table_cmd,
      "redistribute table-direct (1-65535)$table_id [{metric$metric (0-4294967295)$metric_val|route-map WORD$rmap}]",
      "Redistribute information from another routing protocol\n"
      "Non-main Kernel Routing Table - Direct\n"
      "Table ID\n"
      "Metric for redistributed routes\n"
      "Default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bool changed = false;
	struct route_map *route_map = NULL;
	struct bgp_redist *red;

	if (rmap)
		route_map = route_map_lookup_warn_noexist(vty, rmap);

	if (bgp->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"%% Only default BGP instance can use 'table-direct'\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (table_id == RT_TABLE_MAIN || table_id == RT_TABLE_LOCAL) {
		vty_out(vty,
			"%% 'table-direct', can not use %llu routing table\n",
			table_id);
		return CMD_WARNING_CONFIG_FAILED;
	}

	red = bgp_redist_add(bgp, AFI_IP6, ZEBRA_ROUTE_TABLE_DIRECT, table_id);
	if (rmap)
		changed = bgp_redistribute_rmap_set(red, rmap, route_map);
	if (metric)
		changed |= bgp_redistribute_metric_set(bgp, red, AFI_IP6,
						       ZEBRA_ROUTE_TABLE_DIRECT,
						       metric_val);
	return bgp_redistribute_set(bgp, AFI_IP6, ZEBRA_ROUTE_TABLE_DIRECT,
				    table_id, changed);
}

DEFPY(no_bgp_redistribute_ipv6_table, no_bgp_redistribute_ipv6_table_cmd,
      "no redistribute table-direct (1-65535)$table_id [{metric (0-4294967295)|route-map WORD}]",
      NO_STR
      "Redistribute information from another routing protocol\n"
      "Non-main Kernel Routing Table - Direct\n"
      "Table ID\n"
      "Metric for redistributed routes\n"
      "Default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (bgp->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"%% Only default BGP instance can use 'table-direct'\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (table_id == RT_TABLE_MAIN || table_id == RT_TABLE_LOCAL) {
		vty_out(vty,
			"%% 'table-direct', can not use %llu routing table\n",
			table_id);
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_redistribute_unset(bgp, AFI_IP6, ZEBRA_ROUTE_TABLE_DIRECT, table_id);
	return CMD_SUCCESS;
}

/* peer-group helpers for config-write */

bool peergroup_flag_check(struct peer *peer, uint64_t flag)
{
	if (!peer_group_active(peer)) {
		if (CHECK_FLAG(peer->flags_invert, flag))
			return !CHECK_FLAG(peer->flags, flag);
		else
			return !!CHECK_FLAG(peer->flags, flag);
	}

	return !!CHECK_FLAG(peer->flags_override, flag);
}

bool peergroup_af_flag_check(struct peer *peer, afi_t afi, safi_t safi,
			     uint64_t flag)
{
	if (!peer_group_active(peer)) {
		if (CHECK_FLAG(peer->af_flags_invert[afi][safi], flag))
			return !peer_af_flag_check(peer, afi, safi, flag);
		else
			return peer_af_flag_check(peer, afi, safi, flag);
	}

	return !!CHECK_FLAG(peer->af_flags_override[afi][safi], flag);
}

int bgp_config_write(struct vty *vty)
{
	int write = 0;

	/*
	 * When bgpd is an mgmtd backend, the YANG tree config is output by
	 * mgmtd's config_write. This function only outputs daemon-level
	 * (bm/bgp_master) settings that are NOT in the YANG tree.
	 */
	hook_call(bgp_snmp_traps_config_write, vty);

	if (bm->rmap_update_timer != RMAP_DEFAULT_UPDATE_TIMER) {
		vty_out(vty, "bgp route-map delay-timer %u\n",
			bm->rmap_update_timer);
		write++;
	}

	if (bm->v_update_delay != BGP_UPDATE_DELAY_DEFAULT) {
		vty_out(vty, "bgp update-delay %d", bm->v_update_delay);
		if (bm->v_update_delay != bm->v_establish_wait)
			vty_out(vty, " %d", bm->v_establish_wait);
		vty_out(vty, "\n");
		write++;
	}

	/* bgp suppress-fib-pending now emitted by mgmtd cli_show on
	 * /frr-bgp:daemon-settings/suppress-fib-pending — see
	 * bgpd_suppress_fib_pending_cli_show in bgp_cli.c. */

	if (bm->stalepath_time != BGP_DEFAULT_STALEPATH_TIME) {
		vty_out(vty, "bgp graceful-restart stalepath-time %u\n",
			bm->stalepath_time);
		write++;
	}

	if (bm->restart_time != BGP_DEFAULT_RESTART_TIME) {
		vty_out(vty, "bgp graceful-restart restart-time %u\n",
			bm->restart_time);
		write++;
	}

	if (bm->select_defer_time != BGP_DEFAULT_SELECT_DEFERRAL_TIME) {
		vty_out(vty, "bgp graceful-restart select-defer-time %u\n",
			bm->select_defer_time);
		write++;
	}

	/* bgp graceful-restart (RESTARTER) now emitted by mgmtd cli_show on
	 * /frr-bgp:daemon-settings/graceful-restart/enabled — see
	 * bgpd_graceful_restart_enabled_cli_show in bgp_cli.c.
	 * Other GR master flags still emit here pending migration. */
	if (CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED)) {
		vty_out(vty, "bgp graceful-restart-disable\n");
		write++;
	}

	if (CHECK_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD)) {
		vty_out(vty, "bgp graceful-restart preserve-fw-state\n");
		write++;
	}

	if (bm->rib_stale_time != BGP_DEFAULT_RIB_STALE_TIME) {
		vty_out(vty, "bgp graceful-restart rib-stale-time %u\n",
			bm->rib_stale_time);
		write++;
	}

	if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN)) {
		vty_out(vty, "bgp graceful-shutdown\n");
		write++;
	}

	/* No-RIB (Zebra) option flag configuration */
	if (bgp_option_check(BGP_OPT_NO_FIB)) {
		vty_out(vty, "bgp no-rib\n");
		write++;
	}

	/* send-extra-data default is ON, so output when disabled */
	if (!CHECK_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA)) {
		vty_out(vty, "no bgp send-extra-data zebra\n");
		write++;
	}

	if (CHECK_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA)) {
		vty_out(vty, "no bgp ipv6-auto-ra\n");
		write++;
	}

	/* DSCP value for outgoing packets in BGP connections */
	if (bm->ip_tos != IPTOS_PREC_INTERNETCONTROL) {
		vty_out(vty, "bgp session-dscp %u\n", bm->ip_tos >> 2);
		write++;
	}

	/* BGP InQ limit */
	if (bm->inq_limit != BM_DEFAULT_Q_LIMIT) {
		vty_out(vty, "bgp input-queue-limit %u\n", bm->inq_limit);
		write++;
	}

	if (bm->outq_limit != BM_DEFAULT_Q_LIMIT) {
		vty_out(vty, "bgp output-queue-limit %u\n", bm->outq_limit);
		write++;
	}

	return write;
}

/* BGP node structure. */
static struct cmd_node bgp_node = {
	.name = "bgp",
	.node = BGP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = bgp_config_write,
};

static struct cmd_node bgp_ipv4_unicast_node = {
	.name = "bgp ipv4 unicast",
	.node = BGP_IPV4_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv4_multicast_node = {
	.name = "bgp ipv4 multicast",
	.node = BGP_IPV4M_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv4_labeled_unicast_node = {
	.name = "bgp ipv4 labeled unicast",
	.node = BGP_IPV4L_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv6_unicast_node = {
	.name = "bgp ipv6 unicast",
	.node = BGP_IPV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv6_multicast_node = {
	.name = "bgp ipv6 multicast",
	.node = BGP_IPV6M_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv6_labeled_unicast_node = {
	.name = "bgp ipv6 labeled unicast",
	.node = BGP_IPV6L_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_vpnv4_node = {
	.name = "bgp vpnv4",
	.node = BGP_VPNV4_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_vpnv6_node = {
	.name = "bgp vpnv6",
	.node = BGP_VPNV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af-vpnv6)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_evpn_node = {
	.name = "bgp evpn",
	.node = BGP_EVPN_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-evpn)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_evpn_vni_node = {
	.name = "bgp evpn vni",
	.node = BGP_EVPN_VNI_NODE,
	.parent_node = BGP_EVPN_NODE,
	.prompt = "%s(config-router-af-vni)# ",
};

static struct cmd_node bgp_flowspecv4_node = {
	.name = "bgp ipv4 flowspec",
	.node = BGP_FLOWSPECV4_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_flowspecv6_node = {
	.name = "bgp ipv6 flowspec",
	.node = BGP_FLOWSPECV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af-vpnv6)# ",
	.no_xpath = true,
};

/* bgp_srv6_node is defined in bgp_cli.c for mgmtd compatibility */

static void community_list_vty(void);

static void bgp_ac_peergroup(vector comps, struct cmd_token *token)
{
	struct bgp *bgp;
	struct peer_group *group;
	struct listnode *lnbgp, *lnpeer;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, lnbgp, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->group, lnpeer, group))
			vector_set(comps,
				   XSTRDUP(MTYPE_COMPLETION, group->name));
	}
}

static void bgp_ac_peer(vector comps, struct cmd_token *token)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *lnbgp, *lnpeer;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, lnbgp, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, lnpeer, peer)) {
			/* only provide suggestions on the appropriate input
			 * token type,
			 * they'll otherwise show up multiple times */
			enum cmd_token_type match_type;
			char *name = peer->host;

			if (peer->conf_if) {
				match_type = VARIABLE_TKN;
				name = peer->conf_if;
			} else if (strchr(peer->host, ':'))
				match_type = IPV6_TKN;
			else
				match_type = IPV4_TKN;

			if (token->type != match_type)
				continue;

			vector_set(comps, XSTRDUP(MTYPE_COMPLETION, name));
		}
	}
}

static void bgp_ac_neighbor(vector comps, struct cmd_token *token)
{
	bgp_ac_peer(comps, token);

	if (token->type == VARIABLE_TKN)
		bgp_ac_peergroup(comps, token);
}

static const struct cmd_variable_handler bgp_var_neighbor[] = {
	{.varname = "neighbor", .completions = bgp_ac_neighbor},
	{.varname = "neighbors", .completions = bgp_ac_neighbor},
	{.varname = "peer", .completions = bgp_ac_neighbor},
	{.completions = NULL}};

static const struct cmd_variable_handler bgp_var_peergroup[] = {
	{.tokenname = "PGNAME", .completions = bgp_ac_peergroup},
	{.completions = NULL} };

DEFINE_HOOK(bgp_config_end, (struct bgp *bgp), (bgp));

static struct event *t_bgp_cfg;

bool bgp_config_inprocess(void)
{
	return event_is_scheduled(t_bgp_cfg);
}

/* Max wait time for config to load before post-config processing */
#define BGP_PRE_CONFIG_MAX_WAIT_SECONDS 600

static void bgp_config_finish(struct event *t)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp))
		hook_call(bgp_config_end, bgp);
}

static void bgp_config_end_timeout(struct event *t)
{
	flog_err(EC_BGP_CONFIG_TIMEOUT, "BGP configuration end timer expired after %d seconds.",
		 BGP_PRE_CONFIG_MAX_WAIT_SECONDS);
	bgp_config_finish(t);
}

static void bgp_config_start(struct vty *vty)
{
	(void)vty;
	event_cancel(&t_bgp_cfg);
	event_add_timer(bm->master, bgp_config_end_timeout, NULL,
			BGP_PRE_CONFIG_MAX_WAIT_SECONDS, &t_bgp_cfg);
}

/* When we receive a hook the configuration is read,
 * we start a timer to make sure we postpone sending
 * EoR before route-maps are processed.
 * This is especially valid if using `bgp route-map delay-timer`.
 */
static void bgp_config_end(struct vty *vty)
{
	(void)vty;
#define BGP_POST_CONFIG_DELAY_SECONDS 1
	uint32_t bgp_post_config_delay =
		event_is_scheduled(bm->t_rmap_update)
			? event_timer_remain_second(bm->t_rmap_update)
			: BGP_POST_CONFIG_DELAY_SECONDS;

	/* If BGP config processing thread isn't running, then
	 * we can return and rely it's properly handled.
	 */
	if (!bgp_config_inprocess())
		return;

	event_cancel(&t_bgp_cfg);

	/* Start a new timer to make sure we don't send EoR
	 * before route-maps are processed.
	 */
	event_add_timer(bm->master, bgp_config_finish, NULL,
			bgp_post_config_delay, &t_bgp_cfg);
}

static int config_write_interface_one(struct vty *vty, struct vrf *vrf)
{
	int write = 0;
	struct interface *ifp;
	struct bgp_interface *iifp;

	FOR_ALL_INTERFACES (vrf, ifp) {
		iifp = ifp->info;
		if (!iifp)
			continue;

		if_vty_config_start(vty, ifp);

		if (CHECK_FLAG(iifp->flags,
			       BGP_INTERFACE_MPLS_BGP_FORWARDING)) {
			vty_out(vty, " mpls bgp forwarding\n");
			write++;
		}
		if (CHECK_FLAG(iifp->flags,
			       BGP_INTERFACE_MPLS_L3VPN_SWITCHING)) {
			vty_out(vty,
				" mpls bgp l3vpn-multi-domain-switching\n");
			write++;
		}

		if_vty_config_end(vty);
	}

	return write;
}

/* Configuration write function for bgpd. */
static int config_write_interface(struct vty *vty)
{
	int write = 0;
	struct vrf *vrf = NULL;

	/* Display all VRF aware OSPF interface configuration */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		write += config_write_interface_one(vty, vrf);
	}

	return write;
}

DEFPY(mpls_bgp_forwarding, mpls_bgp_forwarding_cmd,
      "[no$no] mpls bgp forwarding",
      NO_STR MPLS_STR BGP_STR
      "Enable MPLS forwarding for eBGP directly connected peers\n")
{
	bool check;
	struct bgp_interface *iifp;

	VTY_DECLVAR_CONTEXT(interface, ifp);
	iifp = ifp->info;
	if (!iifp) {
		vty_out(vty, "Interface %s not available\n", ifp->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	check = CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_BGP_FORWARDING);
	if (check != !no) {
		if (no)
			UNSET_FLAG(iifp->flags,
				   BGP_INTERFACE_MPLS_BGP_FORWARDING);
		else
			SET_FLAG(iifp->flags,
				 BGP_INTERFACE_MPLS_BGP_FORWARDING);
		/* trigger a nht update on eBGP sessions */
		if (if_is_operative(ifp))
			bgp_nht_ifp_up(ifp);
	}
	return CMD_SUCCESS;
}

DEFPY(mpls_bgp_l3vpn_multi_domain_switching,
      mpls_bgp_l3vpn_multi_domain_switching_cmd,
      "[no$no] mpls bgp l3vpn-multi-domain-switching",
      NO_STR MPLS_STR BGP_STR
      "Bind a local MPLS label to incoming L3VPN updates\n")
{
	bool check;
	struct bgp_interface *iifp;

	VTY_DECLVAR_CONTEXT(interface, ifp);
	iifp = ifp->info;
	if (!iifp) {
		vty_out(vty, "Interface %s not available\n", ifp->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	check = CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
	if (check == !no)
		return CMD_SUCCESS;
	if (no)
		UNSET_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
	else
		SET_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
	/* trigger a nht update on eBGP sessions */
	if (if_is_operative(ifp))
		bgp_nht_ifp_up(ifp);

	return CMD_SUCCESS;
}

DEFPY (bgp_inq_limit,
       bgp_inq_limit_cmd,
       "bgp input-queue-limit (1-4294967295)$limit",
       BGP_STR
       "Set the BGP Input Queue limit for all peers when message parsing\n"
       "Input-Queue limit\n")
{
	bm->inq_limit = limit;

	return CMD_SUCCESS;
}

DEFPY (no_bgp_inq_limit,
       no_bgp_inq_limit_cmd,
       "no bgp input-queue-limit [(1-4294967295)$limit]",
       NO_STR
       BGP_STR
       "Set the BGP Input Queue limit for all peers when message parsing\n"
       "Input-Queue limit\n")
{
	bm->inq_limit = BM_DEFAULT_Q_LIMIT;

	return CMD_SUCCESS;
}

DEFPY (bgp_outq_limit,
       bgp_outq_limit_cmd,
       "bgp output-queue-limit (1-4294967295)$limit",
       BGP_STR
       "Set the BGP Output Queue limit for all peers when message parsing\n"
       "Output-Queue limit\n")
{
	bm->outq_limit = limit;

	return CMD_SUCCESS;
}

DEFPY (no_bgp_outq_limit,
       no_bgp_outq_limit_cmd,
       "no bgp output-queue-limit [(1-4294967295)$limit]",
       NO_STR
       BGP_STR
       "Set the BGP Output Queue limit for all peers when message parsing\n"
       "Output-Queue limit\n")
{
	bm->outq_limit = BM_DEFAULT_Q_LIMIT;

	return CMD_SUCCESS;
}

/* Initialization of BGP interface. */
static void bgp_vty_if_init(void)
{
	/* Install interface node. */
	if_cmd_init(config_write_interface);

	/* `mpls bgp forwarding` and `mpls bgp l3vpn-multi-domain-switching`
	 * at INTERFACE_NODE are installed by bgp_cli.c (DEFPY_YANG:
	 * mpls_bgp_forwarding_cli_cmd /
	 * mpls_bgp_l3vpn_multi_domain_switching_cli_cmd).
	 */
}

void bgp_vty_init(void)
{
	cmd_variable_handler_register(bgp_var_neighbor);
	cmd_variable_handler_register(bgp_var_peergroup);

	cmd_init_config_callbacks(bgp_config_start, bgp_config_end);

	/* Install bgp top node. */
	install_node(&bgp_node);
	install_node(&bgp_ipv4_unicast_node);
	install_node(&bgp_ipv4_multicast_node);
	install_node(&bgp_ipv4_labeled_unicast_node);
	install_node(&bgp_ipv6_unicast_node);
	install_node(&bgp_ipv6_multicast_node);
	install_node(&bgp_ipv6_labeled_unicast_node);
	install_node(&bgp_vpnv4_node);
	install_node(&bgp_vpnv6_node);
	install_node(&bgp_evpn_node);
	install_node(&bgp_evpn_vni_node);
	install_node(&bgp_flowspecv4_node);
	install_node(&bgp_flowspecv6_node);
	/* bgp_srv6_node is installed in bgp_cli.c for mgmtd compatibility */

	/* Install default VTY commands to new nodes.  */
	install_default(BGP_NODE);
	install_default(BGP_IPV4_NODE);
	install_default(BGP_IPV4M_NODE);
	install_default(BGP_IPV4L_NODE);
	install_default(BGP_IPV6_NODE);
	install_default(BGP_IPV6M_NODE);
	install_default(BGP_IPV6L_NODE);
	install_default(BGP_VPNV4_NODE);
	install_default(BGP_VPNV6_NODE);
	install_default(BGP_FLOWSPECV4_NODE);
	install_default(BGP_FLOWSPECV6_NODE);
	install_default(BGP_EVPN_NODE);
	install_default(BGP_EVPN_VNI_NODE);
	/* BGP_SRV6_NODE default is installed in bgp_cli.c */

	/* "bgp local-mac" hidden commands. */
	install_element(CONFIG_NODE, &bgp_local_mac_cmd);
	install_element(CONFIG_NODE, &no_bgp_local_mac_cmd);

	/* "bgp router-id" commands - handled by bgp_cli.c via mgmtd */

	/* "bgp suppress-fib-pending" command - handled by bgp_cli.c via mgmtd */

	/* "neighbor graceful-shutdown" command - handled by bgp_cli.c via mgmtd */


	/* "bgp always-compare-med" commands - handled by bgp_cli.c via mgmtd */

	/* bgp ebgp-requires-policy - handled by bgp_cli.c via mgmtd */

	/* bgp enforce-first-as - handled by bgp_cli.c via mgmtd */

	/* bgp labeled-unicast explicit-null - handled by bgp_cli.c via mgmtd */

	/* bgp suppress-duplicates - handled by bgp_cli.c via mgmtd */

	/* "bgp deterministic-med" commands - handled by bgp_cli.c via mgmtd */

	/* "bgp graceful-shutdown" commands - handled by bgp_cli.c via mgmtd */

	/* "bgp fast-external-failover" commands - handled by bgp_cli.c via mgmtd */

	/* "bgp log-neighbor-changes" commands - handled by bgp_cli.c via mgmtd */

	/* "no bgp default <afi>-<safi>" commands - handled by bgp_cli.c via mgmtd */

	/* "bgp network import-check" commands - handled by bgp_cli.c via mgmtd */

	/* "neighbor peer-group" commands - handled by bgp_cli.c via mgmtd */

	/* "neighbor activate" commands - handled by bgp_cli.c via mgmtd */

	/* "no neighbor activate" commands - handled by bgp_cli.c via mgmtd */

	/* "neighbor peer-group" set commands - handled by bgp_cli.c via mgmtd */

	/* "no neighbor peer-group unset" commands - handled by bgp_cli.c via mgmtd */

	/* "neighbor softreconfiguration inbound" commands.*/


	/* "nexthop-local unchanged" commands - handled by bgp_cli.c via mgmtd */
	/* install_element(BGP_IPV6_NODE, &neighbor_nexthop_local_unchanged_cmd); */
	/* install_element(BGP_IPV6_NODE, &no_neighbor_nexthop_local_unchanged_cmd); */

	/* "neighbor next-hop-self" commands - IPV4/IPV6/VPNV4/VPNV6 handled by bgp_cli.c via mgmtd */

	/* "neighbor next-hop-self force" commands - IPV4/IPV6/VPNV4/VPNV6 handled by bgp_cli.c via mgmtd */

	/* AF-specific removed: now in bgp_cli.c */

	/* "neighbor send-community" commands.*/
	

	/* "neighbor route-reflector" commands.*/

	

	/* "neighbor addpath-tx-all-paths" commands.*/
	

	

	/* "neighbor addpath-tx-bestpath-per-AS" commands.*/
	

	/* "neighbor addpath-rx-paths-limit" commands.*/
	

	/* "neighbor sender-as-path-loop-detection" commands. */
	

	/* "neighbor capability extended-nexthop" commands - handled by bgp_cli.c via mgmtd */


	/* "neighbor update-source" commands - handled by bgp_cli.c via mgmtd */


	/* "neighbor weight" commands. */
	

	/* "neighbor distribute" commands. */
	

	/* "neighbor prefix-list" commands. */
	

	/* "neighbor filter-list" commands. */
	

	/* "neighbor route-map" commands. */
	

	/* "neighbor unsuppress-map" commands. */
	

	/* "neighbor advertise-map" commands. */



	/* "neighbor allowas-in" */
	

	/* neighbor accept-own - handled by bgp_cli.c via mgmtd */
	/* install_element(BGP_VPNV4_NODE, &neighbor_accept_own_cmd); */
	/* install_element(BGP_VPNV6_NODE, &neighbor_accept_own_cmd); */

	/* "neighbor dampening" commands. */
	/* BGP_NODE still uses legacy command for now */
	install_element(VIEW_NODE, &show_ip_bgp_neighbor_damp_param_cmd);

#ifdef KEEP_OLD_VPN_COMMANDS
#endif /* KEEP_OLD_VPN_COMMANDS */

	/* "exit-address-family" command - handled by bgp_cli.c via mgmtd */

	/* "clear ip bgp commands" */
	install_element(ENABLE_NODE, &clear_ip_bgp_all_cmd);

	/* clear ip bgp prefix  */
	install_element(ENABLE_NODE, &clear_ip_bgp_prefix_cmd);
	install_element(ENABLE_NODE, &clear_bgp_ipv6_safi_prefix_cmd);
	install_element(ENABLE_NODE, &clear_bgp_instance_ipv6_safi_prefix_cmd);

	/* "show [ip] bgp summary" commands. */
	install_element(VIEW_NODE, &show_bgp_instance_all_ipv6_updgrps_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_updgrps_cmd);
	install_element(VIEW_NODE, &show_bgp_instance_updgrps_stats_cmd);
	install_element(VIEW_NODE, &show_bgp_updgrps_stats_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_instance_updgrps_adj_s_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_summary_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_updgrps_cmd);

	/* "show [ip] bgp neighbors" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_neighbors_cmd);

	install_element(VIEW_NODE, &show_ip_bgp_neighbors_graceful_restart_cmd);

	/* "show [ip] bgp peer-group" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_peer_groups_cmd);

	/* "show [ip] bgp paths" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_paths_cmd);

	/* "show [ip] bgp community" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_community_info_cmd);

	/* "show ip bgp large-community" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_lcommunity_info_cmd);
	/* "show [ip] bgp attribute-info" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_attr_info_cmd);
	/* "show [ip] bgp route-leak" command */
	install_element(VIEW_NODE, &show_ip_bgp_route_leak_cmd);

	/* "redistribute" commands.  */
	/* 		&bgp_redistribute_ipv4_ospf_rmap_metric_cmd); */
	/* 		&bgp_redistribute_ipv4_ospf_metric_rmap_cmd); */

	/* "show [ip] bgp memory" commands. */
	install_element(VIEW_NODE, &show_bgp_memory_cmd);

	/* "show bgp martian next-hop" */
	install_element(VIEW_NODE, &show_bgp_martian_nexthop_db_cmd);

	install_element(VIEW_NODE, &show_bgp_mac_hash_cmd);

	/* "show [ip] bgp views" commands. */
	install_element(VIEW_NODE, &show_bgp_views_cmd);

	/* "show [ip] bgp vrfs" commands. */
	install_element(VIEW_NODE, &show_bgp_vrfs_cmd);

	/* Some overall BGP information */
	install_element(VIEW_NODE, &show_bgp_router_cmd);

	/* "show bgp vrfs bestpath" command. */
	install_element(VIEW_NODE, &show_bgp_vrf_bestpath_cmd);

	/* Community-list. */
	community_list_vty();

	community_alias_vty();

	/* install_element(BGP_NODE, &neighbor_ip_transparent_cmd); */

	install_element(VIEW_NODE, &show_bgp_srv6_cmd);

	bgp_vty_if_init();
}

#include "memory.h"
#include "bgp_regex.h"
#include "bgp_clist.h"
#include "bgp_ecommunity.h"

/* VTY functions.  */

/* Direction value to string conversion.  */
static const char *community_direct_str(int direct)
{
	switch (direct) {
	case COMMUNITY_DENY:
		return "deny";
	case COMMUNITY_PERMIT:
		return "permit";
	default:
		return "unknown";
	}
}

/* Display error string.  */
static __attribute__((unused)) void community_list_perror(struct vty *vty, int ret)
{
	switch (ret) {
	case COMMUNITY_LIST_ERR_MALFORMED_VAL:
		vty_out(vty, "%% Malformed community-list value\n");
		break;
	case COMMUNITY_LIST_ERR_STANDARD_CONFLICT:
		vty_out(vty,
			"%% Community name conflict, previously defined as standard community\n");
		break;
	case COMMUNITY_LIST_ERR_EXPANDED_CONFLICT:
		vty_out(vty,
			"%% Community name conflict, previously defined as expanded community\n");
		break;
	}
}

/* "community-list" keyword help string.  */
#define COMMUNITY_LIST_STR "Add a community list entry\n"

/*community-list standard */

/*community-list expanded */

/* Return configuration string of community-list entry.  */
static const char *community_list_config_str(struct community_entry *entry)
{
	const char *str;

	if (entry->style == COMMUNITY_LIST_STANDARD)
		str = community_str(entry->u.com, false, false);
	else if (entry->style == LARGE_COMMUNITY_LIST_STANDARD)
		str = lcommunity_str(entry->u.lcom, false, false);
	else
		str = entry->config;

	return str;
}

static void community_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Community %s list %s\n",
					entry->style == COMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty, "Named Community %s list %s\n",
					entry->style == COMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		vty_out(vty, "    %s %s\n", community_direct_str(entry->direct),
			community_list_config_str(entry));
	}
}

DEFUN (show_community_list,
       show_bgp_community_list_cmd,
       "show bgp community-list",
       SHOW_STR
       BGP_STR
       "List community-list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist, COMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		community_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		community_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_community_list_arg,
       show_bgp_community_list_arg_cmd,
       "show bgp community-list <(1-500)|COMMUNITY_LIST_NAME> detail",
       SHOW_STR
       BGP_STR
       "List community-list\n"
       "Community-list number\n"
       "Community-list name\n"
       "Detailed information on community-list\n")
{
	int idx_comm_list = 3;
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[idx_comm_list]->arg, 0,
				     COMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find community-list\n");
		return CMD_WARNING;
	}

	community_list_show(vty, list);

	return CMD_SUCCESS;
}

/* "large-community-list" keyword help string.  */
#define LCOMMUNITY_LIST_STR "Add a large community list entry\n"
#define LCOMMUNITY_VAL_STR  "large community in 'aa:bb:cc' format\n"

static void lcommunity_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Large community %s list %s\n",
					entry->style ==
						LARGE_COMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty,
					"Named large community %s list %s\n",
					entry->style ==
						LARGE_COMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		vty_out(vty, "    %s %s\n", community_direct_str(entry->direct),
			community_list_config_str(entry));
	}
}

DEFUN (show_lcommunity_list,
       show_bgp_lcommunity_list_cmd,
       "show bgp large-community-list",
       SHOW_STR
       BGP_STR
       "List large-community list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist,
					  LARGE_COMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		lcommunity_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		lcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_lcommunity_list_arg,
       show_bgp_lcommunity_list_arg_cmd,
       "show bgp large-community-list <(1-500)|LCOMMUNITY_LIST_NAME> detail",
       SHOW_STR
       BGP_STR
       "List large-community list\n"
       "Large-community-list number\n"
       "Large-community-list name\n"
       "Detailed information on large-community-list\n")
{
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[3]->arg, 0,
				     LARGE_COMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find large-community-list\n");
		return CMD_WARNING;
	}

	lcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

/* "extcommunity-list" keyword help string.  */
#define EXTCOMMUNITY_LIST_STR "Add a extended community list entry\n"
#define EXTCOMMUNITY_VAL_STR  "Extended community attribute in 'rt aa:nn_or_IPaddr:nn' OR 'soo aa:nn_or_IPaddr:nn' format\n"

static void extcommunity_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Extended community %s list %s\n",
					entry->style == EXTCOMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty,
					"Named extended community %s list %s\n",
					entry->style == EXTCOMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		vty_out(vty, "    %s %s\n", community_direct_str(entry->direct),
			community_list_config_str(entry));
	}
}

DEFUN (show_extcommunity_list,
       show_bgp_extcommunity_list_cmd,
       "show bgp extcommunity-list",
       SHOW_STR
       BGP_STR
       "List extended-community list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist, EXTCOMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		extcommunity_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		extcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_extcommunity_list_arg,
       show_bgp_extcommunity_list_arg_cmd,
       "show bgp extcommunity-list <(1-500)|EXTCOMMUNITY_LIST_NAME> detail",
       SHOW_STR
       BGP_STR
       "List extended-community list\n"
       "Extcommunity-list number\n"
       "Extcommunity-list name\n"
       "Detailed information on extcommunity-list\n")
{
	int idx_comm_list = 3;
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[idx_comm_list]->arg, 0,
				     EXTCOMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find extcommunity-list\n");
		return CMD_WARNING;
	}

	extcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

/* Display community-list and extcommunity-list configuration.  */
static int community_list_config_write(struct vty *vty)
{
	struct community_list *list;
	struct community_entry *entry;
	struct community_list_master *cm;
	int write = 0;

	/* Community-list.  */
	cm = community_list_master_lookup(bgp_clist, COMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp community-list %s seq %" PRId64 " %s %s\n",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp community-list %s %s seq %" PRId64 " %s %s\n",
				entry->style == COMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}

	/* Extcommunity-list.  */
	cm = community_list_master_lookup(bgp_clist, EXTCOMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp extcommunity-list %s seq %" PRId64 " %s %s\n",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp extcommunity-list %s %s seq %" PRId64" %s %s\n",
				entry->style == EXTCOMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}

	/* lcommunity-list.  */
	cm = community_list_master_lookup(bgp_clist,
					  LARGE_COMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp large-community-list %s seq %" PRId64" %s %s\n",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp large-community-list %s %s seq %" PRId64" %s %s\n",

				entry->style == LARGE_COMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, entry->seq, community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}

	return write;
}

static int community_list_config_write(struct vty *vty);
static struct cmd_node community_list_node = {
	.name = "community list",
	.node = COMMUNITY_LIST_NODE,
	.prompt = "",
	.config_write = community_list_config_write,
};

static void community_list_vty(void)
{
	install_node(&community_list_node);

	/* Community-list show commands (config commands in bgp_filter_cli.c) */
	install_element(VIEW_NODE, &show_bgp_community_list_cmd);
	install_element(VIEW_NODE, &show_bgp_community_list_arg_cmd);

	/* Extcommunity-list show commands (config commands in bgp_filter_cli.c) */
	install_element(VIEW_NODE, &show_bgp_extcommunity_list_cmd);
	install_element(VIEW_NODE, &show_bgp_extcommunity_list_arg_cmd);

	/* Large Community List show commands (config commands in bgp_filter_cli.c) */
	install_element(VIEW_NODE, &show_bgp_lcommunity_list_cmd);
	install_element(VIEW_NODE, &show_bgp_lcommunity_list_arg_cmd);

	bgp_community_list_command_completion_setup();
}

static struct cmd_node community_alias_node = {
	.name = "community alias",
	.node = COMMUNITY_ALIAS_NODE,
	.prompt = "",
	.config_write = bgp_community_alias_write,
};

void community_alias_vty(void)
{
	install_node(&community_alias_node);

	/* bgp_community_alias_cmd removed - using bgp_community_alias_cli_cmd from bgp_cli.c */

	bgp_community_alias_command_completion_setup();
}

void bgp_init_ipv6_nexthop_prefer_global(struct bgp *bgp)
{
	safi_t safi;

	if (!DFLT_BGP_IPV6_NEXTHOP_PREFER_GLOBAL)
		return;

	for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
		if (BGP_IPV6_SAFI_SUPPORTS_NEXTHOP_PREFER_GLOBAL(safi))
			bgp->nexthop_prefer_global[AFI_IP6][safi] = true;
	}
}
