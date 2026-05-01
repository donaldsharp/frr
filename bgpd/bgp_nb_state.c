// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound Operational State Callbacks
 * Copyright (C) 2024 FRRouting
 *
 * This file implements YANG operational state callbacks for BGP,
 * following the pattern established in isisd/isis_nb_state.c.
 * These callbacks provide read-only access to BGP runtime state
 * via RESTCONF GET requests.
 */

#include <zebra.h>

#include "northbound.h"
#include "linklist.h"
#include "memory.h"
#include "sockunion.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_attr_srv6.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_label.h"
#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_private.h"
#endif
#include "log.h"

/*
 * Helper function to count total prefixes across all peers
 */
static uint32_t bgp_count_total_prefixes(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node;
	uint32_t total = 0;
	afi_t afi;
	safi_t safi;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		FOREACH_AFI_SAFI (afi, safi) {
			total += peer->pcount[afi][safi];
		}
	}
	return total;
}

/*
 * Helper function to count established peers
 */
static uint32_t bgp_count_established_peers(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node;
	uint32_t count = 0;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (peer->connection &&
		    peer->connection->status == Established)
			count++;
	}
	return count;
}

/*
 * Helper function to get peer type string for YANG enum
 * Returns lowercase values matching the YANG schema enum
 */
static const char *bgp_peer_type_str(struct peer *peer)
{
	switch (peer->sort) {
	case BGP_PEER_IBGP:
	case BGP_PEER_INTERNAL:
		return "ibgp";
	case BGP_PEER_EBGP:
		return "ebgp";
	case BGP_PEER_CONFED:
		/* For confederation peers, check if internal or external */
		if (peer->local_as == peer->as)
			return "confed-internal";
		else
			return "confed-external";
	case BGP_PEER_UNSPECIFIED:
	default:
		return "ibgp"; /* Default to ibgp if unknown */
	}
}

/*
 * Helper function to get AFI/SAFI identity string for YANG identityref
 * Returns the proper identity string with module prefix
 */
static const char *bgp_afi_safi_identity_str(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP && safi == SAFI_UNICAST)
		return "frr-routing:ipv4-unicast";
	else if (afi == AFI_IP && safi == SAFI_MULTICAST)
		return "frr-routing:ipv4-multicast";
	else if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
		return "frr-routing:l3vpn-ipv4-unicast";
	else if (afi == AFI_IP && safi == SAFI_LABELED_UNICAST)
		return "frr-routing:ipv4-labeled-unicast";
	else if (afi == AFI_IP && safi == SAFI_FLOWSPEC)
		return "frr-routing:ipv4-flowspec";
	else if (afi == AFI_IP6 && safi == SAFI_UNICAST)
		return "frr-routing:ipv6-unicast";
	else if (afi == AFI_IP6 && safi == SAFI_MULTICAST)
		return "frr-routing:ipv6-multicast";
	else if (afi == AFI_IP6 && safi == SAFI_MPLS_VPN)
		return "frr-routing:l3vpn-ipv6-unicast";
	else if (afi == AFI_IP6 && safi == SAFI_LABELED_UNICAST)
		return "frr-routing:ipv6-labeled-unicast";
	else if (afi == AFI_IP6 && safi == SAFI_FLOWSPEC)
		return "frr-routing:ipv6-flowspec";
	else if (afi == AFI_L2VPN && safi == SAFI_EVPN)
		return "frr-routing:l2vpn-evpn";
	else
		return NULL;
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance
 * BGP Instance List Iteration Callbacks
 * ======================================================================== */

/*
 * XPath: /frr-bgp:bgpd/instance
 * get_next callback - Iterate through BGP instances (VRFs)
 */
const void *bgpd_instance_get_next(struct nb_cb_get_next_args *args)
{
	struct listnode *node;
	struct bgp *bgp;

	if (!bm || !bm->bgp)
		return NULL;

	if (args->list_entry == NULL) {
		/* Return first BGP instance */
		node = listhead(bm->bgp);
		if (node)
			return listgetdata(node);
		return NULL;
	}

	/* Get next BGP instance */
	bgp = (struct bgp *)args->list_entry;
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		if (bgp == args->list_entry) {
			node = listnextnode(node);
			if (node)
				return listgetdata(node);
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance
 * get_keys callback - Return the key (vrf name) for a BGP instance
 */
int bgpd_instance_get_keys(struct nb_cb_get_keys_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;

	args->keys->num = 1;
	strlcpy(args->keys->key[0],
		bgp->name ? bgp->name : VRF_DEFAULT_NAME,
		sizeof(args->keys->key[0]));

	return NB_OK;
}

/*
 * XPath: /frr-bgp:bgpd/instance
 * lookup_entry callback - Find a BGP instance by VRF name
 */
const void *bgpd_instance_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *vrf_name = args->keys->key[0];
	struct listnode *node;
	struct bgp *bgp;

	if (!bm || !bm->bgp)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		const char *bgp_vrf = bgp->name ? bgp->name : VRF_DEFAULT_NAME;
		if (strcmp(bgp_vrf, vrf_name) == 0)
			return bgp;
	}

	return NULL;
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/router-id
 * BGP Instance State Leaf Callbacks
 * ======================================================================== */

/*
 * XPath: /frr-bgp:bgpd/instance/router-id
 */
struct yang_data *bgpd_instance_router_id_get_elem(struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;
	char buf[INET_ADDRSTRLEN];

	if (!bgp)
		return NULL;

	inet_ntop(AF_INET, &bgp->router_id, buf, sizeof(buf));
	return yang_data_new_ipv4(args->xpath, &bgp->router_id);
}

/*
 * XPath: /frr-bgp:bgpd/instance/local-as
 */
struct yang_data *bgpd_instance_local_as_get_elem(struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;

	if (!bgp)
		return NULL;

	return yang_data_new_uint32(args->xpath, bgp->as);
}

/*
 * XPath: /frr-bgp:bgpd/instance/uptime
 */
struct yang_data *bgpd_instance_uptime_get_elem(struct nb_cb_get_elem_args *args)
{
	/* BGP doesn't track instance uptime directly, return empty for now */
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/total-peers
 */
struct yang_data *bgpd_instance_total_peers_get_elem(struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;

	if (!bgp || !bgp->peer)
		return NULL;

	return yang_data_new_uint32(args->xpath, listcount(bgp->peer));
}

/*
 * XPath: /frr-bgp:bgpd/instance/established-peers
 */
struct yang_data *bgpd_instance_established_peers_get_elem(struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;

	if (!bgp)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    bgp_count_established_peers(bgp));
}

/*
 * XPath: /frr-bgp:bgpd/instance/total-prefixes
 */
struct yang_data *bgpd_instance_total_prefixes_get_elem(struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;

	if (!bgp)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    bgp_count_total_prefixes(bgp));
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/memory
 * Memory Statistics Callbacks
 * ======================================================================== */

/*
 * XPath: /frr-bgp:bgpd/instance/memory/total-bytes
 * Returns approximate total BGP memory usage based on mtype stats
 */
struct yang_data *bgpd_instance_memory_total_bytes_get_elem(struct nb_cb_get_elem_args *args)
{
	unsigned long total_bytes = 0;

	/* Sum up major BGP memory types */
	total_bytes += mtype_stats_alloc(MTYPE_BGP_NODE) * sizeof(struct bgp_dest);
	total_bytes += mtype_stats_alloc(MTYPE_BGP_ROUTE) * sizeof(struct bgp_path_info);
	total_bytes += mtype_stats_alloc(MTYPE_BGP_PEER) * sizeof(struct peer);
	total_bytes += attr_count() * sizeof(struct attr);
	total_bytes += aspath_count() * sizeof(struct aspath);
	total_bytes += community_count() * sizeof(struct community);

	return yang_data_new_uint64(args->xpath, total_bytes);
}

/*
 * XPath: /frr-bgp:bgpd/instance/memory/rib-count
 */
struct yang_data *bgpd_instance_memory_rib_count_get_elem(struct nb_cb_get_elem_args *args)
{
	unsigned long count;

	count = mtype_stats_alloc(MTYPE_BGP_NODE);
	return yang_data_new_uint64(args->xpath, count);
}

/*
 * XPath: /frr-bgp:bgpd/instance/memory/path-count
 */
struct yang_data *bgpd_instance_memory_path_count_get_elem(struct nb_cb_get_elem_args *args)
{
	unsigned long count;

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE);
	return yang_data_new_uint64(args->xpath, count);
}

/*
 * XPath: /frr-bgp:bgpd/instance/memory/attr-count
 */
struct yang_data *bgpd_instance_memory_attr_count_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_uint64(args->xpath, attr_count());
}

/*
 * XPath: /frr-bgp:bgpd/instance/memory/community-count
 */
struct yang_data *bgpd_instance_memory_community_count_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_uint64(args->xpath, community_count());
}

/*
 * XPath: /frr-bgp:bgpd/instance/memory/aspath-count
 */
struct yang_data *bgpd_instance_memory_aspath_count_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_uint64(args->xpath, aspath_count());
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor
 * Neighbor List Iteration Callbacks
 * ======================================================================== */

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor
 * get_next callback - Iterate through BGP neighbors
 */
const void *bgpd_instance_neighbors_neighbor_get_next(struct nb_cb_get_next_args *args)
{
	struct bgp *bgp = (struct bgp *)args->parent_list_entry;
	struct listnode *node;
	struct peer *peer;

	if (!bgp || !bgp->peer)
		return NULL;

	if (args->list_entry == NULL) {
		/* Return first peer */
		node = listhead(bgp->peer);
		if (node)
			return listgetdata(node);
		return NULL;
	}

	/* Get next peer */
	peer = (struct peer *)args->list_entry;
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (peer == args->list_entry) {
			node = listnextnode(node);
			if (node)
				return listgetdata(node);
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor
 * get_keys callback - Return the key (remote-address) for a neighbor
 */
int bgpd_instance_neighbors_neighbor_get_keys(struct nb_cb_get_keys_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	args->keys->num = 1;
	if (peer->host)
		strlcpy(args->keys->key[0], peer->host,
			sizeof(args->keys->key[0]));
	else
		args->keys->key[0][0] = '\0';

	return NB_OK;
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor
 * lookup_entry callback - Find a neighbor by remote-address
 */
const void *bgpd_instance_neighbors_neighbor_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct bgp *bgp = (struct bgp *)args->parent_list_entry;
	const char *remote_addr = args->keys->key[0];
	struct listnode *node;
	struct peer *peer;

	if (!bgp || !bgp->peer)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (peer->host && strcmp(peer->host, remote_addr) == 0)
			return peer;
	}

	return NULL;
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/{leaf}
 * Neighbor State Leaf Callbacks
 * ======================================================================== */

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/session-state
 * Returns lowercase enum values matching the YANG schema
 */
struct yang_data *bgpd_instance_neighbors_neighbor_session_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	const char *state_str;

	if (!peer || !peer->connection)
		return NULL;

	/* Map BGP FSM states to YANG enum values (lowercase) */
	switch (peer->connection->status) {
	case Idle:
		state_str = "idle";
		break;
	case Connect:
		state_str = "connect";
		break;
	case Active:
		state_str = "active";
		break;
	case OpenSent:
		state_str = "opensent";
		break;
	case OpenConfirm:
		state_str = "openconfirm";
		break;
	case Established:
		state_str = "established";
		break;
	case Clearing:
		state_str = "clearing";
		break;
	case Deleted:
		state_str = "deleted";
		break;
	case BGP_STATUS_MAX:
	default:
		return NULL;
	}

	return yang_data_new_string(args->xpath, state_str);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/uptime
 */
struct yang_data *bgpd_instance_neighbors_neighbor_uptime_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	char timebuf[BGP_UPTIME_LEN];

	if (!peer)
		return NULL;

	peer_uptime(peer->uptime, timebuf, sizeof(timebuf), 0, NULL);
	return yang_data_new_string(args->xpath, timebuf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/remote-as
 */
struct yang_data *bgpd_instance_neighbors_neighbor_remote_as_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath, peer->as);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/remote-router-id
 */
struct yang_data *bgpd_instance_neighbors_neighbor_remote_router_id_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_ipv4(args->xpath, &peer->remote_id);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/peer-type
 */
struct yang_data *bgpd_instance_neighbors_neighbor_peer_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_string(args->xpath, bgp_peer_type_str(peer));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/last-reset-reason
 */
struct yang_data *bgpd_instance_neighbors_neighbor_last_reset_reason_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	const char *reason;

	if (!peer)
		return NULL;

	if (peer->last_reset == 0)
		return NULL;

	reason = peer_down_str[peer->last_reset];
	if (!reason)
		return NULL;

	return yang_data_new_string(args->xpath, reason);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/description
 * Returns the peer description configured by operator.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_description_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->desc)
		return NULL;

	return yang_data_new_string(args->xpath, peer->desc);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/local-as
 * Returns the local AS number used with this peer (may differ from global AS
 * if local-as is configured).
 */
struct yang_data *bgpd_instance_neighbors_neighbor_local_as_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	as_t local_as;

	if (!peer)
		return NULL;

	/* Use change_local_as if configured, otherwise use global local_as */
	local_as = peer->change_local_as ? peer->change_local_as : peer->local_as;

	return yang_data_new_uint32(args->xpath, local_as);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/queues/input
 * Returns the number of messages in the input queue (InQ from show bgp summary).
 */
struct yang_data *bgpd_instance_neighbors_neighbor_queues_input_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	atomic_size_t inq_count;

	if (!peer || !peer->connection || !peer->connection->ibuf)
		return NULL;

	inq_count = atomic_load_explicit(&peer->connection->ibuf->count,
					 memory_order_relaxed);

	return yang_data_new_uint32(args->xpath, (uint32_t)inq_count);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/queues/output
 * Returns the number of messages in the output queue (OutQ from show bgp summary).
 */
struct yang_data *bgpd_instance_neighbors_neighbor_queues_output_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	atomic_size_t outq_count;

	if (!peer || !peer->connection || !peer->connection->obuf)
		return NULL;

	outq_count = atomic_load_explicit(&peer->connection->obuf->count,
					  memory_order_relaxed);

	return yang_data_new_uint32(args->xpath, (uint32_t)outq_count);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/hostname
 * Returns the hostname advertised by peer via BGP hostname capability.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_hostname_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->hostname)
		return NULL;

	return yang_data_new_string(args->xpath, peer->hostname);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/domainname
 * Returns the domain name advertised by peer via BGP hostname capability.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_domainname_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->domainname)
		return NULL;

	return yang_data_new_string(args->xpath, peer->domainname);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/peer-group
 * Returns the peer group this neighbor belongs to.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_peer_group_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->group || !peer->group->name)
		return NULL;

	return yang_data_new_string(args->xpath, peer->group->name);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/interface
 * Returns the interface name for unnumbered or directly connected peers.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_interface_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->conf_if)
		return NULL;

	return yang_data_new_string(args->xpath, peer->conf_if);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/tcp-mss
 * Returns the TCP Maximum Segment Size for this peer.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_tcp_mss_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->tcp_mss)
		return NULL;

	return yang_data_new_uint32(args->xpath, peer->tcp_mss);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/timers/hold-time
 * Returns the negotiated hold time for this peer.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_timers_hold_time_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->v_holdtime,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/timers/keepalive
 * Returns the negotiated keepalive interval for this peer.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_timers_keepalive_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->v_keepalive,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/timestamps/last-read
 * Returns time since last message was read from peer.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_timestamps_last_read_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	char timebuf[BGP_UPTIME_LEN];
	time_t now, diff;

	if (!peer || !peer->readtime)
		return NULL;

	now = monotime(NULL);
	diff = now - peer->readtime;
	peer_uptime(diff, timebuf, sizeof(timebuf), 0, NULL);

	return yang_data_new_string(args->xpath, timebuf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/timestamps/last-write
 * Returns time since last message was written to peer.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_timestamps_last_write_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	char timebuf[BGP_UPTIME_LEN];
	time_t now, diff, last_write;

	if (!peer)
		return NULL;

	last_write = atomic_load_explicit(&peer->last_write, memory_order_relaxed);
	if (!last_write)
		return NULL;

	now = monotime(NULL);
	diff = now - last_write;
	peer_uptime(diff, timebuf, sizeof(timebuf), 0, NULL);

	return yang_data_new_string(args->xpath, timebuf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/timestamps/last-update
 * Returns time since last UPDATE message was received from peer.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_timestamps_last_update_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	char timebuf[BGP_UPTIME_LEN];
	time_t now, diff, update_time;

	if (!peer)
		return NULL;

	update_time = atomic_load_explicit(&peer->update_time, memory_order_relaxed);
	if (!update_time)
		return NULL;

	now = monotime(NULL);
	diff = now - update_time;
	peer_uptime(diff, timebuf, sizeof(timebuf), 0, NULL);

	return yang_data_new_string(args->xpath, timebuf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/connection-stats/established-count
 * Returns the number of times the BGP session was established.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_connection_stats_established_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath, peer->established);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/connection-stats/dropped-count
 * Returns the number of times the BGP session was dropped.
 */
struct yang_data *bgpd_instance_neighbors_neighbor_connection_stats_dropped_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath, peer->dropped);
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics
 * Message Statistics Callbacks
 * ======================================================================== */

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/opens
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_sent_opens_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->open_out,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/updates
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_sent_updates_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->update_out,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/keepalives
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_sent_keepalives_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->keepalive_out,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/notifications
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_sent_notifications_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->notify_out,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/route-refreshes
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_sent_route_refreshes_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->refresh_out,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/opens
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_received_opens_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->open_in,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/updates
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_received_updates_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->update_in,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/keepalives
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_received_keepalives_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->keepalive_in,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/notifications
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_received_notifications_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->notify_in,
							 memory_order_relaxed));
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/route-refreshes
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_received_route_refreshes_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    atomic_load_explicit(&peer->refresh_in,
							 memory_order_relaxed));
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi
 * Prefix Statistics Callbacks
 * ======================================================================== */

/*
 * Helper structure for AFI/SAFI iteration
 */
struct bgp_afi_safi_entry {
	struct peer *peer;
	afi_t afi;
	safi_t safi;
};

static struct bgp_afi_safi_entry afi_safi_entries[AFI_MAX * SAFI_MAX];
static int afi_safi_entry_count = 0;

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi
 * get_next callback - Iterate through configured AFI/SAFIs for a peer
 */
const void *bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_get_next(
	struct nb_cb_get_next_args *args)
{
	struct peer *peer = (struct peer *)args->parent_list_entry;
	afi_t afi;
	safi_t safi;
	int idx;

	if (!peer)
		return NULL;

	/* Build list of active AFI/SAFIs for this peer */
	if (args->list_entry == NULL) {
		afi_safi_entry_count = 0;
		FOREACH_AFI_SAFI (afi, safi) {
			if (peer->afc[afi][safi]) {
				afi_safi_entries[afi_safi_entry_count].peer = peer;
				afi_safi_entries[afi_safi_entry_count].afi = afi;
				afi_safi_entries[afi_safi_entry_count].safi = safi;
				afi_safi_entry_count++;
			}
		}
		if (afi_safi_entry_count > 0)
			return &afi_safi_entries[0];
		return NULL;
	}

	/* Find current entry and return next */
	for (idx = 0; idx < afi_safi_entry_count; idx++) {
		if (&afi_safi_entries[idx] == args->list_entry) {
			if (idx + 1 < afi_safi_entry_count)
				return &afi_safi_entries[idx + 1];
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi
 * get_keys callback - Return the key (afi-safi-name) for prefix stats
 */
int bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_get_keys(
	struct nb_cb_get_keys_args *args)
{
	struct bgp_afi_safi_entry *entry = (struct bgp_afi_safi_entry *)args->list_entry;
	const char *afi_safi_str;

	if (!entry)
		return NB_ERR;

	afi_safi_str = bgp_afi_safi_identity_str(entry->afi, entry->safi);
	if (!afi_safi_str)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], afi_safi_str, sizeof(args->keys->key[0]));

	return NB_OK;
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi
 * lookup_entry callback - Find AFI/SAFI entry by name
 */
const void *bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	/* For simplicity, return NULL - iteration is preferred */
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/received
 */
struct yang_data *bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_received_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_afi_safi_entry *entry = (struct bgp_afi_safi_entry *)args->list_entry;

	if (!entry || !entry->peer)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    entry->peer->pcount[entry->afi][entry->safi]);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/accepted
 */
struct yang_data *bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_accepted_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_afi_safi_entry *entry = (struct bgp_afi_safi_entry *)args->list_entry;

	if (!entry || !entry->peer)
		return NULL;

	/* pcount is the accepted count after filtering */
	return yang_data_new_uint32(args->xpath,
				    entry->peer->pcount[entry->afi][entry->safi]);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/sent
 * Returns the number of prefixes sent (advertised) to this peer for this AFI/SAFI.
 * This matches the PfxSnt column in "show bgp summary".
 */
struct yang_data *bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_advertised_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_afi_safi_entry *entry = (struct bgp_afi_safi_entry *)args->list_entry;
	struct peer_af *paf;
	struct update_subgroup *subgrp;

	if (!entry || !entry->peer)
		return NULL;

	/* Get the peer_af for this AFI/SAFI */
	paf = peer_af_find(entry->peer, entry->afi, entry->safi);
	if (!paf)
		return NULL;

	/* Get the subgroup and its scount (sent prefix count) */
	subgrp = PAF_SUBGRP(paf);
	if (!subgrp)
		return NULL;

	return yang_data_new_uint32(args->xpath, subgrp->scount);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/table-version
 * Returns the routing table version for this AFI/SAFI (TblVer from show bgp summary).
 */
struct yang_data *bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_table_version_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_afi_safi_entry *entry = (struct bgp_afi_safi_entry *)args->list_entry;
	struct peer_af *paf;
	struct update_subgroup *subgrp;

	if (!entry || !entry->peer)
		return NULL;

	/* Get the peer_af for this AFI/SAFI */
	paf = peer_af_find(entry->peer, entry->afi, entry->safi);
	if (!paf)
		return NULL;

	/* Get the subgroup and its version */
	subgrp = PAF_SUBGRP(paf);
	if (!subgrp)
		return NULL;

	return yang_data_new_uint64(args->xpath, subgrp->version);
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities
 * Capability Callbacks
 * ======================================================================== */

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/route-refresh
 */
struct yang_data *bgpd_instance_neighbors_neighbor_capabilities_route_refresh_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_RCV) ? true : false);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/four-octet-as
 */
struct yang_data *bgpd_instance_neighbors_neighbor_capabilities_four_octet_as_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV) ? true : false);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/graceful-restart
 */
struct yang_data *bgpd_instance_neighbors_neighbor_capabilities_graceful_restart_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV) ? true : false);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/add-path
 */
struct yang_data *bgpd_instance_neighbors_neighbor_capabilities_add_path_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(peer->cap, PEER_CAP_ADDPATH_RCV) ? true : false);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/extended-nexthop
 */
struct yang_data *bgpd_instance_neighbors_neighbor_capabilities_extended_nexthop_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(peer->cap, PEER_CAP_ENHE_RCV) ? true : false);
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group
 * Update Group Callbacks
 * ======================================================================== */

/* Static array to collect update groups during iteration */
#define MAX_UPDATE_GROUPS 1024
static struct update_group *updgrp_array[MAX_UPDATE_GROUPS];
static int updgrp_array_count = 0;

/* Callback to collect update groups into array */
static int updgrp_collect_cb(struct update_group *updgrp, void *ctx)
{
	if (updgrp_array_count < MAX_UPDATE_GROUPS) {
		updgrp_array[updgrp_array_count++] = updgrp;
	}
	return UPDWALK_CONTINUE;
}

/*
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group
 * get_next callback - Iterate through update groups
 */
const void *bgpd_instance_update_groups_update_group_get_next(
	struct nb_cb_get_next_args *args)
{
	struct bgp *bgp = (struct bgp *)args->parent_list_entry;
	int idx;

	if (!bgp)
		return NULL;

	if (args->list_entry == NULL) {
		/* First call - collect all update groups */
		updgrp_array_count = 0;
		update_group_walk(bgp, updgrp_collect_cb, NULL);

		if (updgrp_array_count > 0)
			return updgrp_array[0];
		return NULL;
	}

	/* Find current entry and return next */
	for (idx = 0; idx < updgrp_array_count; idx++) {
		if (updgrp_array[idx] == args->list_entry) {
			if (idx + 1 < updgrp_array_count)
				return updgrp_array[idx + 1];
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group
 * get_keys callback
 */
int bgpd_instance_update_groups_update_group_get_keys(
	struct nb_cb_get_keys_args *args)
{
	struct update_group *updgrp = (struct update_group *)args->list_entry;
	char id_str[32];

	if (!updgrp)
		return NB_ERR;

	args->keys->num = 1;
	snprintf(id_str, sizeof(id_str), "%" PRIu64, updgrp->id);
	strlcpy(args->keys->key[0], id_str, sizeof(args->keys->key[0]));

	return NB_OK;
}

/*
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group
 * lookup_entry callback
 */
const void *bgpd_instance_update_groups_update_group_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	/* Lookup by ID would require searching all update groups
	 * Iteration via get_next is preferred */
	return NULL;
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/dampening
 * Dampening State Callbacks (stub implementation)
 * ======================================================================== */

/*
 * Helper to find first active dampening config in BGP instance
 */
static struct bgp_damp_config *bgp_find_active_damp_config(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;

	if (!bgp)
		return NULL;

	FOREACH_AFI_SAFI (afi, safi) {
		if (bgp->damp[afi][safi].half_life > 0)
			return &bgp->damp[afi][safi];
	}
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/dampening/enabled
 */
struct yang_data *bgpd_instance_dampening_enabled_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;
	struct bgp_damp_config *bdc;

	if (!bgp)
		return NULL;

	bdc = bgp_find_active_damp_config(bgp);
	return yang_data_new_bool(args->xpath, bdc != NULL);
}

/*
 * XPath: /frr-bgp:bgpd/instance/dampening/half-life
 */
struct yang_data *bgpd_instance_dampening_half_life_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;
	struct bgp_damp_config *bdc;

	if (!bgp)
		return NULL;

	bdc = bgp_find_active_damp_config(bgp);
	if (!bdc)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)bdc->half_life);
}

/*
 * XPath: /frr-bgp:bgpd/instance/dampening/reuse-limit
 */
struct yang_data *bgpd_instance_dampening_reuse_limit_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;
	struct bgp_damp_config *bdc;

	if (!bgp)
		return NULL;

	bdc = bgp_find_active_damp_config(bgp);
	if (!bdc)
		return NULL;

	return yang_data_new_uint32(args->xpath, bdc->reuse_limit);
}

/*
 * XPath: /frr-bgp:bgpd/instance/dampening/suppress-limit
 */
struct yang_data *bgpd_instance_dampening_suppress_limit_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;
	struct bgp_damp_config *bdc;

	if (!bgp)
		return NULL;

	bdc = bgp_find_active_damp_config(bgp);
	if (!bdc)
		return NULL;

	return yang_data_new_uint32(args->xpath, bdc->suppress_value);
}

/*
 * XPath: /frr-bgp:bgpd/instance/dampening/max-suppress-time
 */
struct yang_data *bgpd_instance_dampening_max_suppress_time_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;
	struct bgp_damp_config *bdc;

	if (!bgp)
		return NULL;

	bdc = bgp_find_active_damp_config(bgp);
	if (!bdc)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)bdc->max_suppress_time);
}

/*
 * XPath: /frr-bgp:bgpd/instance/dampening/dampened-paths
 */
struct yang_data *bgpd_instance_dampening_dampened_paths_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* Dampened paths count requires iteration through damped route list
	 * which is expensive - return count from mtype for now */
	unsigned long count = mtype_stats_alloc(MTYPE_BGP_DAMP_INFO);
	return yang_data_new_uint32(args->xpath, (uint32_t)count);
}

/*
 * XPath: /frr-bgp:bgpd/instance/dampening/history-paths
 */
struct yang_data *bgpd_instance_dampening_history_paths_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* History paths would require iterating the no_reuse_list
	 * Return 0 for now as this is rarely needed */
	return yang_data_new_uint32(args->xpath, 0);
}

/*
 * XPath: /frr-bgp:bgpd/instance/vrf
 */
struct yang_data *bgpd_instance_vrf_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;

	if (!bgp)
		return NULL;

	return yang_data_new_string(args->xpath, bgp->name ? bgp->name : VRF_DEFAULT_NAME);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/remote-address
 */
struct yang_data *bgpd_instance_neighbors_neighbor_remote_address_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	char buf[SU_ADDRSTRLEN];

	if (!peer || !peer->connection)
		return NULL;

	sockunion2str(&peer->connection->su, buf, sizeof(buf));
	return yang_data_new_string(args->xpath, buf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/total
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_sent_total_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	uint64_t total;

	if (!peer)
		return NULL;

	total = atomic_load_explicit(&peer->open_out, memory_order_relaxed) +
		atomic_load_explicit(&peer->update_out, memory_order_relaxed) +
		atomic_load_explicit(&peer->keepalive_out, memory_order_relaxed) +
		atomic_load_explicit(&peer->notify_out, memory_order_relaxed) +
		atomic_load_explicit(&peer->refresh_out, memory_order_relaxed);

	return yang_data_new_uint64(args->xpath, total);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/total
 */
struct yang_data *bgpd_instance_neighbors_neighbor_message_statistics_received_total_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	uint64_t total;

	if (!peer)
		return NULL;

	total = atomic_load_explicit(&peer->open_in, memory_order_relaxed) +
		atomic_load_explicit(&peer->update_in, memory_order_relaxed) +
		atomic_load_explicit(&peer->keepalive_in, memory_order_relaxed) +
		atomic_load_explicit(&peer->notify_in, memory_order_relaxed) +
		atomic_load_explicit(&peer->refresh_in, memory_order_relaxed);

	return yang_data_new_uint64(args->xpath, total);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/afi-safi-name
 */
struct yang_data *bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_afi_safi_name_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_afi_safi_entry *entry = (struct bgp_afi_safi_entry *)args->list_entry;
	const char *afi_safi_str;

	if (!entry)
		return NULL;

	afi_safi_str = bgp_afi_safi_identity_str(entry->afi, entry->safi);
	if (!afi_safi_str)
		return NULL;

	return yang_data_new_string(args->xpath, afi_safi_str);
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/advertised
 * get_next callback for leaf-list
 */
const void *bgpd_instance_neighbors_neighbor_capabilities_advertised_get_next(
	struct nb_cb_get_next_args *args)
{
	/* TODO: Implement capability iteration */
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/advertised
 */
struct yang_data *bgpd_instance_neighbors_neighbor_capabilities_advertised_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: Implement capability list */
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/received
 * get_next callback for leaf-list
 */
const void *bgpd_instance_neighbors_neighbor_capabilities_received_get_next(
	struct nb_cb_get_next_args *args)
{
	/* TODO: Implement capability iteration */
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/received
 */
struct yang_data *bgpd_instance_neighbors_neighbor_capabilities_received_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: Implement capability list */
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group/id
 */
struct yang_data *bgpd_instance_update_groups_update_group_id_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct update_group *updgrp = (struct update_group *)args->list_entry;

	if (!updgrp)
		return NULL;

	return yang_data_new_uint64(args->xpath, updgrp->id);
}

/*
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group/afi-safi
 */
struct yang_data *bgpd_instance_update_groups_update_group_afi_safi_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct update_group *updgrp = (struct update_group *)args->list_entry;
	const char *afi_safi_str;

	if (!updgrp)
		return NULL;

	afi_safi_str = bgp_afi_safi_identity_str(updgrp->afi, updgrp->safi);
	if (!afi_safi_str)
		return NULL;

	return yang_data_new_string(args->xpath, afi_safi_str);
}

/*
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group/member-count
 */
struct yang_data *bgpd_instance_update_groups_update_group_member_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct update_group *updgrp = (struct update_group *)args->list_entry;
	struct update_subgroup *subgrp;
	uint32_t count = 0;

	if (!updgrp)
		return NULL;

	/* Count peers across all subgroups */
	LIST_FOREACH (subgrp, &updgrp->subgrps, updgrp_train) {
		count += subgrp->peer_count;
	}

	return yang_data_new_uint32(args->xpath, count);
}

/*
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group/update-count
 */
struct yang_data *bgpd_instance_update_groups_update_group_update_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct update_group *updgrp = (struct update_group *)args->list_entry;
	struct update_subgroup *subgrp;
	uint32_t count = 0;

	if (!updgrp)
		return NULL;

	/* Count updates across all subgroups */
	LIST_FOREACH (subgrp, &updgrp->subgrps, updgrp_train) {
		count += subgrp->scount;
	}

	return yang_data_new_uint32(args->xpath, count);
}

/*
 * XPath: /frr-bgp:bgpd/instance/update-groups/update-group/packet-queue-length
 */
struct yang_data *bgpd_instance_update_groups_update_group_packet_queue_length_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct update_group *updgrp = (struct update_group *)args->list_entry;
	struct update_subgroup *subgrp;
	uint32_t count = 0;

	if (!updgrp)
		return NULL;

	/* Count packet queue across all subgroups */
	LIST_FOREACH (subgrp, &updgrp->subgrps, updgrp_train) {
		count += bpacket_queue_length(&subgrp->pkt_queue);
	}

	return yang_data_new_uint32(args->xpath, count);
}

/* ========================================================================
 * XPath: /frr-bgp:bgpd/instance/srv6
 * SRv6 Operational State Callbacks
 * ======================================================================== */

/*
 * XPath: /frr-bgp:bgpd/instance/srv6/enabled
 */
struct yang_data *bgpd_instance_srv6_enabled_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;

	if (!bgp)
		return NULL;

	/* SRv6 is enabled when a locator is configured */
	return yang_data_new_bool(args->xpath, bgp->srv6_locator != NULL);
}

/*
 * XPath: /frr-bgp:bgpd/instance/srv6/locator-name
 */
struct yang_data *bgpd_instance_srv6_locator_name_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp *bgp = (struct bgp *)args->list_entry;

	if (!bgp)
		return NULL;

	if (bgp->srv6_locator_name[0] == '\0')
		return NULL;

	return yang_data_new_string(args->xpath, bgp->srv6_locator_name);
}

/* Static array for SRv6 SID iteration */
#define MAX_SRV6_SIDS 256
static struct bgp_srv6_function *srv6_sid_array[MAX_SRV6_SIDS];
static int srv6_sid_array_count = 0;

/*
 * XPath: /frr-bgp:bgpd/instance/srv6/sid
 * get_next callback - Iterate through SRv6 SIDs
 */
const void *bgpd_instance_srv6_sid_get_next(
	struct nb_cb_get_next_args *args)
{
	struct bgp *bgp = (struct bgp *)args->parent_list_entry;
	struct listnode *node;
	struct bgp_srv6_function *func;
	int idx;

	if (!bgp || !bgp->srv6_functions)
		return NULL;

	if (args->list_entry == NULL) {
		/* First call - collect all SRv6 functions */
		srv6_sid_array_count = 0;
		for (ALL_LIST_ELEMENTS_RO(bgp->srv6_functions, node, func)) {
			if (srv6_sid_array_count < MAX_SRV6_SIDS) {
				srv6_sid_array[srv6_sid_array_count++] = func;
			}
		}

		if (srv6_sid_array_count > 0)
			return srv6_sid_array[0];
		return NULL;
	}

	/* Find current entry and return next */
	for (idx = 0; idx < srv6_sid_array_count; idx++) {
		if (srv6_sid_array[idx] == args->list_entry) {
			if (idx + 1 < srv6_sid_array_count)
				return srv6_sid_array[idx + 1];
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/srv6/sid
 * get_keys callback
 */
int bgpd_instance_srv6_sid_get_keys(
	struct nb_cb_get_keys_args *args)
{
	struct bgp_srv6_function *func = (struct bgp_srv6_function *)args->list_entry;
	char buf[INET6_ADDRSTRLEN];

	if (!func)
		return NB_ERR;

	args->keys->num = 1;
	inet_ntop(AF_INET6, &func->sid, buf, sizeof(buf));
	strlcpy(args->keys->key[0], buf, sizeof(args->keys->key[0]));

	return NB_OK;
}

/*
 * XPath: /frr-bgp:bgpd/instance/srv6/sid
 * lookup_entry callback
 */
const void *bgpd_instance_srv6_sid_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	/* Iteration via get_next is preferred */
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/srv6/sid/value
 */
struct yang_data *bgpd_instance_srv6_sid_value_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_srv6_function *func = (struct bgp_srv6_function *)args->list_entry;

	if (!func)
		return NULL;

	return yang_data_new_ipv6(args->xpath, &func->sid);
}

/*
 * XPath: /frr-bgp:bgpd/instance/srv6/sid/function-type
 * Note: BGP SRv6 functions are typically End.DT4/DT6/DT46 based on VPN type
 * Currently return NULL as function type isn't stored in bgp_srv6_function
 */
struct yang_data *bgpd_instance_srv6_sid_function_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* Function type would need to be determined from context
	 * (which VPN/VRF the SID is associated with)
	 * Return NULL for now - this is optional operational data */
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/srv6/sid/vrf
 */
struct yang_data *bgpd_instance_srv6_sid_vrf_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* VRF association would need additional context
	 * Return NULL for now - this is optional operational data */
	return NULL;
}

/* ========================================================================
 * Provides access to BGP routing table entries per AFI/SAFI.
 * ======================================================================== */

/*
 * Structure to hold AFI/SAFI context for routes iteration.
 * We iterate over all AFI/SAFI combinations that have valid tables.
 */
struct bgp_routes_afi_safi_entry {
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
};

/* Static array for AFI/SAFI entries (reused during iteration) */
static struct bgp_routes_afi_safi_entry routes_afi_safi_entries[AFI_MAX * SAFI_MAX];
static int routes_afi_safi_count = 0;

/*
 * Structure to hold route entry context for iteration.
 * Used by lookup_entry callback for specific route queries.
 */
struct bgp_route_entry {
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct bgp_dest *dest;
};

/* Static array for route entries - used by lookup_entry */
static struct bgp_route_entry route_entries[1024];

/*
 * Structure to hold path entry context for iteration.
 * Used by lookup_entry callback for specific path queries.
 */
struct bgp_path_entry {
	struct bgp *bgp;          /* BGP instance - needed for RD formatting */
	struct bgp_dest *dest;    /* Destination node (has RD for VPN) */
	struct bgp_path_info *pi; /* Path info */
	afi_t afi;                /* Address family */
	safi_t safi;              /* Sub-address family - needed for RD/UN checks */
	uint32_t path_id;         /* Path identifier */
};

/* Static array for path entries - used by lookup_entry and get_next */
static struct bgp_path_entry path_entries[256];
static int path_entry_count = 0;

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi
 * get_next callback - Iterate through AFI/SAFIs that have tables
 */
const void *bgpd_instance_routes_afi_safi_get_next(
	struct nb_cb_get_next_args *args)
{
	struct bgp *bgp = (struct bgp *)args->parent_list_entry;
	afi_t afi;
	safi_t safi;
	int idx;

	if (!bgp)
		return NULL;

	/* Build list of AFI/SAFIs with valid tables AND valid identity strings */
	if (args->list_entry == NULL) {
		routes_afi_safi_count = 0;
		FOREACH_AFI_SAFI (afi, safi) {
			/* Only include if we have both a table AND a valid identity */
			if (bgp->rib[afi][safi] &&
			    bgp_afi_safi_identity_str(afi, safi) != NULL) {
				routes_afi_safi_entries[routes_afi_safi_count].bgp = bgp;
				routes_afi_safi_entries[routes_afi_safi_count].afi = afi;
				routes_afi_safi_entries[routes_afi_safi_count].safi = safi;
				routes_afi_safi_count++;
				/* Limit to avoid array overflow */
				if (routes_afi_safi_count >= AFI_MAX * SAFI_MAX)
					break;
			}
		}
		if (routes_afi_safi_count > 0)
			return &routes_afi_safi_entries[0];
		return NULL;
	}

	/* Find current entry and return next */
	for (idx = 0; idx < routes_afi_safi_count; idx++) {
		if (&routes_afi_safi_entries[idx] == args->list_entry) {
			if (idx + 1 < routes_afi_safi_count)
				return &routes_afi_safi_entries[idx + 1];
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi
 * get_keys callback
 */
int bgpd_instance_routes_afi_safi_get_keys(struct nb_cb_get_keys_args *args)
{
	struct bgp_routes_afi_safi_entry *entry =
		(struct bgp_routes_afi_safi_entry *)args->list_entry;
	const char *afi_safi_str;

	if (!entry)
		return NB_ERR;

	afi_safi_str = bgp_afi_safi_identity_str(entry->afi, entry->safi);
	if (!afi_safi_str)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], afi_safi_str, sizeof(args->keys->key[0]));

	return NB_OK;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi
 * lookup_entry callback
 */
const void *bgpd_instance_routes_afi_safi_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	struct bgp *bgp = (struct bgp *)args->parent_list_entry;
	const char *afi_safi_name = args->keys->key[0];
	afi_t afi;
	safi_t safi;

	if (!bgp || !afi_safi_name)
		return NULL;

	/* Find AFI/SAFI from identity string */
	FOREACH_AFI_SAFI (afi, safi) {
		const char *name = bgp_afi_safi_identity_str(afi, safi);
		if (name && strcmp(name, afi_safi_name) == 0) {
			if (bgp->rib[afi][safi]) {
				/* Reuse first entry for lookup */
				routes_afi_safi_entries[0].bgp = bgp;
				routes_afi_safi_entries[0].afi = afi;
				routes_afi_safi_entries[0].safi = safi;
				return &routes_afi_safi_entries[0];
			}
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/afi-safi-name
 */
struct yang_data *bgpd_instance_routes_afi_safi_afi_safi_name_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_routes_afi_safi_entry *entry =
		(struct bgp_routes_afi_safi_entry *)args->list_entry;
	const char *afi_safi_str;

	if (!entry)
		return NULL;

	afi_safi_str = bgp_afi_safi_identity_str(entry->afi, entry->safi);
	if (!afi_safi_str)
		return NULL;

	return yang_data_new_string(args->xpath, afi_safi_str);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/table-version
 */
struct yang_data *bgpd_instance_routes_afi_safi_table_version_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_routes_afi_safi_entry *entry =
		(struct bgp_routes_afi_safi_entry *)args->list_entry;
	struct bgp_table *table;

	if (!entry || !entry->bgp)
		return NULL;

	table = entry->bgp->rib[entry->afi][entry->safi];
	if (!table)
		return NULL;

	return yang_data_new_uint64(args->xpath, table->version);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route-count
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_routes_afi_safi_entry *entry =
		(struct bgp_routes_afi_safi_entry *)args->list_entry;
	struct bgp_table *table;
	struct bgp_dest *dest;
	uint32_t count = 0;

	if (!entry || !entry->bgp)
		return NULL;

	table = entry->bgp->rib[entry->afi][entry->safi];
	if (!table)
		return NULL;

	/* Count routes with at least one path */
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		if (bgp_dest_get_bgp_path_info(dest))
			count++;
	}

	return yang_data_new_uint32(args->xpath, count);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route
 * get_next callback - Iterate through routes in a table
 */
const void *bgpd_instance_routes_afi_safi_route_get_next(
	struct nb_cb_get_next_args *args)
{
	/*
	 * Routes are not exposed via full iteration to avoid performance
	 * issues with large tables. Use specific route lookup via RESTCONF
	 * path instead:
	 *   /frr-bgp:bgpd/instance[name='default']/routes/afi-safi[afi-safi-name='ipv4-unicast']/route[prefix='10.0.0.0/24']
	 *
	 * The AFI/SAFI list will show table-version and route-count for each.
	 */
	(void)args;
	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route
 * get_keys callback
 */
int bgpd_instance_routes_afi_safi_route_get_keys(struct nb_cb_get_keys_args *args)
{
	struct bgp_route_entry *entry = (struct bgp_route_entry *)args->list_entry;
	const struct prefix *p;

	if (!entry || !entry->dest)
		return NB_ERR;

	p = bgp_dest_get_prefix(entry->dest);
	if (!p)
		return NB_ERR;

	args->keys->num = 1;
	prefix2str(p, args->keys->key[0], sizeof(args->keys->key[0]));

	return NB_OK;
}

/*
 * Check if SAFI uses two-level table structure (RD -> prefixes)
 */
static bool safi_is_two_level(safi_t safi)
{
	return (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route
 * lookup_entry callback
 */
const void *bgpd_instance_routes_afi_safi_route_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	struct bgp_routes_afi_safi_entry *afi_safi_entry =
		(struct bgp_routes_afi_safi_entry *)args->parent_list_entry;
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct prefix p;
	const char *prefix_str = args->keys->key[0];

	if (!afi_safi_entry || !afi_safi_entry->bgp || !prefix_str)
		return NULL;

	table = afi_safi_entry->bgp->rib[afi_safi_entry->afi][afi_safi_entry->safi];
	if (!table)
		return NULL;

	if (str2prefix(prefix_str, &p) == 0)
		return NULL;

	/*
	 * VPN/ENCAP/EVPN use two-level table: RD -> sub-table -> prefixes
	 * Other SAFIs use single-level: table -> prefixes
	 */
	if (safi_is_two_level(afi_safi_entry->safi)) {
		/* Two-level table: iterate through all RD entries */
		struct bgp_dest *rd_dest;

		for (rd_dest = bgp_table_top(table); rd_dest;
		     rd_dest = bgp_route_next(rd_dest)) {
			struct bgp_table *sub_table;

			sub_table = bgp_dest_get_bgp_table_info(rd_dest);
			if (!sub_table)
				continue;

			dest = bgp_node_lookup(sub_table, &p);
			if (dest && bgp_dest_get_bgp_path_info(dest)) {
				/* Found it - unlock the RD iteration */
				bgp_dest_unlock_node(rd_dest);
				goto found;
			}
		}
		/* Not found in any RD */
		return NULL;
	} else {
		/* Single-level table: direct lookup */
		dest = bgp_node_lookup(table, &p);
		if (!dest || !bgp_dest_get_bgp_path_info(dest))
			return NULL;
	}

found:
	/* Reuse first entry for lookup */
	route_entries[0].bgp = afi_safi_entry->bgp;
	route_entries[0].afi = afi_safi_entry->afi;
	route_entries[0].safi = afi_safi_entry->safi;
	route_entries[0].dest = dest;

	return &route_entries[0];
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/prefix
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_prefix_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_route_entry *entry = (struct bgp_route_entry *)args->list_entry;
	const struct prefix *p;
	char buf[PREFIX_STRLEN];

	if (!entry || !entry->dest)
		return NULL;

	p = bgp_dest_get_prefix(entry->dest);
	if (!p)
		return NULL;

	prefix2str(p, buf, sizeof(buf));
	return yang_data_new_string(args->xpath, buf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path
 * get_next callback - Iterate through paths for a route
 */
const void *bgpd_instance_routes_afi_safi_route_path_get_next(
	struct nb_cb_get_next_args *args)
{
	struct bgp_route_entry *route_entry =
		(struct bgp_route_entry *)args->parent_list_entry;
	struct bgp_path_info *pi;
	int idx;
	uint32_t path_id = 0;

	if (!route_entry || !route_entry->dest)
		return NULL;

	/* Build list of paths */
	if (args->list_entry == NULL) {
		path_entry_count = 0;
		for (pi = bgp_dest_get_bgp_path_info(route_entry->dest);
		     pi && path_entry_count < 256; pi = pi->next) {
			path_entries[path_entry_count].bgp = route_entry->bgp;
			path_entries[path_entry_count].afi = route_entry->afi;
			path_entries[path_entry_count].safi = route_entry->safi;
			path_entries[path_entry_count].dest = route_entry->dest;
			path_entries[path_entry_count].pi = pi;
			path_entries[path_entry_count].path_id = path_id++;
			path_entry_count++;
		}
		if (path_entry_count > 0)
			return &path_entries[0];
		return NULL;
	}

	/* Find current entry and return next */
	for (idx = 0; idx < path_entry_count; idx++) {
		if (&path_entries[idx] == args->list_entry) {
			if (idx + 1 < path_entry_count)
				return &path_entries[idx + 1];
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path
 * get_keys callback
 */
int bgpd_instance_routes_afi_safi_route_path_get_keys(struct nb_cb_get_keys_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry)
		return NB_ERR;

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]),
		 "%u", entry->path_id);

	return NB_OK;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path
 * lookup_entry callback
 */
const void *bgpd_instance_routes_afi_safi_route_path_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	struct bgp_route_entry *route_entry =
		(struct bgp_route_entry *)args->parent_list_entry;
	struct bgp_path_info *pi;
	uint32_t target_id;
	uint32_t path_id = 0;

	if (!route_entry || !route_entry->dest)
		return NULL;

	target_id = strtoul(args->keys->key[0], NULL, 10);

	for (pi = bgp_dest_get_bgp_path_info(route_entry->dest);
	     pi; pi = pi->next, path_id++) {
		if (path_id == target_id) {
			path_entries[0].bgp = route_entry->bgp;
			path_entries[0].afi = route_entry->afi;
			path_entries[0].safi = route_entry->safi;
			path_entries[0].dest = route_entry->dest;
			path_entries[0].pi = pi;
			path_entries[0].path_id = path_id;
			return &path_entries[0];
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/path-id
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_path_id_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry)
		return NULL;

	return yang_data_new_uint32(args->xpath, entry->path_id);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/nexthop
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_nexthop_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	struct bgp_path_info *pi;
	char buf[INET6_ADDRSTRLEN];

	if (!entry || !entry->pi)
		return NULL;

	pi = entry->pi;
	if (!pi->attr)
		return NULL;

	/* Get nexthop based on address family */
	if (pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL ||
	    pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
		inet_ntop(AF_INET6, &pi->attr->mp_nexthop_global, buf, sizeof(buf));
	} else if (pi->attr->nexthop.s_addr != INADDR_ANY) {
		inet_ntop(AF_INET, &pi->attr->nexthop, buf, sizeof(buf));
	} else {
		return NULL;
	}

	return yang_data_new_string(args->xpath, buf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/metric
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_metric_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	return yang_data_new_uint32(args->xpath, entry->pi->attr->med);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/local-preference
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_local_pref_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	return yang_data_new_uint32(args->xpath, entry->pi->attr->local_pref);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/weight
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_weight_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	return yang_data_new_uint32(args->xpath, entry->pi->attr->weight);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/origin
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_origin_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	const char *origin_str;

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	switch (entry->pi->attr->origin) {
	case BGP_ORIGIN_IGP:
		origin_str = "igp";
		break;
	case BGP_ORIGIN_EGP:
		origin_str = "egp";
		break;
	case BGP_ORIGIN_INCOMPLETE:
	default:
		origin_str = "incomplete";
		break;
	}

	return yang_data_new_string(args->xpath, origin_str);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/as-path
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_as_path_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	const char *aspath_str;

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	if (!entry->pi->attr->aspath)
		return NULL;

	/* aspath_print returns internal string - don't free */
	aspath_str = aspath_print(entry->pi->attr->aspath);
	if (!aspath_str)
		return NULL;

	return yang_data_new_string(args->xpath, aspath_str);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/communities
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_communities_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	char *comm_str;
	struct yang_data *data;

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	if (!bgp_attr_get_community(entry->pi->attr))
		return NULL;

	comm_str = community_str(bgp_attr_get_community(entry->pi->attr), false, false);
	if (!comm_str)
		return NULL;

	data = yang_data_new_string(args->xpath, comm_str);

	return data;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/extended-communities
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_ext_communities_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	char *eccomm_str;
	struct yang_data *data;

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	if (!bgp_attr_get_ecommunity(entry->pi->attr))
		return NULL;

	eccomm_str = ecommunity_ecom2str(bgp_attr_get_ecommunity(entry->pi->attr),
					 ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
	if (!eccomm_str)
		return NULL;

	data = yang_data_new_string(args->xpath, eccomm_str);
	XFREE(MTYPE_ECOMMUNITY_STR, eccomm_str);

	return data;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/large-communities
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_large_communities_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	char *lccomm_str;
	struct yang_data *data;

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	if (!bgp_attr_get_lcommunity(entry->pi->attr))
		return NULL;

	lccomm_str = lcommunity_str(bgp_attr_get_lcommunity(entry->pi->attr), false, false);
	if (!lccomm_str)
		return NULL;

	data = yang_data_new_string(args->xpath, lccomm_str);

	return data;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/source-peer
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_source_peer_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	char buf[SU_ADDRSTRLEN];

	if (!entry || !entry->pi || !entry->pi->peer)
		return NULL;

	/* Check if connection exists - for locally originated routes peer may not have connection */
	if (!entry->pi->peer->connection)
		return NULL;

	sockunion2str(&entry->pi->peer->connection->su, buf, sizeof(buf));

	return yang_data_new_string(args->xpath, buf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/valid
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_valid_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry || !entry->pi)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(entry->pi->flags, BGP_PATH_VALID));
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/best
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_best_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry || !entry->pi)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(entry->pi->flags, BGP_PATH_SELECTED));
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/stale
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_stale_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry || !entry->pi)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(entry->pi->flags, BGP_PATH_STALE));
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/multipath
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_multipath_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry || !entry->pi)
		return NULL;

	return yang_data_new_bool(args->xpath,
				  CHECK_FLAG(entry->pi->flags, BGP_PATH_MULTIPATH));
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/uptime
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_uptime_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	char timebuf[BGP_UPTIME_LEN];

	if (!entry || !entry->pi)
		return NULL;

	peer_uptime(entry->pi->uptime, timebuf, sizeof(timebuf), 0, NULL);

	return yang_data_new_string(args->xpath, timebuf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/route-type
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_route_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;

	if (!entry || !entry->pi)
		return NULL;

	return yang_data_new_string(args->xpath,
				    zebra_route_string(entry->pi->type));
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/route-subtype
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_route_subtype_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	const char *subtype_str;

	if (!entry || !entry->pi)
		return NULL;

	switch (entry->pi->sub_type) {
	case BGP_ROUTE_NORMAL:
		subtype_str = "normal";
		break;
	case BGP_ROUTE_STATIC:
		subtype_str = "static";
		break;
	case BGP_ROUTE_AGGREGATE:
		subtype_str = "aggregate";
		break;
	case BGP_ROUTE_REDISTRIBUTE:
		subtype_str = "redistribute";
		break;
	case BGP_ROUTE_IMPORTED:
		subtype_str = "imported";
		break;
	default:
		subtype_str = "normal";
		break;
	}

	return yang_data_new_string(args->xpath, subtype_str);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/route-distinguisher
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_rd_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	const struct prefix_rd *prd;
	char rd_str[RD_ADDRSTRLEN];
	enum asnotation_mode asnotation;

	if (!entry || !entry->dest)
		return NULL;

	/*
	 * For VPN SAFIs, the RD is stored on the parent dest (RD entry),
	 * not on the prefix dest itself. Use dest->pdest to get the RD.
	 */
	if (entry->dest->pdest)
		prd = bgp_rd_from_dest(entry->dest->pdest, entry->safi);
	else
		prd = bgp_rd_from_dest(entry->dest, entry->safi);

	if (!prd)
		return NULL;

	asnotation = entry->bgp ? bgp_get_asnotation(entry->bgp)
				: ASNOTATION_PLAIN;
	prefix_rd2str(prd, rd_str, sizeof(rd_str), asnotation);
	return yang_data_new_string(args->xpath, rd_str);
}

/*
 * Structure to hold label iteration context for leaf-list.
 * Needed because get_elem doesn't have parent_list_entry.
 */
struct bgp_label_iter {
	struct bgp_path_entry *path_entry;
	uint8_t label_idx;
};

/* Static array for label iteration */
static struct bgp_label_iter label_iters[BGP_MAX_LABELS];
static int label_iter_count;

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/mpls-labels
 * get_next callback - Iterate through labels for a path
 */
const void *bgpd_instance_routes_afi_safi_route_path_mpls_labels_get_next(
	struct nb_cb_get_next_args *args)
{
	struct bgp_path_entry *entry;
	int idx;

	entry = (struct bgp_path_entry *)args->parent_list_entry;
	if (!entry || !entry->pi)
		return NULL;

	/* Check if this path has labels */
	if (!entry->pi->extra || !entry->pi->extra->labels ||
	    entry->pi->extra->labels->num_labels == 0)
		return NULL;

	if (args->list_entry == NULL) {
		/* First iteration - build label iter array */
		label_iter_count = 0;
		for (idx = 0; idx < entry->pi->extra->labels->num_labels &&
			      idx < BGP_MAX_LABELS; idx++) {
			label_iters[idx].path_entry = entry;
			label_iters[idx].label_idx = idx;
			label_iter_count++;
		}
		if (label_iter_count > 0)
			return &label_iters[0];
		return NULL;
	}

	/* Find current entry and return next */
	for (idx = 0; idx < label_iter_count; idx++) {
		if (&label_iters[idx] == args->list_entry) {
			if (idx + 1 < label_iter_count)
				return &label_iters[idx + 1];
			return NULL;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/mpls-labels
 * get_elem callback
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_mpls_labels_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_label_iter *iter;
	struct bgp_path_entry *entry;
	uint32_t label_val;

	iter = (struct bgp_label_iter *)args->list_entry;
	if (!iter || !iter->path_entry)
		return NULL;

	entry = iter->path_entry;
	if (!entry->pi || !entry->pi->extra || !entry->pi->extra->labels)
		return NULL;

	if (iter->label_idx >= entry->pi->extra->labels->num_labels)
		return NULL;

	label_val = decode_label(&entry->pi->extra->labels->label[iter->label_idx]);
	return yang_data_new_uint32(args->xpath, label_val);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/underlay-nexthop
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_underlay_nh_get_elem(
	struct nb_cb_get_elem_args *args)
{
#if ENABLE_BGP_VNC
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	struct prefix pfx_un;
	char buf[INET6_ADDRSTRLEN];

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	/* Underlay nexthop only meaningful for MPLS VPN SAFI */
	if (entry->safi != SAFI_MPLS_VPN)
		return NULL;

	if (rfapiGetVncTunnelUnAddr(entry->pi->attr, &pfx_un) != 0)
		return NULL;

	inet_ntop(pfx_un.family, pfx_un.u.val, buf, sizeof(buf));
	return yang_data_new_string(args->xpath, buf);
#else
	return NULL;
#endif
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/srv6-sid
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_srv6_sid_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	struct in6_addr *sid = NULL;
	char buf[INET6_ADDRSTRLEN];

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	if (entry->pi->attr->srv6_vpn)
		sid = &entry->pi->attr->srv6_vpn->sid;
	else if (entry->pi->attr->srv6_vpn)
		sid = &entry->pi->attr->srv6_vpn->sid;

	if (!sid)
		return NULL;

	inet_ntop(AF_INET6, sid, buf, sizeof(buf));
	return yang_data_new_string(args->xpath, buf);
}

/*
 * XPath: /frr-bgp:bgpd/instance/routes/afi-safi/route/path/srv6-sid-structure
 */
struct yang_data *bgpd_instance_routes_afi_safi_route_path_srv6_sid_struct_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct bgp_path_entry *entry = (struct bgp_path_entry *)args->list_entry;
	char buf[64];

	if (!entry || !entry->pi || !entry->pi->attr)
		return NULL;

	if (!entry->pi->attr->srv6_l3service ||
	    entry->pi->attr->srv6_l3service->loc_block_len == 0)
		return NULL;

	snprintf(buf, sizeof(buf), "[%d,%d,%d,%d]",
		 entry->pi->attr->srv6_l3service->loc_block_len,
		 entry->pi->attr->srv6_l3service->loc_node_len,
		 entry->pi->attr->srv6_l3service->func_len,
		 entry->pi->attr->srv6_l3service->arg_len);

	return yang_data_new_string(args->xpath, buf);
}
