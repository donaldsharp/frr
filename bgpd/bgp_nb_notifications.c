// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound API - YANG Notifications
 * Copyright (C) 2024 FRRouting
 */

#include <zebra.h>

#include "northbound.h"
#include "log.h"
#include "prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_debug.h"

/*
 * Helper function to get VRF name
 */
static const char *bgp_notif_get_vrf_name(const struct bgp *bgp)
{
	if (!bgp || !bgp->name)
		return "default";
	return bgp->name;
}

/*
 * Helper function to get peer address as string
 * Uses peer->host which is already a printable address string
 */
static const char *bgp_notif_get_peer_addr(const struct peer *peer)
{
	if (!peer || !peer->host)
		return "unknown";
	return peer->host;
}

/*
 * XPath: /frr-bgp:peer-state-change
 *
 * Send notification when BGP peer FSM state changes.
 */
void bgp_notif_state_change(const struct peer *peer, int old_state,
			    int new_state)
{
	const char *xpath = "/frr-bgp:peer-state-change";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	if (!peer || !peer->bgp)
		return;

	arguments = yang_data_list_new();

	/* peer-address */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/peer-address", xpath);
	data = yang_data_new_string(xpath_arg, bgp_notif_get_peer_addr(peer));
	listnode_add(arguments, data);

	/* vrf-name */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/vrf-name", xpath);
	data = yang_data_new_string(xpath_arg,
				    bgp_notif_get_vrf_name(peer->bgp));
	listnode_add(arguments, data);

	/* local-as */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/local-as", xpath);
	data = yang_data_new_uint32(xpath_arg, peer->local_as);
	listnode_add(arguments, data);

	/* remote-as */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/remote-as", xpath);
	data = yang_data_new_uint32(xpath_arg, peer->as);
	listnode_add(arguments, data);

	/* old-state */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/old-state", xpath);
	data = yang_data_new_enum(xpath_arg, old_state);
	listnode_add(arguments, data);

	/* new-state */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/new-state", xpath);
	data = yang_data_new_enum(xpath_arg, new_state);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-bgp:peer-established
 *
 * Send notification when BGP peer reaches Established state.
 */
void bgp_notif_peer_established(const struct peer *peer)
{
	const char *xpath = "/frr-bgp:peer-established";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	char router_id[INET_ADDRSTRLEN];
	struct yang_data *data;

	if (!peer || !peer->bgp)
		return;

	arguments = yang_data_list_new();

	/* peer-address */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/peer-address", xpath);
	data = yang_data_new_string(xpath_arg, bgp_notif_get_peer_addr(peer));
	listnode_add(arguments, data);

	/* vrf-name */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/vrf-name", xpath);
	data = yang_data_new_string(xpath_arg,
				    bgp_notif_get_vrf_name(peer->bgp));
	listnode_add(arguments, data);

	/* local-as */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/local-as", xpath);
	data = yang_data_new_uint32(xpath_arg, peer->local_as);
	listnode_add(arguments, data);

	/* remote-as */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/remote-as", xpath);
	data = yang_data_new_uint32(xpath_arg, peer->as);
	listnode_add(arguments, data);

	/* local-router-id */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/local-router-id", xpath);
	inet_ntop(AF_INET, &peer->bgp->router_id, router_id, sizeof(router_id));
	data = yang_data_new_string(xpath_arg, router_id);
	listnode_add(arguments, data);

	/* remote-router-id */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/remote-router-id", xpath);
	inet_ntop(AF_INET, &peer->remote_id, router_id, sizeof(router_id));
	data = yang_data_new_string(xpath_arg, router_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-bgp:backward-transition
 *
 * Send notification when BGP peer leaves Established state (peer down).
 */
void bgp_notif_backward_transition(const struct peer *peer, int old_state,
				   int new_state, const char *reason,
				   uint8_t error_code, uint8_t error_subcode)
{
	const char *xpath = "/frr-bgp:backward-transition";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	if (!peer || !peer->bgp)
		return;

	arguments = yang_data_list_new();

	/* peer-address */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/peer-address", xpath);
	data = yang_data_new_string(xpath_arg, bgp_notif_get_peer_addr(peer));
	listnode_add(arguments, data);

	/* vrf-name */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/vrf-name", xpath);
	data = yang_data_new_string(xpath_arg,
				    bgp_notif_get_vrf_name(peer->bgp));
	listnode_add(arguments, data);

	/* local-as */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/local-as", xpath);
	data = yang_data_new_uint32(xpath_arg, peer->local_as);
	listnode_add(arguments, data);

	/* remote-as */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/remote-as", xpath);
	data = yang_data_new_uint32(xpath_arg, peer->as);
	listnode_add(arguments, data);

	/* old-state */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/old-state", xpath);
	data = yang_data_new_enum(xpath_arg, old_state);
	listnode_add(arguments, data);

	/* new-state */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/new-state", xpath);
	data = yang_data_new_enum(xpath_arg, new_state);
	listnode_add(arguments, data);

	/* reason */
	if (reason) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/reason", xpath);
		data = yang_data_new_string(xpath_arg, reason);
		listnode_add(arguments, data);
	}

	/* notification-error-code */
	if (error_code) {
		snprintf(xpath_arg, sizeof(xpath_arg),
			 "%s/notification-error-code", xpath);
		data = yang_data_new_enum(xpath_arg, error_code);
		listnode_add(arguments, data);

		/* notification-error-subcode */
		snprintf(xpath_arg, sizeof(xpath_arg),
			 "%s/notification-error-subcode", xpath);
		data = yang_data_new_uint8(xpath_arg, error_subcode);
		listnode_add(arguments, data);
	}

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-bgp:notification-received
 *
 * Send notification when a BGP NOTIFICATION message is received.
 */
void bgp_notif_notification_received(const struct peer *peer, uint8_t error_code,
				     uint8_t error_subcode, const uint8_t *data_buf,
				     size_t data_len)
{
	const char *xpath = "/frr-bgp:notification-received";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	if (!peer || !peer->bgp)
		return;

	arguments = yang_data_list_new();

	/* peer-address */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/peer-address", xpath);
	data = yang_data_new_string(xpath_arg, bgp_notif_get_peer_addr(peer));
	listnode_add(arguments, data);

	/* vrf-name */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/vrf-name", xpath);
	data = yang_data_new_string(xpath_arg,
				    bgp_notif_get_vrf_name(peer->bgp));
	listnode_add(arguments, data);

	/* error-code */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/error-code", xpath);
	data = yang_data_new_enum(xpath_arg, error_code);
	listnode_add(arguments, data);

	/* error-subcode */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/error-subcode", xpath);
	data = yang_data_new_uint8(xpath_arg, error_subcode);
	listnode_add(arguments, data);

	/* error-data (if any) */
	if (data_buf && data_len > 0) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/error-data", xpath);
		data = yang_data_new_binary(xpath_arg, (const char *)data_buf,
					    data_len);
		listnode_add(arguments, data);
	}

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-bgp:notification-sent
 *
 * Send notification when a BGP NOTIFICATION message is sent.
 */
void bgp_notif_notification_sent(const struct peer *peer, uint8_t error_code,
				 uint8_t error_subcode, const uint8_t *data_buf,
				 size_t data_len)
{
	const char *xpath = "/frr-bgp:notification-sent";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	if (!peer || !peer->bgp)
		return;

	arguments = yang_data_list_new();

	/* peer-address */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/peer-address", xpath);
	data = yang_data_new_string(xpath_arg, bgp_notif_get_peer_addr(peer));
	listnode_add(arguments, data);

	/* vrf-name */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/vrf-name", xpath);
	data = yang_data_new_string(xpath_arg,
				    bgp_notif_get_vrf_name(peer->bgp));
	listnode_add(arguments, data);

	/* error-code */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/error-code", xpath);
	data = yang_data_new_enum(xpath_arg, error_code);
	listnode_add(arguments, data);

	/* error-subcode */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/error-subcode", xpath);
	data = yang_data_new_uint8(xpath_arg, error_subcode);
	listnode_add(arguments, data);

	/* error-data (if any) */
	if (data_buf && data_len > 0) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/error-data", xpath);
		data = yang_data_new_binary(xpath_arg, (const char *)data_buf,
					    data_len);
		listnode_add(arguments, data);
	}

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-bgp:prefix-limit-reached
 *
 * Send notification when prefix limit is reached for a peer.
 */
void bgp_notif_prefix_limit_reached(const struct peer *peer, afi_t afi,
				    safi_t safi, uint32_t prefix_limit,
				    uint32_t prefix_count, int action)
{
	const char *xpath = "/frr-bgp:prefix-limit-reached";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	const char *action_str;

	if (!peer || !peer->bgp)
		return;

	arguments = yang_data_list_new();

	/* peer-address */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/peer-address", xpath);
	data = yang_data_new_string(xpath_arg, bgp_notif_get_peer_addr(peer));
	listnode_add(arguments, data);

	/* vrf-name */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/vrf-name", xpath);
	data = yang_data_new_string(xpath_arg,
				    bgp_notif_get_vrf_name(peer->bgp));
	listnode_add(arguments, data);

	/* afi */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/afi", xpath);
	data = yang_data_new_enum(xpath_arg, afi);
	listnode_add(arguments, data);

	/* safi */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/safi", xpath);
	data = yang_data_new_enum(xpath_arg, safi);
	listnode_add(arguments, data);

	/* prefix-limit */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/prefix-limit", xpath);
	data = yang_data_new_uint32(xpath_arg, prefix_limit);
	listnode_add(arguments, data);

	/* prefix-count */
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/prefix-count", xpath);
	data = yang_data_new_uint32(xpath_arg, prefix_count);
	listnode_add(arguments, data);

	/* action-taken */
	switch (action) {
	case 0:
		action_str = "warning-only";
		break;
	case 1:
		action_str = "session-cleared";
		break;
	case 2:
		action_str = "session-restart-scheduled";
		break;
	default:
		action_str = "warning-only";
		break;
	}
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/action-taken", xpath);
	data = yang_data_new_string(xpath_arg, action_str);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}
