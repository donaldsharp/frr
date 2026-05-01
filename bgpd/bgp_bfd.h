// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * bgp_bfd.h: BGP BFD definitions and structures
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */

#ifndef _QUAGGA_BGP_BFD_H
#define _QUAGGA_BGP_BFD_H

#define PEER_IS_MULTIHOP(peer)                                                 \
	((((peer)->sort == BGP_PEER_IBGP) && !(peer)->shared_network)          \
	 || is_ebgp_multihop_configured((peer)))

extern void bgp_bfd_init(struct event_loop *tm);

extern void bgp_bfd_peer_config_write(struct vty *vty, struct peer *peer, const char *addr);

/**
 * Show BFD information helper.
 *
 * \param vty the VTY pointer.
 * \param peer the BGP configuration pointer.
 * \param use_json unused.
 * \param json_neigh JSON object when called as JSON command.
 */
extern void bgp_bfd_show_info(struct vty *vty, struct peer *peer, json_object *json_neigh);

/**
 * When called on a group it applies configuration to all peers in that group,
 * otherwise just applies the configuration to a single peer.
 *
 * This function should be called when configuration changes either on group
 * or peer.
 *
 * \param p the BGP peer pointer.
 * \param pg the BGP group to copy configuration from (it is usually
 *           `p->group` exception when copying new group configuration
 *           see `peer_group2peer_config_copy` function case).
 */
extern void bgp_peer_config_apply(struct peer *p, struct peer_group *pg);

/**
 * Allocates and configure BFD session for peer. If it is already configured,
 * then it does nothing.
 *
 * Always call `bgp_peer_config_apply` afterwards if you need the changes
 * immediately applied.
 */
extern void bgp_peer_configure_bfd(struct peer *p, bool manual);

/**
 * Allocates and configures BFD settings for a peer group.
 * This only allocates the configuration structure - it doesn't create
 * BFD sessions. Sessions are created for individual peers in the group.
 *
 * Always call `bgp_peer_config_apply` afterwards if you need the changes
 * immediately applied to group members.
 */
extern void bgp_group_configure_bfd(struct peer *p);

/**
 * Removes BFD configuration from either peer or peer group.
 */
extern void bgp_peer_remove_bfd_config(struct peer *p);

/**
 * Special function to handle the case of changing source address. This
 * happens when the peer/group is configured with `neighbor X update-source Y`.
 */
extern void bgp_peer_bfd_update_source(struct peer *p);

#endif /* _QUAGGA_BGP_BFD_H */
