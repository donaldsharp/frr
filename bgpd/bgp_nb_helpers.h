// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound Helper Functions
 * Copyright (C) 2024 FRRouting
 *
 * Helper functions to reduce code duplication in bgp_nb_config.c
 * These provide common patterns for filter-config, AF flags, weight, etc.
 */

#ifndef _BGP_NB_HELPERS_H
#define _BGP_NB_HELPERS_H

#include "northbound.h"
#include "bgpd/bgpd.h"

/*
 * XPath constants for peer retrieval from different contexts
 * filter-config leaves are at: .../afi-safi/XXX/filter-config/YYY
 * Need to go up 5 levels to reach neighbor/unnumbered-neighbor/peer-group
 */
#define BGP_NB_XPATH_PEER_FILTER_CONFIG "../../../../.."

/*
 * Route-map helper functions
 * Used for rmap-import/rmap-export filter-config callbacks
 */
int bgp_nb_peer_rmap_modify(struct nb_cb_modify_args *args,
			    const char *peer_xpath, afi_t afi, safi_t safi,
			    int direct);
int bgp_nb_peer_rmap_destroy(struct nb_cb_destroy_args *args,
			     const char *peer_xpath, afi_t afi, safi_t safi,
			     int direct);

/*
 * Prefix-list helper functions
 * Used for plist-import/plist-export filter-config callbacks
 */
int bgp_nb_peer_plist_modify(struct nb_cb_modify_args *args,
			     const char *peer_xpath, afi_t afi, safi_t safi,
			     int direct);
int bgp_nb_peer_plist_destroy(struct nb_cb_destroy_args *args,
			      const char *peer_xpath, afi_t afi, safi_t safi,
			      int direct);

/*
 * Access-list (distribute-list) helper functions
 * Used for access-list-import/access-list-export filter-config callbacks
 */
int bgp_nb_peer_distribute_modify(struct nb_cb_modify_args *args,
				  const char *peer_xpath, afi_t afi,
				  safi_t safi, int direct);
int bgp_nb_peer_distribute_destroy(struct nb_cb_destroy_args *args,
				   const char *peer_xpath, afi_t afi,
				   safi_t safi, int direct);

/*
 * AS-path filter list helper functions
 * Used for as-path-filter-list-import/export filter-config callbacks
 */
int bgp_nb_peer_aslist_modify(struct nb_cb_modify_args *args,
			      const char *peer_xpath, afi_t afi, safi_t safi,
			      int direct);
int bgp_nb_peer_aslist_destroy(struct nb_cb_destroy_args *args,
			       const char *peer_xpath, afi_t afi, safi_t safi,
			       int direct);

/*
 * Unsuppress-map helper functions
 * Used for unsuppress-map-import/export filter-config callbacks
 */
int bgp_nb_peer_unsuppress_map_modify(struct nb_cb_modify_args *args,
				      const char *peer_xpath, afi_t afi,
				      safi_t safi);
int bgp_nb_peer_unsuppress_map_destroy(struct nb_cb_destroy_args *args,
				       const char *peer_xpath, afi_t afi,
				       safi_t safi);

/*
 * Address-family flag helper functions
 * Used for send-community, soft-reconfiguration, route-reflector-client, etc.
 */
int bgp_nb_peer_af_flag_modify(struct nb_cb_modify_args *args,
			       const char *peer_xpath, afi_t afi, safi_t safi,
			       uint64_t flag);
int bgp_nb_peer_af_flag_destroy(struct nb_cb_destroy_args *args,
				const char *peer_xpath, afi_t afi, safi_t safi,
				uint64_t flag);

/*
 * Site-of-Origin (SOO) helper functions
 * Used for neighbor soo configuration per AFI-SAFI
 */
int bgp_nb_peer_soo_modify(struct nb_cb_modify_args *args,
			   const char *peer_xpath, afi_t afi, safi_t safi);
int bgp_nb_peer_soo_destroy(struct nb_cb_destroy_args *args,
			    const char *peer_xpath, afi_t afi, safi_t safi);

/*
 * Weight helper functions
 * Used for weight-attribute configuration
 */
int bgp_nb_peer_weight_modify(struct nb_cb_modify_args *args,
			      const char *peer_xpath, afi_t afi, safi_t safi);
int bgp_nb_peer_weight_destroy(struct nb_cb_destroy_args *args,
			       const char *peer_xpath, afi_t afi, safi_t safi);

/*
 * Peer-group specific helper functions
 * These retrieve peer_group and use group->conf for peer operations
 */
int bgp_nb_peer_group_af_flag_modify(struct nb_cb_modify_args *args,
				     const char *group_xpath, afi_t afi,
				     safi_t safi, uint64_t flag);
int bgp_nb_peer_group_af_flag_destroy(struct nb_cb_destroy_args *args,
				      const char *group_xpath, afi_t afi,
				      safi_t safi, uint64_t flag);

/*
 * Peer-group weight helper functions
 * Used for peer-group weight-attribute configuration
 */
int bgp_nb_peer_group_weight_modify(struct nb_cb_modify_args *args,
				    const char *group_xpath, afi_t afi,
				    safi_t safi);
int bgp_nb_peer_group_weight_destroy(struct nb_cb_destroy_args *args,
				     const char *group_xpath, afi_t afi,
				     safi_t safi);

/*
 * Peer-group allowas_in helper functions
 * Used for allow-own-as and allow-own-origin-as configuration
 * origin=0 for allow-own-as, origin=1 for allow-own-origin-as
 */
int bgp_nb_peer_group_allowas_in_modify(struct nb_cb_modify_args *args,
					const char *group_xpath, afi_t afi,
					safi_t safi, int origin);
int bgp_nb_peer_group_allowas_in_destroy(struct nb_cb_destroy_args *args,
					 const char *group_xpath, afi_t afi,
					 safi_t safi);

/*
 * Neighbor allowas_in helper functions
 * Used for allow-own-as and allow-own-origin-as configuration
 * origin=0 for allow-own-as, origin=1 for allow-own-origin-as
 */
int bgp_nb_peer_allowas_in_modify(struct nb_cb_modify_args *args,
				  const char *peer_xpath, afi_t afi,
				  safi_t safi, int origin);
int bgp_nb_peer_allowas_in_destroy(struct nb_cb_destroy_args *args,
				   const char *peer_xpath, afi_t afi,
				   safi_t safi);

/*
 * Add-paths helper functions
 * Used for add-paths/path-type configuration
 */
int bgp_nb_peer_addpath_modify(struct nb_cb_modify_args *args,
			       const char *peer_xpath, afi_t afi, safi_t safi);

/*
 * Peer-group add-paths helper functions
 */
int bgp_nb_peer_group_addpath_modify(struct nb_cb_modify_args *args,
				     const char *group_xpath, afi_t afi,
				     safi_t safi);

/*
 * Default-originate helper functions
 * Used for neighbor default-originate configuration
 */
int bgp_nb_peer_default_originate_modify(struct nb_cb_modify_args *args,
					 const char *peer_xpath, afi_t afi,
					 safi_t safi);
int bgp_nb_peer_default_originate_rmap_modify(struct nb_cb_modify_args *args,
					      const char *peer_xpath, afi_t afi,
					      safi_t safi);
int bgp_nb_peer_default_originate_rmap_destroy(struct nb_cb_destroy_args *args,
					       const char *peer_xpath, afi_t afi,
					       safi_t safi);

/*
 * Peer-group default-originate helper functions
 */
int bgp_nb_peer_group_default_originate_modify(struct nb_cb_modify_args *args,
					       const char *group_xpath, afi_t afi,
					       safi_t safi);
int bgp_nb_peer_group_default_originate_rmap_modify(struct nb_cb_modify_args *args,
						    const char *group_xpath, afi_t afi,
						    safi_t safi);
int bgp_nb_peer_group_default_originate_rmap_destroy(struct nb_cb_destroy_args *args,
						     const char *group_xpath, afi_t afi,
						     safi_t safi);

/*
 * Prefix-limit helper functions
 * Used for neighbor/unnumbered-neighbor prefix-limit configuration
 *
 * XPath depths from different callbacks to peer and direction-list:
 * - direction-list: peer=5up, dir=current
 * - max-prefixes/force-check: peer=6up, dir=1up
 * - options leaves: peer=7up, dir=2up
 */
int bgp_nb_peer_prefix_limit_apply(struct nb_cb_modify_args *args,
				   const char *peer_xpath,
				   const char *dir_xpath,
				   afi_t afi, safi_t safi);
int bgp_nb_peer_prefix_limit_destroy(struct nb_cb_destroy_args *args,
				     const char *peer_xpath,
				     afi_t afi, safi_t safi);

/*
 * Peer-group prefix-limit helper functions
 */
int bgp_nb_peer_group_prefix_limit_apply(struct nb_cb_modify_args *args,
					 const char *group_xpath,
					 const char *dir_xpath,
					 afi_t afi, safi_t safi);
int bgp_nb_peer_group_prefix_limit_destroy(struct nb_cb_destroy_args *args,
					   const char *group_xpath,
					   afi_t afi, safi_t safi);

/*
 * Neighbor dampening helper functions
 * Used for neighbor/peer-group dampening configuration per AFI-SAFI
 */
int bgp_nb_peer_dampening_enable_modify(struct nb_cb_modify_args *args,
					const char *peer_xpath, afi_t afi,
					safi_t safi);

int bgp_nb_peer_group_dampening_enable_modify(struct nb_cb_modify_args *args,
					      const char *group_xpath, afi_t afi,
					      safi_t safi);

/*
 * Maximum-prefix cli_write helper
 * Called from all max_prefixes_cli_write variations
 * addr_xpath is relative path from max-prefixes to remote-address/interface/peer-group-name
 */
void bgp_nb_peer_max_prefix_cli_write(struct vty *vty,
				      const struct lyd_node *dnode,
				      const char *addr_xpath,
				      bool show_defaults);

/*
 * BGP instance creation with defaults applied
 * Used by northbound and VTY code paths
 */
extern int bgp_instance_create(struct bgp **bgp, as_t *as, const char *name,
			       enum bgp_instance_type inst_type,
			       const char *as_pretty,
			       enum asnotation_mode asnotation);

extern int bgp_static_set_nb(struct bgp *bgp, bool negate, const char *ip_str,
			     const char *rd_str, const char *label_str,
			     afi_t afi, safi_t safi, const char *rmap);

#endif /* _BGP_NB_HELPERS_H */
