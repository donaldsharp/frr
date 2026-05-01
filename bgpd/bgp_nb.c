// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound API - YANG Node Registration
 * Copyright (C) 2024 FRRouting
 *
 * Auto-generated from gen_northbound_callbacks
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"

#include "bgpd/bgp_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_bgp_info = {
	.name = "frr-bgp",
	.nodes = {
		/*
		 * Daemon-wide settings (/frr-bgp:bgpd/ leafs)
		 * These affect bgp_master and apply to all BGP instances.
		 */
		{
			.xpath = "/frr-bgp:daemon-settings/no-rib",
			.cbs = {
				.modify = bgpd_no_rib_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/graceful-restart/enabled",
			.cbs = {
				.modify = bgpd_graceful_restart_enabled_modify,
				.destroy = bgpd_graceful_restart_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/advertisement-delay",
			.cbs = {
				.modify = bgpd_advertisement_delay_modify,
				.destroy = bgpd_advertisement_delay_destroy,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/suppress-fib-pending/enabled",
			.cbs = {
				.modify = bgpd_suppress_fib_pending_enabled_modify,
				.destroy = bgpd_suppress_fib_pending_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/suppress-fib-pending/delay",
			.cbs = {
				.modify = bgpd_suppress_fib_pending_delay_modify,
				.destroy = bgpd_suppress_fib_pending_delay_destroy,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/send-extra-data",
			.cbs = {
				.modify = bgpd_send_extra_data_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/input-queue-limit",
			.cbs = {
				.modify = bgpd_input_queue_limit_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/output-queue-limit",
			.cbs = {
				.modify = bgpd_output_queue_limit_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/session-dscp",
			.cbs = {
				.modify = bgpd_session_dscp_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/ipv6-auto-ra",
			.cbs = {
				.modify = bgpd_ipv6_auto_ra_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/community-alias",
			.cbs = {
				.create = bgpd_community_alias_create,
				.destroy = bgpd_community_alias_destroy,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/community-alias/alias",
			.cbs = {
				.modify = bgpd_community_alias_alias_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/debug/updates",
			.cbs = {
				.modify = bgpd_debug_updates_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/debug/updates-out",
			.cbs = {
				.modify = bgpd_debug_updates_out_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/debug/nht",
			.cbs = {
				.modify = bgpd_debug_nht_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/debug/vpn-label",
			.cbs = {
				.modify = bgpd_debug_vpn_label_modify,
			}
		},
		{
			.xpath = "/frr-bgp:daemon-settings/debug/vpn-leak-from-vrf",
			.cbs = {
				.modify = bgpd_debug_vpn_leak_from_vrf_modify,
			}
		},
		/*
		 * Per-instance BGP configuration
		 */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_destroy,
			}
		},
		/* global-system-config entries */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/queue-limits/input-queue-limit",
			.cbs = {
				.modify = bgp_global_queue_input_limit_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/queue-limits/output-queue-limit",
			.cbs = {
				.modify = bgp_global_queue_output_limit_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/session-dscp",
			.cbs = {
				.modify = bgp_global_session_dscp_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ipv6-auto-ra",
			.cbs = {
				.modify = bgp_global_ipv6_auto_ra_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/no-rib",
			.cbs = {
				.modify = bgp_global_no_rib_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/send-extra-data-to-zebra",
			.cbs = {
				.modify = bgp_global_send_extra_data_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_local_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/is-view",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_is_view_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/router-id",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_router_id_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_router_id_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/identifier",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_confederation_identifier_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_confederation_identifier_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/identifier-pretty",
			.cbs = {
				.modify = bgp_global_confederation_identifier_pretty_modify,
				.destroy = bgp_global_confederation_identifier_pretty_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/member-as",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_confederation_member_as_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_confederation_member_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/enable-med-admin",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_med_config_enable_med_admin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-admin",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_med_config_max_med_admin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-onstart-up-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_med_config_max_med_onstart_up_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_med_config_max_med_onstart_up_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-onstart-up-value",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_med_config_max_med_onstart_up_value_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/route-reflector-cluster-id",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_reflector_route_reflector_cluster_id_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_reflector_route_reflector_cluster_id_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/no-client-reflect",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_reflector_no_client_reflect_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/allow-outbound-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_reflector_allow_outbound_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/always-compare-med",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_always_compare_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/deterministic-med",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_deterministic_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/confed-med",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_confed_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/missing-as-worst-med",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_missing_as_worst_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/aspath-confed",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_aspath_confed_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/ignore-as-path-length",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_ignore_as_path_length_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/bestpath-use-imported-attributes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_bestpath_use_imported_attributes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/external-compare-router-id",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_external_compare_router_id_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/allow-multiple-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_allow_multiple_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/multi-path-as-set",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_multi_path_as_set_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_multi_path_as_set_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/compare-aigp",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_compare_aigp_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/peer-type-multipath-relax",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_peer_type_multipath_relax_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/link-bandwidth-handling",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_route_selection_options_link_bandwidth_handling_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/dynamic-neighbors-limit",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_neighbor_config_dynamic_neighbors_limit_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_neighbor_config_dynamic_neighbors_limit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/log-neighbor-changes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_neighbor_config_log_neighbor_changes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/wpkt-quanta",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_neighbor_config_packet_quanta_config_wpkt_quanta_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/rpkt-quanta",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_neighbor_config_packet_quanta_config_rpkt_quanta_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/default-software-version-capability",
			.cbs = {
				.modify = bgp_global_default_software_version_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/default-software-version-capability-latest-encoding",
			.cbs = {
				.modify = bgp_global_default_software_version_capability_latest_encoding_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/default-link-local-capability",
			.cbs = {
				.modify = bgp_global_default_link_local_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/default-dynamic-capability",
			.cbs = {
				.modify = bgp_global_default_dynamic_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/reject-as-sets",
			.cbs = {
				.modify = bgp_global_reject_as_sets_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/hard-administrative-reset",
			.cbs = {
				.modify = bgp_global_hard_administrative_reset_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/labeled-unicast-explicit-null",
			.cbs = {
				.modify = bgp_global_labeled_unicast_explicit_null_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/conditional-advertisement-period",
			.cbs = {
				.modify = bgp_global_conditional_advertisement_period_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/default-originate-timer",
			.cbs = {
				.modify = bgp_global_default_originate_timer_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_graceful_restart_disable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_graceful_restart_disable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/preserve-fw-entry",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_preserve_fw_entry_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/restart-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_restart_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/stale-routes-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_stale_routes_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/selection-deferral-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_selection_deferral_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/rib-stale-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_rib_stale_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/notification",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_notification_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/disable-eor",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_restart_disable_eor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/subgroup-pkt-queue-size",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_update_group_config_subgroup_pkt_queue_size_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/coalesce-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_update_group_config_coalesce_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/rmap-delay-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_rmap_delay_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/update-delay-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_update_delay_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_update_delay_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/establish-wait-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_establish_wait_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_establish_wait_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/connect-retry-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_connect_retry_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/hold-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/keepalive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_keepalive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/delay-open-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_delay_open_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_global_config_timers_delay_open_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/instance-type-view",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_instance_type_view_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/as-notation",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_as_notation_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_as_notation_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-multihop-connected-route-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_ebgp_multihop_connected_route_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/fast-external-failover",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_fast_external_failover_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-pref",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_local_pref_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-shutdown",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_default_shutdown_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-duplicates",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_suppress_duplicates_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-requires-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_ebgp_requires_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-hostname",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_show_hostname_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-nexthop-hostname",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_show_nexthop_hostname_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/enforce-first-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_enforce_first_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-fib-pending",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_suppress_fib_pending_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-fib-pending-delay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_suppress_fib_pending_delay_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/allow-martian-nexthop",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_allow_martian_nexthop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/fast-convergence",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_fast_convergence_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/minimum-holdtime",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_minimum_holdtime_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_minimum_holdtime_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/tcp-keepalive/idle",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_tcp_keepalive_idle_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_tcp_keepalive_idle_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/tcp-keepalive/interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_tcp_keepalive_interval_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_tcp_keepalive_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/tcp-keepalive/probes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_tcp_keepalive_probes_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_tcp_keepalive_probes_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/admin-shutdown/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_admin_shutdown_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/admin-shutdown/message",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_admin_shutdown_message_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_admin_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/llgr-stale-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_llgr_stale_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_llgr_stale_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-afi-safi",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_default_afi_safi_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_default_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ipv4-unicast-default",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_ipv4_unicast_default_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/import-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_import_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-shutdown/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_graceful_shutdown_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/incoming-session/session-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_incoming_session_session_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_incoming_session_session_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_outgoing_session_session_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_outgoing_session_session_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/min-retry-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_outgoing_session_session_list_min_retry_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/max-retry-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_outgoing_session_session_list_max_retry_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/mirror",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_mirror_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/stats-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_stats_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_stats_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/ipv4-access-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_ipv4_access_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_ipv4_access_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/ipv6-access-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_ipv6_access_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_ipv6_access_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/pre-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/post-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/pre-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/post-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/pre-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/post-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/pre-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/post-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/loc-rib",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_loc_rib_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/loc-rib",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_loc_rib_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/loc-rib",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_loc_rib_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/loc-rib",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_loc_rib_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/pre-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv4_unicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/post-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv4_unicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/loc-rib",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv4_unicast_common_config_loc_rib_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/pre-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv6_unicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/post-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv6_unicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/loc-rib",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv6_unicast_common_config_loc_rib_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/pre-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l2vpn_evpn_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/post-policy",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l2vpn_evpn_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/loc-rib",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l2vpn_evpn_common_config_loc_rib_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/stats-send-experimental",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_stats_send_experimental_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/imported-vrf-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_imported_vrf_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_imported_vrf_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/mirror-buffer-limit",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_mirror_buffer_limit_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_mirror_buffer_limit_destroy,
			}
		},
		/* BMP stats-send-experimental */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/stats-send-experimental",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_stats_send_experimental_modify,
			}
		},
		/* BMP loc-rib callbacks */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/loc-rib",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_loc_rib_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/loc-rib",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_loc_rib_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/loc-rib",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_loc_rib_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/loc-rib",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_loc_rib_modify, }
		},
		/* BMP VPN common-config + encapsulation noop */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/pre-policy",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv4_unicast_common_config_pre_policy_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/post-policy",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv4_unicast_common_config_post_policy_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/loc-rib",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv4_unicast_common_config_loc_rib_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-srv6",
			.cbs = { .modify = bgp_global_afi_safi_encapsulation_noop_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-mpls",
			.cbs = { .modify = bgp_global_afi_safi_encapsulation_noop_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/encapsulation",
			.cbs = { .modify = bgp_global_afi_safi_encapsulation_noop_modify, .destroy = bgp_global_afi_safi_encapsulation_noop_destroy, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/encapsulation",
			.cbs = { .modify = bgp_global_afi_safi_encapsulation_noop_modify, .destroy = bgp_global_afi_safi_encapsulation_noop_destroy, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/pre-policy",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv6_unicast_common_config_pre_policy_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/post-policy",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv6_unicast_common_config_post_policy_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/loc-rib",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l3vpn_ipv6_unicast_common_config_loc_rib_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-srv6",
			.cbs = { .modify = bgp_global_afi_safi_encapsulation_noop_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-mpls",
			.cbs = { .modify = bgp_global_afi_safi_encapsulation_noop_modify, }
		},
		/* BMP EVPN common-config */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/pre-policy",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l2vpn_evpn_common_config_pre_policy_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/post-policy",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l2vpn_evpn_common_config_post_policy_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/loc-rib",
			.cbs = { .modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_bmp_config_target_list_afi_safis_afi_safi_l2vpn_evpn_common_config_loc_rib_modify, }
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_destroy,
				/* cli_show removed - address-family output now handled by cli_show_router_bgp_end */
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_destroy,
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/backdoor",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_backdoor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/label-index",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/as-set",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_as_set_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/summary-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_summary_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/origin",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_origin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/match-med",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_match_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_suppress_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_suppress_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/distance",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_access_list_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_access_list_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reuse_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_suppress_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_unreach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ebgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_cluster_length_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list/metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list/rmap-policy-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_rmap_policy_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_rmap_policy_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/external",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_external_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/internal",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_internal_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/local",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_local_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rd",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label-auto",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_auto_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label-per-nexthop",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_per_nexthop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/nexthop",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vpn",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vpn_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-vpn",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_vpn_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vrf-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/redirect-rt",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_redirect_rt_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_redirect_rt_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-rt-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_rt_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-rt-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_rt_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rt-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rt_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/table-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_table_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_unicast_table_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/backdoor",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_backdoor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/label-index",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/as-set",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_as_set_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/summary-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_summary_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/origin",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_origin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/match-med",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_match_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_suppress_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_suppress_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/distance",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_access_list_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_access_list_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reuse_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_suppress_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_unreach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ebgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_cluster_length_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list/metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list/rmap-policy-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_rmap_policy_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_rmap_policy_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/external",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_external_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/internal",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_internal_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/local",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_local_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rd",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rd_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label-auto",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_auto_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label-per-nexthop",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_per_nexthop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/nexthop",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_nexthop_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_nexthop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-vpn",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vpn_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-vpn",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_vpn_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-vrf-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vrf_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vrf_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/redirect-rt",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_redirect_rt_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_redirect_rt_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-rt-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_rt_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-rt-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_rt_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rt-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rt_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/table-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_table_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_unicast_table_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/nexthop-prefer-global",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_nexthop_prefer_global_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_nexthop_prefer_global_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/nexthop-prefer-global",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_multicast_nexthop_prefer_global_modify,
				.destroy = bgp_global_afi_safi_ipv6_multicast_nexthop_prefer_global_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-prefer-global",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_labeled_unicast_nexthop_prefer_global_modify,
				.destroy = bgp_global_afi_safi_ipv6_labeled_unicast_nexthop_prefer_global_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reuse_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_suppress_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_unreach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reuse_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_suppress_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_unreach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list/label-index",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_label_index_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list/label-index",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_label_index_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/retain-route-target-all",
			.cbs = {
				.modify = bgp_global_afi_safi_l3vpn_ipv4_unicast_retain_route_target_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/retain-route-target-all",
			.cbs = {
				.modify = bgp_global_afi_safi_l3vpn_ipv6_unicast_retain_route_target_all_modify,
			}
		},
		/* Global afi-safi encapsulation - noop callbacks (encapsulation only meaningful for peers) */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-srv6",
			.cbs = {
				.modify = bgp_global_afi_safi_encapsulation_noop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-mpls",
			.cbs = {
				.modify = bgp_global_afi_safi_encapsulation_noop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-srv6",
			.cbs = {
				.modify = bgp_global_afi_safi_encapsulation_noop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-mpls",
			.cbs = {
				.modify = bgp_global_afi_safi_encapsulation_noop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/encapsulation",
			.cbs = {
				.modify = bgp_global_afi_safi_encapsulation_noop_modify,
				.destroy = bgp_global_afi_safi_encapsulation_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/encapsulation",
			.cbs = {
				.modify = bgp_global_afi_safi_encapsulation_noop_modify,
				.destroy = bgp_global_afi_safi_encapsulation_noop_destroy,
			}
		},
		/* SRV6 xpaths */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/segment-routing/srv6/enabled",
			.cbs = {
				.modify = bgp_global_segment_routing_srv6_enabled_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/segment-routing/srv6/locator-name",
			.cbs = {
				.modify = bgp_global_segment_routing_srv6_locator_name_modify,
				.destroy = bgp_global_segment_routing_srv6_locator_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/segment-routing/srv6/encap-behavior",
			.cbs = {
				.modify = bgp_global_segment_routing_srv6_encap_behavior_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/segment-routing/srv6/srv6-only",
			.cbs = {
				.modify = bgp_global_segment_routing_srv6_srv6_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/sid-vpn-export/sid-index",
			.cbs = {
				.modify = bgp_global_sid_vpn_export_sid_index_modify,
				.destroy = bgp_global_sid_vpn_export_sid_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/sid-vpn-export/sid-auto",
			.cbs = {
				.modify = bgp_global_sid_vpn_export_sid_auto_modify,
				.destroy = bgp_global_sid_vpn_export_sid_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/sid-vpn-export/sid-value",
			.cbs = {
				.modify = bgp_global_sid_vpn_export_sid_value_modify,
				.destroy = bgp_global_sid_vpn_export_sid_value_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-vpn-export/sid-index",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv4_unicast_sid_vpn_export_sid_index_modify,
				.destroy = bgp_global_afi_safi_ipv4_unicast_sid_vpn_export_sid_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-vpn-export/sid-auto",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv4_unicast_sid_vpn_export_sid_auto_modify,
				.destroy = bgp_global_afi_safi_ipv4_unicast_sid_vpn_export_sid_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-vpn-export/sid-value",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv4_unicast_sid_vpn_export_sid_value_modify,
				.destroy = bgp_global_afi_safi_ipv4_unicast_sid_vpn_export_sid_value_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-vpn-export/sid-index",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_sid_vpn_export_sid_index_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_sid_vpn_export_sid_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-vpn-export/sid-auto",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_sid_vpn_export_sid_auto_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_sid_vpn_export_sid_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-vpn-export/sid-value",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_sid_vpn_export_sid_value_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_sid_vpn_export_sid_value_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-unicast-export",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-unicast-export/sid-index",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_sid_index_modify,
				.destroy = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_sid_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-unicast-export/sid-auto",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_sid_auto_modify,
				.destroy = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_sid_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-unicast-export/behavior-dt46",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_behavior_dt46_modify,
				.destroy = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_behavior_dt46_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-unicast-export/sid-explicit",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_sid_explicit_modify,
				.destroy = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_sid_explicit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-unicast-export/route-map",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_route_map_modify,
				.destroy = bgp_global_afi_safi_ipv4_unicast_sid_unicast_export_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-unicast-export",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-unicast-export/sid-index",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_sid_index_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_sid_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-unicast-export/sid-auto",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_sid_auto_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_sid_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-unicast-export/behavior-dt46",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_behavior_dt46_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_behavior_dt46_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-unicast-export/sid-explicit",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_sid_explicit_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_sid_explicit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-unicast-export/route-map",
			.cbs = {
				.modify = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_route_map_modify,
				.destroy = bgp_global_afi_safi_ipv6_unicast_sid_unicast_export_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/backdoor",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_backdoor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/label-index",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_label_index_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/as-set",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_as_set_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/summary-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_summary_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/origin",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_origin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/match-med",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_match_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_suppress_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_suppress_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/distance",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_access_list_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_access_list_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/external",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_external_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/internal",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_internal_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/local",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_local_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reuse_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_suppress_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_unreach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/table-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_table_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_multicast_table_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/backdoor",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_backdoor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/label-index",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_label_index_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/as-set",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_as_set_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/summary-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_summary_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_rmap_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/origin",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_origin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/match-med",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_match_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_suppress_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_suppress_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/distance",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_access_list_policy_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_access_list_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reuse_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_suppress_above_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_unreach_decay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/external",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_external_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/internal",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_internal_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/local",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_local_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/table-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_table_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv6_multicast_table_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-flowspec/flow-spec-config/interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_flowspec_flow_spec_config_interface_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_global_afi_safis_afi_safi_ipv4_flowspec_flow_spec_config_interface_destroy,
			}
		},
		/* BGP-LS BGP-only fabric distribution */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-link-state/distribute-bgp-fabric-link-state",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_link_state_distribute_bgp_fabric_modify,
				.destroy = bgp_global_afi_safi_l2vpn_link_state_distribute_bgp_fabric_destroy,
			}
		},
		/* BGP-LS per-neighbor filter-config (Fix A) */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-link-state/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-link-state/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_link_state_filter_config_unsuppress_map_export_destroy,
			}
		},
		/* EVPN global config */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-all-vni",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_advertise_all_vni_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-svi-ip",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_advertise_svi_ip_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-default-gw",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_advertise_default_gw_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/enable-resolve-overlay-index",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_enable_resolve_overlay_index_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/evpn-mh-startup-delay",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_evpn_mh_startup_delay_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_evpn_mh_startup_delay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/disable-ead-evi-rx",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_disable_ead_evi_rx_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_disable_ead_evi_rx_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/disable-ead-evi-tx",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_disable_ead_evi_tx_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_disable_ead_evi_tx_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-ipv4-unicast",
			.cbs = {
				.create = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv4_unicast_create,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv4_unicast_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-ipv4-unicast/gateway-ip",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv4_unicast_gateway_ip_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-ipv4-unicast/route-map",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv4_unicast_route_map_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv4_unicast_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-ipv6-unicast",
			.cbs = {
				.create = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv6_unicast_create,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv6_unicast_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-ipv6-unicast/gateway-ip",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv6_unicast_gateway_ip_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-ipv6-unicast/route-map",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv6_unicast_route_map_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_advertise_ipv6_unicast_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vrf-rd",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_vrf_rd_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_vrf_rd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vrf-route-target",
			.cbs = {
				.create = bgp_global_afi_safi_l2vpn_evpn_vrf_route_target_create,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_vrf_route_target_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vrf-route-target-import-auto",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_vrf_rt_import_auto_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vrf-route-target-export-auto",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_vrf_rt_export_auto_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/macvrf-soo",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_macvrf_soo_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_macvrf_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/flooding",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_flooding_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_flooding_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni",
			.cbs = {
				.create = bgp_global_afi_safi_l2vpn_evpn_vni_create,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_vni_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/rd",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_vni_rd_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_vni_rd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/vni-flooding",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_vni_flooding_modify,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_vni_flooding_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/route-target",
			.cbs = {
				.create = bgp_global_afi_safi_l2vpn_evpn_vni_route_target_create,
				.destroy = bgp_global_afi_safi_l2vpn_evpn_vni_route_target_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/advertise-default-gw",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_vni_advertise_default_gw_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/advertise-svi-ip",
			.cbs = {
				.modify = bgp_global_afi_safi_l2vpn_evpn_vni_advertise_svi_ip_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_interface_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-port",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_port_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_port_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/peer-group",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_peer_group_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_peer_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_neighbor_remote_as_remote_as_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_neighbor_remote_as_remote_as_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_neighbor_remote_as_remote_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_neighbor_remote_as_remote_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/password",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_password_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_password_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ttl-security",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_ttl_security_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_ttl_security_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/solo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_solo_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/enforce-first-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_enforce_first_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/description",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_description_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_description_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/passive-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_passive_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/rpki-strict",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_rpki_strict_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/sender-as-path-loop-detection",
			.cbs = {
				.modify = bgp_neighbors_neighbor_sender_as_path_loop_detection_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ip-transparent",
			.cbs = {
				.modify = bgp_neighbors_neighbor_ip_transparent_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-oad",
			.cbs = {
				.modify = bgp_neighbors_neighbor_ebgp_oad_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/aigp",
			.cbs = {
				.modify = bgp_neighbors_neighbor_aigp_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-shutdown",
			.cbs = {
				.modify = bgp_neighbors_neighbor_graceful_shutdown_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/extended-optional-parameters",
			.cbs = {
				.modify = bgp_neighbors_neighbor_extended_optional_parameters_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify = bgp_neighbors_neighbor_disable_link_bw_encoding_ieee_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/extended-link-bandwidth",
			.cbs = {
				.modify = bgp_neighbors_neighbor_extended_link_bandwidth_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/send-nexthop-characteristics",
			.cbs = {
				.modify = bgp_neighbors_neighbor_send_nhc_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/shutdown-rtt/enabled",
			.cbs = {
				.modify = bgp_neighbors_neighbor_shutdown_rtt_enabled_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/shutdown-rtt/threshold",
			.cbs = {
				.modify = bgp_neighbors_neighbor_shutdown_rtt_threshold_modify,
				.destroy = bgp_neighbors_neighbor_shutdown_rtt_threshold_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/shutdown-rtt/count",
			.cbs = {
				.modify = bgp_neighbors_neighbor_shutdown_rtt_count_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/shutdown-rtt",
			.cbs = {
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/path-attribute/discard",
			.cbs = {
				.create = bgp_neighbors_neighbor_path_attribute_discard_create,
				.destroy = bgp_neighbors_neighbor_path_attribute_discard_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/path-attribute/treat-as-withdraw",
			.cbs = {
				.create = bgp_neighbors_neighbor_path_attribute_treat_as_withdraw_create,
				.destroy = bgp_neighbors_neighbor_path_attribute_treat_as_withdraw_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/ip",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_update_source_ip_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_update_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_update_source_interface_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_update_source_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_ebgp_multihop_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_ebgp_multihop_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_ebgp_multihop_disable_connected_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/local-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_as_local_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_as_local_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/no-prepend",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_as_no_prepend_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/replace-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_as_replace_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/dual-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_as_dual_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/detect-multiplier",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_detect_multiplier_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/required-min-rx",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_required_min_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/desired-min-tx",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_desired_min_tx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/session-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_session_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/check-cp-failure",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_check_cp_failure_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/profile",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_profile_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_profile_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/strict-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/strict-hold-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_hold_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_hold_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_admin_shutdown_enable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_admin_shutdown_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/message",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_admin_shutdown_message_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_admin_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_graceful_restart_enable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_graceful_restart_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_graceful_restart_graceful_restart_helper_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_graceful_restart_graceful_restart_helper_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_graceful_restart_graceful_restart_disable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_graceful_restart_graceful_restart_disable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/advertise-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_timers_advertise_interval_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_timers_advertise_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/connect-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_timers_connect_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_timers_connect_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/hold-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_timers_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/keepalive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_timers_keepalive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_addpath_rx_paths_limit_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-srv6",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_encapsulation_srv6_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-mpls",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_encapsulation_mpls_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/encapsulation",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_encapsulation_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_encapsulation_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/encapsulation",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_encapsulation_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_encapsulation_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-srv6",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_encapsulation_srv6_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-mpls",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_encapsulation_mpls_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l2vpn_evpn_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l2vpn_evpn_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l2vpn_evpn_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l2vpn_evpn_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/dynamic-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_dynamic_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/strict-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_strict_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_extended_nexthop_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/capability-negotiate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_capability_negotiate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/override-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_override_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/software-version-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_software_version_capability_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_software_version_capability_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/software-version-capability-latest-encoding",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_software_version_capability_latest_encoding_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_software_version_capability_latest_encoding_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/fqdn-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_fqdn_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/link-local-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_capability_options_link_local_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-role/role",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_role_role_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_role_role_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-role/strict-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_local_role_strict_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/tcp-mss",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_tcp_mss_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_tcp_mss_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/delay-open-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_timers_delay_open_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_timers_delay_open_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/v6only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_v6only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/peer-group",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_peer_group_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_peer_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/password",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_password_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_password_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ttl-security",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_ttl_security_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_ttl_security_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/solo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_solo_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/enforce-first-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_enforce_first_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/description",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_description_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_description_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/passive-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_passive_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/rpki-strict",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_rpki_strict_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/sender-as-path-loop-detection",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_sender_as_path_loop_detection_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ip-transparent",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_ip_transparent_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-oad",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_ebgp_oad_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/aigp",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_aigp_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-shutdown",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_graceful_shutdown_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/extended-optional-parameters",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_extended_optional_parameters_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_disable_link_bw_encoding_ieee_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/extended-link-bandwidth",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_extended_link_bandwidth_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/send-nexthop-characteristics",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_send_nhc_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/shutdown-rtt/enabled",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_shutdown_rtt_enabled_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/shutdown-rtt/threshold",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_shutdown_rtt_threshold_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_shutdown_rtt_threshold_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/shutdown-rtt/count",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_shutdown_rtt_count_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/shutdown-rtt",
			.cbs = {
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/path-attribute/discard",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_path_attribute_discard_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_path_attribute_discard_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/path-attribute/treat-as-withdraw",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_path_attribute_treat_as_withdraw_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_path_attribute_treat_as_withdraw_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/update-source/ip",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_update_source_ip_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_update_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/update-source/interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_update_source_interface_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_update_source_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_ebgp_multihop_disable_connected_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/local-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_local_as_local_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_local_as_local_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/no-prepend",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_local_as_no_prepend_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/replace-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_local_as_replace_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/dual-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_local_as_dual_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/detect-multiplier",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_detect_multiplier_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/required-min-rx",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_required_min_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/desired-min-tx",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_desired_min_tx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/session-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_session_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/check-cp-failure",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_check_cp_failure_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/profile",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_profile_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_bfd_options_profile_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/strict-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/strict-hold-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_hold_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_hold_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_admin_shutdown_enable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_admin_shutdown_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/message",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_admin_shutdown_message_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_admin_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_graceful_restart_enable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_graceful_restart_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_helper_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_helper_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_disable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_disable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/advertise-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/connect-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_timers_connect_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_timers_connect_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/hold-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_timers_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/keepalive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_timers_keepalive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safi_addpath_rx_paths_limit_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safi_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-srv6",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_encapsulation_srv6_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-mpls",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_encapsulation_mpls_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/encapsulation",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_encapsulation_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_encapsulation_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/encapsulation",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_encapsulation_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_encapsulation_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-srv6",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_encapsulation_srv6_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-mpls",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_encapsulation_mpls_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/path-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l2vpn_evpn_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l2vpn_evpn_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l2vpn_evpn_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l2vpn_evpn_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/dynamic-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_dynamic_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/strict-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_strict_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_extended_nexthop_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/capability-negotiate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_capability_negotiate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/override-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_override_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/software-version-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_software_version_capability_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_software_version_capability_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/software-version-capability-latest-encoding",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_software_version_capability_latest_encoding_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_software_version_capability_latest_encoding_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/fqdn-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_fqdn_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/link-local-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_capability_options_link_local_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-role/role",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_local_role_role_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_local_role_role_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-role/strict-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_local_role_strict_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/tcp-mss",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_tcp_mss_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_tcp_mss_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/delay-open-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_timers_delay_open_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_timers_delay_open_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv4-listen-range",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ipv4_listen_range_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ipv4_listen_range_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv6-listen-range",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ipv6_listen_range_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ipv6_listen_range_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/password",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_password_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_password_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ttl-security",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ttl_security_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ttl_security_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/solo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_solo_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/enforce-first-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_enforce_first_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/description",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_description_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_description_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/passive-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_passive_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/rpki-strict",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_rpki_strict_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/sender-as-path-loop-detection",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_sender_as_path_loop_detection_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ip-transparent",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_ip_transparent_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-oad",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_ebgp_oad_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/aigp",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_aigp_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-shutdown",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_graceful_shutdown_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/extended-optional-parameters",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_extended_optional_parameters_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_disable_link_bw_encoding_ieee_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/extended-link-bandwidth",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_extended_link_bandwidth_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/send-nexthop-characteristics",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_send_nhc_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/shutdown-rtt/enabled",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_shutdown_rtt_enabled_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/shutdown-rtt/threshold",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_shutdown_rtt_threshold_modify,
				.destroy = bgp_peer_groups_peer_group_shutdown_rtt_threshold_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/shutdown-rtt/count",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_shutdown_rtt_count_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/shutdown-rtt",
			.cbs = {
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/path-attribute/discard",
			.cbs = {
				.create = bgp_peer_groups_peer_group_path_attribute_discard_create,
				.destroy = bgp_peer_groups_peer_group_path_attribute_discard_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/path-attribute/treat-as-withdraw",
			.cbs = {
				.create = bgp_peer_groups_peer_group_path_attribute_treat_as_withdraw_create,
				.destroy = bgp_peer_groups_peer_group_path_attribute_treat_as_withdraw_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/update-source/ip",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_update_source_ip_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_update_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/update-source/interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_update_source_interface_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_update_source_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ebgp_multihop_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ebgp_multihop_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_ebgp_multihop_disable_connected_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/local-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_local_as_local_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_local_as_local_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/no-prepend",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_local_as_no_prepend_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/replace-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_local_as_replace_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/dual-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_local_as_dual_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/detect-multiplier",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_detect_multiplier_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/required-min-rx",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_required_min_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/desired-min-tx",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_desired_min_tx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/session-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_session_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/check-cp-failure",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_check_cp_failure_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/profile",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_profile_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_bfd_options_profile_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/strict-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/strict-hold-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_hold_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_bfd_options_strict_hold_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_admin_shutdown_enable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_admin_shutdown_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/message",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_admin_shutdown_message_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_admin_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_graceful_restart_enable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_graceful_restart_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_graceful_restart_graceful_restart_helper_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_graceful_restart_graceful_restart_helper_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_graceful_restart_graceful_restart_disable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_graceful_restart_graceful_restart_disable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/advertise-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_timers_advertise_interval_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_timers_advertise_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/connect-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_timers_connect_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_timers_connect_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/hold-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_timers_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/keepalive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_timers_keepalive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safi_addpath_rx_paths_limit_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safi_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_labeled_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_labeled_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_labeled_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_labeled_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_labeled_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_labeled_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-srv6",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_encapsulation_srv6_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation-mpls",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_encapsulation_mpls_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/encapsulation",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_encapsulation_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_encapsulation_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/encapsulation",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_encapsulation_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_encapsulation_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-srv6",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_encapsulation_srv6_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation-mpls",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_encapsulation_mpls_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l2vpn_evpn_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l2vpn_evpn_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l2vpn_evpn_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_l2vpn_evpn_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_multicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_multicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_multicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_dampening_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/disable-rx",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_multicast_add_paths_disable_rx_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/tx-best-selected-paths",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_multicast_add_paths_tx_best_selected_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_multicast_add_paths_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/default-originate/originate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_rpki_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/dampening/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_dampening_enable_modify,
			},
		},
/* neighbors/neighbor dampening parameters */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},

/* neighbors/unnumbered-neighbor dampening parameters */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},

/* peer-groups/peer-group dampening parameters */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/dampening/half-life",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = bgp_dampening_param_modify,
				.destroy = bgp_dampening_param_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_import_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_export_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_filter_config_unsuppress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/dynamic-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_dynamic_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/strict-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_strict_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_extended_nexthop_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/capability-negotiate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_capability_negotiate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/override-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_override_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/software-version-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_software_version_capability_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_software_version_capability_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/software-version-capability-latest-encoding",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_software_version_capability_latest_encoding_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_software_version_capability_latest_encoding_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/fqdn-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_fqdn_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/link-local-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_capability_options_link_local_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-role/role",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_local_role_role_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_local_role_role_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-role/strict-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_local_role_strict_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/tcp-mss",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_tcp_mss_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_tcp_mss_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/delay-open-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_timers_delay_open_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_timers_delay_open_time_destroy,
			}
		},
		/* neighbors/neighbor SOO callbacks */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soo_destroy,
			}
		},
		/* neighbor accept-own callbacks */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/accept-own",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/accept-own",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_soo_destroy,
			}
		},
		/* unnumbered-neighbor SOO callbacks */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soo_destroy,
			}
		},
		/* unnumbered-neighbor accept-own callbacks */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/accept-own",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/accept-own",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_soo_destroy,
			}
		},
		/* peer-group SOO callbacks */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_soo_destroy,
			}
		},
		/* peer-group accept-own callbacks */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/accept-own",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/accept-own",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/soo",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_soo_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_soo_destroy,
			}
		},
		/* neighbors/neighbor advertise-map entries */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_advertise_map_condition_type_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv4_multicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_advertise_map_condition_type_modify,
				.destroy = bgp_neighbors_neighbor_afi_safi_ipv6_multicast_advertise_map_condition_type_destroy,
			}
		},

		/* neighbors/unnumbered-neighbor advertise-map entries */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_labeled_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_labeled_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_advertise_map_condition_type_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv4_multicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_advertise_map_condition_type_modify,
				.destroy = bgp_unnumbered_neighbor_afi_safi_ipv6_multicast_advertise_map_condition_type_destroy,
			}
		},

		/* peer-groups/peer-group advertise-map entries */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_labeled_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_labeled_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_labeled_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_labeled_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_labeled_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_labeled_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_labeled_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_labeled_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_labeled_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_labeled_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_labeled_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_labeled_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_peer_group_afi_safi_l3vpn_ipv4_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_type_modify,
				.destroy = bgp_peer_group_afi_safi_l3vpn_ipv6_unicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_multicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_multicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_multicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_multicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv4_multicast_advertise_map_condition_type_modify,
				.destroy = bgp_peer_group_afi_safi_ipv4_multicast_advertise_map_condition_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/advertise-map/advertise-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_multicast_advertise_map_advertise_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_multicast_advertise_map_advertise_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/advertise-map/condition-map-name",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_multicast_advertise_map_condition_map_name_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_multicast_advertise_map_condition_map_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/advertise-map/condition-type",
			.cbs = {
				.modify = bgp_peer_group_afi_safi_ipv6_multicast_advertise_map_condition_type_modify,
				.destroy = bgp_peer_group_afi_safi_ipv6_multicast_advertise_map_condition_type_destroy,
			}
		},

		/*
		 * BGP Operational State Callbacks
		 * These paths are for the config false 'bgpd' container
		 * that provides read-only access to BGP runtime state.
		 */
		{
			.xpath = "/frr-bgp:bgpd/instance",
			.cbs = {
				.get_next = bgpd_instance_get_next,
				.get_keys = bgpd_instance_get_keys,
				.lookup_entry = bgpd_instance_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/router-id",
			.cbs = {
				.get_elem = bgpd_instance_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/local-as",
			.cbs = {
				.get_elem = bgpd_instance_local_as_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/uptime",
			.cbs = {
				.get_elem = bgpd_instance_uptime_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/total-peers",
			.cbs = {
				.get_elem = bgpd_instance_total_peers_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/established-peers",
			.cbs = {
				.get_elem = bgpd_instance_established_peers_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/total-prefixes",
			.cbs = {
				.get_elem = bgpd_instance_total_prefixes_get_elem,
			}
		},
		/* Memory statistics */
		{
			.xpath = "/frr-bgp:bgpd/instance/memory/total-bytes",
			.cbs = {
				.get_elem = bgpd_instance_memory_total_bytes_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/memory/rib-count",
			.cbs = {
				.get_elem = bgpd_instance_memory_rib_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/memory/path-count",
			.cbs = {
				.get_elem = bgpd_instance_memory_path_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/memory/attr-count",
			.cbs = {
				.get_elem = bgpd_instance_memory_attr_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/memory/community-count",
			.cbs = {
				.get_elem = bgpd_instance_memory_community_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/memory/aspath-count",
			.cbs = {
				.get_elem = bgpd_instance_memory_aspath_count_get_elem,
			}
		},
		/* Neighbors list */
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor",
			.cbs = {
				.get_next = bgpd_instance_neighbors_neighbor_get_next,
				.get_keys = bgpd_instance_neighbors_neighbor_get_keys,
				.lookup_entry = bgpd_instance_neighbors_neighbor_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/session-state",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_session_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/uptime",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_uptime_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/remote-as",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_remote_as_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/remote-router-id",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_remote_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/peer-type",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_peer_type_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/last-reset-reason",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_last_reset_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/description",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_description_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/local-as",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_local_as_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/queues/input",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_queues_input_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/queues/output",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_queues_output_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/hostname",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_hostname_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/timers/hold-time",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_timers_hold_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/timers/keepalive",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_timers_keepalive_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/timestamps/last-read",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_timestamps_last_read_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/timestamps/last-write",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_timestamps_last_write_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/timestamps/last-update",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_timestamps_last_update_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/connection-stats/established-count",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_connection_stats_established_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/connection-stats/dropped-count",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_connection_stats_dropped_count_get_elem,
			}
		},
		
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/domainname",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_domainname_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/peer-group",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_peer_group_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/interface",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/tcp-mss",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_tcp_mss_get_elem,
			}
		},
		/* Message statistics - sent */
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/opens",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_sent_opens_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/updates",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_sent_updates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/keepalives",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_sent_keepalives_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/notifications",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_sent_notifications_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/route-refresh",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_sent_route_refreshes_get_elem,
			}
		},
		/* Message statistics - received */
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/opens",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_received_opens_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/updates",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_received_updates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/keepalives",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_received_keepalives_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/notifications",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_received_notifications_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/route-refresh",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_received_route_refreshes_get_elem,
			}
		},
		/* Prefix statistics */
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi",
			.cbs = {
				.get_next = bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_get_next,
				.get_keys = bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_get_keys,
				.lookup_entry = bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/received",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_received_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/accepted",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_accepted_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/sent",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_advertised_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/table-version",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_table_version_get_elem,
			}
		},
		/* Capabilities */
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/route-refresh",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_capabilities_route_refresh_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/four-octet-as",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_capabilities_four_octet_as_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/graceful-restart",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_capabilities_graceful_restart_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/add-path",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_capabilities_add_path_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/extended-nexthop",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_capabilities_extended_nexthop_get_elem,
			}
		},
		/* Update groups */
		{
			.xpath = "/frr-bgp:bgpd/instance/update-groups/update-group",
			.cbs = {
				.get_next = bgpd_instance_update_groups_update_group_get_next,
				.get_keys = bgpd_instance_update_groups_update_group_get_keys,
				.lookup_entry = bgpd_instance_update_groups_update_group_lookup_entry,
			}
		},
		/* Dampening */
		{
			.xpath = "/frr-bgp:bgpd/instance/dampening/enabled",
			.cbs = {
				.get_elem = bgpd_instance_dampening_enabled_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/dampening/half-life",
			.cbs = {
				.get_elem = bgpd_instance_dampening_half_life_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/dampening/reuse-limit",
			.cbs = {
				.get_elem = bgpd_instance_dampening_reuse_limit_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/dampening/suppress-limit",
			.cbs = {
				.get_elem = bgpd_instance_dampening_suppress_limit_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/dampening/max-suppress-time",
			.cbs = {
				.get_elem = bgpd_instance_dampening_max_suppress_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/dampening/dampened-paths",
			.cbs = {
				.get_elem = bgpd_instance_dampening_dampened_paths_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/dampening/history-paths",
			.cbs = {
				.get_elem = bgpd_instance_dampening_history_paths_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/vrf",
			.cbs = {
				.get_elem = bgpd_instance_vrf_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/remote-address",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_remote_address_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/sent/total",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_sent_total_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/message-statistics/received/total",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_message_statistics_received_total_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/prefix-statistics/afi-safi/afi-safi-name",
			.cbs = {
				.get_elem = bgpd_instance_neighbors_neighbor_prefix_statistics_afi_safi_afi_safi_name_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/advertised",
			.cbs = {
				.get_next = bgpd_instance_neighbors_neighbor_capabilities_advertised_get_next,
				.get_elem = bgpd_instance_neighbors_neighbor_capabilities_advertised_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/neighbors/neighbor/capabilities/received",
			.cbs = {
				.get_next = bgpd_instance_neighbors_neighbor_capabilities_received_get_next,
				.get_elem = bgpd_instance_neighbors_neighbor_capabilities_received_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/update-groups/update-group/id",
			.cbs = {
				.get_elem = bgpd_instance_update_groups_update_group_id_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/update-groups/update-group/afi-safi",
			.cbs = {
				.get_elem = bgpd_instance_update_groups_update_group_afi_safi_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/update-groups/update-group/member-count",
			.cbs = {
				.get_elem = bgpd_instance_update_groups_update_group_member_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/update-groups/update-group/update-count",
			.cbs = {
				.get_elem = bgpd_instance_update_groups_update_group_update_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/update-groups/update-group/packet-queue-length",
			.cbs = {
				.get_elem = bgpd_instance_update_groups_update_group_packet_queue_length_get_elem,
			}
		},
		/* SRv6 */
		{
			.xpath = "/frr-bgp:bgpd/instance/srv6/enabled",
			.cbs = {
				.get_elem = bgpd_instance_srv6_enabled_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/srv6/locator-name",
			.cbs = {
				.get_elem = bgpd_instance_srv6_locator_name_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/srv6/sid",
			.cbs = {
				.get_next = bgpd_instance_srv6_sid_get_next,
				.get_keys = bgpd_instance_srv6_sid_get_keys,
				.lookup_entry = bgpd_instance_srv6_sid_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/srv6/sid/value",
			.cbs = {
				.get_elem = bgpd_instance_srv6_sid_value_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/srv6/sid/function-type",
			.cbs = {
				.get_elem = bgpd_instance_srv6_sid_function_type_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/srv6/sid/vrf",
			.cbs = {
				.get_elem = bgpd_instance_srv6_sid_vrf_get_elem,
			}
		},
		
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi",
			.cbs = {
				.get_next = bgpd_instance_routes_afi_safi_get_next,
				.get_keys = bgpd_instance_routes_afi_safi_get_keys,
				.lookup_entry = bgpd_instance_routes_afi_safi_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/afi-safi-name",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_afi_safi_name_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/table-version",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_table_version_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route-count",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route",
			.cbs = {
				.get_next = bgpd_instance_routes_afi_safi_route_get_next,
				.get_keys = bgpd_instance_routes_afi_safi_route_get_keys,
				.lookup_entry = bgpd_instance_routes_afi_safi_route_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/prefix",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path",
			.cbs = {
				.get_next = bgpd_instance_routes_afi_safi_route_path_get_next,
				.get_keys = bgpd_instance_routes_afi_safi_route_path_get_keys,
				.lookup_entry = bgpd_instance_routes_afi_safi_route_path_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/path-id",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_path_id_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/nexthop",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_nexthop_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/metric",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/local-preference",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_local_pref_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/weight",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/origin",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_origin_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/as-path",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_as_path_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/communities",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_communities_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/extended-communities",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_ext_communities_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/large-communities",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_large_communities_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/source-peer",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_source_peer_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/valid",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_valid_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/best",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_best_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/stale",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_stale_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/multipath",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_multipath_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/uptime",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_uptime_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/route-type",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_route_type_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/route-subtype",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_route_subtype_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/route-distinguisher",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_rd_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/mpls-labels",
			.cbs = {
				.get_next = bgpd_instance_routes_afi_safi_route_path_mpls_labels_get_next,
				.get_elem = bgpd_instance_routes_afi_safi_route_path_mpls_labels_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/underlay-nexthop",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_underlay_nh_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/srv6-sid",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_srv6_sid_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp:bgpd/instance/routes/afi-safi/route/path/srv6-sid-structure",
			.cbs = {
				.get_elem = bgpd_instance_routes_afi_safi_route_path_srv6_sid_struct_get_elem,
			}
		},
		/* RPCs */
		{
			.xpath = "/frr-bgp:clear-bgp-peer",
			.cbs = {
				.rpc = clear_bgp_peer_rpc,
			}
		},
		{
			.xpath = "/frr-bgp:clear-bgp-prefix",
			.cbs = {
				.rpc = clear_bgp_prefix_rpc,
			}
		},
		{
			.xpath = "/frr-bgp:get-routes",
			.cbs = {
				.rpc = get_routes_rpc,
			}
		},
		{
			.xpath = "/frr-interface:lib/frr-interface:interface/frr-bgp:mpls-bgp-forwarding",
			.cbs = {
				.modify = lib_interface_mpls_bgp_forwarding_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/frr-interface:interface/frr-bgp:mpls-l3vpn-multi-domain-switching",
			.cbs = {
				.modify = lib_interface_mpls_l3vpn_multi_domain_switching_modify,
			}
		},
#if ENABLE_BGP_VNC
		/* VNC/RFAPI NB callbacks */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc",
			.cbs = {
				.create = bgp_global_vnc_create,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/rfp/holddown-factor",
			.cbs = {
				.modify = bgp_global_vnc_rfp_holddown_factor_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/rfp/full-table-download",
			.cbs = {
				.modify = bgp_global_vnc_rfp_full_table_download_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/defaults",
			.cbs = {
				.create = bgp_global_vnc_defaults_create,
				.destroy = bgp_global_vnc_defaults_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/defaults/rd",
			.cbs = {
				.modify = bgp_global_vnc_defaults_rd_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/defaults/response-lifetime",
			.cbs = {
				.modify = bgp_global_vnc_defaults_response_lifetime_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/defaults/rt-import",
			.cbs = {
				.modify = bgp_global_vnc_defaults_rt_import_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/defaults/rt-export",
			.cbs = {
				.modify = bgp_global_vnc_defaults_rt_export_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/nve-group",
			.cbs = {
				.create = bgp_global_vnc_nve_group_create,
				.destroy = bgp_global_vnc_nve_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/nve-group/prefix-vn",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_prefix_vn_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/nve-group/prefix-un",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_prefix_un_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/nve-group/rd",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_rd_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/nve-group/response-lifetime",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_response_lifetime_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/nve-group/rt-import",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_rt_import_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/nve-group/rt-export",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_rt_export_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/vrf-policy",
			.cbs = {
				.create = bgp_global_vnc_vrf_policy_create,
				.destroy = bgp_global_vnc_vrf_policy_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/vrf-policy/label",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_label_modify,
				.destroy = bgp_global_vnc_vrf_policy_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/vrf-policy/rd",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_rd_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/vrf-policy/rt-import",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_rt_import_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/vrf-policy/rt-export",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_rt_export_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/vrf-policy/nexthop",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_nexthop_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/export/bgp/mode",
			.cbs = {
				.modify = bgp_global_vnc_export_bgp_mode_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/export/bgp/group-nve-group",
			.cbs = {
				.create = bgp_global_vnc_export_bgp_group_nve_group_create,
				.destroy = bgp_global_vnc_export_bgp_group_nve_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/redistribute/mode",
			.cbs = {
				.modify = bgp_global_vnc_redistribute_mode_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/redistribute/ipv4-source",
			.cbs = {
				.create = bgp_global_vnc_redistribute_ipv4_source_create,
				.destroy = bgp_global_vnc_redistribute_ipv4_source_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/vnc/redistribute/ipv6-source",
			.cbs = {
				.create = bgp_global_vnc_redistribute_ipv6_source_create,
				.destroy = bgp_global_vnc_redistribute_ipv6_source_destroy,
			}
		},
#endif /* ENABLE_BGP_VNC */
		{
			.xpath = NULL,
		},
	}
};

/* clang-format on */
