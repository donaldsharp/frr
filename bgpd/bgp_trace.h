/* Tracing for BGP
 *
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#if !defined(_BGP_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _BGP_TRACE_H

#include "lib/trace.h"


#if defined(HAVE_LTTNG) || defined(HAVE_BGP_LTTNG)

#if !defined(HAVE_LTTNG)
#undef frrtrace
#undef frrtrace_enabled
#undef frrtracelog
#define frrtrace(nargs, provider, name, ...)                                   \
	tracepoint(provider, name, ##__VA_ARGS__)
#define frrtrace_enabled(...) tracepoint_enabled(__VA_ARGS__)
#define frrtracelog(...) tracelog(__VA_ARGS__)
#endif

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_bgp

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "bgpd/bgp_trace.h"

#include <lttng/tracepoint.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "lib/stream.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"


/* clang-format off */

TRACEPOINT_EVENT_CLASS(
	frr_bgp,
	packet_process,
	TP_ARGS(struct peer *, peer, bgp_size_t, size),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

#define PKT_PROCESS_TRACEPOINT_INSTANCE(name)                                  \
	TRACEPOINT_EVENT_INSTANCE(                                             \
		frr_bgp, packet_process, name,                                 \
		TP_ARGS(struct peer *, peer, bgp_size_t, size))                \
	TRACEPOINT_LOGLEVEL(frr_bgp, name, TRACE_INFO)

PKT_PROCESS_TRACEPOINT_INSTANCE(open_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(update_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(notification_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(capability_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(refresh_process)

TRACEPOINT_EVENT(
	frr_bgp,
	process_update,
	TP_ARGS(struct peer *, peer, char *, pfx, uint32_t, addpath_id, afi_t,
		afi, safi_t, safi, struct attr *, attr),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(uint32_t, addpath_id, addpath_id)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer_hex(intptr_t, attribute_ptr, attr)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, process_update, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	input_filter,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t, afi, safi_t, safi,
		const char *, result),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_string(action, result)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, input_filter, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	output_filter,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t, afi, safi_t, safi,
		const char *, result),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_string(action, result)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, output_filter, TRACE_INFO)

/* BMP tracepoints */

/* BMP mirrors a packet to all mirror-enabled targets */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_mirror_packet,
	TP_ARGS(struct peer *, peer, uint8_t, type, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_integer(uint8_t, type, type)
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t,
				 STREAM_READABLE(pkt))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_mirror_packet, TRACE_INFO)


/* BMP sends an EOR */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_eor,
	TP_ARGS(afi_t, afi, safi_t, safi, uint8_t, flags),
	TP_FIELDS(
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer(uint8_t, flags, flags)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_eor, TRACE_INFO)


/* BMP updates its copy of the last OPEN a peer sent */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_update_saved_open,
	TP_ARGS(struct peer *, peer, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t,
				 STREAM_READABLE(pkt))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_update_saved_open, TRACE_DEBUG)


/* BMP is notified of a peer status change internally */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_peer_status_changed,
	TP_ARGS(struct peer *, peer),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_peer_status_changed, TRACE_DEBUG)


/*
 * BMP is notified that a peer has transitioned in the opposite direction of
 * Established internally
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_peer_backward_transition,
	TP_ARGS(struct peer *, peer),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_peer_backward, TRACE_DEBUG)


/*
 * BMP is hooked for a route process
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_process,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t,
		afi, safi_t, safi, bool, withdraw),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer(bool, withdraw, withdraw)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_process, TRACE_DEBUG)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mac_ip_zsend,
	TP_ARGS(int, add, struct bgpevpn *, vpn,
		const struct prefix_evpn *, pfx,
		struct in_addr, vtep, esi_t *, esi),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(vni_t, vni, (vpn ? vpn->vni : 0))
		ctf_integer(uint32_t, eth_tag, &pfx->prefix.macip_addr.eth_tag)
		ctf_array(unsigned char, mac, &pfx->prefix.macip_addr.mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, &pfx->prefix.macip_addr.ip,
			sizeof(struct ipaddr))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mac_ip_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_bum_vtep_zsend,
	TP_ARGS(int, add, struct bgpevpn *, vpn,
		const struct prefix_evpn *, pfx),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(vni_t, vni, (vpn ? vpn->vni : 0))
		ctf_integer_network_hex(unsigned int, vtep,
			pfx->prefix.imet_addr.ip.ipaddr_v4.s_addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_bum_vtep_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_vtep_zsend,
	TP_ARGS(bool, add, struct bgp_evpn_es *, es,
		struct bgp_evpn_es_vtep *, es_vtep),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_string(esi, es->esi_str)
		ctf_string(vtep, es_vtep->vtep_str)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_vtep_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nhg_zsend,
	TP_ARGS(bool, add, bool, type_v4, uint32_t, nhg_id,
		struct bgp_evpn_es_vrf *, es_vrf),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_string(type, type_v4 ? "v4" : "v6")
		ctf_integer(unsigned int, nhg, nhg_id)
		ctf_string(esi, es_vrf->es->esi_str)
		ctf_integer(int, vrf, es_vrf->bgp_vrf->vrf_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_nhg_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nh_zsend,
	TP_ARGS(uint32_t, nhg_id, struct bgp_evpn_es_vtep *, vtep,
		struct bgp_evpn_es_vrf *, es_vrf),
	TP_FIELDS(
		ctf_integer(unsigned int, nhg, nhg_id)
		ctf_string(vtep, vtep->vtep_str)
		ctf_integer(int, svi, es_vrf->bgp_vrf->l3vni_svi_ifindex)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_nh_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nh_rmac_zsend,
	TP_ARGS(bool, add, struct bgp_evpn_nh *, nh),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(int, vrf, nh->bgp_vrf->vrf_id)
		ctf_string(nh, nh->nh_str)
		ctf_array(unsigned char, rmac, &nh->rmac,
			sizeof(struct ethaddr))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_nh_rmac_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_add_zrecv,
	TP_ARGS(esi_t *, esi, struct in_addr, vtep,
		uint8_t, active, uint8_t, bypass, uint16_t, df_pref),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(uint8_t, active, active)
		ctf_integer(uint8_t, bypass, bypass)
		ctf_integer(uint16_t, df_pref, df_pref)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_del_zrecv,
	TP_ARGS(esi_t *, esi),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_evi_add_zrecv,
	TP_ARGS(esi_t *, esi, vni_t, vni),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_evi_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_evi_del_zrecv,
	TP_ARGS(esi_t *, esi, vni_t, vni),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_evi_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_es_evi_vtep_add,
	TP_ARGS(esi_t *, esi, vni_t, vni, struct in_addr, vtep,
		uint8_t, ead_es),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(uint8_t, ead_es, ead_es)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_es_evi_vtep_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_es_evi_vtep_del,
	TP_ARGS(esi_t *, esi, vni_t, vni, struct in_addr, vtep,
		uint8_t, ead_es),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(uint8_t, ead_es, ead_es)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_es_evi_vtep_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_ead_es_evi_route_upd,
	TP_ARGS(esi_t *, esi, vni_t, vni,
		uint8_t, route_type,
		struct in_addr, vtep),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint8_t, route_type, route_type)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_ead_es_evi_route_upd, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_ead_es_evi_route_del,
	TP_ARGS(esi_t *, esi, vni_t, vni,
		uint8_t, route_type,
		struct in_addr, vtep),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint8_t, route_type, route_type)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_ead_es_evi_route_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_vni_add_zrecv,
	TP_ARGS(vni_t, vni, struct in_addr, vtep, vrf_id_t, vrf,
			struct in_addr, mc_grp),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer_network_hex(unsigned int, mc_grp,
			mc_grp.s_addr)
		ctf_integer(int, vrf, vrf)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_vni_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_vni_del_zrecv,
	TP_ARGS(vni_t, vni),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_vni_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_macip_add_zrecv,
	TP_ARGS(vni_t, vni, struct ethaddr *, mac,
		struct ipaddr *, ip, uint32_t, flags,
		uint32_t, seqnum, esi_t *, esi),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			sizeof(struct ipaddr))
		ctf_integer(uint32_t, flags, flags)
		ctf_integer(uint32_t, seq, seqnum)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_macip_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_macip_del_zrecv,
	TP_ARGS(vni_t, vni, struct ethaddr *, mac, struct ipaddr *, ip,
			int, state),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			sizeof(struct ipaddr))
		ctf_integer(int, state, state)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_macip_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_advertise_type5,
	TP_ARGS(vrf_id_t, vrf, const struct prefix_evpn *, pfx,
		struct ethaddr *, rmac, struct in_addr, vtep),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf)
		ctf_array(unsigned char, ip, &pfx->prefix.prefix_addr.ip,
			sizeof(struct ipaddr))
		ctf_array(unsigned char, rmac, rmac,
			sizeof(struct ethaddr))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_advertise_type5, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_withdraw_type5,
	TP_ARGS(vrf_id_t, vrf, const struct prefix_evpn *, pfx),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf)
		ctf_array(unsigned char, ip, &pfx->prefix.prefix_addr.ip,
			sizeof(struct ipaddr))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_withdraw_type5, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_l3vni_add_zrecv,
	TP_ARGS(vni_t, vni, vrf_id_t, vrf,
			struct ethaddr *, svi_rmac,
			struct ethaddr *, vrr_rmac, int, filter,
			struct in_addr, vtep, int, svi_ifindex,
			bool, anycast_mac),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, vrf, vrf)
		ctf_array(unsigned char, svi_rmac, svi_rmac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, vrr_rmac, vrr_rmac,
			sizeof(struct ethaddr))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(int, filter, filter)
		ctf_integer(int, svi_ifindex, svi_ifindex)
		ctf_string(anycast_mac, anycast_mac ? "y" : "n")
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_l3vni_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_l3vni_del_zrecv,
	TP_ARGS(vni_t, vni, vrf_id_t, vrf),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, vrf, vrf)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_l3vni_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	handle_fast_down_zrecv,
	TP_ARGS(bool, upgrade),
	TP_FIELDS(
		ctf_integer(bool, upgrade, upgrade)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, handle_fast_down_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	router_id_update_zrecv,
	TP_ARGS(vrf_id_t, vrf_id, struct prefix *, router_id),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf_id)
        ctf_array(unsigned char, router_id, router_id, sizeof(struct prefix))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, router_id_update_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	interface_address_oper_zrecv,
	TP_ARGS(vrf_id_t, vrf_id, char *, name,
                struct prefix *, address,
                uint8_t, loc),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf_id)
        ctf_string(ifname, name)
        ctf_array(unsigned char, address, address, sizeof(struct prefix))
		ctf_integer(uint8_t, location, loc)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, interface_address_oper_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_redistribute_add_zrecv,
	TP_ARGS(char *, vrf, struct prefix *, pfx, ifindex_t, ifindex,
                enum nexthop_types_t, nhtype, uint8_t, distance,
                enum blackhole_type, bhtype, uint32_t, metric,
                uint8_t, type,
                unsigned short, instance,
                route_tag_t, tag),
	TP_FIELDS(
		ctf_string(vrf, vrf)
        ctf_array(unsigned char, prefix, pfx, sizeof(struct prefix))
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(enum nexthop_types_t, nhtype, nhtype)
		ctf_integer(uint8_t, distance, distance)
		ctf_integer(enum blackhole_type, bhtype, bhtype)
		ctf_integer(uint32_t, metric, metric)
		ctf_integer(uint8_t, type, type)
		ctf_integer(unsigned short, instance, instance)
		ctf_integer(route_tag_t, tag, tag)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_redistribute_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_redistribute_delete_zrecv,
	TP_ARGS(char *, vrf, struct prefix *, pfx, uint8_t, type,
                unsigned short, instance),
	TP_FIELDS(
		ctf_string(vrf, vrf)
        ctf_array(unsigned char, prefix, pfx, sizeof(struct prefix))
		ctf_integer(uint8_t, type, type)
		ctf_integer(unsigned short, instance, instance)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_redistribute_delete_zrecv, TRACE_INFO)

/*
 * Loc 1 - gr_tier1_deferral_timer_start,
 * Loc 2 - gr_tier2_deferral_timer_start,
 */
TRACEPOINT_EVENT(
	frr_bgp,
	gr_deferral_timer_start,
	TP_ARGS(char *, bgp_name, uint8_t, afi, uint8_t, safi,
		uint32_t, defer_time, uint8_t, loc),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		  ctf_integer(uint8_t, afi, afi)
		  ctf_integer(uint8_t, safi, safi)
		ctf_integer(uint32_t, defer_time, defer_time)
		ctf_integer(uint8_t, location, loc)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_deferral_timer_start, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_deferral_timer_expiry,
	TP_ARGS(char *, bgp_name, bool, tier2,uint8_t, afi, uint8_t, safi,
		uint32_t, deferred_rt_cnt),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_string(gr_tier, tier2 ? "2" : "1")
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_integer(uint32_t, deferred_routes, deferred_rt_cnt)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_deferral_timer_expiry, TRACE_INFO)

/*
 * Loc1: gr_check_all_eors
 * Loc2: gr_all_directly_connected_eors_rcvd
 * Loc3: gr_all_multihop_eors_not_rcvd
 * Loc4: gr_all_eors_rcvd
 * Loc5: gr_no_multihop_eors_pending
 * Loc6: gr_eor_rcvd_check_path_select
 * Loc7: gr_do_deferred_path_selection
 */
TRACEPOINT_EVENT(
	frr_bgp,
	gr_eors,
	TP_ARGS(char *, bgp_name,uint8_t, afi, uint8_t, safi, uint8_t, loc),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		  ctf_integer(uint8_t, safi, safi)

		ctf_integer(uint8_t, location, loc)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_eors, TRACE_INFO)

/*
 * Loc1: gr_eor_awaited_from
 * Loc2: gr_eor_ignore
 * Loc3: gr_multihop_eor_awaited
 * Loc4: gr_eor_ignore_after_tier1_timer_expiry
 * Loc5: gr_directly_connected_eor_awaited
 */
TRACEPOINT_EVENT(
	frr_bgp,
	gr_eor_peer,
	TP_ARGS(char *, bgp_name, uint8_t, afi, uint8_t, safi,
		char *, peer_name, uint8_t, loc),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_string(peer, peer_name)
		ctf_integer(uint8_t, location, loc)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_eor_peer, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_start_deferred_path_selection,
	TP_ARGS(char *, bgp_name,uint8_t, afi, uint8_t, safi,
		uint32_t, deferred_rt_cnt),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_integer(uint32_t, deferred_routes, deferred_rt_cnt)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_start_deferred_path_selection, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_peer_up_ignore,
	TP_ARGS(char *, bgp_name, char *, peer_host,
		uint32_t, peer_cap, uint64_t, peer_flags),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_string(peer, peer_host)
		ctf_integer(uint32_t, capability, peer_cap)
		ctf_integer(uint64_t, peer_flags, peer_flags)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_peer_up_ignore, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_send_rbit_capability,
	TP_ARGS(char *, bgp_name, char *, peer_host,
		uint32_t, restart_time, bool, restart),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_string(peer, peer_host)
		ctf_integer(uint32_t, restart_time, restart_time)
		ctf_integer(bool, R_bit, restart)

	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_send_rbit_capability, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_send_fbit_capability,
	TP_ARGS(char *, bgp_name, char *, peer_host,
		uint8_t, afi, uint8_t, safi, bool, f_bit),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_string(peer, peer_host)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_integer(bool, F_bit, f_bit)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_send_fbit_capability, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_continue_deferred_path_selection,
	TP_ARGS(char *, bgp_name, uint8_t, afi, uint8_t, safi,
		uint32_t, deferred_rt_remain),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_integer(uint32_t, remaining_routes, deferred_rt_remain)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_continue_deferred_path_selection, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_send_capabilities,
	TP_ARGS(char *, bgp_name, uint32_t, vrf_id, bool, disable),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint32_t, vrf_id, vrf_id)
		ctf_integer(bool, disable, disable)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_send_capabilities, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_zebra_update,
	TP_ARGS(char *, bgp_name, uint8_t, afi, uint8_t, safi, const char *, type),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_string(type, type)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_zebra_update, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_ignore_suppress_route,
	TP_ARGS(struct bgp_dest *, dest, struct peer *, peer),
	TP_FIELDS(
		ctf_string(prefix, bgp_dest_get_prefix_str(dest))
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_ignore_suppress_route, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _BGP_TRACE_H */
