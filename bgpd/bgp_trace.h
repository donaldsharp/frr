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
	interface_address_vrf_upd,
	TP_ARGS(vrf_id_t, vrf_id,
            char *, name,
            vrf_id_t, new_vrf_id),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf_id)
        ctf_string(ifname, name)
		ctf_integer(int, new_vrf_id, new_vrf_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, interface_address_vrf_upd, TRACE_INFO)

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

TRACEPOINT_EVENT(
	frr_bgp,
	upd_peer_af_announce_route,
	TP_ARGS( uint64_t, updgrp_id, uint64_t, subgrp_id, char *, peer_host),
	TP_FIELDS(
            ctf_integer(uint64_t, updgrp_id, updgrp_id)
            ctf_integer(uint64_t, subgrp_id, subgrp_id)
            ctf_string(peer, peer_host)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_peer_af_announce_route, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_peer_af_announce_route_combined,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgrp_id, char *, peer_host, uint32_t, peer_count),
	TP_FIELDS(
            ctf_integer(uint64_t, updgrp_id, updgrp_id)
            ctf_integer(uint64_t, subgrp_id, subgrp_id)
            ctf_string(peer, peer_host)
            ctf_integer(uint32_t, peer_count, peer_count)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_peer_af_announce_route_combined, TRACE_INFO)

/*
 * Loc1: MP_REACH
 * Loc2: MP_UNREACH
 */
TRACEPOINT_EVENT(
	frr_bgp,
	upd_mp_unrecognized_afi_safi,
	TP_ARGS(char *, peer_host, const char *, afi, const char *, safi, uint8_t, loc),
	TP_FIELDS(
            ctf_string(peer, peer_host)
            ctf_string(afi, afi)
            ctf_string(safi, safi)
            ctf_integer(uint8_t, loc, loc)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_mp_unrecognized_afi_safi, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_ignoring_non_ll_nexthop,
	TP_ARGS(char *, peer_host, const char *, nh_global, const char *, nh_local),
	TP_FIELDS(
            ctf_string(peer, peer_host)
            ctf_string(nh_global, nh_global)
            ctf_string(nh_local, nh_local)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_ignoring_non_ll_nexthop, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_rmac_is_self_mac,
	TP_ARGS(char *, rmac),
	TP_FIELDS(
            ctf_string(rmac, rmac)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_rmac_is_self_mac, TRACE_INFO)

/*
 * Loc1: srv6 sub sub tlv
 * Loc2: srv6 sub tlv
 * Loc3: Prefix Sid
 */
TRACEPOINT_EVENT(
	frr_bgp,
	upd_attr_type_unsupported,
	TP_ARGS(uint8_t, loc, char *, peer_host, uint8_t, type),
	TP_FIELDS(
            ctf_integer(uint8_t, attr, loc)
            ctf_string(peer, peer_host)
            ctf_integer(uint8_t, type, type)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_attr_type_unsupported, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_unknown_attr_rcvd,
	TP_ARGS(char *, peer_host, uint8_t, type, uint16_t, len),
	TP_FIELDS(
            ctf_string(peer, peer_host)
            ctf_integer(uint8_t, type, type)
            ctf_integer(uint16_t, length, len)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_unknown_attr_rcvd, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_evpn_route_entry,
	TP_ARGS(uint8_t, install, const char *, vrf, uint32_t, vrf_id, char *,pfx, uint32_t, vni),
	TP_FIELDS(
            ctf_integer(uint8_t, install, install)
            ctf_string(vrf, vrf)
            ctf_integer(uint32_t, vrf_id, vrf_id)
            ctf_string(prefix, pfx)
            ctf_integer(uint32_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_evpn_route_entry, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_prefix_denied_due_to_self_mac,
	TP_ARGS(const char *, vrf, uint32_t, vrf_id, char *, pfx, char *, attr),
	TP_FIELDS(
            ctf_string(vrf, vrf)
            ctf_integer(uint32_t, vrf_id, vrf_id)
            ctf_string(prefix, pfx)
            ctf_string(attr, attr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_prefix_denied_due_to_self_mac, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_malformed_attr,
	TP_ARGS(char *, peer, char *, attr),
	TP_FIELDS(
        ctf_string(peer, peer)
        ctf_string(attr, attr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_malformed_attr, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_soo_change_reimport_prefix,
	TP_ARGS(char *, pfx, char *, attr),
	TP_FIELDS(
        ctf_string(prefix, pfx)
        ctf_string(attr, attr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_soo_change_reimport_prefix, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_attr_discarded_due_to_martian,
	TP_ARGS(const char *, vrf, char *, pfx, char *, attr, const char *, martian),
	TP_FIELDS(
            ctf_string(vrf, vrf)
            ctf_string(prefix, pfx)
            ctf_string(attr, attr)
            ctf_string(martian_type, martian)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_attr_discarded_due_to_martian , TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_evpn_martian_change,
	TP_ARGS(char *, peer, const char *, martian, uint8_t, soft_in),
	TP_FIELDS(
            ctf_string(peer, peer)
            ctf_string(martian_type, martian)
            ctf_integer(uint32_t, soft_reconfig_in, soft_in)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_evpn_martian_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_skip_update_of_removed_prefix,
	TP_ARGS(char *, peer, char *, pfx),
	TP_FIELDS(
            ctf_string(peer, peer)
            ctf_string(prefix, pfx)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_skip_update_of_removed_prefix, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_mac_rescan_evpn_table,
	TP_ARGS(char *, peer, uint8_t, soft_in),
	TP_FIELDS(
            ctf_string(peer, peer)
            ctf_integer(uint32_t, soft_reconfig_in, soft_in)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_mac_rescan_evpn_table, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_prefix_filtered_no_label,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgrp_id, char *, pfx),
	TP_FIELDS(
            ctf_integer(uint64_t, updgrp_id, updgrp_id)
            ctf_integer(uint64_t, subgrp_id, subgrp_id)
            ctf_string(prefix, pfx)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_prefix_filtered_no_label, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_comm_filter_check_failed,
	TP_ARGS(char *, pfx),
	TP_FIELDS(
            ctf_string(prefix, pfx)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_comm_filter_check_failed, TRACE_INFO)

/*
 * LOC1: Originator-id same as remote router id
 * LOC2: Filtered via ORF
 * LOC3: Output Filter
 */
TRACEPOINT_EVENT(
	frr_bgp,
	upd_prefix_filtered_due_to,
	TP_ARGS(uint8_t, loc, char *, peer, char *, pfx),
	TP_FIELDS(
            ctf_integer(uint64_t, location, loc)
            ctf_string(peer, peer)
            ctf_string(prefix, pfx)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_prefix_filtered_due_to, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_as_path_loop_filter,
	TP_ARGS(char *, peer, char *, pfx, uint32_t, as, uint8_t, confed),
	TP_FIELDS(
            ctf_string(peer, peer)
            ctf_string(prefix, pfx)
            ctf_integer(uint32_t, as, as)
            ctf_integer(uint8_t, confed, confed)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_as_path_loop_filter, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_outbound_route_map_filter,
	TP_ARGS(char *, peer, char *, pfx, char *, routemap),
	TP_FIELDS(
            ctf_string(peer, peer)
            ctf_string(prefix, pfx)
            ctf_string(routemap, routemap)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_outbound_route_map_filter, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_filtered_by_soo_extcomm,
	TP_ARGS(char *, peer, char *, pfx, char *, soo),
	TP_FIELDS(
            ctf_string(peer, peer)
            ctf_string(prefix, pfx)
            ctf_string(soo, soo)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_filtered_by_soo_extcom, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_announce_nh_self,
	TP_ARGS(const char *, family),
	TP_FIELDS(
            ctf_string(family, family)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_announce_nh_self, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_extcomm_change,
	TP_ARGS(char *, existing, char *, new),
	TP_FIELDS(
            ctf_string(existing_extcomm, existing)
            ctf_string(new_extcomm, new)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_extcomm_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_announce_route_on_policy_change,
	TP_ARGS(uint8_t, default_rt, uint64_t, updgrp_id, uint64_t, subgrp_id, const char *, policy, uint8_t, policy_type),
	TP_FIELDS(
        ctf_integer(uint8_t, default_route, default_rt)
        ctf_integer(uint64_t, updgrp_id, updgrp_id)
        ctf_integer(uint64_t, subgrp_id, subgrp_id)
        ctf_string(policy, policy)
        ctf_integer(uint8_t, policy_type, policy_type)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_announce_route_on_policy_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_announce_route_on_coalesce_timer_expiry,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgrp_id, uint32_t, coalesce_time),
	TP_FIELDS(
        ctf_integer(uint64_t, updgrp_id, updgrp_id)
        ctf_integer(uint64_t, subgrp_id, subgrp_id)
        ctf_integer(uint32_t, coalesce_time_ms, coalesce_time)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_announce_route_on_coalesce_timer_expiry, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_announce_all_routes,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgrp_id),
	TP_FIELDS(
        ctf_integer(uint64_t, updgrp_id, updgrp_id)
        ctf_integer(uint64_t, subgrp_id, subgrp_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_announce_all_routes, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_send_mp_unreach,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgrp_id, const char *, afi, const char *, safi),
	TP_FIELDS(
        ctf_integer(uint64_t, updgrp_id, updgrp_id)
        ctf_integer(uint64_t, subgrp_id, subgrp_id)
        ctf_string(afi, afi)
        ctf_string(safi, safi)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_send_mp_unreach, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_send_withdraw_details,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgrp_id, uint32_t, length, uint32_t, num_pfx),
	TP_FIELDS(
        ctf_integer(uint64_t, updgrp_id, updgrp_id)
        ctf_integer(uint64_t, subgrp_id, subgrp_id)
        ctf_integer(uint32_t, length, length)
        ctf_integer(uint32_t, prefix_count, num_pfx)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_send_withdraw_details, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_send_update_default_originate,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgrp_id, char *, tx_buf, char *, attr_str),
	TP_FIELDS(
        ctf_integer(uint64_t, updgrp_id, updgrp_id)
        ctf_integer(uint64_t, subgrp_id, subgrp_id)
        ctf_string(tx_buf, tx_buf)
        ctf_string(attr, attr_str)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_send_update_default_originate, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	upd_send_withdraw_default_originate,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgrp_id, char *, tx_buf),
	TP_FIELDS(
        ctf_integer(uint64_t, updgrp_id, updgrp_id)
        ctf_integer(uint64_t, subgrp_id, subgrp_id)
        ctf_string(tx_buf, tx_buf)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, upd_send_withdraw_default_originate, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	eor_send,
	TP_ARGS(char *, bgp_name, uint8_t, afi, uint8_t, safi,
		char *, peer_name),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_string(peer, peer_name)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, eor_send, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	eor_received,
	TP_ARGS(char *, bgp_name, uint8_t, afi, uint8_t, safi,
		char *, peer_name),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_string(peer, peer_name)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, eor_received, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_bgp_state,
	TP_ARGS(char *, bgp_name, bool, all_peers_admin_down, bool, bgp_in_gr,
		uint8_t, global_gr_mode, bool, gr_cfgd_at_nbr_lvl),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(bool, all_peers_admin_down, all_peers_admin_down)
		ctf_integer(bool, bgp_in_gr, bgp_in_gr)
		ctf_integer(uint8_t, global_gr_mode, global_gr_mode)
        ctf_integer(bool, gr_cfgd_at_nbr_lvl, gr_cfgd_at_nbr_lvl)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_bgp_state, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_err_str,
	TP_ARGS(char *, peer_host,
	  uint64_t, peer_flags,
	  uint8_t, location),
	TP_FIELDS(
		ctf_string(peer, peer_host)
		ctf_integer(uint64_t, peer_flags, peer_flags)
		ctf_integer(uint8_t, location, location)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_err_str, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _BGP_TRACE_H */
