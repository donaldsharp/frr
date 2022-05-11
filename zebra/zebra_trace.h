// SPDX-License-Identifier: GPL-2.0-or-later
/* Tracing for zebra
 *
 * Copyright (c) 2020, 2021, NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved.
 * Donald Sharp
 */

#if !defined(__ZEBRA_TRACE_H__) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define __ZEBRA_TRACE_H__

#include "lib/trace.h"


#if defined(HAVE_LTTNG) || defined(HAVE_ZEBRA_LTTNG)

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_zebra

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "zebra/zebra_trace.h"

#include <lttng/tracepoint.h>

#include <lib/ns.h>
#include <lib/table.h>

#include <zebra/zebra_ns.h>
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mroute.h"
#include "zebra/rt.h"
#include "lib/stream.h"
#include "lib/vrf.h"
#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_l2_bridge_if.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_router.h"

#include <linux/if_bridge.h>

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_request_intf_addr,
	TP_ARGS(struct nlsock *, netlink_cmd,
		int, family,
		int, type,
		uint32_t, filter_mask),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, netlink_cmd, netlink_cmd)
		ctf_integer(int, family, family)
		ctf_integer(int, type, type)
		ctf_integer(uint32_t, filter_mask, filter_mask)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_interface,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_interface_addr,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_route_change_read_unicast,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_rule_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)
/* clang-format off */

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ipmr_route_stats,
	TP_ARGS(
		vrf_id_t, vrf_id),
	TP_FIELDS(
		ctf_integer(unsigned int, vrfid, vrf_id)
		ctf_string(mroute_vrf_id, "Asking for mroute information")
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ipmr_route_stats, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_add_update,
	TP_ARGS(
		struct interface *, ifp),
	TP_FIELDS(
		ctf_integer(unsigned int, ifindex, ifp->ifindex)
		ctf_integer(unsigned int, vrfid, ifp->vrf->vrf_id)
		ctf_string(ifp, ifp->name)
		ctf_string(interface, "Interface Index added")
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_add_update, TRACE_INFO)
/* clang-format on */

TRACEPOINT_EVENT(
	frr_zebra,
	zsend_redistribute_route,
	TP_ARGS(
		uint32_t, cmd,
		struct zserv *, client,
		struct zapi_route, api,
		char *, nexthop),
	TP_FIELDS(
		ctf_string(cmd, zserv_command_string(cmd))
		ctf_string(client_proto, zebra_route_string(client->proto))
		ctf_string(api_type, zebra_route_string(api.type))
		ctf_integer(uint32_t, vrfid, api.vrf_id)
		ctf_integer(unsigned int, prefix_len, api.prefix.prefixlen)
		ctf_string(nexthops, nexthop)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zsend_redistribute_route, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ptm_bfd_dst_register,
	TP_ARGS(
		uint8_t, len),
	TP_FIELDS(
		ctf_string(reg_msg, "Register message Sent")
		ctf_integer(int, len, len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ptm_bfd_dst_register, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ptm_bfd_dst_deregister,
	TP_ARGS(
		int, data_len),
	TP_FIELDS(
		ctf_string(reg_msg, "De-Register message Sent")
		ctf_integer(int, data_len, data_len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ptm_bfd_dst_deregister, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ptm_bfd_client_register,
	TP_ARGS(int, data_len),
	TP_FIELDS(
		ctf_string(reg_msg, "BFD Client Register message Sent")
		ctf_integer(int, data_len, data_len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ptm_bfd_client_register, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ptm_bfd_client_deregister,
	TP_ARGS(
		int, data_len),
	TP_FIELDS(
		ctf_string(reg_msg, "BFD Client De-Register message Sent")
		ctf_integer(int, data_len, data_len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ptm_bfd_client_deregister, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_recv_msg,
	TP_ARGS(
		const struct nlsock *, nl,
		struct msghdr *, msg),
	TP_FIELDS(
		ctf_string(netlink_recv, "netlink message recv")
		ctf_string(nl_name, nl->name)
		ctf_integer(int, msg_len, msg->msg_namelen)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_recv_msg, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_send_msg,
	TP_ARGS(
		const struct nlsock *, nl,
		struct msghdr, msg),
	TP_FIELDS(
		ctf_string(netlink_recv, "netlink message sent")
		ctf_string(nl_name, nl->name)
		ctf_integer(uint32_t, msg_len, msg.msg_namelen)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_qdisc_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_class_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)


TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_filter_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_send_msg, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	ip_prefix_send_to_client,
	TP_ARGS(
		vrf_id_t, vrf_id,
		uint16_t, cmd,
		struct prefix *, p),
	TP_FIELDS(
		ctf_integer(int, vrfid, vrf_id)
		ctf_integer(uint16_t, cmd, cmd)
		ctf_integer(unsigned int, prefix_len, p->prefixlen)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, ip_prefix_send_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_svi_macip_del_for_evpn_hash,
	TP_ARGS(
		struct zebra_evpn *, zevpn),
	TP_FIELDS(
		ctf_integer(int, vni, zevpn->vni)
		ctf_integer(int, flags, zevpn->flags)
		ctf_integer(uint16_t, vlan_id, zevpn->vid)
		ctf_string(vtep_ip,inet_ntoa(zevpn->local_vtep_ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_svi_macip_del_for_evpn_hash, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_read_mac_neigh,
	TP_ARGS(
		struct zebra_evpn *, zevpn,
		struct interface *, br_if,
	        struct zebra_vxlan_vni *, vni,
		struct interface *, vlan_if),
	TP_FIELDS(
		//TBD: mac and remote dest, since macs are SVI MAC-IP, VRR MAC-IP
		ctf_integer(int, vni, zevpn->vni)
		ctf_integer(int, brif_index, br_if->ifindex)
		ctf_string(br_if_name, br_if->name)
		ctf_integer(int, vni_access_vlan, vni->access_vlan)
		ctf_integer(int, vlanif_index, vlan_if->ifindex)
		ctf_string(vlanif_name, vlan_if->name)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_read_mac_neigh, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_send_add_to_client,
	TP_ARGS(
		struct zebra_evpn *, zevpn,
		struct zserv *, client),
	TP_FIELDS(
		ctf_integer(int, vni, zevpn->vni)
		ctf_integer(int, vrfid, zevpn->vrf_id)
		ctf_string(vtep_ip, inet_ntoa(zevpn->local_vtep_ip))
		ctf_string(client_proto, zebra_route_string(client->proto))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_send_add_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	process_remote_macip_add,
	TP_ARGS(
		vni_t, vni,
		struct zebra_evpn *, zevpn,
		struct ethaddr *, mac,
		struct ipaddr *, ip,
		struct in_addr, vtep_ip,
		esi_t *, esi,
		uint8_t , flags,
		uint32_t, seq),
	TP_FIELDS(
		ctf_string(remote_add, "Remote MACIP add from BGP")
		ctf_integer(int, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(uint8_t, flags, flags)
		ctf_integer(uint32_t, seq, seq)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, process_remote_macip_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	process_remote_macip_del,
	TP_ARGS(
		vni_t, vni,
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		struct in_addr, vtep_ip),
	TP_FIELDS(
		ctf_string(remote_del, "Ignoring remote MACIP DEL VNI")
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(int, vni, vni)
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, process_remote_macip_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_macip_send_msg_to_client,
	TP_ARGS(
		vni_t, vni,
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		int, state,
		uint16_t, cmd,
		uint32_t, seq,
		int, ipa_len,
		esi_t *, esi),
	TP_FIELDS(
		ctf_integer(int, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(int, state, state)
		ctf_string(action, (cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del")
		ctf_integer(uint32_t, seq, seq)
		ctf_integer(int, ip_len, ipa_len)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_macip_send_msg_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	vxlan_vni_state_change,
	TP_ARGS(
		uint16_t, id,
		struct zebra_if *, zif,
		vni_t, vni,
		uint8_t, state),
	TP_FIELDS(
		ctf_integer(int, id, id)
		ctf_integer(int, vni, vni)
		ctf_integer(uint8_t, state, state)
		ctf_string(zif_name, zif->ifp->name)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, vxlan_vni_state_change, TRACE_INFO)
TRACEPOINT_EVENT(
	frr_zebra,
	netlink_vlan_change,
	TP_ARGS(
		struct nlmsghdr *, h,
		struct br_vlan_msg *, bvm,
		ns_id_t, ns_id,
		struct bridge_vlan_info *, vinfo,
		uint32_t, vrange,
		uint8_t, state,
		struct interface *, ifp),
	TP_FIELDS(
		ctf_string(if_name,ifp->name)
		ctf_string(type,nlmsg_type2str(h->nlmsg_type))
		ctf_integer(int, ns_id, ns_id)
		ctf_integer(int, vid, vinfo->vid)
		ctf_integer(uint32_t, vrange, vrange)
		ctf_integer(int, bvm_index, bvm->ifindex)
		ctf_integer(int, bvm_family, bvm->family)
		ctf_integer(uint8_t, state, state)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_vlan_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	dplane_vtep_add,
	TP_ARGS(
		const struct interface *, ifp,
		vni_t , vni,
		const struct in_addr *, ip),
	TP_FIELDS(
		ctf_string(ifp,ifp->name)
		ctf_integer(int, ifp_index, ifp->ifindex)
		ctf_integer(int, vni, vni)
		ctf_string(vtep_ip,inet_ntoa(*ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, dplane_vtep_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	dplane_vtep_delete,
	TP_ARGS(
		const struct interface *, ifp,
		vni_t , vni,
		const struct in_addr *, ip),
	TP_FIELDS(
		ctf_string(ifp,ifp->name)
		ctf_integer(int, ifp_index, ifp->ifindex)
		ctf_integer(int, vni, vni)
		ctf_string(vtep_ip,inet_ntoa(*ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, dplane_vtep_delete, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_gw_macip_del_for_evpn_hash,
	TP_ARGS(
		struct zebra_evpn *, zevpn),
	TP_FIELDS(
		ctf_integer(int, vni, zevpn->vni)
		ctf_integer(int, flags, zevpn->flags)
		ctf_integer(uint16_t, vlan_id, zevpn->vid)
		ctf_string(vtep_ip,inet_ntoa(zevpn->local_vtep_ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_gw_macip_del_for_evpn_hash, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_send_del_to_client,
	TP_ARGS(
		struct zserv *, client,
		struct zebra_evpn *,zevpn),
	TP_FIELDS(
		ctf_string(client, zebra_route_string(client->proto))
		ctf_integer(int, vni, zevpn->vni)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_send_del_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_process_sync_macip_add,
	TP_ARGS(
		struct zebra_evpn *, zevpn,
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		uint16_t, ipa_len,
		const esi_t *, esi,
		uint8_t, flags,
		uint32_t, seq),
	TP_FIELDS(
		ctf_integer(int, vni, zevpn->vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(uint16_t, ip_len, ipa_len)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(uint8_t, flags, flags)
		ctf_integer(uint32_t, seq, seq)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_process_sync_macip_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_route_add,
	TP_ARGS(
		struct zapi_route, api,
		char *, pfx,
		vrf_id_t , vrf_id,
		char *, nexthop),
	TP_FIELDS(
		ctf_integer(int, api_flag, api.flags)
		ctf_integer(int, api_msg, api.message)
		ctf_integer(int, api_safi, api.safi)
		ctf_integer(unsigned int, nhg_id, api.nhgid)
		ctf_string(prefix, pfx)
		ctf_integer(int, vrf_id, vrf_id)
		ctf_string(nexthops, nexthop)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_route_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_route_del,
	TP_ARGS(
		struct zapi_route, api,
		char *, pfx,
		uint32_t, table_id),
	TP_FIELDS(
		ctf_integer(int, api_flag, api.flags)
		ctf_integer(int, api_msg, api.message)
		ctf_integer(int, api_safi, api.safi)
		ctf_string(prefix, pfx)
		ctf_integer(int, table_id, table_id)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_route_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_nhg_add,
	TP_ARGS(
		uint32_t, id,
		uint16_t, proto,
		struct nexthop_group *, nhg,
		char *, nexthop),
	TP_FIELDS(
		ctf_integer(uint32_t, id, id)
		ctf_integer(uint16_t, proto, proto)
		ctf_integer(int, vrf_id, nhg->nexthop->vrf_id)
		ctf_integer(int, if_index, nhg->nexthop->ifindex)
		ctf_integer(int, type, nhg->nexthop->type)
		ctf_string(nexthops, nexthop)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_nhg_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_nhg_del,
	TP_ARGS(
		uint32_t, id,
		uint16_t, proto),
	TP_FIELDS(
		ctf_integer(uint32_t, id, id)
		ctf_integer(uint16_t, proto, proto)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_nhg_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_macip_add,
	TP_ARGS(
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		vni_t, vni,
		struct in_addr, vtep_ip,
		uint8_t, flags,
		esi_t *, esi),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_integer(uint8_t, flags, flags)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_macip_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_macip_del,
	TP_ARGS(
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		vni_t, vni,
		struct in_addr, vtep_ip,
		uint16_t, ipa_len),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_integer(int, ip_len, ipa_len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_macip_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_proc_remote_nh,
	TP_ARGS(
		struct ethaddr *, mac,
		struct ipaddr *, ip,
		vrf_id_t, vrf_id),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, nh_ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(int, vrf_id, vrf_id)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_proc_remote_nh, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_proc_remote_es,
	TP_ARGS(
		struct in_addr, vtep_ip,
		esi_t *, esi,
		uint16_t, cmd),
	TP_FIELDS(
		ctf_string(cmd, zserv_command_string(cmd))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_proc_remote_es, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_vtep_add,
	TP_ARGS(
		struct in_addr, vtep_ip,
		vni_t, vni,
		int, flood_control),
	TP_FIELDS(
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, flood_control, flood_control)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_vtep_add, TRACE_INFO)
/* clang-format on */
#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* __ZEBRA_TRACE_H__ */
