#!/usr/bin/env python3
"""
Usage: frr_babeltrace.py trace_path

FRR pushes data into lttng tracepoints in the least overhead way possible
i.e. as binary-data/ctf_arrays. These traces need to be converted into pretty
strings for easy greping etc. This script is a babeltrace python plugin for
that pretty printing.

Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
Anuradha Karuppiah

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option)
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along
with this program; see the file COPYING; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

"""

import ipaddress
import socket
import sys

import babeltrace
import datetime

########################### common parsers - start ############################
def location_if_oper_zrecv(field_val):
    if field_val == 1:
        return ("Rx Intf address Add")
    elif field_val == 2:
        return ("Rx Intf address Delete")
    elif field_val == 3:
        return ("Rx Intf Neighbor Add")
    elif field_val == 4:
        return ("Rx Intf Neighbor Delete")

def location_netlink_nexthop_msg_encode_err(field_val):
    if field_val == 1:
        return ("kernel nexthops not supported, ignoring")
    elif field_val == 2:
        return ("proto-based nexthops only, ignoring")
    elif field_val == 3:
        return ("labeled NHGs not supported, ignoring")

def location_netlink_vrf_change(field_val):
    if field_val == 1:
        return ("IFLA_INFO_DATA missing from VRF message")
    elif field_val == 2:
        return ("IFLA_VRF_TABLE missing from VRF message")

def location_get_iflink_speed(field_val):
    if field_val == 1:
        return ("Failure to read interface")
    elif field_val == 2:
        return ("IOCTL failure to read interface")

def location_zebra_err_string(field_val):
    if field_val == 1:
        return ("IFLA_VLAN_ID missing from VLAN IF message")
    elif field_val == 2:
        return ("IFLA_GRE_LOCAL missing from GRE IF message")
    elif field_val == 3:
        return ("IFLA_GRE_REMOTE missing from GRE IF message")
    elif field_val == 4:
        return ("IFLA_GRE_LINK missing from GRE IF message")
    elif field_val == 5:
        return ("IFLA_VXLAN_ID missing from VXLAN IF message")
    elif field_val == 6:
        return ("IFLA_VXLAN_LOCAL missing from VXLAN IF message")
    elif field_val == 7:
        return ("IFLA_VXLAN_LINK missing from VXLAN IF message")
    elif field_val == 8:
        return ("ignoring IFLA_WIRELESS message")
    elif field_val == 9:
        return ("invalid Intf Name")

def location_netlink_msg_err(field_val):
    if field_val == 1:
        return ("Invalid address family")
    elif field_val == 2:
        return ("netlink msg bad size")
    elif field_val == 3:
        return ("Invalid prefix length-V4")
    elif field_val == 4:
        return ("Invalid prefix length-V6")
    elif field_val == 5:
        return ("Invalid/tentative addr")
    elif field_val == 6:
        return ("No local interface address")
    elif field_val == 7:
        return ("wrong kernel message")

def location_netlink_intf_err(field_val):
    if field_val == 1:
        return ("Local Interface Address is NULL")
    elif field_val == 2:
        return ("RTM_NEWLINK for interface without MTU set")
    elif field_val == 3:
        return ("Cannot find VNI for VID and IF for vlan state update")
    elif field_val == 4:
        return ("Cannot find bridge-vlan IF for vlan update")
    elif field_val == 5:
        return ("Ignoring non-vxlan IF for vlan update")

def location_if_add_del_upd(field_val):
    if field_val == 0:
        return ("Interface Delete")
    elif field_val == 1:
        return ("Interface Index Add")
    elif field_val == 2:
        return ("Interface Index is Shutdown. Wont Wake it up")

def location_if_protodown(field_val):
    if field_val == 1:
        return ("Intf Update Protodown")
    elif field_val == 2:
        return ("Early return if already down & reason bitfield matches")
    elif field_val == 3:
        return ("Early return if already set queued to dplane & reason bitfield matches")
    elif field_val == 4:
        return ("Early return if already unset queued to dplane & reason bitfield matches")
    elif field_val == 5:
        return ("Intf protodown dplane change")
    elif field_val == 6:
        return ("Bond Mbr Protodown on Rcvd but already sent to dplane")
    elif field_val == 7:
        return ("Bond Mbr Protodown off  Rcvd but already sent to dplane")
    elif field_val == 8:
        return ("Bond Mbr reinstate protodown in the dplane")
    elif field_val == 9:
        return ("Intf Sweeping Protodown")

def location_if_upd_ctx_dplane_res(field_val):
    if field_val == 0:
        return ("Zebra Inf Upd Success")
    elif field_val == 1:
        return ("Int Zebra INFO Ptr is NULL")
    elif field_val == 2:
        return ("Int Zebra Upd Failed")

def location_if_vrf_change(field_val):
    if field_val == 0:
        return ("DPLANE_OP_INTF_DELETE")
    elif field_val == 1:
        return ("DPLANE_OP_INTF_UPDATE")

def location_if_dplane_ifp_handling(field_val):
    if field_val == 0:
        return ("RTM_DELLINK")
    elif field_val == 1:
        return ("RTM_NEWLINK UPD: Intf has gone Down-1")
    elif field_val == 2:
        return ("RTM_NEWLINK UPD: Intf PTM up, Notifying clients")
    elif field_val == 3:
        return ("RTM_NEWLINK UPD: Intf Br changed MAC Addr")
    elif field_val == 4:
        return ("RTM_NEWLINK UPD: Intf has come Up")
    elif field_val == 5:
        return ("RTM_NEWLINK UPD: Intf has gone Down-2")

def location_if_dplane_ifp_handling_new(field_val):
    if field_val == 0:
        return ("RTM_NEWLINK ADD")
    elif field_val == 1:
        return ("RTM_NEWLINK UPD")

def location_if_ip_addr_add_del(field_val):
    if field_val == 0:
        return ("RTM_NEWADDR IPv4")
    elif field_val == 1:
        return ("RTM_DELADDR IPv4")
    elif field_val == 2:
        return ("RTM_NEWADDR IPv6")
    elif field_val == 3:
        return ("RTM_DELADDR IPv6")

def print_location_gr_deferral_timer_start(field_val):
    if field_val == 1:
        return ("Tier 1 deferral timer start")
    elif field_val == 2:
        return ("Tier 2 deferral timer start")

def print_location_gr_eors(field_val):
    if field_val == 1:
        return ("Check all EORs")
    elif field_val == 2:
        return ("All dir conn EORs rcvd")
    elif field_val == 3:
        return ("All multihop EORs NOT rcvd")
    elif field_val == 4:
        return ("All EORs rcvd")
    elif field_val == 5:
        return ("No multihop EORs pending")
    elif field_val == 6:
        return ("EOR rcvd,check path select")
    elif field_val == 7:
        return ("Do deferred path selection")

def print_location_gr_eor_peer(field_val):
    if field_val == 1:
        return ("EOR awaited from")
    elif field_val == 2:
        return ("EOR ignore")
    elif field_val == 3:
        return ("Multihop EOR awaited")
    elif field_val == 4:
        return ("Ignore EOR rcvd after tier1 expiry")
    elif field_val == 5:
        return ("Dir conn EOR awaited")

def print_afi_string(field_val):
    if field_val == 0:
        return ("UNSPEC")
    elif field_val == 1:
        return ("IPV4")
    elif field_val == 2:
        return ("IPV6")
    elif field_val == 3:
        return ("L2VPN")
    elif field_val == 4:
        return ("MAX")

def print_safi_string(field_val):
    if field_val == 0:
        return ("UNSPEC")
    elif field_val == 1:
        return ("UNICAST")
    elif field_val == 2:
        return ("MULTICAST")
    elif field_val == 3:
        return ("MPLS_VPN")
    elif field_val == 4:
        return ("ENCAP")
    elif field_val == 5:
        return ("EVPN")
    elif field_val == 6:
        return ("LABELED_UNICAST")
    elif field_val == 7:
        return ("FLOWSPEC")
    elif field_val == 8:
        return ("MAX")

def location_prefix_filter_reason(field_val):
    if field_val == 1:
        return ("Originator-id same as remote router id")
    elif field_val == 2:
        return ("Filtered via ORF")
    elif field_val == 3:
        return ("Outbound policy")

def location_attr_type_unsupported(field_val):
    if field_val == 1:
        return ("SRv6 sub sub TLV")
    elif field_val == 2:
        return ("SRv6 sub TLV")
    elif field_val == 3:
        return ("Prefix SID")

def location_last_route_re(field_val):
    if field_val == 1:
        return ("RE updated")
    elif field_val == 2:
        return ("RE not installed")

def location_bgp_err_str(field_val):
    if field_val == 1:
        return ("failed in bgp_accept")
    elif field_val == 2:
        return ("failed in bgp_connect")
def location_vni_transition(field_val):
    if field_val == 1:
        return ("Del L2-VNI - transition to L3-VNI")
    elif field_val == 2:
        return ("Adding L2-VNI - transition from L3-VNI");

def print_prefix_addr(field_val):
    """
    pretty print "struct prefix"
    """
    if field_val[0] == socket.AF_INET:
        addr = [str(fv) for fv in field_val[8:12]]
        return str(ipaddress.IPv4Address(".".join(addr)))

    if field_val[0] == socket.AF_INET6:
        tmp = "".join("%02x" % fb for fb in field_val[8:24])
        addr = []
        while tmp:
            addr.append(tmp[:4])
            tmp = tmp[4:]
        addr = ":".join(addr)
        return str(ipaddress.IPv6Address(addr))

    if not field_val[0]:
        return ""

    return field_val


def print_ip_addr(field_val):
    """
    pretty print "struct ipaddr"
    """
    if field_val[0] == socket.AF_INET:
        addr = [str(fv) for fv in field_val[4:8]]
        return str(ipaddress.IPv4Address(".".join(addr)))

    if field_val[0] == socket.AF_INET6:
        tmp = "".join("%02x" % fb for fb in field_val[4:])
        addr = []
        while tmp:
            addr.append(tmp[:4])
            tmp = tmp[4:]
        addr = ":".join(addr)
        return str(ipaddress.IPv6Address(addr))

    if not field_val[0]:
        return ""

    return field_val


def print_mac(field_val):
    """
    pretty print "u8 mac[6]"
    """
    return ":".join("%02x" % fb for fb in field_val)

def print_net_ipv4_addr(field_val):
    """
    pretty print ctf_integer_network ipv4
    """
    return str(ipaddress.IPv4Address(field_val))

def print_esi(field_val):
    """
    pretty print ethernet segment id, esi_t
    """
    return ":".join("%02x" % fb for fb in field_val)

def print_kernel_cmd(field_val):
    """
    pretty print kernel opcode to string
    """
    if field_val == 24:
        cmd_str = "RTM_NEWROUTE"
    elif field_val == 25:
        cmd_str = "RTM_DELROUTE"
    elif field_val == 26:
        cmd_str = "RTM_GETROUTE"
    else:
        cmd_str = str(field_val)

    return cmd_str

def print_operation_ug_create_delete(field_val):
    if field_val == 1:
        return ("BGP update-group create")
    elif field_val == 2:
        return ("BGP update-group delete")

def print_operation_ug_subgroup_create_delete(field_val):
    if field_val == 1:
        return ("BGP update-group subgroup create")
    elif field_val == 2:
        return ("BGP update-group subgroup delete")

def print_operation_ug_subgroup_add_remove_peer(field_val):
    if field_val == 1:
        return ("BGP update-group subgroup add peer")
    elif field_val == 2:
        return ("BGP update-group subgroup remove peer")

def get_field_list(event):
    """
    only fetch fields added via the TP, skip metadata etc.
    """
    return event.field_list_with_scope(babeltrace.CTFScope.EVENT_FIELDS)

def parse_event(event, field_parsers):
    """
    Wild card event parser; doesn"t make things any prettier
    """
    field_list = get_field_list(event)
    field_info = {}
    for field in field_list:
        if field in field_parsers:
            field_parser = field_parsers.get(field)
            field_info[field] = field_parser(event.get(field))
        else:
            field_info[field] = event.get(field)
    dt = datetime.datetime.fromtimestamp(event.timestamp/1000000000)
    dt_format = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    print(dt_format, event.name, field_info)

def parse_frr_bgp_router_id_update_zrecv(event):
    """
    bgp router-id update parser
    """
    field_parsers = {"router_id": print_prefix_addr}

    parse_event(event, field_parsers)

def parse_frr_interface_addr_oper_zrecv(event):
    """
    bgp interface (or nbr) address add/del parser
    """
    field_parsers = {"location" : location_if_oper_zrecv,
                     "address": print_prefix_addr}
    parse_event(event, field_parsers)

def parse_bgp_redistribute_zrecv(event):
    """
    bgp redistribute add/del parser
    """
    field_parsers = {"prefix": print_prefix_addr}

    parse_event(event, field_parsers)

############################ common parsers - end #############################

############################ evpn parsers - start #############################
def parse_frr_bgp_evpn_mac_ip_zsend(event):
    """
    bgp evpn mac-ip parser; raw format -
    ctf_array(unsigned char, mac, &pfx->prefix.macip_addr.mac,
            sizeof(struct ethaddr))
    ctf_array(unsigned char, ip, &pfx->prefix.macip_addr.ip,
            sizeof(struct ipaddr))
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac,
                     "esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_bum_vtep_zsend(event):
    """
    bgp evpn bum-vtep parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep,
            pfx->prefix.imet_addr.ip.ipaddr_v4.s_addr)

    """
    field_parsers = {"vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_nh_rmac_send(event):
    """
    bgp evpn nh-rmac parser; raw format -
    ctf_array(unsigned char, rmac, &nh->rmac, sizeof(struct ethaddr))
    """
    field_parsers = {"rmac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_es_add_zrecv(event):
    """
    bgp evpn local-es parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_es_del_zrecv(event):
    """
    bgp evpn local-es parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_es_evi_add_zrecv(event):
    """
    bgp evpn local-es-evi parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_es_evi_del_zrecv(event):
    """
    bgp evpn local-es-evi parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_es_evi_vtep_add(event):
    """
    bgp evpn remote ead evi remote vtep add; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_es_evi_vtep_del(event):
    """
    bgp evpn remote ead evi remote vtep del; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_ead_es_evi_route_upd(event):
    """
    bgp evpn local ead evi vtep; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_ead_es_evi_route_del(event):
    """
    bgp evpn local ead evi vtep del; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_local_vni_add_zrecv(event):
    """
    bgp evpn local-vni parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_integer_network_hex(unsigned int, mc_grp, mc_grp.s_addr)
    """
    field_parsers = {"vtep": print_net_ipv4_addr,
                     "mc_grp": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_local_l3vni_add_zrecv(event):
    """
    bgp evpn local-l3vni parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_array(unsigned char, svi_rmac, svi_rmac, sizeof(struct ethaddr))
    ctf_array(unsigned char, vrr_rmac, vrr_rmac, sizeof(struct ethaddr))
    """
    field_parsers = {"vtep": print_net_ipv4_addr,
                     "svi_rmac": print_mac,
                     "vrr_rmac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_local_macip_add_zrecv(event):
    """
    bgp evpn local-mac-ip parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac,
                     "esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_local_macip_del_zrecv(event):
    """
    bgp evpn local-mac-ip del parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_route_multipath_msg_encode(event):
    """
    bgp evpn local-mac-ip del parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"pfx": print_prefix_addr,
                     "cmd": print_kernel_cmd}

    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_ipneigh_change(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_macfdb_change(event):
    """
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_neigh_update_msg_encode(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_process_remote_macip_add(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_process_remote_macip_del(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_macip_send_msg_to_client(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_process_sync_macip_add(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_vxlan_remote_macip_add(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_vxlan_remote_macip_del(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_proc_remote_nh(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_dplane_remote_nh_add(event):
    """
    dplane enqued zebra evpn remote nh (neigh) add entry
    """
    field_parsers = {"nh_ip": print_ip_addr,
                     "rmac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_dplane_remote_nh_del(event):
    """
    dplane enqued zebra evpn remote nh (neigh) del entry
    """
    field_parsers = {"nh_ip": print_ip_addr,
                     "rmac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_dplane_remote_rmac_add(event):
    """
    dplane enqued zebra evpn remote rmac (FDB) entry
    """
    field_parsers = {"rmac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_dplane_remote_rmac_del(event):
    """
    dplane enqued zebra evpn remote rmac (FDB) entry
    """
    field_parsers = {"rmac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_proc_remote_es(event):
    """
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_advertise_type5(event):
    """
    local originated type-5 route
    """
    field_parsers = {"ip": print_ip_addr,
                     "rmac": print_mac,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_withdraw_type5(event):
    """
    local originated type-5 route withdraw
    """
    field_parsers = {"ip": print_ip_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_if_add_del_update(event):
    field_parsers = {"location" : location_if_add_del_upd}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_protodown(event):
    field_parsers = {"location" : location_if_protodown}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_upd_ctx_dplane_result(event):
    field_parsers = {"location" : location_if_upd_ctx_dplane_res}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_vrf_change(event):
    field_parsers = {"location" : location_if_vrf_change}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_dplane_ifp_handling(event):
    field_parsers = {"location" : location_if_dplane_ifp_handling}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_dplane_ifp_handling_new(event):
    field_parsers = {"location" : location_if_dplane_ifp_handling_new}
    parse_event(event, field_parsers)
    
def parse_frr_zebra_if_ip_addr_add_del(event):
    field_parsers = {"location" : location_if_ip_addr_add_del,
                     "address": print_prefix_addr}
    parse_event(event, field_parsers)

def parse_frr_bgp_gr_deferral_timer_start(event):
    field_parsers = {"location": print_location_gr_deferral_timer_start,
                     "afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_deferral_timer_expiry(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_eors(event):
    field_parsers = {"location": print_location_gr_eors,
                     "afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_eor_peer(event):
    field_parsers = {"location": print_location_gr_eor_peer,
                     "afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_start_deferred_path_selection(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_send_fbit_capability(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_continue_deferred_path_selection(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_zebra_update(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_update_prefix_filter(event):
    field_parsers = {"location" : location_prefix_filter_reason}

    parse_event(event, field_parsers)

def parse_frr_bgp_attr_type_unsupported(event):
    field_parsers = {"attr" : location_attr_type_unsupported}

    parse_event(event, field_parsers)

def parse_frr_zebra_gr_last_route_re(event):
    field_parsers = {"location" : location_last_route_re}
    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_vrf_change(event):
    field_parsers = {"location" : location_netlink_vrf_change}
    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_nexthop_msg_encode_err(event):
    field_parsers = {"location" : location_netlink_nexthop_msg_encode_err}
    parse_event(event, field_parsers)

def parse_frr_zebra_get_iflink_speed(event):
    field_parsers = {"location" : location_get_iflink_speed}
    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_err_string(event):
    field_parsers = {"location" : location_zebra_err_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_msg_err(event):
    field_parsers = {"location" : location_netlink_msg_err}
    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_intf_err(event):
    field_parsers = {"location" : location_netlink_intf_err}
    parse_event(event, field_parsers)

def parse_frr_bgp_err_str(event):
    field_parsers = {"location" : location_bgp_err_str}
    parse_event(event, field_parsers)


def parse_frr_zebra_zebra_vxlan_handle_vni_transition(event):
    field_parsers = {"location" : location_vni_transition}

    parse_event(event, field_parsers)

def parse_frr_bgp_ug_create_delete(event):
    field_parsers = {"operation": print_operation_ug_create_delete}
    parse_event(event, field_parsers)

def parse_frr_bgp_ug_subgroup_create_delete(event):
    field_parsers = {"operation": print_operation_ug_subgroup_create_delete}
    parse_event(event, field_parsers)

def parse_frr_bgp_ug_subgroup_add_remove_peer(event):
    field_parsers = {"operation": print_operation_ug_subgroup_add_remove_peer}
    parse_event(event, field_parsers)

def parse_frr_bgp_ug_bgp_aggregate_install(event):
    field_parsers = {"prefix": print_prefix_addr,
                     "afi": print_afi_string,
                     "safi": print_safi_string}
    parse_event(event, field_parsers)

############################ evpn parsers - end *#############################

def main():
    """
    FRR lttng trace output parser; babel trace plugin
    """
    event_parsers = {"frr_bgp:evpn_mac_ip_zsend":
                     parse_frr_bgp_evpn_mac_ip_zsend,
                     "frr_bgp:evpn_bum_vtep_zsend":
                     parse_frr_bgp_evpn_bum_vtep_zsend,
                     "frr_bgp:evpn_mh_nh_rmac_zsend":
                     parse_frr_bgp_evpn_mh_nh_rmac_send,
                     "frr_bgp:evpn_mh_local_es_add_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_add_zrecv,
                     "frr_bgp:evpn_mh_local_es_del_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_del_zrecv,
                     "frr_bgp:evpn_mh_local_es_evi_add_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_evi_add_zrecv,
                     "frr_bgp:evpn_mh_local_es_evi_del_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_evi_del_zrecv,
                     "frr_bgp:evpn_mh_es_evi_vtep_add":
                     parse_frr_bgp_evpn_mh_es_evi_vtep_add,
                     "frr_bgp:evpn_mh_es_evi_vtep_del":
                     parse_frr_bgp_evpn_mh_es_evi_vtep_del,
                     "frr_bgp:evpn_mh_local_ead_es_evi_route_upd":
                     parse_frr_bgp_evpn_mh_local_ead_es_evi_route_upd,
                     "frr_bgp:evpn_mh_local_ead_es_evi_route_del":
                     parse_frr_bgp_evpn_mh_local_ead_es_evi_route_del,
                     "frr_bgp:evpn_local_vni_add_zrecv":
                     parse_frr_bgp_evpn_local_vni_add_zrecv,
                     "frr_bgp:evpn_local_l3vni_add_zrecv":
                     parse_frr_bgp_evpn_local_l3vni_add_zrecv,
                     "frr_bgp:evpn_local_macip_add_zrecv":
                     parse_frr_bgp_evpn_local_macip_add_zrecv,
                     "frr_bgp:evpn_local_macip_del_zrecv":
                     parse_frr_bgp_evpn_local_macip_del_zrecv,
                     "frr_bgp:evpn_advertise_type5":
                     parse_frr_bgp_evpn_advertise_type5,
                     "frr_bgp:evpn_withdraw_type5":
                     parse_frr_bgp_evpn_withdraw_type5,
                     "frr_zebra:netlink_route_multipath_msg_encode":
                     parse_frr_zebra_netlink_route_multipath_msg_encode,
                     "frr_zebra:netlink_ipneigh_change":
                     parse_frr_zebra_netlink_ipneigh_change,
                     "frr_zebra:netlink_macfdb_change":
                     parse_frr_zebra_netlink_macfdb_change,
                     "frr_zebra:netlink_neigh_update_msg_encode":
                     parse_frr_zebra_netlink_neigh_update_msg_encode,
                     "frr_zebra:process_remote_macip_add":
                     parse_frr_zebra_process_remote_macip_add,
                     "frr_zebra:process_remote_macip_del":
                     parse_frr_zebra_process_remote_macip_del,
                     "frr_zebra:zebra_evpn_macip_send_msg_to_client":
                     parse_frr_zebra_zebra_evpn_macip_send_msg_to_client,
                     "frr_zebra:zebra_evpn_process_sync_macip_add":
                     parse_frr_zebra_zebra_evpn_process_sync_macip_add,
                     "frr_zebra:zebra_vxlan_remote_macip_add":
                     parse_frr_zebra_zebra_vxlan_remote_macip_add,
                     "frr_zebra:zebra_vxlan_remote_macip_del":
                     parse_frr_zebra_zebra_vxlan_remote_macip_del,
                     "frr_zebra:zebra_evpn_proc_remote_nh":
                     parse_frr_zebra_zebra_evpn_proc_remote_nh,
                     "frr_zebra:evpn_dplane_remote_nh_add":
                     parse_frr_zebra_evpn_dplane_remote_nh_add,
                     "frr_zebra:evpn_dplane_remote_nh_del":
                     parse_frr_zebra_evpn_dplane_remote_nh_del,
                     "frr_zebra:evpn_dplane_remote_rmac_add":
                     parse_frr_zebra_evpn_dplane_remote_rmac_add,
                     "frr_zebra:evpn_dplane_remote_rmac_del":
                     parse_frr_zebra_evpn_dplane_remote_rmac_del,
                     "frr_zebra:zebra_evpn_proc_remote_es":
                     parse_frr_zebra_zebra_evpn_proc_remote_es,
                     "frr_zebra:if_add_del_update":
                     parse_frr_zebra_if_add_del_update,
                     "frr_zebra:if_protodown":
                     parse_frr_zebra_if_protodown,
                     "frr_zebra:if_upd_ctx_dplane_result":
                     parse_frr_zebra_if_upd_ctx_dplane_result,
                     "frr_zebra:if_vrf_change":
                     parse_frr_zebra_if_vrf_change,
                     "frr_zebra:if_dplane_ifp_handling":
                     parse_frr_zebra_if_dplane_ifp_handling,
                     "frr_zebra:if_dplane_ifp_handling_new":
                     parse_frr_zebra_if_dplane_ifp_handling_new,
                     "frr_zebra:if_ip_addr_add_del":
                     parse_frr_zebra_if_ip_addr_add_del,
                     "frr_bgp:gr_deferral_timer_start":
                     parse_frr_bgp_gr_deferral_timer_start,
                     "frr_bgp:gr_deferral_timer_expiry":
                     parse_frr_bgp_gr_deferral_timer_expiry,
                     "frr_bgp:gr_eors":
                     parse_frr_bgp_gr_eors,
                     "frr_bgp:gr_eor_peer":
                     parse_frr_bgp_gr_eor_peer,
                     "frr_bgp:gr_start_deferred_path_selection":
                     parse_frr_bgp_gr_start_deferred_path_selection,
                     "frr_bgp:gr_send_fbit_capability":
                     parse_frr_bgp_gr_send_fbit_capability,
                     "frr_bgp:gr_continue_deferred_path_selection":
                     parse_frr_bgp_gr_continue_deferred_path_selection,
                     "frr_bgp:gr_zebra_update":
                     parse_frr_bgp_gr_zebra_update,
                     "frr_bgp:router_id_update_zrecv":
                     parse_frr_bgp_router_id_update_zrecv,
                     "frr_bgp:interface_address_oper_zrecv":
                     parse_frr_interface_addr_oper_zrecv,
                     "frr_bgp:bgp_redistribute_add_zrecv":
                     parse_bgp_redistribute_zrecv,
                     "frr_bgp:bgp_redistribute_delete_zrecv":
                     parse_bgp_redistribute_zrecv,
                     "frr_bgp:upd_prefix_filtered_due_to":
                     parse_frr_update_prefix_filter,
                     "frr_bgp:upd_attr_type_unsupported":
                     parse_frr_bgp_attr_type_unsupported,
                     "frr_zebra:gr_last_route_re":
                     parse_frr_zebra_gr_last_route_re,
                     "frr_zebra:netlink_vrf_change":
                     parse_frr_zebra_netlink_vrf_change,
                     "frr_zebra:netlink_nexthop_msg_encode_err":
                     parse_frr_zebra_netlink_nexthop_msg_encode_err,
                     "frr_zebra:get_iflink_speed":
                     parse_frr_zebra_get_iflink_speed,
                     "frr_zebra:z_err_string":
                     parse_frr_zebra_zebra_err_string,
                     "frr_zebra:netlink_msg_err":
                     parse_frr_zebra_netlink_msg_err,
                     "frr_zebra:netlink_intf_err":
                     parse_frr_zebra_netlink_intf_err,
                     "frr_bgp:bgp_err_str":
                     parse_frr_bgp_err_str,
                     "frr_bgp:ug_create_delete":
                     parse_frr_bgp_ug_create_delete,
                     "frr_bgp:ug_subgroup_create_delete":
                     parse_frr_bgp_ug_subgroup_create_delete,
                     "frr_bgp:ug_subgroup_add_remove_peer":
                     parse_frr_bgp_ug_subgroup_add_remove_peer,
                     "frr_bgp:ug_bgp_aggregate_install":
                     parse_frr_bgp_ug_bgp_aggregate_install,
                    "frr_zebra:zebra_vxlan_handle_vni_transition":
                     parse_frr_zebra_zebra_vxlan_handle_vni_transition,
}

    # get the trace path from the first command line argument
    trace_path = sys.argv[1]

    # grab events
    trace_collection = babeltrace.TraceCollection()
    trace_collection.add_traces_recursive(trace_path, "ctf")

    for event in trace_collection.events:
        if event.name in event_parsers:
            event_parser = event_parsers.get(event.name)
            event_parser(event)
        else:
            parse_event(event, {})

if __name__ == "__main__":
    main()
