/*
 * Interface looking up by netlink.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#ifdef GNU_LINUX

/* The following definition is to workaround an issue in the Linux kernel
 * header files with redefinition of 'struct in6_addr' in both
 * netinet/in.h and linux/in6.h.
 * Reference - https://sourceware.org/ml/libc-alpha/2013-01/msg00599.html
 */
#define _LINUX_IN6_H

#include <netinet/if_ether.h>
#include <linux/if_bridge.h>
#include <linux/if_link.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "zebra_memory.h"
#include "rib.h"
#include "thread.h"
#include "privs.h"
#include "nexthop.h"
#include "vrf.h"
#include "vrf_int.h"
#include "mpls.h"
#include "lib_errors.h"

#include "vty.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_arp_nd.h"

extern struct zebra_privs_t zserv_privs;
uint8_t frr_protodown_r_bit = FRR_PROTODOWN_REASON_DEFAULT_BIT;

/* Note: on netlink systems, there should be a 1-to-1 mapping between interface
   names and ifindex values. */
static void set_ifindex(struct interface *ifp, ifindex_t ifi_index,
			struct zebra_ns *zns)
{
	struct interface *oifp;

	if (((oifp = if_lookup_by_index_per_ns(zns, ifi_index)) != NULL)
	    && (oifp != ifp)) {
		if (ifi_index == IFINDEX_INTERNAL)
			flog_err(
				EC_LIB_INTERFACE,
				"Netlink is setting interface %s ifindex to reserved internal value %u",
				ifp->name, ifi_index);
		else {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"interface index %d was renamed from %s to %s",
					ifi_index, oifp->name, ifp->name);
			if (if_is_up(oifp))
				flog_err(
					EC_LIB_INTERFACE,
					"interface rename detected on up interface: index %d was renamed from %s to %s, results are uncertain!",
					ifi_index, oifp->name, ifp->name);
			if_delete_update(oifp);
		}
	}
	if_set_index(ifp, ifi_index);
}

/* Utility function to parse hardware link-layer address and update ifp */
static void netlink_interface_update_hw_addr(struct rtattr **tb,
					     struct interface *ifp)
{
	int i;

	if (tb[IFLA_ADDRESS]) {
		int hw_addr_len;

		hw_addr_len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);

		if (hw_addr_len > INTERFACE_HWADDR_MAX)
			zlog_debug("Hardware address is too large: %d",
				   hw_addr_len);
		else {
			ifp->hw_addr_len = hw_addr_len;
			memcpy(ifp->hw_addr, RTA_DATA(tb[IFLA_ADDRESS]),
			       hw_addr_len);

			for (i = 0; i < hw_addr_len; i++)
				if (ifp->hw_addr[i] != 0)
					break;

			if (i == hw_addr_len)
				ifp->hw_addr_len = 0;
			else
				ifp->hw_addr_len = hw_addr_len;
		}
	}
}

static enum zebra_link_type netlink_to_zebra_link_type(unsigned int hwt)
{
	switch (hwt) {
	case ARPHRD_ETHER:
		return ZEBRA_LLT_ETHER;
	case ARPHRD_EETHER:
		return ZEBRA_LLT_EETHER;
	case ARPHRD_AX25:
		return ZEBRA_LLT_AX25;
	case ARPHRD_PRONET:
		return ZEBRA_LLT_PRONET;
	case ARPHRD_IEEE802:
		return ZEBRA_LLT_IEEE802;
	case ARPHRD_ARCNET:
		return ZEBRA_LLT_ARCNET;
	case ARPHRD_APPLETLK:
		return ZEBRA_LLT_APPLETLK;
	case ARPHRD_DLCI:
		return ZEBRA_LLT_DLCI;
	case ARPHRD_ATM:
		return ZEBRA_LLT_ATM;
	case ARPHRD_METRICOM:
		return ZEBRA_LLT_METRICOM;
	case ARPHRD_IEEE1394:
		return ZEBRA_LLT_IEEE1394;
	case ARPHRD_EUI64:
		return ZEBRA_LLT_EUI64;
	case ARPHRD_INFINIBAND:
		return ZEBRA_LLT_INFINIBAND;
	case ARPHRD_SLIP:
		return ZEBRA_LLT_SLIP;
	case ARPHRD_CSLIP:
		return ZEBRA_LLT_CSLIP;
	case ARPHRD_SLIP6:
		return ZEBRA_LLT_SLIP6;
	case ARPHRD_CSLIP6:
		return ZEBRA_LLT_CSLIP6;
	case ARPHRD_RSRVD:
		return ZEBRA_LLT_RSRVD;
	case ARPHRD_ADAPT:
		return ZEBRA_LLT_ADAPT;
	case ARPHRD_ROSE:
		return ZEBRA_LLT_ROSE;
	case ARPHRD_X25:
		return ZEBRA_LLT_X25;
	case ARPHRD_PPP:
		return ZEBRA_LLT_PPP;
	case ARPHRD_CISCO:
		return ZEBRA_LLT_CHDLC;
	case ARPHRD_LAPB:
		return ZEBRA_LLT_LAPB;
	case ARPHRD_RAWHDLC:
		return ZEBRA_LLT_RAWHDLC;
	case ARPHRD_TUNNEL:
		return ZEBRA_LLT_IPIP;
	case ARPHRD_TUNNEL6:
		return ZEBRA_LLT_IPIP6;
	case ARPHRD_FRAD:
		return ZEBRA_LLT_FRAD;
	case ARPHRD_SKIP:
		return ZEBRA_LLT_SKIP;
	case ARPHRD_LOOPBACK:
		return ZEBRA_LLT_LOOPBACK;
	case ARPHRD_LOCALTLK:
		return ZEBRA_LLT_LOCALTLK;
	case ARPHRD_FDDI:
		return ZEBRA_LLT_FDDI;
	case ARPHRD_SIT:
		return ZEBRA_LLT_SIT;
	case ARPHRD_IPDDP:
		return ZEBRA_LLT_IPDDP;
	case ARPHRD_IPGRE:
		return ZEBRA_LLT_IPGRE;
	case ARPHRD_PIMREG:
		return ZEBRA_LLT_PIMREG;
	case ARPHRD_HIPPI:
		return ZEBRA_LLT_HIPPI;
	case ARPHRD_ECONET:
		return ZEBRA_LLT_ECONET;
	case ARPHRD_IRDA:
		return ZEBRA_LLT_IRDA;
	case ARPHRD_FCPP:
		return ZEBRA_LLT_FCPP;
	case ARPHRD_FCAL:
		return ZEBRA_LLT_FCAL;
	case ARPHRD_FCPL:
		return ZEBRA_LLT_FCPL;
	case ARPHRD_FCFABRIC:
		return ZEBRA_LLT_FCFABRIC;
	case ARPHRD_IEEE802_TR:
		return ZEBRA_LLT_IEEE802_TR;
	case ARPHRD_IEEE80211:
		return ZEBRA_LLT_IEEE80211;
#ifdef ARPHRD_IEEE802154
	case ARPHRD_IEEE802154:
		return ZEBRA_LLT_IEEE802154;
#endif
#ifdef ARPHRD_IP6GRE
	case ARPHRD_IP6GRE:
		return ZEBRA_LLT_IP6GRE;
#endif
#ifdef ARPHRD_IEEE802154_PHY
	case ARPHRD_IEEE802154_PHY:
		return ZEBRA_LLT_IEEE802154_PHY;
#endif

	default:
		return ZEBRA_LLT_UNKNOWN;
	}
}

static inline void zebra_if_set_ziftype(struct interface *ifp,
					zebra_iftype_t zif_type,
					zebra_slave_iftype_t zif_slave_type)
{
	struct zebra_if *zif;

	zif = (struct zebra_if *)ifp->info;
	zif->zif_slave_type = zif_slave_type;

	if (zif->zif_type != zif_type) {
		zif->zif_type = zif_type;
		/* If the if_type has been set to bond initialize ES info
		 * against it. XXX - note that we don't handle the case where
		 * a zif changes from bond to non-bond; it is really
		 * an unexpected/error condition.
		 */
		zebra_evpn_if_init(zif);
	}
}

static void netlink_determine_zebra_iftype(const char *kind,
					   zebra_iftype_t *zif_type)
{
	*zif_type = ZEBRA_IF_OTHER;

	if (!kind)
		return;

	if (strcmp(kind, "vrf") == 0)
		*zif_type = ZEBRA_IF_VRF;
	else if (strcmp(kind, "bridge") == 0)
		*zif_type = ZEBRA_IF_BRIDGE;
	else if (strcmp(kind, "vlan") == 0)
		*zif_type = ZEBRA_IF_VLAN;
	else if (strcmp(kind, "vxlan") == 0)
		*zif_type = ZEBRA_IF_VXLAN;
	else if (strcmp(kind, "macvlan") == 0)
		*zif_type = ZEBRA_IF_MACVLAN;
	else if (strcmp(kind, "veth") == 0)
		*zif_type = ZEBRA_IF_VETH;
	else if (strcmp(kind, "bond") == 0)
		*zif_type = ZEBRA_IF_BOND;
	else if (strcmp(kind, "bond_slave") == 0)
		*zif_type = ZEBRA_IF_BOND_SLAVE;
}

#define parse_rtattr_nested(tb, max, rta)                                      \
	netlink_parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta))

static void netlink_vrf_change(struct nlmsghdr *h, struct rtattr *tb,
			       uint32_t ns_id, const char *name)
{
	struct ifinfomsg *ifi;
	struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
	struct rtattr *attr[IFLA_VRF_MAX + 1];
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	uint32_t nl_table_id;

	ifi = NLMSG_DATA(h);

	memset(linkinfo, 0, sizeof(linkinfo));
	parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb);

	if (!linkinfo[IFLA_INFO_DATA]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: IFLA_INFO_DATA missing from VRF message: %s",
				__func__, name);
		return;
	}

	memset(attr, 0, sizeof(attr));
	parse_rtattr_nested(attr, IFLA_VRF_MAX, linkinfo[IFLA_INFO_DATA]);
	if (!attr[IFLA_VRF_TABLE]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: IFLA_VRF_TABLE missing from VRF message: %s",
				__func__, name);
		return;
	}

	nl_table_id = *(uint32_t *)RTA_DATA(attr[IFLA_VRF_TABLE]);

	if (h->nlmsg_type == RTM_NEWLINK) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("RTM_NEWLINK for VRF %s(%u) table %u", name,
				   ifi->ifi_index, nl_table_id);

		if (!vrf_lookup_by_id((vrf_id_t)ifi->ifi_index)) {
			vrf_id_t exist_id;

			exist_id = vrf_lookup_by_table(nl_table_id, ns_id);
			if (exist_id != VRF_DEFAULT) {
				vrf = vrf_lookup_by_id(exist_id);

				flog_err(
					EC_ZEBRA_VRF_MISCONFIGURED,
					"VRF %s id %u table id overlaps existing vrf %s, misconfiguration exiting",
					name, ifi->ifi_index, vrf->name);
				exit(-1);
			}
		}

		/*
		 * vrf_get is implied creation if it does not exist
		 */
		vrf = vrf_get((vrf_id_t)ifi->ifi_index,
			      name); // It would create vrf
		if (!vrf) {
			flog_err(EC_LIB_INTERFACE, "VRF %s id %u not created",
				 name, ifi->ifi_index);
			return;
		}

		/*
		 * This is the only place that we get the actual kernel table_id
		 * being used.  We need it to set the table_id of the routes
		 * we are passing to the kernel.... And to throw some totally
		 * awesome parties. that too.
		 *
		 * At this point we *must* have a zvrf because the vrf_create
		 * callback creates one.  We *must* set the table id
		 * before the vrf_enable because of( at the very least )
		 * static routes being delayed for installation until
		 * during the vrf_enable callbacks.
		 */
		zvrf = (struct zebra_vrf *)vrf->info;
		zvrf->table_id = nl_table_id;

		/* Enable the created VRF. */
		if (!vrf_enable(vrf)) {
			flog_err(EC_LIB_INTERFACE,
				 "Failed to enable VRF %s id %u", name,
				 ifi->ifi_index);
			return;
		}

	} else // h->nlmsg_type == RTM_DELLINK
	{
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("RTM_DELLINK for VRF %s(%u)", name,
				   ifi->ifi_index);

		vrf = vrf_lookup_by_id((vrf_id_t)ifi->ifi_index);

		if (!vrf) {
			flog_warn(EC_ZEBRA_VRF_NOT_FOUND, "%s: vrf not found",
				  __func__);
			return;
		}

		vrf_delete(vrf);
	}
}

static uint32_t get_iflink_speed(struct interface *interface, int *error)
{
	struct ifreq ifdata;
	struct ethtool_cmd ecmd;
	int sd;
	int rc;
	const char *ifname = interface->name;

	if (error)
		*error = 0;
	/* initialize struct */
	memset(&ifdata, 0, sizeof(ifdata));

	/* set interface name */
	strlcpy(ifdata.ifr_name, ifname, sizeof(ifdata.ifr_name));

	/* initialize ethtool interface */
	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.cmd = ETHTOOL_GSET; /* ETHTOOL_GLINK */
	ifdata.ifr_data = (caddr_t)&ecmd;

	/* use ioctl to get IP address of an interface */
	frr_with_privs(&zserv_privs) {
		sd = vrf_socket(PF_INET, SOCK_DGRAM, IPPROTO_IP,
				interface->vrf_id,
				NULL);
		if (sd < 0) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("Failure to read interface %s speed: %d %s",
					   ifname, errno, safe_strerror(errno));
			/* no vrf socket creation may probably mean vrf issue */
			if (error)
				*error = -1;
			return 0;
		}
	/* Get the current link state for the interface */
		rc = vrf_ioctl(interface->vrf_id, sd, SIOCETHTOOL,
			       (char *)&ifdata);
	}
	if (rc < 0) {
		if (errno != EOPNOTSUPP && IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"IOCTL failure to read interface %s speed: %d %s",
				ifname, errno, safe_strerror(errno));
		/* no device means interface unreachable */
		if (errno == ENODEV && error)
			*error = -1;
		ecmd.speed_hi = 0;
		ecmd.speed = 0;
	}

	close(sd);

	return ((uint32_t)ecmd.speed_hi << 16) | ecmd.speed;
}

uint32_t kernel_get_speed(struct interface *ifp, int *error)
{
	return get_iflink_speed(ifp, error);
}

static int netlink_extract_bridge_info(struct rtattr *link_data,
				       struct zebra_l2info_bridge *bridge_info)
{
	struct rtattr *attr[IFLA_BR_MAX + 1];

	memset(bridge_info, 0, sizeof(*bridge_info));
	memset(attr, 0, sizeof(attr));
	parse_rtattr_nested(attr, IFLA_BR_MAX, link_data);
	if (attr[IFLA_BR_VLAN_FILTERING])
		bridge_info->bridge.vlan_aware =
			*(uint8_t *)RTA_DATA(attr[IFLA_BR_VLAN_FILTERING]);
	return 0;
}

static int netlink_extract_vlan_info(struct rtattr *link_data,
				     struct zebra_l2info_vlan *vlan_info)
{
	struct rtattr *attr[IFLA_VLAN_MAX + 1];
	vlanid_t vid_in_msg;

	memset(vlan_info, 0, sizeof(*vlan_info));
	memset(attr, 0, sizeof(attr));
	parse_rtattr_nested(attr, IFLA_VLAN_MAX, link_data);
	if (!attr[IFLA_VLAN_ID]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("IFLA_VLAN_ID missing from VLAN IF message");
		return -1;
	}

	vid_in_msg = *(vlanid_t *)RTA_DATA(attr[IFLA_VLAN_ID]);
	vlan_info->vid = vid_in_msg;
	return 0;
}

static int netlink_extract_vxlan_info(struct rtattr *link_data,
				      struct zebra_l2info_vxlan *vxl_info)
{
	uint8_t svd = 0;
	struct rtattr *attr[IFLA_VXLAN_MAX + 1];
	vni_t vni_in_msg;
	struct in_addr vtep_ip_in_msg;
	ifindex_t ifindex_link;

	memset(vxl_info, 0, sizeof(*vxl_info));
	memset(attr, 0, sizeof(attr));
	parse_rtattr_nested(attr, IFLA_VXLAN_MAX, link_data);

	if (attr[IFLA_VXLAN_COLLECT_METADATA]) {
		svd = *(uint8_t *)RTA_DATA(attr[IFLA_VXLAN_COLLECT_METADATA]);
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"IFLA_VXLAN_COLLECT_METADATA=%u in VXLAN IF message", svd);
	}

	if (!svd) {
		/* in case of svd we will not get vni info directly from the device */
		if (!attr[IFLA_VXLAN_ID]) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"IFLA_VXLAN_ID missing from VXLAN IF message");
			return -1;
		}

		vxl_info->vni_info.iftype = ZEBRA_VXLAN_IF_VNI;
		vni_in_msg = *(vni_t *)RTA_DATA(attr[IFLA_VXLAN_ID]);
		vxl_info->vni_info.vni.vni = vni_in_msg;
	} else {
		vxl_info->vni_info.iftype = ZEBRA_VXLAN_IF_SVD;
	}

	if (!attr[IFLA_VXLAN_LOCAL]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"IFLA_VXLAN_LOCAL missing from VXLAN IF message");
	} else {
		vtep_ip_in_msg =
			*(struct in_addr *)RTA_DATA(attr[IFLA_VXLAN_LOCAL]);
		vxl_info->vtep_ip = vtep_ip_in_msg;
	}

	if (attr[IFLA_VXLAN_GROUP]) {
		if (!svd)
			vxl_info->vni_info.vni.mcast_grp =
				*(struct in_addr *)RTA_DATA(attr[IFLA_VXLAN_GROUP]);
	}

	if (!attr[IFLA_VXLAN_LINK]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("IFLA_VXLAN_LINK missing from VXLAN IF message");
	} else {
		ifindex_link =
			*(ifindex_t *)RTA_DATA(attr[IFLA_VXLAN_LINK]);
		vxl_info->ifindex_link = ifindex_link;
	}
	return 0;
}

/*
 * Extract and save L2 params (of interest) for an interface. When a
 * bridge interface is added or updated, take further actions to map
 * its members. Likewise, for VxLAN interface.
 */
static void netlink_interface_update_l2info(struct interface *ifp,
					    struct rtattr *link_data, int add,
					    ns_id_t link_nsid)
{
	if (!link_data)
		return;

	if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		struct zebra_l2info_bridge bridge_info;

		netlink_extract_bridge_info(link_data, &bridge_info);
		zebra_l2_bridge_add_update(ifp, &bridge_info, add);
	} else if (IS_ZEBRA_IF_VLAN(ifp)) {
		struct zebra_l2info_vlan vlan_info;

		netlink_extract_vlan_info(link_data, &vlan_info);
		zebra_l2_vlanif_update(ifp, &vlan_info);
		zebra_evpn_acc_bd_svi_set(ifp->info, NULL,
					  !!if_is_operative(ifp));
	} else if (IS_ZEBRA_IF_VXLAN(ifp)) {
		struct zebra_l2info_vxlan vxlan_info;

		netlink_extract_vxlan_info(link_data, &vxlan_info);
		vxlan_info.link_nsid = link_nsid;
		zebra_l2_vxlanif_add_update(ifp, &vxlan_info, add);
		if (link_nsid != NS_UNKNOWN &&
		    vxlan_info.ifindex_link)
			zebra_if_update_link(ifp, vxlan_info.ifindex_link,
					     link_nsid);
	}
}

static int netlink_bridge_vxlan_vlan_vni_map_update(struct interface *ifp,
	struct rtattr *af_spec)
{
	int rem;
	vni_t vni_id;
	vlanid_t vid;
	uint16_t flags;
	struct rtattr *i;
	struct zebra_vxlan_vni vni;
	struct zebra_vxlan_vni *vnip;
	struct hash *vni_table = NULL;
	struct zebra_vxlan_vni vni_end;
	struct zebra_vxlan_vni vni_start;
	struct rtattr *aftb[IFLA_BRIDGE_VLAN_TUNNEL_MAX + 1];

	for (i = RTA_DATA(af_spec), rem = RTA_PAYLOAD(af_spec);
			RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {

		if (i->rta_type != IFLA_BRIDGE_VLAN_TUNNEL_INFO)
			continue;

		memset(aftb, 0, sizeof(aftb));
		parse_rtattr_nested(aftb, IFLA_BRIDGE_VLAN_TUNNEL_MAX, i);
		if (!aftb[IFLA_BRIDGE_VLAN_TUNNEL_ID] ||
			!aftb[IFLA_BRIDGE_VLAN_TUNNEL_VID])
			/* vlan-vni info missing */
			return 0;

		flags = 0;
		memset(&vni, 0, sizeof(vni));

		vni.vni = *(vni_t *)RTA_DATA(aftb[IFLA_BRIDGE_VLAN_TUNNEL_ID]);
		vni.access_vlan = *(vlanid_t *)RTA_DATA(aftb[IFLA_BRIDGE_VLAN_TUNNEL_VID]);

		if (aftb[IFLA_BRIDGE_VLAN_TUNNEL_FLAGS])
			flags = *(uint16_t *)RTA_DATA(aftb[IFLA_BRIDGE_VLAN_TUNNEL_FLAGS]);

		if (flags & BRIDGE_VLAN_INFO_RANGE_BEGIN) {
			vni_start = vni;
			continue;
		}

		if (flags & BRIDGE_VLAN_INFO_RANGE_END)
			vni_end = vni;

		if (!(flags & BRIDGE_VLAN_INFO_RANGE_END)) {
			vni_start = vni;
			vni_end = vni;
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("Vlan-Vni(%d:%d-%d:%d) update for VxLAN IF %s(%u)",
				vni_start.access_vlan, vni_end.access_vlan,
				vni_start.vni, vni_end.vni, ifp->name, ifp->ifindex);

		if (!vni_table) {
			vni_table = zebra_vxlan_vni_table_create();
			if (!vni_table)
				return 0;
		}

		for (vid = vni_start.access_vlan, vni_id = vni_start.vni;
			vid <= vni_end.access_vlan; vid++, vni_id++) {

			memset(&vni, 0, sizeof(vni));
			vni.vni = vni_id;
			vni.access_vlan = vid;
			vnip = hash_get(vni_table, &vni, zebra_vxlan_vni_alloc);
			if (!vnip)
				return 0;
		}

		memset(&vni_start, 0, sizeof(vni_start));
		memset(&vni_end, 0, sizeof(vni_end));
	}

	if (vni_table)
		zebra_vxlan_if_vni_table_add_update(ifp, vni_table);

	return 0;
}

static int netlink_bridge_vxlan_update(struct interface *ifp,
		struct rtattr *af_spec)
{
	struct rtattr *aftb[IFLA_BRIDGE_MAX + 1];
	struct bridge_vlan_info *vinfo;
	struct zebra_if *zif;
	vlanid_t access_vlan;

	zif = (struct zebra_if *)ifp->info;

	/* Single vxlan devices has vni-vlan range to update */
	if (IS_ZEBRA_VXLAN_IF_SVD(zif))
		return netlink_bridge_vxlan_vlan_vni_map_update(ifp, af_spec);

	/* There is a 1-to-1 mapping of VLAN to VxLAN - hence
	 * only 1 access VLAN is accepted.
	 */
	memset(aftb, 0, sizeof(aftb));
	parse_rtattr_nested(aftb, IFLA_BRIDGE_MAX, af_spec);
	if (!aftb[IFLA_BRIDGE_VLAN_INFO])
		return 0;

	vinfo = RTA_DATA(aftb[IFLA_BRIDGE_VLAN_INFO]);
	if (!(vinfo->flags & BRIDGE_VLAN_INFO_PVID))
		return 0;

	access_vlan = (vlanid_t)vinfo->vid;
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Access VLAN %u for VxLAN IF %s(%u)", access_vlan,
				ifp->name, ifp->ifindex);
	zebra_l2_vxlanif_update_access_vlan(ifp, access_vlan);
	return 0;
}

static void netlink_bridge_vlan_update(struct interface *ifp,
		struct rtattr *af_spec)
{
	struct rtattr *i;
	int rem;
	uint16_t vid_range_start = 0;
	struct zebra_if *zif;
	bitfield_t old_vlan_bitmap;
	struct bridge_vlan_info *vinfo;

	zif = (struct zebra_if *)ifp->info;

	/* cache the old bitmap addrs */
	old_vlan_bitmap = zif->vlan_bitmap;
	/* create a new bitmap space for re-eval */
	bf_init(zif->vlan_bitmap, IF_VLAN_BITMAP_MAX);
	zif->pvid = 0;

	for (i = RTA_DATA(af_spec), rem = RTA_PAYLOAD(af_spec);
			RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {

		if (i->rta_type != IFLA_BRIDGE_VLAN_INFO)
			continue;

		vinfo = RTA_DATA(i);

		if (vinfo->flags & BRIDGE_VLAN_INFO_PVID)
			zif->pvid = vinfo->vid;

		if (vinfo->flags & BRIDGE_VLAN_INFO_RANGE_BEGIN) {
			vid_range_start = vinfo->vid;
			continue;
		}

		if (!(vinfo->flags & BRIDGE_VLAN_INFO_RANGE_END))
			vid_range_start = vinfo->vid;

		zebra_vlan_bitmap_compute(ifp, vid_range_start, vinfo->vid);
	}

	zebra_vlan_mbr_re_eval(ifp, old_vlan_bitmap);

	bf_free(old_vlan_bitmap);
}

static int netlink_bridge_interface(struct nlmsghdr *h, int len, ns_id_t ns_id,
				    int startup)
{
	char *name = NULL;
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	struct interface *ifp;
	struct zebra_if *zif;
	struct rtattr *af_spec;

	/* Fetch name and ifindex */
	ifi = NLMSG_DATA(h);
	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	/* The interface should already be known, if not discard. */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), ifi->ifi_index);
	if (!ifp) {
		zlog_debug("Cannot find bridge IF %s(%u)", name,
			   ifi->ifi_index);
		return 0;
	}

	/* We are only interested in the access VLAN i.e., AF_SPEC */
	af_spec = tb[IFLA_AF_SPEC];
	if (!af_spec)
 		return 0;

	if (IS_ZEBRA_IF_VXLAN(ifp))
		return netlink_bridge_vxlan_update(ifp, af_spec);

	/* build vlan bitmap associated with this interface if that
	 * device type is interested in the vlans
	 */
	zif = (struct zebra_if *)ifp->info;
	if (bf_is_inited(zif->vlan_bitmap))
		netlink_bridge_vlan_update(ifp, af_spec);

	return 0;
}

static bool is_if_protodown_r_only_frr(uint32_t rc_bitfield)
{
	/* This shouldn't be possible */
	assert(frr_protodown_r_bit < 32);
	return (rc_bitfield == (((uint32_t)1) << frr_protodown_r_bit));
}

/*
 * Process interface protodown dplane update.
 *
 * If the interface is an es bond member then it must follow EVPN's
 * protodown setting.
 */
static void netlink_proc_dplane_if_protodown(struct zebra_if *zif,
					     struct rtattr **tb)
{
	bool protodown;
	bool old_protodown;
	uint32_t rc_bitfield = 0;
	struct rtattr *pd_reason_info[IFLA_MAX + 1];

	protodown = !!*(uint8_t *)RTA_DATA(tb[IFLA_PROTO_DOWN]);

	if (tb[IFLA_PROTO_DOWN_REASON]) {
		netlink_parse_rtattr_nested(pd_reason_info, IFLA_INFO_MAX,
					    tb[IFLA_PROTO_DOWN_REASON]);

		if (pd_reason_info[IFLA_PROTO_DOWN_REASON_VALUE])
			rc_bitfield = *(uint32_t *)RTA_DATA(
				pd_reason_info[IFLA_PROTO_DOWN_REASON_VALUE]);
	}

	/*
	 * Set our reason code to note it wasn't us.
	 * If the reason we got from the kernel is ONLY frr though, don't
	 * set it.
	 */
	if (protodown && is_if_protodown_r_only_frr(rc_bitfield) == false)
		zif->protodown_rc |= ZEBRA_PROTODOWN_EXTERNAL;
	else
		zif->protodown_rc &= ~ZEBRA_PROTODOWN_EXTERNAL;

	old_protodown = !!ZEBRA_IF_IS_PROTODOWN(zif);
	if (protodown == old_protodown)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES ||
			IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("interface %s dplane change, protodown %s",
				zif->ifp->name,
				protodown ? "on" : "off");

	if (protodown)
		zif->flags |= ZIF_FLAG_PROTODOWN;
	else
		zif->flags &= ~ZIF_FLAG_PROTODOWN;

	if (zebra_evpn_is_es_bond_member(zif->ifp)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"bond mbr %s re-instate protdown %s in the dplane",
				zif->ifp->name, old_protodown ? "on" : "off");

		if (old_protodown)
			zif->flags |= ZIF_FLAG_SET_PROTODOWN;
		else
			zif->flags |= ZIF_FLAG_UNSET_PROTODOWN;

		dplane_intf_update(zif->ifp);
	}
}

static uint8_t netlink_parse_lacp_bypass(struct rtattr **linkinfo)
{
	uint8_t bypass = 0;
	struct rtattr *mbrinfo[IFLA_BOND_SLAVE_MAX + 1];

	memset(mbrinfo, 0, sizeof(mbrinfo));
	parse_rtattr_nested(mbrinfo, IFLA_BOND_SLAVE_MAX,
			    linkinfo[IFLA_INFO_SLAVE_DATA]);
	if (mbrinfo[IFLA_BOND_SLAVE_AD_RX_BYPASS])
		bypass = *(uint8_t *)RTA_DATA(
			mbrinfo[IFLA_BOND_SLAVE_AD_RX_BYPASS]);

	return bypass;
}

/*
 * Only called at startup to cleanup leftover protodown we may have not cleanup
 */
static void if_sweep_protodown(struct zebra_if *zif)
{
	bool protodown;

	protodown = !!ZEBRA_IF_IS_PROTODOWN(zif);

	if (!protodown)
		return;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("interface %s sweeping protdown %s", zif->ifp->name,
			   protodown ? "on" : "off");

	/* Only clear our reason codes, leave external if it was set */
	zif->protodown_rc |= ~ZEBRA_PROTODOWN_ALL;
	zif->flags |= ZIF_FLAG_UNSET_PROTODOWN;
	dplane_intf_update(zif->ifp);
}

/*
 * Called from interface_lookup_netlink().  This function is only used
 * during bootstrap.
 */
static int netlink_interface(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtattr *linkinfo[IFLA_MAX + 1];
	struct interface *ifp;
	char *name = NULL;
	char *kind = NULL;
	char *desc = NULL;
	char *slave_kind = NULL;
	struct zebra_ns *zns = NULL;
	vrf_id_t vrf_id = VRF_DEFAULT;
	zebra_iftype_t zif_type = ZEBRA_IF_OTHER;
	zebra_slave_iftype_t zif_slave_type = ZEBRA_IF_SLAVE_NONE;
	ifindex_t bridge_ifindex = IFINDEX_INTERNAL;
	ifindex_t link_ifindex = IFINDEX_INTERNAL;
	ifindex_t bond_ifindex = IFINDEX_INTERNAL;
	struct zebra_if *zif;
	ns_id_t link_nsid = ns_id;
	uint8_t bypass = 0;

	zns = zebra_ns_lookup(ns_id);
	ifi = NLMSG_DATA(h);

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size: %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct ifinfomsg)));
		return -1;
	}

	/* We are interested in some AF_BRIDGE notifications. */
	if (ifi->ifi_family == AF_BRIDGE)
		return netlink_bridge_interface(h, len, ns_id, startup);

	/* Looking up interface name. */
	memset(tb, 0, sizeof(tb));
	memset(linkinfo, 0, sizeof(linkinfo));
	netlink_parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(ifi), len,
				   NLA_F_NESTED);

	/* check for wireless messages to ignore */
	if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0)) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: ignoring IFLA_WIRELESS message",
				   __func__);
		return 0;
	}

	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	if (tb[IFLA_IFALIAS])
		desc = (char *)RTA_DATA(tb[IFLA_IFALIAS]);

	if (tb[IFLA_LINKINFO]) {
		parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

		if (linkinfo[IFLA_INFO_KIND])
			kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);

		if (linkinfo[IFLA_INFO_SLAVE_KIND])
			slave_kind = RTA_DATA(linkinfo[IFLA_INFO_SLAVE_KIND]);

		if ((slave_kind != NULL) && strcmp(slave_kind, "bond") == 0)
			netlink_determine_zebra_iftype("bond_slave", &zif_type);
		else
			netlink_determine_zebra_iftype(kind, &zif_type);
	}

	/* If VRF, create the VRF structure itself. */
	if (zif_type == ZEBRA_IF_VRF && !vrf_is_backend_netns()) {
		netlink_vrf_change(h, tb[IFLA_LINKINFO], ns_id, name);
		vrf_id = (vrf_id_t)ifi->ifi_index;
	}

	if (tb[IFLA_MASTER]) {
		if (slave_kind && (strcmp(slave_kind, "vrf") == 0)
		    && !vrf_is_backend_netns()) {
			zif_slave_type = ZEBRA_IF_SLAVE_VRF;
			vrf_id = *(uint32_t *)RTA_DATA(tb[IFLA_MASTER]);
		} else if (slave_kind && (strcmp(slave_kind, "bridge") == 0)) {
			zif_slave_type = ZEBRA_IF_SLAVE_BRIDGE;
			bridge_ifindex =
				*(ifindex_t *)RTA_DATA(tb[IFLA_MASTER]);
		} else if (slave_kind && (strcmp(slave_kind, "bond") == 0)) {
			zif_slave_type = ZEBRA_IF_SLAVE_BOND;
			bond_ifindex = *(ifindex_t *)RTA_DATA(tb[IFLA_MASTER]);
			bypass = netlink_parse_lacp_bypass(linkinfo);
		} else
			zif_slave_type = ZEBRA_IF_SLAVE_OTHER;
	}
	if (vrf_is_backend_netns())
		vrf_id = (vrf_id_t)ns_id;

	/* If linking to another interface, note it. */
	if (tb[IFLA_LINK])
		link_ifindex = *(ifindex_t *)RTA_DATA(tb[IFLA_LINK]);

	if (tb[IFLA_LINK_NETNSID])
		link_nsid = *(ns_id_t *)RTA_DATA(tb[IFLA_LINK_NETNSID]);

	/* Add interface.
	 * We add by index first because in some cases such as the master
	 * interface, we have the index before we have the name. Fixing
	 * back references on the slave interfaces is painful if not done
	 * this way, i.e. by creating by ifindex.
	 */
	ifp = if_get_by_ifindex(ifi->ifi_index, vrf_id);
	set_ifindex(ifp, ifi->ifi_index, zns); /* add it to ns struct */

	if_set_name(ifp, name);

	ifp->flags = ifi->ifi_flags & 0x0000fffff;
	ifp->mtu6 = ifp->mtu = *(uint32_t *)RTA_DATA(tb[IFLA_MTU]);
	ifp->metric = 0;
	ifp->speed = get_iflink_speed(ifp, NULL);
	ifp->ptm_status = ZEBRA_PTM_STATUS_UNKNOWN;

	/* Set zebra interface type */
	zebra_if_set_ziftype(ifp, zif_type, zif_slave_type);
	if (IS_ZEBRA_IF_VRF(ifp))
		SET_FLAG(ifp->status, ZEBRA_INTERFACE_VRF_LOOPBACK);

	/*
	 * Just set the @link/lower-device ifindex. During nldump interfaces are
	 * not ordered in any fashion so we may end up getting upper devices
	 * before lower devices. We will setup the real linkage once the dump
	 * is complete.
	 */
	zif = (struct zebra_if *)ifp->info;
	zif->link_ifindex = link_ifindex;

	if (desc) {
		XFREE(MTYPE_TMP, zif->desc);
		zif->desc = XSTRDUP(MTYPE_TMP, desc);
	}

	/* Hardware type and address. */
	ifp->ll_type = netlink_to_zebra_link_type(ifi->ifi_type);
	netlink_interface_update_hw_addr(tb, ifp);

	if_add_update(ifp);

	/* Extract and save L2 interface information, take additional actions.
	 */
	netlink_interface_update_l2info(ifp, linkinfo[IFLA_INFO_DATA], 1,
					link_nsid);
	if (IS_ZEBRA_IF_BOND(ifp))
		zebra_l2if_update_bond(ifp, true);
	if (IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
		zebra_l2if_update_bridge_slave(ifp, bridge_ifindex);
	else if (IS_ZEBRA_IF_BOND_SLAVE(ifp))
		zebra_l2if_update_bond_slave(ifp, bond_ifindex, bypass);

	if (tb[IFLA_PROTO_DOWN]) {
		netlink_proc_dplane_if_protodown(zif, tb);
		if_sweep_protodown(zif);
	}

	return 0;
}

/* Request for specific interface or address information from the kernel */
static int netlink_request_intf_addr(struct nlsock *netlink_cmd, int family,
				     int type, uint32_t filter_mask)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifm;
		char buf[256];
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.ifm.ifi_family = family;

	/* Include filter, if specified. */
	if (filter_mask)
		nl_attr_put32(&req.n, sizeof(req), IFLA_EXT_MASK, filter_mask);

	return netlink_request(netlink_cmd, &req);
}

/* Interface lookup by netlink socket. */
int interface_lookup_netlink(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;
	struct nlsock *netlink_cmd = &zns->netlink_cmd;

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get interface information. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_PACKET, RTM_GETLINK, 0);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_interface, netlink_cmd, &dp_info, 0,
				 1);
	if (ret < 0)
		return ret;

	/* Get interface information - for bridge interfaces. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_BRIDGE, RTM_GETLINK,
					RTEXT_FILTER_BRVLAN);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_interface, netlink_cmd, &dp_info, 0,
				 0);
	if (ret < 0)
		return ret;

	/* Get interface information - for bridge interfaces. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_BRIDGE, RTM_GETLINK,
					RTEXT_FILTER_BRVLAN);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_interface, netlink_cmd, &dp_info, 0,
				 0);
	if (ret < 0)
		return ret;

	/* fixup linkages */
	zebra_if_update_all_links();
	return 0;
}

/**
 * interface_addr_lookup_netlink() - Look up interface addresses
 *
 * @zns:	Zebra netlink socket
 * Return:	Result status
 */
static int interface_addr_lookup_netlink(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;
	struct nlsock *netlink_cmd = &zns->netlink_cmd;

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get IPv4 address of the interfaces. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_INET, RTM_GETADDR, 0);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_interface_addr, netlink_cmd, &dp_info,
				 0, 1);
	if (ret < 0)
		return ret;

	/* Get IPv6 address of the interfaces. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_INET6, RTM_GETADDR, 0);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_interface_addr, netlink_cmd, &dp_info,
				 0, 1);
	if (ret < 0)
		return ret;

	return 0;
}

int kernel_interface_set_master(struct interface *master,
				struct interface *slave)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifa;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_SETLINK;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.ifa.ifi_index = slave->ifindex;

	nl_attr_put32(&req.n, sizeof(req), IFLA_MASTER, master->ifindex);
	nl_attr_put32(&req.n, sizeof(req), IFLA_LINK, slave->ifindex);

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

/* Interface address modification. */
static int netlink_address_ctx(const struct zebra_dplane_ctx *ctx)
{
	int bytelen;
	const struct prefix *p;
	int cmd;
	const char *label;

	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	p = dplane_ctx_get_intf_addr(ctx);
	memset(&req, 0, sizeof(req) - NL_PKT_BUF_SIZE);

	bytelen = (p->family == AF_INET ? 4 : 16);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_ADDR_INSTALL)
		cmd = RTM_NEWADDR;
	else
		cmd = RTM_DELADDR;

	req.n.nlmsg_type = cmd;
	req.ifa.ifa_family = p->family;

	req.ifa.ifa_index = dplane_ctx_get_ifindex(ctx);

	nl_attr_put(&req.n, sizeof(req), IFA_LOCAL, &p->u.prefix, bytelen);

	if (p->family == AF_INET) {
		if (dplane_ctx_intf_is_connected(ctx)) {
			p = dplane_ctx_get_intf_dest(ctx);
			nl_attr_put(&req.n, sizeof(req), IFA_ADDRESS,
				    &p->u.prefix, bytelen);
		} else if (cmd == RTM_NEWADDR) {
			struct in_addr broad = {
				.s_addr = ipv4_broadcast_addr(p->u.prefix4.s_addr,
							p->prefixlen)
			};
			nl_attr_put(&req.n, sizeof(req), IFA_BROADCAST, &broad,
				    bytelen);
		}
	}

	/* p is now either address or destination/bcast addr */
	req.ifa.ifa_prefixlen = p->prefixlen;

	if (dplane_ctx_intf_is_secondary(ctx))
		SET_FLAG(req.ifa.ifa_flags, IFA_F_SECONDARY);

	if (dplane_ctx_intf_has_label(ctx)) {
		label = dplane_ctx_get_intf_label(ctx);
		nl_attr_put(&req.n, sizeof(req), IFA_LABEL, label,
			    strlen(label) + 1);
	}

	return netlink_talk_info(netlink_talk_filter, &req.n,
				 dplane_ctx_get_ns(ctx), 0);
}

enum zebra_dplane_result kernel_address_update_ctx(struct zebra_dplane_ctx *ctx)
{
	return (netlink_address_ctx(ctx) == 0 ?
		ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE);
}

static ssize_t netlink_intf_msg_encoder(struct zebra_dplane_ctx *ctx, void *buf,
					size_t buflen)
{
	enum dplane_op_e op;
	int cmd = 0;

	op = dplane_ctx_get_op(ctx);

	switch (op) {
	case DPLANE_OP_INTF_UPDATE:
		cmd = RTM_SETLINK;
		break;
	case DPLANE_OP_INTF_INSTALL:
		cmd = RTM_NEWLINK;
		break;
	case DPLANE_OP_INTF_DELETE:
		cmd = RTM_DELLINK;
		break;
	default:
		flog_err(
			EC_ZEBRA_NHG_FIB_UPDATE,
			"Context received for kernel interface update with incorrect OP code (%u)",
			op);
		return -1;
	}

	return netlink_intf_msg_encode(cmd, ctx, buf, buflen);
}

int netlink_interface_addr(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	struct ifaddrmsg *ifa;
	struct rtattr *tb[IFA_MAX + 1];
	struct interface *ifp;
	void *addr;
	void *broad;
	uint8_t flags = 0;
	char *label = NULL;
	struct zebra_ns *zns;
	uint32_t metric = METRIC_MAX;
	uint32_t kernel_flags = 0;

	zns = zebra_ns_lookup(ns_id);
	ifa = NLMSG_DATA(h);

	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6) {
		flog_warn(
			EC_ZEBRA_UNKNOWN_FAMILY,
			"Invalid address family: %u received from kernel interface addr change: %s",
			ifa->ifa_family, nl_msg_type_to_str(h->nlmsg_type));
		return 0;
	}

	if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size: %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct ifaddrmsg)));
		return -1;
	}

	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	ifp = if_lookup_by_index_per_ns(zns, ifa->ifa_index);
	if (ifp == NULL) {
		flog_err(
			EC_LIB_INTERFACE,
			"netlink_interface_addr can't find interface by index %d",
			ifa->ifa_index);
		return -1;
	}

	/* Flags passed through */
	if (tb[IFA_FLAGS])
		kernel_flags = *(int *)RTA_DATA(tb[IFA_FLAGS]);
	else
		kernel_flags = ifa->ifa_flags;

	if (IS_ZEBRA_DEBUG_KERNEL) /* remove this line to see initial ifcfg */
	{
		char buf[BUFSIZ];
		zlog_debug("netlink_interface_addr %s %s flags 0x%x:",
			   nl_msg_type_to_str(h->nlmsg_type), ifp->name,
			   kernel_flags);
		if (tb[IFA_LOCAL])
			zlog_debug("  IFA_LOCAL     %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_LOCAL]), buf,
					     BUFSIZ),
				   ifa->ifa_prefixlen);
		if (tb[IFA_ADDRESS])
			zlog_debug("  IFA_ADDRESS   %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_ADDRESS]), buf,
					     BUFSIZ),
				   ifa->ifa_prefixlen);
		if (tb[IFA_BROADCAST])
			zlog_debug("  IFA_BROADCAST %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_BROADCAST]), buf,
					     BUFSIZ),
				   ifa->ifa_prefixlen);
		if (tb[IFA_LABEL] && strcmp(ifp->name, RTA_DATA(tb[IFA_LABEL])))
			zlog_debug("  IFA_LABEL     %s",
				   (char *)RTA_DATA(tb[IFA_LABEL]));

		if (tb[IFA_CACHEINFO]) {
			struct ifa_cacheinfo *ci = RTA_DATA(tb[IFA_CACHEINFO]);
			zlog_debug("  IFA_CACHEINFO pref %d, valid %d",
				   ci->ifa_prefered, ci->ifa_valid);
		}
	}

	/* logic copied from iproute2/ip/ipaddress.c:print_addrinfo() */
	if (tb[IFA_LOCAL] == NULL)
		tb[IFA_LOCAL] = tb[IFA_ADDRESS];
	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	/* local interface address */
	addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

	/* is there a peer address? */
	if (tb[IFA_ADDRESS]
	    && memcmp(RTA_DATA(tb[IFA_ADDRESS]), RTA_DATA(tb[IFA_LOCAL]),
		      RTA_PAYLOAD(tb[IFA_ADDRESS]))) {
		broad = RTA_DATA(tb[IFA_ADDRESS]);
		SET_FLAG(flags, ZEBRA_IFA_PEER);
	} else
		/* seeking a broadcast address */
		broad = (tb[IFA_BROADCAST] ? RTA_DATA(tb[IFA_BROADCAST])
					   : NULL);

	/* addr is primary key, SOL if we don't have one */
	if (addr == NULL) {
		zlog_debug("%s: Local Interface Address is NULL for %s",
			   __func__, ifp->name);
		return -1;
	}

	/* Flags. */
	if (kernel_flags & IFA_F_SECONDARY)
		SET_FLAG(flags, ZEBRA_IFA_SECONDARY);

	/* Label */
	if (tb[IFA_LABEL])
		label = (char *)RTA_DATA(tb[IFA_LABEL]);

	if (label && strcmp(ifp->name, label) == 0)
		label = NULL;

	if (tb[IFA_RT_PRIORITY])
		metric = *(uint32_t *)RTA_DATA(tb[IFA_RT_PRIORITY]);

	/* Register interface address to the interface. */
	if (ifa->ifa_family == AF_INET) {
		if (ifa->ifa_prefixlen > IPV4_MAX_BITLEN) {
			zlog_err(
				"Invalid prefix length: %u received from kernel interface addr change: %s",
				ifa->ifa_prefixlen,
				nl_msg_type_to_str(h->nlmsg_type));
			return -1;
		}

		if (h->nlmsg_type == RTM_NEWADDR)
			connected_add_ipv4(ifp, flags, (struct in_addr *)addr,
					   ifa->ifa_prefixlen,
					   (struct in_addr *)broad, label,
					   metric);
		else if (CHECK_FLAG(flags, ZEBRA_IFA_PEER)) {
			/* Delete with a peer address */
			connected_delete_ipv4(
				ifp, flags, (struct in_addr *)addr,
				ifa->ifa_prefixlen, broad);
		} else
			connected_delete_ipv4(
				ifp, flags, (struct in_addr *)addr,
				ifa->ifa_prefixlen, NULL);
	}

	if (ifa->ifa_family == AF_INET6) {
		if (ifa->ifa_prefixlen > IPV6_MAX_BITLEN) {
			zlog_err(
				"Invalid prefix length: %u received from kernel interface addr change: %s",
				ifa->ifa_prefixlen,
				nl_msg_type_to_str(h->nlmsg_type));
			return -1;
		}
		if (h->nlmsg_type == RTM_NEWADDR) {
			/* Only consider valid addresses; we'll not get a
			 * notification from
			 * the kernel till IPv6 DAD has completed, but at init
			 * time, Quagga
			 * does query for and will receive all addresses.
			 */
			if (!(kernel_flags
			      & (IFA_F_DADFAILED | IFA_F_TENTATIVE)))
				connected_add_ipv6(ifp, flags,
						   (struct in6_addr *)addr,
						   (struct in6_addr *)broad,
						   ifa->ifa_prefixlen, label,
						   metric);
		} else
			connected_delete_ipv6(ifp, (struct in6_addr *)addr,
					      NULL, ifa->ifa_prefixlen);
	}


	/*
	 * Linux kernel does not send route delete on interface down/addr del
	 * so we have to re-process routes it owns (i.e. kernel routes)
	 */
	if (h->nlmsg_type != RTM_NEWADDR)
		rib_update(RIB_UPDATE_KERNEL);

	return 0;
}

int netlink_link_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtattr *linkinfo[IFLA_MAX + 1];
	struct interface *ifp;
	char *name = NULL;
	char *kind = NULL;
	char *desc = NULL;
	char *slave_kind = NULL;
	struct zebra_ns *zns;
	vrf_id_t vrf_id = VRF_DEFAULT;
	zebra_iftype_t zif_type = ZEBRA_IF_OTHER;
	zebra_slave_iftype_t zif_slave_type = ZEBRA_IF_SLAVE_NONE;
	ifindex_t bridge_ifindex = IFINDEX_INTERNAL;
	ifindex_t bond_ifindex = IFINDEX_INTERNAL;
	ifindex_t link_ifindex = IFINDEX_INTERNAL;
	uint8_t old_hw_addr[INTERFACE_HWADDR_MAX];
	struct zebra_if *zif;
	ifindex_t master_infindex = IFINDEX_INTERNAL;
	ns_id_t link_nsid = ns_id;
	uint8_t bypass = 0;

	zns = zebra_ns_lookup(ns_id);
	ifi = NLMSG_DATA(h);

	/* assume if not default zns, then new VRF */
	if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK)) {
		/* If this is not link add/delete message so print warning. */
		zlog_debug("netlink_link_change: wrong kernel message %s",
			   nl_msg_type_to_str(h->nlmsg_type));
		return 0;
	}

	if (!(ifi->ifi_family == AF_UNSPEC || ifi->ifi_family == AF_BRIDGE
	      || ifi->ifi_family == AF_INET6)) {
		flog_warn(
			EC_ZEBRA_UNKNOWN_FAMILY,
			"Invalid address family: %u received from kernel link change: %s",
			ifi->ifi_family, nl_msg_type_to_str(h->nlmsg_type));
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct ifinfomsg)));
		return -1;
	}

	/* We are interested in some AF_BRIDGE notifications. */
	if (ifi->ifi_family == AF_BRIDGE)
		return netlink_bridge_interface(h, len, ns_id, startup);

	/* Looking up interface name. */
	memset(tb, 0, sizeof(tb));
	memset(linkinfo, 0, sizeof(linkinfo));
	netlink_parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(ifi), len,
				   NLA_F_NESTED);

	/* check for wireless messages to ignore */
	if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0)) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: ignoring IFLA_WIRELESS message",
				   __func__);
		return 0;
	}

	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	if (tb[IFLA_LINKINFO]) {
		parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

		if (linkinfo[IFLA_INFO_KIND])
			kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);

		if (linkinfo[IFLA_INFO_SLAVE_KIND])
			slave_kind = RTA_DATA(linkinfo[IFLA_INFO_SLAVE_KIND]);

		netlink_determine_zebra_iftype(kind, &zif_type);
	}

	/* If linking to another interface, note it. */
	if (tb[IFLA_LINK])
		link_ifindex = *(ifindex_t *)RTA_DATA(tb[IFLA_LINK]);

	if (tb[IFLA_LINK_NETNSID])
		link_nsid = *(ns_id_t *)RTA_DATA(tb[IFLA_LINK_NETNSID]);

	if (tb[IFLA_IFALIAS]) {
		desc = (char *)RTA_DATA(tb[IFLA_IFALIAS]);
	}

	/* If VRF, create or update the VRF structure itself. */
	if (zif_type == ZEBRA_IF_VRF && !vrf_is_backend_netns()) {
		netlink_vrf_change(h, tb[IFLA_LINKINFO], ns_id, name);
		vrf_id = (vrf_id_t)ifi->ifi_index;
	}

	/* See if interface is present. */
	ifp = if_lookup_by_name_per_ns(zns, name);

	if (h->nlmsg_type == RTM_NEWLINK) {
		if (tb[IFLA_MASTER]) {
			if (slave_kind && (strcmp(slave_kind, "vrf") == 0)
			    && !vrf_is_backend_netns()) {
				zif_slave_type = ZEBRA_IF_SLAVE_VRF;
				master_infindex = vrf_id =
					*(uint32_t *)RTA_DATA(tb[IFLA_MASTER]);
			} else if (slave_kind
				   && (strcmp(slave_kind, "bridge") == 0)) {
				zif_slave_type = ZEBRA_IF_SLAVE_BRIDGE;
				master_infindex = bridge_ifindex =
					*(ifindex_t *)RTA_DATA(tb[IFLA_MASTER]);
			} else if (slave_kind
				   && (strcmp(slave_kind, "bond") == 0)) {
				zif_slave_type = ZEBRA_IF_SLAVE_BOND;
				master_infindex = bond_ifindex =
					*(ifindex_t *)RTA_DATA(tb[IFLA_MASTER]);
				bypass = netlink_parse_lacp_bypass(linkinfo);
			} else
				zif_slave_type = ZEBRA_IF_SLAVE_OTHER;
		}
		if (vrf_is_backend_netns())
			vrf_id = (vrf_id_t)ns_id;
		if (ifp == NULL
		    || !CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
			/* Add interface notification from kernel */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"RTM_NEWLINK ADD for %s(%u) vrf_id %u type %d sl_type %d master %u flags 0x%x",
					name, ifi->ifi_index, vrf_id, zif_type,
					zif_slave_type, master_infindex,
					ifi->ifi_flags);

			if (ifp == NULL) {
				/* unknown interface */
				ifp = if_get_by_name(name, vrf_id);
			} else {
				/* pre-configured interface, learnt now */
				if (ifp->vrf_id != vrf_id)
					if_update_to_new_vrf(ifp, vrf_id);
			}

			/* Update interface information. */
			set_ifindex(ifp, ifi->ifi_index, zns);
			ifp->flags = ifi->ifi_flags & 0x0000fffff;
			if (!tb[IFLA_MTU]) {
				zlog_debug(
					"RTM_NEWLINK for interface %s(%u) without MTU set",
					name, ifi->ifi_index);
				return 0;
			}
			ifp->mtu6 = ifp->mtu = *(int *)RTA_DATA(tb[IFLA_MTU]);
			ifp->metric = 0;
			ifp->ptm_status = ZEBRA_PTM_STATUS_UNKNOWN;

			/* Set interface type */
			zebra_if_set_ziftype(ifp, zif_type, zif_slave_type);
			if (IS_ZEBRA_IF_VRF(ifp))
				SET_FLAG(ifp->status,
					 ZEBRA_INTERFACE_VRF_LOOPBACK);

			/* Update link. */
			zebra_if_update_link(ifp, link_ifindex, ns_id);

			ifp->ll_type =
				netlink_to_zebra_link_type(ifi->ifi_type);
			netlink_interface_update_hw_addr(tb, ifp);

			/* Inform clients, install any configured addresses. */
			if_add_update(ifp);

			/* Extract and save L2 interface information, take
			 * additional actions. */
			netlink_interface_update_l2info(
				ifp, linkinfo[IFLA_INFO_DATA],
				1, link_nsid);
			if (IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
				zebra_l2if_update_bridge_slave(ifp,
							       bridge_ifindex);
			else if (IS_ZEBRA_IF_BOND_SLAVE(ifp))
				zebra_l2if_update_bond_slave(ifp, bond_ifindex,
							     bypass);


			/* TEMPORARY, for debugging */
			if (IS_ZEBRA_IF_BRIDGE(ifp)) {
				zif = ifp->info;
				if (IS_ZEBRA_DEBUG_KERNEL)
					zlog_debug(
						"RTM_NEWLINK ADD for %s(%u), vlan-aware %d",
						name, ifp->ifindex,
						IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif));
			}

			if (tb[IFLA_PROTO_DOWN])
				netlink_proc_dplane_if_protodown(ifp->info, tb);

		} else if (ifp->vrf_id != vrf_id) {
			/* VRF change for an interface. */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"RTM_NEWLINK vrf-change for %s(%u) vrf_id %u -> %u flags 0x%x",
					name, ifp->ifindex, ifp->vrf_id, vrf_id,
					ifi->ifi_flags);

			if_handle_vrf_change(ifp, vrf_id);
		} else {
			bool was_bridge_slave, was_bond_slave;
			zif = ifp->info;

			/* Interface update. */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"RTM_NEWLINK update for %s(%u) sl_type %d master %u flags 0x%x",
					name, ifp->ifindex, zif_slave_type,
					master_infindex, ifi->ifi_flags);

			set_ifindex(ifp, ifi->ifi_index, zns);
			if (!tb[IFLA_MTU]) {
				zlog_debug(
					"RTM_NEWLINK for interface %s(%u) without MTU set",
					name, ifi->ifi_index);
				return 0;
			}
			ifp->mtu6 = ifp->mtu = *(int *)RTA_DATA(tb[IFLA_MTU]);
			ifp->metric = 0;

			/* Update interface type - NOTE: Only slave_type can
			 * change. */
			was_bridge_slave = IS_ZEBRA_IF_BRIDGE_SLAVE(ifp);
			was_bond_slave = IS_ZEBRA_IF_BOND_SLAVE(ifp);
			zebra_if_set_ziftype(ifp, zif_type, zif_slave_type);

			memcpy(old_hw_addr, ifp->hw_addr, INTERFACE_HWADDR_MAX);

			ifp->ll_type =
				netlink_to_zebra_link_type(ifi->ifi_type);
			netlink_interface_update_hw_addr(tb, ifp);

			if (tb[IFLA_PROTO_DOWN])
				netlink_proc_dplane_if_protodown(zif, tb);

			if (if_is_no_ptm_operative(ifp)) {
				bool is_up = if_is_operative(ifp);
				ifp->flags = ifi->ifi_flags & 0x0000fffff;
				if (!if_is_no_ptm_operative(ifp)
				    || CHECK_FLAG(zif->flags,
						  ZIF_FLAG_PROTODOWN)) {
					if (IS_ZEBRA_DEBUG_KERNEL)
						zlog_debug(
							"Intf %s(%u) has gone DOWN",
							name, ifp->ifindex);
					if_down(ifp);
					rib_update(RIB_UPDATE_KERNEL);
				} else if (if_is_operative(ifp)) {
					/* Must notify client daemons of new
					 * interface status. */
					if (IS_ZEBRA_DEBUG_KERNEL)
						zlog_debug(
							"Intf %s(%u) PTM up, notifying clients",
							name, ifp->ifindex);
					if_up(ifp, !is_up);

					/* Update EVPN VNI when SVI MAC change
					 */
					if (IS_ZEBRA_IF_VLAN(ifp) &&
					    memcmp(old_hw_addr, ifp->hw_addr,
						   INTERFACE_HWADDR_MAX)) {
						struct interface *link_if;

						link_if =
						if_lookup_by_index_per_ns(
						zebra_ns_lookup(NS_DEFAULT),
								link_ifindex);
						if (link_if)
							zebra_vxlan_svi_up(ifp,
								link_if);
					}
				}
			} else {
				ifp->flags = ifi->ifi_flags & 0x0000fffff;
				if (if_is_operative(ifp)
				    && !CHECK_FLAG(zif->flags,
						   ZIF_FLAG_PROTODOWN)) {
					if (IS_ZEBRA_DEBUG_KERNEL)
						zlog_debug(
							"Intf %s(%u) has come UP",
							name, ifp->ifindex);
					if_up(ifp, true);
				} else {
					if (IS_ZEBRA_DEBUG_KERNEL)
						zlog_debug(
							"Intf %s(%u) has gone DOWN",
							name, ifp->ifindex);
					if_down(ifp);
					rib_update(RIB_UPDATE_KERNEL);
				}
			}

			/* Extract and save L2 interface information, take
			 * additional actions. */
			netlink_interface_update_l2info(
				ifp, linkinfo[IFLA_INFO_DATA], 0, link_nsid);
			if (IS_ZEBRA_IF_BOND(ifp))
				zebra_l2if_update_bond(ifp, true);
			if (IS_ZEBRA_IF_BRIDGE_SLAVE(ifp) || was_bridge_slave)
				zebra_l2if_update_bridge_slave(ifp,
							       bridge_ifindex);
			else if (IS_ZEBRA_IF_BOND_SLAVE(ifp) || was_bond_slave)
				zebra_l2if_update_bond_slave(ifp, bond_ifindex,
							     bypass);

			/* TEMPORARY, for debugging */
			if (IS_ZEBRA_IF_BRIDGE(ifp)) {
				if (IS_ZEBRA_DEBUG_KERNEL)
					zlog_debug(
						"RTM_NEWLINK update for %s(%u), vlan-aware %d",
						name, ifp->ifindex,
						IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif));
			}

			if (tb[IFLA_PROTO_DOWN])
				netlink_proc_dplane_if_protodown(ifp->info, tb);
		}

		zif = ifp->info;
		if (zif) {
			XFREE(MTYPE_TMP, zif->desc);
			if (desc)
				zif->desc = XSTRDUP(MTYPE_TMP, desc);
		}
	} else {
		/* Delete interface notification from kernel */
		if (ifp == NULL) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"RTM_DELLINK for unknown interface %s(%u)",
					name, ifi->ifi_index);
			return 0;
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("RTM_DELLINK for %s(%u)", name,
				   ifp->ifindex);

		UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_VRF_LOOPBACK);

		if (IS_ZEBRA_IF_BOND(ifp))
			zebra_l2if_update_bond(ifp, false);
		if (IS_ZEBRA_IF_BOND_SLAVE(ifp))
			zebra_l2if_update_bond_slave(ifp, bond_ifindex, false);
		/* Special handling for bridge or VxLAN interfaces. */
		if (IS_ZEBRA_IF_BRIDGE(ifp)) {
			zebra_l2_bridge_del(ifp);
		} else {
			if (IS_ZEBRA_IF_VXLAN(ifp))
				zebra_l2_vxlanif_del(ifp);
			else
				zebra_evpn_arp_nd_if_update(ifp->info, false);
		}

		if_delete_update(ifp);
	}

	return 0;
}

int netlink_grat_flood_set(struct interface *ifp, uint8_t on)
{
	struct rtattr *linkinfo;
	struct rtattr *data;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifa;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.ifa.ifi_index = ifp->ifindex;
	req.ifa.ifi_family = AF_UNSPEC;

	linkinfo = nl_attr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	if (!linkinfo)
		return -1;

	nl_attr_put(&req.n, sizeof(req), IFLA_INFO_KIND, "bridge",
		    strlen("bridge"));

	data = nl_attr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
	if (!data)
		return -1;

	nl_attr_put(&req.n, sizeof(req), IFLA_BR_NEIGH_GRAT_FLOOD, &on,
		    sizeof(on));

	nl_attr_nest_end(&req.n, data);

	nl_attr_nest_end(&req.n, linkinfo);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Set ifp %s IFLA_BR_NEIGH_GRAT_FLOOD (%u) %u",
			   ifp->name, IFLA_BR_NEIGH_GRAT_FLOOD, on);

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

/**
 * Interface encoding helper function.
 *
 * \param[in] cmd netlink command.
 * \param[in] ctx dataplane context (information snapshot).
 * \param[out] buf buffer to hold the packet.
 * \param[in] buflen amount of buffer bytes.
 */

ssize_t netlink_intf_msg_encode(uint16_t cmd,
				const struct zebra_dplane_ctx *ctx, void *buf,
				size_t buflen)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifa;
		char buf[];
	} *req = buf;

	struct rtattr *nest_protodown_reason;
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	bool down = dplane_ctx_intf_is_protodown(ctx);

	if (buflen < sizeof(*req))
		return 0;

	memset(req, 0, sizeof(*req));

	if (cmd != RTM_SETLINK)
		flog_err(
			EC_ZEBRA_INTF_UPDATE_FAILURE,
			"Only RTM_SETLINK message type currently supported in dplane pthread");

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_flags = NLM_F_REQUEST;
	req->n.nlmsg_type = cmd;
	req->n.nlmsg_pid = dplane_ctx_get_ns(ctx)->nls.snl.nl_pid;

	req->ifa.ifi_index = ifindex;

	nl_attr_put8(&req->n, buflen, IFLA_PROTO_DOWN, down);
	nl_attr_put32(&req->n, buflen, IFLA_LINK, ifindex);

	/* Reason info nest */
	nest_protodown_reason =
		nl_attr_nest(&req->n, buflen, IFLA_PROTO_DOWN_REASON);

	if (!nest_protodown_reason)
		return -1;

	nl_attr_put32(&req->n, buflen, IFLA_PROTO_DOWN_REASON_MASK,
		      (1 << frr_protodown_r_bit));
	nl_attr_put32(&req->n, buflen, IFLA_PROTO_DOWN_REASON_VALUE,
		      ((int)down) << frr_protodown_r_bit);

	nl_attr_nest_end(&req->n, nest_protodown_reason);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s, protodown=%d ifindex=%u", __func__,
			   nl_msg_type_to_str(cmd), down, ifindex);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/* CUMULUS only function until batching exists */
enum zebra_dplane_result kernel_intf_update(struct zebra_dplane_ctx *ctx)
{
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	netlink_intf_msg_encoder(ctx, &req, sizeof(req));

	if (netlink_talk_info(netlink_talk_filter, &req.n,
			      dplane_ctx_get_ns(ctx), 0)
	    != 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

int netlink_protodown(struct interface *ifp, bool down, uint32_t r_bitfield)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct rtattr *nest_protodown_reason;

	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifa;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_SETLINK;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.ifa.ifi_index = ifp->ifindex;

	nl_attr_put8(&req.n, sizeof(req), IFLA_PROTO_DOWN, down);
	nl_attr_put32(&req.n, sizeof(req), IFLA_LINK, ifp->ifindex);

	if (r_bitfield) {
		nest_protodown_reason = nl_attr_nest(&req.n, sizeof(req),
						     IFLA_PROTO_DOWN_REASON);

		if (!nest_protodown_reason)
			return -1;

		nl_attr_put32(&req.n, sizeof(req), IFLA_PROTO_DOWN_REASON_MASK,
			      (1 << frr_protodown_r_bit));
		nl_attr_put32(&req.n, sizeof(req), IFLA_PROTO_DOWN_REASON_VALUE,
			      ((int)down) << frr_protodown_r_bit);

		nl_attr_nest_end(&req.n, nest_protodown_reason);
	}

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

/* Interface information read by netlink. */
void interface_list(struct zebra_ns *zns)
{
	interface_lookup_netlink(zns);
	/* We add routes for interface address,
	 * so we need to get the nexthop info
	 * from the kernel before we can do that
	 */
	netlink_nexthop_read(zns);

	interface_addr_lookup_netlink(zns);
}

static const char *port_state2str(uint8_t state)
{
	switch (state) {
	case BR_STATE_DISABLED:
		return "DISABLED";
	case BR_STATE_LISTENING:
		return "LISTENING";
	case BR_STATE_LEARNING:
		return "LEARNING";
	case BR_STATE_FORWARDING:
		return "FORWARDING";
	case BR_STATE_BLOCKING:
		return "BLOCKING";
	}

	return "UNKNOWN";
}

static void vxlan_vni_state_change(struct zebra_if *zif, uint16_t id,
				   uint8_t state)
{
	struct zebra_vxlan_vni *vnip;

	vnip = zebra_vxlan_if_vlanid_vni_find(zif, id);

	if (!vnip) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Cannot find VNI for VID (%u) IF %s for vlan state update",
				id, zif->ifp->name);

		return;
	}

	switch (state) {
	case BR_STATE_FORWARDING:
		zebra_vxlan_if_vni_up(zif->ifp, vnip);
		break;
	case BR_STATE_BLOCKING:
		zebra_vxlan_if_vni_down(zif->ifp, vnip);
		break;
	case BR_STATE_DISABLED:
	case BR_STATE_LISTENING:
	case BR_STATE_LEARNING:
	default:
		/* Not used for anything at the moment */
		break;
	}
}

static void vlan_id_range_state_change(struct interface *ifp, uint16_t id_start,
				       uint16_t id_end, uint8_t state)
{
	struct zebra_if *zif;

	zif = (struct zebra_if *)ifp->info;

	if (!zif)
		return;

	for (uint16_t i = id_start; i <= id_end; i++)
		vxlan_vni_state_change(zif, i, state);
}

/**
 * netlink_vlan_change() - Read in change about vlans from the kernel
 *
 * @h:		Netlink message header
 * @ns_id:	Namspace id
 * @startup:	Are we reading under startup conditions?
 *
 * Return:	Result status
 */
int netlink_vlan_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len, rem;
	struct interface *ifp;
	struct br_vlan_msg *bvm;
	struct bridge_vlan_info *vinfo;
	struct rtattr *vtb[BRIDGE_VLANDB_ENTRY_MAX + 1] = {};
	struct rtattr *attr;
	uint8_t state;
	uint32_t vrange;
	int type;

	/* We only care about state changes for now */
	if (!(h->nlmsg_type == RTM_NEWVLAN))
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct br_vlan_msg));
	if (len < 0) {
		zlog_warn(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct br_vlan_msg)));
		return -1;
	}

	bvm = NLMSG_DATA(h);

	if (bvm->family != AF_BRIDGE)
		return 0;

	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), bvm->ifindex);
	if (!ifp) {
		zlog_debug("Cannot find bridge-vlan IF (%u) for vlan update",
			   bvm->ifindex);
		return 0;
	}

	if (!IS_ZEBRA_IF_VXLAN(ifp)) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("Ignoring non-vxlan IF (%s) for vlan update",
				   ifp->name);

		return 0;
	}

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s %s IF %s NS %u",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(bvm->family), ifp->name, ns_id);

	/* Loop over "ALL" BRIDGE_VLANDB_ENTRY */
	rem = len;
	for (attr = BRVLAN_RTA(bvm); RTA_OK(attr, rem);
	     attr = RTA_NEXT(attr, rem)) {
		vinfo = NULL;
		state = 0;
		vrange = 0;

		type = attr->rta_type & NLA_TYPE_MASK;

		if (type != BRIDGE_VLANDB_ENTRY)
			continue;

		/* Parse nested entry data */
		netlink_parse_rtattr_nested(vtb, BRIDGE_VLANDB_ENTRY_MAX, attr);

		/* It must have info for the ID */
		if (!vtb[BRIDGE_VLANDB_ENTRY_INFO])
			continue;

		vinfo = (struct bridge_vlan_info *)RTA_DATA(
			vtb[BRIDGE_VLANDB_ENTRY_INFO]);

		/*
		 * We only care about state info, if there is none, just ignore
		 * it.
		 */
		if (!vtb[BRIDGE_VLANDB_ENTRY_STATE])
			continue;

		state = *(uint8_t *)RTA_DATA(vtb[BRIDGE_VLANDB_ENTRY_STATE]);

		if (vtb[BRIDGE_VLANDB_ENTRY_RANGE])
			vrange = *(uint32_t *)RTA_DATA(
				vtb[BRIDGE_VLANDB_ENTRY_RANGE]);

		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_VXLAN) {
			if (vrange)
				zlog_debug("VLANDB_ENTRY: VID (%u-%u) state=%s",
					   vinfo->vid, vrange,
					   port_state2str(state));
			else
				zlog_debug("VLANDB_ENTRY: VID (%u) state=%s",
					   vinfo->vid, port_state2str(state));
		}

		vlan_id_range_state_change(
			ifp, vinfo->vid, (vrange ? vrange : vinfo->vid), state);
	}

	return 0;
}
/**
 * netlink_request_vlan() - Request vlan information from the kernel
 * @zns:	Zebra namespace
 * @family:	AF_* netlink family
 * @type:	RTM_* type
 *
 * Return:	Result status
 */
static int netlink_request_vlan(struct zebra_ns *zns, int family, int type)
{
	struct {
		struct nlmsghdr n;
		struct br_vlan_msg bvm;
		char buf[256];
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_vlan_msg));
	req.bvm.family = family;

	nl_attr_put32(&req.n, sizeof(req), BRIDGE_VLANDB_DUMP_FLAGS, BRIDGE_VLANDB_DUMPF_STATS);

	return netlink_request(&zns->netlink_cmd, &req);
}

/**
 * netlink_vlan_read() - Vlan read function using netlink interface
 *
 * @zns:	Zebra name space
 *
 * Return:	Result status
 * Only called at bootstrap time.
 */
int netlink_vlan_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get bridg vlan info */
	ret = netlink_request_vlan(zns, PF_BRIDGE, RTM_GETVLAN);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_vlan_change, &zns->netlink_cmd,
				 &dp_info, 0, 1);

	return ret;
}

void if_netlink_set_frr_protodown_r_bit(uint8_t bit)
{
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("FRR protodown reason bit change %u -> %u",
			   frr_protodown_r_bit, bit);

	frr_protodown_r_bit = bit;
}

void if_netlink_unset_frr_protodown_r_bit(void)
{
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("FRR protodown reason bit change %u -> %u",
			   frr_protodown_r_bit,
			   FRR_PROTODOWN_REASON_DEFAULT_BIT);

	frr_protodown_r_bit = FRR_PROTODOWN_REASON_DEFAULT_BIT;
}

bool if_netlink_frr_protodown_r_bit_is_set(void)
{
	return (frr_protodown_r_bit != FRR_PROTODOWN_REASON_DEFAULT_BIT);
}

uint8_t if_netlink_get_frr_protodown_r_bit(void)
{
	return frr_protodown_r_bit;
}

#endif /* GNU_LINUX */
