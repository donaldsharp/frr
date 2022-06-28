/* Lttng Tracing for Zebra daemon
 *
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * Rajesh Varatharaj
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

#if !defined(_ZEBRA_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _ZEBRA_TRACE_H

#include "lib/trace.h"


#if defined(HAVE_LTTNG) || defined(HAVE_ZEBRA_LTTNG)

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
#define TRACEPOINT_PROVIDER frr_zebra

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "zebra/zebra_trace.h"

#include <lttng/tracepoint.h>

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mroute.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "lib/stream.h"
#include "lib/vrf.h"

/* clang-format off */

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ipmr_route_stats,
	TP_ARGS(vrf_id_t,  vrf_id),
	TP_FIELDS(
    ctf_integer(unsigned int, vrfid, vrf_id)
		ctf_string(mroute_vrf_id, "Asking for mroute information")
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ipmr_route_stats, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_add_update,
	TP_ARGS(struct interface *, ifp),
	TP_FIELDS(
    ctf_integer(unsigned int, ifindex, ifp->ifindex)
    ctf_integer(unsigned int, vrfid, ifp->vrf_id)
    ctf_string(ifp, ifp->name)
		ctf_string(interface, "Interface Index added")
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_add_update, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_ipneigh_change,
	TP_ARGS(struct nlmsghdr *, h, struct ndmsg *, ndm, struct interface *, ifp),
	TP_FIELDS(
	  ctf_string(h, nlmsg_type2str(h->nlmsg_type))
    ctf_integer(unsigned int, ndm_family, ndm->ndm_family)
	  ctf_string(ifp,  ifp->name ?  ifp->name : "(unknown interface name )")
    ctf_integer(unsigned int, vrf_id, ifp->vrf_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_ipneigh_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_parse_info,
	TP_ARGS(struct nlmsghdr *, h, const struct nlsock *, nl),
	TP_FIELDS(
	  ctf_string(h, nlmsg_type2str(h->nlmsg_type) ? nlmsg_type2str(h->nlmsg_type) : "(Invalid Msg Type )")
    ctf_integer(unsigned int, nlmsglen, h->nlmsg_len)
    ctf_integer(unsigned int, nlmsgpid, h->nlmsg_pid)
	  ctf_string(nl, nl->name ? nl->name : "(unknown nl name)")
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_parse_info, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_talk_info,
	TP_ARGS( struct nlmsghdr *, n, const struct nlsock *, nl),
	TP_FIELDS(
	  ctf_string(n, nlmsg_type2str(n->nlmsg_type) ? nlmsg_type2str(n->nlmsg_type) : "(Invalid Msg Type )")
    ctf_integer(unsigned int, nlmsglen, n->nlmsg_len)
    ctf_integer(unsigned int, nlmsgseq, n->nlmsg_seq)
    ctf_integer(unsigned int, nlmsg_flags, n->nlmsg_flags)
	  ctf_string(nl, nl->name ? nl->name : "(unknown nl name)")
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_talk_info, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_macfdb_change,
	TP_ARGS(struct nlmsghdr *, h, struct ndmsg *, ndm, uint32_t, nhg_id, vni_t, vni),
	TP_FIELDS(
	  ctf_string(nl_msg_type,  nlmsg_type2str(h->nlmsg_type) ?  nlmsg_type2str(h->nlmsg_type)
	    : "(Invalid Msg Type )")
    ctf_integer(unsigned int, ndm_ifindex, ndm->ndm_ifindex)
    ctf_integer(int, ndm_state, ndm->ndm_state)
    ctf_integer(uint32_t, ndm_flags, ndm->ndm_flags)
	  ctf_integer(unsigned int, nhg, nhg_id)
	  ctf_integer(vni_t, vni, vni)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_macfdb_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_neigh_update_msg_encode,
	TP_ARGS(const struct ethaddr *, mac, const struct ipaddr *, ip, uint32_t ,
	  nhg_id, uint8_t, flags, uint16_t, state, uint8_t, family, uint8_t, type),
	TP_FIELDS(
	  ctf_array(unsigned char, mac, mac,
	          sizeof(struct ethaddr))
	  ctf_array(unsigned char, ip, ip,
	          sizeof(struct ipaddr))
	  ctf_integer(uint32_t, nhg, nhg_id)
	  ctf_integer(uint8_t, flags, flags)
	  ctf_integer(uint16_t, state, state)
	  ctf_integer(uint8_t, family, family)
	  ctf_integer(uint8_t, type, type)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_neigh_update_msg_encode, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_route_multipath_msg_encode,
	TP_ARGS(const struct prefix *, p, int, cmd, size_t , datalen),
	TP_FIELDS(
	  ctf_integer(uint8_t, family, p->family)
    ctf_integer(unsigned int, dst_len, p->prefixlen)
    ctf_integer(uint8_t, cmd, cmd)
    ctf_integer(uint32_t, datalen, datalen)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_route_multipath_msg_encode, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_msg_encode,
	TP_ARGS(const struct nexthop *, nh, uint32_t, id),
	TP_FIELDS(
    ctf_integer(uint32_t, nh_index, nh->ifindex)
    ctf_integer(uint32_t, nh_vrfid, nh->vrf_id)
    ctf_integer(uint32_t, id, id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_nexthop_msg_encode, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _ZEBRA_TRACE_H */
