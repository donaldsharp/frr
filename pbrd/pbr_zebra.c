/*
 * Zebra connect code.
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"

#include "pbr_nht.h"
#include "pbr_map.h"
#include "pbr_zebra.h"

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

DEFINE_MGROUP(PBRD, "pbrd")
DEFINE_MTYPE(PBRD, PBR_INTERFACE, "PBR interface")

/* For registering threads. */
extern struct thread_master *master;

static struct interface *zebra_interface_if_lookup(struct stream *s)
{
	char ifname_tmp[INTERFACE_NAMSIZ];

	/* Read interface name. */
	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

	/* And look it up. */
	return if_lookup_by_name(ifname_tmp, VRF_DEFAULT);
}

static struct pbr_interface *pbr_if_new(struct interface *ifp)
{
	struct pbr_interface *pbr_ifp;

	zassert(ifp);
	zassert(!ifp->info);

	pbr_ifp = XCALLOC(MTYPE_PBR_INTERFACE, sizeof(*pbr_ifp));

	if (!pbr_ifp) {
		zlog_err("PBR XCALLOC(%zu) failure", sizeof(*pbr_ifp));
		return 0;
	}

	return (pbr_ifp);
}

/* Inteface addition message from zebra. */
static int interface_add(int command, struct zclient *zclient,
			       zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);

	if (!ifp)
		return 0;

	if (!ifp->info) {
		struct pbr_interface *pbr_ifp;

		pbr_ifp = pbr_if_new(ifp);
		ifp->info = pbr_ifp;
	}

	return 0;
}



static int interface_delete(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct stream *s;

	s = zclient->ibuf;
	/* zebra_interface_state_read () updates interface structure in iflist
	 */
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	if_set_index(ifp, IFINDEX_INTERNAL);

	return 0;
}

static int interface_address_add(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
	zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(c);
	return 0;
}

static int interface_state_up(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{

	zebra_interface_if_lookup(zclient->ibuf);

	return 0;
}

static int interface_state_down(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{

	zebra_interface_state_read(zclient->ibuf, vrf_id);

	return 0;
}

static int notify_owner(int command, struct zclient *zclient,
			zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table, &note))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		zlog_debug("%s Route install failure for table: %u",
			   __PRETTY_FUNCTION__, table);
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		zlog_debug("%s Route better admin distance won for table: %u",
			   __PRETTY_FUNCTION__, table);
		break;
	case ZAPI_ROUTE_INSTALLED:
		zlog_debug("%s Route installed succeeded for table: %u",
			   __PRETTY_FUNCTION__, table);
		pbr_nht_route_installed_for_table(table);
		break;
	}

	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

/*
 * This function assumes a default route is being
 * installed into the appropriate tableid
 */
void route_add(struct pbr_nexthop_group_cache *pnhgc,
	       struct nexthop_group_cmd *nhgc)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct nexthop *nhop;
	uint32_t i;

	memset(&api, 0, sizeof(api));

	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_PBR;
	api.safi = SAFI_UNICAST;
	/*
	 * Sending a default route
	 */
	api.prefix.family = AF_INET;
	api.tableid = pnhgc->table_id;
	SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	i = 0;
	for (ALL_NEXTHOPS(nhgc->nhg, nhop)) {
		api_nh = &api.nexthops[i];
		api_nh->vrf_id = nhop->vrf_id;
		api_nh->type = nhop->type;
		switch (nhop->type) {
		case NEXTHOP_TYPE_IPV4:
			api_nh->gate.ipv4 = nhop->gate.ipv4;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			api_nh->gate.ipv4 = nhop->gate.ipv4;
			api_nh->ifindex = nhop->ifindex;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			api_nh->ifindex = nhop->ifindex;
			break;
		case NEXTHOP_TYPE_IPV6:
			memcpy(&api_nh->gate.ipv6, &nhop->gate.ipv6, 16);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			api_nh->ifindex = nhop->ifindex;
			memcpy(&api_nh->gate.ipv6, &nhop->gate.ipv6, 16);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			api_nh->bh_type = nhop->bh_type;
			break;
		}
		i++;
	}
	api.nexthop_num = i;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

/*
 * This function assumes a default route is being
 * removed from the appropriate tableid
 */
void route_delete(struct pbr_nexthop_group_cache *pnhgc)
{
	struct zapi_route api;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_PBR;
	api.safi = SAFI_UNICAST;
	api.prefix.family = AF_INET;

	api.tableid = pnhgc->table_id;
	SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

	return;
}

static int pbr_zebra_nexthop_update(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route nhr;

	zapi_nexthop_update_decode(zclient->ibuf, &nhr);

	return 1;
}

extern struct zebra_privs_t pbr_privs;

void pbr_zebra_init(void)
{
	struct zclient_options opt = { .receive_notify = true };

	zclient = zclient_new_notify(master, &opt);

	zclient_init(zclient, ZEBRA_ROUTE_PBR, 0, &pbr_privs);
	zclient->zebra_connected = zebra_connected;
	zclient->interface_add = interface_add;
	zclient->interface_delete = interface_delete;
	zclient->interface_up = interface_state_up;
	zclient->interface_down = interface_state_down;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	zclient->notify_owner = notify_owner;
	zclient->nexthop_update = pbr_zebra_nexthop_update;
}

void pbr_send_rnh(struct nexthop *nhop, bool reg)
{
	uint32_t command;
	struct prefix p;

	command = (reg) ?
		ZEBRA_NEXTHOP_REGISTER : ZEBRA_NEXTHOP_UNREGISTER;

	memset(&p, 0, sizeof(p));
	switch(nhop->type) {
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		return;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		p.family = AF_INET;
		p.u.prefix4.s_addr = nhop->gate.ipv4.s_addr;
		p.prefixlen = 32;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		p.family = AF_INET6;
		memcpy(&p.u.prefix6, &nhop->gate.ipv6, 16);
		p.prefixlen = 128;
		break;
	}

	if (zclient_send_rnh(zclient, command, &p,
			     false, nhop->vrf_id) < 0) {
		zlog_warn("%s: Failure to send nexthop to zebra",
			  __PRETTY_FUNCTION__);
	}
}

static void pbr_encode_pbr_map_sequence_prefix(struct stream *s,
					       struct prefix *p)
{
	if (p) {
		stream_putc(s, p->family);
		stream_putc(s, p->prefixlen);
		stream_put(s, &p->u.prefix, prefix_blen(p));
	} else {
		stream_putc(s, AFI_IP);
		stream_putc(s, 0);
		stream_putl(s, 0);
	}
}

static void pbr_encode_pbr_map_sequence(struct stream *s,
					struct pbr_map_sequence *pbrms,
					struct interface *ifp)
{
	stream_putl(s, pbrms->seqno);
	stream_putl(s, pbrms->ruleno);
	pbr_encode_pbr_map_sequence_prefix(s, pbrms->src);
	stream_putw(s, 0);  /* src port */
	pbr_encode_pbr_map_sequence_prefix(s, pbrms->dst);
	stream_putw(s, 0);  /* dst port */
	stream_putl(s, pbr_nht_get_table(pbrms->nhgrp_name));
	stream_putl(s, ifp->ifindex);
}

void pbr_send_pbr_map(struct pbr_map *pbrm)
{
	struct listnode *inode, *snode;
	struct pbr_map_sequence *pbrms;
	struct interface *ifp;
	struct stream *s;
	uint32_t total;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_RULE_ADD, VRF_DEFAULT);

	total = 0;
	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, snode, pbrms))
		total++;

	stream_putl(s, total);
	for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, inode, ifp)) {
		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, snode, pbrms)) {
			pbr_encode_pbr_map_sequence(s, pbrms, ifp);
		}
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	zclient_send_message(zclient);
}
