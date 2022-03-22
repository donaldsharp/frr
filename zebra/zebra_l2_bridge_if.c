/*
 * Zebra L2 bridge interface handling
 *
 * Copyright (C) 2021 Cumulus Networks, Inc.
 * Sharath Ramamurthy
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
 */

#include <zebra.h>

#include "hash.h"
#include "if.h"
#include "jhash.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "vlan.h"
#include "vxlan.h"
#ifdef GNU_LINUX
#include <linux/neighbour.h>
#endif

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
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_vxlan.h"
#include "zebra/zebra_router.h"

static void zebra_l2_brvlan_mac_iterate_callback(struct hash_bucket *bucket,
						 void *ctxt)
{
	struct zebra_l2_brvlan_mac *bmac;
	struct zebra_l2_brvlan_mac_ctx *ctx;

	bmac = (struct zebra_l2_brvlan_mac *)bucket->data;
	ctx = (struct zebra_l2_brvlan_mac_ctx *)ctxt;

	ctx->func(ctx->br_if, ctx->vid, &bmac->macaddr, bmac->ifindex,
		  bmac->sticky, bmac->local_inactive, bmac->dp_static,
		  ctx->arg);
}

static void zebra_l2_brvlan_print_mac_hash(struct hash_bucket *bucket,
					   void *ctxt)
{
	struct zebra_l2_brvlan_mac_ctx *ctx;
	struct vty *vty;
	struct zebra_l2_brvlan_mac *bmac;
	json_object *json_obj = NULL, *json_mac = NULL;
	char mac[ETHER_ADDR_STRLEN];
	struct interface *ifp;

	ctx = (struct zebra_l2_brvlan_mac_ctx *)ctxt;
	vty = (struct vty *)(ctx->arg);
	bmac = (struct zebra_l2_brvlan_mac *)bucket->data;
	json_obj = ctx->json;

	prefix_mac2str(&bmac->macaddr, mac, sizeof(mac));
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					bmac->ifindex);
	if (json_obj) {
		json_mac = json_object_new_object();
		json_object_int_add(json_mac, "IfIndex", bmac->ifindex);
		json_object_string_add(json_mac, "Interface",
				       ifp ? ifp->name : "-");
		json_object_object_add(json_obj, mac, json_mac);
	} else {
		vty_out(vty, "%-17s %-7u %s\n", mac, bmac->ifindex,
			ifp ? ifp->name : "-");
	}
}

static unsigned int zebra_l2_brvlan_mac_hash_keymake(const void *p)
{
	const struct zebra_l2_brvlan_mac *bmac;
	const void *pnt;

	bmac = (const struct zebra_l2_brvlan_mac *)p;
	pnt = (void *)bmac->macaddr.octet;

	return jhash(pnt, ETH_ALEN, 0xa5a5a55a);
}

static bool zebra_l2_brvlan_mac_hash_cmp(const void *p1, const void *p2)
{
	const struct zebra_l2_brvlan_mac *bmac1;
	const struct zebra_l2_brvlan_mac *bmac2;

	bmac1 = (const struct zebra_l2_brvlan_mac *)p1;
	bmac2 = (const struct zebra_l2_brvlan_mac *)p2;

	if (bmac1 == NULL && bmac2 == NULL)
		return true;

	if (bmac1 == NULL || bmac2 == NULL)
		return false;

	return (memcmp(bmac1->macaddr.octet, bmac2->macaddr.octet, ETH_ALEN) ==
		0);
}

static void zebra_l2_brvlan_mac_free(void *p)
{
	struct zebra_l2_brvlan_mac *bmac;

	bmac = (struct zebra_l2_brvlan_mac *)p;
	XFREE(MTYPE_TMP, bmac);
}

static void *zebra_l2_brvlan_mac_alloc(void *p)
{
	struct zebra_l2_brvlan_mac *bmac;
	const struct zebra_l2_brvlan_mac *tmp_mac;

	tmp_mac = (const struct zebra_l2_brvlan_mac *)p;
	bmac = XCALLOC(MTYPE_TMP, sizeof(*bmac));
	bmac->vid = tmp_mac->vid;
	memcpy(&bmac->macaddr, &tmp_mac->macaddr, ETH_ALEN);

	return (void *)bmac;
}

static void zebra_l2_brvlan_mac_table_destroy(struct hash *mac_table)
{
	if (mac_table) {
		hash_clean(mac_table, zebra_l2_brvlan_mac_free);
		hash_free(mac_table);
	}
}

static struct hash *zebra_l2_brvlan_mac_table_create()
{
	return hash_create(zebra_l2_brvlan_mac_hash_keymake,
			   zebra_l2_brvlan_mac_hash_cmp,
			   "Zebra L2 Bridge MAC Table");
}

void zebra_l2_brvlan_mac_iterate(struct interface *br_if, vlanid_t vid,
				 int (*func)(struct interface *br_if,
					     vlanid_t vid,
					     struct ethaddr *macaddr,
					     ifindex_t ifidx, bool, bool, bool,
					     void *a),
				 void *arg)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;
	struct zebra_l2_brvlan_mac_ctx ctx;

	zif = (struct zebra_if *)br_if->info;
	br = BRIDGE_FROM_ZEBRA_IF(zif);
	if (!br || !br->mac_table[vid])
		return;
	memset(&ctx, 0, sizeof(ctx));
	ctx.br_if = br_if;
	ctx.vid = vid;
	ctx.func = func;
	ctx.arg = arg;
	hash_iterate(br->mac_table[vid], zebra_l2_brvlan_mac_iterate_callback,
		     &ctx);
}

void zebra_l2_brvlan_print_macs(struct vty *vty, struct interface *br_if,
				vlanid_t vid, bool uj)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;
	uint32_t num_macs;
	struct zebra_l2_brvlan_mac_ctx ctx;

	zif = (struct zebra_if *)br_if->info;
	br = BRIDGE_FROM_ZEBRA_IF(zif);
	if (!br) {
		return;
	}
	json_object *json_obj = NULL, *json_mac_obj = NULL;
	if (uj) { /* json format */
		json_obj = json_object_new_object();
		json_mac_obj = json_object_new_object();
	}
	if (!br->mac_table[vid]) {
		vty_out(vty,
			"%% bridge %s VID %u does not have a MAC hash table\n",
			br_if->name, vid);
		return;
	}
	num_macs = hashcount(br->mac_table[vid]);
	if (!num_macs) {
		vty_out(vty, "bridge %s VID %u - No local MACs\n", br_if->name,
			vid);
		return;
	}
	if (uj) {
		json_object_string_add(json_obj, "bridge", br_if->name);
		json_object_int_add(json_obj, "VID", vid);
		json_object_int_add(json_obj, "number of local MACS", num_macs);
	} else {
		vty_out(vty, "bridge %s VID %u - Number of local MACs: %u\n",
			br_if->name, vid, num_macs);
		vty_out(vty, "%-17s %-7s %-30s\n", "MAC", "IfIndex",
			"Interface");
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.br_if = br_if;
	ctx.vid = vid;
	ctx.arg = vty;
	ctx.json = json_mac_obj;
	hash_iterate(br->mac_table[vid], zebra_l2_brvlan_print_mac_hash, &ctx);
	if (uj) {
		json_object_object_add(json_obj, "MAC", json_mac_obj);
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json_obj, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_obj);
	}
}

int zebra_l2_brvlan_mac_del(struct interface *br_if,
			    struct zebra_l2_brvlan_mac *bmac)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;
	vlanid_t vid;
	struct zebra_l2_brvlan_mac *tmp_mac;
	char buf[ETHER_ADDR_STRLEN];
	uint32_t num_macs;

	zif = (struct zebra_if *)br_if->info;
	br = BRIDGE_FROM_ZEBRA_IF(zif);
	if (!br->mac_table[bmac->vid]) {
		zlog_debug("bridge %s VID %u - MAC hash table not found",
			   br_if->name, bmac->vid);
		return -1;
	}
	vid = bmac->vid;
	tmp_mac = hash_release(br->mac_table[vid], bmac);
	if (tmp_mac)
		zebra_l2_brvlan_mac_free(tmp_mac);

	num_macs = hashcount(br->mac_table[vid]);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("bridge %s VID %u bmac %p MAC %s delete - hash# %u",
			   br_if->name, vid, bmac,
			   prefix_mac2str(&bmac->macaddr, buf, sizeof(buf)),
			   num_macs);

	if (!num_macs) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("bridge %s vlan %u - destroying MAC table",
				   br_if->name, vid);
		zebra_l2_brvlan_mac_table_destroy(br->mac_table[vid]);
		br->mac_table[vid] = NULL;
	}

	return 0;
}

int zebra_l2_brvlan_mac_update(struct interface *br_if,
			       struct zebra_l2_brvlan_mac *bmac,
			       ifindex_t ifidx)
{
	char buf[ETHER_ADDR_STRLEN];

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("bridge %s VID %u bmac %p MAC %s update ifidx %u",
			   br_if->name, bmac->vid, bmac,
			   prefix_mac2str(&bmac->macaddr, buf, sizeof(buf)),
			   ifidx);

	bmac->ifindex = ifidx;
	return 0;
}

struct zebra_l2_brvlan_mac *
zebra_l2_brvlan_mac_add(struct interface *br_if, vlanid_t vid,
			struct ethaddr *mac, ifindex_t ifidx, bool sticky,
			bool local_inactive, bool dp_static)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;
	struct zebra_l2_brvlan_mac *bmac;
	struct zebra_l2_brvlan_mac tmp_mac;
	char buf[ETHER_ADDR_STRLEN];
	uint32_t num_macs;

	zif = (struct zebra_if *)br_if->info;
	br = BRIDGE_FROM_ZEBRA_IF(zif);
	if (!br->mac_table[vid]) {
		br->mac_table[vid] = zebra_l2_brvlan_mac_table_create();
		if (!br->mac_table[vid]) {
			zlog_err(
				"bridge %s vid %u - failed to create MAC hash table",
				br_if->name, vid);
			return NULL;
		}
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("bridge %s vid %u - MAC hash table created",
				   br_if->name, vid);
	}

	memset(&tmp_mac, 0, sizeof(tmp_mac));
	memcpy(&tmp_mac.macaddr, mac, ETH_ALEN);
	bmac = hash_get(br->mac_table[vid], (void *)&tmp_mac,
			zebra_l2_brvlan_mac_alloc);
	assert(bmac);
	bmac->br_if = br_if;
	bmac->vid = vid;
	bmac->ifindex = ifidx;
	bmac->sticky = sticky;
	bmac->local_inactive = local_inactive;
	bmac->dp_static = dp_static;
	num_macs = hashcount(br->mac_table[vid]);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"bridge %s VID %u MAC %s ifidx %u add - %p, hash# %u",
			br_if->name, vid, prefix_mac2str(mac, buf, sizeof(buf)),
			ifidx, bmac, num_macs);

	return bmac;
}

struct zebra_l2_brvlan_mac *zebra_l2_brvlan_mac_find(struct interface *br_if,
						     vlanid_t vid,
						     struct ethaddr *mac)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;
	struct zebra_l2_brvlan_mac *bmac;
	struct zebra_l2_brvlan_mac tmp_mac;
	char buf[ETHER_ADDR_STRLEN];

	zif = (struct zebra_if *)br_if->info;
	br = BRIDGE_FROM_ZEBRA_IF(zif);
	if (!br->mac_table[vid])
		return NULL;

	memset(&tmp_mac, 0, sizeof(tmp_mac));
	memcpy(&tmp_mac.macaddr, mac, ETH_ALEN);
	bmac = (struct zebra_l2_brvlan_mac *)hash_lookup(br->mac_table[vid],
							 (void *)&tmp_mac);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("bridge %s VID %u MAC %s find - %p", br_if->name,
			   vid, prefix_mac2str(mac, buf, sizeof(buf)), bmac);

	return bmac;
}

static unsigned int zebra_l2_bridge_vlan_hash_keymake(const void *p)
{
	const struct zebra_l2_bridge_vlan *bvlan;

	bvlan = (const struct zebra_l2_bridge_vlan *)p;
	return jhash(&bvlan->vid, sizeof(bvlan->vid), 0);
}

static bool zebra_l2_bridge_vlan_hash_cmp(const void *p1, const void *p2)
{
	const struct zebra_l2_bridge_vlan *bv1;
	const struct zebra_l2_bridge_vlan *bv2;

	bv1 = (const struct zebra_l2_bridge_vlan *)p1;
	bv2 = (const struct zebra_l2_bridge_vlan *)p2;

	return (bv1->vid == bv2->vid);
}

static int zebra_l2_bridge_if_vlan_walk_callback(struct hash_bucket *bucket,
						 void *ctxt)
{
	int ret;
	struct zebra_l2_bridge_vlan *bvlan;
	struct zebra_l2_bridge_if_ctx *ctx;

	bvlan = (struct zebra_l2_bridge_vlan *)bucket->data;
	ctx = (struct zebra_l2_bridge_if_ctx *)ctxt;

	ret = ctx->func(ctx->zif, bvlan, ctx->arg);
	return ret;
}

static void zebra_l2_bridge_if_vlan_iterate_callback(struct hash_bucket *bucket,
						     void *ctxt)
{
	struct zebra_l2_bridge_vlan *bvlan;
	struct zebra_l2_bridge_if_ctx *ctx;

	bvlan = (struct zebra_l2_bridge_vlan *)bucket->data;
	ctx = (struct zebra_l2_bridge_if_ctx *)ctxt;

	ctx->func(ctx->zif, bvlan, ctx->arg);
}

static int zebra_l2_bridge_if_vlan_clean(struct zebra_if *zif,
					 struct zebra_l2_bridge_vlan *bvlan,
					 void *ctxt)
{
	struct zebra_evpn_access_bd *acc_bd;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("access vlan %d bridge %s cleanup", bvlan->vid,
			   zif->ifp->name);

	acc_bd = zebra_evpn_acc_vl_find(bvlan->vid, zif->ifp);
	if (acc_bd)
		zebra_evpn_access_bd_bridge_cleanup(bvlan->vid, zif->ifp,
						    acc_bd);

	bvlan->access_bd = NULL;
	return 0;
}

static void zebra_l2_bridge_vlan_free(void *arg)
{
	struct zebra_l2_bridge_vlan *bvl;

	bvl = (struct zebra_l2_bridge_vlan *)arg;
	XFREE(MTYPE_TMP, bvl);
}

static void *zebra_l2_bridge_vlan_alloc(void *p)
{
	struct zebra_l2_bridge_vlan *bvlan;
	const struct zebra_l2_bridge_vlan *bvl;

	bvl = (const struct zebra_l2_bridge_vlan *)p;
	bvlan = XCALLOC(MTYPE_TMP, sizeof(*bvlan));
	bvlan->vid = bvl->vid;
	bvlan->access_bd = bvl->access_bd;

	return (void *)bvlan;
}

static void zebra_l2_bridge_vlan_table_destroy(struct hash *vlan_table)
{
	if (vlan_table) {
		hash_clean(vlan_table, zebra_l2_bridge_vlan_free);
		hash_free(vlan_table);
	}
}

static struct hash *zebra_l2_bridge_vlan_table_create(void)
{
	return hash_create(zebra_l2_bridge_vlan_hash_keymake,
			   zebra_l2_bridge_vlan_hash_cmp,
			   "Zebra L2 Bridge Vlan Table");
}

static void zebra_l2_bridge_if_vlan_table_destroy(struct zebra_if *zif)
{
	struct zebra_l2_bridge_if *br;

	br = BRIDGE_FROM_ZEBRA_IF(zif);
	zebra_l2_bridge_if_vlan_iterate(zif, zebra_l2_bridge_if_vlan_clean,
					NULL);
	zebra_l2_bridge_vlan_table_destroy(br->vlan_table);
	br->vlan_table = NULL;
}

static int zebra_l2_bridge_if_vlan_table_create(struct zebra_if *zif)
{
	struct zebra_l2_bridge_if *br;

	br = BRIDGE_FROM_ZEBRA_IF(zif);
	if (!br->vlan_table) {
		br->vlan_table = zebra_l2_bridge_vlan_table_create();
		if (!br->vlan_table)
			return -ENOMEM;
	}

	return 0;
}

static int zebra_l2_bridge_if_vlan_del(struct interface *ifp, vlanid_t vid)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;
	struct zebra_l2_bridge_vlan bvl;
	struct zebra_l2_bridge_vlan *bvlan;

	zif = (struct zebra_if *)ifp->info;
	memset(&bvl, 0, sizeof(bvl));
	bvl.vid = vid;

	br = BRIDGE_FROM_ZEBRA_IF(zif);
	bvlan = hash_release(br->vlan_table, &bvl);

	if (bvlan)
		zebra_l2_bridge_vlan_free(bvlan);

	return 0;
}

static int zebra_l2_bridge_if_vlan_update(struct interface *ifp,
					  struct zebra_l2_bridge_vlan *bvl,
					  int chgflags)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_vlan *bvlan;

	zif = (struct zebra_if *)ifp->info;
	bvlan = zebra_l2_bridge_if_vlan_find(zif, bvl->vid);

	if (chgflags & ZEBRA_BRIDGEIF_ACCESS_BD_CHANGE)
		bvlan->access_bd = bvl->access_bd;

	if (!bvlan->access_bd)
		return zebra_l2_bridge_if_vlan_del(ifp, bvl->vid);

	return 0;
}

static int zebra_l2_bridge_if_vlan_add(struct interface *ifp,
				       struct zebra_l2_bridge_vlan *bvlan)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;

	zif = (struct zebra_if *)ifp->info;
	br = BRIDGE_FROM_ZEBRA_IF(zif);
	hash_get(br->vlan_table, (void *)bvlan, zebra_l2_bridge_vlan_alloc);

	return 0;
}

struct zebra_l2_bridge_vlan *
zebra_l2_bridge_if_vlan_find(const struct zebra_if *zif, vlanid_t vid)
{
	const struct zebra_l2_bridge_if *br;
	struct zebra_l2_bridge_vlan *bvl;
	struct zebra_l2_bridge_vlan bvlan;

	br = BRIDGE_FROM_ZEBRA_IF(zif);
	memset(&bvlan, 0, sizeof(bvlan));
	bvlan.vid = vid;
	bvl = (struct zebra_l2_bridge_vlan *)hash_lookup(br->vlan_table,
							 (void *)&bvlan);

	/* TODO: For debugging. Remove later */
	if (bvl)
		assert(bvl->vid == vid);

	return bvl;
}

vni_t zebra_l2_bridge_if_vni_find(const struct zebra_if *zif, vlanid_t vid)
{
	vni_t vni_id = 0;
	struct zebra_l2_bridge_vlan *bvlan;

	bvlan = zebra_l2_bridge_if_vlan_find(zif, vid);
	if (bvlan && bvlan->access_bd && bvlan->access_bd->vni)
		vni_id = bvlan->access_bd->vni;

	return vni_id;
}

void zebra_l2_bridge_if_vlan_iterate(struct zebra_if *zif,
				     int (*func)(struct zebra_if *zif,
						 struct zebra_l2_bridge_vlan *,
						 void *),
				     void *arg)
{
	struct zebra_l2_bridge_if *br;
	struct zebra_l2_bridge_if_ctx ctx;

	br = BRIDGE_FROM_ZEBRA_IF(zif);
	memset(&ctx, 0, sizeof(ctx));
	ctx.zif = zif;
	ctx.func = func;
	ctx.arg = arg;
	hash_iterate(br->vlan_table, zebra_l2_bridge_if_vlan_iterate_callback,
		     &ctx);
}

void zebra_l2_bridge_if_vlan_walk(struct zebra_if *zif,
				  int (*func)(struct zebra_if *zif,
					      struct zebra_l2_bridge_vlan *,
					      void *),
				  void *arg)
{
	struct zebra_l2_bridge_if *br;
	struct zebra_l2_bridge_if_ctx ctx;

	br = BRIDGE_FROM_ZEBRA_IF(zif);
	memset(&ctx, 0, sizeof(ctx));
	ctx.zif = zif;
	ctx.func = func;
	ctx.arg = arg;
	hash_walk(br->vlan_table, zebra_l2_bridge_if_vlan_walk_callback, &ctx);
}

int zebra_l2_bridge_if_vlan_access_bd_deref(struct zebra_evpn_access_bd *bd)
{
	int chgflags = 0;
	struct zebra_if *zif;
	struct zebra_l2_bridge_vlan bvl;
	struct zebra_l2_bridge_vlan *bvlan;

	zif = bd->bridge_zif;
	if (!zif)
		return -1;

	bvlan = zebra_l2_bridge_if_vlan_find(zif, bd->vid);
	if (!bvlan)
		return 0;

	memset(&bvl, 0, sizeof(bvl));
	bvl.vid = bd->vid;
	bvl.access_bd = NULL;
	chgflags = ZEBRA_BRIDGEIF_ACCESS_BD_CHANGE;
	return zebra_l2_bridge_if_vlan_update(zif->ifp, &bvl, chgflags);
}

int zebra_l2_bridge_if_vlan_access_bd_ref(struct zebra_evpn_access_bd *bd)
{
	int chgflags = 0;
	struct zebra_if *zif;
	struct zebra_l2_bridge_vlan bvl;
	struct zebra_l2_bridge_vlan *bvlan;

	zif = bd->bridge_zif;
	if (!zif)
		return -1;

	if (!bd->vid)
		return -1;

	memset(&bvl, 0, sizeof(bvl));
	bvl.vid = bd->vid;
	bvl.access_bd = bd;

	bvlan = zebra_l2_bridge_if_vlan_find(zif, bd->vid);
	if (!bvlan)
		return zebra_l2_bridge_if_vlan_add(zif->ifp, &bvl);

	chgflags = ZEBRA_BRIDGEIF_ACCESS_BD_CHANGE;
	return zebra_l2_bridge_if_vlan_update(zif->ifp, &bvl, chgflags);
}

int zebra_l2_bridge_if_cleanup(struct interface *ifp)
{
	struct zebra_if *zif;

	if (!IS_ZEBRA_IF_BRIDGE(ifp))
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("bridge %s cleanup", ifp->name);

	zif = (struct zebra_if *)ifp->info;
	zebra_l2_bridge_if_vlan_table_destroy(zif);
	return 0;
}

int zebra_l2_bridge_if_del(struct interface *ifp)
{
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("bridge %s delete", ifp->name);

	return zebra_l2_bridge_if_cleanup(ifp);
}

int zebra_l2_bridge_if_add(struct interface *ifp)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;

	zif = (struct zebra_if *)ifp->info;
	br = BRIDGE_FROM_ZEBRA_IF(zif);
	br->br_zif = (struct zebra_if *)ifp->info;
	zebra_l2_bridge_if_vlan_table_create(zif);
	return 0;
}
