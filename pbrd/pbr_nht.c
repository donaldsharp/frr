/*
 * PBR-nht Code
 * Copyright (C) 2018 Cumulus Networks, Inc.
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

#include <log.h>
#include <nexthop.h>
#include <nexthop_group.h>
#include <hash.h>
#include <jhash.h>

#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_event.h"
#include "pbrd/pbr_zebra.h"

struct hash *pbr_nh_hash;
struct hash *pbr_nhg_hash;

static void *pbr_nh_alloc(void *p);

void pbr_nhgroup_add_cb(const char *name)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new();

	pbre->event = PBR_NHG_ADD;
	strlcpy(pbre->name, name, sizeof(pbre->name));

	pbr_event_enqueue(pbre);
	zlog_debug("Received ADD cb for %s", name);
}

void pbr_nhgroup_modify_cb(const char *name)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new();

	pbre->event = PBR_NHG_MODIFY;
	strlcpy(pbre->name, name, sizeof(pbre->name));

	pbr_event_enqueue(pbre);
	zlog_debug("Received MODIFY cb for %s", name);
}

void pbr_nhgroup_delete_cb(const char *name)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new();

	pbre->event = PBR_NHG_DELETE;
	strlcpy(pbre->name, name, sizeof(pbre->name));

	pbr_event_enqueue(pbre);
	zlog_debug("Recieved DELETE cb for %s", name);
}

#if 0
static struct pbr_nexthop_cache *pbr_nht_lookup_nexthop(struct nexthop *nexthop)
{
	return NULL;
}
#endif

void pbr_nht_change_group(const char *name)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop *nexthop;
	struct pbr_nexthop_cache *pnhc;
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache find;

	nhgc = nhgc_find(name);
	if (!nhgc)
		return;

	memset(&find, 0, sizeof(find));
	strcpy(find.name, name);
	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	if (!pnhgc) {
		zlog_debug("Something wrong here, FUS!");
		return;
	}

	for (ALL_NEXTHOPS(nhgc->nhg, nexthop)) {
		zlog_debug("Handling stuff\n");
		pnhc = hash_get(pbr_nh_hash, nexthop, pbr_nh_alloc);
	}
}

static void *pbr_nhgc_alloc(void *p)
{
	struct pbr_nexthop_group_cache *new;
	struct pbr_nexthop_group_cache *pnhgc =
		(struct pbr_nexthop_group_cache *)p;

	new = XCALLOC(MTYPE_TMP, sizeof(*new));

	strcpy(new->name, pnhgc->name);

	return new;
}

void pbr_nht_add_group(const char *name)
{
	struct nexthop *nhop;
	struct nexthop_group_cmd *nhgc;
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache lookup;

	nhgc = nhgc_find(name);

	if (!nhgc) {
		zlog_warn("Cannot find group %s to add", name);
		return;
	}

	strcpy(lookup.name, name);
	pnhgc = hash_get(pbr_nhg_hash, &lookup, pbr_nhgc_alloc);

	for (ALL_NEXTHOPS(nhgc->nhg, nhop)) {
		struct pbr_nexthop_cache lookup;
		struct pbr_nexthop_cache *pnhc;

		memcpy(&lookup.nexthop, nhop, sizeof(*nhop));
		pnhc = hash_get(pbr_nh_hash, &lookup, pbr_nh_alloc);
	}
}

void pbr_nht_delete_group(const char *name)
{
}

bool pbr_nht_nexthop_valid(struct nexthop *nhop)
{
	zlog_debug("%s %p", __PRETTY_FUNCTION__, nhop);
	return true;
}

bool pbr_nht_nexthop_group_valid(const char *name)
{
	zlog_debug("%s(%s)", __PRETTY_FUNCTION__, name);
	return true;
}

static void *pbr_nh_alloc(void *p)
{
	struct pbr_nexthop_cache *new;
	struct pbr_nexthop_cache *pnhc = (struct pbr_nexthop_cache *)p;

	new = XCALLOC(MTYPE_TMP, sizeof(*new));
	memcpy(&new->nexthop, &pnhc->nexthop, sizeof(struct nexthop));

	zlog_debug("Sending nexthop to Zebra");
	pbr_send_rnh(&new->nexthop, true);

	return new;
}

static uint32_t pbr_nh_hash_key(void *arg)
{
	uint32_t key;
	struct pbr_nexthop_cache *pbrnc = (struct pbr_nexthop_cache *)arg;

	key = jhash_1word(pbrnc->nexthop.vrf_id, 0x45afe398);
	key = jhash_1word(pbrnc->nexthop.ifindex, key);
	key = jhash_1word(pbrnc->nexthop.type, key);
	key = jhash(&pbrnc->nexthop.gate, sizeof(union g_addr), key);

	return key;
}

static int pbr_nh_hash_equal(const void *arg1, const void *arg2)
{
	const struct pbr_nexthop_cache *pbrnc1 =
		(const struct pbr_nexthop_cache *)arg1;
	const struct pbr_nexthop_cache *pbrnc2 =
		(const struct pbr_nexthop_cache *)arg2;

	if (pbrnc1->nexthop.vrf_id != pbrnc2->nexthop.vrf_id)
		return 0;

	if (pbrnc1->nexthop.ifindex != pbrnc2->nexthop.ifindex)
		return 0;

	if (pbrnc1->nexthop.type != pbrnc2->nexthop.type)
		return 0;

	switch (pbrnc1->nexthop.type) {
	case NEXTHOP_TYPE_IFINDEX:
		return 1;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV4:
		return pbrnc1->nexthop.gate.ipv4.s_addr
		       == pbrnc2->nexthop.gate.ipv4.s_addr;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_IPV6:
		return !memcmp(&pbrnc1->nexthop.gate.ipv6,
			       &pbrnc2->nexthop.gate.ipv6, 16);
	case NEXTHOP_TYPE_BLACKHOLE:
		return pbrnc1->nexthop.bh_type == pbrnc2->nexthop.bh_type;
	}

	/*
	 * We should not get here
	 */
	return 0;
}

static uint32_t pbr_nhg_hash_key(void *arg)
{
	struct pbr_nexthop_group_cache *nhgc =
		(struct pbr_nexthop_group_cache *)arg;

	return jhash(&nhgc->name, strlen(nhgc->name), 0x52c34a96);
}

static int pbr_nhg_hash_equal(const void *arg1, const void *arg2)
{
	const struct pbr_nexthop_group_cache *nhgc1 =
		(const struct pbr_nexthop_group_cache *)arg1;
	const struct pbr_nexthop_group_cache *nhgc2 =
		(const struct pbr_nexthop_group_cache *)arg2;

	return !strcmp(nhgc1->name, nhgc2->name);
}

void pbr_nht_init(void)
{
	pbr_nh_hash = hash_create_size(16, pbr_nh_hash_key, pbr_nh_hash_equal,
				       "PBR NH Cache Hash");

	pbr_nhg_hash = hash_create_size(
		16, pbr_nhg_hash_key, pbr_nhg_hash_equal, "PBR NHG Cache Hash");
}
