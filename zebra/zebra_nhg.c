/* Zebra NHG Code.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include "zebra.h"

#include "nexthop.h"
#include "nexthop_group.h"
#include "jhash.h"

#include "zebra_router.h"
#include "zebra_nhg.h"

static void *zebra_nhg_alloc(void *arg)
{
	struct nhg_hash_entry *nhe;
	struct nhg_hash_entry *copy = arg;

	nhe = XMALLOC(MTYPE_TMP, sizeof(struct nhg_hash_entry));

	nhe->vrf_id = copy->vrf_id;
	nhe->afi = copy->afi;
	nhe->refcnt = 0;
	nhe->dplane_ref = zebra_router_get_next_sequence();
	nhe->nhg.nexthop = NULL;

	nexthop_group_copy(&nhe->nhg, &copy->nhg);
	return nhe;
}

static uint32_t zebra_nhg_hash_key_nexthop_group(struct nexthop_group *nhg)
{
	struct nexthop *nh;
	uint32_t i;
	uint32_t key = 0;

	/*
	 * We are not interested in hashing over any recursively
	 * resolved nexthops
	 */
	for (nh = nhg->nexthop; nh; nh = nh->next) {
		key = jhash_2words(nh->vrf_id, nh->nh_label_type, key);
		/* gate and blackhole are together in a union */
		key = jhash(&nh->gate, sizeof(nh->gate), key);
		key = jhash(&nh->src, sizeof(nh->src), key);
		key = jhash(&nh->rmap_src, sizeof(nh->rmap_src), key);
		if (nh->nh_label) {
			for (i = 0; i < nh->nh_label->num_labels; i++)
				key = jhash_1word(nh->nh_label->label[i], key);
		}
		switch (nh->type) {
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IFINDEX:
			key = jhash_1word(nh->ifindex, key);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV6:
			break;
		}
	}
	return key;
}

uint32_t zebra_nhg_hash_key(void *arg)
{
	struct nhg_hash_entry *nhe = arg;
	int key = 0x5a351234;

	key = jhash_2words(nhe->vrf_id, nhe->afi, key);

	return jhash_1word(zebra_nhg_hash_key_nexthop_group(&nhe->nhg), key);
}

bool zebra_nhg_hash_equal(const void *arg1, const void *arg2)
{
	const struct nhg_hash_entry *nhe1 = arg1;
	const struct nhg_hash_entry *nhe2 = arg2;
	struct nexthop *nh1, *nh2;
	uint32_t nh_count = 0;

	if (nhe1->vrf_id != nhe2->vrf_id)
		return false;

	if (nhe1->afi != nhe2->afi)
		return false;

	/*
	 * Again we are not interested in looking at any recursively
	 * resolved nexthops.  Top level only
	 */
	for (nh1 = nhe1->nhg.nexthop; nh1; nh1 = nh1->next) {
		uint32_t inner_nh_count = 0;
		for (nh2 = nhe2->nhg.nexthop; nh2; nh2 = nh2->next) {
			if (inner_nh_count == nh_count) {
				break;
			}
			inner_nh_count++;
		}

		if (!nexthop_same(nh1, nh2))
			return false;

		nh_count++;
	}

	return true;
}

void zebra_nhg_find(afi_t afi, struct nexthop_group *nhg,
		    struct route_entry *re)
{
	struct nhg_hash_entry lookup, *nhe;

	memset(&lookup, 0, sizeof(lookup));
	lookup.vrf_id = re->vrf_id;
	lookup.afi = afi;
	lookup.nhg = *nhg;

	nhe = hash_get(zrouter.nhgs, &lookup, zebra_nhg_alloc);
	nhe->refcnt++;

	//re->ng = nhe->nhg;

	return;
}

void zebra_nhg_release(afi_t afi, struct route_entry *re)
{
	struct nhg_hash_entry lookup, *nhe;

	lookup.vrf_id = re->vrf_id;
	lookup.afi = afi;
	lookup.nhg = re->ng;

	nhe = hash_lookup(zrouter.nhgs, &lookup);
	nhe->refcnt--;

	if (nhe->refcnt == 0)
		hash_release(zrouter.nhgs, nhe);
	// re->ng = NULL;
}

static void zebra_nhg_new(const char *name)
{
}

static void zebra_nhg_add_nexthop(const struct nexthop_group_cmd *nhgc,
				  const struct nexthop *nhop)
{
}

static void zebra_nhg_del_nexthop(const struct nexthop_group_cmd *nhgc,
				  const struct nexthop *nhop)
{
}

static void zebra_nhg_delete(const char *name)
{
}

void zebra_nhg_init(void)
{
	nexthop_group_init(zebra_nhg_new,
			   zebra_nhg_add_nexthop,
			   zebra_nhg_del_nexthop,
			   zebra_nhg_delete);
}

void zebra_nhg_terminate(void)
{
	nexthop_group_init(NULL, NULL, NULL, NULL);
}
