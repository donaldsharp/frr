#include <zebra.h>

#include <nexthop.h>
#include <nexthop_group.h>
#include <hash.h>
#include <jhash.h>

#include "rib.h"
#include "zebra_nhgs.h"
#include "zebra_vrf.h"

#if defined DEV_BUILD

static uint32_t temp_dplane_ref = 1;

static void *zebra_nhgs_alloc(void *arg)
{
	struct nhgs_hash_entry *nhe;
	struct nhgs_hash_entry *copy = arg;

	nhe = XMALLOC(MTYPE_TMP, sizeof(struct nhgs_hash_entry));

	nhe->vrf_id = copy->vrf_id;
	nhe->afi = copy->afi;
	nhe->refcnt = 0;
	nhe->dplane_ref = temp_dplane_ref++;
	nhe->nhg.nexthop = NULL;

	nexthop_group_copy(&nhe->nhg, &copy->nhg);
	return nhe;
}

static int zebra_nhgs_hash_key_nexthop_group(struct nexthop_group *nhg)
{
	struct nexthop *nh;
	int key = 0;

	for (ALL_NEXTHOPS((*nhg), nh)) {
		key = jhash(nh, sizeof(struct nexthop), key);
	}

	return key;
}

uint32_t zebra_nhgs_hash_key(void *arg)
{
	struct nhgs_hash_entry *nhe = arg;
	int key = 0x5a351234;

	key = jhash_2words(nhe->vrf_id, nhe->afi, key);

	return jhash_1word(zebra_nhgs_hash_key_nexthop_group(&nhe->nhg),
			   key);
}

int zebra_nhgs_hash_equal(const void *arg1, const void *arg2)
{
	const struct nhgs_hash_entry *nhe1 = arg1;
	const struct nhgs_hash_entry *nhe2 = arg2;
	struct nexthop *nh1, *nh2;
	uint32_t nh_count = 0;

	if (nhe1->vrf_id != nhe2->vrf_id)
		return 0;

	if (nhe1->afi != nhe2->afi)
		return 0;

	for (ALL_NEXTHOPS(nhe1->nhg, nh1)) {
		uint32_t inner_nh_count = 0;
		for (ALL_NEXTHOPS(nhe2->nhg, nh2)) {
			if (inner_nh_count == nh_count) {
				break;
			}
			inner_nh_count++;
		}

		if (!nexthop_same(nh1, nh2))
			return 0;

		nh_count++;
	}

	return 1;
}

void zebra_nhg_find(afi_t afi, struct route_entry *re)
{
	struct nhgs_hash_entry lookup, *nhe;
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_lookup_by_id(re->vrf_id);

	lookup.vrf_id = zvrf->vrf->vrf_id;
	lookup.afi = afi;
	lookup.nhg = re->ng;

	nhe = hash_get(zvrf->nhgs, &lookup, zebra_nhgs_alloc);
	nhe->refcnt++;

	return;
}
#endif
