#include <zebra.h>

#include <nexthop.h>
#include <nexthop_group.h>
#include <hash.h>
#include <jhash.h>

#include "rib.h"
#include "zebra_nhgs.h"

#if defined DEV_BUILD

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

	key = jhash_3words(nhe->table, nhe->afi, nhe->safi, key);

	return jhash_1word(zebra_nhgs_hash_key_nexthop_group(&nhe->nhg),
			   key);
}

int zebra_nhgs_hash_equal(const void *arg1, const void *arg2)
{
	const struct nhgs_hash_entry *nhe1 = arg1;
	const struct nhgs_hash_entry *nhe2 = arg2;
	struct nexthop *nh1, *nh2;
	uint32_t nh_count = 0;

	if (nhe1->table != nhe2->table)
		return 0;

	if (nhe1->afi != nhe2->afi)
		return 0;

	if (nhe1->safi != nhe2->safi)
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

void zebra_nhg_find(afi_t afi, safi_t safi, struct route_entry *re)
{
	return;
}
#endif
