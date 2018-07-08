#ifndef __ZEBRA_NHGS_H__
#define __ZEBRA_NHGS_H__

#if defined DEV_BUILD

struct nhgs_hash_entry {
	uint32_t table;

	afi_t afi;
	safi_t safi;

	struct nexthop_group nhg;

	uint32_t refcnt;
};

extern uint32_t zebra_nhgs_hash_key(void *arg);
extern int zebra_nhgs_hash_equal(const void *arg1, const void *arg2);

extern void zebra_nhg_find(afi_t afi, safi_t safi, struct route_entry *re);
#endif

#endif
