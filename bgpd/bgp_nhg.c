// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Nexthop Group Support
 * Copyright (C) 2023 NVIDIA Corporation
 * Copyright (C) 2023 6WIND
 */

#include <zebra.h>

#include <bgpd/bgpd.h>
#include <bgpd/bgp_debug.h>
#include <bgpd/bgp_nhg.h>


/****************************************************************************
 * L3 NHGs are used for fast failover of nexthops in the dplane. These are
 * the APIs for allocating L3 NHG ids. Management of the L3 NHG itself is
 * left to the application using it.
 * PS: Currently there are 2 apps using bgp nhgs
 * 1. EVPN host routes using NHG for fast failover of remote ES links.
 * 2. Per Source NHG feature using BGP NHG
 ***************************************************************************/
static struct bgp_nhg_app_info bgp_nhg_app_info[APP_MAX];
static uint32_t bgp_nhg_start;

/* XXX - currently we do nothing on the callbacks */
static void bgp_nhg_add_cb(const char *name)
{
}

static void bgp_nhg_modify_cb(const struct nexthop_group_cmd *nhgc)
{
}

static void bgp_nhg_add_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				   const struct nexthop *nhop)
{
}

static void bgp_nhg_del_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				   const struct nexthop *nhop)
{
}

static void bgp_nhg_del_cb(const char *name)
{
}

static void bgp_nhg_zebra_init(void)
{
	static bool bgp_nhg_zebra_inited;
	if (bgp_nhg_zebra_inited)
		return;

	bgp_nhg_zebra_inited = true;
	bgp_nhg_start = zclient_get_nhg_start(ZEBRA_ROUTE_BGP);
        nexthop_group_init(bgp_nhg_add_cb, bgp_nhg_modify_cb,
                           bgp_nhg_add_nexthop_cb, bgp_nhg_del_nexthop_cb,
                           bgp_nhg_del_cb);
}

void bgp_nhg_init(void)
{
	uint32_t cumulative_offset = 0;
	bgp_nhg_start = zclient_get_nhg_start(ZEBRA_ROUTE_BGP);

	for (enum bgp_nhg_app app = EVPN_MH; app < APP_MAX; app++) {
		if (app == EVPN_MH) {
			bgp_nhg_app_info[app].id_max = MIN(ZEBRA_NHG_PROTO_SPACING - 1,
							   EVPN_MH_NH_ID_SPACE);
		} else if (app == PER_SRC_NHG) {
			bgp_nhg_app_info[app].id_max = MIN(ZEBRA_NHG_PROTO_SPACING - 1,
							   PER_SRC_NH_ID_SPACE);
		} else {
			bgp_nhg_app_info[app].id_max = MIN(ZEBRA_NHG_PROTO_SPACING - 1,
							   DEFAULT_ID_SPACE);
		}

		bgp_nhg_app_info[app].start_id = bgp_nhg_start + cumulative_offset;
		cumulative_offset += bgp_nhg_app_info[app].id_max;

		bf_init(bgp_nhg_app_info[app].bitmap, bgp_nhg_app_info[app].id_max);
		bf_assign_zero_index(bgp_nhg_app_info[app].bitmap);

		if (BGP_DEBUG(nht, NHT) || BGP_DEBUG(evpn_mh, EVPN_MH_ES)) {
			uint32_t start = bgp_nhg_app_info[app].start_id + 1;
			uint32_t end = bgp_nhg_app_info[app].start_id + bgp_nhg_app_info[app].id_max;
			zlog_debug("bgp nhg range for APP%d: %u - %u", app + 1, start, end);
		}
	}
}

void bgp_nhg_finish(void)
{
	for (enum bgp_nhg_app app = EVPN_MH; app < APP_MAX; app++) {
		bf_free(bgp_nhg_app_info[app].bitmap);
	}
}

uint32_t bgp_nhg_id_alloc(enum bgp_nhg_app app)
{
	if (app >= APP_MAX)
		return 0;

	uint32_t nhg_id = 0;

	bgp_nhg_zebra_init();
	bf_assign_index(bgp_nhg_app_info[app].bitmap, nhg_id);
	if (nhg_id)
		nhg_id += bgp_nhg_app_info[app].start_id;

	return nhg_id;
}

void bgp_nhg_id_free(enum bgp_nhg_app app, uint32_t nhg_id)
{
	if (app >= APP_MAX || !nhg_id || (nhg_id <= bgp_nhg_app_info[app].start_id))
		return;

	nhg_id = nhg_id - bgp_nhg_app_info[app].start_id;

	bf_release_index(bgp_nhg_app_info[app].bitmap, nhg_id);
}
