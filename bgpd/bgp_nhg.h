// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Nexthop Group Support
 * Copyright (C) 2023 NVIDIA Corporation
 * Copyright (C) 2023 6WIND
 */

#ifndef _BGP_NHG_H
#define _BGP_NHG_H

#include "nexthop_group.h"

typedef enum { EVPN_MH = 0, PER_SRC_NHG = 1, APP_MAX } bgp_nhg_app_t;

typedef struct {
	bitfield_t bitmap;
	uint32_t start_id;
	uint32_t id_max;
} bgp_nhg_app_info_t;

#define EVPN_MH_NH_ID_SPACE (16 * 1024)
#define PER_SRC_NH_ID_SPACE (16 * 1024)
#define DEFAULT_ID_SPACE    (16 * 1024)

/* APIs for setting up and allocating L3 nexthop group ids */
extern uint32_t bgp_nhg_id_alloc(bgp_nhg_app_t app);
extern void bgp_nhg_id_free(bgp_nhg_app_t app, uint32_t nhg_id);
extern void bgp_nhg_init(void);
void bgp_nhg_finish(void);

#endif /* _BGP_NHG_H */
