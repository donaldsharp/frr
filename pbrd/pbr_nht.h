/*
 * PBR-nht Header
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
#ifndef __PBR_NHT_H__
#define __PBR_NHT_H__

struct pbr_nexthop_cache {
	struct nexthop nexthop;

	bool valid;
};

struct pbr_nexthop_group_cache {
	char name[100];

	uint32_t table_id;

	struct list *pbrnhcache;

	/*
	 * If all nexthops are considered valid
	 */
	bool valid;
};

extern void pbr_nht_write_table_range(struct vty *vty);
#define PBR_NHT_DEFAULT_LOW_TABLEID 5000
#define PBR_NHT_DEFAULT_HIGH_TABLEID 6000
extern void pbr_nht_set_tableid_range(uint32_t low, uint32_t high);
extern uint32_t pbr_nht_get_next_tableid(void);

extern void pbr_nhgroup_add_cb(const char *name);
extern void pbr_nhgroup_modify_cb(const char *name);
extern void pbr_nhgroup_delete_cb(const char *name);

extern bool pbr_nht_nexthop_valid(struct nexthop *nhop);
extern bool pbr_nht_nexthop_group_valid(const char *name);

extern void pbr_nht_add_group(const char *name);
extern void pbr_nht_change_group(const char *name);
extern void pbr_nht_delete_group(const char *name);

extern void pbr_nht_init(void);
#endif
