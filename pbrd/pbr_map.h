/*
 * PBR-map Header
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
#ifndef __PBR_MAP_H__
#define __PBR_MAP_H__

struct pbr_map {
	/*
	 * RB Tree of the pbr_maps
	 */
	RB_ENTRY(pbr_map) pbr_map_entry;

	/*
	 * The name of the PBR_MAP
	 */
	char name[100];

	struct list *seqnumbers;

	/*
	 * The list of incoming interfaces that
	 * we will apply this policy map onto
	 */
	struct list *incoming;

	/*
	 * If valid is true we think the pbr_map is valid,
	 * If false, look in individual pbrms to see
	 * what we think is the invalid reason
	 */
	bool valid;

	/*
	 * Is this actually installed?
	 */
	bool installed;
};

RB_HEAD(pbr_map_entry_head, pbr_map);
RB_PROTOTYPE(pbr_map_entry_head, pbr_map, pbr_map_entry, pbr_map_compare)

struct pbr_map_sequence {
	struct pbr_map *parent;

	/*
	 * The sequence of where we are for display
	 */
	uint32_t seqno;

	/*
	 * The rule number to install into
	 */
	uint32_t ruleno;

	/*
	 * Our policy Catchers
	 */
	struct prefix *src;
	struct prefix *dst;

	/*
	 * The name of the nexthop group
	 */
	struct nexthop *nhop;
	char *nhgrp_name;
	bool nhs_installed;

	/*
	 * A reason of 0 means we think the pbr_map_sequence is good to go
	 * We can accumuluate multiple failure states
	 */
#define PBR_MAP_INVALID_NEXTHOP_GROUP (1 << 0)
#define PBR_MAP_INVALID_NEXTHOP (1 << 1)
#define PBR_MAP_INVALID_NO_NEXTHOPS (1 << 2)
#define PBR_MAP_INVALID_BOTH_NHANDGRP (1 << 3)
#define PBR_MAP_INVALID_SRCDST (1 << 4)
	uint64_t reason;

	QOBJ_FIELDS
};

DECLARE_QOBJ_TYPE(pbr_map_sequence)

extern struct pbr_map_entry_head pbr_maps;

extern struct pbr_map_sequence *pbrms_get(const char *name, uint32_t seqno);

extern struct pbr_map *pbrm_find(const char *name);

extern void pbr_map_add_interface(struct pbr_map *pbrm, struct interface *ifp);
extern void pbr_map_interface_delete(struct pbr_map *pbrm,
				     struct interface *ifp);
extern void pbr_map_write_interfaces(struct vty *vty, struct interface *ifp);
extern void pbr_map_init(void);

extern bool pbr_map_check_valid(const char *name);

extern void pbr_map_check_nh_group_change(const char *nh_group);
extern void pbr_map_check_policy_change(const char *name);
extern void pbr_map_add_interfaces(const char *name);

extern void pbr_map_schedule_policy_from_nhg(const char *nh_group);

extern void pbr_map_install(const char *name);

extern void pbr_map_policy_install(const char *name);
#endif
