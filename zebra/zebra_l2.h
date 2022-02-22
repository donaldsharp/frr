/*
 * Zebra Layer-2 interface Data structures and definitions
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
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

#ifndef _ZEBRA_L2_H
#define _ZEBRA_L2_H

#include <zebra.h>

#include "if.h"
#include "vlan.h"
#include "vxlan.h"

#ifdef __cplusplus
extern "C" {
#endif

/* zebra L2 interface information - bridge slave (linkage to bridge) */
struct zebra_l2info_brslave {
	ifindex_t bridge_ifindex; /* Bridge Master */
	struct interface *br_if;  /* Pointer to master */
};

struct zebra_l2info_bond {
	struct list *mbr_zifs; /* slaves using this bond as a master */
};

struct zebra_l2_bridge_vlan {
	vlanid_t vid;
	struct zebra_evpn_access_bd *access_bd;
};

struct zebra_l2_brvlan_mac {
	struct interface *br_if;
	vlanid_t vid;
	struct ethaddr macaddr;
	ifindex_t ifindex;
};

struct zebra_l2_bridge_if_ctx {
	/* input */
	struct zebra_if *zif;
	int (*func)(struct zebra_if *, struct zebra_l2_bridge_vlan *, void *);

	/* input-output */
	void *arg;
};

struct zebra_l2_brvlan_mac_ctx {
	/* input */
	struct interface *br_if;
	vlanid_t vid;
	int (*func)(struct interface *br_if, vlanid_t vid,
		    struct ethaddr *macaddr, ifindex_t ifidx, void *arg);

	/* input-output */
	void *arg;
};

struct zebra_l2_bridge_if {
	uint8_t vlan_aware;
	struct zebra_if *br_zif;
	struct hash *vlan_table;
	struct hash *mac_table[VLANID_MAX];
};

/* zebra L2 interface information - bridge interface */
struct zebra_l2info_bridge {
	struct zebra_l2_bridge_if bridge;
};

/* zebra L2 interface information - VLAN interface */
struct zebra_l2info_vlan {
	vlanid_t vid; /* VLAN id */
};

struct zebra_vxlan_vni {
	vni_t vni;		/* VNI */
	vlanid_t access_vlan;	/* Access VLAN - for VLAN-aware bridge. */
	struct in_addr mcast_grp;
};

typedef enum {
	ZEBRA_VXLAN_IF_VNI = 0, /* per vni vxlan if */
	ZEBRA_VXLAN_IF_SVD      /* single vxlan device */
} zebra_vxlan_iftype_t;

struct zebra_vxlan_if_vlan_ctx {
	vlanid_t vid;
	struct zebra_vxlan_vni *vni;
};

struct zebra_vxlan_if_update_ctx {
	uint16_t chgflags;
	struct in_addr old_vtep_ip;
	struct zebra_vxlan_vni old_vni;
	struct hash *old_vni_table;
};

struct zebra_vxlan_if_ctx {
	/* input */
	struct zebra_if *zif;
	int (*func)(struct zebra_if*, struct zebra_vxlan_vni *, void *);

	/* input-output */
	void *arg;
};

struct zebra_vxlan_vni_info {
	zebra_vxlan_iftype_t iftype;
	union {
		struct zebra_vxlan_vni vni; /* per vni vxlan device vni info */
		struct hash *vni_table;	    /* table of vni's assocated with this if */
	};
};

/* zebra L2 interface information - VXLAN interface */
struct zebra_l2info_vxlan {
	struct zebra_vxlan_vni_info vni_info;
	struct in_addr vtep_ip; /* Local tunnel IP */
	ifindex_t ifindex_link; /* Interface index of interface
				 * linked with VXLAN
				 */
	ns_id_t link_nsid;
};

struct zebra_l2info_bondslave {
	ifindex_t bond_ifindex;    /* Bridge Master */
	struct interface *bond_if; /* Pointer to master */
};

union zebra_l2if_info {
	struct zebra_l2info_bridge br;
	struct zebra_l2info_vlan vl;
	struct zebra_l2info_vxlan vxl;
};

/* NOTE: These macros are to be invoked only in the "correct" context.
 * IOW, the macro VNI_FROM_ZEBRA_IF() will assume the interface is
 * of type ZEBRA_IF_VXLAN.
 */
#define VNI_INFO_FROM_ZEBRA_IF(zif) (&((zif)->l2info.vxl.vni_info))
#define IS_ZEBRA_VXLAN_IF_SVD(zif) ((zif)->l2info.vxl.vni_info.iftype == ZEBRA_VXLAN_IF_SVD)
#define IS_ZEBRA_VXLAN_IF_VNI(zif) ((zif)->l2info.vxl.vni_info.iftype == ZEBRA_VXLAN_IF_VNI)
#define VLAN_ID_FROM_ZEBRA_IF(zif) (zif)->l2info.vl.vid

#define BRIDGE_FROM_ZEBRA_IF(zif) (&((zif)->l2info.br.bridge))
#define IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif) ((zif)->l2info.br.bridge.vlan_aware == 1)

extern void zebra_l2_map_slave_to_bridge(struct zebra_l2info_brslave *br_slave);
extern void
zebra_l2_unmap_slave_from_bridge(struct zebra_l2info_brslave *br_slave);
extern void zebra_l2_bridge_add_update(struct interface *ifp,
				       struct zebra_l2info_bridge *bridge_info,
				       int add);
extern void zebra_l2_bridge_del(struct interface *ifp);
extern void zebra_l2_vlanif_update(struct interface *ifp,
				   struct zebra_l2info_vlan *vlan_info);
extern void zebra_l2_vxlanif_add_update(struct interface *ifp,
					struct zebra_l2info_vxlan *vxlan_info,
					int add);
extern void zebra_l2_vxlanif_update_access_vlan(struct interface *ifp,
						vlanid_t access_vlan);
extern void zebra_l2_vxlanif_del(struct interface *ifp);
extern void zebra_l2if_update_bridge_slave(struct interface *ifp,
					   ifindex_t bridge_ifindex);

extern void zebra_l2if_update_bond_slave(struct interface *ifp,
					 ifindex_t bond_ifindex, bool bypass);
extern void zebra_vlan_bitmap_compute(struct interface *ifp,
		uint32_t vid_start, uint16_t vid_end);
extern void zebra_vlan_mbr_re_eval(struct interface *ifp,
		bitfield_t vlan_bitmap);
extern void zebra_l2if_update_bond(struct interface *ifp, bool add);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_L2_H */
