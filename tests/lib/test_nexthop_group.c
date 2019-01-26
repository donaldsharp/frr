/*
 * Nexthop Group Testing
 *
 * Copyright (C) 2019 by Cumulus Networks, Inc.
 *                       Donald Sharp
 *
 * This file is part of FRR
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

#include "mpls.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "vty.h"
#include "vrf.h"
#include "qobj.h"

/*
 * So we are cheating, use flags to indicate where in the
 * list of nexthops we want this to show up
 */
struct nexthop nhop_array[] = {
	{
		.vrf_id = 0,
		.ifindex = 0,
		.type = NEXTHOP_TYPE_IPV4,
		.gate.ipv4.s_addr = 0x01000000,
		.nh_label_type = ZEBRA_LSP_NONE,
	},
	{
		.vrf_id = 2,
		.ifindex = 0,
		.type = NEXTHOP_TYPE_IPV4,
		.gate.ipv4.s_addr = 0x04000000,
		.nh_label_type = ZEBRA_LSP_NONE,
	},
	{
		.vrf_id = 1,
		.ifindex = 0,
		.type = NEXTHOP_TYPE_IPV4,
		.gate.ipv4.s_addr = 0x04000000,
		.nh_label_type = ZEBRA_LSP_NONE,
	},
	{
		.vrf_id = 0,
		.ifindex = 0,
		.type = NEXTHOP_TYPE_IPV4,
		.gate.ipv4.s_addr = 0x06000000,
		.nh_label_type = ZEBRA_LSP_NONE,
	},
	{
		.vrf_id = 0,
		.ifindex = 0,
		.type = NEXTHOP_TYPE_IPV4,
		.gate.ipv4.s_addr = 0x03000000,
		.nh_label_type = ZEBRA_LSP_NONE,
	},
	{
		.vrf_id = 2,
		.ifindex = 0,
		.type = NEXTHOP_TYPE_IPV4,
		.gate.ipv4.s_addr = 0x03000000,
		.nh_label_type = ZEBRA_LSP_NONE,
	},
};

static void dump_nhg(struct vty *vty, struct nexthop_group *nhg)
{
	struct nexthop *nhop;

	for (ALL_NEXTHOPS_PTR(nhg, nhop))
		nexthop_group_write_nexthop(vty, nhop);
}

int main(int argc, char **argv)
{
	uint32_t i;
	uint32_t array_size;
	struct nexthop_group nhg = { .nexthop = NULL };
	struct vty *vty = vty_new();

	vty->type = VTY_SHELL;

	/*
	 * We need to create some fake vrf structures for testing
	 */
	qobj_init();
	vrf_init(NULL, NULL, NULL, NULL, NULL);
	vrf_get(1, "TESTONE");
	vrf_get(2, "TESTTWO");

	array_size = sizeof(nhop_array)/sizeof(struct nexthop);
	for (i = 0; i < array_size; i++)
	{
		nexthop_group_add_sorted(&nhg, &nhop_array[i]);
	}

	dump_nhg(vty, &nhg);
}
