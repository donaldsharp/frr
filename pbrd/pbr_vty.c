/*
 * PBR - vty code
 * Copyright (C) Cumulus Networks, Inc.
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
#include <zebra.h>

#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "nexthop.h"
#include "log.h"

#include "pbrd/pbr_zebra.h"
#include "pbrd/pbr_map.h"
#include "pbrd/pbr_vty.h"
#ifndef VTYSH_EXTRACT_PL
#include "pbrd/pbr_vty_clippy.c"
#endif

DEFUN_NOSH (pbr_map,
	    pbr_map_cmd,
	    "pbr-map WORD seq (1-65535)",
	    "Create pbr-map or enter pbr-map command mode\n"
	    "The name of the PBR MAP\n"
	    "Sequence to insert to/delete from existing pbr-map entry\n"
	    "Sequence number\n")
{
	const char *pbrm_name = argv[1]->arg;
	uint32_t seqno = atoi(argv[3]->arg);
	struct pbr_map *pbrm;

	pbrm = pbrm_get(pbrm_name, seqno);
	VTY_PUSH_CONTEXT(PBRMAP_NODE, pbrm);

	return CMD_SUCCESS;
}

DEFPY (pbr_policy,
       pbr_policy_cmd,
       "pbr-policy (1-100000)$seqno {src <A.B.C.D/M|X:X::X:X/M>$src|dest <A.B.C.D/M|X:X::X:X/M>$dst} nexthop-group NAME$nhgroup",
       "Policy to use\n"
       "Sequence Number\n"
       "The Source\n"
       "IP Address\n"
       "IPv6 Address\n"
       "dest\n"
       "IP Address\n"
       "IPv6 Address\n"
       "Nexthop group\n"
       "Name of the Nexthop Group\n")
{
	return CMD_SUCCESS;
}
static struct cmd_node interface_node = {
	INTERFACE_NODE, "%s(config-if)# ", 1 /* vtysh ? yes */
};

static int pbr_interface_config_write(struct vty *vty)
{
	vty_out(vty, "!\n");

	return 1;
}

/* PBR map node structure. */
static struct cmd_node pbr_map_node = {PBRMAP_NODE, "%s(config-pbr-map)# ", 1};

static int pbr_vty_map_config_write_sequence(struct vty *vty,
					     struct pbr_map *pbrm,
					     struct pbr_map_sequence *pbrms)
{
	vty_out (vty, "pbr-map %s seq %u\n",
		 pbrm->name, pbrms->seqno);
	vty_out (vty, "!\n");
	return 1;
}

static int pbr_vty_map_config_write(struct vty *vty)
{
	struct pbr_map *pbrm;

	RB_FOREACH(pbrm, pbr_map_entry_head, &pbr_maps) {
		struct pbr_map_sequence *pbrms;
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms)) {
			pbr_vty_map_config_write_sequence(vty, pbrm, pbrms);
		}
	}

	return 1;
}

void pbr_vty_init(void)
{
	install_node(&interface_node,
		     pbr_interface_config_write);
	if_cmd_init();

	install_node(&pbr_map_node,
		     pbr_vty_map_config_write);

	install_default(PBRMAP_NODE);

	install_element(CONFIG_NODE, &pbr_map_cmd);
	install_element(INTERFACE_NODE, &pbr_policy_cmd);
	return;
}
