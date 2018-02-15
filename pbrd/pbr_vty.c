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
#include "vrf.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "log.h"
#include "json.h"

#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_map.h"
#include "pbrd/pbr_zebra.h"
#include "pbrd/pbr_vty.h"
#include "pbrd/pbr_event.h"
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
	struct pbr_map_sequence *pbrms;

	pbrms = pbrms_get(pbrm_name, seqno);
	VTY_PUSH_CONTEXT(PBRMAP_NODE, pbrms);

	return CMD_SUCCESS;
}

DEFPY (pbr_map_match_src,
       pbr_map_match_src_cmd,
       "match src-ip <A.B.C.D/M|X:X::X:X/M>$prefix",
       "Match the rest of the command\n"
       "Choose the src ip or ipv6 prefix to use\n"
       "v4 Prefix\n"
       "v6 Prefix\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	struct pbr_event *pbre;

	if (!pbrms->src)
		pbrms->src = prefix_new();

	prefix_copy(pbrms->src, prefix);

	pbre = pbr_event_new();
	pbre->event = PBR_MAP_MODIFY;
	strlcpy(pbre->name, pbrms->parent->name, sizeof(pbre->name));
	pbr_event_enqueue(pbre);

	return CMD_SUCCESS;
}

DEFPY (pbr_map_match_dst,
       pbr_map_match_dst_cmd,
       "match dst-ip <A.B.C.D/M|X:X::X:X/M>$prefix",
       "Match the rest of the command\n"
       "Choose the src ip or ipv6 prefix to use\n"
       "v4 Prefix\n"
       "v6 Prefix\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	struct pbr_event *pbre;

	if (!pbrms->dst)
		pbrms->dst = prefix_new();

	prefix_copy(pbrms->dst, prefix);

	pbre = pbr_event_new();
	pbre->event = PBR_MAP_MODIFY;
	strlcpy(pbre->name, pbrms->parent->name, sizeof(pbre->name));
	pbr_event_enqueue(pbre);

	return CMD_SUCCESS;
}

DEFPY (pbr_map_nexthop_group,
       pbr_map_nexthop_group_cmd,
       "set nexthop-group NAME$name",
       "Set for the PBR-MAP\n"
       "nexthop-group to use\n"
       "The name of the nexthop-group\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	struct nexthop_group_cmd *nhgc;
	struct pbr_event *pbre;

	nhgc = nhgc_find(name);
	if (!nhgc) {
		vty_out(vty, "Specified nexthop-group %s does not exist\n",
			name);
		vty_out(vty, "PBR-MAP will not be applied until it is created\n");
	}

	if (pbrms->nhgrp_name)
		XFREE(MTYPE_TMP, pbrms->nhgrp_name);

	pbrms->nhgrp_name = XSTRDUP(MTYPE_TMP, name);

	pbre = pbr_event_new();
	pbre->event = PBR_MAP_MODIFY;
	strlcpy(pbre->name, pbrms->parent->name, sizeof(pbre->name));
	pbr_event_enqueue(pbre);

	return CMD_SUCCESS;
}

DEFPY (pbr_table_range,
       pbr_table_range_cmd,
       "[no]$no pbr table range (5000-65535)$start (6000-65535)$end",
       NO_STR
       "Policy based routing\n"
       "Policy based routing table\n"
       "Table range\n"
       "Initial value of range\n"
       "Final value of range\n")
{
	if (no)
		pbr_nht_set_tableid_range(PBR_NHT_DEFAULT_LOW_TABLEID,
					  PBR_NHT_DEFAULT_HIGH_TABLEID);
	else
		pbr_nht_set_tableid_range(start, end);

	return CMD_SUCCESS;
}

DEFPY (pbr_rule_range,
	pbr_rule_range_cmd,
	"[no] pbr rule range (5000-65535)$start (6000-65535)$end",
	NO_STR
	"Policy based routing\n"
	"Policy based routing rule\n"
	"Rule range\n"
	"Initial value of range\n"
	"Final value of range\n")
{
	if (no)
		pbr_nht_set_rule_range(PBR_NHT_DEFAULT_LOW_RULE,
				       PBR_NHT_DEFAULT_HIGH_RULE);
	else
		pbr_nht_set_rule_range(start, end);

	return CMD_SUCCESS;
}

DEFPY (pbr_policy,
       pbr_policy_cmd,
       "pbr-policy NAME$mapname",
       "Policy to use\n"
       "Name of the pbr-map to apply\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct pbr_map *pbrm;

	/*
	 * In the future we would probably want to
	 * allow pre-creation of the pbr-map
	 * here.  But for getting something
	 * up and running let's not do that yet.
	 */
	pbrm = pbrm_find(mapname);
	if (!pbrm) {
		struct pbr_interface *pbr_ifp = ifp->info;

		strcpy(pbr_ifp->mapname, mapname);
		vty_out (vty, "storing mapname %s on pbr_ifp\n", pbr_ifp->mapname);
	} else
		pbr_map_add_interface(pbrm, ifp);

	return CMD_SUCCESS;
}

DEFPY (show_pbr,
	show_pbr_cmd,
	"show pbr [json$json]",
	SHOW_STR
	"Policy Based Routing\n"
	JSON_STR)
{
	pbr_nht_write_table_range(vty);
	pbr_nht_write_rule_range(vty);

	return CMD_SUCCESS;
}

DEFPY (show_pbr_map,
	show_pbr_map_cmd,
	"show pbr map [NAME$name] [detail$detail] [json$json]",
	SHOW_STR
	"Policy Based Routing\n"
	"PBR Map\n"
	"PBR Map Name\n"
	"Detailed information\n"
	JSON_STR)
{
	struct pbr_map_sequence *pbrms;
	struct pbr_map *pbrm;
	struct listnode *node;
	char buf[PREFIX_STRLEN];

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		if (!name || (strcmp(name, pbrm->name) == 0)) {
			vty_out(vty, "  pbr-map %s valid: %d installed: %d\n",
				pbrm->name, pbrm->valid, pbrm->installed);

			for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node,
						  pbrms)) {
				vty_out(vty,
					"\tSeq: %u rule: %u Reason: %" PRIu64
					"\n",
					pbrms->seqno, pbrms->ruleno,
					pbrms->reason);
				if (pbrms->src)
					vty_out(vty, "\tSRC Match: %s\n",
						prefix2str(pbrms->src, buf,
							   sizeof(buf)));
				if (pbrms->dst)
					vty_out(vty, "\tDST Match: %s\n",
						prefix2str(pbrms->dst, buf,
							   sizeof(buf)));
				vty_out(vty,
					"\tNexthop-Group: %s Installed: %u\n",
					(pbrms->nhgrp_name)
						? pbrms->nhgrp_name
						: "Not Yet Specified",
					pbrms->nhs_installed);
			}
		}
	}
	return CMD_SUCCESS;
}

DEFPY (show_pbr_interface,
	show_pbr_interface_cmd,
	"show pbr interface [NAME$name] [json$json]",
	SHOW_STR
	"Policy Based Routing\n"
	"PBR Interface\n"
	"PBR Interface Name\n"
	JSON_STR)
{
        struct pbr_map *pbrm;
        struct listnode *node;
        struct interface *ifp;

        RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
                for (ALL_LIST_ELEMENTS_RO(pbrm->incoming, node, ifp)) {
                        if (!name || (strcmp(ifp->name, name) == 0)) {
				vty_out(vty, "  %s(%d) with pbr-policy %s\n",
					ifp->name, ifp->ifindex, pbrm->name);
				break;
                        }
                }
        }

	return CMD_SUCCESS;
}

static struct cmd_node interface_node = {
	INTERFACE_NODE, "%s(config-if)# ", 1 /* vtysh ? yes */
};

static int pbr_interface_config_write(struct vty *vty)
{
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (vrf->vrf_id == VRF_DEFAULT)
				vty_frame(vty, "interface %s\n", ifp->name);
			else
				vty_frame(vty, "interface %s vrf %s\n",
					  ifp->name, vrf->name);

			pbr_map_write_interfaces(vty, ifp);

			vty_endframe(vty, "!\n");
		}
	}

	return 1;
}

/* PBR map node structure. */
static struct cmd_node pbr_map_node = {PBRMAP_NODE, "%s(config-pbr-map)# ", 1};

static int pbr_vty_map_config_write_sequence(struct vty *vty,
					     struct pbr_map *pbrm,
					     struct pbr_map_sequence *pbrms)
{
	char buff[PREFIX_STRLEN];

	vty_out (vty, "pbr-map %s seq %u\n",
		 pbrm->name, pbrms->seqno);

	if (pbrms->src)
		vty_out(vty, "  match src-ip %s\n",
			prefix2str(pbrms->src, buff, sizeof buff));

	if (pbrms->dst)
		vty_out(vty, "  match dst-ip %s\n",
			prefix2str(pbrms->dst, buff, sizeof buff));

	if (pbrms->nhgrp_name)
		vty_out(vty, "  set nexthop-group %s\n", pbrms->nhgrp_name);

	vty_out (vty, "!\n");
	return 1;
}

static int pbr_vty_map_config_write(struct vty *vty)
{
	struct pbr_map *pbrm;

	pbr_nht_write_table_range(vty);
	pbr_nht_write_rule_range(vty);

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
	install_element(CONFIG_NODE, &pbr_table_range_cmd);
	install_element(CONFIG_NODE, &pbr_rule_range_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_src_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_dst_cmd);
	install_element(PBRMAP_NODE, &pbr_map_nexthop_group_cmd);
	install_element(VIEW_NODE, &show_pbr_cmd);
	install_element(VIEW_NODE, &show_pbr_map_cmd);
	install_element(VIEW_NODE, &show_pbr_interface_cmd);

	return;
}
