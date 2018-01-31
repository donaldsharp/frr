/*
 * Nexthop Group structure definition.
 * Copyright (C) 2018 Cumulus Networks, Inc.
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

#include <nexthop.h>
#include <nexthop_group.h>
#include <vty.h>
#include <command.h>

static __inline int
nexthop_group_cmd_compare(const struct nexthop_group_cmd *nhgc1,
			  const struct nexthop_group_cmd *nhgc2);
RB_GENERATE(nhgc_entry_head, nexthop_group_cmd, nhgc_entry,
	    nexthop_group_cmd_compare)

struct nhgc_entry_head nhgc_entries;

static __inline int
nexthop_group_cmd_compare(const struct nexthop_group_cmd *nhgc1,
			  const struct nexthop_group_cmd *nhgc2)
{
	return strcmp(nhgc1->name, nhgc2->name);
}

/* Add nexthop to the end of a nexthop list.  */
void nexthop_add(struct nexthop **target, struct nexthop *nexthop)
{
	struct nexthop *last;

	for (last = *target; last && last->next; last = last->next)
		;
	if (last)
		last->next = nexthop;
	else
		*target = nexthop;
	nexthop->prev = last;
}

void copy_nexthops(struct nexthop **tnh, struct nexthop *nh,
		   struct nexthop *rparent)
{
	struct nexthop *nexthop;
	struct nexthop *nh1;

	for (nh1 = nh; nh1; nh1 = nh1->next) {
		nexthop = nexthop_new();
		nexthop->ifindex = nh1->ifindex;
		nexthop->type = nh1->type;
		nexthop->flags = nh1->flags;
		memcpy(&nexthop->gate, &nh1->gate, sizeof(nh1->gate));
		memcpy(&nexthop->src, &nh1->src, sizeof(nh1->src));
		memcpy(&nexthop->rmap_src, &nh1->rmap_src, sizeof(nh1->rmap_src));
		nexthop->rparent = rparent;
		if (nh1->nh_label)
			nexthop_add_labels(nexthop, nh1->nh_label_type,
					   nh1->nh_label->num_labels,
					   &nh1->nh_label->label[0]);
		nexthop_add(tnh, nexthop);

		if (CHECK_FLAG(nh1->flags, NEXTHOP_FLAG_RECURSIVE))
			copy_nexthops(&nexthop->resolved, nh1->resolved,
				      nexthop);
	}
}

static void nhgc_delete_nexthops(struct nexthop_group_cmd *nhgc)
{
	/*
	 * Future Work Here
	 */
	return;
}

static struct nexthop_group_cmd *nhgc_find(const char *name)
{
	struct nexthop_group_cmd find;

	strlcpy(find.name, name, sizeof(find.name));

	return RB_FIND(nhgc_entry_head, &nhgc_entries, &find);
}

static struct nexthop_group_cmd *nhgc_get(const char *name)
{
	struct nexthop_group_cmd *nhgc;

	nhgc = nhgc_find(name);
	if (!nhgc) {
		nhgc = XCALLOC(MTYPE_TMP, sizeof(*nhgc));
		strcpy(nhgc->name, name);

		RB_INSERT(nhgc_entry_head, &nhgc_entries, nhgc);
	}

	return nhgc;
}

static void nhgc_delete(struct nexthop_group_cmd *nhgc)
{
	nhgc_delete_nexthops(nhgc);
	RB_REMOVE(nhgc_entry_head, &nhgc_entries, nhgc);
}

DEFINE_QOBJ_TYPE(nexthop_group_cmd)

DEFUN_NOSH(nexthop_group, nexthop_group_cmd, "nexthop-group NAME",
	   "Enter into the nexthop-group submode\n"
	   "Specify the NAME of the nexthop-group\n")
{
	const char *nhg_name = argv[1]->arg;
	struct nexthop_group_cmd *nhgc = NULL;

	nhgc = nhgc_get(nhg_name);
	VTY_PUSH_CONTEXT(NH_GROUP_NODE, nhgc);

	return CMD_SUCCESS;
}

DEFUN_NOSH(no_nexthop_group, no_nexthop_group_cmd, "no nexthop-group NAME",
	   NO_STR
	   "Enter into the nexthop-group submode\n"
	   "Specify the NAME of the nexthop-group\n")
{
	const char *nhg_name = argv[2]->arg;
	struct nexthop_group_cmd *nhgc = NULL;

	nhgc = nhgc_find(nhg_name);
	if (nhgc)
		nhgc_delete(nhgc);

	return CMD_SUCCESS;
}

struct cmd_node nexthop_group_node = {
	NH_GROUP_NODE,
	"%s(config-nh-group)# ",
	1
};

static int nexthop_group_write(struct vty *vty)
{
	struct nexthop_group_cmd *nhgc;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		vty_out(vty, "nexthop-group %s\n", nhgc->name);
		vty_out(vty, "!\n");
	}

	return 1;
}

void nexthop_group_init(void)
{
	RB_INIT(nhgc_entry_head, &nhgc_entries);
	install_node(&nexthop_group_node, nexthop_group_write);
	install_element(CONFIG_NODE, &nexthop_group_cmd);
	install_element(CONFIG_NODE, &no_nexthop_group_cmd);
}
