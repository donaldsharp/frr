/* BGP community, large-community aliasing.
 *
 * Copyright (C) 2021 Donatas Abraitis <donatas.abraitis@gmail.com>
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "memory.h"
#include "linklist.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_community_alias.h"

struct list *bgp_community_alias_list = NULL;

static void bgp_community_alias_free(struct community_alias *ca)
{
	listnode_delete(bgp_community_alias_list, ca);
	XFREE(MTYPE_COMMUNITY_ALIAS_STR, ca->community);
	XFREE(MTYPE_COMMUNITY_ALIAS_STR, ca->alias);
	XFREE(MTYPE_COMMUNITY_ALIAS, ca);
}

void bgp_community_alias_list_free(void)
{
	struct community_alias *ca;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp_community_alias_list, node, nnode, ca))
		bgp_community_alias_free(ca);
}

void bgp_community_alias_list_add_entry(const char *community,
					const char *alias)
{
	struct community_alias *ca;

	ca = XCALLOC(MTYPE_COMMUNITY_ALIAS, sizeof(struct community_alias));

	if (community && alias) {
		ca->community = XSTRDUP(MTYPE_COMMUNITY_ALIAS_STR, community);
		ca->alias = XSTRDUP(MTYPE_COMMUNITY_ALIAS_STR, alias);
	}

	listnode_add(bgp_community_alias_list, ca);
}

void bgp_community_alias_list_remove_entry(const char *community)
{
	struct community_alias *ca;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp_community_alias_list, node, nnode, ca))
		if (strncmp(ca->community, community, strlen(community)) == 0)
			bgp_community_alias_free(ca);
}

bool bgp_community_alias_list_has_entry(const char *community,
					const char *alias)
{
	struct community_alias *ca;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp_community_alias_list, node, nnode, ca)) {
		/* Comparing strlen in addition to make sure we don't
		 * hit a trap between community and large communities. E.g:
		 * community       65001:1
		 * large-community 65001:1:1
		 */
		if (strlen(ca->community) == strlen(community)
		    && strncmp(ca->community, community, strlen(community)) == 0
		    && strncmp(ca->alias, alias, strlen(community)) == 0)
			return true;

		/* Community found, but alias name is different */
		if (strlen(ca->community) == strlen(community)
		    && strncmp(ca->community, community, strlen(community))
			       == 0) {
			bgp_community_alias_list_remove_entry(ca->community);
			return false;
		}
	}

	return false;
}

const char *bgp_community2alias(char *community)
{
	struct community_alias *ca;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp_community_alias_list, node, nnode, ca)) {
		if (strlen(ca->community) == strlen(community)
		    && strncmp(ca->community, community, strlen(community))
			       == 0)
			return ca->alias;
	}

	return community;
}

void bgp_community_alias_list_write(struct vty *vty)
{
	struct community_alias *ca;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp_community_alias_list, node, nnode, ca))
		vty_out(vty, "bgp community alias %s %s\n", ca->community,
			ca->alias);
}
