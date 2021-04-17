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

#ifndef _QUAGGA_BGP_COMMUNITY_ALIAS_H
#define _QUAGGA_BGP_COMMUNITY_ALIAS_H

struct community_alias {
	/* Human readable community string */
	char *community;

	/* Human readable community alias */
	char *alias;
};

extern struct list *bgp_community_alias_list;

extern void bgp_community_alias_list_free(void);
extern void bgp_community_alias_list_add_entry(const char *community,
					       const char *alias);
extern void bgp_community_alias_list_remove_entry(const char *community);
extern bool bgp_community_alias_list_has_entry(const char *community,
					       const char *alias);
extern const char *bgp_community2alias(char *community);
extern void bgp_community_alias_list_write(struct vty *vty);

#endif /* _QUAGGA_BGP_COMMUNITY_ALIAS_H */
