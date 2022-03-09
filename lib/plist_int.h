/*
 * Prefix list internal definitions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_PLIST_INT_H
#define _QUAGGA_PLIST_INT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <typesafe.h>

struct pltrie_table;

PREDECL_RBTREE_UNIQ(plist);
PREDECL_RBTREE_UNIQ(ple_rbtree);
struct prefix_list {
	char *name;
	char *desc;

	struct prefix_master *master;

	int count;
	int rangecount;

	struct plist_item plist_item;

	struct ple_rbtree_head head;

	struct pltrie_table *trie;
};

/* Each prefix-list's entry. */
struct prefix_list_entry {
	int64_t seq;

	int le;
	int ge;

	enum prefix_list_type type;

	bool any;
	struct prefix prefix;

	unsigned long refcnt;
	unsigned long hitcnt;

	struct prefix_list *pl;

	struct ple_rbtree_item item;

	/* up the chain for best match search */
	struct prefix_list_entry *next_best;

	/* Flag to track trie/list installation status. */
	bool installed;
};

int prefix_list_entry_compare_func(const struct prefix_list_entry *a,
				   const struct prefix_list_entry *b);
DECLARE_RBTREE_UNIQ(ple_rbtree, struct prefix_list_entry, item,
		    prefix_list_entry_compare_func);

extern void prefix_list_entry_free(struct prefix_list_entry *pentry);
extern void prefix_list_entry_delete2(struct prefix_list_entry *ple);
extern void prefix_list_entry_update_start(struct prefix_list_entry *ple);
extern void prefix_list_entry_update_finish(struct prefix_list_entry *ple);

#ifdef __cplusplus
}
#endif

#endif /* _QUAGGA_PLIST_INT_H */
