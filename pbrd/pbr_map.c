/*
 * PBR-map Code
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
#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "nexthop.h"
#include "memory.h"
#include "log.h"

#include "pbr_map.h"
#include "pbr_event.h"
#include "pbr_nht.h"

static __inline int pbr_map_compare(const struct pbr_map *pbrmap1,
				    const struct pbr_map *pbrmap2);

RB_GENERATE(pbr_map_entry_head, pbr_map, pbr_map_entry, pbr_map_compare)

struct pbr_map_entry_head pbr_maps = RB_INITIALIZER(&pbr_maps);

DEFINE_QOBJ_TYPE(pbr_map_sequence)

static __inline int pbr_map_compare(const struct pbr_map *pbrmap1,
				    const struct pbr_map *pbrmap2)
{
	return strcmp(pbrmap1->name, pbrmap2->name);
}

static int pbr_map_sequence_compare(const struct pbr_map_sequence *pbrms1,
				    const struct pbr_map_sequence *pbrms2)
{
	if (pbrms1->seqno == pbrms2->seqno)
		return 0;

	if (pbrms1->seqno < pbrms2->seqno)
		return -1;

	return 1;
}

static void pbr_map_sequence_delete(struct pbr_map_sequence *pbrms)
{
	XFREE(MTYPE_TMP, pbrms);
}

static struct pbr_map *pbrm_find(const char *name)
{
	struct pbr_map pbrm;

	strlcpy(pbrm.name, name, sizeof(pbrm.name));

	return RB_FIND(pbr_map_entry_head, &pbr_maps, &pbrm);
}

extern struct pbr_map_sequence *pbrm_get(const char *name, uint32_t seqno)
{
	struct pbr_map *pbrm;
	struct pbr_map_sequence *pbrms;
	struct listnode *node, *nnode;
	struct pbr_event *pbre;

	pbrm = pbrm_find(name);
	if (!pbrm) {
		pbrm = XCALLOC(MTYPE_TMP, sizeof(*pbrm));
		strcpy(pbrm->name, name);

		pbrm->seqnumbers = list_new();
		pbrm->seqnumbers->cmp =
			(int (*)(void *, void *))pbr_map_sequence_compare;
		pbrm->seqnumbers->del =
			 (void (*)(void *))pbr_map_sequence_delete;

		RB_INSERT(pbr_map_entry_head, &pbr_maps, pbrm);

		pbre = pbr_event_new();
		pbre->event = PBR_MAP_ADD;
		strlcpy(pbre->name, name, sizeof(pbre->name));
	}

	for (ALL_LIST_ELEMENTS(pbrm->seqnumbers, node, nnode, pbrms)) {
		if (pbrms->seqno == seqno)
			break;

	}

	if (!pbrms) {
		pbrms = XCALLOC(MTYPE_TMP, sizeof(*pbrms));
		pbrms->seqno = seqno;
		pbrms->parent = pbrm;

		QOBJ_REG(pbrms, pbr_map_sequence);
		listnode_add_sort(pbrm->seqnumbers, pbrms);
	}

	if (pbre)
		pbr_event_enqueue(pbre);

	return pbrms;
}

static void
pbr_map_sequence_check_nexthops_valid(struct pbr_map_sequence *pbrms)
{
	/*
	 * Check validness of the nexthop or nexthop-group
	 */
	if (!pbrms->nhop && !pbrms->nhgrp_name)
		pbrms->reason |= PBR_MAP_INVALID_NO_NEXTHOPS;

	if (pbrms->nhop && pbrms->nhgrp_name)
		pbrms->reason |= PBR_MAP_INVALID_BOTH_NHANDGRP;

	if (pbrms->nhop && !pbr_nht_nexthop_valid(pbrms->nhop))
		pbrms->reason |= PBR_MAP_INVALID_NEXTHOP;

	if (pbrms->nhgrp_name
	    && !pbr_nht_nexthop_group_valid(pbrms->nhgrp_name))
		pbrms->reason |= PBR_MAP_INVALID_NEXTHOP_GROUP;
}

static void pbr_map_sequence_check_src_dst_valid(struct pbr_map_sequence *pbrms)
{
	if (!pbrms->src && !pbrms->dst)
		pbrms->reason |= PBR_MAP_INVALID_SRCDST;
}

/*
 * Checks to see if we think that the pbmrs is valid.  If we think
 * the config is valid return true.
 */
static void pbr_map_sequence_check_valid(struct pbr_map_sequence *pbrms)
{
	pbr_map_sequence_check_nexthops_valid(pbrms);

	pbr_map_sequence_check_src_dst_valid(pbrms);
}

/*
 * For a given PBR-MAP check to see if we think it is a
 * valid config or not.  If so note that it is and return
 * that we are valid.
 */
extern bool pbr_map_check_valid(const char *name)
{
	struct pbr_map *pbrm;
	struct pbr_map_sequence *pbrms;
	struct listnode *node;

	pbrm = pbrm_find(name);
	if (!pbrm) {
		zlog_debug("%s: Specified PBR-MAP(%s) does not exist?",
			   __PRETTY_FUNCTION__, name);
		return false;
	}

	pbrm->valid = true;
	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms)) {
		pbrms->reason = 0;
		pbr_map_sequence_check_valid(pbrms);
		/*
		 * A pbr_map_sequence that is invalid causes
		 * the whole shebang to be invalid
		 */
		if (pbrms->reason != 0)
			pbrm->valid = false;
	}

	return pbrm->valid;
}

extern void pbr_map_init(void)
{
	RB_INIT(pbr_map_entry_head, &pbr_maps);
}
