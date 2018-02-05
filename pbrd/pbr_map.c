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
#include "prefix.h"
#include "table.h"
#include "memory.h"

#include "pbr_map.h"

static __inline int pbr_map_compare(const struct pbr_map *pbrmap1,
				    const struct pbr_map *pbrmap2);

RB_GENERATE(pbr_map_entry_head, pbr_map, pbr_map_entry, pbr_map_compare)

struct pbr_map_entry_head pbr_maps = RB_INITIALIZER(&pbr_maps);

DEFINE_QOBJ_TYPE(pbr_map)

static __inline int pbr_map_compare(const struct pbr_map *pbrmap1,
				    const struct pbr_map *pbrmap2)
{
	uint32_t res;

	res = strcmp(pbrmap1->name, pbrmap2->name);

	if (res != 0)
		return res;

	return (pbrmap1->seqno - pbrmap2->seqno);
}

static struct pbr_map *pbrm_find(const char *name, uint32_t seqno)
{
	struct pbr_map pbrm;

	strlcpy(pbrm.name, name, sizeof(pbrm.name));
	pbrm.seqno = seqno;

	return RB_FIND(pbr_map_entry_head, &pbr_maps, &pbrm);
}

extern struct pbr_map *pbrm_get(const char *name, uint32_t seqno)
{
	struct pbr_map *pbrm;

	pbrm = pbrm_find(name, seqno);
	if (!pbrm) {
		pbrm = XCALLOC(MTYPE_TMP, sizeof(*pbrm));
		strcpy(pbrm->name, name);
		pbrm->seqno = seqno;

		QOBJ_REG(pbrm, pbr_map);
		RB_INSERT(pbr_map_entry_head, &pbr_maps, pbrm);
	}

	return pbrm;
}

extern void pbr_map_init(void)
{
	RB_INIT(pbr_map_entry_head, &pbr_maps);
}
