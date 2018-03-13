/*
 * PBR - debugging
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "debug.h"
#include "command.h"
#include "vector.h"

#ifndef VTYSH_EXTRACT_PL
#include "pbrd/pbr_debug_clippy.c"
#endif
#include "pbrd/pbr_debug.h"

#define DEBUG_PBR_MAP 0x000001

/* PBR debugging records */
struct debug pbr_dbg_map = {0, "PBR map"};

struct debug *pbr_debugs[] = {&pbr_dbg_map};

static void pbr_debug_set_all(uint32_t flags, bool set)
{
	for (unsigned int i = 0; i < array_size(pbr_debugs); i++) {
		DEBUG_FLAGS_SET(pbr_debugs[i], flags, set);

		/* if all modes have been turned off, don't preserve options */
		if (!DEBUG_MODE_CHECK(pbr_debugs[i], DEBUG_MODE_ALL))
			DEBUG_CLEAR(pbr_debugs[i]);
	}
}

#if 0
static void
pbr_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&pbr_dbg_map, DEBUG_MODE_CONF))
		vty_out(vty, "debug pbr map");
}
#endif

/* PBR debugging CLI ------------------------------------------------------- */

DEFPY(debug_pbr_map, debug_pbr_map_cmd, "[no] debug pbr map [MAP]",
      NO_STR DEBUG_STR
      "Policy Based Routing\n"
      "PBR Map Name\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	DEBUG_MODE_SET(&pbr_dbg_map, mode, !!no);
	return CMD_SUCCESS;
}

/* ------------------------------------------------------------------------- */


struct debug_callbacks pbr_dbg_cbs = {.debug_set_all = pbr_debug_set_all};

void pbr_debug_init(void)
{
	debug_init(&pbr_dbg_cbs);
}

void pbr_debug_init_vty(void)
{
	install_element(VIEW_NODE, &debug_pbr_map_cmd);
	install_element(CONFIG_NODE, &debug_pbr_map_cmd);
}
