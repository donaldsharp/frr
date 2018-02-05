/*
 * PBR-nht Code
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

#include <log.h>

#include "pbrd/pbr_nht.h"

void pbr_nhgroup_add_cb(const char *name)
{
	zlog_debug("Received ADD cb for %s", name);
}

void pbr_nhgroup_modify_cb(const char *name)
{
	zlog_debug("Received MODIFY cb for %s", name);
}

void pbr_nhgroup_delete_cb(const char *name)
{
	zlog_debug("Recieved DELETE cb for %s", name);
}
