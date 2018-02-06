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
#include <nexthop.h>

#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_event.h"

void pbr_nhgroup_add_cb(const char *name)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new();

	pbre->event = PBR_NHG_ADD;
	strlcpy(pbre->name, name, sizeof(pbre->name));

	pbr_event_enqueue(pbre);
	zlog_debug("Received ADD cb for %s", name);
}

void pbr_nhgroup_modify_cb(const char *name)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new();

	pbre->event = PBR_NHG_MODIFY;
	strlcpy(pbre->name, name, sizeof(pbre->name));

	pbr_event_enqueue(pbre);
	zlog_debug("Received MODIFY cb for %s", name);
}

void pbr_nhgroup_delete_cb(const char *name)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new();

	pbre->event = PBR_NHG_DELETE;
	strlcpy(pbre->name, name, sizeof(pbre->name));

	pbr_event_enqueue(pbre);
	zlog_debug("Recieved DELETE cb for %s", name);
}
