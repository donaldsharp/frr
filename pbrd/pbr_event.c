/*
 * PBR-event Code
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

#include <thread.h>
#include <workqueue.h>
#include <nexthop.h>
#include <log.h>

#include "pbrd/pbr_event.h"

struct work_queue *pbr_event_wq;

static const char *pbr_event_wqentry2str(struct pbr_event *pbre,
					 char *buffer, size_t buflen)
{
	switch(pbre->event) {
	case PBR_NHG_ADD:
		snprintf(buffer, buflen, "Nexthop Group Added %s",
			 pbre->name);
		break;
	case PBR_NHG_MODIFY:
		snprintf(buffer, buflen, "Nexthop Group Modified %s",
			 pbre->name);
		break;
	case PBR_NHG_DELETE:
		snprintf(buffer, buflen, "Nexthop Group Deleted %s",
			 pbre->name);
		break;
	case PBR_MAP_ADD:
		snprintf(buffer, buflen, "PBR-MAP %s Added",
			 pbre->name);
		break;
	case PBR_MAP_MODIFY:
		snprintf(buffer, buflen, "PBR_MAP %s Modified",
			 pbre->name);
		break;
	case PBR_MAP_DELETE:
		snprintf(buffer, buflen, "PBR_MAP %s Deleted",
			 pbre->name);
		break;
	case PBR_NH_CHANGED:
		snprintf(buffer, buflen, "Nexthop Call back from Zebra");
		break;
	}

	return buffer;
}

static void pbr_event_delete_wq(struct work_queue *wq, void *data)
{
	struct pbr_event *pbre = (struct pbr_event *)data;

	XFREE(MTYPE_TMP, pbre);
}

static wq_item_status pbr_event_process_wq(struct work_queue *wq, void *data)
{
	struct pbr_event *pbre = (struct pbr_event *)data;
	char buffer[256];

	zlog_debug("%s: Handling %s",
		   __PRETTY_FUNCTION__,
		   pbr_event_wqentry2str(pbre, buffer, sizeof(buffer)));

	XFREE(MTYPE_TMP, pbre);

	return WQ_SUCCESS;
}

void pbr_event_enqueue(struct pbr_event *pbre)
{
	work_queue_add(pbr_event_wq, pbre);
}

struct pbr_event *pbr_event_new(void)
{
	return XCALLOC(MTYPE_TMP, sizeof(struct pbr_event));
}

extern struct thread_master *master;

void pbr_event_init(void)
{
	pbr_event_wq = work_queue_new(master, "PBR Main Work Queue");
	pbr_event_wq->spec.workfunc = &pbr_event_process_wq;
	pbr_event_wq->spec.del_item_data = &pbr_event_delete_wq;
}

void pbr_event_stop(void)
{
	work_queue_free_and_null(&pbr_event_wq);
}
