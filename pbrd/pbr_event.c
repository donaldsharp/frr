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
#include <vty.h>

#include "pbrd/pbr_event.h"
#include "pbrd/pbr_map.h"
#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_memory.h"
#include "pbrd/pbr_debug.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_EVENT, "Event WorkQueue")

struct work_queue *pbr_event_wq;

static const char *pbr_event_wqentry2str(struct pbr_event *pbre,
					 char *buffer, size_t buflen)
{
	return "Event not found.";
}

void pbr_event_free(struct pbr_event **pbre)
{
	XFREE(MTYPE_PBR_EVENT, *pbre);
}

static void pbr_event_delete_wq(struct work_queue *wq, void *data)
{
	struct pbr_event *pbre = (struct pbr_event *)data;

	XFREE(MTYPE_PBR_EVENT, pbre);
}

static wq_item_status pbr_event_process_wq(struct work_queue *wq, void *data)
{
	return WQ_SUCCESS;
}

void pbr_event_enqueue(struct pbr_event *pbre)
{
	work_queue_add(pbr_event_wq, pbre);
}

struct pbr_event *pbr_event_new(enum pbr_events ev, const char *name)
{
	struct pbr_event *event;

	event = XCALLOC(MTYPE_PBR_EVENT, sizeof(struct pbr_event));
	event->event = ev;
	if (name)
		strlcpy(event->name, name, sizeof(event->name));
	return event;
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
