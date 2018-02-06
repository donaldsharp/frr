/*
 * PBR-event Header
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
#ifndef __PBR_EVENT_H__
#define __PBR_EVENT_H__

enum pbr_events {
	PBR_NHG_ADD,
	PBR_NHG_MODIFY,
	PBR_NHG_DELETE,
	PBR_MAP_ADD,
	PBR_MAP_MODIFY,
	PBR_MAP_DELETE,
	PBR_NH_CHANGED,
};

struct pbr_event {
	enum pbr_events event;

	char name[100];
	union g_addr addr;
};

/*
 * Return a event structure that can be filled in and enqueued.
 * Assume this memory is owned by the event subsystem.
 */
extern struct pbr_event *pbr_event_new(void);

/*
 * Enqueue an event for later processing
 */
void pbr_event_enqueue(struct pbr_event *pbre);

extern void pbr_event_init(void);
extern void pbr_event_stop(void);
#endif
