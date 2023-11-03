/*
 * Zebra headers for interfacing with System Manager
 * Copyright (C) 2020 NVIDIA Corporation
 *                    Vivek Venkatraman
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef _ZEBRA_CSM_H
#define _ZEBRA_CSM_H

#include "zserv.h"

/*
 * FRR start mode as per CSM
 */
enum frr_csm_smode {
	COLD_START, /* Cold start */
	FAST_START, /* Fast start, some forwarding info preserved */
	WARM_START, /* Warm start, forwarding plane unaffected */
	MAINT	    /* Maintenance mode */
};

extern const char *frr_csm_smode_str[];

extern void zebra_csm_fast_restart_client_ack(struct zserv *client, bool enter);
extern void zebra_csm_maint_mode_client_ack(struct zserv *client, bool enter);
extern int frr_csm_send_init_complete(void);
extern void frr_csm_unregister(void);
extern void frr_csm_register(void);
extern int frr_csm_send_network_layer_info(void);

static inline const char *frr_csm_smode2str(enum frr_csm_smode smode)
{
	return (frr_csm_smode_str[smode]);
}

#endif
