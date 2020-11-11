/*
 * Zebra code for interfacing with System Manager
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

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "zebra_memory.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "libfrr.h"
#include "frrcu.h"
#include <cumulus/cs_mgr_intf.h>

#include "zebra/zebra_router.h"
#include "zebra/zebra_errors.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_csm.h"

const char *frr_csm_smode_str[] = {
	"cold start",
	"fast start",
	"warm start"
};

extern struct zebra_privs_t zserv_privs;
static struct rcu_thread *csm_rcu_thread;
static bool csm_rcu_set = false;

static void convert_mode(Mode mode, enum frr_csm_smode *smode)
{
	switch(mode) {
	case REBOOT_FAST:
	case SYS_UPGRADE_REBOOT_FAST:
		*smode = FAST_START;
		break;

	case REBOOT_WARM:
	case SYS_UPGRADE_REBOOT_WARM:
		*smode = WARM_START;
		break;

	default:
		*smode = COLD_START;
		break;
	}
}

/*
 * Respond to keepalive
 */
static int frr_csm_send_keep_rsp(int seq)
{
	uint8_t rsp[MAX_MSG_LEN];
	uint8_t ack[MAX_MSG_LEN];
	msg_pkg *m = (msg_pkg *)rsp;
	msg *entry = (msg *)m->entry;
	keepalive_response *kr;
	module_status *mod_status;
	int nbytes;

	/* Send load_complete */
	entry->type = KEEP_ALIVE_RESP;
	entry->len = sizeof(*entry) + sizeof(*kr);
	kr = (keepalive_response *)entry->data;
	kr->seq = seq;
	mod_status = &(kr->mod_status);
	mod_status->mode.mod = zrouter.frr_csm_modid;
	mod_status->mode.state = SUCCESS;
	mod_status->failure_reason = NO_ERROR;
	m->total_len = sizeof(*m) + entry->len;

	zlog_debug("FRRCSM: Sending Keepalive seq %d", seq);

	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m,
			    MAX_MSG_LEN, ack);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send keepalive, error %s",
			 safe_strerror(errno));
		return -1;
	}

	/* We don't care about the response */
	return 0;
}

/*
 * Right after initial registration, handshake with CSM to get our
 * start mode.
 */
static int frr_csm_get_start_mode(enum frr_csm_smode *smode)
{
	uint8_t req[MAX_MSG_LEN];
	uint8_t rsp[MAX_MSG_LEN];
	msg_pkg *m = (msg_pkg *)req;
	msg *entry = (msg *)m->entry;
	module_status *mod_status;
	module_mode *mod_mode;
	int nbytes;

	*smode = COLD_START; /* Init */

	/* Send load_complete */
	entry->type = LOAD_COMPLETE;
	entry->len = sizeof(*entry) + sizeof(*mod_status);
	mod_status = (module_status *)entry->data;
	mod_status->mode.mod = zrouter.frr_csm_modid;
	mod_status->mode.state = LOAD_COMPLETE;
	mod_status->failure_reason = NO_ERROR;
	m->total_len = sizeof(*m) + entry->len;

	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m,
			    MAX_MSG_LEN, rsp);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send load complete, error %s",
			 safe_strerror(errno));
		return -1;
	}

	zlog_debug("FRRCSM: Sent load complete, response length %d", nbytes);

	/* Process the response, which should have our start mode */
	if (!nbytes)
		return 0;

	m = (msg_pkg *)rsp;
	if (nbytes != m->total_len) {
		zlog_err("FRRCSM: Invalid length in load complete response, len %d msg_len %d",
			 nbytes, m->total_len);
		return -1;
	}

	nbytes -= sizeof(*m);
	entry = m->entry;
	while (nbytes && nbytes >= entry->len) {
		zlog_debug("FRRCSM: Received message type 0x%x len %d in load complete response",
			   entry->type, entry->len);
		switch (entry->type) {
		case MODE_INFO:
			mod_mode = (module_mode *)entry->data;
			zlog_debug("... Received start mode %s state %s",
				   mode_to_str(mod_mode->mode),
				   mod_state_to_str(mod_mode->state));
			convert_mode(mod_mode->mode, smode);
			break;
		default:
			/* Right now, we don't care about anything else */
			break;
		}
		nbytes -= entry->len;
		entry = (msg *)((uint8_t *)entry + entry->len);
	}

	return 0;
}

/*
 * Handle enter or exit maintenance mode.
 * This function executes in zebra's main thread. It is a placeholder for now.
 */
static int zebra_csm_maintenance_mode(struct thread *t)
{
	bool enter = THREAD_VAL(t);

	/* Respond back to CSM */
	if (enter) {
		frr_csm_send_down_complete();
	} else {
		int rc;
		enum frr_csm_smode smode;

		rc = frr_csm_get_start_mode(&smode);
		if (rc)
			zlog_err("FRRCSM: Failed to send load complete");
		frr_csm_send_init_complete();
	}

	return 0;
}

/*
 * We're told to exit maintenance mode. Post event to main thread
 * for handling.
 */
static void frr_csm_enter_maintenance_mode()
{
	thread_add_event(zrouter.master, zebra_csm_maintenance_mode,
			 NULL, true, NULL);
}

/*
 * We're told to exit maintenance mode. Post event to main thread
 * for handling.
 */
static void frr_csm_exit_maintenance_mode()
{
	thread_add_event(zrouter.master, zebra_csm_maintenance_mode,
			 NULL, false, NULL);
}

/*
 * Callback handler to process messages from CSM
 */
static int frr_csm_cb(int len, void *buf)
{
	msg_pkg *m = (msg_pkg *)buf;
	msg *entry;
	int nbytes;
	keepalive_request *kr;
	module_mode *mod_mode;
	module_status *mod_status;

	/* Set RCU information in the pthread */
	if (!csm_rcu_set) {
		rcu_thread_start(csm_rcu_thread);
		csm_rcu_set = true;
	}

	nbytes = len;
	if (nbytes != m->total_len) {
		zlog_err("FRRCSM: Invalid length in received message, len %d msg_len %d",
			 nbytes, m->total_len);
		return -1;
	}

	zlog_debug("FRRCSM: Received message, total len %d", len);
	nbytes -= sizeof(*m);
	entry = m->entry;
	while (nbytes && nbytes >= entry->len) {
		switch (entry->type) {
		case COME_UP:
			mod_mode = (module_mode *)entry->data;
			zlog_debug("... Received ComeUp, mode %s state %s",
				   mode_to_str(mod_mode->mode),
				   mod_state_to_str(mod_mode->state));
			/* We only care about maintenance mode. Post event to the
			 * main thread to signal to clients.
			 */
			if (mod_mode->mode == MAINTENANCE)
				frr_csm_exit_maintenance_mode();
			break;
		case GO_DOWN:
			mod_mode = (module_mode *)entry->data;
			zlog_debug("... Received GoDown, mode %s state %s",
				   mode_to_str(mod_mode->mode),
				   mod_state_to_str(mod_mode->state));
			if (mod_mode->mode == MAINTENANCE)
				frr_csm_enter_maintenance_mode();
			break;
		case UP:
			mod_status = (module_status *)entry->data;
			zlog_debug("... Received Up, mod %s mode %s State %s fr %d",
				   mod_id_to_str(mod_status->mode.mod),
				   mode_to_str(mod_status->mode.mode),
				   mod_state_to_str(mod_status->mode.state),
				   mod_status->failure_reason);
			break;
		case DOWN:
			mod_mode = (module_mode *)entry->data;
			zlog_debug("... Received Down, mod %s mode %s state %s",
				   mod_id_to_str(mod_mode->mod),
				   mode_to_str(mod_mode->mode),
				   mod_state_to_str(mod_mode->state));
			break;
		case KEEP_ALIVE_REQ:
			kr = (keepalive_request *)entry->data;
			zlog_debug("... Received Keepalive Req, seq %d",
				   kr->seq);
			frr_csm_send_keep_rsp(kr->seq);
			break;
		default:
			/* Right now, we don't care about anything else */
			zlog_debug("... Received unhandled message %d",
				   entry->type);
			break;
		}
		nbytes -= entry->len;
		entry = (msg *)((uint8_t *)entry + entry->len);
	}

	return 0;
}

/*
 * Send down action complete to CSM.
 * Called in zebra's main thread
 */
int frr_csm_send_down_complete()
{
	uint8_t req[MAX_MSG_LEN];
	uint8_t rsp[MAX_MSG_LEN];
	msg_pkg *m = (msg_pkg *)req;
	msg *entry = (msg *)m->entry;
	module_down_status *ms;
	int nbytes;

	/* Send down_complete */
	if (!zrouter.frr_csm_regd)
		return 0;

	entry->type = GO_DOWN;
	entry->len = sizeof(*entry) + sizeof(*ms);
	ms = (module_down_status *)entry->data;
	ms->mod = zrouter.frr_csm_modid;
	ms->mode.mod = zrouter.frr_csm_modid;
	ms->mode.state = SUCCESS;
	ms->failure_reason = NO_ERROR;
	m->total_len = sizeof(*m) + entry->len;

	zlog_debug("FRRCSM: Sending down complete");

	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m,
			    MAX_MSG_LEN, rsp);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send down complete, error %s",
			 safe_strerror(errno));
		return -1;
	}

	/* We don't care about the response */
	return 0;
}

/*
 * Send initialization complete to CSM.
 * Called in zebra's main thread
 */
int frr_csm_send_init_complete()
{
	uint8_t req[MAX_MSG_LEN];
	uint8_t rsp[MAX_MSG_LEN];
	msg_pkg *m = (msg_pkg *)req;
	msg *entry = (msg *)m->entry;
	module_status *mod_status;
	int nbytes;

	/* Send init_complete */
	if (!zrouter.frr_csm_regd)
		return 0;

	entry->type = INIT_COMPLETE;
	entry->len = sizeof(*entry) + sizeof(*mod_status);
	mod_status = (module_status *)entry->data;
	mod_status->mode.mod = zrouter.frr_csm_modid;
	mod_status->mode.state = INIT_COMPLETE;
	mod_status->failure_reason = NO_ERROR;
	m->total_len = sizeof(*m) + entry->len;

	zlog_debug("FRRCSM: Sending init complete");

	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m,
			    MAX_MSG_LEN, rsp);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send init complete, error %s",
			 safe_strerror(errno));
		return -1;
	}

	/* We don't care about the response */
	return 0;
}

/*
 * Unregister from CSM
 */
void frr_csm_unregister()
{
	if (zrouter.frr_csm_regd) {
		zlog_debug("FRRCSM: Unregistering");
		frr_with_privs(&zserv_privs) {
			csmgr_unregister(zrouter.frr_csm_modid);
		}
	}
}

/*
 * Register with CSM and get our starting state.
 */
void frr_csm_register()
{
	int rc;
	enum frr_csm_smode smode;

	/* Init our CSM module id */
	zrouter.frr_csm_modid = FRR;

	/* CSM register creates a pthread, we have to do prep to
	 * associate RCU with it, since we get a callback in that
	 * thread's context.
	 */
	csm_rcu_thread = rcu_thread_prepare();
	frr_with_privs(&zserv_privs) {
		rc = csmgr_register_cb(zrouter.frr_csm_modid,
				       1, &zrouter.frr_csm_modid,
				       frr_csm_cb);
	}
	if(!rc) {
		zlog_err("FRRCSM: Register failed, error %s",
			 safe_strerror(errno));
		zrouter.frr_csm_regd = false;
		zrouter.frr_csm_smode = COLD_START;
		return;
	}

	zlog_info("FRRCSM: Register succeeded");
	zrouter.frr_csm_regd = true;

	rc = frr_csm_get_start_mode(&smode);
	if (rc) {
		zlog_err("FRRCSM: Failed to get start mode, assuming cold start");
		zrouter.frr_csm_smode = COLD_START;
	} else {
		zlog_err("FRRCSM: Start mode is %s",
			 frr_csm_smode_str[smode]);
		zrouter.frr_csm_smode = smode;
	}
}
