/*
 * Zebra code for interfacing with System Manager
 * Copyright (C) 2020 NVIDIA Corporation
 *                    Vivek Venkatraman
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

#include <lib/version.h>
#include "getopt.h"
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "libfrr.h"
#include "frrcu.h"

#include "zebra/zserv.h"
#include "zebra/zebra_csm.h"

#if defined(HAVE_CSMGR)
#include <cumulus/cs_mgr_intf.h>

#include "zebra/zebra_router.h"
#include "zebra/zebra_errors.h"
#include "zebra/debug.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_trace.h"

const char *frr_csm_smode_str[] = {"cold start", "fast start", "warm start",
				   "maintenance"};

extern struct zebra_privs_t zserv_privs;
pthread_t csm_pthread;
static struct rcu_thread *csm_rcu_thread;
static bool csm_rcu_set = false;

/* Move zebra globals to init complete, and send ack to CSM. */
static int frr_csm_init_complete(void);

static void convert_mode(Mode mode, enum frr_csm_smode *smode)
{
	if (IS_MODE_MAINTENANCE(mode)) {
		*smode = MAINT;
	} else if (IS_BOOT_FAST(mode)) {
		*smode = FAST_START;
	} else if (IS_BOOT_WARM(mode)) {
		*smode = WARM_START;
	} else {
		*smode = COLD_START;
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

	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: Sending Keepalive seq %d", seq);

	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m, MAX_MSG_LEN,
			    ack);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send keepalive, error %s",
			 safe_strerror(errno));
		return -1;
	}

	/* We don't care about the response */
	return 0;
}

/*
 * Send down action complete to CSM.
 */
static int frr_csm_send_down_complete(Module mod)
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
	ms->mod = mod;
	ms->mode.mod = zrouter.frr_csm_modid;
	ms->mode.state = SUCCESS; /* Don't care */
	ms->failure_reason = NO_ERROR;
	m->total_len = sizeof(*m) + entry->len;

	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: Sending down complete for %s",
			   mod_id_to_str(mod));

	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m, MAX_MSG_LEN,
			    rsp);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send down complete, error %s",
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
static int frr_csm_get_start_mode(Mode *mode, State *state)
{
	uint8_t req[MAX_MSG_LEN];
	uint8_t rsp[MAX_MSG_LEN];
	msg_pkg *m = (msg_pkg *)req;
	msg *entry = (msg *)m->entry;
	module_status *mod_status;
	module_mode *mod_mode;
	int nbytes;
	char buf[256];

	*mode = REBOOT_COLD;
	*state = UP;

	/* Send load_complete */
	entry->type = LOAD_COMPLETE;
	entry->len = sizeof(*entry) + sizeof(*mod_status);
	mod_status = (module_status *)entry->data;
	mod_status->mode.mod = zrouter.frr_csm_modid;
	mod_status->mode.state = LOAD_COMPLETE;
	mod_status->failure_reason = NO_ERROR;
	m->total_len = sizeof(*m) + entry->len;

	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m, MAX_MSG_LEN,
			    rsp);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send load complete, error %s",
			 safe_strerror(errno));
		return -1;
	}

	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: Sent load complete, response length %d",
			   nbytes);

	/* Process the response, which should have our start mode */
	if (!nbytes)
		return 0;

	m = (msg_pkg *)rsp;
	if (nbytes != m->total_len) {
		zlog_err(
			"FRRCSM: Invalid length in load complete response, len %d msg_len %d",
			nbytes, m->total_len);
		return -1;
	}

	nbytes -= sizeof(*m);
	entry = m->entry;
	while (nbytes && nbytes >= entry->len) {
		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug(
				"FRRCSM: Received message type 0x%x len %d in load complete response",
				entry->type, entry->len);
		switch (entry->type) {
		case MODE_INFO:
			mod_mode = (module_mode *)entry->data;
			if (IS_ZEBRA_DEBUG_CSM)
				zlog_debug(
					"FRRCSM: ... Received start mode %s state %s",
					mode_to_str(mod_mode->mode, buf),
					mod_state_to_str(mod_mode->state));
			*mode = mod_mode->mode;
			*state = mod_mode->state;
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
 * This function executes in zebra's main thread. It informs clients
 * (currently, only BGP) and takes any local action (currently, none).
 * An ack needs to go back to CSM after we get an ack from client.
 * TODO: When handling multiple clients, we need to track acks also
 * from each one.
 */
static void zebra_csm_maint_mode(struct thread *t)
{
	bool enter = THREAD_VAL(t);
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	if (client) {
		s = stream_new(ZEBRA_MIN_PACKET_SIZE);
		zclient_create_header(s, ZEBRA_MAINTENANCE_MODE, VRF_DEFAULT);
		stream_putc(s, enter);
		/* Write packet size. */
		stream_putw_at(s, 0, stream_get_endp(s));

		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug("FRRCSM: ... Send %s maintenance mode to %s",
				   enter ? "Enter" : "Exit",
				   zebra_route_string(client->proto));
		zserv_send_message(client, s);
	} else {
		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug(
				"FRRCSM: ... %s maintenance mode: no clients",
				enter ? "Enter" : "Exit");

		/* Respond to CSM immediately */
		if (enter)
			frr_csm_send_down_complete(zrouter.frr_csm_modid);
		else
			frr_csm_init_complete();
	}
}

/*
 * Handle event indicating fast restart or fast upgrade is about to
 * be initiated.
 * This function executes in zebra's main thread. It informs clients
 * (currently, only BGP) and takes any local action.
 * An ack needs to go back to CSM after we get an ack from client.
 * TODO: When handling multiple clients, we need to track acks also
 * from each one.
 */
static void zebra_csm_fast_restart(struct thread *t)
{
	bool upgrade = THREAD_VAL(t);
	struct zserv *client;
	struct stream *s;

	zrouter.fast_shutdown = true;
	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	if (client) {
		s = stream_new(ZEBRA_MIN_PACKET_SIZE);
		zclient_create_header(s, ZEBRA_FAST_SHUTDOWN, VRF_DEFAULT);
		stream_putc(s, upgrade);
		/* Write packet size. */
		stream_putw_at(s, 0, stream_get_endp(s));

		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug("FRRCSM: ... Send fast shutdown%s to %s",
				   upgrade ? " (upgrade)" : "",
				   zebra_route_string(client->proto));
		zserv_send_message(client, s);
	} else {
		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug(
				"FRRCSM: ... Send fast shutdown%s : no clients",
				upgrade ? " (upgrade)" : "");

		/* Respond back to CSM immediately */
		frr_csm_send_down_complete(zrouter.frr_csm_modid);
	}
}

/*
 * We're told to exit maintenance mode. Post event to main thread
 * for handling.
 */
static void frr_csm_enter_maintenance_mode(void)
{
	thread_add_event(zrouter.master, zebra_csm_maint_mode, NULL, true,
			 NULL);
}

/*
 * We're told to exit maintenance mode. Post event to main thread
 * for handling.
 */
static void frr_csm_exit_maintenance_mode(void)
{
	thread_add_event(zrouter.master, zebra_csm_maint_mode, NULL, false,
			 NULL);
}

/*
 * We're told to initiate a fast restart. Post event to main thread
 * for handling.
 */
static void frr_csm_fast_restart_triggered(void)
{
	thread_add_event(zrouter.master, zebra_csm_fast_restart, NULL, false,
			 NULL);
}

/*
 * We're told to initiate a fast upgrade. Post event to main thread
 * for handling.
 */
static void frr_csm_fast_upgrade_triggered(void)
{
	thread_add_event(zrouter.master, zebra_csm_fast_restart, NULL, true,
			 NULL);
}

/*
 * Handle trigger from CSM to 'go down' or 'come up'.
 */
static void frr_csm_handle_up_down_trigger(Module mod, Mode mode, State state,
					   bool up)
{
	char buf[256];
	Mode curr_mode = zrouter.csm_cmode;

	if (up) {
		/* We expect 'come up' only in the case of coming out of
		 * 'maintenance' mode.
		 */
		if (!IS_MODE_MAINTENANCE(zrouter.csm_cmode)) {
			if (IS_ZEBRA_DEBUG_CSM)
				zlog_debug(
					"FRRCSM: ...... ignoring ComeUp, current mode (%s) is not maintenance",
					mode_to_str(zrouter.csm_cmode, buf));
			return;
		}

		zrouter.csm_cmode = mode;
		zrouter.csm_cstate = state;
		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug(
				"FRRCSM: %s: Mode updated to: %u, state updated to: %u",
				__func__, mode, state);

		frr_csm_exit_maintenance_mode();
		return;
	}

	/* The 'go down' event can be to tell us to enter 'maintenance' mode
	 * or it could signal the start of a reboot or upgrade. In addition,
	 * we can receive this event targeted to other components also; in
	 * such a case, we only send back a response, otherwise (i.e., meant
	 * for FRR), we'll take further action.
	 */
	if (mod != zrouter.frr_csm_modid) {
		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug(
				"FRRCSM: ...... ignoring GoDown for non-self mod. self (%s), rcv (%s)",
				mod_id_to_str(zrouter.frr_csm_modid),
				mod_id_to_str(mod));
		frr_csm_send_down_complete(mod);
		return;
	}

	zrouter.csm_cmode = mode;
	zrouter.csm_cstate = state;
	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug(
			"FRRCSM: %s: Mode updated to: %u, state updated to: %u",
			__func__, mode, state);

	if (IS_MODE_MAINTENANCE(mode)) {
		frr_csm_enter_maintenance_mode();
	} else if ((IS_BOOT_FAST(mode)) ||
		   (IS_BOOT_WARM(mode) && IS_BOOT_WARM(curr_mode))) {
		/*
		 * When zebra gets a GoDown with the mode as 'warm', it should
		 * execute fast shutdown only if the current mode is 'warm';
		 * otherwise, it should effectively do nothing (i.e., act as if
		 * the request is for a cold boot)
		 */
		char buf1[256];
		char buf2[256];

		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug(
				"FRRCSM: %s: Fast shutdown required. Curr mode: %s, Mode updated to: %s, state updated to: %s",
				__func__, mode_to_str(curr_mode, buf1),
				mode_to_str(mode, buf2),
				mod_state_to_str(state));

		if (IS_SYS_UPGRADE(mode)) {
			frr_csm_fast_upgrade_triggered();
		} else {
			frr_csm_fast_restart_triggered();
		}
	} else {
		char buf1[256];
		char buf2[256];

		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug(
				"FRRCSM: %s: Normal shutdown required. Curr mode: %s,Mode updated to: %s, state updated to: %s",
				__func__, mode_to_str(curr_mode, buf1),
				mode_to_str(mode, buf2),
				mod_state_to_str(state));

		frr_csm_send_down_complete(mod);
	}
}

/*
 * Update our state, if appropriate.
 */
static void frr_csm_update_state(Module mod, Mode mode, State state)
{
	if (mod != zrouter.frr_csm_modid)
		return;

	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: Mode updated to: %u, state updated to: %u",
			   mode, state);

	zrouter.csm_cmode = mode;
	zrouter.csm_cstate = state;
}

/*
 * Inform our current state.
 */
static int frr_csm_send_state(void)
{
	uint8_t rsp[MAX_MSG_LEN];
	uint8_t ack[MAX_MSG_LEN];
	msg_pkg *m = (msg_pkg *)rsp;
	msg *entry = (msg *)m->entry;
	module_status_response *msr;
	int nbytes;

	/* Send module status */
	entry->type = MODULE_STATUS_RESP;
	entry->len = sizeof(*entry) + sizeof(*msr);
	msr = (module_status_response *)entry->data;
	msr->mode.mod = zrouter.frr_csm_modid;
	msr->mode.mode = zrouter.csm_cmode;
	msr->mode.state = zrouter.csm_cstate;
	msr->failure_reason = NO_ERROR;
	m->total_len = sizeof(*m) + entry->len;

	if (IS_ZEBRA_DEBUG_CSM) {
		char buf[256];

		zlog_debug("FRRCSM: Sending module status, mode %s state %s",
			   mode_to_str(msr->mode.mode, buf),
			   mod_state_to_str(msr->mode.state));
	}
	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m, MAX_MSG_LEN,
			    ack);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send module status, error %s",
			 safe_strerror(errno));
		return -1;
	}

	/* We don't care about the response */
	return 0;
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
	nl_data *nl;

	/* Set RCU information in the pthread */
	if (!csm_rcu_set) {
		csm_pthread = pthread_self();
		rcu_thread_start(csm_rcu_thread);

		/*
		 * The RCU mechanism for each pthread is initialized in a
		 * "locked" state. That's ok for pthreads using the
		 * frr_pthread,thread_fetch event loop, because that event
		 * loop unlocks regularly.
		 * For foreign pthreads, the lock needs to be unlocked so
		 * that the background rcu pthread can run.
		 */
		rcu_read_unlock();

		csm_rcu_set = true;
	}

	nbytes = len;
	if (nbytes != m->total_len) {
		zlog_err(
			"FRRCSM: Invalid length in received message, len %d msg_len %d",
			nbytes, m->total_len);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: Received message, total len %d", len);
	nbytes -= sizeof(*m);
	entry = m->entry;
	while (nbytes && nbytes >= entry->len) {
		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug("FRRCSM: msg type: %u", entry->type);
		switch (entry->type) {
		case COME_UP:
			mod_mode = (module_mode *)entry->data;
			if (IS_ZEBRA_DEBUG_CSM) {
				char buf[256];

				zlog_debug(
					"FRRCSM: ... Received ComeUp for %s, mode %s state %s",
					mod_id_to_str(mod_mode->mod),
					mode_to_str(mod_mode->mode, buf),
					mod_state_to_str(mod_mode->state));
			}
			frr_csm_handle_up_down_trigger(mod_mode->mod,
						       mod_mode->mode,
						       mod_mode->state, true);
			break;
		case GO_DOWN:
			mod_mode = (module_mode *)entry->data;
			if (IS_ZEBRA_DEBUG_CSM) {
				char buf[256];

				zlog_debug(
					"FRRCSM: ... Received GoDown for %s, mode %s state %s",
					mod_id_to_str(mod_mode->mod),
					mode_to_str(mod_mode->mode, buf),
					mod_state_to_str(mod_mode->state));
			}
			frr_csm_handle_up_down_trigger(mod_mode->mod,
						       mod_mode->mode,
						       mod_mode->state, false);
			break;
		case UP:
			mod_status = (module_status *)entry->data;
			mod_mode = &mod_status->mode;
			if (IS_ZEBRA_DEBUG_CSM) {
				char buf[256];

				zlog_debug(
					"FRRCSM: ... Received Up for %s, mode %s State %s failure-reason %d",
					mod_id_to_str(mod_mode->mod),
					mode_to_str(mod_mode->mode, buf),
					mod_state_to_str(mod_mode->state),
					mod_status->failure_reason);
			}
			frr_csm_update_state(mod_mode->mod, mod_mode->mode,
					     mod_mode->state);
			break;
		case DOWN:
			mod_mode = (module_mode *)entry->data;
			if (IS_ZEBRA_DEBUG_CSM) {
				char buf[256];

				zlog_debug(
					"FRRCSM: ... Received Down for %s, mode %s state %s",
					mod_id_to_str(mod_mode->mod),
					mode_to_str(mod_mode->mode, buf),
					mod_state_to_str(mod_mode->state));
			}
			frr_csm_update_state(mod_mode->mod, mod_mode->mode,
					     mod_mode->state);
			break;
		case KEEP_ALIVE_REQ:
			kr = (keepalive_request *)entry->data;
			if (IS_ZEBRA_DEBUG_CSM)
				zlog_debug(
					"FRRCSM: ... Received Keepalive Req, seq %d",
					kr->seq);
			frr_csm_send_keep_rsp(kr->seq);
			break;
		case NETWORK_LAYER_INFO:
			nl = (nl_data *)entry->data;
			char *data = nl->data;
			if (!data)
				break;

			if (IS_ZEBRA_DEBUG_CSM) {
				nl_hal_info *hal_info;
				int data_len = nl->total_len - sizeof(nl_data);

				while (data_len > 0) {
					hal_info = (nl_hal_info *)(data);
					switch (hal_info->type) {
					case IPV4:;
						unsigned int v4 =
							((nl_ipv4_info
								  *)(hal_info->data))
								->fib_entries;
						zlog_debug(
							"FRRCSM: ... NL Info. IPv4 count %u",
							v4);
						break;
					case IPV6:;
						unsigned int v6 =
							((nl_ipv6_info
								  *)(hal_info->data))
								->fib_entries;
						zlog_debug(
							"FRRCSM: ... NL Info. IPv6 count %u",
							v6);
						break;
					case RMAC:;
						unsigned int rmac_cnt =
							((nl_rmac_info
								  *)(hal_info->data))
								->rmac_entries;
						zlog_debug(
							"FRRCSM: ... NL Info. RMAC count %u",
							rmac_cnt);
						break;
					case RNEIGH:;
						unsigned int rneigh_cnt =
							((nl_rneigh_info
								  *)(hal_info->data))
								->rneigh_entries;
						zlog_debug(
							"FRRCSM: ... NL Info. RNEIGH count %u",
							rneigh_cnt);
						break;
					case HEREPL:;
						unsigned int hrep_cnt =
							((nl_herepl_info
								  *)(hal_info->data))
								->herepl_entries;
						zlog_debug(
							"FRRCSM: ... NL Info. HREP count %u",
							hrep_cnt);
						break;
					default:
						zlog_debug(
							"FRRCSM: ... NL Info. Unknown type %d, data_len - %d",
							hal_info->type,
							data_len);
						break;
					}
					data += hal_info->len;
					data_len -= hal_info->len;
				}
			}
			/* TBD: Should we do anything with this? */
			break;
		case MODULE_STATUS_REQ:
			if (IS_ZEBRA_DEBUG_CSM)
				zlog_debug(
					"FRRCSM: ... Received ModStatus Req");
			frr_csm_send_state();
			break;
		default:
			/* Right now, we don't care about anything else */
			if (IS_ZEBRA_DEBUG_CSM)
				zlog_debug(
					"FRRCSM: ... Received unhandled message %d",
					entry->type);
			break;
		}
		nbytes -= entry->len;
		entry = (msg *)((uint8_t *)entry + entry->len);
	}

	return 0;
}

/*
 * Move zebra globals to init complete, and send ack to CSM.
 */
static int frr_csm_init_complete(void)
{
	int rc;
	char buf[256];
	Mode mode;
	State state;
	enum frr_csm_smode smode;

	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: %s: init complete", __func__);

	rc = frr_csm_get_start_mode(&mode, &state);
	if (rc)
		zlog_err("FRRCSM: Failed to send load complete");
	convert_mode(mode, &smode);
	zlog_err(
		"FRRCSM: ....... Got start mode %s (converted to %s), state %s",
		mode_to_str(mode, buf), frr_csm_smode_str[smode],
		mod_state_to_str(state));
	zrouter.csm_smode = zrouter.csm_cmode = mode;
	zrouter.csm_cstate = state;
	zrouter.frr_csm_smode = smode;

	frr_csm_send_init_complete();

	return 0;
}

void zebra_csm_fast_restart_client_ack(struct zserv *client, bool upgrade)
{
	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: Ack for entering fast shutdown%s from %s",
			   upgrade ? " (upgrade)" : "",
			   zebra_route_string(client->proto));

	/* Respond back to CSM */
	frr_csm_send_down_complete(zrouter.frr_csm_modid);
}

void zebra_csm_maint_mode_client_ack(struct zserv *client, bool enter)
{
	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: Ack for %s maintenance mode from %s",
			   enter ? "Enter" : "Exit",
			   zebra_route_string(client->proto));

	/* Respond back to CSM */
	if (enter)
		frr_csm_send_down_complete(zrouter.frr_csm_modid);
	else
		frr_csm_init_complete();
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
	mod_status->mode.mode = zrouter.csm_smode;
	mod_status->mode.state = INIT_COMPLETE;
	mod_status->failure_reason = NO_ERROR;
	m->total_len = sizeof(*m) + entry->len;

	if (IS_ZEBRA_DEBUG_CSM)
		zlog_debug("FRRCSM: Sending init complete");

	if (IS_ZEBRA_DEBUG_CSM) {
		char buf1[256];
		char buf2[256];

		zlog_debug(
			"FRRCSM: %s: csm_cmode %s, csm_smode %s frr_mode %s GR enabled %u",
			__func__, mode_to_str(zrouter.csm_cmode, buf2),
			mode_to_str(zrouter.csm_smode, buf1),
			frr_csm_smode2str(zrouter.frr_csm_smode),
			zrouter.graceful_restart);
	}


	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m, MAX_MSG_LEN,
			    rsp);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send init complete, error %s",
			 safe_strerror(errno));
		return -1;
	}

	/* We don't care about the response */
	return 0;
}

/* Send NETWORK_LAYER_INFO on restart complete. */

int frr_csm_send_network_layer_info(void)
{
	uint8_t req[MAX_MSG_LEN];
	uint8_t rsp[MAX_MSG_LEN];
	msg_pkg *m = (msg_pkg *)req;
	msg *entry = (msg *)m->entry;
	int nbytes;

	/* Send init_complete */
	if (!zrouter.frr_csm_regd)
		return 0;

	/* build out the length incrementally. */

	m->total_len = sizeof(*m);

	entry->type = NETWORK_LAYER_INFO;
	entry->len = sizeof(*entry);

	nl_data *nl = (nl_data *)(req + sizeof(msg_pkg) + sizeof(msg));

	nl->total_len = sizeof(nl_data);

	nl_hal_info *hal_item = (nl_hal_info *)(nl->data);

	/* first ipv4, then ipv6. */
	hal_item->type = IPV4;
	hal_item->len = sizeof(nl_hal_info) + sizeof(nl_ipv4_info);
	nl_ipv4_info *v4 = (nl_ipv4_info *)(hal_item->data);
	v4->fib_entries = z_gr_ctx.af_installed_count[AFI_IP];
	nl->total_len += hal_item->len;

	/* v6 */
	hal_item = (nl_hal_info *)((char *)hal_item + hal_item->len);
	hal_item->type = IPV6;
	hal_item->len = sizeof(nl_hal_info) + sizeof(nl_ipv6_info);
	nl_ipv6_info *v6 = (nl_ipv6_info *)(hal_item->data);
	v6->fib_entries = z_gr_ctx.af_installed_count[AFI_IP6];
	nl->total_len += hal_item->len;

	/* RMAC */
	hal_item = (nl_hal_info *)((char *)hal_item + hal_item->len);
	hal_item->type = RMAC;
	hal_item->len = sizeof(nl_hal_info) + sizeof(nl_rmac_info);
	nl_rmac_info *rmac = (nl_rmac_info *)(hal_item->data);
	rmac->rmac_entries = z_gr_ctx.rmac_cnt;
	nl->total_len += hal_item->len;

	/* RNEIGH */
	hal_item = (nl_hal_info *)((char *)hal_item + hal_item->len);
	hal_item->type = RNEIGH;
	hal_item->len = sizeof(nl_hal_info) + sizeof(nl_rneigh_info);
	nl_rneigh_info *rneigh = (nl_rneigh_info *)(hal_item->data);
	rneigh->rneigh_entries = z_gr_ctx.rneigh_cnt;
	nl->total_len += hal_item->len;

	/* HEREPL */
	hal_item = (nl_hal_info *)((char *)hal_item + hal_item->len);
	hal_item->type = HEREPL;
	hal_item->len = sizeof(nl_hal_info) + sizeof(nl_herepl_info);
	nl_herepl_info *hrep = (nl_herepl_info *)(hal_item->data);
	hrep->herepl_entries = z_gr_ctx.hrep_cnt;
	nl->total_len += hal_item->len;

	entry->len += nl->total_len;
	m->total_len += entry->len;

	if (IS_ZEBRA_DEBUG_CSM) {
		zlog_debug(
			"FRRCSM: Sending NETWORK_LAYER_INFO. IPv4 count 0x%x (%u), IPv6 count 0x%x (%u)",
			z_gr_ctx.af_installed_count[AFI_IP],
			z_gr_ctx.af_installed_count[AFI_IP],
			z_gr_ctx.af_installed_count[AFI_IP6],
			z_gr_ctx.af_installed_count[AFI_IP6]);

		zlog_debug(
			"FRRCSM: Sending NETWORK_LAYER_INFO. RMAC count 0x%x(%u), RNEIGH count 0x%x(%u), HREP count 0x%x(%u)",
			z_gr_ctx.rmac_cnt, z_gr_ctx.rmac_cnt,
			z_gr_ctx.rneigh_cnt, z_gr_ctx.rneigh_cnt,
			z_gr_ctx.hrep_cnt, z_gr_ctx.hrep_cnt);
	}

	frrtrace(2, frr_zebra, gr_complete_route_count,
		 z_gr_ctx.af_installed_count[AFI_IP],
		 z_gr_ctx.af_installed_count[AFI_IP6]);
	frrtrace(3, frr_zebra, gr_complete_evpn_count, z_gr_ctx.rmac_cnt,
		 z_gr_ctx.rneigh_cnt, z_gr_ctx.hrep_cnt);

	nbytes = csmgr_send(zrouter.frr_csm_modid, m->total_len, m, MAX_MSG_LEN,
			    rsp);
	if (nbytes == -1) {
		zlog_err("FRRCSM: Failed to send network layer info %s",
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
		if (IS_ZEBRA_DEBUG_CSM)
			zlog_debug("FRRCSM: Unregistering");
		frr_with_privs (&zserv_privs) {
			/* unregister */
			csmgr_unregister(zrouter.frr_csm_modid);

			/* Clean up the thread-specific data (RCU) if we
			 * never attached it to the thread. If we did,
			 * the thread termination would handle the cleanup.
			 */
			if (!csm_rcu_set)
				rcu_thread_unprepare(csm_rcu_thread);
		}
	}
}

/*
 * Register with CSM and get our starting state.
 */
void frr_csm_register()
{
	int rc;
	Mode mode;
	State state;
	enum frr_csm_smode smode;

	/* Init our CSM module id */
	zrouter.frr_csm_modid = FRR;

	/* CSM register creates a pthread, we have to do prep to
	 * associate RCU with it, since we get a callback in that
	 * thread's context.
	 */
	csm_rcu_thread = rcu_thread_prepare();
	frr_with_privs (&zserv_privs) {
		rc = csmgr_register_cb(zrouter.frr_csm_modid, 1,
				       &zrouter.frr_csm_modid, frr_csm_cb);
	}
	if (!rc) {
		zlog_err("FRRCSM: Register failed, error %s",
			 safe_strerror(errno));
		zrouter.frr_csm_regd = false;
		zrouter.frr_csm_smode = COLD_START;
		zrouter.csm_smode = zrouter.csm_cmode = REBOOT_COLD;
		rcu_thread_unprepare(csm_rcu_thread);
		csm_rcu_thread = NULL;
		return;
	}

	zlog_info("FRRCSM: Register succeeded");
	zrouter.frr_csm_regd = true;

	rc = frr_csm_get_start_mode(&mode, &state);
	convert_mode(mode, &smode);
	if (rc) {
		zlog_err(
			"FRRCSM: Failed to get start mode, assuming cold start");
		zrouter.csm_smode = zrouter.csm_cmode = REBOOT_COLD;
		zrouter.csm_cstate = UP;
		zrouter.frr_csm_smode = COLD_START;
		zrouter.load_complete_failed = true;
	} else {
		zrouter.load_complete_failed = false;
		char buf[256];

		zlog_err("FRRCSM: Start mode is %s (converted to %s), state %s",
			 mode_to_str(mode, buf), frr_csm_smode_str[smode],
			 mod_state_to_str(state));
		zrouter.csm_smode = zrouter.csm_cmode = mode;
		zrouter.csm_cstate = state;
		zrouter.frr_csm_smode = smode;
		zlog_err("FRRCSM: mode %s is smode is  %s, ",
			 mode_to_str(mode, buf), frr_csm_smode_str[smode]);
	}
}
#else
void zebra_csm_maint_mode_client_ack(struct zserv *client, bool enter)
{
	zlog_warn("FRRCSM: Maintenance Mode Not Written for this platform yet");
}

void zebra_csm_fast_restart_client_ack(struct zserv *client, bool enter)
{
	zlog_warn(
		"FRRCSM: Fast Restart handling Not Written for this platform yet");
}
#endif
