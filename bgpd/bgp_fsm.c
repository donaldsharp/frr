/* BGP-4 Finite State Machine
 * From RFC1771 [A Border Gateway Protocol 4 (BGP-4)]
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "sockunion.h"
#include "thread.h"
#include "log.h"
#include "stream.h"
#include "ringbuf.h"
#include "memory.h"
#include "plist.h"
#include "workqueue.h"
#include "queue.h"
#include "filter.h"
#include "command.h"
#include "lib_errors.h"
#include "zclient.h"
#include "lib/json.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_keepalives.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_trace.h"

DEFINE_HOOK(peer_backward_transition, (struct peer * peer), (peer));
DEFINE_HOOK(peer_status_changed, (struct peer * peer), (peer));

/* Definition of display strings corresponding to FSM events. This should be
 * kept consistent with the events defined in bgpd.h
 */
static const char *const bgp_event_str[] = {
	NULL,
	"BGP_Start",
	"BGP_Stop",
	"TCP_connection_open",
	"TCP_connection_open_w_delay",
	"TCP_connection_closed",
	"TCP_connection_open_failed",
	"TCP_fatal_error",
	"ConnectRetry_timer_expired",
	"Hold_Timer_expired",
	"KeepAlive_timer_expired",
	"DelayOpen_timer_expired",
	"Receive_OPEN_message",
	"Receive_KEEPALIVE_message",
	"Receive_UPDATE_message",
	"Receive_NOTIFICATION_message",
	"Clearing_Completed",
};

/* BGP FSM (finite state machine) has three types of functions.  Type
   one is thread functions.  Type two is event functions.  Type three
   is FSM functions.  Timer functions are set by bgp_timer_set
   function. */

/* BGP event function. */
void bgp_event(struct thread *);

/* BGP thread functions. */
static void bgp_start_timer(struct thread *);
static void bgp_connect_timer(struct thread *);
static void bgp_holdtime_timer(struct thread *);
static void bgp_delayopen_timer(struct thread *);
static void bgp_graceful_deferral_timer_expire(struct thread *thread);
static void bgp_start_deferral_timer(struct bgp *bgp, afi_t afi, safi_t safi,
				     struct graceful_restart_info *gr_info);


/* BGP FSM functions. */
static int bgp_start(struct peer *);

/* Register peer with NHT */
int bgp_peer_reg_with_nht(struct peer *peer)
{
	int connected = 0;

	if (peer->sort == BGP_PEER_EBGP && peer->ttl == BGP_DEFAULT_TTL
	    && !CHECK_FLAG(peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
	    && !CHECK_FLAG(peer->bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
		connected = 1;

	return bgp_find_or_add_nexthop(
		peer->bgp, peer->bgp, family2afi(peer->su.sa.sa_family),
		SAFI_UNICAST, NULL, peer, connected, NULL);
}

static void peer_xfer_stats(struct peer *peer_dst, struct peer *peer_src)
{
	/* Copy stats over. These are only the pre-established state stats */
	peer_dst->open_in += peer_src->open_in;
	peer_dst->open_out += peer_src->open_out;
	peer_dst->keepalive_in += peer_src->keepalive_in;
	peer_dst->keepalive_out += peer_src->keepalive_out;
	peer_dst->notify_in += peer_src->notify_in;
	peer_dst->notify_out += peer_src->notify_out;
	peer_dst->dynamic_cap_in += peer_src->dynamic_cap_in;
	peer_dst->dynamic_cap_out += peer_src->dynamic_cap_out;
}

static struct peer *peer_xfer_conn(struct peer *from_peer)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	int fd;
	enum bgp_fsm_status status, pstatus;
	enum bgp_fsm_events last_evt, last_maj_evt;

	assert(from_peer != NULL);

	peer = from_peer->doppelganger;

	if (!peer || !CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
		return from_peer;

	/*
	 * Let's check that we are not going to loose known configuration
	 * state based upon doppelganger rules.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (from_peer->afc[afi][safi] != peer->afc[afi][safi]) {
			flog_err(
				EC_BGP_DOPPELGANGER_CONFIG,
				"from_peer->afc[%d][%d] is not the same as what we are overwriting",
				afi, safi);
			return NULL;
		}
	}

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s: peer transfer %p fd %d -> %p fd %d)",
			   from_peer->host, from_peer, from_peer->fd, peer,
			   peer->fd);

	bgp_writes_off(peer);
	bgp_reads_off(peer);
	bgp_writes_off(from_peer);
	bgp_reads_off(from_peer);

	/*
	 * Before exchanging FD remove doppelganger from
	 * keepalive peer hash. It could be possible conf peer
	 * fd is set to -1. If blocked on lock then keepalive
	 * thread can access peer pointer with fd -1.
	 */
	bgp_keepalives_off(from_peer);

	THREAD_OFF(peer->t_routeadv);
	THREAD_OFF(peer->t_connect);
	THREAD_OFF(peer->t_delayopen);
	THREAD_OFF(peer->t_connect_check_r);
	THREAD_OFF(peer->t_connect_check_w);
	THREAD_OFF(from_peer->t_routeadv);
	THREAD_OFF(from_peer->t_connect);
	THREAD_OFF(from_peer->t_delayopen);
	THREAD_OFF(from_peer->t_connect_check_r);
	THREAD_OFF(from_peer->t_connect_check_w);
	THREAD_OFF(from_peer->t_process_packet);

	/*
	 * At this point in time, it is possible that there are packets pending
	 * on various buffers. Those need to be transferred or dropped,
	 * otherwise we'll get spurious failures during session establishment.
	 */
	frr_with_mutex (&peer->io_mtx, &from_peer->io_mtx) {
		fd = peer->fd;
		peer->fd = from_peer->fd;
		from_peer->fd = fd;

		stream_fifo_clean(peer->ibuf);
		stream_fifo_clean(peer->obuf);

		/*
		 * this should never happen, since bgp_process_packet() is the
		 * only task that sets and unsets the current packet and it
		 * runs in our pthread.
		 */
		if (peer->curr) {
			flog_err(
				EC_BGP_PKT_PROCESS,
				"[%s] Dropping pending packet on connection transfer:",
				peer->host);
			/* there used to be a bgp_packet_dump call here, but
			 * that's extremely confusing since there's no way to
			 * identify the packet in MRT dumps or BMP as dropped
			 * due to connection transfer.
			 */
			stream_free(peer->curr);
			peer->curr = NULL;
		}

		// copy each packet from old peer's output queue to new peer
		while (from_peer->obuf->head)
			stream_fifo_push(peer->obuf,
					 stream_fifo_pop(from_peer->obuf));

		// copy each packet from old peer's input queue to new peer
		while (from_peer->ibuf->head)
			stream_fifo_push(peer->ibuf,
					 stream_fifo_pop(from_peer->ibuf));

		ringbuf_wipe(peer->ibuf_work);
		ringbuf_copy(peer->ibuf_work, from_peer->ibuf_work,
			     ringbuf_remain(from_peer->ibuf_work));
	}

	peer->as = from_peer->as;
	peer->v_holdtime = from_peer->v_holdtime;
	peer->v_keepalive = from_peer->v_keepalive;
	peer->v_routeadv = from_peer->v_routeadv;
	peer->v_delayopen = from_peer->v_delayopen;
	peer->v_gr_restart = from_peer->v_gr_restart;
	peer->cap = from_peer->cap;
	peer->remote_role = from_peer->remote_role;
	status = peer->status;
	pstatus = peer->ostatus;
	last_evt = peer->last_event;
	last_maj_evt = peer->last_major_event;
	peer->status = from_peer->status;
	peer->ostatus = from_peer->ostatus;
	peer->last_event = from_peer->last_event;
	peer->last_major_event = from_peer->last_major_event;
	from_peer->status = status;
	from_peer->ostatus = pstatus;
	from_peer->last_event = last_evt;
	from_peer->last_major_event = last_maj_evt;
	peer->remote_id = from_peer->remote_id;
	peer->last_reset = from_peer->last_reset;
	peer->max_packet_size = from_peer->max_packet_size;

	BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(peer->bgp,
							  peer->bgp->peer);

	if (bgp_peer_gr_mode_get(peer) == PEER_DISABLE) {

		UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);

		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {
			peer_nsf_stop(peer);
		}
	}

	if (from_peer->hostname != NULL) {
		if (peer->hostname) {
			XFREE(MTYPE_BGP_PEER_HOST, peer->hostname);
			peer->hostname = NULL;
		}

		peer->hostname = from_peer->hostname;
		from_peer->hostname = NULL;
	}

	if (from_peer->domainname != NULL) {
		if (peer->domainname) {
			XFREE(MTYPE_BGP_PEER_HOST, peer->domainname);
			peer->domainname = NULL;
		}

		peer->domainname = from_peer->domainname;
		from_peer->domainname = NULL;
	}

	FOREACH_AFI_SAFI (afi, safi) {
		peer->af_sflags[afi][safi] = from_peer->af_sflags[afi][safi];
		peer->af_cap[afi][safi] = from_peer->af_cap[afi][safi];
		peer->afc_nego[afi][safi] = from_peer->afc_nego[afi][safi];
		peer->afc_adv[afi][safi] = from_peer->afc_adv[afi][safi];
		peer->afc_recv[afi][safi] = from_peer->afc_recv[afi][safi];
		peer->orf_plist[afi][safi] = from_peer->orf_plist[afi][safi];
		peer->llgr[afi][safi] = from_peer->llgr[afi][safi];
	}

	if (bgp_getsockname(peer) < 0) {
		flog_err(
			EC_LIB_SOCKET,
			"%%bgp_getsockname() failed for %s peer %s fd %d (from_peer fd %d)",
			(CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER)
				 ? "accept"
				 : ""),
			peer->host, peer->fd, from_peer->fd);
		BGP_EVENT_ADD(peer, BGP_Stop);
		BGP_EVENT_ADD(from_peer, BGP_Stop);
		return NULL;
	}
	if (from_peer->status > Active) {
		if (bgp_getsockname(from_peer) < 0) {
			flog_err(
				EC_LIB_SOCKET,
				"%%bgp_getsockname() failed for %s from_peer %s fd %d (peer fd %d)",

				(CHECK_FLAG(from_peer->sflags,
					    PEER_STATUS_ACCEPT_PEER)
					 ? "accept"
					 : ""),
				from_peer->host, from_peer->fd, peer->fd);
			bgp_stop(from_peer);
			from_peer = NULL;
		}
	}


	// Note: peer_xfer_stats() must be called with I/O turned OFF
	if (from_peer)
		peer_xfer_stats(peer, from_peer);

	/* Register peer for NHT. This is to allow RAs to be enabled when
	 * needed, even on a passive connection.
	 */
	bgp_peer_reg_with_nht(peer);
	if (from_peer)
		bgp_replace_nexthop_by_peer(from_peer, peer);

	bgp_reads_on(peer);
	bgp_writes_on(peer);
	thread_add_event(bm->master, bgp_process_packet, peer, 0,
			 &peer->t_process_packet);

	return (peer);
}

/* Hook function called after bgp event is occered.  And vty's
   neighbor command invoke this function after making neighbor
   structure. */
void bgp_timer_set(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	switch (peer->status) {
	case Idle:
		/* First entry point of peer's finite state machine.  In Idle
		   status start timer is on unless peer is shutdown or peer is
		   inactive.  All other timer must be turned off */
		if (BGP_PEER_START_SUPPRESSED(peer) || !peer_active(peer)
		    || peer->bgp->vrf_id == VRF_UNKNOWN) {
			THREAD_OFF(peer->t_start);
		} else {
			BGP_TIMER_ON(peer->t_start, bgp_start_timer,
				     peer->v_start);
		}
		THREAD_OFF(peer->t_connect);
		THREAD_OFF(peer->t_holdtime);
		bgp_keepalives_off(peer);
		THREAD_OFF(peer->t_routeadv);
		THREAD_OFF(peer->t_delayopen);
		break;

	case Connect:
		/* After start timer is expired, the peer moves to Connect
		   status.  Make sure start timer is off and connect timer is
		   on. */
		THREAD_OFF(peer->t_start);
		if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
			BGP_TIMER_ON(peer->t_connect, bgp_connect_timer,
				     (peer->v_delayopen + peer->v_connect));
		else
			BGP_TIMER_ON(peer->t_connect, bgp_connect_timer,
				     peer->v_connect);

		THREAD_OFF(peer->t_holdtime);
		bgp_keepalives_off(peer);
		THREAD_OFF(peer->t_routeadv);
		break;

	case Active:
		/* Active is waiting connection from remote peer.  And if
		   connect timer is expired, change status to Connect. */
		THREAD_OFF(peer->t_start);
		/* If peer is passive mode, do not set connect timer. */
		if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSIVE)
		    || CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {
			THREAD_OFF(peer->t_connect);
		} else {
			if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
				BGP_TIMER_ON(
					peer->t_connect, bgp_connect_timer,
					(peer->v_delayopen + peer->v_connect));
			else
				BGP_TIMER_ON(peer->t_connect, bgp_connect_timer,
					     peer->v_connect);
		}
		THREAD_OFF(peer->t_holdtime);
		bgp_keepalives_off(peer);
		THREAD_OFF(peer->t_routeadv);
		break;

	case OpenSent:
		/* OpenSent status. */
		THREAD_OFF(peer->t_start);
		THREAD_OFF(peer->t_connect);
		if (peer->v_holdtime != 0) {
			BGP_TIMER_ON(peer->t_holdtime, bgp_holdtime_timer,
				     peer->v_holdtime);
		} else {
			THREAD_OFF(peer->t_holdtime);
		}
		bgp_keepalives_off(peer);
		THREAD_OFF(peer->t_routeadv);
		THREAD_OFF(peer->t_delayopen);
		break;

	case OpenConfirm:
		/* OpenConfirm status. */
		THREAD_OFF(peer->t_start);
		THREAD_OFF(peer->t_connect);

		/*
		 * If the negotiated Hold Time value is zero, then the Hold Time
		 * timer and KeepAlive timers are not started.
		 * Additionally if a different hold timer has been negotiated
		 * than we must stop then start the timer again
		 */
		THREAD_OFF(peer->t_holdtime);
		if (peer->v_holdtime == 0)
			bgp_keepalives_off(peer);
		else {
			BGP_TIMER_ON(peer->t_holdtime, bgp_holdtime_timer,
				     peer->v_holdtime);
			bgp_keepalives_on(peer);
		}
		THREAD_OFF(peer->t_routeadv);
		THREAD_OFF(peer->t_delayopen);
		break;

	case Established:
		/* In Established status start and connect timer is turned
		   off. */
		THREAD_OFF(peer->t_start);
		THREAD_OFF(peer->t_connect);
		THREAD_OFF(peer->t_delayopen);

		/*
		 * Same as OpenConfirm, if holdtime is zero then both holdtime
		 * and keepalive must be turned off.
		 * Additionally if a different hold timer has been negotiated
		 * then we must stop then start the timer again
		 */
		THREAD_OFF(peer->t_holdtime);
		if (peer->v_holdtime == 0)
			bgp_keepalives_off(peer);
		else {
			BGP_TIMER_ON(peer->t_holdtime, bgp_holdtime_timer,
				     peer->v_holdtime);
			bgp_keepalives_on(peer);
		}
		break;
	case Deleted:
		THREAD_OFF(peer->t_gr_restart);
		THREAD_OFF(peer->t_gr_stale);

		FOREACH_AFI_SAFI (afi, safi)
			THREAD_OFF(peer->t_llgr_stale[afi][safi]);

		THREAD_OFF(peer->t_pmax_restart);
		THREAD_OFF(peer->t_refresh_stalepath);
	/* fallthru */
	case Clearing:
		THREAD_OFF(peer->t_start);
		THREAD_OFF(peer->t_connect);
		THREAD_OFF(peer->t_holdtime);
		bgp_keepalives_off(peer);
		THREAD_OFF(peer->t_routeadv);
		THREAD_OFF(peer->t_delayopen);
		break;
	case BGP_STATUS_MAX:
		flog_err(EC_LIB_DEVELOPMENT,
			 "BGP_STATUS_MAX while a legal state is not valid state for the FSM");
		break;
	}
}

/* BGP start timer.  This function set BGP_Start event to thread value
   and process event. */
static void bgp_start_timer(struct thread *thread)
{
	struct peer *peer;

	peer = THREAD_ARG(thread);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (start timer expire).", peer->host);

	THREAD_VAL(thread) = BGP_Start;
	bgp_event(thread); /* bgp_event unlocks peer */
}

/* BGP connect retry timer. */
static void bgp_connect_timer(struct thread *thread)
{
	struct peer *peer;

	peer = THREAD_ARG(thread);

	/* stop the DelayOpenTimer if it is running */
	THREAD_OFF(peer->t_delayopen);

	assert(!peer->t_write);
	assert(!peer->t_read);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (connect timer expire)", peer->host);

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER))
		bgp_stop(peer);
	else {
		THREAD_VAL(thread) = ConnectRetry_timer_expired;
		bgp_event(thread); /* bgp_event unlocks peer */
	}
}

/* BGP holdtime timer. */
static void bgp_holdtime_timer(struct thread *thread)
{
	atomic_size_t inq_count;
	struct peer *peer;

	peer = THREAD_ARG(thread);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (holdtime timer expire)",
			   peer->host);

	/*
	 * Given that we do not have any expectation of ordering
	 * for handling packets from a peer -vs- handling
	 * the hold timer for a peer as that they are both
	 * events on the peer.  If we have incoming
	 * data on the peers inq, let's give the system a chance
	 * to handle that data.  This can be especially true
	 * for systems where we are heavily loaded for one
	 * reason or another.
	 */
	inq_count = atomic_load_explicit(&peer->ibuf->count,
					 memory_order_relaxed);
	if (inq_count)
		BGP_TIMER_ON(peer->t_holdtime, bgp_holdtime_timer,
			     peer->v_holdtime);

	THREAD_VAL(thread) = Hold_Timer_expired;
	bgp_event(thread); /* bgp_event unlocks peer */
}

void bgp_routeadv_timer(struct thread *thread)
{
	struct peer *peer;

	peer = THREAD_ARG(thread);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (routeadv timer expire)",
			   peer->host);

	peer->synctime = monotime(NULL);

	thread_add_timer_msec(bm->master, bgp_generate_updgrp_packets, peer, 0,
			      &peer->t_generate_updgrp_packets);

	/* MRAI timer will be started again when FIFO is built, no need to
	 * do it here.
	 */
}

/* RFC 4271 DelayOpenTimer */
void bgp_delayopen_timer(struct thread *thread)
{
	struct peer *peer;

	peer = THREAD_ARG(thread);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (DelayOpentimer expire)",
			   peer->host);

	THREAD_VAL(thread) = DelayOpen_timer_expired;
	bgp_event(thread); /* bgp_event unlocks peer */
}

/* BGP Peer Down Cause */
const char *const peer_down_str[] = {"",
			       "Router ID changed",
			       "Remote AS changed",
			       "Local AS change",
			       "Cluster ID changed",
			       "Confederation identifier changed",
			       "Confederation peer changed",
			       "RR client config change",
			       "RS client config change",
			       "Update source change",
			       "Address family activated",
			       "Admin. shutdown",
			       "User reset",
			       "BGP Notification received",
			       "BGP Notification send",
			       "Peer closed the session",
			       "Neighbor deleted",
			       "Peer-group add member",
			       "Peer-group delete member",
			       "Capability changed",
			       "Passive config change",
			       "Multihop config change",
			       "NSF peer closed the session",
			       "Intf peering v6only config change",
			       "BFD down received",
			       "Interface down",
			       "Neighbor address lost",
			       "Waiting for NHT",
			       "Waiting for Peer IPv6 LLA",
			       "Waiting for VRF to be initialized",
			       "No AFI/SAFI activated for peer",
			       "AS Set config change",
			       "Waiting for peer OPEN",
			       "Reached received prefix count",
			       "Socket Error"};

static void bgp_graceful_restart_timer_off(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_LLGR_WAIT))
			return;

	UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);
	THREAD_OFF(peer->t_gr_stale);

	if (peer_dynamic_neighbor(peer) &&
	    !(CHECK_FLAG(peer->flags, PEER_FLAG_DELETE))) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
	}

	bgp_timer_set(peer);
}

static void bgp_llgr_stale_timer_expire(struct thread *thread)
{
	struct peer_af *paf;
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	paf = THREAD_ARG(thread);

	peer = paf->peer;
	afi = paf->afi;
	safi = paf->safi;

	/* If the timer for the "Long-lived Stale Time" expires before the
	 * session is re-established, the helper MUST delete all the
	 * stale routes from the neighbor that it is retaining.
	 */
	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%pBP Long-lived stale timer (%s) expired", peer,
			   get_afi_safi_str(afi, safi, false));

	UNSET_FLAG(peer->af_sflags[afi][safi], PEER_STATUS_LLGR_WAIT);

	bgp_clear_stale_route(peer, afi, safi);

	bgp_graceful_restart_timer_off(peer);
}

static void bgp_set_llgr_stale(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_table *table;
	struct attr attr;

	if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN) {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			struct bgp_dest *rm;

			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			for (rm = bgp_table_top(table); rm;
			     rm = bgp_route_next(rm))
				for (pi = bgp_dest_get_bgp_path_info(rm); pi;
				     pi = pi->next) {
					if (pi->peer != peer)
						continue;

					if (bgp_attr_get_community(pi->attr) &&
					    community_include(
						    bgp_attr_get_community(
							    pi->attr),
						    COMMUNITY_NO_LLGR))
						continue;

					if (bgp_debug_neighbor_events(peer))
						zlog_debug(
							"%pBP Long-lived set stale community (LLGR_STALE) for: %pFX",
							peer, &dest->p);

					attr = *pi->attr;
					bgp_attr_add_llgr_community(&attr);
					pi->attr = bgp_attr_intern(&attr);
					bgp_recalculate_afi_safi_bestpaths(
						peer->bgp, afi, safi);

					break;
				}
		}
	} else {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest))
			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				if (pi->peer != peer)
					continue;

				if (bgp_attr_get_community(pi->attr) &&
				    community_include(
					    bgp_attr_get_community(pi->attr),
					    COMMUNITY_NO_LLGR))
					continue;

				if (bgp_debug_neighbor_events(peer))
					zlog_debug(
						"%pBP Long-lived set stale community (LLGR_STALE) for: %pFX",
						peer, &dest->p);

				attr = *pi->attr;
				bgp_attr_add_llgr_community(&attr);
				pi->attr = bgp_attr_intern(&attr);
				bgp_recalculate_afi_safi_bestpaths(peer->bgp,
								   afi, safi);

				break;
			}
	}
}

static void bgp_graceful_restart_timer_expire(struct thread *thread)
{
	struct peer *peer, *tmp_peer;
	struct listnode *node, *nnode;
	struct peer_af *paf;
	afi_t afi;
	safi_t safi;

	peer = THREAD_ARG(thread);

	if (bgp_debug_neighbor_events(peer)) {
		zlog_debug("%pBP graceful restart timer expired", peer);
		zlog_debug("%pBP graceful restart stalepath timer stopped",
			   peer);
	}

	FOREACH_AFI_SAFI (afi, safi) {
		if (!peer->nsf[afi][safi])
			continue;

		/* Once the "Restart Time" period ends, the LLGR period is
		 * said to have begun and the following procedures MUST be
		 * performed:
		 *
		 * The helper router MUST start a timer for the
		 * "Long-lived Stale Time".
		 *
		 * The helper router MUST attach the LLGR_STALE community
		 * for the stale routes being retained. Note that this
		 * requirement implies that the routes would need to be
		 * readvertised, to disseminate the modified community.
		 */
		if (peer->llgr[afi][safi].stale_time) {
			paf = peer_af_find(peer, afi, safi);
			if (!paf)
				continue;

			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP Long-lived stale timer (%s) started for %d sec",
					peer,
					get_afi_safi_str(afi, safi, false),
					peer->llgr[afi][safi].stale_time);

			SET_FLAG(peer->af_sflags[afi][safi],
				 PEER_STATUS_LLGR_WAIT);

			bgp_set_llgr_stale(peer, afi, safi);
			bgp_clear_stale_route(peer, afi, safi);

			thread_add_timer(bm->master,
					 bgp_llgr_stale_timer_expire, paf,
					 peer->llgr[afi][safi].stale_time,
					 &peer->t_llgr_stale[afi][safi]);

			for (ALL_LIST_ELEMENTS(peer->bgp->peer, node, nnode,
					       tmp_peer))
				bgp_announce_route(tmp_peer, afi, safi, false);
		} else {
			bgp_clear_stale_route(peer, afi, safi);
		}
	}

	bgp_graceful_restart_timer_off(peer);
}

static void bgp_graceful_stale_timer_expire(struct thread *thread)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	peer = THREAD_ARG(thread);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%pBP graceful restart stalepath timer expired",
			   peer);

	/* NSF delete stale route */
	FOREACH_AFI_SAFI_NSF (afi, safi)
		if (peer->nsf[afi][safi])
			bgp_clear_stale_route(peer, afi, safi);
}

/*
 * Start the tier-2 selection deferral timer thread for the specified AFI, SAFI,
 * mark peers from whom we need an EOR
 */
void bgp_start_tier2_deferral_timer(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct afi_safi_info *thread_info;

	struct graceful_restart_info *gr_info = &(bgp->gr_info[afi][safi]);

	/*
	 * tier-2 deferral timer is already running
	 */
	if (gr_info->t_select_deferral_tier2) {
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
			"%s: tier-2 path-select deferral timer for %s, duration %d is running",
			bgp->name_pretty, get_afi_safi_str(afi, safi, false),
			bgp->select_defer_time);
		return;
	}

	/* Start the timer */
	thread_info = XMALLOC(MTYPE_TMP, sizeof(struct afi_safi_info));

	thread_info->afi = afi;
	thread_info->safi = safi;
	thread_info->bgp = bgp;
	thread_info->tier2_gr = true;

	thread_add_timer(bm->master, bgp_graceful_deferral_timer_expire,
			 thread_info, bgp->select_defer_time,
			 &gr_info->t_select_deferral_tier2);

	gr_info->select_defer_tier2_required = true;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"%s: Started tier-2 path-select deferral timer for %s, duration %ds",
			bgp->name_pretty, get_afi_safi_str(afi, safi, false),
			bgp->select_defer_time);

	frrtrace(5, frr_bgp, gr_deferral_timer_start, bgp->name_pretty, afi,
		 safi, bgp->select_defer_time, 2);
}

/* Selection deferral timer processing function */
static void bgp_graceful_deferral_timer_expire(struct thread *thread)
{
	struct afi_safi_info *info;
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;

	info = THREAD_ARG(thread);
	afi = info->afi;
	safi = info->safi;
	bgp = info->bgp;

	/*
	 * If tier 2 timer expired then set then set the
	 * select_defer_over_tier2 to true to indicate that
	 * BGP tier2 bestpath selection can be done now.
	 */
	if (info->tier2_gr) {
		bgp->gr_info[afi][safi].select_defer_over_tier2 = true;
	} else {
		bgp->gr_info[afi][safi].select_defer_over = true;
	}

	/* Best path selection */
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"%s: Starting %s deferred path selection for %s, #routes %d -- timeout",
			bgp->name_pretty, (info->tier2_gr) ? "2nd" : "1st",
			get_afi_safi_str(afi, safi, false),
			bgp->gr_info[afi][safi].gr_deferred);

	frrtrace(5, frr_bgp, gr_deferral_timer_expiry, bgp->name_pretty,
		 info->tier2_gr, afi, safi,
		 bgp->gr_info[afi][safi].gr_deferred);


	XFREE(MTYPE_TMP, info);

	bgp_do_deferred_path_selection(bgp, afi, safi);
}

static bool bgp_update_delay_applicable(struct bgp *bgp)
{
	/* update_delay_over flag should be reset (set to 0) for any new
	   applicability of the update-delay during BGP process lifetime.
	   And it should be set after an occurence of the update-delay is
	   over)*/
	if (!bgp->update_delay_over)
		return true;
	return false;
}

bool bgp_update_delay_active(struct bgp *bgp)
{
	if (bgp->t_update_delay)
		return true;
	return false;
}

bool bgp_update_delay_configured(struct bgp *bgp)
{
	if (bgp->v_update_delay)
		return true;
	return false;
}

/* Do the post-processing needed when bgp comes out of the read-only mode
   on ending the update delay. */
void bgp_update_delay_end(struct bgp *bgp)
{
	THREAD_OFF(bgp->t_update_delay);
	THREAD_OFF(bgp->t_establish_wait);

	/* Reset update-delay related state */
	bgp->update_delay_over = 1;
	bgp->established = 0;
	bgp->restarted_peers = 0;
	bgp->implicit_eors = 0;
	bgp->explicit_eors = 0;

	frr_timestamp(3, bgp->update_delay_end_time,
		      sizeof(bgp->update_delay_end_time));

	/*
	 * Add an end-of-initial-update marker to the main process queues so
	 * that
	 * the route advertisement timer for the peers can be started. Also set
	 * the zebra and peer update hold flags. These flags are used to achieve
	 * three stages in the update-delay post processing:
	 *  1. Finish best-path selection for all the prefixes held on the
	 * queues.
	 *     (routes in BGP are updated, and peers sync queues are populated
	 * too)
	 *  2. As the eoiu mark is reached in the bgp process routine, ship all
	 * the
	 *     routes to zebra. With that zebra should see updates from BGP
	 * close
	 *     to each other.
	 *  3. Unblock the peer update writes. With that peer update packing
	 * with
	 *     the prefixes should be at its maximum.
	 */
	bgp_add_eoiu_mark(bgp);
	bgp->main_zebra_update_hold = 1;
	bgp->main_peers_update_hold = 1;

	/*
	 * Resume the queue processing. This should trigger the event that would
	 * take care of processing any work that was queued during the read-only
	 * mode.
	 */
	work_queue_unplug(bgp->process_queue);
}

/**
 * see bgp_fsm.h
 */
void bgp_start_routeadv(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	zlog_info("%s, update hold status %d", __func__,
		  bgp->main_peers_update_hold);

	if (bgp->main_peers_update_hold)
		return;

	frr_timestamp(3, bgp->update_delay_peers_resume_time,
		      sizeof(bgp->update_delay_peers_resume_time));

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!peer_established(peer))
			continue;
		THREAD_OFF(peer->t_routeadv);
		BGP_TIMER_ON(peer->t_routeadv, bgp_routeadv_timer, 0);
	}
}

/**
 * see bgp_fsm.h
 */
void bgp_adjust_routeadv(struct peer *peer)
{
	time_t nowtime = monotime(NULL);
	double diff;
	unsigned long remain;

	/* Bypass checks for special case of MRAI being 0 */
	if (peer->v_routeadv == 0) {
		/* Stop existing timer, just in case it is running for a
		 * different
		 * duration and schedule write thread immediately.
		 */
		THREAD_OFF(peer->t_routeadv);

		peer->synctime = monotime(NULL);
		/* If suppress fib pending is enabled, route is advertised to
		 * peers when the status is received from the FIB. The delay
		 * is added to update group packet generate which will allow
		 * more routes to be sent in the update message
		 */
		BGP_UPDATE_GROUP_TIMER_ON(&peer->t_generate_updgrp_packets,
					  bgp_generate_updgrp_packets);
		return;
	}


	/*
	 * CASE I:
	 * If the last update was written more than MRAI back, expire the timer
	 * instantly so that we can send the update out sooner.
	 *
	 *                           <-------  MRAI --------->
	 *         |-----------------|-----------------------|
	 *         <------------- m ------------>
	 *         ^                 ^          ^
	 *         |                 |          |
	 *         |                 |     current time
	 *         |            timer start
	 *      last write
	 *
	 *                     m > MRAI
	 */
	diff = difftime(nowtime, peer->last_update);
	if (diff > (double)peer->v_routeadv) {
		THREAD_OFF(peer->t_routeadv);
		BGP_TIMER_ON(peer->t_routeadv, bgp_routeadv_timer, 0);
		return;
	}

	/*
	 * CASE II:
	 * - Find when to expire the MRAI timer.
	 *   If MRAI timer is not active, assume we can start it now.
	 *
	 *                      <-------  MRAI --------->
	 *         |------------|-----------------------|
	 *         <-------- m ----------><----- r ----->
	 *         ^            ^        ^
	 *         |            |        |
	 *         |            |   current time
	 *         |       timer start
	 *      last write
	 *
	 *                     (MRAI - m) < r
	 */
	if (peer->t_routeadv)
		remain = thread_timer_remain_second(peer->t_routeadv);
	else
		remain = peer->v_routeadv;
	diff = peer->v_routeadv - diff;
	if (diff <= (double)remain) {
		THREAD_OFF(peer->t_routeadv);
		BGP_TIMER_ON(peer->t_routeadv, bgp_routeadv_timer, diff);
	}
}

static bool bgp_maxmed_onstartup_applicable(struct bgp *bgp)
{
	if (!bgp->maxmed_onstartup_over)
		return true;
	return false;
}

bool bgp_maxmed_onstartup_configured(struct bgp *bgp)
{
	if (bgp->v_maxmed_onstartup != BGP_MAXMED_ONSTARTUP_UNCONFIGURED)
		return true;
	return false;
}

bool bgp_maxmed_onstartup_active(struct bgp *bgp)
{
	if (bgp->t_maxmed_onstartup)
		return true;
	return false;
}

void bgp_maxmed_update(struct bgp *bgp)
{
	uint8_t maxmed_active;
	uint32_t maxmed_value;

	if (bgp->v_maxmed_admin) {
		maxmed_active = 1;
		maxmed_value = bgp->maxmed_admin_value;
	} else if (bgp->t_maxmed_onstartup) {
		maxmed_active = 1;
		maxmed_value = bgp->maxmed_onstartup_value;
	} else {
		maxmed_active = 0;
		maxmed_value = BGP_MAXMED_VALUE_DEFAULT;
	}

	if (bgp->maxmed_active != maxmed_active
	    || bgp->maxmed_value != maxmed_value) {
		bgp->maxmed_active = maxmed_active;
		bgp->maxmed_value = maxmed_value;

		update_group_announce(bgp);
	}
}

int bgp_fsm_error_subcode(int status)
{
	int fsm_err_subcode = BGP_NOTIFY_FSM_ERR_SUBCODE_UNSPECIFIC;

	switch (status) {
	case OpenSent:
		fsm_err_subcode = BGP_NOTIFY_FSM_ERR_SUBCODE_OPENSENT;
		break;
	case OpenConfirm:
		fsm_err_subcode = BGP_NOTIFY_FSM_ERR_SUBCODE_OPENCONFIRM;
		break;
	case Established:
		fsm_err_subcode = BGP_NOTIFY_FSM_ERR_SUBCODE_ESTABLISHED;
		break;
	default:
		break;
	}

	return fsm_err_subcode;
}

/* The maxmed onstartup timer expiry callback. */
static void bgp_maxmed_onstartup_timer(struct thread *thread)
{
	struct bgp *bgp;

	zlog_info("Max med on startup ended - timer expired.");

	bgp = THREAD_ARG(thread);
	THREAD_OFF(bgp->t_maxmed_onstartup);
	bgp->maxmed_onstartup_over = 1;

	bgp_maxmed_update(bgp);
}

static void bgp_maxmed_onstartup_begin(struct bgp *bgp)
{
	/* Applicable only once in the process lifetime on the startup */
	if (bgp->maxmed_onstartup_over)
		return;

	zlog_info("Begin maxmed onstartup mode - timer %d seconds",
		  bgp->v_maxmed_onstartup);

	thread_add_timer(bm->master, bgp_maxmed_onstartup_timer, bgp,
			 bgp->v_maxmed_onstartup, &bgp->t_maxmed_onstartup);

	if (!bgp->v_maxmed_admin) {
		bgp->maxmed_active = 1;
		bgp->maxmed_value = bgp->maxmed_onstartup_value;
	}

	/* Route announce to all peers should happen after this in
	 * bgp_establish() */
}

static void bgp_maxmed_onstartup_process_status_change(struct peer *peer)
{
	if (peer_established(peer) && !peer->bgp->established) {
		bgp_maxmed_onstartup_begin(peer->bgp);
	}
}

/* The update delay timer expiry callback. */
static void bgp_update_delay_timer(struct thread *thread)
{
	struct bgp *bgp;

	zlog_info("Update delay ended - timer expired.");

	bgp = THREAD_ARG(thread);
	THREAD_OFF(bgp->t_update_delay);
	bgp_update_delay_end(bgp);
}

/* The establish wait timer expiry callback. */
static void bgp_establish_wait_timer(struct thread *thread)
{
	struct bgp *bgp;

	zlog_info("Establish wait - timer expired.");

	bgp = THREAD_ARG(thread);
	THREAD_OFF(bgp->t_establish_wait);
	bgp_check_update_delay(bgp);
}

/* Steps to begin the update delay:
     - initialize queues if needed
     - stop the queue processing
     - start the timer */
static void bgp_update_delay_begin(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	/* Stop the processing of queued work. Enqueue shall continue */
	work_queue_plug(bgp->process_queue);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		peer->update_delay_over = 0;

	/* Start the update-delay timer */
	thread_add_timer(bm->master, bgp_update_delay_timer, bgp,
			 bgp->v_update_delay, &bgp->t_update_delay);

	if (bgp->v_establish_wait != bgp->v_update_delay)
		thread_add_timer(bm->master, bgp_establish_wait_timer, bgp,
				 bgp->v_establish_wait, &bgp->t_establish_wait);

	frr_timestamp(3, bgp->update_delay_begin_time,
		      sizeof(bgp->update_delay_begin_time));
}

static void bgp_update_delay_process_status_change(struct peer *peer)
{
	if (peer_established(peer)) {
		if (!peer->bgp->established++) {
			bgp_update_delay_begin(peer->bgp);
			zlog_info(
				"Begin read-only mode - update-delay timer %d seconds",
				peer->bgp->v_update_delay);
		}
		if (CHECK_FLAG(peer->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV))
			bgp_update_restarted_peers(peer);
	}
	if (peer->ostatus == Established
	    && bgp_update_delay_active(peer->bgp)) {
		/* Adjust the update-delay state to account for this flap.
		   NOTE: Intentionally skipping adjusting implicit_eors or
		   explicit_eors
		   counters. Extra sanity check in bgp_check_update_delay()
		   should
		   be enough to take care of any additive discrepancy in bgp eor
		   counters */
		peer->bgp->established--;
		peer->update_delay_over = 0;
	}
}

static bool bgp_gr_check_all_eors(struct bgp *bgp, afi_t afi, safi_t safi,
				  bool *multihop_eors_pending)
{
	struct listnode *node, *nnode;
	struct peer *peer = NULL;
	bool eor_rcvd_from_all_mh_peers = true;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s: Checking all peers for EOR receipt for %s",
			   bgp->name_pretty,
			   get_afi_safi_str(afi, safi, false));

	frrtrace(4, frr_bgp, gr_eors, bgp->name_pretty, afi, safi, 1);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {

		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
				"....examining peer %s status %s flags 0x%" PRIx64
				" af_sflags 0x%x",
				peer->host,
				lookup_msg(bgp_status_msg, peer->status, NULL),
				peer->flags, peer->af_sflags[afi][safi]);
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE) ||
		    CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN) ||
		    !CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
			continue;

		if (!CHECK_FLAG(peer->af_sflags[afi][safi],
				PEER_STATUS_GR_WAIT_EOR))
			continue;

		if (!CHECK_FLAG(peer->af_sflags[afi][safi],
				PEER_STATUS_EOR_RECEIVED)) {
			if (!bgp->gr_multihop_peer_exists) {
				/*
				 * This AFI-SAFI doesn't have a mix of directly
				 * connected and multihop peers. So we don't
				 * need to do 2 level deferred bestpath
				 * calculation.
				 */
				if (BGP_DEBUG(graceful_restart,
					      GRACEFUL_RESTART))
					zlog_debug(
						".... EOR still awaited from this peer for this AFI/SAFI");
				frrtrace(5, frr_bgp, gr_eor_peer,
					 bgp->name_pretty, afi, safi,
					 peer->host, 1);

				return false;
			} else {

				if (!peer->afc[afi][safi]) {
					if (BGP_DEBUG(graceful_restart,
						      GRACEFUL_RESTART))
						zlog_debug(
							".... Ignoring EOR from %s. %s is not configured",
							peer->host,
							get_afi_safi_str(
								afi, safi,
								false));
					frrtrace(5, frr_bgp, gr_eor_peer,
						 bgp->name_pretty, afi, safi,
						 peer->host, 2);
					continue;
				}
				/*
				 * This afi-safi(v4-uni or v6-unicast) has a mix
				 * of directly connected and multihop peers.
				 * Since multihop peers could depend on prefixes
				 * learnt from directly connected peers to form
				 * the BGP session, BGP needs to do 2 level
				 * deferred bestpath selection.
				 *
				 * 1st level of deferred bestpath selection will
				 * be done when EORs are recieved from all the
				 * directly connected peers, or when the
				 * select-deferral-timer expires. If the timer
				 * expired, it means that some of the directly
				 * connected peers didn't come up at all. So on
				 * timer expiry, BGP will check to see if
				 * there's a mix of directly-connected and
				 * multihop peers for that afi-safi. if yes,
				 * then BGP will start the tier2-select-deferral
				 * timer and wait for all the multihop peers to
				 * come up, send EORs and then do 2nd deferred
				 * bestpath selection.
				 *
				 * After EORs are rcvd from all the directly
				 * connected peers, BGP will check if there are
				 * any multihop peers from whom we are yet to
				 * rcv EORs. If yes, BGP will start
				 * tier2-select-deferral timer and wait for all
				 * the multihop peers to come up and send EORs.
				 *
				 * If before tier2-select-deferral timer expiry,
				 * if all multihop peers send EOR then BGP will
				 * cancel the tier2 timer and do 2nd deferred
				 * bestpath selection.
				 *
				 * Here, even if the peerB has
				 * disable-connected-check configured, it will
				 * be treated as directly connected peer. This
				 * is because, peerB's session coming up
				 * wouldn't depend on some other BGP session
				 * coming up and learning prefixes.
				 */
				if (PEER_IS_MULTIHOP(peer)) {
					/*
					 * If we have not recieved EOR from a
					 * multihop peer, start the tier2
					 * select-deferral-timer only if EORs
					 * are rcvd from all the directly
					 * connected peers
					 */
					eor_rcvd_from_all_mh_peers = false;
					if (BGP_DEBUG(graceful_restart,
						      GRACEFUL_RESTART))
						zlog_debug(
							".... EOR still awaited from this multihop peer for this AFI/SAFI");
					frrtrace(5, frr_bgp, gr_eor_peer,
						 bgp->name_pretty, afi, safi,
						 peer->host, 3);
				} else {
					/*
					 * If EOR from directly connected peer
					 * is not rcvd even after tier1 timer
					 * expiry, then we are going to ignore
					 * this peer since this peer may not
					 * come up at all.
					 */
					if (bgp->gr_info[afi][safi]
						    .select_defer_over) {
						if (BGP_DEBUG(graceful_restart,
							      GRACEFUL_RESTART))
							zlog_debug(
								".... Ignoring directly connected peer %s. Tier1 GR timer has expired already for %s",
								peer->host,
								get_afi_safi_str(
									afi,
									safi,
									false));
						frrtrace(5, frr_bgp,
							 gr_eor_peer,
							 bgp->name_pretty, afi,
							 safi, peer->host, 4);

						continue;
					}
					/*
					 * If this is a directly connected peer
					 * and if we haven't recieved EOR from
					 * this peer yet, then we will wait to
					 * do the 1st round of deferred
					 * bestpath.
					 */
					if (BGP_DEBUG(graceful_restart,
						      GRACEFUL_RESTART))
						zlog_debug(
							".... EOR still awaited from this directly connected peer for this AFI/SAFI");
					frrtrace(5, frr_bgp, gr_eor_peer,
						 bgp->name_pretty, afi, safi,
						 peer->host, 5);

					return false;
				}
			}
		}
	}

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			".... EOR received from all directly connected peers for this AFI/SAFI");
	frrtrace(4, frr_bgp, gr_eors, bgp->name_pretty, afi, safi, 2);


	/*
	 * EOR is rcvd from all the directly connected peers at this point.
	 *
	 * If EOR is not rcvd from all of the multihop(MH) peers
	 * for this AFI-SAFI then start the tier2-select-deferral-timer
	 * and wait for all MH peers to comeup.
	 *
	 * Note that tier2 GR select deferral timer is started only
	 * after EOR is rcvd from all the directly connected peers.
	 *
	 * TODO: If EORs is not rcvd from all the directly connected peers
	 * then select deferral timer will expire. So when select deferral timer
	 * expires, we will check if there are any multihop peers from whom
	 * we have not rcvd EOR yet. If we find any and if the tier2 timer has
	 * not been started yet, then we will start the timer there.
	 */
	if (!eor_rcvd_from_all_mh_peers) {
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
				".... EOR NOT received from all multihop peers for this AFI/SAFI");
		frrtrace(4, frr_bgp, gr_eors, bgp->name_pretty, afi, safi, 3);

		bgp_start_tier2_deferral_timer(bgp, afi, safi);
		*multihop_eors_pending = true;
	} else {
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
				".... EOR received from all expected peers for this AFI/SAFI");
		frrtrace(4, frr_bgp, gr_eors, bgp->name_pretty, afi, safi, 4);
	}

	return true;
}

void bgp_gr_check_path_select(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct graceful_restart_info *gr_info;
	bool multihop_eors_pending = false;

	if (bgp_gr_check_all_eors(bgp, afi, safi, &multihop_eors_pending)) {
		gr_info = &(bgp->gr_info[afi][safi]);
		THREAD_OFF(gr_info->t_select_deferral);

		/*
		 * If there are no pending EORs from multihop peers
		 * then cancel the timer.
		 */
		if (!multihop_eors_pending) {
			THREAD_OFF(gr_info->t_select_deferral_tier2);
			gr_info->select_defer_over_tier2 = true;
			if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
				zlog_debug(
					"%s: No multihop EORs pending for %s, #routes %d -- EORs recvd",
					bgp->name_pretty,
					get_afi_safi_str(afi, safi, false),
					gr_info->gr_deferred);

			frrtrace(4, frr_bgp, gr_eors, bgp->name_pretty, afi,
				 safi, 5);
		}

		gr_info->select_defer_over = true;
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
				"%s: Starting deferred path selection for %s, #routes %d -- EORs recvd",
				bgp->name_pretty,
				get_afi_safi_str(afi, safi, false),
				gr_info->gr_deferred);

		frrtrace(4, frr_bgp, gr_start_deferred_path_selection,
			 bgp->name_pretty, afi, safi, gr_info->gr_deferred);

		bgp_do_deferred_path_selection(bgp, afi, safi);
	}
}

static void bgp_gr_mark_for_deferred_selection(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	/*
	 * Mark all peers in the instance for EOR wait for the
	 * AFI/SAFI supported for GR.
	 */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		FOREACH_AFI_SAFI_NSF (afi, safi) {
			if (bgp_gr_supported_for_afi_safi(afi, safi))
				SET_FLAG(peer->af_sflags[afi][safi],
					 PEER_STATUS_GR_WAIT_EOR);
			else
				UNSET_FLAG(peer->af_sflags[afi][safi],
					   PEER_STATUS_GR_WAIT_EOR);
		}
	}
}

/*
 * Evaluate if GR is enabled for a mix of directly-connected and
 * multihop peers in ipv4-unicast and ipv6-unicast AFI-SAFI.
 */
static void bgp_gr_evaluate_mix_peer_type(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	bgp->gr_multihop_peer_exists = false;

	FOREACH_AFI_SAFI_NSF (afi, safi) {
		/*
		 * GR is not supported for this afi-safi
		 */
		if (!bgp_gr_supported_for_afi_safi(afi, safi))
			continue;

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			/*
			 * If this is not a config node or
			 * if this peer is admin shutdown or
			 * if GR is not enabled for peer then skip this
			 * peer
			 */
			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE) ||
			    CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN) ||
			    !CHECK_FLAG(peer->flags,
					PEER_FLAG_GRACEFUL_RESTART))
				continue;

			/*
			 * If this is a multihop peer with GR supported
			 * afi-safi is configured for it, then set the
			 * value to true.
			 */
			if (PEER_IS_MULTIHOP(peer) && peer->afc[afi][safi]) {
				bgp->gr_multihop_peer_exists = true;
				return;
			}
		}
	}
}

/*
 * Start the selection deferral timer thread for the specified AFI, SAFI,
 * mark peers from whom we need an EOR and inform zebra
 */
static void bgp_start_deferral_timer(struct bgp *bgp, afi_t afi, safi_t safi,
				     struct graceful_restart_info *gr_info)
{
	struct afi_safi_info *thread_info;

	/*
	 * When starting to defer the path-selection for an instance and
	 * AFI/SAFI, mark that EOR is required from all peers.
	 * For non-established peers, simply mark EOR required, the flag
	 * will be reset based on negotiated AFI/SAFI later on.
	 * For established peers, the caller would have set this already
	 * for negotiated AFI/SAFI.
	 */

	/* Start the timer */
	thread_info = XMALLOC(MTYPE_TMP, sizeof(struct afi_safi_info));

	thread_info->afi = afi;
	thread_info->safi = safi;
	thread_info->bgp = bgp;
	thread_info->tier2_gr = false;

	thread_add_timer(bm->master, bgp_graceful_deferral_timer_expire,
			 thread_info, bgp->select_defer_time,
			 &gr_info->t_select_deferral);

	gr_info->af_enabled = true;
	bgp->gr_route_sync_pending = true;

	/* Inform zebra */
	bgp_zebra_update(bgp, afi, safi, ZEBRA_CLIENT_ROUTE_UPDATE_PENDING);

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"%s: Started path-select deferral timer for %s, duration %ds",
			bgp->name_pretty, get_afi_safi_str(afi, safi, false),
			bgp->select_defer_time);

	frrtrace(5, frr_bgp, gr_deferral_timer_start, bgp->name_pretty, afi,
		 safi, bgp->select_defer_time, 1);
}

/*
 * start the GR deferral timer for all GR supported afi-safis
 */
void bgp_gr_start_all_deferral_timers(struct bgp *bgp)
{
	struct graceful_restart_info *gr_info;
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (!bgp_gr_supported_for_afi_safi(afi, safi))
			continue;

		gr_info = &(bgp->gr_info[afi][safi]);
		if (!gr_info->t_select_deferral)
			bgp_start_deferral_timer(bgp, afi, safi, gr_info);
	}
}

static void bgp_gr_process_peer_up_ignore(struct bgp *bgp, struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	/*
	 * If peer has restarted, GR is disabled for peer or not negotiated
	 * with the peer, we have to ignore this peer for EOR-wait. This
	 * might also be the last peer we were waiting for, so check if
	 * we can move forward with path-selection.
	 */
	FOREACH_AFI_SAFI_NSF (afi, safi) {
		UNSET_FLAG(peer->af_sflags[afi][safi], PEER_STATUS_GR_WAIT_EOR);
		if (bgp_gr_supported_for_afi_safi(afi, safi))
			bgp_gr_check_path_select(bgp, afi, safi);
	}
}

static void bgp_gr_process_peer_up_include(struct bgp *bgp, struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	struct graceful_restart_info *gr_info;

	/*
	 * If peer has not restarted and is potentially a valid Helper,
	 * we need to wait for EOR from the peer for each AFI/SAFI that
	 * has been negotiated. This should also start the path selection
	 * deferral, if not yet done. OTOH, for non-negotiated AFI/SAFI,
	 * we need to check if path-selection can proceed.
	 */
	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (!peer->afc_nego[afi][safi]) {
			UNSET_FLAG(peer->af_sflags[afi][safi],
				   PEER_STATUS_GR_WAIT_EOR);
			if (bgp_gr_supported_for_afi_safi(afi, safi))
				bgp_gr_check_path_select(bgp, afi, safi);
		} else if (!bgp_gr_supported_for_afi_safi(afi, safi)) {
			UNSET_FLAG(peer->af_sflags[afi][safi],
				   PEER_STATUS_GR_WAIT_EOR);
		} else {
			SET_FLAG(peer->af_sflags[afi][safi],
				 PEER_STATUS_GR_WAIT_EOR);
			gr_info = &(bgp->gr_info[afi][safi]);
			if (!gr_info->t_select_deferral &&
			    !gr_info->select_defer_over)
				bgp_start_deferral_timer(bgp, afi, safi,
							 gr_info);
		}
	}
}

static void bgp_gr_process_peer_status_change(struct peer *peer)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	bgp = peer->bgp;

	if (peer->status == Established) {
		/*
		 * If we haven't yet evaluated for path selection deferral,
		 * do it now.
		 *
		 * If we haven't yet evaluated the presence of both directly
		 * connected and multihop peers, do it now.
		 */
		if (!bgp->gr_select_defer_evaluated) {
			bgp_gr_mark_for_deferred_selection(bgp);
			bgp_gr_evaluate_mix_peer_type(bgp);
			bgp->gr_select_defer_evaluated = true;
		}

		/*
		 * Peer has come up. We need to figure out if we need to
		 * wait for EOR from this peer for negotiated AFI/SAFI
		 * and potentially start deferred path selection. For any
		 * non-negotiated AFI/SAFI or if the peer has restarted etc.,
		 * evaluate if path-selection deferral should end
		 */
		if (CHECK_FLAG(peer->cap,
			       PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV) ||
		    !CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART) ||
		    !BGP_PEER_GRACEFUL_RESTART_CAPABLE(peer)) {

			if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
				zlog_debug(
					"%s: Peer %s cap 0x%x flags 0x%" PRIx64
					" restarted or GR not negotiated, check for path-selection",
					bgp->name_pretty, peer->host, peer->cap,
					peer->flags);

			frrtrace(4, frr_bgp, gr_peer_up_ignore,
				 bgp->name_pretty, peer->host, peer->cap,
				 peer->flags);

			bgp_gr_process_peer_up_ignore(bgp, peer);
		} else {
			bgp_gr_process_peer_up_include(bgp, peer);
		}
	} else if (peer->ostatus == Established) {
		/*
		 * If a peer (Helper) went down after establishing the
		 * session, we will not wait for a EOR from it.
		 * Note: This is not spelt out well in the RFC.
		 */
		FOREACH_AFI_SAFI_NSF (afi, safi)
			UNSET_FLAG(peer->af_sflags[afi][safi],
				   PEER_STATUS_GR_WAIT_EOR);
	}
}

static bool gr_path_select_deferral_applicable(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;

	/* True if BGP has (re)started gracefully (based on start
	 * settings and GR is not complete and path selection
	 * deferral not yet done for this instance
	 */
	if (!bgp_in_graceful_restart())
		return false;

	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (!bgp_gr_supported_for_afi_safi(afi, safi))
			continue;

		/*
		 * If GR is not enabled for this VRF,
		 * select-deferral-timer will not be started for any of
		 * the GR supported AFI-SAFIs. In that case, continue
		 */
		if (!bgp->gr_info[afi][safi].af_enabled)
			continue;


		if (!BGP_GR_SELECT_DEFER_DONE(bgp, afi, safi))
			return true;
	}

	return false;
}

/* Called after event occurred, this function change status and reset
   read/write and timer thread. */
void bgp_fsm_change_status(struct peer *peer, int status)
{
	struct bgp *bgp;
	uint32_t peer_count;

	bgp = peer->bgp;
	peer_count = bgp->established_peers;

	if (status == Established)
		bgp->established_peers++;
	else if ((peer_established(peer)) && (status != Established))
		bgp->established_peers--;

	if (bgp_debug_neighbor_events(peer)) {
		struct vrf *vrf = vrf_lookup_by_id(bgp->vrf_id);

		zlog_debug("%s : vrf %s(%u), Status: %s established_peers %u", __func__,
			   vrf ? vrf->name : "Unknown", bgp->vrf_id,
			   lookup_msg(bgp_status_msg, status, NULL),
			   bgp->established_peers);
	}

	/* Set to router ID to the value provided by RIB if there are no peers
	 * in the established state and peer count did not change
	 */
	if ((peer_count != bgp->established_peers) &&
	    (bgp->established_peers == 0))
		bgp_router_id_zebra_bump(bgp->vrf_id, NULL);

	/* Transition into Clearing or Deleted must /always/ clear all routes..
	 * (and must do so before actually changing into Deleted..
	 */
	if (status >= Clearing) {
		bgp_clear_route_all(peer);

		/* If no route was queued for the clear-node processing,
		 * generate the
		 * completion event here. This is needed because if there are no
		 * routes
		 * to trigger the background clear-node thread, the event won't
		 * get
		 * generated and the peer would be stuck in Clearing. Note that
		 * this
		 * event is for the peer and helps the peer transition out of
		 * Clearing
		 * state; it should not be generated per (AFI,SAFI). The event
		 * is
		 * directly posted here without calling clear_node_complete() as
		 * we
		 * shouldn't do an extra unlock. This event will get processed
		 * after
		 * the state change that happens below, so peer will be in
		 * Clearing
		 * (or Deleted).
		 */
		if (!work_queue_is_scheduled(peer->clear_node_queue) &&
		    status != Deleted)
			BGP_EVENT_ADD(peer, Clearing_Completed);
	}

	/* Preserve old status and change into new status. */
	peer->ostatus = peer->status;
	peer->status = status;

	/* Reset received keepalives counter on every FSM change */
	peer->rtt_keepalive_rcv = 0;

	/* Fire backward transition hook if that's the case */
	if (peer->ostatus > peer->status)
		hook_call(peer_backward_transition, peer);

	/* Save event that caused status change. */
	peer->last_major_event = peer->cur_event;

	/* Operations after status change */
	hook_call(peer_status_changed, peer);

	if (status == Established)
		UNSET_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER);

	/* If max-med processing is applicable, do the necessary. */
	if (status == Established) {
		if (bgp_maxmed_onstartup_configured(peer->bgp)
		    && bgp_maxmed_onstartup_applicable(peer->bgp))
			bgp_maxmed_onstartup_process_status_change(peer);
		else
			peer->bgp->maxmed_onstartup_over = 1;
	}

	/* Check for GR restarter or update-delay processing. */
	if (gr_path_select_deferral_applicable(peer->bgp))
		bgp_gr_process_peer_status_change(peer);
	else if (bgp_update_delay_configured(peer->bgp) &&
		 bgp_update_delay_applicable(peer->bgp))
		bgp_update_delay_process_status_change(peer);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s fd %d went from %s to %s",
			   peer->host, peer->fd,
			   lookup_msg(bgp_status_msg, peer->ostatus, NULL),
			   lookup_msg(bgp_status_msg, peer->status, NULL));
}

/* Flush the event queue and ensure the peer is shut down */
static int bgp_clearing_completed(struct peer *peer)
{
	int rc = bgp_stop(peer);

	if (rc >= 0)
		BGP_EVENT_FLUSH(peer);

	return rc;
}

/* Administrative BGP peer stop event. */
/* May be called multiple times for the same peer */
int bgp_stop(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	char orf_name[BUFSIZ];
	int ret = 0;

	peer->nsf_af_count = 0;

	/* deregister peer */
	if (peer->bfd_config
	    && peer->last_reset == PEER_DOWN_UPDATE_SOURCE_CHANGE)
		bfd_sess_uninstall(peer->bfd_config->session);

	if (peer_dynamic_neighbor_no_nsf(peer) &&
	    !(CHECK_FLAG(peer->flags, PEER_FLAG_DELETE))) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
		return -2;
	}

	/* Can't do this in Clearing; events are used for state transitions */
	if (peer->status != Clearing) {
		/* Delete all existing events of the peer */
		BGP_EVENT_FLUSH(peer);
	}

	/* Increment Dropped count. */
	if (peer_established(peer)) {
		peer->dropped++;

		/* Notify BGP conditional advertisement process */
		peer->advmap_table_change = true;

		/* bgp log-neighbor-changes of neighbor Down */
		if (CHECK_FLAG(peer->bgp->flags,
			       BGP_FLAG_LOG_NEIGHBOR_CHANGES)) {
			struct vrf *vrf = vrf_lookup_by_id(peer->bgp->vrf_id);

			zlog_info(
				"%%ADJCHANGE: neighbor %pBP in vrf %s Down %s",
				peer,
				vrf ? ((vrf->vrf_id != VRF_DEFAULT)
					       ? vrf->name
					       : VRF_DEFAULT_NAME)
				    : "",
				peer_down_str[(int)peer->last_reset]);
		}

		/* graceful restart */
		if (peer->t_gr_stale) {
			THREAD_OFF(peer->t_gr_stale);
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP graceful restart stalepath timer stopped",
					peer);
		}
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {
			if (bgp_debug_neighbor_events(peer)) {
				zlog_debug(
					"%pBP graceful restart timer started for %d sec",
					peer, peer->v_gr_restart);
				zlog_debug(
					"%pBP graceful restart stalepath timer started for %d sec",
					peer, peer->bgp->stalepath_time);
			}
			BGP_TIMER_ON(peer->t_gr_restart,
				     bgp_graceful_restart_timer_expire,
				     peer->v_gr_restart);
			BGP_TIMER_ON(peer->t_gr_stale,
				     bgp_graceful_stale_timer_expire,
				     peer->bgp->stalepath_time);
		} else {
			UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);

			FOREACH_AFI_SAFI_NSF (afi, safi)
				peer->nsf[afi][safi] = 0;
		}

		/* Stop route-refresh stalepath timer */
		if (peer->t_refresh_stalepath) {
			THREAD_OFF(peer->t_refresh_stalepath);

			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP route-refresh restart stalepath timer stopped",
					peer);
		}

		/* set last reset time */
		peer->resettime = peer->uptime = monotime(NULL);

		if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
			zlog_debug("%s remove from all update group",
				   peer->host);
		update_group_remove_peer_afs(peer);

		/* Reset peer synctime */
		peer->synctime = 0;
	}

	/* stop keepalives */
	bgp_keepalives_off(peer);

	/* Stop read and write threads. */
	bgp_writes_off(peer);
	bgp_reads_off(peer);

	THREAD_OFF(peer->t_connect_check_r);
	THREAD_OFF(peer->t_connect_check_w);

	/* Stop all timers. */
	THREAD_OFF(peer->t_start);
	THREAD_OFF(peer->t_connect);
	THREAD_OFF(peer->t_holdtime);
	THREAD_OFF(peer->t_routeadv);
	THREAD_OFF(peer->t_delayopen);

	/* Clear input and output buffer.  */
	frr_with_mutex (&peer->io_mtx) {
		if (peer->ibuf)
			stream_fifo_clean(peer->ibuf);
		if (peer->obuf)
			stream_fifo_clean(peer->obuf);

		if (peer->ibuf_work)
			ringbuf_wipe(peer->ibuf_work);

		if (peer->curr) {
			stream_free(peer->curr);
			peer->curr = NULL;
		}
	}

	/* Close of file descriptor. */
	if (peer->fd >= 0) {
		close(peer->fd);
		peer->fd = -1;
	}

	/* Reset capabilities. */
	peer->cap = 0;

	/* Resetting neighbor role to the default value */
	peer->remote_role = ROLE_UNDEFINED;

	FOREACH_AFI_SAFI (afi, safi) {
		/* Reset all negotiated variables */
		peer->afc_nego[afi][safi] = 0;
		peer->afc_adv[afi][safi] = 0;
		peer->afc_recv[afi][safi] = 0;

		/* peer address family capability flags*/
		peer->af_cap[afi][safi] = 0;

		/* peer address family status flags*/
		/* Don't clear WAIT_EOR */
		if (CHECK_FLAG(peer->af_sflags[afi][safi],
				PEER_STATUS_GR_WAIT_EOR)) {
			peer->af_sflags[afi][safi] = 0;
			SET_FLAG(peer->af_sflags[afi][safi],
				 PEER_STATUS_GR_WAIT_EOR);
		} else
			peer->af_sflags[afi][safi] = 0;

		/* Received ORF prefix-filter */
		peer->orf_plist[afi][safi] = NULL;

		if ((peer->status == OpenConfirm) || (peer_established(peer))) {
			/* ORF received prefix-filter pnt */
			snprintf(orf_name, sizeof(orf_name), "%s.%d.%d",
				 peer->host, afi, safi);
			prefix_bgp_orf_remove_all(afi, orf_name);
		}
	}

	/* Reset keepalive and holdtime */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER)) {
		peer->v_keepalive = peer->keepalive;
		peer->v_holdtime = peer->holdtime;
	} else {
		peer->v_keepalive = peer->bgp->default_keepalive;
		peer->v_holdtime = peer->bgp->default_holdtime;
	}

	/* Reset DelayOpenTime */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
		peer->v_delayopen = peer->delayopen;
	else
		peer->v_delayopen = peer->bgp->default_delayopen;

	peer->update_time = 0;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE)
	    && !(CHECK_FLAG(peer->flags, PEER_FLAG_DELETE))) {
		peer_delete(peer);
		ret = -2;
	} else {
		bgp_peer_conf_if_to_su_update(peer);
	}
	return ret;
}

/* BGP peer is stoped by the error. */
static int bgp_stop_with_error(struct peer *peer)
{
	/* Double start timer. */
	peer->v_start *= 2;

	/* Overflow check. */
	if (peer->v_start >= (60 * 2))
		peer->v_start = (60 * 2);

	if (peer_dynamic_neighbor_no_nsf(peer)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
		return -1;
	}

	return (bgp_stop(peer));
}


/* something went wrong, send notify and tear down */
static int bgp_stop_with_notify(struct peer *peer, uint8_t code,
				uint8_t sub_code)
{
	/* Send notify to remote peer */
	bgp_notify_send(peer, code, sub_code);

	if (peer_dynamic_neighbor_no_nsf(peer)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
		return -1;
	}

	/* Clear start timer value to default. */
	peer->v_start = BGP_INIT_START_TIMER;

	return (bgp_stop(peer));
}

/**
 * Determines whether a TCP session has successfully established for a peer and
 * events as appropriate.
 *
 * This function is called when setting up a new session. After connect() is
 * called on the peer's socket (in bgp_start()), the fd is passed to poll()
 * to wait for connection success or failure. When poll() returns, this
 * function is called to evaluate the result.
 *
 * Due to differences in behavior of poll() on Linux and BSD - specifically,
 * the value of .revents in the case of a closed connection - this function is
 * scheduled both for a read and a write event. The write event is triggered
 * when the connection is established. A read event is triggered when the
 * connection is closed. Thus we need to cancel whichever one did not occur.
 */
static void bgp_connect_check(struct thread *thread)
{
	int status;
	socklen_t slen;
	int ret;
	struct peer *peer;

	peer = THREAD_ARG(thread);
	assert(!CHECK_FLAG(peer->thread_flags, PEER_THREAD_READS_ON));
	assert(!CHECK_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON));
	assert(!peer->t_read);
	assert(!peer->t_write);

	THREAD_OFF(peer->t_connect_check_r);
	THREAD_OFF(peer->t_connect_check_w);

	/* Check file descriptor. */
	slen = sizeof(status);
	ret = getsockopt(peer->fd, SOL_SOCKET, SO_ERROR, (void *)&status,
			 &slen);

	/* If getsockopt is fail, this is fatal error. */
	if (ret < 0) {
		zlog_err("can't get sockopt for nonblocking connect: %d(%s)",
			  errno, safe_strerror(errno));
		BGP_EVENT_ADD(peer, TCP_fatal_error);
		return;
	}

	/* When status is 0 then TCP connection is established. */
	if (status == 0) {
		if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
			BGP_EVENT_ADD(peer, TCP_connection_open_w_delay);
		else
			BGP_EVENT_ADD(peer, TCP_connection_open);
		return;
	} else {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s [Event] Connect failed %d(%s)",
				   peer->host, status, safe_strerror(status));
		BGP_EVENT_ADD(peer, TCP_connection_open_failed);
		return;
	}
}

/* TCP connection open.  Next we send open message to remote peer. And
   add read thread for reading open message. */
static int bgp_connect_success(struct peer *peer)
{
	if (peer->fd < 0) {
		flog_err(EC_BGP_CONNECT, "%s peer's fd is negative value %d",
			 __func__, peer->fd);
		bgp_stop(peer);
		return -1;
	}

	if (bgp_getsockname(peer) < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: bgp_getsockname(): failed for peer %s, fd %d",
			     __func__, peer->host, peer->fd);
		bgp_notify_send(peer, BGP_NOTIFY_FSM_ERR,
				bgp_fsm_error_subcode(peer->status));
		bgp_writes_on(peer);
		return -1;
	}

	/*
	 * If we are doing nht for a peer that ls v6 LL based
	 * massage the event system to make things happy
	 */
	bgp_nht_interface_events(peer);

	bgp_reads_on(peer);

	if (bgp_debug_neighbor_events(peer)) {
		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER))
			zlog_debug("%s open active, local address %pSU",
				   peer->host, peer->su_local);
		else
			zlog_debug("%s passive open", peer->host);
	}

	/* Send an open message */
	bgp_open_send(peer);

	return 0;
}

/* TCP connection open with RFC 4271 optional session attribute DelayOpen flag
 * set.
 */
static int bgp_connect_success_w_delayopen(struct peer *peer)
{
	if (peer->fd < 0) {
		flog_err(EC_BGP_CONNECT, "%s: peer's fd is negative value %d",
			 __func__, peer->fd);
		bgp_stop(peer);
		return -1;
	}

	if (bgp_getsockname(peer) < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: bgp_getsockname(): failed for peer %s, fd %d",
			     __func__, peer->host, peer->fd);
		bgp_notify_send(peer, BGP_NOTIFY_FSM_ERR,
				bgp_fsm_error_subcode(peer->status));
		bgp_writes_on(peer);
		return -1;
	}

	/*
	 * If we are doing nht for a peer that ls v6 LL based
	 * massage the event system to make things happy
	 */
	bgp_nht_interface_events(peer);

	bgp_reads_on(peer);

	if (bgp_debug_neighbor_events(peer)) {
		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER))
			zlog_debug("%s open active, local address %pSU",
				   peer->host, peer->su_local);
		else
			zlog_debug("%s passive open", peer->host);
	}

	/* set the DelayOpenTime to the inital value */
	peer->v_delayopen = peer->delayopen;

	/* Start the DelayOpenTimer if it is not already running */
	if (!peer->t_delayopen)
		BGP_TIMER_ON(peer->t_delayopen, bgp_delayopen_timer,
			     peer->v_delayopen);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] BGP OPEN message delayed for %d seconds",
			   peer->host, peer->delayopen);

	return 0;
}

/* TCP connect fail */
static int bgp_connect_fail(struct peer *peer)
{
	if (peer_dynamic_neighbor_no_nsf(peer)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
		return -1;
	}

	/*
	 * If we are doing nht for a peer that ls v6 LL based
	 * massage the event system to make things happy
	 */
	bgp_nht_interface_events(peer);

	return (bgp_stop(peer));
}

/* This function is the first starting point of all BGP connection. It
 * try to connect to remote peer with non-blocking IO.
 */
int bgp_start(struct peer *peer)
{
	int status;

	bgp_peer_conf_if_to_su_update(peer);

	if (peer->su.sa.sa_family == AF_UNSPEC) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s [FSM] Unable to get neighbor's IP address, waiting...",
				peer->host);
		peer->last_reset = PEER_DOWN_NBR_ADDR;
		return -1;
	}

	if (BGP_PEER_START_SUPPRESSED(peer)) {
		if (bgp_debug_neighbor_events(peer))
			flog_err(EC_BGP_FSM,
				 "%s [FSM] Trying to start suppressed peer - this is never supposed to happen!",
				 peer->host);
		if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN))
			peer->last_reset = PEER_DOWN_USER_SHUTDOWN;
		else if (CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SHUTDOWN))
			peer->last_reset = PEER_DOWN_USER_SHUTDOWN;
		else if (CHECK_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
			peer->last_reset = PEER_DOWN_PFX_COUNT;
		return -1;
	}

	/* Scrub some information that might be left over from a previous,
	 * session
	 */
	/* Connection information. */
	if (peer->su_local) {
		sockunion_free(peer->su_local);
		peer->su_local = NULL;
	}

	if (peer->su_remote) {
		sockunion_free(peer->su_remote);
		peer->su_remote = NULL;
	}

	/* Clear remote router-id. */
	peer->remote_id.s_addr = INADDR_ANY;

	/* Clear peer capability flag. */
	peer->cap = 0;

	/* If the peer is passive mode, force to move to Active mode. */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSIVE)) {
		BGP_EVENT_ADD(peer, TCP_connection_open_failed);
		return 0;
	}

	if (peer->bgp->vrf_id == VRF_UNKNOWN) {
		if (bgp_debug_neighbor_events(peer))
			flog_err(
				EC_BGP_FSM,
				"%s [FSM] In a VRF that is not initialised yet",
				peer->host);
		peer->last_reset = PEER_DOWN_VRF_UNINIT;
		return -1;
	}

	/* Register peer for NHT. If next hop is already resolved, proceed
	 * with connection setup, else wait.
	 */
	if (!bgp_peer_reg_with_nht(peer)) {
		if (bgp_zebra_num_connects()) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug("%s [FSM] Waiting for NHT",
					   peer->host);
			peer->last_reset = PEER_DOWN_WAITING_NHT;
			BGP_EVENT_ADD(peer, TCP_connection_open_failed);
			return 0;
		}
	}

	assert(!peer->t_write);
	assert(!peer->t_read);
	assert(!CHECK_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON));
	assert(!CHECK_FLAG(peer->thread_flags, PEER_THREAD_READS_ON));
	status = bgp_connect(peer);

	switch (status) {
	case connect_error:
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s [FSM] Connect error", peer->host);
		BGP_EVENT_ADD(peer, TCP_connection_open_failed);
		break;
	case connect_success:
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s [FSM] Connect immediately success, fd %d",
				peer->host, peer->fd);

		BGP_EVENT_ADD(peer, TCP_connection_open);
		break;
	case connect_in_progress:
		/* To check nonblocking connect, we wait until socket is
		   readable or writable. */
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s [FSM] Non blocking connect waiting result, fd %d",
				peer->host, peer->fd);
		if (peer->fd < 0) {
			flog_err(EC_BGP_FSM,
				 "%s peer's fd is negative value %d", __func__,
				 peer->fd);
			return -1;
		}
		/*
		 * - when the socket becomes ready, poll() will signify POLLOUT
		 * - if it fails to connect, poll() will signify POLLHUP
		 * - POLLHUP is handled as a 'read' event by thread.c
		 *
		 * therefore, we schedule both a read and a write event with
		 * bgp_connect_check() as the handler for each and cancel the
		 * unused event in that function.
		 */
		thread_add_read(bm->master, bgp_connect_check, peer, peer->fd,
				&peer->t_connect_check_r);
		thread_add_write(bm->master, bgp_connect_check, peer, peer->fd,
				 &peer->t_connect_check_w);
		break;
	}
	return 0;
}

/* Connect retry timer is expired when the peer status is Connect. */
static int bgp_reconnect(struct peer *peer)
{
	if (bgp_stop(peer) < 0)
		return -1;

	/* Send graceful restart capabilty */
	BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(peer->bgp,
							  peer->bgp->peer);

	bgp_start(peer);
	return 0;
}

static int bgp_fsm_open(struct peer *peer)
{
	/* If DelayOpen is active, we may still need to send an open message */
	if ((peer->status == Connect) || (peer->status == Active))
		bgp_open_send(peer);

	/* Send keepalive and make keepalive timer */
	bgp_keepalive_send(peer);

	return 0;
}

/* FSM error, unexpected event.  This is error of BGP connection. So cut the
   peer and change to Idle status. */
static int bgp_fsm_event_error(struct peer *peer)
{
	flog_err(EC_BGP_FSM, "%s [FSM] unexpected packet received in state %s",
		 peer->host, lookup_msg(bgp_status_msg, peer->status, NULL));

	return bgp_stop_with_notify(peer, BGP_NOTIFY_FSM_ERR,
				    bgp_fsm_error_subcode(peer->status));
}

/* Hold timer expire.  This is error of BGP connection. So cut the
   peer and change to Idle status. */
static int bgp_fsm_holdtime_expire(struct peer *peer)
{
	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Hold timer expire", peer->host);

	/* RFC8538 updates RFC 4724 by defining an extension that permits
	 * the Graceful Restart procedures to be performed when the BGP
	 * speaker receives a BGP NOTIFICATION message or the Hold Time expires.
	 */
	if (peer_established(peer) &&
	    bgp_has_graceful_restart_notification(peer))
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_MODE))
			SET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);

	return bgp_stop_with_notify(peer, BGP_NOTIFY_HOLD_ERR, 0);
}

/* RFC 4271 DelayOpenTimer_Expires event */
static int bgp_fsm_delayopen_timer_expire(struct peer *peer)
{
	/* Stop the DelayOpenTimer */
	THREAD_OFF(peer->t_delayopen);

	/* Send open message to peer */
	bgp_open_send(peer);

	/* Set the HoldTimer to a large value (4 minutes) */
	peer->v_holdtime = 245;

	return 0;
}

/*
 * Upon session becoming established, process the GR capabilities announced
 * by the peer, and clear stale routes if the peer has not announced a
 * previously announced (afi,safi) or doesn't preserve forwarding for them.
 * The clearing of stale routes applies only to a Helper router.
 */
static void bgp_peer_process_gr_cap_clear_stale(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	int nsf_af_count = 0;

	if (peer->t_gr_restart) {
		THREAD_OFF(peer->t_gr_restart);
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s: graceful restart timer stopped",
				   peer->host);
	}

	UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);
	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (peer->afc_nego[afi][safi] &&
		    CHECK_FLAG(peer->cap, PEER_CAP_RESTART_ADV) &&
		    CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_RESTART_AF_RCV)) {
			/*
			 * If an (afi,safi) is negotiated with the
			 * peer and it has announced the GR capab
			 * for it, it supports NSF for this (afi,
			 * safi). However, if the peer didn't adv
			 * the F-bit, any previous (stale) routes
			 * should be flushed.
			 */
			if (peer->nsf[afi][safi] &&
			    !CHECK_FLAG(peer->af_cap[afi][safi],
					PEER_CAP_RESTART_AF_PRESERVE_RCV))
				bgp_clear_stale_route(peer, afi, safi);

			peer->nsf[afi][safi] = 1;
			nsf_af_count++;
		} else {
			/*
			 * Some other situation like (afi,safi) not
			 * negotiated, GR not negotiated etc. Clear
			 * any previous (stale) routes.
			 */
			if (peer->nsf[afi][safi])
				bgp_clear_stale_route(peer, afi, safi);
			peer->nsf[afi][safi] = 0;
		}
	}

	peer->nsf_af_count = nsf_af_count;

	if (nsf_af_count)
		SET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);
	else {
		UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);
		if (peer->t_gr_stale) {
			THREAD_OFF(peer->t_gr_stale);
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s: graceful restart stalepath timer stopped",
					peer->host);
		}
	}
}

/**
 * Transition to Established state.
 *
 * Convert peer from stub to full fledged peer, set some timers, and generate
 * initial updates.
 */
static int bgp_establish(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	int ret = 0;
	struct peer *other;
	struct peer *orig = peer;

	other = peer->doppelganger;
	hash_release(peer->bgp->peerhash, peer);
	if (other)
		hash_release(peer->bgp->peerhash, other);

	peer = peer_xfer_conn(peer);
	if (!peer) {
		flog_err(EC_BGP_CONNECT, "%%Neighbor failed in xfer_conn");

		/*
		 * A failure of peer_xfer_conn but not putting the peers
		 * back in the hash ends up with a situation where incoming
		 * connections are rejected, as that the peer is not found
		 * when a lookup is done
		 */
		(void)hash_get(orig->bgp->peerhash, orig, hash_alloc_intern);
		if (other)
			(void)hash_get(other->bgp->peerhash, other,
				       hash_alloc_intern);
		return BGP_FSM_FAILURE;
	}

	if (other == peer)
		ret = 1; /* bgp_establish specific code when xfer_conn
			    happens. */

	/* Reset capability open status flag. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_CAPABILITY_OPEN))
		SET_FLAG(peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

	/* Clear start timer value to default. */
	peer->v_start = BGP_INIT_START_TIMER;

	/* Increment established count. */
	peer->established++;
	bgp_fsm_change_status(peer, Established);

	/* bgp log-neighbor-changes of neighbor Up */
	if (CHECK_FLAG(peer->bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES)) {
		struct vrf *vrf = vrf_lookup_by_id(peer->bgp->vrf_id);
		zlog_info("%%ADJCHANGE: neighbor %pBP in vrf %s Up", peer,
			  vrf ? ((vrf->vrf_id != VRF_DEFAULT)
					 ? vrf->name
					 : VRF_DEFAULT_NAME)
			      : "");
	}

	/* assign update-group/subgroup */
	update_group_adjust_peer_afs(peer);

	/* graceful restart handling */
	bgp_peer_process_gr_cap_clear_stale(peer);

	/* Reset uptime, turn on keepalives, send current table. */
	if (!peer->v_holdtime)
		bgp_keepalives_on(peer);

	peer->uptime = monotime(NULL);

	/* Send route-refresh when ORF is enabled.
	 * Stop Long-lived Graceful Restart timers.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (peer->t_llgr_stale[afi][safi]) {
			THREAD_OFF(peer->t_llgr_stale[afi][safi]);
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP Long-lived stale timer stopped for afi/safi: %d/%d",
					peer, afi, safi);
		}

		if (CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_ADV)) {
			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ORF_PREFIX_RM_RCV))
				bgp_route_refresh_send(
					peer, afi, safi, ORF_TYPE_PREFIX,
					REFRESH_IMMEDIATE, 0,
					BGP_ROUTE_REFRESH_NORMAL);
			else if (CHECK_FLAG(peer->af_cap[afi][safi],
					    PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
				bgp_route_refresh_send(
					peer, afi, safi, ORF_TYPE_PREFIX_OLD,
					REFRESH_IMMEDIATE, 0,
					BGP_ROUTE_REFRESH_NORMAL);
		}
	}

	/* First update is deferred until ORF or ROUTE-REFRESH is received */
	FOREACH_AFI_SAFI (afi, safi) {
		if (CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_RM_ADV))
			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ORF_PREFIX_SM_RCV)
			    || CHECK_FLAG(peer->af_cap[afi][safi],
					  PEER_CAP_ORF_PREFIX_SM_OLD_RCV))
				SET_FLAG(peer->af_sflags[afi][safi],
					 PEER_STATUS_ORF_WAIT_REFRESH);
	}

	bgp_announce_peer(peer);

	/* Start the route advertisement timer to send updates to the peer - if
	 * BGP
	 * is not in read-only mode. If it is, the timer will be started at the
	 * end
	 * of read-only mode.
	 */
	if (!bgp_update_delay_active(peer->bgp)) {
		THREAD_OFF(peer->t_routeadv);
		BGP_TIMER_ON(peer->t_routeadv, bgp_routeadv_timer, 0);
	}

	if (peer->doppelganger && (peer->doppelganger->status != Deleted)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"[Event] Deleting stub connection for peer %s",
				peer->host);

		if (peer->doppelganger->status > Active)
			bgp_notify_send(peer->doppelganger, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
		else
			peer_delete(peer->doppelganger);
	}

	/*
	 * If we are replacing the old peer for a doppelganger
	 * then switch it around in the bgp->peerhash
	 * the doppelgangers su and this peer's su are the same
	 * so the hash_release is the same for either.
	 */
	(void)hash_get(peer->bgp->peerhash, peer, hash_alloc_intern);

	/* Start BFD peer if not already running. */
	if (peer->bfd_config)
		bgp_peer_bfd_update_source(peer);

	return ret;
}

/* Keepalive packet is received. */
static int bgp_fsm_keepalive(struct peer *peer)
{
	THREAD_OFF(peer->t_holdtime);
	return 0;
}

/* Update packet is received. */
static int bgp_fsm_update(struct peer *peer)
{
	THREAD_OFF(peer->t_holdtime);
	return 0;
}

/* This is empty event. */
static int bgp_ignore(struct peer *peer)
{
	flog_err(
		EC_BGP_FSM,
		"%s [FSM] Ignoring event %s in state %s, prior events %s, %s, fd %d",
		peer->host, bgp_event_str[peer->cur_event],
		lookup_msg(bgp_status_msg, peer->status, NULL),
		bgp_event_str[peer->last_event],
		bgp_event_str[peer->last_major_event], peer->fd);
	return 0;
}

/* This is to handle unexpected events.. */
static int bgp_fsm_exeption(struct peer *peer)
{
	flog_err(
		EC_BGP_FSM,
		"%s [FSM] Unexpected event %s in state %s, prior events %s, %s, fd %d",
		peer->host, bgp_event_str[peer->cur_event],
		lookup_msg(bgp_status_msg, peer->status, NULL),
		bgp_event_str[peer->last_event],
		bgp_event_str[peer->last_major_event], peer->fd);
	return (bgp_stop(peer));
}

void bgp_fsm_nht_update(struct peer *peer, bool has_valid_nexthops)
{
	if (!peer)
		return;

	switch (peer->status) {
	case Idle:
		if (has_valid_nexthops)
			BGP_EVENT_ADD(peer, BGP_Start);
		break;
	case Connect:
		if (!has_valid_nexthops) {
			THREAD_OFF(peer->t_connect);
			BGP_EVENT_ADD(peer, TCP_fatal_error);
		}
		break;
	case Active:
		if (has_valid_nexthops) {
			THREAD_OFF(peer->t_connect);
			BGP_EVENT_ADD(peer, ConnectRetry_timer_expired);
		}
		break;
	case OpenSent:
	case OpenConfirm:
	case Established:
		if (!has_valid_nexthops
		    && (peer->gtsm_hops == BGP_GTSM_HOPS_CONNECTED
			|| peer->bgp->fast_convergence))
			BGP_EVENT_ADD(peer, TCP_fatal_error);
	case Clearing:
	case Deleted:
	default:
		break;
	}
}

/* Finite State Machine structure */
static const struct {
	int (*func)(struct peer *);
	enum bgp_fsm_status next_state;
} FSM[BGP_STATUS_MAX - 1][BGP_EVENTS_MAX - 1] = {
	{
		/* Idle state: In Idle state, all events other than BGP_Start is
		   ignored.  With BGP_Start event, finite state machine calls
		   bgp_start(). */
		{bgp_start, Connect}, /* BGP_Start                    */
		{bgp_stop, Idle},     /* BGP_Stop                     */
		{bgp_stop, Idle},     /* TCP_connection_open          */
		{bgp_stop, Idle},     /* TCP_connection_open_w_delay */
		{bgp_stop, Idle},     /* TCP_connection_closed        */
		{bgp_ignore, Idle},   /* TCP_connection_open_failed   */
		{bgp_stop, Idle},     /* TCP_fatal_error              */
		{bgp_ignore, Idle},   /* ConnectRetry_timer_expired   */
		{bgp_ignore, Idle},   /* Hold_Timer_expired           */
		{bgp_ignore, Idle},   /* KeepAlive_timer_expired      */
		{bgp_ignore, Idle},   /* DelayOpen_timer_expired */
		{bgp_ignore, Idle},   /* Receive_OPEN_message         */
		{bgp_ignore, Idle},   /* Receive_KEEPALIVE_message    */
		{bgp_ignore, Idle},   /* Receive_UPDATE_message       */
		{bgp_ignore, Idle},   /* Receive_NOTIFICATION_message */
		{bgp_ignore, Idle},   /* Clearing_Completed           */
	},
	{
		/* Connect */
		{bgp_ignore, Connect}, /* BGP_Start                    */
		{bgp_stop, Idle},      /* BGP_Stop                     */
		{bgp_connect_success, OpenSent}, /* TCP_connection_open */
		{bgp_connect_success_w_delayopen,
		 Connect},		    /* TCP_connection_open_w_delay */
		{bgp_stop, Idle},	   /* TCP_connection_closed        */
		{bgp_connect_fail, Active}, /* TCP_connection_open_failed   */
		{bgp_connect_fail, Idle},   /* TCP_fatal_error              */
		{bgp_reconnect, Connect},   /* ConnectRetry_timer_expired   */
		{bgp_fsm_exeption, Idle},   /* Hold_Timer_expired           */
		{bgp_fsm_exeption, Idle},   /* KeepAlive_timer_expired      */
		{bgp_fsm_delayopen_timer_expire,
		 OpenSent},		     /* DelayOpen_timer_expired */
		{bgp_fsm_open, OpenConfirm}, /* Receive_OPEN_message         */
		{bgp_fsm_exeption, Idle},    /* Receive_KEEPALIVE_message    */
		{bgp_fsm_exeption, Idle},    /* Receive_UPDATE_message       */
		{bgp_stop, Idle},	    /* Receive_NOTIFICATION_message */
		{bgp_fsm_exeption, Idle},    /* Clearing_Completed           */
	},
	{
		/* Active, */
		{bgp_ignore, Active}, /* BGP_Start                    */
		{bgp_stop, Idle},     /* BGP_Stop                     */
		{bgp_connect_success, OpenSent}, /* TCP_connection_open */
		{bgp_connect_success_w_delayopen,
		 Active},		  /* TCP_connection_open_w_delay */
		{bgp_stop, Idle},	 /* TCP_connection_closed        */
		{bgp_ignore, Active},     /* TCP_connection_open_failed   */
		{bgp_fsm_exeption, Idle}, /* TCP_fatal_error              */
		{bgp_start, Connect},     /* ConnectRetry_timer_expired   */
		{bgp_fsm_exeption, Idle}, /* Hold_Timer_expired           */
		{bgp_fsm_exeption, Idle}, /* KeepAlive_timer_expired      */
		{bgp_fsm_delayopen_timer_expire,
		 OpenSent},		     /* DelayOpen_timer_expired */
		{bgp_fsm_open, OpenConfirm}, /* Receive_OPEN_message         */
		{bgp_fsm_exeption, Idle},    /* Receive_KEEPALIVE_message    */
		{bgp_fsm_exeption, Idle},    /* Receive_UPDATE_message       */
		{bgp_fsm_exeption, Idle},    /* Receive_NOTIFICATION_message */
		{bgp_fsm_exeption, Idle},    /* Clearing_Completed           */
	},
	{
		/* OpenSent, */
		{bgp_ignore, OpenSent},   /* BGP_Start                    */
		{bgp_stop, Idle},	 /* BGP_Stop                     */
		{bgp_stop, Active},       /* TCP_connection_open          */
		{bgp_fsm_exeption, Idle}, /* TCP_connection_open_w_delay */
		{bgp_stop, Active},       /* TCP_connection_closed        */
		{bgp_stop, Active},       /* TCP_connection_open_failed   */
		{bgp_stop, Active},       /* TCP_fatal_error              */
		{bgp_fsm_exeption, Idle}, /* ConnectRetry_timer_expired   */
		{bgp_fsm_holdtime_expire, Idle}, /* Hold_Timer_expired */
		{bgp_fsm_exeption, Idle},    /* KeepAlive_timer_expired      */
		{bgp_fsm_exeption, Idle},    /* DelayOpen_timer_expired */
		{bgp_fsm_open, OpenConfirm}, /* Receive_OPEN_message         */
		{bgp_fsm_event_error, Idle}, /* Receive_KEEPALIVE_message    */
		{bgp_fsm_event_error, Idle}, /* Receive_UPDATE_message       */
		{bgp_fsm_event_error, Idle}, /* Receive_NOTIFICATION_message */
		{bgp_fsm_exeption, Idle},    /* Clearing_Completed           */
	},
	{
		/* OpenConfirm, */
		{bgp_ignore, OpenConfirm}, /* BGP_Start                    */
		{bgp_stop, Idle},	  /* BGP_Stop                     */
		{bgp_stop, Idle},	  /* TCP_connection_open          */
		{bgp_fsm_exeption, Idle},  /* TCP_connection_open_w_delay */
		{bgp_stop, Idle},	  /* TCP_connection_closed        */
		{bgp_stop, Idle},	  /* TCP_connection_open_failed   */
		{bgp_stop, Idle},	  /* TCP_fatal_error              */
		{bgp_fsm_exeption, Idle},  /* ConnectRetry_timer_expired   */
		{bgp_fsm_holdtime_expire, Idle}, /* Hold_Timer_expired */
		{bgp_ignore, OpenConfirm},    /* KeepAlive_timer_expired      */
		{bgp_fsm_exeption, Idle},     /* DelayOpen_timer_expired */
		{bgp_fsm_exeption, Idle},     /* Receive_OPEN_message         */
		{bgp_establish, Established}, /* Receive_KEEPALIVE_message    */
		{bgp_fsm_exeption, Idle},     /* Receive_UPDATE_message       */
		{bgp_stop_with_error, Idle},  /* Receive_NOTIFICATION_message */
		{bgp_fsm_exeption, Idle},     /* Clearing_Completed           */
	},
	{
		/* Established, */
		{bgp_ignore, Established}, /* BGP_Start                    */
		{bgp_stop, Clearing},      /* BGP_Stop                     */
		{bgp_stop, Clearing},      /* TCP_connection_open          */
		{bgp_fsm_exeption, Idle},  /* TCP_connection_open_w_delay */
		{bgp_stop, Clearing},      /* TCP_connection_closed        */
		{bgp_stop, Clearing},      /* TCP_connection_open_failed   */
		{bgp_stop, Clearing},      /* TCP_fatal_error              */
		{bgp_stop, Clearing},      /* ConnectRetry_timer_expired   */
		{bgp_fsm_holdtime_expire, Clearing}, /* Hold_Timer_expired */
		{bgp_ignore, Established}, /* KeepAlive_timer_expired      */
		{bgp_fsm_exeption, Idle},  /* DelayOpen_timer_expired */
		{bgp_stop, Clearing},      /* Receive_OPEN_message         */
		{bgp_fsm_keepalive,
		 Established}, /* Receive_KEEPALIVE_message    */
		{bgp_fsm_update, Established}, /* Receive_UPDATE_message */
		{bgp_stop_with_error,
		 Clearing},		  /* Receive_NOTIFICATION_message */
		{bgp_fsm_exeption, Idle}, /* Clearing_Completed           */
	},
	{
		/* Clearing, */
		{bgp_ignore, Clearing}, /* BGP_Start                    */
		{bgp_stop, Clearing},   /* BGP_Stop                     */
		{bgp_stop, Clearing},   /* TCP_connection_open          */
		{bgp_stop, Clearing},   /* TCP_connection_open_w_delay */
		{bgp_stop, Clearing},   /* TCP_connection_closed        */
		{bgp_stop, Clearing},   /* TCP_connection_open_failed   */
		{bgp_stop, Clearing},   /* TCP_fatal_error              */
		{bgp_stop, Clearing},   /* ConnectRetry_timer_expired   */
		{bgp_stop, Clearing},   /* Hold_Timer_expired           */
		{bgp_stop, Clearing},   /* KeepAlive_timer_expired      */
		{bgp_stop, Clearing},   /* DelayOpen_timer_expired */
		{bgp_stop, Clearing},   /* Receive_OPEN_message         */
		{bgp_stop, Clearing},   /* Receive_KEEPALIVE_message    */
		{bgp_stop, Clearing},   /* Receive_UPDATE_message       */
		{bgp_stop, Clearing},   /* Receive_NOTIFICATION_message */
		{bgp_clearing_completed, Idle}, /* Clearing_Completed */
	},
	{
		/* Deleted, */
		{bgp_ignore, Deleted}, /* BGP_Start                    */
		{bgp_ignore, Deleted}, /* BGP_Stop                     */
		{bgp_ignore, Deleted}, /* TCP_connection_open          */
		{bgp_ignore, Deleted}, /* TCP_connection_open_w_delay */
		{bgp_ignore, Deleted}, /* TCP_connection_closed        */
		{bgp_ignore, Deleted}, /* TCP_connection_open_failed   */
		{bgp_ignore, Deleted}, /* TCP_fatal_error              */
		{bgp_ignore, Deleted}, /* ConnectRetry_timer_expired   */
		{bgp_ignore, Deleted}, /* Hold_Timer_expired           */
		{bgp_ignore, Deleted}, /* KeepAlive_timer_expired      */
		{bgp_ignore, Deleted}, /* DelayOpen_timer_expired */
		{bgp_ignore, Deleted}, /* Receive_OPEN_message         */
		{bgp_ignore, Deleted}, /* Receive_KEEPALIVE_message    */
		{bgp_ignore, Deleted}, /* Receive_UPDATE_message       */
		{bgp_ignore, Deleted}, /* Receive_NOTIFICATION_message */
		{bgp_ignore, Deleted}, /* Clearing_Completed           */
	},
};

/* Execute event process. */
void bgp_event(struct thread *thread)
{
	enum bgp_fsm_events event;
	struct peer *peer;

	peer = THREAD_ARG(thread);
	event = THREAD_VAL(thread);

	peer_lock(peer);
	bgp_event_update(peer, event);
	peer_unlock(peer);
}

int bgp_event_update(struct peer *peer, enum bgp_fsm_events event)
{
	enum bgp_fsm_status next;
	int ret = 0;
	struct peer *other;
	int passive_conn = 0;
	int dyn_nbr;

	/* default return code */
	ret = FSM_PEER_NOOP;

	other = peer->doppelganger;
	passive_conn =
		(CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER)) ? 1 : 0;
	dyn_nbr = peer_dynamic_neighbor(peer);

	/* Logging this event. */
	next = FSM[peer->status - 1][event - 1].next_state;

	if (bgp_debug_neighbor_events(peer) && peer->status != next)
		zlog_debug("%s [FSM] %s (%s->%s), fd %d", peer->host,
			   bgp_event_str[event],
			   lookup_msg(bgp_status_msg, peer->status, NULL),
			   lookup_msg(bgp_status_msg, next, NULL), peer->fd);

	peer->last_event = peer->cur_event;
	peer->cur_event = event;

	/* Call function. */
	if (FSM[peer->status - 1][event - 1].func)
		ret = (*(FSM[peer->status - 1][event - 1].func))(peer);

	if (ret >= 0) {
		if (ret == 1 && next == Established) {
			/* The case when doppelganger swap accurred in
			   bgp_establish.
			   Update the peer pointer accordingly */
			ret = FSM_PEER_TRANSFERRED;
			peer = other;
		}

		/* If status is changed. */
		if (next != peer->status) {
			bgp_fsm_change_status(peer, next);

			/*
			 * If we're going to ESTABLISHED then we executed a
			 * peer transfer. In this case we can either return
			 * FSM_PEER_TRANSITIONED or FSM_PEER_TRANSFERRED.
			 * Opting for TRANSFERRED since transfer implies
			 * session establishment.
			 */
			if (ret != FSM_PEER_TRANSFERRED)
				ret = FSM_PEER_TRANSITIONED;
		}

		/* Make sure timer is set. */
		bgp_timer_set(peer);

	} else {
		/*
		 * If we got a return value of -1, that means there was an
		 * error, restart the FSM. Since bgp_stop() was called on the
		 * peer. only a few fields are safe to access here. In any case
		 * we need to indicate that the peer was stopped in the return
		 * code.
		 */
		if (!dyn_nbr && !passive_conn && peer->bgp && ret != -2) {
			flog_err(
				EC_BGP_FSM,
				"%s [FSM] Failure handling event %s in state %s, prior events %s, %s, fd %d",
				peer->host, bgp_event_str[peer->cur_event],
				lookup_msg(bgp_status_msg, peer->status, NULL),
				bgp_event_str[peer->last_event],
				bgp_event_str[peer->last_major_event],
				peer->fd);
			bgp_stop(peer);
			bgp_fsm_change_status(peer, Idle);
			bgp_timer_set(peer);
		}
		ret = FSM_PEER_STOPPED;
	}

	return ret;
}
/* BGP GR Code */

static inline void
bgp_peer_inherit_global_gr_mode(struct peer *peer,
				enum global_mode global_gr_mode)
{
	if (global_gr_mode == GLOBAL_HELPER)
		BGP_PEER_GR_HELPER_ENABLE(peer);
	else if (global_gr_mode == GLOBAL_GR)
		BGP_PEER_GR_ENABLE(peer);
	else if (global_gr_mode == GLOBAL_DISABLE)
		BGP_PEER_GR_DISABLE(peer);
	else
		zlog_err("Unexpected Global GR mode %d", global_gr_mode);
}

static void bgp_gr_update_mode_of_all_peers(struct bgp *bgp,
					    enum global_mode global_new_state)
{
	struct peer *peer = {0};
	struct listnode *node = {0};
	struct listnode *nnode = {0};
	enum peer_mode peer_old_state = PEER_INVALID;

	/* TODO: Need to handle peer-groups. */

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {

		peer_old_state = bgp_peer_gr_mode_get(peer);
		if (peer_old_state != PEER_GLOBAL_INHERIT)
			continue;

		bgp_peer_inherit_global_gr_mode(peer, global_new_state);
		bgp_peer_gr_flags_update(peer);

		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
				"... %s: Inherited Global GR mode, GR flags 0x%x peer flags 0x%" PRIx64
				"...resetting session",
				peer->host, peer->peer_gr_new_status_flag,
				peer->flags);

		/* Reset session to match with behavior for other peer
		 * configs that require the session to be re-setup.
		 */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			peer->last_reset = PEER_DOWN_CAPABILITY_CHANGE;
			bgp_notify_send(peer, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			bgp_session_reset(peer);
	}
}

int bgp_gr_update_all(struct bgp *bgp, int global_gr_cmd)
{
	enum global_mode global_new_state = GLOBAL_INVALID;
	enum global_mode global_old_state = GLOBAL_INVALID;

	global_old_state = bgp_global_gr_mode_get(bgp);
	global_new_state = bgp->GLOBAL_GR_FSM[global_old_state][global_gr_cmd];

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"%s: Handle GR command %s, current GR state %s, new GR state %s",
			bgp->name_pretty, print_global_gr_cmd(global_gr_cmd),
			print_global_gr_mode(global_old_state),
			print_global_gr_mode(global_new_state));

	if (global_old_state == GLOBAL_INVALID)
		return BGP_ERR_GR_OPERATION_FAILED;
	/* Next state 'invalid is actually an 'ignore' */
	if (global_new_state == GLOBAL_INVALID)
		return BGP_GR_NO_OPERATION;
	if (global_new_state == global_old_state)
		return BGP_GR_NO_OPERATION;

	/* Update global GR mode and process all peers in instance. */
	bgp->global_gr_present_state = global_new_state;
	bgp_gr_update_mode_of_all_peers(bgp, global_new_state);

	return BGP_GR_SUCCESS;
}

const char *print_peer_gr_mode(enum peer_mode pr_mode)
{
	const char *peer_gr_mode = NULL;

	switch (pr_mode) {
	case PEER_HELPER:
		peer_gr_mode = "PEER_HELPER";
		break;
	case PEER_GR:
		peer_gr_mode = "PEER_GR";
		break;
	case PEER_DISABLE:
		peer_gr_mode = "PEER_DISABLE";
		break;
	case PEER_INVALID:
		peer_gr_mode = "PEER_INVALID";
		break;
	case PEER_GLOBAL_INHERIT:
		peer_gr_mode = "PEER_GLOBAL_INHERIT";
		break;
	}

	return peer_gr_mode;
}

const char *print_peer_gr_cmd(enum peer_gr_command pr_gr_cmd)
{
	const char *peer_gr_cmd = NULL;

	switch (pr_gr_cmd) {
	case PEER_GR_CMD:
		peer_gr_cmd = "PEER_GR_CMD";
		break;
	case NO_PEER_GR_CMD:
		peer_gr_cmd = "NO_PEER_GR_CMD";
		break;
	case PEER_DISABLE_CMD:
		peer_gr_cmd = "PEER_DISABLE_GR_CMD";
		break;
	case NO_PEER_DISABLE_CMD:
		peer_gr_cmd = "NO_PEER_DISABLE_GR_CMD";
		break;
	case PEER_HELPER_CMD:
		peer_gr_cmd = "PEER_HELPER_CMD";
		break;
	case NO_PEER_HELPER_CMD:
		peer_gr_cmd = "NO_PEER_HELPER_CMD";
		break;
	}

	return peer_gr_cmd;
}

const char *print_global_gr_mode(enum global_mode gl_mode)
{
	const char *global_gr_mode = NULL;

	switch (gl_mode) {
	case GLOBAL_HELPER:
		global_gr_mode = "GLOBAL_HELPER";
		break;
	case GLOBAL_GR:
		global_gr_mode = "GLOBAL_GR";
		break;
	case GLOBAL_DISABLE:
		global_gr_mode = "GLOBAL_DISABLE";
		break;
	case GLOBAL_INVALID:
		global_gr_mode = "GLOBAL_INVALID";
		break;
	}

	return global_gr_mode;
}

const char *print_global_gr_cmd(enum global_gr_command gl_gr_cmd)
{
	const char *global_gr_cmd = NULL;

	switch (gl_gr_cmd) {
	case GLOBAL_GR_CMD:
		global_gr_cmd = "GLOBAL_GR_CMD";
		break;
	case NO_GLOBAL_GR_CMD:
		global_gr_cmd = "NO_GLOBAL_GR_CMD";
		break;
	case GLOBAL_DISABLE_CMD:
		global_gr_cmd = "GLOBAL_DISABLE_CMD";
		break;
	case NO_GLOBAL_DISABLE_CMD:
		global_gr_cmd = "NO_GLOBAL_DISABLE_CMD";
		break;
	}

	return global_gr_cmd;
}

enum global_mode bgp_global_gr_mode_get(struct bgp *bgp)
{
	return bgp->global_gr_present_state;
}

enum peer_mode bgp_peer_gr_mode_get(struct peer *peer)
{
	return peer->peer_gr_present_state;
}

int bgp_neighbor_graceful_restart(struct peer *peer, int peer_gr_cmd)
{
	enum peer_mode peer_new_state = PEER_INVALID;
	enum peer_mode peer_old_state = PEER_INVALID;
	struct bgp_peer_gr gr_fsm;
	int result = BGP_GR_FAILURE;

	/* TODO: Needs to handle peer-groups. */

	peer_old_state = bgp_peer_gr_mode_get(peer);
	gr_fsm = peer->PEER_GR_FSM[peer_old_state][peer_gr_cmd];
	peer_new_state = gr_fsm.next_state;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"%s: Handle GR command %s, current GR state %s, new GR state %s",
			peer->host, print_peer_gr_cmd(peer_gr_cmd),
			print_peer_gr_mode(peer_old_state),
			print_peer_gr_mode(peer_new_state));

	if (peer_old_state == PEER_INVALID)
		return BGP_ERR_GR_OPERATION_FAILED;

	/* Next state 'invalid' is actually an 'ignore' */
	if (peer_new_state == PEER_INVALID)
		return BGP_GR_NO_OPERATION;

	if (peer_new_state == peer_old_state)
		return BGP_GR_NO_OPERATION;

	result = gr_fsm.action_fun(peer, peer_old_state, peer_new_state);

	return result;
}

static inline bool gr_mode_matches(enum peer_mode peer_gr_mode,
				   enum global_mode global_gr_mode)
{
	if ((peer_gr_mode == PEER_HELPER && global_gr_mode == GLOBAL_HELPER) ||
	    (peer_gr_mode == PEER_GR && global_gr_mode == GLOBAL_GR) ||
	    (peer_gr_mode == PEER_DISABLE && global_gr_mode == GLOBAL_DISABLE))
		return true;
	return false;
}

unsigned int bgp_peer_gr_action(struct peer *peer, enum peer_mode old_state,
				enum peer_mode new_state)
{
	enum global_mode global_gr_mode = bgp_global_gr_mode_get(peer->bgp);
	bool session_reset = true;

	if (old_state == new_state)
		return BGP_GR_NO_OPERATION;
	if ((old_state == PEER_INVALID) || (new_state == PEER_INVALID))
		return BGP_ERR_GR_INVALID_CMD;

	global_gr_mode = bgp_global_gr_mode_get(peer->bgp);

	if ((old_state == PEER_GLOBAL_INHERIT) &&
	    (new_state != PEER_GLOBAL_INHERIT)) {

		BGP_PEER_GR_GLOBAL_INHERIT_UNSET(peer);

		if (gr_mode_matches(new_state, global_gr_mode))
			/* Peer was inheriting the global state and
			 * its new state still is the same, so a
			 * session reset is not needed.
			 */
			session_reset = false;
	} else if ((new_state == PEER_GLOBAL_INHERIT) &&
		   (old_state != PEER_GLOBAL_INHERIT)) {

		BGP_PEER_GR_GLOBAL_INHERIT_SET(peer);

		if (gr_mode_matches(old_state, global_gr_mode))
			/* Peer is inheriting the global state and
			 * its old state was also the same, so a
			 * session reset is not needed.
			 */
			session_reset = false;
	}

	/* Ensure we move to the new state and update flags */
	bgp_peer_move_to_gr_mode(peer, new_state);

	if (session_reset) {
		/* Reset session to match with behavior for other peer
		 * configs that require the session to be re-setup.
		 */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			peer->last_reset = PEER_DOWN_CAPABILITY_CHANGE;
			bgp_notify_send(peer, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			bgp_session_reset(peer);
	}

	return BGP_GR_SUCCESS;
}

void bgp_peer_move_to_gr_mode(struct peer *peer, enum peer_mode new_state)

{
	enum global_mode global_gr_mode = bgp_global_gr_mode_get(peer->bgp);
	enum peer_mode old_state = bgp_peer_gr_mode_get(peer);

	switch (new_state) {
	case PEER_HELPER:
		BGP_PEER_GR_HELPER_ENABLE(peer);
		break;
	case PEER_GR:
		BGP_PEER_GR_ENABLE(peer);
		break;
	case PEER_DISABLE:
		BGP_PEER_GR_DISABLE(peer);
		break;
	case PEER_GLOBAL_INHERIT:
		BGP_PEER_GR_GLOBAL_INHERIT_SET(peer);
		bgp_peer_inherit_global_gr_mode(peer, global_gr_mode);
		break;
	default:
		zlog_err(
			"[BGP_GR] Default switch mode ::: SOMETHING IS WRONG !!!");
		break;
	}
	bgp_peer_gr_flags_update(peer);
	peer->peer_gr_present_state = new_state;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"%s: Peer GR mode changed from %s to %s, GR flags 0x%x peer flags 0x%" PRIx64,
			peer->host, print_peer_gr_mode(old_state),
			print_peer_gr_mode(new_state),
			peer->peer_gr_new_status_flag, peer->flags);
}

void bgp_peer_gr_flags_update(struct peer *peer)
{
	if (CHECK_FLAG(peer->peer_gr_new_status_flag,
		       PEER_GRACEFUL_RESTART_NEW_STATE_HELPER))
		SET_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART_HELPER);
	else
		UNSET_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART_HELPER);

	if (CHECK_FLAG(peer->peer_gr_new_status_flag,
		       PEER_GRACEFUL_RESTART_NEW_STATE_RESTART))
		SET_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART);
	else
		UNSET_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART);

	if (CHECK_FLAG(peer->peer_gr_new_status_flag,
		       PEER_GRACEFUL_RESTART_NEW_STATE_INHERIT))
		SET_FLAG(peer->flags,
			 PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT);
	else
		UNSET_FLAG(peer->flags,
			   PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT);

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s: Peer flags updated to 0x%" PRIx64
			   ", GR flags 0x%x, GR mode %s",
			   peer->host, peer->flags,
			   peer->peer_gr_new_status_flag,
			   print_peer_gr_mode(bgp_peer_gr_mode_get(peer)));

	/*
	 * If GR has been completely disabled for the peer and we were
	 * acting as the Helper for the peer (i.e., keeping stale routes
	 * and running the restart timer or stalepath timer), clear those
	 * states.
	 */
	if (!CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART)
	    && !CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART_HELPER)) {

		UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);

		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s: GR disabled, stopping NSF and clearing stale routes",
					peer->host);
			peer_nsf_stop(peer);
		}
	}
}
