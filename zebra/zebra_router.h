/* Zebra Router header.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
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
#ifndef __ZEBRA_ROUTER_H__
#define __ZEBRA_ROUTER_H__

#include "lib/mlag.h"

#include "zebra/zebra_ns.h"

#if defined(HAVE_CSMGR)
#include <cumulus/cs_mgr_intf.h>
#endif
#include "zebra/zebra_csm.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header file contains the idea of a router and as such
 * owns data that is associated with a router from zebra's
 * perspective.
 */

struct zebra_router_table {
	RB_ENTRY(zebra_router_table) zebra_router_table_entry;

	uint32_t tableid;
	afi_t afi;
	safi_t safi;
	ns_id_t ns_id;

	struct route_table *table;
};
RB_HEAD(zebra_router_table_head, zebra_router_table);
RB_PROTOTYPE(zebra_router_table_head, zebra_router_table,
	     zebra_router_table_entry, zebra_router_table_entry_compare)

/* RPF lookup behaviour */
enum multicast_mode {
	MCAST_NO_CONFIG = 0,  /* MIX_MRIB_FIRST, but no show in config write */
	MCAST_MRIB_ONLY,      /* MRIB only */
	MCAST_URIB_ONLY,      /* URIB only */
	MCAST_MIX_MRIB_FIRST, /* MRIB, if nothing at all then URIB */
	MCAST_MIX_DISTANCE,   /* MRIB & URIB, lower distance wins */
	MCAST_MIX_PFXLEN,     /* MRIB & URIB, longer prefix wins */
			      /* on equal value, MRIB wins for last 2 */
};

/* An interface can be error-disabled if a protocol (such as EVPN or
 * VRRP) detects a problem with keeping it operationally-up.
 * If any of the protodown bits are set protodown-on is programmed
 * in the dataplane. This results in a carrier/L1 down on the
 * physical device.
 */
enum protodown_reasons {
	/* A process outside of FRR's control protodowned the interface */
	ZEBRA_PROTODOWN_EXTERNAL = (1 << 0),
	/* On startup local ESs are held down for some time to
	 * allow the underlay to converge and EVPN routes to
	 * get learnt
	 */
	ZEBRA_PROTODOWN_EVPN_STARTUP_DELAY = (1 << 1),
	/* If all the uplinks are down the switch has lost access
	 * to the VxLAN overlay and must shut down the access
	 * ports to allow servers to re-direct their traffic to
	 * other switches on the Ethernet Segment
	 */
	ZEBRA_PROTODOWN_EVPN_UPLINK_DOWN = (1 << 2),
	/* We want to protodown all ES bonds on FRR shutdown to
	 * prevent loss in the encap direction on¿bonds which remain
	 * up until LACP times out or the NIC is taken down.
	 */
	ZEBRA_PROTODOWN_EVPN_SHUTDOWN = (1 << 3),
	ZEBRA_PROTODOWN_EVPN_ALL = (ZEBRA_PROTODOWN_EVPN_UPLINK_DOWN |
				    ZEBRA_PROTODOWN_EVPN_STARTUP_DELAY |
				    ZEBRA_PROTODOWN_EVPN_SHUTDOWN),
	ZEBRA_PROTODOWN_VRRP = (1 << 4),
	/* This reason used exclusively for testing */
	ZEBRA_PROTODOWN_SHARP = (1 << 5),
	/* Just used to clear our fields on shutdown, externel not included */
	ZEBRA_PROTODOWN_ALL = (ZEBRA_PROTODOWN_EVPN_ALL | ZEBRA_PROTODOWN_VRRP |
			       ZEBRA_PROTODOWN_SHARP)
};
#define ZEBRA_PROTODOWN_RC_STR_LEN 80

struct zebra_mlag_info {
	/* Role this zebra router is playing */
	enum mlag_role role;

	/* The peerlink being used for mlag */
	char *peerlink;
	ifindex_t peerlink_ifindex;

	/* The system mac being used */
	struct ethaddr mac;
	/*
	 * Zebra will open the communication channel with MLAGD only if any
	 * clients are interested and it is controlled dynamically based on
	 * client registers & un-registers.
	 */
	uint32_t clients_interested_cnt;

	/* coomunication channel with MLAGD is established */
	bool connected;

	/* connection retry timer is running */
	bool timer_running;

	/* Holds the client data(unencoded) that need to be pushed to MCLAGD*/
	struct stream_fifo *mlag_fifo;

	/*
	 * A new Kernel thread will be created to post the data to MCLAGD.
	 * where as, read will be performed from the zebra main thread, because
	 * read involves accessing client registartion data structures.
	 */
	struct frr_pthread *zebra_pth_mlag;

	/* MLAG Thread context 'master' */
	struct thread_master *th_master;

	/*
	 * Event for Initial MLAG Connection setup & Data Read
	 * Read can be performed only after successful connection establishment,
	 * so no issues.
	 *
	 */
	struct thread *t_read;
	/* Event for MLAG write */
	struct thread *t_write;
};

struct zebra_router {
	atomic_bool in_shutdown;

	bool fast_shutdown;

	/* Thread master */
	struct thread_master *master;

	/* Lists of clients who have connected to us */
	struct list *client_list;

	/* List of clients in GR */
	struct list *stale_client_list;

	struct zebra_router_table_head tables;

	/* L3-VNI hash table (for EVPN). Only in default instance */
	struct hash *l3vni_table;

	/* Tables and other global info maintained for EVPN multihoming */
	struct zebra_evpn_mh_info *mh_info;

	struct zebra_neigh_info *neigh_info;

	/* EVPN MH broadcast domains indexed by the VID */
	struct hash *evpn_vlan_table;

	struct hash *rules_hash;

	struct hash *ipset_hash;

	struct hash *ipset_entry_hash;

	struct hash *iptable_hash;

	/* A sequence number used for tracking routes */
	_Atomic uint32_t sequence_num;

	/* rib work queue */
#define ZEBRA_RIB_PROCESS_HOLD_TIME 10
#define ZEBRA_RIB_PROCESS_RETRY_TIME 1
	struct work_queue *ribq;

	/* Meta Queue Information */
	struct meta_queue *mq;

	/* LSP work queue */
	struct work_queue *lsp_process_q;

#define ZEBRA_ZAPI_PACKETS_TO_PROCESS 1000
	_Atomic uint32_t packets_to_process;

	/* Mlag information for the router */
	struct zebra_mlag_info mlag_info;

	/*
	 * The EVPN instance, if any
	 */
	struct zebra_vrf *evpn_vrf;

	uint32_t multipath_num;

	/* RPF Lookup behavior */
	enum multicast_mode ipv4_multicast_mode;

	/*
	 * zebra start time and time of sweeping RIB of old routes
	 */
	uint64_t startup_time;
	time_t rib_sweep_time;
	/* FRR fast/graceful restart info */
	bool graceful_restart;
	bool gr_last_rt_installed;
	bool all_instances_gr_done;
	bool gr_stale_cleanup_time_recorded;
	bool gr_update_pending_time_recorded;
	time_t gr_completion_time;
	int gr_cleanup_time;

#define ZEBRA_GR_DEFAULT_RIB_SWEEP_TIME 500
	struct thread *t_rib_sweep;

#define ZEBRA_GR_DEFAULT_TRIGGER_TIME 60
	struct thread *t_gr_no_clients;
	time_t rib_no_gr_client_time;

	struct thread *sweeper;

	bool maint_mode;

#if defined(HAVE_CSMGR)
	bool frr_csm_regd;
	enum frr_csm_smode frr_csm_smode;
	Mode csm_smode;
	Mode csm_cmode;
	State csm_cstate;
	Module frr_csm_modid;
	int csm_errno;
	bool csm_invalid_len;
	bool load_complete_failed;
#endif

	/*
	 * The hash of nexthop groups associated with this router
	 */
	struct hash *nhgs;
	struct hash *nhgs_id;

	/*
	 * Does the underlying system provide an asic offload
	 */
	bool asic_offloaded;
	bool notify_on_ack;

	bool supports_nhgs;

	bool all_mc_forwardingv4, default_mc_forwardingv4;
	bool all_mc_forwardingv6, default_mc_forwardingv6;
	bool all_linkdownv4, default_linkdownv4;
	bool all_linkdownv6, default_linkdownv6;

#define ZEBRA_DEFAULT_NHG_KEEP_TIMER 180
	uint32_t nhg_keep;

	/* Should we allow non FRR processes to delete our routes */
	bool allow_delete;
	/* Allow NHGs for routes on GRE links */
	bool gre_use_nhg;

	uint8_t protodown_r_bit;

	uint64_t nexthop_weight_scale_value;
};

#define GRACEFUL_RESTART_TIME 60

extern struct zebra_router zrouter;
extern uint32_t rcvbufsize;

struct zebra_gr_ctx {
	struct route_node *rn;
	struct route_entry *re;
	uint32_t af_installed_count[AFI_MAX];
	uint32_t total_queued_rt;
	uint32_t total_processed_rt;
	/* L2vpn counts */
	uint32_t rmac_cnt;
	uint32_t rneigh_cnt;
	uint32_t hrep_cnt;
	uint32_t total_evpn_entries_queued;
	uint32_t total_evpn_entries_processed;
};

extern struct zebra_gr_ctx z_gr_ctx;

extern void zebra_gr_ctx_init(void);

extern void zebra_router_init(bool asic_offload, bool notify_on_ack);
extern void zebra_router_cleanup(void);
extern void zebra_router_terminate(void);

extern struct zebra_router_table *zebra_router_find_zrt(struct zebra_vrf *zvrf,
							uint32_t tableid,
							afi_t afi, safi_t safi);
extern struct route_table *zebra_router_find_table(struct zebra_vrf *zvrf,
						   uint32_t tableid, afi_t afi,
						   safi_t safi);
extern struct route_table *zebra_router_get_table(struct zebra_vrf *zvrf,
						  uint32_t tableid, afi_t afi,
						  safi_t safi);
extern void zebra_router_release_table(struct zebra_vrf *zvrf, uint32_t tableid,
				       afi_t afi, safi_t safi);

extern int zebra_router_config_write(struct vty *vty);

extern void zebra_router_sweep_route(void);
extern void zebra_router_sweep_nhgs(void);

extern void zebra_router_show_table_summary(struct vty *vty);

extern uint32_t zebra_router_get_next_sequence(void);

static inline vrf_id_t zebra_vrf_get_evpn_id(void)
{
	return zrouter.evpn_vrf ? zvrf_id(zrouter.evpn_vrf) : VRF_DEFAULT;
}
static inline struct zebra_vrf *zebra_vrf_get_evpn(void)
{
	return zrouter.evpn_vrf ? zrouter.evpn_vrf
			        : zebra_vrf_lookup_by_id(VRF_DEFAULT);
}

extern void multicast_mode_ipv4_set(enum multicast_mode mode);

extern enum multicast_mode multicast_mode_ipv4_get(void);

extern bool zebra_router_notify_on_ack(void);

static inline void zebra_router_set_supports_nhgs(bool support)
{
	zrouter.supports_nhgs = support;
}

static inline bool zebra_router_in_shutdown(void)
{
	return atomic_load_explicit(&zrouter.in_shutdown, memory_order_relaxed);
}

#define FRR_PROTODOWN_REASON_DEFAULT_BIT 7
/* Protodown bit setter/getter
 *
 * Allow users to change the bit if it conflicts with another
 * on their system.
 */
static inline void if_netlink_set_frr_protodown_r_bit(uint8_t bit)
{
	zrouter.protodown_r_bit = bit;
}

static inline void if_netlink_unset_frr_protodown_r_bit(void)
{
	zrouter.protodown_r_bit = FRR_PROTODOWN_REASON_DEFAULT_BIT;
}

static inline bool if_netlink_frr_protodown_r_bit_is_set(void)
{
	return (zrouter.protodown_r_bit != FRR_PROTODOWN_REASON_DEFAULT_BIT);
}

static inline uint8_t if_netlink_get_frr_protodown_r_bit(void)
{
	return zrouter.protodown_r_bit;
}

/* zebra_northbound.c */
extern const struct frr_yang_module_info frr_zebra_info;

#ifdef __cplusplus
}
#endif

#endif
