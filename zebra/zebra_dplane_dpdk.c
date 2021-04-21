/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h" /* Include this explicitly */
#endif

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <string.h>
#include <vty.h>

#include "lib/zebra.h"
#include "lib/libfrr.h"
#include "lib/frratomic.h"
#include "lib/command.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/ns.h"
#include "lib/frr_pthread.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_dplane_dpdk.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/debug.h"

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>

static const char *plugin_name = "zebra_dplane_dpdk";

static struct zd_dpdk_ctx dpdk_ctx_buf, *dpdk_ctx = &dpdk_ctx_buf;
#define dpdk_stat (&dpdk_ctx->stats)

#define ZD_STR "Zebra dataplane information\n"
#define ZD_DPDK_STR "DPDK offload information\n"

static void zd_dpdk_mac_update(struct zebra_dplane_ctx *ctx)
{
	uint32_t update_flags;

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL) {
		zlog_debug("Dplane %s, mac %pEA, ifindex %u",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_mac_get_addr(ctx),
			   dplane_ctx_get_ifindex(ctx));
	}

	update_flags = dplane_ctx_mac_get_update_flags(ctx);
	if (dplane_ctx_get_op(ctx) == DPLANE_OP_MAC_INSTALL) {
		if (update_flags & DPLANE_MAC_REMOTE)
			atomic_fetch_add_explicit(&dpdk_stat->rem_mac_adds, 1,
						  memory_order_relaxed);
		else
			atomic_fetch_add_explicit(&dpdk_stat->local_mac_adds, 1,
						  memory_order_relaxed);
	} else {
		if (update_flags & DPLANE_MAC_REMOTE)
			atomic_fetch_add_explicit(&dpdk_stat->rem_mac_dels, 1,
						  memory_order_relaxed);
		else
			atomic_fetch_add_explicit(&dpdk_stat->local_mac_dels, 1,
						  memory_order_relaxed);
	}
}


/* DPDK provider callback.
 * XXX - move this processing to a provider thread.
 */
static void zd_dpdk_process_update(struct zebra_dplane_ctx *ctx)
{
	switch (dplane_ctx_get_op(ctx)) {

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		zd_dpdk_mac_update(ctx);
		break;

	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		/* XXX */
		break;

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
		/* XXX */
		break;

	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
		/* XXX */
		break;

	default:
		atomic_fetch_add_explicit(&dpdk_stat->ignored_updates, 1,
					  memory_order_relaxed);

		break;
	}
}

static int zd_dpdk_process(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	int counter, limit;

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
		zlog_debug("processing %s", dplane_provider_get_name(prov));

	limit = dplane_provider_get_work_limit(prov);
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (!ctx)
			break;

		zd_dpdk_process_update(ctx);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	return 0;
}

static int zd_dpdk_start(struct zebra_dplane_provider *prov)
{
	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s start", dplane_provider_get_name(prov));
	return 0;
}

static int zd_dpdk_finish(struct zebra_dplane_provider *prov, bool early)
{
	if (early) {
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
			zlog_debug("%s early finish",
				   dplane_provider_get_name(prov));

		return 0;
	}

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s finish", dplane_provider_get_name(prov));

	return 0;
}

static int zd_dpdk_plugin_init(struct thread_master *tm)
{
	int ret;

	rte_eal_init(0, NULL);

	/* XXX - use DPLANE_PRIO_PRE_KERNEL/DPLANE_PROV_FLAG_THREADED
	 * later (if needed)
	 */
	ret = dplane_provider_register(
		plugin_name, DPLANE_PRIO_KERNEL, DPLANE_PROV_FLAGS_DEFAULT,
		zd_dpdk_start, zd_dpdk_process, zd_dpdk_finish, dpdk_ctx, NULL);

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s register status %d", plugin_name, ret);

	return 0;
}

static int zd_dpdk_module_init(void)
{
	hook_register(frr_late_init, zd_dpdk_plugin_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "dplane_dpdk", .version = "0.0.1",
		 .description = "Data plane plugin using dpdk for hw offload",
		 .init = zd_dpdk_module_init, )
