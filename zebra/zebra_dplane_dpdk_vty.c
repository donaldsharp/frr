/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Donald Sharp
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
#include <zebra.h>

#ifndef VTYSH_EXTRACT_PL
#include "zebra/zebra_dplane_dpdk_clippy.c"
#endif

#define ZD_STR "Zebra dataplane information\n"
#define ZD_DPDK_STR "DPDK offload information\n"

DEFPY (zd_dpdk_show_counters,
       zd_dpdk_show_counters_cmd,
       "show dplane dpdk counters",
       SHOW_STR
       ZD_STR
       ZD_DPDK_STR
       "show counters\n")
{
	uint32_t tmp_cnt;

	vty_out(vty, "%30s\n%30s\n", "Dataplane DPDK counters", "============");

#define ZD_DPDK_SHOW_COUNTER(label, counter)                                   \
	do {                                                                   \
		tmp_cnt =                                                      \
			atomic_load_explicit(&counter, memory_order_relaxed);  \
		vty_out(vty, "%28s: %u\n", (label), (tmp_cnt));                \
	} while (0);

	ZD_DPDK_SHOW_COUNTER("Ignored updates", dpdk_stat->ignored_updates);

	ZD_DPDK_SHOW_COUNTER("Access port adds", dpdk_stat->access_port_adds);
	ZD_DPDK_SHOW_COUNTER("Access port dels", dpdk_stat->access_port_dels);
	ZD_DPDK_SHOW_COUNTER("Access port errors",
			     dpdk_stat->access_port_errors);

	ZD_DPDK_SHOW_COUNTER("Uplink adds", dpdk_stat->uplink_adds);
	ZD_DPDK_SHOW_COUNTER("Uplink dels", dpdk_stat->uplink_dels);
	ZD_DPDK_SHOW_COUNTER("Uplink errors", dpdk_stat->uplink_errors);

	ZD_DPDK_SHOW_COUNTER("Local mac adds", dpdk_stat->local_mac_adds);
	ZD_DPDK_SHOW_COUNTER("Local mac dels", dpdk_stat->local_mac_dels);
	ZD_DPDK_SHOW_COUNTER("Local mac errors", dpdk_stat->local_mac_errors);

	ZD_DPDK_SHOW_COUNTER("Remote mac adds", dpdk_stat->rem_mac_adds);
	ZD_DPDK_SHOW_COUNTER("Remote mac dels", dpdk_stat->rem_mac_dels);
	ZD_DPDK_SHOW_COUNTER("Remote mac errors", dpdk_stat->rem_mac_errors);

	return CMD_SUCCESS;
}

void zd_dpdk_init(void)
{
	install_element(VIEW_NODE, &zd_dpdk_show_counters_cmd);

}
