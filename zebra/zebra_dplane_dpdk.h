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

#ifndef _ZEBRA_DPLANE_DPDK_H
#define _ZEBRA_DPLANE_DPDK_H

#include "lib/zebra.h"

struct zd_dpdk_stat {
	_Atomic uint32_t ignored_updates;

	_Atomic uint32_t access_port_adds;
	_Atomic uint32_t access_port_dels;
	_Atomic uint32_t access_port_errors;

	_Atomic uint32_t uplink_adds;
	_Atomic uint32_t uplink_dels;
	_Atomic uint32_t uplink_errors;

	_Atomic uint32_t local_mac_adds;
	_Atomic uint32_t local_mac_dels;
	_Atomic uint32_t local_mac_errors;

	_Atomic uint32_t rem_mac_adds;
	_Atomic uint32_t rem_mac_dels;
	_Atomic uint32_t rem_mac_errors;
};

struct zd_dpdk_ctx {
	/* Stats */
	struct zd_dpdk_stat stats;
};

#endif
