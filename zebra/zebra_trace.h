/* Lttng Tracing for Zebra daemon
 *
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * Rajesh Varatharaj
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

#if !defined(_ZEBRA_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _ZEBRA_TRACE_H

#include "lib/trace.h"


#if defined(HAVE_LTTNG) || defined(HAVE_ZEBRA_LTTNG)

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_zebra

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "zebra/zebra_trace.h"

#include <lttng/tracepoint.h>

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mroute.h"
#include "zebra/rt.h"
#include "lib/stream.h"
#include "lib/vrf.h"

/* clang-format off */

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ipmr_route_stats,
	TP_ARGS(vrf_id_t,  vrf_id),
	TP_FIELDS(
    ctf_integer(unsigned int, vrfid, vrf_id)
		ctf_string(mroute_vrf_id, "Asking for mroute information")
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ipmr_route_stats, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_add_update,
	TP_ARGS(struct interface *, ifp),
	TP_FIELDS(
    ctf_integer(unsigned int, ifindex, ifp->ifindex)
    ctf_integer(unsigned int, vrfid, ifp->vrf_id)
    ctf_string(ifp, ifp->name)
		ctf_string(interface, "Interface Index added")
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_add_update, TRACE_INFO)
/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _ZEBRA_TRACE_H */
