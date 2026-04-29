// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Route Map declarations
 * Copyright (C) 2025 FRRouting
 */

#ifndef _BGP_ROUTEMAP_H
#define _BGP_ROUTEMAP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Full initialization for bgpd.
 * Sets up route-map hooks, match/set rule callbacks, and installs CLI commands.
 * Only available when compiled for bgpd (not for mgmtd).
 */
extern void bgp_route_map_init(void);

/*
 * Cleanup for bgpd.
 * Only available when compiled for bgpd (not for mgmtd).
 */
extern void bgp_route_map_terminate(void);

/*
 * CLI-only initialization for mgmtd.
 * Installs CLI commands without bgpd-specific hooks and match/set rules.
 * This allows mgmtd to parse BGP route-map configuration.
 */
extern void bgp_route_map_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _BGP_ROUTEMAP_H */
