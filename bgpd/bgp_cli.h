// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP CLI - Northbound CLI commands for BGP
 * Copyright (C) 2024 FRRouting
 */

#ifndef _QUAGGA_BGP_CLI_H
#define _QUAGGA_BGP_CLI_H

/*
 * Initialize BGP CLI commands.
 * This installs all DEFPY_YANG-based commands from bgp_cli.c.
 * Must be called after bgp_vty_init() since it depends on BGP nodes
 * being already installed.
 */
extern void bgp_cli_init(void);

#endif /* _QUAGGA_BGP_CLI_H */
