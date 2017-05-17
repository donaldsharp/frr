/* 
 *
 * Copyright 2009-2015, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_ENCAP_H
#define _QUAGGA_BGP_ENCAP_H
#include "bgpd/bgp_route.h"

extern void bgp_encap_init (void);
extern int bgp_nlri_parse_encap (struct peer *, struct attr *, struct bgp_nlri *);
extern int bgp_show_encap (struct vty *vty, afi_t afi, struct prefix_rd *prd, 
                           enum bgp_show_type type, void *output_arg, int tags);
#include "bgp_encap_types.h"
#endif /* _QUAGGA_BGP_ENCAP_H */
