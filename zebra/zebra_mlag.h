/* Zebra mlag header.
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
#ifndef __ZEBRA_MLAG_H__
#define __ZEBRA_MLAG_H__

#include "mlag.h"

void zebra_mlag_init(void);
void zebra_mlag_terminate(void);

enum mlag_role zebra_mlag_get_role(void);

/*
 * Given new data from a lower level of clag, parse and
 * set appropriate data structures in zebra and then
 * pass up this data to interested parties.
 *
 * The minfo data structure passed in is assumed to
 * be owned by the lower level and as such we must
 * make copies of data.
 */
void zebra_mlag_new_information(struct zebra_mlag_info *minfo);
#endif
