/* Zebra NHG Code.
 * Copyright (C) 2019 Cumulus Networks, Inc.
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
#include "zebra.h"

#include "nexthop_group.h"

#include "zebra_nhg.h"

static void zebra_nhg_new(const char *name)
{
}

static void zebra_nhg_add_nexthop(const struct nexthop_group_cmd *nhgc,
				  const struct nexthop *nhop)
{
}

static void zebra_nhg_del_nexthop(const struct nexthop_group_cmd *nhgc,
				  const struct nexthop *nhop)
{
}

static void zebra_nhg_delete(const char *name)
{
}

void zebra_nhg_init(void)
{
	nexthop_group_init(zebra_nhg_new,
			   zebra_nhg_add_nexthop,
			   zebra_nhg_del_nexthop,
			   zebra_nhg_delete);
}

void zebra_nhg_terminate(void)
{
	nexthop_group_init(NULL, NULL, NULL, NULL);
}
