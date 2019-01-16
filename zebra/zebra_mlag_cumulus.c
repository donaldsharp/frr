/* Zebra Mlag Code.
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
#include "zebra.h"

#include "hook.h"
#include "module.h"
#include "thread.h"
#include "libfrr.h"
#include "version.h"

static int zebra_mlag_cumulus_late_init(struct thread_master *master)
{
	return 0;
}

static int zebra_mlag_cumulus_init(void)
{
	hook_register(frr_late_init, zebra_mlag_cumulus_late_init);

	return 0;
}

FRR_MODULE_SETUP(
		 .name = "MLAG Cumulus",
		 .version = FRR_VERSION,
		 .description = "Cumulus Specific MLAG code",
		 .init = zebra_mlag_cumulus_init,
		 )
