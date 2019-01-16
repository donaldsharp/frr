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
#include "network.h"

#include "zebra/debug.h"
#include "zebra/zebra_mlag.h"

#include <sys/un.h>

static struct thread_master *zmlag_master;
static int mlag_socket;

static int zebra_mlag_connect(struct thread *thread);

static int zebra_mlag_read(struct thread *thread)
{
	char buf[512];
	int count;

	count = read(mlag_socket, &buf, 511);
	if (count == -1) {
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug("Failure to read mlag socket: %d %s(%d), starting over",
				   mlag_socket, safe_strerror(errno), errno);

		close(mlag_socket);
		thread_add_event(zmlag_master, zebra_mlag_connect, NULL,
				 0, NULL);

		return -1;
	}

	if (IS_ZEBRA_DEBUG_MLAG) {
		zlog_debug("Received MLAG Data from socket: %d", mlag_socket);
		zlog_hexdump(buf, 512);
	}

	thread_add_read(zmlag_master, zebra_mlag_read,
			NULL, mlag_socket, NULL);

	return 0;
}

static int zebra_mlag_write_getall(struct thread *thread)
{
	const char cmd[] = "getall\0";

	write(mlag_socket, cmd, strlen(cmd)+1);

	thread_add_read(zmlag_master, zebra_mlag_read,
			NULL, mlag_socket, NULL);

	return 0;
}

static int zebra_mlag_connect(struct thread *thread)
{
	struct sockaddr_un svr;

	memset(&svr, 0, sizeof(svr));
	svr.sun_family = AF_UNIX;
#define MLAG_SOCK_NAME "/var/run/clagd.socket"
	strcpy(svr.sun_path, MLAG_SOCK_NAME);

	mlag_socket = socket(svr.sun_family, SOCK_STREAM, 0);
	if (mlag_socket < 0)
		return -1;

	if (connect(mlag_socket, (struct sockaddr *)&svr, sizeof(svr)) == -1) {
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug("Unable to connect to %s trying again in 10 seconds",
				   svr.sun_path);
		close(mlag_socket);
		thread_add_timer(zmlag_master, zebra_mlag_connect, NULL,
				 10, NULL);

		return 0;
	}

	set_nonblocking(mlag_socket);

	thread_add_write(zmlag_master, zebra_mlag_write_getall,
			 NULL, mlag_socket, NULL);
	return 0;
}

static int zebra_mlag_cumulus_late_init(struct thread_master *master)
{
	zmlag_master = master;

	thread_add_event(zmlag_master, zebra_mlag_connect, NULL, 0, NULL);
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
