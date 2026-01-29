// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Post-kernel dataplane plugin for handling unreachable contexts.
 *
 * Copyright 2026 Nvidia Inc.
 *                Donald Sharp
 */

#include "zebra.h"

#include "lib/libfrr.h"
#include "zebra/zebra_dplane.h"

static const char *plugin_name = "UNREACHABLE";

static struct zebra_dplane_provider *prov_p;

static int dplane_unreachable_start(struct zebra_dplane_provider *prov)
{
	/*
	 * If you have some module specific code, that needs initing
	 * it should go here
	 */
	return 0;
}

static int dplane_unreachable_fini(struct zebra_dplane_provider *prov, bool early)
{
	/*
	 * If you have some module specific code, that needs cleaning up
	 * it should go here
	 */
	return 0;
}

static int dplane_unreachable_process(struct zebra_dplane_provider *prov)
{
	int counter, limit;
	struct zebra_dplane_ctx *ctx;

	limit = dplane_provider_get_work_limit(prov);

	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (!ctx)
			break;

		/*
		 * Do the work here
		 */
		zlog_debug("Handling context %p for unreachable module", ctx);


		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	if (counter >= limit)
		dplane_provider_work_ready();

	return 0;
}

static int dplane_unreachable_new(struct event_loop *tm)
{
	int ret;

	ret = dplane_provider_register(plugin_name, DPLANE_PRIO_POSTPROCESS,
				       DPLANE_PROV_FLAGS_DEFAULT, dplane_unreachable_start,
				       dplane_unreachable_process, dplane_unreachable_fini, NULL,
				       &prov_p);

	if (ret != 0)
		zlog_info("%s: provider registration failed: %d", plugin_name, ret);

	return 0;
}

static int module_init(void)
{
	hook_register(frr_late_init, dplane_unreachable_new);
	return 0;
}

FRR_MODULE_SETUP(.name = "dplane_unreachable", .version = "0.0.1",
		 .description = "Post-kernel dataplane plugin (unreachable).",
		 .init = module_init, );
