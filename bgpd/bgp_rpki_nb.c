// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP RPKI northbound — module registration and NB data callbacks.
 *
 * Copyright (C) 2026 FRRouting
 *
 * Dual module_info pattern (matches frr_bgp_filter_info/cli_info):
 *   - frr_bgp_rpki_info: registered in bgpd's bgpd_yang_modules[] with
 *     data callbacks. Compiled into the bgpd binary.
 *   - frr_bgp_rpki_cli_info: registered in mgmtd's mgmt_yang_modules[]
 *     with ignore_cfg_cbs=true and cli_show only. Compiled into mgmtd.
 *
 * Loadable module pattern (mirrors bmp_nb_cb):
 *   bgpd_rpki.so assigns rpki_nb_cb at module init. Every data callback
 *   below guards on non-null before dispatching. bgpd without the rpki
 *   module loaded sees all NB writes to the bgp-rpki container as
 *   silent no-ops — no crashes, no state change.
 *
 * Why stub callbacks for every leaf: nb_validate_callbacks requires a
 * modify/destroy handler on each configurable leaf in the registered
 * module. The cache-list parent's create/destroy callbacks below do
 * the real work by reading the full entry via yang_dnode_get; the
 * per-leaf stubs are no-ops that exist purely to satisfy the validator.
 */

#include <zebra.h>

#include "log.h"
#include "northbound.h"
#include "yang.h"
#include "vrf.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_rpki_nb.h"

/*
 * Populated by bgp_rpki_module_init() inside bgpd_rpki.so. NULL when
 * the module isn't loaded.
 */
struct rpki_nb_ops *rpki_nb_cb = NULL;

/* Helper — resolve vrf name from any xpath rooted at /frr-vrf:lib/vrf. */
static const char *rpki_nb_vrf_name(const struct lyd_node *dnode)
{
	struct vrf *vrf;

	/*
	 * Walk up the tree to the /frr-vrf:lib/vrf[name=X] ancestor. We
	 * don't know how deep dnode is — the caller might be the
	 * bgp-rpki container itself (1 hop up) or a leaf inside
	 * rpki-cache-server/cache-list/transport/tcp (5 hops up). Ask
	 * libyang to resolve by walking until we find a node that has a
	 * 'name' key-leaf child at VRF level.
	 *
	 * nb_running_get_entry walks to the nearest ancestor that has a
	 * registered entry — lib_vrf_create stores struct vrf* at
	 * /frr-vrf:lib/vrf so this returns the vrf for any descendant.
	 */
	vrf = nb_running_get_entry(dnode, NULL, false);
	if (vrf)
		return vrf->name;
	return VRF_DEFAULT_NAME;
}

/* ---------- Real callbacks ---------- */

static int bgp_rpki_enable_modify(struct nb_cb_modify_args *args)
{
	bool enabled;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	enabled = yang_dnode_get_bool(args->dnode, NULL);
	if (rpki_nb_cb && rpki_nb_cb->enable_set)
		rpki_nb_cb->enable_set(rpki_nb_vrf_name(args->dnode), enabled);
	return NB_OK;
}

static int bgp_rpki_polling_time_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->polling_set)
		rpki_nb_cb->polling_set(rpki_nb_vrf_name(args->dnode),
					yang_dnode_get_uint32(args->dnode,
							      NULL));
	return NB_OK;
}

static int bgp_rpki_expire_time_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->expire_set)
		rpki_nb_cb->expire_set(rpki_nb_vrf_name(args->dnode),
				       yang_dnode_get_uint32(args->dnode,
							     NULL));
	return NB_OK;
}

static int bgp_rpki_retry_time_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->retry_set)
		rpki_nb_cb->retry_set(rpki_nb_vrf_name(args->dnode),
				      yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

/*
 * cache-list entry create — read the whole entry and dispatch to
 * cache_add_tcp or cache_add_ssh based on cache-type. Idempotency
 * handled by the module implementation.
 */
static int bgp_rpki_cache_list_create(struct nb_cb_create_args *args)
{
	const struct lyd_node *dnode = args->dnode;
	const char *vrfname;
	uint8_t pref;
	const char *cache_type;
	const char *host = NULL;
	uint16_t port = 0;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrfname = rpki_nb_vrf_name(dnode);
	pref = yang_dnode_get_uint8(dnode, "preference");
	cache_type = yang_dnode_get_string(dnode, "cache-type");

	if (yang_dnode_exists(dnode, "ip-address"))
		host = yang_dnode_get_string(dnode, "ip-address");
	else if (yang_dnode_exists(dnode, "ip-host-address"))
		host = yang_dnode_get_string(dnode, "ip-host-address");

	if (strmatch(cache_type, "TCP")) {
		if (yang_dnode_exists(dnode, "transport/tcp/tcp-port"))
			port = (uint16_t)yang_dnode_get_uint32(
				dnode, "transport/tcp/tcp-port");
		if (rpki_nb_cb && rpki_nb_cb->cache_add_tcp)
			rpki_nb_cb->cache_add_tcp(vrfname, pref, host, port,
						  NULL);
		return NB_OK;
	}

	if (strmatch(cache_type, "SSH")) {
		const char *user = NULL;
		const char *priv_key = NULL;
		const char *pub_key = NULL;
		const char *server_pub_key = NULL;

		if (yang_dnode_exists(dnode, "transport/ssh/ssh-port"))
			port = (uint16_t)yang_dnode_get_uint32(
				dnode, "transport/ssh/ssh-port");
		if (yang_dnode_exists(dnode, "transport/ssh/user-name"))
			user = yang_dnode_get_string(dnode,
						     "transport/ssh/user-name");
		if (yang_dnode_exists(dnode, "transport/ssh/private-key"))
			priv_key = yang_dnode_get_string(
				dnode, "transport/ssh/private-key");
		if (yang_dnode_exists(dnode, "transport/ssh/public-key"))
			pub_key = yang_dnode_get_string(
				dnode, "transport/ssh/public-key");
		if (yang_dnode_exists(dnode,
				      "transport/ssh/server-public-ley"))
			server_pub_key = yang_dnode_get_string(
				dnode, "transport/ssh/server-public-ley");
		if (rpki_nb_cb && rpki_nb_cb->cache_add_ssh)
			rpki_nb_cb->cache_add_ssh(vrfname, pref, host, port,
						  user, priv_key, pub_key,
						  server_pub_key);
	}
	return NB_OK;
}

static int bgp_rpki_cache_list_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->cache_remove)
		rpki_nb_cb->cache_remove(rpki_nb_vrf_name(args->dnode),
					 yang_dnode_get_uint8(args->dnode,
							      "preference"));
	return NB_OK;
}

/* ---------- Stub no-op callbacks ---------- */

/*
 * These stubs exist to satisfy nb_validate_callbacks, which requires a
 * modify/destroy handler on every leaf in the registered module. The
 * real work happens in the parent cache-list create/destroy, which
 * reads the full entry via yang_dnode_get.
 */
static int bgp_rpki_stub_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int bgp_rpki_stub_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/* ---------- cli_show stubs (moved to bgp_cli.c in step 5) ---------- */

/* Temporary placeholders so the initial build links. They're weak-overridden
 * by the full implementations once bgp_cli.c is updated in a later step. */
void __attribute__((weak)) bgp_rpki_container_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "rpki\n");
}

void __attribute__((weak)) bgp_rpki_container_cli_show_end(
	struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
}

void __attribute__((weak)) bgp_rpki_polling_time_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " rpki polling_period %u\n",
		yang_dnode_get_uint32(dnode, NULL));
}

void __attribute__((weak)) bgp_rpki_expire_time_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " rpki expire_interval %u\n",
		yang_dnode_get_uint32(dnode, NULL));
}

void __attribute__((weak)) bgp_rpki_retry_time_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " rpki retry_interval %u\n",
		yang_dnode_get_uint16(dnode, NULL));
}

void __attribute__((weak)) bgp_rpki_cache_list_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *type = yang_dnode_get_string(dnode, "cache-type");
	const char *host;
	uint16_t port = 0;
	uint8_t pref = yang_dnode_get_uint8(dnode, "preference");

	if (yang_dnode_exists(dnode, "ip-address"))
		host = yang_dnode_get_string(dnode, "ip-address");
	else
		host = yang_dnode_get_string(dnode, "ip-host-address");

	if (strmatch(type, "TCP")) {
		if (yang_dnode_exists(dnode, "transport/tcp/tcp-port"))
			port = (uint16_t)yang_dnode_get_uint32(
				dnode, "transport/tcp/tcp-port");
		vty_out(vty, " rpki cache tcp %s %u preference %u\n", host,
			port, pref);
	} else {
		if (yang_dnode_exists(dnode, "transport/ssh/ssh-port"))
			port = (uint16_t)yang_dnode_get_uint32(
				dnode, "transport/ssh/ssh-port");
		vty_out(vty, " rpki cache ssh %s %u preference %u\n", host,
			port, pref);
	}
}

/* ---------- Module info (bgpd side — data callbacks) ---------- */

/* clang-format off */
const struct frr_yang_module_info frr_bgp_rpki_info = {
	.name = "frr-bgp-rpki",
	.nodes = {
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/enable",
			.cbs = {
				.modify = bgp_rpki_enable_modify,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/polling-time",
			.cbs = {
				.modify = bgp_rpki_polling_time_modify,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/expire-time",
			.cbs = {
				.modify = bgp_rpki_expire_time_modify,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/retry-time",
			.cbs = {
				.modify = bgp_rpki_retry_time_modify,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list",
			.cbs = {
				.create = bgp_rpki_cache_list_create,
				.destroy = bgp_rpki_cache_list_destroy,
			},
		},
		/* Stubs for child leaves — satisfy nb_validate_callbacks.
		 * Real work happens in cache-list create above.
		 */
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/cache-type",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/ip-address",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
				.destroy = bgp_rpki_stub_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/ip-host-address",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
				.destroy = bgp_rpki_stub_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/tcp/tcp-port",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
				.destroy = bgp_rpki_stub_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/ssh-port",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
				.destroy = bgp_rpki_stub_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/user-name",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
				.destroy = bgp_rpki_stub_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/private-key",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
				.destroy = bgp_rpki_stub_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/public-key",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
				.destroy = bgp_rpki_stub_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/server-public-ley",
			.cbs = {
				.modify = bgp_rpki_stub_modify,
				.destroy = bgp_rpki_stub_destroy,
			},
		},
		{
			.xpath = NULL,
		},
	},
};

/*
 * mgmtd-side info: no data callbacks (ignore_cfg_cbs = true), cli_show
 * callbacks only. cli_show functions are defined in bgp_cli.c.
 */
const struct frr_yang_module_info frr_bgp_rpki_cli_info = {
	.name = "frr-bgp-rpki",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki",
			.cbs = {
				.cli_show = bgp_rpki_container_cli_show,
				.cli_show_end = bgp_rpki_container_cli_show_end,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/polling-time",
			.cbs = {
				.cli_show = bgp_rpki_polling_time_cli_show,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/expire-time",
			.cbs = {
				.cli_show = bgp_rpki_expire_time_cli_show,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/retry-time",
			.cbs = {
				.cli_show = bgp_rpki_retry_time_cli_show,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list",
			.cbs = {
				.cli_show = bgp_rpki_cache_list_cli_show,
			},
		},
		{
			.xpath = NULL,
		},
	},
};
/* clang-format on */
