// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP RPKI northbound header — YANG module info + ops-table declarations.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifndef _FRR_BGP_RPKI_NB_H_
#define _FRR_BGP_RPKI_NB_H_

#include "northbound.h"

/*
 * rpki_nb_ops — function table assigned by the loadable bgpd_rpki module
 * at init time. bgpd without the module loaded sees rpki_nb_cb == NULL
 * and every NB callback is a silent no-op.
 */
struct rpki_nb_ops {
	/* container destroy — wipe entire per-vrf rpki state */
	void (*container_destroy)(const char *vrfname);

	/* enable leaf modify — start/stop the rpki session for this vrf */
	void (*enable_set)(const char *vrfname, bool enabled);

	/* rpki-timers - A value of 0 means "reset to default". */
	void (*polling_set)(const char *vrfname, uint32_t seconds);
	void (*expire_set)(const char *vrfname, uint32_t seconds);
	void (*retry_set)(const char *vrfname, uint16_t seconds);

	/* cache-list[preference] create for TCP transport */
	void (*cache_add_tcp)(const char *vrfname, uint8_t preference,
			      const char *host, uint16_t port,
			      const char *source);

	/* cache-list[preference] create for SSH transport */
	void (*cache_add_ssh)(const char *vrfname, uint8_t preference,
			      const char *host, uint16_t port,
			      const char *user, const char *priv_key,
			      const char *pub_key,
			      const char *server_pub_key);

	/* cache-list[preference] destroy */
	void (*cache_remove)(const char *vrfname, uint8_t preference);
};

extern struct rpki_nb_ops *rpki_nb_cb;

/* YANG module info — data callbacks (bgpd side) */
extern const struct frr_yang_module_info frr_bgp_rpki_info;

/* YANG module info — cli_show only (mgmtd side) */
extern const struct frr_yang_module_info frr_bgp_rpki_cli_info;

/* cli_show callbacks — defined in bgp_cli.c */
void bgp_rpki_container_cli_show(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
void bgp_rpki_container_cli_show_end(struct vty *vty,
				     const struct lyd_node *dnode);
void bgp_rpki_polling_time_cli_show(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void bgp_rpki_expire_time_cli_show(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void bgp_rpki_retry_time_cli_show(struct vty *vty,
				  const struct lyd_node *dnode,
				  bool show_defaults);
void bgp_rpki_cache_list_cli_show(struct vty *vty,
				  const struct lyd_node *dnode,
				  bool show_defaults);

#endif /* _FRR_BGP_RPKI_NB_H_ */
