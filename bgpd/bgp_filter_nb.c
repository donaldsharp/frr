// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Filter Northbound Implementation
 * Copyright (C) 2024 FRRouting
 *
 * Northbound callbacks for community-list, large-community-list,
 * extcommunity-list, and as-path-list defined in frr-bgp-filter.yang
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "log.h"
#include "lib/command.h"
#include "lib/filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_filter_nb.h"
#include "frrstr.h"

/* Helper struct for collecting leaf-list values */
struct leaflist_collector {
	char *buffer;
	size_t buffer_size;
	bool first;
};

/* Callback for yang_dnode_iterate to collect leaf-list values */
static int collect_leaflist_value(const struct lyd_node *dnode, void *arg)
{
	struct leaflist_collector *collector = arg;
	const char *val = lyd_get_value(dnode);

	if (!collector->first)
		strlcat(collector->buffer, " ", collector->buffer_size);
	strlcat(collector->buffer, val, collector->buffer_size);
	collector->first = false;

	return YANG_ITER_CONTINUE;
}

/* Shared helpers for community / large / extcommunity list cli_show. */
static void bgp_filter_cli_show_style_line(struct vty *vty, const char *kind,
					   const char *name, bool numbered,
					   bool standard, uint32_t seq,
					   const char *action,
					   const char *value)
{
	if (numbered)
		vty_out(vty, "bgp %s %s seq %u %s %s\n", kind, name, seq,
			action, value);
	else
		vty_out(vty, "bgp %s %s %s seq %u %s %s\n", kind,
			standard ? "standard" : "expanded", name, seq, action,
			value);
}

static void lib_community_list_entry_cli_show(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults)
{
	const char *name;
	uint32_t seq;
	const char *action;
	const char *type_str;
	char comm_str[512] = "";
	bool standard;

	name = yang_dnode_get_string(dnode, "../name");
	seq = yang_dnode_get_uint32(dnode, "sequence");
	action = yang_dnode_get_string(dnode, "action");
	type_str = yang_dnode_get_string(dnode, "type");
	standard = strmatch(type_str, "community-list-standard");

	if (standard) {
		struct leaflist_collector collector = {
			.buffer = comm_str,
			.buffer_size = sizeof(comm_str),
			.first = true,
		};

		yang_dnode_iterate(collect_leaflist_value, &collector, dnode,
				   "standard-community-string");
	} else if (yang_dnode_exists(dnode, "expanded-community-string")) {
		strlcpy(comm_str,
			yang_dnode_get_string(dnode, "expanded-community-string"),
			sizeof(comm_str));
	}

	if (!comm_str[0])
		return;

	bgp_filter_cli_show_style_line(vty, "community-list", name,
				       all_digit(name), standard, seq, action,
				       comm_str);
}

static void lib_large_community_list_entry_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *name;
	uint32_t seq;
	const char *action;
	const char *type_str;
	char comm_str[512] = "";
	bool standard;

	name = yang_dnode_get_string(dnode, "../name");
	seq = yang_dnode_get_uint32(dnode, "sequence");
	action = yang_dnode_get_string(dnode, "action");
	type_str = yang_dnode_get_string(dnode, "type");
	standard = strstr(type_str, "standard") != NULL;

	if (standard) {
		struct leaflist_collector collector = {
			.buffer = comm_str,
			.buffer_size = sizeof(comm_str),
			.first = true,
		};

		yang_dnode_iterate(collect_leaflist_value, &collector, dnode,
				   "standard-large-community-string");
	} else if (yang_dnode_exists(dnode,
				     "expanded-large-community-string")) {
		strlcpy(comm_str,
			yang_dnode_get_string(
				dnode, "expanded-large-community-string"),
			sizeof(comm_str));
	}

	if (!comm_str[0])
		return;

	bgp_filter_cli_show_style_line(vty, "large-community-list", name,
				       all_digit(name), standard, seq, action,
				       comm_str);
}

static void lib_extcommunity_list_entry_cli_show(struct vty *vty,
						 const struct lyd_node *dnode,
						 bool show_defaults)
{
	const char *name;
	uint32_t seq;
	const char *action;
	const char *type_str;
	char comm_str[512] = "";
	bool standard;
	struct leaflist_collector collector = {
		.buffer = comm_str,
		.buffer_size = sizeof(comm_str),
		.first = true,
	};

	name = yang_dnode_get_string(dnode, "../name");
	seq = yang_dnode_get_uint32(dnode, "sequence");
	action = yang_dnode_get_string(dnode, "action");
	type_str = yang_dnode_get_string(dnode, "type");
	standard = strstr(type_str, "standard") != NULL;

	if (standard) {
		if (yang_dnode_exists(dnode, "extcommunity-rt")) {
			strlcpy(comm_str, "rt ", sizeof(comm_str));
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   dnode, "extcommunity-rt");
		} else if (yang_dnode_exists(dnode, "extcommunity-soo")) {
			strlcpy(comm_str, "soo ", sizeof(comm_str));
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   dnode, "extcommunity-soo");
		} else if (yang_dnode_exists(dnode, "extcommunity-nt")) {
			strlcpy(comm_str, "nt ", sizeof(comm_str));
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   dnode, "extcommunity-nt");
		}
	} else if (yang_dnode_exists(dnode, "expanded-extcommunity-string")) {
		strlcpy(comm_str,
			yang_dnode_get_string(dnode,
					      "expanded-extcommunity-string"),
			sizeof(comm_str));
	}

	if (!comm_str[0])
		return;

	bgp_filter_cli_show_style_line(vty, "extcommunity-list", name,
				       all_digit(name), standard, seq, action,
				       comm_str);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:community-list
 *
 * Community lists are created on-demand when entries are added,
 * so we just track the name here.
 */
int lib_community_list_create(struct nb_cb_create_args *args)
{
	/* Lists are created implicitly when entries are added */
	return NB_OK;
}

int lib_community_list_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");

	/* Delete all entries by calling unset with NULL str */
	community_list_unset(bgp_clist, name, NULL, NULL, 0, COMMUNITY_LIST_STANDARD);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:community-list/entry
 */
int lib_community_list_entry_create(struct nb_cb_create_args *args)
{
	const char *name;
	const char *seq_str;
	const char *type_str;
	const char *action_str;
	int direct;
	int style;
	int ret;
	char comm_str[512] = "";

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Get parent list name */
	name = yang_dnode_get_string(args->dnode, "../name");

	/* Get sequence */
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	/* Get action (permit/deny) */
	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	/* Get type (standard/expanded) */
	type_str = yang_dnode_get_string(args->dnode, "type");
	if (strcmp(type_str, "community-list-standard") == 0) {
		style = COMMUNITY_LIST_STANDARD;

		/* Get standard community strings using iterate (handles multiple entries) */
		if (yang_dnode_exists(args->dnode, "standard-community-string")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "standard-community-string");
		}
	} else {
		style = COMMUNITY_LIST_EXPANDED;

		/* Get expanded community string (regex) */
		if (yang_dnode_exists(args->dnode, "expanded-community-string")) {
			const char *regex = yang_dnode_get_string(args->dnode,
					"expanded-community-string");
			strlcpy(comm_str, regex, sizeof(comm_str));
		}
	}

	if (comm_str[0] == '\0') {
		zlog_warn("community-list %s: no community string specified", name);
		return NB_ERR_VALIDATION;
	}

	ret = community_list_set(bgp_clist, name, comm_str, seq_str, direct, style);
	if (ret < 0) {
		zlog_warn("community-list %s: failed to set entry: %d", name, ret);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int lib_community_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;
	const char *seq_str;
	const char *type_str;
	const char *action_str;
	int direct;
	int style;
	char comm_str[512] = "";

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	type_str = yang_dnode_get_string(args->dnode, "type");
	if (strcmp(type_str, "community-list-standard") == 0) {
		style = COMMUNITY_LIST_STANDARD;

		if (yang_dnode_exists(args->dnode, "standard-community-string")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "standard-community-string");
		}
	} else {
		style = COMMUNITY_LIST_EXPANDED;

		if (yang_dnode_exists(args->dnode, "expanded-community-string")) {
			const char *regex = yang_dnode_get_string(args->dnode,
					"expanded-community-string");
			strlcpy(comm_str, regex, sizeof(comm_str));
		}
	}

	community_list_unset(bgp_clist, name, comm_str[0] ? comm_str : NULL,
			     seq_str, direct, style);

	return NB_OK;
}

/*
 * Leaf callbacks for community-list/entry
 * These are no-ops since entry create/destroy handles everything
 */
int lib_community_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	/* Handled by entry create */
	return NB_OK;
}

int lib_community_list_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	/* Handled by entry destroy */
	return NB_OK;
}

int lib_community_list_entry_type_modify(struct nb_cb_modify_args *args)
{
	/* Handled by entry create */
	return NB_OK;
}

int lib_community_list_entry_standard_community_string_create(struct nb_cb_create_args *args)
{
	/* Handled by entry create */
	return NB_OK;
}

int lib_community_list_entry_standard_community_string_destroy(struct nb_cb_destroy_args *args)
{
	/* Handled by entry destroy */
	return NB_OK;
}

int lib_community_list_entry_expanded_community_string_modify(struct nb_cb_modify_args *args)
{
	/* Handled by entry create */
	return NB_OK;
}

int lib_community_list_entry_expanded_community_string_destroy(struct nb_cb_destroy_args *args)
{
	/* Handled by entry destroy */
	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:large-community-list
 */
int lib_large_community_list_create(struct nb_cb_create_args *args)
{
	/* Lists are created implicitly when entries are added */
	return NB_OK;
}

int lib_large_community_list_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");

	/* Delete all entries */
	lcommunity_list_unset(bgp_clist, name, NULL, NULL, 0, LARGE_COMMUNITY_LIST_STANDARD);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:large-community-list/entry
 */
int lib_large_community_list_entry_create(struct nb_cb_create_args *args)
{
	const char *name;
	const char *seq_str;
	const char *type_str;
	const char *action_str;
	int direct;
	int style;
	int ret;
	char comm_str[512] = "";

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	type_str = yang_dnode_get_string(args->dnode, "type");
	if (strcmp(type_str, "large-community-list-standard-id") == 0 ||
	    strcmp(type_str, "large-community-list-standard-name") == 0) {
		style = LARGE_COMMUNITY_LIST_STANDARD;

		if (yang_dnode_exists(args->dnode, "standard-large-community-string")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "standard-large-community-string");
		}
	} else {
		style = LARGE_COMMUNITY_LIST_EXPANDED;

		if (yang_dnode_exists(args->dnode, "expanded-large-community-string")) {
			const char *regex = yang_dnode_get_string(args->dnode,
					"expanded-large-community-string");
			strlcpy(comm_str, regex, sizeof(comm_str));
		}
	}

	if (comm_str[0] == '\0') {
		zlog_warn("large-community-list %s: no community string specified", name);
		return NB_ERR_VALIDATION;
	}

	ret = lcommunity_list_set(bgp_clist, name, comm_str, seq_str, direct, style);
	if (ret < 0) {
		zlog_warn("large-community-list %s: failed to set entry: %d", name, ret);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int lib_large_community_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;
	const char *seq_str;
	const char *type_str;
	const char *action_str;
	int direct;
	int style;
	char comm_str[512] = "";

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	type_str = yang_dnode_get_string(args->dnode, "type");
	if (strcmp(type_str, "large-community-list-standard-id") == 0 ||
	    strcmp(type_str, "large-community-list-standard-name") == 0) {
		style = LARGE_COMMUNITY_LIST_STANDARD;

		if (yang_dnode_exists(args->dnode, "standard-large-community-string")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "standard-large-community-string");
		}
	} else {
		style = LARGE_COMMUNITY_LIST_EXPANDED;

		if (yang_dnode_exists(args->dnode, "expanded-large-community-string")) {
			const char *regex = yang_dnode_get_string(args->dnode,
					"expanded-large-community-string");
			strlcpy(comm_str, regex, sizeof(comm_str));
		}
	}

	lcommunity_list_unset(bgp_clist, name, comm_str[0] ? comm_str : NULL,
			      seq_str, direct, style);

	return NB_OK;
}

/*
 * Leaf callbacks for large-community-list/entry
 */
int lib_large_community_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int lib_large_community_list_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_large_community_list_entry_type_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int lib_large_community_list_entry_standard_large_community_string_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_large_community_list_entry_standard_large_community_string_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_large_community_list_entry_expanded_large_community_string_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int lib_large_community_list_entry_expanded_large_community_string_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:extcommunity-list
 */
int lib_extcommunity_list_create(struct nb_cb_create_args *args)
{
	/* Lists are created implicitly when entries are added */
	return NB_OK;
}

int lib_extcommunity_list_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");

	/* Delete all entries */
	extcommunity_list_unset(bgp_clist, name, NULL, NULL, 0, EXTCOMMUNITY_LIST_STANDARD);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:extcommunity-list/entry
 */
int lib_extcommunity_list_entry_create(struct nb_cb_create_args *args)
{
	const char *name;
	const char *seq_str;
	const char *type_str;
	const char *action_str;
	int direct;
	int style;
	int ret;
	char comm_str[512] = "";

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	type_str = yang_dnode_get_string(args->dnode, "type");
	if (strcmp(type_str, "extcommunity-list-standard-id") == 0 ||
	    strcmp(type_str, "extcommunity-list-standard-name") == 0) {
		style = EXTCOMMUNITY_LIST_STANDARD;

		/* Check for rt or soo */
		if (yang_dnode_exists(args->dnode, "extcommunity-rt")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			strlcpy(comm_str, "rt ", sizeof(comm_str));
			collector.first = false; /* We already have "rt " prefix */
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "extcommunity-rt");
		} else if (yang_dnode_exists(args->dnode, "extcommunity-soo")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			strlcpy(comm_str, "soo ", sizeof(comm_str));
			collector.first = false; /* We already have "soo " prefix */
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "extcommunity-soo");
		} else if (yang_dnode_exists(args->dnode, "extcommunity-nt")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			strlcpy(comm_str, "nt ", sizeof(comm_str));
			collector.first = false; /* We already have "nt " prefix */
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "extcommunity-nt");
		}
	} else {
		style = EXTCOMMUNITY_LIST_EXPANDED;

		if (yang_dnode_exists(args->dnode, "expanded-extcommunity-string")) {
			const char *regex = yang_dnode_get_string(args->dnode,
					"expanded-extcommunity-string");
			strlcpy(comm_str, regex, sizeof(comm_str));
		}
	}

	if (comm_str[0] == '\0') {
		zlog_warn("extcommunity-list %s: no community string specified", name);
		return NB_ERR_VALIDATION;
	}

	ret = extcommunity_list_set(bgp_clist, name, comm_str, seq_str, direct, style);
	if (ret < 0) {
		zlog_warn("extcommunity-list %s: failed to set entry: %d", name, ret);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int lib_extcommunity_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;
	const char *seq_str;
	const char *type_str;
	const char *action_str;
	int direct;
	int style;
	char comm_str[512] = "";

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	type_str = yang_dnode_get_string(args->dnode, "type");
	if (strcmp(type_str, "extcommunity-list-standard-id") == 0 ||
	    strcmp(type_str, "extcommunity-list-standard-name") == 0) {
		style = EXTCOMMUNITY_LIST_STANDARD;

		if (yang_dnode_exists(args->dnode, "extcommunity-rt")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			strlcpy(comm_str, "rt ", sizeof(comm_str));
			collector.first = false; /* We already have "rt " prefix */
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "extcommunity-rt");
		} else if (yang_dnode_exists(args->dnode, "extcommunity-soo")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			strlcpy(comm_str, "soo ", sizeof(comm_str));
			collector.first = false; /* We already have "soo " prefix */
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "extcommunity-soo");
		} else if (yang_dnode_exists(args->dnode, "extcommunity-nt")) {
			struct leaflist_collector collector = {
				.buffer = comm_str,
				.buffer_size = sizeof(comm_str),
				.first = true,
			};
			strlcpy(comm_str, "nt ", sizeof(comm_str));
			collector.first = false; /* We already have "nt " prefix */
			yang_dnode_iterate(collect_leaflist_value, &collector,
					   args->dnode, "extcommunity-nt");
		}
	} else {
		style = EXTCOMMUNITY_LIST_EXPANDED;

		if (yang_dnode_exists(args->dnode, "expanded-extcommunity-string")) {
			const char *regex = yang_dnode_get_string(args->dnode,
					"expanded-extcommunity-string");
			strlcpy(comm_str, regex, sizeof(comm_str));
		}
	}

	extcommunity_list_unset(bgp_clist, name, comm_str[0] ? comm_str : NULL,
				seq_str, direct, style);

	return NB_OK;
}

/*
 * Leaf callbacks for extcommunity-list/entry
 */
int lib_extcommunity_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_type_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_rt_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_rt_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_soo_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_soo_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_nt_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_nt_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_expanded_extcommunity_string_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_expanded_extcommunity_string_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:as-path-list
 *
 * AS-path access lists use a different API in bgp_filter.c
 * For now, provide stub implementations that will be enhanced later
 */
int lib_as_path_list_create(struct nb_cb_create_args *args)
{
	/* Lists are created implicitly when entries are added */
	return NB_OK;
}

int lib_as_path_list_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	as_list_delete_by_name(name);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:as-path-list/entry
 */
int lib_as_path_list_entry_create(struct nb_cb_create_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *aspath_regex;
	enum as_filter_type type;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Get parent list name */
	name = yang_dnode_get_string(args->dnode, "../name");

	/* Get sequence */
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	/* Get action (permit/deny) */
	action_str = yang_dnode_get_string(args->dnode, "action");
	type = (strcmp(action_str, "permit") == 0) ? AS_FILTER_PERMIT : AS_FILTER_DENY;

	/* Get as-path regex */
	aspath_regex = yang_dnode_get_string(args->dnode, "as-path");

	ret = as_list_entry_set(name, seq_str, aspath_regex, type);
	if (ret < 0) {
		zlog_warn("as-path-list %s: failed to set entry with regex '%s'",
			  name, aspath_regex);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int lib_as_path_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *aspath_regex;
	enum as_filter_type type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	type = (strcmp(action_str, "permit") == 0) ? AS_FILTER_PERMIT : AS_FILTER_DENY;

	aspath_regex = yang_dnode_get_string(args->dnode, "as-path");

	as_list_entry_unset(name, seq_str, aspath_regex, type);

	return NB_OK;
}

/*
 * Leaf callbacks for as-path-list/entry
 *
 * When a leaf value is modified on an existing entry, we need to
 * update the as-path-list. We do this by calling as_list_entry_set()
 * which handles both creation and replacement of entries.
 */
int lib_as_path_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *aspath_regex;
	enum as_filter_type type;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Get parent list name - go up to entry, then to as-path-list */
	name = yang_dnode_get_string(args->dnode, "../../name");
	seq_str = yang_dnode_get_string(args->dnode, "../sequence");
	action_str = yang_dnode_get_string(args->dnode, NULL);
	type = (strcmp(action_str, "permit") == 0) ? AS_FILTER_PERMIT : AS_FILTER_DENY;
	aspath_regex = yang_dnode_get_string(args->dnode, "../as-path");

	zlog_debug("as-path-list action_modify: name=%s seq=%s action=%s regex=%s",
		   name, seq_str, action_str, aspath_regex);

	ret = as_list_entry_set(name, seq_str, aspath_regex, type);
	if (ret < 0) {
		zlog_warn("as-path-list %s: failed to update entry action", name);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int lib_as_path_list_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_as_path_list_entry_as_path_modify(struct nb_cb_modify_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *aspath_regex;
	enum as_filter_type type;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Get parent list name - go up to entry, then to as-path-list */
	name = yang_dnode_get_string(args->dnode, "../../name");
	seq_str = yang_dnode_get_string(args->dnode, "../sequence");
	action_str = yang_dnode_get_string(args->dnode, "../action");
	type = (strcmp(action_str, "permit") == 0) ? AS_FILTER_PERMIT : AS_FILTER_DENY;
	aspath_regex = yang_dnode_get_string(args->dnode, NULL);

	zlog_debug("as-path-list as_path_modify: name=%s seq=%s action=%s regex=%s",
		   name, seq_str, action_str, aspath_regex);

	ret = as_list_entry_set(name, seq_str, aspath_regex, type);
	if (ret < 0) {
		zlog_warn("as-path-list %s: failed to update entry as-path", name);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int lib_as_path_list_entry_as_path_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

static void lib_as_path_list_entry_cli_show(struct vty *vty,
					    const struct lyd_node *dnode,
					    bool show_defaults)
{
	const char *name;
	uint32_t seq;
	const char *action;
	const char *aspath;

	name = yang_dnode_get_string(dnode, "../name");
	seq = yang_dnode_get_uint32(dnode, "sequence");
	action = yang_dnode_get_string(dnode, "action");
	aspath = yang_dnode_get_string(dnode, "as-path");

	vty_out(vty, "bgp as-path access-list %s seq %u %s %s\n", name, seq,
		action, aspath);
}

/* ========================================================================
 * Operational State Callbacks for RESTCONF GET
 * ======================================================================== */

/*
 * Helper: Iterate through both numbered and string community lists
 */
struct clist_iter {
	struct community_list *current;
	bool in_str_list;	/* false = still in num list, true = in str list */
	int master_type;	/* COMMUNITY_LIST_MASTER, etc. */
};

static struct community_list *clist_iter_first(int master_type, struct clist_iter *iter)
{
	struct community_list_master *cm;

	iter->master_type = master_type;
	cm = community_list_master_lookup(bgp_clist, master_type);
	if (!cm)
		return NULL;

	/* Try numbered list first */
	iter->in_str_list = false;
	if (cm->num.head) {
		iter->current = cm->num.head;
		return iter->current;
	}

	/* Fall back to string list */
	iter->in_str_list = true;
	iter->current = cm->str.head;
	return iter->current;
}

static struct community_list *clist_iter_next(struct clist_iter *iter)
{
	struct community_list_master *cm;

	if (!iter->current)
		return NULL;

	/* Move to next in current list */
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter->current;
	}

	/* If in numbered list, try string list */
	if (!iter->in_str_list) {
		cm = community_list_master_lookup(bgp_clist, iter->master_type);
		if (cm && cm->str.head) {
			iter->in_str_list = true;
			iter->current = cm->str.head;
			return iter->current;
		}
	}

	/* No more entries */
	iter->current = NULL;
	return NULL;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:community-list
 * Operational state callbacks
 */
static const void *lib_community_list_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *iter;
	struct community_list *clist;

	if (args->list_entry == NULL) {
		/* First call - allocate iterator */
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		clist = clist_iter_first(COMMUNITY_LIST_MASTER, iter);
		if (!clist) {
			XFREE(MTYPE_TMP, iter);
			return NULL;
		}
		/* Store iterator in opaque pointer - we'll retrieve it via list_entry */
		return iter;
	}

	iter = (struct clist_iter *)args->list_entry;
	clist = clist_iter_next(iter);
	if (!clist) {
		XFREE(MTYPE_TMP, iter);
		return NULL;
	}
	return iter;
}

static int lib_community_list_get_keys(struct nb_cb_get_keys_args *args)
{
	struct clist_iter *iter = (struct clist_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], iter->current->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_community_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct community_list *clist;
	struct clist_iter *iter;

	clist = community_list_lookup(bgp_clist, name, 0, COMMUNITY_LIST_MASTER);
	if (!clist)
		return NULL;

	/* Allocate iterator and set current */
	iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
	iter->current = clist;
	iter->master_type = COMMUNITY_LIST_MASTER;
	iter->in_str_list = true; /* Doesn't matter for lookup */
	return iter;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:community-list/entry
 */
struct centry_iter {
	struct community_list *parent;
	struct community_entry *current;
};

static const void *lib_community_list_entry_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *parent_iter;
	struct centry_iter *iter;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	if (args->list_entry == NULL) {
		/* First call */
		if (!parent_iter->current->head)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->parent = parent_iter->current;
		iter->current = parent_iter->current->head;
		return iter;
	}

	iter = (struct centry_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_community_list_entry_get_keys(struct nb_cb_get_keys_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	char seq_buf[32];

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	snprintf(seq_buf, sizeof(seq_buf), "%ld", (long)iter->current->seq);
	strlcpy(args->keys->key[0], seq_buf, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_community_list_entry_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct clist_iter *parent_iter;
	struct community_entry *entry;
	struct centry_iter *iter;
	int64_t seq;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	seq = strtoll(args->keys->key[0], NULL, 10);

	for (entry = parent_iter->current->head; entry; entry = entry->next) {
		if (entry->seq == seq) {
			iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
			iter->parent = parent_iter->current;
			iter->current = entry;
			return iter;
		}
	}
	return NULL;
}

/*
 * Leaf get_elem callbacks for community-list/entry
 */
static __attribute__((unused)) struct yang_data *lib_community_list_entry_sequence_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)iter->current->seq);
}

static __attribute__((unused)) struct yang_data *lib_community_list_entry_action_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* list-action enum: deny=0, permit=1 */
	return yang_data_new_enum(args->xpath,
		iter->current->direct == COMMUNITY_PERMIT ? 1 : 0);
}

static __attribute__((unused)) struct yang_data *lib_community_list_entry_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* community-list type enum: standard=0, extended=1 */
	return yang_data_new_enum(args->xpath,
		iter->current->style == COMMUNITY_LIST_STANDARD ? 0 : 1);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:large-community-list
 */
static const void *lib_large_community_list_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *iter;
	struct community_list *clist;

	if (args->list_entry == NULL) {
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		clist = clist_iter_first(LARGE_COMMUNITY_LIST_MASTER, iter);
		if (!clist) {
			XFREE(MTYPE_TMP, iter);
			return NULL;
		}
		return iter;
	}

	iter = (struct clist_iter *)args->list_entry;
	clist = clist_iter_next(iter);
	if (!clist) {
		XFREE(MTYPE_TMP, iter);
		return NULL;
	}
	return iter;
}

static int lib_large_community_list_get_keys(struct nb_cb_get_keys_args *args)
{
	struct clist_iter *iter = (struct clist_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], iter->current->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_large_community_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct community_list *clist;
	struct clist_iter *iter;

	clist = community_list_lookup(bgp_clist, name, 0, LARGE_COMMUNITY_LIST_MASTER);
	if (!clist)
		return NULL;

	iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
	iter->current = clist;
	iter->master_type = LARGE_COMMUNITY_LIST_MASTER;
	iter->in_str_list = true;
	return iter;
}

/*
 * Large community list entry callbacks - reuse centry_iter structure
 */
static const void *lib_large_community_list_entry_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *parent_iter;
	struct centry_iter *iter;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	if (args->list_entry == NULL) {
		if (!parent_iter->current->head)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->parent = parent_iter->current;
		iter->current = parent_iter->current->head;
		return iter;
	}

	iter = (struct centry_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_large_community_list_entry_get_keys(struct nb_cb_get_keys_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	char seq_buf[32];

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	snprintf(seq_buf, sizeof(seq_buf), "%ld", (long)iter->current->seq);
	strlcpy(args->keys->key[0], seq_buf, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_large_community_list_entry_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct clist_iter *parent_iter;
	struct community_entry *entry;
	struct centry_iter *iter;
	int64_t seq;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	seq = strtoll(args->keys->key[0], NULL, 10);

	for (entry = parent_iter->current->head; entry; entry = entry->next) {
		if (entry->seq == seq) {
			iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
			iter->parent = parent_iter->current;
			iter->current = entry;
			return iter;
		}
	}
	return NULL;
}

static __attribute__((unused)) struct yang_data *lib_large_community_list_entry_sequence_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)iter->current->seq);
}

static __attribute__((unused)) struct yang_data *lib_large_community_list_entry_action_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* list-action enum: deny=0, permit=1 */
	return yang_data_new_enum(args->xpath,
		iter->current->direct == COMMUNITY_PERMIT ? 1 : 0);
}

static __attribute__((unused)) struct yang_data *lib_large_community_list_entry_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	int type_val;

	if (!iter || !iter->current)
		return NULL;

	/* large-community-list type: standard-id=0, extended-id=1, standard-name=2, extended-name=3 */
	switch (iter->current->style) {
	case LARGE_COMMUNITY_LIST_STANDARD:
		type_val = 2; /* standard-name */
		break;
	case LARGE_COMMUNITY_LIST_EXPANDED:
	default:
		type_val = 3; /* extended-name */
		break;
	}
	return yang_data_new_enum(args->xpath, type_val);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:extcommunity-list
 */
static const void *lib_extcommunity_list_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *iter;
	struct community_list *clist;

	if (args->list_entry == NULL) {
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		clist = clist_iter_first(EXTCOMMUNITY_LIST_MASTER, iter);
		if (!clist) {
			XFREE(MTYPE_TMP, iter);
			return NULL;
		}
		return iter;
	}

	iter = (struct clist_iter *)args->list_entry;
	clist = clist_iter_next(iter);
	if (!clist) {
		XFREE(MTYPE_TMP, iter);
		return NULL;
	}
	return iter;
}

static int lib_extcommunity_list_get_keys(struct nb_cb_get_keys_args *args)
{
	struct clist_iter *iter = (struct clist_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], iter->current->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_extcommunity_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct community_list *clist;
	struct clist_iter *iter;

	clist = community_list_lookup(bgp_clist, name, 0, EXTCOMMUNITY_LIST_MASTER);
	if (!clist)
		return NULL;

	iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
	iter->current = clist;
	iter->master_type = EXTCOMMUNITY_LIST_MASTER;
	iter->in_str_list = true;
	return iter;
}

/*
 * Extcommunity list entry callbacks
 */
static const void *lib_extcommunity_list_entry_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *parent_iter;
	struct centry_iter *iter;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	if (args->list_entry == NULL) {
		if (!parent_iter->current->head)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->parent = parent_iter->current;
		iter->current = parent_iter->current->head;
		return iter;
	}

	iter = (struct centry_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_extcommunity_list_entry_get_keys(struct nb_cb_get_keys_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	char seq_buf[32];

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	snprintf(seq_buf, sizeof(seq_buf), "%ld", (long)iter->current->seq);
	strlcpy(args->keys->key[0], seq_buf, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_extcommunity_list_entry_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct clist_iter *parent_iter;
	struct community_entry *entry;
	struct centry_iter *iter;
	int64_t seq;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	seq = strtoll(args->keys->key[0], NULL, 10);

	for (entry = parent_iter->current->head; entry; entry = entry->next) {
		if (entry->seq == seq) {
			iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
			iter->parent = parent_iter->current;
			iter->current = entry;
			return iter;
		}
	}
	return NULL;
}

static __attribute__((unused)) struct yang_data *lib_extcommunity_list_entry_sequence_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)iter->current->seq);
}

static __attribute__((unused)) struct yang_data *lib_extcommunity_list_entry_action_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* list-action enum: deny=0, permit=1 */
	return yang_data_new_enum(args->xpath,
		iter->current->direct == COMMUNITY_PERMIT ? 1 : 0);
}

static __attribute__((unused)) struct yang_data *lib_extcommunity_list_entry_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	int type_val;

	if (!iter || !iter->current)
		return NULL;

	/* extcommunity-list type: standard-id=0, extended-id=1, standard-name=2, extended-name=3 */
	switch (iter->current->style) {
	case EXTCOMMUNITY_LIST_STANDARD:
		type_val = 2; /* standard-name */
		break;
	case EXTCOMMUNITY_LIST_EXPANDED:
	default:
		type_val = 3; /* extended-name */
		break;
	}
	return yang_data_new_enum(args->xpath, type_val);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:as-path-list
 */
struct aslist_iter {
	struct as_list *current;
};

static const void *lib_as_path_list_get_next(struct nb_cb_get_next_args *args)
{
	struct aslist_iter *iter;
	struct as_list *aslist;

	if (args->list_entry == NULL) {
		aslist = as_list_first();
		if (!aslist)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->current = aslist;
		return iter;
	}

	iter = (struct aslist_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_as_path_list_get_keys(struct nb_cb_get_keys_args *args)
{
	struct aslist_iter *iter = (struct aslist_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], iter->current->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_as_path_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct as_list *aslist;
	struct aslist_iter *iter;

	aslist = as_list_lookup(name);
	if (!aslist)
		return NULL;

	iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
	iter->current = aslist;
	return iter;
}

/*
 * AS-path list entry callbacks
 */
struct asfilter_iter {
	struct as_list *parent;
	struct as_filter *current;
};

static const void *lib_as_path_list_entry_get_next(struct nb_cb_get_next_args *args)
{
	struct aslist_iter *parent_iter;
	struct asfilter_iter *iter;

	parent_iter = (struct aslist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	if (args->list_entry == NULL) {
		if (!parent_iter->current->head)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->parent = parent_iter->current;
		iter->current = parent_iter->current->head;
		return iter;
	}

	iter = (struct asfilter_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_as_path_list_entry_get_keys(struct nb_cb_get_keys_args *args)
{
	struct asfilter_iter *iter = (struct asfilter_iter *)args->list_entry;
	char seq_buf[32];

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	snprintf(seq_buf, sizeof(seq_buf), "%ld", (long)iter->current->seq);
	strlcpy(args->keys->key[0], seq_buf, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_as_path_list_entry_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct aslist_iter *parent_iter;
	struct as_filter *filter;
	struct asfilter_iter *iter;
	int64_t seq;

	parent_iter = (struct aslist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	seq = strtoll(args->keys->key[0], NULL, 10);

	for (filter = parent_iter->current->head; filter; filter = filter->next) {
		if (filter->seq == seq) {
			iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
			iter->parent = parent_iter->current;
			iter->current = filter;
			return iter;
		}
	}
	return NULL;
}

static __attribute__((unused)) struct yang_data *lib_as_path_list_entry_sequence_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct asfilter_iter *iter = (struct asfilter_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)iter->current->seq);
}

static __attribute__((unused)) struct yang_data *lib_as_path_list_entry_action_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct asfilter_iter *iter = (struct asfilter_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* list-action enum: deny=0, permit=1 */
	return yang_data_new_enum(args->xpath,
		iter->current->type == AS_FILTER_PERMIT ? 1 : 0);
}

static __attribute__((unused)) struct yang_data *lib_as_path_list_entry_as_path_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct asfilter_iter *iter = (struct asfilter_iter *)args->list_entry;

	if (!iter || !iter->current || !iter->current->reg_str)
		return NULL;

	return yang_data_new_string(args->xpath, iter->current->reg_str);
}

/* clang-format off */
const struct frr_yang_module_info frr_bgp_filter_info = {
	.name = "frr-bgp-filter",
	.nodes = {
		/* community-list */
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list",
			.cbs = {
				.create = lib_community_list_create,
				.destroy = lib_community_list_destroy,
				.get_next = lib_community_list_get_next,
				.get_keys = lib_community_list_get_keys,
				.lookup_entry = lib_community_list_lookup_entry,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry",
			.cbs = {
				.create = lib_community_list_entry_create,
				.destroy = lib_community_list_entry_destroy,
				.get_next = lib_community_list_entry_get_next,
				.get_keys = lib_community_list_entry_get_keys,
				.lookup_entry = lib_community_list_entry_lookup_entry,
				.cli_show = lib_community_list_entry_cli_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry/action",
			.cbs = {
				.modify = lib_community_list_entry_action_modify,
				.destroy = lib_community_list_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry/type",
			.cbs = {
				.modify = lib_community_list_entry_type_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry/standard-community-string",
			.cbs = {
				.create = lib_community_list_entry_standard_community_string_create,
				.destroy = lib_community_list_entry_standard_community_string_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry/expanded-community-string",
			.cbs = {
				.modify = lib_community_list_entry_expanded_community_string_modify,
				.destroy = lib_community_list_entry_expanded_community_string_destroy,
			}
		},
		/* large-community-list */
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list",
			.cbs = {
				.create = lib_large_community_list_create,
				.destroy = lib_large_community_list_destroy,
				.get_next = lib_large_community_list_get_next,
				.get_keys = lib_large_community_list_get_keys,
				.lookup_entry = lib_large_community_list_lookup_entry,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry",
			.cbs = {
				.create = lib_large_community_list_entry_create,
				.destroy = lib_large_community_list_entry_destroy,
				.get_next = lib_large_community_list_entry_get_next,
				.get_keys = lib_large_community_list_entry_get_keys,
				.lookup_entry = lib_large_community_list_entry_lookup_entry,
				.cli_show = lib_large_community_list_entry_cli_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry/action",
			.cbs = {
				.modify = lib_large_community_list_entry_action_modify,
				.destroy = lib_large_community_list_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry/type",
			.cbs = {
				.modify = lib_large_community_list_entry_type_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry/standard-large-community-string",
			.cbs = {
				.create = lib_large_community_list_entry_standard_large_community_string_create,
				.destroy = lib_large_community_list_entry_standard_large_community_string_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry/expanded-large-community-string",
			.cbs = {
				.modify = lib_large_community_list_entry_expanded_large_community_string_modify,
				.destroy = lib_large_community_list_entry_expanded_large_community_string_destroy,
			}
		},
		/* extcommunity-list */
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list",
			.cbs = {
				.create = lib_extcommunity_list_create,
				.destroy = lib_extcommunity_list_destroy,
				.get_next = lib_extcommunity_list_get_next,
				.get_keys = lib_extcommunity_list_get_keys,
				.lookup_entry = lib_extcommunity_list_lookup_entry,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry",
			.cbs = {
				.create = lib_extcommunity_list_entry_create,
				.destroy = lib_extcommunity_list_entry_destroy,
				.get_next = lib_extcommunity_list_entry_get_next,
				.get_keys = lib_extcommunity_list_entry_get_keys,
				.lookup_entry = lib_extcommunity_list_entry_lookup_entry,
				.cli_show = lib_extcommunity_list_entry_cli_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/action",
			.cbs = {
				.modify = lib_extcommunity_list_entry_action_modify,
				.destroy = lib_extcommunity_list_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/type",
			.cbs = {
				.modify = lib_extcommunity_list_entry_type_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/extcommunity-rt",
			.cbs = {
				.create = lib_extcommunity_list_entry_rt_create,
				.destroy = lib_extcommunity_list_entry_rt_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/extcommunity-soo",
			.cbs = {
				.create = lib_extcommunity_list_entry_soo_create,
				.destroy = lib_extcommunity_list_entry_soo_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/extcommunity-nt",
			.cbs = {
				.create = lib_extcommunity_list_entry_nt_create,
				.destroy = lib_extcommunity_list_entry_nt_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/expanded-extcommunity-string",
			.cbs = {
				.modify = lib_extcommunity_list_entry_expanded_extcommunity_string_modify,
				.destroy = lib_extcommunity_list_entry_expanded_extcommunity_string_destroy,
			}
		},
		/* as-path-list */
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:as-path-list",
			.cbs = {
				.create = lib_as_path_list_create,
				.destroy = lib_as_path_list_destroy,
				.get_next = lib_as_path_list_get_next,
				.get_keys = lib_as_path_list_get_keys,
				.lookup_entry = lib_as_path_list_lookup_entry,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:as-path-list/entry",
			.cbs = {
				.create = lib_as_path_list_entry_create,
				.destroy = lib_as_path_list_entry_destroy,
				.get_next = lib_as_path_list_entry_get_next,
				.get_keys = lib_as_path_list_entry_get_keys,
				.lookup_entry = lib_as_path_list_entry_lookup_entry,
				.cli_show = lib_as_path_list_entry_cli_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:as-path-list/entry/action",
			.cbs = {
				.modify = lib_as_path_list_entry_action_modify,
				.destroy = lib_as_path_list_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:as-path-list/entry/as-path",
			.cbs = {
				.modify = lib_as_path_list_entry_as_path_modify,
				.destroy = lib_as_path_list_entry_as_path_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */
