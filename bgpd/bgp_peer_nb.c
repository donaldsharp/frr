#include "bgpd/bgpd.h"
#include "northbound.h"
#include "bgpd/bgp_debug.h"
#include "lib/vrf.h"

/* prototypes */
const void *lib_vrf_get_next(struct nb_cb_get_next_args *args);
int lib_vrf_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_vrf_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_vrf_id_get_elem(struct nb_cb_get_elem_args *args);
const void *lib_vrf_peer_get_next(struct nb_cb_get_next_args *args);
int lib_vrf_peer_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_vrf_peer_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_vrf_peer_name_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_status_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_established_transitions_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_inQ_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_peer_outQ_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_txUpdates_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_rxUpdates_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_ipv4UniRcvdCount_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_ipv6UniRcvdCount_get_elem(struct nb_cb_get_elem_args *args);
const void *lib_vrf_peer_count_get_next(struct nb_cb_get_next_args *args);
int lib_vrf_peer_count_get_keys(struct nb_cb_get_keys_args *args);
const void *
lib_vrf_peer_count_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *
lib_vrf_peer_count_afi_safi_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_count_received_get_elem(struct nb_cb_get_elem_args *args);

/*
 * XPath: /frr-bgp-peer:lib/vrf
 */
const void *lib_vrf_get_next(struct nb_cb_get_next_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;
	if (args->list_entry == NULL) {
		vrfp = RB_MIN(vrf_name_head, &vrfs_by_name);
	} else {
		vrfp = RB_NEXT(vrf_name_head, vrfp);
	}
	return vrfp;
}

int lib_vrf_get_keys(struct nb_cb_get_keys_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;
	args->keys->num = 1;
	strlcpy(args->keys->key[0], vrfp->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

const void *lib_vrf_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *vrfname = args->keys->key[0];
	struct vrf *vrf = vrf_lookup_by_name(vrfname);
	zlog_err("lib_vrf_lookup_entry name %s", vrfname);
	return vrf;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/id
 */
struct yang_data *lib_vrf_id_get_elem(struct nb_cb_get_elem_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;
	return yang_data_new_uint32(args->xpath, vrfp->vrf_id);
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer
 */
const void *lib_vrf_peer_get_next(struct nb_cb_get_next_args *args)
{
        struct bgp *bgp;
        struct peer *peer;
        struct listnode *node, *nnode;
        struct nb_config_entry *config;
	struct vrf *vrfp = (struct vrf *)args->parent_list_entry;
	if (!vrfp)
		return NULL;
	else
		zlog_err("VRF %s VRF id %d", vrfp->name, vrfp->vrf_id);
	if (!vrfp->vrf_id)
	    bgp = bgp_get_default();
	else
	    bgp = bgp_lookup_by_vrf_id(vrfp->vrf_id);
        if (args->list_entry == NULL) {
		if (bgp) {
			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
				if (peer)
					return peer;
			}
		}
	} else {
		struct peer *iter;
		bool next = false;
		peer = (struct peer *)args->list_entry;
		if (!peer)
			return NULL;
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, iter)) {
			if (peer->conf_if) {
				if (strcmp(peer->conf_if, iter->conf_if) == 0)
					next = true;
				else if (next == true)
					return iter;
			} else if (peer->hostname) {
				zlog_err("Hostname %s iter hostname %s",
					 peer->hostname, iter->hostname);
				if (strcmp(peer->hostname, iter->hostname) == 0)
					next = true;
				else if (next == true)
					return iter;
			}
		}
	}
	return NULL;
}

int lib_vrf_peer_get_keys(struct nb_cb_get_keys_args *args)
{
	args->keys->num = 1;
	if (args->list_entry) {
		struct peer *peer = (struct peer *)args->list_entry;
		if (peer) {
			if (peer->conf_if)
				strlcpy(args->keys->key[0], peer->conf_if,
					sizeof(args->keys->key[0]));
			else if (peer->hostname)
				strlcpy(args->keys->key[0], peer->hostname,
					sizeof(args->keys->key[0]));
			else
				strlcpy(args->keys->key[0], &peer->su,
					sizeof(args->keys->key[0]));
		}
	}
	return NB_OK;
}

const void *lib_vrf_peer_lookup_entry(struct nb_cb_lookup_entry_args *args)
{

	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/name
 */
struct yang_data *lib_vrf_peer_name_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/status
 */
struct yang_data *lib_vrf_peer_status_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_string(
			args->xpath,
			lookup_msg(bgp_status_msg, peer->status, NULL));
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/established_transitions
 */
struct yang_data *
lib_vrf_peer_established_transitions_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath, peer->established);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/inQ
 */
struct yang_data *lib_vrf_peer_inQ_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath, peer->ibuf->count);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/outQ
 */
struct yang_data *lib_vrf_peer_outQ_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath, peer->obuf->count);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/txUpdates
 */
struct yang_data *
lib_vrf_peer_txUpdates_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath, PEER_TOTAL_TX(peer));
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/rxUpdates
 */
struct yang_data *
lib_vrf_peer_rxUpdates_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath, PEER_TOTAL_RX(peer));
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/ipv4UniRcvdCount
 */
struct yang_data *
lib_vrf_peer_ipv4UniRcvdCount_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath,
					    peer->pcount[AFI_IP][SAFI_UNICAST]);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/ipv6UniRcvdCount
 */
struct yang_data *
lib_vrf_peer_ipv6UniRcvdCount_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(
			args->xpath, peer->pcount[AFI_IP6][SAFI_UNICAST]);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/count
 */
const void *lib_vrf_peer_count_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_peer_count_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *
lib_vrf_peer_count_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/count/afi-safi
 */
struct yang_data *
lib_vrf_peer_count_afi_safi_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/count/received
 */
struct yang_data *
lib_vrf_peer_count_received_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/* clang-format off */
const struct frr_yang_module_info frr_bgp_peer_info = {
	.name = "frr-bgp-peer",
	.nodes = {
		{
			.xpath = "/frr-bgp-peer:lib/vrf",
			.cbs = {
				.get_next = lib_vrf_get_next,
				.get_keys = lib_vrf_get_keys,
				.lookup_entry = lib_vrf_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/id",
			.cbs = {
				.get_elem = lib_vrf_id_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer",
			.cbs = {
				.get_next = lib_vrf_peer_get_next,
				.get_keys = lib_vrf_peer_get_keys,
				.lookup_entry = lib_vrf_peer_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/name",
			.cbs = {
				.get_elem = lib_vrf_peer_name_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/status",
			.cbs = {
				.get_elem = lib_vrf_peer_status_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/established_transitions",
			.cbs = {
				.get_elem = lib_vrf_peer_established_transitions_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/inQ",
			.cbs = {
				.get_elem = lib_vrf_peer_inQ_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/outQ",
			.cbs = {
				.get_elem = lib_vrf_peer_outQ_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/txUpdates",
			.cbs = {
				.get_elem = lib_vrf_peer_txUpdates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/rxUpdates",
			.cbs = {
				.get_elem = lib_vrf_peer_rxUpdates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/ipv4UniRcvdCount",
			.cbs = {
				.get_elem = lib_vrf_peer_ipv4UniRcvdCount_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/ipv6UniRcvdCount",
			.cbs = {
				.get_elem = lib_vrf_peer_ipv6UniRcvdCount_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/count",
			.cbs = {
				.get_next = lib_vrf_peer_count_get_next,
				.get_keys = lib_vrf_peer_count_get_keys,
				.lookup_entry = lib_vrf_peer_count_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/count/afi-safi",
			.cbs = {
				.get_elem = lib_vrf_peer_count_afi_safi_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/count/received",
			.cbs = {
				.get_elem = lib_vrf_peer_count_received_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
