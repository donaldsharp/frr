#include "bgpd/bgpd.h"
#include "northbound.h"
#include "bgpd/bgp_debug.h"
/* prototypes */
const void *lib_peer_get_next(struct nb_cb_get_next_args *args);
int lib_peer_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_peer_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_peer_name_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_status_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_established_transitions_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_inQ_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_outQ_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_txUpdates_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_rxUpdates_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_ipv4UniRcvdCount_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_ipv6UniRcvdCount_get_elem(struct nb_cb_get_elem_args *args);
const void *lib_peer_count_get_next(struct nb_cb_get_next_args *args);
int lib_peer_count_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_peer_count_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_peer_count_afi_safi_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_peer_count_received_get_elem(struct nb_cb_get_elem_args *args);

/*
 * XPath: /frr-bgp-peer:lib/peer
 */
const void *lib_peer_get_next(struct nb_cb_get_next_args *args)
{
        struct bgp *bgp;
        struct peer *peer;
        struct listnode *node, *nnode;
        struct nb_config_entry *config;
        bgp = bgp_get_default();
        if (args->list_entry == NULL) {
                if (bgp) {
                        for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
                                if (peer) {
                                        return peer;
                                }
                        }
                }
        } else {
                struct peer *iter;
                bool next = false;
                peer = (struct peer *)args->list_entry;
                for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, iter)) {
                        if (strcmp(peer->conf_if, iter->conf_if) == 0) {
                                next = true;
                        } else if (next == true) {
                                return iter;
                        }
                }
                return NULL;
        }
        return NULL;
}


int lib_peer_get_keys(struct nb_cb_get_keys_args *args)
{
        args->keys->num = 1;
        if (args->list_entry) {
                struct peer *peer = (struct peer *)args->list_entry;
                if (peer)
                        strlcpy(args->keys->key[0], peer->conf_if,
                                sizeof(args->keys->key[0]));
        }
        return NB_OK;
}

const void *lib_peer_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
        /* TODO: implement me. */
        return NULL;
}

/*        
 *         * XPath: /frr-bgp-peer:lib/peer/name
 *          */     
struct yang_data *lib_peer_name_get_elem(struct nb_cb_get_elem_args *args)
{            
	        /* TODO: implement me. */
	        return NULL;
}   


/*
 * XPath: /frr-bgp-peer:lib/peer/status
 */
struct yang_data *lib_peer_status_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
        if (peer) {
                return yang_data_new_string(
                        args->xpath,
                        lookup_msg(bgp_status_msg, peer->status, NULL));
        }
        return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/established_transitions
 */
struct yang_data *
lib_peer_established_transitions_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
        if (peer) {
                return yang_data_new_uint32(args->xpath, peer->established);
        }
        return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/inQ
 */
struct yang_data *
lib_peer_inQ_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
        if (peer) {
                return yang_data_new_uint32(args->xpath, peer->ibuf->count);
        }
        return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/outQ
 */
struct yang_data *
lib_peer_outQ_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
        if (peer) {
                return yang_data_new_uint32(args->xpath, peer->obuf->count);
        }
        return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/txUpdates
 */
struct yang_data *
lib_peer_txUpdates_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
        if (peer) {
                return yang_data_new_uint32(args->xpath, PEER_TOTAL_TX(peer));
        }
        return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/rxUpdates
 */
struct yang_data *
lib_peer_rxUpdates_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
        if (peer) {
                return yang_data_new_uint32(args->xpath, PEER_TOTAL_RX(peer));
        }
        return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/ipv4UniRcvdCount
 */
struct yang_data *
lib_peer_ipv4UniRcvdCount_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
        if (peer) {
                return yang_data_new_uint32(args->xpath, peer->pcount[AFI_IP][SAFI_UNICAST]);
        }
        return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/ipv6UniRcvdCount
 */
struct yang_data *
lib_peer_ipv6UniRcvdCount_get_elem(struct nb_cb_get_elem_args *args)
{
        struct peer *peer;
        peer = (struct peer *)args->list_entry;
        if (peer) {
                return yang_data_new_uint32(args->xpath, peer->pcount[AFI_IP][SAFI_UNICAST]);
        }
        return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/count
 */
const void *lib_peer_count_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_peer_count_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *lib_peer_count_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/count/afi-safi
 */
struct yang_data *lib_peer_count_afi_safi_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/peer/count/received
 */
struct yang_data *lib_peer_count_received_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/* clang-format off */
const struct frr_yang_module_info frr_bgp_peer_info = {
	.name = "frr-bgp-peer",
	.nodes = {
		{
			.xpath = "/frr-bgp-peer:lib/peer",
			.cbs = {
				.get_next = lib_peer_get_next,
				.get_keys = lib_peer_get_keys,
				.lookup_entry = lib_peer_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/name",
			.cbs = {
				.get_elem = lib_peer_name_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/status",
			.cbs = {
				.get_elem = lib_peer_status_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/established_transitions",
			.cbs = {
				.get_elem = lib_peer_established_transitions_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/inQ",
			.cbs = {
				.get_elem = lib_peer_inQ_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/outQ",
			.cbs = {
				.get_elem = lib_peer_outQ_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/txUpdates",
			.cbs = {
				.get_elem = lib_peer_txUpdates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/rxUpdates",
			.cbs = {
				.get_elem = lib_peer_rxUpdates_get_elem,
			}
		},
                {
                        .xpath = "/frr-bgp-peer:lib/peer/ipv4UniRcvdCount",
                        .cbs = {
                                .get_elem = lib_peer_ipv4UniRcvdCount_get_elem,
                        }
                },
                {
                        .xpath = "/frr-bgp-peer:lib/peer/ipv6UniRcvdCount",
                        .cbs = {
                                .get_elem = lib_peer_ipv6UniRcvdCount_get_elem,
                        }
                },
		{
			.xpath = "/frr-bgp-peer:lib/peer/count",
			.cbs = {
				.get_next = lib_peer_count_get_next,
				.get_keys = lib_peer_count_get_keys,
				.lookup_entry = lib_peer_count_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/count/afi-safi",
			.cbs = {
				.get_elem = lib_peer_count_afi_safi_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/peer/count/received",
			.cbs = {
				.get_elem = lib_peer_count_received_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
