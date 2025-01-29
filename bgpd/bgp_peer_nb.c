#include "northbound.h"
#include "lib/vrf.h"
#include "bgp_peer_nb.h"
#include "lib/debug.h"

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
	DEBUGD(&nb_dbg_events, "Vrf %s", vrfp->name);
	strlcpy(args->keys->key[0], vrfp->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

const void *lib_vrf_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *vrfname = args->keys->key[0];
	struct vrf *vrf = vrf_lookup_by_name(vrfname);
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
	struct vrf *vrfp = (struct vrf *)args->parent_list_entry;

	if (!vrfp) {
		DEBUGD(&nb_dbg_events, "VRF NULL in parent list");
		return NULL;
	}
	if (!vrfp->vrf_id)
	    bgp = bgp_get_default();
	else
	    bgp = bgp_lookup_by_vrf_id(vrfp->vrf_id);
	if (!bgp || !bgp->peer) {
	    DEBUGD(&nb_dbg_events, "No BGP peers in vrf %d", vrfp->vrf_id);
	    return NULL;
	}
        if (args->list_entry == NULL) {
		if (bgp)
			return listnode_head(bgp->peer);
	} else {
		peer = (struct peer *)args->list_entry;
		if (!peer)
			return NULL;
		node = listnode_lookup(bgp->peer, peer);
		nnode = listnextnode(node);
		if (nnode && nnode->data)
			return nnode->data;
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
			else if (peer->host)
				strlcpy(args->keys->key[0], peer->host,
					sizeof(args->keys->key[0]));
			else {
				char buf[INET6_ADDRSTRLEN];
				if (peer->su.sa.sa_family == AF_INET) {
					inet_ntop(AF_INET,
						  &peer->su.sin.sin_addr, buf,
						  sizeof(buf));
					strlcpy(args->keys->key[0], buf,
						sizeof(args->keys->key[0]));
				} else if (peer->su.sa.sa_family == AF_INET6) {
					inet_ntop(AF_INET6,
						  &peer->su.sin6.sin6_addr, buf,
						  sizeof(buf));
					strlcpy(args->keys->key[0], buf,
						sizeof(args->keys->key[0]));
				}
			}
		}
		DEBUGD(&nb_dbg_events, "Peer name %s", args->keys->key[0]);
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
 * XPath: /frr-bgp-peer:lib/vrf/peer/established-transitions
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
 * XPath: /frr-bgp-peer:lib/vrf/peer/in-queue
 */
struct yang_data *
lib_vrf_peer_in_queue_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath, peer->ibuf->count);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/out-queue
 */
struct yang_data *
lib_vrf_peer_out_queue_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath, peer->obuf->count);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/tx-updates
 */
struct yang_data *
lib_vrf_peer_tx_updates_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	int update_out = 0;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	update_out =
		atomic_load_explicit(&peer->update_out, memory_order_relaxed);
	return yang_data_new_uint32(args->xpath, update_out);
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/rx-updates
 */
struct yang_data *
lib_vrf_peer_rx_updates_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	int update_in = 0;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	update_in =
		atomic_load_explicit(&peer->update_in, memory_order_relaxed);
	return yang_data_new_uint32(args->xpath, update_in);
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/ipv4-unicast-rcvd
 */
struct yang_data *
lib_vrf_peer_ipv4_unicast_rcvd_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath,
					    peer->pcount[AFI_IP][SAFI_UNICAST]);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/ipv6-unicast-rcvd
 */
struct yang_data *
lib_vrf_peer_ipv6_unicast_rcvd_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(
			args->xpath, peer->pcount[AFI_IP6][SAFI_UNICAST]);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/l2vpn-evpn-rcvd
 */
struct yang_data *
lib_vrf_peer_l2vpn_evpn_rcvd_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath,
					    peer->pcount[AFI_L2VPN][SAFI_EVPN]);
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
			.xpath = "/frr-bgp-peer:lib/vrf/peer/established-transitions",
			.cbs = {
				.get_elem = lib_vrf_peer_established_transitions_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/in-queue",
			.cbs = {
				.get_elem = lib_vrf_peer_in_queue_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/out-queue",
			.cbs = {
				.get_elem = lib_vrf_peer_out_queue_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/tx-updates",
			.cbs = {
				.get_elem = lib_vrf_peer_tx_updates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/rx-updates",
			.cbs = {
				.get_elem = lib_vrf_peer_rx_updates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/ipv4-unicast-rcvd",
			.cbs = {
				.get_elem = lib_vrf_peer_ipv4_unicast_rcvd_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/ipv6-unicast-rcvd",
			.cbs = {
				.get_elem = lib_vrf_peer_ipv6_unicast_rcvd_get_elem,
			}
		},
                {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/l2vpn-evpn-rcvd",
                        .cbs = {
                                .get_elem = lib_vrf_peer_l2vpn_evpn_rcvd_get_elem,
                        }
                },
		{
			.xpath = NULL,
		},
	}
};
