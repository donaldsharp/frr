#ifndef _FRR_BGP_PEER_NB_H_
#define _FRR_BGP_PEER_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

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
struct yang_data *
lib_vrf_peer_in_queue_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_out_queue_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_tx_updates_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_rx_updates_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_ipv4_unicast_rcvd_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_peer_ipv6_unicast_rcvd_get_elem(struct nb_cb_get_elem_args *args);
extern const struct frr_yang_module_info frr_bgp_peer_info;

struct yang_data *lib_peer_status_get_elem(struct nb_cb_get_elem_args *args);
void bgpd_peer_notify_event(struct peer *peer);

#ifdef __cplusplus
}
#endif
#endif
