#ifndef _FRR_BGP_PEER_NB_H_
#define _FRR_BGP_PEER_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_bgp_peer_info;

struct yang_data *lib_peer_status_get_elem(struct nb_cb_get_elem_args *args);
void bgpd_peer_notify_event(struct peer *peer);

#ifdef __cplusplus
}
#endif
#endif
