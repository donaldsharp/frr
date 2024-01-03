/*
 * Zebra neighbor table management
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
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
 */

#include <zebra.h>

#include "command.h"
#include "hash.h"
#include "if.h"
#include "jhash.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/interface.h"
#include "zebra/zebra_neigh.h"
#include "zebra/zebra_pbr.h"
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "checksum.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_neigh_throttle.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZNEIGH_INFO, "Zebra neigh table");
DEFINE_MTYPE_STATIC(ZEBRA, ZNEIGH_ENT, "Zebra neigh entry");

static int zebra_neigh_rb_cmp(const struct zebra_neigh_ent *n1,
			      const struct zebra_neigh_ent *n2)
{
	if (n1->ifindex < n2->ifindex)
		return -1;

	if (n1->ifindex > n2->ifindex)
		return 1;

	if (n1->ip.ipa_type < n2->ip.ipa_type)
		return -1;

	if (n1->ip.ipa_type > n2->ip.ipa_type)
		return 1;

	if (n1->ip.ipa_type == AF_INET) {
		if (n1->ip.ipaddr_v4.s_addr < n2->ip.ipaddr_v4.s_addr)
			return -1;

		if (n1->ip.ipaddr_v4.s_addr > n2->ip.ipaddr_v4.s_addr)
			return 1;

		return 0;
	}

	return memcmp(&n1->ip.ipaddr_v6, &n2->ip.ipaddr_v6, IPV6_MAX_BYTELEN);
}
RB_GENERATE(zebra_neigh_rb_head, zebra_neigh_ent, rb_node, zebra_neigh_rb_cmp);

static struct zebra_neigh_ent *zebra_neigh_find(ifindex_t ifindex,
						struct ipaddr *ip)
{
	struct zebra_neigh_ent tmp;

	tmp.ifindex = ifindex;
	memcpy(&tmp.ip, ip, sizeof(*ip));
	return RB_FIND(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, &tmp);
}

static struct zebra_neigh_ent *
zebra_neigh_new(ifindex_t ifindex, struct ipaddr *ip, struct ethaddr *mac)
{
	struct zebra_neigh_ent *n;

	n = XCALLOC(MTYPE_ZNEIGH_ENT, sizeof(struct zebra_neigh_ent));

	memcpy(&n->ip, ip, sizeof(*ip));
	n->ifindex = ifindex;
	if (mac) {
		memcpy(&n->mac, mac, sizeof(*mac));
		n->flags |= ZEBRA_NEIGH_ENT_ACTIVE;
	}

	/* Add to rb_tree */
	if (RB_INSERT(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, n)) {
		XFREE(MTYPE_ZNEIGH_ENT, n);
		return NULL;
	}

	/* Initialise the pbr rule list */
	n->pbr_rule_list = list_new();
	listset_app_node_mem(n->pbr_rule_list);

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh new if %d %pIA %pEA", n->ifindex,
			   &n->ip, &n->mac);

	return n;
}

static void zebra_neigh_pbr_rules_update(struct zebra_neigh_ent *n)
{
	struct zebra_pbr_rule *rule;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(n->pbr_rule_list, node, rule))
		dplane_pbr_rule_update(rule, rule);
}

static void zebra_neigh_free(struct zebra_neigh_ent *n)
{
	if (listcount(n->pbr_rule_list)) {
		/* if rules are still using the neigh mark it as inactive and
		 * update the dataplane
		 */
		if (n->flags & ZEBRA_NEIGH_ENT_ACTIVE) {
			n->flags &= ~ZEBRA_NEIGH_ENT_ACTIVE;
			memset(&n->mac, 0, sizeof(n->mac));
		}
		zebra_neigh_pbr_rules_update(n);
		return;
	}
	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh free if %d %pIA %pEA", n->ifindex,
			   &n->ip, &n->mac);

	/* cleanup resources maintained against the neigh */
	list_delete(&n->pbr_rule_list);

	RB_REMOVE(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, n);

	XFREE(MTYPE_ZNEIGH_ENT, n);
}

/* kernel neigh del */
void zebra_neigh_del(struct interface *ifp, struct ipaddr *ip)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh del if %s/%d %pIA", ifp->name,
			   ifp->ifindex, ip);

	n = zebra_neigh_find(ifp->ifindex, ip);
	if (!n)
		return;
	zebra_neigh_free(n);
}

/* kernel neigh add */
void zebra_neigh_add(struct interface *ifp, struct ipaddr *ip,
		     struct ethaddr *mac)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh add if %s/%d %pIA %pEA", ifp->name,
			   ifp->ifindex, ip, mac);

	n = zebra_neigh_find(ifp->ifindex, ip);
	if (n) {
		if (!memcmp(&n->mac, mac, sizeof(*mac)))
			return;

		memcpy(&n->mac, mac, sizeof(*mac));
		n->flags |= ZEBRA_NEIGH_ENT_ACTIVE;

		/* update rules linked to the neigh */
		zebra_neigh_pbr_rules_update(n);
	} else {
		zebra_neigh_new(ifp->ifindex, ip, mac);
	}
}

void zebra_neigh_deref(struct zebra_pbr_rule *rule)
{
	struct zebra_neigh_ent *n = rule->action.neigh;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh deref if %d %pIA by pbr rule %u",
			   n->ifindex, &n->ip, rule->rule.seq);

	rule->action.neigh = NULL;
	/* remove rule from the list and free if it is inactive */
	list_delete_node(n->pbr_rule_list, &rule->action.neigh_listnode);
	if (!(n->flags & ZEBRA_NEIGH_ENT_ACTIVE))
		zebra_neigh_free(n);
}

/* XXX - this needs to work with evpn's neigh read */
static void zebra_neigh_read_on_first_ref(void)
{
	static bool neigh_read_done;

	if (!neigh_read_done) {
		neigh_read(zebra_ns_lookup(NS_DEFAULT));
		neigh_read_done = true;
	}
}

void zebra_neigh_ref(int ifindex, struct ipaddr *ip,
		     struct zebra_pbr_rule *rule)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh ref if %d %pIA by pbr rule %u", ifindex,
			   ip, rule->rule.seq);

	zebra_neigh_read_on_first_ref();
	n = zebra_neigh_find(ifindex, ip);
	if (!n)
		n = zebra_neigh_new(ifindex, ip, NULL);

	/* link the pbr entry to the neigh */
	if (rule->action.neigh == n)
		return;

	if (rule->action.neigh)
		zebra_neigh_deref(rule);

	rule->action.neigh = n;
	listnode_init(&rule->action.neigh_listnode, rule);
	listnode_add(n->pbr_rule_list, &rule->action.neigh_listnode);
}

static void zebra_neigh_show_one(struct vty *vty, struct zebra_neigh_ent *n)
{
	char mac_buf[ETHER_ADDR_STRLEN];
	char ip_buf[INET6_ADDRSTRLEN];
	struct interface *ifp;

	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					n->ifindex);
	ipaddr2str(&n->ip, ip_buf, sizeof(ip_buf));
	prefix_mac2str(&n->mac, mac_buf, sizeof(mac_buf));
	vty_out(vty, "%-20s %-30s %-18s %u\n", ifp ? ifp->name : "-", ip_buf,
		mac_buf, listcount(n->pbr_rule_list));
}

void zebra_neigh_show(struct vty *vty)
{
	struct zebra_neigh_ent *n;

	vty_out(vty, "%-20s %-30s %-18s %s\n", "Interface", "Neighbor", "MAC",
		"#Rules");
	RB_FOREACH (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree)
		zebra_neigh_show_one(vty, n);
}

void zebra_neigh_init(void)
{
	zneigh_info = XCALLOC(MTYPE_ZNEIGH_INFO, sizeof(*zrouter.neigh_info));
	RB_INIT(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree);
}

void zebra_neigh_terminate(void)
{
	struct zebra_neigh_ent *n, *next;

	if (!zrouter.neigh_info)
		return;

	RB_FOREACH_SAFE (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree,
			 next)
		zebra_neigh_free(n);
	XFREE(MTYPE_ZNEIGH_INFO, zneigh_info);
}

/*
 * In the event the kernel deletes ipv4 link-local neighbor entries created for
 * 5549 support, re-install them.
 * Returns 'true' if it recognizes a 6-to-4 entry.
 */
static bool netlink_handle_5549(uint16_t ndm_state, struct zebra_if *zif,
				struct interface *ifp, struct ipaddr *ip,
				bool handle_failed)
{
	const char ipv4_ll_buf[16] = "169.254.0.1";
	struct in_addr ipv4_ll;
	inet_pton(AF_INET, ipv4_ll_buf, &ipv4_ll);

	if (ip->ipa_type != IPADDR_V4)
		return false;

	if (!zif->v6_2_v4_ll_neigh_entry)
		return false;

	if (ipv4_ll.s_addr != ip->ipaddr_v4.s_addr)
		return false;

	if (handle_failed && ndm_state & NUD_FAILED) {
		zlog_info(
			"Neighbor Entry for %s has entered a failed state, not reinstalling",
			ifp->name);
		return true;
	}

	if_nbr_ipv6ll_to_ipv4ll_neigh_update(ifp, &zif->v6_2_v4_ll_addr6, true);
	return true;
}

/*
 * Helper to send ipv6 ND solicit message
 */
static bool send_nd_helper(const struct ipaddr *addr, struct zebra_ns *zns,
			   struct interface *ifp)
{
	uint8_t buf[200] = {};
	struct ether_header *eth = (struct ether_header *)buf;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)((char *)eth + ETHER_HDR_LEN);
	struct nd_neighbor_advert *ndh =
		(struct nd_neighbor_advert *)((char *)ip6h +
					      sizeof(struct ip6_hdr));
	struct icmp6_hdr *icmp6h = &ndh->nd_na_hdr;
	struct nd_opt_hdr *nd_opt_h =
		(struct nd_opt_hdr *)((char *)ndh +
				      sizeof(struct nd_neighbor_advert));
	char *nd_opt_lladdr = ((char *)nd_opt_h + sizeof(struct nd_opt_hdr));
	char *lladdr = (char *)ifp->hw_addr;
	struct ipv6_ph ph = {};
	uint32_t hlen;
	ssize_t len;
	void *offset;
	struct ipaddr iptemp;
	struct sockaddr_ll sll;

#define ZEBRA_ND_HOPLIMIT 255
#define ZEBRA_ND_SIZE                                                          \
	ETHER_HDR_LEN + sizeof(struct ip6_hdr) +                               \
		sizeof(struct nd_neighbor_advert) +                            \
		sizeof(struct nd_opt_hdr) + ETH_ALEN

	/* Locate source IP address */
	if (!zebra_if_get_source(ifp, addr, &iptemp))
		return false;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: addr %pIA, ifp %s", __func__, addr, ifp->name);

	/*
	 * An IPv6 packet with a multicast destination address DST, consisting
	 * of the sixteen octets DST[1] through DST[16], is transmitted to the
	 * Ethernet multicast address whose first two octets are the value 3333
	 * hexadecimal and whose last four octets are the last four octets of
	 * DST.
	 *    - RFC2464.7
	 *
	 * In this case we are sending to the solicited-node multicast address,
	 * so the last four octets are from the corresponding v6 mcast address,
	 * which in turn are from the target address.
	 */
	eth->ether_dhost[0] = 0x33;
	eth->ether_dhost[1] = 0x33;
	eth->ether_dhost[2] = 0xFF;
	eth->ether_dhost[3] = addr->ipaddr_v6.s6_addr[13];
	eth->ether_dhost[4] = addr->ipaddr_v6.s6_addr[14];
	eth->ether_dhost[5] = addr->ipaddr_v6.s6_addr[15];

	/* Set source Ethernet address to interface link layer address */
	memcpy(eth->ether_shost, lladdr, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_IPV6);

	/* IPv6 Header */
	ip6h->ip6_vfc = 6 << 4;
	ip6h->ip6_plen = htons(sizeof(struct nd_neighbor_advert) +
			       sizeof(struct nd_opt_hdr) + ETH_ALEN);
	ip6h->ip6_nxt = IPPROTO_ICMPV6;
	ip6h->ip6_hlim = ZEBRA_ND_HOPLIMIT;

	/* Source address, found above. */
	memcpy(&ip6h->ip6_src, &iptemp.ipaddr_v6, sizeof(struct in6_addr));

	/* Solicited-node multicast address for the target address */
	ip6h->ip6_dst.s6_addr[0] = 0xFF;
	ip6h->ip6_dst.s6_addr[1] = 0x02;
	ip6h->ip6_dst.s6_addr[11] = 0x01;
	ip6h->ip6_dst.s6_addr[12] = 0xFF;

	ip6h->ip6_dst.s6_addr[13] = addr->ipaddr_v6.s6_addr[13];
	ip6h->ip6_dst.s6_addr[14] = addr->ipaddr_v6.s6_addr[14];
	ip6h->ip6_dst.s6_addr[15] = addr->ipaddr_v6.s6_addr[15];

	/* ICMPv6 Header */
	ndh->nd_na_type = ND_NEIGHBOR_SOLICIT;
	memcpy(&ndh->nd_na_target, &addr->ipaddr_v6, sizeof(struct in6_addr));

	/* NDISC Option header */
	nd_opt_h->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	nd_opt_h->nd_opt_len = 1;
	memcpy(nd_opt_lladdr, lladdr, ETH_ALEN);

	/* Compute checksum */
	hlen = (sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) +
		ETH_ALEN);

	ph.src = ip6h->ip6_src;
	ph.dst = ip6h->ip6_dst;
	ph.ulpl = htonl(hlen);
	ph.next_hdr = IPPROTO_ICMPV6;

	/* Suppress static analysis warnings about accessing icmp6 oob */
	offset = icmp6h;
	icmp6h->icmp6_cksum = in_cksum_with_ph6(&ph, offset, hlen);

	/* Prep and send packet */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = (int)ifp->ifindex;
	sll.sll_halen = ifp->hw_addr_len;
	memcpy(sll.sll_addr, ifp->hw_addr, ETH_ALEN);

	len = sendto(zns->nd_fd, buf, ZEBRA_ND_SIZE, 0, (struct sockaddr *)&sll,
		     sizeof(sll));
	if (len < 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: error sending ND SOLICIT req for %pIA",
				   __func__, addr);
		return false;
	}

	return true;
}

/*
 * Helper to send ipv4 ARP solicit
 */
static bool send_arp_helper(const struct ipaddr *addr, struct zebra_ns *zns,
			    struct interface *ifp)
{
	uint8_t buf[100];
	uint8_t *arp_ptr;
	struct ether_header *eth;
	struct arphdr *arph;
	ssize_t len, alen;
	struct ipaddr iptemp;
	struct sockaddr_ll sll;

	/* Locate source IP address */
	if (!zebra_if_get_source(ifp, addr, &iptemp))
		return false;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: addr %pIA, ifp %s", __func__, addr, ifp->name);

	memset(buf, 0, sizeof(buf));
	memset(&sll, 0, sizeof(sll));

	/* Build Ethernet header */
	eth = (struct ether_header *)buf;

	memset(eth->ether_dhost, 0xFF, ETH_ALEN);
	memcpy(eth->ether_shost, ifp->hw_addr, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_ARP);

	/* Build ARP payload */
	arph = (struct arphdr *)(buf + ETHER_HDR_LEN);

	arph->ar_hrd = htons(ARPHRD_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = ifp->hw_addr_len;
	arph->ar_pln = sizeof(struct in_addr);
	arph->ar_op = htons(ARPOP_REQUEST);

	arp_ptr = (uint8_t *)(arph + 1);

	/* Source MAC: us */
	memcpy(arp_ptr, ifp->hw_addr, ifp->hw_addr_len);
	arp_ptr += ifp->hw_addr_len;

	/* Source IP: us */
	memcpy(arp_ptr, &(iptemp.ipaddr_v4), sizeof(struct in_addr));
	arp_ptr += sizeof(struct in_addr);

	/* TODO -- VRRP uses bcast dest here, but the OS uses zero? */
	/* Dest MAC: zero */
	memset(arp_ptr, 0, ETH_ALEN);
	arp_ptr += ifp->hw_addr_len;

	/* Dest IP, target */
	memcpy(arp_ptr, &addr->ipaddr_v4, sizeof(struct in_addr));
	arp_ptr += sizeof(struct in_addr);

	alen = arp_ptr - buf;

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = ETH_P_ARP;
	sll.sll_ifindex = (int)ifp->ifindex;
	sll.sll_halen = ifp->hw_addr_len;
	memset(sll.sll_addr, 0xFF, ETH_ALEN);

	len = sendto(zns->arp_fd, buf, alen, 0, (struct sockaddr *)&sll,
		     sizeof(sll));
	if (len < 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: error sending ARP req for %pIA",
				   __func__, addr);
		return false;
	}

	return true;
}

/*
 * Handle optional glean throttling. If enabled, we install a blackhole route
 * for each unresolved neighbor entry, and remove that temporary blackhole
 * if the neighbor resolves.
 */
static void netlink_handle_neigh_throttle(int cmd, uint16_t ndm_state,
					  const struct ipaddr *addr,
					  struct zebra_ns *zns,
					  struct interface *ifp)
{
	/*
	 * We may see three different netlink messages:
	 *   NEWNEIGH when an entry is added; maybe resolved or failed.
	 *   DELNEIGH when an entry is removed by the OS
	 *   GETNEIGH if application resolution has been configured (via
	 *   sysctl on linux). in this case, we will attempt to send the
	 *   the first APR or NS request ourselves.
	 */
	if (cmd == RTM_NEWNEIGH) {
		if (ndm_state & NUD_REACHABLE)
			zebra_neigh_throttle_delete(ifp->vrf->vrf_id, addr);
		else if (ndm_state & NUD_FAILED)
			zebra_neigh_throttle_add(ifp, addr, false);

	} else if (cmd == RTM_DELNEIGH) {
		zebra_neigh_throttle_delete(ifp->vrf->vrf_id, addr);

	} else if (cmd == RTM_GETNEIGH) {

		/* If throttling enabled, ARP/ND */
		if (!zebra_neigh_throttle_is_enabled(ifp))
			return;

		/* TODO -- if configured to receive GETNEIGH, ARP/ND always? */

		/* TODO -- only for ethernet interfaces? */

		if (addr->ipa_type == IPADDR_V4)
			send_arp_helper(addr, zns, ifp);
		else
			send_nd_helper(addr, zns, ifp);

		/* Maybe add a delayed throttle entry, instead of waiting
		 * the full OS timeout.
		 */
		zebra_neigh_throttle_add(ifp, addr, true);
	}
}

static int netlink_nbr_entry_state_to_zclient(int nbr_state)
{
	/* an exact match is done between
	 * - netlink neighbor state values: NDM_XXX (see in linux/neighbour.h)
	 * - zclient neighbor state values: ZEBRA_NEIGH_STATE_XXX
	 *  (see in lib/zclient.h)
	 */
	return nbr_state;
}

/*
 * Runs in the Zebra Main thread context.
 * Performs the handling of neigh events which was earlier handled in the
 * netlink_ipneigh_change by dequeuing the ctx and then processing.
 */
void zebra_neigh_dplane_result(struct zebra_dplane_ctx *ctx)
{
	int cmd;
	bool is_ext;
	bool is_router;
	bool dp_static = false;
	bool local_inactive = false;
	struct zebra_if *zif = NULL;
	struct zebra_ns *zns = NULL;
	struct interface *ifp = NULL;
	struct interface *link_if = NULL;
	ns_id_t ns_id = dplane_ctx_get_ns_id(ctx);
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	uint8_t ndm_flags = dplane_ctx_get_neigh_ndm_flags(ctx);
	uint16_t ndm_state = dplane_ctx_get_neigh_ndm_state(ctx);
	uint32_t ext_flags = dplane_ctx_get_neigh_ext_flags(ctx);
	ifindex_t ifindex = dplane_ctx_get_neigh_ifindex(ctx);
	struct ipaddr *ip = dplane_ctx_get_neigh_ipaddr(ctx);
	int l2_len = dplane_ctx_get_neigh_l2_len(ctx);
	void *l2_addr = dplane_ctx_get_neigh_l2_addr(ctx);
	struct ethaddr *mac = dplane_ctx_get_neigh_mac(ctx);
	bool lladdr_present = dplane_ctx_get_neigh_lladdr_present(ctx);

	zns = zebra_ns_lookup(ns_id);
	if (!zns) {
		zlog_err("Where is our namespace?");
		return;
	}

	ifp = if_lookup_by_index_per_ns(zns, ifindex);
	if (!ifp || !ifp->info) {
		zlog_debug("%s ifp or ifp->info is NULL", __func__);
		return;
	}
	zif = (struct zebra_if *)ifp->info;


	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"Dequeuing: Rx %s IF %s(%u) vrf %s(%u) IP %pIA"
			" Process based on Nbr state : %s",
			dplane_op2str(op), ifp->name, ifindex, ifp->vrf->name,
			ifp->vrf->vrf_id, ip,
			(ndm_state & NUD_VALID) ? "Add or Update" : "Delete");

	/* we send link layer information to NHRP client:
	 *  - nlmsg_type = RTM_DELNEIGH|NEWNEIGH|GETNEIGH
	 *  - struct ipaddr ( for DEL and GET)
	 *  - struct ethaddr mac; (for NEW)
	 */
	if (op == DPLANE_OP_NEIGH_GET) {
		cmd = ZEBRA_NHRP_NEIGH_GET;
		/* Handle neighbor throttling */
		netlink_handle_neigh_throttle(RTM_GETNEIGH, ndm_state, ip, zns,
					      ifp);
	} else if (op == DPLANE_OP_NEIGH_DELETE) {
		cmd = ZEBRA_NHRP_NEIGH_REMOVED;
		if (ndm_state & NUD_PERMANENT) {
			/* If kernel deletes our rfc5549 Nbr entry, re-install
			 * it */
			if (netlink_handle_5549(ndm_state, zif, ifp, ip,
						false)) {
				if (IS_ZEBRA_DEBUG_KERNEL)
					zlog_debug(
						"Neighbor Entry Received is a 5549 entry, finished");
				return;
			}
		}

		/* Handle ip neighbor throttling */
		netlink_handle_neigh_throttle(RTM_DELNEIGH, ndm_state, ip, zns,
					      ifp);

	} else if (op == DPLANE_OP_NEIGH_INSTALL) {
		bool handled = false;
		cmd = ZEBRA_NHRP_NEIGH_ADDED;

		if (!(ndm_state & NUD_VALID)) {
			/* If kernel marks our rfc5549 Nbr entry invalid,
			 * re-install it */
			handled = netlink_handle_5549(ndm_state, zif, ifp, ip,
						      true);
		}

		/* Handle ip neighbor throttling */
		if (!handled)
			netlink_handle_neigh_throttle(RTM_NEWNEIGH, ndm_state,
						      ip, zns, ifp);
	} else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: unknown nlmsg type", __func__);
		return;
	}


	if (l2_len == IPV4_MAX_BYTELEN || l2_len == 0) {
		union sockunion link_layer_ipv4;

		if (l2_len) {
			sockunion_family(&link_layer_ipv4) = AF_INET;
			memcpy((void *)sockunion_get_addr(&link_layer_ipv4),
			       l2_addr, l2_len);
		} else
			sockunion_family(&link_layer_ipv4) = AF_UNSPEC;

		zsend_nhrp_neighbor_notify(
			cmd, ifp, ip,
			netlink_nbr_entry_state_to_zclient(ndm_state),
			&link_layer_ipv4);
	}

	if (op == DPLANE_OP_NEIGH_GET)
		return;

	/* The neighbor is present on an SVI. From this, we locate the
	 * underlying bridge because we're only interested in Nbrs on a VxLAN
	 * bridge.
	 * The bridge is located based on the nature of the SVI:
	 *   (a) In the case of a VLAN-aware bridge, the SVI is a L3 VLAN
	 *       interface and is linked to the bridge
	 *   (b) In the case of a VLAN-unaware bridge, the SVI is the bridge
	 *       interface itself
	 */
	if (IS_ZEBRA_IF_VLAN(ifp)) {
		link_if = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
						    zif->link_ifindex);
		if (!link_if) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"Neigh Entry %pIA is Vlan but Link Intf "
					"(idx: %u) is NULL, ignoring",
					ip, zif->link_ifindex);
			return;
		}
	} else if (IS_ZEBRA_IF_BRIDGE(ifp))
		link_if = ifp;
	else {
		link_if = NULL;
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"Neighbor Entry %pIA received on IF %s(%u) is not on "
				"a VLAN or a BRIDGE, ignoring",
				ip, ifp->name, ifindex);
	}

	if (op == DPLANE_OP_NEIGH_INSTALL) {
		if (lladdr_present) {
			if (l2_len != ETH_ALEN) {
				if (IS_ZEBRA_DEBUG_KERNEL)
					zlog_debug(
						"%s IF %s(%u) vrf %s(%u) - LLADDR is not MAC, len %lu",
						dplane_op2str(op), ifp->name,
						ifindex, ifp->vrf->name,
						ifp->vrf->vrf_id,
						(unsigned long)l2_len);
				return;
			}
		}

		is_ext = !!(ndm_flags & NTF_EXT_LEARNED);
		is_router = !!(ndm_flags & NTF_ROUTER);

		if (ext_flags & NTF_E_MH_PEER_SYNC)
			dp_static = true;

		/* If the neighbor state is valid for use, process as an add or
		 * update Else process as a delete.
		 *
		 * Note that the delete handling may result in re-adding the Nbr
		 * if it is a valid "remote" neighbor.
		 */
		if (ndm_state & NUD_VALID) {
			if (zebra_evpn_mh_do_adv_reachable_neigh_only())
				local_inactive =
					!(ndm_state & NUD_LOCAL_ACTIVE);
			else
				/* If EVPN-MH is not enabled we treat STALE
				 * neighbors as locally-active and advertise
				 * them
				 */
				local_inactive = false;

			/* Add local neighbors to the l3 interface database */
			if (is_ext)
				zebra_neigh_del(ifp, ip);
			else
				zebra_neigh_add(ifp, ip, mac);

			if (link_if)
				zebra_vxlan_handle_kernel_neigh_update(
					ifp, link_if, ip, mac, ndm_state,
					is_ext, is_router, local_inactive,
					dp_static);

			return;
		}

		/* Process the delete - it may result in re-adding the neighbor
		 * if it is a valid "remote" neighbor.
		 */
		zebra_neigh_del(ifp, ip);
		if (link_if)
			zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, ip);
		return;
	}
}
