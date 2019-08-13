/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "linklist.h"
#include "if.h"
#include "hash.h"
#include "jhash.h"

#include "pimd.h"
#include "pim_oil.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_time.h"
#include "pim_vxlan.h"

static void pim_channel_update_mute(struct channel_oil *c_oil);

char *pim_channel_oil_dump(struct channel_oil *c_oil, char *buf, size_t size)
{
	struct interface *ifp;
	char *out;
	struct prefix_sg sg;
	int i;

	sg.src = c_oil->oil.mfcc_origin;
	sg.grp = c_oil->oil.mfcc_mcastgrp;
	ifp = pim_if_find_by_vif_index(c_oil->pim, c_oil->oil.mfcc_parent);
	snprintf(buf, size, "%s IIF: %s, OIFS: ", pim_str_sg_dump(&sg),
		 ifp ? ifp->name : "(?)");

	out = buf + strlen(buf);
	for (i = 0; i < MAXVIFS; i++) {
		if (c_oil->oil.mfcc_ttls[i] != 0) {
			ifp = pim_if_find_by_vif_index(c_oil->pim, i);
			snprintf(out, buf + size - out, "%s ",
				 ifp ? ifp->name : "(?)");
			out += strlen(out);
		}
	}

	return buf;
}

static int pim_channel_oil_compare(struct channel_oil *c1,
				   struct channel_oil *c2)
{
	if (ntohl(c1->oil.mfcc_mcastgrp.s_addr)
	    < ntohl(c2->oil.mfcc_mcastgrp.s_addr))
		return -1;

	if (ntohl(c1->oil.mfcc_mcastgrp.s_addr)
	    > ntohl(c2->oil.mfcc_mcastgrp.s_addr))
		return 1;

	if (ntohl(c1->oil.mfcc_origin.s_addr)
	    < ntohl(c2->oil.mfcc_origin.s_addr))
		return -1;

	if (ntohl(c1->oil.mfcc_origin.s_addr)
	    > ntohl(c2->oil.mfcc_origin.s_addr))
		return 1;

	return 0;
}

static bool pim_oil_equal(const void *arg1, const void *arg2)
{
	const struct channel_oil *c1 = (const struct channel_oil *)arg1;
	const struct channel_oil *c2 = (const struct channel_oil *)arg2;

	if ((c1->oil.mfcc_mcastgrp.s_addr == c2->oil.mfcc_mcastgrp.s_addr)
	    && (c1->oil.mfcc_origin.s_addr == c2->oil.mfcc_origin.s_addr))
		return true;

	return false;
}

static unsigned int pim_oil_hash_key(const void *arg)
{
	const struct channel_oil *oil = arg;

	return jhash_2words(oil->oil.mfcc_mcastgrp.s_addr,
			    oil->oil.mfcc_origin.s_addr, 0);
}

void pim_oil_init(struct pim_instance *pim)
{
	char hash_name[64];

	snprintf(hash_name, 64, "PIM %s Oil Hash", pim->vrf->name);
	pim->channel_oil_hash = hash_create_size(8192, pim_oil_hash_key,
						 pim_oil_equal, hash_name);

	pim->channel_oil_list = list_new();
	pim->channel_oil_list->del = (void (*)(void *))pim_channel_oil_free;
	pim->channel_oil_list->cmp =
		(int (*)(void *, void *))pim_channel_oil_compare;
}

void pim_oil_terminate(struct pim_instance *pim)
{
	if (pim->channel_oil_list)
		list_delete(&pim->channel_oil_list);

	if (pim->channel_oil_hash)
		hash_free(pim->channel_oil_hash);
	pim->channel_oil_hash = NULL;
}

void pim_channel_oil_free(struct channel_oil *c_oil)
{
	XFREE(MTYPE_PIM_CHANNEL_OIL, c_oil);
}

struct channel_oil *pim_find_channel_oil(struct pim_instance *pim,
					 struct prefix_sg *sg)
{
	struct channel_oil *c_oil = NULL;
	struct channel_oil lookup;

	lookup.oil.mfcc_mcastgrp = sg->grp;
	lookup.oil.mfcc_origin = sg->src;

	c_oil = hash_lookup(pim->channel_oil_hash, &lookup);

	return c_oil;
}

struct channel_oil *pim_channel_oil_add(struct pim_instance *pim,
					struct prefix_sg *sg,
					const char *caller)
{
	struct channel_oil *c_oil;

	c_oil = pim_find_channel_oil(pim, sg);
	if (c_oil) {
		++c_oil->oil_ref_count;
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s(%s): c_oil %s ref count %d increment",
					__func__, caller, pim_str_sg_dump(sg),
					c_oil->oil_ref_count);
		if (!c_oil->up) {
			/* channel might be present prior to upstream */
			c_oil->up = pim_upstream_find(
					pim, sg);
			/* if the upstream entry is being anchored to an
			 * already existing channel OIL we need to re-evaluate
			 * the "Mute" state on AA OIFs
			 */
			pim_channel_update_mute(c_oil);
		}
		/* check if the IIF has changed
		 * XXX - is this really needed
		 */
		pim_upstream_mroute_iif_update(c_oil, __func__);
		return c_oil;
	}

	c_oil = XCALLOC(MTYPE_PIM_CHANNEL_OIL, sizeof(*c_oil));

	c_oil->oil.mfcc_mcastgrp = sg->grp;
	c_oil->oil.mfcc_origin = sg->src;
	c_oil = hash_get(pim->channel_oil_hash, c_oil, hash_alloc_intern);

	c_oil->oil.mfcc_parent = MAXVIFS;
	c_oil->oil_ref_count = 1;
	c_oil->installed = 0;
	c_oil->up = pim_upstream_find(pim, sg);
	c_oil->pim = pim;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s(%s): c_oil %s add",
				__func__, caller, pim_str_sg_dump(sg));
	listnode_add_sort(pim->channel_oil_list, c_oil);

	return c_oil;
}

struct channel_oil *pim_channel_oil_del(struct channel_oil *c_oil)
{
	--c_oil->oil_ref_count;

	if (c_oil->oil_ref_count < 1) {
		/*
		 * notice that listnode_delete() can't be moved
		 * into pim_channel_oil_free() because the later is
		 * called by list_delete_all_node()
		 */
		c_oil->up = NULL;
		listnode_delete(c_oil->pim->channel_oil_list, c_oil);
		hash_release(c_oil->pim->channel_oil_hash, c_oil);

		pim_channel_oil_free(c_oil);
		return NULL;
	}

	return c_oil;
}

void pim_channel_oil_upstream_deref(struct channel_oil *c_oil)
{
	/* The upstream entry associated with a channel_oil is abt to be
	 * deleted. If the channel_oil is kept around because of other
	 * references we need to remove upstream based states out of it.
	 */
	c_oil = pim_channel_oil_del(c_oil);
	if (c_oil) {
		/* note: here we assume that c_oil->up has already been
		 * cleared
		 */
		pim_channel_update_mute(c_oil);
	}
}

int pim_channel_del_oif(struct channel_oil *channel_oil, struct interface *oif,
			uint32_t proto_mask, const char *caller)
{
	struct pim_interface *pim_ifp;

	zassert(channel_oil);
	zassert(oif);

	pim_ifp = oif->info;

	/*
	 * Don't do anything if we've been asked to remove a source
	 * that is not actually on it.
	 */
	if (!(channel_oil->oif_flags[pim_ifp->mroute_vif_index] & proto_mask)) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: no existing protocol mask %u(%u) for requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, proto_mask,
				channel_oil
					->oif_flags[pim_ifp->mroute_vif_index],
				oif->name, pim_ifp->mroute_vif_index,
				channel_oil->oil
					.mfcc_ttls[pim_ifp->mroute_vif_index],
				source_str, group_str);
		}
		return 0;
	}

	channel_oil->oif_flags[pim_ifp->mroute_vif_index] &= ~proto_mask;

	if (channel_oil->oif_flags[pim_ifp->mroute_vif_index] &
			PIM_OIF_FLAG_PROTO_ANY) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: other protocol masks remain for requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, oif->name,
				pim_ifp->mroute_vif_index,
				channel_oil->oil
					.mfcc_ttls[pim_ifp->mroute_vif_index],
				source_str, group_str);
		}
		return 0;
	}

	channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index] = 0;
	/* clear mute; will be re-evaluated when the OIF becomes valid again */
	channel_oil->oif_flags[pim_ifp->mroute_vif_index] &= ~PIM_OIF_FLAG_MUTE;

	if (pim_upstream_mroute_add(channel_oil, __PRETTY_FUNCTION__)) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: could not remove output interface %s (vif_index=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, oif->name,
				pim_ifp->mroute_vif_index, source_str,
				group_str);
		}
		return -1;
	}

	--channel_oil->oil_size;

	if (PIM_DEBUG_MROUTE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", channel_oil->oil.mfcc_mcastgrp,
			       group_str, sizeof(group_str));
		pim_inet4_dump("<source?>", channel_oil->oil.mfcc_origin,
			       source_str, sizeof(source_str));
		zlog_debug(
			"%s(%s): (S,G)=(%s,%s): proto_mask=%u IIF:%d OIF=%s vif_index=%d",
			__PRETTY_FUNCTION__, caller, source_str, group_str,
			proto_mask, channel_oil->oil.mfcc_parent, oif->name,
			pim_ifp->mroute_vif_index);
	}

	return 0;
}


static bool pim_channel_eval_oif_mute(struct channel_oil *c_oil,
		struct pim_interface *pim_ifp)
{
	struct pim_interface *pim_reg_ifp;
	struct pim_interface *vxlan_ifp;
	bool do_mute = false;
	struct pim_instance *pim = c_oil->pim;

	if (!c_oil->up)
		return do_mute;

	pim_reg_ifp = pim->regiface->info;
	if (pim_ifp == pim_reg_ifp) {
		/* suppress pimreg in the OIL if the mroute is not supposed to
		 * trigger register encapsulated data
		 */
		if (PIM_UPSTREAM_FLAG_TEST_NO_PIMREG_DATA(c_oil->up->flags))
			do_mute = true;

		return do_mute;
	}

	vxlan_ifp = pim_vxlan_get_term_ifp(pim);
	if (pim_ifp == vxlan_ifp) {
		/* 1. vxlan termination device must never be added to the
		 * origination mroute (and that can actually happen because
		 * of XG inheritance from the termination mroute) otherwise
		 * traffic will end up looping.
		 * PS: This check has also been extended to non-orig mroutes
		 * that have a local SIP as such mroutes can move back and
		 * forth between orig<=>non-orig type.
		 * 2. vxlan termination device should be removed from the non-DF
		 * to prevent duplicates to the overlay rxer
		 */
		if (PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(c_oil->up->flags) ||
			PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(c_oil->up->flags) ||
			pim_vxlan_is_local_sip(c_oil->up))
			do_mute = true;

		return do_mute;
	}

	return do_mute;
}

void pim_channel_update_oif_mute(struct channel_oil *c_oil,
		struct pim_interface *pim_ifp)
{
	bool old_mute;
	bool new_mute;

	/* If pim_ifp is not a part of the OIL there is nothing to do */
	if (!c_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index])
		return;

	old_mute = !!(c_oil->oif_flags[pim_ifp->mroute_vif_index] &
			PIM_OIF_FLAG_MUTE);
	new_mute = pim_channel_eval_oif_mute(c_oil, pim_ifp);
	if (old_mute == new_mute)
		return;

	if (new_mute)
		c_oil->oif_flags[pim_ifp->mroute_vif_index] |=
			PIM_OIF_FLAG_MUTE;
	else
		c_oil->oif_flags[pim_ifp->mroute_vif_index] &=
			~PIM_OIF_FLAG_MUTE;

	pim_upstream_mroute_add(c_oil, __PRETTY_FUNCTION__);
}

/* pim_upstream has been set or cleared on the c_oil. re-eval mute state
 * on all existing OIFs
 */
static void pim_channel_update_mute(struct channel_oil *c_oil)
{
	struct pim_interface *pim_reg_ifp;
	struct pim_interface *vxlan_ifp;

	pim_reg_ifp = c_oil->pim->regiface->info;
	if (pim_reg_ifp)
		pim_channel_update_oif_mute(c_oil, pim_reg_ifp);
	vxlan_ifp = pim_vxlan_get_term_ifp(c_oil->pim);
	if (vxlan_ifp)
		pim_channel_update_oif_mute(c_oil, vxlan_ifp);
}

int pim_channel_add_oif(struct channel_oil *channel_oil, struct interface *oif,
			uint32_t proto_mask, const char *caller)
{
	struct pim_interface *pim_ifp;
	int old_ttl;
	bool allow_iif_in_oil = false;

	/*
	 * If we've gotten here we've gone bad, but let's
	 * not take down pim
	 */
	if (!channel_oil) {
		zlog_warn("Attempt to Add OIF for non-existent channel oil");
		return -1;
	}

	pim_ifp = oif->info;

#ifdef PIM_ENFORCE_LOOPFREE_MFC
	/*
	  Prevent creating MFC entry with OIF=IIF.

	  This is a protection against implementation mistakes.

	  PIM protocol implicitely ensures loopfree multicast topology.

	  IGMP must be protected against adding looped MFC entries created
	  by both source and receiver attached to the same interface. See
	  TODO T22.
	  We shall allow igmp to create upstream when it is DR for the intf.
	  Assume RP reachable via non DR.
	*/
	if ((channel_oil->up &&
	    PIM_UPSTREAM_FLAG_TEST_ALLOW_IIF_IN_OIL(channel_oil->up->flags)) ||
	    ((proto_mask == PIM_OIF_FLAG_PROTO_IGMP) && PIM_I_am_DR(pim_ifp))) {
		allow_iif_in_oil = true;
	}

	if (!allow_iif_in_oil &&
		pim_ifp->mroute_vif_index == channel_oil->oil.mfcc_parent) {
		channel_oil->oil_inherited_rescan = 1;
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: refusing protocol mask %u request for IIF=OIF=%s (vif_index=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, proto_mask,
				oif->name, pim_ifp->mroute_vif_index,
				source_str, group_str);
		}
		return -2;
	}
#endif

	/* Prevent single protocol from subscribing same interface to
	   channel (S,G) multiple times */
	if (channel_oil->oif_flags[pim_ifp->mroute_vif_index] & proto_mask) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: existing protocol mask %u requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, proto_mask,
				oif->name, pim_ifp->mroute_vif_index,
				channel_oil->oil
					.mfcc_ttls[pim_ifp->mroute_vif_index],
				source_str, group_str);
		}
		return -3;
	}

	/* Allow other protocol to request subscription of same interface to
	 * channel (S,G), we need to note this information
	 */
	if (channel_oil->oif_flags[pim_ifp->mroute_vif_index]
	    & PIM_OIF_FLAG_PROTO_ANY) {

		/* Updating time here is not required as this time has to
		 * indicate when the interface is added
		 */

		channel_oil->oif_flags[pim_ifp->mroute_vif_index] |= proto_mask;
		/* Check the OIF really exists before returning, and only log
		   warning otherwise */
		if (channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index] < 1) {
			{
				char group_str[INET_ADDRSTRLEN];
				char source_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<group?>",
					       channel_oil->oil.mfcc_mcastgrp,
					       group_str, sizeof(group_str));
				pim_inet4_dump("<source?>",
					       channel_oil->oil.mfcc_origin,
					       source_str, sizeof(source_str));
				zlog_warn(
					"%s %s: new protocol mask %u requested nonexistent OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%s,%s)",
					__FILE__, __PRETTY_FUNCTION__,
					proto_mask, oif->name,
					pim_ifp->mroute_vif_index,
					channel_oil->oil.mfcc_ttls
						[pim_ifp->mroute_vif_index],
					source_str, group_str);
			}
		}

		return 0;
	}

	old_ttl = channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index];

	if (old_ttl > 0) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: interface %s (vif_index=%d) is existing output for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, oif->name,
				pim_ifp->mroute_vif_index, source_str,
				group_str);
		}
		return -4;
	}

	channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index] =
		PIM_MROUTE_MIN_TTL;

	/* Some OIFs are held in a muted state i.e. the PIM state machine
	 * decided to include the OIF but additional status check such as
	 * MLAG DF role prevent it from being activated for traffic
	 * forwarding.
	 */
	if (pim_channel_eval_oif_mute(channel_oil, pim_ifp))
		channel_oil->oif_flags[pim_ifp->mroute_vif_index] |=
			PIM_OIF_FLAG_MUTE;
	else
		channel_oil->oif_flags[pim_ifp->mroute_vif_index] &=
			~PIM_OIF_FLAG_MUTE;

	/* channel_oil->oil.mfcc_parent != MAXVIFS indicate this entry is not
	 * valid to get installed in kernel.
	 */
	if (channel_oil->oil.mfcc_parent != MAXVIFS) {
		if (pim_upstream_mroute_add(channel_oil, __PRETTY_FUNCTION__)) {
			if (PIM_DEBUG_MROUTE) {
				char group_str[INET_ADDRSTRLEN];
				char source_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<group?>",
				      channel_oil->oil.mfcc_mcastgrp,
				      group_str, sizeof(group_str));
				pim_inet4_dump("<source?>",
				      channel_oil->oil.mfcc_origin, source_str,
				      sizeof(source_str));
				zlog_debug(
				    "%s %s: could not add output interface %s (vif_index=%d) for channel (S,G)=(%s,%s)",
				    __FILE__, __PRETTY_FUNCTION__, oif->name,
				    pim_ifp->mroute_vif_index, source_str,
				    group_str);
			}

			channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index]
				= old_ttl;
			return -5;
		}
	}

	channel_oil->oif_creation[pim_ifp->mroute_vif_index] =
		pim_time_monotonic_sec();
	++channel_oil->oil_size;
	channel_oil->oif_flags[pim_ifp->mroute_vif_index] |= proto_mask;

	if (PIM_DEBUG_MROUTE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", channel_oil->oil.mfcc_mcastgrp,
			       group_str, sizeof(group_str));
		pim_inet4_dump("<source?>", channel_oil->oil.mfcc_origin,
			       source_str, sizeof(source_str));
		zlog_debug(
			"%s(%s): (S,G)=(%s,%s): proto_mask=%u OIF=%s vif_index=%d: DONE",
			__PRETTY_FUNCTION__, caller, source_str, group_str,
			proto_mask, oif->name, pim_ifp->mroute_vif_index);
	}

	return 0;
}

int pim_channel_oil_empty(struct channel_oil *c_oil)
{
	static uint32_t zero[MAXVIFS];
	static int inited = 0;

	if (!c_oil)
		return 1;
	/*
	 * Not sure that this is necessary, but I would rather ensure
	 * that this works.
	 */
	if (!inited) {
		memset(&zero, 0, sizeof(uint32_t) * MAXVIFS);
		inited = 1;
	}

	return !memcmp(c_oil->oil.mfcc_ttls, zero, MAXVIFS * sizeof(uint32_t));
}
