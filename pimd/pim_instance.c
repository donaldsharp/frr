/*
 * PIM for FRR - PIM Instance
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Donald Sharp
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#include <zebra.h>

#include "hash.h"
#include "vrf.h"

#include "pimd.h"
#include "pim_ssm.h"
#include "pim_rpf.h"
#include "pim_rp.h"
#include "pim_mroute.h"
#include "pim_oil.h"
#include "pim_static.h"

static void
pim_instance_terminate (struct pim_instance *pim)
{
  /* Traverse and cleanup rpf_hash */
  if (pim->rpf_hash)
    {
      hash_clean (pim->rpf_hash, (void *) pim_rp_list_hash_clean);
      hash_free (pim->rpf_hash);
      pim->rpf_hash = NULL;
    }

  if (pim->ssm_info)
    {
      pim_ssm_terminate (pim->ssm_info);
      pim->ssm_info = NULL;
    }

  if (pim->static_routes)
    list_free(pim->static_routes);

  pim_rp_free (pim);

  pim_upstream_terminate (pim);

  pim_oil_terminate (pim);

  pim_if_terminate (pim);

  XFREE (MTYPE_PIM_PIM_INSTANCE, pimg);
}

static struct pim_instance *
pim_instance_init (struct vrf *vrf)
{
  struct pim_instance *pim;

  pim = XCALLOC (MTYPE_PIM_PIM_INSTANCE, sizeof (struct pim_instance));
  if (!pim)
    return NULL;

  pim_if_init (pim);

  pim->vrf_id = vrf->vrf_id;
  pim->vrf = vrf;

  pim->spt.switchover = PIM_SPT_IMMEDIATE;
  pim->spt.plist = NULL;

  pim->rpf_hash = hash_create_size (256, pim_rpf_hash_key, pim_rpf_equal);

  if (PIM_DEBUG_ZEBRA)
    zlog_debug ("%s: NHT rpf hash init ", __PRETTY_FUNCTION__);

  pim->ssm_info = pim_ssm_init ();
  if (!pim->ssm_info) {
    pim_instance_terminate (pim);
    return NULL;
  }

  pim->static_routes = list_new ();
  if (!pim->static_routes) {
    zlog_err("%s %s: failure: static_routes=list_new()",
             __FILE__, __PRETTY_FUNCTION__);
    pim_instance_terminate (pim);
    return NULL;
  }
  pim->static_routes->del = (void (*)(void *))pim_static_route_free;

  pim->send_v6_secondary = 1;

  if (vrf->vrf_id == VRF_DEFAULT)
    pimg = pim;

  pim_mroute_socket_enable (pim);

  pim_rp_init (pim);

  pim_oil_init (pim);

  pim_upstream_init (pim);

  return pim;
}

struct pim_instance *
pim_get_pim_instance (vrf_id_t vrf_id)
{
  struct vrf *vrf = vrf_lookup_by_id (vrf_id);

  if (vrf)
    return vrf->info;

  return NULL;
}

static int
pim_vrf_new (struct vrf *vrf)
{
  zlog_debug ("VRF Created: %s(%d)", vrf->name, vrf->vrf_id);
  return 0;
}

static int
pim_vrf_delete (struct vrf *vrf)
{
  zlog_debug ("VRF Deletion: %s(%d)", vrf->name, vrf->vrf_id);
  return 0;
}

static int
pim_vrf_enable (struct vrf *vrf)
{
  struct pim_instance *pim;

  zlog_debug ("%s: for %s", __PRETTY_FUNCTION__, vrf->name);
  pim = pim_instance_init (vrf);
  if (pim == NULL)
    {
      zlog_err ("%s %s: pim class init failure ", __FILE__,
                __PRETTY_FUNCTION__);
      /*
       * We will crash and burn otherwise
       */
      exit(1);
    }

  vrf->info = (void *)pim;

  if (vrf->vrf_id == VRF_DEFAULT)
    pimg = pim;

  return 0;
}

static int
pim_vrf_disable (struct vrf *vrf)
{
  pim_instance_terminate ((struct pim_instance *)vrf->info);

  /* Note: This is a callback, the VRF will be deleted by the caller. */
  return 0;
}

void
pim_vrf_init (void)
{
  vrf_init (pim_vrf_new,
            pim_vrf_enable,
            pim_vrf_disable,
            pim_vrf_delete);
}

void
pim_vrf_terminate (void)
{
  vrf_terminate ();
}
