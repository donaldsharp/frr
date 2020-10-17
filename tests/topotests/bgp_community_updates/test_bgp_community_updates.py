#!/usr/bin/env python

#
# bgp_aggregate-address_route-map.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
bgp_aggregate-address_route-map.py:

Test if works the following commands:
router bgp 65031
  address-family ipv4 unicast
    aggregate-address 192.168.255.0/24 route-map aggr-rmap

route-map aggr-rmap permit 10
  set metric 123
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo


#                      --y2--
#                     /  |   \
#  c1 ----- x1 ---- y1   |    z1
#                     \  |   /
#                      --y3--

class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)

        tgen.add_router("z1")
        tgen.add_router("y1")
        tgen.add_router("y2")
        tgen.add_router("y3")
        tgen.add_router("x1")
        tgen.add_router("c1")

        # 10.0.1.0/24
        # c1-eth0
        # x1-eth0
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["c1"])
        switch.add_link(tgen.gears["x1"])

        # 10.0.2.0/24
        # x1-eth1
        # y1-eth0
        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["x1"])
        switch.add_link(tgen.gears["y1"])

        # 10.0.3.0/24
        # y1-eth1
        # y2-eth0
        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["y1"])
        switch.add_link(tgen.gears["y2"])

        # 10.0.4.0/24
        # y1-eth2
        # y3-eth0
        switch = tgen.add_switch("s4")
        switch.add_link(tgen.gears["y1"])
        switch.add_link(tgen.gears["y3"])

        # 10.0.5.0/24
        # y2-eth1
        # y3-eth1
        switch = tgen.add_switch("s5")
        switch.add_link(tgen.gears["y2"])
        switch.add_link(tgen.gears["y3"])

        # 10.0.6.0/24
        # y2-eth2
        # z1-eth0
        switch = tgen.add_switch("s6")
        switch.add_link(tgen.gears["y2"])
        switch.add_link(tgen.gears["z1"])

        # 10.0.7.0/24
        # y3-eth2
        # z1-eth1
        switch = tgen.add_switch("s7")
        switch.add_link(tgen.gears["y3"])
        switch.add_link(tgen.gears["z1"])

def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_EIGRP, os.path.join(CWD, "{}/eigrpd.conf".format(rname)))

    tgen.start_router()
    tgen.mininet_cli()

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_maximum_prefix_invalid():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 3}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_aggregate_address_has_metric(router):
        output = json.loads(router.vtysh_cmd("show ip bgp 172.16.255.0/24 json"))
        expected = {"paths": [{"metric": 123}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, router)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, 'Failed to see bgp convergence in "{}"'.format(router)

    test_func = functools.partial(_bgp_aggregate_address_has_metric, router)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert (
        result is None
    ), 'Failed to see applied metric for aggregated prefix in "{}"'.format(router)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
