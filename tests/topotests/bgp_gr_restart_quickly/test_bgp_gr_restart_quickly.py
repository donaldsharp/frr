#!/usr/bin/env python

#
# test_bgp_gr_restart_quickly.py
#
# Copyright (c) 2022 by
# Nvidia Inc.
# Donald Sharp
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
test_bgp_gr_restart_quickly - Tests a GR situation

"""

import os
import re
import sys
import pytest
import json

pytestmark = [pytest.mark.bgpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    kill_router_daemons,
    start_router_daemons
    )
# Required to instantiate the topology builder class.

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # On main router
    # First switch is for a dummy interface (for local network)
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])

    # Switches for BGP
    # switch 2 switch is for connection to BGP router
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # switch 4 is stub on remote BGP router
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["r3"])

    # switch 3 is between BGP routers
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(30, "Waiting for BGP convergence")

    #assert False, "hi hi hi"
    r3 = tgen.gears["r3"]
    r3.cmd_raises("/usr/sbin/ip6tables -I INPUT -p tcp --sport 179 -j DROP")
    r3.cmd_raises("/usr/sbin/ip6tables -I INPUT -p tcp --dport 179 -j DROP")
    r3.cmd_raises("/usr/sbin/ip6tables -I OUTPUT -p tcp --sport 179 -j DROP")
    r3.cmd_raises("/usr/sbin/ip6tables -I OUTPUT -p tcp --dport 179 -j DROP")
    kill_router_daemons(tgen, "r2", ["bgpd"])
    topotest.sleep(1, "Sleeping 1 second and restarting bgp")
    start_router_daemons(tgen, "r2", ["bgpd"])
    assert False, "HI HI HI"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

#
# Auxiliary Functions
#
