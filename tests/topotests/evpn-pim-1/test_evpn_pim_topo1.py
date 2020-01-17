#!/usr/bin/env python

#
# test_evpn-pim_topo1.py
#
# Copyright (c) 2017 by
# Cumulus Networks, Inc.
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
test_evpn_pim_topo1.py: Testing evpn-pim

"""

import os
import re
import sys
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

#####################################################
##
##   Network Topology Definition
##
#####################################################

class NetworkTopo(Topo):
    "evpn-pim Topology 1"

    def build(self, **_opts):
        "Build function"

        tgen = get_topogen(self)

        tgen.add_router('spine')
        tgen.add_router('leaf1')
        tgen.add_router('leaf2')
        tgen.add_router('host1')
        tgen.add_router('host2')
                    

        # On main router
        # First switch is for a dummy interface (for local network)
        # spine-eth0 is connected to leaf1-eth0
        switch = tgen.add_switch('sw1')
        switch.add_link(tgen.gears['spine']) 
        switch.add_link(tgen.gears['leaf1'])

        # spine-eth1 is connected to leaf2-eth0
        switch = tgen.add_switch('sw2')
        switch.add_link(tgen.gears['spine'])
        switch.add_link(tgen.gears['leaf2'])

        # leaf1-eth1 is connected to host1-eth0
        switch = tgen.add_switch('sw3')
        switch.add_link(tgen.gears['leaf1'])
        switch.add_link(tgen.gears['host1'])

        # leaf2-eth1 is connected to host2-eth0
        switch = tgen.add_switch('sw4')
        switch.add_link(tgen.gears['leaf2'])
        switch.add_link(tgen.gears['host1'])



#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    "Setup topology"
    tgen = Topogen(NetworkTopo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_PIM,
            os.path.join(CWD, '{}/pimd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP,
            os.path.join(CWD, '{}/sharpd.conf'.format(rname))
        )
    tgen.start_router()
    tgen.mininet_cli()


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

    topotest.sleep(15, 'Waiting for stuff to converge')

def test_shutdown_check_stderr():
    if os.environ.get('TOPOTESTS_CHECK_STDERR') is None:
        pytest.skip('Skipping test for Stderr output and memory leaks')

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying unexpected STDERR output from daemons")

    router_list = tgen.routers().values()
    for router in router_list:
        router.stop()

        log = tgen.net[router.name].getStdErr('pimd')
        if log:
            logger.error('PIMd StdErr Log:' + log)
        log = tgen.net[router.name].getStdErr('bgpd')
        if log:
            logger.error('BGPd StdErr Log:' + log)
        log = tgen.net[router.name].getStdErr('zebra')
        if log:
            logger.error('Zebra StdErr Log:' + log)


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

