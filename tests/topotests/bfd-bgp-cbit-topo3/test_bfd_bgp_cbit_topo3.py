#!/usr/bin/env python

#
# test_bfd_bgp_cbit_topo3.py
#
# Copyright (c) 2019 6WIND
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
test_bfd_bgp_cbit_topo3.py: Test the FRR/Quagga BFD daemon with multihop and BGP
unnumbered.
"""

import os
import sys
import json
from functools import partial
import pytest

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

class BFDTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 4 routers.
        for routern in range(1, 4):
            tgen.add_router('r{}'.format(routern))

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(BFDTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname)),
        )
        router.load_config(
            TopoRouter.RD_BFD,
            os.path.join(CWD, '{}/bfdd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    # Initialize all routers.
    tgen.start_router()

    # Verify that we are using the proper version and that the BFD
    # daemon exists.
    for router in router_list.values():
        # Check for Version
        if router.has_version('<', '5.1'):
            tgen.set_error('Unsupported FRR version')
            break

def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged before checking for the BFD
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv6 routing tables.
    logger.info("Checking IPv6 routes for convergence")
    for router in tgen.routers().values():
        if router.name == 'r2':
            continue
        json_file = '{}/{}/ipv6_routes.json'.format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info('skipping file {}'.format(json_file))
            continue
        expected = json.loads(open(json_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show ipv6 route json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=40,
                                            wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_bfd_connection():
    "Assert that the BFD peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bfd peers to go up')
    for router in tgen.routers().values():
        if router.name == 'r2':
            continue
        json_file = '{}/{}/peers.json'.format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(topotest.router_json_cmp,
                            router, 'show bfd peers json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=16, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

def test_bfd_loss_intermediate():
    """
    Assert that BFD notices the bfd link down failure.
    but BGP entries should still be present
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('removing IPv6 address from r2 to simulate loss of connectivity')
    # Disable r2-eth0 ipv6 address
    cmd = 'vtysh -c \"configure terminal\" -c \"interface r2-eth1\" -c "no ipv6 address 2001:db8:4::2/64\"'
    tgen.net['r2'].cmd(cmd)
 
    # Wait the minimum time we can before checking that BGP/BFD
    # converged.
    logger.info('waiting for BFD converge down')

    # Check that BGP converged quickly.
    for router in tgen.routers().values():
        if router.name == 'r2':
            continue
        json_file = '{}/{}/peers_down.json'.format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(topotest.router_json_cmp,
                            router, 'show bfd peers json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=16, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    logger.info('waiting for BGP entries to become stale')
    for router in tgen.routers().values():
        if router.name == 'r2':
            continue
        json_file = '{}/{}/bgp_ipv6_routes_down.json'.format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(topotest.router_json_cmp,
                            router, 'show bgp ipv6 json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=50, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    logger.info("Checking IPv6 routes on r1 should still be present")
    for router in tgen.routers().values():
        if router.name == 'r2':
            continue
        if router.name == 'r3':
            continue
        json_file = '{}/r1/ipv6_routes.json'.format(CWD)
        expected = json.loads(open(json_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show ipv6 route json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=30,
                                            wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

def test_bfd_comes_back_again():
    """
    Assert that BFD notices the bfd link up
    and that ipv6 entries appear back
    """
    tgen = get_topogen()
    logger.info('re-adding IPv6 address from r2 to simulate connectivity is back')
    # adds back r2-eth0 ipv6 address
    cmd = 'vtysh -c \"configure terminal\" -c \"interface r2-eth1\" -c "ipv6 address 2001:db8:4::2/64\"'
    tgen.net['r2'].cmd(cmd)

    # Wait the minimum time we can before checking that BGP/BFD
    # converged.
    logger.info('waiting for BFD to converge up')

    # Check that BGP converged quickly.
    for router in tgen.routers().values():
        if router.name == 'r2':
            continue
        json_file = '{}/{}/peers.json'.format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(topotest.router_json_cmp,
                            router, 'show bfd peers json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=16, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg
    

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
