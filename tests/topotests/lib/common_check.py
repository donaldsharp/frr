#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# common_check.py
#
# Copyright 2024 6WIND S.A.

#
import json
from lib import topotest


def ip_check_path_selection(
    router, ipaddr_str, expected, vrf_name=None, check_fib=False
):
    if vrf_name:
        cmdstr = f"show ip route vrf {vrf_name} {ipaddr_str} json"
    else:
        cmdstr = f"show ip route {ipaddr_str} json"
    try:
        output = json.loads(router.vtysh_cmd(cmdstr))
    except (json.JSONDecodeError, ValueError):
        output = {}

    ret = topotest.json_cmp(output, expected)
    if ret is None:
        num_nh_expected = len(expected[ipaddr_str][0]["nexthops"])
        num_nh_observed = len(output[ipaddr_str][0]["nexthops"])
        if num_nh_expected == num_nh_observed:
            if check_fib:
                # special case: when fib flag is unset,
                # an extra test should be done to check that the flag is really unset
                for nh_output, nh_expected in zip(
                    output[ipaddr_str][0]["nexthops"],
                    expected[ipaddr_str][0]["nexthops"],
                ):
                    if (
                        "fib" in nh_output.keys()
                        and nh_output["fib"]
                        and ("fib" not in nh_expected.keys() or not nh_expected["fib"])
                    ):
                        return "{}, prefix {} nexthop {} has the fib flag set, whereas it is not expected".format(
                            router.name, ipaddr_str, nh_output["ip"]
                        )
            return ret
        return "{}, prefix {} does not have the correct number of nexthops : observed {}, expected {}".format(
            router.name, ipaddr_str, num_nh_observed, num_nh_expected
        )
    return ret


def _iproute_show_dst(prefix):
    """Destination key written by an exact ``ip route show PREFIX``."""
    if prefix in ("default", "0.0.0.0/0", "::/0"):
        return "default"
    if ":" in prefix:
        if prefix.endswith("/128"):
            return prefix[:-4]
        return prefix
    if prefix.endswith("/32"):
        return prefix[:-3]
    return prefix


def iproute2_check_path_selection(router, ipaddr_str, expected, vrf_name=None):
    family = "ipv6" if ":" in ipaddr_str else "ipv4"
    try:
        routes = topotest.kernel_routes(router, vrf=vrf_name or None, family=family)
    except Exception:
        output = []
    else:
        want = _iproute_show_dst(ipaddr_str)
        output = [route for route in routes if route.get("dst") == want]

    return topotest.json_cmp(output, expected)
