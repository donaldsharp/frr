#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Extract BGP configuration CLI commands and classify vs YANG coverage.

Produces a CSV/markdown inventory used by yang/BGP_YANG_CLI_GAP.md.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# VTY nodes that hold BGP configuration (not show/clear/debug-only)
BGP_CONFIG_NODES = {
	"BGP_NODE",
	"BGP_IPV4_NODE",
	"BGP_IPV4M_NODE",
	"BGP_IPV4L_NODE",
	"BGP_IPV6_NODE",
	"BGP_IPV6M_NODE",
	"BGP_IPV6L_NODE",
	"BGP_VPNV4_NODE",
	"BGP_VPNV6_NODE",
	"BGP_EVPN_NODE",
	"BGP_EVPN_VNI_NODE",
	"BGP_FLOWSPECV4_NODE",
	"BGP_FLOWSPECV6_NODE",
	"BGP_IPV4U_NODE",
	"BGP_IPV6U_NODE",
	"BGP_LS_NODE",
	"BGP_SRV6_NODE",
	"BMP_NODE",
	"RPKI_NODE",
	"RMAP_NODE",
	"CONFIG_NODE",  # filtered further
	# VNC
	"BGP_VNC_DEFAULTS_NODE",
	"BGP_VNC_NVE_GROUP_NODE",
	"BGP_VNC_L2_GROUP_NODE",
	"VRF_POLICY_NODE",
	"VNC_VRF_POLICY_NODE",
}

SHOW_CLEAR_DEBUG_RE = re.compile(
	r"^(show_|clear_|debug_|no_debug_|undebug_)", re.I
)

# CONFIG_NODE cmds that are BGP-related
CONFIG_BGP_HINTS = re.compile(
	r"(bgp_|community_list|large_community|extcommunity|as_path|"
	r"rpki|bmp_|neighbor_)",
	re.I,
)

DEFUN_RE = re.compile(
	r"^\s*(?P<kind>DEFPY_YANG_HIDDEN|DEFUN_YANG_HIDDEN|DEFPY_YANG_NOSH|"
	r"DEFUN_YANG_NOSH|DEFPY_YANG|DEFUN_YANG|ALIAS_YANG|ALIAS_ATTR|"
	r"DEFPY_NOSH|DEFUN_NOSH|DEFPY|DEFUN|ALIAS_HIDDEN|ALIAS)\s*\(\s*"
	r"(\w+)\s*,\s*(\w+)\s*,",
	re.M,
)

INSTALL_RE = re.compile(
	r"install_element\s*\(\s*(\w+)\s*,\s*&(\w+)\s*\)",
)

# Intentionally left classic (node-only, hidden test, ops dump).
INTENTIONAL_RE = re.compile(
	r"exit_address_family|bgp_local_mac|no_bgp_local_mac|"
	r"evpnrt5_network|no_evpnrt5_network|test_es_|"
	r"dump_bgp_|no_dump_bgp_|rpki_reset",
	re.I,
)

# Heuristic phase assignment from command name / file
PHASE_RULES = [
	(10, re.compile(r"vnc_|rfapi_|nve_|vrf_policy", re.I), "vnc"),
	(7, re.compile(r"bmp_|rpki_", re.I), "bmp-rpki"),
	(8, re.compile(r"rmap_|match_|set_|community_list|as_path_access|"
			r"large_community|extcommunity|community_alias", re.I),
	 "filter-rmap"),
	(5, re.compile(r"evpn_|vni_|ead_|es_|mac_vrf|advertise_all_vni|"
			r"default_gateway|dup_addr|flood", re.I), "evpn"),
	(6, re.compile(r"srv6_|segment_routing|link_state|upa_|unreach|"
			r"flowspec|local_install", re.I), "srv6-ls-upa-fs"),
	(4, re.compile(r"network_|aggregate_|redistribute_|distance_|"
			r"table_map|route_target|rd_vpn|label_vpn|"
			r"import_vrf|export_vpn|mplsvpn", re.I), "network-vpn"),
	(3, re.compile(r"neighbor_.*_(prefix|filter|route_map|max_prefix|"
			r"nexthop|allowas|as_override|soft_reconfig|"
			r"default_originate|send_community|advertise_map|"
			r"attr_unchanged|remove_private|weight|route_server|"
			r"route_reflector_client|addpath|accept_own|soo|"
			r"path_attribute|activate)", re.I), "af-policy"),
	(2, re.compile(r"neighbor_|peer_group|bfd_|listen_", re.I),
	 "neighbor-session"),
	(1, re.compile(r"^bgp_|^router_bgp|^no_router_bgp|"
			r"confederation|graceful|cluster_id|maxmed|"
			r"bestpath|maximum_paths|timers_|update_delay|"
			r"suppress_fib|fast_converg|session_dscp|"
			r"reject_as|martian|norib|administrative", re.I),
	 "globals"),
]


def assign_phase(cmd: str, path: str) -> tuple[int, str]:
	base = os.path.basename(path)
	if "rfapi" in path or "vnc" in base.lower():
		return 10, "vnc"
	if "evpn" in base:
		return 5, "evpn"
	if "bmp" in base:
		return 7, "bmp-rpki"
	if "rpki" in base:
		return 7, "bmp-rpki"
	if "routemap" in base or "filter" in base:
		return 8, "filter-rmap"
	if "flowspec" in base:
		return 6, "srv6-ls-upa-fs"
	if "mplsvpn" in base or "route.c" in base:
		return 4, "network-vpn"
	if "bfd" in base:
		return 2, "neighbor-session"
	for phase, rx, name in PHASE_RULES:
		if rx.search(cmd):
			return phase, name
	# neighbor without AF keywords → session
	if "neighbor" in cmd.lower():
		return 2, "neighbor-session"
	return 1, "globals"


# Known YANG coverage hints (substring of cmd → status)
YANG_PRESENT = [
	(re.compile(r"router_id|local_as|confederation|cluster_id|"
		    r"client_to_client|maxmed|always_compare_med|"
		    r"deterministic_med|bestpath|graceful_restart|"
		    r"network_import_check|ebgp_requires_policy|"
		    r"log_neighbor|wpkt_quanta|rpkt_quanta|"
		    r"coalesce|dynamic_neighbor|fast_external|"
		    r"default_local_pref|suppress_duplicates|"
		    r"neighbor_remote_as|peer_group|update_source|"
		    r"ebgp_multihop|local_as|bfd|shutdown|"
		    r"password|ttl_security|description|passive|"
		    r"timers|keepalive|holdtime|activate|"
		    r"route_map|prefix_list|filter_list|"
		    r"max_prefix|nexthop_self|allowas_in|"
		    r"default_originate|send_community|"
		    r"soft_reconfig|attr_unchanged|remove_private|"
		    r"weight|route_reflector_client|route_server|"
		    r"addpath|orf_|dampening|distance|"
		    r"aggregate_address|redistribute|network_|"
		    r"maximum_paths|bmp_|rpki", re.I), "PARTIAL"),
]

YANG_LIKELY_MISSING = re.compile(
	r"suppress_fib|fast_converg|session_dscp|reject_as_sets|"
	r"allow_martian|norib|administrative_reset|ipv6_auto_ra|"
	r"community_alias|long_lived|llgr|lu_uses_explicit|"
	r"software_version|tcp_mss|fqdn|link_local|role|"
	r"advertise_map|accept_own|path_attribute|"
	r"srv6|segment_routing|link_state|upa_|"
	r"advertise_all_vni|evpn_|vni_|ead_|dup_addr|"
	r"local_install|import_vrf.*bmp|experimental",
	re.I,
)


def classify_yang(cmd: str, def_kind: str | None) -> str:
	"""Classify CLI conversion status.

	Primary signal: whether the installed command is defined with a
	DEFUN_YANG / DEFPY_YANG / ALIAS_YANG macro (CLI already on NB).
	Heuristic MISSING/PARTIAL is only used for remaining classic DEFUNs.
	"""
	if INTENTIONAL_RE.search(cmd):
		return "INTENTIONAL"
	if def_kind and "YANG" in def_kind:
		return "CONVERTED"
	# Hidden AF aliases of YANG commands (ALIAS_ATTR of …_yang).
	if "yang" in cmd.lower():
		return "CONVERTED"
	# Plain ALIAS / ALIAS_HIDDEN of a YANG command still counts.
	if def_kind in ("ALIAS_HIDDEN", "ALIAS"):
		return "CONVERTED"
	if YANG_LIKELY_MISSING.search(cmd):
		return "MISSING"
	for rx, status in YANG_PRESENT:
		if rx.search(cmd):
			return status
	return "MISSING"


def action_for(status: str, phase: int) -> str:
	if status == "CONVERTED":
		return "keep"
	if status == "INTENTIONAL":
		return "skip"
	if phase == 10:
		return "skip-vnc"
	if status == "MISSING":
		return "add"
	if status == "PARTIAL":
		return "fix"
	return "keep"


def parse_file(path: Path) -> tuple[dict[str, tuple[str, str]], list[tuple[str, str]]]:
	"""Return (cmd_symbol -> (cli, kind), list of (node, cmd_symbol))."""
	text = path.read_text(errors="replace")
	defs: dict[str, tuple[str, str]] = {}
	for m in DEFUN_RE.finditer(text):
		kind, func, cmd_sym = m.group("kind"), m.group(2), m.group(3)
		start = m.end()
		snippet = text[start : start + 400]
		cli_m = re.search(r'"([^"]{8,200})"', snippet)
		cli = cli_m.group(1) if cli_m else func
		defs[cmd_sym] = (cli.replace("\n", " ").strip(), kind)
	installs = INSTALL_RE.findall(text)
	return defs, installs


def is_config_cmd(cmd_sym: str, nodes: set[str]) -> bool:
	if SHOW_CLEAR_DEBUG_RE.match(cmd_sym):
		return False
	# pure ENABLE/VIEW show nodes only → skip if not also on config nodes
	config_nodes = nodes & BGP_CONFIG_NODES
	if not config_nodes:
		return False
	if config_nodes <= {"CONFIG_NODE"} and not CONFIG_BGP_HINTS.search(
		cmd_sym
	):
		return False
	return True


def main() -> int:
	ap = argparse.ArgumentParser()
	ap.add_argument(
		"--bgpd",
		type=Path,
		default=Path(__file__).resolve().parents[2] / "bgpd",
	)
	ap.add_argument(
		"--out-csv",
		type=Path,
		default=Path(__file__).resolve().parents[1]
		/ "BGP_YANG_CLI_GAP.csv",
	)
	ap.add_argument(
		"--out-md",
		type=Path,
		default=Path(__file__).resolve().parents[1]
		/ "BGP_YANG_CLI_GAP.md",
	)
	args = ap.parse_args()

	all_defs: dict[str, tuple[str, str, str]] = {}  # cmd -> (cli, file, kind)
	install_map: dict[str, set[str]] = defaultdict(set)

	for path in sorted(args.bgpd.rglob("*.c")):
		# skip generated / example noise lightly
		if "rfp-example" in str(path):
			continue
		defs, installs = parse_file(path)
		rel = str(path.relative_to(args.bgpd.parent))
		for cmd, (cli, kind) in defs.items():
			all_defs[cmd] = (cli, rel, kind)
		for node, cmd in installs:
			install_map[cmd].add(node)

	rows = []
	for cmd, nodes in sorted(install_map.items()):
		if not is_config_cmd(cmd, nodes):
			continue
		cli, src, kind = all_defs.get(cmd, ("", "?", None))
		phase, phase_name = assign_phase(cmd, src)
		status = classify_yang(cmd, kind)
		action = action_for(status, phase)
		rows.append(
			{
				"cmd": cmd,
				"cli": cli[:120],
				"file": src,
				"nodes": ";".join(sorted(nodes & BGP_CONFIG_NODES)),
				"yang_path": status,
				"action": action,
				"phase": f"{phase}-{phase_name}",
				"pr": "",
			}
		)

	args.out_csv.parent.mkdir(parents=True, exist_ok=True)
	with args.out_csv.open("w", newline="") as f:
		w = csv.DictWriter(
			f,
			fieldnames=[
				"cmd",
				"cli",
				"file",
				"nodes",
				"yang_path",
				"action",
				"phase",
				"pr",
			],
		)
		w.writeheader()
		w.writerows(rows)

	# Markdown summary
	by_phase: dict[str, list] = defaultdict(list)
	by_status: dict[str, int] = defaultdict(int)
	for r in rows:
		by_phase[r["phase"]].append(r)
		by_status[r["yang_path"]] += 1

	lines = [
		"# BGP YANG ↔ CLI Gap Matrix",
		"",
		"Auto-generated inventory of BGP **configuration** CLI commands",
		"versus YANG conversion status. Regenerate with:",
		"",
		"```",
		"python3 yang/tools/extract_bgp_cli_config.py",
		"```",
		"",
		"Classification:",
		"",
		"- **CONVERTED** — installed command is defined with `DEFUN_YANG` /",
		"  `DEFPY_YANG` / `ALIAS_YANG` (or a hidden ALIAS of one).",
		"- **INTENTIONAL** — left classic on purpose (node exit, hidden test,",
		"  ops dump, `rpki reset`).",
		"- **MISSING** / **PARTIAL** — heuristic only for remaining classic",
		"  DEFUNs; do not treat as authoritative without checking the source.",
		"",
		f"**Total config commands:** {len(rows)}",
		"",
		"## Coverage summary",
		"",
		"| yang_path | count |",
		"|-----------|------:|",
	]
	for k in sorted(by_status):
		lines.append(f"| {k} | {by_status[k]} |")
	lines += [
		"",
		"## By phase",
		"",
		"| phase | count | CONVERTED | INTENTIONAL | MISSING | PARTIAL |",
		"|-------|------:|----------:|------------:|--------:|--------:|",
	]
	for phase in sorted(by_phase, key=lambda p: int(p.split("-")[0])):
		rs = by_phase[phase]
		conv = sum(1 for r in rs if r["yang_path"] == "CONVERTED")
		inten = sum(1 for r in rs if r["yang_path"] == "INTENTIONAL")
		miss = sum(1 for r in rs if r["yang_path"] == "MISSING")
		part = sum(1 for r in rs if r["yang_path"] == "PARTIAL")
		lines.append(
			f"| {phase} | {len(rs)} | {conv} | {inten} | {miss} | {part} |"
		)

	lines += [
		"",
		"## Full inventory",
		"",
		"See also machine-readable [`BGP_YANG_CLI_GAP.csv`](BGP_YANG_CLI_GAP.csv).",
		"",
		"| cmd | file | nodes | yang_path | action | phase |",
		"|-----|------|-------|-----------|--------|-------|",
	]
	for r in rows:
		nodes = r["nodes"].replace("|", "\\|")[:40]
		lines.append(
			f"| `{r['cmd']}` | {r['file']} | {nodes} | "
			f"{r['yang_path']} | {r['action']} | {r['phase']} |"
		)
	lines.append("")
	args.out_md.write_text("\n".join(lines))
	print(f"Wrote {len(rows)} rows → {args.out_csv} and {args.out_md}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
