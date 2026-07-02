#!/usr/bin/env python3
"""
Vanguard-OOB :: Unified Blue Team CLI
=======================================
Single entry point for the entire Vanguard-OOB Blue Team Detection Suite.
Run any of the 21 tools through one consistent interface, or use the
built-in workflows that chain multiple tools together automatically.

  vanguard tools                          List all available tools
  vanguard run <tool> [tool-args...]      Run a specific tool directly
  vanguard hunt                           Run threat_hunter with all playbooks
  vanguard audit                          Run config_auditor + ioc_hunter + file_integrity
  vanguard sweep <subnet>                 Run network_mapper + vuln_scanner on a subnet
  vanguard dashboard                      Launch the Master SOC Dashboard
  vanguard correlate <findings-dir>       Run alert_correlator across all findings
  vanguard report <findings-dir>          Generate executive + technical reports
  vanguard full-scan                      Run the complete detection pipeline end-to-end

All tool output (when run via 'vanguard run' with --json) is automatically
written into ./findings/<tool>_<timestamp>.json so the SOC dashboard and
alert_correlator pick it up immediately.

Usage:
    python3 vanguard.py tools
    python3 vanguard.py run threat_intel --query 8.8.8.8
    python3 vanguard.py hunt
    python3 vanguard.py audit
    python3 vanguard.py sweep 192.168.1.0/24
    python3 vanguard.py dashboard --port 8080
    python3 vanguard.py full-scan --target-dir /var/www
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("vanguard.cli")

ROOT = Path(__file__).resolve().parent
FINDINGS_DIR = ROOT / "findings"

# ── Tool registry: name -> (relative_path, description, category) ────────────

TOOLS: Dict[str, dict] = {
    "threat_intel":               {"path": "threat_intel/threat_intel.py",
                                    "desc": "IOC feed engine + reputation scoring",
                                    "category": "Intel"},
    "sigma_engine":                {"path": "sigma_engine/sigma_engine.py",
                                    "desc": "Sigma-compatible detection rules + ATT&CK tags",
                                    "category": "Detection"},
    "log_analyzer":                {"path": "log_analyzer/log_analyzer.py",
                                    "desc": "Multi-source log parser + anomaly detector",
                                    "category": "Detection"},
    "vuln_scanner":                {"path": "vuln_scanner/vuln_scanner.py",
                                    "desc": "Port/service/CVE surface scanner",
                                    "category": "Scanning"},
    "packet_inspector":            {"path": "packet_inspector/packet_inspector.py",
                                    "desc": "PCAP decoder + protocol anomaly engine",
                                    "category": "Network"},
    "ioc_hunter":                  {"path": "ioc_hunter/ioc_hunter.py",
                                    "desc": "Filesystem + process + persistence IOC hunter",
                                    "category": "Hunting"},
    "yara_engine":                 {"path": "yara_engine/yara_engine.py",
                                    "desc": "Custom YARA-like rule engine",
                                    "category": "Detection"},
    "timeline_builder":            {"path": "timeline_builder/timeline_builder.py",
                                    "desc": "Forensic event timeline reconstructor",
                                    "category": "Forensics"},
    "network_mapper":              {"path": "network_mapper/network_mapper.py",
                                    "desc": "LAN host discovery + topology mapper",
                                    "category": "Network"},
    "file_integrity":              {"path": "file_integrity/file_integrity.py",
                                    "desc": "Cryptographic baseline + drift detection (FIM)",
                                    "category": "Integrity"},
    "lateral_movement_detector":   {"path": "lateral_movement_detector/lateral_movement_detector.py",
                                    "desc": "Graph-based lateral movement detection",
                                    "category": "Detection"},
    "dns_analyzer":                {"path": "dns_analyzer/dns_analyzer.py",
                                    "desc": "DGA, fast-flux, tunneling, typosquat detection",
                                    "category": "Network"},
    "credential_monitor":          {"path": "credential_monitor/credential_monitor.py",
                                    "desc": "Password spray, secret exposure, hash audit",
                                    "category": "Identity"},
    "alert_correlator":            {"path": "alert_correlator/alert_correlator.py",
                                    "desc": "Unifies all findings, reconstructs kill chains",
                                    "category": "Correlation"},
    "behavioral_engine":           {"path": "behavioral_engine/behavioral_engine.py",
                                    "desc": "UEBA — per-entity behavioral baselines",
                                    "category": "UEBA"},
    "config_auditor":              {"path": "config_auditor/config_auditor.py",
                                    "desc": "CIS-inspired hardening benchmark scanner",
                                    "category": "Hardening"},
    "deception_engine":            {"path": "deception_engine/deception_engine.py",
                                    "desc": "Honeytokens, canary files, canary credentials",
                                    "category": "Deception"},
    "threat_hunter":               {"path": "threat_hunter/threat_hunter.py",
                                    "desc": "Hypothesis-driven proactive hunt playbooks",
                                    "category": "Hunting"},
    "reporting_engine":            {"path": "reporting_engine/reporting_engine.py",
                                    "desc": "Executive/technical/compliance report generator",
                                    "category": "Reporting"},
    "honeypot_manager":            {"path": "honeypot_manager/honeypot_manager.py",
                                    "desc": "Lightweight service honeypots (SSH/HTTP/FTP/...)",
                                    "category": "Deception"},
    "memory_forensics":            {"path": "memory_forensics/memory_forensics.py",
                                    "desc": "Live + offline memory artifact analysis",
                                    "category": "Forensics"},
    "soc_dashboard":               {"path": "soc_dashboard/soc_dashboard.py",
                                    "desc": "Master real-time SOC dashboard (all tools)",
                                    "category": "Dashboard"},
}

CATEGORIES = sorted({t["category"] for t in TOOLS.values()})


def tool_path(name: str) -> Path:
    return ROOT / TOOLS[name]["path"]


def run_tool(name: str, extra_args: List[str], capture: bool = False) -> subprocess.CompletedProcess:
    if name not in TOOLS:
        print(f"  \033[91mUnknown tool: {name}\033[0m")
        print(f"  Run 'vanguard tools' to see available tools.")
        sys.exit(1)

    script = tool_path(name)
    cmd = [sys.executable, str(script)] + extra_args
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True)
    return subprocess.run(cmd)


def timestamped_findings_path(tool_name: str) -> Path:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return FINDINGS_DIR / f"{tool_name}_{ts}.json"


# ── Subcommand: tools (list registry) ─────────────────────────────────────────

def cmd_tools(args):
    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  VANGUARD-OOB BLUE TEAM SUITE — {len(TOOLS)} TOOLS{R}\n")

    by_cat: Dict[str, list] = {}
    for name, meta in TOOLS.items():
        by_cat.setdefault(meta["category"], []).append((name, meta["desc"]))

    for cat in CATEGORIES:
        print(f"  {C}{B}── {cat.upper()} ──{R}")
        for name, desc in sorted(by_cat.get(cat, [])):
            print(f"    {name:30} {desc}")
        print()

    print(f"  Usage: vanguard run <tool> [args...]")
    print(f"  Example: vanguard run vuln_scanner --target 192.168.1.1\n")


# ── Subcommand: run (direct passthrough) ───────────────────────────────────────

def cmd_run(args):
    name = args.tool
    extra = args.tool_args
    result = run_tool(name, extra)
    sys.exit(result.returncode)


# ── Subcommand: hunt (threat_hunter wrapper) ────────────────────────────────────

def cmd_hunt(args):
    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard Hunt: Running all threat hunt playbooks ──{R}\n")
    out_path = timestamped_findings_path("threat_hunter")
    extra = ["--hunt", "all", "--json", str(out_path)]
    if args.window_hours:
        extra += ["--window-hours", str(args.window_hours)]
    result = run_tool("threat_hunter", extra)
    if out_path.exists():
        print(f"\n  {C}Findings written to {out_path}{R}")
    sys.exit(result.returncode)


# ── Subcommand: audit (multi-tool hardening sweep) ──────────────────────────────

def cmd_audit(args):
    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard Audit: config_auditor + ioc_hunter + file_integrity ──{R}\n")

    print(f"  {B}[1/3] Configuration Hardening Audit{R}")
    out1 = timestamped_findings_path("config_auditor")
    run_tool("config_auditor", ["--audit", "--json", str(out1)])

    print(f"\n  {B}[2/3] IOC Hunt (filesystem + process + persistence){R}")
    out2 = timestamped_findings_path("ioc_hunter")
    run_tool("ioc_hunter", ["--hunt", "all", "--path", args.path or "/etc",
                            "--output", str(out2)])

    print(f"\n  {B}[3/3] File Integrity Baseline{R}")
    baseline = ROOT / "fim_baseline.fimdb"
    if not baseline.exists():
        run_tool("file_integrity", ["--init", "--path", args.path or "/etc",
                                    "--baseline", str(baseline)])
        print(f"  Baseline created: {baseline}")
    else:
        out3 = timestamped_findings_path("file_integrity")
        run_tool("file_integrity", ["--check", "--path", args.path or "/etc",
                                    "--baseline", str(baseline), "--json", str(out3)])

    print(f"\n  {C}Audit complete. Run 'vanguard correlate findings/' to unify results.{R}\n")


# ── Subcommand: sweep (network discovery + vuln scan) ───────────────────────────

def cmd_sweep(args):
    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    subnet = args.subnet
    print(f"\n{B}  ── Vanguard Sweep: network_mapper + vuln_scanner on {subnet} ──{R}\n")

    print(f"  {B}[1/2] Network Discovery{R}")
    out1 = timestamped_findings_path("network_mapper")
    run_tool("network_mapper", ["--sweep", subnet, "--output", str(out1)])

    print(f"\n  {B}[2/2] Vulnerability Scan{R}")
    out2 = timestamped_findings_path("vuln_scanner")
    run_tool("vuln_scanner", ["--target", subnet, "--json", str(out2)])

    print(f"\n  {C}Sweep complete. Run 'vanguard correlate findings/' to unify results.{R}\n")


# ── Subcommand: dashboard ──────────────────────────────────────────────────────

def cmd_dashboard(args):
    extra = ["--findings-dir", args.findings_dir or str(FINDINGS_DIR),
             "--port", str(args.port)]
    result = run_tool("soc_dashboard", extra)
    sys.exit(result.returncode)


# ── Subcommand: correlate ───────────────────────────────────────────────────────

def cmd_correlate(args):
    extra = ["--ingest-dir", args.findings_dir]
    if args.json:
        extra += ["--json", args.json]
    result = run_tool("alert_correlator", extra)
    sys.exit(result.returncode)


# ── Subcommand: report ─────────────────────────────────────────────────────────

def cmd_report(args):
    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard Report: generating executive + technical reports ──{R}\n")

    out_dir = Path(args.output_dir or "reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"  {B}[1/2] Executive Report{R}")
    run_tool("reporting_engine", ["--type", "executive", "--ingest-dir", args.findings_dir,
                                  "--format", "html",
                                  "--output", str(out_dir / "executive_report.html")])

    print(f"\n  {B}[2/2] Technical Report{R}")
    run_tool("reporting_engine", ["--type", "technical", "--ingest-dir", args.findings_dir,
                                  "--format", "html",
                                  "--output", str(out_dir / "technical_report.html")])

    print(f"\n  {C}Reports saved to {out_dir}/{R}\n")


# ── Subcommand: full-scan ───────────────────────────────────────────────────────

def cmd_full_scan(args):
    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"; G = "\033[92m"
    print(f"\n{B}  ════════════════════════════════════════════════")
    print(f"   VANGUARD-OOB FULL DETECTION PIPELINE")
    print(f"  ════════════════════════════════════════════════{R}\n")

    target_dir = args.target_dir or "/etc"
    steps = []

    print(f"  {B}[1/7] Configuration Hardening Audit{R}")
    out = timestamped_findings_path("config_auditor")
    run_tool("config_auditor", ["--audit", "--json", str(out)])
    steps.append(("config_auditor", out))

    print(f"\n  {B}[2/7] IOC Hunt{R}")
    out = timestamped_findings_path("ioc_hunter")
    run_tool("ioc_hunter", ["--hunt", "all", "--path", target_dir, "--output", str(out)])
    steps.append(("ioc_hunter", out))

    print(f"\n  {B}[3/7] YARA Malware Scan{R}")
    out = timestamped_findings_path("yara_engine")
    run_tool("yara_engine", ["--scan", target_dir, "--json", str(out)])
    steps.append(("yara_engine", out))

    print(f"\n  {B}[4/7] Threat Hunting Playbooks{R}")
    out = timestamped_findings_path("threat_hunter")
    run_tool("threat_hunter", ["--hunt", "all", "--json", str(out)])
    steps.append(("threat_hunter", out))

    print(f"\n  {B}[5/7] Threat Intel IOC Scan{R}")
    out = timestamped_findings_path("threat_intel")
    run_tool("threat_intel", ["--scan", target_dir, "--export", str(out)]
             if Path(target_dir).is_file() else
             ["--query", "127.0.0.1", "--export", str(out)])
    steps.append(("threat_intel", out))

    if args.network_target:
        print(f"\n  {B}[6/7] Network Sweep ({args.network_target}){R}")
        out = timestamped_findings_path("network_mapper")
        run_tool("network_mapper", ["--sweep", args.network_target, "--output", str(out)])
        steps.append(("network_mapper", out))
    else:
        print(f"\n  {B}[6/7] Network Sweep{R}  \033[2m(skipped — pass --network-target)\033[0m")

    print(f"\n  {B}[7/7] Correlating all findings...{R}")
    correlate_out = ROOT / "full_scan_correlated.json"
    run_tool("alert_correlator", ["--ingest-dir", str(FINDINGS_DIR),
                                  "--json", str(correlate_out)])

    print(f"\n{G}  ════════════════════════════════════════════════")
    print(f"   FULL SCAN COMPLETE")
    print(f"  ════════════════════════════════════════════════{R}\n")
    print(f"  Findings directory : {C}{FINDINGS_DIR}{R}")
    print(f"  Correlated output  : {C}{correlate_out}{R}")
    print(f"  Next: vanguard report {FINDINGS_DIR}")
    print(f"  Next: vanguard dashboard\n")


# ── Argument parser ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vanguard",
        description="Vanguard-OOB Unified Blue Team CLI — 21 tools, one interface",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_tools = sub.add_parser("tools", help="List all available tools")
    p_tools.set_defaults(func=cmd_tools)

    p_run = sub.add_parser("run", help="Run a specific tool directly")
    p_run.add_argument("tool", choices=list(TOOLS.keys()))
    p_run.add_argument("tool_args", nargs=argparse.REMAINDER)
    p_run.set_defaults(func=cmd_run)

    p_hunt = sub.add_parser("hunt", help="Run all threat hunting playbooks")
    p_hunt.add_argument("--window-hours", type=float, default=24.0)
    p_hunt.set_defaults(func=cmd_hunt)

    p_audit = sub.add_parser("audit", help="Run hardening + IOC + integrity audit")
    p_audit.add_argument("--path", default="/etc")
    p_audit.set_defaults(func=cmd_audit)

    p_sweep = sub.add_parser("sweep", help="Network discovery + vulnerability scan")
    p_sweep.add_argument("subnet", help="e.g. 192.168.1.0/24")
    p_sweep.set_defaults(func=cmd_sweep)

    p_dash = sub.add_parser("dashboard", help="Launch the Master SOC Dashboard")
    p_dash.add_argument("--port", type=int, default=8080)
    p_dash.add_argument("--findings-dir", default=None)
    p_dash.set_defaults(func=cmd_dashboard)

    p_corr = sub.add_parser("correlate", help="Correlate findings across all tools")
    p_corr.add_argument("findings_dir", nargs="?", default=str(FINDINGS_DIR))
    p_corr.add_argument("--json", default=None)
    p_corr.set_defaults(func=cmd_correlate)

    p_report = sub.add_parser("report", help="Generate executive + technical reports")
    p_report.add_argument("findings_dir", nargs="?", default=str(FINDINGS_DIR))
    p_report.add_argument("--output-dir", default="reports")
    p_report.set_defaults(func=cmd_report)

    p_full = sub.add_parser("full-scan", help="Run the complete detection pipeline")
    p_full.add_argument("--target-dir", default="/etc")
    p_full.add_argument("--network-target", default=None,
                        help="Optional subnet for network_mapper, e.g. 192.168.1.0/24")
    p_full.set_defaults(func=cmd_full_scan)

    return parser


def main():
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
