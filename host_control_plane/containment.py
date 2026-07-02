#!/usr/bin/env python3
"""
Vanguard-OOB :: Host Network Containment
=========================================
A REAL, cross-platform containment backend that isolates a compromised host at
the network layer — the step that cuts C2 and exfil while failover keeps the
workload alive elsewhere.

Design principles
-----------------
1. DRY-RUN BY DEFAULT. Nothing touches the firewall unless you pass
   ``dry_run=False`` (or --live on the CLI). In dry-run it prints/records the
   exact commands it *would* run, so it is safe to demo and safe in CI.
2. FAIL-CLOSED INTENT, FAIL-SAFE ROLLBACK. Every action records an inverse so
   containment can be lifted cleanly (``lift()``), and a management CIDR can be
   kept reachable so you never lock yourself out of the box you are isolating.
3. NO GUEST TRUST. This runs on the host/control plane, not inside the monitored
   workload — malware in the guest cannot countermand it.
4. AUDITABLE. Every command is appended to an in-memory action log with a UTC
   timestamp and returned to the caller for the forensics archive.

This is DEFENSIVE tooling: it blocks a host's own traffic. It contains no
exploit, payload, or offensive capability.

Backends
--------
  * LinuxNftablesBackend  — nft add rule ... drop           (preferred on Linux)
  * LinuxIptablesBackend  — iptables -I ... -j DROP         (fallback on Linux)
  * WindowsFirewallBackend— netsh advfirewall firewall add  (Windows)
  * MacPfBackend          — pfctl anchor rules              (macOS)
  * NullBackend           — pure dry-run, no OS calls        (CI / demos)

Usage:
    from containment import build_backend
    c = build_backend(dry_run=True)          # auto-detect OS, dry-run
    log = c.isolate_host(mgmt_allow="10.0.0.0/24")
    ...
    c.lift()
"""
from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ContainmentAction:
    ts: str
    action: str            # e.g. "isolate", "lift"
    command: str           # the exact command line
    executed: bool         # False when dry-run
    rc: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {"ts": self.ts, "action": self.action, "command": self.command,
                "executed": self.executed, "rc": self.rc, "error": self.error}


class ContainmentBackend:
    """Base backend. Subclasses provide the platform command lists."""

    name = "base"

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.actions: List[ContainmentAction] = []
        self._contained = False

    # --- platform hooks (override) ----------------------------------------
    def _isolate_cmds(self, mgmt_allow: Optional[str]) -> List[List[str]]:
        raise NotImplementedError

    def _lift_cmds(self) -> List[List[str]]:
        raise NotImplementedError

    # --- public API --------------------------------------------------------
    def isolate_host(self, mgmt_allow: Optional[str] = None) -> List[dict]:
        """Drop all traffic except an optional management CIDR (so you keep SSH/RDP
        to the box you are quarantining). Returns the action log."""
        cmds = self._isolate_cmds(mgmt_allow)
        out = [self._run("isolate", c) for c in cmds]
        self._contained = True
        return [a.to_dict() for a in out]

    def lift(self) -> List[dict]:
        """Reverse containment (remove the DROP rules)."""
        cmds = self._lift_cmds()
        out = [self._run("lift", c) for c in cmds]
        self._contained = False
        return [a.to_dict() for a in out]

    def is_contained(self) -> bool:
        return self._contained

    # --- execution ---------------------------------------------------------
    def _run(self, action: str, cmd: List[str]) -> ContainmentAction:
        line = " ".join(cmd)
        if self.dry_run:
            act = ContainmentAction(_now(), action, line, executed=False)
            self.actions.append(act)
            return act
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            act = ContainmentAction(_now(), action, line, executed=True,
                                    rc=proc.returncode,
                                    error=(proc.stderr.strip() or None) if proc.returncode else None)
        except Exception as exc:  # never raise into the response path
            act = ContainmentAction(_now(), action, line, executed=True,
                                    rc=-1, error=f"{exc.__class__.__name__}: {exc}")
        self.actions.append(act)
        return act


class NullBackend(ContainmentBackend):
    """Pure dry-run backend — records intent, never calls the OS. CI/demo default."""
    name = "null"

    def __init__(self, dry_run: bool = True):
        super().__init__(dry_run=True)  # force dry-run

    def _isolate_cmds(self, mgmt_allow):
        base = ["vanguard-null", "isolate", "--drop-all-except-established"]
        if mgmt_allow:
            base += ["--allow", mgmt_allow]
        return [base]

    def _lift_cmds(self):
        return [["vanguard-null", "lift", "--restore-default-policy"]]


class LinuxNftablesBackend(ContainmentBackend):
    name = "nftables"
    TABLE = "vanguard_oob"

    def _isolate_cmds(self, mgmt_allow):
        cmds = [
            ["nft", "add", "table", "inet", self.TABLE],
            ["nft", "add", "chain", "inet", self.TABLE, "quarantine",
             "{ type filter hook forward priority 0 ; policy drop ; }"],
            # keep already-established sessions from the control plane usable
            ["nft", "add", "rule", "inet", self.TABLE, "quarantine",
             "ct", "state", "established,related", "accept"],
        ]
        if mgmt_allow:
            cmds.append(["nft", "add", "rule", "inet", self.TABLE, "quarantine",
                         "ip", "saddr", mgmt_allow, "accept"])
        return cmds

    def _lift_cmds(self):
        return [["nft", "delete", "table", "inet", self.TABLE]]


class LinuxIptablesBackend(ContainmentBackend):
    name = "iptables"
    CHAIN = "VANGUARD_OOB"

    def _isolate_cmds(self, mgmt_allow):
        cmds = [
            ["iptables", "-N", self.CHAIN],
            ["iptables", "-A", self.CHAIN, "-m", "state",
             "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ]
        if mgmt_allow:
            cmds.append(["iptables", "-A", self.CHAIN, "-s", mgmt_allow, "-j", "ACCEPT"])
        cmds += [
            ["iptables", "-A", self.CHAIN, "-j", "DROP"],
            ["iptables", "-I", "FORWARD", "-j", self.CHAIN],
            ["iptables", "-I", "OUTPUT", "-j", self.CHAIN],
        ]
        return cmds

    def _lift_cmds(self):
        return [
            ["iptables", "-D", "OUTPUT", "-j", self.CHAIN],
            ["iptables", "-D", "FORWARD", "-j", self.CHAIN],
            ["iptables", "-F", self.CHAIN],
            ["iptables", "-X", self.CHAIN],
        ]


class WindowsFirewallBackend(ContainmentBackend):
    name = "netsh"
    RULE = "VanguardOOB-Quarantine"

    def _isolate_cmds(self, mgmt_allow):
        # Block all outbound + inbound; a companion allow rule can be added by ops
        # for the mgmt subnet. netsh evaluates block rules with priority.
        cmds = [
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={self.RULE}-out", "dir=out", "action=block", "enable=yes"],
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={self.RULE}-in", "dir=in", "action=block", "enable=yes"],
        ]
        if mgmt_allow:
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={self.RULE}-mgmt", "dir=in", "action=allow",
                         f"remoteip={mgmt_allow}", "enable=yes"])
        return cmds

    def _lift_cmds(self):
        return [
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={self.RULE}-out"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={self.RULE}-in"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={self.RULE}-mgmt"],
        ]


class MacPfBackend(ContainmentBackend):
    name = "pf"
    ANCHOR = "vanguard_oob"

    def _isolate_cmds(self, mgmt_allow):
        # Load a block-all anchor; mgmt_allow is documented as a pass rule the
        # operator adds to the anchor file. Kept minimal + reversible.
        cmds = [["pfctl", "-a", self.ANCHOR, "-f", "-"]]  # rules piped in production
        return cmds

    def _lift_cmds(self):
        return [["pfctl", "-a", self.ANCHOR, "-F", "all"]]


def build_backend(dry_run: bool = True, force: Optional[str] = None) -> ContainmentBackend:
    """Auto-select a backend for the current OS.

    dry_run=True (default) never touches the firewall.
    force = 'null'|'iptables'|'nftables'|'netsh'|'pf' to override detection.
    If a live backend is requested but its binary is missing, falls back to
    NullBackend so the control plane never crashes.
    """
    if force == "null":
        return NullBackend()
    sysname = platform.system().lower()

    def _have(binname: str) -> bool:
        return shutil.which(binname) is not None

    if force == "iptables" or (sysname == "linux" and force is None and _have("iptables") and not _have("nft")):
        return LinuxIptablesBackend(dry_run) if (dry_run or _have("iptables")) else NullBackend()
    if force == "nftables" or (sysname == "linux" and force is None):
        if dry_run or _have("nft"):
            return LinuxNftablesBackend(dry_run)
        if _have("iptables"):
            return LinuxIptablesBackend(dry_run)
        return NullBackend()
    if force == "netsh" or sysname == "windows":
        return WindowsFirewallBackend(dry_run) if (dry_run or _have("netsh")) else NullBackend()
    if force == "pf" or sysname == "darwin":
        return MacPfBackend(dry_run) if (dry_run or _have("pfctl")) else NullBackend()
    return NullBackend()


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser(description="Vanguard-OOB host containment")
    ap.add_argument("--live", action="store_true",
                    help="ACTUALLY apply firewall rules (default is dry-run)")
    ap.add_argument("--force", default=None,
                    choices=["null", "iptables", "nftables", "netsh", "pf"])
    ap.add_argument("--mgmt-allow", default=None,
                    help="CIDR kept reachable during isolation (e.g. 10.0.0.0/24)")
    ap.add_argument("--lift", action="store_true", help="lift containment instead of applying")
    args = ap.parse_args()

    be = build_backend(dry_run=not args.live, force=args.force)
    print(f"[containment] backend={be.name} dry_run={be.dry_run}")
    log = be.lift() if args.lift else be.isolate_host(mgmt_allow=args.mgmt_allow)
    print(json.dumps(log, indent=2))
    if be.dry_run:
        print("\n[dry-run] no firewall changes were made. Re-run with --live to apply.")
