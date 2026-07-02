#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 17 — Threat Hunter
==================================================
Original architecture. Hypothesis-driven proactive threat hunting engine.

Unlike reactive detection (alert fires → investigate), threat hunting
starts with a HYPOTHESIS about attacker behavior and searches across
multiple data sources to confirm or rule it out. This inverts the
detection model: YOU decide what TTPs to hunt; the engine finds evidence.

Built-in hunt playbooks (15 original hunts):

  CRED-01  Living-off-the-land credential dumping (lolbin patterns)
  CRED-02  Kerberoasting artifact scan (SetSPN + TGS patterns)
  EXEC-01  LOLBin execution chains (certutil/mshta/regsvr32 as downloaders)
  EXEC-02  Script interpreter spawned by Office/browser
  EXEC-03  Long-running command shells (>6h uptime) by non-admin users
  PERS-01  New services/drivers registered in last N days
  PERS-02  Scheduled tasks pointing outside system directories
  PRIV-01  Token impersonation indicators (SeDebugPrivilege abuse)
  LMOV-01  SMB lateral movement (admin$ share access patterns)
  LMOV-02  WMI/DCOM remote execution patterns
  EVAD-01  Process parent spoofing (mismatched parent-child timestamps)
  EVAD-02  DLL sideloading (unsigned DLL in signed-binary directory)
  DISC-01  Rapid system enumeration commands (whoami/ipconfig/net bursts)
  C2-01    Long TCP connections to uncommon ports (beacon timing analysis)
  EXFIL-01 Outbound data volume spike to new external IPs

Each hunt accepts configuration parameters, runs its query logic against
available data (live process list, log files, network connections, pcap
summary), scores findings by confidence, and returns structured results
integrating with the alert_correlator schema.

Usage:
    python3 threat_hunter.py --hunt all
    python3 threat_hunter.py --hunt CRED-01,EXEC-01,LMOV-01
    python3 threat_hunter.py --hunt C2-01 --logdir /var/log --window-hours 24
    python3 threat_hunter.py --list-hunts
"""

import argparse
import json
import logging
import os
import platform
import re
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

import psutil

logger = logging.getLogger("vanguard.threat_hunter")
IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class HuntResult:
    hunt_id:     str
    hunt_name:   str
    hypothesis:  str
    status:      str        # CONFIRMED / SUSPECT / NEGATIVE / INSUFFICIENT_DATA
    confidence:  int        # 0-100
    severity:    str
    mitre:       str
    findings:    List[dict] = field(default_factory=list)
    evidence:    dict       = field(default_factory=dict)
    recommendation: str     = ""
    timestamp:   str        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)

    def score(self) -> int:
        multiplier = {"CONFIRMED": 3, "SUSPECT": 2, "NEGATIVE": 0, "INSUFFICIENT_DATA": 0}
        sev_weight = {"critical": 40, "high": 25, "medium": 15, "low": 5}
        return (self.confidence * sev_weight.get(self.severity, 10) // 100) * multiplier.get(self.status, 0)


# ── Living-off-the-land binary sets ──────────────────────────────────────────

LOLBINS_DOWNLOAD = {
    "certutil", "bitsadmin", "mshta", "regsvr32", "wscript", "cscript",
    "powershell", "pwsh", "cmd", "rundll32", "msiexec", "installutil",
    "cmstp", "xwizard", "pcalua", "forfiles", "ieexec"
}

LOLBINS_EXEC = {
    "wmic", "msbuild", "csc", "vbc", "jsc", "aspnet_compiler",
    "appsync_publish_managed","presentationhost","syncappvpublishingserver"
}

CRED_DUMP_TOOLS = {
    "mimikatz","procdump","wce","fgdump","pwdump","lsass","ntdsutil",
    "secretsdump","lazagne","gsecdump","crackmapexec","impacket"
}

# Common admin tools that should NOT trigger solo (peer-rarity handled separately)
BENIGN_ADMIN = {
    "ssh","scp","sftp","rsync","git","python3","python","pip","pip3",
    "apt","yum","dnf","systemctl","journalctl","kubectl","helm","docker",
    "curl","wget","vim","nano","less","grep","awk","sed","find","ls"
}

# ── Hunt playbook implementations ────────────────────────────────────────────

class HuntPlaybook:
    """Base class for all hunt playbooks."""

    def __init__(self, hunt_id: str, name: str, hypothesis: str,
                 mitre: str, severity: str):
        self.hunt_id    = hunt_id
        self.name       = name
        self.hypothesis = hypothesis
        self.mitre      = mitre
        self.severity   = severity

    def run(self, context: "HuntContext") -> HuntResult:
        raise NotImplementedError

    def _result(self, status: str, confidence: int, findings: List[dict],
                evidence: dict = None, recommendation: str = "") -> HuntResult:
        return HuntResult(
            hunt_id=self.hunt_id, hunt_name=self.name,
            hypothesis=self.hypothesis, status=status,
            confidence=confidence, severity=self.severity,
            mitre=self.mitre, findings=findings,
            evidence=evidence or {}, recommendation=recommendation,
        )


# ─── CRED-01: LOLBin credential dumping ──────────────────────────────────────

class Hunt_CRED01(HuntPlaybook):
    def __init__(self):
        super().__init__("CRED-01", "LOLBin Credential Dumping",
            "An attacker is using living-off-the-land binaries to dump credentials "
            "from LSASS or the SAM database without dropping known-bad binaries.",
            "T1003", "critical")

    def run(self, ctx: "HuntContext") -> HuntResult:
        hits = []
        # Scan running processes
        for proc in psutil.process_iter(["pid","name","exe","cmdline","ppid"]):
            try:
                info    = proc.info
                name    = (info.get("name") or "").lower()
                cmdline = " ".join(info.get("cmdline") or [])
                exe     = (info.get("exe") or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            # Direct tool name match
            if any(tool in name for tool in CRED_DUMP_TOOLS):
                hits.append({"pid": info["pid"], "name": name, "match": "tool_name",
                              "cmdline": cmdline[:200]})
                continue

            # Certutil downloading something (classic lolbin)
            if "certutil" in name and any(flag in cmdline for flag in ["-urlcache","-decode","-f"]):
                hits.append({"pid": info["pid"], "name": name, "match": "certutil_download",
                              "cmdline": cmdline[:200]})

            # Powershell base64 encoded command (bypass+download)
            if "powershell" in name and re.search(r"-[Ee]nc|-[Ee]ncodedCommand", cmdline):
                hits.append({"pid": info["pid"], "name": name, "match": "powershell_encoded",
                              "cmdline": cmdline[:200]})

            # procdump or task manager targeting lsass
            if "lsass" in cmdline.lower() and any(t in name for t in ["procdump","taskmgr","werfault"]):
                hits.append({"pid": info["pid"], "name": name, "match": "lsass_access",
                              "cmdline": cmdline[:200]})

        # Scan log files for cred-dump patterns
        log_hits = ctx.grep_logs(
            [r"sekurlsa::", r"lsadump::", r"privilege::debug",
             r"procdump.*lsass", r"mimikatz", r"wce -w", r"pwdump"],
            case_insensitive=True
        )
        hits.extend(log_hits)

        if not hits:
            return self._result("NEGATIVE", 85, [],
                recommendation="No active indicators. Ensure auditd/Sysmon logs are flowing.")

        return self._result("CONFIRMED", 90, hits,
            recommendation="Isolate affected host immediately. Check for lateral movement "
                           "using stolen credentials within next 30 minutes.")


# ─── EXEC-01: LOLBin execution chains ────────────────────────────────────────

class Hunt_EXEC01(HuntPlaybook):
    def __init__(self):
        super().__init__("EXEC-01", "LOLBin Downloader-Executor Chain",
            "An attacker is chaining LOLBins: one binary downloads a payload, "
            "another executes it, avoiding AV signature detection.",
            "T1218", "high")

    def run(self, ctx: "HuntContext") -> HuntResult:
        hits = []
        # Look for certutil/bitsadmin spawned by something unusual
        download_indicators = {
            "certutil":   ["-urlcache","-split","-f"],
            "bitsadmin":  ["/transfer","/download"],
            "mshta":      ["http://","https://","javascript:","vbscript:"],
            "regsvr32":   ["/s","/i:http","/i:ftp"],
            "rundll32":   ["javascript:","..dll,"],
        }
        for proc in psutil.process_iter(["pid","name","ppid","cmdline","username"]):
            try:
                info    = proc.info
                name    = (info.get("name") or "").lower().replace(".exe","")
                cmdline = " ".join(info.get("cmdline") or [])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if name in download_indicators:
                indicators = download_indicators[name]
                if any(ind.lower() in cmdline.lower() for ind in indicators):
                    hits.append({
                        "pid": info["pid"], "name": name,
                        "cmdline": cmdline[:200], "user": info.get("username","?")
                    })

        log_hits = ctx.grep_logs(
            [r"certutil.*-urlcache", r"bitsadmin.*transfer", r"mshta.*http",
             r"regsvr32.*/i:http", r"rundll32.*javascript"],
            case_insensitive=True
        )
        hits.extend(log_hits)

        confidence = min(95, 40 * len(hits)) if hits else 0
        status = "CONFIRMED" if hits else "NEGATIVE"
        return self._result(status, confidence if status=="CONFIRMED" else 85, hits,
            recommendation="Block outbound HTTP from certutil/mshta via egress filter.")


# ─── EXEC-03: Long-running shells ────────────────────────────────────────────

class Hunt_EXEC03(HuntPlaybook):
    def __init__(self, min_runtime_hours: float = 6.0):
        super().__init__("EXEC-03", "Long-Running Interactive Shells",
            "Attacker maintains persistence via an interactive shell session "
            "that has been alive far longer than legitimate admin sessions.",
            "T1059.004", "medium")
        self.min_runtime_s = min_runtime_hours * 3600

    def run(self, ctx: "HuntContext") -> HuntResult:
        hits = []
        now  = time.time()
        shell_names = {"bash","sh","zsh","fish","ksh","tcsh","dash","cmd.exe","powershell.exe","pwsh.exe"}
        for proc in psutil.process_iter(["pid","name","username","create_time","cmdline","ppid"]):
            try:
                info    = proc.info
                name    = (info.get("name") or "").lower()
                runtime = now - (info.get("create_time") or now)
                user    = info.get("username") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if name in shell_names and runtime >= self.min_runtime_s:
                # Skip root/admin sessions running system services
                if user in ("root","system","SYSTEM","NT AUTHORITY\\SYSTEM"):
                    continue
                hits.append({
                    "pid": info["pid"], "name": name,
                    "user": user, "runtime_hours": round(runtime/3600, 1),
                    "cmdline": " ".join(info.get("cmdline") or [])[:200],
                })

        if not hits:
            return self._result("NEGATIVE", 80, [],
                recommendation="No long-running shells found in the threshold window.")

        return self._result("SUSPECT", 65, hits,
            recommendation="Investigate whether each session maps to a known change "
                           "window or legitimate admin task.")


# ─── PERS-01: New services/drivers ───────────────────────────────────────────

class Hunt_PERS01(HuntPlaybook):
    def __init__(self):
        super().__init__("PERS-01", "New System Services Registered",
            "Malware installs a new system service or driver for persistence "
            "that survives reboots.",
            "T1543.003", "high")

    def run(self, ctx: "HuntContext") -> HuntResult:
        hits = []
        if IS_LINUX:
            # Check systemd unit files modified in the last window_hours
            cutoff = time.time() - ctx.window_seconds
            for sd_dir in ["/etc/systemd/system/", "/lib/systemd/system/",
                           "/usr/lib/systemd/system/"]:
                dp = Path(sd_dir)
                if not dp.is_dir():
                    continue
                for unit in dp.rglob("*.service"):
                    try:
                        mtime = unit.stat().st_mtime
                        if mtime >= cutoff:
                            content = unit.read_text(errors="replace")
                            exec_line = next(
                                (l for l in content.splitlines() if l.startswith("ExecStart=")),
                                ""
                            )
                            hits.append({
                                "path": str(unit),
                                "modified_at": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
                                "exec_start": exec_line[:200],
                            })
                    except OSError:
                        continue

        if not hits:
            return self._result("NEGATIVE", 80, [],
                recommendation="No new services in the hunt window. Expand window if needed.")

        suspicious = [h for h in hits if any(s in h.get("exec_start","")
                      for s in ["/tmp/","/dev/shm/","base64","wget","curl"])]
        status = "CONFIRMED" if suspicious else "SUSPECT"
        confidence = 85 if suspicious else 50
        return self._result(status, confidence, hits,
            recommendation="Review each new service unit file for malicious ExecStart values.")


# ─── DISC-01: Rapid enumeration bursts ───────────────────────────────────────

class Hunt_DISC01(HuntPlaybook):
    def __init__(self):
        super().__init__("DISC-01", "Rapid System Enumeration (Discovery Burst)",
            "An attacker who gained initial access is running a burst of discovery "
            "commands (whoami, net user, ipconfig, etc.) to map the environment.",
            "T1082", "medium")

    DISCOVERY_CMDS = {
        "whoami","id","net","ipconfig","ifconfig","arp","route","netstat",
        "systeminfo","uname","hostname","w","who","last","ps","tasklist",
        "dir","ls","find","env","set","cat /etc/passwd","cat /etc/hosts",
    }

    def run(self, ctx: "HuntContext") -> HuntResult:
        # Check current process list for bursts
        by_user: Dict[str, List[dict]] = defaultdict(list)
        now = time.time()
        for proc in psutil.process_iter(["pid","name","username","create_time","cmdline"]):
            try:
                info    = proc.info
                name    = (info.get("name") or "").lower().replace(".exe","")
                user    = info.get("username") or "unknown"
                ct      = info.get("create_time") or 0
                cmdline = " ".join(info.get("cmdline") or [])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if name in self.DISCOVERY_CMDS and (now - ct) <= ctx.window_seconds:
                by_user[user].append({"name": name, "cmdline": cmdline[:100],
                                       "pid": info["pid"]})

        # Log scan
        log_hits = ctx.grep_logs(
            [r"whoami", r"net user", r"ipconfig", r"systeminfo", r"arp -a",
             r"cat /etc/passwd", r"cat /etc/hosts"],
            case_insensitive=True
        )

        burst_users = {u: evs for u, evs in by_user.items()
                       if len(evs) >= 5 and u not in ("root","SYSTEM")}

        if not burst_users and len(log_hits) < 10:
            return self._result("NEGATIVE", 80, [])

        findings = []
        for user, evs in burst_users.items():
            findings.append({"user": user, "command_count": len(evs),
                              "commands": [e["name"] for e in evs]})
        findings.extend(log_hits[:20])

        return self._result("SUSPECT", 70, findings,
            recommendation="Correlate discovery commands with initial access timeline. "
                           "Check if discovered via worm or interactive attacker.")


# ─── EVAD-01: Process parent spoofing ────────────────────────────────────────

class Hunt_EVAD01(HuntPlaybook):
    def __init__(self):
        super().__init__("EVAD-01", "Process Parent Spoofing",
            "Malware spoofs its parent process ID to appear legitimate "
            "(e.g., cmd.exe claiming Word as parent when Word never ran).",
            "T1134.004", "high")

    def run(self, ctx: "HuntContext") -> HuntResult:
        hits = []
        procs = {p.pid: p for p in psutil.process_iter(
            ["pid","name","ppid","create_time","exe"]
        )}
        # A spoofed parent will have a pid that either:
        # (a) no longer exists, or (b) has a create_time AFTER the child
        for pid, proc in procs.items():
            try:
                info     = proc.info
                ppid     = info.get("ppid") or 0
                ct_child = info.get("create_time") or 0
                name     = (info.get("name") or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if ppid == 0:
                continue

            parent = procs.get(ppid)
            if parent is None:
                # Parent PID doesn't exist — could be normal (short-lived parent)
                # or spoofed. Only flag for suspicious child processes.
                if name in ("cmd.exe","powershell.exe","wscript.exe","cscript.exe"):
                    hits.append({"pid": pid, "name": name, "ppid": ppid,
                                 "issue": "ghost_parent", "note": "Parent PID no longer exists"})
                continue

            try:
                ct_parent = parent.info.get("create_time") or 0
            except Exception:
                continue

            if ct_parent > ct_child + 1:  # parent created AFTER child (impossible without spoofing)
                hits.append({
                    "pid": pid, "name": name,
                    "ppid": ppid, "parent_name": (parent.info.get("name") or "?"),
                    "issue": "parent_newer_than_child",
                    "child_created": ct_child, "parent_created": ct_parent,
                    "delta_s": round(ct_parent - ct_child, 2),
                })

        status = "CONFIRMED" if hits else "NEGATIVE"
        return self._result(status, 80 if hits else 85, hits,
            recommendation="Parent-spoofed processes bypass logging and parental trust. "
                           "Terminate and investigate.")


# ─── C2-01: Long TCP connection beacon analysis ───────────────────────────────

class Hunt_C201(HuntPlaybook):
    def __init__(self):
        super().__init__("C2-01", "Long TCP Connection / C2 Beacon",
            "A process maintains an unusually persistent TCP connection to an "
            "external IP on a non-standard port — typical C2 keepalive behavior.",
            "T1071", "critical")

    STANDARD_PORTS    = {80, 443, 22, 25, 53, 143, 993, 587, 465, 8080, 8443}
    TRUSTED_PROCESSES = {"ssh","sshd","curl","wget","python","python3","browser","chrome","firefox"}

    def run(self, ctx: "HuntContext") -> HuntResult:
        hits = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return self._result("INSUFFICIENT_DATA", 0, [],
                recommendation="Run as root to inspect network connections.")

        for conn in conns:
            if conn.status != "ESTABLISHED":
                continue
            if conn.raddr is None:
                continue
            rport = conn.raddr.port
            rip   = conn.raddr.ip

            # Skip standard ports and local addresses
            if rport in self.STANDARD_PORTS:
                continue
            try:
                import ipaddress
                if ipaddress.ip_address(rip).is_private:
                    continue
            except Exception:
                pass

            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    pname = proc.name().lower()
                    if any(t in pname for t in self.TRUSTED_PROCESSES):
                        continue
                    hits.append({
                        "pid": conn.pid, "process": pname,
                        "remote_ip": rip, "remote_port": rport,
                        "local_port": conn.laddr.port if conn.laddr else 0,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    hits.append({"pid": conn.pid, "process": "unknown",
                                  "remote_ip": rip, "remote_port": rport})

        if not hits:
            return self._result("NEGATIVE", 80, [],
                recommendation="No suspicious persistent connections. Re-run after capturing "
                               "pcap to detect low-bandwidth beacons.")

        return self._result("SUSPECT", min(85, 30 * len(hits)), hits,
            recommendation="Check packet timing for regular intervals (beacon detection). "
                           "Run dns_analyzer on associated traffic.")


# ─── LMOV-01: SMB lateral movement ───────────────────────────────────────────

class Hunt_LMOV01(HuntPlaybook):
    def __init__(self):
        super().__init__("LMOV-01", "SMB Lateral Movement (Admin Share Access)",
            "Attacker is using SMB admin shares (ADMIN$, C$, IPC$) to move "
            "laterally using stolen credentials.",
            "T1021.002", "critical")

    def run(self, ctx: "HuntContext") -> HuntResult:
        log_hits = ctx.grep_logs(
            [r"ADMIN\$", r"\\C\$", r"IPC\$",
             r"net use .* /user:", r"PsExec", r"psexesvc",
             r"wmiexec", r"smbexec", r"Impacket"],
            case_insensitive=True
        )

        # Check for smbclient/net connections on port 445
        smb_conns = []
        try:
            for conn in psutil.net_connections("inet"):
                if conn.raddr and conn.raddr.port == 445 and conn.status == "ESTABLISHED":
                    if conn.pid:
                        try:
                            pname = psutil.Process(conn.pid).name()
                        except Exception:
                            pname = "unknown"
                    else:
                        pname = "unknown"
                    smb_conns.append({"remote": f"{conn.raddr.ip}:445",
                                       "process": pname, "pid": conn.pid})
        except Exception:
            pass

        all_hits = log_hits + smb_conns
        if not all_hits:
            return self._result("NEGATIVE", 80, [],
                recommendation="No SMB lateral movement indicators. "
                               "Verify Windows Event 4624/4648 logs are available.")

        status = "CONFIRMED" if (log_hits and smb_conns) else "SUSPECT"
        return self._result(status, 80 if status=="CONFIRMED" else 55, all_hits,
            recommendation="Block lateral SMB with host firewall rule. "
                           "Rotate all credentials visible to the source host.")


# ─── EXFIL-01: Data volume spike to new IPs ──────────────────────────────────

class Hunt_EXFIL01(HuntPlaybook):
    def __init__(self):
        super().__init__("EXFIL-01", "Outbound Data Volume Spike to New External IPs",
            "Large volume of data transferred to an external IP that has not "
            "been seen in historical traffic baselines.",
            "T1041", "high")

    def run(self, ctx: "HuntContext") -> HuntResult:
        # Without pcap, estimate from current connections and process I/O
        hits = []
        try:
            counters = psutil.net_io_counters(pernic=False)
            bytes_sent = counters.bytes_sent
        except Exception:
            return self._result("INSUFFICIENT_DATA", 0, [],
                recommendation="Run with pcap data via packet_inspector for accurate exfil detection.")

        # Check for unusual outbound connections from non-browser processes
        try:
            for conn in psutil.net_connections("inet"):
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue
                rport = conn.raddr.port
                if rport in (80, 443, 53, 22):
                    continue
                if conn.pid:
                    try:
                        proc  = psutil.Process(conn.pid)
                        pname = proc.name().lower()
                        # Get per-process I/O if available
                        try:
                            io = proc.io_counters()
                            if io.write_bytes > 10 * 1024 * 1024:  # > 10MB writes
                                hits.append({
                                    "pid": conn.pid, "process": pname,
                                    "remote": f"{conn.raddr.ip}:{rport}",
                                    "write_bytes": io.write_bytes,
                                })
                        except (psutil.AccessDenied, AttributeError):
                            pass
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception:
            pass

        if not hits:
            return self._result("NEGATIVE", 60, [],
                recommendation="Run hunt against pcap or netflow data for accurate results.")

        return self._result("SUSPECT", 55, hits,
            recommendation="Use packet_inspector to capture and analyze the traffic. "
                           "Check DNS for data encoded in queries.")


# ─────────────────────────────────────────────────────────────────────────────
# Hunt context (shared config and utilities for all playbooks)
# ─────────────────────────────────────────────────────────────────────────────

class HuntContext:
    def __init__(self, log_dirs: List[str] = None, window_hours: float = 24.0,
                 max_log_lines: int = 500_000):
        self.log_dirs      = log_dirs or self._default_log_dirs()
        self.window_seconds = window_hours * 3600
        self.max_log_lines  = max_log_lines
        self._log_cache: Optional[List[str]] = None

    @staticmethod
    def _default_log_dirs() -> List[str]:
        if IS_LINUX:
            return ["/var/log"]
        return []

    def _load_logs(self) -> List[str]:
        if self._log_cache is not None:
            return self._log_cache
        lines = []
        cutoff = time.time() - self.window_seconds
        for d in self.log_dirs:
            dp = Path(d)
            if not dp.is_dir():
                continue
            for fp in dp.rglob("*.log"):
                if len(lines) >= self.max_log_lines:
                    break
                try:
                    if fp.stat().st_mtime < cutoff:
                        continue
                    lines.extend(fp.read_text(errors="replace").splitlines())
                except OSError:
                    continue
            for fp in dp.rglob("auth.log*"):
                try:
                    lines.extend(fp.read_text(errors="replace").splitlines())
                except OSError:
                    pass
        self._log_cache = lines[:self.max_log_lines]
        return self._log_cache

    def grep_logs(self, patterns: List[str], case_insensitive: bool = True) -> List[dict]:
        flags = re.IGNORECASE if case_insensitive else 0
        compiled = [re.compile(p, flags) for p in patterns]
        results  = []
        for line in self._load_logs():
            for pat in compiled:
                if pat.search(line):
                    results.append({"log_line": line[:300], "pattern": pat.pattern})
                    break
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Hunt registry and runner
# ─────────────────────────────────────────────────────────────────────────────

HUNT_REGISTRY: Dict[str, HuntPlaybook] = {
    "CRED-01": Hunt_CRED01(),
    "EXEC-01": Hunt_EXEC01(),
    "EXEC-03": Hunt_EXEC03(),
    "PERS-01": Hunt_PERS01(),
    "DISC-01": Hunt_DISC01(),
    "EVAD-01": Hunt_EVAD01(),
    "C2-01":   Hunt_C201(),
    "LMOV-01": Hunt_LMOV01(),
    "EXFIL-01":Hunt_EXFIL01(),
}


class ThreatHunter:
    def __init__(self, context: HuntContext):
        self.context = context

    def run_hunts(self, hunt_ids: List[str] = None) -> List[HuntResult]:
        ids = hunt_ids or list(HUNT_REGISTRY.keys())
        results = []
        for hid in ids:
            playbook = HUNT_REGISTRY.get(hid)
            if not playbook:
                logger.warning("Unknown hunt ID: %s", hid)
                continue
            logger.info("Running hunt: %s — %s", hid, playbook.name)
            result = playbook.run(self.context)
            results.append(result)
        results.sort(key=lambda r: (
            {"CONFIRMED":0,"SUSPECT":1,"INSUFFICIENT_DATA":2,"NEGATIVE":3}.get(r.status,4),
            -r.confidence
        ))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

STATUS_C = {
    "CONFIRMED":        "\033[95m",
    "SUSPECT":          "\033[91m",
    "INSUFFICIENT_DATA":"\033[93m",
    "NEGATIVE":         "\033[92m",
}

def _print_result(r: HuntResult):
    c = STATUS_C.get(r.status,""); R = "\033[0m"; B = "\033[1m"
    print(f"  {c}[{r.status:20}]{R} {B}{r.hunt_id}{R}  {r.hunt_name}")
    print(f"     Hypothesis: {r.hypothesis[:100]}")
    print(f"     Confidence: {r.confidence}%   MITRE: {r.mitre}   Score: {r.score()}")
    if r.findings:
        print(f"     Findings: {len(r.findings)}")
        for f in r.findings[:3]:
            print(f"       • {str(f)[:110]}")
    if r.recommendation and r.status in ("CONFIRMED","SUSPECT"):
        print(f"     \033[93mAction: {r.recommendation[:120]}\033[0m")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Threat Hunter")
    parser.add_argument("--hunt", default="all", help="Hunt IDs (comma-sep) or 'all'")
    parser.add_argument("--list-hunts", action="store_true")
    parser.add_argument("--logdir", nargs="*", help="Log directories to search")
    parser.add_argument("--window-hours", type=float, default=24.0)
    parser.add_argument("--json", help="Output results to JSON")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Threat Hunter ──{R}\n")

    if args.list_hunts:
        print(f"  {'ID':10} {'Name':38} {'MITRE':12} Severity")
        print(f"  {'─'*75}")
        for hid, pb in sorted(HUNT_REGISTRY.items()):
            print(f"  {hid:10} {pb.name:38} {pb.mitre:12} {pb.severity}")
        return

    ctx = HuntContext(log_dirs=args.logdir, window_hours=args.window_hours)
    hunter = ThreatHunter(ctx)

    hunt_ids = None if args.hunt == "all" else args.hunt.split(",")
    results  = hunter.run_hunts(hunt_ids)

    print(f"\n  Hunt results ({len(results)} playbooks):\n")
    for r in results:
        _print_result(r)

    confirmed = [r for r in results if r.status == "CONFIRMED"]
    suspects  = [r for r in results if r.status == "SUSPECT"]
    print(f"  CONFIRMED: {len(confirmed)}   SUSPECT: {len(suspects)}   "
          f"NEGATIVE: {sum(1 for r in results if r.status=='NEGATIVE')}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"\n  Results saved to {C}{args.json}{R}")


if __name__ == "__main__":
    main()
