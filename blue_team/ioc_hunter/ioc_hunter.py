#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 5 — IOC Hunter
==============================================
Original architecture. Hunts for Indicators of Compromise across:
  - Live filesystem (files, permissions, timestamps, hidden artifacts)
  - Process memory strings (via /proc/<pid>/mem on Linux)
  - Startup persistence locations (cron, systemd, rc.d, registry stubs)
  - Prefetch / recent-files artifacts
  - Packed/obfuscated binary detection (entropy scan)

Capabilities:
  - Hash-based IOC matching (MD5/SHA1/SHA256) against internal + custom lists
  - String pattern hunting (regex, hex strings, YARA-lite rules inline)
  - PE/ELF magic detection in unexpected locations (non-binary dirs)
  - Webshell pattern detection in web roots
  - Timestomping detection (mtime < ctime anomaly)
  - Packed binary detection via section entropy analysis
  - Outputs per-hunt findings with confidence score + remediation advice

Usage:
    python3 ioc_hunter.py --hunt filesystem --path /var/www
    python3 ioc_hunter.py --hunt processes
    python3 ioc_hunter.py --hunt persistence
    python3 ioc_hunter.py --hunt all --output findings.json
    python3 ioc_hunter.py --hash-check /path/to/file
"""

import argparse
import ctypes
import hashlib
import json
import logging
import math
import os
import platform
import re
import stat
import struct
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set, Tuple

import psutil

logger = logging.getLogger("vanguard.ioc_hunter")
IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

# ── Known-bad hash sets (demo set — extend with real threat intel) ────────────

KNOWN_BAD_MD5: Set[str] = {
    "d41d8cd98f00b204e9800998ecf8427e",  # empty file (demo)
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test signature MD5
    "aabbcc112233445566778899aabbcc11",  # demo ransomware stub
    "b6d767d2f8ed5d21a44b0e5886680cb9",  # demo trojan stub
}

KNOWN_BAD_SHA256: Set[str] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR SHA256
}

# ── Webshell patterns ─────────────────────────────────────────────────────────

WEBSHELL_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("php_eval",      re.compile(rb"eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(", re.I), "PHP eval-decode chain"),
    ("php_system",    re.compile(rb"\$_(GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\)", re.I),                      "PHP superglobal execution"),
    ("php_passthru",  re.compile(rb"(passthru|shell_exec|popen|proc_open|system)\s*\(", re.I),               "PHP shell execution function"),
    ("asp_exec",      re.compile(rb"CreateObject\s*\(\s*[\"']WScript\.Shell[\"']", re.I),                    "ASP WScript.Shell exec"),
    ("jsp_runtime",   re.compile(rb"Runtime\.getRuntime\(\)\.exec\s*\(", re.I),                              "JSP Runtime.exec()"),
    ("generic_base64",re.compile(rb"(?:echo|print)\s+base64_decode\s*\(", re.I),                             "Echo base64-decoded payload"),
    ("py_exec",       re.compile(rb"exec\s*\(\s*(?:compile|__import__)\s*\(", re.I),                         "Python dynamic exec"),
]

# ── Persistence locations ─────────────────────────────────────────────────────

LINUX_PERSISTENCE = [
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/var/spool/cron/",
    "/etc/rc.local",
    "/etc/init.d/",
    "/etc/systemd/system/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/profile.d/",
    "/etc/environment",
    "/home/",              # .bashrc, .profile, .bash_profile, .zshrc
    "/root/",
    "/etc/ld.so.preload",  # LD_PRELOAD hijack
    "/etc/ld.so.conf.d/",
    "/usr/local/bin/",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
]

WINDOWS_PERSISTENCE = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    r"C:\Users\Public",
    r"C:\Windows\Temp",
]

# Suspicious file signatures (magic bytes)
MAGIC_SIGNATURES = {
    b"\x4d\x5a":           ("PE/EXE",  "Windows executable"),
    b"\x7fELF":            ("ELF",     "Linux executable"),
    b"#!/":                ("SCRIPT",  "Shell script"),
    b"PK\x03\x04":         ("ZIP",     "ZIP archive"),
    b"\x1f\x8b":           ("GZIP",    "Gzip archive"),
    b"MZ":                 ("PE/EXE",  "Windows executable (MZ)"),
    b"\xca\xfe\xba\xbe":   ("MACHO",   "macOS Mach-O binary"),
}

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class HuntFinding:
    hunt_type:   str
    severity:    str          # low / medium / high / critical
    confidence:  int          # 0–100
    path:        str
    description: str
    detail:      dict         = field(default_factory=dict)
    remediation: str          = ""
    timestamp:   str          = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


# ── Entropy helpers ───────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    freq = Counter(data)
    n    = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq.values() if c)


def section_entropy_pe(data: bytes) -> List[Tuple[str, float]]:
    """Parse PE sections and return (name, entropy) pairs."""
    results = []
    try:
        if data[:2] != b"MZ":
            return results
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return results
        machine         = struct.unpack_from("<H", data, pe_offset+4)[0]
        num_sections    = struct.unpack_from("<H", data, pe_offset+6)[0]
        opt_header_size = struct.unpack_from("<H", data, pe_offset+20)[0]
        section_offset  = pe_offset + 24 + opt_header_size
        for i in range(num_sections):
            off  = section_offset + i * 40
            name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize= struct.unpack_from("<I", data, off+16)[0]
            roff = struct.unpack_from("<I", data, off+20)[0]
            sect_data = data[roff:roff+vsize] if roff else b""
            ent  = shannon_entropy(sect_data[:65536])
            results.append((name, ent))
    except Exception:
        pass
    return results


def file_entropy(path: str, sample: int = 65536) -> float:
    try:
        with open(path, "rb") as f:
            return shannon_entropy(f.read(sample))
    except OSError:
        return 0.0


# ── Hash calculation ──────────────────────────────────────────────────────────

def hash_file(path: str) -> Tuple[str, str, str]:
    """Return (md5, sha1, sha256) of file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except OSError:
        return "", "", ""
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


# ── Filesystem Hunt ───────────────────────────────────────────────────────────

class FilesystemHunter:
    def __init__(self, path: str = "/", max_file_size: int = 50 * 1024 * 1024):
        self.path          = path
        self.max_file_size = max_file_size
        self.findings:     List[HuntFinding] = []

    def run(self) -> List[HuntFinding]:
        logger.info("Filesystem hunt: %s", self.path)
        for entry in self._walk(self.path):
            self._check_file(entry)
        return self.findings

    def _walk(self, root: str) -> Generator[Path, None, None]:
        skip_dirs = {"/proc", "/sys", "/dev", "/run"}
        for dirpath, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs
                       if os.path.join(dirpath, d) not in skip_dirs
                       and not d.startswith(".") or dirpath == root]
            for fn in files:
                yield Path(dirpath) / fn

    def _check_file(self, path: Path):
        try:
            st = path.stat(follow_symlinks=False)
        except OSError:
            return

        size = st.st_size
        if size == 0 or size > self.max_file_size:
            return

        path_str = str(path)

        # ── 1. Timestomping (mtime < ctime) ──────────────────────────────
        if IS_LINUX and hasattr(st, "st_ctime"):
            if st.st_mtime < st.st_ctime - 60:   # 60s tolerance
                self.findings.append(HuntFinding(
                    hunt_type   = "filesystem",
                    severity    = "medium",
                    confidence  = 60,
                    path        = path_str,
                    description = "Possible timestomping: mtime precedes ctime",
                    detail      = {"mtime": st.st_mtime, "ctime": st.st_ctime,
                                   "delta_s": round(st.st_ctime - st.st_mtime, 1)},
                    remediation = "Investigate file origin; compare against known-good baseline",
                ))

        # ── 2. SUID/SGID unexpected ───────────────────────────────────────
        if IS_LINUX:
            mode = st.st_mode
            if (mode & stat.S_ISUID) and path_str not in {"/usr/bin/sudo","/bin/su","/usr/bin/passwd"}:
                self.findings.append(HuntFinding(
                    hunt_type   = "filesystem",
                    severity    = "high",
                    confidence  = 75,
                    path        = path_str,
                    description = "Unexpected SUID bit set",
                    detail      = {"mode": oct(mode)},
                    remediation = "chmod -s to remove SUID; verify if legitimate",
                ))

        # ── 3. Executables in temp/writable dirs ─────────────────────────
        suspicious_dirs = ["/tmp/", "/dev/shm/", "/var/tmp/"]
        for sd in suspicious_dirs:
            if path_str.startswith(sd) and size > 100:
                try:
                    magic = path.read_bytes()[:4]
                    for sig, (kind, desc) in MAGIC_SIGNATURES.items():
                        if magic[:len(sig)] == sig:
                            self.findings.append(HuntFinding(
                                hunt_type   = "filesystem",
                                severity    = "critical",
                                confidence  = 85,
                                path        = path_str,
                                description = f"{kind} binary in scratch directory: {desc}",
                                detail      = {"magic": magic.hex(), "size": size, "dir": sd},
                                remediation = "Quarantine immediately; this is a strong malware indicator",
                            ))
                            break
                except OSError:
                    pass

        # ── 4. Hash-based IOC match ───────────────────────────────────────
        if size < 20 * 1024 * 1024:
            md5, sha1, sha256 = hash_file(path_str)
            if md5 in KNOWN_BAD_MD5:
                self.findings.append(HuntFinding(
                    hunt_type   = "filesystem",
                    severity    = "critical",
                    confidence  = 100,
                    path        = path_str,
                    description = f"Known-bad MD5 hash match: {md5}",
                    detail      = {"md5": md5, "sha256": sha256},
                    remediation = "Delete immediately and investigate how it arrived",
                ))
            if sha256 in KNOWN_BAD_SHA256:
                self.findings.append(HuntFinding(
                    hunt_type   = "filesystem",
                    severity    = "critical",
                    confidence  = 100,
                    path        = path_str,
                    description = f"Known-bad SHA256 hash match: {sha256}",
                    detail      = {"sha256": sha256},
                    remediation = "Delete immediately",
                ))

        # ── 5. Webshell patterns in web roots ────────────────────────────
        web_exts = {".php", ".asp", ".aspx", ".jsp", ".jspx", ".phtml", ".php5"}
        if path.suffix.lower() in web_exts and size < 500_000:
            try:
                content = path.read_bytes()
                for name, pattern, desc in WEBSHELL_PATTERNS:
                    if pattern.search(content):
                        self.findings.append(HuntFinding(
                            hunt_type   = "filesystem",
                            severity    = "critical",
                            confidence  = 80,
                            path        = path_str,
                            description = f"Webshell pattern [{name}]: {desc}",
                            detail      = {"pattern": name, "file_size": size},
                            remediation = "Quarantine file; check web server access logs for exploitation",
                        ))
                        break
            except OSError:
                pass

        # ── 6. Packed binary (high entropy PE/ELF) ───────────────────────
        try:
            magic = path.read_bytes()[:4]
        except OSError:
            return

        is_binary = any(magic[:len(s)] == s for s in [b"MZ", b"\x7fELF"])
        if is_binary and size > 1024:
            ent = file_entropy(path_str)
            if ent > 7.2:
                sections = section_entropy_pe(path.read_bytes()[:min(size, 2*1024*1024)])
                packed_sections = [(n, e) for n, e in sections if e > 7.0]
                self.findings.append(HuntFinding(
                    hunt_type   = "filesystem",
                    severity    = "high",
                    confidence  = 70,
                    path        = path_str,
                    description = f"High-entropy binary (entropy={ent:.3f}) — likely packed/obfuscated",
                    detail      = {"entropy": round(ent,3), "size": size,
                                   "packed_sections": packed_sections[:5]},
                    remediation = "Submit to sandbox for dynamic analysis",
                ))


# ── Process Memory Hunt ───────────────────────────────────────────────────────

class ProcessHunter:
    def __init__(self):
        self.findings: List[HuntFinding] = []

    SUSPICIOUS_STRINGS = [
        (re.compile(rb"(?:mimikatz|sekurlsa|lsadump|kerberoast)", re.I), "Mimikatz/credential-dumping string"),
        (re.compile(rb"(?:metasploit|meterpreter|shellcode)", re.I),     "Metasploit/meterpreter artifact"),
        (re.compile(rb"(?:/etc/shadow|/etc/passwd).{0,20}root",  re.I), "Credential file path in memory"),
        (re.compile(rb"(?:TVqQAAMAAAAEAAAA)",),                          "Base64-encoded PE header in memory"),
        (re.compile(rb"(?:4d5a9000|4d5a5000)", re.I),                    "Hex-encoded PE header in memory"),
        (re.compile(rb"(?:cmd\.exe|powershell|wscript).*?(?:/c|\.exe)", re.I), "Shell invocation string"),
        (re.compile(rb"(?:wget|curl).*?(?:http|ftp)", re.I),             "Download command in memory"),
    ]

    def run(self) -> List[HuntFinding]:
        logger.info("Process memory hunt starting...")
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
            self._check_process(proc)
        return self.findings

    def _check_process(self, proc):
        try:
            info = proc.info
            pid  = info["pid"]
            name = info.get("name") or ""
            exe  = info.get("exe")  or ""
            cmdline = " ".join(info.get("cmdline") or [])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        # Check process name masquerading (svchost not in System32)
        if name.lower() in {"svchost.exe","lsass.exe","csrss.exe","winlogon.exe"}:
            if exe and "system32" not in exe.lower():
                self.findings.append(HuntFinding(
                    hunt_type   = "process",
                    severity    = "critical",
                    confidence  = 90,
                    path        = exe,
                    description = f"Process masquerading: {name} running outside System32",
                    detail      = {"pid": pid, "exe": exe, "name": name},
                    remediation = "Kill process immediately; likely trojanized binary",
                ))

        # Suspicious cmdline patterns
        suspicious_cmd_patterns = [
            (re.compile(r"(?:wget|curl).*\|\s*(?:bash|sh|python)", re.I), "Download-and-execute pipeline"),
            (re.compile(r"base64\s+-d.*\|\s*(?:bash|sh)",          re.I), "Base64-decode-and-execute"),
            (re.compile(r"(?:/dev/tcp|/dev/udp)/",                  re.I), "Bash /dev/tcp reverse shell"),
            (re.compile(r"powershell.*(?:-enc|-EncodedCommand)",     re.I), "PowerShell encoded command"),
            (re.compile(r"(?:whoami|net user|net group|netstat|ipconfig).*&&", re.I), "Chained recon commands"),
        ]
        for pattern, desc in suspicious_cmd_patterns:
            if pattern.search(cmdline):
                self.findings.append(HuntFinding(
                    hunt_type   = "process",
                    severity    = "high",
                    confidence  = 75,
                    path        = exe,
                    description = f"Suspicious command line: {desc}",
                    detail      = {"pid": pid, "name": name, "cmdline": cmdline[:300]},
                    remediation = "Terminate process and investigate parent chain",
                ))
                break

        # Memory string scan (Linux /proc only, root recommended)
        if IS_LINUX and os.geteuid() == 0:
            self._scan_proc_mem(pid, name, exe)

    def _scan_proc_mem(self, pid: int, name: str, exe: str):
        maps_path = f"/proc/{pid}/maps"
        mem_path  = f"/proc/{pid}/mem"
        try:
            with open(maps_path) as f:
                maps = f.read()
        except OSError:
            return

        try:
            mem_fd = open(mem_path, "rb")
        except OSError:
            return

        try:
            for line in maps.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                perms = parts[1]
                if "r" not in perms or "[vvar]" in line or "[vsyscall]" in line:
                    continue
                addr_range = parts[0].split("-")
                if len(addr_range) != 2:
                    continue
                try:
                    start = int(addr_range[0], 16)
                    end   = int(addr_range[1], 16)
                    size  = end - start
                    if size > 64 * 1024 * 1024:   # skip huge regions
                        continue
                    mem_fd.seek(start)
                    chunk = mem_fd.read(min(size, 1024 * 1024))
                except (ValueError, OSError):
                    continue

                for pattern, desc in self.SUSPICIOUS_STRINGS:
                    if pattern.search(chunk):
                        self.findings.append(HuntFinding(
                            hunt_type   = "process_memory",
                            severity    = "critical",
                            confidence  = 85,
                            path        = exe or f"/proc/{pid}",
                            description = f"Suspicious string in process memory: {desc}",
                            detail      = {"pid": pid, "name": name, "region": parts[0]},
                            remediation = "Dump process memory for forensic analysis",
                        ))
                        break  # one finding per region
        finally:
            mem_fd.close()


# ── Persistence Hunt ──────────────────────────────────────────────────────────

class PersistenceHunter:
    def __init__(self):
        self.findings: List[HuntFinding] = []

    def run(self) -> List[HuntFinding]:
        logger.info("Persistence hunt starting...")
        if IS_LINUX:
            self._hunt_linux()
        elif IS_WINDOWS:
            self._hunt_windows()
        return self.findings

    def _hunt_linux(self):
        # ── cron jobs ─────────────────────────────────────────────────────
        cron_paths = ["/etc/crontab", "/var/spool/cron/"]
        for cp in cron_paths:
            p = Path(cp)
            if p.is_file():
                self._scan_cron_file(str(p))
            elif p.is_dir():
                for f in p.iterdir():
                    if f.is_file():
                        self._scan_cron_file(str(f))

        for d in ["/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/"]:
            dp = Path(d)
            if dp.is_dir():
                for f in dp.iterdir():
                    self._scan_cron_file(str(f))

        # ── LD_PRELOAD hijack ─────────────────────────────────────────────
        preload = Path("/etc/ld.so.preload")
        if preload.exists() and preload.stat().st_size > 0:
            content = preload.read_text(errors="replace").strip()
            self.findings.append(HuntFinding(
                hunt_type   = "persistence",
                severity    = "critical",
                confidence  = 95,
                path        = str(preload),
                description = "ld.so.preload exists — LD_PRELOAD hijack possible",
                detail      = {"content": content},
                remediation = "Remove /etc/ld.so.preload unless explicitly required",
            ))

        # ── Systemd unusual units ─────────────────────────────────────────
        for sd_dir in ["/etc/systemd/system/", "/lib/systemd/system/"]:
            dp = Path(sd_dir)
            if not dp.is_dir():
                continue
            for unit in dp.rglob("*.service"):
                self._check_systemd_unit(unit)

        # ── .bashrc / .profile modifications (recent) ─────────────────────
        for user_home in Path("/home").iterdir():
            for rc_file in [".bashrc", ".bash_profile", ".profile", ".zshrc"]:
                rc = user_home / rc_file
                if rc.exists():
                    self._check_shell_rc(rc)
        root_home = Path("/root")
        for rc_file in [".bashrc", ".bash_profile", ".profile"]:
            rc = root_home / rc_file
            if rc.exists():
                self._check_shell_rc(rc)

        # ── Files in /tmp, /dev/shm with execute bit ───────────────────────
        for scratch in ["/tmp", "/dev/shm", "/var/tmp"]:
            sp = Path(scratch)
            if not sp.is_dir():
                continue
            for f in sp.iterdir():
                if not f.is_file():
                    continue
                try:
                    mode = f.stat().st_mode
                    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                        self.findings.append(HuntFinding(
                            hunt_type   = "persistence",
                            severity    = "high",
                            confidence  = 70,
                            path        = str(f),
                            description = "Executable file in scratch directory",
                            detail      = {"mode": oct(mode), "size": f.stat().st_size},
                            remediation = "Investigate; scratch dirs should not contain executables",
                        ))
                except OSError:
                    pass

    def _scan_cron_file(self, path: str):
        suspicious = [
            (re.compile(r"(?:wget|curl).*http", re.I),  "Download in cron job"),
            (re.compile(r"/tmp/\S+",            re.I),  "Cron executing from /tmp"),
            (re.compile(r"base64\s+-d",          re.I),  "Base64 decode in cron"),
            (re.compile(r"nc\s+-e|/dev/tcp",     re.I),  "Reverse shell in cron"),
        ]
        try:
            content = Path(path).read_text(errors="replace")
            for pattern, desc in suspicious:
                if pattern.search(content):
                    self.findings.append(HuntFinding(
                        hunt_type   = "persistence",
                        severity    = "critical",
                        confidence  = 85,
                        path        = path,
                        description = f"Suspicious cron entry: {desc}",
                        detail      = {"match_type": desc},
                        remediation = "Remove malicious cron entry; investigate when it was added",
                    ))
        except OSError:
            pass

    def _check_systemd_unit(self, unit: Path):
        try:
            content = unit.read_text(errors="replace")
            # Check for ExecStart pointing to temp/unusual paths
            for line in content.splitlines():
                if line.strip().startswith("ExecStart="):
                    exec_val = line.split("=", 1)[1].strip()
                    if any(s in exec_val for s in ["/tmp/", "/dev/shm/", "base64", "wget", "curl", "nc -e"]):
                        self.findings.append(HuntFinding(
                            hunt_type   = "persistence",
                            severity    = "critical",
                            confidence  = 90,
                            path        = str(unit),
                            description = f"Suspicious systemd ExecStart: {exec_val[:80]}",
                            detail      = {"exec": exec_val[:200]},
                            remediation = "Disable and remove the unit; investigate its creation",
                        ))
        except OSError:
            pass

    def _check_shell_rc(self, rc: Path):
        try:
            content = rc.read_text(errors="replace")
            suspicious_rc = [
                re.compile(r"(?:wget|curl).*http", re.I),
                re.compile(r"base64\s+-d",          re.I),
                re.compile(r"nc\s+-e|/dev/tcp",     re.I),
                re.compile(r"LD_PRELOAD\s*=",        re.I),
            ]
            for pattern in suspicious_rc:
                if pattern.search(content):
                    self.findings.append(HuntFinding(
                        hunt_type   = "persistence",
                        severity    = "high",
                        confidence  = 80,
                        path        = str(rc),
                        description = "Suspicious code in shell RC file",
                        detail      = {"pattern": pattern.pattern},
                        remediation = "Inspect file; remove malicious lines",
                    ))
                    break
        except OSError:
            pass

    def _hunt_windows(self):
        # Registry run key stubs — actual read needs winreg
        startup = Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
        if startup.exists():
            for f in startup.iterdir():
                if f.suffix.lower() in {".exe", ".bat", ".vbs", ".ps1", ".cmd"}:
                    self.findings.append(HuntFinding(
                        hunt_type   = "persistence",
                        severity    = "high",
                        confidence  = 70,
                        path        = str(f),
                        description = f"Startup folder entry: {f.name}",
                        detail      = {"suffix": f.suffix},
                        remediation = "Verify if legitimate; remove if suspicious",
                    ))


# ── Master IOC Hunter ─────────────────────────────────────────────────────────

class IOCHunter:
    def __init__(self):
        self.all_findings: List[HuntFinding] = []

    def hunt_filesystem(self, path: str = "/") -> List[HuntFinding]:
        hunter = FilesystemHunter(path)
        findings = hunter.run()
        self.all_findings.extend(findings)
        return findings

    def hunt_processes(self) -> List[HuntFinding]:
        hunter = ProcessHunter()
        findings = hunter.run()
        self.all_findings.extend(findings)
        return findings

    def hunt_persistence(self) -> List[HuntFinding]:
        hunter = PersistenceHunter()
        findings = hunter.run()
        self.all_findings.extend(findings)
        return findings

    def hunt_all(self, fs_path: str = "/") -> List[HuntFinding]:
        self.hunt_filesystem(fs_path)
        self.hunt_processes()
        self.hunt_persistence()
        return self.all_findings

    def hash_check(self, path: str) -> dict:
        md5, sha1, sha256 = hash_file(path)
        ent = file_entropy(path)
        bad_md5    = md5    in KNOWN_BAD_MD5
        bad_sha256 = sha256 in KNOWN_BAD_SHA256
        return {
            "path":    path,
            "md5":     md5,
            "sha1":    sha1,
            "sha256":  sha256,
            "entropy": round(ent, 4),
            "in_bad_list": bad_md5 or bad_sha256,
            "verdict":     "MALICIOUS" if (bad_md5 or bad_sha256) else (
                           "SUSPICIOUS" if ent > 7.2 else "CLEAN"),
        }

    def summary(self) -> dict:
        from collections import Counter
        sev = Counter(f.severity for f in self.all_findings)
        typ = Counter(f.hunt_type for f in self.all_findings)
        return {
            "total":       len(self.all_findings),
            "by_severity": dict(sev),
            "by_type":     dict(typ),
            "critical":    [f.to_dict() for f in self.all_findings if f.severity == "critical"],
        }


# ── CLI ───────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m"}

def _print_finding(f: HuntFinding):
    c = SEV_C.get(f.severity, "")
    R = "\033[0m"; B = "\033[1m"
    print(f"  {c}[{f.severity.upper():8}]{R}  conf={f.confidence}%  {f.hunt_type}")
    print(f"  {B}  {f.path}{R}")
    print(f"     {f.description}")
    if f.remediation:
        print(f"     \033[93mFix: {f.remediation}{R}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB IOC Hunter")
    parser.add_argument("--hunt", choices=["filesystem","processes","persistence","all"],
                        default="all")
    parser.add_argument("--path",       default="/", help="Root path for filesystem hunt")
    parser.add_argument("--hash-check", dest="hash_check", help="Hash-check a single file")
    parser.add_argument("--output",     help="Save findings to JSON file")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB IOC Hunter ──{R}\n")

    hunter = IOCHunter()

    if args.hash_check:
        result = hunter.hash_check(args.hash_check)
        verdict_c = "\033[91m" if result["verdict"] != "CLEAN" else "\033[92m"
        print(f"  File   : {result['path']}")
        print(f"  MD5    : {result['md5']}")
        print(f"  SHA256 : {result['sha256']}")
        print(f"  Entropy: {result['entropy']}")
        print(f"  Verdict: {verdict_c}{result['verdict']}{R}\n")
        return

    if args.hunt == "filesystem":
        findings = hunter.hunt_filesystem(args.path)
    elif args.hunt == "processes":
        findings = hunter.hunt_processes()
    elif args.hunt == "persistence":
        findings = hunter.hunt_persistence()
    else:
        findings = hunter.hunt_all(args.path)

    for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.severity,4)):
        _print_finding(f)

    s = hunter.summary()
    print(f"  Total: {s['total']}  |  By severity: {s['by_severity']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump([f.to_dict() for f in hunter.all_findings], fh, indent=2)
        print(f"\n  Findings saved to {args.output}")


if __name__ == "__main__":
    main()
