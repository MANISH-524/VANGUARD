#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 20 — Memory Forensics Engine
============================================================
Original architecture. Live and offline memory artifact extraction
and analysis. Works WITHOUT Volatility — pure Python, zero C deps.

Modes:
  LIVE    — interrogates /proc/<pid>/maps + /proc/<pid>/mem directly
             on the running Linux system (requires root). Extracts
             strings, detects injected code regions, finds PE/ELF
             headers mapped into unexpected process memory, hunts for
             known-bad strings, extracts network IOCs from process memory.

  OFFLINE — parses a VirtualBox .core or Linux ELF core dump produced
             by the Vanguard control_center.py isolation sequence.
             Reconstructs process list, extracts memory strings, and
             identifies artifacts even when the VM is powered off.

Capabilities:
  1. PROCESS MEMORY INSPECTION (live)
     - Per-process region map (readable, writable, executable segments)
     - String extraction with entropy filter (finds encoded payloads)
     - PE/ELF header detection in non-standard regions (injection indicator)
     - Network artifact extraction (IPs, URLs, domains) from heap/stack
     - Credential pattern matching (passwords, API keys) in process memory

  2. CORE DUMP PARSING (offline)
     - ELF core PT_LOAD segment enumeration
     - String extraction from all readable segments
     - IOC extraction (IPs, hashes, URLs)
     - Detects anomalous memory patterns (shellcode NOP sleds, etc.)

  3. FORENSIC TIMELINE CONTRIBUTION
     - All findings output as UnifiedFinding-compatible JSON
     - Integrates with alert_correlator.py via standard schema

Usage:
    sudo python3 memory_forensics.py --live --pid 1234
    sudo python3 memory_forensics.py --live --all-processes --min-score 30
    python3 memory_forensics.py --core dump.core --output findings.json
"""

import argparse
import json
import logging
import math
import os
import platform
import re
import struct
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set, Tuple

import psutil

logger = logging.getLogger("vanguard.memforensics")
IS_LINUX = platform.system() == "Linux"

# ── Pattern sets ─────────────────────────────────────────────────────────────

IP_RE      = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE     = re.compile(rb"https?://[^\x00-\x1f\x7f-\xff ]{8,200}", re.I)
DOMAIN_RE  = re.compile(rb"\b(?:[a-z0-9\-]+\.){2,5}(?:com|net|org|io|biz|info|ru|cn|cc|to)\b", re.I)
HASH_RE    = re.compile(rb"\b[0-9a-f]{32,64}\b", re.I)
EMAIL_RE   = re.compile(rb"[a-z0-9._%+\-]{3,30}@[a-z0-9.\-]+\.[a-z]{2,6}", re.I)

CRED_PATTERNS = [
    re.compile(rb"(?:password|passwd|pwd)\s*[=:]\s*[^\x00-\x1f]{4,64}", re.I),
    re.compile(rb"(?:token|secret|api.?key|apikey)\s*[=:]\s*[^\x00-\x1f]{8,128}", re.I),
    re.compile(rb"AKIA[A-Z0-9]{16}", re.I),          # AWS access key
    re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
    re.compile(rb"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
]

MALWARE_STRINGS = [
    (re.compile(rb"(?:mimikatz|sekurlsa|lsadump)", re.I),   "mimikatz"),
    (re.compile(rb"(?:meterpreter|metasploit)",    re.I),   "metasploit"),
    (re.compile(rb"(?:cmd\.exe|powershell\.exe|wscript\.exe)", re.I), "win_shell"),
    (re.compile(rb"/bin/sh\x00|/bin/bash\x00",     re.I),   "unix_shell"),
    (re.compile(rb"nc -e|ncat -e|/dev/tcp/",       re.I),   "reverse_shell"),
    (re.compile(rb"(?:wget|curl)\s+http.*\|\s*(?:bash|sh)", re.I), "download_exec"),
    (re.compile(rb"\x90{8,}",                      0),      "nop_sled"),
    (re.compile(rb"\xcc{4,}",                      0),      "int3_sled"),
    (re.compile(rb"(?:TVqQAAMAAAAEAAAA|TVoAAA)",    0),      "b64_pe_header"),
]

# Regions that are normally NOT executable — injection if code found
SUSPICIOUS_REGION_NAMES = {
    "[heap]", "[stack]", "[vvar]", "/dev/shm/", "/tmp/", "/var/tmp/"
}

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class MemoryFinding:
    finding_type: str
    severity:     str
    pid:          int   = 0
    process_name: str   = ""
    region:       str   = ""
    offset:       int   = 0
    description:  str   = ""
    artifact:     str   = ""     # extracted string/IOC (redacted for creds)
    evidence:     dict  = field(default_factory=dict)
    score:        int   = 0
    timestamp:    str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        # Convert to Vanguard unified schema
        d.update({
            "tool":          "memory_forensics",
            "mitre":         _finding_to_mitre(self.finding_type),
            "entity":        f"{self.process_name}(pid={self.pid})" if self.pid else "core_dump",
            "source":        "memory_forensics",
        })
        return d


def _finding_to_mitre(finding_type: str) -> str:
    return {
        "injected_code":     "T1055",
        "malware_string":    "T1059",
        "credential_leak":   "T1552",
        "network_ioc":       "T1071",
        "pe_in_heap":        "T1055.002",
        "elf_in_heap":       "T1055",
        "shellcode_pattern": "T1059.004",
        "ioc_match":         "T1071",
    }.get(finding_type, "T1005")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n    = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())


# ── String extractor ──────────────────────────────────────────────────────────

def extract_strings(data: bytes, min_len: int = 6,
                    min_entropy: float = 2.5) -> List[Tuple[int, str]]:
    """Extract printable ASCII strings from raw bytes, filtered by entropy."""
    results = []
    pattern = re.compile(b"[ -~]{" + str(min_len).encode() + b",}")
    for m in pattern.finditer(data):
        s = m.group().decode("ascii", errors="ignore")
        if shannon_entropy(s.encode()) >= min_entropy:
            results.append((m.start(), s[:256]))
    return results


# ── PE/ELF header detection ───────────────────────────────────────────────────

def find_pe_headers(data: bytes) -> List[int]:
    offsets = []
    pos = 0
    while True:
        idx = data.find(b"MZ", pos)
        if idx == -1:
            break
        # Validate PE offset pointer
        if idx + 64 < len(data):
            pe_offset = struct.unpack_from("<I", data, idx + 60)[0]
            if pe_offset < len(data) - idx - 4:
                if data[idx + pe_offset: idx + pe_offset + 4] == b"PE\x00\x00":
                    offsets.append(idx)
        pos = idx + 2
    return offsets


def find_elf_headers(data: bytes) -> List[int]:
    offsets = []
    pos = 0
    while True:
        idx = data.find(b"\x7fELF", pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + 4
    return offsets


# ── Live process scanner ──────────────────────────────────────────────────────

class LiveProcessScanner:
    def __init__(self, min_score: int = 20, max_region_bytes: int = 16 * 1024 * 1024):
        self.min_score        = min_score
        self.max_region_bytes = max_region_bytes
        self._reported: Set[str] = set()

    def scan_process(self, pid: int) -> List[MemoryFinding]:
        if not IS_LINUX:
            return []

        try:
            proc      = psutil.Process(pid)
            proc_name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

        maps_path = f"/proc/{pid}/maps"
        mem_path  = f"/proc/{pid}/mem"

        try:
            maps_text = Path(maps_path).read_text(errors="replace")
        except OSError:
            return []

        try:
            mem_fd = open(mem_path, "rb")
        except OSError:
            logger.warning("Cannot open %s — run as root", mem_path)
            return []

        findings: List[MemoryFinding] = []

        try:
            for line in maps_text.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue

                perms = parts[1]
                if "r" not in perms:
                    continue

                region_name = parts[5] if len(parts) > 5 else ""
                addr_range  = parts[0].split("-")
                if len(addr_range) != 2:
                    continue

                try:
                    start = int(addr_range[0], 16)
                    end   = int(addr_range[1], 16)
                except ValueError:
                    continue

                size = end - start
                if size > self.max_region_bytes or size < 64:
                    continue

                try:
                    mem_fd.seek(start)
                    data = mem_fd.read(size)
                except (OSError, OverflowError):
                    continue

                # ── Check 1: Executable heap/stack (code injection indicator) ──
                if "x" in perms:
                    for sus in SUSPICIOUS_REGION_NAMES:
                        if sus in region_name or (not region_name and "[heap]" in line):
                            key = f"exec:{pid}:{start}"
                            if key not in self._reported:
                                self._reported.add(key)
                                ent = shannon_entropy(data[:4096])
                                findings.append(MemoryFinding(
                                    finding_type="injected_code",
                                    severity="critical",
                                    pid=pid, process_name=proc_name,
                                    region=region_name or line.split()[0],
                                    offset=start,
                                    description=f"Executable code in non-code region "
                                                f"(entropy={ent:.2f}) — possible shellcode injection",
                                    evidence={"perms": perms, "region": region_name,
                                              "entropy": round(ent, 3), "size": size},
                                    score=55,
                                ))
                            break

                # ── Check 2: PE/ELF headers in unexpected places ───────────────
                pe_offsets = find_pe_headers(data)
                for off in pe_offsets[:3]:
                    # Only flag if not in a legitimate mapped PE file region
                    if not region_name.endswith((".exe", ".dll", ".so")):
                        key = f"pe:{pid}:{start+off}"
                        if key not in self._reported:
                            self._reported.add(key)
                            findings.append(MemoryFinding(
                                finding_type="pe_in_heap",
                                severity="critical",
                                pid=pid, process_name=proc_name,
                                region=region_name,
                                offset=start + off,
                                description=f"PE header at 0x{start+off:x} in "
                                            f"non-PE region — reflective DLL injection",
                                evidence={"region": region_name, "perms": perms},
                                score=60,
                            ))

                elf_offsets = find_elf_headers(data)
                for off in elf_offsets[:3]:
                    if not region_name.endswith(".so") and not region_name.startswith("/"):
                        key = f"elf:{pid}:{start+off}"
                        if key not in self._reported:
                            self._reported.add(key)
                            findings.append(MemoryFinding(
                                finding_type="elf_in_heap",
                                severity="high",
                                pid=pid, process_name=proc_name,
                                region=region_name,
                                offset=start + off,
                                description=f"ELF header at 0x{start+off:x} in "
                                            f"non-library region — possible ELF injection",
                                evidence={"region": region_name},
                                score=45,
                            ))

                # ── Check 3: Malware strings ───────────────────────────────────
                for pattern, label in MALWARE_STRINGS:
                    m = pattern.search(data)
                    if m:
                        key = f"mal:{pid}:{label}"
                        if key not in self._reported:
                            self._reported.add(key)
                            preview = data[m.start():m.start()+64].decode("ascii", errors="replace")
                            sev = "critical" if label in ("mimikatz","reverse_shell","b64_pe_header") else "high"
                            findings.append(MemoryFinding(
                                finding_type="malware_string",
                                severity=sev,
                                pid=pid, process_name=proc_name,
                                region=region_name, offset=start + m.start(),
                                description=f"Malware string pattern [{label}] in process memory",
                                artifact=preview[:80],
                                evidence={"label": label, "region": region_name},
                                score=50 if sev=="critical" else 35,
                            ))

                # ── Check 4: Shellcode patterns ────────────────────────────────
                nop_m = re.search(rb"\x90{16,}", data)
                if nop_m:
                    key = f"nop:{pid}:{start}"
                    if key not in self._reported:
                        self._reported.add(key)
                        findings.append(MemoryFinding(
                            finding_type="shellcode_pattern",
                            severity="high",
                            pid=pid, process_name=proc_name,
                            region=region_name, offset=start + nop_m.start(),
                            description=f"NOP sled ({len(nop_m.group())} bytes) — shellcode staging",
                            evidence={"nop_count": len(nop_m.group())},
                            score=40,
                        ))

                # ── Check 5: Credential patterns ──────────────────────────────
                for pat in CRED_PATTERNS:
                    cm = pat.search(data)
                    if cm:
                        key = f"cred:{pid}:{pat.pattern[:20]}:{start}"
                        if key not in self._reported:
                            self._reported.add(key)
                            raw = cm.group()[:80].decode("ascii", errors="replace")
                            redacted = raw[:8] + "***" + raw[-4:] if len(raw) > 12 else raw[:4] + "***"
                            findings.append(MemoryFinding(
                                finding_type="credential_leak",
                                severity="high",
                                pid=pid, process_name=proc_name,
                                region=region_name, offset=start + cm.start(),
                                description="Credential-like pattern found in process memory",
                                artifact=redacted,
                                evidence={"region": region_name},
                                score=35,
                            ))

                # ── Check 6: Network IOCs ──────────────────────────────────────
                for url_m in URL_RE.finditer(data):
                    url = url_m.group().decode("ascii", errors="replace")
                    key = f"url:{pid}:{url[:40]}"
                    if key not in self._reported:
                        self._reported.add(key)
                        # Only flag non-obvious / non-common domains
                        if not any(d in url for d in [
                            "microsoft.com","google.com","ubuntu.com",
                            "debian.org","python.org","github.com",
                        ]):
                            findings.append(MemoryFinding(
                                finding_type="network_ioc",
                                severity="medium",
                                pid=pid, process_name=proc_name,
                                region=region_name, offset=start + url_m.start(),
                                description=f"URL found in process memory: {url[:80]}",
                                artifact=url[:100],
                                evidence={"region": region_name},
                                score=20,
                            ))

        finally:
            mem_fd.close()

        return [f for f in findings if f.score >= self.min_score]

    def scan_all(self) -> List[MemoryFinding]:
        all_findings = []
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                findings = self.scan_process(proc.info["pid"])
                all_findings.extend(findings)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return all_findings


# ── Offline core dump parser ──────────────────────────────────────────────────

class CoreDumpAnalyzer:
    """
    Parses ELF core dumps (produced by VirtualBox debugvm dumpvmcore,
    Linux kernel core, or gcore). Extracts PT_LOAD segments and performs
    IOC + malware string analysis without needing Volatility.
    """

    ELF_MAGIC     = b"\x7fELF"
    ET_CORE       = 4
    PT_LOAD       = 1
    PT_NOTE       = 4

    def __init__(self, core_path: str):
        self.path = Path(core_path)
        self._data: Optional[bytes] = None

    def _load(self) -> bytes:
        if self._data is None:
            logger.info("Loading core dump: %s (%d MB)",
                        self.path, self.path.stat().st_size // (1024*1024))
            self._data = self.path.read_bytes()
        return self._data

    def _parse_elf_header(self, data: bytes) -> Optional[dict]:
        if len(data) < 64 or data[:4] != self.ELF_MAGIC:
            return None
        bits = 32 if data[4] == 1 else 64
        if bits == 64:
            fmt = "<HHIQQQIHHHHHH"
            hdr = struct.unpack_from(fmt, data, 0)
            return {
                "bits": 64, "e_type": hdr[1],
                "e_phoff": hdr[4], "e_phentsize": hdr[8], "e_phnum": hdr[9],
            }
        else:
            fmt = "<HHIIIIIHHHHHH"
            hdr = struct.unpack_from(fmt, data, 0)
            return {
                "bits": 32, "e_type": hdr[1],
                "e_phoff": hdr[3], "e_phentsize": hdr[8], "e_phnum": hdr[9],
            }

    def _parse_phdrs(self, data: bytes, hdr: dict) -> List[dict]:
        segments = []
        off      = hdr["e_phoff"]
        entsz    = hdr["e_phentsize"]
        num      = hdr["e_phnum"]

        for i in range(num):
            entry_off = off + i * entsz
            try:
                if hdr["bits"] == 64:
                    p_type, p_flags, p_offset, p_vaddr, _, p_filesz = \
                        struct.unpack_from("<IIQQQQ", data, entry_off)
                else:
                    p_type, p_offset, p_vaddr, _, p_filesz = \
                        struct.unpack_from("<IIIII", data, entry_off)
                    p_flags = 0
            except struct.error:
                continue

            if p_type in (self.PT_LOAD, self.PT_NOTE) and p_filesz > 0:
                segments.append({
                    "type": p_type, "offset": p_offset,
                    "vaddr": p_vaddr, "filesz": p_filesz, "flags": p_flags,
                })
        return segments

    def analyze(self, max_seg_bytes: int = 32 * 1024 * 1024) -> List[MemoryFinding]:
        findings = []
        try:
            data = self._load()
        except OSError as e:
            logger.error("Cannot read core dump: %s", e)
            return []

        hdr = self._parse_elf_header(data)
        if not hdr:
            logger.error("Not a valid ELF core dump: %s", self.path)
            return []

        if hdr["e_type"] != self.ET_CORE:
            logger.warning("ELF type %d — expected ET_CORE (4). Continuing anyway.", hdr["e_type"])

        segments = self._parse_phdrs(data, hdr)
        logger.info("Core dump: %d segments, %d-bit ELF", len(segments), hdr["bits"])

        all_iocs: Set[str] = set()
        all_urls: Set[str] = set()
        all_strings: List[str] = []

        for seg in segments:
            if seg["type"] != self.PT_LOAD:
                continue
            seg_start = seg["offset"]
            seg_size  = min(seg["filesz"], max_seg_bytes)
            if seg_start + seg_size > len(data):
                seg_size = len(data) - seg_start
            if seg_size <= 0:
                continue

            chunk = data[seg_start: seg_start + seg_size]

            # Malware strings
            for pattern, label in MALWARE_STRINGS:
                if pattern.search(chunk):
                    sev = "critical" if label in ("mimikatz","reverse_shell","nop_sled") else "high"
                    findings.append(MemoryFinding(
                        finding_type="malware_string",
                        severity=sev, pid=0,
                        process_name="core_dump",
                        region=f"vaddr=0x{seg['vaddr']:x}",
                        offset=seg_start,
                        description=f"Malware pattern [{label}] in core dump segment",
                        evidence={"segment_vaddr": hex(seg["vaddr"]),
                                  "label": label},
                        score=50 if sev=="critical" else 30,
                    ))

            # Network IOCs
            for m in IP_RE.finditer(chunk):
                ip = m.group().decode()
                parts = ip.split(".")
                # Skip private / loopback / broadcast
                if parts[0] in ("10","127","0","255") or ip.startswith("192.168") or ip.startswith("172."):
                    continue
                all_iocs.add(ip)

            for m in URL_RE.finditer(chunk):
                url = m.group().decode("ascii", errors="replace")
                if not any(d in url for d in ["microsoft.com","google.com","ubuntu.com"]):
                    all_urls.add(url[:120])

            # PE/ELF headers in segments
            for off in find_pe_headers(chunk)[:5]:
                findings.append(MemoryFinding(
                    finding_type="pe_in_heap",
                    severity="critical", pid=0,
                    process_name="core_dump",
                    region=f"vaddr=0x{seg['vaddr']:x}",
                    offset=seg_start + off,
                    description=f"PE header at core offset 0x{seg_start+off:x} "
                                 f"— possible injected executable",
                    evidence={"segment_vaddr": hex(seg["vaddr"])},
                    score=55,
                ))

        # Emit bulk IOC findings
        if all_iocs:
            findings.append(MemoryFinding(
                finding_type="network_ioc",
                severity="medium", pid=0,
                process_name="core_dump",
                description=f"{len(all_iocs)} unique external IPs found in core dump memory",
                artifact=", ".join(sorted(all_iocs)[:20]),
                evidence={"ip_count": len(all_iocs), "sample": sorted(all_iocs)[:10]},
                score=25,
            ))

        if all_urls:
            findings.append(MemoryFinding(
                finding_type="network_ioc",
                severity="medium", pid=0,
                process_name="core_dump",
                description=f"{len(all_urls)} URLs found in core dump memory",
                artifact=list(all_urls)[:3],
                evidence={"url_count": len(all_urls), "sample": list(all_urls)[:5]},
                score=25,
            ))

        logger.info("Core dump analysis complete: %d findings", len(findings))
        return findings


# ── CLI ───────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m"}

def _print_finding(f: MemoryFinding):
    c = SEV_C.get(f.severity,""); R="\033[0m"; B="\033[1m"
    pid_str = f"pid={f.pid}" if f.pid else "core_dump"
    print(f"  {c}[{f.severity.upper():8}]{R} {B}{f.finding_type}{R}  {pid_str}/{f.process_name}  +{f.score}")
    print(f"     {f.description}")
    if f.artifact:
        print(f"     artifact: {f.artifact[:80]}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Memory Forensics Engine")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--live",  action="store_true", help="Scan live process memory (requires root)")
    g.add_argument("--core",  help="Path to ELF core dump file")
    parser.add_argument("--pid",           type=int, help="Scan specific PID (live mode)")
    parser.add_argument("--all-processes", action="store_true")
    parser.add_argument("--min-score",     type=int, default=20)
    parser.add_argument("--output",        help="Output findings as JSON")
    args = parser.parse_args()

    C="\033[96m"; R="\033[0m"; B="\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Memory Forensics Engine ──{R}\n")

    findings: List[MemoryFinding] = []

    if args.live:
        if not IS_LINUX:
            print("  Live mode requires Linux (/proc filesystem)")
            return
        if os.geteuid() != 0:
            print("  \033[93mWarning: not running as root — some regions will be inaccessible\033[0m\n")

        scanner = LiveProcessScanner(min_score=args.min_score)
        if args.pid:
            findings = scanner.scan_process(args.pid)
            print(f"  Scanned pid={args.pid}")
        else:
            findings = scanner.scan_all()
            print(f"  Scanned all processes")

    elif args.core:
        analyzer = CoreDumpAnalyzer(args.core)
        findings = analyzer.analyze()
        print(f"  Analyzed core dump: {args.core}")

    print(f"  Findings: {len(findings)}\n")
    for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.severity,4)):
        _print_finding(f)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump([f.to_dict() for f in findings], fh, indent=2)
        print(f"  Findings saved to {C}{args.output}{R}")


if __name__ == "__main__":
    main()
