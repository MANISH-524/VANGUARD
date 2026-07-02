#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 2 — Log Analyzer & Anomaly Detector
===================================================================
Original architecture. Parses syslog, auth.log, Windows Event XML,
Apache/Nginx access logs, and custom JSON logs.

Capabilities:
  - Auto-detects log format from file content
  - Extracts structured events (timestamp, host, severity, message, fields)
  - Statistical anomaly detection (Z-score on event frequency per source IP/user)
  - Pattern library: brute-force, privesc, lateral movement, persistence, exfil
  - Rolling baseline (exponential moving average) to suppress false positives
  - Outputs ranked findings with MITRE ATT&CK technique tags
  - Tail mode: watches a live log file like `tail -f`

Usage:
    python3 log_analyzer.py --file /var/log/auth.log
    python3 log_analyzer.py --file /var/log/nginx/access.log --format nginx
    python3 log_analyzer.py --tail /var/log/syslog --live
    python3 log_analyzer.py --dir /var/log --recursive
"""

import argparse
import gzip
import json
import logging
import math
import re
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

logger = logging.getLogger("vanguard.log_analyzer")

# ── Log formats ───────────────────────────────────────────────────────────────

# Each format: list of (field_name, regex_group) after full-line match
LOG_PATTERNS = {
    "syslog": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)"
    ),
    "auth": re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)"
    ),
    "nginx": re.compile(
        r"(?P<remote_addr>\S+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<time_local>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r"(?P<status>\d+)\s+(?P<bytes_sent>\d+)"
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    ),
    "apache": re.compile(
        r"(?P<remote_addr>\S+)\s+\S+\s+(?P<remote_user>\S+)\s+\[(?P<time_local>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r"(?P<status>\d+)\s+(?P<bytes_sent>\d+)"
    ),
    "json": None,   # handled separately
    "windows": re.compile(
        r"<EventID>(?P<event_id>\d+)</EventID>.*?"
        r"<TimeCreated SystemTime='(?P<time>[^']+)'/>.*?"
        r"<Computer>(?P<computer>[^<]+)</Computer>",
        re.DOTALL,
    ),
}

# ── Detection rules with MITRE tags ──────────────────────────────────────────

@dataclass
class DetectionRule:
    name:        str
    pattern:     re.Pattern
    severity:    str        # low / medium / high / critical
    mitre:       str        # ATT&CK technique ID
    description: str
    score:       int        # contribution to threat score

DETECTION_RULES: List[DetectionRule] = [
    # ── Authentication attacks ────────────────────────────────────────────
    DetectionRule("ssh_brute_force",
        re.compile(r"Failed password for .+ from (?P<ip>[\d.]+)", re.I),
        "high", "T1110.001", "SSH brute-force attempt", 15),
    DetectionRule("ssh_invalid_user",
        re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)", re.I),
        "medium", "T1110.003", "SSH login with invalid username", 10),
    DetectionRule("sudo_failure",
        re.compile(r"sudo:.*authentication failure.*user=(?P<user>\S+)", re.I),
        "high", "T1548.003", "Sudo privilege escalation failure", 20),
    DetectionRule("su_failure",
        re.compile(r"su: FAILED SU.*to (?P<user>\S+) by (?P<actor>\S+)", re.I),
        "medium", "T1548.003", "su privilege escalation failure", 15),
    DetectionRule("account_lockout",
        re.compile(r"(account locked|too many auth|pam_tally2.*locked)", re.I),
        "high", "T1110", "Account lockout triggered", 25),

    # ── Successful auth from unusual source ──────────────────────────────
    DetectionRule("root_login",
        re.compile(r"Accepted .+ for root from (?P<ip>[\d.]+)", re.I),
        "critical", "T1078", "Direct root login accepted", 40),
    DetectionRule("accepted_password",
        re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)", re.I),
        "low", "T1078", "Password authentication accepted", 5),

    # ── Web attacks ───────────────────────────────────────────────────────
    DetectionRule("web_sqli",
        re.compile(r"(?:union\s+select|select.*from|or\s+1=1|'\s*or\s*'|information_schema)", re.I),
        "critical", "T1190", "SQL injection pattern detected", 35),
    DetectionRule("web_xss",
        re.compile(r"<script[\s>]|javascript:|on(?:load|click|error|mouseover)\s*=", re.I),
        "high", "T1059.007", "XSS payload pattern detected", 25),
    DetectionRule("web_traversal",
        re.compile(r"\.\./|\.\.\\|%2e%2e%2f|%252e%252e", re.I),
        "high", "T1083", "Directory traversal attempt", 30),
    DetectionRule("web_rce",
        re.compile(r"(?:/etc/passwd|/bin/bash|cmd\.exe|powershell|eval\(|base64_decode)", re.I),
        "critical", "T1059", "Remote code execution pattern", 45),
    DetectionRule("web_scanner",
        re.compile(r"(?:nikto|nmap|sqlmap|masscan|gobuster|dirbuster|wfuzz|nuclei)", re.I),
        "medium", "T1595", "Security scanner user-agent", 20),
    DetectionRule("web_4xx_flood",
        re.compile(r'" (?:400|401|403|404|405) '),
        "low", "T1595.003", "HTTP error flood (possible scanner)", 5),

    # ── Persistence ───────────────────────────────────────────────────────
    DetectionRule("cron_added",
        re.compile(r"(?:crontab|cron\.d|at\.allow|at\.deny)", re.I),
        "medium", "T1053.003", "Cron/at job modification", 20),
    DetectionRule("systemd_unit",
        re.compile(r"systemctl.*(enable|start|daemon-reload)|\.service.*created", re.I),
        "medium", "T1543.002", "Systemd service created/enabled", 15),
    DetectionRule("ssh_key_added",
        re.compile(r"authorized_keys|\.ssh/", re.I),
        "high", "T1098.004", "SSH authorized key modification", 30),

    # ── Lateral movement ─────────────────────────────────────────────────
    DetectionRule("new_user_created",
        re.compile(r"(?:useradd|adduser|net user.*\/add|New user|user added)", re.I),
        "high", "T1136.001", "New local user account created", 30),
    DetectionRule("group_modification",
        re.compile(r"(?:usermod|groupadd|gpasswd|net localgroup)", re.I),
        "medium", "T1098", "Group membership modification", 15),

    # ── Exfiltration / data staging ──────────────────────────────────────
    DetectionRule("large_outbound",
        re.compile(r'" \d{3} (?P<bytes>[0-9]{7,}) '),
        "medium", "T1030", "Large HTTP response (possible exfiltration)", 20),
    DetectionRule("base64_payload",
        re.compile(r"(?:base64|b64decode|frombase64|ToBase64)", re.I),
        "medium", "T1027", "Base64 encoding in log entry", 15),

    # ── Malware indicators ────────────────────────────────────────────────
    DetectionRule("temp_execution",
        re.compile(r"(?:/tmp/|/dev/shm/|/var/tmp/|\\Temp\\|\\AppData\\Local\\Temp\\)", re.I),
        "high", "T1059", "Execution from temp/scratch path", 25),
    DetectionRule("wget_curl_pipe",
        re.compile(r"(?:wget|curl).*\|\s*(?:bash|sh|python|perl|ruby)", re.I),
        "critical", "T1059", "Download-and-pipe execution pattern", 45),
    DetectionRule("reverse_shell",
        re.compile(r"(?:nc -e|/bin/bash -i|bash -i|python.*socket|socat.*exec)", re.I),
        "critical", "T1059.004", "Reverse shell pattern", 50),
]


# ── Parsed event ──────────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    line_no:   int
    raw:       str
    timestamp: Optional[str]
    host:      Optional[str]
    process:   Optional[str]
    pid:       Optional[str]
    message:   str
    fields:    dict = field(default_factory=dict)
    fmt:       str  = "unknown"


@dataclass
class Finding:
    rule_name:   str
    severity:    str
    mitre:       str
    description: str
    score:       int
    line_no:     int
    raw_line:    str
    matches:     dict  = field(default_factory=dict)
    timestamp:   str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Statistical anomaly tracker ───────────────────────────────────────────────

class AnomalyTracker:
    """
    Tracks per-key (IP, user, host) event rates using an
    exponential moving average + Z-score alerting.
    """
    def __init__(self, alpha: float = 0.1, z_threshold: float = 3.0):
        self.alpha       = alpha          # EMA smoothing factor
        self.z_threshold = z_threshold
        self._ema:  Dict[str, float]  = defaultdict(float)
        self._var:  Dict[str, float]  = defaultdict(float)
        self._cnt:  Dict[str, int]    = defaultdict(int)
        self._wins: Dict[str, deque]  = defaultdict(lambda: deque(maxlen=100))

    def record(self, key: str, value: float = 1.0) -> Optional[float]:
        """
        Record an observation. Returns Z-score if anomalous, else None.
        """
        self._wins[key].append(value)
        self._cnt[key]  += 1
        n = self._cnt[key]

        if n < 5:
            # Not enough data yet
            self._ema[key] = value
            self._var[key] = 0.0
            return None

        prev_ema = self._ema[key]
        new_ema  = self.alpha * value + (1 - self.alpha) * prev_ema
        self._ema[key] = new_ema

        # Welford-style online variance
        delta = value - prev_ema
        self._var[key] = (1 - self.alpha) * (self._var[key] + self.alpha * delta ** 2)
        std = math.sqrt(max(self._var[key], 1e-9))

        z = abs(value - new_ema) / std
        return z if z > self.z_threshold else None

    def summary(self) -> dict:
        return {k: {"ema": self._ema[k], "count": self._cnt[k]} for k in self._cnt}


# ── Log parser ────────────────────────────────────────────────────────────────

class LogParser:
    def __init__(self):
        self._ip_event_counts:   Counter = Counter()
        self._user_event_counts: Counter = Counter()
        self._anomaly = AnomalyTracker()

    def detect_format(self, sample: str) -> str:
        if sample.strip().startswith("{"):
            return "json"
        if "<Event " in sample or "<EventID>" in sample:
            return "windows"
        if LOG_PATTERNS["nginx"].search(sample):
            return "nginx"
        if LOG_PATTERNS["apache"].search(sample):
            return "apache"
        return "syslog"

    def parse_line(self, line: str, line_no: int, fmt: str) -> Optional[LogEvent]:
        line = line.rstrip("\n")
        if not line.strip():
            return None

        if fmt == "json":
            try:
                obj = json.loads(line)
                return LogEvent(
                    line_no   = line_no,
                    raw       = line,
                    timestamp = str(obj.get("timestamp") or obj.get("time") or obj.get("@timestamp", "")),
                    host      = str(obj.get("host") or obj.get("hostname", "")),
                    process   = str(obj.get("process") or obj.get("program", "")),
                    pid       = str(obj.get("pid", "")),
                    message   = str(obj.get("message") or obj.get("msg") or line),
                    fields    = obj,
                    fmt       = "json",
                )
            except json.JSONDecodeError:
                pass

        pattern = LOG_PATTERNS.get(fmt)
        if pattern:
            m = pattern.search(line)
            if m:
                d = m.groupdict()
                ts_parts = [d.get("month",""), d.get("day",""), d.get("time","")]
                ts = " ".join(p for p in ts_parts if p) or d.get("time_local","") or d.get("time","")
                return LogEvent(
                    line_no   = line_no,
                    raw       = line,
                    timestamp = ts,
                    host      = d.get("host") or d.get("computer"),
                    process   = d.get("process") or d.get("method"),
                    pid       = d.get("pid"),
                    message   = d.get("message") or d.get("uri") or line,
                    fields    = d,
                    fmt       = fmt,
                )

        # Fallback: treat whole line as message
        return LogEvent(line_no=line_no, raw=line, timestamp=None,
                        host=None, process=None, pid=None, message=line, fmt="raw")

    def analyze_event(self, event: LogEvent) -> List[Finding]:
        findings = []
        text     = event.raw  # match against full raw line

        for rule in DETECTION_RULES:
            m = rule.pattern.search(text)
            if m:
                findings.append(Finding(
                    rule_name   = rule.name,
                    severity    = rule.severity,
                    mitre       = rule.mitre,
                    description = rule.description,
                    score       = rule.score,
                    line_no     = event.line_no,
                    raw_line    = event.raw[:400],
                    matches     = m.groupdict(),
                ))

        return findings


# ── File analysis engine ──────────────────────────────────────────────────────

class LogAnalyzer:
    def __init__(self):
        self.parser   = LogParser()
        self.findings: List[Finding] = []
        self._ip_hits: Counter = Counter()

    def analyze_file(self, path: str, fmt: str = None, max_lines: int = 500_000) -> List[Finding]:
        p = Path(path)
        if not p.exists():
            logger.error("File not found: %s", path)
            return []

        opener = gzip.open if p.suffix == ".gz" else open
        mode   = "rt"

        with opener(path, mode, encoding="utf-8", errors="replace") as f:
            sample = f.read(2048)
            detected_fmt = fmt or self.parser.detect_format(sample)
            f.seek(0)

            logger.info("Analyzing %s (format: %s)", path, detected_fmt)
            findings = []
            for line_no, line in enumerate(f, 1):
                if line_no > max_lines:
                    break
                event = self.parser.parse_line(line, line_no, detected_fmt)
                if event:
                    new = self.parser.analyze_event(event)
                    findings.extend(new)
                    for fn in new:
                        ip = fn.matches.get("ip") or fn.matches.get("remote_addr", "")
                        if ip:
                            self._ip_hits[ip] += 1

        findings.sort(key=lambda f: f.score, reverse=True)
        self.findings = findings
        return findings

    def analyze_dir(self, directory: str, recursive: bool = False) -> Dict[str, List[Finding]]:
        results = {}
        p = Path(directory)
        glob_fn = p.rglob if recursive else p.glob
        for fp in glob_fn("*"):
            if fp.is_file() and fp.suffix in {".log", ".gz", ".txt", ""}:
                results[str(fp)] = self.analyze_file(str(fp))
        return results

    def tail(self, path: str, callback=None):
        """Watch a file for new lines (like tail -f)."""
        p = Path(path)
        fmt = None
        with open(path, encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # seek to end
            sample = ""
            line_no = 0
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                line_no += 1
                if not fmt:
                    fmt = self.parser.detect_format(line)
                event    = self.parser.parse_line(line, line_no, fmt)
                if event:
                    findings = self.parser.analyze_event(event)
                    for fn in findings:
                        if callback:
                            callback(fn)
                        else:
                            _print_finding(fn)

    def top_ips(self, n: int = 10) -> List[Tuple[str, int]]:
        return self._ip_hits.most_common(n)

    def summary(self) -> dict:
        by_sev = Counter(f.severity for f in self.findings)
        by_rule = Counter(f.rule_name for f in self.findings)
        return {
            "total_findings":   len(self.findings),
            "by_severity":      dict(by_sev),
            "top_rules":        dict(by_rule.most_common(10)),
            "top_source_ips":   dict(self.top_ips()),
            "total_score":      sum(f.score for f in self.findings),
        }


# ── CLI output ────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "critical": "\033[95m",
    "high":     "\033[91m",
    "medium":   "\033[93m",
    "low":      "\033[92m",
}

def _print_finding(fn: Finding):
    color = SEV_COLOR.get(fn.severity, "")
    reset = "\033[0m"
    print(f"  {color}[{fn.severity.upper():8}]{reset}  "
          f"Line {fn.line_no:>6}  [{fn.mitre}]  {fn.rule_name}")
    print(f"             {fn.description}")
    print(f"             {fn.raw_line[:120]}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Log Analyzer")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--file",  help="Log file to analyze")
    g.add_argument("--dir",   help="Directory of log files")
    g.add_argument("--tail",  help="Live tail a log file")
    parser.add_argument("--format",    choices=list(LOG_PATTERNS.keys()), help="Force log format")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--json-out",  help="Write findings to JSON file")
    parser.add_argument("--min-sev",   default="low",
                        choices=["low","medium","high","critical"])
    args = parser.parse_args()

    ANSI = "\033[96m"; R = "\033[0m"
    print(f"\n{ANSI}  ── Vanguard-OOB Log Analyzer ──{R}\n")

    analyzer = LogAnalyzer()
    SEV_RANK = {"low":0,"medium":1,"high":2,"critical":3}
    min_rank = SEV_RANK[args.min_sev]

    if args.file:
        findings = analyzer.analyze_file(args.file, args.format)
        filtered = [f for f in findings if SEV_RANK.get(f.severity,0) >= min_rank]
        for fn in filtered:
            _print_finding(fn)
        s = analyzer.summary()
        print(f"  Total findings: {s['total_findings']}  "
              f"Score: {s['total_score']}  "
              f"Top IP: {list(s['top_source_ips'].keys())[:3]}")

    elif args.dir:
        results = analyzer.analyze_dir(args.dir, args.recursive)
        for fpath, findings in results.items():
            if findings:
                print(f"\n  {fpath} — {len(findings)} findings")
                for fn in findings[:5]:
                    _print_finding(fn)

    elif args.tail:
        print(f"  Tailing {args.tail}  (Ctrl+C to stop)\n")
        try:
            analyzer.tail(args.tail)
        except KeyboardInterrupt:
            print("\n  Stopped.")

    if args.json_out and analyzer.findings:
        with open(args.json_out, "w") as f:
            json.dump([asdict(fn) for fn in analyzer.findings], f, indent=2)
        print(f"\n  Findings written to {args.json_out}")


if __name__ == "__main__":
    main()
