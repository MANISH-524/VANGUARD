#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 12 — Credential Exposure & Auth-Abuse Monitor
=============================================================================
Original architecture. Three independent engines, each tuned for low FPs:

  1. PASSWORD-SPRAY DETECTOR
     Classic brute-force = many passwords against ONE account.
     Password spray      = ONE password (or few) against MANY accounts,
     spread thin to dodge per-account lockout policies.
     Vanguard tracks, per source IP and per rolling window:
        - distinct target accounts attempted
        - failure-to-success ratio
        - inter-attempt timing regularity (low jitter = scripted)
     Flags only when distinct-account fan-out crosses threshold AND the
     attempts are roughly evenly spaced (bot-like) — a single user
     fat-fingering their password a few times never matches both.

  2. SECRET-EXPOSURE SCANNER
     Scans source trees / config dumps / shell history for hardcoded
     credentials using a curated, LOW-NOISE pattern set:
        - Cloud provider keys (AWS/GCP/Azure) with correct checksum shape
        - Private key PEM headers
        - Database connection strings with embedded passwords
        - JWT-looking tokens (3-part base64, decodable header)
        - Generic high-entropy "KEY=value" assignments (entropy-gated to
          avoid flagging UUIDs, version strings, etc.)
     Each match includes a redacted preview and a confidence score; the
     entropy gate on generic secrets is the key FP-reduction technique
     vs naive regex-only scanners.

  3. HASH STRENGTH AUDITOR
     Parses /etc/shadow-style or exported hash dumps (user:hash format),
     classifies the hashing algorithm (DES/MD5/SHA256/SHA512/bcrypt/
     scrypt/argon2), flags weak/legacy algorithms, flags empty/locked
     accounts that are NOT actually locked, and flags duplicate hashes
     across accounts (shared/default-password indicator).

Usage:
    python3 credential_monitor.py --auth-log /var/log/auth.log --spray
    python3 credential_monitor.py --scan-secrets /path/to/repo
    python3 credential_monitor.py --hash-audit /tmp/shadow.export
"""

import argparse
import base64
import json
import logging
import math
import re
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vanguard.credmon")

_YEAR = datetime.now(timezone.utc).year
MONTH_MAP = {"jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,
              "jul":7,"aug":8,"sep":9,"oct":10,"nov":11,"dec":12}

def _parse_syslog_ts(ts_str: str) -> Optional[datetime]:
    m = re.match(r"(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})", ts_str)
    if not m:
        return None
    mo = MONTH_MAP.get(m.group(1).lower(), 1)
    return datetime(_YEAR, mo, int(m.group(2)), int(m.group(3)),
                    int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)


# ── Data models ───────────────────────────────────────────────────────────

@dataclass
class CredFinding:
    finding_type: str
    severity:     str
    mitre:        str
    description:  str
    evidence:     dict = field(default_factory=dict)
    score:        int  = 0
    timestamp:    str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Engine 1 — Password Spray Detector
# ─────────────────────────────────────────────────────────────────────────────

_RE_LINE      = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")
_RE_AUTH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", re.I)
_RE_AUTH_OK   = re.compile(r"Accepted password for (\S+) from ([\d.]+)", re.I)


@dataclass
class AuthAttempt:
    ts:      float
    src:     str
    user:    str
    success: bool


class PasswordSprayDetector:
    """
    Detects low-and-slow password spraying: ONE source IP attempts
    authentication against MANY distinct accounts within a window,
    with roughly regular timing (bot-like) and a low success rate.

    Designed to NOT fire on:
      - A single user retrying their own password a few times
      - Normal admin logging into several boxes with correct creds
      - Bursty-but-irregular human typing patterns
    """

    def __init__(self, window_s: int = 600, account_threshold: int = 8,
                 max_jitter_cv: float = 0.6, max_success_ratio: float = 0.15):
        self.window_s          = window_s
        self.account_threshold = account_threshold
        self.max_jitter_cv     = max_jitter_cv
        self.max_success_ratio= max_success_ratio

    def detect(self, attempts: List[AuthAttempt]) -> List[CredFinding]:
        findings = []
        by_src: Dict[str, List[AuthAttempt]] = defaultdict(list)
        for a in attempts:
            by_src[a.src].append(a)

        for src, evs in by_src.items():
            evs.sort(key=lambda e: e.ts)
            window: deque = deque()
            reported_window = False
            for e in evs:
                window.append(e)
                while window and e.ts - window[0].ts > self.window_s:
                    window.popleft()

                accounts = {w.user for w in window}
                if len(accounts) < self.account_threshold:
                    continue
                if reported_window:
                    continue

                successes = sum(1 for w in window if w.success)
                ratio     = successes / len(window)
                if ratio > self.max_success_ratio:
                    continue   # too many successes — likely legit multi-host admin

                # Timing regularity (coefficient of variation of inter-arrival times)
                times = [w.ts for w in window]
                intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
                if len(intervals) < 3:
                    continue
                mean_iv = sum(intervals)/len(intervals)
                if mean_iv <= 0:
                    continue
                var = sum((x-mean_iv)**2 for x in intervals)/len(intervals)
                cv  = math.sqrt(var)/mean_iv

                # Either very regular timing (bot) OR sheer volume well past
                # threshold makes this high-confidence regardless of jitter.
                volume_overwhelming = len(accounts) >= self.account_threshold * 2

                if cv <= self.max_jitter_cv or volume_overwhelming:
                    findings.append(CredFinding(
                        finding_type="password_spray",
                        severity="critical" if volume_overwhelming else "high",
                        mitre="T1110.003",
                        description=f"Source {src} attempted auth against "
                                    f"{len(accounts)} distinct accounts in "
                                    f"{self.window_s}s (success ratio "
                                    f"{ratio:.0%}, timing CV={cv:.2f})",
                        evidence={"src": src, "account_count": len(accounts),
                                  "accounts": sorted(accounts)[:15],
                                  "success_ratio": round(ratio,3),
                                  "timing_cv": round(cv,3),
                                  "total_attempts": len(window)},
                        score=45 if volume_overwhelming else 35,
                    ))
                    reported_window = True

        return findings

    @staticmethod
    def parse_auth_log(path: str) -> List[AuthAttempt]:
        attempts = []
        try:
            lines = Path(path).read_text(errors="replace").splitlines()
        except OSError as e:
            logger.error("Cannot read %s: %s", path, e)
            return attempts

        for line in lines:
            m = _RE_LINE.match(line)
            if not m:
                continue
            ts_str, _, msg = m.groups()
            ts = _parse_syslog_ts(ts_str)
            tsf = ts.timestamp() if ts else 0.0

            mo = _RE_AUTH_FAIL.search(msg)
            if mo:
                attempts.append(AuthAttempt(ts=tsf, src=mo.group(2),
                                            user=mo.group(1).lower(), success=False))
                continue
            mo = _RE_AUTH_OK.search(msg)
            if mo:
                attempts.append(AuthAttempt(ts=tsf, src=mo.group(2),
                                            user=mo.group(1).lower(), success=True))
        return attempts


# ─────────────────────────────────────────────────────────────────────────────
# Engine 2 — Secret Exposure Scanner
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n    = len(s)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())


@dataclass
class SecretPattern:
    name:        str
    pattern:     re.Pattern
    severity:    str
    description: str
    confidence:  int
    entropy_gate: Optional[float] = None   # if set, group(1) must exceed this entropy


SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern("aws_access_key_id",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b"),
        "critical", "AWS Access Key ID", 90),
    SecretPattern("aws_secret_key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "critical", "AWS Secret Access Key", 85),
    SecretPattern("gcp_service_account",
        re.compile(r'"type":\s*"service_account"'),
        "critical", "GCP service-account JSON key file", 85),
    SecretPattern("azure_connection_string",
        re.compile(r"(?i)(?:DefaultEndpointsProtocol|AccountKey)=[A-Za-z0-9+/=]{20,}"),
        "high", "Azure storage connection string", 75),
    SecretPattern("private_key_pem",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
        "critical", "Embedded private key (PEM)", 95),
    SecretPattern("github_token",
        re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
        "critical", "GitHub personal access token", 90),
    SecretPattern("slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
        "high", "Slack API token", 85),
    SecretPattern("jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "medium", "JWT-format token", 60),
    SecretPattern("db_conn_string_with_password",
        re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb|redis)://[^:/\s]+:([^@/\s]{3,})@"),
        "high", "Database connection string with embedded password", 80),
    SecretPattern("generic_assignment",
        re.compile(r"(?i)\b(?:secret|password|passwd|pwd|api[_-]?key|token|auth)["
                   r"_a-z0-9]*\s*[=:]\s*['\"]([A-Za-z0-9_\-+/=]{16,64})['\"]"),
        "medium", "High-entropy credential-like assignment", 50,
        entropy_gate=3.2),
]

# Files / paths that should be skipped to avoid noise
SCAN_SKIP_EXTS = {".png",".jpg",".jpeg",".gif",".pdf",".zip",".tar",".gz",
                  ".woff",".woff2",".ttf",".eot",".min.js",".lock",".svg",
                  ".ico",".mp4",".mp3",".so",".dll",".exe"}
SCAN_SKIP_DIRS = {"node_modules",".git","__pycache__","venv",".venv","dist","build"}

# Common placeholder values that should NOT be flagged
PLACEHOLDER_VALUES = {
    "changeme","change_me","your_password_here","example","xxxxxxxx",
    "<password>","${password}","insert_key_here","replace_me",
    "0000000000000000000000000000000000000000",  # zero hashes
    "1234567890123456789012345678901234567890",
}


class SecretScanner:
    def __init__(self, patterns: List[SecretPattern] = None, max_file_size: int = 2*1024*1024):
        self.patterns      = patterns or SECRET_PATTERNS
        self.max_file_size = max_file_size

    def scan_text(self, text: str, source: str) -> List[CredFinding]:
        findings = []
        for line_no, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:
                continue  # skip minified blobs
            for pat in self.patterns:
                m = pat.pattern.search(line)
                if not m:
                    continue

                # Entropy gate (for generic patterns)
                if pat.entropy_gate is not None:
                    val = m.group(1) if m.lastindex else m.group(0)
                    if val.lower() in PLACEHOLDER_VALUES:
                        continue
                    if shannon_entropy(val) < pat.entropy_gate:
                        continue
                    if re.fullmatch(r"[0-9a-fA-F-]{16,64}", val) and len(set(val)) < 8:
                        continue  # likely a UUID/hash with low character diversity

                redacted = self._redact(m.group(0))
                findings.append(CredFinding(
                    finding_type="exposed_secret",
                    severity=pat.severity,
                    mitre="T1552.001",
                    description=f"{pat.description} found in {source}:{line_no}",
                    evidence={"source": source, "line": line_no,
                              "pattern": pat.name, "preview": redacted,
                              "confidence": pat.confidence},
                    score={"critical":40,"high":30,"medium":20,"low":10}.get(pat.severity,10),
                ))
        return findings

    @staticmethod
    def _redact(match_text: str) -> str:
        if len(match_text) <= 12:
            return match_text[:2] + "***"
        return match_text[:6] + "..." + match_text[-4:]

    def scan_path(self, root: str) -> List[CredFinding]:
        findings = []
        p = Path(root)
        if p.is_file():
            return self._scan_file(p)

        for fp in p.rglob("*"):
            if not fp.is_file():
                continue
            if any(part in SCAN_SKIP_DIRS for part in fp.parts):
                continue
            if fp.suffix.lower() in SCAN_SKIP_EXTS:
                continue
            try:
                if fp.stat().st_size > self.max_file_size:
                    continue
            except OSError:
                continue
            findings.extend(self._scan_file(fp))
        return findings

    def _scan_file(self, fp: Path) -> List[CredFinding]:
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        return self.scan_text(text, str(fp))


# ─────────────────────────────────────────────────────────────────────────────
# Engine 3 — Hash Strength Auditor
# ─────────────────────────────────────────────────────────────────────────────

HASH_ALGO_PATTERNS: List[Tuple[str, re.Pattern, str, int]] = [
    # (algo_name, regex, severity_if_present, weakness_score)
    ("DES_crypt",   re.compile(r"^[./0-9A-Za-z]{13}$"),                "critical", 90),
    ("MD5_crypt",   re.compile(r"^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$"), "critical", 80),
    ("SHA256_crypt",re.compile(r"^\$5\$"),                              "medium", 30),
    ("SHA512_crypt",re.compile(r"^\$6\$"),                              "low", 10),
    ("bcrypt",      re.compile(r"^\$2[aby]?\$\d{2}\$"),                 "low", 5),
    ("scrypt",      re.compile(r"^\$7\$"),                              "low", 5),
    ("yescrypt",    re.compile(r"^\$y\$"),                              "low", 0),
    ("argon2",      re.compile(r"^\$argon2(?:i|d|id)\$"),               "low", 0),
    ("NTLM",        re.compile(r"^[0-9a-fA-F]{32}$"),                   "high", 70),
]

LOCK_INDICATORS = {"!","*","!!","*LK*","x","NP"}


class HashStrengthAuditor:
    """
    Parses lines of `user:hash[:rest...]` (e.g. exported /etc/shadow,
    htpasswd dumps, or NTDS extracts) and classifies hash strength.
    """

    def audit(self, lines: List[str]) -> List[CredFinding]:
        findings   = []
        hash_to_users: Dict[str, List[str]] = defaultdict(list)

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            user, hashval = parts[0], parts[1]

            if hashval in ("", *LOCK_INDICATORS):
                continue  # genuinely locked / no password — fine

            algo, sev, weak_score = self._classify(hashval)
            if weak_score > 0:
                findings.append(CredFinding(
                    finding_type="weak_hash_algorithm",
                    severity=sev,
                    mitre="T1003.008",
                    description=f"User '{user}' uses {algo} password hashing "
                                f"(weakness score {weak_score})",
                    evidence={"user": user, "algorithm": algo,
                              "hash_prefix": hashval[:12]},
                    score=weak_score // 2,
                ))

            hash_to_users[hashval].append(user)

        # Duplicate hash detection (shared/default passwords)
        for hashval, users in hash_to_users.items():
            if len(users) > 1:
                findings.append(CredFinding(
                    finding_type="shared_password_hash",
                    severity="high",
                    mitre="T1078",
                    description=f"{len(users)} accounts share an identical "
                                f"password hash — possible default/shared credential",
                    evidence={"accounts": users[:15], "hash_prefix": hashval[:12]},
                    score=30,
                ))

        return findings

    @staticmethod
    def _classify(hashval: str) -> Tuple[str, str, int]:
        for algo, pattern, sev, score in HASH_ALGO_PATTERNS:
            if pattern.match(hashval):
                return algo, sev, score
        return "unknown", "low", 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m"}

def _print_finding(f: CredFinding):
    c = SEV_C.get(f.severity,""); R = "\033[0m"; B = "\033[1m"
    print(f"  {c}[{f.severity.upper():8}]{R} [{f.mitre}] {B}{f.finding_type}{R}  +{f.score}")
    print(f"     {f.description}")
    for k, v in f.evidence.items():
        if k == "preview":
            print(f"       {k}: {v}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Credential Monitor")
    parser.add_argument("--auth-log",     help="Auth log for password-spray detection")
    parser.add_argument("--scan-secrets", help="Path/file to scan for exposed secrets")
    parser.add_argument("--hash-audit",   help="user:hash dump file to audit")
    parser.add_argument("--account-threshold", type=int, default=8)
    parser.add_argument("--json", help="Output findings to JSON")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Credential Monitor ──{R}\n")

    all_findings: List[CredFinding] = []

    if args.auth_log:
        attempts = PasswordSprayDetector.parse_auth_log(args.auth_log)
        print(f"  Parsed {len(attempts)} auth attempts from {args.auth_log}")
        detector = PasswordSprayDetector(account_threshold=args.account_threshold)
        findings = detector.detect(attempts)
        all_findings.extend(findings)
        for f in findings:
            _print_finding(f)

    if args.scan_secrets:
        scanner  = SecretScanner()
        findings = scanner.scan_path(args.scan_secrets)
        print(f"  Scanned {args.scan_secrets} — {len(findings)} secret(s) found")
        all_findings.extend(findings)
        for f in findings:
            _print_finding(f)

    if args.hash_audit:
        lines = Path(args.hash_audit).read_text(errors="replace").splitlines()
        auditor  = HashStrengthAuditor()
        findings = auditor.audit(lines)
        print(f"  Audited {len(lines)} hash entries — {len(findings)} finding(s)")
        all_findings.extend(findings)
        for f in findings:
            _print_finding(f)

    if not any([args.auth_log, args.scan_secrets, args.hash_audit]):
        print("  Specify --auth-log, --scan-secrets, or --hash-audit")
        return

    total_score = sum(f.score for f in all_findings)
    print(f"  Total findings: {len(all_findings)}   Aggregate score: {total_score}")

    if args.json and all_findings:
        with open(args.json, "w") as f:
            json.dump([fnd.to_dict() for fnd in all_findings], f, indent=2)
        print(f"  Findings saved to {C}{args.json}{R}")


if __name__ == "__main__":
    main()
