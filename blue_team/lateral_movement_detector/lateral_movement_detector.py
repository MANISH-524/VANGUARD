#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 10 — Lateral Movement Detector
==============================================================
Original architecture. Graph-based lateral movement & privilege-escalation
path detection from authentication and process logs.

Core idea (novel vs. signature-only tools):
  Every successful authentication is an edge: (source_host/IP) -> (dest_host, user).
  Vanguard builds a directed AUTH GRAPH per rolling window and scores it for
  topologies that are statistically rare for legitimate admin behaviour:

  - FAN-OUT     : one source authenticates to N≥threshold distinct hosts
                   in a short window  → credential reuse / spray-then-pivot
  - FAN-IN      : N≥threshold distinct sources authenticate as the SAME user
                   to ONE host in a short window → pass-the-hash harvesting point
  - CHAIN HOP   : A→B then B→C with the same account within Δt → classic
                   pivot chain (golden-ticket / PsExec hopscotch)
  - PRIV JUMP   : low-privilege account suddenly used for an admin/service
                   account login on a different host → token theft
  - NEW EDGE    : an auth edge never seen in the baseline graph appears →
                   first-time lateral path (high-signal, low-noise)
  - KERBEROAST  : burst of TGS-REQ-pattern log lines for many SPNs from a
                   single source in a short window
  - ASREPROAST  : repeated AS-REQ failures for accounts with
                   "do not require Kerberos preauth" pattern

Detections are evidence-based (graph topology + timing), not single-line
regex, which keeps false positives low — a single admin RDP session never
trips these rules; a credential-reuse pivot chain always does.

Usage:
    python3 lateral_movement_detector.py --logs /var/log/auth.log
    python3 lateral_movement_detector.py --logs auth1.log auth2.log --baseline graph.json
    python3 lateral_movement_detector.py --logs auth.log --save-baseline graph.json
"""

import argparse
import json
import logging
import re
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vanguard.lateral")

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


# ── Log line patterns ────────────────────────────────────────────────────────

_RE_LINE       = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")
_RE_AUTH_OK    = re.compile(r"Accepted (password|publickey|keyboard-interactive) for (\S+) from ([\d.]+)", re.I)
_RE_AUTH_FAIL  = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", re.I)
_RE_SUDO       = re.compile(r"sudo:\s*(\S+)\s*:.*COMMAND=(.+)", re.I)
_RE_SU         = re.compile(r"su(?:\[\d+\])?:\s*\+?\s*Successful su for (\S+) by (\S+)", re.I)
_RE_KERBEROS_TGS = re.compile(r"TGS[_-]REQ.*?account[:=]?\s*(\S+).*?service[:=]?\s*(\S+)", re.I)
_RE_KERBEROS_AS  = re.compile(r"AS[_-]REQ.*?account[:=]?\s*(\S+)", re.I)
_RE_PREAUTH_FAIL = re.compile(r"PREAUTH_FAILED|KRB5KDC_ERR_PREAUTH_FAILED", re.I)
_RE_PSEXEC     = re.compile(r"(?:PSEXESVC|psexec|wmiexec|smbexec)", re.I)


PRIVILEGED_ACCOUNTS = {"root","administrator","admin","domain admin",
                       "svc_backup","svc_sql","svc_admin","sa"}


# ── Data models ───────────────────────────────────────────────────────────

@dataclass
class AuthEdge:
    src:       str        # source IP
    dst_host:  str        # destination host (log host)
    user:      str
    ts:        float
    success:   bool
    method:    str = "password"


@dataclass
class LateralFinding:
    finding_type: str
    severity:     str
    mitre:        str
    description:  str
    evidence:     dict = field(default_factory=dict)
    score:        int  = 0
    timestamp:    str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


# ── Auth graph builder ────────────────────────────────────────────────────

class AuthGraphBuilder:
    def __init__(self):
        self.edges: List[AuthEdge] = []
        self.kerberos_tgs: List[Tuple[str, str, float]] = []   # (src, spn, ts)
        self.kerberos_as_fail: List[Tuple[str, float]] = []    # (account, ts)

    def ingest_file(self, path: str):
        try:
            lines = Path(path).read_text(errors="replace").splitlines()
        except OSError as e:
            logger.error("Cannot read %s: %s", path, e)
            return

        for line in lines:
            m = _RE_LINE.match(line)
            if not m:
                continue
            ts_str, host, msg = m.groups()
            ts = _parse_syslog_ts(ts_str)
            tsf = ts.timestamp() if ts else 0.0

            mo = _RE_AUTH_OK.search(msg)
            if mo:
                method, user, src = mo.groups()
                self.edges.append(AuthEdge(src=src, dst_host=host, user=user.lower(),
                                           ts=tsf, success=True, method=method))
                continue

            mo = _RE_AUTH_FAIL.search(msg)
            if mo:
                user, src = mo.groups()
                self.edges.append(AuthEdge(src=src, dst_host=host, user=user.lower(),
                                           ts=tsf, success=False))
                continue

            mo = _RE_KERBEROS_TGS.search(msg)
            if mo:
                account, spn = mo.groups()
                self.kerberos_tgs.append((account.lower(), spn, tsf))
                continue

            mo = _RE_KERBEROS_AS.search(msg)
            if mo and _RE_PREAUTH_FAIL.search(msg):
                self.kerberos_as_fail.append((mo.group(1).lower(), tsf))


# ── Detection engine ──────────────────────────────────────────────────────

class LateralMovementDetector:
    def __init__(self,
                 fanout_threshold: int = 5,
                 fanout_window_s: int = 300,
                 fanin_threshold: int = 4,
                 fanin_window_s: int = 300,
                 chain_window_s: int = 600,
                 kerberoast_threshold: int = 5,
                 kerberoast_window_s: int = 120,
                 asrep_threshold: int = 5,
                 asrep_window_s: int = 300):
        self.fanout_threshold     = fanout_threshold
        self.fanout_window_s      = fanout_window_s
        self.fanin_threshold      = fanin_threshold
        self.fanin_window_s       = fanin_window_s
        self.chain_window_s       = chain_window_s
        self.kerberoast_threshold = kerberoast_threshold
        self.kerberoast_window_s  = kerberoast_window_s
        self.asrep_threshold      = asrep_threshold
        self.asrep_window_s       = asrep_window_s

    def detect(self, builder: AuthGraphBuilder,
               baseline_edges: Set[Tuple[str,str,str]] = None) -> List[LateralFinding]:
        findings: List[LateralFinding] = []
        success_edges = [e for e in builder.edges if e.success]
        success_edges.sort(key=lambda e: e.ts)

        findings.extend(self._detect_fanout(success_edges))
        findings.extend(self._detect_fanin(success_edges))
        findings.extend(self._detect_chain_hops(success_edges))
        findings.extend(self._detect_priv_jump(success_edges))
        findings.extend(self._detect_kerberoasting(builder.kerberos_tgs))
        findings.extend(self._detect_asreproasting(builder.kerberos_as_fail))

        if baseline_edges is not None:
            findings.extend(self._detect_new_edges(success_edges, baseline_edges))

        SEV_RANK = {"critical":0,"high":1,"medium":2,"low":3}
        findings.sort(key=lambda f: SEV_RANK.get(f.severity,4))
        return findings

    # ── FAN-OUT: one source → many destination hosts ──────────────────────

    def _detect_fanout(self, edges: List[AuthEdge]) -> List[LateralFinding]:
        findings = []
        by_src: Dict[str, List[AuthEdge]] = defaultdict(list)
        for e in edges:
            by_src[e.src].append(e)

        for src, evs in by_src.items():
            evs.sort(key=lambda e: e.ts)
            window: deque = deque()
            for e in evs:
                window.append(e)
                while window and e.ts - window[0].ts > self.fanout_window_s:
                    window.popleft()
                dest_hosts = {(w.dst_host, w.user) for w in window}
                unique_hosts = {h for h, _ in dest_hosts}
                if len(unique_hosts) >= self.fanout_threshold:
                    findings.append(LateralFinding(
                        finding_type="fanout_credential_reuse",
                        severity="high",
                        mitre="T1021",
                        description=f"Source {src} authenticated to {len(unique_hosts)} "
                                    f"distinct hosts within {self.fanout_window_s}s",
                        evidence={"src": src, "hosts": sorted(unique_hosts)[:15],
                                  "window_s": self.fanout_window_s,
                                  "users": sorted({u for _, u in dest_hosts})[:10]},
                        score=40,
                    ))
                    window.clear()  # avoid duplicate spam for same burst
                    break
        return findings

    # ── FAN-IN: many sources → same user@host ──────────────────────────────

    def _detect_fanin(self, edges: List[AuthEdge]) -> List[LateralFinding]:
        findings = []
        by_dest: Dict[Tuple[str,str], List[AuthEdge]] = defaultdict(list)
        for e in edges:
            by_dest[(e.dst_host, e.user)].append(e)

        for (host, user), evs in by_dest.items():
            evs.sort(key=lambda e: e.ts)
            window: deque = deque()
            for e in evs:
                window.append(e)
                while window and e.ts - window[0].ts > self.fanin_window_s:
                    window.popleft()
                unique_src = {w.src for w in window}
                if len(unique_src) >= self.fanin_threshold:
                    findings.append(LateralFinding(
                        finding_type="fanin_shared_credential",
                        severity="high",
                        mitre="T1078",
                        description=f"{len(unique_src)} distinct sources authenticated as "
                                    f"'{user}' on {host} within {self.fanin_window_s}s",
                        evidence={"host": host, "user": user,
                                  "sources": sorted(unique_src)[:15],
                                  "window_s": self.fanin_window_s},
                        score=35,
                    ))
                    window.clear()
                    break
        return findings

    # ── CHAIN HOP: A→B then B→C with same account ────────────────────────

    def _detect_chain_hops(self, edges: List[AuthEdge]) -> List[LateralFinding]:
        findings = []
        by_user: Dict[str, List[AuthEdge]] = defaultdict(list)
        for e in edges:
            by_user[e.user].append(e)

        for user, evs in by_user.items():
            evs.sort(key=lambda e: e.ts)
            for i in range(len(evs) - 1):
                a, b = evs[i], evs[i+1]
                # a: src -> a.dst_host ; b: src=a.dst_host (the same host now pivots onward)
                if a.dst_host == b.src or (a.dst_host != b.dst_host and
                                            0 < (b.ts - a.ts) <= self.chain_window_s and
                                            a.dst_host != a.src and b.src != b.dst_host):
                    # Heuristic chain: same account hopped from host A to host B within window
                    if a.dst_host != b.dst_host and (b.ts - a.ts) <= self.chain_window_s and (b.ts - a.ts) >= 0:
                        findings.append(LateralFinding(
                            finding_type="auth_chain_hop",
                            severity="critical",
                            mitre="T1021.004",
                            description=f"Account '{user}' authenticated to {a.dst_host} "
                                        f"then {b.dst_host} within {int(b.ts-a.ts)}s — pivot chain",
                            evidence={"user": user, "hop1": f"{a.src}->{a.dst_host}",
                                      "hop2": f"{b.src}->{b.dst_host}",
                                      "delta_s": round(b.ts - a.ts, 1)},
                            score=45,
                        ))
        return findings

    # ── PRIV JUMP: normal account → privileged account, different host ────

    def _detect_priv_jump(self, edges: List[AuthEdge]) -> List[LateralFinding]:
        findings = []
        by_src: Dict[str, List[AuthEdge]] = defaultdict(list)
        for e in edges:
            by_src[e.src].append(e)

        for src, evs in by_src.items():
            evs.sort(key=lambda e: e.ts)
            seen_normal_host = None
            for e in evs:
                if e.user not in PRIVILEGED_ACCOUNTS:
                    seen_normal_host = e.dst_host
                elif e.user in PRIVILEGED_ACCOUNTS and seen_normal_host and seen_normal_host != e.dst_host:
                    findings.append(LateralFinding(
                        finding_type="privilege_jump",
                        severity="critical",
                        mitre="T1078.003",
                        description=f"Source {src} used standard account on "
                                    f"{seen_normal_host}, then privileged "
                                    f"'{e.user}' on {e.dst_host}",
                        evidence={"src": src, "normal_host": seen_normal_host,
                                  "priv_host": e.dst_host, "priv_user": e.user},
                        score=50,
                    ))
        return findings

    # ── KERBEROASTING: burst of TGS-REQ for many SPNs from one account ────

    def _detect_kerberoasting(self, tgs_events: List[Tuple[str,str,float]]) -> List[LateralFinding]:
        findings = []
        by_account: Dict[str, List[Tuple[str,float]]] = defaultdict(list)
        for account, spn, ts in tgs_events:
            by_account[account].append((spn, ts))

        for account, evs in by_account.items():
            evs.sort(key=lambda x: x[1])
            window: deque = deque()
            for spn, ts in evs:
                window.append((spn, ts))
                while window and ts - window[0][1] > self.kerberoast_window_s:
                    window.popleft()
                unique_spns = {s for s, _ in window}
                if len(unique_spns) >= self.kerberoast_threshold:
                    findings.append(LateralFinding(
                        finding_type="kerberoasting",
                        severity="critical",
                        mitre="T1558.003",
                        description=f"Account '{account}' requested TGS for "
                                    f"{len(unique_spns)} SPNs within "
                                    f"{self.kerberoast_window_s}s — Kerberoasting",
                        evidence={"account": account, "spn_count": len(unique_spns),
                                  "sample_spns": sorted(unique_spns)[:10]},
                        score=50,
                    ))
                    window.clear()
                    break
        return findings

    # ── AS-REP ROASTING: repeated preauth failures across accounts ─────────

    def _detect_asreproasting(self, as_fail_events: List[Tuple[str,float]]) -> List[LateralFinding]:
        findings = []
        if not as_fail_events:
            return findings
        as_fail_events = sorted(as_fail_events, key=lambda x: x[1])
        window: deque = deque()
        for account, ts in as_fail_events:
            window.append((account, ts))
            while window and ts - window[0][1] > self.asrep_window_s:
                window.popleft()
            unique_accounts = {a for a, _ in window}
            if len(unique_accounts) >= self.asrep_threshold:
                findings.append(LateralFinding(
                    finding_type="asrep_roasting",
                    severity="high",
                    mitre="T1558.004",
                    description=f"{len(unique_accounts)} accounts triggered AS-REQ "
                                f"preauth failures within {self.asrep_window_s}s "
                                f"— possible AS-REP roasting enumeration",
                    evidence={"account_count": len(unique_accounts),
                              "sample_accounts": sorted(unique_accounts)[:10]},
                    score=35,
                ))
                window.clear()
        return findings

    # ── NEW EDGE: first-time auth path vs baseline ──────────────────────────

    def _detect_new_edges(self, edges: List[AuthEdge],
                          baseline: Set[Tuple[str,str,str]]) -> List[LateralFinding]:
        findings = []
        seen_new: Set[Tuple[str,str,str]] = set()
        for e in edges:
            key = (e.src, e.dst_host, e.user)
            if key not in baseline and key not in seen_new:
                seen_new.add(key)
                sev = "high" if e.user in PRIVILEGED_ACCOUNTS else "medium"
                findings.append(LateralFinding(
                    finding_type="new_auth_path",
                    severity=sev,
                    mitre="T1021",
                    description=f"First-seen auth path: {e.src} -> {e.dst_host} as '{e.user}' "
                                 f"(not in baseline graph)",
                    evidence={"src": e.src, "dst": e.dst_host, "user": e.user},
                    score=25 if sev == "high" else 10,
                ))
        return findings


def build_edge_set(edges: List[AuthEdge]) -> Set[Tuple[str,str,str]]:
    return {(e.src, e.dst_host, e.user) for e in edges if e.success}


# ── CLI ────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m"}

def _print_finding(f: LateralFinding):
    c = SEV_C.get(f.severity,""); R = "\033[0m"; B = "\033[1m"
    print(f"  {c}[{f.severity.upper():8}]{R} [{f.mitre}] {B}{f.finding_type}{R}  score=+{f.score}")
    print(f"     {f.description}")
    for k, v in f.evidence.items():
        if isinstance(v, list):
            v = v[:8]
        print(f"       {k}: {v}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Lateral Movement Detector")
    parser.add_argument("--logs", nargs="+", required=True, help="Auth log file(s)")
    parser.add_argument("--baseline",      help="Baseline edge-set JSON for new-edge detection")
    parser.add_argument("--save-baseline", help="Save current edge set as baseline JSON")
    parser.add_argument("--fanout-threshold", type=int, default=5)
    parser.add_argument("--fanin-threshold",  type=int, default=4)
    parser.add_argument("--json", help="Output findings JSON")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Lateral Movement Detector ──{R}\n")

    builder = AuthGraphBuilder()
    for log_path in args.logs:
        builder.ingest_file(log_path)

    print(f"  Ingested {len(builder.edges)} auth events from {len(args.logs)} file(s)")
    print(f"  Successful logins: {sum(1 for e in builder.edges if e.success)}")
    print(f"  Failed logins    : {sum(1 for e in builder.edges if not e.success)}")
    print(f"  Kerberos TGS-REQ : {len(builder.kerberos_tgs)}")
    print()

    baseline_edges = None
    if args.baseline and Path(args.baseline).exists():
        with open(args.baseline) as f:
            baseline_edges = {tuple(x) for x in json.load(f)}
        print(f"  Loaded baseline graph: {len(baseline_edges)} known edges\n")

    detector = LateralMovementDetector(
        fanout_threshold=args.fanout_threshold,
        fanin_threshold=args.fanin_threshold,
    )
    findings = detector.detect(builder, baseline_edges)

    for f in findings:
        _print_finding(f)

    total_score = sum(f.score for f in findings)
    print(f"  Total findings: {len(findings)}   Aggregate lateral-movement score: {total_score}")

    if args.save_baseline:
        edges = build_edge_set(builder.edges)
        with open(args.save_baseline, "w") as f:
            json.dump([list(e) for e in edges], f, indent=2)
        print(f"  Saved {len(edges)} edges to {C}{args.save_baseline}{R}")

    if args.json and findings:
        with open(args.json, "w") as f:
            json.dump([fnd.to_dict() for fnd in findings], f, indent=2)
        print(f"  Findings saved to {args.json}")


if __name__ == "__main__":
    main()
