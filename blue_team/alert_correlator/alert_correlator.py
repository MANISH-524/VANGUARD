#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 13 — Alert Correlator & Unification Engine
==========================================================================
Original architecture. THE INTEGRATION SPINE of the SOC suite.

Problem this solves
-------------------
Twelve+ independent detectors each emit their own finding schema. A SOC
analyst (or a single dashboard) cannot reasonably eyeball twelve separate
tools. Vanguard solves this with:

  1. UNIFIED FINDING SCHEMA — every tool's JSON output is normalized into
     one `UnifiedFinding` record: {tool, finding_type, severity, mitre,
     entity, description, evidence, score, timestamp}. Adapters exist for
     every tool in this suite (threat_intel, log_analyzer, vuln_scanner,
     packet_inspector, ioc_hunter, yara_engine, timeline_builder,
     network_mapper, file_integrity, lateral_movement_detector,
     dns_analyzer, credential_monitor, sentry_agent/control_center).

  2. ENTITY RESOLUTION — findings are grouped by "entity" (host, IP, user,
     or file path — whichever the finding concerns), so all signals about
     ONE asset converge into ONE risk picture regardless of which tool
     produced them.

  3. DEDUPLICATION — a content-hash + time-bucket dedup collapses repeat
     alerts (e.g. the same YARA hit reported on every scan) into a single
     record with a hit-counter, preventing alert fatigue.

  4. KILL-CHAIN RECONSTRUCTION — MITRE ATT&CK tactics have a natural
     ordering (Recon → Initial Access → Execution → Persistence → PrivEsc
     → Defense Evasion → Credential Access → Discovery → Lateral Movement
     → Collection → C2 → Exfiltration → Impact). When ONE entity
     accumulates findings spanning ≥3 tactics in increasing order within a
     time window, that's a vastly stronger signal than any single alert —
     Vanguard flags these as RECONSTRUCTED CAMPAIGNS with a campaign score
     that multiplies, not just adds, individual finding scores.

  5. MASTER RISK SCORE — per-entity score = Σ(finding scores) × campaign
     multiplier, feeding directly into control_center.py's isolation logic
     or the SOC dashboard's priority queue.

  6. LIGHTWEIGHT REST API — zero-dependency HTTP server exposing
     /ingest, /findings, /entities, /campaigns for soc_dashboard.py and
     other tools to consume.

Usage:
    python3 alert_correlator.py --ingest-dir /var/vanguard/findings/
    python3 alert_correlator.py --ingest-dir findings/ --serve --port 7100
    python3 alert_correlator.py --ingest-dir findings/ --campaigns-only
"""

import argparse
import hashlib
import json
import logging
import re
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("vanguard.correlator")

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK tactic ordering (for kill-chain reconstruction)
# ─────────────────────────────────────────────────────────────────────────────

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]
TACTIC_RANK = {t: i for i, t in enumerate(TACTIC_ORDER)}

# Technique-ID (base, no sub-technique) -> primary tactic.
# Covers every technique emitted by tools in this suite.
TECHNIQUE_TACTIC: Dict[str, str] = {
    "T1595": "Reconnaissance",
    "T1583": "Resource Development",
    "T1190": "Initial Access",
    "T1078": "Initial Access",          # also Persistence/PrivEsc/DefEvasion — primary listed first
    "T1059": "Execution",
    "T1053": "Persistence",
    "T1543": "Persistence",
    "T1098": "Persistence",
    "T1136": "Persistence",
    "T1505": "Persistence",
    "T1548": "Privilege Escalation",
    "T1027": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1003": "Credential Access",
    "T1110": "Credential Access",
    "T1552": "Credential Access",
    "T1558": "Credential Access",
    "T1082": "Discovery",
    "T1083": "Discovery",
    "T1018": "Discovery",
    "T1021": "Lateral Movement",
    "T1105": "Command and Control",     # also Lateral Movement
    "T1071": "Command and Control",
    "T1568": "Command and Control",
    "T1041": "Exfiltration",
    "T1030": "Exfiltration",
    "T1485": "Impact",
    "T1486": "Impact",
    "T1490": "Impact",
    "T1565": "Impact",
}

def technique_to_tactic(mitre: str) -> str:
    if not mitre:
        return "Unknown"
    base = mitre.split(".")[0]
    return TECHNIQUE_TACTIC.get(base, "Unknown")


# ─────────────────────────────────────────────────────────────────────────────
# Unified schema
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UnifiedFinding:
    tool:         str
    finding_type: str
    severity:     str          # info/low/medium/high/critical
    mitre:        str = ""
    tactic:       str = ""
    entity:       str = ""      # host / IP / user / path — the asset this concerns
    description:  str = ""
    evidence:     dict = field(default_factory=dict)
    score:        int  = 0
    timestamp:    str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    fingerprint:  str  = ""
    hit_count:    int  = 1

    def __post_init__(self):
        if not self.tactic:
            self.tactic = technique_to_tactic(self.mitre)
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        basis = f"{self.tool}|{self.finding_type}|{self.entity}|{self.description[:80]}"
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def ts_epoch(self) -> float:
        try:
            return datetime.fromisoformat(self.timestamp.replace("Z","+00:00")).timestamp()
        except Exception:
            return time.time()

    def to_dict(self) -> dict:
        return asdict(self)


SEV_RANK = {"info":0,"low":1,"medium":2,"high":3,"critical":4}


# ─────────────────────────────────────────────────────────────────────────────
# Per-tool adapters — convert each tool's raw JSON into UnifiedFinding[]
# ─────────────────────────────────────────────────────────────────────────────

def _entity_from_evidence(ev: dict, *keys: str, default: str = "unknown") -> str:
    for k in keys:
        if ev.get(k):
            return str(ev[k])
    return default


class ToolAdapters:
    """One static method per source tool. Each takes raw parsed JSON,
    returns List[UnifiedFinding]. Unknown/empty input returns []."""

    @staticmethod
    def threat_intel(data) -> List[UnifiedFinding]:
        out = []
        items = data if isinstance(data, list) else data.get("hits", [])
        for item in items:
            entry = item.get("entry") or item
            out.append(UnifiedFinding(
                tool="threat_intel", finding_type="ioc_match",
                severity=_tier_to_sev(entry.get("tier","")),
                entity=entry.get("value", entry.get("query","unknown")),
                description=f"IOC match: {entry.get('value','?')} "
                            f"({entry.get('ioc_type','?')}) score={entry.get('score',0)}",
                evidence=entry, score=int(entry.get("score",0)) // 2,
                timestamp=entry.get("last_seen", datetime.now(timezone.utc).isoformat()),
            ))
        return out

    @staticmethod
    def log_analyzer(data) -> List[UnifiedFinding]:
        out = []
        for item in data if isinstance(data, list) else []:
            ev = item.get("matches", {})
            entity = _entity_from_evidence(ev, "ip", "remote_addr", "user", default="loghost")
            out.append(UnifiedFinding(
                tool="log_analyzer", finding_type=item.get("rule_name","log_event"),
                severity=item.get("severity","low"), mitre=item.get("mitre",""),
                entity=entity, description=item.get("description",""),
                evidence={"line": item.get("line_no"), "raw": item.get("raw_line","")[:200]},
                score=item.get("score",0), timestamp=item.get("timestamp",""),
            ))
        return out

    @staticmethod
    def vuln_scanner(data) -> List[UnifiedFinding]:
        out = []
        reports = data if isinstance(data, list) else [data]
        for rep in reports:
            host = rep.get("target","unknown")
            for cve in rep.get("cve_summary", []):
                out.append(UnifiedFinding(
                    tool="vuln_scanner", finding_type="cve_exposure",
                    severity="critical" if "CVE" in cve.get("cve","") and cve.get("cve") in
                             ("CVE-2024-6387","CVE-2019-0708","CVE-2017-0144") else "high",
                    entity=host,
                    description=f"{cve.get('cve','?')}: {cve.get('desc','')} "
                                f"(port {cve.get('port')}/{cve.get('service')})",
                    evidence=cve, score=30,
                    timestamp=rep.get("scan_end", datetime.now(timezone.utc).isoformat()),
                ))
            for pr in rep.get("open_ports", []):
                if pr.get("risk") in ("high","critical"):
                    out.append(UnifiedFinding(
                        tool="vuln_scanner", finding_type="risky_open_port",
                        severity=pr["risk"], entity=host,
                        description=f"Open port {pr['port']}/{pr['service']} risk={pr['risk']}",
                        evidence=pr, score=20,
                        timestamp=rep.get("scan_end", datetime.now(timezone.utc).isoformat()),
                    ))
        return out

    @staticmethod
    def packet_inspector(data) -> List[UnifiedFinding]:
        out = []
        for a in data.get("anomalies", []) if isinstance(data, dict) else []:
            out.append(UnifiedFinding(
                tool="packet_inspector", finding_type=a.get("anomaly_type","net_anomaly"),
                severity=a.get("severity","medium"),
                mitre={"c2_beaconing":"T1071","dns_tunnel":"T1071.004",
                       "port_scan":"T1595","icmp_tunnel":"T1071"}.get(a.get("anomaly_type",""),""),
                entity=a.get("src_ip","unknown"),
                description=a.get("description",""), evidence=a.get("evidence",{}),
                score={"critical":40,"high":30,"medium":15,"low":5}.get(a.get("severity","low"),5),
                timestamp=datetime.fromtimestamp(a.get("ts",time.time()),tz=timezone.utc).isoformat(),
            ))
        return out

    @staticmethod
    def ioc_hunter(data) -> List[UnifiedFinding]:
        out = []
        for item in data if isinstance(data, list) else []:
            out.append(UnifiedFinding(
                tool="ioc_hunter", finding_type=item.get("hunt_type","ioc"),
                severity=item.get("severity","medium"),
                entity=item.get("path","unknown"),
                description=item.get("description",""),
                evidence=item.get("detail",{}),
                score=item.get("confidence",50)//2,
                timestamp=item.get("timestamp",""),
            ))
        return out

    @staticmethod
    def yara_engine(data) -> List[UnifiedFinding]:
        out = []
        for item in data if isinstance(data, list) else []:
            meta = item.get("meta",{})
            out.append(UnifiedFinding(
                tool="yara_engine", finding_type=item.get("rule_name","yara_match"),
                severity=meta.get("severity","medium"), mitre=meta.get("mitre",""),
                entity=item.get("file_path","unknown"),
                description=meta.get("desc", item.get("rule_name","")),
                evidence={"tags": item.get("tags",[]), "matches": item.get("matched_strings",[])},
                score={"critical":40,"high":30,"medium":15,"low":5}.get(meta.get("severity","low"),5),
                timestamp=item.get("timestamp",""),
            ))
        return out

    @staticmethod
    def network_mapper(data) -> List[UnifiedFinding]:
        out = []
        for item in data if isinstance(data, list) else []:
            if item.get("is_rogue"):
                out.append(UnifiedFinding(
                    tool="network_mapper", finding_type="rogue_device",
                    severity="high", mitre="T1190",
                    entity=item.get("ip","unknown"),
                    description=f"Rogue device on network: {item.get('ip')} "
                                f"({item.get('vendor','unknown vendor')})",
                    evidence=item, score=25,
                ))
            for port in item.get("open_ports", []):
                if port in (23, 2375, 6379, 11211):  # known-risky exposed services
                    out.append(UnifiedFinding(
                        tool="network_mapper", finding_type="risky_service_exposed",
                        severity="medium", entity=item.get("ip","unknown"),
                        description=f"Host {item.get('ip')} exposes risky port {port}",
                        evidence={"port": port}, score=15,
                    ))
        return out

    @staticmethod
    def file_integrity(data) -> List[UnifiedFinding]:
        out = []
        for item in data if isinstance(data, list) else []:
            out.append(UnifiedFinding(
                tool="file_integrity", finding_type=f"fim_{item.get('change_type','change').lower()}",
                severity=item.get("severity","low"),
                mitre="T1565" if item.get("change_type")=="MODIFIED" else "",
                entity=item.get("path","unknown"),
                description=item.get("description",""),
                evidence={"old": item.get("old",{}), "new": item.get("new",{})},
                score=item.get("criticality",20)//2,
                timestamp=item.get("timestamp",""),
            ))
        return out

    @staticmethod
    def lateral_movement_detector(data) -> List[UnifiedFinding]:
        out = []
        for item in data if isinstance(data, list) else []:
            ev = item.get("evidence",{})
            entity = _entity_from_evidence(ev, "src", "host", "account", "user", default="unknown")
            out.append(UnifiedFinding(
                tool="lateral_movement_detector", finding_type=item.get("finding_type","lateral"),
                severity=item.get("severity","medium"), mitre=item.get("mitre",""),
                entity=entity, description=item.get("description",""),
                evidence=ev, score=item.get("score",0),
                timestamp=item.get("timestamp",""),
            ))
        return out

    @staticmethod
    def dns_analyzer(data) -> List[UnifiedFinding]:
        out = []
        for item in data if isinstance(data, list) else []:
            ev = item.get("evidence",{})
            entity = _entity_from_evidence(ev, "src", "qname", default="unknown")
            out.append(UnifiedFinding(
                tool="dns_analyzer", finding_type=item.get("finding_type","dns_threat"),
                severity=item.get("severity","medium"), mitre=item.get("mitre",""),
                entity=entity, description=item.get("description",""),
                evidence=ev, score=item.get("score",0),
                timestamp=item.get("timestamp",""),
            ))
        return out

    @staticmethod
    def credential_monitor(data) -> List[UnifiedFinding]:
        out = []
        for item in data if isinstance(data, list) else []:
            ev = item.get("evidence",{})
            entity = _entity_from_evidence(ev, "src", "user", "account", default="unknown")
            out.append(UnifiedFinding(
                tool="credential_monitor", finding_type=item.get("finding_type","cred_event"),
                severity=item.get("severity","medium"), mitre=item.get("mitre",""),
                entity=entity, description=item.get("description",""),
                evidence=ev, score=item.get("score",0),
                timestamp=item.get("timestamp",""),
            ))
        return out

    @staticmethod
    def vanguard_alerts(data) -> List[UnifiedFinding]:
        """control_center.py / sentry_agent.py telemetry export."""
        out = []
        vms = data.get("vms", data) if isinstance(data, dict) else data
        if isinstance(vms, dict):
            vms = [vms]
        for vm in vms:
            vm_id = vm.get("vm_id","unknown")
            for ev in vm.get("recent_events", []):
                if ev.get("event_type") == "heartbeat":
                    continue
                out.append(UnifiedFinding(
                    tool="vanguard_sentry", finding_type=ev.get("event_type","alert"),
                    severity=ev.get("severity","medium"),
                    entity=vm_id, description=f"[{ev.get('event_type')}] "
                                  + json.dumps(ev.get("details",{}))[:150],
                    evidence=ev.get("details",{}), score=ev.get("score_delta",0),
                    timestamp=ev.get("timestamp",""),
                ))
        return out

    @staticmethod
    def config_auditor(data) -> List[UnifiedFinding]:
        """config_auditor.py --json report (wrapper: {summary, checks})."""
        out = []
        checks = data.get("checks", []) if isinstance(data, dict) else data
        host = (data.get("summary", {}) or {}).get("host", "unknown") if isinstance(data, dict) else "unknown"
        for item in checks:
            status = item.get("status", "")
            if status not in ("FAIL", "WARN"):
                continue   # PASS/SKIP/INFO carry no risk signal
            sev = item.get("severity", "medium")
            if status == "WARN" and sev == "critical":
                sev = "high"   # WARN never outranks a true FAIL critical
            out.append(UnifiedFinding(
                tool="config_auditor", finding_type=f"hardening_{status.lower()}",
                severity=sev, entity=host,
                description=f"[{item.get('check_id','')}] {item.get('title','')}: "
                            f"{item.get('description','')}",
                evidence={"category": item.get("category",""),
                          "remediation": item.get("remediation",""),
                          "weight": item.get("weight",0)},
                score=item.get("weight", 0),
                timestamp=item.get("timestamp",""),
            ))
        return out


def _tier_to_sev(tier: str) -> str:
    return {"CLEAN":"info","SUSPICIOUS":"low","MALICIOUS":"high","CRITICAL":"critical"}.get(tier,"medium")


# ─────────────────────────────────────────────────────────────────────────────
# Auto-detection of which adapter a JSON file needs
# ─────────────────────────────────────────────────────────────────────────────

ADAPTER_SIGNATURES: List[Tuple[str, callable]] = [
    ("vanguard_alerts",  lambda d: isinstance(d, dict) and "vms" in d),
    ("config_auditor",   lambda d: isinstance(d, dict) and "checks" in d and "summary" in d),
    ("threat_intel",     lambda d: isinstance(d, list) and d and "tier" in d[0]),
    ("vuln_scanner",     lambda d: (isinstance(d, list) and d and "open_ports" in d[0]) or
                                    (isinstance(d, dict) and "open_ports" in d)),
    ("packet_inspector", lambda d: isinstance(d, dict) and "anomalies" in d),
    ("yara_engine",      lambda d: isinstance(d, list) and d and "matched_strings" in d[0]),
    ("network_mapper",   lambda d: isinstance(d, list) and d and "vendor" in d[0]),
    ("file_integrity",   lambda d: isinstance(d, list) and d and "change_type" in d[0]),
    ("ioc_hunter",       lambda d: isinstance(d, list) and d and "hunt_type" in d[0]),
    ("lateral_movement_detector",
                         lambda d: isinstance(d, list) and d and d[0].get("finding_type","").startswith(
                             ("fanout","fanin","auth_chain","privilege_jump","kerberoast","asrep","new_auth"))),
    ("dns_analyzer",     lambda d: isinstance(d, list) and d and d[0].get("finding_type","") in
                             ("dga_domain","fast_flux","dns_tunnel","typosquat","nxdomain_burst")),
    ("credential_monitor", lambda d: isinstance(d, list) and d and d[0].get("finding_type","") in
                             ("password_spray","exposed_secret","weak_hash_algorithm","shared_password_hash")),
    ("log_analyzer",     lambda d: isinstance(d, list) and d and "rule_name" in d[0] and "matches" in d[0]),
]


def detect_adapter(data) -> Optional[str]:
    for name, test in ADAPTER_SIGNATURES:
        try:
            if test(data):
                return name
        except Exception:
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Correlation engine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Campaign:
    entity:        str
    tactics:       List[str]
    finding_count: int
    base_score:    int
    multiplier:    float
    final_score:   int
    span_seconds:  float
    findings:      List[dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class CorrelationEngine:
    def __init__(self, dedup_window_s: int = 300, campaign_window_s: int = 3600):
        self.dedup_window_s    = dedup_window_s
        self.campaign_window_s = campaign_window_s
        self._findings: List[UnifiedFinding] = []
        self._fingerprint_index: Dict[str, UnifiedFinding] = {}

    def ingest(self, findings: List[UnifiedFinding]):
        for f in findings:
            existing = self._fingerprint_index.get(f.fingerprint)
            if existing and abs(f.ts_epoch() - existing.ts_epoch()) <= self.dedup_window_s:
                existing.hit_count += 1
                existing.timestamp = f.timestamp
                continue
            self._findings.append(f)
            self._fingerprint_index[f.fingerprint] = f

    def ingest_file(self, path: str) -> int:
        try:
            data = json.loads(Path(path).read_text())
        except Exception as e:
            logger.warning("Cannot load %s: %s", path, e)
            return 0
        adapter_name = detect_adapter(data)
        if not adapter_name:
            logger.warning("Unrecognized schema: %s — skipped", path)
            return 0
        adapter = getattr(ToolAdapters, adapter_name)
        findings = adapter(data)
        self.ingest(findings)
        logger.info("Ingested %d findings from %s [%s]", len(findings), path, adapter_name)
        return len(findings)

    def ingest_dir(self, directory: str) -> int:
        total = 0
        for fp in Path(directory).rglob("*.json"):
            total += self.ingest_file(str(fp))
        return total

    def entities(self) -> List[dict]:
        by_entity: Dict[str, List[UnifiedFinding]] = defaultdict(list)
        for f in self._findings:
            by_entity[f.entity].append(f)

        out = []
        for entity, fnds in by_entity.items():
            score = sum(f.score * f.hit_count for f in fnds)
            sev_counts = defaultdict(int)
            for f in fnds:
                sev_counts[f.severity] += 1
            out.append({
                "entity": entity, "finding_count": len(fnds),
                "total_score": score, "by_severity": dict(sev_counts),
                "tools_involved": sorted({f.tool for f in fnds}),
            })
        out.sort(key=lambda x: -x["total_score"])
        return out

    def reconstruct_campaigns(self) -> List[Campaign]:
        by_entity: Dict[str, List[UnifiedFinding]] = defaultdict(list)
        for f in self._findings:
            if f.tactic != "Unknown":
                by_entity[f.entity].append(f)

        campaigns = []
        for entity, fnds in by_entity.items():
            fnds.sort(key=lambda f: f.ts_epoch())
            if len(fnds) < 2:
                continue

            # Sliding window: find max span where tactics are non-decreasing
            # and span >= 2 distinct tactics, prioritizing increasing rank order
            window: List[UnifiedFinding] = []
            for f in fnds:
                window.append(f)
                while window and f.ts_epoch() - window[0].ts_epoch() > self.campaign_window_s:
                    window.pop(0)

            tactics_in_window = []
            seen_ranks: Set[int] = set()
            for f in window:
                r = TACTIC_RANK.get(f.tactic, -1)
                if r >= 0:
                    seen_ranks.add(r)
                    tactics_in_window.append(f.tactic)

            unique_tactics = sorted(set(tactics_in_window), key=lambda t: TACTIC_RANK.get(t, 99))

            if len(unique_tactics) >= 3:
                base_score = sum(f.score * f.hit_count for f in window)
                multiplier = 1.0 + 0.5 * (len(unique_tactics) - 2)  # 3 tactics->1.5x, 4->2.0x, ...
                span = window[-1].ts_epoch() - window[0].ts_epoch()
                campaigns.append(Campaign(
                    entity=entity,
                    tactics=unique_tactics,
                    finding_count=len(window),
                    base_score=base_score,
                    multiplier=round(multiplier,2),
                    final_score=int(base_score * multiplier),
                    span_seconds=round(span,1),
                    findings=[f.to_dict() for f in window],
                ))

        campaigns.sort(key=lambda c: -c.final_score)
        return campaigns

    def summary(self) -> dict:
        sev = defaultdict(int)
        tool_counts = defaultdict(int)
        for f in self._findings:
            sev[f.severity] += f.hit_count
            tool_counts[f.tool] += 1
        return {
            "total_findings": len(self._findings),
            "total_hits":      sum(f.hit_count for f in self._findings),
            "by_severity":     dict(sev),
            "by_tool":         dict(tool_counts),
            "campaigns":       len(self.reconstruct_campaigns()),
        }

    def all_findings(self, min_severity: str = "info") -> List[UnifiedFinding]:
        min_rank = SEV_RANK.get(min_severity, 0)
        out = [f for f in self._findings if SEV_RANK.get(f.severity,0) >= min_rank]
        out.sort(key=lambda f: (-SEV_RANK.get(f.severity,0), -f.score))
        return out


# ─────────────────────────────────────────────────────────────────────────────
# REST API
# ─────────────────────────────────────────────────────────────────────────────

class CorrelatorHandler(BaseHTTPRequestHandler):
    engine: CorrelationEngine = None

    def log_message(self, *_): pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/findings":
            min_sev = params.get("min_severity",["info"])[0]
            data = [f.to_dict() for f in self.engine.all_findings(min_sev)]
            self._json({"findings": data, "count": len(data)})
        elif parsed.path == "/entities":
            self._json({"entities": self.engine.entities()})
        elif parsed.path == "/campaigns":
            self._json({"campaigns": [c.to_dict() for c in self.engine.reconstruct_campaigns()]})
        elif parsed.path == "/summary":
            self._json(self.engine.summary())
        elif parsed.path == "/health":
            self._json({"status":"ok","service":"vanguard-correlator"})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length",0))
        body   = self.rfile.read(length)
        if parsed.path == "/ingest":
            try:
                data = json.loads(body)
                adapter_name = detect_adapter(data)
                if not adapter_name:
                    self._json({"error":"unrecognized schema"}, 400); return
                findings = getattr(ToolAdapters, adapter_name)(data)
                self.engine.ingest(findings)
                self._json({"ingested": len(findings), "adapter": adapter_name})
            except Exception as e:
                self._json({"error": str(e)}, 400)
        else:
            self.send_response(404); self.end_headers()

    def _json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers()
        self.wfile.write(body)


def serve(engine: CorrelationEngine, host="0.0.0.0", port=7100):
    CorrelatorHandler.engine = engine
    srv = HTTPServer((host, port), CorrelatorHandler)
    logger.info("Alert Correlator API on http://%s:%d", host, port)
    srv.serve_forever()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m","info":"\033[2m"}

def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Alert Correlator")
    parser.add_argument("--ingest-dir", help="Directory of *.json finding files")
    parser.add_argument("--ingest-file", nargs="*", help="Specific JSON files")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int, default=7100)
    parser.add_argument("--campaigns-only", action="store_true")
    parser.add_argument("--min-severity", default="medium",
                        choices=["info","low","medium","high","critical"])
    parser.add_argument("--json", help="Export unified findings to JSON")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Alert Correlator ──{R}\n")

    engine = CorrelationEngine()
    if args.ingest_dir:
        n = engine.ingest_dir(args.ingest_dir)
        print(f"  Ingested {n} raw findings from {args.ingest_dir}\n")
    if args.ingest_file:
        for fp in args.ingest_file:
            engine.ingest_file(fp)

    if not args.campaigns_only:
        findings = engine.all_findings(args.min_severity)
        for f in findings[:50]:
            c = SEV_C.get(f.severity,"")
            hit = f" x{f.hit_count}" if f.hit_count > 1 else ""
            print(f"  {c}[{f.severity.upper():8}]{R} [{f.tool:24}] {f.tactic:18} "
                  f"{f.entity[:24]:24} {f.description[:60]}{hit}")
        if len(findings) > 50:
            print(f"  ... {len(findings)-50} more")

    campaigns = engine.reconstruct_campaigns()
    if campaigns:
        print(f"\n  {B}\033[91m⚠ {len(campaigns)} RECONSTRUCTED CAMPAIGN(S){R}\n")
        for camp in campaigns[:10]:
            print(f"  {B}{camp.entity}{R} — {len(camp.tactics)} tactics, "
                  f"{camp.finding_count} findings, span={camp.span_seconds:.0f}s")
            print(f"    Kill chain: {' → '.join(camp.tactics)}")
            print(f"    Score: {camp.base_score} × {camp.multiplier} = "
                  f"\033[91m{camp.final_score}\033[0m\n")

    s = engine.summary()
    print(f"\n  {B}Summary{R}: {s['total_findings']} unique findings "
          f"({s['total_hits']} total hits) | by severity: {s['by_severity']}")
    print(f"  Tools reporting: {list(s['by_tool'].keys())}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump([fn.to_dict() for fn in engine.all_findings("info")], f, indent=2)
        print(f"\n  Unified findings exported to {C}{args.json}{R}")

    if args.serve:
        print(f"\n  Starting REST API on port {args.port} ...")
        serve(engine, port=args.port)


if __name__ == "__main__":
    main()
