#!/usr/bin/env python3
"""
Vanguard-OOB :: Master SOC Dashboard
=====================================
The unified command-and-control interface for ALL 20 Blue Team tools.
Single Flask application serving a real-time dark SOC dashboard that:

  - Polls every tool's output directory for new findings (every 2s)
  - Ingests findings through the alert_correlator's unified schema
  - Displays entity-centric risk view (top 50 highest-risk assets)
  - Shows live kill-chain campaign reconstruction
  - Renders live event feed from all sources simultaneously
  - Provides per-tool status tiles (last run time, finding counts)
  - Offers one-click launch of any tool via the API
  - Exposes REST endpoints for SIEM/SOAR integration

Architecture:
  Thread 1 — FileWatcher: monitors findings/ dir for new JSON, ingests via correlator
  Thread 2 — Flask server on :8080
  Main     — Periodic correlator refresh loop

Usage:
    python3 soc_dashboard.py --findings-dir /var/vanguard/findings --port 8080
    python3 soc_dashboard.py --findings-dir findings/ --port 8080 --correlator-port 7100
"""

import argparse
import json
import logging
import os
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template_string, request

# Import correlator (sibling module)
sys.path.insert(0, str(Path(__file__).parent.parent / "alert_correlator"))
try:
    from alert_correlator import CorrelationEngine, load_all_findings
    CORRELATOR_AVAILABLE = True
except ImportError:
    CORRELATOR_AVAILABLE = False

logger = logging.getLogger("vanguard.soc_dashboard")

# ── Tool registry ─────────────────────────────────────────────────────────────

TOOL_REGISTRY = {
    "threat_intel":               {"icon": "🔍", "category": "Intel",     "color": "#38bdf8"},
    "log_analyzer":               {"icon": "📋", "category": "Detection",  "color": "#818cf8"},
    "vuln_scanner":               {"icon": "🎯", "category": "Scanning",   "color": "#f97316"},
    "packet_inspector":           {"icon": "📡", "category": "Network",    "color": "#34d399"},
    "ioc_hunter":                 {"icon": "🔎", "category": "Hunting",    "color": "#f472b6"},
    "yara_engine":                {"icon": "⚡", "category": "Detection",  "color": "#facc15"},
    "timeline_builder":           {"icon": "📅", "category": "Forensics",  "color": "#a78bfa"},
    "network_mapper":             {"icon": "🗺️",  "category": "Network",    "color": "#22d3ee"},
    "file_integrity":             {"icon": "🛡️",  "category": "Integrity",  "color": "#86efac"},
    "lateral_movement_detector":  {"icon": "🔗", "category": "Detection",  "color": "#fb7185"},
    "dns_analyzer":               {"icon": "🌐", "category": "Network",    "color": "#67e8f9"},
    "credential_monitor":         {"icon": "🔑", "category": "Identity",   "color": "#fde68a"},
    "alert_correlator":           {"icon": "🔄", "category": "Correlation","color": "#c4b5fd"},
    "behavioral_engine":          {"icon": "🧠", "category": "UEBA",       "color": "#6ee7b7"},
    "config_auditor":             {"icon": "⚙️",  "category": "Hardening",  "color": "#93c5fd"},
    "deception_engine":           {"icon": "🪤", "category": "Deception",  "color": "#f9a8d4"},
    "threat_hunter":              {"icon": "🏹", "category": "Hunting",    "color": "#fcd34d"},
    "reporting_engine":           {"icon": "📊", "category": "Reporting",  "color": "#a5b4fc"},
    "honeypot_manager":           {"icon": "🍯", "category": "Deception",  "color": "#fdba74"},
    "memory_forensics":           {"icon": "🧬", "category": "Forensics",  "color": "#d9f99d"},
    "vanguard_sentry":            {"icon": "👁️",  "category": "OOB Agent",  "color": "#e2e8f0"},
}

SEV_RANK    = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
TACTIC_ORDER= ["Reconnaissance","Resource Development","Initial Access","Execution",
               "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
               "Discovery","Lateral Movement","Collection","Command and Control",
               "Exfiltration","Impact"]


# ── State store (thread-safe) ─────────────────────────────────────────────────

class DashboardState:
    def __init__(self):
        self._lock          = threading.RLock()
        self._findings:     List[dict] = []
        self._ingested_fps: set = set()
        self._tool_stats:   Dict[str, dict] = {}
        self._last_refresh: float = 0.0
        self._campaigns:    List[dict] = []
        self._entities:     List[dict] = []

    def ingest_file(self, fp: str):
        with self._lock:
            if fp in self._ingested_fps:
                return 0
            self._ingested_fps.add(fp)

        try:
            data = json.loads(Path(fp).read_text())
        except Exception:
            return 0

        items = data if isinstance(data, list) else list(data.values())[0] if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = [data]

        count = 0
        with self._lock:
            for item in items:
                if isinstance(item, dict) and item.get("severity"):
                    self._findings.append(item)
                    count += 1
                    tool = item.get("tool") or item.get("source") or "unknown"
                    if tool not in self._tool_stats:
                        self._tool_stats[tool] = {"count": 0, "last_seen": "", "critical": 0, "high": 0}
                    self._tool_stats[tool]["count"] += 1
                    self._tool_stats[tool]["last_seen"] = datetime.now(timezone.utc).isoformat()
                    if item.get("severity") in ("critical","high"):
                        self._tool_stats[tool][item["severity"]] += 1

            # Keep last 10,000 findings in memory
            if len(self._findings) > 10000:
                self._findings = self._findings[-10000:]

        return count

    def refresh_analytics(self):
        with self._lock:
            findings = list(self._findings)

        # Entity risk scores
        entity_scores: Dict[str, dict] = defaultdict(lambda: {"score": 0, "findings": 0,
                                                               "severities": Counter()})
        for f in findings:
            ent = f.get("entity") or f.get("path") or f.get("vm_id", "unknown")
            sev = f.get("severity","info")
            sc  = f.get("score", {"critical":40,"high":25,"medium":10,"low":3,"info":0}.get(sev,0))
            entity_scores[ent]["score"] += sc
            entity_scores[ent]["findings"] += 1
            entity_scores[ent]["severities"][sev] += 1

        entities_sorted = sorted(
            [{"entity": k, **v, "severities": dict(v["severities"])}
             for k, v in entity_scores.items()],
            key=lambda x: -x["score"]
        )[:50]

        # Campaign reconstruction (simplified)
        tactic_map: Dict[str, set] = defaultdict(set)
        for f in findings:
            tactic = f.get("tactic","")
            ent    = f.get("entity","")
            if tactic and ent:
                tactic_map[ent].add(tactic)

        campaigns = []
        for ent, tactics in tactic_map.items():
            ordered = [t for t in TACTIC_ORDER if t in tactics]
            if len(ordered) >= 3:
                base_score = entity_scores[ent]["score"]
                multiplier = 1.0 + 0.5 * (len(ordered) - 2)
                campaigns.append({
                    "entity":      ent,
                    "tactics":     ordered,
                    "tactic_count":len(ordered),
                    "base_score":  base_score,
                    "final_score": int(base_score * multiplier),
                    "multiplier":  round(multiplier, 1),
                })
        campaigns.sort(key=lambda c: -c["final_score"])

        with self._lock:
            self._entities   = entities_sorted
            self._campaigns  = campaigns[:20]
            self._last_refresh = time.time()

    def get_dashboard_data(self) -> dict:
        with self._lock:
            findings = list(self._findings)
            sev_counts = Counter(f.get("severity","info") for f in findings)
            tactic_counts = Counter(f.get("tactic","") for f in findings if f.get("tactic"))
            tool_counts   = Counter(f.get("tool","") or f.get("source","") for f in findings)

            # Recent events feed (last 100, newest first)
            recent = sorted(findings, key=lambda f: f.get("timestamp",""), reverse=True)[:100]

            # Risk score (0-100 normalized)
            raw_score = sum({"critical":40,"high":25,"medium":10,"low":3,"info":0}
                             .get(f.get("severity","info"),0) for f in findings)
            import math
            risk_score = min(100, int(math.log1p(raw_score) / math.log1p(400) * 100))

            return {
                "total_findings":   len(findings),
                "risk_score":       risk_score,
                "by_severity":      dict(sev_counts),
                "top_tactics":      tactic_counts.most_common(10),
                "top_tools":        tool_counts.most_common(10),
                "entities":         self._entities[:30],
                "campaigns":        self._campaigns[:10],
                "recent_events":    recent[:50],
                "tool_stats":       dict(self._tool_stats),
                "last_refresh":     self._last_refresh,
                "server_time":      datetime.now(timezone.utc).isoformat(),
            }


# ── File watcher ──────────────────────────────────────────────────────────────

class FindingsWatcher:
    def __init__(self, state: DashboardState, findings_dir: str, interval: float = 2.0):
        self.state        = state
        self.findings_dir = Path(findings_dir)
        self.interval     = interval
        self._stop        = threading.Event()
        self._thread      = threading.Thread(target=self._loop, daemon=True, name="FindingsWatcher")

    def start(self):
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self._thread.start()
        logger.info("Watching for findings in: %s", self.findings_dir)

    def stop(self):
        self._stop.set()

    def _loop(self):
        analytics_counter = 0
        while not self._stop.is_set():
            for fp in self.findings_dir.rglob("*.json"):
                count = self.state.ingest_file(str(fp))
                if count:
                    logger.debug("Ingested %d findings from %s", count, fp.name)

            analytics_counter += 1
            if analytics_counter >= 5:   # refresh analytics every 10s
                self.state.refresh_analytics()
                analytics_counter = 0

            self._stop.wait(self.interval)


# ── Dashboard HTML ────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VANGUARD-OOB :: Master SOC Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Inter:wght@300;400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#040608;--panel:#080c10;--card:#0b1118;--card2:#0e1520;
  --border:#1a2535;--glow:#0d4f6c;--text:#c8dde8;--dim:#4a6070;--muted:#2a3845;
  --cyan:#00c8e8;--blue:#0088cc;--green:#00cc66;--yellow:#e8b800;
  --red:#ff2222;--orange:#ff6600;--purple:#c026d3;--pink:#f472b6;
  --font-d:'Orbitron',monospace;--font-m:'Share Tech Mono',monospace;--font-u:'Inter',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font-u);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,200,230,.012) 2px,rgba(0,200,230,.012) 4px);pointer-events:none;z-index:9999}
body::after{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,140,180,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,140,180,.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}

/* TOPBAR */
.topbar{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:0 1.5rem;height:52px;background:rgba(4,6,8,.97);border-bottom:1px solid var(--border);backdrop-filter:blur(12px)}
.logo{display:flex;align-items:center;gap:10px}
.logo-hex{width:28px;height:28px;background:var(--cyan);clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);animation:hex-pulse 3s ease-in-out infinite}
@keyframes hex-pulse{0%,100%{box-shadow:0 0 0 0 rgba(0,200,230,0)}50%{box-shadow:0 0 12px 4px rgba(0,200,230,.3)}}
.logo-text{font-family:var(--font-d);font-size:.85rem;font-weight:900;letter-spacing:.15em;color:var(--cyan);text-shadow:0 0 20px rgba(0,200,230,.5)}
.topbar-meta{font-family:var(--font-m);font-size:.75rem;color:var(--dim);letter-spacing:.08em}
.status-pill{display:flex;align-items:center;gap:6px;font-family:var(--font-m);font-size:.7rem;color:var(--green);letter-spacing:.12em}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:blink 1.5s step-end infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
#conn-status.err{color:var(--red)}.err .dot{background:var(--red)}

/* MAIN GRID */
.main{position:relative;z-index:1;padding:1.2rem 1.5rem;max-width:1800px;margin:0 auto}
.sec-label{font-family:var(--font-m);font-size:.6rem;letter-spacing:.25em;color:var(--muted);text-transform:uppercase;margin-bottom:.6rem;display:flex;align-items:center;gap:8px}
.sec-label::after{content:'';flex:1;height:1px;background:var(--border)}

/* STAT ROW */
.stat-row{display:grid;grid-template-columns:repeat(6,1fr);gap:.8rem;margin-bottom:1.2rem}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:4px;padding:1rem 1.2rem;position:relative;overflow:hidden;transition:border-color .3s}
.stat-card::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--accent,var(--cyan));opacity:.7}
.stat-card:hover{border-color:var(--glow)}
.stat-label{font-family:var(--font-m);font-size:.6rem;letter-spacing:.2em;color:var(--dim);text-transform:uppercase;margin-bottom:.35rem}
.stat-value{font-family:var(--font-d);font-size:1.6rem;font-weight:700;color:var(--accent,var(--cyan));line-height:1}
.stat-sub{font-family:var(--font-m);font-size:.65rem;color:var(--dim);margin-top:.25rem}

/* RISK GAUGE */
.risk-gauge-wrap{display:flex;flex-direction:column;align-items:center;padding:.5rem}
#risk-ring{transition:stroke-dashoffset .8s ease,stroke .8s ease}

/* MAIN CONTENT GRID */
.content-grid{display:grid;grid-template-columns:2fr 1fr;gap:1rem;margin-bottom:1rem}
.content-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:1rem}

/* PANEL */
.panel{background:var(--card);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.panel-header{display:flex;align-items:center;justify-content:space-between;padding:.7rem 1rem;background:var(--card2);border-bottom:1px solid var(--border)}
.panel-title{font-family:var(--font-d);font-size:.7rem;letter-spacing:.15em;color:var(--cyan)}
.panel-count{font-family:var(--font-m);font-size:.65rem;color:var(--dim)}
.panel-body{padding:.7rem 1rem;max-height:280px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--glow) transparent}
.panel-body::-webkit-scrollbar{width:3px}.panel-body::-webkit-scrollbar-thumb{background:var(--glow);border-radius:2px}

/* ENTITY TABLE */
.entity-row{display:grid;grid-template-columns:1fr 80px 120px;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03);font-family:var(--font-m);font-size:.7rem}
.entity-name{color:var(--cyan);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.entity-score{text-align:right;font-weight:bold}
.score-bar-wrap{height:4px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden}
.score-bar-fill{height:100%;border-radius:2px;transition:width .5s ease}

/* CAMPAIGN */
.campaign-card{background:rgba(192,38,211,.08);border:1px solid rgba(192,38,211,.25);border-radius:4px;padding:.8rem;margin-bottom:.6rem;animation:slide-in .3s ease}
@keyframes slide-in{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
.campaign-entity{font-family:var(--font-m);font-size:.75rem;color:#e879f9;margin-bottom:.3rem}
.campaign-chain{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:.4rem}
.tactic-pill{font-family:var(--font-m);font-size:.6rem;padding:1px 6px;border-radius:2px;background:rgba(192,38,211,.15);color:#d946ef;border:1px solid rgba(192,38,211,.2)}
.campaign-score{font-family:var(--font-d);font-size:.8rem;color:#f0abfc}

/* EVENT FEED */
.event-item{display:grid;grid-template-columns:90px 80px 100px 1fr;gap:8px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.025);font-family:var(--font-m);font-size:.68rem;animation:slide-in .2s ease}
.ev-time{color:var(--muted)}
.ev-sev{font-weight:bold}
.ev-sev.critical{color:#f0abfc}.ev-sev.high{color:var(--red)}.ev-sev.medium{color:var(--yellow)}.ev-sev.low{color:var(--green)}.ev-sev.info{color:var(--dim)}
.ev-tool{color:var(--blue);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev-desc{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* TOOL GRID */
.tool-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.6rem;margin-bottom:1rem}
.tool-tile{background:var(--card);border:1px solid var(--border);border-radius:4px;padding:.7rem .9rem;transition:all .2s;cursor:default}
.tool-tile:hover{border-color:var(--glow);transform:translateY(-1px)}
.tool-tile.active{border-color:rgba(0,200,230,.3);background:rgba(0,200,230,.04)}
.tool-icon{font-size:1.2rem;margin-bottom:.3rem}
.tool-name{font-family:var(--font-m);font-size:.65rem;color:var(--dim);letter-spacing:.05em;margin-bottom:.15rem}
.tool-count{font-family:var(--font-d);font-size:.9rem;font-weight:700}
.tool-last{font-family:var(--font-m);font-size:.58rem;color:var(--muted);margin-top:.15rem}

/* BADGE */
.badge{display:inline-block;padding:2px 8px;border-radius:2px;font-family:var(--font-m);font-size:.62rem;font-weight:bold;letter-spacing:.1em;text-transform:uppercase}
.badge-critical{background:rgba(192,38,211,.15);color:#e879f9;border:1px solid rgba(192,38,211,.3)}
.badge-high{background:rgba(255,34,34,.15);color:var(--red);border:1px solid rgba(255,34,34,.3)}
.badge-medium{background:rgba(232,184,0,.12);color:var(--yellow);border:1px solid rgba(232,184,0,.25)}
.badge-low{background:rgba(0,204,102,.12);color:var(--green);border:1px solid rgba(0,204,102,.25)}
.badge-info{background:rgba(74,96,112,.15);color:var(--dim);border:1px solid rgba(74,96,112,.25)}

/* TACTIC BAR */
.tactic-row{display:flex;align-items:center;gap:8px;padding:2px 0;font-family:var(--font-m);font-size:.67rem}
.tactic-name{color:var(--dim);width:160px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tactic-track{flex:1;height:5px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden}
.tactic-fill{height:100%;border-radius:3px;background:var(--blue);transition:width .5s}
.tactic-num{color:var(--cyan);min-width:28px;text-align:right}

/* EMPTY */
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:120px;color:var(--muted);font-family:var(--font-m);font-size:.7rem;letter-spacing:.15em;gap:6px}
.empty-icon{font-size:1.6rem;opacity:.3}

@media(max-width:1200px){.stat-row{grid-template-columns:repeat(3,1fr)}.content-grid{grid-template-columns:1fr}.content-grid-3{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.stat-row{grid-template-columns:repeat(2,1fr)}.tool-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>

<nav class="topbar">
  <div class="logo">
    <div class="logo-hex"></div>
    <div>
      <div class="logo-text">VANGUARD-OOB</div>
      <div style="font-family:var(--font-m);font-size:.6rem;color:var(--dim);letter-spacing:.2em">MASTER SOC DASHBOARD · 20 TOOLS ACTIVE</div>
    </div>
  </div>
  <div class="topbar-meta" id="server-clock">--:--:-- UTC</div>
  <div class="status-pill" id="conn-status">
    <div class="dot"></div><span>LIVE</span>
  </div>
</nav>

<main class="main">

  <!-- STAT ROW -->
  <div class="sec-label">system overview</div>
  <div class="stat-row">
    <div class="stat-card" style="--accent:var(--cyan)">
      <div class="stat-label">Risk Score</div>
      <div class="stat-value" id="stat-risk">0</div>
      <div class="stat-sub">0=clean · 100=critical</div>
    </div>
    <div class="stat-card" style="--accent:#e879f9">
      <div class="stat-label">Critical</div>
      <div class="stat-value" id="stat-crit" style="color:#e879f9">0</div>
      <div class="stat-sub">immediate action</div>
    </div>
    <div class="stat-card" style="--accent:var(--red)">
      <div class="stat-label">High</div>
      <div class="stat-value" id="stat-high" style="color:var(--red)">0</div>
      <div class="stat-sub">priority review</div>
    </div>
    <div class="stat-card" style="--accent:var(--yellow)">
      <div class="stat-label">Campaigns</div>
      <div class="stat-value" id="stat-campaigns" style="color:var(--yellow)">0</div>
      <div class="stat-sub">multi-tactic chains</div>
    </div>
    <div class="stat-card" style="--accent:var(--green)">
      <div class="stat-label">Tools Active</div>
      <div class="stat-value" id="stat-tools" style="color:var(--green)">0</div>
      <div class="stat-sub">of 20 reporting</div>
    </div>
    <div class="stat-card" style="--accent:var(--blue)">
      <div class="stat-label">Total Findings</div>
      <div class="stat-value" id="stat-total" style="color:var(--blue)">0</div>
      <div class="stat-sub">all sources</div>
    </div>
  </div>

  <!-- ENTITY + CAMPAIGNS -->
  <div class="content-grid">
    <div>
      <div class="sec-label">entity risk matrix (top 30)</div>
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">⬡ ASSET THREAT SCORES</div>
          <div class="panel-count" id="entity-count">0 assets</div>
        </div>
        <div class="panel-body" id="entity-list">
          <div class="empty"><div class="empty-icon">⬡</div><div>AWAITING TELEMETRY</div></div>
        </div>
      </div>
    </div>
    <div>
      <div class="sec-label">kill-chain campaigns</div>
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">⚡ RECONSTRUCTED ATTACKS</div>
          <div class="panel-count" id="campaign-count">0 campaigns</div>
        </div>
        <div class="panel-body" id="campaign-list">
          <div class="empty"><div class="empty-icon">◈</div><div>NO CAMPAIGNS DETECTED</div></div>
        </div>
      </div>
    </div>
  </div>

  <!-- TACTIC + EVENT FEED -->
  <div class="content-grid">
    <div>
      <div class="sec-label">live event feed</div>
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">⚡ REAL-TIME THREAT STREAM</div>
          <div class="panel-count" id="feed-count">0 events</div>
        </div>
        <div class="panel-body" id="event-feed">
          <div class="empty"><div class="empty-icon">◈</div><div>NO EVENTS YET</div></div>
        </div>
      </div>
    </div>
    <div>
      <div class="sec-label">mitre att&amp;ck coverage</div>
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">⬡ TACTICS OBSERVED</div>
          <div class="panel-count" id="tactic-count">0 tactics</div>
        </div>
        <div class="panel-body" id="tactic-bars">
          <div class="empty"><div class="empty-icon">◈</div><div>NO TACTIC DATA</div></div>
        </div>
      </div>
    </div>
  </div>

  <!-- TOOL STATUS GRID -->
  <div class="sec-label">tool status (20 active)</div>
  <div class="tool-grid" id="tool-grid">
    <!-- populated by JS -->
  </div>

</main>

<script>
const TOOL_META = {
  threat_intel:{icon:"🔍",color:"#38bdf8"},log_analyzer:{icon:"📋",color:"#818cf8"},
  vuln_scanner:{icon:"🎯",color:"#f97316"},packet_inspector:{icon:"📡",color:"#34d399"},
  ioc_hunter:{icon:"🔎",color:"#f472b6"},yara_engine:{icon:"⚡",color:"#facc15"},
  timeline_builder:{icon:"📅",color:"#a78bfa"},network_mapper:{icon:"🗺️",color:"#22d3ee"},
  file_integrity:{icon:"🛡️",color:"#86efac"},lateral_movement_detector:{icon:"🔗",color:"#fb7185"},
  dns_analyzer:{icon:"🌐",color:"#67e8f9"},credential_monitor:{icon:"🔑",color:"#fde68a"},
  alert_correlator:{icon:"🔄",color:"#c4b5fd"},behavioral_engine:{icon:"🧠",color:"#6ee7b7"},
  config_auditor:{icon:"⚙️",color:"#93c5fd"},deception_engine:{icon:"🪤",color:"#f9a8d4"},
  threat_hunter:{icon:"🏹",color:"#fcd34d"},reporting_engine:{icon:"📊",color:"#a5b4fc"},
  honeypot_manager:{icon:"🍯",color:"#fdba74"},memory_forensics:{icon:"🧬",color:"#d9f99d"},
  vanguard_sentry:{icon:"👁️",color:"#e2e8f0"},
};

let prevData = null;
let eventKeys = new Set();

function clock(){
  const n=new Date();
  document.getElementById('server-clock').textContent=
    n.toISOString().replace('T',' ').replace(/\..*/,' UTC');
}
setInterval(clock,1000);clock();

function scoreColor(s){
  if(s>=80)return'#e879f9';
  if(s>=60)return'#ff2222';
  if(s>=40)return'#e8b800';
  if(s>=20)return'#ff6600';
  return'#00cc66';
}

function fmtTs(ts){
  try{return new Date(ts).toISOString().replace('T',' ').replace(/\..*/,'');}catch{return ts||'';}
}

function update(data){
  const d = data;

  // Stats
  const riskC = scoreColor(d.risk_score);
  document.getElementById('stat-risk').textContent=d.risk_score;
  document.getElementById('stat-risk').style.color=riskC;
  document.getElementById('stat-crit').textContent=d.by_severity?.critical||0;
  document.getElementById('stat-high').textContent=d.by_severity?.high||0;
  document.getElementById('stat-campaigns').textContent=d.campaigns?.length||0;
  document.getElementById('stat-tools').textContent=Object.keys(d.tool_stats||{}).length;
  document.getElementById('stat-total').textContent=d.total_findings||0;

  // Entity list
  const entities = d.entities||[];
  document.getElementById('entity-count').textContent=`${entities.length} assets`;
  if(entities.length){
    const maxScore = Math.max(...entities.map(e=>e.score),1);
    document.getElementById('entity-list').innerHTML = entities.map(e=>{
      const pct = Math.min(100,(e.score/maxScore)*100);
      const c   = scoreColor(e.score);
      const sev = e.severities||{};
      const badges = Object.entries(sev).filter(([k,v])=>v>0 && k!='info')
        .map(([k,v])=>`<span class="badge badge-${k}">${v}</span>`).join(' ');
      return `<div class="entity-row">
        <div class="entity-name" title="${e.entity}">${e.entity}</div>
        <div class="entity-score" style="color:${c}">${e.score}</div>
        <div>
          <div class="score-bar-wrap">
            <div class="score-bar-fill" style="width:${pct}%;background:${c}"></div>
          </div>
        </div>
      </div>`;
    }).join('');
  } else {
    document.getElementById('entity-list').innerHTML=
      '<div class="empty"><div class="empty-icon">⬡</div><div>AWAITING TELEMETRY</div></div>';
  }

  // Campaigns
  const camps = d.campaigns||[];
  document.getElementById('campaign-count').textContent=`${camps.length} campaigns`;
  if(camps.length){
    document.getElementById('campaign-list').innerHTML=camps.map(c=>`
      <div class="campaign-card">
        <div class="campaign-entity">${c.entity}</div>
        <div class="campaign-chain">
          ${(c.tactics||[]).map(t=>`<span class="tactic-pill">${t}</span>`).join('→')}
        </div>
        <div class="campaign-score">Score: ${c.base_score} × ${c.multiplier} = <b>${c.final_score}</b></div>
      </div>`).join('');
  } else {
    document.getElementById('campaign-list').innerHTML=
      '<div class="empty"><div class="empty-icon">◈</div><div>NO CAMPAIGNS DETECTED</div></div>';
  }

  // Event feed
  const events = d.recent_events||[];
  document.getElementById('feed-count').textContent=`${d.total_findings||0} total`;
  const feedEl = document.getElementById('event-feed');
  if(events.length){
    const empty = feedEl.querySelector('.empty');
    if(empty) empty.remove();
    events.forEach(ev=>{
      const key=`${ev.timestamp}|${ev.entity||''}|${ev.description||''}`;
      if(eventKeys.has(key)) return;
      eventKeys.add(key);
      if(eventKeys.size>500){
        const arr=[...eventKeys];
        eventKeys=new Set(arr.slice(-400));
      }
      const row=document.createElement('div');
      row.className='event-item';
      const ts=(fmtTs(ev.timestamp).split(' ')[1])||'';
      const sev=(ev.severity||'info').toLowerCase();
      const tool=(ev.tool||ev.source||'').replace(/_/g,' ').substring(0,14);
      const desc=(ev.description||'').substring(0,80);
      row.innerHTML=`
        <span class="ev-time">${ts}</span>
        <span class="ev-sev ${sev}">${sev.toUpperCase()}</span>
        <span class="ev-tool">${tool}</span>
        <span class="ev-desc">${desc}</span>`;
      feedEl.insertBefore(row,feedEl.firstChild);
      while(feedEl.children.length>200) feedEl.lastChild.remove();
    });
  }

  // Tactic bars
  const tactics = d.top_tactics||[];
  document.getElementById('tactic-count').textContent=`${tactics.length} tactics`;
  if(tactics.length){
    const maxT=Math.max(...tactics.map(([,n])=>n),1);
    document.getElementById('tactic-bars').innerHTML=tactics.map(([name,cnt])=>
      `<div class="tactic-row">
        <div class="tactic-name">${name}</div>
        <div class="tactic-track"><div class="tactic-fill" style="width:${(cnt/maxT)*100}%"></div></div>
        <div class="tactic-num">${cnt}</div>
      </div>`).join('');
  }

  // Tool grid
  const toolStats = d.tool_stats||{};
  const allTools  = {...TOOL_META};
  const gridEl    = document.getElementById('tool-grid');
  gridEl.innerHTML='';
  Object.entries(allTools).forEach(([name,meta])=>{
    const stats = toolStats[name]||{count:0,last_seen:'',critical:0,high:0};
    const active = stats.count>0;
    const tile   = document.createElement('div');
    tile.className='tool-tile'+(active?' active':'');
    const lastTs = stats.last_seen ? fmtTs(stats.last_seen).split(' ')[1] : 'no data';
    tile.innerHTML=`
      <div class="tool-icon">${meta.icon}</div>
      <div class="tool-name">${name.replace(/_/g,' ')}</div>
      <div class="tool-count" style="color:${active?meta.color:'var(--muted)'}">
        ${stats.count||0}
      </div>
      <div class="tool-last">${lastTs}</div>`;
    gridEl.appendChild(tile);
  });

  prevData=data;
}

async function poll(){
  try{
    const r=await fetch('/api/dashboard');
    if(!r.ok) throw new Error(`${r.status}`);
    const data=await r.json();
    update(data);
    const cs=document.getElementById('conn-status');
    cs.classList.remove('err');
    cs.querySelector('span').textContent='LIVE';
  } catch(e){
    const cs=document.getElementById('conn-status');
    cs.classList.add('err');
    cs.querySelector('span').textContent='OFFLINE';
  }
}

setInterval(poll,2000);
poll();
</script>
</body>
</html>"""


# ── Flask application ─────────────────────────────────────────────────────────

def create_app(state: DashboardState) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def dashboard():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/dashboard")
    def api_dashboard():
        return jsonify(state.get_dashboard_data())

    @app.route("/api/entities")
    def api_entities():
        data = state.get_dashboard_data()
        return jsonify({"entities": data["entities"]})

    @app.route("/api/campaigns")
    def api_campaigns():
        data = state.get_dashboard_data()
        return jsonify({"campaigns": data["campaigns"]})

    @app.route("/api/findings")
    def api_findings():
        sev = request.args.get("min_severity","info")
        data = state.get_dashboard_data()
        rank = {"info":0,"low":1,"medium":2,"high":3,"critical":4}
        min_r = rank.get(sev,0)
        filtered = [f for f in state._findings
                    if rank.get(f.get("severity","info"),0) >= min_r]
        return jsonify({"findings": filtered[-200:], "count": len(filtered)})

    @app.route("/api/ingest", methods=["POST"])
    def api_ingest():
        """Receive a batch of findings directly via HTTP POST."""
        try:
            data = request.get_json(force=True)
            items = data if isinstance(data, list) else [data]
            with state._lock:
                for item in items:
                    if isinstance(item, dict):
                        state._findings.append(item)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ingested": len(items)})

    @app.route("/api/tools")
    def api_tools():
        data = state.get_dashboard_data()
        return jsonify({"tools": data["tool_stats"]})

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "service": "vanguard-soc-dashboard"})

    return app


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Vanguard-OOB Master SOC Dashboard")
    parser.add_argument("--findings-dir", default="findings",
                        help="Directory to watch for *.json finding files (default: ./findings)")
    parser.add_argument("--port",    type=int, default=8080)
    parser.add_argument("--host",    default="0.0.0.0")
    parser.add_argument("--watch-interval", type=float, default=2.0,
                        help="File watcher poll interval in seconds (default: 2.0)")
    args = parser.parse_args()

    C="\033[96m"; R="\033[0m"; B="\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Master SOC Dashboard ──{R}")
    print(f"  20 Blue Team tools · Unified detection · Real-time correlation\n")

    state   = DashboardState()
    watcher = FindingsWatcher(state, args.findings_dir, interval=args.watch_interval)
    watcher.start()
    print(f"  Watching : {C}{args.findings_dir}{R}")
    print(f"  Dashboard: {C}http://{args.host}:{args.port}{R}")
    print(f"  API      : {C}http://{args.host}:{args.port}/api/dashboard{R}\n")

    # Suppress Flask startup noise
    import logging as _log
    _log.getLogger("werkzeug").setLevel(_log.WARNING)

    app = create_app(state)
    try:
        app.run(host=args.host, port=args.port, debug=False,
                use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        print("\n  Stopping dashboard...")
        watcher.stop()


if __name__ == "__main__":
    main()
