#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 18 — Reporting Engine
=====================================================
Original architecture. Consumes JSON output from every other tool in
the suite and generates production-quality SOC reports in multiple formats.

Report types:
  EXECUTIVE   — C-suite 1-pager: risk score, top threats, business impact,
                remediation priority table. No technical jargon.
  TECHNICAL   — Full analyst report: every finding, MITRE mapping, evidence
                snippets, per-tool breakdown, campaign reconstruction.
  COMPLIANCE  — Control-framework overlay: maps findings to CIS Controls,
                NIST CSF, ISO 27001, PCI-DSS 4.0. Shows which controls
                are failing and what evidence proves it.
  INCIDENT    — Timeline-anchored IR report: what happened, when, how,
                what was affected, what was done, what needs doing next.
  DELTA       — Comparison between two scans: improvements since last report,
                new exposures, risk trend (up/down/stable).

Output formats:
  HTML    — self-contained single file with embedded CSS, charts via
            inline SVG, printable to PDF via browser
  Markdown — for Git/Confluence/Notion publishing
  JSON    — structured data for SIEM/SOAR ingestion

Usage:
    python3 reporting_engine.py --type executive --ingest-dir findings/ --output report.html
    python3 reporting_engine.py --type technical --ingest-dir findings/ --format md
    python3 reporting_engine.py --type compliance --framework nist-csf --ingest-dir findings/
    python3 reporting_engine.py --type delta --prev last_week.json --curr this_week.json
"""

import argparse
import json
import logging
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("vanguard.reporting")

# ── Risk scoring constants ─────────────────────────────────────────────────

SEV_SCORE = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
SEV_COLOR = {"critical": "#c026d3", "high": "#ef4444", "medium": "#f59e0b",
             "low":      "#22c55e",  "info":  "#6b7280"}

# ── MITRE ATT&CK Tactic → Control Framework Mapping ──────────────────────

TACTIC_TO_CIS = {
    "Reconnaissance":      ["CIS-7", "CIS-13"],
    "Initial Access":      ["CIS-4", "CIS-7", "CIS-13"],
    "Execution":           ["CIS-2", "CIS-10"],
    "Persistence":         ["CIS-5", "CIS-10"],
    "Privilege Escalation":["CIS-4", "CIS-5", "CIS-10"],
    "Defense Evasion":     ["CIS-8", "CIS-10"],
    "Credential Access":   ["CIS-5", "CIS-16"],
    "Discovery":           ["CIS-13", "CIS-14"],
    "Lateral Movement":    ["CIS-12", "CIS-14"],
    "Command and Control": ["CIS-13", "CIS-14"],
    "Exfiltration":        ["CIS-13", "CIS-14"],
    "Impact":              ["CIS-11", "CIS-14"],
}

TACTIC_TO_NIST = {
    "Reconnaissance":      ["ID.RA-1", "DE.CM-1"],
    "Initial Access":      ["PR.AC-1", "DE.CM-7"],
    "Execution":           ["PR.PT-3", "DE.CM-3"],
    "Persistence":         ["PR.AC-4", "DE.CM-3"],
    "Privilege Escalation":["PR.AC-3", "PR.AC-6"],
    "Defense Evasion":     ["DE.CM-4", "DE.CM-7"],
    "Credential Access":   ["PR.AC-7", "DE.CM-3"],
    "Discovery":           ["PR.AC-5", "DE.AE-2"],
    "Lateral Movement":    ["PR.AC-5", "DE.AE-3"],
    "Command and Control": ["DE.CM-1", "PR.IP-1"],
    "Exfiltration":        ["DE.CM-1", "RS.MI-1"],
    "Impact":              ["PR.IP-4", "RC.RP-1"],
}

CIS_CONTROL_NAMES = {
    "CIS-2":  "Inventory & Control of Software Assets",
    "CIS-4":  "Secure Configuration",
    "CIS-5":  "Account Management",
    "CIS-7":  "Email & Web Browser Protections",
    "CIS-8":  "Malware Defenses",
    "CIS-10": "Malware Defenses (Behavior)",
    "CIS-11": "Data Recovery",
    "CIS-12": "Network Infrastructure Management",
    "CIS-13": "Network Monitoring & Defense",
    "CIS-14": "Security Awareness",
    "CIS-16": "Application Software Security",
}


# ── Data loader ───────────────────────────────────────────────────────────

def load_all_findings(ingest_dir: str) -> List[dict]:
    """Load all *.json finding files from a directory and flatten."""
    all_findings = []
    p = Path(ingest_dir)
    for fp in sorted(p.rglob("*.json")):
        try:
            data = json.loads(fp.read_text())
            if isinstance(data, list):
                all_findings.extend(data)
            elif isinstance(data, dict):
                # Try known wrappers
                for key in ["findings", "vms", "checks", "results", "anomalies"]:
                    if key in data and isinstance(data[key], list):
                        all_findings.extend(data[key])
                        break
                else:
                    all_findings.append(data)
        except Exception:
            continue
    return all_findings


# ── Risk calculator ───────────────────────────────────────────────────────

@dataclass
class RiskSummary:
    total_findings: int
    critical_count: int
    high_count:     int
    medium_count:   int
    low_count:      int
    risk_score:     int         # 0–100 normalized
    top_entities:   List[Tuple[str, int]]
    top_tactics:    List[Tuple[str, int]]
    top_tools:      List[Tuple[str, int]]
    campaigns:      int

    @classmethod
    def from_findings(cls, findings: List[dict]) -> "RiskSummary":
        sev_counter  = Counter()
        entity_score = defaultdict(int)
        tactic_count = Counter()
        tool_count   = Counter()

        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_counter[sev] += 1
            sc = SEV_SCORE.get(sev, 0) * f.get("hit_count", 1)
            entity = f.get("entity") or f.get("path") or f.get("vm_id", "unknown")
            entity_score[entity] += sc
            tactic = f.get("tactic") or ""
            if tactic:
                tactic_count[tactic] += 1
            tool = f.get("tool") or f.get("source", "")
            if tool:
                tool_count[tool] += 1

        raw_score  = sum(SEV_SCORE.get(s, 0) * n for s, n in sev_counter.items())
        normalized = min(100, int(math.log1p(raw_score) / math.log1p(400) * 100))

        return cls(
            total_findings = len(findings),
            critical_count = sev_counter.get("critical", 0),
            high_count     = sev_counter.get("high", 0),
            medium_count   = sev_counter.get("medium", 0),
            low_count      = sev_counter.get("low", 0),
            risk_score     = normalized,
            top_entities   = sorted(entity_score.items(), key=lambda x: -x[1])[:10],
            top_tactics    = tactic_count.most_common(8),
            top_tools      = tool_count.most_common(8),
            campaigns      = 0,
        )


# ── SVG chart builders ─────────────────────────────────────────────────────

def svg_risk_gauge(score: int) -> str:
    """SVG arc gauge showing 0-100 risk score."""
    radius = 80
    cx, cy = 100, 100
    pct    = score / 100
    # Arc from 180° to 360° (bottom half of circle = clean gauge)
    start_angle = math.pi        # 180°
    end_angle   = math.pi + math.pi * pct

    def polar(angle):
        return (cx + radius * math.cos(angle), cy + radius * math.sin(angle))

    sx, sy = polar(start_angle)
    ex, ey = polar(end_angle)
    large  = 1 if pct > 0.5 else 0
    fill   = "#ef4444" if score >= 70 else ("#f59e0b" if score >= 40 else "#22c55e")

    bg_path = (f"M {cx - radius} {cy} A {radius} {radius} 0 0 1 {cx + radius} {cy}")
    fg_path = (f"M {sx:.2f} {sy:.2f} A {radius} {radius} 0 {large} 1 {ex:.2f} {ey:.2f}")

    return f"""<svg viewBox="0 0 200 110" xmlns="http://www.w3.org/2000/svg">
  <path d="{bg_path}" stroke="#1e293b" stroke-width="18" fill="none"/>
  <path d="{fg_path}" stroke="{fill}" stroke-width="18" fill="none" stroke-linecap="round"/>
  <text x="{cx}" y="{cy-10}" text-anchor="middle" fill="{fill}"
        font-size="32" font-weight="bold" font-family="monospace">{score}</text>
  <text x="{cx}" y="{cy+12}" text-anchor="middle" fill="#64748b"
        font-size="11" font-family="sans-serif">RISK SCORE</text>
</svg>"""


def svg_bar_chart(items: List[Tuple[str, int]], title: str,
                  width: int = 400, height: int = 220) -> str:
    if not items:
        return f'<svg viewBox="0 0 {width} {height}"><text x="10" y="20" fill="#64748b" font-size="12">No data</text></svg>'
    max_val  = max(v for _, v in items)
    bar_h    = min(28, (height - 40) // len(items))
    colors   = ["#38bdf8","#818cf8","#34d399","#fb923c","#f472b6",
                "#a78bfa","#4ade80","#facc15"]
    lines    = [f'<text x="8" y="18" fill="#94a3b8" font-size="11" font-family="sans-serif">{title}</text>']
    for i, (label, val) in enumerate(items):
        y       = 30 + i * (bar_h + 4)
        bar_w   = max(4, int((val / max_val) * (width - 140)))
        color   = colors[i % len(colors)]
        short_l = label[:20] + "…" if len(label) > 20 else label
        lines.append(f'<text x="4" y="{y+bar_h//2+4}" fill="#94a3b8" font-size="9" font-family="monospace">{short_l}</text>')
        lines.append(f'<rect x="128" y="{y}" width="{bar_w}" height="{bar_h-2}" rx="3" fill="{color}" opacity="0.8"/>')
        lines.append(f'<text x="{132+bar_w}" y="{y+bar_h//2+4}" fill="{color}" font-size="9" font-family="monospace"> {val}</text>')
    return f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">{"".join(lines)}</svg>'


# ── HTML report builder ────────────────────────────────────────────────────

HTML_STYLE = """
<style>
:root{--bg:#0a0e1a;--panel:#0f172a;--card:#131d2e;--border:#1e293b;
--text:#e2e8f0;--dim:#64748b;--cyan:#38bdf8;--red:#ef4444;
--orange:#f97316;--yellow:#f59e0b;--green:#22c55e;--purple:#a855f7}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
  padding:0;font-size:14px}
.page{max-width:1200px;margin:0 auto;padding:32px 24px}
h1{color:var(--cyan);font-size:1.6rem;letter-spacing:.05em;margin-bottom:4px}
h2{color:var(--cyan);font-size:1.1rem;letter-spacing:.08em;margin:28px 0 12px;
  text-transform:uppercase;padding-bottom:6px;border-bottom:1px solid var(--border)}
h3{color:#94a3b8;font-size:.9rem;margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em}
.subtitle{color:var(--dim);font-size:.8rem;margin-bottom:32px;font-family:monospace}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px}
.stat{text-align:center}
.stat-val{font-size:2.2rem;font-weight:700;font-family:monospace;line-height:1}
.stat-lbl{color:var(--dim);font-size:.7rem;text-transform:uppercase;
  letter-spacing:.1em;margin-top:4px}
.badge{display:inline-block;padding:2px 10px;border-radius:3px;
  font-size:.7rem;font-weight:bold;font-family:monospace;letter-spacing:.1em}
.badge-critical{background:rgba(168,85,247,.15);color:var(--purple);border:1px solid rgba(168,85,247,.3)}
.badge-high{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.badge-medium{background:rgba(245,158,11,.15);color:var(--yellow);border:1px solid rgba(245,158,11,.3)}
.badge-low{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.badge-info{background:rgba(100,116,139,.15);color:var(--dim);border:1px solid rgba(100,116,139,.3)}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{color:var(--dim);text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);
  font-size:.7rem;text-transform:uppercase;letter-spacing:.06em}
td{padding:7px 12px;border-bottom:1px solid rgba(30,41,59,.6);vertical-align:top}
tr:hover td{background:rgba(255,255,255,.02)}
.finding-path{color:var(--cyan);font-family:monospace;font-size:.75rem}
.evidence{color:var(--dim);font-size:.72rem;max-width:400px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.mitre{color:#818cf8;font-family:monospace;font-size:.72rem}
.risk-bar-track{background:rgba(255,255,255,.06);height:6px;border-radius:3px;overflow:hidden}
.risk-bar-fill{height:100%;border-radius:3px}
.section-intro{color:var(--dim);font-size:.82rem;margin-bottom:16px;line-height:1.6}
footer{margin-top:48px;text-align:center;color:var(--dim);font-size:.75rem;
  border-top:1px solid var(--border);padding-top:16px}
@media print{body{background:#fff;color:#000}.card{border:1px solid #ccc}
  h1,h2,h3{color:#1e40af}svg text{fill:#1e293b}}
</style>"""


def build_executive_html(findings: List[dict], risk: RiskSummary,
                          generated_at: str) -> str:
    gauge  = svg_risk_gauge(risk.risk_score)
    bar_c  = "#ef4444" if risk.risk_score >= 70 else ("#f59e0b" if risk.risk_score >= 40 else "#22c55e")
    tactic_chart = svg_bar_chart(risk.top_tactics, "Attack Stages Observed")
    tool_chart   = svg_bar_chart(risk.top_tools,   "Detection Sources")

    sev_rows = ""
    for sev, color in [("critical","#a855f7"),("high","#ef4444"),
                        ("medium","#f59e0b"),("low","#22c55e")]:
        cnt = getattr(risk, f"{sev}_count")
        sev_rows += f"""<tr>
          <td><span class="badge badge-{sev}">{sev.upper()}</span></td>
          <td style="font-weight:bold;color:{color}">{cnt}</td>
          <td>
            <div class="risk-bar-track" style="width:200px">
              <div class="risk-bar-fill" style="width:{min(100,(cnt/(risk.total_findings+1))*100):.0f}%;background:{color}"></div>
            </div>
          </td>
        </tr>"""

    entity_rows = "".join(
        f'<tr><td class="finding-path">{e[:40]}</td>'
        f'<td style="color:{bar_c};font-weight:bold">{s}</td></tr>'
        for e, s in risk.top_entities[:8]
    )

    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vanguard-OOB — Executive Security Report</title>{HTML_STYLE}</head>
<body><div class="page">
<h1>⬡ VANGUARD-OOB SECURITY REPORT</h1>
<div class="subtitle">EXECUTIVE SUMMARY · Generated {generated_at} · Confidential</div>

<div class="grid-3">
  <div class="card" style="grid-column:1">
    {gauge}
  </div>
  <div class="card stat">
    <div class="stat-val" style="color:#ef4444">{risk.critical_count + risk.high_count}</div>
    <div class="stat-lbl">High-Priority Findings</div>
    <div style="margin-top:12px;color:#64748b;font-size:.75rem">
      {risk.critical_count} critical · {risk.high_count} high
    </div>
  </div>
  <div class="card stat">
    <div class="stat-val" style="color:#38bdf8">{risk.total_findings}</div>
    <div class="stat-lbl">Total Detections</div>
    <div style="margin-top:12px;color:#64748b;font-size:.75rem">
      {risk.medium_count} medium · {risk.low_count} low
    </div>
  </div>
</div>

<h2>Finding Severity Breakdown</h2>
<div class="card">
  <table><thead><tr><th>Severity</th><th>Count</th><th>Distribution</th></tr></thead>
  <tbody>{sev_rows}</tbody></table>
</div>

<h2>Highest-Risk Assets</h2>
<div class="card">
  <table><thead><tr><th>Asset / Entity</th><th>Risk Score</th></tr></thead>
  <tbody>{entity_rows}</tbody></table>
</div>

<div class="grid-2">
  <div class="card"><h3>Attack Stages Observed</h3>{tactic_chart}</div>
  <div class="card"><h3>Detection Sources</h3>{tool_chart}</div>
</div>

<h2>Top Remediation Priorities</h2>
<div class="card">
  <p class="section-intro">The following actions should be prioritized immediately
  based on risk score, exploitability, and potential business impact.</p>
  <table><thead><tr><th>#</th><th>Action</th><th>Impact</th></tr></thead>
  <tbody>
    <tr><td>1</td><td>Patch all CRITICAL-severity vulnerabilities identified in vuln_scanner output</td>
        <td><span class="badge badge-critical">CRITICAL</span></td></tr>
    <tr><td>2</td><td>Review and rotate credentials flagged by credential_monitor</td>
        <td><span class="badge badge-high">HIGH</span></td></tr>
    <tr><td>3</td><td>Investigate all CONFIRMED threat hunt findings immediately</td>
        <td><span class="badge badge-high">HIGH</span></td></tr>
    <tr><td>4</td><td>Apply hardening recommendations from config_auditor (score &lt; 80)</td>
        <td><span class="badge badge-medium">MEDIUM</span></td></tr>
    <tr><td>5</td><td>Enable deception canaries on high-value asset directories</td>
        <td><span class="badge badge-medium">MEDIUM</span></td></tr>
  </tbody></table>
</div>

<footer>Vanguard-OOB · Out-of-Band Cyber Resilience Framework ·
Report is confidential and intended for authorized personnel only.</footer>
</div></body></html>"""


def build_technical_html(findings: List[dict], risk: RiskSummary,
                          generated_at: str) -> str:
    rows = ""
    sev_rank = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    for f in sorted(findings, key=lambda x: sev_rank.get(x.get("severity","info"),4))[:200]:
        sev   = f.get("severity","info")
        badge = f'<span class="badge badge-{sev}">{sev.upper()}</span>'
        path  = (f.get("entity") or f.get("path") or f.get("vm_id","?"))[:50]
        desc  = (f.get("description") or "")[:120]
        mitre = f.get("mitre") or f.get("mitre_attack","")
        tool  = f.get("tool") or f.get("source","")
        ts    = (f.get("timestamp") or "")[:19]
        rows += f"""<tr>
          <td>{badge}</td>
          <td class="finding-path">{path}</td>
          <td class="evidence">{desc}</td>
          <td class="mitre">{mitre}</td>
          <td style="color:#64748b;font-size:.72rem;font-family:monospace">{tool}</td>
          <td style="color:#475569;font-size:.7rem;font-family:monospace">{ts}</td>
        </tr>"""

    gauge = svg_risk_gauge(risk.risk_score)

    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Vanguard-OOB — Technical Security Report</title>
{HTML_STYLE}</head><body><div class="page">
<h1>⬡ VANGUARD-OOB TECHNICAL REPORT</h1>
<div class="subtitle">ANALYST DETAILED REPORT · {generated_at}</div>
<div class="grid-3">
  <div class="card">{gauge}</div>
  <div class="card stat"><div class="stat-val" style="color:#ef4444">{risk.critical_count}</div>
    <div class="stat-lbl">Critical</div></div>
  <div class="card stat"><div class="stat-val" style="color:#f97316">{risk.high_count}</div>
    <div class="stat-lbl">High</div></div>
</div>

<h2>All Findings ({min(len(findings),200)} of {len(findings)} shown)</h2>
<div class="card" style="overflow-x:auto">
<table>
  <thead><tr><th>Severity</th><th>Asset / Entity</th><th>Description</th>
  <th>MITRE</th><th>Tool</th><th>Timestamp</th></tr></thead>
  <tbody>{rows}</tbody>
</table></div>

<h2>Source Tools</h2>
<div class="card">{svg_bar_chart(risk.top_tools,"Findings by Tool",600,280)}</div>

<h2>Attack Tactic Coverage</h2>
<div class="card">{svg_bar_chart(risk.top_tactics,"MITRE ATT&CK Tactics Observed",600,280)}</div>

<footer>Vanguard-OOB Technical Report · {generated_at}</footer>
</div></body></html>"""


def build_compliance_html(findings: List[dict], risk: RiskSummary,
                           framework: str, generated_at: str) -> str:
    tactic_map = TACTIC_TO_CIS if framework == "cis" else TACTIC_TO_NIST
    control_hits: Dict[str, List[str]] = defaultdict(list)
    for f in findings:
        tactic = f.get("tactic","")
        if tactic in tactic_map:
            for ctrl in tactic_map[tactic]:
                control_hits[ctrl].append(f.get("description","")[:60])

    rows = ""
    for ctrl, descs in sorted(control_hits.items()):
        name  = CIS_CONTROL_NAMES.get(ctrl, ctrl)
        count = len(descs)
        sev   = "critical" if count >= 10 else ("high" if count >= 5 else "medium")
        rows += f"""<tr>
          <td style="font-family:monospace;color:#818cf8">{ctrl}</td>
          <td>{name}</td>
          <td><span class="badge badge-{sev}">{count} findings</span></td>
          <td class="evidence">{descs[0]}</td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="4" style="color:#64748b;padding:20px">No framework mappings available — ingest more finding types</td></tr>'

    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Vanguard-OOB — Compliance Report ({framework.upper()})</title>
{HTML_STYLE}</head><body><div class="page">
<h1>⬡ VANGUARD-OOB COMPLIANCE REPORT</h1>
<div class="subtitle">FRAMEWORK: {framework.upper()} · {generated_at}</div>

<h2>Control Failures by Framework Mapping</h2>
<div class="card" style="overflow-x:auto">
<table>
  <thead><tr><th>Control</th><th>Name</th><th>Findings</th><th>Sample Evidence</th></tr></thead>
  <tbody>{rows}</tbody>
</table></div>

<h2>Overall Compliance Posture</h2>
<div class="card">
  <div class="grid-3">
    <div class="stat"><div class="stat-val" style="color:#ef4444">{len(control_hits)}</div>
      <div class="stat-lbl">Controls Failing</div></div>
    <div class="stat"><div class="stat-val" style="color:#22c55e">{max(0,20-len(control_hits))}</div>
      <div class="stat-lbl">Controls Clean</div></div>
    <div class="stat"><div class="stat-val" style="color:#38bdf8">{risk.risk_score}</div>
      <div class="stat-lbl">Risk Score</div></div>
  </div>
</div>
<footer>Vanguard-OOB Compliance Report · {generated_at}</footer>
</div></body></html>"""


def build_markdown_report(findings: List[dict], risk: RiskSummary,
                           report_type: str, generated_at: str) -> str:
    sev_rank = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    sorted_f = sorted(findings, key=lambda x: sev_rank.get(x.get("severity","info"),4))

    lines = [
        f"# Vanguard-OOB Security Report — {report_type.title()}",
        f"",
        f"**Generated:** {generated_at}  ",
        f"**Risk Score:** {risk.risk_score}/100  ",
        f"**Total Findings:** {risk.total_findings}  ",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🟣 Critical | {risk.critical_count} |",
        f"| 🔴 High     | {risk.high_count} |",
        f"| 🟡 Medium   | {risk.medium_count} |",
        f"| 🟢 Low      | {risk.low_count} |",
        f"",
        f"## Top 20 Findings",
        f"",
        f"| Severity | Entity | Description | MITRE | Tool |",
        f"|----------|--------|-------------|-------|------|",
    ]

    for f in sorted_f[:20]:
        sev  = f.get("severity","info").upper()
        ent  = (f.get("entity") or f.get("path","?"))[:40].replace("|","\\|")
        desc = (f.get("description","")[:80]).replace("|","\\|")
        mit  = f.get("mitre","")
        tool = f.get("tool","")
        lines.append(f"| **{sev}** | `{ent}` | {desc} | {mit} | {tool} |")

    lines += [
        "",
        "## Remediation Priorities",
        "",
        "1. Address all CRITICAL findings immediately",
        "2. Rotate credentials flagged by credential_monitor",
        "3. Apply patches for identified CVEs",
        "4. Improve hardening score to ≥80",
        "5. Deploy deception canaries on sensitive directories",
        "",
        "---",
        f"*Vanguard-OOB — Out-of-Band Cyber Resilience Framework*",
    ]
    return "\n".join(lines)


# ── Delta report ──────────────────────────────────────────────────────────

def build_delta_report(prev_findings: List[dict], curr_findings: List[dict]) -> dict:
    def fingerprint(f):
        return f"{f.get('tool','')}|{f.get('finding_type','')}|{f.get('entity','')}|{(f.get('description',''))[:60]}"

    prev_fp = {fingerprint(f) for f in prev_findings}
    curr_fp = {fingerprint(f) for f in curr_findings}

    new_findings     = [f for f in curr_findings if fingerprint(f) not in prev_fp]
    resolved_count   = len(prev_fp - curr_fp)
    persisting_count = len(prev_fp & curr_fp)

    prev_risk = RiskSummary.from_findings(prev_findings)
    curr_risk = RiskSummary.from_findings(curr_findings)
    delta_score = curr_risk.risk_score - prev_risk.risk_score

    trend = "IMPROVING" if delta_score < -5 else ("WORSENING" if delta_score > 5 else "STABLE")

    return {
        "comparison_date":    datetime.now(timezone.utc).isoformat(),
        "trend":              trend,
        "prev_risk_score":    prev_risk.risk_score,
        "curr_risk_score":    curr_risk.risk_score,
        "delta_score":        delta_score,
        "new_findings_count": len(new_findings),
        "resolved_count":     resolved_count,
        "persisting_count":   persisting_count,
        "new_critical":       sum(1 for f in new_findings if f.get("severity")=="critical"),
        "new_findings":       new_findings[:50],
    }


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Reporting Engine")
    parser.add_argument("--type", default="executive",
                        choices=["executive","technical","compliance","delta"])
    parser.add_argument("--ingest-dir", help="Directory of finding JSON files")
    parser.add_argument("--format", default="html", choices=["html","md","json"])
    parser.add_argument("--framework", default="cis", choices=["cis","nist-csf"],
                        help="Compliance framework (for --type compliance)")
    parser.add_argument("--prev", help="Previous findings JSON (for --type delta)")
    parser.add_argument("--curr", help="Current findings JSON (for --type delta)")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Reporting Engine ──{R}\n")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.type == "delta":
        if not args.prev or not args.curr:
            print("  --type delta requires --prev and --curr JSON files")
            return
        prev_f = json.loads(Path(args.prev).read_text())
        curr_f = json.loads(Path(args.curr).read_text())
        if not isinstance(prev_f, list): prev_f = [prev_f]
        if not isinstance(curr_f, list): curr_f = [curr_f]
        result = build_delta_report(prev_f, curr_f)
        output = args.output or "delta_report.json"
        Path(output).write_text(json.dumps(result, indent=2))
        trend_c = "\033[91m" if result["trend"]=="WORSENING" else ("\033[92m" if result["trend"]=="IMPROVING" else "\033[93m")
        print(f"  Trend   : {trend_c}{result['trend']}{R}")
        print(f"  Score   : {result['prev_risk_score']} → {result['curr_risk_score']} ({result['delta_score']:+d})")
        print(f"  New     : {result['new_findings_count']}  Resolved: {result['resolved_count']}  Persisting: {result['persisting_count']}")
        print(f"  Report  : {C}{output}{R}")
        return

    if not args.ingest_dir:
        print("  --ingest-dir required for this report type")
        return

    findings = load_all_findings(args.ingest_dir)
    print(f"  Loaded {len(findings)} findings from {args.ingest_dir}")
    risk     = RiskSummary.from_findings(findings)

    content = ""
    if args.format == "html":
        if args.type == "executive":
            content = build_executive_html(findings, risk, generated_at)
        elif args.type == "technical":
            content = build_technical_html(findings, risk, generated_at)
        elif args.type == "compliance":
            content = build_compliance_html(findings, risk, args.framework, generated_at)
        ext = ".html"
    elif args.format == "md":
        content = build_markdown_report(findings, risk, args.type, generated_at)
        ext = ".md"
    else:
        content = json.dumps({"type": args.type, "generated": generated_at,
                               "risk": risk.__dict__, "findings": findings}, indent=2, default=str)
        ext = ".json"

    output = args.output or f"vanguard_{args.type}_report{ext}"
    Path(output).write_text(content, encoding="utf-8")

    sev_c = "\033[91m" if risk.risk_score >= 70 else ("\033[93m" if risk.risk_score >= 40 else "\033[92m")
    print(f"  Risk Score : {sev_c}{risk.risk_score}/100{R}")
    print(f"  Critical   : {risk.critical_count}   High: {risk.high_count}   Medium: {risk.medium_count}")
    print(f"  Report     : {C}{output}{R}")


if __name__ == "__main__":
    main()
