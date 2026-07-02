#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 7 — Forensic Timeline Builder
=============================================================
Original architecture. Reconstructs a chronological event timeline
from multiple artifact sources and exports it for incident analysis.

Ingestion sources:
  - Filesystem timestamps (mtime/atime/ctime via os.stat)
  - Syslog / auth.log / application logs
  - Process execution history (/proc, psutil snapshot, shell history)
  - Network connection history (netstat snapshot, pcap summary JSON)
  - Vanguard-OOB alert JSON (from control_center.py)
  - YARA match JSON (from yara_engine.py)
  - IOC Hunter JSON (from ioc_hunter.py)
  - Custom CSV/JSON events

Output formats:
  - Terminal: color-coded chronological table
  - JSON: structured timeline with ATT&CK tags
  - HTML: standalone interactive timeline viewer
  - Markdown: for reporting

Usage:
    python3 timeline_builder.py --fs-scan /var/www --since "2025-01-01T00:00:00Z"
    python3 timeline_builder.py --logs /var/log/auth.log /var/log/syslog
    python3 timeline_builder.py --vanguard-alerts alerts.json --yara-matches matches.json
    python3 timeline_builder.py --all-sources --output timeline.html
"""

import argparse
import csv
import json
import logging
import os
import platform
import re
import stat
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

import psutil

logger = logging.getLogger("vanguard.timeline")
IS_LINUX = platform.system() == "Linux"


# ── Event model ───────────────────────────────────────────────────────────────

@dataclass
class TimelineEvent:
    ts:          datetime
    source:      str           # "filesystem" | "log" | "process" | "network" | "alert" | "yara" | "ioc"
    category:    str           # "file_create" | "file_modify" | "login" | "execution" | "network" | ...
    severity:    str           # info / low / medium / high / critical
    actor:       str           = ""      # user / process / IP
    target:      str           = ""      # file path / host / resource
    description: str           = ""
    raw:         str           = ""
    tags:        List[str]     = field(default_factory=list)
    mitre:       str           = ""
    score:       int           = 0

    def ts_str(self) -> str:
        return self.ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts_str()
        return d


# ── Severity & category maps ──────────────────────────────────────────────────

SEV_RANK = {"info":0,"low":1,"medium":2,"high":3,"critical":4}

CATEGORY_MITRE = {
    "login_success":   "T1078",
    "login_failure":   "T1110",
    "file_create":     "T1105",
    "file_modify":     "T1565",
    "file_delete":     "T1485",
    "execution":       "T1059",
    "persistence":     "T1053",
    "network_connect": "T1071",
    "privesc":         "T1548",
    "discovery":       "T1082",
    "exfil":           "T1041",
    "defense_evasion": "T1027",
    "credential":      "T1003",
    "alert":           "T1486",
}


# ── Log parsing (shared patterns from log_analyzer) ──────────────────────────

_SYSLOG_RE = re.compile(
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:\s]+)(?:\[\d+\])?:\s*(.*)"
)
_YEAR = datetime.now(timezone.utc).year

MONTH_MAP = {
    "jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,
    "jul":7,"aug":8,"sep":9,"oct":10,"nov":11,"dec":12,
}

def _parse_syslog_ts(ts_str: str) -> Optional[datetime]:
    m = re.match(r"(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})", ts_str)
    if not m:
        return None
    mo = MONTH_MAP.get(m.group(1).lower(), 1)
    return datetime(_YEAR, mo, int(m.group(2)), int(m.group(3)),
                    int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)


LOG_EVENT_PATTERNS = [
    # Auth events
    (re.compile(r"Accepted (password|publickey) for (\S+) from ([\d.]+)"),
     "login_success", "low",  lambda m: (m.group(2), m.group(3))),
    (re.compile(r"Failed password for (\S+) from ([\d.]+)"),
     "login_failure", "medium", lambda m: (m.group(1), m.group(2))),
    (re.compile(r"Invalid user (\S+) from ([\d.]+)"),
     "login_failure", "medium", lambda m: (m.group(1), m.group(2))),
    (re.compile(r"sudo:\s*(\S+)\s*:.*COMMAND=(.+)"),
     "execution",    "low",   lambda m: (m.group(1), m.group(2).strip()[:100])),
    (re.compile(r"useradd.*name=(\S+)"),
     "persistence",  "high",  lambda m: ("root", m.group(1))),
    (re.compile(r"pam_tally2.*user=(\S+).*locked"),
     "login_failure","high",  lambda m: (m.group(1), "account_locked")),
    # Cron
    (re.compile(r"CRON.*CMD\s*\((.+)\)"),
     "execution",    "info",  lambda m: ("cron", m.group(1)[:80])),
    # Systemd
    (re.compile(r"systemd.*Started (.+)"),
     "execution",    "info",  lambda m: ("systemd", m.group(1)[:80])),
]


# ── Source ingestors ──────────────────────────────────────────────────────────

class FilesystemTimelineSource:
    def __init__(self, path: str, since: Optional[datetime] = None,
                 until: Optional[datetime] = None, max_files: int = 100_000):
        self.path      = path
        self.since     = since
        self.until     = until
        self.max_files = max_files

    def events(self) -> Generator[TimelineEvent, None, None]:
        count = 0
        skip_dirs = {"/proc", "/sys", "/dev", "/run"}
        for dirpath, dirs, files in os.walk(self.path, followlinks=False):
            dirs[:] = [d for d in dirs if os.path.join(dirpath,d) not in skip_dirs]
            for fn in files:
                if count >= self.max_files:
                    return
                fpath = os.path.join(dirpath, fn)
                try:
                    st = os.stat(fpath, follow_symlinks=False)
                except OSError:
                    continue

                count += 1
                size = st.st_size

                # mtime event
                mtime_dt = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                if self._in_window(mtime_dt):
                    yield TimelineEvent(
                        ts          = mtime_dt,
                        source      = "filesystem",
                        category    = "file_modify",
                        severity    = "info",
                        target      = fpath,
                        description = f"File modified: {fpath} ({size:,} bytes)",
                        mitre       = CATEGORY_MITRE["file_modify"],
                        score       = 0,
                    )

                # ctime event (if substantially different — possible timestomping)
                if hasattr(st, "st_ctime"):
                    ctime_dt = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc)
                    delta    = abs(st.st_ctime - st.st_mtime)
                    if delta > 60 and self._in_window(ctime_dt):
                        yield TimelineEvent(
                            ts          = ctime_dt,
                            source      = "filesystem",
                            category    = "file_create",
                            severity    = "low" if delta < 3600 else "medium",
                            target      = fpath,
                            description = f"File metadata changed (Δ{delta:.0f}s vs mtime — possible timestomp)",
                            mitre       = CATEGORY_MITRE["defense_evasion"],
                            score       = 5 if delta < 3600 else 15,
                            tags        = ["timestomping"] if delta > 3600 else [],
                        )

    def _in_window(self, dt: datetime) -> bool:
        if self.since and dt < self.since:
            return False
        if self.until and dt > self.until:
            return False
        return True


class LogTimelineSource:
    def __init__(self, paths: List[str], since: Optional[datetime] = None):
        self.paths = paths
        self.since = since

    def events(self) -> Generator[TimelineEvent, None, None]:
        for path in self.paths:
            yield from self._parse_file(path)

    def _parse_file(self, path: str) -> Generator[TimelineEvent, None, None]:
        try:
            lines = Path(path).read_text(errors="replace").splitlines()
        except OSError:
            return

        for line in lines:
            m = _SYSLOG_RE.match(line)
            if not m:
                continue
            ts   = _parse_syslog_ts(m.group(1))
            host = m.group(2)
            msg  = m.group(4)

            if ts and self.since and ts < self.since:
                continue

            for pattern, category, severity, extractor in LOG_EVENT_PATTERNS:
                pm = pattern.search(msg)
                if pm:
                    try:
                        actor, target = extractor(pm)
                    except Exception:
                        actor, target = "", ""
                    yield TimelineEvent(
                        ts          = ts or datetime.now(timezone.utc),
                        source      = "log",
                        category    = category,
                        severity    = severity,
                        actor       = actor,
                        target      = target,
                        description = msg[:200],
                        raw         = line[:300],
                        mitre       = CATEGORY_MITRE.get(category,""),
                        score       = SEV_RANK.get(severity,0) * 10,
                    )
                    break


class ProcessTimelineSource:
    """Snapshot of running processes as timeline events (time = now)."""

    SUSPICIOUS_NAMES = {"nc","ncat","nmap","masscan","metasploit","msfconsole",
                        "mimikatz","lazagne","hydra","john","hashcat","socat"}

    def events(self) -> Generator[TimelineEvent, None, None]:
        now = datetime.now(timezone.utc)
        for proc in psutil.process_iter(["pid","name","exe","cmdline","create_time","username"]):
            try:
                info     = proc.info
                name     = (info.get("name") or "").lower()
                exe      = info.get("exe") or ""
                cmdline  = " ".join(info.get("cmdline") or [])
                create_t = info.get("create_time") or time.time()
                user     = info.get("username") or ""
                pid      = info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            ts = datetime.fromtimestamp(create_t, tz=timezone.utc)
            sev = "info"
            tags = []
            desc = f"Process started: {name} (pid={pid}) user={user}"

            # Suspicious checks
            if any(s in name for s in self.SUSPICIOUS_NAMES):
                sev = "high"
                tags = ["suspicious_tool"]
                desc = f"Suspicious process: {name} (pid={pid})"
            elif any(s in exe for s in ["/tmp/","/dev/shm/","/var/tmp/"]):
                sev = "critical"
                tags = ["malware_path"]
                desc = f"Process from scratch dir: {exe[:80]}"

            yield TimelineEvent(
                ts          = ts,
                source      = "process",
                category    = "execution",
                severity    = sev,
                actor       = user,
                target      = exe[:120],
                description = desc,
                tags        = tags,
                mitre       = CATEGORY_MITRE["execution"],
                score       = SEV_RANK.get(sev,0) * 10,
            )


class NetworkTimelineSource:
    """Snapshot current network connections as timeline events."""

    def events(self) -> Generator[TimelineEvent, None, None]:
        now = datetime.now(timezone.utc)
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return

        for conn in conns:
            if conn.status not in ("ESTABLISHED","LISTEN"):
                continue
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                pname = proc.name() if proc else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "unknown"

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            sev   = "info" if conn.status == "LISTEN" else "low"
            if conn.raddr and conn.raddr.port not in (80,443,53,22,25):
                sev = "medium"

            yield TimelineEvent(
                ts          = now,
                source      = "network",
                category    = "network_connect",
                severity    = sev,
                actor       = pname,
                target      = raddr or laddr,
                description = f"{conn.status} {laddr} → {raddr}  [{pname}]",
                mitre       = CATEGORY_MITRE["network_connect"],
                score       = SEV_RANK.get(sev,0)*5,
            )


class JSONAlertSource:
    """Ingest Vanguard-OOB alerts, YARA matches, or IOC findings as JSON."""

    def __init__(self, path: str, source_type: str = "alert"):
        self.path        = path
        self.source_type = source_type

    def events(self) -> Generator[TimelineEvent, None, None]:
        try:
            data = json.loads(Path(self.path).read_text())
        except Exception as e:
            logger.error("Cannot load %s: %s", self.path, e)
            return

        if not isinstance(data, list):
            data = data.get("vms", data.get("findings", [data]))

        for item in data:
            ts = self._parse_ts(item)
            if self.source_type == "alert":
                yield from self._from_alert(item, ts)
            elif self.source_type == "yara":
                yield from self._from_yara(item, ts)
            elif self.source_type == "ioc":
                yield from self._from_ioc(item, ts)

    def _parse_ts(self, item: dict) -> datetime:
        for key in ["timestamp","ts","time","@timestamp","first_seen"]:
            val = item.get(key)
            if val:
                try:
                    return datetime.fromisoformat(str(val).replace("Z","+00:00"))
                except Exception:
                    pass
        return datetime.now(timezone.utc)

    def _from_alert(self, item: dict, ts: datetime):
        event_type = item.get("event_type","alert")
        sev        = item.get("severity","medium")
        details    = item.get("details",{})
        vm_id      = item.get("vm_id","")
        yield TimelineEvent(
            ts          = ts,
            source      = "alert",
            category    = "alert",
            severity    = sev,
            actor       = vm_id,
            target      = details.get("path","") or details.get("exe",""),
            description = f"[{event_type.upper()}] {json.dumps(details)[:150]}",
            score       = item.get("score_delta",0),
            tags        = [event_type],
            mitre       = CATEGORY_MITRE.get("alert",""),
        )

    def _from_yara(self, item: dict, ts: datetime):
        sev = item.get("meta",{}).get("severity","medium")
        yield TimelineEvent(
            ts          = ts,
            source      = "yara",
            category    = "defense_evasion",
            severity    = sev,
            target      = item.get("file_path",""),
            description = f"YARA: {item.get('rule_name','')} — {item.get('meta',{}).get('desc','')}",
            score       = SEV_RANK.get(sev,0)*15,
            tags        = item.get("tags",[]),
            mitre       = item.get("meta",{}).get("mitre",""),
        )

    def _from_ioc(self, item: dict, ts: datetime):
        sev = item.get("severity","medium")
        yield TimelineEvent(
            ts          = ts,
            source      = "ioc",
            category    = item.get("hunt_type","alert"),
            severity    = sev,
            target      = item.get("path",""),
            description = item.get("description",""),
            score       = SEV_RANK.get(sev,0)*15,
            tags        = ["ioc"],
        )


# ── Timeline assembler ────────────────────────────────────────────────────────

class Timeline:
    def __init__(self):
        self.events: List[TimelineEvent] = []

    def add_source(self, source):
        before = len(self.events)
        for ev in source.events():
            self.events.append(ev)
        added = len(self.events) - before
        logger.info("Added %d events from %s", added, type(source).__name__)

    def sort(self):
        self.events.sort(key=lambda e: e.ts)

    def filter(self, since: Optional[datetime] = None,
               until: Optional[datetime] = None,
               min_severity: str = "info") -> List[TimelineEvent]:
        min_rank = SEV_RANK.get(min_severity, 0)
        out = []
        for ev in self.events:
            if since and ev.ts < since:
                continue
            if until and ev.ts > until:
                continue
            if SEV_RANK.get(ev.severity, 0) < min_rank:
                continue
            out.append(ev)
        return out

    def summary(self) -> dict:
        from collections import Counter
        sev = Counter(e.severity for e in self.events)
        cat = Counter(e.category for e in self.events)
        src = Counter(e.source   for e in self.events)
        span = ""
        if self.events:
            first = min(e.ts for e in self.events)
            last  = max(e.ts for e in self.events)
            span  = f"{first.strftime('%Y-%m-%dT%H:%M:%SZ')} → {last.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        return {
            "total_events":  len(self.events),
            "timespan":      span,
            "by_severity":   dict(sev),
            "by_category":   dict(cat.most_common(10)),
            "by_source":     dict(src),
            "total_score":   sum(e.score for e in self.events),
        }

    def to_json(self, path: str, events: List[TimelineEvent] = None):
        ev_list = events or self.events
        with open(path, "w") as f:
            json.dump([e.to_dict() for e in ev_list], f, indent=2)

    def to_html(self, path: str, events: List[TimelineEvent] = None):
        ev_list = events or self.events
        rows    = ""
        SEV_BADGE = {
            "critical": "#c026d3", "high": "#ef4444",
            "medium": "#f59e0b",   "low": "#22c55e", "info": "#6b7280",
        }
        for ev in ev_list:
            badge_color = SEV_BADGE.get(ev.severity, "#6b7280")
            tags_html   = " ".join(f'<span style="background:#1e3a5f;color:#7dd3fc;padding:1px 6px;border-radius:3px;font-size:10px">{t}</span>' for t in ev.tags)
            rows += f"""
            <tr>
              <td style="white-space:nowrap;color:#94a3b8">{ev.ts_str()}</td>
              <td><span style="background:{badge_color}22;color:{badge_color};padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold">{ev.severity.upper()}</span></td>
              <td style="color:#7dd3fc">{ev.source}</td>
              <td style="color:#a78bfa">{ev.category}</td>
              <td style="color:#f1f5f9">{ev.description[:120]}</td>
              <td style="color:#94a3b8">{ev.actor[:40]}</td>
              <td style="color:#cbd5e1;font-size:11px">{ev.mitre}</td>
              <td>{tags_html}</td>
            </tr>"""

        html = f"""<!DOCTYPE html><html><head>
        <meta charset="UTF-8"><title>Vanguard-OOB Forensic Timeline</title>
        <style>
          body{{background:#0a0e1a;color:#e2e8f0;font-family:'Segoe UI',sans-serif;margin:0;padding:20px}}
          h1{{color:#38bdf8;font-size:1.4rem;letter-spacing:.1em;margin-bottom:4px}}
          .sub{{color:#475569;font-size:.8rem;margin-bottom:24px}}
          table{{width:100%;border-collapse:collapse;font-size:12px}}
          th{{background:#0f172a;color:#64748b;padding:8px 12px;text-align:left;border-bottom:1px solid #1e293b;letter-spacing:.05em;font-size:10px;text-transform:uppercase}}
          td{{padding:6px 12px;border-bottom:1px solid #0f172a;vertical-align:top;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
          tr:hover td{{background:#0f1f35}}
          input{{background:#0f172a;border:1px solid #1e293b;color:#e2e8f0;padding:6px 12px;border-radius:4px;margin-bottom:16px;width:300px}}
        </style></head><body>
        <h1>⬡ VANGUARD-OOB · FORENSIC TIMELINE</h1>
        <div class="sub">Generated {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} · {len(ev_list)} events</div>
        <input type="text" id="filter" placeholder="Filter events..." onkeyup="filterTable()">
        <table id="tbl">
          <thead><tr>
            <th>Timestamp</th><th>Severity</th><th>Source</th>
            <th>Category</th><th>Description</th><th>Actor</th>
            <th>MITRE</th><th>Tags</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
        <script>
        function filterTable(){{
          var f=document.getElementById('filter').value.toLowerCase();
          document.querySelectorAll('#tbl tbody tr').forEach(r=>{{
            r.style.display=r.textContent.toLowerCase().includes(f)?'':'none';
          }});
        }}
        </script></body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def to_markdown(self, path: str, events: List[TimelineEvent] = None):
        ev_list = events or self.events
        lines = ["# Vanguard-OOB Forensic Timeline\n",
                 f"Generated: {datetime.now(timezone.utc).isoformat()}\n",
                 f"Total events: {len(ev_list)}\n\n",
                 "| Timestamp | Severity | Source | Category | Description | Actor | MITRE |",
                 "|-----------|----------|--------|----------|-------------|-------|-------|"]
        for ev in ev_list:
            desc = ev.description[:80].replace("|","\\|")
            lines.append(f"| {ev.ts_str()} | **{ev.severity}** | {ev.source} | "
                         f"{ev.category} | {desc} | {ev.actor[:20]} | {ev.mitre} |")
        with open(path, "w") as f:
            f.write("\n".join(lines))


# ── CLI ───────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m",
         "low":"\033[92m","info":"\033[2m"}

def _print_events(events: List[TimelineEvent], limit: int = 200):
    R = "\033[0m"
    print(f"\n  {'TIMESTAMP':<22} {'SEV':8} {'SOURCE':12} {'CATEGORY':16} DESCRIPTION")
    print(f"  {'─'*90}")
    for ev in events[:limit]:
        c = SEV_C.get(ev.severity,"")
        ts = ev.ts_str()
        desc = ev.description[:55]
        print(f"  {ts:<22} {c}{ev.severity[:8]:<8}{R} {ev.source[:12]:<12} "
              f"{ev.category[:16]:<16} {desc}")
    if len(events) > limit:
        print(f"\n  ... {len(events)-limit} more events (use --output to see all)")


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Timeline Builder")
    parser.add_argument("--fs-scan",         help="Filesystem path to collect timestamps from")
    parser.add_argument("--logs",            nargs="+", help="Log files to parse")
    parser.add_argument("--processes",       action="store_true", help="Snapshot running processes")
    parser.add_argument("--network",         action="store_true", help="Snapshot network connections")
    parser.add_argument("--vanguard-alerts", help="Vanguard alert JSON file")
    parser.add_argument("--yara-matches",    help="YARA match JSON file")
    parser.add_argument("--ioc-findings",    help="IOC Hunter JSON file")
    parser.add_argument("--all-sources",     action="store_true", help="Enable all local sources")
    parser.add_argument("--since",           help="ISO8601 start time filter")
    parser.add_argument("--until",           help="ISO8601 end time filter")
    parser.add_argument("--min-severity",    default="info",
                        choices=["info","low","medium","high","critical"])
    parser.add_argument("--output",          help="Output file (.json/.html/.md)")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Timeline Builder ──{R}\n")

    since = datetime.fromisoformat(args.since.replace("Z","+00:00")) if args.since else None
    until = datetime.fromisoformat(args.until.replace("Z","+00:00")) if args.until else None

    tl = Timeline()

    if args.fs_scan or args.all_sources:
        tl.add_source(FilesystemTimelineSource(args.fs_scan or "/", since=since))

    if args.logs:
        tl.add_source(LogTimelineSource(args.logs, since=since))

    if args.processes or args.all_sources:
        tl.add_source(ProcessTimelineSource())

    if args.network or args.all_sources:
        tl.add_source(NetworkTimelineSource())

    if args.vanguard_alerts:
        tl.add_source(JSONAlertSource(args.vanguard_alerts, "alert"))

    if args.yara_matches:
        tl.add_source(JSONAlertSource(args.yara_matches, "yara"))

    if args.ioc_findings:
        tl.add_source(JSONAlertSource(args.ioc_findings, "ioc"))

    tl.sort()
    filtered = tl.filter(since=since, until=until, min_severity=args.min_severity)
    _print_events(filtered)

    s = tl.summary()
    print(f"\n  {B}Summary:{R}")
    print(f"    Total : {s['total_events']}  |  Filtered: {len(filtered)}")
    print(f"    Score : {s['total_score']}")
    print(f"    Span  : {s['timespan']}")
    print(f"    Sev   : {s['by_severity']}")

    if args.output:
        out_path = args.output
        ext = Path(out_path).suffix.lower()
        if ext == ".json":
            tl.to_json(out_path, filtered)
        elif ext == ".html":
            tl.to_html(out_path, filtered)
        elif ext in (".md",".markdown"):
            tl.to_markdown(out_path, filtered)
        else:
            tl.to_json(out_path, filtered)
        print(f"\n  Timeline saved to {C}{out_path}{R}")


if __name__ == "__main__":
    main()
