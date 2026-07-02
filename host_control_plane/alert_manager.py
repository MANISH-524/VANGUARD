#!/usr/bin/env python3
"""
Vanguard-OOB :: SOC Alert Manager
===================================
The workflow layer a real SOC actually lives in. Detection is only half the job;
the other half is *triage* — a queue of alerts an analyst works: acknowledge,
assign, escalate, close, or mark false-positive, with notes and an audit trail.

This is what separates "a tool that detects things" from "a SOC platform".

It also computes the operational metrics a SOC lead reports:
  - alert volume over time (for the trend chart)
  - open / acknowledged / escalated / closed / false-positive counts
  - false-positive RATE (closed-as-FP ÷ total dispositioned)
  - mean detection latency (event time → alert raised)

Thread-safe. No external dependencies.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


# Only raise an alert for events that actually matter to an analyst.
ALERT_MIN_DELTA = 15


@dataclass
class Alert:
    alert_id: str
    vm_id: str
    title: str
    severity: str                       # low|medium|high|critical
    event_type: str
    techniques: List[dict]              # [{"id":"T1486","name":...}]
    created_at: str
    created_ts: float
    detection_latency_ms: Optional[float] = None
    status: AlertStatus = AlertStatus.OPEN
    assignee: Optional[str] = None
    notes: List[dict] = field(default_factory=list)
    history: List[dict] = field(default_factory=list)

    def log(self, action: str, by: str = "system", extra: str = ""):
        self.history.append({"timestamp": _now_iso(), "action": action,
                             "by": by, "extra": extra})

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "vm_id": self.vm_id,
            "title": self.title,
            "severity": self.severity,
            "event_type": self.event_type,
            "techniques": self.techniques,
            "created_at": self.created_at,
            "detection_latency_ms": (round(self.detection_latency_ms, 1)
                                     if self.detection_latency_ms is not None else None),
            "status": self.status.value,
            "assignee": self.assignee,
            "notes": self.notes[-10:],
            "history": self.history[-10:],
        }


class AlertManager:
    def __init__(self, dedupe_window_s: float = 30.0):
        self._lock = threading.RLock()
        self._alerts: Dict[str, Alert] = {}
        self._seq = 0
        self._dedupe: Dict[str, float] = {}        # (vm|event_type) -> last_ts
        self._dedupe_window = dedupe_window_s
        self._volume: deque = deque(maxlen=4096)   # alert creation timestamps
        self._latencies: List[float] = []

    # ---- creation --------------------------------------------------------

    def raise_alert(self, vm_id: str, event_type: str, severity: str,
                    delta: int, details: dict, event_ts_iso: Optional[str] = None) -> Optional[Alert]:
        if delta < ALERT_MIN_DELTA:
            return None
        with self._lock:
            # Dedupe: collapse repeats of the same vm+event_type within the window.
            key = f"{vm_id}|{event_type}"
            now = time.time()
            last = self._dedupe.get(key, 0)
            if now - last < self._dedupe_window:
                return None
            self._dedupe[key] = now

            self._seq += 1
            aid = f"ALRT-{self._seq:05d}"
            techs = details.get("attack", [])
            title = self._title_for(event_type, details)

            latency = None
            if event_ts_iso:
                try:
                    ev_ts = datetime.fromisoformat(event_ts_iso.replace("Z", "+00:00")).timestamp()
                    latency = max(0.0, (now - ev_ts) * 1000.0)
                    self._latencies.append(latency)
                except Exception:
                    pass

            alert = Alert(
                alert_id=aid, vm_id=vm_id, title=title, severity=severity,
                event_type=event_type, techniques=techs,
                created_at=_now_iso(), created_ts=now, detection_latency_ms=latency,
            )
            alert.log("raised", "system", f"score +{delta}")
            self._alerts[aid] = alert
            self._volume.append(now)
            return alert

    @staticmethod
    def _title_for(event_type: str, details: dict) -> str:
        reason = details.get("reason", "")
        mapping = {
            "crypto_spike": "Ransomware cryptographic spike",
            "entropy": "High-entropy file encryption",
            "shadow": "Backup / shadow-copy destruction",
            "velocity": "File-modification velocity spike",
            "network": "Suspicious outbound connection (possible C2)",
            "agent_silence": "Security agent silenced (possible tamper)",
        }
        if event_type == "process":
            if reason == "web_server_spawned_shell":
                return "Web server spawned a shell (web shell / RCE)"
            return "Execution from suspicious path"
        return mapping.get(event_type, f"{event_type} event")

    # ---- analyst actions -------------------------------------------------

    def _get(self, alert_id: str) -> Optional[Alert]:
        return self._alerts.get(alert_id)

    def acknowledge(self, alert_id: str, by: str = "analyst") -> dict:
        with self._lock:
            a = self._get(alert_id)
            if not a:
                return {"ok": False, "message": "alert not found"}
            a.status = AlertStatus.ACKNOWLEDGED
            a.log("acknowledged", by)
            return {"ok": True, "message": f"{alert_id} acknowledged"}

    def assign(self, alert_id: str, assignee: str, by: str = "analyst") -> dict:
        with self._lock:
            a = self._get(alert_id)
            if not a:
                return {"ok": False, "message": "alert not found"}
            a.assignee = assignee
            if a.status == AlertStatus.OPEN:
                a.status = AlertStatus.ACKNOWLEDGED
            a.log("assigned", by, assignee)
            return {"ok": True, "message": f"{alert_id} assigned to {assignee}"}

    def escalate(self, alert_id: str, by: str = "analyst") -> dict:
        with self._lock:
            a = self._get(alert_id)
            if not a:
                return {"ok": False, "message": "alert not found"}
            a.status = AlertStatus.ESCALATED
            a.log("escalated", by)
            return {"ok": True, "message": f"{alert_id} escalated to tier-2 / IR"}

    def close(self, alert_id: str, by: str = "analyst", note: str = "") -> dict:
        with self._lock:
            a = self._get(alert_id)
            if not a:
                return {"ok": False, "message": "alert not found"}
            a.status = AlertStatus.CLOSED
            if note:
                a.notes.append({"timestamp": _now_iso(), "by": by, "text": note})
            a.log("closed", by, note)
            return {"ok": True, "message": f"{alert_id} closed"}

    def mark_false_positive(self, alert_id: str, by: str = "analyst", note: str = "") -> dict:
        with self._lock:
            a = self._get(alert_id)
            if not a:
                return {"ok": False, "message": "alert not found"}
            a.status = AlertStatus.FALSE_POSITIVE
            if note:
                a.notes.append({"timestamp": _now_iso(), "by": by, "text": note})
            a.log("false_positive", by, note)
            return {"ok": True, "message": f"{alert_id} marked false-positive"}

    def add_note(self, alert_id: str, text: str, by: str = "analyst") -> dict:
        with self._lock:
            a = self._get(alert_id)
            if not a:
                return {"ok": False, "message": "alert not found"}
            a.notes.append({"timestamp": _now_iso(), "by": by, "text": text})
            a.log("note", by, text[:60])
            return {"ok": True, "message": "note added"}

    # ---- queries / metrics ----------------------------------------------

    def get_alerts(self, limit: int = 100) -> List[dict]:
        with self._lock:
            ordered = sorted(self._alerts.values(), key=lambda a: a.created_ts, reverse=True)
            return [a.to_dict() for a in ordered[:limit]]

    def metrics(self) -> dict:
        with self._lock:
            by_status: Dict[str, int] = {s.value: 0 for s in AlertStatus}
            for a in self._alerts.values():
                by_status[a.status.value] += 1
            total = len(self._alerts)
            dispositioned = (by_status["CLOSED"] + by_status["FALSE_POSITIVE"])
            fp_rate = (100.0 * by_status["FALSE_POSITIVE"] / dispositioned) if dispositioned else 0.0
            mean_latency = (sum(self._latencies) / len(self._latencies)) if self._latencies else 0.0
            return {
                "total": total,
                "by_status": by_status,
                "open": by_status["OPEN"] + by_status["ACKNOWLEDGED"] + by_status["ESCALATED"],
                "false_positive_rate": round(fp_rate, 1),
                "mean_detection_latency_ms": round(mean_latency, 1),
                "volume_series": self._volume_series(),
            }

    def _volume_series(self, buckets: int = 12, bucket_s: float = 10.0) -> List[dict]:
        """Alerts per recent time bucket, for the trend chart."""
        now = time.time()
        series = []
        for i in range(buckets - 1, -1, -1):
            hi = now - i * bucket_s
            lo = hi - bucket_s
            count = sum(1 for ts in self._volume if lo <= ts < hi)
            series.append({"t": int(hi), "count": count})
        return series


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    m = AlertManager(dedupe_window_s=0)
    a1 = m.raise_alert("vm-1", "crypto_spike", "critical", 50,
                       {"attack": [{"id": "T1486", "name": "Data Encrypted for Impact"}]},
                       event_ts_iso=_now_iso())
    a2 = m.raise_alert("vm-1", "network", "medium", 15,
                       {"attack": [{"id": "T1571", "name": "Non-Standard Port"}]})
    print("raised:", a1.alert_id, a1.title, "|", a2.alert_id, a2.title)
    print("ack:", m.acknowledge(a1.alert_id, "alice")["message"])
    print("assign:", m.assign(a1.alert_id, "bob")["message"])
    print("escalate:", m.escalate(a1.alert_id)["message"])
    print("FP:", m.mark_false_positive(a2.alert_id, "alice", "known scanner")["message"])
    met = m.metrics()
    print("metrics:", {k: met[k] for k in ("total", "open", "false_positive_rate")})
    print("by_status:", met["by_status"])
    assert met["total"] == 2 and met["by_status"]["ESCALATED"] == 1
    assert met["by_status"]["FALSE_POSITIVE"] == 1 and met["false_positive_rate"] == 100.0
    print("[OK] alert manager self-test passed")
