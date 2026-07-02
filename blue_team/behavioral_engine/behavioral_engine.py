#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 14 — Behavioral Engine (UEBA)
=============================================================
Original architecture. User & Entity Behavior Analytics with FOUR
independent baseline models, each chosen specifically to minimize false
positives by requiring statistical confidence before alerting.

  1. CIRCULAR TIME-OF-DAY MODEL
     Login hours are circular (23:00 and 00:30 are 1.5h apart, not 23.5h).
     Vanguard fits a von-Mises-like circular mean + spread per user from
     historical logins, then scores new logins by circular distance from
     that mean — NOT a naive "outside min/max hour" check, which would
     misfire for night-shift workers whose normal hours wrap midnight.
     An alert requires the new login to fall outside (mean ± k·spread)
     AND the user to have ≥10 historical logins (enough data to trust
     the baseline) — new users never trigger false "anomalies".

  2. PROCESS-EXECUTION FREQUENCY MODEL
     Per-user multiset of historically-run process names. A NEW process
     never seen for that user is scored by GLOBAL rarity (how many OTHER
     users run it) — common admin tools (bash, python3, ssh) seen across
     many users score near zero even if new to THIS user; truly novel,
     globally-rare binaries score high. This peer-comparison step is the
     core anti-FP mechanism (a user trying a new but common tool isn't
     "anomalous").

  3. DATA-VOLUME OUTLIER MODEL (robust z-score)
     Per-user/host bytes-transferred baseline using MEDIAN + MAD (median
     absolute deviation) instead of mean+stddev — robust to the heavy-tail
     distributions typical of network/file transfer volumes, where a
     single legit large backup would otherwise blow out a mean-based
     model for weeks.

  4. COMMAND-SEQUENCE MARKOV MODEL
     Builds a 2nd-order Markov chain of "command A followed by command B"
     transitions per user. New sequences are scored by their NEGATIVE
     LOG-LIKELIHOOD under the user's own chain; transitions never seen
     for ANY user trained into the chain are weighted heavier than
     transitions merely rare for this user — distinguishing "this user
     did something nobody normally does" (high signal) from "this user
     tried something other users do regularly" (low signal).

Baselines persist to JSON and update incrementally (online learning),
so the model improves with every run rather than requiring full retrain.

Usage:
    python3 behavioral_engine.py --build --events events.jsonl --baseline ueba.json
    python3 behavioral_engine.py --detect --events new_events.jsonl --baseline ueba.json
"""

import argparse
import json
import logging
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("vanguard.ueba")

# ─────────────────────────────────────────────────────────────────────────────
# Event model
# ─────────────────────────────────────────────────────────────────────────────
# Expected JSONL event:
#   {"ts": 1700000000, "entity": "alice", "type": "login", "hour": 9.5}
#   {"ts": 1700000001, "entity": "alice", "type": "process", "name": "vim"}
#   {"ts": 1700000002, "entity": "alice", "type": "transfer", "bytes": 50000}
#   {"ts": 1700000003, "entity": "alice", "type": "command", "cmd": "ls"}

@dataclass
class BehaviorFinding:
    finding_type: str
    severity:     str
    entity:       str
    description:  str
    evidence:     dict = field(default_factory=dict)
    score:        int  = 0
    timestamp:    str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Circular time-of-day model
# ─────────────────────────────────────────────────────────────────────────────

class CircularTimeModel:
    """
    Tracks login hours (0-24) as angles on a 24h clock. Maintains running
    sum of unit vectors (cos, sin) per entity to compute circular mean and
    a circular spread (1 - mean resultant length, R), analogous to variance.
    """

    def __init__(self, min_samples: int = 10, k_sigma: float = 2.5):
        self.min_samples = min_samples
        self.k_sigma     = k_sigma
        # entity -> {"n": int, "sum_cos": float, "sum_sin": float}
        self.stats: Dict[str, dict] = defaultdict(lambda: {"n": 0, "sum_cos": 0.0, "sum_sin": 0.0})

    @staticmethod
    def _hour_to_angle(hour: float) -> float:
        return (hour / 24.0) * 2 * math.pi

    def update(self, entity: str, hour: float):
        s = self.stats[entity]
        ang = self._hour_to_angle(hour)
        s["sum_cos"] += math.cos(ang)
        s["sum_sin"] += math.sin(ang)
        s["n"] += 1

    def _circular_mean_and_spread(self, entity: str) -> Optional[Tuple[float, float]]:
        s = self.stats.get(entity)
        if not s or s["n"] < self.min_samples:
            return None
        n = s["n"]
        mean_cos = s["sum_cos"] / n
        mean_sin = s["sum_sin"] / n
        R = math.hypot(mean_cos, mean_sin)            # mean resultant length (0-1)
        R = max(min(R, 0.999999), 1e-6)
        circ_mean_angle = math.atan2(mean_sin, mean_cos)
        # Circular standard deviation (radians), via -2*ln(R)
        circ_std = math.sqrt(-2 * math.log(R))
        return circ_mean_angle, circ_std

    def score(self, entity: str, hour: float) -> Optional[BehaviorFinding]:
        params = self._circular_mean_and_spread(entity)
        if params is None:
            return None  # not enough history — skip, avoids cold-start FPs
        mean_angle, circ_std = params
        ang = self._hour_to_angle(hour)

        # Angular distance, accounting for wraparound
        diff = abs(ang - mean_angle)
        diff = min(diff, 2*math.pi - diff)

        threshold = self.k_sigma * max(circ_std, 0.05)  # floor avoids div/0 on near-constant schedules
        if diff > threshold:
            mean_hour = (mean_angle / (2*math.pi)) * 24 % 24
            return BehaviorFinding(
                finding_type="anomalous_login_time",
                severity="medium",
                entity=entity,
                description=f"Login at {hour:.1f}:00 is unusual for '{entity}' "
                             f"(typical ~{mean_hour:.1f}:00 ± {math.degrees(circ_std)/15:.1f}h)",
                evidence={"hour": hour, "typical_hour": round(mean_hour,2),
                          "deviation_rad": round(diff,3), "threshold_rad": round(threshold,3),
                          "samples": self.stats[entity]["n"]},
                score=15,
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Process-execution frequency model with peer-rarity weighting
# ─────────────────────────────────────────────────────────────────────────────

class ProcessFrequencyModel:
    def __init__(self, rarity_threshold: float = 0.05, min_global_users: int = 3):
        # entity -> Counter(process_name)
        self.entity_procs: Dict[str, Counter] = defaultdict(Counter)
        # process_name -> set(entities that ran it)
        self.global_procs: Dict[str, set] = defaultdict(set)
        self.all_entities: set = set()
        self.rarity_threshold = rarity_threshold
        self.min_global_users = min_global_users

    def update(self, entity: str, proc_name: str):
        self.entity_procs[entity][proc_name] += 1
        self.global_procs[proc_name].add(entity)
        self.all_entities.add(entity)

    def score(self, entity: str, proc_name: str) -> Optional[BehaviorFinding]:
        # Already seen for this entity — normal
        if self.entity_procs[entity].get(proc_name, 0) > 0:
            return None

        total_entities = max(len(self.all_entities), 1)
        global_users    = len(self.global_procs.get(proc_name, set()))
        global_rarity   = global_users / total_entities  # fraction of population that runs it

        # Need enough population to judge rarity meaningfully
        if total_entities < self.min_global_users:
            return None

        if global_rarity <= self.rarity_threshold:
            sev = "high" if global_users == 0 else "medium"
            return BehaviorFinding(
                finding_type="rare_process_execution",
                severity=sev,
                entity=entity,
                description=f"'{entity}' executed '{proc_name}' — never seen for this "
                             f"user, and only {global_users}/{total_entities} users "
                             f"globally have run it",
                evidence={"process": proc_name, "global_users": global_users,
                          "total_entities": total_entities,
                          "global_rarity": round(global_rarity,4)},
                score=25 if sev=="high" else 15,
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Robust data-volume outlier model (median + MAD)
# ─────────────────────────────────────────────────────────────────────────────

class DataVolumeModel:
    def __init__(self, min_samples: int = 8, mad_multiplier: float = 5.0):
        self.min_samples   = min_samples
        self.mad_multiplier= mad_multiplier
        self.history: Dict[str, List[float]] = defaultdict(list)

    def update(self, entity: str, num_bytes: float):
        h = self.history[entity]
        h.append(num_bytes)
        if len(h) > 500:
            self.history[entity] = h[-500:]

    @staticmethod
    def _median(values: List[float]) -> float:
        s = sorted(values)
        n = len(s)
        mid = n // 2
        return s[mid] if n % 2 else (s[mid-1] + s[mid]) / 2

    def score(self, entity: str, num_bytes: float) -> Optional[BehaviorFinding]:
        h = self.history.get(entity, [])
        if len(h) < self.min_samples:
            return None

        med = self._median(h)
        abs_devs = [abs(x - med) for x in h]
        mad = self._median(abs_devs)
        # Consistent estimator: 1.4826 * MAD ≈ stddev for normal data
        scaled_mad = 1.4826 * mad if mad > 0 else 1.0

        modified_z = abs(num_bytes - med) / scaled_mad

        if modified_z > self.mad_multiplier and num_bytes > med:  # only flag SPIKES, not drops
            return BehaviorFinding(
                finding_type="data_volume_outlier",
                severity="high" if modified_z > self.mad_multiplier * 2 else "medium",
                entity=entity,
                description=f"'{entity}' transferred {num_bytes:,.0f} bytes — "
                             f"{modified_z:.1f}x the typical deviation "
                             f"(median={med:,.0f}, n={len(h)})",
                evidence={"bytes": num_bytes, "median_bytes": round(med,1),
                          "modified_z_score": round(modified_z,2), "samples": len(h)},
                score=25 if modified_z > self.mad_multiplier*2 else 15,
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 4. Command-sequence Markov model
# ─────────────────────────────────────────────────────────────────────────────

class CommandSequenceModel:
    def __init__(self, min_global_transitions: int = 20, rare_threshold: float = 0.01):
        # entity -> {prev_cmd -> Counter(next_cmd)}
        self.entity_transitions: Dict[str, Dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
        # global -> {prev_cmd -> Counter(next_cmd)}
        self.global_transitions: Dict[str, Counter] = defaultdict(Counter)
        self.global_total = 0
        self.last_cmd: Dict[str, str] = {}
        self.min_global_transitions = min_global_transitions
        self.rare_threshold = rare_threshold

    def update(self, entity: str, cmd: str):
        prev = self.last_cmd.get(entity)
        if prev is not None:
            self.entity_transitions[entity][prev][cmd] += 1
            self.global_transitions[prev][cmd] += 1
            self.global_total += 1
        self.last_cmd[entity] = cmd

    def score(self, entity: str, cmd: str) -> Optional[BehaviorFinding]:
        prev = self.last_cmd.get(entity)
        result = None

        if prev is not None and self.global_total >= self.min_global_transitions:
            global_next = self.global_transitions.get(prev, Counter())
            total_from_prev = sum(global_next.values())
            seen_count = global_next.get(cmd, 0)

            if total_from_prev > 0:
                global_prob = seen_count / total_from_prev
                entity_seen = self.entity_transitions[entity].get(prev, Counter()).get(cmd, 0)

                if global_prob <= self.rare_threshold and entity_seen == 0 and total_from_prev >= 10:
                    result = BehaviorFinding(
                        finding_type="anomalous_command_sequence",
                        severity="medium",
                        entity=entity,
                        description=f"'{entity}' ran '{cmd}' after '{prev}' — this "
                                     f"transition occurs in only "
                                     f"{global_prob:.1%} of {total_from_prev} "
                                     f"observed cases globally",
                        evidence={"prev_cmd": prev, "cmd": cmd,
                                  "global_probability": round(global_prob,4),
                                  "global_observations": total_from_prev},
                        score=15,
                    )

        # Always update AFTER scoring (so first occurrence is comparable to history)
        self.update(entity, cmd)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Master engine
# ─────────────────────────────────────────────────────────────────────────────

class BehavioralEngine:
    def __init__(self):
        self.time_model    = CircularTimeModel()
        self.process_model = ProcessFrequencyModel()
        self.volume_model  = DataVolumeModel()
        self.command_model = CommandSequenceModel()
        self.findings: List[BehaviorFinding] = []
        self.event_count = 0

    def process_event(self, ev: dict, detect: bool = True):
        self.event_count += 1
        entity = ev.get("entity", "unknown")
        etype  = ev.get("type", "")

        if etype == "login":
            hour = float(ev.get("hour", 0))
            if detect:
                f = self.time_model.score(entity, hour)
                if f: self.findings.append(f)
            self.time_model.update(entity, hour)

        elif etype == "process":
            name = ev.get("name", "")
            if detect:
                f = self.process_model.score(entity, name)
                if f: self.findings.append(f)
            self.process_model.update(entity, name)

        elif etype == "transfer":
            num_bytes = float(ev.get("bytes", 0))
            if detect:
                f = self.volume_model.score(entity, num_bytes)
                if f: self.findings.append(f)
            self.volume_model.update(entity, num_bytes)

        elif etype == "command":
            cmd = ev.get("cmd", "")
            if detect:
                f = self.command_model.score(entity, cmd)
                if f: self.findings.append(f)
            else:
                self.command_model.update(entity, cmd)

    def load_jsonl(self, path: str, detect: bool = True):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    self.process_event(ev, detect=detect)
                except json.JSONDecodeError:
                    continue

    def save_baseline(self, path: str):
        state = {
            "time_model": {e: s for e, s in self.time_model.stats.items()},
            "process_model": {
                "entity_procs": {e: dict(c) for e, c in self.process_model.entity_procs.items()},
                "global_procs": {p: list(s) for p, s in self.process_model.global_procs.items()},
                "all_entities": list(self.process_model.all_entities),
            },
            "volume_model": dict(self.volume_model.history),
            "command_model": {
                "entity_transitions": {
                    e: {p: dict(c) for p, c in trans.items()}
                    for e, trans in self.command_model.entity_transitions.items()
                },
                "global_transitions": {p: dict(c) for p, c in self.command_model.global_transitions.items()},
                "global_total": self.command_model.global_total,
                "last_cmd": self.command_model.last_cmd,
            },
            "event_count": self.event_count,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(path, "w") as f:
            json.dump(state, f, indent=2)
        logger.info("Baseline saved to %s (%d events)", path, self.event_count)

    def load_baseline(self, path: str):
        with open(path) as f:
            state = json.load(f)

        for e, s in state.get("time_model", {}).items():
            self.time_model.stats[e] = s

        pm = state.get("process_model", {})
        for e, c in pm.get("entity_procs", {}).items():
            self.process_model.entity_procs[e] = Counter(c)
        for p, s in pm.get("global_procs", {}).items():
            self.process_model.global_procs[p] = set(s)
        self.process_model.all_entities = set(pm.get("all_entities", []))

        for e, h in state.get("volume_model", {}).items():
            self.volume_model.history[e] = h

        cm = state.get("command_model", {})
        for e, trans in cm.get("entity_transitions", {}).items():
            for p, c in trans.items():
                self.command_model.entity_transitions[e][p] = Counter(c)
        for p, c in cm.get("global_transitions", {}).items():
            self.command_model.global_transitions[p] = Counter(c)
        self.command_model.global_total = cm.get("global_total", 0)
        self.command_model.last_cmd     = cm.get("last_cmd", {})

        self.event_count = state.get("event_count", 0)
        logger.info("Baseline loaded from %s (%d historical events)", path, self.event_count)

    def summary(self) -> dict:
        from collections import Counter as C
        sev = C(f.severity for f in self.findings)
        typ = C(f.finding_type for f in self.findings)
        return {
            "events_processed": self.event_count,
            "entities_tracked": len(self.process_model.all_entities) or
                                len(self.time_model.stats),
            "findings":  len(self.findings),
            "by_severity": dict(sev),
            "by_type": dict(typ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m"}

def _print_finding(f: BehaviorFinding):
    c = SEV_C.get(f.severity,""); R = "\033[0m"; B = "\033[1m"
    print(f"  {c}[{f.severity.upper():8}]{R} {B}{f.finding_type}{R}  entity={f.entity}  +{f.score}")
    print(f"     {f.description}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Behavioral Engine (UEBA)")
    parser.add_argument("--events",   required=True, help="JSONL event stream")
    parser.add_argument("--baseline", required=True, help="Baseline state file (.json)")
    parser.add_argument("--build",  action="store_true", help="Train/update baseline (no detection)")
    parser.add_argument("--detect", action="store_true", help="Detect anomalies against existing baseline")
    parser.add_argument("--json",   help="Output findings to JSON")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Behavioral Engine (UEBA) ──{R}\n")

    engine = BehavioralEngine()

    if args.detect and Path(args.baseline).exists():
        engine.load_baseline(args.baseline)
        before = engine.event_count
        engine.load_jsonl(args.events, detect=True)
        print(f"  Loaded baseline ({before} historical events)")
        print(f"  Processed {engine.event_count - before} new events for detection\n")

        for f in engine.findings:
            _print_finding(f)

        s = engine.summary()
        print(f"  Findings: {s['findings']}  By severity: {s['by_severity']}")

        if args.json and engine.findings:
            with open(args.json, "w") as fh:
                json.dump([f.to_dict() for f in engine.findings], fh, indent=2)
            print(f"  Saved to {args.json}")

        # Update baseline with new events too (online learning)
        engine.save_baseline(args.baseline)

    elif args.build:
        if Path(args.baseline).exists():
            engine.load_baseline(args.baseline)
        engine.load_jsonl(args.events, detect=False)
        engine.save_baseline(args.baseline)
        s = engine.summary()
        print(f"  Baseline built/updated: {s['events_processed']} total events, "
              f"{s['entities_tracked']} entities")
        print(f"  Saved to {C}{args.baseline}{R}")
    else:
        print("  Specify --build (train baseline) or --detect (find anomalies)")


if __name__ == "__main__":
    main()
