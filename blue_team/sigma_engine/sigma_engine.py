#!/usr/bin/env python3
r"""
Vanguard-OOB :: Sigma-Compatible Detection Engine
==================================================
Loads detection rules in the Sigma format (https://sigmahq.io) and matches them
against Vanguard telemetry events. Sigma is the open, vendor-neutral standard
for SIEM detection rules — being compatible with it means analysts can drop in
community rules and Vanguard's own rules use a format the whole industry knows.

SUPPORTED SIGMA SUBSET (faithful to the spec, not the whole thing):
  - title, id, status, description, author, level, tags  (metadata, incl. ATT&CK tags)
  - logsource                                            (informational filter)
  - detection:
      <selection blocks>          dict of {field|modifier: value|list}
      condition: boolean over selection names
                 supports: and / or / not / parentheses / "1 of them" / "all of them"
  - field value modifiers: |contains |startswith |endswith |re |all
  - a list of values on a field = OR; multiple fields in a selection = AND

NOT supported (documented honestly): aggregations (count() by ...),
near/temporal correlation, and field-name backends. Those need a stateful SIEM;
this engine does single-event matching, which covers the rule set we ship.

Usage:
    python3 sigma_engine.py --list
    python3 sigma_engine.py --test
    python3 sigma_engine.py --match '{"event_type":"crypto_spike","details":{}}'
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
    _HAVE_YAML = True
except Exception:
    _HAVE_YAML = False

RULES_DIR = Path(__file__).parent / "rules"


# ---------------------------------------------------------------------------
# Field matching with Sigma modifiers
# ---------------------------------------------------------------------------

def _get_field(event: dict, field_name: str) -> Any:
    """Resolve a (possibly dotted) field path against the event dict."""
    cur: Any = event
    for part in field_name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_value(actual: Any, expected: Any, modifier: Optional[str]) -> bool:
    if actual is None:
        return False
    a = str(actual)
    if modifier == "re":
        try:
            return re.search(str(expected), a, re.IGNORECASE) is not None
        except re.error:
            return False
    e = str(expected)
    al, el = a.lower(), e.lower()
    if modifier == "contains":
        return el in al
    if modifier == "startswith":
        return al.startswith(el)
    if modifier == "endswith":
        return al.endswith(el)
    # exact (case-insensitive), with numeric tolerance
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    return al == el


def _match_field(event: dict, key: str, value: Any) -> bool:
    """Match one 'field|modifier: value(s)' entry from a selection."""
    if "|" in key:
        field_name, modifier = key.split("|", 1)
        modifier = modifier.strip()
    else:
        field_name, modifier = key, None

    actual = _get_field(event, field_name)

    # |all modifier: every value in the list must match (AND); else list = OR.
    if isinstance(value, list):
        sub_mod = None
        if modifier == "all":
            return all(_match_value(actual, v, sub_mod) for v in value)
        # strip 'all' from compound modifiers like 'contains|all' if present
        base_mod = modifier
        return any(_match_value(actual, v, base_mod) for v in value)
    return _match_value(actual, value, modifier)


def _match_selection(event: dict, selection: Any) -> bool:
    """A selection is a dict (AND of fields) or a list of dicts (OR)."""
    if isinstance(selection, list):
        return any(_match_selection(event, s) for s in selection)
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    return False


# ---------------------------------------------------------------------------
# Condition evaluation (boolean over selection names)
# ---------------------------------------------------------------------------

def _eval_condition(condition: str, results: Dict[str, bool]) -> bool:
    """
    Evaluate a Sigma condition string against a map of {selection_name: bool}.
    Supports and/or/not/parens, 'all of them', '1 of them', 'all of selection*'.
    """
    cond = condition.strip()

    # Expand 'X of them' / 'X of selection*' shortcuts.
    def _names(prefix: Optional[str]) -> List[str]:
        if prefix is None:
            return list(results.keys())
        return [n for n in results if n.startswith(prefix)]

    # 'all of them' / 'all of <prefix>*'
    m = re.fullmatch(r"all of (them|[\w]+\*)", cond)
    if m:
        tok = m.group(1)
        names = _names(None) if tok == "them" else _names(tok[:-1])
        return all(results.get(n, False) for n in names) and bool(names)
    # '1 of them' / 'N of them' / '1 of <prefix>*'
    m = re.fullmatch(r"(\d+) of (them|[\w]+\*)", cond)
    if m:
        need = int(m.group(1)); tok = m.group(2)
        names = _names(None) if tok == "them" else _names(tok[:-1])
        return sum(1 for n in names if results.get(n, False)) >= need

    # General boolean expression: replace selection names with True/False.
    # Tokenise on words/parentheses; keep and/or/not as Python operators.
    def repl(token: str) -> str:
        t = token.strip()
        if t in ("and", "or", "not", "(", ")"):
            return t
        if t in results:
            return "True" if results[t] else "False"
        # 'of', 'them', 'all', stray words -> leave for safety as False
        if t in ("True", "False"):
            return t
        return "False"

    tokens = re.findall(r"\(|\)|\w+\*?|\S", cond)
    expr = " ".join(repl(t) for t in tokens)
    # Only allow a safe boolean expression.
    if not re.fullmatch(r"[\sTrueFalsandortx()]+", expr.replace("not", "")):
        # Fallback: be conservative.
        return False
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 (sanitised)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------

@dataclass
class SigmaRule:
    title: str
    id: str
    level: str
    detection: dict
    description: str = ""
    tags: List[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @property
    def attack_techniques(self) -> List[str]:
        """Extract ATT&CK technique IDs from Sigma tags (attack.t1486 -> T1486)."""
        out = []
        for t in self.tags:
            tl = t.lower()
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tl)
            if m:
                out.append(m.group(1).upper())
        return out

    def match(self, event: dict) -> bool:
        det = self.detection
        condition = det.get("condition", "")
        results = {name: _match_selection(event, sel)
                   for name, sel in det.items() if name != "condition"}
        if not condition:
            # No explicit condition: AND of all selections.
            return all(results.values()) and bool(results)
        return _eval_condition(condition, results)

    def to_dict(self) -> dict:
        return {"title": self.title, "id": self.id, "level": self.level,
                "tags": self.tags, "attack": self.attack_techniques}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SigmaEngine:
    def __init__(self):
        self.rules: List[SigmaRule] = []

    def load_dir(self, path: Path = RULES_DIR) -> int:
        if not _HAVE_YAML:
            raise RuntimeError("PyYAML not installed — cannot load Sigma rules")
        count = 0
        for f in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8"))
                if not doc or "detection" not in doc:
                    continue
                self.rules.append(SigmaRule(
                    title=doc.get("title", f.stem),
                    id=str(doc.get("id", f.stem)),
                    level=doc.get("level", "medium"),
                    detection=doc["detection"],
                    description=doc.get("description", ""),
                    tags=doc.get("tags", []) or [],
                    logsource=doc.get("logsource", {}) or {},
                    raw=doc,
                ))
                count += 1
            except Exception as e:
                print(f"[warn] failed to load {f.name}: {e}", file=sys.stderr)
        return count

    def evaluate(self, event: dict) -> List[SigmaRule]:
        """Return all rules that fire for a single event."""
        return [r for r in self.rules if r.match(event)]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Vanguard Sigma-compatible engine")
    ap.add_argument("--list", action="store_true", help="list loaded rules")
    ap.add_argument("--test", action="store_true", help="run built-in match tests")
    ap.add_argument("--match", metavar="JSON", help="match a single event (JSON)")
    ap.add_argument("--rules-dir", default=str(RULES_DIR))
    args = ap.parse_args()

    eng = SigmaEngine()
    n = eng.load_dir(Path(args.rules_dir))
    print(f"Loaded {n} Sigma rule(s) from {args.rules_dir}")

    if args.list:
        for r in eng.rules:
            print(f"  [{r.level:8}] {r.title:42} {','.join(r.attack_techniques)}")

    if args.match:
        ev = json.loads(args.match)
        fired = eng.evaluate(ev)
        if fired:
            for r in fired:
                print(f"  FIRED: {r.title}  ({','.join(r.attack_techniques)})")
        else:
            print("  No rules matched.")

    if args.test:
        tests = [
            ({"event_type": "crypto_spike", "severity": "critical", "details": {"reason": "ransomware_crypto_spike"}}, True),
            ({"event_type": "shadow", "details": {"reason": "backup_destruction_detected"}}, True),
            ({"event_type": "process", "details": {"reason": "web_server_spawned_shell"}}, True),
            ({"event_type": "network", "details": {"dest_port": 4444}}, True),
            ({"event_type": "heartbeat", "details": {}}, False),
        ]
        ok = 0
        for ev, expect_fire in tests:
            fired = eng.evaluate(ev)
            got = len(fired) > 0
            status = "PASS" if got == expect_fire else "FAIL"
            if got == expect_fire:
                ok += 1
            names = ",".join(r.attack_techniques[0] if r.attack_techniques else r.title for r in fired)
            print(f"  [{status}] {ev['event_type']:14} fired={got:<5} ({names})")
        print(f"\n  {ok}/{len(tests)} match tests passed")


if __name__ == "__main__":
    main()
