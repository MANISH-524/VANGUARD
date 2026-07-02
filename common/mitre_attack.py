#!/usr/bin/env python3
"""
Vanguard-OOB :: MITRE ATT&CK Intelligence Layer
================================================
Gives every detection a common vocabulary. A SOC analyst doesn't think
"high-entropy write" — they think "T1486 Data Encrypted for Impact". This
module maps Vanguard's raw telemetry events to ATT&CK technique IDs, tactics,
and references, so alerts, the dashboard, and reports all speak ATT&CK.

Scope: a curated subset of ATT&CK Enterprise covering the techniques this
framework actually detects. It is NOT the full matrix (that is ~200 techniques);
it is the slice we can honestly claim to detect, each with a real technique ID.

Reference: https://attack.mitre.org/  (technique IDs are the real published IDs)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# ATT&CK Tactics (the "why" — kill-chain phase)
# ---------------------------------------------------------------------------
TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


@dataclass
class Technique:
    tid: str                 # e.g. "T1486"
    name: str                # e.g. "Data Encrypted for Impact"
    tactics: List[str]       # tactic IDs
    description: str = ""

    @property
    def url(self) -> str:
        base = self.tid.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{base}/"

    def to_dict(self) -> dict:
        return {
            "technique_id": self.tid,
            "name": self.name,
            "tactics": [{"id": t, "name": TACTICS.get(t, t)} for t in self.tactics],
            "url": self.url,
        }


# ---------------------------------------------------------------------------
# Technique catalog (the techniques we detect)
# ---------------------------------------------------------------------------
TECHNIQUES: Dict[str, Technique] = {
    "T1486": Technique("T1486", "Data Encrypted for Impact", ["TA0040"],
                       "Adversary encrypts data on target systems (ransomware)."),
    "T1490": Technique("T1490", "Inhibit System Recovery", ["TA0040"],
                       "Deleting backups / shadow copies to prevent recovery."),
    "T1059": Technique("T1059", "Command and Scripting Interpreter", ["TA0002"],
                       "Abuse of command/script interpreters (shells) to execute."),
    "T1505.003": Technique("T1505.003", "Web Shell", ["TA0003"],
                           "Web server backdoor enabling persistent remote access."),
    "T1036.005": Technique("T1036.005", "Masquerading: Match Legitimate Name or Location", ["TA0005"],
                           "Executing from suspicious/temp paths to evade detection."),
    "T1071": Technique("T1071", "Application Layer Protocol", ["TA0011"],
                       "C2 over standard application-layer protocols."),
    "T1571": Technique("T1571", "Non-Standard Port", ["TA0011"],
                       "C2 / exfil over an unusual destination port."),
    "T1496": Technique("T1496", "Resource Hijacking", ["TA0040"],
                       "Abnormal resource consumption (e.g. mass crypto activity)."),
    "T1562.001": Technique("T1562.001", "Impair Defenses: Disable or Modify Tools", ["TA0005"],
                           "Tampering with or killing security agents/tooling."),
    "T1021": Technique("T1021", "Remote Services", ["TA0008"],
                       "Lateral movement via remote services (RDP/SSH/SMB)."),
    "T1110": Technique("T1110", "Brute Force", ["TA0006"],
                       "Password spraying / credential brute forcing."),
    # --- Current-threat additions (2024-2026 incident-driven) ---
    "T1003.001": Technique("T1003.001", "OS Credential Dumping: LSASS Memory", ["TA0006"],
                           "Dumping LSASS to steal credentials (Mimikatz/comsvcs/procdump)."),
    "T1059.001": Technique("T1059.001", "Command and Scripting Interpreter: PowerShell", ["TA0002"],
                           "Encoded/obfuscated PowerShell used to execute payloads in memory."),
    "T1027": Technique("T1027", "Obfuscated Files or Information", ["TA0005"],
                       "Base64/compressed/encoded payloads to evade static detection."),
    "T1219": Technique("T1219", "Remote Access Software", ["TA0011"],
                       "Abuse of RMM tools (AnyDesk/ScreenConnect/TeamViewer) for access."),
    "T1567.002": Technique("T1567.002", "Exfiltration to Cloud Storage", ["TA0010"],
                           "Bulk data exfil to Mega/Dropbox/S3/rclone endpoints."),
    "T1053": Technique("T1053", "Scheduled Task/Job", ["TA0003"],
                       "Persistence/execution via cron, at, or schtasks."),
    "T1546.003": Technique("T1546.003", "Event Triggered Execution: WMI Subscription", ["TA0003"],
                           "Fileless persistence via WMI __EventFilter/CommandLineConsumer."),
    "T1218": Technique("T1218", "System Binary Proxy Execution (LOLBin)", ["TA0005"],
                       "Signed OS binaries (rundll32/mshta/regsvr32) proxying malicious code."),
    "T1560": Technique("T1560", "Archive Collected Data", ["TA0009"],
                       "Staging data into archives (rar/7z/zip) before exfiltration."),
    "T1558.003": Technique("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", ["TA0006"],
                           "Requesting service tickets to crack offline (SPN roasting)."),
    "T1078.004": Technique("T1078.004", "Valid Accounts: Cloud Accounts", ["TA0005"],
                           "Abuse of valid cloud identities (impossible travel / anomalous logon)."),
    "T1621": Technique("T1621", "Multi-Factor Authentication Request Generation", ["TA0006"],
                       "MFA-fatigue / push-bombing to coerce approval."),
    "T1068": Technique("T1068", "Exploitation for Privilege Escalation (BYOVD)", ["TA0004"],
                       "Loading a vulnerable signed driver to gain kernel execution."),
    "T1136": Technique("T1136", "Create Account", ["TA0003"],
                       "Adversary creates a new local/domain account for persistence."),
}


# ---------------------------------------------------------------------------
# Event → technique mapping
# ---------------------------------------------------------------------------
# Map Vanguard event_type (+ optional reason discriminator) to technique IDs.
_EVENT_MAP: Dict[str, List[str]] = {
    "crypto_spike":   ["T1486", "T1496"],
    "entropy":        ["T1486"],
    "velocity":       ["T1486"],
    "shadow":         ["T1490"],
    "network":        ["T1071", "T1571"],
    "agent_silence":  ["T1562.001"],
    # --- current-threat event types ---
    "rmm_tool":       ["T1219"],
    "cloud_exfil":    ["T1567.002"],
    "lolbin":         ["T1218"],
    "staging":        ["T1560"],
    "driver_load":    ["T1068"],
    "cloud_auth":     ["T1078.004"],
    "ransomware_esxi":["T1486"],
    "cred_dump":      ["T1003.001"],
    # process / cred_access / persistence / powershell are discriminated by reason below
}
_PROCESS_REASON_MAP: Dict[str, List[str]] = {
    "web_server_spawned_shell": ["T1505.003", "T1059"],
    "suspicious_exec_path":     ["T1036.005", "T1059"],
}
# (event_type, reason) -> techniques, for events that need a discriminator.
_REASON_MAP: Dict[str, List[str]] = {
    "lsass_dump":       ["T1003.001"],
    "kerberoast":       ["T1558.003"],
    "mfa_fatigue":      ["T1621"],
    "encoded_command":  ["T1059.001", "T1027"],
    "obfuscated":       ["T1027"],
    "scheduled_task":   ["T1053"],
    "wmi_subscription": ["T1546.003"],
    "new_account":      ["T1136"],
}


def map_event_to_techniques(event_type: str, details: Optional[dict] = None) -> List[Technique]:
    """Return the ATT&CK techniques an event maps to (possibly empty)."""
    details = details or {}
    tids: List[str] = []
    reason = details.get("reason", "")
    if event_type == "process":
        tids = _PROCESS_REASON_MAP.get(reason, ["T1059"])
    elif event_type in ("cred_access", "persistence", "powershell") or reason in _REASON_MAP:
        tids = _REASON_MAP.get(reason, [])
    else:
        tids = _EVENT_MAP.get(event_type, [])
    return [TECHNIQUES[t] for t in tids if t in TECHNIQUES]


def annotate_event(event_type: str, details: Optional[dict] = None) -> dict:
    """Return a compact ATT&CK annotation suitable for embedding in an alert."""
    techs = map_event_to_techniques(event_type, details)
    if not techs:
        return {"techniques": [], "tactics": []}
    tactic_ids = sorted({t for tech in techs for t in tech.tactics})
    return {
        "techniques": [{"id": t.tid, "name": t.name, "url": t.url} for t in techs],
        "tactics": [{"id": t, "name": TACTICS.get(t, t)} for t in tactic_ids],
    }


def matrix_state(seen_technique_ids: set) -> List[dict]:
    """Build a tactic→technique matrix with a 'detected' flag, for the dashboard."""
    # Group techniques by their (first) tactic for a clean kill-chain layout.
    ordered_tactics = ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
                       "TA0006", "TA0007", "TA0008", "TA0009", "TA0011",
                       "TA0010", "TA0040"]
    by_tactic: Dict[str, List[dict]] = {t: [] for t in ordered_tactics}
    for tech in TECHNIQUES.values():
        for tac in tech.tactics:
            if tac in by_tactic:
                by_tactic[tac].append({
                    "id": tech.tid, "name": tech.name,
                    "detected": tech.tid in seen_technique_ids,
                })
                break
    return [{"tactic_id": t, "tactic": TACTICS[t], "techniques": by_tactic[t]}
            for t in ordered_tactics if by_tactic[t]]


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"Catalog: {len(TECHNIQUES)} techniques across {len(TACTICS)} tactics\n")
    samples = [
        ("crypto_spike", {}),
        ("shadow", {}),
        ("process", {"reason": "web_server_spawned_shell"}),
        ("process", {"reason": "suspicious_exec_path"}),
        ("network", {}),
        ("agent_silence", {}),
    ]
    for et, d in samples:
        ann = annotate_event(et, d)
        ids = ", ".join(t["id"] for t in ann["techniques"])
        tacs = ", ".join(t["name"] for t in ann["tactics"])
        print(f"  {et:14} ({d.get('reason','')!s:26}) -> [{ids}]  ({tacs})")
    seen = {"T1486", "T1490", "T1505.003"}
    print(f"\nMatrix tactics with detections: "
          f"{sum(1 for row in matrix_state(seen) for t in row['techniques'] if t['detected'])} techniques lit")
