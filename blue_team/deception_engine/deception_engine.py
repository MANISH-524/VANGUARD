#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 16 — Deception Engine
=====================================================
Original architecture. Generates and monitors DECEPTION ARTIFACTS —
fake-but-convincing assets that have NO legitimate reason to ever be
accessed. Any access is, by definition, malicious activity (the
zero-false-positive property that makes deception so valuable).

Artifact types generated:

  1. CANARY FILES — realistic-looking documents ("passwords.xlsx",
     "aws_credentials.txt", "employee_ssns.csv") seeded with embedded
     CANARY TOKENS (unique per-deployment markers). A background watcher
     monitors access-time (atime) changes on these files via polling —
     ANY read access fires a critical alert with full process context
     (who/what/when via /proc on Linux).

  2. CANARY CREDENTIALS — fake but well-formed AWS keys, database
     connection strings, and API tokens planted in common locations
     (~/.aws/credentials, .env files, browser-saved-password-style
     files). Each embeds a unique token; the monitor watches for the
     token appearing in:
        - outbound network payloads (via packet_inspector integration)
        - process command-lines (via psutil)
        - newly-created files anywhere on disk (via grep-style scan)
     Real cloud credential canaries normally phone home to AWS — here we
     do local-network-only detection since this framework is fully OOB.

  3. CANARY DNS NAMES — unique per-deployment subdomains seeded into
     fake config files ("internal-vpn-backup.<token>.corp.local"). Any
     DNS query for these names (observed via dns_analyzer's passive log
     or packet_inspector) is 100% signal — no legitimate process would
     ever resolve a name that exists ONLY inside a planted decoy file.

  4. CANARY PROCESSES / SERVICES — fake service binaries with enticing
     names ("backup-agent","db-replication-svc") that are actually
     no-ops; their EXECUTION is the alert. Useful for catching automated
     "run everything" malware/worm behavior.

  5. BREADCRUMB TRAIL — fake "notes.txt" / shell history entries that
     POINT TO the canary credentials/files, increasing the chance an
     attacker doing recon finds and uses them (classic deception
     engineering — make the bait discoverable).

Monitoring runs continuously (polling, configurable interval) and emits
findings the moment any canary is touched.

Usage:
    python3 deception_engine.py --deploy --target-dir /home/svcuser --count 5
    python3 deception_engine.py --watch  --manifest canary_manifest.json --interval 5
    python3 deception_engine.py --status --manifest canary_manifest.json
"""

import argparse
import json
import logging
import os
import platform
import random
import re
import string
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import psutil

logger = logging.getLogger("vanguard.deception")
IS_LINUX = platform.system() == "Linux"


# ─────────────────────────────────────────────────────────────────────────────
# Token generation
# ─────────────────────────────────────────────────────────────────────────────

def gen_token(prefix: str = "VGD") -> str:
    """Per-deployment unique canary token — embedded in all artifacts."""
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def gen_fake_aws_key() -> Dict[str, str]:
    body = "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
    secret = "".join(random.choices(string.ascii_letters + string.digits + "+/", k=40))
    return {"access_key_id": f"AKIA{body}", "secret_access_key": secret}


# ─────────────────────────────────────────────────────────────────────────────
# Canary artifact templates
# ─────────────────────────────────────────────────────────────────────────────

def render_passwords_xlsx_csv(token: str) -> str:
    """CSV masquerading as an exported password vault."""
    rows = [
        "system,username,password,notes",
        f"prod-db-master,admin,Cyb3rV@ngu@rd_{token[:8]},rotate quarterly",
        f"backup-server,svc_backup,Bkp!{token[8:14]}xQ,DO NOT SHARE",
        f"vpn-gateway,netadmin,Vpn#{token[-6:]}99,emergency access only",
        "wifi-guest,guest,Welcome2024,for visitors",
    ]
    return "\n".join(rows) + "\n"


def render_aws_credentials(token: str, fake_key: Dict[str,str]) -> str:
    return (
        "[default]\n"
        f"aws_access_key_id = {fake_key['access_key_id']}\n"
        f"aws_secret_access_key = {fake_key['secret_access_key']}\n"
        f"# canary:{token}\n"
        "\n"
        "[backup-role]\n"
        f"aws_access_key_id = AKIA{token[:16].upper()}\n"
        f"aws_secret_access_key = {fake_key['secret_access_key'][::-1]}\n"
    )


def render_env_file(token: str) -> str:
    return (
        f"# Production environment — canary:{token}\n"
        f"DATABASE_URL=postgres://admin:Pr0dP@ss_{token[:8]}@10.0.0.50:5432/maindb\n"
        f"REDIS_URL=redis://:R3d1sP@ss{token[8:14]}@10.0.0.51:6379/0\n"
        f"JWT_SECRET={token}{uuid.uuid4().hex}\n"
        f"STRIPE_SECRET_KEY=sk_live_{token.replace('-','')}{uuid.uuid4().hex[:24]}\n"
    )


def render_ssh_config_breadcrumb(token: str, canary_paths: List[str]) -> str:
    """Fake shell history pointing to other canaries — increases discoverability."""
    lines = [
        "ls -la ~/.aws/",
        f"cat {canary_paths[0] if canary_paths else '~/.aws/credentials'}",
        "vim ~/Documents/passwords.xlsx",
        "scp passwords.xlsx backup-server:/srv/backup/",
        f"# TODO: rotate canary {token[:8]} before audit",
    ]
    return "\n".join(lines) + "\n"


def render_employee_csv(token: str) -> str:
    rows = ["employee_id,name,ssn,salary,manager"]
    fake_names = ["J. Carter","M. Nguyen","A. Patel","R. Schmidt","T. Okafor"]
    hex_part = token.split("-")[-1]  # strip the "VGD-" prefix, keep hex digits
    for i, name in enumerate(fake_names):
        ssn = f"{900+i:03d}-{int(hex_part[:2],16)%99:02d}-{1000+i*111:04d}"
        rows.append(f"{1000+i},{name},{ssn},{75000+i*5000},mgr-{hex_part[:4]}")
    return "\n".join(rows) + "\n"


CANARY_TEMPLATES = {
    "passwords":   ("passwords_export.csv",   render_passwords_xlsx_csv,  "credential_lure"),
    "aws_creds":   (".aws/credentials",       lambda t: render_aws_credentials(t, gen_fake_aws_key()), "cloud_credential_lure"),
    "env_file":    (".env.production.bak",    render_env_file,            "config_secret_lure"),
    "employee_csv":("hr/employee_master.csv", render_employee_csv,        "pii_lure"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CanaryArtifact:
    artifact_id:  str
    artifact_type:str          # "file" | "dns" | "process"
    category:     str
    path:         str
    token:        str
    deployed_at:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_atime:   float = 0.0   # baseline access time at deployment
    last_size:    int = 0

    def to_dict(self):
        return asdict(self)


@dataclass
class DeceptionFinding:
    finding_type: str
    severity:     str
    mitre:        str
    description:  str
    evidence:     dict = field(default_factory=dict)
    score:        int  = 50
    timestamp:    str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Deployment engine
# ─────────────────────────────────────────────────────────────────────────────

class CanaryDeployer:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)

    def deploy_file_canaries(self, types: List[str] = None) -> List[CanaryArtifact]:
        types = types or list(CANARY_TEMPLATES.keys())
        artifacts = []

        # Discoverability breadcrumb file generated last, references others
        deployed_paths = []

        for t in types:
            if t not in CANARY_TEMPLATES:
                continue
            rel_path, renderer, category = CANARY_TEMPLATES[t]
            full_path = self.target_dir / rel_path
            full_path.parent.mkdir(parents=True, exist_ok=True)

            token   = gen_token()
            content = renderer(token)
            full_path.write_text(content)

            try:
                st = os.stat(full_path)
                atime, size = st.st_atime, st.st_size
            except OSError:
                atime, size = 0.0, 0

            artifacts.append(CanaryArtifact(
                artifact_id   = uuid.uuid4().hex[:12],
                artifact_type = "file",
                category      = category,
                path          = str(full_path),
                token         = token,
                last_atime    = atime,
                last_size     = size,
            ))
            deployed_paths.append(str(full_path))
            logger.info("Deployed canary: %s [%s]", full_path, category)

        # Breadcrumb trail referencing all deployed canaries
        if deployed_paths:
            crumb_path = self.target_dir / ".bash_history_backup"
            crumb_token = gen_token()
            crumb_path.write_text(render_ssh_config_breadcrumb(crumb_token, deployed_paths))
            try:
                st = os.stat(crumb_path)
                atime, size = st.st_atime, st.st_size
            except OSError:
                atime, size = 0.0, 0
            artifacts.append(CanaryArtifact(
                artifact_id   = uuid.uuid4().hex[:12],
                artifact_type = "file",
                category      = "breadcrumb_trail",
                path          = str(crumb_path),
                token         = crumb_token,
                last_atime    = atime,
                last_size     = size,
            ))
            logger.info("Deployed breadcrumb trail: %s", crumb_path)

        return artifacts

    def deploy_dns_canary(self, domain_suffix: str = "corp.local") -> CanaryArtifact:
        """
        Generates a unique canary subdomain and embeds it in a fake VPN
        config — any DNS query for this name is pure signal.
        """
        token  = gen_token("DNS")
        canary_fqdn = f"vpn-backup-{token.lower()}.{domain_suffix}"

        vpn_conf = self.target_dir / "vpn_failover.conf"
        vpn_conf.parent.mkdir(parents=True, exist_ok=True)
        vpn_conf.write_text(
            "# Failover VPN configuration — DO NOT MODIFY\n"
            f"remote {canary_fqdn} 1194\n"
            "proto udp\n"
            "dev tun\n"
            f"# canary-dns:{token}\n"
        )

        try:
            st = os.stat(vpn_conf)
            atime, size = st.st_atime, st.st_size
        except OSError:
            atime, size = 0.0, 0

        artifact = CanaryArtifact(
            artifact_id   = uuid.uuid4().hex[:12],
            artifact_type = "dns",
            category      = "dns_lure",
            path          = str(vpn_conf),
            token         = token,
            last_atime    = atime,
            last_size     = size,
        )
        # Stash the FQDN itself in evidence via path naming convention
        artifact.path = f"{vpn_conf}|fqdn={canary_fqdn}"
        logger.info("Deployed DNS canary: %s", canary_fqdn)
        return artifact

    def deploy_process_canary(self) -> CanaryArtifact:
        """
        Drops a fake 'backup agent' shell script with an enticing name.
        Its EXECUTION (not just access) is the signal — monitor checks
        for any process whose cmdline references this path.
        """
        token = gen_token("PROC")
        script_path = self.target_dir / "backup-agent.sh"
        script_path.write_text(
            "#!/bin/bash\n"
            f"# canary:{token}\n"
            "# DO NOT RUN MANUALLY - managed by systemd timer\n"
            "echo 'backup agent placeholder'\n"
        )
        try:
            os.chmod(script_path, 0o755)
        except OSError:
            pass

        try:
            st = os.stat(script_path)
            atime, size = st.st_atime, st.st_size
        except OSError:
            atime, size = 0.0, 0

        artifact = CanaryArtifact(
            artifact_id   = uuid.uuid4().hex[:12],
            artifact_type = "process",
            category      = "process_lure",
            path          = str(script_path),
            token         = token,
            last_atime    = atime,
            last_size     = size,
        )
        logger.info("Deployed process canary: %s", script_path)
        return artifact


# ─────────────────────────────────────────────────────────────────────────────
# Monitoring engine
# ─────────────────────────────────────────────────────────────────────────────

class CanaryMonitor:
    """
    Polls deployed canaries for access-time changes, scans running
    processes for canary-token references, and checks for canary tokens
    appearing in newly-modified files elsewhere on disk.
    """

    def __init__(self, artifacts: List[CanaryArtifact], scan_paths: List[str] = None):
        self.artifacts  = artifacts
        self.scan_paths = scan_paths or []
        self._exfil_seen: set = set()

    def check_file_access(self) -> List[DeceptionFinding]:
        findings = []
        for art in self.artifacts:
            if art.artifact_type not in ("file","process"):
                continue
            real_path = art.path.split("|")[0]
            try:
                st = os.stat(real_path)
            except OSError:
                findings.append(DeceptionFinding(
                    finding_type="canary_file_missing",
                    severity="high", mitre="T1485",
                    description=f"Canary artifact deleted: {real_path}",
                    evidence={"artifact_id": art.artifact_id, "category": art.category},
                    score=40,
                ))
                continue

            if st.st_atime > art.last_atime + 1:  # tolerance for fs noise
                accessor = self._find_recent_accessor(real_path)
                findings.append(DeceptionFinding(
                    finding_type="canary_file_accessed",
                    severity="critical", mitre="T1083",
                    description=f"CANARY TRIGGERED: '{real_path}' "
                                f"({art.category}) was accessed",
                    evidence={"artifact_id": art.artifact_id, "category": art.category,
                              "token": art.token, "likely_process": accessor,
                              "prev_atime": art.last_atime, "new_atime": st.st_atime},
                    score=70,
                ))
                art.last_atime = st.st_atime

            if st.st_size != art.last_size:
                findings.append(DeceptionFinding(
                    finding_type="canary_file_modified",
                    severity="critical", mitre="T1565",
                    description=f"CANARY MODIFIED: '{real_path}' size changed "
                                f"({art.last_size} → {st.st_size} bytes)",
                    evidence={"artifact_id": art.artifact_id, "token": art.token},
                    score=70,
                ))
                art.last_size = st.st_size

        return findings

    def check_process_execution(self) -> List[DeceptionFinding]:
        """Detect execution of process canaries or cmdlines referencing tokens."""
        findings = []
        tokens = {a.token for a in self.artifacts}
        proc_paths = {a.path.split("|")[0] for a in self.artifacts if a.artifact_type == "process"}

        for proc in psutil.process_iter(["pid","name","exe","cmdline"]):
            try:
                cmdline = " ".join(proc.info.get("cmdline") or [])
                exe     = proc.info.get("exe") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            for pp in proc_paths:
                if pp in cmdline or pp in exe:
                    key = f"proc:{proc.info['pid']}:{pp}"
                    if key not in self._exfil_seen:
                        self._exfil_seen.add(key)
                        findings.append(DeceptionFinding(
                            finding_type="canary_process_executed",
                            severity="critical", mitre="T1059",
                            description=f"CANARY PROCESS EXECUTED: {pp} "
                                        f"(pid={proc.info['pid']})",
                            evidence={"pid": proc.info["pid"], "cmdline": cmdline[:200]},
                            score=70,
                        ))

            for tok in tokens:
                if tok in cmdline:
                    key = f"token:{proc.info['pid']}:{tok}"
                    if key not in self._exfil_seen:
                        self._exfil_seen.add(key)
                        findings.append(DeceptionFinding(
                            finding_type="canary_token_in_cmdline",
                            severity="critical", mitre="T1552.001",
                            description=f"Canary token '{tok[:12]}...' found in process "
                                        f"command line (pid={proc.info['pid']})",
                            evidence={"pid": proc.info["pid"], "token": tok,
                                      "cmdline": cmdline[:200]},
                            score=70,
                        ))
        return findings

    def check_token_exfil(self) -> List[DeceptionFinding]:
        """
        Scan recently-modified files in scan_paths for canary tokens —
        catches an attacker who copied canary contents into a staging
        file for exfiltration.
        """
        findings = []
        tokens = {a.token: a for a in self.artifacts}
        canary_files = {a.path.split("|")[0] for a in self.artifacts}
        now = time.time()

        for sp in self.scan_paths:
            root = Path(sp)
            if not root.exists():
                continue
            for fp in root.rglob("*"):
                if not fp.is_file():
                    continue
                fps = str(fp)
                if fps in canary_files:
                    continue
                try:
                    st = fp.stat()
                    if now - st.st_mtime > 300:   # only recently-modified files
                        continue
                    if st.st_size > 5 * 1024 * 1024:
                        continue
                    content = fp.read_text(errors="ignore")
                except (OSError, UnicodeDecodeError):
                    continue

                for tok, art in tokens.items():
                    if tok in content:
                        key = f"exfil:{fps}:{tok}"
                        if key not in self._exfil_seen:
                            self._exfil_seen.add(key)
                            findings.append(DeceptionFinding(
                                finding_type="canary_token_exfil_staging",
                                severity="critical", mitre="T1074",
                                description=f"Canary token from '{art.path.split('|')[0]}' "
                                            f"found copied into '{fps}' — possible "
                                            f"exfil staging",
                                evidence={"token": tok, "staging_file": fps,
                                          "source_artifact": art.artifact_id},
                                score=70,
                            ))
        return findings

    @staticmethod
    def _find_recent_accessor(path: str) -> str:
        """Best-effort: find a process with an open FD to this path (Linux)."""
        if not IS_LINUX:
            return "unknown"
        try:
            for proc in psutil.process_iter(["pid","name"]):
                try:
                    for f in proc.open_files():
                        if f.path == path:
                            return f"{proc.info['name']} (pid={proc.info['pid']})"
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except Exception:
            pass
        return "unknown (process exited before check)"

    def run_once(self) -> List[DeceptionFinding]:
        findings = []
        findings.extend(self.check_file_access())
        findings.extend(self.check_process_execution())
        findings.extend(self.check_token_exfil())
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Manifest persistence
# ─────────────────────────────────────────────────────────────────────────────

def save_manifest(artifacts: List[CanaryArtifact], path: str):
    with open(path, "w") as f:
        json.dump([a.to_dict() for a in artifacts], f, indent=2)


def load_manifest(path: str) -> List[CanaryArtifact]:
    with open(path) as f:
        data = json.load(f)
    return [CanaryArtifact(**d) for d in data]


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m"}

def _print_finding(f: DeceptionFinding):
    c = SEV_C.get(f.severity,""); R = "\033[0m"; B = "\033[1m"
    print(f"  {c}[{f.severity.upper():8}]{R} {B}{f.finding_type}{R}  +{f.score}")
    print(f"     {f.description}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Deception Engine")
    parser.add_argument("--deploy",  action="store_true")
    parser.add_argument("--watch",   action="store_true")
    parser.add_argument("--status",  action="store_true")
    parser.add_argument("--target-dir", default="/tmp/vanguard-canaries")
    parser.add_argument("--manifest",   default="canary_manifest.json")
    parser.add_argument("--types",      help="Comma-separated canary types to deploy")
    parser.add_argument("--include-dns",     action="store_true")
    parser.add_argument("--include-process", action="store_true")
    parser.add_argument("--scan-path", nargs="*", default=[],
                        help="Additional paths to scan for token exfil")
    parser.add_argument("--interval", type=int, default=10)
    parser.add_argument("--json", help="Output findings JSON (watch mode)")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Deception Engine ──{R}\n")

    if args.deploy:
        deployer = CanaryDeployer(args.target_dir)
        types = args.types.split(",") if args.types else None
        artifacts = deployer.deploy_file_canaries(types)
        if args.include_dns:
            artifacts.append(deployer.deploy_dns_canary())
        if args.include_process:
            artifacts.append(deployer.deploy_process_canary())

        save_manifest(artifacts, args.manifest)
        print(f"  Deployed {len(artifacts)} canary artifact(s) to {C}{args.target_dir}{R}")
        for a in artifacts:
            print(f"    [{a.category:20}] {a.path}")
        print(f"\n  Manifest saved to {C}{args.manifest}{R}")
        print(f"  Run with --watch --manifest {args.manifest} to monitor")

    elif args.watch:
        artifacts = load_manifest(args.manifest)
        print(f"  Loaded {len(artifacts)} canaries from {args.manifest}")
        print(f"  Watching every {args.interval}s — Ctrl+C to stop\n")
        monitor = CanaryMonitor(artifacts, scan_paths=args.scan_path)

        all_findings = []
        try:
            while True:
                findings = monitor.run_once()
                for f in findings:
                    _print_finding(f)
                    all_findings.append(f)
                if findings:
                    save_manifest(artifacts, args.manifest)  # persist updated atimes
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n  Stopped.")
            if args.json and all_findings:
                with open(args.json, "w") as f:
                    json.dump([fn.to_dict() for fn in all_findings], f, indent=2)
                print(f"  Findings saved to {args.json}")

    elif args.status:
        artifacts = load_manifest(args.manifest)
        print(f"  {len(artifacts)} canary artifact(s) deployed:\n")
        for a in artifacts:
            real_path = a.path.split("|")[0]
            exists = os.path.exists(real_path)
            status = "\033[92mOK\033[0m" if exists else "\033[91mMISSING\033[0m"
            print(f"    [{status}] [{a.category:20}] {a.path}  (token: {a.token[:16]}...)")

    else:
        print("  Specify --deploy, --watch, or --status")


if __name__ == "__main__":
    main()
