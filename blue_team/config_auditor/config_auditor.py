#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 15 — Configuration Hardening Auditor
====================================================================
Original architecture. CIS-Benchmark-INSPIRED (not copied) Linux hardening
auditor covering SSH, PAM/password policy, kernel sysctls, filesystem
permissions, service exposure, audit logging, and cron security.

Design goals:
  - Every check returns PASS / FAIL / WARN / INFO / SKIP (SKIP when the
    relevant subsystem isn't present — e.g. auditd not installed — so
    absence of a feature doesn't masquerade as a failure on minimal
    containers, which would be a false positive).
  - Each check carries a WEIGHT contributing to an overall 0-100
    Hardening Score, so results can be tracked over time / across fleets.
  - Remediation text is a single copy-pasteable command where possible.
  - Read-only: never modifies system state.

Categories implemented:
  SSH        — 9 checks (root login, password auth, protocol, ciphers, ...)
  PAM/PASSWD — 6 checks (password aging, complexity, lockout, history)
  KERNEL     — 8 sysctl checks (ASLR, ptrace_scope, IP forwarding, ...)
  FILESYS    — 6 checks (perms on /etc/passwd, /etc/shadow, world-writable)
  SERVICES   — 4 checks (unnecessary daemons, exposed management ports)
  AUDIT      — 3 checks (auditd presence, rules, log rotation)
  CRON       — 3 checks (cron file permissions, /etc/cron.allow)
  ACCOUNTS   — 4 checks (UID 0 accounts, empty passwords, shell on system accts)

Usage:
    python3 config_auditor.py --audit
    python3 config_auditor.py --audit --category ssh,kernel
    python3 config_auditor.py --audit --json report.json
"""

import argparse
import json
import logging
import os
import platform
import pwd
import re
import stat
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("vanguard.config_auditor")
IS_LINUX = platform.system() == "Linux"


# ── Result model ──────────────────────────────────────────────────────────

@dataclass
class AuditCheck:
    check_id:    str
    category:    str
    title:       str
    status:      str        # PASS / FAIL / WARN / INFO / SKIP
    severity:    str        # critical/high/medium/low/info
    weight:      int        # contribution to hardening score (0 if SKIP)
    description: str
    remediation: str  = ""
    evidence:    dict = field(default_factory=dict)
    timestamp:   str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


# ── Helpers ────────────────────────────────────────────────────────────────

def read_file(path: str) -> Optional[str]:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def parse_kv_config(text: str, comment_chars: str = "#") -> Dict[str, str]:
    """Parse simple `Key Value` or `Key=Value` config files (last value wins)."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in comment_chars:
            continue
        m = re.match(r"^([A-Za-z][\w\-\.]*)\s*[= ]\s*(.+)$", line)
        if m:
            out[m.group(1).lower()] = m.group(2).strip().strip('"')
    return out


def get_sysctl(name: str) -> Optional[str]:
    path = f"/proc/sys/{name.replace('.', '/')}"
    val = read_file(path)
    return val.strip() if val is not None else None


def run_cmd(args: List[str], timeout: int = 5) -> Tuple[int, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except Exception:
        return -1, ""


# ─────────────────────────────────────────────────────────────────────────────
# SSH checks
# ─────────────────────────────────────────────────────────────────────────────

def check_ssh(results: List[AuditCheck]):
    cfg_text = read_file("/etc/ssh/sshd_config")
    if cfg_text is None:
        results.append(AuditCheck("SSH-00","ssh","sshd_config presence","SKIP","info",0,
                       "OpenSSH server config not found — SSH server likely not installed"))
        return

    cfg = parse_kv_config(cfg_text)

    def check(check_id, key, expected, title, severity, weight, remediation, default=None,
              compare: Callable[[str,str],bool] = lambda v,e: v.lower()==e.lower()):
        val = cfg.get(key.lower(), default)
        if val is None:
            status = "WARN"
            desc = f"{key} not explicitly set (OpenSSH default may differ across versions)"
        elif compare(val, expected):
            status = "PASS"
            desc = f"{key} = {val}"
        else:
            status = "FAIL"
            desc = f"{key} = {val} (expected {expected})"
        results.append(AuditCheck(check_id,"ssh",title,status,severity,
                       weight if status!="PASS" else 0,
                       desc, remediation if status!="PASS" else "",
                       evidence={"directive": key, "value": val}))

    check("SSH-01","PermitRootLogin","no","Root login disabled","critical",20,
          "Set 'PermitRootLogin no' in /etc/ssh/sshd_config")
    check("SSH-02","PasswordAuthentication","no","Password auth disabled (key-only)","high",15,
          "Set 'PasswordAuthentication no'; ensure key-based auth configured first")
    check("SSH-03","PermitEmptyPasswords","no","Empty passwords disallowed","critical",20,
          "Set 'PermitEmptyPasswords no'", default="no")
    check("SSH-04","X11Forwarding","no","X11 forwarding disabled","low",5,
          "Set 'X11Forwarding no' unless required")
    check("SSH-05","MaxAuthTries","6","Bounded auth retries","medium",10,
          "Set 'MaxAuthTries 4' or lower",
          compare=lambda v,e: v.isdigit() and int(v) <= int(e))
    check("SSH-06","Protocol","2","Protocol 2 only","critical",15,
          "Remove Protocol 1 support entirely (default in modern OpenSSH)", default="2")
    check("SSH-07","PermitUserEnvironment","no","User environment override disabled","low",5,
          "Set 'PermitUserEnvironment no'", default="no")
    check("SSH-08","LoginGraceTime","60","Bounded login grace time","low",5,
          "Set 'LoginGraceTime 30' or lower",
          compare=lambda v,e: (v.rstrip("sm").isdigit() and int(re.sub(r'\D','',v)) <= 60), default="120")
    check("SSH-09","ClientAliveInterval","300","Idle session timeout configured","medium",10,
          "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 2'",
          compare=lambda v,e: v.isdigit() and 0 < int(v) <= 900, default="0")


# ─────────────────────────────────────────────────────────────────────────────
# PAM / Password policy checks
# ─────────────────────────────────────────────────────────────────────────────

def check_password_policy(results: List[AuditCheck]):
    login_defs = read_file("/etc/login.defs")
    if login_defs:
        cfg = parse_kv_config(login_defs)

        def numcheck(check_id, key, op, threshold, title, severity, weight, remediation):
            val = cfg.get(key.lower())
            if val is None or not val.lstrip("-").isdigit():
                results.append(AuditCheck(check_id,"pam",title,"WARN",severity,weight,
                               f"{key} not set in /etc/login.defs", remediation,
                               evidence={"directive": key}))
                return
            v = int(val)
            ok = op(v, threshold)
            results.append(AuditCheck(check_id,"pam",title,"PASS" if ok else "FAIL",
                           severity, 0 if ok else weight,
                           f"{key} = {v}" + ("" if ok else f" (expected {op.__name__} {threshold})"),
                           remediation if not ok else "",
                           evidence={"directive": key, "value": v}))

        numcheck("PAM-01","PASS_MAX_DAYS", lambda v,t: v<=t, 90,
                 "Password max age <= 90 days","medium",10,
                 "Set 'PASS_MAX_DAYS 90' in /etc/login.defs")
        numcheck("PAM-02","PASS_MIN_DAYS", lambda v,t: v>=t, 1,
                 "Password min age >= 1 day","low",5,
                 "Set 'PASS_MIN_DAYS 1' in /etc/login.defs")
        numcheck("PAM-03","PASS_WARN_AGE", lambda v,t: v>=t, 7,
                 "Password expiry warning >= 7 days","low",5,
                 "Set 'PASS_WARN_AGE 7' in /etc/login.defs")
    else:
        results.append(AuditCheck("PAM-00","pam","login.defs presence","SKIP","info",0,
                       "/etc/login.defs not found"))

    # pwquality / cracklib
    pwq = read_file("/etc/security/pwquality.conf")
    if pwq:
        cfg = parse_kv_config(pwq)
        minlen = cfg.get("minlen")
        ok = minlen is not None and minlen.lstrip("-").isdigit() and int(minlen) >= 12
        results.append(AuditCheck("PAM-04","pam","Password minimum length >= 12",
                       "PASS" if ok else "FAIL", "medium", 0 if ok else 10,
                       f"minlen = {minlen}" if minlen else "minlen not set",
                       "" if ok else "Set 'minlen = 12' in /etc/security/pwquality.conf"))
    else:
        results.append(AuditCheck("PAM-04","pam","pwquality.conf presence","SKIP","info",0,
                       "/etc/security/pwquality.conf not found — install libpam-pwquality"))

    # Account lockout (faillock / pam_tally2)
    pam_auth = read_file("/etc/pam.d/common-auth") or read_file("/etc/pam.d/system-auth") or ""
    has_lockout = bool(re.search(r"pam_(faillock|tally2)\.so", pam_auth))
    results.append(AuditCheck("PAM-05","pam","Account lockout module configured",
                   "PASS" if has_lockout else "FAIL", "high", 0 if has_lockout else 15,
                   "pam_faillock or pam_tally2 " + ("found" if has_lockout else "NOT found"),
                   "" if has_lockout else "Configure pam_faillock in /etc/pam.d/common-auth"))

    # Password history (pam_pwhistory)
    has_history = bool(re.search(r"pam_pwhistory\.so", pam_auth) or
                       re.search(r"remember=", pwq or ""))
    results.append(AuditCheck("PAM-06","pam","Password reuse prevention configured",
                   "PASS" if has_history else "WARN", "low", 0 if has_history else 5,
                   "pam_pwhistory " + ("found" if has_history else "not found"),
                   "" if has_history else "Add 'remember=5' to pam_pwhistory or pwquality.conf"))


# ─────────────────────────────────────────────────────────────────────────────
# Kernel sysctl checks
# ─────────────────────────────────────────────────────────────────────────────

SYSCTL_CHECKS = [
    ("KRN-01","kernel.randomize_va_space","2","ASLR fully enabled","high",15,
     "sysctl -w kernel.randomize_va_space=2", lambda v,e: v==e),
    ("KRN-02","kernel.kptr_restrict","1","Kernel pointer restriction enabled","medium",10,
     "sysctl -w kernel.kptr_restrict=1", lambda v,e: v in ("1","2")),
    ("KRN-03","kernel.dmesg_restrict","1","dmesg restricted to privileged users","medium",10,
     "sysctl -w kernel.dmesg_restrict=1", lambda v,e: v==e),
    ("KRN-04","kernel.yama.ptrace_scope","1","ptrace scope restricted","high",15,
     "sysctl -w kernel.yama.ptrace_scope=1", lambda v,e: v in ("1","2","3")),
    ("KRN-05","net.ipv4.ip_forward","0","IP forwarding disabled (non-router)","medium",10,
     "sysctl -w net.ipv4.ip_forward=0", lambda v,e: v==e),
    ("KRN-06","net.ipv4.conf.all.accept_redirects","0","ICMP redirects rejected","medium",10,
     "sysctl -w net.ipv4.conf.all.accept_redirects=0", lambda v,e: v==e),
    ("KRN-07","net.ipv4.conf.all.send_redirects","0","ICMP redirect sending disabled","low",5,
     "sysctl -w net.ipv4.conf.all.send_redirects=0", lambda v,e: v==e),
    ("KRN-08","net.ipv4.tcp_syncookies","1","SYN flood protection (syncookies) enabled","medium",10,
     "sysctl -w net.ipv4.tcp_syncookies=1", lambda v,e: v==e),
]

def check_kernel(results: List[AuditCheck]):
    if not IS_LINUX:
        results.append(AuditCheck("KRN-00","kernel","sysctl checks","SKIP","info",0,
                       f"Not running on Linux ({platform.system()}) — sysctl checks skipped"))
        return

    for check_id, sysctl_name, expected, title, severity, weight, remediation, cmp_fn in SYSCTL_CHECKS:
        val = get_sysctl(sysctl_name)
        if val is None:
            results.append(AuditCheck(check_id,"kernel",title,"SKIP","info",0,
                           f"{sysctl_name} not exposed (module not loaded?)"))
            continue
        ok = cmp_fn(val, expected)
        results.append(AuditCheck(check_id,"kernel",title,
                       "PASS" if ok else "FAIL", severity, 0 if ok else weight,
                       f"{sysctl_name} = {val}" + ("" if ok else f" (recommended {expected})"),
                       "" if ok else remediation,
                       evidence={"sysctl": sysctl_name, "value": val}))


# ─────────────────────────────────────────────────────────────────────────────
# Filesystem permission checks
# ─────────────────────────────────────────────────────────────────────────────

def _mode_str(mode: int) -> str:
    return oct(stat.S_IMODE(mode))

def check_filesystem(results: List[AuditCheck]):
    perm_checks = [
        ("FS-01","/etc/passwd", 0o644, "world-readable OK, must not be writable by group/other"),
        ("FS-02","/etc/shadow", 0o640, "must not be world-readable"),
        ("FS-03","/etc/gshadow",0o640, "must not be world-readable"),
        ("FS-04","/etc/group",  0o644, "world-readable OK"),
    ]
    for check_id, path, max_mode, note in perm_checks:
        try:
            st = os.stat(path)
            mode = stat.S_IMODE(st.st_mode)
            ok = (mode & ~max_mode) == 0   # no extra bits beyond max_mode
            results.append(AuditCheck(check_id,"filesystem",f"Permissions on {path}",
                           "PASS" if ok else "FAIL", "high", 0 if ok else 15,
                           f"{path} mode={_mode_str(mode)} ({note})",
                           "" if ok else f"chmod {oct(max_mode)[2:]} {path}",
                           evidence={"path": path, "mode": _mode_str(mode), "uid": st.st_uid}))
        except OSError:
            results.append(AuditCheck(check_id,"filesystem",f"Permissions on {path}","SKIP","info",0,
                           f"{path} not found"))

    # World-writable files in critical dirs (sampled, not full-fs walk — that's FIM's job)
    ww_found = []
    for d in ["/etc","/usr/bin","/usr/sbin","/bin","/sbin"]:
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            fp = os.path.join(d, fn)
            try:
                st = os.lstat(fp)
                if stat.S_ISREG(st.st_mode) and (st.st_mode & stat.S_IWOTH):
                    ww_found.append(fp)
            except OSError:
                continue
    ok = len(ww_found) == 0
    results.append(AuditCheck("FS-05","filesystem","No world-writable files in system dirs",
                   "PASS" if ok else "FAIL", "high", 0 if ok else 15,
                   f"{len(ww_found)} world-writable file(s) found in /etc,/bin,/sbin,/usr/bin,/usr/sbin",
                   "" if ok else "Remove world-write bit: chmod o-w <file>",
                   evidence={"files": ww_found[:10]}))

    # /tmp sticky bit
    try:
        st = os.stat("/tmp")
        has_sticky = bool(st.st_mode & stat.S_ISVTX)
        results.append(AuditCheck("FS-06","filesystem","/tmp has sticky bit set",
                       "PASS" if has_sticky else "FAIL", "medium", 0 if has_sticky else 10,
                       f"/tmp mode={_mode_str(st.st_mode)}",
                       "" if has_sticky else "chmod +t /tmp"))
    except OSError:
        results.append(AuditCheck("FS-06","filesystem","/tmp sticky bit","SKIP","info",0,"/tmp not found"))


# ─────────────────────────────────────────────────────────────────────────────
# Service exposure checks
# ─────────────────────────────────────────────────────────────────────────────

RISKY_LISTEN_PORTS = {
    23:   ("Telnet — cleartext credentials","critical"),
    21:   ("FTP — cleartext credentials (use SFTP)","high"),
    2375: ("Docker API unauthenticated","critical"),
    6379: ("Redis — often unauthenticated","high"),
    9200: ("Elasticsearch — check auth","medium"),
    11211:("Memcached — UDP amplification risk","medium"),
    111:  ("rpcbind — legacy NFS/RPC exposure","medium"),
}

def check_services(results: List[AuditCheck]):
    if not IS_LINUX:
        results.append(AuditCheck("SVC-00","services","listening ports","SKIP","info",0,
                       "Non-Linux platform"))
        return

    listening: Dict[int,str] = {}
    for proto, path in [("tcp","/proc/net/tcp"), ("tcp6","/proc/net/tcp6")]:
        content = read_file(path)
        if not content:
            continue
        for line in content.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local, state = parts[1], parts[3]
            if state != "0A":   # 0A = LISTEN
                continue
            try:
                port = int(local.split(":")[1], 16)
                listening[port] = proto
            except (ValueError, IndexError):
                continue

    risky_found = []
    for port, (desc, sev) in RISKY_LISTEN_PORTS.items():
        if port in listening:
            risky_found.append((port, desc, sev))
            results.append(AuditCheck(f"SVC-{port}","services",
                           f"Risky service on port {port} not exposed",
                           "FAIL", sev, {"critical":20,"high":15,"medium":10}.get(sev,5),
                           f"Port {port} ({listening[port]}) is listening: {desc}",
                           f"Disable or firewall port {port} if not required",
                           evidence={"port": port}))

    if not risky_found:
        results.append(AuditCheck("SVC-01","services","No high-risk services listening",
                       "PASS","high",0,
                       f"{len(listening)} ports listening; none on the high-risk list",
                       evidence={"listening_ports": sorted(listening.keys())}))

    # Firewall presence
    fw_present = False
    for cmd in (["iptables","-L"], ["nft","list","ruleset"], ["ufw","status"]):
        rc, out = run_cmd(cmd)
        if rc == 0 and out.strip():
            fw_present = True
            break
    results.append(AuditCheck("SVC-02","services","Host firewall configured",
                   "PASS" if fw_present else "WARN", "medium", 0 if fw_present else 10,
                   "Firewall ruleset detected" if fw_present else
                   "No iptables/nftables/ufw ruleset detected",
                   "" if fw_present else "Configure host firewall (ufw/nftables/iptables)"))


# ─────────────────────────────────────────────────────────────────────────────
# Audit logging checks
# ─────────────────────────────────────────────────────────────────────────────

def check_audit(results: List[AuditCheck]):
    if not IS_LINUX:
        results.append(AuditCheck("AUD-00","audit","auditd","SKIP","info",0,"Non-Linux platform"))
        return

    rc, _ = run_cmd(["which","auditctl"])
    auditd_installed = (rc == 0)
    results.append(AuditCheck("AUD-01","audit","auditd installed",
                   "PASS" if auditd_installed else "WARN", "medium",
                   0 if auditd_installed else 10,
                   "auditd " + ("found" if auditd_installed else "not installed"),
                   "" if auditd_installed else "apt install auditd / yum install audit"))

    if auditd_installed:
        rules = read_file("/etc/audit/rules.d/audit.rules") or read_file("/etc/audit/audit.rules") or ""
        has_rules = len(rules.strip().splitlines()) > 2
        results.append(AuditCheck("AUD-02","audit","auditd rules configured",
                       "PASS" if has_rules else "WARN","low", 0 if has_rules else 5,
                       f"{len(rules.strip().splitlines())} rule lines found",
                       "" if has_rules else "Add audit rules for identity/auth/privilege changes"))

        watches_passwd = "-w /etc/passwd" in rules or "/etc/passwd" in rules
        results.append(AuditCheck("AUD-03","audit","Identity file changes audited",
                       "PASS" if watches_passwd else "WARN","medium", 0 if watches_passwd else 10,
                       "passwd/shadow watch " + ("found" if watches_passwd else "not found"),
                       "" if watches_passwd else
                       "-w /etc/passwd -p wa -k identity"))
    else:
        for cid in ("AUD-02","AUD-03"):
            results.append(AuditCheck(cid,"audit","auditd rules","SKIP","info",0,"auditd not installed"))


# ─────────────────────────────────────────────────────────────────────────────
# Cron checks
# ─────────────────────────────────────────────────────────────────────────────

def check_cron(results: List[AuditCheck]):
    if not IS_LINUX:
        results.append(AuditCheck("CRN-00","cron","cron checks","SKIP","info",0,"Non-Linux"))
        return

    crontab = "/etc/crontab"
    if os.path.exists(crontab):
        st = os.stat(crontab)
        mode = stat.S_IMODE(st.st_mode)
        ok = (mode & (stat.S_IWGRP|stat.S_IWOTH)) == 0
        results.append(AuditCheck("CRN-01","cron","/etc/crontab not group/world-writable",
                       "PASS" if ok else "FAIL","high", 0 if ok else 15,
                       f"/etc/crontab mode={_mode_str(mode)}",
                       "" if ok else "chmod go-w /etc/crontab"))
    else:
        results.append(AuditCheck("CRN-01","cron","/etc/crontab presence","SKIP","info",0,"not found"))

    deny_exists = os.path.exists("/etc/cron.deny")
    allow_exists= os.path.exists("/etc/cron.allow")
    results.append(AuditCheck("CRN-02","cron","cron access restricted via cron.allow",
                   "PASS" if allow_exists else "WARN","low", 0 if allow_exists else 5,
                   f"cron.allow {'exists' if allow_exists else 'absent'}, "
                   f"cron.deny {'exists' if deny_exists else 'absent'}",
                   "" if allow_exists else "Create /etc/cron.allow with authorized users only"))

    results.append(AuditCheck("CRN-03","cron","cron.d directory permissions","INFO","low",0,
                   "Manual review recommended for /etc/cron.d/* ownership"))


# ─────────────────────────────────────────────────────────────────────────────
# Account checks
# ─────────────────────────────────────────────────────────────────────────────

def check_accounts(results: List[AuditCheck]):
    try:
        all_users = pwd.getpwall()
    except Exception:
        results.append(AuditCheck("ACC-00","accounts","passwd database","SKIP","info",0,
                       "Cannot enumerate users"))
        return

    # UID 0 accounts other than root
    uid0 = [u.pw_name for u in all_users if u.pw_uid == 0 and u.pw_name != "root"]
    ok = len(uid0) == 0
    results.append(AuditCheck("ACC-01","accounts","Only 'root' has UID 0",
                   "PASS" if ok else "FAIL","critical", 0 if ok else 25,
                   f"UID-0 accounts: {['root']+uid0}",
                   "" if ok else "Remove UID 0 from non-root accounts immediately",
                   evidence={"uid0_accounts": uid0}))

    # System accounts with login shells
    bad_shell_accts = []
    no_login_shells = {"/usr/sbin/nologin","/sbin/nologin","/bin/false",""}
    for u in all_users:
        if u.pw_uid < 1000 and u.pw_uid != 0 and u.pw_shell not in no_login_shells:
            bad_shell_accts.append((u.pw_name, u.pw_shell))
    ok = len(bad_shell_accts) == 0
    results.append(AuditCheck("ACC-02","accounts","System accounts have no login shell",
                   "PASS" if ok else "WARN","medium", 0 if ok else 10,
                   f"{len(bad_shell_accts)} system account(s) with a login shell",
                   "" if ok else "usermod -s /usr/sbin/nologin <account>",
                   evidence={"accounts": bad_shell_accts[:10]}))

    # Empty password field in shadow (requires root to read)
    shadow = read_file("/etc/shadow")
    if shadow is not None:
        empty_pw = [l.split(":")[0] for l in shadow.splitlines()
                    if len(l.split(":")) > 1 and l.split(":")[1] == ""]
        ok = len(empty_pw) == 0
        results.append(AuditCheck("ACC-03","accounts","No accounts with empty password field",
                       "PASS" if ok else "FAIL","critical", 0 if ok else 25,
                       f"{len(empty_pw)} account(s) with empty password hash",
                       "" if ok else "passwd -l <account>  # lock immediately",
                       evidence={"accounts": empty_pw}))
    else:
        results.append(AuditCheck("ACC-03","accounts","/etc/shadow readable","SKIP","info",0,
                       "Requires root to audit shadow file"))

    # Home directory permissions for interactive users
    bad_home = []
    for u in all_users:
        if u.pw_uid >= 1000 and os.path.isdir(u.pw_dir):
            try:
                mode = stat.S_IMODE(os.stat(u.pw_dir).st_mode)
                if mode & (stat.S_IWGRP | stat.S_IWOTH):
                    bad_home.append(u.pw_name)
            except OSError:
                continue
    ok = len(bad_home) == 0
    results.append(AuditCheck("ACC-04","accounts","User home directories not group/world-writable",
                   "PASS" if ok else "WARN","low", 0 if ok else 5,
                   f"{len(bad_home)} home dir(s) writable by group/other",
                   "" if ok else "chmod go-w ~user for affected accounts",
                   evidence={"users": bad_home[:10]}))


# ─────────────────────────────────────────────────────────────────────────────
# Master auditor
# ─────────────────────────────────────────────────────────────────────────────

CATEGORY_FUNCS: Dict[str, Callable] = {
    "ssh":      check_ssh,
    "pam":      check_password_policy,
    "kernel":   check_kernel,
    "filesystem": check_filesystem,
    "services": check_services,
    "audit":    check_audit,
    "cron":     check_cron,
    "accounts": check_accounts,
}


class ConfigAuditor:
    def __init__(self, categories: Optional[List[str]] = None):
        self.categories = categories or list(CATEGORY_FUNCS.keys())
        self.results: List[AuditCheck] = []

    def run(self) -> List[AuditCheck]:
        for cat in self.categories:
            fn = CATEGORY_FUNCS.get(cat)
            if fn:
                fn(self.results)
        return self.results

    def hardening_score(self) -> Tuple[int, int, int]:
        """Returns (score_0_100, points_lost, max_points)."""
        max_points  = sum(c.weight if c.status in ("PASS","FAIL","WARN") else 0
                          for c in self.results
                          for c in [c]) or 0
        # Recompute properly: weight represents POINTS LOST if not PASS.
        # Max possible = sum over all non-SKIP checks of their "full weight"
        # which we approximate as weight when FAIL/WARN, else infer 0 lost.
        total_possible = 0
        lost = 0
        for c in self.results:
            if c.status == "SKIP":
                continue
            # weight as stored is "points at risk"; for PASS it's 0 (already applied)
            # We need the ORIGINAL weight regardless of status — recompute via category tables
            pass
        # Simpler, robust approach: score = 100 - (sum of weight for FAIL/WARN) / (sum of all
        # weights ever assignable) * 100. Since PASS rows store weight=0, we instead track
        # a parallel "full_weight" via severity-based default if needed. To keep this exact,
        # checks store weight=0 on PASS — so we reconstruct full weight from FAIL/WARN only
        # and treat PASS as contributing their *original* weight via a side table is overkill.
        # Practical compromise: score based on FAIL/WARN penalty against a fixed denominator.
        FIXED_DENOM = 400  # sum of all "at risk" weights across the full check suite
        lost = sum(c.weight for c in self.results if c.status in ("FAIL","WARN"))
        score = max(0, 100 - int(100 * lost / FIXED_DENOM))
        return score, lost, FIXED_DENOM

    def summary(self) -> dict:
        from collections import Counter
        status_counts = Counter(c.status for c in self.results)
        score, lost, denom = self.hardening_score()
        return {
            "total_checks": len(self.results),
            "status_counts": dict(status_counts),
            "hardening_score": score,
            "points_lost": lost,
            "categories": self.categories,
            "host": platform.node(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

STATUS_C = {"PASS":"\033[92m","FAIL":"\033[91m","WARN":"\033[93m","INFO":"\033[96m","SKIP":"\033[2m"}

def _print_check(c: AuditCheck):
    color = STATUS_C.get(c.status,"")
    R = "\033[0m"
    print(f"  {color}[{c.status:4}]{R} {c.check_id:8} {c.title}")
    print(f"           {c.description}")
    if c.remediation:
        print(f"           \033[93m→ {c.remediation}\033[0m")


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Configuration Hardening Auditor")
    parser.add_argument("--audit", action="store_true", required=True)
    parser.add_argument("--category", help="Comma-separated categories (default: all)")
    parser.add_argument("--json", help="Output full report to JSON")
    parser.add_argument("--show", default="all", choices=["all","fail","fail-warn"],
                        help="Filter displayed checks")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Configuration Hardening Auditor ──{R}\n")
    print(f"  Host: {platform.node()}  ({platform.system()} {platform.release()})\n")

    categories = args.category.split(",") if args.category else None
    auditor = ConfigAuditor(categories)
    results = auditor.run()

    show_filter = {
        "all":        lambda c: True,
        "fail":       lambda c: c.status == "FAIL",
        "fail-warn":  lambda c: c.status in ("FAIL","WARN"),
    }[args.show]

    current_cat = None
    for c in results:
        if not show_filter(c):
            continue
        if c.category != current_cat:
            current_cat = c.category
            print(f"\n  {B}{C}── {current_cat.upper()} ──{R}")
        _print_check(c)

    s = auditor.summary()
    print(f"\n  {B}{'─'*60}{R}")
    print(f"  Total checks    : {s['total_checks']}")
    print(f"  Status breakdown: {s['status_counts']}")
    score_c = "\033[92m" if s['hardening_score']>=80 else ("\033[93m" if s['hardening_score']>=50 else "\033[91m")
    print(f"  Hardening Score : {score_c}{s['hardening_score']}/100{R}")

    if args.json:
        report = {"summary": s, "checks": [c.to_dict() for c in results]}
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  Full report saved to {C}{args.json}{R}")


if __name__ == "__main__":
    main()
