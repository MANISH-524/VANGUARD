#!/usr/bin/env python3
"""
Vanguard-OOB :: Hypervisor API
================================
Out-of-band hypervisor control layer.  Wraps both VBoxManage (VirtualBox) and
the Proxmox REST API to perform:

  - Network isolation  (switch VM NIC to quarantine VLAN 30)
  - Memory dump        (capture live RAM to forensics_archive/)
  - Snapshot restore   (revert to clean golden image)
  - Headless reboot    (restart in sandbox environment)

All operations bypass the guest OS entirely - they execute at the hypervisor
layer and cannot be tampered with by malware running inside the VM.

Usage:
    Instantiate HypervisorAPI(config) and call the high-level methods:
        api.isolate_vm(vm_id)
        api.dump_memory(vm_id)
        api.restore_snapshot(vm_id)
        api.boot_headless(vm_id)
        api.full_incident_response(vm_id)
"""

import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logger = logging.getLogger("vanguard.hypervisor")


@dataclass
class VBoxConfig:
    """Configuration for a VirtualBox-managed environment."""
    vboxmanage_path: str = "/usr/bin/VBoxManage"   # or C:\Program Files\Oracle\VirtualBox\VBoxManage.exe
    quarantine_nic:  str = "HostOnly Adapter #3"    # NIC profile mapped to VLAN 30
    golden_snapshot: str = "GoldenImage-Clean"      # Name of the clean baseline snapshot
    sandbox_nic:     str = "HostOnly Adapter #4"    # NIC profile for sandbox VLAN 40
    headless_mode:   bool = True


@dataclass
class ProxmoxConfig:
    """Configuration for a Proxmox-managed environment."""
    api_host:        str = "https://proxmox.local:8006"
    api_user:        str = "vanguard@pam"
    api_token_name:  str = "vanguard-token"
    api_token_value: str = "CHANGEME-TOKEN-UUID"
    node:            str = "pve"
    quarantine_vlan: int = 30
    sandbox_vlan:    int = 40
    golden_snapshot: str = "GoldenImage-Clean"
    verify_ssl:      bool = False


@dataclass
class HypervisorConfig:
    """Top-level config selecting the active backend."""
    backend:         str = "vbox"          # "vbox" | "proxmox"
    forensics_dir:   str = "/opt/vanguard-oob/host_control_plane/forensics_archive"
    vm_name_map:     Dict[str, str] = field(default_factory=dict)  # logical_id -> hypervisor_name
    vbox:            VBoxConfig = field(default_factory=VBoxConfig)
    proxmox:         ProxmoxConfig = field(default_factory=ProxmoxConfig)

    @classmethod
    def from_file(cls, path: str) -> "HypervisorConfig":
        with open(path) as f:
            data = json.load(f)
        cfg = cls()
        cfg.backend       = data.get("backend", "vbox")
        cfg.forensics_dir = data.get("forensics_dir", cfg.forensics_dir)
        cfg.vm_name_map   = data.get("vm_name_map", {})
        if "vbox" in data:
            v = data["vbox"]
            cfg.vbox = VBoxConfig(**{k: v[k] for k in v if hasattr(VBoxConfig, k)})
        if "proxmox" in data:
            p = data["proxmox"]
            cfg.proxmox = ProxmoxConfig(**{k: p[k] for k in p if hasattr(ProxmoxConfig, k)})
        return cfg


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------

@dataclass
class HypervisorResult:
    success:   bool
    operation: str
    vm_id:     str
    message:   str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details:   dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "success":   self.success,
            "operation": self.operation,
            "vm_id":     self.vm_id,
            "message":   self.message,
            "timestamp": self.timestamp,
            "details":   self.details,
        }


# ---------------------------------------------------------------------------
# VirtualBox Backend
# ---------------------------------------------------------------------------

class VBoxBackend:
    def __init__(self, config: VBoxConfig, forensics_dir: str, vm_name_map: Dict[str, str]):
        self.cfg          = config
        self.forensics_dir = Path(forensics_dir)
        self.vm_name_map  = vm_name_map
        self.forensics_dir.mkdir(parents=True, exist_ok=True)

    def _resolve(self, vm_id: str) -> str:
        """Resolve logical VM ID to VBoxManage VM name."""
        return self.vm_name_map.get(vm_id, vm_id)

    def _run(self, args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Execute a VBoxManage command and return (returncode, stdout, stderr)."""
        cmd = [self.cfg.vboxmanage_path] + args
        logger.debug("VBox cmd: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except FileNotFoundError:
            return -1, "", f"VBoxManage not found at {self.cfg.vboxmanage_path}"
        except subprocess.TimeoutExpired:
            return -1, "", "VBoxManage command timed out"

    def vm_exists(self, vm_id: str) -> bool:
        name = self._resolve(vm_id)
        rc, out, _ = self._run(["showvminfo", name, "--machinereadable"])
        return rc == 0

    def isolate_network(self, vm_id: str) -> HypervisorResult:
        """Switch NIC 1 to the quarantine VLAN 30 adapter (no internet)."""
        name = self._resolve(vm_id)
        # Disconnect NIC 1 from current network
        rc1, _, err1 = self._run(["controlvm", name, "nic1", "null"])
        # Reconnect to host-only quarantine adapter
        rc2, _, err2 = self._run([
            "controlvm", name,
            "nic1", "hostonly", self.cfg.quarantine_nic,
        ])
        success = rc1 == 0 and rc2 == 0
        msg = "NIC isolated to quarantine VLAN 30" if success else f"Isolation failed: {err1} | {err2}"
        logger.info("[%s] isolate_network -> %s", vm_id, msg)
        return HypervisorResult(
            success   = success,
            operation = "isolate_network",
            vm_id     = vm_id,
            message   = msg,
            details   = {"nic": self.cfg.quarantine_nic, "errors": [err1, err2]},
        )

    def dump_memory(self, vm_id: str) -> HypervisorResult:
        """Capture a live memory dump to the forensics archive."""
        name     = self._resolve(vm_id)
        ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = self.forensics_dir / f"{vm_id}_{ts}.core"
        rc, stdout, stderr = self._run(
            ["debugvm", name, "dumpvmcore", "--filename", str(out_path)],
            timeout=300,
        )
        success  = rc == 0 and out_path.exists()
        file_sz  = out_path.stat().st_size if out_path.exists() else 0
        msg = f"Memory dump saved: {out_path} ({file_sz:,} bytes)" if success else f"Dump failed: {stderr}"
        logger.info("[%s] dump_memory -> %s", vm_id, msg)
        return HypervisorResult(
            success   = success,
            operation = "dump_memory",
            vm_id     = vm_id,
            message   = msg,
            details   = {"path": str(out_path), "size_bytes": file_sz, "error": stderr},
        )

    def restore_snapshot(self, vm_id: str) -> HypervisorResult:
        """Power off VM and restore to golden clean snapshot."""
        name    = self._resolve(vm_id)
        # Step 1: Power off (ACPI shutdown is unreliable for compromised VMs)
        self._run(["controlvm", name, "poweroff"])
        time.sleep(3)
        # Step 2: Restore snapshot
        rc, stdout, stderr = self._run(
            ["snapshot", name, "restore", self.cfg.golden_snapshot],
            timeout=120,
        )
        success = rc == 0
        msg = f"Restored to snapshot '{self.cfg.golden_snapshot}'" if success else f"Restore failed: {stderr}"
        logger.info("[%s] restore_snapshot -> %s", vm_id, msg)
        return HypervisorResult(
            success   = success,
            operation = "restore_snapshot",
            vm_id     = vm_id,
            message   = msg,
            details   = {"snapshot": self.cfg.golden_snapshot, "error": stderr},
        )

    def boot_headless(self, vm_id: str, sandbox: bool = True) -> HypervisorResult:
        """Start VM headless. Optionally switch to sandbox VLAN 40 for validation."""
        name = self._resolve(vm_id)
        if sandbox:
            # Switch NIC to sandbox VLAN before boot
            self._run(["modifyvm", name, "--nic1", "hostonly",
                        "--hostonlyadapter1", self.cfg.sandbox_nic])

        rc, stdout, stderr = self._run(
            ["startvm", name, "--type", "headless"],
            timeout=60,
        )
        success = rc == 0
        msg = f"VM started headless (sandbox={sandbox})" if success else f"Boot failed: {stderr}"
        logger.info("[%s] boot_headless -> %s", vm_id, msg)
        return HypervisorResult(
            success   = success,
            operation = "boot_headless",
            vm_id     = vm_id,
            message   = msg,
            details   = {"sandbox": sandbox, "nic": self.cfg.sandbox_nic if sandbox else "unchanged", "error": stderr},
        )

    def get_vm_state(self, vm_id: str) -> str:
        """Return current VM state string (running, poweroff, saved, etc.)."""
        name = self._resolve(vm_id)
        rc, out, _ = self._run(["showvminfo", name, "--machinereadable"])
        if rc != 0:
            return "unknown"
        for line in out.splitlines():
            if line.startswith("VMState="):
                return line.split("=", 1)[1].strip().strip('"')
        return "unknown"

    def block_network(self, vm_id: str) -> HypervisorResult:
        """
        Hard kill-switch: fully disconnect NIC 1 (link down). Used as an
        immediate containment step the instant a ransomware crypto-spike is
        seen, BEFORE the slower quarantine-VLAN move completes. Stops
        exfiltration and C2 in milliseconds.
        """
        name = self._resolve(vm_id)
        rc, _, err = self._run(["controlvm", name, "nic1", "null"])
        success = rc == 0
        msg = "NIC link severed (hard block)" if success else f"Block failed: {err}"
        logger.warning("[%s] block_network -> %s", vm_id, msg)
        return HypervisorResult(
            success=success, operation="block_network", vm_id=vm_id,
            message=msg, details={"error": err})


# ---------------------------------------------------------------------------
# Proxmox Backend
# ---------------------------------------------------------------------------

class ProxmoxBackend:
    def __init__(self, config: ProxmoxConfig, forensics_dir: str, vm_name_map: Dict[str, str]):
        self.cfg           = config
        self.forensics_dir = Path(forensics_dir)
        self.vm_name_map   = vm_name_map
        self.forensics_dir.mkdir(parents=True, exist_ok=True)
        self._session      = requests.Session()
        self._session.verify = config.verify_ssl
        self._session.headers.update({
            "Authorization": f"PVEAPIToken={config.api_user}!{config.api_token_name}={config.api_token_value}",
            "Content-Type": "application/json",
        })

    def _resolve(self, vm_id: str) -> str:
        """Resolve logical VM ID to Proxmox VMID (numeric string)."""
        return self.vm_name_map.get(vm_id, vm_id)

    def _url(self, path: str) -> str:
        return f"{self.cfg.api_host}/api2/json/nodes/{self.cfg.node}{path}"

    def _get(self, path: str) -> Tuple[bool, Any]:
        try:
            r = self._session.get(self._url(path), timeout=15)
            r.raise_for_status()
            return True, r.json().get("data")
        except Exception as e:
            return False, str(e)

    def _post(self, path: str, data: dict = None) -> Tuple[bool, Any]:
        try:
            r = self._session.post(self._url(path), json=data or {}, timeout=30)
            r.raise_for_status()
            return True, r.json().get("data")
        except Exception as e:
            return False, str(e)

    def _put(self, path: str, data: dict) -> Tuple[bool, Any]:
        try:
            r = self._session.put(self._url(path), json=data, timeout=30)
            r.raise_for_status()
            return True, r.json().get("data")
        except Exception as e:
            return False, str(e)

    def isolate_network(self, vm_id: str) -> HypervisorResult:
        """Move VM NIC to quarantine VLAN 30 via Proxmox API."""
        vmid    = self._resolve(vm_id)
        # Get current network config
        ok, current = self._get(f"/qemu/{vmid}/config")
        if not ok:
            return HypervisorResult(False, "isolate_network", vm_id,
                                    f"Config fetch failed: {current}")
        # Patch net0 to quarantine VLAN 30 (tag=30, no bridge internet access)
        net_value = f"virtio,bridge=vmbr0,tag={self.cfg.quarantine_vlan},firewall=1"
        ok2, resp = self._put(f"/qemu/{vmid}/config", {"net0": net_value})
        success   = ok2
        msg = f"NIC moved to VLAN {self.cfg.quarantine_vlan}" if success else f"Failed: {resp}"
        logger.info("[%s] Proxmox isolate_network -> %s", vm_id, msg)
        return HypervisorResult(
            success   = success,
            operation = "isolate_network",
            vm_id     = vm_id,
            message   = msg,
            details   = {"vlan": self.cfg.quarantine_vlan, "vmid": vmid},
        )

    def dump_memory(self, vm_id: str) -> HypervisorResult:
        """
        Proxmox doesn't have a native 'dump RAM to host' API equivalent to VBox debugvm.
        We instead trigger a live backup of the VM (which includes RAM state via QEMU
        savevm semantics) and retrieve the resulting archive.
        """
        vmid = self._resolve(vm_id)
        ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # Create a vzdump backup with RAM state
        ok, task = self._post(f"/vzdump", {
            "vmid":    vmid,
            "node":    self.cfg.node,
            "mode":    "snapshot",
            "compress": "zstd",
            "notes-template": f"vanguard-forensic-{ts}",
        })
        msg = f"Proxmox RAM backup task queued: {task}" if ok else f"Backup failed: {task}"
        logger.info("[%s] Proxmox dump_memory -> %s", vm_id, msg)
        return HypervisorResult(
            success   = ok,
            operation = "dump_memory",
            vm_id     = vm_id,
            message   = msg,
            details   = {"task": task, "vmid": vmid, "timestamp": ts},
        )

    def restore_snapshot(self, vm_id: str) -> HypervisorResult:
        """Power off VM and rollback to golden snapshot."""
        vmid = self._resolve(vm_id)
        # Stop VM first
        self._post(f"/qemu/{vmid}/status/stop")
        time.sleep(5)
        # Rollback to golden snapshot
        ok, resp = self._post(
            f"/qemu/{vmid}/snapshot/{self.cfg.golden_snapshot}/rollback"
        )
        success = ok
        msg = f"Rolled back to '{self.cfg.golden_snapshot}'" if success else f"Rollback failed: {resp}"
        logger.info("[%s] Proxmox restore_snapshot -> %s", vm_id, msg)
        return HypervisorResult(
            success   = success,
            operation = "restore_snapshot",
            vm_id     = vm_id,
            message   = msg,
            details   = {"snapshot": self.cfg.golden_snapshot, "vmid": vmid},
        )

    def boot_headless(self, vm_id: str, sandbox: bool = True) -> HypervisorResult:
        """Start VM. Optionally move NIC to sandbox VLAN before starting."""
        vmid = self._resolve(vm_id)
        if sandbox:
            net_value = f"virtio,bridge=vmbr0,tag={self.cfg.sandbox_vlan},firewall=1"
            self._put(f"/qemu/{vmid}/config", {"net0": net_value})

        ok, resp = self._post(f"/qemu/{vmid}/status/start")
        success  = ok
        msg = f"VM started (sandbox VLAN {self.cfg.sandbox_vlan})" if success else f"Start failed: {resp}"
        logger.info("[%s] Proxmox boot_headless -> %s", vm_id, msg)
        return HypervisorResult(
            success   = success,
            operation = "boot_headless",
            vm_id     = vm_id,
            message   = msg,
            details   = {"sandbox": sandbox, "vlan": self.cfg.sandbox_vlan if sandbox else None},
        )

    def get_vm_state(self, vm_id: str) -> str:
        vmid    = self._resolve(vm_id)
        ok, data = self._get(f"/qemu/{vmid}/status/current")
        if ok and data:
            return data.get("status", "unknown")
        return "unknown"

    def block_network(self, vm_id: str) -> HypervisorResult:
        """Hard kill-switch: disconnect the NIC immediately (link=0)."""
        vmid = self._resolve(vm_id)
        ok, current = self._get(f"/qemu/{vmid}/config")
        if not ok:
            return HypervisorResult(False, "block_network", vm_id,
                                    f"Config fetch failed: {current}")
        # Set link_down on net0 — instant containment.
        net_value = "virtio,bridge=vmbr0,link_down=1"
        ok2, resp = self._put(f"/qemu/{vmid}/config", {"net0": net_value})
        msg = "NIC link severed (hard block)" if ok2 else f"Block failed: {resp}"
        logger.warning("[%s] Proxmox block_network -> %s", vm_id, msg)
        return HypervisorResult(
            success=ok2, operation="block_network", vm_id=vm_id,
            message=msg, details={"vmid": vmid})


# ---------------------------------------------------------------------------
# Unified HypervisorAPI facade
# ---------------------------------------------------------------------------

class HypervisorAPI:
    """
    Single facade for all hypervisor OOB actions.
    Automatically selects VBox or Proxmox backend based on config.
    """

    def __init__(self, config: HypervisorConfig):
        self.config = config
        if config.backend == "proxmox":
            self._backend = ProxmoxBackend(
                config.proxmox, config.forensics_dir, config.vm_name_map
            )
        else:
            self._backend = VBoxBackend(
                config.vbox, config.forensics_dir, config.vm_name_map
            )
        logger.info("HypervisorAPI initialized with backend: %s", config.backend)

    # ---- Public API --------------------------------------------------------

    def isolate_vm(self, vm_id: str) -> HypervisorResult:
        """Immediately cut off the VM from the production network (VLAN 30)."""
        logger.warning("[INCIDENT] Isolating VM: %s", vm_id)
        return self._backend.isolate_network(vm_id)

    def block_network(self, vm_id: str) -> HypervisorResult:
        """Hard kill-switch — sever the NIC link instantly (fastest containment)."""
        logger.warning("[INCIDENT] Hard-blocking network for VM: %s", vm_id)
        return self._backend.block_network(vm_id)

    def dump_memory(self, vm_id: str) -> HypervisorResult:
        """Capture RAM to forensics_archive/ for post-mortem analysis."""
        logger.warning("[INCIDENT] Dumping memory for VM: %s", vm_id)
        return self._backend.dump_memory(vm_id)

    def restore_snapshot(self, vm_id: str) -> HypervisorResult:
        """Wipe VM state and restore from the golden clean snapshot."""
        logger.warning("[INCIDENT] Restoring snapshot for VM: %s", vm_id)
        return self._backend.restore_snapshot(vm_id)

    def boot_headless(self, vm_id: str, sandbox: bool = True) -> HypervisorResult:
        """Boot the restored VM headless (optionally in sandbox VLAN 40)."""
        logger.info("[RECOVERY] Booting VM headless: %s (sandbox=%s)", vm_id, sandbox)
        return self._backend.boot_headless(vm_id, sandbox)

    def get_vm_state(self, vm_id: str) -> str:
        """Query real-time VM power state from the hypervisor."""
        return self._backend.get_vm_state(vm_id)

    def full_incident_response(self, vm_id: str) -> List[HypervisorResult]:
        """
        Execute the complete automated incident response sequence:
          1. Isolate network (prevent exfiltration / C2 comms)
          2. Dump memory    (preserve forensic evidence)
          3. Restore snapshot (wipe malware, restore clean disk)
          4. Boot headless  (restart in sandbox for validation)

        Returns list of results for each step.
        """
        logger.critical("[INCIDENT RESPONSE] Starting full IR sequence for VM: %s", vm_id)
        results = []

        step1 = self.isolate_vm(vm_id)
        results.append(step1)
        logger.info("Step 1 - Isolate: %s", step1.message)
        time.sleep(2)   # Allow network state to settle

        step2 = self.dump_memory(vm_id)
        results.append(step2)
        logger.info("Step 2 - Dump memory: %s", step2.message)
        time.sleep(2)

        step3 = self.restore_snapshot(vm_id)
        results.append(step3)
        logger.info("Step 3 - Restore: %s", step3.message)
        time.sleep(5)   # Allow snapshot restore to complete

        step4 = self.boot_headless(vm_id, sandbox=True)
        results.append(step4)
        logger.info("Step 4 - Boot sandbox: %s", step4.message)

        success_count = sum(1 for r in results if r.success)
        logger.critical(
            "[INCIDENT RESPONSE] Sequence complete for %s: %d/4 steps succeeded",
            vm_id, success_count
        )
        return results


# ---------------------------------------------------------------------------
# Default config loader (used by control_center.py)
# ---------------------------------------------------------------------------

def load_default_config(config_path: Optional[str] = None) -> HypervisorConfig:
    """
    Load hypervisor config from file if provided, else return a VBox-based default
    suitable for local development/testing.
    """
    if config_path and Path(config_path).exists():
        return HypervisorConfig.from_file(config_path)

    # Sensible defaults for a single-host VirtualBox environment
    cfg = HypervisorConfig(
        backend       = "vbox",
        forensics_dir = str(Path(__file__).parent / "forensics_archive"),
        vm_name_map   = {
            "prod-vm-01": "VanguardTarget01",
            "prod-vm-02": "VanguardTarget02",
        },
    )
    return cfg
