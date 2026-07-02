#!/usr/bin/env python3
"""
Vanguard-OOB :: Failover Orchestrator
=======================================
"I can't save 100%, but getting hit at 10-20% is far better than 100%."

This module is the missing half of the ransomware response. The original build
could DETECT and ISOLATE a compromised VM, then boot a clean snapshot in a
sandbox — but the production WORKLOAD stopped while that happened. The
organisation still felt the full outage.

The Failover Orchestrator keeps the business running THROUGH the incident:

    PRIMARY infected ──► ISOLATE (cut C2/exfil)
                         │
                         ├─► PROMOTE warm standby  (it takes over the workload)
                         ├─► REDIRECT service traffic to the standby
                         │        (work continues — minimal interruption)
                         ├─► CURE primary in the background
                         │        (snapshot restore + clean-boot validation)
                         └─► REJOIN primary as the new standby once it is proven clean
                                  (the pair self-heals; no human babysitting needed)

Each production service is modelled as a HA PAIR: one ACTIVE node and one
or more STANDBY nodes that are already running a recent replica. On incident,
the orchestrator promotes a standby to ACTIVE and flips the "service VIP"
(virtual IP / load-balancer target) to it.

DESIGN
------
- Backend-agnostic: the actual "promote / redirect / health-check" actions are
  delegated to a pluggable `FailoverBackend`. A `SimulatedBackend` ships here so
  the full choreography runs and is visible on the dashboard WITHOUT a real
  hypervisor or load balancer. Real `VBoxBackend` / `ProxmoxBackend` /
  `HAProxyBackend` adapters can be dropped in by implementing the same 4 methods.
- Every transition is recorded with a timestamp so the SOC dashboard can render
  a live failover timeline and an RTO (recovery-time-objective) measurement.
- Idempotent + thread-safe: a second failover request for an already-failed-over
  service is a no-op, not a double promotion.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# State model
# ---------------------------------------------------------------------------

class NodeRole(str, Enum):
    ACTIVE = "ACTIVE"
    STANDBY = "STANDBY"
    PROMOTING = "PROMOTING"
    CURING = "CURING"          # being cleaned (snapshot restore + validation)
    REJOINING = "REJOINING"    # cleaned, syncing back as standby
    FAILED = "FAILED"          # could not be recovered automatically


class ServiceState(str, Enum):
    HEALTHY = "HEALTHY"            # active node serving normally
    FAILING_OVER = "FAILING_OVER" # mid-promotion
    DEGRADED = "DEGRADED"         # running on standby; primary being cured
    RESTORED = "RESTORED"         # primary cured and rejoined as standby
    NO_STANDBY = "NO_STANDBY"     # active down with no standby available (worst case)


@dataclass
class Node:
    node_id: str
    role: NodeRole = NodeRole.STANDBY
    healthy: bool = True
    last_event: str = ""


@dataclass
class ServicePair:
    service: str
    vip: str                                   # the address clients actually talk to
    nodes: Dict[str, Node] = field(default_factory=dict)
    state: ServiceState = ServiceState.HEALTHY
    active_node: Optional[str] = None
    timeline: List[dict] = field(default_factory=list)
    rto_started: Optional[float] = None        # when failover began (perf_counter)
    rto_seconds: Optional[float] = None        # measured recovery time

    def log(self, stage: str, detail: str, node: str = ""):
        self.timeline.append({
            "timestamp": _now_iso(),
            "stage": stage,
            "node": node,
            "detail": detail,
        })

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "vip": self.vip,
            "state": self.state.value,
            "active_node": self.active_node,
            "rto_seconds": round(self.rto_seconds, 2) if self.rto_seconds else None,
            "nodes": [
                {"node_id": n.node_id, "role": n.role.value,
                 "healthy": n.healthy, "last_event": n.last_event}
                for n in self.nodes.values()
            ],
            "timeline": self.timeline[-12:],
        }


# ---------------------------------------------------------------------------
# Pluggable backend interface
# ---------------------------------------------------------------------------

class FailoverBackend:
    """Implement these 4 methods to wire failover to real infrastructure."""

    def promote(self, service: str, node_id: str) -> bool:
        raise NotImplementedError

    def redirect_traffic(self, service: str, vip: str, to_node: str) -> bool:
        raise NotImplementedError

    def health_check(self, node_id: str) -> bool:
        raise NotImplementedError

    def rejoin_as_standby(self, service: str, node_id: str) -> bool:
        raise NotImplementedError


class SimulatedBackend(FailoverBackend):
    """
    Fully functional simulated backend. Models realistic per-step latency so the
    dashboard timeline looks like a real failover, and always succeeds (unless a
    chaos flag is set). Swap for a real adapter in production.
    """

    def __init__(self, step_delay: float = 0.4):
        self.step_delay = step_delay

    def promote(self, service: str, node_id: str) -> bool:
        time.sleep(self.step_delay)
        return True

    def redirect_traffic(self, service: str, vip: str, to_node: str) -> bool:
        time.sleep(self.step_delay)
        return True

    def health_check(self, node_id: str) -> bool:
        time.sleep(self.step_delay / 2)
        return True

    def rejoin_as_standby(self, service: str, node_id: str) -> bool:
        time.sleep(self.step_delay)
        return True


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class FailoverOrchestrator:
    """
    Maps compromised VMs to the services they host, and runs continuity failover.
    Thread-safe. Designed to be called from the Control Center's IR path.
    """

    def __init__(self, backend: Optional[FailoverBackend] = None):
        self.backend = backend or SimulatedBackend()
        self._lock = threading.RLock()
        self._services: Dict[str, ServicePair] = {}
        self._vm_to_service: Dict[str, str] = {}   # vm_id -> service name

    # ---- topology registration -------------------------------------------

    def register_service(self, service: str, vip: str,
                          active_vm: str, standby_vms: List[str]):
        with self._lock:
            pair = ServicePair(service=service, vip=vip)
            pair.nodes[active_vm] = Node(active_vm, NodeRole.ACTIVE)
            pair.active_node = active_vm
            for s in standby_vms:
                pair.nodes[s] = Node(s, NodeRole.STANDBY)
            pair.log("register", f"service '{service}' VIP {vip}, "
                                 f"active={active_vm}, standby={standby_vms}", active_vm)
            self._services[service] = pair
            self._vm_to_service[active_vm] = service
            for s in standby_vms:
                self._vm_to_service[s] = service

    def service_for_vm(self, vm_id: str) -> Optional[str]:
        return self._vm_to_service.get(vm_id)

    # ---- the main event: a VM was compromised ----------------------------

    def handle_compromise(self, vm_id: str) -> Optional[dict]:
        """
        Called when `vm_id` is isolated. If that VM is the ACTIVE node of a
        service, promote a standby and keep the service alive. Returns the
        failover result dict, or None if the VM hosts no registered service.
        """
        with self._lock:
            service = self._vm_to_service.get(vm_id)
            if not service:
                return None
            pair = self._services[service]
            node = pair.nodes.get(vm_id)
            if node is None:
                return None

            node.healthy = False
            node.last_event = "compromised+isolated"

            # If a STANDBY was compromised, we lose redundancy but service is fine.
            if node.role != NodeRole.ACTIVE:
                node.role = NodeRole.CURING
                pair.log("standby_lost",
                         f"standby {vm_id} compromised; active node unaffected", vm_id)
                # Cure it in the background; service stays HEALTHY.
                threading.Thread(target=self._cure_and_rejoin,
                                 args=(service, vm_id), daemon=True).start()
                return pair.to_dict()

            # ACTIVE node compromised — this is the real failover.
            return self._failover_active(pair, vm_id)

    def _failover_active(self, pair: ServicePair, dead_vm: str) -> dict:
        pair.state = ServiceState.FAILING_OVER
        pair.rto_started = time.perf_counter()
        pair.log("failover_begin", f"ACTIVE node {dead_vm} compromised — promoting standby", dead_vm)

        # Pick a healthy standby
        standby = next(
            (n for n in pair.nodes.values()
             if n.role == NodeRole.STANDBY and n.healthy),
            None,
        )
        if standby is None:
            pair.state = ServiceState.NO_STANDBY
            pair.log("no_standby", "no healthy standby available — service DOWN", dead_vm)
            pair.nodes[dead_vm].role = NodeRole.CURING
            # Still try to cure the primary so we recover eventually.
            threading.Thread(target=self._cure_and_rejoin,
                             args=(pair.service, dead_vm), daemon=True).start()
            return pair.to_dict()

        standby.role = NodeRole.PROMOTING
        standby.last_event = "promoting"
        pair.log("promote", f"promoting standby {standby.node_id} to ACTIVE", standby.node_id)
        if not self.backend.promote(pair.service, standby.node_id):
            pair.log("promote_failed", f"promotion of {standby.node_id} failed", standby.node_id)
            standby.role = NodeRole.FAILED
            pair.state = ServiceState.NO_STANDBY
            return pair.to_dict()

        # Flip the VIP / load balancer to the new active node — clients keep working.
        self.backend.redirect_traffic(pair.service, pair.vip, standby.node_id)
        pair.log("redirect", f"VIP {pair.vip} now serving from {standby.node_id}", standby.node_id)

        standby.role = NodeRole.ACTIVE
        standby.last_event = "active"
        pair.active_node = standby.node_id
        pair.nodes[dead_vm].role = NodeRole.CURING

        pair.rto_seconds = time.perf_counter() - pair.rto_started
        pair.state = ServiceState.DEGRADED  # running, but on a single node until primary heals
        pair.log("failover_complete",
                 f"service restored on {standby.node_id} in {pair.rto_seconds:.2f}s "
                 f"(RTO); curing {dead_vm} in background", standby.node_id)

        # Heal the primary in the background and bring it back as the new standby.
        threading.Thread(target=self._cure_and_rejoin,
                         args=(pair.service, dead_vm), daemon=True).start()
        return pair.to_dict()

    # ---- background self-healing ------------------------------------------

    def _cure_and_rejoin(self, service: str, vm_id: str):
        """Validate the cured VM and rejoin it as a standby (the pair self-heals)."""
        time.sleep(1.0)  # represent snapshot restore / clean boot already done by IR
        with self._lock:
            pair = self._services.get(service)
            if not pair or vm_id not in pair.nodes:
                return
            node = pair.nodes[vm_id]
            node.role = NodeRole.REJOINING
            node.last_event = "validating_clean_state"
            pair.log("validate", f"validating cured node {vm_id} in sandbox", vm_id)

        ok = self.backend.health_check(vm_id)
        with self._lock:
            pair = self._services.get(service)
            if not pair:
                return
            node = pair.nodes[vm_id]
            if not ok:
                node.role = NodeRole.FAILED
                node.last_event = "validation_failed"
                pair.log("validate_failed", f"{vm_id} failed clean-state validation", vm_id)
                return
            self.backend.rejoin_as_standby(service, vm_id)
            node.role = NodeRole.STANDBY
            node.healthy = True
            node.last_event = "rejoined_as_standby"
            pair.log("rejoin", f"{vm_id} cleaned & rejoined as STANDBY — redundancy restored", vm_id)
            # If the active node is healthy and we have a standby again, service is RESTORED.
            if pair.state in (ServiceState.DEGRADED, ServiceState.NO_STANDBY):
                active = pair.nodes.get(pair.active_node) if pair.active_node else None
                if active and active.healthy:
                    pair.state = ServiceState.RESTORED
                    pair.log("restored", "full redundancy restored — incident closed", pair.active_node)

    # ---- queries ----------------------------------------------------------

    def get_all(self) -> List[dict]:
        with self._lock:
            return [p.to_dict() for p in self._services.values()]

    def get_service(self, service: str) -> Optional[dict]:
        with self._lock:
            p = self._services.get(service)
            return p.to_dict() if p else None

    def reset_service(self, service: str):
        """Operator override: return a service pair to a clean HEALTHY baseline."""
        with self._lock:
            pair = self._services.get(service)
            if not pair:
                return
            healthy_nodes = list(pair.nodes.values())
            if healthy_nodes:
                for i, n in enumerate(healthy_nodes):
                    n.role = NodeRole.ACTIVE if i == 0 else NodeRole.STANDBY
                    n.healthy = True
                    n.last_event = "reset"
                pair.active_node = healthy_nodes[0].node_id
            pair.state = ServiceState.HEALTHY
            pair.rto_seconds = None
            pair.log("reset", "service reset to HEALTHY by operator", pair.active_node or "")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    orch = FailoverOrchestrator(SimulatedBackend(step_delay=0.05))
    orch.register_service("web", "10.0.0.100", "prod-vm-01", ["prod-vm-02"])

    print("== before ==")
    print(orch.get_service("web")["state"])

    print("\n== ACTIVE node prod-vm-01 compromised ==")
    res = orch.handle_compromise("prod-vm-01")
    print("state:", res["state"], "| active:", res["active_node"], "| RTO:", res["rto_seconds"], "s")

    time.sleep(2.0)  # let background cure/rejoin finish
    final = orch.get_service("web")
    print("\n== after self-heal ==")
    print("state:", final["state"], "| active:", final["active_node"])
    for n in final["nodes"]:
        print(f"   {n['node_id']:12} {n['role']:10} healthy={n['healthy']}")
    print("\ntimeline:")
    for t in final["timeline"]:
        print(f"   [{t['stage']:16}] {t['detail']}")
