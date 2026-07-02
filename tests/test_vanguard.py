"""
Vanguard-OOB :: pytest unit tests
==================================
Proper unit tests (one behaviour per test, real assertions) that plug into CI
and coverage tooling. These complement verify.py (which is an all-in-one
self-check) by being individually selectable and pytest-native.

Run:  pytest -q
"""

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "host_control_plane"))
sys.path.insert(0, str(ROOT / "blue_team" / "sigma_engine"))


# ---------------------------------------------------------------------------
# Secure channel
# ---------------------------------------------------------------------------
class TestSecureChannel:
    def _mk(self):
        from common.secure_channel import SecureSender, SecureReceiver, load_master_secret
        m = load_master_secret()
        return SecureSender(m, "vm-a"), SecureReceiver(m)

    def test_round_trip(self):
        s, r = self._mk()
        frame = s.seal({"vm_id": "vm-a", "batch": [{"event_type": "heartbeat"}]})
        aid, payload = r.open(frame)
        assert aid == "vm-a"
        assert payload["batch"][0]["event_type"] == "heartbeat"

    def test_replay_rejected(self):
        from common.secure_channel import AuthError
        s, r = self._mk()
        frame = s.seal({"vm_id": "vm-a", "batch": []})
        r.open(frame)
        with __import__("pytest").raises(AuthError):
            r.open(frame)

    def test_vm_id_spoof_rejected(self):
        from common.secure_channel import SecureSender, load_master_secret, AuthError
        import pytest
        m = load_master_secret()
        _, r = self._mk()
        bad = SecureSender(m, "vm-a").seal({"vm_id": "vm-evil", "batch": []})
        with pytest.raises(AuthError):
            r.open(bad)

    def test_tamper_rejected(self):
        from common.secure_channel import AuthError
        import pytest
        s, r = self._mk()
        f = bytearray(s.seal({"vm_id": "vm-a", "batch": []}))
        f[-1] ^= 0xFF
        with pytest.raises(AuthError):
            r.open(bytes(f))

    def test_forged_key_rejected(self):
        from common.secure_channel import SecureSender, AuthError
        import pytest
        _, r = self._mk()
        forged = SecureSender(os.urandom(32), "vm-a").seal({"vm_id": "vm-a", "batch": []})
        with pytest.raises(AuthError):
            r.open(forged)

    def test_ordered_set_eviction_is_bounded(self):
        from common.secure_channel import OrderedSet
        s = OrderedSet(maxlen=3)
        for i in range(10):
            s.add(f"n{i}")
        # only the last 3 remain
        assert "n9" in s and "n8" in s and "n7" in s
        assert "n0" not in s and "n6" not in s


# ---------------------------------------------------------------------------
# Scoring (controller-side, agent never trusted)
# ---------------------------------------------------------------------------
class TestScoring:
    def test_crypto_spike_weight(self):
        from control_center import _resolve_delta
        assert _resolve_delta("crypto_spike", {}) == 50

    def test_velocity_weight_is_20_not_40(self):
        from control_center import _resolve_delta
        assert _resolve_delta("velocity", {}) == 20

    def test_webshell_vs_path(self):
        from control_center import _resolve_delta
        assert _resolve_delta("process", {"reason": "web_server_spawned_shell"}) == 30
        assert _resolve_delta("process", {"reason": "suspicious_exec_path"}) == 40

    def test_agent_supplied_delta_ignored(self):
        from control_center import _resolve_delta
        # malicious agent tries to suppress its own score
        assert _resolve_delta("entropy", {"score_delta": 0}) == 40


# ---------------------------------------------------------------------------
# Alert manager (SOC workflow)
# ---------------------------------------------------------------------------
class TestAlertManager:
    def test_lifecycle_and_metrics(self):
        from alert_manager import AlertManager
        from datetime import datetime, timezone
        m = AlertManager(dedupe_window_s=0)
        a = m.raise_alert("vm-1", "crypto_spike", "critical", 50,
                          {"attack": [{"id": "T1486", "name": "x"}]},
                          event_ts_iso=datetime.now(timezone.utc).isoformat())
        assert a is not None and a.alert_id.startswith("ALRT")
        assert m.acknowledge(a.alert_id)["ok"]
        assert m.escalate(a.alert_id)["ok"]
        assert m.mark_false_positive(a.alert_id)["ok"]
        met = m.metrics()
        assert met["by_status"]["FALSE_POSITIVE"] == 1
        assert met["false_positive_rate"] == 100.0
        assert len(met["volume_series"]) == 12

    def test_low_signal_raises_no_alert(self):
        from alert_manager import AlertManager
        m = AlertManager(dedupe_window_s=0)
        assert m.raise_alert("vm-1", "heartbeat", "low", 0, {}) is None


# ---------------------------------------------------------------------------
# Failover orchestrator
# ---------------------------------------------------------------------------
class TestFailover:
    def test_active_compromise_promotes_and_self_heals(self):
        from failover_orchestrator import FailoverOrchestrator, SimulatedBackend
        o = FailoverOrchestrator(SimulatedBackend(step_delay=0.01))
        o.register_service("web", "10.0.0.100", "vm-1", ["vm-2"])
        res = o.handle_compromise("vm-1")
        assert res["active_node"] == "vm-2"
        assert res["rto_seconds"] is not None
        time.sleep(1.6)
        final = o.get_service("web")
        assert final["state"] == "RESTORED"
        assert any(n["node_id"] == "vm-1" and n["role"] == "STANDBY" for n in final["nodes"])

    def test_standby_compromise_keeps_service(self):
        from failover_orchestrator import FailoverOrchestrator, SimulatedBackend
        o = FailoverOrchestrator(SimulatedBackend(step_delay=0.0))
        o.register_service("db", "10.0.0.110", "vm-3", ["vm-4"])
        res = o.handle_compromise("vm-4")
        assert res["active_node"] == "vm-3"


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------
class TestMitre:
    def test_event_to_technique(self):
        from common.mitre_attack import map_event_to_techniques
        def ids(et, d=None):
            return [t.tid for t in map_event_to_techniques(et, d or {})]
        assert "T1486" in ids("crypto_spike")
        assert "T1490" in ids("shadow")
        assert "T1505.003" in ids("process", {"reason": "web_server_spawned_shell"})
        assert "T1562.001" in ids("agent_silence")


# ---------------------------------------------------------------------------
# Sigma engine
# ---------------------------------------------------------------------------
class TestSigma:
    def _engine(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "sigma_engine", ROOT / "blue_team" / "sigma_engine" / "sigma_engine.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["sigma_engine"] = mod
        spec.loader.exec_module(mod)
        eng = mod.SigmaEngine()
        eng.load_dir(ROOT / "blue_team" / "sigma_engine" / "rules")
        return eng

    def test_rules_load_and_fire(self):
        eng = self._engine()
        assert len(eng.rules) >= 6
        fired = eng.evaluate({"event_type": "crypto_spike", "details": {}})
        assert any("T1486" in r.attack_techniques for r in fired)

    def test_benign_does_not_fire(self):
        eng = self._engine()
        assert eng.evaluate({"event_type": "heartbeat", "details": {}}) == []


# ---------------------------------------------------------------------------
# Geo + threat-intel enrichment
# ---------------------------------------------------------------------------
class TestGeoIntel:
    def test_malicious_and_internal(self):
        from geo_intel import enrich_ip
        assert enrich_ip("185.220.1.9")["intel"]["verdict"] == "malicious"
        assert enrich_ip("10.0.0.5")["intel"]["verdict"] == "internal"

    def test_unknown_is_flagged_approx(self):
        from geo_intel import enrich_ip
        assert enrich_ip("221.244.55.89")["geo"]["approx"] is True


# ---------------------------------------------------------------------------
# Host network containment (dry-run backends)
# ---------------------------------------------------------------------------

def test_containment_dryrun_is_default_and_safe():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host_control_plane"))
    from containment import build_backend, NullBackend
    be = build_backend(dry_run=True, force="null")
    assert isinstance(be, NullBackend)
    assert be.dry_run is True
    log = be.isolate_host(mgmt_allow="10.0.0.0/24")
    assert log and all(a["executed"] is False for a in log)  # nothing was executed
    assert be.is_contained() is True


def test_containment_lift_is_reversible():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host_control_plane"))
    from containment import build_backend
    be = build_backend(dry_run=True, force="iptables")
    be.isolate_host(mgmt_allow="10.0.0.0/24")
    assert be.is_contained() is True
    lift_log = be.lift()
    assert lift_log and be.is_contained() is False


def test_all_backends_produce_commands_in_dryrun():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host_control_plane"))
    from containment import build_backend
    for name in ("null", "iptables", "nftables", "netsh", "pf"):
        be = build_backend(dry_run=True, force=name)
        log = be.isolate_host()
        assert len(log) >= 1, f"{name} produced no commands"
        assert all(a["executed"] is False for a in log), f"{name} executed in dry-run!"
