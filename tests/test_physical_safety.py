"""ABXAGNTS-914: physical safety controls remain intact (and are now tested).

The authorization layer (911-913) composes with the physical gates — it never
replaces them. This file pins the local controls that the 914 cleanup touched
or that guard the system when authz is off:

- the use_unitree danger warning fires ALWAYS (the BYPASS_TOOL_CONSENT
  env-var branch was removed in 914 — it used to silence this in prod)
- HIGH_DANGER_OPS / mutative classification is intact (reads stay unflagged)
- the danger marker travels in the tool reply (model-facing feedback)
- the safety invariants the authz matrix depends on: stop is unenforced,
  arms are shadow (a physical emergency can never wait on a policy server)

Clamps and motion honesty (gates 6 and 8) are already covered by
tests/test_locomotion_honesty.py; the arm mutex (gate 5) and FSM checks
(gate 4) are hardware properties exercised through the same rc paths.
"""
import importlib
import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def uu():
    """The real tools.use_unitree module with its SDK dispatcher stubbed."""
    import tools  # registers tools.use_unitree in sys.modules
    mod = importlib.import_module("tools.use_unitree")
    mod._execute = lambda *a, **k: {"ok": True, "result": "fake-result"}
    return mod


def _call(uu, svc, op, params=None):
    r = uu.use_unitree(svc, op, params or {})
    # strands wraps the return into {status, content: [blocks]}
    if isinstance(r, dict) and isinstance(r.get("content"), list):
        return r["content"]
    if isinstance(r, list):
        return r
    return [r]


def _json(uu, r):
    for v in r:
        if isinstance(v, dict) and "service" in v:
            return v
        if isinstance(v, dict) and isinstance(v.get("json"), dict) and "service" in v["json"]:
            return v["json"]
    return None


def test_high_danger_warning_always_fires(uu, caplog):
    with caplog.at_level(logging.WARNING, logger="tools.use_unitree"):
        _call(uu, "loco", "ZeroTorque")
    assert any("ZeroTorque" in m and "HIGH_DANGER" in m for m in caplog.messages)


def test_env_var_bypass_is_gone(uu, caplog, monkeypatch):
    """The old bypass no longer exists — setting it changes nothing."""
    monkeypatch.setenv("BYPASS_TOOL_CONSENT", "true")
    with caplog.at_level(logging.WARNING, logger="tools.use_unitree"):
        _call(uu, "loco", "SetFsmId", {"fsm_id": 1})
    assert any("SetFsmId" in m and "HIGH_DANGER" in m for m in caplog.messages)
    src = open(ROOT / "tools" / "use_unitree.py").read()
    assert 'os.environ.get("BYPASS_TOOL_CONSENT"' not in src


def test_mutative_rpc_flagged(uu, caplog):
    with caplog.at_level(logging.WARNING, logger="tools.use_unitree"):
        _call(uu, "loco", "BalanceStand")
    assert any("BalanceStand" in m and "mutative" in m for m in caplog.messages)


def test_readonly_rpc_never_flagged(uu, caplog):
    with caplog.at_level(logging.WARNING, logger="tools.use_unitree"):
        _call(uu, "loco", "GetStatus")
        _call(uu, "loco", "CheckMode")
    assert not any("use_unitree:" in m for m in caplog.messages)


def test_danger_markers_in_reply(uu):
    r = _call(uu, "loco", "ZeroTorque")
    j = _json(uu, r)
    assert j["high_danger"] is True and j["mutative"] is True

    r = _call(uu, "loco", "GetStatus")
    j = _json(uu, r)
    # reads carry no danger section at all
    assert j.get("high_danger") is not True


def test_unknown_service_still_rejected(uu):
    r = _call(uu, "nope", "DoThing")
    text = " ".join(b.get("text", "") for b in r if isinstance(b, dict))
    assert "unknown service" in text


def test_authz_invariants_physical_safety_depends_on():
    """Stop/arms are never enforced: a physical emergency must not wait on
    a policy server, and the matrix grants stop to every persona."""
    from tools import agentspp_authz as a

    assert "robot.motion.stop" not in a.ENFORCED_CAPABILITIES
    assert "robot.arm.gesture" not in a.ENFORCED_CAPABILITIES
    for persona, caps in a.PERSONA_CAPABILITY_MATRIX.items():
        assert "robot.motion.stop" in caps, persona
    # the ZeroTorque collapse path is covered by the enforcement set so a
    # persona without the cap cannot even reach it in enforce mode
    assert "robot.control.zerotorque" in a.ENFORCED_CAPABILITIES
    assert a.resolve_neon_capability(
        "use_unitree", {"service_name": "loco",
                        "operation_name": "ZeroTorque", "params": {}}
    ) == "robot.control.zerotorque"


def test_telegram_allowlist_gate_intact():
    """Gate 1 is human identity — deliberately NOT replaced by the
    credential plane. The check still lives in tools/telegram.py."""
    src = open(ROOT / "tools" / "telegram.py").read()
    assert "TELEGRAM_ALLOWED_USERS" in src
