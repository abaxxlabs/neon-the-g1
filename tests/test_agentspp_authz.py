"""Agents++ shadow authorization probe (ABXAGNTS-911).

Pure unit tests: no robot, no DDS, no network. The real
``agentspp_strands_tools`` package is imported (installed in the dev venv)
but its network entry points are monkeypatched with fakes.
"""
import asyncio
import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import agentspp_strands_tools as pkg

from tools import agent_log, agentspp_authz, tool_log


# ─────────────────────────────────────────────────────────────────────────
# fakes
# ─────────────────────────────────────────────────────────────────────────
class FakeClient:
    """Client-side fake of the Agents++ REST surface.

    Since ABXAGNTS-927 NEON talks to Agents++ exclusively through the
    ``agents_*`` Strands tools built ON TOP of this client — the tools are
    real, only this (HTTP-equivalent) boundary is faked.
    """
    base_url = "fake"

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.attempts = 0
        self.sessions = 0
        self.agents = 0
        self.creds = 0
        self.pres = 0
        self.issued = {}        # agent_did -> caps issued in its VC
        self.decides = []       # one entry per authorize_action call
        self.decide_fixed = None    # if set: always return this decision
        self.decide_seq = []        # scripted decisions, FIFO
        self.decide_error = None   # if set: raise from authorize_action

    def _maybe_fail(self):
        if self.fail:
            raise RuntimeError("fake Agents++ down")

    def create_session(self, bearer_token=None, mock_human_did=None):
        self.attempts += 1
        self._maybe_fail()
        self.sessions += 1
        return {"sessionId": "sess-1", "humanDid": mock_human_did or "did:web:anon"}

    def create_agent(self, session, name):
        self._maybe_fail()
        self.agents += 1
        return {"did": f"did:agents:{name}", "name": name}

    def issue_credential(self, session, agent, profile=None, columns=None,
                         actions=None, capabilities=None, expires_in=None, **kw):
        self._maybe_fail()
        self.creds += 1
        self.issued[agent] = [c["action"] for c in (capabilities or [])]
        return "vc.jwt"  # /credentials returns the VC JWT as a JSON string

    def build_presentation(self, session, agent, credential, audience=None,
                           nonce=None, lifetime=None):
        self._maybe_fail()
        self.pres += 1
        return {"presentation": "vp.jwt", "jti": "jti-1"}

    def authorize_action(self, session, *, agent_did, persona, capability, vc, vp,
                         action="invoke_tool", scope=None, context=None):
        """Emulates /authorization/decide server-side: credential-driven —
        allow iff the capability is in this agent's ISSUED VC."""
        self._maybe_fail()
        self.decides.append({
            "session": session, "agent_did": agent_did, "persona": persona,
            "capability": capability, "vc": vc, "vp": vp,
            "action": action, "context": context,
        })
        if self.decide_error is not None:
            raise self.decide_error
        if self.decide_fixed is not None:
            return self.decide_fixed
        if self.decide_seq:
            return self.decide_seq.pop(0)
        ok = capability in self.issued.get(agent_did, [])
        return {
            "decision": "allow" if ok else "deny",
            "decision_id": f"d-{len(self.decides)}",
            "reason": None if ok else f"Action '{capability}' not permitted on any resource",
        }


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    path = tmp_path / "mem.db"
    monkeypatch.setattr(agent_log, "DB", path)
    monkeypatch.setattr(agentspp_authz, "_artifacts", {})
    monkeypatch.setattr(agentspp_authz, "_failed_at", {})
    monkeypatch.setattr(agentspp_authz, "_tools_cache", {})
    agentspp_authz._noticed.clear()
    yield path


def _rows(path):
    c = sqlite3.connect(path)
    c.execute("""CREATE TABLE IF NOT EXISTS agent_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, persona TEXT, role TEXT,
        text TEXT, meta TEXT, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    rows = c.execute("SELECT persona, role, text, meta FROM agent_log ORDER BY id").fetchall()
    c.close()
    return [(p, r, t, json.loads(m) if m else None) for p, r, t, m in rows]


# ─────────────────────────────────────────────────────────────────────────
# capability resolution (NEON vocabulary)
# ─────────────────────────────────────────────────────────────────────────
def test_resolve_map_direct():
    assert agentspp_authz.resolve_neon_capability("g1_turn") == "robot.motion.walk"
    assert agentspp_authz.resolve_neon_capability("g1_walk_forward") == "robot.motion.walk"
    assert agentspp_authz.resolve_neon_capability("g1_stop_move") == "robot.motion.stop"
    assert agentspp_authz.resolve_neon_capability("g1_arm_action") == "robot.arm.gesture"
    assert agentspp_authz.resolve_neon_capability("g1_dds_publish") == "robot.dds.publish.raw"


def test_resolve_map_use_unitree_by_service_op():
    assert agentspp_authz.resolve_neon_capability(
        "use_unitree", {"service_name": "loco", "operation_name": "SetFsmId"}
    ) == "robot.control.fsm.change"
    assert agentspp_authz.resolve_neon_capability(
        "use_unitree", {"service_name": "loco", "operation_name": "Move"}
    ) == "robot.motion.walk"
    assert agentspp_authz.resolve_neon_capability(
        "use_unitree", {"service_name": "motion_switcher", "operation_name": "ReleaseMode"}
    ) == "robot.control.fsm.change"


def test_resolve_map_unmapped_and_readonly():
    assert agentspp_authz.resolve_neon_capability("g1_get_state") is None
    assert agentspp_authz.resolve_neon_capability("memory") is None
    # read-only SDK op: no capability, no probe
    assert agentspp_authz.resolve_neon_capability(
        "use_unitree", {"service_name": "loco", "operation_name": "GetFsmId"}
    ) is None
    # mapped tool name but not use_unitree: args ignored
    assert agentspp_authz.resolve_neon_capability("other", {"service_name": "loco"}) is None


# ─────────────────────────────────────────────────────────────────────────
# mode gating
# ─────────────────────────────────────────────────────────────────────────
def test_mode_off_is_noop(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "off")
    out = agentspp_authz.probe("g1_turn", {"vx": 0.2}, "shell", blocking=True)
    assert out is None
    assert fake.decides == []
    assert _rows(agent_log.DB) == []


def test_invalid_mode_falls_back_to_off(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce2")
    assert agentspp_authz.authz_mode() == "off"


def test_unmapped_operation_skips_probe(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    out = agentspp_authz.probe("g1_get_state", {}, "shell", blocking=True)
    assert out is None
    assert fake.decides == []


# ─────────────────────────────────────────────────────────────────────────
# bootstrap (session -> agent -> VC -> VP)
# ─────────────────────────────────────────────────────────────────────────
def test_bootstrap_provisions_and_caches(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    art = agentspp_authz._get_artifacts("voice")
    assert art is not None
    assert art["session"] == "sess-1"
    assert art["agent_did"] == "did:agents:neon-voice"
    assert art["vc"] == "vc.jwt"
    assert art["vp"] == "vp.jwt"
    # ABXAGNTS-913: persona matrix — voice (slim toolset) gets its own caps
    assert "robot.motion.walk" in art["capabilities"]
    assert "robot.arm.gesture" in art["capabilities"]
    assert "robot.dds.publish.raw" not in art["capabilities"]  # no g1_dds in slim set
    assert "robot.control.sdk.rpc" not in art["capabilities"]  # no use_unitree
    # cached: a second provision is free
    agentspp_authz._get_artifacts("voice")
    assert fake.agents == 1 and fake.creds == 1 and fake.pres == 1


def test_bootstrap_vc_capabilities_override(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_VC_CAPABILITIES", "robot.motion.walk")
    art = agentspp_authz._get_artifacts("telegram")
    assert art["capabilities"] == "robot.motion.walk"


def test_bootstrap_failure_cooldown(monkeypatch):
    fake = FakeClient(fail=True)
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    assert agentspp_authz._get_artifacts("shell") is None
    assert agentspp_authz._get_artifacts("shell") is None  # cooldown: no retry storm
    assert fake.attempts == 1


def test_bootstrap_mock_human_did_default(monkeypatch):
    seen = {}

    class SpyClient(FakeClient):
        def create_session(self, bearer_token=None, mock_human_did=None):
            seen["human"] = mock_human_did
            return super().create_session(bearer_token, mock_human_did)

    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: SpyClient())
    agentspp_authz._get_artifacts("shell")
    assert seen["human"] == "did:web:neon-dev"


# ─────────────────────────────────────────────────────────────────────────
# probe outcome recording
# ─────────────────────────────────────────────────────────────────────────
def test_probe_blocking_records_decision(monkeypatch):
    fake = FakeClient()
    fake.decide_fixed = {"decision": "ALLOW", "decision_id": "d-42",
                         "reason": "capability granted"}
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    agentspp_authz._artifacts["shell"] = {
        "session": "s", "agent_did": "a", "vc": "v", "vp": "p", "capabilities": "c",
    }
    meta = agentspp_authz.probe("g1_turn", {"vx": 0.2}, "shell",
                                tool_use_id="tu-1", blocking=True)
    assert meta is not None
    assert meta["decision"] == "ALLOW"
    assert meta["decision_id"] == "d-42"
    assert meta["tool_use_id"] == "tu-1"
    # the agents_authorize_action tool was called with NEON capability + artifacts
    call = fake.decides[0]
    assert call["capability"] == "robot.motion.walk"
    assert call["session"] == "s" and call["agent_did"] == "a"
    assert call["vc"] == "v"
    assert call["vp"] == "vp.jwt"  # freshly minted via agents_build_presentation
    assert call["persona"] == "shell"
    # logged with role=authz, correlatable
    rows = [r for r in _rows(agent_log.DB) if r[1] == "authz"]
    assert len(rows) == 1
    assert rows[0][0] == "shell"
    assert "d-42" in rows[0][2]
    assert rows[0][3]["decision"] == "ALLOW"


def test_probe_records_denay_and_error(monkeypatch):
    fake = FakeClient()
    fake.decide_fixed = {"decision": "DENY", "decision_id": "d-9",
                         "reason": "credential missing capability"}
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    agentspp_authz._artifacts["shell"] = {
        "session": "s", "agent_did": "a", "vc": "v", "vp": "p", "capabilities": "c",
    }
    meta = agentspp_authz.probe("g1_dds_publish", {}, "shell", blocking=True)
    assert meta["decision"] == "DENY"


def test_probe_survives_gate_exception(monkeypatch):
    fake = FakeClient()
    fake.decide_error = RuntimeError("unexpected")
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    agentspp_authz._artifacts["shell"] = {
        "session": "s", "agent_did": "a", "vc": "v", "vp": "p", "capabilities": "c",
    }
    meta = agentspp_authz.probe("g1_turn", {}, "shell", blocking=True)
    assert meta["decision"] is None
    assert "gate error" in (meta["reason"] or "")


def test_probe_shadow_runs_async_and_never_blocks(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    agentspp_authz._artifacts["voice"] = {
        "session": "s", "agent_did": "a", "vc": "v", "vp": "p", "capabilities": "c",
    }
    t0 = time.monotonic()
    out = agentspp_authz.probe("g1_walk_forward", {"steps": 2}, "voice")
    assert out is None  # fire-and-forget
    assert time.monotonic() - t0 < 0.2  # did not wait on the decide
    # Wait for the daemon thread to FINISH (decide called AND log row landed in the
    # tmp DB). Ending earlier would let the thread write to the restored real DB.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        authz_rows = [r for r in _rows(agent_log.DB) if r[1] == "authz"]
        if fake.decides and authz_rows:
            break
        time.sleep(0.02)
    assert fake.decides, "shadow probe thread never ran the decide"
    assert authz_rows, "shadow probe row never landed in the tmp agent_log"
    assert authz_rows[0][0] == "voice"


# ─────────────────────────────────────────────────────────────────────────
# prompt hygiene: authz rows must not leak into the system prompt
# ─────────────────────────────────────────────────────────────────────────
def test_format_for_prompt_excludes_authz_role():
    agent_log.record("shell", "tool", "g1_get_state ran fine")
    agent_log.record("shell", "authz", "SECRET-AUTHZ-LINE cap=robot.motion.walk")
    block = agent_log.format_for_prompt(exclude_persona=None)
    assert "g1_get_state ran fine" in block
    assert "SECRET-AUTHZ-LINE" not in block


# ─────────────────────────────────────────────────────────────────────────
# LoggedTool wiring: probe fires, masked args preserved, failures contained
# ─────────────────────────────────────────────────────────────────────────
class _FakeInner:
    tool_name = "fake-inner"

    def __call__(self, *a, **k):
        return {"status": "success", "content": [{"text": "ok"}]}

    def stream(self, *a, **k):
        async def _gen():
            yield {"status": "success", "content": [{"text": "ok"}]}

        return _gen()


def test_loggedtool_direct_call_probes(monkeypatch):
    calls = []
    monkeypatch.setattr(
        agentspp_authz, "probe", lambda name, args, persona, tool_use_id=None:
        calls.append((name, args, persona)) or None
    )
    t = tool_log.LoggedTool(_FakeInner(), persona="shell")
    t(service_name="loco", operation_name="SetFsmId", fsm_id=5)
    assert len(calls) == 1
    name, args, persona = calls[0]
    assert name == "fake-inner"
    assert persona == "shell"
    assert args["operation_name"] == "SetFsmId"


def test_loggedtool_stream_probes_and_survives_probe_bomb(monkeypatch):
    def bomb(name, args, persona, tool_use_id=None):
        raise RuntimeError("probe must not kill the tool")

    monkeypatch.setattr(agentspp_authz, "probe", bomb)
    t = tool_log.LoggedTool(_FakeInner(), persona="shell")
    tu = {"toolUseId": "tu-9", "input": {"service_name": "loco",
                                          "operation_name": "SetFsmId",
                                          "api_token": "topsecret"}}

    async def _collect(gen):
        out = []
        async for e in gen:
            out.append(e)
        return out

    results = asyncio.run(_collect(t.stream(tu, None)))
    assert results[-1]["status"] == "success"
    row = [r for r in _rows(agent_log.DB) if r[3] and r[3].get("tool_use_id") == "tu-9"]
    assert row, "tool log row missing"


def test_mask_preserves_unitree_routing_args():
    masked = tool_log._mask({
        "service_name": "loco",
        "operation_name": "SetFsmId",
        "api_token": "topsecret",
    })
    assert masked["service_name"] == "loco"
    assert masked["operation_name"] == "SetFsmId"
    assert "topsecret" not in json.dumps(masked)


# ─────────────────────────────────────────────────────────────────────────
# regression: VP nonce-replay (a presentation is single-use) + error meta
# ─────────────────────────────────────────────────────────────────────────
class _RaisingClient:
    base_url = "fake-raise"

    def __init__(self):
        self.decides = []

    def build_presentation(self, *a, **k):
        raise RuntimeError("present down")

    def authorize_action(self, *a, **k):
        self.decides.append(k)
        return {"decision": "allow", "decision_id": "d-2", "reason": None}


def test_probe_mints_fresh_presentation_per_probe(monkeypatch):
    """Each probe must carry a NEW presentation (anti-replay nonce)."""
    fake = FakeClient()
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    agentspp_authz._artifacts["shell"] = {
        "session": "s", "agent_did": "a", "vc": "v", "vp": "stale", "capabilities": "c",
    }
    agentspp_authz.probe("g1_turn", {}, "shell", blocking=True)
    agentspp_authz.probe("g1_turn", {}, "shell", blocking=True)
    # the decide tool saw the freshly minted presentation both times, never the stale one
    assert all(d["vp"] == "vp.jwt" for d in fake.decides)
    assert fake.pres == 2


def test_probe_falls_back_to_bootstrap_vp_when_present_fails(monkeypatch):
    client = _RaisingClient()
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: client)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    agentspp_authz._artifacts["shell"] = {
        "session": "s", "agent_did": "a", "vc": "v", "vp": "bootstrap-vp", "capabilities": "c",
    }
    meta = agentspp_authz.probe("g1_turn", {}, "shell", blocking=True)
    assert meta["decision"] == "allow"
    # the decide ran on the bootstrap-time presentation (present had failed)
    assert client.decides[0]["vp"] == "bootstrap-vp"


def test_probe_captures_full_gate_error_message(monkeypatch):
    """Tool/client exceptions surface as {'message': ...} — must not be dropped."""
    fake = FakeClient()
    fake.decide_error = RuntimeError("Agents++ request failed with status 400")
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    agentspp_authz._artifacts["shell"] = {
        "session": "s", "agent_did": "a", "vc": "v", "vp": "stale", "capabilities": "c",
    }
    meta = agentspp_authz.probe("g1_turn", {}, "shell", blocking=True)
    assert meta["decision"] is None
    assert meta["error"] == {"message": "Agents++ request failed with status 400"}
