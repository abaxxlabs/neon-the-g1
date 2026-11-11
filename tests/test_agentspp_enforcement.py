"""Agents++ enforcement gate (ABXAGNTS-912).

Pure unit/E2E tests: no robot, no DDS, no network. The real
``agentspp_strands_tools`` package is imported (installed in the dev venv)
but its network entry points are monkeypatched with fakes — same pattern
as the 911 shadow suite.

Covers the ticket's acceptance criteria:
- denied high-risk operations never reach the inner tool (hardware)
- allowed high-risk operations execute normally
- authz unavailability denies (fail closed)
- runtime revocation is effective without redeploy
- allow / deny / revoke / unavailable scenarios, both choke points
  (LoggedTool.stream and LoggedTool.__call__)
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
# fakes (same pattern as tests/test_agentspp_authz.py)
# ─────────────────────────────────────────────────────────────────────────
class FakeClient:
    """Client-side fake of the Agents++ REST surface. Since ABXAGNTS-927 NEON
    talks to Agents++ exclusively through the agents_* Strands tools built on
    top of this client — the tools are real, only this boundary is faked."""
    base_url = "fake"

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.sessions = 0
        self.agents = 0
        self.creds = 0
        self.pres = 0
        self.issued = {}        # agent_did -> caps issued in its VC
        self.decides = []       # one entry per authorize_action call
        self.decide_fixed = None
        self.decide_seq = []
        self.decide_error = None

    def _maybe_fail(self):
        if self.fail:
            raise RuntimeError("fake Agents++ down")

    def create_session(self, bearer_token=None, mock_human_did=None):
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
        return "vc.jwt"

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


class _SpyInner:
    """Inner tool that counts how many times the hardware path ran."""

    def __init__(self, tool_name="g1_turn"):
        self.tool_name = tool_name
        self.calls = 0

    def __call__(self, *a, **k):
        self.calls += 1
        return {"status": "success", "content": [{"text": "hw-ran"}]}

    def stream(self, *a, **k):
        async def _gen():
            self.calls += 1
            yield {"status": "success", "content": [{"text": "hw-ran"}]}

        return _gen()


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


def _authed(monkeypatch, fake=None):
    """Point the package at a fake client (real _probe_sync + real tools)."""
    fake = fake or FakeClient()
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    return fake


def _stream(t, tu):
    async def _collect(gen):
        return [e async for e in gen]

    return asyncio.run(_collect(t.stream(tu, None)))


def _walk_tu(tid="tu-e1"):
    return {"toolUseId": tid, "input": {"angle": 0.5}}


def _deny_text(payload):
    return payload["content"][0]["text"]


# ─────────────────────────────────────────────────────────────────────────
# enforcement_verdict — the fail-closed mapping
# ─────────────────────────────────────────────────────────────────────────
def test_verdict_allow():
    v, _ = agentspp_authz.enforcement_verdict({"decision": "allow", "reason": "granted"})
    assert v == "allow"


def test_verdict_deny_with_reason():
    v, r = agentspp_authz.enforcement_verdict(
        {"decision": "deny", "reason": "capability not in credential"}
    )
    assert (v, r) == ("deny", "capability not in credential")


def test_verdict_deny_default_reason():
    v, r = agentspp_authz.enforcement_verdict({"decision": "deny"})
    assert v == "deny" and r


def test_verdict_error_message_is_deny():
    v, r = agentspp_authz.enforcement_verdict(
        {"decision": None, "error": {"message": "HTTP 500 from decide"}}
    )
    assert (v, r) == ("deny", "HTTP 500 from decide")


def test_verdict_artifacts_unavailable_is_deny():
    v, r = agentspp_authz.enforcement_verdict(
        {"decision": None, "reason": "artifacts unavailable"}
    )
    assert (v, r) == ("deny", "artifacts unavailable")


def test_verdict_none_is_deny_fail_closed():
    v, r = agentspp_authz.enforcement_verdict(None)
    assert v == "deny" and "unavailable" in r


def test_denied_cap_is_not_stop():
    # robot.motion.stop must stay out of the enforcement set: enforcement
    # must never be able to prevent stopping the robot.
    assert "robot.motion.stop" not in agentspp_authz.ENFORCED_CAPABILITIES
    # 913: the full body-movement set is enforced; arms/stop/sdk.rpc stay shadow
    assert {
        "robot.motion.walk",
        "robot.control.fsm.change",
        "robot.control.zerotorque",
        "robot.dds.publish.raw",
    } == set(agentspp_authz.ENFORCED_CAPABILITIES)


def test_enforcement_active_matrix(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    assert agentspp_authz.enforcement_active("g1_turn", {})
    assert agentspp_authz.enforcement_active(
        "use_unitree", {"service_name": "loco", "operation_name": "SetFsmId"}
    )
    assert not agentspp_authz.enforcement_active("g1_arm_action", {})  # shadow only
    assert not agentspp_authz.enforcement_active("g1_stop_move", {})
    assert not agentspp_authz.enforcement_active("g1_get_state", {})
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    assert not agentspp_authz.enforcement_active("g1_turn", {})


# ─────────────────────────────────────────────────────────────────────────
# probe dispatch — sync gate vs async shadow
# ─────────────────────────────────────────────────────────────────────────
def test_probe_enforce_runs_sync_and_returns_meta(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "allow", "decision_id": "d-1"}
    _authed(monkeypatch, fake)
    meta = agentspp_authz.probe("g1_turn", {"angle": 0.5}, "shell")
    assert meta is not None
    assert meta["enforced"] is True
    assert meta["decision"] == "allow"
    assert len(fake.decides) == 1


def test_probe_enforce_non_enforced_cap_stays_async(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "allow", "decision_id": "d-1"}
    _authed(monkeypatch, fake)
    out = agentspp_authz.probe("g1_arm_action", {}, "shell")
    assert out is None  # fire-and-forget, like shadow
    deadline = time.monotonic() + 2
    while not fake.decides and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(fake.decides) == 1


def test_probe_shadow_never_blocks(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "allow", "decision_id": "d-1"}
    _authed(monkeypatch, fake)
    assert agentspp_authz.probe("g1_turn", {"angle": 0.5}, "shell") is None


def test_probe_off_no_gate(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "off")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "allow"}
    _authed(monkeypatch, fake)
    assert agentspp_authz.probe("g1_turn", {"angle": 0.5}, "shell") is None
    assert fake.decides == []


# ─────────────────────────────────────────────────────────────────────────
# LoggedTool.stream — the executor path
# ─────────────────────────────────────────────────────────────────────────
def test_stream_denied_never_reaches_inner(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "deny", "decision_id": "d-9",
                         "reason": "capability not in credential"}
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")

    events = _stream(t, _walk_tu())
    assert inner.calls == 0  # hardware never touched
    assert len(events) == 1
    payload = events[0].tool_result if hasattr(events[0], "tool_result") else events[0]
    assert payload["status"] == "error"
    assert _deny_text(payload).startswith("DENIED by authorization policy")
    assert "d-9" in _deny_text(payload)
    # journal: tool row with status=denied + authz row
    rows = _rows(agent_log.DB)
    assert any(r[1] == "tool" and "status=denied" in r[2] for r in rows)
    authz = [r for r in rows if r[1] == "authz"]
    assert authz and authz[0][3]["enforced"] is True


def test_stream_event_is_tool_result_event(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "deny", "decision_id": "d-1",
                         "reason": "capability not in credential"}
    _authed(monkeypatch, fake)
    t = tool_log.LoggedTool(_SpyInner("g1_turn"), persona="shell")
    events = _stream(t, _walk_tu())
    from strands.types._events import ToolResultEvent
    assert isinstance(events[0], ToolResultEvent)
    assert events[0].tool_result["toolUseId"] == "tu-e1"


def test_stream_allowed_runs_inner_normally(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "allow", "decision_id": "d-2"}
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")

    events = _stream(t, _walk_tu())
    assert inner.calls == 1
    payload = events[-1].tool_result if hasattr(events[-1], "tool_result") else events[-1]
    assert payload["status"] == "success"
    assert "DENIED" not in _deny_text(payload)


def test_stream_fail_closed_when_authz_down(monkeypatch):
    """AC: authz unavailability denies high-risk operations."""
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = _authed(monkeypatch, FakeClient(fail=True))
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")

    events = _stream(t, _walk_tu())
    assert inner.calls == 0
    assert fake.decides == []  # bootstrap failed before any decide
    payload = events[0].tool_result if hasattr(events[0], "tool_result") else events[0]
    assert _deny_text(payload).startswith("DENIED by authorization policy")


def test_stream_revoke_effective_without_redeploy(monkeypatch):
    """AC: runtime revocation — first decide allows, the credential is
    revoked server-side, the next probe must deny. The artifacts (session/
    agent/VC) stay cached: no re-bootstrap, no redeploy."""
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_seq = [
        {"decision": "allow", "decision_id": "d-a"},
        {"decision": "deny", "decision_id": "d-r"},  # post-revocation
    ]
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")

    e1 = _stream(t, _walk_tu(tid="tu-r1"))
    assert inner.calls == 1
    e2 = _stream(t, _walk_tu(tid="tu-r2"))
    assert inner.calls == 1  # second call blocked
    p2 = e2[0].tool_result if hasattr(e2[0], "tool_result") else e2[0]
    assert "d-r" in _deny_text(p2)
    assert fake.agents == 1  # same bootstrap, no redeploy


def test_stream_enforce_non_enforced_cap_not_gated(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "deny", "decision_id": "d-x",
                         "reason": "capability not in credential"}
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_arm_action")
    t = tool_log.LoggedTool(inner, persona="shell")

    events = _stream(t, {"toolUseId": "tu-a1", "input": {}})
    assert inner.calls == 1  # shadow only: decision is logged, not applied
    payload = events[-1].tool_result if hasattr(events[-1], "tool_result") else events[-1]
    assert payload["status"] == "success"


def test_stream_gate_bug_fails_closed_for_enforced(monkeypatch):
    """A bug inside the gate path must deny enforced calls, not execute them."""
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")

    def bomb(*a, **k):
        raise RuntimeError("gate exploded")

    monkeypatch.setattr(agentspp_authz, "probe", bomb)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")
    events = _stream(t, _walk_tu())
    assert inner.calls == 0
    payload = events[0].tool_result if hasattr(events[0], "tool_result") else events[0]
    assert _deny_text(payload).startswith("DENIED by authorization policy")


def test_stream_gate_bug_never_touches_non_enforced(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")

    def bomb(*a, **k):
        raise RuntimeError("gate exploded")

    monkeypatch.setattr(agentspp_authz, "probe", bomb)
    inner = _SpyInner("g1_arm_action")
    t = tool_log.LoggedTool(inner, persona="shell")
    events = _stream(t, {"toolUseId": "tu-b1", "input": {}})
    assert inner.calls == 1  # shadow invariant: authz never takes a tool down
    payload = events[-1].tool_result if hasattr(events[-1], "tool_result") else events[-1]
    assert payload["status"] == "success"


# ─────────────────────────────────────────────────────────────────────────
# LoggedTool.__call__ — the direct/programmatic path
# ─────────────────────────────────────────────────────────────────────────
def test_call_denied_returns_payload_and_skips_inner(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "deny", "decision_id": "d-c",
                         "reason": "capability not in credential"}
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")

    out = t(angle=0.5)
    assert inner.calls == 0
    assert out["status"] == "error"
    assert _deny_text(out).startswith("DENIED by authorization policy")
    assert out["content"][1]["json"]["decision_id"] == "d-c"


def test_call_allowed_runs_inner(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "allow", "decision_id": "d-c2"}
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")

    out = t(angle=0.5)
    assert inner.calls == 1
    assert out["status"] == "success"


def test_call_fail_closed_when_authz_down(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = _authed(monkeypatch, FakeClient(fail=True))
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")

    out = t(angle=0.5)
    assert inner.calls == 0
    assert out["status"] == "error"
    assert _deny_text(out).startswith("DENIED by authorization policy")


def test_call_off_mode_unchanged(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "off")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "deny"}
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="shell")

    out = t(angle=0.5)
    assert inner.calls == 1
    assert out["status"] == "success"
    assert fake.decides == []


# ─────────────────────────────────────────────────────────────────────────
# journal / dashboard visibility
# ─────────────────────────────────────────────────────────────────────────
def test_deny_journal_rows_and_format_for_prompt_clean(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = FakeClient()
    fake.decide_fixed = {"decision": "deny", "decision_id": "d-j",
                         "reason": "capability not in credential"}
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="voice")

    _stream(t, _walk_tu())
    rows = _rows(agent_log.DB)
    authz = [r for r in rows if r[1] == "authz"]
    assert authz and authz[0][3]["decision_id"] == "d-j"
    assert authz[0][3]["enforced"] is True
    # tool row visible in the Activity Log with status=denied
    tool_rows = [r for r in rows if r[1] == "tool"]
    assert tool_rows and "status=denied" in tool_rows[0][2]
    # role=authz rows stay out of the prompt (911 behavior, unchanged).
    # Note: the tool row (status=denied) IS prompt context on purpose —
    # cross-persona awareness; only the authz telemetry line is excluded.
    block = agent_log.format_for_prompt(exclude_persona=None)
    assert "cap=robot.motion.walk" not in block  # authz line marker
