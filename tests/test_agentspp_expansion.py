"""ABXAGNTS-913: persona x capability matrix + capability-map expansion.

Faithful extraction of NEON's pre-existing hardcoded gates into the
Agents++ credential plane:

- every robot MUTATION resolves to a capability (the use_unitree hammer's
  unlisted mutative RPCs fall back to ``robot.control.sdk.rpc``; reads stay
  unmapped)
- each persona's VC carries only the capabilities in
  ``PERSONA_CAPABILITY_MATRIX`` (full toolsets: everything; slim voice /
  dashboard: walk+stop+arm; remote MCP: no walk/fsm/zerotorque/sdk.rpc —
  sealing the ``--safe`` bypass that left use_unitree in place)
- unknown personas get a zero-capability VC (zero trust)

No network: the package's HTTP entry points are faked, and the fake gate
emulates the server's credential check against the caps actually ISSUED to
the persona's VC (that is what makes the matrix denial testable here).
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
    """Client-side fake of the Agents++ REST surface. Since ABXAGNTS-927 NEON
    talks to Agents++ exclusively through the agents_* Strands tools built on
    top of this client — the tools are real, only this boundary is faked.
    ``authorize_action`` emulates the server's credential semantics: allow
    iff the capability is in this agent's ISSUED VC (that is what makes the
    persona-matrix denial testable here)."""
    base_url = "fake"

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.issued = {}      # agent_did -> caps issued in its VC
        self.decides = []
        self.agents = 0

    def _maybe_fail(self):
        if self.fail:
            raise RuntimeError("fake Agents++ down")

    def create_session(self, bearer_token=None, mock_human_did=None):
        self._maybe_fail()
        return {"sessionId": "sess-1", "humanDid": mock_human_did or "did:web:anon"}

    def create_agent(self, session, name):
        self._maybe_fail()
        self.agents += 1
        return {"did": f"did:agents:{name}", "name": name}

    def issue_credential(self, session, agent, profile=None, columns=None,
                         actions=None, capabilities=None, expires_in=None, **kw):
        self._maybe_fail()
        self.agents  # (counted in create_agent)
        self.issued[agent] = [c["action"] for c in (capabilities or [])]
        return "vc.jwt"

    def build_presentation(self, session, agent, credential, audience=None,
                           nonce=None, lifetime=None):
        self._maybe_fail()
        return {"presentation": "vp.jwt", "jti": "jti-1"}

    def authorize_action(self, session, *, agent_did, persona, capability, vc, vp,
                         action="invoke_tool", scope=None, context=None):
        self._maybe_fail()
        self.decides.append({"agent_did": agent_did, "persona": persona,
                             "capability": capability, "vp": vp})
        ok = capability in self.issued.get(agent_did, [])
        return {
            "decision": "allow" if ok else "deny",
            "decision_id": f"d-{len(self.decides)}",
            "reason": None if ok else f"Action '{capability}' not permitted on any resource",
        }

    @property
    def last_caps(self):
        return list(self.issued.values())[-1] if self.issued else []


class _SpyInner:
    def __init__(self, tool_name):
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


def _authed(monkeypatch, fake=None, mode="enforce"):
    fake = fake or FakeClient()
    monkeypatch.setenv("NEON_AUTHZ_MODE", mode)
    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: fake)
    return fake


def _stream(t, tu):
    async def _collect(gen):
        return [e async for e in gen]
    return asyncio.run(_collect(t.stream(tu, None)))


def _payload(events):
    e = events[-1]
    return e.tool_result if hasattr(e, "tool_result") else e


def _wait_authz_row(path, pred, timeout=3.0):
    """Shadow probes are async — poll the journal for the matching row."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for p, r, text, meta in _rows(path):
            if r == "authz" and pred(meta):
                return meta
        time.sleep(0.01)
    return None


# ─────────────────────────────────────────────────────────────────────────
# capability resolution expansion
# ─────────────────────────────────────────────────────────────────────────
def test_set_task_id_is_walk_and_enforced():
    cap = agentspp_authz.resolve_neon_capability("g1_set_task_id", {"task_id": 1})
    assert cap == "robot.motion.walk"
    assert agentspp_authz.is_enforced(cap)


def test_zerotorque_gets_its_own_capability_and_is_enforced():
    cap = agentspp_authz.resolve_neon_capability(
        "use_unitree", {"service_name": "loco", "operation_name": "ZeroTorque"}
    )
    assert cap == "robot.control.zerotorque"
    assert agentspp_authz.is_enforced(cap)


def test_unlisted_mutative_rpc_falls_back_to_sdk_rpc():
    for svc, op in (("loco", "BalanceStand"), ("motion_switcher", "SelectMode"),
                    ("loco", "LedControl")):
        cap = agentspp_authz.resolve_neon_capability(
            "use_unitree", {"service_name": svc, "operation_name": op}
        )
        assert cap == agentspp_authz.SDK_RPC_FALLBACK_CAPABILITY, (svc, op)
    # the fallback is shadow: it is audited, never blocking (913 scope)
    assert not agentspp_authz.is_enforced(agentspp_authz.SDK_RPC_FALLBACK_CAPABILITY)


def test_readonly_rpcs_stay_unmapped():
    for op in ("GetStatus", "Init", "CheckMode", "GetActionList"):
        assert agentspp_authz.resolve_neon_capability(
            "use_unitree", {"service_name": "loco", "operation_name": op}
        ) is None


def test_all_capabilities_includes_new_ones():
    assert "robot.control.zerotorque" in agentspp_authz.ALL_CAPABILITIES
    assert "robot.control.sdk.rpc" in agentspp_authz.ALL_CAPABILITIES


# ─────────────────────────────────────────────────────────────────────────
# persona x capability matrix
# ─────────────────────────────────────────────────────────────────────────
def test_matrix_shapes():
    m = agentspp_authz.PERSONA_CAPABILITY_MATRIX
    full = set(agentspp_authz.ALL_CAPABILITIES)
    for p in ("shell", "telegram", "thinker"):
        assert set(m[p]) == full, p
    for p in ("voice", "dashboard"):
        assert set(m[p]) == {"robot.motion.walk", "robot.motion.stop",
                             "robot.arm.gesture"}, p
    assert set(m["mcp"]) == {"robot.motion.stop", "robot.arm.gesture",
                             "robot.dds.publish.raw"}
    # the safety invariant survives the matrix: stop is granted to EVERYONE
    for p, caps in m.items():
        assert "robot.motion.stop" in caps, p


def test_unknown_persona_zero_trust():
    assert agentspp_authz.persona_caps("ghost") == []


def test_bootstrap_issues_persona_caps(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = _authed(monkeypatch)
    art = agentspp_authz._get_artifacts("voice")
    assert art is not None
    assert sorted(fake.last_caps) == sorted(["robot.arm.gesture",
                                             "robot.motion.stop", "robot.motion.walk"])


def test_mcp_vc_has_no_walk(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "enforce")
    fake = _authed(monkeypatch)
    art = agentspp_authz._get_artifacts("mcp")
    assert art is not None
    assert "robot.motion.walk" not in fake.last_caps
    assert "robot.control.fsm.change" not in fake.last_caps
    assert "robot.control.zerotorque" not in fake.last_caps
    assert "robot.control.sdk.rpc" not in fake.last_caps


def test_env_override_still_wins(monkeypatch):
    monkeypatch.setenv("NEON_AUTHZ_MODE", "shadow")
    monkeypatch.setenv("NEON_AUTHZ_VC_CAPABILITIES", "robot.motion.walk")
    fake = _authed(monkeypatch)
    art = agentspp_authz._get_artifacts("shell")
    assert fake.last_caps == ["robot.motion.walk"]


def test_mcp_server_declares_its_own_persona():
    src = (ROOT / "neon" / "mcp.py").read_text(encoding="utf-8")
    assert 'persona="mcp"' in src


# ─────────────────────────────────────────────────────────────────────────
# enforcement through the matrix (credential-emulating gate)
# ─────────────────────────────────────────────────────────────────────────
def test_mcp_cannot_walk_dedicated_tool(monkeypatch):
    """The --safe bypass, sealed: walk denied for mcp at the credential level."""
    fake = FakeClient()
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="mcp")

    events = _stream(t, {"toolUseId": "x-1", "input": {"angle": 0.5}})
    assert inner.calls == 0
    assert _payload(events)["content"][0]["text"].startswith("DENIED by authorization policy")


def test_mcp_cannot_walk_via_hammer(monkeypatch):
    """Same denial through use_unitree — the path --safe left open today."""
    fake = FakeClient()
    _authed(monkeypatch, fake)
    inner = _SpyInner("use_unitree")
    t = tool_log.LoggedTool(inner, persona="mcp")

    tu = {"toolUseId": "x-2", "input": {
        "service_name": "loco", "operation_name": "SetVelocity", "params": {}}}
    events = _stream(t, tu)
    assert inner.calls == 0
    assert _payload(events)["content"][0]["text"].startswith("DENIED by authorization policy")


def test_mcp_can_still_stop(monkeypatch):
    """Stop is granted to every persona — enforcement never blocks it."""
    fake = FakeClient()
    _authed(monkeypatch, fake)
    inner = _SpyInner("g1_stop_move")
    t = tool_log.LoggedTool(inner, persona="mcp")

    events = _stream(t, {"toolUseId": "x-3", "input": {}})
    assert inner.calls == 1
    assert _payload(events)["status"] == "success"


def test_shell_zerotorque_allowed(monkeypatch):
    """Faithful to today: zerotorque is not blocked (granted to full
    toolsets), but now it is ENFORCED-shaped and audited."""
    fake = FakeClient()
    _authed(monkeypatch, fake)
    inner = _SpyInner("use_unitree")
    t = tool_log.LoggedTool(inner, persona="shell")

    tu = {"toolUseId": "x-4", "input": {
        "service_name": "loco", "operation_name": "ZeroTorque", "params": {}}}
    events = _stream(t, tu)
    assert inner.calls == 1
    assert _payload(events)["status"] == "success"


def test_sdk_rpc_shadow_never_blocks(monkeypatch):
    """Unlisted mutative RPC for a persona without the cap: denied on
    paper (journal), executed in fact (shadow) — faithful to today's
    warn-only danger gate."""
    fake = FakeClient()
    _authed(monkeypatch, fake)
    inner = _SpyInner("use_unitree")
    t = tool_log.LoggedTool(inner, persona="mcp")

    tu = {"toolUseId": "x-5", "input": {
        "service_name": "loco", "operation_name": "BalanceStand", "params": {}}}
    events = _stream(t, tu)
    assert inner.calls == 1  # shadow: never gated
    meta = _wait_authz_row(
        agent_log.DB, lambda m: m and m.get("capability") == "robot.control.sdk.rpc"
    )
    assert meta is not None, "sdk.rpc fallback must be journaled"
    assert meta["decision"] == "deny"  # mcp VC has no sdk.rpc cap


def test_off_mode_matrix_inert(monkeypatch):
    fake = _authed(monkeypatch, mode="off")
    inner = _SpyInner("g1_turn")
    t = tool_log.LoggedTool(inner, persona="mcp")

    events = _stream(t, {"toolUseId": "x-6", "input": {"angle": 0.5}})
    assert inner.calls == 1
    assert fake.issued == {}  # no bootstrap, no VC, zero overhead
