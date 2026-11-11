"""ABXAGNTS-927: the agents_* Strands tools surface is NEON's ONLY Agents++ path.

- every Agents++ operation goes through the package's Strands tools, never a
  direct REST-client call in the authz module
- the five tools are invoked programmatically and NEVER part of any
  model-facing toolset (a model that could call agents_issue_credential
  could self-issue capabilities)
"""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import agentspp_strands_tools as pkg  # noqa: E402

from tools import agentspp_authz  # noqa: E402

_EXPECTED_SURFACE = {
    "agents_create_session",
    "agents_create_agent",
    "agents_issue_credential",
    "agents_build_presentation",
    "agents_authorize_action",
}


def test_authz_module_makes_no_direct_client_calls():
    """AC1: the authz module never calls the REST client's methods or the
    gate helper directly — only the agents_* tools (built by the package)."""
    src = (ROOT / "tools" / "agentspp_authz.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    banned = {
        "create_session", "create_agent", "issue_credential",
        "build_presentation", "authorize_action", "run_authorization_gate",
    }
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in banned:
                offenders.append(ast.unparse(node.func))
    assert not offenders, f"direct Agents++ calls found: {offenders}"


def test_authz_tools_surface_is_exactly_the_five(monkeypatch):
    class _Fake:
        base_url = "fake"

    monkeypatch.setattr(pkg, "default_client", lambda *a, **k: _Fake())
    agentspp_authz._tools_cache.clear()
    tools = agentspp_authz._authz_tools()
    assert set(tools) == _EXPECTED_SURFACE
    for t in tools.values():  # real strands tool objects
        assert hasattr(t, "tool_name")


def test_surface_is_a_subset_of_the_package_toolset():
    """The five tools are the package's own (host-agnostic) toolset, not a
    local re-implementation."""
    class _Fake:
        base_url = "fake3"

    full = {t.tool_name for t in pkg.create_agentspp_tools(_Fake())}
    assert _EXPECTED_SURFACE <= full
    assert len(full) >= 15, "package toolset shrank — check the integration"


def test_no_model_facing_agents_tools():
    """AC3: the toolsets the model sees must contain zero agents_* tools."""
    # Source-level (g1.py is not importable on non-robot dev machines):
    # neither the robot builders nor the MCP server may pull the package's
    # toolset into the model's toolset.
    for rel in ("g1.py", "neon/mcp.py", "agent.py", "telegram_listener.py",
                "thinker_loop.py", "g1_speech_listener.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "create_agentspp_tools" not in src, rel
    # Dynamic, when the full toolchain is importable (robot box / docker):
    try:
        from g1 import build_tools, build_voice_tools
    except ImportError:
        return
    for built in (build_tools(), build_voice_tools()):
        names = {getattr(t, "tool_name", getattr(t, "__name__", "")) for t in built}
        agents_tools = {n for n in names if n.startswith("agents_")}
        assert not agents_tools, f"model-facing Agents++ tools leaked: {agents_tools}"
