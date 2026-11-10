"""Agents++ authorization probe for NEON tool calls (ABXAGNTS-911, shadow phase).

What this is
    Before a mapped (high-risk) operation executes, ask Agents++
    ``POST /authorization/decide`` (via the ``agentspp-strands-tools``
    package) and record the ALLOW/DENY + ``decision_id`` in the journal
    (stderr) and in ``agent_log`` under role="authz". Shadow mode: the
    decision is telemetry — it never blocks the tool. Blocking enforcement
    is a later phase (ABXAGNTS-912/913) and will call ``probe(...,
    blocking=True)``.

What this is NOT
    - The capability vocabulary owner is NEON: the maps below define
      NEON's own ``operation -> capability`` names. The package is
      host-agnostic and ships none of them.
    - Not a safety mechanism. FSM/locks/clamps inside the tools stay as
      they are; the gate answers "is this agent allowed", not "is this
      physically safe".

Modes — ``NEON_AUTHZ_MODE`` env, default ``off`` (behavioral baseline):
    off      no Agents++ calls, zero overhead
    shadow   probe mapped operations, log the decision, never block
    enforce  ABXAGNTS-912: for ``ENFORCED_CAPABILITIES`` the probe runs
             synchronously and GATES execution — allow runs the tool,
             deny / error / unavailable means the tool NEVER runs
             (fail closed), with an explicit deny reason returned to the
             caller/persona. All other mapped capabilities keep shadow
             (async, log only) behavior.

Other env vars:
    AGENTSPP_BASE_URL            Agents++ instance (default http://localhost:3100)
    AGENTSPP_BEARER_TOKEN        production OIDC token for the session
    NEON_AUTHZ_HUMAN_DID         mock human DID in dev (default did:web:neon-dev)
    NEON_AUTHZ_VC_CAPABILITIES   comma-separated capability subset to issue in
                                 the VC — OVERRIDES the persona matrix (dev
                                 knob to observe DENY outcomes).

ABXAGNTS-913 (persona matrix)
    The VC each persona bootstraps carries only the capabilities in
    ``PERSONA_CAPABILITY_MATRIX`` — policy lives in the credential, decided
    server-side by /authorization/decide. The matrix is a faithful extraction
    of NEON's pre-existing hardcoded gates (docs/guide/safety.md, neon-mcp
    --safe, slim voice toolsets); it invents no new restrictions. Unknown
    personas get a zero-capability VC (zero trust). Every robot MUTATION now
    resolves to a capability (the use_unitree hammer's unlisted mutative RPCs
    fall back to ``robot.control.sdk.rpc``); only reads stay unmapped.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, Dict, List, Mapping, Optional

# ─────────────────────────────────────────────────────────────────────────
# NEON operation -> capability vocabulary
# First wave (assessment §9.1): walk / FSM change / raw DDS publish.
# Arm gestures (assessment §9.2) included: they physically move the robot.
# Adding a row here is how the enforcement scope grows in later phases.
# ─────────────────────────────────────────────────────────────────────────
NEON_OPERATION_CAPABILITY_MAP: Dict[str, str] = {
    # locomotion (tools/g1_locomotion.py)
    "g1_move_velocity": "robot.motion.walk",
    "g1_walk_forward": "robot.motion.walk",
    "g1_turn": "robot.motion.walk",
    "g1_wave_hand_loco": "robot.motion.walk",
    "g1_shake_hand_loco": "robot.motion.walk",
    # ABXAGNTS-913: raw locomotion-task dispatch is leg motion — it must go
    # through the same capability as walking (it bypassed the 912 gate).
    "g1_set_task_id": "robot.motion.walk",
    "g1_stop_move": "robot.motion.stop",
    # arm (tools/g1_arm.py)
    "g1_arm_action": "robot.arm.gesture",
    "g1_release_arm": "robot.arm.gesture",
    # DDS escape hatch (tools/g1_dds.py)
    "g1_dds_publish": "robot.dds.publish.raw",
}

# use_unitree is the universal SDK hammer: resolve (service, operation).
_USE_UNITREE_OPS: Dict[tuple, str] = {
    ("loco", "SetFsmId"): "robot.control.fsm.change",
    ("loco", "SetVelocity"): "robot.motion.walk",
    ("loco", "Move"): "robot.motion.walk",
    ("loco", "WaveHand"): "robot.motion.walk",
    ("loco", "ShakeHand"): "robot.motion.walk",
    ("loco", "StopMove"): "robot.motion.stop",
    # ABXAGNTS-913: the collapse op gets its own auditable capability
    # (today it only produced a warning, no decision).
    ("loco", "ZeroTorque"): "robot.control.zerotorque",
    ("motion_switcher", "ReleaseMode"): "robot.control.fsm.change",
}

# ABXAGNTS-913: the hammer can reach ANY SDK RPC; the listed ops above get
# specific capabilities, every OTHER mutative RPC falls back to this one so
# no robot mutation escapes the permission layer. Read-only ops (Get*/Check*/
# whitelist) stay unmapped — there is no robot policy about reads.
SDK_RPC_FALLBACK_CAPABILITY = "robot.control.sdk.rpc"

# Mirrors tools/use_unitree.py (MUTATIVE_PREFIXES / READONLY_WHITELIST).
# Kept local so the authz path has no import dependency on the SDK hammer;
# if the source lists change, change these too.
_MUTATIVE_PREFIXES = (
    "Set", "Execute", "Move", "Start", "Stop", "Damp",
    "Sit", "HighStand", "LowStand", "WaveHand", "ShakeHand",
    "Squat2StandUp", "Lie2StandUp", "StandUp2Squat",
    "BalanceStand", "ZeroTorque",
    "LedControl", "TtsMaker", "PlayStream", "PlayStop",
    "SelectMode", "ReleaseMode",
)
_READONLY_WHITELIST = {
    "CheckMode", "GetActionList", "GetVolume", "GetBrightness", "GetSwitch",
    "Init",  # idempotent singleton init
}


def _unitree_op_is_mutative(operation_name: str) -> bool:
    if operation_name in _READONLY_WHITELIST:
        return False
    return any(operation_name.startswith(p) for p in _MUTATIVE_PREFIXES)

ALL_CAPABILITIES: List[str] = sorted(
    set(NEON_OPERATION_CAPABILITY_MAP.values())
    | set(_USE_UNITREE_OPS.values())
    | {SDK_RPC_FALLBACK_CAPABILITY}
)

# ─────────────────────────────────────────────────────────────────────────
# ABXAGNTS-912: the enforcement set.
# In `enforce` mode, operations resolving to one of these capabilities run
# the probe synchronously and the decision gates execution:
#   allow            -> the tool runs
#   deny             -> the tool NEVER runs, explicit reason returned
#   error/unavailable-> fail closed (same as deny)
# Every other mapped capability stays shadow (async probe, log only):
#   robot.arm.gesture   — no permission policy exists today (only the mutex)
#   robot.motion.stop   — enforcement must never prevent stopping the robot
#   robot.control.sdk.rpc — the hammer's mutative fallback; flagged today,
#                           audited (shadow) here, not blocked
# ABXAGNTS-913 added zerotorque (was an unprobed hole) and the sdk.rpc
# fallback; the set grows here.
# ─────────────────────────────────────────────────────────────────────────
ENFORCED_CAPABILITIES = frozenset({
    "robot.motion.walk",
    "robot.control.fsm.change",
    "robot.control.zerotorque",
    "robot.dds.publish.raw",
})


def is_enforced(capability: Optional[str]) -> bool:
    """True when a capability is in the 912 enforcement set."""
    return capability in ENFORCED_CAPABILITIES


def enforcement_active(
    tool_name: str, args: Optional[Mapping[str, Any]] = None
) -> bool:
    """True when a call to this operation is gated in enforce mode."""
    return authz_mode() == "enforce" and is_enforced(
        resolve_neon_capability(tool_name, args)
    )


def resolve_neon_capability(
    tool_name: str, args: Optional[Mapping[str, Any]] = None
) -> Optional[str]:
    """NEON's own operation -> capability resolution. None = not mapped."""
    cap = NEON_OPERATION_CAPABILITY_MAP.get(tool_name)
    if cap:
        return cap
    if tool_name == "use_unitree" and isinstance(args, Mapping):
        key = (str(args.get("service_name", "")), str(args.get("operation_name", "")))
        if key in _USE_UNITREE_OPS:
            return _USE_UNITREE_OPS[key]
        # ABXAGNTS-913: unlisted mutative RPCs fall back to the generic
        # hammer capability so no mutation escapes the permission layer.
        if _unitree_op_is_mutative(key[1]):
            return SDK_RPC_FALLBACK_CAPABILITY
    return None


# ─────────────────────────────────────────────────────────────────────────
# ABXAGNTS-913: persona x capability matrix.
# Policy = the credential. Each persona's VC carries only the capabilities
# its channel's EXISTING toolset/policy allows (faithful extraction of the
# hardcoded gates — docs/guide/safety.md, neon-mcp --safe, slim toolsets):
#   - shell/telegram/thinker: full toolset (G1_ALL_TOOLS) -> every capability.
#     Telegram's human allowlist (gate 1) is identity, not capability, and
#     stays where it is.
#   - voice/dashboard: slim toolset (no use_unitree, no g1_dds_publish).
#   - mcp: remote client. Documented --safe default is "state/arms/audio/
#     sensing only" — it cannot walk the robot. The flag only filtered
#     locomotion tools by name and left use_unitree in place; the
#     credential-level denial below seals that bypass (walk/fsm/zerotorque/
#     sdk.rpc all resolve to capabilities the mcp VC does not carry).
# Unknown personas get a ZERO-capability VC (zero trust): enforced calls
# deny, shadow calls log deny, nothing is silently granted.
# ─────────────────────────────────────────────────────────────────────────
_ALL_CPS = {
    "walk": "robot.motion.walk",
    "stop": "robot.motion.stop",
    "arm": "robot.arm.gesture",
    "fsm": "robot.control.fsm.change",
    "ztq": "robot.control.zerotorque",
    "dds": "robot.dds.publish.raw",
    "rpc": "robot.control.sdk.rpc",
}

PERSONA_CAPABILITY_MATRIX: Dict[str, List[str]] = {
    "shell":    [_ALL_CPS[k] for k in ("walk", "stop", "arm", "fsm", "ztq", "dds", "rpc")],
    "telegram": [_ALL_CPS[k] for k in ("walk", "stop", "arm", "fsm", "ztq", "dds", "rpc")],
    "thinker":  [_ALL_CPS[k] for k in ("walk", "stop", "arm", "fsm", "ztq", "dds", "rpc")],
    "voice":    [_ALL_CPS[k] for k in ("walk", "stop", "arm")],
    "dashboard": [_ALL_CPS[k] for k in ("walk", "stop", "arm")],
    "mcp":      [_ALL_CPS[k] for k in ("stop", "arm", "dds")],
}


def persona_caps(persona: str) -> List[str]:
    """Capabilities to issue in this persona's VC (see matrix above)."""
    caps = PERSONA_CAPABILITY_MATRIX.get(persona)
    if caps is None:
        _notice_once(
            f"persona:{persona}",
            f"unknown persona '{persona}' for the Agents++ capability matrix — "
            f"issuing a zero-capability VC (zero trust). Add it to "
            f"PERSONA_CAPABILITY_MATRIX to grant capabilities.",
        )
        return []
    return list(caps)


_VALID_MODES = ("off", "shadow", "enforce")


def authz_mode() -> str:
    m = os.getenv("NEON_AUTHZ_MODE", "off").strip().lower()
    return m if m in _VALID_MODES else "off"


# ─────────────────────────────────────────────────────────────────────────
# Artifact bootstrap (per persona): session -> agent -> VC -> VP
# ─────────────────────────────────────────────────────────────────────────
_RETRY_COOLDOWN_S = 60.0
_lock = threading.Lock()
_artifacts: Dict[str, Dict[str, Any]] = {}
_failed_at: Dict[str, float] = {}
_noticed: set = set()


def _notice_once(key: str, msg: str) -> None:
    if key in _noticed:
        return
    _noticed.add(key)
    try:
        print(f"[authz] {msg}", file=sys.stderr, flush=True)
    except Exception:
        pass


def _load_package():
    """Import the package lazily so NEON runs fine without it installed."""
    try:
        import agentspp_strands_tools as pkg
        return pkg
    except Exception as e:
        _notice_once(
            "pkg",
            f"NEON_AUTHZ_MODE is set but agentspp-strands-tools is not "
            f"importable: {e!r}. Install it (pip install "
            f"-e /path/to/agentspp-strands-tools, or the [agentspp] extra). "
            f"Probes disabled.",
        )
        return None


def _get_artifacts(persona: str) -> Optional[Dict[str, Any]]:
    """Provision (and cache) session/agent_did/vc/vp for a persona.

    Returns None on failure; retries are rate-limited to one attempt per
    ``_RETRY_COOLDOWN_S`` so a downed Agents++ instance can't storm the
    tool path.
    """
    pkg = _load_package()
    if pkg is None:
        return None
    with _lock:
        cached = _artifacts.get(persona)
        if cached:
            return cached
        last = _failed_at.get(persona)
        if last is not None and time.monotonic() - last < _RETRY_COOLDOWN_S:
            return None
    try:
        client = pkg.default_client()  # reads AGENTSPP_BASE_URL
        bearer = os.getenv("AGENTSPP_BEARER_TOKEN")
        session_resp = (
            client.create_session(bearer_token=bearer)
            if bearer
            else client.create_session(
                mock_human_did=os.getenv("NEON_AUTHZ_HUMAN_DID", "did:web:neon-dev")
            )
        )
        session = session_resp["sessionId"]
        agent = client.create_agent(session, name=f"neon-{persona}")
        agent_did = agent["did"]
        caps_env = os.getenv("NEON_AUTHZ_VC_CAPABILITIES", "")
        caps = (
            [c.strip() for c in caps_env.split(",") if c.strip()]
            if caps_env
            else persona_caps(persona)
        )
        vc = client.issue_credential(
            session, agent_did, profile="capability",
            capabilities=[{"action": c} for c in caps],
        )
        if isinstance(vc, Mapping):
            vc = vc.get("vc") or vc.get("credential")
        pres = client.build_presentation(session, agent_did, vc)
        vp = pres["presentation"] if isinstance(pres, Mapping) else pres
        artifacts = {
            "session": session,
            "agent_did": agent_did,
            "vc": vc,
            "vp": vp,
            "capabilities": ",".join(caps),
        }
        with _lock:
            _artifacts[persona] = artifacts
            _failed_at.pop(persona, None)
        print(
            f"[authz] artifacts ready persona={persona} agent={agent_did} "
            f"capabilities={artifacts['capabilities']}",
            file=sys.stderr, flush=True,
        )
        return artifacts
    except Exception as e:
        with _lock:
            _failed_at[persona] = time.monotonic()
        _notice_once(
            f"bootstrap:{persona}",
            f"Agents++ artifact bootstrap failed (persona={persona}): {e!r}. "
            f"Retrying at most every {_RETRY_COOLDOWN_S:.0f}s.",
        )
        return None


def _reset_bootstrap_state() -> None:
    """Test hook: clear caches so a test can re-provision."""
    with _lock:
        _artifacts.clear()
        _failed_at.clear()
    _noticed.clear()


# ─────────────────────────────────────────────────────────────────────────
# The probe
# ─────────────────────────────────────────────────────────────────────────
def _probe_sync(
    tool_name: str,
    args: Optional[Mapping[str, Any]],
    persona: str,
    capability: str,
    tool_use_id: Optional[str],
) -> Optional[Any]:
    """Run one decide call and record the outcome. Never raises."""
    from . import agent_log

    mode = authz_mode()
    meta: Dict[str, Any] = {
        "tool": tool_name,
        "capability": capability,
        "mode": mode,
        "decision": None,
        "decision_id": None,
        "reason": None,
        "error": None,
    }
    if mode == "enforce" and is_enforced(capability):
        meta["enforced"] = True
    if tool_use_id:
        meta["tool_use_id"] = tool_use_id

    artifacts = _get_artifacts(persona)
    if artifacts is None:
        meta["reason"] = "artifacts unavailable"
    else:
        pkg = _load_package()
        # A presentation is single-use (anti-replay nonce is consumed by the
        # first decide that carries it), so every probe mints a fresh one
        # from the cached VC. Only on a present failure do we fall back to a
        # bootstrap-time presentation (test doubles / degraded shadow).
        vp = None
        present_error = None
        try:
            pres = pkg.default_client().build_presentation(
                artifacts["session"], artifacts["agent_did"], artifacts["vc"]
            )
            vp = pres["presentation"] if isinstance(pres, Mapping) else pres
        except Exception as e:
            present_error = e
        if vp is None:
            vp = artifacts.get("vp")
        if vp is None:
            meta["error"] = {"message": f"presentation failed: {present_error!r}"}
        else:
            try:
                res = pkg.run_authorization_gate(
                    pkg.default_client(),
                    mode,
                    session=artifacts["session"],
                    agent_did=artifacts["agent_did"],
                    persona=persona,
                    channel=persona,
                    tool=tool_name,
                    operation=tool_name,
                    vc=artifacts["vc"],
                    vp=vp,
                    capability=capability,
                    context={"args": dict(args) if isinstance(args, Mapping) else args},
                )
                decision = res.decision or {}
                meta["decision"] = decision.get("decision")
                meta["decision_id"] = decision.get("decision_id")
                meta["reason"] = decision.get("reason") or res.reason
                # Capture the whole error mapping — the gate may carry a
                # {"message": ...} shape that has no status/error keys.
                meta["error"] = dict(res.error) if res.error else None
            except Exception as e:  # the gate contract is never-raise; belt & braces
                meta["reason"] = f"gate error: {e!r}"

    verdict = meta["decision"] or ("ERROR" if meta["error"] or meta["reason"] == "artifacts unavailable" else "UNKNOWN")
    line = (
        f"[authz-{mode} {persona}] {tool_name} cap={capability} "
        f"-> {verdict} decision_id={meta['decision_id']} "
        f"reason={meta['reason'] or ''}"
    )
    try:
        print(line, file=sys.stderr, flush=True)
    except Exception:
        pass
    try:
        agent_log.record(persona, "authz", line[:2000], meta=meta)
    except Exception:
        pass
    return meta


def probe(
    tool_name: str,
    args: Optional[Mapping[str, Any]],
    persona: str,
    tool_use_id: Optional[str] = None,
    blocking: bool = False,
) -> Optional[Any]:
    """Pre-invocation authorization probe / gate.

    No-op (returns None) unless ``NEON_AUTHZ_MODE`` is shadow/enforce AND
    the operation resolves to a capability. Behavior by mode:

    - shadow (or enforce for non-enforced capabilities): the probe runs on
      a daemon thread so the tool path (especially the latency-critical
      voice path) never waits on Agents++. Returns None (fire-and-forget).
    - enforce + ``ENFORCED_CAPABILITIES`` (ABXAGNTS-912): runs the probe
      synchronously and returns its meta. The caller applies
      :func:`enforcement_verdict` to gate execution (fail closed).
    - ``blocking=True``: force the synchronous path (test hook).
    """
    try:
        if authz_mode() == "off":
            return None
        capability = resolve_neon_capability(tool_name, args)
        if capability is None:
            return None
        if blocking or (authz_mode() == "enforce" and is_enforced(capability)):
            return _probe_sync(tool_name, args, persona, capability, tool_use_id)
        threading.Thread(
            target=_probe_sync,
            args=(tool_name, args, persona, capability, tool_use_id),
            daemon=True,
        ).start()
        return None
    except Exception as e:  # the authz path must never take down a tool
        _notice_once(f"probe:{tool_name}", f"authz probe failed: {e!r}")
        return None


def enforcement_verdict(meta: Optional[Mapping[str, Any]]) -> tuple:
    """Map a synchronous probe meta to ``(verdict, reason)`` for gating.

    Fail closed: ANY meta without a usable ``allow`` decision — deny,
    error, missing artifacts, None — yields ``("deny", reason)``. The
    reason is the explicit message returned to the caller/persona.
    """
    if not isinstance(meta, Mapping):
        return ("deny", "authorization service unavailable")
    decision = meta.get("decision")
    reason = meta.get("reason")
    if decision == "allow":
        return ("allow", reason or "allowed by credential")
    if decision == "deny":
        return ("deny", reason or "capability not in credential")
    err = meta.get("error")
    err_msg = None
    if isinstance(err, Mapping):
        err_msg = err.get("message") or err.get("error")
    return ("deny", reason or err_msg or "authorization service unavailable")


def deny_payload(reason: str, decision_id: Optional[str] = None) -> Dict[str, Any]:
    """Strands-shaped ToolResult for a denied operation.

    ``status`` is ``error`` (the only valid non-success status in the
    strands ToolResult contract); the explicit denial lives in the text
    so the model/persona hears it, and in the json block for machines.
    """
    text = f"DENIED by authorization policy: {reason}"
    if decision_id:
        text += f" (decision_id={decision_id})"
    return {
        "status": "error",
        "content": [
            {"text": text},
            {"json": {"denied": True, "reason": reason, "decision_id": decision_id}},
        ],
    }
