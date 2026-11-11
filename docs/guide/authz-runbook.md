# authz runbook (Agents++ rollout)

Operational guide for the NEON × Agents++ authorization layer
(ABXAGNTS-911/912/913/914). The layer is a **policy plane in front of the
existing safety gates** — see [safety model](safety.md). It is entirely
optional at runtime: `NEON_AUTHZ_MODE=off` (the default) makes it a
zero-overhead no-op.

## mode matrix

| `NEON_AUTHZ_MODE` | behavior |
|---|---|
| *(unset)* / `off` | no bootstrap, no HTTP, no journal `authz` rows. Byte-identical behavior to pre-911 |
| `shadow` | probe + journal every mapped capability; **never blocks** |
| `enforce` | synchronous gate for the enforcement set — deny, gate error or **unavailable Agents++ instance = the tool does not run** (fail closed). Shadow caps still audited, never blocked |

Enforcement set (912/913): `robot.motion.walk` (incl. `g1_set_task_id` and
every walking SDK RPC), `robot.control.fsm.change`,
`robot.control.zerotorque`, `robot.dds.publish.raw`.

Never enforced: `robot.motion.stop` (granted to every persona — the layer
cannot block stopping the robot), `robot.arm.gesture`, `robot.control.sdk.rpc`.

## deployment

```bash
pip install -e .[agentspp]          # or: pip install -e /path/to/agentspp-strands-tools
export AGENTSPP_BASE_URL=http://localhost:3100   # the 909 server
export NEON_AUTHZ_MODE=shadow                      # off | shadow | enforce
export NEON_AUTHZ_HUMAN_DID=did:web:neon-dev       # dev identity
# prod identity: export AGENTSPP_BEARER_TOKEN=...  (OIDC)
# optional, dev-only: narrow the issued VC to observe DENY outcomes
# export NEON_AUTHZ_VC_CAPABILITIES=robot.motion.walk
```

Policy is **persona-driven** (913): each persona's VC carries the
capabilities of `PERSONA_CAPABILITY_MATRIX` — full local toolsets: all 7;
slim voice/dashboard: walk+stop+arm; mcp: stop+arm+dds (no walk); unknown
persona: zero (zero trust). There is no per-call policy configuration: to
change what a persona may do, change the matrix (code + PR) or narrow the VC
temporarily with `NEON_AUTHZ_VC_CAPABILITIES`.

## verification (per stage)

1. `make log-show` / dashboard activity log — every mapped op should show an
   `authz` row with `capability`, `decision` and `decision_id`.
2. Server side: `GET /authorization/decisions` (session-scoped) — same
   decision_ids persisted.
3. Deny drill (enforce): issue a narrow VC with
   `NEON_AUTHZ_VC_CAPABILITIES=robot.motion.stop`, call `g1_turn` → expect
   `DENIED by authorization policy: ... (decision_id=...)`, the robot does
   not move, the inner tool never runs.
4. Kill drill (enforce): stop the Agents++ server, call a forced op → expect
   fail-closed `DENIED ... artifacts unavailable`.

## rollback procedure

**Primary — environment only, no code rollback, no robot-side change:**

```bash
unset NEON_AUTHZ_MODE     # or: export NEON_AUTHZ_MODE=off
# restart the affected agent(s): neon-voice / telegram / dashboard / neon-mcp
```

Effect: layer is a no-op — no bootstrap, no HTTP calls, no `authz` rows,
tools execute exactly as pre-911. The eight physical/identity/prompt gates
(safety.md) are untouched by the layer and stay active. **Validated:**
off-mode tests (`tests/test_agentspp_*.py`) assert zero bootstrap and
unaffected execution, and a live run with the Agents++ server stopped and
`NEON_AUTHZ_MODE=off` confirmed the tools execute (ABXAGNTS-914 evidence).

**Secondary — code revert (only if the layer code itself misbehaves in a way
off mode cannot neutralize):** revert PRs #2/#3 (912/913) on
`abaxxlabs/neon-the-g1`; the 911 probe (PR #1) alone is already
non-blocking, so reverting down to PR #1 is a safe intermediate stop.

**Credential revocation** (targeted, no rollback): revoke the persona's VC in
Agents++ (`/authorization/revoke` or session teardown). Takes effect on the
next probe — no NEON restart — and in enforce mode the next forced op fails
closed.

## incident scenarios

| incident | symptoms | what to do |
|---|---|---|
| Agents++ server down (enforce) | forced ops: `DENIED ... artifacts unavailable`; shadow caps still run | restart the server (migrations already applied; no data loss — decisions are the audit trail, not state). No NEON restart needed: the next probe re-bootstraps after the 30 s failure cooldown |
| Agents++ server down (off/shadow) | off: nothing. shadow: `authz` rows with `error`, tools unaffected | same; shadow never blocks |
| unexpected DENY on a forced op | `DENIED by authorization policy: Action '...' not permitted (decision_id=…)` | look up the decision_id server-side to see the evaluated capability; check the persona's matrix row and VC caps. Fix the matrix/VC (or revoke+reissue). Emergency override: narrow-rollback to `off` if the robot is bricked on a *required* motion — but remember `stop` is never enforced, so the robot can always be stopped, not only started |
| a persona should not have a capability | shadow journal shows `allow` for a persona that must not have it | that persona is in the full-matrix tier: remove the capability from `PERSONA_CAPABILITY_MATRIX` (PR), or narrow the VC with `NEON_AUTHZ_VC_CAPABILITIES` for a hotfix, then revoke+reissue |
| unknown persona shows up (new channel) | stderr notice + zero-cap VC; every forced op fail-closed | expected zero-trust behavior; add the persona to the matrix |
| hammer RPC that no capability covers | `robot.control.sdk.rpc` shadow rows with `deny` for the persona | audited by design (shadow); if it must block, promote it to the enforcement set (PR + re-run the live kill drill) |
| credential rotation | decisions start failing after VC lifetime (1 h default) | the layer re-bootstraps automatically after the failure cooldown; no action needed |

**Recovery invariant:** in every scenario the physical safety gates
(clamps, FSM, arm mutex, `unsafe=True`, honesty) remain active, and
`g1_stop_move` / `use_unitree("loco","SetFsmId",{"fsm_id":1})` are always
reachable — the authorization layer can deny *starting* motion, never
*stopping* it.

## post-rollout verification checklist

| stage | check | status / evidence |
|---|---|---|
| 911 shadow | allow+deny journaled with decision_ids; off mode inert; 21 tests | ✅ merged (PR #1), live-verified — Jira ABXAGNTS-911 |
| 912 enforce | walk/fsm/dds gated fail-closed; stop never gated; 25 tests | ✅ merged (PR #2), live ALLOW `decision_id=edeed0aa…` / DENY `9fc15325…`, kill drill `artifacts unavailable` — Jira ABXAGNTS-912 |
| 913 matrix + map | persona VCs (mcp no walk, ghost zero-trust); `g1_set_task_id`+ZeroTorque mapped; hammer fallback; mcp identity; 17 tests | ✅ PR #3, live: mcp walk DENY on both paths (`f60252da…`/`3c6720bd…`), zerotorque allow `02b13dc8…`, 8 decisions persisted — Jira ABXAGNTS-913 |
| 914 cleanup | `BYPASS_TOOL_CONSENT` removed (danger warning always on); `--safe` deprecated as authz (credential seals it); physical gates intact + tested; this runbook | ✅ this PR |
| cleanup (future, 909 merge) | Agents++ server deploys as durable infrastructure; `NEON_AUTHZ_HUMAN_DID` dev identity retired in favor of OIDC bearer | ⬜ tracked under ABXAGNTS-787 |

## related

- [safety model](safety.md) — the eight gates the layer composes with
- [use_unitree](../tools/use-unitree.md) — the hammer, its danger flags and the sdk.rpc fallback
- `tools/agentspp_authz.py` — capability map, matrix, enforcement set
- `tests/test_agentspp_authz.py` / `test_agentspp_enforcement.py` / `test_agentspp_expansion.py`

---

[safety model](safety.md){ .md-button } [architecture](architecture.md){ .md-button }
