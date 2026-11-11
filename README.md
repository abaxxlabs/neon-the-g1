<div align="center">

<img src="assets/neon.svg" alt="neon" width="100%"/>

# `neon`

**A Strands agent driving a Unitree G1+, running on the robot**

[![status](https://img.shields.io/badge/status-LIVE_on_G1-00ff88?style=flat-square)](https://cagataycali.github.io/neon-the-g1)
[![docs](https://img.shields.io/badge/docs-github.io-00cc60?style=flat-square)](https://cagataycali.github.io/neon-the-g1)
[![tools](https://img.shields.io/badge/tools-38-ff2a6d?style=flat-square)](https://cagataycali.github.io/neon-the-g1/tools/catalog/)
[![license](https://img.shields.io/badge/license-MIT-b967ff?style=flat-square)](LICENSE)

</div>

---

```
user (voice):  "wave at me"
    -> g1_arm_action(action_id=26)   rc=0, released
neon (chest):  *waves*

user (voice):  "walk forward thirty centimetres"
    -> take_photo("Is the path ahead clear for 0.3 m?")
    -> g1_walk_forward(distance=0.3)   moved=true, measured_m=0.28
neon (chest):  "Moved twenty-eight centimetres."
```

NEON is one agent with several personas: the chest speaker, Telegram, the
passkey-gated cockpit in a browser or on your phone, the REPL over SSH, and a
thinker that reflects every 30 s. They share one memory, one tool-call log and
one toolset: 38 robot tools (state, gestures, walking, audio, lidar,
DDS, cameras) plus 5 cross-persona tools. The model
is a Bedrock id you can change live from the cockpit; the voice runs on OpenAI
Realtime, Nova Sonic or Gemini Live; everything that touches a motor runs on
the Jetson over CycloneDDS.

**The docs are the site: [cagataycali.github.io/neon-the-g1](https://cagataycali.github.io/neon-the-g1)**
(3-minute tour, recipes, the tool catalog with counts derived from the code,
the eight safety gates, the runtime).

## see it move

<table>
<tr>
<td width="50%" align="center">

**arm the G1 (enable control)**

<img src="docs/assets/gifs/how-to-arm-the-g1.gif" width="100%"/>

Switch to walk/control mode in the Unitree app before anything can move.

</td>
<td width="50%" align="center">

**wave (dashboard)**

<img src="docs/assets/gifs/neon-wave.gif" width="100%"/>

A gesture triggered from the cockpit.

</td>
</tr>
<tr>
<td width="50%" align="center">

**walk forward (voice)**

<img src="docs/assets/gifs/move-forward.gif" width="60%"/>

Bidirectional speech to speech, then the walking tool, then the measured distance spoken back.

</td>
<td width="50%" align="center">

**walk backward (voice)**

<img src="docs/assets/gifs/move-backwards.gif" width="60%"/>

Same loop, reverse.

</td>
</tr>
</table>

## run

```bash
git clone https://github.com/cagataycali/neon-the-g1.git && cd neon-the-g1
cp .env.example .env && $EDITOR .env    # AWS_BEARER_TOKEN_BEDROCK, OPENAI_API_KEY, optional TELEGRAM_*
make run                                # compose up + attach to the REPL; voice auto-starts
```

The cockpit is up at `https://<robot>:8080` (open it through a hostname: WebAuthn
refuses raw IPs). `make down` stops everything.
[Quickstart](https://cagataycali.github.io/neon-the-g1/start/quickstart/),
[docker](https://cagataycali.github.io/neon-the-g1/start/docker/).

## deploy

Four containers (`neon-agent`, `neon-dashboard`, `neon-telegram`, `neon-thinker`)
plus two host units: `neon-voice` (the mic and ALSA need the host) and
`neon-ctl` (the dashboard's channel for recreating containers and restarting
voice). `make setup` is the shortcut; the full unit set with install lines is on
[systemd](https://cagataycali.github.io/neon-the-g1/start/systemd/).

The dashboard is the single owner of the USB cameras; every other persona pulls
frames from its snapshot API with a service token. The Jetson boots at 1970
until NTP, so the units wait for `time-sync.target` and `make token-refresh`
re-syncs a stale token.

```bash
make auth-status / auth-clear     # passkeys
make token-refresh                # camera-proxy service token into .env
make mute / unmute / voice-status # the voice flag the cockpit pill and voice_control share
make wifi SSID=x PASS=y           # companion WiFi; the robot answers at ubuntu.local
make help                         # every target
```

## safety

- Walking needs FSM 501 and your explicit request; the robot looks first,
  then measures its displacement and says "done" only when `moved=true`.
- Arm actions are mutex-locked on `rt/armsdk` and auto-release.
- Raw publishes to motor topics need `unsafe=True`; `use_unitree` flags the
  seven high-danger RPCs (always — the env-var warning bypass was removed in
  ABXAGNTS-914).
- FSM 0 (ZeroTorque) collapses the robot: gantry only.

[The eight gates](https://cagataycali.github.io/neon-the-g1/guide/safety/).

## authorization (Agents++ probe / enforcement)

Optional policy layer (ABXAGNTS-911/912/913/914): before mapped high-risk
operations (locomotion, FSM change, ZeroTorque, raw DDS publish, arm gestures,
and any other mutative SDK RPC) execute, NEON asks an
[Agents++](https://github.com/abaxxlabs/agentspp-strands-tools) instance
`/authorization/decide` and logs the ALLOW/DENY + `decision_id` to the journal
and the Activity Log (role `authz`).

- `shadow` — the decision is telemetry only; **never blocks a tool**.
- `enforce` (912/913) — for the enforcement set (`robot.motion.walk`,
  `robot.control.fsm.change`, `robot.control.zerotorque`,
  `robot.dds.publish.raw`) the probe runs synchronously and **gates
  execution**: allow runs the tool; deny, error or an unavailable Agents++
  instance means the tool never runs (fail closed), with an explicit deny
  reason. `robot.motion.stop` is deliberately not enforced — enforcement must
  never block stopping the robot. Arms and the generic `robot.control.sdk.rpc`
  fallback stay shadow (audited, not blocking).

**Policy lives in the credential (913).** Each persona bootstraps a VC that
carries only the capabilities in `PERSONA_CAPABILITY_MATRIX` — a faithful
extraction of NEON's pre-existing gates: local/telegram/thinker get the full
set, the slim voice/dashboard toolsets get walk+stop+arm, and the remote MCP
client cannot walk the robot (its `--safe` intent, which previously left the
`use_unitree` hammer open, is now sealed at the credential level). Every robot
mutation resolves to a capability, so no SDK RPC escapes the layer; reads stay
unmapped. Unknown personas get a zero-capability VC (zero trust).

```bash
pip install -e .[agentspp]   # or: pip install -e /path/to/agentspp-strands-tools
export NEON_AUTHZ_MODE=shadow          # off (default) | shadow | enforce
export AGENTSPP_BASE_URL=http://localhost:3100
# dev: mock human identity. prod: OIDC bearer token.
export NEON_AUTHZ_HUMAN_DID=did:web:neon-dev   # or AGENTSPP_BEARER_TOKEN=...
# optional: narrow the issued capabilities to observe DENY outcomes
export NEON_AUTHZ_VC_CAPABILITIES=robot.motion.walk,robot.dds.publish.raw
```

The probe is a no-op (zero overhead) unless `NEON_AUTHZ_MODE` is set and the
operation is mapped in `tools/agentspp_authz.py` — add a row (or a
`(service, operation)` pair) there to map a new operation; add the
capability to `ENFORCED_CAPABILITIES` to gate it in `enforce` mode; add the
persona to `PERSONA_CAPABILITY_MATRIX` to grant it capabilities.

**Rollout complete (914).** Operational guide — mode matrix, verification,
rollback (environment-only, validated), incident/recovery scenarios and the
post-rollout checklist: [`docs/guide/authz-runbook.md`](docs/guide/authz-runbook.md).
Cleanup delivered: `BYPASS_TOOL_CONSENT` removed (the danger warning is a
local control and no longer has an env-var off switch), `neon-mcp --safe`
deprecated as an authorization boundary (the mcp credential seals it) and
kept as a prompt-availability control, and the physical safety gates audited
+ tested (`tests/test_physical_safety.py`).

**Strands tools surface (927).** Every Agents++ operation NEON performs —
session/identity bootstrap, per-persona agent creation, credential issuance,
presentations and the per-operation decision — goes through the package's
`agents_*` Strands tools (`agents_create_session`, `agents_create_agent`,
`agents_issue_credential`, `agents_build_presentation`,
`agents_authorize_action`), never through the REST client directly. The
tools are invoked programmatically by app code and are **never registered on
the model's Agent**: a model that could call `agents_issue_credential` could
issue itself a VC with arbitrary capabilities (self privilege-escalation).

## MCP server

```bash
uvx --from neon-the-g1 neon-mcp --safe        # stdio for Claude Code / Desktop, no walking
neon-mcp --http --port 8022                    # HTTP, several clients
```

`claude mcp add neon -- uvx --from neon-the-g1 neon-mcp --safe`. Without
`--safe` a remote client can walk the robot; read
[AGENTS.md](AGENTS.md) first.

## more

- [strands-robots integration](https://cagataycali.github.io/neon-the-g1/guide/strands-robots/): MuJoCo sim and VLA policies next to the live DDS layer, `from neon import neon`
- [WebXR teleop](https://cagataycali.github.io/neon-the-g1/guide/webxr-teleop/): drive the arms from a Quest 3 browser
- [extending](https://cagataycali.github.io/neon-the-g1/guide/extending/): a tool, a persona, a doc page; `python3 -m pytest tests/` needs no robot
- [AGENTS.md](AGENTS.md): the rules the agents themselves read

Built on [strands-agents](https://github.com/strands-agents),
[devduck](https://github.com/cagataycali/devduck),
[unitree_sdk2_python](https://github.com/unitreerobotics/unitree_sdk2_python),
[CycloneDDS](https://github.com/eclipse-cyclonedds/cyclonedds). MIT license.
