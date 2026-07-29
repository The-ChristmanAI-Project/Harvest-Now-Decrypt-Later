# The Glove Layer — Reference Implementation Skeleton

A Python skeleton of **GLV-SPEC-1.0.0** (*Specification: The Glove Layer —
Universal Neural Interface Sheet for Autonomous Beings → Any Robotic System*).
See `docs/GLOVE_SPECIFICATION.md` in this repository (the single source of truth).

The Glove is a **liner, not a brain** (§1.4): it translates the Neural Contract,
enforces physical limits, and relays governance unchanged. It contains **no
planning, no learning, no goal generation, and no policy interpretation** (§1.3).

- **Minimal runtime deps** (Python ≥ 3.11): `cryptography` only; `pytest` is a dev dep.
- **Optional family crypto**: install `christman-crypto` (this repo) to harden
  continuity-packet sealing (AES-256-GCM, Tier 2) and capability-descriptor
  signing (RSA-PSS-4096, Tier 6) via `glove/family_crypto.py` — automatic
  stdlib fallback when absent.
- **Offline-first**: everything runs locally, in-process (REQ-OF-01). No network calls anywhere.

## Quickstart

```bash
# from the repository root (glove/ lives at the root)
pip install -e .
pytest tests/glove                    # 90 tests (77 core + 13 family-crypto)
python3 examples/glove_drop_in_demo.py
```

Minimal usage — the being side is identical for every body:

```python
from glove import Glove, LocomotionAction, LocomotionMode, Twist
from glove.adapter.examples.mock_humanoid import MockHumanoidAdapter

glove = Glove()
glove.attach_adapter(MockHumanoidAdapter())     # §4.1 lifecycle to ACTIVE
welcome = glove.hello(being_id="…uuid…", supported_versions=["1.0.0"])  # REQ-CV-02
glove.accept(welcome)                           # no traffic before ACCEPT
ack = glove.submit_action(LocomotionAction(
    mode=LocomotionMode.VELOCITY, twist=Twist((0.4, 0, 0), (0, 0, 0.15))))
```

## Architecture map (code → spec sections)

| Path | Spec section | What it does |
|---|---|---|
| `glove/contract/envelope.py` | §3.0 | Common message envelope: ids, monotonic `t_emit_ns`, per-session `seq`, semver, QoS classes (`RT`/`FAST`/`EVENT`/`GOV`), namespaced extensions (REQ-CV-05) |
| `glove/contract/actions.py` | §3.1 | Action dataclasses (locomotion, manipulation, speech/gesture, attention, tool, raw gated channel) + validation + ack events (REQ-AC-01…06) |
| `glove/contract/sensory.py` | §3.2 | Sensory dataclasses (proprio, contact/tactile, vision summary, audio, internal), SI units (REQ-SC-01), canonical frames (REQ-SC-02), joint normalization constants (REQ-SC-04), dropout/staleness (REQ-AD-09) |
| `glove/contract/capabilities.py` | §3.3 | Signed capability descriptor (REQ-CV-03), HELLO/WELCOME/ACCEPT handshake (REQ-CV-02), MAJOR-version rule (REQ-CV-01), graceful degradation (REQ-CV-06), SIMULATED declaration (REQ-CV-07) |
| `glove/family_crypto.py` | §7.1, §3.3 | Optional family crypto bridge: AES-256-GCM packet sealing (Tier 2) and RSA-PSS-4096 descriptor signing (Tier 6) with automatic stdlib fallback and unchanged schemas |
| `glove/adapter/base.py` | §4 | `RobotAdapter` ABC: discover/connect/calibrate/activate/deactivate/disconnect, motion inhibition (REQ-AD-02), dispatch/halt (REQ-AD-04…06), physical limits (REQ-AD-10), fault reporting, no FATAL auto-recovery (REQ-AD-12) |
| `glove/adapter/examples/` | §4, App. B | Three simulated bodies with **different capability subsets**: mobile base, industrial arm, humanoid — demonstrating negotiation + degradation |
| `glove/mapping/engine.py` | §2.3, §9.4 | Deterministic, table-driven being↔robot mapping; static, versioned, hashed tables only — **no learned components** (REQ-CF-08) |
| `glove/safety/envelope.py` | §6 | Composed, hash-stamped envelope (REQ-SE-03); clip-or-refuse, never originate (REQ-SE-02); per-joint velocity clipping for `JOINT_TRAJ` (REQ-SE-01); self-collision volumes expressed as `forbidden_zones`; per-message dead-man (`duration_s` / `expires_ns`, REQ-SE-04); watchdog/e-stop/impact halt (REQ-SE-05); degraded modes HOLD/RETREAT/PARK (REQ-SE-06); audited decisions (REQ-SE-08). Jerk limits are adapter-declared constraints enforced inside native trajectory time-parameterization |
| `glove/governance/bus.py` | §5 | **Strictly pass-through** bus: opaque authenticated ordered transport; classes CONSENSUS/PULSE/ESCALATION/OVERRIDE/RING4/POLICY; payloads never parsed or mutated (INV-1, REQ-GV-06); zero synthesis (REQ-GV-07); override preemption (REQ-GV-04); local Pulse Tether measurement (REQ-GV-05) |
| `glove/continuity/packet.py` | §7.1 | Versioned continuity packet: identity, opaque context handle, opaque governance snapshot, calibration artifacts, schema versions; integrity-signed, hash-chained, sealed at rest (REQ-ST-01/02/03, REQ-GV-10) |
| `glove/continuity/hotswap.py` | §7.2 | Transfer state machine QUIESCE→SNAPSHOT→DETACH→ATTACH→CALIBRATE→RESUME with REQ-ST-06 rollback paths |
| `glove/core/glove.py` | §2 | `Glove`: thin orchestration wiring contract↔mapping↔envelope↔adapter + audit log (REQ-CF-09). **No decision-making** |

## Tests (90)

| File | Proves |
|---|---|
| `tests/glove/test_contract_schemas.py` | §3 schema validation, ranges, quat norm, frames, semver (REQ-AC-01, REQ-SC-01/02/04, REQ-CV-01/05) |
| `tests/glove/test_handshake_degradation.py` | Handshake ordering, clean DECLINE on version mismatch (CF-T-CON-02), CAPABILITY_ABSENT degradation, signed descriptors, SIMULATED visibility |
| `tests/glove/test_safety_envelope.py` | Clipping with correct deltas (CF-T-ACT-02), forbidden-zone refusal, dead-man stop (CF-T-ACT-01), watchdog/impact halt, degraded modes, policy-only-tightens, non-origination |
| `tests/glove/test_governance_passthrough.py` | **Byte-identical payload in/out**, bit-flip rejection (CF-T-GOV-01), ordering + GOV_UNDELIVERED, zero synthesized governance (CF-T-GOV-04), override preemption (CF-T-GOV-02), Pulse Tether fail-closed (CF-T-GOV-03) |
| `tests/glove/test_hotswap.py` | Full transfer across two bodies (CF-T-ST-01), forced-failure rollback at each stage (CF-T-ST-02), tampered/stale packet detection (CF-T-ST-03) |
| `tests/glove/test_conformance_smoke.py` | One being stub drives all three adapters unchanged — the zero-being-modification proof (CR-5) |
| `tests/glove/test_family_crypto.py` | Family AES-256-GCM seal/open round-trip + tamper detection, RSA-PSS descriptor sign/verify + wrong-key/tamper rejection, automatic stdlib fallback with no schema fork |

## How to add a new robot

Implement **`RobotAdapter`** (`glove/adapter/base.py`) — nothing else (REQ-AD-00):

1. `_discover_impl` — enumerate instances; return `[]` on failure, never throw.
2. `_connect_impl(handle)` — open transport, verify firmware; motion stays inhibited automatically.
3. `_calibrate_impl(profile)` — load/compute calibration (accept a continuity-packet profile when present), return a **signed `CapabilityDescriptor`** that faithfully reflects the physical robot (REQ-AD-03).
4. `_activate_impl` / `_deactivate_impl(mode)` / `_disconnect_impl` — lifecycle hooks.
5. `_dispatch_impl(cmd)` — translate already-validated, envelope-clipped robot-space commands to native actuation; **do not re-interpret intent** (REQ-AD-04).
6. `halt()` — safest available stop within REQ-SE-05 latency; safe in any state.
7. `physical_limits()` — manufacturer/measured limits configuring the envelope (REQ-AD-10).
8. Push normalized sensory packets via `self._emit_sensory(msg_type, payload)` (SI units, canonical frames, deterministic — REQ-AD-07/08); surface dropouts explicitly (REQ-AD-09); map native faults via `report_fault` (REQ-AD-11).

The Glove core, contract, mapping tables, safety envelope, governance bus,
continuity store, and every being remain untouched.

## Deliberate skeleton boundaries

- Governance-envelope auth tags are **ed25519 signatures** per Appendix A: the bus registers verification-only public keys and contains no signing code path (INV-1/INV-4); endpoint-side signing tooling lives in `glove/governance/endpoint.py`. With `christman-crypto` installed, packet sealing is AES-256-GCM and descriptor signing is RSA-PSS-4096; without it, the remaining crypto is **skeleton-grade** (HMAC-SHA256 descriptor/packet signatures, SHA-256 keystream sealing) for inspectability, with identical schemas. The *structures* (signed descriptor, hash-chained packet/audit log, opaque payloads) are spec-faithful either way.
- Timing guarantees (REQ-GV-04 ≤ 50 ms, REQ-SE-05 ≤ 10 ms) are structural in-process calls here; latency measurement on real transports is adapter/conformance work.
- `raise NotImplementedError` appears only where a true hardware driver would plug in; all three example adapters are fully simulated and deterministic.
