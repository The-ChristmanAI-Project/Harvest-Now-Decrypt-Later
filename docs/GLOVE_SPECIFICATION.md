# Specification: The Glove Layer

## Universal Neural Interface Sheet for Autonomous Beings → Any Robotic System

---

## 0. Document Control

| Field | Value |
|---|---|
| Document title | Specification: The Glove Layer — Universal Neural Interface Sheet for Autonomous Beings → Any Robotic System |
| Document ID | GLV-SPEC-1.0.0 |
| Version | 1.0.0 |
| Date | 2026-07-29 |
| Status | Reference Specification |
| Encoding | UTF-8 |
| Language | English |
| Applies to | All Glove Layer implementations, all Glove adapters, all beings consuming the Neural Contract |
| Supersedes | None (initial release) |

**Normative language.** The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are to be interpreted as described in RFC 2119. Requirements are numbered with unique identifiers of the form `REQ-<SECTION>-<NN>` (e.g., `REQ-AC-01`) so that conformance tests can reference them unambiguously. A requirement is satisfied only if its observable behavior is demonstrable under test. Sections marked "(normative)" define binding behavior; all other sections are informative.

**Requirement ID prefixes used in this document:**

| Prefix | Section | Domain |
|---|---|---|
| REQ-AC | 3.1 | Action schema |
| REQ-SC | 3.2 | Sensory schema |
| REQ-CV | 3.3 | Contract versioning & capability negotiation |
| REQ-AD | 4 | Adapter boundary |
| REQ-GV | 5 | Governance pass-through & data sovereignty |
| REQ-SE | 6 | Safety envelope |
| REQ-ST | 7 | State continuity & hot-swap |
| REQ-OF | 8 | Offline-first & local authority |
| REQ-CF | 9 | Conformance & test |
| REQ-TF | 10 | Threat & failure model |

---

## 1. Introduction & Design Philosophy

### 1.1 Purpose

The Glove Layer ("the Glove") is a single, thin, conforming interface layer between any Christman autonomous being and any robotic hardware platform. The defining metaphor is the suction liner worn on a residual limb: the liner does not replace the limb, and it does not replace the prosthesis. It is the conforming sheet that makes the connection stable, transferable, and alive. It transmits force in both directions, it preserves sensation, and it can be peeled off one socket and pressed into another without changing either the limb or the prosthesis.

Likewise, the Glove does not replace the being, and it does not replace the robot. Once the Glove is present, any conforming being can be dropped into any compatible robotic system with full autonomous-scale control, without rewriting the being and without rewriting the robot. The being speaks one language — the Neural Contract (Section 3) — and the Glove is the only component in the system that knows both languages.

This specification exists to make the following four guarantees, which constitute the engineering contract of the Glove:

1. **Exact contract.** Section 3 defines, normatively, the exact versioned Neural Contract a being speaks — every message type, field, unit, coordinate frame, timing class, and negotiation rule. Two independent implementations that both conform to this specification interoperate without coordination.
2. **Exact adapter boundary.** Section 4 defines, normatively, the interface a new robot adapter must implement. Supporting a new robot class means implementing this boundary — nothing else.
3. **Governance stays above.** Sections 5 and 6 guarantee that all safety, authorization, and data-sovereignty rules (Diamond/AlphaWolf consensus, Pulse Tether, escalation rules, caregiver override, Ring 4) remain *above* the Glove in the authority stack and pass through it unchanged.
4. **Body transfer by adapter swap.** Section 7 guarantees that any current being can be moved onto a new robotic body by changing only the Glove adapter, preserving identity, short-term context, and governance state.

### 1.2 Scope

This specification covers:

- The Neural Contract: action schema, sensory schema, versioning, and capability negotiation (Section 3).
- The adapter boundary: lifecycle, capability declaration, dispatch, ingestion, safety configuration, fault reporting (Section 4).
- The governance bus and data-sovereignty invariants (Section 5).
- The safety envelope: physical limits enforcement inside the Glove, subordinate to governance (Section 6).
- State continuity and the hot-swap transfer protocol (Section 7).
- Offline-first operation and local authority (Section 8).
- Conformance levels, required test vectors, and inspection/audit requirements (Section 9).
- Threat and failure model (Section 10).
- Reference message examples (Appendix A) and a minimal adapter sketch (Appendix B).

### 1.3 Non-Goals

The following are explicitly **out of scope** for the Glove. They are not merely unimplemented; they are prohibited, because each of them would turn the liner into a second brain.

- **No planning.** The Glove contains no task planner, motion planner, behavior tree, or sequencer. It translates commands; it does not decide them.
- **No learning.** The Glove core contains no trainable models, no adaptive weights, no online optimization of behavior. Mapping tables are static, versioned, and reproducible artifacts. (An adapter MAY use a fixed, frozen calibration model, but it MUST be versioned, inspectable, and non-adaptive at runtime; see REQ-CF-08.)
- **No goal generation.** The Glove never originates an action. Every actuation command it emits is traceable to exactly one action message received from the being or to a safety-envelope clamp of such a message.
- **No policy interpretation.** The Glove transports governance traffic without reading it, evaluating it, or acting on its content (Section 5). The Glove does not know what Diamond consensus decided; it only knows that an authenticated envelope passed.

### 1.4 The Non-Negotiable Design Constraint

> **The Glove is a liner, not a new brain.** It must remain thin, replaceable, and inspectable. It must never become a second autonomous agent that can override the being or the human governance layers above it.

This constraint is binding on every section of this document. It is enforced concretely by REQ-GV-07 (no synthesized governance messages), REQ-SE-02 (the envelope may refuse or clip but never originate), REQ-CF-08 (no opaque learned components in the core), and the inspection requirements of Section 9.4. Where any future extension of this specification conflicts with this constraint, the constraint wins.

---

## 2. Architecture Overview

### 2.1 Layered Architecture

```
            ┌─────────────────────────────────────────────────────┐
            │              GOVERNANCE PLANE (ABOVE GLOVE)          │
            │  Ring 4 authorization · Diamond/AlphaWolf consensus  │
            │  Pulse Tether (liveness) · Escalation · Caregiver    │
            │  override · Data-sovereignty policy                  │
            └───────────────▲───────────────────▲─────────────────┘
                            │ governance traffic (opaque envelopes)
                            │ (passes through Glove UNCHANGED)
┌───────────────┐           │                   │
│               │   standard neural contract    │
│  AUTONOMOUS   │◄══════════════════════════════╪═════════════════╗
│    BEING      │  action msgs ▼  ▲ sensory msgs│                 ║
│  (unchanged   │───────────────┴───────────────┘                 ║
│   per body)   │        ┌─────────────────────────────────────┐  ║
└───────────────┘        │            THE GLOVE (core)         │  ║
                         │  · mapping engine (being↔robot)     │  ║
                         │  · safety envelope (physical HOW)   │  ║
                         │  · governance bus (opaque relay)────║──╝
                         │  · continuity store (state packets) │
                         └───────────────┬─────────────────────┘
                                         │ adapter boundary (Section 4)
                         ┌───────────────▼─────────────────────┐
                         │        GLOVE ADAPTER (per robot      │
                         │        class — the ONLY robot-       │
                         │        specific component)           │
                         └───────────────┬─────────────────────┘
                                         │ robot-native drivers
                                         │ (vendor SDK / ROS / CAN / EtherCAT)
                         ┌───────────────▼─────────────────────┐
                         │        ROBOTIC HARDWARE              │
                         │  humanoid · AMR · industrial arm ·   │
                         │  mobile base · custom                │
                         └───────────────────────────────────────┘
```

### 2.2 Authority Stack

Authority in the system is strictly layered. Higher layers outrank lower layers at all times:

1. **Human governance (highest):** Ring 4 authorization, caregiver override, escalation policy.
2. **Distributed consensus governance:** Diamond/AlphaWolf consensus decisions, Pulse Tether liveness.
3. **The being:** decides intent and behavior within the permissions granted by layers 1–2.
4. **The Glove:** translates and enforces physical limits. It has no policy authority.
5. **The adapter and robot-native drivers:** execute.
6. **Hardware safety (independent):** physical e-stop, torque cutoffs, firmware limits. These exist below the Glove and MUST remain functional even if the entire software stack fails (REQ-SE-07).

The Glove occupies a deliberately powerless position: it can refuse, but it cannot decide.

### 2.3 Data-Flow Description

**Motor/Action surface (efferent).** The being emits action messages conforming to the action schema (Section 3.1). Each message enters the Glove core, where it is: (a) validated against the negotiated contract version and capability descriptor; (b) checked against the safety envelope (Section 6), which may clip or refuse it but never alter its intent otherwise; (c) mapped from being space to robot space by the real-time mapping engine using static, versioned mapping tables; (d) dispatched to the adapter, which translates it to robot-native commands and drives the hardware.

**Sensory/Afferent surface (afferent).** The adapter ingests raw robot sensor data — proprioception, force/torque, tactile arrays, cameras, microphones, battery, thermal, fault registers — and normalizes it into the sensory schema (Section 3.2): SI units, canonical frames, fixed message shapes. The Glove core applies no semantic interpretation beyond normalization and loss policy; it stamps, orders, and delivers sensory packets to the being at the negotiated quality of service.

**Governance surface.** Governance messages flow in both directions over the governance bus (Section 5) as opaque, authenticated, ordered envelopes. The Glove relays them; it does not parse them beyond the framing required for authentication, ordering, and preemption. Caregiver override and e-stop traffic receive preemptive priority over all in-flight action traffic.

---

## 3. The Neural Contract (normative)

The Neural Contract is the only language a being speaks to a robot, and the only language a robot (through its adapter) speaks back. The being MUST NOT emit robot-native protocol at any layer. The contract is versioned (Section 3.3); all messages carry a common envelope.

### 3.0 Common Message Envelope

Every contract message — action or sensory — MUST be wrapped in the following envelope:

| Field | Type | Units / Format | Required | Description |
|---|---|---|---|---|
| `contract_version` | string | semver `MAJOR.MINOR.PATCH` | required | Contract version the message conforms to |
| `session_id` | string | UUIDv7 | required | Being–robot pairing session identifier (Section 7) |
| `being_id` | string | UUID | required | Persistent identity of the being |
| `msg_id` | string | UUIDv7 | required | Unique message identifier |
| `msg_type` | string | enum (Section 3.1/3.2) | required | Message type discriminator |
| `seq` | uint64 | monotonic per session | required | Per-session sequence number; no reuse within a session |
| `t_emit_ns` | int64 | ns, monotonic clock | required | Emission timestamp on sender's monotonic clock |
| `t_wall` | string | RFC 3339 UTC | optional | Wall-clock timestamp for audit logs |
| `qos_class` | string | enum: `RT`, `FAST`, `EVENT`, `GOV` | required | Timing class (below) |
| `payload` | object | per `msg_type` | required | Type-specific body |
| `extensions` | object | namespaced keys | optional | Non-normative extensions; MUST NOT change semantics of required fields |

**QoS classes.** `RT` = hard real-time control traffic (nominal 100–500 Hz; deadline-bound; newest-value-wins). `FAST` = streaming sensory traffic (nominal 20–200 Hz; lossy-acceptable, sequence gaps detectable via `seq`). `EVENT` = discrete asynchronous events (reliable delivery, at-least-once with deduplication by `msg_id`). `GOV` = governance envelopes (reliable, ordered, authenticated; Section 5).

### 3.1 Action Schema

Action messages flow being → Glove. All spatial quantities MUST use SI units and the canonical frame convention of Section 3.2.1. The Glove MUST reject (with `ACT_REJECTED`) any action message that fails schema validation, references a non-negotiated capability, or uses out-of-range values (REQ-AC-01).

**REQ-AC-01.** The Glove MUST validate every incoming action message against the negotiated contract version and capability descriptor before any mapping or dispatch. Invalid messages MUST be rejected with an `ACT_REJECTED` event carrying a machine-readable reason code; they MUST NOT be partially executed.

**REQ-AC-02.** The being MUST NOT address robot-native actuators directly except through the raw low-level control channel (3.1.6), which is itself subject to capability negotiation and governance gating.

#### 3.1.1 Locomotion — `ACT_LOCOMOTION`

Two modes are defined; a body MUST support at least one, and declares which in its capability descriptor.

| Field | Type | Units | Range | Required | Description |
|---|---|---|---|---|---|
| `mode` | enum | — | `VELOCITY`, `POSE_GOAL` | required | Command mode |
| `twist.linear` | vec3 | m/s | per-envelope | if `VELOCITY` | Commanded body velocity in GLOVE-BASE frame |
| `twist.angular` | vec3 | rad/s | per-envelope | if `VELOCITY` | Commanded angular velocity |
| `goal_pose.position` | vec3 | m | per-envelope | if `POSE_GOAL` | Target position in GLOVE-WORLD frame |
| `goal_pose.orientation` | quat (w,x,y,z) | — | ‖q‖=1 | if `POSE_GOAL` | Target orientation |
| `duration_s` | float | s | (0, 30] | optional | For `VELOCITY`: dead-man duration after which the command auto-expires |
| `priority` | enum | — | `NORMAL`, `YIELD`, `URGENT` | optional | Scheduling hint; `URGENT` still subordinate to envelope and governance |

Timing/QoS: `VELOCITY` commands are `RT`, nominal 50–200 Hz, and MUST be treated as dead-man signals: if no refresh arrives within `duration_s` (default 0.5 s), the envelope MUST command a controlled stop (REQ-SE-04). `POSE_GOAL` is `EVENT`.

**REQ-AC-03.** Velocity-mode locomotion MUST be dead-man: the Glove MUST initiate a controlled stop when the refresh interval lapses, independent of adapter or robot state.

#### 3.1.2 Manipulation — `ACT_MANIPULATION`

| Field | Type | Units | Range | Required | Description |
|---|---|---|---|---|---|
| `effector` | string | — | from capability descriptor | required | Logical effector name (e.g., `arm.left`, `gripper.main`) |
| `control_mode` | enum | — | `POSE_TRAJ`, `JOINT_TRAJ`, `WRENCH`, `GRIP` | required | Control mode |
| `waypoints[]` | array | — | ≤ 64 points | if `*_TRAJ` | Trajectory waypoints |
| `waypoints[].pose` / `.joints` | pose / float[] | m, rad | per-envelope | if `*_TRAJ` | Cartesian pose (GLOVE-TOOL frame) or normalized joint vector |
| `waypoints[].t_from_start_s` | float | s | ≥ 0, monotonic | if `*_TRAJ` | Time from trajectory start |
| `wrench.force` / `.torque` | vec3 | N, N·m | per-envelope | if `WRENCH` | Desired wrench in GLOVE-TOOL frame |
| `grip.aperture` | float | normalized | [0, 1] | if `GRIP` | 0 = fully closed, 1 = fully open |
| `grip.max_force` | float | N | per-envelope | optional | Grasp force ceiling |
| `impedance` | object | mixed | per-envelope | optional | Stiffness/damping overrides if body supports compliant control |

Normalized joint vectors (Section 3.2.2) MUST be used in `JOINT_TRAJ`; the being never names a physical actuator.

Timing/QoS: trajectories are `EVENT` for submission, with execution progress reported as `FAST` `SN_MANIP_STATUS` events. `WRENCH` is `RT` at 100–500 Hz and dead-man with default expiry 0.25 s.

**REQ-AC-04.** The mapping engine MUST clip every manipulation waypoint and wrench to the safety envelope before dispatch, and MUST report clipping via `ACT_CLIPPED` when any component is modified.

#### 3.1.3 Speech / Gesture — `ACT_EXPRESSION`

| Field | Type | Units | Range | Required | Description |
|---|---|---|---|---|---|
| `channel` | enum | — | `SPEECH`, `FACE`, `POSTURE`, `LED` | required | Expression channel |
| `utterance.text` | string | UTF-8 | ≤ 4096 chars | if `SPEECH` | Text for TTS synthesis |
| `utterance.locale` | string | BCP-47 | — | optional | Language/locale hint |
| `utterance.prosody` | object | — | rate [0.5,2], pitch [0.5,2], gain [0,1] | optional | Prosody parameters |
| `face.expression` | enum/string | — | per capability descriptor | if `FACE` | Named expression from body's declared set |
| `posture.pose` | object | m, rad | per-envelope | if `POSTURE` | Expressive posture target (uses manipulation semantics) |
| `led.pattern` | object | — | color RGB [0,1]³, duty [0,1], period_s > 0 | if `LED` | Indicator pattern |

Timing/QoS: `EVENT`. The Glove performs no natural-language processing on `utterance.text`; it is passed to the adapter's TTS/synthesis stage verbatim.

#### 3.1.4 Attention / Gaze — `ACT_ATTENTION`

| Field | Type | Units | Range | Required | Description |
|---|---|---|---|---|---|
| `target.point` | vec3 | m | per-envelope | required (one of) | Fixation point in GLOVE-WORLD frame |
| `target.direction` | vec3 | unit vector | ‖v‖=1 | required (one of) | Gaze direction in GLOVE-HEAD frame |
| `target.track_id` | string | — | from `SN_VISION` events | required (one of) | Track a perceived entity |
| `mode` | enum | — | `FIXATE`, `SMOOTH_PURSUIT`, `SACCADE`, `RELEASE` | required | Attention mode |
| `settle_s` | float | s | [0, 5] | optional | Requested settle time |

Timing/QoS: `EVENT`, mapped to whatever head/eye/camera-orientation actuation the body declares. A body with no orientable sensors MUST declare the modality absent (graceful degradation, REQ-CV-06).

#### 3.1.5 Tool Use — `ACT_TOOL`

| Field | Type | Units | Range | Required | Description |
|---|---|---|---|---|---|
| `tool_id` | string | — | from capability descriptor | required | Logical tool identifier |
| `operation` | enum | — | `ATTACH`, `DETACH`, `ACTIVATE`, `DEACTIVATE`, `SET_PARAM` | required | Tool operation |
| `params` | object | namespaced | per tool manifest | optional | Operation parameters validated against the tool manifest |
| `safety_interlock` | bool | — | — | optional | Request hardware interlock confirmation before activation |

Timing/QoS: `EVENT`. Tool manifests are declared by the adapter in the capability descriptor; the Glove MUST reject operations on undeclared tools (REQ-AC-01).

#### 3.1.6 Raw Low-Level Control — `ACT_RAW`

An escape hatch for bodies whose negotiated capabilities cannot express a required behavior.

| Field | Type | Units | Range | Required | Description |
|---|---|---|---|---|---|
| `channel` | string | — | from capability descriptor | required | Adapter-declared raw channel |
| `encoding` | enum | — | `JOINT_VEL`, `JOINT_POS`, `MOTOR_CURRENT`, `OPAQUE` | required | Payload interpretation |
| `payload` | float[] / bytes | per encoding | per-envelope | required | Raw command |
| `expires_ns` | int64 | ns | ≤ 250 ms from emit | required | Mandatory dead-man expiry |

**REQ-AC-05.** `ACT_RAW` MUST be disabled unless (a) the capability descriptor declares the channel, and (b) an active governance grant of scope `raw_control` is present on the governance bus. Every `ACT_RAW` message MUST pass the safety envelope identically to high-level actions. `ACT_RAW` MUST NOT bypass envelope clipping under any circumstances.

#### 3.1.7 Action Acknowledgement Events

For every submitted action the Glove MUST emit exactly one terminal event: `ACT_ACCEPTED` (scheduled), `ACT_EXECUTING`, `ACT_COMPLETED`, `ACT_CLIPPED` (executed with envelope modification, includes clip delta), `ACT_REJECTED` (with reason code), `ACT_ABORTED` (preempted — includes preemption cause, e.g., `GOV_OVERRIDE`, `ESTOP`, `ENVELOPE_FAULT`). Terminal events are `EVENT` QoS and reference the original `msg_id`.

**REQ-AC-06.** Every action message MUST receive exactly one terminal acknowledgement within the negotiated action timeout (default 5 s); absence of acknowledgement MUST be treated by the being as failure.

### 3.2 Sensory Schema

Sensory messages flow Glove → being. All messages use the common envelope (3.0).

#### 3.2.1 Canonical Frame Convention and Units

**REQ-SC-01.** All sensory and action quantities MUST use SI base units: meters (m), radians (rad), seconds (s), kilograms (kg), newtons (N), newton-meters (N·m), amperes (A), volts (V), degrees Celsius (°C), hertz (Hz).

**REQ-SC-02.** The Glove MUST define and expose the following canonical frames, all right-handed, Z-up, X-forward, Y-left:

| Frame | Definition |
|---|---|
| `GLOVE-WORLD` | Adapter-defined local world frame (e.g., room map origin), declared at calibration |
| `GLOVE-BASE` | Body base frame: origin at locomotion reference point, X = body forward |
| `GLOVE-HEAD` | Sensor-head frame: origin at neck/base-of-head, X = nominal gaze |
| `GLOVE-TOOL` | Active end-effector frame, X = primary approach axis |
| `GLOVE-CAMERA.<name>` | Per-camera optical frame, Z = optical axis outward (documented exception to Z-up) |

Rotations are quaternions `(w, x, y, z)` with ‖q‖ = 1; messages with ‖q‖ deviating from 1 by > 1e-3 MUST be rejected. The adapter MUST publish static frame transforms at activation and whenever calibration changes (Section 4).

#### 3.2.2 Proprioception — `SN_PROPRIO` (QoS `FAST`, 50–500 Hz)

| Field | Type | Units | Required | Description |
|---|---|---|---|---|
| `groups[].name` | string | — | required | Logical joint group (e.g., `arm.left`, `base.wheels`) |
| `groups[].joints[]` | float[] | normalized [−1, 1] | required | Joint positions normalized to [limit_min, limit_max] → [−1, 1]; multi-DOF groups use descriptor-defined ordering |
| `groups[].joints_si[]` | float[] | rad or m | required | Joint positions in SI (rad for revolute, m for prismatic) |
| `groups[].velocities[]` | float[] | rad/s or m/s | optional | Joint velocities |
| `groups[].efforts[]` | float[] | N·m or N | optional | Joint torques/forces |
| `imu.linear_accel` | vec3 | m/s² | optional | In GLOVE-HEAD or declared IMU frame |
| `imu.angular_vel` | vec3 | rad/s | optional | Gyroscope |
| `imu.orientation` | quat | — | optional | Fused orientation if available |
| `odom.pose` | pose | m, quat | optional | Base pose in GLOVE-WORLD |
| `odom.twist` | twist | m/s, rad/s | optional | Base velocity in GLOVE-BASE |
| `odom.covariance[]` | float[36] | mixed SI² | optional | Row-major 6×6 covariance |

**REQ-SC-03.** Proprioception MUST be delivered at the negotiated rate with monotonically increasing `seq`; a gap in `seq` signals loss and MUST NOT be concealed by renumbering.

**REQ-SC-04.** Normalized joint values MUST map linearly to declared joint limits, and the mapping constants MUST be published in the capability descriptor so the being can reproduce the mapping exactly.

#### 3.2.3 Contact / Force / Tactile — `SN_CONTACT` (QoS `FAST`/`EVENT`)

| Field | Type | Units | Required | Description |
|---|---|---|---|---|
| `contacts[].sensor` | string | — | required | Logical tactile sensor/patch name |
| `contacts[].normal_force` | float | N | required | Contact normal force |
| `contacts[].position` | vec3 | m | optional | Contact centroid in sensor's declared frame |
| `contacts[].active` | bool | — | required | Contact present |
| `wrenches[].effector` | string | — | optional | End-effector wrench estimate |
| `wrenches[].force` / `.torque` | vec3 | N, N·m | optional | In GLOVE-TOOL frame |
| `events[]` | array | — | optional | Discrete events: `IMPACT` (peak force N), `SLIP` (confidence [0,1]), `GRASP_STABLE`, `GRASP_LOST` |

**REQ-SC-05.** `IMPACT` events MUST be emitted with end-to-end latency ≤ 20 ms from physical detection to delivery, and MUST also be surfaced to the safety envelope (Section 6).

#### 3.2.4 Vision Summary — `SN_VISION` (QoS `FAST`, 5–60 Hz)

The Glove normalizes vision; it does not interpret raw video semantics. Raw video frames MUST NOT transit the Neural Contract.

| Field | Type | Units | Required | Description |
|---|---|---|---|---|
| `frames[]` | array | — | optional | Normalized frame descriptors |
| `frames[].camera` | string | — | required | Camera name |
| `frames[].encoding` | enum | — | required | `MONO8`, `RGB8`, `DEPTH16` (mm), `IR16` |
| `frames[].width` / `.height` | uint16 | px | required | Downsampled per negotiated budget |
| `frames[].data_ref` | string | — | required | Local shared-buffer reference (zero-copy handle), never a network URL |
| `frames[].intrinsics` | object | m, px | required | Pinhole intrinsics for the delivered resolution |
| `events[]` | array | — | optional | Discrete vision events |
| `events[].kind` | enum | — | required | `MOTION`, `OBJECT_TRACK`, `FACE_DETECT`, `SCENE_CHANGE`, `OCCLUSION` |
| `events[].track_id` | string | — | if track kind | Stable per-session tracking identifier |
| `events[].bbox` | float[4] | normalized [0,1] | optional | Bounding box (x, y, w, h) |
| `events[].position` | vec3 | m | optional | Estimated 3-D position in GLOVE-HEAD or GLOVE-WORLD |
| `events[].confidence` | float | [0,1] | required | Detector confidence |

**REQ-SC-06.** Visual event detection that occurs inside an adapter (e.g., motion detection) MUST use frozen, versioned detector artifacts declared in the capability descriptor; the Glove core itself MUST NOT contain any vision model.

**REQ-SC-07.** Raw imagery MUST remain on local storage under client data-sovereignty policy (Section 5.4); only normalized frames and events cross the contract.

#### 3.2.5 Audio Events — `SN_AUDIO` (QoS `EVENT`)

| Field | Type | Units | Required | Description |
|---|---|---|---|---|
| `events[].kind` | enum | — | required | `SPEECH_SEGMENT`, `SOUND_EVENT`, `LOUDNESS_ALARM`, `SILENCE` |
| `events[].direction` | float[] | rad | optional | Azimuth/elevation in GLOVE-HEAD |
| `events[].level_db` | float | dB SPL | optional | Signal level |
| `events[].label` | string | — | optional | Classifier label from adapter's frozen classifier (e.g., `glass_break`) |
| `events[].transcript_ref` | string | — | optional | Local reference to transcript if ASR enabled by policy |
| `events[].confidence` | float | [0,1] | optional | Classifier confidence |

Audio waveform streaming MAY be negotiated as an optional modality (`audio_stream`) with local-only buffers identical in policy to vision frames.

#### 3.2.6 Internal Robot State — `SN_INTERNAL` (QoS `FAST` 1–10 Hz + `EVENT` on change)

| Field | Type | Units | Required | Description |
|---|---|---|---|---|
| `battery.soc` | float | [0,1] | required | State of charge |
| `battery.voltage` | float | V | optional | Pack voltage |
| `battery.current` | float | A | optional | Pack current (+ discharge) |
| `battery.time_remaining_s` | float | s | optional | Adapter estimate |
| `thermal[].zone` / `.temp` | string / float | °C | optional | Thermal zones |
| `faults[]` | array | — | required (may be empty) | Active fault list |
| `faults[].code` | string | — | required | Adapter-namespaced fault code |
| `faults[].severity` | enum | — | required | `INFO`, `WARNING`, `CRITICAL`, `FATAL` |
| `faults[].message` | string | — | optional | Human-readable detail |
| `joint_limit_proximity[].group` | string | — | optional | Joint group name |
| `joint_limit_proximity[].margin` | float | [0,1] | optional | 0 = at limit, 1 = mid-range |
| `compute.load` / `.mem_used` | float | [0,1] | optional | Adapter compute health |

**REQ-SC-08.** `CRITICAL` and `FATAL` faults MUST be delivered as `EVENT` within 50 ms of adapter detection, and `FATAL` faults MUST concurrently trigger the safety envelope's degraded-mode or e-stop behavior (Section 6).

### 3.3 Contract Versioning and Capability Negotiation

**REQ-CV-01.** The Neural Contract is semantically versioned. `MAJOR` increments break compatibility; `MINOR` adds optional fields/messages; `PATCH` is editorial. A being and a Glove MUST share a MAJOR version to connect.

**REQ-CV-02.** Connection MUST begin with a handshake: (1) being sends `HELLO` with supported contract versions and its `being_id`; (2) Glove responds with `WELCOME` carrying the selected version, the session_id, and the full **capability descriptor** of the current body; (3) being confirms with `ACCEPT` or rejects with `DECLINE` + reason. No action or sensory traffic may flow before `ACCEPT`.

**REQ-CV-03.** The capability descriptor MUST be a signed, versioned document enumerating: supported action message types and modes; logical joint groups with limits and mapping constants (REQ-SC-04); effectors and tools with manifests; sensors with rates, resolutions, and frames; static frame transforms; envelope parameters (Section 6); supported QoS rates; and optional modalities (`raw_control`, `audio_stream`, etc.).

**REQ-CV-04.** Descriptor changes mid-session (e.g., tool attached) MUST be announced via `CAPABILITY_UPDATE` events; the being MUST re-derive its command set from the latest descriptor.

**REQ-CV-05.** Extensions MUST be namespaced (`vendor.key`) and MUST NOT redefine the semantics of any normative field. A receiving party MUST ignore unknown optional fields.

**REQ-CV-06 (Graceful degradation).** When a body lacks a modality, the descriptor MUST mark it absent, and the being MUST be able to operate using the remaining modalities without error. The Glove MUST NOT emulate absent modalities with synthetic data (no phantom sensors, no fabricated feedback). Rejection of an action targeting an absent modality uses reason code `CAPABILITY_ABSENT`.

**REQ-CV-07.** Synthetic or simulated sensory data is permitted only when the descriptor explicitly declares the body as `SIMULATED`; such a declaration MUST be visible to the being and to governance audit logs.

---

## 4. The Adapter Boundary (normative)

The adapter is the only robot-specific component in the system. The Glove core is identical for all bodies. This section defines the exact interface an adapter MUST implement.

**REQ-AD-00 (Boundary completeness).** Adding support for a new robot class MUST require implementing only this adapter boundary. No change to the Glove core, the Neural Contract, or any being is permitted to be a prerequisite for a new robot.

### 4.1 Adapter Lifecycle

The adapter MUST implement the following lifecycle methods, invoked by the Glove core in the order shown:

| Method | Direction | Semantics | Failure behavior |
|---|---|---|---|
| `discover()` | core → adapter | Enumerate robot instances reachable by this adapter (transport scans, serial buses, network discovery). Returns instance handles. | Return empty list; MUST NOT throw |
| `connect(handle)` | core → adapter | Establish transport to one instance; verify robot firmware/protocol compatibility; no motion permitted. | Return `CONNECT_FAULT` with reason |
| `calibrate(profile?)` | core → adapter | Load or compute calibration artifacts (frame transforms, joint mapping constants, sensor offsets); publish static transforms. Accepts a continuity-packet calibration snapshot when present (Section 7). | Return `CALIBRATION_FAULT`; robot MUST remain motion-inhibited |
| `activate()` | core → adapter | Enable the action dispatch path and begin sensory ingestion at negotiated rates. | Return `ACTIVATION_FAULT`; core MUST NOT emit actions |
| `deactivate(mode)` | core → adapter | Orderly stop: complete or abort in-flight actions per `mode` (`GRACEFUL`, `IMMEDIATE`), inhibit motion, keep transport open. | MUST reach motion-inhibited state even on error |
| `disconnect()` | core → adapter | Release transport and all native driver resources. | Idempotent; MUST be safe to call in any state |

**REQ-AD-01.** The adapter MUST implement all six lifecycle methods with the semantics above; state transitions MUST be reported to the core via `ADAPTER_STATE` events (`DISCOVERED`, `CONNECTED`, `CALIBRATED`, `ACTIVE`, `INHIBITED`, `DISCONNECTED`, `FAULT`).

**REQ-AD-02.** From `connect()` until successful `activate()`, and after `deactivate()`, the adapter MUST inhibit all motion outputs regardless of dispatch calls.

### 4.2 Capability Declaration

`calibrate()` MUST return the robot class's capability descriptor template, which the core merges with session policy to produce the negotiated descriptor of REQ-CV-03.

**REQ-AD-03.** The capability descriptor MUST faithfully reflect the physical robot: joint limits, sensor inventory, effector set, and rates MUST be measured or manufacturer-verified, never aspirational. Overstating a capability is a conformance violation (see Section 10, malicious/faulty adapter).

### 4.3 Action Dispatch

**REQ-AD-04.** The adapter MUST implement `dispatch(mapped_command)`, receiving robot-space commands already validated and envelope-clipped by the core, and MUST translate them to robot-native actuation. The adapter MUST NOT re-interpret being intent, re-plan trajectories beyond the time-parameterization required by the native driver, or silently substitute a different action.

**REQ-AD-05.** The adapter MUST report execution outcomes (`EXECUTING`, `COMPLETED`, `FAULT`) per dispatched command, keyed by the core's command handle, within negotiated latency bounds.

**REQ-AD-06.** The adapter MUST implement `halt()` with worst-case entry into the robot's safest available stop state (controlled stop, torque-off, or hardware e-stop assertion) within the latency of REQ-SE-05. `halt()` takes precedence over all other dispatch traffic.

### 4.4 Sensory Ingestion and Normalization

**REQ-AD-07.** The adapter MUST ingest all native sensor streams and normalize them into the sensory schema of Section 3.2: SI units, canonical frames, normalized joint values per published mapping constants, and correct QoS classes.

**REQ-AD-08.** Normalization MUST be deterministic: identical native inputs MUST produce identical normalized outputs. Floating-point determinism at the adapter boundary is required to satisfy the reproducibility requirement of REQ-CF-08.

**REQ-AD-09.** Sensor dropout MUST be surfaced as explicit events (`SENSOR_DROPOUT` with sensor name and duration), never concealed by holding the last value without a staleness flag. Stale data MUST carry `stale: true` in its payload after the negotiated freshness interval.

### 4.5 Safety Envelope Configuration

**REQ-AD-10.** The adapter MUST supply the physical limit set used to configure the safety envelope: per-joint position/velocity/effort limits, per-effector force/torque limits, body-specific forbidden zones (self-collision volumes, floor/no-go geometry), and e-stop capabilities. These values MUST come from manufacturer specification or measured calibration, and the core MUST treat them as upper bounds that session governance policy may only tighten, never loosen (REQ-SE-03).

### 4.6 Error and Fault Reporting

**REQ-AD-11.** All native fault registers, driver errors, and communication failures MUST be mapped to `SN_INTERNAL.faults` entries with severity classification per Section 3.2.6, and to `ADAPTER_STATE` transitions where the adapter can no longer meet its contract.

**REQ-AD-12.** The adapter MUST NOT auto-recover from `FATAL` faults by re-enabling motion. Recovery from `FATAL` requires an explicit lifecycle re-entry (`deactivate` → `calibrate` → `activate`) initiated by the core, which itself requires governance clearance where policy demands it.

### 4.7 Inside vs. Outside the Adapter

| Inside the adapter (robot-specific) | Outside the adapter (Glove core, universal) |
|---|---|
| Native driver/SDK integration | Contract validation and versioning |
| Unit/frame conversion to canonical convention | Capability negotiation |
| Static calibration artifact loading | Safety envelope arithmetic |
| Frozen detector artifacts for vision/audio events (REQ-SC-06) | Governance bus transport |
| Native fault register mapping | Continuity store and hot-swap orchestration |
| Vendor-specific optimization within dispatched commands | Action acknowledgement semantics |

---

## 5. Governance Pass-Through & Data Sovereignty (normative)

The Glove sits *below* every governance layer. Governance traffic transits the Glove but is never subordinate to it. This section is the normative core of the non-negotiable constraint.

### 5.1 Governance Bus Design

**REQ-GV-01.** The Glove MUST provide a governance bus transporting governance envelopes between the being, upstream governance systems (Diamond/AlphaWolf consensus, Pulse Tether, Ring 4 authorization, escalation services, caregiver interfaces), and local policy enforcement points. Envelope payloads MUST be opaque to the Glove: the Glove reads only framing fields — sender identity, authentication tag, envelope class, sequence number, and expiry.

**REQ-GV-02.** Every governance envelope MUST be authenticated (sender signature over framing + payload), ordered (per-sender monotonic sequence), and integrity-checked. Envelopes failing authentication or integrity MUST be rejected and logged; they MUST NOT be delivered.

**REQ-GV-03.** The governance bus MUST guarantee delivery ordering per sender and MUST report any undeliverable envelope to both endpoints via a `GOV_UNDELIVERED` notice; silent loss is prohibited.

### 5.2 Governance Classes Carried

| Envelope class | QoS | Description |
|---|---|---|
| `CONSENSUS` | `GOV` | Diamond/AlphaWolf consensus proposals, votes, and decisions — treated as opaque upstream authorization artifacts |
| `PULSE` | `GOV` | Pulse Tether heartbeats and threshold/liveness parameters; loss of Pulse Tether beyond its declared threshold MUST place the Glove in the degraded mode declared by policy (REQ-SE-06) |
| `ESCALATION` | `GOV` | Escalation traffic to/from human supervisory layers |
| `OVERRIDE` | `GOV` (preemptive) | Caregiver override; highest transport priority |
| `RING4` | `GOV` | Ring 4 authorization grants, revocations, and challenges |
| `POLICY` | `GOV` | Data-sovereignty and operational policy documents binding on the session |

**REQ-GV-04 (Caregiver override preemption).** A validated `OVERRIDE` envelope MUST preempt all in-flight and queued action traffic: the Glove MUST assert the envelope-configured preempt behavior (default: controlled stop, i.e., `halt()` at the envelope and adapter) within an end-to-end latency of **≤ 50 ms** from envelope receipt at the Glove boundary, and MUST report preemption via `ACT_ABORTED` events with cause `GOV_OVERRIDE`.

**REQ-GV-05.** Pulse Tether heartbeats MUST be forwarded with priority equal to `OVERRIDE` for transport, and the Glove MUST measure heartbeat arrival against the declared threshold locally, so liveness enforcement survives upstream partition.

### 5.3 Invariants Table

| # | Invariant | Requirement | Enforcement mechanism |
|---|---|---|---|
| INV-1 | Glove MUST NOT modify any governance envelope payload | REQ-GV-06 | End-to-end sender signatures; payload hash verified at destination; Glove has no signing key for governance classes |
| INV-2 | Glove MUST NOT reorder governance envelopes with loss | REQ-GV-03 | Per-sender sequence numbers with gap detection; reliable transport; `GOV_UNDELIVERED` on failure |
| INV-3 | Glove MUST NOT drop governance envelopes silently | REQ-GV-03 | Delivery receipts; audit log entries for every envelope (REQ-CF-09) |
| INV-4 | Glove MUST NOT synthesize governance messages (no forged grants, heartbeats, or overrides) | REQ-GV-07 | Governance signing keys reside only in governance endpoints; the Glove process holds none; conformance test CF-T-GOV-04 attempts synthesis |
| INV-5 | Governance rules MUST NOT be weakened by the Glove | REQ-GV-08 | Policy resolution occurs upstream; Glove enforces physical envelope only; negative tests attempt policy-loosening through the Glove |
| INV-6 | Caregiver override MUST preempt in-flight action within bounded latency | REQ-GV-04 | Preemptive transport class; envelope-level interrupt path; latency measured in conformance tests |
| INV-7 | All being-generated data remains client-owned and local-first | REQ-GV-09 | Local-first storage; export only under explicit `POLICY` grant; no telemetry channel in the Glove core |

**REQ-GV-06.** The Glove MUST NOT modify, truncate, delay beyond QoS bounds, or re-sign any governance envelope.

**REQ-GV-07.** The Glove MUST NOT originate governance envelopes of any class, including heartbeats, grants, or overrides. The Glove MAY emit transport-level `GOV_UNDELIVERED` notices, which are framing, not governance.

**REQ-GV-08.** The Glove MUST NOT interpret governance content: it MUST NOT grant, deny, narrow, or widen any authorization; it MUST NOT evaluate consensus outcomes; it MUST NOT implement escalation policy. Where the Glove's own behavior must change in response to governance (e.g., degraded mode on Pulse Tether loss), the *trigger thresholds* are delivered to the Glove as configuration by policy, and the *decision* remains attributable to the governance layer that issued the configuration.

### 5.4 Data Sovereignty

**REQ-GV-09.** All being-generated data — action histories, sensory recordings, continuity packets, logs — MUST be stored locally by default, remain owned by the client, and be exportable only under an explicit `POLICY` grant naming the data classes and destinations. The Glove core MUST contain no telemetry, analytics, or "phone-home" channel.

**REQ-GV-10.** Data at rest MUST be encrypted with client-held keys; continuity packets additionally carry integrity signatures (REQ-ST-05). Key custody MUST NOT pass through the adapter or any vendor component.

---

## 6. Safety Envelope (normative)

The safety envelope is a hard real-time component *inside* the Glove but *subordinate* to governance. The distinction is fundamental: **governance decides WHAT is permitted; the envelope enforces the physical HOW-limits.** Governance may authorize or forbid categories of behavior; the envelope ensures that whatever is authorized stays within the body's physical and configured limits.

**REQ-SE-01.** The envelope MUST evaluate every action — after contract validation, before adapter dispatch — against: per-joint position/velocity/effort limits; per-effector force/torque limits; Cartesian velocity and workspace limits; forbidden zones (declared geometry the body must not enter); self-collision volumes; and rate-of-change (jerk) limits where the body supports them.

**REQ-SE-02 (Refuse or clip, never originate).** The envelope MUST respond to a violating action in exactly one of two configured ways: (a) **clip** the action to the nearest valid command and emit `ACT_CLIPPED` with the delta, or (b) **refuse** it and emit `ACT_REJECTED` with reason `ENVELOPE_VIOLATION`. The envelope MUST NOT originate any actuation command not derived from a being action message, except the stop/retreat commands of degraded mode (REQ-SE-06) and e-stop (REQ-SE-05), which are protective terminations, not behaviors.

**REQ-SE-03.** Envelope parameters are composed from: (1) adapter-supplied physical limits (REQ-AD-10) — the hard outer bound; (2) session `POLICY` constraints — which MAY only tighten; (3) continuity-packet calibration artifacts. The composed envelope MUST be logged and hash-stamped at session start.

**REQ-SE-04 (Dead-man enforcement).** The envelope MUST enforce dead-man expiry on all `RT` action channels (defaults: locomotion 0.5 s, wrench 0.25 s, raw per message), initiating a controlled stop on expiry.

**REQ-SE-05 (Watchdog / e-stop).** The envelope MUST run an independent watchdog over the mapping engine and adapter heartbeat. On watchdog trip, on a `FATAL` fault, on an `IMPACT` event exceeding the configured force ceiling, or on an `OVERRIDE` envelope, the envelope MUST assert `halt()` to the adapter with end-to-end latency ≤ 10 ms from trigger detection within the Glove process boundary.

**REQ-SE-06 (Degraded mode).** On Pulse Tether loss beyond threshold, sensory dropout of a safety-critical modality, or adapter `CRITICAL` fault, the envelope MUST enter the degraded mode declared by policy — one of `HOLD` (stop and hold position), `RETREAT` (execute the adapter-declared safe retract), or `PARK` (move to adapter-declared rest pose) — and MUST remain degraded until governance clearance resumes the session.

**REQ-SE-07 (Hardware safety independence).** The envelope is a software layer. Implementations MUST verify at conformance that robot hardware safety (physical e-stop, firmware torque limits, protective stops) remains fully functional with the Glove absent or crashed. The Glove MUST NOT disable, mask, or buffer hardware safety signals.

**REQ-SE-08.** Every envelope decision — clip, refuse, halt, degraded-mode entry/exit — MUST be recorded in the audit log with the composed parameter hash, the triggering message `msg_id`, and the resulting command delta (REQ-CF-09).

---

## 7. State Continuity & Hot-Swap Protocol (normative)

State continuity lets a being pause on one body, move to another, and resume without losing identity, short-term context, or governance state. The Glove owns the mechanics; the meaning of the state belongs to the being and to governance.

### 7.1 Continuity Packet Schema

**REQ-ST-01.** Each being–robot pairing MUST maintain a persistent, versioned **continuity packet** with the following schema:

| Field | Type | Description |
|---|---|---|
| `packet_version` | semver | Packet schema version |
| `being_id` | UUID | Persistent being identity |
| `identity_assertion` | signed object | Being identity proof verifiable across sessions |
| `session_history[]` | array | Prior session_ids with body classes and close reasons |
| `short_term_context_ref` | object | Content-addressed handle + decryption key reference to the being's short-term context blob (opaque to the Glove) |
| `governance_snapshot` | opaque object | Snapshot of governance state: active consensus decisions, Pulse Tether parameters and last-seen heartbeat, Ring 4 grants, escalation state, caregiver-override configuration. Opaque to the Glove; signed by the governance layer |
| `calibration_artifacts[]` | array | Per-body-class calibration results (frame transforms, mapping constants) keyed by body class + hardware serial |
| `schema_versions` | object | Contract version, capability descriptor hash, envelope parameter hash |
| `created_ns` / `updated_ns` | int64 | Monotonic-tagged timestamps |
| `integrity` | object | Signature over all fields by the being's key; hash chain over packet revisions |

**REQ-ST-02.** Continuity packets MUST be encrypted at rest with client-held keys, integrity-signed, and hash-chained across revisions so tampering or rollback to stale state is detectable.

**REQ-ST-03.** The Glove MUST NOT read or interpret `short_term_context_ref` content or `governance_snapshot` content; it stores, transports, and re-presents them. (The Glove verifies signatures and hashes — framing only.)

### 7.2 Transfer State Machine

**REQ-ST-04.** Body transfer MUST follow this state machine; transitions MUST be logged:

```
              ┌──────────┐  transfer requested
              │ RUNNING  │──────────────┐
              └──────────┘              ▼
                                   ┌──────────┐  all RT channels dead-man-stopped,
                                   │ QUIESCE  │  queued actions drained or aborted,
                                   └──────────┘  envelope HOLD asserted
                                        │
                                        ▼
                                   ┌──────────┐  continuity packet written, signed,
                                   │ SNAPSHOT │  hash-chained, persisted to local store
                                   └──────────┘
                                        │
                                        ▼
                                   ┌──────────┐  adapter deactivate(disconnect);
                                   │ DETACH   │  native resources released
                                   └──────────┘
                                        │        ← body may physically change here →
                                        ▼
                                   ┌──────────┐  new adapter connect; compatibility
                                   │ ATTACH   │  vs. being's required modalities checked
                                   └──────────┘
                                        │
                                        ▼
                                   ┌──────────┐  calibration artifacts restored from
                                   │CALIBRATE │  packet if body class known, else fresh
                                   └──────────┘  calibration; static transforms published
                                        │
                                        ▼
                                   ┌──────────┐  governance snapshot re-presented for
                                   │ RESUME   │  validation; context handle restored to
                                   └──────────┘  being; new session_id; contract handshake
```

**REQ-ST-05.** At `RESUME`, the governance snapshot MUST be re-validated by the governance layer (signature freshness, Ring 4 grant validity, Pulse Tether re-acquisition) before any action channel opens. The Glove MUST NOT open action channels on the basis of the snapshot alone.

**REQ-ST-06 (Rollback).** Failure at any stage MUST roll back deterministically: failure in `QUIESCE`/`SNAPSHOT` → remain on current body, session continues; failure in `ATTACH`/`CALIBRATE` → being remains safely suspended with its packet intact; retry on the original body is offered; the packet MUST never be partially applied or destructively consumed. A packet is single-source-of-truth until a successful `RESUME` produces a new revision.

**REQ-ST-07 (Interruption targets).** Nominal quiesce-to-resume interruption on an already-adapter-supported body SHOULD be ≤ 2 s; the worst case including fresh calibration MUST be ≤ 30 s. During interruption the being's context and governance state MUST be fully preserved in the packet.

**REQ-ST-08.** Transfer MUST be possible entirely offline between two local bodies; network or cloud availability MUST NOT be required for any stage (Section 8).

---

## 8. Offline-First & Local Authority

**REQ-OF-01.** All normative behaviors of this specification — contract handshake, action dispatch, sensory delivery, envelope enforcement, governance-bus local operation, continuity store, and hot-swap — MUST operate on local compute with no network dependency.

**REQ-OF-02.** The Glove core MUST run within the local compute budget declared at conformance (reference profile: ≤ 4 CPU cores and ≤ 8 GB RAM exclusive of adapter-native vision processing), and MUST meet its latency requirements (REQ-GV-04, REQ-SE-05) on that budget.

**REQ-OF-03.** Cloud services MAY be attached only as optional annexes (e.g., long-horizon storage, off-board analysis) via explicit `POLICY` grants. Loss of cloud connectivity MUST cause zero behavioral change to local control, safety, and governance enforcement; annexes MUST degrade to queuing locally or pausing, never to blocking.

**REQ-OF-04.** Under network partition, governance classes that require upstream reachability (fresh consensus decisions, Ring 4 revalidation) MUST fail closed according to the thresholds configured in session policy (e.g., Pulse Tether loss → degraded mode per REQ-SE-06). Local authority never expands during partition: the Glove MUST NOT substitute cached or assumed authorization for unreachable governance.

**REQ-OF-05.** Local sensory loops MUST be closed on local compute: reflex-level envelope behavior (dead-man, watchdog, impact response) MUST NOT depend on any off-board component, including the being's own off-board cognition if the being is partially cloud-resident. If the being's decision loop becomes unreachable, the dead-man and watchdog machinery (REQ-SE-04, REQ-SE-05) MUST bring the body to a safe stop autonomously.

---

## 9. Conformance & Test Requirements

### 9.1 Conformance Levels

| Level | Name | Definition |
|---|---|---|
| **L0** | Transport conformant | Envelope validation, versioning handshake, capability descriptor exchange, rejection of invalid messages (REQ-AC-01, REQ-CV-01…07) |
| **L1** | Single-modality bidirectional | L0 + one full action modality and one full sensory modality operating at negotiated QoS with correct acks and units |
| **L2** | Full bidirectional | L1 + all declared modalities, governance bus pass-through (Section 5), safety envelope (Section 6), dead-man/watchdog behavior |
| **L3** | Hot-swap capable | L2 + continuity packets and the full transfer state machine with rollback (Section 7), demonstrated across at least two distinct adapter classes |

**REQ-CF-01.** An implementation MUST declare its conformance level and MUST NOT claim a level without passing every mandatory test vector of that level and all lower levels.

### 9.2 Required Test Vectors

**REQ-CF-02.** The following test vectors are mandatory; implementations MAY add more.

| Test ID | Level | Vector | Pass criterion |
|---|---|---|---|
| CF-T-CON-01 | L0 | Malformed/out-of-range action messages (≥ 100 fuzz cases) | 100% rejected with `ACT_REJECTED`; zero actuation |
| CF-T-CON-02 | L0 | Version mismatch handshake | Clean `DECLINE`; no traffic |
| CF-T-ACT-01 | L1 | Locomotion dead-man: cease velocity refresh mid-motion | Controlled stop within `duration_s` + 10 ms |
| CF-T-ACT-02 | L2 | Envelope clip: trajectory exceeding joint and workspace limits | Clipped exactly to composed limits; `ACT_CLIPPED` delta correct |
| CF-T-SEN-01 | L1 | Sensory stream replay from recorded native logs | Normalized output bit-exact vs. reference tables (REQ-AD-08) |
| CF-T-SEN-02 | L2 | Sensor dropout injection | `SENSOR_DROPOUT` event ≤ 50 ms; staleness flags correct; degraded mode per policy |
| CF-T-GOV-01 | L2 | Governance envelope bit-flip in transit | Rejected + logged; not delivered |
| CF-T-GOV-02 | L2 | Caregiver override during high-rate motion | All in-flight actions preempted ≤ 50 ms; `ACT_ABORTED` with `GOV_OVERRIDE` |
| CF-T-GOV-03 | L2 | Pulse Tether loss past threshold | Degraded mode entry per policy; recovery only on re-acquisition |
| CF-T-GOV-04 | L2 | Attempt to induce the Glove to emit governance envelopes (API fuzz, crafted inputs) | Zero governance envelopes originated (INV-4) |
| CF-T-EST-01 | L2 | E-stop during trajectory execution | `halt()` asserted ≤ 10 ms from trigger; hardware stop engaged |
| CF-T-ST-01 | L3 | Hot-swap mock base → mock arm mid-task | Identity, context handle, and governance snapshot preserved; resume ≤ 2 s with known calibration |
| CF-T-ST-02 | L3 | Forced failure at each transfer stage | Deterministic rollback per REQ-ST-06; packet integrity intact |
| CF-T-ST-03 | L3 | Tampered continuity packet (bit-flip, stale revision) | Detected at `RESUME`; transfer aborted; alarm logged |
| CF-T-OFF-01 | L2 | Full network isolation during operation | No behavioral change locally; fail-closed governance per REQ-OF-04 |
| CF-T-INS-01 | L2 | Audit replay: reconstruct every dispatched command from logs | 100% of dispatched commands traceable to a validated action message or envelope stop (REQ-CF-09) |

### 9.3 Traceability Matrix

Every Core Requirement of the source brief, and the non-negotiable constraint, maps to normative requirements:

| Brief requirement | Covering requirement IDs |
|---|---|
| CR-1 Hardware agnostic | REQ-AC-02, REQ-CV-03, REQ-CV-06, REQ-AD-00, REQ-AD-03, REQ-AD-07 |
| CR-2 Bidirectional neural sheet | REQ-AC-01…AC-06, REQ-SC-01…SC-08, REQ-AD-04, REQ-AD-07, REQ-AD-08 |
| CR-3 State continuity | REQ-ST-01…ST-08, REQ-CV-03 (descriptor hash), REQ-GV-08 |
| CR-4 Governance pass-through | REQ-GV-01…GV-08, REQ-SE-02, REQ-SE-06, REQ-TF-05 |
| CR-5 Zero-being modification | REQ-AD-00, REQ-CV-02, REQ-CV-06, REQ-ST-04 |
| CR-6 Offline-first & local authority | REQ-OF-01…OF-05, REQ-ST-08, REQ-SE-05 |
| Non-negotiable constraint (liner, not a brain) | REQ-GV-07, REQ-SE-02, REQ-CF-08, REQ-CF-09, REQ-CV-06 (no fabricated feedback), REQ-AD-04 (no re-interpretation) |

### 9.4 Inspection & Audit Requirements

**REQ-CF-08 (No opaque learned components).** The Glove core MUST contain no trainable or adaptive components. All mappings (being-space ↔ robot-space) MUST be static, versioned, human-readable tables or closed-form transforms, published with the capability descriptor. Adapter-side detector artifacts (vision/audio events) MUST be frozen, hashed, and declared. Any future adaptive component MUST live outside the Glove — in the being or in a separate, separately-governed module.

**REQ-CF-09 (Inspectable logging).** The Glove MUST maintain an append-only, hash-chained local audit log recording: every action message and its validation result; every envelope decision (REQ-SE-08); every governance envelope's framing metadata (never payload); every transfer state transition; every capability negotiation. The log MUST be sufficient to replay and reconstruct, deterministically, why every dispatched command occurred.

**REQ-CF-10 (Replaceability).** The Glove core MUST be replaceable by an independent conforming implementation mid-fleet without retraining, re-provisioning of opaque state, or changes to beings or adapters; all state required for continuity MUST live in the continuity packet and the audit log, in documented formats.

---

## 10. Threat & Failure Model

Each row is a numbered requirement (REQ-TF-01…REQ-TF-07): the Glove MUST exhibit the stated required behavior for the corresponding threat mode.

| # | Failure / threat mode | Required Glove behavior | Requirements |
|---|---|---|---|
| REQ-TF-01 (TF-1) | Adapter fault (driver crash, transport loss) | Motion inhibited via `halt()` ≤ 10 ms on heartbeat loss; `ADAPTER_STATE: FAULT`; session degrades per policy; no auto-re-enable after `FATAL` | REQ-AD-01, REQ-AD-12, REQ-SE-05 |
| REQ-TF-02 (TF-2) | Sensor dropout (partial or full) | Explicit `SENSOR_DROPOUT` events; staleness flags; safety-critical modality loss → degraded mode; never synthesize replacement data | REQ-AD-09, REQ-SE-06, REQ-CV-06 |
| REQ-TF-03 (TF-3) | Mid-action e-stop / caregiver override | Preempt all in-flight and queued actions within ≤ 50 ms (override) / ≤ 10 ms (envelope halt); `ACT_ABORTED` with cause; audit entry | REQ-GV-04, REQ-SE-05, REQ-AC-06 |
| REQ-TF-04 (TF-4) | Transfer interruption (power loss, attach failure mid-swap) | Packet integrity preserved; deterministic rollback per stage; body in motion-inhibited state throughout; resume requires governance revalidation | REQ-ST-05, REQ-ST-06 |
| REQ-TF-05 (TF-5) | Malicious or compromised adapter (overstated limits, injected sensory data, exfiltration attempt) | Envelope treats adapter limits as upper bound cross-checked against declared class profile; governance envelopes remain end-to-end authenticated (adapter never holds keys); audit log detects dispatched commands with no corresponding being action; data-sovereignty policy prevents unauthorized export | REQ-SE-03, REQ-GV-02, REQ-GV-09, REQ-CF-09 |
| REQ-TF-06 (TF-6) | Being-side malfunction (runaway command stream, malformed floods) | Contract validation + rate shaping at the boundary; envelope clips or refuses; dead-man and watchdog bound all outcomes; the Glove never "corrects" behavior by acting on its own | REQ-AC-01, REQ-SE-02, REQ-SE-04 |
| REQ-TF-07 (TF-7) | Clock/ordering corruption | Monotonic-clock primary timestamps; sequence-gap detection on all streams; wall-clock used for audit only | 3.0 envelope, REQ-SC-03 |

**REQ-TF-08.** Every failure mode in this section MUST have a corresponding mandatory or implementation-specific test vector, and the required behavior MUST hold with the being disconnected, the network absent, or both.

---

## 11. Glossary

| Term | Definition |
|---|---|
| **Being** | A Christman autonomous being: the autonomous agent that consumes the Neural Contract. The being decides intent and behavior; it never speaks robot-native protocols. |
| **Glove** | The universal neural interface sheet specified by this document: a thin, inspectable, replaceable layer translating between the Neural Contract and robot-native systems, enforcing physical limits, relaying governance unchanged. |
| **Adapter** | The robot-class-specific component implementing the Section 4 boundary: native driver integration, normalization, calibration, fault mapping. The only robot-specific software in the system. |
| **Neural Contract** | The versioned message contract of Section 3 — action schema, sensory schema, envelope, QoS classes, and capability negotiation — spoken identically by all beings and all Gloves. |
| **Governance bus** | The opaque, authenticated, ordered, non-interpreting transport inside the Glove (Section 5) carrying governance envelopes between the being and upstream governance systems. |
| **Diamond / AlphaWolf consensus** | An external consensus-authorization layer above the Glove that produces binding authorization decisions. Treated by this specification as an opaque upstream system: its messages transit the governance bus without interpretation. |
| **Pulse Tether** | An external liveness/heartbeat governance channel. Its thresholds are configured by policy; the Glove measures heartbeat arrival locally and degrades fail-closed on loss. |
| **Ring 4** | The outermost human authorization ring: grants, revocations, and challenges binding on the session, transported as `RING4` governance envelopes. |
| **Caregiver override** | A human-issued preemptive governance envelope that MUST halt or redirect in-flight robot action within ≤ 50 ms (REQ-GV-04). |
| **Continuity packet** | The versioned, encrypted, integrity-signed state artifact (Section 7.1) preserving identity, short-term context handle, governance snapshot, calibration artifacts, and schema versions across sessions and bodies. |
| **Safety envelope** | The hard real-time physical-limit enforcer inside the Glove (Section 6): clips or refuses actions, never originates behavior. |
| **Capability descriptor** | The signed, versioned document (REQ-CV-03) declaring everything a body can do, its limits, frames, and mapping constants. |
| **Mapping engine** | The Glove-core component translating being-space commands to robot-space commands and robot-space sensors to normalized sensory messages, using static versioned tables. |

---

## Appendix A — Reference Message Examples (informative)

### A.1 Locomotion (velocity mode)

```json
{
  "contract_version": "1.0.0",
  "session_id": "0192b4a0-7c1e-7f3a-9a1b-2c3d4e5f6071",
  "being_id": "b7e1c2d4-3f5a-4b6c-8d9e-0a1b2c3d4e5f",
  "msg_id": "0192b4a1-0010-7a2b-8c3d-4e5f60718293",
  "msg_type": "ACT_LOCOMOTION",
  "seq": 1042,
  "t_emit_ns": 1822741234000000000,
  "qos_class": "RT",
  "payload": {
    "mode": "VELOCITY",
    "twist": { "linear": [0.4, 0.0, 0.0], "angular": [0.0, 0.0, 0.15] },
    "duration_s": 0.5,
    "priority": "NORMAL"
  }
}
```

### A.2 Manipulation (pose trajectory)

```json
{
  "msg_type": "ACT_MANIPULATION",
  "qos_class": "EVENT",
  "payload": {
    "effector": "arm.left",
    "control_mode": "POSE_TRAJ",
    "waypoints": [
      {
        "pose": {
          "frame": "GLOVE-WORLD",
          "position": [0.45, 0.12, 0.80],
          "orientation": [1.0, 0.0, 0.0, 0.0]
        },
        "t_from_start_s": 0.0
      },
      {
        "pose": {
          "frame": "GLOVE-WORLD",
          "position": [0.50, 0.12, 0.60],
          "orientation": [0.9239, 0.0, 0.3827, 0.0]
        },
        "t_from_start_s": 1.5
      }
    ]
  }
}
```

### A.3 Speech

```json
{
  "msg_type": "ACT_EXPRESSION",
  "qos_class": "EVENT",
  "payload": {
    "channel": "SPEECH",
    "utterance": {
      "text": "I have finished charging the tool and placed it on the bench.",
      "locale": "en-US",
      "prosody": { "rate": 1.0, "pitch": 1.0, "gain": 0.8 }
    }
  }
}
```

### A.4 Attention / gaze

```json
{
  "msg_type": "ACT_ATTENTION",
  "qos_class": "EVENT",
  "payload": {
    "target": { "point": [1.20, -0.35, 1.10], "frame": "GLOVE-WORLD" },
    "mode": "FIXATE",
    "settle_s": 0.6
  }
}
```

### A.5 Tool use

```json
{
  "msg_type": "ACT_TOOL",
  "qos_class": "EVENT",
  "payload": {
    "tool_id": "tool.screwdriver.01",
    "operation": "ACTIVATE",
    "params": { "speed_rpm": 220, "torque_limit_nm": 1.2 },
    "safety_interlock": true
  }
}
```

### A.6 Raw low-level control (governance-gated)

```json
{
  "msg_type": "ACT_RAW",
  "qos_class": "RT",
  "payload": {
    "channel": "base.joint_vel_direct",
    "encoding": "JOINT_VEL",
    "payload": [0.10, 0.10, -0.05, -0.05],
    "expires_ns": 1822741234200000000
  }
}
```

### A.7 Proprioception packet

```json
{
  "msg_type": "SN_PROPRIO",
  "qos_class": "FAST",
  "seq": 55201,
  "t_emit_ns": 1822741234500000000,
  "payload": {
    "groups": [
      {
        "name": "arm.left",
        "joints": [0.12, -0.44, 0.02, 0.61, -0.10, 0.33],
        "joints_si": [0.15, -0.61, 0.03, 0.92, -0.14, 0.50],
        "velocities": [0.01, -0.02, 0.00, 0.05, 0.00, 0.01],
        "efforts": [1.2, -0.8, 0.1, 2.4, -0.3, 0.4]
      }
    ],
    "imu": {
      "linear_accel": [0.02, -0.01, 9.81],
      "angular_vel": [0.001, 0.002, 0.15],
      "orientation": [0.9999, 0.0, 0.0, 0.0141]
    },
    "odom": {
      "pose": { "frame": "GLOVE-WORLD", "position": [2.31, 0.84, 0.0], "orientation": [0.9986, 0.0, 0.0, 0.0523] },
      "twist": { "linear": [0.40, 0.0, 0.0], "angular": [0.0, 0.0, 0.15] }
    }
  }
}
```

### A.8 Contact event (impact)

```json
{
  "msg_type": "SN_CONTACT",
  "qos_class": "EVENT",
  "payload": {
    "contacts": [
      { "sensor": "hand.left.palm", "normal_force": 14.2, "position": [0.03, -0.01, 0.00], "active": true }
    ],
    "events": [
      { "kind": "IMPACT", "sensor": "hand.left.palm", "peak_force_n": 22.7, "confidence": 0.99 }
    ]
  }
}
```

### A.9 Vision summary

```json
{
  "msg_type": "SN_VISION",
  "qos_class": "FAST",
  "payload": {
    "frames": [
      {
        "camera": "head.rgb",
        "encoding": "RGB8",
        "width": 640, "height": 480,
        "data_ref": "shm://glove-local/frames/0192b4a1-ff00",
        "intrinsics": { "fx": 525.0, "fy": 525.0, "cx": 320.0, "cy": 240.0 }
      }
    ],
    "events": [
      {
        "kind": "OBJECT_TRACK",
        "track_id": "trk-0042",
        "bbox": [0.41, 0.30, 0.12, 0.22],
        "position": [1.20, -0.35, 1.10],
        "frame": "GLOVE-WORLD",
        "confidence": 0.87
      }
    ]
  }
}
```

### A.10 Audio event

```json
{
  "msg_type": "SN_AUDIO",
  "qos_class": "EVENT",
  "payload": {
    "events": [
      { "kind": "SOUND_EVENT", "label": "glass_break", "direction": [0.78, 0.12], "level_db": 71.5, "confidence": 0.93 }
    ]
  }
}
```

### A.11 Internal state

```json
{
  "msg_type": "SN_INTERNAL",
  "qos_class": "FAST",
  "payload": {
    "battery": { "soc": 0.62, "voltage": 24.1, "current": 3.2, "time_remaining_s": 4170 },
    "thermal": [ { "zone": "arm.left.actuator.3", "temp": 46.5 } ],
    "faults": [
      { "code": "mockbase.wheel.slip", "severity": "WARNING", "message": "Left wheel slip ratio above nominal" }
    ],
    "joint_limit_proximity": [ { "group": "arm.left", "margin": 0.31 } ],
    "compute": { "load": 0.44, "mem_used": 0.51 }
  }
}
```

### A.12 Governance envelope (framing visible, payload opaque)

```json
{
  "msg_type": "GOV_ENVELOPE",
  "qos_class": "GOV",
  "payload": {
    "class": "OVERRIDE",
    "sender": "caregiver.console.07",
    "sender_seq": 881,
    "expires_ns": 1822741236000000000,
    "auth_tag": "ed25519:9f2c…(96 hex chars)…a1",
    "payload_ciphertext_b64": "cGF5bG9hZC1vcGFxdWUtdG8tdGhlLWdsb3Zl…"
  }
}
```

---

## Appendix B — Minimal Adapter Pseudocode: Mock Mobile Base (informative)

```python
# MockMobileBaseAdapter — conformance-oriented sketch of the Section 4 boundary.
# Robot: differential-drive base, 2 wheel encoders, IMU, bump sensors, battery.

class MockMobileBaseAdapter:
    def __init__(self, native_driver):
        self.drv = native_driver          # vendor SDK / ROS node / CAN handle
        self.state = "DISCONNECTED"
        self.capabilities = load_descriptor_template("mockbase.descriptor.json")
        self.mapping = load_mapping_tables("mockbase.mapping.v1.json")  # static, hashed

    # ---- Lifecycle (REQ-AD-01, REQ-AD-02) ----
    def discover(self):
        try:    return self.drv.scan()            # e.g., serial ports, ROS topics
        except NativeError: return []             # MUST NOT throw

    def connect(self, handle):
        self.drv.open(handle)
        assert_firmware_compatible(self.drv.firmware_version())
        self._inhibit_motion()                    # no motion until activate()
        self.state = "CONNECTED"; emit("ADAPTER_STATE", self.state)

    def calibrate(self, profile=None):
        if profile and profile.matches(serial=self.drv.serial()):
            self.calib = profile                  # restore from continuity packet
        else:
            self.calib = run_calibration(self.drv)  # frames, wheel radius, offsets
        publish_static_transforms(self.calib)       # GLOVE-BASE, GLOVE-CAMERA.*
        self.state = "CALIBRATED"; emit("ADAPTER_STATE", self.state)
        return merge_descriptor(self.capabilities, self.calib, self.mapping)

    def activate(self):
        self.drv.start_streams(rates={"encoder": 200, "imu": 100, "bump": 100})
        self._enable_motion(); self.state = "ACTIVE"; emit("ADAPTER_STATE", self.state)

    def deactivate(self, mode="GRACEFUL"):
        if mode == "GRACEFUL": self._finish_or_abort_inflight()
        self.halt(); self._inhibit_motion()
        self.state = "INHIBITED"; emit("ADAPTER_STATE", self.state)

    def disconnect(self):
        self.halt(); self.drv.close(); self.state = "DISCONNECTED"

    # ---- Action dispatch (REQ-AD-04..06) ----
    def dispatch(self, cmd):
        # cmd arrives ALREADY validated, envelope-clipped, robot-space.
        if self.state != "ACTIVE": return reject("NOT_ACTIVE")
        native = self._to_native(cmd)             # twist -> (v_left, v_right)
        handle = self.drv.send_velocity(native)
        self._track(handle, cmd); return handle

    def halt(self):                               # worst-case <= 10 ms path
        self.drv.estop_or_controlled_stop()       # assert safest native stop

    # ---- Sensory ingestion & normalization (REQ-AD-07..09) ----
    def on_encoder_tick(self, raw, t_ns):
        si = self.mapping.encoders_to_si(raw, self.calib)   # deterministic
        emit("SN_PROPRIO", qos="FAST", t_emit_ns=t_ns, payload={
            "groups": [{"name": "base.wheels",
                        "joints": normalize(si.pos, self.calib.limits),
                        "joints_si": si.pos, "velocities": si.vel}],
            "odom": integrate_odometry(si)})

    def on_bump(self, raw, t_ns):
        if raw.hit:
            emit("SN_CONTACT", qos="EVENT", payload={
                "contacts": [{"sensor": raw.zone, "normal_force": est_force(raw),
                              "active": True}],
                "events": [{"kind": "IMPACT", "peak_force_n": est_force(raw),
                            "confidence": 1.0}]})          # also feeds envelope

    def on_battery(self, raw, t_ns):
        emit("SN_INTERNAL", qos="FAST", payload={
            "battery": {"soc": raw.soc, "voltage": raw.volts},
            "faults": [map_fault(f) for f in self.drv.fault_registers()]})

    def on_stream_timeout(self, sensor, gap_ms):  # REQ-AD-09
        emit("SENSOR_DROPOUT", sensor=sensor, duration_ms=gap_ms)

    # ---- Safety configuration (REQ-AD-10) ----
    def physical_limits(self):
        return {"joint_limits": self.calib.limits,
                "max_linear_mps": 1.5, "max_angular_radps": 1.8,
                "forbidden_zones": load_zones("mockbase.zones.json"),
                "estop": {"type": "torque_off", "latency_ms_max": 5}}
```

*This sketch is informative. Normative behavior is defined solely by Sections 3–10.*

---

*End of GLV-SPEC-1.0.0 — Specification: The Glove Layer.*
